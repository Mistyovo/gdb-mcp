"""Hardening for the MCP streamable-HTTP transport.

Mirrors the four lines of defense microsoft/DebugMCP established:

1. loopback-only default bind (enforced by ``Config.validate`` — a token
   is mandatory for any non-loopback bind),
2. Host header validation (anti DNS-rebinding),
3. Origin header validation (browser-based agents cannot cross-origin in),
4. Bearer token on every request when a token is configured.

``check_http_request`` is the pure decision function (unit-tested); the
ASGI wrapper just applies it.
"""

from __future__ import annotations

import hmac

from gdb_mcp.errors import ProtocolError
from gdb_mcp.roles import CURRENT_ROLE

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _is_loopback(host: str) -> bool:
    return host.lower().strip("[]") in _LOOPBACK_HOSTS


def _host_name(header_value: str) -> str:
    """Strip the port from a Host/Origin authority ("[::1]:8001" -> "::1")."""
    if "]:" in header_value:
        return header_value.split("]:", 1)[0].strip("[")
    value = header_value.strip("[]")
    if value.count(":") == 1:  # name:port / ipv4:port
        return value.rsplit(":", 1)[0]
    return value


def check_http_request(
    headers: dict[str, str],
    bind_host: str,
    bind_port: int,
    token: str | None,
    observer_tokens: tuple[str, ...] = (),
) -> str:
    """Validate the request and return the client role ("controller" or
    "observer"). Raises :class:`ProtocolError` on failure.

    ``headers`` keys are lowercase. Header absence rules: ``Host`` is
    mandatory (HTTP/1.1); ``Origin`` is optional (non-browser clients
    omit it); ``Authorization`` is required exactly when a controller
    or observer token is configured. A bearer matching an observer
    token yields the observer role; anything else must match the
    controller token.
    """
    host = headers.get("host")
    if not host:
        raise ProtocolError("MALFORMED", "missing Host header")
    host_name = _host_name(host)
    if host.lower() not in {h.lower() for h in (bind_host, f"{bind_host}:{bind_port}")}:
        # also accept the plain loopback aliases so 127.0.0.1/localhost
        # interchange freely on a loopback bind
        if not (_is_loopback(bind_host) and _is_loopback(host_name)):
            raise ProtocolError(
                "MALFORMED", f"Host header {host!r} does not match the bind address"
            )
    origin = headers.get("origin")
    if origin:
        origin_name = _host_name(origin.split("://", 1)[-1])
        if not (_is_loopback(bind_host) and _is_loopback(origin_name)):
            if origin_name.lower() != bind_host.lower():
                raise ProtocolError(
                    "MALFORMED",
                    f"cross-origin request from {origin!r} is not allowed",
                )
    supplied = headers.get("authorization", "")
    expected = "Bearer " + (token or "")
    role = "controller"
    if token or observer_tokens:
        matched = False
        if token and hmac.compare_digest(
            supplied.encode("utf-8"), expected.encode("utf-8")
        ):
            matched = True
        for observer in observer_tokens:
            if hmac.compare_digest(
                supplied.encode("utf-8"),
                ("Bearer " + observer).encode("utf-8"),
            ):
                matched = True
                role = "observer"
                break
        if not matched:
            raise ProtocolError("MALFORMED", "missing or invalid bearer token")
    return role


class SecurityHeadersMiddleware:
    """Pure-ASGI wrapper applying :func:`check_http_request` to every
    HTTP request before it reaches the MCP app, and binding the derived
    client role to the request's context (D2 observer enforcement)."""

    def __init__(
        self,
        app,
        bind_host: str,
        bind_port: int,
        token: str | None,
        observer_tokens: tuple[str, ...] = (),
        audit=None,
    ):
        self.app = app
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.token = token
        self.observer_tokens = tuple(observer_tokens)
        self.audit = audit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        try:
            role = check_http_request(
                headers,
                self.bind_host,
                self.bind_port,
                self.token,
                self.observer_tokens,
            )
        except ProtocolError as exc:
            if self.audit is not None:
                self.audit.record(
                    "http_rejected",
                    path=scope.get("path", ""),
                    reason=exc.message[:200],
                )
            body = exc.message.encode("utf-8")
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-type", b"text/plain; charset=utf-8"),
                        (b"content-length", str(len(body)).encode("latin-1")),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        CURRENT_ROLE.set(role)
        await self.app(scope, receive, send)
