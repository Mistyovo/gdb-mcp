"""Read-only session dashboard: loopback HTTP + SSE event stream.

Phase 1 (data layer) of docs/dashboard-design.md, plus the Phase 2
frontend (web_static/, dependency-free vanilla JS). The API below is
the stability boundary; the frontend consumes exactly these endpoints,
no more.

Endpoints (GET only - mutating actions are a deliberate non-goal here):

* ``/``                 - dashboard page (web_static/index.html)
* ``/app.css`` / ``/app.js`` - its assets, fixed-name routes
* ``/api/v1/health``    - liveness + dashboard status
* ``/api/v1/snapshot``  - full state: every session + broker sequence
* ``/api/v1/events``    - SSE stream of EventBroker events (15s keepalive)

Security posture matches the archived workbench: loopback-only bind
(enforced by ``Config.validate``), Host/Origin header validation via the
shared ``check_http_request`` (anti DNS-rebinding), hardened response
headers. No bearer auth: exposing debugger session metadata to other
processes on the same loopback host is the accepted residual risk, same
trade-off the archived dashboard made.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, AsyncIterator

from starlette.applications import Starlette
from starlette.responses import FileResponse, JSONResponse, StreamingResponse
from starlette.routing import Route

from gdb_mcp.config import Config
from gdb_mcp.events import EventBroker
from gdb_mcp.http_hardening import SecurityHeadersMiddleware
from gdb_mcp.sessions import Session, SessionRegistry

log = logging.getLogger("gdb_mcp.web")

_STATIC_DIR = Path(__file__).resolve().parent / "web_static"

#: fixed-name asset routes; no path parameters => nothing to traverse
_STATIC_FILES = {
    "app.css": "text/css; charset=utf-8",
    "app.js": "application/javascript; charset=utf-8",
}

#: SSE comment line cadence - keeps proxies/browsers from idling the
#: stream out while adding zero data events
KEEPALIVE_SEC = 15.0


def session_view(session: Session) -> dict[str, Any]:
    """``Session.info()`` plus dashboard-only extras.

    The extras deliberately live here, not in ``Session.info()``:
    ``info()`` feeds the ``list_sessions`` MCP tool, whose payload must
    stay compact for the model's context window.
    """
    view = session.info()
    view.update(
        {
            "pending_requests": len(session.pending),
            "age_sec": round(time.monotonic() - session.created_at, 1),
            "last_event": session.event_log[-1] if session.event_log else None,
            "journal_entries": len(session.journal) if session.journal else 0,
        }
    )
    return view


async def sse_stream(
    events: EventBroker, keepalive_sec: float = KEEPALIVE_SEC
) -> AsyncIterator[str]:
    """Format broker events as Server-Sent Events.

    Pure generator (unit-tested without a socket): the HTTP handler only
    wraps it. Unsubscribes on any exit path so a disconnected client
    never pins a queue. A ``resync`` marker means the client fell behind
    and must re-fetch the snapshot instead of replaying stale events.
    """
    queue = events.subscribe()
    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), keepalive_sec)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
                continue
            yield "data: %s\n\n" % json.dumps(
                event, ensure_ascii=False, separators=(",", ":")
            )
    finally:
        events.unsubscribe(queue)


class _StaticHeadersMiddleware:
    """Pure-ASGI wrapper adding hardened response headers: nosniff,
    no-referrer, and a deny-by-default CSP that allows exactly the
    same-origin script/style/connect the dashboard page needs."""

    _HEADERS = [
        (b"x-content-type-options", b"nosniff"),
        (b"referrer-policy", b"no-referrer"),
        (
            b"content-security-policy",
            b"default-src 'none'; script-src 'self'; style-src 'self'; "
            b"connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
        ),
    ]

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                message.setdefault("headers", []).extend(self._HEADERS)
            await send(message)

        await self.app(scope, receive, send_with_headers)


class DashboardServer:
    """Serves the read-only dashboard API on its own loopback port.

    Runs its own uvicorn instance so the dashboard works in every MCP
    transport mode - including stdio (the Agent default), where no HTTP
    surface otherwise exists. Bind failure is recorded, never fatal:
    the debug server itself must keep running either way (same posture
    as the archived workbench).
    """

    def __init__(
        self,
        config: Config,
        registry: SessionRegistry,
        events: EventBroker,
    ):
        self.config = config
        self.registry = registry
        self.events = events
        self._server: Any = None
        self._task: asyncio.Task | None = None
        self._running = False
        self._error: str | None = None
        self._port = config.dashboard_port

    # -- state --------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        host = self.config.dashboard_host
        display = "[%s]" % host if ":" in host else host
        return {
            "enabled": self.config.dashboard,
            "running": self._running,
            "url": "http://%s:%d" % (display, self._port),
            "error": self._error,
            "read_only": True,
            "event_sequence": self.events.sequence,
        }

    def snapshot(self) -> dict[str, Any]:
        return {
            "sequence": self.events.sequence,
            "sessions": [session_view(s) for s in self.registry.list_all()],
            "dashboard": self.status(),
        }

    # -- lifecycle ----------------------------------------------------------

    def build_app(self) -> Starlette:
        return Starlette(
            routes=[
                Route("/", self._index, methods=["GET"]),
                Route("/app.css", self._asset, methods=["GET"]),
                Route("/app.js", self._asset, methods=["GET"]),
                Route("/api/v1/health", self._health, methods=["GET"]),
                Route("/api/v1/snapshot", self._snapshot, methods=["GET"]),
                Route("/api/v1/events", self._events, methods=["GET"]),
            ]
        )

    def start(self) -> None:
        """Bind the dashboard port and spawn the server task.

        Synchronous on purpose: the bind happens eagerly so port
        conflicts surface at startup, and ``status()`` reflects the real
        (possibly ephemeral) port immediately afterwards.
        """
        if not self.config.dashboard or self._task is not None:
            return
        import uvicorn

        app = _StaticHeadersMiddleware(
            SecurityHeadersMiddleware(
                self.build_app(),
                self.config.dashboard_host,
                self.config.dashboard_port,
                None,
                (),
            )
        )
        uconfig = uvicorn.Config(
            app,
            host=self.config.dashboard_host,
            port=self.config.dashboard_port,
            log_level="warning",
            access_log=False,
        )
        try:
            sock = uconfig.bind_socket()
        except OSError as exc:
            self._error = str(exc)
            log.warning(
                "dashboard could not bind %s:%d: %s",
                self.config.dashboard_host,
                self.config.dashboard_port,
                exc,
            )
            return
        if self.config.dashboard_port == 0:
            self._port = int(sock.getsockname()[1])
        self._server = uvicorn.Server(uconfig)
        self._running = True
        self._error = None
        self._task = asyncio.create_task(self._server.serve(sockets=[sock]))
        log.info("session dashboard on %s", self.status()["url"])

    async def stop(self) -> None:
        self._running = False
        task, self._task = self._task, None
        if self._server is not None:
            self._server.should_exit = True
        self._server = None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    # -- handlers -----------------------------------------------------------

    async def _index(self, request) -> FileResponse:
        return FileResponse(
            _STATIC_DIR / "index.html", media_type="text/html; charset=utf-8"
        )

    async def _asset(self, request) -> FileResponse:
        name = request.url.path.lstrip("/")
        return FileResponse(_STATIC_DIR / name, media_type=_STATIC_FILES[name])

    async def _health(self, request) -> JSONResponse:
        return JSONResponse({"ok": self._running, **self.status()})

    async def _snapshot(self, request) -> JSONResponse:
        return JSONResponse(self.snapshot())

    async def _events(self, request) -> StreamingResponse:
        return StreamingResponse(
            sse_stream(self.events),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )


__all__ = ["DashboardServer", "session_view", "sse_stream"]
