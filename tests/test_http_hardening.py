"""Tests for the MCP HTTP transport hardening."""

import pytest

from gdb_mcp.errors import ProtocolError
from gdb_mcp.http_hardening import SecurityHeadersMiddleware, check_http_request

BIND = ("127.0.0.1", 8001)


class TestCheckHttpRequest:
    def _check(self, headers, token=None, bind=BIND):
        return check_http_request(headers, bind[0], bind[1], token)

    def test_missing_host_rejected(self):
        with pytest.raises(ProtocolError):
            self._check({})

    def test_matching_host_ok(self):
        self._check({"host": "127.0.0.1:8001"})
        self._check({"host": "localhost:8001"})  # loopback alias
        self._check({"host": "127.0.0.1"})  # portless alias

    def test_foreign_host_rejected(self):
        with pytest.raises(ProtocolError):
            self._check({"host": "evil.example:8001"})

    def test_nonloopback_bind_strict(self):
        bind = ("10.0.0.5", 8001)
        check_http_request({"host": "10.0.0.5:8001"}, *bind, None)
        with pytest.raises(ProtocolError):
            check_http_request({"host": "localhost:8001"}, *bind, None)

    def test_cross_origin_rejected(self):
        with pytest.raises(ProtocolError):
            self._check(
                {"host": "127.0.0.1:8001", "origin": "https://evil.example"}
            )

    def test_loopback_origin_ok(self):
        self._check(
            {"host": "127.0.0.1:8001", "origin": "http://localhost:8001"}
        )

    def test_token_enforced(self):
        headers = {"host": "127.0.0.1:8001"}
        with pytest.raises(ProtocolError):
            self._check(headers, token="secret")
        with pytest.raises(ProtocolError):
            self._check({**headers, "authorization": "Bearer wrong"}, "secret")
        self._check({**headers, "authorization": "Bearer secret"}, token="secret")

    def test_no_token_no_auth_needed(self):
        self._check({"host": "127.0.0.1:8001"}, token=None)


class TestSecurityHeadersMiddleware:
    @staticmethod
    async def _run(mw, scope):
        sent = []

        async def receive():
            return {"type": "http.request"}

        async def send(message):
            sent.append(message)

        await mw(scope, receive, send)
        return sent

    @pytest.mark.asyncio
    async def test_blocked_request_short_circuits_403(self):
        reached = []

        async def app(scope, receive, send):
            reached.append(scope)

        mw = SecurityHeadersMiddleware(app, *BIND, None)
        scope = {"type": "http", "headers": [(b"host", b"evil.example:8001")]}
        sent = await self._run(mw, scope)
        assert reached == []
        assert sent[0]["status"] == 403

    @pytest.mark.asyncio
    async def test_valid_request_passes_through(self):
        reached = []

        async def app(scope, receive, send):
            reached.append(scope)

        mw = SecurityHeadersMiddleware(app, *BIND, None)
        scope = {"type": "http", "headers": [(b"host", b"127.0.0.1:8001")]}
        await self._run(mw, scope)
        assert reached == [scope]

    @pytest.mark.asyncio
    async def test_non_http_scope_passes_through(self):
        reached = []

        async def app(scope, receive, send):
            reached.append(scope)

        mw = SecurityHeadersMiddleware(app, *BIND, None)
        scope = {"type": "lifespan"}
        await self._run(mw, scope)
        assert reached == [scope]


class TestObserverRoles:
    def test_observer_bearer_gets_observer_role(self):
        role = check_http_request(
            {"host": "127.0.0.1:8001", "authorization": "Bearer obs-1"},
            "127.0.0.1",
            8001,
            "ctrl",
            ("obs-1",),
        )
        assert role == "observer"

    def test_controller_bearer_gets_controller_role(self):
        role = check_http_request(
            {"host": "127.0.0.1:8001", "authorization": "Bearer ctrl"},
            "127.0.0.1",
            8001,
            "ctrl",
            ("obs-1",),
        )
        assert role == "controller"

    def test_unknown_bearer_rejected_even_with_observers(self):
        with pytest.raises(ProtocolError):
            check_http_request(
                {"host": "127.0.0.1:8001", "authorization": "Bearer nope"},
                "127.0.0.1",
                8001,
                "ctrl",
                ("obs-1",),
            )

    def test_no_tokens_loopback_defaults_controller(self):
        role = check_http_request({"host": "127.0.0.1:8001"}, "127.0.0.1", 8001, None)
        assert role == "controller"

    def test_middleware_sets_observer_role_in_context(self):
        import asyncio

        from gdb_mcp.http_hardening import SecurityHeadersMiddleware
        from gdb_mcp.roles import CURRENT_ROLE

        seen = []

        async def app(scope, receive, send):
            seen.append(CURRENT_ROLE.get())

        mw = SecurityHeadersMiddleware(app, "127.0.0.1", 8001, None, ("obs",))
        scope = {
            "type": "http",
            "headers": [
                (b"host", b"127.0.0.1:8001"),
                (b"authorization", b"Bearer obs"),
            ],
        }
        asyncio.run(mw(scope, None, lambda m: asyncio.sleep(0)))
        assert seen == ["observer"]

    def test_middleware_controller_role_for_master(self):
        import asyncio

        from gdb_mcp.http_hardening import SecurityHeadersMiddleware
        from gdb_mcp.roles import CURRENT_ROLE

        seen = []

        async def app(scope, receive, send):
            seen.append(CURRENT_ROLE.get())

        mw = SecurityHeadersMiddleware(app, "127.0.0.1", 8001, "ctrl", ("obs",))
        scope = {
            "type": "http",
            "headers": [
                (b"host", b"127.0.0.1:8001"),
                (b"authorization", b"Bearer ctrl"),
            ],
        }
        asyncio.run(mw(scope, None, lambda m: asyncio.sleep(0)))
        assert seen == ["controller"]
