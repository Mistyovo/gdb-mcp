"""Execution-control tools (continue/step/interrupt/wait)."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from gdb_mcp.sessions import RUNNING

from ._common import check_resumable, config_from, resolve_gdb

_MODES = ("continue", "step", "next", "stepi", "nexti", "finish", "until")


def register(app, registry, config) -> None:
    @app.tool()
    async def execute_command(
        command: str,
        keep_ansi: bool = False,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Execute a raw gdb command and return its output. Use for
        pwndbg-specific commands (vmmap, heap, got, checksec, ropgadget,
        search, ...) or any other gdb CLI command. Works while the
        inferior is running (queued until the next stop)."""
        session = resolve_gdb(ctx, session_id)
        result = await session.request(
            "eval",
            {"command": command, "keep_ansi": keep_ansi},
            timeout=config_from(ctx).request_timeout,
        )
        return result

    @app.tool()
    async def continue_execution(
        mode: str = "continue",
        until_addr: str | None = None,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Resume the inferior: continue / step / next / stepi / nexti /
        finish / until. Returns immediately; use wait_for_stop to wait for
        the next stop event, or rely on the async stop notification."""
        if mode not in _MODES:
            raise ValueError("mode must be one of %s" % ", ".join(_MODES))
        session = resolve_gdb(ctx, session_id)
        check_resumable(session)
        params = {}
        if mode == "until" and until_addr:
            params["until_addr"] = until_addr
        result = await session.request(
            mode, params, timeout=config_from(ctx).request_timeout
        )
        return result

    @app.tool()
    async def interrupt(session_id: str | None = None, ctx: Context = None) -> dict:
        """Interrupt the running inferior (equivalent to Ctrl-C in gdb).
        The inferior stops and a stop notification is emitted."""
        session = resolve_gdb(ctx, session_id)
        if session.state != RUNNING:
            return {
                "state": "not_running",
                "note": "inferior is not running; nothing to interrupt",
            }
        result = await session.request(
            "interrupt", {}, timeout=config_from(ctx).request_timeout
        )
        return result

    @app.tool()
    async def wait_for_stop(
        timeout_ms: int = 30000,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Wait until the inferior stops (signal, breakpoint, exit) or the
        timeout elapses. Returns immediately when the inferior is already
        stopped."""
        session = resolve_gdb(ctx, session_id)
        stopped = await session.wait_for_stop(timeout=max(0.1, timeout_ms / 1000.0))
        return {
            "session_id": session.session_id,
            "stopped": stopped,
            "state": session.state,
            "stop_info": session.stop_info,
        }

    @app.tool()
    def get_stop_reason(session_id: str | None = None, ctx: Context = None) -> dict:
        """The reason the inferior last stopped (signal, fault address,
        breakpoint info)."""
        session = resolve_gdb(ctx, session_id)
        return {
            "session_id": session.session_id,
            "state": session.state,
            "stop_info": session.stop_info,
            "exited_code": session.exited_code,
        }
