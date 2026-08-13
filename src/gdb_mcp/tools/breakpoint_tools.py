"""Breakpoint management tools."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError

from ._common import check_stopped, config_from, resolve_gdb

_BP_TYPES = ("breakpoint", "hw", "watch", "hw_watch")


def register(app, registry, config) -> None:
    @app.tool()
    async def set_breakpoint(
        location: str,
        type: str = "breakpoint",
        condition: str | None = None,
        temporary: bool = False,
        pending: bool = False,
        thread: int | None = None,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Set a breakpoint at an address/symbol/expression
        ('main', '*main+0x20', '0x401000'). Types: breakpoint (software),
        hw (hardware), watch, hw_watch."""
        if type not in _BP_TYPES:
            raise GdbMcpError(
                "BAD_PARAMS", "type must be one of %s" % ", ".join(_BP_TYPES)
            )
        session = resolve_gdb(ctx, session_id)
        check_stopped(session)
        params = {
            "location": location,
            "type": type,
            "temporary": temporary,
            "pending": pending,
        }
        if condition:
            params["condition"] = condition
        if thread is not None:
            params["thread"] = thread
        return await session.request(
            "break", params, timeout=config_from(ctx).request_timeout
        )

    @app.tool()
    async def list_breakpoints(
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """List all breakpoints/watchpoints."""
        session = resolve_gdb(ctx, session_id)
        check_stopped(session)
        return await session.request(
            "breakpoints", {}, timeout=config_from(ctx).request_timeout
        )

    @app.tool()
    async def manage_breakpoint(
        number: int,
        action: str,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Delete / enable / disable a breakpoint by number."""
        if action not in ("delete", "enable", "disable"):
            raise GdbMcpError(
                "BAD_PARAMS", "action must be delete, enable or disable"
            )
        session = resolve_gdb(ctx, session_id)
        check_stopped(session)
        verb = {"delete": "bp_delete", "enable": "bp_enable", "disable": "bp_disable"}[action]
        return await session.request(
            verb, {"number": number}, timeout=config_from(ctx).request_timeout
        )
