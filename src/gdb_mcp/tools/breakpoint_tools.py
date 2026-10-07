"""Breakpoint management tools."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.security import is_unsafe_gdb_command

from ._common import audit_from, check_stopped, config_from, resolve_gdb
from .registry import tool

_BP_TYPES = ("breakpoint", "hw", "watch", "hw_watch")


@tool(core=True)
async def set_breakpoint(
    location: str,
    type: str = "breakpoint",
    condition: str | None = None,
    temporary: bool = False,
    pending: bool = False,
    thread: int | None = None,
    commands: list[str] | None = None,
    auto_continue: bool = False,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Set a breakpoint at an address/symbol/expression
    ('main', '*main+0x20', '0x401000'). Types: breakpoint (software),
    hw (hardware), watch, hw_watch. With commands (gdb CLI strings),
    they run automatically on hit (prefixed with `silent` so the stop
    is quiet); with auto_continue the hit also resumes immediately —
    together they turn a breakpoint into an unattended probe. Commands
    pass the same unsafe gate as execute_command: anything that can
    execute code outside the debugger requires --allow-unsafe."""
    if type not in _BP_TYPES:
        raise GdbMcpError(
            "BAD_PARAMS", "type must be one of %s" % ", ".join(_BP_TYPES)
        )
    if commands is not None and (
        not isinstance(commands, list)
        or any(not isinstance(c, str) for c in commands)
    ):
        raise GdbMcpError("BAD_PARAMS", "commands must be a list of strings")
    if commands:
        # The plugin joins these into bp.commands and gdb runs them as raw
        # CLI on hit — the same debugger-escape surface as execute_command.
        cfg = config_from(ctx)
        if not cfg.allow_unsafe:
            for c in commands:
                if is_unsafe_gdb_command(c):
                    audit_from(ctx).record("unsafe_command_blocked", command=c)
                    raise GdbMcpError(
                        "UNSAFE_BLOCKED",
                        "breakpoint command %r can execute code outside the "
                        "debugger; start with --allow-unsafe to allow it" % c,
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
    if commands:
        params["commands"] = commands
    if auto_continue:
        params["auto_continue"] = True
    return await session.request(
        "break", params, timeout=config_from(ctx).request_timeout
    )


@tool()
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


@tool()
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
