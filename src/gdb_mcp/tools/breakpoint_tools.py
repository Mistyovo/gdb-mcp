"""Unified breakpoint and watchpoint management tool."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.security import is_unsafe_gdb_command

from ._common import check_stopped, config_from, resolve_gdb
from .registry import tool

_BP_TYPES = ("breakpoint", "hw", "watch", "hw_watch")


@tool(core=True, capability="debug", readonly=True)
async def breakpoint(
    action: str = "set",
    location: str | None = None,
    type: str = "breakpoint",
    condition: str | None = None,
    temporary: bool = False,
    pending: bool = False,
    thread: int | None = None,
    commands: list[str] | None = None,
    auto_continue: bool = False,
    number: int | None = None,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Manage breakpoints/watchpoints. Actions:
    - set: create at `location` (`type`: breakpoint|hw|watch|hw_watch;
      optional condition/temporary/pending/thread/commands/auto_continue).
    - list: list all breakpoints/watchpoints.
    - delete / enable / disable: operate on breakpoint `number`.
    Under --readonly only `list` is available."""
    cfg = config_from(ctx)
    session = resolve_gdb(ctx, session_id)
    check_stopped(session)
    if action == "list":
        return await session.request("breakpoints", {}, timeout=cfg.request_timeout)
    if cfg.readonly:
        raise GdbMcpError(
            "READONLY", "breakpoint %s is disabled in --readonly mode" % action
        )
    if action in ("delete", "enable", "disable"):
        if isinstance(number, bool) or not isinstance(number, int):
            raise GdbMcpError("BAD_PARAMS", "number must be an int")
        verb = {
            "delete": "bp_delete",
            "enable": "bp_enable",
            "disable": "bp_disable",
        }[action]
        return await session.request(
            verb, {"number": number}, timeout=cfg.request_timeout
        )
    if action != "set":
        raise GdbMcpError(
            "BAD_PARAMS", "action must be set, list, delete, enable, or disable"
        )
    if not location:
        raise GdbMcpError("BAD_PARAMS", "location is required")
    if type not in _BP_TYPES:
        raise GdbMcpError(
            "BAD_PARAMS", "type must be one of %s" % ", ".join(_BP_TYPES)
        )
    if commands is not None and (
        not isinstance(commands, list)
        or any(not isinstance(c, str) for c in commands)
    ):
        raise GdbMcpError("BAD_PARAMS", "commands must be a list of strings")
    if commands and not cfg.allow_unsafe:
        for c in commands:
            if is_unsafe_gdb_command(c):
                raise GdbMcpError(
                    "UNSAFE_BLOCKED",
                    "breakpoint command %r can execute code outside the "
                    "debugger; start with --allow-unsafe to allow it" % c,
                )
    params: dict = {
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
    return await session.request("break", params, timeout=cfg.request_timeout)
