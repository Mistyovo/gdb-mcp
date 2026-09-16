"""MCP tool registration."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from gdb_mcp.config import Config
from gdb_mcp.sessions import SessionRegistry

from . import (
    breakpoint_tools,
    crash_tools,
    exec_tools,
    launch_tools,
    session_tools,
    state_tools,
)

TOOL_MODULES = (
    session_tools,
    launch_tools,
    exec_tools,
    state_tools,
    breakpoint_tools,
    crash_tools,
)

#: The GDB_MCP_TOOL_PROFILE=core set: the tools an exploit workflow hits
#: constantly. Everything else stays reachable under the "full" profile.
CORE_TOOLS = frozenset(
    {
        "list_sessions",
        "launch_gdb",
        "launch_script",
        "execute_command",
        "continue_execution",
        "wait_for_stop",
        "interrupt",
        "crash_report",
        "read_memory",
        "evaluate",
        "set_breakpoint",
        "get_events",
    }
)


def register_all(app: FastMCP, registry: SessionRegistry, config: Config) -> None:
    for module in TOOL_MODULES:
        module.register(app, registry, config)
    if config.tool_profile == "core":
        # Drop non-core registrations; the tool manager is the single
        # source of truth for what list_tools exposes.
        tools = app._tool_manager._tools
        for name in list(tools):
            if name not in CORE_TOOLS:
                del tools[name]
