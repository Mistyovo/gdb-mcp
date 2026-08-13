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


def register_all(app: FastMCP, registry: SessionRegistry, config: Config) -> None:
    for module in TOOL_MODULES:
        module.register(app, registry, config)
