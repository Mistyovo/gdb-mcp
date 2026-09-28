"""MCP tool registration.

Each module declares its handlers with ``@tool(...)``; importing the
concrete modules populates the shared ``SPECS`` list (see
:mod:`gdb_mcp.tools.registry`), and :func:`register_all` — called from
``server.build_app`` — is the only place that decides what the MCP
client can see.
"""

from __future__ import annotations

import importlib

from .registry import (
    SPECS,
    ToolSpec,
    core_tool_names,
    registered_tools,
    register_all as _register_all,
    tool,
)

#: importing these populates registry.SPECS
_TOOL_MODULES = (
    "session_tools",
    "launch_tools",
    "exec_tools",
    "state_tools",
    "breakpoint_tools",
    "heap_tools",
    "campaign_tools",
    "static_tools",
    "experimental",
    "crash_tools",
)


def _load_tool_modules() -> None:
    for name in _TOOL_MODULES:
        importlib.import_module("%s.%s" % (__name__, name))


def register_all(app, ctx) -> None:
    """Import the declaring modules, then register what the profile
    allows. Declaration, not registration order, decides visibility."""
    _load_tool_modules()
    _register_all(app, ctx)


def __getattr__(attr_name: str):
    # CORE_TOOLS is derived from the declarations, so it must be computed
    # after the tool modules have been imported.
    if attr_name == "CORE_TOOLS":
        _load_tool_modules()
        return core_tool_names()
    raise AttributeError(attr_name)


__all__ = [
    "SPECS",
    "ToolSpec",
    "core_tool_names",
    "register_all",
    "registered_tools",
    "tool",
    "CORE_TOOLS",
]
