"""Declarative MCP tool registry.

Tool modules declare handlers with :func:`tool` and attach their
visibility policy (core-profile membership, capability, experimental
gating) to the declaration itself. :func:`register_all` is the single
place that decides what reaches the MCP surface.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

from gdb_mcp.config import Config
from gdb_mcp.context import ServerContext

#: What a tool is allowed to affect. ``observe`` is the only capability a
#: ``--readonly`` server exposes; ``host`` and ``admin`` tools can execute
#: code or lifecycle actions outside the inferior.
CAPABILITIES = frozenset({"observe", "debug", "target", "host", "admin"})


@dataclasses.dataclass(frozen=True)
class ToolSpec:
    fn: Callable[..., Any]
    name: str
    #: part of the GDB_MCP_TOOL_PROFILE=core subset
    core: bool = False
    #: observe | debug | target | host | admin
    capability: str = "observe"
    #: only registered when the server runs with --experimental
    experimental: bool = False


SPECS: list[ToolSpec] = []


def tool(
    *,
    core: bool = False,
    capability: str = "observe",
    experimental: bool = False,
) -> Callable:
    """Declare an MCP tool. Returns the function unchanged; the
    declaration (not the app) is the source of truth for visibility."""

    if capability not in CAPABILITIES:
        raise ValueError(
            "capability must be one of %s" % ", ".join(sorted(CAPABILITIES))
        )

    def deco(fn: Callable) -> Callable:
        SPECS.append(
            ToolSpec(
                fn=fn,
                name=fn.__name__,
                core=core,
                capability=capability,
                experimental=experimental,
            )
        )
        return fn

    return deco


def core_tool_names() -> frozenset[str]:
    return frozenset(
        spec.name for spec in SPECS if spec.core and not spec.experimental
    )


def observe_tool_names() -> frozenset[str]:
    """The observe-only surface kept under --readonly."""
    return frozenset(spec.name for spec in SPECS if spec.capability == "observe")


def _visible(spec: ToolSpec, config: Config) -> bool:
    if spec.experimental and not config.experimental:
        return False
    if config.tool_profile == "core" and not spec.core:
        return False
    if config.readonly and spec.capability != "observe":
        return False
    return True


def register_all(app: FastMCP, ctx: ServerContext) -> None:
    """Register every visible tool declared across the tool modules."""
    for spec in SPECS:
        if not _visible(spec, ctx.config):
            continue
        app.add_tool(spec.fn, name=spec.name)


def registered_tools(app: FastMCP) -> dict:
    """Read-only snapshot of the registered tools (name -> Tool), for
    tests and diagnostics."""
    return dict(app._tool_manager._tools)  # noqa: SLF001 - read-only view


def __getattr__(attr_name: str):
    if attr_name == "CORE_TOOLS":
        return core_tool_names()
    raise AttributeError(attr_name)
