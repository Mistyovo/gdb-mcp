"""Declarative MCP tool registry.

Tool modules declare handlers with :func:`tool` and attach their
visibility policy (core-profile membership, readonly-mode behavior,
experimental gating) to the declaration itself. :func:`register_all` is
then the single place that decides what reaches the MCP surface — no
post-registration dictionary surgery, no mutation of already-registered
functions.

Observer-role policy lives in :mod:`gdb_mcp.roles` and is applied here by
*wrapping the handler before registration*; a non-allowlisted tool stays
visible to controllers and rejects observers with ``OBSERVER_READONLY``.
"""

from __future__ import annotations

import dataclasses
import functools
import inspect
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

from gdb_mcp.config import Config
from gdb_mcp.context import ServerContext
from gdb_mcp.errors import GdbMcpError
from gdb_mcp.roles import CURRENT_ROLE, observer_allowed


@dataclasses.dataclass(frozen=True)


class ToolSpec:
    fn: Callable[..., Any]
    name: str
    #: part of the GDB_MCP_TOOL_PROFILE=core subset
    core: bool = False
    #: safe to keep registered when the server runs with --readonly
    readonly_safe: bool = True
    #: only registered when the server runs with --experimental
    experimental: bool = False


SPECS: list[ToolSpec] = []


def tool(
    *,
    core: bool = False,
    readonly_safe: bool = True,
    experimental: bool = False,
) -> Callable:
    """Declare an MCP tool. Returns the function unchanged; the
    declaration (not the app) is the source of truth for visibility."""

    def deco(fn: Callable) -> Callable:
        SPECS.append(
            ToolSpec(
                fn=fn,
                name=fn.__name__,
                core=core,
                readonly_safe=readonly_safe,
                experimental=experimental,
            )
        )
        return fn

    return deco


def core_tool_names() -> frozenset[str]:
    return frozenset(
        spec.name for spec in SPECS if spec.core and not spec.experimental
    )


def _deny_observer(name: str) -> None:
    raise GdbMcpError(
        "OBSERVER_READONLY",
        "tool %r is not available to observer clients" % name,
    )


def _observer_guard(fn: Callable, name: str) -> Callable:
    """Wrap ``fn`` so observer-role calls are rejected.

    ``functools.wraps`` is what makes this safe to register in place of
    the original: it exposes the wrapped signature (which is what FastMCP
    builds the JSON schema from) and keeps the coroutine/sync kind.
    """
    if observer_allowed(name):
        return fn
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def guarded(*args: Any, **kwargs: Any) -> Any:
            if CURRENT_ROLE.get() == "observer":
                _deny_observer(name)
            return await fn(*args, **kwargs)

    else:

        @functools.wraps(fn)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            if CURRENT_ROLE.get() == "observer":
                _deny_observer(name)
            return fn(*args, **kwargs)

    return guarded


def _visible(spec: ToolSpec, config: Config) -> bool:
    if spec.experimental and not config.experimental:
        return False
    if config.tool_profile == "core" and not spec.core:
        return False
    if config.readonly and not spec.readonly_safe:
        return False
    return True


def register_all(app: FastMCP, ctx: ServerContext) -> None:
    """Register every visible tool declared across the tool modules."""
    for spec in SPECS:
        if not _visible(spec, ctx.config):
            continue
        app.add_tool(_observer_guard(spec.fn, spec.name), name=spec.name)


def registered_tools(app: FastMCP) -> dict:
    """Read-only snapshot of the registered tools (name -> Tool), for
    tests and diagnostics."""
    return dict(app._tool_manager._tools)  # noqa: SLF001 - read-only view


def __getattr__(attr_name: str):
    # CORE_TOOLS derives from the declarations, so it is computed after
    # the tool modules have populated SPECS (see tools/__init__.py).
    if attr_name == "CORE_TOOLS":
        return core_tool_names()
    raise AttributeError(attr_name)
