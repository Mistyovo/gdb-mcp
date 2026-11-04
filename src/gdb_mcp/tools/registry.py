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
from gdb_mcp.roles import CURRENT_ROLE

#: What a tool is allowed to affect. ``observe`` is the only capability a
#: read-only client (``--readonly`` / observer role) may use; ``host`` and
#: ``admin`` tools can execute code or lifecycle actions outside the
#: inferior and are controller-only.
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
    #: optional extension family ("static", ...); only registered in the
    #: full tool profile
    extension: str | None = None


SPECS: list[ToolSpec] = []


def tool(
    *,
    core: bool = False,
    capability: str = "observe",
    experimental: bool = False,
    extension: str | None = None,
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
                extension=extension,
            )
        )
        return fn

    return deco


def core_tool_names() -> frozenset[str]:
    return frozenset(
        spec.name for spec in SPECS if spec.core and not spec.experimental
    )


def observe_tool_names() -> frozenset[str]:
    """The observe-only surface shared by --readonly and observer clients."""
    return frozenset(spec.name for spec in SPECS if spec.capability == "observe")


def _deny_observer(name: str, audit=None) -> None:
    if audit is not None:
        audit.record("observer_denied", tool=name)
    raise GdbMcpError(
        "OBSERVER_READONLY",
        "tool %r is not available to observer clients" % name,
    )


def _observer_guard(fn: Callable, name: str, audit=None) -> Callable:
    """Wrap ``fn`` so observer-role calls are rejected.

    ``functools.wraps`` is what makes this safe to register in place of
    the original: it exposes the wrapped signature (which is what FastMCP
    builds the JSON schema from) and keeps the coroutine/sync kind.
    """
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def guarded(*args: Any, **kwargs: Any) -> Any:
            if CURRENT_ROLE.get() == "observer":
                _deny_observer(name, audit)
            return await fn(*args, **kwargs)

    else:

        @functools.wraps(fn)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            if CURRENT_ROLE.get() == "observer":
                _deny_observer(name, audit)
            return fn(*args, **kwargs)

    return guarded


def _visible(spec: ToolSpec, config: Config) -> bool:
    if spec.experimental and not config.experimental:
        return False
    if config.tool_profile == "core" and not spec.core:
        return False
    # extension families (static analysis) are opt-in via the full profile
    if spec.extension and config.tool_profile != "full":
        return False
    if config.readonly and spec.capability != "observe":
        return False
    return True


def register_all(app: FastMCP, ctx: ServerContext) -> None:
    """Register every visible tool declared across the tool modules."""
    audit = getattr(ctx, "audit", None)
    for spec in SPECS:
        if not _visible(spec, ctx.config):
            continue
        fn = (
            spec.fn
            if spec.capability == "observe"
            else _observer_guard(spec.fn, spec.name, audit)
        )
        app.add_tool(fn, name=spec.name)


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
