"""Shared helpers for MCP tool modules."""

from __future__ import annotations

from typing import Any

from gdb_mcp.config import Config
from gdb_mcp.context import ServerContext
from gdb_mcp.errors import InferiorRunningError, SessionStateError
from gdb_mcp.sessions import EXITED, RUNNING, Session, SessionRegistry


def server_ctx(ctx: Any) -> ServerContext:
    """The :class:`ServerContext` behind a FastMCP ``Context``."""
    return ctx.request_context.lifespan_context


def registry_from(ctx: Any) -> SessionRegistry:
    return server_ctx(ctx).registry


def analysis_from(ctx: Any):
    """The 3.5 static-bridge analysis manager (Ghidra headless cache)."""
    return server_ctx(ctx).analysis


def config_from(ctx: Any) -> Config:
    return server_ctx(ctx).config


def audit_from(ctx: Any):
    """The hash-chained security audit log (no-op instance when disabled)."""
    audit = getattr(server_ctx(ctx), "audit", None)
    if audit is None:
        from gdb_mcp.audit import disabled

        audit = disabled()
    return audit


def launcher_from(ctx: Any):
    """The process launcher (lazily built on the shared context)."""
    return server_ctx(ctx).launcher()


def resolve_gdb(ctx: Any, session_id: str | None) -> Session:
    return registry_from(ctx).resolve(session_id, kind="gdb")


def resolve_any(ctx: Any, session_id: str | None) -> Session:
    return registry_from(ctx).resolve(session_id, kind=None)


def check_stopped(session: Session) -> None:
    """Reject operations that require the inferior to be stopped (both
    state queries and resume requests)."""
    if session.state == RUNNING:
        raise InferiorRunningError()
    if session.state == EXITED:
        raise SessionStateError(
            "EXITED",
            "inferior has exited; restart the inferior before debugging further",
        )


def parse_hex_addr(text: str | None) -> int | None:
    """Parse a hex address string like ``0x401000``."""
    if not text:
        return None
    try:
        return int(str(text), 16)
    except ValueError:
        return None
