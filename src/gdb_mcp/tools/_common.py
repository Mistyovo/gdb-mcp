"""Shared helpers for MCP tool modules."""

from __future__ import annotations

from typing import Any

from gdb_mcp.config import Config
from gdb_mcp.errors import InferiorRunningError, SessionStateError
from gdb_mcp.sessions import EXITED, RUNNING, Session, SessionRegistry


def registry_from(ctx: Any) -> SessionRegistry:
    return ctx.request_context.lifespan_context["registry"]


def analysis_from(ctx: Any):
    """The 3.5 static-bridge analysis manager (Ghidra headless cache)."""
    return ctx.request_context.lifespan_context["analysis"]


def config_from(ctx: Any) -> Config:
    return ctx.request_context.lifespan_context["config"]


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
