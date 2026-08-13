"""Error types for gdb-mcp.

All errors surfaced to MCP clients are raised as :class:`GdbMcpError` and
rendered as a single human-readable line (no tracebacks) by the tool layer.
``code`` is a stable machine-readable slug shared with the wire-protocol
error codes; ``message`` is human-readable.
"""

from __future__ import annotations


class GdbMcpError(Exception):
    """Base error for everything gdb-mcp reports to the client."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class ProtocolError(GdbMcpError):
    """Wire-protocol violation (malformed frame, bad handshake, ...)."""


class NoSuchSessionError(GdbMcpError):
    def __init__(self, session_id: str):
        super().__init__("NO_SESSION", f"no session with id {session_id!r}")


class AmbiguousSessionError(GdbMcpError):
    def __init__(self, sessions: list[str]):
        listing = ", ".join(sessions)
        super().__init__(
            "AMBIGUOUS_SESSION",
            f"multiple sessions exist; pass session_id explicitly ({listing})",
        )


class NoSessionsError(GdbMcpError):
    def __init__(self, hint: str = ""):
        msg = "no gdb session connected"
        if hint:
            msg += f"; {hint}"
        super().__init__("NO_SESSION", msg)


class SessionStateError(GdbMcpError):
    """Operation invalid in the session's current state."""


class InferiorRunningError(SessionStateError):
    def __init__(self):
        super().__init__(
            "INFERIOR_RUNNING",
            "inferior is running; interrupt first or wait for it to stop",
        )


class NoInferiorError(SessionStateError):
    def __init__(self):
        super().__init__(
            "NO_INFERIOR",
            "no inferior loaded; use load_target or execute_command('file <path>') first",
        )


class RequestTimeoutError(GdbMcpError):
    def __init__(self, verb: str, timeout: float):
        super().__init__(
            "TIMEOUT", f"request {verb!r} timed out after {timeout:.1f}s"
        )


class LaunchError(GdbMcpError):
    def __init__(self, message: str):
        super().__init__("LAUNCH_FAILED", message)


def error_from_response(err: dict) -> GdbMcpError:
    """Build a :class:`GdbMcpError` from a plugin error object
    (``{"code": ..., "message": ...}``)."""
    code = err.get("code", "PLUGIN_ERROR")
    message = err.get("message", "unknown plugin error")
    return GdbMcpError(code, message)
