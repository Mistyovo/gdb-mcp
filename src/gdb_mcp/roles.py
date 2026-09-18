"""Per-request client roles for the HTTP transport (D2 multiplexing).

A controller token drives everything; observer tokens (configured via
``GDB_MCP_OBSERVER_TOKENS`` / ``--observer-token``) may attach to the
same sessions read-only — every tool outside
``OBSERVER_ALLOWED_TOOLS`` raises ``OBSERVER_READONLY`` for them.
The allowlist is default-deny: tools added later are observer-invisible
until explicitly listed, which is the safe direction for new tools.
"""

from __future__ import annotations

from contextvars import ContextVar

CURRENT_ROLE: ContextVar[str] = ContextVar("gdb_mcp_client_role", default="controller")

OBSERVER_ALLOWED_TOOLS = frozenset(
    {
        "list_sessions",
        "session_status",
        "get_events",
        "get_stop_reason",
        "get_process_output",
        "read_memory",
        "read_registers",
        "get_backtrace",
        "disassemble",
        "evaluate",
        "list_threads",
        "select_frame",
        "get_memory_map",
        "load_target",
        "list_breakpoints",
        "heap_bins",
        "crash_report",
        "export_session_script",
        "read_result",
        "diff_sessions",
    }
)


def observer_allowed(tool_name: str) -> bool:
    return tool_name in OBSERVER_ALLOWED_TOOLS
