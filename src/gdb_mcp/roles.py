"""Per-request client roles for the HTTP transport (D2 multiplexing).

A controller token drives everything; observer tokens (configured via
``GDB_MCP_OBSERVER_TOKENS`` / ``--observer-token``) may attach to the
same sessions read-only. The registry derives the gate from each tool's
declared capability: only ``observe`` tools are callable; every other
capability raises ``OBSERVER_READONLY``. New tools are therefore
observer-invisible by default unless they declare ``capability="observe"``.

``OBSERVER_ALLOWED_TOOLS`` is the smoke-test contract for the default
``pwn`` profile's observe surface (the capability declarations remain the
source of truth).
"""

from __future__ import annotations

from contextvars import ContextVar

CURRENT_ROLE: ContextVar[str] = ContextVar("gdb_mcp_client_role", default="controller")

#: The observe-only surface of the default (pwn) profile. The registry
#: itself derives the observer gate from each tool's declared capability;
#: this set is the smoke-test contract for that surface (a name here that
#: is not actually registered, or a declared-observe tool missing here,
#: means the two views drifted).
OBSERVER_ALLOWED_TOOLS = frozenset(
    {
        "list_sessions",
        "session_status",
        "get_events",
        "get_process_output",
        "read_memory",
        "read_registers",
        "get_backtrace",
        "disassemble",
        "list_threads",
        "get_memory_map",
        "list_breakpoints",
        "heap_bins",
        "crash_report",
        "read_result",
        "diff_sessions",
        "wait_for_stop",
    }
)
