"""Safety gating for gdb CLI commands.

The ``execute_command`` escape hatch intentionally exposes the full gdb
CLI — which includes commands that escape the debugger entirely (``shell``,
``!``, ``pipe``, ``python``, ``source``). These are blocked unless the
operator opts in via ``GDB_MCP_ALLOW_UNSAFE=1`` / ``--allow-unsafe``.

This module is the reference for the prefix rules; the in-gdb plugin
carries a stdlib-only copy of the same list so the gate holds even when
requests bypass the MCP server.
"""

from __future__ import annotations

#: (prefix, needs_word_boundary). "!" blocks anything starting with it;
#: "-" counts as a boundary so "python" also matches "python-interactive"
#: and "pi" matches "pi-…" abbreviations.
UNSAFE_COMMAND_PREFIXES: tuple[tuple[str, bool], ...] = (
    ("shell", True),
    ("!", False),
    ("pipe", True),
    ("python", True),
    ("python-interactive", True),
    ("pi", True),
    ("source", True),
)


def is_unsafe_gdb_command(command: str) -> bool:
    """True when the command can execute code outside the debugger."""
    text = str(command).lstrip().lower()
    if not text:
        return False
    for prefix, needs_boundary in UNSAFE_COMMAND_PREFIXES:
        if not text.startswith(prefix):
            continue
        if not needs_boundary:
            return True
        rest = text[len(prefix) :]
        if rest == "" or rest[0] in (" ", "\t", "-"):
            return True
    return False
