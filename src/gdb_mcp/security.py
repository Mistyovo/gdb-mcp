"""Safety gating for gdb CLI commands.

The ``execute_command`` escape hatch intentionally exposes the full gdb
CLI — which includes commands that escape the debugger entirely (``shell``,
``!``, ``pipe``, ``python``, ``source``, …). These are blocked unless the
operator opts in via ``GDB_MCP_ALLOW_UNSAFE=1`` / ``--allow-unsafe``.

Two properties the matcher must hold (both verified against real gdb
12/15/17, see ``tests/integration/run_unsafe_gate_probe.sh``):

* **Abbreviation-aware.** gdb resolves any unambiguous prefix to a full
  command: ``she id`` IS ``shell id``, ``py`` IS ``python``, ``so`` IS
  ``source``. Matching only exact prefixes let those slip the gate. The
  four single-letter canonical commands (``s``→step, ``r``→run,
  ``p``→print, ``d``→delete) win over any unsafe root sharing their
  letter and are exempted explicitly.
* **Per-line.** One command string can carry several gdb commands
  separated by newlines (``"info registers\\nshell id"``); checking only
  the first line's first word let the second line escape.

This is a best-effort blacklist of the *documented* escape commands —
gdb's command space is too large for a closed-form guarantee; the
deliberate escape hatch for everything else is ``--allow-unsafe``.

This module is the reference implementation; the in-gdb plugin carries a
stdlib-only copy of the same rules so the gate holds even when requests
bypass the MCP server (parity-tested in ``tests/test_security.py``).
"""

from __future__ import annotations

#: gdb command roots that execute code or touch files OUTSIDE the
#: debugger. Multi-word roots gate their subcommand ("set" alone is fine;
#: "set logging …" / "set exec-wrapper …" are not).
UNSAFE_COMMAND_ROOTS: tuple[str, ...] = (
    "shell",
    "!",
    "pipe",
    "python",
    "python-interactive",
    "source",
    "make",  # runs the build system on the host
    "define",  # defines a command whose body runs later, ungated
    "document",  # pairs with define; body lines are gdb commands
    "alias",  # can alias any root above to an innocent-looking name
    "dump",  # dump binary memory …: arbitrary host file write
    "append",  # append binary memory/value …: host file write (audit P1)
    "restore",  # reads a host file into inferior memory (exfil path)
    "add-auto-load-safe-path",  # whitelists gdb-script auto-loading (see
    # the "set auto-load" root below for the chain this enables)
    "add-auto-load-scripts-directory",  # same family: adds hostile-path
    # script search directories (verified on real gdb: the add-auto
    # prefix is ambiguous between exactly these two commands)
    "set logging",  # set logging file/on: arbitrary host file write
    "set exec-wrapper",  # wrapper runs as a host shell command on `run`
    "set auto-load",  # set auto-load python-scripts on + a hostile ELF's
    # .debug_gdb_scripts section = gdb-embedded python execution on the
    # HOST; also gates scripts-directory/safe-path (off included — use
    # --allow-unsafe to harden deliberately)
    "set startup-with-shell",  # off-mutating too, like exec-wrapper: `run`
    # under startup-with-shell=on gives shell redirects $(cmd) and >
    # file host writes through the inferior's /bin/sh -c (audit P2)
)

#: single-letter commands gdb resolves to step/run/print/delete BEFORE
#: any unsafe root sharing the letter ("s" is never shell/source, "r" is
#: never restore, "p" is never python/pipe, "d" is never dump/define).
#: Empirically verified; the gate must not block them.
SAFE_ABBREVIATIONS: frozenset[str] = frozenset({"s", "r", "p", "d"})


def is_unsafe_gdb_command(command: str) -> bool:
    """True when the command can execute code outside the debugger."""
    for line in str(command).splitlines():
        tokens = [t.lower() for t in line.split()]
        if tokens and _tokens_hit_unsafe_root(tokens):
            return True
    return False


def _tokens_hit_unsafe_root(tokens: list[str]) -> bool:
    first = tokens[0]
    if first.startswith("!"):
        return True
    if first in SAFE_ABBREVIATIONS:
        return False
    for root in UNSAFE_COMMAND_ROOTS:
        root_tokens = root.split()
        if len(root_tokens) == 1:
            # `first` abbreviates the root (or is the root): "she" ⊑ shell,
            # "sou" ⊑ source. Longer strings ("shellfish", "pipeline") are
            # different commands and stay allowed.
            if root.startswith(first):
                return True
        else:
            head, sub = root_tokens
            if head != first and not head.startswith(first):
                continue
            rest = tokens[1:]
            # "set" alone, or "set <anything-else>", is a normal command;
            # only the gated subcommand (or its abbreviation) hits
            if rest and (sub == rest[0] or sub.startswith(rest[0])):
                return True
    return False
