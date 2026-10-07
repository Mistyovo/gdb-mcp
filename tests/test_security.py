"""Tests for gdb_mcp.security unsafe-command gating.

The in-gdb plugin deliberately carries its own stdlib-only copy of this
gate (so the rule also holds for a plugin driven without this server), and
the two copies are checked against each other here: a drift between them is
a security hole, not a style problem.

The abbreviation cases are not speculation — gdb really resolves "she" to
shell, "py" to python, "so" to source, while "s"/"r"/"p"/"d" resolve to
step/run/print/delete. ``tests/integration/run_unsafe_gate_probe.sh``
keeps those premises verified against real gdb in CI.
"""

import pytest

from gdb_mcp.security import SAFE_ABBREVIATIONS, UNSAFE_COMMAND_ROOTS, is_unsafe_gdb_command

UNSAFE = [
    "shell pwd",
    "shell",
    "  shell pwd",
    "SHELL pwd",
    "!id",
    "!",
    "pipe print x | wc -c",
    "python import os",
    "python-interactive",
    "pi 1+1",
    "pi",
    "source /tmp/script.gdb",
    "python-",
    # --- abbreviations (audit 2026-10-07; gdb resolves these) ---
    "she echo pwned",  # "she" IS shell
    "py print(1)",  # "py" IS python
    "sou /tmp/x",  # "sou" IS source
    "so /tmp/x",  # even "so" resolves to source
    "pyt print(1)",
    "rest /tmp/core.dump",  # restore reads a host file into memory
    "dump binary memory /tmp/out 0x0 0x10",
    "du binary memory /tmp/out 0x0 0x10",
    "make",
    "ma",
    "def x",
    "alias pw = shell",
    "al pw = shell",
    "set logging file /etc/cron.d/backdoor",
    "set logging on",
    "set log on",  # subcommand abbreviation
    "set exec-wrapper env LD_PRELOAD=/tmp/x.so",
    "set exec-wrap env A=B",
    "se logging on",  # first-word abbreviation still reaches the root
    # --- host file writes / auto-load chain (audit 2026-10-07 round 2) ---
    "append binary memory /home/u/.bashrc 0x1000 0x1010",
    "app value w /tmp/out $rsp",  # "app" IS append (no other app* command)
    "append binary value /tmp/out 1",
    "document helper",  # pairs with define; body is gdb commands
    "doc helper",
    "add-auto-load-safe-path /",  # whitelists ELF-embedded script loading
    "add-auto /",
    "add-auto-load-scripts-directory /tmp/hostile",  # second root of the
    # same family (real gdb: "add-auto" is ambiguous between the two)
    "set auto-load python-scripts on",  # hostile .debug_gdb_scripts chain
    "set auto-load scripts-directory /",
    "set auto-lo safe-path /",
    "set startup-with-shell on",  # `run` gains $(cmd) / > file via /bin/sh
    "set startup-with-sh off",  # both directions gated, like exec-wrapper
    # --- multi-line injection: only the 2nd line is unsafe ---
    "info registers\nshell id",
    "x/4gx $rsp\npy import os",
    "step\n\nsource /tmp/x",
]

SAFE = [
    "",
    "x/4gx $rsp",
    "continue",
    "info proc mappings",
    "shellfish print",  # word boundary: not the shell command
    "pipeline print",  # boundary: not the pipe command
    "vmmap",
    "heap bins",
    "quit",
    # --- single-letter canonical commands (verified on real gdb) ---
    "s",  # step, never shell/source
    "r",  # run, never restore
    "p $rsp",  # print, never python/pipe
    "d 3",  # delete, never dump/define
    # --- other common commands that share prefix space with roots ---
    "del 3",  # delete: not define
    "step",
    "set args loop",  # "set" with an ungated subcommand
    "set $pc = 0x401000",
    "set breakpoint pending on",
    "set pagination off",
    "sharedlibrary",  # shares "sh" but is its own full command
    "show logging",
    "delete breakpoints",
    "return",
    "run",
    # --- share prefix space with the 2026-10-07 additions ---
    "attach 123",  # "at" is attach, not append
    "appr on",  # apropos: "appr" does not prefix-match append
    "add-symbol-file /tmp/x 0x401000",  # not add-auto-load-safe-path
    "show auto-load python-scripts",  # show, never set
    "display/x $pc",  # "dis" is display/disable, not document
]


class TestIsUnsafeGdbCommand:
    @pytest.mark.parametrize("command", UNSAFE)
    def test_unsafe(self, command):
        assert is_unsafe_gdb_command(command) is True

    @pytest.mark.parametrize("command", SAFE)
    def test_safe(self, command):
        assert is_unsafe_gdb_command(command) is False


class TestUnsafeGatePremises:
    def test_roots_table_shape(self):
        # multi-word roots must be lowercase with single spaces so the
        # token matcher's split() agrees with them
        for root in UNSAFE_COMMAND_ROOTS:
            assert root == root.lower()
            assert "  " not in root
            assert root == root.strip()

    def test_safe_abbreviations_are_single_letters(self):
        assert all(len(a) == 1 for a in SAFE_ABBREVIATIONS)


class TestPluginCopyAgrees:
    @pytest.fixture(autouse=True)
    def _plugin(self, plugin_mod):
        self.plugin = plugin_mod

    def test_root_tables_match(self):
        assert self.plugin._UNSAFE_ROOTS == UNSAFE_COMMAND_ROOTS

    def test_safe_abbreviations_match(self):
        assert self.plugin._SAFE_ABBREVIATIONS == SAFE_ABBREVIATIONS

    @pytest.mark.parametrize("command", UNSAFE + SAFE)
    def test_verdicts_match(self, command):
        assert self.plugin._is_unsafe_command(command) == is_unsafe_gdb_command(
            command
        )
