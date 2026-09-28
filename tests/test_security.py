"""Tests for gdb_mcp.security unsafe-command gating.

The in-gdb plugin deliberately carries its own stdlib-only copy of this
gate (so the rule also holds for a plugin driven without this server), and
the two copies are checked against each other here: a drift between them is
a security hole, not a style problem.
"""

import pytest

from gdb_mcp.security import UNSAFE_COMMAND_PREFIXES, is_unsafe_gdb_command

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
]


class TestIsUnsafeGdbCommand:
    @pytest.mark.parametrize("command", UNSAFE)
    def test_unsafe(self, command):
        assert is_unsafe_gdb_command(command) is True

    @pytest.mark.parametrize("command", SAFE)
    def test_safe(self, command):
        assert is_unsafe_gdb_command(command) is False


class TestPluginCopyAgrees:
    @pytest.fixture(autouse=True)
    def _plugin(self, plugin_mod):
        self.plugin = plugin_mod

    def test_prefix_tables_match(self):
        assert self.plugin._UNSAFE_PREFIXES == UNSAFE_COMMAND_PREFIXES

    @pytest.mark.parametrize("command", UNSAFE + SAFE)
    def test_verdicts_match(self, command):
        assert self.plugin._is_unsafe_command(command) == is_unsafe_gdb_command(
            command
        )
