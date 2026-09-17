"""Tests for gdb_mcp.security unsafe-command gating."""

import pytest

from gdb_mcp.security import is_unsafe_gdb_command


class TestIsUnsafeGdbCommand:
    @pytest.mark.parametrize(
        "command",
        [
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
        ],
    )
    def test_unsafe(self, command):
        assert is_unsafe_gdb_command(command) is True

    @pytest.mark.parametrize(
        "command",
        [
            "",
            "x/4gx $rsp",
            "continue",
            "info proc mappings",
            "shellfish print",  # word boundary: not the shell command
            "pipeline print",  # boundary: not the pipe command
            "vmmap",
            "heap bins",
            "quit",
        ],
    )
    def test_safe(self, command):
        assert is_unsafe_gdb_command(command) is False
