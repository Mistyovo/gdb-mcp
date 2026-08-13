"""Shared fixtures for the test suite.

Loads ``gdb_mcp_plugin.py`` under a fake ``gdb`` module so the plugin logic
is fully testable on Windows without gdb.
"""

import importlib.util
import os
import sys
from pathlib import Path

import pytest

import mock_gdb

PLUGIN_PATH = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "gdb_mcp"
    / "plugin"
    / "gdb_mcp_plugin.py"
)

_ENV_VARS = (
    "GDB_MCP_AUTOSTART",
    "GDB_MCP_HOST",
    "GDB_MCP_SESSION_ID",
    "GDB_MCP_TOKEN",
    "GDB_MCP_PORT",
    "GDB_MCP_LOADED",
)


@pytest.fixture(scope="session")
def plugin_mod():
    saved = {var: os.environ.pop(var, None) for var in _ENV_VARS}
    os.environ["GDB_MCP_AUTOSTART"] = "0"  # no threads during tests
    sys.modules["gdb"] = mock_gdb
    spec = importlib.util.spec_from_file_location(
        "gdb_mcp_plugin_under_test", PLUGIN_PATH
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gdb_mcp_plugin_under_test"] = mod
    spec.loader.exec_module(mod)
    yield mod
    sys.modules.pop("gdb_mcp_plugin_under_test", None)
    sys.modules.pop("gdb", None)
    for var, value in saved.items():
        if value is None:
            os.environ.pop(var, None)
        else:
            os.environ[var] = value


@pytest.fixture
def mock_env(plugin_mod):
    mock_gdb.reset()
    return mock_gdb


@pytest.fixture
def plugin(plugin_mod, mock_env):
    return plugin_mod.Plugin()
