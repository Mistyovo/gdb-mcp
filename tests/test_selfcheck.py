"""Tests for the read-only launcher self-check (no gdb required)."""

from __future__ import annotations

import json

import pytest

from gdb_mcp.config import Config
from gdb_mcp.selfcheck import run_selfcheck


def _config(tmp_path, **extra):
    return Config(launcher="native", log_dir=tmp_path / "logs", **extra)


def _ready_probe(responses=None):
    async def probe(gdb, distro=None):
        return {
            "version": "GNU gdb (test) 1.0",
            "embedded_python": "3.12.0",
            "pwndbg": True,
            "error": None,
        }

    return probe


@pytest.mark.asyncio
async def test_ready_native_host(tmp_path):
    plugin = tmp_path / "gdb_mcp_plugin.py"
    plugin.write_text("# plugin", encoding="utf-8")
    cfg = _config(tmp_path)
    result = await run_selfcheck(
        cfg,
        which=lambda name: "/usr/bin/gdb",
        probe=_ready_probe(),
        port_check=lambda config: (True, None),
        plugin=plugin,
    )
    assert result["ready"] is True
    assert result["gdb"]["path"] == "/usr/bin/gdb"
    assert result["gdb"]["embedded_python"] == "3.12.0"
    assert result["gdb"]["pwndbg"] is True
    assert result["plugin"]["present"] is True
    assert result["issues"] == []
    json.dumps(result)


@pytest.mark.asyncio
async def test_configured_gdb_path_is_used_and_missing_is_reported(tmp_path):
    plugin = tmp_path / "plugin.py"
    plugin.write_text("", encoding="utf-8")
    cfg = _config(tmp_path, gdb_path="/opt/gdb/bin/gdb")
    result = await run_selfcheck(
        cfg,
        probe=_ready_probe(),
        port_check=lambda config: (True, None),
        plugin=plugin,
    )
    assert result["gdb"]["path"] == "/opt/gdb/bin/gdb"
    assert result["ready"] is False
    assert "GDB_NOT_FOUND" in {issue["code"] for issue in result["issues"]}

    cfg = _config(tmp_path)
    result = await run_selfcheck(
        cfg,
        which=lambda name: None,
        probe=_ready_probe(),
        port_check=lambda config: (True, None),
        plugin=plugin,
    )
    assert result["ready"] is False
    assert "GDB_NOT_FOUND" in {issue["code"] for issue in result["issues"]}


@pytest.mark.asyncio
async def test_python_less_gdb_fails_the_check(tmp_path):
    plugin = tmp_path / "plugin.py"
    plugin.write_text("", encoding="utf-8")

    async def probe(gdb, distro=None):
        return {
            "version": "GNU gdb 1.0",
            "embedded_python": None,
            "pwndbg": None,
            "error": None,
        }

    result = await run_selfcheck(
        _config(tmp_path),
        which=lambda name: "gdb",
        probe=probe,
        port_check=lambda config: (True, None),
        plugin=plugin,
    )
    assert result["ready"] is False
    assert "GDB_PYTHON_UNAVAILABLE" in {
        issue["code"] for issue in result["issues"]
    }


@pytest.mark.asyncio
async def test_busy_port_and_missing_plugin_are_blocking(tmp_path):
    cfg = _config(tmp_path)
    result = await run_selfcheck(
        cfg,
        which=lambda name: "gdb",
        probe=_ready_probe(),
        port_check=lambda config: (False, "address in use"),
        plugin=tmp_path / "missing.py",
    )
    assert result["ready"] is False
    codes = {issue["code"] for issue in result["issues"]}
    assert {"PORT_UNAVAILABLE", "PLUGIN_MISSING"} <= codes


@pytest.mark.asyncio
async def test_probe_failure_is_reported(tmp_path):
    plugin = tmp_path / "plugin.py"
    plugin.write_text("", encoding="utf-8")

    async def probe(gdb, distro=None):
        return {
            "version": None,
            "embedded_python": None,
            "pwndbg": None,
            "error": "gdb: not executable",
        }

    result = await run_selfcheck(
        _config(tmp_path),
        which=lambda name: "gdb",
        probe=probe,
        port_check=lambda config: (True, None),
        plugin=plugin,
    )
    assert result["ready"] is False
    assert "GDB_PROBE_FAILED" in {issue["code"] for issue in result["issues"]}


def test_selfcheck_flag_is_cli_only():
    from gdb_mcp.__main__ import _build_parser

    assert _build_parser().parse_args(["--selfcheck"]).selfcheck is True
    assert _build_parser().parse_args([]).selfcheck is False


@pytest.mark.asyncio
async def test_wsl_branch_reports_distro_issues(tmp_path):
    plugin = tmp_path / "plugin.py"
    plugin.write_text("", encoding="utf-8")

    from gdb_mcp.wsl import WslError

    async def wsl_error():
        raise WslError("wsl.exe was not found; install or enable WSL")

    async def empty_distros():
        return []

    cfg = Config(launcher="wsl", log_dir=tmp_path / "logs")
    result = await run_selfcheck(
        cfg,
        probe=_ready_probe(),
        port_check=lambda config: (True, None),
        plugin=plugin,
        distros=wsl_error,
    )
    assert result["ready"] is False
    assert "WSL_UNAVAILABLE" in {issue["code"] for issue in result["issues"]}

    result = await run_selfcheck(
        cfg,
        probe=_ready_probe(),
        port_check=lambda config: (True, None),
        plugin=plugin,
        distros=empty_distros,
    )
    assert "WSL_NO_DISTRO" in {issue["code"] for issue in result["issues"]}
