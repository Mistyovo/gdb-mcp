import json

import pytest

from gdb_mcp.config import Config
from gdb_mcp.protocol import validate_plugin_message
from gdb_mcp.reverse.ghidra import GhidraRunner
from gdb_mcp.sessions import SessionRegistry

from test_sessions import FakeWriter, hello


@pytest.mark.asyncio
async def test_target_notification_is_recorded_on_session():
    """Adapted for main: the registry has no broker wiring, but target
    notifications are protocol-valid and land in the event ring."""
    registry = SessionRegistry(Config())
    session = registry.register_hello(hello(inferior="/tmp/old"), FakeWriter())
    await session.push_notification("target", {"path": "/tmp/new"})
    events = [e["event"] for e in session.recent_events(10)]
    assert "target" in events
    assert session.recent_events(1)[0]["payload"] == {"path": "/tmp/new"}


def test_target_notification_is_protocol_valid():
    validate_plugin_message(
        {"type": "notification", "event": "target", "payload": {"path": "/tmp/a"}}
    )


@pytest.mark.asyncio
async def test_ghidra_command_places_processor_before_import(tmp_path, monkeypatch):
    cfg = Config(analysis_timeout=10, decompile_timeout=3)
    runner = GhidraRunner(cfg)
    captured = []

    async def detect(distro=None):
        return "/opt/ghidra/analyzeHeadless", distro

    async def execute(argv, distro, timeout):
        captured.append(argv)
        (tmp_path / "index.json").write_text(json.dumps({"functions": []}), encoding="utf-8")
        return 0, b"ok", b""

    monkeypatch.setattr(runner, "detect", detect)
    monkeypatch.setattr(runner, "_exec", execute)
    await runner.analyze(
        "/tmp/sample", tmp_path, "a-0123456789abcdef", None, "x86:LE:64:default"
    )
    argv = captured[0]
    assert argv.index("-processor") < argv.index("-import")
    assert argv[argv.index("-processor") + 1] == "x86:LE:64:default"
    assert argv[-1] == "-deleteProject"


@pytest.mark.asyncio
async def test_ghidra_detect_executes_posix_test(monkeypatch):
    runner = GhidraRunner(
        Config(ghidra_headless="/opt/ghidra/headless", wsl_distro="kali-linux")
    )
    seen = []

    async def execute(argv, distro, timeout):
        seen.append(argv)
        return 0, b"", b""

    monkeypatch.setattr(runner, "_exec", execute)
    executable, _ = await runner.detect()
    assert executable == "/opt/ghidra/headless"
    assert seen == [["test", "-x", "/opt/ghidra/headless"]]
