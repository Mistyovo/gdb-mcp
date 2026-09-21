import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

import pytest

from gdb_mcp.config import Config
from gdb_mcp.errors import GdbMcpError
from gdb_mcp.events import EventBroker
from gdb_mcp.reverse.manager import AnalysisManager, AnalysisRecord
from gdb_mcp.sessions import RUNNING, STOPPED, Session


def make_index(image_base="0x400000", entry="0x401000"):
    return {
        "schema_version": 2,
        "binary": {"name": "sample", "format": "ELF", "image_base": image_base},
        "sections": [{"name": ".text", "start": entry, "end": "0x401020"}],
        "symbols": [{"name": "main", "address": entry, "kind": "export"}],
        "strings": [{"address": "0x402000", "value": "hello", "length": 6}],
        "functions": [
            {
                "entry": entry,
                "end": "0x401010",
                "name": "main",
                "decompiled": True,
                "external": False,
                "thunk": False,
            }
        ],
        "counts": {"functions": 1, "decompiled": 1, "failed": 0},
    }


def make_function(entry="0x401000"):
    return {
        "entry": entry,
        "end": "0x401010",
        "name": "main",
        "decompiled": True,
        "code": "int main(void) {\n  return 0;\n}",
        "lines": [
            {"number": 1, "text": "int main(void) {", "min": entry, "max": "0x401002"},
            {"number": 2, "text": "  return 0;", "min": "0x401003", "max": "0x401008"},
        ],
        "instructions": [{"address": entry, "bytes": "90", "text": "NOP"}],
        "callers": [],
        "callees": [],
        "xrefs_to": [],
        "xrefs_from": [],
    }


def ready_manager(tmp_path: Path, target="/tmp/sample", image_base="0x400000"):
    cfg = Config(analysis_dir=tmp_path)
    manager = AnalysisManager(cfg, EventBroker())
    analysis_id = "a-" + "1" * 16
    directory = tmp_path / analysis_id
    (directory / "functions").mkdir(parents=True)
    (directory / "index.json").write_text(json.dumps(make_index(image_base)), encoding="utf-8")
    (directory / "functions" / "401000.json").write_text(
        json.dumps(make_function()), encoding="utf-8"
    )
    (directory / "disassembly.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "instructions": [
                    {"address": "0x401000", "bytes": "90", "text": "NOP"},
                    {"address": "0x401018", "bytes": "c3", "text": "RET"},
                ],
            }
        ),
        encoding="utf-8",
    )
    (directory / "annotations.json").write_text("{}", encoding="utf-8")
    record = AnalysisRecord(
        analysis_id=analysis_id,
        sha256="1" * 64,
        source_path=target,
        target_path=target,
        distro="kali-linux",
        size=123,
        status="ready",
        function_count=1,
        decompiled_count=1,
    )
    manager._records[analysis_id] = record
    return manager, analysis_id


def test_queries_pagination_and_annotations(tmp_path):
    manager, analysis_id = ready_manager(tmp_path)
    assert manager.overview(analysis_id)["name"] == "sample"
    assert manager.list_items(analysis_id, "functions", "MAIN", 0, 10)["total"] == 1
    assert manager.decompile(analysis_id, "main")["effective_name"] == "main"
    saved = manager.annotate(analysis_id, "main", "entrypoint", "reviewed")
    assert saved["annotation"]["label"] == "entrypoint"
    assert manager.decompile(analysis_id, "entrypoint")["effective_name"] == "entrypoint"
    assert manager.remove_annotation(analysis_id, "entrypoint")["removed"] is True
    with pytest.raises(GdbMcpError, match="limit"):
        manager.list_items(analysis_id, "functions", limit=1001)


def test_indexes_and_function_files_are_cached(tmp_path, monkeypatch):
    manager, analysis_id = ready_manager(tmp_path)
    original = manager._read_json
    reads = []

    def tracked(path):
        reads.append(path.name)
        return original(path)

    monkeypatch.setattr(manager, "_read_json", tracked)
    manager.overview(analysis_id)
    manager.list_items(analysis_id, "functions")
    manager.decompile(analysis_id, "main")
    manager.decompile(analysis_id, "main")
    assert reads.count("index.json") == 1
    assert reads.count("401000.json") == 1


def test_static_disassembly_works_between_functions(tmp_path):
    manager, analysis_id = ready_manager(tmp_path)
    result = manager.static_disassembly(analysis_id, "0x401011", 10)
    assert result["instructions"] == [
        {"address": "0x401018", "bytes": "c3", "text": "RET"}
    ]


def test_path_matching_preserves_posix_case(tmp_path):
    manager, analysis_id = ready_manager(tmp_path, target="/tmp/App")
    assert manager.analysis_for_module("/tmp/App") == analysis_id
    assert manager.analysis_for_module("/tmp/app") is None
    assert manager._path_key("C:\\Temp\\App") == manager._path_key("c:/temp/app")


def test_concurrent_annotations_do_not_lose_updates(tmp_path):
    manager, analysis_id = ready_manager(tmp_path)

    def save(number):
        manager.annotate(analysis_id, 0x401000 + number, "label_%d" % number, None)

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(save, range(24)))
    annotations = manager.annotations(analysis_id)
    assert len(annotations) == 24
    assert annotations["0x401017"]["label"] == "label_23"


def test_pie_location_and_nearest_line(tmp_path):
    manager, analysis_id = ready_manager(tmp_path)
    session = Session("s-1", state=STOPPED, analysis_id=analysis_id)
    session.stop_info = {
        "pc": "0x55556003",
        "module_path": "/tmp/sample",
        "module_base": "0x55555000",
        "module_offset": "0x1003",
    }
    location = manager.resolve_session_location(session)
    assert location["static_address"] == "0x401003"
    assert location["function"] == "main"
    assert location["line"] == 2
    assert location["exact"] is True


def test_location_prefers_analyzed_text_frame_over_unindexed_stop(tmp_path):
    manager, analysis_id = ready_manager(tmp_path)
    session = Session("s-1", state=STOPPED, analysis_id=analysis_id, target="/tmp/sample")
    session.stop_info = {
        "pc": "0x7ffff7e12345",
        "module_path": "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "module_base": "0x7ffff7d00000",
        "module_offset": "0x112345",
    }
    session.debug_state = {
        "frames": [
            {
                "level": 0,
                **session.stop_info,
            },
            {
                "level": 1,
                "pc": "0x55556003",
                "module_path": "/tmp/sample",
                "module_base": "0x55555000",
                "module_offset": "0x1003",
            },
        ]
    }

    location = manager.resolve_session_location(session)

    assert location["function"] == "main"
    assert location["frame_level"] == 1
    assert location["actual_stop"] is False
    assert location["stop_runtime_pc"] == "0x7ffff7e12345"
    assert session.debug_state["stop_location"]["module"].endswith("libc.so.6")


def test_function_prologue_falls_forward_to_first_mapped_line(tmp_path):
    manager, analysis_id = ready_manager(tmp_path)
    function_path = tmp_path / analysis_id / "functions" / "401000.json"
    function = json.loads(function_path.read_text(encoding="utf-8"))
    function["lines"][0].update({"min": "0x401005", "max": "0x401006"})
    function["lines"][1].update({"min": "0x401007", "max": "0x401008"})
    function_path.write_text(json.dumps(function), encoding="utf-8")
    session = Session("s-1", state=STOPPED, analysis_id=analysis_id)
    session.stop_info = {
        "pc": "0x55556000",
        "module_path": "/tmp/sample",
        "module_base": "0x55555000",
        "module_offset": "0x1000",
    }
    location = manager.resolve_session_location(session)
    assert location["line"] == 1
    assert location["exact"] is False


def test_unindexed_library_does_not_use_main_analysis(tmp_path):
    manager, analysis_id = ready_manager(tmp_path)
    session = Session("s-1", state=STOPPED, analysis_id=analysis_id)
    session.stop_info = {
        "pc": "0x7ffff7e01000",
        "module_path": "/usr/lib/libc.so.6",
        "module_base": "0x7ffff7c00000",
        "module_offset": "0x201000",
    }
    location = manager.resolve_session_location(session)
    assert location["analysis_id"] is None
    assert "static_address" not in location


def test_indexed_library_uses_its_own_analysis(tmp_path):
    manager, main_id = ready_manager(tmp_path)
    library_id = "a-" + "2" * 16
    library_dir = tmp_path / library_id
    (library_dir / "functions").mkdir(parents=True)
    (library_dir / "index.json").write_text(json.dumps(make_index()), encoding="utf-8")
    (library_dir / "functions" / "401000.json").write_text(
        json.dumps(make_function()), encoding="utf-8"
    )
    (library_dir / "annotations.json").write_text("{}", encoding="utf-8")
    manager._records[library_id] = AnalysisRecord(
        analysis_id=library_id,
        sha256="2" * 64,
        source_path="/usr/lib/libsample.so",
        target_path="/usr/lib/libsample.so",
        distro="kali-linux",
        size=456,
        status="ready",
    )
    session = Session("s-1", state=STOPPED, analysis_id=main_id)
    session.stop_info = {
        "pc": "0x7f001003",
        "module_path": "/usr/lib/libsample.so",
        "module_base": "0x7f000000",
        "module_offset": "0x1003",
    }
    location = manager.resolve_session_location(session)
    assert location["analysis_id"] == library_id
    assert location["function"] == "main"


def test_running_location_is_stale(tmp_path):
    manager, analysis_id = ready_manager(tmp_path)
    session = Session("s-1", state=STOPPED, analysis_id=analysis_id)
    session.stop_info = {
        "pc": "0x401003",
        "module_path": "/tmp/sample",
        "module_base": "0x400000",
        "module_offset": "0x1003",
    }
    manager.resolve_session_location(session)
    session.state = RUNNING
    session.location["state"] = RUNNING
    session.location["stale"] = True
    assert manager.resolve_session_location(session)["stale"] is True


@pytest.mark.asyncio
async def test_queue_deduplicates_and_promotes_staging(tmp_path, monkeypatch):
    cfg = Config(analysis_dir=tmp_path)
    manager = AnalysisManager(cfg, EventBroker())
    digest = "a" * 64
    calls = 0

    async def fingerprint(path, distro=None):
        return digest, 10, "kali-linux", "/tmp/sample"

    async def analyze(binary_path, output_dir, analysis_id, distro, language_id=None):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.01)
        (output_dir / "functions").mkdir()
        (output_dir / "index.json").write_text(json.dumps(make_index()), encoding="utf-8")
        (output_dir / "functions" / "401000.json").write_text(
            json.dumps(make_function()), encoding="utf-8"
        )
        return {"backend": "ghidra"}

    monkeypatch.setattr(manager.runner, "fingerprint", fingerprint)
    monkeypatch.setattr(manager.runner, "analyze", analyze)
    first, second = await asyncio.gather(
        manager.queue_analysis("/tmp/sample"), manager.queue_analysis("/tmp/sample")
    )
    assert first.analysis_id == second.analysis_id
    await asyncio.gather(*tuple(manager._tasks.values()))
    assert calls == 1
    assert manager.get_record(first.analysis_id).status == "ready"
    assert (tmp_path / first.analysis_id / "manifest.json").is_file()
    assert not list(tmp_path.glob(".*.staging-*"))


def test_startup_recovers_interrupted_cache_promotion(tmp_path):
    analysis_id = "a-" + "b" * 16
    backup = tmp_path / (".%s.backup" % analysis_id)
    backup.mkdir()
    record = AnalysisRecord(
        analysis_id=analysis_id,
        sha256="b" * 64,
        source_path="/tmp/sample",
        target_path="/tmp/sample",
        distro=None,
        size=10,
        status="ready",
    )
    (backup / "manifest.json").write_text(
        json.dumps({"schema_version": 2, **record.public()}), encoding="utf-8"
    )
    (backup / "index.json").write_text(json.dumps(make_index()), encoding="utf-8")

    manager = AnalysisManager(Config(analysis_dir=tmp_path))

    assert manager.get_record(analysis_id).status == "ready"
    assert (tmp_path / analysis_id / "index.json").is_file()
    assert not backup.exists()


def test_unsupported_index_schema_is_rejected(tmp_path):
    manager, analysis_id = ready_manager(tmp_path)
    index_path = tmp_path / analysis_id / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["schema_version"] = 999
    index_path.write_text(json.dumps(index), encoding="utf-8")

    with pytest.raises(GdbMcpError, match="schema"):
        manager.index(analysis_id)


@pytest.mark.asyncio
async def test_resync_rebuilds_stopped_session_location(tmp_path, monkeypatch):
    manager, analysis_id = ready_manager(tmp_path)
    session = Session("s-1", state=STOPPED, analysis_id=analysis_id, target="/tmp/sample")
    session.stop_info = {
        "pc": "0x401003",
        "module_path": "/tmp/sample",
        "module_base": "0x400000",
        "module_offset": "0x1003",
    }

    class Registry:
        def list_all(self):
            return [session]

    manager._registry = Registry()
    await manager._resync_sessions()
    assert session.location["function"] == "main"
    assert session.location["line"] == 2


@pytest.mark.asyncio
async def test_event_consumer_dispatches_resync(tmp_path, monkeypatch):
    manager, _ = ready_manager(tmp_path)
    called = asyncio.Event()

    async def resync():
        called.set()

    monkeypatch.setattr(manager, "_resync_sessions", resync)
    manager._event_queue = asyncio.Queue()
    manager._event_task = asyncio.create_task(manager._consume_events())
    try:
        await manager._event_queue.put({"type": "resync", "data": {}})
        await asyncio.wait_for(called.wait(), 1)
    finally:
        manager._event_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await manager._event_task


def test_invalid_function_address_is_rejected(tmp_path):
    manager, analysis_id = ready_manager(tmp_path)
    index_path = tmp_path / analysis_id / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["functions"][0]["entry"] = "EXTERNAL:1"
    index_path.write_text(json.dumps(index), encoding="utf-8")

    with pytest.raises(GdbMcpError, match="invalid addresses"):
        manager.index(analysis_id)


def test_search_validation(tmp_path):
    manager, analysis_id = ready_manager(tmp_path)
    assert manager.search_code(analysis_id, "return", False, 20)["results"][0]["line"] == 2
    with pytest.raises(GdbMcpError, match="invalid regex"):
        manager.search_code(analysis_id, "[", True, 20)


def test_manager_starts_without_analysis_dir():
    """Regression: the default config (analysis_dir=None) must not crash
    the server at startup - no cache dir configured means nothing to
    recover or load; the static bridge just stays dormant."""
    manager = AnalysisManager(Config())
    assert manager.backend_status["status"] == "unknown"
    assert manager.list_analyses() == []
