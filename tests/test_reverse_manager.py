import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

import pytest

from gdb_mcp.config import Config
from gdb_mcp.errors import GdbMcpError
from gdb_mcp.reverse.manager import AnalysisManager
from gdb_mcp.reverse.store import AnalysisRecord, path_key


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
    manager = AnalysisManager(cfg)
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
    manager.store.records[analysis_id] = record
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
    import gdb_mcp.reverse.store as store

    original = store.read_json
    reads = []

    def tracked(path):
        reads.append(path.name)
        return original(path)

    monkeypatch.setattr(store, "read_json", tracked)
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
    assert manager.store.newest_for_path("/tmp/App") == analysis_id
    assert manager.store.newest_for_path("/tmp/app") is None
    assert path_key("C:\\Temp\\App") == path_key("c:/temp/app")


def test_concurrent_annotations_do_not_lose_updates(tmp_path):
    manager, analysis_id = ready_manager(tmp_path)

    def save(number):
        manager.annotate(analysis_id, 0x401000 + number, "label_%d" % number, None)

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(save, range(24)))
    annotations = manager.annotations(analysis_id)
    assert len(annotations) == 24
    assert annotations["0x401017"]["label"] == "label_23"


@pytest.mark.asyncio
async def test_queue_deduplicates_and_promotes_staging(tmp_path, monkeypatch):
    cfg = Config(analysis_dir=tmp_path)
    manager = AnalysisManager(cfg)
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
    """The static extension may be constructed with no cache dir; only an
    explicit analyze_binary call needs one."""
    manager = AnalysisManager(Config())
    assert manager.list_analyses() == []
