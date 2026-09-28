"""Tests for the analysis cache on its own (no async, no sessions).

These are the guarantees :class:`gdb_mcp.reverse.store.AnalysisStore`
exists to provide, so they are asserted at that boundary rather than
through the manager.
"""

import json

import pytest

from gdb_mcp.config import Config
from gdb_mcp.errors import GdbMcpError
from gdb_mcp.reverse.store import (
    AnalysisRecord,
    AnalysisStore,
    path_key,
    validate_index,
)


def make_index(image_base="0x400000", entry="0x401000"):
    return {
        "schema_version": 2,
        "binary": {"name": "sample", "format": "ELF", "image_base": image_base},
        "sections": [{"name": ".text", "start": entry, "end": "0x401020", "execute": True}],
        "symbols": [],
        "strings": [],
        "functions": [
            {"entry": entry, "end": "0x401010", "name": "main", "decompiled": True}
        ],
        "counts": {"functions": 1, "decompiled": 1, "failed": 0},
    }


def make_record(analysis_id, tmp_path, status="ready", target="/tmp/sample"):
    return AnalysisRecord(
        analysis_id=analysis_id,
        sha256=analysis_id[2:] + "0" * 48,
        source_path=target,
        target_path=target,
        distro="kali-linux",
        size=123,
        status=status,
    )


@pytest.fixture
def store(tmp_path):
    return AnalysisStore(Config(analysis_dir=tmp_path))


def promote(store, analysis_id, index=None, annotations=None):
    """Write a staging dir the way a finished Ghidra run leaves it."""
    staging = store.root / (".%s.staging-test" % analysis_id)
    (staging / "functions").mkdir(parents=True)
    (staging / "index.json").write_text(
        json.dumps(index or make_index()), encoding="utf-8"
    )
    (staging / "functions" / "401000.json").write_text(
        json.dumps({"entry": "0x401000", "code": "int main(void){}"}), encoding="utf-8"
    )
    if annotations is not None:
        (staging / "annotations.json").write_text(json.dumps(annotations), encoding="utf-8")
    record = make_record(analysis_id, store.root)
    store.promote(record, staging, index or make_index())
    return record


ID = "a-" + "1" * 16
OTHER = "a-" + "2" * 16


class TestPromotion:
    def test_result_becomes_readable(self, store):
        promote(store, ID)
        assert store.index(ID)["binary"]["name"] == "sample"
        assert store.dir_for(ID).joinpath("manifest.json").is_file()
        assert not list(store.root.glob(".*.staging-*"))

    def test_annotations_survive_a_refresh(self, store):
        promote(store, ID, annotations={"0x401000": {"label": "entry"}})
        assert store.annotations(ID) == {"0x401000": {"label": "entry"}}
        promote(store, ID)  # re-analysis replaces index.json
        assert store.annotations(ID)["0x401000"]["label"] == "entry"

    def test_replacing_an_entry_invalidates_its_caches(self, store):
        promote(store, ID)
        assert store.function_payload(ID, 0x401000)["code"] == "int main(void){}"
        index = make_index()
        index["functions"] = []
        staging = store.root / (".%s.staging-2" % ID)
        (staging / "functions").mkdir(parents=True)
        (staging / "index.json").write_text(json.dumps(index), encoding="utf-8")
        store.promote(make_record(ID, store.root), staging, index)
        assert store.function_payload(ID, 0x401000) is None
        assert store.index(ID)["functions"] == []

    def test_recovery_promotes_a_crashed_backup(self, tmp_path):
        """A crash between the two renames leaves the result in .backup; the
        next start must finish the job rather than lose the analysis."""
        first = AnalysisStore(Config(analysis_dir=tmp_path))
        promote(first, ID)
        backup = tmp_path / (".%s.backup" % ID)
        final = tmp_path / ID
        final.rename(backup)
        second = AnalysisStore(Config(analysis_dir=tmp_path))
        assert not backup.exists()
        assert second.index(ID)["binary"]["name"] == "sample"


class TestRecords:
    def test_load_picks_up_manifests(self, store):
        promote(store, ID)
        reloaded = AnalysisStore(Config(analysis_dir=store.root))
        assert reloaded.record(ID).status == "ready"
        assert reloaded.list_public()[0]["analysis_id"] == ID

    def test_interrupted_run_reads_as_ready_once_its_index_exists(self, store):
        directory = store.root / ID
        directory.mkdir(parents=True)
        (directory / "index.json").write_text(json.dumps(make_index()), encoding="utf-8")
        (directory / "manifest.json").write_text(
            json.dumps({"schema_version": 2, **make_record(ID, store.root, "running").public()}),
            encoding="utf-8",
        )
        reloaded = AnalysisStore(Config(analysis_dir=store.root))
        assert reloaded.record(ID).status == "ready"

    def test_unknown_and_unready(self, store):
        with pytest.raises(GdbMcpError, match="unknown analysis"):
            store.record(ID)
        store.put(make_record(ID, store.root, status="running"))
        with pytest.raises(GdbMcpError, match="analysis is running"):
            store.index(ID)

    def test_path_matching_is_case_insensitive_only_where_paths_are(self, store):
        store.put(make_record(ID, store.root, target="/tmp/App"))
        assert store.newest_for_path("/tmp/App") == ID
        assert store.newest_for_path("/tmp/app") is None
        assert path_key("C:\\Temp\\App") == path_key("c:/temp/app")

    def test_invalid_analysis_id_is_rejected(self, store):
        for bad in ("../etc", "a-Z" + "1" * 15, "a-" + "1" * 15, "nope"):
            with pytest.raises(GdbMcpError, match="invalid analysis id"):
                store.dir_for(bad)


class TestIndexValidation:
    def test_corrupt_shapes_are_rejected(self):
        for mutate in (
            lambda index: index.pop("binary"),
            lambda index: index.__setitem__("functions", "main"),
            lambda index: index["binary"].__setitem__("image_base", "zz"),
            lambda index: index["functions"][0].__setitem__("name", 5),
            lambda index: index["functions"][0].__setitem__("end", "0x10"),
            lambda index: index.__setitem__("schema_version", 99),
        ):
            index = make_index()
            mutate(index)
            with pytest.raises(GdbMcpError, match="ANALYSIS_CORRUPT|unsupported"):
                validate_index(index)

    def test_function_payload_absent_for_unanalyzed_entry(self, store):
        promote(store, ID)
        assert store.function_payload(ID, 0x402000) is None

    def test_save_annotations_is_visible_to_readers(self, store):
        promote(store, ID)
        store.save_annotations(ID, {"0x401000": {"label": "x"}})
        fresh = AnalysisStore(Config(analysis_dir=store.root))
        assert fresh.annotations(ID) == {"0x401000": {"label": "x"}}

    def test_annotations_are_a_copy(self, store):
        promote(store, ID)
        first = store.annotations(ID)
        first["0xdeadbeef"] = {"label": "nope"}
        assert "0xdeadbeef" not in store.annotations(ID)
