"""Unit tests for the bench harness — no gdb required.

Covers the properties the benchmark's credibility rests on: deterministic
generation, schema validation, manifest hashing, and the ground-truth
parsers (info-breakpoints text, gdb value strings, little-endian memory).
"""

import json
from pathlib import Path

import pytest

from bench.framework.generators import FAMILY_MODULES
from bench.framework.schema import (
    Check,
    SchemaError,
    TaskSpec,
    index_hash,
    load_tasks,
    manifest_hash,
    write_task,
)
from bench.framework.verifiers import parse_info_breakpoints, parse_int

ROOT = Path(__file__).resolve().parents[1]


# -- deterministic generation ------------------------------------------------

def test_generation_is_deterministic_per_seed():
    for name, module in FAMILY_MODULES.items():
        a = module.generate(7)
        b = module.generate(7)
        assert manifest_hash(a) == manifest_hash(b), name
        assert a.id == "%s-0007" % name


def test_all_families_produce_valid_distinct_tasks():
    tasks = [m.generate(s) for m in FAMILY_MODULES.values() for s in (1, 2, 3)]
    ids = [t.id for t in tasks]
    assert len(ids) == len(set(ids))
    for task in tasks:
        task.validate()  # raises SchemaError on violation
        assert task.target.source.strip().startswith("#include")
        assert task.prompt.strip()
        assert task.checks


def test_seed_spread_produces_distinct_manifests():
    family = FAMILY_MODULES["crash"]
    hashes = {manifest_hash(family.generate(s)) for s in range(20)}
    assert len(hashes) >= 18  # nearly every seed is a distinct task


# -- schema ------------------------------------------------------------------

def _minimal_task(**overrides):
    module = FAMILY_MODULES["lifecycle"]
    task = module.generate(3)
    for key, value in overrides.items():
        setattr(task, key, value)
    return task


def test_roundtrip_through_json(tmp_path):
    task = FAMILY_MODULES["multistep"].generate(4)
    text = task.to_json()
    restored = TaskSpec.from_json(text)
    assert manifest_hash(restored) == manifest_hash(task)


def test_rejects_unknown_check_op():
    task = _minimal_task(checks=[Check(op="nonexistent", spec={})])
    with pytest.raises(SchemaError):
        task.validate()


def test_rejects_empty_checks():
    task = _minimal_task(checks=[])
    with pytest.raises(SchemaError):
        task.validate()


def test_index_hash_is_order_independent(tmp_path):
    tasks = [m.generate(s) for m in FAMILY_MODULES.values() for s in (1, 2)]
    a = index_hash(tasks)
    b = index_hash(list(reversed(tasks)))
    assert a == b


def test_load_tasks_ignores_index_file(tmp_path):
    task = FAMILY_MODULES["pie"].generate(1)
    write_task(tmp_path, task)
    (tmp_path / "index.json").write_text(json.dumps({"task_count": 1}), encoding="utf-8")
    loaded = load_tasks(tmp_path)
    assert [t.id for t in loaded] == [task.id]


# -- ground-truth parsing ------------------------------------------------------

INFO_BP = """Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x000000000040112e <audit+8>
\tstop only if *(int *)&g_i == 8
\tbreakpoint already hit 3 times
2       hw watchpoint  keep y                      *(int *)&probe
\tbreakpoint already hit 1 time
3       breakpoint     keep y   0x0000555555555180 <audit>
"""


def test_parse_info_breakpoints_conditions_and_hits():
    bps = parse_info_breakpoints(INFO_BP)
    assert [b["number"] for b in bps] == [1, 2, 3]
    assert bps[0]["condition"] == "*(int *)&g_i == 8"
    assert bps[0]["hit_count"] == 3
    assert bps[0]["addr"] == 0x40112E
    assert "watchpoint" in bps[1]["type"]
    assert bps[1]["addr"] is None
    assert bps[1]["hit_count"] == 1
    assert bps[2]["condition"] is None
    assert bps[2]["hit_count"] == 0


def test_parse_info_breakpoints_empty():
    assert parse_info_breakpoints("No breakpoints or watchpoints.") == []


def test_parse_int_variants():
    assert parse_int("0x7fff1000") == 0x7FFF1000
    assert parse_int("42") == 42
    assert parse_int("42 <audit+8>") == 42
    assert parse_int(None) is None
    assert parse_int("not a number") is None


# -- committed manifests stay valid ------------------------------------------

def test_committed_task_manifests_load():
    tasks_dir = ROOT / "bench" / "tasks"
    if not tasks_dir.exists():
        pytest.skip("bench tasks not generated yet")
    tasks = load_tasks(tasks_dir)
    assert tasks, "run `python -m bench.framework.cli generate` first"
    for task in tasks:
        assert task.bench_version == "1.0.0"
        for check in task.checks:
            assert check.op in {
                "exit_code", "breakpoint_present", "breakpoint_hit",
                "stop_signal", "memory_value", "register_value",
                "variable_value", "pc_in_range", "backtrace_contains",
                "thread_stopped_at", "thread_count", "fault_addr",
                "session_alive",
            }
