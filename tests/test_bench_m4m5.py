"""Unit tests for the M4/M5 harness logic — pure computation, no gdb."""

from bench.framework.perf import GATES, percentile
from bench.framework.stress import summarize as stress_summarize


# -- stress summary ----------------------------------------------------------

def test_stress_success_rate_and_error_kinds():
    recorded = [
        {"tool": "list_sessions", "ok": True, "kind": "ok"},
        {"tool": "launch_gdb", "ok": True, "kind": "ok"},
        {"tool": "batch_commands", "ok": False, "kind": "ToolFailure"},
        {"tool": "batch_commands", "ok": False, "kind": "ToolFailure"},
    ]
    s = stress_summarize(recorded, wall_s=10.0, config={"sessions": 2})
    assert s["stress_tool_success"] == 0.5
    assert s["total_calls"] == 4 and s["failed_calls"] == 2
    assert s["errors_by_kind"] == {"ToolFailure": 2}
    assert s["calls_per_s"] == 0.4


def test_stress_empty_records_zero_rate():
    s = stress_summarize([], wall_s=0.0, config={"sessions": 0})
    assert s["stress_tool_success"] == 0.0


# -- perf percentiles + gates ------------------------------------------------

def test_percentile_matches_reference_values():
    samples = [float(i) for i in range(1, 101)]  # 1..100
    assert percentile(samples, 50) == 50.5
    assert percentile(samples, 95) == 95.05
    assert percentile(samples, 100) == 100.0
    assert percentile([], 50) != percentile([], 50)  # NaN


def test_perf_gates_are_the_published_budgets():
    assert GATES == {"p50_ms": 50.0, "p95_ms": 200.0, "p99_ms": 500.0,
                     "startup_ms": 2000.0}
