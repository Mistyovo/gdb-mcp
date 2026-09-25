"""Selfcheck: prove every task is solvable before any model touches it.

For each task the deterministic reference solve drives the real MCP server
against real gdb; the ground-truth checks then grade the resulting live state.
A task whose reference solve or grading fails is a *broken task* — the bench
author must fix it. This is the anti-`win.c` gate: no unsolvable target is
ever misdiagnosed as model failure.
"""

from __future__ import annotations

import json
import time
from contextlib import suppress
from pathlib import Path

from .driver import McpDriver
from .generators import derive_truth_for, reference_solve_for
from .verifiers import grade_facts, run_checks


def _check_record(result) -> dict:
    return {"op": result.op, "passed": result.passed, "detail": result.detail}


async def _fact_selfcheck(driver, session_id: str, task, record: dict) -> bool:
    """Fact tasks prove more than state: the truth must be derivable, a
    truth-copy answer must grade PASS, and a corrupted + hallucinated answer
    must grade FAIL — otherwise the grader itself is broken."""
    derive = derive_truth_for(task.family)
    truth = await derive(driver, session_id, task)
    record["truth"] = truth
    fields = task.params.get("fact_fields", [])
    if sorted(truth) != sorted(fields):
        record["error"] = "derived truth fields %s != manifest %s" % (
            sorted(truth), sorted(fields))
        return False
    good = grade_facts(truth, dict(truth))
    record["fact_checks"] = [_check_record(r) for r in good]
    if not all(r.passed for r in good):
        record["error"] = "grader rejected the truth itself"
        return False
    corrupted = dict(truth)
    first = sorted(corrupted)[0]
    corrupted[first] = "corrupted_%s" % corrupted[first]
    corrupted["_hallucinated"] = 1
    if all(r.passed for r in grade_facts(truth, corrupted)):
        record["error"] = "grader accepted a corrupted answer"
        return False
    return True


async def run_selfcheck(
    tasks,
    distro: str,
    port: int,
    results_dir: Path,
    label: str = "selfcheck",
    log_dir: str | None = None,
) -> dict:
    results_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    jsonl_path = results_dir / ("%s-%s.jsonl" % (label, stamp))
    summary_path = results_dir / ("%s-%s.summary.json" % (label, stamp))

    records: list[dict] = []
    async with McpDriver(port=port, distro=distro, log_dir=log_dir) as driver:
        for task in tasks:
            record: dict = {
                "id": task.id,
                "family": task.family,
                "difficulty": task.difficulty,
                "kind": task.kind,
                "tags": task.tags,
                "binary_sha256": task.target.binary_sha256,
            }
            session_id = None
            started = time.perf_counter()
            try:
                solve = reference_solve_for(task.family)
                session_id = await solve(driver, task)
                if task.kind == "fact":
                    if not await _fact_selfcheck(driver, session_id, task, record):
                        record["passed"] = False
                    else:
                        record["passed"] = all(
                            c.passed
                            for c in await run_checks(driver, session_id, task)
                        )
                        if not record["passed"]:
                            record["error"] = record.get(
                                "error", "session checks failed"
                            )
                else:
                    checks = await run_checks(driver, session_id, task)
                    record["checks"] = [_check_record(c) for c in checks]
                    record["passed"] = all(c.passed for c in checks)
                    if not record["passed"]:
                        record["error"] = "ground-truth checks failed"
            except Exception as exc:  # bench wants every failure logged, not raised
                record["passed"] = False
                record["error"] = "%s: %s" % (type(exc).__name__, exc)
            finally:
                record["wall_ms"] = round((time.perf_counter() - started) * 1000, 1)
                if session_id:
                    with suppress(Exception):
                        await driver.call(
                            "kill_session",
                            {"session_id": session_id, "force": True},
                        )
                records.append(record)
                status = "PASS" if record["passed"] else "FAIL"
                print("[%s] %-24s %5.0fms %s" % (
                    status, task.id, record["wall_ms"],
                    record.get("error", "")[:100],
                ), flush=True)

    summary = summarize(records, latency=driver.latency_report())
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record) + "\n")
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("results: %s" % jsonl_path)
    print("summary: %s" % summary_path)
    return summary


def summarize(records: list[dict], latency: dict | None = None) -> dict:
    def rate(subset: list[dict]) -> float:
        if not subset:
            return 0.0
        return round(sum(1 for r in subset if r.get("passed")) / len(subset), 4)

    by_family: dict[str, dict] = {}
    by_difficulty: dict[str, dict] = {}
    tag_records: dict[str, list[dict]] = {}
    for record in records:
        by_family.setdefault(record["family"], []).append(record)
        by_difficulty.setdefault(record["difficulty"], []).append(record)
        for tag in record.get("tags", []):
            tag_records.setdefault(tag, []).append(record)

    return {
        "bench_version": "1.0.0",
        "label": "selfcheck",
        "total": len(records),
        "passed": sum(1 for r in records if r.get("passed")),
        "success_rate": rate(records),
        "by_family": {k: {"n": len(v), "rate": rate(v)} for k, v in sorted(by_family.items())},
        "by_difficulty": {k: {"n": len(v), "rate": rate(v)}
                          for k, v in sorted(by_difficulty.items())},
        "by_tag": {k: {"n": len(v), "rate": rate(v)}
                   for k, v in sorted(tag_records.items())},
        "latency": latency or {},
    }
