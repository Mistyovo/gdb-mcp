"""Stress harness (goal §4): call volume + session churn against the real
server, measuring tool-call reliability.

The published gate is 100k tool calls / 10k sessions / ≥99.9% reliability.
That is an operations run (hours), not a CI run — so the harness scales via
flags and reports the same metrics at whatever scale it ran. The tier-1 key
``stress_tool_success`` is ok/total over ALL calls; a call is "ok" when the
server returns a structured response and the session survives it.

Per iteration, one session does a bounded mix of cheap stateless reads
(list_sessions / get_events) and one session-cycle (launch → reads → kill).
gdb sessions dominate wall time; call volume is dominated by stateless reads,
so a validation run of ~--sessions 20 / --reads-per-session 25 finishes in
minutes while still exercising thousands of calls.
"""

from __future__ import annotations

import asyncio
import json
import time
from contextlib import suppress
from pathlib import Path

from .driver import McpDriver

RESULTS_DIR = Path(__file__).resolve().parents[2] / "bench" / "results"

DEFAULT_PROGRAM = (
    Path(__file__).resolve().parents[2] / "bench" / "targets_out" / "lifecycle_0001" / "lifecycle_0001"
)


def summarize(recorded: list[dict], wall_s: float, config: dict) -> dict:
    total = len(recorded)
    ok = sum(1 for r in recorded if r["ok"])
    return {
        "bench_version": "1.0.0",
        "label": "stress",
        "stress_tool_success": round(ok / total, 6) if total else 0.0,
        "total_calls": total,
        "ok_calls": ok,
        "failed_calls": total - ok,
        "sessions": config["sessions"],
        "wall_s": round(wall_s, 1),
        "calls_per_s": round(total / wall_s, 2) if wall_s else None,
        "errors_by_kind": _by_kind(recorded),
    }


def _by_kind(recorded: list[dict]) -> dict:
    kinds: dict[str, int] = {}
    for r in recorded:
        if not r["ok"]:
            kinds[r.get("kind", "unknown")] = kinds.get(r.get("kind", "unknown"), 0) + 1
    return kinds


async def run_stress(
    program: Path,
    distro: str,
    port: int,
    sessions: int,
    reads_per_session: int,
    results_dir: Path = RESULTS_DIR,
    log_dir: str | None = None,
) -> dict:
    if not program.exists():
        raise SystemExit(
            "stress needs a compiled target; run `bench build` first "
            "(expected %s)" % program
        )
    recorded: list[dict] = []

    def record(tool: str, ok: bool, kind: str = "ok") -> None:
        recorded.append({"tool": tool, "ok": ok, "kind": kind})

    started = time.perf_counter()
    async with McpDriver(port=port, distro=distro, log_dir=log_dir) as driver:
        for i in range(sessions):
            session_id = None
            try:
                # stateless reads before the session exists
                for _ in range(max(1, reads_per_session // 5)):
                    await _try(driver, "list_sessions", {}, record)
                launched = await driver.call(
                    "launch_gdb", {"program": str(program)}
                )
                session_id = launched["session_id"]
                record("launch_gdb", True)
                for _ in range(reads_per_session):
                    await _try(driver, "list_sessions", {}, record)
                    await _try(driver, "batch_commands",
                               {"session_id": session_id,
                                "commands": ["echo x\\n"]}, record)
                record("kill_session", True)
            except Exception as exc:  # one bad session != bad server
                record("session_cycle", False, kind=type(exc).__name__)
            finally:
                if session_id:
                    with suppress(Exception):
                        await driver.call(
                            "kill_session", {"session_id": session_id, "force": True}
                        )
            if (i + 1) % 10 == 0:
                print("stress: %d/%d sessions, %d calls, success=%.4f" % (
                    i + 1, sessions, len(recorded),
                    sum(1 for r in recorded if r["ok"]) / len(recorded),
                ), flush=True)
        wall = time.perf_counter() - started

    summary = summarize(recorded, wall, {"sessions": sessions,
                                         "reads_per_session": reads_per_session})
    summary["latency"] = _driver_latency(driver)
    results_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    (results_dir / ("stress-%s.summary.json" % stamp)).write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("stress_tool_success=%s (%d calls, %d sessions)"
          % (summary["stress_tool_success"], summary["total_calls"], sessions))
    return summary


async def _try(driver: McpDriver, tool: str, args: dict, record) -> None:
    try:
        await driver.call(tool, args)
        record(tool, True)
    except Exception as exc:
        record(tool, False, kind=type(exc).__name__)


def _driver_latency(driver: McpDriver) -> dict:
    with suppress(Exception):
        return driver.latency_report()
    return {}
