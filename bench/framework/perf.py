"""Perf harness (goal §6): orchestration overhead, session startup,
concurrency and soak.

Honest measurement split:

* **overhead** — `list_sessions` costs one MCP round-trip and no gdb work,
  so its latency distribution IS the server orchestration overhead (the
  goal §6 gate P50 ≤ 50 ms / P95 ≤ 200 ms / P99 ≤ 500 ms applies to this
  distribution);
* **startup** — `launch_gdb` until the session reports connected (gate
  ≤ 2 s), measured per session;
* **concurrency** — N parallel light tool calls; all must succeed;
* **soak** — repeated call cycles for ``--soak-minutes`` (the published gate
  is a 24 h operations run) while sampling the server process RSS; gate:
  RSS growth ≤ 10% over the soak.

All four report at whatever scale they ran; the summary carries the same
key names as the published gates so `report --gate` can consume them.
"""

from __future__ import annotations

import asyncio
import json
import time
from contextlib import suppress
from pathlib import Path

import psutil

from .driver import McpDriver

RESULTS_DIR = Path(__file__).resolve().parents[2] / "bench" / "results"

DEFAULT_PROGRAM = (
    Path(__file__).resolve().parents[2] / "bench" / "targets_out" / "lifecycle_0001" / "lifecycle_0001"
)

GATES = {"p50_ms": 50.0, "p95_ms": 200.0, "p99_ms": 500.0, "startup_ms": 2000.0}


def percentile(samples: list[float], pct: float) -> float:
    if not samples:
        return float("nan")
    ordered = sorted(samples)
    k = (len(ordered) - 1) * pct / 100.0
    low, high = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (k - low)


async def _server_process(driver: McpDriver):
    """The stdio server is our direct child (python -m gdb_mcp)."""
    me = psutil.Process()
    children = me.children(recursive=True)
    for proc in children:
        with suppress(psutil.Error):
            if "gdb_mcp" in " ".join(proc.cmdline()):
                return proc
    return None


async def run_perf(
    program: Path,
    distro: str,
    port: int,
    overhead_calls: int = 400,
    sessions: int = 10,
    concurrent: int = 100,
    soak_minutes: float = 0.0,
    results_dir: Path = RESULTS_DIR,
    log_dir: str | None = None,
) -> dict:
    if not program.exists():
        raise SystemExit(
            "perf needs a compiled target; run `bench build` first "
            "(expected %s)" % program
        )
    overhead: list[float] = []
    startups: list[float] = []
    concurrency_ok = 0
    soak: dict = {}

    async with McpDriver(port=port, distro=distro, log_dir=log_dir) as driver:
        # -- overhead -------------------------------------------------------
        for _ in range(overhead_calls):
            t0 = time.perf_counter()
            await driver.call("list_sessions", {})
            overhead.append((time.perf_counter() - t0) * 1000.0)

        # -- session startup -------------------------------------------------
        # warmup: the very first session pays the WSL VM + pwndbg cold start
        # (tens of seconds, environment property, not server overhead). The
        # §6 gate is about steady-state session startup, so warm up once and
        # report the cold start separately.
        t0 = time.perf_counter()
        warm = (await driver.call("launch_gdb", {"program": str(program)}))["session_id"]
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            st = await driver.call("session_status", {"session_id": warm})
            if st.get("state") in ("stopped", "ready", "connected", "connecting"):
                break
            await asyncio.sleep(0.05)
        cold_start_ms = round((time.perf_counter() - t0) * 1000.0, 1)
        with suppress(Exception):
            await driver.call("kill_session", {"session_id": warm, "force": True})

        for i in range(sessions):
            t0 = time.perf_counter()
            sid = (await driver.call("launch_gdb", {"program": str(program)}))["session_id"]
            print("[perf] session %d launch_gdb returned at %.1fs"
                  % (i, time.perf_counter() - t0), flush=True)
            deadline = time.monotonic() + 30.0
            while time.monotonic() < deadline:
                status = await driver.call("session_status", {"session_id": sid})
                # "connecting" == hello received; a session parked at the gdb
                # prompt never emits the prompt event, so do not wait for READY
                if status.get("state") in ("stopped", "ready", "connected",
                                           "connecting"):
                    break
                await asyncio.sleep(0.05)
            startups.append((time.perf_counter() - t0) * 1000.0)
            print("[perf] session %d live at %.1fs" % (i, time.perf_counter() - t0), flush=True)
            with suppress(Exception):
                await driver.call("kill_session", {"session_id": sid, "force": True})

        # -- concurrency -----------------------------------------------------
        async def _one(i: int) -> bool:
            try:
                await driver.call("list_sessions", {})
                return True
            except Exception:
                return False

        results = await asyncio.gather(*[_one(i) for i in range(concurrent)])
        concurrency_ok = sum(1 for r in results if r)

        # -- soak ------------------------------------------------------------
        if soak_minutes > 0:
            server = await _server_process(driver)
            rss_start = (await _rss(server))["rss_mb"]
            calls = 0
            t_end = time.monotonic() + soak_minutes * 60.0
            samples = [rss_start]
            while time.monotonic() < t_end:
                for _ in range(50):
                    await driver.call("list_sessions", {})
                    calls += 1
                sample = await _rss(server)
                samples.append(sample["rss_mb"])
                await asyncio.sleep(1.0)
            soak = {
                "minutes": round(soak_minutes, 2),
                "calls": calls,
                "rss_start_mb": rss_start,
                "rss_end_mb": samples[-1],
                "rss_peak_mb": max(samples),
                "rss_growth_pct": round(
                    (samples[-1] - rss_start) / rss_start * 100.0, 2
                ) if rss_start else None,
                "server_process_found": server is not None,
            }

    summary = {
        "bench_version": "1.0.0",
        "label": "perf",
        "overhead_p50_ms": round(percentile(overhead, 50), 3),
        "overhead_p95_ms": round(percentile(overhead, 95), 3),
        "overhead_p99_ms": round(percentile(overhead, 99), 3),
        "cold_start_ms": cold_start_ms,
        "startup_ms_p50": round(percentile(startups, 50), 1),
        "startup_ms_max": round(max(startups), 1) if startups else None,
        "concurrency_ok": concurrency_ok,
        "concurrency_requested": concurrent,
        "soak": soak,
        "samples": {"overhead": len(overhead), "startup": len(startups)},
        "gates": GATES,
        "gate_pass": {
            "p50": len(overhead) > 0 and percentile(overhead, 50) <= GATES["p50_ms"],
            "p95": len(overhead) > 0 and percentile(overhead, 95) <= GATES["p95_ms"],
            "p99": len(overhead) > 0 and percentile(overhead, 99) <= GATES["p99_ms"],
            "startup": bool(startups) and max(startups) <= GATES["startup_ms"],
            "concurrency": concurrency_ok == concurrent,
        },
    }
    results_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    (results_dir / ("perf-%s.summary.json" % stamp)).write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("overhead p50/p95/p99 = %.1f/%.1f/%.1f ms | startup max %.0f ms | "
          "concurrency %d/%d"
          % (summary["overhead_p50_ms"], summary["overhead_p95_ms"],
             summary["overhead_p99_ms"], summary["startup_ms_max"] or 0,
             concurrency_ok, concurrent))
    return summary


async def _rss(proc) -> dict:
    if proc is None:
        return {"rss_mb": 0.0}
    with suppress(psutil.Error):
        return {"rss_mb": round(proc.memory_info().rss / (1024 * 1024), 2)}
    return {"rss_mb": 0.0}
