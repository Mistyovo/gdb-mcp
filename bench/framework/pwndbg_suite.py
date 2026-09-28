"""pwndbg compatibility suite (goal §7): the plugin must keep its structured
outputs working when pwndbg is loaded inside gdb (pwndbg patches context,
prompts and several info commands — the classic breakage surface).

Probes are run against real WSL gdb sessions with the system pwndbg (the
same one selfcheck implicitly uses). Coverage = the fraction of probed
core verbs that keep their contract; gate ≥ 95% coverage with every probe
stable (the 99% pass gate applies across repeated rounds).
"""

from __future__ import annotations

import asyncio
import json
import time
from contextlib import suppress
from pathlib import Path

from .driver import McpDriver
from .build import win_to_wsl

RESULTS_DIR = Path(__file__).resolve().parents[2] / "bench" / "results"
AUX_DIR = Path(__file__).resolve().parents[2] / "bench" / "targets_out" / "pwndbg_aux"

MALLOC_SOURCE = """#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) void fill(char *p, unsigned n) {
    memset(p, 0x41, n);
}

int main(void) {
    char *a = malloc(64);
    char *b = malloc(24);
    fill(a, 64);
    free(b);
    fill(a, 8);
    free(a);
    return 0;
}
"""

CRASH_SOURCE = """int main(void) {
    volatile int *p = (int *)(void *)0;
    return *p;
}
"""


async def _wsl(distro: str, *args: str) -> None:
    proc = await asyncio.create_subprocess_exec(
        "wsl.exe", "-d", distro, "--", *args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    if proc.returncode:
        raise RuntimeError("wsl %s failed: %s" % (args[0], err.decode()[:300]))


async def _build_targets(distro: str) -> tuple[Path, Path]:
    AUX_DIR.mkdir(parents=True, exist_ok=True)
    malloc_src = AUX_DIR / "mallocer.c"
    crash_src = AUX_DIR / "crasher.c"
    malloc_src.write_text(MALLOC_SOURCE, encoding="utf-8")
    crash_src.write_text(CRASH_SOURCE, encoding="utf-8")
    malloc_bin = AUX_DIR / "mallocer"
    crash_bin = AUX_DIR / "crasher"
    await _wsl(distro, "gcc", "-O0", "-no-pie", "-o",
               win_to_wsl(malloc_bin), win_to_wsl(malloc_src))
    await _wsl(distro, "gcc", "-O0", "-no-pie", "-o",
               win_to_wsl(crash_bin), win_to_wsl(crash_src))
    return malloc_bin, crash_bin


async def _settle(driver, sid, timeout_s: float = 20.0) -> str:
    """run/launch(run=True) return while the inferior is on its way; poll
    until it actually stops (or exits) before inspecting state."""
    deadline = time.monotonic() + timeout_s
    state = ""
    while time.monotonic() < deadline:
        reason = await driver.call("get_stop_reason", {"session_id": sid})
        state = reason.get("state") or ""
        if state in ("stopped", "exited"):
            return state
        await asyncio.sleep(0.2)
    return state


async def _wait_running_or_stopped(driver, sid, timeout_s: float = 20.0) -> str:
    deadline = time.monotonic() + timeout_s
    state = ""
    while time.monotonic() < deadline:
        status = await driver.call("session_status", {"session_id": sid})
        state = status.get("state") or ""
        if state in ("stopped", "running", "exited"):
            return state
        await asyncio.sleep(0.2)
    return state


# -- probes: each returns (ok: bool, detail: str) ----------------------------

async def probe_pwndbg_loaded(driver, ctx) -> tuple[bool, str]:
    result = await driver.call("execute_command", {"command": "pwndbg"})
    text = (result.get("output") or "").lower()
    ok = "pwndbg" in text or "commands" in text
    return ok, text[:80]


async def probe_heap_bins(driver, ctx) -> tuple[bool, str]:
    sid = ctx["malloc"]
    await driver.call("set_breakpoint", {"session_id": sid, "location": "fill"})
    await driver.call("execute_command", {"command": "run", "session_id": sid})
    await _settle(driver, sid)
    bins = await driver.call("heap_bins", {"session_id": sid})
    ok = bool(bins.get("parsed"))
    return ok, json.dumps({k: bins.get(k) for k in ("parsed", "tcachebins")})[:120]


async def probe_stop_reason_shape(driver, ctx) -> tuple[bool, str]:
    sid = ctx["malloc"]
    reason = await driver.call("get_stop_reason", {"session_id": sid})
    ok = reason.get("state") == "stopped" and bool(reason.get("stop_info"))
    return ok, str(reason.get("stop_info"))[:100]


async def probe_crash_report(driver, ctx) -> tuple[bool, str]:
    bin_path = ctx["crash_bin"]
    crash_sid = (await driver.call(
        "launch_gdb", {"program": str(bin_path), "run": True}
    ))["session_id"]
    ctx["crash_sid"] = crash_sid
    await _settle(driver, crash_sid)
    report = await driver.call("crash_report", {"session_id": crash_sid})
    ok = report.get("signal") == "SIGSEGV"
    return ok, "signal=%r" % report.get("signal")


async def probe_long_output_spills(driver, ctx) -> tuple[bool, str]:
    sid = ctx["malloc"]
    result = await driver.call(
        "execute_command", {"command": "info functions", "session_id": sid}
    )
    ok = result.get("total_lines") is not None
    return ok, "total_lines=%r truncated=%r" % (
        result.get("total_lines"), result.get("truncated"))


async def probe_breakpoint_hit_flow(driver, ctx) -> tuple[bool, str]:
    sid = ctx["malloc"]
    bp = await driver.call("set_breakpoint", {"location": "main", "session_id": sid})
    await driver.call("execute_command", {"command": "run", "session_id": sid})
    state = await _settle(driver, sid)
    listing = await driver.call("list_breakpoints", {"session_id": sid})
    hit = any(b.get("number") == bp.get("number") for b in listing.get("breakpoints", []))
    ok = state == "stopped" and hit
    return ok, "state=%s bp=%s" % (state, bp.get("number"))


PROBES = {
    "pwndbg_loaded": probe_pwndbg_loaded,
    "heap_bins": probe_heap_bins,
    "stop_reason_shape": probe_stop_reason_shape,
    "crash_report": probe_crash_report,
    "long_output_spills": probe_long_output_spills,
    "breakpoint_hit_flow": probe_breakpoint_hit_flow,
}


async def run_pwndbg_suite(
    distro: str,
    port: int,
    rounds: int = 1,
    results_dir: Path = RESULTS_DIR,
    log_dir: str | None = None,
) -> dict:
    malloc_bin, crash_bin = await _build_targets(distro)
    records: list[dict] = []
    async with McpDriver(port=port, distro=distro, log_dir=log_dir) as driver:
        for rnd in range(rounds):
            ctx: dict = {}
            sid = None
            try:
                launched = await driver.call(
                    "launch_gdb", {"program": str(malloc_bin)}
                )
                sid = launched["session_id"]
                ctx["malloc"] = sid
                ctx["malloc_bin"] = malloc_bin
                ctx["crash"] = None
                ctx["crash_bin"] = crash_bin
                for name, probe in PROBES.items():
                    rec = {"round": rnd, "probe": name}
                    try:
                        ok, detail = await probe(driver, ctx)
                    except Exception as exc:
                        ok, detail = False, "%s: %s" % (type(exc).__name__, str(exc)[:120])
                    rec["passed"], rec["detail"] = ok, detail
                    records.append(rec)
                    print("[%s] R%d %-20s %s" % (
                        "PASS" if ok else "FAIL", rnd, name, detail[:80],
                    ), flush=True)
            finally:
                for victim in (ctx.get("crash_sid"), sid):
                    if victim:
                        with suppress(Exception):
                            await driver.call(
                                "kill_session", {"session_id": victim, "force": True}
                            )

    passed = sum(1 for r in records if r["passed"])
    summary = {
        "bench_version": "1.0.0",
        "label": "pwndbg",
        "pwndbg_compat": round(passed / len(records), 4) if records else 0.0,
        "probes": len(PROBES),
        "rounds": rounds,
        "records": records,
    }
    results_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    (results_dir / ("pwndbg-%s.summary.json" % stamp)).write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("pwndbg_compat=%s (%d/%d)" % (summary["pwndbg_compat"], passed, len(records)))
    return summary
