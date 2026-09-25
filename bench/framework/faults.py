"""Fault-injection harness (goal §5): recovery ≥ 99%, no cross-session pollution.

Each scenario breaks something on purpose, then requires the server to answer
canary calls again and — the pollution half — requires that a * bystander*
session on the same server is still exactly where it was. Scenarios:

* ``tool_error_flood``  — invalid arguments to real tools; server must
  answer every later call normally (errors are per-call, never lethal).
* ``crash_inferior``    — the victim's inferior segfaults; the victim session
  stays usable and the bystander's stop state is untouched.
* ``kill_inferior``     — gdb ``kill``; the session must survive and accept a
  relaunch of the program.
* ``kill_gdb_process``  — the gdb OS process dies underneath the server; the
  session must surface as disconnected/errored (never silently "ready")
  while the bystander is unaffected.

``server_restart`` (B1 persistence, informational): the driver is torn down
and a fresh server started against the same log dir; recovery = canaries on
the new server, and the persisted sessions file lists the old identity.
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


async def _canary(driver: McpDriver) -> bool:
    try:
        await driver.call("list_sessions", {})
        return True
    except Exception:
        return False


async def _launch(driver: McpDriver, program: Path, run: bool = False) -> str:
    launched = await driver.call(
        "launch_gdb", {"program": str(program), "run": run}
    )
    return launched["session_id"]


async def _stable_marker(driver: McpDriver, session_id: str) -> dict:
    """Observable bystander state: session status + register snapshot."""
    status = await driver.call("session_status", {"session_id": session_id})
    regs = await driver.call(
        "read_registers", {"names": ["rsp", "rip"], "session_id": session_id}
    )
    return {"state": status.get("state"), "regs": regs.get("regs")}


async def _settle(driver: McpDriver, session_id: str, timeout_s: float = 15.0) -> dict:
    deadline = time.monotonic() + timeout_s
    result: dict = {}
    while time.monotonic() < deadline:
        result = await driver.call("get_stop_reason", {"session_id": session_id})
        if result.get("state") in ("stopped", "exited"):
            return result
        await asyncio.sleep(0.25)
    return result


async def _fault_tool_error_flood(driver, victim, bystander, program) -> bool:
    bad_calls = [
        ("read_memory", {"address": "not-an-address", "length": -5, "session_id": victim}),
        ("evaluate", {"expression": "%%%", "session_id": victim}),
        ("set_breakpoint", {"location": "", "session_id": victim}),
        ("batch_commands", {"commands": [], "session_id": victim}),
        ("read_registers", {"names": ["not_a_reg"], "session_id": victim}),
    ] * 4
    for tool, args in bad_calls:
        with suppress(Exception):
            await driver.call(tool, args)
    return await _canary(driver)


async def _fault_crash_inferior(driver, victim, bystander, program) -> bool:
    # victim: launch a crasher fresh, let it fault
    crasher = program.parent.parent / "crash_0001" / "crash_0001"
    target = crasher if crasher.exists() else program
    sid = await _launch(driver, target, run=True)
    await _settle(driver, sid)
    stop = await driver.call("get_stop_reason", {"session_id": sid})
    recovered = stop.get("state") in (
        "stopped", "ready", "exited"
    ) and await _canary(driver)
    with suppress(Exception):
        await driver.call("kill_session", {"session_id": sid, "force": True})
    return bool(recovered)


async def _fault_kill_inferior(driver, victim, bystander, program) -> bool:
    # a busy-looping inferior gets gdb-killed mid-run; the session must stay
    # usable afterwards (lifecycle targets busy-loop on argv "b")
    launched = await driver.call(
        "launch_gdb", {"program": str(program), "args": ["b"], "run": True}
    )
    sid = launched["session_id"]
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        status = await driver.call("session_status", {"session_id": sid})
        if status.get("state") == "running":
            break
        await asyncio.sleep(0.25)
    await driver.call("execute_command", {"command": "kill", "session_id": sid})
    status = await driver.call("session_status", {"session_id": sid})
    recovered = status.get("state") in (
        "stopped", "connected", "ready", "exited"
    ) and await _canary(driver)
    with suppress(Exception):
        await driver.call("kill_session", {"session_id": sid, "force": True})
    return bool(recovered)


def _make_kill_gdb_process(distro):
    async def fault(driver, victim, bystander, program) -> bool:
        return await _fault_kill_gdb_process(driver, victim, bystander, program, distro)
    return fault


async def _fault_kill_gdb_process(driver, victim, bystander, program, distro) -> bool:
    status = await driver.call("session_status", {"session_id": victim})
    gdb_pid = status.get("gdb_pid")
    if not gdb_pid:
        return False
    proc = await asyncio.create_subprocess_exec(
        "wsl.exe", "-d", distro, "--", "kill", "-9", str(gdb_pid),
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.communicate()
    deadline = time.monotonic() + 15.0
    surfaced = False
    while time.monotonic() < deadline:
        status = await driver.call("session_status", {"session_id": victim})
        if status.get("state") in ("disconnected", "error", "lost"):
            surfaced = True
            break
        await asyncio.sleep(0.5)
    return surfaced and await _canary(driver)


SCENARIOS = {
    "tool_error_flood": _fault_tool_error_flood,
    "crash_inferior": _fault_crash_inferior,
    "kill_inferior": _fault_kill_inferior,
    "kill_gdb_process": _fault_kill_gdb_process,
}


async def run_faults(
    program: Path,
    distro: str,
    port: int,
    rounds: int = 3,
    results_dir: Path = RESULTS_DIR,
    log_dir: str | None = None,
    scenarios: list[str] | None = None,
) -> dict:
    if not program.exists():
        raise SystemExit(
            "faults needs a compiled target; run `bench build` first "
            "(expected %s)" % program
        )
    wanted = scenarios or list(SCENARIOS)
    # kill_gdb_process needs the distro to address the WSL instance
    scenario_map = dict(SCENARIOS)
    if "kill_gdb_process" in scenario_map:
        scenario_map["kill_gdb_process"] = _make_kill_gdb_process(distro)
    records: list[dict] = []
    async with McpDriver(port=port, distro=distro, log_dir=log_dir) as driver:
        for rnd in range(rounds):
            victim = None
            bystander = None
            try:
                victim = await _launch(driver, program)
                await driver.call(
                    "execute_command",
                    {"command": "starti", "session_id": victim},
                )
                await _settle(driver, victim)
                bystander = await _launch(driver, program)
                await driver.call(
                    "execute_command",
                    {"command": "starti", "session_id": bystander},
                )
                await _settle(driver, bystander)
                before = await _stable_marker(driver, bystander)
                for name in wanted:
                    fault = scenario_map[name]
                    rec: dict = {"round": rnd, "scenario": name}
                    try:
                        rec["recovered"] = bool(
                            await fault(driver, victim, bystander, program)
                        )
                    except Exception as exc:
                        rec["recovered"] = False
                        rec["error"] = "%s: %s" % (type(exc).__name__, exc)
                    # pollution half: the bystander must be where it was
                    try:
                        after = await _stable_marker(driver, bystander)
                        rec["bystander_clean"] = (
                            before == after
                            and await _canary(driver)
                        )
                    except Exception as exc:
                        rec["bystander_clean"] = False
                        rec["bystander_error"] = "%s: %s" % (type(exc).__name__, exc)
                    records.append(rec)
                    print("[R%d] %-18s recovered=%s clean=%s %s" % (
                        rnd, name, rec["recovered"], rec["bystander_clean"],
                        rec.get("error", "")[:60],
                    ), flush=True)
            finally:
                for sid in (victim, bystander):
                    if sid:
                        with suppress(Exception):
                            await driver.call(
                                "kill_session", {"session_id": sid, "force": True}
                            )

    recovered = sum(1 for r in records if r["recovered"])
    clean = sum(1 for r in records if r["bystander_clean"])
    summary = {
        "bench_version": "1.0.0",
        "label": "faults",
        "recovery": round(recovered / len(records), 4) if records else 0.0,
        "no_pollution": round(clean / len(records), 4) if records else 0.0,
        "rounds": rounds,
        "scenarios": wanted,
        "records": records,
    }
    results_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    (results_dir / ("faults-%s.summary.json" % stamp)).write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print("recovery=%s no_pollution=%s (%d injections)"
          % (summary["recovery"], summary["no_pollution"], len(records)))
    return summary
