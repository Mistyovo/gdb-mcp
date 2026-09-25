"""Family: inspect — fact tasks (goal §3, State Inspection).

The agent must *produce* a stop state and then answer structured questions
about the live state as a JSON object (``submit(answer=…)``). Grading never
trusts the answer's own claims: ``derive_truth`` re-derives every field from
the session via fresh harness-side MCP queries (memory reads, registers,
backtrace), and hallucinated fields fail the task outright.

Two shapes per seed:

* ``report_globals`` — stop in ``report()`` and report the int/unsigned/short
  globals plus the call argument. No DWARF, so everything goes through the
  cast/``&symbol`` idiom.
* ``crash_facts`` — crash the target and report signal, fault address and the
  two innermost frames. Truth comes from the live stop, so optimizer-driven
  inline shapes are graded against what is actually on the stack.
"""

from __future__ import annotations

from ..schema import Check
from ..verifiers import VerifyError, parse_int
from .common import opt_level, flags_for, make_task, program_path, rng_for, settle

FAMILY = "inspect"

_REPORT_SOURCE = """#include <stdio.h>

int idg = {idg_init};
unsigned int uflag = {uflag_init};
short int strv = {strv_init};

__attribute__((noinline)) void report(int token) {{
    printf("token=%d\\n", token);
}}

__attribute__((noinline)) int work(void) {{
    int acc = {acc_seed};
    for (int i = 0; i < {iters}; i++) {{
        acc = acc * 3 + i;
        if (i == {mid}) uflag = (unsigned int)(acc ^ 0x{xor_val:x}u);
    }}
    idg = acc % {mod};
    strv = (short)(acc & 0x7f);
    report(acc);
    return acc;
}}

int main(void) {{
    return work() % 5;
}}
"""

_CRASH_SOURCE = """#include <stdlib.h>

__attribute__((noinline)) long deref(int idx) {{
    if (idx < 0) return 42;
    volatile int *p = (int *)(void *)0;
    return p[idx];
}}

__attribute__((noinline)) int trigger(int idx) {{
    volatile int acc = 0;
    acc += (int)deref(idx);
    return acc + 1;
}}

int main(int argc, char **argv) {{
    int idx = {crash_idx};
    if (argc > 1) idx = atoi(argv[1]);
    return trigger(idx);
}}
"""


def generate(seed: int):
    rng = rng_for(seed)
    build = flags_for(seed)
    opt = {"-O0": "O0", "-O1": "O1", "-O2": "O2", "-O3": "O3"}[opt_level(build)]
    shape = ["report_globals", "crash_facts"][seed % 2]

    if shape == "report_globals":
        iters = rng.randrange(14, 40)
        params = {
            "idg_init": rng.randrange(0, 1000),
            "uflag_init": rng.randrange(0, 0xFFFF),
            "strv_init": rng.randrange(-100, 100),
            "acc_seed": rng.randrange(1, 9000),
            "iters": iters,
            "mid": rng.randrange(3, iters - 2),
            "xor_val": rng.randrange(0x100, 0xFFFF),
            "mod": rng.randrange(500, 4000),
        }
        fields = ["idg", "uflag", "strv", "token"]
        prompt = (
            "Set a breakpoint on the function 'report' and run until it fires, "
            "leaving the session stopped at that hit. Then submit with an "
            "'answer' JSON object with EXACTLY these fields, read from the "
            "live stopped state:\n"
            '  "idg"   — the 4-byte int stored at &idg\n'
            '  "uflag" — the 4-byte unsigned int at &uflag\n'
            '  "strv"  — the 2-byte short at &strv\n'
            '  "token" — the int argument of this report() call (first '
            "argument register).\n"
            "The binary has no debug info: read memory through &symbol casts "
            "(read_memory), registers via read_registers. Any int format "
            "(decimal or 0x hex) is accepted."
        )
        checks = [Check(op="breakpoint_present", spec={"symbol": "report"}),
                  Check(op="session_alive")]
        params["shape"] = shape
        params["fact_fields"] = fields
        difficulty, max_steps = "medium", 7
        source = _REPORT_SOURCE.format(**params)
    else:
        crash_idx = rng.randrange(3, 64)
        params = {"crash_idx": crash_idx, "fault_addr": 4 * crash_idx}
        fields = ["signal", "fault_addr", "pc_function", "caller_function"]
        prompt = (
            "Run the program under gdb and let it crash; keep the session "
            "stopped at the crash. Then submit with an 'answer' JSON object "
            "with EXACTLY these fields, read from the live stopped state:\n"
            '  "signal"          — the stop signal name (e.g. SIGSEGV)\n'
            '  "fault_addr"      — the faulting memory address (any int format)\n'
            '  "pc_function"     — the function containing the faulting PC '
            "(backtrace frame 0)\n"
            '  "caller_function" — its caller (backtrace frame 1)'
        )
        checks = [Check(op="stop_signal", spec={"signal": "SIGSEGV"}),
                  Check(op="session_alive")]
        params["shape"] = shape
        params["fact_fields"] = fields
        difficulty, max_steps = "easy", 5
        source = _CRASH_SOURCE.format(**params)

    return make_task(
        family=FAMILY, seed=seed, kind="fact", difficulty=difficulty,
        tags=["inspect", "facts", shape, opt],
        source=source, build=build, params=params, prompt=prompt,
        max_steps=max_steps, checks=checks,
    )


async def reference_solve(driver, task) -> str:
    """Produce the state the questions are about (the answer side of a fact
    task is proven by the selfcheck: truth must be derivable and a truth
    copy must grade PASS while a corrupted copy grades FAIL)."""
    params = task.params
    if params["shape"] == "report_globals":
        sid = (await driver.call(
            "launch_gdb", {"program": program_path(task)}
        ))["session_id"]
        await driver.call(
            "set_breakpoint", {"location": "report", "session_id": sid}
        )
        await driver.call("execute_command", {"command": "run", "session_id": sid})
        await settle(driver, sid, {"stopped"})
    else:
        sid = (await driver.call(
            "launch_gdb", {"program": program_path(task), "run": True}
        ))["session_id"]
        await settle(driver, sid, {"stopped"})
    return sid


def _frame_function(frames: list, index: int) -> str:
    if len(frames) <= index:
        raise VerifyError("backtrace has no frame %d" % index)
    name = str(frames[index].get("function") or "")
    if not name:
        raise VerifyError("frame %d has no function name" % index)
    return name


async def derive_truth(driver, session_id: str, task) -> dict:
    """Re-derive every fact from the live session (harness-side queries only).

    This is the ground truth for ``kind: "fact"`` grading — the answer is
    compared against THIS, never against task params.
    """
    params = task.params
    if params["shape"] == "report_globals":
        bt = await driver.call(
            "get_backtrace", {"session_id": session_id, "max_frames": 2}
        )
        frames = bt.get("frames") or []
        if "report" not in _frame_function(frames, 0):
            raise VerifyError(
                "session is not stopped inside report(): frame0=%r"
                % _frame_function(frames, 0)
            )
        regs = await driver.call(
            "read_registers", {"names": ["rdi"], "session_id": session_id}
        )
        token = parse_int((regs.get("regs") or {}).get("rdi"))
        if token is None:
            raise VerifyError("rdi unreadable: %r" % (token_raw,))
        truth: dict = {"token": token & 0xFFFFFFFF}
        for name, size in (("idg", 4), ("uflag", 4), ("strv", 2)):
            mem = await driver.call(
                "read_memory",
                {"address": "&" + name, "length": size, "session_id": session_id},
            )
            hexstr = (mem.get("hex") or "").replace(" ", "")
            if len(hexstr) < size * 2:
                raise VerifyError("short read at &%s: %r" % (name, mem))
            truth[name] = int.from_bytes(bytes.fromhex(hexstr[: size * 2]), "little")
        return truth

    stop = await driver.call("get_stop_reason", {"session_id": session_id})
    info = stop.get("stop_info") or {}
    if not info.get("signal"):
        raise VerifyError("no stop signal: %r" % (stop,))
    bt = await driver.call(
        "get_backtrace", {"session_id": session_id, "max_frames": 2}
    )
    frames = bt.get("frames") or []
    fault = parse_int(info.get("fault_addr"))
    if fault is None:
        raise VerifyError("fault address missing: %r" % (info,))
    return {
        "signal": str(info["signal"]),
        "fault_addr": fault,
        "pc_function": _frame_function(frames, 0),
        "caller_function": _frame_function(frames, 1),
    }
