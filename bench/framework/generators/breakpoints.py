"""Family: breakpoints — software bps, conditional bps, watchpoints.

One loop target; three shapes per seed:
* ``first_hit``  — stop inside ``audit`` on its first invocation
* ``conditional``— trigger only when the global loop counter g_i equals K.
  Built without -g on purpose: with minimal symbols only, a condition on a
  *local* cannot even be set, so the idiom is the cast-global form
  ``*(int *)&g_i == K`` — exactly what a pwn practitioner writes.
* ``watch``      — stop when global ``probe`` changes; likewise needs the
  cast form ``watch *(int *)&probe`` because the type is unknown without
  DWARF.

The inferior must be *started* with `run` (continue_execution does not
launch an unstarted inferior), and stops surface asynchronously — the
reference solve polls to a settled state.
"""

from __future__ import annotations

from ..schema import Check
from .common import opt_level, flags_for, make_task, program_path, rng_for, settle

FAMILY = "breakpoints"

_SOURCE = """#include <stdio.h>

int probe = {probe_init};
int g_i = -1;

__attribute__((noinline)) void audit(int i, int secret) {{
    printf("%d %d\\n", i, secret);
}}

__attribute__((noinline)) int work(void) {{
    int acc = {acc_seed};
    for (int i = 0; i < {iters}; i++) {{
        g_i = i;
        if (i == {watch_iter}) probe = {probe_val};
        acc = acc * 3 + i;
        audit(i, acc);
    }}
    return acc;
}}

int main(void) {{
    return work() % 7;
}}
"""


def generate(seed: int):
    rng = rng_for(seed)
    shape = ["first_hit", "conditional", "watch"][seed % 3]
    build = flags_for(seed)
    iters = rng.randrange(12, 32)
    watch_iter = rng.randrange(3, iters - 2)
    probe_init = rng.randrange(100, 999)
    probe_val = probe_init + rng.randrange(1000, 9999)
    k = iters // 2
    params = {"shape": shape, "iters": iters, "watch_iter": watch_iter,
              "probe_init": probe_init, "probe_val": probe_val,
              "acc_seed": rng.randrange(1, 5000), "k": k}

    if shape == "first_hit":
        prompt = (
            "Set a breakpoint on the function 'audit' and run the program so "
            "it stops at the first call. Leave the session stopped at that hit."
        )
        checks = [
            Check(op="breakpoint_present", spec={"symbol": "audit"}),
            Check(op="breakpoint_hit", spec={"symbol": "audit"}),
            Check(op="backtrace_contains",
                  spec={"functions": ["audit", "work", "main"]}),
            Check(op="session_alive"),
        ]
        difficulty = "easy"
        tags = ["breakpoints", "software-bp", "backtrace", _opt(build)]
        max_steps = 5
    elif shape == "conditional":
        cond = "*(int *)&g_i == %d" % k
        prompt = (
            "The loop mirrors its index into the global 'g_i' before each "
            "'audit' call. Set a breakpoint on 'audit' that triggers only "
            "when g_i equals %d (remember: this binary has no debug info, "
            "so read the 4-byte int through a cast), run until it fires, "
            "and leave the session stopped there." % k
        )
        checks = [
            Check(op="breakpoint_present",
                  spec={"symbol": "audit", "condition": cond}),
            Check(op="breakpoint_hit",
                  spec={"symbol": "audit", "condition": cond}),
            Check(op="memory_value", spec={"expr": "&g_i", "size": 4, "value": k}),
            Check(op="session_alive"),
        ]
        difficulty = "medium"
        tags = ["breakpoints", "conditional", "no-dwarf", _opt(build)]
        max_steps = 6
    else:
        prompt = (
            "Stop the program when the global variable 'probe' changes value: "
            "set a watchpoint on the 4-byte int at &probe (no debug info — "
            "cast the address), run until it fires, and leave the session "
            "stopped at the write."
        )
        checks = [
            Check(op="breakpoint_present", spec={"type": "watch"}),
            Check(op="breakpoint_hit", spec={"type": "watch"}),
            Check(op="memory_value",
                  spec={"expr": "&probe", "size": 4, "value": probe_val}),
            Check(op="session_alive"),
        ]
        difficulty = "medium"
        tags = ["watchpoint", "memory", "no-dwarf", _opt(build)]
        max_steps = 6

    return make_task(
        family=FAMILY, seed=seed, kind="state", difficulty=difficulty, tags=tags,
        source=_SOURCE.format(**params), build=build, params=params, prompt=prompt,
        max_steps=max_steps, checks=checks,
    )


def _opt(build) -> str:
    return {"-O0": "O0", "-O1": "O1", "-O2": "O2", "-O3": "O3"}.get(opt_level(build), "O0")


async def reference_solve(driver, task) -> str:
    params = task.params
    sid = (await driver.call(
        "launch_gdb", {"program": program_path(task)}
    ))["session_id"]
    if params["shape"] == "first_hit":
        await driver.call("set_breakpoint", {"location": "audit", "session_id": sid})
    elif params["shape"] == "conditional":
        await driver.call(
            "execute_command",
            {"command": "break audit if *(int *)&g_i == %d" % params["k"],
             "session_id": sid},
        )
    else:
        await driver.call(
            "execute_command",
            {"command": "watch *(int *)&probe", "session_id": sid},
        )
    # `run` returns as soon as the inferior is on its way; stops are async
    await driver.call("execute_command", {"command": "run", "session_id": sid})
    await settle(driver, sid, {"stopped"})
    return sid
