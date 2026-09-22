"""Family: crash — SIGSEGV triage with deterministic fault addresses.

The target dereferences ``NULL + 4*idx`` for a seed-chosen ``idx``, so the
fault address is exactly ``4*idx`` — the agent must *report nothing*: the
grader verifies the stop signal, the fault address, the stopping PC and the
call chain against parameters baked into the source.
"""

from __future__ import annotations

from ..schema import Check
from .common import opt_level, flags_for, make_task, program_path, rng_for

FAMILY = "crash"

_SOURCE = """#include <stdlib.h>

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
    crash_idx = rng.randrange(3, 64)          # fault address = 4 * crash_idx
    fault = 4 * crash_idx
    prompt = (
        "Run the program under gdb; it will crash. Keep the session stopped "
        "at the crash so the debugger shows the faulting state."
    )
    checks = [
        Check(op="stop_signal", spec={"signal": "SIGSEGV"}),
        Check(op="fault_addr", spec={"addr": fault}),
        Check(op="session_alive"),
    ]
    # frame-shape checks only where the optimizer keeps the call chain intact
    if opt_level(build) in ("-O0", "-O1"):
        checks.insert(
            2,
            Check(op="backtrace_contains",
                  spec={"functions": ["deref", "trigger", "main"]}),
        )
    params = {"crash_idx": crash_idx, "fault_addr": fault}
    return make_task(
        family=FAMILY, seed=seed, kind="state", difficulty="easy",
        tags=["crash", "segfault", "fault-addr",
              {"-O0": "O0", "-O1": "O1", "-O2": "O2", "-O3": "O3"}[opt_level(build)]],
        source=_SOURCE.format(**params), build=build, params=params, prompt=prompt,
        max_steps=4, checks=checks,
    )


async def reference_solve(driver, task) -> str:
    from .common import settle

    sid = (await driver.call(
        "launch_gdb", {"program": program_path(task), "run": True}
    ))["session_id"]
    await settle(driver, sid, {"stopped"})
    return sid
