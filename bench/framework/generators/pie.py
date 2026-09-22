"""Family: pie — reason about the runtime load base of a PIE binary.

The agent must determine where the kernel actually mapped the executable and
store that base into the global ``reported_base``. The grader re-derives the
base independently at grading time (live ``&anchor`` minus the build-recorded
symbol offset), so a wrong or guessed base cannot pass. Requires -pie builds.
"""

from __future__ import annotations

from ..schema import BuildSpec, Check
from .common import make_task, program_path, rng_for, settle

FAMILY = "pie"

_SOURCE = """#include <stdio.h>

const char anchor[64] = "pie-anchor";
unsigned long reported_base = 0;

__attribute__((noinline)) int touch(void) {{
    return anchor[0];
}}

int main(void) {{
    printf("%d\\n", touch());
    return 0;
}}
"""


def generate(seed: int):
    rng = rng_for(seed)
    # PIE is the point of this family — force it.
    build = BuildSpec(flags=["-O%d" % (seed % 2 * 2), "-pie"])
    prompt = (
        "The program is position-independent. Launch it stopped, determine "
        "the runtime load base of the main executable (the address where the "
        "first segment of the binary was mapped), and store that 8-byte "
        "little-endian value into the global 'reported_base' before leaving "
        "the session stopped. Do not guess: the value must be the real base "
        "of this run."
    )
    checks = [
        # expected base == live &anchor - build-recorded offset(anchor); the
        # grader derives it itself from live state, never from task params.
        Check(op="memory_value",
              spec={"expr": "&reported_base", "size": 8,
                    "value": {"anchor_offset_of": "anchor"}}),
        Check(op="session_alive"),
    ]
    params = {"anchor_hint": rng.randrange(1, 7)}  # unused in checks; keeps seeds distinct
    return make_task(
        family=FAMILY, seed=seed, kind="state", difficulty="medium",
        tags=["pie", "aslr", "vmmap", "memory-write"],
        source=_SOURCE.format(**params), build=build, params=params, prompt=prompt,
        max_steps=10, checks=checks,
    )


async def reference_solve(driver, task) -> str:
    sid = (await driver.call(
        "launch_gdb", {"program": program_path(task)}
    ))["session_id"]
    await driver.call("set_breakpoint", {"location": "main", "session_id": sid})
    await driver.call("execute_command", {"command": "run", "session_id": sid})
    await settle(driver, sid, {"stopped"})
    # observe where the loader actually put the binary, then report it the
    # same way an agent would: anchor runtime address minus its file offset
    anchor_addr = (await driver.call(
        "evaluate", {"expression": "&anchor", "session_id": sid}
    ))["address"]
    anchor_off = int(task.target.symbols["anchor"], 16)
    base = int(anchor_addr, 16) - anchor_off
    hexstr = base.to_bytes(8, "little").hex()
    await driver.call(
        "write_memory",
        {"address": "&reported_base", "hex": hexstr, "session_id": sid},
    )
    return sid
