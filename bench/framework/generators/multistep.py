"""Family: multistep — 5-20 step observe->decide->act state machines.

``gate(i)`` validates ``answers[i] == keys[i] ^ mask`` at its own entry. The
agent must, per stage: continue to the gate hit, read ``keys[i]`` from live
memory, derive the answer, write it, and resume. One wrong byte aborts with
a distinct exit code, so ``exit_code == 0`` proves every stage succeeded.
Keys exist only at runtime — the answer values are not in this manifest.
"""

from __future__ import annotations

from ..schema import Check
from .common import opt_level, flags_for, make_task, program_path, rng_for, settle

FAMILY = "multistep"

_SOURCE = """#include <stdio.h>

static unsigned keys[{nstages}];
unsigned answers[{nstages}] = {{0}};

__attribute__((noinline)) int gate(int stage) {{
    unsigned want = keys[stage] ^ {mask}u;
    return answers[stage] == want ? 0 : 1;
}}

int main(void) {{
    unsigned s = {cseed}u;
    for (int i = 0; i < {nstages}; i++) {{
        s = s * 1103515245u + 12345u;
        keys[i] = s;
    }}
    for (int i = 0; i < {nstages}; i++) {{
        if (gate(i)) return 91 + i;
    }}
    return 0;
}}
"""


def generate(seed: int):
    rng = rng_for(seed)
    build = flags_for(seed)
    nstages = rng.randrange(3, 10)             # steps = 2*nstages + 2
    mask = rng.randrange(0x1000, 0xFFFFFFF)
    cseed = rng.randrange(1, 1000000)
    steps = 2 * nstages + 2
    prompt = (
        "The program validates %d staged answers and only exits with 0 if "
        "every stage is satisfied. Stage i requires answers[i] to equal "
        "keys[i] XOR %u (unsigned 32-bit). Drive the program so that every "
        "gate passes and the inferior exits with code 0. You must read each "
        "key from live memory — the keys are not known before the run."
        % (nstages, mask)
    )
    checks = [
        Check(op="exit_code", spec={"code": 0}),
        Check(op="session_alive"),
    ]
    params = {"nstages": nstages, "mask": mask, "cseed": cseed}
    return make_task(
        family=FAMILY, seed=seed, kind="state",
        difficulty="hard" if nstages >= 6 else "medium",
        tags=["multistep", "state-machine", "dynamic-decision",
              {"-O0": "O0", "-O1": "O1", "-O2": "O2", "-O3": "O3"}[opt_level(build)]],
        source=_SOURCE.format(**params), build=build, params=params, prompt=prompt,
        max_steps=steps + 3, checks=checks,
    )


async def reference_solve(driver, task) -> str:
    params = task.params
    nstages = params["nstages"]
    mask = params["mask"]
    sid = (await driver.call(
        "launch_gdb", {"program": program_path(task)}
    ))["session_id"]
    await driver.call("set_breakpoint", {"location": "gate", "session_id": sid})
    # `run` stops at the gate(0) hit; later stages resume explicitly
    await driver.call("execute_command", {"command": "run", "session_id": sid})
    await settle(driver, sid, {"stopped"})
    base2 = int((await driver.call(
        "evaluate", {"expression": "&answers", "session_id": sid}
    ))["address"], 16)
    for stage in range(nstages):
        if stage > 0:
            await driver.call(
                "continue_execution",
                {"wait": True, "timeout_ms": 10000, "session_id": sid},
            )
            await settle(driver, sid, {"stopped"})
        base = int((await driver.call(
            "evaluate", {"expression": "&keys", "session_id": sid}
        ))["address"], 16)
        mem = await driver.call(
            "read_memory",
            {"address": base + 4 * stage, "length": 4, "session_id": sid},
        )
        key_val = int.from_bytes(bytes.fromhex(mem["hex"][:8]), "little")
        answer = key_val ^ (mask & 0xFFFFFFFF)
        await driver.call(
            "write_memory",
            {"address": base2 + 4 * stage,
             "hex": answer.to_bytes(4, "little").hex(), "session_id": sid},
        )
    await driver.call(
        "continue_execution", {"wait": True, "timeout_ms": 10000, "session_id": sid}
    )
    return sid
