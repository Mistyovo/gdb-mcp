"""Family: optimize — recover a value that only exists in a register at -O2/-O3.

``compute`` is a deterministic LCG whose expected result the *generator*
simulates in Python and bakes into the ground truth. Under optimization the
intermediate variables are gone; the agent must obtain the return value at
runtime and store it into ``result``. Wrong arithmetic cannot pass.
"""

from __future__ import annotations

from ..schema import BuildSpec, Check
from .common import make_task, program_path, rng_for, settle

FAMILY = "optimize"

_SOURCE = """#include <stdio.h>

unsigned result = 0;

__attribute__((noinline)) int compute(int seed) {{
    unsigned x = (unsigned)seed ^ 0x5a5a5a5au;
    for (int i = 0; i < {rounds}; i++) {{
        x = x * 1103515245u + 12345u;
    }}
    return (int)x;
}}

int main(void) {{
    printf("%u\\n", (unsigned)compute({seed_in}) % 101u);
    return 0;
}}
"""


def simulate(seed_in: int, rounds: int) -> int:
    """Mirror of the C arithmetic (unsigned 32-bit), used for ground truth."""
    x = (seed_in ^ 0x5A5A5A5A) & 0xFFFFFFFF
    for _ in range(rounds):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
    return x


def generate(seed: int):
    rng = rng_for(seed)
    build = BuildSpec(flags=["-O2"]) if seed % 2 == 0 else BuildSpec(flags=["-O3"])
    seed_in = rng.randrange(1, 100000)
    rounds = rng.randrange(3, 40)
    expected = simulate(seed_in, rounds)
    prompt = (
        "Launch the program stopped, then make the debugger stop right after "
        "'compute' has returned. The optimizer keeps its result only in a "
        "register: obtain it and store it (4-byte little-endian, unsigned) "
        "into the global 'result'. Leave the session stopped after the write."
    )
    checks = [
        Check(op="memory_value",
              spec={"expr": "&result", "size": 4, "value": expected}),
        Check(op="session_alive"),
    ]
    params = {"seed_in": seed_in, "rounds": rounds, "expected": expected}
    return make_task(
        family=FAMILY, seed=seed, kind="state", difficulty="hard",
        tags=["optimization", "O2-plus", "registers", "lcg"],
        source=_SOURCE.format(**params), build=build, params=params, prompt=prompt,
        max_steps=10, checks=checks,
    )


async def reference_solve(driver, task) -> str:
    sid = (await driver.call(
        "launch_gdb", {"program": program_path(task)}
    ))["session_id"]
    await driver.call("set_breakpoint", {"location": "compute", "session_id": sid})
    await driver.call("execute_command", {"command": "run", "session_id": sid})
    await settle(driver, sid, {"stopped"})
    await driver.call(
        "continue_execution",
        {"mode": "finish", "wait": True, "timeout_ms": 10000, "session_id": sid},
    )
    regs = await driver.call(
        "read_registers", {"names": ["rax"], "session_id": sid}
    )
    rax = int(regs["regs"]["rax"], 16) & 0xFFFFFFFF
    await driver.call(
        "write_memory",
        {"address": "&result", "hex": rax.to_bytes(4, "little").hex(), "session_id": sid},
    )
    return sid
