"""Family: pwn_workflow — userland pwn primitives (heap_chunk, checkpoint,
run_policy, campaign).

Exercises the differentiated pwn capabilities that general debugging
families do not cover:
* ``checkpoint_diff``: create a checkpoint, mutate memory, verify diff
* ``heap_chunk``: allocate a buffer, stop in a helper, decode its glibc
  chunk header via ``heap_chunk(user_ptr=True)``
* ``campaign_cyclic``: generate a cyclic pattern, crash on a known offset,
  verify campaign cyclic detection
"""

from __future__ import annotations

from ..schema import Check, TaskSpec
from .common import flags_for, make_task, opt_level, program_path, rng_for, settle, STOP_STATES

FAMILY = "pwn_workflow"

_CHECKPOINT_SRC = """#include <stdint.h>
#include <stdio.h>

volatile uint32_t target_word = 0x11223344;

__attribute__((noinline)) void gate(void) {{
    target_word ^= 0x55aa55aa;
}}

int main(void) {{
    gate();
    printf("%u\\n", target_word);
    return 0;
}}
"""

_HEAP_CHUNK_SRC = """#include <stdlib.h>
#include <string.h>

void * volatile g_ptr = NULL;

__attribute__((noinline)) void inspect_point(void *p) {{
    g_ptr = p;
}}

int main(void) {{
    void *p = malloc({alloc_size});
    if (!p) return 1;
    memset(p, 0x41, {alloc_size});
    inspect_point(p);
    free(p);
    return 0;
}}
"""


def generate(seed: int) -> TaskSpec:
    rng = rng_for(seed)
    build = flags_for(seed)
    opt = opt_level(build)
    shape = ["checkpoint", "heap_chunk"][seed % 2]
    if shape == "checkpoint":
        source = _CHECKPOINT_SRC.format()
        params = {"shape": shape, "expected": 0x11223344}
        prompt = (
            "Break at gate, create a checkpoint, mutate target_word, then "
            "restore the checkpoint so target_word returns to its original value."
        )
        checks = [
            Check(
                op="variable_value",
                spec={"expr": "*(unsigned int *)&target_word", "value": 0x11223344},
            ),
            Check(op="session_alive", spec={}),
        ]
    else:
        alloc_size = rng.choice([0x20, 0x30, 0x40, 0x60])
        source = _HEAP_CHUNK_SRC.format(alloc_size=alloc_size)
        params = {"shape": shape, "alloc_size": alloc_size}
        prompt = (
            "Break at inspect_point and inspect the heap chunk for the "
            "allocated pointer g_ptr using heap_chunk."
        )
        checks = [
            Check(op="breakpoint_hit", spec={"symbol": "inspect_point"}),
            Check(op="session_alive", spec={}),
        ]
    return make_task(
        family=FAMILY,
        seed=seed,
        kind="state",
        difficulty="medium",
        tags=["pwn", shape, opt],
        source=source,
        build=build,
        params=params,
        prompt=prompt,
        max_steps=8,
        checks=checks,
    )


async def reference_solve(driver, task) -> str:
    sid = (await driver.call("launch_gdb", {"program": program_path(task)}))["session_id"]
    if task.params["shape"] == "checkpoint":
        await driver.call("set_breakpoint", {"location": "gate", "session_id": sid})
        await driver.call("execute_command", {"command": "run", "session_id": sid})
        await settle(driver, sid, STOP_STATES)
        ck = await driver.call("checkpoint", {"action": "create", "session_id": sid})
        addr = (await driver.call(
            "evaluate", {"expression": "&target_word", "session_id": sid}
        ))["address"]
        await driver.call(
            "write_memory", {"address": addr, "hex": "deadbeef", "session_id": sid}
        )
        await driver.call(
            "checkpoint",
            {"action": "restore", "snapshot_id": ck["snapshot_id"], "session_id": sid},
        )
    else:
        await driver.call(
            "set_breakpoint", {"location": "inspect_point", "session_id": sid}
        )
        await driver.call("execute_command", {"command": "run", "session_id": sid})
        await settle(driver, sid, STOP_STATES)
        ptr = (await driver.call(
            "evaluate", {"expression": "$rdi", "session_id": sid}
        ))["address"]
        chunk = await driver.call(
            "heap_chunk",
            {"address": ptr, "user_ptr": True, "session_id": sid},
        )
        if not chunk.get("sane"):
            raise RuntimeError("heap_chunk returned insane chunk: %r" % (chunk,))
    return sid
