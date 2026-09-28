"""Family: threads — stop a specific worker under a data-dependent condition.

Two workers bump distinct counters; the agent must place a conditional
breakpoint on ``worker_b`` so the debuggee stops inside that worker exactly
when its counter reaches K — with all inferior threads alive at the stop.
"""

from __future__ import annotations

from ..schema import Check
from .common import THREAD_LDFLAGS, flags_for, make_task, program_path, rng_for, settle, STOP_STATES

FAMILY = "threads"

_SOURCE = """#include <pthread.h>
#include <stdio.h>

volatile int ta = 0;
volatile int tb = 0;

__attribute__((noinline)) void *worker_a(void *arg) {{
    (void)arg;
    for (int i = 0; i < {na}; i++) ta++;
    return NULL;
}}

__attribute__((noinline)) void bump(void) {{
    tb++;
}}

__attribute__((noinline)) void *worker_b(void *arg) {{
    (void)arg;
    for (int i = 0; i < {nb}; i++) bump();
    return NULL;
}}

int main(void) {{
    pthread_t a, b;
    pthread_create(&a, NULL, worker_a, NULL);
    pthread_create(&b, NULL, worker_b, NULL);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    printf("%d %d\\n", ta, tb);
    return 0;
}}
"""


def generate(seed: int):
    rng = rng_for(seed)
    build = flags_for(seed)
    build.ldflags = list(THREAD_LDFLAGS)
    na = rng.randrange(20, 60)
    nb = rng.randrange(20, 60)
    k = max(2, nb // 3)
    prompt = (
        "The program runs two worker threads incrementing separate counters. "
        "Make the debugger stop inside 'worker_b' exactly when its counter tb "
        "equals %d, and leave the session stopped there with every thread "
        "still alive." % k
    )
    checks = [
        Check(op="breakpoint_present",
              spec={"symbol": "bump",
                    "condition": "*(int *)&tb == %d" % k}),
        Check(op="breakpoint_hit",
              spec={"symbol": "bump",
                    "condition": "*(int *)&tb == %d" % k}),
        Check(op="memory_value", spec={"expr": "&tb", "size": 4, "value": k}),
        Check(op="thread_count", spec={"min_threads": 2}),
        Check(op="thread_stopped_at", spec={"function": "bump"}),
        Check(op="session_alive"),
    ]
    params = {"na": na, "nb": nb, "k": k}
    return make_task(
        family=FAMILY, seed=seed, kind="state", difficulty="medium",
        tags=["threads", "conditional-bp", "concurrency"],
        source=_SOURCE.format(**params), build=build, params=params, prompt=prompt,
        max_steps=8, checks=checks,
    )


async def reference_solve(driver, task) -> str:
    params = task.params
    sid = (await driver.call(
        "launch_gdb", {"program": program_path(task)}
    ))["session_id"]
    await driver.call(
        "execute_command",
        {"command": "break bump if *(int *)&tb == %d" % params["k"],
         "session_id": sid},
    )
    await driver.call("execute_command", {"command": "run", "session_id": sid})
    await settle(driver, sid, STOP_STATES)
    return sid
