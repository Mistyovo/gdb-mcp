"""Shared helpers for task family generators.

Every family module exposes:

* ``FAMILY``           — its name (== directory under bench/tasks/)
* ``generate(seed)``   — one deterministic :class:`TaskSpec` per seed
* ``reference_solve(driver, task)`` — deterministic MCP op script proving the
  task is solvable (returns the session id it created)

Seeds are the *only* entropy: same seed ⇒ identical manifest, forever. The
hidden set is simply seed ranges never committed under bench/tasks/.
"""

from __future__ import annotations

import random

from ..schema import BuildSpec, Check, TargetSpec, TaskSpec

# Build-flag matrix: index by seed so difficulty and binary shape vary while
# staying deterministic. No -g anywhere: debug info would embed absolute
# paths and break binary-hash reproducibility.
FLAG_MATRIX: list[BuildSpec] = [
    BuildSpec(flags=["-O0"]),
    BuildSpec(flags=["-O0", "-no-pie"]),
    BuildSpec(flags=["-O1"]),
    BuildSpec(flags=["-O2"]),
    BuildSpec(flags=["-O2", "-no-pie"]),
    BuildSpec(flags=["-O3"]),
    BuildSpec(flags=["-O2", "-pie"]),
]

THREAD_LDFLAGS = ["-pthread"]


def flags_for(seed: int) -> BuildSpec:
    return FLAG_MATRIX[seed % len(FLAG_MATRIX)]


def opt_level(build: BuildSpec) -> str:
    for flag in build.flags:
        if flag.startswith("-O"):
            return flag
    return "-O0"


def is_pie(build: BuildSpec) -> bool:
    return "-no-pie" not in build.flags


def rng_for(seed: int) -> random.Random:
    return random.Random(seed)


def make_task(
    family: str,
    seed: int,
    kind: str,
    difficulty: str,
    tags: list[str],
    source: str,
    build: BuildSpec,
    params: dict,
    prompt: str,
    max_steps: int,
    checks: list[Check],
) -> TaskSpec:
    return TaskSpec(
        id="%s-%04d" % (family, seed),
        family=family,
        kind=kind,
        difficulty=difficulty,
        tags=tags,
        target=TargetSpec(name="%s_%04d" % (family, seed), source=source, build=build),
        params=params,
        prompt=prompt,
        max_steps=max_steps,
        checks=checks,
    )


def program_path(task: TaskSpec) -> str:
    """Windows path of the compiled binary (launcher converts for WSL)."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    return str(root / "bench" / "targets_out" / task.target.name / task.target.name)


#: States a settled session may legitimately sit in. After a crash or exit
#: the prompt event can flip STOPPED to READY before any poll observes it, so
#: synchronization must not depend on catching the transient.
SETTLED_STATES = frozenset({"stopped", "ready", "exited"})


async def settle(driver, session_id: str, want: set[str] | None = None,
                 timeout_s: float = 15.0) -> dict:
    """Poll session state until it reaches one of ``want`` (event timing in
    WSL is asynchronous relative to tool returns). Defaults to
    SETTLED_STATES."""
    import asyncio
    import time

    deadline = time.monotonic() + timeout_s
    result: dict = {}
    want = want if want is not None else SETTLED_STATES
    while time.monotonic() < deadline:
        result = await driver.call("get_stop_reason", {"session_id": session_id})
        if result.get("state") in want:
            return result
        await asyncio.sleep(0.25)
    return result
