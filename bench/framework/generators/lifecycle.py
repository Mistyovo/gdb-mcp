"""Family: lifecycle — launch / run / pause / exit-code control.

Three shapes per seed:
* ``natural``   — run the program to natural exit (exit-code check)
* ``exit_code`` — make the inferior exit with a derived code (argv control:
                  the program exits with ``base + atoi(argv[1])``)
* ``interrupt`` — pause a busy-looping inferior (SIGINT stop check)
"""

from __future__ import annotations

from ..schema import Check
from .common import flags_for, make_task, program_path, rng_for

FAMILY = "lifecycle"

_SOURCE = """#include <stdlib.h>
#include <unistd.h>

__attribute__((noinline)) int finish(int code) {{ return code; }}

int main(int argc, char **argv) {{
    if (argc > 1 && argv[1][0] == 'b') {{
        volatile unsigned guard = 0;
        while (guard + 1 != 0) guard++;   /* busy loop for interrupt tests */
        return finish(0);
    }}
    int base = {base};
    if (argc > 1) return finish(base + atoi(argv[1]));
    return finish(base + {delta});
}}
"""


def generate(seed: int):
    rng = rng_for(seed)
    shape = ["natural", "exit_code", "interrupt"][seed % 3]
    build = flags_for(seed)
    base = rng.randrange(1, 30)
    delta = rng.randrange(1, 60)

    if shape == "natural":
        prompt = (
            "Launch the program under gdb and let it run to natural completion. "
            "Leave the session showing the inferior's final exit."
        )
        checks = [
            Check(op="exit_code", spec={"code": base + delta}),
            Check(op="session_alive"),
        ]
        params = {"shape": shape, "base": base, "delta": delta}
        max_steps = 4
        difficulty = "easy"
        tags = ["lifecycle", "exit", _opt_tag(build)]
    elif shape == "exit_code":
        prompt = (
            "Launch the program under gdb so that it exits with exit code %d. "
            "The program's exit code depends on its command line: inspect it "
            "and pass the argument that produces the required code."
            % (base + delta)
        )
        checks = [
            Check(op="exit_code", spec={"code": base + delta}),
            Check(op="session_alive"),
        ]
        params = {"shape": shape, "base": base, "delta": delta, "arg": str(delta)}
        max_steps = 6
        difficulty = "easy"
        tags = ["lifecycle", "exit-code", "argv", _opt_tag(build)]
    else:
        prompt = (
            "Launch the program with the argument 'busy' under gdb, start it, "
            "then pause the running inferior. Leave the session stopped."
        )
        checks = [
            Check(op="stop_signal", spec={"signal": "SIGINT"}),
            Check(op="session_alive"),
        ]
        params = {"shape": shape, "base": base, "delta": delta, "arg": "busy"}
        max_steps = 5
        difficulty = "medium"
        tags = ["lifecycle", "interrupt", "SIGINT", _opt_tag(build)]

    return make_task(
        family=FAMILY, seed=seed, kind="state", difficulty=difficulty, tags=tags,
        source=_SOURCE.format(**params), build=build, params=params, prompt=prompt,
        max_steps=max_steps, checks=checks,
    )


def _opt_tag(build) -> str:
    from .common import opt_level

    return {"-O0": "O0", "-O1": "O1", "-O2": "O2", "-O3": "O3"}.get(opt_level(build), "O0")


async def reference_solve(driver, task) -> str:
    """Deterministic solve: launch (with the right argv), drive to the end state."""
    from .common import settle, STOP_STATES

    params = task.params
    args: list[str] = []
    if params["shape"] == "interrupt":
        args = ["busy"]
    elif params["shape"] == "exit_code":
        args = [str(params["delta"])]
    launched = await driver.call(
        "launch_gdb",
        {"program": program_path(task), "args": args or None, "run": True},
    )
    sid = launched["session_id"]
    if params["shape"] == "interrupt":
        # the busy loop never stops on its own — pause it, confirm the stop
        await settle(driver, sid, {"running"})
        await driver.call("interrupt", {"session_id": sid})
        await settle(driver, sid, STOP_STATES)
    else:
        await settle(driver, sid, {"exited", "ready", "stopped"})
    return sid
