"""E3 bench runner #1: drive DeepSeek to solve bench/crackmes/win.c.

Run INSIDE WSL (it drives a local gdb and binds 127.0.0.1 there):

    wsl.exe -d kali-linux -- bash -lc \\
      'cd /mnt/c/Users/<you>/Develop/gdb-mcp && python3 bench/run_win.py'
    # add --go to really call the API (spends quota)

Difficulty: EASY (ret2win). The harness (session, tools, scoring) lives
in bench/harness.py; this file only declares the target.

Requires: gdb + python3 in WSL; DEEPSEEK_API_KEY in the environment or
the repo-local .env (read via /mnt/c when invoked from the repo copy).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import BenchSpec, run_spec  # noqa: E402

SPEC = BenchSpec(
    name="win",
    source="win.c",
    binary="/tmp/win_bench",
    port=39410,
    delivery="argv",
    task=(
        "The binary /tmp/win_bench takes one argv argument into a "
        "stack buffer. Find and execute the hidden win() function by "
        "overflowing the buffer, using run_payload. You are done when "
        "the output contains WIN{."
    ),
    win_marker="WIN{",
)


def _selftest(tools) -> None:
    sample = tools["run_payload"]({"payload": "A" * 80})
    verdict = sample["verdict"]
    assert verdict["ended"] in ("stop", "exited"), sample
    assert any(
        "back from strcpy" in line for line in sample["output_lines"]
    ), sample
    assert sample["win"] is False


SPEC.selftest = _selftest


if __name__ == "__main__":
    raise SystemExit(run_spec(SPEC))
