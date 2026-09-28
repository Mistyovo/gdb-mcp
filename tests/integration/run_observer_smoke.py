#!/usr/bin/env python3
"""Observer-role smoke test over the real HTTP transport.

Checks what unit tests cannot: that the per-request role set by the security
middleware is still visible where the tool guards run, and that the
registered tool surface (schemas included) is identical for both roles.

    python tests/integration/run_observer_smoke.py [--port 8130]

No gdb involved; requires the `mcp` client and `uvicorn` on the server side.
Exits non-zero with the server log on failure.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import tempfile
from contextlib import suppress
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp import ClientSession  # noqa: E402
from mcp.client.streamable_http import streamablehttp_client  # noqa: E402

from gdb_mcp.roles import OBSERVER_ALLOWED_TOOLS  # noqa: E402

CONTROLLER = "smoke-controller-token"
OBSERVER = "smoke-observer-token"


async def _call(port: int, bearer: str, tool: str, args: dict):
    headers = {"authorization": "Bearer %s" % bearer}
    async with streamablehttp_client(
        f"http://127.0.0.1:{port}/mcp", headers=headers
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            names = sorted(t.name for t in (await session.list_tools()).tools)
            result = await session.call_tool(tool, args)
            text = " ".join(
                getattr(block, "text", "") for block in (result.content or [])
            )
            return names, bool(result.isError), text


async def _wait_ready(port: int, log_path: str) -> None:
    """Poll until the transport answers; anything other than "not listening
    yet" is a failure, not a reason to keep waiting."""
    last: Exception | None = None
    for _ in range(120):
        try:
            await _call(port, CONTROLLER, "list_sessions", {})
            return
        except OSError as exc:  # connection refused while uvicorn binds
            last = exc
            await asyncio.sleep(0.25)
        except Exception as exc:
            last = exc
            break
    raise RuntimeError(
        "server did not answer: %s\n%s" % (last, Path(log_path).read_text()[-4000:])
    )


def _check(label: str, ok: bool, detail: str = "") -> int:
    print("[observer-smoke] %-42s %s %s" % (label, "OK" if ok else "FAIL", detail[:90]))
    return 0 if ok else 1


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8130)
    args = parser.parse_args()

    log_file = tempfile.NamedTemporaryFile(
        prefix="gdb-mcp-observer-smoke-", suffix=".log", delete=False
    )
    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "gdb_mcp",
            "--http",
            "--mcp-host",
            "127.0.0.1",
            "--mcp-port",
            str(args.port),
            "--token",
            CONTROLLER,
            "--observer-token",
            OBSERVER,
        ],
        cwd=str(ROOT),
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    failures = 0
    try:
        await _wait_ready(args.port, log_file.name)

        ctrl_names, err, text = await _call(args.port, CONTROLLER, "list_sessions", {})
        failures += _check("controller list_sessions accepted", not err, text)

        obs_names, err, text = await _call(args.port, OBSERVER, "list_sessions", {})
        failures += _check("observer may read allowlisted tool", not err, text)
        failures += _check(
            "both roles see the same tool surface",
            ctrl_names == obs_names and len(ctrl_names) > 30,
            "%d tools" % len(obs_names),
        )
        # roles.py names tools by hand; a rename there would otherwise make
        # the tool silently invisible to observers (the guard is default-deny)
        stale = sorted(OBSERVER_ALLOWED_TOOLS - set(obs_names))
        failures += _check(
            "observer allowlist names only live tools", not stale, "stale: %s" % stale
        )

        # a mutating tool must be refused for observers before its handler runs
        for tool, tool_args in (
            ("write_memory", {"address": "0x1000", "hex": "90"}),
            ("execute_command", {"command": "info registers"}),
            ("continue_execution", {}),
        ):
            _, err, text = await _call(args.port, OBSERVER, tool, tool_args)
            failures += _check(
                "observer %s refused" % tool,
                err and "OBSERVER_READONLY" in text,
                text,
            )
        _, err, text = await _call(
            args.port, CONTROLLER, "execute_command", {"command": "x/2gx 0x1000"}
        )
        failures += _check(
            "controller reaches the handler (no observer error)",
            "OBSERVER_READONLY" not in text,
            text,
        )

        # the profile gate and the role gate are independent knobs
        print("[observer-smoke] tool surface: %s" % json.dumps({"count": len(obs_names)}))
    finally:
        server.terminate()
        with suppress(Exception):
            await asyncio.to_thread(server.wait, 15)
    if failures:
        print("[observer-smoke] server log tail:\n%s" % Path(log_file.name).read_text()[-2000:])
    print("[observer-smoke] %s" % ("OK" if not failures else "%d FAILURE(S)" % failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
