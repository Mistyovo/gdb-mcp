"""End-to-end walkthrough of the consolidated 17-tool MCP surface against
a real gdb in WSL2."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from gdb_mcp.wsl import win_to_wsl  # noqa: E402

CRASHER_SOURCE = ROOT / "examples" / "crasher.c"
CHILD_GDB_SCRIPT = ROOT / "tests" / "integration" / "launch_child_gdb.py"
PLUGIN = ROOT / "src" / "gdb_mcp" / "plugin" / "gdb_mcp_plugin.py"

REGISTERED_TOOLS = frozenset(
    {
        "breakpoint",
        "campaign",
        "checkpoint",
        "control_execution",
        "crash_report",
        "execute_command",
        "heap",
        "inferior_io",
        "inspect_code",
        "kill_session",
        "launch_gdb",
        "load_target",
        "memory",
        "registers",
        "run_policy",
        "session_info",
        "thread_frame",
    }
)

WALKTHROUGH_TOOLS = frozenset(
    {
        "session_info",
        "launch_gdb",
        "kill_session",
        "execute_command",
        "control_execution",
        "memory",
        "registers",
        "inspect_code",
        "thread_frame",
        "load_target",
        "breakpoint",
        "crash_report",
        "heap",
        "campaign",
    }
)


class E2EFailure(RuntimeError):
    pass


class ToolRunner:
    def __init__(self, session: ClientSession):
        self.session = session
        self.covered: set[str] = set()

    async def call(self, name: str, arguments: dict[str, Any] | None = None) -> dict:
        result = await self.session.call_tool(name, arguments or {})
        if result.isError:
            details = "\n".join(getattr(item, "text", str(item)) for item in result.content)
            raise E2EFailure("%s failed: %s" % (name, details))
        payload = result.structuredContent
        if payload is None:
            text = next(
                (item.text for item in result.content if getattr(item, "text", None)),
                "{}",
            )
            payload = json.loads(text)
        self.covered.add(name)
        print("[PASS] %-20s" % name, flush=True)
        return payload


def require(condition: Any, message: str) -> None:
    if not condition:
        raise E2EFailure(message)


async def run_wsl(distro: str, *argv: str) -> None:
    proc = await asyncio.create_subprocess_exec(
        "wsl.exe", "-d", distro, "--", *argv,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    if proc.returncode:
        raise E2EFailure("wsl %s failed: %s" % (" ".join(argv), (out + err).decode(errors="replace")))


async def wait_for_state(runner: ToolRunner, session_id: str, states: set[str], timeout: float = 10.0) -> dict:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        status = await runner.call("session_info", {"action": "status", "session_id": session_id})
        if status["state"] in states:
            return status
        await asyncio.sleep(0.1)
    raise E2EFailure("session %s did not reach %s" % (session_id, sorted(states)))


async def exercise_all(session: ClientSession, distro: str, program: str, plugin: str) -> None:
    runner = ToolRunner(session)
    registered = set()
    cursor = None
    while True:
        page = await session.list_tools(cursor=cursor)
        registered.update(tool.name for tool in page.tools)
        cursor = page.nextCursor
        if not cursor:
            break
    require(
        registered == REGISTERED_TOOLS,
        "registered mismatch: missing=%s extra=%s"
        % (sorted(REGISTERED_TOOLS - registered), sorted(registered - REGISTERED_TOOLS)),
    )

    owned: list[str] = []
    try:
        launched = await runner.call(
            "launch_gdb", {"distro": distro, "gdb_args": ["-nx"], "attach_timeout_ms": 15000}
        )
        sid = launched["session_id"]
        owned.append(sid)
        await wait_for_state(runner, sid, {"ready", "stopped"}, timeout=15.0)

        await runner.call("load_target", {"session_id": sid, "path": program})
        bp = await runner.call("breakpoint", {"action": "set", "session_id": sid, "location": "main"})
        await runner.call("breakpoint", {"action": "list", "session_id": sid})
        await runner.call("execute_command", {"session_id": sid, "command": "run"})
        stopped = await runner.call(
            "control_execution", {"action": "wait", "session_id": sid, "timeout_ms": 10000}
        )
        require(stopped["stopped"], "did not stop at main")

        ev = await runner.call("inspect_code", {"action": "evaluate", "session_id": sid, "expression": "&main"})
        require(ev.get("address", "").startswith("0x"), "main has no address")
        regs = await runner.call("registers", {"action": "read", "session_id": sid, "names": ["rax", "rsp", "rip"]})
        require("rsp" in regs["regs"], "rsp missing")
        await runner.call("registers", {"action": "write", "session_id": sid, "name": "rax", "value": "$rax"})
        bt = await runner.call("inspect_code", {"action": "backtrace", "session_id": sid, "max_frames": 8})
        require(bt["frames"], "backtrace empty")
        dis = await runner.call("inspect_code", {"action": "disassemble", "session_id": sid, "start": "$pc", "count": 8})
        require(dis["instructions"], "disasm empty")

        th = await runner.call("thread_frame", {"action": "list_threads", "session_id": sid})
        require(th["threads"], "threads empty")
        await runner.call("thread_frame", {"action": "select_thread", "session_id": sid, "number": th["threads"][0]["num"]})
        await runner.call("thread_frame", {"action": "select_frame", "session_id": sid, "level": 0})

        mm = await runner.call("memory", {"action": "map", "session_id": sid})
        require(mm.get("segments"), "memory map empty")
        mem = await runner.call("memory", {"action": "read", "session_id": sid, "address": "$rsp", "length": 8})
        require(mem.get("hex"), "stack unreadable")
        await runner.call("memory", {"action": "write", "session_id": sid, "address": "$rsp", "hex": mem["hex"]})
        chunk = await runner.call("heap", {"action": "chunk", "session_id": sid, "address": "$rsp", "data_length": 0})
        require(chunk.get("chunk"), "heap chunk missing")

        await runner.call("control_execution", {"action": "continue", "wait": True, "session_id": sid, "timeout_ms": 10000})
        report = await runner.call("crash_report", {"session_id": sid})
        require(report.get("signal") == "SIGSEGV", "crash_report missed SIGSEGV")

        await runner.call("session_info", {"action": "events", "session_id": sid, "last": 10})
        await runner.call("session_info", {"action": "output", "session_id": sid, "tail_lines": 20})
        await runner.call("session_info", {"action": "export", "session_id": sid})
        await runner.call("campaign", {"action": "get", "session_id": sid})
        await runner.call("breakpoint", {"action": "delete", "session_id": sid, "number": bp["number"]})

        script = await runner.call(
            "launch_gdb",
            {
                "script": str(CHILD_GDB_SCRIPT),
                "python": "python3",
                "env": {"GDB_MCP_PLUGIN": plugin},
                "distro": distro,
                "attach_timeout_ms": 15000,
            },
        )
        owned.extend([script["script_session_id"], script["gdb_session_id"]])
        require(script["gdb_session_id"], "script did not attach child gdb")
        await runner.call("kill_session", {"session_id": script["gdb_session_id"], "force": True})
        await wait_for_state(runner, script["gdb_session_id"], {"disconnected"}, timeout=10.0)
        await runner.call("kill_session", {"session_id": sid, "force": True})
        owned.remove(sid)

        missing = WALKTHROUGH_TOOLS - runner.covered
        require(not missing, "tools not exercised: %s" % sorted(missing))
        print(
            "ALL %d WALKTHROUGH TOOLS PASSED (%d registered)"
            % (len(WALKTHROUGH_TOOLS), len(REGISTERED_TOOLS)),
            flush=True,
        )
    finally:
        for s in reversed(owned):
            if s:
                with suppress(Exception):
                    await runner.call("kill_session", {"session_id": s, "force": True})


async def async_main(args: argparse.Namespace) -> int:
    program = "/tmp/gdb-mcp-tools-e2e-%d" % os.getpid()
    await run_wsl(args.distro, "gcc", "-g", "-O0", "-o", program, win_to_wsl(str(CRASHER_SOURCE)))
    try:
        with tempfile.TemporaryDirectory(prefix="gdb-mcp-tools-e2e-") as log_dir:
            env = dict(os.environ)
            env.update(
                {
                    "GDB_MCP_PORT": str(args.port),
                    "GDB_MCP_LOG_DIR": log_dir,
                    "GDB_MCP_HOST_BIND": "0.0.0.0",
                    "GDB_MCP_TOKEN": "e2e-tools-secret",
                    "GDB_MCP_WSL_DISTRO": args.distro,
                    "PYTHONUTF8": "1",
                }
            )
            params = StdioServerParameters(
                command=sys.executable,
                args=["-m", "gdb_mcp", "--tool-profile", "pwn"],
                env=env,
                cwd=str(ROOT),
            )
            async with stdio_client(params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    await exercise_all(session, args.distro, program, win_to_wsl(str(PLUGIN)))
    finally:
        with suppress(Exception):
            await run_wsl(args.distro, "rm", "-f", program)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--distro", default="kali-linux")
    parser.add_argument("--port", type=int, default=39590)
    args = parser.parse_args()
    try:
        return asyncio.run(async_main(args))
    except Exception as exc:
        print("MCP TOOLS E2E FAILED: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
