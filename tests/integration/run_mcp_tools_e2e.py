#!/usr/bin/env python3
"""Exercise every registered MCP tool against a real GDB inside WSL2.

Run from Windows at the repository root:

    python tests/integration/run_mcp_tools_e2e.py --distro kali-linux
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import suppress
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from gdb_mcp.wsl import win_to_wsl

ROOT = Path(__file__).resolve().parents[2]
CRASHER_SOURCE = ROOT / "examples" / "crasher.c"
CHILD_GDB_SCRIPT = ROOT / "tests" / "integration" / "launch_child_gdb.py"
PLUGIN = ROOT / "src" / "gdb_mcp" / "plugin" / "gdb_mcp_plugin.py"

#: Everything the server must register under the default (full) profile.
#: Experimental tools are gated behind --experimental and stay out.
REGISTERED_TOOLS = frozenset(
    {
        "analyze_binary",
        "annotate_code",
        "batch_commands",
        "campaign",
        "checkpoint",
        "continue_execution",
        "crash_report",
        "decompile_function",
        "diff_sessions",
        "disassemble",
        "evaluate",
        "execute_command",
        "export_session_script",
        "get_analysis_status",
        "get_backtrace",
        "get_binary_overview",
        "get_call_graph",
        "get_events",
        "get_memory_map",
        "get_process_output",
        "get_static_disassembly",
        "get_stop_reason",
        "get_xrefs",
        "heap_bins",
        "interrupt",
        "kill_session",
        "launch_gdb",
        "launch_script",
        "list_analyses",
        "list_breakpoints",
        "list_functions",
        "list_sections",
        "list_sessions",
        "list_strings",
        "list_symbols",
        "list_threads",
        "load_target",
        "manage_breakpoint",
        "quit_gdb",
        "read_memory",
        "read_registers",
        "read_result",
        "remove_code_annotation",
        "run_policy",
        "search_decompiled_code",
        "select_frame",
        "session_status",
        "set_breakpoint",
        "triage_crash",
        "wait_for_stop",
        "write_memory",
        "write_register",
    }
)

#: Tools the walkthrough below must actually exercise (cheap, deterministic
#: subset — static_* needs Ghidra, heap_bins needs pwndbg, triage/policy
#: flows are covered by the bench selfcheck instead).
WALKTHROUGH_TOOLS = frozenset(
    {
        "list_sessions",
        "session_status",
        "quit_gdb",
        "get_process_output",
        "launch_gdb",
        "launch_script",
        "kill_session",
        "execute_command",
        "batch_commands",
        "get_events",
        "export_session_script",
        "campaign",
        "continue_execution",
        "interrupt",
        "wait_for_stop",
        "get_stop_reason",
        "read_memory",
        "write_memory",
        "read_registers",
        "write_register",
        "get_backtrace",
        "disassemble",
        "evaluate",
        "list_threads",
        "select_frame",
        "get_memory_map",
        "load_target",
        "set_breakpoint",
        "list_breakpoints",
        "manage_breakpoint",
        "crash_report",
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
            details = "\n".join(
                getattr(item, "text", str(item)) for item in result.content
            )
            raise E2EFailure("%s failed: %s" % (name, details))
        payload = result.structuredContent
        if payload is None:
            text = next(
                (
                    item.text
                    for item in result.content
                    if getattr(item, "type", None) == "text"
                ),
                None,
            )
            try:
                payload = json.loads(text) if text is not None else None
            except json.JSONDecodeError:
                payload = None
        if not isinstance(payload, dict):
            raise E2EFailure("%s returned no JSON object" % name)
        self.covered.add(name)
        print("[PASS] %-20s" % name, flush=True)
        return payload


def require(condition: Any, message: str) -> None:
    if not condition:
        raise E2EFailure(message)


async def run_wsl(distro: str, *args: str) -> None:
    process = await asyncio.create_subprocess_exec(
        "wsl.exe",
        "-d",
        distro,
        "--",
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if process.returncode:
        raise E2EFailure(
            "WSL command failed (%d): %s"
            % (process.returncode, stderr.decode(errors="replace"))
        )
    if stdout:
        print(stdout.decode(errors="replace").rstrip(), flush=True)


async def wait_for_state(
    runner: ToolRunner,
    session_id: str,
    states: set[str],
    timeout: float = 10.0,
) -> dict:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        status = await runner.call("session_status", {"session_id": session_id})
        if status["state"] in states:
            return status
        await asyncio.sleep(0.1)
    raise E2EFailure(
        "session %s did not reach one of %s" % (session_id, sorted(states))
    )


async def exercise_all(
    session: ClientSession,
    distro: str,
    program: str,
    plugin: str,
) -> None:
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
        "registered tool set differs: missing=%s extra=%s"
        % (sorted(REGISTERED_TOOLS - registered), sorted(registered - REGISTERED_TOOLS)),
    )

    owned_sessions: list[str] = []
    main_session = None
    script_session = None
    child_gdb_session = None
    try:
        sessions = await runner.call("list_sessions")
        require(sessions["sessions"] == [], "expected no sessions at test start")

        launched = await runner.call(
            "launch_gdb",
            {
                "gdb_args": ["-nx"],
                "distro": distro,
                "attach_timeout_ms": 15000,
            },
        )
        main_session = launched["session_id"]
        owned_sessions.append(main_session)
        require(launched["state"] != "reserved", "launch_gdb did not connect")

        status = await runner.call("session_status", {"session_id": main_session})
        require(status["gdb_version"], "session has no GDB version")
        await runner.call(
            "get_process_output", {"session_id": main_session, "tail_lines": 20}
        )
        await runner.call(
            "load_target", {"session_id": main_session, "path": program}
        )

        breakpoint = await runner.call(
            "set_breakpoint",
            {"session_id": main_session, "location": "main"},
        )
        bp_number = breakpoint["number"]
        breakpoints = await runner.call(
            "list_breakpoints", {"session_id": main_session}
        )
        require(
            any(bp["number"] == bp_number for bp in breakpoints["breakpoints"]),
            "new breakpoint is not listed",
        )
        await runner.call(
            "manage_breakpoint",
            {"session_id": main_session, "number": bp_number, "action": "disable"},
        )
        await runner.call(
            "manage_breakpoint",
            {"session_id": main_session, "number": bp_number, "action": "enable"},
        )

        await runner.call(
            "execute_command", {"session_id": main_session, "command": "run"}
        )
        stopped = await runner.call(
            "wait_for_stop", {"session_id": main_session, "timeout_ms": 10000}
        )
        require(stopped["stopped"], "inferior did not stop at main")
        reason = await runner.call("get_stop_reason", {"session_id": main_session})
        require(reason["stop_info"], "stop reason at main is missing")

        evaluated = await runner.call(
            "evaluate", {"session_id": main_session, "expression": "&main"}
        )
        require(evaluated.get("address", "").startswith("0x"), "main has no address")
        registers = await runner.call(
            "read_registers",
            {"session_id": main_session, "names": ["rax", "rsp", "rip"]},
        )
        require("rsp" in registers["regs"], "rsp was not returned")
        await runner.call(
            "write_register",
            {"session_id": main_session, "name": "rax", "value": "$rax"},
        )
        backtrace = await runner.call(
            "get_backtrace", {"session_id": main_session, "max_frames": 8}
        )
        require(backtrace["frames"], "backtrace is empty")
        disassembly = await runner.call(
            "disassemble",
            {"session_id": main_session, "start": "$pc", "count": 8},
        )
        require(disassembly["instructions"], "disassembly is empty")
        threads = await runner.call("list_threads", {"session_id": main_session})
        require(threads["threads"], "thread list is empty")
        selected = await runner.call(
            "select_frame", {"session_id": main_session, "level": 0}
        )
        require(selected["frame"]["level"] == 0, "frame zero was not selected")
        memory_map = await runner.call(
            "get_memory_map", {"session_id": main_session}
        )
        require(
            memory_map.get("segments"), "memory map returned no segments"
        )
        memory = await runner.call(
            "read_memory",
            {"session_id": main_session, "address": "$rsp", "length": 8},
        )
        require(memory.get("hex"), "stack memory is unreadable")
        await runner.call(
            "write_memory",
            {
                "session_id": main_session,
                "address": "$rsp",
                "hex": memory["hex"],
            },
        )

        await runner.call("continue_execution", {"session_id": main_session})
        crashed = await runner.call(
            "wait_for_stop", {"session_id": main_session, "timeout_ms": 10000}
        )
        require(crashed["stopped"], "inferior did not stop after continue")
        crash_reason = await runner.call(
            "get_stop_reason", {"session_id": main_session}
        )
        require(
            (crash_reason.get("stop_info") or {}).get("signal") == "SIGSEGV",
            "expected SIGSEGV, got %r" % crash_reason.get("stop_info"),
        )
        report = await runner.call("crash_report", {"session_id": main_session})
        require(report.get("signal") == "SIGSEGV", "crash report missed SIGSEGV")

        batch = await runner.call(
            "batch_commands",
            {
                "session_id": main_session,
                "commands": ["echo batch-a\\n", "echo batch-b\\n"],
            },
        )
        require(
            len(batch.get("results", [])) == 2
            and all(r.get("ok") for r in batch["results"]),
            "batch_commands did not run both commands",
        )
        events = await runner.call(
            "get_events", {"session_id": main_session, "last": 10}
        )
        require(events.get("events") is not None, "get_events returned no list")
        campaign_state = await runner.call(
            "campaign", {"session_id": main_session, "action": "get"}
        )
        require("campaign" in campaign_state, "campaign get returned no state")
        exported = await runner.call(
            "export_session_script", {"session_id": main_session}
        )
        require(
            exported.get("script", "").strip(), "export_session_script was empty"
        )
        await runner.call(
            "manage_breakpoint",
            {"session_id": main_session, "number": bp_number, "action": "delete"},
        )

        await runner.call(
            "execute_command",
            {"session_id": main_session, "command": "set args loop"},
        )
        await runner.call(
            "execute_command", {"session_id": main_session, "command": "run"}
        )
        await asyncio.sleep(0.5)
        interrupted = await runner.call("interrupt", {"session_id": main_session})
        require(
            interrupted["state"] == "interrupt_requested",
            "interrupt was not requested",
        )
        interrupt_stop = await runner.call(
            "wait_for_stop", {"session_id": main_session, "timeout_ms": 10000}
        )
        require(
            (interrupt_stop.get("stop_info") or {}).get("signal") == "SIGINT",
            "expected SIGINT after interrupt",
        )
        script = await runner.call(
            "launch_script",
            {
                "script": str(CHILD_GDB_SCRIPT),
                "python": "python3",
                "env": {"GDB_MCP_PLUGIN": plugin},
                "distro": distro,
                "attach_timeout_ms": 15000,
            },
        )
        script_session = script["script_session_id"]
        child_gdb_session = script["gdb_session_id"]
        owned_sessions.extend([script_session, child_gdb_session])
        require(child_gdb_session, "launch_script did not attach its child GDB")
        await runner.call(
            "quit_gdb", {"session_id": child_gdb_session, "kill_gdb": True}
        )
        await wait_for_state(
            runner, child_gdb_session, {"disconnected"}, timeout=10.0
        )

        await runner.call(
            "kill_session", {"session_id": main_session, "force": True}
        )
        owned_sessions.remove(main_session)
        main_session = None

        missing = WALKTHROUGH_TOOLS - runner.covered
        require(not missing, "tools not exercised: %s" % sorted(missing))
        print(
            "ALL %d WALKTHROUGH TOOLS PASSED (%d registered)"
            % (len(WALKTHROUGH_TOOLS), len(REGISTERED_TOOLS)),
            flush=True,
        )
    finally:
        for session_id in reversed(owned_sessions):
            if not session_id:
                continue
            with suppress(Exception):
                await runner.call(
                    "kill_session", {"session_id": session_id, "force": True}
                )


async def async_main(args: argparse.Namespace) -> int:
    program = "/tmp/gdb-mcp-tools-e2e-%d" % os.getpid()
    source = win_to_wsl(str(CRASHER_SOURCE))
    plugin = win_to_wsl(str(PLUGIN))
    await run_wsl(args.distro, "gcc", "-g", "-O0", "-o", program, source)
    try:
        with tempfile.TemporaryDirectory(prefix="gdb-mcp-tools-e2e-") as log_dir:
            env = dict(os.environ)
            env.update(
                {
                    "GDB_MCP_HOST_BIND": "0.0.0.0",
                    "GDB_MCP_PORT": str(args.port),
                    "GDB_MCP_TOKEN": "mcp-tools-e2e-token",
                    "GDB_MCP_WSL_DISTRO": args.distro,
                    "GDB_MCP_LOG_DIR": log_dir,
                    "PYTHONUTF8": "1",
                }
            )
            server = StdioServerParameters(
                command=sys.executable,
                args=["-m", "gdb_mcp"],
                env=env,
                cwd=str(ROOT),
            )
            async with stdio_client(server) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    failure = None
                    try:
                        await exercise_all(session, args.distro, program, plugin)
                    except Exception as exc:
                        failure = exc
            if failure is not None:
                raise failure
        return 0
    finally:
        await run_wsl(args.distro, "rm", "-f", "--", program)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--distro", default="kali-linux")
    parser.add_argument("--port", type=int, default=39406)
    args = parser.parse_args()
    try:
        return asyncio.run(async_main(args))
    except (E2EFailure, OSError) as exc:
        print("MCP TOOLS E2E FAILED: %s" % exc, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
