"""Installed-wheel MCP stdio smoke; run on Linux with a clean venv's python -I.

No source-tree imports or plugin-path overrides: this intentionally tests the
package shipped to users. The CI job builds/installs the wheel before running it.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import sysconfig
import tempfile
import traceback
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

CORE_TOOLS = {
    "session_info", "launch_gdb", "kill_session", "execute_command",
    "control_execution", "memory", "registers", "inspect_code", "breakpoint",
    "crash_report",
}
EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "hello.c"


def require(condition: object, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def process(pid: int) -> tuple[int, int] | None:
    """(parent PID, start ticks), including zombies so they fail leak checks."""
    try:
        # comm may contain spaces/parentheses; field 22 is starttime.
        fields = Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()
        return int(fields[1]), int(fields[19])
    except (FileNotFoundError, ProcessLookupError):
        return None


class OwnedProcesses:
    """Track only this smoke's descendants, with PID-reuse-safe identities."""

    def __init__(self) -> None:
        self.identities: dict[int, int] = {}

    def remember(self, pid: int) -> None:
        info = process(pid)
        require(info is not None, "process %d vanished before observation" % pid)
        self.identities[pid] = info[1]

    def capture_descendants(self, parent: int) -> None:
        pending = [parent]
        snapshot = {}
        for path in Path("/proc").iterdir():
            if path.name.isdecimal():
                info = process(int(path.name))
                if info is not None:
                    snapshot[int(path.name)] = info
        while pending:
            parent = pending.pop()
            for pid, (ppid, start) in snapshot.items():
                if ppid == parent:
                    self.identities[pid] = start
                    pending.append(pid)

    def alive(self, pids: list[int] | None = None) -> list[int]:
        return [
            pid for pid in (self.identities if pids is None else pids)
            if (info := process(pid)) is not None
            and info[1] == self.identities[pid]
        ]

    async def wait_gone(self, pids: list[int], timeout: float = 5.0) -> None:
        deadline = asyncio.get_running_loop().time() + timeout
        while self.alive(pids) and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.05)
        require(not self.alive(pids), "processes leaked (including zombies): %s" % self.alive(pids))

    async def emergency_cleanup(self) -> None:
        # Descendants first: let GDB/server reap their children before killing
        # parents. This is a failure fallback, never evidence of a passing smoke.
        for pid in reversed(list(self.identities)):
            if pid in self.alive():
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await asyncio.sleep(0.1)


def find_server(log_dir: Path) -> int | None:
    for path in Path("/proc").iterdir():
        if not path.name.isdecimal():
            continue
        pid = int(path.name)
        info = process(pid)
        if info is None or info[0] != os.getpid():
            continue
        try:
            argv = (path / "cmdline").read_bytes().split(b"\0")
        except (FileNotFoundError, ProcessLookupError):
            continue
        if (
            b"gdb-mcp" in b" ".join(argv) or b"gdb_mcp" in b" ".join(argv)
        ) and os.fsencode(log_dir) in argv:
            return pid
    return None

async def call(session: ClientSession, name: str, **arguments: object) -> dict:
    try:
        result = await asyncio.wait_for(session.call_tool(name, arguments), timeout=20)
    except asyncio.TimeoutError:
        raise RuntimeError("MCP tool timed out: %s" % name) from None
    require(not result.isError, "%s failed: %s" % (name, result.content))
    payload = result.structuredContent
    if payload is None:
        payload = json.loads(next(item.text for item in result.content if hasattr(item, "text")))
    print("[PASS] %s" % name, flush=True)
    return payload


async def exercise(session: ClientSession, program: Path, owned: OwnedProcesses, server: int) -> None:
    names = set()
    cursor = None
    while True:
        page = await asyncio.wait_for(session.list_tools(cursor=cursor), timeout=10)
        names.update(tool.name for tool in page.tools)
        cursor = page.nextCursor
        if not cursor:
            break
    require(names == CORE_TOOLS, "core tool mismatch: %s" % sorted(names ^ CORE_TOOLS))
    print("[PASS] exact 10-tool core contract", flush=True)
    sid = None
    try:
        launched = await call(
            session, "launch_gdb", program=str(program), gdb_args=["-nx"],
            attach_timeout_ms=10000,
        )
        sid = launched["session_id"]
        require(launched["state"] != "reserved", "plugin failed to handshake: %s" % launched)
        status = await call(session, "session_info", action="status", session_id=sid)
        gdb_pid = status["gdb_pid"]
        require(isinstance(gdb_pid, int), "missing GDB PID: %s" % status)
        owned.capture_descendants(server)
        require(gdb_pid in owned.identities, "GDB is not this server's descendant")
        bp = await call(session, "breakpoint", action="set", location="break_here", session_id=sid)
        await call(session, "execute_command", command="run", session_id=sid)
        stopped = await call(
            session, "control_execution", action="wait", timeout_ms=10000, session_id=sid,
        )
        require(stopped["stopped"], "inferior failed to stop: %s" % stopped)
        require(
            bp["number"] in (stopped.get("stop_info") or {}).get("breakpoints", []),
            "did not stop at the requested breakpoint: %s" % stopped,
        )
        bt = await call(session, "inspect_code", action="backtrace", session_id=sid)
        functions = {frame.get("function") for frame in bt["frames"]}
        require({"break_here", "main"} <= functions, "unexpected backtrace: %s" % bt)
        owned.capture_descendants(server)
        inferior_pids = []
        for pid in owned.alive():
            try:
                if Path("/proc/%d/exe" % pid).resolve(strict=True) == program:
                    inferior_pids.append(pid)
            except (FileNotFoundError, ProcessLookupError):
                pass
        require(inferior_pids, "no live inferior observed; cannot verify cleanup")
        gdb_tree = [pid for pid in owned.identities if pid != server]
        await call(session, "kill_session", force=True, session_id=sid)
        sid = None
        await owned.wait_gone(gdb_tree)
        print("[PASS] GDB and observed inferior exited without leaks", flush=True)
    finally:
        owned.capture_descendants(server)
        if sid is not None:
            try:
                await call(session, "kill_session", force=True, session_id=sid)
            except Exception as exc:
                print("cleanup request failed: %s" % exc, file=sys.stderr)


async def run_smoke(work: Path, owned: OwnedProcesses) -> None:
    program = work / "hello"
    source = work / "hello.c"
    require(EXAMPLE.is_file(), "missing example source: %s" % EXAMPLE)
    shutil.copyfile(EXAMPLE, source)
    subprocess.run(["gcc", "-g", "-O0", "-o", str(program), str(source)], check=True, timeout=15)
    # Reserve an unused loopback port briefly. A collision after release fails
    # explicitly during initialize/handshake instead of hanging indefinitely.
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = {
        key: value for key, value in os.environ.items()
        if not key.startswith("GDB_MCP_") and key not in {"PYTHONPATH", "PYTHONHOME"}
    }
    log_dir = work / "logs"
    # Exercise the console script the wheel installs, not just the module.
    entry = Path(sys.executable).with_name("gdb-mcp")
    require(entry.is_file(), "wheel did not install the gdb-mcp console script")
    doctor = subprocess.run(
        [
            str(entry), "--selfcheck", "--launcher", "native",
            "--host-bind", "127.0.0.1", "--port", str(port),
            "--log-dir", str(log_dir),
        ],
        env=env, cwd=str(work), capture_output=True, text=True, timeout=30,
    )
    require(
        doctor.returncode == 0,
        "installed-wheel selfcheck failed:\n%s%s" % (doctor.stdout, doctor.stderr),
    )
    print("[PASS] gdb-mcp --selfcheck (installed console script)", flush=True)
    params = StdioServerParameters(
        command=str(entry),
        args=[
            "--launcher", "native", "--tool-profile", "core",
            "--host-bind", "127.0.0.1", "--port", str(port), "--log-dir", str(log_dir),
        ],
        env=env, cwd=str(work),
    )
    server = None
    try:
        with (work / "server.log").open("w", encoding="utf-8") as errlog:
            async with stdio_client(params, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    # Remember the process before initialize so failures still
                    # get scoped cleanup, without scanning/killing other GDBs.
                    server = find_server(log_dir)
                    require(server is not None, "could not identify own MCP server")
                    owned.remember(server)
                    await asyncio.wait_for(session.initialize(), timeout=15)
                    await exercise(session, program, owned, server)
        await owned.wait_gone(list(owned.identities))
        print("NATIVE INSTALLED-WHEEL MCP SMOKE PASSED", flush=True)
    finally:
        if server is None:
            server = find_server(log_dir)
            if server is not None:
                owned.remember(server)
        if server is not None:
            owned.capture_descendants(server)


def main() -> int:
    require(sys.platform == "linux", "this smoke requires Linux /proc and GDB")
    require(sys.flags.isolated and sys.prefix != sys.base_prefix, "run with a clean venv's python -I")
    import gdb_mcp

    package = Path(gdb_mcp.__file__).resolve().parent
    require(package.is_relative_to(Path(sysconfig.get_path("purelib"))), "gdb_mcp is not installed in this venv")
    require((package / "plugin" / "gdb_mcp_plugin.py").is_file(), "wheel is missing the GDB plugin")
    print("Installed package: %s" % package, flush=True)
    owned = OwnedProcesses()
    with tempfile.TemporaryDirectory(prefix="gdb-mcp-wheel-") as directory:
        work = Path(directory)
        try:
            asyncio.run(asyncio.wait_for(run_smoke(work, owned), timeout=90))
            return 0
        except Exception as exc:
            print("NATIVE INSTALL SMOKE FAILED: %s" % exc, file=sys.stderr)
            traceback.print_exc()
            for log in work.rglob("*.log"):
                print("--- %s ---\n%s" % (log.name, log.read_text(errors="replace")[-8000:]), file=sys.stderr)
            return 1
        finally:
            asyncio.run(owned.emergency_cleanup())


if __name__ == "__main__":
    raise SystemExit(main())
