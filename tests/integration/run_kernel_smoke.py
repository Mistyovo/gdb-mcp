#!/usr/bin/env python3
"""Kernel layer-1 PoC smoke (Theme F): QEMU gdbstub + plugin gdb + snapshots.

Boots the WSL distro's own kernel with `rdinit=/bin/sh` in a frozen VM,
attaches through the experimental kernel tools, and proves the closed loop:

    launch (frozen) -> continue (VM boots) -> interrupt -> snapshot save ->
    mutate (continue+interrupt again) -> snapshot restore -> register revert

Requires: WSL distro with qemu-system-x86_64 + socat and /boot kernel
packages (kali default). Run from the repo root on Windows:

    python tests/integration/run_kernel_smoke.py --distro kali-linux
"""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[2]


class SmokeFailure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise SmokeFailure(message)


async def call(session, name, arguments=None, timeout_s: float = 60.0) -> dict:
    print("[call] %s %s" % (name, str(arguments or "")[:90]), flush=True)
    result = await asyncio.wait_for(
        session.call_tool(name, arguments or {}), timeout_s
    )
    if result.isError:
        details = "\n".join(getattr(item, "text", str(item)) for item in result.content)
        raise SmokeFailure("%s failed: %s" % (name, details))
    payload = result.structuredContent
    if payload is None:
        # some FastMCP registrations come back text-only; parse the JSON text
        import json

        text = next(
            (item.text for item in result.content if getattr(item, "type", None) == "text"),
            None,
        )
        if text is not None:
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                payload = None
    if not isinstance(payload, dict):
        raise SmokeFailure("%s returned no JSON object" % name)
    return payload


async def wait_state(session, sid, want, timeout_s: float) -> str:
    import time

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = await call(session, "session_status", {"session_id": sid})
        if status["state"] in want:
            return status["state"]
        await asyncio.sleep(0.3)
    raise SmokeFailure("session did not reach %s" % sorted(want))


async def read_rip(session, sid) -> str:
    regs = await call(
        session, "read_registers", {"names": ["rip"], "session_id": sid}
    )
    return str(regs["regs"]["rip"])


def _parse_rip(text: str) -> str:
    # the saved point may sit in 16-bit real mode, where HMP reports EIP
    m = re.search(r"(?:R|E)IP=([0-9a-fA-F]+)", text)
    if not m:
        raise SmokeFailure("no RIP in monitor output: %r" % text[:200])
    return "0x" + m.group(1).lstrip("0").lower()


async def monitor_rip(session, sid) -> str:
    """Read the PC from the EMULATOR (HMP) — gdb caches registers and
    never refreshes after loadvm, so the stub view is stale there."""
    result = await call(
        session, "execute_command",
        {"command": "monitor info registers", "session_id": sid},
    )
    return _parse_rip(result.get("output", ""))


async def main(args) -> int:
    disk = args.disk
    if disk is None:
        # internal snapshots (savevm/loadvm) need a writable qcow2 — the
        # smoke keeps a scratch one in WSL /tmp
        proc = await asyncio.create_subprocess_exec(
            "wsl.exe", "-d", args.distro, "--", "qemu-img", "create", "-f",
            "qcow2", "/tmp/gdb-mcp-kernel-smoke.qcow2", "128M",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
        )
        _, err = await proc.communicate()
        if proc.returncode:
            raise SmokeFailure(
                "qemu-img failed (is qemu-system-x86 installed in WSL?): %s"
                % err.decode()[:200]
            )
        disk = "/tmp/gdb-mcp-kernel-smoke.qcow2"
        print("[ok] scratch qcow2 created")

    env = dict(__import__("os").environ)
    env.update(
        {
            "GDB_MCP_HOST_BIND": "0.0.0.0",
            "GDB_MCP_PORT": str(args.port),
            "GDB_MCP_TOKEN": "kernel-smoke-token",
            "GDB_MCP_WSL_DISTRO": args.distro,
            "PYTHONUTF8": "1",
        }
    )
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "gdb_mcp", "--experimental"],
        env=env,
        cwd=str(ROOT),
    )
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            launched = await call(
                session,
                "kernel_launch",
                {
                    "kernel": args.kernel,
                    "initrd": args.initrd,
                    "append": "console=ttyS0 rdinit=/bin/sh nokaslr",
                    "disk": disk,
                    "gdbstub_port": args.stub_port,
                    "distro": args.distro,
                    "attach_timeout_ms": 20000,
                },
            )
            sid = launched["session_id"]
            print("[ok] kernel session %s (state=%s)" % (sid, launched["state"]), flush=True)
            # kernel_launch may return while state=connecting (plugin hello
            # not in yet); wait for the session to go live before reads
            # CONNECTING == hello received, awaiting first prompt — queries
            # are safe in it (the plugin answers requests), and a frozen
            # remote stub never produces a prompt event, so don't wait for READY
            await wait_state(
                session, sid, {"connecting", "ready", "stopped", "connected"}, 60.0
            )
            print("[ok] session live", flush=True)
            rip_frozen = await read_rip(session, sid)
            print("[ok] frozen RIP", rip_frozen)

            await call(session, "execute_command",
                       {"command": "continue &", "session_id": sid})
            await wait_state(session, sid, {"running"}, 10.0)
            await call(session, "interrupt", {"session_id": sid})
            await wait_state(session, sid, {"stopped"}, 20.0)
            print("[ok] VM booted and interrupted")

            await call(session, "kernel_snapshot",
                       {"action": "save", "tag": "smoke", "session_id": sid})
            rip_saved = await monitor_rip(session, sid)
            print("[ok] snapshot saved; RIP", rip_saved)

            # advance the VM past the saved point, then revert
            await call(session, "execute_command",
                       {"command": "continue &", "session_id": sid})
            await call(session, "interrupt", {"session_id": sid})
            await wait_state(session, sid, {"stopped"}, 20.0)
            rip_after = await monitor_rip(session, sid)
            print("[ok] advanced RIP", rip_after)
            require(rip_after != rip_saved, "VM did not advance past the snapshot")

            await call(session, "kernel_snapshot",
                       {"action": "restore", "tag": "smoke", "session_id": sid})
            rip_restored = await monitor_rip(session, sid)
            print("[ok] restored RIP", rip_restored)
            require(
                rip_restored == rip_saved,
                "snapshot did not revert: %s != %s" % (rip_restored, rip_saved),
            )

            await call(session, "kernel_snapshot",
                       {"action": "stop", "session_id": sid})
            await call(session, "kill_session", {"session_id": sid, "force": True})
            print("KERNEL SMOKE PASSED")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--distro", default="kali-linux")
    parser.add_argument("--port", type=int, default=39410)
    parser.add_argument("--stub-port", type=int, default=1234)
    parser.add_argument("--kernel", default="/boot/vmlinuz-7.1.5+kali-amd64")
    parser.add_argument("--initrd", default="/boot/initrd.img-7.1.5+kali-amd64")
    parser.add_argument("--disk", default=None, help="qcow2 for snapshots")
    try:
        raise SystemExit(asyncio.run(main(parser.parse_args())))
    except (SmokeFailure, OSError) as exc:
        print("KERNEL SMOKE FAILED: %s" % exc, file=sys.stderr)
        raise SystemExit(1)
