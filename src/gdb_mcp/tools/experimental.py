"""Experimental tools — gated behind the ``--experimental`` launch flag.

There is deliberately no environment variable for this gate: a stray
variable in a shell profile or MCP config would silently turn these
tools on for every server start. Anything here is subject to change or
removal without a deprecation cycle. Current contents: the inferior
stdio channel (send_to_inferior / read_inferior_output) that pairs with
the plugin's io_* verbs, libc identification via a libc.rip-compatible
API, structured ROP gadget search via the ROPgadget CLI, and the QEMU
kernel-VM helpers.
"""

from __future__ import annotations

import asyncio
import re
import subprocess
import time
from pathlib import Path

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.output import hex_to_bytes

from ._common import config_from, launcher_from, resolve_gdb
from .registry import tool


def _api_find(endpoint_url: str, payload: dict) -> list:
    """POST to a libc.rip-compatible ``/api/find`` endpoint. Indirection
    for tests."""
    import httpx

    response = httpx.post(endpoint_url, json=payload, timeout=30.0)
    response.raise_for_status()
    data = response.json()
    return data if isinstance(data, list) else []


def _run_ropgadget(binary: str, only: str) -> tuple[int, str]:
    """Run the ROPgadget CLI. Indirection for tests."""
    proc = subprocess.run(
        ["ROPgadget", "--binary", binary, "--only", only],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return proc.returncode, proc.stdout


#: QEMU handles for kernel sessions: session_id -> QemuProcess
_QEMU_BY_SESSION: dict = {}


async def _stop_qemu_of(session_id: str) -> None:
    qemu = _QEMU_BY_SESSION.pop(session_id, None)
    if qemu is None:
        return
    try:
        await qemu.stop()
    except Exception:
        pass


def drop_session_qemu(session_id: str) -> None:
    """Registry on_session_removed hook: a kernel session going away
    (kill_session, GC, shutdown cleanup) must take its QEMU VM with it —
    the handle map alone would leak a running VM."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:  # no loop: drop the handle, nothing to await
        _QEMU_BY_SESSION.pop(session_id, None)
        return
    loop.create_task(_stop_qemu_of(session_id))


async def _qemu_stub_up(port: int, distro: str | None, timeout_s: float) -> bool:
    from gdb_mcp.kernel.qemu_runner import stub_check_argv

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        proc = await asyncio.create_subprocess_exec(
            *stub_check_argv(port, distro),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.communicate()
        if proc.returncode == 0:
            return True
        await asyncio.sleep(0.5)
    return False


@tool(experimental=True)
async def send_to_inferior(
    hex: str,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """EXPERIMENTAL. Write raw bytes (hex string) to the inferior's
    stdin. Requires io_setup on the session (the inferior's stdio is
    redirected to a pty on its next run/start); works while the
    inferior is running, which is the point."""
    session = resolve_gdb(ctx, session_id)
    try:
        hex_to_bytes(hex)
    except ValueError as exc:
        raise GdbMcpError("BAD_PARAMS", str(exc)) from None
    return await session.request(
        "io_send", {"hex": hex}, timeout=config_from(ctx).request_timeout
    )


@tool(experimental=True)
async def read_inferior_output(
    since_seq: int = 0,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """EXPERIMENTAL. Read the inferior's accumulated stdout/stderr
    chunks recorded since seq (0 = everything still buffered). Each
    chunk carries hex and lossily-decoded text."""
    if isinstance(since_seq, bool) or not isinstance(since_seq, int) or since_seq < 0:
        raise ValueError("since_seq must be a non-negative int")
    session = resolve_gdb(ctx, session_id)
    return await session.request(
        "io_read",
        {"since_seq": since_seq},
        timeout=config_from(ctx).request_timeout,
    )


@tool(experimental=True)
async def io_setup(session_id: str | None = None, ctx: Context = None) -> dict:
    """EXPERIMENTAL. Redirect the inferior's stdio to a pty managed by
    the gdb-mcp plugin, enabling send_to_inferior/read_inferior_output.
    Takes effect on the inferior's next run/start; Unix only."""
    session = resolve_gdb(ctx, session_id)
    return await session.request(
        "io_setup", {}, timeout=config_from(ctx).request_timeout
    )


@tool(experimental=True)
async def io_teardown(
    session_id: str | None = None, ctx: Context = None
) -> dict:
    """EXPERIMENTAL. Close the inferior stdio channel and restore the
    previous inferior-tty behavior on the next run."""
    session = resolve_gdb(ctx, session_id)
    return await session.request(
        "io_teardown", {}, timeout=config_from(ctx).request_timeout
    )


@tool(experimental=True)
async def identify_libc(
    leaks: dict[str, str],
    use_api: bool = True,
    ctx: Context = None,
) -> dict:
    """EXPERIMENTAL. Identify a libc from leaked symbol addresses,
    e.g. {"puts": "0x7ffff7a6c720"} — only the low 12 bits of each
    leak are meaningful, everything above is randomized per run.
    Queries the configured libc.rip-compatible API
    (GDB_MCP_LIBC_RIP_API) and returns candidate libcs. Unnecessary
    for purely local debugging: there the target's own libc is
    visible in info proc mappings."""
    if not leaks:
        raise GdbMcpError("BAD_PARAMS", "leaks is required")
    normalized: dict[str, str] = {}
    for symbol, raw in leaks.items():
        text = str(raw).strip()
        try:
            address = int(text, 16)
        except ValueError:
            raise GdbMcpError(
                "BAD_PARAMS",
                "leak %r is not a hex address: %r" % (symbol, raw),
            ) from None
        normalized[str(symbol)[:64]] = "%#x" % (address & 0xFFF)
    if not use_api:
        return {
            "matches": [],
            "query": normalized,
            "note": "use_api=False; nothing queried",
        }
    endpoint = config_from(ctx).libc_rip_api
    try:
        matches = await asyncio.to_thread(
            _api_find,
            endpoint.rstrip("/") + "/api/find",
            {"symbols": normalized},
        )
    except Exception as exc:
        raise GdbMcpError(
            "PLUGIN_ERROR",
            "libc lookup failed (%s); check GDB_MCP_LIBC_RIP_API "
            "reachability" % exc,
        ) from exc
    return {"matches": matches[:16], "query": normalized}


@tool(experimental=True)
async def search_gadgets(
    binary: str,
    pattern: str = "pop rdi",
    only: str = "pop|ret",
    max_results: int = 64,
    ctx: Context = None,
) -> dict:
    """EXPERIMENTAL. Search ROP gadgets in a binary via the ROPgadget
    CLI (pip install ROPgadget), then filter gadget instruction text
    by a case-insensitive regex (pattern). Returns address +
    instruction text per gadget, at most max_results."""
    if not binary.strip():
        raise GdbMcpError("BAD_PARAMS", "binary is required")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise GdbMcpError("BAD_PARAMS", "bad pattern regex: %s" % exc) from None
    max_results = max(1, min(int(max_results), 256))
    try:
        returncode, stdout = await asyncio.to_thread(
            _run_ropgadget, binary, only
        )
    except FileNotFoundError as exc:
        raise GdbMcpError(
            "ROPGADGET_MISSING",
            "ROPgadget was not found; pip install ROPgadget",
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise GdbMcpError("TIMEOUT", "ROPgadget timed out") from exc
    gadgets = []
    truncated = False
    line_re = re.compile(r"^(0x[0-9a-fA-F]+)\s*:\s*(.+)$")
    for line in stdout.splitlines():
        m = line_re.match(line.strip())
        if m is None:
            continue
        instructions = m.group(2).strip()
        if not re.search(pattern, instructions, re.IGNORECASE):
            continue
        if len(gadgets) >= max_results:
            truncated = True
            break
        gadgets.append(
            {
                # normalize away leading zeros; LLMs copy addresses
                # verbatim and 0x0000000000401234 invites typos
                "address": "0x%x" % int(m.group(1), 16),
                "instructions": instructions,
            }
        )
    if returncode not in (0, 1):
        raise GdbMcpError(
            "PLUGIN_ERROR",
            "ROPgadget failed (code %s): %s"
            % (returncode, stdout[-400:] or "no output"),
        )
    return {
        "binary": binary,
        "pattern": pattern,
        "gadgets": gadgets,
        "total_matched": len(gadgets),
        "truncated": truncated,
    }


@tool(experimental=True)
async def kernel_launch(
    kernel: str,
    initrd: str | None = None,
    append: str | None = None,
    disk: str | None = None,
    symbol_file: str | None = None,
    gdbstub_port: int = 1234,
    memory_mb: int = 512,
    distro: str | None = None,
    attach_timeout_ms: int | None = None,
    ctx: Context = None,
) -> dict:
    """EXPERIMENTAL. Boot a Linux kernel VM under QEMU with a gdbstub and
    attach a plugin-loaded gdb to it (Theme F layer 1). The VM starts
    frozen (-S); `continue_execution` starts it. `symbol_file` is the
    uncompressed vmlinux (extract with gdb_mcp.kernel.vmlinux) — KASLR
    slides are NOT yet auto-corrected, so pass nokaslr in `append` or
    fix up symbols yourself. Snapshot via kernel_snapshot."""
    from gdb_mcp.kernel.qemu_runner import QemuProcess, QemuSpec
    from gdb_mcp.wsl import win_to_wsl

    cfg = config_from(ctx)
    use_distro = distro or cfg.wsl_distro

    def conv(raw: str | None) -> Path | None:
        return Path(win_to_wsl(raw)) if raw else None

    spec = QemuSpec(
        kernel=Path(win_to_wsl(kernel)),
        initrd=conv(initrd),
        append=append or "console=ttyS0 nokaslr",
        disk=conv(disk),
        gdbstub_port=gdbstub_port,
        memory_mb=memory_mb,
    )
    qemu = QemuProcess(spec, distro=use_distro)
    await qemu.start()
    stub_ok = await _qemu_stub_up(gdbstub_port, use_distro, timeout_s=30.0)
    if not stub_ok:
        await qemu.stop()
        raise GdbMcpError(
            "QEMU_STUB_TIMEOUT",
            "gdbstub :%d never came up in WSL (check the qemu log)"
            % gdbstub_port,
        )
    # -nx: no .gdbinit/pwndbg — pwndbg's vmmap auto-exploration wedges on
    # a frozen remote stub (no mappings at the reset vector)
    gdb_args = ["-nx", "-ex", "target remote :%d" % gdbstub_port]
    if symbol_file:
        gdb_args += ["-ex", "file %s" % win_to_wsl(symbol_file)]
    session = await launcher_from(ctx).launch_gdb(
        program=None,
        args=None,
        gdb_args=gdb_args,
        cwd=None,
        env=None,
        run=False,
        timeout_ms=(
            20000 if attach_timeout_ms is None else attach_timeout_ms
        ),
        distro=distro,
    )
    _QEMU_BY_SESSION[session.session_id] = qemu
    return {
        "session_id": session.session_id,
        "state": session.state,
        "gdbstub_port": gdbstub_port,
        "monitor_socket": spec.monitor_socket,
        "append": spec.append,
        "note": "VM frozen at -S; continue_execution to boot",
    }


@tool(experimental=True)
async def kernel_snapshot(
    action: str,
    tag: str = "bench",
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """EXPERIMENTAL. savevm/loadvm on the QEMU of a kernel session
    (requires a qcow2 disk: use kernel_launch(disk=...)). Snapshots are
    the kernel-pwn revert primitive: a panicked VM restores in seconds."""
    session = resolve_gdb(ctx, session_id)
    qemu = _QEMU_BY_SESSION.get(session.session_id)
    if qemu is None:
        raise GdbMcpError(
            "BAD_PARAMS", "no QEMU handle for session %r" % session.session_id
        )
    if action == "save":
        code, out = await qemu.snapshot_save(tag)
    elif action == "restore":
        code, out = await qemu.snapshot_restore(tag)
    elif action == "stop":
        await qemu.stop()
        _QEMU_BY_SESSION.pop(session.session_id, None)
        return {"stopped": True}
    else:
        raise GdbMcpError("BAD_PARAMS", "action must be save|restore|stop")
    return {"action": action, "tag": tag, "returncode": code, "output": out[:400]}
