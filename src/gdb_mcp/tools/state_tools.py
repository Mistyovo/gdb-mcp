"""Inferior state inspection and mutation tools (memory, registers, code,
threads/frames, mappings, target loading)."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.output import hex_to_bytes, parse_proc_mappings

from ._common import check_stopped, config_from, resolve_gdb
from .registry import tool

_MAX_FRAMES = 4096
_MAX_DISASM = 4096


@tool(core=True, capability="target")
async def memory(
    action: str = "read",
    address: str | int | None = None,
    length: int = 64,
    hex: str | None = None,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Inspect or patch inferior memory. Actions:
    - read: read `length` bytes at `address` (int, hex, or gdb expr).
    - write: write raw `hex` bytes at `address`.
    - map: structured memory mappings (live `info proc mappings` with
      core-file section fallback)."""
    cfg = config_from(ctx)
    session = resolve_gdb(ctx, session_id)
    check_stopped(session)
    if action == "map":
        result = await session.request("mem_map", {}, timeout=cfg.request_timeout)
        segments = parse_proc_mappings(result.get("output", ""))
        return {
            "segments": segments,
            "count": len(segments),
            "total_lines": result.get("total_lines"),
            "truncated": bool(result.get("truncated", False)),
        }
    if address is None:
        raise GdbMcpError("BAD_PARAMS", "address is required for %s" % action)
    if action == "read":
        if isinstance(length, bool) or not isinstance(length, int) or not (1 <= length <= cfg.max_mem_read):
            raise ValueError("length must be between 1 and %d" % cfg.max_mem_read)
        return await session.request(
            "read_mem", {"addr": address, "length": length}, timeout=cfg.request_timeout
        )
    if action == "write":
        if cfg.readonly:
            raise GdbMcpError("READONLY", "memory write is disabled in --readonly mode")
        try:
            data = hex_to_bytes(hex or "")
        except ValueError as exc:
            raise GdbMcpError("BAD_PARAMS", str(exc)) from None
        if not data or len(data) > cfg.max_mem_read:
            raise GdbMcpError(
                "BAD_PARAMS",
                "write length must be between 1 and %d bytes" % cfg.max_mem_read,
            )
        return await session.request(
            "write_mem", {"addr": address, "hex": hex}, timeout=cfg.request_timeout
        )
    raise GdbMcpError("BAD_PARAMS", "action must be read, write, or map")


@tool(core=True, capability="target")
async def registers(
    action: str = "read",
    names: list[str] | None = None,
    name: str | None = None,
    value: str | None = None,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Read or write inferior registers.
    - read: all GP registers (or `names` subset).
    - write: set register `name` to gdb expression `value`."""
    cfg = config_from(ctx)
    session = resolve_gdb(ctx, session_id)
    check_stopped(session)
    if action == "read":
        params = {"names": names} if names else {}
        return await session.request("regs", params, timeout=cfg.request_timeout)
    if action == "write":
        if cfg.readonly:
            raise GdbMcpError("READONLY", "register write is disabled in --readonly mode")
        if not name or value is None:
            raise GdbMcpError("BAD_PARAMS", "write requires name and value")
        return await session.request(
            "set_reg", {"name": name, "value": value}, timeout=cfg.request_timeout
        )
    raise GdbMcpError("BAD_PARAMS", "action must be read or write")


@tool(core=True)
async def inspect_code(
    action: str = "disassemble",
    start: str | int | None = None,
    count: int = 16,
    max_frames: int = 64,
    expression: str | None = None,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Inspect code, stack, or expressions against the stopped inferior.
    - disassemble: `count` instructions at `start` (default: current PC).
    - backtrace: stack frames up to `max_frames`.
    - evaluate: PIE-aware gdb expression (`expression`)."""
    cfg = config_from(ctx)
    session = resolve_gdb(ctx, session_id)
    check_stopped(session)
    if action == "disassemble":
        if isinstance(count, bool) or not isinstance(count, int) or not (1 <= count <= _MAX_DISASM):
            raise GdbMcpError("BAD_PARAMS", "count must be between 1 and %d" % _MAX_DISASM)
        params: dict = {"count": count}
        if start is not None:
            params["start"] = start
        return await session.request("disasm", params, timeout=cfg.request_timeout)
    if action == "backtrace":
        if isinstance(max_frames, bool) or not isinstance(max_frames, int) or not (1 <= max_frames <= _MAX_FRAMES):
            raise GdbMcpError("BAD_PARAMS", "max_frames must be between 1 and %d" % _MAX_FRAMES)
        return await session.request(
            "backtrace", {"max_frames": max_frames}, timeout=cfg.request_timeout
        )
    if action == "evaluate":
        if cfg.readonly:
            raise GdbMcpError("READONLY", "evaluate is disabled in --readonly mode")
        if not expression:
            raise GdbMcpError("BAD_PARAMS", "expression is required")
        return await session.request(
            "evaluate", {"expression": expression}, timeout=cfg.request_timeout
        )
    raise GdbMcpError("BAD_PARAMS", "action must be disassemble, backtrace, or evaluate")


@tool(capability="debug")
async def thread_frame(
    action: str = "list_threads",
    number: int | None = None,
    level: int | None = None,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Inspect or switch threads and stack frames.
    - list_threads: list inferior threads and the selected one.
    - select_thread: switch to thread `number`.
    - select_frame: switch to stack frame `level` (0 = innermost)."""
    cfg = config_from(ctx)
    session = resolve_gdb(ctx, session_id)
    check_stopped(session)
    if action == "list_threads":
        return await session.request("threads", {}, timeout=cfg.request_timeout)
    if action == "select_thread":
        if isinstance(number, bool) or not isinstance(number, int) or number < 1:
            raise GdbMcpError("BAD_PARAMS", "number must be a positive int")
        return await session.request(
            "thread_select", {"number": number}, timeout=cfg.request_timeout
        )
    if action == "select_frame":
        if isinstance(level, bool) or not isinstance(level, int) or level < 0:
            raise GdbMcpError("BAD_PARAMS", "level must be a non-negative int")
        return await session.request(
            "frame_select", {"level": level}, timeout=cfg.request_timeout
        )
    raise GdbMcpError(
        "BAD_PARAMS", "action must be list_threads, select_thread, or select_frame"
    )


@tool(capability="debug")
async def load_target(
    path: str,
    core: bool = False,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Load an executable (`file <path>`) or core dump (`core=True`,
    `core-file <path>`) into the gdb session."""
    session = resolve_gdb(ctx, session_id)
    verb = "core" if core else "file"
    return await session.request(
        verb, {"path": path}, timeout=config_from(ctx).request_timeout
    )
