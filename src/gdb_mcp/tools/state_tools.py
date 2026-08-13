"""Inferior-state inspection tools (memory, registers, code, threads)."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.output import hex_to_bytes

from ._common import check_stopped, config_from, resolve_gdb


def register(app, registry, config) -> None:
    @app.tool()
    async def read_memory(
        address: str | int,
        length: int = 64,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Read raw memory from the inferior. `address` may be an int, a
        hex string ('0x401000'), or a gdb expression ('main+0x10',
        '&puts@got'). Returns hex, printable-ascii, and unreadable ranges."""
        cfg = config_from(ctx)
        if not isinstance(length, int) or length < 1 or length > cfg.max_mem_read:
            raise ValueError("length must be between 1 and %d" % cfg.max_mem_read)
        session = resolve_gdb(ctx, session_id)
        check_stopped(session)
        return await session.request(
            "read_mem",
            {"addr": address, "length": length},
            timeout=cfg.request_timeout,
        )

    @app.tool()
    async def write_memory(
        address: str | int,
        hex: str,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Write raw bytes (given as a hex string, e.g. '9090c3' or
        '90 90 c3') to the inferior's memory."""
        try:
            hex_to_bytes(hex)  # validate early for a clean error
        except ValueError as exc:
            raise GdbMcpError("BAD_PARAMS", str(exc)) from None
        session = resolve_gdb(ctx, session_id)
        check_stopped(session)
        return await session.request(
            "write_mem",
            {"addr": address, "hex": hex},
            timeout=config_from(ctx).request_timeout,
        )

    @app.tool()
    async def read_registers(
        names: list[str] | None = None,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Read register values (all general-purpose registers by
        default, or the named subset)."""
        session = resolve_gdb(ctx, session_id)
        check_stopped(session)
        params = {"names": names} if names else {}
        return await session.request(
            "regs", params, timeout=config_from(ctx).request_timeout
        )

    @app.tool()
    async def write_register(
        name: str,
        value: str,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Write a register. `value` is a gdb expression
        (e.g. '0x401000', '$rax+8', 'main')."""
        session = resolve_gdb(ctx, session_id)
        check_stopped(session)
        return await session.request(
            "set_reg",
            {"name": name, "value": value},
            timeout=config_from(ctx).request_timeout,
        )

    @app.tool()
    async def get_backtrace(
        max_frames: int = 64,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Stack backtrace: pc, function name, source file/line per frame."""
        session = resolve_gdb(ctx, session_id)
        check_stopped(session)
        return await session.request(
            "backtrace",
            {"max_frames": max_frames},
            timeout=config_from(ctx).request_timeout,
        )

    @app.tool()
    async def disassemble(
        start: str | int | None = None,
        count: int = 16,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Disassemble `count` instructions at `start` (address, gdb
        expression, function name — or the current PC when omitted)."""
        session = resolve_gdb(ctx, session_id)
        check_stopped(session)
        params = {"count": count}
        if start is not None:
            params["start"] = start
        return await session.request(
            "disasm", params, timeout=config_from(ctx).request_timeout
        )

    @app.tool()
    async def evaluate(
        expression: str,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Evaluate a gdb expression against the live inferior (PIE-aware):
        'main', '&puts@got', '$rax+8', '*(char**)0x404000'."""
        session = resolve_gdb(ctx, session_id)
        check_stopped(session)
        return await session.request(
            "evaluate",
            {"expression": expression},
            timeout=config_from(ctx).request_timeout,
        )

    @app.tool()
    async def list_threads(
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """List inferior threads and which one is selected."""
        session = resolve_gdb(ctx, session_id)
        check_stopped(session)
        return await session.request(
            "threads", {}, timeout=config_from(ctx).request_timeout
        )

    @app.tool()
    async def select_frame(
        level: int,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Select a stack frame by level (0 = innermost) for subsequent
        register/memory/local inspection."""
        session = resolve_gdb(ctx, session_id)
        check_stopped(session)
        return await session.request(
            "frame_select",
            {"level": level},
            timeout=config_from(ctx).request_timeout,
        )

    @app.tool()
    async def get_memory_map(
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Memory mappings of the inferior (`info proc mappings` — works
        without pwndbg). For richer output use
        execute_command('vmmap')."""
        session = resolve_gdb(ctx, session_id)
        check_stopped(session)
        return await session.request(
            "mem_map", {}, timeout=config_from(ctx).request_timeout
        )

    @app.tool()
    async def load_target(
        path: str,
        core: bool = False,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Load a program (`file <path>`) or core dump (`core-file
        <path>`) into the gdb session. For gdb sessions started without
        an inferior."""
        session = resolve_gdb(ctx, session_id)
        verb = "core" if core else "file"
        return await session.request(
            verb, {"path": path}, timeout=config_from(ctx).request_timeout
        )
