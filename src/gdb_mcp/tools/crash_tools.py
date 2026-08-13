"""Crash-triage tool: one call to get the full picture of a stop."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.sessions import RUNNING

from ._common import check_stopped, config_from, parse_hex_addr, resolve_gdb


def register(app, registry, config) -> None:
    @app.tool()
    async def crash_report(
        max_frames: int = 16,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """One-call crash triage: signal, fault address, PC, registers,
        backtrace, disassembly around PC, memory at PC/SP/fault address
        and the head of the memory map. Use after wait_for_stop (or after
        a stop notification). Best-effort: unreadable pieces are reported
        in `warnings` instead of failing the whole call."""
        cfg = config_from(ctx)
        session = resolve_gdb(ctx, session_id)
        check_stopped(session)
        if session.state == RUNNING:
            raise GdbMcpError(
                "INFERIOR_RUNNING",
                "inferior is running; interrupt + wait_for_stop first",
            )
        timeout = min(cfg.request_timeout, 10.0)
        stop_info = session.stop_info or {}
        report = {
            "session_id": session.session_id,
            "state": session.state,
            "signal": stop_info.get("signal"),
            "fault_addr": stop_info.get("fault_addr"),
            "pc": stop_info.get("pc"),
            "thread": stop_info.get("thread"),
        }
        warnings = []

        async def try_verb(verb, params):
            try:
                return await session.request(
                    verb, params, timeout=timeout, locked=True
                )
            except GdbMcpError as exc:
                warnings.append("%s: %s" % (verb, exc))
                return None

        # Keep the whole report consistent: hold the session lock across
        # all sub-requests.
        async with session.lock:
            bt = await try_verb("backtrace", {"max_frames": max_frames})
            report["backtrace"] = (bt or {}).get("frames", [])
            if not report["pc"] and report["backtrace"]:
                report["pc"] = report["backtrace"][0].get("pc")
            regs = await try_verb("regs", {})
            report["registers"] = (regs or {}).get("regs", {})

            pc = parse_hex_addr(report.get("pc"))
            if pc is not None:
                dis = await try_verb("disasm", {"start": max(pc - 16, 0), "count": 32})
                report["disassembly"] = (dis or {}).get("instructions", [])
                mem = await try_verb("read_mem", {"addr": pc, "length": 64})
                if mem is not None:
                    report["memory_at_pc"] = mem
            else:
                report["disassembly"] = []
                warnings.append("no PC available for disassembly")

            sp = parse_hex_addr(report["registers"].get("rsp"))
            if sp is not None:
                mem = await try_verb("read_mem", {"addr": sp, "length": 256})
                if mem is not None:
                    report["memory_at_sp"] = mem
            else:
                warnings.append("no rsp available for stack dump")

            fault = parse_hex_addr(report.get("fault_addr"))
            if fault is not None:
                mem = await try_verb("read_mem", {"addr": fault, "length": 64})
                if mem is not None:
                    report["memory_at_fault_addr"] = mem

            mmap = await try_verb("mem_map", {})
            if mmap is not None:
                lines = mmap.get("output", "").splitlines()
                report["memory_map_head"] = lines[:40]
            report["warnings"] = warnings
        return report
