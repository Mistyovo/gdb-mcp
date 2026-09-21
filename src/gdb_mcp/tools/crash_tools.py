"""Crash-triage tools: one call to get the full picture of a stop, and
the crash→report pipeline for fuzz_loop verdicts (D3)."""

from __future__ import annotations

import json

from mcp.server.fastmcp import Context

from gdb_mcp.campaign import (
    campaign_detect,
    campaign_note,
    campaign_summary,
    is_empty,
)
from gdb_mcp.errors import GdbMcpError
from gdb_mcp.output import parse_proc_mappings
from gdb_mcp.results import store_result
from gdb_mcp.sessions import RUNNING, Session

from ._common import (
    check_stopped,
    config_from,
    parse_hex_addr,
    registry_from,
    resolve_gdb,
)

#: policies loop plugin-side; a long minimize can legitimately take minutes
_POLICY_TIMEOUT = 600.0


async def _collect_crash_report(
    session: Session,
    cfg,
    registry,
    stop_info: dict,
    max_frames: int,
) -> dict:
    """One-call crash triage body, shared by crash_report (current stop)
    and triage_crash (a reproduced stop). Best-effort: unreadable pieces
    are reported in ``warnings`` instead of failing the whole call."""
    timeout = min(cfg.request_timeout, 10.0)
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
            segments = parse_proc_mappings(mmap.get("output", ""))
            head = segments[:24]
            report["memory_map"] = {
                "segments": head,
                "total_segments": len(segments),
                "truncated": len(segments) > len(head)
                or bool(mmap.get("truncated", False)),
            }
        # cyclic oracle over the stop values: a pattern hit is recorded
        # in the campaign as a pc-control candidate
        detect = campaign_detect(session.campaign, stop_info)
        if detect is not None:
            report["cyclic_match"] = detect
            registry.save()
        if not is_empty(session.campaign):
            report["campaign"] = campaign_summary(session.campaign)
        report["warnings"] = warnings
    return report


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
        return await _collect_crash_report(
            session, cfg, registry_from(ctx), session.stop_info or {}, max_frames
        )

    @app.tool()
    async def triage_crash(
        payload_hex: str = "",
        buffer_addr: str | None = None,
        stop_location: str | None = None,
        snapshot_id: str | None = None,
        minimize: bool = False,
        max_frames: int = 16,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """D3 crash→report pipeline: verify that a crashing payload
        (e.g. the payload_index entry of a run_policy(fuzz_loop) crash
        list) still crashes when replayed from the checkpoint, collect
        the full crash_report on the reproduced stop, optionally
        minimize the payload, and store the whole package as evidence
        (result file + campaign note). With empty payload/buffer/
        stop_location, triages whatever stop the session is in right
        now. The checkpoint restore gives the replay a fresh process
        image — the deterministic equivalent of a dedicated debug
        session, and unlike stdin replay it also reproduces payloads
        that were delivered by direct memory writes."""
        cfg = config_from(ctx)
        registry = registry_from(ctx)
        session = resolve_gdb(ctx, session_id)
        check_stopped(session)
        can_verify = bool(payload_hex and buffer_addr and stop_location)
        verify = None
        verify_error = None
        if can_verify:
            params: dict = {
                "kind": "crash_check",
                "buffer_addr": buffer_addr,
                "payload": payload_hex,
                "stop_location": stop_location,
            }
            if snapshot_id:
                params["snapshot_id"] = snapshot_id
            try:
                verify = await session.request(
                    "policy", params, timeout=_POLICY_TIMEOUT
                )
            except GdbMcpError as exc:
                verify_error = str(exc)
        reproduced = None
        if verify is not None:
            reproduced = bool(
                not verify.get("survived") and verify.get("error") is None
            )
            if not reproduced:
                return {
                    "reproduced": False,
                    "verify": verify,
                    "verify_error": verify_error,
                    "note": (
                        "payload did not crash from the checkpoint; "
                        "nothing to triage"
                    ),
                }
        stop_info = (verify or {}).get("stop") or session.stop_info or {}
        report = await _collect_crash_report(
            session, cfg, registry, stop_info, max_frames
        )
        result = {
            "reproduced": reproduced,
            "verify_error": verify_error,
            "signal": report.get("signal"),
            "fault_addr": report.get("fault_addr"),
            "pc": report.get("pc"),
            "cyclic_match": report.get("cyclic_match"),
            "report": report,
        }
        if minimize and can_verify:
            params = {
                "kind": "minimize",
                "buffer_addr": buffer_addr,
                "payload": payload_hex,
                "stop_location": stop_location,
            }
            if snapshot_id:
                params["snapshot_id"] = snapshot_id
            try:
                result["minimized"] = await session.request(
                    "policy", params, timeout=_POLICY_TIMEOUT
                )
            except GdbMcpError as exc:
                result["minimize_error"] = str(exc)
        evidence = {
            "session_id": session.session_id,
            "reproduced": reproduced,
            "payload_hex": payload_hex,
            "signal": report.get("signal"),
            "pc": report.get("pc"),
            "fault_addr": report.get("fault_addr"),
            "cyclic_match": report.get("cyclic_match"),
            "minimized": result.get("minimized"),
            "report": report,
        }
        stored = store_result(
            cfg.log_dir, json.dumps(evidence, ensure_ascii=False, indent=1)
        )
        result["evidence_file"] = stored["path"]
        campaign_note(
            session.campaign,
            "crash triaged: signal=%s pc=%s evidence=%s"
            % (report.get("signal"), report.get("pc"), stored["path"]),
        )
        registry.save()
        return result
