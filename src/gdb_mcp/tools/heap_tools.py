"""Pwn-workflow tools: glibc heap inspection, checkpoints, and delegated
native-speed policies."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from gdb_mcp.campaign import campaign_set
from gdb_mcp.errors import GdbMcpError
from gdb_mcp.heap import parse_heap_chunk
from gdb_mcp.output import parse_pwndbg_bins

from ._common import check_stopped, config_from, registry_from, resolve_gdb
from .registry import tool

_SNAPSHOT_ACTIONS = ("create", "list", "restore", "diff")


def _read_bytes(result: dict) -> bytes:
    hex_data = result.get("hex")
    if hex_data:
        return bytes.fromhex(hex_data)
    start = int(result.get("addr") or 0)
    for segment in result.get("segments") or []:
        try:
            if int(segment.get("addr")) == start and segment.get("hex"):
                return bytes.fromhex(segment["hex"])
        except (TypeError, ValueError):
            continue
    return b""


@tool()
async def heap(
    action: str = "bins",
    address: str | int | None = None,
    user_ptr: bool = False,
    data_length: int = 32,
    include_raw: bool = False,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Inspect glibc heap state. Actions:
    - bins: structured tcache/fast/unsorted/small/large bins (requires pwndbg).
    - chunk: decode one 64-bit malloc_chunk at `address` (no pwndbg; set
      `user_ptr=True` for a malloc return pointer; safe-linking aware)."""
    cfg = config_from(ctx)
    session = resolve_gdb(ctx, session_id)
    check_stopped(session)
    if action == "bins":
        if not (session.hello or {}).get("pwndbg"):
            raise GdbMcpError(
                "NO_PWNDBG",
                "heap(action='bins') requires pwndbg; start gdb with pwndbg "
                "or use execute_command('bins')",
            )
        result = await session.request(
            "eval", {"command": "bins"}, timeout=cfg.request_timeout
        )
        parsed = parse_pwndbg_bins(result.get("output", ""))
        parsed["truncated"] = bool(result.get("truncated", False))
        if not parsed["parsed"] or include_raw:
            parsed["output"] = result.get("output", "")
        return parsed
    if action == "chunk":
        if address is None:
            raise GdbMcpError("BAD_PARAMS", "address is required for action='chunk'")
        if (
            isinstance(data_length, bool)
            or not isinstance(data_length, int)
            or not (0 <= data_length <= 256)
        ):
            raise GdbMcpError("BAD_PARAMS", "data_length must be between 0 and 256")
        expr = "(char*)(%s) - 16" % address if user_ptr else str(address)
        header_resp = await session.request(
            "read_mem", {"addr": expr, "length": 32}, timeout=cfg.request_timeout
        )
        header = _read_bytes(header_resp)
        if len(header) < 16:
            raise GdbMcpError(
                "MEMORY_ERROR",
                "cannot read a 16-byte chunk header at %s" % address,
            )
        chunk_addr = int(header_resp.get("addr") or 0)
        chunk_size = int.from_bytes(header[8:16], "little") & ~0x7
        next_size = None
        if chunk_size >= 0x20:
            try:
                next_resp = await session.request(
                    "read_mem",
                    {"addr": "0x%x" % (chunk_addr + chunk_size), "length": 8},
                    timeout=cfg.request_timeout,
                )
            except GdbMcpError:
                next_resp = None
            if next_resp is not None:
                raw_next = _read_bytes(next_resp)
                if len(raw_next) >= 8:
                    next_size = raw_next[:8]
        data = None
        if data_length:
            try:
                data_resp = await session.request(
                    "read_mem",
                    {"addr": "0x%x" % (chunk_addr + 16), "length": data_length},
                    timeout=cfg.request_timeout,
                )
            except GdbMcpError:
                data = None
            else:
                data = _read_bytes(data_resp)
        parsed = parse_heap_chunk(
            header[:32],
            chunk_addr=chunk_addr,
            next_size=next_size,
            data=data,
            data_length=data_length,
        )
        parsed["user_ptr"] = bool(user_ptr)
        if len(header) < 32:
            parsed["warnings"].append(
                "only %d header bytes readable; fd/bk unavailable" % len(header)
            )
        return parsed
    raise GdbMcpError("BAD_PARAMS", "action must be bins or chunk")


@tool(capability="target")
async def run_policy(
    kind: str,
    params: dict | None = None,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Delegate a bounded loop to run inside gdb at native speed; returns
    a constant-size summary. Kinds (require stopped inferior):
    - trace: {max_steps} single-steps -> unique PCs.
    - heap_arm/heap_read/heap_disarm: probe {symbols, max_events,
      capture_returns, return_symbols} -> raw/named args + return ptr.
    - fuzz_loop: {snapshot_id, buffer_addr, payloads, stop_location} ->
      deduped crashes.
    - crash_check: single-payload {survived, stop}.
    - minimize: delta-debug crashing payload {snapshot_id, payload,
      buffer_addr, stop_location, max_rounds}.
    - bp_stats: {locations, stop_location, max_hits, max_passes}.
    - verify_pc_control: replay canary at offset -> verified pc_control."""
    session = resolve_gdb(ctx, session_id)
    check_stopped(session)
    policy_params = dict(params or {})
    policy_params["kind"] = kind
    result = await session.request(
        "policy",
        policy_params,
        timeout=max(config_from(ctx).request_timeout, 600.0),
    )
    if kind == "verify_pc_control" and result.get("verified") is True:
        target = result.get("target", "pc")
        prim = "pc_control" if target == "pc" else "fault_addr_controlled"
        campaign_set(
            session.campaign,
            "primitives",
            prim,
            "verified",
            evidence="%s == %s at offset %s"
            % (target, result.get("expected"), result.get("offset")),
        )
        registry_from(ctx).save()
    return result


@tool(capability="target")
async def checkpoint(
    action: str = "create",
    snapshot_id: str | None = None,
    max_segment_bytes: int | None = None,
    max_total_bytes: int | None = None,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Registers + writable-memory snapshots for hypothesis testing.
    Actions: create, list, restore (snapshot_id), diff (snapshot_id)."""
    if action not in _SNAPSHOT_ACTIONS:
        raise GdbMcpError(
            "BAD_PARAMS",
            "action must be one of create, list, restore, diff",
        )
    if action in ("restore", "diff") and not snapshot_id:
        raise GdbMcpError(
            "BAD_PARAMS", "action %r requires snapshot_id" % action
        )
    cfg = config_from(ctx)
    session = resolve_gdb(ctx, session_id)
    check_stopped(session)
    params: dict = {}
    if snapshot_id:
        params["snapshot_id"] = snapshot_id
    if max_segment_bytes is not None:
        params["max_segment_bytes"] = max_segment_bytes
    if max_total_bytes is not None:
        params["max_total_bytes"] = max_total_bytes
    verb = (
        "snapshot_create"
        if action == "create"
        else "snapshot_list"
        if action == "list"
        else "snapshot_restore"
        if action == "restore"
        else "snapshot_diff"
    )
    return await session.request(verb, params, timeout=cfg.request_timeout)
