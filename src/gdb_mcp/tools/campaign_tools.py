"""Exploit-campaign tools: structured state + cyclic oracle."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from gdb_mcp import campaign as camp

from ._common import check_stopped, config_from, registry_from, resolve_gdb
from .registry import tool


@tool()
async def campaign(
    action: str = "get",
    section: str | None = None,
    key: str | None = None,
    value: str | None = None,
    text: str | None = None,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """The session's exploit-campaign state — what has been
    established so far (protections, libc leaks, offsets, primitives,
    notes). Actions: get (full state), set (section/key/value:
    sections protections|libc|offsets|primitives), note (text),
    detect (run the cyclic oracle over the last stop's pc/fault/
    registers; a hit is recorded as a pc-control candidate), pattern
    (value = requested length; returns a pwntools-compatible cyclic
    string for payload building). A compact summary is auto-injected
    into stop responses."""
    if action not in ("get", "set", "note", "detect", "pattern"):
        raise ValueError(
            "action must be one of get, set, note, detect, pattern"
        )
    session = resolve_gdb(ctx, session_id)
    data = session.campaign
    if action == "get":
        return {"session_id": session.session_id, "campaign": data}
    if action == "set":
        if not section or not key or value is None:
            raise ValueError("set requires section, key and value")
        try:
            camp.campaign_set(data, section, key, value)
        except ValueError as exc:
            raise ValueError(str(exc)) from None
        registry_from(ctx).save()
        return {"session_id": session.session_id, "set": {section: {key: value}}}
    if action == "note":
        if not text:
            raise ValueError("note requires text")
        camp.campaign_note(data, text)
        registry_from(ctx).save()
        return {"session_id": session.session_id, "noted": True}
    if action == "detect":
        match = camp.campaign_detect(data, session.stop_info or {})
        registry_from(ctx).save()
        return {
            "session_id": session.session_id,
            "match": match,
            "primitives": data.get("primitives", {}),
        }
    # pattern
    try:
        count = int(value or 4096)
    except ValueError:
        raise ValueError("pattern requires value = requested length") from None
    return {
        "session_id": session.session_id,
        "pattern": camp.cyclic_pattern(count),
        "length": min(max(count, 0), camp._MAX_PATTERN),
    }


@tool()
async def diff_sessions(
    session_a: str,
    session_b: str,
    memory_addr: str | int | None = None,
    memory_length: int = 128,
    ctx: Context = None,
) -> dict:
    """Differential debugging: compare two sessions' register state
    (and optionally one memory region) — same binary, different
    inputs; the differences are the behavioral semantics. Both
    session_ids are required explicitly."""
    cfg = config_from(ctx)
    registry = registry_from(ctx)
    sa = registry.get(session_a)
    sb = registry.get(session_b)
    check_stopped(sa)
    check_stopped(sb)
    regs_a = (await sa.request("regs", {}, timeout=cfg.request_timeout)).get(
        "regs", {}
    )
    regs_b = (await sb.request("regs", {}, timeout=cfg.request_timeout)).get(
        "regs", {}
    )
    changed = {
        name: {"a": regs_a[name], "b": regs_b[name]}
        for name in sorted(set(regs_a) | set(regs_b))
        if regs_a.get(name) != regs_b.get(name)
    }
    result = {
        "session_a": session_a,
        "session_b": session_b,
        "registers_changed": changed,
        "registers_truncated": len(changed) > 64,
    }
    if memory_addr is not None:
        mem_a = await sa.request(
            "read_mem",
            {"addr": memory_addr, "length": max(1, min(memory_length, 4096))},
            timeout=cfg.request_timeout,
        )
        mem_b = await sb.request(
            "read_mem",
            {"addr": memory_addr, "length": max(1, min(memory_length, 4096))},
            timeout=cfg.request_timeout,
        )
        hex_a, hex_b = mem_a.get("hex"), mem_b.get("hex")
        if hex_a and hex_b:
            rows = []
            data_a = bytes.fromhex(hex_a)
            data_b = bytes.fromhex(hex_b)
            for off in range(0, len(data_a), 16):
                row_a = data_a[off : off + 16]
                row_b = data_b[off : off + 16]
                if row_a != row_b:
                    rows.append(
                        {
                            "addr": "0x%x"
                            % (int(mem_a["addr"]) + off),
                            "a_hex": row_a.hex(),
                            "b_hex": row_b.hex(),
                        }
                    )
                    if len(rows) >= 128:
                        break
            result["memory_diff"] = {
                "addr": memory_addr,
                "rows": rows,
                "truncated": len(rows) >= 128,
            }
    return result
