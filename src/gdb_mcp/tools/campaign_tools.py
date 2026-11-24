"""Exploit-campaign tools: structured state + cyclic oracle."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from gdb_mcp import campaign as camp

from ._common import check_stopped, config_from, registry_from, resolve_gdb
from .registry import tool


@tool(capability="debug")
async def campaign(
    action: str = "get",
    section: str | None = None,
    key: str | None = None,
    value: str | None = None,
    text: str | None = None,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Session exploit-campaign state (protections, libc, offsets,
    primitives, notes). Actions: get, set (section/key/value), note
    (text), detect (cyclic oracle over last stop: PC->pc_control,
    fault_addr->fault_addr_controlled, reg->cyclic_match), protections
    (parse pwndbg checksec into protections), pattern (value=length)."""
    if action not in ("get", "set", "note", "detect", "protections", "pattern"):
        raise ValueError(
            "action must be one of get, set, note, detect, protections, pattern"
        )
    session = resolve_gdb(ctx, session_id)
    data = session.campaign
    if action == "get":
        return {"session_id": session.session_id, "campaign": data}
    if action == "set":
        if not section or not key or value is None:
            raise ValueError("set requires section, key and value")
        camp.campaign_set(data, section, key, value)
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
    if action == "protections":
        if not (session.hello or {}).get("pwndbg"):
            return {
                "session_id": session.session_id,
                "detected": False,
                "reason": "pwndbg is not loaded in this session",
                "protections": data.get("protections", {}),
            }
        check_stopped(session)
        cfg = config_from(ctx)
        res = await session.request(
            "eval", {"command": "checksec"}, timeout=cfg.request_timeout
        )
        parsed = camp.parse_checksec(res.get("output", ""))
        if not parsed:
            return {
                "session_id": session.session_id,
                "detected": False,
                "reason": "checksec output had no recognized protection fields",
                "protections": data.get("protections", {}),
            }
        for pkey, info in parsed.items():
            camp.campaign_set(
                data, "protections", pkey, info["value"], evidence=info["evidence"]
            )
        registry_from(ctx).save()
        return {
            "session_id": session.session_id,
            "detected": True,
            "protections": data.get("protections", {}),
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


@tool(experimental=True)
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
    changed_names = [
        name
        for name in sorted(set(regs_a) | set(regs_b))
        if regs_a.get(name) != regs_b.get(name)
    ]
    changed = {
        name: {"a": regs_a[name], "b": regs_b[name]}
        for name in changed_names[:64]
    }
    result = {
        "session_a": session_a,
        "session_b": session_b,
        "registers_changed": changed,
        "registers_truncated": len(changed_names) > 64,
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
