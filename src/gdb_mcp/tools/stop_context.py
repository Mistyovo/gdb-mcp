"""Composed stop context: registers + backtrace + disassembly in one call.

Server-side composition only — the plugin's existing ``regs`` /
``backtrace`` / ``disasm`` verbs are fanned out under the session lock so
all three observe the same stop. This is the token-efficient counterpart
of crashing into 3-5 separate tool calls after every breakpoint hit.
"""

from __future__ import annotations

from gdb_mcp.campaign import campaign_summary, is_empty
from gdb_mcp.config import Config
from gdb_mcp.errors import GdbMcpError
from gdb_mcp.output import fmt_addr
from gdb_mcp.sessions import Session

from ._common import parse_hex_addr

# Registers worth surfacing to a model after a stop, across common
# architectures. Falls back to the full set when nothing matches.
_KEY_REGS = {
    "pc", "rip", "eip", "ip", "sp", "rsp", "esp", "bp", "rbp", "ebp",
    "lr", "x30", "rflags", "eflags", "flags", "cpsr", "pstate", "nzcv",
    "rax", "eax", "rbx", "ebx", "rcx", "ecx", "rdx", "edx",
    "rsi", "esi", "rdi", "edi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
}
_KEY_REGS.update("x%d" % i for i in range(30))
_KEY_REGS.update("w%d" % i for i in range(30))
_KEY_REGS.update("r%d" % i for i in range(13))
_KEY_REGS = frozenset(_KEY_REGS)


def key_registers(regs: dict) -> dict:
    """The architecturally interesting subset of a full register dump."""
    subset = {k: v for k, v in regs.items() if k.lower() in _KEY_REGS}
    return subset or dict(regs)


async def collect_stop_context(
    session: Session,
    config: Config,
    *,
    max_frames: int = 8,
    disasm_count: int = 12,
) -> dict:
    """Best-effort snapshot of the current stop. Failures of individual
    sub-requests are reported in ``warnings`` instead of failing the
    whole composition (mirrors crash_report)."""
    warnings: list[str] = []
    timeout = min(config.request_timeout, 10.0)

    async def try_verb(verb: str, params: dict):
        try:
            return await session.request(
                verb, params, timeout=timeout, locked=True
            )
        except GdbMcpError as exc:
            warnings.append("%s: %s" % (verb, exc))
            return None

    context: dict = {"warnings": warnings}
    # Hold the session lock across the sub-requests so the trio observes
    # one consistent stop even if other tools run concurrently.
    async with session.lock:
        regs = await try_verb("regs", {})
        context["registers"] = key_registers((regs or {}).get("regs", {}))
        bt = await try_verb("backtrace", {"max_frames": max_frames})
        frames = (bt or {}).get("frames", [])
        context["backtrace"] = frames
        pc = parse_hex_addr((session.stop_info or {}).get("pc"))
        if pc is None and frames:
            pc = parse_hex_addr(frames[0].get("pc"))
        if pc is not None:
            dis = await try_verb(
                "disasm", {"start": fmt_addr(max(pc - 16, 0)), "count": disasm_count}
            )
            context["disassembly"] = (dis or {}).get("instructions", [])
        else:
            context["disassembly"] = []
            warnings.append("no PC available for disassembly")
    # constant-size campaign brief: what this session has already
    # established, so the model never re-derives it
    if not is_empty(session.campaign):
        context["campaign"] = campaign_summary(session.campaign)
    return context
