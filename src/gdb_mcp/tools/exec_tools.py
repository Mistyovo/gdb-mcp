"""Execution control, raw gdb command passthrough, and inferior stdio."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.output import hex_to_bytes
from gdb_mcp.protocol import ASYNC_VERBS
from gdb_mcp.results import load_result_slice, store_result
from gdb_mcp.security import is_unsafe_gdb_command
from gdb_mcp.sessions import RUNNING

from ._common import check_stopped, config_from, resolve_gdb, validate_page
from .registry import tool
from .stop_context import collect_stop_context

_MODES = tuple(sorted(ASYNC_VERBS))


def _maybe_store_result(config, result: dict) -> dict:
    """Store oversized eval output on disk; attach result_file/sha256."""
    output = result.get("output")
    if isinstance(output, str) and len(output) > config.result_inline_limit:
        stored = store_result(config.log_dir, output)
        result = dict(result)
        result["output"] = (
            output[: config.result_inline_limit] + "\n...[stored to result_file]"
        )
        result["truncated"] = True
        result["result_file"] = stored["path"]
        result["result_sha256"] = stored["sha256"]
    return result


@tool(core=True, capability="host")
async def execute_command(
    command: str = "",
    keep_ansi: bool = False,
    offset: int | None = None,
    limit: int | None = None,
    result_file: str | None = None,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Run a raw gdb/pwndbg command (supports multi-line; every line
    passes the unsafe gate unless --allow-unsafe). Page large output
    with offset/limit. Oversized outputs spill to `result_file`; pass
    `result_file` + `offset`/`limit` to read slices back."""
    validate_page(offset, limit)
    cfg = config_from(ctx)
    if result_file is not None:
        return load_result_slice(cfg.log_dir, result_file, offset or 0, limit)
    if not command or not command.strip():
        raise GdbMcpError("BAD_PARAMS", "command or result_file is required")
    if not cfg.allow_unsafe and is_unsafe_gdb_command(command):
        raise GdbMcpError(
            "UNSAFE_BLOCKED",
            "command can execute code outside the debugger "
            "(shell/!/pipe/python/source); set GDB_MCP_ALLOW_UNSAFE=1 "
            "or --allow-unsafe to allow it",
        )
    session = resolve_gdb(ctx, session_id)
    params = {"command": command, "keep_ansi": keep_ansi}
    if offset is not None:
        params["offset"] = offset
    if limit is not None:
        params["limit"] = limit
    result = await session.request("eval", params, timeout=cfg.request_timeout)
    return _maybe_store_result(cfg, result)


@tool(core=True, capability="debug")
async def control_execution(
    action: str = "continue",
    until_addr: str | None = None,
    wait: bool = True,
    timeout_ms: int = 30000,
    with_context: bool = False,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Control inferior execution. Actions:
    - continue / step / next / stepi / nexti / finish / until /
      reverse_continue / reverse_step / reverse_next: resume (by default
      waits for stop; set `with_context=True` for registers+bt+disasm).
    - wait: block until the running inferior stops (supports `with_context`).
    - interrupt: Ctrl-C the running inferior (also cancels active policy)."""
    if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or timeout_ms < 100:
        raise ValueError("timeout_ms must be an int >= 100")
    cfg = config_from(ctx)
    session = resolve_gdb(ctx, session_id)
    if action == "interrupt":
        if session.state != RUNNING:
            return {
                "state": "not_running",
                "note": "inferior is not running; nothing to interrupt",
            }
        return await session.request("interrupt", {}, timeout=cfg.request_timeout)
    if action == "wait":
        stopped = await session.wait_for_stop(timeout=max(0.1, timeout_ms / 1000.0))
        result = {
            "session_id": session.session_id,
            "stopped": stopped,
            "state": session.state,
            "stop_info": session.stop_info,
        }
        if with_context and stopped:
            result["context"] = await collect_stop_context(session, cfg)
        return result
    if action not in _MODES:
        raise ValueError(
            "action must be interrupt, wait, or one of %s" % ", ".join(_MODES)
        )
    check_stopped(session)
    params = {}
    if action == "until" and until_addr:
        params["until_addr"] = until_addr
    result = await session.request(action, params, timeout=cfg.request_timeout)
    if not wait:
        return result
    stopped = await session.wait_for_stop(timeout=max(0.1, timeout_ms / 1000.0))
    response = {
        "session_id": session.session_id,
        "resumed": True,
        "stopped": stopped,
        "state": session.state,
        "stop_info": session.stop_info,
        "exited_code": session.exited_code,
    }
    if with_context and stopped:
        response["context"] = await collect_stop_context(session, cfg)
    return response


@tool(capability="target")
async def inferior_io(
    action: str = "read",
    text: str | None = None,
    hex: str | None = None,
    since_seq: int = 0,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Interact with the inferior's stdio pty (works while running).
    - send: write UTF-8 `text` or raw `hex` (auto-creates pty if needed).
    - read: return buffered stdout/stderr chunks since `since_seq`."""
    cfg = config_from(ctx)
    session = resolve_gdb(ctx, session_id)
    if action == "read":
        if isinstance(since_seq, bool) or not isinstance(since_seq, int) or since_seq < 0:
            raise ValueError("since_seq must be a non-negative int")
        return await session.request(
            "io_read", {"since_seq": since_seq}, timeout=cfg.request_timeout
        )
    if action == "send":
        if (text is None) == (hex is None):
            raise GdbMcpError("BAD_PARAMS", "pass either text or hex, not both")
        if text is not None:
            payload_hex = text.encode("utf-8").hex()
        else:
            try:
                data = hex_to_bytes(hex or "")
            except ValueError as exc:
                raise GdbMcpError("BAD_PARAMS", str(exc)) from None
            if not data:
                raise GdbMcpError("BAD_PARAMS", "hex payload must not be empty")
            payload_hex = data.hex()
        try:
            return await session.request(
                "io_send", {"hex": payload_hex}, timeout=cfg.request_timeout
            )
        except GdbMcpError as exc:
            if "io not set up" not in exc.message:
                raise
        setup = await session.request("io_setup", {}, timeout=cfg.request_timeout)
        sent = await session.request(
            "io_send", {"hex": payload_hex}, timeout=cfg.request_timeout
        )
        return {**sent, "io_setup": setup}
    raise GdbMcpError("BAD_PARAMS", "action must be send or read")
