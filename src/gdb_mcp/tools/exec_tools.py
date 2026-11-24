"""Execution-control tools (continue/step/interrupt/wait) and result store."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.output import hex_to_bytes
from gdb_mcp.results import load_result_slice, store_result
from gdb_mcp.security import is_unsafe_gdb_command
from gdb_mcp.sessions import RUNNING

from ._common import check_stopped, config_from, resolve_gdb, validate_page
from .registry import tool
from .stop_context import collect_stop_context

# the plugin's async verb table is the single source: this tool's mode
# parameter accepts exactly those resumes (imported, not retyped, so a
# new verb cannot drift between the two tables)
from gdb_mcp.protocol import ASYNC_VERBS  # noqa: E402

_MODES = tuple(sorted(ASYNC_VERBS))


def _maybe_store_result(config, result: dict) -> dict:
    """Store oversized eval output on disk; returns the (possibly
    preview-trimmed) result with result_file/result_sha256 attached."""
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
    command: str,
    keep_ansi: bool = False,
    offset: int | None = None,
    limit: int | None = None,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Execute a raw gdb command (or newline-separated commands) and
    return its output. Supports pwndbg commands (vmmap, heap, got,
    checksec, ...). Every line passes the unsafe gate unless
    --allow-unsafe. Page large output with offset/limit; oversized output
    spills to result_file (read via read_result)."""
    validate_page(offset, limit)
    cfg = config_from(ctx)
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
    result = await session.request(
        "eval",
        params,
        timeout=cfg.request_timeout,
    )
    return _maybe_store_result(cfg, result)


@tool()
def read_result(
    path: str,
    offset: int = 0,
    limit: int | None = None,
    ctx: Context = None,
) -> dict:
    """Read a line range from a stored result file (the result_file
    path returned when an execute_command output was too large for an
    inline response). offset is a 0-based line number; the response
    carries total_lines and truncated."""
    validate_page(offset, limit)
    cfg = config_from(ctx)
    return load_result_slice(cfg.log_dir, path, offset, limit)


@tool(core=True, capability="debug")
async def continue_execution(
    mode: str = "continue",
    until_addr: str | None = None,
    wait: bool = False,
    timeout_ms: int = 30000,
    with_context: bool = False,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Resume the inferior: continue / step / next / stepi / nexti /
    finish / until, plus reverse_continue / reverse_step /
    reverse_next under gdb native record (start recording first with
    execute_command('record full') while stopped). By default returns
    immediately ({'state': 'running'}). With wait=True the call
    blocks until the next stop (or timeout_ms) and returns the stop
    reason; add with_context=True to also get key registers,
    backtrace and disassembly around PC in the same response — the
    one-call breakpoint-hit pattern."""
    if mode not in _MODES:
        raise ValueError("mode must be one of %s" % ", ".join(_MODES))
    if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or timeout_ms < 100:
        raise ValueError("timeout_ms must be an int >= 100")
    cfg = config_from(ctx)
    session = resolve_gdb(ctx, session_id)
    check_stopped(session)
    params = {}
    if mode == "until" and until_addr:
        params["until_addr"] = until_addr
    result = await session.request(
        mode, params, timeout=cfg.request_timeout
    )
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


@tool(core=True, capability="debug")
async def interrupt(session_id: str | None = None, ctx: Context = None) -> dict:
    """Interrupt the running inferior (equivalent to Ctrl-C in gdb).
    The inferior stops and a stop notification is emitted."""
    session = resolve_gdb(ctx, session_id)
    if session.state != RUNNING:
        return {
            "state": "not_running",
            "note": "inferior is not running; nothing to interrupt",
        }
    result = await session.request(
        "interrupt", {}, timeout=config_from(ctx).request_timeout
    )
    return result


@tool(core=True)
async def wait_for_stop(
    timeout_ms: int = 30000,
    with_context: bool = False,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Wait until the inferior stops (signal, breakpoint, exit) or the
    timeout elapses. Returns immediately when the inferior is already
    stopped. With with_context=True the response also carries key
    registers, backtrace and disassembly around PC."""
    cfg = config_from(ctx)
    session = resolve_gdb(ctx, session_id)
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


@tool(capability="target")
async def send_input(
    text: str | None = None,
    hex: str | None = None,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Send input to the inferior's stdio pty (pass either UTF-8 `text`
    or raw `hex`). If the pty channel is not yet set up, sets it up
    automatically (effective on the next run/start). Works while the
    inferior is running."""
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
    cfg = config_from(ctx)
    session = resolve_gdb(ctx, session_id)
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


@tool()
async def read_output(
    since_seq: int = 0,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Read the inferior's accumulated stdout/stderr chunks recorded on
    its pty since `since_seq` (0 = everything buffered). Each chunk
    carries seq, length, hex, and decoded text."""
    if isinstance(since_seq, bool) or not isinstance(since_seq, int) or since_seq < 0:
        raise ValueError("since_seq must be a non-negative int")
    session = resolve_gdb(ctx, session_id)
    return await session.request(
        "io_read",
        {"since_seq": since_seq},
        timeout=config_from(ctx).request_timeout,
    )
