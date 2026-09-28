"""Execution-control tools (continue/step/interrupt/wait) and result store."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.results import load_result_slice, store_result
from gdb_mcp.security import is_unsafe_gdb_command
from gdb_mcp.sessions import RUNNING

from ._common import audit_from, check_stopped, config_from, resolve_gdb
from .registry import tool
from .stop_context import collect_stop_context

_MODES = (
    "continue",
    "step",
    "next",
    "stepi",
    "nexti",
    "finish",
    "until",
    # gdb native record/replay (recording must be started first with
    # execute_command('record full')); requires the reverse_* resume
    # modes below
    "reverse_continue",
    "reverse_step",
    "reverse_next",
)

_BATCH_LIMIT = 32


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


@tool(core=True)
async def execute_command(
    command: str,
    keep_ansi: bool = False,
    offset: int | None = None,
    limit: int | None = None,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Execute a raw gdb command and return its output. Use for
    pwndbg-specific commands (vmmap, heap, got, checksec, ropgadget,
    search, ...) or any other gdb CLI command. Works while the
    inferior is running (queued until the next stop). Large output
    should be read in line ranges: pass offset (0-based) and limit to
    page through; responses carry total_lines and truncated. Outputs
    exceeding the inline limit are stored on disk — the response then
    carries result_file/result_sha256 and read_result serves the
    rest."""
    if offset is not None and (
        isinstance(offset, bool) or not isinstance(offset, int) or offset < 0
    ):
        raise ValueError("offset must be a non-negative int")
    if limit is not None and (
        isinstance(limit, bool) or not isinstance(limit, int) or limit < 1
    ):
        raise ValueError("limit must be a positive int")
    cfg = config_from(ctx)
    if not cfg.allow_unsafe and is_unsafe_gdb_command(command):
        audit_from(ctx).record("unsafe_command_blocked", command=command)
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
async def batch_commands(
    commands: list[str],
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Execute multiple raw gdb commands in one round-trip. Returns
    per-command results ({ok, output, ...} or {ok, error}) in order;
    execution stops at the first failing command. For composed state
    reads prefer wait_for_stop(with_context=True) or crash_report."""
    if (
        not isinstance(commands, list)
        or not commands
        or len(commands) > _BATCH_LIMIT
    ):
        raise ValueError(
            "commands must be a list of 1..%d strings" % _BATCH_LIMIT
        )
    # validate everything up front so no command is executed for an
    # otherwise-invalid batch
    if any(not isinstance(c, str) or not c.strip() for c in commands):
        raise ValueError("each command must be a non-empty string")
    cfg = config_from(ctx)
    session = resolve_gdb(ctx, session_id)
    results = []
    for command in commands:
        if not cfg.allow_unsafe and is_unsafe_gdb_command(command):
            audit_from(ctx).record("unsafe_command_blocked", command=command)
            results.append(
                {
                    "ok": False,
                    "error": "UNSAFE_BLOCKED: command can execute code "
                    "outside the debugger",
                }
            )
            break
        try:
            r = await session.request(
                "eval", {"command": command}, timeout=cfg.request_timeout
            )
            results.append({"ok": True, **_maybe_store_result(cfg, r)})
        except GdbMcpError as exc:
            results.append({"ok": False, "error": str(exc)})
            break
    return {
        "results": results,
        "executed": len(results),
        "completed": bool(results) and results[-1].get("ok") is True,
    }


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
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be a non-negative int")
    if limit is not None and (
        isinstance(limit, bool) or not isinstance(limit, int) or limit < 1
    ):
        raise ValueError("limit must be a positive int")
    cfg = config_from(ctx)
    return load_result_slice(cfg.log_dir, path, offset, limit)


@tool(core=True)
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


@tool(core=True)
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


@tool()
def get_stop_reason(session_id: str | None = None, ctx: Context = None) -> dict:
    """The reason the inferior last stopped (signal, fault address,
    breakpoint info)."""
    session = resolve_gdb(ctx, session_id)
    return {
        "session_id": session.session_id,
        "state": session.state,
        "stop_info": session.stop_info,
        "exited_code": session.exited_code,
    }
