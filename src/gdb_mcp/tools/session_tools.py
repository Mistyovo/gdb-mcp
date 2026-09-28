"""Session management / inspection tools."""

from __future__ import annotations

import asyncio
import time

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.journal import compile_gdbscript
from gdb_mcp.output import tail_text_file
from gdb_mcp.sessions import DISCONNECTED, RESERVED

from ._common import config_from, registry_from, resolve_any, resolve_gdb
from .registry import tool


@tool(core=True)
def list_sessions(ctx: Context) -> dict:
    """List all known sessions (gdb plugin connections and launched
    processes) with their state."""
    sessions = []
    for session in registry_from(ctx).list_all():
        sessions.append(session.info())
    return {"sessions": sessions}


@tool(readonly_safe=True)
def session_status(session_id: str | None = None, ctx: Context = None) -> dict:
    """Detailed status of one gdb session: state, inferior info,
    last stop reason."""
    session = resolve_gdb(ctx, session_id)
    info = session.info()
    info["uptime_sec"] = round(
        time.monotonic() - (session.connected_at or session.created_at), 1
    )
    info["exited_code"] = session.exited_code
    return info


@tool()
async def quit_gdb(
    kill_gdb: bool = False,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Detach the MCP plugin from gdb. With kill_gdb=True, also quit
    gdb itself (and with it the debugged process). Default leaves the
    externally launched gdb running."""
    session = resolve_gdb(ctx, session_id)
    if session.state == RESERVED:
        raise GdbMcpError(
            "DISCONNECTED", "session is not connected (hello pending)"
        )
    await session.send_quit(kill_gdb=kill_gdb)
    return {
        "session_id": session.session_id,
        "detached": True,
        "kill_gdb": kill_gdb,
        "note": "gdb process left running" if not kill_gdb else "gdb quit requested",
    }


@tool(core=True)
def get_events(
    last: int = 20,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Recent session events (connected / stop / running / exited /
    prompt / disconnected), oldest first, each with a monotonic seq.
    Use this to catch events that happened between other tool calls
    instead of re-polling state."""
    if isinstance(last, bool) or not isinstance(last, int) or not (1 <= last <= 100):
        raise ValueError("last must be an int between 1 and 100")
    session = resolve_any(ctx, session_id)
    return {
        "session_id": session.session_id,
        "state": session.state,
        "events": session.recent_events(last),
        "total_recorded": len(session.event_log),
    }


@tool()
def export_session_script(
    session_id: str | None = None, ctx: Context = None
) -> dict:
    """Compile the session's journal into a deterministic, replayable
    gdbscript (state-mutating and control-flow operations only; pure
    reads and plugin-specific checkpoint ops are skipped, with
    counters). This is the audit artifact: run it under plain gdb to
    reproduce what was done — no gdb-mcp required."""
    session = resolve_gdb(ctx, session_id)
    if session.journal is None or len(session.journal) == 0:
        raise GdbMcpError(
            "NO_JOURNAL", "session has no journal entries yet"
        )
    meta = {
        "session_id": session.session_id,
        "inferior": (session.hello or {}).get("inferior"),
    }
    script, stats = compile_gdbscript(meta, session.journal.entries())
    cfg = config_from(ctx)
    out_dir = cfg.log_dir / "scripts"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / ("%s.gdb" % session.session_id)
    path.write_text(script, encoding="utf-8")
    return {
        "session_id": session.session_id,
        "path": str(path),
        "total_lines": script.count("\n"),
        "journal_entries": len(session.journal),
        **stats,
        "script": script,
    }


@tool()
async def get_process_output(
    tail_lines: int = 200,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Tail the stdout/stderr log of a launched session (gdb or
    script). Requires the session to have been started by launch_gdb /
    launch_script."""
    session = resolve_any(ctx, session_id)
    if not session.log_file:
        raise GdbMcpError(
            "NO_LOG",
            "session %r has no log file (it was not launched by this server)"
            % session.session_id,
        )
    try:
        output, truncated = await asyncio.to_thread(
            tail_text_file, session.log_file, tail_lines
        )
    except OSError as exc:
        raise GdbMcpError("NO_LOG", "cannot read log: %s" % exc)
    return {
        "session_id": session.session_id,
        "log_file": session.log_file,
        "output": output,
        "truncated": truncated,
        "running": (
            getattr(session.proc, "returncode", None) is None
            if session.proc is not None
            else session.state not in (DISCONNECTED, RESERVED)
        ),
    }
