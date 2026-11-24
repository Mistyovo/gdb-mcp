"""Session lifecycle and inspection tools."""

from __future__ import annotations

import asyncio
import os
import time

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.journal import compile_gdbscript
from gdb_mcp.output import tail_text_file
from gdb_mcp.sessions import DISCONNECTED, RESERVED

from ._common import config_from, registry_from, resolve_any, resolve_gdb
from .registry import tool


@tool(core=True)
async def session_info(
    action: str = "list",
    tail_lines: int = 200,
    last: int = 20,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """Inspect gdb-mcp sessions. Actions:
    - list: all sessions with state/arch/inferior/last_stop.
    - status: detailed status + uptime + exited_code for one session.
    - events: recent events (connected/stop/running/exited/prompt, last=1..100).
    - output: tail stdout/stderr log of a launched session (tail_lines).
    - export: compile the session journal into a replayable gdbscript."""
    if action == "list":
        return {"sessions": [s.info() for s in registry_from(ctx).list_all()]}
    if action == "status":
        session = resolve_gdb(ctx, session_id)
        info = session.info()
        info["uptime_sec"] = round(
            time.monotonic() - (session.connected_at or session.created_at), 1
        )
        info["exited_code"] = session.exited_code
        return info
    if action == "events":
        if isinstance(last, bool) or not isinstance(last, int) or not (1 <= last <= 100):
            raise ValueError("last must be an int between 1 and 100")
        session = resolve_any(ctx, session_id)
        return {
            "session_id": session.session_id,
            "state": session.state,
            "events": session.recent_events(last),
            "total_recorded": session.event_seq,
            "stored": len(session.event_log),
        }
    if action == "output":
        session = resolve_any(ctx, session_id)
        if not session.log_file:
            raise GdbMcpError(
                "NO_LOG",
                "session %r has no log file (not launched by this server)"
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
    if action == "export":
        cfg = config_from(ctx)
        if cfg.readonly:
            raise GdbMcpError("READONLY", "export is disabled in --readonly mode")
        session = resolve_gdb(ctx, session_id)
        if session.journal is None or len(session.journal) == 0:
            raise GdbMcpError("NO_JOURNAL", "session has no journal entries yet")
        launch = session.launch_info or {}
        meta = {
            "session_id": session.session_id,
            "inferior": (session.hello or {}).get("inferior"),
            "program": launch.get("program"),
            "args": launch.get("args"),
            "cwd": launch.get("cwd"),
        }
        script, stats = compile_gdbscript(meta, session.journal.entries())
        out_dir = cfg.log_dir / "scripts"
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / ("%s.gdb" % session.session_id)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(script)
        return {
            "session_id": session.session_id,
            "path": str(path),
            "total_lines": script.count("\n"),
            "journal_entries": len(session.journal),
            **stats,
            "script": script,
        }
    raise GdbMcpError(
        "BAD_PARAMS",
        "action must be one of list, status, events, output, export",
    )
