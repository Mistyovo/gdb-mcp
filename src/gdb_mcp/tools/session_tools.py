"""Session management / inspection tools."""

from __future__ import annotations

import asyncio
import time

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.output import tail_text_file
from gdb_mcp.sessions import DISCONNECTED, RESERVED

from ._common import resolve_any, resolve_gdb


def register(app, registry, config) -> None:
    @app.tool()
    def list_sessions(ctx: Context) -> dict:
        """List all known sessions (gdb plugin connections and launched
        processes) with their state."""
        sessions = []
        for session in registry.list_all():
            sessions.append(session.info())
        return {"sessions": sessions}

    @app.tool()
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

    @app.tool()
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

    @app.tool()
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
