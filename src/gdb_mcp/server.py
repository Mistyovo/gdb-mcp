"""FastMCP server wiring: tools + TCP listener + lifecycle."""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager, suppress

from mcp.server.fastmcp import FastMCP

from gdb_mcp import __version__
from gdb_mcp.campaign import campaign_summary
from gdb_mcp.config import Config
from gdb_mcp.context import ServerContext
from gdb_mcp.sessions import SessionRegistry
from gdb_mcp.tcp_listener import PluginTcpListener
from gdb_mcp.tools import register_all

log = logging.getLogger("gdb_mcp.server")


def build_app(config: Config, registry: SessionRegistry) -> FastMCP:
    server_ctx = ServerContext(config=config, registry=registry)

    @asynccontextmanager
    async def _lifespan(app: FastMCP):
        yield server_ctx

    app = FastMCP(
        "gdb-mcp",
        lifespan=_lifespan,
        instructions=(
            "gdb-mcp v%s drives local Linux userland gdb sessions "
            "(pwndbg-aware). Start with launch_gdb(program=...) or "
            "launch_gdb(attach_pid=...), or launch_script for pwntools. "
            "One-call stop inspection: continue_execution(wait=True, "
            "with_context=True); deeper triage/replay: crash_report; "
            "missed events: get_events. Pwn workflow: heap_bins (pwndbg), "
            "heap_chunk (no pwndbg), checkpoint(create/restore/diff), "
            "run_policy(trace|heap_arm|heap_read|heap_disarm|fuzz_loop|"
            "crash_check|minimize|bp_stats|verify_pc_control), campaign "
            "(state + cyclic oracle + protections), send_input/read_output "
            "for inferior stdio, and export_session_script."
        )
        % __version__,
    )
    register_all(app, server_ctx)

    @app.resource("gdb://campaign/{session_id}")
    def campaign_resource(session_id: str) -> str:
        """Read-only view of a session's exploit-campaign state."""
        session = server_ctx.registry.get(session_id)
        payload = {
            "session_id": session.session_id,
            "state": session.state,
            "campaign": session.campaign,
            "summary": campaign_summary(session.campaign),
        }
        return json.dumps(payload, ensure_ascii=False, indent=1)

    return app


async def serve(config: Config) -> None:
    """Run the full server: TCP listener for gdb plugins (+ GC loop) and
    the stdio MCP transport."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    config.ensure_dirs()
    registry = SessionRegistry(config)
    registry.enable_persistence(config.log_dir / "sessions.json")

    listener = PluginTcpListener(config, registry)
    await listener.start()
    from gdb_mcp.launcher import Launcher

    reaper = Launcher(config, registry)
    registry.on_reserved_drop = reaper.kill_stale
    gc_task = asyncio.create_task(registry.gc_loop())
    try:
        if config.mcp_transport:
            app = build_app(config, registry)
            await app.run_stdio_async()
        else:
            log.info(
                "TCP-only mode: waiting for gdb plugin connections on %s:%d "
                "(Ctrl-C to exit)",
                config.host_bind,
                config.port,
            )
            await asyncio.Event().wait()
    finally:
        gc_task.cancel()
        with suppress(asyncio.CancelledError):
            await gc_task
        await listener.stop()
        try:
            killed = await reaper.terminate_all_reserved()
            if killed:
                log.info("terminated %d un-handshook session(s) at shutdown", killed)
        except Exception:  # pragma: no cover - best-effort teardown
            log.exception("shutdown sweep failed")
