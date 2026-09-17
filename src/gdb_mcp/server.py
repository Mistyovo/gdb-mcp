"""FastMCP server wiring: tools + TCP listener + lifecycle."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, suppress

from mcp.server.fastmcp import FastMCP

from gdb_mcp import __version__
from gdb_mcp.config import Config
from gdb_mcp.sessions import SessionRegistry
from gdb_mcp.tcp_listener import PluginTcpListener
from gdb_mcp.tools import register_all

log = logging.getLogger("gdb_mcp.server")


@asynccontextmanager
async def _lifespan(app: FastMCP):
    registry = app._registry  # set before startup (see serve)
    config = app._config
    yield {"registry": registry, "config": config}


def build_app(config: Config, registry: SessionRegistry) -> FastMCP:
    app = FastMCP(
        "gdb-mcp",
        lifespan=_lifespan,
        instructions=(
            "gdb-mcp v%s drives local Linux gdb sessions (pwndbg-aware) "
            "for binary exploitation. One-call stop inspection: "
            "continue_execution(wait=True, with_context=True) returns the "
            "stop reason plus registers/backtrace/disassembly in a single "
            "response; crash_report does deeper crash triage; get_events "
            "surfaces events between calls. Pwn workflow: heap_bins for "
            "structured glibc bins (needs pwndbg), checkpoint(create/"
            "restore/diff) for state snapshots, batch_commands to run "
            "several gdb commands per round-trip. export_session_script "
            "compiles the session into a replayable gdbscript."
        )
        % __version__,
    )
    app._registry = registry  # type: ignore[attr-defined]
    app._config = config  # type: ignore[attr-defined]
    register_all(app, registry, config)

    @app.resource("gdb://campaign/{session_id}")
    def campaign_resource(session_id: str) -> str:
        """Read-only view of a session's exploit-campaign state."""
        import json

        from gdb_mcp.campaign import campaign_summary

        session = registry.get(session_id)
        payload = {
            "session_id": session.session_id,
            "state": session.state,
            "campaign": session.campaign,
            "summary": campaign_summary(session.campaign),
        }
        return json.dumps(payload, ensure_ascii=False, indent=1)

    return app


async def _serve_http(app: FastMCP, config: Config) -> None:
    """Run the streamable-HTTP transport behind the security middleware."""
    import uvicorn

    from gdb_mcp.http_hardening import SecurityHeadersMiddleware

    log.info(
        "MCP streamable HTTP on http://%s:%d/mcp (token %s)",
        config.mcp_host,
        config.mcp_port,
        "required" if config.token else "disabled",
    )
    hardened = SecurityHeadersMiddleware(
        app.streamable_http_app(), config.mcp_host, config.mcp_port, config.token
    )
    server = uvicorn.Server(
        uvicorn.Config(
            hardened,
            host=config.mcp_host,
            port=config.mcp_port,
            log_level="info",
        )
    )
    await server.serve()


async def serve(config: Config) -> None:
    """Run the full server: TCP listener for gdb plugins (+ GC loop) and
    the MCP transport (stdio by default, or hardened streamable HTTP)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    config.ensure_dirs()
    registry = SessionRegistry(config)
    registry.enable_persistence(config.log_dir / "sessions.json")
    listener = PluginTcpListener(config, registry)
    await listener.start()
    gc_task = asyncio.create_task(registry.gc_loop())
    try:
        if config.mcp_transport:
            app = build_app(config, registry)
            if config.mcp_http:
                await _serve_http(app, config)
            else:
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
