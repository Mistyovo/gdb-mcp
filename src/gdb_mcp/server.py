"""FastMCP server wiring: tools + TCP listener + lifecycle."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

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
            "gdb-mcp v%s drives a local Linux gdb (possibly with pwndbg) "
            "for binary exploitation. Sessions are gdb processes connected "
            "via the in-gdb plugin. Typical crash-triage flow: "
            "continue_execution -> wait_for_stop -> crash_report."
        )
        % __version__,
    )
    app._registry = registry  # type: ignore[attr-defined]
    app._config = config  # type: ignore[attr-defined]
    register_all(app, registry, config)
    return app


async def serve(config: Config) -> None:
    """Run the full server: TCP listener for gdb plugins (+ GC loop) and,
    unless ``--no-mcp``, the stdio MCP transport."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    config.ensure_dirs()
    registry = SessionRegistry(config)
    listener = PluginTcpListener(config, registry)
    await listener.start()
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
        await listener.stop()
