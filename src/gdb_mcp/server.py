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
    analysis = app._analysis  # set before startup (see serve)
    yield {
        "registry": registry,
        "config": config,
        "analysis": analysis,
    }


def build_app(config: Config, registry: SessionRegistry, analysis=None) -> FastMCP:
    app = FastMCP(
        "gdb-mcp",
        lifespan=_lifespan,
        instructions=(
            "gdb-mcp v%s drives local Linux gdb sessions (pwndbg-aware) "
            "for binary exploitation. One-call stop inspection: "
            "continue_execution(wait=True, with_context=True) returns the "
            "stop reason plus registers/backtrace/disassembly in a single "
            "response; crash_report does deeper crash triage; triage_crash "
            "replays a crashing payload from a checkpoint and packages the "
            "full report as stored evidence; get_events surfaces events "
            "between calls. Pwn workflow: heap_bins for structured glibc "
            "bins (needs pwndbg), checkpoint(create/restore/diff) for "
            "state snapshots, batch_commands to run several gdb commands "
            "per round-trip, run_policy(kind=trace|heap_arm|fuzz_loop|"
            "minimize|bp_stats|...) to delegate bounded loops to the "
            "plugin so they run at native speed for a constant-size "
            "summary. export_session_script compiles the session into a "
            "replayable gdbscript. Static bridge: analyze_binary + "
            "decompile_function etc. when a Ghidra headless installation "
            "is available."
        )
        % __version__,
    )
    app._registry = registry  # type: ignore[attr-defined]
    app._config = config  # type: ignore[attr-defined]
    app._analysis = analysis  # type: ignore[attr-defined]
    register_all(app, registry, config)

    if config.observer_tokens:
        _install_observer_guards(app)

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


def _install_observer_guards(app: FastMCP) -> None:
    """D2: wrap every tool outside the observer allowlist so a
    read-only observer client gets a clean OBSERVER_READONLY error.
    Default-deny: tools registered later are observer-invisible until
    allowlisted in roles.OBSERVER_ALLOWED_TOOLS."""
    from gdb_mcp.errors import GdbMcpError
    from gdb_mcp.roles import CURRENT_ROLE, observer_allowed

    tools = app._tool_manager._tools
    for name, tool in list(tools.items()):
        if observer_allowed(name):
            continue
        original = tool.fn

        def guarded(*args, _original=original, _name=name, **kwargs):
            if CURRENT_ROLE.get() == "observer":
                raise GdbMcpError(
                    "OBSERVER_READONLY",
                    "tool %r is not available to observer clients" % _name,
                )
            return _original(*args, **kwargs)

        tool.fn = guarded


async def _serve_http(app: FastMCP, config: Config) -> None:
    """Run the streamable-HTTP transport behind the security middleware."""
    import uvicorn

    from gdb_mcp.http_hardening import SecurityHeadersMiddleware

    scheme = "https" if config.mcp_tls_cert else "http"
    log.info(
        "MCP streamable HTTP on %s://%s:%d/mcp (token %s)",
        scheme,
        config.mcp_host,
        config.mcp_port,
        "required" if config.token else "disabled",
    )
    hardened = SecurityHeadersMiddleware(
        app.streamable_http_app(),
        config.mcp_host,
        config.mcp_port,
        config.token,
        config.observer_tokens,
    )
    uvicorn_kwargs: dict = {}
    if config.mcp_tls_cert:
        uvicorn_kwargs["ssl_certfile"] = config.mcp_tls_cert
        uvicorn_kwargs["ssl_keyfile"] = config.mcp_tls_key
        if config.mcp_tls_client_ca:
            # E4: mutual TLS - the client must present a certificate
            # signed by this CA
            uvicorn_kwargs["ssl_ca_certs"] = config.mcp_tls_client_ca
            uvicorn_kwargs["ssl_cert_reqs"] = 2  # ssl.CERT_REQUIRED
    server = uvicorn.Server(
        uvicorn.Config(
            hardened,
            host=config.mcp_host,
            port=config.mcp_port,
            log_level="info",
            **uvicorn_kwargs,
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

    analysis = None
    try:
        from gdb_mcp.reverse.manager import AnalysisManager
    except Exception:  # pragma: no cover - broken optional module
        log.exception("static bridge unavailable")
    else:
        # the manager reads config.analysis_dir itself; auto-analyze is
        # off by default so no background work starts unprompted
        analysis = AnalysisManager(config)

    listener = PluginTcpListener(config, registry)
    await listener.start()
    gc_task = asyncio.create_task(registry.gc_loop())
    try:
        if config.mcp_transport:
            app = build_app(config, registry, analysis)
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
