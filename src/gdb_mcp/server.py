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
from gdb_mcp.events import EventBroker
from gdb_mcp.sessions import SessionRegistry
from gdb_mcp.tcp_listener import PluginTcpListener
from gdb_mcp.tools import register_all

log = logging.getLogger("gdb_mcp.server")


def build_app(config: Config, registry: SessionRegistry, analysis=None, audit=None) -> FastMCP:
    from gdb_mcp.audit import AuditLog, disabled

    if audit is None:
        audit = (
            AuditLog(config.log_dir / "audit.log", key=config.token)
            if config.audit_log
            else disabled()
        )
    server_ctx = ServerContext(
        config=config, registry=registry, analysis=analysis, audit=audit
    )

    @asynccontextmanager
    async def _lifespan(app: FastMCP):
        # the one DI channel: tools read registry/config/analysis/launcher
        # off this object (see gdb_mcp.context and tools._common)
        yield server_ctx

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


async def _serve_http(app: FastMCP, config: Config, audit=None) -> None:
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
        audit=audit,
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
    # one broker fans session lifecycle events to in-process subscribers
    # (the static-bridge AnalysisManager tracks sessions this way)
    broker = EventBroker()
    registry = SessionRegistry(config, events=broker)
    registry.enable_persistence(config.log_dir / "sessions.json")

    analysis = None
    try:
        from gdb_mcp.reverse.manager import AnalysisManager
    except Exception:  # pragma: no cover - broken optional module
        log.exception("static bridge unavailable")
    else:
        # the manager reads config.analysis_dir itself; auto-analyze is
        # off by default so no background work starts unprompted
        analysis = AnalysisManager(config, events=broker)

    # security audit log (hash-chained, separate from session journals)
    from gdb_mcp.audit import AuditLog, disabled

    audit = (
        AuditLog(config.log_dir / "audit.log", key=config.token)
            if config.audit_log
            else disabled()
    )

    listener = PluginTcpListener(config, registry, audit=audit)
    await listener.start()
    # stale-launch reaping: GC dropping (or shutdown leaving) a session
    # that never handshook must also terminate its process tree, or the
    # gdb leaks with no owner. Handshook sessions deliberately survive a
    # server restart (B1: re-hello revives them).
    from gdb_mcp.launcher import Launcher

    reaper = Launcher(config, registry)
    registry.on_reserved_drop = reaper.kill_stale
    # kernel sessions own a QEMU VM; the registry's final hook takes it
    # down when the session goes away for any reason
    from gdb_mcp.tools.experimental import drop_session_qemu

    registry.on_session_removed = drop_session_qemu
    gc_task = asyncio.create_task(registry.gc_loop())
    try:
        if config.mcp_transport:
            app = build_app(config, registry, analysis, audit=audit)
            if config.mcp_http:
                await _serve_http(app, config, audit=audit)
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
        # launches that never handshook have nothing to re-hello to:
        # terminate their process trees instead of leaking them
        try:
            killed = await reaper.terminate_all_reserved()
            if killed:
                log.info("terminated %d un-handshook session(s) at shutdown", killed)
        except Exception:  # pragma: no cover - best-effort teardown
            log.exception("shutdown sweep failed")
