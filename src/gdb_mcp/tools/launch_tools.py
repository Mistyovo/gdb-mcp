"""Launch tools: run gdb / pwntools scripts inside WSL2."""

from __future__ import annotations

import asyncio

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.launcher import Launcher
from gdb_mcp.sessions import DISCONNECTED, RESERVED

from ._common import config_from, registry_from, resolve_any, resolve_gdb


def register(app, registry, config) -> None:
    launcher = Launcher(config, registry)

    @app.tool()
    async def launch_gdb(
        program: str | None = None,
        args: list[str] | None = None,
        gdb_args: list[str] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        run: bool = False,
        distro: str | None = None,
        attach_timeout_ms: int = 30000,
        ctx: Context = None,
    ) -> dict:
        """Launch gdb with the MCP plugin loaded inside WSL2 (background
        process, log captured to a file). `program` may be a Windows or WSL
        path; the session registers itself when the plugin connects. With
        `run=True`, the inferior is started immediately (equivalent to
        `gdb -ex run`)."""
        cfg = config_from(ctx)
        if distro:
            launcher.config.wsl_distro = distro
        session = await launcher.launch_gdb(
            program=program,
            args=args,
            gdb_args=gdb_args,
            cwd=cwd,
            env=env,
            run=run,
            timeout_ms=attach_timeout_ms or cfg.attach_timeout_ms,
        )
        return {
            "session_id": session.session_id,
            "state": session.state,
            "log_file": session.log_file,
            "distro": await launcher.distro(),
            "note": (
                "plugin connected" if session.state != RESERVED
                else "hello not received yet; the plugin retries in the background"
            ),
        }

    @app.tool()
    async def launch_script(
        script: str,
        python: str = "python3",
        args: list[str] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        distro: str | None = None,
        attach_timeout_ms: int = 30000,
        ctx: Context = None,
    ) -> dict:
        """Launch a Python (typically pwntools) script inside WSL2. If the
        script starts gdb with the MCP plugin loaded (via gdb_args/gdbscript),
        the new gdb session id is returned once it registers."""
        cfg = config_from(ctx)
        if distro:
            launcher.config.wsl_distro = distro
        script_session, gdb_session = await launcher.launch_script(
            script=script,
            python=python,
            args=args,
            cwd=cwd,
            env=env,
            timeout_ms=attach_timeout_ms or cfg.attach_timeout_ms,
        )
        result = {
            "script_session_id": script_session.session_id,
            "gdb_session_id": gdb_session.session_id if gdb_session else None,
            "log_file": script_session.log_file,
        }
        if gdb_session is None:
            result["note"] = (
                "no gdb session appeared; script log tail: %s"
                % launcher.log_tail(script_session.log_file)
            )
        return result

    @app.tool()
    async def kill_session(
        force: bool = False,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """Kill a session: detach the plugin (gdb stays alive) or, with
        force=True, quit gdb / terminate the launched process tree."""
        registry = registry_from(ctx)
        session = resolve_any(ctx, session_id)
        if session.kind == "gdb":
            if session.state != RESERVED and session.writer is not None:
                await session.send_quit(kill_gdb=force)
                for _ in range(20):
                    if session.state == DISCONNECTED:
                        break
                    await asyncio.sleep(0.1)
        if session.launched:
            await launcher.pkill_marker(session.session_id, force)
        elif session.kind == "script":
            raise GdbMcpError(
                "NOT_LAUNCHED",
                "session %r was not launched by this server; kill its process "
                "manually" % session.session_id,
            )
        registry.remove(session.session_id)
        return {
            "session_id": session.session_id,
            "killed": True,
            "force": force,
            "log_file": session.log_file,
        }
