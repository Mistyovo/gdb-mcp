"""Launch tools: run gdb / pwntools scripts inside WSL2."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.sessions import DISCONNECTED, EXITED, RESERVED, Session

from ._common import config_from, launcher_from, registry_from, resolve_any
from .registry import tool


def _disconnected(session: Session) -> bool:
    return session.state == DISCONNECTED


@tool(core=True)
async def launch_gdb(
    program: str | None = None,
    args: list[str] | None = None,
    gdb_args: list[str] | None = None,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    run: bool = False,
    distro: str | None = None,
    attach_timeout_ms: int | None = None,
    ctx: Context = None,
) -> dict:
    """Launch gdb with the MCP plugin loaded inside WSL2 (background
    process, log captured to a file). `program` may be a Windows or WSL
    path; the session registers itself when the plugin connects. With
    `run=True`, the inferior is started immediately (equivalent to
    `gdb -ex run`)."""
    cfg = config_from(ctx)
    session = await launcher_from(ctx).launch_gdb(
        program=program,
        args=args,
        gdb_args=gdb_args,
        cwd=cwd,
        env=env,
        run=run,
        timeout_ms=(
            cfg.attach_timeout_ms
            if attach_timeout_ms is None
            else attach_timeout_ms
        ),
        distro=distro,
    )
    return {
        "session_id": session.session_id,
        "state": session.state,
        "log_file": session.log_file,
        "distro": session.distro,
        "note": (
            "plugin connected" if session.state != RESERVED
            else "hello not received yet; the plugin retries in the background"
        ),
    }


@tool(core=True)
async def launch_script(
    script: str,
    python: str = "python3",
    args: list[str] | None = None,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    distro: str | None = None,
    attach_timeout_ms: int | None = None,
    ctx: Context = None,
) -> dict:
    """Launch a Python (typically pwntools) script inside WSL2. `script`
    must be an absolute Windows or WSL file path; inline code is not
    supported. If the script starts gdb with the MCP plugin loaded (via
    gdb_args/gdbscript), the new gdb session id is returned once it
    registers. A script that exits without gdb returns immediately with
    its state, return code, and log tail."""
    cfg = config_from(ctx)
    launcher = launcher_from(ctx)
    script_session, gdb_session = await launcher.launch_script(
        script=script,
        python=python,
        args=args,
        cwd=cwd,
        env=env,
        timeout_ms=(
            cfg.attach_timeout_ms
            if attach_timeout_ms is None
            else attach_timeout_ms
        ),
        distro=distro,
    )
    result = {
        "script_session_id": script_session.session_id,
        "script_state": script_session.state,
        "script_returncode": script_session.proc_returncode,
        "gdb_session_id": gdb_session.session_id if gdb_session else None,
        "log_file": script_session.log_file,
    }
    if gdb_session is None:
        if script_session.state == EXITED:
            status = "script exited (code %s) without starting gdb" % (
                script_session.proc_returncode,
            )
        else:
            status = (
                "no gdb session appeared before the attach timeout; "
                "script is still running"
            )
        result["note"] = (
            "%s; script log tail: %s"
            % (status, launcher.log_tail(script_session.log_file))
        )
    return result


@tool()
async def kill_session(
    force: bool = False,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """End a session. For gdb, the default detaches the plugin and
    leaves gdb running; force=True also terminates gdb. Script sessions
    are terminated gracefully by default or killed with force=True."""
    registry = registry_from(ctx)
    session = resolve_any(ctx, session_id)
    if session.kind == "gdb":
        if session.state != RESERVED and session.writer is not None:
            await session.send_quit(kill_gdb=force)
            # the plugin closes the socket on shutdown: wait for that
            # transition rather than sampling for it
            await session.wait_for_state(_disconnected, 2.0)
    should_kill_process = session.kind == "script" or force
    if session.launched and should_kill_process:
        await launcher_from(ctx).pkill_marker(
            session.session_id, force, distro=session.distro
        )
    elif session.kind == "script":
        raise GdbMcpError(
            "NOT_LAUNCHED",
            "session %r was not launched by this server; kill its process "
            "manually" % session.session_id,
        )
    registry.remove(session.session_id)
    return {
        "session_id": session.session_id,
        "detached": session.kind == "gdb",
        "killed": should_kill_process,
        "force": force,
        "log_file": session.log_file,
    }
