"""Launch tools: run gdb / pwntools scripts inside WSL2."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.security import is_unsafe_gdb_command
from gdb_mcp.sessions import DISCONNECTED, EXITED, RESERVED, Session

from ._common import audit_from, config_from, launcher_from, registry_from, resolve_any
from .registry import tool

#: gdb argv options that run a command / source a file before the inferior
#: starts. They reach the same debugger-escape surface as execute_command,
#: so they pass the same gate.
_EVAL_FLAGS = frozenset(
    {"-ex", "-e", "--eval-command", "-iex", "--init-eval-command"}
)
_FILE_FLAGS = frozenset({"-x", "--command", "-ix", "--init-command"})


def _unsafe_launch_arg(gdb_args: list[str] | None) -> str | None:
    """The first startup argument that escapes the debugger, if any.

    ``-x/--command`` sources an arbitrary file (equivalent to gdb's
    ``source``) and cannot be inspected here, so it is gated as a whole;
    inline eval flags are checked with the same abbreviation-aware rules
    as execute_command.
    """
    args = list(gdb_args or [])
    index = 0
    while index < len(args):
        flag, sep, inline = args[index].partition("=")
        if flag in _EVAL_FLAGS:
            if sep:
                command = inline
            elif index + 1 < len(args):
                command = args[index + 1]
                index += 1
            else:
                break
            if is_unsafe_gdb_command(command):
                return args[index]
        elif flag in _FILE_FLAGS:
            return args[index]
        index += 1
    return None


def _disconnected(session: Session) -> bool:
    return session.state == DISCONNECTED


def _with_attach(gdb_args: list[str] | None, attach_pid: int | None) -> list[str] | None:
    """Prepend ``-p PID`` so gdb attaches before the plugin loads."""
    if attach_pid is None:
        return gdb_args
    return ["-p", str(attach_pid)] + list(gdb_args or [])


@tool(core=True, capability="host")
async def launch_gdb(
    program: str | None = None,
    attach_pid: int | None = None,
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
    `gdb -ex run`). Use `attach_pid` instead of `program` to attach to a
    running Linux userland process (the plugin loads after the attach)."""
    if attach_pid is not None:
        if isinstance(attach_pid, bool) or not isinstance(attach_pid, int) or attach_pid < 1:
            raise GdbMcpError("BAD_PARAMS", "attach_pid must be a positive int")
        if program is not None:
            raise GdbMcpError(
                "BAD_PARAMS", "pass either program or attach_pid, not both"
            )
        if args:
            raise GdbMcpError(
                "BAD_PARAMS",
                "args only applies with program; omit them when attaching",
            )
        if run:
            raise GdbMcpError(
                "BAD_PARAMS",
                "run=True would restart the attached process; omit it",
            )
    cfg = config_from(ctx)
    gdb_args = _with_attach(gdb_args, attach_pid)
    if not cfg.allow_unsafe:
        unsafe = _unsafe_launch_arg(gdb_args)
        if unsafe is not None:
            audit_from(ctx).record("unsafe_command_blocked", command=unsafe)
            raise GdbMcpError(
                "UNSAFE_BLOCKED",
                "gdb startup argument %r can source/execute code outside "
                "the debugger; start with --allow-unsafe to allow it"
                % unsafe,
            )
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


@tool(core=True, capability="host")
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


@tool(capability="admin")
async def kill_session(
    force: bool = False,
    forget: bool = False,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """End a session. For gdb, the default detaches the plugin and keeps
    gdb (and the session record) alive, so a later re-hello revives the
    same session id. force=True terminates the gdb process tree;
    forget=True drops the record even when detaching. Script sessions are
    terminated and removed."""
    registry = registry_from(ctx)
    session = resolve_any(ctx, session_id)
    if session.kind == "gdb":
        if session.state == RESERVED:
            if session.launched:
                await launcher_from(ctx).pkill_marker(
                    session.session_id, force, distro=session.distro
                )
            registry.remove(session.session_id)
            return {
                "session_id": session.session_id,
                "detached": True,
                "killed": session.launched,
                "force": force,
                "forget": True,
                "record_kept": False,
                "log_file": session.log_file,
            }
        if session.writer is not None:
            await session.send_quit(kill_gdb=force)
            # the plugin closes the socket on shutdown: wait for that
            # transition rather than sampling for it
            await session.wait_for_state(_disconnected, 2.0)
        if force and session.launched:
            await launcher_from(ctx).pkill_marker(
                session.session_id, True, distro=session.distro
            )
        keep_record = not force and not forget
        if not keep_record:
            registry.remove(session.session_id)
        return {
            "session_id": session.session_id,
            "detached": True,
            "killed": force,
            "force": force,
            "forget": forget,
            "record_kept": keep_record,
            "log_file": session.log_file,
        }
    if not session.launched:
        raise GdbMcpError(
            "NOT_LAUNCHED",
            "session %r was not launched by this server; kill its process "
            "manually" % session.session_id,
        )
    await launcher_from(ctx).pkill_marker(
        session.session_id, force, distro=session.distro
    )
    registry.remove(session.session_id)
    return {
        "session_id": session.session_id,
        "detached": False,
        "killed": True,
        "force": force,
        "forget": True,
        "record_kept": False,
        "log_file": session.log_file,
    }
