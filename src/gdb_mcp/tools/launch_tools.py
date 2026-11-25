"""Launch and session-termination tools."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.security import is_unsafe_gdb_command
from gdb_mcp.sessions import DISCONNECTED, EXITED, RESERVED, Session

from ._common import config_from, launcher_from, registry_from, resolve_any
from .registry import tool

_EVAL_FLAGS = frozenset(
    {"-ex", "-e", "--eval-command", "-iex", "--init-eval-command"}
)
_FILE_FLAGS = frozenset({"-x", "--command", "-ix", "--init-command"})


def _unsafe_launch_arg(gdb_args: list[str] | None) -> str | None:
    """The first startup argument that escapes the debugger, if any."""
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


def _termination(
    session: Session, force: bool, *, always: bool = False, had_writer: bool | None = None
) -> dict:
    """Explicit close semantics instead of one ambiguous "killed" flag."""
    connected = session.writer is not None if had_writer is None else had_writer
    if always or (force and session.launched):
        return {
            "process_termination": "terminate_requested",
            "termination_note": (
                "termination of the launched process tree was requested; "
                "this result does not confirm that gdb has exited"
            ),
        }
    if force and not connected and not session.launched:
        return {
            "process_termination": "record_only",
            "termination_note": (
                "no live plugin connection and the gdb was not launched by "
                "this server; only the session record changed"
            ),
        }
    if force:
        return {
            "process_termination": "terminate_requested_via_plugin",
            "termination_note": (
                "the attached gdb was asked to quit through the plugin; it "
                "was not launched by this server, so verify the process yourself"
            ),
        }
    return {
        "process_termination": "detach_only",
        "termination_note": (
            "plugin detached; gdb and the inferior keep running; pass "
            "force=True to request termination"
        ),
    }


def _with_attach(gdb_args: list[str] | None, attach_pid: int | None) -> list[str] | None:
    if attach_pid is None:
        return gdb_args
    return ["-p", str(attach_pid)] + list(gdb_args or [])


@tool(core=True, capability="host")
async def launch_gdb(
    program: str | None = None,
    attach_pid: int | None = None,
    script: str | None = None,
    python: str = "python3",
    args: list[str] | None = None,
    gdb_args: list[str] | None = None,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    run: bool = False,
    stdio: str | None = None,
    distro: str | None = None,
    attach_timeout_ms: int | None = None,
    ctx: Context = None,
) -> dict:
    """Launch gdb (with MCP plugin), attach to a PID, or run a pwntools
    Python script. Pass one of:
    - `program`: binary path (`run=True` to start immediately,
      `stdio="pty"` to bind a pty for `inferior_io`).
    - `attach_pid`: attach to a running userland PID.
    - `script`: absolute path to a pwntools script (returns
      `script_session_id` + `gdb_session_id`)."""
    if script is not None:
        if program is not None or attach_pid is not None:
            raise GdbMcpError(
                "BAD_PARAMS", "pass only one of program, attach_pid, or script"
            )
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
            result["note"] = "%s; script log tail: %s" % (
                status,
                launcher.log_tail(script_session.log_file),
            )
        return result

    if stdio not in (None, "pty"):
        raise GdbMcpError("BAD_PARAMS", "stdio must be None or 'pty'")
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
        run=run and stdio != "pty",
        timeout_ms=(
            cfg.attach_timeout_ms
            if attach_timeout_ms is None
            else attach_timeout_ms
        ),
        distro=distro,
    )
    io_info = None
    if stdio == "pty" and session.state != RESERVED:
        io_info = await session.request("io_setup", {}, timeout=cfg.request_timeout)
        if run:
            await session.request(
                "eval", {"command": "run"}, timeout=cfg.request_timeout
            )
    connected = session.state != RESERVED
    result = {
        "session_id": session.session_id,
        "state": session.state,
        "plugin_connected": connected,
        "log_file": session.log_file,
        "distro": session.distro,
        "note": (
            "plugin connected" if connected
            else "hello not received yet; the plugin retries in the background"
        ),
    }
    if not connected:
        if session.proc_returncode is not None:
            result["diagnosis"] = (
                "gdb exited (code %s) before the plugin connected; inspect log_file"
                % session.proc_returncode
            )
        else:
            result["diagnosis"] = (
                "gdb is running but the plugin has not connected; check that "
                "gdb loaded the plugin (init files, Python support) and that "
                "%s:%d is reachable from gdb's namespace"
                % (cfg.host_bind, cfg.port)
            )
    if io_info is not None:
        result["io"] = io_info
    return result


@tool(core=True, capability="admin")
async def kill_session(
    force: bool = False,
    forget: bool = False,
    session_id: str | None = None,
    ctx: Context = None,
) -> dict:
    """End a session. Default detaches the plugin and keeps gdb/record
    alive; `force=True` requests termination of the gdb process tree
    (launched sessions) or asks an attached gdb to quit; `forget=True`
    also drops the record. The result says whether termination was
    requested; it does not confirm that the process exited."""
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
                "launched": session.launched,
                "log_file": session.log_file,
                **_termination(session, force, always=session.launched),
            }
        if session.writer is not None:
            had_writer = True
            await session.send_quit(kill_gdb=force)
            await session.wait_for_state(_disconnected, 2.0)
        else:
            had_writer = False
        if force and session.launched:
            await launcher_from(ctx).pkill_marker(
                session.session_id, True, distro=session.distro
            )
        keep_record = not forget
        if not keep_record:
            registry.remove(session.session_id)
        return {
            "session_id": session.session_id,
            "detached": True,
            "killed": force,
            "force": force,
            "forget": forget,
            "record_kept": keep_record,
            "launched": session.launched,
            "log_file": session.log_file,
            **_termination(session, force, had_writer=had_writer),
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
        "launched": session.launched,
        "log_file": session.log_file,
        **_termination(session, force, always=True),
    }
