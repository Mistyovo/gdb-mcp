"""Launch gdb / pwntools scripts inside WSL2 from the Windows-side server.

Design notes:

* Commands run as ``wsl.exe -d <distro> -- bash -lc '<script>'``; stdout of
  the launched process goes straight to a log file (no pipes, no deadlock).
* The launched process gets ``argv[0]`` renamed to ``gdbmcp_<session_id>``
  via ``exec -a`` so kill_session can ``pkill -f`` it from inside WSL.
* ``wsl.exe`` emits UTF-16-LE on its piped stdout — distro parsing decodes
  accordingly and filters out non-interactive distros (docker-desktop*).
"""

from __future__ import annotations

import asyncio
import logging
import re
import subprocess
from pathlib import Path

from gdb_mcp.config import Config
from gdb_mcp.errors import LaunchError
from gdb_mcp.output import tail_text_file
from gdb_mcp.sessions import (
    EXITED,
    RESERVED,
    RUNNING,
    Session,
    SessionRegistry,
    first_to_settle,
    plugin_token_for,
)
from gdb_mcp.wsl import WslError, list_distros, win_to_wsl

log = logging.getLogger("gdb_mcp.launcher")

_PLUGIN_WIN_PATH = (
    Path(__file__).resolve().parent / "plugin" / "gdb_mcp_plugin.py"
)

_MARKER_PREFIX = "gdbmcp_"

#: where the mounted plugin lives inside docker launcher containers
DOCKER_PLUGIN_PATH = "/opt/gdb-mcp/gdb_mcp_plugin.py"

#: the plugin's own configuration: a caller-supplied env must never be able
#: to redirect a launched gdb to another session/port or lift a limit
_RESERVED_PLUGIN_ENV = frozenset(
    {
        "GDB_MCP_SESSION_ID",
        "GDB_MCP_PORT",
        "GDB_MCP_TOKEN",
        "GDB_MCP_SESSION_TOKEN",
        "GDB_MCP_EVAL_OUTPUT_LIMIT",
        "GDB_MCP_MAX_MEM_READ",
        "GDB_MCP_MAX_ASYNC_LINE",
        "GDB_MCP_ALLOW_UNSAFE",
    }
)


# --- pure helpers (unit-testable) ------------------------------------------


def build_plugin_env(
    config: Config, session_id: str, plugin_token: str | None, user_env: dict | None
) -> dict:
    """The environment a launched plugin connects with: the caller's vars
    plus the reserved plugin ones (which always win)."""
    env = {k: v for k, v in (user_env or {}).items() if k not in _RESERVED_PLUGIN_ENV}
    env.update(
        {
            "GDB_MCP_SESSION_ID": session_id,
            "GDB_MCP_PORT": str(config.port),
            "GDB_MCP_EVAL_OUTPUT_LIMIT": str(config.eval_output_limit),
            "GDB_MCP_MAX_MEM_READ": str(config.max_mem_read),
            "GDB_MCP_MAX_ASYNC_LINE": str(config.max_async_line),
        }
    )
    if plugin_token:
        # E4: session-scoped token; the master never reaches the child
        env["GDB_MCP_SESSION_TOKEN"] = plugin_token
    if config.allow_unsafe:
        env["GDB_MCP_ALLOW_UNSAFE"] = "1"
    return env


def bash_quote(s: str) -> str:
    """Single-quote a string for embedding in a bash -lc script."""
    return "'" + str(s).replace("'", "'\\''") + "'"


_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def build_bash_command(
    argv: list[str],
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    marker: str | None = None,
) -> str:
    """Assemble the payload for ``bash -lc``: env exports, cd, then the
    command (with argv[0] renamed to ``marker`` via ``exec -a``).

    Env keys are interpolated into shell syntax and therefore validated
    against the POSIX name charset — values are single-quote escaped,
    keys must be, or the script would allow command injection through
    the launch tools' ``env`` parameter."""
    parts = []
    for key, value in (env or {}).items():
        if value is None:
            continue
        if not _ENV_KEY_RE.match(key):
            raise ValueError(
                "invalid environment variable name: %r" % key[:64]
            )
        parts.append("export %s=%s" % (key, bash_quote(value)))
    if cwd:
        parts.append("cd %s" % bash_quote(cwd))
    cmd = " ".join(bash_quote(a) for a in argv)
    if marker:
        cmd = "exec -a %s %s" % (bash_quote(marker), cmd)
    parts.append(cmd)
    return " && ".join(parts)


def build_pkill_command(session_id: str, force: bool) -> str:
    """bash snippet killing the process tree of a launched session by its
    argv[0] marker."""
    marker = _MARKER_PREFIX + session_id
    if force:
        return "pkill -9 -f %s || true" % bash_quote(marker)
    return "pkill -TERM -f %s || true; sleep 3; pkill -9 -f %s || true" % (
        bash_quote(marker),
        bash_quote(marker),
    )


def _launch_settled(session: Session) -> bool:
    """A launch wait ends when the plugin registered or the process died."""
    return session.state != RESERVED or session.proc_returncode is not None


def _plugin_arrived(session: Session) -> bool:
    return session.state != RESERVED


def _is_exited(session: Session) -> bool:
    return session.state == EXITED


def build_gdb_argv(
    plugin_wsl_path: str,
    program: str | None,
    args: list[str] | None,
    gdb_args: list[str] | None,
    run: bool,
) -> list[str]:
    """Assemble the gdb command line for a launch (WSL paths)."""
    argv = ["gdb", "-q"]
    argv += list(gdb_args or [])
    argv += ["-x", plugin_wsl_path]
    if run:
        argv += ["-ex", "run"]
    if program:
        argv += ["--args", program] + list(args or [])
    return argv


def build_ssh_argv(host: str, remote_command: str) -> list[str]:
    """argv running ``remote_command`` through a single shell on ``host``."""
    return [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        host,
        remote_command,
    ]


def build_docker_run_argv(
    image: str,
    session_id: str,
    bash_cmd: str,
    cwd: str | None,
    plugin_host_path: str | None,
) -> list[str]:
    """``docker run`` argv for an ephemeral debugging container.

    SYS_PTRACE + a relaxed seccomp profile are the minimum for
    ptrace-based debugging; the container is named after the session so
    termination is a single ``docker kill``.
    """
    argv = [
        "docker",
        "run",
        "--rm",
        "--name",
        _MARKER_PREFIX + session_id,
        "--cap-add=SYS_PTRACE",
        "--security-opt",
        "seccomp=unconfined",
    ]
    if plugin_host_path:
        argv += ["-v", "%s:%s:ro" % (plugin_host_path, DOCKER_PLUGIN_PATH)]
    if cwd:
        argv += ["-v", "%s:%s" % (cwd, cwd), "-w", cwd]
    argv += [image, "bash", "-lc", bash_cmd]
    return argv


def build_terminate_argv(
    launcher: str,
    session_id: str,
    force: bool,
    distro: str | None = None,
    ssh_host: str | None = None,
) -> list[str]:
    """argv that terminates a launched session for the given backend."""
    if launcher == "docker":
        return ["docker", "kill", _MARKER_PREFIX + session_id]
    cmd = build_pkill_command(session_id, force)
    if launcher == "wsl":
        return ["wsl.exe", "-d", distro, "--", "bash", "-lc", cmd]
    if launcher == "native":
        return ["bash", "-lc", cmd]
    return build_ssh_argv(ssh_host, cmd)


# --- the launcher -----------------------------------------------------------


class Launcher:
    def __init__(self, config: Config, registry: SessionRegistry):
        self.config = config
        self.registry = registry
        self._distro_cache: str | None = None

    # -- distro -------------------------------------------------------------

    async def distro(self, override: str | None = None) -> str:
        """The WSL distro to run in: an explicit override, then the
        configured one, then the first interactive distro WSL reports
        (cached after the first query, which shells out to wsl.exe)."""
        if self.config.launcher != "wsl":
            raise LaunchError(
                "the WSL distro only applies to the wsl launcher backend"
            )
        configured = override or self.config.wsl_distro
        if configured:
            return configured
        if self._distro_cache:
            return self._distro_cache
        try:
            names = await list_distros(self.config.launch_timeout_ms / 1000.0)
        except WslError as exc:
            raise LaunchError(str(exc)) from exc
        if not names:
            raise LaunchError(
                "no WSL distro found (wsl.exe -l -q); install one or set "
                "GDB_MCP_WSL_DISTRO"
            )
        self._distro_cache = names[0]
        log.info("WSL distro: %s (candidates: %s)", names[0], names)
        return names[0]

    # -- launch -------------------------------------------------------------

    def plugin_wsl_path(self) -> str:
        if self.config.plugin_wsl_path:
            return self.config.plugin_wsl_path
        return win_to_wsl(str(_PLUGIN_WIN_PATH))

    async def _spawn(
        self,
        argv: list[str],
        env: dict[str, str],
        cwd_wsl: str | None,
        session_id: str,
        log_file: Path,
        kind: str,
        marker: bool,
        distro_override: str | None = None,
    ) -> Session:
        launcher = self.config.launcher
        if launcher == "docker":
            argv = [
                DOCKER_PLUGIN_PATH if a == self.plugin_wsl_path() else a
                for a in argv
            ]
        bash_cmd = build_bash_command(
            argv,
            env,
            cwd_wsl,
            marker=_MARKER_PREFIX + session_id if marker else None,
        )
        if launcher == "wsl":
            distro = await self.distro(distro_override)
            exec_argv = ["wsl.exe", "-d", distro, "--", "bash", "-lc", bash_cmd]
        elif launcher == "native":
            exec_argv = ["bash", "-lc", bash_cmd]
        elif launcher == "docker":
            exec_argv = build_docker_run_argv(
                self.config.docker_image,
                session_id,
                bash_cmd,
                cwd_wsl,
                self.config.plugin_wsl_path or str(_PLUGIN_WIN_PATH),
            )
        else:  # ssh
            exec_argv = build_ssh_argv(self.config.ssh_host, bash_cmd)
        session = self.registry.reserve(
            session_id, kind=kind, log_file=str(log_file)
        )
        session.distro = (
            await self.distro(distro_override) if launcher == "wsl" else None
        )
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            log_fh = open(log_file, "w", encoding="utf-8", errors="replace")
            try:
                proc = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(
                        *exec_argv,
                        stdout=log_fh,
                        stderr=asyncio.subprocess.STDOUT,
                        stdin=(
                            asyncio.subprocess.PIPE
                            if kind == "gdb"
                            else asyncio.subprocess.DEVNULL
                        ),
                        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                        if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP")
                        else 0,
                    ),
                    self.config.launch_timeout_ms / 1000.0,
                )
            finally:
                log_fh.close()
        except (OSError, asyncio.TimeoutError) as exc:
            self.registry.remove(session_id)
            raise LaunchError("failed to start %s in WSL: %s" % (kind, exc)) from exc
        session.proc = proc
        session.proc_task = asyncio.create_task(self._watch_process(session))
        session.update_seen()
        if kind != "gdb":
            session.set_state(RUNNING)  # scripts never hello
        log.info(
            "launched %s session %s via %s launcher (log: %s)",
            kind,
            session_id,
            launcher,
            log_file,
        )
        return session

    async def _watch_process(self, session: Session) -> None:
        """Mirror subprocess completion without blocking the MCP event loop."""
        try:
            returncode = await session.proc.wait()
        except asyncio.CancelledError:
            return
        await session.note_process_exit(returncode)

    async def launch_gdb(
        self,
        program: str | None,
        args: list[str] | None,
        gdb_args: list[str] | None,
        cwd: str | None,
        env: dict[str, str] | None,
        run: bool,
        timeout_ms: int,
        distro: str | None = None,
    ) -> Session:
        """Launch gdb with the plugin loaded; returns once the plugin's
        hello has been registered (or after the timeout, with the session
        left in RESERVED state — the plugin's retry loop self-heals)."""
        session_id = self.registry.new_session_id()
        wsl_cwd = win_to_wsl(cwd) if cwd else None
        program_wsl = None
        if program:
            program_wsl = win_to_wsl(program)
        plugin = self.plugin_wsl_path()
        argv = build_gdb_argv(plugin, program_wsl, args, gdb_args, run)
        env_vars = build_plugin_env(
            self.config,
            session_id,
            plugin_token_for(self.config, session_id, launched=True),
            env,
        )
        log_file = self.config.log_dir / ("%s.log" % session_id)
        session = await self._spawn(
            argv,
            env_vars,
            wsl_cwd,
            session_id,
            log_file,
            kind="gdb",
            marker=True,
            distro_override=distro,
        )
        # the plugin's hello or the process dying are both state changes:
        # wait for one instead of polling for it
        await session.wait_for_state(_launch_settled, max(0.1, timeout_ms / 1000.0))
        if session.state == RESERVED and session.proc_returncode is not None:
            raise LaunchError(
                "gdb exited during startup (code %s); log: %s"
                % (session.proc_returncode, log_file)
            )
        return session

    async def launch_script(
        self,
        script: str,
        python: str,
        args: list[str] | None,
        cwd: str | None,
        env: dict[str, str] | None,
        timeout_ms: int,
        distro: str | None = None,
    ) -> tuple[Session, Session | None]:
        """Launch a (typically pwntools) script and wait for a *new* gdb
        session to register itself (the script's own gdb carrying the
        plugin). Return as soon as either gdb registers or the script exits.
        Returns (script_session, gdb_session_or_None)."""
        session_id = self.registry.new_session_id()
        gdb_session_id = self.registry.new_session_id(exclude={session_id})
        wsl_cwd = win_to_wsl(cwd) if cwd else None
        try:
            script_wsl = win_to_wsl(script)
        except ValueError:
            raise ValueError(
                "script must be an absolute file path (a Windows drive path "
                "or a WSL path); inline Python code is not supported: %r" % script
            ) from None
        argv = [python, "-u", script_wsl] + list(args or [])
        log_file = self.config.log_dir / ("%s.log" % session_id)
        # The pwntools-spawned gdb inherits these and binds to the
        # reservation created here; its credential is scoped to that
        # reserved id, so the script cannot redirect it elsewhere.
        gdb_token = plugin_token_for(self.config, gdb_session_id, launched=True)
        env_vars = build_plugin_env(self.config, gdb_session_id, gdb_token, env)
        gdb_session = self.registry.reserve(
            gdb_session_id,
            kind="gdb",
            launched=False,
            token=gdb_token,
        )
        try:
            session = await self._spawn(
                argv,
                env_vars,
                wsl_cwd,
                session_id,
                log_file,
                kind="script",
                marker=True,
                distro_override=distro,
            )
            await first_to_settle(
                [(gdb_session, _plugin_arrived), (session, _is_exited)],
                max(0.1, timeout_ms / 1000.0),
            )
            return (session, gdb_session) if gdb_session.state != RESERVED else (
                session,
                None,
            )
        finally:
            if gdb_session.state == RESERVED:
                self.registry.remove(gdb_session_id)

    # -- kill ----------------------------------------------------------------

    async def pkill_marker(
        self, session_id: str, force: bool, distro: str | None = None
    ) -> None:
        argv = build_terminate_argv(
            self.config.launcher,
            session_id,
            force,
            distro=distro,
            ssh_host=self.config.ssh_host,
        )
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except OSError as exc:
            raise LaunchError("failed to terminate session %s: %s" % (session_id, exc)) from exc
        try:
            await asyncio.wait_for(proc.wait(), 15)
        except asyncio.TimeoutError:
            log.warning("pkill for %s timed out", session_id)

    def log_tail(self, log_file: str | None, lines: int = 20) -> str:
        if not log_file:
            return ""
        try:
            content, _ = tail_text_file(log_file, lines=lines)
        except OSError:
            return ""
        return content
