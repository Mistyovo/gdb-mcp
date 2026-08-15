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
import time
from pathlib import Path

from gdb_mcp.config import Config
from gdb_mcp.errors import LaunchError
from gdb_mcp.output import tail_text_file
from gdb_mcp.sessions import EXITED, RESERVED, RUNNING, Session, SessionRegistry

log = logging.getLogger("gdb_mcp.launcher")

#: distros that are not interactive targets
_NON_INTERACTIVE_PREFIXES = ("docker-desktop",)

_PLUGIN_WIN_PATH = (
    Path(__file__).resolve().parent / "plugin" / "gdb_mcp_plugin.py"
)

_MARKER_PREFIX = "gdbmcp_"


# --- pure helpers (unit-testable) ------------------------------------------


def win_to_wsl(path: str) -> str:
    """Convert a Windows path to its WSL ``/mnt/...`` form.

    ``C:\\Users\\x\\y`` -> ``/mnt/c/Users/x/y``. Paths that already look
    like absolute WSL paths (starting with ``/``) pass through unchanged.
    UNC paths and relative paths raise :class:`ValueError`.
    """
    p = str(path).strip()
    if p.startswith("/"):
        return p  # already a WSL path
    m = re.match(r"^([a-zA-Z]):[\\/](.*)$", p)
    if not m:
        raise ValueError(
            "not an absolute Windows path (use a drive path or a WSL path): %r" % path
        )
    drive = m.group(1).lower()
    rest = m.group(2).replace("\\", "/")
    return "/mnt/%s/%s" % (drive, rest)


def parse_distro_list(raw: bytes) -> list[str]:
    """Parse ``wsl.exe -l -q`` output (UTF-16-LE) into distro names,
    dropping empties and non-interactive distros."""
    text = raw.decode("utf-16-le", errors="ignore")
    names = []
    for line in text.splitlines():
        name = line.replace("\x00", "").strip()
        if not name:
            continue
        if name.startswith(_NON_INTERACTIVE_PREFIXES):
            continue
        if name not in names:
            names.append(name)
    return names


def bash_quote(s: str) -> str:
    """Single-quote a string for embedding in a bash -lc script."""
    return "'" + str(s).replace("'", "'\\''") + "'"


def build_bash_command(
    argv: list[str],
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    marker: str | None = None,
) -> str:
    """Assemble the payload for ``bash -lc``: env exports, cd, then the
    command (with argv[0] renamed to ``marker`` via ``exec -a``)."""
    parts = []
    for key, value in (env or {}).items():
        if value is None:
            continue
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


# --- the launcher -----------------------------------------------------------


class Launcher:
    def __init__(self, config: Config, registry: SessionRegistry):
        self.config = config
        self.registry = registry
        self._distro_cache: str | None = None

    # -- distro -------------------------------------------------------------

    async def _list_distros(self) -> list[str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                "wsl.exe",
                "-l",
                "-q",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await asyncio.wait_for(
                proc.communicate(), self.config.launch_timeout_ms / 1000.0
            )
        except FileNotFoundError as exc:
            raise LaunchError("wsl.exe was not found; install or enable WSL") from exc
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise LaunchError("wsl.exe -l -q timed out") from None
        except OSError as exc:
            raise LaunchError("failed to query WSL distros: %s" % exc) from exc
        if proc.returncode:
            raise LaunchError("wsl.exe -l -q failed with code %s" % proc.returncode)
        return parse_distro_list(out or b"")

    async def distro(self, override: str | None = None) -> str:
        if override:
            return override
        if self.config.wsl_distro:
            return self.config.wsl_distro
        if self._distro_cache:
            return self._distro_cache
        names = await self._list_distros()
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
        distro = await self.distro(distro_override)
        bash_cmd = build_bash_command(
            argv,
            env,
            cwd_wsl,
            marker=_MARKER_PREFIX + session_id if marker else None,
        )
        session = self.registry.reserve(
            session_id, kind=kind, log_file=str(log_file)
        )
        session.distro = distro
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            log_fh = open(log_file, "w", encoding="utf-8", errors="replace")
            try:
                proc = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(
                        "wsl.exe",
                        "-d",
                        distro,
                        "--",
                        "bash",
                        "-lc",
                        bash_cmd,
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
            session.state = RUNNING  # scripts never hello
        log.info(
            "launched %s session %s via %s (log: %s)",
            kind,
            session_id,
            distro,
            log_file,
        )
        return session

    async def _watch_process(self, session: Session) -> None:
        """Mirror subprocess completion without blocking the MCP event loop."""
        try:
            returncode = await session.proc.wait()
        except asyncio.CancelledError:
            return
        session.proc_returncode = returncode
        session.update_seen()
        if session.kind == "script":
            session.state = EXITED
            session.exited_code = returncode
            session.state_gen += 1
            await session._wake_stop_waiters()

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
        env_vars = dict(env or {})
        for reserved_name in (
            "GDB_MCP_SESSION_ID",
            "GDB_MCP_PORT",
            "GDB_MCP_TOKEN",
            "GDB_MCP_EVAL_OUTPUT_LIMIT",
            "GDB_MCP_MAX_MEM_READ",
            "GDB_MCP_MAX_ASYNC_LINE",
        ):
            env_vars.pop(reserved_name, None)
        env_vars.update({
            "GDB_MCP_SESSION_ID": session_id,
            "GDB_MCP_PORT": str(self.config.port),
            "GDB_MCP_EVAL_OUTPUT_LIMIT": str(self.config.eval_output_limit),
            "GDB_MCP_MAX_MEM_READ": str(self.config.max_mem_read),
            "GDB_MCP_MAX_ASYNC_LINE": str(self.config.max_async_line),
        })
        if self.config.token:
            env_vars["GDB_MCP_TOKEN"] = self.config.token
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
        deadline = time.monotonic() + max(0.1, timeout_ms / 1000.0)
        while time.monotonic() < deadline:
            await asyncio.sleep(0.1)
            if session.state != RESERVED:
                break
            if session.proc is not None and session.proc.returncode is not None:
                raise LaunchError(
                    "gdb exited during startup (code %s); log: %s"
                    % (session.proc.returncode, log_file)
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
        plugin). Returns (script_session, gdb_session_or_None)."""
        session_id = self.registry.new_session_id()
        gdb_session_id = self.registry.new_session_id(exclude={session_id})
        wsl_cwd = win_to_wsl(cwd) if cwd else None
        script_wsl = win_to_wsl(script)
        env_vars = dict(env or {})
        for reserved_name in (
            "GDB_MCP_SESSION_ID",
            "GDB_MCP_PORT",
            "GDB_MCP_TOKEN",
            "GDB_MCP_EVAL_OUTPUT_LIMIT",
            "GDB_MCP_MAX_MEM_READ",
            "GDB_MCP_MAX_ASYNC_LINE",
        ):
            env_vars.pop(reserved_name, None)
        env_vars.update({
            # The pwntools-spawned gdb inherits these and binds to the
            # reservation created below.
            "GDB_MCP_SESSION_ID": gdb_session_id,
            "GDB_MCP_PORT": str(self.config.port),
            "GDB_MCP_EVAL_OUTPUT_LIMIT": str(self.config.eval_output_limit),
            "GDB_MCP_MAX_MEM_READ": str(self.config.max_mem_read),
            "GDB_MCP_MAX_ASYNC_LINE": str(self.config.max_async_line),
        })
        if self.config.token:
            env_vars["GDB_MCP_TOKEN"] = self.config.token
        argv = [python, "-u", script_wsl] + list(args or [])
        log_file = self.config.log_dir / ("%s.log" % session_id)
        gdb_session = self.registry.reserve(
            gdb_session_id,
            kind="gdb",
            log_file=str(log_file),
            launched=False,
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
        except Exception:
            self.registry.remove(gdb_session_id)
            raise
        deadline = time.monotonic() + max(0.1, timeout_ms / 1000.0)
        while time.monotonic() < deadline:
            await asyncio.sleep(0.2)
            if gdb_session.state != RESERVED:
                return session, gdb_session
        return session, None

    # -- kill ----------------------------------------------------------------

    async def pkill_marker(
        self, session_id: str, force: bool, distro: str | None = None
    ) -> None:
        distro = await self.distro(distro)
        cmd = build_pkill_command(session_id, force)
        try:
            proc = await asyncio.create_subprocess_exec(
                "wsl.exe",
                "-d",
                distro,
                "--",
                "bash",
                "-lc",
                cmd,
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
