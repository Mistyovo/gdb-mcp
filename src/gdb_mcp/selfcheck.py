"""Launcher self-check (``gdb-mcp --selfcheck``).

Answers one question before a session exists: can this host start a gdb that
will load the plugin? The probe is read-only apart from a short port bind and
runs the same startup path users get (init files included), so ``~/.gdbinit``
problems surface here instead of during the first ``launch_gdb`` call.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import socket
import sys
from pathlib import Path
from typing import Any, Awaitable, Callable

from gdb_mcp.config import Config
from gdb_mcp.wsl import WslError, list_distros

_PLUGIN_PATH = Path(__file__).resolve().parent / "plugin" / "gdb_mcp_plugin.py"
_PROBE = (
    "python import sys; "
    "print('GDBMCP_PY ' + sys.version.split()[0]); "
    "print('GDBMCP_PWDNBG ' + ('1' if 'pwndbg' in sys.modules else '0'))"
)
_PROBE_TIMEOUT = 15.0
_VERSION_TIMEOUT = 10.0

Probe = Callable[..., Awaitable[dict]]
PortCheck = Callable[[Config], tuple[bool, str | None]]


async def _run(argv: list[str], timeout: float) -> tuple[int, str, str]:
    # WSL_UTF8 keeps wsl.exe from emitting UTF-16 on its pipes.
    env = dict(os.environ, WSL_UTF8="1")
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", "timed out after %.0fs" % timeout
    return proc.returncode, _decode(out or b""), _decode(err or b"")


def _decode(raw: bytes) -> str:
    """Older wsl.exe versions ignore WSL_UTF8 and write UTF-16 to a pipe."""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    if b"\x00" in raw:
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("utf-8", errors="replace")


def _version_line(text: str) -> str | None:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in lines:
        if "gdb" in line.lower():
            return line
    return lines[0] if lines else None


async def probe_gdb(gdb: str, distro: str | None = None) -> dict:
    """Version, embedded Python, and pwndbg visibility of one gdb."""
    prefix = ["wsl.exe", "-d", distro, "--"] if distro else []
    rc, version_out, version_err = await _run(
        prefix + [gdb, "--version"], _VERSION_TIMEOUT
    )
    result: dict[str, Any] = {
        "version": _version_line(version_out),
        "embedded_python": None,
        "pwndbg": None,
        "error": None if rc == 0 else (version_err.strip() or version_out.strip() or "exit code %s" % rc),
    }
    if rc != 0:
        return result
    rc, probe_out, probe_err = await _run(
        prefix + [gdb, "-batch", "-ex", _PROBE], _PROBE_TIMEOUT
    )
    python = re.search(r"GDBMCP_PY (\S+)", probe_out)
    if python:
        result["embedded_python"] = python.group(1)
    if "GDBMCP_PWDNBG 1" in probe_out:
        result["pwndbg"] = True
    elif "GDBMCP_PWDNBG 0" in probe_out:
        result["pwndbg"] = False
    if result["embedded_python"] is None:
        result["error"] = (
            "gdb has no usable embedded Python (the plugin needs it); "
            "install the python support for gdb"
        )
        tail = (probe_err or probe_out).strip().splitlines()[-3:]
        if tail:
            result["error"] += ": " + " | ".join(tail)
    return result


def _port_available(config: Config) -> tuple[bool, str | None]:
    try:
        family, _, _, _, address = socket.getaddrinfo(
            config.host_bind, config.port, type=socket.SOCK_STREAM
        )[0]
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(address)
    except OSError as exc:
        return False, str(exc)
    return True, None


def _issue(code: str, message: str) -> dict:
    return {"code": code, "message": message}


async def run_selfcheck(
    config: Config,
    *,
    which: Callable[[str], str | None] = shutil.which,
    probe: Probe | None = None,
    port_check: PortCheck = _port_available,
    plugin: Path = _PLUGIN_PATH,
    distros: Callable[[], Awaitable[list[str]]] | None = None,
) -> dict:
    """JSON-ready readiness report; ``ready`` is false for blocking issues."""
    probe_gdb_fn = probe or probe_gdb
    issues: list[dict] = []
    result: dict[str, Any] = {
        "ready": False,
        "platform": sys.platform,
        "launcher": config.launcher,
        "gdb": {
            "configured": config.gdb_path,
            "path": None,
            "version": None,
            "embedded_python": None,
            "pwndbg": None,
        },
        "plugin": {"path": str(plugin), "present": plugin.is_file()},
        "port": {"host": config.host_bind, "port": config.port, "available": None},
        "wsl_distro": None,
        "issues": issues,
    }
    if not result["plugin"]["present"]:
        issues.append(
            _issue(
                "PLUGIN_MISSING",
                "gdb_mcp_plugin.py is not in the installed package at %s" % plugin,
            )
        )

    available, port_error = port_check(config)
    result["port"]["available"] = available
    if not available:
        result["port"]["error"] = port_error
        issues.append(
            _issue(
                "PORT_UNAVAILABLE",
                "cannot bind %s:%d (%s); another gdb-mcp or process may hold it"
                % (config.host_bind, config.port, port_error),
            )
        )

    gdb = config.gdb_path or "gdb"
    distro: str | None = None
    if config.launcher == "wsl":
        lister = distros or list_distros
        try:
            names = await lister()
        except WslError as exc:
            issues.append(_issue("WSL_UNAVAILABLE", str(exc)))
            names = []
        distro = config.wsl_distro or (names[0] if names else None)
        result["wsl_distro"] = distro
        if not distro:
            issues.append(
                _issue(
                    "WSL_NO_DISTRO",
                    "no interactive WSL distro found; install one or set "
                    "GDB_MCP_WSL_DISTRO",
                )
            )
        elif config.wsl_distro and names and config.wsl_distro not in names:
            issues.append(
                _issue(
                    "WSL_DISTRO_MISSING",
                    "configured distro %r is not in wsl.exe -l -q (%s)"
                    % (config.wsl_distro, ", ".join(names)),
                )
            )
    elif not config.gdb_path:
        found = which("gdb")
        if not found:
            issues.append(
                _issue(
                    "GDB_NOT_FOUND",
                    "gdb is not on PATH; install it or pass --gdb-path",
                )
            )
        gdb = found or gdb
    else:
        configured = Path(config.gdb_path)
        looks_like_path = configured.name != config.gdb_path or configured.is_absolute()
        if not configured.is_file() and looks_like_path:
            issues.append(
                _issue(
                    "GDB_NOT_FOUND",
                    "configured gdb path %r does not exist" % config.gdb_path,
                )
            )

    result["gdb"]["path"] = gdb
    if not issues or not any(
        issue["code"] in {"GDB_NOT_FOUND", "WSL_UNAVAILABLE", "WSL_NO_DISTRO"} for issue in issues
    ):
        try:
            probed = await probe_gdb_fn(gdb, distro)
        except OSError as exc:
            probed = {"version": None, "embedded_python": None, "pwndbg": None, "error": str(exc)}
        result["gdb"].update(probed)
        if probed.get("version") is None:
            issues.append(
                _issue(
                    "GDB_PROBE_FAILED",
                    str(probed.get("error") or "gdb --version produced no output"),
                )
            )
        elif probed.get("embedded_python") is None:
            issues.append(
                _issue(
                    "GDB_PYTHON_UNAVAILABLE",
                    str(
                        probed.get("error")
                        or "gdb has no usable embedded Python; the plugin cannot load"
                    ),
                )
            )
        elif probed.get("error"):
            issues.append(_issue("GDB_PROBE_FAILED", str(probed["error"])))

    result["ready"] = not issues
    return result
