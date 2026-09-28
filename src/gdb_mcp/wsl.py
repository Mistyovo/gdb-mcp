"""Windows/WSL path and distro helpers — the single implementation.

Both subsystems that shell out into WSL (the process launcher and the
Ghidra static bridge) need the same two things: a Windows path in
``/mnt/...`` form, and the name of a usable distro. Having them here
keeps that dependency pointed one way (subsystem -> WSL), instead of the
static bridge importing the launcher.
"""

from __future__ import annotations

import asyncio
import os
import re

#: distros that are not interactive targets
NON_INTERACTIVE_PREFIXES = ("docker-desktop",)

_DISTRO_LIST_TIMEOUT = 10.0


class WslError(Exception):
    """WSL is unavailable, unusable, or did not answer in time."""


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
    names: list[str] = []
    for line in text.splitlines():
        name = line.replace("\x00", "").strip()
        if not name:
            continue
        if name.startswith(NON_INTERACTIVE_PREFIXES):
            continue
        if name not in names:
            names.append(name)
    return names


def uses_wsl() -> bool:
    """Whether this process must reach gdb tooling through WSL."""
    return os.name == "nt"


async def list_distros(timeout: float = _DISTRO_LIST_TIMEOUT) -> list[str]:
    """Interactive WSL distros, in ``wsl.exe`` order.

    Raises :class:`WslError` rather than returning an empty list, so a
    caller cannot confuse "no WSL" with "WSL said nothing".
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "wsl.exe",
            "-l",
            "-q",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise WslError("wsl.exe was not found; install or enable WSL") from exc
    except OSError as exc:
        raise WslError("failed to query WSL distros: %s" % exc) from exc
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise WslError("wsl.exe -l -q timed out") from None
    if proc.returncode:
        raise WslError("wsl.exe -l -q failed with code %s" % proc.returncode)
    return parse_distro_list(out or b"")


__all__ = [
    "NON_INTERACTIVE_PREFIXES",
    "WslError",
    "list_distros",
    "parse_distro_list",
    "uses_wsl",
    "win_to_wsl",
]
