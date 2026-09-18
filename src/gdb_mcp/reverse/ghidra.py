"""Ghidra Headless process runner for Windows+WSL and native Linux."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import re
import sys
import uuid

from gdb_mcp.config import Config
from gdb_mcp.errors import GdbMcpError
from gdb_mcp.launcher import win_to_wsl

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DEFAULT_GHIDRA = "/usr/share/ghidra/support/analyzeHeadless"
_SCRIPTS_DIR = Path(__file__).resolve().parent / "ghidra_scripts"


class GhidraRunner:
    def __init__(self, config: Config):
        self.config = config

    @property
    def uses_wsl(self) -> bool:
        return os.name == "nt"

    async def _distro(self, override: str | None = None) -> str | None:
        if not self.uses_wsl:
            return None
        if override:
            return override
        if self.config.wsl_distro:
            return self.config.wsl_distro
        proc = await asyncio.create_subprocess_exec(
            "wsl.exe",
            "-l",
            "-q",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        if proc.returncode:
            raise GdbMcpError("BACKEND_UNAVAILABLE", "unable to list WSL distros")
        text = stdout.decode("utf-16-le", errors="ignore")
        names = [
            line.replace("\x00", "").strip()
            for line in text.splitlines()
            if line.replace("\x00", "").strip()
            and not line.replace("\x00", "").strip().startswith("docker-desktop")
        ]
        if not names:
            raise GdbMcpError("BACKEND_UNAVAILABLE", "no usable WSL distro found")
        return names[0]

    def _target_path(self, path: str) -> str:
        if not self.uses_wsl:
            return str(Path(path).expanduser().resolve())
        return win_to_wsl(path) if not str(path).startswith("/") else str(path)

    def _host_path_for_target(self, path: Path) -> str:
        return win_to_wsl(str(path)) if self.uses_wsl else str(path)

    async def _exec(
        self,
        argv: list[str],
        distro: str | None,
        timeout: float,
    ) -> tuple[int, bytes, bytes]:
        command = argv
        if self.uses_wsl:
            command = ["wsl.exe", "-d", str(distro), "--"] + argv
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            raise GdbMcpError("BACKEND_UNAVAILABLE", str(exc)) from exc
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise GdbMcpError(
                "ANALYSIS_TIMEOUT", "headless analysis exceeded %.0f seconds" % timeout
            ) from None
        return proc.returncode or 0, stdout, stderr

    async def fingerprint(
        self, path: str, distro: str | None = None
    ) -> tuple[str, int, str | None, str]:
        selected = await self._distro(distro)
        target = self._target_path(path)
        if self.uses_wsl:
            code, canonical_out, _ = await self._exec(
                ["readlink", "-f", "--", target], selected, 30.0
            )
            if code == 0 and canonical_out.strip():
                target = canonical_out.decode("utf-8", errors="replace").strip()
            argv = ["sha256sum", "--", target]
        else:
            argv = [sys.executable, "-c", _NATIVE_HASH_SCRIPT, target]
        code, stdout, stderr = await self._exec(argv, selected, 60.0)
        if code:
            message = stderr.decode(errors="replace").strip() or "target is not readable"
            raise GdbMcpError("BAD_TARGET", message)
        parts = stdout.decode("utf-8", errors="replace").split()
        if not parts or not _SHA256_RE.fullmatch(parts[0].lower()):
            raise GdbMcpError("BAD_TARGET", "could not fingerprint target")
        digest = parts[0].lower()
        if self.uses_wsl:
            code, size_out, size_err = await self._exec(
                ["stat", "-c", "%s", "--", target], selected, 30.0
            )
            if code:
                raise GdbMcpError(
                    "BAD_TARGET", size_err.decode(errors="replace").strip()
                )
            size = int(size_out.decode().strip())
        else:
            size = Path(target).stat().st_size
        return digest, size, selected, target

    async def detect(self, distro: str | None = None) -> tuple[str | None, str | None]:
        selected = await self._distro(distro)
        executable = self.config.ghidra_headless or _DEFAULT_GHIDRA
        code, _, _ = await self._exec(["test", "-x", executable], selected, 20.0)
        if code:
            return None, selected
        return executable, selected

    async def analyze(
        self,
        binary_path: str,
        output_dir: Path,
        analysis_id: str,
        distro: str | None,
        language_id: str | None = None,
    ) -> dict[str, str | int]:
        executable, selected = await self.detect(distro)
        if executable is None:
            raise GdbMcpError(
                "BACKEND_UNAVAILABLE",
                "Ghidra Headless was not found; install the open-source ghidra package "
                "or set GDB_MCP_GHIDRA_HEADLESS",
            )
        output_target = self._host_path_for_target(output_dir)
        scripts_target = self._host_path_for_target(_SCRIPTS_DIR)
        project_name = "gdb_mcp_%s_%s" % (
            analysis_id.replace("-", "_"),
            uuid.uuid4().hex[:8],
        )
        argv = [
            "timeout",
            "--signal=TERM",
            "--kill-after=10s",
            "%ds" % max(1, int(self.config.analysis_timeout)),
            executable,
            "/tmp",
            project_name,
        ]
        if language_id:
            argv.extend(["-processor", language_id])
        argv.extend([
            "-import",
            binary_path,
            "-overwrite",
            "-analysisTimeoutPerFile",
            str(max(1, int(self.config.analysis_timeout))),
            "-scriptPath",
            scripts_target,
            "-postScript",
            "ExportAnalysis.java",
            output_target,
            str(self.config.decompile_timeout),
            "-deleteProject",
        ])
        code, stdout, stderr = await self._exec(
            argv, selected, self.config.analysis_timeout + 60.0
        )
        log_text = (stdout + b"\n" + stderr).decode("utf-8", errors="replace")
        (output_dir / "analysis.log").write_text(log_text, encoding="utf-8")
        if code in {124, 137}:
            raise GdbMcpError(
                "ANALYSIS_TIMEOUT",
                "headless analysis exceeded %.0f seconds" % self.config.analysis_timeout,
            )
        if code:
            tail = "\n".join(log_text.splitlines()[-20:])
            raise GdbMcpError("ANALYSIS_FAILED", tail or "Ghidra exited with an error")
        if not (output_dir / "index.json").is_file():
            raise GdbMcpError("ANALYSIS_FAILED", "Ghidra produced no analysis index")
        return {"backend": "ghidra", "executable": executable, "distro": selected or ""}


_NATIVE_HASH_SCRIPT = """
import hashlib, pathlib, sys
p = pathlib.Path(sys.argv[1])
h = hashlib.sha256()
with p.open('rb') as f:
    for chunk in iter(lambda: f.read(1024 * 1024), b''):
        h.update(chunk)
print(h.hexdigest(), p)
""".strip()


__all__ = ["GhidraRunner"]
