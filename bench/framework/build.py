"""Compile task targets inside WSL and record build evidence.

Build evidence (binary sha256 + symbol offset table from ``nm -S``) is patched
into the task manifests: after ``bench build``, a manifest pins the exact
artifact a run must use. gcc without ``-g`` is deterministic for a given
source + flags + toolchain, so regenerating and rebuilding reproduces the same
patched manifests. Any solution that needs a symbol offset reads it from the
manifest, never from a hardcoded address.
"""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGETS_OUT = ROOT / "bench" / "targets_out"


class BuildError(RuntimeError):
    pass


@dataclass
class BuildRecord:
    name: str
    binary_sha256: str
    symbols: dict[str, str]
    warnings: list[str]


def run_wsl(distro: str, argv: list[str], timeout: int = 180) -> subprocess.CompletedProcess:
    """Run a command inside WSL; with distro=None run natively (Linux CI)."""
    if distro is None:
        cmd = list(argv)
    else:
        cmd = ["wsl.exe", "-d", distro, "--"] + list(argv)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace", timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        raise BuildError("command timed out: %s" % " ".join(argv)) from exc
    return proc


def win_to_wsl(path: Path) -> str:
    """Path passthrough on native Linux; /mnt conversion under WSL."""
    import os

    if os.name != "nt" or str(path).startswith("/"):
        return str(path)
    from gdb_mcp.wsl import win_to_wsl as convert

    return convert(str(path))


def build_target(task, distro: str) -> BuildRecord:
    """Compile one task target; returns build evidence."""
    name = task.target.name
    out_dir = TARGETS_OUT / name
    out_dir.mkdir(parents=True, exist_ok=True)
    src = out_dir / "src.c"
    src.write_text(task.target.source, encoding="utf-8")
    binary = out_dir / name

    proc = run_wsl(
        distro,
        ["gcc", *task.target.build.flags,
         *task.target.build.ldflags,
         "-o", win_to_wsl(binary), win_to_wsl(src)],
    )
    if proc.returncode != 0:
        raise BuildError("gcc failed for %s:\n%s" % (name, proc.stderr))
    warnings = [ln for ln in proc.stderr.splitlines() if "warning" in ln]

    if task.target.build.strip:
        stripped = run_wsl(distro, ["strip", win_to_wsl(binary)])
        if stripped.returncode != 0:
            raise BuildError("strip failed for %s:\n%s" % (name, stripped.stderr))
        warnings.append("stripped: symbol offsets recorded pre-strip")

    nm = run_wsl(distro, ["nm", "--defined-only", "-S", win_to_wsl(binary)])
    symbols: dict[str, str] = {}
    if nm.returncode == 0:
        for line in nm.stdout.splitlines():
            parts = line.split()
            if len(parts) == 4:
                addr, size, _typ, sym = parts
                symbols[sym] = "0x%x" % int(addr, 16)
                symbols[sym + "$end"] = "0x%x" % (int(addr, 16) + int(size, 16))
            elif len(parts) == 3:
                addr, _typ, sym = parts
                symbols.setdefault(sym, "0x%x" % int(addr, 16))
    else:
        warnings.append("nm unavailable (%s); symbol-dependent checks will fail"
                        % nm.stderr.strip()[:120])

    sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    return BuildRecord(name=name, binary_sha256=sha, symbols=symbols, warnings=warnings)


def build_all(tasks, distro: str, force: bool = False) -> dict[str, BuildRecord]:
    """Build every target (each task name gets its own binary on disk) and
    patch evidence into the manifests."""
    records: dict[str, BuildRecord] = {}
    for task in tasks:
        name = task.target.name
        marker = TARGETS_OUT / name / name
        if not force and marker.exists() and task.target.binary_sha256:
            continue  # already built and pinned
        record = build_target(task, distro)
        records[name] = record
        task.target.binary_sha256 = record.binary_sha256
        task.target.symbols = dict(record.symbols)
    return records
