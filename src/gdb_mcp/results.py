"""On-disk store for oversized tool results.

When a tool response exceeds the inline limit, the full text is stored
under ``<log_dir>/results/`` and the response only carries a preview plus
the storage metadata (path + sha256); the :func:`read_result` MCP tool
serves line ranges back on demand. File names are the sha256 prefix of
the content, so identical outputs deduplicate.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from gdb_mcp.errors import GdbMcpError


def results_dir(log_dir: Path) -> Path:
    return Path(log_dir) / "results"


#: the result store is a bounded cache, not an archive
RESULTS_MAX_FILES = 500


def prune_results(log_dir: Path, max_files: int = RESULTS_MAX_FILES) -> int:
    """Delete the oldest stored results beyond ``max_files``; returns how
    many were removed. Called after every store so the directory stays a
    bounded cache instead of leaking disk forever."""
    directory = results_dir(log_dir)
    try:
        files = [p for p in directory.iterdir() if p.is_file() and p.suffix == ".txt"]
    except OSError:
        return 0
    try:
        files.sort(key=lambda p: p.stat().st_mtime)
    except OSError:
        return 0
    removed = 0
    for path in files[: max(0, len(files) - max_files)]:
        try:
            path.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def store_result(log_dir: Path, text: str) -> dict:
    """Store ``text`` in the results store (idempotent per content)."""
    data = text.encode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    directory = results_dir(log_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / ("%s.txt" % digest[:16])
    if not path.exists():
        path.write_bytes(data)
    prune_results(log_dir)
    return {"path": str(path), "sha256": digest, "bytes": len(data)}


def load_result_slice(log_dir: Path, path: str, offset: int, limit: int | None) -> dict:
    """Return a line range from a stored result file.

    ``path`` must point inside the results store. The slice semantics
    match the plugin's eval pagination: 0-based ``offset``, optional
    ``limit``, response always carries ``total_lines``.
    """
    root = results_dir(log_dir).resolve()
    candidate = Path(path).resolve()
    if candidate.parent != root or candidate.suffix != ".txt":
        raise GdbMcpError(
            "BAD_PARAMS",
            "path is not a stored result file (must be directly inside the "
            "results store): %r" % path,
        )
    try:
        text = candidate.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise GdbMcpError("NO_RESULT", "cannot read result file: %s" % exc) from exc
    lines = text.splitlines()
    stop = None if limit is None else offset + limit
    selected = lines[offset:stop]
    return {
        "output": "\n".join(selected),
        "total_lines": len(lines),
        "offset": offset,
        "truncated": offset + len(selected) < len(lines),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }
