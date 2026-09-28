"""On-disk Ghidra analysis cache.

This is the *storage* half of the static bridge: analysis records, the
SHA-256-addressed cache directories, crash-safe promotion of a freshly
analyzed binary, and the in-memory caches over the parsed artifacts.

It knows nothing about gdb sessions, MCP tools, or subprocesses — that is
:mod:`gdb_mcp.reverse.manager`'s job. All of its methods are synchronous
file IO, meant to be called through ``asyncio.to_thread`` by the manager.

Locking: ``_lock`` guards the in-memory maps only, and ``_promote_lock``
serializes directory swaps. Neither is ever held across file IO, so a
slow disk cannot block a cache reader.
"""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import threading
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from gdb_mcp.config import Config
from gdb_mcp.errors import GdbMcpError

SCHEMA_VERSION = 2

#: parsed function payloads kept for the hottest analysis (LRU bound)
FUNCTION_CACHE_SIZE = 512


@dataclass
class AnalysisRecord:
    analysis_id: str
    sha256: str
    source_path: str
    target_path: str
    distro: str | None
    size: int
    status: str = "queued"
    backend: str = "ghidra"
    partial: bool = False
    error: str | None = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    function_count: int = 0
    decompiled_count: int = 0
    failed_count: int = 0

    def public(self) -> dict[str, Any]:
        return asdict(self)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GdbMcpError("ANALYSIS_CORRUPT", "cannot read %s" % path.name) from exc


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    os.replace(temp, path)


def validate_index(index: Any) -> None:
    """Reject an analysis index the query layer could not trust, before
    anything caches or serves it."""
    if not isinstance(index, dict):
        raise GdbMcpError("ANALYSIS_CORRUPT", "analysis index must be an object")
    version = index.get("schema_version")
    if version != SCHEMA_VERSION:
        raise GdbMcpError(
            "ANALYSIS_CORRUPT", "unsupported analysis index schema %r" % version
        )
    if not isinstance(index.get("binary"), dict):
        raise GdbMcpError("ANALYSIS_CORRUPT", "analysis index has no binary metadata")
    for key in ("sections", "symbols", "strings", "functions"):
        if not isinstance(index.get(key), list):
            raise GdbMcpError("ANALYSIS_CORRUPT", "analysis index has invalid %s" % key)
    binary = index["binary"]
    try:
        int(binary.get("image_base", ""), 16)
        for function in index["functions"]:
            if not isinstance(function, dict) or not isinstance(function.get("name"), str):
                raise TypeError
            start = int(function["entry"], 16)
            end = int(function.get("end", function["entry"]), 16)
            if end < start:
                raise ValueError
    except (KeyError, TypeError, ValueError):
        raise GdbMcpError(
            "ANALYSIS_CORRUPT", "analysis index contains invalid addresses"
        ) from None


def path_key(path: str | None) -> str:
    """Case-insensitive on Windows/WSL-mount paths, exact elsewhere."""
    if not path:
        return ""
    normalized = str(path).replace("\\", "/").rstrip("/")
    if re.match(r"^[A-Za-z]:/", normalized) or normalized.startswith("//"):
        return normalized.casefold()
    return normalized


class AnalysisStore:
    """Records + cache artifacts for analyzed binaries."""

    def __init__(self, config: Config):
        self.config = config
        self.records: dict[str, AnalysisRecord] = {}
        self._lock = threading.RLock()
        self._promote_lock = threading.Lock()
        #: serializes read-modify-write on annotations.json across analyses
        self.annotation_lock = threading.Lock()
        self._index_cache: dict[str, dict[str, Any]] = {}
        self._function_cache: OrderedDict[tuple[str, int], dict[str, Any]] = OrderedDict()
        self._disassembly_cache: dict[str, tuple[list[int], list[dict[str, Any]]]] = {}
        self._annotation_cache: dict[str, dict[str, Any]] = {}
        self._function_indexes: dict[
            str, tuple[list[int], list[tuple[int, int, dict[str, Any]]], list[int], dict[str, int]]
        ] = {}
        self.recover_promotions()
        self.load()

    # -- root / layout --------------------------------------------------------

    @property
    def root(self) -> Path | None:
        return self.config.analysis_dir

    def dir_for(self, analysis_id: str) -> Path:
        if not re.fullmatch(r"a-[0-9a-f]{16}", analysis_id):
            raise GdbMcpError("NO_ANALYSIS", "invalid analysis id")
        return self.config.analysis_dir / analysis_id

    def ready_dir(self, analysis_id: str) -> Path:
        directory = self.dir_for(analysis_id)
        if not directory.joinpath("index.json").is_file():
            raise GdbMcpError(
                "ANALYSIS_NOT_READY", "analysis is %s" % self.record(analysis_id).status
            )
        return directory

    # -- records --------------------------------------------------------------

    def record(self, analysis_id: str) -> AnalysisRecord:
        with self._lock:
            record = self.records.get(analysis_id)
        if record is None:
            raise GdbMcpError("NO_ANALYSIS", "unknown analysis %r" % analysis_id)
        return record

    def put(self, record: AnalysisRecord) -> None:
        with self._lock:
            self.records[record.analysis_id] = record

    def list_public(self) -> list[dict[str, Any]]:
        with self._lock:
            records = sorted(
                self.records.values(), key=lambda item: item.updated_at, reverse=True
            )
        return [record.public() for record in records]

    def matches_path(self, analysis_id: str, path: str | None) -> bool:
        try:
            record = self.record(analysis_id)
        except GdbMcpError:
            return False
        if not path:
            return False
        return path_key(path) in {path_key(record.source_path), path_key(record.target_path)}

    def newest_for_path(self, module_path: str | None) -> str | None:
        """The most recent ready analysis whose source or target path is
        ``module_path`` (runtime modules are addressed by file name)."""
        with self._lock:
            ready = [r for r in self.records.values() if r.status == "ready"]
        ready.sort(key=lambda item: item.updated_at, reverse=True)
        for record in ready:
            if self.matches_path(record.analysis_id, module_path):
                return record.analysis_id
        return None

    # -- persistence ----------------------------------------------------------

    def recover_promotions(self) -> None:
        """Restore a cache hidden by a process crash during promotion."""
        root = self.root
        if root is None or not root.is_dir():
            return
        for backup in root.glob(".a-[0-9a-f]*.backup"):
            analysis_id = backup.name[1:-7]
            if not re.fullmatch(r"a-[0-9a-f]{16}", analysis_id):
                continue
            final_dir = root / analysis_id
            if final_dir.exists():
                shutil.rmtree(backup, ignore_errors=True)
            elif backup.joinpath("manifest.json").is_file() and backup.joinpath(
                "index.json"
            ).is_file():
                os.replace(backup, final_dir)

    def load(self) -> int:
        """Load manifests from a previous run; returns how many loaded."""
        root = self.root
        if root is None or not root.is_dir():
            return 0
        loaded = 0
        for manifest_path in root.glob("a-*/manifest.json"):
            try:
                raw = read_json(manifest_path)
                if raw.get("schema_version") != SCHEMA_VERSION:
                    continue
                fields = {
                    key: raw[key] for key in AnalysisRecord.__dataclass_fields__ if key in raw
                }
                record = AnalysisRecord(**fields)
                index_path = manifest_path.parent / "index.json"
                if index_path.is_file():
                    validate_index(read_json(index_path))
                    record.status = (
                        "ready" if record.status in {"running", "queued"} else record.status
                    )
                self.put(record)
                loaded += 1
            except (OSError, ValueError, TypeError, KeyError, GdbMcpError):
                continue
        return loaded

    def write_manifest(self, directory: Path, record: AnalysisRecord) -> None:
        write_json(directory / "manifest.json", {"schema_version": SCHEMA_VERSION, **record.public()})

    def promote(self, record: AnalysisRecord, staging: Path, index: dict[str, Any]) -> None:
        """Move a completed staging directory into the cache atomically.

        The old entry is renamed aside first, so a crash leaves either the
        old or the new result readable (and :meth:`recover_promotions`
        finishes the job at the next start). User annotations survive the
        refresh.
        """
        root = self.root.resolve()
        final_dir = root / record.analysis_id
        backup = root / (".%s.backup" % record.analysis_id)
        with self._promote_lock:
            if final_dir.joinpath("annotations.json").is_file():
                shutil.copy2(final_dir / "annotations.json", staging / "annotations.json")
            elif not staging.joinpath("annotations.json").exists():
                write_json(staging / "annotations.json", {})
            self.write_manifest(staging, record)
            if backup.exists():
                shutil.rmtree(backup)
            moved_old = False
            if final_dir.exists():
                os.replace(final_dir, backup)
                moved_old = True
            try:
                os.replace(staging, final_dir)
            except Exception:
                if moved_old and backup.exists() and not final_dir.exists():
                    os.replace(backup, final_dir)
                raise
            if backup.exists():
                shutil.rmtree(backup, ignore_errors=True)
        self.invalidate(record.analysis_id)
        self.cache_index(record.analysis_id, index)

    # -- caches ---------------------------------------------------------------

    def invalidate(self, analysis_id: str) -> None:
        with self._lock:
            self._index_cache.pop(analysis_id, None)
            self._function_indexes.pop(analysis_id, None)
            self._disassembly_cache.pop(analysis_id, None)
            self._annotation_cache.pop(analysis_id, None)
            for key in [key for key in self._function_cache if key[0] == analysis_id]:
                self._function_cache.pop(key, None)

    def cache_index(self, analysis_id: str, index: dict[str, Any]) -> None:
        """Derive the address-lookup structures once per index."""
        functions = index.get("functions") or []
        rows = sorted(
            (
                int(item["entry"], 16),
                int(item.get("end", item["entry"]), 16),
                item,
            )
            for item in functions
        )
        starts = [row[0] for row in rows]
        prefix_ends: list[int] = []
        maximum = -1
        for _, end, _ in rows:
            maximum = max(maximum, end)
            prefix_ends.append(maximum)
        names = {
            item["name"]: int(item["entry"], 16)
            for item in functions
            if isinstance(item.get("name"), str)
        }
        with self._lock:
            self._index_cache[analysis_id] = index
            self._function_indexes[analysis_id] = (starts, rows, prefix_ends, names)

    def index(self, analysis_id: str) -> dict[str, Any]:
        with self._lock:
            cached = self._index_cache.get(analysis_id)
        if cached is not None:
            return cached
        path = self.ready_dir(analysis_id) / "index.json"
        index = read_json(path)
        validate_index(index)
        self.cache_index(analysis_id, index)
        return index

    def function_index(
        self, analysis_id: str
    ) -> tuple[list[int], list[tuple[int, int, dict[str, Any]]], list[int], dict[str, int]]:
        self.index(analysis_id)
        with self._lock:
            return self._function_indexes[analysis_id]

    def function_payload(self, analysis_id: str, entry: int) -> dict[str, Any] | None:
        """The per-function artifact, or None when the analysis has none
        (external / thunk functions are described by their index summary)."""
        path = self.ready_dir(analysis_id) / "functions" / ("%x.json" % entry)
        if not path.is_file():
            return None
        cache_key = (analysis_id, entry)
        with self._lock:
            cached = self._function_cache.get(cache_key)
            if cached is not None:
                self._function_cache.move_to_end(cache_key)
        if cached is not None:
            return cached
        payload = read_json(path)
        if not isinstance(payload, dict):
            raise GdbMcpError("ANALYSIS_CORRUPT", "function data must be an object")
        with self._lock:
            self._function_cache[cache_key] = payload
            self._function_cache.move_to_end(cache_key)
            while len(self._function_cache) > FUNCTION_CACHE_SIZE:
                self._function_cache.popitem(last=False)
        return payload

    def disassembly(
        self, analysis_id: str
    ) -> tuple[list[int], list[dict[str, Any]]] | None:
        """The flat instruction stream, address-sorted, or None when the
        analysis predates it (callers fall back to per-function text)."""
        path = self.ready_dir(analysis_id) / "disassembly.json"
        if not path.is_file():
            return None
        with self._lock:
            cached = self._disassembly_cache.get(analysis_id)
        if cached is not None:
            return cached
        payload = read_json(path)
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version") != SCHEMA_VERSION
            or not isinstance(payload.get("instructions"), list)
        ):
            raise GdbMcpError("ANALYSIS_CORRUPT", "invalid disassembly index")
        items = sorted(payload["instructions"], key=lambda item: int(item["address"], 16))
        cached = ([int(item["address"], 16) for item in items], items)
        with self._lock:
            self._disassembly_cache[analysis_id] = cached
        return cached

    def annotations(self, analysis_id: str) -> dict[str, Any]:
        """The annotation map (a private copy: callers mutate it before
        saving)."""
        with self._lock:
            cached = self._annotation_cache.get(analysis_id)
            if cached is not None:
                return copy.deepcopy(cached)
        path = self.ready_dir(analysis_id) / "annotations.json"
        loaded = read_json(path) if path.exists() else {}
        if not isinstance(loaded, dict):
            raise GdbMcpError("ANALYSIS_CORRUPT", "annotations must be an object")
        with self._lock:
            self._annotation_cache.setdefault(analysis_id, loaded)
            return copy.deepcopy(self._annotation_cache[analysis_id])

    def annotation(self, analysis_id: str, key: str) -> dict[str, Any]:
        return dict(self.annotations(analysis_id).get(key, {}))

    def read_valid_index(self, path: Path) -> dict[str, Any]:
        """Read + validate an index a Ghidra run just produced."""
        index = read_json(path)
        validate_index(index)
        return index

    def save_annotations(self, analysis_id: str, annotations: dict[str, Any]) -> None:
        """Persist then publish the new map (disk first: a failed write must
        not leave a cache that disagrees with the file)."""
        write_json(self.ready_dir(analysis_id) / "annotations.json", annotations)
        with self._lock:
            self._annotation_cache[analysis_id] = annotations


__all__ = [
    "FUNCTION_CACHE_SIZE",
    "SCHEMA_VERSION",
    "AnalysisRecord",
    "AnalysisStore",
    "path_key",
    "read_json",
    "validate_index",
    "write_json",
]
