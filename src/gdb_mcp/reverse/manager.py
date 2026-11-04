"""Optional static-analysis extension: Ghidra analysis queueing + queries.

This is a *query-only* extension, enabled by the full tool profile. It owns
the asynchronous half — queueing Ghidra runs and exposing the SHA-256
addressed cache. It deliberately has no gdb-session coupling: the removed
dashboard used to map live stops onto static addresses, but the plugin
never emitted module metadata, so that path was dead and is not advertised.

Two collaborators take the rest: :class:`~gdb_mcp.reverse.store.AnalysisStore`
owns the on-disk cache and the in-memory indexes over it, and
:class:`~gdb_mcp.reverse.ghidra.GhidraRunner` owns the headless process.
"""

from __future__ import annotations

import asyncio
from bisect import bisect_left, bisect_right
from collections import deque
import json
import logging
import re
import shutil
import time
import uuid
from pathlib import Path
from typing import Any

from gdb_mcp.config import Config
from gdb_mcp.errors import GdbMcpError

from .ghidra import GhidraRunner
from .store import AnalysisRecord, AnalysisStore

log = logging.getLogger("gdb_mcp.reverse")

DEFAULT_LIMIT = 100
MAX_LIMIT = 1000
MAX_SEARCH_RESULTS = 200
MAX_GRAPH_NODES = 1000


class AnalysisManager:
    """Query facade over the SHA-256-addressed Ghidra analysis cache.

    This is an optional static-analysis extension. It deliberately knows
    nothing about gdb sessions: live location mapping was removed with the
    dashboard (the plugin never emitted module metadata, so the old path
    was dead). Ghidra runs are queued explicitly through ``analyze_binary``.
    """

    def __init__(self, config: Config):
        self.config = config
        self.runner = GhidraRunner(config)
        self.store = AnalysisStore(config)
        #: Ghidra runs are serialized: the analyzer is slow and memory-hungry
        self._semaphore = asyncio.Semaphore(1)
        self._tasks: dict[str, asyncio.Task] = {}

    @staticmethod
    def _forget(registry: dict, key: str):
        """Done-callback: log a failure that would otherwise vanish, and drop
        the entry only if the registry still holds *this* task (a newer one
        may already have replaced it)."""

        def _done(finished: asyncio.Task) -> None:
            if not finished.cancelled():
                exc = finished.exception()
                if exc is not None:
                    log.warning("task for %s failed: %s", key, exc)
            if registry.get(key) is finished:
                registry.pop(key, None)

        return _done

    # -- analysis queue -------------------------------------------------------

    async def queue_analysis(
        self,
        path: str,
        distro: str | None = None,
        force: bool = False,
        language_id: str | None = None,
    ) -> AnalysisRecord:
        """Return the record for ``path``, starting an analysis if needed.

        Deduplicated by content hash: concurrent requests for one binary
        share a run, and a request for an already-ready binary does not
        re-analyze unless ``force`` is set.
        """
        if self.config.analysis_dir is None:
            raise GdbMcpError(
                "BAD_PARAMS",
                "analysis_dir is not configured; set GDB_MCP_ANALYSIS_DIR",
            )
        digest, size, selected, target_path = await self.runner.fingerprint(path, distro)
        analysis_id = "a-" + digest[:16]
        existing = self.store.records.get(analysis_id)
        if (
            existing is not None
            and existing.status == "ready"
            and self.store.dir_for(analysis_id).joinpath("index.json").is_file()
            and not force
        ):
            return existing
        record = existing or AnalysisRecord(
            analysis_id=analysis_id,
            sha256=digest,
            source_path=path,
            target_path=target_path,
            distro=selected,
            size=size,
        )
        record.source_path = path
        record.target_path = target_path
        record.distro = selected
        record.size = size
        record.status = "queued"
        record.error = None
        record.updated_at = time.time()
        self.store.put(record)
        running = self._tasks.get(analysis_id)
        if running is None or running.done():
            task = asyncio.create_task(self._run_analysis(record, language_id))
            self._tasks[analysis_id] = task
            task.add_done_callback(self._forget(self._tasks, analysis_id))
        return record

    async def _run_analysis(
        self, record: AnalysisRecord, language_id: str | None
    ) -> None:
        async with self._semaphore:
            record.status = "running"
            record.updated_at = time.time()
            if self.config.analysis_dir is None:
                record.status = "error"
                record.error = (
                    "analysis_dir is not configured; set GDB_MCP_ANALYSIS_DIR"
                )
                record.updated_at = time.time()
                return
            root = self.config.analysis_dir.resolve()
            staging = root / (
                ".%s.staging-%s" % (record.analysis_id, uuid.uuid4().hex[:8])
            )
            try:
                await asyncio.to_thread(staging.mkdir, parents=True)
                await self.runner.analyze(
                    record.target_path,
                    staging,
                    record.analysis_id,
                    record.distro,
                    language_id,
                )
                index = await asyncio.to_thread(
                    self.store.read_valid_index, staging / "index.json"
                )
                _tally(record, index)
                record.status = "ready"
                record.error = None
                record.updated_at = time.time()
                await asyncio.to_thread(self.store.promote, record, staging, index)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                record.status = "error"
                record.error = getattr(exc, "message", str(exc))
                record.updated_at = time.time()
            finally:
                await asyncio.to_thread(_discard, staging)

    # -- static queries -------------------------------------------------------

    def list_analyses(self) -> list[dict[str, Any]]:
        return self.store.list_public()

    def get_record(self, analysis_id: str) -> AnalysisRecord:
        return self.store.record(analysis_id)

    def index(self, analysis_id: str) -> dict[str, Any]:
        return self.store.index(analysis_id)

    def annotations(self, analysis_id: str) -> dict[str, Any]:
        return self.store.annotations(analysis_id)

    @staticmethod
    def _limit(limit: int, maximum: int = MAX_LIMIT) -> int:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= maximum
        ):
            raise GdbMcpError("BAD_PARAMS", "limit must be between 1 and %d" % maximum)
        return limit

    def overview(self, analysis_id: str) -> dict[str, Any]:
        index = self.store.index(analysis_id)
        return {
            **(index.get("binary") or {}),
            "analysis": self.get_record(analysis_id).public(),
            "counts": index.get("counts") or {},
        }

    def list_items(
        self,
        analysis_id: str,
        key: str,
        query: str | None = None,
        offset: int = 0,
        limit: int = DEFAULT_LIMIT,
    ) -> dict[str, Any]:
        limit = self._limit(limit)
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise GdbMcpError("BAD_PARAMS", "offset must be a non-negative integer")
        items = list(self.store.index(analysis_id).get(key) or [])
        if query:
            needle = query.casefold()
            items = [
                item
                for item in items
                if needle in json.dumps(item, ensure_ascii=False).casefold()
            ]
        return {key: items[offset : offset + limit], "total": len(items), "offset": offset}

    def _resolve_address(self, analysis_id: str, address: str | int) -> int:
        """Accept a number, a hex string, an annotation label or a function
        name — the forms an agent actually writes."""
        if isinstance(address, bool):
            raise GdbMcpError("BAD_PARAMS", "invalid address")
        if isinstance(address, int):
            return address
        text = str(address).strip()
        try:
            return int(text, 0)
        except ValueError:
            pass
        for addr, item in self.store.annotations(analysis_id).items():
            if item.get("label") == text:
                return int(addr, 16)
        names = self.store.function_index(analysis_id)[3]
        if text in names:
            return names[text]
        raise GdbMcpError("BAD_PARAMS", "unknown address or function %r" % address)

    def _function_summary(self, analysis_id: str, address: int) -> dict[str, Any] | None:
        """The tightest function containing ``address``, if any.

        Ghidra reports overlapping ranges (inlined and wrapper bodies), so
        "containing" is not enough: taking the smallest keeps the real code
        in view instead of an enclosing thunk.
        """
        starts, rows, prefix_ends, _ = self.store.function_index(analysis_id)
        position = bisect_right(starts, address) - 1
        containing = []
        while position >= 0 and prefix_ends[position] >= address:
            start, end, item = rows[position]
            if start <= address <= end:
                containing.append(item)
            position -= 1
        if not containing:
            return None
        return min(
            containing,
            key=lambda item: int(item.get("end", item["entry"]), 16) - int(item["entry"], 16),
        )

    def decompile(self, analysis_id: str, function: str | int) -> dict[str, Any]:
        address = self._resolve_address(analysis_id, function)
        summary = self._function_summary(analysis_id, address)
        if summary is None:
            raise GdbMcpError("NO_FUNCTION", "no function contains 0x%x" % address)
        entry = int(summary["entry"], 16)
        payload = self.store.function_payload(analysis_id, entry)
        if payload is None:
            payload = {
                **summary,
                "decompiled": False,
                "error": (
                    "external or thunk function"
                    if summary.get("external") or summary.get("thunk")
                    else "decompilation unavailable"
                ),
                "code": "",
                "lines": [],
                "instructions": [],
                "callers": [],
                "callees": [],
                "xrefs_to": [],
                "xrefs_from": [],
            }
        else:
            payload = dict(payload)
        annotation = self.store.annotation(analysis_id, "0x%x" % entry)
        payload["effective_name"] = annotation.get("label") or payload.get("name")
        payload["annotation"] = annotation
        return payload

    def static_disassembly(
        self, analysis_id: str, address: str | int, count: int = 32
    ) -> dict[str, Any]:
        count = self._limit(count, 4096)
        resolved = self._resolve_address(analysis_id, address)
        cached = self.store.disassembly(analysis_id)
        if cached is not None:
            addresses, items = cached
            start = bisect_left(addresses, resolved)
            instructions = items[start : start + count]
        else:
            function = self.decompile(analysis_id, resolved)
            instructions = [
                item
                for item in function.get("instructions") or []
                if int(item["address"], 16) >= resolved
            ][:count]
        return {"address": "0x%x" % resolved, "instructions": instructions}

    def xrefs(self, analysis_id: str, address: str | int, direction: str) -> dict[str, Any]:
        if direction not in {"to", "from", "both"}:
            raise GdbMcpError("BAD_PARAMS", "direction must be to, from, or both")
        function = self.decompile(analysis_id, address)
        result: dict[str, Any] = {"address": function["entry"]}
        if direction in {"to", "both"}:
            result["to"] = function.get("xrefs_to") or []
        if direction in {"from", "both"}:
            result["from"] = function.get("xrefs_from") or []
        return result

    def call_graph(
        self, analysis_id: str, function: str | int, direction: str, depth: int
    ) -> dict[str, Any]:
        if direction not in {"callers", "callees", "both"}:
            raise GdbMcpError("BAD_PARAMS", "direction must be callers, callees, or both")
        if isinstance(depth, bool) or not isinstance(depth, int) or not 1 <= depth <= 5:
            raise GdbMcpError("BAD_PARAMS", "depth must be between 1 and 5")
        start = self.decompile(analysis_id, function)
        queue = deque([(start["entry"], 0)])
        seen: set[str] = set()
        nodes: dict[str, dict[str, Any]] = {}
        edges: set[tuple[str, str]] = set()
        while queue and len(nodes) < MAX_GRAPH_NODES:
            entry, level = queue.popleft()
            if entry in seen:
                continue
            seen.add(entry)
            current = self.decompile(analysis_id, entry)
            nodes[entry] = {
                "entry": entry,
                "name": current.get("effective_name") or current.get("name"),
            }
            if level >= depth:
                continue
            around = []
            if direction in {"callees", "both"}:
                around += [("callee", item) for item in current.get("callees") or []]
            if direction in {"callers", "both"}:
                around += [("caller", item) for item in current.get("callers") or []]
            for kind, item in around:
                other = item["entry"]
                edges.add(
                    (entry, other) if kind == "callee" else (other, entry)
                )
                if self._function_summary(analysis_id, int(other, 16)):
                    queue.append((other, level + 1))
        return {
            "root": start["entry"],
            "nodes": list(nodes.values()),
            "edges": [{"from": source, "to": target} for source, target in sorted(edges)],
        }

    def search_code(
        self, analysis_id: str, query: str, regex: bool, limit: int
    ) -> dict[str, Any]:
        limit = self._limit(limit, MAX_SEARCH_RESULTS)
        if not query:
            raise GdbMcpError("BAD_PARAMS", "query is required")
        try:
            pattern = re.compile(query, re.IGNORECASE) if regex else None
        except re.error as exc:
            raise GdbMcpError("BAD_PARAMS", "invalid regex: %s" % exc) from None
        results: list[dict[str, Any]] = []
        for summary in self.store.index(analysis_id).get("functions") or []:
            if len(results) >= limit:
                break
            if not summary.get("decompiled"):
                continue
            function = self.decompile(analysis_id, int(summary["entry"], 16))
            for number, line in enumerate((function.get("code") or "").splitlines(), 1):
                matched = (
                    bool(pattern.search(line))
                    if pattern
                    else query.casefold() in line.casefold()
                )
                if matched:
                    results.append(
                        {
                            "function": function.get("effective_name"),
                            "entry": function["entry"],
                            "line": number,
                            "text": line,
                        }
                    )
                    if len(results) >= limit:
                        break
        return {"results": results, "truncated": len(results) == limit}

    def annotate(
        self,
        analysis_id: str,
        address: str | int,
        label: str | None,
        comment: str | None,
    ) -> dict[str, Any]:
        if label is None and comment is None:
            raise GdbMcpError("BAD_PARAMS", "label or comment is required")
        if label is not None and (not label.strip() or len(label) > 256):
            raise GdbMcpError("BAD_PARAMS", "label must be 1-256 characters")
        if comment is not None and len(comment) > 8192:
            raise GdbMcpError("BAD_PARAMS", "comment is too long")
        resolved = self._resolve_address(analysis_id, address)
        key = "0x%x" % resolved
        # read-modify-write, serialized: concurrent annotates of one analysis
        # must not lose each other's update
        with self.store.annotation_lock:
            annotations = self.store.annotations(analysis_id)
            item = annotations.get(key, {})
            if label is not None:
                item["label"] = label.strip()
            if comment is not None:
                item["comment"] = comment
            item["updated_at"] = time.time()
            annotations[key] = item
            self.store.save_annotations(analysis_id, annotations)
        return {"analysis_id": analysis_id, "address": key, "annotation": item}

    def remove_annotation(self, analysis_id: str, address: str | int) -> dict[str, Any]:
        resolved = self._resolve_address(analysis_id, address)
        key = "0x%x" % resolved
        with self.store.annotation_lock:
            annotations = self.store.annotations(analysis_id)
            removed = annotations.pop(key, None) is not None
            self.store.save_annotations(analysis_id, annotations)
        return {"analysis_id": analysis_id, "address": key, "removed": removed}


def _tally(record: AnalysisRecord, index: dict[str, Any]) -> None:
    """Fold an analysis' own counts into its record."""
    functions = index.get("functions") or []
    counts = index.get("counts") or {}
    record.function_count = len(functions)
    record.decompiled_count = int(
        counts.get("decompiled", sum(1 for item in functions if item.get("decompiled")))
    )
    record.failed_count = int(counts.get("failed", 0))
    record.partial = record.failed_count > 0


def _discard(staging: Path) -> None:
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)


__all__ = [
    "AnalysisManager",
    "AnalysisRecord",
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "MAX_SEARCH_RESULTS",
]
