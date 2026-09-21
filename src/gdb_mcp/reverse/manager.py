"""Persistent headless-analysis cache and live location coordinator."""

from __future__ import annotations

import asyncio
from bisect import bisect_left, bisect_right
from collections import OrderedDict, deque
import copy
from contextlib import suppress
from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import re
import shutil
import threading
import time
from typing import Any
import uuid

from gdb_mcp.config import Config
from gdb_mcp.errors import GdbMcpError
from gdb_mcp.events import EventBroker
from gdb_mcp.sessions import RUNNING, Session, SessionRegistry

from .ghidra import GhidraRunner

SCHEMA_VERSION = 2
DEFAULT_LIMIT = 100
MAX_LIMIT = 1000
MAX_SEARCH_RESULTS = 200


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


class AnalysisManager:
    def __init__(self, config: Config, events: EventBroker | None = None):
        self.config = config
        self.events = events or EventBroker()
        self.runner = GhidraRunner(config)
        self._records: dict[str, AnalysisRecord] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._semaphore = asyncio.Semaphore(1)
        self._registry: SessionRegistry | None = None
        self._event_queue: asyncio.Queue | None = None
        self._event_task: asyncio.Task | None = None
        self._attachment_tasks: dict[str, asyncio.Task] = {}
        self._attachment_targets: dict[str, str] = {}
        self._probe_task: asyncio.Task | None = None
        self._index_cache: dict[str, dict[str, Any]] = {}
        self._function_cache: OrderedDict[tuple[str, int], dict[str, Any]] = OrderedDict()
        self._disassembly_cache: dict[str, tuple[list[int], list[dict[str, Any]]]] = {}
        self._annotation_cache: dict[str, dict[str, Any]] = {}
        self._function_indexes: dict[
            str, tuple[list[int], list[tuple[int, int, dict[str, Any]]], list[int], dict[str, int]]
        ] = {}
        self._cache_lock = threading.RLock()
        self.backend_status: dict[str, Any] = {
            "name": "ghidra",
            "status": "unknown",
            "executable": None,
            "distro": None,
            "error": None,
        }
        self._recover_cache_promotions()
        self._load_cache()

    def _recover_cache_promotions(self) -> None:
        """Restore a cache hidden by a process crash during directory promotion."""
        root = self.config.analysis_dir
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

    def _load_cache(self) -> None:
        root = self.config.analysis_dir
        if root is None or not root.is_dir():
            return
        for manifest_path in root.glob("a-*/manifest.json"):
            try:
                raw = json.loads(manifest_path.read_text(encoding="utf-8"))
                if raw.get("schema_version") != SCHEMA_VERSION:
                    continue
                fields = {key: raw[key] for key in AnalysisRecord.__dataclass_fields__ if key in raw}
                record = AnalysisRecord(**fields)
                index_path = manifest_path.parent / "index.json"
                if index_path.is_file():
                    self._validate_index(self._read_json(index_path))
                    record.status = "ready" if record.status in {"running", "queued"} else record.status
                self._records[record.analysis_id] = record
            except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, GdbMcpError):
                continue

    async def start(self, registry: SessionRegistry) -> None:
        if self._event_task is not None:
            return
        self._registry = registry
        self._event_queue = self.events.subscribe()
        self._event_task = asyncio.create_task(self._consume_events())
        self.backend_status["status"] = "checking"
        self._probe_task = asyncio.create_task(self._probe_backend())

    async def _probe_backend(self) -> None:
        try:
            executable, distro = await self.runner.detect()
        except Exception as exc:
            self.backend_status.update(status="unavailable", error=str(exc))
        else:
            self.backend_status.update(
                status="available" if executable else "unavailable",
                executable=executable,
                distro=distro,
                error=None if executable else "Ghidra Headless was not found",
            )
        self.events.publish("analysis.updated", {"backend": dict(self.backend_status)})

    async def stop(self) -> None:
        if self._event_queue is not None:
            self.events.unsubscribe(self._event_queue)
        if self._event_task is not None:
            self._event_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._event_task
        if self._probe_task is not None:
            self._probe_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._probe_task
        for task in tuple(self._tasks.values()):
            task.cancel()
        for task in tuple(self._attachment_tasks.values()):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        if self._attachment_tasks:
            await asyncio.gather(*self._attachment_tasks.values(), return_exceptions=True)

    async def _consume_events(self) -> None:
        assert self._event_queue is not None
        while True:
            event = await self._event_queue.get()
            if event["type"] == "resync":
                await self._resync_sessions()
                continue
            if event["type"] != "session.updated" or self._registry is None:
                continue
            data = event["data"]
            with suppress(Exception):
                session = self._registry.get(data["session_id"])
                event_name = data.get("event")
                if event_name in {"connected", "ready", "target"}:
                    target = session.target or session.info().get("inferior")
                    if self.config.auto_analyze and target:
                        self._schedule_attachment(session, target)
                if event_name == "running" and session.location:
                    self._publish_location(session)
                elif event_name == "stop":
                    asyncio.create_task(self._resolve_stop(session))

    async def _resync_sessions(self) -> None:
        if self._registry is None:
            return
        stopped = []
        for session in self._registry.list_all():
            target = session.target or session.info().get("inferior")
            if self.config.auto_analyze and target:
                self._schedule_attachment(session, target)
            if session.state == RUNNING and session.location:
                self._publish_location(session)
            elif session.stop_info:
                stopped.append(self._resolve_stop(session))
        if stopped:
            await asyncio.gather(*stopped, return_exceptions=True)

    async def _resolve_stop(self, session: Session) -> None:
        location = await self.refresh_session_location(session)
        if not location or location.get("analysis_id") or not location.get("runtime_pc"):
            return
        try:
            dynamic = await session.request(
                "disasm",
                {"start": location["runtime_pc"], "count": 48},
                timeout=self.config.request_timeout,
            )
        except Exception as exc:
            location["dynamic_disassembly_error"] = str(exc)
        else:
            location["dynamic_disassembly"] = dynamic
        self._publish_location(session)

    def _schedule_attachment(self, session: Session, target: str) -> None:
        current = self._attachment_tasks.get(session.session_id)
        if (
            self._attachment_targets.get(session.session_id) == target
            and current is not None
            and not current.done()
        ):
            return
        if session.analysis_id and self._record_matches_path(session.analysis_id, target):
            return
        self._attachment_targets[session.session_id] = target
        task = asyncio.create_task(self._attach_analysis(session, target))
        self._attachment_tasks[session.session_id] = task
        task.add_done_callback(
            lambda done, sid=session.session_id: self._attachment_tasks.pop(sid, None)
            if self._attachment_tasks.get(sid) is done
            else None
        )

    async def _attach_analysis(self, session: Session, target: str) -> None:
        try:
            record = await self.queue_analysis(target, distro=session.distro)
        except GdbMcpError as exc:
            session.analysis_error = exc.message
            self.events.publish(
                "analysis.updated",
                {"session_id": session.session_id, "status": "error", "error": exc.message},
            )
            return
        if self._attachment_targets.get(session.session_id) != target:
            return
        session.analysis_id = record.analysis_id
        session.analysis_error = None
        if session.stop_info:
            await self.refresh_session_location(session)

    def _analysis_dir(self, analysis_id: str) -> Path:
        if not re.fullmatch(r"a-[0-9a-f]{16}", analysis_id):
            raise GdbMcpError("NO_ANALYSIS", "invalid analysis id")
        return self.config.analysis_dir / analysis_id

    async def queue_analysis(
        self,
        path: str,
        distro: str | None = None,
        force: bool = False,
        language_id: str | None = None,
    ) -> AnalysisRecord:
        digest, size, selected, target_path = await self.runner.fingerprint(path, distro)
        analysis_id = "a-" + digest[:16]
        existing = self._records.get(analysis_id)
        final_dir = self._analysis_dir(analysis_id)
        if (
            existing is not None
            and existing.status == "ready"
            and final_dir.joinpath("index.json").is_file()
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
        self._records[analysis_id] = record
        self._publish_record(record)
        running = self._tasks.get(analysis_id)
        if running is None or running.done():
            task = asyncio.create_task(self._run_analysis(record, language_id))
            self._tasks[analysis_id] = task
            task.add_done_callback(lambda _task, aid=analysis_id: self._tasks.pop(aid, None))
        return record

    async def _run_analysis(
        self, record: AnalysisRecord, language_id: str | None
    ) -> None:
        async with self._semaphore:
            record.status = "running"
            record.updated_at = time.time()
            self._publish_record(record)
            root = self.config.analysis_dir.resolve()
            root.mkdir(parents=True, exist_ok=True)
            staging = root / (".%s.staging-%s" % (record.analysis_id, uuid.uuid4().hex[:8]))
            staging.mkdir(parents=True)
            try:
                await self.runner.analyze(
                    record.target_path,
                    staging,
                    record.analysis_id,
                    record.distro,
                    language_id,
                )
                index = await asyncio.to_thread(
                    self._read_valid_index, staging / "index.json"
                )
                functions = index.get("functions") or []
                counts = index.get("counts") or {}
                record.function_count = len(functions)
                record.decompiled_count = int(
                    counts.get("decompiled", sum(1 for item in functions if item.get("decompiled")))
                )
                record.failed_count = int(counts.get("failed", 0))
                record.partial = record.failed_count > 0
                record.status = "ready"
                record.error = None
                record.updated_at = time.time()
                await asyncio.to_thread(
                    self._promote_analysis_result, record, staging, index
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                record.status = "error"
                record.error = getattr(exc, "message", str(exc))
                record.updated_at = time.time()
                if getattr(exc, "code", None) == "BACKEND_UNAVAILABLE":
                    self.backend_status.update(status="unavailable", error=record.error)
            finally:
                if staging.exists():
                    await asyncio.to_thread(shutil.rmtree, staging, ignore_errors=True)
                self._publish_record(record)
                if record.status == "ready" and self._registry is not None:
                    for session in self._registry.list_all():
                        if session.analysis_id == record.analysis_id and session.stop_info:
                            asyncio.create_task(self._resolve_stop(session))

    def _read_valid_index(self, path: Path) -> dict[str, Any]:
        index = self._read_json(path)
        self._validate_index(index)
        return index

    def _promote_analysis_result(
        self,
        record: AnalysisRecord,
        staging: Path,
        index: dict[str, Any],
    ) -> None:
        root = self.config.analysis_dir.resolve()
        final_dir = root / record.analysis_id
        backup = root / (".%s.backup" % record.analysis_id)
        with self._cache_lock:
            if final_dir.joinpath("annotations.json").is_file():
                shutil.copy2(final_dir / "annotations.json", staging / "annotations.json")
            elif not staging.joinpath("annotations.json").exists():
                self._write_json(staging / "annotations.json", {})
            self._write_manifest(staging, record)
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
            self._invalidate_analysis_cache(record.analysis_id)
            self._store_index(record.analysis_id, index)

    def _write_manifest(self, directory: Path, record: AnalysisRecord) -> None:
        payload = {"schema_version": SCHEMA_VERSION, **record.public()}
        self._write_json(directory / "manifest.json", payload)

    @staticmethod
    def _validate_index(index: Any) -> None:
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

    def _invalidate_analysis_cache(self, analysis_id: str) -> None:
        with self._cache_lock:
            self._index_cache.pop(analysis_id, None)
            self._function_indexes.pop(analysis_id, None)
            self._disassembly_cache.pop(analysis_id, None)
            self._annotation_cache.pop(analysis_id, None)
            for key in [key for key in self._function_cache if key[0] == analysis_id]:
                self._function_cache.pop(key, None)

    def _store_index(self, analysis_id: str, index: dict[str, Any]) -> None:
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
        with self._cache_lock:
            self._index_cache[analysis_id] = index
            self._function_indexes[analysis_id] = (starts, rows, prefix_ends, names)

    @staticmethod
    def _read_json(path: Path) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise GdbMcpError("ANALYSIS_CORRUPT", "cannot read %s" % path.name) from exc

    @staticmethod
    def _write_json(path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(path.suffix + ".tmp")
        temp.write_text(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        os.replace(temp, path)

    def _publish_record(self, record: AnalysisRecord) -> None:
        self.events.publish("analysis.updated", record.public())

    def _publish_location(self, session: Session) -> None:
        self.events.publish(
            "location.updated",
            {"session_id": session.session_id, "location": session.location},
        )

    def list_analyses(self) -> list[dict[str, Any]]:
        return [
            record.public()
            for record in sorted(self._records.values(), key=lambda item: item.updated_at, reverse=True)
        ]

    def get_record(self, analysis_id: str) -> AnalysisRecord:
        try:
            return self._records[analysis_id]
        except KeyError:
            raise GdbMcpError("NO_ANALYSIS", "unknown analysis %r" % analysis_id) from None

    def _ready_dir(self, analysis_id: str) -> Path:
        record = self.get_record(analysis_id)
        directory = self._analysis_dir(analysis_id)
        if not directory.joinpath("index.json").is_file():
            raise GdbMcpError(
                "ANALYSIS_NOT_READY", "analysis is %s" % record.status
            )
        return directory

    def index(self, analysis_id: str) -> dict[str, Any]:
        with self._cache_lock:
            cached = self._index_cache.get(analysis_id)
        if cached is not None:
            return cached
        index = self._read_json(self._ready_dir(analysis_id) / "index.json")
        self._validate_index(index)
        self._store_index(analysis_id, index)
        return index

    def annotations(self, analysis_id: str) -> dict[str, Any]:
        with self._cache_lock:
            return copy.deepcopy(self._cached_annotations(analysis_id))

    def _cached_annotations(self, analysis_id: str) -> dict[str, Any]:
        cached = self._annotation_cache.get(analysis_id)
        if cached is None:
            path = self._ready_dir(analysis_id) / "annotations.json"
            cached = self._read_json(path) if path.exists() else {}
            if not isinstance(cached, dict):
                raise GdbMcpError("ANALYSIS_CORRUPT", "annotations must be an object")
            self._annotation_cache[analysis_id] = cached
        return cached

    @staticmethod
    def _limit(limit: int, maximum: int = MAX_LIMIT) -> int:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= maximum:
            raise GdbMcpError("BAD_PARAMS", "limit must be between 1 and %d" % maximum)
        return limit

    def overview(self, analysis_id: str) -> dict[str, Any]:
        index = self.index(analysis_id)
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
        items = list(self.index(analysis_id).get(key) or [])
        if query:
            needle = query.casefold()
            items = [item for item in items if needle in json.dumps(item, ensure_ascii=False).casefold()]
        return {key: items[offset : offset + limit], "total": len(items), "offset": offset}

    def _resolve_address(self, analysis_id: str, address: str | int) -> int:
        if isinstance(address, bool):
            raise GdbMcpError("BAD_PARAMS", "invalid address")
        if isinstance(address, int):
            return address
        text = str(address).strip()
        try:
            return int(text, 0)
        except ValueError:
            annotations = self.annotations(analysis_id)
            for addr, item in annotations.items():
                if item.get("label") == text:
                    return int(addr, 16)
            self.index(analysis_id)
            names = self._function_indexes[analysis_id][3]
            if text in names:
                return names[text]
        raise GdbMcpError("BAD_PARAMS", "unknown address or function %r" % address)

    def _function_summary(self, analysis_id: str, address: int) -> dict[str, Any] | None:
        self.index(analysis_id)
        starts, rows, prefix_ends, _ = self._function_indexes[analysis_id]
        position = bisect_right(starts, address) - 1
        containing = []
        while position >= 0 and prefix_ends[position] >= address:
            start, end, item = rows[position]
            if start <= address <= end:
                containing.append(item)
            position -= 1
        if containing:
            return min(containing, key=lambda item: int(item.get("end", item["entry"]), 16) - int(item["entry"], 16))
        return None

    def decompile(self, analysis_id: str, function: str | int) -> dict[str, Any]:
        address = self._resolve_address(analysis_id, function)
        summary = self._function_summary(analysis_id, address)
        if summary is None:
            raise GdbMcpError("NO_FUNCTION", "no function contains 0x%x" % address)
        entry = int(summary["entry"], 16)
        path = self._ready_dir(analysis_id) / "functions" / ("%x.json" % entry)
        if path.is_file():
            cache_key = (analysis_id, entry)
            with self._cache_lock:
                raw = self._function_cache.get(cache_key)
                if raw is not None:
                    self._function_cache.move_to_end(cache_key)
            if raw is None:
                raw = self._read_json(path)
                if not isinstance(raw, dict):
                    raise GdbMcpError("ANALYSIS_CORRUPT", "function data must be an object")
                with self._cache_lock:
                    self._function_cache[cache_key] = raw
                    self._function_cache.move_to_end(cache_key)
                    while len(self._function_cache) > 512:
                        self._function_cache.popitem(last=False)
            payload = dict(raw)
        else:
            payload = {
                **summary,
                "decompiled": False,
                "error": "external or thunk function" if summary.get("external") or summary.get("thunk") else "decompilation unavailable",
                "code": "",
                "lines": [],
                "instructions": [],
                "callers": [],
                "callees": [],
                "xrefs_to": [],
                "xrefs_from": [],
            }
        with self._cache_lock:
            annotation = dict(
                self._cached_annotations(analysis_id).get("0x%x" % entry, {})
            )
        payload["effective_name"] = annotation.get("label") or payload.get("name")
        payload["annotation"] = annotation
        return payload

    def static_disassembly(
        self, analysis_id: str, address: str | int, count: int = 32
    ) -> dict[str, Any]:
        count = self._limit(count, 4096)
        resolved = self._resolve_address(analysis_id, address)
        disassembly_path = self._ready_dir(analysis_id) / "disassembly.json"
        if disassembly_path.is_file():
            with self._cache_lock:
                cached = self._disassembly_cache.get(analysis_id)
            if cached is None:
                payload = self._read_json(disassembly_path)
                if (
                    not isinstance(payload, dict)
                    or payload.get("schema_version") != SCHEMA_VERSION
                    or not isinstance(payload.get("instructions"), list)
                ):
                    raise GdbMcpError("ANALYSIS_CORRUPT", "invalid disassembly index")
                items = sorted(
                    payload["instructions"], key=lambda item: int(item["address"], 16)
                )
                cached = ([int(item["address"], 16) for item in items], items)
                with self._cache_lock:
                    self._disassembly_cache[analysis_id] = cached
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
        result = {"address": function["entry"]}
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
        while queue and len(nodes) < 1000:
            entry, level = queue.popleft()
            if entry in seen:
                continue
            seen.add(entry)
            current = self.decompile(analysis_id, entry)
            nodes[entry] = {"entry": entry, "name": current.get("effective_name") or current.get("name")}
            if level >= depth:
                continue
            if direction in {"callees", "both"}:
                for item in current.get("callees") or []:
                    target = item["entry"]
                    edges.add((entry, target))
                    if self._function_summary(analysis_id, int(target, 16)):
                        queue.append((target, level + 1))
            if direction in {"callers", "both"}:
                for item in current.get("callers") or []:
                    source = item["entry"]
                    edges.add((source, entry))
                    if self._function_summary(analysis_id, int(source, 16)):
                        queue.append((source, level + 1))
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
        results = []
        for summary in self.index(analysis_id).get("functions") or []:
            if len(results) >= limit:
                break
            if not summary.get("decompiled"):
                continue
            function = self.decompile(analysis_id, int(summary["entry"], 16))
            for number, line in enumerate((function.get("code") or "").splitlines(), 1):
                matched = bool(pattern.search(line)) if pattern else query.casefold() in line.casefold()
                if matched:
                    results.append(
                        {"function": function.get("effective_name"), "entry": function["entry"], "line": number, "text": line}
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
        with self._cache_lock:
            resolved = self._resolve_address(analysis_id, address)
            if label is None and comment is None:
                raise GdbMcpError("BAD_PARAMS", "label or comment is required")
            if label is not None and (not label.strip() or len(label) > 256):
                raise GdbMcpError("BAD_PARAMS", "label must be 1-256 characters")
            if comment is not None and len(comment) > 8192:
                raise GdbMcpError("BAD_PARAMS", "comment is too long")
            annotations = self.annotations(analysis_id)
            key = "0x%x" % resolved
            item = annotations.get(key, {})
            if label is not None:
                item["label"] = label.strip()
            if comment is not None:
                item["comment"] = comment
            item["updated_at"] = time.time()
            annotations[key] = item
            self._write_json(self._ready_dir(analysis_id) / "annotations.json", annotations)
            self._annotation_cache[analysis_id] = annotations
        summary = self._function_summary(analysis_id, resolved)
        self.events.publish(
            "annotation.updated",
            {
                "analysis_id": analysis_id,
                "address": key,
                "annotation": item,
                "effective_name": item.get("label") or (summary or {}).get("name"),
            },
        )
        return {"analysis_id": analysis_id, "address": key, "annotation": item}

    def remove_annotation(self, analysis_id: str, address: str | int) -> dict[str, Any]:
        with self._cache_lock:
            resolved = self._resolve_address(analysis_id, address)
            key = "0x%x" % resolved
            annotations = self.annotations(analysis_id)
            removed = annotations.pop(key, None) is not None
            self._write_json(self._ready_dir(analysis_id) / "annotations.json", annotations)
            self._annotation_cache[analysis_id] = annotations
        summary = self._function_summary(analysis_id, resolved)
        self.events.publish(
            "annotation.updated",
            {
                "analysis_id": analysis_id,
                "address": key,
                "annotation": None,
                "effective_name": (summary or {}).get("name"),
            },
        )
        return {"analysis_id": analysis_id, "address": key, "removed": removed}

    @staticmethod
    def _path_key(path: str | None) -> str:
        if not path:
            return ""
        normalized = str(path).replace("\\", "/").rstrip("/")
        if re.match(r"^[A-Za-z]:/", normalized) or normalized.startswith("//"):
            return normalized.casefold()
        return normalized

    def _record_matches_path(self, analysis_id: str, path: str | None) -> bool:
        record = self._records.get(analysis_id)
        if record is None or not path:
            return False
        key = self._path_key(path)
        candidates = {self._path_key(record.source_path), self._path_key(record.target_path)}
        return key in candidates

    def analysis_for_module(self, module_path: str | None) -> str | None:
        ready = [record for record in self._records.values() if record.status == "ready"]
        ready.sort(key=lambda item: item.updated_at, reverse=True)
        for record in ready:
            if self._record_matches_path(record.analysis_id, module_path):
                return record.analysis_id
        return None

    def _runtime_location(
        self, session: Session, source: dict[str, Any]
    ) -> dict[str, Any] | None:
        pc_text = source.get("pc")
        if not pc_text:
            return None
        try:
            runtime_pc = int(pc_text, 16)
        except (TypeError, ValueError):
            return None
        module_offset = source.get("module_offset")
        module_path = source.get("module_path")
        analysis_id = None
        if session.analysis_id and self._record_matches_path(session.analysis_id, module_path):
            analysis_id = session.analysis_id
        elif module_path:
            analysis_id = self.analysis_for_module(module_path)
        location: dict[str, Any] = {
            "runtime_pc": "0x%x" % runtime_pc,
            "module": module_path,
            "module_base": source.get("module_base"),
            "module_offset": module_offset,
            "analysis_id": analysis_id,
            "state": session.state,
            "stale": session.state == RUNNING,
            "exact": False,
        }
        if analysis_id and module_offset is not None:
            with suppress(Exception):
                index = self.index(analysis_id)
                image_base = int((index.get("binary") or {}).get("image_base", "0x0"), 16)
                offset = int(module_offset, 16) if isinstance(module_offset, str) else int(module_offset)
                static_address = image_base + offset
                location["static_address"] = "0x%x" % static_address
                summary = self._function_summary(analysis_id, static_address)
                if summary:
                    function = self.decompile(analysis_id, static_address)
                    location["function"] = function.get("effective_name") or function.get("name")
                    location["function_entry"] = function["entry"]
                    lines = [line for line in function.get("lines") or [] if line.get("min")]
                    exact = [line for line in lines if int(line["min"], 16) <= static_address <= int(line.get("max", line["min"]), 16)]
                    chosen = min(exact, key=lambda line: int(line.get("max", line["min"]), 16) - int(line["min"], 16)) if exact else None
                    if chosen is None:
                        previous = [line for line in lines if int(line["min"], 16) <= static_address]
                        chosen = max(previous, key=lambda line: int(line["min"], 16)) if previous else None
                    if chosen is None and lines:
                        chosen = min(
                            lines,
                            key=lambda line: abs(int(line["min"], 16) - static_address),
                        )
                    if chosen:
                        location["line"] = chosen["number"]
                        location["exact"] = bool(exact)
        return location

    def _location_priority(self, location: dict[str, Any]) -> int:
        analysis_id = location.get("analysis_id")
        address = location.get("static_address")
        if not analysis_id or not address:
            return 9
        with suppress(Exception):
            value = int(address, 16)
            sections = self.index(analysis_id).get("sections") or []
            for section in sections:
                start = int(section["start"], 16)
                end = int(section["end"], 16)
                if start <= value <= end:
                    if section.get("name") == ".text":
                        return 0
                    if section.get("execute"):
                        return 1
                    return 2
        return 3

    def resolve_session_location(
        self, session: Session, *, publish: bool = True
    ) -> dict[str, Any] | None:
        stop = session.stop_info or {}
        actual = self._runtime_location(session, stop)
        if actual is None:
            return session.location
        actual["actual_stop"] = True
        actual["frame_level"] = 0

        candidates: list[dict[str, Any]] = [actual]
        debug_state = session.debug_state
        if isinstance(debug_state, dict):
            debug_state["stop_location"] = copy.deepcopy(actual)
            for frame in debug_state.get("frames") or []:
                if not isinstance(frame, dict):
                    continue
                frame_location = self._runtime_location(session, frame)
                if frame_location is None:
                    continue
                frame_location["frame_level"] = frame.get("level")
                frame["location"] = frame_location
                candidates.append(frame_location)

        analyzed = [item for item in candidates if item.get("analysis_id")]
        location = min(
            analyzed,
            key=lambda item: (
                self._location_priority(item),
                int(item.get("frame_level") or 0),
            ),
            default=actual,
        )
        location = copy.deepcopy(location)
        location["stop_runtime_pc"] = actual["runtime_pc"]
        location["actual_stop"] = location.get("frame_level") == 0
        session.location = location
        session.update_debug_location(location)
        if publish:
            self._publish_location(session)
        return location

    async def refresh_session_location(self, session: Session) -> dict[str, Any] | None:
        location = await asyncio.to_thread(
            self.resolve_session_location, session, publish=False
        )
        self._publish_location(session)
        return location


__all__ = [
    "AnalysisManager",
    "AnalysisRecord",
    "DEFAULT_LIMIT",
    "MAX_LIMIT",
    "MAX_SEARCH_RESULTS",
]
