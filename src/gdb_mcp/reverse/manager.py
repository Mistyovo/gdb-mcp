"""Static-bridge coordinator: analysis queueing and live location mapping.

Owns the *async* half of the static bridge — queueing Ghidra runs,
following session lifecycle events to attach an analysis to a session, and
mapping a runtime stop back to a static function and line.

Two collaborators take the rest: :class:`~gdb_mcp.reverse.store.AnalysisStore`
owns the on-disk cache and the in-memory indexes over it, and
:class:`~gdb_mcp.reverse.ghidra.GhidraRunner` owns the headless process.
Everything here is state that only exists while the server runs.
"""

from __future__ import annotations

import asyncio
from bisect import bisect_left, bisect_right
from collections import deque
import copy
from contextlib import suppress
import json
import logging
import re
import shutil
import time
import uuid
from pathlib import Path
from typing import Any, Coroutine

from gdb_mcp.config import Config
from gdb_mcp.errors import GdbMcpError
from gdb_mcp.events import EventBroker
from gdb_mcp.sessions import RUNNING, Session, SessionRegistry

from .ghidra import GhidraRunner
from .store import AnalysisRecord, AnalysisStore

log = logging.getLogger("gdb_mcp.reverse")

DEFAULT_LIMIT = 100
MAX_LIMIT = 1000
MAX_SEARCH_RESULTS = 200
MAX_GRAPH_NODES = 1000


class AnalysisManager:
    def __init__(self, config: Config, events: EventBroker | None = None):
        self.config = config
        self.events = events or EventBroker()
        self.runner = GhidraRunner(config)
        self.store = AnalysisStore(config)
        #: Ghidra runs are serialized: the analyzer is slow and memory-hungry
        self._semaphore = asyncio.Semaphore(1)
        self._tasks: dict[str, asyncio.Task] = {}
        self._attachments: dict[str, asyncio.Task] = {}
        self._attachment_targets: dict[str, str] = {}
        self._background: set[asyncio.Task] = set()
        self._registry: SessionRegistry | None = None
        self._event_queue: asyncio.Queue | None = None
        self._event_task: asyncio.Task | None = None
        self._probe_task: asyncio.Task | None = None
        self.backend_status: dict[str, Any] = {
            "name": "ghidra",
            "status": "unknown",
            "executable": None,
            "distro": None,
            "error": None,
        }

    # -- task bookkeeping -----------------------------------------------------

    def _spawn(self, coro: Coroutine[Any, Any, Any], name: str) -> asyncio.Task:
        """Run a background coroutine, keeping it referenced and its failure
        visible.

        A task nobody references can be garbage-collected mid-flight, and an
        exception nobody retrieves is dropped silently — both easy to hit in
        an event-driven coordinator.
        """
        task = asyncio.create_task(coro, name=name)
        self._background.add(task)

        def _done(finished: asyncio.Task) -> None:
            self._background.discard(finished)
            if finished.cancelled():
                return
            exc = finished.exception()
            if exc is not None:
                log.warning("background task %s failed: %s", name, exc)

        task.add_done_callback(_done)
        return task

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

    # -- lifecycle ------------------------------------------------------------

    async def start(self, registry: SessionRegistry) -> None:
        if self._event_task is not None:
            return
        self._registry = registry
        self._event_queue = self.events.subscribe()
        self._event_task = self._spawn(self._consume_events(), "reverse.events")
        self.backend_status["status"] = "checking"
        self._probe_task = self._spawn(self._probe_backend(), "reverse.probe")

    async def stop(self) -> None:
        if self._event_queue is not None:
            self.events.unsubscribe(self._event_queue)
        tracked = (
            [self._event_task, self._probe_task]
            + list(self._tasks.values())
            + list(self._attachments.values())
            + list(self._background)
        )
        for task in tracked:
            if task is not None:
                task.cancel()
        pending = [task for task in tracked if task is not None]
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        self._tasks.clear()
        self._attachments.clear()
        self._background.clear()

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

    # -- following sessions ---------------------------------------------------

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
            try:
                session = self._registry.get(data["session_id"])
            except GdbMcpError as exc:
                # the session was removed while this event waited its turn
                log.debug("dropping event for absent session: %s", exc.message)
                continue
            await self._on_session_event(session, data.get("event"))

    async def _on_session_event(self, session: Session, event_name: str | None) -> None:
        if event_name in {"connected", "ready", "target"}:
            target = session.info().get("inferior")
            if self.config.auto_analyze and target:
                self._schedule_attachment(session, target)
        if event_name == "running" and session.location:
            self._publish_location(session)
        elif event_name == "stop":
            self._spawn(self._resolve_stop(session), "reverse.resolve_stop")

    async def _resync_sessions(self) -> None:
        """Re-derive every session's location after the broker dropped
        events (a slow subscriber gets a resync marker, not a replay)."""
        if self._registry is None:
            return
        stopped = []
        for session in self._registry.list_all():
            target = session.info().get("inferior")
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
        # with no analysis for this module, fall back to the runtime text so
        # the stop is still readable
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
        current = self._attachments.get(session.session_id)
        if (
            self._attachment_targets.get(session.session_id) == target
            and current is not None
            and not current.done()
        ):
            return
        if session.analysis_id and self.store.matches_path(session.analysis_id, target):
            return
        self._attachment_targets[session.session_id] = target
        task = asyncio.create_task(self._attach_analysis(session, target))
        self._attachments[session.session_id] = task
        task.add_done_callback(self._forget(self._attachments, session.session_id))

    async def _attach_analysis(self, session: Session, target: str) -> None:
        try:
            record = await self.queue_analysis(target, distro=session.distro)
        except GdbMcpError as exc:
            session.attach_analysis(None, error=exc.message)
            self.events.publish(
                "analysis.updated",
                {
                    "session_id": session.session_id,
                    "status": "error",
                    "error": exc.message,
                },
            )
            return
        if self._attachment_targets.get(session.session_id) != target:
            return  # a newer target superseded this attachment
        session.attach_analysis(record.analysis_id)
        if session.stop_info:
            await self.refresh_session_location(session)

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
        self._publish_record(record)
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
            self._publish_record(record)
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
                if getattr(exc, "code", None) == "BACKEND_UNAVAILABLE":
                    self.backend_status.update(status="unavailable", error=record.error)
            finally:
                await asyncio.to_thread(_discard, staging)
                self._publish_record(record)
                if record.status == "ready":
                    self._reproject(record)

    def _reproject(self, record: AnalysisRecord) -> None:
        """An analysis just became ready: re-map the stops of the sessions
        that were waiting on it."""
        if self._registry is None:
            return
        for session in self._registry.list_all():
            if session.analysis_id == record.analysis_id and session.stop_info:
                self._spawn(self._resolve_stop(session), "reverse.resolve_stop")

    def _publish_record(self, record: AnalysisRecord) -> None:
        self.events.publish("analysis.updated", record.public())

    def _publish_location(self, session: Session) -> None:
        self.events.publish(
            "location.updated",
            {"session_id": session.session_id, "location": session.location},
        )

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
        resolved = self._resolve_address(analysis_id, address)
        key = "0x%x" % resolved
        with self.store.annotation_lock:
            annotations = self.store.annotations(analysis_id)
            removed = annotations.pop(key, None) is not None
            self.store.save_annotations(analysis_id, annotations)
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

    # -- runtime -> static location mapping -----------------------------------

    def analysis_for_module(self, module_path: str | None) -> str | None:
        return self.store.newest_for_path(module_path)

    def _runtime_location(
        self, session: Session, source: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Map one runtime frame description (pc + module + offset) to static
        code, or None when it carries no usable pc."""
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
        if session.analysis_id and self.store.matches_path(session.analysis_id, module_path):
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
                location.update(self._map_module_offset(analysis_id, module_offset))
        return location

    def _map_module_offset(self, analysis_id: str, module_offset: Any) -> dict[str, Any]:
        """Static address, function and best line for a module-relative
        offset — the slide from a runtime address back to link time.

        A line hit is preferred; failing that the closest preceding line
        (what a debugger would show), and failing that the nearest line.
        """
        image_base = int(
            (self.store.index(analysis_id).get("binary") or {}).get("image_base", "0x0"), 16
        )
        offset = (
            int(module_offset, 16) if isinstance(module_offset, str) else int(module_offset)
        )
        static_address = image_base + offset
        mapped: dict[str, Any] = {"static_address": "0x%x" % static_address}
        if self._function_summary(analysis_id, static_address) is None:
            return mapped
        function = self.decompile(analysis_id, static_address)
        mapped["function"] = function.get("effective_name") or function.get("name")
        mapped["function_entry"] = function["entry"]
        lines = [line for line in function.get("lines") or [] if line.get("min")]
        exact = [
            line
            for line in lines
            if int(line["min"], 16) <= static_address <= int(line.get("max", line["min"]), 16)
        ]
        chosen = (
            min(
                exact,
                key=lambda line: int(line.get("max", line["min"]), 16) - int(line["min"], 16),
            )
            if exact
            else None
        )
        if chosen is None:
            previous = [line for line in lines if int(line["min"], 16) <= static_address]
            chosen = (
                max(previous, key=lambda line: int(line["min"], 16)) if previous else None
            )
        if chosen is None and lines:
            chosen = min(lines, key=lambda line: abs(int(line["min"], 16) - static_address))
        if chosen:
            mapped["line"] = chosen["number"]
            mapped["exact"] = bool(exact)
        return mapped

    def _location_priority(self, location: dict[str, Any]) -> int:
        """Rank candidate frames so the reported location is the most
        debuggable one, not merely the innermost."""
        analysis_id = location.get("analysis_id")
        address = location.get("static_address")
        if not analysis_id or not address:
            return 9
        with suppress(Exception):
            value = int(address, 16)
            for section in self.store.index(analysis_id).get("sections") or []:
                if int(section["start"], 16) <= value <= int(section["end"], 16):
                    if section.get("name") == ".text":
                        return 0
                    if section.get("execute"):
                        return 1
                    return 2
        return 3

    def resolve_session_location(
        self, session: Session, *, publish: bool = True
    ) -> dict[str, Any] | None:
        """Map the session's current stop (and its backtrace) to static code
        and remember the result on the session.

        Every frame is a candidate; the one in real, analyzed code wins, so a
        libc return address does not hide the frame the agent cares about.
        """
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
        session.note_location(location)
        if publish:
            self._publish_location(session)
        return location

    async def refresh_session_location(self, session: Session) -> dict[str, Any] | None:
        """Resolve off the event loop: the mapping reads Ghidra artifacts
        from disk, and a stop notification must not wait on it."""
        location = await asyncio.to_thread(
            self.resolve_session_location, session, publish=False
        )
        self._publish_location(session)
        return location


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
