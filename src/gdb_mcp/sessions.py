"""Server-side session model and registry.

A :class:`Session` represents one gdb plugin connection (or one launched
process). The plugin is authoritative for inferior state; the server mirrors
it from ``notification`` messages and optimistically marks ``running`` when
an execution verb is accepted.

State machine::

    RESERVED (launch_gdb, hello pending) ──hello──▶ CONNECTING ──ready/prompt──▶ READY
    READY/STOPPED ──continue accepted──▶ RUNNING ──stop──▶ STOPPED ──prompt──▶ READY
    RUNNING/READY/STOPPED ──exited──▶ EXITED
    any ──socket closed──▶ DISCONNECTED (GC'd later; a re-hello can revive a
                                        RESERVED/DISCONNECTED session id)
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from gdb_mcp.config import Config
from gdb_mcp.errors import (
    AmbiguousSessionError,
    GdbMcpError,
    NoSessionsError,
    NoSuchSessionError,
    RequestTimeoutError,
)
from gdb_mcp.journal import Journal
from gdb_mcp.protocol import (
    ASYNC_VERBS,
    build_quit,
    build_request,
    encode,
    is_ok_response,
)

log = logging.getLogger("gdb_mcp.sessions")

#: Session states.
CONNECTING = "connecting"
READY = "ready"
RUNNING = "running"
STOPPED = "stopped"
EXITED = "exited"
DISCONNECTED = "disconnected"
RESERVED = "reserved"

#: States in which the inferior is not executing (safe to query state).
STOPPED_STATES = frozenset({CONNECTING, READY, STOPPED, EXITED})

#: States in which a session counts as a live gdb session for auto-select.
ACTIVE_STATES = frozenset({CONNECTING, READY, RUNNING, STOPPED, EXITED})

#: Maximum number of events kept per session for get_events.
EVENT_LOG_LIMIT = 100


@dataclass
class Session:
    session_id: str
    kind: str = "gdb"  # "gdb" | "script"
    state: str = CONNECTING
    hello: dict | None = None
    stop_info: dict | None = None
    exited_code: int | None = None
    writer: Any = None
    reader_task: Any = None
    hb_task: Any = None
    proc: Any = None
    proc_task: Any = None
    proc_returncode: int | None = None
    launched: bool = False
    reserved: bool = False
    log_file: str | None = None
    distro: str | None = None
    token: str | None = None
    created_at: float = field(default_factory=time.monotonic)
    connected_at: float | None = None
    last_seen: float | None = None

    #: serialize socket writes and atomic composite operations
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    #: req_id -> future, completed by the tcp_listener dispatch
    pending: dict[int, asyncio.Future] = field(default_factory=dict)
    #: stop-notification generation + condition for wait_for_stop
    stop_cond: asyncio.Condition = field(default_factory=asyncio.Condition)
    stop_gen: int = 0
    #: incremented only by authoritative plugin/lifecycle events
    state_gen: int = 0
    #: ring of protocol/lifecycle events, newest last (for get_events)
    event_log: deque = field(
        default_factory=lambda: deque(maxlen=EVENT_LOG_LIMIT)
    )
    event_seq: int = 0
    #: per-session JSONL journal (audit + gdbscript export), if enabled
    journal: Any = None
    #: structured exploit-campaign state (campaign tool / brief injection)
    campaign: dict = field(
        default_factory=lambda: {
            "protections": {},
            "libc": {},
            "offsets": {},
            "primitives": {},
            "notes": [],
        }
    )

    _next_id: int = field(default=1, init=False)

    # -- request/response ---------------------------------------------------

    async def request(
        self,
        verb: str,
        params: dict | None = None,
        timeout: float | None = None,
        *,
        locked: bool = False,
    ) -> dict:
        """Send a request to the plugin and await its response.

        Returns the ``result`` payload on success. Raises
        :class:`GdbMcpError` on plugin-reported errors,
        :class:`RequestTimeoutError` on timeout, and a ``DISCONNECTED``
        error when the plugin is not connected.

        ``locked=True`` means the caller already holds ``self.lock`` (used
        by composite tools like crash_report to keep a multi-request
        sequence atomic).
        """
        req_id = self._next_id
        self._next_id += 1
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self.pending[req_id] = fut
        previous_state = self.state
        request_state_gen = self.state_gen
        try:
            if locked:
                writer = self._connected_writer()
                if verb in ASYNC_VERBS:
                    self.state = RUNNING
                writer.write(encode(build_request(req_id, verb, params), self.token))
                await writer.drain()
            else:
                async with self.lock:
                    writer = self._connected_writer()
                    if verb in ASYNC_VERBS:
                        self.state = RUNNING
                    writer.write(encode(build_request(req_id, verb, params), self.token))
                    await writer.drain()
            result = await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            self._journal_request(verb, params, ok=False, error="TIMEOUT")
            raise RequestTimeoutError(verb, timeout or 0.0) from None
        except (ConnectionError, OSError) as exc:
            if verb in ASYNC_VERBS and self.state_gen == request_state_gen:
                self.state = previous_state
            self._journal_request(verb, params, ok=False, error="DISCONNECTED")
            raise GdbMcpError("DISCONNECTED", "connection to gdb lost") from exc
        except GdbMcpError as exc:
            if verb in ASYNC_VERBS and self.state_gen == request_state_gen:
                self.state = previous_state
            self._journal_request(verb, params, ok=False, error=exc.code)
            raise
        finally:
            self.pending.pop(req_id, None)
        self._journal_request(verb, params, ok=True, result=result)
        return result

    def _journal_request(
        self, verb: str, params: dict, ok: bool, result=None, error=None
    ) -> None:
        if self.journal is None:
            return
        data: dict = {"verb": verb, "params": params, "ok": ok}
        if error:
            data["error"] = error
        if result is not None:
            data["result"] = result
        self.journal.append("request", data)

    def _connected_writer(self) -> Any:
        writer = self.writer
        if writer is None or self.state == DISCONNECTED:
            raise GdbMcpError(
                "DISCONNECTED", f"session {self.session_id!r} is not connected"
            )
        return writer

    async def send_quit(self, kill_gdb: bool = False) -> None:
        """Send the one-way ``quit`` message (no response expected; the
        plugin closes the connection after shutting down)."""
        async with self.lock:
            writer = self._connected_writer()
            writer.write(encode(build_quit("server_quit", kill_gdb), self.token))
            await writer.drain()

    async def complete_response(self, req_id: int, msg: dict) -> None:
        """Complete the pending future for ``req_id`` (called by the
        tcp_listener). Late/unknown responses are dropped."""
        fut = self.pending.pop(req_id, None)
        if fut is None or fut.done():
            return
        if is_ok_response(msg):
            fut.set_result(msg.get("result", {}))
        else:
            err = msg.get("error") or {}
            fut.set_exception(
                GdbMcpError(
                    err.get("code", "PLUGIN_ERROR"),
                    err.get("message", "unknown plugin error"),
                )
            )

    # -- notifications ------------------------------------------------------

    def record_event(self, event: str, payload: dict) -> None:
        """Append to the per-session event ring (get_events reads it)."""
        self.event_seq += 1
        self.event_log.append(
            {
                "seq": self.event_seq,
                "ts": round(time.time(), 3),
                "event": event,
                "payload": payload,
            }
        )

    def recent_events(self, last: int = 20) -> list[dict]:
        """The most recent ``last`` events, oldest first."""
        last = max(0, last)
        if not last:
            return []
        return list(self.event_log)[-last:]

    async def push_notification(self, event: str, payload: dict) -> None:
        """Apply a plugin notification (called by the tcp_listener)."""
        self.state_gen += 1
        self.record_event(event, payload)
        if self.journal is not None:
            self.journal.append(
                "notification", {"event": event, "payload": payload}
            )
        if event == "running":
            self.state = RUNNING
        elif event == "stop":
            self.state = STOPPED
            self.stop_info = payload
            await self._wake_stop_waiters()
        elif event == "exited":
            self.state = EXITED
            self.exited_code = payload.get("exit_code")
            await self._wake_stop_waiters()
        elif event in ("prompt", "ready"):
            # Inferior is idle at the prompt; keep stop_info for
            # get_stop_reason.
            self.state = READY
            await self._wake_stop_waiters()
        else:
            log.debug("session %s: unknown notification event %r", self.session_id, event)

    async def _wake_stop_waiters(self) -> None:
        async with self.stop_cond:
            self.stop_gen += 1
            self.stop_cond.notify_all()

    async def wait_for_stop(self, timeout: float) -> bool:
        """Wait until the inferior stops (or gdb is idle/exited).

        Returns True if stopped; False on timeout or disconnect.
        """
        async with self.stop_cond:
            if self.state in STOPPED_STATES:
                return True
            gen = self.stop_gen
            try:
                await asyncio.wait_for(
                    self.stop_cond.wait_for(
                        lambda: self.stop_gen != gen
                        or self.state in STOPPED_STATES
                        or self.state == DISCONNECTED
                    ),
                    timeout,
                )
            except asyncio.TimeoutError:
                return False
            return self.state in STOPPED_STATES

    # -- lifecycle ----------------------------------------------------------

    def update_seen(self) -> None:
        self.last_seen = time.monotonic()

    async def on_disconnect(self) -> None:
        """Socket closed: fail pending requests, wake stop waiters."""
        self.state = DISCONNECTED
        self.state_gen += 1
        self.record_event("disconnected", {})
        self.writer = None
        for fut in self.pending.values():
            if not fut.done():
                fut.set_exception(
                    GdbMcpError(
                        "DISCONNECTED", "connection to gdb lost"
                    )
                )
        self.pending.clear()
        await self._wake_stop_waiters()

    def info(self) -> dict:
        """Compact dict for list_sessions / session_status tools."""
        hello = self.hello or {}
        return {
            "session_id": self.session_id,
            "kind": self.kind,
            "state": self.state,
            "gdb_pid": hello.get("pid"),
            "inferior": hello.get("inferior"),
            "arch": hello.get("arch"),
            "gdb_version": hello.get("gdb_version"),
            "pwndbg": hello.get("pwndbg"),
            "log_file": self.log_file,
            "distro": self.distro,
            "launched": self.launched,
            "proc_running": (
                getattr(self.proc, "returncode", None) is None if self.proc else None
            ),
            "proc_returncode": self.proc_returncode,
            "last_stop": self.stop_info,
        }


class SessionRegistry:
    def __init__(
        self,
        config: Config,
        session_id_factory: Any = None,
    ):
        self.config = config
        self._factory = session_id_factory or (
            lambda: "s-" + uuid.uuid4().hex[:8]
        )
        self._sessions: dict[str, Session] = {}
        self._by_pid: dict[int, str] = {}
        self._persist_path: Path | None = None

    # -- registration -------------------------------------------------------

    def new_session_id(self, exclude: set[str] | None = None) -> str:
        excluded = exclude or set()
        while True:
            sid = self._factory()
            if sid not in self._sessions and sid not in excluded:
                return sid

    def reserve(
        self,
        session_id: str,
        kind: str = "gdb",
        log_file: str | None = None,
        *,
        launched: bool = True,
    ) -> Session:
        """Create a session placeholder for a launch whose plugin will
        connect later (hello carries the same session id via env)."""
        session = Session(
            session_id=session_id,
            kind=kind,
            state=RESERVED,
            reserved=True,
            launched=launched,
            log_file=log_file,
            token=self.config.token,
        )
        self._sessions[session_id] = session
        self._attach_journal(session)
        self.save()
        return session

    def _attach_journal(self, session: Session) -> None:
        if session.journal is None:
            session.journal = Journal(
                self.config.log_dir
                / "journals"
                / ("%s.jsonl" % session.session_id)
            )

    def register_hello(self, hello: dict, writer: Any) -> Session:
        """Register a plugin connection from its hello message.

        Binds to an existing RESERVED/DISCONNECTED session when the hello
        carries the matching ``session_id`` (launch flow / reconnection);
        otherwise creates a new session. If the target session has a live
        writer, the old connection is closed.
        """
        session = None
        sid = hello.get("session_id")
        if sid and sid in self._sessions:
            existing = self._sessions[sid]
            if existing.state in (RESERVED, DISCONNECTED) or existing.writer is None:
                session = existing
                if session.writer is not None:
                    session.writer.close()  # stale socket; its reader dies
        if session is None:
            session = Session(
                session_id=self.new_session_id(),
                kind="gdb",
                launched=False,
                token=self.config.token,
            )
            self._sessions[session.session_id] = session
        old_pid = (session.hello or {}).get("pid")
        if isinstance(old_pid, int) and self._by_pid.get(old_pid) == session.session_id:
            self._by_pid.pop(old_pid, None)
        session.hello = hello
        session.writer = writer
        session.token = self.config.token
        session.state = CONNECTING
        session.reserved = False
        session.connected_at = time.monotonic()
        session.update_seen()
        pid = hello.get("pid")
        if isinstance(pid, int):
            self._by_pid[pid] = session.session_id
        session.record_event(
            "connected",
            {
                "pid": pid,
                "inferior": hello.get("inferior"),
                "pwndbg": hello.get("pwndbg"),
            },
        )
        self._attach_journal(session)
        self.save()
        log.debug(
            "hello from pid=%s arch=%s -> session %s",
            pid,
            hello.get("arch"),
            session.session_id,
        )
        return session

    # -- lookup -------------------------------------------------------------

    def get(self, session_id: str) -> Session:
        try:
            return self._sessions[session_id]
        except KeyError:
            raise NoSuchSessionError(session_id) from None

    def by_pid(self, pid: int) -> Session | None:
        sid = self._by_pid.get(pid)
        return self._sessions.get(sid) if sid else None

    def resolve(
        self, session_id: str | None = None, kind: str | None = "gdb"
    ) -> Session:
        """Get an explicit session, or auto-select when exactly one live
        session exists (of ``kind`` when given, of any kind when None)."""
        if session_id:
            return self.get(session_id)
        live = [
            s
            for s in self._sessions.values()
            if s.state in ACTIVE_STATES and (kind is None or s.kind == kind)
        ]
        if not live:
            raise NoSessionsError(
                "launch one with launch_gdb, or start gdb with the plugin loaded"
            )
        if len(live) == 1:
            return live[0]
        raise AmbiguousSessionError([s.session_id for s in live])

    def list_all(self) -> list[Session]:
        return list(self._sessions.values())

    def list_live(self, kind: str = "gdb") -> list[Session]:
        return [
            s
            for s in self._sessions.values()
            if s.kind == kind and s.state in ACTIVE_STATES
        ]

    # -- lifecycle ----------------------------------------------------------

    def remove(self, session_id: str) -> None:
        session = self._sessions.pop(session_id, None)
        if session is not None and session.hello:
            pid = session.hello.get("pid")
            if isinstance(pid, int) and self._by_pid.get(pid) == session_id:
                self._by_pid.pop(pid, None)
        self.save()

    # -- persistence ----------------------------------------------------------
    #
    # The server is restarted far more often than its gdbs are stopped
    # (it tracks an editor session). Persisting gdb session identity
    # lets a plugin's re-hello reattach to the SAME session id instead
    # of forking a new anonymous one.

    def enable_persistence(self, path: Path) -> int:
        """Track gdb sessions in ``path`` and restore any previously
        persisted ones as DISCONNECTED (a re-hello revives them)."""
        self._persist_path = Path(path)
        return self.load()

    def save(self) -> None:
        if self._persist_path is None:
            return
        payload = {
            "version": 1,
            "sessions": [
                {
                    "session_id": s.session_id,
                    "log_file": s.log_file,
                    "distro": s.distro,
                    "launched": s.launched,
                    "hello": s.hello,
                    "stop_info": s.stop_info,
                    "campaign": s.campaign,
                }
                for s in self._sessions.values()
                if s.kind == "gdb"
            ],
        }
        try:
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._persist_path.with_suffix(".json.tmp")
            tmp.write_text(
                json.dumps(payload, ensure_ascii=False), encoding="utf-8"
            )
            tmp.replace(self._persist_path)
        except OSError:
            log.warning("session persistence write failed", exc_info=True)

    def load(self) -> int:
        if self._persist_path is None or not self._persist_path.exists():
            return 0
        try:
            data = json.loads(
                self._persist_path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            log.warning("session persistence file unreadable; starting clean")
            return 0
        restored = 0
        for entry in data.get("sessions", []):
            sid = entry.get("session_id")
            if not isinstance(sid, str) or sid in self._sessions:
                continue
            session = Session(
                session_id=sid,
                kind="gdb",
                state=DISCONNECTED,
                hello=entry.get("hello"),
                log_file=entry.get("log_file"),
                distro=entry.get("distro"),
                launched=bool(entry.get("launched")),
                token=self.config.token,
            )
            session.stop_info = entry.get("stop_info")
            campaign = entry.get("campaign")
            if isinstance(campaign, dict):
                session.campaign = campaign
            self._sessions[sid] = session
            self._attach_journal(session)
            restored += 1
        if restored:
            log.info("restored %d persisted session(s)", restored)
        return restored

    async def gc_once(self) -> int:
        """Drop stale sessions; returns how many were removed."""
        cfg = self.config
        now = time.monotonic()
        removed = 0
        for sid, s in list(self._sessions.items()):
            drop = False
            last = s.last_seen or s.connected_at or s.created_at
            if s.state in (DISCONNECTED, RESERVED):
                idle = cfg.gc_idle_reserved if s.state == RESERVED else cfg.gc_idle_disconnected
                drop = now - last > idle
            elif s.kind == "script" and s.proc is not None and s.proc.returncode is not None:
                drop = now - last > cfg.gc_idle_disconnected
            if drop:
                self.remove(sid)
                removed += 1
        if removed:
            self.save()
        return removed

    async def gc_loop(self, interval: float = 60.0) -> None:
        """Periodic GC + persistence checkpoint (runs until cancelled)."""
        while True:
            await asyncio.sleep(interval)
            try:
                await self.gc_once()
            except Exception:  # pragma: no cover - never let GC die
                log.exception("gc_once failed")
            # safety net: catch campaign/journal metadata mutations that
            # did not go through an explicitly save-triggering path
            self.save()


def make_registry(config: Config) -> SessionRegistry:
    return SessionRegistry(config)


__all__ = [
    "Session",
    "SessionRegistry",
    "make_registry",
    "CONNECTING",
    "READY",
    "RUNNING",
    "STOPPED",
    "EXITED",
    "DISCONNECTED",
    "RESERVED",
    "STOPPED_STATES",
    "ACTIVE_STATES",
]
