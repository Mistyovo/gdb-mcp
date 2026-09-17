"""Tests for the server-side session model and registry."""

import asyncio

import pytest

from gdb_mcp.config import Config
from gdb_mcp.errors import (
    AmbiguousSessionError,
    GdbMcpError,
    NoSessionsError,
    NoSuchSessionError,
    RequestTimeoutError,
)
from gdb_mcp.sessions import (
    CONNECTING,
    DISCONNECTED,
    EVENT_LOG_LIMIT,
    EXITED,
    READY,
    RESERVED,
    RUNNING,
    STOPPED,
    Session,
    SessionRegistry,
)


class FakeWriter:
    def __init__(self):
        self.sent = []
        self.closed = False

    def write(self, data):
        self.sent.append(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    def is_closing(self):
        return self.closed


@pytest.fixture
def registry():
    ids = iter(f"s-{i:03d}" for i in range(100))
    return SessionRegistry(Config(), session_id_factory=lambda: next(ids))


def hello(session_id=None, pid=1234, **extra):
    h = {
        "type": "hello",
        "proto": 1,
        "session_id": session_id,
        "pid": pid,
        "gdb_version": "15.2",
        "arch": "x86_64",
        "inferior": "/tmp/vuln",
        "pwndbg": True,
    }
    h.update(extra)
    return h


class TestRegisterHello:
    @pytest.mark.asyncio
    async def test_new_session(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        assert s.state == CONNECTING
        assert registry.get(s.session_id) is s
        assert registry.by_pid(1234) is s

    @pytest.mark.asyncio
    async def test_hello_binds_to_reserved_session(self, registry):
        reserved = registry.reserve("s-abc")
        assert reserved.state == RESERVED
        s = registry.register_hello(hello(session_id="s-abc"), FakeWriter())
        assert s is reserved
        assert s.state == CONNECTING
        assert s.reserved is False
        assert s.hello["gdb_version"] == "15.2"

    @pytest.mark.asyncio
    async def test_hello_with_unknown_session_id_creates_new(self, registry):
        s = registry.register_hello(hello(session_id="s-nope"), FakeWriter())
        assert s.session_id != "s-nope"

    @pytest.mark.asyncio
    async def test_rebind_disconnected_session(self, registry):
        reserved = registry.reserve("s-abc")
        s1 = registry.register_hello(hello(session_id="s-abc"), FakeWriter())
        assert s1 is reserved
        await s1.on_disconnect()
        assert s1.state == DISCONNECTED
        s2 = registry.register_hello(hello(session_id="s-abc"), FakeWriter())
        assert s2 is s1
        assert s2.state == CONNECTING


class TestResolve:
    @pytest.mark.asyncio
    async def test_no_sessions(self, registry):
        with pytest.raises(NoSessionsError):
            registry.resolve()

    @pytest.mark.asyncio
    async def test_single_session_autoselect(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        assert registry.resolve() is s

    @pytest.mark.asyncio
    async def test_multiple_ambiguous(self, registry):
        registry.register_hello(hello(), FakeWriter())
        registry.register_hello(hello(pid=9999), FakeWriter())
        with pytest.raises(AmbiguousSessionError) as ei:
            registry.resolve()
        assert "s-" in ei.value.message

    @pytest.mark.asyncio
    async def test_explicit_id(self, registry):
        registry.register_hello(hello(), FakeWriter())
        s2 = registry.register_hello(hello(pid=9999), FakeWriter())
        assert registry.resolve(s2.session_id) is s2

    @pytest.mark.asyncio
    async def test_unknown_id(self, registry):
        with pytest.raises(NoSuchSessionError):
            registry.resolve("s-missing")

    @pytest.mark.asyncio
    async def test_kind_filter_excludes_scripts(self, registry):
        script = registry.reserve("s-script", kind="script")
        script.state = RUNNING
        with pytest.raises(NoSessionsError):
            registry.resolve(kind="gdb")
        assert registry.resolve(kind="script") is script

    @pytest.mark.asyncio
    async def test_disconnected_not_autoselected(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        await s.on_disconnect()
        with pytest.raises(NoSessionsError):
            registry.resolve()


class TestRequest:
    @pytest.mark.asyncio
    async def test_roundtrip(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        task = asyncio.create_task(s.request("eval", {"command": "vmmap"}, timeout=5))
        await asyncio.sleep(0)  # let it send
        assert len(s.writer.sent) == 1
        assert s.pending  # one pending future
        await s.complete_response(1, {"ok": True, "result": {"output": "ok"}})
        assert await task == {"output": "ok"}

    @pytest.mark.asyncio
    async def test_error_response_raises(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        task = asyncio.create_task(s.request("read_mem", {}, timeout=5))
        await asyncio.sleep(0)
        await s.complete_response(
            1, {"ok": False, "error": {"code": "NO_INFERIOR", "message": "none"}}
        )
        with pytest.raises(GdbMcpError) as ei:
            await task
        assert ei.value.code == "NO_INFERIOR"

    @pytest.mark.asyncio
    async def test_timeout(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        with pytest.raises(RequestTimeoutError):
            await s.request("eval", {}, timeout=0.05)
        assert not s.pending  # cleaned up

    @pytest.mark.asyncio
    async def test_late_response_dropped(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        with pytest.raises(RequestTimeoutError):
            await s.request("eval", {}, timeout=0.05)
        await s.complete_response(1, {"ok": True, "result": {}})  # no crash

    @pytest.mark.asyncio
    async def test_async_verb_sets_running(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        task = asyncio.create_task(s.request("continue", {}, timeout=5))
        await asyncio.sleep(0)
        assert s.state == RUNNING
        await s.complete_response(1, {"ok": True, "result": {"state": "running"}})
        assert await task == {"state": "running"}
        assert s.state == RUNNING

    @pytest.mark.asyncio
    async def test_stop_notification_wins_over_async_response(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        task = asyncio.create_task(s.request("continue", {}, timeout=5))
        await asyncio.sleep(0)
        await s.complete_response(1, {"ok": True, "result": {"state": "running"}})
        await s.push_notification("stop", {"signal": "SIGTRAP"})
        await task
        assert s.state == STOPPED
        assert s.stop_info == {"signal": "SIGTRAP"}

    @pytest.mark.asyncio
    async def test_async_error_restores_previous_state(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        s.state = READY
        task = asyncio.create_task(s.request("continue", {}, timeout=5))
        await asyncio.sleep(0)
        await s.complete_response(
            1,
            {
                "ok": False,
                "error": {"code": "NO_INFERIOR", "message": "none"},
            },
        )
        with pytest.raises(GdbMcpError):
            await task
        assert s.state == READY

    @pytest.mark.asyncio
    async def test_request_on_disconnected_raises(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        await s.on_disconnect()
        with pytest.raises(GdbMcpError) as ei:
            await s.request("eval", {}, timeout=5)
        assert ei.value.code == "DISCONNECTED"

    @pytest.mark.asyncio
    async def test_disconnect_fails_pending(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        task = asyncio.create_task(s.request("eval", {}, timeout=5))
        await asyncio.sleep(0)
        await s.on_disconnect()
        with pytest.raises(GdbMcpError) as ei:
            await task
        assert ei.value.code == "DISCONNECTED"


class TestNotifications:
    @pytest.mark.asyncio
    async def test_stop(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        await s.push_notification(
            "stop", {"signal": "SIGSEGV", "fault_addr": "0x41414141"}
        )
        assert s.state == STOPPED
        assert s.stop_info["signal"] == "SIGSEGV"

    @pytest.mark.asyncio
    async def test_prompt_keeps_stop_info(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        await s.push_notification("stop", {"signal": "SIGSEGV"})
        await s.push_notification("prompt", {})
        assert s.state == READY
        assert s.stop_info == {"signal": "SIGSEGV"}

    @pytest.mark.asyncio
    async def test_exited(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        await s.push_notification("exited", {"exit_code": 139})
        assert s.state == EXITED
        assert s.exited_code == 139

    @pytest.mark.asyncio
    async def test_running(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        await s.push_notification("running", {})
        assert s.state == RUNNING


class TestWaitForStop:
    @pytest.mark.asyncio
    async def test_immediate_when_already_stopped(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        await s.push_notification("stop", {"signal": "SIGTRAP"})
        assert await s.wait_for_stop(timeout=1) is True

    @pytest.mark.asyncio
    async def test_wakes_on_stop_notification(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        s.state = RUNNING
        wait_task = asyncio.create_task(s.wait_for_stop(timeout=5))
        await asyncio.sleep(0)
        await s.push_notification("stop", {"signal": "SIGTRAP"})
        assert await wait_task is True

    @pytest.mark.asyncio
    async def test_notification_before_wait_no_race(self, registry):
        # stop lands before wait_for_stop is called -> immediate return
        s = registry.register_hello(hello(), FakeWriter())
        await s.push_notification("stop", {"signal": "SIGTRAP"})
        assert await s.wait_for_stop(timeout=1) is True

    @pytest.mark.asyncio
    async def test_timeout(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        s.state = RUNNING
        assert await s.wait_for_stop(timeout=0.05) is False

    @pytest.mark.asyncio
    async def test_disconnect_wakes_with_false(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        s.state = RUNNING
        wait_task = asyncio.create_task(s.wait_for_stop(timeout=5))
        await asyncio.sleep(0)
        await s.on_disconnect()
        assert await wait_task is False


class TestGC:
    @pytest.mark.asyncio
    async def test_stale_reserved_removed(self, registry):
        s = registry.reserve("s-abc")
        s.created_at = s.created_at - 10_000
        s.last_seen = s.created_at
        assert await registry.gc_once() == 1
        with pytest.raises(NoSuchSessionError):
            registry.get("s-abc")

    @pytest.mark.asyncio
    async def test_stale_disconnected_removed(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        await s.on_disconnect()
        s.last_seen = s.last_seen - 10_000
        assert await registry.gc_once() == 1

    @pytest.mark.asyncio
    async def test_fresh_sessions_kept(self, registry):
        registry.register_hello(hello(), FakeWriter())
        registry.reserve("s-abc")
        assert await registry.gc_once() == 0

    @pytest.mark.asyncio
    async def test_script_session_with_dead_proc_removed(self, registry):
        import time

        class DeadProc:
            returncode = 0

        s = registry.reserve("s-script", kind="script")
        s.state = RUNNING
        s.proc = DeadProc()
        s.last_seen = time.monotonic() - 10_000
        assert await registry.gc_once() == 1

    @pytest.mark.asyncio
    async def test_live_script_session_kept(self, registry):
        import time

        class LiveProc:
            returncode = None

        s = registry.reserve("s-script", kind="script")
        s.state = RUNNING
        s.proc = LiveProc()
        s.last_seen = time.monotonic() - 10_000
        assert await registry.gc_once() == 0


class TestInfo:
    @pytest.mark.asyncio
    async def test_info_shape(self, registry):
        s = registry.register_hello(hello(), FakeWriter())
        info = s.info()
        assert info["session_id"] == s.session_id
        assert info["gdb_pid"] == 1234
        assert info["arch"] == "x86_64"
        assert info["pwndbg"] is True
        assert info["inferior"] == "/tmp/vuln"


class TestEventRing:
    def test_records_are_bounded_and_ordered(self):
        s = Session(session_id="s-ev")
        for i in range(EVENT_LOG_LIMIT + 5):
            s.record_event("stop", {"i": i})
        assert len(s.event_log) == EVENT_LOG_LIMIT
        events = s.recent_events(3)
        assert [e["payload"]["i"] for e in events] == [
            EVENT_LOG_LIMIT + 2,
            EVENT_LOG_LIMIT + 3,
            EVENT_LOG_LIMIT + 4,
        ]
        assert events[-1]["seq"] == EVENT_LOG_LIMIT + 5

    def test_recent_events_zero_returns_empty(self):
        s = Session(session_id="s-ev0")
        s.record_event("stop", {})
        assert s.recent_events(0) == []

    @pytest.mark.asyncio
    async def test_push_notification_records_event(self):
        s = Session(session_id="s-ev2")
        await s.push_notification("stop", {"pc": "0x401000"})
        await s.push_notification("exited", {"exit_code": 0})
        kinds = [e["event"] for e in s.recent_events(10)]
        assert kinds == ["stop", "exited"]
        assert s.recent_events(1)[0]["event"] == "exited"

    @pytest.mark.asyncio
    async def test_disconnect_recorded(self):
        s = Session(session_id="s-ev3")
        s.writer = FakeWriter()
        await s.on_disconnect()
        assert s.recent_events(1)[0]["event"] == "disconnected"

    def test_register_hello_records_connected(self):
        registry = SessionRegistry(Config())
        s = registry.register_hello(hello(), FakeWriter())
        kinds = [e["event"] for e in s.recent_events(10)]
        assert kinds == ["connected"]


class TestPersistence:
    def test_roundtrip_and_revival(self, tmp_path):
        path = tmp_path / "sessions.json"
        r1 = SessionRegistry(Config())
        r1.enable_persistence(path)
        r1.reserve("s-p1", log_file="/logs/s-p1.log")
        s1 = r1.register_hello(hello(session_id="s-p1"), FakeWriter())
        from gdb_mcp.campaign import campaign_set

        campaign_set(s1.campaign, "offsets", "libc_base", "0x7ffff7d80000")
        # campaign mutations are persisted by the tool layer / GC loop;
        # this test simulates both by saving explicitly
        r1.save()

        # server restart: fresh registry over the same persistence file
        r2 = SessionRegistry(Config())
        assert r2.enable_persistence(path) == 1
        old = r2.get("s-p1")
        assert old.state == DISCONNECTED
        assert old.log_file == "/logs/s-p1.log"
        assert old.hello["pid"] == 1234
        assert old.campaign["offsets"]["libc_base"]["value"] == "0x7ffff7d80000"

        # the plugin's re-hello revives the SAME identity
        revived = r2.register_hello(hello(session_id="s-p1", pid=999), FakeWriter())
        assert revived.session_id == "s-p1"
        assert revived.state == CONNECTING
        assert revived.log_file == "/logs/s-p1.log"
        assert revived.journal is not None

    def test_script_sessions_not_persisted(self, tmp_path):
        path = tmp_path / "sessions.json"
        r1 = SessionRegistry(Config())
        r1.enable_persistence(path)
        r1.reserve("s-scr", kind="script")
        r1.save()
        r2 = SessionRegistry(Config())
        assert r2.enable_persistence(path) == 0

    def test_corrupt_file_starts_clean(self, tmp_path):
        path = tmp_path / "sessions.json"
        path.write_text("not json", encoding="utf-8")
        registry = SessionRegistry(Config())
        assert registry.enable_persistence(path) == 0
        assert registry.list_all() == []

    def test_remove_updates_persistence(self, tmp_path):
        path = tmp_path / "sessions.json"
        r1 = SessionRegistry(Config())
        r1.enable_persistence(path)
        r1.reserve("s-p2")
        assert "s-p2" in path.read_text(encoding="utf-8")
        r1.remove("s-p2")
        r2 = SessionRegistry(Config())
        assert r2.enable_persistence(path) == 0
