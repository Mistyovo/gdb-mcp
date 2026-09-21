"""Dashboard data layer: lifecycle events, snapshot enrichment, SSE, API.

Covers the Phase 1 contract in docs/dashboard-design.md:

* every session lifecycle transition reaches the broker as one
  ``session.updated`` event carrying the refreshed snapshot,
* ``session.request`` started/finished events carry verb/duration but
  never params/results,
* snapshot extras stay out of ``Session.info()`` (MCP payload budget),
* the HTTP surface validates Host headers and answers with hardened
  headers.
"""

import asyncio

import pytest
from starlette.testclient import TestClient

from gdb_mcp.config import Config
from gdb_mcp.errors import GdbMcpError
from gdb_mcp.events import EventBroker
from gdb_mcp.http_hardening import SecurityHeadersMiddleware
from gdb_mcp.sessions import STOPPED, SessionRegistry
from gdb_mcp.web import DashboardServer, _StaticHeadersMiddleware, sse_stream


class FakeWriter:
    def __init__(self):
        self.sent = []

    def write(self, data):
        self.sent.append(data)

    async def drain(self):
        pass

    def close(self):
        pass

    def is_closing(self):
        return False


def _hello(session_id=None, pid=1234):
    return {
        "type": "hello",
        "proto": 1,
        "session_id": session_id,
        "pid": pid,
        "gdb_version": "15.2",
        "python_version": "3.13",
        "arch": "i386:x86-64",
        "inferior": "/tmp/target",
        "pwndbg": False,
    }


@pytest.fixture
def wired():
    """Registry + broker pair; the queue subscribes inside each test's
    event loop so broker delivery lands on that loop."""
    broker = EventBroker()
    ids = iter(f"s-{i:03d}" for i in range(100))
    registry = SessionRegistry(
        Config(), session_id_factory=lambda: next(ids), events=broker
    )
    return broker, registry


async def _drain(queue, count):
    return [await asyncio.wait_for(queue.get(), 1.0) for _ in range(count)]


# -- lifecycle events -------------------------------------------------------


@pytest.mark.asyncio
async def test_lifecycle_transitions_publish_snapshots(wired):
    broker, registry = wired
    queue = broker.subscribe()

    registry.reserve("s-001")
    session = registry.register_hello(_hello(session_id="s-001", pid=42), FakeWriter())
    await session.push_notification("running", {})
    await session.push_notification(
        "stop", {"reason": "breakpoint-hit", "pc": "0x40119b"}
    )
    await session.on_disconnect()
    registry.remove("s-001")

    events = await _drain(queue, 6)
    transitions = [e["data"]["event"] for e in events]
    assert transitions == [
        "reserved",
        "connected",
        "running",
        "stop",
        "disconnected",
        "removed",
    ]
    assert all(e["type"] == "session.updated" for e in events)
    # each event embeds the refreshed snapshot: state after "stop" is
    # STOPPED and the payload is carried through verbatim
    stop_event = events[3]["data"]
    assert stop_event["session"]["state"] == STOPPED
    assert stop_event["payload"]["reason"] == "breakpoint-hit"
    # "removed" carries the final state even though the session is
    # already out of the registry
    assert events[5]["data"]["session"]["state"] == "disconnected"


@pytest.mark.asyncio
async def test_request_events_verb_only(wired):
    broker, registry = wired
    session = registry.register_hello(_hello(), FakeWriter())
    queue = broker.subscribe()

    task = asyncio.create_task(session.request("ping", timeout=1.0))
    for _ in range(200):  # wait until the request is in flight
        if session.pending:
            break
        await asyncio.sleep(0.005)
    req_id = next(iter(session.pending))
    await session.complete_response(
        req_id, {"type": "response", "id": req_id, "ok": True, "result": {"pong": True}}
    )
    await task

    started, finished = await _drain(queue, 2)
    assert started["type"] == finished["type"] == "session.request"
    assert started["data"]["verb"] == finished["data"]["verb"] == "ping"
    assert started["data"]["phase"] == "started"
    assert finished["data"]["phase"] == "finished"
    assert finished["data"]["ok"] is True
    assert finished["data"]["duration_ms"] >= 0
    # the contract: no params or results ever ride the event stream
    assert "params" not in started["data"] and "result" not in finished["data"]


@pytest.mark.asyncio
async def test_request_failure_publishes_error_code(wired):
    broker, registry = wired
    session = registry.register_hello(_hello(), FakeWriter())
    await session.on_disconnect()
    queue = broker.subscribe()  # after disconnect: only request events follow

    with pytest.raises(GdbMcpError):
        await session.request("ping", timeout=0.1)

    _, finished = await _drain(queue, 2)
    assert finished["data"]["ok"] is False
    assert finished["data"]["error"] == "DISCONNECTED"


# -- snapshot enrichment ----------------------------------------------------


def test_snapshot_extras_stay_out_of_info(wired):
    broker, registry = wired
    registry.register_hello(_hello(pid=7), FakeWriter())
    dashboard = DashboardServer(Config(), registry, broker)

    snapshot = dashboard.snapshot()
    assert snapshot["dashboard"]["read_only"] is True
    assert snapshot["sequence"] == broker.sequence
    (view,) = snapshot["sessions"]
    assert view["gdb_pid"] == 7
    # dashboard-only fields present here...
    assert view["pending_requests"] == 0
    assert view["age_sec"] >= 0
    assert view["last_event"]["event"] == "connected"
    assert view["journal_entries"] >= 0
    # ...and absent from the MCP-facing compact info()
    assert "pending_requests" not in registry.list_all()[0].info()


# -- SSE stream -------------------------------------------------------------


@pytest.mark.asyncio
async def test_sse_stream_formats_events_and_keepalive():
    broker = EventBroker()
    stream = sse_stream(broker, keepalive_sec=0.05)

    first = asyncio.create_task(stream.__anext__())
    for _ in range(200):  # let the generator subscribe first
        await asyncio.sleep(0.005)
        if broker._subscribers:
            break
    broker.publish("session.updated", {"event": "stop"})
    line = await asyncio.wait_for(first, 1.0)
    assert line.startswith("data: ")
    assert '"session.updated"' in line and '"stop"' in line

    # idle stream emits a keepalive comment, not a data frame
    line = await asyncio.wait_for(stream.__anext__(), 1.0)
    assert line == ": keepalive\n\n"

    await stream.aclose()  # unsubscribe on any exit path
    assert not broker._subscribers


# -- HTTP surface -----------------------------------------------------------


@pytest.fixture
def client(wired):
    broker, registry = wired
    dashboard = DashboardServer(Config(), registry, broker)
    app = _StaticHeadersMiddleware(
        SecurityHeadersMiddleware(dashboard.build_app(), "127.0.0.1", 3940, None, ())
    )
    return TestClient(app, base_url="http://127.0.0.1:3940")


def test_health_and_snapshot_endpoints(client, wired):
    broker, registry = wired
    registry.register_hello(_hello(pid=9), FakeWriter())

    health = client.get("/api/v1/health").json()
    assert health["ok"] is False  # not started: TestClient drives the bare app
    assert health["read_only"] is True

    response = client.get("/api/v1/snapshot")
    assert response.status_code == 200
    (view,) = response.json()["sessions"]
    assert view["gdb_pid"] == 9
    assert view["state"] == "connecting"


def test_hardened_headers_and_host_validation(client):
    response = client.get("/api/v1/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    # anti DNS-rebinding: a foreign Host header never reaches the app
    rejected = client.get("/api/v1/health", headers={"Host": "evil.example"})
    assert rejected.status_code == 403


# -- configuration ----------------------------------------------------------


def test_dashboard_is_cli_only(monkeypatch):
    monkeypatch.setenv("GDB_MCP_DASHBOARD", "1")
    assert Config.from_env().dashboard is False
    assert Config.from_env(overrides={"dashboard": True}).dashboard is True


def test_dashboard_rejects_non_loopback_bind():
    with pytest.raises(ValueError, match="loopback"):
        Config.from_env(overrides={"dashboard": True, "dashboard_host": "0.0.0.0"})


def test_dashboard_port_range():
    with pytest.raises(ValueError, match="dashboard_port"):
        Config.from_env(overrides={"dashboard": True, "dashboard_port": 70000})


def test_dashboard_host_port_env_overridable(monkeypatch):
    monkeypatch.setenv("GDB_MCP_DASHBOARD_PORT", "4321")
    monkeypatch.setenv("GDB_MCP_DASHBOARD_HOST", "localhost")
    cfg = Config.from_env(overrides={"dashboard": True})
    assert cfg.dashboard_port == 4321
    assert cfg.dashboard_host == "localhost"
