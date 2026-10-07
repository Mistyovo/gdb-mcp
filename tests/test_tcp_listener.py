"""End-to-end tests for the TCP listener over real loopback sockets."""

import asyncio
import json

import pytest
import pytest_asyncio

from gdb_mcp.config import Config
from gdb_mcp.errors import GdbMcpError
from gdb_mcp.protocol import encode
from gdb_mcp.sessions import CONNECTING, DISCONNECTED, STOPPED, SessionRegistry
from gdb_mcp.tcp_listener import PluginTcpListener


@pytest_asyncio.fixture
async def listener():
    cfg = Config(host_bind="127.0.0.1", port=0, heartbeat_sec=60.0)
    registry = SessionRegistry(cfg)
    lis = PluginTcpListener(cfg, registry)
    await lis.start()
    port = lis.server.sockets[0].getsockname()[1]
    yield lis, registry, port
    await lis.stop()


async def _connect(port, first_msg):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(first_msg)
    await writer.drain()
    return reader, writer


HELLO = json.dumps(
    {
        "type": "hello",
        "proto": 1,
        "session_id": None,
        "pid": 4242,
        "gdb_version": "15.2",
        "arch": "x86_64",
        "inferior": None,
        "pwndbg": False,
    },
    separators=(",", ":"),
).encode() + b"\n"


@pytest.mark.asyncio
async def test_hello_handshake_and_registration(listener):
    _, registry, port = listener
    reader, writer = await _connect(port, HELLO)

    ack_line = await asyncio.wait_for(reader.readline(), 5)
    ack = json.loads(ack_line)
    assert ack["type"] == "hello_ack"
    assert ack["session_id"].startswith("s-")
    session = registry.get(ack["session_id"])
    assert session.state == CONNECTING
    assert session.hello["pid"] == 4242

    writer.close()


@pytest.mark.asyncio
async def test_hello_binds_to_reserved_session(listener):
    _, registry, port = listener
    registry.reserve("s-reserved")
    hello = json.loads(HELLO)
    hello["session_id"] = "s-reserved"
    reader, writer = await _connect(
        port, json.dumps(hello, separators=(",", ":")).encode() + b"\n"
    )
    ack = json.loads(await asyncio.wait_for(reader.readline(), 5))
    assert ack["session_id"] == "s-reserved"
    writer.close()


@pytest.mark.asyncio
async def test_launched_session_hello_is_not_flagged_without_a_token(listener, caplog):
    """A tokenless server's reserved sessions legitimately have token=None;
    'unknown session' must mean unknown, or the warning stops being worth
    reading."""
    _, registry, port = listener
    registry.reserve("s-quiet")
    hello = json.loads(HELLO)
    hello["session_id"] = "s-quiet"
    with caplog.at_level("WARNING", logger="gdb_mcp.listener"):
        reader, writer = await _connect(
            port, json.dumps(hello, separators=(",", ":")).encode() + b"\n"
        )
        await asyncio.wait_for(reader.readline(), 5)
    writer.close()
    assert "unknown session" not in caplog.text


@pytest.mark.asyncio
async def test_hello_with_unknown_session_id_is_flagged(listener, caplog):
    registry = listener[1]
    hello = json.loads(HELLO)
    hello["session_id"] = "s-never-reserved"
    with caplog.at_level("WARNING", logger="gdb_mcp.listener"):
        reader, writer = await _connect(
            port := listener[2], json.dumps(hello, separators=(",", ":")).encode() + b"\n"
        )
        ack = json.loads(await asyncio.wait_for(reader.readline(), 5))
    writer.close()
    assert ack["session_id"] != "s-never-reserved"  # never allowed to bind
    assert "s-never-reserved" in caplog.text
    assert "s-never-reserved" not in registry._sessions


@pytest.mark.asyncio
async def test_notification_and_response_dispatch(listener):
    _, registry, port = listener
    reader, writer = await _connect(port, HELLO)
    ack = json.loads(await asyncio.wait_for(reader.readline(), 5))
    session = registry.get(ack["session_id"])

    # send a notification -> state updates
    writer.write(
        encode(
            {
                "type": "notification",
                "event": "stop",
                "payload": {"signal": "SIGSEGV", "fault_addr": "0x41414141"},
            }
        )
    )
    await writer.drain()
    for _ in range(50):
        if session.state == STOPPED:
            break
        await asyncio.sleep(0.01)
    assert session.state == STOPPED
    assert session.stop_info["fault_addr"] == "0x41414141"

    # start a request, then answer it from the plugin side
    req_task = asyncio.create_task(session.request("eval", {"command": "vmmap"}, timeout=5))
    req_line = await asyncio.wait_for(reader.readline(), 5)
    req = json.loads(req_line)
    assert req["verb"] == "eval"
    writer.write(
        encode(
            {
                "type": "response",
                "id": req["id"],
                "ok": True,
                "result": {"output": "0x7fff..."},
            }
        )
    )
    await writer.drain()
    assert await req_task == {"output": "0x7fff..."}

    writer.close()
    await asyncio.wait_for(session.reader_task, 5)
    assert session.state == DISCONNECTED


@pytest.mark.asyncio
async def test_request_fails_after_disconnect(listener):
    _, registry, port = listener
    reader, writer = await _connect(port, HELLO)
    ack = json.loads(await asyncio.wait_for(reader.readline(), 5))
    session = registry.get(ack["session_id"])
    writer.close()
    await asyncio.wait_for(session.reader_task, 5)
    with pytest.raises(GdbMcpError) as ei:
        await session.request("eval", {}, timeout=1)
    assert ei.value.code == "DISCONNECTED"


@pytest.mark.asyncio
async def test_non_hello_first_message_rejected(listener):
    _, registry, port = listener
    reader, writer = await _connect(port, encode({"type": "request", "id": 1, "verb": "eval"}))
    # server closes; reading yields EOF
    assert await reader.read() == b""
    writer.close()


@pytest.mark.asyncio
async def test_bad_json_line_drops_connection(listener):
    _, registry, port = listener
    reader, writer = await _connect(port, HELLO)
    await asyncio.wait_for(reader.readline(), 5)
    writer.write(b"this is not json\n")
    await writer.drain()
    assert await asyncio.wait_for(reader.read(), 5) == b""
    writer.close()


@pytest.mark.asyncio
async def test_token_auth(listener):
    lis, registry, port = listener
    # reconfigure with a token mid-test (config is shared by reference)
    lis.config.token = "sekret"
    # bare hello rejected when token required
    reader, writer = await _connect(port, HELLO)
    assert await asyncio.wait_for(reader.read(), 5) == b""
    writer.close()
    # wrapped hello accepted
    wrapped = encode({"token": "sekret", "msg": json.loads(HELLO)})
    reader2, writer2 = await _connect(port, wrapped)
    envelope = json.loads(await asyncio.wait_for(reader2.readline(), 5))
    assert envelope["token"] == "sekret"
    ack = envelope["msg"]
    assert ack["type"] == "hello_ack"
    session = registry.get(ack["session_id"])
    request_task = asyncio.create_task(session.request("eval", {}, timeout=5))
    request_envelope = json.loads(await asyncio.wait_for(reader2.readline(), 5))
    assert request_envelope["token"] == "sekret"
    request = request_envelope["msg"]
    writer2.write(
        encode(
            {
                "type": "response",
                "id": request["id"],
                "ok": True,
                "result": {"output": "secured"},
            },
            "sekret",
        )
    )
    await writer2.drain()
    assert await request_task == {"output": "secured"}
    writer2.close()


@pytest.mark.asyncio
async def test_token_wrong_rejected(listener):
    lis, registry, port = listener
    lis.config.token = "sekret"
    wrapped = encode({"token": "wrong", "msg": json.loads(HELLO)})
    reader, writer = await _connect(port, wrapped)
    assert await asyncio.wait_for(reader.read(), 5) == b""
    writer.close()


@pytest.mark.asyncio
async def test_scoped_session_token_handshake(listener):
    """E4: a launched session verifies against its scoped token; the
    master token is refused for that session id."""
    lis, registry, port = listener
    lis.config.token = "master-secret"
    session = registry.reserve("s-scoped")
    from gdb_mcp.sessions import derive_session_token

    scoped = derive_session_token("master-secret", "s-scoped")
    assert session.token == scoped  # reserve() paired it

    # master token for a scoped session: refused
    bad = encode(
        {
            "token": "master-secret",
            "msg": {**json.loads(HELLO), "session_id": "s-scoped"},
        }
    )
    reader, writer = await _connect(port, bad)
    assert await asyncio.wait_for(reader.read(), 5) == b""
    writer.close()

    # scoped token: accepted and bound to the same reservation
    good = encode(
        {
            "token": scoped,
            "msg": {**json.loads(HELLO), "session_id": "s-scoped"},
        }
    )
    reader2, writer2 = await _connect(port, good)
    envelope = json.loads(await asyncio.wait_for(reader2.readline(), 5))
    # the ack must be wrapped with the SESSION token: the plugin holds
    # only the derivation and silently drops master-token frames (audit
    # 2026-10-07: hello_ack/heartbeat pings used the master token, so a
    # scoped session lost protocol negotiation and heartbeat health)
    assert envelope["token"] == scoped
    ack = envelope.get("msg", envelope)
    assert ack["session_id"] == "s-scoped"
    writer2.close()

    # an unknown session id falls back to the master token
    ext = encode(
        {
            "token": "master-secret",
            "msg": {**json.loads(HELLO), "session_id": "s-external"},
        }
    )
    reader3, writer3 = await _connect(port, ext)
    envelope3 = json.loads(await asyncio.wait_for(reader3.readline(), 5))
    ack3 = envelope3.get("msg", envelope3)
    assert ack3["session_id"].startswith("s-")
    writer3.close()

    # after restart-style revival the scoped token is recomputed
    registry.remove("s-scoped")


@pytest.mark.asyncio
async def test_scoped_session_receives_heartbeat_ping():
    """The heartbeat ping must carry the session token: the plugin drops
    token-mismatched lines silently, so a master-wrapped ping reads as a
    missed pong and churns a healthy connection (audit 2026-10-07)."""
    from gdb_mcp.sessions import derive_session_token

    cfg = Config(
        host_bind="127.0.0.1", port=0, heartbeat_sec=0.2, token="master-secret"
    )
    registry = SessionRegistry(cfg)
    lis = PluginTcpListener(cfg, registry)
    await lis.start()
    port = lis.server.sockets[0].getsockname()[1]
    try:
        registry.reserve("s-hb")
        scoped = derive_session_token("master-secret", "s-hb")
        hello = encode(
            {
                "token": scoped,
                "msg": {**json.loads(HELLO), "session_id": "s-hb"},
            }
        )
        reader, writer = await _connect(port, hello)
        ack_env = json.loads(await asyncio.wait_for(reader.readline(), 5))
        assert ack_env["token"] == scoped

        # the heartbeat ping is a reader-thread request (verb=ping);
        # the fake client never pongs, so the listener will close the
        # connection after 2 intervals — the frame itself is the assertion
        ping_env = None
        for _ in range(10):
            line = await asyncio.wait_for(reader.readline(), 5)
            if not line:
                break
            env = json.loads(line)
            if env["msg"].get("verb") == "ping":
                ping_env = env
                break
        assert ping_env is not None, "no heartbeat ping before close"
        assert ping_env["token"] == scoped
        writer.close()
    finally:
        await lis.stop()
