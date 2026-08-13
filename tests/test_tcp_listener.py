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
    ack = json.loads(await asyncio.wait_for(reader2.readline(), 5))
    assert ack["type"] == "hello_ack"
    writer2.close()


@pytest.mark.asyncio
async def test_token_wrong_rejected(listener):
    lis, registry, port = listener
    lis.config.token = "sekret"
    wrapped = encode({"token": "wrong", "msg": json.loads(HELLO)})
    reader, writer = await _connect(port, wrapped)
    assert await asyncio.wait_for(reader.read(), 5) == b""
    writer.close()
