"""Protocol-layer robustness fuzz tests (deterministic, dependency-free).

The JSON-lines control channel is the one surface an attacker — or just a
flaky network — can feed arbitrary bytes into. The contract under test:

* server side (:mod:`gdb_mcp.protocol` + the TCP reader loop): every input
  either yields a dict message or raises :class:`ProtocolError`. No other
  exception may escape — anything else tears down a session (or the
  listener) instead of rejecting one bad line.
* plugin side (``_dispatch_line``): every input is silently dropped; the
  connection and the dispatch queue stay untouched.

Randomness is seeded per case so failures are exactly reproducible.
"""

import asyncio
import json
import random

import pytest
import pytest_asyncio

from gdb_mcp.errors import ProtocolError
from gdb_mcp.protocol import (
    LineReader,
    encode,
    parse_line,
    unwrap_token,
    validate_hello,
    validate_plugin_message,
)
from gdb_mcp.config import Config
from gdb_mcp.sessions import SessionRegistry
from gdb_mcp.tcp_listener import PluginTcpListener

# --- corpus -----------------------------------------------------------------

VALID_HELLO = {
    "type": "hello",
    "proto": 1,
    "session_id": None,
    "pid": 4242,
    "gdb_version": "15.2",
    "arch": "x86_64",
    "inferior": None,
    "pwndbg": False,
    "features": ["blocked_signals"],
}

VALID_RESPONSE_OK = {"type": "response", "id": 7, "ok": True, "result": {"v": 1}}

VALID_RESPONSE_ERR = {
    "type": "response",
    "id": 8,
    "ok": False,
    "error": {"code": "NO_INFERIOR", "message": "m"},
}

VALID_NOTIFICATION = {"type": "notification", "event": "stop", "payload": {}}

SEEDS = range(24)

BYTE_ALPHABET = (
    b'{}[]",:0123456789 \t\r\n\xff\xfe\x00\x80abcXYZ-_.\\eE+'
    b"+truefalsnl/"
)


def _random_blobs(rng: random.Random, count: int) -> list[bytes]:
    blobs = []
    for _ in range(count):
        size = rng.choice((0, 1, 2, 7, 64, 300, 4096))
        style = rng.randrange(4)
        if style == 0:
            blob = bytes(rng.choice(BYTE_ALPHABET) for _ in range(size))
        elif style == 1:  # dense structural characters (parser stress)
            blob = bytes(rng.choice(b'{}[]",:0') for _ in range(size))
        elif style == 2:  # valid json prefix + garbage tail
            base = json.dumps(VALID_RESPONSE_OK).encode()
            blob = base[: min(size, len(base))] + bytes(
                rng.choice(BYTE_ALPHABET) for _ in range(max(0, size - len(base)))
            )
        else:  # repeated byte (runs of newlines / nulls)
            blob = bytes([rng.choice(b"\n\r\x00 {}")]) * size
        blobs.append(blob)
    return blobs


def _mutate(payload: bytes, rng: random.Random) -> bytes:
    out = bytearray(payload)
    for _ in range(rng.choice((1, 1, 2, 4))):
        if not out:
            out = bytes([rng.randrange(256)])
            break
        op = rng.randrange(4)
        pos = rng.randrange(len(out))
        if op == 0:
            out[pos] = rng.randrange(256)
        elif op == 1:
            del out[pos]
        elif op == 2:
            out[pos:pos] = bytes([rng.choice(BYTE_ALPHABET)])
        else:
            out = out[:pos]
    return bytes(out)


# --- server-side pure-layer invariants --------------------------------------


class TestFramingInvariants:
    @pytest.mark.parametrize("seed", SEEDS)
    def test_random_bytes_never_escape_protocol_error(self, seed):
        """LineReader.feed: only ProtocolError, and every emitted line is
        newline-free and within the size bound."""
        rng = random.Random(seed)
        reader = LineReader(1024)
        for blob in _random_blobs(rng, 16):
            try:
                lines = reader.feed(blob)
            except ProtocolError:
                continue  # oversized; the connection would be dropped
            for line in lines:
                assert b"\n" not in line
                assert len(line) <= 1024

    def test_feed_never_loses_data(self):
        """Property: emitted lines + the still-buffered tail reassemble the
        entire input (no bytes silently vanish or duplicate)."""
        rng = random.Random(2026)
        for _ in range(64):
            reader = LineReader(1 << 20)
            payload = bytes(rng.choice(BYTE_ALPHABET) for _ in range(rng.randrange(0, 600)))
            try:
                lines = reader.feed(payload)
            except ProtocolError:
                continue
            parts = lines + [bytes(reader._buf)]
            normalized = payload.replace(b"\r\n", b"\n")
            assert b"\n".join(parts) == normalized

    @pytest.mark.parametrize(
        "raw",
        [
            b"",
            b"\n",
            b"\r\n",
            b"\n" * 64,
            b"\x00" * 128,
            b'{"a":NaN}\n',
            b'{"a":Infinity}\n',
            b'{"a":1e999}\n',
            b'{"a":"\\ud800"}\n',  # lone surrogate escape
            b'{"a":1,"a":2}\n',  # duplicate keys are legal JSON
            b'{"type":"response","id":1e400,"ok":true}\n',
            b"9" * 4096 + b"\n",  # huge int literal
            b'"' + b"z" * 4096 + b'"\n',
            b"\xff\xfe\xfd\xfc\xfb\xfa\n",
            b'{"type":"hello","proto":1,"pid":true}\n',  # bool is not int
            b'{"type":"hello","proto":"1","pid":1}\n',
            b'{"type":"hello","proto":1,"pid":-5}\n',
            b'{"type":"hello","proto":1,"pid":1,"verbs":["eval",42]}\n',
            b'{"type":"notification","event":null,"payload":{}}\n',
            b'{"type":"response","id":1,"ok":true,"result":[1,2]}\n',
        ],
    )
    def test_degenerate_lines_are_classified_not_crashed(self, raw):
        line = raw.rstrip(b"\n")
        try:
            msg = parse_line(line)
        except ProtocolError as exc:
            assert exc.code == "MALFORMED"
            return
        assert isinstance(msg, dict)
        # whatever parsed must still validate (or cleanly reject) — never crash
        try:
            validate_plugin_message(msg)
        except ProtocolError:
            pass


class TestDeepNesting:
    def test_deep_nesting_rejected_as_malformed(self):
        """Regression: RecursionError from json.loads used to escape
        parse_line and tear down the reader loop's session."""
        with pytest.raises(ProtocolError) as ei:
            parse_line(b"[" * 200_000)
        assert ei.value.code == "MALFORMED"
        assert "nest" in ei.value.message.lower()

    def test_deep_nesting_inside_token_wrapper_rejected(self):
        raw = b'{"token":"t","msg":' + b"[" * 200_000
        with pytest.raises(ProtocolError):
            parse_line(raw)

    def test_moderate_nesting_parses(self):
        depth = 400  # below the interpreter recursion limit
        msg = parse_line((b'{"x":' + b"[" * depth + b"]" * depth + b"}"))
        assert isinstance(msg, dict)


class TestMutatedValidMessages:
    """Byte-level mutations of otherwise-valid frames must never produce an
    exception other than ProtocolError anywhere in the parse/validate
    pipeline."""

    @pytest.mark.parametrize("seed", SEEDS)
    def test_mutations_classified(self, seed):
        rng = random.Random(1000 + seed)
        corpus = [
            json.dumps(m, separators=(",", ":")).encode()
            for m in (
                VALID_HELLO,
                VALID_RESPONSE_OK,
                VALID_RESPONSE_ERR,
                VALID_NOTIFICATION,
            )
        ]
        for base in corpus:
            for _ in range(16):
                mutated = _mutate(base, rng)
                try:
                    msg = parse_line(mutated)
                except ProtocolError:
                    continue
                # token-wrapped variant exercises the auth unwrap path too
                try:
                    unwrapped = unwrap_token(msg, "t" if rng.randrange(2) else None)
                except ProtocolError:
                    continue
                try:
                    validate_hello(unwrapped)
                except ProtocolError:
                    pass
                try:
                    validate_plugin_message(unwrapped)
                except ProtocolError:
                    pass


# --- live listener end-to-end ------------------------------------------------


@pytest_asyncio.fixture
async def listener(tmp_path):
    cfg = Config(
        host_bind="127.0.0.1",
        port=0,
        heartbeat_sec=60.0,
        log_dir=tmp_path / "logs",
        token="sekret",
    )
    registry = SessionRegistry(cfg)
    lis = PluginTcpListener(cfg, registry)
    await lis.start()
    port = lis.server.sockets[0].getsockname()[1]
    yield lis, registry, port
    await lis.stop()


class TestListenerSurvivesGarbage:
    @pytest.mark.asyncio
    async def test_random_garbage_connections_do_not_harm_listener(self, listener):
        """Spray malformed frames at the listener; it must keep serving a
        well-formed handshake afterwards."""
        _, registry, port = listener
        rng = random.Random(7)
        for blob in _random_blobs(rng, 12):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(blob)
            await writer.drain()
            writer.close()
        # oversized unterminated hello line
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b'{"type":"hello","pad":"' + b"A" * 200_000)
        await writer.drain()
        writer.close()
        # deep nesting as the hello line itself
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"[" * 200_000 + b"]" * 200_000 + b"\n")
        await writer.drain()
        writer.close()
        await asyncio.sleep(0.05)

        wrapped = {"token": "sekret", "msg": dict(VALID_HELLO)}
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(encode(wrapped))
        await writer.drain()
        ack = json.loads(await asyncio.wait_for(reader.readline(), 5))
        # the ack itself is token-wrapped when a token is configured
        assert ack["msg"]["type"] == "hello_ack"
        writer.close()
        assert registry.list_live()

    @pytest.mark.asyncio
    async def test_malformed_post_handshake_fails_closed(self, listener):
        """A malformed line after a successful handshake drops that one
        connection (documented fail-closed behavior) — but the listener
        survives and serves the next session cleanly."""
        _, registry, port = listener
        wrapped = {"token": "sekret", "msg": dict(VALID_HELLO)}
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(encode(wrapped))
        await writer.drain()
        ack = json.loads(await asyncio.wait_for(reader.readline(), 5))
        session = registry.get(ack["msg"]["session_id"])

        deep = b'{"token":"sekret","msg":' + b"[" * 200_000 + b"]" * 200_000 + b"}\n"
        writer.write(deep)
        await writer.drain()
        await asyncio.sleep(0.1)
        assert session.state == "disconnected"  # fail closed, no zombie

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(encode(wrapped))
        await writer.drain()
        ack2 = json.loads(await asyncio.wait_for(reader.readline(), 5))
        assert ack2["msg"]["type"] == "hello_ack"
        writer.close()


# --- plugin side --------------------------------------------------------------


class TestPluginDispatchLineRobustness:
    @pytest.mark.parametrize("seed", SEEDS)
    def test_garbage_lines_dropped_without_side_effects(self, plugin, seed):
        rng = random.Random(2000 + seed)
        for blob in _random_blobs(rng, 16):
            for raw in blob.split(b"\n")[:8]:
                plugin._dispatch_line(raw)  # must not raise
        assert plugin.in_q.empty()

    def test_deep_nesting_dropped(self, plugin):
        plugin._dispatch_line(b"[" * 200_000)
        plugin._dispatch_line(b'{"msg":' + b"[" * 200_000)
        assert plugin.in_q.empty()

    def test_non_object_and_wrong_token_dropped(self, plugin):
        plugin._dispatch_line(b"[1,2,3]")
        plugin._dispatch_line(b'"scalar"')
        plugin._dispatch_line(b'{"token":"wrong","msg":{"type":"ping","id":1}}')
        assert plugin.in_q.empty()

    def test_valid_request_still_dispatched(self, plugin):
        """Robustness must not over-reject: a well-formed ping reaches the
        reader-verb path and is answered immediately (not queued)."""
        plugin.out_q.queue.clear()
        plugin._dispatch_line(b'{"type":"request","id":5,"verb":"ping"}')
        assert plugin.in_q.empty()
        sent = []
        while not plugin.out_q.empty():
            sent.append(plugin.out_q.get_nowait())
        # out_q carries (wire_generation, line) pairs
        assert sent and b'"pong":true' in sent[0][1]
