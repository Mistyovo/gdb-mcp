"""Tests for gdb_mcp.protocol framing and message helpers."""

import pytest

from gdb_mcp.errors import ProtocolError
from gdb_mcp.protocol import (
    ASYNC_VERBS,
    HEARTBEAT_PING_ID,
    LineReader,
    READER_VERBS,
    SERVER_CAPABILITIES,
    VERBS,
    build_hello_ack,
    build_ping,
    build_quit,
    build_request,
    encode,
    is_ok_response,
    parse_line,
    unwrap_token,
    validate_hello,
    validate_plugin_message,
    wrap_with_token,
)


class TestLineReader:
    def test_single_line(self):
        lr = LineReader(4096)
        assert lr.feed(b'{"a":1}\n') == [b'{"a":1}']

    def test_partial_feed(self):
        lr = LineReader(4096)
        assert lr.feed(b'{"a":1}') == []
        assert lr.feed(b"\n") == [b'{"a":1}']

    def test_multiple_lines_one_feed(self):
        lr = LineReader(4096)
        assert lr.feed(b'{"a":1}\n{"b":2}\n') == [b'{"a":1}', b'{"b":2}']

    def test_crlf_tolerated(self):
        lr = LineReader(4096)
        assert lr.feed(b'{"a":1}\r\n') == [b'{"a":1}']

    def test_empty_line(self):
        lr = LineReader(4096)
        assert lr.feed(b"\n") == [b""]

    def test_oversized_line_raises(self):
        lr = LineReader(8)
        with pytest.raises(ProtocolError) as ei:
            lr.feed(b"0123456789\n")
        assert ei.value.code == "MALFORMED"

    def test_oversized_unterminated_buffer_raises(self):
        lr = LineReader(8)
        with pytest.raises(ProtocolError):
            lr.feed(b"0123456789")


class TestParseLine:
    def test_valid(self):
        assert parse_line(b'{"type": "hello"}') == {"type": "hello"}

    def test_bad_utf8(self):
        with pytest.raises(ProtocolError) as ei:
            parse_line(b"\xff\xfe\x00\n")
        assert ei.value.code == "MALFORMED"

    def test_bad_json(self):
        with pytest.raises(ProtocolError) as ei:
            parse_line(b"{not json}\n")
        assert ei.value.code == "MALFORMED"

    def test_non_object(self):
        with pytest.raises(ProtocolError):
            parse_line(b"[1,2,3]")


class TestBuilders:
    def test_build_request(self):
        msg = build_request(7, "read_mem", {"addr": "main", "length": 16})
        assert msg == {
            "type": "request",
            "id": 7,
            "verb": "read_mem",
            "params": {"addr": "main", "length": 16},
        }

    def test_build_request_default_params(self):
        assert build_request(1, "ping")["params"] == {}

    def test_build_ping_uses_reserved_id(self):
        assert build_ping()["id"] == HEARTBEAT_PING_ID
        assert build_ping()["verb"] == "ping"

    def test_build_hello_ack(self):
        msg = build_hello_ack("s-abc", "0.1.0", 30.0)
        assert msg["type"] == "hello_ack"
        assert msg["proto"] == 1
        assert msg["session_id"] == "s-abc"

    def test_build_quit(self):
        assert build_quit("server_shutdown") == {
            "type": "quit",
            "reason": "server_shutdown",
            "kill_gdb": False,
        }
        assert build_quit("x", kill_gdb=True)["kill_gdb"] is True

    def test_encode_compact_line(self):
        line = encode({"type": "ping"})
        assert line == b'{"type":"ping"}\n'
        # ensure_ascii=False keeps UTF-8 text readable
        assert encode({"t": "é"}) == '{"t":"é"}\n'.encode("utf-8")

    def test_encode_roundtrip(self):
        msg = {"type": "request", "id": 3, "verb": "eval", "params": {"command": "vmmap"}}
        assert parse_line(encode(msg)) == msg

    def test_encode_with_token(self):
        encoded = parse_line(encode({"type": "ping"}, "sekret"))
        assert encoded == {"token": "sekret", "msg": {"type": "ping"}}


class TestTokenAuth:
    def test_wrap_unwrap(self):
        wrapped = wrap_with_token("sekret", {"type": "hello"})
        assert unwrap_token(wrapped, "sekret") == {"type": "hello"}

    def test_unicode_token(self):
        wrapped = wrap_with_token("密钥", {"type": "hello"})
        assert unwrap_token(wrapped, "密钥") == {"type": "hello"}

    def test_mismatch_raises(self):
        wrapped = wrap_with_token("sekret", {"type": "hello"})
        with pytest.raises(ProtocolError) as ei:
            unwrap_token(wrapped, "other")
        assert ei.value.code == "MALFORMED"

    def test_missing_token_raises_when_configured(self):
        with pytest.raises(ProtocolError):
            unwrap_token({"type": "hello"}, "sekret")

    def test_bare_message_passthrough_without_token(self):
        assert unwrap_token({"type": "hello"}, None) == {"type": "hello"}

    def test_wrapped_message_rejected_without_token(self):
        wrapped = wrap_with_token("anything", {"type": "hello"})
        with pytest.raises(ProtocolError):
            unwrap_token(wrapped, None)

    def test_inner_must_be_object(self):
        with pytest.raises(ProtocolError):
            unwrap_token({"token": "t", "msg": [1]}, "t")


class TestMessageValidation:
    def test_valid_hello(self):
        validate_hello({"type": "hello", "proto": 1, "pid": 123})

    def test_protocol_mismatch(self):
        with pytest.raises(ProtocolError) as exc:
            validate_hello({"type": "hello", "proto": 2, "pid": 123})
        assert exc.value.code == "PROTOCOL_MISMATCH"

    @pytest.mark.parametrize(
        "message",
        [
            {"type": "response", "id": [], "ok": True, "result": {}},
            {"type": "response", "id": 1, "ok": "yes", "result": {}},
            {"type": "notification", "event": "unknown", "payload": {}},
            {"type": "notification", "event": "stop", "payload": []},
        ],
    )
    def test_malformed_plugin_messages_rejected(self, message):
        with pytest.raises(ProtocolError):
            validate_plugin_message(message)

    def test_valid_plugin_messages(self):
        validate_plugin_message(
            {"type": "response", "id": 1, "ok": True, "result": {}}
        )
        validate_plugin_message(
            {"type": "notification", "event": "stop", "payload": {}}
        )


class TestVerbSets:
    def test_reader_and_async_verbs_disjoint(self):
        assert READER_VERBS & ASYNC_VERBS == set()

    def test_all_verbs_known(self):
        assert READER_VERBS | ASYNC_VERBS <= VERBS

    def test_plugin_verb_table_matches_protocol(self, plugin_mod):
        """H5: the two hand-written verb tables must never drift."""
        plugin_verbs = (
            set(plugin_mod.VERB_HANDLERS)
            | set(plugin_mod.ASYNC_VERBS)
            | set(plugin_mod.READER_VERBS)
        )
        assert plugin_verbs == set(VERBS)
        # every gated verb must be a dispatchable sync verb
        assert set(plugin_mod.GATED_VERBS) <= set(plugin_mod.VERB_HANDLERS)
        assert not (
            set(plugin_mod.GATED_VERBS)
            & (set(plugin_mod.ASYNC_VERBS) | set(plugin_mod.READER_VERBS))
        )


class TestProtocolV2:
    def _hello(self, **extra):
        hello = {
            "type": "hello",
            "proto": 1,
            "pid": 5,
            "features": ["gdb_interrupt"],
            "verbs": sorted(VERBS),
        }
        hello.update(extra)
        return hello

    def test_matching_verbs_pass(self):
        validate_hello(self._hello())

    def test_mismatched_verbs_rejected(self):
        with pytest.raises(ProtocolError) as ei:
            validate_hello(self._hello(verbs=sorted(VERBS - {"eval"})))
        assert ei.value.code == "PROTOCOL_MISMATCH"
        assert "eval" in ei.value.message

    def test_missing_verbs_is_backward_compatible(self):
        hello = self._hello()
        del hello["verbs"]
        validate_hello(hello)

    def test_malformed_verbs_rejected(self):
        with pytest.raises(ProtocolError) as ei:
            validate_hello(self._hello(verbs="eval"))
        assert ei.value.code == "MALFORMED"

    def test_hello_ack_advertises_capabilities(self):
        ack = build_hello_ack("s-1", "0.1.0", 30.0)
        assert ack["capabilities"] == sorted(SERVER_CAPABILITIES)
        assert "journal" in ack["capabilities"]

    def test_plugin_verb_table_matches_protocol(self, plugin_mod):
        """H5: the two hand-written verb tables must never drift."""
        plugin_verbs = (
            set(plugin_mod.VERB_HANDLERS)
            | set(plugin_mod.ASYNC_VERBS)
            | set(plugin_mod.READER_VERBS)
        )
        assert plugin_verbs == set(VERBS)
        # every gated verb must be a dispatchable sync verb
        assert set(plugin_mod.GATED_VERBS) <= set(plugin_mod.VERB_HANDLERS)
        assert not (
            set(plugin_mod.GATED_VERBS)
            & (set(plugin_mod.ASYNC_VERBS) | set(plugin_mod.READER_VERBS))
        )


class TestResponseHelpers:
    def test_is_ok_response(self):
        assert is_ok_response({"ok": True, "result": {}}) is True
        assert is_ok_response({"ok": False, "error": {}}) is False
        assert is_ok_response({}) is False
