"""Wire protocol v1 between the MCP server and the in-gdb plugin.

Framing: one compact JSON object per line, UTF-8, ``\\n`` terminated
(``\\r\\n`` tolerated), max line 32 MiB. The server is the TCP listener; the
plugin is the connecting client.

Message types:

* plugin -> server: ``hello``, ``response``, ``notification``
* server -> plugin: ``hello_ack``, ``request``, ``quit``

Optional auth: when configured with a token, every line in both directions is
wrapped as ``{"token": "<token>", "msg": {...}}`` and either peer rejects a
missing or mismatched token.
"""

from __future__ import annotations

import json
import secrets
from typing import Any

from gdb_mcp import PROTOCOL_VERSION
from gdb_mcp.errors import ProtocolError

# --- constants -------------------------------------------------------------

ERROR_CODES = frozenset(
    {
        "MALFORMED",
        "UNKNOWN_VERB",
        "BAD_PARAMS",
        "INFERIOR_RUNNING",
        "NO_INFERIOR",
        "NO_FRAME",
        "MEMORY_ERROR",
        "INTERRUPT_FAILED",
        "TIMEOUT",
        "QUIT",
        "NO_SESSION",
        "AMBIGUOUS_SESSION",
        "LAUNCH_FAILED",
        "PLUGIN_ERROR",
        "DISCONNECTED",
        "PROTOCOL_MISMATCH",
        "UNSAFE_BLOCKED",
        "NO_PWNDBG",
        "NO_JOURNAL",
        "NO_RESULT",
        "NO_LOG",
        "NOT_LAUNCHED",
        "EXITED",
    }
)

# Verbs handled entirely on the plugin's reader thread (never queued onto the
# gdb main thread).
READER_VERBS = frozenset({"ping", "interrupt", "quit"})

# Execution verbs: the plugin replies immediately with {"state": "running"}
# and the actual resume happens afterwards on the gdb main thread.
ASYNC_VERBS = frozenset(
    {
        "continue",
        "step",
        "next",
        "stepi",
        "nexti",
        "finish",
        "until",
        "reverse_continue",
        "reverse_step",
        "reverse_next",
    }
)

# Server capabilities advertised in hello_ack. Additive by design: v1
# plugins ignore unknown hello_ack fields, and these describe optional
# server-side features rather than wire-format changes.
SERVER_CAPABILITIES = frozenset(
    {
        "journal",
        "campaign",
        "checkpoints",
        "policies",
        "io",
        "static",
        "observer-roles",
    }
)

# All request verbs the plugin understands.
VERBS = frozenset(
    {
        "eval",
        "read_mem",
        "write_mem",
        "regs",
        "set_reg",
        "backtrace",
        "disasm",
        "evaluate",
        "threads",
        "frame_select",
        "breakpoints",
        "break",
        "bp_delete",
        "bp_enable",
        "bp_disable",
        "mem_map",
        "file",
        "core",
        "snapshot_create",
        "snapshot_list",
        "snapshot_restore",
        "snapshot_diff",
        "policy",
        "io_setup",
        "io_send",
        "io_read",
        "io_teardown",
    }
) | ASYNC_VERBS | READER_VERBS

NOTIFICATION_EVENTS = frozenset(
    {"stop", "exited", "running", "prompt", "ready"}
)

HEARTBEAT_PING_ID = -1


# --- framing ---------------------------------------------------------------


class LineReader:
    """Incremental JSON-lines framing over an incoming byte stream.

    Raises :class:`ProtocolError` (``MALFORMED``) when a line exceeds
    ``max_line`` bytes; the connection should be dropped then.
    """

    def __init__(self, max_line: int):
        self.max_line = max_line
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        """Append ``data``; return complete lines (without the trailing
        newline)."""
        lines: list[bytes] = []
        self._buf.extend(data)
        while True:
            idx = self._buf.find(b"\n")
            if idx == -1:
                break
            raw = bytes(self._buf[:idx])
            del self._buf[: idx + 1]
            if raw.endswith(b"\r"):
                raw = raw[:-1]
            self._check_len(raw)
            lines.append(raw)
        # Guard against a never-terminated line growing unboundedly.
        self._check_len(bytes(self._buf))
        return lines

    def _check_len(self, raw: bytes) -> None:
        if len(raw) > self.max_line:
            raise ProtocolError(
                "MALFORMED", f"line exceeds {self.max_line} bytes"
            )


def parse_line(line: bytes) -> dict:
    """Decode and parse one framed JSON line into a dict message.

    Raises :class:`ProtocolError` (``MALFORMED``) on bad UTF-8, bad JSON, or
    a non-object payload.
    """
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError("MALFORMED", "line is not valid UTF-8") from exc
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProtocolError("MALFORMED", f"bad JSON: {exc.msg}") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("MALFORMED", "message must be a JSON object")
    return obj


# --- message builders (server -> plugin) -----------------------------------


def build_request(req_id: int, verb: str, params: dict | None = None) -> dict:
    return {"type": "request", "id": req_id, "verb": verb, "params": params or {}}


def build_ping() -> dict:
    return build_request(HEARTBEAT_PING_ID, "ping")


def build_hello_ack(
    session_id: str, server_version: str, heartbeat_sec: float
) -> dict:
    return {
        "type": "hello_ack",
        "proto": PROTOCOL_VERSION,
        "server_version": server_version,
        "session_id": session_id,
        "heartbeat_sec": heartbeat_sec,
        "capabilities": sorted(SERVER_CAPABILITIES),
    }


def build_quit(reason: str, kill_gdb: bool = False) -> dict:
    return {"type": "quit", "reason": reason, "kill_gdb": kill_gdb}


def encode(msg: dict, token: str | None = None) -> bytes:
    """Serialize a message to one framed line (UTF-8 + ``\\n``)."""
    if token:
        msg = wrap_with_token(token, msg)
    return json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    ) + b"\n"


# --- auth wrapping ---------------------------------------------------------


def wrap_with_token(token: str, msg: dict) -> dict:
    return {"token": token, "msg": msg}


def unwrap_token(msg: dict, token: str | None) -> dict:
    """Strip the optional token wrapper from a plugin message.

    When ``token`` is None (auth disabled), only bare messages are accepted.
    Returns the inner message, or raises ProtocolError on a bad token.
    """
    if not isinstance(msg, dict):
        raise ProtocolError("MALFORMED", "message must be a JSON object")
    if "msg" in msg:
        if token is None:
            raise ProtocolError("MALFORMED", "unexpected auth wrapper")
        supplied = msg.get("token")
        if (
            not isinstance(supplied, str)
            or not secrets.compare_digest(
                supplied.encode("utf-8"), token.encode("utf-8")
            )
        ):
            raise ProtocolError("MALFORMED", "auth token mismatch")
        inner = msg["msg"]
        if not isinstance(inner, dict):
            raise ProtocolError("MALFORMED", "wrapped msg must be an object")
        return inner
    if token is not None:
        raise ProtocolError("MALFORMED", "missing auth token")
    return msg


def peek_session_id(envelope: dict) -> str | None:
    """Best-effort session_id extraction from a possibly token-wrapped
    hello envelope. Used ONLY to select which verification token to
    apply — the envelope itself is still untrusted until unwrap."""
    if not isinstance(envelope, dict):
        return None
    inner = envelope.get("msg")
    if not isinstance(inner, dict):
        inner = envelope
    sid = inner.get("session_id")
    return sid if isinstance(sid, str) else None


def validate_hello(msg: dict) -> None:
    """Validate the plugin handshake before it enters the registry."""
    if msg.get("type") != "hello":
        raise ProtocolError("MALFORMED", "first message must be hello")
    proto = msg.get("proto")
    if proto != PROTOCOL_VERSION:
        raise ProtocolError(
            "PROTOCOL_MISMATCH",
            f"plugin protocol {proto!r} is incompatible with server protocol "
            f"{PROTOCOL_VERSION}",
        )
    session_id = msg.get("session_id")
    if session_id is not None and not isinstance(session_id, str):
        raise ProtocolError("MALFORMED", "hello session_id must be a string or null")
    pid = msg.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid < 1:
        raise ProtocolError("MALFORMED", "hello pid must be a positive integer")
    features = msg.get("features")
    if features is not None and (
        not isinstance(features, list)
        or any(not isinstance(feature, str) for feature in features)
    ):
        raise ProtocolError("MALFORMED", "hello features must be a list of strings")
    # E1: plugins built after the verb-table drift guard advertise their
    # full verb set; a mismatch means plugin/server builds are paired
    # incorrectly and every later request would fail — fail the
    # handshake instead.
    verbs = msg.get("verbs")
    if verbs is not None:
        if not isinstance(verbs, list) or any(
            not isinstance(verb, str) for verb in verbs
        ):
            raise ProtocolError("MALFORMED", "hello verbs must be a list of strings")
        mismatch = set(verbs).symmetric_difference(VERBS)
        if mismatch:
            raise ProtocolError(
                "PROTOCOL_MISMATCH",
                "plugin verb table does not match server (differing: %s); "
                "update the plugin file to match the server build"
                % ", ".join(sorted(mismatch))[:200],
            )


def validate_plugin_message(msg: dict) -> None:
    """Validate a post-handshake plugin message."""
    mtype = msg.get("type")
    if mtype == "response":
        req_id = msg.get("id")
        if not isinstance(req_id, int) or isinstance(req_id, bool):
            raise ProtocolError("MALFORMED", "response id must be an integer")
        if not isinstance(msg.get("ok"), bool):
            raise ProtocolError("MALFORMED", "response ok must be a boolean")
        if msg["ok"]:
            if not isinstance(msg.get("result", {}), dict):
                raise ProtocolError("MALFORMED", "response result must be an object")
        else:
            error = msg.get("error")
            if not isinstance(error, dict):
                raise ProtocolError("MALFORMED", "response error must be an object")
            if not isinstance(error.get("code"), str) or not isinstance(
                error.get("message"), str
            ):
                raise ProtocolError(
                    "MALFORMED", "response error requires string code and message"
                )
        return
    if mtype == "notification":
        event = msg.get("event")
        if event not in NOTIFICATION_EVENTS:
            raise ProtocolError("MALFORMED", f"unknown notification event {event!r}")
        if not isinstance(msg.get("payload", {}), dict):
            raise ProtocolError("MALFORMED", "notification payload must be an object")
        return
    raise ProtocolError("MALFORMED", f"unexpected message type {mtype!r}")


# --- message validation helpers --------------------------------------------


def error_message(code: str, message: str) -> dict:
    return {"code": code, "message": message}


def is_ok_response(msg: dict) -> bool:
    return bool(msg.get("ok", False))


def response_result(msg: dict) -> Any:
    """Extract ``result`` from a response; raise on error responses."""
    if is_ok_response(msg):
        return msg.get("result", {})
    err = msg.get("error", {})
    raise ProtocolError(
        err.get("code", "PLUGIN_ERROR"),
        err.get("message", "unknown plugin error"),
    )
