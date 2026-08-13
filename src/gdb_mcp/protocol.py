"""Wire protocol v1 between the MCP server and the in-gdb plugin.

Framing: one compact JSON object per line, UTF-8, ``\\n`` terminated
(``\\r\\n`` tolerated), max line 32 MiB. The server is the TCP listener; the
plugin is the connecting client.

Message types:

* plugin -> server: ``hello``, ``response``, ``notification``
* server -> plugin: ``hello_ack``, ``request``, ``quit``

Optional auth: when the server is configured with a token, every plugin line
is wrapped as ``{"token": "<token>", "msg": {...}}`` and the server rejects
mismatched tokens.
"""

from __future__ import annotations

import json
from typing import Any

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
    }
)

# Verbs handled entirely on the plugin's reader thread (never queued onto the
# gdb main thread).
READER_VERBS = frozenset({"ping", "interrupt", "quit"})

# Execution verbs: the plugin replies immediately with {"state": "running"}
# and the actual resume happens afterwards on the gdb main thread.
ASYNC_VERBS = frozenset(
    {"continue", "step", "next", "stepi", "nexti", "finish", "until"}
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
        "server_version": server_version,
        "session_id": session_id,
        "heartbeat_sec": heartbeat_sec,
    }


def build_quit(reason: str, kill_gdb: bool = False) -> dict:
    return {"type": "quit", "reason": reason, "kill_gdb": kill_gdb}


def encode(msg: dict) -> bytes:
    """Serialize a message to one framed line (UTF-8 + ``\\n``)."""
    return json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    ) + b"\n"


# --- auth wrapping ---------------------------------------------------------


def wrap_with_token(token: str, msg: dict) -> dict:
    return {"token": token, "msg": msg}


def unwrap_token(msg: dict, token: str | None) -> dict:
    """Strip the optional token wrapper from a plugin message.

    When ``token`` is None (auth disabled), a wrapped message is still
    accepted and unwrapped; a bare message passes through unchanged.
    Returns the inner message, or raises ProtocolError on a bad token.
    """
    if not isinstance(msg, dict):
        raise ProtocolError("MALFORMED", "message must be a JSON object")
    if "msg" in msg:
        if token is not None and msg.get("token") != token:
            raise ProtocolError("MALFORMED", "auth token mismatch")
        inner = msg["msg"]
        if not isinstance(inner, dict):
            raise ProtocolError("MALFORMED", "wrapped msg must be an object")
        return inner
    if token is not None:
        raise ProtocolError("MALFORMED", "missing auth token")
    return msg


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
