"""Security audit log — deliberately separate from session journals.

Journals are a *functional* artifact: they feed gdbscript export, carry
trimmed target data, and get archived away with their session. The audit
log answers a different question — "what security-relevant decisions did
this server make, and can I prove afterwards that the record was not
edited?" — so it lives in its own file with its own retention and a
SHA-256 hash chain: every record commits to the previous record's hash,
making silent after-the-fact edits detectable via :func:`verify_log`.

Recorded events (all best-effort: auditing must never break the server):

* ``handshake`` / ``handshake_rejected`` — plugin TCP handshakes and why
  one was refused (auth mismatch, malformed hello, protocol mismatch)
* ``protocol_violation`` — malformed post-handshake line (connection is
  dropped fail-closed; the evidence stays here)
* ``http_rejected`` — MCP HTTP request refused by the hardening middleware
* ``observer_denied`` — an observer-role client calling a mutating tool
* ``unsafe_command_blocked`` — gdb escape-hatch command blocked

The file is opened per record (append mode, like the journal) so a crash
never loses a torn buffer of prior events.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path

log = logging.getLogger("gdb_mcp.audit")

#: sentinel prev-hash of the first record in a chain
GENESIS = "0" * 64

_TRIM_DETAIL = 200


class AuditLog:
    """Append-only, hash-chained JSONL audit writer.

    ``enabled=False`` (or no path) turns every call into a no-op, so call
    sites never need to check the flag themselves.
    """

    def __init__(self, path: Path | str | None, enabled: bool = True):
        self.path = Path(path) if path else None
        self.enabled = bool(enabled and self.path is not None)
        self._seq = 0
        self._prev = GENESIS
        self._loaded = False
        if self.enabled:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if not self.path.exists():
                    self.path.touch(mode=0o600)
            except OSError:
                log.warning("audit log unusable at %s; continuing without",
                            self.path)
                self.enabled = False

    # -- writing -------------------------------------------------------------

    def record(self, event: str, **details) -> None:
        """Append one chained record; never raises."""
        if not self.enabled:
            return
        self._ensure_loaded()
        record = {
            "ts": round(time.time(), 3),
            "seq": self._seq + 1,
            "event": event,
            "details": _bound(details),
        }
        digest = _chain_hash(self._prev, record)
        line = dict(record)
        line["prev"] = self._prev
        line["hash"] = digest
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(line, ensure_ascii=False) + "\n")
        except OSError:
            return  # audit must never break the server
        self._seq += 1
        self._prev = digest

    def _ensure_loaded(self) -> None:
        """One-time scan to resume the sequence counter and chain head
        across restarts (audit records are few; scanning is cheap)."""
        if self._loaded:
            return
        self._loaded = True
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        for line in lines:
            try:
                rec = json.loads(line)
            except ValueError:
                continue  # torn tail from a crash mid-write
            if not isinstance(rec, dict):
                continue
            if isinstance(rec.get("hash"), str):
                self._prev = rec["hash"]
            seq = rec.get("seq")
            if isinstance(seq, int) and not isinstance(seq, bool):
                self._seq = max(self._seq, seq)


def _bound(details: dict) -> dict:
    """Details are evidence, not payloads: cap unbounded strings so a
    hostile input cannot balloon the audit file."""

    def cap(value):
        if isinstance(value, str):
            return value[:_TRIM_DETAIL]
        if isinstance(value, dict):
            return {str(k)[:_TRIM_DETAIL]: cap(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [cap(v) for v in value[:32]]
        return value

    return {k: cap(v) for k, v in details.items()}


def _chain_hash(prev: str, record: dict) -> str:
    payload = json.dumps(
        record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256((prev + "|" + payload).encode("utf-8")).hexdigest()


def verify_log(path: Path | str) -> dict:
    """Recompute the hash chain of an audit file.

    Returns ``{"ok": bool, "records": n, "broken_at": seq | None,
    "error": str | None}``. A record whose stored hash does not match the
    recomputation, or whose ``prev`` does not equal the previous record's
    hash (including a deleted or reordered prefix), breaks the chain.
    """
    path = Path(path)
    result: dict = {"ok": True, "records": 0, "broken_at": None, "error": None}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return {**result, "ok": False, "error": "unreadable: %s" % exc}
    prev = GENESIS
    for line in lines:
        try:
            rec = json.loads(line)
        except ValueError:
            return {**result, "ok": False, "broken_at": None,
                    "error": "unparsable line"}
        if not isinstance(rec, dict) or not isinstance(rec.get("hash"), str):
            return {**result, "ok": False, "broken_at": None,
                    "error": "record without hash"}
        body = {k: rec[k] for k in ("ts", "seq", "event", "details") if k in rec}
        if _chain_hash(prev, body) != rec["hash"] or rec.get("prev") != prev:
            return {**result, "ok": False,
                    "broken_at": rec.get("seq"),
                    "error": "chain mismatch"}
        prev = rec["hash"]
        result["records"] += 1
    return result


def disabled() -> AuditLog:
    """A no-op audit log for contexts that opted out."""
    return AuditLog(None, enabled=False)


__all__ = ["AuditLog", "GENESIS", "verify_log", "disabled"]
