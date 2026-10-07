"""Security audit log — deliberately separate from session journals.

Journals are a *functional* artifact: they feed gdbscript export, carry
trimmed target data, and get archived away with their session. The audit
log answers a different question — "what security-relevant decisions did
this server make, and can I prove afterwards that the record was not
edited?" — so it lives in its own file with its own retention and a
chained MAC: every record commits to the previous record's hash, making
silent after-the-fact edits detectable via :func:`verify_log`.

Two chain algorithms exist:

* ``hmac-sha256`` — used when the server has a master token configured
  (the default for token-protected deployments). Without the secret, an
  attacker with write access to the file cannot re-forge a rewritten
  chain; ``verify_log(path, key=...)`` additionally refuses records that
  are not HMAC-protected, so downgrading a keyed chain to plain hashes
  is itself detected.
* ``sha256`` — plain hash chain for tokenless deployments. It detects
  opportunistic edits, not a determined rewriter.

Tail truncation (dropping the last records and keeping a self-consistent
chain) cannot be detected from the file alone. As a mitigation the writer
logs a chain-head *anchor* to stderr every :data:`ANCHOR_INTERVAL` records
— anchors live outside the rewriteable audit file, so the last anchored
head bounds what can be silently cut.

Recorded events (all best-effort: auditing must never break the server):

* ``handshake`` / ``handshake_rejected`` — plugin TCP handshakes and why
  one was refused (auth mismatch, malformed hello, protocol mismatch)
* ``protocol_violation`` — malformed post-handshake line (connection is
  dropped fail-closed; the evidence stays here)
* ``http_rejected`` — MCP HTTP request refused by the hardening middleware
* ``observer_denied`` — an observer-role client calling a mutating tool
* ``unsafe_command_blocked`` — gdb escape-hatch command blocked

The file is opened per record (append mode, like the journal) so a crash
never loses a torn buffer of prior events. Write failures never raise,
but they are counted (:attr:`AuditLog.failed_writes`) and warned about
once — a dead audit log must at least be visible as dead.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from pathlib import Path

log = logging.getLogger("gdb_mcp.audit")

#: sentinel prev-hash of the first record in a chain
GENESIS = "0" * 64

#: chain-head anchors logged between writes of this many records
ANCHOR_INTERVAL = 256

#: record algorithm names (stored inside the hashed body)
PLAIN = "sha256"
KEYED = "hmac-sha256"

_TRIM_DETAIL = 200


class AuditLog:
    """Append-only, hash-chained JSONL audit writer.

    ``enabled=False`` (or no path) turns every call into a no-op, so call
    sites never need to check the flag themselves. ``key`` (the server's
    master token) switches the chain to HMAC-SHA256; keep it secret —
    whoever holds it can forge a consistent chain.
    """

    #: class-level so tests can shrink the anchor cadence
    ANCHOR_INTERVAL = ANCHOR_INTERVAL

    def __init__(self, path: Path | str | None, enabled: bool = True,
                 key: str | bytes | None = None):
        self.path = Path(path) if path else None
        self.key: bytes | None = key.encode("utf-8") if isinstance(key, str) else key
        self.enabled = bool(enabled and self.path is not None)
        self._seq = 0
        self._prev = GENESIS
        self._loaded = False
        self._since_anchor = 0
        #: appends that failed after init — audit stopped recording, which
        #: must be observable (see stats()) rather than silently absorbed
        self.failed_writes = 0
        self._warned_failure = False
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
            "algo": KEYED if self.key else PLAIN,
        }
        digest = _chain_hash(self._prev, record, self.key)
        line = dict(record)
        line["prev"] = self._prev
        line["hash"] = digest
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(line, ensure_ascii=False) + "\n")
        except OSError as exc:
            self.failed_writes += 1
            if not self._warned_failure:
                self._warned_failure = True
                log.warning(
                    "audit log write failed (%s); audit records are being "
                    "dropped until %s becomes writable again — check disk "
                    "space and permissions", exc, self.path)
            return  # audit must never break the server
        self._warned_failure = False
        self._seq += 1
        self._prev = digest
        self._since_anchor += 1
        if self._since_anchor >= self.ANCHOR_INTERVAL:
            self._since_anchor = 0
            self._anchor()

    def _anchor(self) -> None:
        """Emit the chain head OUTSIDE the rewriteable audit file. An
        attacker who truncates the tail cannot forge these stderr lines,
        so the newest anchor bounds the silent-cut window. Logged at
        WARNING so default configurations surface it."""
        log.warning("audit chain anchor: seq=%d head=%s algo=%s",
                    self._seq, self._prev, KEYED if self.key else PLAIN)

    def stats(self) -> dict:
        """Live health of the audit log (also usable as an anchor source
        for external monitoring)."""
        return {
            "enabled": self.enabled,
            "seq": self._seq,
            "head": self._prev,
            "algo": KEYED if self.key else PLAIN,
            "failed_writes": self.failed_writes,
        }

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
        legacy_plain = 0
        for line in lines:
            try:
                rec = json.loads(line)
            except ValueError:
                continue  # torn tail from a crash mid-write
            if not isinstance(rec, dict):
                continue
            if isinstance(rec.get("hash"), str):
                self._prev = rec["hash"]
            if rec.get("algo", PLAIN) == PLAIN:
                legacy_plain += 1
            seq = rec.get("seq")
            if isinstance(seq, int) and not isinstance(seq, bool):
                self._seq = max(self._seq, seq)
        if self.key and legacy_plain:
            log.warning(
                "audit.log resumes on a chain with %d unkeyed (plain "
                "sha256) records; they verify only without a key. Rotate "
                "the file (archive + fresh start) for a fully keyed chain.",
                legacy_plain)


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


def _chain_hash(prev: str, record: dict, key: bytes | None = None) -> str:
    payload = json.dumps(
        record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    data = (prev + "|" + payload).encode("utf-8")
    if key:
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


def verify_log(path: Path | str, key: str | bytes | None = None) -> dict:
    """Recompute the hash chain of an audit file.

    Returns ``{"ok": bool, "records": n, "broken_at": seq | None,
    "error": str | None}``. A record whose stored hash does not match the
    recomputation, or whose ``prev`` does not equal the previous record's
    hash (including a deleted or reordered prefix), breaks the chain.

    With ``key`` (the master token) the verification is strict: any record
    that is not HMAC-protected fails the report — a chain downgraded from
    keyed to plain hashes is treated as tampered, because whoever rewrote
    it could not produce valid MACs. Files written before the token
    existed verify only without a key (see the rotation note in
    :meth:`AuditLog._ensure_loaded`)."""
    if isinstance(key, str):
        key = key.encode("utf-8")
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
        algo = rec.get("algo", PLAIN)
        if algo == KEYED and not key:
            return {**result, "ok": False,
                    "error": "keyed record: re-verify with the master token"}
        if algo == PLAIN and key:
            return {**result, "ok": False, "broken_at": rec.get("seq"),
                    "error": "unkeyed record in keyed verification "
                             "(pre-token record or downgrade attack); "
                             "verify without the key or rotate the log"}
        body = {k: rec[k]
                for k in ("ts", "seq", "event", "details", "algo") if k in rec}
        mac_key = key if algo == KEYED else None
        if _chain_hash(prev, body, mac_key) != rec["hash"] or rec.get("prev") != prev:
            return {**result, "ok": False,
                    "broken_at": rec.get("seq"),
                    "error": "chain mismatch"}
        prev = rec["hash"]
        result["records"] += 1
    return result


def disabled() -> AuditLog:
    """A no-op audit log for contexts that opted out."""
    return AuditLog(None, enabled=False)


def _main(argv: list[str] | None = None) -> int:  # pragma: no cover
    """``python -m gdb_mcp.audit <audit.log> [--token MASTER]`` — verify a
    chain offline. Exit code 0 = intact, 1 = broken, 2 = usage error."""
    import argparse

    parser = argparse.ArgumentParser(prog="python -m gdb_mcp.audit")
    parser.add_argument("path", help="audit.log to verify")
    parser.add_argument("--token", help="master token for HMAC verification")
    args = parser.parse_args(argv)
    report = verify_log(args.path, key=args.token)
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())

__all__ = ["AuditLog", "GENESIS", "verify_log", "disabled"]
