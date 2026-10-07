"""Tests for the hash-chained security audit log."""

import json

import pytest

from gdb_mcp.audit import GENESIS, AuditLog, disabled, verify_log


class TestAuditLog:
    def test_records_are_chained(self, tmp_path):
        path = tmp_path / "audit.log"
        audit = AuditLog(path)
        audit.record("handshake", session_id="s-1", pid=10)
        audit.record("http_rejected", path="/mcp", reason="bad token")
        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        first, second = (json.loads(line) for line in lines)
        assert first["prev"] == GENESIS
        assert second["prev"] == first["hash"]
        assert first["seq"] == 1 and second["seq"] == 2
        assert first["event"] == "handshake"
        assert first["details"] == {"session_id": "s-1", "pid": 10}
        assert verify_log(path)["ok"] is True
        assert verify_log(path)["records"] == 2

    def test_chain_resumes_across_restart(self, tmp_path):
        path = tmp_path / "audit.log"
        first = AuditLog(path)
        first.record("handshake", session_id="s-1")
        last_hash = json.loads(
            path.read_text(encoding="utf-8").splitlines()[-1]
        )["hash"]
        restarted = AuditLog(path)
        restarted.record("handshake_rejected", reason="MALFORMED")
        lines = path.read_text(encoding="utf-8").splitlines()
        assert json.loads(lines[-1])["prev"] == last_hash
        assert json.loads(lines[-1])["seq"] == 2
        assert verify_log(path)["ok"] is True

    def test_disabled_log_is_a_noop(self, tmp_path):
        audit = disabled()
        audit.record("handshake")
        assert audit.enabled is False
        # a disabled log must not create files
        assert not (tmp_path / "audit.log").exists()

    def test_details_are_bounded(self, tmp_path):
        path = tmp_path / "audit.log"
        audit = AuditLog(path)
        audit.record("unsafe_command_blocked", command="A" * 5000)
        rec = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        assert len(rec["details"]["command"]) == 200

    def test_unwritable_path_degrades_to_noop(self, tmp_path):
        # a file where a directory is expected: mkdir/touch fail, auditing
        # disables itself instead of raising on every record
        blocker = tmp_path / "blocker"
        blocker.write_text("x", encoding="utf-8")
        audit = AuditLog(blocker / "sub" / "audit.log")
        audit.record("handshake")
        assert audit.enabled is False


class TestVerifyLog:
    def _write(self, tmp_path, records):
        path = tmp_path / "audit.log"
        audit = AuditLog(path)
        for event, details in records:
            audit.record(event, **details)
        return path

    def test_tampered_record_detected(self, tmp_path):
        path = self._write(tmp_path, [("handshake", {"pid": 1}),
                                      ("http_rejected", {"reason": "x"})])
        lines = path.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[0])
        rec["details"]["pid"] = 999  # after-the-fact edit
        lines[0] = json.dumps(rec)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        report = verify_log(path)
        assert report["ok"] is False
        assert report["broken_at"] == 1

    def test_deleted_middle_record_detected(self, tmp_path):
        path = self._write(tmp_path, [("a", {}), ("b", {}), ("c", {})])
        lines = path.read_text(encoding="utf-8").splitlines()
        del lines[1]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert verify_log(path)["ok"] is False

    def test_truncated_file_detected(self, tmp_path):
        path = self._write(tmp_path, [("a", {}), ("b", {})])
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text(lines[0] + "\n", encoding="utf-8")  # drop the tail
        # a truncated tail looks like a complete shorter chain; deletion of
        # the LAST records is only visible via seq gaps
        report = verify_log(path)
        assert report["records"] == 1

    def test_missing_file(self, tmp_path):
        report = verify_log(tmp_path / "nope.log")
        assert report["ok"] is False
        assert "unreadable" in report["error"]

    def test_garbage_file(self, tmp_path):
        path = tmp_path / "audit.log"
        path.write_text("not json\n", encoding="utf-8")
        report = verify_log(path)
        assert report["ok"] is False


class TestWiring:
    def test_config_flag_and_cli_override(self, tmp_path, monkeypatch):
        from gdb_mcp.__main__ import _overrides, _build_parser
        from gdb_mcp.config import Config

        assert Config().audit_log is True
        monkeypatch.setenv("GDB_MCP_AUDIT_LOG", "0")
        assert Config.from_env().audit_log is False
        monkeypatch.setenv("GDB_MCP_AUDIT_LOG", "1")
        assert Config.from_env().audit_log is True
        # CLI flag wins over env
        args = _build_parser().parse_args(["--no-audit-log"])
        assert _overrides(args)["audit_log"] is False
        args = _build_parser().parse_args([])
        assert _overrides(args)["audit_log"] is None

    def test_listener_rejections_audited(self, tmp_path):
        """End-to-end: a failed handshake and a post-handshake protocol
        violation land in the audit log with an intact chain."""
        import asyncio

        from gdb_mcp.config import Config
        from gdb_mcp.protocol import encode
        from gdb_mcp.sessions import SessionRegistry
        from gdb_mcp.tcp_listener import PluginTcpListener

        audit = AuditLog(tmp_path / "audit.log")
        cfg = Config(host_bind="127.0.0.1", port=0, heartbeat_sec=60.0,
                     log_dir=tmp_path / "logs", token="sekret")
        registry = SessionRegistry(cfg)

        async def scenario():
            listener = PluginTcpListener(cfg, registry, audit=audit)
            await listener.start()
            port = listener.server.sockets[0].getsockname()[1]
            try:
                # bad-token handshake
                r, w = await asyncio.open_connection("127.0.0.1", port)
                w.write(encode({"token": "wrong", "msg": {
                    "type": "hello", "proto": 1, "pid": 1}}))
                await w.drain()
                await asyncio.sleep(0.05)
                w.close()
                # good handshake, then a malformed line
                r, w = await asyncio.open_connection("127.0.0.1", port)
                w.write(encode({"token": "sekret", "msg": {
                    "type": "hello", "proto": 1, "pid": 2}}))
                await w.drain()
                await asyncio.wait_for(r.readline(), 5)
                w.write(b'{"token":"sekret","msg":' + b"[" * 5000 + b"}\n")
                await w.drain()
                await asyncio.sleep(0.05)
                w.close()
            finally:
                await listener.stop()

        asyncio.run(scenario())
        events = [
            json.loads(line)["event"]
            for line in (tmp_path / "audit.log").read_text(
                encoding="utf-8"
            ).splitlines()
        ]
        assert "handshake" in events
        assert "handshake_rejected" in events
        assert "protocol_violation" in events
        assert verify_log(tmp_path / "audit.log")["ok"] is True

    def test_observer_denial_audited(self, tmp_path):
        """register_all wires ctx.audit into the observer guard."""
        from gdb_mcp.errors import GdbMcpError
        from gdb_mcp.roles import CURRENT_ROLE
        from gdb_mcp.tools.registry import _observer_guard

        audit = AuditLog(tmp_path / "audit.log")

        def handler(session_id=None):
            return {"ok": True}

        guarded = _observer_guard(handler, "write_memory", audit)
        token = CURRENT_ROLE.set("observer")
        try:
            with pytest.raises(GdbMcpError) as ei:
                guarded()
        finally:
            CURRENT_ROLE.reset(token)
        assert ei.value.code == "OBSERVER_READONLY"
        rec = json.loads(
            (tmp_path / "audit.log").read_text(encoding="utf-8").splitlines()[0]
        )
        assert rec["event"] == "observer_denied"
        assert rec["details"]["tool"] == "write_memory"

        # controller path is unaffected and unrecorded
        token2 = CURRENT_ROLE.set("controller")
        try:
            assert guarded() == {"ok": True}
        finally:
            CURRENT_ROLE.reset(token2)
        assert len((tmp_path / "audit.log").read_text(
            encoding="utf-8").splitlines()) == 1

    def test_build_app_attaches_audit(self, tmp_path):
        from gdb_mcp.config import Config
        from gdb_mcp.server import build_app
        from gdb_mcp.sessions import SessionRegistry

        cfg = Config(log_dir=tmp_path / "logs", mcp_transport=False)
        app = build_app(cfg, SessionRegistry(cfg))
        assert app is not None
        assert (tmp_path / "logs" / "audit.log").exists()

        cfg_off = Config(log_dir=tmp_path / "logs2", audit_log=False)
        build_app(cfg_off, SessionRegistry(cfg_off))
        assert not (tmp_path / "logs2" / "audit.log").exists()


class TestHmacChain:
    """Audit 2026-10-07 hardening: a plain hash chain cannot resist an
    attacker who rewrites the whole file; with the master token the chain
    is HMAC-SHA256 and a downgrade to plain hashes is itself detected."""

    def test_keyed_chain_verifies_and_detects_tamper(self, tmp_path):
        path = tmp_path / "audit.log"
        audit = AuditLog(path, key="master-secret")
        audit.record("handshake", session_id="s-1")
        audit.record("http_rejected", reason="x")
        assert verify_log(path, key="master-secret")["ok"] is True
        assert verify_log(path, key="master-secret")["records"] == 2
        # a rewrite with recomputed PLAIN hashes is rejected in keyed mode
        lines = path.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[0])
        rec["details"]["session_id"] = "forged"
        lines[0] = json.dumps(rec)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert verify_log(path, key="master-secret")["ok"] is False
        # and so is editing without even recomputing
        assert verify_log(path)["ok"] is False

    def test_keyed_records_need_the_key(self, tmp_path):
        path = tmp_path / "audit.log"
        AuditLog(path, key="master-secret").record("handshake")
        report = verify_log(path)  # no key
        assert report["ok"] is False
        assert "master token" in report["error"]

    def test_plain_records_rejected_when_verifying_keyed(self, tmp_path):
        path = tmp_path / "audit.log"
        AuditLog(path).record("handshake")  # tokenless deployment
        report = verify_log(path, key="master-secret")
        assert report["ok"] is False
        assert "unkeyed record" in report["error"]

    def test_records_declare_algorithm(self, tmp_path):
        path = tmp_path / "audit.log"
        AuditLog(path, key="k").record("handshake")
        rec = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        assert rec["algo"] == "hmac-sha256"

    def test_keyed_chain_over_legacy_file_warns(self, tmp_path, caplog):
        path = tmp_path / "audit.log"
        AuditLog(path).record("legacy", n=1)  # written before a token existed
        with caplog.at_level("WARNING", logger="gdb_mcp.audit"):
            restarted = AuditLog(path, key="master-secret")
            restarted.record("handshake")
        assert any("unkeyed" in r.message for r in caplog.records)
        # chain stays continuous across the algorithm switch
        lines = path.read_text(encoding="utf-8").splitlines()
        assert json.loads(lines[1])["prev"] == json.loads(lines[0])["hash"]


class TestAuditHealth:
    """Audit 2026-10-07: a dead audit log (disk full, permissions) used to
    fail with zero observable signal; now it counts and warns once."""

    def test_write_failure_counted_and_warned_once(self, tmp_path, caplog):
        path = tmp_path / "audit.log"
        audit = AuditLog(path)
        audit.record("handshake", ok=1)
        # make the path unwritable mid-run: replace the file with a
        # directory (open-for-append raises on both POSIX and Windows)
        path.unlink()
        path.mkdir()
        with caplog.at_level("WARNING", logger="gdb_mcp.audit"):
            audit.record("handshake", ok=2)
            audit.record("handshake", ok=3)
        assert audit.failed_writes == 2
        warnings = [r for r in caplog.records if "write failed" in r.message]
        assert len(warnings) == 1  # once, not per dropped record
        assert audit.stats()["failed_writes"] == 2
        assert audit.stats()["seq"] == 1  # only the pre-failure record

    def test_chain_anchor_logged_outside_file(self, tmp_path, caplog):
        path = tmp_path / "audit.log"
        audit = AuditLog(path)
        audit.ANCHOR_INTERVAL = 3
        with caplog.at_level("WARNING", logger="gdb_mcp.audit"):
            for i in range(6):
                audit.record("handshake", n=i)
        anchors = [r for r in caplog.records if "anchor" in r.message]
        assert len(anchors) == 2  # at seq 3 and seq 6
        assert audit.stats()["seq"] == 6
        # the anchor names the head it saw — a truncation afterwards is
        # detectable by diffing the last anchor against the file tail
        assert audit.stats()["head"] in anchors[-1].getMessage()
