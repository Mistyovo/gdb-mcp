"""Tests for the plugin's gdb event handlers and connection logic."""

import json
import queue
import threading
import time

import mock_gdb
from mock_gdb import FakeExitedEvent, FakeStopEvent, set_inferior


def drain(plugin):
    out = []
    while True:
        try:
            line = plugin.out_q.get_nowait()
        except queue.Empty:
            return out
        msg = json.loads(line.decode("utf-8"))
        if "msg" in msg:  # token wrapper
            msg = msg["msg"]
        out.append(msg)


def last_notification(plugin, event):
    msgs = drain(plugin)
    for msg in reversed(msgs):
        if msg.get("type") == "notification" and msg.get("event") == event:
            return msg["payload"]
    return None


class TestStopEvent:
    def test_sigsegv_payload(self, plugin):
        set_inferior()  # newest frame at 0x401000
        plugin._connect_events()
        mock_gdb.events.stop.fire(
            FakeStopEvent("SIGSEGV", {"addr": 0x41414141, "stopped-threads": "all"})
        )
        payload = last_notification(plugin, "stop")
        assert payload["signal"] == "SIGSEGV"
        assert payload["fault_addr"] == "0x41414141"
        assert payload["pc"] == "0x401000"
        assert payload["thread"] == "1"
        assert payload["details"]["stopped-threads"] == "all"
        assert plugin.state == "stopped"
        assert plugin.stop_info == payload

    def test_no_details(self, plugin):
        set_inferior()
        plugin._connect_events()
        mock_gdb.events.stop.fire(FakeStopEvent("SIGTRAP", None))
        payload = last_notification(plugin, "stop")
        assert payload["signal"] == "SIGTRAP"
        assert "fault_addr" not in payload

    def test_none_signal_omitted(self, plugin):
        # real gdb reports stop_signal=None for breakpoint-hit stops
        set_inferior()
        plugin._connect_events()
        mock_gdb.events.stop.fire(
            FakeStopEvent(None, {"reason": "breakpoint-hit", "bkptno": 1})
        )
        payload = last_notification(plugin, "stop")
        assert "signal" not in payload
        assert payload["details"]["reason"] == "breakpoint-hit"

    def test_fault_addr_from_siginfo(self, plugin):
        # gdb >= 16: details carry no addr; plugin reads si_addr instead
        set_inferior()
        mock_gdb.state.expr_map["$_siginfo._sifields._sigfault.si_addr"] = 0x0
        plugin._connect_events()
        mock_gdb.events.stop.fire(
            FakeStopEvent("SIGSEGV", {"reason": "signal-received"})
        )
        payload = last_notification(plugin, "stop")
        assert payload["fault_addr"] == "0x0"

    def test_no_frame_tolerated(self, plugin):
        set_inferior()
        mock_gdb.state.newest_frame = None
        plugin._connect_events()
        mock_gdb.events.stop.fire(FakeStopEvent("SIGKILL", {}))
        payload = last_notification(plugin, "stop")
        assert "pc" not in payload


class TestOtherEvents:
    def test_cont(self, plugin):
        plugin._connect_events()
        mock_gdb.events.cont.fire(object())
        assert last_notification(plugin, "running") == {}
        assert plugin.state == "running"

    def test_exited(self, plugin):
        plugin._connect_events()
        mock_gdb.events.exited.fire(FakeExitedEvent(139))
        payload = last_notification(plugin, "exited")
        assert payload == {"exit_code": 139}
        assert plugin.state == "exited"

    def test_before_prompt(self, plugin):
        plugin._connect_events()
        plugin.state = "running"
        mock_gdb.events.before_prompt.fire()
        assert last_notification(plugin, "prompt") == {}
        assert plugin.state == "stopped"

    def test_disconnect_events_stops_notifications(self, plugin):
        plugin._connect_events()
        plugin._disconnect_events()
        mock_gdb.events.stop.fire(FakeStopEvent("SIGTRAP", {}))
        assert drain(plugin) == []

    def test_gdb_exiting_shuts_down(self, plugin):
        plugin._connect_events()
        mock_gdb.events.gdb_exiting.fire(object())
        assert plugin._shutdown_done is True


class TestHelloAck:
    def test_ack_sets_session_and_ready(self, plugin):
        plugin._dispatch_line(
            b'{"type":"hello_ack","server_version":"0.1.0",'
            b'"session_id":"s-abc","heartbeat_sec":30}'
        )
        assert plugin.session_id == "s-abc"
        assert plugin.state == "ready"
        payload = last_notification(plugin, "ready")
        assert payload["session_id"] == "s-abc"


class TestResolveHosts:
    def test_env_override(self, plugin, monkeypatch):
        monkeypatch.setenv("GDB_MCP_HOST", "1.2.3.4")
        assert plugin._resolve_hosts() == ["1.2.3.4"]

    def test_env_comma_list(self, plugin, monkeypatch):
        monkeypatch.setenv("GDB_MCP_HOST", "1.2.3.4, 5.6.7.8")
        assert plugin._resolve_hosts() == ["1.2.3.4", "5.6.7.8"]

    def test_fallback_nameserver(self, plugin, monkeypatch):
        monkeypatch.delenv("GDB_MCP_HOST", raising=False)
        real_open = open

        def fake_open(path, *a, **kw):
            if path == "/etc/resolv.conf":
                import io

                return io.StringIO("nameserver 10.0.0.2\nnameserver 10.0.0.2\n")
            return real_open(path, *a, **kw)

        monkeypatch.setattr("builtins.open", fake_open)
        assert plugin._resolve_hosts() == ["127.0.0.1", "10.0.0.2"]

    def test_default_no_resolv_conf(self, plugin, monkeypatch):
        monkeypatch.delenv("GDB_MCP_HOST", raising=False)
        assert plugin._resolve_hosts()[0] == "127.0.0.1"


class TestTokenAuth:
    def test_encode_wraps_token(self, plugin):
        plugin.token = "sekret"
        line = plugin._encode_msg({"type": "ping"})
        msg = json.loads(line.decode("utf-8"))
        assert msg["token"] == "sekret"
        assert msg["msg"] == {"type": "ping"}

    def test_dispatch_requires_token(self, plugin):
        plugin.token = "sekret"
        plugin._dispatch_line(
            b'{"token":"sekret","msg":{"type":"request","id":1,"verb":"ping","params":{}}}'
        )
        assert drain(plugin)[-1]["result"] == {"pong": True}

    def test_dispatch_wrong_token_dropped(self, plugin):
        plugin.token = "sekret"
        plugin._dispatch_line(
            b'{"token":"nope","msg":{"type":"request","id":1,"verb":"ping","params":{}}}'
        )
        assert drain(plugin) == []

    def test_dispatch_missing_token_dropped(self, plugin):
        plugin.token = "sekret"
        plugin._dispatch_line(b'{"type":"request","id":1,"verb":"ping","params":{}}')
        assert drain(plugin) == []


class FakeSocket:
    def __init__(self, incoming=b""):
        self._in = incoming
        self.sent = b""
        self.closed = False

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        if self._in:
            chunk, self._in = self._in[:n], self._in[n:]
            return chunk
        return b""

    def settimeout(self, t):
        pass

    def close(self):
        self.closed = True


class TestConnectionLoop:
    def test_hello_sent_and_ack_processed(self, plugin, monkeypatch):
        monkeypatch.setattr(plugin.__class__.__module__ + ".BACKOFF", [0.01], raising=False)
        import gdb_mcp_plugin_under_test as mod

        monkeypatch.setattr(mod, "BACKOFF", [0.01])
        fake = FakeSocket(
            b'{"type":"hello_ack","server_version":"0.1.0",'
            b'"session_id":"s-x","heartbeat_sec":30}\n'
        )
        results = [fake, None]  # second connect attempt fails

        def fake_connect(addr, timeout=None):
            return results.pop(0) if results else None

        monkeypatch.setattr("socket.create_connection", fake_connect)
        plugin._connect_events()
        thread = threading.Thread(target=plugin._thread_main, args=(plugin._connection_loop,))
        thread.start()
        try:
            deadline = time.time() + 5
            while not fake.sent and time.time() < deadline:
                time.sleep(0.01)
            hello = json.loads(fake.sent.split(b"\n")[0])
            assert hello["type"] == "hello"
            assert hello["pid"] > 0
            assert hello["arch"] == "x86_64"
            assert hello["plugin_version"]
            deadline = time.time() + 5
            while plugin.state != "ready" and time.time() < deadline:
                time.sleep(0.01)
            assert plugin.session_id == "s-x"
        finally:
            plugin.shutdown_evt.set()
            thread.join(5)
        assert not thread.is_alive()


class TestDoubleLoadGuard:
    def test_load_flag_set(self, plugin_mod, mock_env):
        import os

        assert os.environ.get("GDB_MCP_LOADED") == "1"

    def test_second_load_skips(self, plugin_mod, mock_env, capsys):
        # Re-executing the top level under GDB_MCP_LOADED=1 must not start
        # a second plugin instance.
        import importlib.util
        import os
        import sys

        os.environ["GDB_MCP_LOADED"] = "1"
        spec = importlib.util.spec_from_file_location(
            "gdb_mcp_plugin_reloaded", plugin_mod.__file__
        )
        mod2 = importlib.util.module_from_spec(spec)
        sys.modules["gdb_mcp_plugin_reloaded"] = mod2
        spec.loader.exec_module(mod2)
        err = capsys.readouterr().err
        assert "already loaded" in err
        assert mod2._PLUGIN is None
        sys.modules.pop("gdb_mcp_plugin_reloaded", None)
