"""Stdlib-only stand-in for the gdb-mcp SERVER side of the wire protocol.

Used by the WSL integration test to drive a REAL gdb running the plugin.
Implements just enough of the protocol: accept the plugin's hello, send
requests, collect responses and notifications.
"""

from __future__ import print_function

import argparse
import hmac
import json
import os
import socket
import sys
import threading
import time

DEBUG = os.environ.get("GDB_MCP_TEST_DEBUG") == "1"
TOKEN = os.environ.get("GDB_MCP_TEST_TOKEN")


class FakeServer(object):
    def __init__(self, port, token=None):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(4)
        self.sock.settimeout(60)
        self.conn = None
        self.buf = b""
        self.notifications = []
        self._notif_idx = 0
        self._next_id = 1000
        self.token = token

    def accept(self):
        self.conn, addr = self.sock.accept()
        print("[fake-server] plugin connected from %s" % (addr,), flush=True)
        self.conn.settimeout(60)
        # Watchdog: if the plugin ever reconnects (a second connection),
        # log it loudly — it explains lost messages on the first socket.
        def watchdog():
            while True:
                try:
                    extra, addr2 = self.sock.accept()
                except OSError:
                    return
                print(
                    "[fake-server] EXTRA CONNECTION from %s (plugin reconnected!)"
                    % (addr2,),
                    flush=True,
                )
                extra.close()

        threading.Thread(target=watchdog, daemon=True).start()

    def send(self, msg):
        if self.token:
            msg = {"token": self.token, "msg": msg}
        self.conn.sendall(json.dumps(msg).encode("utf-8") + b"\n")

    def _unwrap(self, envelope):
        if not self.token:
            return envelope
        supplied = envelope.get("token")
        if not isinstance(supplied, str) or not hmac.compare_digest(
            supplied, self.token
        ):
            raise RuntimeError("plugin sent a missing or invalid token")
        msg = envelope.get("msg")
        if not isinstance(msg, dict):
            raise RuntimeError("plugin sent an invalid token envelope")
        return msg

    def recv_msg(self, timeout=60.0):
        deadline = time.time() + timeout
        while True:
            # Serve already-buffered complete lines first (recv may batch
            # several messages into one chunk).
            if b"\n" in self.buf:
                raw, self.buf = self.buf.split(b"\n", 1)
                msg = self._unwrap(json.loads(raw.decode("utf-8")))
                if DEBUG:
                    print("  << %s" % msg, flush=True)
                return msg
            remaining = deadline - time.time()
            if remaining <= 0:
                raise RuntimeError("timeout waiting for message")
            self.conn.settimeout(min(1.0, remaining))
            try:
                data = self.conn.recv(65536)
            except socket.timeout:
                continue
            if not data:
                raise RuntimeError("connection closed by plugin")
            if DEBUG:
                print(
                    "  <raw %d bytes: %r>" % (len(data), data[:80]),
                    flush=True,
                )
            self.buf += data

    def expect(self, mtype, timeout=60.0):
        msg = self.recv_msg(timeout)
        assert msg.get("type") == mtype, "expected %r, got %r" % (mtype, msg)
        return msg

    def request(self, verb, params=None, timeout=120.0):
        """Send a request; return the response, collecting any
        notifications seen along the way."""
        rid = self._next_id
        self._next_id += 1
        self.send({"type": "request", "id": rid, "verb": verb, "params": params or {}})
        while True:
            msg = self.recv_msg(timeout)
            if msg.get("type") == "notification":
                self.notifications.append(msg)
                continue
            if msg.get("type") == "response" and msg.get("id") == rid:
                assert msg.get("ok"), "request %s failed: %s" % (verb, msg)
                return msg["result"]
            # response for some other request id: ignore

    def send_only(self, verb, params=None, rid=None):
        """Fire a request without waiting for its response."""
        if rid is None:
            rid = self._next_id
            self._next_id += 1
        self.send({"type": "request", "id": rid, "verb": verb, "params": params or {}})
        return rid

    def wait_for_event(self, event, timeout=60.0):
        """Wait for a notification of the given event type, consuming
        notifications up to (and including) the match."""
        for i in range(self._notif_idx, len(self.notifications)):
            msg = self.notifications[i]
            if msg.get("type") == "notification" and msg.get("event") == event:
                self._notif_idx = i + 1
                return msg
        self._notif_idx = len(self.notifications)
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = self.recv_msg(deadline - time.time())
            if msg.get("type") == "notification":
                idx = len(self.notifications)
                self.notifications.append(msg)
                if msg.get("event") == event:
                    self._notif_idx = idx + 1
                    return msg
        raise AssertionError("no %r notification within %ss" % (event, timeout))


def run(port, crasher):
    srv = FakeServer(port, TOKEN)
    srv.accept()

    hello = srv.expect("hello")
    print("[1] hello:", {k: hello.get(k) for k in ("gdb_version", "arch", "pid")}, flush=True)
    # Before any file is loaded, Debian's multiarch gdb defaults to i386;
    # the arch becomes x86_64 once the ELF is loaded.
    assert hello.get("arch") in ("x86_64", "i386", None), hello
    assert "gdb_interrupt" in hello.get("features", []), hello
    srv.send(
        {
            "type": "hello_ack",
            "proto": 1,
            "server_version": "0.1.0",
            "session_id": "s-integration",
            "heartbeat_sec": 30,
        }
    )
    srv.wait_for_event("ready")

    # load the target and break at main
    out = srv.request("file", {"path": crasher})
    tail = (out.get("output") or "").strip().splitlines()
    print("[2] file loaded: %s" % (tail[-1] if tail else "(no output)"), flush=True)
    bp = srv.request("break", {"location": "main"})
    print("[3] breakpoint #%s at main" % bp["number"], flush=True)

    # run to the breakpoint (eval 'run' blocks until the first stop)
    srv.request("eval", {"command": "run"})
    stop = srv.wait_for_event("stop")
    payload = stop["payload"]
    print("[4] stop at main: signal=%s pc=%s" % (payload.get("signal"), payload.get("pc")), flush=True)
    assert payload.get("signal") in ("SIGTRAP", "SIGILL", None), payload

    # continue into the crash
    srv.request("continue", {})
    stop = srv.wait_for_event("stop")
    payload = stop["payload"]
    print("[5] crash stop: %s" % payload, flush=True)
    assert payload["signal"] == "SIGSEGV", payload
    assert payload.get("fault_addr") == "0x0", payload
    pc = int(payload["pc"], 16)

    # structured inspection
    regs = srv.request("regs", {})["regs"]
    print("[6] regs: %d registers, rsp=%s" % (len(regs), regs.get("rsp")), flush=True)
    assert regs.get("rsp")
    frames = srv.request("backtrace", {"max_frames": 8})["frames"]
    names = [f.get("function", "?") for f in frames]
    print("[7] backtrace: %s" % names, flush=True)
    assert "crash" in names and "main" in names, names

    insns = srv.request("disasm", {"start": pc - 8, "count": 8})["instructions"]
    print("[8] disasm around pc: %d insns, last=%s" % (len(insns), insns[-1]["asm"]), flush=True)

    mem = srv.request("read_mem", {"addr": pc, "length": 16})
    print("[9] memory at pc: hex=%s" % mem["hex"], flush=True)

    sp = int(regs["rsp"], 16)
    w = srv.request("write_mem", {"addr": sp, "hex": "4141414141414141"})
    print("[10] wrote %d bytes to rsp" % w["bytes_written"], flush=True)
    assert w["bytes_written"] == 8

    ev = srv.request("evaluate", {"expression": "&main"})
    print("[11] evaluate &main -> %s" % ev["address"], flush=True)
    assert ev["address"].startswith("0x")
    # function symbols evaluate fine too, just without an address field
    ev2 = srv.request("evaluate", {"expression": "main"})
    assert "main" in ev2["value"]

    thr = srv.request("threads", {})
    print("[12] threads: %s" % [t["num"] for t in thr["threads"]], flush=True)

    bps = srv.request("breakpoints", {})["breakpoints"]
    print("[13] breakpoints: %s" % [b["number"] for b in bps], flush=True)

    # ---- interrupt test: restart the inferior in infinite-loop mode ----
    srv.request("eval", {"command": "set args loop"})
    srv.send_only("eval", {"command": "run"}, rid=9000)  # runs until interrupt
    srv.wait_for_event("running")
    # the restart stops at breakpoint #1 at main again; continue into the loop
    stop = srv.wait_for_event("stop")
    assert stop["payload"]["details"].get("reason") == "breakpoint-hit", stop
    srv.request("continue", {})
    srv.wait_for_event("running")
    time.sleep(1.0)  # let it spin in the loop
    intr = srv.request("interrupt", {})
    print("[14] interrupt requested: %s" % intr, flush=True)
    stop = srv.wait_for_event("stop", timeout=30)
    print("[15] stop after interrupt: signal=%s" % stop["payload"].get("signal"), flush=True)
    assert stop["payload"].get("signal") == "SIGINT", stop

    # ---- crash_report-style sequence already covered; now quit ----
    srv.send({"type": "quit", "reason": "integration_done", "kill_gdb": True})
    time.sleep(1.0)
    print("INTEGRATION OK", flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=39401)
    parser.add_argument("--crasher", required=True)
    args = parser.parse_args()
    return run(args.port, args.crasher)


if __name__ == "__main__":
    sys.exit(main())
