"""Driver for run_pc_control_smoke.sh: exercises the plugin's
``verify_pc_control`` policy against a real gdb (issue 13).

Two builds of pc_control_target.c:
  * vuln : unbounded strcpy -> a canary written at offset 32 becomes PC
           -> verified == True, observed == canary
  * safe : bounded strncpy  -> the canary cannot reach PC; the run reaches
           the ``done`` marker -> verified == False
"""

from __future__ import print_function

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fake_mcp_client import FakeServer  # noqa: E402

TOKEN = os.environ.get("GDB_MCP_TEST_TOKEN")
CANARY = 0x0000414243444546
OFFSET = 32


def start(srv, binary):
    srv.request("file", {"path": binary})
    srv.request("break", {"location": "handle"})
    srv.request("eval", {"command": "run"})
    srv.wait_for_event("stop")
    # the start breakpoint would re-fire on every replay and stop the
    # round before the overflow; only the verify marker may stop it
    srv.request("eval", {"command": "delete"})


def buffer_addr(srv):
    r = srv.request("eval", {"command": "print/x &g_input"})
    return int(r["output"].split()[-1], 16)


def checkpoint(srv):
    r = srv.request("snapshot_create", {})
    return r["snapshot_id"]


def verify(srv, sid, buf_addr):
    return srv.request(
        "policy",
        {
            "kind": "verify_pc_control",
            "snapshot_id": sid,
            "buffer_addr": buf_addr,
            "stop_location": "done",
            "offset": OFFSET,
            "canary": CANARY,
            "payload": "",
            "target": "pc",
        },
        timeout=120.0,
    )


def run(port, vuln, safe):
    srv = FakeServer(port, TOKEN)
    srv.accept()
    hello = srv.expect("hello")
    print("[1] hello: gdb %s" % hello.get("gdb_version"), flush=True)
    srv.send(
        {
            "type": "hello_ack",
            "proto": 1,
            "server_version": "0.1.0",
            "session_id": "s-pc-control-smoke",
            "heartbeat_sec": 30,
        }
    )
    srv.wait_for_event("ready")

    # ---- controllable build: canary at offset 32 hijacks PC -------------
    start(srv, vuln)
    addr = buffer_addr(srv)
    print("[2] vuln &g_input: 0x%x" % addr, flush=True)
    sid = checkpoint(srv)
    r = verify(srv, sid, addr)
    print("[3] vuln verify: %s" % {k: r.get(k) for k in
                                   ("verified", "expected", "observed", "offset")},
          flush=True)
    assert r["verified"] is True, r
    assert r["expected"] == "0x%x" % CANARY, r
    assert r["observed"] == "0x%x" % CANARY, r
    assert r["offset"] == OFFSET, r

    # the campaign write happens in the tool layer; the plugin verdict is
    # what is pinned here. Kill the controllable run before the next build.
    srv.request("eval", {"command": "kill"})
    # consume the kill's exit notification so the next start's stop wait
    # cannot match a stale SIGSEGV stop from the controllable run
    srv.wait_for_event("exited")

    # ---- non-controllable build: the canary cannot reach PC -------------
    start(srv, safe)
    addr = buffer_addr(srv)
    sid = checkpoint(srv)
    r = verify(srv, sid, addr)
    print("[4] safe verify: %s" % {k: r.get(k) for k in
                                   ("verified", "expected", "observed", "survived")},
          flush=True)
    assert r["verified"] is False, r

    srv.send({"type": "quit", "reason": "pc_control_smoke_done", "kill_gdb": True})
    time.sleep(1.0)
    print("PC CONTROL DRIVER OK", flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=39405)
    parser.add_argument("--vuln", required=True)
    parser.add_argument("--safe", required=True)
    args = parser.parse_args()
    return run(args.port, args.vuln, args.safe)


if __name__ == "__main__":
    sys.exit(main())
