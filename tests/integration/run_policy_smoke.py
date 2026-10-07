"""Driver for run_policy_smoke.sh: drives the plugin's policy verbs
against a real gdb via the stdlib fake server (reuses fake_mcp_client).

Asserts the loop primitives deterministically:
  * trace: 16 stepi's from main -> steps==16, >=2 unique PCs, stop=max_steps
  * bp_stats: tick_a/tick_b probed exactly 60x each -> total_hits==120,
    marker stops at tick_b each pass (passes>=2), run ends when the
    inferior exits (stop_reason=inferior_stop)
"""

from __future__ import print_function

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fake_mcp_client import FakeServer  # noqa: E402

TOKEN = os.environ.get("GDB_MCP_TEST_TOKEN")


def run(port, counter):
    srv = FakeServer(port, TOKEN)
    srv.accept()

    hello = srv.expect("hello")
    print("[1] hello: gdb %s" % hello.get("gdb_version"), flush=True)
    srv.send(
        {
            "type": "hello_ack",
            "proto": 1,
            "server_version": "0.1.0",
            "session_id": "s-policy-smoke",
            "heartbeat_sec": 30,
        }
    )
    srv.wait_for_event("ready")

    srv.request("file", {"path": counter})
    srv.request("break", {"location": "main"})
    srv.request("eval", {"command": "run"})
    srv.wait_for_event("stop")

    # ---- policy: bp_stats ----------------------------------------------
    # probes auto-continue at native speed; the marker at tick_b stops
    # the run once per pass; the run ends when the inferior exits.
    # Runs FIRST: from the main breakpoint nothing has executed yet, so
    # every tick_a/tick_b call crosses its probe (trace would step into
    # the first tick_a call and steal it).
    r = srv.request(
        "policy",
        {
            "kind": "bp_stats",
            "locations": ["tick_a", "tick_b"],
            "stop_location": "tick_b",
            "max_hits": 1000,
            "max_passes": 1000,
        },
    )
    counts = r["counts"]
    print("[2] bp_stats: counts=%s total=%s passes=%s stop=%s"
          % (counts, r["total_hits"], r["passes"], r.get("stop_reason")),
          flush=True)
    assert counts.get("tick_a") == 60, r
    assert counts.get("tick_b") == 60, r
    assert r["total_hits"] == 120, r
    assert r["passes"] >= 2, r
    assert r["stop_reason"] == "inferior_stop", r

    # consume the buffered stop/prompt notifications up to and including
    # the exit, so the stop wait below cannot match a stale marker stop
    srv.wait_for_event("exited")

    # ---- restart the program (bp_stats ran it to exit) -----------------
    srv.request("eval", {"command": "run"})
    srv.wait_for_event("stop")

    # ---- policy: trace ---------------------------------------------------
    # policy is a GATED verb: it must be accepted now that the handshake
    # acknowledged capabilities and the inferior is stopped
    r = srv.request("policy", {"kind": "trace", "max_steps": 16})
    print("[3] trace: %s" % {k: r[k] for k in ("steps", "unique_count", "stop")},
          flush=True)
    assert r["steps"] == 16, r
    assert r["unique_count"] >= 2, r
    assert r["stop"] == "max_steps", r
    assert len(r["unique_pc"]) >= 2, r

    # unknown kind must be rejected, not crash the plugin
    srv.send_only("policy", {"kind": "nope"}, rid=9100)
    msg = srv.recv_msg()
    while msg.get("type") == "notification":
        msg = srv.recv_msg()
    assert msg.get("id") == 9100 and not msg.get("ok"), msg
    assert msg["error"]["code"] == "BAD_PARAMS", msg
    print("[4] unknown policy kind rejected: %s" % msg["error"]["code"], flush=True)

    srv.send({"type": "quit", "reason": "policy_smoke_done", "kill_gdb": True})
    import time
    time.sleep(1.0)
    print("POLICY DRIVER OK", flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=39403)
    parser.add_argument("--counter", required=True)
    args = parser.parse_args()
    return run(args.port, args.counter)


if __name__ == "__main__":
    sys.exit(main())
