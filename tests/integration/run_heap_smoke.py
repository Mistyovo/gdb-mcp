"""Driver for run_heap_smoke.sh: drives the heap timeline through a real
gdb via the stdlib fake server.

Asserts the 2026-11-23 heap-timeline contract:
  * malloc/calloc/realloc events carry their returned pointer (`ret`)
  * the raw args dict is joined by a named view (size/ptr/nmemb)
  * free records its pointer as `named.ptr` and gets no return probe
  * the free of the realloc'd pointer matches the realloc return
"""

from __future__ import print_function

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fake_mcp_client import FakeServer  # noqa: E402

TOKEN = os.environ.get("GDB_MCP_TEST_TOKEN")


def find(events, symbol, **named):
    for event in events:
        if event.get("symbol", "").split("@")[0] != symbol:
            continue
        got = event.get("named") or {}
        if all(got.get(key) == value for key, value in named.items()):
            return event
    return None


def run(port, demo):
    srv = FakeServer(port, TOKEN)
    srv.accept()
    hello = srv.expect("hello")
    print(
        "[1] hello: gdb %s arch=%s"
        % (hello.get("gdb_version"), hello.get("arch")),
        flush=True,
    )
    srv.send(
        {
            "type": "hello_ack",
            "proto": 1,
            "server_version": "0.1.0",
            "session_id": "s-heap-smoke",
            "heartbeat_sec": 30,
        }
    )
    srv.wait_for_event("ready")

    srv.request("file", {"path": demo})
    srv.request("break", {"location": "main"})
    srv.request("eval", {"command": "run"})
    srv.wait_for_event("stop")

    arm = srv.request(
        "policy",
        {
            "kind": "heap_arm",
            "symbols": ["malloc", "calloc", "realloc", "free"],
            "max_events": 256,
        },
    )
    print(
        "[2] heap_arm: armed=%s return_capture=%s"
        % (arm.get("armed"), arm.get("return_capture")),
        flush=True,
    )
    assert arm.get("return_capture") == [
        "malloc",
        "calloc",
        "realloc",
    ], arm

    srv.request("eval", {"command": "continue"})
    srv.wait_for_event("exited")

    read = srv.request("policy", {"kind": "heap_read"})
    events = read.get("events") or []
    print(
        "[3] heap_read: total=%s events=%s pending_returns=%s"
        % (read.get("total"), len(events), read.get("pending_returns")),
        flush=True,
    )
    assert events, read

    malloc_ev = find(events, "malloc", size="0x20")
    assert malloc_ev is not None, "malloc(0x20) not in timeline"
    assert malloc_ev.get("ret"), "malloc has no return pointer: %r" % malloc_ev
    malloc_ptr = int(malloc_ev["ret"], 16)
    assert malloc_ptr % 16 == 0, malloc_ev

    calloc_ev = find(events, "calloc", nmemb="0x2", size="0x10")
    assert calloc_ev is not None, "calloc(2,0x10) not in timeline"
    assert calloc_ev.get("ret"), "calloc has no return pointer: %r" % calloc_ev

    realloc_ev = find(events, "realloc", size="0x40")
    assert realloc_ev is not None, "realloc(...,0x40) not in timeline"
    assert realloc_ev.get("ret"), "realloc has no return pointer: %r" % realloc_ev

    free_ev = find(events, "free", ptr=realloc_ev["ret"])
    assert free_ev is not None, (
        "free(%s) not in timeline" % realloc_ev["ret"]
    )
    assert "ret" not in free_ev, "free must not have a return probe: %r" % free_ev

    print(
        "[4] timeline: malloc=%s (size=%s caller=%s) calloc=%s realloc=%s free(ptr)=%s"
        % (
            malloc_ev.get("ret"),
            (malloc_ev.get("named") or {}).get("size"),
            malloc_ev.get("caller"),
            calloc_ev.get("ret"),
            realloc_ev.get("ret"),
            (free_ev.get("named") or {}).get("ptr"),
        ),
        flush=True,
    )

    disarm = srv.request("policy", {"kind": "heap_disarm"})
    print("[5] heap_disarm: %s" % disarm, flush=True)
    assert disarm.get("disarmed") is True, disarm

    srv.send({"type": "quit", "reason": "heap_smoke_done", "kill_gdb": True})
    time.sleep(1.0)
    print("HEAP DRIVER OK", flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=39404)
    parser.add_argument("--demo", required=True)
    args = parser.parse_args()
    return run(args.port, args.demo)


if __name__ == "__main__":
    sys.exit(main())
