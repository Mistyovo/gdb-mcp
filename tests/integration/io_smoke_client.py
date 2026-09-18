"""WSL-side smoke test for the experimental inferior stdio channel.

Expects a real gdb with the gdb-mcp plugin listening on --port (launch
it via run_io_smoke.sh). Validates the full pty path: io_setup ->
inferior run (prompt arrives through the pty) -> io_send -> echo read
back -> io_teardown.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_mcp_client import FakeServer  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--token", default=os.environ.get("GDB_MCP_TEST_TOKEN"))
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()

    client = FakeServer(args.port, token=args.token)
    client.accept()
    # complete the handshake before anything else: the plugin waits for
    # hello_ack and treats a proto mismatch as a reconnect trigger
    client.expect("hello")
    client.send(
        {
            "type": "hello_ack",
            "proto": 1,
            "server_version": "0.1.0",
            "session_id": "s-io-smoke",
            "heartbeat_sec": 30,
        }
    )
    client.wait_for_event("ready")

    setup = client.request("io_setup", {})
    print("[io] pty at %s" % setup["slave_path"])

    client.request("file", {"path": args.binary})
    # resume without waiting: the inferior blocks on stdin, so the eval
    # would not return until it exits; the io verbs are handled by the
    # gdb event loop while the run is in flight (same mechanism as
    # interrupt)
    client.send_only("eval", {"command": "run"})
    time.sleep(1.5)

    read = client.request("io_read", {}, timeout=30.0)
    text = "".join(chunk["text"] for chunk in read["chunks"])
    print("[io] captured %d chunk(s)" % len(read["chunks"]))
    assert "menu:> " in text, "prompt did not arrive through the pty: %r" % text

    client.request("io_send", {"hex": b"hello\n".hex()})
    time.sleep(1.0)
    read = client.request("io_read", {"since_seq": read["last_seq"]}, timeout=30.0)
    text = "".join(chunk["text"] for chunk in read["chunks"])
    assert "got:hello" in text, "echo did not arrive: %r" % text

    client.wait_for_event("exited", timeout=30.0)
    client.request("io_teardown", {})
    print("IO SMOKE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
