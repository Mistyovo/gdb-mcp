#!/usr/bin/env python3
"""Fixture used by the MCP tools end-to-end test to spawn a child GDB."""

from __future__ import annotations

import os
import subprocess
import sys


def main() -> int:
    plugin = os.environ.get("GDB_MCP_PLUGIN")
    if not plugin:
        print("GDB_MCP_PLUGIN is required", file=sys.stderr)
        return 2
    process = subprocess.Popen(
        ["gdb", "-q", "-nx", "-x", plugin],
        stdin=subprocess.PIPE,
    )
    try:
        return process.wait()
    except KeyboardInterrupt:
        process.terminate()
        return process.wait()


if __name__ == "__main__":
    raise SystemExit(main())
