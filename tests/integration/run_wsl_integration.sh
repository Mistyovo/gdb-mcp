#!/usr/bin/env bash
# gdb-mcp WSL2 integration test.
#
# Run INSIDE WSL2 (or via `wsl.exe -d <distro> -- bash -lc ...`):
#   bash tests/integration/run_wsl_integration.sh
#
# Drives a REAL gdb running the in-gdb plugin against a stdlib-only fake
# server (fake_mcp_client.py), over loopback inside the VM. Validates:
# hello/ack, file, breakpoint, run-to-main, SIGSEGV stop notification with
# fault address, registers, backtrace, disassembly, memory read/write,
# expression evaluation, threads, breakpoint listing, and interrupt of a
# running inferior (gdb.interrupt() on gdb >= 15).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
PLUGIN="$ROOT/src/gdb_mcp/plugin/gdb_mcp_plugin.py"
PORT="${GDB_MCP_TEST_PORT:-39401}"
TOKEN="${GDB_MCP_TEST_TOKEN:-integration-secret}"
WORK="$(mktemp -d)"
GDB_PID=""

cleanup() {
    if [ -n "$GDB_PID" ]; then kill "$GDB_PID" 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "[1/4] compile crasher"
gcc -g -O0 -o "$WORK/crasher" "$ROOT/examples/crasher.c"

echo "[2/4] launch gdb with plugin (port $PORT)"
# `tail -f /dev/null` keeps stdin open so gdb does not exit on EOF. Note
# the env vars must be attached to the gdb command itself, not to tail.
tail -f /dev/null | GDB_MCP_PORT="$PORT" GDB_MCP_HOST=127.0.0.1 \
    GDB_MCP_TOKEN="$TOKEN" \
    GDB_MCP_DEBUG="${GDB_MCP_TEST_DEBUG:-0}" \
    gdb -q -nx -x "$PLUGIN" >"$WORK/gdb.log" 2>&1 &
GDB_PID=$!

echo "[3/4] run fake server client"
if ! GDB_MCP_TEST_TOKEN="$TOKEN" python3 "$DIR/fake_mcp_client.py" \
    --port "$PORT" --crasher "$WORK/crasher"; then
    echo "--- gdb.log (full) ---"
    cat "$WORK/gdb.log" || true
    exit 1
fi

echo "[4/4] integration test passed"
