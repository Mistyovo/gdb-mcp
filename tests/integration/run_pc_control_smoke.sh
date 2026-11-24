#!/usr/bin/env bash
# gdb-mcp verify_pc_control real-gdb smoke test (issue 13).
#
# Builds two variants of pc_control_target.c:
#   vuln : unbounded strcpy -> canary at offset 32 reaches PC  -> verified
#   safe : bounded strncpy  -> canary cannot reach PC          -> not verified
#
# Run INSIDE WSL2 (or a Linux CI runner): needs gcc, gdb, python3.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
PLUGIN="$ROOT/src/gdb_mcp/plugin/gdb_mcp_plugin.py"
PORT="${GDB_MCP_TEST_PORT:-39405}"
TOKEN="${GDB_MCP_TEST_TOKEN:-pc-control-smoke-secret}"
WORK="$(mktemp -d)"
GDB_PID=""

cleanup() {
    if [ -n "$GDB_PID" ]; then kill "$GDB_PID" 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "[1/3] compile vuln + safe targets"
SRC="$DIR/pc_control_target.c"
gcc -g -O0 -fno-stack-protector -no-pie -DVULN -o "$WORK/pc_vuln" "$SRC"
gcc -g -O0 -fno-stack-protector -no-pie -o "$WORK/pc_safe" "$SRC"

echo "[2/3] launch gdb with plugin (port $PORT)"
tail -f /dev/null | GDB_MCP_PORT="$PORT" GDB_MCP_HOST=127.0.0.1 \
    GDB_MCP_TOKEN="$TOKEN" \
    gdb -q -nx -x "$PLUGIN" >"$WORK/gdb.log" 2>&1 &
GDB_PID=$!

echo "[3/3] run pc-control driver"
if ! GDB_MCP_TEST_TOKEN="$TOKEN" python3 "$DIR/run_pc_control_smoke.py" \
    --port "$PORT" --vuln "$WORK/pc_vuln" --safe "$WORK/pc_safe"; then
    echo "--- gdb.log (tail) ---"
    tail -30 "$WORK/gdb.log" || true
    exit 1
fi
echo "PC CONTROL SMOKE OK"
