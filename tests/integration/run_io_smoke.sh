#!/usr/bin/env bash
# gdb-mcp inferior-stdio smoke test (experimental io channel).
#
# Run INSIDE WSL2 (or via `wsl.exe -d <distro> -- bash -lc ...`):
#   bash tests/integration/run_io_smoke.sh
#
# Compiles a tiny interactive target, launches gdb with the plugin, and
# drives the full pty path: io_setup -> run -> prompt captured ->
# io_send -> echo captured -> exit -> io_teardown.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
PLUGIN="$ROOT/src/gdb_mcp/plugin/gdb_mcp_plugin.py"
PORT="${GDB_MCP_TEST_PORT:-39402}"
TOKEN="${GDB_MCP_TEST_TOKEN:-io-smoke-secret}"
WORK="$(mktemp -d)"
GDB_PID=""

cleanup() {
    if [ -n "$GDB_PID" ]; then kill "$GDB_PID" 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "[1/3] compile interactive target"
gcc -g -O0 -o "$WORK/menu" "$DIR/menu.c"

echo "[2/3] launch gdb with plugin (port $PORT)"
tail -f /dev/null | GDB_MCP_PORT="$PORT" GDB_MCP_HOST=127.0.0.1 \
    GDB_MCP_TOKEN="$TOKEN" \
    gdb -q -nx -x "$PLUGIN" >"$WORK/gdb.log" 2>&1 &
GDB_PID=$!

echo "[3/3] run io smoke client"
if ! GDB_MCP_TEST_TOKEN="$TOKEN" python3 "$DIR/io_smoke_client.py" \
    --port "$PORT" --binary "$WORK/menu"; then
    echo "--- gdb.log (full) ---"
    cat "$WORK/gdb.log" || true
    exit 1
fi
echo "[done] io smoke test passed"
