#!/usr/bin/env bash
# gdb-mcp policy-verb real-gdb smoke test (audit 2026-10-07 P1-7).
#
# The policy verb family (trace / heap_timeline / fuzz_loop / bp_stats)
# had zero real-gdb coverage — mock-only. This drives the two loop
# primitives every policy builds on (single-step trace and auto-continue
# breakpoint probes) against a real gdb:
#
#   trace    : 16 stepi's from main -> steps==16, >=2 unique PCs
#   bp_stats : tick_a/tick_b probed exactly 60x each in a deterministic
#              loop; the tick_b marker stops once per pass (passes>=2)
#              and the run ends when the inferior exits
#
# Run INSIDE WSL2 (or a Linux CI runner): needs gcc, gdb, python3.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
PLUGIN="$ROOT/src/gdb_mcp/plugin/gdb_mcp_plugin.py"
PORT="${GDB_MCP_TEST_PORT:-39403}"
TOKEN="${GDB_MCP_TEST_TOKEN:-policy-smoke-secret}"
WORK="$(mktemp -d)"
GDB_PID=""

cleanup() {
    if [ -n "$GDB_PID" ]; then kill "$GDB_PID" 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "[1/3] compile counter"
cat > "$WORK/counter.c" <<'EOF'
#include <stdio.h>
__attribute__((noinline)) int tick_a(int i) { return i + 1; }
__attribute__((noinline)) int tick_b(int i) { return i + 2; }
int main(void) {
    int i = 0;
    for (int k = 0; k < 60; k++) {
        i = tick_a(i);
        i = tick_b(i);
    }
    printf("done %d\n", i);
    return 0;
}
EOF
gcc -g -O0 -o "$WORK/counter" "$WORK/counter.c"

echo "[2/3] launch gdb with plugin (port $PORT)"
tail -f /dev/null | GDB_MCP_PORT="$PORT" GDB_MCP_HOST=127.0.0.1 \
    GDB_MCP_TOKEN="$TOKEN" \
    gdb -q -nx -x "$PLUGIN" >"$WORK/gdb.log" 2>&1 &
GDB_PID=$!

echo "[3/3] run policy driver"
if ! GDB_MCP_TEST_TOKEN="$TOKEN" python3 "$DIR/run_policy_smoke.py" \
    --port "$PORT" --counter "$WORK/counter"; then
    echo "--- gdb.log (tail) ---"
    tail -30 "$WORK/gdb.log" || true
    exit 1
fi
echo "POLICY SMOKE OK"
