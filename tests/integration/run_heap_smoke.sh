#!/usr/bin/env bash
# gdb-mcp heap-timeline real-gdb smoke test (issue 11).
#
# Verifies that heap_arm records allocation identity on a real gdb:
#   malloc/calloc/realloc events carry the returned pointer (`ret`)
#   free records its pointer as named.ptr and gets no return probe
#   the free of the realloc'd pointer matches the realloc return
#
# Run INSIDE WSL2 (or a Linux CI runner): needs gcc, gdb, python3.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
PLUGIN="$ROOT/src/gdb_mcp/plugin/gdb_mcp_plugin.py"
PORT="${GDB_MCP_TEST_PORT:-39404}"
TOKEN="${GDB_MCP_TEST_TOKEN:-heap-smoke-secret}"
WORK="$(mktemp -d)"
GDB_PID=""

cleanup() {
    if [ -n "$GDB_PID" ]; then kill "$GDB_PID" 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "[1/3] compile heap demo"
cat > "$WORK/heapdemo.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>

void *keep;

int main(void) {
    void *p = malloc(0x20);
    keep = p;
    void *q = calloc(2, 0x10);
    void *r = realloc(q, 0x40);
    printf("%p %p %p\n", p, q, r);
    free(r);
    return 0;
}
EOF
gcc -g -O0 -o "$WORK/heapdemo" "$WORK/heapdemo.c"

echo "[2/3] launch gdb with plugin (port $PORT)"
GDB_ARGS=(-q)
if [ "${GDB_MCP_SMOKE_PWNDBG:-0}" != "1" ]; then
    GDB_ARGS+=(-nx)
fi
GDB_ARGS+=(-x "$PLUGIN")
tail -f /dev/null | GDB_MCP_PORT="$PORT" GDB_MCP_HOST=127.0.0.1 \
    GDB_MCP_TOKEN="$TOKEN" \
    gdb "${GDB_ARGS[@]}" >"$WORK/gdb.log" 2>&1 &
GDB_PID=$!

echo "[3/3] run heap driver"
if ! GDB_MCP_TEST_TOKEN="$TOKEN" python3 "$DIR/run_heap_smoke.py" \
    --port "$PORT" --demo "$WORK/heapdemo"; then
    echo "--- gdb.log (tail) ---"
    tail -50 "$WORK/gdb.log" || true
    exit 1
fi
echo "HEAP SMOKE OK"
