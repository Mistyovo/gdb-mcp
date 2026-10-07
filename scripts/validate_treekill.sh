#!/bin/bash
# Tree-kill validation for build_pkill_command (run inside WSL).
#
# Spawns the real launch shape — a marker-named process (exec -a, like the
# launched gdb) with a child "inferior" whose own cmdline does not match
# the marker — then runs the EXACT snippet build_pkill_command produces
# (imported from the real module, byte-identical) and asserts both the
# marker process and the inferior are gone.
set -u
cd "$(dirname "$0")/.." || exit 2
export PYTHONPATH="$PWD/src${PYTHONPATH:+:$PYTHONPATH}"
SID="killtest"
MARKER="gdbmcp_$SID"

bash -c "exec -a $MARKER bash -c 'sleep 777; true'" &
sleep 0.5
MARKER_PIDS="$(pgrep -f "$MARKER" | tr '\n' ' ')"
INFERIOR_PIDS="$(pgrep -x sleep | tr '\n' ' ')"
echo "marker before: $MARKER_PIDS"
echo "inferior before: $INFERIOR_PIDS"
[ -n "$MARKER_PIDS" ] || { echo "FIXTURE BROKEN (marker missing)"; exit 2; }
[ -n "$INFERIOR_PIDS" ] || { echo "FIXTURE BROKEN (inferior missing)"; exit 2; }

# the exact string the launcher ships, byte for byte
SNIPPET="$(python3 - "$SID" <<'PY'
import sys
from gdb_mcp.launcher import build_pkill_command
print(build_pkill_command(sys.argv[1], force=False))
PY
)"
echo "snippet: $SNIPPET"
eval "$SNIPPET"
sleep 1

LEFT_MARKER="$(pgrep -cf "$MARKER" || true)"
LEFT_INF="$(pgrep -x -c sleep || true)"
echo "after: marker=$LEFT_MARKER inferior=$LEFT_INF"
if [ "${LEFT_MARKER:-0}" != "0" ] || [ "${LEFT_INF:-0}" != "0" ]; then
    echo "TREEKILL FAILED"; exit 1
fi
echo "TREEKILL OK"
