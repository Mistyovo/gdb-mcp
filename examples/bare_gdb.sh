#!/usr/bin/env bash
# Start gdb manually with the gdb-mcp plugin loaded (no pwntools needed).
# Run INSIDE WSL2:
#
#   bash examples/bare_gdb.sh [program [args...]]
#
# The plugin connects back to the MCP server (GDB_MCP_HOST / GDB_MCP_PORT,
# with 127.0.0.1 -> resolv.conf nameserver fallback for WSL2 NAT mode).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN="${GDB_MCP_PLUGIN:-$HERE/../src/gdb_mcp/plugin/gdb_mcp_plugin.py}"

if [ $# -gt 0 ]; then
    exec gdb -q -x "$PLUGIN" --args "$@"
else
    exec gdb -q -x "$PLUGIN"
fi
