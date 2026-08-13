#!/usr/bin/env python3
"""pwntools + gdb-mcp example: run the crasher under gdb via
``gdb.debug()`` with the MCP plugin loaded.

Run INSIDE WSL2 (or any Linux box with pwntools installed). The gdb
process opens in a terminal (tmux split by default) and its plugin
connects back to the gdb-mcp server, where it appears as a session.

    python3 examples/pwntools_debug.py

The MCP server's TCP endpoint must be reachable from here; the plugin
tries GDB_MCP_HOST, then 127.0.0.1, then the /etc/resolv.conf nameserver
(WSL2 NAT mode host IP).
"""
import os
import time

from pwn import context, gdb, log

PLUGIN = os.environ.get("GDB_MCP_PLUGIN") or os.path.normpath(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "src",
        "gdb_mcp",
        "plugin",
        "gdb_mcp_plugin.py",
    )
)

context.arch = "amd64"

# gdb_args is inserted verbatim into the gdb command line, so the plugin
# loads at gdb startup (after pwndbg, if installed) and auto-connects.
# The gdbscript below is passed as `-x <tempfile>` afterwards.
io = gdb.debug(
    "./crasher",
    gdb_args=["-x", PLUGIN],
    gdbscript="""
set pagination off
break main
""",
)
log.info("gdb launched with the gdb-mcp plugin - check list_sessions in the MCP")
log.info("keep this script running (Ctrl-D to exit and kill the debuggee)")
io.interactive()
