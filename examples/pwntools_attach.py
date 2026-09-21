#!/usr/bin/env python3
"""pwntools + gdb-mcp example: attach gdb to an already-running process.

Run INSIDE WSL2. The inferior spins in an infinite loop; gdb attaches to
it in a new terminal with the MCP plugin loaded, and the MCP server can
then interrupt/inspect it.

    python3 examples/pwntools_attach.py
"""
import os

from pwn import context, gdb, log, process

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

io = process(["./crasher", "loop"])
log.info("started crasher pid=%d", io.pid)

gdb.attach(
    io,
    gdb_args=["-x", PLUGIN],
    gdbscript="set pagination off",
)
log.info("gdb attached with the gdb-mcp plugin - check list_sessions in the MCP")
io.interactive()
