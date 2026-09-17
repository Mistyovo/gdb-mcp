"""Experimental tools — gated behind GDB_MCP_EXPERIMENTAL=1.

Anything in this module is subject to change or removal without a
deprecation cycle. Current contents: the inferior stdio channel
(send_to_inferior / read_inferior_output) that pairs with the plugin's
io_* verbs.
"""

from __future__ import annotations

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.output import hex_to_bytes

from ._common import config_from, resolve_gdb


def register(app, registry, config) -> None:
    if not config.experimental:
        return

    @app.tool()
    async def send_to_inferior(
        hex: str,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """EXPERIMENTAL. Write raw bytes (hex string) to the inferior's
        stdin. Requires io_setup on the session (the inferior's stdio is
        redirected to a pty on its next run/start); works while the
        inferior is running, which is the point."""
        session = resolve_gdb(ctx, session_id)
        try:
            hex_to_bytes(hex)
        except ValueError as exc:
            raise GdbMcpError("BAD_PARAMS", str(exc)) from None
        return await session.request(
            "io_send", {"hex": hex}, timeout=config_from(ctx).request_timeout
        )

    @app.tool()
    async def read_inferior_output(
        since_seq: int = 0,
        session_id: str | None = None,
        ctx: Context = None,
    ) -> dict:
        """EXPERIMENTAL. Read the inferior's accumulated stdout/stderr
        chunks recorded since seq (0 = everything still buffered). Each
        chunk carries hex and lossily-decoded text."""
        if isinstance(since_seq, bool) or not isinstance(since_seq, int) or since_seq < 0:
            raise ValueError("since_seq must be a non-negative int")
        session = resolve_gdb(ctx, session_id)
        return await session.request(
            "io_read",
            {"since_seq": since_seq},
            timeout=config_from(ctx).request_timeout,
        )

    @app.tool()
    async def io_setup(session_id: str | None = None, ctx: Context = None) -> dict:
        """EXPERIMENTAL. Redirect the inferior's stdio to a pty managed by
        the gdb-mcp plugin, enabling send_to_inferior/read_inferior_output.
        Takes effect on the inferior's next run/start; Unix only."""
        session = resolve_gdb(ctx, session_id)
        return await session.request(
            "io_setup", {}, timeout=config_from(ctx).request_timeout
        )

    @app.tool()
    async def io_teardown(
        session_id: str | None = None, ctx: Context = None
    ) -> dict:
        """EXPERIMENTAL. Close the inferior stdio channel and restore the
        previous inferior-tty behavior on the next run."""
        session = resolve_gdb(ctx, session_id)
        return await session.request(
            "io_teardown", {}, timeout=config_from(ctx).request_timeout
        )
