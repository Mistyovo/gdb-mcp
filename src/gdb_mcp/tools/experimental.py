"""Experimental tools — gated behind GDB_MCP_EXPERIMENTAL=1.

Anything in this module is subject to change or removal without a
deprecation cycle. Current contents: the inferior stdio channel
(send_to_inferior / read_inferior_output) that pairs with the plugin's
io_* verbs, libc identification via a libc.rip-compatible API, and
structured ROP gadget search via the ROPgadget CLI.
"""

from __future__ import annotations

import asyncio
import re
import subprocess

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError
from gdb_mcp.output import hex_to_bytes

from ._common import config_from, resolve_gdb


def _api_find(endpoint_url: str, payload: dict) -> list:
    """POST to a libc.rip-compatible ``/api/find`` endpoint. Indirection
    for tests."""
    import httpx

    response = httpx.post(endpoint_url, json=payload, timeout=30.0)
    response.raise_for_status()
    data = response.json()
    return data if isinstance(data, list) else []


def _run_ropgadget(binary: str, only: str) -> tuple[int, str]:
    """Run the ROPgadget CLI. Indirection for tests."""
    proc = subprocess.run(
        ["ROPgadget", "--binary", binary, "--only", only],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return proc.returncode, proc.stdout


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

    @app.tool()
    async def identify_libc(
        leaks: dict[str, str],
        use_api: bool = True,
        ctx: Context = None,
    ) -> dict:
        """EXPERIMENTAL. Identify a libc from leaked symbol addresses,
        e.g. {"puts": "0x7ffff7a6c720"} — only the low 12 bits of each
        leak are meaningful, everything above is randomized per run.
        Queries the configured libc.rip-compatible API
        (GDB_MCP_LIBC_RIP_API) and returns candidate libcs. Unnecessary
        for purely local debugging: there the target's own libc is
        visible in info proc mappings."""
        if not leaks:
            raise GdbMcpError("BAD_PARAMS", "leaks is required")
        normalized: dict[str, str] = {}
        for symbol, raw in leaks.items():
            text = str(raw).strip()
            try:
                address = int(text, 16)
            except ValueError:
                raise GdbMcpError(
                    "BAD_PARAMS",
                    "leak %r is not a hex address: %r" % (symbol, raw),
                ) from None
            normalized[str(symbol)[:64]] = "%#x" % (address & 0xFFF)
        if not use_api:
            return {
                "matches": [],
                "query": normalized,
                "note": "use_api=False; nothing queried",
            }
        endpoint = config_from(ctx).libc_rip_api
        try:
            matches = await asyncio.to_thread(
                _api_find,
                endpoint.rstrip("/") + "/api/find",
                {"symbols": normalized},
            )
        except Exception as exc:
            raise GdbMcpError(
                "PLUGIN_ERROR",
                "libc lookup failed (%s); check GDB_MCP_LIBC_RIP_API "
                "reachability" % exc,
            ) from exc
        return {"matches": matches[:16], "query": normalized}

    @app.tool()
    async def search_gadgets(
        binary: str,
        pattern: str = "pop rdi",
        only: str = "pop|ret",
        max_results: int = 64,
        ctx: Context = None,
    ) -> dict:
        """EXPERIMENTAL. Search ROP gadgets in a binary via the ROPgadget
        CLI (pip install ROPgadget), then filter gadget instruction text
        by a case-insensitive regex (pattern). Returns address +
        instruction text per gadget, at most max_results."""
        if not binary.strip():
            raise GdbMcpError("BAD_PARAMS", "binary is required")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise GdbMcpError("BAD_PARAMS", "bad pattern regex: %s" % exc) from None
        max_results = max(1, min(int(max_results), 256))
        try:
            returncode, stdout = await asyncio.to_thread(
                _run_ropgadget, binary, only
            )
        except FileNotFoundError as exc:
            raise GdbMcpError(
                "ROPGADGET_MISSING",
                "ROPgadget was not found; pip install ROPgadget",
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise GdbMcpError("TIMEOUT", "ROPgadget timed out") from exc
        gadgets = []
        truncated = False
        line_re = re.compile(r"^(0x[0-9a-fA-F]+)\s*:\s*(.+)$")
        for line in stdout.splitlines():
            m = line_re.match(line.strip())
            if m is None:
                continue
            instructions = m.group(2).strip()
            if not re.search(pattern, instructions, re.IGNORECASE):
                continue
            if len(gadgets) >= max_results:
                truncated = True
                break
            gadgets.append(
                {
                    # normalize away leading zeros; LLMs copy addresses
                    # verbatim and 0x0000000000401234 invites typos
                    "address": "0x%x" % int(m.group(1), 16),
                    "instructions": instructions,
                }
            )
        if returncode not in (0, 1):
            raise GdbMcpError(
                "PLUGIN_ERROR",
                "ROPgadget failed (code %s): %s"
                % (returncode, stdout[-400:] or "no output"),
            )
        return {
            "binary": binary,
            "pattern": pattern,
            "gadgets": gadgets,
            "total_matched": len(gadgets),
            "truncated": truncated,
        }
