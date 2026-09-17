"""Experimental tools — gated behind GDB_MCP_EXPERIMENTAL=1.

Anything in this module is subject to change or removal without a
deprecation cycle. Current contents: libc identification via a
libc.rip-compatible API and structured ROP gadget search via the
ROPgadget CLI.
"""

from __future__ import annotations

import asyncio
import re
import subprocess

from mcp.server.fastmcp import Context

from gdb_mcp.errors import GdbMcpError

from ._common import config_from


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
