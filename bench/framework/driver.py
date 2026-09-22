"""McpDriver — async MCP stdio client used by every bench component.

Reference solves, graders, stress and perf harnesses all speak to the server
through this one class, so per-call orchestration latency is recorded
uniformly (goal §6). One driver owns one server process; tasks run in their
own gdb sessions underneath it.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from contextlib import AsyncExitStack, suppress
from pathlib import Path
from statistics import median
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[2]


class DriverError(RuntimeError):
    pass


class ToolFailure(DriverError):
    def __init__(self, tool: str, details: str):
        super().__init__("%s failed: %s" % (tool, details))
        self.tool = tool


class McpDriver:
    """Spawns `python -m gdb_mcp` over stdio and exposes typed tool calls."""

    def __init__(
        self,
        port: int,
        distro: str | None = "kali-linux",
        log_dir: str | None = None,
        experimental: bool = False,
        extra_env: dict[str, str] | None = None,
    ):
        self.port = port
        self.distro = distro
        self.log_dir = log_dir or os.path.join(tempfile.gettempdir(), "gdb-mcp-bench")
        self.experimental = experimental
        self.extra_env = extra_env or {}
        self._session: ClientSession | None = None
        self._stack: AsyncExitStack | None = None
        self.call_latencies_ms: dict[str, list[float]] = {}

    async def __aenter__(self) -> "McpDriver":
        env = dict(os.environ)
        # The gdb plugin connects back from inside WSL via the NAT gateway,
        # so the server must bind non-loopback; that in turn requires a token
        # (same setup as tests/integration/run_mcp_tools_e2e.py).
        env.update(
            {
                "GDB_MCP_PORT": str(self.port),
                "GDB_MCP_LOG_DIR": self.log_dir,
                "GDB_MCP_HOST_BIND": "0.0.0.0",
                "GDB_MCP_TOKEN": "bench-internal-token",
                "PYTHONUTF8": "1",
            }
        )
        if self.distro:
            env["GDB_MCP_WSL_DISTRO"] = self.distro
        env.update(self.extra_env)
        args = ["-m", "gdb_mcp"]
        if self.experimental:
            args.append("--experimental")
        params = StdioServerParameters(
            command=os.environ.get("GDB_MCP_BENCH_PYTHON") or "python",
            args=args,
            env=env,
            cwd=str(ROOT),
        )
        self._stack = AsyncExitStack()
        read_stream, write_stream = await self._stack.enter_async_context(
            stdio_client(params)
        )
        session = await self._stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )
        await session.initialize()
        self._session = session
        return self

    async def __aexit__(self, *exc_info) -> None:
        if self._stack is not None:
            with suppress(Exception):
                await self._stack.aclose()
            self._stack = None
            self._session = None

    async def call(self, tool: str, arguments: dict[str, Any] | None = None) -> dict:
        if self._session is None:
            raise DriverError("driver not started (use async with)")
        started = time.perf_counter()
        result = await self._session.call_tool(tool, arguments or {})
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        self.call_latencies_ms.setdefault(tool, []).append(elapsed_ms)
        if result.isError:
            details = "\n".join(getattr(item, "text", str(item)) for item in result.content)
            raise ToolFailure(tool, details)
        payload = result.structuredContent
        if payload is None:
            text = next(
                (item.text for item in result.content if getattr(item, "type", None) == "text"),
                None,
            )
            payload = _json_or_none(text)
        if not isinstance(payload, dict):
            raise DriverError("%s returned no JSON object" % tool)
        return payload

    async def try_call(self, tool: str, arguments: dict[str, Any] | None = None) -> dict | None:
        """Best-effort call: returns None on tool failure instead of raising."""
        try:
            return await self.call(tool, arguments)
        except ToolFailure:
            return None

    # -- latency summary (goal §6 raw material; MCP orchestration overhead =
    #    this minus plugin execution time, separated in the perf milestone) --

    def latency_report(self) -> dict:
        all_samples: list[float] = []
        per_tool = {}
        for tool, samples in sorted(self.call_latencies_ms.items()):
            per_tool[tool] = {
                "n": len(samples),
                "p50_ms": round(_percentile(samples, 50), 3),
                "p95_ms": round(_percentile(samples, 95), 3),
                "p99_ms": round(_percentile(samples, 99), 3),
            }
            all_samples.extend(samples)
        return {
            "total_calls": len(all_samples),
            "p50_ms": round(_percentile(all_samples, 50), 3) if all_samples else None,
            "p95_ms": round(_percentile(all_samples, 95), 3) if all_samples else None,
            "p99_ms": round(_percentile(all_samples, 99), 3) if all_samples else None,
            "median_ms": round(median(all_samples), 3) if all_samples else None,
            "per_tool": per_tool,
        }


def _json_or_none(text: str | None):
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _percentile(samples: list[float], pct: float) -> float:
    if not samples:
        return float("nan")
    ordered = sorted(samples)
    k = (len(ordered) - 1) * pct / 100.0
    low = int(k)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (k - low)
