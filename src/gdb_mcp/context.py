"""Dependency-injection context shared by the MCP transport and tools.

One :class:`ServerContext` is created in :func:`server.build_app` and
handed to FastMCP's lifespan, so every tool handler reaches the registry,
config, analysis manager and launcher through
``ctx.request_context.lifespan_context`` — the only sanctioned channel
(see :mod:`gdb_mcp.tools._common` for the accessors).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from gdb_mcp.config import Config
from gdb_mcp.sessions import SessionRegistry


@dataclass
class ServerContext:
    config: Config
    registry: SessionRegistry
    analysis: Any = None
    _launcher: Any = field(default=None, repr=False)

    def launcher(self) -> Any:
        """The process launcher, built on first use (kept lazy so the
        WSL-specific code never loads where it is not needed)."""
        if self._launcher is None:
            from gdb_mcp.launcher import Launcher

            self._launcher = Launcher(self.config, self.registry)
        return self._launcher
