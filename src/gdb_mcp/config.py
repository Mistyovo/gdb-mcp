"""Server configuration, assembled from environment variables and CLI flags.

Environment variables (all optional, prefixed ``GDB_MCP_``):

* ``GDB_MCP_PORT``          - TCP port the gdb plugins connect to (default 3939)
* ``GDB_MCP_HOST_BIND``     - bind address for that TCP listener (default 127.0.0.1)
* ``GDB_MCP_TOKEN``         - optional shared token the plugin must present
* ``GDB_MCP_WSL_DISTRO``    - WSL distro used by launch tools (default: auto)
* ``GDB_MCP_LOG_DIR``       - log directory for launched processes
* ``GDB_MCP_REQUEST_TIMEOUT`` - per-request timeout in seconds (default 30)
* ``GDB_MCP_HEARTBEAT_SEC`` - heartbeat interval in seconds (default 30)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

_ENV_PREFIX = "GDB_MCP"

DEFAULTS = {
    "host_bind": "127.0.0.1",
    "port": 3939,
    "wsl_distro": None,
    "request_timeout": 30.0,
    "heartbeat_sec": 30.0,
    "eval_output_limit": 200 * 1024,
    "max_mem_read": 1024 * 1024,
    "max_async_line": 32 * 1024 * 1024,
    "gc_idle_disconnected": 600.0,
    "gc_idle_reserved": 300.0,
    "attach_timeout_ms": 30_000,
    "launch_timeout_ms": 10_000,
}


def _default_log_dir() -> Path:
    base = os.environ.get("USERPROFILE") or str(Path.home())
    return Path(base) / ".gdb-mcp" / "logs"


@dataclass
class Config:
    host_bind: str = DEFAULTS["host_bind"]
    port: int = DEFAULTS["port"]
    token: str | None = None
    wsl_distro: str | None = DEFAULTS["wsl_distro"]
    log_dir: Path = field(default_factory=_default_log_dir)
    request_timeout: float = DEFAULTS["request_timeout"]
    heartbeat_sec: float = DEFAULTS["heartbeat_sec"]
    eval_output_limit: int = DEFAULTS["eval_output_limit"]
    max_mem_read: int = DEFAULTS["max_mem_read"]
    max_async_line: int = DEFAULTS["max_async_line"]
    gc_idle_disconnected: float = DEFAULTS["gc_idle_disconnected"]
    gc_idle_reserved: float = DEFAULTS["gc_idle_reserved"]
    attach_timeout_ms: int = DEFAULTS["attach_timeout_ms"]
    launch_timeout_ms: int = DEFAULTS["launch_timeout_ms"]
    #: WSL path of the plugin file (default: /mnt/<drive>/.../gdb_mcp_plugin.py)
    plugin_wsl_path: str | None = None
    mcp_transport: bool = True  # False => TCP-only mode (integration tests)

    def ensure_dirs(self) -> None:
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def validate(self) -> None:
        """Reject unsafe or nonsensical runtime settings."""
        if not 0 <= self.port <= 65535:
            raise ValueError("port must be between 0 and 65535")
        for name in (
            "request_timeout",
            "heartbeat_sec",
            "gc_idle_disconnected",
            "gc_idle_reserved",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be greater than zero")
        for name in ("eval_output_limit", "max_mem_read", "max_async_line"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be a positive integer")
        for name in ("attach_timeout_ms", "launch_timeout_ms"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be a positive integer")
        minimum_line_size = max(self.eval_output_limit, self.max_mem_read * 2) + 4096
        if self.max_async_line < minimum_line_size:
            raise ValueError(
                "max_async_line is too small for the configured output/memory limits"
            )
        if self.token is not None and not self.token:
            raise ValueError("token must not be empty")
        loopback = self.host_bind.lower() in {"127.0.0.1", "::1", "localhost"}
        if not loopback and not self.token:
            raise ValueError(
                "a token is required when GDB_MCP_HOST_BIND is not a loopback address"
            )

    @classmethod
    def from_env(cls, overrides: dict | None = None) -> "Config":
        """Build a Config from environment variables, then apply ``overrides``
        (CLI flags win; ``None`` values are ignored)."""

        def env(name: str, cast):
            raw = os.environ.get(f"{_ENV_PREFIX}_{name}")
            if raw is None or raw == "":
                return None
            try:
                return cast(raw)
            except ValueError:
                return None

        cfg = cls(
            host_bind=env("HOST_BIND", str) or DEFAULTS["host_bind"],
            port=env("PORT", int) or DEFAULTS["port"],
            token=env("TOKEN", str),
            wsl_distro=env("WSL_DISTRO", str),
            log_dir=Path(env("LOG_DIR", str))
            if env("LOG_DIR", str)
            else _default_log_dir(),
            request_timeout=env("REQUEST_TIMEOUT", float)
            or DEFAULTS["request_timeout"],
            heartbeat_sec=env("HEARTBEAT_SEC", float)
            or DEFAULTS["heartbeat_sec"],
            eval_output_limit=env("EVAL_OUTPUT_LIMIT", int)
            or DEFAULTS["eval_output_limit"],
            max_mem_read=env("MAX_MEM_READ", int) or DEFAULTS["max_mem_read"],
            max_async_line=env("MAX_ASYNC_LINE", int)
            or DEFAULTS["max_async_line"],
            gc_idle_disconnected=env("GC_IDLE_DISCONNECTED", float)
            or DEFAULTS["gc_idle_disconnected"],
            gc_idle_reserved=env("GC_IDLE_RESERVED", float)
            or DEFAULTS["gc_idle_reserved"],
            attach_timeout_ms=env("ATTACH_TIMEOUT_MS", int)
            or DEFAULTS["attach_timeout_ms"],
            launch_timeout_ms=env("LAUNCH_TIMEOUT_MS", int)
            or DEFAULTS["launch_timeout_ms"],
            plugin_wsl_path=env("PLUGIN_WSL_PATH", str),
        )
        if overrides:
            for key, value in overrides.items():
                if value is not None and hasattr(cfg, key):
                    setattr(cfg, key, value)
        cfg.validate()
        return cfg
