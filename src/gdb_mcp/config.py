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
    "tool_profile": "full",
    "result_inline_limit": 16_000,
    "launcher": "wsl",
    "ssh_host": None,
    "docker_image": "gdb-mcp:latest",
    "mcp_http": False,
    "mcp_host": "127.0.0.1",
    "mcp_port": 8001,
    "readonly": False,
    "allow_unsafe": False,
    "experimental": False,
    "libc_rip_api": "https://libc.rip",
    "observer_tokens": (),
    "mcp_tls_cert": None,
    "mcp_tls_key": None,
    "mcp_tls_client_ca": None,
    "ghidra_headless": "/usr/share/ghidra/support/analyzeHeadless",
    "analysis_dir": None,
    "analysis_timeout": 900.0,
    "decompile_timeout": 120.0,
    "auto_analyze": False,
    "archive_retention": 20,
    "archive_dir": None,
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
    #: which MCP tools are registered: "full" or "core" (a minimal set)
    tool_profile: str = DEFAULTS["tool_profile"]
    #: tool outputs longer than this are stored on disk and previewed
    result_inline_limit: int = DEFAULTS["result_inline_limit"]
    #: where launch_* run processes: "wsl" | "native" | "docker" | "ssh"
    launcher: str = DEFAULTS["launcher"]
    #: target host for the ssh launcher backend
    ssh_host: str | None = DEFAULTS["ssh_host"]
    #: container image for the docker launcher backend
    docker_image: str = DEFAULTS["docker_image"]
    #: expose the MCP server over streamable HTTP instead of stdio
    mcp_http: bool = DEFAULTS["mcp_http"]
    #: HTTP bind (kept loopback unless deliberately changed; token required
    #: for anything non-loopback, like the TCP listener)
    mcp_host: str = DEFAULTS["mcp_host"]
    mcp_port: int = DEFAULTS["mcp_port"]
    #: drop state-mutating tools (write_memory/write_register)
    readonly: bool = DEFAULTS["readonly"]
    #: allow gdb commands that escape the debugger (shell/!/python/...)
    allow_unsafe: bool = DEFAULTS["allow_unsafe"]
    #: register experimental tools (subject to change without notice).
    #: CLI-only (--experimental) on purpose — never enabled by ambient
    #: environment variables.
    experimental: bool = DEFAULTS["experimental"]
    #: libc.rip-compatible API endpoint for identify_libc
    libc_rip_api: str = DEFAULTS["libc_rip_api"]
    #: read-only observer bearer tokens for the HTTP transport
    #: (D2: observers may query state but every mutating tool rejects)
    observer_tokens: tuple[str, ...] = DEFAULTS["observer_tokens"]
    #: mTLS material for the HTTP transport; client_ca enables mutual TLS
    mcp_tls_cert: str | None = DEFAULTS["mcp_tls_cert"]
    mcp_tls_key: str | None = DEFAULTS["mcp_tls_key"]
    mcp_tls_client_ca: str | None = DEFAULTS["mcp_tls_client_ca"]
    #: 3.5 static bridge: Ghidra headless analyzer + analysis cache dir.
    #: auto_analyze defaults False here (the archive auto-started analyses
    #: for every connected target; explicit analyze_binary calls keep the
    #: server quiet by default)
    ghidra_headless: str = DEFAULTS["ghidra_headless"]
    analysis_dir: Path | None = DEFAULTS["analysis_dir"]
    analysis_timeout: float = DEFAULTS["analysis_timeout"]
    decompile_timeout: float = DEFAULTS["decompile_timeout"]
    auto_analyze: bool = DEFAULTS["auto_analyze"]
    #: B4: closed sessions' journals + launched-process logs are moved to
    #: archive_dir, keeping the newest ``archive_retention`` sessions
    #: (0 disables archiving; artifacts then stay where they are)
    archive_retention: int = DEFAULTS["archive_retention"]
    archive_dir: Path | None = DEFAULTS["archive_dir"]
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
        if self.archive_retention < 0:
            raise ValueError("archive_retention must not be negative")
        if self.tool_profile not in ("core", "full"):
            raise ValueError("tool_profile must be 'core' or 'full'")
        if self.result_inline_limit < 1:
            raise ValueError("result_inline_limit must be a positive integer")
        if self.launcher not in ("wsl", "native", "docker", "ssh"):
            raise ValueError("launcher must be wsl, native, docker or ssh")
        if self.launcher == "ssh" and not self.ssh_host:
            raise ValueError("GDB_MCP_SSH_HOST is required for the ssh launcher")
        if not 0 <= self.mcp_port <= 65535:
            raise ValueError("mcp_port must be between 0 and 65535")
        mcp_loopback = self.mcp_host.lower() in {"127.0.0.1", "::1", "localhost"}
        if self.mcp_http and not mcp_loopback and not self.token:
            raise ValueError(
                "a token is required when the MCP HTTP transport binds a "
                "non-loopback address"
            )
        # TLS material comes in pairs; a bare cert or key is a mistake
        if bool(self.mcp_tls_cert) != bool(self.mcp_tls_key):
            raise ValueError(
                "mcp_tls_cert and mcp_tls_key must be provided together"
            )
        if self.mcp_tls_client_ca and not self.mcp_tls_cert:
            raise ValueError(
                "mcp_tls_client_ca requires mcp_tls_cert/mcp_tls_key (mTLS)"
            )
        for token in self.observer_tokens:
            if not token or self.token == token:
                raise ValueError(
                    "observer tokens must be non-empty and differ from "
                    "the controller token"
                )
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

        def env_bool(name: str) -> bool | None:
            raw = os.environ.get(f"{_ENV_PREFIX}_{name}")
            if raw is None or raw == "":
                return None
            return raw.lower() in ("1", "true", "yes", "on")

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
            tool_profile=env("TOOL_PROFILE", str) or DEFAULTS["tool_profile"],
            result_inline_limit=env("RESULT_INLINE_LIMIT", int)
            or DEFAULTS["result_inline_limit"],
            launcher=env("LAUNCHER", str) or DEFAULTS["launcher"],
            ssh_host=env("SSH_HOST", str),
            docker_image=env("DOCKER_IMAGE", str) or DEFAULTS["docker_image"],
            mcp_http=env_bool("MCP_HTTP") or DEFAULTS["mcp_http"],
            mcp_host=env("MCP_HOST", str) or DEFAULTS["mcp_host"],
            mcp_port=env("MCP_PORT", int) or DEFAULTS["mcp_port"],
            readonly=env_bool("READONLY") or DEFAULTS["readonly"],
            allow_unsafe=env_bool("ALLOW_UNSAFE") or DEFAULTS["allow_unsafe"],
            # experimental is deliberately NOT env-configurable: a stray
            # variable in a shell profile would silently turn the tools
            # on for every server start. Only --experimental enables it.
            experimental=False,
            libc_rip_api=env("LIBC_RIP_API", str) or DEFAULTS["libc_rip_api"],
            observer_tokens=tuple(
                t.strip()
                for t in (os.environ.get(f"{_ENV_PREFIX}_OBSERVER_TOKENS") or "").split(",")
                if t.strip()
            )
            or DEFAULTS["observer_tokens"],
            mcp_tls_cert=env("MCP_TLS_CERT", str),
            mcp_tls_key=env("MCP_TLS_KEY", str),
            mcp_tls_client_ca=env("MCP_TLS_CLIENT_CA", str),
            ghidra_headless=env("GHIDRA_HEADLESS", str)
            or DEFAULTS["ghidra_headless"],
            analysis_dir=Path(env("ANALYSIS_DIR", str))
            if env("ANALYSIS_DIR", str)
            else None,
            analysis_timeout=env("ANALYSIS_TIMEOUT", float)
            or DEFAULTS["analysis_timeout"],
            decompile_timeout=env("DECOMPILE_TIMEOUT", float)
            or DEFAULTS["decompile_timeout"],
            auto_analyze=env_bool("AUTO_ANALYZE") or DEFAULTS["auto_analyze"],
            archive_retention=env("ARCHIVE_RETENTION", int)
            if env("ARCHIVE_RETENTION", int) is not None
            else DEFAULTS["archive_retention"],
            archive_dir=Path(env("ARCHIVE_DIR", str))
            if env("ARCHIVE_DIR", str)
            else None,
            plugin_wsl_path=env("PLUGIN_WSL_PATH", str),
        )
        if overrides:
            for key, value in overrides.items():
                if value is not None and hasattr(cfg, key):
                    setattr(cfg, key, value)
        cfg.validate()
        return cfg
