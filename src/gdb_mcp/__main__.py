"""Command-line entrypoint: ``gdb-mcp`` / ``python -m gdb_mcp``."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gdb-mcp",
        description="MCP server driving a local GDB (incl. pwndbg) for "
        "binary exploitation.",
    )
    p.add_argument("--host-bind", default=None, help="TCP bind address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=None, help="TCP port (default 3939)")
    p.add_argument("--token", default=None, help="optional shared token for gdb plugins")
    p.add_argument("--log-dir", default=None, help="launched-process log directory")
    p.add_argument(
        "--no-mcp",
        action="store_true",
        help="run the TCP listener only, without the stdio MCP transport "
        "(for integration tests)",
    )
    p.add_argument(
        "--http",
        action="store_true",
        help="expose MCP over hardened streamable HTTP instead of stdio",
    )
    p.add_argument("--mcp-host", default=None, help="MCP HTTP bind (default 127.0.0.1)")
    p.add_argument("--mcp-port", type=int, default=None, help="MCP HTTP port (default 8001)")
    p.add_argument(
        "--launcher",
        choices=("wsl", "native", "docker", "ssh"),
        default=None,
        help="where launch_* run processes (default: wsl)",
    )
    p.add_argument("--ssh-host", default=None, help="target host for the ssh launcher")
    p.add_argument(
        "--docker-image", default=None, help="image for the docker launcher (default gdb-mcp:latest)"
    )
    p.add_argument(
        "--readonly",
        action="store_true",
        help="drop state-mutating tools (write_memory/write_register)",
    )
    p.add_argument(
        "--allow-unsafe",
        action="store_true",
        help="allow gdb commands that escape the debugger (shell/!/python/...)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Lazy import so the scaffold stays importable before server.py exists.
    from gdb_mcp.config import Config

    try:
        cfg = Config.from_env(
            overrides={
                "host_bind": args.host_bind,
                "port": args.port,
                "token": args.token,
                "log_dir": Path(args.log_dir) if args.log_dir else None,
                "mcp_transport": not args.no_mcp,
                "mcp_http": args.http,
                "mcp_host": args.mcp_host,
                "mcp_port": args.mcp_port,
                "launcher": args.launcher,
                "ssh_host": args.ssh_host,
                "docker_image": args.docker_image,
                "readonly": args.readonly,
                "allow_unsafe": args.allow_unsafe,
            }
        )
    except ValueError as exc:
        parser.error(str(exc))
    from gdb_mcp.server import serve

    try:
        asyncio.run(serve(cfg))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
