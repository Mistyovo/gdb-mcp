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
    p.add_argument("--host-bind", default=None, help="TCP bind address (default 0.0.0.0)")
    p.add_argument("--port", type=int, default=None, help="TCP port (default 3939)")
    p.add_argument("--token", default=None, help="optional shared token for gdb plugins")
    p.add_argument("--log-dir", default=None, help="launched-process log directory")
    p.add_argument(
        "--no-mcp",
        action="store_true",
        help="run the TCP listener only, without the stdio MCP transport "
        "(for integration tests)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    # Lazy import so the scaffold stays importable before server.py exists.
    from gdb_mcp.config import Config

    cfg = Config.from_env(
        overrides={
            "host_bind": args.host_bind,
            "port": args.port,
            "token": args.token,
            "log_dir": Path(args.log_dir) if args.log_dir else None,
            "mcp_transport": not args.no_mcp,
        }
    )
    from gdb_mcp.server import serve

    try:
        asyncio.run(serve(cfg))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
