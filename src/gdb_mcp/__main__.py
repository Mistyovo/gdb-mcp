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
        "Linux userland binary exploitation.",
    )
    p.add_argument("--host-bind", default=None, help="TCP bind address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=None, help="TCP port (default 3939)")
    p.add_argument("--token", default=None, help="optional shared token for gdb plugins")
    p.add_argument("--log-dir", default=None, help="launched-process log directory")
    p.add_argument(
        "--archive-retention",
        type=int,
        default=None,
        metavar="N",
        help="keep the newest N closed sessions' journals+logs in the "
        "archive (default 20; 0 disables archiving)",
    )
    p.add_argument(
        "--no-mcp",
        action="store_true",
        default=None,
        help="run the TCP listener only, without the stdio MCP transport "
        "(for integration tests)",
    )
    p.add_argument(
        "--tool-profile",
        choices=("core", "pwn"),
        default=None,
        help="MCP tool surface: core (minimal) or pwn (default: userland "
        "debugging + pwn workflow)",
    )
    p.add_argument(
        "--launcher",
        choices=("wsl", "native"),
        default=None,
        help="where launch_* run processes: wsl (default on Windows) or "
        "native (default on Linux)",
    )
    p.add_argument(
        "--gdb-path",
        default=None,
        help="gdb executable to launch (default: gdb from PATH)",
    )
    p.add_argument(
        "--selfcheck",
        action="store_true",
        default=False,
        help="check launcher prerequisites (gdb, embedded Python, plugin, "
        "port) and exit; prints JSON",
    )
    p.add_argument(
        "--readonly",
        action="store_true",
        default=None,
        help="keep only observe-capability tools (excludes execution, "
        "breakpoints, launches, writes, policies, and host tools)",
    )
    p.add_argument(
        "--allow-unsafe",
        action="store_true",
        default=None,
        help="allow gdb commands that escape the debugger (shell/!/python/...)",
    )
    p.add_argument(
        "--experimental",
        action="store_true",
        default=None,
        help="register experimental tools (unstable; CLI-only, no env var)",
    )
    return p


def _overrides(args) -> dict:
    """CLI flags as Config overrides.

    Every flag defaults to None so absent options never overwrite values
    loaded from the environment (such as ``GDB_MCP_READONLY``).
    """
    return {
        "host_bind": args.host_bind,
        "port": args.port,
        "token": args.token,
        "log_dir": Path(args.log_dir) if args.log_dir else None,
        "archive_retention": args.archive_retention,
        "mcp_transport": None if args.no_mcp is None else not args.no_mcp,
        "tool_profile": args.tool_profile,
        "launcher": args.launcher,
        "gdb_path": args.gdb_path,
        "readonly": args.readonly,
        "allow_unsafe": args.allow_unsafe,
        "experimental": args.experimental,
    }


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    from gdb_mcp.config import Config

    try:
        cfg = Config.from_env(overrides=_overrides(args))
    except ValueError as exc:
        parser.error(str(exc))
    if args.selfcheck:
        import json

        from gdb_mcp.selfcheck import run_selfcheck

        result = asyncio.run(run_selfcheck(cfg))
        print(json.dumps(result, indent=2))
        return 0 if result["ready"] else 1
    from gdb_mcp.server import serve

    try:
        asyncio.run(serve(cfg))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
