"""Architecture guards: the dependency direction this project settled on.

Each assertion here is the regression test for a specific structural defect
that existed before (see the 2026-09 audit): the static bridge importing the
launcher, sessions importing the reverse package, and — most of all — the
MCP layer reaching into FastMCP's private internals. Those are cheap to
re-introduce by accident and expensive to notice later, so they are checked
mechanically instead of by review.
"""

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "gdb_mcp"


def _tree(module_path: Path) -> ast.Module:
    return ast.parse(module_path.read_text(encoding="utf-8"))


def _imports(module_path: Path) -> set[str]:
    """Every gdb_mcp module this file imports, by dotted name."""
    found: set[str] = set()
    for node in ast.walk(_tree(module_path)):
        if isinstance(node, ast.ImportFrom):
            if node.level:  # relative import inside the package
                found.add("gdb_mcp.%s" % (node.module or ""))
                for alias in node.names:
                    found.add(
                        "gdb_mcp.%s.%s" % (node.module or "", alias.name)
                    )
            elif node.module:
                found.add(node.module)
                for alias in node.names:
                    found.add("%s.%s" % (node.module, alias.name))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
    return {name.rstrip(".") for name in found}


def _source(name: str) -> str:
    return (SRC / name).read_text(encoding="utf-8")


class TestLayering:
    def test_wsl_helpers_depend_on_nothing_internal(self):
        """launcher sits above this module, so it must not learn about it."""
        assert {n for n in _imports(SRC / "wsl.py") if n.startswith("gdb_mcp")} == set()

    def test_sessions_does_not_import_its_consumers(self):
        imported = _imports(SRC / "sessions.py")
        for forbidden in ("gdb_mcp.launcher", "gdb_mcp.tools", "gdb_mcp.server"):
            assert not any(name.startswith(forbidden) for name in imported)

    def test_tool_modules_do_not_import_the_server(self):
        for path in (SRC / "tools").glob("*.py"):
            assert "gdb_mcp.server" not in _imports(path), path.name

    def test_launcher_and_bridge_talk_to_sessions_only_through_the_registry(self):
        """Session state changes are a documented API (set_state /
        note_process_exit); assigning the attributes from outside the
        sessions module is how the state machine got bypassed before."""
        offenders = []
        for relative in ("launcher.py", "tcp_listener.py", "campaign.py", "journal.py"):
            path = SRC / relative
            for node in ast.walk(_tree(path)):
                if not isinstance(node, ast.Assign):
                    continue
                for target in node.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and target.attr
                        in {"state", "token", "stop_info", "exited_code"}
                        and isinstance(target.value, ast.Name)
                        and target.value.id in {"session", "s", "gdb_session", "script_session"}
                    ):
                        offenders.append("%s:%s" % (relative, node.lineno))
        assert offenders == []


class TestMcpBoundary:
    """Everything the tool surface needs must come from gdb_mcp.tools.registry
    and gdb_mcp.context; FastMCP's private attributes stay private."""

    def test_only_the_registry_reads_fastmcp_internals(self):
        users = []
        for path in SRC.rglob("*.py"):
            if "_tool_manager" in path.read_text(encoding="utf-8"):
                users.append(str(path.relative_to(SRC)))
        assert users == [str(Path("tools") / "registry.py")]

    def test_no_private_attributes_are_attached_to_the_app(self):
        offenders = []
        for path in SRC.rglob("*.py"):
            for node in ast.walk(_tree(path)):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if (
                            isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == "app"
                            and target.attr.startswith("_")
                        ):
                            offenders.append("%s:%s" % (path.name, node.lineno))
        assert offenders == []

    def test_the_lifespan_context_is_a_typed_object(self):
        """Tools reach the registry / config / analysis manager / launcher
        through ServerContext, not through ad-hoc dict keys."""
        assert "class ServerContext" in _source("context.py")
        common = _source("tools/_common.py")
        assert "ctx.request_context.lifespan_context" in common
        assert 'lifespan_context["' not in common
        assert "ServerContext" in _source("server.py")


class TestDocumentedCounts:
    """README numbers are load-bearing claims. The declarations are the
    source of truth; these checks fail when a tool change is not carried
    into BOTH READMEs, and enforce the default-profile schema token
    budget so tool definitions never silently bloat."""

    #: default pwn-profile schema byte budget (~6.5k tokens at ~3.5 chars/tok)
    PWN_SCHEMA_BYTE_BUDGET = 24_000

    @staticmethod
    def _counts():
        import gdb_mcp.tools as tools

        tools._load_tool_modules()
        from gdb_mcp.tools.registry import SPECS

        total = len(SPECS)
        experimental = sum(1 for spec in SPECS if spec.experimental)
        core = sum(1 for spec in SPECS if spec.core)
        pwn = sum(1 for spec in SPECS if not spec.experimental)
        return total, experimental, core, pwn

    def test_declared_tool_counts(self):
        # (total, experimental, core, pwn-default)
        assert self._counts() == (37, 1, 12, 36)

    def test_pwn_schema_within_token_budget(self, tmp_path):
        import json

        from gdb_mcp.config import Config
        from gdb_mcp.server import build_app
        from gdb_mcp.sessions import SessionRegistry
        from gdb_mcp.tools import registered_tools

        cfg = Config(tool_profile="pwn", log_dir=tmp_path / "l")
        tools = registered_tools(build_app(cfg, SessionRegistry(cfg)))
        total_bytes = sum(
            len(t.description or "")
            + len(json.dumps({"name": t.name, "parameters": t.parameters}, ensure_ascii=False))
            for t in tools.values()
        )
        assert total_bytes <= self.PWN_SCHEMA_BYTE_BUDGET, (
            "pwn schema is %d bytes (budget %d)" % (total_bytes, self.PWN_SCHEMA_BYTE_BUDGET)
        )

    def test_readmes_state_the_declared_counts(self):
        root = SRC.parent.parent
        _, experimental, core, pwn = self._counts()
        claims = {
            "README.md": [
                "**%d tools by default**" % pwn,
                "**%d** under `GDB_MCP_TOOL_PROFILE=core`" % core,
            ],
            "README.zh-CN.md": [
                "`pwn` 档 %d 个" % pwn,
                "`core` 档 %d 个" % core,
            ],
        }
        for name, needles in claims.items():
            text = " ".join(
                (root / name).read_text(encoding="utf-8").split()
            )
            for needle in needles:
                assert needle in text, "%s lost its %r claim" % (name, needle)
