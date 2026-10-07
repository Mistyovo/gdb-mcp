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
        """launcher and the static bridge both sit above this module, so it
        must not learn about either."""
        assert {n for n in _imports(SRC / "wsl.py") if n.startswith("gdb_mcp")} == set()

    def test_store_does_not_reach_upward(self):
        forbidden = {"gdb_mcp.reverse.manager", "gdb_mcp.sessions", "gdb_mcp.tools"}
        imported = _imports(SRC / "reverse" / "store.py")
        assert not (imported & forbidden)

    def test_reverse_does_not_import_the_launcher(self):
        """Path/distro helpers live in gdb_mcp.wsl precisely so the static
        bridge does not depend on process launching."""
        for path in (SRC / "reverse").glob("*.py"):
            assert "gdb_mcp.launcher" not in _imports(path), path.name

    def test_sessions_does_not_import_its_consumers(self):
        imported = _imports(SRC / "sessions.py")
        for forbidden in ("gdb_mcp.reverse", "gdb_mcp.launcher", "gdb_mcp.tools", "gdb_mcp.server"):
            assert not any(name.startswith(forbidden) for name in imported)

    def test_tool_modules_do_not_import_the_server(self):
        for path in (SRC / "tools").glob("*.py"):
            assert "gdb_mcp.server" not in _imports(path), path.name

    def test_launcher_and_bridge_talk_to_sessions_only_through_the_registry(self):
        """Session state changes are a documented API (set_state /
        note_process_exit / attach_analysis / note_location); assigning the
        attributes from outside the sessions module is how the state machine
        got bypassed before."""
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
                        in {"state", "token", "stop_info", "exited_code", "location", "analysis_id"}
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


class TestPackagingInputs:
    """Files referenced by build/deploy recipes must exist.

    The docker launcher's image recipe once pointed `COPY` at a plugin path
    that had moved, so the documented build command failed with a cache-key
    error that nothing in the test suite could see.
    """

    def test_dockerfile_copy_sources_exist(self):
        root = SRC.parent.parent
        dockerfile = (root / "docker" / "Dockerfile").read_text(encoding="utf-8")
        missing = []
        for line in dockerfile.splitlines():
            if not line.startswith("COPY"):
                continue
            # COPY [--flag ...] <src>... <dest>: everything but the flags and
            # the final destination is a path in the build context
            tokens = [t for t in line.split()[1:] if not t.startswith("--")]
            for src in tokens[:-1]:
                if not (root / src).exists():
                    missing.append(src)
        assert not missing, "docker/Dockerfile COPYs absent paths: %s" % missing

    def test_plugin_is_shipped_where_the_launcher_looks(self):
        """The container path the launcher mounts must be the path the image
        actually copies."""
        root = SRC.parent.parent
        dockerfile = (root / "docker" / "Dockerfile").read_text(encoding="utf-8")
        destination = "/opt/gdb-mcp/" + (SRC / "plugin" / "gdb_mcp_plugin.py").name
        lines = [line for line in dockerfile.splitlines() if line.startswith("COPY")]
        matches = [line for line in lines if line.rstrip().endswith(destination)]
        assert matches, "nothing COPYs the plugin to %s" % destination
        assert (root / matches[0].split()[1]).is_file()


class TestDocumentedCounts:
    """README numbers are load-bearing claims, and every one of them had
    drifted by 2026-10-07 (tests, experimental tools, static tools). The
    declarations are the source of truth; these checks fail when a tool
    change is not carried into BOTH READMEs, so the docs cannot lag the
    code again. Adding a tool means updating these numbers on purpose."""

    @staticmethod
    def _counts():
        import gdb_mcp.tools as tools

        tools._load_tool_modules()
        from gdb_mcp.tools.registry import SPECS

        total = len(SPECS)
        experimental = sum(1 for spec in SPECS if spec.experimental)
        core = sum(1 for spec in SPECS if spec.core)
        return total, experimental, core, total - experimental

    def test_declared_tool_counts(self):
        # (total, experimental, core, default-visible)
        assert self._counts() == (60, 8, 12, 52)

    def test_readmes_state_the_declared_counts(self):
        root = SRC.parent.parent
        _, experimental, core, default = self._counts()
        claims = {
            "README.md": [
                "**%d tools by default**" % default,
                "%d under `GDB_MCP_TOOL_PROFILE=core`" % core,
                "**%d experimental tools**" % experimental,
                "**15 static-analysis tools**",
            ],
            "README.zh-CN.md": [
                "默认 %d 个" % default,
                "`core` 档 %d 个" % core,
                "%d 个实验工具" % experimental,
            ],
        }
        for name, needles in claims.items():
            text = (root / name).read_text(encoding="utf-8")
            for needle in needles:
                assert needle in text, "%s lost its %r claim" % (name, needle)
