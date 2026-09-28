"""Tests for the experimental libc-identification and gadget tools."""

import pytest

from gdb_mcp.config import Config
from gdb_mcp.errors import GdbMcpError
from gdb_mcp.server import build_app
from gdb_mcp.sessions import SessionRegistry
from gdb_mcp.tools import registered_tools

from test_tools import add_gdb_session, run_tool


class _Env:
    def __init__(self, tmp_path):
        self.cfg = Config(log_dir=tmp_path / "l", experimental=True)
        self.registry = SessionRegistry(self.cfg)
        self.app = build_app(self.cfg, self.registry)
        self.tools = registered_tools(self.app)

    def ctx(self):
        from test_tools import FakeContext

        return FakeContext(self.registry, self.cfg)


class TestExperimentalGating:
    def test_hidden_by_default(self, tmp_path):
        cfg = Config(log_dir=tmp_path / "l")
        app = build_app(cfg, SessionRegistry(cfg))
        names = set(registered_tools(app))
        assert "identify_libc" not in names
        assert "search_gadgets" not in names

    def test_registered_when_enabled(self, tmp_path):
        env = _Env(tmp_path)
        assert {"identify_libc", "search_gadgets"} <= set(env.tools)


class TestIdentifyLibc:
    @pytest.mark.asyncio
    async def test_normalizes_leaks_and_queries(self, tmp_path, monkeypatch):
        env = _Env(tmp_path)
        add_gdb_session(env.registry)
        captured = {}

        def fake_api_find(endpoint, payload):
            # matches the production contract: a sync function invoked
            # via asyncio.to_thread
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return [
                {
                    "libc_id": "libc6_2.31-0ubuntu9_amd64",
                    "download_url": "http://example/libc.so.6",
                }
            ]

        from gdb_mcp.tools import experimental as exp

        monkeypatch.setattr(exp, "_api_find", fake_api_find)
        result = await run_tool(
            env.tools["identify_libc"],
            {"leaks": {"puts": "0x7ffff7a6c720", "gets": "720"}},
            env.ctx(),
        )
        assert captured["endpoint"] == "https://libc.rip/api/find"
        # only the page offset (low 12 bits) is meaningful in a leak
        assert captured["payload"]["symbols"] == {"puts": "0x720", "gets": "0x720"}
        assert result["matches"][0]["libc_id"] == "libc6_2.31-0ubuntu9_amd64"
        assert result["query"] == {"puts": "0x720", "gets": "0x720"}

    @pytest.mark.asyncio
    async def test_use_api_false_skips_query(self, tmp_path, monkeypatch):
        env = _Env(tmp_path)
        add_gdb_session(env.registry)

        def boom(endpoint, payload):
            raise AssertionError("API must not be queried")

        from gdb_mcp.tools import experimental as exp

        monkeypatch.setattr(exp, "_api_find", boom)
        result = await run_tool(
            env.tools["identify_libc"],
            {"leaks": {"puts": "0x720"}, "use_api": False},
            env.ctx(),
        )
        assert result["matches"] == []
        assert "nothing queried" in result["note"]

    @pytest.mark.asyncio
    async def test_invalid_leak_rejected(self, tmp_path):
        env = _Env(tmp_path)
        add_gdb_session(env.registry)
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(
                env.tools["identify_libc"],
                {"leaks": {"puts": "not-hex"}},
                env.ctx(),
            )
        assert ei.value.code == "BAD_PARAMS"

    @pytest.mark.asyncio
    async def test_api_failure_is_reported(self, tmp_path, monkeypatch):
        env = _Env(tmp_path)
        add_gdb_session(env.registry)

        def boom(endpoint, payload):
            raise ConnectionError("unreachable")

        from gdb_mcp.tools import experimental as exp

        monkeypatch.setattr(exp, "_api_find", boom)
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(
                env.tools["identify_libc"],
                {"leaks": {"puts": "0x720"}},
                env.ctx(),
            )
        assert ei.value.code == "PLUGIN_ERROR"
        assert "reachability" in ei.value.message


class TestSearchGadgets:
    FAKE_OUTPUT = (
        "Gadgets information\n"
        "============================================================\n"
        "0x0000000000401234 : pop rdi ; ret\n"
        "0x0000000000401238 : ret\n"
        "0x000000000040123c : pop rsi ; pop r15 ; ret\n"
        "\n"
        "Unique gadgets found: 3\n"
    )

    @pytest.mark.asyncio
    async def test_parses_and_filters(self, tmp_path, monkeypatch):
        env = _Env(tmp_path)

        def fake_run(binary, only):
            assert only == "pop|ret"
            return 0, self.FAKE_OUTPUT

        from gdb_mcp.tools import experimental as exp

        monkeypatch.setattr(exp, "_run_ropgadget", fake_run)
        result = await run_tool(
            env.tools["search_gadgets"],
            {"binary": "/tmp/vuln", "pattern": "pop rdi"},
            env.ctx(),
        )
        assert result["total_matched"] == 1
        assert result["gadgets"][0] == {
            "address": "0x401234",
            "instructions": "pop rdi ; ret",
        }
        assert result["truncated"] is False

    @pytest.mark.asyncio
    async def test_max_results_truncates(self, tmp_path, monkeypatch):
        env = _Env(tmp_path)

        def fake_run(binary, only):
            return 0, self.FAKE_OUTPUT

        from gdb_mcp.tools import experimental as exp

        monkeypatch.setattr(exp, "_run_ropgadget", fake_run)
        result = await run_tool(
            env.tools["search_gadgets"],
            {"binary": "/tmp/vuln", "pattern": "ret", "max_results": 2},
            env.ctx(),
        )
        assert result["total_matched"] == 2
        assert result["truncated"] is True

    @pytest.mark.asyncio
    async def test_missing_ropgadget_reported(self, tmp_path, monkeypatch):
        env = _Env(tmp_path)

        def boom(binary, only):
            raise FileNotFoundError("ROPgadget")

        from gdb_mcp.tools import experimental as exp

        monkeypatch.setattr(exp, "_run_ropgadget", boom)
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(
                env.tools["search_gadgets"],
                {"binary": "/tmp/vuln"},
                env.ctx(),
            )
        assert ei.value.code == "ROPGADGET_MISSING"
        assert "pip install ROPgadget" in ei.value.message

    @pytest.mark.asyncio
    async def test_bad_pattern_rejected(self, tmp_path):
        env = _Env(tmp_path)
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(
                env.tools["search_gadgets"],
                {"binary": "/tmp/vuln", "pattern": "([bad"},
                env.ctx(),
            )
        assert ei.value.code == "BAD_PARAMS"
