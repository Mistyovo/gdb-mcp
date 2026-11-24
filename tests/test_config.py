"""Tests for gdb_mcp.config environment assembly."""

import os

import pytest

from gdb_mcp.config import Config, DEFAULTS


class TestPhase3Options:
    def test_launcher_validation(self):
        assert Config().launcher == "wsl"
        with pytest.raises(ValueError):
            Config(launcher="telnet").validate()
        with pytest.raises(ValueError):
            Config(launcher="ssh").validate()
        with pytest.raises(ValueError):
            Config(launcher="docker").validate()
        Config(launcher="native").validate()

    def test_bool_env_flags(self, monkeypatch):
        monkeypatch.setenv("GDB_MCP_READONLY", "1")
        monkeypatch.setenv("GDB_MCP_ALLOW_UNSAFE", "true")
        cfg = Config.from_env()
        assert cfg.readonly is True
        assert cfg.allow_unsafe is True

    def test_experimental_never_from_env(self, monkeypatch):
        """Regression: experimental tools are --experimental-only. A stray
        environment variable must never enable them at server start."""
        monkeypatch.setenv("GDB_MCP_EXPERIMENTAL", "1")
        cfg = Config.from_env()
        assert cfg.experimental is False

    def test_experimental_via_cli_override(self):
        cfg = Config.from_env(overrides={"experimental": True})
        assert cfg.experimental is True
        assert Config.from_env().experimental is False

    def test_launcher_env(self, monkeypatch):
        monkeypatch.setenv("GDB_MCP_LAUNCHER", "native")
        cfg = Config.from_env()
        assert cfg.launcher == "native"


class TestPhase1Options:
    def test_tool_profile_default_and_validation(self):
        assert Config().tool_profile == "pwn"
        with pytest.raises(ValueError):
            Config(tool_profile="mega").validate()

    def test_result_inline_limit_default(self):
        assert Config().result_inline_limit == DEFAULTS["result_inline_limit"]

    def test_env_overrides(self, monkeypatch):
        monkeypatch.setenv("GDB_MCP_TOOL_PROFILE", "core")
        monkeypatch.setenv("GDB_MCP_RESULT_INLINE_LIMIT", "2048")
        cfg = Config.from_env()
        assert cfg.tool_profile == "core"
        assert cfg.result_inline_limit == 2048


class TestDefaults:
    def test_factory_defaults(self):
        cfg = Config()
        assert cfg.host_bind == DEFAULTS["host_bind"]
        assert cfg.port == 3939
        assert cfg.token is None
        assert cfg.wsl_distro is None
        assert cfg.mcp_transport is True

    def test_default_log_dir_under_userprofile(self, monkeypatch, tmp_path):
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
        assert Config().log_dir == tmp_path / ".gdb-mcp" / "logs"

    def test_ensure_dirs(self, tmp_path):
        cfg = Config(log_dir=tmp_path / "nested" / "logs")
        cfg.ensure_dirs()
        assert cfg.log_dir.is_dir()

    def test_remote_bind_requires_token(self):
        cfg = Config(host_bind="0.0.0.0")
        with pytest.raises(ValueError, match="token is required"):
            cfg.validate()

    def test_remote_bind_with_token_is_valid(self):
        Config(host_bind="0.0.0.0", token="sekret").validate()


class TestFromEnv:
    def test_empty_env_yields_defaults(self, monkeypatch):
        for name in (
            "PORT",
            "HOST_BIND",
            "TOKEN",
            "WSL_DISTRO",
            "LOG_DIR",
            "REQUEST_TIMEOUT",
            "HEARTBEAT_SEC",
        ):
            monkeypatch.delenv(f"GDB_MCP_{name}", raising=False)
        cfg = Config.from_env()
        assert cfg.port == 3939
        assert cfg.host_bind == "127.0.0.1"
        assert cfg.token is None

    def test_env_values_parsed(self, monkeypatch, tmp_path):
        monkeypatch.setenv("GDB_MCP_PORT", "4001")
        monkeypatch.setenv("GDB_MCP_HOST_BIND", "127.0.0.1")
        monkeypatch.setenv("GDB_MCP_TOKEN", "sekret")
        monkeypatch.setenv("GDB_MCP_WSL_DISTRO", "ubuntu")
        monkeypatch.setenv("GDB_MCP_LOG_DIR", str(tmp_path / "logs"))
        monkeypatch.setenv("GDB_MCP_REQUEST_TIMEOUT", "12.5")
        cfg = Config.from_env()
        assert cfg.port == 4001
        assert cfg.host_bind == "127.0.0.1"
        assert cfg.token == "sekret"
        assert cfg.wsl_distro == "ubuntu"
        assert cfg.log_dir == tmp_path / "logs"
        assert cfg.request_timeout == 12.5

    def test_invalid_values_fall_back(self, monkeypatch):
        monkeypatch.setenv("GDB_MCP_PORT", "not-a-number")
        cfg = Config.from_env()
        assert cfg.port == 3939

    def test_overrides_win(self, monkeypatch):
        monkeypatch.setenv("GDB_MCP_PORT", "4001")
        cfg = Config.from_env(overrides={"port": 5000, "token": None})
        assert cfg.port == 5000
        assert cfg.token is None


class TestArchiveOptions:
    def test_archive_retention_validation(self):
        Config(archive_retention=20).validate()
        Config(archive_retention=0).validate()
        with pytest.raises(ValueError):
            Config(archive_retention=-1).validate()

    def test_archive_retention_env(self, monkeypatch):
        monkeypatch.setenv("GDB_MCP_ARCHIVE_RETENTION", "5")
        assert Config.from_env().archive_retention == 5


class TestPathFields:
    def test_strings_are_coerced_to_paths(self, tmp_path):
        """The annotations promise Path; accepting a str and failing later
        inside ensure_dirs() is a trap for embedders."""
        cfg = Config(
            log_dir=str(tmp_path / "logs"),
            archive_dir=str(tmp_path / "archive"),
        )
        assert cfg.log_dir == tmp_path / "logs"
        assert cfg.archive_dir == tmp_path / "archive"
        cfg.ensure_dirs()
        assert cfg.log_dir.is_dir()

    def test_none_stays_none(self):
        cfg = Config()
        assert cfg.archive_dir is None


class TestCliOverridesDoNotEraseEnv:
    """Precedence is CLI > env > default, and "flag absent" must not read as
    "flag set to false".
    """

    @pytest.fixture
    def env(self, monkeypatch):
        for var in list(os.environ):
            if var.startswith("GDB_MCP_"):
                monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("GDB_MCP_READONLY", "1")
        monkeypatch.setenv("GDB_MCP_ALLOW_UNSAFE", "true")
        monkeypatch.setenv("GDB_MCP_TOOL_PROFILE", "core")

    def _config(self, argv, tmp_path):
        from gdb_mcp.__main__ import _build_parser, _overrides

        args = _build_parser().parse_args(argv + ["--log-dir", str(tmp_path / "l")])
        return Config.from_env(overrides=_overrides(args))

    def test_environment_survives_a_bare_invocation(self, env, tmp_path):
        cfg = self._config([], tmp_path)
        assert cfg.readonly is True
        assert cfg.allow_unsafe is True
        assert cfg.tool_profile == "core"

    def test_explicit_flag_still_wins(self, env, tmp_path):
        cfg = self._config(["--readonly"], tmp_path)
        assert cfg.readonly is True
        # the inverse case: an operator can turn a hard env default off only
        # by unsetting the variable, never by accident of the CLI parser
        assert cfg.mcp_transport is True

    def test_no_mcp_flag_overrides_transport(self, env, tmp_path):
        assert self._config(["--no-mcp"], tmp_path).mcp_transport is False

    def test_experimental_stays_cli_only(self, env, monkeypatch, tmp_path):
        monkeypatch.setenv("GDB_MCP_EXPERIMENTAL", "1")
        assert self._config([], tmp_path).experimental is False
        assert self._config(["--experimental"], tmp_path).experimental is True

    def test_readonly_profile_actually_drops_write_tools(self, env, tmp_path):
        """The env var has to reach the tool surface, not just the config."""
        from gdb_mcp.server import build_app
        from gdb_mcp.sessions import SessionRegistry
        from gdb_mcp.tools import registered_tools

        cfg = self._config([], tmp_path)
        names = set(registered_tools(build_app(cfg, SessionRegistry(cfg))))
        assert not names & {"write_memory", "write_register"}
        assert "read_memory" in names
