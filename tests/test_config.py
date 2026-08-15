"""Tests for gdb_mcp.config environment assembly."""

import pytest

from gdb_mcp.config import Config, DEFAULTS


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
