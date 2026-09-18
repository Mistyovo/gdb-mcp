"""Tests for gdb_mcp.config environment assembly."""

import pytest

from gdb_mcp.config import Config, DEFAULTS


class TestPhase3Options:
    def test_launcher_validation(self):
        assert Config().launcher == "wsl"
        with pytest.raises(ValueError):
            Config(launcher="telnet").validate()
        with pytest.raises(ValueError):
            Config(launcher="ssh").validate()  # ssh_host required
        Config(launcher="ssh", ssh_host="box").validate()
        Config(launcher="native").validate()
        Config(launcher="docker").validate()

    def test_http_nonloopback_requires_token(self):
        with pytest.raises(ValueError):
            Config(mcp_http=True, mcp_host="0.0.0.0").validate()
        Config(mcp_http=True, mcp_host="0.0.0.0", token="secret").validate()
        Config(mcp_http=True, mcp_host="127.0.0.1").validate()

    def test_bool_env_flags(self, monkeypatch):
        monkeypatch.setenv("GDB_MCP_READONLY", "1")
        monkeypatch.setenv("GDB_MCP_ALLOW_UNSAFE", "true")
        monkeypatch.setenv("GDB_MCP_MCP_HTTP", "on")
        cfg = Config.from_env()
        assert cfg.readonly is True
        assert cfg.allow_unsafe is True
        assert cfg.mcp_http is True

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
        monkeypatch.setenv("GDB_MCP_LAUNCHER", "docker")
        monkeypatch.setenv("GDB_MCP_DOCKER_IMAGE", "gdb-mcp:dev")
        cfg = Config.from_env()
        assert cfg.launcher == "docker"
        assert cfg.docker_image == "gdb-mcp:dev"


class TestPhase1Options:
    def test_tool_profile_default_and_validation(self):
        assert Config().tool_profile == "full"
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


class TestE4Options:
    def test_tls_material_pairs(self):
        with pytest.raises(ValueError):
            Config(mcp_tls_cert="a.pem").validate()
        with pytest.raises(ValueError):
            Config(mcp_tls_key="a.key").validate()
        with pytest.raises(ValueError):
            Config(mcp_tls_client_ca="ca.pem").validate()
        Config(mcp_tls_cert="a.pem", mcp_tls_key="a.key").validate()
        Config(
            mcp_tls_cert="a.pem", mcp_tls_key="a.key", mcp_tls_client_ca="ca.pem"
        ).validate()

    def test_observer_tokens_validation(self):
        with pytest.raises(ValueError):
            Config(token="m", observer_tokens=("m",)).validate()
        with pytest.raises(ValueError):
            Config(observer_tokens=("",)).validate()
        Config(token="m", observer_tokens=("o",)).validate()

    def test_observer_tokens_env_comma_list(self, monkeypatch):
        monkeypatch.setenv("GDB_MCP_OBSERVER_TOKENS", "a, b ,")
        assert Config.from_env().observer_tokens == ("a", "b")
