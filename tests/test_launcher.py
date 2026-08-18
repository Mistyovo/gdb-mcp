"""Tests for gdb_mcp.launcher pure helpers (no wsl.exe needed)."""

import asyncio

import pytest

from gdb_mcp.launcher import (
    bash_quote,
    build_bash_command,
    build_gdb_argv,
    build_pkill_command,
    parse_distro_list,
    win_to_wsl,
)


class TestWinToWsl:
    def test_drive_path(self):
        assert win_to_wsl(r"C:\Users\x\y") == "/mnt/c/Users/x/y"

    def test_drive_letter_lowercased(self):
        assert win_to_wsl(r"D:\data\bin") == "/mnt/d/data/bin"

    def test_forward_slashes(self):
        assert win_to_wsl("C:/Users/x") == "/mnt/c/Users/x"

    def test_wsl_path_passthrough(self):
        assert win_to_wsl("/home/user/bin") == "/home/user/bin"

    def test_relative_path_raises(self):
        with pytest.raises(ValueError):
            win_to_wsl("relative/path")

    def test_unc_path_raises(self):
        with pytest.raises(ValueError):
            win_to_wsl(r"\\server\share")


class TestParseDistroList:
    def test_basic(self):
        raw = "kali-linux\r\ndocker-desktop\r\nUbuntu\r\n".encode("utf-16-le")
        assert parse_distro_list(raw) == ["kali-linux", "Ubuntu"]

    def test_docker_prefixes_filtered(self):
        raw = "docker-desktop-data\ndocker-desktop\nkali-linux\n".encode("utf-16-le")
        assert parse_distro_list(raw) == ["kali-linux"]

    def test_empty_and_dupes(self):
        raw = "\n\nkali-linux\nkali-linux\n\n".encode("utf-16-le")
        assert parse_distro_list(raw) == ["kali-linux"]

    def test_garbage_decodes_to_empty(self):
        assert parse_distro_list(b"") == []


class TestBashQuote:
    def test_plain(self):
        assert bash_quote("hello") == "'hello'"

    def test_single_quote_escaped(self):
        assert bash_quote("it's") == "'it'\\''s'"

    def test_spaces(self):
        assert bash_quote("a b") == "'a b'"


class TestBuildBashCommand:
    def test_full(self):
        cmd = build_bash_command(
            ["python3", "-u", "/home/u/exploit.py", "arg with space"],
            env={"GDB_MCP_PORT": "3939", "A": "b c"},
            cwd="/home/u",
            marker="gdbmcp_s-001",
        )
        assert "export GDB_MCP_PORT='3939'" in cmd
        assert "export A='b c'" in cmd
        assert "cd '/home/u'" in cmd
        assert "exec -a 'gdbmcp_s-001'" in cmd
        assert "'arg with space'" in cmd

    def test_minimal(self):
        cmd = build_bash_command(["gdb", "-q"])
        assert cmd == "'gdb' '-q'"

    def test_no_env_no_cwd_no_marker(self):
        assert build_bash_command(["x"], env=None, cwd=None, marker=None) == "'x'"


class TestBuildPkillCommand:
    def test_graceful(self):
        cmd = build_pkill_command("s-001", force=False)
        assert "pkill -TERM -f 'gdbmcp_s-001'" in cmd
        assert "sleep 3" in cmd
        assert "pkill -9 -f 'gdbmcp_s-001'" in cmd

    def test_force(self):
        cmd = build_pkill_command("s-001", force=True)
        assert cmd.startswith("pkill -9 -f 'gdbmcp_s-001'")


class TestBuildGdbArgv:
    def test_with_program(self):
        argv = build_gdb_argv(
            "/mnt/c/plugin.py", "/tmp/vuln", ["arg1"], None, run=False
        )
        assert argv == [
            "gdb",
            "-q",
            "-x",
            "/mnt/c/plugin.py",
            "--args",
            "/tmp/vuln",
            "arg1",
        ]

    def test_gdb_args_and_run(self):
        argv = build_gdb_argv(
            "/mnt/c/plugin.py", None, None, ["-nh"], run=True
        )
        assert argv == [
            "gdb",
            "-q",
            "-nh",
            "-x",
            "/mnt/c/plugin.py",
            "-ex",
            "run",
        ]

    def test_no_program(self):
        argv = build_gdb_argv("/mnt/c/plugin.py", None, None, None, run=False)
        assert argv == ["gdb", "-q", "-x", "/mnt/c/plugin.py"]


class TestLogTail:
    def test_tail(self, tmp_path):
        from gdb_mcp.launcher import Launcher
        from gdb_mcp.config import Config
        from gdb_mcp.sessions import SessionRegistry

        log = tmp_path / "x.log"
        log.write_text("a\nb\nc\nd\n")
        launcher = Launcher(Config(), SessionRegistry(Config()))
        assert launcher.log_tail(str(log), lines=2) == "c\nd\n"

    def test_missing_file(self):
        from gdb_mcp.launcher import Launcher
        from gdb_mcp.config import Config
        from gdb_mcp.sessions import SessionRegistry

        launcher = Launcher(Config(), SessionRegistry(Config()))
        assert launcher.log_tail("nope.log") == ""


class TestLauncherLifecycle:
    @pytest.mark.asyncio
    async def test_session_reserved_before_process_spawn(self, monkeypatch, tmp_path):
        from gdb_mcp.config import Config
        from gdb_mcp.launcher import Launcher
        from gdb_mcp.sessions import RESERVED, SessionRegistry

        config = Config(log_dir=tmp_path)
        registry = SessionRegistry(config)
        launcher = Launcher(config, registry)
        wait_forever = asyncio.Event()

        class Proc:
            returncode = None

            async def wait(self):
                await wait_forever.wait()

        async def fake_spawn(*args, **kwargs):
            assert registry.get("s-race").state == RESERVED
            assert kwargs["stdin"] == asyncio.subprocess.PIPE
            return Proc()

        async def fake_distro(override=None):
            return "kali-linux"

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_spawn)
        monkeypatch.setattr(launcher, "distro", fake_distro)
        session = await launcher._spawn(
            ["gdb"],
            {},
            None,
            "s-race",
            tmp_path / "race.log",
            "gdb",
            True,
        )
        assert registry.get("s-race") is session
        registry.remove("s-race")
        session.proc_task.cancel()
        await asyncio.sleep(0)

    @pytest.mark.asyncio
    async def test_launch_script_uses_explicit_gdb_reservation(
        self, monkeypatch, tmp_path
    ):
        from gdb_mcp.config import Config
        from gdb_mcp.launcher import Launcher
        from gdb_mcp.sessions import RUNNING, SessionRegistry

        config = Config(log_dir=tmp_path)
        registry = SessionRegistry(config)
        launcher = Launcher(config, registry)
        captured = {}

        class Writer:
            def close(self):
                pass

        async def fake_spawn(
            argv,
            env,
            cwd_wsl,
            session_id,
            log_file,
            kind,
            marker,
            distro_override=None,
        ):
            captured.update(env)
            script = registry.reserve(session_id, kind=kind, log_file=str(log_file))
            script.state = RUNNING
            registry.register_hello(
                {
                    "type": "hello",
                    "proto": 1,
                    "session_id": env["GDB_MCP_SESSION_ID"],
                    "pid": 4242,
                },
                Writer(),
            )
            return script

        monkeypatch.setattr(launcher, "_spawn", fake_spawn)
        script, gdb = await launcher.launch_script(
            script=r"C:\work\exploit.py",
            python="python3",
            args=None,
            cwd=None,
            env={"GDB_MCP_SESSION_ID": "attacker-controlled"},
            timeout_ms=1000,
        )
        assert script.kind == "script"
        assert gdb is not None
        assert gdb.session_id == captured["GDB_MCP_SESSION_ID"]
        assert gdb.session_id != "attacker-controlled"
        assert gdb.log_file is None

    @pytest.mark.asyncio
    async def test_launch_script_returns_when_script_exits_and_removes_reservation(
        self, monkeypatch, tmp_path
    ):
        from gdb_mcp.config import Config
        from gdb_mcp.launcher import Launcher
        from gdb_mcp.sessions import EXITED, SessionRegistry

        config = Config(log_dir=tmp_path)
        registry = SessionRegistry(config)
        launcher = Launcher(config, registry)

        async def fake_spawn(
            argv,
            env,
            cwd_wsl,
            session_id,
            log_file,
            kind,
            marker,
            distro_override=None,
        ):
            script = registry.reserve(session_id, kind=kind, log_file=str(log_file))
            script.state = EXITED
            script.proc_returncode = 0
            return script

        monkeypatch.setattr(launcher, "_spawn", fake_spawn)
        script, gdb = await asyncio.wait_for(
            launcher.launch_script(
                script=r"C:\work\pure_script.py",
                python="python3",
                args=None,
                cwd=None,
                env=None,
                timeout_ms=60_000,
            ),
            timeout=0.5,
        )

        assert script.state == EXITED
        assert gdb is None
        assert registry.list_all() == [script]

    @pytest.mark.asyncio
    async def test_launch_script_timeout_removes_unused_gdb_reservation(
        self, monkeypatch, tmp_path
    ):
        from gdb_mcp.config import Config
        from gdb_mcp.launcher import Launcher
        from gdb_mcp.sessions import RUNNING, SessionRegistry

        config = Config(log_dir=tmp_path)
        registry = SessionRegistry(config)
        launcher = Launcher(config, registry)

        async def fake_spawn(
            argv,
            env,
            cwd_wsl,
            session_id,
            log_file,
            kind,
            marker,
            distro_override=None,
        ):
            script = registry.reserve(session_id, kind=kind, log_file=str(log_file))
            script.state = RUNNING
            return script

        monkeypatch.setattr(launcher, "_spawn", fake_spawn)
        script, gdb = await launcher.launch_script(
            script=r"C:\work\long_running.py",
            python="python3",
            args=None,
            cwd=None,
            env=None,
            timeout_ms=1,
        )

        assert gdb is None
        assert registry.list_all() == [script]

    @pytest.mark.asyncio
    async def test_cancelled_launch_script_removes_unused_gdb_reservation(
        self, monkeypatch, tmp_path
    ):
        from gdb_mcp.config import Config
        from gdb_mcp.launcher import Launcher
        from gdb_mcp.sessions import RUNNING, SessionRegistry

        config = Config(log_dir=tmp_path)
        registry = SessionRegistry(config)
        launcher = Launcher(config, registry)

        async def fake_spawn(
            argv,
            env,
            cwd_wsl,
            session_id,
            log_file,
            kind,
            marker,
            distro_override=None,
        ):
            script = registry.reserve(session_id, kind=kind, log_file=str(log_file))
            script.state = RUNNING
            return script

        monkeypatch.setattr(launcher, "_spawn", fake_spawn)
        task = asyncio.create_task(
            launcher.launch_script(
                script=r"C:\work\long_running.py",
                python="python3",
                args=None,
                cwd=None,
                env=None,
                timeout_ms=60_000,
            )
        )
        await asyncio.sleep(0)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(registry.list_all()) == 1
        assert registry.list_all()[0].kind == "script"

    @pytest.mark.asyncio
    async def test_launch_script_rejects_inline_code_with_specific_message(self, tmp_path):
        from gdb_mcp.config import Config
        from gdb_mcp.launcher import Launcher
        from gdb_mcp.sessions import SessionRegistry

        config = Config(log_dir=tmp_path)
        launcher = Launcher(config, SessionRegistry(config))

        with pytest.raises(ValueError, match="absolute file path.*inline Python code"):
            await launcher.launch_script(
                script="print('hello')",
                python="python3",
                args=None,
                cwd=None,
                env=None,
                timeout_ms=100,
            )
