"""Tests for the MCP tool layer (fake session transport, no sockets)."""

import asyncio
import json

import pytest

from gdb_mcp.config import Config
from gdb_mcp.errors import GdbMcpError
from gdb_mcp.server import build_app
from gdb_mcp.sessions import EXITED, RUNNING, SessionRegistry
from gdb_mcp.tools import CORE_TOOLS

from test_sessions import FakeWriter, hello


class FakeRequestContext:
    def __init__(self, registry, config):
        self.lifespan_context = {"registry": registry, "config": config}


class FakeContext:
    def __init__(self, registry, config):
        self.request_context = FakeRequestContext(registry, config)


@pytest.fixture
def env(tmp_path):
    cfg = Config(
        request_timeout=5.0,
        max_mem_read=1024,
        log_dir=tmp_path / "logs",
        result_inline_limit=64,
    )
    ids = iter("s-%03d" % i for i in range(100))
    registry = SessionRegistry(cfg, session_id_factory=lambda: next(ids))
    app = build_app(cfg, registry)
    tools = {
        name: app._tool_manager._tools[name]
        for name in app._tool_manager._tools
    }
    return registry, cfg, tools


def ctx_for(env):
    return FakeContext(env[0], env[1])


def add_gdb_session(registry, **extra):
    return registry.register_hello(hello(**extra), FakeWriter())


async def run_tool(tool, kwargs, ctx):
    call_kwargs = dict(kwargs)
    if tool.context_kwarg:
        call_kwargs[tool.context_kwarg] = ctx
    result = tool.fn(**call_kwargs)
    if asyncio.iscoroutine(result):
        result = await result
    return result


async def next_request(session, writer):
    """Wait for the next request line the tool wrote to the fake writer."""
    for _ in range(200):
        if writer.sent:
            break
        await asyncio.sleep(0.005)
    assert writer.sent, "no request was sent"
    return json.loads(writer.sent.pop(0).decode("utf-8"))


async def respond_to(session, writer, result=None, error=None):
    req = await next_request(session, writer)
    if error:
        await session.complete_response(
            req["id"], {"ok": False, "error": {"code": error, "message": error}}
        )
    else:
        await session.complete_response(req["id"], {"ok": True, "result": result})
    return req


class TestSessionTools:
    @pytest.mark.asyncio
    async def test_list_sessions_empty(self, env):
        tool = env[2]["list_sessions"]
        assert await run_tool(tool, {}, ctx_for(env)) == {"sessions": []}

    @pytest.mark.asyncio
    async def test_list_sessions_fields(self, env):
        registry, _, _ = env
        add_gdb_session(registry)
        script = registry.reserve("s-script", kind="script", log_file="x.log")
        script.state = RUNNING
        result = await run_tool(env[2]["list_sessions"], {}, ctx_for(env))
        assert len(result["sessions"]) == 2
        gdb_info = [s for s in result["sessions"] if s["kind"] == "gdb"][0]
        assert gdb_info["arch"] == "x86_64"
        assert gdb_info["pwndbg"] is True

    @pytest.mark.asyncio
    async def test_session_status(self, env):
        registry, _, _ = env
        s = add_gdb_session(registry)
        result = await run_tool(
            env[2]["session_status"], {"session_id": s.session_id}, ctx_for(env)
        )
        assert result["state"] == "connecting"
        assert "uptime_sec" in result

    @pytest.mark.asyncio
    async def test_quit_gdb_sends_quit_message(self, env):
        registry, _, _ = env
        s = add_gdb_session(registry)
        result = await run_tool(
            env[2]["quit_gdb"], {"session_id": s.session_id}, ctx_for(env)
        )
        assert result["detached"] is True
        assert result["kill_gdb"] is False
        line = json.loads(s.writer.sent[0].decode("utf-8"))
        assert line["type"] == "quit"
        assert line["kill_gdb"] is False

    @pytest.mark.asyncio
    async def test_get_process_output(self, env, tmp_path):
        registry, _, _ = env
        log = tmp_path / "out.log"
        log.write_text("line1\nline2\nline3\n")
        s = registry.reserve("s-script", kind="script", log_file=str(log))
        s.state = RUNNING
        result = await run_tool(
            env[2]["get_process_output"],
            {"tail_lines": 2, "session_id": "s-script"},
            ctx_for(env),
        )
        assert result["output"] == "line2\nline3\n"

    @pytest.mark.asyncio
    async def test_reserved_gdb_is_not_reported_as_running(self, env, tmp_path):
        registry, _, _ = env
        log = tmp_path / "out.log"
        log.write_text("pending\n")
        registry.reserve("s-pending", log_file=str(log), launched=False)

        result = await run_tool(
            env[2]["get_process_output"],
            {"session_id": "s-pending"},
            ctx_for(env),
        )

        assert result["running"] is False

    @pytest.mark.asyncio
    async def test_get_process_output_no_log(self, env):
        registry, _, _ = env
        add_gdb_session(registry)
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(env[2]["get_process_output"], {}, ctx_for(env))
        assert ei.value.code == "NO_LOG"


class TestLaunchTools:
    @pytest.mark.asyncio
    async def test_launch_script_reports_completed_pure_script(
        self, env, monkeypatch, tmp_path
    ):
        registry, _, tools = env
        log = tmp_path / "pure.log"
        log.write_text("done\n")

        async def fake_launch_script(self, **kwargs):
            script = registry.reserve(
                "s-pure", kind="script", log_file=str(log)
            )
            script.state = EXITED
            script.proc_returncode = 0
            return script, None

        monkeypatch.setattr(
            "gdb_mcp.tools.launch_tools.Launcher.launch_script", fake_launch_script
        )
        result = await run_tool(
            tools["launch_script"],
            {"script": r"C:\work\pure.py"},
            ctx_for(env),
        )

        assert result["script_state"] == EXITED
        assert result["script_returncode"] == 0
        assert result["gdb_session_id"] is None
        assert "script exited (code 0)" in result["note"]
        assert "done" in result["note"]

    @pytest.mark.asyncio
    async def test_non_force_gdb_kill_only_detaches(self, env, monkeypatch):
        registry, _, tools = env
        registry.reserve("s-launched")
        session = registry.register_hello(
            hello(session_id="s-launched"), FakeWriter()
        )
        pkill_calls = []

        async def fake_pkill(self, session_id, force, distro=None):
            pkill_calls.append((session_id, force, distro))

        monkeypatch.setattr(
            "gdb_mcp.tools.launch_tools.Launcher.pkill_marker", fake_pkill
        )
        task = asyncio.create_task(
            run_tool(
                tools["kill_session"],
                {"session_id": session.session_id, "force": False},
                ctx_for(env),
            )
        )
        quit_message = await next_request(session, session.writer)
        assert quit_message["type"] == "quit"
        assert quit_message["kill_gdb"] is False
        await session.on_disconnect()
        result = await task
        assert result["detached"] is True
        assert result["killed"] is False
        assert pkill_calls == []


class TestExecTools:
    @pytest.mark.asyncio
    async def test_execute_command(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["execute_command"],
                {"command": "vmmap", "session_id": s.session_id},
                ctx_for(env),
            )
        )
        req = await respond_to(s, s.writer, {"output": "mapped", "truncated": False})
        assert req["verb"] == "eval"
        assert req["params"]["command"] == "vmmap"
        assert await task == {"output": "mapped", "truncated": False}

    @pytest.mark.asyncio
    async def test_execute_command_error_propagates(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["execute_command"],
                {"command": "nope", "session_id": s.session_id},
                ctx_for(env),
            )
        )
        await respond_to(s, s.writer, error="PLUGIN_ERROR")
        with pytest.raises(GdbMcpError) as ei:
            await task
        assert ei.value.code == "PLUGIN_ERROR"

    @pytest.mark.asyncio
    async def test_execute_command_pagination_params(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["execute_command"],
                {
                    "command": "heap",
                    "offset": 40,
                    "limit": 20,
                    "session_id": s.session_id,
                },
                ctx_for(env),
            )
        )
        req = await respond_to(
            s,
            s.writer,
            {"output": "chunk", "truncated": True, "total_lines": 100, "offset": 40},
        )
        assert req["verb"] == "eval"
        assert req["params"]["offset"] == 40
        assert req["params"]["limit"] == 20
        result = await task
        assert result["total_lines"] == 100
        assert result["truncated"] is True

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "kwargs",
        [{"offset": -1}, {"offset": 1.5}, {"limit": 0}, {"limit": True}],
    )
    async def test_execute_command_bad_window(self, env, kwargs):
        _, _, tools = env
        with pytest.raises(ValueError):
            await run_tool(
                tools["execute_command"],
                {"command": "vmmap", **kwargs},
                ctx_for(env),
            )

    @pytest.mark.asyncio
    async def test_continue_sets_running(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["continue_execution"],
                {"session_id": s.session_id},
                ctx_for(env),
            )
        )
        req = await respond_to(s, s.writer, {"state": "running"})
        assert req["verb"] == "continue"
        assert await task == {"state": "running"}
        assert s.state == RUNNING

    @pytest.mark.asyncio
    async def test_continue_rejected_while_running(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        s.state = RUNNING
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(
                tools["continue_execution"],
                {"session_id": s.session_id},
                ctx_for(env),
            )
        assert ei.value.code == "INFERIOR_RUNNING"
        assert s.writer.sent == []  # no request sent

    @pytest.mark.asyncio
    async def test_continue_invalid_mode(self, env):
        registry, _, tools = env
        add_gdb_session(registry)
        with pytest.raises(ValueError):
            await run_tool(
                tools["continue_execution"], {"mode": "teleport"}, ctx_for(env)
            )

    @pytest.mark.asyncio
    async def test_interrupt_while_stopped_is_noop(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        result = await run_tool(
            tools["interrupt"], {"session_id": s.session_id}, ctx_for(env)
        )
        assert result["state"] == "not_running"
        assert s.writer.sent == []

    @pytest.mark.asyncio
    async def test_interrupt_while_running(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        s.state = RUNNING
        task = asyncio.create_task(
            run_tool(
                tools["interrupt"], {"session_id": s.session_id}, ctx_for(env)
            )
        )
        req = await respond_to(s, s.writer, {"state": "interrupt_requested"})
        assert req["verb"] == "interrupt"
        assert await task == {"state": "interrupt_requested"}

    @pytest.mark.asyncio
    async def test_wait_for_stop_immediate_when_stopped(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        result = await run_tool(
            tools["wait_for_stop"], {"session_id": s.session_id}, ctx_for(env)
        )
        assert result["stopped"] is True

    @pytest.mark.asyncio
    async def test_wait_for_stop_wakes_on_notification(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        s.state = RUNNING
        task = asyncio.create_task(
            run_tool(
                tools["wait_for_stop"],
                {"timeout_ms": 5000, "session_id": s.session_id},
                ctx_for(env),
            )
        )
        await asyncio.sleep(0)
        await s.push_notification("stop", {"signal": "SIGSEGV"})
        result = await task
        assert result["stopped"] is True
        assert result["stop_info"]["signal"] == "SIGSEGV"

    @pytest.mark.asyncio
    async def test_get_stop_reason(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        await s.push_notification("stop", {"signal": "SIGTRAP"})
        result = await run_tool(
            tools["get_stop_reason"], {"session_id": s.session_id}, ctx_for(env)
        )
        assert result["stop_info"]["signal"] == "SIGTRAP"


class TestStateTools:
    @pytest.mark.asyncio
    async def test_read_memory_validation(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        with pytest.raises(ValueError):
            await run_tool(
                tools["read_memory"],
                {"address": 0x1000, "length": 0, "session_id": s.session_id},
                ctx_for(env),
            )
        with pytest.raises(ValueError):
            await run_tool(
                tools["read_memory"],
                {"address": 0x1000, "length": 999999, "session_id": s.session_id},
                ctx_for(env),
            )
        assert s.writer.sent == []

    @pytest.mark.asyncio
    async def test_read_memory_roundtrip(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["read_memory"],
                {"address": "main", "length": 16, "session_id": s.session_id},
                ctx_for(env),
            )
        )
        req = await respond_to(
            s, s.writer, {"addr": 0x401000, "hex": "4142", "ascii": "AB", "unreadable": [], "partial": False}
        )
        assert req["verb"] == "read_mem"
        assert req["params"] == {"addr": "main", "length": 16}
        assert (await task)["hex"] == "4142"

    @pytest.mark.asyncio
    async def test_write_memory_bad_hex_rejected_locally(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(
                tools["write_memory"],
                {"address": 0x1000, "hex": "zz", "session_id": s.session_id},
                ctx_for(env),
            )
        assert ei.value.code == "BAD_PARAMS"
        assert s.writer.sent == []

    @pytest.mark.asyncio
    async def test_evaluate_and_disassemble(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["evaluate"],
                {"expression": "&puts@got", "session_id": s.session_id},
                ctx_for(env),
            )
        )
        await respond_to(
            s, s.writer, {"expression": "&puts@got", "type": "long", "value": "1", "address": "0x404000"}
        )
        assert (await task)["address"] == "0x404000"

    @pytest.mark.asyncio
    async def test_state_tools_rejected_while_running(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        s.state = RUNNING
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(
                tools["get_backtrace"], {"session_id": s.session_id}, ctx_for(env)
            )
        assert ei.value.code == "INFERIOR_RUNNING"


class TestBreakpointTools:
    @pytest.mark.asyncio
    async def test_set_breakpoint(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["set_breakpoint"],
                {"location": "main", "type": "hw", "condition": "i>5", "session_id": s.session_id},
                ctx_for(env),
            )
        )
        req = await respond_to(s, s.writer, {"number": 1, "type": "hw", "enabled": True})
        assert req["verb"] == "break"
        assert req["params"]["condition"] == "i>5"
        assert (await task)["number"] == 1

    @pytest.mark.asyncio
    async def test_set_breakpoint_bad_type(self, env):
        registry, _, tools = env
        add_gdb_session(registry)
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(
                tools["set_breakpoint"], {"location": "x", "type": "magic"}, ctx_for(env)
            )
        assert ei.value.code == "BAD_PARAMS"

    @pytest.mark.asyncio
    async def test_manage_breakpoint(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["manage_breakpoint"],
                {"number": 3, "action": "delete", "session_id": s.session_id},
                ctx_for(env),
            )
        )
        req = await respond_to(s, s.writer, {"number": 3, "deleted": True})
        assert req["verb"] == "bp_delete"
        assert await task == {"number": 3, "deleted": True}


CRASH_SCRIPT = [
    ("backtrace", {"frames": [{"level": 0, "pc": "0x401000", "function": "vuln"}]}),
    ("regs", {"regs": {"rax": "0x1", "rsp": "0x7fffffffe000", "rip": "0x401000"}}),
    ("disasm", {"start": "0x400ff0", "instructions": [{"addr": "0x400ff0", "size": 4, "asm": "nop"}]}),
    ("read_mem", {"addr": 0x401000, "hex": "90", "ascii": ".", "unreadable": [], "partial": False}),
    ("read_mem", {"addr": 0x7FFFFFFFE000, "hex": "41", "ascii": "A", "unreadable": [], "partial": False}),
    ("read_mem", {"addr": 0x41414141, "hex": "42", "ascii": "B", "unreadable": [], "partial": False}),
    (
        "mem_map",
        {
            "output": (
                "          Start Addr           End Addr       Size     Offset  Perms  objfile\n"
                "          0x555555554000     0x555555555000     0x1000        0x0"
                "  r--p   /usr/bin/vuln\n"
                "          0x7ffff7dd0000     0x7ffff7dfd000    0x2d000        0x0"
                "  r--p   /usr/lib/x86_64-linux-gnu/libc.so.6\n"
            ),
            "truncated": False,
            "total_lines": 3,
        },
    ),
]


class TestCrashReport:
    @pytest.mark.asyncio
    async def test_full_report(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        await s.push_notification(
            "stop",
            {
                "signal": "SIGSEGV",
                "fault_addr": "0x41414141",
                "pc": "0x401000",
                "thread": "1",
            },
        )
        task = asyncio.create_task(
            run_tool(
                tools["crash_report"], {"session_id": s.session_id}, ctx_for(env)
            )
        )
        for verb, result in CRASH_SCRIPT:
            req = await respond_to(s, s.writer, result)
            assert req["verb"] == verb
        report = await task
        assert report["signal"] == "SIGSEGV"
        assert report["fault_addr"] == "0x41414141"
        assert report["pc"] == "0x401000"
        assert report["registers"]["rsp"] == "0x7fffffffe000"
        assert report["backtrace"][0]["function"] == "vuln"
        assert report["disassembly"][0]["asm"] == "nop"
        assert report["memory_at_pc"]["hex"] == "90"
        assert report["memory_at_sp"]["hex"] == "41"
        assert report["memory_at_fault_addr"]["hex"] == "42"
        mmap = report["memory_map"]
        assert mmap["total_segments"] == 2
        assert mmap["segments"][0]["objfile"] == "/usr/bin/vuln"
        assert mmap["segments"][1]["size"] == 0x2D000
        assert mmap["truncated"] is False
        assert report["warnings"] == []

    @pytest.mark.asyncio
    async def test_partial_failures_reported_as_warnings(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        await s.push_notification("stop", {"signal": "SIGSEGV", "pc": "0x401000"})
        task = asyncio.create_task(
            run_tool(
                tools["crash_report"], {"session_id": s.session_id}, ctx_for(env)
            )
        )
        # regs fails -> no rsp -> no memory_at_sp; mem_map fails too
        await respond_to(s, s.writer, CRASH_SCRIPT[0][1])  # backtrace
        await respond_to(s, s.writer, error="NO_INFERIOR")  # regs fails
        await respond_to(s, s.writer, CRASH_SCRIPT[2][1])  # disasm
        await respond_to(s, s.writer, CRASH_SCRIPT[3][1])  # read pc
        await respond_to(s, s.writer, error="PLUGIN_ERROR")  # mem_map fails
        report = await task
        assert report["registers"] == {}
        assert "memory_at_sp" not in report
        assert "memory_map" not in report
        assert any("regs:" in w for w in report["warnings"])
        assert any("mem_map:" in w for w in report["warnings"])

    @pytest.mark.asyncio
    async def test_rejected_while_running(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        s.state = RUNNING
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(
                tools["crash_report"], {"session_id": s.session_id}, ctx_for(env)
            )
        assert ei.value.code == "INFERIOR_RUNNING"


class TestSessionResolution:
    @pytest.mark.asyncio
    async def test_ambiguous_session_error(self, env):
        registry, _, tools = env
        s1 = add_gdb_session(registry)
        s2 = add_gdb_session(registry, pid=9999)
        assert s1.session_id != s2.session_id
        assert len(registry.list_live()) == 2
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(tools["get_backtrace"], {}, ctx_for(env))
        assert ei.value.code == "AMBIGUOUS_SESSION"

    @pytest.mark.asyncio
    async def test_no_session_error(self, env):
        _, _, tools = env
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(tools["get_backtrace"], {}, ctx_for(env))
        assert ei.value.code == "NO_SESSION"

    @pytest.mark.asyncio
    async def test_autoselect_single(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(tools["list_breakpoints"], {}, ctx_for(env))
        )
        req = await respond_to(s, s.writer, {"breakpoints": []})
        assert req["verb"] == "breakpoints"
        assert await task == {"breakpoints": []}


CONTEXT_SCRIPT = [
    (
        "regs",
        {
            "regs": {
                "rax": "0x1",
                "rsp": "0x7fffffffe000",
                "rip": "0x401000",
                "xmm0": "0x0",
            }
        },
    ),
    (
        "backtrace",
        {
            "frames": [{"level": 0, "pc": "0x401000", "function": "vuln"}],
            "truncated": False,
        },
    ),
    (
        "disasm",
        {
            "start": "0x400ff0",
            "instructions": [{"addr": "0x400ff0", "size": 4, "asm": "nop"}],
            "truncated": False,
        },
    ),
]


class TestStopContext:
    @pytest.mark.asyncio
    async def test_wait_for_stop_with_context(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        await s.push_notification("stop", {"signal": "SIGSEGV", "pc": "0x401000"})
        task = asyncio.create_task(
            run_tool(
                tools["wait_for_stop"],
                {"with_context": True, "session_id": s.session_id},
                ctx_for(env),
            )
        )
        for verb, result in CONTEXT_SCRIPT:
            req = await respond_to(s, s.writer, result)
            assert req["verb"] == verb
        result = await task
        assert result["stopped"] is True
        context = result["context"]
        assert context["registers"]["rip"] == "0x401000"
        assert "xmm0" not in context["registers"]  # key-register filter
        assert context["backtrace"][0]["function"] == "vuln"
        assert context["disassembly"][0]["asm"] == "nop"
        assert context["warnings"] == []

    @pytest.mark.asyncio
    async def test_wait_for_stop_without_context(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        await s.push_notification("stop", {"pc": "0x401000"})
        result = await run_tool(
            tools["wait_for_stop"], {"session_id": s.session_id}, ctx_for(env)
        )
        assert result["stopped"] is True
        assert "context" not in result

    @pytest.mark.asyncio
    async def test_continue_wait_with_context(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["continue_execution"],
                {"wait": True, "with_context": True, "session_id": s.session_id},
                ctx_for(env),
            )
        )
        req = await respond_to(s, s.writer, {"state": "running"})
        assert req["verb"] == "continue"
        # the inferior stops while the tool call is waiting
        await s.push_notification("stop", {"signal": "SIGSEGV", "pc": "0x401000"})
        for _, result in CONTEXT_SCRIPT:
            await respond_to(s, s.writer, result)
        result = await task
        assert result["resumed"] is True
        assert result["stopped"] is True
        assert result["stop_info"]["pc"] == "0x401000"
        assert result["context"]["registers"]["rip"] == "0x401000"

    @pytest.mark.asyncio
    async def test_continue_wait_timeout_has_no_context(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["continue_execution"],
                {"wait": True, "timeout_ms": 100, "session_id": s.session_id},
                ctx_for(env),
            )
        )
        await respond_to(s, s.writer, {"state": "running"})
        result = await task
        assert result["stopped"] is False
        assert result["state"] == RUNNING
        assert "context" not in result

    @pytest.mark.asyncio
    async def test_continue_wait_rejects_tiny_timeout(self, env):
        _, _, tools = env
        add_gdb_session(env[0])
        with pytest.raises(ValueError):
            await run_tool(
                tools["continue_execution"],
                {"wait": True, "timeout_ms": 1},
                ctx_for(env),
            )


class TestGetEvents:
    def test_events_recorded_and_ordered(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)  # hello records a "connected" event
        s.record_event("stop", {"pc": "0x401000"})
        s.record_event("running", {})
        result = asyncio.run(
            run_tool(
                tools["get_events"],
                {"last": 2, "session_id": s.session_id},
                ctx_for(env),
            )
        )
        assert [e["event"] for e in result["events"]] == ["stop", "running"]
        seqs = [e["seq"] for e in result["events"]]
        assert seqs[1] > seqs[0]
        assert result["total_recorded"] == 3

    def test_get_events_validates_last(self, env):
        _, _, tools = env
        add_gdb_session(env[0])
        for bad in (0, -1, True, 101):
            with pytest.raises(ValueError):
                asyncio.run(
                    run_tool(tools["get_events"], {"last": bad}, ctx_for(env))
                )


class TestResultStore:
    @pytest.mark.asyncio
    async def test_large_output_stored_and_read_back(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        big = "\n".join("line-%04d" % i for i in range(50))  # > inline limit
        task = asyncio.create_task(
            run_tool(
                tools["execute_command"],
                {"command": "heap", "session_id": s.session_id},
                ctx_for(env),
            )
        )
        await respond_to(
            s, s.writer, {"output": big, "total_lines": 50, "truncated": False}
        )
        result = await task
        assert result["truncated"] is True
        assert result["result_file"]
        assert len(result["output"]) < len(big)
        assert result["output"].startswith("line-0000")
        tail = await run_tool(
            tools["read_result"],
            {"path": result["result_file"], "offset": 45},
            ctx_for(env),
        )
        assert tail["total_lines"] == 50
        assert tail["output"].splitlines()[0] == "line-0045"
        assert tail["truncated"] is False
        assert tail["sha256"] == result["result_sha256"]

    @pytest.mark.asyncio
    async def test_small_output_not_stored(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["execute_command"],
                {"command": "vmmap", "session_id": s.session_id},
                ctx_for(env),
            )
        )
        await respond_to(
            s, s.writer, {"output": "short", "total_lines": 1, "truncated": False}
        )
        result = await task
        assert "result_file" not in result
        assert result["output"] == "short"

    @pytest.mark.asyncio
    async def test_read_result_rejects_paths_outside_store(self, env):
        _, _, tools = env
        for bad in ("C:/Windows/win.ini", "relative.txt", "logs/../etc/passwd"):
            with pytest.raises(GdbMcpError) as ei:
                await run_tool(
                    tools["read_result"], {"path": bad}, ctx_for(env)
                )
            assert ei.value.code == "BAD_PARAMS"

    def test_prune_results_bounds_directory(self, tmp_path):
        import os

        from gdb_mcp.results import prune_results, results_dir, store_result

        for i in range(5):
            store_result(tmp_path, "content-%d" % i)
        directory = results_dir(tmp_path)
        files = sorted(directory.iterdir(), key=lambda p: p.name)
        for i, p in enumerate(files):  # deterministic mtimes
            os.utime(p, (i + 1, i + 1))
        removed = prune_results(tmp_path, max_files=2)
        assert removed == 3
        remaining = {p.name for p in directory.iterdir()}
        assert len(remaining) == 2
        # the two newest (highest mtime) survive
        survivors = {files[-1].name, files[-2].name}
        assert remaining == survivors


class TestToolProfile:
    def test_core_profile_registers_subset(self, tmp_path):
        cfg = Config(log_dir=tmp_path / "l", tool_profile="core")
        app = build_app(cfg, SessionRegistry(cfg))
        names = set(app._tool_manager._tools)
        assert names == CORE_TOOLS
        assert "write_memory" not in names
        assert "execute_command" in names

    def test_full_profile_registers_everything(self, tmp_path):
        cfg = Config(log_dir=tmp_path / "l")
        app = build_app(cfg, SessionRegistry(cfg))
        names = set(app._tool_manager._tools)
        assert "write_memory" in names
        assert "kill_session" in names
        assert len(names) > len(CORE_TOOLS)


class TestMemoryMap:
    @pytest.mark.asyncio
    async def test_get_memory_map_structured(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["get_memory_map"], {"session_id": s.session_id}, ctx_for(env)
            )
        )
        req = await respond_to(
            s,
            s.writer,
            {
                "output": (
                    "          Start Addr           End Addr       Size"
                    "     Offset  Perms  objfile\n"
                    "          0x555555554000     0x555555555000     0x1000"
                    "        0x0  r--p   /usr/bin/vuln\n"
                    "          0x7ffff7dd0000     0x7ffff7dfd000    0x2d000"
                    "        0x0  r--p   /lib/x86_64-linux-gnu/libc.so.6\n"
                ),
                "total_lines": 3,
                "truncated": False,
            },
        )
        assert req["verb"] == "mem_map"
        result = await task
        assert result["count"] == 2
        assert result["segments"][0] == {
            "start": "0x555555554000",
            "end": "0x555555555000",
            "size": 0x1000,
            "offset": "0x0",
            "perms": "r--p",
            "objfile": "/usr/bin/vuln",
        }
        assert result["truncated"] is False


BINS_TEXT = (
    "tcachebins\n"
    "0x20 [  2]: 0x5555555592a0 —▸ 0x5555555592c0 ◂— 0x0\n"
    "fastbins\n"
    "empty\n"
    "small bins\n"
    "empty\n"
    "large bins\n"
    "empty\n"
    "unsorted bins\n"
    "empty\n"
)


class TestHeapBins:
    @pytest.mark.asyncio
    async def test_structured_bins(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)  # hello advertises pwndbg
        task = asyncio.create_task(
            run_tool(
                tools["heap_bins"], {"session_id": s.session_id}, ctx_for(env)
            )
        )
        req = await respond_to(
            s,
            s.writer,
            {"output": BINS_TEXT, "total_lines": 10, "truncated": False},
        )
        assert req["verb"] == "eval"
        assert req["params"]["command"] == "bins"
        result = await task
        assert result["parsed"] is True
        assert result["tcachebins"]["0x20"] == ["0x5555555592a0", "0x5555555592c0"]
        assert result["truncated"] is False
        assert "output" not in result

    @pytest.mark.asyncio
    async def test_unparsed_output_includes_raw(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["heap_bins"],
                {"session_id": s.session_id, "include_raw": False},
                ctx_for(env),
            )
        )
        await respond_to(
            s, s.writer, {"output": "gef➤ no idea", "total_lines": 1, "truncated": False}
        )
        result = await task
        assert result["parsed"] is False
        assert "no idea" in result["output"]

    @pytest.mark.asyncio
    async def test_requires_pwndbg(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        s.hello = {"pwndbg": False}
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(
                tools["heap_bins"], {"session_id": s.session_id}, ctx_for(env)
            )
        assert ei.value.code == "NO_PWNDBG"


class TestCheckpoint:
    @pytest.mark.asyncio
    async def test_create_flow(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["checkpoint"],
                {"action": "create", "session_id": s.session_id},
                ctx_for(env),
            )
        )
        # regs/mem_map sub-requests happen inside the plugin; only one
        # wire request leaves the server
        req = await respond_to(
            s,
            s.writer,
            {
                "snapshot_id": "ck-1",
                "registers": 4,
                "segments": [{"addr": "0x1000", "length": 0x2000}],
                "skipped": [],
                "total_bytes": 0x2000,
            },
        )
        assert req["verb"] == "snapshot_create"
        result = await task
        assert result["snapshot_id"] == "ck-1"
        assert result["segments"] == [{"addr": "0x1000", "length": 0x2000}]

    @pytest.mark.asyncio
    async def test_restore_requires_snapshot_id(self, env):
        _, _, tools = env
        add_gdb_session(env[0])
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(
                tools["checkpoint"], {"action": "restore"}, ctx_for(env)
            )
        assert ei.value.code == "BAD_PARAMS"

    @pytest.mark.asyncio
    async def test_invalid_action(self, env):
        _, _, tools = env
        add_gdb_session(env[0])
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(
                tools["checkpoint"], {"action": "teleport"}, ctx_for(env)
            )
        assert ei.value.code == "BAD_PARAMS"

    @pytest.mark.asyncio
    async def test_diff_passes_snapshot_id(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["checkpoint"],
                {
                    "action": "diff",
                    "snapshot_id": "ck-3",
                    "session_id": s.session_id,
                },
                ctx_for(env),
            )
        )
        req = await respond_to(s, s.writer, {"memory_changes": []})
        assert req["verb"] == "snapshot_diff"
        assert req["params"]["snapshot_id"] == "ck-3"
        assert await task == {"memory_changes": []}


class TestBatchCommands:
    @pytest.mark.asyncio
    async def test_batches_eval_requests(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["batch_commands"],
                {"commands": ["aaa", "bbb", "ccc"], "session_id": s.session_id},
                ctx_for(env),
            )
        )
        for cmd in ("aaa", "bbb", "ccc"):
            req = await respond_to(
                s,
                s.writer,
                {"output": "out-" + cmd, "total_lines": 1, "truncated": False},
            )
            assert req["verb"] == "eval"
            assert req["params"]["command"] == cmd
        result = await task
        assert result["executed"] == 3
        assert result["completed"] is True
        assert [r["ok"] for r in result["results"]] == [True, True, True]

    @pytest.mark.asyncio
    async def test_stops_on_first_error(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["batch_commands"],
                {"commands": ["good", "bad", "never"], "session_id": s.session_id},
                ctx_for(env),
            )
        )
        await respond_to(
            s, s.writer, {"output": "ok", "total_lines": 1, "truncated": False}
        )
        req = await respond_to(s, s.writer, error="PLUGIN_ERROR")
        assert req["params"]["command"] == "bad"
        result = await task
        assert result["executed"] == 2
        assert result["completed"] is False
        assert result["results"][-1]["ok"] is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad", [[], "x", [""], ["ok", 1], list(range(33))])
    async def test_validates_input(self, env, bad):
        _, _, tools = env
        add_gdb_session(env[0])
        with pytest.raises(ValueError):
            await run_tool(
                tools["batch_commands"], {"commands": bad}, ctx_for(env)
            )


class TestBreakpointCommands:
    @pytest.mark.asyncio
    async def test_forwards_commands_and_auto_continue(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["set_breakpoint"],
                {
                    "location": "main",
                    "commands": ["x/1gx $rdi"],
                    "auto_continue": True,
                    "session_id": s.session_id,
                },
                ctx_for(env),
            )
        )
        req = await respond_to(s, s.writer, {"number": 1, "has_commands": True})
        assert req["verb"] == "break"
        assert req["params"]["commands"] == ["x/1gx $rdi"]
        assert req["params"]["auto_continue"] is True
        assert await task == {"number": 1, "has_commands": True}


class TestUnsafeGate:
    @pytest.mark.asyncio
    async def test_execute_command_blocks_unsafe_by_default(self, env):
        registry, cfg, tools = env
        assert cfg.allow_unsafe is False
        s = add_gdb_session(registry)
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(
                tools["execute_command"],
                {"command": "shell pwd", "session_id": s.session_id},
                ctx_for(env),
            )
        assert ei.value.code == "UNSAFE_BLOCKED"
        assert s.writer.sent == []  # nothing reached the plugin

    @pytest.mark.asyncio
    async def test_execute_command_allows_normal(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["execute_command"],
                {"command": "x/4gx $rsp", "session_id": s.session_id},
                ctx_for(env),
            )
        )
        req = await respond_to(s, s.writer, {"output": "ok", "total_lines": 1})
        assert req["params"]["command"] == "x/4gx $rsp"
        assert (await task)["output"] == "ok"

    @pytest.mark.asyncio
    async def test_batch_stops_on_unsafe(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["batch_commands"],
                {"commands": ["x/1gx $sp", "shell id"], "session_id": s.session_id},
                ctx_for(env),
            )
        )
        await respond_to(s, s.writer, {"output": "ok", "total_lines": 1})
        result = await task
        assert result["executed"] == 2
        assert result["completed"] is False
        assert result["results"][-1]["ok"] is False
        # the unsafe second command never reached the plugin (respond_to
        # already consumed the only request line)
        assert len(s.writer.sent) == 0

    def test_readonly_drops_write_tools(self, tmp_path):
        cfg = Config(log_dir=tmp_path / "l", readonly=True)
        app = build_app(cfg, SessionRegistry(cfg))
        names = set(app._tool_manager._tools)
        assert "write_memory" not in names
        assert "write_register" not in names
        assert "read_memory" in names
        assert "continue_execution" in names


class TestJournal:
    @pytest.mark.asyncio
    async def test_requests_and_notifications_journaled(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        assert s.journal is not None
        task = asyncio.create_task(
            run_tool(
                tools["execute_command"],
                {"command": "checksec", "session_id": s.session_id},
                ctx_for(env),
            )
        )
        await respond_to(s, s.writer, {"output": "ok", "total_lines": 1})
        await task
        await s.push_notification("stop", {"pc": "0x401000"})
        kinds = [
            (e["kind"], e.get("verb") or e.get("event"))
            for e in s.journal.entries()
        ]
        assert kinds == [("request", "eval"), ("notification", "stop")]
        req_entry = s.journal.entries()[0]
        assert req_entry["params"]["command"] == "checksec"
        assert req_entry["ok"] is True

    @pytest.mark.asyncio
    async def test_failed_requests_journaled_with_error(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["execute_command"],
                {"command": "nope", "session_id": s.session_id},
                ctx_for(env),
            )
        )
        await respond_to(s, s.writer, error="PLUGIN_ERROR")
        with pytest.raises(GdbMcpError):
            await task
        entry = s.journal.entries()[-1]
        assert entry["ok"] is False and entry["error"] == "PLUGIN_ERROR"


class TestExportSessionScript:
    @pytest.mark.asyncio
    async def test_exports_compiled_script(self, env):
        registry, cfg, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(
                tools["set_breakpoint"],
                {"location": "main", "session_id": s.session_id},
                ctx_for(env),
            )
        )
        await respond_to(s, s.writer, {"number": 1, "type": "breakpoint", "enabled": True})
        await task
        result = await run_tool(
            tools["export_session_script"],
            {"session_id": s.session_id},
            ctx_for(env),
        )
        assert result["used"] == 1
        assert "break main" in result["script"]
        assert result["script"].splitlines()[-1] == "quit"
        assert (cfg.log_dir / "scripts" / ("%s.gdb" % s.session_id)).exists()

    @pytest.mark.asyncio
    async def test_empty_journal_errors(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(
                tools["export_session_script"],
                {"session_id": s.session_id},
                ctx_for(env),
            )
        assert ei.value.code == "NO_JOURNAL"
