"""Tests for the MCP tool layer (fake session transport, no sockets)."""

import asyncio
import json

import pytest

from gdb_mcp.config import Config
from gdb_mcp.errors import GdbMcpError
from gdb_mcp.server import build_app
from gdb_mcp.sessions import RUNNING, SessionRegistry

from test_sessions import FakeWriter, hello


class FakeRequestContext:
    def __init__(self, registry, config):
        self.lifespan_context = {"registry": registry, "config": config}


class FakeContext:
    def __init__(self, registry, config):
        self.request_context = FakeRequestContext(registry, config)


@pytest.fixture
def env():
    cfg = Config(request_timeout=5.0, max_mem_read=1024)
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
    async def test_get_process_output_no_log(self, env):
        registry, _, _ = env
        add_gdb_session(registry)
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(env[2]["get_process_output"], {}, ctx_for(env))
        assert ei.value.code == "NO_LOG"


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
    ("mem_map", {"output": "m1\nm2\n", "truncated": False}),
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
        assert report["memory_map_head"] == ["m1", "m2"]
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
        assert "memory_map_head" not in report
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
