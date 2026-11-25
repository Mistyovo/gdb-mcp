"""Tests for the consolidated 17-tool MCP surface (fake session transport)."""

from __future__ import annotations

import asyncio
import json
import struct

import pytest

from gdb_mcp.config import Config
from gdb_mcp.context import ServerContext
from gdb_mcp.errors import GdbMcpError
from gdb_mcp.server import build_app
from gdb_mcp.sessions import DISCONNECTED, EXITED, RUNNING, STOPPED, SessionRegistry
from gdb_mcp.tools import CORE_TOOLS, registered_tools

from test_sessions import FakeWriter, hello


class FakeRequestContext:
    def __init__(self, registry, config):
        self.lifespan_context = ServerContext(config=config, registry=registry)


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
        tool_profile="pwn",
        experimental=True,
    )
    ids = iter("s-%03d" % i for i in range(100))
    registry = SessionRegistry(cfg, session_id_factory=lambda: next(ids))
    app = build_app(cfg, registry)
    tools = registered_tools(app)
    return registry, cfg, tools


@pytest.fixture
def readonly_env(tmp_path):
    cfg = Config(readonly=True, log_dir=tmp_path / "readonly-logs")
    registry = SessionRegistry(cfg)
    return registry, cfg, registered_tools(build_app(cfg, registry))


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


class TestToolProfile:
    EXPECTED_CORE = {
        "session_info",
        "launch_gdb",
        "kill_session",
        "execute_command",
        "control_execution",
        "memory",
        "registers",
        "inspect_code",
        "breakpoint",
        "crash_report",
    }

    def test_core_set_matches_contract(self):
        assert set(CORE_TOOLS) == self.EXPECTED_CORE

    def test_every_handler_is_declared(self):
        import importlib
        import inspect

        from gdb_mcp.tools import _TOOL_MODULES
        from gdb_mcp.tools.registry import SPECS

        declared = {spec.fn for spec in SPECS}
        for name in _TOOL_MODULES:
            module = importlib.import_module("gdb_mcp.tools.%s" % name)
            for _, fn in inspect.getmembers(module, inspect.isfunction):
                if fn.__module__ != module.__name__:
                    continue
                params = inspect.signature(fn).parameters
                if "ctx" in params and "self" not in params:
                    assert fn in declared, "%s.%s is not declared" % (name, fn.__name__)

    def test_core_profile_registers_subset(self, tmp_path):
        cfg = Config(log_dir=tmp_path / "l", tool_profile="core")
        app = build_app(cfg, SessionRegistry(cfg))
        names = set(registered_tools(app))
        assert names == CORE_TOOLS
        assert "heap" not in names

    def test_default_profile_is_pwn(self, tmp_path):
        cfg = Config(log_dir=tmp_path / "l")
        app = build_app(cfg, SessionRegistry(cfg))
        names = set(registered_tools(app))
        assert cfg.tool_profile == "pwn"
        assert len(names) == 17
        assert "diff_sessions" not in names

    def test_experimental_gating(self, tmp_path):
        cfg = Config(log_dir=tmp_path / "l", experimental=True)
        names = set(registered_tools(build_app(cfg, SessionRegistry(cfg))))
        assert "diff_sessions" in names

    def test_readonly_keeps_only_observe_tools(self, tmp_path):
        cfg = Config(log_dir=tmp_path / "l", readonly=True)
        names = set(registered_tools(build_app(cfg, SessionRegistry(cfg))))
        assert {"session_info", "inspect_code", "crash_report", "heap"} <= names
        # the breakpoint tool stays registered for its read-only list action
        assert "breakpoint" in names
        assert not names & {"launch_gdb", "kill_session", "execute_command", "memory", "registers"}

    def test_readonly_registration_matches_the_declared_surface(self, tmp_path):
        from gdb_mcp.tools.registry import readonly_tool_names

        cfg = Config(log_dir=tmp_path / "l", readonly=True)
        names = set(registered_tools(build_app(cfg, SessionRegistry(cfg))))
        assert names == set(readonly_tool_names())


class TestReadonlyActions:
    @pytest.mark.asyncio
    async def test_session_observations_remain_available(self, readonly_env, tmp_path):
        registry, _, tools = readonly_env
        session = add_gdb_session(registry)
        await session.push_notification("stop", {"pc": "0x401000", "signal": "SIGTRAP"})
        log = tmp_path / "inferior.log"
        log.write_text("observed output\n", encoding="utf-8")
        session.log_file = str(log)
        ctx = ctx_for(readonly_env)

        listed = await run_tool(tools["session_info"], {"action": "list"}, ctx)
        assert listed["sessions"][0]["session_id"] == session.session_id
        args = {"session_id": session.session_id}
        status = await run_tool(tools["session_info"], {"action": "status", **args}, ctx)
        assert status["state"] == STOPPED
        assert status["uptime_sec"] >= 0
        events = await run_tool(tools["session_info"], {"action": "events", **args}, ctx)
        assert events["events"][-1]["event"] == "stop"
        output = await run_tool(tools["session_info"], {"action": "output", **args}, ctx)
        assert output["output"] == "observed output\n"
        assert session.writer.sent == []

    @pytest.mark.asyncio
    async def test_export_is_denied_without_creating_files(self, readonly_env):
        registry, cfg, tools = readonly_env
        session = add_gdb_session(registry)
        # A populated journal ensures READONLY, not NO_JOURNAL, blocks export.
        session.journal.append(
            "request", {"verb": "break", "params": {"location": "main"}, "ok": True}
        )
        before = set(cfg.log_dir.rglob("*"))
        with pytest.raises(GdbMcpError) as error:
            await run_tool(
                tools["session_info"],
                {"action": "export", "session_id": session.session_id},
                ctx_for(readonly_env),
            )
        assert error.value.code == "READONLY"
        assert set(cfg.log_dir.rglob("*")) == before
        assert not (cfg.log_dir / "scripts").exists()
        assert session.writer.sent == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("action", "params", "verb", "response"),
        [
            ("backtrace", {"max_frames": 2}, "backtrace", {"frames": [{"function": "main"}]}),
            ("disassemble", {"count": 2}, "disasm", {"instructions": [{"asm": "nop"}]}),
        ],
    )
    async def test_inspect_observations_reach_gdb(
        self, readonly_env, action, params, verb, response
    ):
        registry, _, tools = readonly_env
        session = add_gdb_session(registry)
        session.set_state(STOPPED)
        task = asyncio.create_task(
            run_tool(
                tools["inspect_code"],
                {"action": action, "session_id": session.session_id, **params},
                ctx_for(readonly_env),
            )
        )
        request = await respond_to(session, session.writer, response)
        assert request["verb"] == verb
        assert request["params"] == params
        assert await task == response

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("name", "arguments"),
        [
            ("inspect_code", {"action": "evaluate", "expression": "(int) puts(\"mutate\")"}),
            (
                "crash_report",
                {"payload_hex": "41", "buffer_addr": "0x1000", "stop_location": "main"},
            ),
        ],
    )
    async def test_mutating_actions_are_denied_before_dispatch(
        self, readonly_env, name, arguments
    ):
        registry, _, tools = readonly_env
        session = add_gdb_session(registry)
        session.set_state(STOPPED)
        with pytest.raises(GdbMcpError) as error:
            await run_tool(
                tools[name], {"session_id": session.session_id, **arguments}, ctx_for(readonly_env)
            )
        assert error.value.code == "READONLY"
        assert session.writer.sent == []

    @pytest.mark.asyncio
    async def test_breakpoint_list_is_observable_but_mutations_are_denied(
        self, readonly_env
    ):
        registry, _, tools = readonly_env
        session = add_gdb_session(registry)
        session.set_state(STOPPED)
        ctx = ctx_for(readonly_env)
        task = asyncio.create_task(
            run_tool(
                tools["breakpoint"],
                {"action": "list", "session_id": session.session_id},
                ctx,
            )
        )
        request = await respond_to(
            session,
            session.writer,
            {"breakpoints": [{"number": 1, "location": "main", "enabled": True}]},
        )
        assert request["verb"] == "breakpoints"
        assert (await task)["breakpoints"][0]["number"] == 1

        for action, extra in (
            ("set", {"location": "main"}),
            ("delete", {"number": 1}),
            ("enable", {"number": 1}),
            ("disable", {"number": 1}),
        ):
            with pytest.raises(GdbMcpError) as error:
                await run_tool(
                    tools["breakpoint"],
                    {"action": action, "session_id": session.session_id, **extra},
                    ctx,
                )
            assert error.value.code == "READONLY"
        assert session.writer.sent == []


class TestSessionInfoAndKill:
    @pytest.mark.asyncio
    async def test_list_and_status(self, env):
        registry, _, tools = env
        assert await run_tool(tools["session_info"], {"action": "list"}, ctx_for(env)) == {"sessions": []}
        s = add_gdb_session(registry)
        listed = await run_tool(tools["session_info"], {"action": "list"}, ctx_for(env))
        assert len(listed["sessions"]) == 1
        status = await run_tool(
            tools["session_info"], {"action": "status", "session_id": s.session_id}, ctx_for(env)
        )
        assert status["state"] == "connecting"
        assert "uptime_sec" in status

    @pytest.mark.asyncio
    async def test_events_and_output_and_export(self, env, tmp_path):
        registry, _, tools = env
        s = add_gdb_session(registry)
        await s.push_notification("stop", {"signal": "SIGTRAP", "pc": "0x401000"})
        ev = await run_tool(
            tools["session_info"], {"action": "events", "last": 10, "session_id": s.session_id}, ctx_for(env)
        )
        assert ev["events"][-1]["event"] == "stop"

        log = tmp_path / "out.log"
        log.write_text("line1\nline2\nline3\n")
        sc = registry.reserve("s-script", kind="script", log_file=str(log))
        sc.set_state(RUNNING)
        out = await run_tool(
            tools["session_info"], {"action": "output", "tail_lines": 2, "session_id": "s-script"}, ctx_for(env)
        )
        assert out["output"] == "line2\nline3\n"

        s.journal.append("request", {"verb": "break", "params": {"location": "main"}, "ok": True})
        exp = await run_tool(
            tools["session_info"], {"action": "export", "session_id": s.session_id}, ctx_for(env)
        )
        assert "break main" in exp["script"]

    @pytest.mark.asyncio
    async def test_kill_session_force_and_forget(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(tools["kill_session"], {"session_id": s.session_id, "force": True}, ctx_for(env))
        )
        line = await next_request(s, s.writer)
        assert line["type"] == "quit" and line["kill_gdb"] is True
        await s.on_disconnect()
        res = await task
        assert res["killed"] is True and res["record_kept"] is True
        assert res["launched"] is False
        assert res["process_termination"] == "terminate_requested_via_plugin"
        assert registry.has_session(s.session_id) and s.state == DISCONNECTED

        s2 = add_gdb_session(registry, pid=2222)
        task2 = asyncio.create_task(
            run_tool(tools["kill_session"], {"session_id": s2.session_id, "forget": True}, ctx_for(env))
        )
        await next_request(s2, s2.writer)
        await s2.on_disconnect()
        res2 = await task2
        assert res2["record_kept"] is False and not registry.has_session(s2.session_id)
        assert res2["process_termination"] == "detach_only"
        assert "keep running" in res2["termination_note"]


class TestLaunchDiagnosis:
    @pytest.mark.asyncio
    async def test_unconnected_plugin_is_reported(self, env, tmp_path):
        registry, _, tools = env
        session = registry.reserve(
            "s-wait", kind="gdb", log_file=str(tmp_path / "g.log")
        )

        class FakeLauncher:
            async def launch_gdb(self, **kwargs):
                return session

        context = ctx_for(env)
        context.request_context.lifespan_context._launcher = FakeLauncher()
        result = await run_tool(
            tools["launch_gdb"], {"program": "/tmp/hello"}, context
        )
        assert result["plugin_connected"] is False
        assert "namespace" in result["diagnosis"]
        assert result["log_file"].endswith("g.log")


class TestExecutionAndIO:
    @pytest.mark.asyncio
    async def test_execute_command_and_spill_readback(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        big = "line\n" * 40
        task = asyncio.create_task(
            run_tool(tools["execute_command"], {"command": "vmmap", "session_id": s.session_id}, ctx_for(env))
        )
        req = await respond_to(s, s.writer, {"output": big, "total_lines": 40, "truncated": False})
        assert req["verb"] == "eval"
        res = await task
        assert res["truncated"] is True and res["result_file"]

        back = await run_tool(
            tools["execute_command"],
            {"result_file": res["result_file"], "offset": 0, "limit": 2},
            ctx_for(env),
        )
        assert back["output"] == "line\nline"

    @pytest.mark.asyncio
    async def test_unsafe_command_blocked(self, env):
        registry, _, tools = env
        add_gdb_session(registry)
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(tools["execute_command"], {"command": "shell id"}, ctx_for(env))
        assert ei.value.code == "UNSAFE_BLOCKED"

    @pytest.mark.asyncio
    async def test_control_execution_wait_and_interrupt(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        s.set_state(RUNNING)
        task = asyncio.create_task(
            run_tool(tools["control_execution"], {"action": "interrupt", "session_id": s.session_id}, ctx_for(env))
        )
        req = await respond_to(s, s.writer, {"state": "interrupt_requested"})
        assert req["verb"] == "interrupt"
        assert (await task)["state"] == "interrupt_requested"

        s.set_state(EXITED)
        with pytest.raises(GdbMcpError) as ei:
            await run_tool(tools["control_execution"], {"action": "continue", "session_id": s.session_id}, ctx_for(env))
        assert ei.value.code == "EXITED"

    @pytest.mark.asyncio
    async def test_inferior_io_send_and_read(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        task = asyncio.create_task(
            run_tool(tools["inferior_io"], {"action": "send", "text": "hi\n", "session_id": s.session_id}, ctx_for(env))
        )
        await respond_to(s, s.writer, error="io not set up")
        await respond_to(s, s.writer, {"slave_path": "/dev/pts/9"})
        await respond_to(s, s.writer, {"sent": 3})
        res = await task
        assert res["sent"] == 3 and res["io_setup"]["slave_path"] == "/dev/pts/9"

        task2 = asyncio.create_task(
            run_tool(tools["inferior_io"], {"action": "read", "since_seq": 2, "session_id": s.session_id}, ctx_for(env))
        )
        req = await respond_to(s, s.writer, {"chunks": [], "last_seq": 2})
        assert req["verb"] == "io_read" and req["params"]["since_seq"] == 2
        assert (await task2)["last_seq"] == 2


class TestStateAndBreakpoints:
    @pytest.mark.asyncio
    async def test_memory_read_write_map(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        t1 = asyncio.create_task(
            run_tool(tools["memory"], {"action": "read", "address": "0x401000", "length": 4, "session_id": s.session_id}, ctx_for(env))
        )
        req = await respond_to(s, s.writer, {"addr": 0x401000, "hex": "90909090"})
        assert req["verb"] == "read_mem"
        assert (await t1)["hex"] == "90909090"

        t2 = asyncio.create_task(
            run_tool(tools["memory"], {"action": "write", "address": "0x401000", "hex": "9090", "session_id": s.session_id}, ctx_for(env))
        )
        req2 = await respond_to(s, s.writer, {"addr": 0x401000, "bytes_written": 2})
        assert req2["verb"] == "write_mem"
        assert (await t2)["bytes_written"] == 2

        t3 = asyncio.create_task(
            run_tool(tools["memory"], {"action": "map", "session_id": s.session_id}, ctx_for(env))
        )
        await respond_to(s, s.writer, {"output": "0x400000 0x401000 0x1000 0x0 r-xp /bin/a\n", "truncated": False})
        m = await t3
        assert m["count"] == 1 and m["segments"][0]["objfile"] == "/bin/a"

    @pytest.mark.asyncio
    async def test_registers_and_inspect_code_and_threads(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        t1 = asyncio.create_task(
            run_tool(tools["registers"], {"action": "read", "names": ["rip"], "session_id": s.session_id}, ctx_for(env))
        )
        await respond_to(s, s.writer, {"regs": {"rip": "0x401000"}})
        assert (await t1)["regs"]["rip"] == "0x401000"

        t2 = asyncio.create_task(
            run_tool(tools["inspect_code"], {"action": "evaluate", "expression": "&main", "session_id": s.session_id}, ctx_for(env))
        )
        await respond_to(s, s.writer, {"address": "0x401100", "value": "0x401100"})
        assert (await t2)["address"] == "0x401100"

        t3 = asyncio.create_task(
            run_tool(tools["thread_frame"], {"action": "select_thread", "number": 2, "session_id": s.session_id}, ctx_for(env))
        )
        req = await respond_to(s, s.writer, {"number": 2, "selected": True, "frame": {"level": 0}})
        assert req["verb"] == "thread_select"
        assert (await t3)["number"] == 2

    @pytest.mark.asyncio
    async def test_breakpoint_set_list_manage_and_unsafe_gate(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        t1 = asyncio.create_task(
            run_tool(tools["breakpoint"], {"action": "set", "location": "main", "session_id": s.session_id}, ctx_for(env))
        )
        req = await respond_to(s, s.writer, {"number": 1, "enabled": True})
        assert req["verb"] == "break" and (await t1)["number"] == 1

        t2 = asyncio.create_task(
            run_tool(tools["breakpoint"], {"action": "delete", "number": 1, "session_id": s.session_id}, ctx_for(env))
        )
        req2 = await respond_to(s, s.writer, {"number": 1, "deleted": True})
        assert req2["verb"] == "bp_delete" and (await t2)["deleted"] is True

        with pytest.raises(GdbMcpError) as ei:
            await run_tool(
                tools["breakpoint"],
                {"action": "set", "location": "main", "commands": ["shell id"], "session_id": s.session_id},
                ctx_for(env),
            )
        assert ei.value.code == "UNSAFE_BLOCKED"


class TestHeapAndPwnTools:
    @pytest.mark.asyncio
    async def test_heap_bins_and_chunk(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        bins_txt = "tcachebins\n0x20 [ 1]: 0x5555555592a0 ◂— 0x0\n"
        t1 = asyncio.create_task(
            run_tool(tools["heap"], {"action": "bins", "session_id": s.session_id}, ctx_for(env))
        )
        await respond_to(s, s.writer, {"output": bins_txt, "truncated": False})
        r1 = await t1
        assert r1["parsed"] is True and r1["tcachebins"]["0x20"] == ["0x5555555592a0"]

        addr = 0x555555559290
        hdr = struct.pack("<QQQQ", 0, 0x31, 0x5555555592C0, 0x5555AAAA1234)
        t2 = asyncio.create_task(
            run_tool(tools["heap"], {"action": "chunk", "address": "0x%x" % addr, "data_length": 0, "session_id": s.session_id}, ctx_for(env))
        )
        await respond_to(s, s.writer, {"addr": addr, "length": 32, "hex": hdr.hex()})
        await respond_to(s, s.writer, {"addr": addr + 0x30, "length": 8, "hex": struct.pack("<Q", 0x20).hex()})
        r2 = await t2
        assert r2["in_use"] is False and r2["tcache"]["suspected"] is True

    @pytest.mark.asyncio
    async def test_campaign_protections_and_verify_pc(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        t1 = asyncio.create_task(
            run_tool(tools["campaign"], {"action": "protections", "session_id": s.session_id}, ctx_for(env))
        )
        await respond_to(s, s.writer, {"output": "RELRO: Full RELRO\nPIE: PIE enabled\n"})
        assert (await t1)["detected"] is True
        assert s.campaign["protections"]["pie"]["value"] == "PIE enabled"

        t2 = asyncio.create_task(
            run_tool(
                tools["run_policy"],
                {
                    "kind": "verify_pc_control",
                    "params": {"snapshot_id": "ck-1", "buffer_addr": "0x1000", "stop_location": "main", "offset": 72},
                    "session_id": s.session_id,
                },
                ctx_for(env),
            )
        )
        await respond_to(
            s, s.writer,
            {"verified": True, "target": "pc", "expected": "0x4142434445464748", "observed": "0x4142434445464748", "offset": 72, "rounds": 1},
        )
        assert (await t2)["verified"] is True
        assert s.campaign["primitives"]["pc_control"]["value"] == "verified"

    @pytest.mark.asyncio
    async def test_crash_report_basic_and_replay(self, env):
        registry, _, tools = env
        s = add_gdb_session(registry)
        stop = {"signal": "SIGSEGV", "pc": "0x401000", "fault_addr": "0x41414141"}
        await s.push_notification("stop", stop)
        t = asyncio.create_task(
            run_tool(
                tools["crash_report"],
                {
                    "session_id": s.session_id,
                    "payload_hex": "41" * 16,
                    "buffer_addr": "0x1000",
                    "stop_location": "main",
                },
                ctx_for(env),
            )
        )
        await respond_to(s, s.writer, {"survived": False, "error": None, "stop": stop})
        await respond_to(s, s.writer, {"frames": [{"level": 0, "pc": "0x401000", "function": "vuln"}]})
        await respond_to(s, s.writer, {"regs": {"rsp": "0x7fffffffe000", "rip": "0x401000"}})
        await respond_to(s, s.writer, {"instructions": [{"addr": "0x401000", "asm": "nop"}]})
        await respond_to(s, s.writer, {"addr": 0x401000, "hex": "90"})
        await respond_to(s, s.writer, {"addr": 0x7FFFFFFFE000, "hex": "41"})
        await respond_to(s, s.writer, {"addr": 0x41414141, "hex": "42"})
        await respond_to(s, s.writer, {"output": "0x400000 0x401000 0x1000 0x0 r-xp /bin/v\n", "truncated": False})
        r = await t
        assert r["reproduced"] is True and r["signal"] == "SIGSEGV" and r["evidence_file"]
