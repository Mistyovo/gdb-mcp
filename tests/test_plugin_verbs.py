"""Tests for the plugin's verb handlers (driven with mock_gdb)."""

import json
import queue

import mock_gdb
from mock_gdb import MockBreakpoint, set_inferior


def drain(plugin):
    out = []
    while True:
        try:
            _, line = plugin.out_q.get_nowait()
        except queue.Empty:
            return out
        msg = json.loads(line.decode("utf-8"))
        if "msg" in msg:  # token wrapper
            msg = msg["msg"]
        out.append(msg)


def call(plugin, verb, params, req_id=1):
    """Run a request through the main-thread dispatch path."""
    plugin._handle_request(
        {"type": "request", "id": req_id, "verb": verb, "params": params}
    )
    return drain(plugin)[-1]


class TestEval:
    def test_ok_strips_ansi(self, plugin):
        mock_gdb.state.output_map["vmmap"] = "\x1b[31mred\x1b[0m output"
        resp = call(plugin, "eval", {"command": "vmmap"})
        assert resp["ok"] is True
        assert resp["result"]["output"] == "red output"
        assert resp["result"]["truncated"] is False

    def test_keep_ansi(self, plugin):
        mock_gdb.state.output_map["x"] = "\x1b[31mred\x1b[0m"
        resp = call(plugin, "eval", {"command": "x", "keep_ansi": True})
        assert "\x1b[31m" in resp["result"]["output"]

    def test_truncation(self, plugin):
        mock_gdb.state.output_map["big"] = "A" * (300 * 1024)
        resp = call(plugin, "eval", {"command": "big"})
        assert resp["result"]["truncated"] is True
        assert len(resp["result"]["output"]) <= 200 * 1024 + 32

    def test_missing_command(self, plugin):
        assert call(plugin, "eval", {})["error"]["code"] == "BAD_PARAMS"

    def test_total_lines_always_reported(self, plugin):
        mock_gdb.state.output_map["vmmap"] = "a\nb\nc"
        resp = call(plugin, "eval", {"command": "vmmap"})
        r = resp["result"]
        assert r["total_lines"] == 3
        assert r["output"] == "a\nb\nc"
        assert r["truncated"] is False
        assert "offset" not in r

    def test_pagination_window(self, plugin):
        mock_gdb.state.output_map["heap"] = "l0\nl1\nl2\nl3\nl4\n"
        resp = call(plugin, "eval", {"command": "heap", "offset": 1, "limit": 2})
        r = resp["result"]
        assert r["output"] == "l1\nl2"
        assert r["total_lines"] == 5
        assert r["offset"] == 1
        assert r["truncated"] is True

    def test_pagination_tail_not_truncated(self, plugin):
        mock_gdb.state.output_map["heap"] = "l0\nl1\nl2"
        resp = call(plugin, "eval", {"command": "heap", "offset": 1})
        r = resp["result"]
        assert r["output"] == "l1\nl2"
        assert r["total_lines"] == 3
        assert r["truncated"] is False
        assert "offset" not in r

    def test_pagination_beyond_end(self, plugin):
        mock_gdb.state.output_map["heap"] = "l0\nl1"
        resp = call(plugin, "eval", {"command": "heap", "offset": 5, "limit": 2})
        r = resp["result"]
        assert r["output"] == ""
        assert r["total_lines"] == 2
        assert r["truncated"] is False

    def test_pagination_bad_offset(self, plugin):
        resp = call(plugin, "eval", {"command": "x", "offset": -1})
        assert resp["error"]["code"] == "BAD_PARAMS"

    def test_pagination_bad_limit(self, plugin):
        resp = call(plugin, "eval", {"command": "x", "limit": 0})
        assert resp["error"]["code"] == "BAD_PARAMS"

    def test_pagination_window_strips_ansi(self, plugin):
        mock_gdb.state.output_map["heap"] = "\x1b[31ml0\x1b[0m\nl1"
        resp = call(plugin, "eval", {"command": "heap", "offset": 0, "limit": 1})
        assert resp["result"]["output"] == "l0"


class TestReadMem:
    def test_whole_read(self, plugin):
        inf = set_inferior()
        inf.memory[0x100 : 0x110] = b"ABCDEFGHIJKLMNOP"
        resp = call(plugin, "read_mem", {"addr": "0x100", "length": 16})
        assert resp["ok"] is True
        r = resp["result"]
        assert r["addr"] == 0x100
        assert r["hex"] == "4142434445464748494a4b4c4d4e4f50"
        assert r["ascii"] == "ABCDEFGHIJKLMNOP"
        assert r["unreadable"] == [] and r["partial"] is False

    def test_expression_addr(self, plugin):
        mock_gdb.state.expr_map["main"] = 0x401000
        set_inferior()
        resp = call(plugin, "read_mem", {"addr": "main", "length": 4})
        assert resp["result"]["addr"] == 0x401000

    def test_chunk_fallback(self, plugin):
        inf = set_inferior()
        inf.memory[0x1000 : 0x4000] = b"\x41" * 0x3000
        inf.read_fail = [(0x2000, 0x1000)]  # one bad 4K chunk
        resp = call(plugin, "read_mem", {"addr": 0x1000, "length": 0x3000})
        r = resp["result"]
        assert r["partial"] is True
        assert r["unreadable"] == [{"addr": 0x2000, "length": 0x1000}]
        assert r["hex"] is None
        assert [(s["addr"], s["length"]) for s in r["segments"]] == [
            (0x1000, 0x1000),
            (0x3000, 0x1000),
        ]

    def test_chunk_fallback_covers_full_large_request(self, plugin):
        inf = set_inferior()
        inf.read_fail = [(0, 0x1000)]
        resp = call(plugin, "read_mem", {"addr": 0, "length": 0x50000})
        result = resp["result"]
        assert result["unreadable"] == [{"addr": 0, "length": 0x1000}]
        assert result["segments"][-1]["addr"] + result["segments"][-1]["length"] == 0x50000

    def test_bad_length(self, plugin):
        set_inferior()
        assert call(plugin, "read_mem", {"addr": 0, "length": 0})["error"]["code"] == "BAD_PARAMS"
        assert call(plugin, "read_mem", {"addr": 0, "length": 1 << 22})["error"]["code"] == "BAD_PARAMS"

    def test_bad_addr(self, plugin):
        set_inferior()
        assert call(plugin, "read_mem", {"addr": "nosuchsym"})["error"]["code"] == "BAD_PARAMS"

    def test_no_inferior(self, plugin):
        resp = call(plugin, "read_mem", {"addr": 0x1000, "length": 16})
        assert resp["error"]["code"] == "NO_INFERIOR"


class TestWriteMem:
    def test_write(self, plugin):
        inf = set_inferior()
        resp = call(plugin, "write_mem", {"addr": 0x2000, "hex": "41 42 43"})
        assert resp["result"] == {"addr": 0x2000, "bytes_written": 3}
        assert inf.writes == [(0x2000, b"ABC")]

    def test_bad_hex(self, plugin):
        set_inferior()
        assert call(plugin, "write_mem", {"addr": 0x2000, "hex": "zz"})["error"]["code"] == "BAD_PARAMS"

    def test_empty_write_rejected(self, plugin):
        set_inferior()
        assert call(plugin, "write_mem", {"addr": 0x2000, "hex": ""})["error"]["code"] == "BAD_PARAMS"


class TestRegs:
    def test_full_listing_skips_unavailable(self, plugin):
        set_inferior()
        resp = call(plugin, "regs", {})
        regs = resp["result"]["regs"]
        assert regs["rax"] == "0x1"
        assert regs["rip"] == "0x401000"
        assert "rsp" not in regs  # unavailable in the mock frame

    def test_names_subset(self, plugin):
        set_inferior()
        resp = call(plugin, "regs", {"names": ["rax", "rip"]})
        assert set(resp["result"]["regs"]) == {"rax", "rip"}


class TestSetReg:
    def test_set(self, plugin):
        set_inferior()
        resp = call(plugin, "set_reg", {"name": "rip", "value": "0xdead"})
        assert resp["result"] == {"name": "rip", "old": "0x401000", "new": "0xdead"}
        assert mock_gdb.state.executed == ["set $rip = 0xdead"]

    def test_missing_params(self, plugin):
        set_inferior()
        assert call(plugin, "set_reg", {})["error"]["code"] == "BAD_PARAMS"

    def test_rejects_invalid_register_name(self, plugin):
        set_inferior()
        resp = call(
            plugin,
            "set_reg",
            {"name": "rax\nquit", "value": "0xdead"},
        )
        assert resp["error"]["code"] == "BAD_PARAMS"
        assert mock_gdb.state.executed == []


class TestBacktrace:
    def test_walk_frames(self, plugin):
        set_inferior()
        f1 = mock_gdb.state.newest_frame
        f2 = mock_gdb.MockFrame(0x402000, "helper", filename="b.c", line=42)
        f1._older = f2
        resp = call(plugin, "backtrace", {"max_frames": 64})
        frames = resp["result"]["frames"]
        assert len(frames) == 2
        assert frames[0]["function"] == "main"
        assert frames[0]["file"] == "a.c" and frames[0]["line"] == 10
        assert frames[1]["function"] == "helper"
        assert frames[1]["line"] == 42
        assert resp["result"]["truncated"] is False

    def test_max_frames_cap(self, plugin):
        set_inferior()
        f = mock_gdb.state.newest_frame
        for i in range(10):
            nxt = mock_gdb.MockFrame(0x402000 + 0x10 * i, "f%d" % i)
            f._older = nxt
            f = nxt
        resp = call(plugin, "backtrace", {"max_frames": 3})
        assert len(resp["result"]["frames"]) == 3
        assert resp["result"]["truncated"] is True

    def test_no_frame(self, plugin):
        set_inferior()
        mock_gdb.state.newest_frame = None
        assert call(plugin, "backtrace", {})["error"]["code"] == "NO_FRAME"


class TestDisasm:
    def test_with_start(self, plugin):
        set_inferior()
        resp = call(plugin, "disasm", {"start": "0x401000", "count": 5})
        r = resp["result"]
        assert r["start"] == "0x401000"
        assert len(r["instructions"]) == 5
        assert r["instructions"][0] == {"addr": "0x401000", "size": 4, "asm": "nop"}
        # one extra instruction is requested to detect continuation
        assert mock_gdb.state.arch.disasm_calls == [(0x401000, 6)]
        assert r["truncated"] is True

    def test_default_pc(self, plugin):
        set_inferior()
        resp = call(plugin, "disasm", {})
        assert resp["result"]["start"] == "0x401000"
        assert len(resp["result"]["instructions"]) == 16
        assert resp["result"]["truncated"] is False


class TestEvaluate:
    def test_value(self, plugin):
        mock_gdb.state.expr_map["$rax"] = 0x4040
        set_inferior()
        resp = call(plugin, "evaluate", {"expression": "$rax"})
        r = resp["result"]
        assert r["value"] == "16448"
        assert r["address"] == "0x4040"
        assert r["type"] == "long"

    def test_unknown_expression(self, plugin):
        set_inferior()
        resp = call(plugin, "evaluate", {"expression": "nosuch"})
        assert resp["error"]["code"] == "PLUGIN_ERROR"

    def test_function_value_has_no_address_field(self, plugin):
        # int(gdb.Value) raises gdb.error for function symbols; the
        # evaluate result must still succeed without an address field
        class FuncValue:
            type = mock_gdb.MockType("void (void)")
            _val = None

            def __int__(self):
                raise mock_gdb.error("Cannot convert value to long.")

            def __str__(self):
                return "{void (void)} 0x401000 <main>"

        mock_gdb.state.expr_map["main"] = FuncValue()
        set_inferior()
        resp = call(plugin, "evaluate", {"expression": "main"})
        assert resp["ok"] is True
        assert "address" not in resp["result"]
        assert "main" in resp["result"]["value"]


class TestThreads:
    def test_threads(self, plugin):
        set_inferior()
        mock_gdb.state.threads = [
            mock_gdb.MockThread(1, "main"),
            mock_gdb.MockThread(2, "worker"),
        ]
        mock_gdb.state.selected_thread = mock_gdb.state.threads[1]
        resp = call(plugin, "threads", {})
        r = resp["result"]
        assert r["selected"] == 2
        assert [t["state"] for t in r["threads"]] == ["stopped", "stopped"]
        assert r["threads"][1]["selected"] is True


class TestFrameSelect:
    def test_select(self, plugin):
        set_inferior()
        f1 = mock_gdb.state.newest_frame
        f2 = mock_gdb.MockFrame(0x402000, "helper")
        f1._older = f2
        resp = call(plugin, "frame_select", {"level": 1})
        assert resp["result"]["frame"]["function"] == "helper"

    def test_out_of_range(self, plugin):
        set_inferior()
        assert call(plugin, "frame_select", {"level": 99})["error"]["code"] == "NO_FRAME"

    def test_bad_level(self, plugin):
        set_inferior()
        assert call(plugin, "frame_select", {"level": "x"})["error"]["code"] == "BAD_PARAMS"


class TestBreakpoints:
    def test_list(self, plugin):
        bp = MockBreakpoint("0x401000")
        bp.hit_count = 3
        mock_gdb.state.breakpoints = [bp]
        resp = call(plugin, "breakpoints", {})
        r = resp["result"]["breakpoints"][0]
        assert r["number"] == bp.number
        assert r["enabled"] is True
        assert r["location"] == "0x401000"
        assert r["addr"] == "0x401000"
        assert r["hit_count"] == 3

    def test_break_with_options(self, plugin):
        set_inferior()
        resp = call(
            plugin,
            "break",
            {
                "location": "main",
                "type": "hw",
                "condition": "i > 5",
                "thread": 2,
                "temporary": True,
                "pending": True,
            },
        )
        assert resp["result"]["type"] == "hw"
        bp = mock_gdb.state.breakpoints[0]
        assert bp.location == "main"
        assert bp.condition == "i > 5"
        assert bp.thread == 2
        assert bp.temporary is True
        # pending is implemented via the global gdb setting
        executed = mock_gdb.state.executed
        assert "set breakpoint pending on" in executed
        assert executed[-1] == "set breakpoint pending auto"

    def test_break_with_commands_and_auto_continue(self, plugin):
        set_inferior()
        resp = call(
            plugin,
            "break",
            {
                "location": "main",
                "commands": ["x/4gx $rdi", "info registers"],
                "auto_continue": True,
            },
        )
        r = resp["result"]
        assert r["has_commands"] is True
        bp = mock_gdb.state.breakpoints[0]
        assert bp.commands == "silent\nx/4gx $rdi\ninfo registers\ncontinue"

    def test_break_auto_continue_only(self, plugin):
        set_inferior()
        resp = call(plugin, "break", {"location": "main", "auto_continue": True})
        assert resp["result"]["has_commands"] is True
        assert mock_gdb.state.breakpoints[0].commands == "silent\ncontinue"

    def test_break_commands_invalid_type(self, plugin):
        set_inferior()
        resp = call(plugin, "break", {"location": "main", "commands": "x/1i $pc"})
        assert resp["error"]["code"] == "BAD_PARAMS"

    def test_break_invalid_type(self, plugin):
        set_inferior()
        assert call(plugin, "break", {"location": "main", "type": "weird"})["error"]["code"] == "BAD_PARAMS"

    def test_delete_enable_disable(self, plugin):
        bp = MockBreakpoint("0x401000")
        mock_gdb.state.breakpoints = [bp]
        call(plugin, "bp_disable", {"number": bp.number})
        assert bp.enabled is False
        call(plugin, "bp_enable", {"number": bp.number})
        assert bp.enabled is True
        call(plugin, "bp_delete", {"number": bp.number})
        assert mock_gdb.state.breakpoints == []

    def test_missing_breakpoint(self, plugin):
        assert call(plugin, "bp_delete", {"number": 999})["error"]["code"] == "BAD_PARAMS"


class TestMemMapFileCore:
    def test_mem_map(self, plugin):
        mock_gdb.state.output_map["info proc mappings"] = "\x1b[32mmaps\x1b[0m"
        resp = call(plugin, "mem_map", {})
        assert resp["result"]["output"] == "maps"

    def test_file_quotes_path(self, plugin):
        resp = call(plugin, "file", {"path": "/tmp/my bin"})
        assert resp["ok"] is True
        assert mock_gdb.state.executed[-1] == "file '/tmp/my bin'"

    def test_core(self, plugin):
        call(plugin, "core", {"path": "/tmp/core.1"})
        assert mock_gdb.state.executed[-1] == "core-file /tmp/core.1"


class TestContinueFamily:
    def test_continue_replies_before_execute(self, plugin):
        set_inferior()
        resp = call(plugin, "continue", {})
        assert resp["ok"] is True
        assert resp["result"] == {"state": "running"}
        assert plugin.state == "running"
        assert "continue" in mock_gdb.state.executed

    def test_already_running(self, plugin):
        set_inferior()
        plugin.state = "running"
        resp = call(plugin, "continue", {})
        assert resp["error"]["code"] == "INFERIOR_RUNNING"

    def test_no_inferior(self, plugin):
        resp = call(plugin, "continue", {})
        assert resp["error"]["code"] == "NO_INFERIOR"

    def test_step_variants(self, plugin):
        set_inferior()
        for verb in ("step", "next", "stepi", "nexti", "finish"):
            plugin.state = "stopped"
            assert call(plugin, verb, {}, req_id=len(mock_gdb.state.executed) + 2)["ok"] is True
            assert mock_gdb.state.executed[-1] == verb

    def test_until_with_addr(self, plugin):
        set_inferior()
        resp = call(plugin, "until", {"until_addr": "0x401100"})
        assert resp["ok"] is True
        assert mock_gdb.state.executed[-1] == "until *0x401100"


class TestGuards:
    def test_gated_verb_rejected_while_running(self, plugin):
        set_inferior()
        plugin.state = "running"
        resp = call(plugin, "read_mem", {"addr": 0x1000, "length": 4})
        assert resp["error"]["code"] == "INFERIOR_RUNNING"

    def test_eval_not_gated(self, plugin):
        mock_gdb.state.output_map["x"] = "ok"
        plugin.state = "running"
        resp = call(plugin, "eval", {"command": "x"})
        assert resp["ok"] is True

    def test_unknown_verb(self, plugin):
        resp = call(plugin, "frobnicate", {})
        assert resp["error"]["code"] == "UNKNOWN_VERB"

    def test_reader_side_gate(self, plugin):
        set_inferior()
        plugin.state = "running"
        plugin._dispatch_request(
            {"type": "request", "id": 5, "verb": "read_mem", "params": {"addr": 0, "length": 1}}
        )
        resp = drain(plugin)[-1]
        assert resp["id"] == 5 and resp["error"]["code"] == "INFERIOR_RUNNING"


class TestPump:
    def test_pump_executes_queued(self, plugin):
        set_inferior()
        plugin._dispatch_request(
            {"type": "request", "id": 9, "verb": "regs", "params": {"names": ["rax"]}}
        )
        assert len(mock_gdb.state.posted) == 1
        mock_gdb.flush_posted()
        resp = drain(plugin)[-1]
        assert resp["id"] == 9 and resp["result"]["regs"]["rax"] == "0x1"


class TestReaderVerbs:
    def test_ping(self, plugin):
        plugin._handle_reader_verb({"type": "request", "id": 3, "verb": "ping"})
        assert drain(plugin)[-1]["result"] == {"pong": True}

    def test_interrupt_posts_to_main_thread(self, plugin):
        plugin._handle_reader_verb({"type": "request", "id": 3, "verb": "interrupt"})
        assert drain(plugin)[-1]["result"] == {"state": "interrupt_requested"}
        # the actual interrupt runs on the gdb main thread
        assert len(mock_gdb.state.posted) == 1
        mock_gdb.flush_posted()
        assert "interrupt" in mock_gdb.state.executed

    def test_do_interrupt_fallback_to_gdb_interrupt(self, plugin, monkeypatch):
        # execute("interrupt") fails -> gdb.interrupt() (gdb>=15) fallback
        def failing_execute(cmd, to_string=False):
            if cmd == "interrupt":
                raise mock_gdb.error("cannot interrupt")
            return ""

        monkeypatch.setattr(mock_gdb, "execute", failing_execute)
        plugin._do_interrupt()
        assert mock_gdb.state.interrupt_calls == 1

    def test_quit_posts_shutdown(self, plugin):
        plugin._connect_events()
        plugin._handle_reader_verb(
            {"type": "request", "id": 3, "verb": "quit", "params": {"kill_gdb": False}}
        )
        mock_gdb.flush_posted()
        assert plugin._shutdown_done is True
        assert plugin.state == "disconnected"

    def test_interrupt_post_event_failure_reported(self, plugin, monkeypatch):
        def boom(cb):
            raise RuntimeError("post_event failed")

        monkeypatch.setattr(mock_gdb, "post_event", boom)
        plugin._handle_reader_verb({"type": "request", "id": 3, "verb": "interrupt"})
        assert drain(plugin)[-1]["error"]["code"] == "INTERRUPT_FAILED"


SNAP_MAPPINGS = (
    "          Start Addr           End Addr       Size     Offset  Perms  objfile\n"
    "          0x1000             0x3000             0x2000        0x0  rw-p   [heap]\n"
    "          0x400000           0x401000             0x1000        0x0  r-xp   /tmp/vuln\n"
)


class TestSnapshots:
    def _setup(self, plugin):
        inf = set_inferior()
        inf.memory[0x1000:0x3000] = b"\x00" * 0x2000
        mock_gdb.state.output_map["info proc mappings"] = SNAP_MAPPINGS
        return inf

    def test_create_and_list(self, plugin):
        self._setup(plugin)
        resp = call(plugin, "snapshot_create", {})
        r = resp["result"]
        assert r["snapshot_id"] == "ck-1"
        # only the rw mapping is captured; r-x is skipped by the perms filter
        assert r["segments"] == [{"addr": "0x1000", "length": 0x2000}]
        assert r["total_bytes"] == 0x2000
        assert r["registers"] == 4  # rax/rbx/rcx + rip
        assert r["skipped"] == []
        listing = call(plugin, "snapshot_list", {})["result"]["snapshots"]
        assert [s["snapshot_id"] for s in listing] == ["ck-1"]
        assert listing[0]["segments"] == 1

    def test_diff_detects_memory_and_register_changes(self, plugin):
        self._setup(plugin)
        call(plugin, "snapshot_create", {})
        inf = mock_gdb.state.inferior
        inf.memory[0x1080:0x1088] = b"AAAAAAAA"
        mock_gdb.state.newest_frame._regs["rax"] = 0x99
        r = call(plugin, "snapshot_diff", {"snapshot_id": "ck-1"})["result"]
        assert r["memory_changes"][0]["addr"] == "0x1080"
        # rows are DIFF_ROW_BYTES wide; the tail of the row is untouched
        assert r["memory_changes"][0]["new_hex"] == "4141414141414141" + "00" * 8
        assert {
            "name": "rax",
            "old": "0x1",
            "new": "0x99",
        } in r["registers_changed"]
        assert r["memory_truncated"] is False

    def test_restore_round_trip(self, plugin):
        inf = self._setup(plugin)
        inf.memory[0x1000:0x1010] = b"\x41" * 16
        call(plugin, "snapshot_create", {})
        inf.memory[0x1000:0x1010] = b"\x42" * 16
        mock_gdb.state.newest_frame._regs["rbx"] = 7
        r = call(plugin, "snapshot_restore", {"snapshot_id": "ck-1"})["result"]
        assert r["segments_written"] == 1
        assert r["segments_skipped"] == []
        assert r["registers_written"] >= 1
        assert bytes(inf.memory[0x1000:0x1010]) == b"\x41" * 16
        assert mock_gdb.state.newest_frame._regs["rbx"] == 2

    def test_budget_skips_large_segments(self, plugin):
        self._setup(plugin)
        r = call(
            plugin,
            "snapshot_create",
            {"max_segment_bytes": 0x1000, "max_total_bytes": 0x1000},
        )["result"]
        assert r["segments"] == []
        assert r["skipped"][0]["reason"] == "segment exceeds max_segment_bytes"

    def test_unknown_snapshot_id(self, plugin):
        self._setup(plugin)
        resp = call(plugin, "snapshot_diff", {"snapshot_id": "nope"})
        assert resp["error"]["code"] == "BAD_PARAMS"

    def test_gated_while_running(self, plugin):
        self._setup(plugin)
        plugin.state = "running"
        resp = call(plugin, "snapshot_create", {})
        assert resp["error"]["code"] == "INFERIOR_RUNNING"


class TestPolicies:
    def test_trace_steps_and_unique_pcs(self, plugin):
        set_inferior()
        mock_gdb.state.stepi_stride = 4
        r = call(plugin, "policy", {"kind": "trace", "max_steps": 5})["result"]
        assert r["steps"] == 5
        # the starting PC is recorded, then the 5 stepped PCs
        assert r["unique_count"] == 6
        assert r["unique_pc"][:2] == ["0x401000", "0x401004"]
        assert r["stop"] == "max_steps"
        assert r["truncated"] is False

    def test_trace_unknown_kind(self, plugin):
        set_inferior()
        resp = call(plugin, "policy", {"kind": "teleport"})
        assert resp["error"]["code"] == "BAD_PARAMS"

    def test_heap_arm_read_disarm(self, plugin):
        set_inferior()
        r = call(
            plugin,
            "policy",
            {"kind": "heap_arm", "symbols": ["malloc", "free"]},
        )["result"]
        assert r["armed"] == ["malloc", "free"]
        assert len(mock_gdb.state.breakpoints) == 2
        # a probe hit records args and auto-continues (stop() -> False)
        assert mock_gdb.state.breakpoints[0].stop() is False
        r = call(plugin, "policy", {"kind": "heap_read"})["result"]
        assert r["total"] == 1
        assert r["events"][0]["symbol"] == "malloc"
        # mock frames only carry rax/rbx/rcx/rip; rcx is a probe register
        assert r["events"][0]["args"] == {"rcx": "0x3"}
        r = call(plugin, "policy", {"kind": "heap_disarm"})["result"]
        assert r == {"disarmed": True, "total_events": 1}
        assert mock_gdb.state.breakpoints == []

    def test_heap_max_events_stops_inferior(self, plugin):
        set_inferior()
        call(plugin, "policy", {"kind": "heap_arm", "symbols": ["malloc"], "max_events": 1})
        bp = mock_gdb.state.breakpoints[0]
        assert bp.stop() is False  # records the first hit
        assert bp.stop() is True  # budget exhausted: let the run stop

    def test_heap_double_arm_rejected(self, plugin):
        set_inferior()
        call(plugin, "policy", {"kind": "heap_arm", "symbols": ["malloc"]})
        resp = call(plugin, "policy", {"kind": "heap_arm", "symbols": ["free"]})
        assert resp["error"]["code"] == "BAD_PARAMS"

    def test_fuzz_loop_crash_and_survive(self, plugin):
        plugin._connect_events()
        inf = set_inferior()
        inf.memory[0x1000:0x3000] = b"\x00" * 0x2000
        mock_gdb.state.output_map["info proc mappings"] = SNAP_MAPPINGS
        call(plugin, "snapshot_create", {})
        mock_gdb.state.continue_script = [
            ("bp",),                 # round 1: reaches the marker -> survived
            ("sig", "SIGSEGV"),      # round 2: crash (pc bumped by 0x10)
            ("sig", "SIGSEGV"),      # round 3: crash at a different pc
        ]
        r = call(
            plugin,
            "policy",
            {
                "kind": "fuzz_loop",
                "snapshot_id": "ck-1",
                "buffer_addr": "0x1000",
                "payloads": ["41" * 16, "42" * 8, "43" * 8],
                "stop_location": "main",
            },
        )["result"]
        assert r["rounds"] == 3
        assert r["survived"] == 1
        assert r["crash_count"] == 2
        assert r["truncated"] is False
        crash_signals = {c["stop"]["signal"] for c in r["crashes"]}
        assert crash_signals == {"SIGSEGV"}
        # the inferior is left stopped for the next policy round
        assert plugin.state == "stopped"

    def test_fuzz_loop_requires_snapshot_and_params(self, plugin):
        set_inferior()
        resp = call(plugin, "policy", {"kind": "fuzz_loop"})
        assert resp["error"]["code"] == "BAD_PARAMS"

    def test_policy_gated_while_running(self, plugin):
        set_inferior()
        plugin.state = "running"
        resp = call(plugin, "policy", {"kind": "trace"})
        assert resp["error"]["code"] == "INFERIOR_RUNNING"

    def _minimize_setup(self, plugin):
        plugin._connect_events()
        inf = set_inferior()
        inf.memory[0x1000:0x3000] = b"\x00" * 0x2000
        mock_gdb.state.output_map["info proc mappings"] = SNAP_MAPPINGS
        call(plugin, "snapshot_create", {})

    def test_crash_check_verdicts(self, plugin):
        self._minimize_setup(plugin)
        common = {
            "snapshot_id": "ck-1",
            "buffer_addr": "0x1000",
            "payload": "41" * 8,
            "stop_location": "main",
        }
        mock_gdb.state.continue_script = [("bp",)]
        r = call(plugin, "policy", {"kind": "crash_check", **common})["result"]
        assert r["survived"] is True
        assert r["error"] is None
        mock_gdb.state.continue_script = [("sig", "SIGSEGV")]
        r = call(plugin, "policy", {"kind": "crash_check", **common})["result"]
        assert r["survived"] is False
        assert r["stop"]["signal"] == "SIGSEGV"

    def test_minimize_reduces_crashing_payload(self, plugin):
        self._minimize_setup(plugin)
        mock_gdb.state.continue_script = [("sig", "SIGSEGV")] * 400
        r = call(
            plugin,
            "policy",
            {
                "kind": "minimize",
                "snapshot_id": "ck-1",
                "buffer_addr": "0x1000",
                "payload": "41" * 64,
                "stop_location": "main",
            },
        )["result"]
        assert r["reduced"] is True
        assert r["minimized_bytes"] == 1
        assert r["original_bytes"] == 64
        assert r["signal"] == "SIGSEGV"
        assert r["rounds"] < 128
        assert r["rounds_truncated"] is False

    def test_minimize_rejects_non_crashing_payload(self, plugin):
        self._minimize_setup(plugin)
        mock_gdb.state.continue_script = [("bp",)]
        resp = call(
            plugin,
            "policy",
            {
                "kind": "minimize",
                "snapshot_id": "ck-1",
                "buffer_addr": "0x1000",
                "payload": "41" * 8,
                "stop_location": "main",
            },
        )
        assert resp["error"]["code"] == "BAD_PARAMS"
        assert "does not crash" in resp["error"]["message"]
