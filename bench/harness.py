"""Shared E3 bench harness: compile, gdb+plugin session, base tools.

Crackme runners stay thin: they define a :class:`BenchSpec` (target,
task text, solved marker, extra tools, selftest) and call :func:`run_spec`.
Everything here is API-cost-free; real model calls happen only when a
runner is invoked with ``--go``.

Design rules (inherited from gdb_mcp.bench):

* Tool observations are structured (protocol verdicts, byte-offset log
  slices, key-register subsets) — correct and machine-readable, not
  prose summaries.
* Raw inferior output also travels as ``output_b64`` so exploit leaks
  (binary address bytes) survive the text round-trip intact.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import shlex
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "integration"))

from gdb_mcp.bench import DeepSeekClient, run_agent  # noqa: E402

#: per-crackme ports keep parallel runners out of each other's way
PORT_BASE = 39410

RAW_OUTPUT_B64_BYTES = 4096


@dataclass
class BenchSpec:
    """One graded crackme: target, task, tools, and self-checks."""

    name: str
    source: str  # path under bench/crackmes
    binary: str  # absolute WSL path for the compiled target
    port: int = PORT_BASE  # per-crackme port keeps parallel runners apart
    compile_flags: list[str] = field(
        default_factory=lambda: [
            "-g", "-O0", "-fno-stack-protector", "-no-pie",
        ]
    )
    #: how run_payload delivers bytes: "argv" (string payload as argv[1])
    #: or "stdin" (raw bytes written to a file, `run < file` — NULs OK)
    delivery: str = "argv"
    task: str = ""
    system_prompt: str = (
        "You are a binary exploitation agent. Work step by step; keep "
        "payloads short; use cyclic-style patterns to find offsets."
    )
    #: substring in the inferior output that proves the solve
    win_marker: str = "WIN{"
    #: (tools, schemas) merged after the base set; called once the
    #: plugin session is live
    extra_tools: Callable | None = None
    #: infra-level self-check executed by --selftest (no API calls)
    selftest: Callable | None = None


# -- structured observation helpers -----------------------------------------


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


def program_output_lines(log_text: str, limit: int = 30) -> list[str]:
    """The inferior's own output lines: gdb prompts, banners and blanks
    are noise for a model and are dropped."""
    lines = []
    for raw in log_text.splitlines():
        line = raw.strip()
        if not line or line == "(gdb)":
            continue
        lines.append(line)
    return lines[-limit:]


def wait_run_result(client, timeout: float = 60.0) -> dict:
    """Structured end-of-run verdict straight from the protocol
    notifications (never scraped from console text).

    Lifecycle events that belong to the PREVIOUS run being torn down
    (e.g. the ``exited`` a restart emits when it kills a crashed
    process) are skipped: the first ``running`` marks the run we care
    about, and only a stop/exited after it counts as the verdict."""
    deadline = time.time() + timeout
    seen_running = False
    while time.time() < deadline:
        msg = client.recv_msg(max(0.1, deadline - time.time()))
        mtype = msg.get("type")
        if mtype == "notification":
            client.notifications.append(msg)
            event = msg.get("event")
            if event == "running":
                seen_running = True
                continue
            if event in ("stop", "exited"):
                if not seen_running:
                    continue
                payload = msg.get("payload") or {}
                return {
                    "ended": event,
                    "signal": payload.get("signal"),
                    "pc": payload.get("pc"),
                    "exit_code": payload.get("exit_code"),
                }
        if mtype == "response" and not msg.get("ok", True):
            error = msg.get("error") or {}
            return {
                "ended": "error",
                "error": error.get("message", "run failed"),
            }
        # "ready"/"prompt" notifications are intentionally ignored
    return {"ended": "timeout"}


def run_payload_enriched(verdict, client):
    """On a stop, attach rsp plus a hex window straddling it.

    Failure analysis of the first real-model runs showed why this
    matters: a stack-smash crash reports pc AT the faulting ``ret``
    (non-canonical jump target), so the overwritten return-slot value is
    invisible in the verdict, and models went digging through stale
    strcpy registers for a cyclic marker - one derived offset 64 from a
    leftover register when the true slot offset was 72. The window at
    [rsp-16, rsp+32) contains the popped/unpopped return value either
    way, making cyclic_offset directly applicable."""
    if verdict.get("ended") != "stop":
        return verdict
    try:
        regs = client.request("regs", {}).get("regs", {})
        rsp = regs.get("rsp") or regs.get("esp")
        if not rsp:
            return verdict
        verdict["rsp"] = rsp
        base = int(str(rsp), 16) - 16
        window = client.request("read_mem", {"addr": base, "length": 48})
        verdict["stack_window_hex"] = window.get("hex")
        verdict["stack_window_addr"] = "0x%x" % base
    except Exception:  # observations must never mask the verdict itself
        pass
    return verdict


class OutputCapture:
    """Byte-offset slices of the gdb log: the inferior's output plus an
    intact base64 view of the raw bytes (leaks survive as bytes)."""

    def __init__(self, log_path: str):
        self.log_path = log_path

    def size(self) -> int:
        try:
            return os.path.getsize(self.log_path)
        except OSError:
            return 0

    def read_from(self, offset: int) -> bytes:
        try:
            with open(self.log_path, "rb") as fh:
                fh.seek(offset)
                return fh.read()
        except OSError:
            return b""

    def observation(self, offset: int, limit: int = 30) -> dict:
        raw = self.read_from(offset)
        text = raw.decode("utf-8", "replace")
        return {
            "output_lines": program_output_lines(text, limit),
            "output_b64": base64.b64encode(raw[:RAW_OUTPUT_B64_BYTES]).decode(
                "ascii"
            ),
        }


# -- pure parsers (unit-tested on any OS; used by reference solves) ---------

_PLT_CALL_RE = re.compile(r"call\s+0x([0-9a-f]+)\s+<(\w+)@plt>")
_GOT_COMMENT_RE = re.compile(
    r"#\s*(0x[0-9a-f]+)\s*<(\w+)@got", re.IGNORECASE
)

def parse_plt_address(instructions: list[dict], symbol: str) -> int | None:
    """The PLT stub address of ``symbol`` from a disassembly of a caller
    (gdb annotates calls as ``call 0x401040 <puts@plt>``)."""
    for insn in instructions:
        match = _PLT_CALL_RE.search(insn.get("asm", ""))
        if match and match.group(2) == symbol:
            return int(match.group(1), 16)
    return None


def parse_got_address(instructions: list[dict], symbol: str) -> int | None:
    """The GOT slot of ``symbol`` from a disassembly of its PLT stub
    (gdb annotates the first ``jmp [rip+X]`` with ``# 0x... <sym@got>``)."""
    for insn in instructions:
        match = _GOT_COMMENT_RE.search(insn.get("asm", ""))
        if match and match.group(2).startswith(symbol):
            return int(match.group(1), 16)
    return None


def parse_objdump_strings(objdump_output: str, min_len: int = 4) -> list[dict]:
    """Printable strings with virtual addresses from ``objdump -s``.
    Line shape: ``  4006a0 48656c6c 6f00...  Hello.``"""
    results = []
    partial_addr = None
    partial_bytes = bytearray()
    for line in objdump_output.splitlines():
        match = re.match(
            r"\s+([0-9a-f]+)\s+((?:[0-9a-f]{2,8}\s+)+)", line, re.IGNORECASE
        )
        if not match:
            continue
        addr = int(match.group(1), 16)
        hex_part = match.group(2)
        chunk = bytes.fromhex(hex_part.replace(" ", ""))
        if partial_addr is None or addr < partial_addr:
            # new run (or first): the chunk starts at its own addr
            if partial_bytes:
                results.append((partial_addr, bytes(partial_bytes)))
            partial_addr, partial_bytes = addr, bytearray(chunk)
        else:
            # continuation line of the same run
            partial_bytes.extend(chunk)
        if len(partial_bytes) > 65536:
            results.append((partial_addr, bytes(partial_bytes)))
            partial_addr, partial_bytes = None, bytearray()
    if partial_bytes:
        results.append((partial_addr, bytes(partial_bytes)))
    strings = []
    for addr, blob in results:
        start = None
        for i, byte in enumerate(blob + b"\x00"):
            if 0x20 <= byte < 0x7F:
                if start is None:
                    start = i
            else:
                if start is not None and i - start >= min_len:
                    strings.append(
                        {
                            "addr": "0x%x" % (addr + start),
                            "text": blob[start:i].decode("ascii"),
                        }
                    )
                start = None
    return strings


def find_arg_index(
    observed: dict, marker_bytes: bytes, first_arg: int = 6
) -> int | None:
    """Which printf positional arg carried ``marker_bytes``.

    The probe format prints one ``%N$p`` per segment separated by ``|``
    (``"%6$p|%7$p|..."``), so the k-th ``|``-segment in the output line
    belongs to arg ``first_arg + k``. Marker bytes are compared
    little-endian (``%p`` renders the loaded qword as a number)."""
    raw = base64.b64decode(observed.get("output_b64") or b"")
    needle = ("0x" + marker_bytes[::-1].hex()).encode("ascii")
    for line in raw.split(b"\n"):
        for position, segment in enumerate(line.split(b"|")):
            if segment.strip() == needle:
                return first_arg + position
    return None


# -- session + tools ---------------------------------------------------------


def compile_crackme(spec: BenchSpec) -> None:
    source = ROOT / "bench" / "crackmes" / spec.source
    proc = subprocess.run(
        ["gcc", *spec.compile_flags, "-o", spec.binary, str(source)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise SystemExit("compile failed: %s" % proc.stderr[-400:])


def launch_gdb(spec: BenchSpec, plugin_path: Path):
    """Start gdb with the plugin; the tail|gdb pipeline keeps both alive.
    Returns the Popen handle (the shell anchoring the pipeline)."""
    log = "/tmp/%s_gdb.log" % spec.name
    script = (
        "tail -f /dev/null | GDB_MCP_PORT=%d GDB_MCP_HOST=127.0.0.1 "
        "gdb -q -nx -x %s > %s 2>&1 & wait"
        % (spec.port, shlex.quote(str(plugin_path)), shlex.quote(log))
    )
    return subprocess.Popen(["bash", "-lc", script])


def start_session(spec: BenchSpec, plugin_path: Path):
    """Launch gdb and complete the plugin handshake; returns
    ``(proc, client, output)`` with the target already ``file``-loaded."""
    gdb_proc = launch_gdb(spec, plugin_path)
    from fake_mcp_client import FakeServer

    try:
        client = FakeServer(spec.port)
        client.accept()
        client.expect("hello")
        client.send(
            {
                "type": "hello_ack",
                "proto": 1,
                "server_version": "0.1.0",
                "session_id": "s-bench-%s" % spec.name,
                "heartbeat_sec": 30,
            }
        )
        client.wait_for_event("ready")
        client.request("file", {"path": spec.binary})
        # restarts of a crashed/stopped inferior must not prompt
        client.request("eval", {"command": "set confirm off"})
    except Exception as exc:
        gdb_proc.kill()
        raise SystemExit(
            "[bench] infrastructure failed: %s\n--- gdb.log ---\n%s"
            % (exc, _log_tail("/tmp/%s_gdb.log" % spec.name))
        ) from exc
    return gdb_proc, client, OutputCapture("/tmp/%s_gdb.log" % spec.name)


def _log_tail(path: str, lines: int = 40) -> str:
    proc = subprocess.run(
        ["tail", "-n", str(lines), path], capture_output=True, text=True
    )
    return proc.stdout


def make_base_tools(spec: BenchSpec, client, output: OutputCapture):
    """The seven base tools every crackme agent gets, plus their OpenAI
    schemas. run_payload delivers per spec.delivery and always returns
    the structured verdict, the inferior's own output lines, an intact
    base64 view of the raw bytes, and win=<<marker in output>>."""

    def tool_run_payload(arguments: dict) -> dict:
        if "payload_hex" in arguments:
            payload = bytes.fromhex(str(arguments["payload_hex"]))
            if spec.delivery == "argv":
                return {
                    "error": "argv delivery takes a plain payload string "
                    "(NUL bytes cannot travel in argv)"
                }
        else:
            payload_text = str(arguments.get("payload", ""))
            payload = (
                payload_text.encode("utf-8")
                if spec.delivery == "stdin"
                else payload_text
            )
        offset = output.size()
        if spec.delivery == "argv":
            client.request(
                "eval", {"command": "set args %s" % shlex.quote(payload)}
            )
            client.send_only("eval", {"command": "run"})
        else:
            path = "/tmp/%s_payload" % spec.name
            with open(path, "wb") as fh:
                fh.write(payload)
            client.request("eval", {"command": "set args"})
            client.send_only("eval", {"command": "run < %s" % path})
        verdict = wait_run_result(client)
        verdict = run_payload_enriched(verdict, client)
        observation = output.observation(offset)
        # the win check scans the FULL raw slice, not the b64 preview
        # (the marker may print after megabytes of %c padding)
        raw = output.read_from(offset)
        return {
            "verdict": verdict,
            **observation,
            "win": spec.win_marker.encode("utf-8") in raw,
        }

    def tool_get_output(_arguments: dict) -> dict:
        return output.observation(0)

    def tool_disassemble(arguments: dict) -> dict:
        result = client.request(
            "disasm",
            {
                "start": arguments.get("start", "main"),
                "count": min(int(arguments.get("count", 24)), 128),
            },
        )
        return {
            "start": result.get("start"),
            "instructions": result.get("instructions", []),
        }

    key_register_names = {
        "pc", "rip", "eip", "sp", "rsp", "esp", "bp", "rbp", "ebp",
        "rax", "eax", "rbx", "ebx", "rcx", "ecx", "rdx", "edx",
        "rsi", "esi", "rdi", "edi", "r8", "r9", "r10", "r11",
        "r12", "r13", "r14", "r15",
    }

    def tool_read_registers(arguments: dict) -> dict:
        regs = client.request("regs", {}).get("regs", {})
        if arguments.get("full"):
            return {"registers": regs}
        subset = {
            k: v for k, v in regs.items() if k.lower() in key_register_names
        }
        return {
            "registers": subset or regs,
            "note": "key subset; full=true for all",
        }

    def tool_read_memory(arguments: dict) -> dict:
        result = client.request(
            "read_mem",
            {
                "addr": arguments.get("addr"),
                "length": min(max(int(arguments.get("length", 64)), 1), 1024),
            },
        )
        return {
            "addr": result.get("addr"),
            "hex": result.get("hex"),
            "ascii": result.get("ascii"),
            "unreadable": result.get("unreadable", []),
        }

    from gdb_mcp.campaign import cyclic_pattern, match_cyclic

    def tool_cyclic_offset(arguments: dict) -> dict:
        value = int(str(arguments.get("value", "0")), 16)
        return {"match": match_cyclic(value)}

    def tool_cyclic_pattern(arguments: dict) -> dict:
        count = min(max(int(arguments.get("count", 200)), 1), 4096)
        return {"pattern": cyclic_pattern(count)}

    tools = {
        "run_payload": tool_run_payload,
        "get_output": tool_get_output,
        "disassemble": tool_disassemble,
        "read_registers": tool_read_registers,
        "read_memory": tool_read_memory,
        "cyclic_offset": tool_cyclic_offset,
        "cyclic_pattern": tool_cyclic_pattern,
    }
    hex_payload_property = {
        "payload_hex": {
            "type": "string",
            "description": "raw payload bytes as hex (stdin delivery)",
        }
    }
    schemas = [
        {
            "type": "function",
            "function": {
                "name": "run_payload",
                "description": "Run the binary with the payload (%s). "
                "Returns structured verdict {ended: stop|exited, signal, "
                "pc, exit_code, and on a stop also rsp + "
                "stack_window_hex (48 bytes around rsp - the overwritten "
                "return-slot value lives there; feed qwords to "
                "cyclic_offset)}, output_lines, output_b64 (raw bytes; "
                "decode for binary leaks), and win=true when the win "
                "marker appeared"
                % (
                    "argv[1]"
                    if spec.delivery == "argv"
                    else "bytes on stdin; payload_hex for non-printable"
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "payload": {"type": "string"},
                        **(hex_payload_property if spec.delivery == "stdin" else {}),
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_output",
                "description": "Return the inferior's accumulated "
                "output_lines and raw output_b64",
                "parameters": {"type": "object", "properties": {}},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "disassemble",
                "description": "Disassemble instructions at an address or "
                "symbol (default main). Returns start + instruction list "
                "[{addr, size, asm}]",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string"},
                        "count": {"type": "integer"},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_registers",
                "description": "Read registers. Returns the key-register "
                "subset by default; full=true returns every register",
                "parameters": {
                    "type": "object",
                    "properties": {"full": {"type": "boolean"}},
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_memory",
                "description": "Read inferior memory at an address or "
                "symbol. Returns addr, hex and ascii rendering",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string"},
                        "length": {"type": "integer"},
                    },
                    "required": ["addr"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "cyclic_offset",
                "description": "Given a hex value (e.g. a crashed PC or a "
                "register), return the offset into the standard de Bruijn "
                "cyclic pattern (lowercase, subsequence 4) that it "
                "contains, if any",
                "parameters": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "cyclic_pattern",
                "description": "Return a de Bruijn cyclic pattern string "
                "of the requested length for payload construction",
                "parameters": {
                    "type": "object",
                    "properties": {"count": {"type": "integer"}},
                },
            },
        },
    ]
    return tools, schemas


# -- runner driver -----------------------------------------------------------


def run_spec(spec: BenchSpec, argv: list[str] | None = None) -> int:
    """CLI shared by all crackme runners: dry-run / --selftest / --go."""
    if os.name == "nt":
        print(
            "run this inside WSL:\n  wsl.exe -d <distro> -- bash -lc "
            "'cd %s && python3 bench/run_%s.py'" % (ROOT, spec.name)
        )
        return 2
    parser = argparse.ArgumentParser(description=spec.task.splitlines()[0])
    parser.add_argument("--go", action="store_true", help="really call the API")
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="validate infrastructure AND solve the crackme with the "
        "built-in reference exploit (no API calls)",
    )
    parser.add_argument("--max-turns", type=int, default=12)
    parser.add_argument("--model", default="deepseek-chat")
    parser.add_argument(
        "--dump",
        default=None,
        metavar="PATH",
        help="after --go, write the full conversation (messages) as JSON "
        "for failure analysis",
    )
    args = parser.parse_args(argv)

    compile_crackme(spec)
    print("[bench] crackme compiled at %s" % spec.binary)

    gdb_proc, client, output = start_session(
        spec, ROOT / "src" / "gdb_mcp" / "plugin" / "gdb_mcp_plugin.py"
    )
    print("[bench] plugin session ready; target loaded")
    tools, schemas = make_base_tools(spec, client, output)
    if spec.extra_tools:
        extra_tools, extra_schemas = spec.extra_tools(client)
        tools.update(extra_tools)
        schemas.extend(extra_schemas)

    try:
        if not args.go:
            if args.selftest:
                assert spec.selftest is not None, "spec has no selftest"
                spec.selftest(tools)
                print(
                    "[bench] selftest OK: reference exploit solved %s; "
                    "structured verdicts correct" % spec.name
                )
            else:
                print(
                    "[bench] infrastructure OK; tools: %s"
                    % ", ".join(sorted(tools))
                )
                print("[bench] dry run only (no API calls). Re-run with --go.")
            return 0

        llm = DeepSeekClient(model=args.model)
        llm.bind_tools(schemas)
        try:
            result = run_agent(
                llm,
                tools,
                task=spec.task,
                system_prompt=spec.system_prompt,
                max_turns=args.max_turns,
                check_solved=lambda name, observation: bool(
                    isinstance(observation, dict) and observation.get("win")
                ),
                solved_answer="win marker observed",
            )
        finally:
            gdb_proc.kill()
        if args.dump:
            import json

            Path(args.dump).write_text(
                json.dumps(result.messages, ensure_ascii=False, indent=1),
                encoding="utf-8",
            )
            print("[bench] conversation dumped to %s" % args.dump)
        print(
            "[bench] solved=%s finish=%s turns=%d tool_calls=%d "
            "total_tokens=%d"
            % (
                result.solved,
                result.finish,
                result.turns,
                result.tool_calls,
                llm.total_tokens,
            )
        )
        return 0 if result.solved else 1
    finally:
        if gdb_proc.poll() is None:
            gdb_proc.kill()
