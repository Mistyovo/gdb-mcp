"""Ground-truth check operators.

Every check is evaluated by the harness issuing *fresh* MCP tool calls against
the live session — agent output is never consulted (goal: "final state
satisfies ground truth"). `value` fields may be:

* an int                       — compared numerically
* a "0x…"/decimal string       — parsed and compared numerically
* ``{"expr": "<gdb expr>"}``   — evaluated in the live inferior, then compared

This last form is what keeps PIE/heap tasks honest: the expected value is
derived from runtime state the harness observes itself, at grading time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - import cycle guard for type checkers
    from .driver import McpDriver
    from .schema import Check, TaskSpec


@dataclass
class CheckResult:
    op: str
    passed: bool
    detail: str


class VerifyError(RuntimeError):
    """The check itself could not be executed (bad spec, dead session…)."""


_INT_RE = re.compile(r"[-+]?(0[xX][0-9a-fA-F]+|\d+)")
_BP_NUM_RE = re.compile(r"^\s*(\d+)\s+(.+?)\s+(keep|del)\s+([yn])\s*(.*)$")
_BP_COND_RE = re.compile(r"^\s+stop only if\s+(.*?)\s*$")
_BP_HIT_RE = re.compile(r"^\s*(?:\S+\s+)?already hit (\d+) times?\s*$")


def parse_info_breakpoints(text: str) -> list[dict]:
    """Parse `info breakpoints` output into dicts.

    Deliberately text-based: the plugin's bp entries can carry location=None
    (pwndbg patches gdb.Breakpoint), while `info breakpoints` always shows
    the resolved address, condition and hit count.
    """
    out: list[dict] = []
    current = None
    for line in text.splitlines():
        m = _BP_NUM_RE.match(line)
        if m:
            num, btype, _disp, enb, rest = m.groups()
            addr = None
            where = rest.strip()
            if where.startswith("0x"):
                token = where.split()[0]
                addr = parse_int(token)
                where = where[len(token):].strip()
            current = {
                "number": int(num),
                "type": btype.strip(),
                "enabled": enb == "y",
                "addr": addr,
                "where": where,
                "condition": None,
                "hit_count": 0,
            }
            out.append(current)
            continue
        m = _BP_COND_RE.match(line)
        if m and current is not None:
            current["condition"] = m.group(1)
            continue
        m = _BP_HIT_RE.match(line)
        if m and current is not None:
            current["hit_count"] = int(m.group(1))
    return out


def parse_int(value: Any) -> int | None:
    """Best-effort int from gdb value strings ('0x7fff1000', '42', '42 <foo>')."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    m = _INT_RE.search(value.strip())
    if m is None:
        return None
    text = m.group(0)
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def _norm_addr(value: Any) -> int | None:
    n = parse_int(value)
    if n is None:
        return None
    return n & 0xFFFFFFFFFFFFFFFF


def _hex(value: int) -> str:
    return "0x%x" % (value & 0xFFFFFFFFFFFFFFFF)


class Verifier:
    """Executes check ops for one session. One instance per task grading."""

    def __init__(self, driver: "McpDriver", session_id: str):
        self.driver = driver
        self.session_id = session_id
        self._bp_cache: list[dict] | None = None

    # -- helpers ------------------------------------------------------------

    async def _breakpoints(self) -> list[dict]:
        """Ground truth for breakpoints straight from gdb's own listing."""
        if self._bp_cache is None:
            result = await self.driver.call(
                "execute_command",
                {"command": "info breakpoints", "session_id": self.session_id},
            )
            self._bp_cache = parse_info_breakpoints(result.get("output", ""))
        return self._bp_cache

    async def _stop_info(self) -> dict:
        result = await self.driver.call("get_stop_reason", {"session_id": self.session_id})
        return result.get("stop_info") or {}

    async def _eval_int(self, expression: str) -> int:
        result = await self.driver.call(
            "evaluate", {"expression": expression, "session_id": self.session_id}
        )
        n = parse_int(result.get("address", result.get("value")))
        if n is None:
            raise VerifyError("evaluate(%r) yielded no integer: %r" % (expression, result))
        return n

    async def _expected_value(self, spec_value: Any) -> int:
        if isinstance(spec_value, dict):
            expr = spec_value.get("expr")
            if expr:
                return await self._eval_int(expr)
            sym = spec_value.get("anchor_offset_of")
            if sym:
                # runtime address of `sym` minus its build-recorded file
                # offset == the executable's load base (offset==vaddr layout)
                off = parse_int(self.symbols.get(sym))
                if off is None:
                    raise VerifyError(
                        "symbol %r not recorded in build manifest" % sym
                    )
                return await self._eval_int("&" + sym) - off
            raise VerifyError("value object requires 'expr' or 'anchor_offset_of'")
        n = parse_int(spec_value)
        if n is None:
            raise VerifyError("unparseable expected value: %r" % (spec_value,))
        return n

    async def _symbol_span(self, symbol: str) -> tuple[int, int]:
        """[start, end) address span for a symbol via the build manifest."""
        symbols = self.symbols
        start = symbols.get(symbol)
        end = symbols.get(symbol + "$end")
        if start is None:
            raise VerifyError("symbol %r not recorded in build manifest" % symbol)
        base = await self._base_addr()
        start_addr = _norm_addr(start) + base
        end_addr = _norm_addr(end) + base if end is not None else start_addr + 0x10000
        return start_addr, end_addr

    async def _base_addr(self) -> int:
        """Load base of the main executable from live mappings."""
        result = await self.driver.call(
            "get_memory_map", {"session_id": self.session_id}
        )
        for seg in result.get("segments", []):
            objfile = str(seg.get("objfile", ""))
            offset = parse_int(seg.get("offset", 0)) or 0
            if self.binary_name and objfile.endswith(self.binary_name) and offset == 0:
                return _norm_addr(seg.get("start"))
        raise VerifyError("no mapping for %r; is the inferior running?" % self.binary_name)

    # -- op dispatch ---------------------------------------------------------

    def set_task_context(self, task: "TaskSpec") -> None:
        self.symbols: dict[str, str] = dict(task.target.symbols)
        self.binary_name = task.target.name

    async def verify(self, check: "Check") -> CheckResult:
        handler = getattr(self, "_op_%s" % check.op, None)
        if handler is None:
            raise VerifyError("no verifier implemented for op %r" % check.op)
        return await handler(**check.spec)

    # -- state ops -----------------------------------------------------------

    async def _op_exit_code(self, code: int) -> CheckResult:
        result = await self.driver.call("get_stop_reason", {"session_id": self.session_id})
        actual = result.get("exited_code")
        # after the inferior exits, gdb returns to its prompt and the
        # session settles into 'ready' — the exit code is still recorded
        passed = (
            result.get("state") in ("exited", "ready") and actual == code
        )
        return CheckResult(
            "exit_code", passed,
            "state=%r exited_code=%r expected=%r" % (result.get("state"), actual, code),
        )

    def _bp_matches(self, bp: dict, spec: dict, resolved_addr: int | None) -> bool:
        if "number" in spec and bp.get("number") != spec["number"]:
            return False
        if "type" in spec:
            wanted = spec["type"]
            if wanted == "watch" and "watchpoint" not in bp.get("type", ""):
                return False
            if wanted in ("breakpoint", "hw") and wanted not in bp.get("type", ""):
                return False
        if "condition" in spec:
            want = str(spec["condition"]).replace(" ", "")
            have = str(bp.get("condition") or "").replace(" ", "")
            if want != have:
                return False
        if "enabled" in spec and bool(bp.get("enabled")) != bool(spec["enabled"]):
            return False
        symbol = spec.get("symbol")
        if symbol is not None:
            where = str(bp.get("where") or "")
            by_addr = resolved_addr is not None and bp.get("addr") == resolved_addr
            by_name = symbol in where
            if not (by_addr or by_name):
                return False
        if "location_contains" in spec and spec["location_contains"] not in str(
            bp.get("where") or ""
        ):
            return False
        return True

    async def _op_breakpoint_present(
        self, symbol: str | None = None, condition: str | None = None,
        type: str | None = None, enabled: bool | None = None,
        min_hit_count: int | None = None, **extra: Any,
    ) -> CheckResult:
        spec: dict[str, Any] = {}
        if symbol is not None:
            spec["symbol"] = symbol
        if condition is not None:
            spec["condition"] = condition
        if type is not None:
            spec["type"] = type
        if enabled is not None:
            spec["enabled"] = enabled
        resolved = None
        if symbol is not None:
            try:
                resolved = _norm_addr(await self._eval_int(symbol))
            except Exception:
                resolved = None  # stripped binary: name match via `where` only
        if resolved is not None:
            for bp in await self._breakpoints():
                if bp.get("addr") is not None:
                    bp["addr"] = _norm_addr(bp["addr"])
        matches = [bp for bp in await self._breakpoints() if self._bp_matches(bp, spec, resolved)]
        if matches and min_hit_count is not None:
            matches = [bp for bp in matches if bp.get("hit_count", 0) >= min_hit_count]
        passed = bool(matches)
        detail = "matched=%d of %s" % (len(matches), [
            {k: bp.get(k) for k in ("number", "type", "addr", "condition", "hit_count")}
            for bp in await self._breakpoints()
        ])
        return CheckResult("breakpoint_present", passed, detail)

    async def _op_breakpoint_hit(
        self, symbol: str | None = None, condition: str | None = None,
        type: str | None = None, **extra: Any,
    ) -> CheckResult:
        import asyncio
        import time

        # stops surface asynchronously relative to the solve's last call —
        # poll for the hit instead of trusting a single snapshot
        deadline = time.monotonic() + 8.0
        present_detail = ""
        while time.monotonic() < deadline:
            present = await self._op_breakpoint_present(
                symbol=symbol, condition=condition, type=type, min_hit_count=1
            )
            if present.passed:
                break
            present_detail = present.detail
            self._bp_cache = None  # re-fetch: hit counters move
            await asyncio.sleep(0.5)
        else:
            return CheckResult("breakpoint_hit", False,
                               "bp not present/hit: " + present_detail)
        stop = await self._stop_info()
        passed = stop.get("reason") == "breakpoint-hit" and stop.get("pc") is not None
        return CheckResult(
            "breakpoint_hit", passed,
            "stop reason=%r pc=%r (bp present with hit_count>=1)" % (stop.get("reason"), stop.get("pc")),
        )

    async def _op_stop_signal(self, signal: str) -> CheckResult:
        stop = await self._stop_info()
        passed = stop.get("signal") == signal
        return CheckResult(
            "stop_signal", passed, "signal=%r expected=%r stop=%s"
            % (stop.get("signal"), signal, stop)
        )

    async def _op_fault_addr(self, addr: Any) -> CheckResult:
        stop = await self._stop_info()
        expected = await self._expected_value(addr)
        actual = _norm_addr(stop.get("fault_addr"))
        passed = actual is not None and actual == _norm_addr(expected)
        return CheckResult(
            "fault_addr", passed, "fault_addr=%s expected=%s" % (_hex(actual or 0), _hex(expected))
        )

    async def _op_memory_value(self, expr: str, size: int = 4, value: Any = None,
                               fmt: str = "uint") -> CheckResult:
        if fmt != "uint":
            raise VerifyError("only fmt=uint supported for now")
        if size not in (1, 2, 4, 8):
            raise VerifyError("size must be 1/2/4/8")
        expected = await self._expected_value(value)
        mem = await self.driver.call(
            "read_memory",
            {"address": expr, "length": size, "session_id": self.session_id},
        )
        hexstr = (mem.get("hex") or "").replace(" ", "")
        if len(hexstr) < size * 2:
            return CheckResult("memory_value", False, "short read: %r" % mem)
        # x86-64 inferior: memory bytes are little-endian
        actual = int.from_bytes(bytes.fromhex(hexstr[: size * 2]), "little")
        passed = actual == (expected & ((1 << (size * 8)) - 1))
        return CheckResult(
            "memory_value", passed,
            "%s (%d bytes) actual=%s expected=%s" % (expr, size, _hex(actual), _hex(expected)),
        )

    async def _op_register_value(self, name: str, value: Any) -> CheckResult:
        expected = await self._expected_value(value)
        result = await self.driver.call(
            "read_registers", {"names": [name], "session_id": self.session_id}
        )
        regs = result.get("regs") or {}
        if name not in regs:
            return CheckResult("register_value", False, "register %r missing: %r" % (name, result))
        actual = parse_int(regs[name])
        passed = actual is not None and actual == (expected & 0xFFFFFFFFFFFFFFFF)
        return CheckResult(
            "register_value", passed,
            "$%s actual=%s expected=%s" % (name, regs[name], _hex(expected)),
        )

    async def _op_variable_value(self, expr: str, value: Any) -> CheckResult:
        expected = await self._expected_value(value)
        result = await self.driver.call(
            "evaluate", {"expression": expr, "session_id": self.session_id}
        )
        actual = parse_int(result.get("value"))
        passed = actual is not None and actual == expected
        return CheckResult(
            "variable_value", passed,
            "%s actual=%r expected=%s (raw %r)" % (expr, actual, expected, result.get("value")),
        )

    async def _op_pc_in_range(self, start_symbol: str | None = None,
                              end_symbol: str | None = None,
                              start: Any = None, end: Any = None) -> CheckResult:
        if start_symbol is not None:
            lo, hi = await self._symbol_span(start_symbol)
            if end_symbol is not None:
                hi, _ = await self._symbol_span(end_symbol)
        elif start is not None:
            lo = await self._expected_value(start)
            hi = await self._expected_value(end) if end is not None else lo + 0x10000
        else:
            raise VerifyError("pc_in_range requires start_symbol or start")
        stop = await self._stop_info()
        pc = _norm_addr(stop.get("pc"))
        if pc is None:
            regs = await self.driver.call(
                "read_registers", {"names": ["rip", "pc"], "session_id": self.session_id}
            ).get("regs") or {}
            pc = next((parse_int(v) for v in regs.values() if parse_int(v) is not None), None)
        passed = pc is not None and lo <= pc < hi
        return CheckResult(
            "pc_in_range", passed, "pc=%s range=[%s, %s)" % (
                _hex(pc) if pc is not None else None, _hex(lo), _hex(hi))
        )

    async def _op_backtrace_contains(self, functions: list[str], ordered: bool = True) -> CheckResult:
        result = await self.driver.call(
            "get_backtrace", {"session_id": self.session_id}
        )
        frames = [str(f.get("function") or "") for f in result.get("frames", [])]
        if ordered:
            it = iter(frames)
            passed = all(any(fn in f for f in it) for fn in functions)
        else:
            passed = all(any(fn in f for f in frames) for fn in functions)
        return CheckResult(
            "backtrace_contains", passed,
            "want=%s ordered=%s frames=%s" % (functions, ordered, frames[:8]),
        )

    async def _op_thread_count(self, min_threads: int) -> CheckResult:
        result = await self.driver.call("list_threads", {"session_id": self.session_id})
        threads = result.get("threads", [])
        passed = len(threads) >= min_threads
        return CheckResult("thread_count", passed, "n=%d min=%d" % (len(threads), min_threads))

    async def _op_thread_stopped_at(self, function: str) -> CheckResult:
        """The *selected* (stopping) thread's frame chain contains `function`."""
        result = await self.driver.call(
            "get_backtrace", {"session_id": self.session_id}
        )
        frames = [str(f.get("function") or "") for f in result.get("frames", [])]
        passed = any(function in f for f in frames)
        return CheckResult(
            "thread_stopped_at", passed, "want=%r frames=%s" % (function, frames[:8])
        )

    async def _op_session_alive(self) -> CheckResult:
        result = await self.driver.call("session_status", {"session_id": self.session_id})
        state = result.get("state")
        passed = state in ("stopped", "running", "ready", "connected", "exited")
        return CheckResult("session_alive", passed, "state=%r" % state)


async def run_checks(driver: "McpDriver", session_id: str, task: "TaskSpec") -> list[CheckResult]:
    verifier = Verifier(driver, session_id)
    verifier.set_task_context(task)
    return [await verifier.verify(check) for check in task.checks]


# -- fact tasks (kind: "fact") -----------------------------------------------

def canonical_fact(value: Any) -> str:
    """Canonical text of a fact: ints compare by value (hex/dec interchangeable),
    everything else as stripped lowercase text."""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (int, str)):
        n = parse_int(value)
        if n is not None:
            return str(n)
    return str(value).strip().lower()


def grade_facts(truth: dict, answer: Any) -> list[CheckResult]:
    """Grade a ``kind: "fact"`` answer against harness-derived truth.

    Every truth field must be present and equal; any answer field outside the
    truth set is a hallucination and fails the task even if the required
    fields are all correct (goal §3: field accuracy, no invented facts).
    """
    if not isinstance(answer, dict):
        return [CheckResult("facts", False, "answer is not a JSON object: %r" % (answer,))]
    results: list[CheckResult] = []
    answer_keys = set(answer)
    truth_keys = set(truth)
    for key in sorted(truth_keys - answer_keys):
        results.append(CheckResult("fact_missing", False, "field %r missing" % key))
    for key in sorted(answer_keys - truth_keys):
        results.append(
            CheckResult("fact_hallucinated", False, "field %r was not requested" % key)
        )
    for key in sorted(truth_keys & answer_keys):
        want, got = truth[key], answer[key]
        passed = canonical_fact(want) == canonical_fact(got)
        results.append(CheckResult("fact", passed, "%s want=%r got=%r" % (key, want, got)))
    if not results:
        results.append(CheckResult("facts", False, "no fact fields defined"))
    return results
