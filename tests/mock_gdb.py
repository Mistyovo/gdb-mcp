"""Fake ``gdb`` module for testing the in-gdb plugin without a real gdb.

Injected into ``sys.modules["gdb"]`` before loading
``gdb_mcp_plugin.py``. Mutable per-test state lives in :data:`state`; call
:func:`reset` between tests.

Threading note: the mock does not enforce gdb's main-thread rule — tests
call plugin methods directly (as if on the main thread).
"""

from __future__ import annotations

import contextlib
import re

# --- exceptions -------------------------------------------------------------


class error(Exception):
    pass


class MemoryError(error):
    pass


# --- constants --------------------------------------------------------------


VERSION = "15.2"

BP_BREAKPOINT = 1
BP_HARDWARE_BREAKPOINT = 2
BP_WATCHPOINT = 3
BP_HARDWARE_WATCHPOINT = 4
BP_READ_WATCHPOINT = 5
BP_ACCESS_WATCHPOINT = 6

COMMAND_USER = 1

prompt_hook = None


# --- value-ish objects ------------------------------------------------------


class MockType:
    def __init__(self, name="long"):
        self.name = name

    def __str__(self):
        return self.name


class MockValue:
    def __init__(self, val, type_name="long"):
        self._val = val
        self.type = MockType(type_name)

    def __int__(self):
        return int(self._val)

    def __str__(self):
        return str(self._val)


class MockSal:
    def __init__(self, filename, line):
        self.symtab = MockSymtab(filename) if filename else None
        self.line = line


class MockSymtab:
    def __init__(self, filename):
        self.filename = filename


class MockFrame:
    def __init__(self, pc, name="func", regs=None, filename="a.c", line=10):
        self._pc = pc
        self._name = name
        self._regs = dict(regs or {})
        self._regs.setdefault("rip", pc)
        self._older = None
        self._filename = filename
        self._line = line

    def pc(self):
        return self._pc

    def name(self):
        return self._name

    def older(self):
        return self._older

    def read_register(self, name):
        if name not in self._regs:
            # mirrors gdb raising for unavailable vector registers
            raise ValueError("register %s unavailable" % name)
        return MockValue(self._regs[name], "long")

    def find_sal(self):
        return MockSal(self._filename, self._line)

    def select(self):
        state.selected_frame = self


class MockThread:
    def __init__(self, num=1, name="main", running=False, exited=False):
        self.num = num
        self.name = name
        self.ptid = "%d.1" % num
        self._running = running
        self._exited = exited

    def is_running(self):
        return self._running

    def is_exited(self):
        return self._exited


class MockReg:
    def __init__(self, name):
        self.name = name


class MockArch:
    REGS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "eflags"]
    #: instruction stream ends here, so disassembly can run out
    DISASM_END = 0x401000 + 0x40

    def __init__(self, name="x86_64"):
        self._name = name
        self.disasm_calls = []

    def name(self):
        return self._name

    def registers(self):
        return [MockReg(r) for r in self.REGS]

    def disassemble(self, start, count=16):
        self.disasm_calls.append((start, count))
        out = []
        for i in range(count):
            addr = start + 4 * i
            if addr >= self.DISASM_END:
                break
            out.append({"addr": addr, "length": 4, "asm": "nop"})
        return out


class MockProgspace:
    def __init__(self, filename=None):
        self.filename = filename

    def architecture(self):
        return state.arch


class MockInferior:
    def __init__(self, mem_size=0x100000):
        self.progspace = MockProgspace(state.progspace_filename)
        self.memory = bytearray(mem_size)
        self.read_fail = []  # list of (addr, size) raising MemoryError
        self.writes = []

    def read_memory(self, addr, size):
        for bad_addr, bad_size in self.read_fail:
            if addr < bad_addr + bad_size and bad_addr < addr + size:
                raise MemoryError("cannot read memory")
        if addr < 0 or addr + size > len(self.memory):
            raise MemoryError("cannot read memory at 0x%x" % addr)
        return memoryview(bytes(self.memory[addr : addr + size]))

    def write_memory(self, addr, data):
        self.writes.append((addr, bytes(data)))
        end = addr + len(data)
        if end > len(self.memory):
            self.memory.extend(b"\x00" * (end - len(self.memory)))
        self.memory[addr:end] = data

    def threads(self):
        return list(state.threads)

    def architecture(self):
        return state.arch


class MockBreakpoint:
    _next = 1

    def __init__(self, location, type=None, temporary=False, qualified=False):
        self.number = MockBreakpoint._next
        MockBreakpoint._next += 1
        self.location = location
        self.type = type if type is not None else BP_BREAKPOINT
        self.enabled = True
        self.temporary = temporary
        self.pending = False
        self.condition = None
        self.thread = None
        self.hit_count = 0
        state.breakpoints.append(self)

    def delete(self):
        if self in state.breakpoints:
            state.breakpoints.remove(self)


class MockSymbol:
    def __init__(self, value):
        self._value = value

    def value(self):
        return MockValue(self._value)


class MockEventRegistry:
    def __init__(self):
        self.handlers = []

    def connect(self, handler):
        self.handlers.append(handler)
        return handler

    def disconnect(self, handler):
        if handler in self.handlers:
            self.handlers.remove(handler)

    def fire(self, *args):
        # stop-event depth: resumes issued from INSIDE a stop handler are
        # synchronous on real gdb (verified 17.2) — execute() checks this
        # to decide whether to defer
        is_stop = self is events.stop
        if is_stop:
            state._in_stop_event += 1
        try:
            for handler in list(self.handlers):
                handler(*args)
        finally:
            if is_stop:
                state._in_stop_event -= 1


class MockEvents:
    def __init__(self):
        self.stop = MockEventRegistry()
        self.cont = MockEventRegistry()
        self.exited = MockEventRegistry()
        self.before_prompt = MockEventRegistry()
        self.gdb_exiting = MockEventRegistry()


# --- fake stop/exit events ---------------------------------------------------


class FakeStopEvent:
    def __init__(self, signal_name="SIGSEGV", details=None):
        self.stop_signal = signal_name
        self.details = details or {}


class FakeBreakHitEvent:
    def __init__(self, breakpoints):
        self.breakpoints = breakpoints


class FakeExitedEvent:
    def __init__(self, exit_code=139):
        self.exit_code = exit_code


class FakeContEvent:
    pass


# --- module state ------------------------------------------------------------


class _State:
    def __init__(self):
        self.reset()

    def reset(self):
        self.executed = []  # commands run via gdb.execute
        self.output_map = {}  # cmd -> output string
        self.expr_map = {}  # expression -> value (MockValue or raw)
        self.symbols = {}  # name -> MockSymbol
        self.posted = []  # callbacks queued via gdb.post_event
        self.arch = MockArch()
        self.progspace_filename = None
        self.inferior = None
        self.threads = [MockThread(1)]
        self.newest_frame = None
        self.selected_frame = None
        self.selected_thread = self.threads[0] if self.threads else None
        self.breakpoints = []
        self.interrupt_calls = 0
        self.continue_script = []  # simulated stops for execute("continue")
        self.stepi_stride = 4  # pc advance per execute("stepi")
        # fidelity switches (audit 2026-10-07):
        # - resume commands (step/stepi/...) always fire a stop event, like
        #   a real gdb — without it the plugin's state machine never returns
        #   to "stopped" after a synchronous _resume
        # - strict execute raises gdb.error for unmodeled commands, like a
        #   real gdb rejects unknown input (default stays lenient so tests
        #   only modeling output, not errors, keep passing)
        # - async_posted_resume: a resume issued from a posted event (but
        #   NOT from inside a stop handler — nested resumes there are
        #   synchronous, verified on real gdb 17.2) returns immediately;
        #   the stop event fires later from the "event loop", i.e. on the
        #   next flush_posted() — exactly the race _policy_drive exists
        #   to survive, so deferred-policy tests must enable this
        self.fire_stop_on_resume = True
        self.execute_strict = False
        self.async_posted_resume = False
        self.inferior_exited = False  # resume commands raise, like real gdb
        self.resume_hook = None  # optional: hook(cmd) -> True = handled
        self._in_posted = 0  # depth: running inside flush_posted()
        self._in_stop_event = 0  # depth: running inside a stop event fire
        self.writes = []  # gdb.write captures: (text, stream)
        MockBreakpoint._next = 1


state = _State()
events = MockEvents()


def reset():
    state.reset()
    events.stop.handlers = []
    events.cont.handlers = []
    events.exited.handlers = []
    events.before_prompt.handlers = []
    events.gdb_exiting.handlers = []


# --- fake gdb module functions -----------------------------------------------


def execute(cmd, to_string=False):
    state.executed.append(cmd)
    register_assignment = re.fullmatch(
        r"set \$([A-Za-z][A-Za-z0-9_]*) = (.+)", cmd, re.DOTALL
    )
    if register_assignment is not None:
        frame = selected_frame()
        if frame is None:
            raise error("No frame selected.")
        name, expression = register_assignment.groups()
        frame._regs[name] = int(parse_and_eval(expression))
        return ""
    if cmd == "continue" or cmd in _STEP_CMDS:
        if (
            state.async_posted_resume
            and state._in_posted > 0
            and state._in_stop_event == 0
        ):
            # posted-context resume: gdb.execute returns while the
            # inferior still runs; the stop event fires from the event
            # loop — modeled as the next flush_posted() round
            post_event(lambda: _run_resume(cmd))
            return ""
        _run_resume(cmd)
        return ""
    if cmd in state.output_map:
        return state.output_map[cmd]
    if state.execute_strict:
        # real gdb rejects unknown commands; the lenient default only
        # exists so tests that model output for the commands they care
        # about are not forced to enumerate the rest
        raise error('Undefined command: "%s".' % cmd.split()[0])
    return ""


_STEP_CMDS = ("step", "stepi", "next", "nexti", "finish")


def _fire_exit(exit_code):
    state.inferior_exited = True
    state.newest_frame = None
    state.selected_frame = None
    events.exited.fire(FakeExitedEvent(exit_code))


def _run_resume(cmd):
    """Fire the stop/exit event a real gdb would produce for a resume.

    Runs synchronously when called from execute() and again from the
    deferred posted closure — both contexts must behave identically.
    """
    if state.resume_hook is not None and state.resume_hook(cmd):
        return
    if state.inferior_exited:
        raise error("The program is not being run.")
    if cmd == "continue":
        if state.continue_script:
            # simulate the next stop of a real resume: fire the connected
            # event handlers exactly like a real gdb stop would
            action = state.continue_script.pop(0)
            if action[0] == "bp":
                last = state.breakpoints[-1] if state.breakpoints else None
                events.stop.fire(FakeBreakHitEvent([last] if last else []))
            elif action[0] == "bp_num":
                target = next(
                    (b for b in state.breakpoints if b.number == action[1]),
                    None,
                )
                events.stop.fire(FakeBreakHitEvent([target] if target else []))
            elif action[0] == "sig":
                if state.newest_frame is not None:
                    state.newest_frame._pc += action[2] if len(action) > 2 else 0x10
                events.stop.fire(
                    FakeStopEvent(action[1], {"reason": "signal-received"})
                )
            elif action[0] == "exit":
                _fire_exit(action[1] if len(action) > 1 else 0)
            return
        # no scripted stop: a real continue with no breakpoint to hit runs
        # the target to completion — tests must script the stops they mean
        if state.fire_stop_on_resume:
            _fire_exit(0)
        return
    if cmd in _STEP_CMDS:
        # a real gdb ALWAYS stops again after a step-family resume (no
        # script needed) — firing the stop is what returns the plugin's
        # state machine to "stopped" after a synchronous _resume
        if cmd == "stepi" and state.newest_frame is not None:
            state.newest_frame._pc += state.stepi_stride
        if state.fire_stop_on_resume:
            events.stop.fire(FakeStopEvent(None, {"reason": "stepi"}))
        return


def parse_and_eval(expr):
    if expr in state.expr_map:
        raw = state.expr_map[expr]
        return raw if isinstance(raw, MockValue) else MockValue(raw)
    s = str(expr).strip()
    if s.lower().startswith("0x"):
        return MockValue(int(s, 16))
    if s.lstrip("-").isdigit():
        return MockValue(int(s, 10))
    raise error("No symbol \"%s\" in current context." % expr)


STDOUT = 1
ERROR = 2


def write(text, stream=STDOUT):
    """Capture gdb.write output instead of printing (assertable, silent)."""
    state.writes.append((text, stream))


def post_event(callback):
    state.posted.append(callback)


def flush_posted():
    # one batch per call: callbacks queued DURING this batch wait for
    # the next call — one flush_posted() is one beat of gdb's event
    # loop, so tests can observe intermediate states (a deferred policy
    # response mid-chain) by pumping one beat at a time
    pending, state.posted = state.posted, []
    state._in_posted += 1
    try:
        for cb in pending:
            cb()
    finally:
        state._in_posted -= 1


def selected_inferior():
    return state.inferior


def selected_frame():
    return state.selected_frame if state.selected_frame is not None else state.newest_frame


def newest_frame():
    return state.newest_frame


def selected_thread():
    return state.selected_thread


def current_progspace():
    return MockProgspace(state.progspace_filename)


def breakpoints():
    return list(state.breakpoints)


class Breakpoint(MockBreakpoint):
    pass


def lookup_global_symbol(name):
    return state.symbols.get(name)


@contextlib.contextmanager
def blocked_signals():
    yield


def interrupt():
    state.interrupt_calls += 1


class Command:
    def __init__(self, name, command_class):
        self.name = name


def set_inferior(filename="/tmp/vuln"):
    state.progspace_filename = filename
    state.inferior = MockInferior()
    state.inferior_exited = False
    state.newest_frame = MockFrame(0x401000, "main", {"rax": 1, "rbx": 2, "rcx": 3})
    state.selected_frame = None
    state.selected_thread = state.threads[0] if state.threads else None
    return state.inferior
