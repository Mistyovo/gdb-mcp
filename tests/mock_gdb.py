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
        for handler in list(self.handlers):
            handler(*args)


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
    if cmd in state.output_map:
        return state.output_map[cmd]
    return ""


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


def post_event(callback):
    state.posted.append(callback)


def flush_posted():
    pending, state.posted = state.posted, []
    for cb in pending:
        cb()


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
    state.newest_frame = MockFrame(0x401000, "main", {"rax": 1, "rbx": 2, "rcx": 3})
    state.selected_frame = None
    state.selected_thread = state.threads[0] if state.threads else None
    return state.inferior
