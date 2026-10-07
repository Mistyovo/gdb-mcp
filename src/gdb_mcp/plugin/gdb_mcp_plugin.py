"""gdb-mcp in-gdb plugin (wire protocol v1).

A self-contained, stdlib-only Python script loaded into gdb via
``-x gdb_mcp_plugin.py`` (or ``source gdb_mcp_plugin.py`` in a gdbscript /
``~/.gdbinit``). It opens a TCP connection to the gdb-mcp server and serves
requests from it.

Design rules (see the gdb-mcp project docs):

* gdb is NOT thread-safe: every ``gdb.*`` API call happens on gdb's main
  thread. The socket reader thread only parses JSON and enqueues requests;
  ``gdb.post_event`` marshals execution onto the main thread.
* Only ``ping`` / ``interrupt`` / ``quit`` are handled on the reader thread.
  ``gdb.interrupt()`` is thread-safe (GDB 15+); the fallback is
  ``os.kill(os.getpid(), SIGINT)``.
* Socket threads block SIGINT/SIGCHLD (``gdb.blocked_signals()`` or
  ``pthread_sigmask``) so a process-directed SIGINT lands on gdb's main
  thread.
* Coexists with pwndbg: only ``connect``s its own event handlers, never
  touches ``gdb.prompt_hook`` and never scrapes the prompt.
* Coexists with pwntools: inert w.r.t. whatever the gdbscript does (e.g.
  ``target remote`` to a gdbserver).

Environment variables:

* ``GDB_MCP_HOST``    - server host (default: try 127.0.0.1, then WSL's
                        default gateway, then /etc/resolv.conf nameservers)
* ``GDB_MCP_PORT``    - server port (default 3939)
* ``GDB_MCP_TOKEN``   - optional shared auth token
* ``GDB_MCP_SESSION_ID`` - session id handed out by the server's launch tool
* ``GDB_MCP_AUTOSTART``  - set to ``0`` to load without connecting
"""

from __future__ import print_function

import json
import hmac
import os
import queue
import re
import shlex
import signal
import socket
import sys
import threading
import time
from collections import deque

import gdb

PLUGIN_VERSION = "0.1.0"
_DEBUG = os.environ.get("GDB_MCP_DEBUG") == "1"


def _dbg(msg):
    if _DEBUG:
        try:
            print("[gdb-mcp-debug] %s" % msg, file=sys.stderr, flush=True)
        except Exception:
            pass
PROTO = 1
DEFAULT_PORT = 3939
READ_BUF = 65536
CONNECT_TIMEOUT = 3.0
SOCK_TIMEOUT = 90.0
BACKOFF = [1, 2, 4, 8, 15, 30]
PUMP_BATCH = 100


def _positive_env_int(name, default):
    try:
        return max(1, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


MAX_LINE = _positive_env_int("GDB_MCP_MAX_ASYNC_LINE", 32 * 1024 * 1024)
EVAL_OUTPUT_LIMIT = _positive_env_int("GDB_MCP_EVAL_OUTPUT_LIMIT", 200 * 1024)
MAX_MEM_READ = _positive_env_int("GDB_MCP_MAX_MEM_READ", 1024 * 1024)
CHUNK_PROBE = 4096
MAX_BACKTRACE_FRAMES = 4096
MAX_DISASM_INSTRUCTIONS = 4096

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_REGISTER_NAME_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_]*\Z")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_TRUNC_MARKER = "\n...[truncated]"

#: commands that escape the debugger; blocked unless GDB_MCP_ALLOW_UNSAFE=1.
#: Mirrors gdb_mcp.security.UNSAFE_COMMAND_PREFIXES (stdlib-only copy).
_UNSAFE_PREFIXES = (
    ("shell", True),
    ("!", False),
    ("pipe", True),
    ("python", True),
    ("python-interactive", True),
    ("pi", True),
    ("source", True),
)


def _is_unsafe_command(command):
    text = str(command).lstrip().lower()
    if not text:
        return False
    for prefix, needs_boundary in _UNSAFE_PREFIXES:
        if not text.startswith(prefix):
            continue
        if not needs_boundary:
            return True
        rest = text[len(prefix) :]
        if rest == "" or rest[0] in (" ", "\t", "-"):
            return True
    return False


def _guard_unsafe_command(command):
    """Block debugger-escaping commands unless GDB_MCP_ALLOW_UNSAFE=1."""
    if os.environ.get("GDB_MCP_ALLOW_UNSAFE") == "1":
        return
    if _is_unsafe_command(command):
        raise PluginError(
            "UNSAFE_BLOCKED",
            "command can execute code outside the debugger; "
            "set GDB_MCP_ALLOW_UNSAFE=1 to allow it",
        )

#: checkpoint (snapshot) knobs: per-segment / total memory budgets and the
#: ring size of kept snapshots. Budgets bound the wire line (hex doubles).
SNAPSHOT_MAX_SEGMENT = 4 * 1024 * 1024
SNAPSHOT_MAX_TOTAL = 8 * 1024 * 1024
SNAPSHOT_HARD_TOTAL = 12 * 1024 * 1024
SNAPSHOT_KEEP = 8
SNAPSHOT_RESTORE_CHUNK = 1024 * 1024
DIFF_ROW_BYTES = 16
DIFF_MAX_ROWS = 256
DIFF_MAX_REGS = 64
POLICY_MAX_STEPS = 4096
POLICY_MAX_EVENTS = 4096
POLICY_TRACE_CAP = 512
POLICY_TIMELINE_READ = 256
POLICY_MAX_PAYLOADS = 64
POLICY_MAX_CRASHES = 32
POLICY_MAX_LOCATIONS = 32
POLICY_MAX_HITS = 1_000_000
IO_BUFFER_CHUNKS = 1024
IO_READ_CHUNK = 4096
IO_MAX_CHUNKS_PER_READ = 64


class _PtyChannel:
    """Unix pty pair feeding the inferior's stdio; the master side is our
    write/read endpoint, the slave path becomes ``set inferior-tty``."""

    def __init__(self):
        master, slave = os.openpty()
        self._master = master
        self.slave_path = os.ttyname(slave)
        self._stop = threading.Event()

    def start(self, sink):
        """Spawn the reader thread; ``sink`` is called with each chunk."""

        def loop():
            while not self._stop.is_set():
                try:
                    data = os.read(self._master, IO_READ_CHUNK)
                except OSError:
                    break
                if not data:
                    break
                sink(data)

        thread = threading.Thread(target=loop, name="gdbmcp-io", daemon=True)
        thread.start()
        return thread

    def write(self, data: bytes) -> int:
        view = memoryview(data)
        total = 0
        while view:
            written = os.write(self._master, view)
            total += written
            view = view[written:]
        return total

    def close(self) -> None:
        self._stop.set()
        try:
            os.close(self._master)
        except OSError:
            pass


def _make_io_channel():
    """Factory indirection so tests can inject a memory-backed channel."""
    return _PtyChannel()


_HAS_OPENPTY = hasattr(os, "openpty")


class _TimelineBreakpoint(gdb.Breakpoint):
    """Allocation probe: records arguments on every hit and returns False
    so the inferior resumes invisibly — the timeline accumulates without
    ever stopping the run."""

    def __init__(self, location, sink, max_events):
        gdb.Breakpoint.__init__(self, location, gdb.BP_BREAKPOINT)
        self._sink = sink
        self._max = max_events

    def stop(self):
        if len(self._sink) >= self._max:
            return True  # budget exhausted: let the inferior stop
        try:
            frame = gdb.selected_frame()
            entry = {"symbol": str(self.location), "pc": "0x%x" % int(frame.pc())}
            older = frame.older()
            if older is not None:
                entry["caller"] = "0x%x" % int(older.pc())
            args = {}
            for name in ("rdi", "rsi", "rdx", "rcx", "r8", "r9",
                         "edi", "esi", "edx", "ecx",
                         "x0", "x1", "x2", "x3", "w0", "w1", "w2", "w3"):
                try:
                    args[name] = "0x%x" % int(frame.read_register(name))
                except Exception:
                    pass
            entry["args"] = args
            self._sink.append(entry)
        except Exception:
            pass
        return False


class _StatsBreakpoint(gdb.Breakpoint):
    """Hit counter: tallies hits per location and auto-continues until
    the shared hit budget is exhausted (the budget-exhausting hit then
    stops the inferior so it can be inspected at native speed)."""

    def __init__(self, location, counts, total, max_hits):
        gdb.Breakpoint.__init__(self, location, gdb.BP_BREAKPOINT)
        self._counts = counts  # location string -> hit count
        self._total = total  # single-element list shared by all probes
        self._max = max_hits

    def stop(self):
        if self._total[0] >= self._max:
            return True
        key = str(self.location)
        self._counts[key] = self._counts.get(key, 0) + 1
        self._total[0] += 1
        return self._total[0] >= self._max

#: handled entirely on the reader thread
READER_VERBS = frozenset(["ping", "interrupt", "quit"])
#: resume verbs: reply before executing, then emit running/stop notifications
ASYNC_VERBS = frozenset(
    ["continue", "step", "next", "stepi", "nexti", "finish", "until",
     "reverse_continue", "reverse_step", "reverse_next"]
)
#: structured verbs rejected while the inferior is running
GATED_VERBS = frozenset(
    [
        "read_mem",
        "write_mem",
        "regs",
        "set_reg",
        "backtrace",
        "disasm",
        "evaluate",
        "threads",
        "frame_select",
        "breakpoints",
        "break",
        "bp_delete",
        "bp_enable",
        "bp_disable",
        "mem_map",
        "snapshot_create",
        "snapshot_list",
        "snapshot_restore",
        "snapshot_diff",
        "policy",
    ]
)
_CONTINUE_CMDS = {
    "continue": "continue",
    "step": "step",
    "next": "next",
    "stepi": "stepi",
    "nexti": "nexti",
    "finish": "finish",
    # gdb native record/replay (start recording with `record full` first);
    # reverse execution blocks exactly like the forward resume verbs
    "reverse_continue": "reverse-continue",
    "reverse_step": "reverse-step",
    "reverse_next": "reverse-next",
}
_BP_TYPES = {
    gdb.BP_BREAKPOINT: "breakpoint",
    gdb.BP_HARDWARE_BREAKPOINT: "hw_breakpoint",
    gdb.BP_WATCHPOINT: "watchpoint",
    gdb.BP_HARDWARE_WATCHPOINT: "hw_watchpoint",
    gdb.BP_READ_WATCHPOINT: "read_watchpoint",
    gdb.BP_ACCESS_WATCHPOINT: "access_watchpoint",
}


class PluginError(Exception):
    def __init__(self, code, message):
        super(PluginError, self).__init__(message)
        self.code = code
        self.message = message


# --- small local helpers (deliberately duplicated from the server package) --


def _strip_ansi(text):
    return _OSC_RE.sub("", _ANSI_RE.sub("", text))


def _ascii_repr(data):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def _memory_segment(addr, data):
    """One readable memory run in the shape read_mem reports."""
    return {
        "addr": addr,
        "length": len(data),
        "hex": data.hex(),
        "ascii": _ascii_repr(data),
    }


def _warn(msg):
    """Surface a plugin problem on gdb's console.

    Used where the failure would otherwise be invisible: the control
    channel may not be up, so the wire cannot carry it either.
    """
    _dbg(msg)
    try:
        gdb.write("[gdb-mcp] %s\n" % msg, gdb.ERROR)
    except Exception:
        try:
            print("[gdb-mcp] %s" % msg, file=sys.stderr, flush=True)
        except Exception:
            pass


def _hex_to_bytes(hexstr):
    h = str(hexstr).strip()
    if h.lower().startswith("0x"):
        h = h[2:]
    h = re.sub(r"\s+", "", h)
    if len(h) % 2 != 0 or any(c not in _HEX_DIGITS for c in h):
        raise ValueError("invalid hex string %r" % hexstr)
    return bytes.fromhex(h)


def _json_safe(obj):
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, dict):
        return dict((str(k), _json_safe(v)) for k, v in obj.items())
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    return str(obj)


def _limited_output(text, strip=True):
    if strip:
        text = _strip_ansi(text)
    if len(text) > EVAL_OUTPUT_LIMIT:
        return {
            "output": text[:EVAL_OUTPUT_LIMIT] + _TRUNC_MARKER,
            "truncated": True,
        }
    return {"output": text, "truncated": False}


def _slice_index(value, name, minimum):
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise PluginError(
            "BAD_PARAMS", "%s must be an int >= %d" % (name, minimum)
        )
    return value


def _eval_window(params):
    """Validated (offset, limit) output window; raises before any command
    runs so a bad window never executes the request."""
    offset = params.get("offset")
    offset = 0 if offset is None else _slice_index(offset, "offset", 0)
    limit = params.get("limit")
    if limit is not None:
        limit = _slice_index(limit, "limit", 1)
    return offset, limit


def _eval_output(text, strip=True, window=(0, None)):
    """:func:`_limited_output` plus line-range readback for eval output.

    Every response carries ``total_lines``; a ranged read additionally
    carries ``offset`` and sets ``truncated`` when further lines remain.
    """
    offset, limit = window
    if strip:
        text = _strip_ansi(text)
    lines = text.splitlines()
    result = {"total_lines": len(lines), "truncated": False}
    if offset or limit is not None:
        stop = None if limit is None else offset + limit
        selected = lines[offset:stop]
        text = "\n".join(selected)
        if offset + len(selected) < len(lines):
            result["truncated"] = True
        if limit is not None:
            result["offset"] = offset
    if len(text) > EVAL_OUTPUT_LIMIT:
        text = text[:EVAL_OUTPUT_LIMIT] + _TRUNC_MARKER
        result["truncated"] = True
    result["output"] = text
    return result


def _probe_features():
    feats = set()
    if hasattr(gdb, "interrupt"):
        feats.add("gdb_interrupt")
    if hasattr(gdb, "blocked_signals"):
        feats.add("blocked_signals")
    if hasattr(gdb, "events"):
        ev = gdb.events
        if hasattr(ev, "before_prompt"):
            feats.add("before_prompt")
        if hasattr(ev, "gdb_exiting"):
            feats.add("gdb_exiting")
    return feats


def _gdb_version():
    try:
        return str(gdb.VERSION)
    except Exception:
        pass
    try:
        out = gdb.execute("show version", to_string=True)
        m = re.search(r"GNU gdb .*?(\d+(?:\.\d+)*)", out or "")
        if m:
            return m.group(1)
    except Exception:
        pass
    return "unknown"


def _arch_name():
    try:
        return gdb.selected_inferior().architecture().name()
    except Exception:
        pass
    try:
        return gdb.current_progspace().architecture().name()
    except Exception:
        pass
    return None


def _inferior_path():
    try:
        inf = gdb.selected_inferior()
        if inf is not None:
            fn = inf.progspace.filename
            if fn:
                return fn
    except Exception:
        pass
    return None


def _pwndbg_loaded():
    if "pwndbg" in sys.modules:
        return True
    try:
        if gdb.prompt_hook is not None:
            return True
    except Exception:
        pass
    return False


def _writable_segments(mappings_text):
    """(start, end) pairs of rw mappings, parsed from ``info proc
    mappings`` text. Tolerates with/without size-column layouts."""
    segments = []
    for raw in mappings_text.splitlines():
        parts = raw.strip().split()
        if len(parts) < 3 or not parts[0].startswith("0x") or not parts[1].startswith("0x"):
            continue
        try:
            start = int(parts[0], 16)
            end = int(parts[1], 16)
        except ValueError:
            continue
        perms = None
        for tok in parts[2:6]:
            if tok and set(tok) <= set("rwxps-") and ("r" in tok or "w" in tok):
                perms = tok
                break
        if perms and "w" in perms and end > start:
            segments.append((start, end))
    return segments


def _bounded_int(value, default, lo, hi):
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise PluginError("BAD_PARAMS", "expected an int, got %r" % (value,))
    return max(lo, min(hi, value))


# --- the plugin ------------------------------------------------------------


class Plugin(object):
    """Bridge between the gdb-mcp server socket and gdb's Python API."""

    def __init__(self):
        # E4: session-scoped token (launch flow) wins over the master
        self.token = (
            os.environ.get("GDB_MCP_SESSION_TOKEN")
            or os.environ.get("GDB_MCP_TOKEN")
        )
        self.session_id = os.environ.get("GDB_MCP_SESSION_ID") or None
        port_env = os.environ.get("GDB_MCP_PORT", "")
        try:
            self.port = int(port_env) if port_env else DEFAULT_PORT
        except ValueError:
            self.port = DEFAULT_PORT
        self.features = _probe_features()
        self.state = "connecting"  # connecting|ready|running|stopped|exited|disconnected
        self.stop_info = None
        self.in_q = queue.Queue()
        self.out_q = queue.Queue()
        self.sock = None
        self.posted = False
        self._pump_lock = threading.Lock()
        self.shutdown_evt = threading.Event()
        self._shutdown_done = False
        self._event_handlers = []
        self._connection = None
        self._wire_generation = 0
        self._snapshots = {}
        self._snapshot_counter = 0
        self._timeline_bps = []
        self._timeline_events = []
        self._timeline_max = POLICY_MAX_EVENTS
        self._io = None
        self._io_buf = deque(maxlen=IO_BUFFER_CHUNKS)
        self._io_seq = 0
        self._io_dropped = 0
        self._io_thread = None
        #: the pty reader thread stamps sequence numbers and appends as one
        #: unit; without this a chunk could be recorded out of order
        self._io_lock = threading.Lock()

    # -- lifecycle ----------------------------------------------------------

    def start(self):
        self._connect_events()
        self._connection = threading.Thread(
            target=self._thread_main,
            args=(self._connection_loop,),
            name="gdbmcp-conn",
            daemon=True,
        )
        self._connection.start()

    def _thread_main(self, fn, *args):
        """Thread entry: block SIGINT/SIGCHLD so those signals land on
        gdb's main thread (gdb installs its own handlers for them)."""
        try:
            if "blocked_signals" in self.features:
                with gdb.blocked_signals():
                    fn(*args)
            else:
                if hasattr(signal, "pthread_sigmask"):
                    try:
                        signal.pthread_sigmask(
                            signal.SIG_BLOCK, {signal.SIGINT, signal.SIGCHLD}
                        )
                    except (ValueError, OSError):
                        pass
                fn(*args)
        except Exception as exc:
            _dbg("socket thread failed: %s" % exc)

    def request_reconnect(self):
        """Drop the current connection; the connect loop re-establishes it."""
        sock = self.sock
        self.sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        self.state = "disconnected"

    def _shutdown(self, kill_gdb=False):
        """Runs on gdb's main thread."""
        if self._shutdown_done:
            return
        self._shutdown_done = True
        self.shutdown_evt.set()
        self._disconnect_events()
        sock = self.sock
        self.sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        self.state = "disconnected"
        if kill_gdb:
            try:
                self._exec("set confirm off")
                self._exec("quit")
            except Exception:
                pass

    # -- connection (reader/conn threads) -----------------------------------

    def _resolve_hosts(self):
        env = os.environ.get("GDB_MCP_HOST", "")
        if env:
            return [h.strip() for h in env.split(",") if h.strip()]
        hosts = ["127.0.0.1"]
        try:
            with open("/proc/net/route") as fh:
                next(fh, None)  # column headings
                for line in fh:
                    fields = line.split()
                    if len(fields) < 8 or fields[1] != "00000000":
                        continue
                    try:
                        gateway_raw = bytes.fromhex(fields[2])
                        flags = int(fields[3], 16)
                    except (TypeError, ValueError):
                        continue
                    if len(gateway_raw) != 4 or flags & 0x3 != 0x3:
                        continue
                    gateway = socket.inet_ntoa(gateway_raw[::-1])
                    if gateway != "0.0.0.0":
                        hosts.append(gateway)
        except OSError:
            pass
        try:
            with open("/etc/resolv.conf") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) == 2 and parts[0] == "nameserver":
                        hosts.append(parts[1])
        except OSError:
            pass
        # Docker Desktop puts its containers behind a VM NAT: the bridge
        # gateway above is the VM, not the machine running gdb-mcp, so the
        # documented alias for reaching the host goes last (an unresolvable
        # name is just another skipped candidate).
        hosts.append("host.docker.internal")
        seen = set()
        out = []
        for h in hosts:
            if h not in seen:
                seen.add(h)
                out.append(h)
        return out

    def _connect_once(self):
        for host in self._resolve_hosts():
            try:
                sock = socket.create_connection(
                    (host, self.port), timeout=CONNECT_TIMEOUT
                )
                sock.settimeout(SOCK_TIMEOUT)
                return sock
            except OSError:
                continue
        return None

    def _connection_loop(self):
        backoff_idx = 0
        warned = False
        while not self.shutdown_evt.is_set():
            sock = self._connect_once()
            if sock is None:
                if not warned:
                    print(
                        "[gdb-mcp] MCP server unreachable; retrying in the background",
                        file=sys.stderr,
                    )
                    warned = True
                delay = BACKOFF[min(backoff_idx, len(BACKOFF) - 1)]
                self.shutdown_evt.wait(delay)
                backoff_idx += 1
                continue
            warned = False
            backoff_idx = 0
            self._wire_generation += 1
            generation = self._wire_generation
            stop_evt = threading.Event()
            self.sock = sock
            self.state = "connecting"
            self._send_hello(sock)
            reader = threading.Thread(
                target=self._thread_main,
                args=(self._reader_loop, sock, stop_evt),
                name="gdbmcp-reader",
                daemon=True,
            )
            writer = threading.Thread(
                target=self._thread_main,
                args=(self._writer_loop, sock, stop_evt, generation),
                name="gdbmcp-writer",
                daemon=True,
            )
            reader.start()
            writer.start()
            reader.join()
            stop_evt.set()
            try:
                sock.close()
            except OSError:
                pass
            writer.join(2.0)
            self._on_socket_lost(sock)

    def _send_hello(self, sock):
        hello = {
            "type": "hello",
            "proto": PROTO,
            "session_id": self.session_id,
            "pid": os.getpid(),
            "gdb_version": _gdb_version(),
            "python_version": "%d.%d.%d" % sys.version_info[:3],
            "arch": _arch_name(),
            "inferior": _inferior_path(),
            "pwndbg": _pwndbg_loaded(),
            "features": sorted(self.features),
            "hostname": socket.gethostname(),
            "plugin_version": PLUGIN_VERSION,
            # E1: let the server fail fast on plugin/server build mismatch
            "verbs": sorted(
                set(VERB_HANDLERS) | ASYNC_VERBS | READER_VERBS
            ),
        }
        try:
            sock.sendall(self._encode_msg(hello))
        except OSError:
            pass

    def _on_socket_lost(self, sock=None):
        if sock is None:
            sock = self.sock
        if self.sock is sock:
            self.sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        self.state = "disconnected"

    def _reader_loop(self, sock, stop_evt):
        buf = b""
        while not self.shutdown_evt.is_set() and not stop_evt.is_set():
            try:
                data = sock.recv(READ_BUF)
            except OSError:
                return
            if not data:
                return
            buf += data
            if len(buf) > MAX_LINE and b"\n" not in buf:
                return
            while True:
                nl = buf.find(b"\n")
                if nl == -1:
                    break
                raw, buf = buf[:nl], buf[nl + 1 :]
                if raw.endswith(b"\r"):
                    raw = raw[:-1]
                try:
                    self._dispatch_line(raw)
                except Exception:
                    # malformed line: drop it, keep the connection
                    continue

    def _dispatch_line(self, raw):
        if len(raw) > MAX_LINE:
            return
        try:
            msg = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            # RecursionError: deep nesting aborts the parser before it can
            # raise ValueError; the line is garbage either way — drop it
            return
        if not isinstance(msg, dict):
            return
        if "msg" in msg:
            supplied = msg.get("token")
            if (
                self.token is None
                or not isinstance(supplied, str)
                or not hmac.compare_digest(
                    supplied.encode("utf-8"), self.token.encode("utf-8")
                )
            ):
                return
            msg = msg["msg"]
            if not isinstance(msg, dict):
                return
        elif self.token is not None:
            return  # missing token
        mtype = msg.get("type")
        if mtype == "request":
            self._dispatch_request(msg)
        elif mtype == "quit":
            kill = bool(msg.get("kill_gdb", False))
            gdb.post_event(lambda: self._shutdown(kill))
        elif mtype == "hello_ack":
            if msg.get("proto") != PROTO:
                self.request_reconnect()
                return
            self.session_id = msg.get("session_id") or self.session_id
            # hello_ack also advertises server capabilities; the plugin has
            # no behavior that depends on them, so nothing records them
            heartbeat = msg.get("heartbeat_sec")
            if isinstance(heartbeat, (int, float)) and heartbeat > 0:
                try:
                    self.sock.settimeout(max(30.0, float(heartbeat) * 3.0))
                except (AttributeError, OSError):
                    pass
            self.state = "ready"
            self._notify("ready", {"session_id": self.session_id})

    def _dispatch_request(self, msg):
        verb = msg.get("verb")
        if verb in READER_VERBS:
            self._handle_reader_verb(msg)
            return
        if verb in ASYNC_VERBS and self.state == "running":
            self._send_error(
                msg.get("id"), "INFERIOR_RUNNING", "inferior is already running"
            )
            return
        if verb in GATED_VERBS and self.state == "running":
            self._send_error(
                msg.get("id"),
                "INFERIOR_RUNNING",
                "inferior is running; interrupt first",
            )
            return
        self.in_q.put(msg)
        self._post_pump()

    def _writer_loop(self, sock, stop_evt, generation):
        while not self.shutdown_evt.is_set() and not stop_evt.is_set():
            try:
                queued_generation, line = self.out_q.get(timeout=0.5)
            except queue.Empty:
                continue
            if queued_generation != generation:
                continue
            try:
                sock.sendall(line)
                _dbg("sent %d bytes" % len(line))
            except OSError:
                _dbg("sendall failed")
                stop_evt.set()
                return

    # -- reader-thread verbs -------------------------------------------------

    def _handle_reader_verb(self, req):
        verb = req.get("verb")
        req_id = req.get("id")
        if verb == "ping":
            self._send_response(req_id, True, result={"pong": True})
        elif verb == "interrupt":
            try:
                # Verified empirically (gdb 17.2): gdb.interrupt() does NOT
                # stop an inferior resumed asynchronously from a posted
                # event, and a process-directed SIGINT is swallowed. The
                # mechanism that works is posting the `interrupt` command
                # onto gdb's event loop (which stays live while the
                # inferior runs).
                gdb.post_event(self._do_interrupt)
                self._send_response(
                    req_id, True, result={"state": "interrupt_requested"}
                )
            except Exception as exc:
                self._send_response(
                    req_id,
                    False,
                    error={"code": "INTERRUPT_FAILED", "message": str(exc)},
                )
        elif verb == "quit":
            kill = bool((req.get("params") or {}).get("kill_gdb", False))
            gdb.post_event(lambda: self._shutdown(kill))
        else:  # pragma: no cover
            self._send_error(req_id, "UNKNOWN_VERB", "unknown verb %r" % verb)

    def _do_interrupt(self):
        """Runs on gdb's main thread; interrupts the running inferior."""
        try:
            self._exec("interrupt", to_string=False)
        except Exception:
            # last resort (gdb >= 15): thread-safe interrupt API
            if "gdb_interrupt" in self.features:
                try:
                    gdb.interrupt()
                except Exception:
                    pass

    # -- main-thread dispatch ------------------------------------------------

    def _post_pump(self):
        # `posted` is read by this (main) thread and cleared in _pump; the
        # reader thread only ever queues onto in_q, so a lost duplicate post
        # would mean at most one extra empty pump - the lock keeps the
        # bookkeeping honest without costing a syscall per request.
        with self._pump_lock:
            if not self.posted:
                self.posted = True
                gdb.post_event(self._pump)

    def _pump(self):
        """Runs on gdb's main thread; executes queued requests."""
        with self._pump_lock:
            self.posted = False
        try:
            n = 0
            while n < PUMP_BATCH:
                try:
                    req = self.in_q.get_nowait()
                except queue.Empty:
                    break
                n += 1
                self._handle_request(req)
        finally:
            if not self.in_q.empty():
                self._post_pump()

    def _handle_request(self, req):
        verb = req.get("verb")
        req_id = req.get("id")
        params = req.get("params") or {}
        try:
            if verb in ASYNC_VERBS:
                self._handle_continue_family(req_id, verb, params)
                return
            handler = VERB_HANDLERS.get(verb)
            if handler is None:
                raise PluginError("UNKNOWN_VERB", "unknown verb %r" % verb)
            if verb in GATED_VERBS:
                self._guard_stopped()
            result = handler(self, params)
            self._send_response(req_id, True, result=result)
        except PluginError as exc:
            self._send_response(
                req_id, False, error={"code": exc.code, "message": exc.message}
            )
        except Exception as exc:
            self._send_response(
                req_id, False, error={"code": "PLUGIN_ERROR", "message": str(exc)}
            )

    # -- guards and small helpers -------------------------------------------

    def _guard_stopped(self):
        if self.state == "running":
            raise PluginError(
                "INFERIOR_RUNNING", "inferior is running; interrupt first"
            )

    def _require_inferior(self):
        try:
            inf = gdb.selected_inferior()
        except Exception:
            inf = None
        if inf is None:
            raise PluginError(
                "NO_INFERIOR",
                "no inferior loaded; use the file/load_target tool first",
            )
        return inf

    def _require_frame(self):
        self._require_inferior()
        try:
            frame = gdb.selected_frame()
        except Exception:
            frame = None
        if frame is None:
            raise PluginError("NO_FRAME", "no stack frame selected")
        return frame

    def _resolve_addr(self, expr):
        if isinstance(expr, bool):
            raise PluginError("BAD_PARAMS", "invalid address expression")
        if isinstance(expr, int):
            return expr
        if not isinstance(expr, str) or not expr.strip():
            raise PluginError("BAD_PARAMS", "address is required")
        s = expr.strip()
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", s):
            return int(s, 16)
        if s.isdigit():
            return int(s, 10)
        val = None
        try:
            val = gdb.parse_and_eval(s)
        except gdb.error:
            pass
        addr = None
        if val is not None:
            try:
                addr = int(val)
            except (TypeError, ValueError, gdb.error):
                addr = None  # e.g. function symbols: cannot convert to int
        if addr is None:
            try:
                sym = gdb.lookup_global_symbol(s)
                if sym is not None and sym.value() is not None:
                    try:
                        addr = int(sym.value().address)
                    except (TypeError, ValueError, gdb.error):
                        addr = None
            except Exception:
                addr = None
        if addr is None:
            # function / minimal symbols (incl. plain asm labels): the
            # bare name evaluates to a function value that refuses
            # int(), but &name is a plain pointer
            try:
                addr = int(gdb.parse_and_eval("&" + s))
            except Exception:
                addr = None
        if addr is None:
            raise PluginError(
                "BAD_PARAMS", "expression %r is not an address" % expr
            )
        return addr

    def _fmt_value(self, value):
        try:
            return "0x%x" % int(value)
        except Exception:
            return str(value)

    def _frame_entry(self, frame, level):
        entry = {"level": level}
        try:
            entry["pc"] = "0x%x" % int(frame.pc())
        except Exception:
            pass
        try:
            name = frame.name()
            if name:
                entry["function"] = name
        except Exception:
            pass
        try:
            sal = frame.find_sal()
            if sal is not None and sal.symtab is not None:
                entry["file"] = sal.symtab.filename
                if sal.line:
                    entry["line"] = sal.line
        except Exception:
            pass
        return entry

    # -- resume verbs ---------------------------------------------------------

    def _resume(self, cmd):
        """Resume the inferior on the main thread and return once it stops
        again.

        This is the one resume primitive. ``gdb.execute("continue")`` blocks
        the main thread until the next stop (running gdb's event loop in the
        meantime, which is how ``stop_info`` gets refreshed), so a policy can
        drive rounds by calling this directly instead of faking a wire
        request. Callers must have checked the stopped/inferior preconditions.
        """
        self.state = "running"
        try:
            self._exec(cmd, to_string=False)
        except gdb.error as exc:
            self.state = "stopped"
            self._notify("prompt", {"note": "resume failed: %s" % exc})
            raise PluginError("PLUGIN_ERROR", "resume failed: %s" % exc) from exc

    def _drop_breakpoint(self, number):
        """Delete a policy breakpoint. A temporary breakpoint that was hit
        has already consumed itself, and that is not an error."""
        try:
            self._handle_bp_delete({"number": number})
        except PluginError:
            pass

    def _policy_resume(self):
        """Resume the inferior for a plugin-side policy round.

        The preconditions of the wire ``continue`` verb, but a violation is
        raised to the waiting policy instead of being answered on a request
        id that does not exist.
        """
        self._guard_stopped()
        self._require_inferior()
        self._resume("continue")

    def _resume_command(self, verb, params):
        """The gdb CLI command for a resume verb, or None if it is not one."""
        cmd = _CONTINUE_CMDS.get(verb)
        if cmd is None and verb == "until":
            until_addr = params.get("until_addr")
            cmd = "until *0x%x" % self._resolve_addr(until_addr) if until_addr else "until"
        return cmd

    def _handle_continue_family(self, req_id, verb, params):
        cmd = self._resume_command(verb, params)
        if cmd is None:  # pragma: no cover - dispatch only routes resume verbs
            self._send_error(req_id, "UNKNOWN_VERB", "unknown verb %r" % verb)
            return
        if self.state == "running":
            self._send_error(
                req_id, "INFERIOR_RUNNING", "inferior is already running"
            )
            return
        try:
            inf = gdb.selected_inferior()
        except Exception:
            inf = None
        if inf is None:
            self._send_error(req_id, "NO_INFERIOR", "no inferior loaded")
            return
        # reply before executing: the response must reach the server even
        # though the inferior will now run for an unbounded time
        self._send_response(req_id, True, result={"state": "running"})
        try:
            self._resume(cmd)
        except PluginError:
            pass  # already reported through the prompt notification

    # -- sync verb handlers ---------------------------------------------------

    def _handle_eval(self, params):
        command = params.get("command")
        if not command:
            raise PluginError("BAD_PARAMS", "command is required")
        window = _eval_window(params)
        _guard_unsafe_command(command)
        keep_ansi = bool(params.get("keep_ansi", False))
        out = self._exec(str(command)) or ""
        return _eval_output(out, strip=not keep_ansi, window=window)

    def _handle_read_mem(self, params):
        addr = self._resolve_addr(params.get("addr"))
        length = params.get("length", 64)
        if not isinstance(length, int) or not (1 <= length <= MAX_MEM_READ):
            raise PluginError(
                "BAD_PARAMS", "length must be an int between 1 and %d" % MAX_MEM_READ
            )
        inf = self._require_inferior()
        try:
            data = bytes(inf.read_memory(addr, length))
            segment = _memory_segment(addr, data)
            return {
                **segment,
                "segments": [segment],
                "unreadable": [],
                "partial": False,
            }
        except gdb.MemoryError:
            pass
        # chunked fallback: report unreadable regions instead of failing
        segments = []
        unreadable = []
        off = 0
        current_addr = None
        current_data = bytearray()

        def flush_segment():
            if current_addr is not None:
                segments.append(_memory_segment(current_addr, bytes(current_data)))

        while off < length:
            size = min(CHUNK_PROBE, length - off)
            try:
                piece = bytes(inf.read_memory(addr + off, size))
                if current_addr is None:
                    current_addr = addr + off
                current_data.extend(piece)
            except gdb.MemoryError:
                flush_segment()
                current_addr = None
                current_data = bytearray()
                unreadable.append({"addr": addr + off, "length": size})
            off += size
        flush_segment()
        return {
            "addr": addr,
            "length": length,
            "hex": None,
            "ascii": None,
            "segments": segments,
            "unreadable": unreadable,
            "partial": True,
        }

    def _handle_write_mem(self, params):
        addr = self._resolve_addr(params.get("addr"))
        try:
            data = _hex_to_bytes(params.get("hex", ""))
        except ValueError as exc:
            raise PluginError("BAD_PARAMS", str(exc))
        if not data or len(data) > MAX_MEM_READ:
            raise PluginError(
                "BAD_PARAMS",
                "write length must be between 1 and %d bytes" % MAX_MEM_READ,
            )
        inf = self._require_inferior()
        inf.write_memory(addr, data)
        return {"addr": addr, "bytes_written": len(data)}

    def _handle_regs(self, params):
        frame = self._require_frame()
        try:
            arch = gdb.selected_inferior().architecture()
        except Exception:
            arch = None
        names = params.get("names")
        regs = {}
        if names:
            for name in names:
                try:
                    regs[str(name)] = self._fmt_value(frame.read_register(str(name)))
                except (gdb.error, ValueError):
                    continue
            return {"regs": regs}
        if arch is None:
            raise PluginError("NO_INFERIOR", "no architecture available")
        for r in arch.registers():
            try:
                regs[r.name] = self._fmt_value(frame.read_register(r.name))
            except (gdb.error, ValueError):
                continue
        return {"regs": regs}

    def _handle_set_reg(self, params):
        name = params.get("name")
        value_expr = params.get("value")
        if not name or value_expr is None:
            raise PluginError("BAD_PARAMS", "name and value are required")
        frame = self._require_frame()
        name = str(name)
        if _REGISTER_NAME_RE.fullmatch(name) is None:
            raise PluginError("BAD_PARAMS", "invalid register name: %r" % name)
        old = self._fmt_value(frame.read_register(name))
        try:
            gdb.parse_and_eval(str(value_expr))
        except gdb.error as exc:
            raise PluginError(
                "BAD_PARAMS", "cannot evaluate %r: %s" % (value_expr, exc)
            )
        try:
            # gdb.Frame exposes read_register but no write_register API.
            self._exec("set $%s = %s" % (name, str(value_expr)))
        except (gdb.error, ValueError) as exc:
            raise PluginError("PLUGIN_ERROR", "write_register failed: %s" % exc)
        new = self._fmt_value(frame.read_register(name))
        return {"name": name, "old": old, "new": new}

    def _handle_backtrace(self, params):
        max_frames = params.get("max_frames", 64)
        if (
            not isinstance(max_frames, int)
            or isinstance(max_frames, bool)
            or not (1 <= max_frames <= MAX_BACKTRACE_FRAMES)
        ):
            raise PluginError(
                "BAD_PARAMS",
                "max_frames must be between 1 and %d" % MAX_BACKTRACE_FRAMES,
            )
        try:
            frame = gdb.newest_frame()
        except gdb.error:
            raise PluginError("NO_FRAME", "no stack frame available")
        if frame is None:
            raise PluginError("NO_FRAME", "no stack frame available")
        frames = []
        level = 0
        while frame is not None and level < max_frames:
            frames.append(self._frame_entry(frame, level))
            frame = frame.older()
            level += 1
        # one extra walk tells the caller the stack continues
        return {"frames": frames, "truncated": frame is not None}

    def _handle_disasm(self, params):
        count = params.get("count", 16)
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or not (1 <= count <= MAX_DISASM_INSTRUCTIONS)
        ):
            raise PluginError(
                "BAD_PARAMS",
                "count must be between 1 and %d" % MAX_DISASM_INSTRUCTIONS,
            )
        start = params.get("start")
        if start is None:
            frame = self._require_frame()
            start = int(frame.pc())
        else:
            start = self._resolve_addr(start)
        try:
            arch = gdb.selected_inferior().architecture()
        except Exception:
            try:
                arch = gdb.current_progspace().architecture()
            except Exception:
                raise PluginError("NO_INFERIOR", "no architecture available")
        insns = []
        truncated = False
        try:
            # ask for one extra instruction so we can report continuation
            fetched = list(arch.disassemble(start, count=count + 1))
        except gdb.MemoryError as exc:
            raise PluginError(
                "MEMORY_ERROR", "cannot disassemble at 0x%x: %s" % (start, exc)
            )
        if len(fetched) > count:
            truncated = True
            fetched = fetched[:count]
        for ins in fetched:
            insns.append(
                {
                    "addr": "0x%x" % int(ins["addr"]),
                    "size": int(ins["length"]),
                    "asm": str(ins["asm"]),
                }
            )
        return {"start": "0x%x" % start, "instructions": insns, "truncated": truncated}

    def _handle_evaluate(self, params):
        expr = params.get("expression")
        if not expr:
            raise PluginError("BAD_PARAMS", "expression is required")
        try:
            value = gdb.parse_and_eval(str(expr))
        except gdb.error as exc:
            raise PluginError(
                "PLUGIN_ERROR", "cannot evaluate %r: %s" % (expr, exc)
            )
        result = {
            "expression": str(expr),
            "type": str(value.type),
            "value": str(value),
        }
        try:
            result["address"] = "0x%x" % int(value)
        except (TypeError, ValueError, gdb.error):
            pass  # e.g. function symbols: no integer address
        return result

    def _handle_threads(self, params):
        inf = self._require_inferior()
        selected = None
        try:
            sel = gdb.selected_thread()
            if sel is not None:
                selected = sel.num
        except Exception:
            pass
        threads = []
        for thr in inf.threads():
            if thr.is_running():
                state = "running"
            elif thr.is_exited():
                state = "exited"
            else:
                state = "stopped"
            threads.append(
                {
                    "num": thr.num,
                    "ptid": str(thr.ptid),
                    "name": thr.name,
                    "state": state,
                    "selected": thr.num == selected,
                }
            )
        return {"threads": threads, "selected": selected}

    def _handle_frame_select(self, params):
        level = params.get("level")
        if not isinstance(level, int) or level < 0:
            raise PluginError("BAD_PARAMS", "level must be a non-negative int")
        try:
            frame = gdb.newest_frame()
        except gdb.error:
            raise PluginError("NO_FRAME", "no stack frame available")
        if frame is None:
            raise PluginError("NO_FRAME", "no stack frame available")
        for _ in range(level):
            frame = frame.older()
            if frame is None:
                raise PluginError("NO_FRAME", "no frame at level %d" % level)
        frame.select()
        return {"frame": self._frame_entry(frame, level)}

    def _bp_entry(self, bp):
        entry = {
            "number": bp.number,
            "enabled": bp.enabled,
            "type": _BP_TYPES.get(getattr(bp, "type", None), "breakpoint"),
            "location": bp.location,
            "hit_count": bp.hit_count,
        }
        try:
            entry["condition"] = bp.condition
        except Exception:
            pass
        try:
            entry["thread"] = bp.thread
        except Exception:
            pass
        loc = str(bp.location or "").strip()
        m = re.fullmatch(r"\*?(0[xX][0-9a-fA-F]+)", loc)
        if m:
            entry["addr"] = m.group(1)
        return entry

    def _handle_breakpoints(self, params):
        return {"breakpoints": [self._bp_entry(bp) for bp in gdb.breakpoints()]}

    def _handle_break(self, params):
        location = params.get("location")
        if not location:
            raise PluginError("BAD_PARAMS", "location is required")
        type_map = {
            "breakpoint": gdb.BP_BREAKPOINT,
            "hw": gdb.BP_HARDWARE_BREAKPOINT,
            "watch": gdb.BP_WATCHPOINT,
            "hw_watch": gdb.BP_HARDWARE_WATCHPOINT,
        }
        type_str = params.get("type", "breakpoint")
        bptype = type_map.get(type_str)
        if bptype is None:
            raise PluginError(
                "BAD_PARAMS", "type must be one of %s" % sorted(type_map)
            )
        # Validate and gate `commands` BEFORE creating the breakpoint so a
        # rejected request leaves no half-configured breakpoint behind.
        commands = params.get("commands")
        if commands is not None and not isinstance(commands, list):
            raise PluginError("BAD_PARAMS", "commands must be a list of strings")
        if commands and any(not isinstance(c, str) for c in commands):
            raise PluginError("BAD_PARAMS", "commands must be a list of strings")
        if commands:
            # bp.commands run as raw gdb CLI on hit — they reach the same
            # debugger-escape surface as eval, so the same gate applies.
            for c in commands:
                _guard_unsafe_command(c)
        # Note: gdb.Breakpoint has no `pending` constructor arg (the
        # breakpoint.pending attribute is read-only); pending creation is
        # done via the global "set breakpoint pending" setting.
        pending = bool(params.get("pending", False))
        if pending:
            self._exec("set breakpoint pending on")
        try:
            bp = self._create_breakpoint(
                str(location), bptype, bool(params.get("temporary", False))
            )
            if params.get("condition"):
                bp.condition = str(params["condition"])
            if params.get("thread") is not None:
                bp.thread = int(params["thread"])
        except gdb.error as exc:
            raise PluginError("PLUGIN_ERROR", "failed to set breakpoint: %s" % exc)
        finally:
            if pending:
                self._exec("set breakpoint pending auto")
        auto_continue = bool(params.get("auto_continue", False))
        has_commands = bool(commands) or auto_continue
        if has_commands:
            lines = ["silent"] + list(commands or [])
            if auto_continue:
                lines.append("continue")
            try:
                bp.commands = "\n".join(lines)
            except (gdb.error, AttributeError) as exc:
                raise PluginError(
                    "PLUGIN_ERROR", "cannot set breakpoint commands: %s" % exc
                )
        return {
            "number": bp.number,
            "type": type_str,
            "enabled": bp.enabled,
            "has_commands": has_commands,
        }

    @staticmethod
    def _create_breakpoint(spec, bptype, temporary):
        """gdb.Breakpoint with a version fallback: `qualified` exists only
        on gdb >= 11 and older gdbs raise TypeError on unknown kwargs."""
        kwargs = {"type": bptype}
        if temporary:
            kwargs["temporary"] = True
        while True:
            try:
                return gdb.Breakpoint(spec, **kwargs)
            except TypeError:
                if "temporary" in kwargs:
                    kwargs.pop("temporary")
                    continue
                raise

    def _find_bp(self, number):
        for bp in gdb.breakpoints():
            if bp.number == number:
                return bp
        raise PluginError("BAD_PARAMS", "no breakpoint %d" % number)

    def _handle_bp_delete(self, params):
        number = params.get("number")
        if not isinstance(number, int):
            raise PluginError("BAD_PARAMS", "number must be an int")
        self._find_bp(number).delete()
        return {"number": number, "deleted": True}

    def _handle_bp_enable(self, params):
        number = params.get("number")
        if not isinstance(number, int):
            raise PluginError("BAD_PARAMS", "number must be an int")
        bp = self._find_bp(number)
        bp.enabled = True
        return {"number": number, "enabled": True}

    def _handle_bp_disable(self, params):
        number = params.get("number")
        if not isinstance(number, int):
            raise PluginError("BAD_PARAMS", "number must be an int")
        bp = self._find_bp(number)
        bp.enabled = False
        return {"number": number, "enabled": False}

    def _handle_mem_map(self, params):
        out = self._exec("info proc mappings") or ""
        return _limited_output(out)

    def _handle_file(self, params):
        path = params.get("path")
        if not path:
            raise PluginError("BAD_PARAMS", "path is required")
        out = self._exec("file %s" % shlex.quote(str(path))) or ""
        return _limited_output(out)

    def _handle_core(self, params):
        path = params.get("path")
        if not path:
            raise PluginError("BAD_PARAMS", "path is required")
        out = self._exec("core-file %s" % shlex.quote(str(path))) or ""
        return _limited_output(out)

    # -- checkpoints (registers + writable memory snapshots) -----------------

    def _find_snapshot(self, params):
        sid = params.get("snapshot_id")
        snap = self._snapshots.get(sid) if isinstance(sid, str) else None
        if snap is None:
            known = ", ".join(self._snapshots) or "none"
            raise PluginError(
                "BAD_PARAMS", "unknown snapshot_id %r (kept: %s)" % (sid, known)
            )
        return sid, snap

    def _handle_snapshot_create(self, params):
        self._guard_stopped()
        max_segment = _bounded_int(
            params.get("max_segment_bytes"),
            SNAPSHOT_MAX_SEGMENT,
            1024,
            SNAPSHOT_HARD_TOTAL,
        )
        max_total = _bounded_int(
            params.get("max_total_bytes"),
            max(max_segment, SNAPSHOT_MAX_TOTAL),
            max_segment,
            SNAPSHOT_HARD_TOTAL,
        )
        regs = self._handle_regs({}).get("regs", {})
        mappings = self._handle_mem_map({}).get("output", "")
        inf = self._require_inferior()
        taken = []
        skipped = []
        total = 0
        for start, end in _writable_segments(mappings):
            size = end - start
            entry = {"addr": "0x%x" % start, "length": size}
            if size > max_segment:
                entry["reason"] = "segment exceeds max_segment_bytes"
                skipped.append(entry)
                continue
            if total + size > max_total:
                entry["reason"] = "total budget exhausted"
                skipped.append(entry)
                continue
            try:
                data = bytes(inf.read_memory(start, size))
            except gdb.MemoryError:
                entry["reason"] = "unreadable"
                skipped.append(entry)
                continue
            taken.append((start, data))
            total += size
        self._snapshot_counter += 1
        sid = "ck-%d" % self._snapshot_counter
        self._snapshots[sid] = {
            "regs": regs,
            "segments": taken,
            "total_bytes": total,
            "created": time.time(),
        }
        while len(self._snapshots) > SNAPSHOT_KEEP:
            self._snapshots.pop(next(iter(self._snapshots)))
        return {
            "snapshot_id": sid,
            "registers": len(regs),
            "segments": [
                {"addr": "0x%x" % addr, "length": len(data)} for addr, data in taken
            ],
            "skipped": skipped,
            "total_bytes": total,
        }

    def _handle_snapshot_list(self, params):
        return {
            "snapshots": [
                {
                    "snapshot_id": sid,
                    "created": snap["created"],
                    "total_bytes": snap["total_bytes"],
                    "segments": len(snap["segments"]),
                    "registers": len(snap["regs"]),
                }
                for sid, snap in self._snapshots.items()
            ]
        }

    def _handle_snapshot_restore(self, params):
        sid, snap = self._find_snapshot(params)
        regs_written = 0
        regs_skipped = []
        for name, value in snap["regs"].items():
            try:
                self._handle_set_reg({"name": name, "value": value})
                regs_written += 1
            except PluginError as exc:
                regs_skipped.append({"name": name, "reason": exc.message})
        segments_written = 0
        segments_skipped = []
        for addr, data in snap["segments"]:
            try:
                for off in range(0, len(data), SNAPSHOT_RESTORE_CHUNK):
                    chunk = data[off : off + SNAPSHOT_RESTORE_CHUNK]
                    self._handle_write_mem({"addr": addr + off, "hex": chunk.hex()})
                segments_written += 1
            except PluginError as exc:
                segments_skipped.append(
                    {"addr": "0x%x" % addr, "reason": exc.message}
                )
        return {
            "snapshot_id": sid,
            "registers_written": regs_written,
            "registers_skipped": regs_skipped,
            "segments_written": segments_written,
            "segments_skipped": segments_skipped,
        }

    def _handle_snapshot_diff(self, params):
        sid, snap = self._find_snapshot(params)
        inf = self._require_inferior()
        current_regs = self._handle_regs({}).get("regs", {})
        regs_changed = []
        regs_truncated = False
        for name, old in snap["regs"].items():
            new = current_regs.get(name)
            if new is None or new == old:
                continue
            if len(regs_changed) >= DIFF_MAX_REGS:
                regs_truncated = True
                break
            regs_changed.append({"name": name, "old": old, "new": new})
        rows = []
        memory_truncated = False
        segments_skipped = []
        for addr, data in snap["segments"]:
            try:
                current = bytes(inf.read_memory(addr, len(data)))
            except gdb.MemoryError:
                segments_skipped.append(
                    {"addr": "0x%x" % addr, "reason": "unreadable"}
                )
                continue
            if current == data:
                continue
            for off in range(0, len(data), DIFF_ROW_BYTES):
                old_row = data[off : off + DIFF_ROW_BYTES]
                new_row = current[off : off + DIFF_ROW_BYTES]
                if old_row == new_row:
                    continue
                if len(rows) >= DIFF_MAX_ROWS:
                    memory_truncated = True
                    break
                rows.append(
                    {
                        "addr": "0x%x" % (addr + off),
                        "old_hex": old_row.hex(),
                        "new_hex": new_row.hex(),
                    }
                )
            if memory_truncated:
                break
        return {
            "snapshot_id": sid,
            "registers_changed": regs_changed,
            "registers_truncated": regs_truncated,
            "memory_changes": rows,
            "memory_truncated": memory_truncated,
            "segments_skipped": segments_skipped,
        }

    # -- delegated policies (plugin-side loops, constant-size summaries) -----

    def _handle_policy(self, params):
        kind = params.get("kind")
        handlers = {
            "trace": self._policy_trace,
            "heap_arm": self._policy_heap_arm,
            "heap_read": self._policy_heap_read,
            "heap_disarm": self._policy_heap_disarm,
            "fuzz_loop": self._policy_fuzz_loop,
            "crash_check": self._policy_crash_check,
            "minimize": self._policy_minimize,
            "bp_stats": self._policy_bp_stats,
        }
        handler = handlers.get(kind)
        if handler is None:
            raise PluginError(
                "BAD_PARAMS",
                "unknown policy kind %r (expected %s)"
                % (kind, ", ".join(sorted(handlers))),
            )
        self._guard_stopped()
        return handler(params)

    def _policy_trace(self, params):
        max_steps = _bounded_int(
            params.get("max_steps"), 200, 1, POLICY_MAX_STEPS
        )
        self._require_frame()
        visited = []
        seen = set()
        try:
            first_pc = int(gdb.selected_frame().pc())
            visited.append(first_pc)
            seen.add(first_pc)
        except Exception:
            pass
        steps = 0
        stop = "max_steps"
        for _ in range(max_steps):
            try:
                self._handle_eval({"command": "stepi"})
            except PluginError as exc:
                stop = "error:%s" % exc.code
                break
            except Exception as exc:
                stop = "error:%s" % exc
                break
            steps += 1
            try:
                pc = int(gdb.selected_frame().pc())
            except Exception:
                stop = "no_frame"
                break
            if pc not in seen:
                seen.add(pc)
                visited.append(pc)
        return {
            "steps": steps,
            "unique_count": len(visited),
            "unique_pc": ["0x%x" % pc for pc in visited[:POLICY_TRACE_CAP]],
            "truncated": len(visited) > POLICY_TRACE_CAP,
            "stop": stop,
        }

    def _policy_heap_arm(self, params):
        if self._timeline_bps:
            raise PluginError(
                "BAD_PARAMS", "timeline already armed; heap_disarm first"
            )
        max_events = _bounded_int(
            params.get("max_events"), 256, 1, POLICY_MAX_EVENTS
        )
        symbols = params.get("symbols") or [
            "malloc", "free", "realloc", "calloc",
        ]
        self._timeline_events = []
        self._timeline_max = max_events
        armed = []
        skipped = []
        for sym in symbols:
            try:
                self._timeline_bps.append(
                    _TimelineBreakpoint(str(sym), self._timeline_events, max_events)
                )
                armed.append(str(sym))
            except gdb.error as exc:
                skipped.append({"symbol": str(sym), "reason": str(exc)})
        if not armed:
            raise PluginError(
                "PLUGIN_ERROR", "no allocation symbol could be armed"
            )
        return {"armed": armed, "skipped": skipped, "max_events": max_events}

    def _policy_heap_read(self, params):
        if not self._timeline_bps:
            raise PluginError("BAD_PARAMS", "timeline not armed")
        events = self._timeline_events
        return {
            "armed": [str(bp.location) for bp in self._timeline_bps],
            "total": len(events),
            "events": events[-POLICY_TIMELINE_READ:],
            "truncated": len(events) > POLICY_TIMELINE_READ,
        }

    def _policy_heap_disarm(self, params):
        if not self._timeline_bps:
            raise PluginError("BAD_PARAMS", "timeline not armed")
        total = len(self._timeline_events)
        for bp in self._timeline_bps:
            try:
                bp.delete()
            except Exception:
                pass
        self._timeline_bps = []
        self._timeline_events = []
        return {"disarmed": True, "total_events": total}

    def _policy_fuzz_loop(self, params):
        sid, _snap = self._find_snapshot(params)
        payloads = params.get("payloads")
        if not isinstance(payloads, list) or not payloads:
            raise PluginError(
                "BAD_PARAMS", "payloads must be a non-empty list of hex strings"
            )
        payloads = payloads[:POLICY_MAX_PAYLOADS]
        if "buffer_addr" not in params or "stop_location" not in params:
            raise PluginError(
                "BAD_PARAMS",
                "fuzz_loop requires buffer_addr and stop_location (a "
                "guaranteed-stop marker, e.g. the caller of the function "
                "under test)",
            )
        buffer_addr = self._resolve_addr(params.get("buffer_addr"))
        stop_location = str(params.get("stop_location"))
        crashes = []
        survived = 0
        rounds = 0
        signatures = set()
        for index, payload_hex in enumerate(payloads):
            if not isinstance(payload_hex, str) or not payload_hex.strip():
                continue
            try:
                payload = _hex_to_bytes(payload_hex)
            except ValueError as exc:
                raise PluginError("BAD_PARAMS", str(exc))
            rounds += 1
            verdict = self._fuzz_round(sid, buffer_addr, payload, stop_location)
            if verdict["error"] is not None:
                crashes.append(
                    {
                        "round": rounds,
                        "payload_index": index,
                        "error": verdict["error"],
                    }
                )
                break
            if verdict["survived"]:
                survived += 1
            else:
                stop = verdict["stop"]
                signature = (stop.get("signal"), stop.get("pc"))
                if signature not in signatures:
                    signatures.add(signature)
                    crashes.append(
                        {
                            "round": rounds,
                            "payload_index": index,
                            "payload_bytes": len(payload),
                            "stop": stop,
                        }
                    )
        return {
            "snapshot_id": sid,
            "rounds": rounds,
            "survived": survived,
            "crash_count": len(crashes),
            "crashes": crashes[:POLICY_MAX_CRASHES],
            "truncated": len(crashes) > POLICY_MAX_CRASHES,
        }

    # -- experimental: inferior stdio over a pty -----------------------------

    def _io_sink(self, data: bytes) -> None:
        # runs on the pty reader thread, not gdb's main thread
        with self._io_lock:
            if len(self._io_buf) == self._io_buf.maxlen:
                self._io_dropped += 1
            self._io_seq += 1
            self._io_buf.append((self._io_seq, data))

    def _handle_io_setup(self, params):
        if self._io is not None:
            raise PluginError("BAD_PARAMS", "io already set up; io_teardown first")
        if not _HAS_OPENPTY:
            raise PluginError(
                "IO_UNSUPPORTED", "this platform has no pty support"
            )
        channel = _make_io_channel()
        self._io = channel
        with self._io_lock:
            self._io_buf.clear()
            self._io_seq = 0
            self._io_dropped = 0
        self._io_thread = channel.start(self._io_sink)
        # applies to the inferior's NEXT run/start (documented behavior
        # of gdb's inferior-tty)
        self._handle_eval(
            {"command": "set inferior-tty %s" % channel.slave_path}
        )
        return {
            "slave_path": channel.slave_path,
            "note": "inferior stdio switches to the pty on its next run/start",
        }

    def _handle_io_send(self, params):
        if self._io is None:
            raise PluginError("BAD_PARAMS", "io not set up; io_setup first")
        data = _hex_to_bytes(params.get("hex", ""))
        if not data:
            raise PluginError("BAD_PARAMS", "hex payload is required")
        sent = self._io.write(data)
        return {"sent": sent}

    def _handle_io_read(self, params):
        if self._io is None:
            raise PluginError("BAD_PARAMS", "io not set up; io_setup first")
        since = _bounded_int(params.get("since_seq"), 0, 0, 1 << 62)
        with self._io_lock:
            snapshot = list(self._io_buf)
            last_seq = self._io_seq
            dropped = self._io_dropped
        chunks = []
        for seq, data in snapshot:
            if seq <= since:
                continue
            chunks.append(
                {
                    "seq": seq,
                    "length": len(data),
                    "hex": data.hex(),
                    "text": data.decode("utf-8", "replace"),
                }
            )
        return {
            "chunks": chunks[-IO_MAX_CHUNKS_PER_READ:],
            "total_chunks": len(snapshot),
            # older chunks evicted by the buffer cap (page back with
            # since_seq for anything still buffered but beyond the
            # per-read chunk limit)
            "dropped_overflow": dropped,
            "last_seq": last_seq,
        }

    def _handle_io_teardown(self, params):
        if self._io is None:
            raise PluginError("BAD_PARAMS", "io not set up")
        self._io.close()
        self._io = None
        with self._io_lock:
            total = self._io_seq
            self._io_buf.clear()
        return {"torn_down": True, "total_chunks_seen": total}

    def _fuzz_round(self, sid, buffer_addr, payload, stop_location):
        """One restore -> write -> resume cycle. Returns
        ``{"survived", "stop", "error"}`` — survived means the marker
        breakpoint (a guaranteed stop) was hit rather than the run
        dying."""
        self._handle_snapshot_restore({"snapshot_id": sid})
        if payload:
            self._handle_write_mem({"addr": buffer_addr, "hex": payload.hex()})
        marker = self._handle_break(
            {"location": stop_location, "temporary": True}
        )
        try:
            self._policy_resume()
        except PluginError as exc:
            # a failed resume poisons the round; report it instead of
            # spinning on a bad state
            self._drop_breakpoint(marker["number"])
            return {"survived": False, "stop": None, "error": exc.message}
        stop = self.stop_info or {}
        survived = marker["number"] in (stop.get("breakpoints") or [])
        self._drop_breakpoint(marker["number"])
        return {"survived": survived, "stop": stop, "error": None}

    def _policy_crash_check(self, params):
        sid, _snap = self._find_snapshot(params)
        if "buffer_addr" not in params or "stop_location" not in params:
            raise PluginError(
                "BAD_PARAMS",
                "crash_check requires buffer_addr and stop_location",
            )
        buffer_addr = self._resolve_addr(params.get("buffer_addr"))
        payload = _hex_to_bytes(params.get("payload", ""))
        verdict = self._fuzz_round(
            sid, buffer_addr, payload, str(params.get("stop_location"))
        )
        return {
            "survived": verdict["survived"],
            "stop": verdict["stop"],
            "error": verdict["error"],
        }

    def _policy_minimize(self, params):
        sid, _snap = self._find_snapshot(params)
        if "buffer_addr" not in params or "stop_location" not in params:
            raise PluginError(
                "BAD_PARAMS", "minimize requires buffer_addr and stop_location"
            )
        buffer_addr = self._resolve_addr(params.get("buffer_addr"))
        stop_location = str(params.get("stop_location"))
        payload = _hex_to_bytes(params.get("payload", ""))
        if not payload:
            raise PluginError("BAD_PARAMS", "payload (hex) is required")
        max_rounds = _bounded_int(params.get("max_rounds"), 128, 1, 512)
        initial_len = len(payload)
        first = self._fuzz_round(sid, buffer_addr, payload, stop_location)
        rounds = 1
        if first["error"] is not None:
            raise PluginError("PLUGIN_ERROR", first["error"])
        if first["survived"]:
            raise PluginError(
                "BAD_PARAMS",
                "payload does not crash (marker hit); nothing to minimize",
            )
        signature = (first["stop"] or {}).get("signal")
        # classic delta debugging: try dropping chunks, shrink the grain
        # on success, coarsen when a full sweep removes nothing. Removals
        # are only accepted while the crash signal stays the same — a
        # changed signal means the minimizer drifted to a different bug.
        chunks = 2
        while len(payload) > 1 and rounds < max_rounds:
            chunk_len = max(1, (len(payload) + chunks - 1) // chunks)
            removed = False
            i = 0
            while i < chunks and rounds < max_rounds:
                candidate = (
                    payload[: i * chunk_len] + payload[(i + 1) * chunk_len :]
                )
                i += 1
                if not candidate or candidate == payload:
                    continue
                rounds += 1
                verdict = self._fuzz_round(
                    sid, buffer_addr, candidate, stop_location
                )
                if verdict["error"] is not None or verdict["survived"]:
                    continue
                if (verdict["stop"] or {}).get("signal") == signature:
                    payload = candidate
                    removed = True
                    chunks = max(2, chunks - 1)
                    break
            if not removed:
                if chunks >= len(payload):
                    break
                chunks = min(chunks * 2, len(payload))
        return {
            "original_bytes": initial_len,
            "minimized_bytes": len(payload),
            "minimized_hex": payload.hex(),
            "signal": signature,
            "rounds": rounds,
            "reduced": len(payload) < initial_len,
            "rounds_truncated": rounds >= max_rounds,
        }

    def _policy_bp_stats(self, params):
        """Hit-count probes at ``locations`` plus a temporary marker at
        ``stop_location``; resumes until the hit budget, the pass count
        or the inferior's own stop ends the run, then reports per-
        location counts. Probes auto-continue, so the loop runs at
        native speed without any per-hit round-trip."""
        locations = params.get("locations")
        if not isinstance(locations, list) or not locations:
            raise PluginError(
                "BAD_PARAMS", "locations must be a non-empty list"
            )
        if len(locations) > POLICY_MAX_LOCATIONS:
            raise PluginError(
                "BAD_PARAMS",
                "too many locations (max %d)" % POLICY_MAX_LOCATIONS,
            )
        if "stop_location" not in params:
            raise PluginError(
                "BAD_PARAMS", "bp_stats requires stop_location"
            )
        stop_location = str(params.get("stop_location"))
        max_hits = _bounded_int(
            params.get("max_hits"), 10_000, 1, POLICY_MAX_HITS
        )
        max_passes = _bounded_int(params.get("max_passes"), 1, 1, 1024)
        counts: dict = {}
        total = [0]
        armed, skipped = [], []
        probes = []
        for loc in locations:
            try:
                probes.append(
                    _StatsBreakpoint(str(loc), counts, total, max_hits)
                )
            except gdb.error as exc:
                skipped.append({"location": str(loc), "reason": str(exc)})
                continue
            armed.append(str(loc))
        if not armed:
            raise PluginError(
                "PLUGIN_ERROR", "no location could be armed"
            )
        probe_numbers = {bp.number for bp in probes}
        passes = 0
        stop_reason = "max_passes"
        final_stop = None
        while True:
            marker = self._handle_break(
                {"location": stop_location, "temporary": True}
            )
            try:
                self._policy_resume()
            except PluginError as exc:
                stop_reason = "error:%s" % exc.code
                self._drop_breakpoint(marker["number"])
                break
            stop = self.stop_info or {}
            stopped_at = set(stop.get("breakpoints") or [])
            if marker["number"] in stopped_at:
                passes += 1
                self._drop_breakpoint(marker["number"])
                if total[0] >= max_hits:
                    stop_reason = "max_hits"
                    break
                if passes >= max_passes:
                    stop_reason = "max_passes"
                    break
                continue
            # stopped away from the marker: probe budget or crash/exit
            final_stop = stop
            self._drop_breakpoint(marker["number"])
            stop_reason = (
                "max_hits" if stopped_at & probe_numbers else "inferior_stop"
            )
            break
        for bp in probes:
            try:
                bp.delete()
            except Exception:
                pass
        return {
            "counts": counts,
            "total_hits": total[0],
            "passes": passes,
            "armed": armed,
            "skipped": skipped,
            "max_hits": max_hits,
            "stop_reason": stop_reason,
            "stop": final_stop,
        }

    # -- gdb events (main thread; never block) ------------------------------

    def _exec(self, command, to_string=True):
        """Single choke point for gdb CLI execution. All gdb.execute
        calls live here so the plugin has exactly one line to audit."""
        return gdb.execute(command, to_string=to_string)

    def _connect_events(self):
        ev = gdb.events
        pairs = []

        missing = []

        def connect(attr, handler):
            registry = getattr(ev, attr, None)
            if registry is None:
                missing.append(attr)
                return
            try:
                registry.connect(handler)
                pairs.append((registry, handler))
            except Exception as exc:
                missing.append("%s (%s)" % (attr, exc))

        connect("stop", self._on_stop)
        connect("cont", self._on_cont)
        connect("exited", self._on_exited)
        connect("before_prompt", self._on_before_prompt)
        connect("gdb_exiting", self._on_gdb_exiting)
        self._event_handlers = pairs
        # without these the server waits forever for stop/exit
        # notifications and nothing in the protocol says why
        if missing:
            _warn("gdb events not connected: %s" % ", ".join(missing))

    def _disconnect_events(self):
        for registry, handler in self._event_handlers:
            try:
                registry.disconnect(handler)
            except Exception:
                pass
        self._event_handlers = []

    def _on_stop(self, event):
        _dbg("on_stop fired")
        payload = {"reason": "stopped"}
        try:
            sig = getattr(event, "stop_signal", None)
            if sig is not None:
                payload["signal"] = str(sig)
                payload["reason"] = "signal-received"
        except Exception:
            pass
        details = getattr(event, "details", None)
        if isinstance(details, dict):
            payload["details"] = _json_safe(details)
            if isinstance(details.get("reason"), str):
                payload["reason"] = details["reason"]
            addr = details.get("addr")
            if isinstance(addr, int):
                payload["fault_addr"] = "0x%x" % addr
        try:
            breakpoints = getattr(event, "breakpoints", None)
            if breakpoints:
                payload["reason"] = "breakpoint-hit"
                payload["breakpoints"] = [bp.number for bp in breakpoints]
        except Exception:
            pass
        # gdb >= 16 no longer puts the fault address in the MI details;
        # read it from the signal info instead (works for memory faults).
        if "fault_addr" not in payload and payload.get("signal") in (
            "SIGSEGV",
            "SIGBUS",
            "SIGILL",
            "SIGFPE",
        ):
            try:
                si_addr = gdb.parse_and_eval("$_siginfo._sifields._sigfault.si_addr")
                payload["fault_addr"] = "0x%x" % int(si_addr)
            except Exception:
                pass
        try:
            frame = gdb.selected_frame()
            if frame is not None:
                payload["pc"] = "0x%x" % int(frame.pc())
        except Exception:
            pass
        try:
            thr = gdb.selected_thread()
            if thr is not None:
                payload["thread"] = str(thr.num)
        except Exception:
            pass
        self.state = "stopped"
        self.stop_info = payload
        self._notify("stop", payload)

    def _on_cont(self, event):
        _dbg("on_cont fired")
        self.state = "running"
        self._notify("running", {})

    def _on_exited(self, event):
        payload = {}
        code = getattr(event, "exit_code", None)
        if code is None:
            try:
                inf = getattr(event, "inferior", None)
                if inf is not None:
                    payload["inferior_num"] = str(inf.num)
            except Exception:
                pass
        else:
            payload["exit_code"] = int(code)
        self.state = "exited"
        self._notify("exited", payload)

    def _on_before_prompt(self):
        _dbg("on_before_prompt fired (state=%s)" % self.state)
        if self.state == "running":
            self.state = "stopped"
        self._notify("prompt", {})

    def _on_gdb_exiting(self, event):
        self._shutdown(False)

    # -- output ---------------------------------------------------------------

    def _encode_msg(self, msg):
        if self.token:
            msg = {"token": self.token, "msg": msg}
        return (
            json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
            + b"\n"
        )

    def _send(self, msg):
        try:
            self.out_q.put((self._wire_generation, self._encode_msg(msg)))
        except Exception:
            pass

    def _send_response(self, req_id, ok, result=None, error=None):
        msg = {"type": "response", "id": req_id, "ok": ok}
        if ok:
            msg["result"] = result if result is not None else {}
        else:
            msg["error"] = error
        self._send(msg)

    def _send_error(self, req_id, code, message):
        self._send_response(req_id, False, error={"code": code, "message": message})

    def _notify(self, event, payload=None):
        self._send(
            {
                "type": "notification",
                "event": event,
                "payload": payload or {},
            }
        )

    def status_text(self):
        return (
            "[gdb-mcp] state=%s session=%s port=%d host=%s" %
            (self.state, self.session_id, self.port, self._resolve_hosts())
        )


VERB_HANDLERS = {
    "eval": Plugin._handle_eval,
    "read_mem": Plugin._handle_read_mem,
    "write_mem": Plugin._handle_write_mem,
    "regs": Plugin._handle_regs,
    "set_reg": Plugin._handle_set_reg,
    "backtrace": Plugin._handle_backtrace,
    "disasm": Plugin._handle_disasm,
    "evaluate": Plugin._handle_evaluate,
    "threads": Plugin._handle_threads,
    "frame_select": Plugin._handle_frame_select,
    "breakpoints": Plugin._handle_breakpoints,
    "break": Plugin._handle_break,
    "bp_delete": Plugin._handle_bp_delete,
    "bp_enable": Plugin._handle_bp_enable,
    "bp_disable": Plugin._handle_bp_disable,
    "mem_map": Plugin._handle_mem_map,
    "file": Plugin._handle_file,
    "core": Plugin._handle_core,
    "snapshot_create": Plugin._handle_snapshot_create,
    "snapshot_list": Plugin._handle_snapshot_list,
    "snapshot_restore": Plugin._handle_snapshot_restore,
    "snapshot_diff": Plugin._handle_snapshot_diff,
    "policy": Plugin._handle_policy,
    "io_setup": Plugin._handle_io_setup,
    "io_send": Plugin._handle_io_send,
    "io_read": Plugin._handle_io_read,
    "io_teardown": Plugin._handle_io_teardown,
}


class McpCommand(gdb.Command):
    """mcp status|reconnect|detach - manage the gdb-mcp plugin."""

    def __init__(self, plugin):
        super(McpCommand, self).__init__("mcp", gdb.COMMAND_USER)
        self.plugin = plugin

    def invoke(self, arg, from_tty):
        arg = (arg or "").strip()
        if arg in ("", "status"):
            print(self.plugin.status_text())
        elif arg == "reconnect":
            self.plugin.request_reconnect()
            print("[gdb-mcp] reconnect requested")
        elif arg == "detach":
            self.plugin._shutdown(False)
            print("[gdb-mcp] detached from MCP server")
        else:
            print("usage: mcp [status|reconnect|detach]")


_PLUGIN = None


def _autostart():
    global _PLUGIN
    if os.environ.get("GDB_MCP_AUTOSTART", "1") == "0":
        return
    _PLUGIN = Plugin()
    _PLUGIN.start()
    McpCommand(_PLUGIN)
    print(
        "[gdb-mcp] plugin v%s loaded; connecting to port %d" %
        (PLUGIN_VERSION, _PLUGIN.port)
    )


if os.environ.get("GDB_MCP_LOADED"):
    print("[gdb-mcp] already loaded in this gdb; skipping", file=sys.stderr)
else:
    os.environ["GDB_MCP_LOADED"] = "1"
    _autostart()
