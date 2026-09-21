<div align="center">

# gdb-mcp

**Give your coding agent hands on a real GDB — built for binary exploitation.**

An MCP server that lets Claude Code, Codex, or any MCP client drive live Linux
`gdb` sessions (pwndbg-aware) for vulnerability research, CTF pwn, and exploit
development.

[![CI](https://github.com/Mistyovo/gdb-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Mistyovo/gdb-mcp/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20WSL2-lightgrey)](#launchers)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-519%20passing-brightgreen)](#testing)

[Quick Start](#quick-start) · [Tools](#tool-catalog) · [Architecture](#architecture) · [Experimental](#experimental-features) · [Roadmap](ROADMAP_V2.md) · [中文文档](README.zh-CN.md)

</div>

---

## Why gdb-mcp?

Most "debugger MCP" projects parse GDB/MI output or scrape terminal screens.
**gdb-mcp takes a different route: a small Python plugin runs *inside* the gdb
process** and talks to the server over a JSON-lines control channel — so pwndbg
contexts, pwntools-launched sessions, and reverse-execution all just work,
with none of the prompt-scraping fragility.

- **Built for pwn, not just debugging** — structured crash triage, glibc heap
  bins, checkpoint/restore, a cyclic-offset oracle, and a campaign state
  machine that remembers what your session has already proven.
- **Token-frugal by design** — one call returns the whole stop picture
  (verdict + key registers + backtrace + disassembly); large outputs spill to
  disk instead of flooding the context window.
- **Delegated execution** — bounded loops (`trace`, heap probes, `fuzz_loop`,
  `minimize`) run *inside* gdb at native speed and return constant-size
  summaries, so iterating 1,000 times costs one tool call.
- **pwntools stays in charge** — `gdb.debug()` / `gdb.attach()` sessions
  register automatically; the server never fights your scripts for I/O.
- **Verified against reality** — 519 unit tests plus end-to-end suites driving
  real gdb 17.2 in WSL, and a live bench that scores models on real crackmes.

## Quick Start

**1. Install** (Windows side, WSL2 backend — or natively on Linux):

```powershell
pip install -e .
```

**2. Prepare WSL** (Kali/Ubuntu recommended):

```bash
sudo apt install gdb python3 python3-pip gcc   # pwndbg optional but recommended
```

**3. Register with your MCP client** (`.mcp.json`):

```json
{
  "mcpServers": {
    "gdb-mcp": {
      "command": "gdb-mcp",
      "env": { "GDB_MCP_PORT": "3939" }
    }
  }
}
```

**4. Start a session** — either let the server launch gdb:

```text
launch_gdb(program="/tmp/cracker", run=True)
```

or keep your pwntools workflow untouched and just load the plugin:

```python
from pwn import *
io = gdb.debug("./vuln", gdb_args=["-x", "src/gdb_mcp/plugin/gdb_mcp_plugin.py"])
```

The session registers itself. Then ask your agent:

> *Continue and tell me exactly why it crashed — then prove you control PC.*

```text
→ continue_execution(wait=True, with_context=True)
  {"stopped": true, "stop_info": {"signal": "SIGSEGV", "pc": "0x4011eb"},
   "context": {"registers": {...}, "backtrace": [...], "disassembly": [...]}}
```

One call. Full picture.

## Tool Catalog

**37 core tools**, grouped by job:

| Group | Tools |
|---|---|
| Sessions | `list_sessions` `session_status` `launch_gdb` `launch_script` `get_process_output` `kill_session` `quit_gdb` `get_events` `export_session_script` `diff_sessions` |
| Execution | `execute_command` (raw gdb, pwndbg-compatible, paginated + spilled to disk) `continue_execution` (`wait`/`with_context`) `interrupt` `wait_for_stop` `get_stop_reason` `read_result` `batch_commands` |
| Crash triage | `crash_report` — signal, fault addr, registers, backtrace, disasm, memory at PC/SP/fault, structured memory map · `triage_crash` — replay a crashing payload from a checkpoint, collect the full report, optionally minimize, store evidence |
| State | `read_memory` `write_memory` `read_registers` `write_register` `get_backtrace` `disassemble` `evaluate` `list_threads` `select_frame` `get_memory_map` (structured) `load_target` |
| Breakpoints | `set_breakpoint` (sw/hw/watch/condition/temporary + `commands`/`auto_continue` probes) `list_breakpoints` `manage_breakpoint` |
| Pwn workflow | `heap_bins` (pwndbg bins → JSON) `checkpoint` (create/restore/diff) `run_policy` (trace / heap probes / fuzz_loop / minimize / crash_check / bp_stats — bounded loops at native speed) `campaign` (state machine + cyclic oracle) |

**6 experimental tools** (behind `--experimental`): inferior stdio channel
(`io_setup` / `send_to_inferior` / `read_inferior_output` / `io_teardown`),
crash delta-minimization, `identify_libc`, `search_gadgets`.

**16 static-analysis tools** when a Ghidra headless install is available:
`analyze_binary`, `decompile_function`, `get_xrefs`, `get_call_graph`,
`search_decompiled_code`, annotations, and more.

`export_session_script` compiles everything your session did into a
**deterministic, replayable gdbscript** — audit trail, reproducer, and the
answer to *"why not just write a gdbscript?"* in one artifact.

## Architecture

```
Claude Code / any MCP client ──stdio or HTTPS──► gdb-mcp server (37+ tools)
        ▲  campaign state · journals · policies · static bridge
        │
        │ TCP JSON-lines (scoped session tokens, heartbeats)
        ▼
gdb process (WSL2 / native / Docker / SSH target)
  └─ gdb_mcp_plugin.py — in-process bridge
       ├─ all gdb API calls marshalled to gdb's main thread
       ├─ stop/running/exited events pushed as they happen
       └─ coexists with pwndbg & pwntools (never touches prompt or I/O)
```

Launchers: **WSL2** · **native Linux** · **Docker** (`SYS_PTRACE` image recipe
included) · **SSH** — pick with `GDB_MCP_LAUNCHER`. Transport: stdio by
default, or hardened **streamable HTTP** (`--http`) with Host/Origin
validation, bearer tokens, TLS and mutual-TLS options.

## Designed for Agents

- **Stop = full context.** `continue_execution(wait=True, with_context=True)`
  returns verdict, key registers, backtrace and disassembly in one response.
- **Bounded everything.** Pagination, result spilling with SHA-256 handles,
  explicit `truncated` flags, ring-buffered events — no silent truncation, no
  unbounded dumps.
- **Campaign state machine.** Cyclic-offset oracle, libc leak bookkeeping, and
  pc-control detection are injected into every stop — the agent never
  re-derives what the session already proved.
- **Delegated policies.** `run_policy` runs tracing, heap timelines, snapshot
  fuzzing and delta-minimization inside gdb at native speed; the model only
  sees constant-size summaries.
- **Session = asset.** Journals persist across restarts; sessions re-attach
  with their identity intact; everything exports to replayable gdbscript.

## Launchers

| Backend | Target | Notes |
|---|---|---|
| `wsl` (default) | WSL2 distro | mirrored networking recommended |
| `native` | local Linux | plain `bash -lc` |
| `docker` | ephemeral container | `SYS_PTRACE` + relaxed seccomp; per-session containers |
| `ssh` | remote host | key-based auth; great for IoT/router targets |

## Experimental Features

Enable with the **`--experimental`** launch flag (deliberately no environment
variable — a stray shell variable must never destabilize your server):

- **Inferior stdio channel** — drive menu-style targets without pwntools.
- **Crash minimizer** — delta-debugging over checkpoint restore.
- **`identify_libc` / `search_gadgets`** — libc.rip API and ROPgadget CLI
  integrations with honest-degradation errors.

## Security Model

- TCP listener is loopback-only by default; non-loopback binds require a
  token. Launched gdb sessions use **session-scoped tokens** (HMAC-derived) —
  the master never reaches child processes.
- HTTP transport adds Host/Origin validation, bearer tokens (controller +
  read-only **observer** roles), TLS and mutual TLS.
- `--readonly` drops mutating tools; debugger-escaping commands
  (`shell`/`python`/…) are blocked at **two layers** unless
  `--allow-unsafe`.
- Journals, session state and results are written `0600`; persisted state is
  re-validated on load. GDB can execute arbitrary code on its target — run it
  on targets you own. Full notes: [ROADMAP_V2.md](ROADMAP_V2.md), CIA audit
  in the commit history.

## Testing

```bash
python -m pytest tests/ -q                       # 519 unit tests (no gdb needed)
wsl bash tests/integration/run_wsl_integration.sh # real-gdb end-to-end suite
wsl bash tests/integration/run_io_smoke.sh        # inferior-stdio pty smoke
python bench/run_win.py --selftest               # bench harness self-check
```

## Roadmap

Development status, benchmark results, and the long-term vision live in
[ROADMAP.md](ROADMAP.md) and [ROADMAP_V2.md](ROADMAP_V2.md).
中文文档见 [README.zh-CN.md](README.zh-CN.md)。

## Contributing

Issues and PRs welcome — the test suite (519 tests, no gdb required for unit
runs) is the contract: please add tests for behavior changes and keep
`ruff check` clean.

## License

[MIT](LICENSE) © gdb-mcp contributors
