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
[![Tests](https://img.shields.io/badge/tests-765%20passing-brightgreen)](#testing)

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
- **Verified against reality** — 765 unit tests (including seeded
  protocol-layer fuzzing against the JSON-lines control channel) plus
  end-to-end suites driving real gdb in WSL, and a versioned acceptance
  benchmark (`bench/`, 576 tasks across 8 families, reference-solved
  576/576) that proves every task solvable before any model runs on it —
  the first model report is committed under `bench/reports/`.

## Quick Start

**1. Install** (Windows side, WSL2 backend — or natively on Linux):

```powershell
pip install -e .
```

**2. Prepare WSL** (Kali/Ubuntu recommended):

```bash
sudo apt install gdb python3 python3-pip gcc   # pwndbg optional but recommended
```

**3. Register with your MCP client**:

Claude Code (`.mcp.json` in the project or user scope):

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

Cursor — same shape, in `~/.cursor/mcp.json`. Codex CLI — add to
`~/.codex/config.toml`:

```toml
[mcp_servers.gdb-mcp]
command = "gdb-mcp"
env = { GDB_MCP_PORT = "3939" }
```

Any other MCP client: a stdio server launching `gdb-mcp` (or the hardened
HTTP transport via `--http` + `--mcp-port`, with a bearer token).

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

**52 tools by default** (12 under `GDB_MCP_TOOL_PROFILE=core`, 60 with
`--experimental`), grouped by job — and by capability layer: **core**
(sessions/execution/breakpoints/state — any debugging scenario),
**pwn** (crash triage, heap, checkpoints, campaign, policies),
**static** (the Ghidra bridge), and **kernel** (experimental QEMU/gdbstub
tooling). The layers share one wire protocol; the `core` profile is the
subset a non-exploitation backend would need.

| Group | Tools |
|---|---|
| Sessions | `list_sessions` `session_status` `launch_gdb` `launch_script` `get_process_output` `kill_session` `quit_gdb` `get_events` `export_session_script` `diff_sessions` |
| Execution | `execute_command` (raw gdb, pwndbg-compatible, paginated + spilled to disk) `continue_execution` (`wait`/`with_context`) `interrupt` `wait_for_stop` `get_stop_reason` `read_result` `batch_commands` |
| Crash triage | `crash_report` — signal, fault addr, registers, backtrace, disasm, memory at PC/SP/fault, structured memory map · `triage_crash` — replay a crashing payload from a checkpoint, collect the full report, optionally minimize, store evidence |
| State | `read_memory` `write_memory` `read_registers` `write_register` `get_backtrace` `disassemble` `evaluate` `list_threads` `select_frame` `get_memory_map` (structured) `load_target` |
| Breakpoints | `set_breakpoint` (sw/hw/watch/condition/temporary + `commands`/`auto_continue` probes) `list_breakpoints` `manage_breakpoint` |
| Pwn workflow | `heap_bins` (pwndbg bins → JSON) `checkpoint` (create/restore/diff) `run_policy` (trace / heap probes / fuzz_loop / minimize / crash_check / bp_stats — bounded loops at native speed) `campaign` (state machine + cyclic oracle) |
| Static bridge (Ghidra) | `analyze_binary` `list_analyses` `get_analysis_status` `get_binary_overview` `list_sections` `list_symbols` `list_functions` `list_strings` `decompile_function` `get_static_disassembly` `get_xrefs` `get_call_graph` `search_decompiled_code` `annotate_code` `remove_code_annotation` — SHA-256-keyed analysis cache; runtime stops map back to static function/line |

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
Claude Code / any MCP client ──stdio or HTTPS──► gdb-mcp server (52 tools)
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

**Concurrency semantics.** Within one session, tool calls execute strictly
one-at-a-time: the plugin marshals every gdb API call onto gdb's main
thread, and the server serializes requests per session (composite tools
like `crash_report` run atomically under the same lock). A second call on
a busy session waits — bounded by `GDB_MCP_REQUEST_TIMEOUT` (30s default)
— rather than interleaving. Execution verbs while the inferior runs fail
fast with `INFERIOR_RUNNING` instead of queueing silently. Different
sessions are fully independent.

**Compatibility.** The plugin's gdb API usage carries explicit per-version
fallbacks (feature-probed at load, e.g. `gdb.interrupt` on gdb ≥ 15,
`qualified` breakpoints on newer builds). Verified against:

| gdb | Where |
|---|---|
| 12.1 | CI (ubuntu-22.04 apt) |
| 15.x | CI (ubuntu-24.04 apt) |
| 17.2 + pwndbg | WSL2, full end-to-end suites locally |

Python 3.10+ on the server side; the plugin itself is stdlib-only so it
can be `source`-deployed into any gdb with an embedded Python.

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
| `docker` | ephemeral container | `SYS_PTRACE` + relaxed seccomp; per-session containers. Build the image first (`docker build -f docker/Dockerfile -t gdb-mcp:latest .`); run the server with `--host-bind 0.0.0.0 --token ...` (a non-loopback bind requires a token) and the plugin dials back over `host.docker.internal` |
| `ssh` | remote host | key-based auth; great for IoT/router targets |

## Experimental Features

Enable with the **`--experimental`** launch flag (deliberately no environment
variable — a stray shell variable must never destabilize your server):

- **Inferior stdio channel** — drive menu-style targets without pwntools.
- **Crash minimizer** — delta-debugging over checkpoint restore.
- **`identify_libc` / `search_gadgets`** — libc.rip API and ROPgadget CLI
  integrations with honest-degradation errors.
- **`kernel_launch` / `kernel_snapshot`** — boot a Linux kernel VM under QEMU
  with a gdbstub and attach gdb to it; savevm/loadvm is the kernel-pwn revert
  primitive. Requires QEMU inside the launcher backend.

## Security Model

- TCP listener is loopback-only by default; non-loopback binds require a
  token. Launched gdb sessions use **session-scoped tokens** (HMAC-derived) —
  the master never reaches child processes.
- HTTP transport adds Host/Origin validation, bearer tokens (controller +
  read-only **observer** roles), TLS and mutual TLS.
- `--readonly` drops mutating tools; debugger-escaping commands
  (`shell`/`python`/…) are blocked at **two layers** unless
  `--allow-unsafe`.
- A **hash-chained audit log** (`<log-dir>/audit.log`, on by default,
  `--no-audit-log` to disable) records security decisions — handshakes
  and rejections, HTTP 403s, observer denials, unsafe-command blocks —
  as a SHA-256 chain where every record commits to its predecessor, so
  after-the-fact edits are detectable (`gdb_mcp.audit.verify_log`).
- Journals, session state and results are written `0600`; persisted state is
  re-validated on load (journals and `sessions.json` carry explicit schema
  versions; unknown newer versions are refused, not guessed at). GDB can
  execute arbitrary code on its target — run it on targets you own. Full
  notes: [ROADMAP_V2.md](ROADMAP_V2.md), CIA audit in the commit history.

**On token lifetimes:** session tokens are stateless
HMAC-SHA256 derivations of the master token, which is what lets a plugin
re-verify after a server restart without state — so they cannot expire
individually. The compensating design: the master token never leaves the
server process, per-session tokens are useless for any other session, and
HTTP exposure should use TLS/mTLS (client certificates *are* revocable).
If you need a shorter leak window, restart the server with a new master
token — plugins re-derive automatically.

## Testing

```bash
# unit (no gdb required)
python -m pytest tests/ -q                        # 765 tests, ~12s

# real-gdb suites (WSL2 or native Linux; each prints its own verdict)
wsl bash tests/integration/run_wsl_integration.sh # plugin <-> server protocol
python tests/integration/run_mcp_tools_e2e.py --distro kali-linux
                                                  # every registered tool, end to end
wsl bash tests/integration/run_io_smoke.sh        # inferior stdio over a pty
bash tests/integration/run_tls_smoke.sh           # HTTP / TLS / mTLS / bearer tokens
python tests/integration/run_observer_smoke.py    # observer role over live HTTP

# acceptance benchmark (576 versioned tasks; bench/SPEC.md is the outline)
python -m bench.framework.cli selfcheck --distro kali-linux  # reference-solve + grade
python -m bench.framework.cli stress --distro kali-linux     # call volume + churn
python -m bench.framework.cli faults --distro kali-linux     # fault injection + recovery
python -m bench.framework.cli perf --distro kali-linux       # overhead / startup / concurrency
python -m bench.framework.cli pwndbg --distro kali-linux     # pwndbg compatibility probes
```

## Roadmap

Development status, benchmark results, and the long-term vision live in
[ROADMAP.md](ROADMAP.md) and [ROADMAP_V2.md](ROADMAP_V2.md).
中文文档见 [README.zh-CN.md](README.zh-CN.md)。

## Contributing

Issues and PRs welcome — the test suite (765 tests, no gdb required for unit
runs) is the contract: please add tests for behavior changes and keep
`ruff check` clean.

## License

[MIT](LICENSE) © gdb-mcp contributors
