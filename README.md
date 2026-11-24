<div align="center">

# gdb-mcp

**Give your coding agent hands on a real GDB — Linux userland dynamic debugging.**

An MCP server that lets Claude Code, Codex, or any MCP client drive live Linux
`gdb` sessions (pwndbg-aware): launch or attach, control execution, inspect
state, triage crashes (live or core dumps), drive inferior stdio, and delegate
bounded pwn loops inside `gdb`.

[![CI](https://github.com/Mistyovo/gdb-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Mistyovo/gdb-mcp/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20WSL2-lightgrey)](#launchers)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-834%20passing-brightgreen)](#testing)

[Quick Start](#quick-start) · [Tools](#tool-catalog) · [Architecture](#architecture) · [Scope Gate](docs/adr/0001-userland-dynamic-debugging-scope.md) · [中文文档](README.zh-CN.md)

</div>

---

## Why gdb-mcp?

Most "debugger MCP" projects parse GDB/MI output or scrape terminal screens.
**gdb-mcp takes a different route: a small stdlib-only Python plugin runs
*inside* the gdb process** and talks to the server over a JSON-lines control
channel — so pwndbg contexts, pwntools-launched sessions, and reverse-execution
all just work, with none of the prompt-scraping fragility.

- **Sharp userland surface** — the default `pwn` profile exposes **36 tools**,
  all aimed at a live Linux userland process (and kept under a CI-enforced
  schema byte budget). Static analysis, kernel VMs, and enterprise HTTP stacks
  are deliberately out of scope ([ADR-0001](docs/adr/0001-userland-dynamic-debugging-scope.md)).
- **Built for pwn, not just debugging** — one-call crash triage & replay,
  glibc heap bins + standalone `heap_chunk` decoding (safe-linking aware),
  allocation return timelines, checkpoint/restore, `send_input`/`read_output`
  for menu targets, and an evidence-backed campaign state machine.
- **Token-frugal by design** — `continue_execution(wait=True, with_context=True)`
  returns the stop picture (verdict + key registers + backtrace + disassembly)
  in one call; oversized outputs spill to disk instead of flooding context.
- **Delegated execution** — bounded loops (`trace`, `heap_arm`, `fuzz_loop`,
  `minimize`, `bp_stats`, `verify_pc_control`) run *inside* gdb at native speed
  and return constant-size summaries; `interrupt` cancels an active policy
  cleanly with partial results.
- **pwntools stays in charge** — `gdb.debug()` / `gdb.attach()` sessions
  register automatically; the server never fights your scripts for I/O.
- **Verified against reality** — 834 unit tests (including seeded protocol
  fuzzing), real-gdb CI smokes across gdb 12 / 15 / 18, and a 72-task
  acceptance benchmark across 9 families (including `pwn_workflow`,
  reference-solved 72/72).

## Quick Start

**1. Install** (Windows side with WSL2 backend, or natively on Linux):

```powershell
pip install -e .
```

**2. Prepare Linux / WSL2**:

```bash
sudo apt install gdb python3 python3-pip gcc   # pwndbg optional but recommended
```

**3. Register with your MCP client**:

Claude Code (`.mcp.json`):

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

Cursor uses the same shape in `~/.cursor/mcp.json`. Codex CLI:

```toml
[mcp_servers.gdb-mcp]
command = "gdb-mcp"
env = { GDB_MCP_PORT = "3939" }
```

**4. Start a session** — either let the server launch gdb:

```text
launch_gdb(program="/tmp/cracker", run=True)
launch_gdb(program="/tmp/menu", stdio="pty", run=True)
launch_gdb(attach_pid=4242)
```

or keep your pwntools workflow untouched and load the plugin:

```python
from pwn import *
io = gdb.debug("./vuln", gdb_args=["-x", "src/gdb_mcp/plugin/gdb_mcp_plugin.py"])
```

## Tool Catalog

**36 tools by default** in the `pwn` profile, **12** under
`GDB_MCP_TOOL_PROFILE=core`, plus **1 experimental tool** (`diff_sessions`,
behind `--experimental`).

| Profile | Purpose |
|---|---|
| `core` | Minimal 12-tool session/execution/state/breakpoint surface |
| `pwn` (default) | Core + crash triage/replay, heap bins & chunks, checkpoints, policies, campaign, inferior stdio |

| Group | Tools |
|---|---|
| Sessions | `list_sessions` `session_status` `launch_gdb` (`program` or `attach_pid`, optional `stdio="pty"`) `launch_script` `get_process_output` `kill_session` (`force`/`forget`) `get_events` `export_session_script` |
| Execution & I/O | `execute_command` (raw gdb/pwndbg, multi-line, paginated + spilled to disk) `continue_execution` (`wait`/`with_context`, forward & reverse) `interrupt` (also cancels active policies) `wait_for_stop` `read_result` `send_input` `read_output` |
| Crash triage | `crash_report` — signal, fault addr, registers, backtrace, disasm, memory at PC/SP/fault, structured memory map (with core-file fallback), plus optional checkpoint replay, minimize, and evidence storage |
| State | `read_memory` `write_memory` `read_registers` `write_register` `get_backtrace` `disassemble` `evaluate` `list_threads` `select_thread` `select_frame` `get_memory_map` (live & core-file) `load_target` |
| Breakpoints | `set_breakpoint` (sw/hw/watch/condition/temporary + `commands`/`auto_continue` probes) `list_breakpoints` `manage_breakpoint` |
| Pwn workflow | `heap_bins` (pwndbg bins → JSON) `heap_chunk` (glibc chunk header → size/flags/fd/bk/tcache + safe-linking decode, no pwndbg) `checkpoint` (create/list/restore/diff) `run_policy` (`trace` / `heap_arm`·`read`·`disarm` with return pointers / `fuzz_loop` / `crash_check` / `minimize` / `bp_stats` / `verify_pc_control`) `campaign` (state + source-aware cyclic oracle + `protections` checksec parser) |

## Architecture

```
Claude Code / any MCP client ──stdio──► gdb-mcp server (36 tools)
        ▲  campaign state · journals · policies
        │
        │ TCP JSON-lines (scoped session tokens, heartbeats)
        ▼
gdb process (WSL2 / native Linux)
  └─ gdb_mcp_plugin.py — in-process stdlib-only bridge
       ├─ all gdb API calls marshalled to gdb's main thread
       ├─ stop/running/exited events pushed as they happen
       └─ coexists with pwndbg & pwntools (never touches prompt or I/O)
```

Launchers: **WSL2** (`--launcher wsl`, default) and **native Linux**
(`--launcher native`). Transport: **stdio**.

**Concurrency semantics.** Within one session, tool calls execute strictly
one-at-a-time: the plugin marshals every gdb API call onto gdb's main thread,
and the server serializes requests per session. Execution verbs while the
inferior runs fail fast with `INFERIOR_RUNNING`. Different sessions are fully
independent.

**Compatibility.** Verified against gdb 12.1 (CI ubuntu-22.04), gdb 15.x (CI
ubuntu-24.04), and gdb 18.1 + pwndbg (WSL2).

## Security Model

- TCP listener is loopback-only (`127.0.0.1:3939`) by default; non-loopback
  binds require `--token` / `GDB_MCP_TOKEN`.
- Launched gdb sessions use **session-scoped HMAC tokens** — the master token
  never reaches child processes.
- **Capability model:** every tool declares `observe`, `debug`, `target`,
  `host`, or `admin`. `--readonly` keeps only `observe` tools (excluding
  `execute_command`, `continue_execution`, `launch_gdb`, breakpoints, writes,
  and policies).
- **Unsafe command gate:** debugger-escaping commands (`shell`, `!`, `pipe`,
  `python`, `source`, `dump`, `append`, `restore`, `set exec-wrapper`,
  `set auto-load`, `set startup-with-shell`, …) are blocked at both server and
  plugin layers unless `--allow-unsafe`. The gate is abbreviation-aware and
  checks every line of multi-command strings, verified against real gdb in CI.
- Journals, session state, result files, and exported scripts are written
  `0600` with explicit schema validation on reload.

## Testing

```bash
# unit (no gdb required)
python -m pytest tests/ -q                        # 834 passed, ~9s

# real-gdb suites (WSL2 or native Linux)
wsl bash tests/integration/run_wsl_integration.sh # plugin <-> server protocol
wsl bash tests/integration/run_policy_smoke.sh    # policy loops (trace/bp_stats)
wsl bash tests/integration/run_heap_smoke.sh      # heap timeline (allocation returns)
wsl bash tests/integration/run_io_smoke.sh        # inferior stdio over a pty
wsl bash tests/integration/run_unsafe_gate_probe.sh # unsafe gate premises
PYTHONPATH=src python tests/integration/run_mcp_tools_e2e.py --distro kali-linux

# acceptance benchmark (72 tasks across 9 families, incl. pwn_workflow)
python -m bench.framework.cli build --distro kali-linux
python -m bench.framework.cli selfcheck --distro kali-linux
```

## Contributing

Issues and PRs welcome — please keep `python -m pytest tests/ -q` and
`ruff check src tests bench` clean, and check new capabilities against
[ADR-0001](docs/adr/0001-userland-dynamic-debugging-scope.md).

## License

[MIT](LICENSE) © gdb-mcp contributors
