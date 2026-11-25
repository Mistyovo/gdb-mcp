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
[![Tests](https://img.shields.io/badge/tests-unit%20%2B%20real--gdb-brightgreen)](#testing)

[Quick Start](#quick-start) · [Tools](#tool-catalog) · [Architecture](#architecture) · [Scope Gate](docs/adr/0001-userland-dynamic-debugging-scope.md) · [中文文档](README.zh-CN.md)

</div>

---

## Why gdb-mcp?

Most "debugger MCP" projects parse GDB/MI output or scrape terminal screens.
**gdb-mcp takes a different route: a small stdlib-only Python plugin runs
*inside* the gdb process** and talks to the server over a JSON-lines control
channel — so pwndbg contexts, pwntools-launched sessions, and reverse-execution
all just work, with none of the prompt-scraping fragility.

- **Sharp userland surface** — the default `pwn` profile exposes **17 focused tools**
  (consolidated from 36, ~5.2k tokens total and bounded by a CI-enforced
  schema byte budget). Static analysis, kernel VMs, and enterprise HTTP stacks
  are deliberately out of scope ([ADR-0001](docs/adr/0001-userland-dynamic-debugging-scope.md)).
- **Built for pwn, not just debugging** — one-call crash triage & replay,
  glibc `heap(action="bins")` + standalone `heap(action="chunk")` decoding
  (safe-linking aware), allocation return timelines, checkpoint/restore,
  `inferior_io(action="send")` / `inferior_io(action="read")`
  for menu targets, and an evidence-backed campaign state machine.
- **Token-frugal by design** — `control_execution(action="continue", wait=True, with_context=True)`
  returns the stop picture (verdict + key registers + backtrace + disassembly)
  in one call; oversized outputs spill to disk instead of flooding context.
- **Delegated execution** — bounded loops (`trace`, `heap_arm`, `fuzz_loop`,
  `minimize`, `bp_stats`, `verify_pc_control`) run *inside* gdb at native speed
  and return constant-size summaries; `interrupt` cancels an active policy
  cleanly with partial results.
- **Fails fast before the first launch** — `gdb-mcp --selfcheck` reports the
  gdb command/version, embedded Python, pwndbg visibility, plugin file, and
  listener port in one JSON report, exiting non-zero when a session could not
  start. Linux defaults to the native launcher; Windows defaults to WSL.
- **pwntools stays in charge** — `gdb.debug()` / `gdb.attach()` sessions
  register automatically; the server never fights your scripts for I/O.
- **Verified against reality** — unit tests (including seeded protocol
  fuzzing), real-gdb CI smokes across gdb 12 / 15 / 18, and a 72-task
  acceptance benchmark across 9 families (including `pwn_workflow`,
  reference-solved 72/72).

## Quick Start

**1. Install** (Windows side with WSL2 backend, or natively on Linux):

```powershell
pip install -e .
```

The default launcher follows the host: **`native` on Linux**, **`wsl` on
Windows**. Override it with `--launcher` / `GDB_MCP_LAUNCHER`; point at a
specific binary with `--gdb-path` / `GDB_MCP_GDB_PATH` (for example
`gdb-multiarch`).

**2. Prepare Linux / WSL2**:

```bash
sudo apt install gdb python3 python3-pip gcc   # pwndbg optional but recommended
```

**3. Register with your MCP client**:

When the MCP server runs **on Windows** and launches gdb in WSL2, use
`--launcher wsl` explicitly. Claude Code (`.mcp.json`):

```json
{
  "mcpServers": {
    "gdb-mcp": {
      "command": "gdb-mcp",
      "args": ["--launcher", "wsl"],
      "env": { "GDB_MCP_PORT": "3939" }
    }
  }
}
```

When the MCP client and server run **inside Linux or WSL2**, install the
package there and use `--launcher native` instead (do not invoke WSL from
inside WSL):

```json
{
  "mcpServers": {
    "gdb-mcp": {
      "command": "gdb-mcp",
      "args": ["--launcher", "native"],
      "env": { "GDB_MCP_PORT": "3939" }
    }
  }
}
```

Cursor uses the same shape in `~/.cursor/mcp.json`. Codex CLI (Windows
host; change `wsl` to `native` inside Linux/WSL2):

```toml
[mcp_servers.gdb-mcp]
command = "gdb-mcp"
args = ["--launcher", "wsl"]
env = { GDB_MCP_PORT = "3939" }
```

**4. Check the launcher before debugging.** `gdb-mcp --selfcheck` prints a
JSON report and exits non-zero when a session could not start: the gdb
command and version, embedded Python, pwndbg visibility, the installed
plugin file, and whether the listener port is free. It accepts the same
`--launcher`, `--gdb-path`, and `--port` flags as the server.

```bash
gdb-mcp --selfcheck
```

**5. Call tools through your MCP client.** These Python-shaped blocks are
**MCP call notation, not an importable Python API or standalone Python script**.
Use your own Linux target path; replace `SESSION_ID` with the session ID returned
by `launch_gdb`. The examples below are individual operations, not one script.

Start with the bundled example (`examples/hello.c`):

```bash
gcc -g -O0 -o /tmp/gdb-mcp-hello examples/hello.c
```

<!-- mcp-calls:start -->
```python
launch_gdb(program="/tmp/gdb-mcp-hello", run=False)
breakpoint(action="set", location="break_here", session_id="SESSION_ID")
execute_command(command="run", session_id="SESSION_ID")
control_execution(action="wait", timeout_ms=10000, session_id="SESSION_ID")
inspect_code(action="backtrace", max_frames=8, session_id="SESSION_ID")
kill_session(force=True, session_id="SESSION_ID")
```
<!-- mcp-calls:end -->

`examples/crasher.c` is the crash-triage example; the menu example below uses
a pty for interactive I/O.

<!-- mcp-calls:start -->
```python
launch_gdb(program="/tmp/menu", stdio="pty", run=True)
control_execution(action="continue", wait=True, with_context=True, session_id="SESSION_ID")
inferior_io(action="send", text="1\n", session_id="SESSION_ID")
inferior_io(action="read", since_seq=0, session_id="SESSION_ID")
```
<!-- mcp-calls:end -->

Only resume a stopped inferior; send/read stdio while it runs at a menu prompt.
For a stopped session, these are additional operations: bins require pwndbg,
chunk requires a valid chunk address (replace the example address), and loading
a core requires a matching executable already loaded.

<!-- mcp-calls:start -->
```python
heap(action="bins", session_id="SESSION_ID")
heap(action="chunk", address="0x555555559290", session_id="SESSION_ID")
load_target(path="/tmp/menu", session_id="SESSION_ID")
load_target(path="/tmp/core.menu", core=True, session_id="SESSION_ID")
```
<!-- mcp-calls:end -->

Alternatively, keep your pwntools workflow untouched and load the installed
plugin (run this script inside Linux/WSL2, with the package installed there):

```python
from pathlib import Path
from pwn import *
import gdb_mcp

plugin = Path(gdb_mcp.__file__).resolve().parent / "plugin" / "gdb_mcp_plugin.py"
io = gdb.debug("./vuln", gdb_args=["-x", str(plugin)])
```

## Tool Catalog

**17 tools by default** in the `pwn` profile (~5.2k tokens), **10** under
`GDB_MCP_TOOL_PROFILE=core` (~3.3k tokens), plus **1 experimental tool**
(`diff_sessions`, behind `--experimental`).

| Profile | Purpose |
|---|---|
| `core` | Minimal 10-tool session/execution/state/breakpoint/crash surface |
| `pwn` (default) | Core + heap, checkpoints, policies, campaign, inferior stdio, threads/frames, target loading |

| Group | Tools |
|---|---|
| Sessions | `launch_gdb` (`program`, `attach_pid`, or `script` for pwntools; optional `stdio="pty"`) `kill_session` (`force`/`forget`) `session_info` (`list`/`status`/`events`/`output`/`export`) |
| Execution & I/O | `control_execution` (`continue`/`step`/`next`/`stepi`/`nexti`/`finish`/`until`/`reverse_*`/`wait`/`interrupt`, `with_context=True`) `execute_command` (raw gdb/pwndbg, multi-line, paginated + `result_file` slicing) `inferior_io` (`send`/`read` over pty) |
| State & Breakpoints | `memory` (`read`/`write`/`map` with core fallback) `registers` (`read`/`write`) `inspect_code` (`disassemble`/`backtrace`/`evaluate`) `thread_frame` (`list_threads`/`select_thread`/`select_frame`) `load_target` (`path`, optional `core=True` for a core dump; no `action`) `breakpoint` (`set`/`list`/`delete`/`enable`/`disable`) |
| Crash & Pwn | `crash_report` (triage + optional checkpoint replay/minimize/evidence) `heap` (`bins` via pwndbg / `chunk` standalone with safe-linking decode) `checkpoint` (`create`/`list`/`restore`/`diff`) `run_policy` (`trace`/`heap_arm`·`read`·`disarm`/`fuzz_loop`/`crash_check`/`minimize`/`bp_stats`/`verify_pc_control`) `campaign` (`get`/`set`/`note`/`detect`/`protections`/`pattern`) |

`kill_session` separates four outcomes instead of one ambiguous "killed":

| Call | What happens |
|---|---|
| `kill_session()` | plugin detaches; gdb and the inferior keep running |
| `kill_session(force=True)` | termination of a launched process tree is *requested*; an attached gdb is asked to quit |
| `kill_session(forget=True)` | also drops the server-side record |
| `kill_session(force=True, forget=True)` | request termination and drop the record |

Results carry `launched`, `process_termination`, and `termination_note`;
termination is a request, not proof that the process exited.

## Architecture

```
Claude Code / any MCP client ──stdio──► gdb-mcp server (17 default tools)
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

Launchers: **WSL2** (`--launcher wsl`, default on Windows) and **native Linux**
(`--launcher native`, default on Linux). Transport: **stdio**.

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
  `host`, or `admin`. `--readonly` keeps only `observe` tools plus the
  read-only view `breakpoint(action="list")` (excluding `execute_command`,
  `control_execution`, `launch_gdb`, breakpoint mutations, writes, and
  policies). Retained tools still reject mutating actions:
  `session_info(action="export")` and `inspect_code(action="evaluate")` return
  `READONLY`; status, backtrace, and disassembly remain available.
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
python -m pytest tests/ -q

# real-gdb suites (WSL2 or native Linux)
wsl bash tests/integration/run_wsl_integration.sh # plugin <-> server protocol
wsl bash tests/integration/run_policy_smoke.sh    # policy loops (trace/bp_stats)
wsl bash tests/integration/run_pc_control_smoke.sh # PC-control verification
wsl bash tests/integration/run_heap_smoke.sh      # heap timeline (allocation returns)
wsl bash tests/integration/run_io_smoke.sh        # inferior stdio over a pty
wsl bash tests/integration/run_unsafe_gate_probe.sh # unsafe gate premises
PYTHONPATH=src python tests/integration/run_mcp_tools_e2e.py --distro kali-linux

# acceptance benchmark (72 tasks across 9 families, incl. pwn_workflow)
python -m bench.framework.cli build --distro kali-linux
python -m bench.framework.cli selfcheck --distro kali-linux
```

For the installed-package MCP end-to-end regression, first build a wheel and
install it into a **clean Linux/WSL2 virtual environment**, then run
`python -I tests/integration/run_native_install_smoke.py` using that venv's
Python. This tests the installed wheel over MCP stdio with the native launcher
through the generated `gdb-mcp` entry point; it is not a source-tree smoke.
CI runs it on Ubuntu 22.04 with Python 3.10 and Ubuntu 24.04 with Python 3.13.
Do not use an editable install, `PYTHONPATH=src`, or a plugin-path override for
this check.

## Contributing

Issues and PRs welcome — please keep `python -m pytest tests/ -q` and
`ruff check src tests bench` clean, and check new capabilities against
[ADR-0001](docs/adr/0001-userland-dynamic-debugging-scope.md).

## License

[MIT](LICENSE) © gdb-mcp contributors
