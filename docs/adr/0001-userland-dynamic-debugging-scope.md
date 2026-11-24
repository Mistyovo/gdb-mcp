# ADR-0001: Userland Dynamic Debugging Scope Gate

- Status: Accepted
- Date: 2026-11-23
- Audit reference: `.scratch/scope-review-2026-11-23/spec.md`

## Context

In its first three months, `gdb-mcp` expanded beyond driving a live userland
`gdb` process into static decompilation (Ghidra), kernel VM orchestration
(QEMU), host-side pwn helpers (`identify_libc`, `search_gadgets`), unverified
Docker/SSH launchers, and enterprise HTTP/TLS/mTLS/observer/audit
infrastructure. That expansion taxed the MCP tool schema, blurred the product
narrative, and created maintenance surface unrelated to the core mission.

## Decision

1. **Product identity**: `gdb-mcp` is an MCP frontend for a real,
   pwndbg-aware Linux userland `gdb` process.
2. **In scope**:
   - Launching and attaching to Linux userland processes (`wsl`, `native`),
     and coexisting with `pwntools` (`gdb.debug()` / `gdb.attach()`).
   - Execution control, structured state inspection, breakpoints, thread and
     frame selection, inferior stdio (`send_input`/`read_output`), and
     core-file crash triage.
   - Bounded, native-speed pwn workflows inside `gdb`: glibc heap bins and
     chunk decoding, allocation return timelines, checkpoints, fuzz/minimize
     loops, and evidence-backed campaign state.
   - Local security primitives: loopback-by-default TCP listener, session-
     scoped HMAC tokens, abbreviation-aware unsafe-command gate, and
     `--readonly` capability filtering.
3. **Out of scope**:
   - Static binary analysis / decompilation (Ghidra/IDA/Binary Ninja).
   - Kernel / VM debugging (QEMU/gdbstub).
   - Host-side network/CLI helpers that do not touch `gdb` (`libc.rip`,
     `ROPgadget`).
   - Web dashboards, enterprise HTTP/TLS/mTLS/observer/audit stacks, and
     unverified remote/container launchers.
4. **Admission gate**: Every new tool or subsystem must answer *yes* to:
   > Does this help an agent drive a live Linux userland `gdb` better?
   Anything that answers *no* belongs in a separate MCP server or package.
5. **Schema budget**: The default `pwn` profile is bounded by a CI-enforced
   schema byte budget (`TestDocumentedCounts.PWN_SCHEMA_BYTE_BUDGET`).

## Consequences

- Removed out-of-scope modules (`reverse/`, `kernel/`, `static_tools.py`,
  `experimental.py`, `audit.py`, `http_hardening.py`, `roles.py`, `docker/`).
- Consolidated overlapping tools (`triage_crash` -> `crash_report`,
  removed `batch_commands`, moved `diff_sessions` behind `--experimental`).
- Promoted userland pwn essentials into the default `pwn` profile
  (`heap_chunk`, `select_thread`, `send_input`, `read_output`,
  `verify_pc_control`, `campaign(action="protections")`, core-file map
  fallback, and policy cancellation).
- Shrunk the committed acceptance benchmark to 72 tasks across 9 families
  (including `pwn_workflow`).
