# gdb-mcp Acceptance Benchmark — Specification

`BENCH_VERSION = 1.0.0` · schema `TASK_SCHEMA = 1.0.0` · created 2026-09-22

This is the **permanent, versioned acceptance benchmark** for gdb-mcp. It exists to
prove one claim: *an autonomous agent driving gdb-mcp can complete real GDB/pwndbg
debugging tasks, reliably, and we can measure that without trusting the agent's
self-reports.*

The previous E3 harness (3 crackmes + DeepSeek loop) was removed on 2026-09-22 by
user decision; its lessons are codified here:

1. **Reference solves are mandatory.** Every task must be solved by a deterministic
   script through the real MCP server before any model runs on it. A task no
   reference solve passes is a broken task, not a hard task (the old `win.c`
   incident: an unsolvable target was misdiagnosed as model failure).
2. **Ground truth is state, not prose.** Task success means the live gdb/inferior
   state satisfies machine-checked predicates. The agent's final message is never
   evidence (fact-extraction tasks are the one exception, and they are graded
   against harness-observed truth).
3. **Everything is versioned and reproducible**: task manifests (with source and
   binary hashes), ground truth, runner code, and results all carry
   `BENCH_VERSION` and SHA-256 content hashes.

## 1. Layout

```
bench/
  SPEC.md            this document
  framework/         the harness (pure Python, drives the server over MCP stdio)
    schema.py        TaskSpec, checks, manifest versioning/hashing
    driver.py        McpDriver — async MCP client with timing for every call
    verifiers.py     ground-truth check operators (executed by the harness)
    targets/         C source generators + WSL build matrix (+ core dumps)
    generators/      task families: generate(seeds) -> [TaskSpec]
    solutions/       reference solves: deterministic MCP op scripts per family
    cli.py           generate | build | selfcheck | agent | report
  tasks/             generated task manifests (JSON, deterministic, committed)
  targets_out/       build artifacts (gitignored; rebuilt from generators)
  results/           raw run output (gitignored)
  reports/           committed metric snapshots keyed by BENCH_VERSION
```

## 2. Goal → component mapping

| Goal § | Requirement | Component | Metric gate |
|---|---|---|---|
| 1 | Hidden Debugging Benchmark ≥ 500 tasks, 98% success | `generators/` matrix × seeds → `tasks/`; `solutions/` anti-cheat | `report total_success_rate` |
| 2 | Expert Trace Dataset comparison | `expert_traces/` schema + recorder (human data collection) | AI ≥ 99% of expert, steps ≤ 1.5×, time ≤ 2× |
| 3 | State Inspection correctness ≥ 99% / fields ≥ 99.5% | `kind: "fact"` tasks; grader recomputes truth via independent MCP calls | field accuracy report |
| 4 | 100k tool calls / 10k sessions / ≥ 99.9% reliability | `framework/stress.py` (planned M4) | stress report |
| 5 | Failure recovery ≥ 99%, no cross-session pollution | `framework/faults.py` fault injection (planned M4) | recovery report |
| 6 | P50 ≤ 50 ms / P95 ≤ 200 ms / P99 ≤ 500 ms overhead, session ≤ 2 s, 100 concurrent, 24 h soak ≤ 10% RSS | `driver.py` records per-call overhead; `framework/perf.py` (planned M5) | perf report |
| 7 | pwndbg compatibility ≥ 95% coverage / 99% pass | `generators/pwndbg_suite.py` + probe of pwndbg feature set (planned M6) | compat report |
| 8 | 100 agentic tasks ≥ 90% (hard ≥ 85%), ≤ 80% of step budget | `generators/agentic.py` multi-phase families | agentic report |
| 9 | CI regression: any tier-1 metric −1% ⇒ fail | `cli.py report --gate baseline.json`; `.github/workflows/ci.yml` bench job | exit code |
| 10 | Independent hidden set keeps all gates | generator supports held-out seed ranges (`--hidden`) | hidden report |

Milestones: **M0** (this commit) framework + first families + end-to-end selfcheck;
M1 scale to 500+ tasks, all reference-solved; M2 fact tasks at scale; M3 model agent
runner (pluggable OpenAI-compatible provider; `chat` class only — flash-class models
abandon tool loops); M4 stress + recovery; M5 perf + soak + concurrency; M6 pwndbg
suite + expert traces + CI gates.

## 3. Task model

A task is a JSON manifest (`bench/tasks/<family>/<id>.json`):

```jsonc
{
  "bench_version": "1.0.0",
  "schema_version": "1.0.0",
  "id": "bp_conditional-0003",              // family-seed, stable under regen
  "family": "breakpoints",
  "kind": "state",                          // "state" (grader inspects live state)
                                            // or "fact" (agent returns JSON facts)
  "difficulty": "easy" | "medium" | "hard",
  "tags": ["breakpoints", "conditions", "O2"],
  "target": {                               // produced by targets/generators
    "name": "bp_conditional_0003",
    "source": "int payload(...) { ... }",   // deterministic C text (in manifest)
    "build": {"flags": ["-O2", "-pie"], "strip": false, "core": false},
    "binary_sha256": "…",                   // filled by `build`
    "symbols": {"target": "0x11b9"}         // offsets recorded at build time
  },
  "params": {…},                            // family-specific deterministic params
  "prompt": "Set a breakpoint that only triggers when …",
  "max_steps": 8,
  "checks": [                               // ground truth (see §4)
    {"op": "breakpoint_hit", "spec": {"symbol": "audit", "cond": "i == 7"}}
  ]
}
```

Rules:

- Generation is seeded and deterministic: same seed ⇒ byte-identical manifest.
- `source` is embedded in the manifest, so tasks are self-contained and auditable;
  the compiled binary hash pins the exact artifact a run used.
- The **hidden set** (goal §10-J) is produced by held-out seed ranges with the same
  generators; nothing about a hidden task is visible in `bench/tasks/`.
- Answers cannot be hardcoded: every check derives its expected values from task
  `params` and build-time symbol offsets, then compares against *fresh harness-side
  MCP queries* of the live session.

## 4. Ground-truth check operators (`verifiers.py`)

`kind: "state"` — the agent must *make the state true*; the harness verifies by
querying the session itself (never by parsing agent output):

| op | verifies |
|---|---|
| `exit_code` | inferior exited with the required code |
| `breakpoint_present` | a breakpoint exists at symbol/address (+condition, +enabled) |
| `breakpoint_hit` | required breakpoint exists AND session stopped on it |
| `stop_signal` | last stop was the given signal at the given location class |
| `memory_value` | memory at symbol/expr equals the required bytes/value |
| `register_value` | register equals value/expr in the current stop |
| `variable_value` | evaluated expression equals required value in current frame |
| `pc_in_range` | PC inside [start, end) from symbol offsets |
| `backtrace_contains` | required frames (function names) present in order |
| `thread_stopped_at` | given thread stopped inside given function |
| `session_alive` | session healthy after the whole task (no pollution) |

`kind: "fact"` — State Inspection (goal §3). The harness first derives truth via
its own MCP calls (`derive_truth`), then asks the agent for a JSON answer and
compares structured fields; hallucinated fields (not in truth) count as errors.

## 5. Success definition and gates

```
task_success = all(checks pass) AND steps_used <= max_steps AND session_alive
```

Tier-1 metrics (goal §9/§10): `total`, `hard`, `multistep`, `pwndbg`, `state_fact`,
`recovery`, `stress_tool_success`, plus overhead percentiles. `cli.py report`
compares a result file against the committed baseline in `bench/reports/` and
exits non-zero if any tier-1 metric drops by more than 1 percentage point.

## 6. What this benchmark deliberately does NOT do

- It does not hardcode per-task answers anywhere in the repo; tasks ship as
  parameterized sources + checks.
- It does not trust any model-generated trace as evidence; `--dump` transcripts
  are for attribution only.
- It does not grade exploit *elegance*; only the ground-truth state predicates.
