# gdb-mcp agent notes

Give your coding agent hands on a real GDB — built for binary exploitation.
See `README.md` for the product surface; this file is the agent-workflow
configuration for the engineering skills.

## Agent skills

### Issue tracker

Issues and specs live as local markdown under `.scratch/` (no `gh` CLI on
this machine). See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage roles, used verbatim as `Status:` strings.
See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout (`GLOSSARY.md` + `docs/adr/`, created lazily);
`ROADMAP_V2.md` decision sections count as ADRs. See `docs/agents/domain.md`.

## Repo ground rules (mirror of README/CI)

- Unit tests run on Windows with no gdb: `python -m pytest tests/ -q`
  (exit code must be checked explicitly — never trust a piped tail).
- `ruff check src tests bench` must stay clean.
- Real-gdb suites live under `tests/integration/` and run in WSL2 or CI;
  the policy family's resume/stop semantics are pinned by
  `run_policy_smoke.sh` (see `src/gdb_mcp/plugin/gdb_mcp_plugin.py`,
  `_policy_drive` docstring, for the three verified gdb facts).
- Experimental features are CLI-gated only (`--experimental`); never add
  environment-variable paths for them.
