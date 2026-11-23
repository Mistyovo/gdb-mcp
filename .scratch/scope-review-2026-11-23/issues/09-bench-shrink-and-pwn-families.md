# 09 — bench 收缩并对准 pwn 闭环

Status: needs-triage
Type: grilling
Priority: P1
Area: bench / CI
Depends on: —

## 背景

当前 bench：

- 576 个任务、53,381 行提交的 JSON、577 个文件；
- 8 个家族：breakpoints / crash / inspect / lifecycle / multistep / optimize /
  pie / threads，全部是**通用 gdb 调试**任务；
- 框架约 3,864 行，含模型 agent runner 与已提交的 deepseek-chat 报告
  （18/48 = 37.5%）；
- CI 每个 PR 构建目标 + 参考解 576 个任务 + tier-1 gate。

问题不是“大”，而是**测错了东西**：`checkpoint` / `run_policy` / `campaign` /
`triage_crash` / heap 利用闭环在 bench 里一个任务都没有；576/576 参考解只证明
工具能用，模型 18/48 才暴露 agent 可用性问题。

## 决策选项

- **A（建议）收缩 + 对准**：
  - committed 任务降到 60–100 个（每个现有家族保留 6–9 个代表）；
  - 新增 pwn 家族：`heap_bins`、`checkpoint`（create/restore/diff）、
    `run_policy`（fuzz_loop/crash_check/minimize）、`campaign`（pattern/detect）、
    `triage_crash`；
  - 保留 `selfcheck` 与 tier-1 gate；
  - 模型 agent runner / 报告移到 `research/` 或外仓，不随产品 CI 跑。
- **B 只收缩**：不新增 pwn 家族，只减任务数。
- **C 维持现状**：继续加通用任务。

推荐 A：用更小的回归集覆盖真正的差异化路径。

## 验收

- 决策记录在本 issue。
- 若 A/B：`bench/tasks/` 文件数与 JSON 行数显著下降；CI bench job 时间下降；
  baseline 更新；README 的“576 tasks”等数字同步。
- 若 A：至少 4 个 pwn 家族入库，且全部 reference-solve 通过；`report --gate`
  仍能覆盖 tier-1 指标。
- 模型 runner/报告不再位于产品 CI 路径。

## 参考

- `bench/SPEC.md`
- `bench/framework/generators/`
- `bench/reports/agent-deepseek-chat-first48-20260926.json`
- `.github/workflows/ci.yml`（bench job）
- `.scratch/scope-review-2026-11-23/spec.md` §3.8
