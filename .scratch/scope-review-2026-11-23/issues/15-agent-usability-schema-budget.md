# 15 — agent 可用性与工具 schema token 预算

Status: needs-triage
Type: research
Priority: P2
Area: agent ergonomics / token budget
Depends on: 10

## 背景

实测工具 schema 的固定上下文成本：

| profile | 工具数 | schema |
|---|---|---|
| core | 12 | 约 3.2k tokens |
| pwn（默认） | 35 | 约 8.0k tokens |
| full | 50 | 约 10.2k tokens |
| full + experimental | 56 | 约 11.7k tokens |

README 把“token-frugal by design”作为卖点，但工具定义本身是每次会话的固定税。
同时，bench 的唯一模型报告（deepseek-chat）只有 18/48 = 37.5%，说明瓶颈更多在
agent 可用性/工具描述/错误信息，而不是工具数量不够。

## 任务

- 设定预算目标（建议：默认 `pwn` 档 ≤ 6.5k tokens，`full` 退役或 ≤ 8k）。
- 审计 35 个工具的 docstring：
  - 保留“何时用 / 关键参数 / 返回形状 / 常见错误”；
  - 删除营销性描述、重复的背景说明、与 README 重复的长段；
  - 统一参数命名（`session_id`、`timeout_ms`、`offset/limit`）。
- 与 issue 10 的工具合并联动，优先删/并低价值工具。
- 增加一个回归测试：构造 app 后计算已注册工具的 schema 字节数，断言不超过预算
  （防止后续 PR 无声膨胀）。
- 用 bench 的失败样本（optimize/threads 家族 0%）复盘：是工具描述、错误信息，
  还是缺少一步到位的流程？把结论写入本 issue 的 Comments。

## 验收

- 预算目标记录在本 issue。
- `pwn` 档 schema 降到目标内；核心工具的“何时用/参数/错误”信息不丢。
- schema 预算测试入库并被 CI 执行。
- 至少一份基于 bench 失败样本的可用性结论（不是泛泛而谈）。

## 参考

- `src/gdb_mcp/tools/*.py` docstrings
- `src/gdb_mcp/server.py` instructions
- `bench/reports/agent-deepseek-chat-first48-20260926.json`
- `.scratch/scope-review-2026-11-23/spec.md` §2
