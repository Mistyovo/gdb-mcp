# 16 — ADR：用户态动态调试范围守则

Status: resolved
Type: task
Priority: P1
Area: process / docs
Depends on: 05, 06, 07, 08

## 问题

过去三个月的漂移没有一条成文的范围判据，导致“功能尽可能强大”成为默认决策。
审计报告提出了四条判据；应把它固化成 ADR，供后续 PR/issue 引用。

## 任务

新增 `docs/adr/0001-userland-dynamic-debugging-scope.md`（编号按当时 `docs/adr/`
现状调整），内容至少包含：

1. **定位**：gdb-mcp 是真实、pwndbg-aware 的用户态 gdb 的 MCP 前端。
2. **范围**：拉起/附着、执行控制、状态检查、断点、崩溃定位、有界 pwn 循环
   （checkpoint/fuzz/minimize）、pwntools 共存。
3. **非范围**：静态分析、内核调试、Web UI、企业级认证、基准研究。
4. **准入判据**：新功能必须回答“它是否让 agent 更好地驱动一个活的用户态 gdb？”
   答否的做成独立 MCP/独立仓库，不进入默认面。
5. **减法原则**：默认面只保留 pwn 闭环需要的工具；扩展家族必须 opt-in，且有明确
   的退役条件。

同时：

- 在 `AGENTS.md` 的“Repo ground rules”加一行指向该 ADR；
- 在 README 的 Contributing 或 Architecture 段落链接；
- 若 05–08 的决策已落地，把结论写进 ADR 的 Decision 段。

## 验收

- ADR 文件存在，格式与 `docs/agents/domain.md` 约定一致；
- `AGENTS.md`/README 有链接；
- 后续 issue 模板（若有）或 PR 描述可引用“准入判据”；
- 不在 ADR 中复制整份审计报告，只引用
  `.scratch/scope-review-2026-11-23/spec.md`。

## 参考

- `docs/agents/domain.md`
- `.scratch/scope-review-2026-11-23/spec.md` §4.5、§5
- `AGENTS.md`
