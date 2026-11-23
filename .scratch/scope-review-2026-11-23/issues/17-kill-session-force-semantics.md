# 17 — kill_session(force=True) 与文档/e2e 的语义不一致

Status: resolved
Type: grilling
Priority: P2
Area: sessions / e2e
Depends on: —

## 问题

`src/gdb_mcp/tools/launch_tools.py::kill_session` 的 docstring 写明：

> force=True terminates the gdb process tree; forget=True drops the record
> even when detaching.

按此契约，`force=True` 只负责杀进程，`forget=True` 才丢记录。但实现是：

```python
keep_record = not force and not forget
```

即 `force=True` 也会删除 session 记录。2026-11-23 跑
`tests/integration/run_mcp_tools_e2e.py` 时，脚本在
`kill_session(child_gdb_session, force=True)` 之后调用
`wait_for_state(..., {"disconnected"})`，`session_status` 返回
`NO_SESSION`（`wait_for_state` 只接受状态字符串，于是 e2e 结束失败）。
这与 heap 时间线改动无关，是既有行为。

## 决策选项

- **A（建议）按 docstring 修实现**：`keep_record = not forget`。force 杀进程但
  保留 DISCONNECTED 记录（GC 会回收），forget 才删；补一条 force=True 的单测。
- **B 按实现修文档/e2e**：明确 force 隐含 forget，更新 docstring，并让 e2e 的
  `wait_for_state` 把 `NO_SESSION` 视为 disconnected。
- **C 拆成两个显式参数**：`kill` 与 `forget` 分开，拒绝歧义组合；成本最高。

推荐 A：docstring 与 e2e 的期望一致，且“杀掉进程但保留会话历史”更有用；
B 会让“force 杀进程”意外丢历史，C 对现有 API 破坏较大。

## 验收

- 决策记录在本 issue。
- 若 A：`kill_session(force=True, forget=False)` 返回 `record_kept: true`，
  `session_status` 可见 `state: disconnected`；`forget=True` 才删除记录；
  补单测；e2e 全绿。
- 若 B/C：docstring、README、e2e 同步，并补对应单测。

## 参考

- `src/gdb_mcp/tools/launch_tools.py::kill_session`
- `tests/test_tools.py::TestSessionTools`
- `tests/integration/run_mcp_tools_e2e.py::wait_for_state`（约 191 行）
- 2026-11-23 本地 e2e 输出：
  `MCP TOOLS E2E FAILED: session_status failed: ... NO_SESSION: no session with id 's-...'`

## Resolution（2026-11-23）

采用选项 A：

- `kill_session` 的 `keep_record` 改为 `not forget`：`force=True` 只终止进程
  树，记录保留为 `DISCONNECTED`（由 GC 在 `gc_idle_disconnected` 后回收）；
  `forget=True` 才删除记录。RESERVED 占位会话与 script 会话的行为不变
  （前者没有可复活的插件，后者按文档终止并移除）。
- docstring 明确 force 保留记录；README.zh-CN 的 kill_session 说明同步。
- 新增单测：
  `test_kill_session_force_keeps_record`（quit 的 `kill_gdb=True`、记录保留、
  状态 disconnected）与 `test_kill_session_forget_drops_record`
  （`kill_gdb=False`、记录删除）。
- 验证：`python -m pytest tests/ -q` → 930 passed, 1 skipped；
  `ruff` 全绿；`run_mcp_tools_e2e.py --distro kali-linux` →
  `ALL 30 WALKTHROUGH TOOLS PASSED (51 registered)`，原尾部
  `NO_SESSION` 失败消失。

