# 04 — 长 policy 的取消语义

Status: ready-for-agent
Type: task
Priority: P1
Area: run_policy / plugin
Depends on: —

## 问题

`run_policy` 的 `fuzz_loop` / `minimize` / `trace` / `bp_stats` 在插件内以原生速度
跑，单次调用最长 600s。当前没有用户可见的取消路径：`_policy_active` 只会在
“新的 policy 请求”或“gdb 关闭”时被 abort；`interrupt` 只中断 inferior，policy 链
可能以错误收尾或留下半套状态。

## 任务

- 在插件 `_policy_drive` 的 `active` 句柄上增加 `cancel(partial_result)`：
  - 断开 stop/exited 链；
  - 把已积累的状态（rounds/crashes/survived/counts 等）作为部分结果返回；
  - 将 inferior 留在 stopped 状态，不杀会话。
- 二选一（建议先做前者）：
  - `interrupt` 检测到活动 policy 时走 `cancel`，原 `run_policy` 请求收到
    `cancelled: true` + 部分摘要；
  - 新增 `cancel_policy` 工具，显式取消。
- 区分“用户取消”和“policy 被新请求取代”：错误码 `POLICY_CANCELLED` vs
  `POLICY_STALE`。
- 补单测（mock 插件状态机）与真机 smoke（长 fuzz_loop 中途 interrupt）。

## 验收

- 长 `fuzz_loop` 可在不杀会话的前提下取消；
- 原 `run_policy` 调用收到结构化部分结果（`cancelled: true`，含已完成 rounds）；
- 取消后 inferior 停在可继续调试的状态；
- 会话后续工具调用正常。

## 参考

- `src/gdb_mcp/plugin/gdb_mcp_plugin.py::_policy_drive`、`_handle_policy`
- `src/gdb_mcp/tools/heap_tools.py::run_policy`
- `src/gdb_mcp/tools/exec_tools.py::interrupt`
