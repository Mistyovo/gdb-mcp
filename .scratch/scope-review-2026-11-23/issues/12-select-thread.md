# 12 — 增加 select_thread 工具

Status: resolved
Type: task
Priority: P1
Area: state / threads
Depends on: —

## 问题

`list_threads` 能列出线程与选中项，但没有选择线程的结构化工具。多线程调试时
agent 只能 `execute_command("thread N")`，把结构化路径降级成 CLI 字符串，且
`read_registers` / `get_backtrace` / 内存读取都受当前选中线程影响。

bench 的 threads 家族也依赖线程切换；结构化选择能减少 agent 的步数和错误。

## 任务

- 新增工具 `select_thread(number: int, session_id=None)`：
  - capability `debug`（改变调试器选中状态）；
  - 要求 stopped；
  - 插件新增 verb `thread_select`（或复用 `eval` 但不要暴露 CLI 字符串）；
  - 返回 `{"number", "selected", "frame": {...}}`，与 `list_threads` 的字段一致。
- `_handle_threads` 已有选中逻辑，复用。
- 同步 README 工具表、server instructions、e2e。

## 验收

- `list_threads` → `select_thread(2)` → `read_registers()` 返回线程 2 的寄存器；
- 非法线程号返回 `BAD_PARAMS`，不改变当前选中；
- 线程运行中拒绝（`INFERIOR_RUNNING`）；
- 单测 + e2e 通过；`ruff` 干净。

## 参考

- `src/gdb_mcp/tools/state_tools.py::list_threads`
- `src/gdb_mcp/plugin/gdb_mcp_plugin.py::_handle_threads`
- `bench/framework/generators/threads.py`
