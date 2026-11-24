# 10 — 工具面合并：triage_crash / batch_commands / diff_sessions

Status: resolved
Type: task
Priority: P1
Area: tools / surface
Depends on: 01

## 问题

默认 `pwn` 档有 35 个工具，其中三个与既有路径重叠，增加概念面和 schema token：

1. **`triage_crash`**：本质是 `run_policy(crash_check)` + `crash_report` +
   `run_policy(minimize)` + 证据落盘 + campaign note；与 `crash_report` 重复收集
   报告，维护两套路径。
2. **`batch_commands`**：`execute_command` 已能执行多行 gdb 命令，unsafe gate 也
   逐行检查；`batch_commands` 仅多了 per-command 结果。
3. **`diff_sessions`**：两输入差分调试，边缘能力；受 ASLR 影响时寄存器差分意义有限。

## 任务

- 把 `triage_crash` 合并进 `crash_report`，新增可选参数：
  `payload_hex`、`buffer_addr`、`stop_location`、`snapshot_id`、`minimize`。
  有回放参数时先走 `crash_check`，再收集报告；保留证据文件与 campaign note。
  可保留 `triage_crash` 作为一版弃用别名（直接转调），或一次性移除。
- 删除 `batch_commands`；在 `execute_command` 文档里说明多行命令与逐行 unsafe gate。
- 把 `diff_sessions` 移到 `--experimental`，或删除；若保留，文档注明 ASLR 前提
  （关闭 ASLR 或只比较同基址会话）。
- 同步更新：`tools/__init__.py` 无需改（模块导入），但 e2e 脚本、README 工具表、
  `server.py` instructions、测试计数需更新。

## 验收

- 默认 `pwn` 档工具数 35 → 32（保留别名则 33）；
- `crash_report` 在带回放参数时覆盖原 `triage_crash` 行为（reproduced / report /
  minimized / evidence_file / campaign note）；
- e2e：`tests/integration/run_mcp_tools_e2e.py` 更新并通过；
- README / instructions 不再列出已删工具；
- `pytest` + `ruff` 通过。

## 参考

- `src/gdb_mcp/tools/crash_tools.py`
- `src/gdb_mcp/tools/exec_tools.py`
- `src/gdb_mcp/tools/campaign_tools.py`
- `tests/integration/run_mcp_tools_e2e.py`
