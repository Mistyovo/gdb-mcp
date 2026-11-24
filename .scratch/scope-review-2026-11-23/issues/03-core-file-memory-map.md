# 03 — core file 的停止上下文与内存映射

Status: resolved
Type: task
Priority: P1
Area: crash triage / state
Depends on: —

## 问题

`load_target(core=True)` 能加载 core，但 `get_memory_map` 与
`crash_report` 的映射部分依赖插件的 `mem_map` verb，而该 verb 执行的是
`info proc mappings`——它需要活进程。core 文件场景下该命令通常为空，
`crash_report` 于是缺少结构化内存映射（memory_at_pc / memory_at_sp 仍可用）。

“崩溃快速定位”是初衷旗舰之一，离线 core 是它的自然场景，应补齐。

## 任务

- 插件 `_handle_mem_map`：先试 `info proc mappings`；输出没有可解析段时回退到
  `info files` / `maintenance info sections`（core 文件可用的格式）。
- 服务端补一个 core 段解析器（或在 `output.py` 里扩展 `parse_proc_mappings`
  的兄弟函数），产出与现有 `segments` 相同的结构（start/end/size/perms/objfile）。
- `crash_report` 在 `mem_map` 为空时给出 `warnings` 而不是静默缺失；若回退成功，
  正常填充 `memory_map`。
- 补 mock 单测（core 文本样例）与一个真 gdb/core 冒烟（可用 `generate-core-file`
  生成）。

## 验收

- `load_target(core=True)` 后 `get_memory_map()` 返回非空 `segments`；
- `crash_report()` 的 `memory_map.segments` 非空，且包含 PC/SP 所在段；
- 活进程路径行为不变；
- 单测 + 真机冒烟通过。

## 参考

- `src/gdb_mcp/plugin/gdb_mcp_plugin.py::_handle_mem_map`、`_handle_core`
- `src/gdb_mcp/tools/state_tools.py::get_memory_map`
- `src/gdb_mcp/tools/crash_tools.py::_collect_crash_report`
- `src/gdb_mcp/output.py::parse_proc_mappings`
