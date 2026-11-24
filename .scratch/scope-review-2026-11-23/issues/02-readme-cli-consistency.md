# 02 — README 与 CLI 帮助的失准点

Status: resolved
Type: task
Priority: P1
Area: docs / config
Depends on: —

## 问题

范围审计发现四类文档/帮助失准：

1. **死链接**：`ROADMAP.md`、`ROADMAP_V2.md` 已在最新提交删除，但
   `README.md`（目录、Security Model、Roadmap 三处）和 `README.zh-CN.md`
   仍指向它们；`docs/agents/domain.md` 也提到 `ROADMAP_V2.md`。
2. **`--readonly` help 失准**：`src/gdb_mcp/__main__.py` 写的是
   “drop state-mutating tools (write_memory/write_register)”，但
   `tools/registry.py::_visible` 实际丢掉**所有**非 `observe` 工具，包括
   `execute_command`、`continue_execution`、`launch_gdb`。
3. **experimental 归属矛盾**：README 的 Experimental Features 把
   `minimize` 列为实验特性，但 `run_policy(kind="minimize")` 在默认 `pwn`
   档即可用，没有被 `--experimental` 门控。
4. **计数**：README 写“910 unit tests”；当前为 910 passed + 1 skipped。
   数字本身接近，但应写成可复核的口径。

## 任务

- 删除或替换所有指向已删除 roadmap 的链接；若需要 roadmap，补一个短文件或改指向
  git 历史/ADR。
- 把 `--readonly` help 改成准确描述（“只保留 observe 能力；execute_command /
  launch / 断点 / 写操作均被排除”）。
- 二选一：把 `run_policy(kind="minimize")` 真正纳入 `--experimental` 门控，或把它从
  Experimental Features 移到 Pwn workflow，并在 README 中说明默认可用。
- 统一测试计数口径（passed / skipped）。
- 检查 `README.zh-CN.md` 同步。

## 验收

- `grep -rn "ROADMAP" README.md README.zh-CN.md docs/` 不再命中已删除文件；
- `gdb-mcp --help` 的 `--readonly` 描述与 `_visible` 行为一致；
- README 的 Experimental 列表与实际 `experimental=True` 工具一一对应；
- 中文 README 与英文 README 的档位/工具数一致。

## 参考

- `README.md:19,282,319`、`README.zh-CN.md:22`
- `src/gdb_mcp/__main__.py`（`--readonly`）
- `src/gdb_mcp/tools/registry.py::_visible`
- `README.md` Experimental Features vs `src/gdb_mcp/tools/heap_tools.py::run_policy`
