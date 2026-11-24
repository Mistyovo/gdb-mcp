# 05 — 范围决策：Ghidra 静态分析族是否外移

Status: resolved
Type: grilling
Priority: P1
Area: scope / static analysis
Depends on: —

## 背景

`full` 档包含 15 个 Ghidra 静态查询工具：

`analyze_binary` `list_analyses` `get_analysis_status` `get_binary_overview`
`list_sections` `list_symbols` `list_functions` `list_strings`
`decompile_function` `get_static_disassembly` `get_xrefs` `get_call_graph`
`search_decompiled_code` `annotate_code` `remove_code_annotation`

体量：`static_tools.py` + `reverse/` 约 1,327 行 Python，外加
`ghidra_scripts/ExportAnalysis.java` 和 Ghidra headless 依赖；`full` 档工具 schema
比 `pwn` 档多约 2.2k tokens。它与 gdb 会话零耦合，`AnalysisManager` 自己也写明
“live location mapping was removed with the dashboard”。

残留：`AnalysisStore.newest_for_path` / `matches_path` / `path_key` 只有测试引用，
是 dashboard 时代的死代码。

## 决策选项

- **A（建议）外移到独立包/仓库**（如 `gdb-mcp-static`，或独立 MCP server），
  本仓库最多保留一个不投入的薄桥；`full` 档退役或改名为 `labs`。
- **B 保留但冻结**：不再加功能，只修安全/兼容问题；删除死代码。
- **C 直接删除**：从本仓库移除静态族与 `reverse/`。

推荐 A：它保留了能力，但把“静态分析”从动态调试器的叙事和默认面里拿掉。

## 验收

- 决策记录在本 issue（或升级为 ADR）。
- 若 A/C：`src/gdb_mcp/reverse/`、`static_tools.py`、Ghidra 相关配置从本仓库移除或
  隔离；`README` 的 profile 表、Security Model、Testing 同步更新；相关测试随代码迁移。
- 若 B：删除 `newest_for_path`/`matches_path` 死代码，并在 README 标注“冻结/不推荐”。

## 参考

- `src/gdb_mcp/tools/static_tools.py`
- `src/gdb_mcp/reverse/`
- `.scratch/scope-review-2026-11-23/spec.md` §3.5
