# 01 — campaign cyclic 命中按来源归因

Status: resolved
Type: task
Priority: P0
Area: campaign / crash triage
Depends on: —

## 问题

`campaign_detect` 把 PC、fault_addr、所有寄存器的 cyclic 命中一律写成
`primitives["pc_control"]`。任意寄存器命中都会被当成“已控制 PC”，并被注入后续
停止摘要，误导 agent。

复现（修复前）：

```text
match: {'source': 'reg:rax', 'offset': 64, 'sub': 4}
primitives recorded: {'pc_control': {'evidence': 'reg:rax matches cyclic pattern at offset 64'}}
```

PC 实际未变。

## 修复

`src/gdb_mcp/campaign.py`：

- 新增 `_CYCLIC_PRIMITIVE_KEYS`：`pc -> pc_control`、`fault_addr -> fault_addr_controlled`；
- 其余来源（`reg:<name>`）记为通用 `cyclic_match`，`value` 保留来源名（如 `reg:rax`）；
- `campaign_detect` docstring、`campaign` 工具描述、`crash_report` 注释同步更新；
- README / README.zh-CN 的 campaign 说明改为“按来源归因”。

## 验收

- `tests/test_campaign.py::test_detect_uses_register_values` 断言寄存器命中**不**产生
  `pc_control`，且 `cyclic_match.value == "reg:rax"`；
- 新增 `test_detect_records_fault_addr_control`；
- `python -m pytest tests/ -q`：910 passed, 1 skipped；
- `ruff check src tests bench`：通过。

## 参考

- `src/gdb_mcp/campaign.py`（`campaign_detect`）
- `src/gdb_mcp/tools/campaign_tools.py`
- `src/gdb_mcp/tools/crash_tools.py`
- `tests/test_campaign.py`
