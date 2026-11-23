# 13 — campaign 证据硬化：verify_pc_control + checksec 自动识别

Status: ready-for-agent
Type: task
Priority: P1
Area: campaign / run_policy
Depends on: 01

## 问题

修复 01 之后，campaign 只会把 **PC 命中**记为 `pc_control` 候选，但这仍是
“候选”：cyclic 命中说明寄存器/PC 值来自模式串，不等于攻击者能稳定改写 PC。
另外 `campaign.protections` 目前只能手工 `campaign set`，agent 常常忘记填。

## 任务

### A. `run_policy(kind="verify_pc_control")`

- 输入：`snapshot_id`、`payload`（hex）、`buffer_addr`、`stop_location`、
  `offset`、`canary`（默认唯一 8 字节，如 `0x4142434445464748`）。
- 逻辑：从 checkpoint 恢复 → 在 `buffer_addr + offset` 写入 canary → 继续执行 →
  在停止时检查 `pc == canary`（或 `fault_addr == canary`，按参数选择）。
- 返回：`{verified: bool, pc, expected, offset, stop, rounds}`。
- 成功时把 `campaign.primitives.pc_control` 写成 `value: "verified"`，
  `evidence` 带 canary/offset/session；失败时不覆盖已有候选，只返回结果。
- 预算/超时沿用 policy 机制；输出常量大小。

### B. checksec 自动识别

- 在 `campaign(action="detect")` 或单独的 `action="protections"` 中解析 pwndbg
  `checksec` 输出（PIE / Canary / NX / RELRO / Fortify），写入
  `campaign.protections`，每项含 `value` + `evidence`（原始行）。
- 无 pwndbg 时降级：从 `info proc mappings`/`evaluate` 推断 PIE/NX 的有限子集，
  或返回 `detected=false` + 原因；不得编造。
- 只在显式调用或 launch 后首次检测时执行，避免每次停止都跑 checksec。

## 验收

- 对一个可控 PC 的样例（cyclic offset + canary）`verify_pc_control` 返回
  `verified: true`，campaign 记录 `value: "verified"`；
- 对不可控样例返回 `verified: false`，campaign 不新增/不改写 `pc_control`；
- `checksec` 自动识别在 pwndbg 会话填充 5 项 protections；无 pwndbg 时给出
  `detected=false` 与原因；
- 单测 + 真机 smoke；`ruff` 干净。

## 参考

- `src/gdb_mcp/campaign.py::campaign_detect`
- `src/gdb_mcp/plugin/gdb_mcp_plugin.py::_policy_*`
- `src/gdb_mcp/tools/campaign_tools.py`
- `src/gdb_mcp/tools/heap_tools.py::run_policy`
