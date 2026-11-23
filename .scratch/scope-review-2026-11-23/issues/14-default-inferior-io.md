# 14 — 默认档 inferior I/O 的去留

Status: needs-triage
Type: grilling
Priority: P1
Area: pwn workflow / stdio
Depends on: —

## 背景

`inferior_io` / `read_inferior_output` 目前是 `--experimental` 工具，通过 pty +
`set inferior-tty` 驱动 inferior 的 stdin/stdout。它填的是一个真实缺口：

- `launch_gdb(program, run=True)` 的用户无法给 inferior 喂输入；
- menu 型目标只能靠 `launch_script`（pwntools）或用户自己开终端；
- 但 README 又把“pwntools stays in charge / server never fights your scripts for I/O”
  作为设计原则，二者存在张力。

## 决策选项

- **A（建议，若 menu 型目标是 pwn 范围）提升最小 I/O 到 pwn 档**：
  - 只暴露 `send_input(hex/text)` + `read_output(since_seq)`；
  - 在 `launch_gdb(stdio="pty")` 或首次 `send_input` 时 setup；
  - 不暴露 setup/teardown 的内部细节；teardown 随会话结束自动做。
- **B 删除 `inferior_io`，明确“输入归 pwntools”**：
  - 文档只推荐 `launch_script`；
  - 删除 2 个实验工具与 pty 代码；
  - 默认档不接受“喂输入”这个需求。
- **C 维持 experimental**：现状，半支持。

推荐 A：pwn 的默认路径不应把“给目标喂输入”降级为实验能力；如果决定不做，
就选 B，别留 C。

## 验收

- 决策记录在本 issue。
- 若 A：`launch_gdb` + `send_input`/`read_output` 能驱动一个 menu 样例；工具在
  `pwn` 档可见；e2e 覆盖；README 更新。
- 若 B：`inferior_io`/`read_inferior_output` 与 pty 代码删除；README 明确
  “inferior I/O 由 pwntools 脚本负责”；`launch_script` 文档补一个输入示例。
- 若 C：README 明确 experimental 的已知限制与不保证项。

## 参考

- `src/gdb_mcp/tools/experimental.py`（`inferior_io`、`read_inferior_output`）
- `src/gdb_mcp/plugin/gdb_mcp_plugin.py::_handle_io_*`
- `examples/pwntools_debug.py`
- `tests/integration/run_io_smoke.sh`
