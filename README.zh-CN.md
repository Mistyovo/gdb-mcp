# gdb-mcp

MCP 服务器，让大模型（Claude Code / Codex / Cursor 等）驱动 Linux 下的
**真实 gdb 进程**（兼容 pwndbg），专注于**用户态二进制漏洞挖掘与 exploit
开发**中的动态调试、崩溃定位与有界 pwn 循环。

- **gdb 进程内插件**：stdlib-only 单文件插件在 gdb 进程内运行，经 JSON-lines
  TCP 通道回连服务器——pwndbg 上下文、pwntools 会话、反向执行天然可用，
  不解析 GDB/MI，不抓终端 prompt。
- **聚焦用户态动态调试**：默认 `pwn` 档暴露 **36 个工具**（受 CI schema
  token 预算约束），只保留驱动活体 Linux 用户态进程所需的能力。静态反编译、
  内核 VM、宿主侧网络助手、企业级 HTTP/TLS 栈均已按范围守则
  （[ADR-0001](docs/adr/0001-userland-dynamic-debugging-scope.md)）排除。
- **原生支持 pwntools**：`gdb.debug()` / `gdb.attach()` 拉起的 gdb 自动回连
  注册，无需改造 pwntools 脚本。
- **为 pwn 闭环设计**：一键崩溃定位与回放（支持活进程与 core file）、
  glibc `heap_bins` + 无需 pwndbg 的 `heap_chunk`（含 safe-linking 解码）、
  带返回指针的堆分配时间线、checkpoint 快照/恢复/差分、`send_input` /
  `read_output` 交互式 I/O，以及带证据归因的 campaign 状态机。

## 安装与配置

**1. 安装**（Windows 侧 + WSL2，或原生 Linux）：

```powershell
pip install -e .
```

**2. Linux / WSL2 侧**：

```bash
sudo apt install gdb python3 python3-pip gcc   # pwndbg 可选但推荐
```

**3. MCP 客户端配置**（Claude Code `.mcp.json`）：

```json
{
  "mcpServers": {
    "gdb-mcp": {
      "command": "gdb-mcp",
      "env": { "GDB_MCP_PORT": "3939" }
    }
  }
}
```

## 工具一览（默认 `pwn` 档 36 个；`core` 档 12 个；`--experimental` 额外 1 个）

| Profile | 用途 |
|---|---|
| `core` | 会话/执行/状态/断点最小面（12 个工具） |
| `pwn`（默认） | core + 崩溃定位/回放、堆 bins & chunk、checkpoint、委托循环、campaign、inferior stdio |

| 类别 | 工具 |
|---|---|
| 会话/启动 | `list_sessions` `session_status` `launch_gdb`（`program` 或 `attach_pid`，可选 `stdio="pty"`）`launch_script` `get_process_output` `kill_session`（`force` 杀进程保留记录 / `forget` 删记录）`get_events` `export_session_script` |
| 执行与 I/O | `execute_command`（raw 透传，支持多行命令、分页与大结果落盘）`continue_execution`（可选 `wait`/`with_context`，支持 reverse）`interrupt`（同时干净取消活动 policy）`wait_for_stop` `read_result` `send_input` `read_output` |
| 崩溃定位 | `crash_report`（信号/故障地址/寄存器/回溯/反汇编/PC·SP·故障地址内存/内存映射含 core 回退，支持可选 checkpoint 回放、minimize 与证据落盘） |
| 状态检查 | `read_memory` `write_memory` `read_registers` `write_register` `get_backtrace` `disassemble` `evaluate` `list_threads` `select_thread` `select_frame` `get_memory_map`（活进程 + core）`load_target` |
| 断点 | `set_breakpoint`（软件/硬件/watch/条件/临时/线程；`commands`+`auto_continue` 可做无人值守探针）`list_breakpoints` `manage_breakpoint` |
| pwn 工作流 | `heap_bins`（pwndbg `bins` → 结构化 JSON）`heap_chunk`（glibc chunk 头 → size/flags/prev_size/fd/bk/tcache + safe-linking 解码，无需 pwndbg）`checkpoint`（create/list/restore/diff）`run_policy`（`trace` / `heap_arm`·`read`·`disarm` 含返回指针 / `fuzz_loop` / `crash_check` / `minimize` / `bp_stats` / `verify_pc_control`）`campaign`（战役状态 + 按来源归因的 cyclic oracle + `protections` checksec 自动识别 + pattern 生成） |

实验工具（仅 CLI `--experimental` 开启）：`diff_sessions`。

## 架构与启动后端

- 启动后端：`--launcher wsl`（默认）与 `--launcher native`。
- 传输层：MCP `stdio`；插件回连走本机 TCP JSON-lines（默认 `127.0.0.1:3939`，
  非 loopback 强制要求 `--token`）。
- 安全模型：会话级 HMAC token、双层缩写感知/逐行 unsafe 命令门、`--readonly`
  只保留 `observe` 能力。

## 测试

```bash
# 单元测试（无需 gdb）
python -m pytest tests/ -q                        # 834 项

# 真实 gdb 套件（WSL2 或原生 Linux）
wsl bash tests/integration/run_wsl_integration.sh # 插件 <-> 服务端协议
wsl bash tests/integration/run_policy_smoke.sh    # policy 循环原语（trace/bp_stats）
wsl bash tests/integration/run_heap_smoke.sh      # heap 时间线（分配返回指针）
wsl bash tests/integration/run_io_smoke.sh        # inferior stdio（pty）
wsl bash tests/integration/run_unsafe_gate_probe.sh
PYTHONPATH=src python tests/integration/run_mcp_tools_e2e.py --distro kali-linux

# 验收基准（72 个版本化任务，9 个家族含 pwn_workflow）
python -m bench.framework.cli build --distro kali-linux
python -m bench.framework.cli selfcheck --distro kali-linux
```

## 许可

[MIT](LICENSE) © gdb-mcp contributors
