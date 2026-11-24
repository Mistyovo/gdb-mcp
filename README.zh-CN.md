# gdb-mcp

MCP 服务器，让大模型（Claude Code / Codex / Cursor 等）驱动 Linux 下的
**真实 gdb 进程**（兼容 pwndbg），专注于**用户态二进制漏洞挖掘与 exploit
开发**中的动态调试、崩溃定位与有界 pwn 循环。

- **gdb 进程内插件**：stdlib-only 单文件插件在 gdb 进程内运行，经 JSON-lines
  TCP 通道回连服务器——pwndbg 上下文、pwntools 会话、反向执行天然可用，
  不解析 GDB/MI，不抓终端 prompt。
- **聚焦用户态动态调试**：默认 `pwn` 档精简为 **17 个高内聚工具**（从 36 个合并而来，
  总 schema 仅 ~5.2k tokens，受 CI 字节预算约束），只保留驱动活体 Linux 用户态进程
  所需的能力。静态反编译、内核 VM、宿主侧网络助手、企业级 HTTP/TLS 栈均已按范围守则
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

## 工具一览（默认 `pwn` 档 17 个；`core` 档 10 个；`--experimental` 额外 1 个）

| Profile | 用途 |
|---|---|
| `core` | 最小 10 工具面（会话/执行/状态/断点/崩溃定位） |
| `pwn`（默认） | core + 堆、checkpoint、委托循环、campaign、inferior stdio、线程/栈帧、目标加载 |

| 类别 | 工具 |
|---|---|
| 会话 | `launch_gdb`（`program` / `attach_pid` / `script` pwntools，可选 `stdio="pty"`）`kill_session`（`force`/`forget`）`session_info`（`list`/`status`/`events`/`output`/`export`） |
| 执行与 I/O | `control_execution`（`continue`/`step`/`next`/`stepi`/`nexti`/`finish`/`until`/`reverse_*`/`wait`/`interrupt`，支持 `with_context`）`execute_command`（raw gdb/pwndbg、多行、分页 + `result_file` 读取）`inferior_io`（`send`/`read`） |
| 状态与断点 | `memory`（`read`/`write`/`map` 含 core 回退）`registers`（`read`/`write`）`inspect_code`（`disassemble`/`backtrace`/`evaluate`）`thread_frame`（`list_threads`/`select_thread`/`select_frame`）`load_target`（`file`/`core`）`breakpoint`（`set`/`list`/`delete`/`enable`/`disable`） |
| 崩溃与 Pwn | `crash_report`（一键定位 + 可选 checkpoint 回放/最小化/证据落盘）`heap`（`bins` pwndbg / `chunk` 独立解码含 safe-linking）`checkpoint`（`create`/`list`/`restore`/`diff`）`run_policy`（`trace`/`heap_arm`·`read`·`disarm`/`fuzz_loop`/`crash_check`/`minimize`/`bp_stats`/`verify_pc_control`）`campaign`（`get`/`set`/`note`/`detect`/`protections`/`pattern`） |

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
