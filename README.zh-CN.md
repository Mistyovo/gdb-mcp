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
- **首次启动前先失败**：`gdb-mcp --selfcheck` 用一份 JSON 报告 GDB 命令/版本、
  内嵌 Python、pwndbg 可见性、插件文件与监听端口，无法启动会话时退出码非零。
  Linux 默认走 native，Windows 默认走 WSL。
- **原生支持 pwntools**：`gdb.debug()` / `gdb.attach()` 拉起的 gdb 自动回连
  注册，无需改造 pwntools 脚本。
- **为 pwn 闭环设计**：一键崩溃定位与回放（支持活进程与 core file）、
  glibc `heap(action="bins")` + 无需 pwndbg 的 `heap(action="chunk")`（含 safe-linking 解码）、
  带返回指针的堆分配时间线、checkpoint 快照/恢复/差分、`inferior_io(action="send")` /
  `inferior_io(action="read")` 交互式 I/O，以及带证据归因的 campaign 状态机。
- **节省上下文**：`control_execution(action="continue", wait=True, with_context=True)`
  在一次调用中返回停止状态、关键寄存器、回溯与反汇编。

## 安装与配置

**1. 安装**（Windows 侧 + WSL2，或原生 Linux）：

```powershell
pip install -e .
```

启动后端随宿主平台选择默认值：**Linux 默认 `native`**，**Windows 默认
`wsl`**。可用 `--launcher` / `GDB_MCP_LAUNCHER` 显式覆盖；用
`--gdb-path` / `GDB_MCP_GDB_PATH` 指定具体 GDB 可执行文件（例如
`gdb-multiarch`）。

**2. Linux / WSL2 侧**：

```bash
sudo apt install gdb python3 python3-pip gcc   # pwndbg 可选但推荐
```

**3. MCP 客户端配置**：MCP 服务器运行在 **Windows 侧**、通过 WSL2
启动 gdb 时，显式使用 `--launcher wsl`（Claude Code `.mcp.json`）：

```json
{
  "mcpServers": {
    "gdb-mcp": {
      "command": "gdb-mcp",
      "args": ["--launcher", "wsl"],
      "env": { "GDB_MCP_PORT": "3939" }
    }
  }
}
```

MCP 客户端与服务器运行在 **Linux 或 WSL2 内部**时，在该环境安装本项目，
改用 `--launcher native`（不要在 WSL 内再次调用 WSL）：

```json
{
  "mcpServers": {
    "gdb-mcp": {
      "command": "gdb-mcp",
      "args": ["--launcher", "native"],
      "env": { "GDB_MCP_PORT": "3939" }
    }
  }
}
```

Cursor 可在 `~/.cursor/mcp.json` 使用相同配置。Codex CLI（Windows 侧；
在 Linux/WSL2 内将 `wsl` 改为 `native`）：

```toml
[mcp_servers.gdb-mcp]
command = "gdb-mcp"
args = ["--launcher", "wsl"]
env = { GDB_MCP_PORT = "3939" }
```

**4. 调试前先自检**：`gdb-mcp --selfcheck` 输出 JSON 报告，无法启动会话时
退出码非零。报告包含 GDB 命令与版本、内嵌 Python、pwndbg 可见性、已安装插件
文件和监听端口是否空闲。它接受与服务端相同的 `--launcher`、
`--gdb-path`、`--port` 参数。

```bash
gdb-mcp --selfcheck
```

**5. 通过 MCP 客户端调用工具**：以下 Python 形状代码块是 **MCP 调用记法，
不是可 import 的 Python API，也不是可直接运行的 Python 脚本**。请使用自己的
Linux 目标路径，将 `SESSION_ID` 替换为 `launch_gdb` 返回的会话 ID。
示例展示独立操作，不是按顺序执行的脚本。

先用仓库自带示例（`examples/hello.c`）走通首次断点：

```bash
gcc -g -O0 -o /tmp/gdb-mcp-hello examples/hello.c
```

<!-- mcp-calls:start -->
```python
launch_gdb(program="/tmp/gdb-mcp-hello", run=False)
breakpoint(action="set", location="break_here", session_id="SESSION_ID")
execute_command(command="run", session_id="SESSION_ID")
control_execution(action="wait", timeout_ms=10000, session_id="SESSION_ID")
inspect_code(action="backtrace", max_frames=8, session_id="SESSION_ID")
kill_session(force=True, session_id="SESSION_ID")
```
<!-- mcp-calls:end -->

`examples/crasher.c` 用于崩溃定位；下面的菜单示例使用 pty 做交互 I/O。

<!-- mcp-calls:start -->
```python
launch_gdb(program="/tmp/menu", stdio="pty", run=True)
control_execution(action="continue", wait=True, with_context=True, session_id="SESSION_ID")
inferior_io(action="send", text="1\n", session_id="SESSION_ID")
inferior_io(action="read", since_seq=0, session_id="SESSION_ID")
```
<!-- mcp-calls:end -->

只对已停止的 inferior 恢复执行；在运行中的菜单提示符处发送/读取 stdio。
下面的操作用于已停止会话：bins 需要 pwndbg；chunk 需要有效的 chunk 地址
（请替换示例地址）；加载 core 之前需先加载匹配的可执行文件。

<!-- mcp-calls:start -->
```python
heap(action="bins", session_id="SESSION_ID")
heap(action="chunk", address="0x555555559290", session_id="SESSION_ID")
load_target(path="/tmp/menu", session_id="SESSION_ID")
load_target(path="/tmp/core.menu", core=True, session_id="SESSION_ID")
```
<!-- mcp-calls:end -->

## 工具一览（默认 `pwn` 档 17 个；`core` 档 10 个；`--experimental` 额外 1 个）

| Profile | 用途 |
|---|---|
| `core` | 最小 10 工具面（会话/执行/状态/断点/崩溃定位） |
| `pwn`（默认） | core + 堆、checkpoint、委托循环、campaign、inferior stdio、线程/栈帧、目标加载 |

| 类别 | 工具 |
|---|---|
| 会话 | `launch_gdb`（`program` / `attach_pid` / `script` pwntools，可选 `stdio="pty"`）`kill_session`（`force`/`forget`）`session_info`（`list`/`status`/`events`/`output`/`export`） |
| 执行与 I/O | `control_execution`（`continue`/`step`/`next`/`stepi`/`nexti`/`finish`/`until`/`reverse_*`/`wait`/`interrupt`，支持 `with_context`）`execute_command`（raw gdb/pwndbg、多行、分页 + `result_file` 读取）`inferior_io`（`send`/`read`） |
| 状态与断点 | `memory`（`read`/`write`/`map` 含 core 回退）`registers`（`read`/`write`）`inspect_code`（`disassemble`/`backtrace`/`evaluate`）`thread_frame`（`list_threads`/`select_thread`/`select_frame`）`load_target`（`path`，加载 core dump 时设 `core=True`；无 `action`）`breakpoint`（`set`/`list`/`delete`/`enable`/`disable`） |
| 崩溃与 Pwn | `crash_report`（一键定位 + 可选 checkpoint 回放/最小化/证据落盘）`heap`（`bins` pwndbg / `chunk` 独立解码含 safe-linking）`checkpoint`（`create`/`list`/`restore`/`diff`）`run_policy`（`trace`/`heap_arm`·`read`·`disarm`/`fuzz_loop`/`crash_check`/`minimize`/`bp_stats`/`verify_pc_control`）`campaign`（`get`/`set`/`note`/`detect`/`protections`/`pattern`） |

`kill_session` 将四种结果分开表达，而不是一个含糊的“已终止”：

| 调用 | 实际效果 |
|---|---|
| `kill_session()` | 插件断开；gdb 与被调试进程继续运行 |
| `kill_session(force=True)` | 对服务启动的进程树**请求**终止；外部附加的 gdb 会被要求退出 |
| `kill_session(forget=True)` | 同时删除服务端会话记录 |
| `kill_session(force=True, forget=True)` | 请求终止并删除记录 |

返回结果带 `launched`、`process_termination`、`termination_note`；终止是请求，
不代表进程已经退出。

实验工具（仅 CLI `--experimental` 开启）：`diff_sessions`。

## 架构与启动后端

```text
MCP 客户端 ──stdio──► gdb-mcp server（默认 17 tools）
                         │ TCP JSON-lines（会话 token / heartbeat）
                         ▼
gdb（WSL2 / 原生 Linux）内的 stdlib-only 插件 gdb_mcp_plugin.py
```

- 启动后端：Linux 默认 `--launcher native`，Windows 默认 `--launcher wsl`。
- 传输层：MCP `stdio`；插件回连走本机 TCP JSON-lines（默认 `127.0.0.1:3939`，
  非 loopback 强制要求 `--token`）。
- 安全模型：会话级 HMAC token、双层缩写感知/逐行 unsafe 命令门、`--readonly`
  保留 `observe` 能力，并额外保留只读的 `breakpoint(action="list")`。保留工具
  中的修改动作仍受限制：`session_info` 的 `export`、`inspect_code` 的
  `evaluate` 以及断点的增删启停返回 `READONLY`；状态、回溯、反汇编和断点列表仍可用。

## 测试

```bash
# 单元测试（无需 gdb）
python -m pytest tests/ -q

# 真实 gdb 套件（WSL2 或原生 Linux）
wsl bash tests/integration/run_wsl_integration.sh # 插件 <-> 服务端协议
wsl bash tests/integration/run_policy_smoke.sh    # policy 循环原语（trace/bp_stats）
wsl bash tests/integration/run_pc_control_smoke.sh # PC 控制验证
wsl bash tests/integration/run_heap_smoke.sh      # heap 时间线（分配返回指针）
wsl bash tests/integration/run_io_smoke.sh        # inferior stdio（pty）
wsl bash tests/integration/run_unsafe_gate_probe.sh
PYTHONPATH=src python tests/integration/run_mcp_tools_e2e.py --distro kali-linux

# 验收基准（72 个版本化任务，9 个家族含 pwn_workflow）
python -m bench.framework.cli build --distro kali-linux
python -m bench.framework.cli selfcheck --distro kali-linux
```

安装包 MCP 端到端回归需先构建 wheel，并将其安装到 **干净的 Linux/WSL2
虚拟环境**，再用该 venv 的 Python 执行
`python -I tests/integration/run_native_install_smoke.py`。该测试通过 MCP stdio
与 native launcher、经由安装生成的 `gdb-mcp` 命令验证已安装的 wheel，不是源码
环境 smoke。CI 在 Ubuntu 22.04 + Python 3.10 与 Ubuntu 24.04 + Python 3.13
上各跑一次。不要使用 editable 安装、`PYTHONPATH=src` 或插件路径覆盖。

## 许可

[MIT](LICENSE) © gdb-mcp contributors
