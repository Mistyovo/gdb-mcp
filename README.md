# gdb-mcp

MCP 服务器，让大模型（Claude Code 等）驱动 Linux 下的 **gdb 进程本身**（可带 pwndbg 插件），用于用户态二进制漏洞挖掘与 exploit 开发中的动态调试与崩溃快速定位。

- 目标是 **gdb 前端**，不是 gdbserver——即使 pwntools 的 `gdb.debug()` 内部用 gdbserver + `target remote`，MCP 统一通过 gdb 控制一切。
- **原生支持 pwntools 拉起的 gdb**（`gdb.debug()` / `gdb.attach()`），无需改造 pwntools 代码。
- 服务器跑在 **Windows**（Claude Code），gdb 跑在 **WSL2 / Linux**：gdb 内插件通过 TCP 回连服务器，多会话注册表自动管理。
- 结构化工具（内存/寄存器/回溯/断点/线程/反汇编）+ **pwndbg 命令透传**（`vmmap`/`heap`/`got`/`checksec`/`ropgadget`…）+ 一键崩溃定位（`crash_report`）。

## 与同类项目的差异

| 项目 | 架构 | 多会话 | pwndbg | pwntools 协同 | 崩溃定位 |
|---|---|---|---|---|---|
| **gdb-mcp（本项目）** | gdb 进程内插件 + TCP 回连 | ✅ | ✅ 命令透传 | ✅ `gdb.debug()`/`attach()` 原生 | ✅ `crash_report` |
| [signal-slot/mcp-gdb](https://github.com/signal-slot/mcp-gdb) | GDB/MI 子进程 | ✅ | ❌ | ❌ | ❌ |
| [yywz1999/gdb-mcp-server](https://github.com/yywz1999/gdb-mcp-server) | tmux/iTerm 终端注入 | ❌ | 附加用户现成会话 | ❌ | ❌ |
| [BeaCox/gdb-mcp](https://github.com/BeaCox/gdb-mcp) | GDB/MI + lazy 代理 | ✅ | pwndbg 风格自实现 | ❌ | 诊断工具组 |
| [RocketMaDev/pwndbg-mcp](https://github.com/RocketMaDev/pwndbg-mcp) | GDB/MI 直连 | ❌ 单会话 | ✅ 别名透传 | 官方 roadmap 未完成 | ❌ |

本项目的进程内插件路线：pwndbg 上下文天然可用、不依赖 MI 解析与终端模拟（无 prompt
兼容问题）、`stop`/`running`/`exited` 事件经 `gdb.events` 主动推送。生态全景与后续
路线见 [ROADMAP.md](ROADMAP.md)。

## 架构

```
Claude Code (Windows) ──stdio/MCP──► gdb-mcp server (FastMCP, Windows)
                                          │ TCP listener 127.0.0.1:3939（会话注册表）
                                          ▼ 插件从 WSL2 回连（JSON-lines 协议 v1）
                    WSL2: gdb (+pwndbg) ── gdb_mcp_plugin.py（stdlib-only 单文件）
                          ▲
                          └── pwntools 经 gdb_args=['-x', plugin] 注入；或 MCP 经 wsl.exe 自启动
```

- 插件是 TCP **客户端**：谁先启动都无所谓，断线自动退避重连。
- gdb 非线程安全：插件内所有 `gdb.*` 调用经 `gdb.post_event` 派发到 gdb 主线程；`stop`/`running`/`exited`/`prompt` 等异步通知经 `gdb.events` 推送。
- 打断运行中的 inferior：`post_event(execute("interrupt"))`（gdb 17.2 实测唯一可靠机制；`gdb.interrupt()` 与进程 SIGINT 均不可靠）。

## 安装

**Windows 侧（MCP 服务器）**（在仓库根目录执行）

```powershell
pip install -e .
```

**WSL2 侧（kali-linux）**

```bash
sudo apt install gdb python3 python3-pip gcc   # pwndbg 可选
```

无需在 WSL 内安装任何 gdb-mcp 组件——插件文件直接经 `/mnt/c/...` 由 gdb 的 `-x` 加载。若 `/mnt/c` 不可用，把 `src/gdb_mcp/plugin/gdb_mcp_plugin.py` 复制进 WSL 并设置 `GDB_MCP_PLUGIN` 指向它。

## WSL2 网络（重要）

插件从 WSL2 **回连** Windows 侧服务器，依次尝试：`GDB_MCP_HOST` → `127.0.0.1` → WSL 默认网关 → `/etc/resolv.conf` 的 nameserver IP。

| 模式 | 配置（`%USERPROFILE%\.wslconfig`） | 插件应连 |
|---|---|---|
| **Mirrored**（推荐） | `[wsl2] networkingMode=Mirrored` | `127.0.0.1`（共享 localhost） |
| NAT（默认） | 无配置 | 默认网关（自动发现）；服务端需非 loopback 监听并配置 token |

排查：`wsl.exe -l -q` 报 `0x8007054f` / VM 内 `ip route` 为空 → mirrored 网络未生效，`wsl --shutdown` 重启或改回 NAT。NAT 下若自动发现失败，显式设置：

```bash
export GDB_MCP_HOST=$(ip route show default | awk '{print $3}')
```

服务器默认只绑定 `127.0.0.1:3939`。NAT 模式需要设置
`GDB_MCP_HOST_BIND=0.0.0.0`，此时服务端会强制要求同时设置
`GDB_MCP_TOKEN`；gdb 进程侧必须使用相同 token。非 loopback 监听可能触发
Windows 防火墙授权。

## Claude Code 配置

项目根目录 `.mcp.json`（或 Claude Code 的 MCP 设置）：

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

## 用法

### 方式 1：pwntools 脚本拉起 gdb（核心场景）

```python
from pwn import *

# 插件路径：examples 脚本会自动定位仓库内的插件文件（也可用 GDB_MCP_PLUGIN 覆盖）
import os
PLUGIN = os.environ.get("GDB_MCP_PLUGIN") or "<repo>/src/gdb_mcp/plugin/gdb_mcp_plugin.py"

io = gdb.debug("./vuln", gdb_args=["-x", PLUGIN])     # 或 gdb.attach(io, gdb_args=["-x", PLUGIN])
io.interactive()
```

gdb 在新终端（tmux 窗格）中打开、pwndbg 照常加载、插件自动回连 → MCP 里 `list_sessions` 即可看到会话。完整示例见 `examples/pwntools_debug.py`、`examples/pwntools_attach.py`。

### 方式 2：MCP 自启动（headless）

- `launch_gdb(program="/mnt/c/.../vuln", run=True)` —— wsl.exe 后台拉起 gdb + 插件
- `launch_script(script="C:\\...\\exploit.py")` —— 后台跑脚本，等待其 gdb 注册；纯脚本退出时立即返回状态、退出码与日志尾
- `kill_session(force=False)` 仅断开插件、保留 gdb；`force=True` 终止 gdb
- `quit_gdb(kill_gdb=False)` —— 断开外部启动的 gdb

### 方式 3：手动 gdb

```bash
bash examples/bare_gdb.sh ./vuln        # 等价于 gdb -q -x plugin.py --args ./vuln
```

gdb 内还有 `mcp status|reconnect|detach` 命令。

## 运行后端与传输

`launch_gdb`/`launch_script` 的执行位置由 `GDB_MCP_LAUNCHER` 决定：

| 后端 | 说明 |
|---|---|
| `wsl`（默认） | 经 `wsl.exe -d <distro>` 在 WSL2 内启动（现状行为） |
| `native` | 服务器所在 Linux 主机直接启动（`bash -lc`） |
| `docker` | 一次性容器内启动（`SYS_PTRACE` + 放宽 seccomp；镜像见 `docker/Dockerfile`，`docker build -f docker/Dockerfile -t gdb-mcp:latest .`；cwd 与插件按次挂载，容器以 `gdbmcp_<session>` 命名，终止即 `docker kill`） |
| `ssh` | 经 SSH 在远端靶机启动（需 `GDB_MCP_SSH_HOST`，BatchMode 免密） |

MCP 传输默认 stdio；`GDB_MCP_MCP_HTTP=1`（或 `--http`）切换为 streamable
HTTP（默认 `127.0.0.1:8001/mcp`），带四道防线：非 loopback 绑定强制
token、Host 头校验（防 DNS rebinding）、Origin 校验、配置了 token 则所有
请求必须带 `Authorization: Bearer`。

## 安全分级

- `GDB_MCP_READONLY=1`（`--readonly`）：不注册 `write_memory`/`write_register`。
- `shell`/`!`/`pipe`/`python`/`source` 类逃逸调试器的命令默认拒绝
  （`UNSAFE_BLOCKED`），服务端与 gdb 内插件双层拦截；`GDB_MCP_ALLOW_UNSAFE=1`
  （`--allow-unsafe`）显式放行并向下传递给被 launch 的 gdb。注意 gdb 命令
  缩写（如 `sh`、`py`）使前缀黑名单是尽力而为的纵深防御，不是沙箱。

## 崩溃定位流程（LLM 视角）

```
# 一步到位（推荐）：resume + 等停 + 上下文，一次调用
continue_execution(wait=True, with_context=True) →
  stop_info(signal/fault_addr/pc) + 关键寄存器 + backtrace + disasm(PC附近)
# 崩溃现场需要更深细节时：
crash_report（一次调用返回：signal / fault_addr / pc / thread / registers /
  backtrace / disasm(PC±) / memory@PC / memory@SP / memory@fault /
  结构化内存映射）
→ evaluate / read_memory / write_memory 验证利用思路
→ execute_command("vmmap") 拿 libc/PIE 基址（大输出自动落盘，read_result 续读）
→ set_reg / write_memory 现场修补
→ continue_execution 复跑
两次调用之间错过的事件用 get_events 兜底。
```

## 工具一览（32 个）

| 类别 | 工具 |
|---|---|
| 会话/启动 | `list_sessions` `session_status` `launch_gdb` `launch_script` `get_process_output` `kill_session` `quit_gdb` `get_events` |
| 执行控制 | `execute_command`（raw 透传，pwndbg 全兼容；分页 + 大结果落盘）`continue_execution`（可选 `wait`/`with_context`）`interrupt` `wait_for_stop`（可选 `with_context`）`get_stop_reason` `read_result` `batch_commands`（多命令一次往返） |
| 崩溃定位 | `crash_report` |
| 状态检查 | `read_memory` `write_memory` `read_registers` `write_register` `get_backtrace` `disassemble` `evaluate` `list_threads` `select_frame` `get_memory_map`（结构化 segments）`load_target` |
| 断点 | `set_breakpoint`（软件/硬件/watch/条件/临时/线程；`commands`+`auto_continue` 可做无人值守探针）`list_breakpoints` `manage_breakpoint` |
| pwn 工作流 | `heap_bins`（pwndbg `bins` → 结构化 JSON，含 `parsed` 诚实降级）`checkpoint`（寄存器+可写内存快照 create/list/restore/diff，预算受控） |

`GDB_MCP_TOOL_PROFILE=core` 只注册 12 个高频工具（省每次请求的 schema
token）；默认 `full` 注册全部。`get_backtrace`/`disassemble` 响应带
`truncated` 标记；`execute_command` 输出超过内联阈值时自动存盘并在响应中
给出 `result_file`/`result_sha256`。

所有工具带可选 `session_id`（唯一会话自动选中；多会话时报错并列出）。地址参数均支持 gdb 表达式（`main+0x20`、`&puts@got`，PIE 按实时基址解析）。

## 环境变量

| 变量 | 位置 | 说明 |
|---|---|---|
| `GDB_MCP_PORT` | 两侧 | 端口（默认 3939） |
| `GDB_MCP_HOST_BIND` | 服务器 | 监听地址（默认 127.0.0.1） |
| `GDB_MCP_TOKEN` | 两侧 | 共享 token；非 loopback 监听时必需 |
| `GDB_MCP_HOST` | gdb 进程 | 强制指定服务器地址 |
| `GDB_MCP_SESSION_ID` | gdb 进程 | launch_gdb 内部使用 |
| `GDB_MCP_AUTOSTART` | gdb 进程 | `0` = 仅加载不连接 |
| `GDB_MCP_DEBUG` | gdb 进程 | `1` = 插件调试输出（stderr） |
| `GDB_MCP_WSL_DISTRO` / `GDB_MCP_LOG_DIR` | 服务器 | launch 工具配置 |
| `GDB_MCP_REQUEST_TIMEOUT` / `GDB_MCP_HEARTBEAT_SEC` | 服务器 | 请求与心跳超时 |
| `GDB_MCP_TOOL_PROFILE` / `GDB_MCP_RESULT_INLINE_LIMIT` | 服务器 | 工具分档（core/full）与大结果内联阈值（字符数） |
| `GDB_MCP_LAUNCHER` / `GDB_MCP_SSH_HOST` / `GDB_MCP_DOCKER_IMAGE` | 服务器 | 启动后端（wsl/native/docker/ssh）及其参数 |
| `GDB_MCP_MCP_HTTP` / `GDB_MCP_MCP_HOST` / `GDB_MCP_MCP_PORT` | 服务器 | MCP streamable HTTP 传输（默认关，127.0.0.1:8001） |
| `GDB_MCP_READONLY` / `GDB_MCP_ALLOW_UNSAFE` | 两侧 | 只读模式；放行逃逸调试器的命令（双层拦截的开关） |
| `GDB_MCP_MAX_MEM_READ` / `GDB_MCP_MAX_ASYNC_LINE` | 两侧 | 内存读取与协议帧上限 |

部分内存读取返回 `segments`（每段都含实际 `addr`、`length`、`hex` 和
`ascii`）以及 `unreadable` 范围；存在缺口时顶层 `hex` / `ascii` 为 `null`，
避免把不连续数据误当成连续内存。

## 与 pwndbg / pwntools 共存

- 插件只 `connect` 自己的 `gdb.events` 处理器，绝不接管 `gdb.prompt_hook`、不抓 prompt；在 pwndbg 前后加载均可。
- 对 pwntools 的 gdbscript（含 `target remote`）完全惰性，inferior 如何被接管与插件无关。
- 已知事实（gdb 17.2 实测）：`gdb.execute("continue")` 从 post_event 回调中执行时**异步返回**；`gdb.events.stop` 在 execute 返回之后触发；`StopEvent.details` 不含 fault addr（插件用 `$_siginfo._sifields._sigfault.si_addr` 兜底）；`gdb.interrupt()` 无法中断异步运行的 inferior（插件用 `post_event(execute("interrupt"))`）。

## 测试

```bash
python -m pytest tests/                 # 单元测试（Windows 直接跑，无需 gdb）
bash tests/integration/run_wsl_integration.sh   # WSL2 内真实 gdb 端到端
```

集成测试覆盖：握手 → 断点 → SIGSEGV 崩溃定位 → 寄存器/回溯/反汇编/内存读写 → 表达式求值 → interrupt 中断死循环 → 优雅退出。

## 安全说明

该 TCP 通道具备执行任意 gdb 命令的能力。默认仅监听 loopback；任何非
loopback 监听都必须配置共享 token，并仍建议用防火墙限制 3939 端口来源。
协议拒绝版本不匹配和结构不合法的消息。
