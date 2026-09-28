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

**并发语义**：同一会话内工具调用严格串行——插件把所有 gdb API 调用
marshal 到 gdb 主线程，服务端按会话加锁（`crash_report` 等复合工具在同一
锁下原子执行）。忙会话上的第二个调用会等待，上限为
`GDB_MCP_REQUEST_TIMEOUT`（默认 30s）；inferior 运行中调用执行类动词会立刻
返回 `INFERIOR_RUNNING` 而非静默排队。不同会话之间完全独立。

**兼容性**：插件对 gdb API 的版本差异带显式回退（加载期探测，如
`gdb.interrupt` 需 gdb ≥ 15、`qualified` 断点参数仅新版存在）。已验证：

| gdb | 验证途径 |
|---|---|
| 12.1 | CI（ubuntu-22.04 apt） |
| 15.x | CI（ubuntu-24.04 apt） |
| 17.2 + pwndbg | WSL2 本地全套端到端 |

服务器侧 Python 3.10+；插件本体 stdlib-only 单文件，任何带内嵌 Python 的
gdb 都能 `-x` 直接加载。

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

## MCP 客户端配置

Claude Code（项目根或用户级 `.mcp.json`）：

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

Cursor：同结构，写入 `~/.cursor/mcp.json`。Codex CLI 写入
`~/.codex/config.toml`：

```toml
[mcp_servers.gdb-mcp]
command = "gdb-mcp"
env = { GDB_MCP_PORT = "3939" }
```

其他 MCP 客户端：stdio 方式拉起 `gdb-mcp`（或 `--http` + `--mcp-port`
走加固 HTTP 传输，配 bearer token）。

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
| `docker` | 一次性容器内启动（`SYS_PTRACE` + 放宽 seccomp；镜像见 `docker/Dockerfile`，`docker build -f docker/Dockerfile -t gdb-mcp:latest .`；cwd 与插件按次挂载，容器以 `gdbmcp_<session>` 命名，终止即 `docker kill`。服务端需 `--host-bind 0.0.0.0 --token ...`（非回环绑定强制要求 token），插件经 `host.docker.internal` 回连） |
| `ssh` | 经 SSH 在远端靶机启动（需 `GDB_MCP_SSH_HOST`，BatchMode 免密） |

MCP 传输默认 stdio；`GDB_MCP_MCP_HTTP=1`（或 `--http`）切换为 streamable
HTTP（默认 `127.0.0.1:8001/mcp`），带四道防线：非 loopback 绑定强制
token、Host 头校验（防 DNS rebinding）、Origin 校验、配置了 token 则所有
请求必须带 `Authorization: Bearer`。

## 会话日志与持久化

每个 gdb 会话自动记录 **journal**（`~/.gdb-mcp/logs/journals/<session>.jsonl`，
长值截断、hex 超限变长度标记）：`export_session_script` 将其中的变更与控制流
操作编译为**确定性、可独立重放的 gdbscript**（纯读取与 checkpoint 类操作跳过
并计数）——审计、复现、分享都靠它。服务器重启后，已持久化的 gdb 会话身份
（session_id/日志/启动信息）保留，插件重连即自动复活同一会话。

## 安全分级

- `GDB_MCP_READONLY=1`（`--readonly`）：不注册 `write_memory`/`write_register`。
- `shell`/`!`/`pipe`/`python`/`source` 类逃逸调试器的命令默认拒绝
  （`UNSAFE_BLOCKED`），服务端与 gdb 内插件双层拦截；`GDB_MCP_ALLOW_UNSAFE=1`
  （`--allow-unsafe`）显式放行并向下传递给被 launch 的 gdb。注意 gdb 命令
  缩写（如 `sh`、`py`）使前缀黑名单是尽力而为的纵深防御，不是沙箱。
- **哈希链审计日志**（`<log-dir>/audit.log`，默认开启，`--no-audit-log`
  关闭）独立于会话 journal 记录安全决策——握手与拒绝、HTTP 403、观察者
  越权、unsafe 命令拦截；每条记录 SHA-256 提交前一条的哈希，事后篡改可被
  `gdb_mcp.audit.verify_log` 检出。
- journal 与 `sessions.json` 持久化带**显式 schema 版本**：未知的新版本
  拒绝加载而非猜测语义（journal 历史保留在磁盘不删）。

**关于 token 有效期**：会话 token 是主 token 的无状态 HMAC-SHA256 派生——
这正是插件能在服务器重启后免状态重新验证的原因，因此无法单独过期。补偿
设计：主 token 不出服务进程、会话 token 对其他会话无效、HTTP 暴露面应走
TLS/mTLS（客户端证书可吊销）。需要缩短泄漏窗口时，换主 token 重启服务器
即可——插件自动重新派生。

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

## 工具一览（默认 52 个；`core` 档 12 个；开 `--experimental` 共 60 个）

按职责分组，也按 **capability 层**划分：**core**（会话/执行/断点/状态——
任何调试场景都需要）、**pwn**（崩溃定位/堆/checkpoint/campaign/委托执行）、
**static**（Ghidra 静态桥）、**kernel**（实验性 QEMU/gdbstub 工具）。各层共享
同一套线协议；`core` 档即非漏洞利用后端所需的子集。

| 类别 | 工具 |
|---|---|
| 会话/启动 | `list_sessions` `session_status` `launch_gdb` `launch_script` `get_process_output` `kill_session` `quit_gdb` `get_events` `export_session_script`（journal → 可重放 gdbscript）`diff_sessions`（跨会话寄存器/内存差分） |
| 执行控制 | `execute_command`（raw 透传，pwndbg 全兼容；分页 + 大结果落盘）`continue_execution`（可选 `wait`/`with_context`）`interrupt` `wait_for_stop`（可选 `with_context`）`get_stop_reason` `read_result` `batch_commands`（多命令一次往返） |
| 崩溃定位 | `crash_report`（信号/故障地址/寄存器/回溯/PC·SP·故障地址内存/内存映射一屏拿全）`triage_crash`（checkpoint 重放崩溃 payload → 完整报告 → 可选最小化 → 证据落盘） |
| 状态检查 | `read_memory` `write_memory` `read_registers` `write_register` `get_backtrace` `disassemble` `evaluate` `list_threads` `select_frame` `get_memory_map`（结构化 segments）`load_target` |
| 断点 | `set_breakpoint`（软件/硬件/watch/条件/临时/线程；`commands`+`auto_continue` 可做无人值守探针）`list_breakpoints` `manage_breakpoint` |
| pwn 工作流 | `heap_bins`（pwndbg `bins` → 结构化 JSON，含 `parsed` 诚实降级）`checkpoint`（寄存器+可写内存快照 create/list/restore/diff，预算受控）`run_policy`（委托执行：trace / heap_arm·read·disarm / fuzz_loop / crash_check / minimize / bp_stats——循环下沉插件原生速度）`campaign`（战役状态 + cyclic 偏移 oracle + 模式生成） |

| 静态桥（Ghidra） | `analyze_binary` `list_analyses` `get_analysis_status` `get_binary_overview` `list_sections` `list_symbols` `list_functions` `list_strings` `decompile_function` `get_static_disassembly` `get_xrefs` `get_call_graph` `search_decompiled_code` `annotate_code` `remove_code_annotation`（按 SHA-256 建分析缓存；运行期停机点可回映射到静态函数/行号） |


## 实验性功能

**只在服务器启动参数 `--experimental` 显式开启**（刻意不提供环境变量——防止
shell profile 或 MCP 配置里残留的变量把实验工具带进每次启动）。在 MCP 配置中的
用法：

```json
{
  "mcpServers": {
    "gdb-mcp": {
      "command": "gdb-mcp",
      "args": ["--experimental"]
    }
  }
}
```

开启后额外注册 6 个实验工具（可能在没有弃用周期的情况下变动）：

- **Inferior stdio 通道**：`io_setup` / `send_to_inferior` / `read_inferior_output` /
  `io_teardown` — 把 inferior 的 stdio 重定向到插件管理的 pty，无需 pwntools 即可
  交互菜单式程序，`run_policy(fuzz_loop)` 也可全自动喂输入。Unix only。
- **崩溃最小化**：`run_policy(kind="minimize")` 对崩溃 payload 做 delta debugging，
  只接受信号不变的删除（防漂移）；`kind="crash_check"` 单发判定。
- **libc 识别 / ROP 搜索**：`identify_libc`（libc.rip 兼容 API，`GDB_MCP_LIBC_RIP_API`
  可配）与 `search_gadgets`（ROPgadget CLI + 正则过滤，地址规范化）。
- **内核 VM**：`kernel_launch`（QEMU + gdbstub，`-S` 冻结启动，插件加载的 gdb 直接
  attach）与 `kernel_snapshot`（savevm/loadvm——内核 pwn 的秒级回退原语）。需启动
  后端内有 QEMU。

## 战役状态与委托执行

- **campaign**：服务器为每个会话维护结构化漏洞利用进度（protections/libc 泄漏/
  偏移/primitives/notes）。`campaign(action="detect")` 对最近一次停机的 PC/fault/
  寄存器跑 **cyclic 偏移 oracle**（pwntools 兼容 de Bruijn 序列），命中即记录
  pc_control 候选；`action="pattern"` 直接生成模式串。停机响应自动注入 3–6 行
  战役摘要——agent 不再每轮重推上下文。状态只读视图经 MCP Resource
  `gdb://campaign/{session_id}` 暴露。
- **run_policy（委托执行）**：有界循环下沉到 gdb 进程内原生速度执行，响应大小
  与迭代次数无关——`trace`（有界单步轨迹）、`heap_arm/read/disarm`（分配函数
  探针记录参数、自动续跑不打断执行流）、`fuzz_loop`（checkpoint 恢复 + payload
  写入 + 续跑的**gdb 内快照模糊测试**，崩溃按信号+PC 去重）。

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
| `GDB_MCP_AUDIT_LOG` | 服务器 | `0` 关闭哈希链安全审计日志（默认开，`--no-audit-log` 同效） |
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
# 单元测试（无需 gdb）
python -m pytest tests/ -q                        # 765 项（含协议层种子模糊测试）

# 真实 gdb 套件（WSL2 或原生 Linux；各自打印结论）
wsl bash tests/integration/run_wsl_integration.sh # 插件 <-> 服务端协议
python tests/integration/run_mcp_tools_e2e.py --distro kali-linux
                                                  # 逐个工具端到端走查
wsl bash tests/integration/run_io_smoke.sh        # inferior stdio（pty）
bash tests/integration/run_tls_smoke.sh           # HTTP / TLS / mTLS / bearer
python tests/integration/run_observer_smoke.py    # 观察者角色 + 实时 HTTP

# 验收基准（576 个版本化任务，总纲见 bench/SPEC.md）
python -m bench.framework.cli selfcheck --distro kali-linux  # 参考解 + 评分
python -m bench.framework.cli stress --distro kali-linux     # 调用量 + 会话翻涌
python -m bench.framework.cli faults --distro kali-linux     # 故障注入与恢复
python -m bench.framework.cli perf --distro kali-linux       # 开销 / 启动 / 并发
python -m bench.framework.cli pwndbg --distro kali-linux     # pwndbg 兼容探针
```

集成测试覆盖：握手 → 断点 → SIGSEGV 崩溃定位 → 寄存器/回溯/反汇编/内存读写 → 表达式求值 → interrupt 中断死循环 → 优雅退出。

## 安全说明

该 TCP 通道具备执行任意 gdb 命令的能力。默认仅监听 loopback；任何非
loopback 监听都必须配置共享 token，并仍建议用防火墙限制 3939 端口来源。
协议拒绝版本不匹配和结构不合法的消息。
