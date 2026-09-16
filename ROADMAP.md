# gdb-mcp 长期开发路线图

> 基于 2026-09 的生态调研（GDB/LLDB/WinDbg/x64dbg/DAP/RE MCP 全景，60+ 项目）与对本仓库
> 全部源码（src ~3.8k 行，260 个单元测试）的批判性评审。调研结论见本文附录 A。

## 0. 战略判断

**核心资产**（不要动摇）：
- gdb 进程内插件 + TCP 回连架构——pwndbg 上下文天然可用，免疫 MI 解析和终端抓屏的所有病。
- 事件驱动的会话状态机（`sessions.py`）+ 协议验证（`protocol.py`）+ 测试纪律。

**生存威胁**（调研中最尖锐的教训）：pwndbg-mcp 作者自己承认"MCP 太耗 token"而转向
tmux + skill；pwndbg 官方两次拒绝 MCP PR，理由是"LLM 直接写 gdbscript 就够了"。
MCP 层的价值必须靠 **gdbscript 拿不到的东西** 证明：上下文聚合、增量 diff、token 治理、
多会话、防阻塞控制。**Token 经济学决定这条路线的生死，因此排 P0。**

**三条主线**：
- A. Token 经济学与上下文聚合（P0，决定可用性）
- B. 漏洞挖掘工作流纵深：堆分析、checkpoint、静态-动态桥（P1，差异化护城河）
- C. 分发与规模：跨平台 launcher、HTTP、安全分级、生态身份（P2）

---

## Phase 0 — 还债与卫生（1~2 周，无新能力）✅ 已完成（2026-09-17）

| 事项 | 位置 | 状态 |
|---|---|---|
| 删除重复函数 | `tools/_common.py` | ✅ `check_resumable` 已删除，调用方统一到 `check_stopped` |
| `execute_command` 输出回读 | `tools/exec_tools.py` + 插件 `_eval_output` | ✅ `offset`/`limit` 行段读取；响应始终带 `total_lines`，截断显式标记 |
| 收敛实验分支 | git 标签 `archive/reverse-tools-dashboard` | ✅ 分支已删除、内容以标签归档（Ghidra 导出器留待 Phase 3.5 复活） |
| README 对比表 | 根目录 | ✅ 与 signal-slot/yywz1999/BeaCox/RocketMaDev 的差异表 |
| `.gitignore` | 根目录 | ✅ `tests/bridge/`、`tests/ezheap/`、`tests/dashboard_demo.py`、`.mimosa/` 等本地产物 |

## Phase 1 (v0.2) — Token 经济学（主线 A）

### 1.1 停机即上下文（对标 go-delve Automatic Context / pwno-mcp / BeaCox）
- 新增复合行为：`continue_execution` / `wait_for_stop` 增加可选 `with_context: bool`。
  命中时一次返回：stop_info + 关键寄存器子集（pc/sp/ax 系/参数寄存器）+ backtrace 顶 N 帧
  + PC±8 反汇编。服务端组合现有 `regs`/`backtrace`/`disasm` 请求即可（参照
  `crash_tools.py` 的 `try_verb` + `session.lock` 原子模式），**插件无需改动**。
- `crash_report` 保留，作为崩溃场景的更深变体（memory@fault 等）。
- 现有细粒度工具不动（逃生舱哲学：高频操作聚合，低频操作保留）。

### 1.2 输出治理（对标 veh / BeaCox）
- 所有列表型输出带精确 `truncated` 计数（丢弃多少条），禁止静默截断。
- 大结果（> 配置阈值）落盘 `%GDB_MCP_LOG_DIR%/results/`，响应只回
  `path + sha256 + 总行数 + 前 N 行`，新工具 `read_result(path, offset, limit)` 按需读回。
- `execute_command` 是最大的 token 漏洞：pwndbg `heap`/`vmmap` 轻则几千 token。
  除分页外，为高频 pwndbg 命令写**解析器**（不重实现）：`vmmap`/`info proc mappings`
  → 结构化 segments（现在 `mem_map` 只回原文，`crash_report` 只取头 40 行文本）。

### 1.3 事件环形缓冲（对标 x64dbg GetEventLog）
- `push_notification` 时同时 append 到 `session.event_log`（deque maxlen，带单调序号与
  时间戳），新增 `get_events(last=N)`。改动 ~20 行，解决"事件发生在两次调用之间"。
- 插件侧顺手加 `new_objfile`/库加载事件（dashboard 分支的 hello features 里已出现过）。

### 1.4 工具分档（对标 BeaCox tool-profile / veh lazy gateway）
- `GDB_MCP_TOOL_PROFILE=core|full`：core 只注册 10~12 个高频工具，其余经 full 档或
  逃生舱 `execute_command` 可达。降低每次请求的 schema token 成本。
- 顺带精简过长的工具 docstring（schema 成本）。

## Phase 2 (v0.3) — 漏洞工作流纵深（主线 B，护城河）

### 2.1 堆分析结构化（生态最大空位，对标 Aiyakami/PWN-MCP 的 20 个 heap 工具）
分两步，全程依赖 pwndbg 而非重写：
1. **状态导出**：新插件 verb `heap_state` —— 透传 `heap`/`bins` 并解析为 JSON
   （tcache/fastbins/unsorted/small/large、chunk header 字段、arena 基址），支持
   `delta_since=<token>` 增量模式（服务端保存上次快照做 diff）。
2. **行为日志**（可选，对标 PWN-MCP heap_logger）：在 malloc/calloc/realloc/free 上下断
   （内部实现，不经 LLM），自动记录参数/返回值/caller 到环形缓冲，`heap_timeline` 工具
   读取；支持"请求粒度"标记（begin/end 一对断点）。
- 你已有实验基础：`tests/ezheap/`（堆题 core dump）、`build/ezheap-analysis/`（glibc 2.31
  导出）。heap 探测逻辑在插件内实现（进程内、免 IPC）。

### 2.2 checkpoint / restore / diff（对标 veh，全生态独有设计）
- 插件 verb `snapshot_create/restore/diff`：寄存器全集 + 可写内存段（按 `info proc
  mappings` 过滤 rw 段，单段大小上限保护）。
- 价值场景：改 payload → restore → 重跑 → diff 堆布局。与 2.1 的 delta 模式共用 diff 引擎。

### 2.3 断点 action 与批量（对标 veh / x64dbg）
- `set_breakpoint` 增加 `commands: list[str]`（命中自动执行，可选 `auto_continue`）。
- 新 verb `batch`：一次调用顺序执行多个既有 verb，合并响应。省 round-trip 的最后一块。

### 2.4 inferior I/O 通道（可选能力，对标 PWN-MCP send_to_process）
- 插件侧经 inferior tty 提供 `send_to_inferior` / `read_inferior_output`（环形缓冲）。
- **pwntools 场景保持脚本自治**（这是你的核心设计，不要抢 pwntools 的 I/O）；
  此能力只服务"纯 gdb 调试无脚本"的次要场景。默认关闭，`launch_gdb(io=True)` 开启。

## Phase 3 (v0.4) — 分发与规模（主线 C）

### 3.1 Launcher 抽象（当前 `launcher.py` 硬编码 wsl.exe）
- 接口化 `LauncherBackend`，四个实现：`wsl`（现状）/ `native`（Linux 本机）/ `ssh` /
  `docker`。Docker 后端附带官方镜像（pwndbg + pwntools + 插件预装，`--cap-add=SYS_PTRACE`，
  对标 pwno-mcp），同时解决隔离与安装门槛两个问题。

### 3.2 MCP HTTP transport（对标 microsoft/DebugMCP 四防线）
- 在 stdio 之外提供 streamable-HTTP（FastMCP 原生支持），必须带：loopback 默认绑定、
  Host/Origin 校验、Bearer token、非 loopback 拒绝启动。服务远程 agent / 多客户端共享。

### 3.3 安全分级（对标 BeaCox 四级）
- 现状只有 token（`config.py` validate 已强制非 loopback 必须 token，好底子）。补：
  - `GDB_MCP_READONLY=1`：注册时直接不挂 write_memory/write_register/kill 等 mutation 工具；
  - `GDB_MCP_ALLOW_UNSAFE=1` 才放行 `execute_command` 中的 `shell`/`!`/`python` 类命令
    （插件 `_handle_eval` 里做命令前缀黑名单，SDK 侧再挡一层）；
  - 每个工具的 error/info 输出附 `risk` 字段供前端展示。

### 3.4 rr 时间旅行（对标 schuay / BeaCox / karellen-rr-mcp）
- `rr_record` / `rr_replay` launch 变体 + `reverse_continue/step/next/finish` verbs
  （ASYNC_VERBS 机制直接复用）。漏洞复现价值极高，且三家竞品已验证需求。

### 3.5 静态-动态桥（复活 Ghidra 导出器）
- git 标签 `archive/reverse-tools-dashboard` 中保存了已实测跑通的 Ghidra headless 导出器
  （manifest v2：按 sha256 缓存 functions/disassembly/annotations JSON，曾对 glibc 2.31
  成功导出 225/235 个函数），以 `gdb-mcp-static` 附属包形式复活。
- 动态侧新增 `load_static_analysis(path)`：backtrace/disasm 的 function 字段优先用静态
  分析标注（无符号二进制收益巨大）。替代方案：直接集成 decomp2dbg（RocketMaDev 已趟过）。
- 这是逆向 Agent 工作流的闭环：静态找嫌疑 → 动态验证，全在同一个 MCP 里。

## Phase 4 (v1.0) — 生态身份与稳定

- PyPI 发布 + MCP registry（server.json）+ awesome-mcp-servers 提交。
- Agent Skill 附加包（对标 Microsoft DebugMCP "工具描述极简 + 工作流进 skill"）：
  `crash-triage`、`heap-exploit`、`ret2libc` 多步工作流文档，随包分发，经 MCP
  `instructions` 指向。正面回应"为什么不用 gdbscript"——skill + 聚合工具提供的是
  gdbscript 给不了的工作流。
- 协议 v2：hello 已有 `features` 列表，升级为双向能力协商；明确向后兼容策略
  （server 兼容 v1 插件 N 个大版本）。
- 多架构：gdb-multiarch（ARM/MIPS 嵌入式 + 模拟器调试，gdb-multiarch-mcp 先例）。

---

## 反目标（明确不做）

1. **不内嵌 LLM**（pwndbg PR 教训：分析质量交给客户端 agent）。
2. **不重写 pwndbg 工具**（BeaCox 自实现的教训：只透传 + 解析）。
3. **不做终端抓屏备用路线**（yywz1999 路线脆弱，与插件路线互斥）。
4. **不抢 pwntools 的进程 I/O**（协同而非接管是核心设计）。

## 里程碑与验证

| 里程碑 | 判定标准 |
|---|---|
| v0.2 | 典型"断点→定位→改内存→复跑"回合的 MCP 调用次数下降 ≥50%（写进集成测试断言） |
| v0.3 | 在一道真实 glibc 2.31 堆题（tests/ezheap 素材）上，agent 全程用 MCP 完成 leak→利用 |
| v0.4 | 官方 Docker 镜像一条命令在无 WSL 的 Linux 主机可用；HTTP 模式过安全清单 |
| v1.0 | PyPI + registry 上架，协议 v2，两个以上外部贡献者 PR |

---

## 附录 A：调研要点备忘（2026-09）

- **GDB MCP**：signal-slot/mcp-gdb 159★（MI 子进程、最早多会话）；yywz1999 86★
  （tmux/iTerm 终端附加派，脆弱）；BeaCox 9★（98 工具、四级安全、lazy 代理、迭代最猛）；
  RocketMaDev/pwndbg-mcp 35★（pwndbg 别名透传、TOON、pwntools 集成是未完成 TODO）；
  Aiyakami/PWN-MCP 11★（堆 20 工具最深）；jtang613 15★（同为插件路线但仅 1 个透传工具）；
  pwno-mcp 281★（Docker SYS_PTRACE 容器派）。
- **跨调试器**：LLDB 官方内置（单工具哲学）；mcp-windbg 1.6k★（wait_for_break 阻塞、
  超时自愈、脱敏钩子）；x64dbg-mcp 1978★（事件环形缓冲、断点 action、批量求值）；
  Microsoft DebugMCP 506★（变量点名制、凭据脱敏、skill 承载工作流）；Meta dapper
  （DAP 代理实现人机共享会话）；go-delve（Automatic Context 共识源头）；veh
  （落盘+SHA-256、checkpoint、永不静默截断）。
- **RE 生态**：ida-pro-mcp 12k★（batch-first、cursor 分页、反幻觉约束写进工具描述、
  高危组默认隐藏）；GhidraMCP 10k★（插件内 HTTP 双层桥奠基）；radare2-mcp 官方
  （只读/沙箱/白名单）；Binary Ninja 官方内置；angr.mcp 官方（AI 进分析管线）。
- **反对意见**：pwndbg 拒绝 MCP PR（#4005/#4009）——"LLM 写 gdbscript 就够了"；
  pwndbg-mcp 作者弃 MCP 转 tmux+skill——token 成本是生死线。
