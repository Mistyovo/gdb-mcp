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

## Phase 1 (v0.2) — Token 经济学（主线 A）✅ 已完成（2026-09-17）

### 1.1 停机即上下文 ✅
- `continue_execution(wait=True, with_context=True)`：一次调用完成 resume →
  等停 → 返回 stop_info + 关键寄存器子集（x86/ARM 常用集，未知架构回退全量）+
  backtrace 顶 N 帧 + PC 附近反汇编（`tools/stop_context.py`，复用 crash_report
  的持锁 try_verb 模式，插件零改动）。
- `wait_for_stop(with_context=True)` 同样支持。默认行为（立即返回）保持不变；
  `crash_report` 保留为崩溃场景的更深变体。

### 1.2 输出治理 ✅（精确丢弃计数一项以布尔标记+total_lines 替代）
- `execute_command` 分页（Phase 0 已有）+ **大结果落盘**：超过
  `GDB_MCP_RESULT_INLINE_LIMIT`（默认 16k 字符）自动存盘
  （内容寻址去重），响应只回 preview + `result_file`/`result_sha256`，
  新工具 `read_result(path, offset, limit)` 按行续读（带路径越界校验）。
- `get_memory_map` 返回**结构化 segments**（start/end/size/offset/perms/
  objfile，`output.parse_proc_mappings` 容错解析，不依赖 pwndbg）；
  `crash_report` 的 memory_map 同步结构化。
- `backtrace`/`disasm` 响应带 `truncated` 标记（插件多走一帧/一条探测；
  未做全栈游走的精确丢弃计数——对模型用途布尔+total_lines 已足够）。
- eval 响应始终携带精确 `total_lines`。

### 1.3 事件环形缓冲 ✅
- `Session.event_log`（deque maxlen=100，单调 seq + 时间戳），记录
  connected / stop / running / exited / prompt / disconnected；
  新工具 `get_events(last=N)` 兜底"两次调用之间的事件"。

### 1.4 工具分档 ✅
- `GDB_MCP_TOOL_PROFILE=core`（12 个高频工具）| `full`（全部 29 个）。
  server instructions 已指向 one-call 模式。

## Phase 2 (v0.3) — 漏洞工作流纵深（主线 B，护城河）✅ 核心完成（2026-09-17）

### 2.1 堆分析结构化 ✅（bins 部分；malloc/free 行为日志延期）
- 新工具 `heap_bins`：pwndbg `bins` → 结构化 JSON（tcachebins/fastbins/unsorted/
  small/large，每节 size → chunk 地址表）。节名解析覆盖新旧 pwndbg 两种写法
  （`unsorted bins` 与 `unsortedbin` 等——后者已在 kali 真实环境采样验证，glibc 2.42）；
  无法识别时 `parsed=false` 并原样带回文本，**诚实降级而非猜测**。
- 插件要求 pwndbg（`hello.pwndbg` 门控，缺失时报 NO_PWNDBG 并指引 execute_command）。
- **延期**：malloc/free hook 行为日志 + heap_timeline（需在真实调试会话验证断点
  自动采样，见 2.1b）。

### 2.2 checkpoint / restore / diff ✅
- 插件新增 4 个 GATED 动词 `snapshot_create/list/restore/diff`；寄存器全集 +
  可写内存段（`info proc mappings` perms 过滤），单段/总预算默认 4MiB/8MiB
  （硬顶 12MiB，保护协议帧上限），保留最近 8 个快照（内容寻址去重无需——按
  id 环形）。restore 复用 `set_reg`/`write_mem` 既有校验路径；diff 输出变更
  寄存器 + 16 字节粒度内存差异行（上限 256 行 + truncated 标记）。
- 新工具 `checkpoint(action=create|list|restore|diff, snapshot_id, ...)`。
- 价值场景闭环：snapshot → 打 payload → diff 堆布局 → restore 重跑。

### 2.3 断点 action 与批量 ✅
- `set_breakpoint` 新增 `commands`（命中自动执行，自动加 `silent` 前缀）与
  `auto_continue`（命中即恢复）——一条指令布好无人值守信息收集探针。
- 新工具 `batch_commands(commands)`：多条 gdb CLI 命令一次往返，逐条结果、
  首错即停；全部命令在执行前校验（不含 verb 级 batch——CLI 批量 + 停机上下文
  + crash_report 已覆盖主要 round-trip 场景）。

### 2.1b（延期项）heap 行为日志与 timeline
- malloc/calloc/realloc/free 断点自动采样（ABI 感知取参 + caller 回溯）→
  环形缓冲 → `heap_timeline` 工具；请求粒度 begin/end 标记。与 2.2 的 diff
  引擎共用行格式。这是 v0.3 里程碑判定（真实堆题全流程）的前置项。

### 2.4 inferior I/O 通道 ⏸ 延期
- `send_to_inferior`/`read_inferior_output`（inferior-tty + 环形缓冲）需要
  在 WSL 无头环境做 tty 交互验证，且 pwntools 场景必须保持脚本自治。延期到
  专门的小迭代，不阻塞主线。

## Phase 3 (v0.4) — 分发与规模（主线 C）✅ 核心完成（2026-09-17）

### 3.1 Launcher 抽象 ✅
- `GDB_MCP_LAUNCHER=wsl|native|docker|ssh`：`_spawn`/`pkill_marker` 按后端
  构造 argv（`build_ssh_argv`/`build_docker_run_argv`/`build_terminate_argv`
  纯函数，全单测）。docker 后端：一次性容器（`SYS_PTRACE` + 放宽 seccomp）、
  容器名即会话标记（终止= `docker kill`）、cwd 与插件按次 bind-mount、插件
  路径重写为容器内 `/opt/gdb-mcp/`。镜像配方 `docker/Dockerfile`
  （kali + gdb + pwndbg + pwntools + 服务器包）。
- **注意**：镜像构建与 docker/ssh 端到端在本机（无 docker/远端靶机）未实测，
  构造器逻辑已单测覆盖——首次使用时按 Dockerfile 注释构建即可。

### 3.2 MCP HTTP transport ✅
- `GDB_MCP_MCP_HTTP=1` 切换 streamable-HTTP（FastMCP + uvicorn），默认
  `127.0.0.1:8001/mcp`。`http_hardening.py` 落实四防线：非 loopback 绑定
  强制 token（Config.validate 拒绝启动）、Host 头校验（防 DNS rebinding）、
  Origin 校验、配置 token 则全请求 Bearer（常量时间比较）。决策函数纯化
  单测；ASGI wrapper 拦截返回 403。
- **注意**：加固逻辑单测覆盖；真实 MCP 客户端走 HTTP 握手的端到端未跑
  （本机无第二客户端），首次启用建议先用 curl 验证 403/通行行为。

### 3.3 安全分级 ✅
- `GDB_MCP_READONLY=1`：注册层直接不挂 `write_memory`/`write_register`。
- `GDB_MCP_ALLOW_UNSAFE=1`（`--allow-unsafe`，launch 时同步传给被拉起的
  gdb）：`shell`/`!`/`pipe`/`python`/`source` 类逃逸命令默认 `UNSAFE_BLOCKED`，
  服务端工具层与 gdb 内插件**双层拦截**（插件 stdlib 复制同一前缀表，
  防绕过 MCP 直连插件）。文档明确：gdb 命令缩写使前缀门是纵深防御而非沙箱。
- risk 字段标注延期（噪声大、收益低，前端有需要再说）。

### 3.4 rr 时间旅行 ⏸ 延期（同 2.1b：需真实 rr 环境；反向执行动词设计
  已明确——复用 ASYNC_VERBS 机制映射 `reverse-continue/step/next/finish`）

### 3.5 静态-动态桥 ⏸ 延期（归档标签 `archive/reverse-tools-dashboard`
  的 Ghidra 导出器复活为 `gdb-mcp-static` 附属包，独立小迭代）

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
