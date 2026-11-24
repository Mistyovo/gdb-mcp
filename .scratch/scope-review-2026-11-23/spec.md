# gdb-mcp 功能面与初衷切合度研判

日期：2026-11-23
范围：`src/`、`bench/`、`tests/`、README 与 git 历史
性质：产品范围审计（不做代码修改）

## 0. 结论先行

你的直觉大方向是对的，但需要更精确的表述：

- **默认工具面（27 → 35）不是主要问题**。新增的 10 个工具里，`heap_bins`、`checkpoint`、
  `run_policy`、`campaign` 恰好是"面向二进制利用"的自然加深；`crash_report`/停止上下文
  也仍是初衷本体。把默认面砍回 27 个并不会让项目更聚焦，反而会削弱 pwn 卖点。
- **真正的漂移在三个地方**：
  1. **跨域扩张**：Ghidra 静态分析（15 个工具、约 1.3k 行 + Java 脚本 + Ghidra 依赖）、
     内核 QEMU（2 个工具、约 0.6k 行）、libc.rip / ROPgadget 宿主侧助手（2 个工具）。
  2. **部署/安全基础设施**：HTTP + TLS/mTLS + observer 角色 + 哈希链审计日志
     （约 0.6k 行，且默认开启审计）。对一个本地单用户调试工具，这是企业部署件的体量。
  3. **验证/研究基础设施**：576 个通用调试任务 + 3.9k 行 bench 框架 + 模型 agent runner +
     已提交的模型报告。它不是产品功能，但占了仓库最大的一块体积和 CI 时间。
- **"始终做加法"的惯性仍在**：第一版 27 个工具、3,630 行 src；三个月后 76 个提交、
  11.2k 行 src、11.5k 行测试、3.8k 行 bench 框架、53k 行任务 JSON。期间已经删过
  一次 Web dashboard——说明你已经有一次"减法"的先例，现在需要第二次，但这次要减在
  **域外扩展**，而不是减在 pwn 深度上。
- **最值得补的缺口恰好都在初衷之内**：默认档没有给 inferior 喂 stdin 的能力、
  heap 时间线拿不到 malloc 返回指针、`list_threads` 没有配套的 `select_thread`、
  campaign 的 pc-control 判定会把任意寄存器命中都记成"pc 控制"。
  这些比再加一个静态分析工具重要得多。

一句话：**不要回到 27 个工具，要回到“只做用户态动态调试”这一个域，然后把 pwn 闭环做深。**

> 实施更新（2026-11-23）：issues/01 已修复；issues/11 已落地 `heap_chunk` 与
> 分配返回指针，默认 `pwn` 面 35→36（`full` 50→51，总数 56→57）。本报告的
> 计数与评级是审计时快照，实施状态以 issue 文件为准。

## 1. 初衷的原始定义

第一版提交（6e27899，2026-08-13）的 README 把边界写得很清楚：

> MCP 服务器，让大模型（Claude Code 等）驱动 Linux 下的 **gdb 进程本身**（可带 pwndbg
> 插件），用于用户态二进制漏洞挖掘与 exploit 开发中的动态调试与崩溃快速定位。
>
> - 目标是 **gdb 前端**，不是 gdbserver——即使 pwntools 的 `gdb.debug()` 内部用
>   gdbserver + `target remote`，MCP 统一通过 gdb 控制一切。
> - **原生支持 pwntools 拉起的 gdb**（`gdb.debug()` / `gdb.attach()`），无需改造
>   pwntools 代码。
> - 服务器跑在 **Windows**，gdb 跑在 **WSL2 / Linux**：gdb 内插件通过 TCP 回连服务器，
>   多会话注册表自动管理。
> - 结构化工具（内存/寄存器/回溯/断点/线程/反汇编）+ **pwndbg 命令透传** +
>   一键崩溃定位（`crash_report`）。

由此可以提炼出四条"初衷判据"：

1. **控制对象是真实 gdb 进程**（不是 MI 解析、不是终端抓屏）。
2. **场景是用户态二进制利用**（pwndbg-aware，pwntools 共存）。
3. **价值是 agent 的调试效率**（结构化状态、一次调用拿到停止全貌、token 可控）。
4. **不承担**：静态分析、内核调试、Web UI、企业级部署、基准研究。

任何功能只要不服务于第 1–3 条，或落入第 4 条，就是漂移。

## 2. 量化现状

| 指标 | 数值 | 说明 |
|---|---|---|
| 首个提交 | 2026-08-13 | 76 个提交（截至 2026-11-23） |
| `src/` 总行数 | 11,253 | 其中插件单文件 2,817 行 |
| 默认 `pwn` 工具 | 35 | 首版 27；+10 新增、−2 合并 |
| `core` 工具 | 12 | 最小会话/执行/状态面 |
| `full` 稳定工具 | 50 | pwn + 15 个 Ghidra 静态工具 |
| `full --experimental` | 56 | 50 + 6 个实验工具 |
| 默认工具 schema | 24.1 KB ≈ 8.0k tokens | 每次会话的固定上下文税 |
| `full` schema | 30.6 KB ≈ 10.2k tokens | 静态族单独约占 2.2k tokens |
| 最大 schema | 35.2 KB ≈ 11.7k tokens | 56 个工具 |
| 单元测试 | 909 passed, 1 skipped | README 写的是 910 |
| 集成/真机脚本 | 1,791 行 | WSL/CI 真 gdb 冒烟 |
| bench 框架 | 3,864 行 | 22 个文件 |
| bench 任务 | 576 个 / 53,381 行 JSON | 8 个家族，全部通用调试任务 |
| 模型报告 | deepseek-chat 18/48 = 37.5% | 平均 83,861 tokens/任务、11 次工具调用 |

工具面构成（AST 统计）：

| 模块 | 工具数 | 备注 |
|---|---|---|
| static_tools | 15 | 仅 `full`，Ghidra 查询族 |
| state_tools | 11 | 核心状态面 |
| exec_tools | 6 | execute/continue/interrupt/wait/read_result/batch |
| experimental | 6 | inferior_io / libc / ROP / kernel |
| session_tools | 5 | 会话与产物 |
| breakpoint_tools | 3 | 断点 |
| heap_tools | 3 | heap_bins / run_policy / checkpoint |
| launch_tools | 3 | launch/kill |
| campaign_tools | 2 | campaign / diff_sessions |
| crash_tools | 2 | crash_report / triage_crash |

首版 27 → 当前 35 的具体变化：

- 删/并：`quit_gdb`（并入 `kill_session`）、`get_stop_reason`（并入 `wait_for_stop` /
  `continue_execution(wait=True)`）。这是健康的合并先例。
- 新增：`get_events`、`read_result`、`export_session_script`、`diff_sessions`、
  `batch_commands`、`triage_crash`、`heap_bins`、`checkpoint`、`run_policy`、`campaign`。

## 3. 逐项判读

评级：
- **A 核心契合**：直接服务于"agent 操控真实 gdb 做用户态调试/利用"，保留并强化。
- **B 相关但需收敛**：方向对，但概念/实现/文档需要瘦身或修正。
- **C 边缘可降级**：不是主路径，降到 experimental / 部署附加件，或明确标注。
- **D 偏离应外移**：属于另一个产品域，切到独立仓库/包，或删除。

### 3.1 平台核心层

| 功能点 | 解决什么 | 评级 | 结论 |
|---|---|---|---|
| gdb 进程内插件（stdlib-only、JSON-lines、主线程 marshal、事件推送） | 不解析 MI、不抓屏，pwndbg 天然可用 | A | 这是项目护城河，保持单文件、零依赖 |
| TCP 回连 + 心跳 + 退避重连 + 多宿主发现 | 谁先启动都行，WSL/NAT 可穿透 | A | 保留 |
| 会话注册表、自动选中、歧义报错、状态机 | 多 gdb 会话 | A | 保留 |
| 会话持久化 + re-hello 复活 | gdb 比 MCP 服务器活得久 | A | 保留；这是 pwntools 场景的关键 |
| WSL / native launcher | 主路径 | A | 保留 |
| Docker launcher | 容器内调试 | D | README 自认"未端到端验证"；切走或冻结 |
| SSH launcher | 远程目标 | D | 同上；若要做远程，应作为独立、受测特性 |
| `launch_gdb`（program/attach_pid/args/env/run） | 拉起/附着 | A | 保留 |
| `launch_script`（pwntools） | 不改 pwntools 代码 | A | 保留；这是差异化 |
| `kill_session`（detach/force/forget） | 生命周期 | A | 保留 |
| `get_process_output` | 看被启动进程日志 | A | 保留 |
| TCP token + 会话级 HMAC token | execute_command 等价本机代码执行 | A | 保留 |
| unsafe 命令门（缩写感知、逐行、双层） | 防止 agent 被二进制内容注入后 `shell` | A | 保留；这是 agent 场景的刚需 |
| capability 模型 + `--readonly` | 权限分级 | A | 保留；修 help 文案 |
| HTTP 传输 + Host/Origin + bearer | 远程 MCP 客户端 | C | 可保留为 opt-in，不进主线叙事 |
| TLS / mTLS | 部署安全 | D | 企业部署件，切到 deployment extra |
| observer token/role | 只读观察者 | C | 与 `--readonly` 重叠；降级 |
| 哈希链审计日志 + 离线校验 | 防篡改审计 | C/D | 本地单用户工具过重；降级为普通日志或切走 |
| `mcp status/reconnect/detach` | gdb 内运维 | B | 保留 |

### 3.2 调试面

| 功能点 | 解决什么 | 评级 | 结论 |
|---|---|---|---|
| `execute_command`（pwndbg 透传、分页、落盘） | vmmap/heap/got/checksec 等一切 CLI | A | 核心，保留 |
| `batch_commands` | 一次往返多条命令 | C | 与 `execute_command` 多行等价；删 |
| `continue_execution`（continue/step/next/stepi/nexti/finish/until + reverse + wait + context） | 执行控制 + 一次拿停止全貌 | A | 核心，保留 |
| `interrupt` | 打断运行 | A | 保留 |
| `wait_for_stop` | 等异步停止 | A | 保留；与 continue(wait) 文档上二选一 |
| `read_result` + 大结果落盘/分页 | token 经济 | A | 保留 |
| `read_memory` / `write_memory` | 内存 | A | 保留 |
| `read_registers` / `write_register` | 寄存器 | A | 保留 |
| `get_backtrace` / `disassemble` | 回溯/反汇编 | A | 保留 |
| `evaluate` | PIE-aware 表达式 | A | 保留（capability=target 定得对：可调用 inferior 函数） |
| `list_threads` | 线程列表 | A | 保留；**缺 `select_thread`** |
| `select_frame` | 栈帧选择 | A | 保留 |
| `get_memory_map` | 结构化映射 | A | 保留；core file 场景有缺口 |
| `load_target`（file/core） | 加载目标/core | A | 保留；core 的映射解析需补 |
| `set_breakpoint`（sw/hw/watch/cond/temp/commands/auto_continue） | 断点 | A | 核心，保留 |
| `list_breakpoints` / `manage_breakpoint` | 断点管理 | A | 保留 |
| 停止上下文组合（regs+bt+disasm+键寄存器） | 一次调用全貌 | A | 核心差异化 |
| reverse_continue/step/next | gdb record 时间旅行 | B | 低成本，保留 |
| `crash_report` | 旗舰：signal/fault/PC/regs/bt/disasm/mem/map | A | 核心，保留 |
| `triage_crash` | 回放 payload→报告→最小化→证据 | B | 与 crash_report + run_policy 重叠；合并 |

### 3.3 Pwn 工作流

| 功能点 | 解决什么 | 评级 | 结论 |
|---|---|---|---|
| `heap_bins` | pwndbg bins 结构化 | A | 保留；但只覆盖 bins，深度不够 |
| `checkpoint` create/list/restore/diff | 假设检验的状态快照 | A | 保留；它是 fuzz_loop/minimize 的基座 |
| `run_policy(trace)` | 原生速度单步去重 | B | 保留；与 gdb record 有重叠，别扩展 |
| `run_policy(heap_arm/read/disarm)` | 分配事件时间线 | A/B | 已补齐返回指针与命名参数（issues/11） |
| `run_policy(fuzz_loop)` | 批量 payload 回放、去重崩溃 | A | 核心差异化，保留 |
| `run_policy(crash_check)` | 单 payload 判定 | A | 保留 |
| `run_policy(minimize)` | delta-debugging 最小化 | A | 保留；README 误标为 experimental |
| `run_policy(bp_stats)` | 命中计数循环 | B | 保留；别扩展 |
| `campaign`（state + cyclic oracle + pattern） | 跨会话记住已证明的事 | B | 保留轻量版；pc_control 判定过宽，**已修复（issues/01）** |
| campaign 自动注入停止上下文 | 避免重复推导 | B | 保留摘要；可改为显式 `campaign get` |
| `diff_sessions` | 两输入差分调试 | C | 边缘；降 experimental 或删 |
| cyclic pattern 生成 | 无 pwntools 时也能造 pattern | A | 保留 |

**campaign 的具体缺陷（已复现）**：`campaign_detect` 遍历 PC、fault_addr 以及**所有寄存器**；
任意寄存器命中 cyclic 都会写入 `primitives["pc_control"]`。实测：

```text
match: {'source': 'reg:rax', 'offset': 64, 'sub': 4}
primitives recorded: {'pc_control': {'evidence': 'reg:rax matches cyclic pattern at offset 64'}}
```

PC 根本没变。这不是范围问题，是"把猜测写成结论"的正确性问题：这个结论还会被注入后续
停止响应，误导 agent。建议改名为 `cyclic_match`，或只在 `source == "pc"` 时记 `pc_control`，
fault_addr 另记 `fault_addr_controlled` 候选。

**已于 2026-11-23 修复**：PC → `pc_control`、fault_addr → `fault_addr_controlled`、
其余寄存器 → `cyclic_match`（`value` 保留来源名）。见
[issues/01](issues/01-campaign-cyclic-attribution.md)。

### 3.4 产物、持久化与审计

| 功能点 | 解决什么 | 评级 | 结论 |
|---|---|---|---|
| 每会话 JSONL journal | 请求/通知审计、导出源 | B | 保留；schema/migration/mirror 机制可简化 |
| `export_session_script` | 生成可重放 gdbscript | B | 保留；但它跳过 checkpoint/policy、写入上限 256B，不能宣称完整重放 |
| 会话归档 + retention | 有界磁盘 | B | 保留 |
| 结果文件存储 `read_result` | 大输出不淹上下文 | A | 保留 |
| 哈希链 audit.log | 防篡改安全决策记录 | C/D | 与"本地调试工具"不匹配；降级/切走 |

### 3.5 静态分析（Ghidra）

15 个工具：`analyze_binary`、`list_analyses`、`get_analysis_status`、
`get_binary_overview`、`list_sections`、`list_symbols`、`list_functions`、
`list_strings`、`decompile_function`、`get_static_disassembly`、`get_xrefs`、
`get_call_graph`、`search_decompiled_code`、`annotate_code`、`remove_code_annotation`。

评级：**D**。理由：

- 它与 gdb 会话零耦合；`AnalysisManager` 文档自己说"live location mapping was removed
  with the dashboard"。
- 1,327 行 Python + `ExportAnalysis.java` + Ghidra headless 依赖；`full` 档每次会话
  多约 2.2k tokens 的工具 schema。
- 静态反编译是另一个产品域；agent 真需要时可以自己跑 Ghidra/objdump，或接一个独立的
  static MCP。
- 保留的 `AnalysisStore.newest_for_path` / `matches_path` 只有测试在用，是 dashboard
  时代的残留，说明这块的维护动机已经不足。

建议：拆成独立包/仓库；本仓库最多保留一个 `full` 档的薄桥，且不再投入。

### 3.6 内核（QEMU）

`kernel_launch` / `kernel_snapshot`：评级 **D**。README 自己承认"separate target class"、
KASLR 未自动纠正、需要 QEMU + qcow2 + socat。内核 pwn 与用户态 pwn 是两种工作流，
放在同一个默认产品里只会稀释叙事。切走或冻结为独立实验分支。

### 3.7 实验性宿主侧助手

| 功能点 | 评级 | 结论 |
|---|---|---|
| `inferior_io` / `read_inferior_output`（pty） | C | 唯一填了真实缺口（默认档不能喂 stdin）的实验件；要么提升最小版到 pwn 档，要么删掉，别半吊子 |
| `identify_libc`（libc.rip） | D | 不碰调试器、依赖第三方网络、只发低 12 位；切走 |
| `search_gadgets`（ROPgadget） | D | 在**服务器宿主**上跑，主场景 Windows/WSL 下二进制通常不在宿主可读路径；切走 |

### 3.8 验证体系（tests / bench）

| 功能点 | 评级 | 结论 |
|---|---|---|
| 909 个单元测试（无 gdb 可跑） | A | 保留；这是质量契约 |
| 真 gdb 集成冒烟（gdb 12/15/17、policy、unsafe gate、IO、TLS） | A | 保留；mock 保真度事故的教训值得 |
| bench selfcheck（576 任务全部参考解） | B | 作为回归门有价值，但 576 个太多 |
| bench 8 个通用调试家族 | B/C | 覆盖 breakpoints/crash/inspect/lifecycle/multistep/optimize/pie/threads，**完全不覆盖 heap/checkpoint/run_policy/campaign/triage_crash**；测的是"通用调试"，不是本项目差异化 |
| bench agent runner + deepseek 报告 | D | 研究基础设施，不是产品；拆到 research/ 或外仓 |
| stress/faults/perf/pwndbg suite | B/C | 保留为定期跑，不必每次 PR |

bench 的关键问题不是"大"，而是**测错了东西**：576/576 参考解证明工具能用，
但 deepseek-chat 18/48（37.5%）说明 agent 不一定好用；而真正需要度量的 pwn 闭环
（heap、checkpoint、fuzz_loop、campaign）一个任务都没有。继续加通用任务只会放大
"自证"成分。建议缩到 60–100 个代表性任务，并新增 pwn 家族。

### 3.9 文档与脚手架

- `docs/agents/` 三份约定：中性，保留。
- `README.md` / `README.zh-CN.md`：叙事已经从"gdb 前端"扩成"agentic pwn platform"，
  是漂移的文本表现。
- 具体失准：
  - `ROADMAP.md`、`ROADMAP_V2.md` 已在最新提交删除，但 README 仍有 4 处链接指向它们。
  - "910 unit tests" 实际是 909 passed + 1 skipped。
  - `--readonly` 的 help 说"drop state-mutating tools (write_memory/write_register)"，
    实际会丢掉所有非 observe 工具（包括 `execute_command`、`continue_execution`、
    `launch_gdb`）。
  - README 把 `minimize` 写在 Experimental Features 下，但 `run_policy(kind="minimize")`
    在默认 `pwn` 档就是可用的，并没有被 `--experimental` 门控。
  - `search_gadgets` 的宿主路径限制已在 docstring 说明，但 README 仍把它列为普通 pwn 助手。

## 4. 取舍清单

### 4.1 立即修（正确性/一致性，不改范围）

1. `campaign_detect`：只在 `pc` 命中时记 `pc_control`；`fault_addr` 记
   `fault_addr_controlled`；任意寄存器记 `cyclic_match`。补一条"rax 命中不得产生
   pc_control"的测试。**已完成，见 [issues/01](issues/01-campaign-cyclic-attribution.md)。**
2. README/README.zh-CN：删/补 ROADMAP 链接；改测试数；把 `minimize` 归到 pwn workflow
   或真正加 `--experimental` 门控；修正 `--readonly` 说明。
3. core file 的 `get_memory_map`/`crash_report`：`info proc mappings` 依赖活进程，
   core 场景应有 `info files`/`maintenance info sections` 回退。
4. 给 `run_policy` 加取消语义（或让 `interrupt` 中止活动 policy 并返回部分摘要）。

### 4.2 第一批减法（体量最大、风险最低）

| 动作 | 对象 | 理由 |
|---|---|---|
| 外移 | Ghidra 静态族（15 工具 + reverse/ + Java） | 另一个产品域；默认 pwn 档不受影响 |
| 删除/外移 | kernel QEMU（2 工具 + kernel/） | 另一个目标类；README 自认实验 |
| 删除 | `identify_libc` / `search_gadgets` | 不碰调试器；第三方网络/宿主路径 |
| 冻结/删除 | Docker / SSH launcher | 未端到端验证；主路径是 WSL/native |
| 降级或外移 | HTTP TLS/mTLS、observer、哈希链 audit | 企业部署件；保留 token+loopback+unsafe gate 即可 |
| 收缩 | bench：60–100 个任务 + selfcheck；删 agent runner/模型报告 | 减少仓库体积与 CI 时间；把度量对准 pwn |

预期效果：src 减少约 1.8k 行（static 1.3k + kernel 0.5k 上下），工具 schema 最大面
从 56 个 / 35KB 降到约 37 个 / 25KB；bench 任务 JSON 从 53k 行降到 ~6k 行。

### 4.3 第二批收敛（工具合并/降级）

| 动作 | 对象 | 替代 |
|---|---|---|
| 合并 | `triage_crash` → `crash_report(replay=..., minimize=...)` | 少一个工具、少一套重复报告路径 |
| 删除 | `batch_commands` | `execute_command` 多行命令（unsafe gate 已逐行检查） |
| 降级/删除 | `diff_sessions` | experimental，或由 agent 手动对比两个会话 |
| 二选一 | `inferior_io` | 要么把最小 send/read 提升到 pwn 档，要么删 |
| 简化 | journal（保留导出，去掉过度 schema/migration） | export_session_script 仍需 journal |
| 显式化 | campaign 自动注入 | 保留摘要，或改成 `campaign get` 按需 |

### 4.4 第三批加深（护城河，不是新域）

1. **默认档 inferior I/O**：`send_input(hex/text)` + `read_output`，或 `run(input=...)`。
   这是 pwn 的真缺口；pwntools-only 路径不能覆盖 `launch_gdb` 用户。
2. **heap 时间线拿到分配身份**：malloc/calloc/realloc 的返回指针、free 的入参、
   tcache bin 变化；再加 `heap_chunk(addr)`（size/prev_size/fd/bk/tcache key）。
   **已完成（issues/11）：返回指针、命名参数与 heap_chunk；bin 迁移快照仍为可选。**
3. **`select_thread`**：`list_threads` 有了，缺选择；现在只能 `execute_command("thread N")`。
4. **`verify_pc_control` policy**：用 canary 重放，验证 offset 真的改写了 PC；
   把 campaign 的"candidate"变成证据。
5. **protections 自动识别**：解析 `checksec` 写入 `campaign.protections`；
   比手工 `campaign set` 可靠。
6. **core-file triage**：补齐 core 的映射解析，让"崩溃快速定位"覆盖离线 core。
7. **policy 取消**：长 fuzz_loop/minimize 的干净取消。

### 4.5 未来的准入门槛

每加一个工具/家族，先回答：

> 它是否让 agent 更好地驱动一个**活的用户态 gdb**？

答否的，做成独立 MCP / 独立仓库 / 外部脚本，不进入本仓库默认面。新域不共享
这个准入门槛，是过去三个月漂移的根因。

## 5. 建议的新产品叙事

> **gdb-mcp 是真实、pwndbg-aware 的用户态 gdb 的 MCP 前端。**
> 它负责：拉起/附着、执行控制、状态检查、断点、崩溃定位、有界的 pwn 循环
> （checkpoint/fuzz/minimize），以及与 pwntools 共存。
> 它不负责：静态分析、内核调试、Web UI、企业级认证、基准研究。

对应的三档 profile 可以保持不变：

- `core`：12 个工具，3.2k tokens，适合"只想要一个 gdb 前端"。
- `pwn`（默认）：35 个工具，8k tokens，用户态利用闭环。
- `full`：**建议只保留 pwn + 可选的实验件**；静态族外移后，full 可以退役，
  或改名为 `labs`。

## 6. Issue 索引

实施票据在 [issues/](issues/)；状态以各文件顶部的 `Status:` 行为准。

| # | 标题 | 状态 |
|---|---|---|
| 01 | [campaign cyclic 命中按来源归因](issues/01-campaign-cyclic-attribution.md) | resolved |
| 02 | [README 与 CLI 帮助的失准点](issues/02-readme-cli-consistency.md) | resolved |
| 03 | [core file 的停止上下文与内存映射](issues/03-core-file-memory-map.md) | resolved |
| 04 | [长 policy 的取消语义](issues/04-policy-cancellation.md) | resolved |
| 05 | [范围决策：Ghidra 静态分析族是否外移](issues/05-scope-decision-ghidra-static.md) | resolved |
| 06 | [范围决策：内核 QEMU 与宿主侧 pwn 助手](issues/06-scope-decision-kernel-and-helpers.md) | resolved |
| 07 | [范围决策：Docker / SSH launcher 的冻结或补测](issues/07-scope-decision-docker-ssh.md) | resolved |
| 08 | [范围决策：部署安全设施降级](issues/08-scope-decision-deployment-security.md) | resolved |
| 09 | [bench 收缩并对准 pwn 闭环](issues/09-bench-shrink-and-pwn-families.md) | resolved |
| 10 | [工具面合并：triage_crash / batch_commands / diff_sessions](issues/10-tool-surface-consolidation.md) | resolved |
| 11 | [heap 时间线补齐分配身份与 chunk 视图](issues/11-heap-allocation-identity.md) | resolved |
| 12 | [增加 select_thread 工具](issues/12-select-thread.md) | resolved |
| 13 | [campaign 证据硬化：verify_pc_control + checksec 自动识别](issues/13-campaign-evidence-hardening.md) | resolved |
| 14 | [默认档 inferior I/O 的去留](issues/14-default-inferior-io.md) | resolved |
| 15 | [agent 可用性与工具 schema token 预算](issues/15-agent-usability-schema-budget.md) | resolved |
| 16 | [ADR：用户态动态调试范围守则](issues/16-adr-scope-gate.md) | resolved |
| 17 | [kill_session(force=True) 与文档/e2e 的语义不一致](issues/17-kill-session-force-semantics.md) | resolved |

## 7. 附：证据与复现

- 初衷原文：`git show 6e27899:README.md`
- 工具计数/schema：AST 统计 + `build_app` 实测（core 12/9.7KB，pwn 35/24.1KB，
  full 50/30.6KB，full+exp 56/35.2KB）
- campaign 过宽判定：`python -c` 调用 `campaign_detect`，rax 命中产生
  `primitives.pc_control`（见 3.3）
- bench 工具覆盖：`grep` 结果显示 `checkpoint/run_policy/campaign/triage_crash`
  只出现在 e2e 脚本，不出现在 bench 家族
- 模型报告：`bench/reports/agent-deepseek-chat-first48-20260926.json`（18/48）
- 失效链接：`grep -n ROADMAP README.md README.zh-CN.md`（4 处指向已删除文件）
- 残留死代码：`AnalysisStore.newest_for_path`/`matches_path` 仅测试引用
- Docker/SSH 未验证：README "Launchers" 表
- `--readonly` 行为：`tools/registry.py::_visible`
- README 实验档矛盾：`README.md` Experimental Features vs `tools/heap_tools.py::run_policy`
