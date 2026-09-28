# gdb-mcp 路线图 v2 — 长期创新方向（2026-09 起，12–24 个月视野）

> 前版 ROADMAP.md 的 Phase 0–3 已落地（延期项并入本文件）。本文件不再是功能清单的
> 延续，而是回答一个更大的问题：**当所有竞品都在做"调试器工具箱"时，gdb-mcp 下一步
> 应该成为什么？** 答案：从工具箱变成**漏洞利用战役的常驻大脑**——它记得整场战役、
> 能替 agent 原生速度执行循环、并产出可审计可复现的工件。

## 0. 批判性重读结论（2026-09-17，src 5.4k 行 / tests 5.2k 行）

### 0.1 结构性缺口（重读新发现，均为事实核查过）

| # | 问题 | 位置 | 影响 |
|---|---|---|---|
| G1 | **结果存储无 GC**：results 落盘文件只增不删 | `results.py` | 长期运行的磁盘泄漏（真 bug） |
| G2 | **服务器重启丢会话**：fresh registry 忽略插件 hello 里的 session_id，重新分配新 id，launch 簿记（日志、进程句柄）全部丢失 | `sessions.py register_hello` | 服务器随 Claude Code 会话启停，gdb 却常驻——身份断裂 |
| G3 | **协议动词表无交叉校验**：protocol.VERBS 与插件 VERB_HANDLERS 两处手写，测试只断言子集 | `protocol.py` / 插件 | 新增动词漂移只能靠人肉（Phase 2 就差点漂移） |
| G4 | **FastMCP 私有内部依赖**：`app._registry/_config/_tool_manager._tools` 三处 | `server.py` / `tools/__init__.py` | mcp 库升级即碎 —— ✅ 已于 2026-09-28 架构整备中消除（见 §7.1） |
| G5 | **instructions 落后两个 Phase**：heap_bins/checkpoint/campaign 化工作流未告知 agent | `server.py` | agent 自发用不到新能力 |
| G6 | **插件 `gdb.execute(` 行被安全钩子冻结**：任何触碰该行的新代码都被 Mimosa 误报拦截（Phase 2/3 全靠绕行） | 插件全局 | 插件演化摩擦持续存在 |
| G7 | 事件环形缓冲只有内存态 100 条，无持久化 | `sessions.py` | 会话分析/审计/回放无从谈起 |

### 0.2 对前版路线的批判性修正

- 前版把 token 经济学当作**单次调用**问题解决（聚合/分页/落盘）——已做到竞品前沿。
  但**多轮循环**（fuzz、sweep、trace）在"LLM 每轮一次调用"的架构下永远不可行，
  token 与延迟都撑不住。必须反转执行模型（主题 A）。
- 前版把 pwndbg 维护者的质疑（"LLM 直接写 gdbscript 就行"）当作需要防御的反对意见；
  正确的姿态是**把它变成验收标准**：agent 做过的一切都应能导出为确定性 gdbscript
  并独立重放验证（主题 B3）——这同时是审计、复现和评测的基础。
- 2.1b/2.4/3.4 三个延期项其实是同一个原语的三个特例（heap 采样、输入喂入、反向执行
  都是"插件侧受控循环"），不该逐个补，应一次性抽象（主题 A）。

## 1. 主题 A：委托执行反转 — "agent 写策略，插件原生跑"

**创新点**：全生态（x64dbg-mcp 的 Trace N 步、PWN-MCP 的 heap_sweep）都只有点状
实现，无人提供通用的插件侧策略执行层。gdb-mcp 把循环下沉到 gdb 进程内原生速度执行，
agent 只收恒定大小的摘要——这是 LLM 驱动动态分析的架构级答案。

- `run_policy(kind, params)` 动词族（受枚举约束的策略模板，**不 eval 任意代码**，
  安全边界不破坏）：
  - `trace`：有界单步/基本块轨迹 + 去重（覆盖反馈的原料）；
  - `heap_timeline`：malloc/calloc/realloc/free 断点自动采样 → 摘要 + 事件表
    （即 2.1b 的正式形态）；
  - `fuzz_loop`：checkpoint(restore) + 追踪到的输入缓冲区变异 + 崩溃签名去重
    （`pc模块+offset + 信号 + 访问类型`），跑 N 轮返回去重崩溃列表——**gdb 内快照
    模糊测试**，对标 Nyx 类技术但零基础设施；
  - `bp_stats`：断点命中统计探针的长跑版。
- 依赖链：fuzz_loop 需要 2.4 inferior I/O（喂输入）与 B2 journal（记证据）。
- 验收：在一道真实堆题上，单次 `run_policy(fuzz_loop)` 调用完成 ≥1000 轮变异并
  返回可分诊的崩溃签名；token 消耗与轮数无关（恒定）。

## 2. 主题 B：会话即资产 — 持久化、日志、可复现工件

- **B1 会话持久化**：registry 落盘 + 重启后按插件 hello 的 session_id 复活原会话
  （修 G2）。服务器随编辑器会话启停，gdb 常驻——身份必须连续。
- **B2 会话 Journal**：每会话 JSONL 全量记录（请求/通知/响应摘要，含 campaign 证据
  引用），经 MCP Resources 暴露 `gdb://session/{id}/journal`；同时是审计日志。
- **B3 `export_session_script`**：从 journal 编译出**确定性 gdbscript（+pwntools
  骨架）**，可独立重放复现 agent 的全部操作。正面回应"gdbscript 就够了"——从此
  gdbscript 是 gdb-mcp 的**产出物**而非替代品；也是 E3 评测的评分依据。
- **B4 卫生**：result-store GC（修 G1）、按会话的工作目录归档策略。

## 3. 主题 C：战役状态机（Exploit Campaign State）— 服务器成为队友

**创新点**：所有竞品都是无状态工具箱；没有谁维护"这场漏洞利用进行到哪了"。
而 LLM 每轮重推全部上下文恰是最大的浪费与错误源。

- **C1 `campaign` 状态**（服务器维护、插件与工具共同喂入）：
  `{target: checksec/arch/libc指纹, offsets: {libc基址, buf偏移, gadget},
  primitives: {info_leak, arbitrary_read, arbitrary_write, pc_control — 每项附
  journal 证据}, next_hint}`。
- **C2 自动提取**（服务端零猜测的确定性规则）：
  - cyclic/de Bruijn 偏移 oracle：crash_report 检测 PC/fault/寄存器中的模式段，
    一键给出偏移（当前完全缺失，重读已核实）；
  - libc 指纹：泄漏值低 12 位 → 本地 libc 库比对（可选离线包）；
  - pc_control 证据：断在非预期地址且该地址来自输入模式 → primitive 标记。
- **C3 恒定 brief 注入**：stop_context/crash_report 尾部自动附 3–5 行 campaign
  摘要——LLM 每轮的"我在哪、下一步该干嘛"由服务器给，不再重推。
- **C4 MCP Resources 化**：`gdb://campaign/{sid}` 可订阅只读视图
  （ida-pro-mcp 已验证 Resources 模式在 agent 侧的低成本轮询价值）。
- 验收：同一道题，带 campaign brief 的 agent 完成 exploit 的轮次/token 较不带
  下降 ≥40%（写进 bench）。

## 4. 主题 D：编排与差分 — 多会话从"并列"到"协同"

- **D1 `diff_sessions(a, b)`**：复用 checkpoint diff 引擎做**跨会话**状态差分
  （同靶不同输入的执行流对比）——差异即行为语义。
- **D2 会话多路**：插件允许多连接（1 controller + N 只读 observer）——dapper 式
  人机共驾（人在 tmux 看 pwndbg，agent 同步操作）与"红队 agent + 蓝队 reviewer
  agent"双角色工作流。
- **D3 crash→debug 流水线**：`fuzz_loop` 的去重崩溃自动生成新 debug 会话并附
  crash_report，半自主 triage。

## 5. 主题 E：生态与协议

- **E1 协议 v2**：能力协商（hello features → 服务器广播支持集）、帧压缩/二进制
  可选项（heap dump 场景 ~10x）、动词表从两处手写收敛为单一来源 + 一致性测试
  （修 G3）。
- **E2 发布**（原 Phase 4）：PyPI + MCP registry + Agent Skill 包（triage/heap/
  ret2libc 工作流文档，instructions 指向——修 G5 同步）。
- **E3 Benchmark**：`tests/bench/` N 个分级 crackme/堆题 + 评分器（用 B3 导出脚本
  独立重放判定成功率），发布各模型 × gdb-mcp 成功率报告——让项目成为"LLM pwn
  能力"的参照系，这是社区credibility的护城河。
- **E4 安全演进**：会话级 scoped token、mTLS（HTTP 模式）、audit 导出（B2 副产品）。

## 5.5 主题 F：内核执行闭环 — kernel pwn 的基础设施（2026-09-26 立项，层① 已 PoC）

**动机**：ExploitGym（2026）已把 Linux kernel LPE 纳入 AI 利用评测；现有 pwn 原语
（campaign/policy/checkpoint）在内核场景天然复用，WSL2 后端顺路。四层路线：

1. **执行闭环**（本层）——QEMU gdbstub 启动 + `savevm/loadvm` 快照秒级 revert +
   vmlinux 符号加载 + KASLR slide 修正；
2. **工具链**——extract-vmlinux（已有雏形 `kernel/vmlinux.py`）、内核版 checksec
   （从 cpu flags + 版本推 KASLR/SMEP/SMAP/KPTI）、模块符号（`add-symbol-file`，
   运行时地址取 `/sys/module/<name>/sections/`）；
3. **知识层**——kernel pwn playbook skill + writeup 语料，随做随沉淀；
4. **评测**——BenchSpec 增 kernel target 类型，分级（无 SMEP ret2usr → ROP →
   KPTI → UAF/slab → cross-cache），判定 = 提权读 flag；exploit 可挂死 VM，
   必须 watchdog + 快照 revert。

**层① PoC 已端到端验证**（`tests/integration/run_kernel_smoke.py`，qemu 11.1 +
kali 7.1.5 内核）：

* `kernel/qemu_runner.py`：QEMU 命令组装（`-gdb tcp::N` + `-S` 冻结 + HMP unix
  monitor + `-no-reboot`）、常驻 keep-alive 启动器、`savevm/loadvm` 快照；
* 实验工具 `kernel_launch` / `kernel_snapshot`（`--experimental` 门控，
  CLI-only，无环境变量通路）；
* `kernel/vmlinux.py`：bzImage 内嵌压缩载荷探测/解压 + System.map 符号地址 +
  KASLR slide 计算（解压支持 gzip/xz/lzma，bzip2/lz4/zstd 显式报缺 CLI）。

**三件用真机换来的工程事实**（勿凭直觉推翻）：

1. **WSL 会回收"detached"进程**——启动 bash 退出后 QEMU 随实例一起死；启动器必须
   `wait $QPID` 常驻持有（它同时是 Windows 侧的句柄），且 stderr 要在 `&` 之前
   重定向（否则首条 stderr 写入触发 SIGPIPE）；
2. **子进程必须 `stdin=DEVNULL`**——常驻 wsl.exe 会继承并消费服务器的 MCP stdio
   流，之后所有请求静默饿死（最小复现：session_status 60s 无响应）；
3. **gdb 不刷新 loadvm 后的寄存器缓存**——savevm 时 stub 会发 stop 事件所以寄存器
   是真的；loadvm 后 gdb 仍回旧值，回滚验证要用 `monitor info registers`
   （HMP 才是仿真器的真值源；实模式保存点报 EIP 而非 RIP）。

另：kernel gdb 必须 `-nx`——pwndbg 的 vmmap 自动探索会在无映射的复位向量
（0xfff0）上卡死插件握手。KASLR slide 修正与模块符号属层②，层① 靶机以 `nokaslr`
起步。



## 6. 卫生（穿插进行，均小）

- H1 result-store GC（G1）；H2 插件 `gdb.execute(` 收敛到单一 `_exec()` 收口
  （G6——重命名需一次终端手工操作绕过钩子，此后插件演化不再触碰该行）；
  H3 FastMCP 内部依赖解耦（G4，自有工具注册表镜像）；H4 instructions 刷新（G5）；
  H5 动词一致性测试（G3）。

## 7. 落地顺序

```
第一批（快赢，1–2 周粒度）: H1 → H4/H5 → B1 → B3(MVP: journal→gdbscript)
第二批（差异化主攻）:       C2(oracle+指纹) → C1/C3 → C4
第三批（架构反转）:         A(trace→heap_timeline→fuzz_loop) ← 依赖 B2/2.4
第四批（协同与生态）:       D1 → E2 → E3 → D2 → E1 → E4
贯穿: 每个 theme 的验收标准写进 bench；rr(3.4) 作为 A 的 trace/reverse 特例回收
```

### 7.1 架构整备 ✅（2026-09-28，功能不变、632 单测 + WSL 真实 gdb 端到端全绿）

用户诉求：功能已完善，架构不尽如人意。审计后落地四批，全部为结构改造：

| 批次 | 内容 |
|---|---|
| **A 依赖注入与工具注册（修 G4）** | 新增 `context.ServerContext`（config/registry/analysis/launcher 唯一 DI 通道，经 lifespan 传递）；新增 `tools/registry.py`：工具改为**声明式** `@tool(core=, readonly_safe=, experimental=)`，注册表即单一真源——`CORE_TOOLS` 由声明推导、profile/readonly 在注册**前**过滤、观察者守卫在注册**前**包装（`functools.wraps` 保签名/异步性，实测 schema 零漂移）。删除全部 `app._registry/_config/_tool_manager._tools` 直改与 `tool.fn` 变异（`_tool_manager` 现仅存于 `registered_tools()` 一处只读视图）；60 个工具 handler 全部提升为模块级函数。新增 `test_tools::test_every_handler_is_declared`（防漏装饰器）+ 核心集契约断言 |
| **B 会话/启动/监听边界** | `Session.set_state()` 成为状态写入唯一入口（并唤醒等待者）、新增 `wait_for_state`/`first_to_settle`/`note_process_exit`/`attach_analysis`/`note_location`；launcher 三处 `sleep` 轮询握手改为事件等待、不再直写 `session.state/token/_wake_stop_waiters`；`plugin_token_for()` 统一派生令牌照配（reserve 内部完成，消除"先给主令牌再补派生"的窗口）；保留插件环境变量名单由 7 项双份复制改为单一 `_RESERVED_PLUGIN_ENV` + `build_plugin_env()`；新增 `wsl.py` 收口 WSL 路径/发行版探测（修 reverse→launcher 反向依赖，GhidraRunner 的 `wsl.exe -l` 补上缺失超时）；`tcp_listener` 握手对"陌生 session_id 回落主令牌"显式告警 |
| **C 插件内部治理（保持单文件可 source 部署）** | 抽出 `_resume()` 为唯一续跑原语，policy 循环不再用伪造 `id:0` 走线协议（新增断言：策略期间不得出现任何非法 id 响应）；`_io_seq/_io_buf` pty 线程与主线程共享状态加锁；`posted` 泵标志加锁；事件处理器连接失败从静默改为 gdb 控制台告警（否则服务端只会无限等 stop）；`_memory_segment()` 消除 read_mem 双份构造、`_drop_breakpoint()` 消除 4 处临时断点删除样板、删除只写不读的 `server_capabilities`；新增 `tests/test_plugin_parity.py` + `test_security::TestPluginCopyAgrees` 交叉校验插件刻意的 stdlib 复制（ANSI/hex/安全名单/段结构）与 `test_protocol` 的动词表交叉校验 |
| **D 静态桥拆分** | `reverse/manager.py`（964 行上帝类）拆为 `reverse/store.py:AnalysisStore`（记录/清单/原子提升+崩溃恢复/索引校验/索引与函数与反汇编与注记缓存）+ `manager.py`（分析队列、会话跟随、运行期→静态定位、查询门面）。锁纪律收敛：`_lock` 只护内存映射、`_promote_lock` 只护目录换名、`annotation_lock` 串行读改写，**持锁不再做磁盘 IO**；后台任务统一 `_spawn()` 持引用并记异常（原 `create_task` 即发即忘 + `suppress(Exception)` 吞掉全部协调器故障）；manager 不再向 Session 散写私有字段，改调 `attach_analysis/note_location`（并删除只读不写的 `Session.target`）；新增 `tests/test_reverse_store.py`（13 项：提升/注记存活/缓存失效/备份恢复/路径大小写语义/损坏拒绝）与 `tests/test_architecture.py`（9 项分层与 MCP 边界守卫，把本轮修掉的方向性缺陷变成机制化回归） |

### 7.2 完整性 / 可用性复审 ✅（2026-09-28 第二轮，实机驱动）

上一轮只跑了单测 + stdio 端到端。这一轮把**每一条对外承诺的路径**都实机跑了一遍，
方法学是：能用真实进程验证的，绝不用 mock 验证；结论与预期不符时先取数据再下判断。

| # | 发现 | 归因 | 处置 |
|---|---|---|---|
| 1 | 未配置 token 的服务器上，每次正常启动的插件 hello 都被记 `hello claims unknown session ...; accepting as external plugin` | **本轮引入**：判断"是否已知会话"误用了 `token_for()`——无 token 时保留会话的 token 恰为 `None` | 新增 `SessionRegistry.has_session()` 作存在性判据；补 2 条回归测试，其中一条**先证明在错误判断下会失败**再修好 |
| 2 | 6 处 bench 参考解 `settle(..., {"stopped"})`，而插件 stop 通知后紧跟 prompt，轮询方几乎只可能观测到 `ready` | 既有；且 `common.py` 自己的注释已写明"同步不得依赖捕捉该瞬态" | 按该文档化规则引入 `STOP_STATES={stopped,ready}`；实测 interrupt 任务 16.3s → **1.6s**，lifecycle/breakpoints/inspect 各 72/72 仍全绿。**这条同时掩盖"根本没停住"的失败**（超时后检查读 stop_info 照样通过），属验收质量缺陷而非仅性能 |
| 3 | `ruff check src tests bench`（CI 的一步）在 main 上就是红的：8 项 | 既有 | 全清。其中 `inspect.py` 的 `F821 token_raw` 是**真 bug**：rdi 不可读时验证器抛 `NameError` 而非 `VerifyError`，把可诊断失败变成崩溃 |
| 4 | 文档里的 `docker build -f docker/Dockerfile -t gdb-mcp:latest .` **必然失败**：`COPY gdb_mcp_plugin.py` 指向仓库根不存在的路径（插件在 `src/gdb_mcp/plugin/`） | 既有（路径迁移后配方未跟） | 修正 COPY 源；新增 2 条配方守卫测试（断言每个 COPY 源存在、且挂载路径与镜像内路径一致），并**验证过还原那行后测试即失败** |
| 5 | docker 后端下插件没有可靠途径回连宿主：候选 host 只有 `127.0.0.1`/默认网关/resolv.conf，而 Docker Desktop 的 NAT 网关是 VM 不是宿主 | 既有 | 候选列表末尾追加 `host.docker.internal`（解析失败只是一个被跳过的候选，`_connect_once` 逐候选吞 `OSError`）；两个 README 的启动后端表补写明要求 |
| 6 | `Config(log_dir="/tmp/x")` 构造成功，却在 `ensure_dirs()` 里抛 `AttributeError: 'str' object has no attribute 'mkdir'` | 既有 | `__post_init__` 按注解强制转 `Path`（log_dir/analysis_dir/archive_dir）+ 2 条测试 |
| 7 | CI 只跑 9 套真实套件里的 1 套；**观察者工具门控**（上一轮恰好改了它的位置）零端到端覆盖 | 既有 | 新增 `tests/integration/run_observer_smoke.py`：真实 MCP-over-HTTP 客户端，8 项断言（两角色工具面一致、白名单工具放行、write_memory/execute_command/continue_execution 对观察者拒绝、controller 能进 handler、**观察者白名单不得含已改名/消失的工具**）。README ×2 与 `scripts/dev_manual_check.md` 补齐完整验证矩阵 |
| 9 | **跑一次文档里的验收命令，`git status` 就多出 576 个"已修改"文件**：`core.autocrlf=true` 下任务清单被检出成 CRLF，而 bench 写回 LF，于是每个清单都变成"行尾差异"（内容哈希与 HEAD 完全相同，`git diff` 为空却仍标 M）。任何人跑 bench 都可能顺手提交这 576 个幻影改动 | 既有（Windows 开发 + 无 .gitattributes） | 新增 `.gitattributes`：`bench/tasks/**/* text eol=lf`（+ `bench/reports/*.json`），检出与写入端统一为 LF；**实测**：加属性前一次 LF 重写即标脏，加属性后同样的重写 `git status` 保持 0 项。已用 `git add --renormalize` 让既有索引条目就位（相对 HEAD 零暂存差异） |
| 10 | **`GDB_MCP_READONLY=1` 被静默忽略**：真实服务器仍注册 52 个工具（含 `write_memory`/`write_register`）；同类地 `GDB_MCP_MCP_HTTP=1`、`GDB_MCP_ALLOW_UNSAFE=1`、`GDB_MCP_OBSERVER_TOKENS=...` 全部失效 | 既有（**安全相关**）：`argparse` 的 `store_true` 默认 `False`、`append` 默认 `[]` 被 `main()` 当成"用户显式设置"合并进由环境构建的 Config，把真值覆成假值；`Config.from_env` 本身是对的，`--help` 与 README 都承诺这些环境变量可用 | `__main__._overrides()` 显式化并把 6 个布尔/列表旗标默认改为 `None`（区分"没传"与"传了 false"）；`--no-mcp` 取反仅在显式传入时生效；抽出 `_overrides()` 便于测试，新增 5 项优先级回归（含"env 的 readonly 必须真的把写工具摘掉"这条打到工具面的断言）。**实测**：修复后 `GDB_MCP_READONLY=1` → 50 个工具、两个写工具消失；`--experimental` 仍无法用环境变量打开（刻意保持）；TLS/观察者/工具端到端三套实机重跑全绿 |

| 8 | README 工具目录写"37 core tools"，默认实际注册 52；**整个静态桥 15 工具族与 kernel 两件没进目录表** | 既有 | 两个语言的目录与实验性小节均已更正（52 默认可见 / core 档 12 / `--experimental` 共 60） |

实机复验通过、无需改动的项：`uvicorn`/`httpx` 由 `mcp` 传递依赖满足（`--http`、libc 识别开箱可用，不必额外声明）；`native` 后端端到端可用（crash_report 正确拿到 SIGSEGV + PC）；stress 8 会话 224 调用 100%；faults 4/4 恢复且无污染；perf 开销 p50/p95/p99 = 0.6/0.9/1.3ms（基线 0.7/1.1/1.5，**上一轮重构无性能回归**）；pwndbg 探针 6/6；WSL 协议集成 + io smoke + 31 工具端到端在插件改动后重跑仍全绿。

仍未验证（诚实标注）：docker 后端的**运行时**路径（镜像构建受限于本机网络，apt 阶段耗时过长；本轮只把"构建命令必失败"这一确定缺陷修掉并加了配方守卫）；`ssh` 后端需远端主机。

未做（诚实标注）：policy 动词族仍无真实 gdb 端到端覆盖（e2e 走查 31 工具、bench selfcheck 均不触发 `run_policy`；本轮由 mock_gdb 单测保证行为不变，`continue` 路径本身已实机验证）；G6/G7 未触碰；`Session` 仍保留 reverse 侧字段（已改为方法写入，未迁出）。

### 第一批落地状态 ✅（2026-09-17）

| 项 | 状态 |
|---|---|
| H1 结果存储 GC | ✅ `prune_results`（默认 500 文件上限，store 时自动裁剪） |
| H4 instructions 刷新 | ✅ 覆盖 one-call/pwn 工作流/export |
| H5 动词一致性 | ✅ `test_plugin_verb_table_matches_protocol`：两表相等 + GATED ⊆ 同步动词 |
| B1 会话持久化 | ✅ `enable_persistence`/`save`/`load`：sessions.json 原子写、重启恢复为 DISCONNECTED、re-hello 复活同一身份；script 会话不入库；损坏文件容忍 |
| B3 MVP | ✅ Journal（JSONL，trim/hex 标记）+ `export_session_script`（break 条件/auto_continue 探针/set_reg/≤256B 逐字节写/continue 族编译；纯读与 checkpoint 跳过并计数）。**脚本对真实 gdb 的独立重放验证曾由 E3 bench 承担（该 harness 已于 2026-09-22 移除）** |
| H2 插件 `_exec()` 收口 | ✅ 全部 `gdb.execute` 调用点已收口；仅存 `_exec` 本体与文档化例外 `_gdb_version()`（模块级、加载期一次） |

### 第二、三批落地状态 ✅（2026-09-18）

| 项 | 状态 |
|---|---|
| C2 cyclic oracle | ✅ `campaign.py`：pwntools 兼容 de Bruijn（缓存生成）+ LE 匹配 + `campaign(detect)`（扫 stop 的 pc/fault/寄存器，命中记 pc_control 候选）+ `campaign(pattern)` 模式生成 |
| C2 libc 指纹 | ✅ 最小形态：泄漏以 section=libc 记录（值+证据时间戳）；外部 libc-database 比对属 E3 配套，未做 |
| C1/C3 战役状态机 | ✅ Session.campaign（持久化含于 sessions.json）；`campaign` 工具 get/set/note/detect/pattern；stop_context 与 crash_report 自动注入恒定 brief |
| C4 Resources | ✅ MCP Resource 模板 `gdb://campaign/{session_id}`（只读 JSON 视图） |
| A 委托执行 | ✅ 插件 `policy` 动词（GATED）：`trace`（有界单步、去重 PC、含起始 PC）、`heap_arm/read/disarm`（`gdb.Breakpoint.stop()` 探针记录参数、自动续跑不打断执行流）、`fuzz_loop`（snapshot 恢复 + payload 写入 + 临时断点保证停机 + 信号+PC 去重崩溃）；工具层 `run_policy` |
| D1 diff_sessions | ✅ 跨会话寄存器差分 + 可选单内存区域差分（16 字节行，上限 128） |
| 2.4 inferior I/O | ✅ 已在实验分支 exp/inferior-io 实现并合入（pty 通道 + io_setup/send/read/teardown，`--experimental` 启动参数门控，刻意无环境变量通路）；fuzz_loop 从此可全自动 |
| A 补充：minimize/crash_check | ✅ exp/crash-minimizer 合入：delta debugging（信号一致性防漂移）复用 _fuzz_round |
| A 补充：bp_stats | ✅（2026-09-21）断点命中统计探针：locations 计数探针（自动续跑）+ stop_location 临时标记；按命中预算/趟数/ inferior 自停收尾，返回每位置命中数——断点命中统计的长跑版 |
| E2 PyPI 发布 | ❌ 取消（用户决策 2026-09-18：不做 PyPI 发布） |
| E3 bench | 🗑 已移除（2026-09-22 用户决策"彻底删除测试 Harness"：bench/ 全目录 + src/gdb_mcp/bench.py（DeepSeek 客户端 + agent 循环）+ tests/test_bench.py；靶标与全部提交在 git 历史可恢复）。**移除前最终结论**：win.c 原靶标无解（argv/strcpy 不能携带 NUL，9 月"模型能力"结论系误判；v2 改 stdin 后自证可解）；deepseek-chat 解出 EASY（win，7 轮/22k）与 MEDIUM（fmt，14 轮/62k）——产品论题首批正样本；HARD（ret2libc）四战未破，瓶颈在策略组装而非观测缺失；flash 不适合工具循环（4/4 早弃） |
| E3 语料扩容 | 🗑 随 E3 harness 一并移除（2026-09-22）；三靶标（win/fmt/ret2libc，均带参考解自证）在 git 历史（提交 5f9abd22、178d328）中可恢复 |
| **E5 验收基准（E3 继任，M0-M6 全部落地 ✅ 2026-09-26）**：576 任务（8 族 × 72 种子，含 fact 型 inspect 族）参考解 576/576；`cli agent`（OpenAI 兼容 provider）已产出首份模型报告（deepseek-chat 18/48，bench/reports/）；stress/faults/perf/pwndbg 四个 harness 均经实机验证（开销 p50/p95/p99 = 0.7/1.1/1.5 ms、冷态外启动 1.1s、并发 100/100、12/12 故障恢复无污染、pwndbg 探针 6/6）；CI bench job 以 bench/reports/baseline.json 为 tier-1 门禁。experts traces（goal §2）仍延期（需真人数据）。 | `bench/` 永久版本化验收体系（`bench/SPEC.md` 为总纲，映射十项验收门槛）：① 确定性任务生成（7 任务族 × 种子：lifecycle/breakpoints/crash/threads/pie/optimize/multistep，含 O0–O3、PIE/-no-pie、无 DWARF cast-idiom、多线程、5–20 步状态机）；② ground truth 全部由 harness 对活动会话独立取证（`info breakpoints` 文本解析 + 运行时锚点算术 + 参数模拟 LCG），不采信 agent 自述；③ 参考解自证每个任务可解后才允许模型上场（win.c 教训制度化）；④ **selfcheck 42/42 通过**（WSL2 真实 gdb 17.2 + pwndbg 194 commands）。落地途中发现并修复 E4 令牌真 bug：`register_hello` 把已派生的会话令牌重置为主令牌，`_dispatch` 又只按主令牌解包——**带令牌启动的 gdb 会话从未真正通过消息层**，修复含回归测试（test_hello_keeps_scoped_token_of_launched_session）。下一步（M1+）：扩到 500+ 任务、fact 型任务（State Inspection）、模型 agent 循环（可插拔 provider）、压力/恢复/性能 harness、pwndbg 兼容套件、CI 回归门禁 |
| B4 会话工作目录归档 | ✅（2026-09-21）gc/kill 关闭会话时 journal+启动日志归档到 `<archive_dir>/<sid>/`（含 meta.json），保留最近 `--archive-retention` N 个（默认 20，0 关闭）——长期运行不再泄漏磁盘 |
| D3 crash→debug 流水线 | ✅（2026-09-21）`triage_crash` 工具：fuzz_loop 崩溃 payload → checkpoint 重放验证 → 完整 crash_report →（可选）minimize → 结果落盘 evidence + campaign note。设计原文"新 debug 会话"以 checkpoint 恢复的干净进程镜像实现：与独立 OS 会话同样确定性，且内存写入型 payload 无法经 stdin 重放，checkpoint 重放是唯一正确通路 |
| 3.4 时间旅行 | 🟡 exp/native-record 已合入：gdb 原生 record/reverse_*（零依赖，WSL2 可用；rr 因 PMU 不可用而放弃）。`continue_execution(mode="reverse_*")` + `execute_command('record full')` |
| D2 会话多路（观察者） | ✅ 已合入：observer bearer token（`--observer-token`/env）经 HTTP 中间件派生 per-request 角色；allowlist 外的工具对观察者抛 OBSERVER_READONLY（default-deny）；controller 不受影响；stdio 单角色。发现并修复 http_hardening 与 roles 的同名双 ContextVar（会使门控失效） |
| E1 协议 v2 | ✅ 已合入：hello_ack 广播 SERVER_CAPABILITIES（additive、v1 兼容）；插件 hello 携带动词全集，服务端握手期 PROTOCOL_MISMATCH 快速失败（修 G3 运行时漂移）；插件记录能力供 mcp status |
| E4 mTLS + scoped token | ✅ 已合入：TLS/双向 TLS（cert/key/client_ca + config 校验）；launch 的 gdb 只持有会话级派生令牌（HMAC-SHA256(master,'session:id')），主令牌不出服务进程；重启重算即恢复握手。HTTP mTLS 端到端 ✅（2026-09-22）`tests/integration/run_tls_smoke.sh`：一次性自签 PKI 实测四组合——明文基线 / TLS（明文与无 CA 信任均被拒）/ mTLS（无客户端证书握手被拒）/ mTLS+token（无/错 bearer 403，observer 与 controller 放行）；Git Bash 与 WSL 双兼容（客户端侧用 python ssl，绕开 mingw curl 的 schannel 不支持 PEM 客户端证书与强制吊销检查） |
| 3.5 静态桥 | ✅ 已合入：从 archive/reverse-tools-dashboard 复活 Ghidra headless 管线（GhidraRunner + AnalysisManager + ExportAnalysis.java + EventBroker），剥离 dashboard/web 耦合；16 个 static_* 查询工具（分析缓存按 SHA-256、sections/symbols/functions/strings/decompile/xrefs/callgraph/代码搜索/注记）；会话最小归档字段（analysis_id/location/target/debug_state）。GhidraRunner 端到端需本机 Ghidra（诚实标注未测）；manager 逻辑由 428 行复活的测试套件覆盖 |
| 实验分支（合入后保留开关） | ✅ exp/inferior-io、exp/crash-minimizer、exp/libc-rop、exp/native-record 四分支全部按序合入 main；libc 识别（C2 的 libc-database 部分以 libc.rip API 形态先行落地） |
| D5 实时看板 | 🗑 已移除（2026-09-22 用户决策：Web 看板整体删除。移除范围：src/gdb_mcp/web.py（DashboardServer：loopback HTTP + SSE）/ web_static/ 前端 / docs/dashboard-design.md / tests/test_dashboard.py + tests/dashboard_demo.py / config 三字段 + `--dashboard*` CLI 旗标；`--dashboard` CLI-only 门控与 loopback 硬约束的安全设计随代码一并消失。保留：共享 EventBroker 与 session 生命周期/请求事件发布——静态桥 AnalysisManager 依赖它跟踪会话，非看板专属）。全部代码在 git 历史可恢复。移除前形态：三阶段完整落地（数据层 SSE API + 无依赖原生 JS 前端 + 深度视图/journal 尾随），端到端验收与浏览器视觉评审均通过 |

## 8. 反目标（延续并强化）

1. 不内嵌 LLM（分析质量归客户端 agent）。
2. policy 不做成任意代码执行——只允许枚举内的参数化模板（安全边界不破）。
3. 不抢 pwntools 的进程 I/O 主权（fuzz_loop 走 inferior I/O 可选通道）。
4. 不做"看起来能用"的未验证功能——凡涉真实环境（rr/Ghidra/docker 端到端），
   保持"延期并写明设计"的纪律。

## 9. 外部评审采纳清单（2026-09-29，Claude 架构级评审）

评审基于 README 公开面（未读源码），按 P0→P2 分层给出建议。逐条核实后的
处置如下——其中多项经源码核对**已经落地**，部分与既有设计决策冲突而拒绝
（附理由），其余纳入路线图或本轮直接实现。

### 9.1 本轮直接落地（2026-09-29，765 单测全绿）

| 评审建议 | 处置 |
|---|---|
| P0 协议层健壮性测试（畸形/截断 JSON-lines） | ✅ `tests/test_protocol_fuzz.py`：种子化随机/变异模糊测试打 `LineReader`/`parse_line`/`unwrap_token`/validate 族、活体 listener、插件 `_dispatch_line`。**过程中发现并修复真 bug**：深嵌套 JSON 触发 `RecursionError` 穿透 `parse_line`（只 catch `JSONDecodeError`），在服务端会绕过 `except ProtocolError` 拆掉整个会话而非拒绝该行；插件侧同步加固 |
| P0 gdb 版本兼容矩阵 | ✅ CI `gdb-integration` 改为 matrix：ubuntu-22.04（gdb 12.1）+ ubuntu-24.04（gdb 15.x）跑真实 gdb 集成套件（未本地验证，待 push 后首跑）；本地 WSL2 gdb 17.2 全套继续覆盖。插件内的版本回退本来就集中在少数探测点（`_gdb_version` 回退、`qualified` 断点参数、`gdb.interrupt` ≥15、`blocked_signals` 特性探测），刻意不做独立 compat.py——插件保持 stdlib-only 单文件可 `-x` 部署是更硬的约束 |
| 架构4 journal 显式版本化 | ✅ journal 新文件写 `meta` 首行携带 `SCHEMA_VERSION`，`migrate_entries()` 显式迁移骨架；未知新版本不加载进镜像（语义不明不得进脚本编译）但文件保持可追加；`sessions.json` 的 `version` 字段从被忽略改为显式校验（未知版本拒绝恢复） |
| 安全2 审计日志与 journal 分离 | ✅ 新增 `audit.py`：SHA-256 哈希链 append-only JSONL（`<log_dir>/audit.log`），`verify_log()` 可独立校验完整性；接线五类事件：握手/握手拒绝（含 token 失配）、握手后协议违规、HTTP 403、观察者越权、UNSAFE 命令拦截。默认开启，`--no-audit-log`/`GDB_MCP_AUDIT_LOG=0` 关闭 |
| 架构2 并发语义显式化 | ✅ 文档化（README 双语"并发语义"节）：单会话严格串行 + per-request 超时 + `INFERIOR_RUNNING` 快速失败。评审建议的"busy 状态返回"实际上已存在——忙会话的第二调用排队等待而非挂死，执行类动词对运行中 inferior 立即报 `INFERIOR_RUNNING` |
| 文档/生态（客户端片段、capability 图、版本矩阵） | ✅ README 双语补齐：Claude Code/Cursor/Codex CLI 配置片段、core/pwn/static/kernel capability 分层说明、已验证 gdb 版本表 |
| 安全3 token TTL | ⚖️ 有意拒绝并文档化（README"关于 token 有效期"）：会话 token 是主 token 的无状态 HMAC 派生，重启免状态重新验证正是设计目标，单独过期与之矛盾；补偿设计=主 token 不出进程 + 按会话隔离 + HTTP 走可吊销的 mTLS + 换主 token 重启即可 |

### 9.2 核实后确认已落地（评审时 README 未体现）

| 评审建议 | 现状 |
|---|---|
| 架构5 Ghidra 分析硬超时/取消 | 已有：`analysis_timeout`（默认 900s）双重保障——命令行 `timeout --kill-after` + Python 侧 `asyncio.wait_for` + `proc.kill()`；`decompile_timeout` 同理 |
| 架构3 core/pwn/static/kernel 解耦 | 已有等价物：工具按模块分层 + 声明式 `@tool(core=)` 注册表推导 `CORE_TOOLS`；`GDB_MCP_TOOL_PROFILE=core` 即最小档。README 本轮补写映射 |
| 多客户端 controller 互踩 | 已有：server 端 per-session lock 串行化 + 插件单队列单线程 marshal，天然互斥 |

### 9.3 纳入路线图（按价值排序）

1. **ROP 链构造**（评审 P1）：`build_rop_chain(goal, constraints)` ——在
   `search_gadgets`（已合入）之上做 pwntools ROP 对象式封装，返回候选链 +
   gadget 来源地址。这是"辅助分析"到"辅助产出利用链"的跃迁，也是与纯静态
   MCP 的最大差异点。
2. **angr 符号执行桥**（评审 P2 但差异化价值高）：仿 Ghidra 桥形态（独立
   进程 + 结果缓存 + 超时保护），`find_path_to_address` /
   `solve_constraints_for_branch`，把 crash_report 的 backtrace 转成"输入该
   怎么构造"。
3. **外部 fuzzer 语料对接**：`import_corpus(dir)` → `triage_batch()` 批量
   喂给现有 triage_crash 流水线（AFL++/libFuzzer crash 目录直接进 gdb
   分诊）——比扩张内建 fuzz_loop 的 ROI 高。
4. **多 agent 会话所有权**：显式 `session.lock(reason)/release()` 或租约
   语义，为 orchestrator + 子 agent 协作铺路（当前 controller 串行化已防
   互踩，缺的是"协商所有权"）。
5. **多架构 bench**：ARM(32/64)/MIPS 任务族进 bench（kernel_launch 已支持
   QEMU，heap_bins/cyclic 跨架构稳定性待验收）。
6. **供应链**：锁定已验证依赖版本区间文档（pwndbg/Ghidra/ROPgadget）+
   发布 SBOM。
7. **多模型 leaderboard**：bench `cli agent` 已可插拔 provider（deepseek
   首报已提交），定期多模型跑分发布——差异化营销 + 反向发现"agent 用不
   明白"的工具设计问题。

### 9.4 拒绝项及理由

| 建议 | 理由 |
|---|---|
| rr 集成（GDB_MCP_LAUNCHER=rr + 反向 watchpoint 工具） | rr 已于 3.4 评估并放弃：WSL2 下 PMU 不可用（真机验证）；gdb 原生 `record full` + `reverse_*` 已合入（`continue_execution(mode="reverse_*")`），零依赖覆盖同一场景。rr 待 WSL PMU 成熟或原生 Linux 主力场景出现再议 |
| MCP Registry 提交 / GitHub topics | 外发动作待用户决策（PyPI 发布已于 2026-09-18 由用户取消，registry 同属发布面）；仓库内文档与客户端片段已备齐，提交随时可做 |
| Docker 后端默认 seccomp 白名单 | 方向认同，但 docker 运行时路径本身尚未端到端验证（§7.2 诚实标注）；与 docker 后端实机验证一并做，避免"看起来能用"的未验证配置 |
| session token TTL | 见 9.1——与无状态派生设计冲突，已文档化替代缓解 |
