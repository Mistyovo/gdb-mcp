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
| G4 | **FastMCP 私有内部依赖**：`app._registry/_config/_tool_manager._tools` 三处 | `server.py` / `tools/__init__.py` | mcp 库升级即碎 |
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
| B4 会话工作目录归档 | ✅（2026-09-21）gc/kill 关闭会话时 journal+启动日志归档到 `<archive_dir>/<sid>/`（含 meta.json），保留最近 `--archive-retention` N 个（默认 20，0 关闭）——长期运行不再泄漏磁盘 |
| D3 crash→debug 流水线 | ✅（2026-09-21）`triage_crash` 工具：fuzz_loop 崩溃 payload → checkpoint 重放验证 → 完整 crash_report →（可选）minimize → 结果落盘 evidence + campaign note。设计原文"新 debug 会话"以 checkpoint 恢复的干净进程镜像实现：与独立 OS 会话同样确定性，且内存写入型 payload 无法经 stdin 重放，checkpoint 重放是唯一正确通路 |
| 3.4 时间旅行 | 🟡 exp/native-record 已合入：gdb 原生 record/reverse_*（零依赖，WSL2 可用；rr 因 PMU 不可用而放弃）。`continue_execution(mode="reverse_*")` + `execute_command('record full')` |
| D2 会话多路（观察者） | ✅ 已合入：observer bearer token（`--observer-token`/env）经 HTTP 中间件派生 per-request 角色；allowlist 外的工具对观察者抛 OBSERVER_READONLY（default-deny）；controller 不受影响；stdio 单角色。发现并修复 http_hardening 与 roles 的同名双 ContextVar（会使门控失效） |
| E1 协议 v2 | ✅ 已合入：hello_ack 广播 SERVER_CAPABILITIES（additive、v1 兼容）；插件 hello 携带动词全集，服务端握手期 PROTOCOL_MISMATCH 快速失败（修 G3 运行时漂移）；插件记录能力供 mcp status |
| E4 mTLS + scoped token | ✅ 已合入：TLS/双向 TLS（cert/key/client_ca + config 校验）；launch 的 gdb 只持有会话级派生令牌（HMAC-SHA256(master,'session:id')），主令牌不出服务进程；重启重算即恢复握手。HTTP mTLS 端到端 ✅（2026-09-22）`tests/integration/run_tls_smoke.sh`：一次性自签 PKI 实测四组合——明文基线 / TLS（明文与无 CA 信任均被拒）/ mTLS（无客户端证书握手被拒）/ mTLS+token（无/错 bearer 403，observer 与 controller 放行）；Git Bash 与 WSL 双兼容（客户端侧用 python ssl，绕开 mingw curl 的 schannel 不支持 PEM 客户端证书与强制吊销检查） |
| 3.5 静态桥 | ✅ 已合入：从 archive/reverse-tools-dashboard 复活 Ghidra headless 管线（GhidraRunner + AnalysisManager + ExportAnalysis.java + EventBroker），剥离 dashboard/web 耦合；16 个 static_* 查询工具（分析缓存按 SHA-256、sections/symbols/functions/strings/decompile/xrefs/callgraph/代码搜索/注记）；会话最小归档字段（analysis_id/location/target/debug_state）。GhidraRunner 端到端需本机 Ghidra（诚实标注未测）；manager 逻辑由 428 行复活的测试套件覆盖 |
| 实验分支（合入后保留开关） | ✅ exp/inferior-io、exp/crash-minimizer、exp/libc-rop、exp/native-record 四分支全部按序合入 main；libc 识别（C2 的 libc-database 部分以 libc.rip API 形态先行落地） |
| D5 实时看板 Phase 1（数据层） | ✅（2026-09-21）设计 docs/dashboard-design.md；session 生命周期 + 请求执行全量接入共享 EventBroker（`session.updated` 内嵌最新快照、`session.request` 只带 verb/时长/成败——params/results 刻意不入流）；只读 API `/api/v1/{health,snapshot,events}`（SSE，starlette+uvicorn 零新增依赖；复用 http_hardening Host/Origin 校验 + 硬化响应头）；`--dashboard` CLI-only 门控（无 env 通路，同 --experimental 纪律）+ loopback 硬约束；tests/dashboard_demo.py 端到端验收通过（双会话状态正确、SSE 实时流）。顺带修复 main 既有启动崩溃：默认 `analysis_dir=None` 时 AnalysisManager 初始化 AttributeError（裸启动必崩）。Phase 2 前端待做 |
| D5 实时看板 Phase 2（前端） | ✅（2026-09-22）`web_static/` 无构建无依赖原生 JS：session 卡片（状态徽章/快照增补字段）+ SSE 实时时间线；seq 断档/resync 回拉快照、5s 轮询补增补字段；DOM 全 textContent 构建（注入安全 + 严格 CSP 可满足）；静态路由固定名字（无穿越面），CSP 放宽至 self。浏览器实测：双会话卡片实时增删、9 帧事件按序入线、视觉评审无渲染缺陷 |
| D5 实时看板 Phase 3（深度视图） | ✅（2026-09-22）`GET /api/v1/sessions/{sid}`（stop 全量 payload + 事件环 + campaign 摘要/protections/counts）与 `.../journal?last=N`（journal 镜像尾随，默认 30 钳制 500；bp_stats 等策略结果经 request 条目天然覆盖，不做专用解析器）；未知 sid → 404。前端卡片可展开四分区详情（展开态跨事件重渲染保留、异步填充代际守卫防竞态）；时间线空态提示。浏览器实测展开交互 + 视觉评审通过 |

## 8. 反目标（延续并强化）

1. 不内嵌 LLM（分析质量归客户端 agent）。
2. policy 不做成任意代码执行——只允许枚举内的参数化模板（安全边界不破）。
3. 不抢 pwntools 的进程 I/O 主权（fuzz_loop 走 inferior I/O 可选通道）。
4. 不做"看起来能用"的未验证功能——凡涉真实环境（rr/Ghidra/docker 端到端），
   保持"延期并写明设计"的纪律。
