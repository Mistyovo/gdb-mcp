# 11 — heap 时间线补齐分配身份与 chunk 视图

Status: resolved
Type: task
Priority: P0
Area: pwn workflow / heap
Depends on: —

## 问题

`run_policy(kind="heap_arm")` 的 `_TimelineBreakpoint` 只在函数**入口**记录参数
（rdi/rsi/...）然后自动续跑。对堆利用来说这不够：

- 不知道 malloc/calloc/realloc **返回了哪个指针**；
- 无法把一次 free 的指针与之前的分配对应起来；
- 没有 tcache/fastbin 的 bin 迁移视图；
- 没有结构化的 `heap_chunk(addr)`（size/prev_size/fd/bk/tcache key）。

结果是“heap timeline”只能看到分配大小和调用点，不能支撑 tcache poisoning、
double-free、UAF 这类主流堆利用分析。

## 任务

1. **分配返回指针**：在 `_TimelineBreakpoint` 之上增加返回捕获：
   - 用 `gdb.FinishBreakpoint`（或 break 在调用者返回点）记录 `ret`；
   - 事件结构扩展为 `{symbol, caller, args, ret, size}`；
   - free/realloc 记录入参 `ptr`；realloc 同时记录新旧指针；
   - 预算沿用 `max_events`，避免无限增长。
2. **bin 迁移**：在分配/释放事件后按需采样 pwndbg `bins`（可选开关，避免每次
   命中都跑昂贵命令），记录 tcache/fastbin 的 size→ptrs 快照。
3. **`heap_chunk(addr)` 工具**：解析一个 chunk 头，返回：
   `addr`、`size`、`prev_size`、`in_use`、`fd`、`bk`、`tcache_key`（x86_64 glibc），
   并标注是否可读/是否属于 tcache。无 pwndbg 时用直接内存读取 + 结构解析。
4. 文档：`run_policy` 的 `heap_arm` 说明从“记录参数”改为“记录分配/释放的
   ptr/size/caller”。

## 验收

- 一个包含 malloc/free/realloc 的样例程序，timeline 能给出：
  `malloc(size=0x20, caller=X, ret=0x...)`、`free(ptr=0x...)`、realloc 新旧指针；
- `heap_chunk(0x...)` 返回上述字段，错误地址有清晰错误；
- 单测（mock gdb 对象）+ 真机 smoke（pwndbg 与无 pwndbg 两种）；
- 事件上限、JSON 大小、响应 token 仍受控。

## 参考

- `src/gdb_mcp/plugin/gdb_mcp_plugin.py::_TimelineBreakpoint`、`_policy_heap_arm`
- `src/gdb_mcp/tools/heap_tools.py::run_policy`、`heap_bins`
- `src/gdb_mcp/output.py::parse_pwndbg_bins`

## Resolution（2026-11-23）

已落地：

1. **分配返回指针**：`_TimelineBreakpoint` 新增 `capture_return`；对
   malloc/calloc/realloc（及 `operator new` 等）在入口记录后创建
   `gdb.FinishBreakpoint` 返回探针。真机验证发现 libc malloc 的断点命中
   inline frame（`checked_request2size`，gdb 18.1），而 gdb 拒绝在 inline
   frame 上建 FinishBreakpoint——探针改为沿 `older()` 找到外层普通帧再创建。
   没有走“返回地址临时断点”方案：该方案在 gdb 18.1 上触发过 gdb 内部段错误。
2. **命名参数**：事件在原始 `args` 之外增加 `named`（`size`/`ptr`/`nmemb`/
   `alignment`），支持 `malloc`/`calloc`/`realloc`/`free`/`aligned_alloc`/
   `memalign`/`valloc`/`pvalloc`/`operator new`，并识别 libc 内部别名
   （`__libc_*`、`__GI___libc_*`）。
3. **`heap_chunk` 工具**：纯解析器 `src/gdb_mcp/heap.py` + 只读 MCP 工具；
   返回 size/flags/prev_size/usable_size、下一 chunk 的 PREV_INUSE（即本 chunk
   的 in_use）、free chunk 的 fd/bk、tcache next/key 与 safe-linking 解码后的
   next，以及用户数据预览；无需 pwndbg。
4. **测试**：`tests/test_heap.py`（8 项）、`tests/test_plugin_verbs.py`（6 项
   mock gdb）、`tests/test_tools.py`（4 项工具层）；新增
   `tests/integration/run_heap_smoke.sh`，在真实 gdb 上验证
   malloc/calloc/realloc 的 `ret`、free 的 `named.ptr` 与 realloc 返回值一致，
   并已分别以无 pwndbg 与带 pwndbg 两种模式跑通（gdb 18.1）。CI 的
   `gdb-integration` 矩阵已加入该 smoke。
5. **文档**：README/README.zh-CN 工具表、计数、测试命令；AGENTS.md 的
   “验证事实”段记录 inline frame 事实。

未做（原任务 2 的“可选”部分）：在每次分配/释放事件后按需采样 pwndbg `bins`
形成 bin 迁移快照。当前 `heap_chunk` 已能直接解码单个 tcache chunk 的
next/key；若需要完整 bin 时间线，另开 issue。事件上限、JSON 大小、响应
token 仍受 `max_events` / `POLICY_TIMELINE_READ` 控制。

