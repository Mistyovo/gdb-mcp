# Session Dashboard 设计（Phase 1：数据层 + 只读 API）

日期：2026-09-21 · 状态：已实施（Phase 1）
关联：`archive/reverse-tools-dashboard` 归档分支（前身）、ROADMAP_V2「D5 实时看板」

## 1. 问题

gdb-mcp 接入 Agent 后不可观测：Agent 通过 MCP 驱动多个 gdb session，
人类无法回答"现在有哪些 session？各自什么状态？正在执行什么？哪个卡住了？"。

## 2. 目标 / 非目标

**目标（Phase 1）**
- session 生命周期与请求执行的全部状态变化以事件形式流出（进程内 EventBroker）。
- 只读 HTTP API：全量快照 + SSE 增量事件流。
- 端到端可验收：`--dashboard` 启动 + `tests/dashboard_demo.py` 模拟插件 + curl 验证。

**非目标（后续 Phase）**
- 前端页面（Phase 2，消费同一 API——本 API 即稳定性边界）。
- 交互动作（POST 断点/continue 等，归档版有，刻意延后）。
- journal 全文浏览、bp_stats 等深度视图（Phase 3）。

## 3. 数据契约

### 3.1 快照 `GET /api/v1/snapshot`

```json
{
  "sequence": 42,                      // broker 全局事件序号（单调递增）
  "sessions": [ /* SessionView，见下 */ ],
  "dashboard": { "enabled": true, "running": true, "url": "http://127.0.0.1:3940",
                 "error": null, "read_only": true, "event_sequence": 42 }
}
```

`SessionView = Session.info()`（session_id/kind/state/gdb_pid/inferior/arch/
gdb_version/pwndbg/log_file/distro/launched/proc_running/proc_returncode/last_stop）
**外加看板专属字段**（刻意不进 `info()`——`list_sessions` 是给模型看的，必须保持紧凑）：

| 字段 | 类型 | 含义 |
|---|---|---|
| `pending_requests` | int | 在途 plugin 请求数（>0 且不回落 ⇒ 疑似卡住） |
| `age_sec` | float | session 存活时长 |
| `last_event` | dict\|null | 事件环最后一条（"刚发生了什么"一跳可得） |
| `journal_entries` | int | journal 条目数（会话忙闲程度） |

### 3.2 事件（SSE `GET /api/v1/events`，每条 `data:` 一行 JSON）

沿用归档版"单一事件类型内嵌最新快照"的设计（前端无需二次取数）：

| type | 触发点 | data 关键字段 |
|---|---|---|
| `session.updated` | reserved / connected / 各通知（running/stop/exited/prompt/ready）/ disconnected / removed | `session_id`, `event`, `payload`, `session`（= info() 快照） |
| `session.request` | `Session.request()` 进入/退出 | `session_id`, `verb`, `phase`(started/finished), `ok`, `error`?, `duration_ms`? |
| `analysis.updated` | AnalysisManager（既有） | 复用共享 broker 后自然汇入同一流 |
| `resync` | 订阅方队列溢出 | 客户端必须重新拉取 snapshot（broker 既有语义） |

`session.request` **刻意不携带 params/results**：写内存的 hex payload 可达 MB 级
（deepcopy 会伤生产路径），且全文已在 journal——看板时间线只需 verb + 耗时 + 结果。

## 4. API 与安全

- `GET /api/v1/health`：`{ok, ...dashboard.status()}`
- `GET /api/v1/snapshot`：见 3.1
- `GET /api/v1/events`：SSE（text/event-stream，15s keepalive 注释行）
- 复用 `http_hardening.check_http_request`（Host/Origin 校验，防 DNS rebinding），
  token=None / observer=() —— 与归档版一致的 loopback 免鉴权姿态；
  响应统一加 `X-Content-Type-Options: nosniff` / `Referrer-Policy: no-referrer` /
  CSP `default-src 'none'; frame-ancestors 'none'`（Phase 2 出静态页时再放宽到 'self'）。
- 绑定地址**硬约束 loopback**（`Config.validate` 拒绝非 loopback，同归档版 web_host 规则）。
  远程查看走 SSH 隧道，不开远程面。

## 5. 决策记录（ADR）

| # | 决策 | 理由 |
|---|---|---|
| 1 | starlette + uvicorn，**不引入 aiohttp** | 归档版用 aiohttp 是新增直接依赖；starlette/uvicorn 已是 mcp 的传递依赖（0.52/0.44 实测在环），且 uvicorn 已被 server.py 直接 import。`SecurityHeadersMiddleware` 是纯 ASGI，零改动复用。 |
| 2 | SSE 而非 WebSocket | 流量单向（服务端→浏览器）；WS 需 websockets/wsproto 额外依赖；SSE 可 `curl -N` 直接验收。 |
| 3 | 启用仅 `--dashboard` CLI 开关，**无环境变量通路** | 延续 --experimental 纪律：开一个 HTTP 面必须是启动者的显式行为。host/port 可 env 覆盖（非门控，同 mcp_host/mcp_port）。 |
| 4 | 事件形状沿用归档版 `session.updated` 内嵌快照 | 未来若复活 3.5 工作台前端可直接兼容；`disconnect` 更名为 `disconnected`（与状态名一致）。 |
| 5 | 看板 API 与 MCP 传输解耦，独立端口（默认 3940，归档版同值） | stdio 模式（Agent 默认接入方式）下没有 HTTP 面，看板必须自起 uvicorn。 |
| 6 | request 事件不带 params/results | 体积上界（hex 写可达 32MB）+ 全文已在 journal；时间线只需 verb/耗时/成败。 |
| 7 | 绑定失败不致命 | 归档版同姿态：记 `dashboard.error` + warning 日志，调试主服务照常跑。 |

## 6. 验收（Phase 1 完成的定义）

1. `gdb-mcp --no-mcp --dashboard` 起服务；跑 `tests/dashboard_demo.py`（模拟
   stopped/running 两个插件会话）；
2. `curl /api/v1/snapshot`：2 个 session、state 正确（stopped/running）；
3. `curl -N /api/v1/events`：能收到 `session.updated`（connected/stop/running）；
4. pytest 全绿（生命周期 publish 点位、快照字段、SSE 格式、config 校验、
   Host 头 403），**显式检查退出码后**才算通过。

## 7. 后续

- Phase 2：最小前端（session 列表 + 状态 + 事件时间线），静态文件随 dashboard 端口分发。
- Phase 3：深度视图（journal 尾随、stop 详情、bp_stats）。
- Phase 4（可选）：交互动作（同源 + CSRF 防护，复用归档版 mutating guard）。
