# 08 — 范围决策：部署安全设施降级

Status: resolved
Type: grilling
Priority: P1
Area: security / scope
Depends on: —

## 背景

当前安全面包含两层性质不同的东西：

**核心（建议保留）**

- loopback 默认绑定；非 loopback 强制 token；
- 会话级 HMAC token（master 不下发到子进程）；
- unsafe 命令门（缩写感知、逐行、服务器+插件双层）；
- capability 模型与 `--readonly`。

**部署/企业设施（建议降级）**

- HTTP streamable transport（Host/Origin 校验、bearer）；
- TLS / mutual TLS；
- observer token/role；
- 哈希链审计日志（HMAC-SHA256、链头锚点、离线 `verify_log`）。

这些设施共约 600 行，且审计默认开启。对本地单用户 stdio 工具，投入产出不匹配；
它们还让 README 的 Security Model 占据了大量篇幅，稀释了产品叙事。

## 决策选项

- **A（建议）隔离为 deployment extra**：单独包/分支（如 `gdb-mcp-server`），
  或至少放到 `--http` 时才初始化的可选模块；核心只保留 token+loopback+unsafe gate。
- **B 保留但停止扩展**：不删代码，只在 README 标为“部署附加件”。
- **C 删除 HTTP/TLS/observer/audit**：只保留 stdio + token + unsafe gate。

推荐 A：保留能力，但不让它塑造核心产品。

## 验收

- 决策记录在本 issue。
- 核心 README 的 Security Model 精简为“本地调试工具的威胁模型 + unsafe gate +
  token”；部署设施单独成文。
- 若 A/C：observer/audit/TLS 代码与测试移出或隔离；`--no-audit-log` 等开关随迁移；
  本地 stdio 路径没有安全回归。
- 保留项必须有测试：unsafe gate 的缩写/逐行/双层 parity、token 校验、loopback 约束。

## 参考

- `src/gdb_mcp/http_hardening.py`
- `src/gdb_mcp/audit.py`
- `src/gdb_mcp/roles.py`
- `src/gdb_mcp/config.py`（TLS/observer/audit 字段）
- `.scratch/scope-review-2026-11-23/spec.md` §3.1
