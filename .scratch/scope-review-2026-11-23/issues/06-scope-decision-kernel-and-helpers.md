# 06 — 范围决策：内核 QEMU 与宿主侧 pwn 助手

Status: resolved
Type: grilling
Priority: P1
Area: scope / kernel / experimental
Depends on: —

## 背景

三组实验工具不属于“用户态动态调试”域：

1. **内核**：`kernel_launch` / `kernel_snapshot` + `src/gdb_mcp/kernel/`（约 250 行）
   + `experimental.py` 中的 QEMU 句柄管理。需要 QEMU、qcow2、socat，且 README
   自认 KASLR 未自动纠正、属于“separate target class”。
2. **`identify_libc`**：向 libc.rip 兼容 API 发送 leak 的低 12 位；不碰调试器。
3. **`search_gadgets`**：在**服务器宿主**上跑 ROPgadget；主场景 Windows/WSL 下，
   目标二进制通常不在宿主可读路径，实际可用性差。

## 决策选项

- **A（建议）从本仓库移除**：内核能力若要继续，放独立仓库/分支；libc/ROP 助手
  由 agent 在目标环境用 pwntools/ROPgadget 自己跑，或做成独立 pwn-helpers MCP。
- **B 独立成包**：`gdb-mcp-kernel`、`gdb-mcp-pwn-helpers`，本仓库只留接口。
- **C 保留在 `--experimental`**：现状，但继续占用维护/文档/安全面。

推荐 A：这三组都不是“让 agent 更好地驱动活的用户态 gdb”。

## 验收

- 决策记录在本 issue。
- 若 A/B：移除/迁移 `kernel/`、QEMU 相关代码与配置、`identify_libc`、
  `search_gadgets`；`experimental.py` 只剩真正要保留的实验件；README 的
  Experimental Features、Architecture、Testing 同步更新；不再依赖 qemu/socat。
- 若 C：在 README 明确“不保证可用”，并给 `search_gadgets` 标注宿主路径限制。

## 参考

- `src/gdb_mcp/tools/experimental.py`
- `src/gdb_mcp/kernel/`
- `.scratch/scope-review-2026-11-23/spec.md` §3.6–3.7
