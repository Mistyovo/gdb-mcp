# 07 — 范围决策：Docker / SSH launcher 的冻结或补测

Status: needs-triage
Type: grilling
Priority: P2
Area: launcher / scope
Depends on: —

## 背景

`--launcher` 提供 `wsl`（默认）、`native`、`docker`、`ssh`。README 的 Launchers 表
明确标注 Docker 与 SSH 为 **optional / not end-to-end verified**：

- Docker：需要 `SYS_PTRACE`、relaxed seccomp、每会话容器、`host.docker.internal`
  回连；镜像需要用户自建。
- SSH：key-based auth；远程进程/日志/清理路径与 WSL/native 不同。

两者都增加配置项、代码路径和文档承诺，但主路径是 WSL/native。

## 决策选项

- **A（建议）冻结/移除**：CLI 的 `--launcher` 只保留 `wsl`/`native`，或保留选项但
  标为 unsupported 并从 README 的 supported matrix 里移除；删除 Dockerfile 与
  未测代码。
- **B 补测并保留**：为 Docker/SSH 各加一条真机端到端 smoke（启动→握手→断点→崩溃→
  清理），纳入 CI 或至少 release 检查。
- **C 维持现状**：只改文档措辞，不投入。

推荐 A：在“减法”阶段，未验证的部署后端不值得保留叙事。

## 验收

- 决策记录在本 issue。
- 若 A：`--launcher` 选项/配置/README/测试同步；`docker/Dockerfile` 删除或移到
  `contrib/`；不再声称支持 Docker/SSH。
- 若 B：两条 smoke 脚本入库并在文档中给出可复现命令；CI 至少跑一条。

## 参考

- `src/gdb_mcp/launcher.py`
- `src/gdb_mcp/__main__.py`（`--launcher`、`--ssh-host`、`--docker-image`）
- `docker/Dockerfile`
- `README.md` Launchers 表
