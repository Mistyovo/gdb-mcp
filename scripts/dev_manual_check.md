# gdb-mcp 手工验证清单

## 1. 环境准备

```powershell
pip install -e .                      # Windows 侧安装服务器
wsl.exe -l -q                         # 确认 WSL 发行版（kali-linux）
wsl.exe -d kali-linux -- bash -lc "gdb --version | head -1"   # gdb 15+ 最佳
```

## 2. WSL2 网络（关键）

```powershell
cat $env:USERPROFILE\.wslconfig      # 有 networkingMode=Mirrored 时：
wsl.exe -d kali-linux -- bash -c "ip route show default; cat /etc/resolv.conf"
```

- `ip route` 为空 / 启动报 `0x8007054f` → mirrored 未生效：`wsl --shutdown` 重启，或删掉 networkingMode 回到 NAT。
- NAT 模式：插件自动尝试 `/proc/net/route` 中的默认网关，并以
  `/etc/resolv.conf` 的 nameserver IP 作为兼容回退；失败时显式设置
  `export GDB_MCP_HOST=<ip route show default 的网关>`。
- mirrored 模式使用默认 `127.0.0.1:3939`。NAT 模式设置
  `GDB_MCP_HOST_BIND=0.0.0.0` 和 `GDB_MCP_TOKEN=<随机值>`，并在 gdb
  进程侧设置相同 token；首次监听时按需放行防火墙。

## 3. 注册 MCP 并启动

1. 项目根 `.mcp.json` 已含配置；在 Claude Code 中启用（/mcp 查看）。
2. 或独立跑 `gdb-mcp`（stdio）；仅 TCP 模式：`gdb-mcp --no-mcp`。

## 4. pwntools 拉起 gdb → MCP 接管

```bash
# WSL2 内（<repo> 为仓库在 WSL 中的路径，如 /mnt/c/.../gdb-mcp）
cd <repo>/examples
gcc -g -O0 -o crasher crasher.c
python3 pwntools_debug.py        # tmux 里打开 gdb；服务器上出现新会话
```

在 Claude Code 中依次验证：

1. `list_sessions` → 可见会话（gdb_pid、arch=x86_64、pwndbg 标志）
2. `continue_execution` → `wait_for_stop` → `get_stop_reason`（SIGSEGV, fault_addr=0x0）
3. `crash_report` → 一键拿到 signal/regs/backtrace/disasm/内存
4. `execute_command("vmmap")` / `execute_command("checksec")` → pwndbg 命令透传
5. `set_breakpoint("main+0x10")` → `continue_execution` → 命中
6. `launch_gdb` 自启动 → 新会话；`kill_session(force=true)` 清理
7. `quit_gdb` → gdb 进程存活、会话断开

## 5. 集成测试（自动化）

```powershell
wsl.exe -d kali-linux -- bash -lc "cd <repo>/tests/integration && bash run_wsl_integration.sh"
python -m pytest tests/
```

> `<repo>` 为仓库路径（WSL 视角，如 `/mnt/c/.../gdb-mcp`）。

预期：`INTEGRATION OK` + 全部单元测试通过。
