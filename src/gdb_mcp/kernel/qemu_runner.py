"""QEMU execution loop for kernel work (Theme F, layer ①).

The runner assembles a QEMU command line with a gdbstub (``-s``), a frozen
CPU at start (``-S``) and an HMP monitor on a unix socket, starts it inside
WSL as a background process, and exposes snapshot save/restore over that
monitor (via ``socat``, which speaks unix sockets from the WSL shell).

Snapshots are the kernel-pwn primitive everything else builds on: an
exploit attempt that panics or wedges the VM reverts in seconds instead of
rebooting. The monitor path deliberately runs inside WSL (the unix socket
is not reachable from the Windows side).
"""

from __future__ import annotations

import asyncio
import shlex
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class QemuSpec:
    """Everything needed to boot one debuggable kernel VM."""

    kernel: Path                  # bzImage / vmlinuz
    initrd: Path | None = None
    append: str = "console=ttyS0 nokaslr"
    disk: Path | None = None      # qcow2 root disk (snapshot target)
    gdbstub_port: int = 1234
    monitor_socket: str = "/tmp/gdb-mcp-qemu-monitor.sock"
    memory_mb: int = 512
    cpus: int = 1
    kvm: bool = False             # WSL2 has no /dev/kvm by default
    extra_args: list[str] = field(default_factory=list)

    def command(self) -> list[str]:
        """The qemu-system-x86_64 argv. Pure; unit-tested."""
        argv = [
            "qemu-system-x86_64",
            "-m", str(self.memory_mb),
            "-smp", str(self.cpus),
            "-kernel", _posix(self.kernel),
            "-append", self.append,
            "-gdb", "tcp::%d" % self.gdbstub_port,
            "-S",                              # freeze CPUs until the debugger says go
            "-monitor", "unix:%s,server,nowait" % self.monitor_socket,
            "-no-reboot",                      # triple-faults die loudly instead of looping
            "-display", "none",
            "-serial", "null",
        ]
        if self.initrd is not None:
            argv += ["-initrd", _posix(self.initrd)]
        if self.disk is not None:
            argv += ["-drive", "file=%s,format=qcow2,if=virtio" % _posix(self.disk)]
        if self.kvm:
            argv += ["-enable-kvm"]
        argv += self.extra_args
        return argv


def _posix(path: Path) -> str:
    return str(path).replace("\\", "/")


def wsl_launch_argv(spec: QemuSpec, distro: str | None, log_file: str) -> list[str]:
    """argv that starts QEMU detached inside WSL, logging to log_file.

    Two hard-won constraints:

    * the launcher bash must NOT exit after backgrounding — when the last
      WSL process of a launch exits, WSL tears the instance down and kills
      the "detached" emulator. So this bash stays alive on ``wait $QPID``
      and is the Windows-side handle for the VM's lifetime;
    * qemu's stderr is redirected BEFORE backgrounding — otherwise the
      first stderr write hits the dying parent's pipe (SIGPIPE).
    """
    inner = (
        " %s > %s 2>&1 & QPID=$!; "
        "trap 'kill $QPID' TERM INT; "
        "echo $QPID > %s.pid; wait $QPID"
    ) % (
        " ".join(shlex.quote(a) for a in spec.command()),
        shlex.quote(log_file),
        shlex.quote(log_file),
    )
    if distro:
        return ["wsl.exe", "-d", distro, "--", "bash", "-lc", inner]
    return ["bash", "-lc", inner]


def wsl_monitor_argv(monitor_socket: str, command: str, distro: str | None) -> list[str]:
    """argv that pipes one HMP command into the monitor unix socket."""
    inner = "echo %s | socat - unix:%s" % (
        shlex.quote(command + "\n"), shlex.quote(monitor_socket)
    )
    if distro:
        return ["wsl.exe", "-d", distro, "--", "bash", "-lc", inner]
    return ["bash", "-lc", inner]


def stub_check_argv(port: int, distro: str | None) -> list[str]:
    """argv that exits 0 iff the gdbstub TCP port answers (bash /dev/tcp)."""
    inner = (
        "timeout 1 bash -c 'cat < /dev/null > /dev/tcp/127.0.0.1/%d' "
        "> /dev/null 2>&1" % port
    )
    if distro:
        return ["wsl.exe", "-d", distro, "--", "bash", "-lc", inner]
    return ["bash", "-lc", inner]


class QemuProcess:
    """One running QEMU (async subprocess) + its monitor path."""

    def __init__(self, spec: QemuSpec, distro: str | None):
        self.spec = spec
        self.distro = distro
        self._proc: asyncio.subprocess.Process | None = None
        self._log: str | None = None

    async def start(self, log_file: str | None = None) -> None:
        # the log is written by the WSL-side shell, so the default must be a
        # WSL path — a Windows tempdir path is unreachable there
        self._log = log_file or "/tmp/gdb-mcp-qemu.log"
        argv = wsl_launch_argv(self.spec, self.distro, self._log)
        # the wsl-side bash waits on qemu for the VM's whole lifetime; do NOT
        # await it here — it IS the keep-alive handle
        # stdin MUST be devnull: the launcher bash lives as long as the VM,
        # and an inherited handle would make wsl.exe consume the server's
        # own stdio (MCP) stream — every later request then starves.
        self._proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

    async def stop(self) -> None:
        # kill the emulator through the monitor first: QEMU spawned via
        # `bash -lc "... &"` is not our direct child
        with suppress_oserror():
            await self.monitor("quit")
        if self._proc and self._proc.returncode is None:
            with suppress_oserror():
                self._proc.kill()
                await self._proc.wait()
        self._proc = None

    async def monitor(self, command: str, timeout: float = 30.0) -> tuple[int, str]:
        """One HMP command; returns (returncode, output)."""
        argv = wsl_monitor_argv(self.spec.monitor_socket, command, self.distro)
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
        return proc.returncode or 0, out.decode(errors="replace") + err.decode(errors="replace")

    async def snapshot_save(self, tag: str) -> tuple[int, str]:
        return await self.monitor("savevm %s" % tag)

    async def snapshot_restore(self, tag: str) -> tuple[int, str]:
        return await self.monitor("loadvm %s" % tag)


class suppress_oserror:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return exc_type is not None and issubclass(exc_type, OSError)
