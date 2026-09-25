"""Unit tests for the kernel layer-1 PoC (Theme F): pure logic only."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gdb_mcp.kernel.qemu_runner import (
    QemuSpec,
    stub_check_argv,
    wsl_launch_argv,
    wsl_monitor_argv,
)
from gdb_mcp.kernel.vmlinux import (
    find_payload,
    kaslr_slide,
    static_symbol_address,
)


# -- QEMU command assembly ---------------------------------------------------

def _spec(**overrides):
    base = dict(
        kernel=Path("/boot/vmlinuz"),
        initrd=Path("/boot/initrd.img"),
        disk=Path("/tmp/root.qcow2"),
        gdbstub_port=1234,
        monitor_socket="/tmp/mon.sock",
    )
    base.update(overrides)
    return QemuSpec(**base)


def test_command_has_gdbstub_frozen_cpu_and_monitor():
    argv = _spec().command()
    joined = " ".join(argv)
    assert "-gdb tcp::1234" in joined
    assert "-S" in argv
    assert "-monitor unix:/tmp/mon.sock,server,nowait" in joined
    assert "-no-reboot" in argv
    assert "-kernel /boot/vmlinuz" in joined
    assert "-initrd /boot/initrd.img" in joined
    assert "file=/tmp/root.qcow2,format=qcow2,if=virtio" in joined


def test_kvm_and_optional_parts():
    argv = QemuSpec(kernel=Path("/k")).command()  # no initrd/disk/kvm
    assert "-initrd" not in argv and "-drive" not in argv
    assert "-enable-kvm" not in QemuSpec(kernel=Path("/k")).command()
    assert "-enable-kvm" in QemuSpec(kernel=Path("/k"), kvm=True).command()


def test_wsl_launch_argv_detaches_and_redirects_log():
    argv = wsl_launch_argv(_spec(), "kali-linux", "/tmp/qemu.log")
    assert argv[:5] == ["wsl.exe", "-d", "kali-linux", "--", "bash"]
    inner = argv[-1]
    # keep-alive form: bash waits on qemu (WSL kills "detached" processes
    # when the launching session ends) and stderr is redirected BEFORE `&`
    assert "> /tmp/qemu.log 2>&1 & QPID=$!" in inner
    assert "trap 'kill $QPID' TERM INT" in inner
    assert "wait $QPID" in inner


def test_monitor_argv_speaks_unix_socket_via_socat():
    argv = wsl_monitor_argv("/tmp/mon.sock", "savevm snap1", None)
    inner = argv[-1]
    assert "socat" in inner and "unix:/tmp/mon.sock" in inner
    assert "savevm snap1" in inner


def test_stub_check_is_a_tcp_probe():
    argv = stub_check_argv(1234, None)
    assert "/dev/tcp/127.0.0.1/1234" in argv[-1]


# -- vmlinux helpers ---------------------------------------------------------

def test_find_payload_gzip_magic():
    blob = b"junk header" + b"\x1f\x8b\x08" + b"payload"
    assert find_payload(blob) == ("gzip", len(b"junk header"))


def test_find_payload_xz_magic_preferred_order():
    blob = b"\xfd7zXZ\x00rest"
    assert find_payload(blob) == ("xz", 0)


def test_find_payload_absent():
    assert find_payload(b"no compressed payload here") is None


def test_static_symbol_address():
    system_map = (
        "ffffffff81000000 T _text\n"
        "ffffffff82000000 B __bss_start\n"
        "ffffffff81234567 t some_fn\n"
    )
    assert static_symbol_address(system_map, "_text") == 0xFFFFFFFF81000000
    assert static_symbol_address(system_map, "_text\n") is None
    assert static_symbol_address(system_map, "missing") is None


def test_kaslr_slide_is_runtime_minus_static():
    assert kaslr_slide(0xFFFFFFFF81000000, 0xFFFFFFFFA0000000) == 0x1F000000


def test_decompress_gzip_roundtrip():
    import zlib

    from gdb_mcp.kernel.vmlinux import decompress

    compressor = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    payload = compressor.compress(b"elf-ish bytes") + compressor.flush()
    out = decompress("gzip", payload)
    assert out == b"elf-ish bytes"


def test_decompress_rejects_external_tool_formats():
    from gdb_mcp.kernel.vmlinux import decompress

    with pytest.raises(ValueError):
        decompress("zstd", b"whatever")
