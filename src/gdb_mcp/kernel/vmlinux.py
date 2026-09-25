"""vmlinux symbol plumbing (Theme F, layer ①).

Distribution kernels ship a compressed ``bzImage``; gdb needs the *uncompressed*
``vmlinux`` ELF for symbols. ``extract_vmlinux`` finds the embedded compressed
payload by magic bytes and decompresses it (the extract-vmlinux recipe).
KASLR relocates the kernel at boot: ``kaslr_slide`` recovers the slide by
comparing the runtime address of any stable symbol (default ``_text``)
against its static ``vmlinux`` address.
"""

from __future__ import annotations

import lzma
import re
import zlib
from pathlib import Path

#: magic -> (offset of compressed payload after the magic, decompressor)
_MAGICS = (
    (b"\x1f\x8b\x08", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bzip2"),
    (b"\x5d\x00\x00", "lzma"),
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
)


def find_payload(bzimage: bytes) -> tuple[str, int] | None:
    """(kind, payload offset) of the first embedded compressed image."""
    for magic, kind in _MAGICS:
        idx = bzimage.find(magic)
        if idx >= 0:
            return kind, idx
    return None


def decompress(kind: str, data: bytes) -> bytes:
    if kind == "gzip":
        return zlib.decompress(data, 16 + zlib.MAX_WBITS)
    if kind == "xz":
        return lzma.LZMADecompressor().decompress(data)
    if kind == "lzma":
        return lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(data)
    raise ValueError("decompression for %r requires its CLI tool" % kind)


def extract_vmlinux(bzimage_path: Path) -> bytes:
    """Uncompressed kernel image bytes from a bzImage."""
    blob = Path(bzimage_path).read_bytes()
    found = find_payload(blob)
    if found is None:
        raise ValueError("no compressed payload found in %s" % bzimage_path)
    kind, offset = found
    if kind in ("bzip2", "lz4", "zstd"):
        raise ValueError(
            "kernel uses %s; install the matching CLI and extend decompress()"
            % kind
        )
    return decompress(kind, blob[offset:])


_SYMBOL_RE = re.compile(r"^(?P<addr>[0-9a-fA-F]+)\s+\S+\s+(?P<sym>\S+)")


def static_symbol_address(symbol_blob: str, name: str) -> int | None:
    """Address of ``name`` from System.map/vmlinux nm text output."""
    for line in symbol_blob.splitlines():
        m = _SYMBOL_RE.match(line)
        if m and m.group("sym") == name:
            return int(m.group("addr"), 16)
    return None


def kaslr_slide(static_address: int, runtime_address: int) -> int:
    """Runtime - static for the same symbol, modulo-cleared to page granularity
    by the caller if needed. KASLR slides are page-aligned."""
    return runtime_address - static_address
