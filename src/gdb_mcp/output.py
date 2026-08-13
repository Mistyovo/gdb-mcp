"""Text/bytes helpers shared by the server and the tool layer.

NOTE: the in-gdb plugin (``src/gdb_mcp/plugin/gdb_mcp_plugin.py``) must stay
stdlib-only and dependency-free, so it carries its own small copies of the
ANSI-strip regex and hex codec rather than importing this module.
"""

from __future__ import annotations

import re

# ANSI CSI sequences (SGR colors, cursor movement, ...) and OSC sequences
# (hyperlink / title escapes: ESC ] ... BEL or ESC ] ... ESC \).
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")

_TRUNC_MARKER = "\n...[truncated]"

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences (CSI + OSC) from ``text``."""
    return _OSC_RE.sub("", _ANSI_RE.sub("", text))


def hex_to_bytes(hexstr: str) -> bytes:
    """Parse a hex string to bytes.

    Accepts ``"41424344"``, ``"41 42 43 44"`` (any whitespace), and an
    optional ``0x`` prefix; case-insensitive. Raises :class:`ValueError` on
    invalid characters or an odd number of nibbles.
    """
    h = hexstr.strip()
    if h.lower().startswith("0x"):
        h = h[2:]
    h = re.sub(r"\s+", "", h)
    if len(h) % 2 != 0 or any(c not in _HEX_DIGITS for c in h):
        raise ValueError(f"invalid hex string: {hexstr!r}")
    return bytes.fromhex(h)


def bytes_to_hex(data: bytes) -> str:
    """Lowercase hex encoding of ``data`` (no separators)."""
    return data.hex()


def ascii_repr(data: bytes) -> str:
    """Printable-ASCII rendering of raw bytes; non-printables become ``.``."""
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def truncate_text(text: str, limit: int) -> tuple[str, bool]:
    """Truncate ``text`` to at most ``limit`` characters (marker included).

    Returns ``(text, truncated)``. The result never exceeds ``limit``; for
    limits too small to hold the truncation marker, plain truncation is used.
    """
    if len(text) <= limit:
        return text, False
    if limit <= len(_TRUNC_MARKER):
        return text[:limit], True
    keep = limit - len(_TRUNC_MARKER)
    return text[:keep] + _TRUNC_MARKER, True


def decode_with_fallback(data: bytes) -> str:
    """Decode bytes as UTF-8 with replacement chars; strip trailing NULs."""
    return data.decode("utf-8", errors="replace").rstrip("\x00")


def fmt_addr(value: int) -> str:
    """Format an integer address as lowercase hex (``0x401000``)."""
    return "0x%x" % value
