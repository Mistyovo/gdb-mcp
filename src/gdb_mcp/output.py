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


_PERMS_RE = re.compile(r"^[r-][w-][x-][psa-]?$")


def parse_proc_mappings(text: str) -> list[dict]:
    """Parse ``info proc mappings`` (or core-file ``info files`` /
    ``maintenance info sections`` fallback) into structured segments.

    Accepts the common gdb column layouts (start end size offset perms
    [objfile], with or without size/perms) as well as core-file section
    lines like ``0x00401000 - 0x00402000 is .text`` or
    ``[0] 0x00401000->0x00402000 at ...: .text ALLOC LOAD CODE``.
    """
    segments: list[dict] = []
    for raw in text.splitlines():
        parts = raw.strip().split()
        if (
            len(parts) >= 2
            and parts[0].startswith("0x")
            and parts[1].startswith("0x")
        ):
            try:
                start = int(parts[0], 16)
                end = int(parts[1], 16)
            except ValueError:
                continue
            hex_vals: list[int] = []
            perms = None
            rest: list[str] = []
            for tok in parts[2:]:
                if len(hex_vals) < 2 and perms is None and tok.startswith("0x"):
                    try:
                        hex_vals.append(int(tok, 16))
                        continue
                    except ValueError:
                        pass
                if perms is None and _PERMS_RE.match(tok):
                    perms = tok
                    continue
                rest.append(tok)
            size = hex_vals[0] if hex_vals else end - start
            segment: dict = {
                "start": fmt_addr(start),
                "end": fmt_addr(end),
                "size": size,
            }
            if len(hex_vals) > 1:
                segment["offset"] = fmt_addr(hex_vals[1])
            if perms:
                segment["perms"] = perms
            if rest:
                segment["objfile"] = " ".join(rest)
            segments.append(segment)
            continue
        # core-file fallback: `0x401000 - 0x402000 is .text`
        m = _CORE_INFO_FILES_RE.match(raw.strip())
        if m is not None:
            start = int(m.group(1), 16)
            end = int(m.group(2), 16)
            if end > start:
                segments.append(
                    {
                        "start": fmt_addr(start),
                        "end": fmt_addr(end),
                        "size": end - start,
                        "objfile": m.group(3).strip(),
                    }
                )
            continue
        # core-file fallback: `[0] 0x401000->0x402000 at 0x...: .text ALLOC LOAD CODE`
        m2 = _CORE_MAINT_SEC_RE.match(raw.strip())
        if m2 is not None:
            start = int(m2.group(1), 16)
            end = int(m2.group(2), 16)
            if end > start:
                flags_text = m2.group(4) or ""
                r = "r" if "ALLOC" in flags_text or "LOAD" in flags_text else "-"
                w = "w" if "READONLY" not in flags_text and "DATA" in flags_text else "-"
                x = "x" if "CODE" in flags_text else "-"
                segments.append(
                    {
                        "start": fmt_addr(start),
                        "end": fmt_addr(end),
                        "size": end - start,
                        "perms": "%s%s%s-" % (r, w, x),
                        "objfile": m2.group(3).strip(),
                    }
                )
    return segments


_CORE_INFO_FILES_RE = re.compile(
    r"^(0x[0-9a-fA-F]+)\s*-\s*(0x[0-9a-fA-F]+)\s+is\s+(.+)$"
)
_CORE_MAINT_SEC_RE = re.compile(
    r"^(?:\[\d+\]\s+)?(0x[0-9a-fA-F]+)->(0x[0-9a-fA-F]+)\s+at\s+0x[0-9a-fA-F]+:\s+(\S+)(?:\s+(.*))?$"
)


_BIN_SECTION_NAMES = {
    "tcachebins": "tcachebins",
    "tcache": "tcachebins",
    "fastbins": "fastbins",
    "fastbin": "fastbins",
    "unsorted bins": "unsorted",
    "unsorted bin": "unsorted",
    "unsortedbin": "unsorted",
    "small bins": "small",
    "small bin": "small",
    "smallbins": "small",
    "large bins": "large",
    "large bin": "large",
    "largebins": "large",
}

# "0x20 [ 3]: ..." or "0x20: ..." — a bin size followed by a chunk chain
_BIN_SIZE_LINE_RE = re.compile(r"^(0x[0-9a-fA-F]+)\s*(?:\[\s*(\d+)\s*\])?\s*:")
_HEX_TOKEN_RE = re.compile(r"0x[0-9a-fA-F]+")


def parse_pwndbg_bins(text: str) -> dict:
    """Tolerant parse of pwndbg ``bins`` output into per-bin chunk lists.

    Returns five bins sections (tcachebins/fastbins as size->entries maps,
    unsorted/small/large likewise) and a ``parsed`` flag that is only True
    when at least one known section header was seen. Unknown formats must
    be surfaced to the caller as raw text instead of guessed at.
    """
    result: dict = {
        "tcachebins": {},
        "fastbins": {},
        "unsorted": {},
        "small": {},
        "large": {},
        "parsed": False,
    }
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        canonical = _BIN_SECTION_NAMES.get(line.lower())
        if canonical:
            section = canonical
            result["parsed"] = True
            continue
        if section is None:
            continue
        size_match = _BIN_SIZE_LINE_RE.match(line)
        if size_match is None:
            continue  # annotations, banners, other commands' output
        size = size_match.group(1).lower()
        after_colon = line[line.index(":") + 1 :]
        entries = [
            tok.lower()
            for tok in _HEX_TOKEN_RE.findall(after_colon)
            if int(tok, 16) != 0  # chain terminators (◔— 0x0) are not chunks
        ]
        result[section].setdefault(size, [])
        result[section][size].extend(entries)
    return result


def tail_text_file(
    path: str, lines: int = 200, max_bytes: int = 1024 * 1024
) -> tuple[str, bool]:
    """Read a bounded tail of a text file without loading the whole file."""
    lines = max(1, min(int(lines), 10_000))
    max_bytes = max(1, int(max_bytes))
    with open(path, "rb") as fh:
        fh.seek(0, 2)
        position = fh.tell()
        chunks = []
        bytes_read = 0
        newline_count = 0
        while position > 0 and bytes_read < max_bytes and newline_count <= lines:
            size = min(64 * 1024, position, max_bytes - bytes_read)
            position -= size
            fh.seek(position)
            chunk = fh.read(size)
            chunks.append(chunk)
            bytes_read += len(chunk)
            newline_count += chunk.count(b"\n")
    data = b"".join(reversed(chunks))
    selected = b"".join(data.splitlines(keepends=True)[-lines:])
    text = decode_with_fallback(selected).replace("\r\n", "\n").replace("\r", "\n")
    return text, position > 0
