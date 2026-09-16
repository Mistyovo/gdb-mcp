"""Tests for gdb_mcp.output text/bytes helpers."""

from gdb_mcp.output import (
    ascii_repr,
    bytes_to_hex,
    decode_with_fallback,
    fmt_addr,
    hex_to_bytes,
    parse_proc_mappings,
    strip_ansi,
    truncate_text,
)


class TestParseProcMappings:
    def test_canonical_six_columns(self):
        text = (
            "          Start Addr           End Addr       Size     Offset"
            "  Perms  objfile\n"
            "          0x555555554000     0x555555555000     0x1000"
            "        0x0  r--p   /usr/bin/vuln\n"
            "          0x7ffff7dd0000     0x7ffff7dfd000    0x2d000"
            "        0x0  r--p   /usr/lib/x86_64-linux-gnu/libc.so.6\n"
        )
        segs = parse_proc_mappings(text)
        assert len(segs) == 2
        assert segs[0] == {
            "start": "0x555555554000",
            "end": "0x555555555000",
            "size": 0x1000,
            "offset": "0x0",
            "perms": "r--p",
            "objfile": "/usr/bin/vuln",
        }
        assert segs[1]["size"] == 0x2D000
        assert segs[1]["objfile"].endswith("libc.so.6")

    def test_anon_mapping_without_objfile(self):
        text = "    0x7ffff7800000     0x7ffff7801000     0x1000        0x0  rw-p\n"
        segs = parse_proc_mappings(text)
        assert segs == [
            {
                "start": "0x7ffff7800000",
                "end": "0x7ffff7801000",
                "size": 0x1000,
                "offset": "0x0",
                "perms": "rw-p",
            }
        ]

    def test_skips_header_and_garbage(self):
        text = "legend: some text\nnot a mapping line\n0xzz 0xyy bad\n"
        assert parse_proc_mappings(text) == []

    def test_size_defaults_to_span(self):
        text = "0x1000 0x2000\n"
        segs = parse_proc_mappings(text)
        assert segs == [{"start": "0x1000", "end": "0x2000", "size": 0x1000}]


class TestStripAnsi:
    def test_passthrough_plain(self):
        assert strip_ansi("hello world") == "hello world"

    def test_sgr_colors(self):
        assert strip_ansi("\x1b[31mred\x1b[0m plain") == "red plain"

    def test_cursor_and_other_csi(self):
        assert strip_ansi("\x1b[2J\x1b[Habc") == "abc"
        assert strip_ansi("\x1b[?25lhidden") == "hidden"

    def test_osc_hyperlink(self):
        text = "\x1b]8;;http://example.com\x1b\\link\x1b]8;;\x1b\\"
        assert strip_ansi(text) == "link"

    def test_osc_bel_terminated(self):
        assert strip_ansi("\x1b]0;title\x07body") == "body"

    def test_incomplete_escape_at_end_is_kept(self):
        # Trailing partial escape has no terminator; regex leaves it as-is.
        assert strip_ansi("text\x1b[31") == "text\x1b[31"

    def test_empty(self):
        assert strip_ansi("") == ""


class TestHexCodec:
    def test_plain(self):
        assert hex_to_bytes("41424344") == b"ABCD"

    def test_0x_prefix(self):
        assert hex_to_bytes("0x4142") == b"AB"

    def test_uppercase(self):
        assert hex_to_bytes("DEADBEEF") == b"\xde\xad\xbe\xef"

    def test_whitespace(self):
        assert hex_to_bytes("41 42\n43\t44") == b"ABCD"

    def test_empty(self):
        assert hex_to_bytes("") == b""

    def test_odd_length_raises(self):
        import pytest

        with pytest.raises(ValueError):
            hex_to_bytes("abc")

    def test_invalid_chars_raise(self):
        import pytest

        with pytest.raises(ValueError):
            hex_to_bytes("zz")
        with pytest.raises(ValueError):
            hex_to_bytes("414-2")

    def test_roundtrip(self):
        data = bytes(range(256))
        assert hex_to_bytes(bytes_to_hex(data)) == data


class TestAsciiRepr:
    def test_printable_and_controls(self):
        assert ascii_repr(b"AB\x00\n\xffZ") == "AB...Z"

    def test_all_controls(self):
        assert ascii_repr(b"\x01\x02") == ".."


class TestTruncateText:
    def test_under_limit_unchanged(self):
        text, truncated = truncate_text("short", 100)
        assert text == "short" and truncated is False

    def test_exact_limit_not_truncated(self):
        text, truncated = truncate_text("12345", 5)
        assert text == "12345" and truncated is False

    def test_over_limit(self):
        text, truncated = truncate_text("x" * 100, 50)
        assert truncated is True
        assert len(text) <= 50
        assert text.endswith("[truncated]")

    def test_zero_limit(self):
        text, truncated = truncate_text("abc", 0)
        assert truncated is True and text == ""


class TestDecodeWithFallback:
    def test_valid_utf8(self):
        assert decode_with_fallback("héllo".encode()) == "héllo"

    def test_invalid_replaced(self):
        assert decode_with_fallback(b"a\xffb") == "a�b"

    def test_trailing_nuls_stripped(self):
        assert decode_with_fallback(b"abc\x00\x00") == "abc"


class TestFmtAddr:
    def test_basic(self):
        assert fmt_addr(0x401000) == "0x401000"
        assert fmt_addr(0) == "0x0"
