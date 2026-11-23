"""Tests for the pure glibc malloc_chunk decoder."""

import struct

import pytest

from gdb_mcp.heap import parse_heap_chunk


def _chunk(size_field, prev_size=0, fd=0, bk=0):
    return struct.pack("<QQQQ", prev_size, size_field, fd, bk)


class TestParseHeapChunk:
    def test_free_tcache_chunk(self):
        addr = 0x555555559290
        fd = 0x5555555592C0
        key = 0x5555AAAA1234
        result = parse_heap_chunk(
            _chunk(0x31, fd=fd, bk=key),
            chunk_addr=addr,
            next_size=struct.pack("<Q", 0x20),
            data=b"ABCD" * 8,
            data_length=32,
        )
        assert result["chunk"] == "0x555555559290"
        assert result["mem"] == "0x5555555592a0"
        assert result["size_field"] == "0x31"
        assert result["chunk_size"] == "0x30"
        assert result["usable_size_estimate"] == "0x28"
        assert result["in_use"] is False
        assert result["flags"] == {
            "prev_inuse": True,
            "is_mmapped": False,
            "non_main_arena": False,
        }
        assert result["prev_size_valid"] is False
        assert result["fd"] == "0x5555555592c0"
        assert result["bk"] == "0x5555aaaa1234"
        assert result["tcache"]["suspected"] is True
        assert result["tcache"]["next"] == "0x5555555592c0"
        assert result["tcache"]["key"] == "0x5555aaaa1234"
        assert result["tcache"]["next_decoded"] == "0x%x" % (
            fd ^ (addr >> 12)
        )
        assert result["data_hex"] == (b"ABCD" * 8).hex()
        assert result["data_ascii"] == "ABCD" * 8
        assert result["warnings"] == []

    def test_allocated_chunk_has_no_bin_links(self):
        addr = 0x555555559290
        result = parse_heap_chunk(
            _chunk(0x21, fd=0x4141414141414141, bk=0x4242424242424242),
            chunk_addr=addr,
            next_size=struct.pack("<Q", 0x21),  # next PREV_INUSE=1
        )
        assert result["in_use"] is True
        assert "fd" not in result
        assert "bk" not in result
        assert "tcache" not in result
        assert result["first_qwords"] == [
            "0x4141414141414141",
            "0x4242424242424242",
        ]

    def test_prev_size_valid_when_previous_chunk_is_free(self):
        result = parse_heap_chunk(
            _chunk(0x30, prev_size=0x1234),
            chunk_addr=0x1000,
            next_size=struct.pack("<Q", 0x21),
        )
        assert result["prev_size"] == "0x1234"
        assert result["prev_size_valid"] is True

    def test_mmapped_usable_size_estimate(self):
        result = parse_heap_chunk(
            _chunk(0x22),
            chunk_addr=0x1000,
            next_size=struct.pack("<Q", 0x22),
        )
        assert result["flags"]["is_mmapped"] is True
        assert result["usable_size_estimate"] == "0x10"

    def test_unreadable_next_chunk_is_unknown(self):
        result = parse_heap_chunk(_chunk(0x21), chunk_addr=0x1000)
        assert result["in_use"] is None
        assert result["next_size"] is None
        assert any("in_use is unknown" in warning for warning in result["warnings"])

    def test_corrupt_size_is_flagged(self):
        result = parse_heap_chunk(
            _chunk(0x11),
            chunk_addr=0x1000,
            next_size=struct.pack("<Q", 0x20),
        )
        assert result["sane"] is False
        assert any("minimum" in warning for warning in result["warnings"])

    def test_short_header_rejected(self):
        with pytest.raises(ValueError):
            parse_heap_chunk(b"\x00" * 8, chunk_addr=0x1000)

    def test_header_without_fd_bytes(self):
        result = parse_heap_chunk(
            _chunk(0x31)[:16],
            chunk_addr=0x1000,
            next_size=struct.pack("<Q", 0x20),
        )
        assert result["fd"] is None
        assert result["bk"] is None
        assert result["tcache"]["next_decoded"] is None
