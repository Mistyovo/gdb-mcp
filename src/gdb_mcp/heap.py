"""glibc ``malloc_chunk`` decoding for the ``heap_chunk`` tool.

The target class this project serves is 64-bit Linux userland (pwndbg,
glibc), so the header layout is the x86_64 one:

* ``mchunk_prev_size`` (8 bytes)
* ``mchunk_size`` (8 bytes; low three bits are PREV_INUSE / IS_MMAPPED /
  NON_MAIN_ARENA)
* ``fd`` / ``bk`` (the first two words of user data, meaningful only when
  the chunk is free; for a tcache chunk they hold next/key)

The decoder is deliberately pure (bytes in, dict out) so it is
unit-testable without gdb or pwndbg.
"""

from __future__ import annotations

from .output import ascii_repr

SIZE_T = 8
CHUNK_HEADER = 2 * SIZE_T
PREV_INUSE = 0x1
IS_MMAPPED = 0x2
NON_MAIN_ARENA = 0x4
SIZE_MASK = ~0x7
MIN_CHUNK = 0x20
#: glibc's default tcache_max on 64-bit (1032 usable bytes -> 0x410 chunk)
TCACHE_MAX = 0x410


def parse_heap_chunk(
    header: bytes,
    *,
    chunk_addr: int,
    next_size: bytes | None = None,
    data: bytes | None = None,
    data_length: int = 0,
) -> dict:
    """Decode one chunk.

    ``header`` is the first 16+ bytes at the chunk header; pass 32 bytes
    to also see the fd/bk (or tcache next/key) words. ``next_size`` is
    the size field of the following chunk, used to derive this chunk's
    in-use bit. ``data`` is the user-data preview at ``chunk_addr + 16``.
    Raises ``ValueError`` when fewer than 16 header bytes were supplied.
    """
    if len(header) < CHUNK_HEADER:
        raise ValueError(
            "chunk header needs %d bytes, got %d" % (CHUNK_HEADER, len(header))
        )
    prev_size = int.from_bytes(header[0:SIZE_T], "little")
    size_field = int.from_bytes(header[SIZE_T:CHUNK_HEADER], "little")
    chunk_size = size_field & SIZE_MASK
    flags = {
        "prev_inuse": bool(size_field & PREV_INUSE),
        "is_mmapped": bool(size_field & IS_MMAPPED),
        "non_main_arena": bool(size_field & NON_MAIN_ARENA),
    }
    warnings: list[str] = []
    if chunk_addr % 0x10:
        warnings.append("chunk address is not 16-byte aligned")
    if chunk_size < MIN_CHUNK:
        warnings.append(
            "chunk size 0x%x is below the minimum 0x%x"
            % (chunk_size, MIN_CHUNK)
        )
    elif chunk_size % 0x10:
        warnings.append("chunk size is not 16-byte aligned")
    sane = (
        chunk_addr % 0x10 == 0
        and chunk_size >= MIN_CHUNK
        and chunk_size % 0x10 == 0
    )

    next_field = None
    in_use = None
    if next_size is not None and len(next_size) >= SIZE_T:
        next_field = int.from_bytes(next_size[:SIZE_T], "little")
        # the next chunk's PREV_INUSE bit describes THIS chunk
        in_use = bool(next_field & PREV_INUSE)
    else:
        warnings.append("next chunk size unreadable; in_use is unknown")

    first_qwords = []
    if len(header) >= CHUNK_HEADER + SIZE_T:
        first_qwords.append(
            "0x%x"
            % int.from_bytes(
                header[CHUNK_HEADER : CHUNK_HEADER + SIZE_T], "little"
            )
        )
    if len(header) >= CHUNK_HEADER + 2 * SIZE_T:
        first_qwords.append(
            "0x%x"
            % int.from_bytes(
                header[CHUNK_HEADER + SIZE_T : CHUNK_HEADER + 2 * SIZE_T],
                "little",
            )
        )

    usable = chunk_size - (
        2 * SIZE_T if flags["is_mmapped"] else SIZE_T
    )
    result: dict = {
        "chunk": "0x%x" % chunk_addr,
        "mem": "0x%x" % (chunk_addr + CHUNK_HEADER),
        "size_field": "0x%x" % size_field,
        "chunk_size": "0x%x" % chunk_size,
        "usable_size_estimate": "0x%x" % max(usable, 0),
        "prev_size": "0x%x" % prev_size,
        # prev_size is meaningful only when the previous chunk is free
        "prev_size_valid": not flags["prev_inuse"],
        "flags": flags,
        "sane": sane,
        "next_chunk": "0x%x" % (chunk_addr + chunk_size),
        "next_size": "0x%x" % next_field if next_field is not None else None,
        "in_use": in_use,
        "first_qwords": first_qwords,
        "warnings": warnings,
    }

    if in_use is False:
        fd = (
            int.from_bytes(header[CHUNK_HEADER : CHUNK_HEADER + SIZE_T], "little")
            if len(header) >= CHUNK_HEADER + SIZE_T
            else None
        )
        bk = (
            int.from_bytes(
                header[CHUNK_HEADER + SIZE_T : CHUNK_HEADER + 2 * SIZE_T],
                "little",
            )
            if len(header) >= CHUNK_HEADER + 2 * SIZE_T
            else None
        )
        result["fd"] = "0x%x" % fd if fd is not None else None
        result["bk"] = "0x%x" % bk if bk is not None else None
        if chunk_size <= TCACHE_MAX:
            decoded = fd ^ (chunk_addr >> 12) if fd else None
            result["tcache"] = {
                "suspected": True,
                "next": result["fd"],
                "key": result["bk"],
                # glibc >= 2.32 safe-links tcache->next as
                # next ^ (chunk_addr >> 12); pre-2.32 stores the direct
                # pointer. Compare both before trusting either.
                "next_decoded": "0x%x" % decoded if decoded is not None else None,
            }

    if data is not None:
        preview = data[:data_length] if data_length else data
        result["data_hex"] = preview.hex()
        result["data_ascii"] = ascii_repr(preview)
    return result


__all__ = ["parse_heap_chunk"]
