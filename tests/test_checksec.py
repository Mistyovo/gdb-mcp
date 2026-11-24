"""parse_checksec against the real pwndbg ``checksec`` layout (gdb 18.1 +
pwndbg, captured on kali-linux): ANSI-colored values and the canary field
reported on a ``Stack:`` line."""

from gdb_mcp.campaign import parse_checksec

REAL_PWNDBG_CHECKSEC = (
    "File:     /root/v\n"
    "Arch:     amd64\n"
    "RELRO:      \x1b[33mPartial RELRO\x1b[0m\n"
    "Stack:      \x1b[31mNo canary found\x1b[0m\n"
    "NX:         \x1b[32mNX enabled\x1b[0m\n"
    "PIE:        \x1b[31mNo PIE (0x400000)\x1b[0m\n"
    "Stripped:   \x1b[31mNo\x1b[0m\n"
    "Debuginfo:  \x1b[32mYes\x1b[0m\n"
)


def test_real_output_yields_clean_values_and_canary():
    parsed = parse_checksec(REAL_PWNDBG_CHECKSEC)
    assert parsed["relro"]["value"] == "Partial RELRO"
    assert parsed["canary"]["value"] == "No canary found"
    assert parsed["nx"]["value"] == "NX enabled"
    assert parsed["pie"]["value"] == "No PIE (0x400000)"
    for info in parsed.values():
        assert "\x1b" not in info["value"]
        assert "\x1b" not in info["evidence"]


def test_canary_label_variant_still_parses():
    parsed = parse_checksec("Canary:  Canary found\n")
    assert parsed["canary"]["value"] == "Canary found"


def test_unrecognized_output_returns_empty():
    assert parse_checksec("hello world\n") == {}
    assert parse_checksec("") == {}
