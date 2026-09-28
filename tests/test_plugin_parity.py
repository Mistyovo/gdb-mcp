"""Cross-checks for code the plugin duplicates on purpose.

``gdb_mcp_plugin.py`` is sourced into a running gdb and must stay
stdlib-only and single-file, so it cannot import the server package. The
price is a handful of deliberately duplicated helpers; these tests make
that price explicit by asserting the copies still behave identically.
(the unsafe-command gate has its own check in ``test_security.py``, and
the verb table in ``test_protocol.py``.)
"""

import pytest

from gdb_mcp.output import ascii_repr, bytes_to_hex, hex_to_bytes, strip_ansi

SAMPLES = [
    "",
    "plain text",
    "\x1b[31mred\x1b[0m output",
    "\x1b[1;38;5;204mcolourful\x1b[0m",
    "before\x1b]8;;http://x\x07after",  # OSC hyperlink
    "cursor\x1b[2Aup",
    "\x1b[?25hvisible",
]

HEX_SAMPLES = [
    b"",
    b"\x00\x01\x02",
    b"\x7f\xff",
    b"deadBeef\x00",
]


class TestPluginParity:
    @pytest.fixture(autouse=True)
    def _plugin(self, plugin_mod):
        self.plugin = plugin_mod

    @pytest.mark.parametrize("text", SAMPLES)
    def test_strip_ansi(self, text):
        assert self.plugin._strip_ansi(text) == strip_ansi(text)

    @pytest.mark.parametrize("data", HEX_SAMPLES)
    def test_hex_roundtrip_and_ascii(self, data):
        hexed = bytes_to_hex(data)
        assert self.plugin._hex_to_bytes(hexed) == hex_to_bytes(hexed) == data
        assert self.plugin._ascii_repr(data) == ascii_repr(data)

    def test_hex_rejects_the_same_input(self):
        for bad in ("zz", "414", "0x41z"):
            with pytest.raises(ValueError):
                hex_to_bytes(bad)
            with pytest.raises(ValueError):
                self.plugin._hex_to_bytes(bad)

    def test_memory_segment_fields(self):
        """read_mem's segment keys are consumed by the server's result
        trimming and by crash_report; a rename on one side would silently
        produce empty output on the other."""
        segment = self.plugin._memory_segment(0x400000, b"\x90\x90")
        assert set(segment) == {"addr", "length", "hex", "ascii"}
        assert segment["length"] == 2 and segment["hex"] == "9090"
