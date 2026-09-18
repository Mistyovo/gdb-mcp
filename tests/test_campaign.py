"""Tests for the exploit campaign module (cyclic oracle + bookkeeping)."""

import pytest

from gdb_mcp.campaign import (
    campaign_detect,
    campaign_note,
    campaign_set,
    campaign_summary,
    cyclic_pattern,
    debruijn_bytes,
    is_empty,
    match_cyclic,
    new_campaign,
)


class TestCyclic:
    def test_pattern_is_pwntools_compatible(self):
        assert cyclic_pattern(12) == "aaaabaaacaaa"
        assert len(cyclic_pattern(4096)) == 4096
        assert cyclic_pattern(0) == ""

    def test_match_roundtrip(self):
        pattern = cyclic_pattern(256)
        for offset in (0, 1, 72, 255 - 3):
            value = int.from_bytes(
                pattern[offset : offset + 4].encode(), "little"
            )
            match = match_cyclic(value)
            assert match is not None
            assert match["offset"] == offset

    def test_match_ignores_non_pattern_values(self):
        assert match_cyclic(0x7FFFF7E1BCE0) is None
        assert match_cyclic(0) is None

    def test_sequence_cached_and_deterministic(self):
        assert debruijn_bytes(4) == debruijn_bytes(4)


class TestCampaignState:
    def test_set_and_summary(self):
        data = new_campaign()
        assert is_empty(data)
        campaign_set(data, "offsets", "libc_base", "0x7ffff7d80000")
        campaign_set(
            data,
            "primitives",
            "pc_control",
            "candidate",
            evidence="pc matches cyclic at 72",
        )
        campaign_note(data, "leak via puts@plt")
        assert not is_empty(data)
        lines = campaign_summary(data)
        assert any("libc_base" in line for line in lines)
        assert any("pc_control" in line for line in lines)
        assert any("leak via puts@plt" in line for line in lines)

    def test_invalid_section_rejected(self):
        with pytest.raises(ValueError):
            campaign_set(new_campaign(), "notes_are_separate", "k", "v")

    def test_section_cap(self):
        data = new_campaign()
        for i in range(64):
            campaign_set(data, "offsets", "k%d" % i, i)
        with pytest.raises(ValueError):
            campaign_set(data, "offsets", "overflow", 1)

    def test_notes_capped(self):
        data = new_campaign()
        for i in range(100):
            campaign_note(data, "note %d" % i)
        notes = data["notes"]
        assert len(notes) == 32
        assert notes[-1]["text"] == "note 99"

    def test_values_capped(self):
        data = new_campaign()
        campaign_set(data, "offsets", "huge", "A" * 5000)
        stored = data["offsets"]["huge"]["value"]
        assert len(stored) < 3000
        assert "...<+" in stored
        # non-string values are stringified then capped
        campaign_set(data, "offsets", "obj", object())
        assert isinstance(data["offsets"]["obj"]["value"], str)

    def test_detect_records_pc_control(self):
        data = new_campaign()
        pattern = cyclic_pattern(256)
        pc = "0x%x" % int.from_bytes(pattern[72:76].encode(), "little")
        stop_info = {"pc": pc, "signal": "SIGSEGV"}
        match = campaign_detect(data, stop_info)
        assert match is not None
        assert match["offset"] == 72
        assert data["primitives"]["pc_control"]["value"] == "candidate"
        assert "cyclic" in data["primitives"]["pc_control"]["evidence"]

    def test_detect_clean_stop_is_none(self):
        data = new_campaign()
        assert campaign_detect(data, {"pc": "0x401000"}) is None
        assert data["primitives"] == {}


class TestSanitizeCampaign:
    def test_malformed_is_dropped(self):
        from gdb_mcp.campaign import sanitize_campaign

        dirty = {
            "offsets": {"ok": {"value": "0x1000", "ts": 1},
                        "bad": "not-a-dict",
                        "huge": {"value": "X" * 9999}},
            "primitives": "not-a-dict",
            "notes": [{"text": "fine"}, "junk", 42],
        }
        clean = sanitize_campaign(dirty)
        assert clean["offsets"]["ok"]["value"] == "0x1000"
        assert "bad" not in clean["offsets"]
        assert clean["offsets"]["huge"]["value"].endswith("...<+7951 chars>")
        assert clean["primitives"] == {}
        assert [n["text"] for n in clean["notes"]] == ["fine"]

    def test_non_dict_input_returns_fresh(self):
        from gdb_mcp.campaign import sanitize_campaign

        clean = sanitize_campaign("injected instructions")
        assert clean["notes"] == [] and clean["offsets"] == {}
