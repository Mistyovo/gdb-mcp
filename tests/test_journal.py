"""Tests for the session journal and gdbscript compilation."""

import json

from gdb_mcp.journal import Journal, _trim, compile_gdbscript


class TestTrim:
    def test_long_string_trimmed_with_note(self):
        out = _trim("A" * 300)
        assert out.startswith("A" * 256)
        assert "...<+44 chars>" in out

    def test_hex_payload_becomes_length_marker(self):
        out = _trim("ab" * 5000)
        assert out == "<hex:5000 bytes>"

    def test_short_values_untouched(self):
        assert _trim({"a": "ok", "b": ["x", "y"]}) == {"a": "ok", "b": ["x", "y"]}

    def test_lists_bounded(self):
        out = _trim(list(range(100)))
        assert len(out) == 33  # 32 kept + marker
        assert out[-1] == "<+68 more>"

    def test_unknown_objects_stringified(self):
        class Thing:
            def __str__(self):
                return "thing"

        assert _trim(Thing()) == "thing"


class TestJournal:
    def test_append_writes_jsonl_and_mirrors(self, tmp_path):
        journal = Journal(tmp_path / "journals" / "s-1.jsonl")
        journal.append("request", {"verb": "eval", "params": {"command": "x " * 200}, "ok": True})
        journal.append("notification", {"event": "stop", "payload": {"pc": "0x1"}})
        assert len(journal) == 2
        lines = (tmp_path / "journals" / "s-1.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()
        # schema meta line + the two entries; meta is never mirrored
        assert len(lines) == 3
        assert json.loads(lines[0])["kind"] == "meta"
        assert json.loads(lines[0])["schema_version"] >= 1
        assert '"kind": "request"' in lines[1] or '"kind":"request"' in lines[1]

    def test_append_survives_unwritable_path(self, tmp_path):
        journal = Journal(tmp_path / "journals" / "s-2.jsonl")
        # repoint to an un-creatable nested path: append must not raise
        journal.path = journal.path.parent / "no" / "such" / "dir" / "j.jsonl"
        journal.append("request", {"verb": "eval", "params": {}, "ok": True})
        assert len(journal) == 1

    def test_restart_continuity(self, tmp_path):
        path = tmp_path / "journals" / "s-1.jsonl"
        first = Journal(path)
        first.append("request", {"verb": "eval", "params": {"command": "x"}, "ok": True})
        first.append("notification", {"event": "stop", "payload": {}})
        # server restart: a fresh Journal over the same file re-reads it
        second = Journal(path, load_existing=True)
        assert len(second) == 2
        assert second.entries()[0]["verb"] == "eval"
        assert second.entries()[1]["event"] == "stop"
        second.append("request", {"verb": "break", "params": {}, "ok": True})
        assert len(second) == 3
        # the file holds the full continuous history (meta + 3 entries)
        assert len(path.read_text(encoding="utf-8").splitlines()) == 4

    def test_torn_tail_line_tolerated(self, tmp_path):
        path = tmp_path / "journals" / "torn.jsonl"
        path.parent.mkdir(parents=True)
        good = {"ts": 1.0, "kind": "request", "verb": "eval", "ok": True}
        path.write_text(
            json.dumps(good) + "\n" + '{"kind": "req', encoding="utf-8"
        )
        journal = Journal(path, load_existing=True)
        assert len(journal) == 1

    def test_mirror_cap_drops_oldest_from_memory_only(self, tmp_path):
        path = tmp_path / "journals" / "cap.jsonl"
        journal = Journal(path)
        journal.MIRROR_CAP = 5
        for i in range(8):
            journal.append("request", {"verb": "eval", "params": {"i": i}, "ok": True})
        assert len(journal) == 5
        assert journal.entries()[0]["params"]["i"] == 3
        assert journal.head_truncated is True
        # the file keeps everything (meta + 8 entries)
        assert len(path.read_text(encoding="utf-8").splitlines()) == 9


class TestJournalSchemaVersion:
    def test_new_file_records_schema_version(self, tmp_path):
        from gdb_mcp.journal import SCHEMA_VERSION

        journal = Journal(tmp_path / "j" / "new.jsonl")
        assert journal.schema_version == SCHEMA_VERSION
        first = json.loads(
            (tmp_path / "j" / "new.jsonl").read_text(encoding="utf-8").splitlines()[0]
        )
        assert first == {
            "ts": first["ts"],
            "kind": "meta",
            "schema_version": SCHEMA_VERSION,
        }

    def test_pre_versioning_journal_loads_as_v1(self, tmp_path):
        path = tmp_path / "old.jsonl"
        path.write_text(
            json.dumps({"ts": 1.0, "kind": "request", "verb": "eval", "ok": True})
            + "\n",
            encoding="utf-8",
        )
        journal = Journal(path, load_existing=True)
        assert journal.schema_version == 1
        assert journal.unsupported_schema is False
        assert len(journal) == 1

    def test_newer_schema_journal_not_loaded_but_still_appendable(self, tmp_path):
        """A journal from a newer build: history is left on disk untouched,
        the mirror stays empty (unknown semantics must not leak into script
        compilation), and appending still works — journaling must never
        break debugging."""
        path = tmp_path / "future.jsonl"
        path.write_text(
            json.dumps({"kind": "meta", "schema_version": 99, "ts": 1.0})
            + "\n"
            + json.dumps({"kind": "request", "verb": "eval", "ok": True})
            + "\n",
            encoding="utf-8",
        )
        journal = Journal(path, load_existing=True)
        assert journal.unsupported_schema is True
        assert journal.schema_version == 99
        assert len(journal) == 0
        journal.append("request", {"verb": "ping", "ok": True})
        assert len(journal) == 1
        # original two lines preserved, new entry appended after them
        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 3
        assert json.loads(lines[0])["schema_version"] == 99

    def test_migrate_entries_identity_for_current_version(self):
        from gdb_mcp.journal import SCHEMA_VERSION, migrate_entries

        entries = [{"kind": "request", "verb": "eval", "ok": True}]
        assert migrate_entries(SCHEMA_VERSION, entries) is entries


class TestCompileGdbscript:
    def _entries(self):
        return [
            {"kind": "notification", "event": "stop", "payload": {}},
            {"kind": "request", "verb": "regs", "params": {}, "ok": True},
            {"kind": "request", "verb": "eval", "params": {"command": "checksec"}, "ok": True},
            {
                "kind": "request",
                "verb": "break",
                "params": {
                    "location": "main",
                    "condition": "i>1",
                    "commands": ["x/4gx $rdi"],
                    "auto_continue": True,
                },
                "ok": True,
            },
            {"kind": "request", "verb": "continue", "params": {}, "ok": True},
            {"kind": "request", "verb": "set_reg", "params": {"name": "rax", "value": "0x2"}, "ok": True},
            {"kind": "request", "verb": "write_mem", "params": {"addr": "0x1000", "hex": "9090c3"}, "ok": True},
            {"kind": "request", "verb": "snapshot_create", "params": {}, "ok": True},
            {"kind": "request", "verb": "continue", "params": {}, "ok": False, "error": "INFERIOR_RUNNING"},
        ]

    def test_full_compilation(self):
        script, stats = compile_gdbscript(
            {"session_id": "s-9", "inferior": "/tmp/vuln"}, self._entries()
        )
        lines = script.splitlines()
        assert "# session: s-9" in lines
        assert "# inferior: /tmp/vuln" in lines
        assert "checksec" in lines
        assert "break main if i>1" in lines
        # breakpoint probe compiles to a silent auto-continue block
        i = lines.index("commands")
        assert lines[i + 1 : i + 4] == ["silent", "x/4gx $rdi", "continue"]
        assert lines[i + 4] == "end"
        assert "continue" in lines
        assert "set $rax = 0x2" in lines
        # 3-byte write compiles to per-byte assignments
        assert "set {unsigned char}0x1000 = 0x90" in lines
        assert "set {unsigned char}0x1002 = 0xc3" in lines
        assert "# checkpoint create (plugin-specific; not replayable here)" in lines
        assert lines[-1] == "quit"
        assert stats["used"] == 6
        assert stats["reads"] == 1  # regs
        assert stats["skipped"] == 1  # failed continue

    def test_reads_do_not_appear_in_script(self):
        entries = [
            {"kind": "request", "verb": "read_mem", "params": {"addr": "0x1"}, "ok": True},
            {"kind": "request", "verb": "backtrace", "params": {}, "ok": True},
        ]
        script, stats = compile_gdbscript({"session_id": "s"}, entries)
        assert stats["reads"] == 2 and stats["used"] == 0
        assert "quit" in script

    def test_write_mem_degrades_on_bad_payload(self):
        entries = [
            {"kind": "request", "verb": "write_mem", "params": {"addr": "main", "hex": "90"}, "ok": True},
            {"kind": "request", "verb": "write_mem", "params": {"addr": "0x1000", "hex": "zz"}, "ok": True},
        ]
        script, stats = compile_gdbscript({"session_id": "s"}, entries)
        assert stats["skipped"] == 2 and stats["used"] == 0
        assert "set {unsigned char}" not in script
