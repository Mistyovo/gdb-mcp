"""Exploit campaign state: what the session has established so far.

The server maintains a small structured record per session — protections,
libc leaks, derived offsets, demonstrated primitives — so the model stops
re-deriving it every turn. Everything here is deterministic bookkeeping:
values enter only via explicit tool calls or the cyclic oracle, and every
primitive claim carries an evidence timestamp.
"""

from __future__ import annotations

import string
import time

_SECTIONS = ("protections", "libc", "offsets", "primitives", "notes")
_SECTION_CAP = 64
_NOTES_CAP = 32
_MAX_PATTERN = 65536

# --- cyclic pattern (de Bruijn, pwntools-compatible lowercase alphabet) -----

_CYCLE_CACHE: dict[int, bytes] = {}


def debruijn_bytes(sub: int = 4, alphabet: str = string.ascii_lowercase) -> bytes:
    """de Bruijn sequence over ``alphabet`` with ``sub``-length
    subsequences — same layout pwntools' ``cyclic`` produces."""
    cached = _CYCLE_CACHE.get(sub)
    if cached is not None and len(cached) >= _MAX_PATTERN:
        return cached[:_MAX_PATTERN]
    k = len(alphabet)
    a = [0] * (k * sub)
    sequence: list[int] = []

    def db(t: int, p: int) -> None:
        if t > sub:
            if sub % p == 0:
                sequence.extend(a[1 : p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    raw = "".join(alphabet[i] for i in sequence).encode("ascii")
    _CYCLE_CACHE[sub] = raw
    return raw[:_MAX_PATTERN]


def cyclic_pattern(count: int, sub: int = 4) -> str:
    count = max(0, min(int(count), _MAX_PATTERN))
    return debruijn_bytes(sub).decode("ascii")[:count]


def match_cyclic(value: int, sub: int = 4) -> dict | None:
    """Locate a value inside the cyclic pattern (little-endian, the way a
    buffer overflow loads it into a register). Returns the smallest buffer
    offset whose sub-sequence appears in the value, or None."""
    if value <= 0:
        return None
    seq = debruijn_bytes(sub)
    width = max(1, (value.bit_length() + 7) // 8)
    data = value.to_bytes(width, "little")
    best: int | None = None
    for start in range(0, max(1, len(data) - sub + 1)):
        chunk = data[start : start + sub]
        idx = seq.find(chunk)
        if idx != -1 and (best is None or idx < best):
            best = idx
    if best is None:
        return None
    return {"offset": best, "sub": sub}


# --- campaign bookkeeping ----------------------------------------------------


def new_campaign() -> dict:
    return {section: {} for section in _SECTIONS[:4]} | {"notes": []}


def campaign_set(data: dict, section: str, key: str, value, evidence=None) -> dict:
    if section not in _SECTIONS[:4]:
        raise ValueError("section must be one of %s" % ", ".join(_SECTIONS[:4]))
    bucket = data.setdefault(section, {})
    if len(bucket) >= _SECTION_CAP and key not in bucket:
        raise ValueError("section %r is full" % section)
    text = value if isinstance(value, str) else str(value)
    if len(text) > 2048:
        text = text[:2048] + "...<+%d chars>" % (len(text) - 2048)
    entry = {"value": text, "ts": round(time.time(), 3)}
    if evidence:
        entry["evidence"] = str(evidence)[:256]
    bucket[str(key)[:128]] = entry
    return data


def campaign_note(data: dict, text: str) -> dict:
    notes = data.setdefault("notes", [])
    notes.append({"text": str(text)[:512], "ts": round(time.time(), 3)})
    del notes[:-_NOTES_CAP]
    return data


def campaign_detect(data: dict, stop_info: dict) -> dict | None:
    """Run the cyclic oracle over the last stop's pc/fault/registers;
    a pattern hit on PC is recorded as a pc-control primitive candidate."""
    candidates: list[tuple[str, int]] = []
    for name in ("pc", "fault_addr"):
        raw = stop_info.get(name)
        if isinstance(raw, str) and raw.startswith("0x"):
            try:
                candidates.append((name, int(raw, 16)))
            except ValueError:
                pass
    for name, raw in (stop_info.get("registers") or {}).items():
        if isinstance(raw, str) and raw.startswith("0x"):
            try:
                candidates.append(("reg:%s" % name, int(raw, 16)))
            except ValueError:
                pass
    for source, value in candidates:
        match = match_cyclic(value)
        if match is not None:
            primitives = data.setdefault("primitives", {})
            primitives["pc_control"] = {
                "value": "candidate",
                "ts": round(time.time(), 3),
                "evidence": "%s matches cyclic pattern at offset %d"
                % (source, match["offset"]),
            }
            return {"source": source, **match}
    return None


def campaign_summary(data: dict) -> list[str]:
    """3-6 compact lines for injection into stop responses."""
    lines: list[str] = []
    primitives = data.get("primitives") or {}
    if primitives:
        names = ", ".join(sorted(primitives))
        lines.append("campaign primitives: %s" % names)
    offsets = data.get("offsets") or {}
    for key in list(offsets)[:3]:
        lines.append(
            "campaign offset %s = %s" % (key, offsets[key].get("value"))
        )
    libc = data.get("libc") or {}
    for key in list(libc)[:2]:
        lines.append("campaign libc %s = %s" % (key, libc[key].get("value")))
    notes = data.get("notes") or []
    if notes:
        lines.append("campaign note: %s" % notes[-1]["text"][:160])
    return lines[:6]


def is_empty(data: dict) -> bool:
    return not any(
        (data or {}).get(section) for section in _SECTIONS
    )


def sanitize_campaign(data) -> dict:
    """Validate a campaign dict loaded from persistence (or anywhere
    outside this module). Campaign content is re-injected into model
    context via stop briefs, so nothing malformed or oversized is
    trusted: malformed sections/entries are dropped, strings clamped."""
    clean = new_campaign()
    if not isinstance(data, dict):
        return clean
    for section in _SECTIONS[:4]:
        bucket = data.get(section)
        if not isinstance(bucket, dict):
            continue
        for key, entry in list(bucket.items())[:_SECTION_CAP]:
            if not isinstance(key, str) or not isinstance(entry, dict):
                continue
            value = entry.get("value")
            if not isinstance(value, str) or not value:
                continue
            if len(value) > 2048:
                value = value[:2048] + "...<+%d chars>" % (len(value) - 2048)
            clean_entry = {
                "value": value,
                "ts": entry.get("ts"),
            }
            if isinstance(entry.get("evidence"), str):
                clean_entry["evidence"] = entry["evidence"][:256]
            clean[section][key[:128]] = clean_entry
    notes = data.get("notes")
    if isinstance(notes, list):
        for note in notes[-_NOTES_CAP:]:
            if isinstance(note, dict) and isinstance(note.get("text"), str):
                clean["notes"].append(
                    {"text": note["text"][:512], "ts": note.get("ts")}
                )
    return clean
