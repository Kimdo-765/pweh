"""합성 timing/PSSH만으로 제한 선언·범위·원자 게시·원문 비노출을 검증한다."""
from __future__ import annotations

import hashlib
import json
import struct

import pytest

from pweh import media as M
from pweh.errors import PwehError
from .test_media_inventory import box, check, ftyp, run


SECRET = b"SYNTHETIC_PRIVATE_DECLARATION"
STAMP0 = 0x73514329
STAMP1 = 0x7365432151432987


def timing_payload(version=0, *, scale=1000, duration=2500, creation=0, modification=1, flags=0, tail=b""):
    fmt = ">IIIII" if version == 0 else ">IQQIQ"
    return struct.pack(fmt, (version << 24) | flags, creation, modification, scale, duration) + tail


def timing_movie(payload, *, kind=b"mvhd", extended=False):
    leaf = box(kind, payload, extended=extended)
    if kind == b"mdhd":
        leaf = box(b"trak", box(b"mdia", leaf))
    return ftyp() + box(b"moov", leaf)


def pssh_payload(version=0, *, kids=(), data=b"", size=None, flags=0):
    return (struct.pack(">I", (version << 24) | flags) + b"SYSTEM_ID_SECRET" +
            (struct.pack(">I", len(kids)) + b"".join(kids) if version else b"") +
            struct.pack(">I", len(data) if size is None else size) + data)


def pssh_movie(payload, *, parent=b"moov", extended=False):
    return ftyp() + box(parent, box(b"pssh", payload, extended=extended))


@pytest.mark.parametrize("version", [0, 1])
@pytest.mark.parametrize("kind", [b"mvhd", b"mdhd"])
@pytest.mark.parametrize("extended", [False, True])
def test_timing_fixed_prefix_and_opaque_tail(version, kind, extended):
    stamp = STAMP0 if version == 0 else STAMP1
    data = timing_movie(timing_payload(version, creation=stamp, modification=0, tail=SECRET),
                        kind=kind, extended=extended)
    report = check(run(data))
    row, = report["declarations"]["timing"]
    assert row == {"box_index": 2 if kind == b"mvhd" else 4,
                   "parent_index": 1 if kind == b"mvhd" else 3, "kind": kind.decode(),
                   "version": version, "status": "complete", "creation_time_state": "nonzero",
                   "modification_time_state": "zero", "timescale": 1000, "duration_units": 2500,
                   "duration_state": "declared", "issues": []}
    assert report["status"] == "ok" and report["coverage"]["structure_complete"]
    assert report["coverage"]["skipped_payload_bytes"] == len(SECRET)
    assert report["coverage"]["header_bytes"] == len(data) - len(SECRET)
    dumped = json.dumps(report)
    for hidden in (str(stamp), SECRET.decode(), SECRET.hex(), hashlib.sha256(SECRET).hexdigest()):
        assert hidden not in dumped


@pytest.mark.parametrize("version", [0, 1])
@pytest.mark.parametrize("scale", [0, 1, 0xffffffff])
@pytest.mark.parametrize("value", ["zero", "maximum", "indeterminate"])
def test_timing_integer_width_and_duration_states(version, scale, value):
    limit = (1 << (32 if version == 0 else 64)) - 1
    duration = {"zero": 0, "maximum": limit - 1, "indeterminate": limit}[value]
    report = check(run(timing_movie(timing_payload(version, scale=scale, duration=duration))))
    row, = report["declarations"]["timing"]
    assert row["timescale"] == scale
    assert row["duration_units"] == (None if value == "indeterminate" else duration)
    assert row["duration_state"] == ("declared" if value == "maximum" else value)
    assert row["issues"] == (["zero_timescale"] if scale == 0 else [])
    assert row["status"] == ("malformed" if scale == 0 else "complete")
    assert report["framing_status"] == "complete"
    assert report["coverage"]["structure_complete"]
    assert report["declarations"]["coverage"]["fields_complete"] == (scale != 0)
    assert report["status"] == ("partial" if scale == 0 else "ok")


@pytest.mark.parametrize("version", [0, 1])
@pytest.mark.parametrize("kind", [b"mvhd", b"mdhd"])
@pytest.mark.parametrize("size", [0, 1, 3, 4, 10, "last"])
def test_timing_short_prefix_reads_no_partial_values(version, kind, size):
    payload = timing_payload(version, creation=STAMP0, tail=b"")
    size = len(payload) - 1 if size == "last" else size
    report = check(run(timing_movie(payload[:size], kind=kind) + box(b"free", payload)))
    row, = report["declarations"]["timing"]
    assert row["version"] == (version if size >= 4 else None)
    assert row["status"] == "malformed" and row["issues"] == ["truncated_declaration_fields"]
    assert row["creation_time_state"] == row["modification_time_state"] == row["duration_state"] == "unread"
    assert row["timescale"] is row["duration_units"] is None
    # 완전한 뒤 상자가 있어도 값을 빌리지 않고 다음 framing은 계속 관찰한다.
    assert report["boxes"][-1]["kind"] == "free" and report["framing_status"] == "complete"
    leaf = report["boxes"][row["box_index"]]
    # 연속한 box_header는 부모·뒤 상자와 합쳐지므로 해당 leaf와의 교집합만 센다.
    examined = sum(max(0, min(r["offset"] + r["length"], leaf["offset"] + leaf["size"]) -
                       max(r["offset"], leaf["offset"])) for r in report["coverage"]["ranges"]
                   if r["kind"] == "header")
    assert examined == 8 + (4 if size >= 4 else 0)


@pytest.mark.parametrize("kind", [b"mvhd", b"mdhd", b"pssh"])
@pytest.mark.parametrize(("version", "flags", "issue"), [
    (2, 0, "unsupported_declaration_version"), (255, 0xffffff, "unsupported_declaration_version"),
    (0, 1, "unsupported_declaration_flags"), (1, 0xffffff, "unsupported_declaration_flags")])
def test_unsupported_fullbox_priority_and_only_fullbox_read(kind, version, flags, issue):
    payload = struct.pack(">I", (version << 24) | flags) + SECRET
    data = pssh_movie(payload) if kind == b"pssh" else timing_movie(payload, kind=kind)
    report = check(run(data))
    row, = report["declarations"]["pssh" if kind == b"pssh" else "timing"]
    assert row["version"] == (version if version in (0, 1) else None)
    assert row["status"] == "unsupported" and row["issues"] == [issue]
    assert report["coverage"]["skipped_payload_bytes"] == len(SECRET)
    assert report["declarations"]["coverage"]["reasons"] == [issue]
    assert report["framing_status"] == "complete" and report["status"] == "partial"


@pytest.mark.parametrize("version", [0, 1])
@pytest.mark.parametrize("kids", [(), (b"KID_VALUE_SECRET", b"OTHER_KID_SECRET")])
@pytest.mark.parametrize("parent", [b"moov", b"moof"])
@pytest.mark.parametrize("extended", [False, True])
def test_pssh_structure_skips_ids_and_data(version, kids, parent, extended):
    payload = pssh_payload(version, kids=kids, data=SECRET)
    report = check(run(pssh_movie(payload, parent=parent, extended=extended)))
    row, = report["declarations"]["pssh"]
    assert row == {"box_index": 2, "parent_index": 1, "version": version, "status": "complete", "issues": []}
    assert report["coverage"]["header_bytes"] == 16 + 8 + (16 if extended else 8) + (12 if version else 8)
    identifiers = 16 + (16 * len(kids) if version else 0)
    assert sum(r["length"] for r in report["coverage"]["ranges"] if r["reason"] ==
               "declaration_identifiers") == identifiers
    assert report["coverage"]["skipped_payload_bytes"] == identifiers + len(SECRET)
    dumped = json.dumps(report)
    for hidden in (b"SYSTEM_ID_SECRET", *kids, SECRET):
        for encoding in (hidden.decode(), hidden.hex(), hashlib.sha256(hidden).hexdigest()):
            assert encoding not in dumped
    for key in ("system_id", "kid", "kid_count", "data_size", "data", "hash"):
        assert key not in row


@pytest.mark.parametrize("version", [0, 1])
@pytest.mark.parametrize("size", [0, 1, 3, 4, 19, 23, "last"])
def test_pssh_short_fixed_fields(version, size):
    payload = pssh_payload(version)
    size = len(payload) - 1 if size == "last" else size
    report = check(run(pssh_movie(payload[:size])))
    row, = report["declarations"]["pssh"]
    assert row["version"] == (version if size >= 4 else None)
    assert row["status"] == "malformed" and row["issues"] == ["truncated_declaration_fields"]
    assert report["framing_status"] == "complete"


@pytest.mark.parametrize("version", [0, 1])
@pytest.mark.parametrize("size", [0, 1, 100, 0xffffffff])
def test_pssh_declared_data_length_must_end_at_box(version, size):
    report = check(run(pssh_movie(pssh_payload(version, data=b"abc", size=size)) + box()))
    row, = report["declarations"]["pssh"]
    assert row["issues"] == ["pssh_length_mismatch"] and row["status"] == "malformed"
    assert report["boxes"][-1]["kind"] == "free" and report["framing_status"] == "complete"


@pytest.mark.parametrize("count", [1, 1000000, 0xffffffff])
def test_pssh_impossible_kid_count_is_constant_work(count, monkeypatch):
    payload = struct.pack(">I", 1 << 24) + b"SYSTEM_ID_SECRET" + struct.pack(">II", count, 0)
    calls = 0
    original = M.struct.unpack_from
    def read(*args):
        nonlocal calls
        calls += 1
        return original(*args)
    monkeypatch.setattr(M.struct, "unpack_from", read)
    report = check(run(pssh_movie(payload)))
    row, = report["declarations"]["pssh"]
    assert row["issues"] == ["pssh_length_mismatch"]
    assert calls == 5  # ftyp/moov/pssh 헤더 3개와 FullBox/count만 읽는다.


def test_pssh_zero_data_and_zero_kids_are_valid():
    report = check(run(ftyp() + box(b"moov", box(b"pssh", pssh_payload()) +
                                   box(b"pssh", pssh_payload(1)))))
    assert len(report["declarations"]["pssh"]) == 2
    assert report["declarations"]["coverage"]["fields_complete"]


def test_multiple_tracks_and_duplicate_declarations_stay_separate():
    mdia = box(b"mdia", box(b"mdhd", timing_payload(scale=44100, duration=44100)))
    movie = (box(b"mvhd", timing_payload(scale=1000, duration=5000)) +
             box(b"mvhd", timing_payload(1, scale=90000, duration=180000)) +
             box(b"trak", mdia) + box(b"trak", mdia) + box(b"pssh", pssh_payload()) * 2)
    report = check(run(ftyp() + box(b"moov", movie)))
    rows = report["declarations"]["timing"]
    assert [(r["timescale"], r["duration_units"]) for r in rows] == [(1000, 5000), (90000, 180000),
                                                                            (44100, 44100), (44100, 44100)]
    assert len(report["declarations"]["pssh"]) == 2
    assert report["declarations"]["status"] == "complete"


@pytest.mark.parametrize("kind", [b"mvhd", b"mdhd", b"pssh"])
@pytest.mark.parametrize("wrap", [lambda data: data, lambda data: box(b"moov", box(b"trak", data)),
                                  lambda data: box(b"moov", box(b"mvex", data))])
def test_known_declaration_in_wrong_context_is_skipped(kind, wrap):
    report = check(run(ftyp() + wrap(box(kind, SECRET))))
    leaf = report["boxes"][-1]
    assert leaf["kind"] == kind.decode() and leaf["handling"] == "skipped"
    assert report["coverage"]["ranges"][-1]["reason"] == "unsupported_context"
    assert report["declarations"]["timing"] == report["declarations"]["pssh"] == []
    assert report["declarations"]["status"] == "complete"


@pytest.mark.parametrize("kind", [b"mdat", b"meta", b"udta", b"uuid", b"ZZZZ", b"stsd"])
def test_opaque_boxes_do_not_search_for_declarations(kind):
    fake = box(b"mvhd", timing_payload()) + box(b"pssh", pssh_payload())
    report = check(run(ftyp() + box(b"moov", box(kind, fake))))
    assert report["declarations"]["timing"] == report["declarations"]["pssh"] == []
    assert len(report["boxes"]) == 3


def test_fragment_without_brand_keeps_existing_unsupported_meaning():
    report = check(run(box(b"moof", box(b"pssh", pssh_payload()))))
    assert report["recognition"] == "fragment_candidate" and report["status"] == "unsupported"
    assert report["declarations"]["status"] == "complete"


def test_non_declaration_reasons_do_not_pollute_declaration_coverage():
    report = check(run(ftyp() * 2 + box(b"wide", b"extra")))
    assert report["status"] == "partial"
    assert report["declarations"]["status"] == "complete"
    assert report["declarations"]["coverage"]["reasons"] == []


@pytest.mark.parametrize("at", range(1, 8))
def test_deadline_in_leaf_and_atomic_emit_keeps_only_previous_rows(monkeypatch, at):
    first = box(b"mvhd", timing_payload())
    second = box(b"mvhd", timing_payload(scale=0))
    data = ftyp() + box(b"moov", first + second) + box()
    target = len(ftyp()) + 8 + len(first)
    original = M._Parser.check
    calls = 0
    now = 0
    def checkpoint(self, offset, *, deadline=True):
        nonlocal calls, now
        if offset == target and deadline:
            calls += 1
            if calls == at:
                now = 2
        return original(self, offset, deadline=deadline)
    monkeypatch.setattr(M._Parser, "check", checkpoint)
    monkeypatch.setattr(M.time, "monotonic", lambda: now)
    report = check(run(data, deadline=1))
    assert len(report["declarations"]["timing"]) == 1
    assert len(report["boxes"]) == 3
    assert report["coverage"]["reasons"] == ["time_limit"]
    assert report["declarations"]["coverage"] == {"traversal_complete": False, "fields_complete": True,
                                                    "reasons": ["time_limit"]}
    assert report["coverage"]["ranges"][-1] == {"offset": target, "length": len(data) - target,
                                                "kind": "unexamined", "reason": "time_limit"}


@pytest.mark.parametrize("at", range(1, 8))
def test_cancel_in_leaf_or_emit_returns_no_partial_report(monkeypatch, at):
    original = M._Parser.check
    target, calls, cancelled = len(ftyp()) + 8, 0, False
    def checkpoint(self, offset, *, deadline=True):
        nonlocal calls, cancelled
        if offset == target and deadline:
            calls += 1
            if calls == at:
                cancelled = True
        return original(self, offset, deadline=deadline)
    monkeypatch.setattr(M._Parser, "check", checkpoint)
    with pytest.raises(PwehError) as exc:
        run(timing_movie(timing_payload()), cancel=lambda: cancelled)
    assert exc.value.code == "cancelled"


@pytest.mark.parametrize("limit", range(1, 10))
def test_range_limit_rolls_back_row_and_semantic_issue(limit):
    malformed = pssh_payload(1, kids=(b"KID_VALUE_SECRET",), data=SECRET, size=0)
    data = pssh_movie(malformed) + box()
    report = check(run(data, limits=M.MediaLimits(max_ranges=limit)))
    rows = report["declarations"]["pssh"]
    assert ("pssh_length_mismatch" in report["coverage"]["reasons"]) == bool(rows)
    assert len(report["coverage"]["ranges"]) <= limit
    if not rows and len(report["boxes"]) == 2:
        assert report["coverage"]["ranges"][-1]["offset"] == len(ftyp()) + 8


@pytest.mark.parametrize("limit", [4096, 8192, 16384])
def test_output_limit_counts_all_rows_and_keeps_atomic_tail(limit):
    movie = box(b"mvhd", timing_payload(scale=0, tail=SECRET)) * 100
    report = check(run(ftyp() + box(b"moov", movie), limits=M.MediaLimits(max_output_bytes=limit)))
    rows = report["declarations"]["timing"]
    assert "output_limit" in report["coverage"]["reasons"]
    assert len(rows) == sum(b["handling"] == "declaration" for b in report["boxes"])
    assert ("zero_timescale" in report["coverage"]["reasons"]) == bool(rows)
    assert len(json.dumps(report, separators=(",", ":")).encode()) <= limit


@pytest.mark.parametrize("limit", [1, 2, 3, 4])
def test_box_limit_retains_only_published_declarations(limit):
    data = ftyp() + box(b"moov", box(b"mvhd", timing_payload()) * 4)
    report = check(run(data, limits=M.MediaLimits(max_boxes=limit)))
    assert report["coverage"]["reasons"] == ["box_limit"]
    assert len(report["declarations"]["timing"]) == max(0, limit - 2)


def test_empty_input_has_complete_empty_declaration_scope():
    report = check(run(b""))
    assert report["status"] == "unsupported" and report["declarations"]["status"] == "complete"
    assert report["declarations"]["timing"] == report["declarations"]["pssh"] == []
