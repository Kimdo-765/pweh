"""합성 헤더만으로 후보 prefix·상한·출력 비노출을 확인한다."""
from __future__ import annotations

import copy
import dataclasses
import json
import random
import struct
import time
from types import SimpleNamespace

import pytest

from pweh import media_candidates as M
from pweh.errors import PwehError, ValidationFailed
from pweh.schemas import validate

PRIVATE = b"PRIVATE_SYNTHETIC_CANDIDATE_482"


def box(kind=b"free", payload=b"", *, extended=False, size=None):
    length = (16 if extended else 8) + len(payload)
    head = struct.pack(">I4s", 1 if extended else length if size is None else size, kind)
    return head + (struct.pack(">Q", length if size is None else size) if extended else b"") + payload


def ftyp(major=b"isom", compatible=(), **kwargs):
    return box(b"ftyp", major + b"PRIV" + b"".join(compatible), **kwargs)


def run(data, **kwargs):
    kwargs.setdefault("deadline", time.monotonic() + 30)
    return M.scan_bmff_candidates(data, **kwargs)


def envelope(report):
    result = copy.deepcopy(report)
    result["source"] = {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a" * 64,
        "container": "file", "member_selected": False, "selected_sha256": "b" * 64,
        "selected_size": result["coverage"]["input_bytes"], "complete": True, "method": "whole-file",
        "confidence": "high", "partition": None, "ref": None, "deleted": None, "parent_deleted": None,
        "container_truncated": None, "container_truncated_reasons": []}
    result["params"] = {"partition": None, "method": "auto", "max_seconds": 45}
    return result


def check(report, data, limits=M.BmffCandidateLimits()):
    validate("media-candidates", envelope(report))
    cov, summary, rows = report["coverage"], report["summary"], report["candidates"]
    n, p = max(0, len(data) - 7), cov["search_positions_examined"]
    assert cov["input_bytes"] == len(data) and cov["search_positions_total"] == n
    assert 0 <= p <= n
    if cov["search_complete"]:
        assert p == n and cov["unexamined_positions"] is None and cov["pending_anchor_offset"] is None
    else:
        assert p < n
        assert cov["unexamined_positions"] == {"start": p, "count": n-p,
                                               "reason": cov["unexamined_positions"]["reason"]}
    pending = cov["pending_anchor_offset"]
    assert pending is None or (pending == p and data[p+4:p+8] == b"ftyp")
    found = [i for i in range(p) if data[i+4:i+8] == b"ftyp"]
    assert summary["anchors_observed"] == len(found) + int(pending is not None)
    assert summary["candidates_reported"] == len(rows)
    assert summary["anchors_rejected"] == sum(summary["anchor_rejections"].values())
    assert summary["candidates_omitted"] == summary["supported_anchors"] - len(rows)
    if cov["candidate_list_complete"]:
        assert cov["search_complete"] and cov["candidate_checks_complete"] and not summary["candidates_omitted"]
    assert [row["index"] for row in rows] == list(range(len(rows)))
    assert [row["offset"] for row in rows] == sorted({row["offset"] for row in rows})
    for row in rows:
        assert data[row["offset"]+4:row["offset"]+8] == b"ftyp"
        assert 16 <= row["validated_prefix_length"] <= len(data) - row["offset"]
        assert row["boxes_validated"] == sum(row["box_counts"].values()) <= limits.max_boxes_per_candidate
        assert row["box_counts"]["ftyp"] == 1
        assert row["offset"] < p or row["offset"] == pending
        for key in ("overlap_with_reported", "contained_by_reported"):
            assert row[key] == sorted(set(row[key]))
            assert all(0 <= i < len(rows) and i != row["index"] for i in row[key])
        for i in row["overlap_with_reported"]:
            assert row["index"] in rows[i]["overlap_with_reported"]
    assert cov["relation_pairs_total"] == len(rows)*(len(rows)-1)//2
    assert cov["relation_pairs_examined"] <= cov["relation_pairs_total"]
    if cov["relations_complete"]:
        assert cov["relation_pairs_examined"] == cov["relation_pairs_total"]
    for key, limit in (("anchor_probes", "max_anchor_probes"), ("boxes_examined", "max_boxes_total"),
                       ("brand_slots_examined", "max_brands_total"), ("structure_bytes_read", "max_structure_bytes")):
        assert cov[key] <= getattr(limits, limit)
    assert len(rows) <= limits.max_candidates
    assert len(json.dumps(report, ensure_ascii=True, separators=(",", ":")).encode()) <= limits.max_output_bytes
    return report


@pytest.mark.parametrize("data", [b"", b"x", b"ftyp", b"xxxftyp", b"nothing recognized"])
def test_empty_domain_or_unrecognized_has_complete_search_not_media_claim(data):
    report = check(run(data), data)
    assert report["status"] == "unsupported"
    assert report["candidates"] == []
    assert not report["physical_carving_performed"]


@pytest.mark.parametrize("extended", [False, True])
def test_known_brand_and_allowed_top_level_boxes(extended):
    data = ftyp(b"xxxx", [b"qt  ", b"isom", b"isom"], extended=extended)
    data += b"".join(box(kind.encode(), b"U" * 16 if kind == "uuid" else b"", extended=extended and kind != "wide")
                      for kind in M.BOX_KINDS if kind != "ftyp")
    report = check(run(data), data)
    assert report["status"] == "ok"
    row = report["candidates"][0]
    assert row["known_brands"] == ["isom", "quicktime"]
    assert all(count == 1 for count in row["box_counts"].values())
    assert row["validated_prefix_length"] == len(data)


@pytest.mark.parametrize("data,reason", [
    (ftyp(size=0), "size_zero"),
    (struct.pack(">I4s", 1, b"ftyp"), "truncated_extended_header"),
    (ftyp(size=7), "size_below_header"),
    (ftyp(size=1000), "box_beyond_selection"),
    (box(b"ftyp", b"1234"), "invalid_ftyp_shape"),
    (box(b"ftyp", b"123456789"), "invalid_ftyp_shape"),
    (ftyp(b"xxxx", [b"zzzz"]), "unknown_brand"),
])
def test_rejected_anchors_are_complete_unsupported(data, reason):
    report = check(run(data), data)
    assert report["status"] == "unsupported"
    assert report["summary"]["anchor_rejections"][reason] == 1
    assert report["coverage"]["candidate_checks_complete"]


@pytest.mark.parametrize("suffix,reason", [
    (b"abc", "truncated_header"),
    (box(size=0), "size_zero"),
    (struct.pack(">I4s", 1, b"free"), "truncated_extended_header"),
    (box(b"uuid", size=24), "truncated_uuid_header"),
    (box(size=7), "size_below_header"),
    (box(size=1000), "box_beyond_selection"),
    (box(b"SECR", PRIVATE), "unknown_next_type"),
    (box(b"wide", b"1234"), "unsupported_wide_shape"),
    (box(b"wide", extended=True), "unsupported_wide_shape"),
])
def test_partial_chain_is_processed_but_not_complete_framing(suffix, reason):
    data = ftyp() + suffix
    report = check(run(data), data)
    assert report["status"] == "partial"
    assert report["coverage"]["search_complete"] and report["coverage"]["candidate_checks_complete"]
    assert report["candidates"][0]["end_reason"] == reason
    assert report["candidates"][0]["validated_prefix_length"] == 16


def test_adjacent_anchors_and_size_zero_next_anchor():
    data = ftyp() + ftyp(size=0)
    report = check(run(data), data)
    assert report["status"] == "ok"
    assert report["candidates"][0]["end_reason"] == "next_ftyp"
    assert report["summary"]["anchor_rejections"]["size_zero"] == 1


@pytest.mark.parametrize("offset", range(65527, 65540))
def test_find_window_overlap_has_exact_header_position_prefix(offset):
    data = b"\x00" * offset + ftyp()
    report = check(run(data), data)
    assert report["summary"]["anchors_observed"] == 1
    assert report["candidates"][0]["offset"] == offset


def nested(count):
    data = ftyp()
    for _ in range(count - 1):
        data = ftyp() + box(b"mdat", data)
    return data


def test_nested_payload_anchors_overlap_and_containment_are_reported_only():
    data = nested(4)
    report = check(run(data), data)
    assert report["status"] == "ok"
    assert [row["offset"] for row in report["candidates"]] == [0, 24, 48, 72]
    for i, row in enumerate(report["candidates"]):
        assert row["overlap_with_reported"] == [j for j in range(4) if i != j]
        assert row["contained_by_reported"] == list(range(i))


def test_touching_intervals_are_not_overlaps():
    data = ftyp() * 3
    report = check(run(data), data)
    assert all(not row["overlap_with_reported"] for row in report["candidates"])
    assert report["coverage"]["relation_pairs_examined"] == 3


@pytest.mark.parametrize("changes,data,offset,reason,rows", [
    ({"max_anchor_probes": 1}, ftyp()*2, 16, "probe_limit", 1),
    ({"max_candidates": 1}, ftyp()*2, 16, "candidate_limit", 1),
    ({"max_boxes_per_candidate": 1}, ftyp()+box(), 0, "box_limit", 1),
    ({"max_boxes_total": 1}, ftyp()+box(), 0, "box_limit", 1),
    ({"max_brands_per_anchor": 1}, ftyp(compatible=[b"iso2"]), 0, "brand_limit", 0),
    ({"max_brands_total": 1}, ftyp()*2, 16, "brand_limit", 1),
    ({"max_structure_bytes": 8}, ftyp(), 0, "structure_byte_limit", 0),
    ({"max_structure_bytes": 12}, ftyp()+box(), 0, "structure_byte_limit", 1),
    ({"max_output_bytes": 8192}, ftyp()*5, 64, "output_limit", 4),
])
def test_current_anchor_limits_stop_global_search(changes, data, offset, reason, rows):
    limits = dataclasses.replace(M.BmffCandidateLimits(), **changes)
    report = check(run(data, limits=limits), data, limits)
    cov = report["coverage"]
    assert report["status"] == "partial" and len(report["candidates"]) == rows
    assert cov["pending_anchor_offset"] == cov["search_positions_examined"] == offset
    assert not cov["candidate_checks_complete"] and not cov["candidate_list_complete"]
    assert reason in cov["reasons"]
    if rows and report["candidates"][-1]["offset"] == offset:
        assert report["candidates"][-1]["end_reason"] == reason


def test_relation_output_limit_preserves_search_and_rows_atomically():
    data = nested(4)
    limits = dataclasses.replace(M.BmffCandidateLimits(), max_output_bytes=8192)
    report = check(run(data, limits=limits), data, limits)
    cov = report["coverage"]
    assert cov["search_complete"] and cov["candidate_checks_complete"] and cov["candidate_list_complete"]
    assert not cov["relations_complete"] and cov["relation_pairs_examined"] == 0
    assert report["summary"]["candidates_omitted"] == 0
    assert all(not row["overlap_with_reported"] for row in report["candidates"])
    assert report["status"] == "partial" and cov["reasons"] == ["output_limit"]


def test_relation_output_can_stop_after_atomic_pair_prefix():
    data = nested(4)
    limits = dataclasses.replace(M.BmffCandidateLimits(), max_output_bytes=8195)
    report = check(run(data, limits=limits), data, limits)
    assert report["coverage"]["relation_pairs_examined"] == 1
    assert report["candidates"][0]["overlap_with_reported"] == [1]
    assert report["candidates"][1]["overlap_with_reported"] == [0]
    assert report["candidates"][1]["contained_by_reported"] == [0]


def test_deadline_between_windows_preserves_exact_nonanchor_prefix(monkeypatch):
    clock = {"now": 0.0, "checks": 0}
    monkeypatch.setattr(M, "time", SimpleNamespace(monotonic=lambda: clock["now"]))
    def cancel():
        clock["checks"] += 1
        if clock["checks"] == 3:
            clock["now"] = 2.0
        return False
    data = b"x" * 140000
    report = check(run(data, deadline=1, cancel=cancel), data)
    cov = report["coverage"]
    assert cov["search_positions_examined"] == 65533
    assert cov["pending_anchor_offset"] is None and cov["candidate_checks_complete"]


def test_deadline_in_chain_retains_partial_row_and_pending(monkeypatch):
    monkeypatch.setattr(M, "time", SimpleNamespace(monotonic=lambda: 0.0))
    original = M._Scanner.header
    def header(self, offset, **kwargs):
        if offset == 16:
            raise M._Limit("time_limit")
        return original(self, offset, **kwargs)
    monkeypatch.setattr(M._Scanner, "header", header)
    data = ftyp() + box()
    report = check(run(data, deadline=1), data)
    assert report["coverage"]["pending_anchor_offset"] == 0
    assert report["candidates"][0]["end_reason"] == "time_limit"


def test_relation_time_limit_does_not_undo_search(monkeypatch):
    original = M._Scanner.relations
    def relations(self):
        self.deadline = -1
        return original(self)
    monkeypatch.setattr(M._Scanner, "relations", relations)
    data = nested(2)
    report = check(run(data), data)
    assert report["coverage"]["candidate_list_complete"]
    assert not report["coverage"]["relations_complete"]
    assert report["coverage"]["pending_anchor_offset"] is None


@pytest.mark.parametrize("value", [True, None, "secret", float("nan"), float("inf"), 10**400])
def test_invalid_deadline_is_fixed_error(value):
    with pytest.raises(ValidationFailed) as error:
        run(ftyp(), deadline=value)
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("field", [f.name for f in dataclasses.fields(M.BmffCandidateLimits)])
def test_limits_are_frozen_and_can_only_be_lowered(field):
    base = M.BmffCandidateLimits()
    for value in (True, 0, getattr(base, field)+1):
        with pytest.raises(ValidationFailed):
            run(ftyp(), limits=dataclasses.replace(base, **{field: value}))
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(base, field, 1)


@pytest.mark.parametrize("data", [bytearray(b"x"), memoryview(b"x"), None, "private"])
def test_exact_bytes_only(data):
    with pytest.raises(ValidationFailed):
        run(data)


def test_size_limit_does_not_silently_scan_prefix():
    with pytest.raises(ValidationFailed):
        run(ftyp(), limits=dataclasses.replace(M.BmffCandidateLimits(), max_input_bytes=15))


@pytest.mark.parametrize("callback,code", [(lambda: True, "cancelled"), (lambda: 1, "media_candidates_failed")])
def test_cancel_and_invalid_callback_return(callback, code):
    with pytest.raises(PwehError) as error:
        run(ftyp(), cancel=callback)
    assert error.value.code == code


def test_callback_exception_has_no_original_message_or_context():
    def fail():
        raise ValueError(PRIVATE.decode())
    with pytest.raises(PwehError) as error:
        run(ftyp(), cancel=fail)
    assert error.value.code == "media_candidates_failed"
    assert error.value.__context__ is None and PRIVATE.decode() not in str(error.value)


def test_raw_payload_uuid_unknown_brand_and_minor_are_never_output():
    data = ftyp(b"SECR", [b"isom"]) + box(b"uuid", b"SECRET_UUID_12345"+PRIVATE) + box(b"mdat", PRIVATE)
    report = check(run(data), data)
    text = json.dumps(report)
    for raw in ("SECR", "PRIV", "SECRET_UUID_12345", PRIVATE.decode()):
        assert raw not in text
    assert "sha256" not in text and "recovered_length" not in text


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(raw="secret"),
    lambda d: d.update(media_decoded=True),
    lambda d: d["candidates"][0].update(raw_fourcc="SECR"),
    lambda d: d["candidates"][0].update(end_reason="secret"),
    lambda d: d["source"].update(path="secret"),
    lambda d: d["params"].update(method="empty"),
    lambda d: d["coverage"].update(container_examined=True),
])
def test_closed_schema_rejects_unpromised_fields_and_values(mutate):
    result = envelope(run(ftyp()))
    mutate(result)
    with pytest.raises(ValidationFailed):
        validate("media-candidates", result)


def test_deterministic_small_synthetic_combinations_and_lower_limits():
    rng = random.Random(482)
    pieces = [b"", b"x", b"ftyp", ftyp(), ftyp(size=0), ftyp(b"zzzz"), box(),
              box(b"mdat", ftyp()), box(b"SECR", b"hidden"), struct.pack(">I4s", 1, b"ftyp")]
    for _ in range(120):
        data = b"".join(rng.choice(pieces) for _ in range(rng.randrange(1, 12)))
        limits = dataclasses.replace(M.BmffCandidateLimits(), max_anchor_probes=rng.randrange(1, 8),
            max_candidates=rng.randrange(1, 6), max_boxes_total=rng.randrange(1, 24),
            max_structure_bytes=rng.randrange(1, 300), max_brands_total=rng.randrange(1, 8))
        check(run(data, limits=limits), data, limits)


def test_reserved_envelope_and_row_cover_maximum_fixed_field_sizes():
    # 독립적으로 가장 긴 수치/고정 문자열을 넣어 예약 상계를 확인한다.
    report = M._new(64 << 20)
    report["status"] = "partial"
    summary, cov = report["summary"], report["coverage"]
    for key in summary:
        if key != "anchor_rejections":
            summary[key] = 1025
    summary["anchor_rejections"] = dict.fromkeys(M.REJECTIONS, 1024)
    for key, value in tuple(cov.items()):
        if type(value) is int:
            cov[key] = 64 << 20
        elif type(value) is bool:
            cov[key] = False  # false는 true보다 한 글자 길다.
    cov["pending_anchor_offset"] = (64 << 20)-8
    cov["unexamined_positions"] = {"start": (64 << 20)-8, "count": (64 << 20)-7,
                                   "reason": "structure_byte_limit"}
    cov["reasons"] = list(M.REASONS)
    assert len(json.dumps(report, separators=(",", ":"))) <= M._ENVELOPE_RESERVE
    row = run(ftyp())["candidates"][0]
    row.update(index=127, offset=(64 << 20)-16, validated_prefix_length=64 << 20, boxes_validated=1024,
               box_counts={name: 1 if name == "ftyp" else 1023 for name in M.BOX_KINDS},
               known_brands=list(M.BRANDS), end_reason=max(M.END_REASONS, key=len), framing_status="partial")
    # 배열의 row 사이 comma도 예약에 포함한다.
    assert len(json.dumps(row, separators=(",", ":"))) + 1 <= M._ROW_RESERVE


def test_maximum_candidate_count_and_relation_matrix_stay_bounded():
    data = nested(128)
    report = check(run(data), data)
    assert report["status"] == "ok" and len(report["candidates"]) == 128
    assert report["coverage"]["relation_pairs_examined"] == 8128
    assert report["candidates"][-1]["contained_by_reported"] == list(range(127))
    assert report["candidates"][0]["overlap_with_reported"] == list(range(1, 128))


def test_caller_deadline_is_capped_to_shared_45_seconds(monkeypatch):
    state = {"now": 0.0, "checks": 0}
    monkeypatch.setattr(M, "time", SimpleNamespace(monotonic=lambda: state["now"]))
    def cancel():
        state["checks"] += 1
        if state["checks"] == 3:
            state["now"] = 46.0
        return False
    data = ftyp()
    report = check(run(data, deadline=10**100, cancel=cancel), data)
    assert report["status"] == "partial"
    assert report["coverage"]["pending_anchor_offset"] == 0
    assert report["coverage"]["reasons"] == ["time_limit"]
