"""합성 reader로 BMFF 전역 예산·재개·기존 bytes 구조 검사 호환을 검증한다."""
from __future__ import annotations

import copy
from dataclasses import fields, replace
import json
import random
import struct
import time
from types import SimpleNamespace

import pytest

from pweh import bmff_stream as M, media_candidates as B
from pweh.errors import PwehError, ValidationFailed
from pweh.schemas import validate

PRIVATE = b"PRIVATE_SYNTHETIC_BMFF_739"


def box(kind=b"free", payload=b"", *, extended=False, size=None):
    n = (16 if extended else 8) + len(payload) if size is None else size
    return struct.pack(">I4s", 1 if extended else n, kind) + (struct.pack(">Q", n) if extended else b"") + payload


def ftyp(major=b"isom", compatible=(), **kwargs):
    return box(b"ftyp", major + b"PRIV" + b"".join(compatible), **kwargs)


def envelope(report):
    result = copy.deepcopy(report)
    c = result["coverage"]
    result["source"] = {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a" * 64,
                        "evidence_size": c["evidence_size"]}
    result["params"] = {"start_offset": c["start_offset"], "max_scan_bytes": c["max_scan_bytes"], "max_seconds": 45}
    return result


def check(report, calls=(), limits=M.BmffScanLimits()):
    M.validate_bmff_scan_accounting(report)
    full = envelope(report)
    validate("bmff-scan", full)
    M.validate_bmff_scan_accounting(full)
    c = report["coverage"]
    if calls:
        assert sum(n for _, n in calls) == c["total_bytes_read"]
        assert len(calls) == c["search_read_calls"] + c["structure_read_calls"]
    assert c["total_bytes_read"] <= c["max_scan_bytes"] + limits.max_structure_bytes
    assert c["structure_bytes_read"] <= limits.max_structure_bytes
    assert len(json.dumps(full, ensure_ascii=True, separators=(",", ":")).encode()) + 1 <= limits.max_output_bytes
    assert PRIVATE.decode() not in json.dumps(full)
    assert all(report[field] is False for field in M.FALSE_FIELDS)
    return report


def run(data, **kwargs):
    calls = []
    def read(offset, length):
        assert 0 <= offset <= len(data) - length and 1 <= length <= 65536
        calls.append((offset, length))
        return data[offset:offset + length]
    kwargs.setdefault("deadline", time.monotonic() + 30)
    result = M.scan_bmff_stream(read, evidence_size=len(data), **kwargs)
    return check(result, calls, kwargs.get("limits", M.BmffScanLimits()))


def sparse(size, blocks):
    calls = []
    def read(offset, length):
        assert 0 <= offset <= size - length and 1 <= length <= 65536
        calls.append((offset, length))
        out = bytearray(length)
        for start, data in blocks:
            left, right = max(offset, start), min(offset + length, start + len(data))
            if left < right:
                out[left-offset:right-offset] = data[left-start:right-start]
        return bytes(out)
    return read, calls


@pytest.mark.parametrize("length", range(1, 10))
@pytest.mark.parametrize("at_end", [False, True])
def test_short_domain_and_explicit_end(length, at_end):
    result = run(b"x" * length, start_offset=length if at_end else 0)
    c = result["coverage"]
    assert result["status"] == "unsupported" and c["search_complete"]
    assert c["whole_evidence_search_complete"] is (not at_end)
    if at_end or length < 8:
        assert c["total_bytes_read"] == 0


@pytest.mark.parametrize("offset", range(65528, 65544))
@pytest.mark.parametrize("extended", [False, True])
def test_header_crosses_window_once(offset, extended):
    result = run(b"x" * offset + ftyp(extended=extended))
    assert result["summary"]["anchors_observed"] == 1
    assert result["candidates"][0]["offset"] == offset
    assert result["candidates"][0]["end_reason"] == "evidence_end"


@pytest.mark.parametrize("budget", [8, 9, 15, 16, 31, 64, 65536])
def test_continuation_handles_final_seven_bytes_without_duplicates(budget):
    data = b"x" * 17 + ftyp() + b"x" * 7 + ftyp() + b"x" * 9
    offsets, start = [], 0
    for _ in range(len(data)):
        report = run(data, start_offset=start, max_scan_bytes=budget)
        offsets += [r["offset"] for r in report["candidates"]]
        c = report["coverage"]
        assert c["positions_before_start"] + c["search_positions_examined"] + (c["unexamined_positions"] or {}).get("count", 0) == len(data)-7
        if c["next_offset"] is None:
            break
        assert c["next_offset"] > start
        start = c["next_offset"]
    else:
        pytest.fail("유한 검색이 진전하지 않음")
    assert offsets == [17, 40]


@pytest.mark.parametrize("data,reason", [
    (ftyp(size=0), "size_zero"), (box(b"ftyp", size=1), "truncated_extended_header"),
    (ftyp(size=7), "size_below_header"), (ftyp(size=1000), "box_beyond_evidence"),
    (box(b"ftyp", b"1234"), "invalid_ftyp_shape"), (box(b"ftyp", b"123456789"), "invalid_ftyp_shape"),
    (ftyp(b"xxxx", [b"xxxx"]), "unknown_brand"),
])
def test_rejected_anchor_is_classified_without_prefix(data, reason):
    result = run(data)
    assert result["summary"]["anchor_rejections"][reason] == 1
    assert result["status"] == "unsupported" and result["coverage"]["candidate_checks_complete"]


@pytest.mark.parametrize("suffix,reason", [
    (b"x", "truncated_header"), (box(size=0), "size_zero"),
    (box(size=1), "truncated_extended_header"), (box(b"uuid", size=24), "truncated_uuid_header"),
    (box(size=7), "size_below_header"), (box(size=1000), "box_beyond_evidence"),
    (box(b"HIDE", PRIVATE), "unknown_next_type"), (box(b"wide", b"abcd"), "unsupported_wide_shape"),
    (box(b"wide", extended=True), "unsupported_wide_shape"),
])
def test_partial_framing_is_not_an_unexamined_chain(suffix, reason):
    result = run(ftyp() + suffix)
    row = result["candidates"][0]
    assert row["end_reason"] == reason and row["validated_prefix_length"] == 16
    assert result["coverage"]["candidate_checks_complete"]
    assert result["summary"]["chain_limited_candidates"] == 0
    assert result["status"] == "partial"


@pytest.mark.parametrize("extended", [False, True])
def test_every_fixed_box_and_brand_preserves_bytes_parser_projection(extended):
    data = ftyp(b"xxxx", [b"qt  ", b"isom"], extended=extended)
    data += b"".join(box(k.encode(), PRIVATE[:16] if k == "uuid" else b"", extended=extended and k != "wide")
                     for k in B.BOX_KINDS if k != "ftyp")
    old = B.scan_bmff_candidates(data, deadline=time.monotonic()+30)
    result = run(data)
    expected = copy.deepcopy(old["candidates"][0])
    expected.pop("overlap_with_reported"); expected.pop("contained_by_reported")
    expected["end_reason"] = "evidence_end"
    assert result["candidates"] == [expected]
    assert result["coverage"]["boxes_examined"] == old["coverage"]["boxes_examined"]


def test_size_zero_next_ftyp_is_only_rejected_as_next_anchor():
    result = run(ftyp() + ftyp(size=0))
    assert result["status"] == "ok"
    assert result["candidates"][0]["end_reason"] == "next_ftyp"
    assert result["summary"]["anchor_rejections"]["size_zero"] == 1


def test_nested_payload_anchor_is_searched_without_relation_claim():
    data = ftyp() + box(b"mdat", b"x" + ftyp())
    report = run(data)
    assert [r["offset"] for r in report["candidates"]] == [0, 25]
    assert not report["relations_assessed"]
    assert all("overlap_with_reported" not in r for r in report["candidates"])


@pytest.mark.parametrize("extra", [0, 8])
def test_box_aligned_prefix_cap_without_payload_copy(extra):
    n = M.MAX_PREFIX_BYTES + extra
    reader, calls = sparse(n, [(0, ftyp()), (16, box(b"mdat", size=M.MAX_PREFIX_BYTES-16)),
                              (M.MAX_PREFIX_BYTES, box())])
    result = M.scan_bmff_stream(reader, evidence_size=n, max_scan_bytes=8, deadline=time.monotonic()+30)
    check(result, calls)
    row = result["candidates"][0]
    assert row["validated_prefix_length"] == M.MAX_PREFIX_BYTES and row["boxes_validated"] == 2
    assert row["end_reason"] == ("prefix_size_limit" if extra else "evidence_end")
    assert result["summary"]["chain_limited_candidates"] == int(bool(extra))
    assert result["coverage"]["search_bytes_read"] == 8
    assert result["coverage"]["structure_bytes_read"] == 20 + extra


def test_next_box_crossing_cap_is_not_partially_included():
    reader, calls = sparse(M.MAX_PREFIX_BYTES+16, [(0, ftyp()), (16, box(b"mdat", size=M.MAX_PREFIX_BYTES))])
    result = M.scan_bmff_stream(reader, evidence_size=M.MAX_PREFIX_BYTES+16, max_scan_bytes=8, deadline=time.monotonic()+30)
    check(result, calls)
    assert result["candidates"][0]["validated_prefix_length"] == 16
    assert result["candidates"][0]["end_reason"] == "prefix_size_limit"


@pytest.mark.parametrize("length,oversized", [(M.MAX_PREFIX_BYTES, False), (M.MAX_PREFIX_BYTES+4, True)])
def test_first_ftyp_cap_before_brand_iteration(length, oversized):
    reader, calls = sparse(length, [(0, ftyp(size=length))])
    result = M.scan_bmff_stream(reader, evidence_size=length, max_scan_bytes=8, deadline=time.monotonic()+30)
    check(result, calls)
    assert result["summary"]["oversize_anchors"] == int(oversized)
    assert not result["candidates"]
    assert result["coverage"]["brand_slots_examined"] == (0 if oversized else 64)
    assert result["coverage"]["pending_anchor_offset"] == (None if oversized else 0)


def test_int64_absolute_coordinates_and_output_reserve():
    n = M.MAX_EVIDENCE_SIZE
    start = n - 16*12
    reader, calls = sparse(n, [(start, ftyp() * 12)])
    limits = replace(M.BmffScanLimits(), max_output_bytes=8192)
    result = M.scan_bmff_stream(reader, evidence_size=n, start_offset=start, limits=limits, deadline=time.monotonic()+30)
    check(result, calls, limits)
    assert len(result["candidates"]) == 4
    assert result["coverage"]["pending_anchor_offset"] == start+64


@pytest.mark.parametrize("name,value,reason", [("max_candidates", 1, "candidate_limit"),
    ("max_anchor_probes", 1, "probe_limit"), ("max_output_bytes", 8192, "output_limit")])
def test_output_and_probe_reservation_pending_can_resume(name, value, reason):
    data = ftyp() * 20
    report = run(data, limits=replace(M.BmffScanLimits(), **{name: value}))
    c = report["coverage"]
    assert c["reasons"] == [reason]
    assert c["pending_anchor_offset"] == c["next_offset"] == len(report["candidates"])*16
    assert not c["candidate_checks_complete"]
    assert run(data, start_offset=c["next_offset"])["candidates"][0]["offset"] == c["next_offset"]


@pytest.mark.parametrize("size", range(1, 29))
def test_structure_budget_distinguishes_pending_and_saved_prefix(size):
    report = run(ftyp()+box()+box(), limits=replace(M.BmffScanLimits(), max_structure_bytes=size))
    c = report["coverage"]
    if size < 12:
        assert not report["candidates"] and c["pending_anchor_offset"] == c["next_offset"] == 0
    elif size < 28:
        assert len(report["candidates"]) == 1 and c["pending_anchor_offset"] is None and c["next_offset"] == 1
        assert report["summary"]["chain_limited_candidates"] == 1
    else:
        assert c["candidate_list_complete"]


@pytest.mark.parametrize("changes,rows,pending,reason", [
    ({"max_boxes_per_candidate": 1}, 1, None, "box_limit"),
    ({"max_boxes_total": 1}, 1, None, "box_limit"),
    ({"max_boxes_total": 2}, 1, 16, "box_limit"),
    ({"max_brands_total": 1}, 1, 16, "brand_limit"),
    ({"max_brands_per_anchor": 1}, 0, 0, "brand_limit"),
])
def test_global_budgets_do_not_reset(changes, rows, pending, reason):
    data = ftyp(compatible=[b"isom"]) if "max_brands_per_anchor" in changes else ftyp()*3
    report = run(data, limits=replace(M.BmffScanLimits(), **changes))
    assert len(report["candidates"]) == rows
    assert report["coverage"]["pending_anchor_offset"] == pending
    assert report["coverage"]["unexamined_positions"]["reason"] == reason


@pytest.mark.parametrize("stage", ["before", "header", "brand"])
def test_time_limit_distinguishes_anchor_and_chain(monkeypatch, stage):
    clock = [100.0 if stage == "before" else 0.0]
    monkeypatch.setattr(M, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    data = ftyp()+box()
    calls = []
    def reader(offset, size):
        calls.append((offset, size))
        if (stage == "header" and (offset, size) == (0, 8)) or (stage == "brand" and (offset, size) == (8, 4)):
            clock[0] = 100.0
        return data[offset:offset+size]
    report = M.scan_bmff_stream(reader, evidence_size=len(data), deadline=10)
    check(report, calls)
    c = report["coverage"]
    assert c["unexamined_positions"]["reason"] == "time_limit"
    if stage == "before":
        assert not calls and c["pending_anchor_offset"] is None
    elif stage == "header":
        assert not report["candidates"] and c["pending_anchor_offset"] == 0
    else:
        assert c["pending_anchor_offset"] is None and c["next_offset"] == 1
        assert report["candidates"][0]["end_reason"] == "time_limit"


@pytest.mark.parametrize("bad", [b"", bytearray(b"x"*16), "SECRET_RAW", None, 2])
def test_callback_invalid_result_is_fixed_failure(bad):
    with pytest.raises(PwehError, match="BMFF") as exc:
        M.scan_bmff_stream(lambda *_: bad, evidence_size=16, deadline=time.monotonic()+30)
    assert exc.value.code == "bmff_scan_read_failed" and "SECRET_RAW" not in str(exc.value)


def test_callback_exception_is_not_partial():
    def bad(*_):
        raise RuntimeError(PRIVATE.decode())
    with pytest.raises(PwehError) as exc:
        M.scan_bmff_stream(bad, evidence_size=16, deadline=time.monotonic()+30)
    assert exc.value.code == "bmff_scan_read_failed" and PRIVATE.decode() not in str(exc.value)


@pytest.mark.parametrize("answer", [True, 1, None, "PRIVATE"])
def test_cancel_is_strict_and_never_saved(answer):
    with pytest.raises(PwehError) as exc:
        run(ftyp(), cancel=lambda: answer)
    assert exc.value.code == ("cancelled" if answer is True else "bmff_scan_failed")


def test_callback_cancel_after_read_prevents_saved_result():
    cancelled = [False]
    def read(offset, count):
        cancelled[0] = True
        return ftyp()[offset:offset+count]
    with pytest.raises(PwehError) as exc:
        M.scan_bmff_stream(read, evidence_size=16, deadline=time.monotonic()+30, cancel=lambda: cancelled[0])
    assert exc.value.code == "cancelled"


@pytest.mark.parametrize("name", [f.name for f in fields(M.BmffScanLimits())])
@pytest.mark.parametrize("variant", ["zero", "bool", "over"])
def test_limits_exact_and_only_lowerable(name, variant):
    value = {"zero": 0, "bool": True, "over": getattr(M.BmffScanLimits(), name)+1}[variant]
    with pytest.raises(ValidationFailed):
        run(ftyp(), limits=replace(M.BmffScanLimits(), **{name: value}))


@pytest.mark.parametrize("kwargs", [
    {"evidence_size": 0}, {"evidence_size": True}, {"evidence_size": 1<<63}, {"start_offset": -1},
    {"start_offset": 17}, {"start_offset": True}, {"max_scan_bytes": 7}, {"max_scan_bytes": 1<<31},
    {"max_scan_bytes": True}, {"deadline": float("nan")}, {"deadline": float("inf")},
    {"deadline": True}, {"deadline": 10**400}, {"cancel": 5}, {"limits": None},
])
def test_invalid_public_arguments(kwargs):
    args = {"evidence_size": 16, "deadline": time.monotonic()+30, **kwargs}
    with pytest.raises(ValidationFailed):
        M.scan_bmff_stream(lambda a,n: ftyp()[a:a+n], **args)


@pytest.mark.parametrize("path,value", [
    (("coverage", "evidence_size"), True), (("coverage", "start_offset"), True),
    (("coverage", "search_positions_total"), 99), (("coverage", "search_positions_examined"), 8),
    (("coverage", "positions_before_start"), 1), (("coverage", "anchor_probes"), 0),
    (("coverage", "boxes_examined"), 0), (("coverage", "brand_slots_examined"), 0),
    (("coverage", "total_bytes_read"), 0), (("coverage", "search_read_calls"), True),
    (("coverage", "candidate_checks_complete"), 1), (("coverage", "whole_evidence_search_complete"), False),
    (("coverage", "reasons"), ["time_limit"]), (("summary", "anchors_observed"), 2),
    (("summary", "chain_limited_candidates"), 1), (("source", "evidence_size"), 17),
    (("params", "start_offset"), True), (("params", "max_scan_bytes"), 8),
    (("candidates", 0, "offset"), 1), (("candidates", 0, "boxes_validated"), True),
    (("candidates", 0, "known_brands"), ["isom", "isom"]),
    (("candidates", 0, "framing_status"), "partial"), (("status",), "partial"),
])
def test_semantic_relationships_are_exact(path, value):
    result = envelope(run(ftyp()))
    target = result
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValidationFailed):
        M.validate_bmff_scan_accounting(result)


@pytest.mark.parametrize("where", [(), ("coverage",), ("summary",), ("source",), ("params",),
                                   ("candidates", 0), ("candidates", 0, "box_counts")])
def test_schema_closes_every_public_object(where):
    result = envelope(run(ftyp()))
    target = result
    for key in where:
        target = target[key]
    target["unapproved_raw"] = PRIVATE.decode()
    with pytest.raises(ValidationFailed):
        validate("bmff-scan", result)


def test_seeded_header_streams_match_bytes_without_new_payload_interpretation():
    rng = random.Random(2179)
    choices = [ftyp(), ftyp(size=0), ftyp(b"zzzz"), box(), box(b"mdat", PRIVATE), box(b"HIDE", PRIVATE),
               ftyp(extended=True), box(b"uuid", PRIVATE), struct.pack(">I4sQ", 1, b"free", (1<<64)-1)]
    for _ in range(50):
        data = b"".join(rng.choice(choices) for _ in range(rng.randrange(1, 12)))
        old = B.scan_bmff_candidates(data, deadline=time.monotonic()+30)
        new = run(data)
        expected = []
        for row in old["candidates"]:
            row = {k: v for k,v in row.items() if k not in ("overlap_with_reported", "contained_by_reported")}
            row["end_reason"] = {"selection_end":"evidence_end", "box_beyond_selection":"box_beyond_evidence"}.get(row["end_reason"], row["end_reason"])
            expected.append(row)
        assert new["candidates"] == expected
        assert new["summary"]["anchors_observed"] == old["summary"]["anchors_observed"]


def test_worst_reservation_bounds_and_maximum_rows():
    result = run(ftyp(compatible=[b"qt  ", b"iso2", b"iso3", b"iso4", b"iso5", b"iso6", b"mp41", b"mp42"])*129)
    assert len(result["candidates"]) == 128
    assert result["coverage"]["pending_anchor_offset"] is not None
    full = envelope(result)
    bare = copy.deepcopy(full); bare["candidates"] = []
    assert len(json.dumps(bare, separators=(",", ":")).encode()) < M._ENVELOPE
    assert all(len(json.dumps(r, separators=(",", ":")).encode())+1 < M._ROW for r in result["candidates"])


def test_chain_limit_row_cannot_claim_unrelated_completed_search():
    report = run(ftyp()+box(size=0))
    report["candidates"][0]["end_reason"] = "box_limit"
    report["summary"]["chain_limited_candidates"] = 1
    report["coverage"]["candidate_checks_complete"] = False
    report["coverage"]["candidate_list_complete"] = False
    with pytest.raises(ValidationFailed):
        M.validate_bmff_scan_accounting(report)


@pytest.mark.parametrize("key", ["known_brands", "reasons"])
def test_semantic_list_bounds_before_membership_work(key):
    report = run(ftyp())
    target = report["candidates"][0] if key == "known_brands" else report["coverage"]
    target[key] = ["isom" if key == "known_brands" else "time_limit"] * 10000
    with pytest.raises(ValidationFailed):
        M.validate_bmff_scan_accounting(report)
