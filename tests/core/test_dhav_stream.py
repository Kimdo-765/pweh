"""합성 reader로 EV 검색·경계·재개·닫힌 보고서의 수치 계약을 검사한다."""

from __future__ import annotations

import copy
from dataclasses import replace
import json
import random
import struct
import time

import pytest

from pweh import dhav, dhav_stream as D
from pweh.errors import PwehError, ValidationFailed
from pweh.schemas import validate

PRIVATE = b"PRIVATE_STREAM_SYNTHETIC_475"


def record(kind=0xF0, payload=b"x", extension=b"", *, declared=None, footer=None):
    head = bytearray(b"Q" * 24)
    head[:4], head[4], head[22] = b"DHAV", kind, len(extension)
    size = 32 + len(payload) + len(extension) if declared is None else declared
    struct.pack_into("<I", head, 12, size)
    tail = b"dhav" + struct.pack("<I", size) if footer is None else footer
    return bytes(head) + extension + payload + tail


def envelope(result):
    result = copy.deepcopy(result)
    c = result["coverage"]
    result["source"] = {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a" * 64,
                        "evidence_size": c["evidence_size"]}
    result["params"] = {"start_offset": c["start_offset"], "max_scan_bytes": c["max_scan_bytes"], "max_seconds": 45}
    return result


def run(data, **kwargs):
    calls = []
    def reader(offset, length):
        calls.append((offset, length))
        assert 1 <= length <= 65536 and 0 <= offset <= len(data) - length
        return data[offset:offset + length]
    kwargs.setdefault("deadline", time.monotonic() + 30)
    result = D.scan_dhav_stream(reader, evidence_size=len(data), **kwargs)
    check(result, calls, kwargs.get("limits", D.DhavScanLimits()))
    return result


def check(result, calls=(), limits=D.DhavScanLimits()):
    D.validate_dhav_scan_accounting(result)
    full = envelope(result)
    validate("dhav-scan", full)
    D.validate_dhav_scan_accounting(full)
    c = result["coverage"]
    if calls:
        assert sum(n for _, n in calls) == c["total_bytes_read"]
        assert len(calls) == c["search_read_calls"] + c["structure_read_calls"]
    assert c["total_bytes_read"] <= c["max_scan_bytes"] + limits.max_structure_bytes
    assert c["search_bytes_read"] <= c["max_scan_bytes"]
    assert c["structure_bytes_read"] <= limits.max_structure_bytes
    assert len(json.dumps(full, ensure_ascii=True, separators=(",", ":")).encode()) + 1 <= limits.max_output_bytes
    assert all(result[field] is False for field in D.FALSE_FIELDS)


@pytest.mark.parametrize("data", [b"x", b"xx", b"xxx", b"xxxx", PRIVATE])
@pytest.mark.parametrize("start", [0, 1])
def test_no_magic_and_short_eof(data, start):
    result = run(data, start_offset=start)
    assert result["status"] == "unsupported"
    assert result["coverage"]["next_offset"] is None
    assert result["coverage"]["whole_evidence_search_complete"] is (start == 0)


@pytest.mark.parametrize("kind", [0xF0, 0xFC, 0xFD])
@pytest.mark.parametrize("extension", [b"", b"E" * 255])
@pytest.mark.parametrize("offset", [0, 65533, 65534, 65535, 65536, 65537])
def test_record_crosses_search_window_without_duplicate(kind, extension, offset):
    data = b"x" * offset + record(kind, PRIVATE, extension)
    result = run(data)
    assert result["status"] == "ok"
    assert result["summary"]["anchors_observed"] == 1
    assert result["candidates"][0]["offset"] == offset
    assert result["coverage"]["structure_bytes_read"] == 14
    assert result["coverage"]["structure_read_calls"] == 4
    assert PRIVATE.decode() not in json.dumps(result)


@pytest.mark.parametrize("budget", [4, 5, 7, 32, 64, 65536])
def test_continuation_preserves_boundary_anchor_and_reports_once(budget):
    data = b"x" * 17 + record() + b"z" * 5 + record(0xFC) + b"e" * 8
    offsets, start, calls = [], 0, 0
    while True:
        result = run(data, start_offset=start, max_scan_bytes=budget)
        offsets.extend(row["offset"] for row in result["candidates"])
        c = result["coverage"]
        assert c["positions_before_start"] + c["search_positions_examined"] + (c["unexamined_positions"] or {}).get("count", 0) == len(data) - 3
        calls += 1
        if c["next_offset"] is None:
            break
        assert start < c["next_offset"]
        assert c["reasons"] == ["scan_byte_limit"]
        start = c["next_offset"]
    assert offsets == [17, 55]
    assert calls <= len(data)


def test_nested_payload_magic_is_still_searched():
    inner = record(0xFD)
    data = record(payload=b"x" + inner + b"y")
    result = run(data)
    assert [row["offset"] for row in result["candidates"]] == [0, 25]


@pytest.mark.parametrize("data,reason", [
    (b"DHAV", "truncated_header"),
    (b"DHAV\xf0", "truncated_header"),
    (record(declared=100), "record_beyond_evidence"),
])
def test_incomplete_observation_is_partial_even_when_search_complete(data, reason):
    result = run(data)
    assert result["summary"]["anchor_incomplete"][reason] == 1
    assert result["coverage"]["search_complete"]
    assert not result["coverage"]["candidate_checks_complete"]
    assert result["status"] == "partial"


@pytest.mark.parametrize("data,reason", [
    (record(0xF1), "unsupported_record_type"),
    (record(declared=31), "length_below_header_and_footer"),
    (record(payload=b""), "empty_payload"),
    (record(footer=b"xxxx" + struct.pack("<I", 33)), "footer_missing"),
    (record(footer=b"dhav" + struct.pack("<I", 34)), "footer_length_mismatch"),
])
def test_rejected_anchor_does_not_become_candidate(data, reason):
    result = run(data)
    assert result["summary"]["anchor_rejections"][reason] == 1
    assert result["candidates"] == [] and result["status"] == "unsupported"


def sparse_reader(size, blocks):
    calls = []
    def read(offset, length):
        assert 0 <= offset <= size - length and 1 <= length <= 65536
        calls.append((offset, length))
        result = bytearray(length)
        for block_start, data in blocks:
            start, end = max(offset, block_start), min(offset + length, block_start + len(data))
            if start < end:
                result[start - offset:end - offset] = data[start - block_start:end - block_start]
        return bytes(result)
    return read, calls


def test_footer_outside_search_budget_uses_only_tiny_structural_reads():
    length, n = 32 << 20, 80 << 20
    head = record(declared=length)[:24]
    reader, calls = sparse_reader(n, [(7, head), (7 + length - 8, b"dhav" + struct.pack("<I", length))])
    result = D.scan_dhav_stream(reader, evidence_size=n, max_scan_bytes=64, deadline=time.monotonic() + 30)
    check(result, calls)
    assert result["candidates"][0]["record_length"] == length
    assert result["coverage"]["search_bytes_read"] == 64
    assert result["coverage"]["structure_bytes_read"] == 14
    assert result["coverage"]["next_offset"] == 61
    assert calls[-1] == (7 + length - 8, 8)


def test_oversized_record_is_not_footer_verified_or_reported():
    length, n = (64 << 20) + 1, 90 << 20
    reader, calls = sparse_reader(n, [(0, record(declared=length)[:24])])
    result = D.scan_dhav_stream(reader, evidence_size=n, max_scan_bytes=64, deadline=time.monotonic() + 30)
    check(result, calls)
    assert result["summary"]["oversize_anchors"] == 1 and not result["candidates"]
    assert result["coverage"]["structure_bytes_read"] == 6
    assert result["coverage"]["reasons"] == ["scan_byte_limit", "record_size_limit"]
    assert not result["coverage"]["candidate_checks_complete"]


def test_int64_evidence_coordinates_without_large_allocation():
    n = D.MAX_EVIDENCE_SIZE
    start = n - 40
    reader, calls = sparse_reader(n, [(start, record())])
    result = D.scan_dhav_stream(reader, evidence_size=n, start_offset=start, deadline=time.monotonic() + 30)
    check(result, calls)
    assert result["candidates"][0]["offset"] == start
    assert result["coverage"]["search_complete"] and not result["coverage"]["whole_evidence_search_complete"]


@pytest.mark.parametrize("limit,value,reason", [("max_candidates", 1, "candidate_limit"),
    ("max_anchor_probes", 1, "probe_limit"), ("max_output_bytes", 8192, "output_limit")])
def test_pending_anchor_can_resume_without_missing_valid_output(limit, value, reason):
    data = record() * 20
    limits = replace(D.DhavScanLimits(), **{limit: value})
    first = run(data, limits=limits)
    c = first["coverage"]
    assert c["reasons"] == [reason]
    assert c["pending_anchor_offset"] == c["next_offset"]
    assert first["summary"]["anchors_observed"] == len(first["candidates"]) + 1
    second = run(data, start_offset=c["next_offset"])
    assert second["candidates"][0]["offset"] == len(first["candidates"]) * 33


@pytest.mark.parametrize("size", list(range(1, 15)))
def test_structure_budget_atomic_candidate(size):
    result = run(record(), limits=replace(D.DhavScanLimits(), max_structure_bytes=size))
    if size < 14:
        assert result["candidates"] == []
        assert result["coverage"]["pending_anchor_offset"] == 0
        assert result["coverage"]["next_offset"] == 0
        assert result["coverage"]["reasons"] == ["structure_byte_limit"]
    else:
        assert len(result["candidates"]) == 1


def test_candidate_count128_and_json_bound():
    result = run(record() * 129)
    assert len(result["candidates"]) == 128
    assert result["coverage"]["next_offset"] == 128 * 33
    assert result["coverage"]["anchor_probes"] == 128


def test_time_expired_before_io_and_after_prefetch(monkeypatch):
    result = run(record(), deadline=-1)
    assert result["coverage"]["search_bytes_read"] == 0 and result["coverage"]["next_offset"] == 0
    clock = [0.0]
    monkeypatch.setattr(D.time, "monotonic", lambda: clock[0])
    def reader(offset, length):
        clock[0] = 2
        return record()[offset:offset + length]
    result = D.scan_dhav_stream(reader, evidence_size=33, deadline=1)
    check(result)
    assert result["coverage"]["search_bytes_read"] == 33
    assert result["coverage"]["search_positions_examined"] == 0
    assert result["coverage"]["pending_anchor_offset"] is None


@pytest.mark.parametrize("bad", [None, b"", bytearray(b"x"), "PRIVATE_FAILURE", 4])
def test_wrong_read_result_is_fixed_error(bad):
    with pytest.raises(PwehError) as error:
        D.scan_dhav_stream(lambda *_: bad, evidence_size=33, deadline=time.monotonic() + 30)
    assert error.value.code == "dhav_scan_read_failed"
    assert "PRIVATE_FAILURE" not in str(error.value)


def test_reader_exception_is_fixed_without_context():
    def reader(*_):
        raise RuntimeError("PRIVATE_CALLBACK_PATH")
    with pytest.raises(PwehError) as error:
        D.scan_dhav_stream(reader, evidence_size=33, deadline=time.monotonic() + 30)
    assert error.value.code == "dhav_scan_read_failed"
    assert error.value.__suppress_context__ and "PRIVATE" not in str(error.value)


@pytest.mark.parametrize("cancel,code", [(lambda: True, "cancelled"), (lambda: 1, "dhav_scan_failed")])
def test_cancel_and_invalid_cancel_return(cancel, code):
    with pytest.raises(PwehError) as error:
        run(record(), cancel=cancel)
    assert error.value.code == code


def test_cancel_callback_failure_is_fixed():
    def cancel():
        raise RuntimeError("PRIVATE_CANCEL")
    with pytest.raises(PwehError) as error:
        run(record(), cancel=cancel)
    assert error.value.code == "dhav_scan_failed" and "PRIVATE" not in str(error.value)


@pytest.mark.parametrize("key,value", [
    ("evidence_size", 0), ("evidence_size", True), ("evidence_size", 1.0),
    ("evidence_size", 1 << 63), ("start_offset", -1), ("start_offset", 34), ("start_offset", False),
    ("max_scan_bytes", 3), ("max_scan_bytes", True), ("max_scan_bytes", (1 << 30) + 1),
    ("deadline", True), ("deadline", float("nan")), ("deadline", float("inf")),
    ("deadline", 10**400), ("read_at", None), ("cancel", 1), ("limits", None),
])
def test_argument_types_and_numeric_bounds(key, value):
    arguments = dict(read_at=lambda p, n: record()[p:p + n], evidence_size=33, deadline=time.monotonic() + 30)
    arguments[key] = value
    with pytest.raises(ValidationFailed):
        D.scan_dhav_stream(**arguments)


@pytest.mark.parametrize("field", list(D.DhavScanLimits.__dataclass_fields__))
@pytest.mark.parametrize("bad", [0, True, 1.0, 1 << 40])
def test_limits_are_exact_int_and_cannot_be_raised(field, bad):
    with pytest.raises(ValidationFailed):
        run(record(), limits=replace(D.DhavScanLimits(), **{field: bad}))


@pytest.mark.parametrize("path,value", [
    (("coverage", "evidence_size"), True), (("coverage", "search_positions_total"), 31),
    (("coverage", "search_positions_examined"), 29), (("coverage", "positions_before_start"), 1),
    (("coverage", "search_bytes_read"), 32), (("coverage", "search_read_calls"), 0),
    (("coverage", "structure_bytes_read"), 13), (("coverage", "structure_read_calls"), 3),
    (("coverage", "total_bytes_read"), 1.0), (("coverage", "next_offset"), 1),
    (("coverage", "pending_anchor_offset"), 0), (("coverage", "candidate_checks_complete"), 1),
    (("coverage", "search_complete"), False), (("coverage", "whole_evidence_search_complete"), False),
    (("coverage", "reasons"), ["record_size_limit"]), (("summary", "anchors_observed"), 0),
    (("summary", "oversize_anchors"), 1), (("summary", "candidates_reported"), True),
    (("source", "evidence_size"), 34), (("params", "start_offset"), 1),
    (("params", "max_scan_bytes"), 4), (("status",), "unsupported"),
])
def test_semantic_rejects_contradictory_accounting(path, value):
    result = envelope(run(record()))
    target = result
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValidationFailed):
        D.validate_dhav_scan_accounting(result)


@pytest.mark.parametrize("field,value", [("index", True), ("offset", -1), ("offset", 30),
    ("record_length", 34), ("header_length", 25), ("extension_length", 1),
    ("payload_length", 2), ("record_type", "PRIVATE"), ("footer_length_matches", 1)])
def test_row_arithmetic_exactness(field, value):
    result = run(record())
    result["candidates"][0][field] = value
    with pytest.raises(ValidationFailed):
        D.validate_dhav_scan_accounting(result)


@pytest.mark.parametrize("path", [(), ("source",), ("params",), ("summary",), ("coverage",), ("candidates", 0)])
def test_schema_rejects_extra_keys(path):
    result = envelope(run(record()))
    target = result
    for key in path:
        target = target[key]
    target["PRIVATE_EXTRA"] = "PRIVATE_VALUE"
    with pytest.raises(ValidationFailed):
        validate("dhav-scan", result)


def test_random_small_records_match_existing_byte_scanner():
    rng = random.Random(7741)
    for _ in range(80):
        data = bytearray(rng.randbytes(rng.randrange(1, 80)))
        for _ in range(rng.randrange(5)):
            data.extend(record(rng.choice([0xF0, 0xFC, 0xFD, 0xF1]), rng.randbytes(rng.randrange(1, 40))))
            data.extend(rng.randbytes(rng.randrange(20)))
        data = bytes(data)
        streamed = run(data)
        old = dhav.scan_dhav_candidates(data, deadline=time.monotonic() + 30)
        assert streamed["candidates"] == old["candidates"]
        assert streamed["summary"]["anchors_observed"] == old["summary"]["anchors_observed"]
