"""합성 EV reader로 네 parser의 최소 재검증 범위·검색 재개·전역 회계를 확인한다."""

from __future__ import annotations

import copy
from dataclasses import fields, replace
import json
import random
import time
from types import SimpleNamespace

import pytest

from pweh import media_unit_stream as M, media_units as U
from pweh.errors import PwehError, ValidationFailed
from pweh.schemas import validate

PRIVATE = b"SYNTHETIC_PRIVATE_UNIT_STREAM_0921"
PACK = bytes.fromhex("000001ba440004000401000007f8")
PES = bytes.fromhex("000001e0000480000058")
B9 = bytes.fromhex("000001b9")


def segment(code, body):
    return b"\xff" + bytes([code]) + (len(body) + 2).to_bytes(2, "big") + body


def jpeg(payload=b"x", *, prefix=b""):
    return (b"\xff\xd8" + prefix + segment(0xc0, bytes.fromhex("080001000101011100"))
            + segment(0xda, bytes.fromhex("010100003f00")) + payload + b"\xff\xd9")


def avc(header=0x0a, payload=b"", prefix=b"\0\0\1", next_header=0x0b):
    return prefix + bytes([header]) + payload + b"\0\0\1" + bytes([next_header])


def xm(kind=0xfd, payload=b"x"):
    head = bytearray(16 if kind in (0xfc, 0xfe) else 8)
    head[:4] = b"\0\0\1" + bytes([kind])
    if kind in (0xfc, 0xfe):
        head[4] = int(kind == 0xfc)
        head[12:] = len(payload).to_bytes(4, "little")
    elif kind == 0xfd:
        head[4:] = len(payload).to_bytes(4, "little")
    else:
        head[4] = 14 if kind == 0xfa else 1
        head[6:] = len(payload).to_bytes(2, "little")
    return bytes(head) + payload


def sample(format):
    return {"jpeg": jpeg(), "avc-annexb": avc(), "mpeg2-ps": PACK + PES + B9, "xm": xm()}[format]


def envelope(report):
    full = copy.deepcopy(report)
    cov = full["coverage"]
    full["source"] = {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a" * 64,
                      "evidence_size": cov["evidence_size"]}
    full["params"] = {"format": full["format"], "start_offset": cov["start_offset"],
                      "max_scan_bytes": cov["max_scan_bytes"], "max_seconds": 45}
    return full


def check(report, calls=(), limits=M.MediaUnitScanLimits()):
    M.validate_media_unit_scan_accounting(report)
    full = envelope(report)
    validate("media-unit-scan", full)
    M.validate_media_unit_scan_accounting(full)
    cov = report["coverage"]
    if calls:
        assert sum(count for _, count in calls) == cov["total_bytes_read"]
        assert len(calls) == cov["search_read_calls"] + cov["structure_read_calls"]
    assert cov["structure_bytes_read"] <= limits.max_structure_bytes
    assert cov["structure_work_bytes"] <= limits.max_structure_work_bytes
    assert cov["total_bytes_read"] <= cov["max_scan_bytes"] + limits.max_structure_bytes
    assert len(json.dumps(full, ensure_ascii=True, separators=(",", ":")).encode()) + 1 <= limits.max_output_bytes
    assert PRIVATE.decode() not in json.dumps(full)
    return report


def run(data, format="xm", **kwargs):
    calls = []
    def reader(offset, count):
        assert type(offset) is int and type(count) is int
        assert 0 <= offset <= len(data) - count and 1 <= count <= 65536
        calls.append((offset, count))
        return data[offset:offset + count]
    kwargs.setdefault("deadline", time.monotonic() + 30)
    return check(M.scan_media_unit_stream(reader, format=format, evidence_size=len(data), **kwargs),
                 calls, kwargs.get("limits", M.MediaUnitScanLimits()))


def sparse(size, blocks, fill=b"x"):
    calls = []
    def reader(offset, count):
        assert 0 <= offset <= size - count and 1 <= count <= 65536
        calls.append((offset, count))
        out = bytearray(fill * count)
        for at, block in blocks:
            left, right = max(offset, at), min(offset + count, at + len(block))
            if left < right:
                out[left-offset:right-offset] = block[left-at:right-at]
        return bytes(out)
    return reader, calls


def differential(data, report):
    for row in report["candidates"]:
        at, count = row["selection_offset"], row["selection_length"]
        selected = data[at:at + count]
        result = U.scan_media_unit_candidates(selected, format=report["format"], deadline=time.monotonic() + 30)
        U.validate_media_unit_accounting(result)
        wanted = {k: v for k, v in row.items() if k not in ("index", "selection_offset", "selection_length")}
        wanted["offset"] = 0
        if wanted["end_reason"] == "evidence_end":
            wanted["end_reason"] = "selection_end"
        assert any({k: v for k, v in other.items() if k != "index"} == wanted for other in result["candidates"])


@pytest.mark.parametrize("format", U.FORMATS)
@pytest.mark.parametrize("length", range(1, 7))
@pytest.mark.parametrize("at_end", [False, True])
def test_small_domains_and_explicit_end(format, length, at_end):
    report = run(b"x" * length, format, start_offset=length if at_end else 0)
    assert report["status"] == "unsupported" and report["coverage"]["search_complete"]
    assert report["coverage"]["whole_evidence_search_complete"] is (not at_end)


@pytest.mark.parametrize("format", U.FORMATS)
@pytest.mark.parametrize("offset", range(65531, 65540))
def test_window_boundary_and_minimal_witness(format, offset):
    data = b"x" * offset + sample(format) + PRIVATE
    report = run(data, format)
    row = report["candidates"][0]
    assert row["offset"] == offset and row["selection_length"] == len(sample(format))
    assert row["length"] == U.MIN_UNIT_BYTES[format]
    differential(data, report)


@pytest.mark.parametrize("format", U.FORMATS)
def test_ev_over_64mib_and_search_end_before_structure(format):
    offset = (65 << 20) - 2
    value = sample(format)
    size = offset + len(value) + 99
    reader, calls = sparse(size, [(offset, value)])
    report = check(M.scan_media_unit_stream(reader, format=format, evidence_size=size,
        start_offset=offset - 2, max_scan_bytes=8, deadline=time.monotonic() + 30), calls)
    row = report["candidates"][0]
    assert row["offset"] == offset and row["selection_length"] == len(value)
    assert report["coverage"]["search_bytes_read"] == 8
    assert report["coverage"]["next_offset"] < offset + row["selection_length"]


@pytest.mark.parametrize("format", U.FORMATS)
@pytest.mark.parametrize("budget", [4, 5, 8, 17, 65536])
def test_resume_never_loses_or_duplicates_candidates(format, budget):
    data = b"x" * 17 + sample(format) + b"x" * 7 + sample(format) + b"x" * 9
    expected = [row["offset"] for row in run(data, format)["candidates"]]
    found, start = [], 0
    for _ in range(len(data)):
        report = run(data, format, start_offset=start, max_scan_bytes=budget)
        found += [row["offset"] for row in report["candidates"]]
        nxt = report["coverage"]["next_offset"]
        if nxt is None:
            break
        assert nxt > start
        start = nxt
    else:
        pytest.fail("유한 검색이 진전하지 않음")
    assert found == expected


@pytest.mark.parametrize("budget", [4, 8, 65536])
def test_avc_three_zero_tail_waits_for_next_window_or_call(budget):
    offset = budget - 3
    data = b"x" * offset + avc(prefix=b"\0\0\0\1")
    report = run(data, "avc-annexb", max_scan_bytes=budget)
    assert report["coverage"]["next_offset"] == offset
    assert report["summary"]["anchors_observed"] == 0
    resumed = run(data, "avc-annexb", start_offset=offset)
    assert resumed["candidates"][0]["offset"] == offset
    whole = run(data, "avc-annexb")
    assert whole["candidates"][0]["offset"] == offset
    differential(data, whole)


@pytest.mark.parametrize("start", [0, 1, 2, 3, 4, 5])
def test_avc_canonical_start_before_requested_position_is_not_selected(start):
    data = avc(prefix=b"\0\0\0\1")
    report = run(data, "avc-annexb", start_offset=start)
    assert len(report["candidates"]) == (1 if start == 0 else 0)


@pytest.mark.parametrize("tail", [b"\0", b"\0\0", b"\0\0\0", b"\0\0\0\0"])
def test_avc_actual_eof_zero_tail_completes_search_without_new_anchor(tail):
    report = run(b"x" * 20 + tail, "avc-annexb")
    assert report["coverage"]["search_complete"] and not report["summary"]["anchors_observed"]


@pytest.mark.parametrize("data,format", [
    (jpeg(prefix=segment(0xe0, b"\xff\xd9" + PRIVATE)), "jpeg"),
    (jpeg(payload=b"x" * 200000), "jpeg"),
    (avc(0x61, b"x\0\0\3\1y"), "avc-annexb"),
    (b"\0\0\1\x61x" + b"\0" * 10000 + b"\1\x0a", "avc-annexb"),
    (xm(0xfc, PRIVATE), "xm"), (xm(0xfe, PRIVATE), "xm"),
    (xm(0xfa, PRIVATE), "xm"), (xm(0xf9, PRIVATE), "xm"),
])
def test_existing_subset_and_opaque_body_differential(data, format):
    report = run(data, format)
    assert report["candidates"]
    differential(data, report)


@pytest.mark.parametrize("tail,reason,selected_extra", [
    (B9, "program_end", 4), (PACK + b"tail", "next_pack", 14),
    (b"", "evidence_end", 0), (b"x", "truncated_packet", 1),
    (b"xy", "truncated_packet", 2), (b"xyz", "truncated_packet", 3),
    (b"xxxx", "invalid_packet", 4), (b"\0\0\1\xff", "unsupported_packet", 4),
    (b"\0\0\1\xe0\0\0", "zero_length_packet", 6),
])
def test_ps_exact_tail_witness(tail, reason, selected_extra):
    data = PACK + PES + tail
    report = run(data, "mpeg2-ps")
    row = report["candidates"][0]
    assert row["end_reason"] == reason and row["selection_length"] == len(PACK + PES) + selected_extra
    differential(data, report)


@pytest.mark.parametrize("head,reason", [(b"\0\0\0", "invalid_packet"), (b"\x80\x01\0", "unsupported_packet")])
def test_ps_successful_extent_before_header_error_is_in_witness(head, reason):
    tail = b"\0\0\1\xe0" + (100).to_bytes(2, "big") + head + b"x" * 97
    data = PACK + PES + tail + b"unneeded"
    report = run(data, "mpeg2-ps")
    row = report["candidates"][0]
    assert row["end_reason"] == reason
    assert row["length"] == 24 and row["selection_length"] == 130
    differential(data, report)
    shortened = U.scan_media_unit_candidates(data[:33], format="mpeg2-ps", deadline=time.monotonic() + 30)
    assert shortened["candidates"][0]["end_reason"] == "truncated_packet"


@pytest.mark.parametrize("stuffing", range(8))
def test_ps_next_pack_requires_stuffing_and_zero_reads_never_reach_callback(stuffing):
    pack = PACK[:-1] + bytes([PACK[-1] | stuffing]) + b"\xff" * stuffing
    data = PACK + PES + pack + b"xxxx"
    report = run(data, "mpeg2-ps")
    assert report["candidates"][0]["selection_length"] == 24 + 14 + stuffing
    differential(data, report)


@pytest.mark.parametrize("format,data", [
    ("jpeg", jpeg(payload=b"x" * 80)), ("avc-annexb", avc(0x61, b"x" * 80)),
    ("xm", xm(payload=b"x" * 80)),
    ("mpeg2-ps", PACK + PES + b"\0\0\1\xe0\0\x64\0\0\0" + b"x" * 97),
])
def test_selection_cap_is_not_eof_and_later_small_unit_is_examined(monkeypatch, format, data):
    monkeypatch.setattr(M, "MAX_SELECTION_BYTES", 64)
    data += b"xxxx" + sample(format)
    report = run(data, format)
    assert report["summary"]["selection_limited_anchors"] >= 1
    assert all(row["offset"] != 0 for row in report["candidates"])
    assert any(row["offset"] == len(data) - len(sample(format)) for row in report["candidates"])
    assert "selection_size_limit" in report["coverage"]["reasons"]
    assert not report["coverage"]["candidate_checks_complete"]
    differential(data, report)


def test_real_64mib_witness_limit_does_not_emit_avc_open_tail_or_prefix():
    size = (64 << 20) + 64
    reader, calls = sparse(size, [(0, b"\0\0\1\x61"), (size - 4, b"\0\0\1\x0a")])
    report = check(M.scan_media_unit_stream(reader, format="avc-annexb", evidence_size=size,
        max_scan_bytes=4, deadline=time.monotonic() + 30), calls)
    assert report["summary"]["selection_limited_anchors"] == 1
    assert not report["candidates"] and report["summary"]["incomplete_anchors"] == 0


@pytest.mark.parametrize("field,value,reason", [
    ("max_anchor_probes", 1, "probe_limit"), ("max_candidates", 1, "candidate_limit"),
    ("max_structure_steps", 1, "step_limit"), ("max_structure_bytes", 1, "structure_byte_limit"),
    ("max_structure_work_bytes", 1, "work_byte_limit"), ("max_output_bytes", 8192, "output_limit"),
])
def test_global_limit_is_pending_not_local_prefix(field, value, reason):
    limits = replace(M.MediaUnitScanLimits(), **{field: value})
    report = run(sample("xm") * 4, limits=limits)
    cov = report["coverage"]
    assert reason in cov["reasons"] and cov["pending_anchor_offset"] == cov["next_offset"]
    # 두 번째 probe의 첫 step에서 멈출 때는 예약 자체는 이미 완료됐다.
    assert cov["anchor_probes"] <= (2 if field == "max_structure_steps" else 1)


@pytest.mark.parametrize("field,reason", [("max_structure_steps", "step_limit"), ("max_structure_work_bytes", "work_byte_limit"),
                                         ("max_structure_bytes", "structure_byte_limit")])
def test_ps_budget_does_not_become_truncated_prefix(field, reason):
    value = {"max_structure_steps": 2, "max_structure_work_bytes": 25, "max_structure_bytes": 25}[field]
    report = run(PACK + PES + B9, "mpeg2-ps", limits=replace(M.MediaUnitScanLimits(), **{field: value}))
    assert not report["candidates"] and reason in report["coverage"]["reasons"]
    assert report["coverage"]["pending_anchor_offset"] == 0


def test_search_reads_are_contiguous_and_structure_cache_hits_still_charge(monkeypatch):
    reads = []
    old = M._Scanner.read
    def traced(self, offset, count, *, structure=True):
        reads.append((offset, count, structure))
        return old(self, offset, count, structure=structure)
    monkeypatch.setattr(M._Scanner, "read", traced)
    report = run(b"x" * 65533 + avc(prefix=b"\0\0\0\1") + b"x" * 70000, "avc-annexb")
    selected = [(o, n) for o, n, kind in reads if not kind]
    assert selected[0][0] == 0
    assert all(a + b == c for (a, b), (c, _) in zip(selected, selected[1:]))
    assert report["coverage"]["structure_work_bytes"] > 0
    assert report["coverage"]["structure_read_calls"] < report["coverage"]["structure_work_bytes"]


@pytest.mark.parametrize("format", U.FORMATS)
def test_deadline_during_probe_has_no_local_row(monkeypatch, format):
    now = [0.0]
    monkeypatch.setattr(M, "time", SimpleNamespace(monotonic=lambda: now[0]))
    original = M._Engine.probe_unit
    def probe(self, offset):
        result = original(self, offset)
        now[0] = 2.0
        return result
    monkeypatch.setattr(M._Engine, "probe_unit", probe)
    report = run(sample(format), format, deadline=1.0)
    assert report["summary"]["anchors_observed"] == 1 and not report["candidates"]
    assert report["coverage"]["pending_anchor_offset"] == 0
    assert report["coverage"]["reasons"] == ["time_limit"]


def test_last_anchor_classified_before_deadline_has_no_empty_unexamined_suffix(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(M, "time", SimpleNamespace(monotonic=lambda: now[0]))
    original = M._Scanner.probe
    def probe(self, offset):
        original(self, offset)
        now[0] = 2.0
    monkeypatch.setattr(M._Scanner, "probe", probe)
    report = run(b"\0\0\1", deadline=1.0)
    assert report["coverage"]["search_complete"]
    assert report["coverage"]["unexamined_positions"] is None
    assert report["coverage"]["reasons"] == ["unit_framing_incomplete"]


@pytest.mark.parametrize("format", U.FORMATS)
def test_cancel_after_probe_is_fatal(monkeypatch, format):
    state = [False]
    original = M._Engine.probe_unit
    def probe(self, offset):
        result = original(self, offset)
        state[0] = True
        return result
    monkeypatch.setattr(M._Engine, "probe_unit", probe)
    with pytest.raises(PwehError) as caught:
        run(sample(format), format, cancel=lambda: state[0])
    assert caught.value.code == "cancelled"


@pytest.mark.parametrize("value", [None, bytearray(b"xxxx"), b"xxx", b"xxxxx", 3])
def test_reader_exact_bytes_and_length(value):
    with pytest.raises(PwehError) as caught:
        M.scan_media_unit_stream(lambda *_: value, format="xm", evidence_size=4, deadline=time.monotonic() + 30)
    assert caught.value.code == "media_unit_scan_read_failed"


@pytest.mark.parametrize("where", ["read", "cancel"])
def test_callback_exception_is_closed_without_original(where):
    def bad(*args):
        raise RuntimeError(PRIVATE.decode())
    with pytest.raises(PwehError) as caught:
        M.scan_media_unit_stream(bad if where == "read" else lambda o,n: b"x" * n,
            format="xm", evidence_size=4, deadline=time.monotonic() + 30, cancel=bad if where == "cancel" else None)
    assert caught.value.code == ("media_unit_scan_read_failed" if where == "read" else "media_unit_scan_failed")
    assert PRIVATE.decode() not in str(caught.value)


@pytest.mark.parametrize("value", [1, None, "false"])
def test_cancel_callback_requires_exact_bool(value):
    with pytest.raises(PwehError, match="취소 상태"):
        run(b"xxxx", cancel=lambda: value)


@pytest.mark.parametrize("name,value", [
    ("evidence_size", True), ("evidence_size", 0), ("evidence_size", 1 << 63),
    ("start_offset", True), ("start_offset", -1), ("start_offset", 5),
    ("max_scan_bytes", 3), ("max_scan_bytes", 1 << 31), ("max_scan_bytes", 4.0),
    ("format", "JPEG"), ("format", ["xm"]), ("deadline", True), ("deadline", float("nan")),
    ("deadline", float("inf")), ("deadline", 10 ** 1000), ("cancel", True), ("read_at", b"xxxx"),
])
def test_input_exact_types_and_caps(name, value):
    args = {"read_at": lambda o,n: b"x" * n, "format": "xm", "evidence_size": 4, "deadline": time.monotonic() + 30}
    args[name] = value
    with pytest.raises(ValidationFailed):
        M.scan_media_unit_stream(**args)


@pytest.mark.parametrize("field", [f.name for f in fields(M.MediaUnitScanLimits)])
@pytest.mark.parametrize("value", [True, 1.0, 0, -1, 1 << 40])
def test_limits_exact_lower_only(field, value):
    with pytest.raises(ValidationFailed):
        run(b"xxxx", limits=replace(M.MediaUnitScanLimits(), **{field: value}))


@pytest.mark.parametrize("field", ["source", "params"])
def test_validator_rejects_half_envelope(field):
    report = envelope(run(sample("xm")))
    del report[field]
    with pytest.raises(ValidationFailed):
        M.validate_media_unit_scan_accounting(report)


@pytest.mark.parametrize("section,key,value", [
    ("source", "evidence_id", "EV-0001\n"), ("source", "evidence_sha256", "a" * 64 + "\n"),
    ("source", "kind", "artifact"), ("source", "evidence_size", True), ("source", "evidence_size", 99),
    ("params", "format", "jpeg"), ("params", "start_offset", 1), ("params", "max_scan_bytes", 4),
    ("params", "max_seconds", True), ("params", "max_seconds", float("nan")),
    ("params", "max_seconds", 46), ("source", "extra", 0),
])
def test_full_binding_mismatch_rejected(section, key, value):
    report = envelope(run(sample("xm")))
    report[section][key] = value
    with pytest.raises(ValidationFailed):
        M.validate_media_unit_scan_accounting(report)


@pytest.mark.parametrize("section,key", [("summary", "anchors_observed"), ("summary", "selection_limited_anchors"),
    ("summary", "closed_candidates"), ("coverage", "evidence_size"), ("coverage", "anchor_probes"),
    ("coverage", "search_bytes_read"), ("coverage", "structure_steps"), ("coverage", "structure_work_bytes"),
    ("coverage", "total_bytes_read"), ("coverage", "positions_before_start")])
@pytest.mark.parametrize("value", [True, 1.0, -1, 1 << 64])
def test_accounting_exact_integer_mutations(section, key, value):
    report = run(sample("xm"))
    report[section][key] = value
    with pytest.raises(ValidationFailed):
        M.validate_media_unit_scan_accounting(report)


@pytest.mark.parametrize("key,value", [("selection_offset", 1), ("selection_length", 8), ("selection_length", True),
    ("offset", 1), ("index", True), ("length", 8), ("end_reason", "evidence_end"), ("extra", 0)])
def test_row_boundaries_and_closed_shape(key, value):
    report = run(sample("xm"))
    report["candidates"][0][key] = value
    with pytest.raises(ValidationFailed):
        M.validate_media_unit_scan_accounting(report)


def test_deterministic_small_mutations_preserve_accounting_and_witness():
    rng = random.Random(51027)
    for format in U.FORMATS:
        for _ in range(32):
            data = bytearray(sample(format))
            for _ in range(rng.randrange(1, 4)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            data = b"x" * rng.randrange(6) + bytes(data) + b"x" * rng.randrange(6)
            report = run(data, format)
            differential(data, report)
