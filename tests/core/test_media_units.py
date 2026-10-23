"""독립 합성 네 형식으로 구조경계·원자회계·제한·출처 분기를 확인한다."""

from __future__ import annotations

import copy
import dataclasses
import json
import random
import time

import pytest

from pweh import media_units as M
from pweh.errors import PwehError, ValidationFailed
from pweh.schemas import validate

PRIVATE = b"SYNTHETIC_PRIVATE_CONTENT_0921"
PACK = bytes.fromhex("000001ba440004000401000007f8")
PES = bytes.fromhex("000001e0000480000058")
B9 = bytes.fromhex("000001b9")


def segment(code, body):
    return b"\xff" + bytes([code]) + (len(body) + 2).to_bytes(2, "big") + body


def jpeg(payload=b"x", *, prefix=b"", frame=None, scan=None):
    frame = bytes.fromhex("080001000101011100") if frame is None else frame
    scan = bytes.fromhex("010100003f00") if scan is None else scan
    return b"\xff\xd8" + prefix + segment(0xc0, frame) + segment(0xda, scan) + payload + b"\xff\xd9"


def avc(header=0x0a, payload=b"", prefix=b"\0\0\1", next_header=0x0b):
    return prefix + bytes([header]) + payload + b"\0\0\1" + bytes([next_header])


def xm(kind=0xfd, payload=b"x", *, t=None, declared=None):
    length = len(payload) if declared is None else declared
    head = bytearray(16 if kind in (0xfc, 0xfe) else 8)
    head[:4] = b"\0\0\1" + bytes([kind])
    if kind in (0xfc, 0xfe):
        head[4] = (1 if kind == 0xfc else 0) if t is None else t
        head[12:] = length.to_bytes(4, "little")
    elif kind == 0xfd:
        head[4:] = length.to_bytes(4, "little")
    else:
        head[4] = (14 if kind == 0xfa else 1) if t is None else t
        head[6:] = length.to_bytes(2, "little")
    return bytes(head) + payload


def sample(format):
    return {"jpeg": jpeg(), "avc-annexb": avc(), "mpeg2-ps": PACK + PES + B9, "xm": xm()}[format]


def envelope(report, ranged=False):
    result = copy.deepcopy(report)
    size, format = result["coverage"]["input_bytes"], result["format"]
    result["source"] = {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a" * 64,
        "container": "file", "member_selected": False, "selected_sha256": "b" * 64,
        "selected_size": size, "complete": True, "method": "whole-file", "confidence": "high",
        "partition": None, "ref": None, "deleted": None, "parent_deleted": None,
        "container_truncated": None, "container_truncated_reasons": []}
    result["params"] = {"format": format, "partition": None, "method": "auto", "max_seconds": 45}
    if ranged:
        result["profile"] = M.RANGE_PROFILES[format]
        result["source"].update(method="byte-range", offset=100, evidence_size=size + 200)
        result["params"].update(offset=100, length=size)
        result["limitations"] += list(M.RANGE_LIMITATIONS)
    return result


def run(data, format="xm", **kwargs):
    kwargs.setdefault("deadline", time.monotonic() + 30)
    report = M.scan_media_unit_candidates(data, format=format, **kwargs)
    M.validate_media_unit_accounting(report)
    full = envelope(report)
    validate("media-unit-candidates", full)
    M.validate_media_unit_accounting(full)
    if data:
        ranged = envelope(report, True)
        validate("media-unit-candidates", ranged)
        M.validate_media_unit_accounting(ranged)
    assert PRIVATE.decode() not in json.dumps(report)
    assert all(report[key] is False for key in M.FALSE_FIELDS)
    lim = kwargs.get("limits", M.MediaUnitLimits())
    assert len(json.dumps(report, ensure_ascii=True, separators=(",", ":")).encode()) + 1 <= lim.max_output_bytes
    return report


@pytest.mark.parametrize("format", M.FORMATS)
@pytest.mark.parametrize("data", [b"", b"x", b"\0", b"\0\0", PRIVATE])
def test_empty_and_non_anchor_complete_does_not_establish_absence(format, data):
    report = run(data, format)
    assert report["status"] == "unsupported"
    assert report["coverage"]["candidate_list_complete"]
    assert report["coverage"]["search_positions_examined"] == len(data)


@pytest.mark.parametrize("format", M.FORMATS)
def test_minimum_units(format):
    report = run(sample(format), format)
    row = report["candidates"][0]
    assert row["length"] == M.MIN_UNIT_BYTES[format]
    assert row["framing_status"] == "closed"
    assert report["status"] == ("partial" if format == "avc-annexb" else "ok")


@pytest.mark.parametrize("offset", [0, 1, 65527, 65530, 65531, 65532, 65533, 65534, 65535, 65536, 65538])
@pytest.mark.parametrize("format", M.FORMATS)
def test_window_crossing(offset, format):
    report = run(b"Q" * offset + sample(format), format)
    assert report["candidates"][0]["offset"] == offset
    assert report["coverage"]["search_complete"]


@pytest.mark.parametrize("code", [0xe0, 0xef, 0xfe, 0xdb, 0xc4])
def test_jpeg_opaque_segments_hide_false_end(code):
    report = run(jpeg(prefix=segment(code, PRIVATE + b"\xff\xd9")), "jpeg")
    assert len(report["candidates"]) == 1 and report["status"] == "ok"


def test_large_jpeg_entropy_is_marker_work_not_one_step_per_byte():
    data = jpeg(b"J" * (2 << 20))
    report = run(data, "jpeg")
    assert report["candidates"][0]["length"] == len(data)
    assert report["coverage"]["structure_steps"] < 10


@pytest.mark.parametrize("payload,prefix,expected", [
    (b"x\xff\x00y", b"", True),
    (b"x\xff\xff\xd9", b"", True),
    (b"x\xff\xd0y", segment(0xdd, b"\0\1"), True),
    (b"x\xff\xd0y", b"", False),
    (b"x\xff\xd0y", segment(0xdd, b"\0\0"), False),
    (b"x\xff\xd1y", segment(0xdd, b"\0\1"), False),
    (b"x\xff\xff\0y", b"", False),
    (b"", b"", False),
])
def test_jpeg_stuffing_fill_restart(payload, prefix, expected):
    report = run(jpeg(payload, prefix=prefix), "jpeg")
    assert bool(report["candidates"]) == expected


def test_jpeg_restart_wrap_and_multiple_scan():
    entropy = b"x" + b"".join(b"\xff" + bytes([0xd0 + n % 8]) + b"x" for n in range(10))
    assert run(jpeg(entropy, prefix=segment(0xdd, b"\0\1")), "jpeg")["candidates"]
    report = run(jpeg(b"x" + segment(0xda, b"")), "jpeg")
    assert report["summary"]["anchor_unsupported"]["multiple_scans"] == 1


@pytest.mark.parametrize("index,value", [(0, 9), (3, 0), (4, 0), (6, 1), (7, 0), (7, 0x51), (8, 4)])
def test_jpeg_bad_frame(index, value):
    frame = bytearray.fromhex("080001000101011100")
    frame[index] = value
    # 일부 대입은 원래 값과 같거나 치수를 바꾸므로 유효 여부를 별도로 정한다.
    result = run(jpeg(frame=bytes(frame)), "jpeg")
    if index in (0, 7, 8) or (index == 4 and value == 0):
        assert not result["candidates"]


@pytest.mark.parametrize("scan", [bytes.fromhex(v) for v in ("010120003f00", "010102003f00", "010200003f00", "010100013f00", "010100003e00", "010100003f01")])
def test_jpeg_baseline_scan_constraints(scan):
    assert not run(jpeg(scan=scan), "jpeg")["candidates"]


@pytest.mark.parametrize("cut", [2, 3, 5, 10, 16, 20, 26, 27])
def test_jpeg_truncated(cut):
    report = run(jpeg()[:cut], "jpeg")
    assert not report["candidates"] and report["status"] == "partial"


def test_jpeg_progressive_and_nested_soi():
    assert run(jpeg().replace(b"\xff\xc0", b"\xff\xc2"), "jpeg")["summary"]["unsupported_anchors"] == 1
    data = b"\xff\xd8" + jpeg()
    report = run(data, "jpeg")
    assert report["candidates"][0]["offset"] == 2


@pytest.mark.parametrize("prefix", [b"\0\0\1", b"\0\0\0\1", b"\0" * 20 + b"\1"])
def test_avc_canonical_prefix_does_not_rediscover_inner_three(prefix):
    data = avc(prefix=prefix)
    report = run(data, "avc-annexb")
    assert len(report["candidates"]) == 1
    assert report["candidates"][0]["offset"] == max(0, len(prefix) - 4)
    assert report["candidates"][0]["length"] == min(4, len(prefix)) + 1
    assert report["summary"]["anchors_observed"] == 2


@pytest.mark.parametrize("kind", range(1, 13))
def test_avc_all_headers(kind):
    ref = 0x20 if kind in (5, 7, 8) else 0
    payload = b"" if kind in (10, 11) else b"\x80"
    result = run(avc(kind | ref, payload), "avc-annexb")
    assert result["candidates"][0]["unit_subtype"] == f"nal_{kind}"


@pytest.mark.parametrize("header", [0x80, 5, 7, 8, 0x26, 0x29, 0x2a, 0x2b, 0x2c, 0, 13, 31])
def test_avc_invalid_or_unsupported_header(header):
    result = run(avc(header, b"x"), "avc-annexb")
    assert not result["candidates"]


@pytest.mark.parametrize("payload,valid", [(b"x\0\0\3", True), (b"x\0\0\3\0x", True),
                                         (b"x\0\0\3\3x", True), (b"x\0\0\3\4x", False),
                                         (b"x\0\0\2x", False), (b"x\0\0\0x", False), (b"", False)])
def test_avc_escape_and_trailing_zero(payload, valid):
    result = run(avc(1, payload), "avc-annexb")
    assert bool(result["candidates"]) == valid


def test_avc_next_header_required_and_trailing_zeros_excluded():
    result = run(avc(1, b"x\0\0\0\0"), "avc-annexb")
    assert result["candidates"][0]["length"] == 5
    assert not run(avc(1, b"x", next_header=0x80), "avc-annexb")["candidates"]
    assert not run(b"\0\0\1\x01x", "avc-annexb")["candidates"]


@pytest.mark.parametrize("end,reason,framing", [(b"", "selection_end", "prefix"), (B9, "program_end", "closed"),
    (PACK + PES + B9, "next_pack", "closed"), (b"x", "truncated_packet", "prefix"),
    (b"xxxx", "invalid_packet", "prefix"), (bytes.fromhex("000001bf"), "unsupported_packet", "prefix"),
    (bytes.fromhex("000001e00000"), "zero_length_packet", "prefix")])
def test_ps_prefix_and_closed_distinction(end, reason, framing):
    result = run(PACK + PES + end, "mpeg2-ps")
    row = result["candidates"][0]
    assert row["length"] == 24 and row["end_reason"] == reason and row["framing_status"] == framing


@pytest.mark.parametrize("index,value", [(4,0), (4,0x40), (6,0), (8,0), (9,0), (12,4), (13,0)])
def test_ps_pack_bit_constraints(index, value):
    data = bytearray(PACK);data[index] = value
    assert not run(bytes(data) + PES + B9, "mpeg2-ps")["candidates"]


def test_ps_stuffing_and_payload_startcode_not_prefix_end():
    head = bytearray(PACK);head[-1] |= 3
    assert run(bytes(head) + b"\xff" * 3 + PES + B9, "mpeg2-ps")["candidates"][0]["length"] == 27
    assert not run(bytes(head) + b"x" * 3 + PES + B9, "mpeg2-ps")["candidates"]
    payload = PACK + PRIVATE
    pes = bytes.fromhex("000001e0") + (len(payload) + 3).to_bytes(2,"big") + b"\x80\0\0" + payload
    result = run(PACK + pes + B9, "mpeg2-ps")
    assert result["candidates"][0]["length"] == 14 + len(pes)


@pytest.mark.parametrize("header", [bytes.fromhex(h) for h in ("800000", "8080052100010001", "80c00a31000100011100010001")])
def test_ps_pts_dts_framing_without_timestamp_output(header):
    pes = bytes.fromhex("000001e0") + (len(header) + 1).to_bytes(2,"big") + header + b"x"
    assert run(PACK + pes + B9, "mpeg2-ps")["candidates"]


@pytest.mark.parametrize("kind", [0xfc, 0xfe, 0xfd, 0xfa, 0xf9])
def test_xm_types_and_positive_little_endian_lengths(kind):
    result = run(xm(kind, PRIVATE), "xm")
    assert result["candidates"][0]["unit_subtype"] == f"type_{kind:x}"
    assert not run(xm(kind, declared=10000), "xm")["candidates"]
    assert not run(xm(kind, payload=b""), "xm")["candidates"]


@pytest.mark.parametrize("kind,t", [(0xfc,0xf1),(0xfc,0x82),(0xfe,0xf0),(0xfa,0x0e),(0xf9,1)])
def test_xm_high_bits_and_t_field(kind,t):
    assert run(xm(kind,t=t), "xm")["candidates"]
    assert not run(xm(kind,t=7), "xm")["candidates"]


@pytest.mark.parametrize("format", M.FORMATS)
@pytest.mark.parametrize("limit,reason", [("max_anchor_probes","probe_limit"), ("max_candidates","candidate_limit"),
                                        ("max_structure_steps","step_limit"), ("max_work_bytes","work_byte_limit")])
def test_limit_pending_is_atomic(format, limit, reason):
    data = sample(format) * 3
    limits = dataclasses.replace(M.MediaUnitLimits(), **{limit:1})
    result = run(data,format,limits=limits)
    assert reason in result["coverage"]["reasons"]
    assert result["status"] == "partial"
    assert result["coverage"]["search_positions_examined"] < len(data)


@pytest.mark.parametrize("format", M.FORMATS)
def test_output_reserve_cap_and_maximum_rows(format):
    data = sample(format) * 150
    small = run(data,format,limits=dataclasses.replace(M.MediaUnitLimits(),max_output_bytes=8192))
    assert len(small["candidates"]) <= 8 and "output_limit" in small["coverage"]["reasons"]
    full = run(data,format)
    assert len(full["candidates"]) == 128 and "candidate_limit" in full["coverage"]["reasons"]
    assert len(json.dumps(envelope(full,True)).encode()) < 1 << 20


@pytest.mark.parametrize("format", M.FORMATS)
def test_deadline_partial_cancel_error_and_bad_callback(format):
    result = run(sample(format),format,deadline=0)
    assert result["coverage"]["reasons"] == ["time_limit"]
    with pytest.raises(PwehError) as caught:
        run(sample(format),format,cancel=lambda:True)
    assert caught.value.code == "cancelled"
    def broken():
        raise RuntimeError(PRIVATE.decode())
    for callback in (broken, lambda:1, lambda:None):
        with pytest.raises(PwehError) as caught:
            run(sample(format),format,cancel=callback)
        assert caught.value.code == "media_unit_candidates_failed"
        assert PRIVATE.decode() not in str(caught.value)


@pytest.mark.parametrize("deadline", [None, True, float('nan'), float('inf'), 10**400, "private"])
def test_bad_deadline_fixed(deadline):
    with pytest.raises(ValidationFailed):
        run(b"",deadline=deadline)


@pytest.mark.parametrize("field", [f.name for f in dataclasses.fields(M.MediaUnitLimits)])
@pytest.mark.parametrize("value", [True, 1.0, 0, -1, 1 << 40])
def test_bad_limit_types_or_bounds(field,value):
    with pytest.raises(ValidationFailed):
        run(b"",limits=dataclasses.replace(M.MediaUnitLimits(),**{field:value}))


@pytest.mark.parametrize("format", M.FORMATS)
@pytest.mark.parametrize("section,key,value", [("summary","anchors_observed",True), ("summary","closed_candidates",1.0),
    ("coverage","work_bytes_charged",0), ("coverage","search_positions_total",0),
    ("coverage","search_complete",False), ("coverage","candidate_list_complete",False),
    ("coverage","selection_uncertain",True)])
def test_accounting_rejects_exact_integer_and_relationship_mismatch(format,section,key,value):
    report = run(sample(format),format)
    if key == "candidate_list_complete":
        value = not report[section][key]
    report[section][key] = value
    with pytest.raises(ValidationFailed):
        M.validate_media_unit_accounting(report)


@pytest.mark.parametrize("format", M.FORMATS)
def test_schema_and_source_range_cross_mixing(format):
    report = envelope(run(sample(format),format),True)
    for field,value in (("offset",True),("length",float(report['params']['length'])),("format","jpeg" if format!='jpeg' else 'xm')):
        bad=copy.deepcopy(report);bad['params'][field]=value
        with pytest.raises(ValidationFailed):M.validate_media_unit_accounting(bad)
    bad=copy.deepcopy(report);bad['source']['offset']+=1
    with pytest.raises(ValidationFailed):M.validate_media_unit_accounting(bad)
    for section in (bad, bad['coverage'],bad['summary'],bad['candidates'][0],bad['source'],bad['params']):
        section['private']=PRIVATE.decode()
    with pytest.raises(ValidationFailed):validate('media-unit-candidates',bad)
    bad=copy.deepcopy(report);bad['profile']=M.FILE_PROFILES[format]
    with pytest.raises(ValidationFailed):validate('media-unit-candidates',bad)


@pytest.mark.parametrize("format", M.FORMATS)
def test_source_uncertainty_preserves_original_completion(format):
    report=run(sample(format),format)
    original=report['coverage']['candidate_list_complete']
    report['coverage']['selection_uncertain']=True
    report['coverage']['reasons'] += ['selection_uncertain','container_listing_incomplete']
    report['status']='partial'
    M.validate_media_unit_accounting(report)
    validate('media-unit-candidates',envelope(report))
    assert report['coverage']['candidate_list_complete'] is original


def test_random_small_inputs_and_mutated_structures_have_bounded_accounting():
    rng=random.Random(1729)
    for format in M.FORMATS:
        base=sample(format)
        for _ in range(35):
            data=bytearray(base)
            for _ in range(rng.randrange(1,5)):
                data[rng.randrange(len(data))]=rng.randrange(256)
            data=bytes(rng.randrange(256) for _ in range(rng.randrange(4)))+bytes(data)
            run(data,format)


@pytest.mark.parametrize("format", M.FORMATS)
def test_timeout_inside_current_probe_keeps_pending_without_local_row(format, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(M.time, "monotonic", lambda: clock[0])
    original = M._Scanner.row
    def expired_after_local_row(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        clock[0] = 100.0
        return result
    monkeypatch.setattr(M._Scanner, "row", expired_after_local_row)
    result = run(sample(format), format, deadline=10)
    assert result['candidates'] == [] and result['summary']['candidates_reported'] == 0
    assert result['coverage']['pending_anchor_offset'] == 0
    assert result['coverage']['reasons'] == ['time_limit']


@pytest.mark.parametrize("format", M.FORMATS)
def test_cancel_inside_parser_raises_without_converting_to_partial(format, monkeypatch):
    state = [False]
    original = M._Scanner.row
    def cancel_after_local_row(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        state[0] = True
        return result
    monkeypatch.setattr(M._Scanner, "row", cancel_after_local_row)
    with pytest.raises(PwehError) as error:
        run(sample(format), format, cancel=lambda: state[0])
    assert error.value.code == 'cancelled'


def test_maximal_envelope_still_fits_reserved_output_and_manifest_coverage():
    report = envelope(run(xm() * 130), True)
    for row in report['candidates']:
        row.update(offset=(64 << 20) - 33, length=17, unit_subtype='type_fe')
    # 유효 회계를 위조하는 시험이 아니라 고정 가장 긴 수치/row의 직렬화 크기 상한이다.
    assert len(json.dumps(report,ensure_ascii=True).encode()) < 1 << 20
    assert len(json.dumps(report['coverage']).encode()) < 4096
