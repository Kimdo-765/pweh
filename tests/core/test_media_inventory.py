"""미디어 없이 합성 BMFF 헤더로 범위·상한·출력 비노출을 검증한다."""
from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import struct
import time

import pytest

from pweh import media as M
from pweh.errors import PwehError, ValidationFailed
from pweh.schemas import validate

PRIVATE = b"PRIVATE_SYNTHETIC_MEDIA_739"


def box(kind=b"free", payload=b"", *, extended=False, zero=False, usertype=b"U" * 16):
    extra = usertype if kind == b"uuid" else b""
    size = (16 if extended else 8) + len(extra) + len(payload)
    header = struct.pack(">I4s", 0 if zero else 1 if extended else size, kind)
    if extended:
        header += struct.pack(">Q", size)
    return header + extra + payload


def ftyp(major=b"isom", compatible=(), **kwargs):
    return box(b"ftyp", major + b"PRIV" + b"".join(compatible), **kwargs)


def run(data, **kwargs):
    if "deadline" not in kwargs:
        kwargs["deadline"] = time.monotonic() + 30
    return M.inventory_isobmff(data, **kwargs)


def envelope(report):
    result = copy.deepcopy(report)
    result["source"] = {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a" * 64,
        "container": "file", "member_selected": False, "selected_sha256": "b" * 64,
        "selected_size": result["coverage"]["input_bytes"], "complete": True, "method": "whole-file",
        "confidence": "high", "partition": None, "ref": None, "deleted": None, "parent_deleted": None,
        "container_truncated": None, "container_truncated_reasons": []}
    result["params"] = {"partition": None, "method": "auto", "max_seconds": 45}
    return result


def check(report):
    cov = report["coverage"]
    cursor = 0
    for span in cov["ranges"]:
        assert span["offset"] == cursor
        assert span["length"] > 0
        cursor += span["length"]
    assert cursor == cov["input_bytes"]
    assert cov["header_bytes"] + cov["skipped_payload_bytes"] + cov["unexamined_bytes"] == cursor
    for kind, key in [("header", "header_bytes"), ("skipped", "skipped_payload_bytes"), ("unexamined", "unexamined_bytes")]:
        assert sum(r["length"] for r in cov["ranges"] if r["kind"] == kind) == cov[key]
    assert cov["structure_complete"] == (report["framing_status"] == "complete")
    for index, item in enumerate(report["boxes"]):
        assert item["index"] == index
        assert item["size"] >= item["header_size"]
        assert item["offset"] + item["size"] <= cursor
        parent = item["parent_index"]
        if parent is not None:
            assert parent < index
            p = report["boxes"][parent]
            assert p["handling"] == "children"
            assert item["offset"] >= p["offset"] + p["header_size"]
            assert item["offset"] + item["size"] <= p["offset"] + p["size"]
            assert item["depth"] == p["depth"] + 1
    assert report["summary"]["boxes_reported"] == len(report["boxes"])
    assert not any(report[field] for field in ("media_decoded", "playback_verified", "recording_time_verified",
                                               "encryption_assessed", "format_conformance_assessed"))
    validate("media-inventory", envelope(report))
    return report


@pytest.mark.parametrize("extended", [False, True])
def test_header_tree_and_disjoint_coverage(extended):
    leaf = box(b"zzzz", PRIVATE)
    movie = box(b"moov", box(b"trak", box(b"mdia", box(b"minf", box(b"stbl", leaf)))), extended=extended)
    data = ftyp(compatible=[b"mp42"]) + movie + box(b"mdat", PRIVATE)
    result = check(run(data))
    assert result["status"] == "ok" and result["recognition"] == "allowed_brand"
    assert result["brands"]["known"] == ["isom", "mp42"]
    assert result["summary"]["max_depth_seen"] == 6
    assert result["coverage"]["skipped_payload_bytes"] == 2 * len(PRIVATE)
    assert all(b["children_complete"] for b in result["boxes"] if b["handling"] == "children")
    assert result["boxes"][1]["header_size"] == (16 if extended else 8)
    assert result["observations"]["initialization_context"] == "moov-observed"
    assert PRIVATE.decode() not in json.dumps(result)


@pytest.mark.parametrize("extended", [False, True])
def test_uuid_24_32_header_and_private_values(extended):
    usertype = PRIVATE[:16]
    result = check(run(box(b"uuid", PRIVATE, extended=extended, usertype=usertype)))
    assert result["boxes"][0]["header_size"] == (32 if extended else 24)
    assert result["coverage"]["header_bytes"] == (32 if extended else 24)
    assert result["coverage"]["skipped_payload_bytes"] == len(PRIVATE)
    dumped = json.dumps(result)
    assert usertype.decode() not in dumped
    assert usertype.hex() not in dumped
    assert hashlib.sha256(usertype).hexdigest() not in dumped


@pytest.mark.parametrize(("data", "reason"), [
    (b"x", "truncated_base_header"), (b"x" * 7, "truncated_base_header"),
    (struct.pack(">I4s", 1, b"free"), "truncated_extended_header"),
    (struct.pack(">I4s", 1, b"free") + b"x" * 7, "truncated_extended_header"),
    (struct.pack(">I4s", 24, b"uuid") + b"x" * 15, "truncated_uuid_header"),
    (struct.pack(">I4sQ", 1, b"uuid", 32) + b"x" * 15, "truncated_uuid_header"),
    (struct.pack(">I4s", 7, b"free"), "size_below_header"),
    (struct.pack(">I4sQ", 1, b"free", 15), "size_below_header"),
    (struct.pack(">I4s", 23, b"uuid") + b"x" * 16, "size_below_header"),
    (struct.pack(">I4sQ", 1, b"uuid", 31) + b"x" * 16, "size_below_header"),
    (struct.pack(">I4s", 16, b"free"), "box_beyond_parent"),
    (struct.pack(">I4sQ", 1, b"free", (1 << 64) - 1), "box_beyond_parent"),
    (box(b"ftyp", b"x" * 7), "invalid_ftyp_shape"),
    (box(b"ftyp", b"x" * 9), "invalid_ftyp_shape"),
])
def test_malformed_tail_preserves_known_prefix(data, reason):
    prefix = ftyp()
    result = check(run(prefix + data))
    assert result["status"] == "partial" and result["framing_status"] == "partial"
    assert result["coverage"]["reasons"] == [reason]
    assert result["coverage"]["ranges"][-1] == {"offset": len(prefix), "length": len(data),
                                                   "kind": "unexamined", "reason": reason}
    assert len(result["boxes"]) == 1


@pytest.mark.parametrize("small", range(2, 8))
def test_short_size_never_stalls(small):
    result = check(run(struct.pack(">I4s", small, b"free")))
    assert result["coverage"]["reasons"] == ["size_below_header"]


def test_parent_boundary_does_not_borrow_next_sibling():
    child = struct.pack(">I4s", 16, b"free")
    result = check(run(box(b"moov", child) + box(b"free")))
    assert [b["kind"] for b in result["boxes"]] == ["moov"]
    assert result["boxes"][0]["children_complete"] is False
    assert result["coverage"]["header_bytes"] == 8
    assert result["coverage"]["unexamined_bytes"] == 16
    assert result["coverage"]["reasons"] == ["box_beyond_parent"]


@pytest.mark.parametrize("kind", [b"mdat", b"free", b"uuid"])
def test_top_level_size_zero_consumes_eof(kind):
    result = check(run(box(kind, ftyp() + box(b"moov"), zero=True)))
    assert len(result["boxes"]) == 1
    assert result["coverage"]["structure_complete"] is True
    assert result["brands"]["tables"] == []
    assert result["boxes"][0]["header_size"] == (24 if kind == b"uuid" else 8)


def test_nested_size_zero_is_unsupported_without_resynchronization():
    child = box(b"mdat", ftyp(), zero=True)
    result = check(run(box(b"moov", child) + ftyp()))
    assert [b["kind"] for b in result["boxes"]] == ["moov"]
    assert result["coverage"]["reasons"] == ["unsupported_nested_size_zero"]
    assert result["coverage"]["unexamined_bytes"] == len(child) + len(ftyp())


@pytest.mark.parametrize("kind", [b"mdat", b"uuid", b"meta", b"udta", b"ABCD", b"styp"])
def test_payload_fake_boxes_are_opaque(kind):
    payload = ftyp() + box(b"moov", box(b"trak"))
    result = check(run(box(kind, payload)))
    assert len(result["boxes"]) == 1 and not result["brands"]["tables"]
    assert result["coverage"]["skipped_payload_bytes"] == len(payload)


def test_unapproved_parent_context_is_opaque():
    inner = box(b"moov", box(b"trak", ftyp()))
    result = check(run(box(b"moov", box(b"trak", inner))))
    assert [b["kind"] for b in result["boxes"]] == ["moov", "trak", "moov"]
    assert result["boxes"][-1]["handling"] == "skipped"
    assert result["coverage"]["ranges"][-1]["reason"] == "unsupported_context"


@pytest.mark.parametrize("order", [0, 1])
def test_moov_before_or_after_mdat(order):
    parts = [box(b"moov"), box(b"mdat", b"opaque")]
    if order:
        parts.reverse()
    result = check(run(ftyp() + b"".join(parts)))
    assert result["status"] == "ok"
    assert result["observations"]["top_level_moov"] and result["observations"]["top_level_mdat"]


@pytest.mark.parametrize("with_styp", [False, True])
def test_fragment_without_initialization_is_not_called_malformed(with_styp):
    data = (box(b"styp", PRIVATE) if with_styp else b"") + box(b"moof", box(b"traf")) + box(b"mdat")
    result = check(run(data))
    assert result["status"] == "unsupported"
    assert result["framing_status"] == "complete"
    assert result["recognition"] == "fragment_candidate"
    assert result["observations"]["initialization_context"] == "unavailable"
    assert not result["coverage"]["reasons"]


@pytest.mark.parametrize(("data", "recognition"), [
    (b"", "empty"), (box(b"moov"), "unbranded"), (box(b"mdat"), "unbranded"),
    (box(b"free"), "unbranded"), (ftyp(b"avif"), "unknown_brand"),
])
def test_empty_and_unsupported_framing_do_not_confirm_media(data, recognition):
    result = check(run(data))
    assert result["status"] == "unsupported" and result["recognition"] == recognition
    assert result["framing_status"] == "complete" and result["format"] == "unknown"


def test_unknown_major_known_compatible_and_exact_brand_mapping():
    result = check(run(ftyp(b"PRIV", [b"qt  ", b"isom", b"PRIV", b"XXYY", b"isom"])))
    table = result["brands"]["tables"][0]
    assert table["major"] == "unknown"
    assert table["compatible"] == ["quicktime", "isom", "unknown"]
    assert table["compatible_count"] == 5 and table["slots_examined"] == 6
    assert table["unknown_count"] == 3 and table["unknown_distinct_count"] == 2
    assert result["brands"]["known"] == ["isom", "quicktime"]
    assert result["recognition"] == "allowed_brand"
    assert "PRIV" not in json.dumps(result) and "XXYY" not in json.dumps(result)


@pytest.mark.parametrize("brand", [b"ISOM", b"qt\x00\x00", b" mp4", b"avif", b"mif1"])
def test_no_normalization_or_foreign_brand_assertions(brand):
    result = check(run(ftyp(brand)))
    assert result["brands"]["tables"][0]["major"] == "unknown"
    assert result["status"] == "unsupported"


def test_multiple_ftyp_preserves_observations():
    result = check(run(ftyp(b"mp41") + ftyp(b"PRIV")))
    assert result["framing_status"] == "complete" and result["status"] == "partial"
    assert result["coverage"]["reasons"] == ["multiple_ftyp"]
    assert [t["major"] for t in result["brands"]["tables"]] == ["mp41", "unknown"]


@pytest.mark.parametrize("count", [64, 65])
def test_brand_limit_per_box(count):
    result = check(run(ftyp(compatible=[b"isom"] * (count - 1))))
    assert result["brands"]["slots_examined"] == 64
    assert result["coverage"]["unexamined_bytes"] == (4 if count == 65 else 0)
    assert ("brand_limit" in result["coverage"]["reasons"]) == (count == 65)
    assert result["brands"]["tables"][0]["complete"] == (count == 64)


def test_brand_total_limit_includes_partial_next_table():
    result = check(run(ftyp() * 257))
    assert result["brands"]["slots_examined"] == 256
    assert len(result["brands"]["tables"]) == 257
    assert result["brands"]["tables"][-1]["major"] is None
    assert result["coverage"]["unexamined_bytes"] == 8
    assert "brand_limit" in result["coverage"]["reasons"]


def test_count_limit_at_4096_and_no_quadratic_walk():
    result = check(run(box() * 4097))
    assert len(result["boxes"]) == 4096
    assert result["coverage"]["reasons"] == ["box_limit"]
    assert result["coverage"]["unexamined_bytes"] == 8
    assert len(json.dumps(result, separators=(",", ":")).encode()) < M.MAX_OUTPUT_BYTES


def test_depth_limit_keeps_unfinished_ancestors():
    data = box(b"moov", box(b"trak", box(b"mdia", box(b"minf", box(b"stbl")))))
    result = check(run(data, limits=M.MediaLimits(max_depth=3)))
    assert [b["kind"] for b in result["boxes"]] == ["moov", "trak", "mdia"]
    assert all(b["children_complete"] is False for b in result["boxes"])
    assert result["coverage"]["header_bytes"] == 24
    assert result["coverage"]["reasons"] == ["depth_limit"]


@pytest.mark.parametrize("limit", [1, 2, 3, 4, 5])
def test_range_limit_reserves_complete_unexamined_tail(limit):
    result = check(run(box(b"mdat", b"opaque") * 10, limits=M.MediaLimits(max_ranges=limit)))
    assert len(result["coverage"]["ranges"]) <= limit
    assert result["coverage"]["reasons"] == ["range_limit"]


def test_output_limit_is_partial_and_does_not_drop_coverage():
    result = check(run(box(b"mdat", b"opaque") * 100, limits=M.MediaLimits(max_output_bytes=4096)))
    assert result["coverage"]["reasons"] == ["output_limit"]
    assert len(result["boxes"]) < 100
    assert len(json.dumps(result, separators=(",", ":")).encode()) <= 4096


def test_output_stop_does_not_pollute_unknown_brand_distinct_count():
    data = ftyp(b"ABCD") + box() * 30 + ftyp(b"EFGH", [b"IJKL"])
    result = check(run(data, limits=M.MediaLimits(max_output_bytes=4096)))
    assert result["brands"]["unknown_distinct_count"] == 1
    assert result["brands"]["unknown_count"] == 1


def test_timeout_inside_brand_table_preserves_examined_prefix(monkeypatch):
    ticks = iter([0, 1, 2, 3])
    monkeypatch.setattr(M.time, "monotonic", lambda: next(ticks))
    result = check(run(ftyp(compatible=[b"mp42"]), deadline=3))
    assert result["coverage"]["header_bytes"] == 16
    assert result["coverage"]["unexamined_bytes"] == 4
    assert result["brands"]["tables"][0]["major"] == "isom"
    assert result["brands"]["tables"][0]["complete"] is False
    assert result["coverage"]["reasons"] == ["time_limit"]


def test_already_expired_deadline_returns_partial():
    result = check(run(ftyp(), deadline=0))
    assert result["coverage"]["unexamined_bytes"] == len(ftyp())
    assert result["coverage"]["reasons"] == ["time_limit"]


@pytest.mark.parametrize("at", [1, 3, 6])
def test_cancel_during_scan_never_returns_result(at):
    calls = 0
    def cancel():
        nonlocal calls
        calls += 1
        return calls >= at
    with pytest.raises(PwehError) as exc:
        run(ftyp(compatible=[b"isom"] * 10), cancel=cancel)
    assert exc.value.code == "cancelled"


@pytest.mark.parametrize("callback", [lambda: PRIVATE.decode(), lambda: (_ for _ in ()).throw(ValueError(PRIVATE.decode()))])
def test_callback_error_is_fixed(callback):
    with pytest.raises(PwehError) as exc:
        run(ftyp(), cancel=callback)
    assert exc.value.code == "media_inventory_failed" and PRIVATE.decode() not in str(exc.value)


def test_input_size_boundary_uses_complete_bytes():
    assert check(run(ftyp(), limits=M.MediaLimits(max_input_bytes=16)))["status"] == "ok"
    with pytest.raises(PwehError) as exc:
        run(ftyp() + b"x", limits=M.MediaLimits(max_input_bytes=16))
    assert exc.value.code == "input_too_large"


@pytest.mark.parametrize("data", [bytearray(), memoryview(b""), "", None])
def test_requires_immutable_exact_bytes(data):
    with pytest.raises(ValidationFailed):
        run(data)


@pytest.mark.parametrize("field", [f.name for f in dataclasses.fields(M.MediaLimits)])
@pytest.mark.parametrize("bad", [True, 0, -1, 1.5, "10", None])
def test_limit_type_and_range(field, bad):
    with pytest.raises(ValidationFailed):
        run(b"", limits=dataclasses.replace(M.MediaLimits(), **{field: bad}))


@pytest.mark.parametrize("field", [f.name for f in dataclasses.fields(M.MediaLimits)])
def test_limits_cannot_exceed_fixed_maximum(field):
    limits = M.MediaLimits()
    with pytest.raises(ValidationFailed):
        run(b"", limits=dataclasses.replace(limits, **{field: getattr(limits, field) + 1}))


@pytest.mark.parametrize("bad", [True, "1", None, float("inf"), float("nan")])
def test_deadline_validation_is_fixed(bad):
    with pytest.raises(ValidationFailed):
        run(b"", deadline=bad)


def test_unknown_fourcc_output_has_only_fixed_kind_and_counts():
    raws = [b"PRIV", b"ABCD", b"PRIV", b"\xff\x00\xfe\x01"]
    result = check(run(b"".join(box(raw, PRIVATE) for raw in raws)))
    assert result["summary"]["unknown_box_count"] == 4
    assert result["summary"]["unknown_type_distinct_count"] == 3
    dumped = json.dumps(result)
    for raw in raws:
        assert raw.hex() not in dumped
        assert hashlib.sha256(raw).hexdigest() not in dumped
    assert "PRIV" not in dumped and "ABCD" not in dumped and PRIVATE.decode() not in dumped


def test_schema_rejects_raw_fields_and_source_shape_conflicts():
    original = envelope(run(ftyp()))
    changes = [lambda r: r.update(raw_fourcc="PRIV"),
               lambda r: r["boxes"][0].update(kind="PRIV"),
               lambda r: r["brands"]["tables"][0].update(major="PRIV"),
               lambda r: r["source"].update(path=PRIVATE.decode()),
               lambda r: r["source"].update(ref="root/0"),
               lambda r: r["source"].update(method="empty"),
               lambda r: r["coverage"]["ranges"][0].update(reason="PRIV"),
               lambda r: r["source"].update(parent_deleted=False),
               lambda r: r["params"].update(method="chain")]
    for mutate in changes:
        result = copy.deepcopy(original)
        mutate(result)
        with pytest.raises(ValidationFailed):
            validate("media-inventory", result)


def test_schema_allows_only_zero_size_filesystem_empty_method():
    result = envelope(run(b""))
    result["source"].update(container="filesystem", member_selected=True, partition=1, ref="root/0",
                            method="empty", deleted=True, parent_deleted=None)
    validate("media-inventory", result)
    result["source"]["selected_size"] = 1
    with pytest.raises(ValidationFailed):
        validate("media-inventory", result)
