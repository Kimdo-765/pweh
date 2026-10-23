"""기존 file/range와 독립인 residual source19·profile 분기의 닫힌 schema 시험."""
from __future__ import annotations

import hashlib
import struct
import time

import pytest

from pweh import dhav, media_candidates, media_units, schemas
from pweh.errors import PwehError

KINDS = ("bmff", "dhav", "jpeg", "avc-annexb", "mpeg2-ps", "xm")
SUFFIX = ["exfat_valid_data_length_residual_only", "logical_offsets_not_evidence_offsets",
          "no_original_recording_or_deletion_verification"]
PROFILES = {
    "bmff": "ftyp-contiguous-exfat-residual-v1", "dhav": "dhav-record-exfat-residual-v1",
    "jpeg": "jpeg-baseline-marker-exfat-residual-v1",
    "avc-annexb": "avc-annexb-delimited-nal-exfat-residual-v1",
    "mpeg2-ps": "mpeg2-ps-bounded-pack-prefix-exfat-residual-v1",
    "xm": "xm-length-delimited-frame-exfat-residual-v1",
}


def sample(kind):
    """기존 형식 시험의 독립 합성 구조만 재사용한다."""
    if kind == "bmff":
        from core.test_media_candidate_input import box
        return box(b"ftyp", b"isom\0\0\0\0") + box(b"mdat", b"synthetic")
    if kind == "dhav":
        from core.test_dhav_candidate_input import record
        return record(payload=b"synthetic")
    if kind == "jpeg":
        return bytes.fromhex("ffd8ffc0000b080001000101011100ffda0008010100003f0058ffd9")
    if kind == "avc-annexb":
        return b"\0\0\1\x0a\0\0\1\x0b"
    if kind == "mpeg2-ps":
        return bytes.fromhex("000001ba440004000401000007f8000001e0000480000058000001b9")
    return b"\0\0\1\xfd" + struct.pack("<I", 1) + b"X"


def schema_name(kind):
    return {"bmff": "media-candidates", "dhav": "dhav-candidates"}.get(kind, "media-unit-candidates")


def report_for(kind, *, mode="residual", data=None, ev="EV-0001", evidence_sha=None):
    data = sample(kind) if data is None else data
    deadline = time.monotonic() + 20
    if kind == "bmff":
        report = media_candidates.scan_bmff_candidates(data, deadline=deadline)
    elif kind == "dhav":
        report = dhav.scan_dhav_candidates(data, deadline=deadline)
    else:
        report = media_units.scan_media_unit_candidates(data, format=kind, deadline=deadline)
    report["source"] = {
        "kind": "evidence", "evidence_id": ev, "evidence_sha256": evidence_sha or "e" * 64,
        "container": "file", "member_selected": False, "selected_sha256": hashlib.sha256(data).hexdigest(),
        "selected_size": len(data), "complete": True, "method": "whole-file", "confidence": "high",
        "partition": None, "ref": None, "deleted": None, "parent_deleted": None,
        "container_truncated": None, "container_truncated_reasons": [],
    }
    report["params"] = {"partition": None, "method": "auto", "max_seconds": 45.0}
    if kind not in ("bmff", "dhav"):
        report["params"]["format"] = kind
    if mode == "residual":
        report["profile"] = PROFILES[kind]
        report["limitations"] += SUFFIX
        report["source"].update(container="filesystem", member_selected=True, method="nofatchain",
                                partition=1, ref="root/3", deleted=False, parent_deleted=False,
                                region="residual", data_length=37 + len(data), valid_data_length=37)
        report["params"].update(partition=1, region="residual")
    elif mode == "range":
        report["profile"] = ({"bmff": "ftyp-contiguous-ev-range-v1", "dhav": dhav.RANGE_PROFILE}.get(kind)
                             or media_units.RANGE_PROFILES[kind])
        report["limitations"] += ["explicit_evidence_range_only", "outside_range_unexamined"]
        report["source"].update(method="byte-range", offset=5, evidence_size=len(data) + 5)
        report["params"].update(offset=5, length=len(data))
    return report


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("mode", ["file", "range", "residual"])
def test_independent_three_profile_shapes(kind, mode):
    report = report_for(kind, mode=mode)
    schemas.validate(schema_name(kind), report)
    assert len(report["source"]) == {"file": 16, "range": 18, "residual": 19}[mode]
    assert len(report["params"]) == ({"file": 3, "range": 5, "residual": 4}[mode]
                                     + (kind not in ("bmff", "dhav")))
    if kind in media_units.FORMATS:
        media_units.validate_media_unit_accounting(report)
    if mode != "residual":
        assert "region" not in report["source"] and "region" not in report["params"]


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("section,key,value", [
    ("source", "region", "data"), ("source", "container", "file"),
    ("source", "member_selected", False), ("source", "method", "auto"),
    ("source", "method", "empty"), ("source", "method", "fat-chain"),
    ("source", "method", "skip-claimed"), ("source", "partition", None),
    ("source", "partition", 4097), ("source", "ref", "arc:1"),
    ("source", "ref", "root/3\n"), ("source", "evidence_id", "EV-0001\n"),
    ("source", "evidence_sha256", "e" * 64 + "\n"),
    ("source", "selected_sha256", "a" * 64 + "\n"),
    ("source", "selected_size", 0), ("source", "data_length", 0),
    ("source", "data_length", 1 << 63), ("source", "valid_data_length", -1),
    ("source", "offset", 0), ("source", "evidence_size", 1000),
    ("source", "path", "PRIVATE"), ("params", "region", "data"),
    ("params", "partition", None), ("params", "method", "skip-claimed"),
    ("params", "offset", 0), ("params", "length", 1),
])
def test_residual_source_and_params_are_closed(kind, section, key, value):
    report = report_for(kind)
    report[section][key] = value
    with pytest.raises(PwehError):
        schemas.validate(schema_name(kind), report)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("mode", ["file", "range"])
@pytest.mark.parametrize("section", ["source", "params"])
def test_old_branches_reject_even_explicit_data_region(kind, mode, section):
    report = report_for(kind, mode=mode)
    report[section]["region"] = "data"
    with pytest.raises(PwehError):
        schemas.validate(schema_name(kind), report)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("change", ["file-profile", "range-profile", "file-source", "range-params", "suffix", "format"])
def test_profile_source_params_limitations_cannot_mix(kind, change):
    report = report_for(kind)
    if change.endswith("profile"):
        report["profile"] = report_for(kind, mode=change.split("-")[0])["profile"]
    elif change == "file-source":
        report["source"] = report_for(kind, mode="file")["source"]
    elif change == "range-params":
        report["params"] = report_for(kind, mode="range")["params"]
    elif change == "suffix":
        report["limitations"][-1] = "outside_range_unexamined"
    else:
        report["params"]["format"] = "jpeg" if kind != "jpeg" else "xm"
    with pytest.raises(PwehError):
        schemas.validate(schema_name(kind), report)


@pytest.mark.parametrize("kind", media_units.FORMATS)
@pytest.mark.parametrize("change", ["dl", "vdl", "partition", "method", "params-float", "source-extra"])
def test_unit_accounting_binds_residual_arithmetic_without_changing_scanner(kind, change):
    report = report_for(kind)
    if change == "dl":
        report["source"]["data_length"] += 1
    elif change == "vdl":
        report["source"]["valid_data_length"] = 37.0
    elif change == "partition":
        report["params"]["partition"] = 2
    elif change == "method":
        report["params"]["method"] = "chain"
    elif change == "params-float":
        report["params"]["partition"] = 1.0
    else:
        report["source"]["extra"] = None
    with pytest.raises(PwehError):
        media_units.validate_media_unit_accounting(report)


@pytest.mark.parametrize("kind", KINDS)
def test_large_data_length_small_residual_is_a_valid_schema_relation(kind):
    report = report_for(kind)
    size = report["source"]["selected_size"]
    report["source"].update(data_length=(1 << 63) - 1, valid_data_length=(1 << 63) - 1 - size)
    schemas.validate(schema_name(kind), report)
    if kind in media_units.FORMATS:
        media_units.validate_media_unit_accounting(report)
