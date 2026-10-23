"""독립 manifest로 residual 출처와 기존 file/range 분기의 분리를 확인한다."""

from __future__ import annotations

import copy

import pytest

from core.test_dhav_record_extract_schema import manifest as dhav_manifest
from core.test_media_candidate_range_schema import old_report, prefix, range_report
from core.test_media_unit_extract_schema import manifest as unit_manifest
from pweh import schemas
from pweh.errors import ValidationFailed

KINDS = ("bmff", "dhav", "jpeg", "avc-annexb", "mpeg2-ps", "xm")
SCHEMAS = {"bmff": "media-prefix-extract", "dhav": "dhav-record-extract"}
PROFILES = {
    "jpeg": "jpeg-baseline-marker-exfat-residual-v1",
    "avc-annexb": "avc-annexb-delimited-nal-exfat-residual-v1",
    "mpeg2-ps": "mpeg2-ps-bounded-pack-prefix-exfat-residual-v1",
    "xm": "xm-length-delimited-frame-exfat-residual-v1",
}


def manifest(kind, *, region="residual"):
    """기존 독립 fixture를 소비하며 제품 parser·source helper를 쓰지 않는다."""
    ranged = region == "range"
    if kind == "bmff":
        result = prefix(range_report() if ranged else old_report())
    elif kind == "dhav":
        result = dhav_manifest(ranged=ranged)
    else:
        result = unit_manifest(format=kind, ranged=ranged)
    if region == "residual":
        size = result["source"]["selected_size"]
        result["source"].update(container="filesystem", member_selected=True, method="nofatchain",
                                partition=1, ref="root/3", deleted=False, parent_deleted=False,
                                region="residual", data_length=101 + size, valid_data_length=101)
        if kind in PROFILES:
            result["source_profile"] = PROFILES[kind]
    return result


def validate(kind, value):
    schemas.validate(SCHEMAS.get(kind, "media-unit-extract"), value)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("region,keys", [("file", 16), ("range", 18), ("residual", 19)])
def test_three_independent_source_branches(kind, region, keys):
    value = manifest(kind, region=region)
    validate(kind, value)
    assert len(value["source"]) == keys
    assert "params" not in value and "profile" not in value
    assert ("source_profile" in value) == (kind in PROFILES)


@pytest.mark.parametrize("kind", ("bmff", "dhav", "xm"))
@pytest.mark.parametrize("key,value", [
    ("region", "data"), ("region", None), ("data_length", 0), ("data_length", 2**63),
    ("data_length", True), ("valid_data_length", -1), ("valid_data_length", 2**63),
    ("valid_data_length", False), ("selected_size", 0), ("selected_size", (64 << 20) + 1),
    ("offset", 0), ("evidence_size", 4096), ("container", "file"), ("container", "zip"),
    ("member_selected", False), ("complete", False), ("method", "auto"), ("method", "byte-range"),
    ("method", "fat-chain"), ("method", "skip-claimed"), ("partition", None), ("partition", 4097),
    ("partition", True), ("ref", "arc:0"), ("ref", None), ("deleted", None),
    ("path", "PRIVATE_RESIDUAL_SOURCE"),
])
def test_residual_source_is_closed(kind, key, value):
    result = manifest(kind)
    result["source"][key] = value
    with pytest.raises(ValidationFailed):
        validate(kind, result)


@pytest.mark.parametrize("kind", ("bmff", "dhav", "xm"))
@pytest.mark.parametrize("key", ("region", "data_length", "valid_data_length", "partition", "ref"))
def test_residual_identity_fields_are_required(kind, key):
    value = manifest(kind)
    del value["source"][key]
    with pytest.raises(ValidationFailed):
        validate(kind, value)


@pytest.mark.parametrize("kind", ("bmff", "dhav", "xm"))
@pytest.mark.parametrize("region", ("file", "range"))
@pytest.mark.parametrize("key,value", [("region", "residual"), ("data_length", 128), ("valid_data_length", 0)])
def test_old_sources_cannot_gain_residual_fields(kind, region, key, value):
    result = manifest(kind, region=region)
    result["source"][key] = value
    with pytest.raises(ValidationFailed):
        validate(kind, result)


@pytest.mark.parametrize("kind", ("bmff", "dhav", "xm"))
@pytest.mark.parametrize("key", ("evidence_id", "evidence_sha256", "selected_sha256", "ref"))
def test_residual_identity_regex_rejects_final_newline(kind, key):
    value = manifest(kind)
    value["source"][key] += "\n"
    with pytest.raises(ValidationFailed):
        validate(kind, value)


@pytest.mark.parametrize("kind", ("bmff", "dhav", "xm"))
@pytest.mark.parametrize("key,value", [("deleted", True), ("parent_deleted", True),
                                      ("parent_deleted", None), ("confidence", "low")])
def test_residual_uncertainty_cannot_be_cleared(kind, key, value):
    result = manifest(kind)
    result["source"][key] = value
    result.update(status="partial", source_status="partial", effective_selection_uncertain=True)
    result["source_coverage"].update(selection_uncertain=True, reasons=["selection_uncertain"])
    validate(kind, result)
    result["effective_selection_uncertain"] = False
    with pytest.raises(ValidationFailed):
        validate(kind, result)


@pytest.mark.parametrize("format", tuple(PROFILES))
@pytest.mark.parametrize("profile_kind", ("file", "range", "other-residual"))
def test_media_unit_profile_cannot_disagree_with_source(format, profile_kind):
    result = manifest(format)
    result["source_profile"] = (PROFILES["xm" if format != "xm" else "jpeg"]
                                if profile_kind == "other-residual"
                                else manifest(format, region=profile_kind)["source_profile"])
    with pytest.raises(ValidationFailed):
        validate(format, result)


@pytest.mark.parametrize("kind", ("bmff", "dhav"))
def test_bmff_dhav_manifest_top_level_is_unchanged(kind):
    value = manifest(kind)
    old = manifest(kind, region="file")
    assert value.keys() == old.keys()
    value["source_profile"] = "unexpected"
    with pytest.raises(ValidationFailed):
        validate(kind, value)


@pytest.mark.parametrize("kind,candidate", [("bmff", "media-candidates"), ("dhav", "dhav-candidates"),
                                           ("xm", "media-unit-candidates")])
def test_candidate_and_manifest_residual_definitions_only_differ_in_minimum(kind, candidate):
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[2] / "src/pweh/schemas"
    source = json.loads((root / (candidate + ".schema.json")).read_text())["$defs"]["exfat_residual_source"]
    output = json.loads((root / (SCHEMAS.get(kind, "media-unit-extract") + ".schema.json")).read_text())
    selected = copy.deepcopy(output["$defs"]["exfat_residual_source"])
    source = copy.deepcopy(source)
    selected["properties"]["selected_size"]["minimum"] = source["properties"]["selected_size"]["minimum"]
    assert selected == source
