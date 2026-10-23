"""독립 저장 fixture로 보호 선언의 닫힌 shape와 profile 호환을 검증한다."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from pweh import schemas
from pweh.errors import ValidationFailed
from core.test_media_declarations_schema import NEW_LIMITATIONS, change, new_report, old_report


PROFILE = "mp4-quicktime-protection-declarations-v1"
SCOPE = "mvhd-mdhd-pssh-sample-protection-selected-contexts"
LIMITATIONS = NEW_LIMITATIONS[:-1] + [
    "sample_protection_prefixes_only", "full_tenc_and_constant_iv_unexamined",
    "sample_auxiliary_and_groups_unexamined", "protection_declarations_not_encryption_proof",
]


def empty_protection():
    return {
        "scope": "stsd-encv-enca-sinf-schm-tenc-prefixes", "status": "complete",
        "tables": [], "entries": [], "schemes": [], "track_defaults": [],
        "coverage": {"traversal_complete": True, "fields_complete": True, "reasons": []},
        "full_tenc_examined": False, "sample_auxiliary_examined": False, "identifiers_returned": False,
    }


def empty_report():
    report = old_report()
    report.update(profile=PROFILE, limitations=list(LIMITATIONS))
    report["declarations"] = {
        "scope": SCOPE, "status": "complete", "timing": [], "pssh": [],
        "coverage": {"traversal_complete": True, "fields_complete": True, "reasons": []},
        "absolute_times_returned": False, "sample_entries_examined": False,
        "sample_encryption_examined": False, "protection": empty_protection(),
    }
    return report


def protection_report():
    """고정 210바이트 트리의 독립 행/좌표다. 코어 실행으로 expected를 만들지 않는다."""
    report = empty_report()
    kinds = ["moov", "trak", "mdia", "minf", "stbl", "stsd", "encv", "sinf", "schm", "schi", "tenc"]
    offsets = [0, 8, 16, 24, 32, 40, 56, 142, 150, 170, 178]
    parents = [None, 0, 1, 2, 3, 4, 5, 6, 7, 7, 9]
    depths = [1, 2, 3, 4, 5, 6, 7, 8, 9, 9, 10]
    report["boxes"] = [
        {"index": i, "parent_index": parents[i], "kind": kind, "offset": offsets[i],
         "size": (170 if i == 8 else 210) - offsets[i], "header_size": 8, "depth": depths[i],
         "handling": "declaration" if i in (8, 10) else "children",
         "children_complete": None if i in (8, 10) else True}
        for i, kind in enumerate(kinds)
    ]
    ranges = [
        (0, 48, "header", "box_header"), (48, 8, "header", "declaration_fields"),
        (56, 8, "header", "box_header"), (64, 78, "skipped", "declaration_payload"),
        (142, 16, "header", "box_header"), (158, 8, "header", "declaration_fields"),
        (166, 4, "skipped", "declaration_payload"), (170, 16, "header", "box_header"),
        (186, 4, "header", "declaration_fields"), (190, 2, "skipped", "declaration_payload"),
        (192, 1, "header", "declaration_fields"), (193, 17, "skipped", "declaration_payload"),
    ]
    report["coverage"].update(input_bytes=210, header_bytes=109, skipped_payload_bytes=101,
        ranges=[dict(zip(("offset", "length", "kind", "reason"), row)) for row in ranges])
    report["source"]["selected_size"] = 210
    report["summary"].update(boxes_seen=11, boxes_reported=11, unknown_box_count=0,
        unknown_type_distinct_count=0, max_depth_seen=10)
    report["observations"].update(top_level_moov=True, initialization_context="moov-observed")
    report["declarations"]["sample_entries_examined"] = True
    report["declarations"]["protection"].update(
        tables=[{"box_index": 5, "version": 0, "entries_declared": 1, "entries_reported": 1,
                 "entries_complete": True, "status": "complete", "issues": []}],
        entries=[{"box_index": 6, "parent_index": 5, "kind": "encv", "prefix_kind": "visual",
                  "status": "complete", "issues": []}],
        schemes=[{"box_index": 8, "parent_index": 7, "entry_index": 6, "version": 0,
                  "scheme_type": "cenc", "status": "complete", "issues": []}],
        track_defaults=[{"box_index": 10, "parent_index": 9, "entry_index": 6, "version": 0,
                         "default_is_protected_state": "one", "status": "complete", "issues": []}],
    )
    return report


def validate(report):
    from pweh.media import validate_media_protection_accounting
    schemas.validate("media-inventory", report)
    validate_media_protection_accounting(report)


@pytest.mark.parametrize("factory", [empty_report, protection_report])
def test_independent_protection_fixture(factory):
    validate(factory())


def test_old_definitions_are_preserved_exactly():
    """c657035의 독립 canonical SHA로 옛 하위 정의의 비완화를 확인한다."""
    root = Path(__file__).resolve().parents[2]
    path = "src/pweh/schemas/media-inventory.schema.json"
    current = json.loads((root / path).read_text())
    expected = {
        "source_rule": "1c4e4cf35f35229db52a7b55db68ce464907f6692d3d6bd1e676faf517ff82d4",
        "source": "34d8a047bfa264ee2e46c89e8fdf84c20f08354869720b501cc5cdb306b55356",
        "params": "23757e839b10103b1f34b8025d73b75f3f8fb2ecba95570d03a3b50323a2f7d6",
        "legacy_boxes": "bb0587ad7fbc731afa7e711a4102cd6ff08004f562b6d770a56b9f0a4f422d58",
        "legacy_summary": "0cce65d3f3adf50a2371e33c0644d57d05eabf5e5149b931f5db2726c72be480",
        "legacy_coverage": "fb5d954c9d503add5082cfd13d99bc3e7473d6263c1a0f43345acf48b0b9447e",
        "declarations_v1": "a73b7f91b3f61cd8707bee7c4fac6faa4e339c8460c53a188392e69031df7835",
        "timing_declaration": "19dee644363c6a4d2b74f1bbf6fa2b7ee39e3bd4da7cc54a86477e595ea77f77",
        "pssh_declaration": "bf80e3e5b79a41a3cf972ddee7d23319b666620114d0c9cd3f0ca07664d0e627",
    }
    for key, digest in expected.items():
        node = (current["allOf"][0] if key == "source_rule" else
                current["properties"][key] if key in ("source", "params") else current["$defs"][key])
        encoded = json.dumps(node, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        assert hashlib.sha256(encoded).hexdigest() == digest


@pytest.mark.parametrize("factory", [old_report, new_report])
@pytest.mark.parametrize("mutation", [
    (("boxes", 0, "kind"), kind) for kind in ("stsd", "encv", "enca", "sinf", "schm", "schi", "tenc")
] + [
    (("boxes", 0, "depth"), 9), (("summary", "max_depth_seen"), 9),
    (("coverage", "reasons"), ["unsupported_protection_shape"]),
    (("coverage", "ranges", 0, "reason"), "stsd_entry_count_mismatch"),
    (("limitations",), LIMITATIONS),
])
def test_both_old_profiles_reject_new_vocabulary(factory, mutation):
    report = factory()
    change(report, *mutation)
    with pytest.raises(ValidationFailed):
        schemas.validate("media-inventory", report)


@pytest.mark.parametrize("factory", [old_report, new_report])
def test_both_old_profiles_reject_new_declaration_section(factory):
    report = factory()
    report["declarations"] = empty_report()["declarations"]
    with pytest.raises(ValidationFailed):
        schemas.validate("media-inventory", report)


@pytest.mark.parametrize("mutation", [
    (("profile",), "mp4-quicktime-declarations-v1"), (("limitations",), NEW_LIMITATIONS),
    (("declarations", "scope"), "mvhd-mdhd-pssh-selected-contexts"),
    (("declarations", "protection", "scope"), "all-encryption"),
    (("declarations", "protection", "full_tenc_examined"), True),
    (("declarations", "protection", "sample_auxiliary_examined"), True),
    (("declarations", "protection", "identifiers_returned"), True),
    (("declarations", "sample_encryption_examined"), True),
    (("declarations", "absolute_times_returned"), True),
    (("encryption_assessed",), True), (("boxes", 10, "depth"), 11),
    (("summary", "max_depth_seen"), 11),
    (("declarations", "protection", "coverage", "reasons"), ["zero_timescale"]),
    (("declarations", "protection", "coverage", "reasons"), ["pssh_length_mismatch"]),
    (("declarations", "protection", "coverage", "reasons"), ["selection_uncertain"]),
    (("declarations", "protection", "tables", 0, "entries_declared"), 4294967296),
    (("declarations", "protection", "tables", 0, "entries_reported"), 4097),
    (("declarations", "protection", "tables", 0, "version"), 1),
    (("declarations", "protection", "tables", 0, "entries_declared"), None),
    (("declarations", "protection", "entries", 0, "prefix_kind"), "audio-v0"),
    (("declarations", "protection", "entries", 0, "kind"), "unknown"),
    (("declarations", "protection", "entries", 0, "prefix_kind"), "unread"),
    (("declarations", "protection", "schemes", 0, "scheme_type"), "cbca"),
    (("declarations", "protection", "schemes", 0, "scheme_type"), "other"),
    (("declarations", "protection", "schemes", 0, "version"), 1),
    (("declarations", "protection", "track_defaults", 0, "version"), 2),
    (("declarations", "protection", "track_defaults", 0, "default_is_protected_state"), "other"),
    (("declarations", "protection", "track_defaults", 0, "default_is_protected_state"), 1),
])
def test_closed_new_profile(mutation):
    report = protection_report()
    change(report, *mutation)
    with pytest.raises(ValidationFailed):
        schemas.validate("media-inventory", report)


@pytest.mark.parametrize("section", ["tables", "entries", "schemes", "track_defaults"])
@pytest.mark.parametrize("field", ["raw", "kid", "iv", "sha256", "uri"])
def test_protection_rows_reject_arbitrary_metadata(section, field):
    report = protection_report()
    report["declarations"]["protection"][section][0][field] = "PRIVATE"
    with pytest.raises(ValidationFailed):
        schemas.validate("media-inventory", report)


@pytest.mark.parametrize("field", list(empty_protection()))
def test_protection_requires_all_ten_fields(field):
    report = empty_report()
    del report["declarations"]["protection"][field]
    with pytest.raises(ValidationFailed):
        schemas.validate("media-inventory", report)


@pytest.mark.parametrize("mutation", [
    (("declarations", "protection", "tables", 0, "box_index"), 4),
    (("declarations", "protection", "tables", 0, "entries_reported"), 0),
    (("declarations", "protection", "tables", 0, "entries_declared"), 0),
    (("declarations", "protection", "entries", 0, "parent_index"), 4),
    (("declarations", "protection", "schemes", 0, "parent_index"), 9),
    (("declarations", "protection", "schemes", 0, "entry_index"), 5),
    (("declarations", "protection", "track_defaults", 0, "entry_index"), 7),
    (("declarations", "protection", "track_defaults", 0, "parent_index"), 7),
    (("boxes", 6, "parent_index"), 4), (("boxes", 7, "parent_index"), 5),
    (("boxes", 4, "kind"), "udta"), (("boxes", 8, "handling"), "skipped"),
    (("boxes", 5, "children_complete"), False),
])
def test_cross_array_relations_reject_schema_valid_forgery(mutation):
    from pweh.media import validate_media_protection_accounting
    report = protection_report()
    change(report, *mutation)
    schemas.validate("media-inventory", report)
    with pytest.raises(ValidationFailed):
        validate_media_protection_accounting(report)


@pytest.mark.parametrize("section", ["tables", "entries", "schemes", "track_defaults"])
def test_duplicate_row_index_is_rejected(section):
    from pweh.media import validate_media_protection_accounting
    report = protection_report()
    rows = report["declarations"]["protection"][section]
    rows.append(copy.deepcopy(rows[0]))
    schemas.validate("media-inventory", report)
    with pytest.raises(ValidationFailed):
        validate_media_protection_accounting(report)


@pytest.mark.parametrize("value", [True, 1.0])
@pytest.mark.parametrize("section,field", [("tables", "entries_declared"), ("tables", "entries_reported"),
                                          ("entries", "box_index"), ("schemes", "entry_index")])
def test_exact_integer_relationships(section, field, value):
    report = protection_report()
    report["declarations"]["protection"][section][0][field] = value
    with pytest.raises(ValidationFailed):
        validate(report)


def test_count_prefix_remains_complete_when_traversal_stops():
    report = protection_report()
    protection = report["declarations"]["protection"]
    table = protection["tables"][0]
    table.update(entries_declared=4294967295, entries_complete=False)
    report["boxes"][5]["children_complete"] = False
    report.update(status="partial", framing_status="partial")
    report["coverage"].update(structure_complete=False, reasons=["time_limit"])
    for section in (report["declarations"], protection):
        section["status"] = "partial"
        section["coverage"].update(traversal_complete=False, reasons=["time_limit"])
    validate(report)
    assert table["status"] == "complete" and protection["coverage"]["fields_complete"]


@pytest.mark.parametrize("kind", ["sinf", "tenc", "stsd", "mdat", "unknown"])
def test_known_other_entry_keeps_box_kind_without_protection_children(kind):
    report = protection_report()
    report["boxes"] = report["boxes"][:7]
    entrybox = report["boxes"][6]
    entrybox.update(kind=kind, handling="declaration", children_complete=None)
    report["summary"].update(boxes_seen=7, boxes_reported=7, max_depth_seen=7,
                            unknown_box_count=int(kind == "unknown"), unknown_type_distinct_count=int(kind == "unknown"))
    report["coverage"].update(header_bytes=64, skipped_payload_bytes=146, reasons=["unsupported_sample_entry"], ranges=[
        {"offset": 0, "length": 48, "kind": "header", "reason": "box_header"},
        {"offset": 48, "length": 8, "kind": "header", "reason": "declaration_fields"},
        {"offset": 56, "length": 8, "kind": "header", "reason": "box_header"},
        {"offset": 64, "length": 146, "kind": "skipped", "reason": "declaration_payload"}])
    report["status"] = "partial"
    protection = report["declarations"]["protection"]
    protection["entries"][0].update(kind="other", prefix_kind="unsupported", status="unsupported", issues=["unsupported_sample_entry"])
    protection.update(schemes=[], track_defaults=[])
    report["declarations"]["sample_entries_examined"] = False
    for section in (report["declarations"], protection):
        section["status"] = "partial"
        section["coverage"].update(fields_complete=False, reasons=["unsupported_sample_entry"])
    validate(report)


@pytest.mark.parametrize("kind", ["timing", "pssh"])
def test_unrelated_malformed_declaration_does_not_pollute_empty_protection(kind):
    from pweh.media import validate_media_protection_accounting
    report = new_report()
    report.update(profile=PROFILE, limitations=list(LIMITATIONS), status="partial")
    declarations = report["declarations"]
    declarations.update(scope=SCOPE, protection=empty_protection(), status="partial")
    row = declarations[kind][0]
    row.update(status="malformed", version=None, issues=["truncated_declaration_fields"])
    if kind == "timing":
        row.update(creation_time_state="unread", modification_time_state="unread", timescale=None,
                   duration_units=None, duration_state="unread")
    declarations["coverage"].update(fields_complete=False, reasons=["truncated_declaration_fields"])
    report["coverage"]["reasons"] = ["truncated_declaration_fields"]
    validate(report)
    protection = declarations["protection"]
    assert protection["status"] == "complete" and protection["coverage"]["reasons"] == []
    protection["coverage"]["reasons"] = ["truncated_declaration_fields"]
    schemas.validate("media-inventory", report)
    with pytest.raises(ValidationFailed):
        validate_media_protection_accounting(report)
