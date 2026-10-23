"""옛 single 계약 보존과 새 full range의 닫힌 shape·동적 관계를 독립 검사한다."""
from __future__ import annotations

import copy
import hashlib
import json
import time

import pytest
from jsonschema import Draft202012Validator

from pweh import schemas, secretscan as S
from pweh.errors import ValidationFailed


def example():
    # scanner를 호출하지 않는 고정 3바이트 plain 선택 봉투다.
    return {"schema": "pweh.secrets-scan/v1", "profile": "utf8-masked-secrets-ev-range-v1", "status": "ok",
            "source": {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a" * 64,
                       "evidence_size": 3, "offset": 0, "length": 3, "selected_sha256": "b" * 64,
                       "selected_size": 3, "complete": True},
            "params": {"xor_key": None, "max_hits": 200, "decoder": "utf-8", "max_seconds": 45,
                       "prefix_complete": True, "suffix_complete": True},
            "rules": {"pack": "pweh-credential-spans-v1", "pattern_ids": list(S.PATTERN_IDS)},
            "coverage": {"input_bytes": 3, "read_bytes": 3, "scanned_bytes": 3, "framing_bytes": 0,
                         "unscanned_bytes": 0, "scanned_ranges": [{"offset": 0, "length": 3, "framing_bytes": 0}],
                         "unscanned_ranges": [], "lines_seen": 1, "lines_scanned": 1, "lines_skipped": 0,
                         "analysis_complete": True, "container_examined": False, "selection_uncertain": False,
                         "hits_are_lower_bound": False, "reasons": []},
            "matches": [], "summary": {"hits": 0, "by_kind": dict.fromkeys(S.KINDS, 0), "unique_digest_count": 0},
            "limitations": list(S.RANGE_LIMITATIONS)}


def old_example():
    r = example()
    r.pop("profile")
    for key in ("prefix_complete", "suffix_complete"):
        r["params"].pop(key)
    r["source"] = {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a" * 64,
                   "container": "file", "member_selected": False, "selected_sha256": "b" * 64,
                   "selected_size": 3, "complete": True, "method": "whole-file", "confidence": "high"}
    r["limitations"] = list(S.LIMITATIONS)
    return r


def actual(data=b"password=Alpha42 psk=Beta42\n", **kw):
    r = S.scan_secrets(data, digest=lambda value: "sha256:" + hashlib.sha256(value).hexdigest()[:16],
                       deadline=time.monotonic() + 45, cancel=lambda: False,
                       boundary=S.SelectionBoundary(True, True), **kw)
    r["params"]["max_seconds"] = 45
    r["source"] = {**example()["source"], "evidence_size": len(data), "length": len(data),
                   "selected_size": len(data), "selected_sha256": hashlib.sha256(data).hexdigest()}
    return r


def put(report, path, value):
    current = report
    for key in path[:-1]:
        current = current[key]
    current[path[-1]] = value


def reject(report):
    with pytest.raises(ValidationFailed) as exc:
        S.validate_secrets_range_accounting(report)
    assert "SYNTHETIC_PRIVATE" not in str(exc.value)
    assert exc.value.data in (None, {})


def test_schema_is_valid_and_legacy_object_is_exactly_preserved():
    schema = schemas.load("secrets-scan")
    Draft202012Validator.check_schema(schema)
    assert schema["oneOf"] == [{"$ref": "#/$defs/legacy_report"}, {"$ref": "#/$defs/range_report"}]
    legacy = json.dumps(schema["$defs"]["legacy_report"], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    assert hashlib.sha256(legacy).hexdigest() == "36f5cd39feec4915468553fb730e26b50ebaefc25d54384cbe941837f7ed9905"
    schemas.validate("secrets-scan", old_example())
    schemas.validate("secrets-scan", example())
    S.validate_secrets_range_accounting(example())
    reject(old_example())


@pytest.mark.parametrize("change", ["old_profile", "old_boundary", "old_reason", "old_limitations", "range_without_profile",
                                    "range_old_source", "range_old_params", "range_old_limitations"])
def test_old_new_mixed_shapes_fail_closed(change):
    old, new = old_example(), example()
    if change.startswith("old"):
        r = old
        if change == "old_profile": r["profile"] = S.RANGE_PROFILE
        elif change == "old_boundary": r["params"]["prefix_complete"] = True
        elif change == "old_reason": r["coverage"]["reasons"] = ["selection_boundary"]
        else: r["limitations"] = new["limitations"]
    else:
        r = new
        if change == "range_without_profile": r.pop("profile")
        elif change == "range_old_source": r["source"] = old["source"]
        elif change == "range_old_params": r["params"] = old["params"]
        else: r["limitations"] = old["limitations"]
    with pytest.raises(ValidationFailed):
        schemas.validate("secrets-scan", r)


@pytest.mark.parametrize("path", [(), ("source",), ("params",), ("rules",), ("coverage",),
    ("coverage", "scanned_ranges", 0), ("summary",), ("summary", "by_kind")])
def test_closed_maps_and_each_required_field(path):
    base = example()
    target = base
    for key in path:
        target = target[key]
    keys = tuple(target)
    for key in (*keys, "SYNTHETIC_PRIVATE"):
        r = copy.deepcopy(base)
        current = r
        for part in path:
            current = current[part]
        if key in current:
            current.pop(key)
        else:
            current[key] = "SYNTHETIC_PRIVATE"
        with pytest.raises(ValidationFailed):
            schemas.validate("secrets-scan", r)
        reject(r)


@pytest.mark.parametrize("path", [("source", "evidence_size"), ("source", "offset"), ("source", "length"),
    ("source", "selected_size"), ("params", "max_hits"), ("coverage", "input_bytes"),
    ("coverage", "read_bytes"), ("coverage", "scanned_bytes"), ("coverage", "framing_bytes"),
    ("coverage", "unscanned_bytes"), ("coverage", "lines_seen"), ("coverage", "lines_scanned"),
    ("coverage", "lines_skipped"), ("coverage", "scanned_ranges", 0, "offset"),
    ("coverage", "scanned_ranges", 0, "length"), ("coverage", "scanned_ranges", 0, "framing_bytes"),
    ("summary", "hits"), ("summary", "by_kind", "password"), ("summary", "unique_digest_count")])
@pytest.mark.parametrize("kind", ["float", "bool"])
def test_integer_numbers_have_exact_python_type(path, kind):
    r = example()
    value = r
    for key in path:
        value = value[key]
    put(r, path, float(value) if kind == "float" else bool(value))
    reject(r)


@pytest.mark.parametrize("path", [("source", "complete"), ("params", "prefix_complete"), ("params", "suffix_complete"),
    ("coverage", "analysis_complete"), ("coverage", "container_examined"),
    ("coverage", "selection_uncertain"), ("coverage", "hits_are_lower_bound")])
def test_boolean_numbers_are_not_flags(path):
    r = example()
    put(r, path, 1 if path[-1] in ("complete", "prefix_complete", "suffix_complete", "analysis_complete") else 0)
    reject(r)


@pytest.mark.parametrize("path,value", [(("source", "evidence_size"), 2), (("source", "evidence_size"), 4),
    (("source", "offset"), 1), (("source", "length"), 2), (("source", "selected_size"), 2),
    (("source", "evidence_size"), 1 << 63), (("source", "offset"), -1), (("source", "length"), 0),
    (("source", "length"), (4 << 20) + 1), (("params", "prefix_complete"), False),
    (("params", "suffix_complete"), False), (("params", "max_seconds"), float("nan")),
    (("params", "max_seconds"), float("inf")), (("params", "max_seconds"), True),
    (("params", "max_seconds"), 0), (("params", "max_seconds"), 45.01), (("params", "xor_key"), 144.0),
    (("coverage", "scanned_ranges", 0, "offset"), 1), (("coverage", "scanned_ranges", 0, "length"), 2),
    (("coverage", "scanned_ranges", 0, "framing_bytes"), 4), (("coverage", "lines_seen"), 2),
    (("coverage", "reasons"), ["selection_boundary"]), (("coverage", "reasons"), ["selection_uncertain"]),
    (("coverage", "reasons"), ["time_limit", "time_limit"]), (("status",), "partial"),
    (("rules", "pattern_ids"), ["SYNTHETIC_PRIVATE"]), (("summary", "hits"), 1)])
def test_dynamic_source_coverage_and_status_relationships(path, value):
    r = example()
    put(r, path, value)
    reject(r)


@pytest.mark.parametrize("key", ["evidence_id", "evidence_sha256", "selected_sha256"])
def test_new_identifiers_have_exact_end(key):
    r = example()
    r["source"][key] += "\n"
    with pytest.raises(ValidationFailed):
        schemas.validate("secrets-scan", r)
    reject(r)
    if key == "evidence_id":
        old = old_example()
        old["source"][key] += "\n"
        schemas.validate("secrets-scan", old)  # 기존 정규식 의미를 이번 분기에서 바꾸지 않는다.


@pytest.mark.parametrize("path,value", [(("offset",), 999), (("length",), 0), (("line",), 2),
    (("offset",), 9.0), (("length",), True), (("line",), 1.0), (("kind",), "SYNTHETIC_PRIVATE"),
    (("masked",), "SYNTHETIC_PRIVATE"), (("value_complete",), 1), (("digest",), "SYNTHETIC_PRIVATE"),
    (("digest",), None), (("pattern_ids",), []), (("pattern_ids",), [S.PATTERN_IDS[0]] * 2),
    (("confidence",), "confirmed")])
def test_match_relations_and_no_raw_error(path, value):
    r = actual()
    put(r, ("matches", 0, *path), value)
    reject(r)


def test_match_order_summary_and_explicit_boundary_intersection():
    r = actual()
    schemas.validate("secrets-scan", r)
    S.validate_secrets_range_accounting(r)
    for mutate in (lambda x: x["matches"].reverse(), lambda x: x["matches"].append(copy.deepcopy(x["matches"][0])),
                   lambda x: x["summary"]["by_kind"].update(password=0)):
        bad = copy.deepcopy(r)
        mutate(bad)
        reject(bad)
    size = r["source"]["length"]
    r["source"].update(offset=1, evidence_size=size + 1)
    r["params"]["prefix_complete"] = False
    r["status"] = "partial"
    r["coverage"].update(scanned_bytes=0, framing_bytes=0, unscanned_bytes=size, scanned_ranges=[],
                          unscanned_ranges=[{"offset": 0, "length": size, "reason": "selection_boundary"}],
                          reasons=["selection_boundary"], lines_scanned=0, lines_skipped=1,
                          analysis_complete=False, hits_are_lower_bound=True)
    schemas.validate("secrets-scan", r)
    reject(r)


def test_bom_ranges_unsupported_and_lowered_limits_are_actual_valid_results():
    for data, kw in [(b"\xef\xbb\xbf", {}), (b"plain\r\n", {}), (b"\xff", {}),
                     (b"password=Alpha42 psk=Beta42\n", {"limits": S.ScanLimits(max_hits=1)}),
                     (b"password=Alpha42\n" * 60, {"limits": S.ScanLimits(max_output_bytes=4096)})]:
        r = actual(data, **kw)
        schemas.validate("secrets-scan", r)
        S.validate_secrets_range_accounting(r)


def test_pure_report_or_partial_envelope_is_not_validator_input():
    for names in (("source",), ("params",), ("source", "params")):
        r = example()
        for name in names:
            r.pop(name)
        reject(r)
    r = example()
    r["params"].pop("max_seconds")
    reject(r)


def test_bounded_arrays_and_duplicate_ranges_are_rejected():
    for path, value in [(("coverage", "scanned_ranges"), [{"offset": 0, "length": 3, "framing_bytes": 0}] * 1025),
                        (("coverage", "unscanned_ranges"), [None] * 1025), (("matches",), [None] * 201),
                        (("coverage", "reasons"), ["time_limit"] * 14)]:
        r = example()
        put(r, path, value)
        reject(r)
