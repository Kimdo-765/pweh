"""합성 DHAV record로 경계·검색 prefix·정확 회계·원문 비노출을 확인한다."""

from __future__ import annotations

import copy
import dataclasses
import json
import random
import struct
import time
from types import SimpleNamespace

import pytest

from pweh import dhav as D
from pweh.errors import PwehError, ValidationFailed
from pweh.schemas import validate

PRIVATE = b"PRIVATE_SYNTHETIC_RECORD_872"


def record(kind=0xF0, payload=b"x", extension=b"", *, length=None, footer=None):
    head = bytearray(b"Q" * 24)
    head[:4], head[4], head[22] = b"DHAV", kind, len(extension)
    declared = 32 + len(extension) + len(payload) if length is None else length
    struct.pack_into("<I", head, 12, declared)
    tail = b"dhav" + struct.pack("<I", declared) if footer is None else footer
    return bytes(head) + extension + payload + tail


def run(data, **kwargs):
    kwargs.setdefault("deadline", time.monotonic() + 30)
    return D.scan_dhav_candidates(data, **kwargs)


def envelope(report, *, ranged=False):
    result = copy.deepcopy(report)
    size = result["coverage"]["input_bytes"]
    result["source"] = {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a" * 64,
        "container": "file", "member_selected": False, "selected_sha256": "b" * 64,
        "selected_size": size, "complete": True, "method": "whole-file", "confidence": "high",
        "partition": None, "ref": None, "deleted": None, "parent_deleted": None,
        "container_truncated": None, "container_truncated_reasons": []}
    result["params"] = {"partition": None, "method": "auto", "max_seconds": 45}
    if ranged:
        result["profile"] = D.RANGE_PROFILE
        result["source"].update(method="byte-range", offset=100, evidence_size=size + 200)
        result["params"].update(offset=100, length=size)
        result["limitations"] += list(D.RANGE_LIMITATIONS)
    return result


def check(report, data, limits=D.DhavLimits()):
    validate("dhav-candidates", envelope(report))
    D.validate_dhav_accounting(report)
    cov, summary = report["coverage"], report["summary"]
    n, cursor = len(data), cov["search_positions_examined"]
    assert cov["input_bytes"] == n and cov["search_positions_total"] == max(0, n - 3)
    observed = sum(data[pos:pos + 4] == b"DHAV" for pos in range(cursor))
    pending = cov["pending_anchor_offset"]
    if pending is not None:
        assert pending == cursor and data[pending:pending + 4] == b"DHAV"
    assert summary["anchors_observed"] == observed + int(pending is not None)
    assert cov["anchor_probes"] <= limits.max_anchor_probes
    assert cov["structure_bytes_read"] <= limits.max_structure_bytes
    assert len(report["candidates"]) <= limits.max_candidates
    for row in report["candidates"]:
        start, length = row["offset"], row["record_length"]
        assert data[start:start + 4] == b"DHAV"
        assert data[start + length - 8:start + length - 4] == b"dhav"
        assert struct.unpack_from("<I", data, start + length - 4)[0] == length
    assert len(json.dumps(report, ensure_ascii=True, separators=(",", ":")).encode()) + 1 <= limits.max_output_bytes
    assert all(report[field] is False for field in D.FALSE_FIELDS)
    return report


@pytest.mark.parametrize("data", [b"", b"D", b"DH", b"DHA", b"DAHUA", PRIVATE])
def test_empty_or_no_magic_search_complete_does_not_confirm_format(data):
    result = check(run(data), data)
    assert result["status"] == "unsupported" and result["candidates"] == []
    assert result["coverage"]["candidate_list_complete"]


@pytest.mark.parametrize("kind", [0xF0, 0xFC, 0xFD])
@pytest.mark.parametrize("extension", [b"", b"E" * 255])
def test_supported_record_types_and_extension_bounds(kind, extension):
    data = record(kind, PRIVATE, extension)
    result = check(run(data), data)
    assert result["status"] == "ok"
    assert result["coverage"]["structure_bytes_read"] == 14
    assert result["candidates"] == [{"index": 0, "offset": 0, "record_length": len(data),
        "header_length": 24 + len(extension), "extension_length": len(extension),
        "payload_length": len(PRIVATE), "record_type": f"type_{kind:x}",
        "footer_length_matches": True, "confidence": "possible"}]
    assert PRIVATE.decode() not in json.dumps(result)


@pytest.mark.parametrize("kind", [0, 0xF1, 0xFF])
@pytest.mark.parametrize("short", [True, False])
def test_unknown_and_f1_have_no_common_header_interpretation(kind, short):
    data = b"DHAV" + bytes([kind]) if short else record(kind)
    result = check(run(data), data)
    assert result["status"] == "unsupported"
    assert result["summary"]["anchor_rejections"]["unsupported_record_type"] == 1
    assert result["coverage"]["structure_bytes_read"] == 1
    assert result["coverage"]["candidate_checks_complete"]


@pytest.mark.parametrize("length", range(4, 24))
def test_supported_short_header_is_incomplete_even_after_search_finishes(length):
    data = record()[:length]
    result = check(run(data), data)
    assert result["status"] == "partial"
    assert result["coverage"]["search_complete"] and not result["coverage"]["candidate_checks_complete"]
    assert result["summary"]["anchor_incomplete"]["truncated_header"] == 1


@pytest.mark.parametrize("data,reason", [
    (record(length=0), "length_below_header_and_footer"),
    (record(length=31), "length_below_header_and_footer"),
    (record(payload=b""), "empty_payload"),
    (record(extension=b"E" * 5, length=36), "length_below_header_and_footer"),
    (record(extension=b"E" * 5, payload=b""), "empty_payload"),
    (record(footer=b"DHAV" + struct.pack("<I", 33)), "footer_missing"),
    (record(footer=b"dhav" + struct.pack("<I", 34)), "footer_length_mismatch"),
    (record(footer=b"dhav" + struct.pack(">I", 33)), "footer_length_mismatch"),
])
def test_rejected_length_or_footer_does_not_become_valid_candidate(data, reason):
    result = check(run(data), data)
    assert result["status"] == "unsupported" and not result["candidates"]
    assert result["summary"]["anchor_rejections"][reason] == 1


def test_record_beyond_selection_is_incomplete_and_later_record_still_found():
    first = record(length=0xFFFFFFFF)
    data = first + record()
    result = check(run(data), data)
    assert result["status"] == "partial"
    assert result["summary"]["anchor_incomplete"]["record_beyond_selection"] == 1
    assert result["candidates"][0]["offset"] == len(first)


@pytest.mark.parametrize("offset", range(65528, 65539))
def test_three_byte_window_overlap_preserves_all_header_positions(offset):
    data = b"\0" * offset + record()
    result = check(run(data), data)
    assert result["summary"]["anchors_observed"] == 1
    assert result["candidates"][0]["offset"] == offset


def test_payload_anchors_are_searched_without_payload_semantic_claim():
    inner = record(0xFC)
    data = record(payload=b"AA" + inner + b"BB")
    result = check(run(data), data)
    assert result["status"] == "ok"
    assert [row["offset"] for row in result["candidates"]] == [0, 26]
    assert not result["payload_semantics_examined"]


def test_dahua_wrapper_is_only_uninterpreted_prefix():
    data = b"DAHUA" + b"\0" * (0x400 - 5) + record()
    result = check(run(data), data)
    assert result["candidates"][0]["offset"] == 0x400
    assert "DAHUA" not in json.dumps(result)


@pytest.mark.parametrize("cap,read", [(1, 1), (4, 1), (5, 5), (6, 6), (13, 6)])
def test_structure_budget_charged_before_fixed_field_copy(cap, read):
    limits = dataclasses.replace(D.DhavLimits(), max_structure_bytes=cap)
    data = record()
    result = check(run(data, limits=limits), data, limits)
    cov = result["coverage"]
    assert cov["pending_anchor_offset"] == cov["search_positions_examined"] == 0
    assert cov["structure_bytes_read"] == read
    assert cov["anchor_probes"] == 1 and not cov["candidate_checks_complete"]
    assert cov["reasons"] == ["structure_byte_limit"]
    assert result["summary"]["supported_anchors"] == 0


@pytest.mark.parametrize("changes,reason,cursor,pending,probes,supported,rows,omitted", [
    ({"max_anchor_probes": 1}, "probe_limit", 33, 33, 1, 1, 1, 0),
    ({"max_structure_bytes": 14}, "structure_byte_limit", 33, 33, 2, 1, 1, 0),
    ({"max_candidates": 1}, "candidate_limit", 34, None, 2, 2, 1, 1),
    ({"max_output_bytes": 8192}, "output_limit", 265, None, 9, 9, 8, 1),
])
def test_pending_and_fully_checked_but_omitted_anchor_are_distinct(
        changes, reason, cursor, pending, probes, supported, rows, omitted):
    limits = dataclasses.replace(D.DhavLimits(), **changes)
    data = record() * 10
    result = check(run(data, limits=limits), data, limits)
    cov, summary = result["coverage"], result["summary"]
    assert cov["search_positions_examined"] == cursor and cov["pending_anchor_offset"] == pending
    assert cov["anchor_probes"] == probes and cov["reasons"] == [reason]
    assert summary["supported_anchors"] == supported and summary["candidates_reported"] == rows
    assert summary["candidates_omitted"] == omitted
    assert cov["candidate_checks_complete"] == (pending is None)
    assert not cov["search_complete"] and not cov["candidate_list_complete"]


def test_default_candidate_limit_has_one_verified_omission_and_unsearched_tail():
    data = record() * 129
    result = check(run(data), data)
    assert result["summary"]["candidates_reported"] == 128
    assert result["summary"]["candidates_omitted"] == 1
    assert result["coverage"]["search_positions_examined"] == 128 * 33 + 1
    assert not result["coverage"]["search_complete"]


def test_default_probe_limit_preserves_current_unprocessed_anchor():
    data = b"DHAV\x00" * 1025
    result = check(run(data), data)
    assert result["summary"]["anchors_observed"] == 1025
    assert result["summary"]["anchors_rejected"] == 1024
    assert result["coverage"]["pending_anchor_offset"] == 5120
    assert result["coverage"]["anchor_probes"] == 1024


def test_time_limit_between_windows_reports_exact_examined_prefix(monkeypatch):
    clock = SimpleNamespace(value=0.0)
    monkeypatch.setattr(D.time, "monotonic", lambda: clock.value)
    calls = 0

    def cancel():
        nonlocal calls
        calls += 1
        if calls == 3:
            clock.value = 50.0
        return False

    data = b"\0" * 70000
    result = check(run(data, deadline=100, cancel=cancel), data)
    assert result["coverage"]["search_positions_examined"] == 65533
    assert result["coverage"]["pending_anchor_offset"] is None
    assert result["coverage"]["candidate_checks_complete"]
    assert result["coverage"]["reasons"] == ["time_limit"]


@pytest.mark.parametrize("at", [3, 4, 5, 6, 7, 8])
def test_time_limit_during_anchor_never_commits_partial_row(monkeypatch, at):
    clock, calls = SimpleNamespace(value=0.0), 0
    monkeypatch.setattr(D.time, "monotonic", lambda: clock.value)

    def cancel():
        nonlocal calls
        calls += 1
        if calls == at:
            clock.value = 45.0
        return False

    data = record()
    result = check(run(data, deadline=100, cancel=cancel), data)
    assert result["coverage"]["pending_anchor_offset"] == 0
    assert result["summary"]["supported_anchors"] == 0 and result["candidates"] == []


def test_expired_empty_input_has_no_work_and_complete_empty_domain():
    result = check(run(b"", deadline=-1), b"")
    assert result["status"] == "unsupported" and result["coverage"]["search_complete"]


@pytest.mark.parametrize("at", [1, 3, 7, 10])
def test_cancellation_including_final_check_returns_no_partial(at):
    calls = 0

    def cancel():
        nonlocal calls
        calls += 1
        return calls == at

    with pytest.raises(PwehError) as error:
        run(record(), cancel=cancel)
    assert error.value.code == "cancelled"


@pytest.mark.parametrize("value", [0, 1, None, "PRIVATE", object()])
def test_nonboolean_callback_result_is_fixed_failure(value):
    with pytest.raises(PwehError) as error:
        run(record(), cancel=lambda: value)
    assert error.value.code == "dhav_candidates_failed"
    assert "PRIVATE" not in str(error.value)


def test_callback_exception_is_not_exposed():
    def cancel():
        raise RuntimeError(PRIVATE.decode())

    with pytest.raises(PwehError) as error:
        run(record(), cancel=cancel)
    assert error.value.code == "dhav_candidates_failed"
    assert PRIVATE.decode() not in str(error.value) and error.value.__cause__ is None


@pytest.mark.parametrize("deadline", [True, "deadline", None, float("inf"), float("nan"), 10 ** 400])
def test_invalid_deadline_is_fixed_validation_error(deadline):
    with pytest.raises(ValidationFailed):
        run(record(), deadline=deadline)


@pytest.mark.parametrize("field", [field.name for field in dataclasses.fields(D.DhavLimits)])
@pytest.mark.parametrize("bad", [True, 0, 1.5, "PRIVATE", 1 << 40])
def test_limits_are_exact_bounded_integers(field, bad):
    with pytest.raises(ValidationFailed):
        run(record(), limits=dataclasses.replace(D.DhavLimits(), **{field: bad}))


@pytest.mark.parametrize("kwargs", [{"data": bytearray(b"DHAV")}, {"data": memoryview(b"DHAV")},
    {"limits": {}}, {"cancel": 3}, {"limits": D.DhavLimits(max_output_bytes=8191)},
    {"limits": D.DhavLimits(max_input_bytes=1)}])
def test_invalid_inputs_do_not_start_scan(kwargs):
    args = {"data": record(), **kwargs}
    with pytest.raises(ValidationFailed):
        run(**args)


def test_randomized_small_inputs_match_independent_magic_prefix_accounting():
    rng = random.Random(9021)
    variants = [record(), record(0xFC, b"xyz"), b"DHAV", b"DHAV\xf1", record(length=9999),
                record(payload=b""), record(footer=b"notfooter")]
    for _ in range(60):
        parts = [rng.choice(variants) if rng.randrange(2) else bytes([rng.randrange(32)]) * rng.randrange(16)
                 for _ in range(rng.randrange(1, 12))]
        data = b"".join(parts)
        limits = dataclasses.replace(D.DhavLimits(), max_anchor_probes=rng.randrange(1, 8),
            max_structure_bytes=rng.randrange(1, 80), max_candidates=rng.randrange(1, 5))
        check(run(data, limits=limits), data, limits)


def test_conservative_output_reservation_covers_maximum_numeric_widths():
    report = run(record())
    n = 64 << 20
    report["summary"].update(anchors_observed=128, supported_anchors=128, candidates_reported=128)
    report["coverage"].update(input_bytes=n, search_positions_total=n - 3,
        search_positions_examined=n - 3, anchor_probes=128, structure_bytes_read=128 * 14)
    report["candidates"] = [{**report["candidates"][0], "index": i, "offset": n - (128 - i) * 33}
                            for i in range(128)]
    validate("dhav-candidates", envelope(report))
    D.validate_dhav_accounting(report)
    assert max(len(json.dumps(row, separators=(",", ":")).encode()) for row in report["candidates"]) < 512
    empty_rows = {**report, "candidates": []}
    assert len(json.dumps(empty_rows, separators=(",", ":")).encode()) < 4096
    assert len(json.dumps(report, separators=(",", ":")).encode()) + 1 < 4096 + 128 * 512


@pytest.mark.parametrize("path", [
    ("summary", "anchors_observed"), ("summary", "anchors_rejected"),
    ("summary", "incomplete_anchors"), ("summary", "supported_anchors"),
    ("summary", "candidates_reported"), ("summary", "candidates_omitted"),
    ("coverage", "input_bytes"), ("coverage", "anchor_probes"),
    ("coverage", "structure_bytes_read"), ("coverage", "search_positions_total"),
    ("coverage", "search_positions_examined"), ("candidates", 0, "index"),
    ("candidates", 0, "offset"), ("candidates", 0, "record_length"),
    ("candidates", 0, "header_length"), ("candidates", 0, "extension_length"),
    ("candidates", 0, "payload_length"),
])
@pytest.mark.parametrize("floating", [False, True])
def test_accounting_rejects_boolean_and_integral_float_numbers(path, floating):
    result = run(record())
    owner = result
    for part in path[:-1]:
        owner = owner[part]
    owner[path[-1]] = float(owner[path[-1]]) if floating else bool(owner[path[-1]])
    with pytest.raises(ValidationFailed):
        D.validate_dhav_accounting(result)


@pytest.mark.parametrize("path,value", [
    (("summary", "anchors_observed"), 2), (("summary", "candidates_reported"), 0),
    (("coverage", "search_positions_total"), 1), (("coverage", "search_complete"), False),
    (("coverage", "candidate_checks_complete"), False), (("coverage", "candidate_list_complete"), False),
    (("coverage", "pending_anchor_offset"), 0), (("coverage", "selection_uncertain"), True),
    (("coverage", "reasons"), ["record_framing_incomplete"]),
    (("coverage", "container_examined"), True), (("media_decoded",), True),
    (("status",), "unsupported"), (("candidates", 0, "header_length"), 25),
    (("candidates", 0, "record_length"), 34), (("candidates", 0, "payload_length"), 2),
    (("candidates", 0, "offset"), 1), (("candidates", 0, "footer_length_matches"), False),
])
def test_accounting_rejects_inconsistent_relationships_with_fixed_error(path, value):
    result, owner = run(record()), None
    owner = result
    for part in path[:-1]:
        owner = owner[part]
    owner[path[-1]] = value
    with pytest.raises(ValidationFailed) as error:
        D.validate_dhav_accounting(result)
    assert error.value.__cause__ is None and not error.value.data


def test_accounting_allows_adapter_uncertainty_without_mutating_search_counts():
    result = run(PRIVATE)
    result["status"] = "partial"
    result["coverage"].update(selection_uncertain=True,
        reasons=["selection_uncertain", "container_listing_incomplete"])
    D.validate_dhav_accounting(result)
    validate("dhav-candidates", envelope(result))
    result["coverage"]["reasons"].reverse()
    with pytest.raises(ValidationFailed):
        D.validate_dhav_accounting(result)


@pytest.mark.parametrize("ranged", [False, True])
def test_schema_accepts_closed_file_and_range_profiles(ranged):
    report = envelope(run(record()), ranged=ranged)
    validate("dhav-candidates", report)
    D.validate_dhav_accounting(report)


@pytest.mark.parametrize("mutation", ["range_profile", "range_source", "range_params", "range_limits",
                                    "old_profile", "old_row", "top_raw", "row_raw", "source_raw"])
def test_schema_rejects_mixed_profiles_and_unknown_raw_fields(mutation):
    report = envelope(run(record()))
    ranged = envelope(run(record()), ranged=True)
    if mutation in {"range_profile", "range_source", "range_params", "range_limits"}:
        key = {"range_profile": "profile", "range_source": "source", "range_params": "params",
               "range_limits": "limitations"}[mutation]
        report[key] = ranged[key]
    elif mutation == "old_profile":
        report["profile"] = "ftyp-contiguous-prefix-v1"
    elif mutation == "old_row":
        report["candidates"][0]["validated_prefix_length"] = 33
    else:
        owner = report if mutation == "top_raw" else report["source"] if mutation == "source_raw" else report["candidates"][0]
        owner["raw"] = PRIVATE.decode()
    with pytest.raises(ValidationFailed):
        validate("dhav-candidates", report)
