"""합성 CU snapshot의 폐쇄 문법·신원·페이지 회계. 태그·원장·포트는 사용하지 않는다."""
from __future__ import annotations

import builtins
import dataclasses
import json
import socket
import subprocess
import time

import pytest
from jsonschema import Draft202012Validator

from pweh import cu_protocol as CU
from pweh import nfc_cu_snapshot as N
from pweh import schemas
from pweh.errors import PwehError
from pweh.nfc_formats import _NfcFileIdentity


def snapshot_value(family=CU.NtagFamily.NTAG213, *, observed=None, stop_reason=None):
    """서버/원장 없이 고정 CU 상수와 독립 합성 UID로 JSON 값을 만든다."""
    uid = bytes.fromhex("04223344556677")
    total = family.pages_total
    observed = total if observed is None else observed
    if observed < total and stop_reason is None:
        stop_reason = "time_limit"
    pages = [(bytes((index, 0xa5, 0x5a, 0x11))).hex() for index in range(total)]
    pages[0] = (uid[:3] + bytes((0x88 ^ uid[0] ^ uid[1] ^ uid[2],))).hex()
    pages[1] = uid[3:].hex()
    return {
        "schema": N.SNAPSHOT_SCHEMA, "profile": N.SNAPSHOT_PROFILE,
        "binding": {"tag_ref": "NT-" + "1" * 32, "scan_ref": "NS-" + "2" * 32,
                    "identity_digest": "sha256:" + "3" * 16, "scan_seq": 1,
                    "scan_entry_sha256": "4" * 64, "inventory_seq": 2,
                    "inventory_entry_sha256": "5" * 64},
        "reader": {"profile": CU.PROFILE, "profile_sha256": CU.PROFILE_SHA256,
                   "firmware_commit": CU.FIRMWARE_COMMIT, "app_version": CU.FIRMWARE_VERSION,
                   "git_version": CU.FIRMWARE_GIT_VERSION},
        "identity": {"family": family.family, "uid": uid.hex(), "atqa_msb": "0044",
                     "sak": "00", "mifare_version": family.mifare_version.hex()},
        "pages_total": total, "pages": pages[:observed] + [None] * (total - observed),
        "pages_observed": observed, "read_complete": stop_reason is None,
        "stop_reason": stop_reason, "unobserved_fields": list(N.UNOBSERVED_FIELDS),
        **dict.fromkeys(N.FALSE_FIELDS, False),
    }


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                       allow_nan=False) + "\n").encode("ascii")


def parse(value=None, **kwargs):
    return N.parse_cu_snapshot(encoded(snapshot_value() if value is None else value),
                               deadline=kwargs.pop("deadline", time.monotonic() + 5), **kwargs)


def inspect(value, **kwargs):
    return N.inspect_cu_snapshot(value, deadline=kwargs.pop("deadline", time.monotonic() + 5), **kwargs)


def diff(before, after, **kwargs):
    return N.diff_cu_snapshots(before, after, deadline=kwargs.pop("deadline", time.monotonic() + 5), **kwargs)


def error(call, code="nfc_snapshot_invalid"):
    with pytest.raises(PwehError) as caught:
        call()
    exc = caught.value
    assert exc.code == code
    assert exc.data == {} and exc.hint is None
    assert exc.__context__ is None and exc.__cause__ is None
    assert "SYNTHETIC_RAW_PRIVATE" not in str(exc)
    return exc


def schema_ok(value):
    validator = Draft202012Validator(schemas.load("nfc-cu-snapshot"))
    return validator.is_valid(value)


def assert_report(report, operation):
    assert set(report) == {"schema_version", "operation", "status", "profile", "summary", "coverage", "limitations"}
    assert report["schema_version"] == 1 and type(report["schema_version"]) is int
    assert report["operation"] == operation
    assert report["profile"] == N.ANALYSIS_PROFILE
    assert report["limitations"] == list(N.LIMITATIONS)
    cov, summary = report["coverage"], report["summary"]
    assert cov["consumed_bytes"] == cov["input_bytes"]
    assert cov["unexamined_bytes"] == 0
    raw = json.dumps(report)
    for forbidden in ("04223344556677", "NT-" + "1" * 32, "sha256:" + "3" * 16,
                      "0004040201000f03", "a55a11", "uid", "mifare_version", "binding"):
        assert forbidden not in raw
    if operation == "inspect":
        assert set(summary) == {"family", "pages_total", "pages_observed", "read_complete", "stop_reason", "unobserved_fields"}
        assert set(cov) == {"input_bytes", "consumed_bytes", "unexamined_bytes", "input_exhausted", "pages_unobserved", "reasons"}
        assert cov["input_exhausted"] is True
        assert cov["pages_unobserved"] == summary["pages_total"] - summary["pages_observed"]
        assert report["status"] == ("ok" if summary["read_complete"] else "partial")
        assert cov["reasons"] == ([] if summary["read_complete"] else ["read_partial"])
    else:
        assert set(summary) == {"family", "pages_total", "before", "after", "pages_compared",
                               "before_only_pages", "after_only_pages", "neither_observed_pages",
                               "comparison_unexamined_pages", "changed_pages", "stored_pages_equal"}
        assert set(cov) == {"input_bytes", "consumed_bytes", "unexamined_bytes", "comparison_complete",
                           "changes_complete", "changed_pages_count_is_lower_bound", "reasons"}
        assert sum(summary[key] for key in ("pages_compared", "before_only_pages", "after_only_pages",
                                           "neither_observed_pages", "comparison_unexamined_pages")) == summary["pages_total"]
        assert summary["changed_pages"] == sorted(set(summary["changed_pages"]))
        assert len(summary["changed_pages"]) <= summary["pages_compared"]
        complete = summary["comparison_unexamined_pages"] == 0
        read_complete = summary["before"]["read_complete"] and summary["after"]["read_complete"]
        assert cov["comparison_complete"] is complete and cov["changes_complete"] is complete
        assert cov["changed_pages_count_is_lower_bound"] is not complete
        assert report["status"] == ("ok" if complete and read_complete else "partial")
        assert summary["stored_pages_equal"] == ((not summary["changed_pages"]) if complete and read_complete else None)
        assert cov["reasons"] == ([] if read_complete else ["read_partial"]) + ([] if complete else ["time_limit"])


@pytest.mark.parametrize("family", list(CU.NtagFamily))
@pytest.mark.parametrize("state", ["full", "prefix2", "prefix7", "full_timeout", "full_invalid"])
def test_three_families_and_read_completion(family, state):
    count = 2 if state == "prefix2" else 7 if state == "prefix7" else family.pages_total
    stop = "time_limit" if state == "full_timeout" else "nfc_scan_invalid" if state == "full_invalid" else None
    value = snapshot_value(family, observed=count, stop_reason=stop)
    assert schema_ok(value)
    result = parse(value)
    assert type(result) is N.CuSnapshot
    assert [field.name for field in dataclasses.fields(result)] == [
        "identity", "pages", "binding", "family", "pages_total", "pages_observed",
        "read_complete", "stop_reason", "input_size"]
    assert tuple(key for key, _ in result.binding) == N.BINDING_FIELDS
    assert dict(result.binding) == value["binding"]
    assert type(result.identity) is _NfcFileIdentity and result.identity.profile == family.family
    assert result.identity.mifare_version == family.mifare_version
    assert result.identity.uid == bytes.fromhex(value["identity"]["uid"])
    assert result.pages[:2] == (bytes.fromhex(value["pages"][0]), bytes.fromhex(value["pages"][1]))
    assert all(type(item) is bytes and len(item) == 4 for item in result.pages[:count])
    assert result.pages[count:] == (None,) * (family.pages_total - count)
    assert result.input_size == len(encoded(value))
    assert_report(inspect(result), "inspect")
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.pages_total = 1
    assert "042233" not in repr(result) and "pages=" not in repr(result)
    assert "042233" not in repr(result.identity)


@pytest.mark.parametrize("wire", [b"", b"null", b"[]", b"{}", b"true", b'"SYNTHETIC_RAW_PRIVATE"',
    b"\xef\xbb\xbf{}", b'{"x":"\xff"}', b'{"x":"\x00"}', b'{"x":"\n"}', b"{", b"]",
    b'{"x":}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1.0}', b'{"x":1e2}',
    b'{"x":+1}', b'{"x":01}', b'{"x":-}', b'{"x":"\\q"}', b'{"x":false}garbage'])
def test_invalid_json_never_leaks(wire):
    error(lambda: N.parse_cu_snapshot(wire, deadline=time.monotonic() + 5))


@pytest.mark.parametrize("key", ["schema", "family", "tag_ref", "app_version"])
def test_duplicate_keys_at_each_object(key):
    raw = encoded(snapshot_value())
    needle = ('"' + key + '":').encode()
    changed = raw.replace(needle, needle + b'"SYNTHETIC_RAW_PRIVATE",' + needle, 1)
    error(lambda: N.parse_cu_snapshot(changed, deadline=time.monotonic() + 5))


@pytest.mark.parametrize("field", list(snapshot_value()))
def test_each_top_field_required(field):
    value = snapshot_value()
    del value[field]
    assert not schema_ok(value)
    error(lambda: parse(value))


@pytest.mark.parametrize("object_name", [None, "reader", "identity", "binding"])
def test_unknown_keys_and_old_v4_fields_rejected(object_name):
    value = snapshot_value()
    target = value if object_name is None else value[object_name]
    target["Signature"] = "SYNTHETIC_RAW_PRIVATE"
    assert not schema_ok(value)
    error(lambda: parse(value))


@pytest.mark.parametrize("field", list(N.FALSE_FIELDS))
@pytest.mark.parametrize("bad", [True, 0, None])
def test_false_fields_are_exact(field, bad):
    value = snapshot_value()
    value[field] = bad
    assert not schema_ok(value)
    error(lambda: parse(value))


@pytest.mark.parametrize("field", list(snapshot_value()["reader"]))
def test_reader_is_pinned(field):
    value = snapshot_value()
    value["reader"][field] += "SYNTHETIC_RAW_PRIVATE"
    assert not schema_ok(value)
    error(lambda: parse(value))


@pytest.mark.parametrize("section,key,bad", [
    (None, "schema", "pweh.nfc-cu-snapshot/v2"), (None, "profile", "imported-v4"),
    (None, "pages_total", True), (None, "pages_total", 45.0), (None, "pages_total", "45"),
    (None, "pages_total", 135), (None, "pages_observed", True), (None, "pages_observed", 45.0),
    (None, "pages_observed", 1), (None, "pages_observed", 46),
    (None, "read_complete", 1), (None, "read_complete", "true"),
    (None, "stop_reason", "cu_protocol_invalid"), (None, "stop_reason", "cancelled"),
    (None, "stop_reason", "time_limit"), (None, "read_complete", False),
    (None, "unobserved_fields", ["signature", "tearing", "counters"]),
    (None, "unobserved_fields", []), (None, "unobserved_fields", "signature"),
    ("identity", "family", "ntag215"), ("identity", "family", None),
    ("identity", "uid", "04223344556677\n"), ("identity", "uid", "0422334455667A"),
    ("identity", "uid", "042233445566"), ("identity", "atqa_msb", "4400"),
    ("identity", "sak", "08"), ("identity", "mifare_version", "0004040201001103"),
    ("binding", "tag_ref", "NT-" + "1" * 32 + "\n"),
    ("binding", "scan_ref", "NS-" + "A" * 32),
    ("binding", "identity_digest", "sha256:" + "3" * 16 + "\n"),
    ("binding", "scan_seq", True), ("binding", "scan_seq", 1.0), ("binding", "scan_seq", 0),
    ("binding", "inventory_seq", 2**63), ("binding", "inventory_seq", -1),
    ("binding", "scan_entry_sha256", "4" * 64 + "\n"),
    ("binding", "inventory_entry_sha256", "F" * 64),
])
def test_closed_scalar_semantics(section, key, bad):
    value = snapshot_value()
    (value if section is None else value[section])[key] = bad
    error(lambda: parse(value))
    # JSON Schema는 수학적으로 정수인 float를 허용하므로 exact type는 core 권위다.
    if type(bad) is not float:
        assert not schema_ok(value)


@pytest.mark.parametrize("mutation", ["gap", "null_full", "count", "short", "long", "uid", "bcc",
                                       "short_page", "uppercase", "page_bool", "page_object"])
def test_pages_relations_and_semantic_only_rejections(mutation):
    value = snapshot_value(observed=7)
    if mutation == "gap":
        value["pages"][3], value["pages"][7] = None, "01020304"
    elif mutation == "null_full":
        value = snapshot_value()
        value["pages"][2] = None
    elif mutation == "count":
        value["pages_observed"] = 6
    elif mutation == "short":
        value["pages"].pop()
    elif mutation == "long":
        value["pages"].append(None)
    elif mutation == "uid":
        value["pages"][1] = "11223344"
    elif mutation == "bcc":
        value["pages"][0] = "04223300"
    else:
        value["pages"][2] = {"short_page": "000102", "uppercase": "000000AB", "page_bool": False,
                              "page_object": {"SYNTHETIC_RAW_PRIVATE": 1}}[mutation]
    error(lambda: parse(value))
    if mutation in ("gap", "count", "uid", "bcc"):
        assert schema_ok(value)  # 배열 사이의 결속은 parser의 독립 책임이다.


@pytest.mark.parametrize("key", ["tag_ref", "scan_ref", "identity_digest", "scan_entry_sha256", "inventory_entry_sha256"])
def test_schema_rejects_end_newline(key):
    value = snapshot_value()
    value["binding"][key] += "\n"
    assert not schema_ok(value)


def test_schema_draft_constants_and_positive_seq_bound():
    schema = schemas.load("nfc-cu-snapshot")
    Draft202012Validator.check_schema(schema)
    assert schema["$id"] == N.SNAPSHOT_SCHEMA
    assert schema["properties"]["reader"]["properties"]["profile_sha256"]["const"] == CU.PROFILE_SHA256
    value = snapshot_value()
    value["binding"]["scan_seq"] = 2**63 - 1
    value["binding"]["inventory_seq"] = 2**63 - 1
    assert schema_ok(value)
    parse(value)


def test_exact_byte_limit_and_noncanonical_ascii_whitespace():
    raw = encoded(snapshot_value())
    padded = raw + b" " * (65536 - len(raw))
    assert N.parse_cu_snapshot(padded, deadline=time.monotonic() + 5).input_size == 65536
    error(lambda: N.parse_cu_snapshot(padded + b" ", deadline=time.monotonic() + 5), "nfc_input_limit")
    text = json.dumps(snapshot_value(), indent=2, ensure_ascii=True).encode("ascii")
    assert N.parse_cu_snapshot(text, deadline=time.monotonic() + 5).input_size == len(text)


@pytest.mark.parametrize("raw,limit", [
    (b"[" * 8 + b"null" + b"]" * 8, False),
    (b"[" * 9 + b"null" + b"]" * 9, True),
    (b"[" + b",".join([b"null"] * 2047) + b"]", False),
    (b"[" + b",".join([b"null"] * 2048) + b"]", True),
    (b"9" * 20, False), (b"9" * 21, True),
])
def test_predecode_depth_nodes_and_integer_width(raw, limit, monkeypatch):
    called = []
    original = N.json.loads
    def loads(*args, **kwargs):
        called.append(True)
        return original(*args, **kwargs)
    monkeypatch.setattr(N.json, "loads", loads)
    error(lambda: N.parse_cu_snapshot(raw, deadline=time.monotonic() + 5),
          "nfc_input_limit" if limit else "nfc_snapshot_invalid")
    assert bool(called) is not limit


def test_preflight_strings_escapes_and_object_keys_are_not_extra_nodes(monkeypatch):
    value = snapshot_value()
    raw = encoded(value).replace(b'"ntag213"', b'"ntag\\u0032\\u0031\\u0033"')
    assert N.parse_cu_snapshot(raw, deadline=time.monotonic() + 5).family == "ntag213"
    # value 2048개까지 decode한 뒤에도 허용하지 않은 객체 shape는 거부한다.
    raw = encoded({str(i): None for i in range(2047)})
    called = []
    original = N.json.loads
    def loads(*args, **kwargs):
        called.append(True)
        return original(*args, **kwargs)
    monkeypatch.setattr(N.json, "loads", loads)
    error(lambda: N.parse_cu_snapshot(raw, deadline=time.monotonic() + 5))
    assert called == [True]


@pytest.mark.parametrize("data", [None, {}, "{}", bytearray(b"{}"), memoryview(b"{}"), True])
def test_input_bytes_exact(data):
    error(lambda: N.parse_cu_snapshot(data, deadline=time.monotonic() + 5), "nfc_input_invalid")


@pytest.mark.parametrize("deadline", [None, True, "5", float("inf"), float("nan"), -(10**500), 10**500])
def test_deadline_exact_finite(deadline):
    error(lambda: parse(deadline=deadline), "nfc_input_invalid")


@pytest.mark.parametrize("operation", ["parse", "inspect", "diff"])
def test_api_cancel_deadline_and_raw_callback_errors(operation):
    one = parse()
    call = {"parse": lambda **kw: parse(**kw), "inspect": lambda **kw: inspect(one, **kw),
            "diff": lambda **kw: diff(one, one, **kw)}[operation]
    error(lambda: call(deadline=time.monotonic() - 1), "time_limit")
    error(lambda: call(cancel=42), "nfc_input_invalid")
    error(lambda: call(cancel=lambda: 1), "nfc_failed")
    error(lambda: call(cancel=lambda: "SYNTHETIC_RAW_PRIVATE"), "nfc_failed")
    def broken():
        raise RuntimeError("SYNTHETIC_RAW_PRIVATE")
    error(lambda: call(cancel=broken), "nfc_failed")
    error(lambda: call(cancel=lambda: True, deadline=time.monotonic() - 1), "cancelled")


@pytest.mark.parametrize("key,bad", [
    ("pages_total", True), ("pages_total", 46), ("pages_observed", 1), ("pages_observed", 44),
    ("read_complete", 1), ("read_complete", False), ("stop_reason", "time_limit"),
    ("input_size", 0), ("input_size", 65537), ("input_size", 1.0),
    ("family", None), ("family", "ntag215"), ("pages", []), ("pages", (b"1234",)),
    ("binding", []), ("binding", ()), ("identity", None),
])
def test_inspect_and_diff_recheck_forged_typed_values(key, bad):
    valid = parse()
    forged = dataclasses.replace(valid, **{key: bad})
    error(lambda: inspect(forged))
    error(lambda: diff(valid, forged))


@pytest.mark.parametrize("key,bad", [
    ("uid", b"123456"), ("atqa_msb", b"\x44\x00"), ("sak", b"\x01"),
    ("mifare_version", None), ("profile", "iso14443-3a"),
])
def test_forged_private_identity_rechecked(key, bad):
    valid = parse()
    identity = dataclasses.replace(valid.identity, **{key: bad})
    error(lambda: inspect(dataclasses.replace(valid, identity=identity)))


def test_typed_missing_extra_fields_and_binding_order():
    error(lambda: inspect(object.__new__(N.CuSnapshot)))
    valid = parse()
    object.__setattr__(valid, "unexpected", "SYNTHETIC_RAW_PRIVATE")
    error(lambda: inspect(valid))
    valid = parse()
    error(lambda: inspect(dataclasses.replace(valid, binding=tuple(reversed(valid.binding)))))
    error(lambda: inspect(dataclasses.replace(valid, binding=tuple((k, True if k == "scan_seq" else v)
                                                                  for k, v in valid.binding))))
    error(lambda: inspect({}), "nfc_input_invalid")


@pytest.mark.parametrize("family", list(CU.NtagFamily))
def test_full_diff_same_and_changed_indices(family):
    value = snapshot_value(family)
    before = parse(value)
    unchanged = diff(before, parse(value))
    assert_report(unchanged, "diff")
    assert unchanged["summary"]["stored_pages_equal"] is True
    for index in (2, family.pages_total - 1):
        value["pages"][index] = "11223344"
    changed = diff(before, parse(value))
    assert_report(changed, "diff")
    assert changed["summary"]["changed_pages"] == [2, family.pages_total - 1]
    assert changed["summary"]["stored_pages_equal"] is False
    assert changed["summary"]["pages_compared"] == family.pages_total


@pytest.mark.parametrize("left,right", [(2, 2), (2, 7), (7, 2), (7, 45), (45, 7), (45, 45)])
def test_partial_read_intersection_and_null_suffix(left, right):
    before = parse(snapshot_value(observed=left, stop_reason="time_limit"))
    after = parse(snapshot_value(observed=right, stop_reason="nfc_scan_invalid"))
    report = diff(before, after)
    assert_report(report, "diff")
    summary = report["summary"]
    assert summary["pages_compared"] == min(left, right)
    assert summary["before_only_pages"] == max(0, left - right)
    assert summary["after_only_pages"] == max(0, right - left)
    assert summary["neither_observed_pages"] == 45 - max(left, right)
    assert summary["stored_pages_equal"] is None


@pytest.mark.parametrize("field", list(N.BINDING_FIELDS) + ["identity", "family"])
def test_diff_requires_same_entire_binding_and_identity(field):
    before = parse()
    value = snapshot_value()
    if field == "family":
        value = snapshot_value(CU.NtagFamily.NTAG215)
    elif field == "identity":
        uid = bytes.fromhex("04665544332211")
        value["identity"]["uid"] = uid.hex()
        value["pages"][0] = (uid[:3] + bytes((0x88 ^ uid[0] ^ uid[1] ^ uid[2],))).hex()
        value["pages"][1] = uid[3:].hex()
    elif field.endswith("seq"):
        value["binding"][field] += 1
    else:
        old = value["binding"][field]
        value["binding"][field] = old[:-1] + "6"
    error(lambda: diff(before, parse(value)), "nfc_source_mismatch")


def compare_clock(monkeypatch, deadline, *, allowed):
    state = {"validated": 0, "comparisons": 0}
    original = N._checked
    def checked(snapshot, control):
        original(snapshot, control)
        state["validated"] += 1
    def clock():
        if state["validated"] == 2:
            state["comparisons"] += 1
            if state["comparisons"] > allowed:
                return deadline
        return deadline - 1
    monkeypatch.setattr(N, "_checked", checked)
    monkeypatch.setattr(N, "_clock", clock)
    return state


@pytest.mark.parametrize("observed", [7, 45])
@pytest.mark.parametrize("processed", [0, 1, 3, 44, 45])
def test_diff_time_cutoff_preserves_only_processed_prefix(observed, processed, monkeypatch):
    before = parse(snapshot_value(observed=observed))
    value = snapshot_value(observed=observed)
    value["pages"][2] = "11223344"
    after = parse(value)
    end = time.monotonic() + 5
    state = compare_clock(monkeypatch, end, allowed=processed)
    report = diff(before, after, deadline=end)
    assert_report(report, "diff")
    assert report["summary"]["comparison_unexamined_pages"] == 45 - processed
    assert report["summary"]["changed_pages"] == ([2] if processed > 2 else [])
    assert state["comparisons"] == min(processed + 1, 45)


def test_diff_final_cancel_still_fatal_after_complete_compare(monkeypatch):
    one = parse()
    end = time.monotonic() + 5
    state = compare_clock(monkeypatch, end, allowed=45)
    def cancel():
        return state["validated"] == 2 and state["comparisons"] == 45
    error(lambda: diff(one, one, deadline=end, cancel=cancel), "cancelled")


def test_parse_cancellation_during_preflight_and_nodes(monkeypatch):
    raw = encoded(snapshot_value())
    data = raw + b" " * (65536 - len(raw))
    count = 0
    def cancel():
        nonlocal count
        count += 1
        return count == 3
    error(lambda: N.parse_cu_snapshot(data, deadline=time.monotonic() + 5, cancel=cancel), "cancelled")
    count = 0
    def cancel_node():
        nonlocal count
        count += 1
        return count == 20
    error(lambda: parse(cancel=cancel_node), "cancelled")


def test_no_file_network_process_or_schema_io(monkeypatch):
    raw = encoded(snapshot_value())
    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected I/O")
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(schemas, "validate", forbidden)
    parsed = N.parse_cu_snapshot(raw, deadline=time.monotonic() + 5)
    assert_report(inspect(parsed), "inspect")
    assert_report(diff(parsed, parsed), "diff")
