"""Ultralight snapshot 순수 검사기의 불변 관계·NTAG snapshot과의 분리·inspect/diff 등식을 합성 값으로 검사한다."""
from __future__ import annotations

import copy
import json
import time

import pytest

from pweh import cu_protocol as C, nfc_cu_snapshot as N, nfc_cu_ul_snapshot as U, schemas
from pweh.errors import PwehError

UID = bytes.fromhex("04a1b2c3d4e5f6")
# 독립 literal. 구현 상수를 읽지 않는다.
READER = {"profile": "cu-ultralight-v2.3.0-v1",
          "profile_sha256": "fde75c1da05251b816628e491b9e554d556857f455b39dc439df46a78225b728",
          "firmware_commit": "4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1", "app_version": "2.3", "git_version": "v2.3.0"}
LAYOUT = {"ultralight_ev1_mf0ul11": (20, 17, {"pwd_pack_readback_zero": [18, 19]}, "0004030101000b03"),
          "ultralight_ev1_mf0ulh11": (20, 17, {"pwd_pack_readback_zero": [18, 19]}, "0004030201000b03"),
          "ultralight_ev1_mf0ul21": (41, 38, {"pwd_pack_readback_zero": [39, 40]}, "0004030101000e03"),
          "ultralight_ev1_mf0ulh21": (41, 38, {"pwd_pack_readback_zero": [39, 40]}, "0004030201000e03"),
          "ultralight_or_ultralight_c": (48, 43, {"key_never_readable": [44, 45, 46, 47]}, None)}
FALSE = ["snapshot_atomic", "physical_same_tag_verified", "device_command_termination_verified", "rf_off_verified",
         "host_crc_verified", "tag_content_written", "authentication_attempted", "emulation_performed",
         "read_sig_sent", "read_cnt_sent"]
LEGACY = "ultralight_or_ultralight_c"


def end():
    return time.monotonic() + 5


def page_values(uid=UID, total=48):
    pages = [bytes((i, 0x55, 9, 0xa5)) for i in range(total)]
    pages[0] = uid[:3] + bytes((0x88 ^ uid[0] ^ uid[1] ^ uid[2],))
    pages[1] = uid[3:7]
    pages[2] = bytes((uid[3] ^ uid[4] ^ uid[5] ^ uid[6], 0x48, 0, 0))
    return pages


def variant(family, kind, page, observed):
    if family != LEGACY:
        return family
    if observed > 0x10 or (kind == "nak_with_rollover" and 3 <= page < 0x10):
        return "ultralight_c"
    return LEGACY


def snapshot(family="ultralight_ev1_mf0ul11", *, kind="end_of_targets", observed=None, reason=None):
    total, last, withheld, version = LAYOUT[family]
    observed = last + 1 if observed is None else observed
    page = None if kind == "end_of_targets" else observed
    values = page_values()
    pages = [values[i].hex() if i < observed else None for i in range(total)]
    complete = kind in ("end_of_targets", "nak_with_rollover")
    return {"schema": "pweh.nfc-cu-ul-snapshot/v1", "profile": "cu-ultralight-pages-v1",
            "binding": {"ul_tag_ref": "UT-" + "1" * 32, "ul_scan_ref": "US-" + "2" * 32,
                        "ul_identity_digest": "sha256:" + "3" * 16, "scan_seq": 1, "scan_entry_sha256": "4" * 64,
                        "inventory_seq": 2, "inventory_entry_sha256": "5" * 64},
            "attestation": {"kind": "tag-ownership", "attestation_id": "att-0123456789"},
            "reader": dict(READER),
            "identity": {"family": family, "uid": UID.hex(), "atqa_msb": "0044", "sak": "00", "mifare_version": version},
            "pages_total": total, "read_last_target": last, "withheld_pages": copy.deepcopy(withheld),
            "pages": pages, "pages_observed": observed, "read_end": {"kind": kind, "page": page},
            "observed_variant": variant(family, kind, page, observed), "read_complete": complete,
            "stop_reason": reason if not complete else None, "activation_per_page": True,
            "unobserved_fields": ["signature", "counters", "tearing"], **{k: False for k in FALSE}}


def encode(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def parse(value):
    return U.parse_cu_ul_snapshot(encode(value) if type(value) is dict else value, deadline=end())


def code_of(value):
    with pytest.raises(PwehError) as exc:
        parse(value)
    assert UID.hex() not in str(exc.value)
    return exc.value.code


VALID = [snapshot(f) for f in LAYOUT] + [
    snapshot(LEGACY, kind="nak_with_rollover", observed=0x10),
    snapshot(LEGACY, kind="nak_with_rollover", observed=8),
    snapshot("ultralight_ev1_mf0ul21", kind="nak_without_rollover", observed=16, reason="tag_nak"),
    snapshot("ultralight_ev1_mf0ul11", kind="stopped", observed=3, reason="time_limit"),
    snapshot("ultralight_ev1_mf0ul11", kind="stopped", observed=9, reason="nfc_scan_invalid"),
]


@pytest.mark.parametrize("value", VALID, ids=range(len(VALID)))
def test_valid_snapshots_parse_and_match_schema(value):
    schemas.validate("nfc-cu-ul-snapshot", value)
    parsed = parse(value)
    assert parsed.family == value["identity"]["family"] and parsed.pages_observed == value["pages_observed"]
    assert parsed.read_end == (value["read_end"]["kind"], value["read_end"]["page"])
    assert parsed.attestation_id == "att-0123456789" and UID.hex() not in repr(parsed)


def _set(path, new):
    def mutate(value):
        target = value
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = new(target[path[-1]]) if callable(new) else new
    return mutate


MUTATIONS = {
    "family-unknown": _set(("identity", "family"), "ntag213"),
    "pages-total": _set(("pages_total",), 41),
    "last-target": _set(("read_last_target",), 18),
    "withheld": _set(("withheld_pages",), {"pwd_pack_readback_zero": [17, 18]}),
    "ev1-version": _set(("identity", "mifare_version"), "0004030201000b03"),
    "ev1-null-version": _set(("identity", "mifare_version"), None),
    "withheld-page-filled": _set(("pages",), lambda pages: pages[:18] + ["00000000", None]),
    "gap": _set(("pages",), lambda pages: pages[:5] + [None] + pages[6:]),
    "observed-count": _set(("pages_observed",), 17),
    "uid-page1": _set(("pages",), lambda pages: [pages[0], "00000000"] + pages[2:]),
    "bcc0": _set(("pages",), lambda pages: [pages[0][:6] + "00"] + pages[1:]),
    "bcc1": _set(("pages",), lambda pages: pages[:2] + ["ff" + pages[2][2:]] + pages[3:]),
    "end-page-not-null": _set(("read_end",), {"kind": "end_of_targets", "page": 18}),
    "complete-flag": _set(("read_complete",), False),
    "stop-reason-on-complete": _set(("stop_reason",), "time_limit"),
    "variant": _set(("observed_variant",), "ultralight_c"),
    "attestation-kind": _set(("attestation", "kind"), "tag-purpose"),
    "attestation-id": _set(("attestation", "attestation_id"), "att-123"),
    "reader": _set(("reader", "profile_sha256"), "0" * 64),
    "ntag-reader": _set(("reader",), {"profile": "cu-ntag21x-v2.3.0-v1",
                                      "profile_sha256": "95132f6c6e6609854cf32af0f1644eb409147cf21060ba97e7eb3dee4d783eb5",
                                      "firmware_commit": "4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1",
                                      "app_version": "2.3", "git_version": "v2.3.0"}),
    "activation": _set(("activation_per_page",), False),
    "read-sig": _set(("read_sig_sent",), True),
    "read-cnt": _set(("read_cnt_sent",), True),
    "binding-ntag-ref": _set(("binding", "ul_tag_ref"), "NT-" + "1" * 32),
    "binding-order": _set(("binding", "scan_seq"), 3),
    "extra-key": _set(("schema",), "pweh.nfc-cu-snapshot/v1"),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_each_invariant_mutation_is_rejected(name):
    value = snapshot()
    MUTATIONS[name](value)
    assert code_of(value) in ("nfc_snapshot_invalid", "nfc_input_limit")


@pytest.mark.parametrize("change", [
    {"observed": 2, "kind": "stopped", "reason": "time_limit"},
    {"observed": 2, "kind": "nak_with_rollover"},
])
def test_fewer_than_three_pages_is_rejected(change):
    value = snapshot(**change)
    assert code_of(value) == "nfc_snapshot_invalid"


@pytest.mark.parametrize("kind,reason", [("stopped", "tag_nak"), ("stopped", None), ("nak_without_rollover", None),
                                         ("nak_without_rollover", "time_limit"), ("nak_with_rollover", "tag_nak")])
def test_read_end_and_reason_relations(kind, reason):
    value = snapshot(kind=kind, observed=8)
    value["read_complete"] = reason is None and kind != "stopped"
    value["stop_reason"] = reason
    assert code_of(value) == "nfc_snapshot_invalid"


def test_nak_page_must_equal_retained_count():
    value = snapshot(kind="nak_with_rollover", observed=8)
    value["read_end"]["page"] = 9
    assert code_of(value) == "nfc_snapshot_invalid"


@pytest.mark.parametrize("observed,kind,expected", [
    (0x10, "nak_with_rollover", LEGACY), (0x0f, "nak_with_rollover", "ultralight_c"),
    (0x11, "nak_without_rollover", "ultralight_c"), (0x10, "nak_without_rollover", LEGACY),
    (0x05, "stopped", LEGACY), (44, "end_of_targets", "ultralight_c")])
def test_legacy_variant_inference(observed, kind, expected):
    value = snapshot(LEGACY, kind=kind, observed=observed,
                     reason={"nak_without_rollover": "tag_nak", "stopped": "time_limit"}.get(kind))
    assert value["observed_variant"] == expected
    assert parse(value).observed_variant == expected
    value["observed_variant"] = LEGACY if expected == "ultralight_c" else "ultralight_c"
    assert code_of(value) == "nfc_snapshot_invalid"


def test_parsers_reject_each_others_snapshots():
    ul = encode(snapshot())
    with pytest.raises(PwehError):
        N.parse_cu_snapshot(ul, deadline=end())
    ntag_value = {"schema": "pweh.nfc-cu-snapshot/v1", "profile": "cu-ntag21x-pages-v1",
                  "binding": {"tag_ref": "NT-" + "1" * 32, "scan_ref": "NS-" + "2" * 32,
                              "identity_digest": "sha256:" + "3" * 16, "scan_seq": 1, "scan_entry_sha256": "4" * 64,
                              "inventory_seq": 2, "inventory_entry_sha256": "5" * 64},
                  "reader": C.LIVE.reader(),
                  "identity": {"family": "ntag213", "uid": UID.hex(), "atqa_msb": "0044", "sak": "00",
                               "mifare_version": "0004040201000f03"},
                  "pages_total": 45, "pages": [p.hex() for p in page_values(total=45)], "pages_observed": 45,
                  "read_complete": True, "stop_reason": None, "unobserved_fields": ["signature", "counters", "tearing"],
                  **{k: False for k in FALSE[:8]}}
    ntag = encode(ntag_value)
    assert N.parse_cu_snapshot(ntag, deadline=end()).family == "ntag213"
    assert code_of(ntag) == "nfc_snapshot_invalid"


def test_json_limits_are_shared():
    value = snapshot()
    data = encode(value).replace(b'"pages_observed":18', b'"pages_observed":18.0')
    assert code_of(data) == "nfc_snapshot_invalid"
    dup = encode(value).replace(b'{"activation_per_page":true', b'{"activation_per_page":true,"activation_per_page":true')
    assert code_of(dup) == "nfc_snapshot_invalid"
    assert code_of(b"[" * 9 + b"]" * 9) == "nfc_input_limit"
    assert code_of(b"x" * 65537) == "nfc_input_limit"


def test_inspect_summary_has_no_page_values():
    parsed = parse(snapshot("ultralight_ev1_mf0ul21", kind="nak_without_rollover", observed=16, reason="tag_nak"))
    report = U.inspect_cu_ul_snapshot(parsed, deadline=end())
    assert report["status"] == "partial" and report["coverage"]["reasons"] == ["read_partial"]
    assert report["summary"]["withheld_pages_count"] == 2 and report["coverage"]["pages_unobserved"] == 39 - 16
    assert report["limitations"] == list(U.LIMITATIONS) and "tag_ownership_is_human_statement" in report["limitations"]
    text = json.dumps(report)
    assert UID.hex() not in text and page_values()[5].hex() not in text


def test_diff_relations_and_equality():
    before = parse(snapshot())
    changed = snapshot()
    changed["pages"][7] = "deadbeef"
    after = parse(changed)
    report = U.diff_cu_ul_snapshots(before, after, deadline=end())
    s = report["summary"]
    assert s["changed_pages"] == [7] and s["stored_pages_equal"] is False and s["read_end_changed"] is False
    assert (s["pages_compared"], s["withheld_pages"], s["comparison_unexamined_pages"]) == (18, 2, 0)
    assert sum(s[k] for k in ("pages_compared", "before_only_pages", "after_only_pages", "neither_observed_pages",
                              "withheld_pages", "comparison_unexamined_pages")) == s["pages_total"]
    same = U.diff_cu_ul_snapshots(before, before, deadline=end())
    assert same["summary"]["stored_pages_equal"] is True and same["status"] == "ok"
    partial = parse(snapshot(kind="nak_with_rollover", observed=8))
    out = U.diff_cu_ul_snapshots(before, partial, deadline=end())
    s = out["summary"]
    assert s["read_end_changed"] is True and s["stored_pages_equal"] is None and out["status"] == "ok"
    assert (s["pages_compared"], s["before_only_pages"], s["after_only_pages"], s["neither_observed_pages"]) == (8, 10, 0, 0)
    stopped = parse(snapshot(kind="stopped", observed=4, reason="nfc_scan_invalid"))
    out = U.diff_cu_ul_snapshots(stopped, partial, deadline=end())
    assert out["status"] == "partial" and out["coverage"]["reasons"] == ["read_partial"]
    assert out["summary"]["stored_pages_equal"] is None


@pytest.mark.parametrize("field", ["family", "binding", "uid", "reader_last"])
def test_diff_requires_same_source(field):
    before = parse(snapshot())
    value = snapshot()
    if field == "family":
        value = snapshot("ultralight_ev1_mf0ulh11")
    elif field == "binding":
        value["binding"]["inventory_seq"] = 3
    elif field == "uid":
        other = bytes.fromhex("04a1b2c3d4e5f7")
        value["identity"]["uid"] = other.hex()
        values = page_values(other)
        value["pages"][:3] = [v.hex() for v in values[:3]]
    else:
        value = snapshot("ultralight_ev1_mf0ul21")
    with pytest.raises(PwehError) as exc:
        U.diff_cu_ul_snapshots(before, parse(value), deadline=end())
    assert exc.value.code == "nfc_source_mismatch"


def test_diff_time_limit_marks_unexamined(monkeypatch):
    from pweh import nfc_cu_snapshot
    before, after = parse(snapshot()), parse(snapshot())
    real = U._checked
    state = {"checked": 0, "loop": 0}

    def checked(value, control):
        real(value, control)
        state["checked"] += 1

    def clock():
        # 두 snapshot 검사가 끝난 뒤 비교 루프의 다섯 번째 확인부터 시간 한도를 넘긴다.
        if state["checked"] < 2:
            return 0.0
        state["loop"] += 1
        return 0.0 if state["loop"] <= 5 else 10.0

    monkeypatch.setattr(U, "_checked", checked)
    monkeypatch.setattr(nfc_cu_snapshot, "_clock", clock)
    out = U.diff_cu_ul_snapshots(before, after, deadline=5.0)
    s = out["summary"]
    assert out["status"] == "partial" and "time_limit" in out["coverage"]["reasons"]
    assert s["comparison_unexamined_pages"] > 0 and s["stored_pages_equal"] is None
    assert sum(s[k] for k in ("pages_compared", "before_only_pages", "after_only_pages", "neither_observed_pages",
                              "withheld_pages", "comparison_unexamined_pages")) == s["pages_total"]


def _report(inspection, snapshots):
    files = [{"artifact_id": "A-0001", "size": s.input_size, "sha256": "6" * 64, "provenance_kind": "device-read",
              "ledger_seq": 3, "ledger_entry_sha256": "7" * 64, "read_attestation_id": s.attestation_id}
             for s in snapshots]
    return {"schema": "pweh.nfc-ul-file-analysis/v1", "operation": inspection["operation"],
            "status": inspection["status"],
            "source": {"kind": "case-artifact", "tag_ref": "UT-" + "1" * 32, "scan_ref": "US-" + "2" * 32,
                       "scan_entry_sha256": "4" * 64, "inventory_entry_sha256": "5" * 64,
                       "tag_ownership_attestation_id": "att-0123456789", "files": files},
            "params": {"profile": U.ANALYSIS_PROFILE, "max_seconds": 5}, "inspection": inspection,
            "inventory_binding_verified": True, "physical_same_tag_verified": False}


@pytest.mark.parametrize("operation,mutation", [
    ("inspect", ("coverage", "pages_unobserved", 1)), ("inspect", ("summary", "withheld_pages_count", 4)),
    ("inspect", ("summary", "read_complete", False)), ("diff", ("summary", "pages_compared", 17)),
    ("diff", ("summary", "withheld_pages", 4)), ("diff", ("summary", "stored_pages_equal", None)),
    ("diff", ("summary", "read_end_changed", True)), ("diff", ("summary", "changed_pages", [19])),
    ("diff", ("coverage", "reasons", ["time_limit"]))])
def test_relations_reject_false_equations_after_schema(operation, mutation):
    from nfc_mcp import ul_analysis as A
    snaps = [parse(snapshot())] if operation == "inspect" else [parse(snapshot()), parse(snapshot())]
    inspection = (U.inspect_cu_ul_snapshot(snaps[0], deadline=end()) if operation == "inspect"
                  else U.diff_cu_ul_snapshots(*snaps, deadline=end()))
    report = _report(inspection, snaps)
    schemas.validate("nfc-ul-file-analysis", report)
    A._validate_ul_relations(report, snaps)
    bad = copy.deepcopy(report)
    section, key, value = mutation
    bad["inspection"][section][key] = value
    with pytest.raises(PwehError):
        schemas.validate("nfc-ul-file-analysis", bad)
        A._validate_ul_relations(bad, snaps)
