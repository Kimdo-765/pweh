"""합성 목록의 자동 선정·회계·scanner 호환·원문 차단 경계."""
import copy
import hashlib
import json
import time
from dataclasses import replace

import pytest

from pweh import schemas
from pweh.errors import PwehError
from pweh.secret_survey import (
    READ_REASONS, SurveyCollector, SurveyLimits, plan_survey,
)
from pweh.secretscan import scan_secrets


def entry(slot=0, size=20, *, fs="fat16", **overrides):
    value = {"ref": f"0/{slot}", "fs": fs, "size": size, "name": "private-name.cfg",
             "path": "/private-name.cfg", "is_dir": False, "deleted": False,
             "parent_deleted": False, "name_lossy": False}
    if fs == "exfat":
        value["valid_data_length"] = size
    value.update(overrides)
    return value


def volume(entries, index=1, fs="fat16"):
    return {"partition": {"index": index, "fs_hint": fs, "size_bytes": 1 << 20},
            "info": {"fs_type": fs, "truncated": False, "volume_size": 1 << 20},
            "walk": {"fs": fs, "entries": entries, "truncated": False, "truncated_reasons": [],
                     "cut_dirs_total": 0, "unvalidated_dirs_total": 0}}


def listing(*volumes, **params):
    return {"schema": "pweh.forensics.fs-list/v1", "evidence_id": "EV-0001",
            "params": {"partition": None, "include_deleted": True, **params}, "volumes": list(volumes),
            "call": {"partitions_unexamined": [], "partitions_skipped": {},
                     "volumes_failed": {"count": 0, "examples": []}}}


def plan(document, **kwargs):
    return plan_survey(document, deadline=time.monotonic() + 30, is_media_name=lambda s: s.endswith(".mp4"), **kwargs)


def fresh(target, data, **changes):
    value = {k: getattr(target, k) for k in ("partition", "ref", "fs", "declared_size", "expected_size",
                                            "deleted", "parent_deleted", "name_lossy")}
    value.update(selected_size=len(data), selected_sha256=hashlib.sha256(data).hexdigest(), complete=True,
                 method="chain", confidence="high", residual_unexamined=target.declared_size > target.expected_size)
    if value["parent_deleted"] is None:
        value["parent_deleted"] = False
    value.update(changes)
    return value


def accept(collector, target, data, **source_changes):
    report = scan_secrets(data, digest=lambda v: "sha256:" + hashlib.sha256(v).hexdigest()[:16],
                          limits=collector.scan_limits(), xor_key=collector.xor_key, deadline=time.monotonic() + 30,
                          cancel=lambda: False)
    collector.accept_file(target, fresh(target, data, **source_changes), report)
    return report


def publish(report):
    report = copy.deepcopy(report)
    report.update(source={"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a" * 64,
                          "fs_list": {"path": "forensics/analysis/fs-list-EV-0001-001.json", "sha256": "b" * 64,
                                      "size": 1234, "custody_seq": 2, "custody_hash": "c" * 64}},
                  params={"partition": None, "xor_key": None, "max_seconds": 45})
    schemas.validate("secrets-survey", report)
    return report


def test_full_classification_then_stable_prefix_and_policy_precedence():
    rows = [entry(0, 0, path="/private.mp4"), entry(1, 0), entry(2, (4 << 20) + 1),
            entry(3, 5, is_dir=True), entry(4, 6), entry(5, 7), entry(6, 1)]
    document = listing(volume(rows), volume([entry(0, 3)], 2))
    before = copy.deepcopy(document)
    p = plan(document, limits=SurveyLimits(max_read_bytes=10))
    assert [(t.volume_index, t.entry_index, t.partition, t.ref) for t in p.targets] == [(0, 4, 1, "0/4")]
    s = p.selection
    assert s["entries_total"] == 8 and s["directories"] == 1
    assert s["excluded"] == {"media_name": 1, "empty_data": 1, "file_too_large": 1}
    assert (s["eligible_files"], s["eligible_bytes"]) == (4, 17)
    assert (s["deferred_eligible_files"], s["deferred_eligible_bytes"]) == (3, 11)
    assert s["cutoff_reason"] == "total_bytes_limit"
    assert document == before
    p.selection["eligible_files"] = 999
    assert p.selection["eligible_files"] == 4
    assert "private" not in repr(p)


def test_file_limit_does_not_stop_population_counting():
    p = plan(listing(volume([entry(i, 1) for i in range(40)])))
    assert len(p.targets) == 32
    assert p.selection["eligible_files"] == 40
    assert p.selection["deferred_eligible_files"] == 8
    assert p.selection["cutoff_reason"] == "file_limit"


def test_exact_four_mib_and_sixteen_mib_boundary():
    p = plan(listing(volume([entry(i, 4 << 20) for i in range(5)])))
    assert len(p.targets) == 4 and p.selection["scheduled_bytes"] == 16 << 20
    assert p.selection["cutoff_reason"] == "total_bytes_limit"


def test_partition_none_means_stored_scope_and_explicit_selection():
    document = listing(volume([entry()], 2), volume([entry()], 3), partition=2)
    p = plan(document)
    assert p.listing["selected_partitions"] == [2, 3]
    assert p.listing["complete"] and p.listing["reasons"] == ["partition_restricted"]
    q = plan(document, partition=3)
    assert [t.partition for t in q.targets] == [3]
    assert q.listing["partitions_outside_selection"] == 1
    with pytest.raises(PwehError, match="scope_unavailable"):
        plan(document, partition=4)


def test_exfat_declared_vdl_residual_and_empty():
    p = plan(listing(volume([entry(0, 100, fs="exfat", valid_data_length=5),
                             entry(1, 100, fs="exfat", valid_data_length=0)], fs="exfat")))
    assert (p.targets[0].declared_size, p.targets[0].expected_size) == (100, 5)
    assert p.selection["residual_files"] == 2 and p.selection["residual_bytes"] == 195
    c = SurveyCollector(p, xor_key=None)
    accept(c, p.targets[0], b"hello")
    r = publish(c.finish())
    assert r["files"][0]["source"]["residual_unexamined"] is True
    assert r["coverage"]["read_complete_bytes"] == 5
    assert r["coverage"]["whole_card_examined"] is False


@pytest.mark.parametrize("field,value", [("deleted", True), ("parent_deleted", True), ("parent_deleted", None), ("name_lossy", True)])
def test_uncertainty_does_not_mutate_ok_child(field, value):
    p = plan(listing(volume([entry(size=5, **{field: value})])))
    c = SurveyCollector(p, xor_key=None)
    child = accept(c, p.targets[0], b"hello")
    r = publish(c.finish())
    assert r["status"] == "partial" and r["coverage"]["selection_uncertain"]
    assert r["files"][0]["scan"] == child and child["status"] == "ok"


@pytest.mark.parametrize("field,value", [("size", True), ("size", 1.0), ("size", -1), ("size", 1 << 64),
                                       ("deleted", 0), ("parent_deleted", 1), ("name_lossy", None),
                                       ("ref", "private\n0/1"), ("fs", "ntfs"), ("is_dir", 1)])
def test_entry_contract_rejects_invalid_values_without_original(field, value):
    with pytest.raises(PwehError) as got:
        plan(listing(volume([entry(**{field: value})])))
    assert got.value.code == "secret_survey_invalid"
    assert "private" not in str(got.value)


@pytest.mark.parametrize("value", [True, 1.0, -1, 101, None])
def test_invalid_exfat_vdl_is_not_clamped(value):
    with pytest.raises(PwehError):
        plan(listing(volume([entry(size=100, fs="exfat", valid_data_length=value)], fs="exfat")))


def test_duplicate_partition_and_ref_rejected():
    for document in (listing(volume([entry(), entry()])), listing(volume([]), volume([]))):
        with pytest.raises(PwehError):
            plan(document)


@pytest.mark.parametrize("count", [0, 1, 27])
def test_failed_budget_rows_not_double_counted_and_examples_not_authority(count):
    document = listing(volume([]), {"partition": 2, "error": {"code": "fs_error", "data": {"reason": "budget_exceeded", "limit": "time"}}})
    document["call"]["partitions_skipped"] = {"time": {"count": count, "examples": [2] if count else []}}
    p = plan(document)
    assert p.listing["partitions_unexamined"] == count
    assert p.listing["volumes_failed"] == 0
    assert not p.listing["complete"]


def test_unsupported_unexamined_list_and_skip_do_not_double_count():
    document = listing(volume([]))
    document["call"]["partitions_unexamined"] = [{"index": 3, "fs_hint": "ntfs", "reason": "unsupported_partitions"}]
    document["call"]["partitions_skipped"] = {"unsupported_partitions": {"count": 1, "examples": [3]}}
    p = plan(document)
    assert p.listing["partitions_unexamined"] == p.listing["partitions_unsupported"] == 1


def test_missing_coverage_remains_unknown():
    document = listing(volume([]))
    document["call"] = {}
    document["volumes"][0]["walk"].pop("cut_dirs_total")
    p = plan(document)
    assert p.listing["partitions_unexamined"] is None and p.listing["volumes_failed"] is None
    assert p.listing["cut_dirs"] is None
    assert "listing_coverage_unknown" in p.listing["reasons"]
    assert publish(SurveyCollector(p, xor_key=None).finish())["status"] == "partial"


def test_nosupported_and_noeligible_are_not_clean_card_claims():
    for document, status, result in ((listing(), "unsupported", "no_supported_volume"),
                                     (listing(volume([entry(size=0)])), "ok", "no_eligible_files")):
        r = publish(SurveyCollector(plan(document), xor_key=None).finish())
        assert (r["status"], r["summary"]["result"]) == (status, result)
        assert r["coverage"]["whole_card_examined"] is False


def test_read_failure_unsupported_partial_and_unattempted_are_distinct():
    data = b"password=SurveySecret123\n"
    p = plan(listing(volume([entry(i, len(data)) for i in range(4)])))
    c = SurveyCollector(p, xor_key=None)
    c.skip_file(p.targets[0], "refs_unverifiable")
    accept(c, p.targets[1], b"\0" * len(data))
    accept(c, p.targets[2], data)
    r = publish(c.finish("time_limit"))
    cov = r["coverage"]
    assert (cov["files_attempted"], cov["files_read_complete"], cov["files_read_failed"], cov["files_unattempted"]) == (3, 2, 1, 1)
    assert cov["files_scan_unsupported"] == cov["files_scanned_complete"] == 1
    assert cov["eligible_files_unread"] == 2 and cov["read_complete_bytes"] == 2 * len(data)
    assert r["summary"]["hits"] == 1 and r["status"] == "partial"
    assert all(v not in json.dumps(r) for v in ("SurveySecret123", "private-name"))


@pytest.mark.parametrize("reason", READ_REASONS)
def test_each_fixed_read_reason(reason):
    p = plan(listing(volume([entry()])))
    c = SurveyCollector(p, xor_key=None)
    c.skip_file(p.targets[0], reason)
    r = publish(c.finish("time_limit" if reason == "time_limit" else None))
    assert r["coverage"]["files_read_failed"] == 1
    assert r["files"][0]["source"] is None


def test_global_hit_budget_stops_before_next_file():
    data = b"password=SurveySecret123\n"
    limits = SurveyLimits(max_hits=1)
    p = plan(listing(volume([entry(i, len(data)) for i in range(2)])), limits=limits)
    c = SurveyCollector(p, xor_key=None, limits=limits)
    accept(c, p.targets[0], data)
    assert c.scan_limits() is None
    r = publish(c.finish())
    assert r["summary"]["hits"] == 1 and r["coverage"]["files_unattempted"] == 1
    assert "hit_limit" in r["coverage"]["reasons"]


def test_small_output_budget_stops_without_read_or_dropped_accounting():
    limits = SurveyLimits(max_output_bytes=20 << 10)
    p = plan(listing(volume([entry()])), limits=limits)
    c = SurveyCollector(p, xor_key=None, limits=limits)
    assert c.scan_limits() is None
    r = publish(c.finish())
    assert r["coverage"]["files_attempted"] == 0 and r["summary"]["hits"] == 0
    assert "output_limit" in r["coverage"]["reasons"]


def test_same_scanner_digest_aggregation_and_input_immutability():
    data = b"password=SurveySecret123\n"
    p = plan(listing(volume([entry(i, len(data)) for i in range(2)])))
    c = SurveyCollector(p, xor_key=None)
    child = accept(c, p.targets[0], data)
    child["matches"][0]["digest"] = "sha256:" + "f" * 16
    accept(c, p.targets[1], data)
    r = publish(c.finish())
    assert r["summary"]["hits"] == 2 and r["summary"]["unique_digest_count"] == 1


@pytest.mark.parametrize("data", [b"\xef\xbb\xbfhello\r\n", b"abc\n\nxyz", b"plain", b"\xff\xfeabc", b"\0bad",
                                 b"\x89PNG\r\n\x1a\n", b"a" * 16385 + b"\nhello"],
                         ids=["bom", "lines", "plain", "utf16", "binary", "media", "long-line"])
def test_existing_scanner_range_and_unsupported_reports_are_preserved(data):
    p = plan(listing(volume([entry(size=len(data))])))
    c = SurveyCollector(p, xor_key=None)
    child = accept(c, p.targets[0], data)
    r = publish(c.finish())
    assert r["files"][0]["scan"] == child
    assert sum(r["coverage"][k] for k in ("scanned_bytes", "framing_bytes", "unscanned_read_bytes")) == len(data)


@pytest.mark.parametrize("mutation", ["size", "complete", "method", "extra", "boolint", "floatint", "offset", "summary", "range", "params", "status"])
def test_bad_child_or_fresh_contract_rejected_atomically(mutation):
    data = b"password=SurveySecret123\n"
    p = plan(listing(volume([entry(size=len(data))])))
    c = SurveyCollector(p, xor_key=None)
    child = scan_secrets(data, digest=lambda _: "sha256:" + "a" * 16, limits=c.scan_limits(),
                         deadline=time.monotonic() + 5, cancel=lambda: False)
    source = fresh(p.targets[0], data)
    if mutation == "size": source["selected_size"] += 1
    elif mutation == "complete": source["complete"] = 1
    elif mutation == "method": source["method"] = "nofatchain"
    elif mutation == "extra": source["filename"] = "private"
    elif mutation == "boolint": child["summary"]["hits"] = True
    elif mutation == "floatint": child["summary"]["hits"] = 1.0
    elif mutation == "offset": child["matches"][0]["offset"] = len(data)
    elif mutation == "summary": child["summary"]["unique_digest_count"] = 0
    elif mutation == "range": child["coverage"]["scanned_ranges"][0]["offset"] = 1
    elif mutation == "params": child["params"]["max_hits"] -= 1
    elif mutation == "status": child["status"] = "partial"
    with pytest.raises(PwehError): c.accept_file(p.targets[0], source, child)
    c.skip_file(p.targets[0], "read_failed")
    assert c.finish()["summary"]["hits"] == 0


def test_target_order_and_late_reuse_rejected():
    p = plan(listing(volume([entry(i) for i in range(2)])))
    c = SurveyCollector(p, xor_key=None)
    with pytest.raises(PwehError): c.skip_file(p.targets[1], "read_failed")
    with pytest.raises(PwehError): c.finish()
    c.skip_file(p.targets[0], "read_failed")
    with pytest.raises(PwehError): c.skip_file(p.targets[0], "read_failed")
    c.skip_file(p.targets[1], "read_failed")
    c.finish()
    with pytest.raises(PwehError): c.finish()


@pytest.mark.parametrize("deadline", [float("nan"), float("inf"), True, 10 ** 400])
def test_invalid_deadlines_are_fixed(deadline):
    with pytest.raises(PwehError):
        plan_survey(listing(), is_media_name=lambda _: False, deadline=deadline)


def test_classification_deadline_does_not_publish_partial_population():
    with pytest.raises(PwehError) as exc:
        plan_survey(listing(volume([entry()])), is_media_name=lambda _: False, deadline=time.monotonic() - 1)
    assert exc.value.code == "timeout"


@pytest.mark.parametrize("callback", [lambda _: 1, lambda _: (_ for _ in ()).throw(ValueError("private"))])
def test_media_callback_has_fixed_error(callback):
    with pytest.raises(PwehError) as exc:
        plan_survey(listing(volume([entry()])), is_media_name=callback, deadline=time.monotonic() + 5)
    assert exc.value.code == "secret_survey_callback_failed" and "private" not in str(exc.value)


def test_cancel_during_classification_and_after_child():
    with pytest.raises(PwehError, match="cancelled"):
        plan(listing(), cancel=lambda: True)
    flag = [False]
    p = plan(listing(volume([entry(size=5)])))
    c = SurveyCollector(p, xor_key=None, cancel=lambda: flag[0])
    accept(c, p.targets[0], b"hello")
    flag[0] = True
    with pytest.raises(PwehError, match="cancelled"):
        c.finish()


@pytest.mark.parametrize("name", list(SurveyLimits.__dataclass_fields__))
@pytest.mark.parametrize("bad", [0, True, 1.5])
def test_limits_are_exact_and_positive(name, bad):
    with pytest.raises(PwehError): plan(listing(), limits=replace(SurveyLimits(), **{name: bad}))


def test_maximum_population_of_32_child_reports_and_global_200_hits_fits():
    # 범위가 많은32개 child에200hits를 분산하여 전체 hit 공유와 출력 봉투를 함께 확인한다.
    secret = b"password=SurveySecret123\n"
    last = secret * 14
    # 첫31개는 실제 read 총량16MiB 안에 들도록 range를64개 정도로 줄인다.
    lines = (b"x" * 16385 + b"\nhello\n") * 31
    data = [lines + secret * 6] * 31 + [last]
    p = plan(listing(volume([entry(i, len(d)) for i, d in enumerate(data)])))
    assert len(p.targets) == 32
    c = SurveyCollector(p, xor_key=None)
    for target, content in zip(p.targets, data): accept(c, target, content)
    r = publish(c.finish())
    assert r["summary"]["hits"] == 200 and len(r["files"]) == 32
    assert len(json.dumps(r, ensure_ascii=True, separators=(",", ":")).encode()) + 1 < 901120


def test_source_less_child_definition_matches_existing_single_contract():
    # 기존 공개 single schema의 의도한 두 필드와 survey 범위상한만 다르다.
    expected = copy.deepcopy(schemas.load("secrets-scan"))
    for key in ("$schema", "$id", "title", "description"):
        expected.pop(key, None)
    expected["properties"].pop("source")
    expected["required"].remove("source")
    params = expected["properties"]["params"]
    params["properties"].pop("max_seconds")
    params["required"].remove("max_seconds")
    for key in ("scanned_ranges", "unscanned_ranges"):
        expected["properties"]["coverage"]["properties"][key]["maxItems"] = 128
    assert schemas.load("secrets-survey")["$defs"]["scan_result"] == expected


def _simple_report():
    p = plan(listing(volume([entry(size=5)])))
    c = SurveyCollector(p, xor_key=None)
    accept(c, p.targets[0], b"hello")
    return publish(c.finish())


@pytest.mark.parametrize("path", [(), ("source",), ("source", "fs_list"), ("params",), ("rules",),
                                   ("limits",), ("listing",), ("selection",), ("selection", "excluded"),
                                   ("coverage",), ("files", 0), ("files", 0, "target"),
                                   ("files", 0, "source"), ("files", 0, "scan"),
                                   ("files", 0, "scan", "params"), ("summary",)])
def test_schema_rejects_unlisted_fields_in_every_public_section(path):
    report = _simple_report()
    section = report
    for key in path:
        section = section[key]
    section["raw_name"] = "DO-NOT-RETURN"
    assert schemas.errors("secrets-survey", report)


@pytest.mark.parametrize("mutate", [
    lambda r: r["files"][0].update(outcome="read_failed"),
    lambda r: r["files"][0].update(reason="raw OS message"),
    lambda r: r["files"][0]["source"].update(method="whole-file"),
    lambda r: r["files"][0]["scan"].update(source={}),
    lambda r: r["files"][0]["scan"]["params"].update(max_seconds=45),
    lambda r: r["source"]["fs_list"].update(path="forensics/recovered/private-name.cfg"),
    lambda r: r["coverage"].update(whole_card_examined=True),
    lambda r: r["files"][0]["source"].update(parent_deleted=None),
])
def test_schema_rejects_mixed_source_and_outcome_branches(mutate):
    report = _simple_report()
    mutate(report)
    assert schemas.errors("secrets-survey", report)


def test_xor_uses_existing_single_scanner_without_plaintext():
    clear = b"password=SurveySecret123\n"
    data = bytes(v ^ 144 for v in clear)
    p = plan(listing(volume([entry(size=len(data))])))
    c = SurveyCollector(p, xor_key=144)
    accept(c, p.targets[0], data)
    report = publish(c.finish())
    assert report["summary"]["hits"] == 1 and "SurveySecret123" not in json.dumps(report)


def test_exact_remaining_range_and_output_limits_are_preserved():
    # 과도한 범위 또는 hits는 기존 scanner가 partial로 줄이며 집계는 이를 성공으로 바꾸지 않는다.
    data = (b"x" * 16385 + b"\nplain\n") * 65
    p = plan(listing(volume([entry(size=len(data))])))
    c = SurveyCollector(p, xor_key=None)
    child = accept(c, p.targets[0], data)
    r = publish(c.finish())
    assert child["status"] == "partial" and "range_limit" in child["coverage"]["reasons"]
    assert r["coverage"]["files_scanned_partial"] == 1


def test_entry_cap_fails_before_population_result():
    with pytest.raises(PwehError) as exc:
        plan(listing(volume([entry(0), entry(1)])), limits=SurveyLimits(max_entries=1))
    assert exc.value.code == "secret_survey_limit"


def test_expired_scanner_returns_partial_after_complete_selection():
    data = b"password=SurveySecret123\n"
    p = plan(listing(volume([entry(size=len(data))])))
    c = SurveyCollector(p, xor_key=None)
    child = scan_secrets(data, digest=lambda _: "sha256:" + "a" * 16, limits=c.scan_limits(),
                         deadline=time.monotonic() - 1, cancel=lambda: False)
    c.accept_file(p.targets[0], fresh(p.targets[0], data), child)
    report = publish(c.finish())
    assert report["selection"]["complete"] is True
    assert report["coverage"]["files_read_complete"] == 1
    assert report["coverage"]["files_scanned_partial"] == 1
    assert report["coverage"]["unscanned_read_bytes"] == len(data)
    assert child["coverage"]["reasons"] == ["time_limit"]
