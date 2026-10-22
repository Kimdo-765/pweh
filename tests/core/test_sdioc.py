"""원문 없는 SD 이름 대조의 합성 경로·범위·예산 시험."""
from __future__ import annotations

import copy
import dataclasses
import json
import time

import pytest

from pweh import sdioc as S
from pweh.errors import PwehError, ValidationFailed
from pweh.schemas import validate

PRIVATE = "PRIVATE_SYNTHETIC_PATH_739"


def entry(path="/" + PRIVATE, ref="root/0", **changes):
    return {"path": path, "name": path.rsplit("/", 1)[-1], "ref": ref, "parent_ref": None,
            "parent_deleted": False, "deleted": False, "is_dir": False, "name_lossy": False,
            "name_source": "sfn", "lfn_status": "none", "chain": {"status": "eoc", "size_check": "ok"}, **changes}


def inputs(paths=None, entries=None, fs="fat32"):
    paths = ["/" + PRIVATE] if paths is None else paths
    fw = {"schema": "pweh.fwtriage.sd-surface/v1", "tool": "fw_sd_surface", "case_id": "synthetic",
          "mount_points": [{"path": "/mnt/sd"}], "sd_paths_referenced": [
              {"path": "/mnt/sd" + p, "mount_point": "/mnt/sd", "card_relative": p[1:],
               "actions": ["exec"], "checks": ["SD-01"], "refs": [{"excerpt": PRIVATE}]} for p in paths],
          "sd_paths_total": len(paths), "sd_paths_truncated": False, "timed_out": False,
          "checks": [{"id": check, "status": "not-found"} for check in S.CHECKS], "phases": {"rootfs": "complete"},
          "limitations": [], "stats": {"skipped_large": [], "overlong_files": [], "hits_dropped_files": []}}
    listing = {"schema": "pweh.forensics.fs-list/v1", "evidence_id": "EV-0001", "params": {"include_deleted": True},
               "call": {"partitions_unexamined": [], "partitions_skipped": {}, "volumes_failed": {"count": 0}},
               "volumes": [{"partition": {"index": 1, "size_bytes": 1000},
                            "info": {"fs_type": fs, "volume_size": 1000, "truncated": False},
                            "walk": {"entries": [entry()] if entries is None else entries, "truncated": False,
                                     "truncated_reasons": [], "cut_dirs_total": 0, "unvalidated_dirs_total": 0,
                                     "warnings": [], "warnings_suppressed": 0}}]}
    return fw, listing


def run(fw=None, listing=None, **kwargs):
    if fw is None:
        fw, listing = inputs()
    return S.compare_sd_paths(fw, listing, deadline=time.monotonic() + 30, **kwargs)


def envelope(report):
    report = copy.deepcopy(report)
    report["params"] = {"partition": None, "max_matches": 200, "max_seconds": 45}
    report["source"] = {"kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": "a" * 64,
        "firmware": {"path": "analysis/sd-surface-001.json", "sha256": "b" * 64, "size": 100,
                     "artifact_id": "A-0001", "origin_basis": "case-artifact-index"},
        "listing": {"path": "forensics/analysis/fs-list-EV-0001-001.json", "sha256": "c" * 64, "size": 100,
                    "custody_seq": 1, "custody_hash": "d" * 64, "origin_basis": "evidence-custody-list"}}
    return report


def assert_ranges(report):
    cov = report["coverage"]
    for prefix, ranges in (("entries", "unprocessed_entry_ranges"), ("firmware_refs", "unprocessed_ref_ranges")):
        assert cov[prefix + "_processed"] + cov[prefix + "_remaining"] == cov[prefix + "_total"]
        assert sum(row["count"] for row in cov[ranges]) == cov[prefix + "_remaining"]
        for row in cov[ranges]:
            assert row["start"] == cov[prefix + "_processed"]
    validate("sd-ioc-scan", envelope(report))


@pytest.mark.parametrize("fs", ["fat12", "fat16", "fat32", "exfat"])
def test_exact_closed_report_and_input_unchanged(fs):
    fw, listing = inputs(fs=fs)
    before = copy.deepcopy((fw, listing))
    result = run(fw, listing)
    assert result["status"] == "ok"
    assert result["summary"]["by_kind"]["exact_live_name"] == 1
    assert result["matches"][0]["actions"] == ["exec"]
    assert result["device_association_verified"] is False
    assert PRIVATE not in json.dumps(result)
    assert (fw, listing) == before
    assert_ranges(result)


@pytest.mark.parametrize(("firmware_path", "card_path", "kind"), [
    ("/HELLO", "/hello", "case_variant_candidate"), ("/é", "/é", "exact_live_name"),
    ("/Ä", "/ä", None), ("/é", "/e\u0301", None), ("/a%20b", "/a b", None),
    ("/LONGNA~1", "/LongName.txt", None), ("/x ", "/x", None),
])
def test_exact_and_ascii_only_semantics(firmware_path, card_path, kind):
    fw, listing = inputs([firmware_path], [entry(card_path)])
    result = run(fw, listing)
    assert [m["match_kind"] for m in result["matches"]] == ([] if kind is None else [kind])
    assert_ranges(result)


@pytest.mark.parametrize("bad", ["/a/../b", "/a/./b", "/a//b", "/$secret", "/a*", "/a?", "/a[0]",
                                      "/a\\b", "/`secret`", "/a\x00b", "/a\u200bb", '/"secret"', "/<masked>", "/a…"])
def test_unresolved_paths_are_not_expanded(bad):
    fw, listing = inputs([bad], [entry(bad)])
    result = run(fw, listing)
    assert result["status"] == "partial" and not result["matches"]
    assert result["coverage"]["firmware_refs_unmatchable"] == 1
    assert bad not in json.dumps(result)
    assert_ranges(result)


@pytest.mark.parametrize("change", [{"path": "/mnt/sdextra/" + PRIVATE}, {"mount_point": "/else"},
                                     {"card_relative": "mismatch"}, {"card_relative": ""}, {"card_relative": None}])
def test_mount_boundary_and_relative_contract(change):
    fw, listing = inputs()
    fw["sd_paths_referenced"][0].update(change)
    result = run(fw, listing)
    assert not result["matches"] and result["status"] == "partial"
    assert_ranges(result)


def test_directory_and_duplicate_paths_preserved():
    fw, listing = inputs(["/directory", "/item"], [entry("/directory", is_dir=True), entry("/item", "root/1"), entry("/ITEM", "root/2")])
    result = run(fw, listing)
    assert result["summary"]["directory_references"] == 1
    assert len(result["matches"]) == 2 and all(m["ambiguous"] for m in result["matches"])
    assert {m["match_kind"] for m in result["matches"]} == {"exact_live_name", "case_variant_candidate"}
    assert_ranges(result)


def test_duplicate_ref_is_invalid_without_input_leak():
    fw, listing = inputs(entries=[entry(), entry("/another")])
    with pytest.raises(ValidationFailed) as exc:
        run(fw, listing)
    assert PRIVATE not in str(exc.value)


@pytest.mark.parametrize(("change", "kind"), [
    ({"deleted": True}, "deleted_name_candidate"), ({"parent_deleted": True}, "deleted_name_candidate"),
    ({"name_lossy": True}, "uncertain_name"), ({"lfn_status": "checksum_mismatch"}, "uncertain_name"),
    ({"name_status": "partial"}, "uncertain_name"), ({"set_complete": False}, "uncertain_name"),
    ({"set_checksum_ok": False}, "uncertain_name"), ({"name_hash_ok": False}, "uncertain_name"),
    ({"deleted": True, "first_char": {"known": False}}, "uncertain_name"),
    ({"parent_ref": "root/99"}, "uncertain_name"),
])
def test_name_and_deletion_uncertainty(change, kind):
    fw, listing = inputs(entries=[entry(**change)])
    result = run(fw, listing)
    assert result["matches"][0]["match_kind"] == kind and result["status"] == "partial"
    assert_ranges(result)


def test_deleted_parent_and_missing_parent():
    fw, listing = inputs(["/dir/file"], [entry("/dir", is_dir=True, deleted=True), entry("/dir/file", "c2/0", parent_ref="root/0")])
    assert run(fw, listing)["matches"][0]["match_kind"] == "deleted_name_candidate"
    listing["volumes"][0]["walk"]["entries"].pop(0)
    assert run(fw, listing)["matches"][0]["match_kind"] == "uncertain_name"


@pytest.mark.parametrize("chain", [None, {}, {"status": "limit", "size_check": "unknown"}])
def test_chain_is_separate_from_name(chain):
    fw, listing = inputs(entries=[entry(chain=chain)])
    result = run(fw, listing)
    assert result["matches"][0]["match_kind"] == "exact_live_name"
    assert result["status"] == "partial"


@pytest.mark.parametrize("change", ["firmware", "walk", "call", "deleted", "cut", "unknown", "large"])
def test_incomplete_inputs_never_complete(change):
    fw, listing = inputs()
    if change == "firmware": fw["sd_paths_truncated"] = True
    if change == "walk": listing["volumes"][0]["walk"]["truncated"] = True
    if change == "call": listing["call"]["partitions_unexamined"] = [{"path": PRIVATE}]
    if change == "deleted": listing["params"]["include_deleted"] = False
    if change == "cut": listing["volumes"][0]["walk"]["cut_dirs_total"] = 100
    if change == "unknown": fw["checks"][0]["status"] = "unknown"
    if change == "large": fw["stats"]["skipped_large"] = [PRIVATE]
    result = run(fw, listing)
    assert result["status"] == "partial" and not result["coverage"]["comparison_complete"]
    assert PRIVATE not in json.dumps(result)
    assert_ranges(result)


def test_volume_selection_and_unsupported():
    fw, listing = inputs()
    another = copy.deepcopy(listing["volumes"][0]); another["partition"]["index"] = 2
    listing["volumes"].append(another)
    with pytest.raises(ValidationFailed) as exc: run(fw, listing)
    assert exc.value.data == {"partitions": [1, 2]}
    assert run(fw, listing, partition=2)["selected_partition"] == 2
    with pytest.raises(ValidationFailed): run(fw, listing, partition=3)
    listing["archive"] = {"name": PRIVATE}
    result = run(fw, listing)
    assert result["status"] == "unsupported" and not result["matches"]
    assert_ranges(result)
    fw, listing = inputs(fs="ext4")
    assert run(fw, listing)["status"] == "unsupported"


@pytest.mark.parametrize(("field", "value", "reason"), [
    ("max_entries", 1, "entry_limit"), ("max_firmware_refs", 1, "ref_limit"),
    ("max_matches", 1, "match_limit"), ("max_steps", 1, "step_limit"),
    ("max_path_chars", 5, "path_chars_limit"), ("max_path_length", 5, "path_too_long"),
    ("max_output_bytes", 4096, "output_limit"),
])
def test_limits_and_remaining_ranges(field, value, reason):
    fw, listing = inputs(["/item"] * 40, [entry("/item", f"root/{i}") for i in range(20)])
    result = run(fw, listing, limits=dataclasses.replace(S.IocLimits(), **{field: value}))
    assert result["status"] == "partial" and reason in result["coverage"]["reasons"]
    if field == "max_output_bytes":
        assert len(json.dumps(result, separators=(",", ":")).encode()) <= value
    assert_ranges(result)


def test_deadline_and_cancellation():
    fw, listing = inputs()
    result = S.compare_sd_paths(fw, listing, deadline=0)
    assert result["coverage"]["reasons"] == ["time_limit"]
    assert_ranges(result)
    with pytest.raises(PwehError, match="cancelled"):
        run(fw, listing, cancel=lambda: True)


@pytest.mark.parametrize("key,value", [("filename", PRIVATE), ("device_association_verified", True)])
def test_schema_rejects_freeform_and_false_association(key, value):
    report = envelope(run())
    report[key] = value
    with pytest.raises(PwehError): validate("sd-ioc-scan", report)


def test_unknown_actions_and_checks_are_not_copied():
    fw, listing = inputs()
    fw["sd_paths_referenced"][0]["actions"].append(PRIVATE)
    fw["sd_paths_referenced"][0]["checks"].append(PRIVATE)
    result = run(fw, listing)
    assert result["status"] == "partial" and PRIVATE not in json.dumps(result)
    assert_ranges(result)


@pytest.mark.parametrize("change", [{"name_lossy": True}, {"lfn_status": "checksum_mismatch"},
                                     {"set_checksum_ok": False}, {"set_complete": False},
                                     {"name_hash_ok": False}, {"name_status": "missing"}, {"name": "other"}])
@pytest.mark.parametrize("reverse", [False, True])
def test_parent_name_integrity_propagates_independent_of_order(change, reverse):
    entries = [entry("/dir", is_dir=True, **change), entry("/dir/file", "c2/0", parent_ref="root/0")]
    if reverse:
        entries.reverse()
    fw, listing = inputs(["/dir/file"], entries)
    result = run(fw, listing)
    assert result["matches"][0]["match_kind"] == "uncertain_name"
    assert_ranges(result)


def test_parent_replacement_character_and_sfn_first_char_not_wildcard():
    fw, listing = inputs(["/di\ufffdr/file"], [entry("/di\ufffdr", is_dir=True), entry("/di\ufffdr/file", "c2/0", parent_ref="root/0")])
    assert run(fw, listing)["matches"][0]["match_kind"] == "uncertain_name"
    fw, listing = inputs(["/xfile"], [entry("/_file", deleted=True, first_char={"known": False})])
    assert not run(fw, listing)["matches"]


def test_all_truncation_points_have_disjoint_remaining_ranges():
    fw, listing = inputs(["/item"] * 8, [entry("/item", f"root/{i}") for i in range(8)])
    for steps in range(1, 120):
        result = run(fw, listing, limits=dataclasses.replace(S.IocLimits(), max_steps=steps))
        assert_ranges(result)
    result = run(fw, listing, limits=dataclasses.replace(S.IocLimits(), max_output_bytes=4096))
    assert len(json.dumps(result, separators=(",", ":")).encode()) <= 4096
    assert result["coverage"]["firmware_refs_remaining"] == 8


def test_cancel_during_index_parent_and_ref_walk():
    fw, listing = inputs(["/item"] * 8, [entry("/item", f"root/{i}") for i in range(8)])
    for stop in (1, 10, 30, 60, 100):
        calls = 0
        def cancel():
            nonlocal calls
            calls += 1
            return calls == stop
        with pytest.raises(PwehError, match="cancelled"):
            run(fw, listing, cancel=cancel)


@pytest.mark.parametrize("field", [f.name for f in dataclasses.fields(S.IocLimits())])
def test_limit_bool_cannot_be_integer(field):
    with pytest.raises(ValidationFailed):
        run(limits=dataclasses.replace(S.IocLimits(), **{field: True}))


def test_callback_error_cannot_reflect_input():
    def cancel():
        raise PwehError(PRIVATE)
    with pytest.raises(ValidationFailed) as exc:
        run(cancel=cancel)
    assert PRIVATE not in str(exc.value)
