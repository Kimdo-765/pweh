"""합성 목록의 출처·메타데이터·같은 fd의 최종 커밋 검증 회귀."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import time
from types import SimpleNamespace

import pytest

from core.test_evidence import _commit_intake
from pweh import evidence as E, secret_survey_input as I
from pweh.case import CaseStore
from pweh.errors import PwehError

PRIVATE = "PRIVATE_SURVEY_SENTINEL_45ac"


def listing(ev):
    return {
        "schema": "pweh.forensics.fs-list/v1", "evidence_id": ev,
        "params": {"partition": None, "include_deleted": True},
        "volumes": [{
            "partition": {"index": 1, "fs_hint": "fat32", "start_offset": 0, "size_bytes": 8192},
            "info": {"fs_type": "fat32", "volume_size": 8192, "truncated": False},
            "walk": {"fs": "fat32", "truncated": False, "truncated_reasons": [],
                     "cut_dirs_total": 0, "unvalidated_dirs_total": 0, "unvalidated_dirs_live": 0,
                     "entries": [{"ref": "root/0", "fs": "fat32", "dir": "root", "slot": 0,
                                  "is_dir": False, "deleted": False, "size": 20, "first_cluster": 3,
                                  "name": "config.txt", "display_name": "config.txt", "path": "/config.txt",
                                  "name_lossy": False, "parent_deleted": False, "parent_ref": None,
                                  "attributes": {"raw": 32}}]},
        }],
        "call": {"entries_used": 1, "partitions_walked": 1, "partitions_skipped": {},
                 "partitions_unexamined": [], "volumes_failed": {"count": 0, "examples": []}},
    }


@pytest.fixture
def prepared(workspace, auth):
    case = CaseStore(workspace["cases_dir"]).create(
        title="합성 목록 입력", authorization=auth, case_id="survey-input")
    log = E.CustodyLog(case, workspace["state_dir"] / "custody")
    with contextlib.ExitStack() as stack:
        def make(mutate=None, raw=None, data=b"synthetic survey evidence", producer=None):
            ev = _commit_intake(case, log, data)
            opened = stack.enter_context(E.open_checked(case, ev, log.entries()))
            report = producer(opened) if producer else listing(ev)
            if mutate:
                mutate(report)
            encoded = raw if raw is not None else (json.dumps(report) + "\n").encode()
            path = f"forensics/analysis/fs-list-{ev}-001.json"
            target = case.dir / path
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(encoded)
            target.chmod(0o444)
            log.append("list", evidence_id=ev,
                       data={"result_path": path, "result_sha256": hashlib.sha256(encoded).hexdigest()})
            return SimpleNamespace(case=case, log=log, opened=opened, report=report, path=path,
                                   target=target, raw=encoded, entries=log.entries())
        yield make


def load(v, **changes):
    args = {"fs_list_path": v.path, "entries": v.entries,
            "deadline": time.monotonic() + 30, "cancel": lambda: False}
    args.update(changes)
    return I.open_list_input(v.case, v.opened, **args)


def entry(report):
    return report["volumes"][0]["walk"]["entries"][0]


def test_source_fd_lifetime_light_checks_and_exactly_two_full_hashes(prepared, monkeypatch):
    value = prepared()
    opened, reads = [], []
    old_open, old_pread = I.safeio.open_regular, I.os.pread
    def track_open(*args, **kwargs):
        result = old_open(*args, **kwargs)
        opened.append(result[0])
        return result
    def track_read(fd, length, offset):
        reads.append((fd, length, offset))
        return old_pread(fd, length, offset)
    monkeypatch.setattr(I.safeio, "open_regular", track_open)
    monkeypatch.setattr(I.os, "pread", track_read)
    with load(value) as inputs:
        assert inputs.source == {
            "kind": "evidence", "evidence_id": value.opened.evidence_id,
            "evidence_sha256": value.opened.intake["hashes"]["sha256"],
            "fs_list": {"path": value.path, "size": len(value.raw),
                        "sha256": hashlib.sha256(value.raw).hexdigest(),
                        "custody_seq": value.entries[-1]["seq"], "custody_hash": E.entry_hash(value.entries[-1])},
        }
        assert inputs.origin.to_dict() == inputs.source["fs_list"]
        fds = [inputs._fd, *inputs._dirs]
        assert len(opened) == 1 and len(reads) == 1
        inputs.check()
        inputs.check()
        assert len(reads) == 1
        inputs.check_entries(value.entries)
        assert len(reads) == 2 and all(row[0] == inputs._fd for row in reads)
    for fd in fds:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert os.fstat(value.opened.fd).st_size > 0  # EV는 caller 소유다.


@pytest.mark.parametrize("kind", ["fat", "exfat"])
def test_actual_synthetic_producer_shape_and_fresh_reader(prepared, kind):
    from fs.builders import fat32_small, exfat_small
    from forensics_mcp import fsops, server, secret_survey_selection as selection
    from pweh.fs import detect_partitions
    from pweh.secret_survey import plan_survey

    builder = fat32_small() if kind == "fat" else exfat_small()
    builder.mkdir("/cfg")
    builder.add_file("/cfg/settings.txt", b"password=synthetic\n",
                     **({"residual": b"private residual"} if kind == "exfat" else {}))
    builder.add_file("/old.txt", b"token=old\n")
    builder.delete("/old.txt")

    def producer(opened):
        limits = fsops.limits_for(max_seconds=20)
        budget = fsops.CallBudget.from_limits(limits)
        with fsops.image_reader(opened.fd) as img:
            layout = detect_partitions(img)
            volumes = []
            for volume in fsops.iter_volumes(img, layout, None, limits, budget, include_deleted=True):
                stream = io.StringIO()
                server._write_volume(stream, volume)
                volumes.append(json.loads(stream.getvalue()))
        return {"schema": "pweh.forensics.fs-list/v1", "evidence_id": opened.evidence_id,
                "params": {"partition": None, "include_deleted": True}, "volumes": volumes,
                "call": budget.summary()}

    value = prepared(data=builder.image(), producer=producer)
    with load(value) as inputs:
        plan = plan_survey(inputs.listing, is_media_name=lambda name: False,
                           deadline=time.monotonic() + 20, cancel=lambda: False)
        assert len(plan.targets) == 2 and any(t.deleted for t in plan.targets)
        assert any(t.expected_size < t.declared_size for t in plan.targets) is (kind == "exfat")
        for target in plan.targets:
            data, fresh = selection.read_survey_target(value.opened, target, listing=inputs.listing,
                                                       deadline=time.monotonic() + 20, cancel=lambda: False)
            assert len(data) == target.expected_size and fresh["complete"] is True
        inputs.check_entries(value.log.entries())


@pytest.mark.parametrize("path", [PRIVATE, "/forensics/analysis/x.json", "../" + PRIVATE,
                                 "forensics/analysis/fs-list-EV-9999-001.json",
                                 "forensics/analysis/fs-list-EV-0001-01.json",
                                 "forensics/analysis/fs-list-EV-0001-1000000000.json"])
def test_generated_same_ev_path_before_any_open(prepared, monkeypatch, path):
    value = prepared()
    monkeypatch.setattr(I.safeio, "open_dir_chain", lambda *a, **k: pytest.fail("열기 전 거부해야 한다"))
    with pytest.raises(PwehError) as caught:
        with load(value, fs_list_path=path):
            pass
    assert caught.value.code == "secret_survey_input_invalid" and PRIVATE not in str(caught.value)


@pytest.mark.parametrize("kind", ["missing", "duplicate", "sha", "ev", "path", "case", "seq", "boolseq", "hash"])
def test_unique_upstream_event_authority(prepared, kind):
    value = prepared()
    events = copy.deepcopy(value.entries)
    record = events[-1]
    if kind == "missing":
        events.pop()
    elif kind == "duplicate":
        events.append(copy.deepcopy(record))
    elif kind in {"sha", "path"}:
        record["data"]["result_" + ("sha256" if kind == "sha" else "path")] = PRIVATE
    elif kind == "hash":
        record["data"]["result_sha256"] = "0" * 64
    elif kind in {"case", "ev"}:
        record["case_id" if kind == "case" else "evidence_id"] = PRIVATE
    else:
        record["seq"] = True if kind == "boolseq" else 1
    with pytest.raises(PwehError) as caught:
        with load(value, entries=events):
            pass
    assert caught.value.code in {"secret_survey_input_invalid", "secret_survey_input_changed"}
    assert PRIVATE not in str(caught.value) and not caught.value.data


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(archive={}),
    lambda r: r.update(schema=PRIVATE),
    lambda r: r.update(evidence_id="EV-9999"),
    lambda r: r.update(evidence_sha256="0" * 64),
    lambda r: r.update(call=[]),
    lambda r: r["params"].update(partition=True),
    lambda r: r["params"].update(include_deleted=1),
    lambda r: r["volumes"].append(copy.deepcopy(r["volumes"][0])),
    lambda r: r["volumes"][0]["walk"]["entries"].append(copy.deepcopy(entry(r))),
    lambda r: r["volumes"][0]["partition"].update(index=0),
    lambda r: r["volumes"][0]["partition"].update(size_bytes=True),
    lambda r: r["volumes"][0]["info"].update(fs_type="exfat"),
    lambda r: r["volumes"][0]["walk"].update(fs="fat16"),
    lambda r: r["volumes"][0]["walk"].update(cut_dirs_total=-1),
    lambda r: r["volumes"][0]["walk"].update(truncated=0),
    lambda r: entry(r).update(ref="arc:1"),
    lambda r: entry(r).update(ref="../" + PRIVATE),
    lambda r: entry(r).update(fs="exfat"),
    lambda r: entry(r).update(size=True),
    lambda r: entry(r).update(size=1.0),
    lambda r: entry(r).update(size=-1),
    lambda r: entry(r).update(size=1 << 64),
    lambda r: entry(r).update(first_cluster=False),
    lambda r: entry(r).update(name=[]),
    lambda r: entry(r).update(is_dir=0),
    lambda r: entry(r).update(deleted=None),
    lambda r: entry(r).update(name_lossy=1),
    lambda r: entry(r).update(parent_deleted=1),
    lambda r: entry(r).update(slot=1),
    lambda r: entry(r).update(dir="c2"),
    lambda r: r["call"].update(entries_used=False),
    lambda r: r["call"].update(volumes_failed={"count": 0, "examples": [{"partition": 1}]}),
])
def test_critical_metadata_mismatch_is_fixed_failure(prepared, mutate):
    with pytest.raises(PwehError) as caught:
        with load(prepared(mutate=mutate)):
            pass
    assert caught.value.code == "secret_survey_input_invalid"
    assert PRIVATE not in json.dumps(caught.value.to_dict())


def test_exfat_vdl_cannot_exceed_declared(prepared):
    def mutate(r):
        v = r["volumes"][0]
        v["partition"]["fs_hint"] = v["info"]["fs_type"] = v["walk"]["fs"] = "exfat"
        entry(r).update(fs="exfat", valid_data_length=21)
    with pytest.raises(PwehError) as caught:
        with load(prepared(mutate=mutate)):
            pass
    assert caught.value.code == "secret_survey_input_invalid"


def test_legacy_unknown_parent_and_coverage_not_invented(prepared):
    def mutate(r):
        r["params"].clear()
        r["call"].clear()
        r["volumes"][0]["walk"].pop("cut_dirs_total")
        entry(r).pop("parent_deleted")
    with load(prepared(mutate=mutate)) as inputs:
        assert inputs.listing["params"] == inputs.listing["call"] == {}
        assert "cut_dirs_total" not in inputs.listing["volumes"][0]["walk"]
        assert entry(inputs.listing)["parent_deleted"] is None


def test_same_ref_different_partition_and_oversize_file_are_valid(prepared):
    def mutate(r):
        second = copy.deepcopy(r["volumes"][0])
        second["partition"]["index"] = 2
        second["walk"]["entries"][0]["size"] = 1 << 40
        r["volumes"].append(second)
    with load(prepared(mutate=mutate)) as inputs:
        assert len(inputs.listing["volumes"]) == 2


def test_failures_and_sample_counts_preserved_without_raw_names(prepared):
    def mutate(r):
        r.update(generated_at=PRIVATE, label=PRIVATE)
        r["volumes"][0]["partition"]["label"] = PRIVATE
        entry(r).update(times={"modified": PRIVATE}, arbitrary=PRIVATE)
        r["volumes"].append({"partition": 2, "fs": "fat32",
            "partition_info": {"index": 2, "fs_hint": "fat32"},
            "error": {"code": "validation_failed", "message": PRIVATE,
                      "data": {"reason": "budget_exceeded", "limit": "time", "filename": PRIVATE}}})
        r["call"].update(partitions_skipped={"time": {"count": 30, "examples": list(range(2, 22))}},
                         volumes_failed={"count": 0, "examples": []})
        r["volumes"][0]["walk"].update(warnings=[{"code": PRIVATE, "message": PRIVATE}],
                                       cut_dirs=[{"path": PRIVATE, "reason": PRIVATE}])
    with load(prepared(mutate=mutate)) as inputs:
        assert PRIVATE not in json.dumps(inputs.listing)
        assert inputs.listing["call"]["volumes_failed"]["count"] == 0
        assert inputs.listing["call"]["partitions_skipped"]["time"]["count"] == 30
        assert inputs.listing["volumes"][1]["error"]["data"]["reason"] == "budget_exceeded"
        assert inputs.listing["volumes"][0]["walk"]["warnings"] == [{"code": "unknown"}]


@pytest.mark.parametrize("raw", [b'{"x":NaN}', b'{"x":1,"x":2}', b'{"x":"\xff"}',
                                  b'{"x":"\\ud800"}', b'[]', b'{"' + PRIVATE.encode() + b'": }'])
def test_strict_json_error_is_safe(prepared, raw):
    with pytest.raises(PwehError) as caught:
        with load(prepared(raw=raw)):
            pass
    assert caught.value.code == "secret_survey_input_invalid"
    assert PRIVATE not in json.dumps(caught.value.to_dict())


@pytest.mark.parametrize("kind", ["size", "string", "depth", "empty"])
def test_json_and_file_limits_no_prefix_success(prepared, kind):
    raw = {"size": b" " * (I.MAX_REPORT_BYTES + 1),
           "string": json.dumps({"x": "x" * (256 * 1024 + 1)}).encode(),
           "depth": b'{"x":' + b'[' * 33 + b'0' + b']' * 33 + b'}', "empty": b""}[kind]
    with pytest.raises(PwehError) as caught:
        with load(prepared(raw=raw)):
            pass
    assert caught.value.code == "secret_survey_input_limit"
    assert "max_entries" in caught.value.hint


@pytest.mark.parametrize("kind", ["writable", "symlink", "hardlink"])
def test_file_admission_policy(prepared, kind):
    value = prepared()
    if kind == "writable":
        value.target.chmod(0o644)
    elif kind == "hardlink":
        os.link(value.target, value.target.with_name("alias.json"))
    else:
        saved = value.target.with_name("saved.json")
        value.target.rename(saved)
        value.target.symlink_to(saved.name)
    with pytest.raises(PwehError):
        with load(value):
            pass


@pytest.mark.parametrize("kind", ["file", "parent", "root", "same_inode", "mode", "link"])
def test_final_names_and_seals_cannot_change(prepared, kind):
    value = prepared()
    with load(value) as inputs:
        if kind == "file":
            value.target.rename(value.target.with_name("saved.json"))
            value.target.write_bytes(value.raw)
            value.target.chmod(0o444)
        elif kind in {"parent", "root"}:
            root = value.target.parent if kind == "parent" else value.case.dir
            root.rename(root.with_name(root.name + "-old"))
            root.mkdir()
        elif kind == "same_inode":
            value.target.chmod(0o644)
            value.target.write_bytes(value.raw.replace(b"config.txt", b"change.txt"))
            value.target.chmod(0o444)
        elif kind == "mode":
            value.target.chmod(0o644)
        else:
            os.link(value.target, value.target.with_name("alias.json"))
        with pytest.raises(PwehError) as caught:
            inputs.check_entries(value.entries)
        assert caught.value.code == "secret_survey_input_changed"


def test_final_hash_catches_content_even_if_seal_observation_is_stubbed(prepared, monkeypatch):
    value = prepared()
    with load(value) as inputs:
        monkeypatch.setattr(inputs, "_names", lambda: None)
        value.target.chmod(0o644)
        value.target.write_bytes(value.raw.replace(b"config.txt", b"change.txt"))
        with pytest.raises(PwehError) as caught:
            inputs.check_entries(value.entries)
        assert caught.value.code == "secret_survey_input_changed"


def test_mutable_public_projections_cannot_rebind_authority(prepared):
    value = prepared()
    with load(value) as inputs:
        inputs.source["fs_list"]["sha256"] = "0" * 64
        inputs.listing.clear()
        inputs.origin = I.ListOrigin(PRIVATE, "0" * 64, 0, 1, "0" * 64)
        inputs.check_entries(value.entries)
        changed = copy.deepcopy(value.entries)
        changed[-1]["data"]["result_sha256"] = "0" * 64
        with pytest.raises(PwehError) as caught:
            inputs.check_entries(changed)
        assert caught.value.code == "secret_survey_input_changed"


def test_final_hash_rechecks_unique_event(prepared):
    value = prepared()
    with load(value) as inputs:
        events = copy.deepcopy(value.entries)
        events.append(copy.deepcopy(events[-1]))
        with pytest.raises(PwehError) as caught:
            inputs.check_entries(events)
        assert caught.value.code == "secret_survey_input_changed"


def test_expired_input_fails_but_final_bounded_hash_finishes(prepared, monkeypatch):
    value = prepared()
    end = time.monotonic() + 20
    with load(value, deadline=end) as inputs:
        monkeypatch.setattr(I.time, "monotonic", lambda: end + 1)
        inputs.check()
        inputs.check_entries(value.entries)
    with pytest.raises(PwehError) as caught:
        with load(value, deadline=end):
            pass
    assert caught.value.code == "timeout"


@pytest.mark.parametrize("deadline", [True, None, "bad", float("inf"), float("nan"), 10 ** 400])
def test_deadline_invalid_fixed_error(prepared, deadline):
    with pytest.raises(PwehError) as caught:
        with load(prepared(), deadline=deadline):
            pass
    assert caught.value.code == "secret_survey_input_invalid"


def test_final_cancel_between_hash_chunks_no_commit(prepared, monkeypatch):
    value = prepared(mutate=lambda r: r.update(ignored="x" * (130 << 10)))
    stopped = False
    original = I.os.pread
    with load(value, cancel=lambda: stopped) as inputs:
        def read(fd, length, offset):
            nonlocal stopped
            assert length <= 64 << 10
            result = original(fd, length, offset)
            stopped = True
            return result
        monkeypatch.setattr(I.os, "pread", read)
        with pytest.raises(PwehError) as caught:
            inputs.check_entries(value.entries)
        assert caught.value.code == "cancelled"


@pytest.mark.parametrize("kind", ["raise", "badreturn", "cancel"])
def test_cancel_callback_sanitized(prepared, kind):
    def cancel():
        if kind == "raise":
            raise RuntimeError(PRIVATE)
        return PRIVATE if kind == "badreturn" else True
    with pytest.raises(PwehError) as caught:
        with load(prepared(), cancel=cancel):
            pass
    assert PRIVATE not in json.dumps(caught.value.to_dict())
    assert caught.value.code == ("cancelled" if kind == "cancel" else "secret_survey_input_invalid")


def test_custody_commit_hash_once_and_late_cancel_preserves_report(prepared, monkeypatch):
    value = prepared()
    cancelled = False
    with load(value, cancel=lambda: cancelled) as inputs:
        calls = []
        original = inputs._hash
        def hashed(**kwargs):
            calls.append(kwargs)
            return original(**kwargs)
        monkeypatch.setattr(inputs, "_hash", hashed)
        report = {"schema": "pweh.secrets-survey/v1", "source": inputs.source,
                  "status": "partial", "params": {"partition": None}}
        def committed():
            nonlocal cancelled
            cancelled = True
        result = E.store_analysis(value.case, value.opened, report, event="secrets-survey", custody_log=value.log,
                                  check=inputs.check, check_entries=inputs.check_entries, on_commit=committed)
        assert result["ok"] is True and len(calls) == 1
        assert (value.case.dir / result["analysis"]["path"]).is_file()
        assert value.log.entries()[-1]["event"] == "secrets-survey"


def test_commit_input_change_prevents_new_event_and_output(prepared, monkeypatch):
    value = prepared()
    count = len(value.log.entries())
    with load(value) as inputs:
        original = inputs.check_entries
        def changed(entries):
            value.target.chmod(0o644)
            value.target.write_bytes(value.raw.replace(b"config.txt", b"change.txt"))
            value.target.chmod(0o444)
            original(entries)
        with pytest.raises(PwehError) as caught:
            E.store_analysis(value.case, value.opened, {"source": inputs.source}, event="secrets-survey",
                             custody_log=value.log, check=inputs.check, check_entries=changed)
        assert caught.value.code == "secret_survey_input_changed"
    assert len(value.log.entries()) == count
    assert list(value.target.parent.glob("secrets-survey-*.json")) == []
