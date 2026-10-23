"""등록 합성 전력 CSV의 같은 FD·부모 신원·최종 commit 수명을 검증한다."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import sys
import threading
import time
import traceback
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "mcp-servers/sdr-mcp"))
from sdr_mcp import power_analysis as A
from pweh import rf_power, schemas
from pweh.errors import PwehError
from pweh.runtime import get_runtime

PRIVATE = "SYNTHETIC_POWER_PRIVATE"
CSV = b"2025-03-04, 05:06:07, 100, 200, 25.00, 4, -12.50, -11.25\n"


@pytest.fixture
def case(workspace, auth):
    return get_runtime("test").cases.create(title="합성 전력 CSV", authorization=auth)


def attach(case, data=CSV, relative="signals/SYNTHETIC_POWER_PRIVATE.csv"):
    path = case.dir / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    entry = case.register_artifact(relative, kind="other", producer="synthetic")
    return entry, path


def analyze(case, entry, **kwargs):
    return A.analyze_registered_power(case, entry["id"],
                                    deadline=kwargs.pop("deadline", time.monotonic() + 5),
                                    max_seconds=kwargs.pop("max_seconds", 5),
                                    cancel=kwargs.pop("cancel", None), **kwargs)


def replace_entry(case, update):
    def change(meta):
        update(meta["artifacts"][0])
    case._update(change)


def outputs(case):
    return list((case.dir / "analysis").glob("rf-power-*.json"))


def fail(case, entry, *, code=None, **kwargs):
    with pytest.raises(PwehError) as caught:
        analyze(case, entry, **kwargs)
    if code:
        assert caught.value.code == code
    rendered = "".join(traceback.format_exception(caught.value))
    assert PRIVATE not in str(caught.value) and PRIVATE not in json.dumps(caught.value.to_dict())
    # traceback에는 합성 시험 코드의 호출 위치만 있고 원래 예외 사슬은 드러나지 않는다.
    assert "RuntimeError: " + PRIVATE not in rendered
    return caught.value


@pytest.mark.parametrize("data,status", [
    (CSV, "complete"), (b"", "unsupported"),
    (CSV.replace(b"100", b"1x0"), "malformed"),
    (CSV.replace(b"-12.50", b"nan"), "unsupported"),
    (b"x" * 65537 + b"\n", "partial"),
    (CSV.replace(b"-12.50, -11.25", b"-inf, -inf"), "complete"),
])
def test_registered_bytes_produce_closed_persisted_report(case, data, status):
    entry, path = attach(case, data)
    result = analyze(case, entry)
    assert set(result) == {"ok", "report", "analysis", "warnings"}
    assert result["ok"] is True and result["warnings"] == []
    report = result["report"]
    assert report["status"] == status
    assert report["source"] == {"kind": "case-artifact", "artifact_id": entry["id"],
                                "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    schemas.validate("rf-power-analysis", report)
    analysis = result["analysis"]
    assert set(analysis) == {"path", "sha256", "size", "artifact_id"}
    saved = (case.dir / analysis["path"]).read_bytes()
    assert json.loads(saved) == report and analysis["size"] == len(saved)
    assert saved == (json.dumps(report, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")
    assert len(saved) <= 65536
    assert hashlib.sha256(saved).hexdigest() == analysis["sha256"]
    assert stat.S_IMODE((case.dir / analysis["path"]).stat().st_mode) == 0o444
    art = case.artifacts()[-1]
    assert art["id"] == analysis["artifact_id"] and art["sha256"] == analysis["sha256"]
    assert art["kind"] == "other" and art["producer"] == "pweh-sdr"
    assert art["extra"] == {"type": "rf-power-analysis"}
    assert PRIVATE not in saved.decode() and str(path) not in saved.decode()
    assert "2025-03-04" not in saved.decode() and "05:06:07" not in saved.decode()


@pytest.mark.parametrize("field,value", [
    ("size", True), ("size", 1.0), ("size", -1), ("size", None),
    ("sha256", None), ("sha256", "A" * 64), ("sha256", PRIVATE),
    ("is_dir", 0), ("is_dir", True),
    ("path", "../outside"), ("path", "/outside"), ("path", "signals//x"),
    ("path", "signals/./x"), ("path", "signals/../x"), ("path", "signals/\x00x"),
    ("path", "forensics/file"), ("path", "emu/file"),
    ("path", "x/" * 257 + "f"), ("path", "x" * 4097),
])
def test_invalid_artifact_projection_is_rejected_before_read(case, monkeypatch, field, value):
    entry, _ = attach(case)
    replace_entry(case, lambda row: row.update({field: value}))
    monkeypatch.setattr(A.safeio, "open_regular", lambda *a, **k: pytest.fail("입력 open 전에 거부해야 함"))
    fail(case, entry, code="rf_power_input_invalid")
    assert not outputs(case)


@pytest.mark.parametrize("shape", ["missing", "duplicate", "not_list"])
def test_artifact_must_have_one_registered_projection(case, shape):
    entry, _ = attach(case)
    def change(meta):
        if shape == "missing": meta["artifacts"] = []
        elif shape == "duplicate": meta["artifacts"].append(dict(meta["artifacts"][0]))
        else: meta["artifacts"] = {}
    case._update(change)
    fail(case, entry, code="rf_power_input_invalid")
    assert not outputs(case)


@pytest.mark.parametrize("size", [A.MAX_INPUT_BYTES, A.MAX_INPUT_BYTES + 1])
def test_input_size_ceiling(case, monkeypatch, size):
    entry, _ = attach(case, b"#" * size)
    if size > A.MAX_INPUT_BYTES:
        monkeypatch.setattr(A.safeio, "open_regular", lambda *a, **k: pytest.fail("초과 입력을 열면 안 됨"))
        fail(case, entry, code="rf_power_input_limit")
    else:
        assert analyze(case, entry)["report"]["source"]["size"] == size


@pytest.mark.parametrize("kind", ["file_link", "parent_link", "hardlink", "fifo", "directory"])
def test_link_or_nonregular_input_is_not_followed(case, kind):
    entry, path = attach(case, relative="signals/nested/source.csv")
    if kind == "parent_link":
        parent = path.parent
        moved = parent.with_name("moved")
        parent.rename(moved)
        parent.symlink_to(moved, target_is_directory=True)
    elif kind == "hardlink":
        os.link(path, path.with_name("hard.csv"))
    else:
        data = path.read_bytes()
        path.unlink()
        if kind == "file_link":
            target = path.with_name("other.csv")
            target.write_bytes(data)
            path.symlink_to(target)
        elif kind == "fifo": os.mkfifo(path)
        else: path.mkdir()
    fail(case, entry)
    assert not outputs(case)


@pytest.mark.parametrize("real_path", [None, "/outside/source.csv"])
def test_fd_real_path_must_prove_case_containment(case, monkeypatch, real_path):
    entry, _ = attach(case)
    monkeypatch.setattr(A.safeio, "fd_real_path", lambda fd: real_path)
    fail(case, entry, code="rf_power_input_invalid")


@pytest.mark.parametrize("kwargs", [
    {"max_seconds": True}, {"max_seconds": 0},
    {"max_seconds": 6}, {"max_seconds": float("nan")}, {"max_seconds": 10 ** 400},
    {"deadline": True}, {"deadline": float("inf")}, {"deadline": 10 ** 400},
    {"cancel": "not-callable"},
])
def test_worker_contract_validation_is_fixed(case, kwargs):
    entry, _ = attach(case)
    fail(case, entry, code="rf_power_input_invalid", **kwargs)
    assert not outputs(case)


def test_one_input_open_two_bounded_passes_and_worker_closes(case, monkeypatch):
    # 문법 미지원 큰 파일도 입력 전체 SHA와 최종 같은 FD 재해시를 해야 한다.
    data = PRIVATE.encode() + b"x" * (2 * A.CHUNK)
    entry, _ = attach(case, data)
    original_open, original_pread = A.safeio.open_regular, os.pread
    fds, reads = [], []
    def opened(*args, **kwargs):
        result = original_open(*args, **kwargs)
        fds.append(result[0])
        return result
    def read(fd, length, offset):
        assert 0 < length <= A.CHUNK
        if fd in fds: reads.append((fd, length, offset))
        return original_pread(fd, length, offset)
    monkeypatch.setattr(A.safeio, "open_regular", opened)
    monkeypatch.setattr(A.os, "pread", read)
    result = analyze(case, entry)
    assert result["report"]["status"] == "partial"
    assert result["report"]["inspection"]["stop"]["code"] == "line_length_limit"
    assert len(fds) == 1 and len(reads) == 6
    assert [r[2] for r in reads] == [0, A.CHUNK, 2 * A.CHUNK] * 2
    with pytest.raises(OSError): os.fstat(fds[0])


@pytest.mark.parametrize("mutation", ["replace_name", "same_inode", "parent"])
def test_parser_return_rechecks_input_and_parent(case, monkeypatch, mutation):
    entry, path = attach(case, relative="signals/nested/source.csv")
    original = A.rf_power.inspect_power_csv
    def changed(data, **kwargs):
        report = original(data, **kwargs)
        if mutation == "replace_name":
            path.unlink()
            path.write_bytes(CSV)
        elif mutation == "same_inode":
            path.write_bytes(CSV.replace(b"100", b"101"))
        else:
            path.parent.rename(path.parent.with_name("moved"))
            path.parent.mkdir()
        return report
    monkeypatch.setattr(A.rf_power, "inspect_power_csv", changed)
    fail(case, entry, code="rf_power_input_changed")
    assert not outputs(case)


@pytest.mark.parametrize("mutation", ["index", "same_inode", "hash_only", "hardlink"])
def test_final_callback_rechecks_projection_content_and_link_count(case, monkeypatch, mutation):
    entry, path = attach(case)
    original = case.register_artifact
    def changed(*args, **kwargs):
        if mutation == "index":
            replace_entry(case, lambda row: row.update(sha256="0" * 64))
        elif mutation in ("same_inode", "hash_only"):
            path.write_bytes(CSV.replace(b"100", b"101"))
            if mutation == "hash_only":
                # stat 검사를 제외해도 최종 전체 SHA가 같은 inode 변조를 검출한다.
                monkeypatch.setattr(A, "_check_file", lambda *a: None)
        else: os.link(path, path.with_name("linked.csv"))
        return original(*args, **kwargs)
    monkeypatch.setattr(case, "register_artifact", changed)
    fail(case, entry, code="rf_power_input_changed")
    assert not outputs(case) and len(case.artifacts()) == 1


def test_input_mutation_during_output_rehash_is_rechecked_before_commit(case, monkeypatch):
    entry, path = attach(case)
    original = A._read_fd
    mutated = []
    def read(fd, size, deadline, cancel, **kwargs):
        result = original(fd, size, deadline, cancel, **kwargs)
        if os.readlink(f"/proc/self/fd/{fd}").endswith("rf-power-001.json"):
            path.write_bytes(CSV.replace(b"100", b"101"))
            mutated.append(True)
        return result
    monkeypatch.setattr(A, "_read_fd", read)
    fail(case, entry, code="rf_power_input_changed")
    assert mutated == [True] and not outputs(case) and len(case.artifacts()) == 1


@pytest.mark.parametrize("mutation", ["name", "parent"])
def test_unknown_output_replacement_is_preserved(case, monkeypatch, mutation):
    entry, _ = attach(case)
    original = case.register_artifact
    replacement = []
    def changed(relative, **kwargs):
        target = case.dir / relative
        if mutation == "name":
            target.rename(target.with_suffix(".held"))
        else:
            target.parent.rename(target.parent.with_name("old-analysis"))
            target.parent.mkdir()
        target.write_bytes(PRIVATE.encode())
        replacement.append(target)
        return original(relative, **kwargs)
    monkeypatch.setattr(case, "register_artifact", changed)
    fail(case, entry, code="rf_power_cleanup_incomplete")
    assert replacement[0].read_bytes() == PRIVATE.encode()
    assert len(case.artifacts()) == 1


def test_output_same_inode_mutation_is_removed_without_registration(case, monkeypatch):
    entry, _ = attach(case)
    original = case.register_artifact
    def changed(relative, **kwargs):
        target = case.dir / relative
        target.chmod(0o600)
        target.write_bytes(b"{}")
        target.chmod(0o444)
        return original(relative, **kwargs)
    monkeypatch.setattr(case, "register_artifact", changed)
    fail(case, entry, code="rf_power_input_changed")
    assert not outputs(case) and len(case.artifacts()) == 1


def test_normal_parent_mtime_change_and_existing_output_do_not_replace_files(case, monkeypatch):
    entry, _ = attach(case)
    existing = case.dir / "analysis/rf-power-001.json"
    existing.write_bytes(b"existing")
    original = case.register_artifact
    def extra(*args, **kwargs):
        (case.dir / "analysis/independent.txt").write_bytes(b"other")
        return original(*args, **kwargs)
    monkeypatch.setattr(case, "register_artifact", extra)
    result = analyze(case, entry)
    assert result["analysis"]["path"] == "analysis/rf-power-002.json"
    assert existing.read_bytes() == b"existing"


@pytest.mark.parametrize("when", ["before_read", "during_read", "before_final", "final_check"])
def test_cancel_before_commit_removes_only_owned_output(case, monkeypatch, when):
    entry, _ = attach(case)
    stopped = threading.Event()
    if when == "before_read": stopped.set()
    elif when == "during_read":
        original = os.pread
        def read(*args):
            value = original(*args); stopped.set(); return value
        monkeypatch.setattr(A.os, "pread", read)
    elif when == "before_final":
        original = A.rf_power.inspect_power_csv
        def inspected(*args, **kwargs):
            value = original(*args, **kwargs); stopped.set(); return value
        monkeypatch.setattr(A.rf_power, "inspect_power_csv", inspected)
    else:
        original = case.register_artifact
        def registering(*args, **kwargs):
            check = kwargs["check"]
            def cancelled(entry):
                stopped.set(); check(entry)
            kwargs["check"] = cancelled
            return original(*args, **kwargs)
        monkeypatch.setattr(case, "register_artifact", registering)
    fail(case, entry, code="cancelled", cancel=stopped.is_set)
    assert not outputs(case) and len(case.artifacts()) == 1


def test_expired_input_phase_creates_no_report(case):
    entry, _ = attach(case)
    fail(case, entry, code="time_limit", deadline=time.monotonic() - 1)
    assert not outputs(case)


def test_parser_time_partial_uses_single_new_final_deadline(case, monkeypatch):
    entry, _ = attach(case)
    original = A.rf_power.inspect_power_csv
    deadlines = []
    work_end = time.monotonic() + 5
    def expired(data, **kwargs):
        deadlines.append(kwargs["deadline"])
        return original(data, deadline=time.monotonic() - 1, cancel=kwargs["cancel"])
    monkeypatch.setattr(A.rf_power, "inspect_power_csv", expired)
    original_register = case.register_artifact
    def registering(*args, **kwargs):
        deadlines.append(kwargs["deadline"])
        return original_register(*args, **kwargs)
    monkeypatch.setattr(case, "register_artifact", registering)
    result = analyze(case, entry, deadline=work_end)
    assert result["report"]["status"] == "partial"
    assert result["report"]["inspection"]["stop"]["code"] == "time_limit"
    assert deadlines[0] == work_end and work_end <= deadlines[1] <= work_end + 1


def test_final_deadline_expiration_does_not_refresh_at_commit(case, monkeypatch):
    entry, _ = attach(case)
    clock = SimpleNamespace(now=time.monotonic())
    monkeypatch.setattr(A, "time", SimpleNamespace(monotonic=lambda: clock.now))
    original = case.register_artifact
    def registering(*args, **kwargs):
        clock.now = kwargs["deadline"] + 0.1
        return original(*args, **kwargs)
    monkeypatch.setattr(case, "register_artifact", registering)
    fail(case, entry, code="time_limit")
    assert not outputs(case)


@pytest.mark.parametrize("code", ["lock_timeout", "artifact_timeout"])
def test_metadata_lock_timeout_is_fixed_and_output_removed(case, monkeypatch, code):
    entry, _ = attach(case)
    def raising(*args, **kwargs): raise PwehError(PRIVATE, code=code)
    monkeypatch.setattr(case, "register_artifact", raising)
    fail(case, entry, code="time_limit")
    assert not outputs(case)


@pytest.mark.parametrize("when", ["cancel", "audit"])
def test_late_cancel_or_audit_error_keeps_commit(case, monkeypatch, when):
    entry, _ = attach(case)
    stopped = threading.Event()
    if when == "cancel":
        original = case.register_artifact
        def registering(*args, **kwargs):
            committed = kwargs["on_commit"]
            def late(entry): committed(entry); stopped.set()
            kwargs["on_commit"] = late
            return original(*args, **kwargs)
        monkeypatch.setattr(case, "register_artifact", registering)
    else:
        def raising(*args): raise RuntimeError(PRIVATE)
        monkeypatch.setattr(case, "audit", raising)
    result = analyze(case, entry, cancel=stopped.is_set)
    assert len(case.artifacts()) == 2 and len(outputs(case)) == 1
    assert result["warnings"] == ([] if when == "cancel" else ["post_commit_callback_failed"])
    assert PRIVATE not in json.dumps(result)


def test_precommit_write_failure_is_fixed_and_cleans_owned_file(case, monkeypatch):
    entry, _ = attach(case)
    def raising(*args): raise RuntimeError(PRIVATE)
    monkeypatch.setattr(A.os, "write", raising)
    fail(case, entry, code="rf_power_failed")
    assert not outputs(case)


def test_constructor_failure_closes_root_fd(case, monkeypatch):
    entry, _ = attach(case)
    original = A.safeio._walk_directory
    held = []
    def opening(*args, **kwargs):
        fd = original(*args, **kwargs); held.append(fd); return fd
    def fail_check(*args): raise PwehError(PRIVATE, code="cancelled")
    monkeypatch.setattr(A.safeio, "_walk_directory", opening)
    monkeypatch.setattr(A._Directories, "check", fail_check)
    fail(case, entry, code="cancelled")
    assert len(held) == 1
    with pytest.raises(OSError): os.fstat(held[0])


def test_close_failure_after_commit_is_warning_not_deletion(case, monkeypatch):
    entry, _ = attach(case)
    original = os.close
    failed = []
    def close(fd):
        target = os.readlink(f"/proc/self/fd/{fd}")
        original(fd)
        if target.endswith("rf-power-001.json") and not failed:
            failed.append(True); raise OSError(PRIVATE)
    monkeypatch.setattr(A.os, "close", close)
    result = analyze(case, entry)
    assert result["warnings"] == ["output_close_unconfirmed"]
    assert len(case.artifacts()) == 2 and len(outputs(case)) == 1


@pytest.mark.parametrize("entry_key,value", [("size", 1.0), ("is_dir", 0), ("sha256", "0" * 64)])
def test_final_registration_entry_requires_exact_fd_facts(case, monkeypatch, entry_key, value):
    entry, _ = attach(case)
    original = case.register_artifact
    def registering(*args, **kwargs):
        check = kwargs["check"]
        def corrupt(observed):
            observed[entry_key] = float(observed[entry_key]) if entry_key == "size" else value
            check(observed)
        kwargs["check"] = corrupt
        return original(*args, **kwargs)
    monkeypatch.setattr(case, "register_artifact", registering)
    fail(case, entry, code="rf_power_input_changed")
    assert not outputs(case)


@pytest.mark.parametrize("field", ["input_bytes", "accepted_prefix_bytes", "remaining_bytes", "rows_seen"])
def test_schema_integer_compatible_float_is_still_rejected(case, monkeypatch, field):
    entry, _ = attach(case)
    original = A.rf_power.inspect_power_csv
    def corrupt(*args, **kwargs):
        item = original(*args, **kwargs)
        item["coverage"][field] = float(item["coverage"][field])
        return item
    monkeypatch.setattr(A.rf_power, "inspect_power_csv", corrupt)
    fail(case, entry, code="rf_power_failed")
    assert not outputs(case)


@pytest.mark.parametrize("mutation", ["size", "status", "accepted", "range", "count", "scope", "false_flag", "source_sha", "source_id", "profile", "seconds"])
def test_relations_reject_corrupted_parser_linkage(mutation):
    item = rf_power.inspect_power_csv(CSV, deadline=time.monotonic() + 5)
    digest = hashlib.sha256(CSV).hexdigest()
    source = {"id": "A-0001"}
    report = {"status": item["status"], "source": {"kind": "case-artifact", "artifact_id": source["id"],
              "size": len(CSV), "sha256": digest}, "params": {"profile": A.PROFILE, "max_seconds": 5},
              "inspection": copy.deepcopy(item)}
    cov, stats = report["inspection"]["coverage"], report["inspection"]["statistics"]
    if mutation == "size": report["source"]["size"] += 1
    elif mutation == "status": report["status"] = "partial"
    elif mutation == "accepted": cov["accepted_prefix_bytes"] -= 1
    elif mutation == "range": cov["remaining_range"] = {"offset": 0, "length": 1}
    elif mutation == "count": stats["values_accepted"] += 1
    elif mutation == "scope": cov["statistics_scope"] = "whole_file"
    elif mutation == "source_sha": report["source"]["sha256"] = "0" * 64
    elif mutation == "source_id": report["source"]["artifact_id"] = "A-0002"
    elif mutation == "profile": report["params"]["profile"] = PRIVATE
    elif mutation == "seconds": report["params"]["max_seconds"] = 3
    else: cov["decoded"] = True
    with pytest.raises(PwehError, match="rf_power_failed"):
        A._validate_relations(report, source, len(CSV), digest, 5)


def test_schema_failure_and_output_limit_leave_no_report(case, monkeypatch):
    entry, _ = attach(case)
    monkeypatch.setattr(A, "MAX_OUTPUT_BYTES", 1)
    fail(case, entry, code="rf_power_failed")
    assert not outputs(case)


def test_cancel_callback_exception_has_no_raw_exception_chain(case):
    entry, _ = attach(case)
    def raising(): raise RuntimeError(PRIVATE)
    fail(case, entry, code="rf_power_failed", cancel=raising)
    assert not outputs(case)
