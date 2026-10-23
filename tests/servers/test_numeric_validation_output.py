"""공급 숫자의 digest·반환 관계식·같은 FD 등록 수명을 합성 입력으로 검증한다."""
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

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "mcp-servers/play-mcp"))
from play_mcp import numeric_validation as A
from pweh import schemas, vision_sequence as V
from pweh.errors import PwehError
from pweh.runtime import get_runtime

PRIVATE = "SYNTHETIC_NUMERIC_PRIVATE"
OBS = tuple(V.NumericObservation(t, 42, .9) for t in (8, 9, 10))


@pytest.fixture
def case(workspace, auth):
    return get_runtime("test").cases.create(title="합성 숫자", authorization=auth)


def analyze(case, observations=OBS, **kwargs):
    return A.validate_supplied_numeric(case, observations, now=kwargs.pop("now", 10),
                                      policy=kwargs.pop("policy", V.NumericPolicy()),
                                      deadline=kwargs.pop("deadline", time.monotonic() + 5),
                                      cancel=kwargs.pop("cancel", None), **kwargs)


def outputs(case):
    return list((case.dir / "analysis").glob("numeric-observations-*.json"))


def fail(case, observations=OBS, *, code=None, **kwargs):
    with pytest.raises(PwehError) as caught:
        analyze(case, observations, **kwargs)
    if code is not None:
        assert caught.value.code == code
    assert PRIVATE not in str(caught.value) + json.dumps(caught.value.to_dict())
    assert "RuntimeError: " + PRIVATE not in "".join(traceback.format_exception(caught.value))
    return caught.value


@pytest.mark.parametrize("observations,now,policy,status,reason,value", [
    ((), 10, V.NumericPolicy(), "unknown", "no_observations", None),
    (OBS, 20, V.NumericPolicy(), "stale", "no_recent_observations", None),
    (OBS[:1], 10, V.NumericPolicy(), "unknown", "insufficient_valid", None),
    (tuple(V.NumericObservation(t, v, 1) for t, v in enumerate((1, 1, 2, 2))), 3,
     V.NumericPolicy(4, 2, 2, .8, 10), "unknown", "tied_votes", None),
    (tuple(V.NumericObservation(t, v, 1) for t, v in enumerate((1, 1, 2))), 2,
     V.NumericPolicy(3, 3, 3), "unknown", "insufficient_votes", None),
    (OBS, 10, V.NumericPolicy(), "stable", "vote_consensus", 42),
])
def test_each_valid_core_state_is_persisted(case, observations, now, policy, status, reason, value):
    result = analyze(case, observations, now=now, policy=policy)
    assert set(result) == {"ok", "report", "artifact_id", "analysis_path", "sha256", "size", "warnings"}
    assert result["ok"] is True and result["warnings"] == []
    report = result["report"]
    assert report["schema"] == A.SCHEMA and report["profile"] == A.PROFILE
    assert report["analysis"] == V.summarize_numeric_observations(observations, now=now, policy=policy)
    assert (report["analysis"]["status"], report["analysis"]["reason"], report["analysis"]["value"]) == (status, reason, value)
    schemas.validate("numeric-validation", report)
    path = case.dir / result["analysis_path"]
    data = path.read_bytes()
    assert data.endswith(b"\n") and json.loads(data) == report
    assert len(data) == result["size"] <= 65536 and hashlib.sha256(data).hexdigest() == result["sha256"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o444
    art = case.artifacts()[0]
    assert art["id"] == result["artifact_id"] and art["sha256"] == result["sha256"]
    assert art["kind"] == "other" and art["producer"] == "pweh-play"
    assert art["extra"] == {"type": "numeric-validation"}


def test_canonical_digest_matches_exact_declared_input_and_core_called_once(case, monkeypatch):
    original = A.V.summarize_numeric_observations
    called = []
    def counted(observations, **kwargs):
        called.append((observations, kwargs))
        return original(observations, **kwargs)
    monkeypatch.setattr(A.V, "summarize_numeric_observations", counted)
    report = analyze(case)["report"]
    canonical = {"schema": "pweh.numeric-input/v1", "input_kind": "numeric-observations", "now": 10,
                 "policy": {"window_size": 5, "votes_required": 3, "min_valid": 3,
                            "min_confidence": .8, "ttl_seconds": 2.0},
                 "observations": [{"timestamp": t, "value": 42, "confidence": .9} for t in (8, 9, 10)]}
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    assert len(called) == 1 and called[0][1]["now"] == 10
    assert report["source"]["canonical_size"] == len(encoded)
    assert report["source"]["canonical_sha256"] == hashlib.sha256(encoded).hexdigest()
    assert report["source"]["observation_count"] == 3


@pytest.mark.parametrize("change", ["timestamp", "value", "confidence", "now", "policy", "int_float", "signed_zero"])
def test_canonical_changes_preserve_numeric_representation(case, change):
    rows = tuple(V.NumericObservation(t, 42, .9) for t in (0, 1, 2))
    first = analyze(case, rows, now=2)["report"]["source"]["canonical_sha256"]
    kwargs = {"now": 2}
    if change == "timestamp": rows = (V.NumericObservation(.25, 42, .9), *rows[1:])
    elif change == "value": rows = (V.NumericObservation(0, 41, .9), *rows[1:])
    elif change == "confidence": rows = (V.NumericObservation(0, 42, .91), *rows[1:])
    elif change == "now": kwargs["now"] = 2.25
    elif change == "policy": kwargs["policy"] = V.NumericPolicy(ttl_seconds=2)
    elif change == "int_float": kwargs["now"] = 2.0
    else: rows = (V.NumericObservation(-0.0, 42, .9), *rows[1:])
    assert analyze(case, rows, **kwargs)["report"]["source"]["canonical_sha256"] != first


def test_equal_expanded_defaults_and_no_previous_value_cache(case):
    first = analyze(case)
    second = analyze(case, policy=V.NumericPolicy(5, 3, 3, .8, 2.0))
    assert first["report"]["source"] == second["report"]["source"]
    assert analyze(case, ())["report"]["analysis"]["value"] is None
    assert analyze(case, now=20)["report"]["analysis"]["status"] == "stale"


def test_samples_and_private_low_vote_value_are_not_stored(case, monkeypatch):
    private_number = 98765432190123456
    rows = (V.NumericObservation(8.125, private_number, .8123456789),
            V.NumericObservation(8.5, 7, .9), V.NumericObservation(9, 7, .9), V.NumericObservation(9.5, 7, .9))
    logged = []
    original = case.audit
    def audit(event):
        logged.append(event)
        return original(event)
    monkeypatch.setattr(case, "audit", audit)
    result = analyze(case, rows)
    rendered = json.dumps({"result": result, "case": case.load(), "audit": logged})
    assert result["report"]["analysis"]["value"] == 7
    assert all(value not in rendered for value in (str(private_number), "8.125", "0.8123456789", '"timestamp"', '"confidence"'))


@pytest.mark.parametrize("kwargs", [
    {"deadline": True}, {"deadline": float("nan")}, {"deadline": float("inf")},
    {"deadline": 10 ** 400}, {"deadline": time.monotonic() + 3600},
    {"cancel": PRIVATE}, {"policy": {}},
])
def test_worker_contract_is_bounded_and_fixed(case, kwargs):
    fail(case, code="numeric_input_invalid", **kwargs)
    assert not outputs(case)


@pytest.mark.parametrize("rows,kwargs,code", [
    (list(OBS), {}, "numeric_input_invalid"),
    (OBS * 86, {}, "observation_limit"),
    ((V.NumericObservation(-1, 0, 1), *OBS), {}, "invalid_observation"),
    ((V.NumericObservation(1, True, 1),), {}, "invalid_observation"),
    (OBS, {"now": True}, "invalid_observation"),
    (OBS, {"policy": V.NumericPolicy(window_size=2)}, "invalid_policy"),
])
def test_existing_core_is_the_input_validation_authority(case, rows, kwargs, code):
    fail(case, rows, code=code, **kwargs)
    assert not outputs(case)


@pytest.mark.parametrize("count", [0, 256])
def test_observation_endpoints(case, count):
    rows = tuple(V.NumericObservation(t, -t, 1) for t in range(count))
    result = analyze(case, rows, now=max(0, count - 1))
    assert result["report"]["source"]["observation_count"] == count


@pytest.mark.parametrize("field", A._COUNTS)
@pytest.mark.parametrize("badtype", [float, bool])
def test_schema_integer_compatible_nonexact_counts_are_rejected(case, monkeypatch, field, badtype):
    original = A.V.summarize_numeric_observations
    def corrupt(*args, **kwargs):
        report = original(*args, **kwargs)
        report["evidence"][field] = badtype(report["evidence"][field])
        return report
    monkeypatch.setattr(A.V, "summarize_numeric_observations", corrupt)
    fail(case, code="numeric_output_invalid")
    assert not outputs(case)


@pytest.mark.parametrize("mutation", [
    "schema", "extra", "status", "reason", "value", "flags", "policy_type", "policy_value",
    "received", "window", "recent", "valid", "winning", "leaders", "age", "age_bool", "age_nan",
])
def test_result_relations_reject_corrupt_core_projection(case, monkeypatch, mutation):
    original = A.V.summarize_numeric_observations
    def corrupt(*args, **kwargs):
        report = original(*args, **kwargs)
        ev = report["evidence"]
        if mutation == "schema": report["schema"] = PRIVATE
        elif mutation == "extra": report[PRIVATE] = 1
        elif mutation == "status": report["status"] = "unknown"
        elif mutation == "reason": report["reason"] = "tied_votes"
        elif mutation == "value": report["value"] = True
        elif mutation == "flags": report["action_generated"] = 0
        elif mutation == "policy_type": report["policy"]["ttl_seconds"] = 2
        elif mutation == "policy_value": report["policy"]["ttl_seconds"] = 3.0
        elif mutation == "received": ev["received_count"] += 1
        elif mutation == "window": ev["window_count"] -= 1
        elif mutation == "recent": ev["recent_count"] = 0
        elif mutation == "valid": ev["valid_count"] = 4
        elif mutation == "winning": ev["winning_votes"] = 0
        elif mutation == "leaders": ev["tied_leaders"] = 2
        elif mutation == "age": ev["latest_age_seconds"] = 1
        elif mutation == "age_bool": ev["latest_age_seconds"] = False
        else: ev["latest_age_seconds"] = float("nan")
        return report
    monkeypatch.setattr(A.V, "summarize_numeric_observations", corrupt)
    fail(case, code="numeric_output_invalid")
    assert not outputs(case)


@pytest.mark.parametrize("limit", ["MAX_CANONICAL_BYTES", "MAX_OUTPUT_BYTES"])
def test_byte_ceiling_leaves_no_output(case, monkeypatch, limit):
    monkeypatch.setattr(A, limit, 1)
    fail(case, code="numeric_input_invalid" if limit == "MAX_CANONICAL_BYTES" else "numeric_output_invalid")
    assert not outputs(case)


@pytest.mark.parametrize("operation", ["core", "schema", "write", "callback"])
def test_unexpected_failures_hide_input_and_exception_chain(case, monkeypatch, operation):
    def raising(*args, **kwargs): raise RuntimeError(PRIVATE)
    kwargs = {}
    if operation == "core": monkeypatch.setattr(A.V, "summarize_numeric_observations", raising)
    elif operation == "schema": monkeypatch.setattr(A.schemas, "validate", raising)
    elif operation == "write": monkeypatch.setattr(A.os, "write", raising)
    else: kwargs["cancel"] = raising
    fail(case, code="numeric_analysis_failed", **kwargs)
    assert not outputs(case)


@pytest.mark.parametrize("value", [0, 1, None, PRIVATE])
def test_cancel_callback_must_return_exact_boolean(case, value):
    fail(case, code="numeric_analysis_failed", cancel=lambda: value)


def test_one_written_fd_two_bounded_hashes_and_cleanup(case, monkeypatch):
    original_open, original_pread = A.os.open, A.os.pread
    held, reads = [], []
    def opening(path, flags, *args, **kwargs):
        fd = original_open(path, flags, *args, **kwargs)
        if str(path).startswith("numeric-observations-"):
            assert flags & os.O_EXCL and flags & os.O_NOFOLLOW
            held.append(fd)
        return fd
    def read(fd, n, offset):
        if fd in held:
            assert 0 < n <= A.CHUNK
            reads.append((fd, n, offset))
        return original_pread(fd, n, offset)
    monkeypatch.setattr(A.os, "open", opening)
    monkeypatch.setattr(A.os, "pread", read)
    result = analyze(case)
    assert len(held) == 1 and reads == [(held[0], result["size"], 0)] * 2
    with pytest.raises(OSError): os.fstat(held[0])


def test_analysis_symlink_is_rejected_before_output(case):
    parent = case.dir / "analysis"
    moved = parent.with_name("old-analysis")
    parent.rename(moved)
    parent.symlink_to(moved, target_is_directory=True)
    fail(case, code="numeric_output_invalid")
    assert not list(moved.iterdir())


def test_existing_name_and_independent_sibling_are_preserved(case, monkeypatch):
    existing = case.dir / "analysis/numeric-observations-001.json"
    existing.symlink_to(case.dir / "missing")
    original = case.register_artifact
    def registering(*args, **kwargs):
        (case.dir / "analysis/other.txt").write_bytes(b"independent")
        return original(*args, **kwargs)
    monkeypatch.setattr(case, "register_artifact", registering)
    result = analyze(case)
    assert result["analysis_path"].endswith("002.json") and existing.is_symlink()


@pytest.mark.parametrize("mutation", ["name", "parent", "root"])
def test_replaced_output_or_parent_is_not_deleted(case, monkeypatch, mutation):
    original = case.register_artifact
    replacement = []
    def registering(relative, **kwargs):
        path = case.dir / relative
        if mutation == "name": path.rename(path.with_suffix(".held"))
        elif mutation == "parent":
            path.parent.rename(path.parent.with_name("old-analysis")); path.parent.mkdir()
        else:
            case.dir.rename(case.dir.with_name(case.dir.name + "-moved"))
            case.dir.mkdir(); (case.dir / "analysis").mkdir()
        path.write_bytes(PRIVATE.encode())
        replacement.append(path)
        # commit callback에 직접 들어가 신원 교체를 metadata 파일 존재와 독립해서 검사한다.
        kwargs["check"]({})
    monkeypatch.setattr(case, "register_artifact", registering)
    fail(case, code="cleanup_incomplete")
    assert replacement[0].read_bytes() == PRIVATE.encode()


@pytest.mark.parametrize("mutation", ["same_inode", "same_size", "hardlink", "hash_only"])
def test_final_output_mutation_prevents_registration(case, monkeypatch, mutation):
    original = case.register_artifact
    linked = []
    def registering(relative, **kwargs):
        path = case.dir / relative
        if mutation == "hardlink":
            other = path.with_suffix(".link"); os.link(path, other); linked.append(other)
        else:
            data = path.read_bytes()
            path.chmod(0o600)
            path.write_bytes((b" " + data[1:]) if mutation != "same_inode" else b"{}")
            path.chmod(0o444)
            if mutation == "hash_only": monkeypatch.setattr(A, "_check_file", lambda *args: None)
        return original(relative, **kwargs)
    monkeypatch.setattr(case, "register_artifact", registering)
    fail(case, code="numeric_output_invalid")
    assert not case.artifacts() and not outputs(case)
    assert all(path.exists() for path in linked)


def test_mutation_after_final_hash_is_caught_by_last_seal(case, monkeypatch):
    original = A._hash_fd
    calls = []
    def hash_fd(fd, *args):
        value = original(fd, *args)
        calls.append(fd)
        if len(calls) == 2:
            os.pwrite(fd, b" ", 0)
        return value
    monkeypatch.setattr(A, "_hash_fd", hash_fd)
    fail(case, code="numeric_output_invalid")
    assert not outputs(case) and not case.artifacts()


@pytest.mark.parametrize("key,value", [("path", "analysis/other.json"), ("size", 1.0),
                                       ("is_dir", 0), ("sha256", "0" * 64)])
def test_registration_entry_matches_fd_exactly(case, monkeypatch, key, value):
    original = case.register_artifact
    def registering(*args, **kwargs):
        check = kwargs["check"]
        def corrupted(entry):
            entry[key] = float(entry[key]) if key == "size" else value
            check(entry)
        kwargs["check"] = corrupted
        return original(*args, **kwargs)
    monkeypatch.setattr(case, "register_artifact", registering)
    fail(case, code="numeric_output_invalid")
    assert not outputs(case) and not case.artifacts()


@pytest.mark.parametrize("when", ["initial", "after_core", "write", "hash", "final"])
def test_cancel_before_commit_leaves_no_artifact(case, monkeypatch, when):
    stop = threading.Event()
    if when == "initial": stop.set()
    elif when == "after_core":
        original = A.V.summarize_numeric_observations
        def core(*args, **kwargs):
            value = original(*args, **kwargs); stop.set(); return value
        monkeypatch.setattr(A.V, "summarize_numeric_observations", core)
    elif when == "write":
        original = A.os.write
        def write(*args):
            value = original(*args); stop.set(); return value
        monkeypatch.setattr(A.os, "write", write)
    elif when == "hash":
        original = A.os.pread
        def read(*args):
            value = original(*args); stop.set(); return value
        monkeypatch.setattr(A.os, "pread", read)
    else:
        original = case.register_artifact
        def registering(*args, **kwargs):
            check = kwargs["check"]
            def final(entry): stop.set(); return check(entry)
            kwargs["check"] = final
            return original(*args, **kwargs)
        monkeypatch.setattr(case, "register_artifact", registering)
    fail(case, code="cancelled", cancel=stop.is_set)
    assert not outputs(case) and not case.artifacts()


@pytest.mark.parametrize("when", ["core", "register"])
def test_one_shared_deadline_is_not_renewed(case, monkeypatch, when):
    clock = SimpleNamespace(now=time.monotonic())
    end = clock.now + 5
    monkeypatch.setattr(A, "time", SimpleNamespace(monotonic=lambda: clock.now))
    if when == "core":
        original = A.V.summarize_numeric_observations
        def core(*args, **kwargs):
            result = original(*args, **kwargs); clock.now = end; return result
        monkeypatch.setattr(A.V, "summarize_numeric_observations", core)
    else:
        original = case.register_artifact
        def registering(*args, **kwargs):
            assert kwargs["deadline"] == end
            clock.now = end
            return original(*args, **kwargs)
        monkeypatch.setattr(case, "register_artifact", registering)
    fail(case, code="time_limit", deadline=end)
    assert not outputs(case)


@pytest.mark.parametrize("code", ["lock_timeout", "artifact_timeout"])
def test_case_timeout_is_projected_and_output_removed(case, monkeypatch, code):
    def raising(*args, **kwargs): raise PwehError(PRIVATE, code=code)
    monkeypatch.setattr(case, "register_artifact", raising)
    fail(case, code="time_limit")
    assert not outputs(case)


@pytest.mark.parametrize("late", ["cancel", "audit"])
def test_commit_receipt_survives_late_cancel_or_audit_failure(case, monkeypatch, late):
    stop = threading.Event()
    if late == "cancel":
        original = case.register_artifact
        def registering(*args, **kwargs):
            committed = kwargs["on_commit"]
            def commit(entry): committed(entry); stop.set()
            kwargs["on_commit"] = commit
            return original(*args, **kwargs)
        monkeypatch.setattr(case, "register_artifact", registering)
    else:
        def audit(*args): raise RuntimeError(PRIVATE)
        monkeypatch.setattr(case, "audit", audit)
    result = analyze(case, cancel=stop.is_set)
    assert result["warnings"] == ([] if late == "cancel" else ["post_commit_audit_failed"])
    assert len(outputs(case)) == len(case.artifacts()) == 1


def test_close_failure_after_commit_preserves_registered_output(case, monkeypatch):
    original = os.close
    def close(fd):
        target = os.readlink(f"/proc/self/fd/{fd}")
        original(fd)
        if target.endswith("numeric-observations-001.json"):
            raise OSError(PRIVATE)
    monkeypatch.setattr(A.os, "close", close)
    fail(case, code="cleanup_incomplete")
    assert len(outputs(case)) == len(case.artifacts()) == 1


def test_constructor_failure_closes_held_directory(case, monkeypatch):
    original = A.safeio._walk_directory
    held = []
    def opened(*args, **kwargs):
        fd = original(*args, **kwargs); held.append(fd); return fd
    def changed(*args): raise PwehError(PRIVATE, code="cancelled")
    monkeypatch.setattr(A.safeio, "_walk_directory", opened)
    monkeypatch.setattr(A._Directories, "check", changed)
    fail(case, code="cancelled")
    assert len(held) == 1
    with pytest.raises(OSError): os.fstat(held[0])
