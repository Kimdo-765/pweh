"""합성 EV의 공용 분석 저장: custody 잠금 안의 출력 seal과 실패 후 소유 파일 정리."""

from __future__ import annotations

import hashlib
import json
import os
import stat

import pytest

from core.test_evidence import _commit_intake
from pweh import evidence as E
from pweh import safeio
from pweh.case import CaseStore
from pweh.errors import PwehError, ValidationFailed


@pytest.fixture
def analysis_case(workspace, auth):
    case = CaseStore(workspace["cases_dir"]).create(title="합성 분석 seal", authorization=auth, case_id="analysis-seal")
    log = E.CustodyLog(case, workspace["state_dir"] / "custody")
    ev = _commit_intake(case, log, b"synthetic evidence for output seal\n")
    with E.open_checked(case, ev, log.entries()) as opened:
        report = {"status": "ok", "source": {"kind": "evidence", "evidence_id": ev,
                  "evidence_sha256": opened.intake["hashes"]["sha256"]}, "params": {}, "matches": []}
        yield case, log, opened, report


def store(context, **kwargs):
    case, log, opened, report = context
    return E.store_analysis(case, opened, report, custody_log=log, event=kwargs.pop("event", "secrets-scan"), **kwargs)


def outputs(case):
    return list((case.dir / "forensics/analysis").glob("*.json"))


@pytest.mark.parametrize("event", ["secrets-scan", "sd-ioc-scan", "media-inventory", "sqlite-inventory", "android-artifacts", "timeline"])
def test_analysis_held_fd_and_custody_lock_through_final_check(analysis_case, monkeypatch, event):
    case, log, opened, report = analysis_case
    created = []
    create = safeio.create_excl
    recheck = E.recheck_opened

    def capture(directory, name, *args, **kwargs):
        fd = create(directory, name, *args, **kwargs)
        if name.startswith(event + "-"):
            created.append(fd)
        return fd

    def locked_check(*args, **kwargs):
        assert len(created) == 1
        assert stat.S_IMODE(os.fstat(created[0]).st_mode) == 0o444
        ffd = E.open_forensics(case)
        try:
            assert safeio.try_lock_at(ffd, E.CUSTODY_LOCK, create=False) is None
        finally:
            os.close(ffd)
        recheck(*args, **kwargs)

    monkeypatch.setattr(safeio, "create_excl", capture)
    monkeypatch.setattr(E, "recheck_opened", locked_check)
    result = store(analysis_case, event=event)
    saved = case.dir / result["analysis"]["path"]
    assert result["ok"] and result["warnings"] == []
    assert result["report"] == report
    assert saved.stat().st_nlink == 1 and stat.S_IMODE(saved.stat().st_mode) == 0o444
    assert hashlib.sha256(saved.read_bytes()).hexdigest() == result["analysis"]["sha256"]
    assert json.loads(saved.read_bytes()) == report
    assert log.entries()[-1]["event"] == event
    assert log.entries()[-1]["data"]["analysis"]["sha256"] == result["analysis"]["sha256"]
    with pytest.raises(OSError):
        os.fstat(created[0])


@pytest.mark.parametrize("mutation", ["regular", "symlink", "foreign-hardlink", "own-hardlink", "content", "writable", "missing"])
def test_analysis_file_swapped_or_changed_inside_final_check(analysis_case, monkeypatch, tmp_path, mutation):
    case, log, opened, report = analysis_case
    recheck = E.recheck_opened
    foreign = tmp_path / "foreign.json"
    foreign.write_bytes(b"synthetic unrelated file")
    foreign.chmod(0o444)
    output = None
    old = None

    def replace_after_input_check(*args, **kwargs):
        nonlocal output, old
        recheck(*args, **kwargs)
        output, = outputs(case)
        old = output.stat()
        if mutation in ("regular", "symlink", "foreign-hardlink", "missing"):
            output.rename(tmp_path / "original.json")
            if mutation == "regular":
                output.write_bytes(b"replacement")
                output.chmod(0o444)
            elif mutation == "symlink":
                output.symlink_to(foreign)
            elif mutation == "foreign-hardlink":
                os.link(foreign, output)
        elif mutation == "own-hardlink":
            os.link(output, tmp_path / "owned-alias.json")
        elif mutation == "content":
            output.chmod(0o644)
            output.write_bytes(b"x" * old.st_size)
            os.utime(output, ns=(old.st_atime_ns, old.st_mtime_ns))
            output.chmod(0o444)
        else:
            output.chmod(0o644)

    monkeypatch.setattr(E, "recheck_opened", replace_after_input_check)
    with pytest.raises((safeio.UnsafeFile, FileNotFoundError)):
        store(analysis_case, event="timeline")
    assert [e["event"] for e in log.entries()] == ["intake"]
    assert foreign.read_bytes() == b"synthetic unrelated file"
    if mutation == "regular":
        assert output.read_bytes() == b"replacement"
    elif mutation == "symlink":
        assert output.is_symlink()
    elif mutation == "foreign-hardlink":
        assert safeio.same_file(output.stat(), foreign.stat())
    else:
        assert not output.exists(), "자기가 만든 파일 이름만 실패 정리한다"
    if mutation in ("regular", "symlink", "foreign-hardlink", "missing"):
        assert safeio.same_file((tmp_path / "original.json").stat(), old)
    elif mutation == "own-hardlink":
        assert (tmp_path / "owned-alias.json").exists()


@pytest.mark.parametrize("mutation", ["directory", "symlink"])
def test_analysis_parent_swapped_preserves_replacement(analysis_case, monkeypatch, tmp_path, mutation):
    case, log, opened, report = analysis_case
    recheck = E.recheck_opened
    directory = case.dir / "forensics/analysis"
    moved = case.dir / "forensics/analysis-moved"
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = b"unrelated output directory"

    def replace_parent(*args, **kwargs):
        recheck(*args, **kwargs)
        directory.rename(moved)
        if mutation == "directory":
            directory.mkdir()
        else:
            directory.symlink_to(outside, target_is_directory=True)
        (directory / "foreign.txt").write_bytes(marker)

    monkeypatch.setattr(E, "recheck_opened", replace_parent)
    with pytest.raises((safeio.UnsafeFile, E.EvidenceError)):
        store(analysis_case, event="timeline")
    assert [e["event"] for e in log.entries()] == ["intake"]
    assert not list(moved.iterdir()), "고정한 원래 디렉터리에서 자기 출력만 정리한다"
    assert (directory / "foreign.txt").read_bytes() == marker


def test_analysis_concurrent_distinct_output_does_not_invalidate_directory(analysis_case, monkeypatch):
    case, log, opened, report = analysis_case
    recheck = E.recheck_opened

    def add_other_output(*args, **kwargs):
        recheck(*args, **kwargs)
        (case.dir / "forensics/analysis/other.json").write_bytes(b"synthetic other analysis")

    monkeypatch.setattr(E, "recheck_opened", add_other_output)
    assert store(analysis_case)["ok"]


def test_analysis_input_rechecked_under_same_commit_lock(analysis_case):
    case, log, opened, report = analysis_case
    calls = 0

    def change_input_before_commit():
        nonlocal calls
        calls += 1
        if calls == 2:
            source = case.dir / opened.record["stored"]["path"]
            source.chmod(0o644)
            source.write_bytes(b"changed synthetic source")
            source.chmod(0o444)

    with pytest.raises(E.IntegrityProblem):
        store(analysis_case, check=change_input_before_commit)
    assert outputs(case) == []
    assert [entry["event"] for entry in log.entries()] == ["intake"]


def test_analysis_entries_callback_receives_current_entries_under_lock(analysis_case, monkeypatch):
    case, log, opened, report = analysis_case
    calls = []
    original = E.recheck_opened

    def recheck(*args, **kwargs):
        original(*args, **kwargs)
        calls.append("ev")

    def check_entries(entries):
        assert calls == ["ev"]
        assert [entry["event"] for entry in entries] == ["intake"]
        assert "hash" not in entries[0]
        ffd = E.open_forensics(case)
        try:
            assert safeio.try_lock_at(ffd, E.CUSTODY_LOCK, create=False) is None
        finally:
            os.close(ffd)
        calls.append("entries")

    monkeypatch.setattr(E, "recheck_opened", recheck)
    assert store(analysis_case, event="sd-ioc-scan", check_entries=check_entries)["ok"]
    assert calls == ["ev", "entries"]


def test_analysis_entries_callback_failure_prevents_commit(analysis_case):
    case, log, opened, report = analysis_case

    def reject(entries):
        raise ValidationFailed("합성 목록 사건 불일치")

    with pytest.raises(ValidationFailed):
        store(analysis_case, event="sd-ioc-scan", check_entries=reject)
    assert outputs(case) == []
    assert [entry["event"] for entry in log.entries()] == ["intake"]


def test_analysis_write_failure_does_not_delete_replaced_name(analysis_case, monkeypatch, tmp_path):
    case, log, opened, report = analysis_case
    write = safeio.write_all
    foreign = b"synthetic replacement before seal"
    replaced = None

    def write_then_replace(fd, data):
        nonlocal replaced
        write(fd, data)
        if b'"matches"' not in data:
            return
        replaced, = outputs(case)
        replaced.rename(tmp_path / "owned-original.json")
        replaced.write_bytes(foreign)
        raise OSError("합성 write 실패")

    monkeypatch.setattr(safeio, "write_all", write_then_replace)
    with pytest.raises(OSError):
        store(analysis_case, event="timeline")
    assert replaced.read_bytes() == foreign
    assert [entry["event"] for entry in log.entries()] == ["intake"]


@pytest.mark.parametrize("when", ["before-write", "before-commit"])
def test_analysis_precommit_cancel_discards_only_owned_output(analysis_case, when):
    case, log, opened, report = analysis_case
    calls = 0

    def cancel():
        nonlocal calls
        calls += 1
        if calls == (1 if when == "before-write" else 2):
            raise PwehError("합성 취소", code="cancelled")

    with pytest.raises(PwehError) as error:
        store(analysis_case, check=cancel)
    assert error.value.code == "cancelled"
    assert outputs(case) == []
    assert [e["event"] for e in log.entries()] == ["intake"]


@pytest.mark.parametrize("event", ["secrets_scan", "secrets-scan/other", "sd_ioc_scan", "sd-ioc-scan/other", "media_inventory", "media-inventory/other", "other", "note", "image-hints"])
def test_analysis_unknown_event_stays_closed(analysis_case, event):
    case, log, opened, report = analysis_case
    with pytest.raises(ValidationFailed):
        store(analysis_case, event=event)
    assert E.ANALYSIS_EVENTS == {"sqlite-inventory", "android-artifacts", "timeline", "secrets-scan", "sd-ioc-scan", "media-inventory"}
    if event not in {"note", "image-hints"}:
        with pytest.raises(ValidationFailed):
            log.append(event, evidence_id=opened.evidence_id, data={})
    assert [e["event"] for e in log.entries()] == ["intake"]


@pytest.mark.parametrize("failure", ["audit", "cancel", "index", "late-cancel"])
def test_analysis_postcommit_failure_keeps_output_and_event(analysis_case, monkeypatch, failure):
    case, log, opened, report = analysis_case
    committed = False

    def check():
        if committed:
            pytest.fail("커밋 뒤 취소 검사를 다시 호출했다")

    def on_commit(entry):
        nonlocal committed
        committed = True
        if failure in {"audit", "cancel"}:
            raise PwehError("합성 보조 기록 실패", code="cancelled" if failure == "cancel" else "failed")

    def bad_index(*args, **kwargs):
        raise RuntimeError("합성 색인 오류")

    if failure == "index":
        monkeypatch.setattr(case, "register_artifact", bad_index)
    result = store(analysis_case, check=check, on_commit=on_commit)
    assert result["ok"] and committed
    assert bool(result["warnings"]) is (failure != "late-cancel")
    assert (case.dir / result["analysis"]["path"]).is_file()
    assert log.entries()[-1]["event"] == "secrets-scan"


def test_analysis_postcommit_close_error_keeps_success(analysis_case, monkeypatch):
    case, log, opened, report = analysis_case
    create = safeio.create_excl
    close = os.close
    fd_to_fail = None

    def capture(directory, name, *args, **kwargs):
        nonlocal fd_to_fail
        fd = create(directory, name, *args, **kwargs)
        if name.startswith("secrets-scan-"):
            fd_to_fail = fd
        return fd

    def close_once(fd):
        nonlocal fd_to_fail
        close(fd)
        if fd == fd_to_fail:
            fd_to_fail = None
            raise OSError("합성 close 실패")

    monkeypatch.setattr(safeio, "create_excl", capture)
    monkeypatch.setattr(os, "close", close_once)
    result = store(analysis_case)
    assert result["ok"] and (case.dir / result["analysis"]["path"]).is_file()
    assert log.entries()[-1]["event"] == "secrets-scan"
