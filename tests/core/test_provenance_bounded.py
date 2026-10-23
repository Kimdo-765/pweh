"""기존 원장 형식을 유지하는 선택 bounded read/checked append 회귀."""
from __future__ import annotations

import contextlib
import hashlib
import os
import time

import pytest

from pweh import provenance as P
from pweh.errors import PwehError
from pweh.runtime import get_runtime

SRC = {"server": "synthetic", "tool": "synthetic_fact"}


def options(**kw):
    return {"max_bytes": 16 << 20, "max_entries": 10000, "deadline": time.monotonic() + 5, **kw}


@pytest.fixture
def setup(workspace, auth):
    rt = get_runtime("test")
    case = rt.cases.create(title="제한 원장", authorization=auth, case_id="bounded-ledger")
    return rt.provenance, case


def fact(ledger, case, data=None, **kw):
    return ledger.record_device_fact(case, "synthetic", data or {"value": 1}, SRC, **kw)


@pytest.mark.parametrize("key,value", [("max_bytes", True), ("max_bytes", 0), ("max_bytes", (16 << 20) + 1),
    ("max_bytes", 1.0), ("max_entries", True), ("max_entries", 0), ("max_entries", 10001),
    ("deadline", True), ("deadline", float("inf")), ("deadline", float("nan")), ("deadline", 10 ** 400),
    ("check", True)])
def test_bounded_arguments_are_exact_and_fixed(setup, key, value):
    ledger, case = setup
    with pytest.raises(P.ProvenanceError) as exc:
        ledger.entries(case, **options(**{key: value}))
    assert exc.value.code == "provenance_bounded_invalid"
    assert not ledger.ledger_path(case).exists()


def test_absence_is_read_only_and_valid_chain_equals_legacy(setup):
    ledger, case = setup
    assert ledger.entries(case, **options()) == []
    assert not ledger.dir.exists()
    fact(ledger, case)
    fact(ledger, case, {"value": 2}, **options())
    assert ledger.entries(case, **options()) == ledger.entries(case)


def test_chunk_reads_are_64k_and_bound_applies_before_read(setup, monkeypatch):
    ledger, case = setup
    fact(ledger, case, {"blob": "x" * 150000})
    original = os.pread
    lengths = []
    def watched(fd, count, offset):
        lengths.append(count)
        return original(fd, count, offset)
    monkeypatch.setattr(P.os, "pread", watched)
    assert len(ledger.entries(case, **options())) == 1
    assert len(lengths) >= 3 and max(lengths) <= 65536
    lengths.clear()
    with pytest.raises(P.ProvenanceError) as exc:
        ledger.entries(case, **options(max_bytes=100))
    assert exc.value.code == "provenance_bounded_limit" and lengths == []


def test_entry_and_new_byte_bounds_leave_original_untouched(setup):
    ledger, case = setup
    fact(ledger, case)
    fact(ledger, case)
    path = ledger.ledger_path(case)
    before = path.read_bytes()
    for opts in (options(max_entries=1), options(max_bytes=len(before))):
        with pytest.raises(P.ProvenanceError) as exc:
            fact(ledger, case, **opts)
        assert exc.value.code == "provenance_bounded_limit"
        assert path.read_bytes() == before
    with pytest.raises(P.ProvenanceError):
        ledger.entries(case, **options(max_entries=1))


@pytest.mark.parametrize("limit", ["bytes", "entries"])
def test_production_caps_reject_before_json_read(setup, monkeypatch, limit):
    ledger, case = setup
    ledger._ensure_dir()
    path = ledger.ledger_path(case)
    if limit == "bytes":
        with path.open("wb") as stream:
            stream.truncate((16 << 20) + 1)
        def forbidden(*args): raise AssertionError("크기 초과 파일 읽음")
        monkeypatch.setattr(P.os, "pread", forbidden)
    else:
        path.write_bytes(b"{}\n" * 10001)
        def forbidden(*args, **kwargs): raise AssertionError("항목 초과 JSON 해석")
        monkeypatch.setattr(P.json, "loads", forbidden)
    with pytest.raises(P.ProvenanceError) as exc:
        ledger.entries(case, **options())
    assert exc.value.code == "provenance_bounded_limit"


@pytest.mark.parametrize("mutation", ["grow", "shrink", "same_inode", "name", "parent", "parent_alias", "mode", "hardlink"])
def test_changed_ledger_during_read_is_never_a_snapshot(setup, monkeypatch, tmp_path, mutation):
    ledger, case = setup
    fact(ledger, case, {"blob": "x" * 80000})
    path = ledger.ledger_path(case)
    original = os.pread
    done = [False]
    def changed(fd, count, offset):
        result = original(fd, count, offset)
        if not done[0]:
            done[0] = True
            if mutation == "grow":
                with path.open("ab") as stream: stream.write(b"x")
            elif mutation == "shrink":
                with path.open("r+b") as stream: stream.truncate(10)
            elif mutation == "same_inode":
                with path.open("r+b") as stream: stream.write(b"X")
            elif mutation == "name":
                content = path.read_bytes()
                path.rename(path.with_suffix(".old"))
                path.write_bytes(content)
            elif mutation in ("parent", "parent_alias"):
                old = ledger.dir.with_name("old-ledger")
                ledger.dir.rename(old)
                if mutation == "parent_alias":
                    ledger.dir.symlink_to(old, target_is_directory=True)
                else:
                    ledger.dir.mkdir()
                    path.write_bytes((old / path.name).read_bytes())
            elif mutation == "mode": path.chmod(0o400)
            else: os.link(path, tmp_path / "alias")
        return result
    monkeypatch.setattr(P.os, "pread", changed)
    with pytest.raises(PwehError):
        ledger.entries(case, **options())


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_bounded_leaf_link_rejected_without_changing_legacy(setup, tmp_path, kind):
    ledger, case = setup
    fact(ledger, case)
    path = ledger.ledger_path(case)
    if kind == "symlink":
        target = tmp_path / "copy"
        path.rename(target)
        path.symlink_to(target)
    else:
        os.link(path, tmp_path / "alias")
    with pytest.raises(PwehError): ledger.entries(case, **options())
    assert len(ledger.entries(case)) == 1


@pytest.mark.parametrize("raw", [b"not-json\n", b"{}", b"\xff\n", b"\n", b'{"private":"SENTINEL"}\n'])
def test_broken_chain_not_accepted_under_bounds(setup, raw):
    ledger, case = setup
    ledger._ensure_dir()
    ledger.ledger_path(case).write_bytes(raw)
    with pytest.raises(P.ProvenanceError): ledger.entries(case, **options())
    with pytest.raises(P.ProvenanceError): fact(ledger, case, **options())
    assert ledger.ledger_path(case).read_bytes() == raw


@pytest.mark.parametrize("raw", [b"[" * 33 + b"0" + b"]" * 33 + b"\n", b'{"x":' + b"1" * 129 + b"}\n"])
def test_json_depth_and_numeric_tokens_have_bounded_preflight(setup, raw):
    ledger, case = setup
    ledger._ensure_dir()
    ledger.ledger_path(case).write_bytes(raw)
    with pytest.raises(P.ProvenanceError) as exc:
        ledger.entries(case, **options())
    assert exc.value.code == "provenance_bounded_limit"


@pytest.mark.parametrize("change", ["raise", "return_non_none", "replace_name", "same_inode", "deadline"])
def test_checked_append_last_seal_or_callback_failure_prevents_commit(setup, change):
    ledger, case = setup
    fact(ledger, case)
    path = ledger.ledger_path(case)
    before = path.read_bytes()
    expired = [False]
    def check():
        if expired[0]: raise P.ProvenanceError("취소", code="cancelled")
    def callback(entries):
        assert entries[0]["data"] == {"value": 1}
        if change == "raise": raise P.ProvenanceError("취소", code="cancelled")
        if change == "return_non_none": return False
        if change == "replace_name":
            path.rename(path.with_suffix(".old"))
            path.write_bytes(before)
        elif change == "same_inode":
            with path.open("r+b") as stream: stream.write(b"X")
        else: expired[0] = True
    with pytest.raises(PwehError):
        fact(ledger, case, **options(check=check), check_entries=callback)
    assert path.read_bytes() in (before, b"X" + before[1:])


def test_new_missing_leaf_cannot_be_inserted_during_checked_append(setup):
    ledger, case = setup
    def callback(entries):
        assert entries == []
        ledger.ledger_path(case).write_bytes(b"SENTINEL")
    with pytest.raises(PwehError): fact(ledger, case, **options(), check_entries=callback)
    assert ledger.ledger_path(case).read_bytes() == b"SENTINEL"


def test_callbacks_stop_at_atomic_commit(setup, monkeypatch):
    ledger, case = setup
    original = P.atomic_write_bytes
    committed = [False]
    def check():
        assert not committed[0], "commit 뒤 검사는 기록을 실패로 바꾸면 안 된다"
    def commit(path, data):
        original(path, data)
        committed[0] = True
    monkeypatch.setattr(P, "atomic_write_bytes", commit)
    entry = fact(ledger, case, **options(check=check))
    assert entry["seq"] == 1 and committed[0]
    assert ledger.verify_chain(case)["ok"]


@pytest.mark.parametrize("operation", ["fact", "import"])
def test_committed_bounded_append_returns_receipt_when_read_fd_close_fails(setup, monkeypatch, operation):
    ledger, case = setup
    fact(ledger, case)
    ledger_inode = ledger.ledger_path(case).stat().st_ino
    parent_inode = ledger.dir.stat().st_ino
    original_close = P.os.close
    closed = []
    failed = [False]
    def close(fd):
        inode = os.fstat(fd).st_ino
        original_close(fd)
        closed.append(inode)
        if inode == ledger_inode and not failed[0]:
            failed[0] = True
            raise OSError("SYNTHETIC_CLOSE_PRIVATE")
    monkeypatch.setattr(P.os, "close", close)
    if operation == "fact":
        result = fact(ledger, case, **options())
    else:
        (case.dir / "dumps" / "source.bin").write_bytes(b"synthetic")
        result = ledger.record_import(case, "dumps/source.bin", SRC, **options())
    assert result["seq"] == 2
    assert getattr(result, "warnings", ()) == ("provenance_close_unconfirmed",)
    assert "warnings" not in result
    assert parent_inode in closed[closed.index(ledger_inode) + 1:]
    assert ledger.entries(case)[-1] == result


def test_precommit_failure_attempts_parent_close_even_if_file_close_fails(setup, monkeypatch):
    ledger, case = setup
    fact(ledger, case)
    before = ledger.ledger_path(case).read_bytes()
    file_inode = ledger.ledger_path(case).stat().st_ino
    parent_inode = ledger.dir.stat().st_ino
    original_close = P.os.close
    closed = []
    def close(fd):
        inode = os.fstat(fd).st_ino
        original_close(fd)
        closed.append(inode)
        if inode == file_inode:
            raise OSError("SYNTHETIC_CLOSE_PRIVATE")
    def reject(entries): raise P.ProvenanceError("취소", code="cancelled")
    monkeypatch.setattr(P.os, "close", close)
    with pytest.raises(PwehError) as exc:
        fact(ledger, case, **options(), check_entries=reject)
    assert "SYNTHETIC_CLOSE_PRIVATE" not in str(exc.value)
    assert parent_inode in closed[closed.index(file_inode) + 1:]
    assert ledger.ledger_path(case).read_bytes() == before


def test_lock_budget_uses_remaining_deadline_and_legacy_stays30(setup, monkeypatch):
    ledger, case = setup
    waits = []
    @contextlib.contextmanager
    def lock(path, *, timeout):
        waits.append(timeout)
        yield
    monkeypatch.setattr(P, "file_lock", lock)
    fact(ledger, case)
    fact(ledger, case, **options(deadline=time.monotonic() + 0.5))
    assert waits[0] == 30 and 0 < waits[1] <= 0.5


def test_cancel_during_chunk_read_and_deadline_after_lock_prevent_append(setup, monkeypatch):
    ledger, case = setup
    fact(ledger, case, {"blob": "x" * 80000})
    before = ledger.ledger_path(case).read_bytes()
    reads = [0]
    original = P.os.pread
    def read(*args):
        reads[0] += 1
        return original(*args)
    def check():
        if reads[0]: raise P.ProvenanceError("취소", code="cancelled")
    monkeypatch.setattr(P.os, "pread", read)
    with pytest.raises(P.ProvenanceError) as exc:
        fact(ledger, case, **options(check=check))
    assert exc.value.code == "cancelled"
    assert ledger.ledger_path(case).read_bytes() == before


def test_lock_wait_cannot_extend_shared_deadline(setup, monkeypatch):
    ledger, case = setup
    now = [time.monotonic()]
    deadline = now[0] + 0.5
    @contextlib.contextmanager
    def delayed(path, *, timeout):
        now[0] = deadline + 1
        yield
    monkeypatch.setattr(P, "file_lock", delayed)
    monkeypatch.setattr(P.time, "monotonic", lambda: now[0])
    with pytest.raises(P.ProvenanceError) as exc:
        fact(ledger, case, **options(deadline=deadline))
    assert exc.value.code == "time_limit"
    assert not ledger.ledger_path(case).exists()


def test_bounded_import_rechecks_hash_and_entry_callback(setup):
    ledger, case = setup
    path = case.dir / "dumps" / "synthetic.bin"
    path.write_bytes(b"synthetic")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    seen = []
    entry = ledger.record_import(case, "dumps/synthetic.bin", SRC, sha256=digest,
        **options(), check_entries=lambda entries: seen.append(len(entries)))
    assert seen == [0] and entry["sha256"] == digest and entry["kind"] == "imported-unattested"
    with pytest.raises(PwehError):
        ledger.record_import(case, "dumps/synthetic.bin", SRC, sha256="0" * 64, **options())
    assert len(ledger.entries(case)) == 1
