"""합성 일반 파일의 명시 구간·borrowed fd·초기 seal·재선택 계약만 검증한다."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import os
import stat
import time
from types import SimpleNamespace

import pytest

from forensics_mcp import media_candidate_selection as S
from pweh import evidence as E
from pweh.errors import PwehError

PRIVATE = "SYNTHETIC_PRIVATE_RANGE_51e4"


@pytest.fixture
def opened_file(tmp_path):
    with contextlib.ExitStack() as stack:
        count = 0
        def make(data=b"0123456789" * 20000, *, size=None):
            nonlocal count
            count += 1
            path = tmp_path / (PRIVATE + str(count))
            path.write_bytes(data)
            if size is not None:
                with path.open("r+b") as stream:
                    stream.truncate(size)
            path.chmod(0o444)
            fd = os.open(path, os.O_RDONLY)
            st = os.fstat(fd)
            opened = E.OpenedEvidence(
                evidence_id="EV-0001", record={}, intake={"size": st.st_size,
                "hashes": {"sha256": hashlib.sha256(data).hexdigest()}}, intake_ts=None, fd=fd, st=st)
            stack.enter_context(opened)
            return opened, path
        yield make


def read(opened, offset, length, **kwargs):
    return S.read_candidate_range(opened, offset, length,
                                  **{"deadline": time.monotonic() + 30, "cancel": lambda: False, **kwargs})


def check(opened, source, **kwargs):
    return S.check_candidate_range(opened, source,
                                   **{"deadline": time.monotonic() + 30, "cancel": lambda: False, **kwargs})


@pytest.mark.parametrize(("offset", "length"), [(0, 1), (0, 200000), (11, 150000), (199999, 1)])
def test_exact_chunked_range_and_closed_source(opened_file, monkeypatch, offset, length):
    content = b"0123456789" * 20000
    opened, _ = opened_file(content)
    original, calls = os.pread, []
    def pread(fd, size, pos):
        calls.append((fd, size, pos))
        return original(fd, size, pos)
    monkeypatch.setattr(S.os, "pread", pread)
    data, source = read(opened, offset, length)
    assert data == content[offset:offset + length] and type(data) is bytes
    assert len(source) == 18 and source == {
        "kind": "evidence", "evidence_id": "EV-0001", "evidence_sha256": hashlib.sha256(content).hexdigest(),
        "container": "file", "member_selected": False, "selected_sha256": hashlib.sha256(data).hexdigest(),
        "selected_size": length, "complete": True, "method": "byte-range", "confidence": "high",
        "partition": None, "ref": None, "deleted": None, "parent_deleted": None,
        "container_truncated": None, "container_truncated_reasons": [], "evidence_size": len(content), "offset": offset}
    position = offset
    for fd, size, start in calls:
        assert fd == opened.fd and start == position and 0 < size <= 65536
        position += size
    assert position == offset + length and len(calls) == (length + 65535) // 65536
    assert not opened._closed and os.fstat(opened.fd).st_size == len(content)


def test_large_evidence_does_not_read_outside_explicit_selection(opened_file, monkeypatch):
    opened, path = opened_file(b"", size=(64 << 20) + 100)
    path.chmod(0o644)
    with path.open("r+b") as stream:
        stream.seek((64 << 20) + 12)
        stream.write(b"RANGE")
    path.chmod(0o444)
    opened.st = os.fstat(opened.fd)
    original, calls = os.pread, []
    def pread(fd, size, offset):
        calls.append((size, offset))
        return original(fd, size, offset)
    monkeypatch.setattr(S.os, "pread", pread)
    data, source = read(opened, (64 << 20) + 12, 5)
    assert data == b"RANGE" and calls == [(5, (64 << 20) + 12)]
    assert source["evidence_size"] > 64 << 20


def test_reader_and_check_never_close_seek_or_reopen_borrowed_fd(opened_file, monkeypatch):
    opened, _ = opened_file()
    with monkeypatch.context() as scoped:
        for name in ("open", "close", "dup", "lseek"):
            scoped.setattr(S.os, name, lambda *a, **k: pytest.fail("borrowed fd 소유권 변경"))
        _, source = read(opened, 3, 20)
        scoped.setattr(S.os, "pread", lambda *a: pytest.fail("seal 확인 중 재읽기"))
        check(opened, source)
    assert os.fstat(opened.fd).st_size == 200000


@pytest.mark.parametrize(("offset", "length", "code"), [
    (True, 1, "media_prefix_input_invalid"), (0, True, "media_prefix_input_invalid"),
    (0.0, 1, "media_prefix_input_invalid"), (0, 1.0, "media_prefix_input_invalid"),
    ("0", 1, "media_prefix_input_invalid"), (0, "1", "media_prefix_input_invalid"),
    (-1, 1, "media_prefix_input_invalid"), (0, 0, "media_prefix_input_invalid"),
    (0, -1, "media_prefix_input_invalid"), (10**400, 1, "media_prefix_input_invalid"),
    (S.MAX_RANGE_END, 1, "media_prefix_input_invalid"), (0, 10**400, "media_prefix_input_invalid"),
    (0, (64 << 20) + 1, "media_prefix_input_limit"), (199999, 2, "media_prefix_input_invalid"),
    (200000, 1, "media_prefix_input_invalid"),
])
def test_bad_range_rejected_before_pread(opened_file, monkeypatch, offset, length, code):
    opened, _ = opened_file()
    monkeypatch.setattr(S.os, "pread", lambda *a: pytest.fail("잘못된 구간 읽기"))
    with pytest.raises(PwehError) as exc:
        read(opened, offset, length)
    assert exc.value.code == code and not exc.value.data


@pytest.mark.parametrize("bad", [True, None, "time", float("nan"), float("inf"), 10**400])
def test_bad_deadline_is_fixed_before_read(opened_file, monkeypatch, bad):
    opened, _ = opened_file()
    monkeypatch.setattr(S.os, "pread", lambda *a: pytest.fail("잘못된 마감 뒤 읽기"))
    with pytest.raises(PwehError) as exc:
        read(opened, 0, 1, deadline=bad)
    assert exc.value.code == "media_prefix_input_invalid"


@pytest.mark.parametrize("value", [None, 0, 1, PRIVATE])
def test_cancel_callback_requires_exact_bool(opened_file, value):
    opened, _ = opened_file()
    with pytest.raises(PwehError) as exc:
        read(opened, 0, 1, cancel=lambda: value)
    assert exc.value.code == "media_prefix_input_invalid" and PRIVATE not in str(exc.value)


def test_callback_exception_has_no_raw_context(opened_file):
    opened, _ = opened_file()
    def fail():
        raise ValueError(PRIVATE)
    with pytest.raises(PwehError) as exc:
        read(opened, 0, 1, cancel=fail)
    assert exc.value.code == "media_prefix_input_invalid"
    assert PRIVATE not in str(exc.value) and exc.value.__suppress_context__


@pytest.mark.parametrize("short", [b"", b"short", bytearray(b"x" * 100)])
def test_short_or_nonbytes_read_never_trims_success(opened_file, monkeypatch, short):
    opened, _ = opened_file()
    monkeypatch.setattr(S.os, "pread", lambda *a: short)
    with pytest.raises(PwehError) as exc:
        read(opened, 0, 100)
    assert exc.value.code == "media_prefix_input_changed"


@pytest.mark.parametrize(("field", "value"), [
    ("st_dev", -1), ("st_ino", -1), ("st_size", 199999), ("st_mtime_ns", -1),
    ("st_ctime_ns", -1), ("st_mode", stat.S_IFREG | 0o644), ("st_nlink", 2),
    ("st_mode", stat.S_IFIFO | 0o444),
])
def test_final_check_binds_all_initial_fd_seal_fields(opened_file, monkeypatch, field, value):
    opened, _ = opened_file()
    _, source = read(opened, 0, 20)
    names = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_nlink")
    after = SimpleNamespace(**{name: getattr(opened.st, name) for name in names})
    setattr(after, field, value)
    monkeypatch.setattr(S.os, "fstat", lambda fd: after)
    with pytest.raises(E.IntegrityProblem) as exc:
        check(opened, source)
    assert exc.value.record and exc.value.reason == "source-changed"


def test_same_size_modification_during_read_is_integrity_failure(opened_file, monkeypatch):
    opened, path = opened_file()
    original = os.pread
    changed = False
    def pread(fd, size, offset):
        nonlocal changed
        data = original(fd, size, offset)
        if not changed:
            changed = True
            path.chmod(0o644)
            with path.open("r+b") as stream:
                stream.seek(100000)
                stream.write(b"X")
            path.chmod(0o444)
            os.utime(path, ns=(opened.st.st_atime_ns, opened.st.st_mtime_ns + 10**9))
        return data
    monkeypatch.setattr(S.os, "pread", pread)
    with pytest.raises(E.IntegrityProblem):
        read(opened, 0, 150000)


@pytest.mark.parametrize("signal", ["cancelled", "timeout"])
def test_read_checks_after_each_chunk_without_new_deadline(opened_file, monkeypatch, signal):
    opened, _ = opened_file()
    original, now, stopped, calls = os.pread, 0, False, 0
    def pread(fd, size, offset):
        nonlocal now, stopped, calls
        calls += 1
        result = original(fd, size, offset)
        now, stopped = 2, signal == "cancelled"
        return result
    monkeypatch.setattr(S.os, "pread", pread)
    monkeypatch.setattr(S.time, "monotonic", lambda: now)
    with pytest.raises(PwehError) as exc:
        read(opened, 0, 150000, deadline=1, cancel=lambda: stopped)
    assert exc.value.code == signal and calls == 1


def test_partial_finalize_ignores_expiry_but_not_cancel_or_seal(opened_file, monkeypatch):
    opened, _ = opened_file()
    _, source = read(opened, 0, 20)
    monkeypatch.setattr(S.os, "pread", lambda *a: pytest.fail("마감 seal은 재해시하지 않음"))
    check(opened, source, deadline=0, time_limit=False)
    with pytest.raises(PwehError) as exc:
        check(opened, source, deadline=0)
    assert exc.value.code == "timeout"
    with pytest.raises(PwehError) as exc:
        check(opened, source, deadline=0, time_limit=False, cancel=lambda: True)
    assert exc.value.code == "cancelled"
    os.fchmod(opened.fd, 0o644)
    with pytest.raises(E.IntegrityProblem):
        check(opened, source, deadline=0, time_limit=False)


@pytest.mark.parametrize(("field", "value"), [
    ("offset", True), ("selected_size", 20.0), ("evidence_size", True), ("evidence_size", 19),
    ("kind", PRIVATE), ("container", "filesystem"), ("method", "whole-file"), ("confidence", "low"),
    ("complete", 1), ("member_selected", 0), ("partition", 1), ("ref", "root/0"),
    ("deleted", False), ("parent_deleted", False), ("container_truncated", False),
    ("container_truncated_reasons", ()), ("selected_sha256", PRIVATE), ("evidence_sha256", "b" * 64),
    ("evidence_id", "EV-0002"), ("raw", PRIVATE),
])
def test_closed_source_and_range_identity(opened_file, field, value):
    opened, _ = opened_file()
    _, source = read(opened, 0, 20)
    source[field] = value
    with pytest.raises(PwehError) as exc:
        check(opened, source)
    assert PRIVATE not in str(exc.value) and not exc.value.data


def test_reselect_uses_same_complete_range_and_source_not_fs_or_scanner(opened_file, monkeypatch):
    opened, _ = opened_file()
    expected, source = read(opened, 11, 80000)
    candidate = SimpleNamespace(source=copy.deepcopy(source))
    monkeypatch.setattr(S.fsops, "read_selected_file", lambda *a, **k: pytest.fail("range의 FS 선택 금지"))
    import pweh.media_candidates as scanner
    monkeypatch.setattr(scanner, "scan_bmff_candidates", lambda *a, **k: pytest.fail("후보 재탐색 금지"))
    data, fresh = S.reselect_candidate_source(opened, candidate, deadline=time.monotonic() + 30, cancel=lambda: False)
    assert data == expected and fresh == source == candidate.source and fresh is not candidate.source


def test_reselect_compares_whole_selected_sha_independently(opened_file, monkeypatch):
    opened, _ = opened_file()
    _, source = read(opened, 0, 100)
    source["selected_sha256"] = "f" * 64
    with pytest.raises(PwehError) as exc:
        S.reselect_candidate_source(opened, SimpleNamespace(source=source), deadline=time.monotonic() + 30,
                                     cancel=lambda: False)
    assert exc.value.code == "media_prefix_input_changed"
