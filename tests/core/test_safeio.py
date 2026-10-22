"""pweh.safeio — 믿을 수 없는 파일을 안전하게 여는 도구 (장치·FIFO·링크를 열지 않음, fd 로만 읽기, 링크를 따르지 않는 디렉터리·생성)."""

from __future__ import annotations

import hashlib
import os
import threading
import time

import pytest

from pweh import safeio
from pweh.errors import PwehError, ValidationFailed


def test_open_regular_reads_through_the_fd(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"0123456789")
    fd, st = safeio.open_regular(p)
    try:
        assert st.st_size == 10 and safeio.read_fd(fd, 4, offset=3) == b"3456"
        assert safeio.fd_real_path(fd) == str(p.resolve())
        assert os.get_blocking(fd)  # 연 뒤에는 O_NONBLOCK 을 끈다
    finally:
        os.close(fd)


@pytest.mark.parametrize("kind", ["symlink", "fifo", "dir", "dangling"])
def test_open_regular_refuses_non_regular_without_opening(tmp_path, kind):
    target = tmp_path / "real.bin"
    target.write_bytes(b"x")
    p = tmp_path / "p"
    if kind == "symlink":
        p.symlink_to(target)
    elif kind == "fifo":
        os.mkfifo(p)
    elif kind == "dir":
        p.mkdir()
    else:
        p.symlink_to(tmp_path / "missing")
    t0 = time.monotonic()
    with pytest.raises(safeio.UnsafeFile):
        safeio.open_regular(p)
    assert time.monotonic() - t0 < 2  # FIFO 를 열고 기다리지 않는다


def test_open_regular_detects_swap_between_lstat_and_open(tmp_path, monkeypatch):
    """lstat 은 일반 파일이었는데 연 객체가 FIFO 인 경우(바꿔치기) — O_NONBLOCK 이라 기다리지 않고 fstat 대조로 거부한다."""
    reg = tmp_path / "reg.bin"
    reg.write_bytes(b"data")
    fifo = tmp_path / "f"
    os.mkfifo(fifo)
    real_lstat = os.lstat
    monkeypatch.setattr(safeio.os, "lstat", lambda path, dir_fd=None: real_lstat(reg) if os.fspath(path) == "f" else real_lstat(path, dir_fd=dir_fd))
    t0 = time.monotonic()
    with pytest.raises(safeio.UnsafeFile, match="바뀌었습니다"):
        safeio.open_regular(fifo)
    assert time.monotonic() - t0 < 2


def test_open_regular_intermediate_dir_swap_keeps_original_fd(tmp_path, monkeypatch):
    """중간 이름을 FIFO 쪽 링크로 바꿔도 원래 디렉터리 fd 에서 일반 파일만 연다."""
    src = tmp_path / "src"
    sub, alt = src / "sub", src / "alt"
    sub.mkdir(parents=True)
    alt.mkdir()
    (sub / "card.img").write_bytes(b"x" * 10)
    os.mkfifo(alt / "card.img")  # 장치 대신 FIFO (장치 노드는 만들지도 열지도 않는다)
    real_lstat = os.lstat
    armed = [True]

    def lstat_then_swap(path, *, dir_fd=None):
        st = real_lstat(path, dir_fd=dir_fd)
        if armed[0] and os.fspath(path).endswith("card.img"):
            armed[0] = False
            os.rename(sub, src / "sub.orig")
            os.symlink(alt, sub)  # 중간 디렉터리 바꿔치기
        return st

    monkeypatch.setattr(safeio.os, "lstat", lstat_then_swap)
    t0 = time.monotonic()
    fd, st = safeio.open_regular(sub / "card.img")
    try:
        assert safeio.read_fd(fd, 10) == b"x" * 10 and st.st_size == 10
    finally:
        os.close(fd)
    assert time.monotonic() - t0 < 2 and not armed[0]
    monkeypatch.setattr(safeio.os, "lstat", real_lstat)
    os.unlink(sub)
    os.rename(src / "sub.orig", sub)
    dfd = safeio.open_dir_chain(src, ["sub"])
    try:
        armed[0] = True
        monkeypatch.setattr(safeio.os, "lstat", lstat_then_swap)
        fd, st = safeio.open_regular("card.img", dir_fd=dfd)  # 같은 바꿔치기가 일어나도 원래 디렉터리의 일반 파일을 연다
        monkeypatch.setattr(safeio.os, "lstat", real_lstat)
        try:
            assert not armed[0] and st.st_size == 10 and safeio.read_fd(fd, 10) == b"x" * 10
        finally:
            os.close(fd)
    finally:
        os.close(dfd)


def test_open_regular_expect_and_nul(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.write_bytes(b"aaaa")
    b.write_bytes(b"bbbb")
    sta = os.stat(a)
    fd, _ = safeio.open_regular(a, expect=sta)
    os.close(fd)
    with pytest.raises(safeio.UnsafeFile, match="검증한 파일과 다릅니다"):
        safeio.open_regular(b, expect=sta)
    a.write_bytes(b"aaaaa")  # 같은 inode, 크기만 바뀜
    with pytest.raises(safeio.UnsafeFile):
        safeio.open_regular(a, expect=sta)
    with pytest.raises(ValidationFailed):
        safeio.open_regular(str(a) + "\x00x")
    with pytest.raises(FileNotFoundError):
        safeio.open_regular(tmp_path / "none")


def test_read_regular_caps_size(tmp_path):
    p = tmp_path / "log.txt"
    p.write_bytes(b"x" * 100)
    assert safeio.read_regular(p, max_bytes=100) == b"x" * 100
    with pytest.raises(ValidationFailed, match="너무 큽니다"):
        safeio.read_regular(p, max_bytes=99)


def test_hash_fd_reads_exactly_the_validated_size_and_copies(tmp_path):
    data = os.urandom(3 * 1024 * 1024 + 17)
    p = tmp_path / "img"
    p.write_bytes(data)
    fd, st = safeio.open_regular(p)
    out = tmp_path / "copy"
    ofd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    seen = []
    try:
        with open(p, "ab") as fh:
            fh.write(b"appended later")  # 확인한 크기 뒤에 자란 부분은 읽지 않는다
        h = safeio.hash_fd(fd, st.st_size, out_fd=ofd, progress=lambda d, t: seen.append(d))
    finally:
        os.close(fd)
        os.close(ofd)
    assert h == {"sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest()}
    assert out.read_bytes() == data and seen[-1] == len(data)


def test_hash_fd_shrink_and_check(tmp_path):
    p = tmp_path / "img"
    p.write_bytes(b"y" * (2 << 20))
    fd, st = safeio.open_regular(p)
    try:
        os.truncate(p, 1 << 20)
        with pytest.raises(safeio.UnsafeFile, match="줄어들었습니다"):
            safeio.hash_fd(fd, st.st_size)

        class Stop(Exception):
            pass

        def check():
            raise Stop

        with pytest.raises(Stop):
            safeio.hash_fd(fd, 10, check=check)
    finally:
        os.close(fd)


def test_open_dir_chain_refuses_links_and_creates(tmp_path):
    base = tmp_path / "case"
    base.mkdir()
    fd = safeio.open_dir_chain(base, ["forensics", "images"], create=True)
    os.close(fd)
    assert (base / "forensics" / "images").is_dir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (base / "forensics" / "recovered").symlink_to(outside)
    with pytest.raises(safeio.UnsafeFile):
        safeio.open_dir_chain(base, ["forensics", "recovered"], create=True)
    (base / "forensics" / "file").write_bytes(b"")
    with pytest.raises(safeio.UnsafeFile):
        safeio.open_dir_chain(base, ["forensics", "file"])
    for bad in ("..", ".", "a/b", ""):
        with pytest.raises(safeio.UnsafeFile):
            safeio.open_dir_chain(base, [bad])
    with pytest.raises(FileNotFoundError):
        safeio.open_dir_chain(base, ["forensics", "analysis"])
    assert not any(outside.iterdir())


def test_create_excl_never_follows_or_overwrites(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep")
    (d / "manifest.json").symlink_to(victim)
    dfd = safeio.open_dir_chain(d)
    try:
        with pytest.raises(FileExistsError):
            safeio.create_excl(dfd, "manifest.json")
        fd = safeio.create_excl(dfd, "new.json", 0o600)
        safeio.write_all(fd, b"{}")
        os.fchmod(fd, 0o444)
        os.close(fd)
    finally:
        os.close(dfd)
    assert victim.read_text() == "keep" and (d / "new.json").read_bytes() == b"{}"
    assert (d / "new.json").stat().st_mode & 0o777 == 0o444


def test_open_regular_does_not_block_on_fifo_without_writer(tmp_path):
    """FIFO 앞에서 서버 스레드가 멈추지 않는다 (쓰는 쪽이 없어도 즉시 거부)."""
    fifo = tmp_path / "card.img"
    os.mkfifo(fifo)
    done = threading.Event()
    err: list[BaseException] = []

    def run():
        try:
            safeio.open_regular(fifo)
        except BaseException as exc:  # noqa: BLE001
            err.append(exc)
        done.set()

    threading.Thread(target=run, daemon=True).start()
    assert done.wait(3) and isinstance(err[0], safeio.UnsafeFile)


def test_is_under():
    assert safeio.is_under("/a/b/c", "/a/b") and safeio.is_under("/a/b", "/a/b")
    assert not safeio.is_under("/a/bc", "/a/b") and not safeio.is_under("/a", "/a/b")


def test_write_new_and_atomic_write_at_never_follow_links(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep")
    (d / "manifest.json").symlink_to(victim)
    (d / "custody.jsonl").symlink_to(victim)
    dfd = safeio.open_dir_chain(d)
    try:
        with pytest.raises(FileExistsError):
            safeio.write_new(dfd, "manifest.json", b"{}")
        safeio.write_new(dfd, "new.json", b"{}", final_mode=0o444)
        # 원자적 바꿔 쓰기는 링크를 따라 쓰지 않고 디렉터리 항목 자체를 바꾼다
        safeio.atomic_write_at(dfd, "custody.jsonl", b"line\n", 0o600)
    finally:
        os.close(dfd)
    assert victim.read_text() == "keep"
    assert (d / "new.json").read_bytes() == b"{}" and (d / "new.json").stat().st_mode & 0o777 == 0o444
    assert not (d / "custody.jsonl").is_symlink() and (d / "custody.jsonl").read_bytes() == b"line\n"
    assert (d / "custody.jsonl").stat().st_mode & 0o777 == 0o600
    assert sorted(p.name for p in d.iterdir()) == ["custody.jsonl", "manifest.json", "new.json"]  # 임시 파일이 남지 않는다


def test_locks_shared_exclusive_and_try_lock(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    dfd = safeio.open_dir_chain(d)
    try:
        with safeio.locked_at(dfd, ".lock", shared=True):
            with safeio.locked_at(dfd, ".lock", shared=True, timeout=1):  # 공유 잠금끼리는 함께 잡힌다
                pass
            with pytest.raises(PwehError, match="시간 초과"):
                with safeio.locked_at(dfd, ".lock", timeout=0.2):  # 배타 잠금은 기다리다 시간 초과
                    pass
        held = safeio.try_lock_at(dfd, ".lock")
        assert held is not None
        try:
            assert safeio.try_lock_at(dfd, ".lock") is None  # 다른 쪽이 잡고 있음(같은 프로세스의 다른 열기도 막힌다)
        finally:
            os.close(held)
        with pytest.raises(FileNotFoundError):
            safeio.try_lock_at(dfd, "missing.lock")
        os.mkfifo(d / "fifo.lock")
        t0 = time.monotonic()
        with pytest.raises(safeio.UnsafeFile):
            safeio.try_lock_at(dfd, "fifo.lock")
        assert time.monotonic() - t0 < 2
    finally:
        os.close(dfd)


def test_remove_dir_at_removes_without_following_links(tmp_path):
    parent = tmp_path / "p"
    out = parent / "out-001"
    out.mkdir(parents=True)
    victim = tmp_path / "victim.bin"
    victim.write_bytes(b"keep")
    (out / "0001-a.mp4").write_bytes(b"x")
    os.chmod(out / "0001-a.mp4", 0o444)
    (out / "link").symlink_to(victim)
    os.chmod(out, 0o555)
    pfd = safeio.open_dir_chain(parent)
    try:
        assert safeio.remove_dir_at(pfd, "out-001") == []
        assert safeio.remove_dir_at(pfd, "out-001") == []  # 이미 없으면 그대로
    finally:
        os.close(pfd)
    assert not out.exists() and victim.read_bytes() == b"keep"


def test_path_alias_compatibility_and_relative_fd_boundary(tmp_path):
    """일반 경로의 기존 디렉터리 별칭은 유지하되 dir_fd 아래 링크·상위 이동은 거부한다."""
    base = tmp_path / "real"
    (base / "sub").mkdir(parents=True)
    (base / "sub" / "data").write_bytes(b"synthetic")
    (tmp_path / "alias").symlink_to("real", target_is_directory=True)
    (tmp_path / "absolute").symlink_to(base, target_is_directory=True)
    for alias in ("alias", "absolute"):
        assert safeio.read_regular(tmp_path / alias / "sub" / "data", max_bytes=20) == b"synthetic"
    fd = safeio.open_dir_chain(tmp_path)
    try:
        assert safeio.read_regular("real/sub/data", dir_fd=fd, max_bytes=20) == b"synthetic"
        for bad in ("alias/sub/data", "../real/sub/data", str(base / "sub" / "data")):
            with pytest.raises(safeio.UnsafeFile):
                safeio.open_regular(bad, dir_fd=fd)
    finally:
        os.close(fd)


@pytest.mark.parametrize("replacement", ["symlink", "directory"])
def test_directory_swap_before_open_never_opens_final_file(tmp_path, monkeypatch, replacement):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "data").write_bytes(b"original")
    other = tmp_path / "other"
    other.mkdir()
    os.mkfifo(other / "data")
    real_lstat, real_open = os.lstat, os.open
    seen = []
    def changing_lstat(name, *, dir_fd=None):
        st = real_lstat(name, dir_fd=dir_fd)
        if name == "sub":
            sub.rename(tmp_path / "original")
            if replacement == "symlink":
                sub.symlink_to(other, target_is_directory=True)
            else:
                sub.mkdir()
        return st
    def opening(name, flags, *args, **kwargs):
        if name == "data":
            seen.append(name)
        return real_open(name, flags, *args, **kwargs)
    monkeypatch.setattr(safeio.os, "lstat", changing_lstat)
    monkeypatch.setattr(safeio.os, "open", opening)
    with pytest.raises(safeio.UnsafeFile, match="바뀌었습니다"):
        safeio.open_regular(sub / "data")
    assert seen == []


def test_directory_resolution_bounds_and_no_fd_leak(tmp_path, monkeypatch):
    (tmp_path / "loop").symlink_to("loop", target_is_directory=True)
    initial = len(os.listdir("/proc/self/fd"))
    with pytest.raises(safeio.UnsafeFile, match="상한"):
        safeio.open_regular(tmp_path / "loop" / "data")
    with pytest.raises(safeio.UnsafeFile, match="길이 상한"):
        safeio.open_regular("a" * (safeio.PATH_MAX_BYTES + 1))
    monkeypatch.setattr(safeio, "PATH_MAX_STEPS", 2)
    with pytest.raises(safeio.UnsafeFile, match="상한"):
        safeio.open_regular(tmp_path / "a" / "b" / "c")
    monkeypatch.setattr(safeio, "PATH_MAX_STEPS", 256)
    clock = iter((0., 10.))
    monkeypatch.setattr(safeio.time, "monotonic", lambda: next(clock))
    with pytest.raises(safeio.UnsafeFile, match="시간 상한"):
        safeio.open_regular(tmp_path / "data")
    assert len(os.listdir("/proc/self/fd")) == initial


def test_hardlink_rejection_is_opt_in_and_precedes_file_open(tmp_path, monkeypatch):
    p = tmp_path / "source"
    p.write_bytes(b"synthetic")
    os.link(p, tmp_path / "alias")
    assert safeio.read_regular(p, max_bytes=20) == b"synthetic"
    real_open = os.open
    seen = []
    def opening(name, flags, *args, **kwargs):
        if name == "source":
            seen.append(name)
        return real_open(name, flags, *args, **kwargs)
    monkeypatch.setattr(safeio.os, "open", opening)
    with pytest.raises(safeio.UnsafeFile, match="하드 링크"):
        safeio.read_regular(p, max_bytes=20, reject_hardlinks=True)
    assert seen == []


@pytest.mark.parametrize("reply", [b"/private/tmp/board.bin\0", b"relative.bin\0", b"\0", b"x" * 1024, None])
def test_fd_real_path_darwin_fixed_buffer(tmp_path, monkeypatch, reply):
    """Darwin F_GETPATH 는 고정 1024바이트 버퍼를 사용하며 오류·상대·잘린 결과를 신뢰하지 않는다."""
    from types import SimpleNamespace

    p = tmp_path / "source"
    p.write_bytes(b"synthetic")
    fd = os.open(p, os.O_RDONLY)
    calls = []

    def getpath(got_fd, command, buffer):
        calls.append((got_fd, command, buffer))
        if reply is None:
            raise OSError("합성 F_GETPATH 실패")
        return reply

    monkeypatch.setattr(safeio, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(safeio.fcntl, "fcntl", getpath)
    try:
        assert safeio.fd_real_path(fd) == ("/private/tmp/board.bin" if reply == b"/private/tmp/board.bin\0" else None)
        assert calls == [(fd, getattr(safeio.fcntl, "F_GETPATH", 50), bytes(1024))]
        p.unlink()
        assert safeio.fd_real_path(fd) is None
        assert len(calls) == 1
    finally:
        os.close(fd)


def test_hardlink_created_between_lstat_and_open_is_rejected(tmp_path, monkeypatch):
    p = tmp_path / "source"
    p.write_bytes(b"synthetic")
    real_open = os.open
    def opening(name, flags, *args, **kwargs):
        if name == "source":
            os.link(p, tmp_path / "alias")
        return real_open(name, flags, *args, **kwargs)
    monkeypatch.setattr(safeio.os, "open", opening)
    initial = len(os.listdir("/proc/self/fd"))
    with pytest.raises(safeio.UnsafeFile, match="하드 링크"):
        safeio.open_regular(p, reject_hardlinks=True)
    assert len(os.listdir("/proc/self/fd")) == initial


def test_read_regular_rejects_hardlink_added_during_read(tmp_path, monkeypatch):
    p = tmp_path / "source"
    p.write_bytes(b"synthetic")
    original = safeio.read_fd
    def read_then_link(*args, **kwargs):
        data = original(*args, **kwargs)
        os.link(p, tmp_path / "alias")
        return data
    monkeypatch.setattr(safeio, "read_fd", read_then_link)
    with pytest.raises(safeio.UnsafeFile, match="하드 링크"):
        safeio.read_regular(p, max_bytes=20, reject_hardlinks=True)
