"""가져오기 원본 fd 고정·하드 링크 거부·대상 정리 경합의 합성 시험."""

import hashlib
import os
import stat

import pytest

from pweh import safeio
from pweh.errors import ValidationFailed
from pweh.runtime import get_runtime


@pytest.fixture
def case(workspace, auth):
    return get_runtime("test").cases.create(title="합성 가져오기", authorization=auth, case_id="import-fd")


def test_import_keeps_source_fd_and_original_metadata_after_name_swap(case, tmp_path, monkeypatch):
    source = tmp_path / "firmware.bin"
    source.write_bytes(b"PWEH SYNTHETIC original")
    source.chmod(0o640)
    os.utime(source, ns=(1_000_000_000, 2_000_000_000))
    original = source.read_bytes()
    old_stat = source.stat()
    real_hash = safeio.hash_fd

    def swap(fd, size, **kwargs):
        source.rename(tmp_path / "original.bin")
        source.write_bytes(b"PWEH SYNTHETIC replacement")
        source.chmod(0o600)
        return real_hash(fd, size, **kwargs)

    monkeypatch.setattr(safeio, "hash_fd", swap)
    artifact = case.import_file(source, "dumps", kind="firmware-image", producer="test")
    copied = case.dir / artifact["path"]
    assert copied.read_bytes() == original
    assert artifact["sha256"] == hashlib.sha256(original).hexdigest()
    assert artifact["size"] == len(original)
    assert stat.S_IMODE(copied.stat().st_mode) == 0o640
    assert copied.stat().st_mtime_ns == old_stat.st_mtime_ns


def test_import_borrows_checked_fd_without_reopening_or_moving_cursor(case, tmp_path):
    source = tmp_path / "firmware.bin"
    source.write_bytes(b"PWEH SYNTHETIC checked source")
    fd, _ = safeio.open_regular(source, reject_hardlinks=True)
    try:
        os.lseek(fd, 7, os.SEEK_SET)
        source.rename(tmp_path / "original.bin")
        os.mkfifo(source)
        artifact = case.import_file(source, "dumps", kind="other", producer="test", source_fd=fd)
        assert (case.dir / artifact["path"]).read_bytes() == b"PWEH SYNTHETIC checked source"
        assert os.lseek(fd, 0, os.SEEK_CUR) == 7
    finally:
        os.close(fd)


@pytest.mark.parametrize("kind", ["hardlink", "fifo"])
def test_import_refuses_non_unique_or_special_source_before_copy(case, tmp_path, kind):
    source = tmp_path / "source.bin"
    if kind == "fifo":
        os.mkfifo(source)
    else:
        source.write_bytes(b"PWEH SYNTHETIC linked")
        os.link(source, tmp_path / "alias.bin")
    with pytest.raises(ValidationFailed):
        case.import_file(source, "dumps", kind="other", producer="test")
    assert list((case.dir / "dumps").iterdir()) == []
    assert case.artifacts() == []


def test_import_keeps_source_symlink_alias_compatibility(case, tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"PWEH SYNTHETIC alias")
    alias = tmp_path / "alias.bin"
    alias.symlink_to(source)
    artifact = case.import_file(alias, "dumps", kind="other", producer="test")
    assert artifact["path"] == "dumps/source.bin"
    assert (case.dir / artifact["path"]).read_bytes() == source.read_bytes()


def test_import_changed_source_removes_partial_output(case, tmp_path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"PWEH SYNTHETIC original")
    real_hash = safeio.hash_fd

    def grow(fd, size, **kwargs):
        with source.open("ab") as stream:
            stream.write(b"changed")
        return real_hash(fd, size, **kwargs)

    monkeypatch.setattr(safeio, "hash_fd", grow)
    with pytest.raises(safeio.UnsafeFile, match="복사 중"):
        case.import_file(source, "dumps", kind="other", producer="test")
    assert list((case.dir / "dumps").iterdir()) == []
    assert case.artifacts() == []


def test_import_cleanup_never_unlinks_replacement(case, tmp_path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"PWEH SYNTHETIC source")
    dest = case.dir / "dumps/source.bin"

    def fail_after_swap(fd, size, **kwargs):
        dest.rename(case.dir / "dumps/original.bin")
        dest.write_bytes(b"PWEH SYNTHETIC replacement")
        raise OSError("합성 복사 실패")

    monkeypatch.setattr(safeio, "hash_fd", fail_after_swap)
    with pytest.raises(OSError, match="합성 복사 실패"):
        case.import_file(source, "dumps", kind="other", producer="test")
    assert dest.read_bytes() == b"PWEH SYNTHETIC replacement"
    assert case.artifacts() == []
