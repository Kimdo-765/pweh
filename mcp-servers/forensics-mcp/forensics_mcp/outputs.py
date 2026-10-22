"""보관 기록 커밋 전 생성 파일·디렉터리 이름을 열린 객체와 대조한다."""

from __future__ import annotations

import os
import stat
from typing import Any

from pweh import evidence as E
from pweh import safeio


def _identity(st: os.stat_result) -> tuple[int, ...]:
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def seal_file(directory: int, name: str, fd: int) -> os.stat_result:
    """쓴 fd의 최종 신원을 메모리에 보존한다. inode 등 호스트 값은 산출물에 쓰지 않는다."""
    saved = os.fstat(fd)
    check_file(directory, name, saved)
    return saved


def check_file(directory: int, name: str, saved: os.stat_result) -> None:
    """심볼릭·하드 링크, 이름 교체와 쓰기 이후 변경을 거부한다."""
    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1 or
            _identity(saved) != _identity(current) or current.st_mode & 0o222):
        raise safeio.UnsafeFile(f"만든 출력 파일이 기록 전에 바뀌었습니다: {name}")


def write_sealed(directory: int, name: str, data: bytes) -> os.stat_result:
    """새 매니페스트를 쓰고 그 파일의 열린 fd에서 최종 신원을 얻는다."""
    fd = safeio.create_excl(directory, name, 0o600)
    try:
        safeio.write_all(fd, data)
        os.fchmod(fd, 0o444)
        os.fsync(fd)
        return seal_file(directory, name, fd)
    finally:
        os.close(fd)


def check_root(case: Any, sub: str, directory: int) -> None:
    """기록할 케이스 상대 경로가 아직 작성에 사용한 디렉터리인지 확인한다."""
    current = E.open_forensics(case, sub)
    try:
        if not safeio.same_file(os.fstat(current), os.fstat(directory)):
            raise safeio.UnsafeFile("출력 디렉터리가 기록 전에 바뀌었습니다.")
    finally:
        os.close(current)


def discard_file(directory: int, name: str, fd: int) -> None:
    """실패한 작성의 파일만 지운다. 이름 자리에 바뀌어 들어온 객체는 남긴다."""
    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if safeio.same_file(current, os.fstat(fd)):
        os.unlink(name, dir_fd=directory)


def check_tree(case: Any, parent: int, name: str, directory: int,
               seals: dict[str, os.stat_result]) -> None:
    """새 추출 디렉터리와 모든 출력 이름을 커밋 직전에 확인한다(최대 추출 파일 수+매니페스트)."""
    check_root(case, "recovered", parent)
    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if not stat.S_ISDIR(current.st_mode) or not safeio.same_file(current, os.fstat(directory)):
        raise safeio.UnsafeFile("추출 디렉터리 이름이 기록 전에 바뀌었습니다.")
    with os.scandir(directory) as entries:
        seen = set()
        for entry in entries:
            if entry.name not in seals or entry.name in seen:
                raise safeio.UnsafeFile("추출 디렉터리에 서버가 만들지 않은 항목이 있습니다.")
            check_file(directory, entry.name, seals[entry.name])
            seen.add(entry.name)
    if len(seen) != len(seals):
        raise safeio.UnsafeFile("추출 파일이 기록 전에 사라졌습니다.")
