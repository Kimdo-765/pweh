"""실행 없는 helper 경로·해시 검사와 소유한 실행 사본. 핀은 사용자 값으로 받지 않는다."""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from ..errors import DeviceError, ToolMissing, ValidationFailed
from . import pin

BASENAME = "pweh-serial-helper.exe"
MAX_BINARY = 8 << 20


@dataclass(frozen=True)
class HelperBinary:
    source_path: str
    source: str
    sha256: str
    source_commit: str
    version: tuple[int, int, int]


def expected_pin() -> tuple[str, str]:
    """소스 S의 미준비 핀을 실행 가능한 placeholder로 취급하지 않는다."""
    if (not isinstance(pin.PINNED_SHA256, str) or not re.fullmatch(r"[0-9a-f]{64}", pin.PINNED_SHA256)
            or pin.PINNED_SHA256 == "0" * 64 or not isinstance(pin.EXPECTED_SOURCE_COMMIT, str)
            or not re.fullmatch(r"[0-9a-f]{40}", pin.EXPECTED_SOURCE_COMMIT)
            or pin.EXPECTED_SOURCE_COMMIT == "0" * 40):
        raise ToolMissing("직렬 helper release 핀이 아직 준비되지 않았습니다.", code="serial_helper_unpinned")
    return pin.PINNED_SHA256, pin.EXPECTED_SOURCE_COMMIT


def _path(path: str) -> Path:
    if not isinstance(path, str) or any(ord(c) < 32 for c in path):
        raise ValidationFailed("helper 경로 형식 오류")
    p = Path(path)
    if not p.is_absolute() or p.name != BASENAME or ".." in p.parts:
        raise ValidationFailed("helper는 고정 basename의 POSIX 절대 경로여야 합니다.")
    for part in (*reversed(p.parents), p):
        if part.is_symlink():
            raise ValidationFailed("helper 경로의 심볼릭 링크는 허용하지 않습니다.")
    return p


def read_verified(path: str) -> bytes:
    """단일 fd의 bounded bytes를 해시한다. 이름/mtime 캐시를 신뢰하지 않는다."""
    wanted, _ = expected_pin()
    p = _path(path)
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_BINARY or before.st_nlink != 1:
            raise ValidationFailed("helper 파일 형식/크기/링크 수 오류")
        chunks = bytearray()
        while len(chunks) <= MAX_BINARY:
            chunk = os.read(fd, min(65536, MAX_BINARY + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")
        if len(chunks) != before.st_size or any(getattr(before, f) != getattr(after, f) for f in fields):
            raise DeviceError("검사 중 helper 파일이 변경됐습니다.", code="serial_helper_changed")
        if hashlib.sha256(chunks).hexdigest() != wanted:
            raise DeviceError("직렬 helper SHA256이 release 핀과 다릅니다.", code="serial_helper_hash_mismatch")
        return bytes(chunks)
    finally:
        os.close(fd)


def resolve_helper(*, configured: str | None = None, env_value: str | None = None,
                   tools_root: Path) -> HelperBinary:
    """config→env→관리 경로. 명시한 후보가 잘못되어도 다른 파일로 바꾸지 않는다."""
    from ..toolsdir import serial_helper_candidates
    wanted, commit = expected_pin()
    candidates = serial_helper_candidates(configured, env_value, tools_root)
    if not candidates:
        raise ToolMissing("직렬 helper 경로가 없습니다.")
    path, source = candidates[0]
    try:
        read_verified(path)
    except FileNotFoundError as exc:
        raise ToolMissing("직렬 helper가 없습니다. 선택 구성요소 winserial을 설치하세요.") from exc
    return HelperBinary(path, source, wanted, commit, pin.HELPER_VERSION)


@dataclass
class Snapshot:
    path: Path
    directory: Path

    def remove(self) -> None:
        """실행 종료가 확인된 뒤에만 호출한다."""
        self.path.unlink(missing_ok=True)
        self.directory.rmdir()


def snapshot(helper: HelperBinary, *, runtime_root: Path) -> Snapshot:
    """검증한 bytes를 private 실행 사본으로 고정한다(WSL exec에 owner x 필요)."""
    wanted, commit = expected_pin()
    if (helper.sha256, helper.source_commit, helper.version) != (wanted, commit, pin.HELPER_VERSION):
        raise DeviceError("helper 메타데이터가 현재 핀과 다릅니다.", code="serial_helper_hash_mismatch")
    data = read_verified(helper.source_path)
    from ..portlock import _Records
    store = _Records(runtime_root, "serial-helper-runs")
    fd = store.directory(create=True)
    assert fd is not None
    name = secrets.token_hex(16)
    child = out = None
    try:
        os.mkdir(name, 0o700, dir_fd=fd)
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        out = os.open(BASENAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500, dir_fd=child)
        view = memoryview(data)
        while view:
            n = os.write(out, view)
            if n <= 0:
                raise OSError("실행 사본 쓰기 실패")
            view = view[n:]
        os.fsync(out); os.close(out); out = None
        directory = runtime_root / "serial-helper-runs" / name
        result = Snapshot(directory / BASENAME, directory)
        read_verified(str(result.path))
        return result
    except BaseException:
        if out is not None:
            os.close(out)
        if child is not None:
            try:
                os.unlink(BASENAME, dir_fd=child)
            except FileNotFoundError:
                pass
        try:
            os.rmdir(name, dir_fd=fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        if child is not None:
            os.close(child)
        os.close(fd)
