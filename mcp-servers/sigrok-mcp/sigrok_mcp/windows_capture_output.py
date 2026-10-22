"""Windows writer의 종료 뒤에만 여는 고정 capture.sr 출력 record.

출력은 불변 실행 사본의 sibling이다. fd/name 신원이 불명확한 항목은 삭제하지 않는다.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
import time
import uuid

from pweh import safeio
from pweh.errors import DeviceError
from pweh.wininterop import validate_windows_path

MAX_OUTPUT_BYTES = 64 << 20
OUTPUT_NAME = 'capture.sr'


class CaptureOutputError(DeviceError):
    code = 'sigrok_capture_output_changed'
    def __init__(self, code='sigrok_capture_output_changed'):
        super().__init__('캡처 출력의 소유권 또는 검증 상태를 확인하지 못했습니다.', code=code)


def _fail(code='sigrok_capture_output_changed'):
    raise CaptureOutputError(code) from None


def _tick(end, cancel=None):
    try:
        if cancel is not None:
            value = cancel()
            if type(value) is not bool:
                _fail('sigrok_capture_check_failed')
            if value:
                _fail('sigrok_capture_cancelled')
    except CaptureOutputError:
        raise
    except BaseException:
        _fail('sigrok_capture_check_failed')
    if time.monotonic() >= end:
        _fail('sigrok_capture_timeout')


def _inode(st):
    return st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode)


def _seal(st):
    return st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns


@dataclass(frozen=True)
class CapturePublication:
    """파일·원장 게시의 닫힌 내부 영수증. runtime 경로/원문은 받지 않는다."""
    disposition: str
    path: str | None = None
    artifact_id: str | None = None
    size: int = 0
    sha256: str | None = None
    partial: bool = False
    reason: str | None = None

    def __post_init__(self):
        if type(self.size) is not int or not 0 <= self.size <= MAX_OUTPUT_BYTES or type(self.partial) is not bool:
            _fail('sigrok_capture_invalid')
        if self.disposition == 'published':
            if (type(self.path) is not str or re.fullmatch(r'signals/[A-Za-z0-9][A-Za-z0-9._-]{0,119}\.sr', self.path) is None
                    or type(self.artifact_id) is not str or re.fullmatch(r'A-[0-9]{4,9}', self.artifact_id) is None
                    or type(self.sha256) is not str or re.fullmatch(r'[0-9a-f]{64}', self.sha256) is None
                    or self.size == 0 or self.reason not in (None, 'sample_shortfall', 'cancelled', 'timeout')):
                _fail('sigrok_capture_invalid')
        elif self.disposition in ('no_output', 'invalid_output'):
            allowed = ('missing', 'empty') if self.disposition == 'no_output' else ('bad_zip', 'empty_capture', 'cli_failed')
            if (self.path is not None or self.artifact_id is not None or self.sha256 is not None
                    or self.partial or self.reason not in allowed
                    or (self.disposition == 'no_output' and self.size != 0)):
                _fail('sigrok_capture_invalid')
        else:
            _fail('sigrok_capture_invalid')


@dataclass(frozen=True)
class CaptureOutput:
    """publisher가 빌려 쓰는 fd와 고정 검사/commit 통지. close 책임은 owner에게 있다."""
    fd: int
    size: int
    check: object
    on_commit: object


class OutputRecord:
    """생성 직후부터 owner가 보유한다. 부분 실패도 생성 신원을 잃지 않는다."""
    def __init__(self, parent):
        self.parent = parent
        self.root = parent / ('sigrok-capture-output-' + uuid.uuid4().hex)
        self.path = self.root / OUTPUT_NAME
        self.parent_fd = self.dir_fd = self.fd = None
        self.parent_stat = self.dir_stat = self.file_stat = None
        self.created = False
        self.output_removed = self.dir_removed = self.released = False
        self.windows_path = None

    def prepare(self, *, deadline, converter, cancel=None):
        _tick(deadline, cancel)
        if (not isinstance(self.parent, Path) or not self.parent.is_absolute() or '..' in self.parent.parts
                or len(os.fsencode(self.parent)) > 8192 or self.parent_fd is not None):
            _fail('sigrok_capture_invalid')
        self.parent_fd = safeio._walk_directory(str(self.parent), follow_links=False, deadline=deadline)
        self.parent_stat = os.fstat(self.parent_fd)
        if self.parent_stat.st_uid != os.getuid() or stat.S_IMODE(self.parent_stat.st_mode) != 0o700:
            _fail()
        os.mkdir(self.root.name, 0o700, dir_fd=self.parent_fd)
        self.created = True
        self.dir_stat = os.stat(self.root.name, dir_fd=self.parent_fd, follow_symlinks=False)
        self.dir_fd = os.open(self.root.name, safeio.DIR_FLAGS, dir_fd=self.parent_fd)
        self.check_empty(deadline)
        raw = converter(self.path, min(deadline, time.monotonic() + 30))
        try:
            if type(raw) is bytes:
                if len(raw) > 8192:
                    _fail()
                raw = raw.decode('utf-8', 'strict')
            if type(raw) is not str or len(raw.encode('utf-8')) > 8192:
                _fail()
            if raw.endswith('\r\n'):
                raw = raw[:-2]
            elif raw.endswith('\n'):
                raw = raw[:-1]
            self.windows_path = validate_windows_path(raw)
        except BaseException:
            _fail('sigrok_capture_invalid')
        self.check_empty(deadline)
        _tick(deadline, cancel)

    def _dirs(self, end):
        _tick(end)
        if self.parent_fd is None or self.parent_stat is None:
            _fail()
        fd = safeio._walk_directory(str(self.parent), follow_links=False, deadline=end)
        try:
            now = os.fstat(fd)
            if (_inode(now) != _inode(self.parent_stat) or _inode(os.fstat(self.parent_fd)) != _inode(now)
                    or now.st_uid != os.getuid() or stat.S_IMODE(now.st_mode) != 0o700):
                _fail()
        finally:
            os.close(fd)
        if self.dir_removed:
            try:
                os.stat(self.root.name, dir_fd=self.parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            _fail()
        if not self.created or self.dir_fd is None or self.dir_stat is None:
            _fail()
        now = os.stat(self.root.name, dir_fd=self.parent_fd, follow_symlinks=False)
        if (_inode(now) != _inode(self.dir_stat) or _inode(os.fstat(self.dir_fd)) != _inode(now)
                or not stat.S_ISDIR(now.st_mode) or now.st_uid != os.getuid() or stat.S_IMODE(now.st_mode) != 0o700):
            _fail()

    def _names(self, end):
        self._dirs(end)
        names = set()
        with os.scandir(self.dir_fd) as rows:
            for row in rows:
                _tick(end)
                if row.name != OUTPUT_NAME or row.name in names:
                    _fail()
                names.add(row.name)
        return names

    def check_empty(self, end):
        if self._names(end):
            _fail()

    def size_exceeded(self, end):
        """실행 중 알려진 이름의 크기만 관찰한다. 읽기/검증/소유권 승격은 하지 않는다."""
        self._dirs(end)
        try:
            st = os.stat(OUTPUT_NAME, dir_fd=self.dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return stat.S_ISREG(st.st_mode) and st.st_size > MAX_OUTPUT_BYTES

    def open_final(self, end):
        names = self._names(end)
        if not names:
            if self.file_stat is not None or self.fd is not None:
                _fail()
            return None
        if self.fd is None:
            before = os.stat(OUTPUT_NAME, dir_fd=self.dir_fd, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                _fail()
            self.fd = os.open(OUTPUT_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.dir_fd)
            current = os.fstat(self.fd)
            if _seal(before) != _seal(current):
                _fail()
            self.file_stat = current
        self.check(end)
        if self.file_stat.st_size > MAX_OUTPUT_BYTES:
            _fail('sigrok_capture_limit')
        return self.fd, self.file_stat.st_size

    def check(self, end):
        if self.fd is None or self.file_stat is None or self._names(end) != {OUTPUT_NAME}:
            _fail()
        current = os.stat(OUTPUT_NAME, dir_fd=self.dir_fd, follow_symlinks=False)
        if (_seal(current) != _seal(self.file_stat) or _seal(os.fstat(self.fd)) != _seal(current)
                or not stat.S_ISREG(current.st_mode) or current.st_nlink != 1):
            _fail()

    def release(self, *, deadline, resolved):
        if self.released:
            return True
        try:
            _tick(deadline)
            if not resolved:
                return False
            if not self.created:
                # mkdir 실패 전까지 확보한 parent만 닫는다. 같은 이름의 다른 객체를 삭제하지 않는다.
                if self.parent_fd is not None:
                    os.close(self.parent_fd)
                    self.parent_fd = None
                self.released = True
                return True
            if not self.dir_removed:
                if self.file_stat is not None and not self.output_removed:
                    self.check(deadline)
                    os.unlink(OUTPUT_NAME, dir_fd=self.dir_fd)
                    self.output_removed = True
                self.check_empty(deadline)
                os.rmdir(self.root.name, dir_fd=self.parent_fd)
                self.dir_removed = True
            self._dirs(deadline)
            for attr in ('fd', 'dir_fd', 'parent_fd'):
                fd = getattr(self, attr)
                if fd is not None:
                    os.close(fd)
                    setattr(self, attr, None)
            self.released = True
            return True
        except Exception:
            return False
