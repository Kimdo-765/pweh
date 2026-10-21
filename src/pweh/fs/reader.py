"""카드 이미지 읽기.

- `ImageReader`: 일반 파일만 연다. 열기 전에 stat 으로 종류를 확인하고(tty 를 열면 DTR 이 바뀌어 보드가 리셋될 수 있고,
  FIFO 를 읽기 전용으로 열면 영원히 멈춘다), O_RDONLY|O_NONBLOCK|O_CLOEXEC 로 연 뒤 fstat 으로 다시 확인한다.
  `/dev`·`/proc`·`/sys` 아래와 Windows 장치 경로(`\\\\.\\…`)는 거부한다. 읽기는 os.pread 로 필요한 만큼만 한다
  (mmap 은 읽는 중 파일이 잘리면 SIGBUS 가 나므로 쓰지 않는다). 이미지에 쓰지 않는다.
  `ImageReader.from_fd(fd)` 는 호출자가 이미 `pweh.safeio.open_regular` 로 열고 확인한 fd 를 dup 해서 쓴다 — 경로를 다시 열지 않으므로
  확인한 바로 그 파일을 읽는다(확인과 다시 열기 사이에 다른 파일로 바뀌는 경쟁이 없다).
- `BytesReader`: 메모리 버퍼 (시험·작은 조각 해석용).
- `SliceReader`: 파티션처럼 이미지의 한 구간을 0 부터 시작하는 것처럼 보이게 하는 보기. 구간이 이미지 끝을 넘으면
  `truncated=True` 이고 `size` 는 실제로 읽을 수 있는 길이다.

모든 읽기는 범위를 확인하고, 범위를 벗어나면 `FsError(reason="out_of_bounds")` 를 낸다.
"""

from __future__ import annotations

import os
import stat
import threading
from typing import Any, Protocol

from .common import FsError

__all__ = ["ImageReader", "BytesReader", "SliceReader", "Source", "open_image", "MAX_SINGLE_READ"]

MAX_SINGLE_READ = 64 << 20  # read() 한 번의 최대 크기 (큰 내용은 나눠 읽는다)

_DEVICE_DIRS = ("/dev", "/proc", "/sys")


class Source(Protocol):
    """해석기가 쓰는 최소 인터페이스."""

    size: int
    base_offset: int

    def read(self, offset: int, size: int) -> bytes: ...


def _check_range(offset: Any, size: Any, total: int) -> None:
    if type(offset) is not int or type(size) is not int:
        raise FsError("읽기 오프셋과 크기는 정수여야 합니다.", reason="out_of_bounds")
    if offset < 0 or size < 0:
        raise FsError("음수 오프셋/크기로는 읽을 수 없습니다.", reason="out_of_bounds",
                      data={"offset": offset, "size": size})
    if size > MAX_SINGLE_READ:
        raise FsError(f"한 번에 {MAX_SINGLE_READ} 바이트보다 많이 읽을 수 없습니다.", reason="too_large",
                      data={"size": size})
    if offset + size > total:
        raise FsError("이미지 범위를 벗어난 읽기입니다.", reason="out_of_bounds",
                      data={"offset": offset, "size": size, "available": total})


def _is_under(path: str, top: str) -> bool:
    return path == top or path.startswith(top + "/")


class ImageReader:
    """일반 파일로 된 카드 이미지를 읽기 전용으로 연다."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        p = os.fspath(path)
        if isinstance(p, bytes):  # pragma: no cover - 방어
            p = os.fsdecode(p)
        if not p:
            raise FsError("이미지 경로가 비어 있습니다.", reason="open_failed")
        if p.startswith(("\\\\.\\", "\\\\?\\", "//./", "//?/")):
            raise FsError("Windows 장치 경로는 열지 않습니다. 사람이 만든 이미지 파일을 주세요.", reason="not_regular_file",
                          data={"path": p})
        real = os.path.realpath(p)
        for top in _DEVICE_DIRS:
            if _is_under(real, top) or _is_under(os.path.abspath(p), top):
                raise FsError(f"{top} 아래 경로는 열지 않습니다(원시 장치·커널 파일 거부).", reason="not_regular_file",
                              data={"path": p, "realpath": real})
        try:
            st = os.stat(p)
        except FileNotFoundError:
            raise FsError(f"이미지 파일이 없습니다: {p}", reason="not_found", data={"path": p}) from None
        except OSError as e:
            raise FsError(f"이미지 파일 정보를 읽을 수 없습니다: {e}", reason="open_failed", data={"path": p}) from None
        if not stat.S_ISREG(st.st_mode):
            raise FsError("일반 파일이 아닙니다(블록·문자 장치, FIFO, 소켓, 디렉터리는 거부).", reason="not_regular_file",
                          data={"path": p, "mode": stat.filemode(st.st_mode)})
        flags = os.O_RDONLY
        for name in ("O_NONBLOCK", "O_CLOEXEC", "O_NOCTTY", "O_BINARY"):
            flags |= getattr(os, name, 0)
        try:
            fd = os.open(p, flags)
        except OSError as e:
            raise FsError(f"이미지 파일을 열 수 없습니다: {e}", reason="open_failed", data={"path": p}) from None
        try:
            st2 = os.fstat(fd)
            if not stat.S_ISREG(st2.st_mode) or (st2.st_dev, st2.st_ino) != (st.st_dev, st.st_ino):
                raise FsError("연 파일이 확인한 일반 파일과 다릅니다(열기 사이에 바뀜).", reason="not_regular_file",
                              data={"path": p})
        except BaseException:
            os.close(fd)
            raise
        self._fd: int | None = fd
        self._lock = threading.Lock()
        self.path = p
        self.realpath = real
        self.size = int(st2.st_size)
        self.base_offset = 0
        self.identity = {"dev": st2.st_dev, "ino": st2.st_ino, "size": st2.st_size, "mtime_ns": st2.st_mtime_ns}

    @classmethod
    def from_fd(cls, fd: int, path: str | os.PathLike[str] | None = None) -> "ImageReader":
        """이미 연(호출자가 `pweh.safeio.open_regular` 로 확인한) 일반 파일 fd 를 읽는 ImageReader.

        fd 를 dup 해서 쓴다(호출자는 자기 fd 를 따로 닫는다). 경로는 열지 않는다 — path 는 표시용이다. fstat 이 일반 파일이 아니면
        FsError(not_regular_file). identity·size 는 경로로 연 경우와 같이 fstat 에서 얻는다.
        """
        if type(fd) is not int or fd < 0:
            raise FsError("파일 디스크립터가 잘못됐습니다.", reason="open_failed")
        try:
            st0 = os.fstat(fd)
        except OSError as e:
            raise FsError(f"파일 디스크립터 정보를 읽을 수 없습니다: {e}", reason="open_failed") from None
        if not stat.S_ISREG(st0.st_mode):
            raise FsError("일반 파일이 아닙니다(블록·문자 장치, FIFO, 소켓, 디렉터리는 거부).", reason="not_regular_file",
                          data={"mode": stat.filemode(st0.st_mode)})
        try:
            dfd = os.dup(fd)
        except OSError as e:
            raise FsError(f"파일 디스크립터를 복제할 수 없습니다: {e}", reason="open_failed") from None
        try:
            os.set_inheritable(dfd, False)
            st = os.fstat(dfd)
            if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != (st0.st_dev, st0.st_ino):
                raise FsError("복제한 fd 가 확인한 일반 파일과 다릅니다.", reason="not_regular_file")
        except BaseException:
            os.close(dfd)
            raise
        self = cls.__new__(cls)
        self._fd = dfd
        self._lock = threading.Lock()
        shown = os.fsdecode(os.fspath(path)) if path is not None else None
        real = None
        try:
            target = os.readlink(f"/proc/self/fd/{dfd}")
            real = None if target.endswith(" (deleted)") else target
        except OSError:
            real = None
        self.path = shown if shown is not None else (real or f"<fd {fd}>")
        self.realpath = real or shown
        self.size = int(st.st_size)
        self.base_offset = 0
        self.identity = {"dev": st.st_dev, "ino": st.st_ino, "size": st.st_size, "mtime_ns": st.st_mtime_ns}
        return self

    # -- 읽기 --
    def _pread(self, n: int, off: int) -> bytes:
        assert self._fd is not None
        if hasattr(os, "pread"):
            return os.pread(self._fd, n, off)
        with self._lock:  # pragma: no cover - pread 가 없는 플랫폼
            os.lseek(self._fd, off, os.SEEK_SET)
            return os.read(self._fd, n)

    def read(self, offset: int, size: int) -> bytes:
        if self._fd is None:
            raise FsError("이미 닫힌 이미지입니다.", reason="io_error")
        _check_range(offset, size, self.size)
        if size == 0:
            return b""
        parts: list[bytes] = []
        got = 0
        while got < size:
            try:
                chunk = self._pread(size - got, offset + got)
            except OSError as e:
                raise FsError(f"이미지 읽기 실패: {e}", reason="io_error", data={"offset": offset + got}) from None
            if not chunk:
                raise FsError("이미지가 열 때보다 짧습니다(읽는 중 파일이 줄었을 수 있음).", reason="short_read",
                              data={"offset": offset + got})
            parts.append(chunk)
            got += len(chunk)
        return parts[0] if len(parts) == 1 else b"".join(parts)

    def read_clamped(self, offset: int, size: int) -> bytes:
        """이미지 끝에서 잘라 읽는다 (끝을 넘는 부분은 빠짐)."""
        if offset < 0 or size <= 0 or offset >= self.size:
            return b""
        return self.read(offset, min(size, self.size - offset, MAX_SINGLE_READ))

    # -- 수명 --
    def close(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            os.close(fd)

    @property
    def closed(self) -> bool:
        return self._fd is None

    def __enter__(self) -> "ImageReader":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - GC
        try:
            self.close()
        except Exception:  # noqa: BLE001
            pass

    def __repr__(self) -> str:
        return f"ImageReader({self.path!r}, size={self.size})"


class BytesReader:
    """메모리 버퍼를 이미지처럼 읽는다 (복사하지 않음 — bytearray 를 넘기면 바깥에서 바꾼 내용이 보인다)."""

    def __init__(self, data: bytes | bytearray | memoryview) -> None:
        self._mv = memoryview(data).cast("B") if not isinstance(data, memoryview) else data.cast("B")
        self.size = len(self._mv)
        self.base_offset = 0

    def read(self, offset: int, size: int) -> bytes:
        _check_range(offset, size, self.size)
        return bytes(self._mv[offset:offset + size])

    def read_clamped(self, offset: int, size: int) -> bytes:
        if offset < 0 or size <= 0 or offset >= self.size:
            return b""
        return self.read(offset, min(size, self.size - offset, MAX_SINGLE_READ))

    def close(self) -> None:
        self._mv.release()

    def __enter__(self) -> "BytesReader":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class SliceReader:
    """다른 Source 의 [offset, offset+length) 구간 보기."""

    def __init__(self, base: Any, offset: int, length: int | None = None, *, label: str | None = None) -> None:
        if type(offset) is not int or offset < 0:
            raise FsError("구간 시작 오프셋이 잘못됐습니다.", reason="out_of_bounds", data={"offset": offset})
        avail = max(0, int(base.size) - offset)
        if length is None:
            length = avail
        if type(length) is not int or length < 0:
            raise FsError("구간 길이가 잘못됐습니다.", reason="out_of_bounds", data={"length": length})
        self.base = base
        self.offset = offset
        self.declared_size = length
        self.size = min(length, avail)
        self.truncated = length > avail
        self.base_offset = int(getattr(base, "base_offset", 0)) + offset
        self.label = label

    def read(self, offset: int, size: int) -> bytes:
        _check_range(offset, size, self.size)
        return self.base.read(self.offset + offset, size)

    def read_clamped(self, offset: int, size: int) -> bytes:
        if offset < 0 or size <= 0 or offset >= self.size:
            return b""
        return self.read(offset, min(size, self.size - offset, MAX_SINGLE_READ))

    def __repr__(self) -> str:
        return f"SliceReader(offset={self.offset}, size={self.size}, declared={self.declared_size})"


def open_image(path: str | os.PathLike[str]) -> ImageReader:
    """`ImageReader(path)` 와 같다."""
    return ImageReader(path)
