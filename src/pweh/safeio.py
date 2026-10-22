"""믿을 수 없는 파일·디렉터리를 안전하게 다루는 저수준 도구 (증거 이미지·접수 기록·보관 기록·추출물, 다른 서버의 증거 가드).

규칙:
- 일반 파일만 읽는다. 먼저 lstat 으로 일반 파일인지 보고 아니면(장치·FIFO·소켓·디렉터리·심볼릭 링크) 열지 않는다 — tty 는 여는 것만으로
  DTR 이 바뀐다. 그다음 ``O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY|O_CLOEXEC`` 로 열고 fstat 의 S_ISREG 와 (st_dev, st_ino) 를 lstat 결과와
  대조해, 그 사이에 바뀐 것은 읽지 않고 닫는다(UnsafeFile). 연 뒤에는 O_NONBLOCK 을 끈다.
- lstat 과 open 사이의 바꿔치기는 막는 것이 아니라 fstat 대조로 거부한다. 그래서 '열지 않는다'가 보장되는 범위는 이렇다:
  · 마지막 구성요소: 심볼릭 링크는 O_NOFOLLOW 때문에 열리지 않는다(ELOOP). 그 이름에 바꿔 넣은 FIFO 는 열리지만 O_NONBLOCK 이라 멈추지
    않고 fstat 대조로 거부된다(읽지 않음). 장치 노드는 보통 같은 계정의 특권 없는 프로세스가 그 자리에 만들 수 없다(mknod 는
    CAP_MKNOD 가 필요하고, 하드 링크·이름 바꾸기는 파일 시스템을 넘지 못한다 — /dev 는 다른 파일 시스템). 예외: 같은 파일 시스템에 이미
    있는 장치 노드(컨테이너 rootfs 의 정적 노드 등)에 읽기·쓰기 권한이 있으면 하드 링크로 가져올 수 있다 — 그때도 fstat 대조로 거부하지만
    여는 부수효과는 막지 못한다.
  · 중간 디렉터리: 구성요소마다 디렉터리 fd 를 고정하므로 이후 이름 교체가 다음 파일 열기를 다른 디렉터리로 돌리지 않는다.
    일반 경로의 중간 링크 별칭은 최대 40개까지 해석한다. dir_fd 상대 경로의 중간 링크·상위 이동은 거부한다.
    경로 길이·구성요소 수·순회 시간은 제한하지만, 개별 OS 호출의 정지(예: 응답 없는 원격 파일 시스템)를 중단시키지는 않는다.
- 읽기·해시·복사는 연 fd 로만 하고 경로를 다시 열지 않는다. 해시·복사는 확인한 크기만큼만 읽는다(파일이 자라도 그 뒤는 읽지 않는다).
- 디렉터리는 믿는 기준 디렉터리에서 한 구성요소씩 ``O_DIRECTORY|O_NOFOLLOW`` 로 내려가 연다(중간의 심볼릭 링크도 거부).
  파일은 그 디렉터리 fd 기준으로 ``O_CREAT|O_EXCL|O_NOFOLLOW`` 로 만들고, 쓰기와 권한 변경도 그 fd 로 한다.
- POSIX 전용이다 (PWEH 는 Linux·WSL 에서 돈다).
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import hashlib
import os
import secrets
import stat
import sys
import time
from collections import deque
from collections.abc import Callable, Iterable, Iterator, Sequence
from pathlib import Path

from .errors import PwehError, ValidationFailed

READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
CHUNK = 1 << 20
PATH_MAX_BYTES = 4096
PATH_MAX_STEPS = 256
PATH_MAX_LINKS = 40
PATH_MAX_SECONDS = 5.0


class UnsafeFile(PwehError):
    """일반 파일이 아니거나(장치·FIFO·소켓·디렉터리·심볼릭 링크), 확인한 뒤 바뀐 파일·디렉터리."""

    code = "unsafe_file"


def file_kind(mode: int) -> str:
    """st_mode → 사람이 읽는 종류 이름."""
    for test, name in ((stat.S_ISREG, "일반 파일"), (stat.S_ISDIR, "디렉터리"), (stat.S_ISLNK, "심볼릭 링크"), (stat.S_ISFIFO, "FIFO"),
                       (stat.S_ISSOCK, "소켓"), (stat.S_ISCHR, "문자 장치"), (stat.S_ISBLK, "블록 장치")):
        if test(mode):
            return name
    return "알 수 없는 종류"


def same_file(a: os.stat_result, b: os.stat_result) -> bool:
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def _check_name(name: str) -> None:
    if not name or name in (".", "..") or "/" in name or "\x00" in name:
        raise UnsafeFile(f"잘못된 경로 구성요소입니다: {name!r}")


def _path_text(path: str | os.PathLike[str]) -> str:
    value = os.fspath(path)
    if not isinstance(value, str) or "\x00" in value:
        raise ValidationFailed("파일 경로는 NUL 없는 문자열이어야 합니다.")
    if len(os.fsencode(value)) > PATH_MAX_BYTES:
        raise UnsafeFile("경로 길이 상한을 넘었습니다.")
    return value


def _walk_directory(path: str, *, dir_fd: int | None = None, follow_links: bool = True,
                    deadline: float | None = None) -> int:
    """중간 이름을 디렉터리 fd 로 고정한다. 링크는 허용할 때만 한 번씩 읽고 한도 안에서 해석한다."""
    path = _path_text(path)
    absolute = path.startswith("/")
    fd = os.open("/", DIR_FLAGS) if absolute else (os.dup(dir_fd) if dir_fd is not None else os.open(".", DIR_FLAGS))
    deadline = time.monotonic() + PATH_MAX_SECONDS if deadline is None else deadline
    todo = deque(p for p in path.split("/") if p not in ("", "."))
    steps = links = 0
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise UnsafeFile("기준 fd 가 디렉터리가 아닙니다.")
        while todo:
            steps += 1
            if steps > PATH_MAX_STEPS or time.monotonic() > deadline:
                raise UnsafeFile("디렉터리 순회 개수·시간 상한을 넘었습니다.")
            name = todo.popleft()
            if name == ".." and not follow_links:
                raise UnsafeFile("dir_fd 상대 경로의 상위 이동은 허용하지 않습니다.")
            st0 = os.lstat(name, dir_fd=fd)
            if stat.S_ISLNK(st0.st_mode):
                links += 1
                if not follow_links or links > PATH_MAX_LINKS:
                    raise UnsafeFile("중간 심볼릭 링크가 허용되지 않거나 링크 해석 상한을 넘었습니다.")
                target = _path_text(os.readlink(name, dir_fd=fd))
                # 링크 자체가 교체됐으면 새 목적지를 이어 읽지 않는다.
                if not same_file(st0, os.lstat(name, dir_fd=fd)):
                    raise UnsafeFile("디렉터리 링크가 확인하는 동안 바뀌었습니다.")
                parts = [p for p in target.split("/") if p not in ("", ".")]
                if len(parts) + len(todo) + steps > PATH_MAX_STEPS or len(os.fsencode("/".join(parts + list(todo)))) > PATH_MAX_BYTES:
                    raise UnsafeFile("링크를 푼 경로의 길이·구성요소 상한을 넘었습니다.")
                if target.startswith("/"):
                    root = os.open("/", DIR_FLAGS)
                    os.close(fd)
                    fd = root
                todo.extendleft(reversed(parts))
                continue
            if not stat.S_ISDIR(st0.st_mode):
                raise UnsafeFile(f"중간 구성요소가 디렉터리가 아닙니다: {name}")
            try:
                nfd = os.open(name, DIR_FLAGS, dir_fd=fd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise UnsafeFile(f"디렉터리가 확인하는 동안 바뀌었습니다: {name}") from exc
                raise
            try:
                if not same_file(st0, os.fstat(nfd)):
                    raise UnsafeFile(f"디렉터리가 확인하는 동안 바뀌었습니다: {name}")
            except BaseException:
                os.close(nfd)
                raise
            os.close(fd)
            fd = nfd
        if time.monotonic() > deadline:
            raise UnsafeFile("디렉터리 순회 시간 상한을 넘었습니다.")
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_regular(path: str | os.PathLike[str], *, dir_fd: int | None = None, expect: os.stat_result | None = None,
                 what: str = "파일", reject_hardlinks: bool = False) -> tuple[int, os.stat_result]:
    """부모 디렉터리를 fd 로 고정한 뒤 일반 파일을 연다 → (fd, fstat). 호출자가 닫는다.

    최종 링크·특수파일은 lstat 단계에서 거부한다. 일반 경로의 중간 링크 별칭은 한도 안에서 해석하고,
    dir_fd 상대 경로에서는 중간 링크·상위 이동을 거부한다. expect 는 dev·ino·size 를 대조한다.
    reject_hardlinks=True 는 증거 경계용으로, 열기 전·후 st_nlink 가 1이 아니면 거부한다.
    마지막 이름의 lstat/open 사이 특수파일 교체 한계는 모듈 설명을 따른다."""
    raw = _path_text(path)
    parent, name = os.path.split(raw)
    _check_name(name)
    if dir_fd is not None and raw.startswith("/"):
        raise UnsafeFile("dir_fd 에는 상대 경로만 허용합니다.")
    pfd = _walk_directory(parent, dir_fd=dir_fd, follow_links=dir_fd is None)
    try:
        st0 = os.lstat(name, dir_fd=pfd)
        if not stat.S_ISREG(st0.st_mode):
            raise UnsafeFile(f"{what}이(가) 일반 파일이 아닙니다({file_kind(st0.st_mode)}): {raw}")
        if reject_hardlinks and st0.st_nlink != 1:
            raise UnsafeFile(f"{what}의 하드 링크 수가 1이 아닙니다: {raw}")
        try:
            fd = os.open(name, READ_FLAGS, dir_fd=pfd)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENXIO, errno.EISDIR):
                raise UnsafeFile(f"{what}이(가) 확인하는 동안 일반 파일이 아닌 것으로 바뀌었습니다: {raw}") from exc
            raise
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or not same_file(st, st0):
                raise UnsafeFile(f"{what}이(가) 확인하는 동안 바뀌었습니다: {raw}")
            if reject_hardlinks and st.st_nlink != 1:
                raise UnsafeFile(f"{what}의 하드 링크 수가 1이 아닙니다: {raw}")
            if expect is not None and (not same_file(st, expect) or st.st_size != expect.st_size):
                raise UnsafeFile(f"{what}이(가) 앞서 검증한 파일과 다릅니다(바뀌었거나 크기가 다름): {raw}")
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl & ~os.O_NONBLOCK)
            return fd, st
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(pfd)


def read_fd(fd: int, size: int, *, offset: int = 0) -> bytes:
    """fd 의 [offset, offset+size) 를 pread 로 읽는다 (파일 위치를 바꾸지 않음). 파일이 그보다 짧으면 읽은 만큼."""
    out = bytearray()
    while len(out) < size:
        b = os.pread(fd, min(CHUNK, size - len(out)), offset + len(out))
        if not b:
            break
        out += b
    return bytes(out)


def read_regular(path: str | os.PathLike[str], *, max_bytes: int, dir_fd: int | None = None, what: str = "파일",
                 reject_hardlinks: bool = False) -> bytes:
    """일반 파일 전체를 안전하게 읽는다. 크기가 max_bytes 를 넘으면(읽는 동안 자란 경우 포함) ValidationFailed — 상한까지만 읽는다."""
    fd, st = open_regular(path, dir_fd=dir_fd, what=what, reject_hardlinks=reject_hardlinks)
    try:
        if st.st_size > max_bytes:
            raise ValidationFailed(f"{what}이(가) 너무 큽니다({st.st_size} 바이트 > 상한 {max_bytes} 바이트).")
        data = read_fd(fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise ValidationFailed(f"{what}이(가) 읽는 동안 상한({max_bytes} 바이트)을 넘게 자랐습니다.")
        if reject_hardlinks and os.fstat(fd).st_nlink != 1:
            raise UnsafeFile(f"{what}의 하드 링크 수가 읽는 동안 바뀌었습니다.")
        return data
    finally:
        os.close(fd)


def write_all(fd: int, data: bytes | bytearray | memoryview) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def hash_fd(fd: int, size: int, *, algorithms: Iterable[str] = ("sha256", "md5", "sha1"), out_fd: int | None = None,
            progress: Callable[[int, int], None] | None = None, check: Callable[[], None] | None = None, chunk: int = CHUNK) -> dict[str, str]:
    """fd 의 0..size 바이트를 pread 로 한 번 읽어 해시한다 (out_fd 를 주면 같은 바이트를 쓴다 — 복사). 확인한 크기만큼만 읽는다.

    파일이 size 보다 일찍 끝나면 UnsafeFile(읽는 동안 줄어듦). progress(done, size) 는 청크마다, check() 는 청크마다 부른다(취소 확인 —
    예외를 던지면 그대로 올라간다)."""
    hs = {a: hashlib.new(a) for a in algorithms}
    done = 0
    while done < size:
        if check is not None:
            check()
        b = os.pread(fd, min(chunk, size - done), done)
        if not b:
            raise UnsafeFile(f"파일이 읽는 동안 줄어들었습니다({done}/{size} 바이트에서 끝남).")
        for h in hs.values():
            h.update(b)
        if out_fd is not None:
            write_all(out_fd, b)
        done += len(b)
        if progress is not None:
            progress(done, size)
    return {a: h.hexdigest() for a, h in hs.items()}


def open_dir_chain(base: str | os.PathLike[str], parts: Sequence[str] = (), *, create: bool = False, mode: int = 0o755) -> int:
    """믿는 기준 디렉터리 base 에서 parts 를 한 구성요소씩 ``O_DIRECTORY|O_NOFOLLOW`` 로 내려가 연다 → 마지막 디렉터리 fd (호출자가 닫는다).

    구성요소가 심볼릭 링크이거나 디렉터리가 아니면 UnsafeFile. create 면 없는 구성요소를 mkdir(mode, dir_fd=…) 로 만든다(umask 적용).
    base 는 신뢰된 위치(예: 케이스 디렉터리)로서 링크 별칭을 한도 안에서 해석해 fd 로 고정한다.
    base 아래 parts 의 링크는 거부하며 경로 길이·구성요소 수·순회 시간 상한을 함께 적용한다."""
    base = _path_text(base)
    deadline = time.monotonic() + PATH_MAX_SECONDS
    fd = _walk_directory(base, deadline=deadline)
    path_bytes = len(os.fsencode(base))
    try:
        for index, name in enumerate(parts):
            path_bytes += len(os.fsencode(name)) + 1
            if index >= PATH_MAX_STEPS or path_bytes > PATH_MAX_BYTES or time.monotonic() > deadline:
                raise UnsafeFile("디렉터리 순회 개수·시간 상한을 넘었습니다.")
            _check_name(name)
            try:
                nfd = os.open(name, DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(name, mode, dir_fd=fd)
                except FileExistsError:
                    pass
                try:
                    nfd = os.open(name, DIR_FLAGS, dir_fd=fd)
                except OSError as exc:
                    if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                        raise UnsafeFile(f"디렉터리가 아니거나 심볼릭 링크입니다: {name}") from exc
                    raise
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise UnsafeFile(f"디렉터리가 아니거나 심볼릭 링크입니다: {name}") from exc
                raise
            os.close(fd)
            fd = nfd
        if time.monotonic() > deadline:
            raise UnsafeFile("디렉터리 순회 시간 상한을 넘었습니다.")
        return fd
    except BaseException:
        os.close(fd)
        raise


def create_excl(dir_fd: int, name: str, mode: int = 0o644) -> int:
    """dir_fd 안에 새 파일을 만든다 → 쓰기용 fd. 이미 있으면(심볼릭 링크 포함) FileExistsError, 링크를 따라가지 않는다."""
    _check_name(name)
    return os.open(name, CREATE_FLAGS, mode, dir_fd=dir_fd)


def write_new(dir_fd: int, name: str, data: bytes | bytearray | memoryview, *, final_mode: int | None = 0o444) -> None:
    """dir_fd 안에 새 파일을 만들어(create_excl) 쓰고 fsync 한 뒤 final_mode 로 fchmod 한다 — 경로로 다시 열거나 chmod 하지 않는다.
    쓰다가 실패하면 만든 파일을 지운다."""
    fd = create_excl(dir_fd, name, 0o644)
    try:
        write_all(fd, data)
        os.fsync(fd)
        if final_mode is not None:
            os.fchmod(fd, final_mode)
    except BaseException:
        os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(name, dir_fd=dir_fd)
        raise
    os.close(fd)


def atomic_write_at(dir_fd: int, name: str, data: bytes | bytearray | memoryview, mode: int = 0o644) -> None:
    """dir_fd 안의 name 을 원자적으로 바꿔 쓴다: 같은 디렉터리에 O_EXCL 임시 파일을 만들어 쓰고 fsync·fchmod(mode) 한 뒤 rename.
    name 이 심볼릭 링크여도 링크를 따라 쓰지 않는다(rename 은 디렉터리 항목 자체를 바꾼다)."""
    _check_name(name)
    tmp = f".{name}.{secrets.token_hex(6)}.tmp"
    fd = create_excl(dir_fd, tmp, 0o600)
    try:
        try:
            write_all(fd, data)
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp, dir_fd=dir_fd)
        raise


def _open_lock(dir_fd: int, name: str, create: bool) -> int:
    """잠금 파일을 연다 (일반 파일만 — lstat 이 장치·FIFO·링크면 열지 않는다. lstat 과 open 사이에 그 이름에 바꿔 넣은 FIFO 는
    O_NONBLOCK 으로 열린 뒤 fstat 대조로 거부한다). 없으면 create 일 때 0600 으로 만든다. name 은 dir_fd 안의 한 구성요소다."""
    _check_name(name)
    try:
        st0 = os.lstat(name, dir_fd=dir_fd)
    except FileNotFoundError:
        if not create:
            raise
        st0 = None
    if st0 is not None and not stat.S_ISREG(st0.st_mode):
        raise UnsafeFile(f"잠금 파일이 일반 파일이 아닙니다({file_kind(st0.st_mode)}): {name}")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC | (os.O_CREAT if create else 0)
    try:
        fd = os.open(name, flags, 0o600, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENXIO, errno.EISDIR):
            raise UnsafeFile(f"잠금 파일이 일반 파일이 아닙니다: {name}") from exc
        raise
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or (st0 is not None and not same_file(st, st0)):
        os.close(fd)
        raise UnsafeFile(f"잠금 파일이 확인하는 동안 바뀌었습니다: {name}")
    return fd


@contextlib.contextmanager
def locked_at(dir_fd: int, name: str, *, shared: bool = False, timeout: float = 30.0, create: bool = True) -> Iterator[int]:
    """dir_fd 안의 잠금 파일에 flock (shared=True 면 공유 잠금 — 읽기, 아니면 배타 잠금 — 쓰기). timeout 초 안에 못 얻으면 lock_timeout."""
    fd = _open_lock(dir_fd, name, create)
    try:
        op = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, op | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise PwehError(f"잠금 획득 시간 초과: {name}", code="lock_timeout") from None
                time.sleep(0.02)
        try:
            yield fd
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def try_lock_at(dir_fd: int, name: str, *, create: bool = False) -> int | None:
    """배타 잠금을 기다리지 않고 시도한다 → 잠근 fd(호출자가 닫으면 풀린다) | 다른 쪽이 잡고 있으면 None. 없는 파일은 create 가 아니면 FileNotFoundError."""
    fd = _open_lock(dir_fd, name, create)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BlockingIOError:
        os.close(fd)
        return None
    except BaseException:
        os.close(fd)
        raise


def remove_dir_at(parent_fd: int, name: str, *, expect: os.stat_result | None = None) -> list[str]:
    """parent_fd 안의 디렉터리 name 을 지운다: 안의 디렉터리가 아닌 항목을 unlink 하고(링크는 따라가지 않는다) 빈 하위 디렉터리를
    rmdir 한 뒤 name 을 rmdir. expect가 있으면 다른 디렉터리로 교체된 이름은 건드리지 않는다.
    0555 면 fchmod 로 쓰기를 열고 지운다(경로로 chmod 하지 않는다). 반환: 지우지 못한 항목 이름(없으면 빈 목록)."""
    _check_name(name)
    left: list[str] = []
    try:
        fd = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        return left
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise UnsafeFile(f"디렉터리가 아니거나 심볼릭 링크입니다: {name}") from exc
        raise
    try:
        if expect is not None and not same_file(os.fstat(fd), expect):
            raise UnsafeFile(f"정리할 디렉터리가 바뀌었습니다: {name}")
        with contextlib.suppress(OSError):
            os.fchmod(fd, 0o755)
        with os.scandir(fd) as it:
            names = [(e.name, e.is_dir(follow_symlinks=False)) for e in it]
        for child, is_dir in names:
            try:
                if is_dir:
                    os.rmdir(child, dir_fd=fd)
                else:
                    os.unlink(child, dir_fd=fd)
            except OSError:
                left.append(child)
    finally:
        os.close(fd)
    if not left:
        try:
            os.rmdir(name, dir_fd=parent_fd)
        except OSError:
            left.append(".")
    return left


def fd_real_path(fd: int) -> str | None:
    """열린 fd 의 실제 경로(Linux /proc, macOS F_GETPATH). 확인할 수 없거나 이름이 지워졌으면 None."""
    try:
        if sys.platform == "darwin":
            # XNU bsd/sys/fcntl.h: F_GETPATH=50, syslimits.h: PATH_MAX=1024.
            # 고정 크기 버퍼로만 호출하며 경로를 얻으려고 원본 이름을 다시 열지 않는다.
            if os.fstat(fd).st_nlink == 0:
                return None
            raw = fcntl.fcntl(fd, getattr(fcntl, "F_GETPATH", 50), bytes(1024))
            if not isinstance(raw, bytes) or b"\0" not in raw:
                return None
            target = os.fsdecode(raw.split(b"\0", 1)[0])
        else:
            target = os.readlink(f"/proc/self/fd/{fd}")
    except OSError:
        return None
    return None if not os.path.isabs(target) or target.endswith(" (deleted)") else target


def is_under(path: str | os.PathLike[str], base: str | os.PathLike[str]) -> bool:
    """path 가 base 와 같거나 그 아래인가 (둘 다 이미 실제 경로라고 본다 — 문자열 구성요소 비교)."""
    p, b = Path(path), Path(base)
    return p == b or b in p.parents
