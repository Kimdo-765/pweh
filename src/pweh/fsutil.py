"""파일시스템 유틸리티: 원자적 쓰기, 프로세스 간 잠금, 해시, 안전한 경로 결합.

여러 MCP 서버 프로세스(uart-mcp, fwtriage-mcp, case-mcp …)가 같은 케이스 디렉터리에
동시에 기록하므로 case.json / findings.json 은 반드시 file_lock + atomic write 로 갱신한다.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import re
import hashlib
import json
import os
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator

from .errors import PwehError

try:  # POSIX
    import fcntl  # type: ignore

    _HAVE_FCNTL = True
except ImportError:  # pragma: no cover - Windows
    _HAVE_FCNTL = False


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def utcnow_iso() -> str:
    """ISO-8601 UTC 타임스탬프 (밀리초)."""
    return utcnow().isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_id(prefix: str = "", nbytes: int = 4) -> str:
    token = secrets.token_hex(nbytes)
    return f"{prefix}{token}" if prefix else token


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def atomic_write_text(path: Path, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))


def atomic_write_json(path: Path, obj: Any) -> None:
    atomic_write_text(path, json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False) + "\n")


def read_json(path: Path, default: Any = None) -> Any:
    path = Path(path)
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


@contextlib.contextmanager
def file_lock(lock_path: Path, timeout: float = 30.0) -> Iterator[None]:
    """프로세스 간 배타 잠금. POSIX 는 flock, 그 외에는 O_EXCL 잠금 파일."""
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    if _HAVE_FCNTL:
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            deadline = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() > deadline:
                        raise PwehError(f"잠금 획득 시간 초과: {lock_path}", code="lock_timeout")
                    time.sleep(0.02)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
    else:  # pragma: no cover
        deadline = time.monotonic() + timeout
        excl = lock_path.with_suffix(lock_path.suffix + ".excl")
        while True:
            try:
                fd = os.open(str(excl), os.O_CREAT | os.O_EXCL | os.O_RDWR)
                os.close(fd)
                break
            except FileExistsError:
                if time.monotonic() > deadline:
                    raise PwehError(f"잠금 획득 시간 초과: {lock_path}", code="lock_timeout")
                time.sleep(0.05)
        try:
            yield
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(excl)


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_within(base: Path, target: Path) -> bool:
    base_r = Path(base).resolve()
    target_r = Path(target).resolve()
    try:
        target_r.relative_to(base_r)
        return True
    except ValueError:
        return False


def safe_join(base: Path, *parts: str | os.PathLike[str]) -> Path:
    """base 밖으로 벗어나지 않는 경로를 만든다 (``..``, 절대경로, 심볼릭 링크 탈출 차단)."""
    base_r = Path(base).resolve()
    candidate = base_r.joinpath(*[str(p) for p in parts])
    resolved = candidate.resolve()
    try:
        resolved.relative_to(base_r)
    except ValueError:
        via_link = ""
        if resolved != candidate.absolute():
            via_link = f" (심볼릭 링크/상대 경로 해석 결과: {resolved})"
        raise PwehError(
            f"경로가 허용된 디렉터리 밖을 가리킵니다: {candidate}{via_link}",
            code="path_outside_base",
            hint=f"{base_r} 내부의 상대 경로를 사용하세요. 추출된 펌웨어 안의 심볼릭 링크는 케이스 밖을 가리킬 수 있으므로 따라가지 마세요.",
            data={"requested": str(candidate), "resolved": str(resolved)},
        )
    return resolved


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.2f} {unit}"
        size /= 1024
    return f"{n} B"  # pragma: no cover


def parse_size(text: str | int) -> int:
    """'16M', '64k', '0x10000', '1048576', '2MiB' 같은 크기 문자열을 바이트 수로."""
    if isinstance(text, int):
        return text
    s = str(text).strip().lower().replace("_", "")
    if s.startswith("0x"):
        m = re.fullmatch(r"0x([0-9a-f]+)([kmgtpe]?)(?:i?b)?", s)
        if not m:
            raise PwehError(f"크기 문자열을 해석할 수 없습니다: {text!r}", code="bad_size")
        shift = {"": 0, "k": 10, "m": 20, "g": 30, "t": 40, "p": 50, "e": 60}[m.group(2)]
        return int(m.group(1), 16) << shift
    mult = 1
    for suffix, m in (("kib", 1024), ("mib", 1024**2), ("gib", 1024**3), ("kb", 1024), ("mb", 1024**2), ("gb", 1024**3), ("k", 1024), ("m", 1024**2), ("g", 1024**3), ("b", 1)):
        if s.endswith(suffix):
            s = s[: -len(suffix)]
            mult = m
            break
    try:
        return int(float(s) * mult) if "." in s else int(s, 10) * mult
    except ValueError:
        raise PwehError(f"크기 문자열을 해석할 수 없습니다: {text!r}", code="bad_size")
