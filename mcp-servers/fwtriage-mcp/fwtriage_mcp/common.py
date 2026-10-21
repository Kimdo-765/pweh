"""fwtriage 공통 헬퍼.

- 작업 제어(Ctl): 취소 확인, 시간 예산, 진행률 보고 (인라인 실행과 백그라운드 job 모두에서 같은 코드 경로)
- 케이스 내부 입력 경로 해석 (심볼릭 링크 탈출에 대한 명확한 안내 포함)
- 출력 번호(NNN) 원자적 확보: ``analysis/<prefix>-NNN.json``, ``extract/<label>-NNN/``
- 결과 JSON 저장 + 아티팩트 등록
- 큰 파일을 위한 읽기 전용 mmap, 응답 크기 제한(compact) 헬퍼

펌웨어에서 나온 어떤 파일도 실행하지 않는다. 모든 입력은 신뢰할 수 없는 데이터로 다룬다.
"""

from __future__ import annotations

import contextlib
import logging
import mmap
import os
import re
import stat
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator

from pweh import __version__ as PWEH_VERSION
from pweh.case import Case
from pweh.errors import CaseError, NotFound, PwehError, ValidationFailed
from pweh.fsutil import atomic_write_json, human_size, is_within, parse_size, sha256_file, utcnow_iso

log = logging.getLogger("pweh.fwtriage")

PRODUCER = "fwtriage-mcp"
SCHEMA_PREFIX = "pweh.fwtriage"
TOOL_VERSION = f"fwtriage-mcp {PWEH_VERSION}"

# 응답(MCP 결과)에 포함할 목록 항목 수의 상한. 전체 결과는 항상 JSON 파일에 있다.
DEFAULT_MAX_RESULTS = 50
HARD_MAX_RESULTS = 1000


class Cancelled(PwehError):
    """작업 취소 요청(클라이언트 취소 또는 job_cancel)으로 중단됨."""

    code = "cancelled"


class Ctl:
    """작업 제어 핸들.

    - ``check()``: 취소되었으면 Cancelled 예외
    - ``expired()``: 시간 예산을 넘겼는지 (넘기면 timed_out=True 로 표시하고 True 반환; 부분 결과로 마무리할 때 사용)
    - ``progress(done, total, message)``: 진행률 보고 (job 모드에서 job_status 에 반영)
    """

    def __init__(
        self,
        cancel_event: threading.Event | None = None,
        *,
        max_seconds: float | None = None,
        progress: Callable[..., Any] | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> None:
        self._event = cancel_event
        self._cancelled_fn = cancelled
        self._progress = progress
        self.t0 = time.monotonic()
        self.deadline = (self.t0 + float(max_seconds)) if max_seconds else None
        self.timed_out = False

    @property
    def is_cancelled(self) -> bool:
        if self._event is not None and self._event.is_set():
            return True
        if self._cancelled_fn is not None:
            try:
                return bool(self._cancelled_fn())
            except Exception:  # pragma: no cover - 방어
                return False
        return False

    def check(self) -> None:
        if self.is_cancelled:
            raise Cancelled("작업이 취소되었습니다.")

    def expired(self) -> bool:
        self.check()
        if self.deadline is not None and time.monotonic() > self.deadline:
            self.timed_out = True
            return True
        return False

    def remaining(self) -> float | None:
        if self.deadline is None:
            return None
        return max(0.0, self.deadline - time.monotonic())

    def progress(self, done: float, total: float | None = None, message: str | None = None) -> None:
        if self._progress is None:
            return
        try:
            self._progress(done, total, message)
        except Exception:  # pragma: no cover - 진행률 보고 실패는 무시
            pass

    def elapsed(self) -> float:
        return round(time.monotonic() - self.t0, 3)


# ---------------------------------------------------------------------------
# 입력 경로
# ---------------------------------------------------------------------------


def _lexical_join(case: Case, path: str) -> Path:
    p = Path(path)
    if p.is_absolute():
        return Path(os.path.normpath(str(p)))
    return Path(os.path.normpath(str(case.dir / p)))


def _symlink_hint(case: Case, path: str) -> str | None:
    """경로(또는 그 상위)가 심볼릭 링크라서 케이스 밖을 가리키는 경우 안내 문구."""
    lex = _lexical_join(case, path)
    cur = lex
    try:
        lex.relative_to(case.dir)
    except ValueError:
        return None
    while True:
        try:
            if cur.is_symlink():
                target = os.readlink(cur)
                return (
                    f"{case.rel(cur) if is_within(case.dir, cur.parent) else cur} 은(는) 심볼릭 링크입니다 (-> {target}). "
                    "추출된 rootfs 안의 절대 경로 링크는 호스트 파일을 가리키므로 따라가지 않습니다. "
                    "rootfs 내부의 실제 대상 파일 경로(예: extract/rootfs-001/bin/busybox)를 직접 지정하세요."
                )
        except OSError:
            return None
        if cur == case.dir or cur.parent == cur:
            return None
        cur = cur.parent


def resolve_case_path(case: Case, path: str, *, must_exist: bool = True) -> Path:
    """케이스 상대/내부 절대 경로를 해석. 케이스 밖이면 명확한 오류(심볼릭 링크면 안내 포함)."""
    if not isinstance(path, str) or not path.strip():
        raise ValidationFailed("경로가 비어 있습니다.")
    try:
        p = case.resolve_path(path)
    except PwehError as exc:
        hint = _symlink_hint(case, path)
        if hint:
            raise ValidationFailed(f"케이스 디렉터리 밖을 가리키는 경로입니다: {path}", hint=hint) from exc
        raise
    if must_exist and not (p.exists() or p.is_symlink()):
        raise NotFound(
            f"파일/디렉터리가 없습니다: {path}",
            hint="case_get(include_artifacts=true) 로 케이스 안의 경로를 확인하세요 (케이스 상대 경로 예: dumps/flash.bin).",
        )
    _refuse_forensics(case, p)
    return p


def _refuse_forensics(case: Case, p: Path) -> None:
    """케이스의 증거 폴더(forensics/ — SD 카드 이미지·복구한 녹화)는 이 서버가 읽지 않는다(링크를 풀어 판단).

    이 서버는 자동 허용이고 결과 문자열을 에이전트에게 돌려주므로, 녹화 내용이 pweh-forensics 를 거치지 않고 문맥에 들어가지 않게 한다.
    forensics/ 를 포함하는 디렉터리(케이스 루트 등)도 훑지 않는다.
    """
    from pweh.evidence import contains_forensics_dir, forensics_dir, is_forensics_path

    if is_forensics_path(case, p):
        raise ValidationFailed(
            "케이스의 증거 폴더(forensics/ — SD 카드 이미지·복구한 녹화)는 펌웨어 도구로 읽지 않습니다.",
            hint="카드 이미지는 pweh-forensics 도구(forensics_*)로만 다룬다. 녹화 내용은 에이전트가 열지 않는다.",
        )
    try:
        is_dir = p.is_dir()
    except OSError:
        is_dir = False
    if is_dir and forensics_dir(case).exists() and contains_forensics_dir(case, p):
        raise ValidationFailed(
            "이 디렉터리 아래에 증거 폴더(forensics/)가 있어 훑지 않습니다.",
            hint="펌웨어 추출 트리(예: extract/rootfs-001)처럼 forensics/ 를 포함하지 않는 하위 디렉터리를 지정하세요.",
        )


def resolve_input_file(case: Case, path: str) -> Path:
    p = resolve_case_path(case, path)
    try:
        st = os.stat(p)
    except OSError as exc:
        raise NotFound(f"파일을 열 수 없습니다: {path} ({exc})") from exc
    if stat.S_ISDIR(st.st_mode):
        raise ValidationFailed(
            f"디렉터리입니다 (파일이 필요합니다): {path}",
            hint="디렉터리 전체를 보려면 fw_strings_hunt / fw_rootfs_audit / fw_elf_info(디렉터리 모드)를 사용하세요.",
        )
    if not stat.S_ISREG(st.st_mode):
        raise ValidationFailed(f"일반 파일이 아닙니다 (장치/FIFO/소켓은 읽지 않습니다): {path}")
    return p


def resolve_input_dir(case: Case, path: str) -> Path:
    p = resolve_case_path(case, path)
    if not p.is_dir():
        raise ValidationFailed(f"디렉터리가 아닙니다: {path}", hint="파일이면 해당 파일용 도구를 사용하세요.")
    return p


# ---------------------------------------------------------------------------
# 출력 경로 (번호 원자적 확보)
# ---------------------------------------------------------------------------

_LABEL_RE = re.compile(r"[^A-Za-z0-9_-]")


def safe_label(label: str | None, default: str) -> str:
    s = _LABEL_RE.sub("-", str(label or "")).strip("-")[:32]
    return s or default


def safe_name(name: str, default: str = "part", maxlen: int = 48) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", str(name or "")).strip("._-")[:maxlen]
    return s or default


def claim_numbered_file(directory: Path, prefix: str, suffix: str = ".json") -> Path:
    """``<directory>/<prefix>-NNN<suffix>`` 를 O_EXCL 로 확보 (동시 호출에도 번호 중복 없음)."""
    directory.mkdir(parents=True, exist_ok=True)
    for n in range(1, 100000):
        p = directory / f"{prefix}-{n:03d}{suffix}"
        if p.exists() or p.is_symlink():
            continue
        try:
            fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            continue
        os.close(fd)
        return p
    raise CaseError(f"출력 파일 번호를 확보할 수 없습니다: {directory}/{prefix}-NNN{suffix}")


def claim_numbered_dir(directory: Path, label: str) -> Path:
    """``<directory>/<label>-NNN/`` 를 mkdir 로 원자적으로 확보."""
    directory.mkdir(parents=True, exist_ok=True)
    for n in range(1, 100000):
        p = directory / f"{label}-{n:03d}"
        if p.exists() or p.is_symlink():
            continue
        try:
            os.mkdir(p, 0o755)
        except FileExistsError:
            continue
        return p
    raise CaseError(f"출력 디렉터리 번호를 확보할 수 없습니다: {directory}/{label}-NNN")


def sanitize(obj: Any) -> Any:
    """JSON/UTF-8 로 쓸 수 없는 값 정리: os.walk 의 surrogateescape 문자열(비 UTF-8 파일 이름, 예: GBK) → 대체 문자,
    bytes → \\xHH 표기. dict/list 는 재귀 처리."""
    if isinstance(obj, str):
        try:
            obj.encode("utf-8")
            return obj
        except UnicodeEncodeError:
            return obj.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    if isinstance(obj, dict):
        return {sanitize(k) if isinstance(k, str) else k: sanitize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize(v) for v in obj]
    if isinstance(obj, (bytes, bytearray)):
        return printable(bytes(obj), 400)
    return obj


class ResultFile:
    """``analysis/<prefix>-NNN.json`` 을 확보하고, 실패 시 빈 자리표시 파일을 지운다."""

    def __init__(self, case: Case, prefix: str, subdir: str = "analysis") -> None:
        self.case = case
        self.path = claim_numbered_file(case.subdir(subdir), prefix)
        self.rel = case.rel(self.path)
        self._written = False

    def write(self, payload: dict[str, Any], *, description: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        atomic_write_json(self.path, sanitize(payload))
        self._written = True
        return self.case.register_artifact(self.path, kind="triage-report", producer=PRODUCER, description=description, extra=extra)

    def discard(self) -> None:
        if not self._written:
            with contextlib.suppress(OSError):
                if self.path.exists() and self.path.stat().st_size == 0:
                    self.path.unlink()


def base_payload(tool: str, case: Case, *, schema: str, input_info: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": f"{SCHEMA_PREFIX}.{schema}/v1",
        "tool": tool,
        "producer": TOOL_VERSION,
        "case_id": case.id,
        "generated_at": utcnow_iso(),
        "input": input_info,
        "params": params,
    }


def file_info(case: Case, p: Path, *, with_hash: bool = True) -> dict[str, Any]:
    st = p.stat()
    info: dict[str, Any] = {"path": case.rel(p), "size": st.st_size, "size_human": human_size(st.st_size)}
    if with_hash and stat.S_ISREG(st.st_mode):
        info["sha256"] = sha256_file(p)
    return info


# ---------------------------------------------------------------------------
# 파일 읽기
# ---------------------------------------------------------------------------


# CPython 3.11.0–3.11.4 의 mmap.find() 는 검색 구간 바로 뒤 1바이트를 읽는다 (gh-105235, 3.11.5 에서 고침).
# 구간이 파일 끝까지이면 그 바이트는 매핑 밖이라, 파일 크기가 페이지 크기의 배수(플래시 덤프는 거의 다)이고
# 매핑 바로 뒤 페이지가 비어 있으면 SIGSEGV 로 서버 프로세스가 죽는다 (Debian 12 의 python3.11 3.11.2 에서 재현).
_MMAP_FIND_OVERREAD = (3, 11) <= sys.version_info < (3, 11, 5)


class _SafeFindMmap(mmap.mmap):
    """gh-105235 우회: 구간 끝이 매핑 끝이면 마지막 1바이트를 뺀 구간을 찾고, 끝에 붙은 위치만 따로 비교한다."""

    def find(self, sub: Any, start: Any = None, end: Any = None) -> int:  # type: ignore[override]
        size = len(self)
        s, e, _ = slice(self.tell() if start is None else start, size if end is None else end).indices(size)
        sub = bytes(sub)
        n = len(sub)
        if e < size or n < 2 or e - s < n:  # 매핑 안쪽에서 끝남 / memchr 경로 / 비교 없이 -1
            return super().find(sub, s, e)
        r = super().find(sub, s, e - 1)
        if r < 0 and self[e - n:e] == sub:
            r = e - n
        return r


@contextlib.contextmanager
def open_mmap(path: Path) -> Iterator[Any]:
    """읽기 전용 mmap. 0바이트 파일이면 빈 bytes 를 돌려준다 (mmap 은 0바이트를 매핑할 수 없음)."""
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        size = os.fstat(fd).st_size
        if size == 0:
            yield b""
            return
        mm = (_SafeFindMmap if _MMAP_FIND_OVERREAD else mmap.mmap)(fd, 0, access=mmap.ACCESS_READ)
        try:
            yield mm
        finally:
            mm.close()
    finally:
        os.close(fd)


def read_regular_file(path: Path, max_bytes: int) -> bytes | None:
    """심볼릭 링크를 따라가지 않고(O_NOFOLLOW), 블로킹 특수 파일을 열지 않고(O_NONBLOCK) 최대 max_bytes 읽기.

    일반 파일이 아니면 None.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        chunks = []
        remaining = max_bytes
        while remaining > 0:
            b = os.read(fd, min(remaining, 1 << 20))
            if not b:
                break
            chunks.append(b)
            remaining -= len(b)
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# 값 정리 / 응답 크기 제한
# ---------------------------------------------------------------------------


def clamp_int(value: Any, lo: int, hi: int, name: str) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise ValidationFailed(f"{name} 는 정수여야 합니다: {value!r}")
    return max(lo, min(hi, v))


def parse_int_arg(value: Any, name: str, *, allow_none: bool = True) -> int | None:
    """정수 인자 해석: 10진수, '0x..' 16진수, '64k'/'1M' 같은 크기 문자열 허용."""
    if value is None or (isinstance(value, str) and value.strip() in ("", "-")):
        if allow_none:
            return None
        raise ValidationFailed(f"{name} 값이 필요합니다.")
    if isinstance(value, bool):
        raise ValidationFailed(f"{name} 는 정수여야 합니다: {value!r}")
    if isinstance(value, int):
        if value < 0:
            raise ValidationFailed(f"{name} 는 0 이상이어야 합니다: {value}")
        return value
    try:
        v = parse_size(str(value).strip())
    except (PwehError, ValueError):
        raise ValidationFailed(f"{name} 값을 해석할 수 없습니다: {value!r}", hint="예: 65536, '0x10000', '64k', '1M'")
    if v < 0:
        raise ValidationFailed(f"{name} 는 0 이상이어야 합니다: {value}")
    return v


def compact_list(items: list[Any], max_results: int) -> tuple[list[Any], bool]:
    n = max(0, int(max_results))
    return items[:n], len(items) > n


def hexs(n: int | None) -> str | None:
    return None if n is None else f"0x{n:x}"


_NONPRINT_RE = re.compile(rb"[^\x20-\x7e]")


def printable(data: bytes, limit: int = 200) -> str:
    """바이트를 안전한 문자열로 (인쇄 불가 문자는 \\xHH)."""
    out = _NONPRINT_RE.sub(lambda m: f"\\x{m.group(0)[0]:02x}".encode(), data[:limit]).decode("ascii")
    if len(data) > limit:
        out += "…"
    return out


def clip(text: str, limit: int = 240) -> str:
    text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def mask_secret(value: str | None) -> str | None:
    """보고용 마스킹: 앞 2글자만 남김 (cctv-vuln-patterns.md 7.5: 보고서에는 마스킹)."""
    if value is None:
        return None
    if value == "":
        return "(빈 문자열)"
    keep = 2 if len(value) > 4 else 1
    return value[:keep] + "*" * max(3, len(value) - keep)


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def severity_key(sev: str | None) -> int:
    return SEVERITY_ORDER.get(str(sev or "info"), 5)
