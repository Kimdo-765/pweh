"""증거 이미지의 보관 기록(custody)과 증거 목록 — pweh-forensics 서버와 보고서(report.py)가 함께 쓴다.

설계: docs/design/sd-forensics.md §4·§6. 위치는 ``cases/<id>/forensics/`` 다(필요할 때 만든다)::

  images/EV-NNNN/<이름>           접수한 이미지 사본 (파일 0444, 디렉터리 0555). 복사하는 동안은 <이름>.partial, 다 쓰면 이름을 바꾼다
  images/EV-NNNN/EV-NNNN.json     접수 기록 (0444): 해시·크기·지문·접수 정보(목적·법적 근거·설치 장소 유형·역할)
  images/EV-NNNN/.intake.lock     접수 job 이 커밋할 때까지 잡는 잠금 (다른 프로세스의 정리가 진행 중인 접수를 건드리지 않게).
                                  커밋하면 지운다 — 남아 있는데 잡은 쪽이 없으면 중단된 접수의 흔적이다
  images/.claim.lock              EV 번호 확보·정리 잠금
  aborted-intakes/EV-NNNN-<시각>/  커밋하지 못한 접수(복사 중 서버가 끝남 등)를 옮겨 둔 곳 (파일 0444, 보관 기록 intake-aborted)
  custody.jsonl                   보관 기록 (해시 체인, 덧붙이기만)
  analysis/ recovered/            서버 산출물 (pweh-forensics 가 만든다)

경로 규칙(믿을 수 없는 같은 계정 프로세스가 링크를 심어도 케이스 밖에 쓰거나 장치를 열지 않게 — pweh.safeio):
- forensics/ 아래 디렉터리는 케이스 디렉터리에서 한 구성요소씩 링크를 따르지 않고 연다. 링크·파일이면 거부한다(path_outside_base).
- 파일은 그 디렉터리 fd 기준으로만 만들고(O_CREAT|O_EXCL|O_NOFOLLOW) 그 fd 로 쓰고 fchmod 한다. 경로로 다시 열거나 chmod 하지 않는다.
- 읽기는 일반 파일만(lstat → O_NOFOLLOW|O_NONBLOCK → fstat 대조) 크기 상한을 두고 한다. 장치·FIFO·링크는 읽지 않는다: lstat 에서 거부하고
  열지 않으며, lstat 과 open 사이에 그 이름에 바꿔 넣은 FIFO 는 O_NONBLOCK 으로 열려도 fstat 대조로 거부한다(중간 디렉터리는 fd 로
  고정돼 다른 곳의 장치에 닿지 않는다). 사용자가 준 경로(접수할 이미지·이미징 로그)는 경로로 열므로 safeio 모듈 설명의 한계가 있다.

보관 기록 한 줄 = 정규화 JSON(키 정렬·공백 없음): ``schema, seq(1부터 연속), ts, case_id, event, evidence_id, actor, data, prev``.
``prev`` 는 앞 줄 정규화 JSON 의 sha256, 첫 줄은 케이스 id 에 묶인 시작값이라 다른 케이스의 기록을 복사해도 깨진다.
읽을 때 체인 전체를 검증하고 하나라도 깨지면 **모두 신뢰하지 않는다**(fail closed). 같은 사건을 감사 로그에도 남긴다(서버가 rt().audit).
증거의 상태(마지막 검증, 무결성 실패, 사람 증명)는 보관 기록을 처음부터 다시 읽어 정한다 — 따로 바뀌는 색인 파일을 두지 않는다.
읽기는 공유 잠금, 덧붙이기는 배타 잠금 안에서 한다(덧붙이는 도중의 기록을 읽어 깨짐으로 오판하지 않게).

접수의 커밋 지점은 보관 기록의 ``intake`` 사건이다. 그 사건에는 해시·크기·저장 경로와 함께 빠른 지문과 접수 기록 파일의 sha256 을 남기고,
내용 도구·검증·증거 목록은 접수 기록을 이 사건(고정점으로 보호됨)과 대조한다 — 접수 기록 파일만 고쳐서는 통과하지 못한다.
한 EV 번호에는 접수 사건이 하나만 있을 수 있고, 번호는 디렉터리와 보관 기록에 나온 번호 중 가장 큰 것 + 1 이다(지운 증거의 번호를 다시 쓰지 않는다).
보관 기록에 intake 가 없는 EV 디렉터리는 중단된 접수의 흔적이 있을 때만(잡은 쪽이 없는 접수 잠금 파일, 복사 중 이름 ``*.partial``,
빈 디렉터리 — 접수 기록 파일이 있어도 같다) 다음 접수·서버 시작 때 ``aborted-intakes/`` 로 옮기고 ``intake-aborted`` 사건으로 번호를
소비한다. 흔적이 없는 디렉터리(커밋한 증거인데 보관 기록과 고정점을 함께 잃음, 사람이 만든 디렉터리 등)는 보관 기록 없이는 커밋 여부를
알 수 없으므로 옮기지 않고 증거 목록에 record-without-intake 로 남긴다(사람이 판단한다 — 번호는 디렉터리가 있으므로 다시 쓰지 않는다).

해시 체인만으로는 마지막 줄을 고치거나 잘라 내는 것을 알 수 없다. 그래서 서버는 줄을 덧붙일 때마다 그 줄의 (seq, 해시)를
보호 위치(``<state_dir>/custody/<case_id>.jsonl`` — 에이전트 수정 금지)의 고정점(anchor)에도 남기고, 읽을 때 둘을 대조한다
(고정점과 다른 줄·고정점 없는 줄·고정점보다 짧은 기록 = 깨짐). 덧붙이기는 세 단계다: 고정점에 '기록 중'(pending) 줄 → 보관 기록 →
고정점 확정. 도중에 끊기면(디스크 가득·강제 종료) 읽을 때 '기록 중' 줄을 보관 기록과 맞춰 본다 — 보관 기록에 그 줄이 그대로 있으면 확정,
없으면 기록 전 중단으로 본다. 그래서 고정점 쓰기 실패가 케이스의 보관 기록을 영구히 깨뜨리지 않는다.
보관 기록 쓰기(둘째 단계)가 사건의 커밋 지점이다: 그 뒤(확정 쓰기·정리)의 실패는 어떤 예외든 로그만 남기고 덧붙이기를 성공으로 돌려준다 —
``CustodyLog.append`` 는 사건이 남지 않았을 때만 예외를 던진다(호출자는 예외 = 커밋 안 됨으로 믿고 되돌린다).
접수 때 이미지 sha256 은 출처 원장(imported-unattested)에도 남긴다.
한계(출처 원장과 같다 — docs/safety.md §3.5·§3.6): 비밀 키가 없으므로 같은 OS 계정이 두 기록을 함께 일관되게 다시 쓰는 것은 감지하지 못한다.

이 모듈은 이미지 내용을 해석하지 않는다(파일 시스템 해석은 ``pweh.fs``). 이미지를 쓰거나 마운트하지 않는다.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import hashlib
import json
import logging
import os
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from . import safeio
from .case import Case
from .errors import PwehError, ValidationFailed
from .fsutil import utcnow_iso
from .safeio import UnsafeFile
from .safety.attestations import canonical_json

#: 로그는 stderr 로만 간다(서버의 stdout 은 MCP 채널 — mcpkit 이 'pweh' 로거를 stderr 로 설정한다).
#: 이름이 _log 인 것은 함수 인자 log(CustodyLog)와 겹치지 않게 하려는 것이다.
_log = logging.getLogger("pweh.evidence")

SCHEMA_CUSTODY = "pweh.custody/v1"
SCHEMA_EVIDENCE = "pweh.evidence/v1"
FORENSICS_DIR = "forensics"
IMAGES_DIR = "images"
QUARANTINE_DIR = "aborted-intakes"
CUSTODY_FILE = "custody.jsonl"
CUSTODY_LOCK = ".custody.lock"
CLAIM_LOCK = ".claim.lock"
INTAKE_LOCK = ".intake.lock"
PARTIAL_SUFFIX = ".partial"
IMAGING_LOG_NAME = "imaging-log.txt"
EV_RE = re.compile(r"^EV-(\d{4,6})$")
_QUARANTINE_RE = re.compile(r"^EV-(\d{4,6})-")
#: 이미지 사본 이름으로 쓸 수 없는 이름 (같은 디렉터리의 접수 기록·로그 사본·잠금·복사 중 이름과 겹침)
RESERVED_NAME_RE = re.compile(r"(?i)^(?:EV-\d+\.json|imaging-log\.txt|\.intake\.lock|.*\.partial)$")
#: 보관 기록 사건 종류 (닫힌 집합)
CUSTODY_EVENTS = ("intake", "intake-aborted", "verify", "integrity-failed", "attest", "check", "list", "extract", "evidence-list", "note")
CUSTODY_ACTORS = ("server", "agent", "human")
#: 빠른 지문: 앞·뒤 1 MiB 의 sha256 + 크기·mtime_ns
FINGERPRINT_BLOCK = 1 << 20
HASH_BLOCK = 4 << 20
HASH_ALGORITHMS = ("sha256", "md5", "sha1")
_HEX_LEN = {"md5": 32, "sha1": 40, "sha256": 64}
#: 읽기 상한 (믿을 수 없는 파일을 메모리로 읽을 때)
RECORD_MAX = 1 << 20
CUSTODY_MAX = 64 << 20
ANCHOR_MAX = 16 << 20
#: 이미징 로그에서 해시 줄 찾기. 두 모양: '알고리즘 이름 … 16진 값'(FTK Imager·ewfacquire·ewfinfo·Guymager)과
#: '16진 값 (알고리즘)'(dc3dd). 16진 값은 32·40·64자 토큰만 본다.
_HEX_TOKEN = r"\b([0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})\b"
_LOG_HASH_RX = re.compile(r"(?i)\b(md5|sha-?1|sha-?256)\b[^\n]{0,60}?" + _HEX_TOKEN)
_LOG_HASH_SUFFIX_RX = re.compile(r"(?i)" + _HEX_TOKEN + r"\s*\((md5|sha-?1|sha-?256)\)")
_LOG_TOOLS = (
    ("ftk-imager", re.compile(r"(?i)\bFTK\b.{0,10}\bImager\b|AccessData")),
    ("dc3dd", re.compile(r"(?i)\bdc3dd\b")),
    ("ewfacquire", re.compile(r"(?i)\bewfacquire\b")),
    ("ewfinfo", re.compile(r"(?i)\bewfinfo\b")),
    ("guymager", re.compile(r"(?i)\bguymager\b")),
)
#: 이미징 로그 크기 상한 (로그는 텍스트 몇 KB 다)
IMAGING_LOG_MAX = 4 << 20
#: 모든 SD 카드 포렌식 산출물(증거 목록·보고서)에 붙이는 고지 (설계 §7 — 법률 자문 아님)
FORENSICS_NOTICE = ("PWEH 는 인증·검증된 포렌식 도구가 아니다. 법적 용도라면 원본 카드를 보존하고 원본·이미지·보관 기록을 자격 있는 전문가에게 넘긴다. "
                    "녹화 내용은 열지 않았고(개수·범위·해시만), 오디오를 재생·전사하지 않았으며, 얼굴·번호판 처리와 업로드를 하지 않았다.")
#: E01(EWF) 서명 — 1차에는 raw 이미지만 받는다
EWF_SIGNATURES = (b"EVF\x09\x0d\x0a\xff\x00", b"EVF2\x0d\x0a\x81\x00", b"LVF\x09\x0d\x0a\xff\x00")
#: 앵커(고정점)가 있는 상태 — 증거 목록의 해시값 확인서에는 이 상태의 항목만 싣는다(해시가 보관 기록의 intake 사건에서 온다)
ANCHORED_STATUSES = ("ok", "unverified", "integrity-failed", "missing", "record-invalid")


class EvidenceError(PwehError):
    code = "evidence_error"


class IntegrityProblem(EvidenceError):
    """증거 사본·접수 기록이 보관 기록과 맞지 않는다 (code=integrity_failed). record=True 면 서버가 integrity-failed 사건으로 남긴다."""

    code = "integrity_failed"

    def __init__(self, message: str, *, reason: str, problems: list[str] | None = None, record: bool = True,
                 hint: str | None = None) -> None:
        super().__init__(message, code="integrity_failed",
                         hint=hint or "무결성 실패다. 이 사본은 더 쓰지 않는다 — 원본 이미지에서 다시 접수하세요(새 EV 번호).",
                         data={"reason": reason, "problems": list(problems or [])})
        self.reason = reason
        self.problems = list(problems or [])
        self.record = record


# ---------------------------------------------------------------------------
# 경로·디렉터리 (링크를 따르지 않는다)
# ---------------------------------------------------------------------------


def forensics_dir(case: Case) -> Path:
    return case.dir / FORENSICS_DIR


def strict_rel(case: Case, path: str | os.PathLike[str]) -> str:
    """케이스 상대 경로 (엄격): 케이스 디렉터리 밖이거나 중간에 심볼릭 링크가 있으면 EvidenceError(path_outside_base) — case.rel 처럼
    밖의 절대 경로를 돌려주지 않는다(fail closed). forensics 서버가 응답·보관 기록·매니페스트에 적는 경로는 모두 이것으로 만든다."""
    p = Path(os.path.abspath(os.fspath(path)))
    try:
        rel = p.relative_to(case.dir)
    except ValueError:
        raise EvidenceError(f"케이스 밖의 경로입니다: {p}", code="path_outside_base") from None
    if not rel.parts or ".." in rel.parts:
        raise EvidenceError(f"케이스 안의 경로가 아닙니다: {p}", code="path_outside_base")
    if os.path.realpath(p) != str(p):
        raise EvidenceError(f"경로 중간에 심볼릭 링크가 있습니다(따라가지 않음): {rel.as_posix()}", code="path_outside_base",
                            hint="사람이 케이스의 forensics/ 를 확인해야 한다. PWEH 는 링크를 따라 쓰거나 읽지 않는다.")
    return rel.as_posix()


def forensics_rel(*parts: str) -> str:
    """forensics/ 아래 케이스 상대 경로 문자열 (구성요소마다 이름 규칙 확인 — '..'·'/'·NUL 거부)."""
    for p in parts:
        if not p or p in (".", "..") or "/" in p or "\x00" in p:
            raise EvidenceError(f"잘못된 경로 구성요소입니다: {p!r}", code="path_outside_base")
    return "/".join((FORENSICS_DIR, *parts))


def open_forensics(case: Case, *parts: str, create: bool = False, mode: int = 0o755) -> int:
    """cases/<id>/forensics/<parts…> 디렉터리 fd (호출자가 닫는다). 구성요소마다 O_DIRECTORY|O_NOFOLLOW — 링크·파일이면
    EvidenceError(path_outside_base). 없으면 create 가 아니면 FileNotFoundError."""
    try:
        return safeio.open_dir_chain(case.dir, [FORENSICS_DIR, *parts], create=create, mode=mode)
    except UnsafeFile as exc:
        where = "/".join((FORENSICS_DIR, *parts))
        raise EvidenceError(f"{where} 경로에 실제 디렉터리가 아닌 것(심볼릭 링크·파일)이 있습니다 — 따라가지 않습니다: {exc.message}",
                            code="path_outside_base",
                            hint="사람이 케이스의 forensics/ 를 확인해야 한다(링크를 지우고 실제 디렉터리로). PWEH 는 링크를 따라 쓰거나 읽지 않는다.") from exc


def ensure_forensics_dir(case: Case) -> Path:
    """forensics/images 를 만든다(링크를 따르지 않는다) → forensics/ 경로."""
    os.close(open_forensics(case, IMAGES_DIR, create=True))
    return forensics_dir(case)


def is_forensics_path(case: Case, path: str | Path) -> bool:
    """케이스의 forensics/ 아래(또는 그 자체)인가 — 심볼릭 링크를 풀어 판단한다."""
    try:
        p = Path(path).resolve()
        base = forensics_dir(case).resolve()
    except (OSError, RuntimeError):
        return True  # 판단할 수 없으면 막는 쪽으로
    return p == base or base in p.parents


def under_any_case_forensics(path: str | Path, cases_root: str | Path) -> bool:
    """``<cases_root>/<케이스>/forensics`` 아래인가 (case_import_file 등 다른 케이스의 증거를 우회 복사하지 못하게).

    링크를 푼 경로와 푼 전 경로(정규화만)를 모두 본다 — forensics/ 자체가 다른 곳을 가리키는 링크여도 그 아래 경로로 부르면 막는다."""
    def _hit(p: Path, root: Path) -> bool:
        try:
            rel = p.relative_to(root)
        except ValueError:
            return False
        return len(rel.parts) >= 2 and rel.parts[1] == FORENSICS_DIR

    try:
        root_abs = Path(os.path.abspath(os.fspath(cases_root)))
        if _hit(Path(os.path.abspath(os.fspath(path))), root_abs):
            return True
        return _hit(Path(path).resolve(), Path(cases_root).resolve())
    except (OSError, RuntimeError, ValueError):
        return False


def contains_forensics_dir(case: Case, directory: str | Path) -> bool:
    """디렉터리를 훑으면 forensics/ 를 지나게 되는가 (케이스 루트 등)."""
    try:
        d = Path(directory).resolve()
        base = forensics_dir(case).resolve()
    except (OSError, RuntimeError):
        return True
    return d == base or d in base.parents


def evidence_dir(case: Case, evidence_id: str) -> Path:
    check_evidence_id(evidence_id)
    return forensics_dir(case) / IMAGES_DIR / evidence_id


def check_evidence_id(evidence_id: Any) -> str:
    if not isinstance(evidence_id, str) or not EV_RE.match(evidence_id):
        raise ValidationFailed(f"잘못된 증거 id: {evidence_id!r}", hint="예: EV-0001 (forensics_evidence_list 로 확인)")
    return evidence_id


def _ev_num(evidence_id: str) -> int:
    m = EV_RE.match(evidence_id)
    return int(m.group(1)) if m else 0


def _list_dir(fd: int) -> list[tuple[str, bool]]:
    """디렉터리 fd 의 항목 (이름, 실제 디렉터리인가 — 링크는 따르지 않음)."""
    with os.scandir(fd) as it:
        return [(e.name, e.is_dir(follow_symlinks=False)) for e in it]


def evidence_ids(case: Case) -> list[str]:
    """forensics/images 의 EV 디렉터리 (실제 디렉터리만 — 링크는 세지 않는다). images/ 가 링크면 EvidenceError(path_outside_base)."""
    try:
        fd = open_forensics(case, IMAGES_DIR)
    except FileNotFoundError:
        return []
    try:
        return sorted((n for n, is_dir in _list_dir(fd) if is_dir and EV_RE.match(n)), key=_ev_num)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# 입력 이미지 검사·해시·지문
# ---------------------------------------------------------------------------


_RAW_DISK_RX = re.compile(r"(?i)^\\\\\?\\(?:PhysicalDrive|Volume|[A-Z]:)")
_KERNEL_TOPS = ("/dev", "/proc", "/sys")


def _under_kernel_dirs(p: str) -> bool:
    return any(p == top or p.startswith(top + "/") for top in _KERNEL_TOPS)


def _source_path(raw_in: Any, what: str) -> tuple[str, Path]:
    raw = str(raw_in) if raw_in is not None else ""
    if not raw.strip():
        raise ValidationFailed(f"{what} 경로가 비어 있습니다.")
    if "\x00" in raw:
        raise ValidationFailed(f"{what} 경로에 NUL 문자가 있습니다.")
    if raw.startswith("\\\\.\\") or raw.startswith("//./") or raw.startswith("//?/") or _RAW_DISK_RX.match(raw):
        raise ValidationFailed("원시 디스크 경로는 받지 않습니다.", hint="사람이 쓰기 방지 장치를 거쳐 이미징 도구로 만든 이미지 파일을 주세요.")
    p = Path(raw).expanduser()
    if _under_kernel_dirs(os.path.abspath(p)):
        raise ValidationFailed("장치·커널 파일은 받지 않습니다.", hint="PWEH 는 원시 디스크를 열지 않는다. 이미지 파일을 주세요.")
    try:
        real = os.path.realpath(p, strict=True)
    except OSError as exc:
        raise ValidationFailed(f"{what} 파일을 열 수 없습니다: {raw} ({exc.strerror or exc})") from exc
    if _under_kernel_dirs(real):
        raise ValidationFailed("장치·커널 파일은 받지 않습니다.", hint="PWEH 는 원시 디스크를 열지 않는다. 이미지 파일을 주세요.")
    return raw, Path(real)


def _open_source(raw: str, real: Path, what: str) -> tuple[int, os.stat_result]:
    """링크를 푼 실제 경로를 safeio.open_regular 로 연다 (lstat 이 일반 파일이 아니면 열지 않는다)."""
    try:
        lst = os.lstat(real)
    except OSError as exc:
        raise ValidationFailed(f"{what} 파일을 열 수 없습니다: {raw} ({exc.strerror or exc})") from exc
    if stat.S_ISDIR(lst.st_mode):
        raise ValidationFailed(f"디렉터리입니다 ({what} 파일이 필요합니다): {raw}")
    if not stat.S_ISREG(lst.st_mode):
        raise ValidationFailed(f"일반 파일이 아닙니다 (장치·FIFO·소켓은 읽지 않습니다): {raw}")
    try:
        return safeio.open_regular(real, what=what)
    except UnsafeFile as exc:
        raise ValidationFailed(f"{what} 파일이 확인하는 동안 바뀌었거나 일반 파일이 아닙니다: {raw}",
                               hint="원본을 다른 프로그램이 바꾸지 않는지 확인하고 다시 접수하세요.") from exc
    except OSError as exc:
        raise ValidationFailed(f"{what} 파일을 열 수 없습니다: {raw} ({exc.strerror or exc})") from exc


def open_image_source(path: str | Path) -> tuple[int, os.stat_result, Path]:
    """접수할 이미지를 한 번 연다 → (fd, fstat, 실제로 연 파일의 경로). 호출자가 fd 를 닫는다.

    장치(/dev/*, \\\\.\\*), FIFO, 소켓, 디렉터리, 빈 파일, E01 은 거부한다(ValidationFailed — PWEH 는 원시 디스크를 열지 않는다).
    경로의 링크는 한 번 풀고, 푼 경로는 safeio.open_regular 로 연다(lstat 이 일반 파일이 아니면 열지 않음, 연 fd 의 fstat 대조).
    이후의 해시·복사는 이 fd 로만, 이 fstat 의 크기만큼만 한다(경로를 다시 열지 않는다)."""
    raw, real = _source_path(path, "이미지")
    fd, st = _open_source(raw, real, "이미지")
    try:
        if st.st_size <= 0:
            raise ValidationFailed(f"빈 파일입니다: {raw}")
        head = safeio.read_fd(fd, 16)
        if any(head.startswith(sig) for sig in EWF_SIGNATURES):
            raise ValidationFailed(
                "E01(EWF) 이미지는 아직 받지 않습니다.",
                hint="이미징 도구에서 raw(dd) 형식으로 다시 내보내거나 ewfexport 로 raw 로 바꾼 뒤 접수하세요(원본 E01 과 로그는 따로 보존).",
            )
        actual = safeio.fd_real_path(fd)
        return fd, st, Path(actual) if actual else real
    except BaseException:
        os.close(fd)
        raise


def check_image_source(path: str | Path) -> Path:
    """접수할 이미지가 일반 파일인지 확인한다(열어서 확인하고 닫는다) → 실제 경로. 접수는 open_image_source 의 fd 를 쓴다."""
    fd, _, real = open_image_source(path)
    os.close(fd)
    return real


def new_hashers() -> dict[str, Any]:
    return {alg: hashlib.new(alg) for alg in HASH_ALGORITHMS}


def hash_stream(src: Path, *, cancel: Callable[[], bool] | None = None, progress: Callable[[int], None] | None = None,
                block: int = HASH_BLOCK) -> dict[str, Any]:
    """파일을 safeio.open_regular 로 열어 연 fd 로 한 번 읽으며 sha256·md5·sha1 을 계산한다(연 때의 크기만큼).

    ``cancel()`` 이 참이면 EvidenceError(code='cancelled'). 반환: {size, sha256, md5, sha1}.
    """
    fd, st = safeio.open_regular(src, what="파일")

    def check() -> None:
        if cancel is not None and cancel():
            raise EvidenceError("작업이 취소되었습니다.", code="cancelled")

    try:
        hs = safeio.hash_fd(fd, st.st_size, algorithms=HASH_ALGORITHMS, check=check, chunk=block,
                            progress=(lambda d, t: progress(d)) if progress is not None else None)
    finally:
        os.close(fd)
    return {"size": st.st_size, **hs}


def fingerprint_fd(fd: int, st: os.stat_result) -> dict[str, Any]:
    """연 fd 로 만든 빠른 지문: 크기·mtime_ns(fstat)·앞 1 MiB·뒤 1 MiB 의 sha256."""
    size = st.st_size
    head = safeio.read_fd(fd, FINGERPRINT_BLOCK, offset=0)
    tail = safeio.read_fd(fd, FINGERPRINT_BLOCK, offset=size - FINGERPRINT_BLOCK) if size > FINGERPRINT_BLOCK else head
    return {
        "size": size,
        "mtime_ns": st.st_mtime_ns,
        "head_sha256": hashlib.sha256(head).hexdigest(),
        "tail_sha256": hashlib.sha256(tail).hexdigest(),
    }


def fingerprint(path: Path) -> dict[str, Any]:
    """빠른 지문 (경로를 safeio.open_regular 로 열어 fd 로 읽는다). 내용 도구는 open_checked 의 fd 로 확인한다."""
    fd, st = safeio.open_regular(path, what="증거 사본")
    try:
        return fingerprint_fd(fd, st)
    finally:
        os.close(fd)


def fingerprint_problems_fd(expected: dict[str, Any], fd: int, st: os.stat_result) -> list[str]:
    """보관 기록(접수 때)의 지문과 연 fd 의 지금 지문을 비교한다. 문제 목록(비어 있으면 일치)."""
    try:
        now = fingerprint_fd(fd, st)
    except OSError as exc:
        return [f"파일을 읽을 수 없음: {exc.strerror or exc}"]
    problems = [f"{key} 다름" for key in ("size", "mtime_ns", "head_sha256", "tail_sha256") if expected.get(key) != now.get(key)]
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o222:
        problems.append(f"쓰기 권한이 생김({mode:o})")
    return problems


def fingerprint_problems(expected: dict[str, Any], path: Path) -> list[str]:
    """접수 때 지문과 지금 파일을 비교한다 (경로를 안전하게 열어 fd 로). 열 수 없거나 일반 파일이 아니면 그것이 문제다."""
    try:
        fd, st = safeio.open_regular(path, what="증거 사본")
    except UnsafeFile as exc:
        return [f"일반 파일이 아님: {exc.message}"]
    except OSError as exc:
        return [f"파일을 읽을 수 없음: {exc.strerror or exc}"]
    try:
        return fingerprint_problems_fd(expected, fd, st)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# 이미징 로그
# ---------------------------------------------------------------------------


def _alg_name(raw: str) -> str:
    return raw.lower().replace("-", "")


def parse_imaging_log(text: str) -> dict[str, Any]:
    """이미징 도구 로그(FTK Imager·dc3dd·ewfacquire·ewfinfo·Guymager)에서 도구와 해시 값을 찾는다.

    반환: {tool, hashes: {alg: [값…]}(나온 순서, 중복 제거), conflicts: [alg…](한 알고리즘에 다른 값이 둘 이상)}.
    원본 해시와 검증 해시가 같은 값으로 두 번 나오는 것은 정상이다. 해시 값의 길이가 알고리즘과 맞지 않으면 버린다.
    """
    tool = "unknown"
    for name, rx in _LOG_TOOLS:
        if rx.search(text):
            tool = name
            break
    hashes: dict[str, list[str]] = {}
    found = [(m.start(), _alg_name(m.group(1)), m.group(2)) for m in _LOG_HASH_RX.finditer(text)]
    found += [(m.start(), _alg_name(m.group(2)), m.group(1)) for m in _LOG_HASH_SUFFIX_RX.finditer(text)]
    for _, alg, raw in sorted(found):
        val = raw.lower()
        if len(val) != _HEX_LEN[alg]:
            continue
        lst = hashes.setdefault(alg, [])
        if val not in lst:
            lst.append(val)
    conflicts = sorted(alg for alg, vals in hashes.items() if len(vals) > 1)
    return {"tool": tool, "hashes": hashes, "conflicts": conflicts}


def compare_log_hashes(log: dict[str, Any], hashes: dict[str, Any]) -> dict[str, Any]:
    """이미징 로그의 해시와 접수 때 계산한 해시를 비교한다.

    status: match(로그에 있는 알고리즘이 모두 일치) | mismatch(하나라도 다름 — 값이 여럿이면 모두 달라야 다름) | no-hashes(로그에 해시 없음).
    """
    found = log.get("hashes") or {}
    details: dict[str, str] = {}
    for alg in HASH_ALGORITHMS:
        vals = found.get(alg)
        if not vals:
            continue
        details[alg] = "match" if hashes.get(alg) in vals else "mismatch"
    if not details:
        return {"status": "no-hashes", "details": {}}
    status = "mismatch" if any(v == "mismatch" for v in details.values()) else "match"
    return {"status": status, "details": details}


def read_imaging_log(path: str | Path, *, refuse: Callable[[Path], None] | None = None) -> tuple[Path, str]:
    """이미징 로그 파일을 읽는다(일반 파일, 4 MiB 이하, UTF-8/UTF-16/latin-1) → (실제 경로, 텍스트).

    refuse(path) 는 읽기 전에 부른다(케이스·상태 폴더 안의 파일 거부 등) — 링크를 푼 경로와 실제로 연 fd 의 경로 둘 다.
    연 fd 로 상한까지만 읽는다(크기를 확인한 뒤 파일이 커져도 상한을 넘겨 읽지 않는다)."""
    raw, real = _source_path(path, "이미징 로그")
    if refuse is not None:
        refuse(real)
    fd, st = _open_source(raw, real, "이미징 로그")
    try:
        actual = safeio.fd_real_path(fd)
        if refuse is not None and actual and actual != str(real):
            refuse(Path(actual))
        if st.st_size > IMAGING_LOG_MAX:
            raise ValidationFailed(f"이미징 로그가 너무 큽니다({st.st_size} 바이트, 상한 {IMAGING_LOG_MAX}).")
        data = safeio.read_fd(fd, IMAGING_LOG_MAX + 1)
        if len(data) > IMAGING_LOG_MAX:
            raise ValidationFailed(f"이미징 로그가 읽는 동안 상한({IMAGING_LOG_MAX} 바이트)을 넘게 자랐습니다.")
    finally:
        os.close(fd)
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = data.decode("utf-16", "replace")
    else:
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = data.decode("latin-1")
    return real, text


# ---------------------------------------------------------------------------
# 보관 기록 (custody.jsonl)
# ---------------------------------------------------------------------------


def _genesis(case_id: str) -> str:
    return hashlib.sha256(f"pweh-custody:{case_id}".encode()).hexdigest()


def _line_hash(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def entry_hash(entry: dict[str, Any]) -> str:
    """보관 기록 한 줄(읽은 사건 dict)의 해시 = 다음 줄의 prev = 고정점 값."""
    return _line_hash(canonical_json(entry))


def parse_custody(case_id: str, raw: bytes) -> tuple[list[dict[str, Any]], str | None]:
    """보관 기록 바이트를 검증하며 읽는다. 반환: (항목, 깨진 이유 | None). 깨졌으면 항목을 비운다(fail closed)."""
    if not raw:
        return [], None
    if not raw.endswith(b"\n"):
        return [], "마지막 줄이 잘렸다(줄바꿈 없음)"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return [], "UTF-8 이 아닌 내용"
    entries: list[dict[str, Any]] = []
    prev = _genesis(case_id)
    for seq, line in enumerate(text.split("\n")[:-1], 1):
        try:
            entry = json.loads(line)
        except ValueError:
            return [], f"{seq}번째 줄을 해석할 수 없다"
        if not isinstance(entry, dict):
            return [], f"{seq}번째 줄이 객체가 아니다"
        try:
            canonical = canonical_json(entry)
        except ValidationFailed:
            return [], f"{seq}번째 줄을 정규화할 수 없다"
        if canonical != line:
            return [], f"{seq}번째 줄이 정규화 JSON 이 아니다(수정됨?)"
        if entry.get("schema") != SCHEMA_CUSTODY or entry.get("case_id") != case_id:
            return [], f"{seq}번째 줄의 schema/case_id 가 다르다"
        if entry.get("seq") != seq:
            return [], f"{seq}번째 줄의 seq 가 {entry.get('seq')!r} 다(불연속)"
        if entry.get("prev") != prev:
            return [], f"{seq}번째 줄의 prev 가 앞 줄의 해시와 다르다"
        if entry.get("event") not in CUSTODY_EVENTS:
            return [], f"{seq}번째 줄의 event 가 잘못되었다: {entry.get('event')!r}"
        ev = entry.get("evidence_id")
        if ev is not None and (not isinstance(ev, str) or not EV_RE.match(ev)):
            return [], f"{seq}번째 줄의 evidence_id 가 잘못되었다"
        entries.append(entry)
        prev = _line_hash(line)
    return entries, None


def _parse_anchor_lines(raw: bytes) -> tuple[list[tuple[int, str]], tuple[int, str] | None, str | None]:
    """고정점 파일 → (확정된 고정점 [(seq, hash)], 마지막 줄의 '기록 중' 고정점 | None, 깨진 이유)."""
    if not raw:
        return [], None, None
    if not raw.endswith(b"\n"):
        return [], None, "고정점 파일의 마지막 줄이 잘렸다"
    try:
        lines = raw.decode("utf-8").split("\n")[:-1]
    except UnicodeDecodeError:
        return [], None, "고정점 파일이 UTF-8 이 아니다"
    out: list[tuple[int, str]] = []
    pending: tuple[int, str] | None = None
    for i, line in enumerate(lines, 1):
        try:
            d = json.loads(line)
        except ValueError:
            return [], None, f"고정점 {i}번째 줄을 해석할 수 없다"
        if not isinstance(d, dict) or d.get("seq") != i or not isinstance(d.get("hash"), str) or len(d["hash"]) != 64:
            return [], None, f"고정점 {i}번째 줄의 모양이 다르다"
        extra = set(d) - {"seq", "hash", "pending"}
        if extra or ("pending" in d and d["pending"] is not True):
            return [], None, f"고정점 {i}번째 줄의 모양이 다르다"
        if d.get("pending"):
            if i != len(lines):
                return [], None, f"고정점 {i}번째 줄의 '기록 중' 표시가 마지막 줄이 아니다"
            pending = (i, d["hash"])
        else:
            out.append((i, d["hash"]))
    return out, pending, None


def parse_anchors(raw: bytes) -> tuple[list[tuple[int, str]], str | None]:
    """고정점 파일: 줄마다 정규화 JSON {seq, hash}(마지막 줄은 {seq, hash, pending: true} 일 수 있다). seq 는 1부터 연속이어야 한다.
    반환: (확정된 고정점 [(seq, hash)], 깨진 이유)."""
    anchors, _, broken = _parse_anchor_lines(raw)
    return anchors, broken


def _anchor_line(seq: int, digest: str, *, pending: bool = False) -> bytes:
    d: dict[str, Any] = {"seq": seq, "hash": digest}
    if pending:
        d["pending"] = True
    return canonical_json(d).encode("utf-8") + b"\n"


class CustodyLog:
    """케이스별 보관 기록. 여러 프로세스가 덧붙일 수 있으므로 덧붙이기(읽기 + 검증 + 쓰기)는 배타 잠금, 읽기는 공유 잠금 안에서 한다.

    ``anchor_dir`` 를 주면(서버·보고서는 ``<state_dir>/custody``) 덧붙일 때 고정점을 함께 쓰고 읽을 때 대조한다.
    forensics/·custody.jsonl·고정점은 링크를 따르지 않고 일반 파일만 연다(아니면 깨짐 — fail closed).
    """

    def __init__(self, case: Case, anchor_dir: str | Path | None = None) -> None:
        self.case = case
        self.anchor_dir = Path(anchor_dir) if anchor_dir is not None else None

    @property
    def anchor_path(self) -> Path | None:
        return self.anchor_dir / f"{self.case.id}.jsonl" if self.anchor_dir is not None else None

    @property
    def path(self) -> Path:
        return forensics_dir(self.case) / CUSTODY_FILE

    # -- 고정점 --------------------------------------------------------------
    def _anchor_fd(self, *, create: bool) -> int | None:
        """고정점 디렉터리 fd (<state_dir>/custody — 상태 폴더 아래는 링크를 따르지 않는다). 없으면 None (create 면 0700 으로 만든다)."""
        if self.anchor_dir is None:
            return None
        parent, name = self.anchor_dir.parent, self.anchor_dir.name
        if create:
            parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = safeio.open_dir_chain(parent, [name], create=create, mode=0o700)
        except FileNotFoundError:
            if create:
                raise
            return None
        if create:
            with contextlib.suppress(OSError):
                os.fchmod(fd, 0o700)
        return fd

    def _read_anchor_raw(self, afd: int | None) -> tuple[bytes, str | None]:
        if afd is None:
            return b"", None
        try:
            return safeio.read_regular(f"{self.case.id}.jsonl", dir_fd=afd, max_bytes=ANCHOR_MAX, what="고정점"), None
        except FileNotFoundError:
            return b"", None
        except PwehError as exc:  # UnsafeFile·너무 큼
            return b"", f"고정점을 읽을 수 없다: {exc.message}"
        except OSError as exc:
            return b"", f"고정점을 읽을 수 없다: {exc.strerror or exc}"

    def _anchor_state(self, entries: list[dict[str, Any]], raw: bytes) -> tuple[list[tuple[int, str]], str | None]:
        """고정점을 보관 기록과 대조한다 → (보관 기록 줄마다의 확정 고정점, 깨진 이유). '기록 중' 줄은 보관 기록과 맞춰 본다."""
        anchors, pending, broken = _parse_anchor_lines(raw)
        if broken:
            return [], broken
        n = len(entries)
        if pending is not None:
            pseq, phash = pending
            if n == pseq and entry_hash(entries[-1]) == phash:
                anchors = anchors + [pending]  # 보관 기록에 그 줄이 있다 — 확정 표시만 못 했다
            elif n != pseq - 1:
                return [], f"고정점의 '기록 중' 표시({pseq}번째)가 보관 기록({n}줄)과 맞지 않는다"
            # n == pseq - 1: 보관 기록을 쓰기 전에 중단됐다 — '기록 중' 줄은 없는 것으로 본다
        if len(anchors) > n:
            return [], f"보관 기록이 고정점보다 짧다({n} < {len(anchors)} — 잘림)"
        if len(anchors) < n:
            return [], (f"고정점이 없는 보관 기록 줄이 있다({len(anchors) + 1}번째부터 — 서버 밖에서 덧붙였거나 고정점 파일이 "
                        "바뀌었다. 서버의 덧붙이기는 '기록 중' 고정점을 먼저 쓰므로 중단돼도 이렇게 되지 않는다)")
        for (seq, h), e in zip(anchors, entries):
            if entry_hash(e) != h:
                return [], f"{seq}번째 줄이 고정점과 다르다(수정됨)"
        return anchors, None

    # -- 읽기 ----------------------------------------------------------------
    def _read_custody_raw(self, ffd: int) -> tuple[bytes, str | None]:
        try:
            return safeio.read_regular(CUSTODY_FILE, dir_fd=ffd, max_bytes=CUSTODY_MAX, what="보관 기록"), None
        except FileNotFoundError:
            return b"", None
        except PwehError as exc:  # UnsafeFile(장치·FIFO·링크)·너무 큼
            return b"", f"보관 기록을 읽을 수 없다: {exc.message}"
        except OSError as exc:
            return b"", f"보관 기록을 읽을 수 없다: {exc.strerror or exc}"

    def _parse_all(self, raw: bytes) -> tuple[list[dict[str, Any]], list[tuple[int, str]], str | None]:
        entries, broken = parse_custody(self.case.id, raw)
        if broken:
            return [], [], broken
        if self.anchor_dir is None:
            return entries, [], None
        try:
            afd = self._anchor_fd(create=False)
        except UnsafeFile as exc:
            return [], [], f"고정점 위치가 실제 디렉터리가 아니다: {exc.message}"
        except OSError as exc:
            return [], [], f"고정점 위치를 열 수 없다: {exc.strerror or exc}"
        try:
            araw, broken = self._read_anchor_raw(afd)
        finally:
            if afd is not None:
                os.close(afd)
        if broken:
            return [], [], broken
        anchors, broken = self._anchor_state(entries, araw)
        if broken:
            return [], [], broken
        return entries, anchors, None

    def read(self) -> tuple[list[dict[str, Any]], str | None]:
        """(항목, 깨진 이유 | None). forensics/ 가 없으면 빈 기록(고정점이 있으면 잘림으로 깨짐). 디렉터리를 만들지 않는다."""
        try:
            ffd = open_forensics(self.case)
        except FileNotFoundError:
            entries, _, broken = self._parse_all(b"")
            return entries, broken
        except EvidenceError as exc:
            return [], f"forensics/ 가 실제 디렉터리가 아니다(심볼릭 링크 등) — 보관 기록을 믿지 않는다: {exc.message}"
        except OSError as exc:
            return [], f"forensics/ 를 열 수 없다: {exc.strerror or exc}"
        try:
            with contextlib.ExitStack() as stack:
                try:
                    stack.enter_context(safeio.locked_at(ffd, CUSTODY_LOCK, shared=True))
                except UnsafeFile as exc:
                    return [], f"보관 기록 잠금 파일이 일반 파일이 아니다: {exc.message}"
                except OSError:
                    pass  # 잠금 파일을 만들 수 없는 읽기 전용 위치 — 잠금 없이 읽는다
                raw, broken = self._read_custody_raw(ffd)
                if broken:
                    return [], broken
                entries, _, broken = self._parse_all(raw)
                return entries, broken
        finally:
            os.close(ffd)

    def verify(self) -> dict[str, Any]:
        """{ok, count, head(마지막 줄 해시 | null), detail?}."""
        return chain_summary(*self.read())

    def entries(self) -> list[dict[str, Any]]:
        entries, broken = self.read()
        if broken:
            raise EvidenceError(f"보관 기록이 깨졌습니다: {broken}", code="custody_broken",
                                hint="깨진 보관 기록은 신뢰하지 않는다(fail closed). 사람이 원인을 확인해야 한다 — PWEH 는 기록을 고치지 않는다.")
        return entries

    # -- 덧붙이기 ------------------------------------------------------------
    def append(self, event: str, *, evidence_id: str | None, data: dict[str, Any], actor: str = "server",
               check: Callable[[list[dict[str, Any]]], None] | None = None) -> dict[str, Any]:
        """사건 한 줄을 덧붙인다(배타 잠금). check(entries) 는 잠금 안에서 쓰기 전에 부른다 — 예외를 던지면 쓰지 않는다
        (예: 같은 EV 번호의 두 번째 접수 거부). 고정점은 '기록 중' → 보관 기록 → 확정 순서로 쓴다(_append_anchored).

        커밋 지점은 보관 기록(custody.jsonl) 쓰기다. 예외를 던지는 것은 사건이 남지 않았을 때뿐이다: 그 뒤의 실패(고정점 확정 쓰기,
        fd 닫기·잠금 풀기)는 어떤 예외든 로그만 남기고 사건을 돌려준다 — 호출자(접수)는 예외를 '커밋 안 됨'으로 믿고 되돌리기 때문이다."""
        if event not in CUSTODY_EVENTS:
            raise ValidationFailed(f"잘못된 보관 기록 사건: {event!r}")
        if actor not in CUSTODY_ACTORS:
            raise ValidationFailed(f"잘못된 actor: {actor!r}")
        if evidence_id is not None:
            check_evidence_id(evidence_id)
        ffd = open_forensics(self.case, create=True)
        committed = False
        try:
            with safeio.locked_at(ffd, CUSTODY_LOCK):
                raw, broken = self._read_custody_raw(ffd)
                entries: list[dict[str, Any]] = []
                anchors: list[tuple[int, str]] = []
                if not broken:
                    entries, anchors, broken = self._parse_all(raw)
                if broken:
                    raise EvidenceError(f"보관 기록이 깨져 덧붙이지 않습니다: {broken}", code="custody_broken",
                                        hint="깨진 기록에는 쓰지 않는다(fail closed). 사람이 원인을 확인해야 한다.")
                if check is not None:
                    check(entries)
                prev = entry_hash(entries[-1]) if entries else _genesis(self.case.id)
                entry = {"schema": SCHEMA_CUSTODY, "seq": len(entries) + 1, "ts": utcnow_iso(), "case_id": self.case.id,
                         "event": event, "evidence_id": evidence_id, "actor": actor, "data": data, "prev": prev}
                line = canonical_json(entry)
                digest = _line_hash(line)
                if self.anchor_dir is None:
                    safeio.atomic_write_at(ffd, CUSTODY_FILE, raw + line.encode("utf-8") + b"\n", 0o644)
                else:
                    self._append_anchored(ffd, raw, line, entry["seq"], digest, anchors)  # 커밋 뒤에는 예외를 던지지 않는다
                committed = True
        except Exception:
            if not committed:
                raise
            # 사건은 커밋됐다 — 잠금 풀기(flock·close) 실패로 '커밋 안 됨'처럼 보이게 하지 않는다
            _log.warning("보관 기록 덧붙이기 뒤 잠금 정리 실패(사건은 커밋됨): case=%s seq=%s", self.case.id, entry["seq"], exc_info=True)
        finally:
            try:
                os.close(ffd)
            except Exception:  # noqa: BLE001 - 디렉터리 fd 닫기 실패는 덧붙이기의 성패와 무관하다
                _log.warning("forensics/ 디렉터리 fd 닫기 실패: case=%s", self.case.id, exc_info=True)
        entry["hash"] = digest
        return entry

    def _append_anchored(self, ffd: int, raw: bytes, line: str, seq: int, digest: str, anchors: list[tuple[int, str]]) -> None:
        """고정점과 함께 덧붙인다: 1) 고정점에 '기록 중' 줄 → 2) 보관 기록(커밋 지점) → 3) 고정점 확정.

        1·2 가 실패하면 그 예외를 그대로 올린다(사건이 남지 않았다). 2 가 실패하면 '기록 중' 줄을 거두고, 못 거둬도(어떤 예외든 삼키고
        원래 예외를 올린다) 읽을 때 기록 전 중단으로 본다. 2 가 끝나면 사건은 커밋됐다: 3(확정 쓰기와 고정점 디렉터리 fd 닫기)에서 나는
        예외는 OSError 뿐 아니라 무엇이든(RuntimeError 등) 로그만 남기고 올리지 않는다 — '기록 중' 줄이 보관 기록의 마지막 줄과 맞으므로
        읽을 때 확정으로 보고, 다음 덧붙이기가 확정 줄로 다시 쓴다."""
        name = f"{self.case.id}.jsonl"
        try:
            afd = self._anchor_fd(create=True)
        except UnsafeFile as exc:
            raise EvidenceError(f"고정점 위치가 실제 디렉터리가 아니어서 덧붙이지 않습니다: {exc.message}", code="custody_broken") from exc
        assert afd is not None
        try:
            base = b"".join(_anchor_line(s, h) for s, h in anchors)
            # 1) '기록 중' 고정점 — 여기서 실패하면 아무것도 바뀌지 않는다
            safeio.atomic_write_at(afd, name, base + _anchor_line(seq, digest, pending=True), 0o600)
            # 2) 보관 기록(커밋 지점) — 실패하면 '기록 중' 줄을 거둔다(못 거둬도 읽을 때 기록 전 중단으로 본다)
            try:
                safeio.atomic_write_at(ffd, CUSTODY_FILE, raw + line.encode("utf-8") + b"\n", 0o644)
            except BaseException:
                try:
                    safeio.atomic_write_at(afd, name, base, 0o600)
                except Exception:  # noqa: BLE001 - 원래 예외(기록 실패)를 올린다
                    _log.warning("'기록 중' 고정점을 거두지 못함(읽을 때 기록 전 중단으로 본다): case=%s seq=%d", self.case.id, seq, exc_info=True)
                raise
            # 3) 확정 — 사건은 이미 커밋됐다. 실패해도(어떤 예외든) '기록 중' 줄이 보관 기록과 맞으므로 읽을 때 확정으로 본다
            try:
                safeio.atomic_write_at(afd, name, base + _anchor_line(seq, digest), 0o600)
            except Exception:  # noqa: BLE001 - 커밋한 사건을 실패로 돌려주지 않는다
                _log.warning("고정점 확정 쓰기 실패(사건은 커밋됨 — 읽을 때 '기록 중' 줄로 확정): case=%s seq=%d", self.case.id, seq, exc_info=True)
        finally:
            try:
                os.close(afd)
            except Exception:  # noqa: BLE001 - 고정점 디렉터리 fd 닫기 실패는 덧붙이기의 성패와 무관하다(1·2 의 예외는 그대로 올라간다)
                _log.warning("고정점 디렉터리 fd 닫기 실패: case=%s", self.case.id, exc_info=True)


def chain_summary(entries: list[dict[str, Any]], broken: str | None) -> dict[str, Any]:
    """CustodyLog.read() 결과 → {ok, count, head, detail?}."""
    if broken:
        return {"ok": False, "count": 0, "head": None, "detail": broken}
    return {"ok": True, "count": len(entries), "head": entry_hash(entries[-1]) if entries else None}


# ---------------------------------------------------------------------------
# 접수 기록·EV 번호
# ---------------------------------------------------------------------------


def record_path(case: Case, evidence_id: str) -> Path:
    return evidence_dir(case, evidence_id) / f"{evidence_id}.json"


def record_bytes(record: dict[str, Any]) -> bytes:
    """접수 기록 파일의 바이트 (이 바이트의 sha256 이 보관 기록 intake 사건의 record_sha256)."""
    return (json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_record(case: Case, evidence_id: str, record: dict[str, Any]) -> Path:
    """접수 기록을 EV 디렉터리 fd 기준 O_EXCL 로 한 번만 쓰고 fd 로 0444 로 바꾼다."""
    fd = open_forensics(case, IMAGES_DIR, evidence_id)
    try:
        safeio.write_new(fd, f"{evidence_id}.json", record_bytes(record), final_mode=0o444)
    finally:
        os.close(fd)
    return record_path(case, evidence_id)


def stored_name(record: dict[str, Any], evidence_id: str) -> str:
    """접수 기록의 저장 경로 → EV 디렉터리 안의 파일 이름. 'forensics/images/<EV>/<이름>' 모양이 아니면 EvidenceError."""
    stored = (record.get("stored") or {}).get("path")
    if not isinstance(stored, str):
        raise EvidenceError(f"접수 기록에 저장 경로가 없습니다({evidence_id}).", code="integrity_failed")
    prefix = f"{FORENSICS_DIR}/{IMAGES_DIR}/{evidence_id}/"
    name = stored[len(prefix):] if stored.startswith(prefix) else ""
    if not name or "/" in name or name in (".", "..") or "\x00" in name or RESERVED_NAME_RE.match(name):
        raise EvidenceError(f"접수 기록의 저장 경로가 증거 디렉터리 밖입니다({evidence_id}).", code="integrity_failed")
    return name


def validate_record(case: Case, evidence_id: str, raw: bytes) -> dict[str, Any]:
    """접수 기록 바이트의 모양을 확인한다 (schema·id·케이스·저장 경로·해시 길이). 아니면 EvidenceError(integrity_failed)."""
    try:
        rec = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise EvidenceError(f"접수 기록을 읽을 수 없습니다({evidence_id}): {exc}", code="integrity_failed") from exc
    if not isinstance(rec, dict) or rec.get("schema") != SCHEMA_EVIDENCE or rec.get("evidence_id") != evidence_id or rec.get("case_id") != case.id:
        raise EvidenceError(f"접수 기록의 모양이 다릅니다({evidence_id}).", code="integrity_failed")
    stored_name(rec, evidence_id)
    for alg in HASH_ALGORITHMS:
        v = (rec.get("hashes") or {}).get(alg)
        if not isinstance(v, str) or len(v) != _HEX_LEN[alg]:
            raise EvidenceError(f"접수 기록의 {alg} 값이 잘못되었습니다({evidence_id}).", code="integrity_failed")
    return rec


def read_record_at(case: Case, evidence_id: str, ev_fd: int) -> tuple[dict[str, Any], bytes]:
    """EV 디렉터리 fd 에서 접수 기록을 안전하게 읽는다 → (기록, 원래 바이트). 없으면 FileNotFoundError."""
    try:
        raw = safeio.read_regular(f"{evidence_id}.json", dir_fd=ev_fd, max_bytes=RECORD_MAX, what="접수 기록")
    except FileNotFoundError:
        raise
    except PwehError as exc:
        raise EvidenceError(f"접수 기록을 읽을 수 없습니다({evidence_id}): {exc.message}", code="integrity_failed") from exc
    except OSError as exc:
        raise EvidenceError(f"접수 기록을 읽을 수 없습니다({evidence_id}): {exc.strerror or exc}", code="integrity_failed") from exc
    return validate_record(case, evidence_id, raw), raw


def load_record(case: Case, evidence_id: str) -> dict[str, Any]:
    """접수 기록을 읽고 모양을 확인한다. 저장 경로는 그 증거 디렉터리 안이어야 한다(밖을 가리키는 기록은 거부)."""
    check_evidence_id(evidence_id)
    try:
        fd = open_forensics(case, IMAGES_DIR, evidence_id)
    except FileNotFoundError:
        raise EvidenceError(f"증거가 없습니다: {evidence_id}", code="not_found", hint="forensics_evidence_list 로 증거 id 를 확인하세요.") from None
    except EvidenceError as exc:
        raise EvidenceError(exc.message, code="integrity_failed", hint=exc.hint) from exc
    try:
        return read_record_at(case, evidence_id, fd)[0]
    except FileNotFoundError:
        raise EvidenceError(f"증거가 없습니다: {evidence_id}", code="not_found", hint="forensics_evidence_list 로 증거 id 를 확인하세요.") from None
    finally:
        os.close(fd)


def stored_path(case: Case, record: dict[str, Any]) -> Path:
    """접수 기록의 저장 경로 (케이스 디렉터리 기준, 링크를 풀지 않음 — 열 때는 open_checked 의 fd 를 쓴다)."""
    return case.dir / record["stored"]["path"]


def latest_intake(entries: Iterable[dict[str, Any]], evidence_id: str) -> dict[str, Any] | None:
    """그 증거의 (마지막) intake 사건."""
    found = None
    for e in entries:
        if e.get("evidence_id") == evidence_id and e.get("event") == "intake":
            found = e
    return found


def intake_count(entries: Iterable[dict[str, Any]], evidence_id: str) -> int:
    return sum(1 for e in entries if e.get("evidence_id") == evidence_id and e.get("event") == "intake")


def refuse_second_intake(evidence_id: str) -> Callable[[list[dict[str, Any]]], None]:
    """CustodyLog.append(check=…) 용: 그 번호에 이미 접수·중단(intake-aborted) 사건이 있으면 거부(같은 번호를 두 번 쓰지 않는다)."""

    def check(entries: list[dict[str, Any]]) -> None:
        for e in entries:
            if e.get("evidence_id") == evidence_id and e.get("event") in ("intake", "intake-aborted"):
                raise EvidenceError(f"보관 기록에 이미 {evidence_id} 의 {e.get('event')} 사건이 있습니다(seq {e.get('seq')}) — 같은 번호로 다시 접수하지 않습니다.",
                                    code="integrity_failed", hint="다시 접수하면 새 EV 번호를 받는다.")

    return check


_INTAKE_KEYS = ("hashes", "size", "stored_path", "fingerprint", "record_sha256")


def record_problems(record: dict[str, Any], record_sha256: str, intake_data: dict[str, Any]) -> list[str]:
    """접수 기록(파일)을 보관 기록의 intake 사건(고정점으로 보호됨)과 대조한다. 문제 목록(비어 있으면 일치)."""
    problems = [f"보관 기록의 접수 사건에 대조할 값이 없음({k})" for k in _INTAKE_KEYS if k not in intake_data]
    if intake_data.get("record_sha256") != record_sha256:
        problems.append("접수 기록 파일이 접수 때와 다름(sha256)")
    if intake_data.get("hashes") != {a: (record.get("hashes") or {}).get(a) for a in HASH_ALGORITHMS}:
        problems.append("해시가 보관 기록과 다름")
    if intake_data.get("size") != (record.get("stored") or {}).get("size"):
        problems.append("크기가 보관 기록과 다름")
    if intake_data.get("stored_path") != (record.get("stored") or {}).get("path"):
        problems.append("저장 경로가 보관 기록과 다름")
    if intake_data.get("fingerprint") != record.get("fingerprint"):
        problems.append("빠른 지문이 보관 기록과 다름")
    return problems


@dataclass
class OpenedEvidence:
    """대조를 마치고 안전하게 연 증거 사본. intake = 보관 기록의 intake 사건 data (해시·크기·지문의 권위 값). close() 는 여러 번 불러도 된다."""

    evidence_id: str
    record: dict[str, Any]
    intake: dict[str, Any]
    intake_ts: str | None
    fd: int
    st: os.stat_result
    _closed: bool = field(default=False, repr=False)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            with contextlib.suppress(OSError):
                os.close(self.fd)

    def __del__(self) -> None:  # 요청이 취소돼 결과를 버려도 fd 가 새지 않게
        self.close()

    def __enter__(self) -> "OpenedEvidence":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def open_checked(case: Case, evidence_id: str, entries: list[dict[str, Any]]) -> OpenedEvidence:
    """내용 도구·검증의 공통 입구: 보관 기록(entries, 이미 검증된 것)의 intake 사건 → 상태(무결성 실패면 거부) → EV 디렉터리·접수 기록을
    링크를 따르지 않고 열어 intake 사건과 대조 → 사본을 safeio.open_regular 로 열어 그 fd 로 빠른 지문을 intake 사건의 지문과 대조.

    실패하면 IntegrityProblem (record=True 면 호출자가 integrity-failed 사건으로 남긴다). 증거 id 가 보관 기록에도 디렉터리에도 없으면
    EvidenceError(not_found). 반환한 fd 는 호출자가 닫는다(OpenedEvidence.close) — 해석·재해시는 이 fd 로만 한다."""
    check_evidence_id(evidence_id)
    intake = latest_intake(entries, evidence_id)
    if intake is None:
        if evidence_id in evidence_ids(case):
            raise IntegrityProblem(f"보관 기록에 접수 기록이 없는 증거입니다: {evidence_id}", reason="no-intake", record=False,
                                   hint=("커밋하지 못한 접수다(접수 중이거나 중단됨). 중단된 접수의 흔적(잡은 쪽이 없는 접수 잠금 파일·복사 중 *.partial·"
                                         "빈 디렉터리)이 있으면 다음 접수·서버 시작 때 aborted-intakes/ 로 옮겨지고, 흔적이 없으면(보관 기록을 잃은 "
                                         "증거 등) 그대로 둔다. 사람이 원인을 확인한다."))
        raise EvidenceError(f"증거가 없습니다: {evidence_id}", code="not_found", hint="forensics_evidence_list 로 증거 id 를 확인하세요.")
    if intake_count(entries, evidence_id) > 1:
        raise IntegrityProblem(f"같은 증거 id 의 접수 사건이 둘 이상입니다: {evidence_id}", reason="duplicate-intake", record=False)
    st = replay_status(entries, evidence_id)
    if st["status"] == "integrity-failed":
        raise IntegrityProblem(f"무결성 실패로 표시된 증거입니다: {evidence_id}", reason="already-failed", record=False,
                               hint="이 사본은 더 쓰지 않는다. 원본 이미지에서 다시 접수하세요(새 EV 번호).")
    data = intake.get("data") or {}
    try:
        ev_fd = open_forensics(case, IMAGES_DIR, evidence_id)
    except FileNotFoundError:
        raise IntegrityProblem(f"증거 사본 디렉터리가 없습니다(지워짐): {evidence_id} — 보관 기록에는 접수가 남아 있다", reason="missing",
                               record=False, hint="증거 목록에 missing 으로 남는다. 원본 이미지가 있으면 다시 접수하세요(새 EV 번호).") from None
    except EvidenceError as exc:
        raise IntegrityProblem(f"증거 디렉터리를 안전하게 열 수 없습니다({evidence_id}): {exc.message}", reason="unsafe-path",
                               problems=[exc.message]) from exc
    try:
        try:
            rec, raw = read_record_at(case, evidence_id, ev_fd)
        except FileNotFoundError:
            raise IntegrityProblem(f"접수 기록 파일이 없습니다({evidence_id}).", reason="record-missing", problems=["접수 기록 없음"]) from None
        except EvidenceError as exc:
            raise IntegrityProblem(exc.message, reason="record-invalid", problems=[exc.message]) from exc
        problems = record_problems(rec, hashlib.sha256(raw).hexdigest(), data)
        if problems:
            raise IntegrityProblem(f"접수 기록이 보관 기록의 접수 사건과 다릅니다({evidence_id}): {', '.join(problems)}", reason="record-mismatch",
                                   problems=problems)
        name = stored_name(rec, evidence_id)
        try:
            fd, fst = safeio.open_regular(name, dir_fd=ev_fd, what="증거 사본")
        except FileNotFoundError:
            raise IntegrityProblem(f"증거 사본이 없습니다({evidence_id}).", reason="stored-copy-missing", problems=["사본 없음"]) from None
        except UnsafeFile as exc:
            raise IntegrityProblem(f"증거 사본이 일반 파일이 아닙니다({evidence_id}) — 열지 않았습니다: {exc.message}", reason="stored-copy-not-regular",
                                   problems=[exc.message]) from exc
        except OSError as exc:
            raise IntegrityProblem(f"증거 사본을 열 수 없습니다({evidence_id}): {exc.strerror or exc}", reason="stored-copy-unreadable",
                                   problems=[str(exc.strerror or exc)]) from exc
        try:
            fp_problems = fingerprint_problems_fd(data.get("fingerprint") or {}, fd, fst)
            if fp_problems:
                raise IntegrityProblem(f"증거 사본이 접수 때와 다릅니다({evidence_id}): {', '.join(fp_problems)}", reason="fingerprint-mismatch",
                                       problems=fp_problems, hint="무결성 실패로 기록했다. 원본 이미지에서 다시 접수하세요.")
        except BaseException:
            os.close(fd)
            raise
        return OpenedEvidence(evidence_id=evidence_id, record=rec, intake=data, intake_ts=intake.get("ts"), fd=fd, st=fst)
    finally:
        os.close(ev_fd)


# ---------------------------------------------------------------------------
# EV 번호 확보·커밋하지 못한 접수 정리
# ---------------------------------------------------------------------------


@dataclass
class EvidenceClaim:
    """확보한 EV 번호: 디렉터리 fd 와 접수 잠금(커밋할 때까지 잡는다). commit()·rollback() 뒤 close()."""

    evidence_id: str
    images_fd: int
    dir_fd: int
    lock_fd: int | None
    _closed: bool = field(default=False, repr=False)

    @property
    def rel_dir(self) -> str:
        return forensics_rel(IMAGES_DIR, self.evidence_id)

    def commit(self) -> None:
        """보관 기록에 intake 를 남긴 뒤: 접수 잠금 파일을 지우고 잠금을 풀고 디렉터리를 0555 로(fd 로)."""
        with contextlib.suppress(OSError):
            os.unlink(INTAKE_LOCK, dir_fd=self.dir_fd)
        self._release_lock()
        os.fchmod(self.dir_fd, 0o555)

    def rollback(self) -> list[str]:
        """커밋 전 실패·취소: 만든 파일과 디렉터리를 지우고(디렉터리 fd 기준, 링크를 따르지 않음) 번호를 돌려놓는다 → 지우지 못한 항목."""
        left = safeio.remove_dir_at(self.images_fd, self.evidence_id)
        self._release_lock()
        return left

    def _release_lock(self) -> None:
        fd, self.lock_fd = self.lock_fd, None
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._release_lock()
        for fd in (self.dir_fd, self.images_fd):
            with contextlib.suppress(OSError):
                os.close(fd)


def _custody_ids(entries: Iterable[dict[str, Any]]) -> set[str]:
    return {e["evidence_id"] for e in entries if isinstance(e.get("evidence_id"), str)}


def _intake_ids(entries: Iterable[dict[str, Any]]) -> set[str]:
    return {e["evidence_id"] for e in entries if e.get("event") == "intake" and isinstance(e.get("evidence_id"), str)}


def _quarantine_names(case: Case) -> list[str]:
    try:
        qfd = open_forensics(case, QUARANTINE_DIR)
    except (FileNotFoundError, EvidenceError):
        return []
    try:
        return [n for n, _ in _list_dir(qfd)]
    finally:
        os.close(qfd)


def _compact_ts() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _intake_lock_state(ev_fd: int) -> int | None | str:
    """EV 디렉터리의 접수 잠금: 잠근 fd(잠금 파일이 있고 잡은 쪽이 없음 — 호출자가 닫는다) | None(다른 쪽이 잡고 있음 = 진행 중)
    | 'absent'(잠금 파일 없음) | 'unknown'(잠금 자리가 일반 파일이 아니거나 열 수 없음 — 장치·FIFO·링크는 열지 않는다. 판단하지 않는다)."""
    try:
        return safeio.try_lock_at(ev_fd, INTAKE_LOCK)
    except FileNotFoundError:
        return "absent"
    except (UnsafeFile, OSError):
        return "unknown"


def _quarantine_one(case: Case, log: CustodyLog, images_fd: int, name: str, entries: list[dict[str, Any]],
                    on_event: Callable[[dict[str, Any]], None] | None) -> dict[str, Any] | None:
    """보관 기록에 intake 가 없는 EV 디렉터리 하나를 정리한다(확보 잠금 CLAIM_LOCK 안에서만 부른다) → 옮긴 항목 | None(그대로 둠).

    중단된 접수의 흔적이 있을 때만 aborted-intakes/ 로 옮기고 intake-aborted 사건으로 번호를 소비한다(data.basis 에 근거를 남긴다):
    - 'intake-lock': 접수 잠금 파일이 있고 잡은 쪽이 없다 — 접수 job 이 커밋 전에 끝났다(확보 직후·복사 중·접수 기록 뒤·'기록 중'
      고정점 뒤). 접수는 확보 때 잠금 파일을 만들고 커밋(보관 기록 intake) 뒤에야 지우므로 커밋 전 중단에는 늘 이 파일이 남는다.
    - 'empty-dir': 잠금 파일이 없고 디렉터리가 비었다 — 확보가 mkdir 과 잠금 파일 만들기 사이에 끝났다(확보는 둘을 확보 잠금 안에서
      하므로 확보 잠금을 잡은 지금 진행 중일 수 없다).
    - 'partial-copy': 잠금 파일이 없고 복사 중 이름(*.partial)이 있다 — 되돌리기(rollback)가 잠금 파일만 지우고 끝났다 등. 커밋한
      디렉터리에는 *.partial 이 없다(사본은 접수 기록·보관 기록 전에 최종 이름으로 바뀌고, 저장 이름으로 *.partial 은 쓸 수 없다).
    - 보관 기록에 이미 그 번호의 intake-aborted 사건이 있다(앞의 옮기기가 실패함) — 사건을 다시 남기지 않고 기록한 자리로 다시 옮긴다.
    그 밖의 잠금 파일 없는 디렉터리(커밋한 증거인데 보관 기록과 고정점을 함께 잃음, 사람이 만든 디렉터리 등)는 옮기지 않는다 — 보관 기록
    없이는 커밋 여부를 알 수 없으므로 증거 목록에 record-without-intake 로 남겨 사람이 판단한다(디렉터리가 있으므로 번호는 다시 쓰지 않는다).
    잠금을 다른 쪽이 잡고 있거나(진행 중) 잠금 자리가 일반 파일이 아니면(열지 않음) 건드리지 않는다.
    한계: 커밋(보관 기록 intake) 직후 commit() 전에 끝나 잠금 파일이 남은 디렉터리는 보관 기록·고정점까지 잃으면 중단된 접수와 구별되지
    않아 옮겨진다(두 겹의 사고 — 보관 기록이 있으면 _finish_commit 이 커밋을 마저 한다)."""
    try:
        dfd = os.open(name, safeio.DIR_FLAGS, dir_fd=images_fd)
    except OSError:
        return None  # 링크·파일·사라짐 — 따라가지 않는다
    lock: int | None | str = None
    try:
        lock = _intake_lock_state(dfd)
        if lock is None or lock == "unknown":
            return None  # 다른 job(프로세스)이 접수 중이거나 잠금 자리가 수상함 — 건드리지 않는다
        listing = sorted(_list_dir(dfd))
        prior = [e for e in entries if e.get("evidence_id") == name and e.get("event") == "intake-aborted"]
        already = bool(prior)
        if isinstance(lock, int):
            basis = "intake-lock"
        elif not listing:
            basis = "empty-dir"
        elif any(child.endswith(PARTIAL_SUFFIX) and not is_dir for child, is_dir in listing):
            basis = "partial-copy"
        elif already:
            basis = "retry"
        else:
            return None  # 중단된 접수의 흔적이 없다 — 커밋 여부를 알 수 없으므로 그대로 둔다(record-without-intake)
        files = []
        had_record = False
        for child, is_dir in listing:
            if child == INTAKE_LOCK:
                continue
            try:
                cst = os.lstat(child, dir_fd=dfd)
            except OSError:
                continue
            files.append({"name": child[:120], "size": cst.st_size if stat.S_ISREG(cst.st_mode) else None,
                          "kind": "file" if stat.S_ISREG(cst.st_mode) else safeio.file_kind(cst.st_mode)})
            had_record = had_record or child == f"{name}.json"
        existing = set(_quarantine_names(case))
        recorded = str((prior[-1].get("data") or {}).get("quarantine_path") or "").rsplit("/", 1)[-1] if prior else ""
        if recorded and _QUARANTINE_RE.match(recorded) and recorded.startswith(name + "-") and recorded not in existing:
            qname = recorded  # 앞서 기록한 자리로 옮기기를 다시 한다(앞의 옮기기가 실패한 경우)
        else:
            qname = f"{name}-{_compact_ts()}"
            k = 1
            while qname in existing:
                k += 1
                qname = f"{name}-{_compact_ts()}-{k}"
        qrel = forensics_rel(QUARANTINE_DIR, qname)
        if not already:
            entry = log.append("intake-aborted", evidence_id=name, actor="server", data={
                "reason": "uncommitted-intake", "basis": basis, "quarantine_path": qrel, "had_record": had_record, "files": files[:20],
                "note": "커밋(보관 기록 intake) 전에 끝난 접수 — 서버가 복사 중 끝났거나 기록 도중 실패했다. 파일은 읽기 전용으로 옮겨 두었다.",
            })
            if on_event is not None:
                on_event(entry)
        # 읽기 전용으로 바꾸고(fd 로) 옮긴다. 디렉터리를 다른 부모로 옮기려면 그 디렉터리에 쓰기 권한이 있어야 한다('..' 갱신).
        # 접수 잠금 파일은 옮긴 뒤에 지운다 — 옮기기가 실패하면 흔적이 남아 다음 정리가 다시 옮긴다
        for child, is_dir in _list_dir(dfd):
            if is_dir or child == INTAKE_LOCK:
                continue
            with contextlib.suppress(OSError, PwehError):
                cfd, _ = safeio.open_regular(child, dir_fd=dfd)
                try:
                    os.fchmod(cfd, 0o444)
                finally:
                    os.close(cfd)
        qfd = open_forensics(case, QUARANTINE_DIR, create=True)
        try:
            os.fchmod(dfd, 0o755)
            os.rename(name, qname, src_dir_fd=images_fd, dst_dir_fd=qfd)
        finally:
            os.close(qfd)
        with contextlib.suppress(OSError):
            os.unlink(INTAKE_LOCK, dir_fd=dfd)  # dfd 는 옮긴 디렉터리를 가리킨다
        with contextlib.suppress(OSError):
            os.fchmod(dfd, 0o555)
        return {"evidence_id": name, "quarantine_path": qrel, "files": len(files), "had_record": had_record, "basis": basis}
    finally:
        if isinstance(lock, int):
            with contextlib.suppress(OSError):
                os.close(lock)
        os.close(dfd)


def _finish_commit(images_fd: int, name: str) -> None:
    """보관 기록에는 intake 가 있는데 접수 잠금 파일이 남은 디렉터리(커밋 직후 프로세스가 죽음): 잠금이 풀려 있으면 commit() 을 마저 한다
    (잠금 파일을 지우고 디렉터리를 0555 로 — 링크를 따르지 않고 fd 로). 다른 쪽이 잡고 있거나 잠금 자리가 일반 파일이 아니면 그대로 둔다."""
    try:
        dfd = os.open(name, safeio.DIR_FLAGS, dir_fd=images_fd)
    except OSError:
        return
    try:
        lock = _intake_lock_state(dfd)
        if not isinstance(lock, int):
            return  # 잠금 파일이 없음(정상 커밋)·진행 중·잠금 자리가 수상함
        try:
            with contextlib.suppress(OSError):
                os.unlink(INTAKE_LOCK, dir_fd=dfd)
            with contextlib.suppress(OSError):
                os.fchmod(dfd, 0o555)
        finally:
            os.close(lock)
    finally:
        os.close(dfd)


def _reconcile_locked(case: Case, log: CustodyLog, images_fd: int, entries: list[dict[str, Any]],
                      on_event: Callable[[dict[str, Any]], None] | None = None) -> list[dict[str, Any]]:
    committed = _intake_ids(entries)
    out = []
    for name, is_dir in sorted(_list_dir(images_fd)):
        if not is_dir or not EV_RE.match(name):
            continue
        if name in committed:
            _finish_commit(images_fd, name)
            continue
        moved = _quarantine_one(case, log, images_fd, name, entries, on_event)
        if moved:
            out.append(moved)
    return out


def reconcile_orphans(case: Case, log: CustodyLog, on_event: Callable[[dict[str, Any]], None] | None = None) -> list[dict[str, Any]]:
    """커밋하지 못한 EV 디렉터리(보관 기록에 intake 가 없고 중단된 접수의 흔적 — 잡은 쪽이 없는 접수 잠금 파일·*.partial·빈 디렉터리 —
    이 있는 것, _quarantine_one)를 forensics/aborted-intakes/EV-NNNN-<시각>/ 로 옮기고 intake-aborted 사건으로 번호를 소비한다
    (파일은 0444, 디렉터리 0555 — 지우지 않는다). 다른 job 이 잠근 디렉터리와 흔적이 없는 디렉터리(보관 기록을 잃은 커밋한 증거 등 —
    증거 목록의 record-without-intake)는 건드리지 않는다. 보관 기록에 intake 가 있는데 잠금 파일이 남은 디렉터리는 커밋을 마저 한다
    (_finish_commit). 보관 기록이 깨졌으면 아무것도 하지 않는다(EvidenceError custody_broken). 반환: 옮긴 항목."""
    try:
        images_fd = open_forensics(case, IMAGES_DIR)
    except FileNotFoundError:
        return []
    try:
        with safeio.locked_at(images_fd, CLAIM_LOCK):
            return _reconcile_locked(case, log, images_fd, log.entries(), on_event)
    finally:
        os.close(images_fd)


def claim_evidence_id(case: Case, log: CustodyLog | None = None,
                      on_event: Callable[[dict[str, Any]], None] | None = None) -> EvidenceClaim:
    """다음 증거 id 를 확보한다: 확보 잠금 안에서 커밋하지 못한 디렉터리를 정리하고(reconcile_orphans 와 같은 규칙 — 중단된 접수의 흔적이
    있는 것만 옮긴다), 번호 = (디렉터리·옮긴 디렉터리·보관 기록에 나온 번호 중 가장 큰 것) + 1 로 디렉터리를 만들고(mkdir 은 O_EXCL 처럼
    원자적), 그 안의 접수 잠금 파일을 만들어 잡는다 — mkdir 과 잠금 파일 만들기는 둘 다 확보 잠금 안이다(그 사이에 끝나면 빈 디렉터리가 남는다).
    보관 기록이 깨졌으면 확보하지 않는다(custody_broken). 호출자는 commit()/rollback() 뒤 close() 한다."""
    log = log or CustodyLog(case)
    images_fd = open_forensics(case, IMAGES_DIR, create=True)
    dir_fd = lock_fd = None
    try:
        with safeio.locked_at(images_fd, CLAIM_LOCK):
            entries = log.entries()
            if _reconcile_locked(case, log, images_fd, entries, on_event):
                entries = log.entries()
            nums = [_ev_num(n) for n, _ in _list_dir(images_fd) if EV_RE.match(n)]
            nums += [int(m.group(1)) for n in _quarantine_names(case) if (m := _QUARANTINE_RE.match(n))]
            nums += [_ev_num(i) for i in _custody_ids(entries)]
            n = max(nums, default=0) + 1
            for _ in range(1000):
                ev = f"EV-{n:04d}"
                try:
                    os.mkdir(ev, 0o755, dir_fd=images_fd)
                    break
                except FileExistsError:
                    n += 1
            else:  # pragma: no cover
                raise EvidenceError("증거 id 를 확보하지 못했습니다.")
            dir_fd = os.open(ev, safeio.DIR_FLAGS, dir_fd=images_fd)
            for _ in range(250):  # 증거 목록이 상태를 보려고 잠깐 잡을 수 있다
                lock_fd = safeio.try_lock_at(dir_fd, INTAKE_LOCK, create=True)
                if lock_fd is not None:
                    break
                time.sleep(0.02)
            else:  # pragma: no cover
                raise EvidenceError("접수 잠금을 잡지 못했습니다.")
        return EvidenceClaim(evidence_id=ev, images_fd=images_fd, dir_fd=dir_fd, lock_fd=lock_fd)
    except BaseException:
        for fd in (lock_fd, dir_fd, images_fd):
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)
        raise


# ---------------------------------------------------------------------------
# 상태·증거 목록
# ---------------------------------------------------------------------------


def replay_status(entries: Iterable[dict[str, Any]], evidence_id: str) -> dict[str, Any]:
    """보관 기록에서 한 증거의 상태를 정한다.

    반환: {intake: bool, status: 'ok'|'unverified'|'integrity-failed', last_verify: {ts, result, seq} | None,
           integrity_failures: [...], attestation: {status, attestation_id, ts} | None, extracts: n, events: n}.
    'unverified' = 접수만 했고 사본 전체 재해시가 아직 없다. 'integrity-failed' 는 한 번 생기면 되돌리지 않는다(새로 접수) —
    접수 사건의 copy_verified 가 false 이면 integrity-failed 사건이 없어도 실패다.
    attestation 은 보관 기록의 마지막 attest 사건 그대로다 — 지금 상태(철회·만료)와 대상 일치는 evidence_items 가 증명 저장소에서 확인한다.
    """
    out: dict[str, Any] = {"intake": False, "status": "unverified", "last_verify": None, "integrity_failures": [],
                           "attestation": None, "extracts": 0, "events": 0}
    copy_mismatch: dict[str, Any] | None = None
    for e in entries:
        if e.get("evidence_id") != evidence_id:
            continue
        out["events"] += 1
        ev, data = e.get("event"), e.get("data") or {}
        if ev == "intake":
            out["intake"] = True
            if data.get("copy_verified") is True:
                out["last_verify"] = {"ts": e.get("ts"), "result": "match", "seq": e.get("seq"), "kind": "intake-copy"}
            elif data.get("copy_verified") is False:  # 사본 재해시 불일치 — integrity-failed 사건을 못 남겼어도 실패로 본다
                copy_mismatch = {"seq": e.get("seq"), "ts": e.get("ts"), "reason": "copy-verify-mismatch"}
        elif ev == "verify":
            out["last_verify"] = {"ts": e.get("ts"), "result": data.get("result"), "seq": e.get("seq"), "kind": "full-rehash"}
            if data.get("result") != "match":
                out["integrity_failures"].append({"seq": e.get("seq"), "ts": e.get("ts"), "reason": "verify-mismatch"})
        elif ev == "integrity-failed":
            out["integrity_failures"].append({"seq": e.get("seq"), "ts": e.get("ts"), "reason": data.get("reason")})
        elif ev == "attest":
            out["attestation"] = {"status": data.get("status"), "attestation_id": data.get("attestation_id"), "ts": e.get("ts")}
        elif ev == "extract":
            out["extracts"] += 1
    if copy_mismatch and not any(f.get("reason") == "copy-verify-mismatch" for f in out["integrity_failures"]):
        out["integrity_failures"].insert(0, copy_mismatch)
    if out["integrity_failures"]:
        out["status"] = "integrity-failed"
    elif out["last_verify"] and out["last_verify"].get("result") == "match":
        out["status"] = "ok"
    return out


def attestation_view(store: Any, custody_att: dict[str, Any] | None, *, evidence_id: str, sha256: str | None, size: Any,
                     case_id: str) -> dict[str, Any] | None:
    """보관 기록의 attest 사건 → 표시할 증명: 증명 저장소의 레코드를 id 로 찾아 지금 상태(승인·거부·철회·만료)를 보이고,
    레코드의 대상(증거 id·sha256·크기)과 케이스가 이 항목과 같을 때만 보인다(다른 사본·다시 쓴 번호의 증명은 보이지 않는다).
    store 가 없으면(고정점 위치를 모름) 보관 기록 그대로."""
    if not custody_att or not custody_att.get("attestation_id"):
        return None
    if store is None:
        return dict(custody_att)
    try:
        rec = store.get(custody_att["attestation_id"])
    except Exception:  # noqa: BLE001 - 없거나 형식이 깨진 레코드는 보이지 않는다(fail closed)
        return None
    subject = rec.get("subject") or {}
    binding = rec.get("binding") or {}
    if (rec.get("kind") != "write-blocker" or subject.get("evidence_id") != evidence_id or subject.get("sha256") != sha256
            or subject.get("size") != size or binding.get("case_id") != case_id):
        return None
    status = rec.get("status")
    if status == "approved":
        try:
            trusted = store.require("write-blocker", {"evidence_id": evidence_id, "sha256": sha256, "size": size},
                                    {"scope": "case", "case_id": case_id})
        except Exception:  # noqa: BLE001
            trusted = None
        if not trusted or trusted.get("id") != rec.get("id"):
            status = "invalid"
    return {"status": status, "attestation_id": rec.get("id"), "ts": custody_att.get("ts"), "decided_at": rec.get("decided_at"),
            "expires_at": rec.get("expires_at")}


def _default_attestation_store(anchor_dir: str | Path | None) -> Any:
    """고정점 위치(<state_dir>/custody) 옆의 증명 저장소(<state_dir>/attestations — runtime.py 와 같은 배치). 읽기만 한다."""
    if anchor_dir is None:
        return None
    from .safety.attestations import AttestationStore

    return AttestationStore(Path(anchor_dir).parent / "attestations")


def _dir_record_problems(case: Case, evidence_id: str, intake: dict[str, Any]) -> tuple[str | None, list[str]]:
    """증거 목록용: EV 디렉터리의 접수 기록을 intake 사건과 대조 → (상태 | None, 문제). 사본은 열지 않는다(서버가 따로 지문을 본다)."""
    try:
        fd = open_forensics(case, IMAGES_DIR, evidence_id)
    except FileNotFoundError:
        return "missing", []
    except EvidenceError as exc:
        return "integrity-failed", [exc.message]
    try:
        try:
            rec, raw = read_record_at(case, evidence_id, fd)
        except FileNotFoundError:
            return "record-invalid", ["접수 기록 없음"]
        except EvidenceError as exc:
            return "record-invalid", [exc.message]
        problems = record_problems(rec, hashlib.sha256(raw).hexdigest(), intake.get("data") or {})
        return ("integrity-failed", problems) if problems else (None, [])
    finally:
        os.close(fd)


def _uncommitted_state(case: Case, evidence_id: str) -> str:
    """보관 기록에 intake 가 없는 EV 디렉터리: 접수 잠금을 다른 쪽이 잡고 있으면 intake-in-progress, 아니면 record-without-intake
    (중단된 접수의 흔적이 있으면 다음 접수·서버 시작 때 aborted-intakes/ 로 옮겨지고, 없으면 사람이 판단할 때까지 그대로 남는다 — _quarantine_one)."""
    try:
        fd = open_forensics(case, IMAGES_DIR, evidence_id)
    except (FileNotFoundError, EvidenceError):
        return "record-without-intake"
    try:
        lock = _intake_lock_state(fd)
    except (OSError, PwehError):
        lock = "absent"
    finally:
        os.close(fd)
    if lock is None:
        return "intake-in-progress"
    if isinstance(lock, int):
        os.close(lock)
    return "record-without-intake"


def status_label(status: str, history_status: str | None = None) -> str:
    """사람이 읽는 출력(증거 목록 md·보고서)에 쓰는 상태 표시(evidence_items 의 items[].status_label): status 그대로이고, EV 디렉터리가
    지워졌는데(missing) 보관 기록에 무결성 실패가 남은 항목(history_status = replay_status 의 status 가 integrity-failed)만
    'missing (integrity-failed)' — missing 이 앞선 무결성 실패를 가리지 않게."""
    if status == "missing" and history_status == "integrity-failed":
        return "missing (integrity-failed)"
    return status


def evidence_items(case: Case, anchor_dir: str | Path | None = None, *, attestations: Any = None) -> dict[str, Any]:
    """증거 목록: {custody: {ok, count, head, detail?}, items: [...], aborted: [...]}.

    보관 기록이 멀쩡하면 항목은 보관 기록의 intake 사건(커밋한 접수)과 EV 디렉터리의 합집합이다:
    - 커밋한 접수: 해시·크기·저장 경로·라벨은 intake 사건(고정점으로 보호됨) 값. 상태 ok / unverified / integrity-failed(보관 기록 또는
      접수 기록 대조 문제 — problems) / missing(EV 디렉터리가 지워짐) / record-invalid(접수 기록 파일을 읽을 수 없음).
    - 커밋하지 못한 디렉터리: intake-in-progress(접수 잠금이 잡혀 있음) / record-without-intake — 해시를 싣지 않는다(보관 기록 근거 없음).
    - 쓰기 방지 장치 증명: attest 사건의 증명 레코드를 증명 저장소(attestations, 없으면 anchor_dir 옆)에서 찾아, 대상이 이 항목의
      증거 id·sha256·크기와 같을 때만 지금 상태(approved/denied/revoked/expired/invalid)로 보인다.
    보관 기록이 깨졌으면 EV 디렉터리마다 status custody-broken (해시 없음 — 믿을 근거가 없다).
    모든 항목에 status_label(사람이 읽는 출력용 — status_label() 참고)을 붙인다: status 와 같고, 디렉터리가 지워졌는데 보관 기록에
    무결성 실패가 남은 항목만 'missing (integrity-failed)' 다(status 는 missing, integrity_failures 에 기록이 남는다).
    """
    log = CustodyLog(case, anchor_dir)
    entries, broken = log.read()
    try:
        dirs = evidence_ids(case)
    except EvidenceError as exc:
        dirs = []
        broken = broken or f"forensics/images 가 실제 디렉터리가 아니다: {exc.message}"
    chain = chain_summary(entries, broken)
    items: list[dict[str, Any]] = []
    if broken:
        for ev in dirs:
            items.append({"evidence_id": ev, "status": "custody-broken", "status_label": "custody-broken"})
        return {"custody": chain, "items": items, "aborted": []}
    store = attestations if attestations is not None else _default_attestation_store(anchor_dir)
    intakes: dict[str, dict[str, Any]] = {}
    for e in entries:
        if e.get("event") == "intake" and isinstance(e.get("evidence_id"), str):
            intakes[e["evidence_id"]] = e
    for ev in sorted(set(intakes) | set(dirs), key=_ev_num):
        intake = intakes.get(ev)
        if intake is None:
            pending = _uncommitted_state(case, ev)
            items.append({"evidence_id": ev, "status": pending, "status_label": pending, "intake": False})
            continue
        d = intake.get("data") or {}
        st = replay_status(entries, ev)
        hashes = d.get("hashes") if isinstance(d.get("hashes"), dict) else {}
        item: dict[str, Any] = {
            "evidence_id": ev,
            "label": d.get("label"),
            "stored_path": d.get("stored_path"),
            "size": d.get("size"),
            "hashes": hashes,
            "intake_ts": intake.get("ts"),
            "imaging_log": (d.get("imaging_log") or {}).get("comparison"),
            **st,
        }
        state, problems = (None, [])
        if ev not in dirs:
            state = "missing"
        else:
            state, problems = _dir_record_problems(case, ev, intake)
        if intake_count(entries, ev) > 1:
            state, problems = "integrity-failed", problems + ["같은 증거 id 의 접수 사건이 둘 이상"]
        if state == "missing" or (state and st["status"] != "integrity-failed"):
            item["status"] = state
        item["status_label"] = status_label(item["status"], st["status"])
        if problems:
            item["problems"] = problems
        item["attestation"] = attestation_view(store, st.get("attestation"), evidence_id=ev, sha256=hashes.get("sha256"),
                                               size=d.get("size"), case_id=case.id)
        items.append(item)
    aborted = [{"evidence_id": e.get("evidence_id"), "ts": e.get("ts"), "seq": e.get("seq"),
                "quarantine_path": (e.get("data") or {}).get("quarantine_path"), "reason": (e.get("data") or {}).get("reason")}
               for e in entries if e.get("event") == "intake-aborted"]
    return {"custody": chain, "items": items, "aborted": aborted}


__all__ = [
    "ANCHORED_STATUSES",
    "CUSTODY_EVENTS",
    "CustodyLog",
    "EV_RE",
    "EvidenceClaim",
    "EvidenceError",
    "FORENSICS_DIR",
    "FORENSICS_NOTICE",
    "HASH_ALGORITHMS",
    "IntegrityProblem",
    "OpenedEvidence",
    "QUARANTINE_DIR",
    "RESERVED_NAME_RE",
    "SCHEMA_CUSTODY",
    "SCHEMA_EVIDENCE",
    "attestation_view",
    "chain_summary",
    "check_evidence_id",
    "check_image_source",
    "claim_evidence_id",
    "compare_log_hashes",
    "contains_forensics_dir",
    "ensure_forensics_dir",
    "entry_hash",
    "evidence_dir",
    "evidence_ids",
    "evidence_items",
    "fingerprint",
    "fingerprint_fd",
    "fingerprint_problems",
    "fingerprint_problems_fd",
    "forensics_dir",
    "forensics_rel",
    "hash_stream",
    "is_forensics_path",
    "latest_intake",
    "load_record",
    "open_checked",
    "open_forensics",
    "open_image_source",
    "parse_anchors",
    "parse_custody",
    "parse_imaging_log",
    "read_imaging_log",
    "read_record_at",
    "reconcile_orphans",
    "record_bytes",
    "record_path",
    "record_problems",
    "refuse_second_intake",
    "replay_status",
    "status_label",
    "stored_name",
    "stored_path",
    "strict_rel",
    "under_any_case_forensics",
    "validate_record",
    "write_record",
]
