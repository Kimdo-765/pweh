"""보관 사건에 결속된 미디어 단위 후보 보고서의 fd·해시·선택 범위를 유지한다.

후보를 다시 탐색하지 않는다. 호출자가 검증한 EV/보관 기록을 받아 보고서만 열며,
최종 커밋 잠금 안에서 같은 보고서 fd 전체와 upstream 사건을 다시 대조한다.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import math
import os
import re
import stat
import time
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass
from typing import Any

from . import media_units, evidence as E, safeio, schemas
from .case import Case
from .errors import PwehError, ValidationFailed
from .sdioc_input import load_json

MAX_REPORT_BYTES = 1 << 20
MAX_SELECTED_BYTES = 64 << 20
MAX_EVIDENCE_BYTES = (1 << 63) - 1
_SHA = re.compile(r"[0-9a-f]{64}")
_MESSAGES = {
    "media_unit_input_invalid": "미디어 단위 후보 보고서의 형식·출처 또는 선택 범위가 유효하지 않습니다.",
    "media_unit_input_limit": "미디어 단위 후보 입력의 크기·구조 상한을 넘었습니다.",
    "media_unit_input_changed": "미디어 단위 후보 보고서 또는 선택 출처가 변경되었습니다.",
    "cancelled": "미디어 단위 후보 입력 처리가 취소되었습니다.",
    "timeout": "미디어 단위 후보 입력 검증 시간 상한에 도달했습니다.",
}


def input_error(code: str = "media_unit_input_invalid") -> PwehError:
    """호출자에게 원문 경로·내용이 없는 고정 오류만 돌려준다."""
    if type(code) is not str or code not in _MESSAGES:
        code = "media_unit_input_invalid"
    return ValidationFailed(_MESSAGES[code], code=code)


def check_budget(deadline: float, cancel: Callable[[], bool]) -> None:
    """공통 절대 마감과 취소를 확인한다. callback 오류에도 원문을 넣지 않는다."""
    try:
        valid = type(deadline) in (int, float) and math.isfinite(deadline)
        if not valid:
            raise input_error()
        stopped = cancel()
        if type(stopped) is not bool:
            raise input_error()
    except PwehError:
        raise input_error() from None
    except Exception:
        raise input_error() from None
    if stopped:
        raise input_error("cancelled")
    if time.monotonic() >= deadline:
        raise input_error("timeout")


def _identity(st: os.stat_result) -> tuple[int, ...]:
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_nlink


def _directory_identity(st: os.stat_result) -> tuple[int, ...]:
    # 다른 분석이 같은 부모에 파일을 추가할 수 있으므로 디렉터리 mtime/크기는 제외한다.
    return st.st_dev, st.st_ino, st.st_mode, st.st_uid


def _sha(value: Any) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _event(entries: list[dict], case_id: str, ev: str, path: str,
           check: Callable[[], None]) -> dict:
    if type(entries) is not list:
        raise input_error()
    found = None
    for n, item in enumerate(entries):
        if n % 256 == 0:
            check()
        if type(item) is not dict:
            raise input_error()
        data = item.get("data")
        analysis = data.get("analysis") if type(data) is dict else None
        if (item.get("event") == "media-unit-candidates" and item.get("evidence_id") == ev
                and type(analysis) is dict and analysis.get("path") == path):
            if found is not None:
                raise input_error()
            found = item
    if found is None or found.get("case_id") != case_id:
        raise input_error()
    seq, analysis = found.get("seq"), found["data"]["analysis"]
    if (type(seq) is not int or not 1 <= seq <= min(len(entries), (1 << 53) - 1) or entries[seq - 1] is not found
            or set(analysis) != {"path", "sha256", "size"}
            or not _sha(analysis["sha256"]) or type(analysis["size"]) is not int):
        raise input_error()
    if not 0 < analysis["size"] <= MAX_REPORT_BYTES:
        raise input_error("media_unit_input_limit")
    check()
    return found


def _semantic(report: dict, index: int, opened: E.OpenedEvidence, event: dict) -> None:
    """전체 미디어 단위 회계는 코어에 맡기고 출처·정확한 정수·선택 범위만 추가 대조한다."""
    schemas.validate("media-unit-candidates", report)
    media_units.validate_media_unit_accounting(report)
    source, coverage, rows, params = (report[key] for key in ("source", "coverage", "candidates", "params"))
    data = event["data"]
    format = report["format"]
    if index >= len(rows):
        raise input_error()
    if (source != data.get("source") or params != data.get("params")
            or report["status"] != data.get("status")
            or source["evidence_id"] != opened.evidence_id
            or source["evidence_sha256"] != opened.intake["hashes"]["sha256"]
            or report["status"] == "unsupported" or source["method"] == "empty"
            or source["complete"] is not True
            or type(source["selected_size"]) is not int
            or not media_units.MIN_SELECTED_BYTES[format] <= source["selected_size"] <= MAX_SELECTED_BYTES
            or params["format"] != format or rows[index]["format"] != format
            or any(item["partition"] is not None and type(item["partition"]) is not int
                   for item in (source, params))
            or coverage["input_bytes"] != source["selected_size"]):
        raise input_error()
    # max_seconds만 원래 유한 float를 허용한다. 위치·길이 정수는 강제 변환하지 않는다.
    seconds = params["max_seconds"]
    if type(seconds) not in (int, float) or not math.isfinite(seconds):
        raise input_error()
    if report["profile"] == media_units.RANGE_PROFILES[format]:
        offset, length, evidence_size = source["offset"], source["selected_size"], source["evidence_size"]
        if (any(type(v) is not int for v in (offset, length, evidence_size,
                                            params["offset"], params["length"], opened.intake.get("size")))
                or offset != params["offset"] or length != params["length"]
                or not 0 <= offset <= MAX_EVIDENCE_BYTES
                or not 0 < evidence_size <= MAX_EVIDENCE_BYTES
                or length > evidence_size - offset
                or evidence_size != opened.intake["size"]
                or evidence_size != opened.st.st_size or evidence_size != os.fstat(opened.fd).st_size):
            raise input_error()


@dataclass(frozen=True)
class MediaUnitCandidateOrigin:
    """생성 보고서 hash와 upstream 보관 사건 hash를 구분한 고정 출처."""

    path: str
    sha256: str
    size: int
    custody_seq: int
    custody_hash: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class MediaUnitCandidateInput:
    """context가 소유한 보고서 fd. 공개 dict는 복사본이며 사건 권위 값이 아니다."""

    source: dict
    candidate: dict
    params: dict
    coverage: dict
    upstream_status: str
    origin: MediaUnitCandidateOrigin
    format: str
    profile: str
    _case: Case
    _ev: str
    _dirs: tuple[int, ...]
    _dir_seals: tuple[tuple[int, ...], ...]
    _fd: int
    _seal: tuple[int, ...]
    _origin: MediaUnitCandidateOrigin
    _deadline: float
    _cancel: Callable[[], bool]

    def _names(self) -> None:
        current = safeio.open_dir_chain(self._case.dir)
        try:
            for n, part in enumerate((None, "forensics", "analysis")):
                if part is not None:
                    child = os.open(part, safeio.DIR_FLAGS, dir_fd=current)
                    os.close(current)
                    current = child
                if (_directory_identity(os.fstat(current)) != self._dir_seals[n]
                        or _directory_identity(os.fstat(self._dirs[n])) != self._dir_seals[n]):
                    raise input_error("media_unit_input_changed")
            named = os.stat(self._origin.path.rsplit("/", 1)[1], dir_fd=current, follow_symlinks=False)
            if _identity(named) != self._seal or _identity(os.fstat(self._fd)) != self._seal:
                raise input_error("media_unit_input_changed")
        finally:
            os.close(current)

    def _read(self) -> bytes:
        out, digest = bytearray(), hashlib.sha256()
        while len(out) < self._origin.size:
            check_budget(self._deadline, self._cancel)
            chunk = os.pread(self._fd, min(64 << 10, self._origin.size - len(out)), len(out))
            if not chunk:
                raise input_error("media_unit_input_changed")
            digest.update(chunk)
            out.extend(chunk)
        if digest.hexdigest() != self._origin.sha256:
            raise input_error("media_unit_input_changed")
        return bytes(out)

    def check(self) -> None:
        """커밋 직전 같은 fd 전체를 해시하고 부모·이름·fd 신원을 재대조한다."""
        check_budget(self._deadline, self._cancel)
        try:
            self._names()
            self._read()
            self._names()
            check_budget(self._deadline, self._cancel)
        except (OSError, safeio.UnsafeFile):
            raise input_error("media_unit_input_changed") from None

    def check_entries(self, entries: list[dict]) -> None:
        """append 잠금에서 받은 검증 entries만 읽는다. 보관 로그를 다시 열지 않는다."""
        try:
            event = _event(entries, self._case.id, self._ev, self._origin.path,
                           lambda: check_budget(self._deadline, self._cancel))
            if event["seq"] != self._origin.custody_seq or E.entry_hash(event) != self._origin.custody_hash:
                raise input_error("media_unit_input_changed")
        except PwehError as exc:
            if exc.code in {"cancelled", "timeout"}:
                raise
            raise input_error("media_unit_input_changed") from None
        except Exception:
            raise input_error("media_unit_input_changed") from None


@contextlib.contextmanager
def open_media_unit_candidate(case: Case, opened: E.OpenedEvidence, *, analysis_path: str,
                              candidate_index: int, entries: list[dict], deadline: float,
                              cancel: Callable[[], bool]) -> Iterator[MediaUnitCandidateInput]:
    """닫힌 생성 경로와 같은 EV의 유일한 후보 사건을 대조한 보고서를 유지한다."""
    dirs: list[int] = []
    fd = None
    try:
        check_budget(deadline, cancel)
        ev = opened.evidence_id
        if (type(ev) is not str or E.EV_RE.fullmatch(ev) is None
                or type(analysis_path) is not str
                or re.fullmatch(r"forensics/analysis/media-unit-candidates-" + re.escape(ev)
                                + r"-[0-9]{3,9}\.json", analysis_path) is None
                or type(candidate_index) is not int or not 0 <= candidate_index < 128
                or opened.record.get("case_id") != case.id
                or not _sha(opened.intake.get("hashes", {}).get("sha256"))):
            raise input_error()
        event = _event(entries, case.id, ev, analysis_path, lambda: check_budget(deadline, cancel))
        analysis = event["data"]["analysis"]
        origin = MediaUnitCandidateOrigin(analysis_path, analysis["sha256"], analysis["size"],
                                          event["seq"], E.entry_hash(event))
        dirs.append(safeio.open_dir_chain(case.dir))
        for name in ("forensics", "analysis"):
            dirs.append(os.open(name, safeio.DIR_FLAGS, dir_fd=dirs[-1]))
        fd, st = safeio.open_regular(analysis_path.rsplit("/", 1)[1], dir_fd=dirs[-1], reject_hardlinks=True)
        if not 0 < st.st_size <= MAX_REPORT_BYTES:
            raise input_error("media_unit_input_limit")
        if st.st_size != origin.size or st.st_mode & 0o222 or not stat.S_ISREG(st.st_mode):
            raise input_error()
        result = MediaUnitCandidateInput({}, {}, {}, {}, "", origin, "", "", case, ev, tuple(dirs),
                                         tuple(_directory_identity(os.fstat(d)) for d in dirs), _fd=fd,
                                         _seal=_identity(st), _origin=origin, _deadline=deadline, _cancel=cancel)
        raw = result._read()
        result._names()
        report = load_json(raw, deadline=deadline, cancel=cancel)
        _semantic(report, candidate_index, opened, event)
        result.source = copy.deepcopy(report["source"])
        result.candidate = copy.deepcopy(report["candidates"][candidate_index])
        result.params = copy.deepcopy(report["params"])
        result.coverage = copy.deepcopy(report["coverage"])
        result.upstream_status = report["status"]
        result.format, result.profile = report["format"], report["profile"]
        check_budget(deadline, cancel)
    except BaseException as exc:
        for owned in ([fd] if fd is not None else []) + list(reversed(dirs)):
            with contextlib.suppress(OSError):
                os.close(owned)
        if not isinstance(exc, Exception):
            raise
        code = getattr(exc, "code", None)
        if code == "sdioc_input_limit":
            code = "media_unit_input_limit"
        raise input_error(code) from None
    try:
        yield result
    finally:
        for owned in [fd, *reversed(dirs)]:
            with contextlib.suppress(OSError):
                os.close(owned)
