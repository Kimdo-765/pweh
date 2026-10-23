"""같은 증거 fd에서 FAT/exFAT의 명시 할당 창을 검사하는 MCP 입구."""

from __future__ import annotations

import dataclasses
import json
import math
import os
import re
import stat
import threading
import time
from typing import Any, Callable

from pydantic import StrictFloat, StrictInt

from pweh import evidence as E, schemas
from pweh.errors import PwehError, ValidationFailed
from pweh.mcpkit import ANN_LOCAL_WRITE, run_blocking_cancellable, safe_tool

MAX_REPORT_BYTES = 1 << 20
MAX_WINDOW_BYTES = 64 << 20
MAX_EVIDENCE_BYTES = (1 << 63) - 1
_ERRORS = {
    "cancelled": "할당 창 검사가 취소되었습니다.",
    "time_limit": "할당 창 검사 준비의 시간 한도에 닿았습니다.",
    "validation_failed": "할당 창 검사 인자가 허용 범위가 아닙니다.",
    "authorization_required": "케이스의 소유 또는 허가 확인이 필요합니다.",
    "not_found": "요청한 케이스 또는 증거를 찾지 못했습니다.",
    "case_error": "케이스를 확인하지 못했습니다.",
    "custody_broken": "증거의 보관 기록을 검증하지 못했습니다.",
    "integrity_failed": "증거 또는 분석 출력의 무결성을 확인하지 못했습니다.",
    "evidence_error": "증거 확인 또는 분석 저장을 완료하지 못했습니다.",
    "allocation_input_invalid": "할당 창의 파일 시스템 또는 범위 인자가 유효하지 않습니다.",
    "allocation_unsupported": "선택한 파티션의 할당 검사를 지원하지 않습니다.",
    "allocation_limit": "할당 창의 구조를 확인하기 전에 검사 한도에 닿았습니다.",
    "allocation_read_failed": "할당 메타데이터의 완전한 읽기를 확인하지 못했습니다.",
    "allocation_failed": "할당 창 검사를 완료하지 못했습니다.",
}


class _ServerAPI:
    """runtime과 합성 시험의 주입을 서버 namespace의 늦은 참조로 유지한다."""

    def __init__(self, namespace: dict[str, Any]):
        self.namespace = namespace

    def __getattr__(self, name: str) -> Any:
        return self.namespace[name]


@dataclasses.dataclass(frozen=True, repr=False)
class _EvidenceSource:
    """fd 소유권을 넘기거나 경로를 다시 열지 않는 순수 코어의 읽기 입구."""

    size: int
    read: Callable[[int, int], bytes]
    base_offset: int = 0


def _check(cancelled: threading.Event, deadline: float, *, timing: bool = True) -> None:
    if cancelled.is_set():
        raise PwehError(_ERRORS["cancelled"], code="cancelled")
    if timing and time.monotonic() >= deadline:
        raise PwehError(_ERRORS["time_limit"], code="time_limit")


def _arguments(evidence_id: Any, partition: Any, offset: Any, length: Any,
               max_seconds: Any) -> float:
    if (type(evidence_id) is not str or re.fullmatch(r"EV-[0-9]{4,6}", evidence_id) is None
            or type(partition) is not int or not 1 <= partition <= 4096
            or type(offset) is not int or not 0 <= offset <= MAX_EVIDENCE_BYTES
            or type(length) is not int or not 1 <= length <= MAX_WINDOW_BYTES
            or type(max_seconds) not in (int, float) or not 0 < max_seconds <= 45
            or not math.isfinite(max_seconds)):
        raise ValidationFailed(_ERRORS["validation_failed"])
    return time.monotonic() + max_seconds


def _identity(st: os.stat_result) -> tuple[int, ...]:
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_nlink


def _check_opened(opened: E.OpenedEvidence) -> int:
    """접수 크기와 보유 fd의 seal을 검사한다. atime 변화는 제외한다."""
    size = opened.intake["size"]
    if type(size) is not int or not 1 <= size <= MAX_EVIDENCE_BYTES:
        raise ValidationFailed(_ERRORS["validation_failed"])
    before, now = opened.st, os.fstat(opened.fd)
    if (not stat.S_ISREG(before.st_mode) or not stat.S_ISREG(now.st_mode)
            or before.st_nlink != 1 or now.st_nlink != 1 or before.st_size != size
            or _identity(before) != _identity(now)):
        raise E.IntegrityProblem("할당 검사 중 증거의 파일 신원 또는 상태가 변경되었습니다.",
                                 reason="source-changed")
    return size


def _fixed_error(exc: Exception) -> PwehError:
    code = getattr(exc, "code", None)
    if type(code) is not str or code not in _ERRORS:
        code = "allocation_failed"
    return PwehError(_ERRORS[code], code=code)


def _audit_commit(S: _ServerAPI, case: Any, entry: dict) -> None:
    S.rt().audit({"event": "forensics_" + entry["event"].replace("-", "_"),
                  "evidence_id": entry.get("evidence_id"), "custody_seq": entry.get("seq"),
                  "custody_hash": entry.get("hash")}, case.id)


def _record_integrity(S: _ServerAPI, case: Any, evidence_id: str, exc: E.IntegrityProblem) -> None:
    if not exc.record:
        return
    entry = S.custody(case).append(
        "integrity-failed", evidence_id=evidence_id, actor="server",
        data={"reason": "allocation-window-integrity-check", "problems": ["증거 무결성 검증 실패"],
              "found_by": "allocation-window"})
    try:
        _audit_commit(S, case, entry)
    except Exception:
        pass  # 커밋된 무결성 사건은 보조 감사 실패 뒤에도 보존한다.


async def _allocation_run(S: _ServerAPI, *, case_id: str, evidence_id: str,
                          partition: int, offset: int, length: int, max_seconds: float) -> dict:
    cancelled = threading.Event()
    try:
        deadline = _arguments(evidence_id, partition, offset, length, max_seconds)
        case = await S._case(case_id)

        def work_body() -> dict:
            from pweh.fs.allocation import AllocationLimits, inspect_allocation_window, validate_allocation_accounting

            _check(cancelled, deadline)
            entries = S.custody(case).entries()
            read_problem = None
            try:
                with E.open_checked(case, evidence_id, entries, reference_roots=S._reference_roots()) as opened:
                    size = _check_opened(opened)
                    if offset > size or length > size - offset:
                        raise ValidationFailed(_ERRORS["validation_failed"])

                    def read_at(at: int, count: int) -> bytes:
                        nonlocal read_problem
                        try:
                            # 시간 한도는 코어가 geometry 전 실패/후 partial로 구분한다.
                            _check(cancelled, deadline, timing=False)
                            if (type(at) is not int or type(count) is not int
                                    or not 0 <= at <= size or not 0 <= count <= 65536
                                    or count > size - at):
                                raise ValidationFailed(_ERRORS["validation_failed"])
                            _check_opened(opened)
                            data = os.pread(opened.fd, count, at) if count else b""
                            _check_opened(opened)
                            _check(cancelled, deadline, timing=False)
                            if type(data) is not bytes or len(data) != count:
                                raise PwehError(_ERRORS["allocation_read_failed"], code="allocation_read_failed")
                            return data
                        except Exception as exc:
                            # FS guard가 원인을 unknown/partial로 닫아도 최초 원인을 복원한다.
                            if read_problem is None:
                                read_problem = exc if isinstance(exc, PwehError) else PwehError(
                                    _ERRORS["allocation_read_failed"], code="allocation_read_failed")
                            raise read_problem from None

                    limits = dataclasses.replace(AllocationLimits(), output_bytes=MAX_REPORT_BYTES - (16 << 10))
                    try:
                        report = inspect_allocation_window(
                            _EvidenceSource(size, read_at), partition=partition, offset=offset, length=length,
                            limits=limits, deadline=deadline, cancel=cancelled.is_set)
                    except Exception:
                        if read_problem is not None:
                            raise read_problem from None
                        raise
                    if read_problem is not None:
                        raise read_problem from None
                    report["source"] = {"kind": "evidence", "evidence_id": evidence_id,
                                        "evidence_sha256": opened.intake["hashes"]["sha256"], "evidence_size": size}
                    report["params"] = {"partition": partition, "offset": offset,
                                        "length": length, "max_seconds": max_seconds}
                    schemas.validate("allocation-window", report)
                    validate_allocation_accounting(report)
                    if (report["source"]["evidence_size"] != size
                            or report["params"] != {"partition": partition, "offset": offset,
                                                    "length": length, "max_seconds": max_seconds}
                            or type(report["coverage"]["requested_bytes"]) is not int
                            or report["coverage"]["requested_bytes"] != length):
                        raise ValidationFailed(_ERRORS["validation_failed"])
                    raw = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
                    if len(raw.encode("utf-8")) + 1 > MAX_REPORT_BYTES:
                        raise ValidationFailed(_ERRORS["validation_failed"])

                    def final_check() -> None:
                        # 시간 partial도 저장하되 취소·증거 seal은 커밋 직전까지 검사한다.
                        _check(cancelled, deadline, timing=False)
                        _check_opened(opened)

                    final_check()
                    return E.store_analysis(
                        case, opened, report, event="allocation-window", custody_log=S.custody(case),
                        reference_roots=lambda: S._reference_roots(), check=final_check,
                        on_commit=lambda entry: _audit_commit(S, case, entry))
            except E.IntegrityProblem as exc:
                _record_integrity(S, case, evidence_id, exc)
                raise

        def work() -> dict:
            try:
                return work_body()
            except Exception as exc:
                raise _fixed_error(exc) from None

        return await run_blocking_cancellable(work, on_cancel=cancelled.set)
    except Exception as exc:
        raise _fixed_error(exc) from None


def register_allocation_tools(server: Any, namespace: dict[str, Any]) -> None:
    """기존 포렌식 서버에 명시 FAT/exFAT 할당 창 도구 하나를 등록한다."""
    S = _ServerAPI(namespace)

    @server.tool(description=(
        "접수한 EV 이미지의 명시 FAT/exFAT 파티션에서 현재 할당 상태 메타데이터를 검사한다. "
        "partition은 필수 index, offset은 EV 절대 위치, length는 1 byte..64 MiB이며 exact int만 받는다. "
        "창은 해당 파티션의 데이터 클러스터 영역 안이어야 한다. "
        "unallocated/allocated/bad/unknown 연속 범위와 미검사 suffix·next_offset을 반환한다. "
        "최대45초·메타데이터 읽기 합계4 MiB·128행·JSON1 MiB, 각 읽기는64 KiB 이하다. "
        "window_complete는 요청 창의 행 표현 완료이며 allocation_complete는 unknown이 없는 완료다. "
        "접수 EV 해시를 출처에 결속하며 이번 호출이 전체 EV를 다시 해시했다는 뜻은 아니다. "
        "보고서를 forensics/analysis에0444로 저장하고 allocation-window 사건에 결속한다. "
        "행의 offset/length는 기존 범위 후보 도구로 독립 검증한 뒤 그 후보 보고서로 추출한다. "
        "이 보고서는 직접 추출 권위가 아니며 파일 소속·삭제/과거 할당·녹화 경계·재생을 판정하지 않는다. "
        "원시 파일명·시각·FAT값·bitmap 본문을 반환하지 않고 영상/음성을 해독하지 않는다."
    ), annotations=ANN_LOCAL_WRITE)
    @safe_tool
    async def forensics_allocation_window(
        case_id: str, evidence_id: str, partition: StrictInt,
        offset: StrictInt, length: StrictInt, max_seconds: StrictFloat | StrictInt = 45,
    ) -> dict:
        return await _allocation_run(S, case_id=case_id, evidence_id=evidence_id,
                                     partition=partition, offset=offset, length=length, max_seconds=max_seconds)

    namespace["forensics_allocation_window"] = forensics_allocation_window
    try:
        registered = server._tool_manager.get_tool("forensics_allocation_window")
        if registered is None:
            raise RuntimeError
        model = registered.fn_metadata.arg_model
        model.model_config["hide_input_in_errors"] = True
        model.model_rebuild(force=True)
    except Exception:
        raise RuntimeError("할당 창 도구의 비공개 입력 검증 설정을 완료하지 못했습니다.") from None
