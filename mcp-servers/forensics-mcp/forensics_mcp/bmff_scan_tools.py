"""같은 EV fd에서 제한된 BMFF 검색 창과 구조 필드를 읽는 MCP 입구."""

from __future__ import annotations

import dataclasses
import json
import math
import os
import re
import stat
import threading
import time
from typing import Any

from pydantic import StrictFloat, StrictInt

from pweh import evidence as E, schemas
from pweh.errors import PwehError, ValidationFailed
from pweh.mcpkit import ANN_LOCAL_WRITE, run_blocking_cancellable, safe_tool

MAX_REPORT_BYTES = 1 << 20
MAX_SCAN_BYTES = 1 << 30
MAX_EVIDENCE_BYTES = (1 << 63) - 1
_ERRORS = {
    "cancelled": "BMFF 이미지 검색이 취소되었습니다.",
    "time_limit": "BMFF 이미지 검색 준비의 시간 한도에 닿았습니다.",
    "validation_failed": "BMFF 이미지 검색 인자가 허용 범위가 아닙니다.",
    "authorization_required": "케이스의 소유 또는 허가 확인이 필요합니다.",
    "not_found": "요청한 케이스 또는 증거를 찾지 못했습니다.",
    "case_error": "케이스를 확인하지 못했습니다.",
    "custody_broken": "증거의 보관 기록을 검증하지 못했습니다.",
    "integrity_failed": "증거 또는 분석 출력의 무결성을 확인하지 못했습니다.",
    "evidence_error": "증거 확인 또는 분석 저장을 완료하지 못했습니다.",
    "bmff_scan_read_failed": "BMFF 이미지 검색의 완전한 읽기를 확인하지 못했습니다.",
    "bmff_scan_failed": "BMFF 이미지 검색을 완료하지 못했습니다.",
}


class _ServerAPI:
    """서버 runtime과 시험 주입을 늦은 참조로 유지한다."""

    def __init__(self, namespace: dict[str, Any]):
        self.namespace = namespace

    def __getattr__(self, name: str) -> Any:
        return self.namespace[name]


def _check(cancelled: threading.Event, deadline: float, *, timing: bool = True) -> None:
    if cancelled.is_set():
        raise PwehError(_ERRORS["cancelled"], code="cancelled")
    if timing and time.monotonic() >= deadline:
        raise PwehError(_ERRORS["time_limit"], code="time_limit")


def _arguments(evidence_id: Any, start_offset: Any, max_scan_bytes: Any, max_seconds: Any) -> float:
    if (type(evidence_id) is not str or re.fullmatch(r"EV-[0-9]{4,6}", evidence_id) is None
            or type(start_offset) is not int or not 0 <= start_offset <= MAX_EVIDENCE_BYTES
            or type(max_scan_bytes) is not int or not 8 <= max_scan_bytes <= MAX_SCAN_BYTES
            or type(max_seconds) not in (int, float)
            or not 0 < max_seconds <= 45 or not math.isfinite(max_seconds)):
        raise ValidationFailed(_ERRORS["validation_failed"])
    return time.monotonic() + max_seconds


def _identity(st: os.stat_result) -> tuple[int, ...]:
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_nlink


def _check_opened(opened: E.OpenedEvidence) -> int:
    """처음 확인한 fd 신원·전체 seal·접수 크기를 대조한다. 경로를 다시 열지 않는다."""
    size = opened.intake["size"]
    if type(size) is not int or not 1 <= size <= MAX_EVIDENCE_BYTES:
        raise ValidationFailed(_ERRORS["validation_failed"])
    before, now = opened.st, os.fstat(opened.fd)
    if (not stat.S_ISREG(before.st_mode) or not stat.S_ISREG(now.st_mode)
            or before.st_nlink != 1 or now.st_nlink != 1 or before.st_size != size
            or _identity(before) != _identity(now)):
        raise E.IntegrityProblem("이미지 검색 중 증거의 파일 신원 또는 상태가 변경되었습니다.",
                                 reason="source-changed")
    return size


def _fixed_error(exc: Exception) -> PwehError:
    code = getattr(exc, "code", None)
    if type(code) is not str or code not in _ERRORS:
        code = "bmff_scan_failed"
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
        data={"reason": "bmff-scan-integrity-check", "problems": ["증거 무결성 검증 실패"],
              "found_by": "bmff-scan"})
    try:
        _audit_commit(S, case, entry)
    except Exception:
        pass  # 이미 커밋한 무결성 사건은 보조 감사 오류 뒤에도 유지한다.


async def _bmff_scan_run(S: _ServerAPI, *, case_id: str, evidence_id: str,
                         start_offset: int, max_scan_bytes: int, max_seconds: float) -> dict:
    cancelled = threading.Event()
    try:
        deadline = _arguments(evidence_id, start_offset, max_scan_bytes, max_seconds)
        case = await S._case(case_id)

        def work_body() -> dict:
            from pweh.bmff_stream import BmffScanLimits, scan_bmff_stream, validate_bmff_scan_accounting

            _check(cancelled, deadline)
            entries = S.custody(case).entries()
            read_problem = None
            try:
                with E.open_checked(case, evidence_id, entries, reference_roots=S._reference_roots()) as opened:
                    size = _check_opened(opened)
                    if start_offset > size:
                        raise ValidationFailed(_ERRORS["validation_failed"])

                    def read_at(offset: int, length: int) -> bytes:
                        nonlocal read_problem
                        try:
                            # 시간 한도는 core가 partial로 기록한다. 취소와 fd 변경은 읽기 전후 거부한다.
                            _check(cancelled, deadline, timing=False)
                            if (type(offset) is not int or type(length) is not int
                                    or not 0 <= offset <= size or not 1 <= length <= 65536
                                    or length > size - offset):
                                raise ValidationFailed(_ERRORS["validation_failed"])
                            _check_opened(opened)
                            data = os.pread(opened.fd, length, offset)
                            _check_opened(opened)
                            _check(cancelled, deadline, timing=False)
                            if type(data) is not bytes or len(data) != length:
                                raise PwehError(_ERRORS["bmff_scan_read_failed"], code="bmff_scan_read_failed")
                            return data
                        except Exception as exc:
                            # 순수 reader가 예외 내용을 닫아도 서버는 원래 취소·무결성 원인을 유지한다.
                            read_problem = exc
                            raise

                    limits = dataclasses.replace(BmffScanLimits(), max_output_bytes=MAX_REPORT_BYTES - (16 << 10))
                    try:
                        report = scan_bmff_stream(read_at, evidence_size=size, start_offset=start_offset,
                                                  max_scan_bytes=max_scan_bytes, limits=limits,
                                                  deadline=deadline, cancel=cancelled.is_set)
                    except Exception:
                        if read_problem is not None:
                            raise read_problem from None
                        raise
                    report["source"] = {"kind": "evidence", "evidence_id": evidence_id,
                                        "evidence_sha256": opened.intake["hashes"]["sha256"], "evidence_size": size}
                    report["params"] = {"start_offset": start_offset, "max_scan_bytes": max_scan_bytes,
                                        "max_seconds": max_seconds}
                    schemas.validate("bmff-scan", report)
                    validate_bmff_scan_accounting(report)
                    raw = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
                    if len(raw.encode("utf-8")) + 1 > MAX_REPORT_BYTES:
                        raise ValidationFailed(_ERRORS["validation_failed"])

                    def final_check() -> None:
                        # 시간 초과 partial은 저장하되 취소·seal 검사는 커밋 직전까지 유지한다.
                        _check(cancelled, deadline, timing=False)
                        _check_opened(opened)

                    final_check()
                    return E.store_analysis(
                        case, opened, report, event="bmff-scan", custody_log=S.custody(case),
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


def register_bmff_scan_tools(server: Any, namespace: dict[str, Any]) -> None:
    """기존 서버에 전체 EV를 메모리에 올리지 않는 제한된 구조 검색을 등록한다."""
    S = _ServerAPI(namespace)

    @server.tool(description=(
        "접수한 EV 이미지에서 ftyp 기반 BMFF 연속 최상위 상자 prefix 후보를 나눠 읽어 검색한다. "
        "start_offset은 EV 절대 위치(기본0), max_scan_bytes는 연속 검색 읽기 합계8 bytes..1 GiB(기본1 GiB)다. "
        "64 KiB 이하 창과 메모리 carry로 창 경계 표지를 확인한다. 구조 필드는 별도1 MiB까지 읽으며 "
        "검색 창 밖이라도 EV 안의 헤더/브랜드를 검사한다. 전체 EV를 메모리에 올리지 않는다. "
        "최대45초·1024 anchor·128 후보·JSON1 MiB, 검증 prefix는16 bytes..64 MiB다. "
        "64 MiB 상한에서는 완전한 상자 경계까지만 남기며 size0을 EV 끝까지 확장하지 않는다. "
        "미검사 prefix/tail·한도·next_offset과 이번 검색/전체 EV 검색 완료를 구분한다. "
        "후보 offset/validated_prefix_length는 EV 절대 위치와 검증 prefix 길이이며 "
        "미할당·삭제·잔여·원본 파일 경계 판정은 아니다. source 해시는 접수 EV 해시이며 이번 전체 재해시가 아니다. "
        "보고서를 forensics/analysis에0444로 저장하고 bmff-scan 사건에 결속한다. "
        "추출하려면 후보 offset/validated_prefix_length로 forensics_media_candidates(offset,length)를 별도 호출해 "
        "구간 전체 해시·후보를 다시 검증한 다음 그 보고서를 forensics_extract_media_candidate에 준다. "
        "이 검색 보고서를 직접 추출에 쓰지 않는다. 원문 헤더/브랜드/본문/시각은 반환하지 않으며 "
        "후보 간 관계·영상/음성 해독·재생·암호화·조각 재조립·완전 녹화는 검증하지 않는다."
    ), annotations=ANN_LOCAL_WRITE)
    @safe_tool
    async def forensics_bmff_scan(
        case_id: str, evidence_id: str, start_offset: StrictInt = 0,
        max_scan_bytes: StrictInt = MAX_SCAN_BYTES, max_seconds: StrictFloat | StrictInt = 45,
    ) -> dict:
        return await _bmff_scan_run(S, case_id=case_id, evidence_id=evidence_id,
                                    start_offset=start_offset, max_scan_bytes=max_scan_bytes,
                                    max_seconds=max_seconds)

    namespace["forensics_bmff_scan"] = forensics_bmff_scan
    try:
        registered = server._tool_manager.get_tool("forensics_bmff_scan")
        if registered is None:
            raise RuntimeError
        model = registered.fn_metadata.arg_model
        model.model_config["hide_input_in_errors"] = True
        model.model_rebuild(force=True)
    except Exception:
        raise RuntimeError("BMFF 검색 도구의 비공개 입력 검증 설정을 완료하지 못했습니다.") from None
