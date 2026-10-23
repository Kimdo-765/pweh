"""같은 EV fd의 제한된 검색·구조 읽기로 미디어 단위 후보 위치를 기록한다."""

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

from mcp.server.mcpserver.utilities.func_metadata import FuncMetadata
from pydantic import StrictFloat, StrictInt, StrictStr, ValidationError
from pydantic_core import PydanticCustomError

from pweh import evidence as E, schemas
from pweh.case import CASE_ID_RE
from pweh.errors import PwehError, ValidationFailed
from pweh.mcpkit import ANN_LOCAL_WRITE, run_blocking_cancellable, safe_tool

MAX_REPORT_BYTES = 1 << 20
MAX_SCAN_BYTES = 1 << 30
MAX_EVIDENCE_BYTES = (1 << 63) - 1
_ERRORS = {
    "cancelled": "미디어 단위 이미지 검색이 취소되었습니다.",
    "time_limit": "미디어 단위 이미지 검색 준비의 시간 한도에 닿았습니다.",
    "validation_failed": "미디어 단위 이미지 검색 인자가 허용 범위가 아닙니다.",
    "authorization_required": "케이스의 소유 또는 허가 확인이 필요합니다.",
    "not_found": "요청한 케이스 또는 증거를 찾지 못했습니다.",
    "case_error": "케이스를 확인하지 못했습니다.",
    "custody_broken": "증거의 보관 기록을 검증하지 못했습니다.",
    "integrity_failed": "증거 또는 분석 출력의 무결성을 확인하지 못했습니다.",
    "evidence_error": "증거 확인 또는 분석 저장을 완료하지 못했습니다.",
    "media_unit_scan_read_failed": "미디어 단위 이미지 검색의 완전한 읽기를 확인하지 못했습니다.",
    "media_unit_scan_failed": "미디어 단위 이미지 검색을 완료하지 못했습니다.",
}


class _ServerAPI:
    """서버 runtime과 합성 시험의 주입을 늦은 참조로 유지한다."""

    def __init__(self, namespace: dict[str, Any]):
        self.namespace = namespace

    def __getattr__(self, name: str) -> Any:
        return self.namespace[name]


def _check(cancelled: threading.Event, deadline: float, *, timing: bool = True) -> None:
    if cancelled.is_set():
        raise PwehError(_ERRORS["cancelled"], code="cancelled")
    if timing and time.monotonic() >= deadline:
        raise PwehError(_ERRORS["time_limit"], code="time_limit")


def _arguments(case_id: Any, evidence_id: Any, format: Any, start_offset: Any,
               max_scan_bytes: Any, max_seconds: Any) -> float:
    from pweh.media_units import FORMATS

    if (type(case_id) is not str or len(case_id) > 80 or CASE_ID_RE.fullmatch(case_id) is None
            or type(evidence_id) is not str or re.fullmatch(r"EV-[0-9]{4,6}", evidence_id) is None
            or type(format) is not str or format not in FORMATS
            or type(start_offset) is not int or not 0 <= start_offset <= MAX_EVIDENCE_BYTES
            or type(max_scan_bytes) is not int or not 4 <= max_scan_bytes <= MAX_SCAN_BYTES
            or type(max_seconds) not in (int, float) or not 0 < max_seconds <= 45
            or not math.isfinite(max_seconds)):
        raise ValidationFailed(_ERRORS["validation_failed"])
    # 케이스 조회부터 같은 처리 예산을 쓰며 worker에서 새로 시작하지 않는다.
    return time.monotonic() + max_seconds


def _identity(st: os.stat_result) -> tuple[int, ...]:
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_nlink


def _check_opened(opened: E.OpenedEvidence) -> int:
    """처음 확인한 fd와 접수 크기를 대조한다. atime은 seal에 넣지 않는다."""
    size = opened.intake["size"]
    if type(size) is not int or not 1 <= size <= MAX_EVIDENCE_BYTES:
        raise ValidationFailed(_ERRORS["validation_failed"])
    before, now = opened.st, os.fstat(opened.fd)
    if (not stat.S_ISREG(before.st_mode) or not stat.S_ISREG(now.st_mode)
            or before.st_nlink != 1 or now.st_nlink != 1 or before.st_size != size
            or _identity(before) != _identity(now)):
        raise E.IntegrityProblem("미디어 단위 검색 중 증거의 파일 신원 또는 상태가 변경되었습니다.",
                                 reason="source-changed")
    return size


def _fixed_error(exc: Exception) -> PwehError:
    code = getattr(exc, "code", None)
    if type(code) is not str or code not in _ERRORS:
        code = "media_unit_scan_failed"
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
        data={"reason": "media-unit-scan-integrity-check", "problems": ["증거 무결성 검증 실패"],
              "found_by": "media-unit-scan"})
    try:
        _audit_commit(S, case, entry)
    except Exception:
        pass  # 커밋된 무결성 사건은 보조 감사 실패 뒤에도 유지한다.


async def _media_unit_scan_run(S: _ServerAPI, *, case_id: str, evidence_id: str, format: str,
                               start_offset: int, max_scan_bytes: int, max_seconds: float) -> dict:
    cancelled = threading.Event()
    try:
        deadline = _arguments(case_id, evidence_id, format, start_offset, max_scan_bytes, max_seconds)
        case = await S._case(case_id)

        def work_body() -> dict:
            from pweh.media_unit_stream import (PROFILES, MediaUnitScanLimits, scan_media_unit_stream,
                                                validate_media_unit_scan_accounting)

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
                            if read_problem is not None:
                                raise read_problem
                            # 시간 partial은 core가 판정하고 취소·fd 변경은 읽기 전후 거부한다.
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
                                raise PwehError(_ERRORS["media_unit_scan_read_failed"], code="media_unit_scan_read_failed")
                            return data
                        except Exception as exc:
                            # core가 원인을 고정 오류나 partial로 닫아도 최초 실패를 복원한다.
                            if read_problem is None:
                                read_problem = exc if isinstance(exc, PwehError) else PwehError(
                                    _ERRORS["media_unit_scan_read_failed"], code="media_unit_scan_read_failed")
                            raise read_problem from None

                    limits = dataclasses.replace(MediaUnitScanLimits(), max_output_bytes=MAX_REPORT_BYTES - (16 << 10))
                    try:
                        report = scan_media_unit_stream(
                            read_at, format=format, evidence_size=size, start_offset=start_offset,
                            max_scan_bytes=max_scan_bytes, limits=limits, deadline=deadline, cancel=cancelled.is_set)
                    except Exception:
                        if read_problem is not None:
                            raise read_problem from None
                        raise
                    if read_problem is not None:
                        raise read_problem from None
                    source = {"kind": "evidence", "evidence_id": evidence_id,
                              "evidence_sha256": opened.intake["hashes"]["sha256"], "evidence_size": size}
                    params = {"format": format, "start_offset": start_offset,
                              "max_scan_bytes": max_scan_bytes, "max_seconds": max_seconds}
                    report["source"], report["params"] = dict(source), dict(params)
                    schemas.validate("media-unit-scan", report)
                    validate_media_unit_scan_accounting(report)
                    if (report["format"] != format or report["profile"] != PROFILES[format]
                            or report["source"] != source or report["params"] != params
                            or type(report["source"]["evidence_size"]) is not int
                            or any(type(report["params"][key]) is not type(value) for key, value in params.items())):
                        raise ValidationFailed(_ERRORS["validation_failed"])
                    raw = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
                    if len(raw.encode("utf-8")) + 1 > MAX_REPORT_BYTES:
                        raise ValidationFailed(_ERRORS["validation_failed"])

                    def final_check() -> None:
                        # 시간 partial도 보존하며 취소·seal은 실제 custody append 직전까지 검사한다.
                        _check(cancelled, deadline, timing=False)
                        _check_opened(opened)

                    final_check()
                    return E.store_analysis(
                        case, opened, report, event="media-unit-scan", custody_log=S.custody(case),
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


class _MediaUnitScanMetadata(FuncMetadata):
    """입력 원문과 추가 키의 위치를 SDK 오류로 복사하지 않는다."""

    def validate_arguments(self, arguments_to_validate: dict) -> dict:
        try:
            return self.arg_model.model_validate(arguments_to_validate).model_dump_one_level()
        except ValidationError:
            raise ValidationError.from_exception_data(
                "MediaUnitScanInput", [{"type": PydanticCustomError("validation_failed", _ERRORS["validation_failed"]),
                                       "loc": (), "input": None}], hide_input=True,
            ) from None


def register_media_unit_scan_tools(server: Any, namespace: dict[str, Any]) -> None:
    """기존 포렌식 서버에 명시 형식 하나의 제한된 EV 검색을 등록한다."""
    S = _ServerAPI(namespace)

    @server.tool(description=(
        "접수한 EV 이미지에서 명시 format(jpeg, avc-annexb, mpeg2-ps, xm)의 고정 미디어 단위 후보를 나눠 읽어 검색한다. "
        "start_offset은 EV 절대 위치(기본0), max_scan_bytes는 연속 검색 읽기 합계4 bytes..1GiB(기본1GiB)다. "
        "leaf는64KiB 이하이며 검색 창 밖의 구조 읽기와 논리 검사량은 각각128MiB로 따로 제한한다. "
        "공통45초·1024 anchor·8192 구조단계·128 후보·JSON1MiB이며 전체 EV를 메모리에 올리지 않는다. "
        "offset/length는 EV 절대 단위 위치/길이, selection_offset/selection_length는 같은 후보의 재검증에 필요한 "
        "64MiB 이하 구간이다. 다음 delimiter/header가 필요한 AVC/PS에서는 두 길이가 다르다. "
        "미검사 prefix/tail·next_offset·이번 검색과 전체EV 검색 완료를 구분한다. "
        "선택 상한을 실제EOF로 취급하지 않으며 원본 파일·미할당·삭제·잔여·완전 녹화를 판정하지 않는다. "
        "source는 접수EV 해시이며 이번 전체 또는 개별 단위 재해시가 아니다. "
        "보고서를 forensics/analysis에0444로 저장하고 media-unit-scan 사건에 결속한다. "
        "시간 partial의 bounded 직렬화·최종seal 검사는 처리 시간 뒤 끝내되 취소를 계속 확인한다. "
        "추출은 selection_offset/selection_length로 같은 format의 forensics_media_unit_candidates를 호출한 뒤 "
        "좌표·길이·경계가 일치하는 새 보고서의 행을 찾아 forensics_extract_media_unit에 전달한다. "
        "이 검색 보고서는 직접 추출할 수 없다. 원시 헤더·본문·시각·채널을 반환하지 않으며 "
        "프레임/음성 해독·재생·암호화·형식 전체 적합성·조각 재조립을 검증하지 않는다."
    ), annotations=ANN_LOCAL_WRITE)
    @safe_tool
    async def forensics_media_unit_scan(
        case_id: StrictStr, evidence_id: StrictStr, format: StrictStr,
        start_offset: StrictInt = 0, max_scan_bytes: StrictInt = MAX_SCAN_BYTES,
        max_seconds: StrictFloat | StrictInt = 45,
    ) -> dict:
        return await _media_unit_scan_run(S, case_id=case_id, evidence_id=evidence_id, format=format,
                                         start_offset=start_offset, max_scan_bytes=max_scan_bytes,
                                         max_seconds=max_seconds)

    namespace["forensics_media_unit_scan"] = forensics_media_unit_scan
    try:
        registered = server._tool_manager.get_tool("forensics_media_unit_scan")
        if registered is None:
            raise RuntimeError
        old = registered.fn_metadata
        model = old.arg_model
        model.model_config.update(strict=True, extra="forbid", hide_input_in_errors=True)
        model.model_rebuild(force=True)
        registered.fn_metadata = _MediaUnitScanMetadata(
            arg_model=model, output_schema=old.output_schema,
            output_model=old.output_model, wrap_output=old.wrap_output)
        registered.parameters = model.model_json_schema(by_alias=True)
        if registered.parameters.get("additionalProperties") is not False:
            raise RuntimeError
    except Exception:
        raise RuntimeError("미디어 단위 검색 도구의 비공개 입력 검증 설정을 완료하지 못했습니다.") from None
