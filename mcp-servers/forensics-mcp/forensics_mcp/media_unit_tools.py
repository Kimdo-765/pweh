"""선택한 증거 바이트의 명시 형식의 미디어 단위 구조 후보만 기록하는 MCP 입구.

워커가 증거 fd를 커밋까지 소유한다. 선택 이름·본문·자유 형식 오류를 반환하지
않으며, 선택 바이트의 후보 검사와 전체 컨테이너 목록 범위를 구분한다.
"""

from __future__ import annotations

import dataclasses
import json
import math
import re
import threading
import time
from typing import Any

from pydantic import StrictFloat, StrictInt

from pweh import evidence as E, schemas
from pweh.errors import PwehError, ValidationFailed
from pweh.mcpkit import ANN_LOCAL_WRITE, run_blocking_cancellable, safe_tool

from . import fsops, media_candidate_selection as selection
from .media_tools import _residual_source, _source

MAX_FILE_BYTES = 64 << 20
MAX_REPORT_BYTES = 1 << 20
_FS_REF = r"(?:root|c[0-9]{1,10}(?:\+[0-9]{1,10})?|n[0-9]{1,10}\+[0-9]{1,10})/[0-9]{1,9}"
_REF = re.compile(r"(?:arc:[0-9]{1,6}|" + _FS_REF + r")\Z")
_METHODS = frozenset({"auto", "chain", "nofatchain", "contiguous", "skip-allocated",
                      "skip-claimed", "fat-chain", "stale-chain"})
_ERRORS = {
    "cancelled": "미디어 단위 후보 검사가 취소되었습니다.",
    "time_limit": "선택 파일 읽기의 시간 한도에 닿았습니다.",
    "validation_failed": "선택 파일 또는 후보 검사 인자가 허용 범위가 아닙니다.",
    "authorization_required": "케이스의 소유 또는 허가 확인이 필요합니다.",
    "not_found": "요청한 케이스 또는 증거를 찾지 못했습니다.",
    "case_error": "케이스를 확인하지 못했습니다.",
    "custody_broken": "증거의 보관 기록을 검증하지 못했습니다.",
    "integrity_failed": "증거 또는 분석 출력의 무결성을 확인하지 못했습니다.",
    "evidence_error": "증거 확인 또는 분석 저장을 완료하지 못했습니다.",
    "input_too_large": "선택 파일이 64 MiB 상한을 넘었습니다.",
    "invalid_selection": "선택 파일의 완전한 바이트를 확인하지 못했습니다.",
    "selection_failed": "검증된 선택 파일 하나를 찾지 못했습니다.",
    "media_unit_candidates_failed": "미디어 단위 후보 검사를 완료하지 못했습니다.",
}


class _ServerAPI:
    """서버 runtime과 시험 주입을 늦은 참조로 유지한다."""

    def __init__(self, namespace: dict[str, Any]):
        self.namespace = namespace

    def __getattr__(self, name: str) -> Any:
        return self.namespace[name]


def _check(cancelled: threading.Event, deadline: float, *, time_limit: bool = True) -> None:
    if cancelled.is_set():
        raise PwehError(_ERRORS["cancelled"], code="cancelled")
    if time_limit and time.monotonic() >= deadline:
        raise PwehError(_ERRORS["time_limit"], code="time_limit")


def _arguments(evidence_id: Any, format: Any, partition: Any, ref: Any, path: Any,
               method: Any, max_seconds: Any, *, offset: Any = None, length: Any = None,
               region: Any = "data") -> float:
    """원시 선택자를 오류에 복사하지 않고 공통 시간 한도를 만든다."""
    from pweh.media_units import FORMATS

    invalid = _ERRORS["validation_failed"]
    if type(region) is not str or region not in ("data", "residual"):
        raise ValidationFailed(invalid)
    if type(format) is not str or format not in FORMATS:
        raise ValidationFailed(invalid)
    if not isinstance(evidence_id, str) or re.fullmatch(r"EV-[0-9]{4,6}", evidence_id) is None:
        raise ValidationFailed(invalid)
    if ref is not None and path is not None:
        raise ValidationFailed(invalid)
    for item in (ref, path):
        if item is not None and (not isinstance(item, str) or not item.strip()
                                 or len(item) > 32768 or "\x00" in item):
            raise ValidationFailed(invalid)
    if ref is not None and _REF.fullmatch(ref) is None:
        raise ValidationFailed(invalid)
    if partition is not None and (type(partition) is not int or not 1 <= partition <= 4096):
        raise ValidationFailed(invalid)
    if not isinstance(method, str) or method not in _METHODS:
        raise ValidationFailed(invalid)
    if region == "residual":
        if (type(partition) is not int or not 1 <= partition <= 4096
                or type(ref) is not str or re.fullmatch(_FS_REF, ref) is None
                or any(v is not None for v in (path, offset, length))
                or type(method) is not str or method not in (_METHODS - {"skip-claimed", "fat-chain"})):
            raise ValidationFailed(invalid)
    if ref is None and path is None and (partition is not None or method != "auto"):
        raise ValidationFailed(invalid)
    if offset is not None or length is not None:
        if (type(offset) is not int or type(length) is not int
                or any(value is not None for value in (partition, ref, path)) or method != "auto"
                or not 0 <= offset <= selection.MAX_RANGE_END or not 1 <= length <= MAX_FILE_BYTES
                or length > selection.MAX_RANGE_END - offset):
            raise ValidationFailed(invalid)
    if type(max_seconds) not in (int, float) or not 0 < max_seconds <= 45 or not math.isfinite(max_seconds):
        raise ValidationFailed(invalid)
    return time.monotonic() + max_seconds


def _selection_coverage(report: dict, source: dict) -> None:
    """후보 검색 완료를 보존하면서 출처 불확실성은 unsupported에도 표시한다."""
    uncertain = (source["deleted"] is True or source["parent_deleted"] is True
                 or source["confidence"] != "high"
                 or (source["container"] == "filesystem" and source["parent_deleted"] is None))
    report["coverage"]["selection_uncertain"] = uncertain
    reasons = report["coverage"]["reasons"]
    if uncertain and "selection_uncertain" not in reasons:
        reasons.append("selection_uncertain")
    if source["container_truncated"] is True and "container_listing_incomplete" not in reasons:
        reasons.append("container_listing_incomplete")
    if uncertain or source["container_truncated"] is True:
        report["status"] = "partial"


def _audit_commit(S: _ServerAPI, case: Any, entry: dict) -> None:
    try:
        S.rt().audit({"event": "forensics_" + entry["event"].replace("-", "_"),
                      "evidence_id": entry.get("evidence_id"), "custody_seq": entry.get("seq"),
                      "custody_hash": entry.get("hash")}, case.id)
    except Exception:
        raise PwehError("보조 감사 기록을 완료하지 못했습니다.", code="evidence_error") from None


def _record_integrity(S: _ServerAPI, case: Any, evidence_id: str, exc: E.IntegrityProblem) -> None:
    if not exc.record:
        return
    entry = S.custody(case).append(
        "integrity-failed", evidence_id=evidence_id, actor="server",
        data={"reason": "media-unit-candidates-integrity-check", "problems": ["증거 무결성 검증 실패"],
              "found_by": "media-unit-candidates"})
    try:
        _audit_commit(S, case, entry)
    except PwehError:
        pass  # 이미 커밋한 무결성 사건은 보조 감사 오류 뒤에도 유지한다.


def _fixed_error(exc: Exception) -> PwehError:
    code, reason = getattr(exc, "code", None), getattr(exc, "reason", None)
    # FS 순회 예산은 별도 reason과 닫힌 limit 코드로 취소/시간을 표현한다.
    details = getattr(exc, "data", None)
    if reason == "budget_exceeded" and isinstance(details, dict):
        limit = details.get("limit")
        if limit in ("cancelled", "time"):
            reason = limit
    if reason == "cancelled":
        code = "cancelled"
    elif reason in ("time", "timeout", "time_limit") or code == "timeout":
        code = "time_limit"
    elif reason == "max_bytes":
        code = "input_too_large"
    elif reason in ("incomplete_file", "crc_mismatch"):
        code = "invalid_selection"
    elif reason in ("bad_ref", "not_found", "ambiguous_path", "refs_unverifiable"):
        code = "selection_failed"
    elif code in ("media_prefix_input_invalid", "media_prefix_input_changed"):
        code = "invalid_selection"
    elif code == "media_prefix_input_limit":
        code = "input_too_large"
    if not isinstance(code, str) or code not in _ERRORS:
        code = "media_unit_candidates_failed"
    return PwehError(_ERRORS[code], code=code)


async def _media_unit_run(S: _ServerAPI, *, case_id: str, evidence_id: str, format: str,
                         partition: int | None, ref: str | None, path: str | None,
                         method: str, max_seconds: float, offset: int | None = None,
                         length: int | None = None, region: str = "data") -> dict:
    cancelled = threading.Event()
    try:
        deadline = _arguments(evidence_id, format, partition, ref, path, method, max_seconds, offset=offset, length=length, region=region)
        case = await S._case(case_id)

        def work_body() -> dict:
            from pweh.media_units import (MediaUnitLimits, FILE_PROFILES, RANGE_PROFILES,
                                          RESIDUAL_PROFILES, RESIDUAL_LIMITATIONS,
                                          scan_media_unit_candidates, validate_media_unit_accounting)

            _check(cancelled, deadline)
            entries = S.custody(case).entries()
            try:
                with E.open_checked(case, evidence_id, entries, reference_roots=S._reference_roots()) as opened:
                    if region == "residual":
                        try:
                            with fsops.image_reader(opened.fd) as img:
                                data, member = fsops.read_selected_residual(
                                    img, partition=partition, ref=ref, method=method,
                                    max_bytes=MAX_FILE_BYTES, deadline=deadline, cancel=cancelled.is_set)
                        except fsops.FsError as exc:
                            if exc.reason in ("bad_argument", "unsupported_fs"):
                                raise PwehError(_ERRORS["invalid_selection"], code="invalid_selection") from None
                            raise
                        _check(cancelled, deadline)
                        source = _residual_source(opened, evidence_id, member, data)
                        if (source["partition"] != partition or source["ref"] != ref
                                or method != "auto" and source["method"] != method):
                            raise ValidationFailed(_ERRORS["validation_failed"])
                    elif offset is None:
                        data, member = fsops.read_selected_file(
                            opened.fd, partition=partition, ref=ref, path=path, method=method,
                            max_bytes=MAX_FILE_BYTES, deadline=deadline, cancel=cancelled.is_set,
                            allow_empty=True)
                        _check(cancelled, deadline)
                        source = _source(opened, evidence_id, member, data)
                    else:
                        data, source = selection.read_candidate_range(
                            opened, offset, length, deadline=deadline, cancel=cancelled.is_set)
                        _check(cancelled, deadline)
                    limits = dataclasses.replace(MediaUnitLimits(), max_output_bytes=MAX_REPORT_BYTES - (16 << 10))
                    report = scan_media_unit_candidates(data, format=format, limits=limits, deadline=deadline, cancel=cancelled.is_set)
                    report["source"] = source
                    report["params"] = {"format": format, "partition": partition, "method": method, "max_seconds": max_seconds}
                    if region == "residual":
                        report["profile"] = RESIDUAL_PROFILES[format]
                        report["limitations"] = [*report["limitations"], *RESIDUAL_LIMITATIONS]
                        report["params"]["region"] = "residual"
                    elif offset is not None:
                        # 순수 scanner의 좌표는 그대로다. 명시 구간의 출처·한계만 별도 profile로 닫는다.
                        report["profile"] = RANGE_PROFILES[format]
                        report["limitations"] = [*report["limitations"], *selection.RANGE_LIMITATIONS]
                        report["params"].update(offset=offset, length=length)
                        if (type(source["offset"]) is not int or source["offset"] != offset
                                or type(source["selected_size"]) is not int or source["selected_size"] != length
                                or source["selected_size"] != len(data)):
                            raise ValidationFailed(_ERRORS["validation_failed"])
                    expected_profile = (RESIDUAL_PROFILES[format] if region == "residual"
                                        else RANGE_PROFILES[format] if offset is not None else FILE_PROFILES[format])
                    if report["format"] != format or report["profile"] != expected_profile:
                        raise ValidationFailed(_ERRORS["validation_failed"])
                    _selection_coverage(report, source)
                    schemas.validate("media-unit-candidates", report)
                    validate_media_unit_accounting(report)
                    # 회계 검증은 출처를 읽지 않는다. 실제 선택 bytes와의 결속은 입구가 확인한다.
                    if (type(source["selected_size"]) is not int
                            or source["selected_size"] != len(data)
                            or report["coverage"]["input_bytes"] != len(data)):
                        raise ValidationFailed(_ERRORS["validation_failed"])
                    raw = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
                    if len(raw.encode("utf-8")) + 1 > MAX_REPORT_BYTES:
                        raise ValidationFailed(_ERRORS["validation_failed"])

                    def final_check() -> None:
                        # scanner가 만료로 반환한 partial도 기록하지만 취소·같은 fd seal은 끝까지 확인한다.
                        _check(cancelled, deadline, time_limit=False)
                        if offset is not None:
                            selection.check_candidate_range(opened, source, deadline=deadline,
                                                            cancel=cancelled.is_set, time_limit=False)

                    final_check()
                    return E.store_analysis(
                        case, opened, report, event="media-unit-candidates", custody_log=S.custody(case),
                        reference_roots=lambda: S._reference_roots(),
                        check=final_check,
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


def register_media_unit_tools(server: Any, namespace: dict[str, Any]) -> None:
    """기존 서버에 명시한 네 형식의 제한된 단위 구조 후보 도구를 등록한다."""
    S = _ServerAPI(namespace)

    @server.tool(description=(
        "선택한 완전 파일 또는 EV 명시 구간에서 format 하나의 고정 미디어 단위 구조 후보를 관찰한다. "
        "format은 jpeg, avc-annexb, mpeg2-ps, xm만 받으며 자동 형식 판정은 하지 않는다. "
        "ref/path는 FAT/exFAT·TAR/ZIP 파일 하나, 둘 다 없으면 EV 전체다. "
        "offset/length는 exact int로 함께 지정하고 selector·partition과 혼용하지 않으며 method=auto만 허용한다. "
        "region 기본 data는 기존 선택이다. residual은 명시 partition+FS ref의 exFAT 파일에서 "
        "ValidDataLength 뒤 DataLength까지의 완전한 잔여만 읽고 path/offset/length는 받지 않는다. "
        "residual source19는 두 논리 길이·선택 SHA를 결속하며 VDL+후보 offset은 파일 논리좌표다. "
        "선택 최대64MiB·공통45초·후보128개이며 candidate.offset/length는 선택 bytes 상대다. "
        "구간 모드에서만 source.offset을 더해 EV 위치를 계산한다. "
        "JPEG baseline 단일 scan의 EOI, AVC 다음 NAL delimiter, MPEG-2 PS 검증 pack prefix, "
        "XM 고정 header의 선언 길이만 검사한다. PS prefix는 부분 경계로 보존하고 마지막 열린 AVC는 추출 후보가 아니다. "
        "선택 전체 SHA·크기 및 원래 삭제/복구/목록 불확실성을 source와 coverage에 기록한다. "
        "원시 header·본문·시각·채널·선택 이름·개별 후보 hash는 반환하지 않는다. "
        "source.complete는 선택 읽기 완료이며 내용/영상 해독·형식 전체 적합성·재생·암호화·원본 파일 경계·완전 녹화는 검증하지 않는다. "
        "닫힌 JSON을 forensics/analysis에0444로 저장하고 media-unit-candidates 사건에 결속한다. "
        "추출은 저장 보고서/index를 forensics_extract_media_unit에 전달한다. 전체 카드 자동검색·조각 재조립은 하지 않는다."
    ), annotations=ANN_LOCAL_WRITE)
    @safe_tool
    async def forensics_media_unit_candidates(
        case_id: str, evidence_id: str, format: str, partition: StrictInt | None = None,
        ref: str | None = None, path: str | None = None, method: str = "auto",
        max_seconds: StrictFloat | StrictInt = 45,
        offset: StrictInt | None = None, length: StrictInt | None = None, region: str = "data",
    ) -> dict:
        return await _media_unit_run(S, case_id=case_id, evidence_id=evidence_id, format=format, partition=partition,
                                    ref=ref, path=path, method=method, max_seconds=max_seconds,
                                    offset=offset, length=length, region=region)

    namespace["forensics_media_unit_candidates"] = forensics_media_unit_candidates
    try:
        registered = server._tool_manager.get_tool("forensics_media_unit_candidates")
        if registered is None:
            raise RuntimeError
        model = registered.fn_metadata.arg_model
        model.model_config["hide_input_in_errors"] = True
        model.model_rebuild(force=True)
    except Exception:
        raise RuntimeError("미디어 단위 후보 도구의 비공개 입력 검증 설정을 완료하지 못했습니다.") from None
