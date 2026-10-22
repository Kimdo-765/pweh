"""선택한 증거 바이트의 DHAV 고정 record 구조 후보만 기록하는 MCP 입구.

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
from .media_tools import _source

MAX_FILE_BYTES = 64 << 20
MAX_REPORT_BYTES = 1 << 20
_FS_REF = r"(?:root|c[0-9]{1,10}(?:\+[0-9]{1,10})?|n[0-9]{1,10}\+[0-9]{1,10})/[0-9]{1,9}"
_REF = re.compile(r"(?:arc:[0-9]{1,6}|" + _FS_REF + r")\Z")
_METHODS = frozenset({"auto", "chain", "nofatchain", "contiguous", "skip-allocated",
                      "skip-claimed", "fat-chain", "stale-chain"})
_ERRORS = {
    "cancelled": "DHAV 후보 검사가 취소되었습니다.",
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
    "dhav_candidates_failed": "DHAV 후보 검사를 완료하지 못했습니다.",
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


def _arguments(evidence_id: Any, partition: Any, ref: Any, path: Any,
               method: Any, max_seconds: Any, *, offset: Any = None, length: Any = None) -> float:
    """원시 선택자를 오류에 복사하지 않고 공통 시간 한도를 만든다."""
    invalid = _ERRORS["validation_failed"]
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
        data={"reason": "dhav-candidates-integrity-check", "problems": ["증거 무결성 검증 실패"],
              "found_by": "dhav-candidates"})
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
        code = "dhav_candidates_failed"
    return PwehError(_ERRORS[code], code=code)


async def _dhav_run(S: _ServerAPI, *, case_id: str, evidence_id: str,
                         partition: int | None, ref: str | None, path: str | None,
                         method: str, max_seconds: float, offset: int | None = None,
                         length: int | None = None) -> dict:
    cancelled = threading.Event()
    try:
        deadline = _arguments(evidence_id, partition, ref, path, method, max_seconds, offset=offset, length=length)
        case = await S._case(case_id)

        def work_body() -> dict:
            from pweh.dhav import (DhavLimits, RANGE_PROFILE, RANGE_LIMITATIONS,
                                   scan_dhav_candidates, validate_dhav_accounting)

            _check(cancelled, deadline)
            entries = S.custody(case).entries()
            try:
                with E.open_checked(case, evidence_id, entries, reference_roots=S._reference_roots()) as opened:
                    if offset is None:
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
                    limits = dataclasses.replace(DhavLimits(), max_output_bytes=MAX_REPORT_BYTES - (16 << 10))
                    report = scan_dhav_candidates(data, limits=limits, deadline=deadline, cancel=cancelled.is_set)
                    report["source"] = source
                    report["params"] = {"partition": partition, "method": method, "max_seconds": max_seconds}
                    if offset is not None:
                        # 순수 scanner의 좌표는 그대로다. 명시 구간의 출처·한계만 별도 profile로 닫는다.
                        report["profile"] = RANGE_PROFILE
                        report["limitations"] = [*report["limitations"], *RANGE_LIMITATIONS]
                        report["params"].update(offset=offset, length=length)
                        if (type(source["offset"]) is not int or source["offset"] != offset
                                or type(source["selected_size"]) is not int or source["selected_size"] != length
                                or source["selected_size"] != len(data)):
                            raise ValidationFailed(_ERRORS["validation_failed"])
                    _selection_coverage(report, source)
                    schemas.validate("dhav-candidates", report)
                    validate_dhav_accounting(report)
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
                        case, opened, report, event="dhav-candidates", custody_log=S.custody(case),
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


def register_dhav_tools(server: Any, namespace: dict[str, Any]) -> None:
    """기존 서버에 선택 바이트의 제한된 DHAV record 구조 후보 도구를 등록한다."""
    S = _ServerAPI(namespace)

    @server.tool(description=(
        "선택한 완전 파일 또는 EV의 명시 바이트 구간에서 DHAV 고정 record 구조 후보를 관찰한다. "
        "ref/path는 FAT/exFAT·TAR/ZIP 파일 하나이며 둘 다 없으면 EV 전체를 읽는다. "
        "offset/length는 exact int로 함께 지정하고 선택자·partition과 혼용하지 않으며 method=auto만 받는다. "
        "선택·구간은 최대 64 MiB, offset+length는 실제 EV 안이어야 한다. 구간 밖은 검사하지 않는다. "
        "고정 DHAV type f0/fc/fd의 선언 길이와 끝 표지·반복 길이만 대조하고 최대 128개 후보를 기록한다. "
        "후보 offset은 선택 bytes 상대이며 구간 모드에서만 source.offset을 더해 EV 내 위치를 계산한다. "
        "출처16필드 또는 구간18필드에 선택 전체 SHA·크기와 EV 크기/시작을 결속한다. "
        "선택/검색은 최대 45초이며 시간·한도·삭제/복구·전체 목록 불확실성을 coverage에 보존한다. "
        "source.complete는 선택 읽기 의미이며 record checksum·본문 의미·시각·암호화·재생·완전 녹화는 검증하지 않는다. "
        "선택 이름·원시 헤더/확장/본문·시각/채널·개별 record 해시는 반환하지 않는다. "
        "닫힌 메타데이터 JSON은 forensics/analysis에 0444로 저장하고 dhav-candidates 사건에 결속한다. "
        "추출·해독·재조립·전체 카드 자동 검색은 하지 않는다."
    ), annotations=ANN_LOCAL_WRITE)
    @safe_tool
    async def forensics_dhav_candidates(
        case_id: str, evidence_id: str, partition: StrictInt | None = None,
        ref: str | None = None, path: str | None = None, method: str = "auto",
        max_seconds: StrictFloat | StrictInt = 45,
        offset: StrictInt | None = None, length: StrictInt | None = None,
    ) -> dict:
        return await _dhav_run(S, case_id=case_id, evidence_id=evidence_id, partition=partition,
                                    ref=ref, path=path, method=method, max_seconds=max_seconds,
                                    offset=offset, length=length)

    namespace["forensics_dhav_candidates"] = forensics_dhav_candidates
    try:
        registered = server._tool_manager.get_tool("forensics_dhav_candidates")
        if registered is None:
            raise RuntimeError
        model = registered.fn_metadata.arg_model
        model.model_config["hide_input_in_errors"] = True
        model.model_rebuild(force=True)
    except Exception:
        raise RuntimeError("DHAV 후보 도구의 비공개 입력 검증 설정을 완료하지 못했습니다.") from None
