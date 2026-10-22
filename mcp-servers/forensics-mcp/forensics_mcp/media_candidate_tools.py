"""선택한 증거 바이트의 BMFF 연속 prefix 후보만 기록하는 MCP 입구.

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

from . import fsops
from .media_tools import _source

MAX_FILE_BYTES = 64 << 20
MAX_REPORT_BYTES = 1 << 20
_FS_REF = r"(?:root|c[0-9]{1,10}(?:\+[0-9]{1,10})?|n[0-9]{1,10}\+[0-9]{1,10})/[0-9]{1,9}"
_REF = re.compile(r"(?:arc:[0-9]{1,6}|" + _FS_REF + r")\Z")
_METHODS = frozenset({"auto", "chain", "nofatchain", "contiguous", "skip-allocated",
                      "skip-claimed", "fat-chain", "stale-chain"})
_ERRORS = {
    "cancelled": "미디어 후보 검사가 취소되었습니다.",
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
    "media_candidates_failed": "미디어 후보 검사를 완료하지 못했습니다.",
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
               method: Any, max_seconds: Any) -> float:
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
        data={"reason": "media-candidates-integrity-check", "problems": ["증거 무결성 검증 실패"],
              "found_by": "media-candidates"})
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
    if not isinstance(code, str) or code not in _ERRORS:
        code = "media_candidates_failed"
    return PwehError(_ERRORS[code], code=code)


async def _candidates_run(S: _ServerAPI, *, case_id: str, evidence_id: str,
                         partition: int | None, ref: str | None, path: str | None,
                         method: str, max_seconds: float) -> dict:
    cancelled = threading.Event()
    try:
        deadline = _arguments(evidence_id, partition, ref, path, method, max_seconds)
        case = await S._case(case_id)

        def work_body() -> dict:
            from pweh.media_candidates import BmffCandidateLimits, scan_bmff_candidates

            _check(cancelled, deadline)
            entries = S.custody(case).entries()
            try:
                with E.open_checked(case, evidence_id, entries, reference_roots=S._reference_roots()) as opened:
                    data, member = fsops.read_selected_file(
                        opened.fd, partition=partition, ref=ref, path=path, method=method,
                        max_bytes=MAX_FILE_BYTES, deadline=deadline, cancel=cancelled.is_set,
                        allow_empty=True)
                    _check(cancelled, deadline)
                    source = _source(opened, evidence_id, member, data)
                    limits = dataclasses.replace(BmffCandidateLimits(), max_output_bytes=MAX_REPORT_BYTES - (16 << 10))
                    report = scan_bmff_candidates(data, limits=limits, deadline=deadline, cancel=cancelled.is_set)
                    report["source"] = source
                    report["params"] = {"partition": partition, "method": method, "max_seconds": max_seconds}
                    _selection_coverage(report, source)
                    if (report["coverage"]["input_bytes"] != len(data)
                            or report["summary"]["candidates_reported"] != len(report["candidates"])):
                        raise ValidationFailed(_ERRORS["validation_failed"])
                    schemas.validate("media-candidates", report)
                    raw = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
                    if len(raw.encode("utf-8")) + 1 > MAX_REPORT_BYTES:
                        raise ValidationFailed(_ERRORS["validation_failed"])
                    _check(cancelled, deadline, time_limit=False)
                    return E.store_analysis(
                        case, opened, report, event="media-candidates", custody_log=S.custody(case),
                        reference_roots=lambda: S._reference_roots(),
                        check=lambda: _check(cancelled, deadline, time_limit=False),
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


def register_media_candidate_tools(server: Any, namespace: dict[str, Any]) -> None:
    """기존 서버에 선택 바이트의 제한된 연속 prefix 후보 도구를 등록한다."""
    S = _ServerAPI(namespace)

    @server.tool(
        description=(
            "증거에서 선택한 파일 1개의 완전한 바이트에서 ftyp 기반 ISO BMFF 연속 최상위 상자 prefix 후보를 찾는다. "
            "소유/허가·보관 기록·무결성 확인 후 FAT/exFAT·TAR/ZIP ref 또는 path 하나를 선택한다. "
            "둘 다 없으면 EV 전체를 선택한다. 최대 64 MiB, max_seconds는 0 초 초과·최대 45초이며 "
            "선택·읽기·후보 검색에 같은 시간 예산을 쓴다. 후보는 최대 128개로 고정된다. "
            "선택 바이트 기준 offset·검증한 prefix 길이·고정 상자 종류·반환 후보 사이 관계와 미검사 범위를 기록한다. "
            "원본 파일 경계·전체 녹화·미디어 형식 적합성·재생·녹화 시각·암호화는 확인하지 않는다. "
            "삭제·복구·부모 미확인 또는 잘린 컨테이너 출처는 후보 0개여도 partial로 표시한다. "
            "전체 카드 자동 검색·residual 검색·물리 카빙·파일 추출·프레임·음성 해독은 하지 않는다. "
            "빈 파일·지원 anchor가 없는 선택도 unsupported로 기록할 수 있다. "
            "이름·경로·본문·자유 형식 상자/브랜드 값은 반환하거나 저장하지 않는다. "
            "고정 분류 JSON만 forensics/analysis/에 0444로 저장하고 media-candidates 보관 기록에 해시를 결속한다."
        ), annotations=ANN_LOCAL_WRITE,
    )
    @safe_tool
    async def forensics_media_candidates(
        case_id: str, evidence_id: str, partition: StrictInt | None = None,
        ref: str | None = None, path: str | None = None, method: str = "auto",
        max_seconds: StrictFloat | StrictInt = 45,
    ) -> dict:
        return await _candidates_run(S, case_id=case_id, evidence_id=evidence_id, partition=partition,
                                    ref=ref, path=path, method=method, max_seconds=max_seconds)

    namespace["forensics_media_candidates"] = forensics_media_candidates
    try:
        registered = server._tool_manager.get_tool("forensics_media_candidates")
        if registered is None:
            raise RuntimeError
        model = registered.fn_metadata.arg_model
        model.model_config["hide_input_in_errors"] = True
        model.model_rebuild(force=True)
    except Exception:
        raise RuntimeError("미디어 후보 도구의 비공개 입력 검증 설정을 완료하지 못했습니다.") from None
