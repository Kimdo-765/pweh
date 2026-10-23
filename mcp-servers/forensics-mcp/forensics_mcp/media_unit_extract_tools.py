"""보관 기록에 결속된 미디어 후보 단위 하나의 파생 추출 입구.

워커가 증거와 보고서 fd를 커밋까지 소유한다. 저장된 후보를 다시 탐색하거나
바이트 범위를 늘리지 않으며, 응답에는 생성 경로와 고정 메타데이터만 남긴다.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import time
from typing import Any

from pydantic import StrictInt

from pweh import evidence as E, schemas
from pweh.errors import ValidationFailed
from pweh.mcpkit import ANN_LOCAL_WRITE, safe_tool

MAX_FILE_BYTES = 64 << 20
MAX_MANIFEST_BYTES = 64 << 10
CHUNK_BYTES = 64 << 10
MAX_SECONDS = 45
_PATH = re.compile(r"forensics/analysis/media-unit-candidates-(EV-[0-9]{4,6})-[0-9]{3,9}\.json\Z")
_ERRORS = {
    "cancelled": "미디어 후보 단위 추출이 취소되었습니다.",
    "time_limit": "미디어 후보 단위 추출의 시간 한도에 닿았습니다.",
    "validation_failed": "미디어 후보 단위 추출 인자 또는 저장 범위가 허용 범위가 아닙니다.",
    "authorization_required": "케이스의 소유 또는 허가 확인이 필요합니다.",
    "not_found": "요청한 케이스 또는 증거를 찾지 못했습니다.",
    "case_error": "케이스를 확인하지 못했습니다.",
    "custody_broken": "증거의 보관 기록을 검증하지 못했습니다.",
    "integrity_failed": "증거의 무결성을 확인하지 못했습니다.",
    "media_unit_input_invalid": "보관 기록에 결속된 후보 보고서와 선택 범위를 확인하지 못했습니다.",
    "media_unit_input_limit": "후보 보고서 또는 선택 바이트의 입력 한도를 넘었습니다.",
    "media_unit_input_changed": "원래 후보 보고서 또는 선택 바이트가 바뀌어 추출을 중단했습니다.",
    "input_too_large": "선택 파일이 64 MiB 상한을 넘었습니다.",
    "output_limit": "미디어 후보 단위 산출물의 크기 한도를 넘었습니다.",
    "cleanup_incomplete": "미커밋 산출물의 신원 또는 정리를 확인하지 못해 남은 항목을 보존했습니다.",
    "job_busy": "이 증거의 추출 작업이 이미 실행 중입니다.",
    "media_unit_failed": "미디어 후보 단위 추출을 완료하지 못했습니다.",
}


class _ServerAPI:
    """공통 서버 함수와 시험 주입을 늦은 참조로 유지한다."""

    def __init__(self, namespace: dict[str, Any]):
        self.namespace = namespace

    def __getattr__(self, name: str) -> Any:
        return self.namespace[name]


def _arguments(evidence_id: Any, analysis_path: Any, candidate_index: Any) -> None:
    match = _PATH.fullmatch(analysis_path) if type(analysis_path) is str else None
    if (type(evidence_id) is not str or match is None or match.group(1) != evidence_id
            or type(candidate_index) is not int or not 0 <= candidate_index <= 127):
        raise ValidationFailed(_ERRORS["validation_failed"])


def _fixed_error(exc: Exception) -> E.EvidenceError:
    """worker 오류의 원문·경로·체인을 공개 job 오류로 보내지 않는다."""
    code, reason = getattr(exc, "code", None), getattr(exc, "reason", None)
    details = getattr(exc, "data", None)
    if reason == "budget_exceeded" and isinstance(details, dict):
        reason = details.get("limit")
    if reason == "cancelled" or code == "cancelled":
        code = "cancelled"
    elif reason in ("time", "timeout", "time_limit") or code == "timeout":
        code = "time_limit"
    elif reason == "max_bytes":
        code = "input_too_large"
    elif code == "busy":
        code = "job_busy"
    elif code in ("media_prefix_input_invalid", "media_prefix_input_limit", "media_prefix_input_changed"):
        code = {"media_prefix_input_invalid": "media_unit_input_invalid",
                "media_prefix_input_limit": "media_unit_input_limit",
                "media_prefix_input_changed": "media_unit_input_changed"}[code]
    if not isinstance(code, str) or code not in _ERRORS:
        code = "media_unit_failed"
    return E.EvidenceError(_ERRORS[code], code=code)


def _uncertain(source: dict) -> bool:
    return (source["deleted"] is True or source["parent_deleted"] is True
            or source["confidence"] != "high"
            or (source["container"] == "filesystem" and source["parent_deleted"] is None))


def _manifest(candidate_input: Any, data: bytes, fresh: dict, candidate_index: int,
              check: Any) -> dict:
    """원래 관찰을 보존하고 작성할 단위 해시만 유한 조각으로 계산한다."""
    from pweh.media_units import FALSE_FIELDS, FILE_PROFILES, RANGE_PROFILES, MIN_UNIT_BYTES, MIN_SELECTED_BYTES

    check()
    format = candidate_input.format
    if type(format) is not str or format not in MIN_UNIT_BYTES:
        raise ValidationFailed(_ERRORS["validation_failed"])
    source = copy.deepcopy(candidate_input.source)
    candidate = copy.deepcopy(candidate_input.candidate)
    coverage = copy.deepcopy(candidate_input.coverage)
    offset, length = candidate["offset"], candidate["length"]
    if (type(data) is not bytes or type(source["selected_size"]) is not int
            or not MIN_SELECTED_BYTES[format] <= len(data) == source["selected_size"] <= MAX_FILE_BYTES
            or type(candidate["index"]) is not int or candidate["index"] != candidate_index
            or type(offset) is not int or type(length) is not int
            or offset < 0 or length < MIN_UNIT_BYTES[format] or offset + length > len(data)):
        raise ValidationFailed(_ERRORS["validation_failed"])
    expected_profile = RANGE_PROFILES[format] if source["method"] == "byte-range" else FILE_PROFILES[format]
    if (candidate["format"] != format or candidate_input.params["format"] != format
            or candidate_input.profile != expected_profile
            or candidate["confidence"] != "possible" or coverage["input_bytes"] != len(data)):
        raise ValidationFailed(_ERRORS["validation_failed"])
    if source["method"] == "byte-range" or fresh.get("method") == "byte-range":
        params = candidate_input.params
        # source.offset은 EV 읽기 위치다. 아래 단위 slice에는 후보의 상대 offset만 쓴다.
        if (source != fresh or source["method"] != "byte-range"
                or any(type(item.get(key)) is not int for item in (source, fresh)
                       for key in ("offset", "evidence_size", "selected_size"))
                or type(params.get("offset")) is not int or type(params.get("length")) is not int
                or params["offset"] != source["offset"] or params["length"] != len(data)
                or not 0 <= source["offset"] <= (1 << 63) - 1
                or not 0 < source["evidence_size"] <= (1 << 63) - 1
                or source["offset"] + len(data) > source["evidence_size"]
                or coverage["input_bytes"] != len(data)):
            raise ValidationFailed(_ERRORS["validation_failed"])
    digest = hashlib.sha256()
    view = memoryview(data)
    for start in range(offset, offset + length, CHUNK_BYTES):
        check()
        digest.update(view[start:min(start + CHUNK_BYTES, offset + length)])
    uncertain = coverage["selection_uncertain"] or _uncertain(source) or _uncertain(fresh)
    incomplete = (source["container_truncated"] is True or fresh["container_truncated"] is True
                  or "container_listing_incomplete" in coverage["reasons"])
    status = ("partial" if candidate_input.upstream_status == "partial" or uncertain or incomplete
              or candidate["framing_status"] == "prefix"
              else "ok")
    origin = candidate_input.origin
    manifest = {
        "schema": "pweh.media-unit-extract/v1", "method": "media_unit", "status": status,
        "format": format, "source_profile": candidate_input.profile,
        "evidence_id": source["evidence_id"], "evidence_sha256": source["evidence_sha256"],
        "source": source,
        "analysis": origin.to_dict(),
        "candidate": candidate, "source_status": candidate_input.upstream_status,
        "source_coverage": coverage, "effective_selection_uncertain": uncertain,
        "effective_container_listing_incomplete": incomplete,
        "files": [{"file": "unit-000.bin", "size": length,
                   "sha256": digest.hexdigest(), "complete": True}], "bytes_total": length,
        **{key: False for key in FALSE_FIELDS},
    }
    schemas.validate("media-unit-extract", manifest)
    encoded = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode("utf-8")) + 1 > MAX_MANIFEST_BYTES:
        raise E.EvidenceError(_ERRORS["output_limit"], code="output_limit")
    check()
    return manifest


def _record_integrity(S: _ServerAPI, case: Any, evidence_id: str, exc: E.IntegrityProblem) -> None:
    if not exc.record:
        return
    entry = S.custody(case).append(
        "integrity-failed", evidence_id=evidence_id, actor="server",
        data={"reason": "media-unit-integrity-check", "problems": ["증거 무결성 검증 실패"],
              "found_by": "media-unit-extract"})
    try:
        _audit(S, case, entry)
    except Exception:
        pass  # 이미 기록한 무결성 사건은 보조 감사 실패 뒤에도 유지한다.


def _audit(S: _ServerAPI, case: Any, entry: dict) -> None:
    try:
        S.rt().audit({"event": "forensics_" + entry["event"].replace("-", "_"),
                      "evidence_id": entry.get("evidence_id"), "custody_seq": entry.get("seq"),
                      "custody_hash": entry.get("hash")}, case.id)
    except Exception:
        raise E.EvidenceError("보조 감사 기록을 완료하지 못했습니다.") from None


async def _extract_run(S: _ServerAPI, *, case_id: str, evidence_id: str,
                       analysis_path: str, candidate_index: int) -> dict:
    try:
        _arguments(evidence_id, analysis_path, candidate_index)
        case = await S._case(case_id)

        def work(jctx: Any) -> dict:
            deadline = time.monotonic() + MAX_SECONDS

            def check() -> None:
                if jctx.cancelled:
                    raise E.EvidenceError(_ERRORS["cancelled"], code="cancelled")
                if time.monotonic() >= deadline:
                    raise E.EvidenceError(_ERRORS["time_limit"], code="time_limit")

            def committed(entry: dict) -> None:
                jctx.mark_committed()
                _audit(S, case, entry)

            try:
                from pweh.media_unit_input import open_media_unit_candidate
                from pweh.media_units import MIN_SELECTED_BYTES
                from .media_candidate_selection import check_candidate_range, reselect_candidate_source
                from .media_unit_output import store_media_unit

                check()
                jctx.progress(0, 4, "후보 보고서 확인")
                entries = S.custody(case).entries()
                with E.open_checked(case, evidence_id, entries, reference_roots=S._reference_roots()) as opened:
                    with open_media_unit_candidate(
                        case, opened, analysis_path=analysis_path, candidate_index=candidate_index,
                        entries=entries, deadline=deadline, cancel=lambda: jctx.cancelled,
                    ) as candidate_input:
                        check()
                        jctx.progress(1, 4, "같은 선택 바이트 확인")
                        data, fresh = reselect_candidate_source(
                            opened, candidate_input, deadline=deadline, cancel=lambda: jctx.cancelled,
                            min_selected_bytes=MIN_SELECTED_BYTES[candidate_input.format])
                        manifest = _manifest(candidate_input, data, fresh, candidate_index, check)
                        candidate_input.check()
                        jctx.progress(2, 4, "저장된 단위 작성")

                        def check_entries(current_entries: list[dict]) -> None:
                            check()
                            candidate_input.check()
                            candidate_input.check_entries(current_entries)
                            if fresh["method"] == "byte-range":
                                check_candidate_range(opened, fresh, deadline=deadline,
                                                      cancel=lambda: jctx.cancelled)

                        return store_media_unit(
                            case, opened, data, manifest=manifest, custody_log=S.custody(case),
                            reference_roots=lambda: S._reference_roots(), deadline=deadline,
                            check=check, check_entries=check_entries, on_commit=committed)
            except E.IntegrityProblem as exc:
                try:
                    _record_integrity(S, case, evidence_id, exc)
                except Exception:
                    pass  # 공개 오류에는 최초 검증 실패의 고정 코드만 남긴다.
                raise _fixed_error(exc) from None
            except Exception as exc:
                raise _fixed_error(exc) from None

        return await S._run_job("forensics-media-unit", case.id, f"미디어 후보 단위 추출 {evidence_id}", work,
                                exclusive_key=f"extract:{case.id}:{evidence_id}")
    except Exception as exc:
        raise _fixed_error(exc) from None


def register_media_unit_extract_tools(server: Any, namespace: dict[str, Any]) -> None:
    """기존 forensics 서버에 후보 하나의 제한된 파생 추출 job을 등록한다."""
    S = _ServerAPI(namespace)

    @server.tool(description=(
        "보관 기록에 결속된 media-unit-candidates 보고서의 candidate_index 하나를 파생 추출한다(job). "
        "analysis_path는 같은 케이스·EV의 생성 보고서이며 index는 저장 후보0~127이다. "
        "format과 bytes 범위는 저장된 보고서만 사용하며 새 selector/offset/길이를 받지 않는다. "
        "원래 ref/partition/복구 방법 또는 EV 명시 구간으로 같은 완전 bytes를 다시 읽어 SHA·크기·신원을 대조한다. "
        "선택 최대64MiB·전체45초·manifest64KiB, 출력은 forensics/recovered/media-unit-NNN/unit-000.bin 하나다. "
        "JPEG/AVC의 닫힌 단위, MPEG-2 PS의 검증 prefix, XM 선언 길이를 그대로 복사한다. "
        "원래 source/status/coverage와 과거·새 선택 불확실성을 보존한다. "
        "complete는 지정 bytes 작성 완료이며 형식 전체 적합성·재생·원본 파일 경계·완전 녹화가 확인된 것은 아니다. "
        "후보 재탐색·전체 카드 자동검색·조각 재조립·영상/음성 해독은 하지 않는다. "
        "commit 전 실패/취소는 부분 출력을 게시하지 않고 commit 뒤 취소는 기록한 산출물을 보존한다. "
        "반환은 생성 경로·해시·크기뿐이며 에이전트는 추출물을 직접 열지 않는다."
    ), annotations=ANN_LOCAL_WRITE)
    @safe_tool
    async def forensics_extract_media_unit(
        case_id: str, evidence_id: str, analysis_path: str, candidate_index: StrictInt,
    ) -> dict:
        return await _extract_run(S, case_id=case_id, evidence_id=evidence_id,
                                  analysis_path=analysis_path, candidate_index=candidate_index)

    namespace["forensics_extract_media_unit"] = forensics_extract_media_unit
    try:
        registered = server._tool_manager.get_tool("forensics_extract_media_unit")
        if registered is None:
            raise RuntimeError
        model = registered.fn_metadata.arg_model
        model.model_config["hide_input_in_errors"] = True
        model.model_rebuild(force=True)
    except Exception:
        raise RuntimeError("미디어 단위 도구의 비공개 입력 검증 설정을 완료하지 못했습니다.") from None
