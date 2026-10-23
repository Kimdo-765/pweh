"""선택한 증거 파일의 ISO BMFF 상자 구조만 기록하는 MCP 입구.

워커가 증거 fd를 커밋까지 소유한다. 선택 이름·본문·자유 형식 오류를 반환하지
않으며, 선택 바이트의 구조 검사와 전체 컨테이너 목록 범위를 구분한다.
"""

from __future__ import annotations

import dataclasses
import hashlib
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

MAX_FILE_BYTES = 64 << 20
MAX_REPORT_BYTES = 1 << 20
_FS_REF = r"(?:root|c[0-9]{1,10}(?:\+[0-9]{1,10})?|n[0-9]{1,10}\+[0-9]{1,10})/[0-9]{1,9}"
_REF = re.compile(r"(?:arc:[0-9]{1,6}|" + _FS_REF + r")\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_METHODS = frozenset({"auto", "chain", "nofatchain", "contiguous", "skip-allocated",
                      "skip-claimed", "fat-chain", "stale-chain"})
_SOURCE_METHODS = (_METHODS - {"auto"}) | {"whole-file", "archive-member", "empty"}
_CONTAINER_REASONS = frozenset({
    "time", "unsupported_archive_compression", "incomplete_archive", "max_metadata",
    "max_entries", "invalid_archive", "unsupported_archive", "trailing_data_unexamined",
    "trailing_data", "unsupported_sparse", "steps", "max_depth", "max_dir_slots",
    "max_total_slots", "max_path_chars", "beyond_image", "dir_chain_broken", "dir_unreadable",
    "dir_unvalidated", "unknown_container_limit",
})
_ERRORS = {
    "cancelled": "미디어 구조 검사가 취소되었습니다.",
    "time_limit": "선택 파일 읽기의 시간 한도에 닿았습니다.",
    "validation_failed": "선택 파일 또는 구조 검사 인자가 허용 범위가 아닙니다.",
    "authorization_required": "케이스의 소유 또는 허가 확인이 필요합니다.",
    "not_found": "요청한 케이스 또는 증거를 찾지 못했습니다.",
    "case_error": "케이스를 확인하지 못했습니다.",
    "custody_broken": "증거의 보관 기록을 검증하지 못했습니다.",
    "integrity_failed": "증거 또는 분석 출력의 무결성을 확인하지 못했습니다.",
    "evidence_error": "증거 확인 또는 분석 저장을 완료하지 못했습니다.",
    "input_too_large": "선택 파일이 64 MiB 상한을 넘었습니다.",
    "invalid_selection": "선택 파일의 완전한 바이트를 확인하지 못했습니다.",
    "selection_failed": "검증된 선택 파일 하나를 찾지 못했습니다.",
    "media_inventory_failed": "미디어 구조 검사를 완료하지 못했습니다.",
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


def _source(opened: Any, evidence_id: str, member: dict, data: bytes) -> dict:
    """선택 metadata를 닫힌 출처로 투영하며 누락된 관찰을 false로 바꾸지 않는다."""
    invalid = _ERRORS["validation_failed"]
    if not isinstance(data, bytes) or len(data) > MAX_FILE_BYTES:
        raise ValidationFailed(invalid)
    if not isinstance(member, dict) or member.get("complete") is not True:
        raise ValidationFailed(invalid)
    sha = hashlib.sha256(data).hexdigest()
    if member.get("sha256") != sha or type(member.get("size")) is not int or member["size"] != len(data):
        raise ValidationFailed(invalid)
    ev_sha = opened.intake["hashes"]["sha256"]
    if not isinstance(ev_sha, str) or _HASH.fullmatch(ev_sha) is None:
        raise ValidationFailed(invalid)
    if (member.get("container") not in {"file", "tar", "zip", "filesystem"}
            or type(member.get("member_selected")) is not bool
            or member.get("method") not in _SOURCE_METHODS
            or member.get("confidence") not in {"high", "medium", "low"}):
        raise ValidationFailed(invalid)
    partition, ref = member.get("partition"), member.get("ref")
    if partition is not None and (type(partition) is not int or not 1 <= partition <= 4096):
        raise ValidationFailed(invalid)
    if ref is not None and (not isinstance(ref, str) or _REF.fullmatch(ref) is None):
        raise ValidationFailed(invalid)
    out = {"kind": "evidence", "evidence_id": evidence_id, "evidence_sha256": ev_sha,
           "container": member["container"], "member_selected": member["member_selected"],
           "selected_sha256": sha, "selected_size": len(data), "complete": True,
           "method": member["method"], "confidence": member["confidence"],
           "partition": partition, "ref": ref, "deleted": None, "parent_deleted": None,
           "container_truncated": None, "container_truncated_reasons": []}
    if not out["member_selected"]:
        if out["container"] != "file" or out["method"] != "whole-file" or ref is not None or partition is not None:
            raise ValidationFailed(invalid)
        return out
    if not ref:
        raise ValidationFailed(invalid)
    if out["container"] in {"tar", "zip"}:
        if (not ref.startswith("arc:") or out["method"] != "archive-member"
                or partition is not None or member.get("deleted") is not False):
            raise ValidationFailed(invalid)
        out["deleted"] = False
        if type(member.get("container_truncated")) is not bool:
            raise ValidationFailed(invalid)
    elif (out["container"] != "filesystem" or ref.startswith("arc:") or partition is None
          or out["method"] not in (_METHODS - {"auto"}) | {"empty"}):
        raise ValidationFailed(invalid)
    else:
        if type(member.get("deleted")) is not bool:
            raise ValidationFailed(invalid)
        parent = member.get("parent_deleted")
        if parent is not None and type(parent) is not bool:
            raise ValidationFailed(invalid)
        out.update(deleted=member["deleted"], parent_deleted=parent)
        if out["method"] == "empty" and len(data) != 0:
            raise ValidationFailed(invalid)
    truncated = member.get("container_truncated")
    if truncated is not None and type(truncated) is not bool:
        raise ValidationFailed(invalid)
    out["container_truncated"] = truncated
    reasons = member.get("container_truncated_reasons", [])
    if not isinstance(reasons, list) or len(reasons) > 64:
        raise ValidationFailed(invalid)
    if "cancelled" in reasons:
        raise PwehError(_ERRORS["cancelled"], code="cancelled")
    out["container_truncated_reasons"] = sorted({
        r if isinstance(r, str) and r in _CONTAINER_REASONS else "unknown_container_limit"
        for r in reasons})
    return out


def _residual_source(opened: Any, evidence_id: str, member: dict, data: bytes) -> dict:
    """검증된 exFAT residual member만 기존 source16에 세 필드로 결속한다."""
    keys = {"container", "member_selected", "partition", "ref", "path", "requested_path",
            "deleted", "parent_deleted", "method", "confidence", "complete", "note", "size", "sha256",
            "region", "data_length", "valid_data_length"}
    if type(member) is not dict or set(member) != keys or type(data) is not bytes:
        raise ValidationFailed(_ERRORS["validation_failed"])
    source = _source(opened, evidence_id, member, data)
    dl, vdl = member["data_length"], member["valid_data_length"]
    if (type(member["region"]) is not str or member["region"] != "residual"
            or source["container"] != "filesystem" or source["member_selected"] is not True
            or type(source["partition"]) is not int or not 1 <= source["partition"] <= 4096
            or type(source["ref"]) is not str or source["ref"].startswith("arc:")
            or type(source["method"]) is not str or source["method"] not in {
                "chain", "nofatchain", "contiguous", "skip-allocated", "stale-chain"}
            or type(dl) is not int or type(vdl) is not int
            or not 0 <= vdl < dl <= (1 << 63) - 1
            or not 1 <= dl - vdl == source["selected_size"] <= MAX_FILE_BYTES):
        raise ValidationFailed(_ERRORS["validation_failed"])
    return {**source, "region": "residual", "data_length": dl, "valid_data_length": vdl}


def _selection_coverage(report: dict, source: dict) -> None:
    """선택 바이트 구조의 완료와 삭제·복구·전체 목록 불확실성을 구분한다."""
    uncertain = (source["deleted"] is True or source["parent_deleted"] is True
                 or source["confidence"] != "high"
                 or (source["container"] == "filesystem" and source["parent_deleted"] is None))
    report["coverage"]["selection_uncertain"] = uncertain
    reasons = report["coverage"]["reasons"]
    if uncertain and "selection_uncertain" not in reasons:
        reasons.append("selection_uncertain")
    if source["container_truncated"] is True and "container_listing_incomplete" not in reasons:
        reasons.append("container_listing_incomplete")
    if (uncertain or source["container_truncated"] is True) and report["status"] == "ok":
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
        data={"reason": "media-inventory-integrity-check", "problems": ["증거 무결성 검증 실패"],
              "found_by": "media-inventory"})
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
        code = "media_inventory_failed"
    return PwehError(_ERRORS[code], code=code)


async def _inventory_run(S: _ServerAPI, *, case_id: str, evidence_id: str,
                         partition: int | None, ref: str | None, path: str | None,
                         method: str, max_seconds: float) -> dict:
    cancelled = threading.Event()
    try:
        deadline = _arguments(evidence_id, partition, ref, path, method, max_seconds)
        case = await S._case(case_id)

        def work_body() -> dict:
            from pweh.media import (MediaLimits, inventory_isobmff,
                                    validate_media_protection_accounting)

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
                    limits = dataclasses.replace(MediaLimits(), max_output_bytes=MAX_REPORT_BYTES - (16 << 10))
                    report = inventory_isobmff(data, limits=limits, deadline=deadline, cancel=cancelled.is_set)
                    report["source"] = source
                    report["params"] = {"partition": partition, "method": method, "max_seconds": max_seconds}
                    _selection_coverage(report, source)
                    schemas.validate("media-inventory", report)
                    validate_media_protection_accounting(report)
                    raw = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
                    if len(raw.encode("utf-8")) + 1 > MAX_REPORT_BYTES:
                        raise ValidationFailed(_ERRORS["validation_failed"])
                    _check(cancelled, deadline, time_limit=False)
                    return E.store_analysis(
                        case, opened, report, event="media-inventory", custody_log=S.custody(case),
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


def register_media_tools(server: Any, namespace: dict[str, Any]) -> None:
    """기존 서버에 선택 파일의 제한된 상자 목록 도구를 등록한다."""
    S = _ServerAPI(namespace)

    @server.tool(
        description=(
            "증거에서 선택한 파일 1개의 MP4/QuickTime 계열 ISO BMFF 상자 구조를 오프라인 목록화한다. "
            "소유/허가·보관 기록·무결성 확인 후 FAT/exFAT·TAR/ZIP ref 또는 path 하나를 선택한다. "
            "둘 다 없으면 EV 자체를 읽으며 자동 검색·카빙은 하지 않는다. 완전한 파일만 최대 64 MiB, "
            "max_seconds는 0 초 초과·최대 45초(선택·읽기·구조 검사 공통)다. "
            "크기·부모 경계·알려진 상자 종류와 header/skipped/unexamined 범위를 기록하고 "
            "브랜드 인식과 구조 검사 완료를 구분한다. 허용 계층의 mvhd/mdhd에서 시간 단위·길이 선언과 "
            "생성/수정 시각의 zero/nonzero/unread 상태, moov/moof 직계 pssh의 제한 구조를 관찰한다. "
            "정확한 stsd/encv·enca/sinf/schm·schi/tenc 경로에서는 고정 prefix와 제한 보호 선언만 관찰한다. "
            "scheme은 cenc/cbcs/other/unread, 기본 보호 상태는 zero/one/other/unread로 분류하며 "
            "실제 sample·전체 tenc·constant-IV·sample group·auxiliary data는 검사하지 않는다. "
            "선언 길이는 실제 재생 길이가 아니며 절대 시각·SystemID/KID/IV·보호 data와 개별 해시는 반환하지 않는다. "
            "declarations와 protection에 순회/필드 완료도를 따로 기록하며 보호 값·부재를 암호화/평문 판정으로 쓰지 않는다. "
            "새 protection-declarations-v1은 깊이 10까지 관찰하고 기존 box-v1/declarations-v1 저장물과 구분한다. "
            "삭제 파일·삭제된 부모·복구 불확실성과 "
            "전체 컨테이너 목록 미검사를 따로 표시한다. 빈 파일·지원 밖 형식도 unsupported로 기록할 수 있다. "
            "프레임·음성·썸네일을 해독하지 않으며 재생·녹화 시각·암호화·형식 적합성은 판정하지 않는다. "
            "이름·경로·본문·자유 형식 상자/브랜드 값은 반환하거나 저장하지 않는다. "
            "고정 분류 JSON을 forensics/analysis/에 0444로 저장하고 media-inventory 보관 기록에 해시를 결속한다."
        ), annotations=ANN_LOCAL_WRITE,
    )
    @safe_tool
    async def forensics_media_inventory(
        case_id: str, evidence_id: str, partition: StrictInt | None = None,
        ref: str | None = None, path: str | None = None, method: str = "auto",
        max_seconds: StrictFloat | StrictInt = 45,
    ) -> dict:
        return await _inventory_run(S, case_id=case_id, evidence_id=evidence_id, partition=partition,
                                    ref=ref, path=path, method=method, max_seconds=max_seconds)

    namespace["forensics_media_inventory"] = forensics_media_inventory
    try:
        registered = server._tool_manager.get_tool("forensics_media_inventory")
        if registered is None:
            raise RuntimeError
        model = registered.fn_metadata.arg_model
        model.model_config["hide_input_in_errors"] = True
        model.model_rebuild(force=True)
    except Exception:
        raise RuntimeError("미디어 구조 도구의 비공개 입력 검증 설정을 완료하지 못했습니다.") from None
