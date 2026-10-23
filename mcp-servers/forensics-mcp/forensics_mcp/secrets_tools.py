"""검증한 증거의 선택 텍스트에서 비밀값 후보를 찾는 MCP 입구.

원문과 선택 경로는 결과·오류에 복사하지 않는다. 워커가 EV fd를 끝까지 소유하며,
새 분석 JSON은 입력과 출력의 최종 검증 뒤 보관 기록에 결속한다.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import os
import re
import stat
import threading
import time
from pathlib import PurePosixPath
from typing import Any

from pydantic import StrictFloat, StrictInt

from pweh import evidence as E, schemas
from pweh.errors import PwehError, ValidationFailed
from pweh.mcpkit import ANN_LOCAL_WRITE, run_blocking_cancellable, safe_tool

from . import fsops

MAX_FILE_BYTES = 4 << 20
MAX_REPORT_BYTES = 1 << 20
MAX_RANGE_END = (1 << 63) - 1
RANGE_CHUNK_BYTES = 64 << 10
_RANGE_KEYS = frozenset({"kind", "evidence_id", "evidence_sha256", "evidence_size", "offset",
                         "length", "selected_sha256", "selected_size", "complete"})
_REF = re.compile(r"(?:arc:[0-9]{1,9}|[0-9a-z+]{1,40}/[0-9]{1,9})\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_METHODS = frozenset({"auto", "chain", "nofatchain", "contiguous", "skip-allocated",
                      "skip-claimed", "fat-chain", "stale-chain"})
_SOURCE_METHODS = (_METHODS - {"auto"}) | {"whole-file", "archive-member"}
_MEDIA_SUFFIXES = frozenset({
    ".mp4", ".mov", ".m4v", ".3gp", ".avi", ".mkv", ".webm", ".ts", ".mts", ".m2ts",
    ".mpg", ".mpeg", ".ps", ".h264", ".h265", ".264", ".265", ".hevc", ".dav", ".dhav",
    ".mp3", ".wav", ".aac", ".m4a", ".ogg", ".opus", ".flac", ".amr", ".wma", ".wmv",
})
_CONTAINER_REASONS = frozenset({
    "time", "cancelled", "unsupported_archive_compression", "incomplete_archive", "max_metadata",
    "max_entries", "invalid_archive", "unsupported_archive", "trailing_data_unexamined",
    "trailing_data", "unsupported_sparse", "unknown_container_limit",
})
_ERRORS = {
    "cancelled": "비밀값 검사가 취소되었습니다.",
    "time_limit": "선택 파일 읽기의 시간 한도에 닿았습니다.",
    "validation_failed": "선택 파일 또는 검사 인자가 허용 범위가 아닙니다.",
    "authorization_required": "케이스의 소유 또는 허가 확인이 필요합니다.",
    "not_found": "요청한 케이스 또는 증거를 찾지 못했습니다.",
    "case_error": "케이스를 확인하지 못했습니다.",
    "custody_broken": "증거의 보관 기록을 검증하지 못했습니다.",
    "integrity_failed": "증거 또는 분석 출력의 무결성을 확인하지 못했습니다.",
    "evidence_error": "증거의 선택 또는 분석 저장을 완료하지 못했습니다.",
    "salt_invalid": "케이스 솔트가 올바른 일반 파일이 아닙니다.",
    "salt_corrupt": "케이스 솔트가 손상되어 지문을 만들지 못했습니다.",
    "unsupported_media": "영상·음성 이름의 파일은 비밀값 검사 대상으로 받지 않습니다.",
    "secrets_scan_failed": "비밀값 검사를 완료하지 못했습니다.",
}


class _ServerAPI:
    """서버의 늦은 참조를 유지하여 순환 import와 runtime 고정을 피한다."""

    def __init__(self, namespace: dict[str, Any]):
        self.namespace = namespace

    def __getattr__(self, name: str) -> Any:
        return self.namespace[name]


def _check(cancelled: threading.Event, deadline: float, *, time_limit: bool = True) -> None:
    if cancelled.is_set():
        raise PwehError(_ERRORS["cancelled"], code="cancelled")
    if time_limit and time.monotonic() >= deadline:
        raise PwehError(_ERRORS["time_limit"], code="time_limit")


def _arguments(partition: Any, ref: Any, path: Any, method: Any, xor_key: Any,
               max_hits: Any, max_seconds: Any, *, offset: Any = None, length: Any = None) -> float:
    """입력값을 오류 문자열에 넣지 않고 검증한 뒤 공통 deadline을 만든다."""
    if offset is not None or length is not None:
        _range_arguments(offset, length)
        if partition is not None or ref is not None or path is not None or method != "auto":
            raise ValidationFailed(_ERRORS["validation_failed"])
    if ref is not None and path is not None:
        raise ValidationFailed("ref 와 path 는 함께 지정하지 않습니다.")
    for item in (ref, path):
        if item is not None and (not isinstance(item, str) or not item.strip()
                                 or len(item) > 32768 or "\x00" in item):
            raise ValidationFailed("선택자는 비어 있지 않은 32768자 이하 문자열이어야 합니다.")
    if ref is not None and _REF.fullmatch(ref) is None:
        raise ValidationFailed("ref 는 검증된 파일 목록의 항목 참조여야 합니다.")
    if partition is not None and (type(partition) is not int or not 1 <= partition <= 4096):
        raise ValidationFailed("partition 은 1~4096 정수여야 합니다.")
    if not isinstance(method, str) or method not in _METHODS:
        raise ValidationFailed("지원하지 않는 복구 method 입니다.")
    if ref is None and path is None and (partition is not None or method != "auto"):
        raise ValidationFailed("EV 자체를 검사할 때 partition·method 를 지정하지 않습니다.")
    if xor_key is not None and (type(xor_key) is not int or xor_key != 144):
        raise ValidationFailed("xor_key 는 생략하거나 정수 144만 지정합니다.")
    if type(max_hits) is not int or not 1 <= max_hits <= 200:
        raise ValidationFailed("max_hits 는 1~200 정수여야 합니다.")
    if type(max_seconds) not in (int, float) or not 0 < max_seconds <= 45 or not math.isfinite(max_seconds):
        raise ValidationFailed("max_seconds 는 0 초 초과, 45 초 이하의 유한한 값이어야 합니다.")
    return time.monotonic() + max_seconds


def _range_arguments(offset: Any, length: Any) -> None:
    if (type(offset) is not int or not 0 <= offset <= MAX_RANGE_END
            or type(length) is not int or not 1 <= length <= MAX_FILE_BYTES
            or length > MAX_RANGE_END - offset):
        raise ValidationFailed(_ERRORS["validation_failed"])


def _range_identity(st: os.stat_result) -> tuple[int, ...]:
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_nlink


def _range_state(opened: E.OpenedEvidence, offset: int, length: int) -> int:
    """초기 열린 fd와 접수 크기·구간 산술을 대조한다. 내용·경로를 다시 열지 않는다."""
    _range_arguments(offset, length)
    size = opened.intake["size"]
    if type(size) is not int or not 1 <= size <= MAX_RANGE_END or length > size - offset:
        raise ValidationFailed(_ERRORS["validation_failed"])
    before, now = opened.st, os.fstat(opened.fd)
    if (not stat.S_ISREG(before.st_mode) or not stat.S_ISREG(now.st_mode)
            or before.st_nlink != 1 or now.st_nlink != 1 or before.st_size != size
            or _range_identity(before) != _range_identity(now)):
        raise E.IntegrityProblem("텍스트 구간 검사 중 증거의 파일 신원 또는 상태가 변경되었습니다.",
                                 reason="source-changed")
    return size


def _check_secret_range(opened: E.OpenedEvidence, source: dict, *, deadline: float,
                        cancelled: threading.Event, time_limit: bool = True) -> None:
    """최종 취소·같은 fd seal·출처 상수를 확인하며 구간 밖 문맥은 읽지 않는다."""
    _check(cancelled, deadline, time_limit=time_limit)
    if (type(source) is not dict or set(source) != _RANGE_KEYS
            or source["kind"] != "evidence" or source["complete"] is not True
            or type(source["evidence_id"]) is not str
            or re.fullmatch(r"EV-[0-9]{4,6}", source["evidence_id"]) is None
            or source["evidence_id"] != opened.evidence_id
            or any(type(source[k]) is not str or _HASH.fullmatch(source[k]) is None
                   for k in ("evidence_sha256", "selected_sha256"))
            or source["evidence_sha256"] != opened.intake["hashes"]["sha256"]
            or type(source["evidence_size"]) is not int or type(source["selected_size"]) is not int
            or source["selected_size"] != source["length"]):
        raise ValidationFailed(_ERRORS["validation_failed"])
    size = _range_state(opened, source["offset"], source["length"])
    if source["evidence_size"] != size:
        raise ValidationFailed(_ERRORS["validation_failed"])
    _check(cancelled, deadline, time_limit=time_limit)


def _read_secret_range(opened: E.OpenedEvidence, evidence_id: str, offset: int, length: int, *,
                       deadline: float, cancelled: threading.Event) -> tuple[bytes, dict]:
    """선택한 구간 전체만 최대64KiB씩 읽고 SHA를 한 번 계산한다. 짧은 읽기는 실패다."""
    _check(cancelled, deadline)
    size = _range_state(opened, offset, length)
    chunks, digest = [], hashlib.sha256()
    position = 0
    while position < length:
        _check(cancelled, deadline)
        _range_state(opened, offset, length)
        need = min(RANGE_CHUNK_BYTES, length - position)
        chunk = os.pread(opened.fd, need, offset + position)
        _range_state(opened, offset, length)
        _check(cancelled, deadline)
        if type(chunk) is not bytes or len(chunk) != need:
            raise PwehError(_ERRORS["secrets_scan_failed"], code="secrets_scan_failed")
        digest.update(chunk)
        chunks.append(chunk)
        position += len(chunk)
    data = b"".join(chunks)
    source = {"kind": "evidence", "evidence_id": evidence_id,
              "evidence_sha256": opened.intake["hashes"]["sha256"], "evidence_size": size,
              "offset": offset, "length": length, "selected_sha256": digest.hexdigest(),
              "selected_size": len(data), "complete": True}
    _check_secret_range(opened, source, deadline=deadline, cancelled=cancelled)
    return data, source


def _reject_media_name(name: Any) -> None:
    """요청·검증된 이름은 비교만 하고 거부 응답에 되풀이하지 않는다."""
    if isinstance(name, str) and PurePosixPath(name.replace("\\", "/")).suffix.lower() in _MEDIA_SUFFIXES:
        raise PwehError(_ERRORS["unsupported_media"], code="unsupported_media")


def _source(opened: Any, evidence_id: str, member: dict, data: bytes) -> dict:
    """선택 metadata의 경로·파일명·메모를 버리고 검증한 출처 필드만 투영한다."""
    if not isinstance(member, dict) or member.get("complete") is not True:
        raise ValidationFailed("완전한 선택 파일 출처가 필요합니다.")
    sha = hashlib.sha256(data).hexdigest()
    if member.get("sha256") != sha or type(member.get("size")) is not int or member["size"] != len(data):
        raise ValidationFailed("선택 파일의 바이트와 출처 해시·크기가 다릅니다.")
    ev_sha = opened.intake["hashes"]["sha256"]
    if not isinstance(ev_sha, str) or _HASH.fullmatch(ev_sha) is None:
        raise ValidationFailed("접수 증거의 해시 형식이 올바르지 않습니다.")
    if (member.get("container") not in {"file", "tar", "zip", "filesystem"}
            or type(member.get("member_selected")) is not bool
            or member.get("method") not in _SOURCE_METHODS
            or member.get("confidence") not in {"high", "medium", "low"}):
        raise ValidationFailed("선택 파일 출처의 형식이 올바르지 않습니다.")
    out = {"kind": "evidence", "evidence_id": evidence_id, "evidence_sha256": ev_sha,
           "container": member["container"], "member_selected": member["member_selected"],
           "selected_sha256": sha, "selected_size": len(data), "complete": True,
           "method": member["method"], "confidence": member["confidence"]}
    if "partition" in member:
        p = member["partition"]
        if p is not None and (type(p) is not int or not 1 <= p <= 4096):
            raise ValidationFailed("선택 파티션 출처가 올바르지 않습니다.")
        out["partition"] = p
    if "ref" in member:
        ref = member["ref"]
        if ref is not None and (not isinstance(ref, str) or _REF.fullmatch(ref) is None):
            raise ValidationFailed("선택 파일 참조가 올바르지 않습니다.")
        out["ref"] = ref
    if out["member_selected"]:
        if not out.get("ref"):
            raise ValidationFailed("선택 파일의 검증된 참조가 없습니다.")
        if out["container"] in {"tar", "zip"}:
            if not out["ref"].startswith("arc:") or out["method"] != "archive-member" or out.get("partition") is not None:
                raise ValidationFailed("선택 아카이브 출처가 일치하지 않습니다.")
        elif (out["container"] != "filesystem" or out["ref"].startswith("arc:")
              or out.get("partition") is None or out["method"] not in _METHODS - {"auto"}):
            raise ValidationFailed("선택 파일 시스템 출처가 일치하지 않습니다.")
    elif out["container"] != "file" or out["method"] != "whole-file" or out.get("ref") is not None or out.get("partition") is not None:
        raise ValidationFailed("EV 자체 파일 출처가 일치하지 않습니다.")
    for key in ("deleted", "container_truncated"):
        if key in member:
            if type(member[key]) is not bool:
                raise ValidationFailed("선택 파일 상태가 올바르지 않습니다.")
            out[key] = member[key]
    if "container_truncated_reasons" in member:
        reasons = member["container_truncated_reasons"]
        if not isinstance(reasons, list) or len(reasons) > 64:
            raise ValidationFailed("컨테이너 검사 상태가 올바르지 않습니다.")
        out["container_truncated_reasons"] = sorted({
            r if isinstance(r, str) and r in _CONTAINER_REASONS else "unknown_container_limit"
            for r in reasons})
    return out


def _selection_coverage(report: dict, source: dict) -> None:
    """선택 바이트의 패턴 검사 완료와 복구·컨테이너 검사의 불확실성을 구분한다.

    analysis_complete/hits_are_lower_bound는 선택 바이트에서 지원 패턴을 얼마나
    검사했는지만 뜻한다. 출처의 불확실성은 이 값을 바꾸지 않고 overall partial로 남긴다.
    """
    uncertain = source.get("deleted", False) or source["confidence"] != "high"
    report["coverage"]["selection_uncertain"] = bool(uncertain)
    reasons = report["coverage"]["reasons"]
    if uncertain and "selection_uncertain" not in reasons:
        reasons.append("selection_uncertain")
    if source.get("container_truncated") and "container_listing_incomplete" not in reasons:
        reasons.append("container_listing_incomplete")
    if (uncertain or source.get("container_truncated")) and report["status"] == "ok":
        report["status"] = "partial"


async def _scan_run(S: Any, *, case_id: str, evidence_id: str, partition: int | None,
                    ref: str | None, path: str | None, method: str, xor_key: int | None,
                    max_hits: int, max_seconds: float, offset: int | None = None,
                    length: int | None = None) -> dict:
    from pweh.secretscan import (RANGE_PROFILE, ScanLimits, SelectionBoundary, scan_secrets,
                                validate_secrets_range_accounting)

    deadline = _arguments(partition, ref, path, method, xor_key, max_hits, max_seconds,
                          offset=offset, length=length)
    cancelled = threading.Event()
    ranged = offset is not None

    def work() -> dict:
        try:
            _check(cancelled, deadline)
            case = S.rt().case(case_id, hardware=True)
            with S._open_evidence_sync(case, evidence_id) as opened:
                try:
                    _reject_media_name(path)
                    if ref is None and path is None:
                        _reject_media_name(opened.intake.get("source_name"))
                    if ranged:
                        data, source = _read_secret_range(opened, evidence_id, offset, length,
                                                          deadline=deadline, cancelled=cancelled)
                        expected_source = dict(source)
                        boundary = SelectionBoundary(offset == 0, offset + length == source["evidence_size"])
                    else:
                        data, member = fsops.read_selected_file(
                            opened.fd, partition=partition, ref=ref, path=path, method=method,
                            max_bytes=MAX_FILE_BYTES, deadline=deadline, cancel=cancelled.is_set)
                        _reject_media_name(member.get("path"))
                        _check(cancelled, deadline)
                        source = _source(opened, evidence_id, member, data)
                    _check(cancelled, deadline)
                    limits = dataclasses.replace(ScanLimits(), max_hits=max_hits,
                                                 max_output_bytes=MAX_REPORT_BYTES - (16 << 10))
                    report = scan_secrets(data, digest=lambda value: S.rt().secret_digest(case_id, value),
                                          xor_key=xor_key, limits=limits, deadline=deadline,
                                          cancel=cancelled.is_set,
                                          **({"boundary": boundary} if ranged else {}))
                    report["source"] = dict(source)
                    report["params"]["max_seconds"] = max_seconds
                    if not ranged:
                        _selection_coverage(report, source)
                    schemas.validate("secrets-scan", report)
                    if ranged:
                        validate_secrets_range_accounting(report)
                        expected_params = {"xor_key": xor_key, "max_hits": max_hits, "decoder": "utf-8",
                                           "max_seconds": max_seconds, "prefix_complete": boundary.prefix_complete,
                                           "suffix_complete": boundary.suffix_complete}
                        if (report["profile"] != RANGE_PROFILE or report["source"] != expected_source
                                or any(type(report["source"][k]) is not type(v) for k, v in expected_source.items())
                                or report["params"] != expected_params
                                or any(type(report["params"][k]) is not type(v) for k, v in expected_params.items())
                                or len(data) != expected_source["selected_size"]):
                            raise ValidationFailed(_ERRORS["validation_failed"])
                    raw = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
                    if len(raw.encode("utf-8")) + int(ranged) > MAX_REPORT_BYTES:
                        raise ValidationFailed("분석 보고서 크기 상한을 넘었습니다.")
                    _check(cancelled, deadline, time_limit=False)
                    def final_check() -> None:
                        if ranged:
                            _check_secret_range(opened, expected_source, deadline=deadline,
                                                cancelled=cancelled, time_limit=False)
                            if report["source"] != expected_source or any(
                                    type(report["source"][k]) is not type(v) for k, v in expected_source.items()):
                                raise ValidationFailed(_ERRORS["validation_failed"])
                            if (report["profile"] != RANGE_PROFILE or report["params"] != expected_params
                                    or any(type(report["params"][k]) is not type(v)
                                           for k, v in expected_params.items())):
                                raise ValidationFailed(_ERRORS["validation_failed"])
                        else:
                            _check(cancelled, deadline, time_limit=False)
                    return E.store_analysis(
                        case, opened, report, event="secrets-scan", custody_log=S.custody(case),
                        reference_roots=lambda: S._reference_roots(),
                        check=final_check,
                        on_commit=lambda entry: S._audit_custody(case, entry))
                except E.IntegrityProblem as exc:
                    S._record_integrity_failure(case, evidence_id, exc, found_by="secrets-scan")
                    raise
        except Exception as exc:
            # safe_tool은 일반 예외를 로그에 쓰므로 내용 처리 예외의 문자열을 넘기지 않는다.
            code = getattr(exc, "code", None)
            if getattr(exc, "reason", None) == "cancelled":
                code = "cancelled"
            elif getattr(exc, "reason", None) == "time":
                code = "time_limit"
            if not isinstance(code, str) or code not in _ERRORS:
                code = "secrets_scan_failed"
            raise PwehError(_ERRORS[code], code=code) from None

    return await run_blocking_cancellable(work, on_cancel=cancelled.set)


def register_secrets_tools(server: Any, namespace: dict[str, Any]) -> None:
    """기존 forensics 서버에 선택 파일 검사 도구 하나를 등록한다."""
    S = _ServerAPI(namespace)

    @server.tool(
        description=(
            "증거의 선택 텍스트 파일 1개에서 자격증명·토큰 후보를 오프라인 검사한다. "
            "소유/허가·보관 기록·무결성 검사 후 FAT/exFAT·TAR/ZIP ref 또는 path 하나를 선택하며, "
            "둘 다 없으면 EV 자체를 읽는다. 완전한 파일만, 해제 크기 최대 4 MiB·UTF-8/BOM만 받는다. "
            "offset/length를 함께 지정하면 EV 안의 1바이트~4MiB 명시 구간만 선택한다. "
            "구간은 exact 정수이며 partition/ref/path와 혼용하지 않고 method=auto만 받는다. "
            "구간 밖의 텍스트 문맥을 읽지 않으며 앞뒤 불완전 경계 줄은 미검사로 남긴다. "
            "기존 EV 무결성 지문 검사는 유지하고, source의 접수 SHA와 선택 구간 SHA를 구분한다. "
            "xor_key는 생략하거나 144(0x90)를 명시하며 자동 XOR 탐색은 없다. "
            "max_hits는 1~200, max_seconds는 0 초 초과·최대 45초(선택·읽기·검사 공통). "
            "16 KiB를 넘는 줄과 한도로 못 본 범위는 partial로 표시한다. "
            "결과는 위치·길이·규칙·고정 마스킹·케이스 솔트 지문뿐이며 원문·키·URL·경로는 반환/저장하지 않는다. "
            "영상·음성 이름은 거부하고 미디어/바이너리 내용은 unsupported다. 후보 없음은 비밀 없음의 증명이 아니다. "
            "마스킹 JSON을 forensics/analysis/에 0444로 저장하고 secrets-scan 보관 기록에 해시를 결속한다."
        ),
        annotations=ANN_LOCAL_WRITE,
    )
    @safe_tool
    async def forensics_scan_secrets(
        case_id: str, evidence_id: str, partition: StrictInt | None = None,
        ref: str | None = None, path: str | None = None, method: str = "auto",
        xor_key: StrictInt | None = None, max_hits: StrictInt = 200,
        max_seconds: StrictFloat | StrictInt = 45,
        offset: StrictInt | None = None, length: StrictInt | None = None,
    ) -> dict:
        return await _scan_run(S, case_id=case_id, evidence_id=evidence_id, partition=partition,
                               ref=ref, path=path, method=method, xor_key=xor_key,
                               max_hits=max_hits, max_seconds=max_seconds, offset=offset, length=length)

    namespace["forensics_scan_secrets"] = forensics_scan_secrets
    try:
        registered = server._tool_manager.get_tool("forensics_scan_secrets")
        if registered is None:
            raise RuntimeError
        model = registered.fn_metadata.arg_model
        model.model_config["hide_input_in_errors"] = True
        model.model_rebuild(force=True)
    except Exception:
        raise RuntimeError("비밀값 검사 도구의 비공개 입력 검증 설정을 완료하지 못했습니다.") from None
