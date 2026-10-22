"""기존 펌웨어·카드 목록 보고서의 이름 후보를 대조하는 MCP 입구.

원시 카드 경로·펌웨어 발췌는 결과와 오류에 복사하지 않는다. 워커가 입력 fd를
커밋까지 소유하고, 목록의 보관 기록과 입력 이름 신원을 마지막에 재검증한다.
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

MAX_REPORT_BYTES = 2 << 20
_FIRMWARE = re.compile(r"analysis/sd-surface-[0-9]{3,9}\.json\Z")
_LISTING = re.compile(r"forensics/analysis/fs-list-(EV-[0-9]{4,6})-[0-9]{3,9}\.json\Z")
_ERRORS = {
    "cancelled": "SD 이름 대조가 취소되었습니다.",
    "time_limit": "입력 보고서 검증의 시간 한도에 닿았습니다.",
    "validation_failed": "대조 인자 또는 입력 보고서가 허용 범위가 아닙니다.",
    "authorization_required": "케이스의 소유 또는 허가 확인이 필요합니다.",
    "not_found": "요청한 케이스·증거·생성 보고서를 찾지 못했습니다.",
    "case_error": "케이스를 확인하지 못했습니다.",
    "custody_broken": "증거의 보관 기록을 검증하지 못했습니다.",
    "integrity_failed": "증거 또는 분석 입력·출력의 무결성을 확인하지 못했습니다.",
    "evidence_error": "증거 확인 또는 분석 저장을 완료하지 못했습니다.",
    "sdioc_input_invalid": "생성 보고서의 형식 또는 출처 결속을 확인하지 못했습니다.",
    "sdioc_input_limit": "입력 보고서가 크기 또는 JSON 구조 상한을 넘었습니다.",
    "sdioc_input_changed": "검사 중 입력 보고서의 신원이 바뀌었습니다.",
    "sd_ioc_scan_failed": "SD 이름 대조를 완료하지 못했습니다.",
}


class _ServerAPI:
    """서버의 늦은 참조를 유지하여 runtime과 테스트 주입을 고정하지 않는다."""

    def __init__(self, namespace: dict[str, Any]):
        self.namespace = namespace

    def __getattr__(self, name: str) -> Any:
        return self.namespace[name]


def _check(cancelled: threading.Event, deadline: float, *, time_limit: bool = True) -> None:
    if cancelled.is_set():
        raise PwehError(_ERRORS["cancelled"], code="cancelled")
    if time_limit and time.monotonic() >= deadline:
        raise PwehError(_ERRORS["time_limit"], code="time_limit")


def _arguments(evidence_id: Any, firmware_result_path: Any, fs_list_path: Any,
               partition: Any, max_matches: Any, max_seconds: Any) -> float:
    """생성 경로 문법과 수치형을 검증하며 요청 문자열은 오류에 넣지 않는다."""
    if not isinstance(evidence_id, str) or re.fullmatch(r"EV-[0-9]{4,6}", evidence_id) is None:
        raise ValidationFailed(_ERRORS["validation_failed"])
    if (not isinstance(firmware_result_path, str) or len(firmware_result_path) > 80
            or _FIRMWARE.fullmatch(firmware_result_path) is None):
        raise ValidationFailed(_ERRORS["validation_failed"])
    match = _LISTING.fullmatch(fs_list_path) if isinstance(fs_list_path, str) and len(fs_list_path) <= 100 else None
    if match is None or match.group(1) != evidence_id:
        raise ValidationFailed(_ERRORS["validation_failed"])
    if partition is not None and (type(partition) is not int or not 1 <= partition <= 4096):
        raise ValidationFailed(_ERRORS["validation_failed"])
    if type(max_matches) is not int or not 1 <= max_matches <= 200:
        raise ValidationFailed(_ERRORS["validation_failed"])
    if type(max_seconds) not in (int, float) or not 0 < max_seconds <= 45 or not math.isfinite(max_seconds):
        raise ValidationFailed(_ERRORS["validation_failed"])
    return time.monotonic() + max_seconds


def _audit_commit(S: _ServerAPI, case: Any, entry: dict) -> None:
    """보조 감사 오류에도 원시 예외나 traceback을 로그에 쓰지 않는다."""
    try:
        S.rt().audit({"event": "forensics_" + entry["event"].replace("-", "_"),
                      "evidence_id": entry.get("evidence_id"), "custody_seq": entry.get("seq"),
                      "custody_hash": entry.get("hash")}, case.id)
    except Exception:
        raise PwehError("보조 감사 기록을 완료하지 못했습니다.", code="evidence_error") from None


def _record_integrity(S: _ServerAPI, case: Any, evidence_id: str, exc: E.IntegrityProblem) -> None:
    """무결성 실패 표시는 보존하되 입력 유래 문제 문자열은 복사하지 않는다."""
    if not exc.record:
        return
    entry = S.custody(case).append(
        "integrity-failed", evidence_id=evidence_id, actor="server",
        data={"reason": "sd-ioc-integrity-check", "problems": ["증거 무결성 검증 실패"],
              "found_by": "sd-ioc-scan"})
    try:
        _audit_commit(S, case, entry)
    except PwehError:
        # 보호된 사건은 커밋됐다. 감사 오류로 입력 문자열을 다시 노출하지 않는다.
        pass


def _fixed_error(exc: Exception) -> PwehError:
    """취소된 awaiter 뒤에 끝나는 워커도 원시 예외를 보관하지 않는다."""
    code = getattr(exc, "code", None)
    if getattr(exc, "reason", None) == "cancelled":
        code = "cancelled"
    elif getattr(exc, "reason", None) == "time" or code == "timeout":
        code = "time_limit"
    if not isinstance(code, str) or code not in _ERRORS:
        code = "sd_ioc_scan_failed"
    hint = ("forensics_fs_list에서 partition 또는 max_entries를 줄여 전체 목록을 다시 만드세요. "
            "잘린 목록의 coverage는 그대로 유지됩니다.") if code == "sdioc_input_limit" else None
    return PwehError(_ERRORS[code], code=code, hint=hint)


async def _scan_run(S: _ServerAPI, *, case_id: str, evidence_id: str,
                    firmware_result_path: str, fs_list_path: str, partition: int | None,
                    max_matches: int, max_seconds: float) -> dict:
    cancelled = threading.Event()
    try:
        deadline = _arguments(evidence_id, firmware_result_path, fs_list_path, partition, max_matches, max_seconds)
        case = await S._case(case_id)

        def work_body() -> dict:
            from pweh.sdioc import IocLimits, compare_sd_paths
            from pweh.sdioc_input import open_inputs

            _check(cancelled, deadline)
            entries = S.custody(case).entries()
            try:
                with E.open_checked(case, evidence_id, entries, reference_roots=S._reference_roots()) as opened:
                    with open_inputs(case, opened, firmware_result_path=firmware_result_path,
                                     fs_list_path=fs_list_path, entries=entries,
                                     deadline=deadline, cancel=cancelled.is_set) as inputs:
                        _check(cancelled, deadline)
                        limits = dataclasses.replace(IocLimits(), max_matches=max_matches,
                                                     max_output_bytes=MAX_REPORT_BYTES - (16 << 10))
                        report = compare_sd_paths(inputs.firmware, inputs.listing, partition=partition,
                                                  limits=limits, deadline=deadline, cancel=cancelled.is_set)
                        report["source"] = inputs.source
                        report["params"] = {"partition": partition, "max_matches": max_matches,
                                            "max_seconds": max_seconds}
                        schemas.validate("sd-ioc-scan", report)
                        raw = json.dumps(report, ensure_ascii=False, sort_keys=True,
                                         separators=(",", ":"), allow_nan=False)
                        if len(raw.encode("utf-8")) + 1 > MAX_REPORT_BYTES:
                            raise ValidationFailed(_ERRORS["validation_failed"])
                        _check(cancelled, deadline, time_limit=False)
                        return E.store_analysis(
                            case, opened, report, event="sd-ioc-scan", custody_log=S.custody(case),
                            reference_roots=lambda: S._reference_roots(),
                            check=inputs.check, check_entries=inputs.check_entries,
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
        # safe_tool로 원시 JSON·선택 경로·라이브러리 예외를 전달하지 않는다.
        raise _fixed_error(exc) from None


def register_ioc_tools(server: Any, namespace: dict[str, Any]) -> None:
    """기존 forensics 서버에 보고서 메타데이터 대조 도구 하나를 등록한다."""
    S = _ServerAPI(namespace)

    @server.tool(
        description=(
            "같은 케이스의 fw_sd_surface 전체 결과와 같은 EV의 FAT/exFAT fs-list 전체 JSON을 "
            "대조해 펌웨어 참조 경로와 카드 파일 이름이 겹치는 후보를 찾는다. "
            "firmware_result_path는 analysis/sd-surface-NNN.json, fs_list_path는 "
            "forensics/analysis/fs-list-EV-NNNN-NNN.json의 생성 상대 경로다. "
            "소유/허가·EV 지문·목록 보관 기록·펌웨어 아티팩트 해시를 확인하고 입력을 커밋까지 재검증한다. "
            "partition 생략 시 지원 볼륨 하나만 허용하며, max_matches는 1~200, max_seconds는 0 초 초과·최대 45초다. "
            "원시 증거 내용·복구 파일은 읽지 않으며 TAR/ZIP은 받지 않는다. "
            "정확 이름·ASCII 대소문자 변형·삭제 이름 후보와 불확실성·검사 한도를 구분한다. "
            "같은 장치 출처·실행·악성 여부를 확인하지 않으며 0건도 검사 범위 내 이름 불일치만 뜻한다. "
            "원시 카드 이름·경로·발췌 대신 생성 보고서 경로·해시·ref·배열 index·고정 분류만 반환한다. "
            "결과 JSON은 forensics/analysis/에 0444로 저장하고 sd-ioc-scan 보관 기록에 결속한다."
        ), annotations=ANN_LOCAL_WRITE,
    )
    @safe_tool
    async def forensics_sd_ioc_scan(
        case_id: str, evidence_id: str, firmware_result_path: str, fs_list_path: str,
        partition: StrictInt | None = None, max_matches: StrictInt = 200,
        max_seconds: StrictFloat | StrictInt = 45,
    ) -> dict:
        return await _scan_run(S, case_id=case_id, evidence_id=evidence_id,
                               firmware_result_path=firmware_result_path, fs_list_path=fs_list_path,
                               partition=partition, max_matches=max_matches, max_seconds=max_seconds)

    namespace["forensics_sd_ioc_scan"] = forensics_sd_ioc_scan
    # SDK의 인자 검증은 safe_tool 앞에서 실행된다. 이 도구의 모델에만 원문 숨김을
    # 적용하여 잘못된 숫자/누락 인자 오류가 input_value 전체를 되풀이하지 않게 한다.
    try:
        registered = server._tool_manager.get_tool("forensics_sd_ioc_scan")
        if registered is None:
            raise RuntimeError
        model = registered.fn_metadata.arg_model
        model.model_config["hide_input_in_errors"] = True
        model.model_rebuild(force=True)
    except Exception:
        raise RuntimeError("SD 이름 대조 도구의 비공개 입력 검증 설정을 완료하지 못했습니다.") from None
