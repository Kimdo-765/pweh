"""보관 기록에 결속된 FAT/exFAT 목록에서 파일을 자동 선정해 비밀값을 검사한다."""
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
from .secret_survey_selection import SurveyReadError, check_opened, read_survey_target
from .secrets_tools import _ServerAPI, _reject_media_name

MAX_REPORT_BYTES = 1 << 20
_LIST = re.compile(r"forensics/analysis/fs-list-(EV-[0-9]{4,6})-[0-9]{3,9}\.json\Z")
_ERRORS = {
    "validation_failed": "검사 인자 또는 생성 목록 경로가 허용 범위가 아닙니다.",
    "authorization_required": "케이스의 소유 또는 허가 확인이 필요합니다.",
    "not_found": "요청한 케이스·증거·생성 목록을 찾지 못했습니다.",
    "case_error": "케이스를 확인하지 못했습니다.",
    "custody_broken": "보관 기록을 검증하지 못했습니다.",
    "integrity_failed": "증거 또는 분석 입력·출력의 무결성을 확인하지 못했습니다.",
    "evidence_error": "증거 확인 또는 분석 저장을 완료하지 못했습니다.",
    "secret_survey_input_invalid": "생성 목록의 형식 또는 출처 결속을 확인하지 못했습니다.",
    "secret_survey_input_limit": "입력 목록이 크기 또는 구조 상한을 넘었습니다.",
    "secret_survey_input_changed": "저장 목록 또는 선택 항목의 신원이 일치하지 않습니다.",
    "secret_survey_invalid": "검사 결과의 내부 계약을 확인하지 못했습니다.",
    "secret_survey_limit": "검사 입력 또는 결과의 상한을 넘었습니다.",
    "secret_survey_callback_failed": "검사 상태를 확인하지 못했습니다.",
    "salt_invalid": "케이스 솔트가 올바른 일반 파일이 아닙니다.",
    "salt_corrupt": "케이스 솔트가 손상되어 지문을 만들지 못했습니다.",
    "cancelled": "목록 비밀값 검사가 취소되었습니다.",
    "timeout": "목록 검사의 공통 처리 시간 한도에 닿았습니다.",
    "scope_unavailable": "요청한 파티션이 저장 목록에 없습니다.",
    "secret_survey_failed": "목록 비밀값 검사를 완료하지 못했습니다.",
}


def _fixed(exc: Exception) -> PwehError:
    code = getattr(exc, "code", None)
    if not isinstance(code, str) or code not in _ERRORS:
        code = "secret_survey_failed"
    hint = "forensics_fs_list의 partition 또는 max_entries를 줄여 새 목록을 만드세요." if code == "secret_survey_input_limit" else None
    return PwehError(_ERRORS[code], code=code, hint=hint)


def _check(cancel: threading.Event, deadline: float, *, time_limit: bool = True) -> None:
    if cancel.is_set():
        raise PwehError(_ERRORS["cancelled"], code="cancelled")
    if time_limit and time.monotonic() >= deadline:
        raise PwehError(_ERRORS["timeout"], code="timeout")


def _arguments(evidence_id: Any, fs_list_path: Any, partition: Any, xor_key: Any, max_seconds: Any) -> float:
    match = _LIST.fullmatch(fs_list_path) if type(fs_list_path) is str and len(fs_list_path) <= 100 else None
    if (type(evidence_id) is not str or re.fullmatch(r"EV-[0-9]{4,6}", evidence_id) is None
            or match is None or match.group(1) != evidence_id
            or (partition is not None and (type(partition) is not int or not 1 <= partition <= 4096))
            or (xor_key is not None and (type(xor_key) is not int or xor_key != 144))
            or type(max_seconds) not in (int, float) or not 0 < max_seconds <= 45
            or not math.isfinite(max_seconds)):
        raise ValidationFailed(_ERRORS["validation_failed"])
    return time.monotonic() + max_seconds


def _media_name(name: Any) -> bool:
    try:
        _reject_media_name(name)
    except PwehError as exc:
        if exc.code == "unsupported_media":
            return True
        raise
    return False


def _audit(S: Any, case: Any, entry: dict) -> None:
    try:
        S.rt().audit({"event": "forensics_secrets_survey", "evidence_id": entry.get("evidence_id"),
                      "custody_seq": entry.get("seq"), "custody_hash": entry.get("hash")}, case.id)
    except Exception:
        raise PwehError("보조 감사 기록을 완료하지 못했습니다.", code="evidence_error") from None


def _integrity(S: Any, case: Any, evidence_id: str, exc: E.IntegrityProblem) -> None:
    if not exc.record:
        return
    entry = S.custody(case).append("integrity-failed", evidence_id=evidence_id, actor="server",
        data={"reason": "secret-survey-integrity-check", "problems": ["증거 무결성 검증 실패"],
              "found_by": "secrets-survey"})
    try:
        _audit(S, case, entry)
    except PwehError:
        pass


async def _survey_run(S: Any, *, case_id: str, evidence_id: str, fs_list_path: str,
                      partition: int | None, xor_key: int | None, max_seconds: float) -> dict:
    cancelled = threading.Event()
    try:
        deadline = _arguments(evidence_id, fs_list_path, partition, xor_key, max_seconds)
        case = await S._case(case_id)

        def body() -> dict:
            from pweh.secret_survey_input import open_list_input
            from pweh.secret_survey import SurveyLimits, SurveyCollector, plan_survey
            from pweh.secretscan import scan_secrets

            _check(cancelled, deadline)
            entries = S.custody(case).entries()
            try:
                with E.open_checked(case, evidence_id, entries, reference_roots=S._reference_roots()) as opened:
                    with open_list_input(case, opened, fs_list_path=fs_list_path, entries=entries,
                                         deadline=deadline, cancel=cancelled.is_set) as inputs:
                        limits = dataclasses.replace(SurveyLimits(), max_output_bytes=MAX_REPORT_BYTES - (16 << 10))
                        plan = plan_survey(inputs.listing, partition=partition, is_media_name=_media_name,
                                           limits=limits, deadline=deadline, cancel=cancelled.is_set)
                        _check(cancelled, deadline, time_limit=False)
                        collector = SurveyCollector(plan, xor_key=xor_key, limits=limits, cancel=cancelled.is_set)
                        stop_reason = None
                        for target in plan.targets:
                            _check(cancelled, deadline, time_limit=False)
                            if time.monotonic() >= deadline:
                                stop_reason = "time_limit"
                                break
                            scan_limits = collector.scan_limits()
                            if scan_limits is None:
                                break
                            try:
                                data, source = read_survey_target(opened, target, listing=inputs.listing,
                                                                 deadline=deadline, cancel=cancelled.is_set)
                            except SurveyReadError as exc:
                                collector.skip_file(target, exc.reason)
                                if exc.reason == "time_limit":
                                    stop_reason = "time_limit"
                                    break
                                continue
                            report = scan_secrets(data, digest=lambda value: S.rt().secret_digest(case_id, value),
                                                  xor_key=xor_key, limits=scan_limits, deadline=deadline,
                                                  cancel=cancelled.is_set)
                            collector.accept_file(target, source, report)
                            del data, source, report
                        report = collector.finish(stop_reason)
                        report["source"] = inputs.source
                        report["params"] = {"partition": partition, "xor_key": xor_key, "max_seconds": max_seconds}
                        schemas.validate("secrets-survey", report)
                        raw = json.dumps(report, ensure_ascii=False, sort_keys=True,
                                         separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
                        if len(raw) > MAX_REPORT_BYTES:
                            raise PwehError(_ERRORS["secret_survey_limit"], code="secret_survey_limit")
                        _check(cancelled, deadline, time_limit=False)

                        def final_check() -> None:
                            # 시간 partial도 취소·EV seal·목록 신원을 생략하지 않는다.
                            _check(cancelled, deadline, time_limit=False)
                            check_opened(opened)
                            inputs.check()

                        return E.store_analysis(case, opened, report, event="secrets-survey",
                            custody_log=S.custody(case), reference_roots=lambda: S._reference_roots(),
                            check=final_check, check_entries=inputs.check_entries,
                            on_commit=lambda entry: _audit(S, case, entry))
            except E.IntegrityProblem as exc:
                _integrity(S, case, evidence_id, exc)
                raise

        def work() -> dict:
            try:
                return body()
            except Exception as exc:
                raise _fixed(exc) from None
        return await run_blocking_cancellable(work, on_cancel=cancelled.set)
    except Exception as exc:
        raise _fixed(exc) from None


def register_secret_survey_tools(server: Any, namespace: dict[str, Any]) -> None:
    """기존 단일 파일 검사와 별개로 저장 목록 자동 선정 도구 하나를 등록한다."""
    S = _ServerAPI(namespace)

    @server.tool(description=(
        "같은 EV의 보관 기록에 결속된 FAT/exFAT fs-list 전체 JSON에서 파일을 자동 선정해 비밀값 후보를 검사한다. "
        "fs_list_path는 forensics/analysis/fs-list-EV-NNNN-NNN.json 생성 경로이며, partition 생략 시 저장 목록의 모든 지원 볼륨을 대상으로 한다. "
        "목록의 순서대로 디렉터리·미디어 이름·빈 data·4MiB 초과 파일을 제외하고 최대32개, 예정 data 합계16MiB를 선정한다. "
        "현재 항목의 도달성·크기·삭제·이름 metadata를 다시 확인하고 auto 복구의 완전한 data만 읽는다. exFAT VDL 뒤 잔여는 읽지 않는다. "
        "UTF-8/BOM만 검사하고 xor_key는 생략 또는 정수144, 후보 총200개·JSON1MiB 상한이다. "
        "max_seconds는 최대45초로 목록 입구·선정·읽기·검사의 공통 한도이며, 시간 partial의 최종 목록 해시·seal 검증은 별도 유한 검증이다. "
        "원문 이름·경로·시각·내용 대신 ref·고정 분류·마스킹·케이스 솔트 지문과 목록/선정/실제 검사 coverage만 반환한다. "
        "전체 카드 검사나 비밀 없음의 증명이 아니며, TAR/ZIP·미할당·residual·새 목록 순회는 포함하지 않는다. "
        "결과를 forensics/analysis/에0444로 저장하고 secrets-survey 사건에 EV·목록·출력 해시를 결속한다."
    ), annotations=ANN_LOCAL_WRITE)
    @safe_tool
    async def forensics_scan_secrets_from_list(
        case_id: str, evidence_id: str, fs_list_path: str, partition: StrictInt | None = None,
        xor_key: StrictInt | None = None, max_seconds: StrictInt | StrictFloat = 45,
    ) -> dict:
        return await _survey_run(S, case_id=case_id, evidence_id=evidence_id, fs_list_path=fs_list_path,
                                  partition=partition, xor_key=xor_key, max_seconds=max_seconds)

    namespace["forensics_scan_secrets_from_list"] = forensics_scan_secrets_from_list
