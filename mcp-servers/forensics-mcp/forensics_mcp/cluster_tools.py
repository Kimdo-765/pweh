"""같은 증거 fd에서 FAT/exFAT의 현재 할당·live 참조를 비교하는 MCP 입구."""

from __future__ import annotations

import dataclasses
import json
import math
import os
import re
import stat
import threading
import time
from typing import Any, Callable

from mcp.server.mcpserver.utilities.func_metadata import FuncMetadata
from pydantic import StrictFloat, StrictInt, StrictStr, ValidationError
from pydantic_core import PydanticCustomError

from pweh import evidence as E, schemas
from pweh.case import CASE_ID_RE
from pweh.errors import PwehError, ValidationFailed
from pweh.mcpkit import ANN_LOCAL_WRITE, run_blocking_cancellable, safe_tool

MAX_REPORT_BYTES = 1 << 20
MAX_EVIDENCE_BYTES = (1 << 63) - 1
_ERRORS = {
    "cancelled": "클러스터 참조 검사가 취소되었습니다.",
    "time_limit": "클러스터 참조 검사 준비의 시간 한도에 닿았습니다.",
    "validation_failed": "클러스터 참조 검사 인자가 허용 범위가 아닙니다.",
    "authorization_required": "케이스의 소유 또는 허가 확인이 필요합니다.",
    "not_found": "요청한 케이스 또는 증거를 찾지 못했습니다.",
    "case_error": "케이스를 확인하지 못했습니다.",
    "custody_broken": "증거의 보관 기록을 검증하지 못했습니다.",
    "integrity_failed": "증거 또는 분석 출력의 무결성을 확인하지 못했습니다.",
    "evidence_error": "증거 확인 또는 분석 저장을 완료하지 못했습니다.",
    "unsupported_fs": "선택한 파티션의 파일 시스템 검사를 지원하지 않습니다.",
    "partition_unavailable": "선택한 파티션을 하나로 확인하지 못했습니다.",
    "cluster_read_failed": "할당 메타데이터의 완전한 읽기를 확인하지 못했습니다.",
    "cluster_report_failed": "클러스터 참조 검사를 완료하지 못했습니다.",
}


class _ServerAPI:
    """runtime과 합성 시험의 주입을 서버 namespace의 늦은 참조로 유지한다."""

    def __init__(self, namespace: dict[str, Any]):
        self.namespace = namespace

    def __getattr__(self, name: str) -> Any:
        return self.namespace[name]


@dataclasses.dataclass(frozen=True, repr=False)
class _EvidenceSource:
    """fd 소유권을 넘기거나 경로를 다시 열지 않는 순수 코어의 읽기 입구."""

    size: int
    read: Callable[[int, int], bytes]
    base_offset: int = 0


def _check(cancelled: threading.Event, deadline: float, *, timing: bool = True) -> None:
    if cancelled.is_set():
        raise PwehError(_ERRORS["cancelled"], code="cancelled")
    if timing and time.monotonic() >= deadline:
        raise PwehError(_ERRORS["time_limit"], code="time_limit")


def _arguments(case_id: Any, evidence_id: Any, partition: Any, max_seconds: Any) -> float:
    if (type(case_id) is not str or len(case_id) > 80 or CASE_ID_RE.fullmatch(case_id) is None
            or type(evidence_id) is not str or re.fullmatch(r"EV-[0-9]{4,6}", evidence_id) is None
            or type(partition) is not int or not 1 <= partition <= 4096
            or type(max_seconds) not in (int, float) or not 0 < max_seconds <= 45
            or not math.isfinite(max_seconds)):
        raise ValidationFailed(_ERRORS["validation_failed"])
    # async 케이스 조회도 같은 시간 예산에 포함하며 worker에서 다시 시작하지 않는다.
    return time.monotonic() + max_seconds


def _identity(st: os.stat_result) -> tuple[int, ...]:
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_nlink


def _check_opened(opened: E.OpenedEvidence) -> int:
    """접수 크기와 보유 fd의 seal을 검사한다. atime 변화는 제외한다."""
    size = opened.intake["size"]
    if type(size) is not int or not 1 <= size <= MAX_EVIDENCE_BYTES:
        raise ValidationFailed(_ERRORS["validation_failed"])
    before, now = opened.st, os.fstat(opened.fd)
    if (not stat.S_ISREG(before.st_mode) or not stat.S_ISREG(now.st_mode)
            or before.st_nlink != 1 or now.st_nlink != 1 or before.st_size != size
            or _identity(before) != _identity(now)):
        raise E.IntegrityProblem("클러스터 참조 검사 중 증거의 파일 신원 또는 상태가 변경되었습니다.",
                                 reason="source-changed")
    return size


def _fixed_error(exc: Exception) -> PwehError:
    code = getattr(exc, "code", None)
    if type(code) is str:
        code = {"cluster_report_invalid": "validation_failed",
                "cluster_report_unsupported": "unsupported_fs"}.get(code, code)
    if type(code) is not str or code not in _ERRORS:
        code = "cluster_report_failed"
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
        data={"reason": "cluster-report-integrity-check", "problems": ["증거 무결성 검증 실패"],
              "found_by": "cluster-report"})
    try:
        _audit_commit(S, case, entry)
    except Exception:
        pass  # 커밋된 무결성 사건은 보조 감사 실패 뒤에도 보존한다.


async def _cluster_run(S: _ServerAPI, *, case_id: str, evidence_id: str,
                       partition: int, max_seconds: float) -> dict:
    cancelled = threading.Event()
    try:
        deadline = _arguments(case_id, evidence_id, partition, max_seconds)
        case = await S._case(case_id)

        def work_body() -> dict:
            from pweh.fs.cluster_report import ClusterReportLimits, inspect_cluster_report, validate_cluster_report_accounting

            _check(cancelled, deadline)
            entries = S.custody(case).entries()
            read_problem = None
            try:
                with E.open_checked(case, evidence_id, entries, reference_roots=S._reference_roots()) as opened:
                    size = _check_opened(opened)

                    def read_at(at: int, count: int) -> bytes:
                        nonlocal read_problem
                        try:
                            if read_problem is not None:
                                raise read_problem
                            # 시간 한도는 코어가 geometry 전 실패/후 partial로 구분한다.
                            _check(cancelled, deadline, timing=False)
                            if (type(at) is not int or type(count) is not int
                                    or not 0 <= at <= size or not 0 <= count <= 65536
                                    or count > size - at):
                                raise ValidationFailed(_ERRORS["validation_failed"])
                            _check_opened(opened)
                            data = os.pread(opened.fd, count, at) if count else b""
                            _check_opened(opened)
                            _check(cancelled, deadline, timing=False)
                            if type(data) is not bytes or len(data) != count:
                                raise PwehError(_ERRORS["cluster_read_failed"], code="cluster_read_failed")
                            return data
                        except Exception as exc:
                            # FS guard가 원인을 unknown/partial로 닫아도 최초 원인을 복원한다.
                            if read_problem is None:
                                read_problem = exc if isinstance(exc, PwehError) else PwehError(
                                    _ERRORS["cluster_read_failed"], code="cluster_read_failed")
                            raise read_problem from None

                    limits = dataclasses.replace(ClusterReportLimits(), output_bytes=MAX_REPORT_BYTES - (16 << 10))
                    try:
                        report = inspect_cluster_report(
                            _EvidenceSource(size, read_at), partition=partition,
                            limits=limits, deadline=deadline, cancel=cancelled.is_set)
                    except Exception:
                        if read_problem is not None:
                            raise read_problem from None
                        raise
                    if read_problem is not None:
                        raise read_problem from None
                    source = {"kind": "evidence", "evidence_id": evidence_id,
                              "evidence_sha256": opened.intake["hashes"]["sha256"], "evidence_size": size}
                    params = {"partition": partition, "max_seconds": max_seconds}
                    report["source"], report["params"] = dict(source), dict(params)
                    schemas.validate("cluster-report", report)
                    validate_cluster_report_accounting(report)
                    if (report["source"] != source or report["params"] != params
                            or type(report["source"]["evidence_size"]) is not int
                            or type(report["params"]["partition"]) is not int
                            or type(report["params"]["max_seconds"]) is not type(max_seconds)):
                        raise ValidationFailed(_ERRORS["validation_failed"])
                    raw = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
                    if len(raw.encode("utf-8")) + 1 > MAX_REPORT_BYTES:
                        raise ValidationFailed(_ERRORS["validation_failed"])

                    def final_check() -> None:
                        # 시간 partial도 저장하되 취소·증거 seal은 커밋 직전까지 검사한다.
                        _check(cancelled, deadline, timing=False)
                        _check_opened(opened)

                    final_check()
                    return E.store_analysis(
                        case, opened, report, event="cluster-report", custody_log=S.custody(case),
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


class _ClusterMetadata(FuncMetadata):
    """원 입력과 추가 키의 위치를 SDK 오류에 옮기지 않는다."""

    def validate_arguments(self, arguments_to_validate: dict) -> dict:
        try:
            return self.arg_model.model_validate(arguments_to_validate).model_dump_one_level()
        except ValidationError:
            raise ValidationError.from_exception_data(
                "ClusterInput", [{"type": PydanticCustomError("validation_failed", _ERRORS["validation_failed"]),
                                  "loc": (), "input": None}], hide_input=True,
            ) from None


def register_cluster_tools(server: Any, namespace: dict[str, Any]) -> None:
    """기존 포렌식 서버에 명시 파티션의 live 참조 일관성 도구 하나를 등록한다."""
    S = _ServerAPI(namespace)

    @server.tool(description=(
        "접수한 EV 이미지의 명시 FAT12/16/32·exFAT 파티션에서 현재 할당과 live 항목 참조를 비교한다. "
        "partition은 필수 exact int1..4096, max_seconds는0초 초과..45초다. "
        "케이스 조회 전부터 같은 처리 예산으로 탐지·metadata·live 순회·분류를 수행한다. "
        "metadata 읽기 합계32MiB·클러스터2**20개·항목16384개·행128개·JSON1MiB로 제한한다. "
        "참조 지도/할당 검사가 불완전하면 allocated_without_live_reference는null이며 고아 파일로 확정하지 않는다. "
        "관찰한 참조 중복·미할당 참조·체인 이상과 완료도·미검사 수를 원시 이름 없이 기록한다. "
        "접수 EV 해시를 출처에 결속하며 이번 전체EV 재해시는 아니다. "
        "시간 partial의 bounded 직렬화·최종seal 검사는 처리 시간 뒤 별도로 끝내되 취소를 계속 확인한다. "
        "보고서를 forensics/analysis에0444로 저장하고 cluster-report 보관 기록에 결속한다. "
        "이 보고서는 직접 추출 권위가 아니며 필요한 구간은 기존 후보 도구로 별도 검증한다. "
        "파일 소속·삭제/과거 할당·녹화 완전성·재생을 판정하지 않고 미디어를 해독하지 않는다."
    ), annotations=ANN_LOCAL_WRITE)
    @safe_tool
    async def forensics_cluster_report(
        case_id: StrictStr, evidence_id: StrictStr, partition: StrictInt,
        max_seconds: StrictFloat | StrictInt = 45,
    ) -> dict:
        return await _cluster_run(S, case_id=case_id, evidence_id=evidence_id,
                                  partition=partition, max_seconds=max_seconds)

    namespace["forensics_cluster_report"] = forensics_cluster_report
    try:
        registered = server._tool_manager.get_tool("forensics_cluster_report")
        if registered is None:
            raise RuntimeError
        old = registered.fn_metadata
        model = old.arg_model
        model.model_config.update(strict=True, extra="forbid", hide_input_in_errors=True)
        model.model_rebuild(force=True)
        registered.fn_metadata = _ClusterMetadata(
            arg_model=model, output_schema=old.output_schema,
            output_model=old.output_model, wrap_output=old.wrap_output)
        registered.parameters = model.model_json_schema(by_alias=True)
        if registered.parameters.get("additionalProperties") is not False:
            raise RuntimeError
    except Exception:
        raise RuntimeError("클러스터 참조 도구의 비공개 입력 검증 설정을 완료하지 못했습니다.") from None
