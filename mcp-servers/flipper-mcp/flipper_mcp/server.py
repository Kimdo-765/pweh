"""Flipper의 고정 CLI 연결·조회·파일 복사를 제공하는 MCP 입구."""

from __future__ import annotations

import functools
import inspect
import math
import re
import threading
from typing import Annotated

import anyio
from mcp.server.mcpserver.utilities.func_metadata import FuncMetadata
from pydantic import Field, StrictStr, ValidationError
from pydantic_core import PydanticCustomError

from pweh.case import CASE_ID_RE
from pweh.errors import PwehError
from pweh.jobs import JobCancelled
from pweh.mcpkit import (ANN_DEVICE, ANN_LOCAL_WRITE, ANN_READ_ONLY, Context, create_server,
                         gate_response, register_job_tools, run_blocking, run_blocking_cancellable, safe_tool)
from pweh.runtime import Runtime, get_runtime
from pweh.safety import Classification, Risk

SERVER_NAME = "flipper-mcp"
_ERRORS = {
    "flipper_invalid_input": "Flipper 입력이 허용된 형식이나 범위가 아닙니다.",
    "flipper_identity_unknown": "Flipper의 고정 USB 신원을 확인하지 못했습니다.",
    "flipper_identity_changed": "Flipper 포트 또는 USB 범위가 변경되었습니다.",
    "flipper_role_conflict": "대상 콘솔 또는 브리지로 표시된 포트입니다.",
    "flipper_firmware_unsupported": "이 Flipper 펌웨어는 고정 읽기 프로필과 일치하지 않습니다.",
    "flipper_handshake_failed": "새 Flipper 배너와 기본 프롬프트를 확인하지 못했습니다.",
    "flipper_app_busy": "Flipper 앱의 유휴 상태를 확인하지 못했습니다.",
    "flipper_protocol_error": "Flipper 응답이 고정 읽기 프로토콜과 일치하지 않습니다.",
    "flipper_storage_error": "Flipper 저장소 읽기를 완료하지 못했습니다.",
    "flipper_limit": "Flipper 읽기의 고정 한도에 닿았습니다.",
    "flipper_checksum_mismatch": "Flipper 파일 전송의 MD5가 일치하지 않습니다.",
    "flipper_busy": "이 Flipper 케이스 또는 세션이 사용 중입니다.",
    "flipper_terminal": "Flipper 세션을 사용할 수 없습니다. 먼저 명시적으로 닫으세요.",
    "flipper_cleanup_pending": "Flipper 작업 또는 물리 핸들 정리를 확인하지 못했습니다.",
    "flipper_failed": "Flipper 읽기 작업을 완료하지 못했습니다.",
    "cancelled": "Flipper 읽기 작업이 취소되었습니다.",
    "time_limit": "Flipper 읽기의 시간 한도에 닿았습니다.",
    "authorization_required": "케이스의 소유 또는 서면 허가 확인이 필요합니다.",
    "not_found": "요청한 케이스 또는 작업을 찾지 못했습니다.",
    "case_error": "Flipper 케이스를 확인하지 못했습니다.",
    "config_error": "Flipper 실행 설정을 확인하지 못했습니다.",
    "safety_denied": "현재 정책에서 이 Flipper 작업을 허용하지 않습니다.",
    "instrument_port": "고정 계측기로 표시된 포트에 접근하지 않습니다.",
    "instrument_identity_unknown": "고정 계측기와 대상 포트를 구분하지 못했습니다.",
    "port_role_conflict": "대상 콘솔 또는 브리지로 표시된 포트에 접근하지 않습니다.",
    "port_role_unknown": "포트 역할 표지를 확인하지 못했습니다.",
    "port_scope_unknown": "USB 장치의 전체 인터페이스 범위를 확인하지 못했습니다.",
    "port_lease_invalid": "Flipper 포트 잠금을 확인하지 못했습니다.",
    "route_changed": "승인 이후 포트 경로 또는 장치 식별이 변경되었습니다.",
    "busy": "요청한 포트 또는 작업이 사용 중입니다.",
}
_TOOLS = ("flipper_connect", "flipper_close", "flipper_device_info", "flipper_storage_list",
          "flipper_storage_pull_start", "flipper_job_status", "flipper_job_cancel", "flipper_jobs")
CaseId = Annotated[StrictStr, Field(max_length=80, pattern=CASE_ID_RE.pattern)]


def rt() -> Runtime:
    return get_runtime(SERVER_NAME)


def _fixed_error(exc: Exception) -> PwehError:
    """공용 도구의 ToolError까지 원문 없이 고정 오류로 투영한다."""
    code = getattr(exc, "code", None)
    if type(code) is not str or code not in _ERRORS:
        # register_job_tools의 safe_tool은 이미 문자열 ToolError로 바꾸었을 수 있다.
        match = re.match(r"\[([a-z_]+)\]", str(exc)) if type(exc).__name__ == "ToolError" else None
        code = match[1] if match and match[1] in _ERRORS else "flipper_failed"
    return PwehError(_ERRORS[code], code=code)


def _invalid() -> PwehError:
    return PwehError(_ERRORS["flipper_invalid_input"], code="flipper_invalid_input")


def _case_id(value) -> None:
    if type(value) is not str or len(value) > 80 or CASE_ID_RE.fullmatch(value) is None:
        raise _invalid()


def _text(value, limit: int) -> None:
    if (type(value) is not str or not 1 <= len(value) <= limit
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise _invalid()


class _FlipperMetadata(FuncMetadata):
    """8개 도구의 SDK 오류에서 추가 키·값·원문 위치를 제거한다."""

    def validate_arguments(self, arguments_to_validate: dict) -> dict:
        try:
            # SDK의 문자열 JSON 변환을 사용하지 않고 원래 scalar 타입을 보존한다.
            result = self.arg_model.model_validate(arguments_to_validate).model_dump_one_level()
            if "wait_seconds" in result:
                value = result["wait_seconds"]
                if type(value) not in (int, float) or not math.isfinite(value):
                    raise _invalid()
            return result
        except (ValidationError, PwehError, OverflowError):
            raise ValidationError.from_exception_data(
                "FlipperInput", [{"type": PydanticCustomError(
                    "flipper_invalid_input", _ERRORS["flipper_invalid_input"]), "loc": (), "input": None}],
                hide_input=True,
            ) from None


def _fixed_call(fn):
    """공통 job 도구를 바꾸지 않고 이 서버의 오류 경계만 닫는다."""
    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def async_call(*args, **kwargs):
            try:
                return await fn(*args, **kwargs)
            except Exception as exc:
                raise _fixed_error(exc) from None
        return safe_tool(async_call)

    @functools.wraps(fn)
    def sync_call(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            raise _fixed_error(exc) from None
    return safe_tool(sync_call)


def _configure_input(instance) -> None:
    try:
        for name in _TOOLS:
            tool = instance._tool_manager.get_tool(name)
            if tool is None:
                raise RuntimeError
            old = tool.fn_metadata
            model = old.arg_model
            model.model_config.update(strict=True, extra="forbid", hide_input_in_errors=True)
            model.model_rebuild(force=True)
            tool.fn_metadata = _FlipperMetadata(arg_model=model, output_schema=old.output_schema,
                                                output_model=old.output_model, wrap_output=old.wrap_output)
            tool.parameters = model.model_json_schema(by_alias=True)
            if tool.parameters.get("additionalProperties") is not False:
                raise RuntimeError
            if name in _TOOLS[5:]:
                tool.fn = _fixed_call(tool.fn)
    except Exception:
        raise RuntimeError("Flipper 도구의 비공개 입력 검증 설정을 완료하지 못했습니다.") from None


server = create_server(SERVER_NAME, title="PWEH Flipper 읽기 전송", instructions=(
    "소유/허가 케이스의 명시 Flipper USB CLI 포트를 고정1.5.1 읽기 프로필로 사용한다. "
    "flipper_connect → device_info/storage_list/storage_pull_start → job_status → flipper_close 순서다. "
    "connect는 DTR=true 포트 열기로 MODIFY이며 새 배너·버전·프롬프트를 확인하기 전 명령 바이트를 보내지 않는다. "
    "원격 /ext/pweh/<case_id>/ 아래 파일만 최대1MiB 받아 MD5와 host SHA를 확인한다. "
    "임의 명령·앱 실행·RF/NFC 작업·재생·storage 쓰기는 없다. 파일 전송은 기기 파일 출처나 원자 snapshot 증명이 아니다. "
    "끝나면 항상 close하며 물리 정리 미확인은 같은 세션과 잠금을 보존한다."
))


async def _close_owner(owner) -> None:
    """취소된 호출도 이미 만들어진 owner의 정리 책임을 놓치지 않는다."""
    with anyio.CancelScope(shield=True):
        result = await run_blocking(owner.close)
        if result.get("state") == "cleanup_pending":
            raise PwehError(_ERRORS["flipper_cleanup_pending"], code="flipper_cleanup_pending")


@server.tool(description=(
    "명시 Flipper USB CLI 포트에 연결한다. 소유/허가 확인 및 전체 USB sibling 잠금 뒤 MODIFY gate를 거친다. "
    "115200 8N1, DTR=true/RTS=false 고정이며 포트 열기가 장치 상태에 영향을 줄 수 있다. "
    "VID/PID0483:5740·첫 CLI interface00과 공식1.5.1 고정 문법만 받는다. 새 배너·버전·기본 프롬프트 전 명령 TX0이다. "
    "loader idle과 제한된 info를 확인한다. 배너·info는 공식 펌웨어 서명 증명이 아니다. "
    "approval_required면 사람이 승인한 뒤 같은 인자와 approval_id로 재호출한다."
), annotations=ANN_DEVICE)
@safe_tool
async def flipper_connect(case_id: CaseId, port: Annotated[StrictStr, Field(max_length=4096)],
                          approval_id: Annotated[StrictStr, Field(max_length=128)] | None = None,
                          ctx: Context | None = None) -> dict:
    cancelled = threading.Event()
    holder = {}
    lock = threading.Lock()
    connected = False
    try:
        _case_id(case_id)
        _text(port, 4096)
        if approval_id is not None:
            _text(approval_id, 128)
        runtime = rt()

        def prepare():
            from .session import prepare_session
            case = runtime.case(case_id, hardware=True)
            owner = prepare_session(runtime, case, port)
            with lock:
                holder["owner"] = owner
                abandoned = cancelled.is_set()
            if abandoned:
                owner.close()
                raise PwehError(_ERRORS["cancelled"], code="cancelled")
            return owner

        owner = await run_blocking_cancellable(prepare, on_cancel=cancelled.set)
        decision = await runtime.authorize(tool="flipper_connect", action=owner.action,
            classification=Classification(Risk.MODIFY, "flipper.connect.dtr", "DTR를 설정하는 고정 Flipper CLI 포트 열기"),
            case_id=case_id, approval_id=approval_id, ctx=ctx, summary="고정 Flipper CLI 연결과 새 배너 확인")
        if not decision.allowed:
            return gate_response(decision)

        def connect():
            runtime.case(case_id, hardware=True)
            return owner.connect(cancelled)

        result = await run_blocking_cancellable(connect, on_cancel=cancelled.set)
        connected = True
        return result
    except Exception as exc:
        raise _fixed_error(exc) from None
    finally:
        if not connected:
            cancelled.set()
            with lock:
                owner = holder.get("owner")
            if owner is not None:
                try:
                    await _close_owner(owner)
                except Exception as exc:
                    raise _fixed_error(exc) from None


@server.tool(description=(
    "Flipper 세션을 닫는다. 새 요청을 막고 worker 취소·직렬 read 깨우기 뒤 실제 핸들 닫힘과 사용권0을 확인한다. "
    "정리가 미확인이면 cleanup_pending으로 세션·잠금을 보존하며 같은 도구로 다시 정리한다. "
    "케이스 허가가 철회되어도 정리할 수 있다. 장치 명령 종료나 RF field off는 증명하지 않는다."
), annotations=ANN_LOCAL_WRITE)
@safe_tool
async def flipper_close(case_id: CaseId) -> dict:
    try:
        _case_id(case_id)
        from .session import close_session

        def work():
            try:
                runtime = rt()
                for row in runtime.jobs.list(active_only=True):
                    if row.get("case_id") == case_id and row.get("kind") == "flipper-storage-pull":
                        runtime.jobs.cancel(row["job_id"])
            finally:
                result = close_session(case_id)
            return result

        return await run_blocking(work)
    except Exception as exc:
        raise _fixed_error(exc) from None


async def _operation(case_id, kind, path, ctx):
    cancelled = threading.Event()
    holder = {}
    lock = threading.Lock()
    completed = False

    def cancel():
        cancelled.set()
        with lock:
            use = holder.get("use")
        if use is not None:
            use.cancel()

    try:
        _case_id(case_id)
        runtime = rt()

        def prepare():
            from .session import get_session
            runtime.case(case_id, hardware=True)
            owner = get_session(case_id)
            if path is not None:
                from pweh.flipper_cli import remote_path
                remote_path(case_id, path, file=False)
            use = owner.reserve_use()
            with lock:
                holder["use"] = use
                abandoned = cancelled.is_set()
            if abandoned:
                use.cancel()
                raise PwehError(_ERRORS["cancelled"], code="cancelled")
            return owner, use

        owner, use = await run_blocking_cancellable(prepare, on_cancel=cancel)
        action = {**owner.action, "operation": kind}
        if path is not None:
            action["path"] = path
        decision = await runtime.authorize(tool="flipper_" + kind, action=action,
            classification=Classification(Risk.OBSERVE, "flipper.fixed-read", "고정 Flipper 읽기 명령"),
            case_id=case_id, ctx=ctx, summary="고정 Flipper 정보 또는 저장소 목록 읽기")
        if not decision.allowed:
            return gate_response(decision)

        def work():
            if not use.claim():
                raise PwehError(_ERRORS["cancelled"], code="cancelled")
            try:
                runtime.case(case_id, hardware=True)
                return owner.device_info(use) if kind == "device_info" else owner.storage_list(use, path)
            finally:
                use.finish()

        result = await run_blocking_cancellable(work, on_cancel=cancel)
        completed = True
        return result
    except Exception as exc:
        raise _fixed_error(exc) from None
    finally:
        if not completed:
            cancel()


@server.tool(description=(
    "연결된 Flipper의 loader idle을 확인하고 고정 info device 응답을 읽는다(OBSERVE). "
    "model·target·format·고정 firmware 호환 정보만 반환하며 장치 UID·이름·BLE MAC·원문을 반환하지 않는다. "
    "소유/허가와 현재 포트·역할·잠금을 다시 확인하며 앱 유휴 관찰은 앱 실행 잠금이 아니다."
), annotations=ANN_READ_ONLY)
@safe_tool
async def flipper_device_info(case_id: CaseId, ctx: Context | None = None) -> dict:
    return await _operation(case_id, "device_info", None, ctx)


@server.tool(description=(
    "연결된 Flipper의 /ext/pweh/<case_id>/ 아래 한 디렉터리를 고정 storage list로 읽는다(OBSERVE). "
    "loader idle·현재 신원 확인 후 이름/type/size 최대256개와 종결 여부를 반환한다. "
    "path는 제한 ASCII 경로이며 링크 이동·임의 루트·명령은 받지 않는다. 응답 한도256KiB를 넘으면 실패한다. "
    "listing_complete는 CLI 응답 종결만 뜻하며 파일시스템 전체 목록의 완전성 증명이 아니다."
), annotations=ANN_READ_ONLY)
@safe_tool
async def flipper_storage_list(case_id: CaseId, path: Annotated[StrictStr, Field(max_length=512)],
                               ctx: Context | None = None) -> dict:
    return await _operation(case_id, "storage_list", path, ctx)


@server.tool(description=(
    "연결된 Flipper의 /ext/pweh/<case_id>/ 아래 파일 하나를 받는 job을 시작한다(고정 읽기 OBSERVE). "
    "flipper_path는 제한 ASCII 파일 경로, dest_name은 선택적 host basename이며 출력은 flipper/ 아래 새 파일이다. "
    "최대1MiB·300초이며 binary 본문은 해석하지 않는다. 종결 뒤 장치 MD5와 host MD5·SHA를 검증하고 "
    "같은 FD로 별도 최대5초 최종 검증·0444 게시·일반 케이스 아티팩트 등록을 한다. "
    "원격 원자 snapshot이나 파일 생성 출처·RF 캡처를 증명하지 않는다. 부분 전송은 등록하지 않고 commit 뒤 취소는 결과를 보존한다."
), annotations=ANN_DEVICE)
@safe_tool
async def flipper_storage_pull_start(case_id: CaseId,
    flipper_path: Annotated[StrictStr, Field(max_length=512)],
    dest_name: Annotated[StrictStr, Field(max_length=96)] | None = None,
    ctx: Context | None = None) -> dict:
    cancelled = threading.Event()
    holder = {}
    lock = threading.Lock()
    started = False

    def cancel():
        cancelled.set()
        with lock:
            use = holder.get("use")
        if use is not None:
            use.cancel()

    try:
        _case_id(case_id)
        runtime = rt()

        def prepare():
            from pweh.flipper_cli import destination_name, remote_path
            from .session import get_session
            case = runtime.case(case_id, hardware=True)
            remote_path(case_id, flipper_path, file=True)
            if dest_name is not None:
                destination_name(dest_name)
            owner = get_session(case_id)
            use = owner.reserve_use()
            with lock:
                holder["use"] = use
                abandoned = cancelled.is_set()
            if abandoned:
                use.cancel()
                raise PwehError(_ERRORS["cancelled"], code="cancelled")
            return case, owner, use

        case, owner, use = await run_blocking_cancellable(prepare, on_cancel=cancel)
        decision = await runtime.authorize(tool="flipper_storage_pull_start",
            action={**owner.action, "operation": "storage_pull", "path": flipper_path, "dest_name": dest_name},
            classification=Classification(Risk.OBSERVE, "flipper.fixed-read", "고정 Flipper 파일 읽기"),
            case_id=case_id, ctx=ctx, summary="고정 Flipper 파일 읽기와 host 사본 등록")
        if not decision.allowed:
            return gate_response(decision)

        def worker(jctx):
            if not use.claim():
                raise JobCancelled()
            try:
                runtime.case(case_id, hardware=True)
                from .storage import pull
                return pull(use, case, flipper_path, dest_name, jctx)
            except JobCancelled:
                raise
            except Exception as exc:
                if getattr(exc, "code", None) == "cancelled":
                    raise JobCancelled() from None
                raise _fixed_error(exc) from None
            finally:
                use.finish()

        def start():
            if cancelled.is_set():
                raise PwehError(_ERRORS["cancelled"], code="cancelled")
            return runtime.jobs.start("flipper-storage-pull", worker, description="Flipper 파일 읽기",
                case_id=case_id, meta={"session_id": owner.session_id}, exclusive_key="flipper:" + owner.session_id)

        job = await run_blocking_cancellable(start, on_cancel=cancel)
        started = True
        return {"ok": True, "job_id": job.id, "status": job.status}
    except Exception as exc:
        raise _fixed_error(exc) from None
    finally:
        if not started:
            cancel()


register_job_tools(server, rt, "flipper")
_configure_input(server)


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
