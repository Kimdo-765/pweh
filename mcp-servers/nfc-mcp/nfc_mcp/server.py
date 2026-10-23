"""scan 사실에 결속한 NFC inventory·등록 파일 분석 MCP 입구."""
from __future__ import annotations

import re
import threading
import time
from typing import Annotated

from mcp.server.mcpserver.utilities.func_metadata import FuncMetadata
from pydantic import Field, StrictFloat, StrictInt, StrictStr, ValidationError
from pydantic_core import PydanticCustomError

from pweh import schemas
from pweh.case import CASE_ID_RE
from pweh.errors import PwehError
from pweh.mcpkit import ANN_LOCAL_WRITE, Context, create_server, run_blocking_cancellable, safe_tool
from pweh.provenance import PROVENANCE_IMPORT_QUESTIONS, provenance_import_target
from pweh.runtime import Runtime, get_runtime
from pweh.safety import attestation_response
from . import analysis as A

SERVER_NAME = 'nfc-mcp'
_TOOLS = ('nfc_tag_inventory_add', 'nfc_parse_file', 'nfc_diff_dumps')
CaseId = Annotated[StrictStr, Field(max_length=80, pattern=CASE_ID_RE.pattern)]
ArtifactId = Annotated[StrictStr, Field(pattern=r'^A-[0-9]{4,8}$', max_length=10)]
TagRef = Annotated[StrictStr, Field(pattern=r'^NT-[0-9a-f]{32}$', max_length=35)]
ScanRef = Annotated[StrictStr, Field(pattern=r'^NS-[0-9a-f]{32}$', max_length=35)]
Seconds = Annotated[StrictInt | StrictFloat, Field(gt=0, le=5)]
_ERRORS = {code: 'NFC 요청을 완료하지 못했습니다.' for code in A._CODES}
_ERRORS.update({
    'authorization_required': '케이스의 소유 또는 서면 허가 확인이 필요합니다.',
    'not_found': '요청한 케이스를 찾지 못했습니다.',
    'case_error': 'NFC 케이스를 확인하지 못했습니다.',
    'config_error': 'NFC 실행 설정을 확인하지 못했습니다.',
    'safety_denied': '현재 정책에서 NFC 요청을 허용하지 않습니다.',
})


def rt() -> Runtime:
    return get_runtime(SERVER_NAME)


def _fixed_error(exc):
    code = getattr(exc, 'code', None)
    if type(code) is not str or code not in _ERRORS:
        code = 'nfc_failed'
    return PwehError(_ERRORS[code], code=code)


class _NfcMetadata(FuncMetadata):
    """SDK 자동 JSON 변환을 생략하고 검증 오류의 원문 위치도 제거한다."""
    def validate_arguments(self, arguments_to_validate):
        try:
            return self.arg_model.model_validate(arguments_to_validate).model_dump_one_level()
        except ValidationError:
            raise ValidationError.from_exception_data(
                'NfcInput', [{'type': PydanticCustomError('nfc_input_invalid', _ERRORS['nfc_input_invalid']),
                              'loc': (), 'input': None}], hide_input=True) from None


def _configure_input(instance):
    try:
        for name in _TOOLS:
            tool = instance._tool_manager.get_tool(name)
            if tool is None:
                raise RuntimeError
            old = tool.fn_metadata
            model = old.arg_model
            model.model_config.update(strict=True, extra='forbid', hide_input_in_errors=True)
            model.model_rebuild(force=True)
            tool.fn_metadata = _NfcMetadata(arg_model=model, output_schema=old.output_schema,
                                            output_model=old.output_model, wrap_output=old.wrap_output)
            tool.parameters = model.model_json_schema(by_alias=True)
            if tool.parameters.get('additionalProperties') is not False:
                raise RuntimeError
    except Exception:
        raise RuntimeError('NFC 도구의 입력 검증 설정을 완료하지 못했습니다.') from None


def _case_id(value):
    if type(value) is not str or len(value) > 80 or CASE_ID_RE.fullmatch(value) is None:
        raise A._error('nfc_input_invalid')


server = create_server(SERVER_NAME, title='PWEH NFC scan 결속 분석', instructions=(
    'flipper_nfc_probe가 만든 같은 케이스 scan_ref를 nfc_tag_inventory_add로 등록한다. '
    'nfc_parse_file/nfc_diff_dumps는 등록한 파일과 보호 scan·inventory의 신원을 비교한다. '
    '가져온 파일은 기존 provenance-import 사람 증명이 필요하다. raw UID·페이지·키 값은 반환하지 않는다. '
    '태그 쓰기·인증·에뮬레이션·키 탐색·임의 명령은 제공하지 않는다.'
))


@server.tool(description=(
    '같은 케이스 flipper_nfc_probe의 보호된 scan_ref를 NTAG213/215/216 inventory로 등록한다. '
    '사용자 UID/family나 cache로 scan을 대신하지 않는다. 공개 tag_ref·scan_ref·케이스 솔트 지문과 '
    'scan/inventory 원장 seq/hash만 반환한다. 물리적으로 같은 태그인지는 검증하지 않는다.'
), annotations=ANN_LOCAL_WRITE)
@safe_tool
async def nfc_tag_inventory_add(case_id: CaseId, scan_ref: ScanRef) -> dict:
    cancel = threading.Event()
    try:
        _case_id(case_id)
        if type(scan_ref) is not str or re.fullmatch(r'NS-[0-9a-f]{32}', scan_ref) is None:
            raise A._error('nfc_input_invalid')
        def work():
            from pweh.nfc_inventory import add_inventory
            runtime = rt()
            case = runtime.case(case_id, hardware=True)
            result = add_inventory(runtime, case, scan_ref, deadline=time.monotonic() + 5,
                                   cancel=cancel.is_set).to_dict()
            schemas.validate('nfc-inventory', result)
            return result
        return await run_blocking_cancellable(work, on_cancel=cancel.set)
    except Exception as exc:
        raise _fixed_error(exc) from None


async def _analyze(case_id, ids, tag_ref, max_seconds, ctx, tool):
    cancel = threading.Event()
    try:
        _case_id(case_id)
        if type(max_seconds) not in (int, float) or not 0 < max_seconds <= 5:
            raise A._error('nfc_input_invalid')
        runtime = rt()
        def prepare():
            case = runtime.case(case_id, hardware=True)
            return A.prepare_admission(runtime, case, ids, tag_ref,
                                       deadline=time.monotonic() + max_seconds, cancel=cancel.is_set)
        admission = await run_blocking_cancellable(prepare, on_cancel=cancel.set)
        # prepare의 모든 FD가 닫힌 뒤에만 사람 응답을 기다린다.
        for digest in dict.fromkeys(sha for _, sha in admission.artifacts):
            kind, subject, binding = provenance_import_target(case_id, digest)
            decision = await runtime.attest(kind, subject, binding, list(PROVENANCE_IMPORT_QUESTIONS),
                                            case_id, ctx, '등록 NFC 파일의 소유·취득 출처 확인', tool=tool)
            if not decision.satisfied:
                return attestation_response(decision, **({'warnings': list(admission.warnings)}
                                                         if admission.warnings else {}))
        def finish():
            case = runtime.case(case_id, hardware=True)
            return A.analyze_files(runtime, case, ids, tag_ref, admission,
                                   max_seconds=max_seconds, cancel=cancel.is_set)
        return await run_blocking_cancellable(finish, on_cancel=cancel.set)
    except Exception as exc:
        raise _fixed_error(exc) from None


@server.tool(description=(
    '등록 artifact_id의 Flipper v4 NFC 파일 하나를 같은 케이스 tag_ref와 결속해 오프라인 검사한다. '
    '각 입력은1MiB 이하 단일 링크 일반 파일이며 forensics/emu/보호 경로는 받지 않는다. '
    'UID/ATQA/SAK/GET_VERSION 신원은 내부에서만 비교한다. 가져온 파일은 기존 provenance-import 증명이 필요하며 '
    '대기 중 입력 FD를 보유하지 않는다. max_seconds는0초 초과5초 이하(기본5); 각 입구/최종 분석 worker에 적용하고 '
    '분석 후 최종 재검증·저장에는 별도5초를 사용한다. read<total은 페이지 배치를 추정하지 않는다. '
    'analysis/nfc-file-NNN.json에 마스킹 결과·전체 입력 SHA·원장/증명 결속을0444로 저장하며 실제 생성 경로를 반환한다.'
), annotations=ANN_LOCAL_WRITE)
@safe_tool
async def nfc_parse_file(case_id: CaseId, artifact_id: ArtifactId, tag_ref: TagRef,
                         max_seconds: Seconds = 5, ctx: Context = None) -> dict:
    return await _analyze(case_id, (artifact_id,), tag_ref, max_seconds, ctx, 'nfc_parse_file')


@server.tool(description=(
    '같은 tag_ref에 결속한 before/after 등록 NFC 덤프 두 개의 저장 페이지를 오프라인 비교한다. '
    '입력마다1MiB 이하, 두 파일 각각의 현재 provenance-import 증명을 확인한다. '
    'read<total·ISO 헤더·불완전 layout에서는 비교 불가/null을 유지한다. raw UID·페이지·Counter·PWD/PACK은 반환하지 않는다. '
    'max_seconds는0초 초과5초 이하이며 분석 후 별도5초 최종 검증·등록을 수행한다. '
    'analysis/nfc-diff-NNN.json의 실제 경로와 해시를 반환한다. 태그 쓰기·인증·에뮬레이션은 수행하지 않는다.'
), annotations=ANN_LOCAL_WRITE)
@safe_tool
async def nfc_diff_dumps(case_id: CaseId, before_artifact_id: ArtifactId, after_artifact_id: ArtifactId,
                         tag_ref: TagRef, max_seconds: Seconds = 5, ctx: Context = None) -> dict:
    return await _analyze(case_id, (before_artifact_id, after_artifact_id), tag_ref,
                          max_seconds, ctx, 'nfc_diff_dumps')


_configure_input(server)


def main():
    server.run()
