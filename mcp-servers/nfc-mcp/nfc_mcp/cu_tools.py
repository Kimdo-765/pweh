"""CU 고정 reader 연결·NTAG probe·정리의 MCP 입구."""
from __future__ import annotations

import threading
import time
from typing import Annotated

import anyio
from pydantic import Field, StrictStr

from pweh import cu_protocol as CU, nfc_inventory as I, schemas
from pweh.case import CASE_ID_RE
from pweh.errors import PwehError
from pweh.mcpkit import (ANN_DEVICE, ANN_LOCAL_WRITE, Context, gate_response,
                         run_blocking, run_blocking_cancellable, safe_tool)
from pweh.nfc_formats import _NfcFileIdentity
from pweh.safety import Classification, Risk

CaseId = Annotated[StrictStr, Field(max_length=80, pattern=CASE_ID_RE.pattern)]
SessionId = Annotated[StrictStr, Field(min_length=1, max_length=128)]
ApprovalId = Annotated[StrictStr, Field(min_length=1, max_length=128)]
START_SECONDS = 5
SCAN_SECONDS = 45
CLOSE_SECONDS = 10
_CODES = frozenset((
    'cu_protocol_invalid', 'cu_model_unsupported', 'cu_firmware_unsupported',
    'cu_reader_required', 'cu_identity_unknown', 'cu_cleanup_unknown',
    'nfc_input_invalid', 'nfc_input_limit', 'nfc_scan_invalid', 'nfc_family_unsupported',
    'nfc_identity_mismatch', 'nfc_provenance_invalid', 'nfc_failed',
    'cancelled', 'time_limit', 'authorization_required', 'not_found', 'case_error', 'config_error',
    'safety_denied', 'instrument_port', 'instrument_identity_unknown', 'port_role_conflict',
    'port_role_unknown', 'port_scope_unknown', 'port_lease_invalid', 'route_changed', 'busy',
    'port_busy', 'port_lock_busy',
))
_CLOSE_REASONS = (None, 'worker_pending', 'transport_close_unconfirmed', 'lease_close_unconfirmed', 'cleanup_failed')


def _error(code='nfc_failed'):
    return PwehError('CU 고정 읽기 요청을 완료하지 못했습니다.', code=code)


def _fixed(exc):
    code = getattr(exc, 'code', None)
    return _error(code if type(code) is str and code in _CODES else 'nfc_failed')


def _text(value, limit):
    if (type(value) is not str or not 1 <= len(value) <= limit
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)):
        raise _error('nfc_input_invalid')


def _args(case_id, *, session_id=None, port=None, approval_id=None):
    if type(case_id) is not str or len(case_id) > 80 or CASE_ID_RE.fullmatch(case_id) is None:
        raise _error('nfc_input_invalid')
    for value, limit in ((session_id, 128), (port, 4096), (approval_id, 128)):
        if value is not None:
            _text(value, limit)


def _close_projection(result):
    """정리 상태도 임의 원문이나 불명확한 truthy 값 없이 반환한다."""
    data = result.to_dict()
    flags = ('workers_stopped', 'transport_closed', 'lease_closed', 'cleanup_confirmed',
             'device_command_termination_verified', 'rf_off_verified')
    if (type(data) is not dict or set(data) != {*flags, 'reason'}
            or any(type(data[k]) is not bool for k in flags)
            or data['device_command_termination_verified'] or data['rf_off_verified']
            or data['reason'] not in _CLOSE_REASONS
            or data['cleanup_confirmed'] != all(data[k] for k in flags[:3])
            or (data['reason'] is None) != data['cleanup_confirmed']):
        raise _error('cu_cleanup_unknown')
    return dict(data)


async def _close_prepared(owner):
    with anyio.CancelScope(shield=True):
        result = await run_blocking(lambda: owner.close(deadline=time.monotonic() + CLOSE_SECONDS))
        if not _close_projection(result)['cleanup_confirmed']:
            raise _error('cu_cleanup_unknown')


def approval_action(owner):
    """probe의 정확 세션과 고정 recipe만 승인 지문에 추가한다."""
    return {**owner.action, 'operation': 'ntag_scan', 'session_id': owner.session_id,
            'nfc_profile': CU.PROFILE, 'nfc_profile_sha256': CU.PROFILE_SHA256,
            'read_requests': 2, 'pages_retained': 2}


def _observation(probe, session_id):
    from .cu_owner import CuProbe
    if (type(probe) is not CuProbe or probe.session_id != session_id
            or type(probe.identity) is not CU.CuScanIdentity or type(probe.family) is not CU.NtagFamily):
        raise _error('nfc_scan_invalid')
    value = probe.identity
    identity = _NfcFileIdentity(value.uid, value.atqa_msb, value.sak,
                                probe.family.mifare_version, 'iso14443-3a')
    return I.CuScanObservation(probe.session_id, probe.reader_binding, identity,
                              probe.page_identity_match, probe.reader_crc_check_succeeded,
                              probe.steps_complete)


async def _connect(namespace, case_id, port, approval_id, ctx):
    cancelled, lock, holder = threading.Event(), threading.Lock(), {}
    connected = False

    def cancel():
        cancelled.set()
        with lock:
            use = holder.get('use')
        if use is not None:
            use.cancel()

    try:
        _args(case_id, port=port, approval_id=approval_id)
        runtime = namespace['rt']()
        def prepare():
            from .cu_owner import prepare_cu_session
            case = runtime.case(case_id, hardware=True)
            owner = prepare_cu_session(runtime, case, port)
            with lock:
                holder['owner'] = owner
                abandoned = cancelled.is_set()
            if abandoned:
                owner.close(deadline=time.monotonic() + CLOSE_SECONDS)
                raise _error('cancelled')
            return owner

        owner = await run_blocking_cancellable(prepare, on_cancel=cancel)
        decision = await runtime.authorize(tool='nfc_cu_connect', action=owner.action,
            classification=Classification(Risk.MODIFY, 'cu.connect.dtr', 'DTR를 설정하는 고정 CU reader 포트 열기'),
            case_id=case_id, approval_id=approval_id, ctx=ctx, summary='고정 CU 모델·버전·reader 모드 확인')
        if not decision.allowed:
            return gate_response(decision)

        def work():
            use = owner.reserve_use(opening=True, cancel=cancelled.is_set)
            with lock:
                holder['use'] = use
                abandoned = cancelled.is_set()
            if abandoned:
                use.cancel()
            if not use.claim():
                raise _error('cancelled')
            try:
                deadline = time.monotonic() + START_SECONDS
                runtime.case(case_id, hardware=True)
                device = owner.start(use, deadline=deadline)
                if (type(device) is not CU.CuDevice or device.model != 'chameleon-ultra'
                        or device.app_version != CU.FIRMWARE_VERSION or device.git_version != CU.FIRMWARE_GIT_VERSION
                        or device.reader_mode is not True):
                    raise _error('cu_protocol_invalid')
                return {'ok': True, 'case_id': case_id, 'session_id': owner.session_id,
                    'profile': CU.PROFILE, 'state': 'ready',
                    'device': {'model': device.model, 'app_version': device.app_version,
                               'git_version': device.git_version, 'reader_mode': True,
                               'firmware_claim_verified': False},
                    'device_command_termination_verified': False, 'rf_off_verified': False}
            finally:
                use.finish()

        result = await run_blocking_cancellable(work, on_cancel=cancel)
        connected = True
        return result
    except Exception as exc:
        raise _fixed(exc) from None
    finally:
        if not connected:
            cancel()
            with lock:
                owner = holder.get('owner')
            if owner is not None:
                try:
                    await _close_prepared(owner)
                except Exception as exc:
                    raise _fixed(exc) from None


async def _scan(namespace, case_id, session_id, approval_id, ctx):
    cancelled, lock, holder = threading.Event(), threading.Lock(), {}
    completed = False

    def cancel():
        cancelled.set()
        with lock:
            use = holder.get('use')
        if use is not None:
            use.cancel()

    try:
        _args(case_id, session_id=session_id, approval_id=approval_id)
        runtime = namespace['rt']()
        def prepare():
            from .cu_owner import get_cu_session
            runtime.case(case_id, hardware=True)
            owner = get_cu_session(case_id, session_id)
            use = owner.reserve_use(cancel=cancelled.is_set)
            with lock:
                holder['use'] = use
                abandoned = cancelled.is_set()
            if abandoned:
                use.cancel()
                raise _error('cancelled')
            return owner, use

        owner, use = await run_blocking_cancellable(prepare, on_cancel=cancel)
        decision = await runtime.authorize(tool='nfc_cu_scan', action=approval_action(owner),
            classification=Classification(Risk.MODIFY, 'cu.ntag-probe', '고정 NFC 선택·GET_VERSION·시작 페이지0·1 읽기'),
            case_id=case_id, approval_id=approval_id, ctx=ctx, summary='CU NTAG 신원 대조와 scan 사실 기록')
        if not decision.allowed:
            return gate_response(decision)

        def work():
            if not use.claim():
                raise _error('cancelled')
            try:
                deadline = time.monotonic() + SCAN_SECONDS
                case = runtime.case(case_id, hardware=True)
                probe = owner.probe_ntag(use, deadline=deadline)
                observation = _observation(probe, session_id)
                result = I.record_cu_scan(runtime, case, observation,
                    deadline=deadline, cancel=use.cancelled).to_dict()
                schemas.validate('nfc-scan', result)
                return result
            finally:
                use.finish()

        result = await run_blocking_cancellable(work, on_cancel=cancel)
        completed = True
        return result
    except Exception as exc:
        raise _fixed(exc) from None
    finally:
        if not completed:
            cancel()


def register_cu_tools(server, namespace):
    """기존 NFC 서버에 고정 CU 세 도구만 더한다. strict metadata는 서버의 공통 등록 단계가 적용한다."""
    @server.tool(description=(
        '명시 USB CDC CU 포트를 전체 장치 범위로 잠근 뒤 MODIFY gate를 거쳐 연결한다. '
        '115200 8N1/DTR=true/RTS=false이며 모델 Ultra·정확2.2/v2.2.0·현재 reader 모드를 고정 조회한다. '
        '모드 변경은 하지 않으며 호환 확인 전 RF 명령을 보내지 않는다. 모델·버전은 자기 보고이며 서명 증명이 아니다. '
        '조회 worker5초, 정리 최대10초이며 미확인 handle/worker/lease는 보존한다. '
        'approval_required이면 사람이 승인 후 같은 인자와 approval_id로 재호출한다.'
    ), annotations=ANN_DEVICE)
    @safe_tool
    async def nfc_cu_connect(case_id: CaseId, port: Annotated[StrictStr, Field(min_length=1, max_length=4096)],
            approval_id: ApprovalId | None = None, ctx: Context | None = None) -> dict:
        return await _connect(namespace, case_id, port, approval_id, ctx)

    @server.tool(description=(
        '정확한 case/session의 CU reader에서 MODIFY gate 뒤 고정14A 선택·GET_VERSION·READ0/1을 수행한다. '
        '45초 안에 NTAG213/215/216·UID7/ATQA/SAK와 두 시작 페이지의 UID/BCC를 내부 대조하고 scan 사실을 남긴다. '
        'READ16B마다 첫4B만 해당 시작 페이지로 사용하며 원시 UID·페이지·version은 반환하지 않는다. '
        'reader CRC 성공 관찰과 host RF CRC 검산을 구분한다. 스캔 전에 펌웨어가 RATS를 보낼 수 있다. '
        '원자적 동일 실물·진품·RF off·장치 명령 종료는 증명하지 않는다. '
        '인증·쓰기·전체 태그 덤프·임의 raw는 없으며 불완전 probe는 scan 사실을 만들지 않는다. '
        'approval_required이면 사람이 승인 후 같은 인자와 approval_id로 재호출한다.'
    ), annotations=ANN_DEVICE)
    @safe_tool
    async def nfc_cu_scan(case_id: CaseId, session_id: SessionId,
            approval_id: ApprovalId | None = None, ctx: Context | None = None) -> dict:
        return await _scan(namespace, case_id, session_id, approval_id, ctx)

    @server.tool(description=(
        '정확한 case/session의 CU worker를 취소하고 물리 transport 종료 및 사용권0 뒤 lease를 해제한다. '
        '허가 철회 뒤에도 정리 가능하며 최대10초의 정리 미확인은 세션·잠금을 보존한다. '
        '추가 RF-off·mode 변경 명령은 보내지 않고 RF off나 장치 명령 종료를 검증했다고 하지 않는다.'
    ), annotations=ANN_LOCAL_WRITE)
    @safe_tool
    async def nfc_cu_disconnect(case_id: CaseId, session_id: SessionId) -> dict:
        try:
            _args(case_id, session_id=session_id)
            from .cu_owner import close_cu_session
            with anyio.CancelScope(shield=True):
                result = await run_blocking(lambda: close_cu_session(case_id, session_id,
                                            deadline=time.monotonic() + CLOSE_SECONDS))
            data = _close_projection(result)
            return {'ok': data['cleanup_confirmed'], 'case_id': case_id, 'session_id': session_id, **data}
        except Exception as exc:
            raise _fixed(exc) from None

    namespace.update(nfc_cu_connect=nfc_cu_connect, nfc_cu_scan=nfc_cu_scan,
                     nfc_cu_disconnect=nfc_cu_disconnect)
