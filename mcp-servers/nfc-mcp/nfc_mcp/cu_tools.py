"""CU 고정 reader 연결·NTAG probe·HF 식별·상태 조회·정리의 MCP 입구."""
from __future__ import annotations

import re
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
IDENTIFY_SECONDS = 45
STATUS_SECONDS = 5
CLOSE_SECONDS = 10
_CODES = frozenset((
    'cu_protocol_invalid', 'cu_model_unsupported', 'cu_firmware_unsupported',
    'cu_reader_required', 'cu_identity_unknown', 'cu_cleanup_unknown',
    'nfc_input_invalid', 'nfc_input_limit', 'nfc_scan_invalid', 'nfc_family_unsupported',
    'nfc_identity_mismatch', 'nfc_provenance_invalid', 'nfc_failed',
    'nfc_snapshot_invalid', 'nfc_source_mismatch', 'nfc_artifact_registration_failed',
    'nfc_scan_required', 'nfc_input_changed', 'nfc_cleanup_pending',
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
            'nfc_profile': CU.LIVE.profile, 'nfc_profile_sha256': CU.LIVE.profile_sha256,
            'read_requests': 2, 'pages_retained': 2}


def identify_approval_action(owner):
    """HF 식별의 정확 세션과 고정 식별 recipe만 승인 지문에 추가한다. 페이지 READ·인증은 0이다."""
    return {**owner.action, 'operation': 'hf_identify', 'session_id': owner.session_id,
            'identify_profile': CU.IDENTIFY.profile, 'identify_profile_sha256': CU.IDENTIFY.profile_sha256,
            'version_requests_max': 1, 'page_reads': 0, 'authentication': False}


def status_action(owner):
    """상태 조회의 정확 세션과 고정 getter 목록. INTERACT 감사 기록에 남는다."""
    return {**owner.action, 'operation': 'device_status', 'session_id': owner.session_id,
            'status_queries': [CU.CuQuery.DEVICE_MODE.value, *(query.value for query in CU.STATUS_QUERIES)]}


def _identify_digest(runtime, case_id, family, scan, version):
    """계열별 domain 분리 케이스 솔트 지문. 원시 UID·ATQA·SAK·version은 결과에 넣지 않는다."""
    if scan.uid is None:
        return None
    raw = version.version if version is not None and version.version is not None else b''
    value = (CU.HF_DIGEST_DOMAIN + b'\0' + family.encode('ascii') + b'\0' + bytes((len(scan.uid),))
             + scan.uid + scan.atqa_msb + bytes((scan.sak,)) + bytes((len(raw),)) + raw)
    digest = runtime.secret_digest(case_id, value)
    if type(digest) is not str or re.fullmatch(r'sha256:[0-9a-f]{16}', digest) is None:
        raise _error('nfc_scan_invalid')
    return digest


def _identify_projection(runtime, case_id, session_id, result):
    """닫힌 분류만 공개한다. 판정 근거 원문과 내부 객체는 반환하지 않는다."""
    from .cu_owner import CuIdentify
    if (type(result) is not CuIdentify or result.session_id != session_id
            or result.profile != CU.IDENTIFY.profile or type(result.scan) is not CU.CuHfScan
            or type(result.get_version_sent) is not bool or type(result.family) is not str
            or result.family not in CU.HF_FAMILIES
            or result.get_version_sent != (result.scan.scan_class == 'type2')):
        raise _error('nfc_scan_invalid')
    scan, version = result.scan, result.version
    if result.get_version_sent:
        if type(version) is not CU.CuHfVersion or version.family != result.family:
            raise _error('nfc_scan_invalid')
    elif version is not None or result.family != scan.scan_class:
        raise _error('nfc_scan_invalid')
    return {'ok': True, 'case_id': case_id, 'session_id': session_id, 'profile': CU.IDENTIFY.profile,
            'family': result.family, 'policy': CU.HF_POLICIES[result.family],
            'uid_length': None if scan.uid is None else len(scan.uid),
            'ats_present': None if scan.ats_length is None else scan.ats_length > 0,
            'get_version_sent': result.get_version_sent, 'page_reads_sent': False,
            'authentication_attempted': False,
            'identity_digest': _identify_digest(runtime, case_id, result.family, scan, version),
            'physical_same_tag_verified': False, 'rf_off_verified': False}


def _status_projection(case_id, session_id, result):
    from .cu_owner import CuStatus
    if (type(result) is not CuStatus or result.session_id != session_id
            or type(result.status) is not CU.CuDeviceStatus or type(result.device) is not CU.CuDevice):
        raise _error('cu_protocol_invalid')
    status, device = result.status, result.device
    return {'ok': True, 'case_id': case_id, 'session_id': session_id,
            'battery_mv': status.battery_mv, 'battery_percent': status.battery_percent,
            'battery_percent_is_estimate': True, 'active_slot': status.active_slot, 'mode': 'reader',
            'hf14a_config_default': status.hf14a_config_default, 'app_version': device.app_version,
            'git_version': device.git_version, 'model': device.model}


async def _session_tool(namespace, case_id, session_id, approval_id, ctx, *, tool, action,
                        classification, summary, run):
    """ready 세션 하나의 사용권 예약→gate→claim worker 실행. scan과 같은 취소·정리 규칙이다."""
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
        decision = await runtime.authorize(tool=tool, action=action(owner), classification=classification,
            case_id=case_id, approval_id=approval_id, ctx=ctx, summary=summary)
        if not decision.allowed:
            return gate_response(decision)

        def work():
            if not use.claim():
                raise _error('cancelled')
            try:
                runtime.case(case_id, hardware=True)
                return run(runtime, owner, use)
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


async def _identify(namespace, case_id, session_id, approval_id, ctx):
    def run(runtime, owner, use):
        result = owner.identify_hf(use, deadline=time.monotonic() + IDENTIFY_SECONDS)
        return _identify_projection(runtime, case_id, session_id, result)

    return await _session_tool(namespace, case_id, session_id, approval_id, ctx, tool='nfc_cu_identify',
        action=identify_approval_action,
        classification=Classification(Risk.MODIFY, 'cu.hf-identify',
                                      '고정14A scan과 Type 2 후보의 단독 GET_VERSION 한 번(READ·인증 없음)'),
        summary='CU HF 카드 계열 식별(페이지 읽기 없음)', run=run)


async def _status(namespace, case_id, session_id, ctx):
    def run(runtime, owner, use):
        result = owner.device_status(use, deadline=time.monotonic() + STATUS_SECONDS)
        return _status_projection(case_id, session_id, result)

    return await _session_tool(namespace, case_id, session_id, None, ctx, tool='nfc_cu_status',
        action=status_action,
        classification=Classification(Risk.INTERACT, 'cu.status',
                                      'RF·설정 변경 없는 고정 getter(1002/1025/1018/2200) 조회'),
        summary='CU 배터리·활성 slot·HF14A 설정 조회', run=run)


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
                        or device.app_version != CU.LIVE.app_version or device.git_version != CU.LIVE.git_version
                        or device.reader_mode is not True):
                    raise _error('cu_protocol_invalid')
                return {'ok': True, 'case_id': case_id, 'session_id': owner.session_id,
                    'profile': CU.LIVE.profile, 'state': 'ready',
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
                # schema는 검증용 두 이름을 모두 받으므로 새 scan은 live 이름인지 따로 확인한다.
                if result.get('profile') != CU.LIVE.profile:
                    raise _error('nfc_scan_invalid')
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
    """기존 NFC 서버에 고정 CU 다섯 도구만 더한다. strict metadata는 서버의 공통 등록 단계가 적용한다."""
    @server.tool(description=(
        '명시 USB CDC CU 포트를 전체 장치 범위로 잠근 뒤 MODIFY gate를 거쳐 연결한다. '
        '115200 8N1/DTR=true/RTS=false이며 모델 Ultra·APP2.3·GIT 정확 v2.3.0·현재 reader 모드를 고정 조회한다. '
        'v2.2.0과 v2.3.0 이후 dev build는 cu_firmware_unsupported다. '
        '모드 변경은 하지 않으며 호환 확인 전 RF 명령을 보내지 않는다. 모델·버전은 자기 보고이며 서명 증명이 아니다. '
        '조회 worker5초, 정리 최대10초이며 미확인 handle/worker/lease는 보존한다. '
        'approval_required이면 사람이 승인 후 같은 인자와 approval_id로 재호출한다.'
    ), annotations=ANN_DEVICE)
    @safe_tool
    async def nfc_cu_connect(case_id: CaseId, port: Annotated[StrictStr, Field(min_length=1, max_length=4096)],
            approval_id: ApprovalId | None = None, ctx: Context | None = None) -> dict:
        return await _connect(namespace, case_id, port, approval_id, ctx)

    @server.tool(description=(
        '정확한 case/session의 CU reader에서 MODIFY gate 뒤 고정14A 선택·단독 GET_VERSION(field 해제)·새 선택 READ0/1을 수행한다. '
        'NTAG213/215/216이 아닌 version 응답은 READ 없이 nfc_family_unsupported로 끝난다. '
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
        '정확한 case/session의 ready CU reader에서 MODIFY gate 뒤 mode 확인과 고정14A scan을 한 번 보내고, '
        'UID7/ATQA0044/SAK00/ATS0인 Type 2 후보에만 단독 GET_VERSION(f4, keep=0) 하나를 더 보내 닫힌 표로 계열을 분류한다. '
        'READ(0x30)·인증·RATS 직접 송신·모드 변경은 없으며 Ultralight와 Ultralight C를 READ로 나누지 않는다. '
        '결과는 family·§6.2 policy·UID 길이·ATS 유무·계열별 케이스 솔트 지문이며 원시 UID/ATQA/SAK/version과 scan 사실·inventory는 만들지 않는다. '
        '잘 형성된 분류(none·multiple 포함)는 세션을 ready로 두고 잘못된 응답·transport timeout·취소는 terminal이다. '
        'scan 중 firmware가 SAK bit0x20 태그에 RATS를 보낼 수 있고 RF off·동일 실물은 검증하지 않는다. '
        '교통·결제·출입 자격증명은 policy와 관계없이 범위 밖이다. '
        'approval_required이면 사람이 승인 후 같은 인자와 approval_id로 재호출한다.'
    ), annotations=ANN_DEVICE)
    @safe_tool
    async def nfc_cu_identify(case_id: CaseId, session_id: SessionId,
            approval_id: ApprovalId | None = None, ctx: Context | None = None) -> dict:
        return await _identify(namespace, case_id, session_id, approval_id, ctx)

    @server.tool(description=(
        '정확한 case/session의 ready CU에 RF 없이 mode(1002)·배터리(1025)·활성 slot(1018)·HF14A 설정(2200) getter만 보내고 '
        '연결 때 확인한 모델·APP·GIT을 함께 반환한다. 상태를 바꾸지 않는 INTERACT로 gate 감사 기록을 남긴다. '
        'battery_percent는 전압 곡선 추정이며 부팅 직후 약5초는 mV·percent가 0일 수 있다. active_slot은 0부터 센다. '
        'hf14a_config_default는 2200의 네 값(forcebcc/cl2/cl3/rats)이 모두0인지다. '
        'BLE PIN·장치 식별자·slot 별명·emulator 상태 조회와 설정 변경 명령은 보내지 않는다. 성공하면 세션은 ready로 남는다.'
    ), annotations=ANN_DEVICE)
    @safe_tool
    async def nfc_cu_status(case_id: CaseId, session_id: SessionId, ctx: Context | None = None) -> dict:
        return await _status(namespace, case_id, session_id, ctx)

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
                def cancel_jobs():
                    runtime = namespace['rt']()
                    for job in runtime.jobs.list(active_only=True):
                        if (job.get('kind') == 'nfc-cu-read' and job.get('case_id') == case_id
                                and type(job.get('meta')) is dict
                                and job['meta'].get('session_id') == session_id):
                            runtime.jobs.cancel(job['job_id'])
                await run_blocking(cancel_jobs)
                result = await run_blocking(lambda: close_cu_session(case_id, session_id,
                                            deadline=time.monotonic() + CLOSE_SECONDS))
            data = _close_projection(result)
            return {'ok': data['cleanup_confirmed'], 'case_id': case_id, 'session_id': session_id, **data}
        except Exception as exc:
            raise _fixed(exc) from None

    namespace.update(nfc_cu_connect=nfc_cu_connect, nfc_cu_scan=nfc_cu_scan,
                     nfc_cu_identify=nfc_cu_identify, nfc_cu_status=nfc_cu_status,
                     nfc_cu_disconnect=nfc_cu_disconnect)
