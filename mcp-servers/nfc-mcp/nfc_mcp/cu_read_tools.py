"""고정 CU 읽기 작업(NTAG21x·Ultralight 계열)의 승인·예약 인계 입구."""
from __future__ import annotations

import re
import threading
import time
from typing import Annotated

from pydantic import Field, StrictStr

from pweh.mcpkit import ANN_DEVICE, Context, gate_response, run_blocking_cancellable, safe_tool
from pweh.safety import Classification, Risk, attestation_response
from .cu_tools import ApprovalId, CaseId, SessionId, _args, _fixed

# NT-는 NTAG inventory(기존 흐름 그대로), UT-는 Ultralight inventory(tag-ownership 증명 재확인 뒤 UL 읽기)다.
TagRef = Annotated[StrictStr, Field(pattern=r'^(NT|UT)-[0-9a-f]{32}$', max_length=35)]
UL_PREPARE_SECONDS = 5


def register_cu_read_tools(server, namespace):
    """공통 NFC metadata를 재사용할 단일 고정 읽기 도구를 등록한다."""
    @server.tool(description=(
        '같은 케이스의 ready CU session_id와 현재 tag_ref에 결속해 저장 페이지 읽기 job을 시작한다. '
        'NT- tag_ref는 NTAG213/215/216이다. '
        '고정 Ultra v2.3.0 reader만 사용하며 페이지 범위·임의 명령·인증·쓰기는 받지 않는다. '
        '단독 GET_VERSION 뒤 READ0부터 새 선택으로 읽으며 읽기 중 실패는 field를 남길 수 있다. '
        'wire45초와 별도 host 게시5초 안에 검증한 prefix를 nfc/cu-read-NNN.json에 저장한다. '
        'time_limit/nfc_scan_invalid만 부분 읽기를 보존하며 원장 기록 뒤 artifact 등록 실패는 '
        'registered=false인 실제 partial_result로 남긴다. raw UID·페이지는 job 응답에 넣지 않는다. '
        'nfc_job_status로 완료를 확인하고 등록 artifact_id를 같은 inventory의 nfc_parse_file/nfc_diff_dumps에 사용한다. '
        'UT- tag_ref(nfc_cu_ul_scan→nfc_tag_inventory_add의 Ultralight 계열, 사용자 소유 또는 소유자 서면 허가 태그)는 '
        'CU 사용권을 예약하기 전에 tag-ownership 사람 증명을 다시 확인하고 없으면 frame·예약 없이 바로 attestation_required를 '
        '돌려준다(사람이 pweh attest <id> 후 같은 인자로 재호출, denied면 멈춤). 증명이 있으면 MODIFY gate 뒤 mode·scan·'
        'GET_VERSION으로 같은 태그·계열을 확인하고 page마다 f4 단독 activation READ(0x30)를 0부터 계열의 마지막 대상까지 보낸다. '
        'PWD/PACK·UL C 키 페이지는 요청하지 않고 null(보류)로 두며 인증·쓰기·READ_SIG/READ_CNT/FAST_READ·keep=1은 없다. '
        'page0 UID/BCC와 앞 응답과의 겹침을 대조하고, NAK는 정상 끝(roll-over 근거가 있으면 완료, 없으면 tag_nak 부분)이며 '
        '세션을 ready로 둔다. 3페이지 이상 검증한 time_limit/nfc_scan_invalid만 부분 snapshot으로 보존한다. '
        '결과는 nfc/cu-ul-read-NNN.json(증명 id와 함께 device-read 원장 기록)이며 job 응답에 원시 UID·페이지는 없다. '
        '사용한 교통 승차권 같은 자격증명도 사용자 소유면 읽기 전용으로만 다룬다(복제·에뮬레이션·인증 없음).'
    ), annotations=ANN_DEVICE)
    @safe_tool
    async def nfc_cu_read_start(case_id: CaseId, session_id: SessionId, tag_ref: TagRef,
                                approval_id: ApprovalId | None = None, ctx: Context = None) -> dict:
        cancel_event = threading.Event()
        lock = threading.Lock()
        holder = {}

        def cancel():
            cancel_event.set()
            with lock:
                work = holder.get('work')
            if work is not None:
                work.cancel()

        try:
            _args(case_id, session_id=session_id, approval_id=approval_id)
            if type(tag_ref) is str and re.fullmatch(r'UT-[0-9a-f]{32}', tag_ref) is not None:
                return await _ul_read_start(namespace, case_id, session_id, tag_ref, approval_id, ctx,
                                            cancel_event, lock, holder, cancel)
            if type(tag_ref) is not str or re.fullmatch(r'NT-[0-9a-f]{32}', tag_ref) is None:
                from .analysis import _error
                raise _error('nfc_input_invalid')
            runtime = namespace['rt']()

            def prepare():
                from pweh.nfc_inventory import resolve_inventory
                from .cu_owner import get_cu_session
                from .cu_read import prepare_cu_read
                end = time.monotonic() + 5
                case = runtime.case(case_id, hardware=True)
                owner = get_cu_session(case_id, session_id)
                bound = resolve_inventory(runtime, case, tag_ref, deadline=end, cancel=cancel_event.is_set)
                work = prepare_cu_read(runtime, case, owner, bound, cancel_event=cancel_event)
                with lock:
                    holder['work'] = work
                    stopped = cancel_event.is_set()
                if stopped:
                    work.cancel()
                return work

            work = await run_blocking_cancellable(prepare, on_cancel=cancel)
            decision = await runtime.authorize(tool='nfc_cu_read_start', action=work.action,
                classification=Classification(Risk.MODIFY, 'cu.ntag-read', 'CU NTAG 페이지 읽기'),
                case_id=case_id, approval_id=approval_id, ctx=ctx)
            if not decision.allowed:
                cancel()
                return gate_response(decision)
            job = await run_blocking_cancellable(work.start, on_cancel=cancel)
            return {'ok': True, 'job_id': job.id, 'status': job.status}
        except BaseException as exc:
            cancel()
            if isinstance(exc, Exception):
                raise _fixed(exc) from None
            raise

    namespace['nfc_cu_read_start'] = nfc_cu_read_start


async def _ul_read_start(namespace, case_id, session_id, tag_ref, approval_id, ctx, cancel_event, lock, holder, cancel):
    """UT-: 결속 풀이(예약 없음)→ctx 없는 소유 증명 확인(대기 없음)→재풀이·같은 id 동기 확인·사용권 예약→gate→job 시작."""
    from pweh import nfc_ul_inventory as UL
    runtime = namespace['rt']()

    def resolve():
        from .cu_owner import get_cu_session
        case = runtime.case(case_id, hardware=True)
        get_cu_session(case_id, session_id)
        return UL.resolve_ul_inventory(runtime, case, tag_ref, deadline=time.monotonic() + UL_PREPARE_SECONDS,
                                       cancel=cancel_event.is_set)

    bound = await run_blocking_cancellable(resolve, on_cancel=cancel)
    # 여기까지 CU 사용권은 없다. 사람 증명은 즉시 결과만 돌려주며 기다리지 않는다.
    attestation = await UL.ul_attest(runtime, case_id, bound.family, bound.ul_identity_digest,
                                     tool='nfc_cu_read_start')
    if not attestation.satisfied:
        return attestation_response(attestation, tag_ref=tag_ref, family=bound.family,
                                    ul_identity_digest=bound.ul_identity_digest, page_reads_sent=False,
                                    job_started=False)

    def prepare():
        from .cu_owner import get_cu_session
        from .cu_read import prepare_ul_read
        case = runtime.case(case_id, hardware=True)
        owner = get_cu_session(case_id, session_id)
        work = prepare_ul_read(runtime, case, owner, bound, attestation.attestation_id, cancel_event=cancel_event,
                               deadline=time.monotonic() + UL_PREPARE_SECONDS)
        with lock:
            holder['work'] = work
            stopped = cancel_event.is_set()
        if stopped:
            work.cancel()
        return work

    work = await run_blocking_cancellable(prepare, on_cancel=cancel)
    decision = await runtime.authorize(tool='nfc_cu_read_start', action=work.action,
        classification=Classification(Risk.MODIFY, 'cu.ul-read',
            'CU Ultralight 계열 공개 페이지 읽기(페이지마다 f4 단독 activation, 인증·쓰기 없음)'),
        case_id=case_id, approval_id=approval_id, ctx=ctx,
        summary='CU Ultralight 계열 페이지 읽기(소유 증명 태그, 읽기 전용)')
    if not decision.allowed:
        cancel()
        return gate_response(decision)
    job = await run_blocking_cancellable(work.start, on_cancel=cancel)
    return {'ok': True, 'job_id': job.id, 'status': job.status}
