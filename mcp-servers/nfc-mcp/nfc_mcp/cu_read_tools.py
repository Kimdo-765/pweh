"""고정 CU 읽기 작업의 승인·예약 인계 입구."""
from __future__ import annotations

import re
import threading
import time
from typing import Annotated

from pydantic import Field, StrictStr

from pweh.mcpkit import ANN_DEVICE, Context, gate_response, run_blocking_cancellable, safe_tool
from pweh.safety import Classification, Risk
from .cu_tools import ApprovalId, CaseId, SessionId, _args, _fixed

TagRef = Annotated[StrictStr, Field(pattern=r'^NT-[0-9a-f]{32}$', max_length=35)]


def register_cu_read_tools(server, namespace):
    """공통 NFC metadata를 재사용할 단일 고정 읽기 도구를 등록한다."""
    @server.tool(description=(
        '같은 케이스의 ready CU session_id와 현재 tag_ref에 결속해 NTAG213/215/216 저장 페이지 읽기 job을 시작한다. '
        '고정 Ultra2.2 reader만 사용하며 페이지 범위·임의 명령·인증·쓰기는 받지 않는다. '
        'wire45초와 별도 host 게시5초 안에 검증한 prefix를 nfc/cu-read-NNN.json에 저장한다. '
        'time_limit/nfc_scan_invalid만 부분 읽기를 보존하며 원장 기록 뒤 artifact 등록 실패는 '
        'registered=false인 실제 partial_result로 남긴다. raw UID·페이지는 job 응답에 넣지 않는다. '
        'nfc_job_status로 완료를 확인하고 등록 artifact_id를 같은 inventory의 nfc_parse_file/nfc_diff_dumps에 사용한다.'
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
