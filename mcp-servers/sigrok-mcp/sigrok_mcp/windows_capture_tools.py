"""Windows 유한 OLS 캡처의 공통 동기/job 소비자. 실제 argv/출력은 고정 owner만 만든다."""
from __future__ import annotations

import math
import os
import time
from dataclasses import dataclass
from typing import Any

from pweh import ports
from pweh.errors import PwehError
from pweh.safety import Risk
from . import windows_com_tools as com
from . import windows_info as info
from .cli import stderr_problems
from .windows_capture_publish import CapturePublisher, error, public_error

WORKER_SECONDS=420.0


@dataclass(frozen=True)
class WindowsCapturePlan:
    case: Any
    command: Any
    output_name: str | None
    timeout_s: float
    expected_s: float
    bundle: Any
    classification: Any
    action: dict
    runtime: Any
    use: Any


def _reserve(bundle,command,**kw):
    from .windows_capture import reserve_capture_owner
    return reserve_capture_owner(bundle,command,**kw)


def _seconds(value):
    if value is None:
        return 60.0
    try:
        if type(value) not in (int,float): raise ValueError
        value=float(value)
        if not math.isfinite(value) or not 0<value<=300: raise ValueError
    except (ValueError,OverflowError):
        raise error('invalid') from None
    return value


def _request(driver,conn,samplerate,samples,channels,duration_ms,triggers,capture_ratio,output_name,background):
    from pweh.sigrok_capture import CaptureCommand, PROFILE_ID, normalize_channels
    from . import server as S
    if (driver!='ols' or type(conn) is not str or ports.parse_win_com(conn) is None
            or conn.lower()!=f'com{ports.parse_win_com(conn)}'
            or duration_ms is not None or triggers is not None or capture_ratio is not None
            or (background is not None and type(background) is not bool)):
        raise error('invalid')
    for value in (samplerate,samples):
        if type(value) not in (str,int) or (isinstance(value,str) and len(value)>64):
            raise error('invalid')
    if output_name is not None and (type(output_name) is not str or len(output_name)>64):
        raise error('invalid')
    try:
        rate=S.parse_samplerate(samplerate)
        count=S.validate_samples(samples)
        command=CaptureCommand(PROFILE_ID,f'COM{ports.parse_win_com(conn)}',rate,count,normalize_channels(channels))
        name=S.validate_output_name(output_name)
        return command,name
    except Exception as exc:
        raise public_error(exc) from None


def _base_classification(plan_command,policy):
    # 승인 전 logical 출력은 사용자 경로가 아니며 실제 투영은 owner의 고정 타입만 만든다.
    from pathlib import Path
    from . import server as S
    logical=Path('/pweh-capture-output')
    tail=list(plan_command.argv_tail('C:\\PWEH_CAPTURE\\capture.sr'))
    tail[-1]='--output-file='+str(logical/'capture.sr')
    return S.classify_sigrok_argv(['sigrok-cli',*tail],policy=policy,allowed_output_dir=logical)


def _worker(plan, *, cancel, job_context=None):
    from . import server as S
    use=plan.use
    if not use.handoff.claim_worker():
        return {'ok':False,'status':'cancelled'}
    owner=publisher=None
    failure=None
    publication=None
    end=time.monotonic()+WORKER_SECONDS
    metadata=info._metadata(plan.bundle)
    try:
        if cancel():
            return {'ok':False,'status':'cancelled'}
        owner=_reserve(plan.bundle,plan.command,deadline=end)
        use.cleanup_owner=owner; use.unverified=True
        owner.prepare(info._runtime_parent(plan.runtime.config),ambient_env=tuple(os.environ.items()),deadline=end,cancel=cancel)
        def fresh():
            S.guard_target_port(plan.runtime,plan.command.conn,consumer='sigrok',driver='ols',phase='pre-process')
            use.fresh()
            cls=_base_classification(plan.command,S._policy())
            if cls.risk>=Risk.MODIFY:
                raise error('invalid')
            action=dict(plan.action)
            cls=S._capture_classification(use,action,cls)
            action['profile']=plan.command.approval_identity()
            if action!=plan.action or (cls.risk,cls.rule_id)!=(plan.classification.risk,plan.classification.rule_id):
                raise error('check_failed')
            use.lease.set_state('running')
        exit=owner.run(before_spawn=fresh,deadline=end,cancel=cancel,timeout_s=plan.timeout_s)
        if not owner.processes_quiescent:
            raise error('cleanup_unknown')
        if exit.output_limit:
            raise error('output_limit')
        rep=stderr_problems(exit.stderr)
        cli_failed=bool(rep.fatal) or (exit.returncode!=0 and not(exit.cancelled or exit.timed_out))
        publisher=CapturePublisher(plan.case,plan.command,output_name=plan.output_name,bundle_meta=metadata,
                                   job_context=job_context,cli_failed=cli_failed)
        # pending 게시 기록도 use와 함께 보관해 종료한 awaiter가 소유권을 잃지 않게 한다.
        use.capture_publication=publisher
        publication=owner.finalize_output(publisher,deadline=min(end,exit.post_deadline),cancel=cancel)
        if publication.disposition!='published':
            failure=error('failed' if cli_failed else 'cancelled' if exit.cancelled else 'timeout' if exit.timed_out
                          else 'empty_capture' if publication.reason=='empty_capture' else 'bad_zip' if publication.reason=='bad_zip' else 'no_output')
    except Exception as exc:
        if owner is None:
            owner=getattr(exc,'owner',None)
            if owner is not None:
                use.cleanup_owner=owner; use.unverified=True
        failure=public_error(exc)
    finally:
        if owner is not None:
            try: confirmed=owner.close(deadline=time.monotonic()+10).confirmed is True
            except Exception: confirmed=False
            use.unverified=not confirmed
            if not confirmed:
                failure=error('cleanup_unknown')
        use.finish()
    saved=publisher.result if publisher is not None else None
    if saved is not None:
        saved=dict(saved)
        saved['cleanup_pending']=use.unverified
        saved['route']=use.route.to_dict()
        saved['classification']=plan.classification.to_dict()
        if failure is not None:
            saved.update(ok=False,status='failed',error=failure.to_dict())
        if job_context is not None:
            job_context.set_partial(saved)
        return saved
    if failure is not None:
        raise failure from None
    raise error('no_output')


async def capture(*,case_id,driver,samplerate,duration_ms,samples,channels,triggers,output_name,conn,
                  capture_ratio,background,timeout_s,approval_id=None,ctx=None):
    from . import server as S
    timeout=_seconds(timeout_s)
    # 금지 driver는 기존 hard policy 판정을 먼저 보존한다.
    r=S.rt(); case=r.case(case_id,hardware=True)
    if driver!='ols':
        cls=S.classify_sigrok_argv(['sigrok-cli',f'--driver={driver}','--scan'],policy=S._policy())
        if cls.risk>=Risk.MODIFY:
            return S._policy_denied('sigrok_capture',{'driver':driver,'backend':'windows'},cls,case.id)
        raise error('invalid')
    command,name=_request(driver,conn,samplerate,samples,channels,duration_ms,triggers,capture_ratio,output_name,background)
    await S._offload(S.guard_target_port,r,command.conn,consumer='sigrok',driver='ols')
    use=await S._acquire_port_use(S._serial_use,case.id,command.conn,'windows')
    try:
        bundle=await S._run_cancellable(com._bundle,r.config)
        cls=_base_classification(command,S._policy())
        action={'backend':'windows','driver':'ols','conn':command.conn,'output_name':name,
                'profile':command.approval_identity(),
                'bundle':{'release_id':bundle.release_id,'manifest_sha256':bundle.manifest_sha256}}
        if cls.risk>=Risk.MODIFY:
            return S._policy_denied('sigrok_capture',action,cls,case.id)
        cls=S._capture_classification(use,action,cls)
        decision=await r.authorize(tool='sigrok_capture',action=action,classification=cls,case_id=case.id,
                                   approval_id=approval_id,ctx=ctx)
        if not decision.allowed:
            return S.gate_response(decision)
        expected=command.samples/command.samplerate_hz
        plan=WindowsCapturePlan(case,command,name,timeout,expected,bundle,cls,action,r,use)
        if background is True or (background is None and expected>S.SYNC_CAPTURE_LIMIT_S):
            def job_fn(jctx):
                jctx.log('Windows OLS 유한 캡처를 시작합니다.')
                try:
                    result=_worker(plan,cancel=lambda:jctx.cancelled,job_context=jctx)
                except PwehError as exc:
                    if exc.code=='sigrok_capture_cancelled' and jctx.cancelled:
                        from pweh.jobs import JobCancelled
                        raise JobCancelled() from None
                    raise
                if result.get('status') in ('timeout','failed'):
                    err=result.get('error') or {'code':'sigrok_capture_timeout'}
                    raise error(err['code'],data={'result':result})
                return result
            job=r.jobs.start('sigrok-capture',job_fn,description='Windows OLS 유한 캡처',case_id=case.id,
                meta={'backend':'windows','requested':command.approval_identity(),'bundle':info._metadata(bundle),
                      'route':use.route.to_dict(),'port_keys':list(use.keys)},
                exclusive_key=S._device_key('ols',command.conn))
            use.accepted=True
            return {'ok':True,'status':'started','backend':'windows','job_id':job.id,
                    'requested':command.approval_identity(),'expected_duration_s':expected,'timeout_s':timeout,
                    'classification':cls.to_dict(),'route':use.route.to_dict()}
        def worker(cancel_event):
            return _worker(plan,cancel=cancel_event.is_set)
        return await S._run_cancellable(worker)
    finally:
        if not use.accepted and use.handoff.abandon_caller():
            use.finish()
