"""고정 Tigard 시작·전체 USB lease·승인 뒤 신원 재확인. 임의 타깃은 만들지 않는다."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import math
import os
import threading
import time

from anyio import CancelScope
from pweh import instrument_guard, portlock, windows_bundle
from pweh.errors import DeviceError, PwehError, TimeoutExpired, ValidationFailed
from pweh.mcpkit import gate_response, run_blocking, run_blocking_cancellable
from pweh.safety import Classification, Risk
from . import parsers, process_windows as PW, semihosting, windows_plan as WP, windows_start as W, windows_usb
from .session import OcdSession, REGISTRY
from .tigard_profile import TIGARD_PROFILE, validate_tigard_start


def scope_fields(scope) -> dict:
    """실행 UUID와 무관한 승인 지문. 전체 graph 원문은 응답에 넣지 않는다."""
    fingerprint = hashlib.sha256(json.dumps(asdict(scope), sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'usb_scope_sha256': fingerprint, 'usb_parent': scope.usb_parent,
            'usb_vid': scope.vid, 'usb_pid': scope.pid, 'whole_device': True,
            'claim_keys': list(scope.claim_keys), 'descriptor_serial_verified': False}


def fresh(sess, *, deadline, cancel, phase):
    """최초 범위를 바꾸거나 잠금을 추가하지 않고 현재 관찰과 보유권을 대조한다."""
    scope = windows_usb.revalidate_tigard_scope(sess.windows_scope, TIGARD_PROFILE, sess.windows_runtime.config,
                                               deadline=deadline, cancel=cancel)
    sess.windows_lease.assert_held(scope.claim_keys)
    portlock.get_role_store().assert_usb_scope_allowed(scope)
    instrument_guard.guard_target_usb_scope(sess.windows_runtime, scope, consumer='openocd', phase=phase)


async def _stage(sess, function):
    """awaiter 취소와 실제 worker 완료를 분리하고 늦은 완료까지 세션이 자원을 소유한다."""
    sess.reserve_use(startup=True)
    handoff = portlock.LeaseHandoff()
    lock = threading.Lock()
    state = {'finished': False, 'abandoned': False, 'cleanup_claimed': False}
    success = False

    def worker():
        if not handoff.claim_worker():
            raise DeviceError('Windows 시작이 취소되었습니다.', code='cancelled')
        try:
            if sess.cancel_start.is_set():
                raise DeviceError('Windows 시작이 취소되었습니다.', code='cancelled')
            return function()
        finally:
            sess.finish_use()
            with lock:
                state['finished'] = True
                cleanup = state['abandoned'] and not state['cleanup_claimed']
                if cleanup:
                    state['cleanup_claimed'] = True
            if cleanup:
                W.close_session(sess)
    try:
        result = await run_blocking_cancellable(worker, on_cancel=sess.cancel_start.set)
        success = True
        return result
    finally:
        if not success:
            sess.cancel_start.set()
            pending = handoff.abandon_caller()
            if pending:
                sess.finish_use()
            with lock:
                state['abandoned'] = True
                cleanup = (pending or state['finished']) and not state['cleanup_claimed']
                if cleanup:
                    state['cleanup_claimed'] = True
            if cleanup:
                with CancelScope(shield=True):
                    await run_blocking(W.close_session, sess)


def _verify_start(sess, *, deadline):
    """이미 예약된 시작 worker의 같은 pipe로 가드 단계와 target0 계약을 확인한다."""
    required = (*semihosting.STARTUP_PHASES, 'verify')
    remaining = deadline - time.monotonic()
    if sess.cancel_start.is_set():
        raise DeviceError('Windows 시작이 취소되었습니다.', code='cancelled')
    if remaining <= 0:
        raise TimeoutExpired('Windows 가드 확인 준비 시간이 초과되었습니다.')
    reply = sess.client.call(semihosting.VERIFY_CALL, timeout=remaining, cancel_check=sess.cancel_start.is_set)
    report = semihosting.parse_report(reply.output if reply.ok else '', required=required, startup_only=False)
    problems = semihosting.verification_problems(report, required)
    if not reply.ok or problems or report['targets']:
        raise DeviceError('고정 Tigard의 semihosting 가드 또는 target0 계약을 확인하지 못했습니다.',
                          code='openocd_tigard_guard_failed')
    sess.semihosting_managed = True
    sess.semihost_procs = frozenset(report['procs'])
    sess.semihosting = {**report, 'mode': 'fixed-adapter-init', 'hardware_initialized': True,
                        'verification_performed': True, 'target_configured': False,
                        'target_communication_verified': False}
    sess.hardware_initialized = True
    text = sess.run_log()
    summary = parsers.parse_log_summary(text)
    diagnosis = parsers.diagnose(text)
    health = 'degraded' if summary['errors'] or any(d.get('code') in
        {'jtag_all_ones', 'jtag_all_zeroes', 'examine_failed', 'ir_capture_error'} for d in diagnosis) else 'ok'
    sess.startup = {'summary': summary, 'diagnosis': diagnosis, 'health': health,
                    'semihosting': dict(sess.semihosting)}
    return summary, diagnosis, health


async def start(r, case, *, ctx, approval_id, ready_timeout, **args):
    """전체 USB 잠금을 승인 대기부터 물리 종료 및 run 정리까지 유지한다."""
    from . import server as S
    profile = validate_tigard_start(**args)
    if (type(ready_timeout) not in (int, float) or abs(ready_timeout) > 30
            or not math.isfinite(ready_timeout) or ready_timeout <= 0):
        raise ValidationFailed('Windows 준비 제한은 0초 초과 30초 이하의 유한 수여야 합니다.')
    sess = OcdSession(case.id, 'spawned', None, None, None, transport='windows-pipe',
                      windows_profile=profile.profile_id, windows_runtime=r, starting=True)
    REGISTRY.add(sess)
    success = False

    def preflight():
        end = time.monotonic() + 30
        W._check_environment(r.config)
        bundle = W._resolve_bundle(r.config, end)
        inputs = W._inputs(bundle, profile, end)
        sess.windows_bundle = bundle
        scope = windows_usb.observe_tigard_scope(profile, r.config, deadline=end, cancel=sess.cancel_start.is_set)
        sess.windows_scope = scope
        sess.windows_lease = portlock.get_manager().acquire(scope.claim_keys, owner=portlock.PortOwner(
            server='openocd-mcp', case_id=case.id, ref=profile.profile_id, role='bridge'))
        portlock.get_role_store().assert_usb_scope_allowed(scope)
        instrument_guard.guard_target_usb_scope(r, scope, consumer='openocd', phase='preflight')
        sess.windows_lease.set_state('awaiting_approval')
        return inputs

    classification = Classification(Risk.MODIFY, 'openocd.start.windows-tigard',
        '고정 Tigard JTAG 초기화·자동 TAP 탐색과 reset 해제를 수행합니다. 타깃 통신은 검증하지 않습니다.', profile.profile_id)
    try:
        inputs = await _stage(sess, preflight)
        action = {**W.action_fields(sess), 'profile_sha256': profile.profile_sha256,
                  'interface_sha256': profile.interface_sha256, 'transport': profile.transport,
                  'adapter_speed_khz': profile.adapter_speed_khz, 'target_cfg': [], 'extra_commands': [], 'tcl_port': None}
        decision = await r.authorize(tool='openocd_start', action=action, classification=classification,
                                    case_id=case.id, approval_id=approval_id, ctx=ctx)
        if not decision.allowed:
            return gate_response(decision)

        def launch():
            end = time.monotonic() + ready_timeout
            W._check_environment(r.config)
            bundle = sess.windows_bundle
            windows_bundle.revalidate_bundle(bundle, deadline=end, cancel=sess.cancel_start.is_set)
            jdir = case.subdir('jtag')
            n = S._next_index(jdir, 'openocd-', '.log')
            sess.log_path = jdir / f'openocd-{n}.log'
            sess.state_file = jdir / f'openocd-{n}.json'
            try:
                sess.windows_layout = PW.prepare_windows_run(jdir, deadline=end)
            except Exception as exc:
                sess.windows_layout = getattr(exc, 'prepared_run', None)
                raise
            plan = WP.build_tigard_plan(inputs, sess.windows_layout, ambient_env=tuple(os.environ.items()),
                                        path_converter=W._path_converter, deadline=end)
            sess.argv = list(plan.argv)
            try:
                owner = PW.spawn_windows(plan, bundle=bundle, log_path=sess.log_path, deadline=end,
                    cancel_check=sess.cancel_start.is_set, path_converter=W._path_converter,
                    profile_id=profile.profile_id,
                    before_spawn=lambda: fresh(sess, deadline=end, cancel=sess.cancel_start.is_set, phase='before-spawn'))
            except PW.WindowsSpawnError as exc:
                sess.windows_owner = exc.owner
                raise
            sess.windows_owner, sess.client = owner, owner.client
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TimeoutExpired('Windows 시작 준비 시간이 초과되었습니다.')
            ready = owner.wait_ready(timeout=remaining, cancel_check=sess.cancel_start.is_set)
            if not ready.ready or sess.cancel_start.is_set():
                raise DeviceError('Windows Tigard 준비를 확인하지 못했습니다.', code='openocd_windows_start_failed')
            sess.version = ready.version or {}
            summary, diagnosis, health = _verify_start(sess, deadline=end)
            if sess.cancel_start.is_set():
                raise DeviceError('Windows 시작이 취소되었습니다.', code='cancelled')
            sess.windows_lease.set_state('open')
            sess.starting = False
            W._save(sess)
            return {'ok': True, **sess.describe(), 'log_path': case.rel(sess.log_path),
                    'semihosting': dict(sess.semihosting), 'startup': summary, 'diagnosis': diagnosis,
                    'health': health, 'targets': [], 'scan_chain': summary.get('taps', []),
                    'warnings': summary['warnings'], 'classification': classification.to_dict()}
        result = await _stage(sess, launch)
        success = True
        return result
    except PwehError:
        raise
    except Exception:
        raise DeviceError('Windows Tigard 시작 준비에 실패했습니다.', code='openocd_windows_start_failed') from None
    finally:
        if not success:
            sess.cancel_start.set()
            with CancelScope(shield=True):
                await run_blocking(W.close_session, sess)
