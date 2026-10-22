"""고정 Windows 프로필의 승인·시작·단일 pipe 사용권. 덤프 작업은 지원하지 않는다."""
from __future__ import annotations

import math
import os
from pathlib import Path
import threading
import time

from anyio import CancelScope

from pweh import hostenv, toolsdir, windows_bundle
from pweh.errors import DeviceError, PwehError, TimeoutExpired, ValidationFailed
from pweh.fsutil import utcnow_iso
from pweh.mcpkit import gate_response, run_blocking, run_blocking_cancellable
from pweh.portlock import LeaseHandoff
from pweh.safety import Classification, Risk
from . import process_windows as PW, windows_plan as WP
from .dummy_profile import validate_dummy_start
from .session import OcdSession, REGISTRY

QUERIES = frozenset({'version', 'targets', 'scan_chain', 'jtag names', 'adapter name'})
SEMIHOSTING = {'mode': 'fixed-dummy-noinit', 'hardware_initialized': False, 'verification_performed': False}


def unsupported() -> DeviceError:
    return DeviceError('Windows 고정 프로필은 이 동작을 지원하지 않습니다.', code='openocd_windows_unsupported')


def require_query(command: str, sess=None) -> None:
    allowed = QUERIES if sess is None or sess.windows_profile != "tigard-jtag-v1" else {"version", "scan_chain", "targets"}
    if type(command) is not str or command not in allowed:
        raise unsupported()


def action_fields(sess: OcdSession) -> dict:
    if not sess.windows:
        return {}
    fields = {'backend': 'windows', 'windows_profile': sess.windows_profile,
              'bundle_release_id': sess.windows_bundle.release_id,
              'bundle_manifest_sha256': sess.windows_bundle.manifest_sha256}
    if sess.windows_scope is not None:
        from .windows_tigard import scope_fields
        fields.update(scope_fields(sess.windows_scope))
    return fields


def _environment(config):
    return hostenv.detect(smoke=False, config=config)


def _check_environment(config) -> None:
    env = _environment(config)
    if (hostenv.disabled_keys(config) & {'interop', 'windows_tools'}
            or not str(env.get('kind', '')).startswith('WSL')
            or env.get('wsl', {}).get('interop', {}).get('usable') is not True):
        raise DeviceError('Windows OpenOCD 실행 경로를 사용할 수 없습니다.', code='openocd_windows_unavailable')


def _resolve_bundle(config, deadline):
    configured = config.tools.get('openocd_win_bundle')
    candidates = toolsdir.windows_bundle_candidates('openocd', configured, os.environ.get('PWEH_OPENOCD_WIN_BUNDLE'), None)
    if not candidates:
        manifest = windows_bundle.load_registered_manifest('openocd', deadline=deadline)
        root = windows_bundle.managed_release_root(toolsdir.tools_dir(), manifest)
        candidates = toolsdir.windows_bundle_candidates('openocd', None, None, root)
    return windows_bundle.verify_release(Path(candidates[0][0]), 'openocd', deadline=deadline)


def _inputs(bundle, profile, deadline):
    if bundle.release_id != profile.release_id or len(bundle.search_dirs) != 1:
        raise DeviceError('Windows 고정 프로필에 맞는 등록 번들이 아닙니다.', code='openocd_windows_bundle_mismatch')
    cfg = WP.observe_file(bundle.root / profile.interface_relative_path, max_bytes=profile.interface_size, deadline=deadline)
    if cfg.sha256 != profile.interface_sha256 or cfg.size != profile.interface_size:
        raise DeviceError('Windows 고정 프로필 설정의 지문이 맞지 않습니다.', code='openocd_windows_bundle_mismatch')
    return WP.PipeStartInputs(WP.observe_file(bundle.entrypoint, max_bytes=WP.MAX_FILE_BYTES, deadline=deadline), tuple(bundle.search_dirs),
                             WP.CfgInput('standard', cfg), (), (), profile.transport, profile.adapter_speed_khz, ())


def _path_converter(path, deadline):
    return PW.convert_path(path, deadline)


def _save(sess, **extra):
    from . import server as S
    try:
        S._write_session_state(sess, S.rt().case(sess.case_id), **extra)
    except Exception:
        # 정리 실패와 상태 기록 실패를 성공으로 바꾸거나 원문 경로를 로그에 넣지 않는다.
        pass


def close_session(sess: OcdSession, *, timeout: float = 10.0) -> dict:
    """물리 종료 확인과 실제 worker 사용권 반환을 모두 기다린 뒤 run을 해제한다."""
    end = time.monotonic() + timeout
    sess.begin_close()
    if not sess.close_lock.acquire(timeout=max(0, end-time.monotonic())):
        return {'ok': False, 'stopped': False, 'cleanup_pending': True, 'reason': 'cleanup_busy'}
    confirmed = False
    reason = 'cleanup_unknown'
    try:
        if sess.cleanup_reason == 'confirmed' and not sess.cleanup_pending:
            return {'ok': True, 'stopped': True, 'backend': 'windows', 'transport': 'windows-pipe',
                    'windows_profile': sess.windows_profile, 'cleanup_pending': False, 'reason': 'confirmed'}
        # 시작 worker가 owner를 게시하기 전에 run을 정리하지 않는다.
        if sess.starting and not sess.wait_unused(end):
            reason = 'worker_pending'
        else:
            owner = sess.windows_owner
            physical = owner is None
            if owner is not None:
                result = owner.close(timeout=max(.001, end-time.monotonic()))
                physical = result.confirmed
                reason = result.reason
            unused = sess.wait_unused(end)
            if physical and unused:
                if owner is not None:
                    confirmed = owner.release_run(deadline=end)
                elif sess.windows_layout is not None:
                    confirmed = PW.release_prepared_run(sess.windows_layout, deadline=end)
                else:
                    confirmed = True
                if confirmed and sess.windows_lease is not None:
                    sess.windows_lease.close()
                    confirmed = sess.windows_lease.closed
                reason = 'confirmed' if confirmed else 'run_cleanup_unknown'
            elif not unused:
                reason = 'worker_pending'
        if not confirmed and sess.windows_lease is not None and not sess.windows_lease.closed:
            sess.windows_lease.set_state('orphan')
        sess.cleanup_pending = not confirmed
        sess.cleanup_reason = reason
        _save(sess, cleanup_confirmed=confirmed, **({'stopped_at': utcnow_iso()} if confirmed else {}))
        if confirmed and REGISTRY.find(sess.case_id) is sess:
            REGISTRY.remove(sess.case_id)
        return {'ok': confirmed, 'stopped': confirmed, 'backend': 'windows', 'transport': 'windows-pipe',
                'windows_profile': sess.windows_profile, 'cleanup_pending': not confirmed, 'reason': reason}
    except Exception:
        sess.cleanup_pending = True
        sess.cleanup_reason = 'cleanup_unknown'
        _save(sess, cleanup_confirmed=False)
        return {'ok': False, 'stopped': False, 'cleanup_pending': True, 'reason': 'cleanup_unknown'}
    finally:
        sess.close_lock.release()


async def call_session(sess, command, *, timeout, raw=False, internal=False):
    if internal:
        from . import semihosting
        if sess.windows_profile != 'tigard-jtag-v1' or command not in (semihosting.CHECK_CALL, semihosting.STATUS_CALL):
            raise unsupported()
    else:
        require_query(command, sess)
    sess.reserve_use()
    handoff = LeaseHandoff()
    cancel = threading.Event()

    def worker():
        if not handoff.claim_worker():
            raise DeviceError('Windows 조회가 취소되었습니다.', code='cancelled')
        try:
            end = time.monotonic() + timeout
            if sess.windows_scope is not None:
                from .windows_tigard import fresh
                fresh(sess, deadline=end, cancel=cancel.is_set, phase='rpc')
            if cancel.is_set() or sess.closing:
                raise DeviceError('Windows 조회가 취소되었습니다.', code='cancelled')
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TimeoutExpired('Windows 조회 준비 시간이 초과되었습니다.')
            method = sess.client.call_raw if raw else sess.client.call
            return method(command, timeout=remaining, cancel_check=cancel.is_set)
        finally:
            sess.finish_use()

    try:
        return await run_blocking_cancellable(worker, on_cancel=cancel.set)
    finally:
        cancel.set()
        if handoff.abandon_caller():
            sess.finish_use()


async def start(r, case, *, ctx, approval_id, ready_timeout, **args):
    from . import server as S
    if args.get('windows_profile') == 'tigard-jtag-v1':
        from .windows_tigard import start as start_tigard
        return await start_tigard(r, case, ctx=ctx, approval_id=approval_id, ready_timeout=ready_timeout, **args)
    profile = validate_dummy_start(**args)
    if (type(ready_timeout) not in (int, float) or abs(ready_timeout) > 30
            or not math.isfinite(ready_timeout) or ready_timeout <= 0):
        raise ValidationFailed('Windows 준비 제한은 0초 초과 30초 이하의 유한 수여야 합니다.')
    await run_blocking(_check_environment, r.config)
    end = time.monotonic() + 30
    bundle = await run_blocking(_resolve_bundle, r.config, end)
    inputs = await run_blocking(_inputs, bundle, profile, end)
    sess = OcdSession(case.id, 'spawned', None, None, None, transport='windows-pipe',
                      windows_bundle=bundle, windows_profile=profile.profile_id, starting=True,
                      semihosting=dict(SEMIHOSTING))
    REGISTRY.add(sess)
    sess.reserve_use(startup=True)
    handoff = LeaseHandoff()
    state_lock = threading.Lock()
    state = {'finished': False, 'abandoned': False, 'cleanup_claimed': False}
    success = False

    def cancel():
        sess.cancel_start.set()

    def worker():
        if not handoff.claim_worker():
            raise DeviceError('Windows 시작이 취소되었습니다.', code='cancelled')
        try:
            if sess.cancel_start.is_set():
                raise DeviceError('Windows 시작이 취소되었습니다.', code='cancelled')
            _check_environment(r.config)
            end = time.monotonic() + ready_timeout
            windows_bundle.revalidate_bundle(bundle, deadline=end, cancel=sess.cancel_start.is_set)
            jdir = case.subdir('jtag')
            n = S._next_index(jdir, 'openocd-', '.log')
            sess.log_path = jdir / f'openocd-{n}.log'
            sess.state_file = jdir / f'openocd-{n}.json'
            try:
                sess.windows_layout = PW.prepare_windows_run(jdir, deadline=end)
            except Exception as exc:
                sess.windows_layout = getattr(exc, "prepared_run", None)
                raise
            plan = WP.build_dummy_plan(inputs, sess.windows_layout, ambient_env=tuple(os.environ.items()),
                                       path_converter=_path_converter, deadline=end)
            sess.argv = list(plan.argv)
            try:
                owner = PW.spawn_windows(plan, bundle=bundle, log_path=sess.log_path, deadline=end,
                                         cancel_check=sess.cancel_start.is_set, path_converter=_path_converter)
            except PW.WindowsSpawnError as exc:
                sess.windows_owner = exc.owner
                raise
            sess.windows_owner = owner
            sess.client = owner.client
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TimeoutExpired('Windows 시작 준비 시간이 초과되었습니다.')
            result = owner.wait_ready(timeout=remaining, cancel_check=sess.cancel_start.is_set)
            if not result.ready or sess.cancel_start.is_set():
                raise DeviceError('Windows dummy 준비를 확인하지 못했습니다.', code='openocd_windows_start_failed')
            sess.version = result.version or {}
            sess.starting = False
            _save(sess)
            return {'ok': True, **sess.describe(), 'log_path': case.rel(sess.log_path),
                    'semihosting': dict(SEMIHOSTING), 'hardware_initialized': False,
                    'usb_scope': 'not-applicable', 'classification': classification.to_dict()}
        except PwehError:
            raise
        except Exception:
            raise DeviceError("Windows dummy 시작 준비에 실패했습니다.", code="openocd_windows_start_failed") from None
        finally:
            sess.finish_use()
            with state_lock:
                state['finished'] = True
                cleanup = state['abandoned'] and not state['cleanup_claimed']
                if cleanup:
                    state['cleanup_claimed'] = True
            if cleanup:
                close_session(sess)

    classification = Classification(Risk.MODIFY, 'openocd.start.windows-dummy',
        '등록 Windows dummy 프로필 시작. USB 접근 및 하드웨어 초기화 없음', profile.profile_id)
    action = {**action_fields(sess), 'profile_sha256': profile.profile_sha256,
              'interface_sha256': profile.interface_sha256, 'transport': profile.transport,
              'adapter_speed_khz': profile.adapter_speed_khz, 'extra_commands': list(profile.commands), 'tcl_port': None}
    try:
        decision = await r.authorize(tool='openocd_start', action=action, classification=classification,
                                    case_id=case.id, approval_id=approval_id, ctx=ctx)
        if not decision.allowed:
            return gate_response(decision)
        result = await run_blocking_cancellable(worker, on_cancel=cancel)
        success = True
        return result
    finally:
        if not success:
            cancel()
            pending = handoff.abandon_caller()
            if pending:
                sess.finish_use()
            with state_lock:
                state['abandoned'] = True
                cleanup = (pending or state['finished']) and not state['cleanup_claimed']
                if cleanup:
                    state['cleanup_claimed'] = True
            if cleanup:
                # AnyIO scope와 raw Task.cancel은 별개다. worker 인계는 위 latch가 보장한다.
                with CancelScope(shield=True):
                    await run_blocking(close_session, sess)
