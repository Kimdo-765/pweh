"""명시 Windows OLS COM 프로브의 승인·worker·공개 결과 경계.

정보용 version/list 실행기나 Linux 기본 CLI는 사용하지 않는다. worker가 owner를
포트 사용권에 결속하고 실제 정리 결과까지 보관하며 원문 실행 오류는 밖에 내보내지 않는다.
"""
from __future__ import annotations

import math
import os
import threading
import time
from typing import Any

from pweh import ports
from pweh.errors import PwehError
from pweh.safety import Risk
from pweh.sigrok_com import ComCommand, PROFILE_ID

from . import windows_info as info
from .cli import CliResult, parse_scan, parse_device_show, stderr_problems

WORKER_SECONDS = 120.0
CLEANUP_SECONDS = 10.0
_MESSAGES = {
    'sigrok_com_invalid': 'Windows OLS 프로브의 입력 형식을 확인하지 못했습니다.',
    'sigrok_com_failed': 'Windows OLS 프로브를 완료하지 못했습니다.',
    'sigrok_com_busy': 'Windows OLS 프로브 또는 이전 실행 정리가 진행 중입니다.',
    'sigrok_com_cleanup_unknown': 'Windows OLS 실행·제어 프로세스 또는 사본의 정리를 확인하지 못했습니다. 포트 잠금을 보존합니다.',
    'sigrok_com_cancelled': 'Windows OLS 프로브가 취소되었습니다.',
    'sigrok_com_timeout': 'Windows OLS 프로브의 시간 상한을 넘었습니다.',
    'sigrok_com_output_limit': 'Windows OLS 프로브의 출력 상한을 넘었습니다.',
    'sigrok_com_bad_output': 'Windows OLS 프로브 출력의 형식 또는 선택 장치를 확인하지 못했습니다.',
    'sigrok_com_decoder_error': 'Windows OLS 프로브에서 디코더 오류가 발생하여 결과를 반환하지 않습니다.',
    'route_changed': '승인 뒤 직렬 장치 신원 또는 범위가 바뀌었습니다.',
    'port_role_conflict': '선택 포트의 역할 표지가 프로브와 충돌합니다.',
    'port_scope_unknown': '선택 포트의 영향 범위를 확인하지 못했습니다.',
    'instrument_port': '보호된 계측기 포트에는 OLS 프로브를 실행하지 않습니다.',
    'instrument_identity_unknown': '보호 계측기와 선택 포트의 신원을 확인하지 못했습니다.',
}


def _error(code='sigrok_com_failed'):
    if type(code) is not str or code not in _MESSAGES:
        code = 'sigrok_com_failed'
    return PwehError(_MESSAGES[code], code=code)


def _public_error(exc):
    code = getattr(exc, 'code', None)
    if type(code) is not str:
        return _error()
    code = {'timeout': 'sigrok_com_timeout', 'cancelled': 'sigrok_com_cancelled',
            'busy': 'sigrok_com_busy', 'sigrok_windows_timeout': 'sigrok_com_timeout',
            'sigrok_windows_cancelled': 'sigrok_com_cancelled',
            'sigrok_windows_busy': 'sigrok_com_busy'}.get(code, code)
    if code in info._BUNDLE_CODES or code == 'sigrok_windows_unavailable':
        return info._error(code)
    return _error(code)


def _tick(end, cancel):
    if cancel():
        raise _error('sigrok_com_cancelled')
    if time.monotonic() >= end:
        raise _error('sigrok_com_timeout')


def _timeout(value, mode):
    if value is None:
        return 45.0 if mode == 'scan' else 60.0
    if type(value) not in (int, float):
        raise _error('sigrok_com_invalid')
    try:
        seconds = float(value)
    except (OverflowError, ValueError):
        raise _error('sigrok_com_invalid') from None
    if not math.isfinite(seconds) or not 0 < seconds <= 60:
        raise _error('sigrok_com_invalid')
    return seconds


def _bundle(config, *, cancel_event):
    """gate의 안정 지문에 쓸 등록 번들 관찰. 실행 사본은 만들지 않는다."""
    end = time.monotonic() + 45
    try:
        _tick(end, cancel_event.is_set)
        info._check_environment(config)
        bundle = info._resolve_bundle(config, deadline=end, cancel=cancel_event.is_set)
        _tick(end, cancel_event.is_set)
        return bundle
    except Exception as exc:
        raise _public_error(exc) from None


def _reserve(bundle, command, **kwargs):
    from .windows_com import reserve_com_owner
    return reserve_com_owner(bundle, command, **kwargs)


def _device(value, command):
    if type(value) is not dict or value.get('driver') != 'ols':
        raise _error('sigrok_com_bad_output')
    reported = value.get('conn')
    if reported is not None and reported != command.conn:
        raise _error('sigrok_com_bad_output')
    # raw 원문에는 정상 문법 밖 데이터도 붙을 수 있으므로 정형 필드만 반환한다.
    return {key: value[key] for key in ('driver', 'conn', 'description', 'serial_number', 'channel_count', 'channels')}


def _project(result: CliResult, command, bundle, policy):
    if not result.cleanup_verified:
        raise _error('sigrok_com_cleanup_unknown')
    if result.cancelled:
        raise _error('sigrok_com_cancelled')
    if result.timed_out:
        raise _error('sigrok_com_timeout')
    if (result.output_limit_hit or len(result.stdout) > info.MAX_STDOUT
            or len(result.stderr.encode('utf-8')) > info.MAX_STDERR):
        raise _error('sigrok_com_output_limit')
    report = stderr_problems(result.stderr)
    codes = {item['code'] for item in report.errors}
    no_device = command.mode == 'show' and codes == {'no_device'}
    if not no_device and (result.returncode != 0 or codes):
        if result.returncode == 0 and codes and codes <= info.DECODER_CODES:
            raise _error('sigrok_com_decoder_error')
        raise _error()
    try:
        text = result.stdout.decode('utf-8', 'strict')
    except UnicodeError:
        raise _error('sigrok_com_bad_output') from None
    base = {'ok': True, 'backend': 'windows', 'bundle': info._metadata(bundle),
            'profile': command.approval_identity(),
            'note': '고정 OLS COM 식별·정보 프로브입니다. capture_allowed는 정책이며 Windows 캡처 지원을 뜻하지 않습니다.'}
    if command.mode == 'scan':
        if text.strip() and 'The following devices were found:' not in text.splitlines():
            raise _error('sigrok_com_bad_output')
        devices = parse_scan(text)
        lines = [line for line in text.splitlines() if line.strip()]
        if lines and (lines[0] != 'The following devices were found:' or len(lines) != 1+len(devices)):
            raise _error('sigrok_com_bad_output')
        if len(devices) > 1:
            raise _error('sigrok_com_bad_output')
        devices = [{**_device(item, command), **policy.describe('ols')} for item in devices]
        return {**base, 'count': len(devices), 'devices': devices}
    parsed = parse_device_show(text)
    # OLS 고정 기능/scan 옵션에 원시 진단 행이 섞이면 정형 정보로 투영하지 않는다.
    if (parsed['driver_functions'] != ['Logic analyzer']
            or len(parsed['scan_options']) != len(set(parsed['scan_options']))
            or any(item not in ('conn', 'serialcomm') for item in parsed['scan_options'])):
        raise _error('sigrok_com_bad_output')
    if parsed['device'] is not None:
        parsed['device'] = _device(parsed['device'], command)
    # 파서의 마지막 장치 덮어쓰기로 복수 응답을 정상 한 장치처럼 만들지 않는다.
    from .cli import parse_dev_line
    device_lines = [parse_dev_line(line) for line in text.splitlines() if line and not line.startswith(' ')
                    and ' - ' in line]
    headers = {'Driver functions:', 'Scan options:', 'Channel groups:', 'Supported configuration options:'}
    if any(line and not line.startswith(' ') and line not in headers
           and parse_dev_line(line) is None for line in text.splitlines()):
        raise _error('sigrok_com_bad_output')
    if len(device_lines) > 1 or any(item is None for item in device_lines):
        raise _error('sigrok_com_bad_output')
    if no_device:
        if parsed['device'] is not None or result.returncode not in (0, 1):
            raise _error('sigrok_com_bad_output')
        return {**base, 'ok': False, 'status': 'no_device', 'driver': 'ols', 'conn': command.conn,
                'driver_functions': parsed['driver_functions'], 'scan_options': parsed['scan_options'],
                'message': '지정 COM에서 OLS 장치를 확인하지 못했습니다.'}
    if parsed['device'] is None:
        raise _error('sigrok_com_bad_output')
    return {**base, 'driver': 'ols', 'conn': command.conn, **parsed, **policy.describe('ols')}


def _work(use, bundle, command, timeout, policy, classification, action, *, cancel_event):
    """owner는 worker와 use가 공유하며 caller 취소 뒤에도 이 finally가 정리한다."""
    from . import server as S
    end = time.monotonic() + WORKER_SECONDS
    cancel = cancel_event.is_set
    owner = None
    result = None
    problem = None
    callback_problem = None

    def before_spawn():
        nonlocal callback_problem
        try:
            S.guard_target_port(use.runtime, command.conn, consumer='sigrok', driver='ols', phase='pre-process')
            use.fresh()
            argv = [str(bundle.entrypoint), *command.argv_tail]
            actual = S.classify_sigrok_argv(argv, policy=S._policy())
            if actual.risk >= Risk.MODIFY:
                raise _error('sigrok_com_invalid')
            now = dict(action)
            actual = S._probe_classification(use, now, actual, command.mode)
            now['profile'] = command.approval_identity()
            if now != action or (actual.risk, actual.rule_id) != (classification.risk, classification.rule_id):
                raise _error('route_changed')
            use.lease.set_state('running')
        except Exception as exc:
            callback_problem = _public_error(exc)
            raise

    try:
        _tick(end, cancel)
        owner = _reserve(bundle, command, deadline=end)
        use.cleanup_owner = owner
        use.unverified = True
        owner.prepare(info._runtime_parent(use.runtime.config), ambient_env=tuple(os.environ.items()),
                      deadline=end, cancel=cancel)
        result = owner.run(before_spawn=before_spawn, deadline=end, cancel=cancel, timeout_s=timeout)
        _tick(end, cancel)
    except Exception as exc:
        if owner is None:
            owner = getattr(exc, 'owner', None)
            if owner is not None:
                use.cleanup_owner, use.unverified = owner, True
        problem = callback_problem or _public_error(exc)
    finally:
        if owner is not None:
            try:
                verified = owner.close(deadline=time.monotonic()+CLEANUP_SECONDS).confirmed is True
            except Exception:
                verified = False
            use.unverified = not verified
            if not verified:
                problem = _error('sigrok_com_cleanup_unknown')
    if problem is not None:
        raise problem from None
    if cancel():
        raise _error('sigrok_com_cancelled')
    try:
        return _project(result, command, bundle, policy)
    except Exception as exc:
        raise _public_error(exc) from None


async def probe(mode, *, case_id, driver, conn, timeout_s=None, approval_id=None, ctx=None):
    """Windows 명시 두 프로브만 기존 case/gate/lease/handoff로 실행한다."""
    from . import server as S
    timeout = _timeout(timeout_s, mode)
    if type(driver) is not str or type(conn) is not str or not case_id:
        raise _error('sigrok_com_invalid')
    # 공백·경로형 COM을 canonical 포트로 잘못 승격하지 않는다.
    com = ports.parse_win_com(conn)
    if com is None or conn.strip() != conn or conn.lower() != f'com{com}':
        raise _error('sigrok_com_invalid')
    canonical = f'COM{com}'
    r = S.rt()
    case = r.case(case_id, hardware=True)
    policy = S._policy()
    argv = ['sigrok-cli', f'--driver={driver}:conn={canonical}', '--dont-scan', '--'+mode]
    base_cls = S.classify_sigrok_argv(argv, policy=policy)
    action: dict[str, Any] = {'driver': driver, 'conn': canonical, 'backend': 'windows'}
    tool = 'sigrok_scan' if mode == 'scan' else 'sigrok_device_info'
    if base_cls.risk >= Risk.MODIFY:
        return S._policy_denied(tool, action, base_cls, case.id)
    if driver != 'ols':
        raise _error('sigrok_com_invalid')
    command = ComCommand(PROFILE_ID, mode, canonical)
    await S._offload(S.guard_target_port, r, canonical, consumer='sigrok', driver=driver)
    use = await S._acquire_port_use(S._serial_use, case.id, canonical, 'windows')
    try:
        bundle = await S._run_cancellable(_bundle, r.config)
        action['bundle'] = {'release_id': bundle.release_id, 'manifest_sha256': bundle.manifest_sha256}
        cls = S._probe_classification(use, action, base_cls, mode)
        action['profile'] = command.approval_identity()
        decision = await r.authorize(tool=tool, action=action, classification=cls,
                                     case_id=case.id, approval_id=approval_id, ctx=ctx)
        if not decision.allowed:
            return S.gate_response(decision)

        def work(cancel_event):
            return _work(use, bundle, command, timeout, policy, cls, action, cancel_event=cancel_event)

        def finish(result):
            result['classification'] = cls.to_dict()
            return result

        def wrapped(cancel_event):
            return S._port_worker(use, work, finish, cancel_event)

        return await S._run_cancellable(wrapped)
    finally:
        if use.handoff.abandon_caller():
            use.finish()
