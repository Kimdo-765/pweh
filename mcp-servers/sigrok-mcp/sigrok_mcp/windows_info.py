"""등록 Windows sigrok의 두 정보 명령만 실행하고 고정 오류·결과로 투영한다.

단일 worker가 사본과 owner를 소유한다. caller 취소 뒤에도 finally가 종료 확인을
완료하며, 미확인 owner는 runner registry에 남는다. Linux 실행·캐시는 사용하지 않는다.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path
import threading
import time
from typing import Any

from pweh import hostenv, toolsdir, windows_bundle
from pweh.errors import PwehError
from .cli import CliResult, parse_supported, parse_version, stderr_problems

VERSION_SECONDS = 90.0
LIST_SECONDS = 60.0
CLEANUP_SECONDS = 10.0
MAX_STDOUT = 8 * 1024 * 1024
MAX_STDERR = 128 * 1024
DECODER_CODES = frozenset({'decoder_exception', 'no_decoder'})
_MESSAGES = {
    'sigrok_windows_unavailable': 'Windows sigrok 정보 조회 경로를 사용할 수 없습니다.',
    'sigrok_windows_failed': 'Windows sigrok 정보 조회를 완료하지 못했습니다.',
    'sigrok_windows_busy': '다른 Windows sigrok 정보 조회 또는 정리가 진행 중입니다.',
    'sigrok_windows_cleanup_unknown': 'Windows sigrok 하위 프로세스 또는 실행 사본의 정리를 확인하지 못했습니다. 다음 정보 조회에서 다시 확인합니다.',
    'cancelled': 'Windows sigrok 정보 조회가 취소되었습니다.',
    'timeout': 'Windows sigrok 정보 조회의 시간 상한을 넘었습니다.',
    'sigrok_windows_output_limit': 'Windows sigrok 정보 출력 상한을 넘었습니다.',
    'sigrok_failed': 'Windows sigrok 정보 명령이 실패했습니다.',
    'sigrok_bad_output': 'Windows sigrok 정보 출력 형식을 확인하지 못했습니다.',
    'sigrok_decoder_exception': 'Windows sigrok 디코더 로드 중 Python 오류가 발생했습니다. 전체 지원 목록을 반환하지 않습니다.',
    'sigrok_no_decoder': 'Windows sigrok 디코더 로드를 완료하지 못했습니다. 전체 지원 목록을 반환하지 않습니다.',
}
_BUNDLE_CODES = frozenset({'bundle_invalid_argument', 'bundle_registry_invalid', 'bundle_release_unregistered',
    'bundle_missing', 'bundle_receipt_invalid', 'bundle_tree_invalid', 'bundle_changed', 'bundle_limit',
    'bundle_timeout', 'bundle_io_failed', 'bundle_cancel_failed'})


def _error(code: str) -> PwehError:
    if type(code) is not str:
        code = 'sigrok_windows_failed'
    if code in _BUNDLE_CODES:
        return PwehError('등록 Windows sigrok 번들을 확인하지 못했습니다.', code=code)
    if code not in _MESSAGES:
        code = 'sigrok_windows_failed'
    return PwehError(_MESSAGES[code], code=code)


def _public_error(exc: Exception) -> PwehError:
    code = getattr(exc, 'code', None)
    aliases = {'process_cleanup_unverified': 'sigrok_windows_cleanup_unknown',
               'sigrok_windows_timeout': 'timeout', 'sigrok_windows_cancelled': 'cancelled'}
    if type(code) is str:
        code = aliases.get(code, code)
    return _error(code)


def _tick(deadline: float, cancel) -> None:
    if cancel():
        raise _error('cancelled')
    if time.monotonic() >= deadline:
        raise _error('timeout')


def _environment(config):
    return hostenv.detect(smoke=False, config=config)


def _check_environment(config):
    report = _environment(config)
    if (hostenv.disabled_keys(config) & {'interop', 'windows_tools'}
            or not hostenv.is_wsl(report)
            or report.get('wsl', {}).get('interop', {}).get('usable') is not True):
        raise _error('sigrok_windows_unavailable')


def _resolve_bundle(config, *, deadline, cancel):
    candidates = toolsdir.windows_bundle_candidates('sigrok', config.tools.get('sigrok_win_bundle'),
        os.environ.get('PWEH_SIGROK_WIN_BUNDLE'), None)
    cap = min(deadline, time.monotonic() + 45)
    if not candidates:
        manifest = windows_bundle.load_registered_manifest('sigrok', deadline=cap, cancel=cancel)
        root = windows_bundle.managed_release_root(toolsdir.tools_dir(), manifest)
        candidates = toolsdir.windows_bundle_candidates('sigrok', None, None, root)
    return windows_bundle.verify_release(Path(candidates[0][0]), 'sigrok', deadline=cap, cancel=cancel)


def _runtime_parent(config) -> Path:
    # TMPDIR·케이스·보호 state 설정과 독립된 uid별 고정 부모다. 기존 모드는 바꾸지 않는다.
    parent = Path(f'/tmp/pweh-sigrok-{os.getuid()}')
    fd = None
    try:
        try:
            os.mkdir(parent, 0o700)
        except FileExistsError:
            pass
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        opened = os.fstat(fd)
        named = os.stat(parent, follow_symlinks=False)
        if (not stat.S_ISDIR(opened.st_mode) or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) != 0o700
                or (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid)
                   != (named.st_dev, named.st_ino, named.st_mode, named.st_uid)):
            raise _error('sigrok_windows_failed')
        return parent
    except OSError:
        raise _error('sigrok_windows_failed') from None
    finally:
        if fd is not None:
            os.close(fd)


def _prepare_info(*args, **kwargs):
    # Linux 기본 경로는 Windows owner를 import하거나 실행하지 않는다.
    from .windows_runner import prepare_info
    return prepare_info(*args, **kwargs)


def _metadata(bundle) -> dict[str, Any]:
    return {'release_id': bundle.release_id, 'manifest_sha256': bundle.manifest_sha256,
            'digest_basis': bundle.digest_basis, 'known_limitations': list(bundle.known_limitations)}


def _result_checks(result: CliResult) -> None:
    """정리·취소·상한·종료코드는 파싱이나 decoder partial보다 먼저 확인한다."""
    if not result.cleanup_verified:
        raise _error('sigrok_windows_cleanup_unknown')
    if result.cancelled:
        raise _error('cancelled')
    if result.timed_out:
        raise _error('timeout')
    if result.output_limit_hit or len(result.stdout) > MAX_STDOUT or len(result.stderr.encode('utf-8')) > MAX_STDERR:
        raise _error('sigrok_windows_output_limit')
    if result.returncode != 0:
        raise _error('sigrok_failed')


def _codes(result: CliResult) -> frozenset[str]:
    return frozenset(item['code'] for item in stderr_problems(result.stderr).errors)


def _fatal(codes: frozenset[str]) -> None:
    if not codes:
        return
    if codes <= DECODER_CODES:
        raise _error('sigrok_decoder_exception' if 'decoder_exception' in codes else 'sigrok_no_decoder')
    raise _error('sigrok_failed')


def _text(result: CliResult) -> str:
    try:
        return result.stdout.decode('utf-8', 'strict')
    except UnicodeError:
        raise _error('sigrok_bad_output') from None


def _supported(result: CliResult) -> dict:
    parsed = parse_supported(_text(result))
    if not any(parsed.values()):
        raise _error('sigrok_bad_output')
    return parsed


def run_info(mode: str, config, *, cancel_event: threading.Event) -> dict[str, Any]:
    """Windows 정보 worker. 반환 전에 owner 정리를 확인하며 raw 오류를 밖에 내보내지 않는다."""
    if mode not in ('version', 'list'):
        raise _error('sigrok_windows_failed')
    deadline = time.monotonic() + (VERSION_SECONDS if mode == 'version' else LIST_SECONDS)
    cancel = cancel_event.is_set
    owner = None
    out = None
    problem = None
    try:
        _tick(deadline, cancel)
        _check_environment(config)
        _tick(deadline, cancel)
        bundle = _resolve_bundle(config, deadline=deadline, cancel=cancel)
        _tick(deadline, cancel)
        owner = _prepare_info(bundle, _runtime_parent(config), deadline=deadline, cancel=cancel,
                              ambient_env=tuple(os.environ.items()))
        base = {'ok': True, 'backend': 'windows', 'status': 'ok', 'bundle': _metadata(bundle)}
        if mode == 'version':
            result = owner.run('version', deadline=min(deadline, time.monotonic()+30), cancel=cancel)
            _result_checks(result)
            _fatal(_codes(result))
            version = parse_version(_text(result))
            if not version.get('sigrok_cli'):
                raise _error('sigrok_bad_output')
            _tick(deadline, cancel)
            result = owner.run('list', deadline=min(deadline, time.monotonic()+60), cancel=cancel)
            _result_checks(result)
            codes = _codes(result)
            if codes and not codes <= DECODER_CODES:
                _fatal(codes)
            supported = _supported(result)  # decoder 오류만이어도 정상 목록 형식은 필수다.
            out = {**base, **version, 'path': str(bundle.entrypoint), 'list_complete': not codes,
                   'counts': None if codes else {k: len(v) for k, v in supported.items()}}
            if codes:
                out.update(status='partial', problems=sorted('sigrok_'+c for c in codes),
                    warnings=['버전은 확인했으나 디코더 로드 오류로 전체 지원 수를 확인하지 못했습니다. 등록 번들의 알려진 제한을 확인하세요.'])
        else:
            result = owner.run('list', deadline=min(deadline, time.monotonic()+60), cancel=cancel)
            _result_checks(result)
            _fatal(_codes(result))
            out = {**base, 'supported': _supported(result)}
        _tick(deadline, cancel)
    except Exception as exc:
        if owner is None:
            owner = getattr(exc, 'owner', None)
        problem = _public_error(exc)
    finally:
        if owner is not None:
            try:
                cleanup = owner.close(deadline=time.monotonic()+CLEANUP_SECONDS)
                if not cleanup.confirmed:
                    problem = _error('sigrok_windows_cleanup_unknown')
            except Exception:
                problem = _error('sigrok_windows_cleanup_unknown')
    if problem is not None:
        raise problem from None
    # 정리에는 별도 유한 예산을 썼다. 정리 중 도착한 취소도 성공 응답으로 바꾸지 않는다.
    if cancel():
        raise _error('cancelled')
    if out is None:
        raise _error('sigrok_windows_failed')
    return out
