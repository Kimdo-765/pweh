"""고정 Flipper CLI 세션과 전체 USB lease의 단일 worker 소유권."""
from __future__ import annotations

import contextlib
import copy
import threading
import time
import uuid

from pweh import hostenv, ports, portlock, serialtransport
from pweh.errors import PwehError
from pweh import flipper_cli as F
from pweh.instrument_guard import guard_target_port

CONNECT_SECONDS = 30.0
CLOSE_SECONDS = 10.0
TEXT_SECONDS = 10.0
PULL_SECONDS = 300.0
_REGISTRY = {}
_PREPARING = set()
_REGISTRY_LOCK = threading.RLock()
_CODES = frozenset((
    'flipper_invalid_input', 'flipper_identity_unknown', 'flipper_identity_changed',
    'flipper_role_conflict', 'flipper_firmware_unsupported', 'flipper_handshake_failed',
    'flipper_app_busy', 'flipper_protocol_error', 'flipper_storage_error', 'flipper_limit',
    'flipper_checksum_mismatch', 'flipper_busy', 'flipper_terminal', 'flipper_cleanup_pending',
    'flipper_failed', 'cancelled', 'time_limit', 'authorization_required',
    'instrument_port', 'instrument_identity_unknown', 'port_role_unknown', 'port_busy', 'port_lock_busy',
))


def error(code='flipper_failed'):
    return PwehError('Flipper 고정 읽기 작업을 완료하지 못했습니다.',
                     code=code if code in _CODES else 'flipper_failed')


def public_error(exc):
    code = getattr(exc, 'code', None)
    aliases = {'busy': 'flipper_busy', 'route_changed': 'flipper_identity_changed',
               'port_scope_unknown': 'flipper_identity_unknown',
               'port_role_conflict': 'flipper_role_conflict',
               'port_lease_invalid': 'flipper_identity_changed',
               'artifact_timeout': 'time_limit'}
    return error(aliases.get(code, code) if type(code) is str else 'flipper_failed')


def _environment(runtime):
    return hostenv.detect(smoke=False, config=runtime.config)


def _resolve(runtime, port):
    return ports.resolve(_environment(runtime), port, 'serial-session', config=runtime.config)


def _scope(runtime, route):
    return ports.reset_scope(route, whole_device=True, config=runtime.config)


def _identity(route):
    i = route.identity
    if (route.backend not in ('posix-tty', 'win-helper') or route.continuity_key() is None
            or i.status != 'known' or i.present is not True or i.kind != 'serial'
            or i.vid != '0483' or i.pid != '5740' or i.interface_number != '00'
            or not i.usb_ancestor or not i.serial or not i.serial.casefold().startswith('flip_')
            or i.serial_basis != ('instance-tail' if route.backend == 'win-helper' else 'sysfs')):
        raise error('flipper_identity_unknown')


def _roles(runtime, route, phase):
    portlock.get_role_store().assert_probe_allowed(route)
    guard_target_port(runtime, route.ref, consumer='flipper', phase=phase)


class Use:
    """예약은 caller, claim 이후 transport와 파일은 worker만 해제한다."""
    def __init__(self, session, external=None):
        self.session = session
        self._handoff = portlock.LeaseHandoff()
        self._cancel = threading.Event()
        self._external = external
        self._job_cancel = None
        self._finished = False
        self._claimed = False

    def claim(self):
        with self.session._condition:
            if not self._handoff.claim_worker():
                return False
            self._claimed = True
            if self.session._closing or self.cancelled():
                self.finish()
                return False
            return True

    def cancelled(self):
        return (self._cancel.is_set() or (self._external is not None and self._external.is_set())
                or (self._job_cancel is not None and self._job_cancel()))

    def check(self, deadline):
        if self.cancelled() or self.session._closing:
            raise error('cancelled')
        if time.monotonic() >= deadline:
            raise error('time_limit')
        if not self._claimed or self._finished:
            raise error('flipper_terminal')

    def cancel(self):
        with self.session._condition:
            if self._finished:
                return
            self._cancel.set()
            transport = self.session.transport
            if self._claimed and transport is not None:
                with contextlib.suppress(Exception):
                    transport.cancel_read()
            if self._handoff.abandon_caller():
                self.finish()

    def finish(self):
        with self.session._condition:
            if not self._finished:
                self._finished = True
                self.session._uses.discard(self)
                self.session._condition.notify_all()


class Session:
    """재연결 없는 세션. 정리 미확인 owner는 registry에 계속 남긴다."""
    def __init__(self, runtime, case, route, keys, sid):
        self.runtime, self.case_id = runtime, case.id
        self.route, self.keys, self.session_id = route, keys, sid
        self.lease = None
        self.transport = None
        self.cli = F.FlipperCli(case.id)
        self.device = None
        self.state = 'awaiting_approval'
        self._condition = threading.Condition(threading.RLock())
        self._uses = set()
        self._closing = False
        self._cleanup_thread = None
        self._cleanup_done = threading.Event()
        self._warnings = set()

    @property
    def action(self):
        return {'port': self.route.device_path, 'route': self.route.approval_identity(),
                'profile': F.PROFILE, 'parent': self.route.identity.usb_ancestor,
                'interface_number': '00', 'scope_keys': list(self.keys),
                'baudrate': 115200, 'dtr': True, 'rts': False}

    def reserve_use(self, *, _opening=False, _external=None):
        with self._condition:
            if self._closing or self.state in ('terminal', 'closed', 'cleanup_pending'):
                raise error('flipper_terminal')
            if (self._uses or (not _opening and self.state != 'ready')
                    or (_opening and self.state != 'awaiting_approval')):
                raise error('flipper_busy')
            use = Use(self, _external)
            self._uses.add(use)
            return use

    def fresh(self, use, deadline):
        use.check(deadline)
        self.runtime.case(self.case_id, hardware=True)
        fresh = ports.revalidate(self.route, env=_environment(self.runtime), config=self.runtime.config)
        _identity(fresh)
        if fresh._binding() != self.route._binding():
            raise error('flipper_identity_changed')
        keys = _scope(self.runtime, fresh)
        if keys != self.keys or self.lease.keys != self.keys:
            raise error('flipper_identity_changed')
        self.lease.assert_held(keys)
        _roles(self.runtime, fresh, 'pre-io')
        use.check(deadline)

    def terminal(self):
        self.cli.abort()
        with self._condition:
            if self.state != 'closed':
                self.state = 'terminal'

    def _receive(self, use, deadline, sink=None, *, passive=False):
        progress_end = min(deadline, time.monotonic() + TEXT_SECONDS)
        while not self.cli.ready:
            use.check(min(deadline, progress_end))
            block = self.transport.read(self.cli.read_size)
            if type(block) is not bytes or len(block) > self.cli.read_size:
                raise error('flipper_protocol_error')
            if block:
                progress_end = min(deadline, time.monotonic() + TEXT_SECONDS)
                payload = self.cli.feed(block)
                if payload:
                    if sink is None or sink(payload) is not None:
                        raise error('flipper_protocol_error')
            elif not self.transport.is_open:
                self.cli.eof()
            else:
                # 합성/비차단 transport가 즉시 빈 bytes를 반환해도 busy-loop하지 않는다.
                self._condition.acquire()
                try:
                    self._condition.wait(.002)
                finally:
                    self._condition.release()
        use.check(deadline)
        return copy.deepcopy(self.cli.result)

    def _exchange(self, use, kind, path, sink, deadline):
        self.fresh(use, deadline)
        command = self.cli.begin(kind, path)
        pos = 0
        while pos < len(command):
            use.check(deadline)
            count = self.transport.write(command[pos:])
            if type(count) is not int or not 0 <= count <= len(command) - pos:
                raise error('flipper_protocol_error')
            if count == 0:
                use._cancel.wait(.002)
            pos += count
        return self._receive(use, deadline, sink)

    def request(self, use, kind, path=None, sink=None, *, deadline):
        if kind not in ('info', 'list', 'read', 'md5'):
            raise error('flipper_invalid_input')
        try:
            self._exchange(use, 'loader', None, None, min(deadline, time.monotonic() + TEXT_SECONDS))
            end = deadline if kind == 'read' else min(deadline, time.monotonic() + TEXT_SECONDS)
            return self._exchange(use, kind, path, sink, end)
        except Exception as exc:
            self.terminal()
            raise public_error(exc) from None

    def connect(self, cancel_event):
        deadline = time.monotonic() + CONNECT_SECONDS
        use = self.reserve_use(_opening=True, _external=cancel_event)
        if not use.claim():
            raise error('cancelled')
        try:
            self.lease.set_state('opening')
            self.state = 'opening'
            try:
                self.transport = serialtransport.open_serial(
                    self.route, serialtransport.SerialSettings(timeout=.05, write_timeout=1,
                                                               dtr=True, rts=False),
                    lease=self.lease, before_io=lambda: self.fresh(use, deadline))
            except serialtransport.SerialOpenError as exc:
                self.transport = exc.transport
                raise error('flipper_cleanup_pending') from None
            self._receive(use, min(deadline, time.monotonic() + TEXT_SECONDS), passive=True)
            self.device = self.request(use, 'info', deadline=deadline)
            self.lease.set_state('open')
            self.state = 'ready'
            return {'ok': True, 'case_id': self.case_id, 'session_id': self.session_id,
                    'profile': F.PROFILE, 'state': 'ready', 'port': self.route.device_path,
                    'route': {'backend': self.route.backend, 'device_id': self.route.device_id,
                              'identity_strength': self.route.identity_strength, 'interface_number': '00',
                              'whole_device_locked': True},
                    'handshake': {'banner_seen': True, 'prompt_seen': True,
                                  'firmware_claim_verified': False, 'tx_before_banner': 0},
                    'device': copy.deepcopy(self.device), 'limits': dict(F.LIMITS), 'warnings': []}
        except Exception as exc:
            self.terminal()
            raise public_error(exc) from None
        finally:
            use.finish()

    def device_info(self, use):
        device = self.request(use, 'info', deadline=time.monotonic() + 2 * TEXT_SECONDS)
        self.device = device
        return {'ok': True, 'case_id': self.case_id, 'session_id': self.session_id,
                'profile': F.PROFILE, 'device': device, 'warnings': []}

    def storage_list(self, use, path):
        path = F.remote_path(self.case_id, path)
        result = self.request(use, 'list', path, deadline=time.monotonic() + 2 * TEXT_SECONDS)
        return {'ok': True, 'case_id': self.case_id, 'session_id': self.session_id,
                'path': path, **result, 'warnings': []}

    def _cleanup(self):
        try:
            with self._condition:
                while self._uses:
                    self._condition.wait(.05)
            if self.transport is not None:
                try:
                    self.transport.close()
                except Exception:
                    self._warnings.add('transport_close_failed')
                if self.transport.closed is not True:
                    return
            if self.lease is not None:
                try:
                    self.lease.close()
                except Exception:
                    self._warnings.add('lease_close_failed')
                if self.lease.closed is not True:
                    return
            with self._condition:
                self.state = 'closed'
            with _REGISTRY_LOCK:
                if _REGISTRY.get(self.case_id) is self:
                    del _REGISTRY[self.case_id]
        except Exception:
            self._warnings.add('cleanup_unconfirmed')
        finally:
            self._cleanup_done.set()

    def close(self):
        with self._condition:
            already_closed = self.state == 'closed'
            self._closing = True
            for use in tuple(self._uses):
                use.cancel()
            if not already_closed:
                self.state = 'cleanup_pending'
                if self._cleanup_thread is None or not self._cleanup_thread.is_alive():
                    self._cleanup_done.clear()
                    self._cleanup_thread = threading.Thread(target=self._cleanup, daemon=True,
                                                            name='flipper-cleanup')
                    self._cleanup_thread.start()
        self._cleanup_done.wait(CLOSE_SECONDS)
        with self._condition:
            physical = self.transport is None or self.transport.closed is True
            finished = not self._uses
            released = self.lease is None or self.lease.closed is True
            return {'ok': physical and finished and released, 'case_id': self.case_id,
                    'session_id': self.session_id, 'state': self.state,
                    'already_closed': already_closed, 'physical_close_verified': physical,
                    'worker_finished': finished, 'lease_released': released,
                    'device_command_termination_verified': False,
                    'warnings': sorted(set(self._warnings))}


def prepare_session(runtime, case, port):
    """미개방 lease를 registry에 먼저 결속한다. gate는 서버가 수행한다."""
    with _REGISTRY_LOCK:
        if case.id in _REGISTRY or case.id in _PREPARING or len(_REGISTRY) + len(_PREPARING) >= 16:
            raise error('flipper_busy')
        _PREPARING.add(case.id)
    owner = None
    try:
        route = _resolve(runtime, port)
        _identity(route)
        _roles(runtime, route, 'preflight')
        keys = _scope(runtime, route)
        owner = Session(runtime, case, route, keys, uuid.uuid4().hex)
        owner.lease = portlock.get_manager().acquire(keys, owner=portlock.PortOwner(
            server='pweh-flipper', case_id=case.id, ref=route.ref, role='instrument',
            session_id=owner.session_id), state='awaiting_approval')
        with _REGISTRY_LOCK:
            _REGISTRY[case.id] = owner
        return owner
    except Exception as exc:
        raise public_error(exc) from None
    finally:
        with _REGISTRY_LOCK:
            _PREPARING.discard(case.id)


def get_session(case_id):
    with _REGISTRY_LOCK:
        owner = _REGISTRY.get(case_id)
    if owner is None:
        raise error('flipper_terminal')
    return owner


def close_session(case_id):
    with _REGISTRY_LOCK:
        owner = _REGISTRY.get(case_id)
    if owner is not None:
        return owner.close()
    return {'ok': True, 'case_id': case_id, 'session_id': None, 'state': 'closed',
            'already_closed': True, 'physical_close_verified': True, 'worker_finished': True,
            'lease_released': True, 'device_command_termination_verified': False, 'warnings': []}
