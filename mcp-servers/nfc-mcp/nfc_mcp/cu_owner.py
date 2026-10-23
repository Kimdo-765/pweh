"""고정 CU query·NTAG 읽기의 단일 사용권과 물리 직렬 수명."""
from __future__ import annotations

import contextlib
import math
import re
import threading
import time
import uuid
from dataclasses import asdict, dataclass

from pweh import cu_protocol as P
from pweh import hostenv, portlock, ports, serialtransport
from pweh.errors import PwehError
from pweh.instrument_guard import guard_target_port

START_SECONDS = 5.0
OPERATION_SECONDS = 45.0
COMMAND_SECONDS = 2.0
CLOSE_SECONDS = 10.0
_REGISTRY = {}
_PREPARING = set()
_LOCK = threading.RLock()
_CODES = frozenset((
    'cu_protocol_invalid', 'cu_model_unsupported', 'cu_firmware_unsupported',
    'cu_reader_required', 'cu_identity_unknown', 'cu_cleanup_unknown',
    'nfc_input_invalid', 'nfc_scan_invalid', 'nfc_family_unsupported', 'nfc_identity_mismatch',
    'time_limit', 'cancelled', 'busy', 'authorization_required', 'instrument_port',
    'instrument_identity_unknown', 'port_role_unknown', 'port_role_conflict',
    'port_busy', 'port_lock_busy', 'route_changed',
))


def error(code='cu_protocol_invalid'):
    return PwehError('CU 고정 읽기 요청을 완료하지 못했습니다.',
                     code=code if code in _CODES else 'cu_protocol_invalid')


def public_error(exc):
    code = getattr(exc, 'code', None)
    aliases = {'port_scope_unknown': 'cu_identity_unknown', 'port_lease_invalid': 'route_changed'}
    return error(aliases.get(code, code) if type(code) is str else 'cu_protocol_invalid')


def _end(deadline, seconds):
    valid = False
    if type(deadline) in (int, float):
        try:
            valid = math.isfinite(deadline)
        except OverflowError:
            pass
    if not valid:
        raise error('nfc_input_invalid')
    return min(deadline, time.monotonic() + seconds)


def _environment(runtime):
    return hostenv.detect(smoke=False, config=runtime.config)


def _resolve(runtime, port):
    return ports.resolve(_environment(runtime), port, 'serial-session', config=runtime.config)


def _scope(runtime, route):
    return ports.reset_scope(route, whole_device=True, config=runtime.config)


def _identity(route, keys=None):
    i = route.identity
    if (route.backend not in ('posix-tty', 'win-helper') or route.purpose != 'serial-session'
            or route.continuity_key() is None or i.status != 'known' or i.present is not True
            or i.kind != 'serial' or (i.vid, i.pid) != ('6868', '8686') or not i.usb_ancestor):
        raise error('cu_identity_unknown')
    if i.interface_number == '00':
        return 'observed-interface00'
    if (route.backend == 'win-helper' and i.interface_number is None
            and i.device_instance == i.usb_ancestor == i.parent_instance
            and re.fullmatch(r'USB\\VID_6868&PID_8686\\[^\\]+', i.usb_ancestor, re.I)):
        if keys is not None and tuple(key for key in keys if key.startswith('win:')) != (route.lock_key,):
            raise error('cu_identity_unknown')
        return 'observed-single-cdc-parent'
    raise error('cu_identity_unknown')


def _roles(runtime, route, phase):
    portlock.get_role_store().assert_probe_allowed(route)
    guard_target_port(runtime, route.ref, consumer='cu', phase=phase)


@dataclass(frozen=True, repr=False)
class CuProbe:
    session_id: str
    reader_binding: dict
    identity: P.CuScanIdentity
    family: P.NtagFamily
    page_identity_match: bool
    reader_crc_check_succeeded: bool
    steps_complete: bool


@dataclass(frozen=True, repr=False)
class CuRead:
    identity: P.CuScanIdentity
    family: P.NtagFamily
    total_pages: int
    pages: tuple
    pages_observed: int
    read_complete: bool
    stop_reason: str | None
    reader_binding: dict
    profile: str
    physical_same_tag_verified: bool = False
    device_command_termination_verified: bool = False
    rf_off_verified: bool = False


@dataclass(frozen=True)
class CuCloseResult:
    workers_stopped: bool
    transport_closed: bool
    lease_closed: bool
    cleanup_confirmed: bool
    device_command_termination_verified: bool = False
    rf_off_verified: bool = False
    reason: str | None = None

    def to_dict(self):
        return asdict(self)


class CuUse:
    """예약은 caller, claim 뒤 I/O·완료 통지는 worker가 소유한다."""
    def __init__(self, owner, opening, cancel):
        self.owner, self.opening, self._external = owner, opening, cancel
        self._handoff = portlock.LeaseHandoff()
        self._cancel = threading.Event()
        self._claimed = self._finished = False
        self._thread_id = None

    def claim(self):
        with self.owner._condition:
            if not self._handoff.claim_worker():
                return False
            self._claimed, self._thread_id = True, threading.get_ident()
            try:
                if self.owner._closing or self.cancelled():
                    self.finish()
                    return False
            except Exception:
                self.finish()
                raise
            return True

    def cancelled(self):
        if self._cancel.is_set():
            return True
        if self._external is None:
            return False
        try:
            value = self._external()
        except Exception:
            raise error() from None
        if type(value) is not bool:
            raise error()
        return value

    def check(self, deadline):
        if self.cancelled() or self.owner._closing:
            raise error('cancelled')
        if time.monotonic() >= deadline:
            raise error('time_limit')
        if (not self._claimed or self._finished or self._thread_id != threading.get_ident()
                or self.owner.state in ('terminal', 'closed', 'cleanup_pending')):
            raise error()

    def cancel(self):
        with self.owner._condition:
            if self._finished:
                return
            self._cancel.set()
            if self._claimed and self.owner._transport is not None:
                with contextlib.suppress(Exception):
                    self.owner._transport.cancel_read()
            if self._handoff.abandon_caller():
                self.finish()

    def finish(self):
        with self.owner._condition:
            if not self._finished:
                if self._claimed and self._thread_id != threading.get_ident():
                    raise error()
                self._finished = True
                self.owner._uses.discard(self)
                self.owner._condition.notify_all()


class CuOwner:
    """재연결 없는 owner. 물리 정리 미확인 owner와 lease는 registry에 남긴다."""
    def __init__(self, runtime, case, route, keys, basis):
        self._runtime, self._case_id, self._route = runtime, case.id, route
        self._keys, self._basis, self._session_id = keys, basis, uuid.uuid4().hex
        self._lease = self._transport = self._device = None
        self._decoder = P.CuDecoder()
        self._state = 'awaiting_approval'
        self._condition = threading.Condition(threading.RLock())
        self._uses = set()
        self._closing = False
        self._cleanup_thread = None
        self._cleanup_done = threading.Event()
        self._cleanup_failed = False

    case_id = property(lambda self: self._case_id)
    session_id = property(lambda self: self._session_id)
    route = property(lambda self: self._route)
    keys = property(lambda self: self._keys)
    state = property(lambda self: self._state)

    @property
    def action(self):
        return {'port': self.route.device_path, 'route': self.route.approval_identity(),
                'profile': P.PROFILE, 'profile_sha256': P.PROFILE_SHA256,
                'parent': self.route.identity.usb_ancestor, 'scope_keys': list(self.keys),
                'cdc_basis': self._basis, 'interface_number': self.route.identity.interface_number,
                'reset_risk': self.route.reset_risk, 'baudrate': 115200, 'dtr': True, 'rts': False}

    def reserve_use(self, *, opening=False, cancel=None):
        with self._condition:
            if type(opening) is not bool or (cancel is not None and not callable(cancel)):
                raise error('nfc_input_invalid')
            if self._closing or self.state in ('terminal', 'closed', 'cleanup_pending'):
                raise error()
            if self._uses or self.state != ('awaiting_approval' if opening else 'ready'):
                raise error('busy')
            use = CuUse(self, opening, cancel)
            self._uses.add(use)
            return use

    def _terminal(self):
        self._decoder.abort()
        with self._condition:
            if self.state not in ('closed', 'cleanup_pending'):
                self._state = 'terminal'

    def _fresh(self, use, end):
        use.check(end)
        self._runtime.case(self.case_id, hardware=True)
        route = ports.revalidate(self.route, env=_environment(self._runtime), config=self._runtime.config)
        _identity(route)
        keys = _scope(self._runtime, route)
        if (route._binding() != self.route._binding() or keys != self.keys
                or _identity(route, keys) != self._basis or self._lease.keys != self.keys):
            raise error('route_changed')
        self._lease.assert_held(keys)
        _roles(self._runtime, route, 'pre-io')
        use.check(end)

    def _request(self, use, kind, end, *, family=None, page=None, last=False):
        """고정 enum/phase만 wire로 만든다. 외부 raw frame 입력은 없다."""
        end = min(end, time.monotonic() + COMMAND_SECONDS)
        self._fresh(use, end)
        waiting = self._transport.in_waiting
        if type(waiting) is not int or waiting != 0 or self._decoder.buffered_bytes or self._decoder.terminal:
            raise error()
        if type(kind) is P.CuQuery:
            wire = P.build_cu_query(kind)
            expected = kind.value
        elif kind == 'version':
            wire, expected = P.build_ntag_version(keep_field=True), 2010
        elif kind == 'read':
            wire, expected = P.build_ntag_read(family, page, last=last), 2010
        else:
            raise error()
        position = 0
        while position < len(wire):
            use.check(end)
            count = self._transport.write(wire[position:])
            if type(count) is not int or not 0 <= count <= len(wire) - position:
                raise error()
            position += count
            if count == 0:
                use._cancel.wait(.002)
        while True:
            use.check(end)
            size = min(4096, P.MAX_BUFFER_BYTES - self._decoder.buffered_bytes)
            block = self._transport.read(size)
            if type(block) is not bytes or not 0 <= len(block) <= size:
                raise error()
            if not block:
                if not self._transport.is_open:
                    self._decoder.eof()
                use._cancel.wait(.002)
                continue
            frames = self._decoder.feed(block)
            if frames:
                if len(frames) != 1 or self._decoder.buffered_bytes or frames[0].command != expected:
                    raise error()
                waiting = self._transport.in_waiting
                if type(waiting) is not int or waiting != 0:
                    raise error()
                use.check(end)
                return frames[0]

    def start(self, use, *, deadline):
        try:
            end = _end(deadline, START_SECONDS)
            if use.owner is not self or not use.opening or self.state != 'awaiting_approval':
                raise error()
            use.check(end)
            self._state = 'opening'
            self._lease.set_state('opening')
            try:
                self._transport = serialtransport.open_serial(self.route,
                    serialtransport.SerialSettings(timeout=.05, write_timeout=2, dtr=True, rts=False),
                    lease=self._lease, before_io=lambda: self._fresh(use, end))
            except serialtransport.SerialOpenError as exc:
                self._transport = exc.transport
                raise error('cu_cleanup_unknown') from None
            use.check(end)
            replies = tuple(self._request(use, kind, end) for kind in
                (P.CuQuery.APP_VERSION, P.CuQuery.GIT_VERSION, P.CuQuery.DEVICE_MODEL, P.CuQuery.DEVICE_MODE))
            self._device = P.parse_cu_device(replies)
            use.check(end)
            self._lease.set_state('open')
            self._state = 'ready'
            return self._device
        except Exception as exc:
            self._terminal()
            raise public_error(exc) from None

    def _mode(self, use, end):
        frame = self._request(use, P.CuQuery.DEVICE_MODE, end)
        if frame.status != 0x68 or frame.data != b'\x01':
            raise error('cu_reader_required')

    def _read_page(self, use, family, page, end, *, last):
        frame = self._request(use, 'read', end, family=family, page=page, last=last)
        if frame.status != 0 or len(frame.data) != 16:
            raise error('nfc_scan_invalid')
        return frame.data[:4]

    def _admit(self, use, end, *, reading, expected=None):
        if use.owner is not self or use.opening or self.state != 'ready':
            raise error()
        self._mode(use, end)
        identity = P.parse_cu_scan(self._request(use, P.CuQuery.SCAN_14A, end))
        # expected는 inventory의 내부 identity뿐이며 MCP가 UID/family를 받지 않는다.
        if expected is not None and (identity.uid, identity.atqa_msb, identity.sak) != (
                expected.uid, expected.atqa_msb, expected.sak):
            raise error('nfc_identity_mismatch')
        family = P.parse_ntag_version(self._request(use, 'version', end))
        if expected is not None and family.mifare_version != expected.mifare_version:
            raise error('nfc_identity_mismatch')
        first = self._read_page(use, family, 0, end, last=False)
        second = self._read_page(use, family, 1, end, last=not reading)
        if first[:3] + second != identity.uid or first[3] != (0x88 ^ first[0] ^ first[1] ^ first[2]):
            raise error('nfc_identity_mismatch')
        return identity, family, (first, second)

    def _binding(self):
        return {**self.route.approval_identity(), 'scope_keys': list(self.keys)}

    def probe_ntag(self, use, *, deadline):
        try:
            end = _end(deadline, OPERATION_SECONDS)
            identity, family, _ = self._admit(use, end, reading=False)
            use.check(end)
            return CuProbe(self.session_id, self._binding(), identity, family, True, True, True)
        except Exception as exc:
            self._terminal()
            raise public_error(exc) from None

    def read_ntag(self, use, expected_identity, *, deadline):
        try:
            from pweh.nfc_formats import _NfcFileIdentity
            if type(expected_identity) is not _NfcFileIdentity:
                raise error('nfc_input_invalid')
            end = _end(deadline, OPERATION_SECONDS)
            identity, family, initial = self._admit(use, end, reading=True, expected=expected_identity)
            pages = list(initial) + [None] * (family.pages_total - 2)
        except Exception as exc:
            self._terminal()
            raise public_error(exc) from None
        reason = None
        try:
            for page in range(2, family.pages_total):
                pages[page] = self._read_page(use, family, page, end, last=page == family.pages_total - 1)
            use.check(end)
        except Exception as exc:
            self._terminal()
            reason = public_error(exc).code
        return CuRead(identity, family, family.pages_total, tuple(pages),
                      sum(value is not None for value in pages), reason is None,
                      reason, self._binding(), P.PROFILE)

    def _cleanup(self):
        try:
            with self._condition:
                while self._uses:
                    self._condition.wait(.05)
            if self._transport is not None:
                try:
                    self._transport.close()
                except Exception:
                    pass
                if self._transport.closed is not True:
                    return
            if self._lease is not None:
                try:
                    self._lease.close()
                except Exception:
                    pass
                if self._lease.closed is not True:
                    return
            with self._condition:
                self._state = 'closed'
            with _LOCK:
                if _REGISTRY.get(self.case_id) is self:
                    del _REGISTRY[self.case_id]
        except Exception:
            self._cleanup_failed = True
        finally:
            self._cleanup_done.set()

    def close(self, *, deadline):
        end = _end(deadline, CLOSE_SECONDS)
        with self._condition:
            self._closing = True
            for use in tuple(self._uses):
                use.cancel()
            if self.state != 'closed':
                self._state = 'cleanup_pending'
                if self._cleanup_thread is None or not self._cleanup_thread.is_alive():
                    self._cleanup_done.clear()
                    self._cleanup_failed = False
                    self._cleanup_thread = threading.Thread(target=self._cleanup, daemon=True,
                                                            name='cu-cleanup')
                    try:
                        self._cleanup_thread.start()
                    except Exception:
                        self._cleanup_failed = True
                        self._cleanup_done.set()
            worker = self._cleanup_thread
        if worker is not None and worker.ident is not None and worker is not threading.current_thread():
            worker.join(max(0, end - time.monotonic()))
        with self._condition:
            stopped = not self._uses and (worker is None or not worker.is_alive())
            physical = self._transport is None or self._transport.closed is True
            released = self._lease is None or self._lease.closed is True
            confirmed = stopped and physical and released
            reason = (None if confirmed else 'worker_pending' if not stopped else
                      'transport_close_unconfirmed' if not physical else
                      'lease_close_unconfirmed' if not released else 'cleanup_failed')
            if self._cleanup_failed and not confirmed:
                reason = 'cleanup_failed'
            return CuCloseResult(stopped, physical, released, confirmed, reason=reason)


def prepare_cu_session(runtime, case, port):
    """route와 전체 scope를 검증하고 미개방 lease를 strong registry에 인계한다."""
    with _LOCK:
        if case.id in _REGISTRY or case.id in _PREPARING or len(_REGISTRY) + len(_PREPARING) >= 16:
            raise error('busy')
        _PREPARING.add(case.id)
    owner = None
    try:
        case.require_authorization()
        route = _resolve(runtime, port)
        _identity(route)
        _roles(runtime, route, 'preflight')
        keys = _scope(runtime, route)
        basis = _identity(route, keys)
        owner = CuOwner(runtime, case, route, keys, basis)
        owner._lease = portlock.get_manager().acquire(keys, owner=portlock.PortOwner(
            server='pweh-nfc', case_id=case.id, ref=route.ref, role='instrument',
            session_id=owner.session_id), state='awaiting_approval')
        with _LOCK:
            _REGISTRY[case.id] = owner
        return owner
    except Exception as exc:
        raise public_error(exc) from None
    finally:
        with _LOCK:
            _PREPARING.discard(case.id)


def get_cu_session(case_id, session_id):
    with _LOCK:
        owner = _REGISTRY.get(case_id)
    if owner is None or type(session_id) is not str or session_id != owner.session_id:
        raise error('nfc_input_invalid')
    return owner


def close_cu_session(case_id, session_id, *, deadline):
    return get_cu_session(case_id, session_id).close(deadline=deadline)
