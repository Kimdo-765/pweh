"""CU 고정 읽기 결과를 두 commit의 실제 receipt와 함께 보존한다."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
import threading
import time

from pweh import cu_protocol as P, nfc_cu_snapshot as N, nfc_inventory as I, safeio, schemas
from pweh.case import Case
from pweh.errors import PwehError
from pweh.jobs import JobCancelled
from pweh.safety.attestations import canonical_json

from .cu_owner import CuOwner, CuRead, get_cu_session, _CODES as CU_CODES

WIRE_SECONDS = 45.0
HOST_SECONDS = 5.0
MAX_BYTES = 65536
SOURCE = {'server': 'nfc-mcp', 'tool': 'nfc_cu_read_start'}
WARNINGS = ('provenance_close_unconfirmed', 'artifact_registration_incomplete',
            'post_commit_callback_failed', 'output_close_unconfirmed')
_CODES = CU_CODES | frozenset(('nfc_failed', 'nfc_input_limit', 'nfc_scan_required',
    'nfc_provenance_invalid', 'nfc_snapshot_invalid', 'nfc_source_mismatch',
    'nfc_artifact_registration_failed', 'nfc_cleanup_pending'))


def _error(code='nfc_failed'):
    return PwehError('CU 읽기 산출물을 완료하지 못했습니다.', code=code if code in _CODES else 'nfc_failed')


def _fixed(exc, *, artifact=False):
    code = getattr(exc, 'code', '')
    if isinstance(exc, JobCancelled) or code == 'cancelled':
        return JobCancelled()
    if code in ('lock_timeout', 'artifact_timeout'):
        code = 'time_limit'
    elif code == 'provenance_bounded_limit':
        code = 'nfc_input_limit'
    elif type(code) is str and code.startswith('provenance_'):
        code = 'nfc_provenance_invalid'
    if code not in _CODES:
        code = 'nfc_artifact_registration_failed' if artifact else 'nfc_failed'
    return _error(code)


def _binding(bound):
    return {key: getattr(bound, key) for key in N.BINDING_FIELDS}


def _entry_hash(entry):
    return hashlib.sha256(canonical_json(entry).encode('utf-8')).hexdigest()


def _dir_seal(st):
    return st.st_dev, st.st_ino, st.st_mode, st.st_uid


def _file_seal(st):
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_nlink


class _Output:
    """확인한 root/parent/name/FD만 정리하며 원장 commit 뒤에는 파일을 보존한다."""
    def __init__(self, case, check, deadline):
        self.case, self.check = case, check
        self.root = self.parent = self.fd = self.identity = self.name = self.seal = None
        self.path = self.size = self.sha256 = None
        try:
            check()
            self.root = safeio._walk_directory(str(case.dir), deadline=deadline)
            self.root_seal = _dir_seal(os.fstat(self.root))
            try:
                os.mkdir('nfc', 0o700, dir_fd=self.root)
            except FileExistsError:
                pass
            self.parent = os.open('nfc', safeio.DIR_FLAGS, dir_fd=self.root)
            self.parent_seal = _dir_seal(os.fstat(self.parent))
            self.directories()
        except Exception:
            self.close()
            raise

    def directories(self):
        root = os.stat(self.case.dir, follow_symlinks=False)
        parent = os.stat('nfc', dir_fd=self.root, follow_symlinks=False)
        if (not stat.S_ISDIR(root.st_mode) or not stat.S_ISDIR(parent.st_mode)
                or _dir_seal(root) != self.root_seal or _dir_seal(os.fstat(self.root)) != self.root_seal
                or _dir_seal(parent) != self.parent_seal or _dir_seal(os.fstat(self.parent)) != self.parent_seal):
            raise _error('nfc_source_mismatch')

    def verify(self):
        self.check()
        self.directories()
        if self.fd is not None and self.seal is not None:
            held = os.fstat(self.fd)
            named = os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)
            if (not stat.S_ISREG(held.st_mode) or held.st_nlink != 1 or held.st_mode & 0o222
                    or _file_seal(held) != self.seal or _file_seal(named) != self.seal):
                raise _error('nfc_source_mismatch')

    def digest(self):
        self.verify()
        digest, position = hashlib.sha256(), 0
        while position < self.size:
            self.check()
            block = os.pread(self.fd, min(MAX_BYTES, self.size - position), position)
            if type(block) is not bytes or not 0 < len(block) <= min(MAX_BYTES, self.size - position):
                raise _error('nfc_source_mismatch')
            digest.update(block)
            position += len(block)
        self.verify()
        if digest.hexdigest() != self.sha256:
            raise _error('nfc_source_mismatch')

    def write(self, data):
        self.size, self.sha256 = len(data), hashlib.sha256(data).hexdigest()
        for number in range(1, 100000):
            self.check()
            self.directories()
            name = f'cu-read-{number:03d}.json'
            try:
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=self.parent)
            except FileExistsError:
                continue
            self.fd, self.name, self.path = fd, name, f'nfc/{name}'
            self.identity = os.fstat(fd)
            break
        if self.fd is None:
            raise _error('nfc_input_limit')
        position = 0
        while position < self.size:
            self.check()
            n = os.write(self.fd, data[position:position + MAX_BYTES])
            if type(n) is not int or not 0 < n <= min(MAX_BYTES, self.size - position):
                raise _error('nfc_failed')
            position += n
        os.fchmod(self.fd, 0o444)
        os.fsync(self.fd)
        self.seal = _file_seal(os.fstat(self.fd))
        self.digest()

    def remove(self):
        if self.fd is None:
            return True
        try:
            self.directories()
            if self.identity is None:
                return False
            named = os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)
            if not safeio.same_file(named, self.identity) or not safeio.same_file(os.fstat(self.fd), self.identity):
                return False
            os.unlink(self.name, dir_fd=self.parent)
            return True
        except Exception:
            return False

    def close(self):
        confirmed = True
        for key in ('fd', 'parent', 'root'):
            fd = getattr(self, key)
            if fd is not None:
                try:
                    os.close(fd)
                except Exception:
                    confirmed = False
                setattr(self, key, None)
        return confirmed


def _snapshot(read, owner, bound, deadline, cancel):
    if type(read) is not CuRead:
        raise _error('nfc_snapshot_invalid')
    if read.read_complete is not True and read.stop_reason not in ('time_limit', 'nfc_scan_invalid'):
        raise _error(read.stop_reason)
    if (type(read.family) is not P.NtagFamily or type(read.identity) is not P.CuScanIdentity
            or read.profile != P.PROFILE or read.reader_binding != owner._binding()
            or any(getattr(read, key) is not False for key in ('physical_same_tag_verified',
                    'device_command_termination_verified', 'rf_off_verified'))):
        raise _error('nfc_snapshot_invalid')
    I._reader_binding(read.reader_binding)
    snapshot = {'schema': 'pweh.nfc-cu-snapshot/v1', 'profile': 'cu-ntag21x-pages-v1',
        'binding': _binding(bound), 'reader': {'profile': P.PROFILE, 'profile_sha256': P.PROFILE_SHA256,
            'firmware_commit': P.FIRMWARE_COMMIT, 'app_version': P.FIRMWARE_VERSION,
            'git_version': P.FIRMWARE_GIT_VERSION},
        'identity': {'family': read.family.family, 'uid': read.identity.uid.hex(),
            'atqa_msb': read.identity.atqa_msb.hex(), 'sak': read.identity.sak.hex(),
            'mifare_version': read.family.mifare_version.hex()},
        'pages_total': read.total_pages, 'pages': [page.hex() if type(page) is bytes else page for page in read.pages],
        'pages_observed': read.pages_observed, 'read_complete': read.read_complete, 'stop_reason': read.stop_reason,
        'unobserved_fields': list(N.UNOBSERVED_FIELDS), **{key: False for key in N.FALSE_FIELDS}}
    schemas.validate('nfc-cu-snapshot', snapshot)
    data = (json.dumps(snapshot, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')
    if not 0 < len(data) <= MAX_BYTES:
        raise _error('nfc_snapshot_invalid')
    parsed = N.parse_cu_snapshot(data, deadline=deadline, cancel=cancel)
    if dict(parsed.binding) != _binding(bound) or parsed.family != bound.family:
        raise _error('nfc_source_mismatch')
    I.match_file_identity(bound, parsed.identity)
    return data


class CuReadWork:
    """gate 앞 예약과 worker claim을 기존 CuUse에 한 번만 이관한다."""
    def __init__(self, runtime, case, owner, bound, event):
        self.runtime, self.case, self.owner, self.bound = runtime, case, owner, bound
        self._event, self._cancel = event, threading.Event()
        self._lock = threading.Lock()
        self._context = None
        self._started = self._finished = False
        self._action = copy.deepcopy(owner.action)
        self._action.update(operation='ntag_read', session_id=owner.session_id, family=bound.family,
                            pages_total=P.NtagFamily(int(bound.family[4:])).pages_total)
        self._action.update({key: value for key, value in _binding(bound).items() if key != 'identity_digest'})
        self.use = owner.reserve_use(cancel=self.cancelled)

    @property
    def action(self):
        return copy.deepcopy(self._action)

    def cancelled(self):
        with self._lock:
            context = self._context
        return self._event.is_set() or self._cancel.is_set() or context is not None and context.cancelled

    def cancel(self):
        with self._lock:
            if self._finished:
                return
            self._cancel.set()
        self.use.cancel()

    def start(self):
        with self._lock:
            cancelled = self._cancel.is_set() or self._event.is_set()
            if self._started:
                raise _error('busy')
            self._started = True
        if cancelled:
            self.cancel()
            raise _error('cancelled')
        try:
            return self.runtime.jobs.start('nfc-cu-read', self._run, description='CU NTAG 읽기 snapshot',
                case_id=self.case.id, meta={'session_id': self.owner.session_id, 'tag_ref': self.bound.tag_ref,
                'scan_ref': self.bound.scan_ref}, exclusive_key=f'nfc-cu-read:{self.case.id}:{self.owner.session_id}')
        except Exception as exc:
            self.cancel()
            raise _fixed(exc) from None

    def _run(self, j):
        wire_end = time.monotonic() + WIRE_SECONDS
        with self._lock:
            self._context = j
        output = ledger = artifact = read = failure = None
        claimed = False
        warnings = set()

        def receipt():
            return {'ok': artifact is not None, 'registered': artifact is not None,
                'status': 'ok' if read.read_complete else 'partial',
                'artifact': {'artifact_id': artifact['id'] if artifact is not None else None,
                             'path': output.path, 'size': output.size, 'sha256': output.sha256},
                'provenance': {'kind': 'device-read', 'ledger_seq': ledger['seq'],
                               'ledger_entry_sha256': _entry_hash(ledger)},
                'tag_ref': self.bound.tag_ref, 'family': self.bound.family, 'pages_total': read.total_pages,
                'pages_observed': read.pages_observed, 'read_complete': read.read_complete,
                'stop_reason': read.stop_reason, 'inventory_binding_verified': True,
                'physical_same_tag_verified': False, 'warnings': [key for key in WARNINGS if key in warnings]}

        def control(end):
            if self.use.cancelled():
                raise _error('cancelled')
            if time.monotonic() >= end:
                raise _error('time_limit')
            self.runtime.case(self.case.id, hardware=True)

        def inventory(end, check):
            entries = self.runtime.provenance.entries(self.case, **I._bounds(end, check))
            I.check_inventory_entries(self.runtime, self.case, self.bound, entries, check=check)
            return entries

        try:
            claimed = self.use.claim()
            if not claimed:
                raise JobCancelled()
            inventory(wire_end, lambda: control(wire_end))
            read = self.owner.read_ntag(self.use, self.bound.identity, deadline=wire_end)
            host_end = time.monotonic() + HOST_SECONDS
            host_check = lambda: control(host_end)
            host_check()
            data = _snapshot(read, self.owner, self.bound, host_end, self.use.cancelled)
            output = _Output(self.case, host_check, host_end)
            output.write(data)
            extra = {'snapshot_profile': 'cu-ntag21x-pages-v1', 'reader_profile': P.PROFILE,
                'reader_profile_sha256': P.PROFILE_SHA256, 'firmware_commit': P.FIRMWARE_COMMIT,
                'session_id': self.owner.session_id, 'reader_binding': copy.deepcopy(read.reader_binding),
                'binding': _binding(self.bound), 'family': self.bound.family, 'pages_total': read.total_pages,
                'pages_observed': read.pages_observed, 'read_complete': read.read_complete, 'stop_reason': read.stop_reason}

            def before_append(entries):
                I.check_inventory_entries(self.runtime, self.case, self.bound, entries, check=output.verify)
                if any(entry.get('path') == output.path for entry in entries):
                    raise _error('nfc_source_mismatch')
                output.digest()

            # 이 check는 원장 잠금 안에서도 불린다. 원장 재조회는 하지 않는다.
            ledger = self.runtime.provenance.record_device_read(self.case, output.path, dict(SOURCE), extra,
                sha256=output.sha256, attestation_id=None, check_entries=before_append,
                **I._bounds(host_end, output.verify))
            if 'provenance_close_unconfirmed' in getattr(ledger, 'warnings', ()):
                warnings.add('provenance_close_unconfirmed')
            j.set_partial(receipt())

            def final(entry):
                entries = inventory(host_end, output.verify)
                latest = next((item for item in reversed(entries) if item.get('path') == output.path), None)
                if latest is None or latest != dict(ledger):
                    raise _error('nfc_source_mismatch')
                output.digest()
                expected = {'path': output.path, 'size': output.size, 'sha256': output.sha256, 'is_dir': False,
                            'kind': 'other', 'producer': 'pweh-nfc', 'extra': {'type': 'nfc-cu-snapshot'}}
                if any(type(entry.get(key)) is not type(value) or entry.get(key) != value for key, value in expected.items()):
                    raise _error('nfc_source_mismatch')
                if type(entry.get('id')) is not str or re.fullmatch(r'A-[0-9]{4,8}', entry['id']) is None:
                    raise _error('nfc_source_mismatch')
                output.verify()

            def committed(entry):
                nonlocal artifact
                artifact = dict(entry)
                j.mark_committed()
                j.set_partial(receipt())

            self.case.register_artifact(output.path, kind='other', producer='pweh-nfc',
                extra={'type': 'nfc-cu-snapshot'}, compute_hash=False, sha256=output.sha256,
                check=final, on_commit=committed, deadline=host_end, replace_existing=False)
            if artifact is None:
                raise _error('nfc_artifact_registration_failed')
        except Exception as exc:
            if artifact is not None:
                warnings.add('post_commit_callback_failed')
            else:
                failure = JobCancelled() if self.cancelled() else _fixed(exc, artifact=ledger is not None)
        finally:
            if output is not None:
                if ledger is None and not output.remove() and not isinstance(failure, JobCancelled):
                    failure = _error('nfc_cleanup_pending')
                if not output.close():
                    if ledger is not None:
                        warnings.add('output_close_unconfirmed')
                    elif not isinstance(failure, JobCancelled):
                        failure = _error('nfc_cleanup_pending')
            try:
                if claimed:
                    self.use.finish()
                else:
                    self.use.cancel()
            except Exception:
                if artifact is not None:
                    warnings.add('output_close_unconfirmed')
                elif not isinstance(failure, JobCancelled):
                    failure = _error('nfc_cleanup_pending')
            with self._lock:
                self._finished = True
        if ledger is not None:
            if artifact is None:
                warnings.add('artifact_registration_incomplete')
            result = receipt()
            j.set_partial(result)
            if artifact is not None:
                return result
        if failure is not None:
            raise failure from None
        raise _error() from None


def prepare_cu_read(runtime, case, owner, bound, *, cancel_event):
    """검증한 같은 케이스 owner의 사용권을 gate 앞에서 예약한다."""
    try:
        if (type(case) is not Case or type(owner) is not CuOwner or type(bound) is not I.BoundTag
                or type(cancel_event) is not threading.Event or owner._runtime is not runtime
                or owner.case_id != case.id or get_cu_session(case.id, owner.session_id) is not owner
                or bound.family not in ('ntag213', 'ntag215', 'ntag216')):
            raise _error('nfc_input_invalid')
        case.require_authorization()
        if (I._identity(bound.identity, scan=True) != bound.family
                or not I._matches(I._TAG, bound.tag_ref) or not I._matches(I._SCAN, bound.scan_ref)
                or not I._matches(I._DIGEST, bound.identity_digest)
                or not I._matches(I._SHA, bound.scan_entry_sha256)
                or not I._matches(I._SHA, bound.inventory_entry_sha256)
                or not I._uint(bound.scan_seq) or not I._uint(bound.inventory_seq)
                or bound.scan_seq >= bound.inventory_seq):
            raise _error('nfc_input_invalid')
        if cancel_event.is_set():
            raise _error('cancelled')
        return CuReadWork(runtime, case, owner, bound, cancel_event)
    except Exception as exc:
        raise _fixed(exc) from None
