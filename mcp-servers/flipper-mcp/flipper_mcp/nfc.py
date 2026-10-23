"""고정 3A probe·GET_VERSION과 생성 scratch 한 개만 처리한다."""
from __future__ import annotations

import hashlib
import re
import time
import uuid

from pweh.errors import PwehError
from pweh import flipper_cli as F

PROBE_SECONDS = 45
TEXT_SECONDS = 10
MAX_PROBE_BYTES = 4096
NFC_PROMPT = b'\r\n[\x1b[32mnfc\x1b[0m]>: '
_WELCOME = (b'\r\n\x1b[97mWelcome to NFC Command Line Interface!\r\n'
            b'Run `help` or `?` to list available commands\r\n\x1b[0m')


def _error(code='nfc_scan_invalid'):
    return PwehError('고정 NFC probe를 완료하지 못했습니다.', code=code)


def approval_action(owner):
    """생성 UUID를 제외한 고정 작업과 실제 연결 범위를 승인에 결속한다."""
    from pweh.nfc_inventory import PROFILE, PROFILE_SHA256
    return {**owner.action, 'operation': 'nfc_probe', 'nfc_profile': PROFILE,
            'nfc_profile_sha256': PROFILE_SHA256,
            'scratch_root': f'/ext/pweh/{owner.case_id}/',
            'scratch_basename': 'probe-<uuid32>.nfc', 'scratch_files': 1,
            'scratch_max_bytes': MAX_PROBE_BYTES,
            'sequence': 'iso14443-3a-select/fixed-get-version/remove-scratch'}


def _crc_a(data):
    """CRC-A의 초기값·반사 다항식으로 계산하며 wire에는 하위 바이트부터 둔다."""
    value = 0x6363
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x8408 if value & 1 else 0)
    return value.to_bytes(2, 'little')


def _raw_identity(body):
    from pweh.nfc_formats import _NfcFileIdentity
    # firmware 배열의 마지막 공백과 다음 label의 앞 공백을 각각 확인한다.
    match = re.fullmatch(
        rb'UID: ((?:[0-9A-F]{2} ){7}) ATQA: ([0-9A-F]{4}) SAK: ([0-9A-F]{2})\r\n'
        rb'Tx: ((?:[0-9A-F]{2} ){3})\r\nRx: ((?:[0-9A-F]{2} ){10})', body)
    if match is None:
        raise _error()
    uid, atqa, sak, tx, rx = (bytes.fromhex(value.decode('ascii')) for value in match.groups())
    if tx != b'\x60' + _crc_a(b'\x60') or _crc_a(rx[:8]) != rx[8:]:
        raise _error()
    return _NfcFileIdentity(uid=uid, atqa_msb=atqa[::-1], sak=sak,
                            mifare_version=rx[:8], profile='iso14443-3a')


def _motd(body):
    # 그림은 숫자/공백 19줄만 허용한다. 권위는 그림이 아니라 고정 접속 profile이다.
    prefix = b'\x1b[94m\r\n'
    if not body.startswith(prefix) or not body.endswith(_WELCOME):
        raise _error()
    art = body[len(prefix):-len(_WELCOME)]
    if not art.endswith(b'\r\n'):
        raise _error()
    lines = art[:-2].split(b'\r\n')
    if len(lines) != 19 or any(re.fullmatch(rb'[ 05]{1,64}', row) is None for row in lines):
        raise _error()


class _Wire:
    """한 probe의 고정 상태만 전송한다. 임의 command/parser 입력은 없다."""
    def __init__(self, owner, use, path, deadline):
        self.owner, self.use, self.path, self.deadline = owner, use, path, deadline
        self.state = 'top'

    def run(self, step):
        states = {'enter_probe': ('top',), 'dump': ('nfc_probe',),
                  'leave_probe': ('dumped',), 'enter_version': ('probe_top',),
                  'version': ('nfc_version',), 'leave_version': ('versioned',),
                  'remove': ('probe_top', 'version_top')}
        if step not in states or self.state not in states[step]:
            raise _error()
        end = min(self.deadline, time.monotonic() + TEXT_SECONDS)
        if step.startswith('enter') or step == 'remove':
            self.owner._exchange(self.use, 'loader', None, None, end)
        self.owner.fresh(self.use, end)
        if step.startswith('enter'):
            command, prompt = b'nfc', NFC_PROMPT
        elif step == 'dump':
            # NFC option parser는 인용을 제거하지 않는다. 생성 ASCII 경로만 사용한다.
            command, prompt = ('dump -p 14_3a -f ' + self.path).encode('ascii'), NFC_PROMPT
        elif step == 'version':
            command, prompt = b'raw -p 14a -s -c -d 60 -t 60000', NFC_PROMPT
        elif step.startswith('leave'):
            command, prompt = b'exit', F.PROMPT
        else:
            command = ('storage remove "' + self.path + '"').encode('ascii')
            prompt = F.PROMPT
        tx, pos = command + b'\r', 0
        while pos < len(tx):
            self.use.check(end)
            count = self.owner.transport.write(tx[pos:])
            if type(count) is not int or not 0 <= count <= len(tx) - pos:
                raise _error()
            if count == 0:
                self.use._cancel.wait(.002)
            pos += count
        data, echo = bytearray(), command + b'\r\n'
        while True:
            self.use.check(end)
            block = self.owner.transport.read(4096)
            if type(block) is not bytes or len(block) > 4096:
                raise _error()
            if not block:
                if not self.owner.transport.is_open:
                    raise _error()
                self.use._cancel.wait(.002)
                continue
            data.extend(block)
            if len(data) > 4096:
                raise _error('nfc_input_limit')
            take = min(len(data), len(echo))
            if data[:take] != echo[:take]:
                raise _error()
            if len(data) < len(echo):
                continue
            body = bytes(data[len(echo):])
            if len(body.split(b'\r\n')) > 32 or any(len(x) > 512 for x in body.split(b'\r\n')):
                raise _error('nfc_input_limit')
            index = body.find(prompt)
            if index < 0:
                continue
            if index + len(prompt) != len(body):
                raise _error()
            body = body[:index]
            self.use.check(end)
            break
        if step.startswith('enter'):
            _motd(body)
        elif step == 'dump':
            expected = (b'Dumping as "Iso14443-3a"\r\nDump saved to \''
                        + self.path.encode('ascii') + b'\'\r\n')
            if body != expected:
                raise _error()
        elif step == 'version':
            result = _raw_identity(body)
        elif body:
            raise _error('nfc_cleanup_pending' if step == 'remove' else 'nfc_scan_invalid')
        self.state = {'enter_probe': 'nfc_probe', 'dump': 'dumped', 'leave_probe': 'probe_top',
                      'enter_version': 'nfc_version', 'version': 'versioned',
                      'leave_version': 'version_top', 'remove': 'removed'}[step]
        return result if step == 'version' else None


def _entry(owner, use, root, name, deadline):
    result = owner.request(use, 'list', root, deadline=deadline)
    if result.get('listing_complete') is not True:
        raise _error('nfc_cleanup_pending')
    return next((row for row in result['entries'] if row['name'] == name), None)


def _read_probe(owner, use, path, expected, deadline):
    if expected is None or expected['type'] != 'file' or not 0 < expected['size'] <= MAX_PROBE_BYTES:
        raise _error('nfc_input_limit')
    data = bytearray()
    def sink(block):
        if (owner.cli.declared_size != expected['size']
                or len(data) + len(block) > MAX_PROBE_BYTES):
            raise _error('nfc_input_changed')
        data.extend(block)
    result = owner.request(use, 'read', path, sink, deadline=deadline)
    digest = owner.request(use, 'md5', path, deadline=deadline)['md5']
    if (result['declared_size'] != len(data) or len(data) != expected['size']
            or hashlib.md5(data).hexdigest() != digest):
        raise _error('nfc_input_changed')
    return bytes(data), digest


def probe(owner, use, case):
    """claim한 worker만 호출한다. 원문은 메모리/보호 scan fact 이외에 게시하지 않는다."""
    from pweh.nfc_formats import _inspect_nfc_bound
    from pweh.nfc_inventory import ScanObservation, VERSION_FAMILIES, record_flipper_scan
    end = time.monotonic() + PROBE_SECONDS
    root = F.remote_path(case.id, f'/ext/pweh/{case.id}/')
    name = 'probe-' + uuid.uuid4().hex + '.nfc'
    path = F.remote_path(case.id, root + name, file=True)
    try:
        if not owner.cli.ready or owner.device is None or case.id != owner.case_id:
            raise _error()
        if _entry(owner, use, root, name, end) is not None:
            raise _error('nfc_input_changed')
        wire = _Wire(owner, use, path, end)
        wire.run('enter_probe')
        wire.run('dump')
        wire.run('leave_probe')
        entry = _entry(owner, use, root, name, end)
        data, md5 = _read_probe(owner, use, path, entry, end)
        _, identity = _inspect_nfc_bound(data, deadline=end, cancel=use.cancelled)
        if identity is None or identity.profile != 'iso14443-3a':
            raise _error()
        denied = None
        if len(identity.uid) != 7 or identity.sak != b'\x00':
            denied = 'nfc_family_unsupported'
        else:
            wire.run('enter_version')
            fresh = wire.run('version')
            wire.run('leave_version')
            if (fresh.uid, fresh.atqa_msb, fresh.sak) != (identity.uid, identity.atqa_msb, identity.sak):
                denied = 'nfc_identity_mismatch'
            elif fresh.mifare_version not in VERSION_FAMILIES:
                denied = 'nfc_family_unsupported'
        # 정상 shell 상태에서만 자신이 만든 동일 파일의 확인·정리를 수행한다.
        if (_entry(owner, use, root, name, end) != entry
                or owner.request(use, 'md5', path, deadline=end)['md5'] != md5):
            raise _error('nfc_cleanup_pending')
        wire.run('remove')
        if _entry(owner, use, root, name, end) is not None:
            raise _error('nfc_cleanup_pending')
        if denied:
            raise _error(denied)
        owner.fresh(use, end)
        route = owner.route.approval_identity()
        observation = ScanObservation(session_id=owner.session_id,
            reader_binding={key: route[key] for key in ('backend', 'lock_key', 'device_id')} |
                           {'scope_keys': list(owner.keys)},
            identity=fresh, probe_sha256=hashlib.sha256(data).hexdigest(), probe_size=len(data),
            probe_identity_match=True, version_crc_valid=True, scratch_cleanup_confirmed=True)
        # commit 뒤에는 추가 wire/check 없이 receipt를 반환한다.
        return record_flipper_scan(owner.runtime, case, observation,
                                   deadline=end, cancel=use.cancelled).to_dict()
    except Exception:
        owner.terminal()
        raise
