"""실제 포트 없이 공통 SerialTransport에 연결하는 독립 CU wire fixture."""
from __future__ import annotations

import stat
import threading
import time
from types import SimpleNamespace

import pytest

from pweh import ports, serialtransport
from pweh.portidentity import PortIdentity
from pweh.runtime import get_runtime
from nfc_mcp import cu_owner as S

UID = bytes.fromhex('04112233445566')
VERSIONS = {213: bytes.fromhex('0004040201000f03'),
            215: bytes.fromhex('0004040201001103'),
            216: bytes.fromhex('0004040201001303')}
TOTALS = {213: 45, 215: 135, 216: 231}
# 1000 APP·1017 GIT 응답. dev는 v2.3.0과 APP·명령표가 같고 GIT 문자열만 다르다.
FIRMWARES = {'v2.3.0': (b'\x02\x03', b'v2.3.0'), 'v2.2.0': (b'\x02\x02', b'v2.2.0'),
             'dev': (b'\x02\x03', b'v2.3.0-14-g4c5bc2c')}
# NTAG와 같은 UID7/ATQA 0044/SAK 00을 보이지만 GET_VERSION에서 갈리는 태그의 (status, data).
TAG_MODELS = {'mf0icu1-nak': (0x00, b''), 'mf0icu1-timeout': (0x01, b''),
              'mf0icu2-crc': (0x03, b''), 'ul-ev1': (0x00, bytes.fromhex('0004030101000b03'))}
# 공식 v2.3.0의 인증·쓰기·키 변경·BLE PIN·고정 식별자·모드·field 직접 제어 명령. 어떤 경로도 보내면 안 된다.
DENIED = frozenset((1001, 1011, 1012, 1031, 1034, 2016, 2018, 2019, 2021, 2022, 2100, 2101, 3021))
RAW_OPTIONS = frozenset((0xf4, 0xfc, 0xec, 0xe4))
VERSION_WIRE = bytes.fromhex('f40064000860')
_CREATED = []


def frame(command, data=b'', *, status=0x68):
    header = b'\x11\xef' + command.to_bytes(2, 'big') + status.to_bytes(2, 'big') + len(data).to_bytes(2, 'big')
    body = header + bytes((-sum(header) & 255,)) + data
    return body + bytes((-sum(body) & 255,))


def scan_bytes(*, uid=UID, atqa=b'\x44\x00', sak=b'\x00', ats=b''):
    return bytes((len(uid),)) + uid + atqa + sak + bytes((len(ats),)) + ats


class FakeCu:
    """field 상태는 write()에서 option byte로만 갱신한다. 사용자 정의 응답도 이 규칙을 우회하지 못한다.

    위반은 owner가 고정 오류로 감싸 숨길 수 있으므로 violations에 남기고 fixture 정리에서 검사한다.
    """
    def __init__(self, *, family=213, chunk=17, write_chunk=4096, firmware='v2.3.0', tag=None):
        self.family, self.chunk, self.write_chunk = family, chunk, write_chunk
        self.app, self.git = FIRMWARES[firmware]
        self.tag = tag
        self.scan_data = scan_bytes()
        self.version_status, self.version = (0, VERSIONS[family]) if tag is None else TAG_MODELS[tag]
        self.pages = [bytes((index, 0x42, 0, 255)) for index in range(TOTALS[family])]
        self.pages[0] = UID[:3] + bytes((0x88 ^ UID[0] ^ UID[1] ^ UID[2],))
        self.pages[1] = UID[3:]
        self.buffer, self.input = bytearray(), bytearray()
        self.writes, self.commands, self.frames, self.read_sizes = [], [], [], []
        self.responses = {}
        self.violations, self.field_log = [], []
        self.is_open = False
        self.close_verified, self.close_error = True, False
        self.open_calls = self.close_calls = self.cancel_calls = 0
        self.before_open = self.before_read = self.before_write = self.before_close = None
        self.field = False
        self._lock = threading.RLock()
        _CREATED.append(self)

    @property
    def cleanup_verified(self):
        return not self.is_open and self.close_verified

    @property
    def in_waiting(self):
        return len(self.buffer)

    def fileno(self):
        return 123456

    def open(self):
        self.open_calls += 1
        if self.before_open:
            self.before_open()
        self.is_open = True

    def read(self, size):
        self.read_sizes.append(size)
        if self.before_read:
            self.before_read(size)
        with self._lock:
            count = min(size, self.chunk, len(self.buffer))
            result = bytes(self.buffer[:count])
            del self.buffer[:count]
            return result

    def violation(self, text):
        self.violations.append(text)
        raise AssertionError(text)

    def reads(self):
        """기록된 0x30 READ 요청 payload 목록."""
        return [data for cmd, data in self.commands if cmd == 2010 and len(data) == 7 and data[5] == 0x30]

    def _before(self, command, payload):
        """firmware의 activate/auto-select 처리를 응답 계산 전에 반영한다."""
        if command in DENIED:
            self.violation('거부 목록 명령 송신')
        if command != 2010:
            return
        if len(payload) < 5 or payload[0] not in RAW_OPTIONS:
            self.violation('고정 option 이외 RAW')
        option = payload[0]
        if option & 0x10:
            self.field = True
        elif not self.field:
            self.violation('field가 꺼진 상태의 비선택 RAW')

    def _after(self, command, payload):
        """응답 내용과 무관하게 keep=0 RAW와 scan 뒤 field를 끈다. keep=1 실패는 켜진 채 남는다."""
        if command == 2000:
            self.field = False
        elif command == 2010 and payload and not payload[0] & 0x08:
            self.field = False
        self.field_log.append((command, payload[:1], self.field))

    def write(self, data):
        if self.before_write:
            self.before_write(data)
        count = min(len(data), self.write_chunk)
        block = data[:count]
        self.writes.append(block)
        with self._lock:
            self.input.extend(block)
            while len(self.input) >= 9:
                size = int.from_bytes(self.input[6:8], 'big') + 10
                if len(self.input) < size:
                    break
                wire = bytes(self.input[:size])
                del self.input[:size]
                if not (wire[:2] == b'\x11\xef' and sum(wire[:9]) % 256 == 0 and sum(wire) % 256 == 0
                        and wire[4:6] == b'\x00\x00'):
                    self.violation('손상된 요청 frame')
                command, payload = int.from_bytes(wire[2:4], 'big'), wire[9:-1]
                self.frames.append(wire)
                self.commands.append((command, payload))
                self._before(command, payload)
                try:
                    custom = self.responses.get((command, payload), self.responses.get(command))
                    response = (custom(command, payload) if callable(custom) else custom) if custom is not None else self.response(command, payload)
                finally:
                    self._after(command, payload)
                if response is not None:
                    self.buffer.extend(response)
        return count

    def response(self, command, payload):
        queries = {1000: self.app, 1017: self.git, 1033: b'\x00', 1002: b'\x01'}
        if command in queries:
            if payload != b'':
                self.violation('조회 payload')
            return frame(command, queries[command])
        if command == 2000:
            if payload != b'':
                self.violation('scan payload')
            return frame(command, self.scan_data, status=0)
        if command == 2010 and payload == VERSION_WIRE:
            return frame(command, self.version, status=self.version_status)
        if command == 2010 and len(payload) == 7 and payload[1:6] == bytes.fromhex('0064001030'):
            if payload[0] not in (0xfc, 0xec, 0xe4) or (payload[0] == 0xfc) != (payload[6] == 0):
                self.violation('READ0 이외 선택 또는 선택 없는 READ0')
            if self.tag is not None:
                self.violation('NTAG가 아닌 태그에 READ')
            if payload[6] >= len(self.pages):
                self.violation('범위 밖 page')
            # 뒤 12B는 다음 페이지와 일부러 달라 첫 4B 귀속만 검사할 수 있다.
            data = self.pages[payload[6]] + b'UNTRUSTED123'
            return frame(command, data, status=0)
        self.violation('고정 명령 이외 송신')

    def cancel_read(self):
        self.cancel_calls += 1

    def close(self):
        self.close_calls += 1
        if self.before_close:
            self.before_close()
        if self.close_verified:
            self.is_open = False
        if self.close_error:
            raise OSError('PRIVATE_CLOSE_SENTINEL')


def configure(monkeypatch, runtime, case, *, fake=None, backend='posix-tty'):
    fake = fake or FakeCu()
    windows = backend == 'win-helper'
    port = 'COM4096' if windows else '/dev/ttyACM4096'
    parent = 'USB\\VID_6868&PID_8686\\CU_SYNTHETIC' if windows else 'devices/usb1/1-9'
    key = 'win:COM4096' if windows else 'tty:166:4096'
    node = 'USB\\VID_6868&PID_8686&MI_00\\CU_CHILD' if windows else parent + '/if00'
    identity = PortIdentity(key, 'known', present=True, backend='windows' if windows else 'linux',
        device_instance=node, parent_instance=parent, usb_ancestor=parent, vid='6868', pid='8686',
        interface_number='00', serial='CU_SYNTHETIC', serial_basis='instance-tail' if windows else 'sysfs')
    route = ports.PortRoute(port, 'serial-session', backend, 'windows' if windows else 'linux',
        port, key, 'synthetic-cu/00', identity, 'serial', 'unknown',
        node_identity=None if windows else (1, 2, 3))
    keys = tuple(sorted((key, 'synthetic-cu-whole', 'synthetic-cu-sibling')))
    context = SimpleNamespace(runtime=runtime, case=case, fake=fake, route=route, keys=keys,
        port=port, opens=[], fresh_calls=[], owners=[])
    monkeypatch.setattr(S, '_environment', lambda r: {'kind': 'SYNTHETIC'})
    monkeypatch.setattr(S, '_resolve', lambda r, p: context.route)
    monkeypatch.setattr(S, '_scope', lambda r, fresh: context.keys)
    monkeypatch.setattr(S, 'guard_target_port', lambda *a, **kw: None)
    def fresh(old, **kwargs):
        context.fresh_calls.append(old)
        return context.route
    monkeypatch.setattr(S.ports, 'revalidate', fresh)
    real_open = serialtransport.open_serial
    def opened(route, settings, *, lease, before_io):
        context.opens.append(settings)
        def raw_factory(*args, **kwargs):
            return context.fake
        def helper_factory(*, before_open, **kwargs):
            previous = context.fake.before_open
            def before():
                before_open()
                if previous:
                    previous()
            context.fake.before_open = before
            return context.fake
        return real_open(route, settings, lease=lease, before_io=before_io,
            serial_factory=raw_factory, helper_factory=helper_factory, ioctl_fn=lambda *a: None,
            fstat_fn=lambda fd: SimpleNamespace(st_mode=stat.S_IFCHR, st_dev=1, st_ino=2, st_rdev=3))
    monkeypatch.setattr(S.serialtransport, 'open_serial', opened)
    def prepare():
        owner = S.prepare_cu_session(runtime, case, port)
        context.owners.append(owner)
        return owner
    def connect():
        owner = prepare()
        use = owner.reserve_use(opening=True)
        assert use.claim()
        try:
            owner.start(use, deadline=time.monotonic() + 5)
        finally:
            use.finish()
        return owner
    context.prepare, context.connect = prepare, connect
    return context


@pytest.fixture
def setup(workspace, auth, monkeypatch, request):
    _CREATED.clear()
    runtime = get_runtime('cu-test')
    case = runtime.cases.create(title='합성 CU', authorization=auth)
    context = configure(monkeypatch, runtime, case, backend=getattr(request, 'param', 'posix-tty'))
    context.workspace = workspace
    yield context
    context.fake.before_read = context.fake.before_write = context.fake.before_close = None
    context.fake.close_verified = True
    for owner in tuple(S._REGISTRY.values()):
        for use in tuple(owner._uses):
            use.cancel()
            if not use._claimed or use._thread_id == threading.get_ident():
                use.finish()
        owner.close(deadline=time.monotonic() + 1)
    # owner가 고정 오류로 감싼 fixture 위반도 시험 실패로 드러낸다.
    violations = [text for fake in _CREATED for text in fake.violations]
    _CREATED.clear()
    assert violations == []
