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


def frame(command, data=b'', *, status=0x68):
    header = b'\x11\xef' + command.to_bytes(2, 'big') + status.to_bytes(2, 'big') + len(data).to_bytes(2, 'big')
    body = header + bytes((-sum(header) & 255,)) + data
    return body + bytes((-sum(body) & 255,))


def scan_bytes(*, uid=UID, atqa=b'\x44\x00', sak=b'\x00', ats=b''):
    return bytes((len(uid),)) + uid + atqa + sak + bytes((len(ats),)) + ats


class FakeCu:
    def __init__(self, *, family=213, chunk=17, write_chunk=4096):
        self.family, self.chunk, self.write_chunk = family, chunk, write_chunk
        self.scan_data, self.version = scan_bytes(), VERSIONS[family]
        self.pages = [bytes((index, 0x42, 0, 255)) for index in range(TOTALS[family])]
        self.pages[0] = UID[:3] + bytes((0x88 ^ UID[0] ^ UID[1] ^ UID[2],))
        self.pages[1] = UID[3:]
        self.buffer, self.input = bytearray(), bytearray()
        self.writes, self.commands, self.frames, self.read_sizes = [], [], [], []
        self.responses = {}
        self.is_open = False
        self.close_verified, self.close_error = True, False
        self.open_calls = self.close_calls = self.cancel_calls = 0
        self.before_open = self.before_read = self.before_write = self.before_close = None
        self.field = False
        self._lock = threading.RLock()

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
                assert wire[:2] == b'\x11\xef' and sum(wire[:9]) % 256 == 0 and sum(wire) % 256 == 0
                assert wire[4:6] == b'\x00\x00'
                command, payload = int.from_bytes(wire[2:4], 'big'), wire[9:-1]
                self.frames.append(wire)
                self.commands.append((command, payload))
                custom = self.responses.get((command, payload), self.responses.get(command))
                response = (custom(command, payload) if callable(custom) else custom) if custom is not None else self.response(command, payload)
                if response is not None:
                    self.buffer.extend(response)
        return count

    def response(self, command, payload):
        queries = {1000: b'\x02\x02', 1017: b'v2.2.0', 1033: b'\x00', 1002: b'\x01'}
        if command in queries:
            assert payload == b''
            return frame(command, queries[command])
        if command == 2000:
            assert payload == b''
            return frame(command, self.scan_data, status=0)
        if command == 2010 and payload == bytes.fromhex('fc0064000860'):
            self.field = True
            return frame(command, self.version, status=0)
        if command == 2010 and len(payload) == 7:
            assert payload[0] in (0xec, 0xe4) and payload[1:6] == bytes.fromhex('0064001030')
            assert self.field and payload[6] < len(self.pages)
            # 뒤 12B는 다음 페이지와 일부러 달라 첫 4B 귀속만 검사할 수 있다.
            data = self.pages[payload[6]] + b'UNTRUSTED123'
            if payload[0] == 0xe4:
                self.field = False
            return frame(command, data, status=0)
        raise AssertionError('고정 명령 이외 송신')

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
