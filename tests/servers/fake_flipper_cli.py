"""실제 포트 없이 고정 Flipper CLI를 분할 송수신하는 합성 fixture."""
from __future__ import annotations

import hashlib
import threading
from types import SimpleNamespace

import pytest

from pweh import ports
from pweh.portidentity import PortIdentity
from pweh.runtime import get_runtime
from flipper_mcp import session as S

BANNER = (b'\r\nWelcome to Flipper Zero Command Line Interface!\r\n'
          b'Firmware version: release 1.5.1 (9e810dc3 built on 01-10-2025)\r\n\r\n>: ')
PROMPT = b'\r\n>: '
INFO = b''.join(k.ljust(30) + b': ' + v + b'\r\n' for k, v in (
    (b'format.major', b'3'), (b'format.minor', b'3'), (b'hardware.model', b'Flipper Zero'),
    (b'hardware.target', b'7'), (b'firmware.version', b'1.5.1'),
    (b'firmware.commit.hash', b'9e810dc3'), (b'firmware.commit.dirty', b'false'),
    (b'hardware.uid', b'PRIVATE_UID_SENTINEL'), (b'hardware.name', b'PRIVATE_NAME_SENTINEL')))


class FakeFlipper:
    def __init__(self, *, payload=b'hello', banner=BANNER, chunk=17, write_chunk=4096):
        self.payload, self.chunk, self.write_chunk = payload, chunk, write_chunk
        self.buffer = bytearray(banner)
        self.input = bytearray()
        self.writes, self.commands, self.read_sizes = [], [], []
        self.responses = {}
        self.opened, self.closed = True, False
        self.close_verified = True
        self.close_error = False
        self.close_calls = self.cancel_calls = 0
        self.before_read = self.before_write = self.before_close = None
        self._lock = threading.RLock()

    @property
    def is_open(self):
        return self.opened

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
            while b'\r' in self.input:
                command, _, tail = self.input.partition(b'\r')
                self.input[:] = tail
                command = bytes(command)
                self.commands.append(command)
                custom = next((value for prefix, value in self.responses.items()
                               if command.startswith(prefix)), None)
                if custom is not None:
                    response = custom(command) if callable(custom) else custom
                else:
                    response = self.response(command)
                if response is not None:
                    self.buffer.extend(response)
        return count

    def response(self, command):
        if command == b'loader info':
            body = b'No application is running\r\n'
        elif command == b'info device':
            body = INFO
        elif command.startswith(b'storage list '):
            body = b'\t[F] fixture.sub ' + str(len(self.payload)).encode() + b'b\r\n'
        elif command.startswith(b'storage read '):
            body = b'Size: ' + str(len(self.payload)).encode() + b'\r\n' + self.payload + b'\r\n'
        elif command.startswith(b'storage md5 '):
            body = hashlib.md5(self.payload).hexdigest().encode() + b'\r\n'
        else:
            raise AssertionError('고정 명령 이외 송신')
        return command + b'\r\n' + body + PROMPT

    def cancel_read(self):
        self.cancel_calls += 1

    def close(self):
        self.close_calls += 1
        if self.before_close:
            self.before_close()
        if self.close_verified:
            self.closed, self.opened = True, False
        if self.close_error:
            raise OSError('PRIVATE_CLOSE_SENTINEL')


def configure(monkeypatch, runtime, case, *, fake=None, backend='posix-tty'):
    """C의 실제 Client 시험도 동일한 session/storage를 사용한다."""
    fake = fake or FakeFlipper()
    windows = backend == 'win-helper'
    port = 'COM4096' if windows else '/dev/ttyACM4096'
    parent = 'USB\\VID_0483&PID_5740\\flip_SYNTHETIC' if windows else 'devices/usb1/1-9'
    key = 'win:COM4096' if windows else 'tty:166:4096'
    ident = PortIdentity(key, 'known', present=True, backend='windows' if windows else 'linux',
                         device_instance=parent + '/if00', parent_instance=parent, usb_ancestor=parent,
                         vid='0483', pid='5740', interface_number='00', serial='flip_SYNTHETIC',
                         serial_basis='instance-tail' if windows else 'sysfs')
    route = ports.PortRoute(port, 'serial-session', backend, 'windows' if windows else 'linux',
                            port, key, 'synthetic-flipper/00', ident, 'serial', 'wired',
                            node_identity=None if windows else (1, 2, 3))
    keys = tuple(sorted((key, 'synthetic-flipper-whole', 'synthetic-flipper-sibling')))
    context = SimpleNamespace(runtime=runtime, case=case, fake=fake, route=route, keys=keys,
                              port=port, opens=[], fresh_calls=[], owners=[])
    monkeypatch.setattr(S, '_environment', lambda r: {'kind': 'SYNTHETIC'})
    monkeypatch.setattr(S, '_resolve', lambda r, p: route)
    monkeypatch.setattr(S, '_scope', lambda r, fresh: context.keys)
    monkeypatch.setattr(S, 'guard_target_port', lambda *a, **kw: None)
    def fresh(old, **kwargs):
        context.fresh_calls.append(old)
        return context.route
    monkeypatch.setattr(S.ports, 'revalidate', fresh)
    def opened(route, settings, *, lease, before_io):
        before_io()
        if windows:
            before_io()
        context.opens.append(settings)
        return context.fake
    monkeypatch.setattr(S.serialtransport, 'open_serial', opened)
    def prepare():
        owner = S.prepare_session(runtime, case, port)
        context.owners.append(owner)
        return owner
    def connect():
        owner = prepare()
        owner.connect(threading.Event())
        return owner
    context.prepare, context.connect = prepare, connect
    return context


@pytest.fixture
def setup(workspace, auth, monkeypatch, request):
    runtime = get_runtime('flipper-test')
    case = runtime.cases.create(title='합성 Flipper', authorization=auth)
    context = configure(monkeypatch, runtime, case, backend=getattr(request, 'param', 'posix-tty'))
    yield context
    for owner in tuple(S._REGISTRY.values()):
        for use in tuple(owner._uses):
            use.cancel()
            use.finish()
        if owner.transport is not None:
            owner.transport.close_verified = True
            owner.transport.before_close = None
        owner.close()
