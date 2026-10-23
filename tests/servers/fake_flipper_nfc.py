"""합성 NFC subshell만 추가한 Flipper fixture. 실제 장치 호출은 없다."""
from __future__ import annotations

import hashlib
from pathlib import PurePosixPath

import pytest

from pweh.runtime import get_runtime
from flipper_mcp import session as S
from .fake_flipper_cli import FakeFlipper, PROMPT, configure

NFC_PROMPT = b'\r\n[\x1b[32mnfc\x1b[0m]>: '
MOTD = (b'\x1b[94m\r\n' + b'     0000      \r\n' * 19
        + b'\r\n\x1b[97mWelcome to NFC Command Line Interface!\r\n'
        b'Run `help` or `?` to list available commands\r\n\x1b[0m')
UID = b'SYNTH01'


def crc(data):
    value = 0x6363
    for byte in data:
        byte ^= value & 255
        byte ^= (byte << 4) & 255
        value = ((value >> 8) ^ (byte << 8) ^ (byte << 3) ^ (byte >> 4)) & 65535
    return value.to_bytes(2, 'little')


def probe_bytes(uid=UID, sak=b'\0'):
    return (b'Filetype: Flipper NFC device\nVersion: 4\nDevice type: ISO14443-3A\nUID: '
            + uid.hex(' ').upper().encode() + b'\nATQA: 00 44\nSAK: '
            + sak.hex().upper().encode() + b'\n')


def raw_body(uid=UID, version=bytes.fromhex('0004040201000f03'), sak=b'\0'):
    return (b'UID: ' + uid.hex(' ').upper().encode() + b'  ATQA: 4400 SAK: '
            + sak.hex().upper().encode() + b'\r\nTx: 60 F8 32 \r\nRx: '
            + (version + crc(version)).hex(' ').upper().encode() + b' ')


class FakeNfc(FakeFlipper):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.nfc = False
        self.files = {}
        self.probe_data = probe_bytes()
        self.raw_body = raw_body()
        self.keep_scratch = False
        self.deleted = []
        self.created = []

    def response(self, command):
        echo = command + b'\r\n'
        if command == b'nfc':
            assert not self.nfc
            self.nfc = True
            return echo + MOTD + NFC_PROMPT
        if command == b'exit':
            assert self.nfc
            self.nfc = False
            return echo + PROMPT
        if command.startswith(b'dump -p 14_3a -f '):
            assert self.nfc
            path = command[len(b'dump -p 14_3a -f '):].decode('ascii')
            assert '"' not in path and ' ' not in path and path not in self.files
            self.files[path] = self.probe_data
            self.created.append(path)
            return echo + b'Dumping as "Iso14443-3a"\r\nDump saved to \'' + path.encode() + b'\'\r\n' + NFC_PROMPT
        if command == b'raw -p 14a -s -c -d 60 -t 60000':
            assert self.nfc
            return echo + self.raw_body + NFC_PROMPT
        if command.startswith(b'storage '):
            assert not self.nfc
            kind, path = command[8:].split(b' ', 1)
            assert path.startswith(b'"') and path.endswith(b'"')
            path = path[1:-1].decode('ascii')
            if kind == b'list':
                rows = [b'\t[F] ' + PurePosixPath(key).name.encode() + b' '
                        + str(len(value)).encode() + b'b\r\n'
                        for key, value in sorted(self.files.items()) if str(PurePosixPath(key).parent) == path.rstrip('/')]
                return echo + (b''.join(rows) if rows else b'\tEmpty\r\n') + PROMPT
            if kind == b'read':
                data = self.files[path]
                return echo + b'Size: ' + str(len(data)).encode() + b'\r\n' + data + b'\r\n' + PROMPT
            if kind == b'md5':
                return echo + hashlib.md5(self.files[path]).hexdigest().encode() + b'\r\n' + PROMPT
            if kind == b'remove':
                assert path in self.created
                self.deleted.append(path)
                if not self.keep_scratch:
                    del self.files[path]
                return echo + PROMPT
            raise AssertionError('합성 범위 밖 storage 명령')
        assert not self.nfc
        return super().response(command)


@pytest.fixture
def setup(workspace, auth, monkeypatch, request):
    runtime = get_runtime('flipper-test')
    case = runtime.cases.create(title='합성 NFC probe', authorization=auth)
    env = configure(monkeypatch, runtime, case, fake=FakeNfc(),
                    backend=getattr(request, 'param', 'posix-tty'))
    env.workspace = workspace
    yield env
    for owner in tuple(S._REGISTRY.values()):
        for use in tuple(owner._uses):
            use.cancel()
            use.finish()
        if owner.transport is not None:
            owner.transport.close_verified = True
            owner.transport.before_close = None
        owner.close()
