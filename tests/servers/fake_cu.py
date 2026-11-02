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
# version-crc-error는 3B 이상 응답의 CRC 오류(firmware 0x03)이며 특정 칩 모델이 아니다.
TAG_MODELS = {'mf0icu1-nak': (0x00, b''), 'mf0icu1-timeout': (0x01, b''),
              'version-crc-error': (0x03, b''), 'ul-ev1': (0x00, bytes.fromhex('0004030101000b03')),
              'ul-ev1-mf0ulh21': (0x00, bytes.fromhex('0004030201000e03')),
              'type2-other-version': (0x00, bytes.fromhex('0004040101000b03')),
              'ul-ev1-mf0ulh11': (0x00, bytes.fromhex('0004030201000b03')),
              'ul-ev1-mf0ul21': (0x00, bytes.fromhex('0004030101000e03'))}
# Ultralight 계열 scan 모델: TAG_MODELS 이름과 recipe 계열. READ 없는 scan 경로만 쓴다(READ는 여전히 위반이다).
UL_SCAN_MODELS = {'mf0icu1': ('mf0icu1-nak', 'ultralight_or_ultralight_c'),
                  'mf0icu1-silent': ('mf0icu1-timeout', 'ultralight_or_ultralight_c'),
                  'mf0ul11': ('ul-ev1', 'ultralight_ev1_mf0ul11'),
                  'mf0ulh11': ('ul-ev1-mf0ulh11', 'ultralight_ev1_mf0ulh11'),
                  'mf0ul21': ('ul-ev1-mf0ul21', 'ultralight_ev1_mf0ul21'),
                  'mf0ulh21': ('ul-ev1-mf0ulh21', 'ultralight_ev1_mf0ulh21')}
# 합성 EV1 MF0UL11 일회용 종이 승차권 모델의 UID. 실제 승차권 값이 아니다.
TICKET_UID = bytes.fromhex('04c0ffee5a1e7b')
# Ultralight READ 모델(합성 내용이며 실제 덤프가 아니다). (GET_VERSION 응답, 물리 페이지 수, decode 끝, 모델 번호,
# READ 시작 page로 요청하면 위반인 page 집합). 원조 UL/UL C는 0x2C 이상, EV1은 PWD·PACK 두 페이지가 위반이다.
UL_MODELS = {
    'mf0icu1': ((0x00, b''), 16, 0x10, 1, frozenset(range(0x2c, 0x100))),
    'mf0icu1-silent': ((0x01, b''), 16, 0x10, 2, frozenset(range(0x2c, 0x100))),
    'mf0icu2': ((0x00, b''), 48, 0x2c, 3, frozenset(range(0x2c, 0x100))),
    'mf0ul11': ((0x00, bytes.fromhex('0004030101000b03')), 20, 20, 4, frozenset((0x12, 0x13))),
    'mf0ulh11': ((0x00, bytes.fromhex('0004030201000b03')), 20, 20, 5, frozenset((0x12, 0x13))),
    'mf0ul21': ((0x00, bytes.fromhex('0004030101000e03')), 41, 41, 6, frozenset((0x27, 0x28))),
    'mf0ulh21': ((0x00, bytes.fromhex('0004030201000e03')), 41, 41, 7, frozenset((0x27, 0x28))),
}
UL_FAMILY_OF = {'mf0icu1': 'ultralight_or_ultralight_c', 'mf0icu1-silent': 'ultralight_or_ultralight_c',
                'mf0icu2': 'ultralight_or_ultralight_c', 'mf0ul11': 'ultralight_ev1_mf0ul11',
                'mf0ulh11': 'ultralight_ev1_mf0ulh11', 'mf0ul21': 'ultralight_ev1_mf0ul21',
                'mf0ulh21': 'ultralight_ev1_mf0ulh21'}
# recipe의 never_sent_opcodes. Ultralight 모델에 이 opcode의 RAW가 오면 위반이다(인증·쓰기·서명·카운터·FAST_READ 등).
UL_NEVER_SENT = frozenset((0x1a, 0x1b, 0x39, 0x3a, 0x3c, 0x3e, 0x4b, 0xa0, 0xa2))
_UL_READ_PREFIX = bytes.fromhex('f40064001030')
UL_OTP = bytes.fromhex('f00d0000')


def ul_pages(model, uid, number=None):
    """page0=UID[0:3]+BCC0, page1=UID[3:7], page2=BCC1·0x48·00·00, page3=OTP, 나머지는 (i, 0x55, 모델 번호, 0xA5)."""
    _, total, _, model_number, _ = UL_MODELS[model]
    number = model_number if number is None else number
    pages = [bytes((i, 0x55, number, 0xa5)) for i in range(total)]
    pages[0] = uid[:3] + bytes((0x88 ^ uid[0] ^ uid[1] ^ uid[2],))
    pages[1] = uid[3:7]
    pages[2] = bytes((uid[3] ^ uid[4] ^ uid[5] ^ uid[6], 0x48, 0, 0))
    pages[3] = UL_OTP
    if UL_MODELS[model][4] and model.startswith('mf0ul'):
        for page in UL_MODELS[model][4]:
            pages[page] = bytes(4)  # PWD/PACK는 읽으면 00h다(MF0ULX1 §8.6.1).
    return pages
# 공식 v2.3.0 data_cmd.h(L103-L123·L199-L216)의 LF 쓰기(T55xx 복제·블록 쓰기)·EM4x05 LOGIN scan·스니프·원시 ADC·
# ioProx 변환·emulator ID 명령. LF 식별을 포함한 어떤 경로도 보내면 안 된다.
LF_DENIED = frozenset((3001, 3003, 3005, 3006, 3007, 3008, 3009, 3011, 3012, 3013, 3015, 3016, 3018, 3020,
                       3030, 3031, 3032, *range(5000, 5014)))
# 공식 v2.3.0의 인증·쓰기·키 변경·BLE PIN·고정 식별자·모드·field 직접 제어 명령. 어떤 경로도 보내면 안 된다.
# 상태 조회도 slot 별명(1008/1038)·slot 정보(1019)·long-press(1041/1042)·battery-ex(1043)·HF14A 설정 변경(2201)을 보내지 않는다.
# 3021 Pyramid scan은 LF 식별의 고정 scan이 되어 이 목록에서 뺐다(HF 경로의 명령 순서 검사가 대신 막는다).
DENIED = frozenset((1001, 1008, 1011, 1012, 1019, 1031, 1034, 1038, 1041, 1042, 1043,
                    2016, 2018, 2019, 2021, 2022, 2100, 2101, 2201)) | LF_DENIED
# LF 식별의 고정 scan(명령, 정확 payload)과 송신 순서. 숫자 순서가 아니다.
LF_SCANS = ((3000, b''), (3002, b'\x00'), (3010, b'\x00'), (3004, b''), (3014, b''), (3019, b''), (3021, b''))
LF_SCAN_PAYLOADS = dict(LF_SCANS)
# 합성 LF ID. 실제 카드 값이 아니며 공개 결과·로그에 hex로 나오지 않아야 한다.
EM_ID = bytes.fromhex('5aa51337c0')
ELECTRA_EPILOGUE = bytes.fromhex('e1ec7a0011223344')
HID16 = bytes.fromhex('01') + (0xc0ffee).to_bytes(4, 'big') + (0x5eed1234).to_bytes(5, 'big') + b'\x07\xbe\xef' + b'\0' * 3
IOPROX16 = bytes.fromhex('01a5') + (0x4d2e).to_bytes(2, 'big') + bytes.fromhex('f00dfacecafe1234') + b'\0' * 4
# (감지되는 scan 명령, 0x40 payload). em410x 변형은 tag_type 101–104(u16 BE)와 ID 5B, Electra는 ID 13B다.
LF_MODELS = {
    'em410x-16': (3000, b'\x00\x65' + EM_ID), 'em410x-32': (3000, b'\x00\x66' + EM_ID),
    'em410x-64': (3000, b'\x00\x67' + EM_ID), 'electra': (3000, b'\x00\x68' + EM_ID + ELECTRA_EPILOGUE),
    'hidprox': (3002, HID16), 'ioprox': (3010, IOPROX16), 'viking': (3004, bytes.fromhex('5ca1ab1e')),
    'pac': (3014, b'SYNPAC01'), 'jablotron': (3019, bytes.fromhex('a5b4c3d2e1')),
    'pyramid': (3021, bytes.fromhex('0000000000000001dead5eedc0de4242')),
}
UID4 = bytes.fromhex('a1b2c3d4')
RAW_OPTIONS = frozenset((0xf4, 0xfc, 0xec, 0xe4))
VERSION_WIRE = bytes.fromhex('f40064000860')
_CREATED = []


def scan_bytes_for(uid, atqa, sak, ats=b''):
    return bytes((len(uid),)) + uid + atqa + bytes((sak,)) + bytes((len(ats),)) + ats


# 2000 scan 모델의 (status, payload). ATQA는 wire 순서(LSB 먼저)다. 합성 값이며 실제 카드 덤프가 아니다.
SCAN_MODELS = {
    'none': (0x01, b''),
    'multiple': (0x04, b''),
    'classic-mini': (0x00, scan_bytes_for(UID4, b'\x04\x00', 0x09)),
    'classic-1k': (0x00, scan_bytes_for(UID4, b'\x04\x00', 0x08)),
    'classic-4k': (0x00, scan_bytes_for(UID4, b'\x02\x00', 0x18)),
    'classic-2k': (0x00, scan_bytes_for(UID4, b'\x04\x00', 0x19)),
    'tnp3xxx': (0x00, scan_bytes_for(UID4, b'\x04\x00', 0x01)),
    # firmware ATS는 CRC만 뺀 값이므로 TL(전체 길이) 바이트로 시작한다.
    'iso14443-4': (0x00, scan_bytes_for(UID, b'\x44\x03', 0x20, b'\x06\x75\x77\x81\x02\x80')),
    'plus-sl2': (0x00, scan_bytes_for(UID4, b'\x04\x00', 0x10)),
    'other-sak02': (0x00, scan_bytes_for(UID4, b'\x04\x00', 0x02)),
    'type2-uid4': (0x00, scan_bytes_for(UID4, b'\x44\x00', 0x00)),
}


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
    def __init__(self, *, family=213, chunk=17, write_chunk=4096, firmware='v2.3.0', tag=None, scan=None, lf=None,
                 uid=None, ul=None, auth0=None, prot=False, swap_after_page=None, inject=None, no_rollover=False,
                 coincident=False):
        self.family, self.chunk, self.write_chunk = family, chunk, write_chunk
        self.app, self.git = FIRMWARES[firmware]
        self.tag, self.scan_model = tag, scan
        # LF 모델 이름. None이면 모든 LF scan이 0x41(미감지)이다.
        self.lf_found = None if lf is None else LF_MODELS[lf]
        self.lf_log = []
        # uid는 Type 2 scan 레코드의 합성 UID만 바꾼다(다른 태그 시험용). READ 페이지는 기본 UID 그대로다.
        self.scan_status, self.scan_data = ((0, scan_bytes(uid=UID if uid is None else uid)) if scan is None
                                            else SCAN_MODELS[scan])
        # 1025 mV·percent, 1018 0부터 센 slot, 2200 forcebcc/cl2/cl3/rats. 합성 기본값이다.
        self.battery, self.slot, self.hf14a_config = (3900, 61), 0, b'\0\0\0\0'
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
        # Ultralight READ 모델. ul_reads_allowed는 시험이 사람 증명(decide) 뒤에만 켠다. 꺼진 동안 0x30은 위반이다.
        self.ul, self.ul_reads_allowed = ul, False
        self.ul_state, self.ul_log = 'off', []
        if ul is not None:
            self.ul_uid = UID if uid is None else uid
            self.version_status, self.version = UL_MODELS[ul][0]
            self.ul_pages = ul_pages(ul, self.ul_uid)
            # 보호 경계: AUTH0 이상이 READ 보호(EV1 PROT=1, UL C AUTH1 bit0=0)일 때만 decode 끝보다 앞당긴다.
            self.ul_auth0, self.ul_prot = auth0, prot
            if coincident:
                # 사용자 페이지가 우연히 page0–2와 같아도 겹침 대조·끝 판정이 맞아야 한다.
                self.ul_pages[4:7] = self.ul_pages[0:3]
            self.ul_swap_after = swap_after_page
            # 교체 태그 B: 다른 UID와 다른 모델 번호라 사용자 페이지 내용도 다르다.
            self.ul_swap_pages = ul_pages(ul, bytes.fromhex('04d1d2d3d4d5d6'), number=0x7b)
            self.ul_inject = dict(inject or {})
            self.ul_no_rollover = no_rollover
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
        if command in LF_SCAN_PAYLOADS and payload != LF_SCAN_PAYLOADS[command]:
            self.violation('고정 payload 이외 LF scan')
        if command != 2010:
            return
        if len(payload) < 5 or payload[0] not in RAW_OPTIONS:
            self.violation('고정 option 이외 RAW')
        if self.ul is not None:
            if payload[0] != 0xf4:
                self.violation('Ultralight 모델에 f4 이외 RAW option')
            if len(payload) > 5 and payload[5] in UL_NEVER_SENT:
                self.violation('Ultralight 모델에 금지 opcode')
        option = payload[0]
        if option & 0x10:
            self.field = True
        elif not self.field:
            self.violation('field가 꺼진 상태의 비선택 RAW')

    def _after(self, command, payload):
        """응답 내용과 무관하게 keep=0 RAW와 scan 뒤 field를 끈다. keep=1 실패는 켜진 채 남는다."""
        if command in LF_SCAN_PAYLOADS:
            # firmware의 각 LF read 함수는 끝에서 stop_lf_125khz_radio를 부른다. HF field는 건드리지 않는다.
            self.lf_log.append(command)
        if command == 2000:
            self.field = False
        elif command == 2010 and payload and not payload[0] & 0x08:
            self.field = False
        if self.ul is not None and command in (2000, 2010):
            if not self.field:
                self.ul_state = 'off'
            elif self.field:
                self.violation('Ultralight frame 뒤 field가 켜져 있음')
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
        queries = {1000: self.app, 1017: self.git, 1033: b'\x00', 1002: b'\x01',
                   1025: self.battery[0].to_bytes(2, 'big') + bytes((self.battery[1],)),
                   1018: bytes((self.slot,)), 2200: self.hf14a_config}
        if command in queries:
            if payload != b'':
                self.violation('조회 payload')
            return frame(command, queries[command])
        if command == 2000:
            if payload != b'':
                self.violation('scan payload')
            return frame(command, self.scan_data, status=self.scan_status)
        if command in LF_SCAN_PAYLOADS:
            if self.lf_found is not None and self.lf_found[0] == command:
                return frame(command, self.lf_found[1], status=0x40)
            return frame(command, b'', status=0x41)
        if command == 2010 and self.ul is not None:
            return self._ul_response(command, payload)
        if command == 2010 and payload == VERSION_WIRE:
            return frame(command, self.version, status=self.version_status)
        if command == 2010 and len(payload) == 7 and payload[1:6] == bytes.fromhex('0064001030'):
            if payload[0] not in (0xfc, 0xec, 0xe4) or (payload[0] == 0xfc) != (payload[6] == 0):
                self.violation('READ0 이외 선택 또는 선택 없는 READ0')
            if self.tag is not None or self.scan_model is not None:
                self.violation('NTAG가 아닌 태그에 READ')
            if payload[6] >= len(self.pages):
                self.violation('범위 밖 page')
            # 뒤 12B는 다음 페이지와 일부러 달라 첫 4B 귀속만 검사할 수 있다.
            data = self.pages[payload[6]] + b'UNTRUSTED123'
            return frame(command, data, status=0)
        self.violation('고정 명령 이외 송신')

    def _ul_response(self, command, payload):
        """off→idle(field on)→active(auto-select)만 거친다. NAK·원조 GET_VERSION 뒤 idle, keep=0 뒤 off다."""
        if payload[0] & 0x10:
            self.ul_state = 'active'
        if payload == VERSION_WIRE:
            if self.version_status != 0 or not self.version:
                self.ul_state = 'idle'
            return frame(command, self.version, status=self.version_status)
        if len(payload) != 7 or payload[:6] != _UL_READ_PREFIX:
            self.violation('Ultralight 모델에 고정 READ·GET_VERSION 이외 RAW')
        page = payload[6]
        self.ul_log.append(page)
        if not self.ul_reads_allowed:
            self.violation('사람 증명 전 Ultralight READ')
        if page >= 0x2c or page in UL_MODELS[self.ul][4]:
            self.violation('보류·키 페이지 또는 0x2C 이상 READ')
        if self.ul_state != 'active':
            self.violation('선택되지 않은 태그에 READ')
        if page in self.ul_inject:
            status, data = self.ul_inject[page]
            return frame(command, data, status=status)
        _, _, decode_end, _, _ = UL_MODELS[self.ul]
        boundary = decode_end
        if self.ul_prot and self.ul_auth0 is not None:
            boundary = min(boundary, self.ul_auth0)
        if page >= boundary:
            self.ul_state = 'idle'
            return frame(command, b'', status=0)
        swapped = self.ul_swap_after is not None and page > self.ul_swap_after
        store = self.ul_swap_pages if swapped else self.ul_pages
        data = b''
        for index in range(page, page + 4):
            if index >= boundary:
                data += bytes(4) if self.ul_no_rollover else store[index % boundary]
            else:
                data += store[index]
        return frame(command, data, status=0)

    def ul_reads(self):
        """Ultralight 모델에 실제로 보낸 READ 시작 page 순서."""
        return list(self.ul_log)

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
