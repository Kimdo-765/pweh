"""고정 Flipper 1.5.1 읽기 CLI의 순수 명령·응답 상태기계.

호출자가 새 transport의 수신만 feed하고 반환한 binary 조각을 자기 FD에 쓴다.
이 모듈은 포트·시간·파일을 열지 않으며 배너의 주장을 서명 검증으로 삼지 않는다.
"""
from __future__ import annotations

import copy
import re
from types import MappingProxyType

from .case import CASE_ID_RE
from .errors import PwehError

PROFILE = "flipper-cli-1.5.1-read-v1"
COMMIT = "9e810dc399e027e48ce07751df72168abbb19065"
VERSION = "1.5.1"
PROMPT = b"\r\n>: "
MAX_FILE_BYTES = 1 << 20
MAX_BANNER_BYTES = 16 << 10
MAX_TEXT_BYTES = 256 << 10
MAX_TEXT_LINES = 1024
MAX_LINE_BYTES = 1024
MAX_LIST_ENTRIES = 256
MAX_READ_BYTES = 4096
LIMITS = MappingProxyType({
    "max_file_bytes": MAX_FILE_BYTES, "max_text_bytes": MAX_TEXT_BYTES,
    "max_list_entries": MAX_LIST_ENTRIES, "connect_seconds": 30, "pull_seconds": 300,
})
_WELCOME = b"Welcome to Flipper Zero Command Line Interface!"
_MESSAGES = {
    "flipper_invalid_input": "Flipper 읽기 입력의 형식 또는 범위가 올바르지 않습니다.",
    "flipper_firmware_unsupported": "관찰한 펌웨어가 고정 Flipper 읽기 프로필과 맞지 않습니다.",
    "flipper_handshake_failed": "새 Flipper 배너와 프롬프트를 확인하지 못했습니다.",
    "flipper_app_busy": "Flipper 앱이 유휴 상태임을 확인하지 못했습니다.",
    "flipper_protocol_error": "Flipper 읽기 응답의 구조를 확인하지 못했습니다.",
    "flipper_storage_error": "Flipper 저장소 읽기가 실패했습니다.",
    "flipper_limit": "Flipper 읽기의 고정 한도를 넘었습니다.",
    "flipper_terminal": "Flipper 세션의 후속 명령을 사용할 수 없습니다.",
    "cancelled": "Flipper 읽기가 취소되었습니다.",
    "time_limit": "Flipper 읽기의 시간 한도에 닿았습니다.",
}
_COMPONENT = re.compile(r"[A-Za-z0-9._ -]+\Z", re.ASCII)
_DEST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z", re.ASCII)
_DECIMAL = re.compile(rb"(?:0|[1-9][0-9]{0,9})\Z")
_HASH = re.compile(r"[0-9a-f]{7,40}\Z", re.ASCII)
_KEY = re.compile(rb"[a-z0-9_]+(?:\.[a-z0-9_]+)*\Z")
_FIRMWARE = re.compile(
    rb"Firmware version: [A-Za-z0-9._/-]{1,64} ([A-Za-z0-9._+-]{1,64}) "
    # 고정 scripts/version.py는 BUILD_DATE를 %d-%m-%Y로 만든다.
    rb"\(([0-9a-f]{7,40})(-dirty)? built on [0-9]{2}-[0-9]{2}-[0-9]{4}\)\Z"
)


class FlipperCliError(PwehError):
    """입력·장치 원문을 담지 않는 고정 protocol 오류."""


def _error(code):
    raise FlipperCliError(_MESSAGES[code], code=code) from None


def _component(value):
    return (type(value) is str and 1 <= len(value) <= 254
            and _COMPONENT.fullmatch(value) is not None
            and value == value.strip(" ") and value not in (".", ".."))


def remote_path(case_id: str, path: str, *, file: bool = False) -> str:
    """현재 케이스의 준비된 원격 폴더 안 경로만 그대로 받는다."""
    if (type(case_id) is not str or CASE_ID_RE.fullmatch(case_id) is None
            or type(path) is not str or type(file) is not bool or len(path) > 512):
        _error("flipper_invalid_input")
    root = "/ext/pweh/" + case_id
    # list에서 root 자체와 문서의 root 표기(root/)만 같게 취급한다.
    if not file and path in (root, root + "/"):
        return path
    if not path.startswith(root + "/") or path.endswith("/"):
        _error("flipper_invalid_input")
    parts = path.split("/")[1:]
    if len(parts) > 16 or not all(_component(part) for part in parts):
        _error("flipper_invalid_input")
    return path


def destination_name(value: str) -> str:
    """호스트 basename만 검사하며 원격 이름으로 기본값을 만들지 않는다."""
    if type(value) is not str or _DEST.fullmatch(value) is None or value.endswith("."):
        _error("flipper_invalid_input")
    return value


def _commit(value):
    return (type(value) is str and _HASH.fullmatch(value) is not None
            and COMMIT.startswith(value))


def _lines(body):
    if not body.endswith(b"\r\n"):
        _error("flipper_protocol_error")
    lines = body[:-2].split(b"\r\n")
    if len(lines) > MAX_TEXT_LINES or any(len(line) > MAX_LINE_BYTES for line in lines):
        _error("flipper_limit")
    if any(any(c < 32 and c != 9 or c > 126 for c in line) for line in lines):
        _error("flipper_protocol_error")
    return lines


def _banner(body):
    # 배너만 bounded SGR을 허용한다. OSC/편집 escape/불완전 escape는 고치지 않는다.
    plain = bytearray()
    i = count = 0
    while i < len(body):
        if body[i] == 27:
            end = body.find(b"m", i + 1, min(len(body), i + 36))
            if (end < 0 or body[i + 1:i + 2] != b"["
                    or not re.fullmatch(rb"[0-9;]{0,32}", body[i + 2:end])):
                _error("flipper_handshake_failed")
            count += 1
            if count > 64:
                _error("flipper_limit")
            i = end + 1
        else:
            plain.append(body[i])
            i += 1
    lines = _lines(bytes(plain))
    if lines.count(_WELCOME) != 1:
        _error("flipper_handshake_failed")
    versions = [line for line in lines if line.startswith(b"Firmware version:")]
    if len(versions) != 1 or lines.index(_WELCOME) >= lines.index(versions[0]):
        _error("flipper_handshake_failed")
    match = _FIRMWARE.fullmatch(versions[0])
    if match is None:
        _error("flipper_firmware_unsupported")
    version, commit = match[1].decode("ascii"), match[2].decode("ascii")
    if version != VERSION or not _commit(commit) or match[3] is not None:
        _error("flipper_firmware_unsupported")
    return {"version": version, "commit_hash": commit, "dirty": False}


def _info(lines, banner):
    if len(lines) > 256:
        _error("flipper_limit")
    values = {}
    for line in lines:
        keyfield, sep, value = line.partition(b": ")
        key = keyfield.rstrip(b" ")
        if (not sep or len(key) > 128 or not _KEY.fullmatch(key)
                or keyfield != key.ljust(30, b" ") or key in values
                or any(c < 32 or c > 126 for c in value)):
            _error("flipper_protocol_error")
        if len(value) > 512:
            _error("flipper_limit")
        values[key] = value
    expected = {
        b"format.major": b"3", b"format.minor": b"3", b"hardware.model": b"Flipper Zero",
        b"hardware.target": b"7", b"firmware.version": VERSION.encode(),
        b"firmware.commit.hash": banner["commit_hash"].encode(), b"firmware.commit.dirty": b"false",
    }
    if any(values.get(key) != value for key, value in expected.items()):
        _error("flipper_firmware_unsupported")
    # UID/name/MAC와 나머지 자유 값은 projection에 포함하지 않는다.
    return {"model": "Flipper Zero", "hardware_target": 7,
            "info_format": {"major": 3, "minor": 3}, "firmware": dict(banner),
            "profile_compatible": True, "firmware_claim_verified": False}


def _listing(lines):
    if lines == [b"\tEmpty"]:
        return {"entries": [], "count": 0, "listing_complete": True,
                "filesystem_completeness_verified": False}
    if len(lines) > MAX_LIST_ENTRIES:
        _error("flipper_limit")
    entries, names = [], set()
    for line in lines:
        if line.startswith(b"\t[D] "):
            name, kind, size = line[5:], "directory", None
        elif line.startswith(b"\t[F] "):
            name, sep, tail = line[5:].rpartition(b" ")
            if not sep or not tail.endswith(b"b") or not _DECIMAL.fullmatch(tail[:-1]):
                _error("flipper_protocol_error")
            size, kind = int(tail[:-1]), "file"
            if size > 0xffffffff:
                _error("flipper_protocol_error")
        else:
            _error("flipper_protocol_error")
        value = name.decode("ascii")
        if not _component(value) or value in names:
            _error("flipper_protocol_error")
        names.add(value)
        entries.append({"name": value, "type": kind, "size": size})
    return {"entries": entries, "count": len(entries), "listing_complete": True,
            "filesystem_completeness_verified": False}


class FlipperCli:
    """한 연결·한 미완료 요청의 순수 상태. 실패 뒤 상태를 복구하지 않는다."""

    def __init__(self, case_id: str):
        if type(case_id) is not str or CASE_ID_RE.fullmatch(case_id) is None:
            _error("flipper_invalid_input")
        self._case_id = case_id
        self._state = "passive"
        self._buffer = bytearray()
        self._echo = b""
        self._kind = None
        self._result = None
        self._banner = None
        self._idle = False
        self._device_validated = False
        self._declared_size = None
        self._received_size = 0
        self._text_total = 0
        self._terminal_reason = None

    @property
    def state(self):
        return self._state

    @property
    def ready(self):
        return self._state == "ready"

    @property
    def result(self):
        return copy.deepcopy(self._result)

    @property
    def banner(self):
        return None if self._banner is None else dict(self._banner)

    @property
    def declared_size(self):
        return self._declared_size

    @property
    def received_size(self):
        return self._received_size

    @property
    def terminal_reason(self):
        return self._terminal_reason

    @property
    def read_size(self):
        if self._state == "binary":
            return min(MAX_READ_BYTES, self._declared_size - self._received_size)
        return MAX_READ_BYTES

    def abort(self, reason="flipper_terminal"):
        """취소·IO 실패의 owner가 호출한다. 재동기화나 송신은 하지 않는다."""
        if self._state != "terminal":
            self._terminal_reason = reason if type(reason) is str and reason in _MESSAGES else "flipper_terminal"
        self._state = "terminal"
        self._buffer.clear()
        self._echo = b""
        self._result = None
        self._idle = False

    def eof(self):
        """transport EOF는 정상 prompt가 있더라도 연결 종료로 남긴다."""
        code = "flipper_handshake_failed" if self._state == "passive" else "flipper_protocol_error"
        if self._state == "terminal":
            code = "flipper_terminal"
        self.abort(code)
        _error(code)

    def begin(self, kind: str, path: str | None = None) -> bytes:
        """허용 고정 명령만 생성한다. loader 유휴 확인은 한 명령에만 유효하다."""
        if self._state == "terminal":
            _error("flipper_terminal")
        try:
            if self._state != "ready":
                _error("flipper_protocol_error")
            if type(kind) is not str or kind not in ("loader", "info", "list", "read", "md5"):
                _error("flipper_invalid_input")
            if kind in ("loader", "info"):
                if path is not None:
                    _error("flipper_invalid_input")
                command = b"loader info" if kind == "loader" else b"info device"
            else:
                checked = remote_path(self._case_id, path, file=kind != "list")
                command = ('storage ' + kind + ' "' + checked + '"').encode("ascii")
            if kind != "loader" and (not self._idle or kind != "info" and not self._device_validated):
                _error("flipper_protocol_error")
            self._idle = False
            self._kind = kind
            self._result = None
            self._declared_size = None
            self._received_size = 0
            self._text_total = 0
            self._echo = command + b"\r\n"
            self._state = "echo"
            return command + b"\r"
        except FlipperCliError as exc:
            self.abort(exc.code)
            raise

    def _finish(self, result):
        if self._buffer:
            _error("flipper_protocol_error")
        self._result = result
        self._state = "ready"

    def _text(self, body):
        lines = _lines(body)
        if any(line.startswith(b"Storage error:") for line in lines):
            _error("flipper_storage_error")
        if self._kind == "loader":
            if lines != [b"No application is running"]:
                _error("flipper_app_busy")
            self._idle = True
            return {"idle": True}
        if self._kind == "info":
            result = _info(lines, self._banner)
            self._device_validated = True
            return result
        if self._kind == "list":
            return _listing(lines)
        if self._kind == "md5" and len(lines) == 1 and re.fullmatch(rb"[0-9a-f]{32}", lines[0]):
            return {"md5": lines[0].decode("ascii")}
        _error("flipper_protocol_error")

    def feed(self, data: bytes) -> bytes:
        """수신 조각을 소비하고 binary payload만 반환한다. 원문을 결과로 저장하지 않는다."""
        if self._state == "terminal":
            _error("flipper_terminal")
        try:
            if type(data) is not bytes:
                _error("flipper_invalid_input")
            if len(data) > MAX_READ_BYTES:
                _error("flipper_limit")
            if self._state == "ready":
                if data:
                    _error("flipper_protocol_error")
                return b""
            self._buffer.extend(data)
            payload = bytearray()
            while True:
                if self._state == "passive":
                    if len(self._buffer) > MAX_BANNER_BYTES:
                        _error("flipper_limit")
                    index = self._buffer.find(PROMPT)
                    if index < 0:
                        break
                    body = bytes(self._buffer[:index])
                    del self._buffer[:index + len(PROMPT)]
                    self._banner = _banner(body)
                    self._finish({"banner_seen": True, "prompt_seen": True,
                                  "firmware_claim_verified": False, "tx_before_banner": 0})
                elif self._state == "echo":
                    take = min(len(self._echo), len(self._buffer))
                    if self._buffer[:take] != self._echo[:take]:
                        _error("flipper_protocol_error")
                    del self._buffer[:take]
                    self._echo = self._echo[take:]
                    self._text_total += take
                    if self._echo:
                        break
                    self._state = "size" if self._kind == "read" else "text"
                elif self._state in ("text", "size"):
                    if self._text_total + len(self._buffer) > MAX_TEXT_BYTES:
                        _error("flipper_limit")
                    if self._state == "size":
                        index = self._buffer.find(b"\r\n")
                        if index < 0:
                            if len(self._buffer) > MAX_LINE_BYTES:
                                _error("flipper_limit")
                            break
                        line = bytes(self._buffer[:index])
                        del self._buffer[:index + 2]
                        if line.startswith(b"Storage error:"):
                            _error("flipper_storage_error")
                        if not line.startswith(b"Size: ") or not _DECIMAL.fullmatch(line[6:]):
                            _error("flipper_protocol_error")
                        size = int(line[6:])
                        if size > 0xffffffff:
                            _error("flipper_protocol_error")
                        if size > MAX_FILE_BYTES:
                            _error("flipper_limit")
                        self._declared_size = size
                        self._state = "binary" if size else "trailer"
                    else:
                        index = self._buffer.find(PROMPT)
                        if index < 0:
                            # 바이트 프레임을 잇는 동안에도 줄 폭·개수 상한을 적용한다.
                            lines = self._buffer.split(b"\r\n")
                            if len(lines) > MAX_TEXT_LINES + 2 or any(len(x) > MAX_LINE_BYTES for x in lines):
                                _error("flipper_limit")
                            break
                        body = bytes(self._buffer[:index])
                        del self._buffer[:index + len(PROMPT)]
                        self._finish(self._text(body))
                elif self._state == "binary":
                    take = min(self._declared_size - self._received_size, len(self._buffer))
                    payload.extend(self._buffer[:take])
                    del self._buffer[:take]
                    self._received_size += take
                    if self._received_size == self._declared_size:
                        self._state = "trailer"
                    else:
                        break
                elif self._state == "trailer":
                    trailer = b"\r\n" + PROMPT
                    take = min(len(self._buffer), len(trailer))
                    if self._buffer[:take] != trailer[:take]:
                        _error("flipper_protocol_error")
                    if len(self._buffer) < len(trailer):
                        break
                    del self._buffer[:len(trailer)]
                    self._finish({"declared_size": self._declared_size,
                                  "received_size": self._received_size, "complete": True})
                else:
                    break
                if self._state == "ready":
                    break
            return bytes(payload)
        except FlipperCliError as exc:
            self.abort(exc.code)
            raise
