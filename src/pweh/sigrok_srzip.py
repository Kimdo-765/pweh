"""고정 OLS 출력의 동일 fd srzip 검사. 경로 재열기·추출·원시 데이터 반환은 하지 않는다."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from decimal import Decimal
import io
import json
import math
import os
import re
import stat
import struct
import time
from typing import Callable
import zipfile
import zlib

from .errors import ValidationFailed
from .sigrok_capture import CaptureChannel, CaptureCommand


_MESSAGES = {
    "invalid": "캡처 검사 입력이 올바르지 않습니다.",
    "bad_zip": "캡처 ZIP 구조 또는 CRC가 손상되었습니다.",
    "unsupported": "고정 캡처 profile에서 검사하지 않는 형식입니다.",
    "metadata_mismatch": "캡처 metadata가 고정 요청과 일치하지 않습니다.",
    "limit": "캡처 검사 작업량 상한을 넘었습니다.",
    "io_failed": "캡처 파일을 끝까지 읽지 못했습니다.",
    "check_failed": "캡처 파일의 동일성 또는 검사 callback을 확인하지 못했습니다.",
    "timeout": "캡처 검사 시간 예산이 끝났습니다.",
    "cancelled": "캡처 검사가 취소되었습니다.",
    "empty": "캡처 파일에 로직 샘플이 없습니다.",
}


class CaptureZipError(ValidationFailed):
    """원시 파일 이름·metadata·OS 오류를 포함하지 않는 고정 오류."""


def _fail(reason: str) -> None:
    raise CaptureZipError(_MESSAGES[reason], code="sigrok_capture_" + reason) from None


@dataclass(frozen=True)
class CaptureZipLimits:
    """시험에서 낮출 수 있으나 운영 hard ceiling을 높일 수 없는 내부 상한."""

    max_archive_bytes: int = 64 * 1024 * 1024
    max_uncompressed_bytes: int = 64 * 1024 * 1024
    max_logic_bytes: int = 32 * 1024 * 1024
    max_entries: int = 4096
    max_central_bytes: int = 1024 * 1024
    max_metadata_bytes: int = 64 * 1024
    max_version_bytes: int = 64
    max_metadata_lines: int = 4096
    max_line_bytes: int = 1024
    max_name_bytes: int = 64
    block_bytes: int = 64 * 1024
    max_activity_channel_samples: int = 8_388_608
    max_output_bytes: int = 16 * 1024


@dataclass(frozen=True)
class CaptureActivity:
    """검사한 prefix의 집계만 보유하며 에지 위치/샘플 원문은 보유하지 않는다."""

    index: int
    name: str
    edges: int
    high_count: int
    initial_level: int | None
    final_level: int | None


@dataclass(frozen=True)
class CaptureInspection:
    """모든 member의 CRC 확인 결과와 bounded 활동 통계."""

    version: int
    archive_bytes: int
    entries: int
    uncompressed_bytes: int
    logic_bytes: int
    unitsize: int
    samplerate_hz: int
    samples: int
    channels: tuple[CaptureChannel, ...]
    crc_verified: bool
    notes: tuple[str, ...]
    activity: tuple[CaptureActivity, ...]
    activity_samples: int
    activity_complete: bool
    activity_reason: str | None

    def to_dict(self) -> dict:
        """경로·원시 metadata 없이 반환할 값만 새 JSON 객체로 투영한다."""
        result = asdict(self)
        for key in ("channels", "activity", "notes"):
            result[key] = list(result[key])
        return result


def _identity(st: os.stat_result) -> tuple[int, ...]:
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)


class _Budget:
    def __init__(self, fd: int, size: int, deadline: float,
                 cancel: Callable[[], bool] | None, check: Callable[[], None] | None):
        self.fd, self.size = fd, size
        self.deadline, self.cancel, self.callback = deadline, cancel, check
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size != size:
            _fail("check_failed")
        self.identity = _identity(st)

    def check(self) -> None:
        if time.monotonic() >= self.deadline:
            _fail("timeout")
        try:
            cancelled = self.cancel() if self.cancel else False
            if self.callback:
                self.callback()
        except Exception:
            _fail("check_failed")
        if type(cancelled) is not bool:
            _fail("check_failed")
        if cancelled:
            _fail("cancelled")
        if _identity(os.fstat(self.fd)) != self.identity:
            _fail("check_failed")
        if time.monotonic() >= self.deadline:
            _fail("timeout")

    def read(self, offset: int, count: int) -> bytes:
        self.check()
        if offset < 0 or count < 0 or offset + count > self.size:
            _fail("bad_zip")
        data = os.pread(self.fd, count, offset)
        if len(data) != count:
            _fail("io_failed")
        self.check()
        return data


class _View(io.RawIOBase):
    """ZipFile의 seek 위치를 fd offset과 분리한다. close도 빌린 fd를 닫지 않는다."""

    def __init__(self, budget: _Budget, read_cap: int):
        super().__init__()
        self.budget, self.position, self.read_cap = budget, 0, read_cap

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence not in (os.SEEK_SET, os.SEEK_CUR, os.SEEK_END):
            _fail("bad_zip")
        base = (0, self.position, self.budget.size)[whence]
        position = base + offset
        if not 0 <= position <= self.budget.size:
            _fail("bad_zip")
        self.position = position
        return position

    def read(self, size: int = -1) -> bytes:
        remaining = self.budget.size - self.position
        count = remaining if size < 0 else min(size, remaining)
        if count > self.read_cap:
            _fail("limit")
        data = self.budget.read(self.position, count)
        self.position += count
        return data


_END = struct.Struct("<4s4H2IH")
_CENTRAL = struct.Struct("<4s6H3I5H2I")
_LOCAL = struct.Struct("<4s5H3I2H")
_CHUNK = re.compile(rb"logic-1-([1-9][0-9]{0,3})\Z")


@dataclass(frozen=True)
class _Member:
    offset: int
    compressed: int
    size: int
    method: int
    crc: int


def _extra(data: bytes) -> None:
    pos = 0
    while pos < len(data):
        if pos + 4 > len(data):
            _fail("bad_zip")
        kind, length = struct.unpack_from("<HH", data, pos)
        pos += 4
        if pos + length > len(data):
            _fail("bad_zip")
        if kind == 1:
            _fail("unsupported")
        pos += length


def _preflight(budget: _Budget, limits: CaptureZipLimits) -> tuple[dict[str, int], list[str], dict[str, _Member]]:
    """bounded EOCD/중앙목록/로컬 범위를 확인한 뒤에만 ZipFile 객체를 허용한다."""
    tail = budget.read(max(0, budget.size - 65557), min(budget.size, 65557))
    pos = len(tail)
    while True:
        pos = tail.rfind(b"PK\x05\x06", 0, pos)
        if pos < 0:
            _fail("bad_zip")
        budget.check()
        if pos + _END.size <= len(tail):
            end = _END.unpack_from(tail, pos)
            if pos + _END.size + end[-1] == len(tail):
                break
    _, disk, cd_disk, disk_entries, entries, cd_size, cd_offset, _ = end
    eocd = budget.size - len(tail) + pos
    if (disk or cd_disk or disk_entries != entries or entries == 65535
            or cd_size == 0xffffffff or cd_offset == 0xffffffff):
        _fail("unsupported")
    if eocd >= 20 and budget.read(eocd - 20, 4) == b"PK\x06\x07":
        _fail("unsupported")
    if not entries or cd_offset + cd_size != eocd:
        _fail("bad_zip")
    if entries > limits.max_entries or cd_size > limits.max_central_bytes:
        _fail("limit")
    central = budget.read(cd_offset, cd_size)
    names: dict[str, int] = {}
    members: dict[str, _Member] = {}
    chunks: dict[int, str] = {}
    ranges = []
    consumed, total, logic = 0, 0, 0
    for _ in range(entries):
        budget.check()
        if consumed + _CENTRAL.size > len(central):
            _fail("bad_zip")
        (sig, made, need, flags, method, _, _, crc, compressed, size, name_len, extra_len,
         comment_len, entry_disk, _, attrs, offset) = _CENTRAL.unpack_from(central, consumed)
        if sig != b"PK\x01\x02":
            _fail("bad_zip")
        if (entry_disk or compressed == 0xffffffff or size == 0xffffffff or offset == 0xffffffff
                or need > 20 or flags & ~0x080e or method not in (0, 8)):
            _fail("unsupported")
        mode = attrs >> 16
        if (attrs & 0x10 or (made >> 8 == 3 and stat.S_IFMT(mode) not in (0, stat.S_IFREG))):
            _fail("unsupported")
        start = consumed + _CENTRAL.size
        consumed = start + name_len + extra_len + comment_len
        if consumed > len(central):
            _fail("bad_zip")
        if not 1 <= name_len <= limits.max_name_bytes:
            _fail("limit")
        raw = central[start:start + name_len]
        match = _CHUNK.fullmatch(raw)
        if raw not in (b"version", b"metadata", b"logic-1") and not match:
            _fail("unsupported")
        name = raw.decode("ascii")
        if name in names:
            _fail("bad_zip")
        names[name] = size
        if match:
            chunks[int(match[1])] = name
        _extra(central[start + name_len:start + name_len + extra_len])
        total += size
        if total > limits.max_uncompressed_bytes:
            _fail("limit")
        if name == "metadata" and size > limits.max_metadata_bytes:
            _fail("limit")
        if name == "version" and size > limits.max_version_bytes:
            _fail("limit")
        if name.startswith("logic-"):
            logic += size
            if logic > limits.max_logic_bytes:
                _fail("limit")
            if size % 4:
                _fail("metadata_mismatch")
        if offset + _LOCAL.size > cd_offset:
            _fail("bad_zip")
        (local_sig, local_need, local_flags, local_method, _, _, local_crc,
         local_compressed, local_size, local_name, local_extra) = _LOCAL.unpack(budget.read(offset, _LOCAL.size))
        if (local_sig != b"PK\x03\x04" or local_need != need or local_flags != flags
                or local_method != method or local_name != name_len):
            _fail("bad_zip")
        data_start = offset + _LOCAL.size + local_name + local_extra
        data_end = data_start + compressed
        if data_end > cd_offset:
            _fail("bad_zip")
        if budget.read(offset + _LOCAL.size, local_name) != raw:
            _fail("bad_zip")
        _extra(budget.read(offset + _LOCAL.size + local_name, local_extra))
        members[name] = _Member(data_start, compressed, size, method, crc)
        if flags & 8:
            if ((local_crc, local_compressed, local_size) not in ((0, 0, 0), (crc, compressed, size))):
                _fail("bad_zip")
            if data_end + 12 > cd_offset:
                _fail("bad_zip")
            has_sig = budget.read(data_end, 4) == b"PK\x07\x08"
            descriptor_start = data_end + (4 if has_sig else 0)
            if descriptor_start + 12 > cd_offset:
                _fail("bad_zip")
            if struct.unpack("<III", budget.read(descriptor_start, 12)) != (crc, compressed, size):
                _fail("bad_zip")
            data_end = descriptor_start + 12
        elif (local_crc, local_compressed, local_size) != (crc, compressed, size):
            _fail("bad_zip")
        ranges.append((offset, data_end))
    if consumed != cd_size or "version" not in names or "metadata" not in names:
        _fail("bad_zip")
    ranges.sort()
    if ranges[0][0] != 0:
        _fail("unsupported")
    if any(ranges[i][0] < ranges[i - 1][1] for i in range(1, len(ranges))):
        _fail("bad_zip")
    if "logic-1" in names:
        if chunks:
            _fail("bad_zip")
        ordered = ["logic-1"]
    else:
        if sorted(chunks) != list(range(1, len(chunks) + 1)):
            _fail("bad_zip")
        ordered = [chunks[i] for i in range(1, len(chunks) + 1)]
    return names, ordered, members


def _blocks(member: _Member, budget: _Budget, limits: CaptureZipLimits):
    """선언 크기로 잘라 읽지 않고 실제 deflate EOF·길이·CRC를 모두 확인한다."""
    decoder = zlib.decompressobj(-15) if member.method == 8 else None
    done, crc, offset = 0, 0, 0

    def verified(data: bytes) -> bytes:
        nonlocal done, crc
        done += len(data)
        if done > member.size:
            _fail("bad_zip")
        crc = zlib.crc32(data, crc)
        return data

    while offset < member.compressed:
        pending = budget.read(member.offset + offset, min(limits.block_bytes, member.compressed - offset))
        offset += len(pending)
        if decoder is None:
            yield verified(pending)
            continue
        while True:
            budget.check()
            data = decoder.decompress(pending, limits.block_bytes)
            pending = decoder.unconsumed_tail
            if decoder.unused_data:
                _fail("bad_zip")
            if data:
                yield verified(data)
            if not pending:
                break
    if decoder is not None:
        # max_length 경계에서 내부에 남은 출력도 같은 작은 블록으로 소진한다.
        while True:
            budget.check()
            data = decoder.decompress(b"", limits.block_bytes)
            if not data:
                break
            yield verified(data)
        if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            _fail("bad_zip")
    if done != member.size or crc != member.crc:
        _fail("bad_zip")
    budget.check()


_RATE = re.compile(r"([0-9]{1,9}(?:\.[0-9]{1,9})?) (Hz|kHz|MHz)\Z")
_PROBE = re.compile(r"probe([1-9]|[12][0-9]|3[0-2])\Z")
_INT = re.compile(r"(?:0|[1-9][0-9]?)\Z")


def _metadata(raw: bytes, command: CaptureCommand, limits: CaptureZipLimits) -> int:
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError:
        _fail("metadata_mismatch")
    if any(ord(c) < 32 and c not in "\r\n\t" for c in text):
        _fail("metadata_mismatch")
    lines = text.splitlines()
    if len(lines) > limits.max_metadata_lines or any(len(line.encode("utf-8")) > limits.max_line_bytes for line in lines):
        _fail("limit")
    sections: dict[str, dict[str, str]] = {}
    current = None
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            if line not in ("[global]", "[device 1]"):
                _fail("unsupported")
            current = line[1:-1]
            if current in sections:
                _fail("metadata_mismatch")
            sections[current] = {}
            continue
        if current is None or "=" not in line:
            _fail("metadata_mismatch")
        key, value = (part.strip() for part in line.split("=", 1))
        if key in sections[current]:
            _fail("metadata_mismatch")
        allowed = key == "sigrok version" if current == "global" else (
            key in ("capturefile", "total probes", "samplerate", "total analog", "unitsize")
            or _PROBE.fullmatch(key) is not None)
        if not allowed:
            _fail("unsupported")
        sections[current][key] = value
    if set(sections) != {"global", "device 1"} or set(sections["global"]) != {"sigrok version"}:
        _fail("metadata_mismatch")
    if not re.fullmatch(r"[A-Za-z0-9.+_-]{1,64}", sections["global"]["sigrok version"]):
        _fail("metadata_mismatch")
    dev = sections["device 1"]
    expected_keys = {"capturefile", "total probes", "samplerate", "total analog", "unitsize"}
    expected_keys.update(f"probe{ch.index + 1}" for ch in command.channels)
    if (set(dev) != expected_keys or dev["capturefile"] != "logic-1"
            or dev["unitsize"] != "4" or dev["total analog"] != "0"
            or not _INT.fullmatch(dev["total probes"])):
        _fail("metadata_mismatch")
    probes = int(dev["total probes"])
    if not len(command.channels) <= probes <= 32:
        _fail("metadata_mismatch")
    for ch in command.channels:
        if dev[f"probe{ch.index + 1}"] != ch.name:
            _fail("metadata_mismatch")
    match = _RATE.fullmatch(dev["samplerate"])
    if not match:
        _fail("metadata_mismatch")
    rate = Decimal(match[1]) * {"Hz": 1, "kHz": 1000, "MHz": 1_000_000}[match[2]]
    if rate != rate.to_integral_value() or rate != command.expected_reported_rate_hz:
        _fail("metadata_mismatch")
    return int(rate)


class _Activity:
    def __init__(self, command: CaptureCommand, limits: CaptureZipLimits):
        self.channels = command.channels
        self.cap = limits.max_activity_channel_samples // len(self.channels)
        self.samples = 0
        self.stats = [[0, 0, None, None] for _ in self.channels]
        self.tables = [bytes(1 if n & (1 << (ch.index % 8)) else 0 for n in range(256))
                       for ch in self.channels]

    def add(self, data: bytes, budget: _Budget) -> None:
        count = min(len(data) // 4, self.cap - self.samples)
        if count <= 0:
            return
        data = data[:count * 4]
        for ch, table, row in zip(self.channels, self.tables, self.stats):
            budget.check()
            lane = data[ch.index // 8::4].translate(table)
            value = int.from_bytes(lane, "little")
            edges = (value ^ (value >> 8)).bit_count() - lane[-1]
            if row[3] is not None and row[3] != lane[0]:
                edges += 1
            if row[2] is None:
                row[2] = lane[0]
            row[0] += edges
            row[1] += lane.count(1)
            row[3] = lane[-1]
        self.samples += count

    def result(self) -> tuple[CaptureActivity, ...]:
        return tuple(CaptureActivity(ch.index, ch.name, *row)
                     for ch, row in zip(self.channels, self.stats))


def _inspect(budget: _Budget, command: CaptureCommand, limits: CaptureZipLimits) -> CaptureInspection:
    names, chunks, members = _preflight(budget, limits)
    budget.check()
    logic_size = sum(names[name] for name in chunks)
    if logic_size // 4 > command.samples:
        _fail("metadata_mismatch")
    activity = _Activity(command, limits)
    total = 0
    with _View(budget, max(65557, limits.max_central_bytes, limits.block_bytes)) as view:
        with zipfile.ZipFile(view) as archive:
            if {entry.filename: entry.file_size for entry in archive.infolist()} != names:
                _fail("bad_zip")
            small: dict[str, bytes] = {}
            for name in ["version", "metadata", *chunks]:
                read = 0
                parts = []
                carry = b""
                for data in _blocks(members[name], budget, limits):
                    read += len(data)
                    total += len(data)
                    if total > limits.max_uncompressed_bytes:
                        _fail("limit")
                    if name in ("version", "metadata"):
                        parts.append(data)
                    else:
                        data = carry + data
                        aligned = len(data) - len(data) % 4
                        carry = data[aligned:]
                        activity.add(data[:aligned], budget)
                if carry:
                    _fail("metadata_mismatch")
                if read != names[name]:
                    _fail("bad_zip")
                if name in ("version", "metadata"):
                    small[name] = b"".join(parts)
            budget.check()
    if small["version"] != b"2":
        _fail("unsupported")
    rate = _metadata(small["metadata"], command, limits)
    samples = logic_size // 4
    if not samples:
        _fail("empty")
    notes = []
    if rate != command.samplerate_hz:
        notes.append("rate_quantized")
    if samples < command.samples:
        notes.append("fewer_samples")
    complete = activity.samples == samples
    result = CaptureInspection(2, budget.size, len(names), total, logic_size, 4, rate, samples,
                               command.channels, True, tuple(notes), activity.result(), activity.samples,
                               complete, None if complete else "activity_limit")
    if len((json.dumps(result.to_dict(), separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")) > limits.max_output_bytes:
        _fail("limit")
    budget.check()
    return result


def inspect_capture_fd(fd: int, *, size: int, command: CaptureCommand,
                       limits: CaptureZipLimits = CaptureZipLimits(), deadline: float,
                       cancel: Callable[[], bool] | None = None,
                       check: Callable[[], None] | None = None) -> CaptureInspection:
    """빌린 일반 파일 fd의 전체 CRC/metadata를 검사한다. 호출자는 전체 수명 동안 fd를 소유한다."""
    if (type(fd) is not int or fd < 0 or type(size) is not int or size < 0
            or type(command) is not CaptureCommand or type(limits) is not CaptureZipLimits
            or (cancel is not None and not callable(cancel)) or (check is not None and not callable(check))
            or type(deadline) not in (int, float)):
        _fail("invalid")
    try:
        end = float(deadline)
    except (OverflowError, ValueError):
        _fail("invalid")
    if not math.isfinite(end):
        _fail("invalid")
    ceilings = CaptureZipLimits()
    for field in fields(limits):
        value = getattr(limits, field.name)
        if type(value) is not int or not 1 <= value <= getattr(ceilings, field.name):
            _fail("invalid")
    if limits.block_bytes % 4:
        _fail("invalid")
    command.__post_init__()
    if size > limits.max_archive_bytes:
        _fail("limit")
    try:
        budget = _Budget(fd, size, min(end, time.monotonic() + 60), cancel, check)
        budget.check()
        if size == 0:
            _fail("empty")
        return _inspect(budget, command, limits)
    except CaptureZipError:
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, EOFError, struct.error):
        _fail("bad_zip")
    except (OSError, OverflowError):
        _fail("io_failed")
    except (ValueError, UnicodeError, NotImplementedError):
        _fail("unsupported")
