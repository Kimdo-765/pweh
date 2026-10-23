"""등록된 hello-only 릴리스의 내부 projection. 설치·실행·payload 읽기는 하지 않는다."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from importlib import resources
import json
import math
import re
import time
from typing import Callable

from .errors import PwehError
from .firmwarebuild import policy_blob, validate_release

MAX_CATALOG_BYTES = 1 << 20
MAX_SECONDS = 5.0
_KEY = ("0.1.0", "probe-hello", "esp32s3-devkitc1-hello")
_CODES = frozenset({"firmware_not_pinned", "espprobe_timeout", "espprobe_cancelled", "espprobe_protocol"})


class ProbeReleaseError(PwehError):
    """등록 자료·경로·내부 예외를 노출하지 않는 오류."""

    def __init__(self, code: str = "firmware_not_pinned"):
        super().__init__("고정 계측기 릴리스 확인을 완료하지 못했습니다.",
                         code=code if code in _CODES else "firmware_not_pinned")


def _fail(code="firmware_not_pinned"):
    raise ProbeReleaseError(code) from None


def _tick(deadline, cancel):
    if cancel is not None:
        try:
            stopped = cancel()
        except Exception:
            _fail("espprobe_protocol")
        if type(stopped) is not bool:
            _fail("espprobe_protocol")
        if stopped:
            _fail("espprobe_cancelled")
    if time.monotonic() >= deadline:
        _fail("espprobe_timeout")


def _deadline(deadline, cancel):
    try:
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            _fail("espprobe_protocol")
        if cancel is not None and not callable(cancel):
            _fail("espprobe_protocol")
        end = min(deadline, time.monotonic() + MAX_SECONDS)
    except (OverflowError, ValueError, TypeError):
        _fail("espprobe_protocol")
    _tick(end, cancel)
    return end


def _text(value, maximum):
    return type(value) is str and 0 < len(value) <= maximum and all(32 <= ord(c) <= 126 for c in value)


def _hex(value, size):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % size, value) is not None


@dataclass(frozen=True, repr=False)
class ProbeUsbPolicy:
    vid: int
    pid: int
    product: str
    serial_rule: str
    cdc_count: int

    def __post_init__(self):
        if (type(self.vid) is not int or self.vid != 0x303A or type(self.pid) is not int
                or self.pid != 0x4002 or type(self.cdc_count) is not int or self.cdc_count != 2
                or type(self.product) is not str or self.product != "PWEH espprobe"
                or type(self.serial_rule) is not str or self.serial_rule != "base-mac-12hex"):
            _fail()


@dataclass(frozen=True, repr=False)
class ProbeRelease:
    fw_name: str
    fw_version: str
    build_profile: str
    board: str
    git_commit: str
    idf_version: str
    image_sha256: str
    app_elf_sha256: str
    policy_sha256: str
    usb: ProbeUsbPolicy
    max_payload: int
    hb_ms: int
    max_credit: int
    caps: tuple[str, ...]
    tx_caps: tuple[str, ...]
    pins_allowed: tuple[tuple[str, tuple[int, ...]], ...]
    pclk_pad: int | None
    pin_drive: str | None
    spi_read_opcodes: tuple[int, ...]
    radio: str

    def __post_init__(self):
        for name, expected in (("fw_name", "PWEH espprobe"), ("fw_version", _KEY[0]),
                               ("build_profile", _KEY[1]), ("board", _KEY[2]),
                               ("idf_version", "v6.1"), ("radio", "none")):
            if type(getattr(self, name)) is not str or getattr(self, name) != expected:
                _fail()
        if not _hex(self.git_commit, 40) or any(not _hex(getattr(self, k), 64)
                for k in ("image_sha256", "app_elf_sha256", "policy_sha256")):
            _fail()
        if self.policy_sha256 != hashlib.sha256(policy_blob()).hexdigest() or type(self.usb) is not ProbeUsbPolicy:
            _fail()
        for name, expected in (("max_payload", 4096), ("hb_ms", 1000), ("max_credit", 0)):
            if type(getattr(self, name)) is not int or getattr(self, name) != expected:
                _fail()
        if any(type(getattr(self, k)) is not tuple or getattr(self, k)
               for k in ("caps", "tx_caps", "spi_read_opcodes")):
            _fail()
        if (type(self.pins_allowed) is not tuple or self.pins_allowed != (("H0", ()), ("H1", ()), ("H1a", ()))
                or any(type(row) is not tuple or type(row[0]) is not str or type(row[1]) is not tuple
                       for row in self.pins_allowed) or self.pclk_pad is not None or self.pin_drive is not None):
            _fail()


def _read_release_bytes() -> bytes:
    """패키지의 고정 파일만 제한해 읽는다. 시험은 이 reader만 대체한다."""
    with resources.files("pweh.data").joinpath("espprobe-releases.json").open("rb") as stream:
        return stream.read(MAX_CATALOG_BYTES + 1)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            _fail()
        result[key] = value
    return result


def _number(value):
    if len(value) > 32:
        _fail()
    return int(value)


def _reject_number(value):
    _fail()


def load_probe_release(*, deadline: float, cancel: Callable[[], bool] | None = None) -> ProbeRelease:
    """고정 catalog 한 항목을 검증한다. 늦은 I/O 결과를 사용하지 않는다."""
    end = _deadline(deadline, cancel)
    try:
        raw = _read_release_bytes()
        _tick(end, cancel)
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_CATALOG_BYTES:
            _fail()
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_int=_number,
                              parse_float=_reject_number, parse_constant=_reject_number)
        _tick(end, cancel)
        if (type(document) is not dict or document.get("schema") != "pweh.espprobe-releases/v1"
                or type(document.get("releases")) is not list or len(document["releases"]) > 100):
            _fail()
        seen, selected = set(), None
        for entry in document["releases"]:
            _tick(end, cancel)
            validate_release(entry)
            key = (entry["fw_version"], entry["build_profile"], entry["board"])
            if key in seen:
                _fail()
            seen.add(key)
            if key == _KEY:
                selected = entry
        if selected is None:
            _fail()
        entry = selected
        if (type(entry.get("protocol_version")) is not int or entry["protocol_version"] != 1
                or type(entry["verification"].get("runs")) is not int
                or any(type(row.get("offset")) is not int for row in entry["files"]
                       if row["role"] in ("app", "bootloader", "partition-table", "merged"))):
            _fail()
        usb = entry["usb"]
        if type(usb) is not dict or set(usb) != {"vid", "pid", "product", "serial_rule", "cdc_count"}:
            _fail()
        policy = ProbeUsbPolicy(**usb)
        result = ProbeRelease(**{k: entry[k] for k in (
            "fw_name", "fw_version", "build_profile", "board", "git_commit", "idf_version",
            "image_sha256", "app_elf_sha256", "policy_sha256", "pclk_pad", "pin_drive", "radio")},
            usb=policy, **entry["limits"], caps=tuple(entry["caps"]), tx_caps=tuple(entry["tx_caps"]),
            pins_allowed=tuple((k, tuple(entry["pins_allowed"][k])) for k in ("H0", "H1", "H1a")),
            spi_read_opcodes=tuple(entry["spi_read_opcodes"]))
        _tick(end, cancel)
        return result
    except ProbeReleaseError:
        raise
    except Exception:
        _fail()
