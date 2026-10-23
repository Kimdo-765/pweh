"""고정 계측기의 내부 입장 자료와 HELLO를 대조한다. 관찰·pin 생산·포트 I/O는 없다.

입력은 현재 검증을 마친 생산자의 projection이어야 한다. 순수 값 생성이 실제 원장/증명의
진위를 증명하지 않으며, 생산자가 없는 운영 경로는 None으로 거부된다.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
import hashlib
import json
import math
import os
import re
import time
from typing import Callable

from . import espprobe_protocol as P
from .errors import PwehError
from .espprobe_release import ProbeRelease, ProbeReleaseError
from .instrument_guard import PIN_QUESTIONS
from .portidentity import PortIdentity
from .ports import PortRoute, identity_projection

_CODES = frozenset({"firmware_not_pinned", "instrument_identity_unknown", "instrument_identity_mismatch",
                    "route_changed", "espprobe_protocol", "espprobe_timeout", "espprobe_cancelled"})
_INTERFACES = ((0, 2, 2, 0), (1, 10, 0, 0), (2, 2, 2, 0), (3, 10, 0, 0))


class ProbeAdmissionError(PwehError):
    """식별값·경로·응답을 포함하지 않는 닫힌 오류."""

    def __init__(self, code="instrument_identity_mismatch"):
        super().__init__("고정 계측기의 입장 또는 HELLO 확인을 완료하지 못했습니다.",
                         code=code if code in _CODES else "instrument_identity_mismatch")


def _fail(code="instrument_identity_mismatch"):
    raise ProbeAdmissionError(code) from None


def _text(value):
    return type(value) is str and 0 < len(value) <= 4096 and all(ord(c) >= 32 and ord(c) != 127 for c in value)


def _uint(value):
    return type(value) is int and 0 <= value <= (1 << 64) - 1


def _sha(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _mac(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{12}", value) is not None


def _optional(rule):
    return lambda value: value is None or rule(value)


def _tuple(rule, limit):
    return lambda value: type(value) is tuple and len(value) <= limit and all(rule(item) for item in value)


def _identity(value):
    if type(value) is not PortIdentity or type(value.present) is not bool:
        return False
    for f in fields(value):
        item = getattr(value, f.name)
        if f.name == "observed_at":
            # 관찰 시각은 아래 canonical 신원 hash에서 제외한다.
            try:
                if type(item) not in (int, float) or not math.isfinite(item):
                    return False
            except OverflowError:
                return False
        elif f.name == "present":
            continue
        elif f.name in ("location_paths", "reasons"):
            if not _tuple(_text, 64)(item):
                return False
        elif f.name == "tty_devnum":
            if item is not None and not (type(item) is tuple and len(item) == 2 and all(_uint(x) for x in item)):
                return False
        elif not _optional(_text)(item):
            return False
    return True


class _Projection:
    """생성자에서 mutable/잘못된 scalar가 frozen 값 안에 들어가지 못하게 한다."""

    def __post_init__(self):
        for name, rule in _RULES[type(self)].items():
            if not rule(getattr(self, name)):
                _fail()


@dataclass(frozen=True, repr=False)
class ProbeRecordRef(_Projection):
    case_id: str
    seq: int
    entry_sha256: str


@dataclass(frozen=True, repr=False)
class ProbeChipFact(_Projection):
    record: ProbeRecordRef
    data_sha256: str
    base_mac: str
    chip: str
    chip_revision: int
    flash_size: int


@dataclass(frozen=True, repr=False)
class ProbeSecurityFact(_Projection):
    record: ProbeRecordRef
    data_sha256: str
    base_mac: str
    chip: str
    status: str
    secure_boot: bool | None
    flash_encryption: bool | None
    secure_download_mode: bool | None
    read_flash_possible: bool | None


@dataclass(frozen=True, repr=False)
class ProbeBackup(_Projection):
    record: ProbeRecordRef
    base_mac: str
    chip: str
    role: str
    sha256: str
    observed_sha256: str
    size: int
    offset: int
    length: int
    verify: str
    match: bool | None


@dataclass(frozen=True, repr=False)
class ProbePinEvidence(_Projection):
    pin_id: str
    fingerprint: str
    subject_sha256: str
    binding_sha256: str
    questions_sha256: str
    case_id: str
    base_mac: str
    binding_scope: str
    instrument_id: str
    release_key: tuple[str, str, str, str]
    chip_entry_sha256: str
    security_entry_sha256: str
    backup_entry_sha256s: tuple[str, str]
    observation_sha256: str


@dataclass(frozen=True, repr=False)
class ProbeAuthority(_Projection):
    case_id: str
    chip: ProbeChipFact
    security: ProbeSecurityFact
    primary_backup: ProbeBackup
    verification_backup: ProbeBackup
    pin: ProbePinEvidence | None


@dataclass(frozen=True, repr=False)
class ProbeObservation(_Projection):
    identity: PortIdentity
    complete: bool | None
    parent_instance: str | None
    parent_serial: str | None
    product: str | None
    driver_service: str | None
    interfaces: tuple[tuple[int, int, int, int], ...] | None
    siblings: tuple[PortIdentity, ...]
    scope_keys: tuple[str, ...]
    boot_identities: tuple[PortIdentity, ...]
    aux_inventory: tuple[PortIdentity, ...] | None
    aux_present: tuple[PortIdentity, ...] | None
    aux_complete: bool | None


@dataclass(frozen=True, repr=False)
class ProbeAdmission:
    case_id: str
    release: ProbeRelease
    base_mac: str
    chip_revision: int
    pin_id: str
    pin_fingerprint: str
    authority_sha256: str
    route: PortRoute
    observation: ProbeObservation
    claim_keys: tuple[str, ...]

    def __post_init__(self):
        if (not _text(self.case_id) or type(self.release) is not ProbeRelease or not _mac(self.base_mac)
                or not _uint(self.chip_revision) or self.chip_revision > 65535 or not _text(self.pin_id)
                or not _sha(self.pin_fingerprint) or not _sha(self.authority_sha256)
                or type(self.route) is not PortRoute or type(self.observation) is not ProbeObservation
                or not _tuple(_text, 64)(self.claim_keys) or not self.claim_keys
                or tuple(sorted(set(self.claim_keys))) != self.claim_keys):
            _fail()


@dataclass(frozen=True, repr=False)
class ProbeHello:
    release: ProbeRelease
    base_mac: str
    chip_revision: int
    psram_bytes: int | None
    flash_voltage_mv: int | None
    reset_reason: str
    last_release_reason: str
    session_token: int
    boot_id: bytes
    usb_session: int
    hb_ms: int

    def __post_init__(self):
        if (type(self.release) is not ProbeRelease or not _mac(self.base_mac)
                or not _uint(self.chip_revision) or self.chip_revision > 65535
                or not _optional(lambda v: _uint(v) and v <= 0xFFFFFFFF)(self.psram_bytes)
                or not _optional(lambda v: _uint(v) and v <= 65535)(self.flash_voltage_mv)
                or type(self.reset_reason) is not str or self.reset_reason not in P.RESET_REASONS
                or type(self.last_release_reason) is not str or self.last_release_reason not in P.RELEASE_REASONS
                or not _uint(self.session_token) or not 1 <= self.session_token <= 0xFFFFFFFF
                or not _uint(self.usb_session) or not 1 <= self.usb_session <= 0xFFFFFFFF
                or type(self.boot_id) is not bytes or len(self.boot_id) != 16
                or type(self.hb_ms) is not int or self.hb_ms != 1000):
            _fail("espprobe_protocol")


def _is(kind):
    return lambda value: type(value) is kind


_BOOL = _optional(_is(bool))
_REF = _is(ProbeRecordRef)
_RULES = {
    ProbeRecordRef: dict(case_id=_text, seq=lambda v: _uint(v) and v > 0, entry_sha256=_sha),
    ProbeChipFact: dict(record=_REF, data_sha256=_sha, base_mac=_mac, chip=_text,
                        chip_revision=_uint, flash_size=_uint),
    ProbeSecurityFact: dict(record=_REF, data_sha256=_sha, base_mac=_mac, chip=_text, status=_text,
                            secure_boot=_BOOL, flash_encryption=_BOOL, secure_download_mode=_BOOL,
                            read_flash_possible=_BOOL),
    ProbeBackup: dict(record=_REF, base_mac=_mac, chip=_text, role=_text, sha256=_sha,
                      observed_sha256=_sha, size=_uint, offset=_uint, length=_uint, verify=_text, match=_BOOL),
    ProbePinEvidence: dict(pin_id=_text, fingerprint=_sha, subject_sha256=_sha, binding_sha256=_sha,
        questions_sha256=_sha, case_id=_text, base_mac=_mac, binding_scope=_text, instrument_id=_text,
        release_key=lambda v: _tuple(_text, 4)(v) and len(v) == 4,
        chip_entry_sha256=_sha, security_entry_sha256=_sha,
        backup_entry_sha256s=lambda v: _tuple(_sha, 2)(v) and len(v) == 2, observation_sha256=_sha),
    ProbeAuthority: dict(case_id=_text, chip=_is(ProbeChipFact), security=_is(ProbeSecurityFact),
        primary_backup=_is(ProbeBackup), verification_backup=_is(ProbeBackup), pin=_optional(_is(ProbePinEvidence))),
    ProbeObservation: dict(identity=_identity, complete=_BOOL, parent_instance=_optional(_text),
        parent_serial=_optional(_text), product=_optional(_text), driver_service=_optional(_text),
        interfaces=_optional(_tuple(lambda row: _tuple(lambda n: _uint(n) and n <= 255, 4)(row) and len(row) == 4, 16)),
        siblings=_tuple(_identity, 16), scope_keys=_tuple(_text, 64), boot_identities=_tuple(_identity, 16),
        aux_inventory=_optional(_tuple(_identity, 16)), aux_present=_optional(_tuple(_identity, 16)), aux_complete=_BOOL),
}


def _plain(value):
    """검증된 작은 projection만 canonical 자료로 바꾼다. 관찰 시각은 신원에서 제외한다."""
    if type(value) in _RULES or type(value) is PortIdentity:
        return {f.name: _plain(getattr(value, f.name)) for f in fields(value)
                if not (type(value) is PortIdentity and f.name == "observed_at")}
    if type(value) is tuple:
        return [_plain(item) for item in value]
    return value


def _digest(value):
    raw = json.dumps(_plain(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


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


def _authority(release, case_id, authority):
    if type(authority) is not ProbeAuthority:
        _fail("instrument_identity_unknown")
    pin = authority.pin
    if pin is None:
        _fail("firmware_not_pinned")
    chip, sec = authority.chip, authority.security
    backups = authority.primary_backup, authority.verification_backup
    records = tuple(row.record for row in (chip, sec) + backups)
    if (not _text(case_id) or authority.case_id != case_id or pin.case_id != case_id
            or any(r.case_id != case_id for r in records) or len({r.seq for r in records}) != 4
            or len({r.entry_sha256 for r in records}) != 4 or not 0 < chip.flash_size <= 1 << 32
            or chip.chip_revision > 65535 or chip.chip != "esp32s3"
            or any(row.chip != chip.chip or row.base_mac != chip.base_mac for row in (sec,) + backups)
            or pin.base_mac != chip.base_mac):
        _fail()
    if (sec.status != "ok" or sec.secure_boot is not False or sec.flash_encryption is not False
            or sec.secure_download_mode is not False or sec.read_flash_possible is not True):
        _fail("instrument_identity_unknown" if any(v is None for v in (
            sec.secure_boot, sec.flash_encryption, sec.secure_download_mode, sec.read_flash_possible)) else "instrument_identity_mismatch")
    for row, role in zip(backups, ("primary", "verification-read")):
        if (row.role != role or row.offset != 0 or row.length != row.size or row.size != chip.flash_size
                or row.verify != "double" or row.match is not True or row.sha256 != row.observed_sha256):
            _fail()
    if backups[0].sha256 != backups[1].sha256:
        _fail()
    if (pin.binding_scope != "instrument" or pin.instrument_id != chip.base_mac
            or pin.release_key != (release.fw_version, release.build_profile, release.board, release.image_sha256)
            or pin.chip_entry_sha256 != chip.record.entry_sha256 or pin.security_entry_sha256 != sec.record.entry_sha256
            or pin.backup_entry_sha256s != tuple(row.record.entry_sha256 for row in backups)
            or pin.questions_sha256 != _digest(PIN_QUESTIONS)):
        _fail("firmware_not_pinned")
    return chip


def _observed(release, chip, obs, route, scope_keys):
    if type(obs) is not ProbeObservation or obs.complete is not True or obs.aux_complete is not True:
        _fail("instrument_identity_unknown")
    if any(getattr(obs, k) is None for k in ("parent_instance", "parent_serial", "product", "driver_service",
                                             "interfaces", "aux_inventory", "aux_present")):
        _fail("instrument_identity_unknown")
    selected = obs.identity
    if selected.status != "known" or selected.present is not True:
        _fail("instrument_identity_unknown")
    if (obs.parent_serial != chip.base_mac.upper() or obs.product != release.usb.product
            or obs.interfaces != _INTERFACES or obs.aux_present or selected.interface_number != "00"
            or selected.backend not in ("windows", "linux")):
        _fail()
    if obs.driver_service != ("usbser" if selected.backend == "windows" else "cdc_acm"):
        _fail()
    # 두 native CDC endpoint와 전체 descriptor 관찰이 함께 필요하다.
    if len(obs.siblings) != 2 or {row.interface_number for row in obs.siblings} != {"00", "02"}:
        _fail("instrument_identity_unknown")
    if len({row.endpoint_key for row in obs.siblings}) != 2:
        _fail()
    selected_rows = [row for row in obs.siblings if row.interface_number == "00"]
    if _plain(selected_rows[0]) != _plain(selected):
        _fail()
    required = set()
    for row in obs.siblings:
        if row.status != "known" or row.present is not True:
            _fail("instrument_identity_unknown")
        if (row.kind != "serial" or row.backend != selected.backend or row.vid != "303a" or row.pid != "4002"
                or row.usb_ancestor != obs.parent_instance or row.serial is None
                or row.serial.upper() != obs.parent_serial or row.reasons
                or row.serial_basis != ("instance-tail" if row.backend == "windows" else "sysfs")):
            _fail()
        if row.backend == "windows":
            if (not re.fullmatch(r"COM[1-9][0-9]{0,3}", row.endpoint_key) or int(row.endpoint_key[3:]) > 4096
                    or row.parent_instance != obs.parent_instance or not row.device_instance
                    or not re.fullmatch(r"USB\\VID_303A&PID_4002&MI_" + row.interface_number + r"\\[^\\]+", row.device_instance)):
                _fail()
            required.update(("win:" + row.endpoint_key, "winif:" + row.device_instance))
        else:
            if (row.tty_devnum is None or row.endpoint_key != "tty:%d:%d" % row.tty_devnum
                    or row.parent_instance != obs.parent_instance or not row.device_instance):
                _fail()
            required.add("tty:%d:%d" % row.tty_devnum)
    if selected.backend == "windows":
        if obs.parent_instance != "USB\\VID_303A&PID_4002\\" + obs.parent_serial:
            _fail()
        required.add("winif:" + obs.parent_instance)
    else:
        parent = obs.parent_instance.rsplit("/", 1)[-1]
        required.update("usbif:%s:1.%d" % (parent, i) for i in range(4))
    # aux 부재와 boot/native 분리는 현재 완전 관찰의 책임이며 빈 None으로 승격하지 않는다.
    for row in obs.boot_identities + obs.aux_inventory:
        if row.status != "known":
            _fail("instrument_identity_unknown")
        if row.endpoint_key in {s.endpoint_key for s in obs.siblings}:
            _fail()
    if not _tuple(_text, 64)(scope_keys) or not scope_keys or tuple(sorted(set(scope_keys))) != scope_keys:
        _fail("route_changed")
    if scope_keys != obs.scope_keys or not required.issubset(scope_keys):
        _fail("route_changed")
    if type(route) is not PortRoute or not _identity(route.identity) or _plain(route.identity) != _plain(selected):
        _fail("route_changed")
    if route.purpose != "serial-session" or route.lock_key not in required or route.warnings:
        _fail("route_changed")
    if (route.device_id, route.identity_strength) != identity_projection(selected):
        _fail("route_changed")
    if selected.backend == "windows":
        if (route.backend != "win-helper" or route.side != "windows" or route.ref != selected.endpoint_key
                or route.device_path != selected.endpoint_key or route.lock_key != "win:" + selected.endpoint_key
                or route.node_identity is not None):
            _fail("route_changed")
    else:
        if (route.backend != "posix-tty" or route.side != "local" or not _text(route.ref)
                or not route.ref.startswith("/dev/") or ".." in route.ref.split("/")
                or type(route.device_path) is not str or not re.fullmatch(r"/dev/ttyACM[0-9]+", route.device_path)
                or route.lock_key != selected.endpoint_key
                or route.node_identity is None
                or (os.major(route.node_identity[2]), os.minor(route.node_identity[2])) != selected.tty_devnum):
            _fail("route_changed")


def validate_probe_admission(*, release: ProbeRelease, case_id: str, authority: ProbeAuthority | None,
                             observation: ProbeObservation | None, route: PortRoute, scope_keys: tuple[str, ...],
                             deadline: float, cancel: Callable[[], bool] | None = None) -> ProbeAdmission:
    """검증된 내부 projection을 결속한다. 누락 자료를 생산하거나 장치를 열지 않는다."""
    try:
        if type(deadline) not in (int, float) or not math.isfinite(deadline) or (cancel is not None and not callable(cancel)):
            _fail("espprobe_protocol")
        end = min(deadline, time.monotonic() + 5.0)
        _tick(end, cancel)
        if type(release) is not ProbeRelease:
            _fail("firmware_not_pinned")
        release.__post_init__()
        chip = _authority(release, case_id, authority)
        _tick(end, cancel)
        _observed(release, chip, observation, route, scope_keys)
        if authority.pin.observation_sha256 != _digest(observation):
            _fail("route_changed")
        result = ProbeAdmission(case_id, release, chip.base_mac, chip.chip_revision,
            authority.pin.pin_id, authority.pin.fingerprint, _digest(authority), route, observation, scope_keys)
        _tick(end, cancel)
        return result
    except ProbeAdmissionError:
        raise
    except ProbeReleaseError:
        _fail("firmware_not_pinned")
    except (OverflowError, TypeError, ValueError, AttributeError):
        _fail("espprobe_protocol")


def verify_probe_hello(frame: P.Frame, *, nonce: bytes, admission: ProbeAdmission) -> ProbeHello:
    """bounded HELLO의 신원·정책을 대조한다. token과 원문은 내부 값으로만 보유한다."""
    try:
        if type(admission) is not ProbeAdmission or type(admission.release) is not ProbeRelease:
            _fail("firmware_not_pinned")
        if type(nonce) is not bytes or len(nonce) != 16 or type(frame) is not P.Frame:
            _fail("espprobe_protocol")
        for name, value in (("version", 1), ("type", P.RSP), ("op", P.HELLO), ("flags", 0), ("credit", 0), ("seq", 1)):
            if type(getattr(frame, name)) is not int or getattr(frame, name) != value:
                _fail("espprobe_protocol")
        if type(frame.session) is not int or not 1 <= frame.session <= 0xFFFFFFFF:
            _fail("espprobe_protocol")
        hello = P.decode_hello(frame.payload)
        if hello["nonce"] != nonce.hex() or frame.session != hello["session_token"]:
            _fail("espprobe_protocol")
        release = admission.release
        for name in ("fw_name", "fw_version", "build_profile", "board", "git_commit", "idf_version", "image_sha256", "app_elf_sha256"):
            if hello[name] != getattr(release, name):
                _fail("firmware_not_pinned")
        if (hello["caps"] != list(release.caps) or hello["tx_caps"] != list(release.tx_caps)
                or hello["pins_allowed"] != {k: list(v) for k, v in release.pins_allowed}
                or hello["pclk_pad"] != release.pclk_pad or hello["pin_drive"] != release.pin_drive
                or hello["spi_read_opcodes"] != list(release.spi_read_opcodes) or hello["radio"] != release.radio
                or hello["limits"] != {"max_payload": release.max_payload, "hb_ms": release.hb_ms, "max_credit": release.max_credit}):
            _fail("firmware_not_pinned")
        if (hello["base_mac"] != admission.base_mac or hello["chip"]["model"] != "esp32s3"
                or hello["chip"]["revision"] != admission.chip_revision
                or hello["usb"] != {"vid": release.usb.vid, "pid": release.usb.pid, "product": release.usb.product,
                                    "serial": admission.base_mac.upper()}):
            _fail()
        return ProbeHello(release, admission.base_mac, admission.chip_revision, hello["chip"]["psram_bytes"],
            hello["chip"]["flash_voltage_mv"], hello["reset_reason"], hello["last_release_reason"],
            hello["session_token"], bytes.fromhex(hello["boot_id"]), hello["usb_session"], hello["limits"]["hb_ms"])
    except ProbeAdmissionError:
        raise
    except Exception:
        _fail("espprobe_protocol")
