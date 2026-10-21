"""유효한 전역 고정 계측기를 대상 도구에서 거부한다. 승인·역할 태그는 허용 우회가 아니다.

pin이 없으면 PnP·표지 저장소를 전혀 건드리지 않는다. 실제 식별은 portidentity의 읽기 전용 seam뿐이다.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import PwehError, ValidationFailed
from .portidentity import PortIdentity, mac_text, probe_identity, unknown
from .procutil import boot_id

GUARD_CODES = frozenset({"instrument_port", "instrument_identity_unknown"})
PIN_SCHEMA = "pweh.instrument-pin/v1"
PIN_QUESTIONS = [
    {"id": "instrument_not_target", "text": "이 보드는 내 계측기이며 분석 대상이 아니다", "type": "yesno", "expected": "yes"},
    {"id": "pweh_release_flashed", "text": "검증한 PWEH 계측기 릴리스가 이 보드에 쓰여 있다", "type": "yesno", "expected": "yes"},
    {"id": "aux_unplugged", "text": "분석 대상과 계측기의 보조 USB-UART 연결을 구분하고 불필요한 연결을 뺐다", "type": "yesno", "expected": "yes"},
]


@dataclass(frozen=True)
class PinInventory:
    state: str
    pins: tuple[dict[str, Any], ...] = ()
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class GuardDecision:
    action: str
    code: str | None = None
    role: str | None = None
    matched_by: str | None = None
    pin_ids: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()


def _usb_records(subject: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    native = subject.get("native_usb")
    if not isinstance(native, dict):
        raise ValueError("native_identity_missing")
    result = [("instrument", native)]
    for key, role in (("boot_usb", "pinned-instrument-boot-or-rom"), ("aux_usb", "instrument-aux")):
        items = subject.get(key, [])
        if not isinstance(items, list) or len(items) > 16 or any(not isinstance(i, dict) for i in items):
            raise ValueError("usb_identity_list_invalid")
        result.extend((role, i) for i in items)
    for _, item in result:
        for key in ("vid", "pid", "serial", "parent_instance", "device_instance"):
            value = item.get(key)
            if value is not None and (not isinstance(value, str) or not value or len(value) > 4096):
                raise ValueError("usb_identity_invalid")
        for key in ("vid", "pid"):
            value = item.get(key)
            if value is not None and not re.fullmatch(r"[0-9a-fA-F]{4}", value):
                raise ValueError("usb_id_format_unknown")
        loc = item.get("location_paths", [])
        if not isinstance(loc, list) or len(loc) > 16 or any(not isinstance(i, str) or not i or len(i) > 4096 for i in loc):
            raise ValueError("usb_locations_invalid")
    return result


def load_pins(store: Any) -> PinInventory:
    """권위 저장소의 유효 global pin만 사용한다. 형식이 낡은 유효 pin은 unknown으로 보호한다."""
    try:
        # 기존 store.list/require가 JSON 전체를 읽으므로 먼저 저장소 크기를 제한한다(쓰기 없음).
        directory = Path(store.dir)
        try:
            dst = directory.lstat()
        except FileNotFoundError:
            return PinInventory("empty")
        if not stat.S_ISDIR(dst.st_mode):
            raise ValueError("attestation_directory_invalid")
        total = 0
        count = 0
        with os.scandir(directory) as entries:
            for entry in entries:
                if not entry.name.startswith("att-") or not entry.name.endswith(".json"):
                    continue
                count += 1
                st = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(st.st_mode) or st.st_size > 64 * 1024 or count > 2048:
                    raise ValueError("attestation_limit")
                total += st.st_size
                if total > 8 * 1024 * 1024:
                    raise ValueError("attestation_limit")
        rows = store.list()
        if len(rows) != count:
            raise ValueError("attestation_unreadable")
        pins: dict[str, dict[str, Any]] = {}
        for rec in rows:
            if rec.get("kind") != "instrument-pin" or (rec.get("binding") or {}).get("scope") != "instrument":
                continue
            trusted = store.require("instrument-pin", rec.get("subject"), rec.get("binding"))
            if trusted is None:
                continue
            subject = trusted["subject"]
            mac = mac_text(subject.get("base_mac"))
            if subject.get("schema") != PIN_SCHEMA or not mac or mac_text(trusted["binding"].get("instrument_id")) != mac:
                raise ValueError("pin_identity_schema_unknown")
            _usb_records(subject)
            pins[trusted["id"]] = trusted
            if len(pins) > 128:
                raise ValueError("pin_limit")
        return PinInventory("active" if pins else "empty", tuple(pins.values()))
    except (OSError, ValueError, TypeError, KeyError, PwehError) as exc:
        return PinInventory("unknown", reasons=(str(exc)[:100],))


def _eq(left: Any, right: Any, *, windows: bool = False) -> bool:
    if not isinstance(left, str) or not isinstance(right, str) or not left or not right:
        return False
    return left.casefold() == right.casefold() if windows else left == right


def classify_instrument(snapshot: PortIdentity, inventory: PinInventory, tags: tuple[dict, ...] = ()) -> GuardDecision:
    """순수 거부 판정. 부재·부모 미확인·forwarding 경로는 active pin이 있으면 거부한다."""
    if inventory.state == "empty":
        return GuardDecision("pass")
    if inventory.state != "active":
        return GuardDecision("deny", "instrument_identity_unknown", reasons=inventory.reasons)
    if snapshot.kind == "memory" and snapshot.status == "known":
        return GuardDecision("pass")
    uncertain_aux = False
    for rec in inventory.pins:
        subject = rec["subject"]
        if mac_text(snapshot.serial) and mac_text(snapshot.serial) == mac_text(subject["base_mac"]):
            role = "pinned-instrument-boot-or-rom" if snapshot.vid == "303a" and snapshot.pid in ("1001", "0009") else "instrument"
            return GuardDecision("deny", "instrument_port", role, "base-mac", (rec["id"],))
        for role, ident in _usb_records(subject):
            matched = None
            vidpid = _eq(snapshot.vid, ident.get("vid"), windows=True) and _eq(snapshot.pid, ident.get("pid"), windows=True)
            if _eq(snapshot.serial, ident.get("serial"), windows=snapshot.backend == "windows") and (role != "instrument-aux" or vidpid):
                matched = "usb-serial"
            if _eq(snapshot.parent_instance, ident.get("parent_instance"), windows=snapshot.backend == "windows"):
                matched = "usb-parent"
            if any(_eq(current, pinned, windows=snapshot.backend == "windows")
                   for current in snapshot.location_paths for pinned in ident.get("location_paths", [])):
                matched = "usb-location"
            if matched:
                return GuardDecision("deny", "instrument_port", role, matched, (rec["id"],))
            if role == "instrument-aux" and vidpid and (not snapshot.serial or not ident.get("serial")):
                uncertain_aux = True
    active = {(p["id"], p["fingerprint"]) for p in inventory.pins}
    for tag in tags:
        if (tag.get("attestation_id"), tag.get("fingerprint")) not in active:
            continue
        ident = tag.get("identity", {})
        if tag.get("endpoint") == snapshot.endpoint_key and snapshot.status != "known":
            return GuardDecision("deny", "instrument_port", tag.get("role"), "runtime-tag", (tag["attestation_id"],))
        if snapshot.parent_instance and _eq(snapshot.parent_instance, ident.get("parent_instance"), windows=snapshot.backend == "windows"):
            return GuardDecision("deny", "instrument_port", tag.get("role"), "runtime-tag-parent", (tag["attestation_id"],))
    if snapshot.status != "known" or not snapshot.present or uncertain_aux or not snapshot.serial:
        return GuardDecision("deny", "instrument_identity_unknown", reasons=snapshot.reasons or ("identity_incomplete",))
    return GuardDecision("pass")


def _raise(decision: GuardDecision, consumer: str, phase: str) -> None:
    raise PwehError("고정 계측기의 대상 도구 접근을 거부했습니다." if decision.code == "instrument_port" else
                    "고정 계측기와 대상 포트를 구분할 수 없어 접근을 거부했습니다.",
                    code=decision.code, hint="포트와 계측기 고정을 확인하세요. 승인으로 이 거부를 해제할 수 없습니다.",
                    data={"consumer": consumer, "phase": phase, "role": decision.role, "matched_by": decision.matched_by,
                          "pin_ids": list(decision.pin_ids), "reasons": list(decision.reasons)})


def guard_target_port(runtime: Any, endpoint: str | None, *, consumer: str, phase: str = "preflight",
                      driver: str | None = None) -> PortIdentity | None:
    """운영 서버 접점. pin0은 PnP/provider/tag 접근 이전에 반환한다."""
    inventory = load_pins(runtime.attestations)
    if inventory.state == "empty":
        return None
    if inventory.state == "unknown":
        _raise(GuardDecision("deny", "instrument_identity_unknown", reasons=inventory.reasons), consumer, phase)
    if consumer == "sigrok" and driver == "demo" and endpoint is None:
        return PortIdentity("sigrok:demo", "known", "memory", True)
    snapshot = probe_identity(endpoint, config=runtime.config)
    try:
        tags = InstrumentTagStore().read()
    except (OSError, ValueError, TypeError) as exc:
        _raise(GuardDecision("deny", "instrument_identity_unknown", reasons=("instrument_tags_unreadable",)), consumer, phase)
    decision = classify_instrument(snapshot, inventory, tags)
    if decision.action != "pass":
        _raise(decision, consumer, phase)
    return snapshot


def guard_observed_mac(runtime: Any, value: Any, *, consumer: str) -> None:
    """이미 얻은 MAC의 보조 확인. 장치 접촉 전 PnP guard를 대신하지 않는다."""
    inventory = load_pins(runtime.attestations)
    if inventory.state == "unknown":
        _raise(GuardDecision("deny", "instrument_identity_unknown", reasons=inventory.reasons), consumer, "observed-mac")
    mac = mac_text(value)
    for rec in inventory.pins:
        if mac and mac == mac_text(rec["subject"]["base_mac"]):
            _raise(GuardDecision("deny", "instrument_port", "instrument", "observed-mac", (rec["id"],)), consumer, "observed-mac")


class InstrumentTagStore:
    """uid별 runtime 거부 표지. 환경 변수·사용자 입력 경로는 운영에서 받지 않는다."""
    def __init__(self, root: Path | None = None) -> None:
        self.root = root if root is not None else Path(f"/tmp/pweh-{os.getuid()}")

    def _directory(self, create: bool = False) -> int | None:
        if create:
            self.root.mkdir(mode=0o700, exist_ok=True)
        try:
            rootfd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        try:
            self._check(os.fstat(rootfd), directory=True)
            if create:
                try:
                    os.mkdir("tags", mode=0o700, dir_fd=rootfd)
                except FileExistsError:
                    pass
            try:
                fd = os.open("tags", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rootfd)
            except FileNotFoundError:
                return None
            try:
                self._check(os.fstat(fd), directory=True)
            except BaseException:
                os.close(fd)
                raise
            return fd
        finally:
            os.close(rootfd)

    @staticmethod
    def _check(st: os.stat_result, *, directory: bool = False) -> None:
        if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != (0o700 if directory else 0o600):
            raise ValueError("tag_permissions")
        if not (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)):
            raise ValueError("tag_file_type")
        if not directory and (st.st_size > 16384 or st.st_nlink != 1):
            raise ValueError("tag_size_or_link")

    def read(self) -> tuple[dict, ...]:
        fd = self._directory()
        if fd is None:
            return ()
        try:
            names = os.listdir(fd)
            if len(names) > 1024:
                raise ValueError("tag_count_limit")
            out = []
            for name in names:
                if not name.endswith(".json"):
                    continue
                f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                try:
                    self._check(os.fstat(f))
                    raw = os.read(f, 16385)
                    if len(raw) > 16384:
                        raise ValueError("tag_size_limit")
                    rec = json.loads(raw)
                    if (not isinstance(rec, dict) or rec.get("schema") != "pweh.instrument-tag/v1"
                            or rec.get("role") not in ("instrument", "instrument-aux") or not isinstance(rec.get("identity"), dict)
                            or any(not isinstance(rec.get(k), str) or not rec[k] for k in ("attestation_id", "fingerprint", "endpoint"))):
                        raise ValueError("tag_schema")
                    out.append(rec)
                finally:
                    os.close(f)
            return tuple(out)
        finally:
            os.close(fd)

    def put_from_pin(self, identity: PortIdentity, pin: dict, *, attestations: Any, role: str) -> dict:
        """현재 identity가 권위 pin에 맞을 때만 표지 생성. instrument-aux도 허용 근거가 아니다."""
        trusted = attestations.require("instrument-pin", pin.get("subject"), pin.get("binding"))
        inventory = load_pins(attestations)
        if trusted is None or inventory.state != "active" or trusted["id"] not in {p["id"] for p in inventory.pins}:
            raise ValidationFailed("유효한 전역 계측기 고정이 필요합니다.")
        decision = classify_instrument(identity, PinInventory("active", (trusted,)))
        if decision.code != "instrument_port" or role not in ("instrument", "instrument-aux") or (role == "instrument-aux") != (decision.role == "instrument-aux"):
            raise ValidationFailed("표지 역할과 관찰된 계측기 식별이 맞지 않습니다.")
        rec = {"schema": "pweh.instrument-tag/v1", "attestation_id": trusted["id"], "fingerprint": trusted["fingerprint"],
               "role": role, "endpoint": identity.endpoint_key, "identity": identity.to_dict(), "boot_id": boot_id()}
        raw = json.dumps(rec, ensure_ascii=False, separators=(",", ":")).encode()
        if len(raw) > 16384:
            raise ValidationFailed("표지 크기 상한 초과")
        fd = self._directory(create=True)
        assert fd is not None
        name = hashlib.sha256(identity.endpoint_key.encode()).hexdigest() + ".json"
        tmp = ".tag-" + secrets.token_hex(8)
        try:
            names = os.listdir(fd)
            if len(names) >= 1024 and name not in names:
                raise ValidationFailed("계측기 표지 수 상한 초과")
            f = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                os.fchmod(f, 0o600)
                with os.fdopen(f, "wb", closefd=False) as out:
                    out.write(raw)
                    out.flush()
                    os.fsync(f)
            finally:
                os.close(f)
            os.replace(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
        finally:
            try:
                os.unlink(tmp, dir_fd=fd)
            except FileNotFoundError:
                pass
            os.close(fd)
        return rec

    def remove_if_stale(self, identity: PortIdentity, *, attestations: Any) -> bool:
        """철회되었거나 현재 장치가 확실히 다른 때만 그 endpoint 표지를 지운다."""
        inventory = load_pins(attestations)
        if inventory.state == "unknown":
            return False
        active = {(p["id"], p["fingerprint"]) for p in inventory.pins}
        remove = False
        for rec in self.read():
            if rec.get("endpoint") != identity.endpoint_key:
                continue
            revoked = (rec.get("attestation_id"), rec.get("fingerprint")) not in active
            distinct = (identity.status == "known" and bool(identity.serial) and identity.serial != rec["identity"].get("serial")
                        and classify_instrument(identity, inventory).action == "pass")
            remove = revoked or distinct
        if not remove:
            return False
        fd = self._directory()
        if fd is None:
            return False
        try:
            name = hashlib.sha256(identity.endpoint_key.encode()).hexdigest() + ".json"
            os.unlink(name, dir_fd=fd)
            return True
        except FileNotFoundError:
            return False
        finally:
            os.close(fd)
