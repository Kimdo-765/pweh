"""서버가 관찰한 NTAG21x 사실과 같은 케이스의 마스킹 inventory 결속."""
from __future__ import annotations

import hashlib
import math
import os
import re
import time
import uuid
from dataclasses import dataclass, field

from . import safeio
from .errors import PwehError
from .nfc_formats import _NfcFileIdentity
from .provenance import KIND_DEVICE_FACT, SCHEMA as LEDGER_SCHEMA
from .safety.attestations import canonical_json

PROFILE = "flipper-ntag21x-admission-v1"
POLICY_PROFILE = "ntag21x-only-v1"
FIRMWARE_COMMIT = "9e810dc399e027e48ce07751df72168abbb19065"
MAX_LEDGER_BYTES = 16 << 20
MAX_LEDGER_ENTRIES = 10000
SCAN_FACT = "nfc-ntag21x-scan-v1"
INVENTORY_FACT = "nfc-inventory-v1"
VERSION_FAMILIES = {bytes.fromhex("0004040201000f03"): "ntag213",
                    bytes.fromhex("0004040201001103"): "ntag215",
                    bytes.fromhex("0004040201001303"): "ntag216"}
PROFILE_SHA256 = hashlib.sha256(canonical_json({
    "profile": PROFILE, "commit": FIRMWARE_COMMIT, "probe": "ISO14443-3A",
    "raw_command": "raw -p 14a -s -c -d 60 -t 60000", "probe_bytes": 4096,
    "uid_length": 7, "sak": 0, "families": list(VERSION_FAMILIES.values()),
    "page_read_performed": False, "scratch_cleanup_required": True,
}).encode()).hexdigest()
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_SCAN = re.compile(r"NS-[0-9a-f]{32}\Z")
_TAG = re.compile(r"NT-[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{16}\Z")
_SCAN_KEYS = frozenset(("scan_ref", "session_id", "reader_binding", "profile", "firmware_commit",
                       "firmware_claim_verified", "identity", "probe_sha256", "probe_size",
                       "probe_identity_match", "version_crc_valid", "family", "steps_complete",
                       "reselection_atomic", "page_read_performed", "scratch_cleanup_confirmed"))
_INV_KEYS = frozenset(("tag_ref", "scan_ref", "scan_seq", "scan_entry_sha256", "identity_digest",
                      "family", "policy_profile"))
_ENTRY_KEYS = frozenset(("schema", "seq", "ts", "case_id", "kind", "fact_kind", "path", "sha256",
                        "size", "source", "attestation_id", "data", "prev"))


def error(code="nfc_failed"):
    return PwehError("NFC inventory 결속을 완료하지 못했습니다.", code=code)


def _valid_text(value, maximum=4096):
    return type(value) is str and 0 < len(value) <= maximum and not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)


def _matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def _uint(value, maximum=MAX_LEDGER_ENTRIES):
    return type(value) is int and 0 < value <= maximum


def _control(deadline, cancel):
    try:
        valid = type(deadline) in (int, float) and math.isfinite(deadline)
    except OverflowError:
        valid = False
    if not valid or cancel is not None and not callable(cancel):
        raise error("nfc_input_invalid")
    def check():
        failed = False
        answer = False
        if cancel is not None:
            try:
                answer = cancel()
                failed = type(answer) is not bool
            except Exception:
                failed = True
        if failed:
            raise error()
        if answer:
            raise error("cancelled")
        if time.monotonic() >= deadline:
            raise error("time_limit")
    check()
    return check


def _fixed(exc):
    code = getattr(exc, "code", "")
    if code in ("cancelled", "time_limit", "authorization_required"):
        return error(code)
    if code in ("nfc_input_invalid", "nfc_scan_required", "nfc_scan_invalid", "nfc_family_unsupported",
                "nfc_identity_mismatch", "nfc_provenance_invalid"):
        return error(code)
    if code == "provenance_bounded_limit":
        return error("nfc_input_limit")
    return error("nfc_provenance_invalid")


def _bounds(deadline, check):
    return dict(max_bytes=MAX_LEDGER_BYTES, max_entries=MAX_LEDGER_ENTRIES, deadline=deadline, check=check)


def _entry_hash(entry):
    return hashlib.sha256(canonical_json(entry).encode("utf-8")).hexdigest()


def _identity(value, *, scan=False):
    if (type(value) is not _NfcFileIdentity or type(value.uid) is not bytes or len(value.uid) != 7
            or type(value.atqa_msb) is not bytes or len(value.atqa_msb) != 2
            or type(value.sak) is not bytes or value.sak != b"\0"
            or type(value.profile) is not str or value.profile not in ("iso14443-3a", "ntag213", "ntag215", "ntag216")):
        raise error("nfc_identity_mismatch")
    if scan or value.profile != "iso14443-3a":
        if type(value.mifare_version) is not bytes or value.mifare_version not in VERSION_FAMILIES:
            raise error("nfc_family_unsupported")
        family = VERSION_FAMILIES[value.mifare_version]
        if value.profile != "iso14443-3a" and value.profile != family:
            raise error("nfc_identity_mismatch")
        return family
    if value.mifare_version is not None:
        raise error("nfc_identity_mismatch")
    return None


def _identity_data(value):
    return {"uid": value.uid.hex(), "atqa_msb": value.atqa_msb.hex(), "sak": value.sak.hex(),
            "mifare_version": value.mifare_version.hex(), "profile": value.profile}


def _decode_identity(value):
    if type(value) is not dict or set(value) != {"uid", "atqa_msb", "sak", "mifare_version", "profile"}:
        raise error("nfc_scan_invalid")
    parts = []
    for name, width in (("uid", 14), ("atqa_msb", 4), ("sak", 2), ("mifare_version", 16)):
        raw = value[name]
        if type(raw) is not str or len(raw) != width or any(c not in "0123456789abcdef" for c in raw):
            raise error("nfc_scan_invalid")
        parts.append(bytes.fromhex(raw))
    identity = _NfcFileIdentity(*parts, value["profile"])
    _identity(identity, scan=True)
    return identity


def _reader_binding(binding):
    if type(binding) is not dict or set(binding) != {"backend", "lock_key", "device_id", "scope_keys"}:
        raise error("nfc_scan_invalid")
    if (binding["backend"] not in ("posix-tty", "win-helper")
            or not _valid_text(binding["lock_key"]) or not _valid_text(binding["device_id"])
            or type(binding["scope_keys"]) is not list or not 1 <= len(binding["scope_keys"]) <= 64
            or any(not _valid_text(v) for v in binding["scope_keys"])
            or len(set(binding["scope_keys"])) != len(binding["scope_keys"])
            or binding["lock_key"] not in binding["scope_keys"]):
        raise error("nfc_scan_invalid")
    return {**binding, "scope_keys": list(binding["scope_keys"])}


@dataclass(frozen=True, repr=False)
class ScanObservation:
    """성공한 고정 probe worker만 전달하는 private 관찰이다."""
    session_id: str
    reader_binding: dict
    identity: _NfcFileIdentity
    probe_sha256: str
    probe_size: int
    probe_identity_match: bool
    version_crc_valid: bool
    scratch_cleanup_confirmed: bool


@dataclass(frozen=True, repr=False)
class ScanRef:
    scan_ref: str
    family: str
    identity_digest: str
    scan_seq: int
    scan_entry_sha256: str
    warnings: tuple[str, ...] = ()

    def to_dict(self):
        return {"ok": True, "schema": "pweh.nfc-scan/v1", "scan_ref": self.scan_ref,
                "family": self.family, "identity_digest": self.identity_digest, "uid_length": 7,
                "profile": PROFILE, "inventory_eligible": True, "probe_identity_match": True,
                "version_crc_valid": True, "page_read_performed": False, "reselection_atomic": False,
                "physical_same_tag_verified": False, "device_command_termination_verified": False,
                "scratch_cleanup_confirmed": True, "warnings": list(self.warnings)}


@dataclass(frozen=True, repr=False)
class BoundTag:
    tag_ref: str
    scan_ref: str
    family: str
    identity_digest: str
    scan_seq: int
    scan_entry_sha256: str
    inventory_seq: int
    inventory_entry_sha256: str
    identity: _NfcFileIdentity = field(repr=False)
    warnings: tuple[str, ...] = ()

    def to_dict(self):
        return {"ok": True, "schema": "pweh.nfc-inventory/v1", "tag_ref": self.tag_ref,
                "scan_ref": self.scan_ref, "family": self.family, "identity_digest": self.identity_digest,
                "source": {"scan_seq": self.scan_seq, "scan_entry_sha256": self.scan_entry_sha256,
                           "inventory_seq": self.inventory_seq, "inventory_entry_sha256": self.inventory_entry_sha256},
                "inventory_binding_verified": True, "physical_same_tag_verified": False,
                "warnings": list(self.warnings)}


InventoryRef = BoundTag


def _digest(runtime, case, identity):
    # UID7/ATQA2/SAK1/version8의 고정길이 직렬화이며 개별 unsalted digest는 내보내지 않는다.
    digest = runtime.secret_digest(case.id, identity.uid + identity.atqa_msb + identity.sak + identity.mifare_version)
    if not _matches(_DIGEST, digest):
        raise error("nfc_scan_invalid")
    return digest


def _fact(entry, case_id, fact_kind, source):
    if (type(entry) is not dict or set(entry) != _ENTRY_KEYS or entry.get("schema") != LEDGER_SCHEMA
            or entry.get("case_id") != case_id or entry.get("kind") != KIND_DEVICE_FACT
            or entry.get("fact_kind") != fact_kind or entry.get("source") != source
            or entry.get("path") is not None or entry.get("size") is not None or entry.get("attestation_id") is not None
            or not _uint(entry.get("seq")) or not _valid_text(entry.get("ts"), 64)
            or not _matches(_SHA, entry.get("prev")) or not _matches(_SHA, entry.get("sha256"))
            or type(entry.get("data")) is not dict or _entry_hash(entry["data"]) != entry["sha256"]):
        raise error("nfc_scan_invalid")


def _scan(entry, case_id):
    _fact(entry, case_id, SCAN_FACT, {"server": "flipper-mcp", "tool": "flipper_nfc_probe"})
    d = entry["data"]
    if (set(d) != _SCAN_KEYS or not _matches(_SCAN, d["scan_ref"]) or not _valid_text(d["session_id"], 128)
            or d["profile"] != PROFILE or d["firmware_commit"] != FIRMWARE_COMMIT
            or not _matches(_SHA, d["probe_sha256"]) or not _uint(d["probe_size"], 4096)):
        raise error("nfc_scan_invalid")
    for key in ("firmware_claim_verified", "reselection_atomic", "page_read_performed"):
        if d[key] is not False:
            raise error("nfc_scan_invalid")
    for key in ("probe_identity_match", "version_crc_valid", "steps_complete", "scratch_cleanup_confirmed"):
        if d[key] is not True:
            raise error("nfc_scan_invalid")
    _reader_binding(d["reader_binding"])
    identity = _decode_identity(d["identity"])
    if d["family"] != _identity(identity, scan=True):
        raise error("nfc_scan_invalid")
    return identity


def _inventory(entry, case_id):
    _fact(entry, case_id, INVENTORY_FACT, {"server": "nfc-mcp", "tool": "nfc_tag_inventory_add"})
    d = entry["data"]
    if (set(d) != _INV_KEYS or not _matches(_TAG, d["tag_ref"]) or not _matches(_SCAN, d["scan_ref"])
            or not _uint(d["scan_seq"]) or not _matches(_SHA, d["scan_entry_sha256"])
            or not _matches(_DIGEST, d["identity_digest"]) or d["family"] not in VERSION_FAMILIES.values()
            or d["policy_profile"] != POLICY_PROFILE or d["scan_seq"] >= entry["seq"]):
        raise error("nfc_scan_invalid")


def _index(entries, case, check=lambda: None):
    """같은 ref를 다른 kind/source로 숨겨 유일하게 보이게 만들지 않는다."""
    scans, inventories = {}, {}
    seen_scans, seen_tags = set(), set()
    for entry in entries:
        check()
        d = entry.get("data")
        if type(d) is not dict:
            if entry.get("fact_kind") in (SCAN_FACT, INVENTORY_FACT):
                raise error("nfc_scan_invalid")
            continue
        scan_ref, tag_ref = d.get("scan_ref"), d.get("tag_ref")
        # inventory의 scan_ref는 참조다. 다른 모든 행에서의 선언은 오염으로 본다.
        if entry.get("fact_kind") == INVENTORY_FACT:
            _inventory(entry, case.id)
            if tag_ref in seen_tags:
                raise error("nfc_scan_invalid")
            seen_tags.add(tag_ref)
            inventories[tag_ref] = entry
        elif scan_ref is not None:
            if not _matches(_SCAN, scan_ref) or scan_ref in seen_scans:
                raise error("nfc_scan_invalid")
            seen_scans.add(scan_ref)
            _scan(entry, case.id)
            scans[scan_ref] = entry
        elif entry.get("fact_kind") == SCAN_FACT:
            raise error("nfc_scan_invalid")
        if tag_ref is not None and entry.get("fact_kind") != INVENTORY_FACT:
            raise error("nfc_scan_invalid")
    linked = set()
    for inv in inventories.values():
        check()
        d = inv["data"]
        scan = scans.get(d["scan_ref"])
        if (scan is None or d["scan_seq"] != scan["seq"] or d["scan_entry_sha256"] != _entry_hash(scan)
                or d["family"] != scan["data"]["family"] or d["scan_ref"] in linked):
            raise error("nfc_scan_invalid")
        linked.add(d["scan_ref"])
    return scans, inventories


def _bound(runtime, case, scan, inv):
    identity = _scan(scan, case.id)
    d = inv["data"]
    if _digest(runtime, case, identity) != d["identity_digest"]:
        raise error("nfc_scan_invalid")
    return BoundTag(d["tag_ref"], d["scan_ref"], d["family"], d["identity_digest"], scan["seq"],
                    _entry_hash(scan), inv["seq"], _entry_hash(inv), identity)


def record_flipper_scan(runtime, case, observation: ScanObservation, *, deadline, cancel=None) -> ScanRef:
    """고정 worker의 완전한 관찰만 원장 사실로 기록한다. 원시 identity는 보호 원장에만 남는다."""
    try:
        case.require_authorization()
        check = _control(deadline, cancel)
        if type(observation) is not ScanObservation:
            raise error("nfc_scan_invalid")
        o = observation
        family = _identity(o.identity, scan=True)
        if (not _valid_text(o.session_id, 128) or not _matches(_SHA, o.probe_sha256)
                or not _uint(o.probe_size, 4096) or o.probe_identity_match is not True
                or o.version_crc_valid is not True or o.scratch_cleanup_confirmed is not True):
            raise error("nfc_scan_invalid")
        binding = _reader_binding(o.reader_binding)
        ref = "NS-" + uuid.uuid4().hex
        digest = _digest(runtime, case, o.identity)
        d = {"scan_ref": ref, "session_id": o.session_id, "reader_binding": binding,
             "profile": PROFILE, "firmware_commit": FIRMWARE_COMMIT, "firmware_claim_verified": False,
             "identity": _identity_data(o.identity), "probe_sha256": o.probe_sha256, "probe_size": o.probe_size,
             "probe_identity_match": True, "version_crc_valid": True, "family": family, "steps_complete": True,
             "reselection_atomic": False, "page_read_performed": False, "scratch_cleanup_confirmed": True}
        def final(entries):
            check()
            scans, _ = _index(entries, case, check)
            if ref in scans:
                raise error("nfc_scan_invalid")
        entry = runtime.provenance.record_device_fact(case, SCAN_FACT, d,
                {"server": "flipper-mcp", "tool": "flipper_nfc_probe"}, check_entries=final, **_bounds(deadline, check))
        return ScanRef(ref, family, digest, entry["seq"], _entry_hash(entry), getattr(entry, "warnings", ()))
    except Exception as exc:
        failure = _fixed(exc)
    raise failure from None


class _ExistingInventory(Exception):
    def __init__(self, bound):
        self.bound = bound
        super().__init__("existing_inventory")


def _write_cache(case, rows, total, check):
    """권위가 아닌 최근32행 사본. 기존 cache를 읽어 신뢰하지 않는다."""
    payload = (canonical_json({"schema": "pweh.nfc-inventory-cache/v1", "total_inventory_count": total,
                              "truncated": total > len(rows), "entries": rows}) + "\n").encode()
    if len(payload) > 65536:
        raise error("nfc_input_limit")
    fd = safeio.open_dir_chain(case.dir, ("nfc",))
    try:
        before = os.fstat(fd)
        check()
        if not safeio.same_file(before, os.stat(case.dir / "nfc", follow_symlinks=False)):
            raise error()
        safeio.atomic_write_at(fd, "inventory.json", payload, mode=0o444)
    finally:
        os.close(fd)


def add_inventory(runtime, case, scan_ref, *, deadline, cancel=None) -> InventoryRef:
    """명시 scan을 같은 원장 잠금 안에서 결속하고 중복 추가는 기존 참조를 돌려준다."""
    try:
        case.require_authorization()
        check = _control(deadline, cancel)
        if not _matches(_SCAN, scan_ref):
            raise error("nfc_input_invalid")
        entries = runtime.provenance.entries(case, **_bounds(deadline, check))
        scans, _ = _index(entries, case, check)
        scan = scans.get(scan_ref)
        if scan is None:
            raise error("nfc_scan_required")
        identity = _scan(scan, case.id)
        scan_hash = _entry_hash(scan)
        tag = "NT-" + uuid.uuid4().hex
        d = {"tag_ref": tag, "scan_ref": scan_ref, "scan_seq": scan["seq"], "scan_entry_sha256": scan_hash,
             "identity_digest": _digest(runtime, case, identity), "family": scan["data"]["family"],
             "policy_profile": POLICY_PROFILE}
        cache_entries = []
        def final(current):
            check()
            fresh_scans, fresh_inv = _index(current, case, check)
            found = fresh_scans.get(scan_ref)
            if found is None or _entry_hash(found) != scan_hash:
                raise error("nfc_scan_invalid")
            cache_entries[:] = current
            for inv in fresh_inv.values():
                if inv["data"]["scan_ref"] == scan_ref:
                    raise _ExistingInventory(_bound(runtime, case, found, inv))
                if inv["data"]["tag_ref"] == tag:
                    raise error("nfc_scan_invalid")
        try:
            entry = runtime.provenance.record_device_fact(case, INVENTORY_FACT, d,
                     {"server": "nfc-mcp", "tool": "nfc_tag_inventory_add"}, check_entries=final, **_bounds(deadline, check))
            bound = BoundTag(tag, scan_ref, d["family"], d["identity_digest"], scan["seq"],
                             scan_hash, entry["seq"], _entry_hash(entry), identity, getattr(entry, "warnings", ()))
            cache_entries.append(dict(entry))
        except _ExistingInventory as reuse:
            bound = reuse.bound
    except Exception as exc:
        failure = _fixed(exc)
    else:
        # 원장 commit 뒤 cache/취소 실패는 권위 사실을 되돌리지 않는다.
        warnings = bound.warnings
        try:
            scans, invs = _index(cache_entries, case, check)
            recent = sorted(invs.values(), key=lambda e: e["seq"], reverse=True)[:32]
            rows = [_bound(runtime, case, scans[e["data"]["scan_ref"]], e).to_dict() for e in recent]
            _write_cache(case, rows, len(invs), check)
        except Exception:
            warnings += ("inventory_cache_write_failed",)
        if warnings:
            from dataclasses import replace
            bound = replace(bound, warnings=warnings)
        return bound
    raise failure from None


def resolve_inventory(runtime, case, tag_ref, *, deadline, cancel=None) -> BoundTag:
    """cache에 접근하지 않고 검증된 원장의 명시 tag/scan 결속만 반환한다."""
    try:
        case.require_authorization()
        check = _control(deadline, cancel)
        if not _matches(_TAG, tag_ref):
            raise error("nfc_input_invalid")
        entries = runtime.provenance.entries(case, **_bounds(deadline, check))
        scans, invs = _index(entries, case, check)
        inv = invs.get(tag_ref)
        if inv is None:
            raise error("nfc_scan_required")
        bound = _bound(runtime, case, scans[inv["data"]["scan_ref"]], inv)
        check()
        return bound
    except Exception as exc:
        failure = _fixed(exc)
    raise failure from None


def match_file_identity(bound: BoundTag, identity: _NfcFileIdentity) -> None:
    """스캔의 exact identity와 파일 선언을 대조한다. 물리 동일 태그 증명은 아니다."""
    if type(bound) is not BoundTag:
        raise error("nfc_identity_mismatch")
    _identity(identity)
    expected = bound.identity
    if (identity.uid != expected.uid or identity.atqa_msb != expected.atqa_msb or identity.sak != expected.sak
            or identity.profile != "iso14443-3a" and
            (identity.profile != bound.family or identity.mifare_version != expected.mifare_version)):
        raise error("nfc_identity_mismatch")
