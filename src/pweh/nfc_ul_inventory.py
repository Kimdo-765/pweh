"""서버가 관찰한 Ultralight 계열 scan 사실과 사람 소유 증명(tag-ownership)에 결속한 UL inventory.

NTAG inventory(``nfc_inventory``)와 겹치지 않는 별도 원장 namespace를 쓴다.
  - fact kind ``nfc-ultralight-cu-scan-v1``·``nfc-ultralight-inventory-v1``, data 키 ``ul_scan_ref``(``US-``)·``ul_tag_ref``(``UT-``).
  - UL 행은 ``scan_ref``·``tag_ref`` 키를 갖지 않으므로 NTAG ``_index``는 UL 행을 그대로 건너뛴다(NTAG 기호는 그대로).
  - UL 키를 가진 다른 kind 행, UL kind인데 형식이 다른 행은 UL 색인 전체를 오염으로 본다(NTAG 규칙과 같다).

사람 증명:
  - kind ``tag-ownership``, 질문은 ``owned_tag`` 하나다. 문구는 recipe의 질문 hash로 고정한다.
    저장소는 질문을 id·type·expected로만 대조하므로 UL 확인 지점(``ul_attest``·``ul_require``)이 기록의 질문 문구까지
    현재 고정 문구와 같은지 따로 확인한다. 문구를 바꾸면 기존 기록은 충족하지 않는다(뜻을 바꾸면 새 id도 쓴다).
  - subject는 ``{tag_family, ul_identity_digest, policy_profile}``이고 바인딩은 케이스다(기본 7일).
    서버 자신의 scan 관찰·검증한 원장 행에서만 만들며 원시 UID를 넣지 않는다.
  - 요청은 언제나 ``ctx=None``이다. 호출 안에서 사람 응답을 기다리지 않고 곧바로 ``attestation_required``를 돌려주며,
    사람이 별도 터미널에서 ``pweh attest <id>``로 답한 뒤 에이전트가 다시 부른다. 검증은 저장소의 신뢰 규칙에 더해
    ``decided_via``가 recipe의 고정 목록(cli-tty·elicitation) 안에 있어야 한다(저장소에 새 경로가 생겨도 UL은 받지 않는다).
  - scan 기록·inventory 추가는 원장 잠금 안에서 같은 증명 id를 다시 확인한다(철회·만료되면 기록하지 않는다).

결과·예외·승인 action에는 원시 UID·version을 넣지 않는다. 원시 식별값은 보호 원장에만 남는다.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field

from . import cu_protocol as CU
from .case import CASE_ID_RE
from .errors import PwehError
from .nfc_inventory import (LEDGER_SCHEMA, MAX_LEDGER_ENTRIES, _ENTRY_KEYS, _bounds, _control, _entry_hash,
                            _matches, _reader_binding, _uint, _valid_text)
from .provenance import KIND_DEVICE_FACT
from .safety.attestations import ATTESTATION_KINDS, DECIDED_VIA, canonical_json, normalize_questions

UL_SCAN_FACT = "nfc-ultralight-cu-scan-v1"
UL_INVENTORY_FACT = "nfc-ultralight-inventory-v1"
UL_FACTS = frozenset((UL_SCAN_FACT, UL_INVENTORY_FACT))
SCAN_SOURCE = {"server": "nfc-mcp", "tool": "nfc_cu_ul_scan"}
INVENTORY_SOURCE = {"server": "nfc-mcp", "tool": "nfc_tag_inventory_add"}
OWNERSHIP_KIND = "tag-ownership"
POLICY_PROFILE = CU.UL_POLICY_PROFILE
#: tag-ownership 확인 항목. 요청하는 쪽과 확인하는 쪽이 같은 정의를 쓴다. 문구까지 기록과 대조하므로(``_same_questions``)
#: 바꾸면 기존 증명은 모두 충족하지 않는다. 바꿀 때는 recipe의 질문 hash도 다시 고정한다.
UL_OWNERSHIP_QUESTIONS = (
    {"id": "owned_tag", "type": "yesno", "expected": "yes",
     "text": "방금 CU 리더에 올려 스캔한 태그 한 장(위 대상의 계열·지문)은 내가 소유했거나 소유자의 서면 허가를 받은 것이다"},
)
_QUESTIONS_JSON = canonical_json(list(UL_OWNERSHIP_QUESTIONS))
QUESTIONS_SHA256 = hashlib.sha256(_QUESTIONS_JSON.encode("utf-8")).hexdigest()
if (QUESTIONS_SHA256 != CU.UL_OWNERSHIP["questions_sha256"]
        or tuple(q["id"] for q in UL_OWNERSHIP_QUESTIONS) != CU.UL_OWNERSHIP["question_ids"]
        or OWNERSHIP_KIND != CU.UL_OWNERSHIP["kind"] or OWNERSHIP_KIND not in ATTESTATION_KINDS
        or CU.UL_OWNERSHIP["binding_scope"] != "case"
        or not set(CU.UL_OWNERSHIP["decided_via"]) <= set(DECIDED_VIA)):
    raise RuntimeError("Ultralight 소유 증명 질문·종류가 고정 recipe와 다릅니다.")
#: UL 확인 지점이 받는 사람 결정 경로. 저장소 목록(``DECIDED_VIA``)이 늘어도 recipe의 고정 목록만 받는다.
UL_DECIDED_VIA = frozenset(CU.UL_OWNERSHIP["decided_via"])

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_UL_SCAN = re.compile(r"US-[0-9a-f]{32}\Z")
_UL_TAG = re.compile(r"UT-[0-9a-f]{32}\Z")
_ATT = re.compile(r"att-[0-9a-f]{10}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{16}\Z")
_HEX = frozenset("0123456789abcdef")
_UL_SCAN_KEYS = frozenset(("ul_scan_ref", "session_id", "reader_binding", "profile", "profile_sha256",
                           "firmware_commit", "firmware_claim_verified", "identity", "family", "policy_profile",
                           "page_read_performed", "read_requests", "version_requests", "steps_complete",
                           "host_crc_verified", "reselection_atomic"))
_UL_INV_KEYS = frozenset(("ul_tag_ref", "ul_scan_ref", "scan_seq", "scan_entry_sha256", "ul_identity_digest",
                          "family", "policy_profile"))
_IDENTITY_KEYS = frozenset(("uid", "atqa_msb", "sak", "mifare_version"))
_PASS_CODES = frozenset(("cancelled", "time_limit", "authorization_required", "nfc_input_invalid",
                         "nfc_scan_required", "nfc_scan_invalid", "nfc_family_unsupported", "nfc_identity_mismatch",
                         "nfc_provenance_invalid", "nfc_attestation_required"))


def error(code="nfc_failed"):
    return PwehError("NFC Ultralight inventory 결속을 완료하지 못했습니다.", code=code)


def _fixed(exc):
    code = getattr(exc, "code", "")
    if code in _PASS_CODES:
        return error(code)
    if code == "provenance_bounded_limit":
        return error("nfc_input_limit")
    return error("nfc_provenance_invalid")


def ul_questions() -> list:
    """고정 질문의 새 사본. 모듈 tuple의 dict가 바뀌어도 요청·확인은 import 때 고정한 문구를 쓴다."""
    return json.loads(_QUESTIONS_JSON)


def _same_questions(rec) -> bool:
    """기록이 물은 질문 전체(문구 포함)가 현재 고정 질문과 같은지. 저장소의 id·type·expected 대조를 보강한다."""
    try:
        return normalize_questions(rec.get("questions")) == normalize_questions(ul_questions())
    except Exception:
        return False


@dataclass(frozen=True, repr=False)
class UlIdentity:
    """Ultralight 계열 Type 2 후보의 내부 식별값. version은 EV1 정확8B, 원조 UL/UL C는 None이다."""
    uid: bytes
    atqa_msb: bytes
    sak: bytes
    version: bytes | None

    def __post_init__(self):
        if (type(self.uid) is not bytes or len(self.uid) != 7
                or type(self.atqa_msb) is not bytes or self.atqa_msb != b"\x00\x44"
                or type(self.sak) is not bytes or self.sak != b"\x00"
                or not (self.version is None or (type(self.version) is bytes and len(self.version) == 8))):
            raise error("nfc_scan_invalid")


def _check_family(identity, family):
    """계열과 identity의 version 관계: 원조 UL/UL C ⇔ version None, EV1 ⇔ 그 계열의 정확8B."""
    if type(identity) is not UlIdentity or type(family) is not str or family not in CU.UL_FAMILIES:
        raise error("nfc_scan_invalid")
    spec = CU.UL_SPECS[family]
    if (identity.version is None) != (spec.version is None) or (
            spec.version is not None and identity.version != spec.version):
        raise error("nfc_scan_invalid")
    return spec


def ul_identity_digest(runtime, case_id, identity, family) -> str:
    """Ultralight 전용 domain의 케이스 솔트 지문. NTAG inventory·HF 식별 지문과 입력 domain이 다르다."""
    _check_family(identity, family)
    raw = identity.version or b""
    value = (CU.UL_DIGEST_DOMAIN + b"\0" + family.encode("ascii") + b"\0" + b"\x07" + identity.uid
             + identity.atqa_msb + identity.sak + bytes((len(raw),)) + raw)
    digest = runtime.secret_digest(case_id, value)
    if not _matches(_DIGEST, digest):
        raise error("nfc_scan_invalid")
    return digest


def ul_ownership_target(case_id, family, ul_identity_digest):
    """요청하는 서버와 모든 확인 지점이 같은 지문을 계산하도록 (kind, subject, binding)을 한 곳에서 만든다."""
    if (type(case_id) is not str or CASE_ID_RE.fullmatch(case_id) is None or type(family) is not str
            or family not in CU.UL_FAMILIES or not _matches(_DIGEST, ul_identity_digest)):
        raise error("nfc_input_invalid")
    return (OWNERSHIP_KIND,
            {"tag_family": family, "ul_identity_digest": ul_identity_digest, "policy_profile": POLICY_PROFILE},
            {"scope": "case", "case_id": case_id})


def _summary(family):
    return f"Ultralight 계열 태그의 소유 확인(family={family}, 페이지 읽기 전)"


async def ul_attest(runtime, case_id, family, digest, *, tool):
    """증명을 찾거나 pending 요청을 만든다. ctx는 언제나 None이라 호출 안에서 사람 응답을 기다리지 않는다.

    충족이면 decision(satisfied)을, 아니면 그대로 ``attestation_response``에 넘길 decision을 돌려준다.
    """
    kind, subject, binding = ul_ownership_target(case_id, family, digest)
    decision = await runtime.attest(kind, subject, binding, ul_questions(), case_id, None, _summary(family),
                                    tool=tool)
    if decision.satisfied and (decision.kind != OWNERSHIP_KIND or not _matches(_ATT, decision.attestation_id)
                               or type(decision.record) is not dict or not _same_questions(decision.record)
                               or decision.record.get("decided_via") not in UL_DECIDED_VIA):
        raise error("nfc_attestation_required")
    return decision


def ul_require(runtime, case_id, family, digest, *, expected_id=None) -> str:
    """동기 재확인. 현재 신뢰하는 tag-ownership 기록이 없거나 기대한 id와 다르면 nfc_attestation_required다.

    저장소의 질문 대조(id·type·expected)에 더해 문구 전체와 recipe의 ``decided_via`` 목록을 확인한다.
    """
    kind, subject, binding = ul_ownership_target(case_id, family, digest)
    try:
        rec = runtime.attestations.require(kind, subject, binding, questions=ul_questions())
    except Exception:
        rec = None
    if (type(rec) is not dict or rec.get("kind") != OWNERSHIP_KIND or not _matches(_ATT, rec.get("id"))
            or rec.get("decided_via") not in UL_DECIDED_VIA or not _same_questions(rec)
            or (expected_id is not None and rec["id"] != expected_id)):
        raise error("nfc_attestation_required")
    return rec["id"]


@dataclass(frozen=True, repr=False)
class UlScanObservation:
    """CU worker가 READ 없이 완료한 HF 식별 관찰. 서버 타입이나 원시 frame은 보관하지 않는다."""
    session_id: str
    reader_binding: dict
    identity: UlIdentity
    family: str


@dataclass(frozen=True, repr=False)
class UlScanRef:
    scan_ref: str
    family: str
    ul_identity_digest: str
    scan_seq: int
    scan_entry_sha256: str
    attestation_id: str
    warnings: tuple = ()

    def to_dict(self):
        return {"ok": True, "schema": "pweh.nfc-ul-scan/v1", "scan_ref": self.scan_ref, "family": self.family,
                "ul_identity_digest": self.ul_identity_digest, "uid_length": 7, "profile": CU.UL_READ.profile,
                "policy": "attestation_required", "policy_profile": POLICY_PROFILE,
                "attestation": {"kind": OWNERSHIP_KIND, "attestation_id": self.attestation_id},
                "inventory_eligible": True, "page_read_performed": False, "read_requests": 0,
                "version_requests": 1, "authentication_attempted": False, "physical_same_tag_verified": False,
                "rf_off_verified": False, "warnings": list(self.warnings)}


@dataclass(frozen=True, repr=False)
class UlScanTarget:
    """inventory 추가 전 검증한 UL scan 행의 공개 결속 값(증명 대상 계산용)."""
    scan_ref: str
    family: str
    ul_identity_digest: str
    scan_seq: int
    scan_entry_sha256: str


@dataclass(frozen=True, repr=False)
class UlBoundTag:
    tag_ref: str
    scan_ref: str
    family: str
    ul_identity_digest: str
    scan_seq: int
    scan_entry_sha256: str
    inventory_seq: int
    inventory_entry_sha256: str
    identity: UlIdentity = field(repr=False)
    inventory_attestation_id: str = ""
    warnings: tuple = ()

    def to_dict(self, attestation_id):
        """attestation_id는 이 호출에서 다시 확인한 현재 증명 id, inventory_attestation_id는 inventory 행의 id다."""
        return {"ok": True, "schema": "pweh.nfc-ul-inventory/v1", "tag_ref": self.tag_ref,
                "scan_ref": self.scan_ref, "family": self.family, "ul_identity_digest": self.ul_identity_digest,
                "policy_profile": POLICY_PROFILE,
                "attestation": {"kind": OWNERSHIP_KIND, "attestation_id": attestation_id,
                                "inventory_attestation_id": self.inventory_attestation_id},
                "source": {"scan_seq": self.scan_seq, "scan_entry_sha256": self.scan_entry_sha256,
                           "inventory_seq": self.inventory_seq, "inventory_entry_sha256": self.inventory_entry_sha256},
                "inventory_binding_verified": True, "physical_same_tag_verified": False,
                "warnings": list(self.warnings)}


def _identity_data(identity):
    return {"uid": identity.uid.hex(), "atqa_msb": identity.atqa_msb.hex(), "sak": identity.sak.hex(),
            "mifare_version": None if identity.version is None else identity.version.hex()}


def _hex(value, width):
    return type(value) is str and len(value) == width and all(c in _HEX for c in value)


def _decode_identity(value):
    if (type(value) is not dict or set(value) != _IDENTITY_KEYS or not _hex(value["uid"], 14)
            or value["atqa_msb"] != "0044" or value["sak"] != "00"
            or not (value["mifare_version"] is None or _hex(value["mifare_version"], 16))):
        raise error("nfc_scan_invalid")
    version = None if value["mifare_version"] is None else bytes.fromhex(value["mifare_version"])
    return UlIdentity(bytes.fromhex(value["uid"]), b"\x00\x44", b"\x00", version)


def _ul_fact(entry, case_id, fact_kind, source):
    """NTAG ``_fact``와 같은 envelope 검사이되 attestation_id는 반드시 증명 id다."""
    if (type(entry) is not dict or set(entry) != _ENTRY_KEYS or entry.get("schema") != LEDGER_SCHEMA
            or entry.get("case_id") != case_id or entry.get("kind") != KIND_DEVICE_FACT
            or entry.get("fact_kind") != fact_kind or entry.get("source") != source
            or entry.get("path") is not None or entry.get("size") is not None
            or not _matches(_ATT, entry.get("attestation_id"))
            or not _uint(entry.get("seq")) or not _valid_text(entry.get("ts"), 64)
            or not _matches(_SHA, entry.get("prev")) or not _matches(_SHA, entry.get("sha256"))
            or type(entry.get("data")) is not dict or _entry_hash(entry["data"]) != entry["sha256"]):
        raise error("nfc_scan_invalid")


def _ul_scan(entry, case_id):
    """UL scan 사실은 닫힌 UL 프로필 집합의 정확한 이름 조회 뒤 hash·commit 전체 일치와 READ 0·GET_VERSION 1만 받는다.

    live ``UL_READ`` 하나와만 비교하지 않으므로 다시 고정(새 이름)한 뒤에도 이전 행이 그대로 검증된다.
    """
    _ul_fact(entry, case_id, UL_SCAN_FACT, SCAN_SOURCE)
    d = entry["data"]
    row = CU.known_ul_profile(d.get("profile"))
    if (set(d) != _UL_SCAN_KEYS or not _matches(_UL_SCAN, d["ul_scan_ref"]) or not _valid_text(d["session_id"], 128)
            or row is None or type(d["profile_sha256"]) is not str or d["profile_sha256"] != row.profile_sha256
            or type(d["firmware_commit"]) is not str or d["firmware_commit"] != row.firmware_commit
            or d["policy_profile"] != POLICY_PROFILE
            or type(d["family"]) is not str or d["family"] not in CU.UL_FAMILIES
            or type(d["read_requests"]) is not int or d["read_requests"] != 0
            or type(d["version_requests"]) is not int or d["version_requests"] != 1):
        raise error("nfc_scan_invalid")
    for key in ("firmware_claim_verified", "page_read_performed", "host_crc_verified", "reselection_atomic"):
        if d[key] is not False:
            raise error("nfc_scan_invalid")
    if d["steps_complete"] is not True:
        raise error("nfc_scan_invalid")
    _reader_binding(d["reader_binding"])
    identity = _decode_identity(d["identity"])
    _check_family(identity, d["family"])
    return identity


def _ul_inventory(entry, case_id):
    _ul_fact(entry, case_id, UL_INVENTORY_FACT, INVENTORY_SOURCE)
    d = entry["data"]
    if (set(d) != _UL_INV_KEYS or not _matches(_UL_TAG, d["ul_tag_ref"]) or not _matches(_UL_SCAN, d["ul_scan_ref"])
            or not _uint(d["scan_seq"]) or not _matches(_SHA, d["scan_entry_sha256"])
            or not _matches(_DIGEST, d["ul_identity_digest"]) or type(d["family"]) is not str
            or d["family"] not in CU.UL_FAMILIES or d["policy_profile"] != POLICY_PROFILE
            or d["scan_seq"] >= entry["seq"]):
        raise error("nfc_scan_invalid")


def _ul_index(entries, case, check=lambda: None):
    """UL kind 또는 UL 키(ul_scan_ref·ul_tag_ref)를 가진 행은 그 kind의 정확한 형식이어야 한다.

    UL 키가 없는 다른 행(NTAG 행 포함)은 건너뛴다. NTAG 행의 검증은 NTAG ``_index``가 맡는다.
    """
    if type(entries) is not list or len(entries) > MAX_LEDGER_ENTRIES:
        raise error("nfc_scan_invalid")
    scans, inventories = {}, {}
    for entry in entries:
        check()
        if type(entry) is not dict:
            raise error("nfc_scan_invalid")
        kind, d = entry.get("fact_kind"), entry.get("data")
        if type(d) is not dict:
            if kind in UL_FACTS:
                raise error("nfc_scan_invalid")
            continue
        if kind not in UL_FACTS and "ul_scan_ref" not in d and "ul_tag_ref" not in d:
            continue
        if kind == UL_SCAN_FACT:
            _ul_scan(entry, case.id)
            if d["ul_scan_ref"] in scans:
                raise error("nfc_scan_invalid")
            scans[d["ul_scan_ref"]] = entry
        elif kind == UL_INVENTORY_FACT:
            _ul_inventory(entry, case.id)
            if d["ul_tag_ref"] in inventories:
                raise error("nfc_scan_invalid")
            inventories[d["ul_tag_ref"]] = entry
        else:
            raise error("nfc_scan_invalid")
    linked = set()
    for inv in inventories.values():
        check()
        d = inv["data"]
        scan = scans.get(d["ul_scan_ref"])
        if (scan is None or d["scan_seq"] != scan["seq"] or d["scan_entry_sha256"] != _entry_hash(scan)
                or d["family"] != scan["data"]["family"] or d["ul_scan_ref"] in linked):
            raise error("nfc_scan_invalid")
        linked.add(d["ul_scan_ref"])
    return scans, inventories


def _bound(runtime, case, scan, inv):
    identity = _ul_scan(scan, case.id)
    d = inv["data"]
    if ul_identity_digest(runtime, case.id, identity, scan["data"]["family"]) != d["ul_identity_digest"]:
        raise error("nfc_scan_invalid")
    return UlBoundTag(d["ul_tag_ref"], d["ul_scan_ref"], d["family"], d["ul_identity_digest"], scan["seq"],
                      _entry_hash(scan), inv["seq"], _entry_hash(inv), identity, inv["attestation_id"])


def record_ul_scan(runtime, case, observation: UlScanObservation, attestation_id, *, deadline,
                   cancel=None) -> UlScanRef:
    """READ 없는 UL 식별 관찰을 같은 케이스 원장에 남긴다. 원장 잠금 안에서 같은 증명 id를 다시 확인한다."""
    try:
        case.require_authorization()
        check = _control(deadline, cancel)
        if type(observation) is not UlScanObservation:
            raise error("nfc_scan_invalid")
        o = observation
        _check_family(o.identity, o.family)
        if not _valid_text(o.session_id, 128):
            raise error("nfc_scan_invalid")
        if not _matches(_ATT, attestation_id):
            raise error("nfc_attestation_required")
        binding = _reader_binding(o.reader_binding)
        digest = ul_identity_digest(runtime, case.id, o.identity, o.family)
        ref = "US-" + uuid.uuid4().hex
        d = {"ul_scan_ref": ref, "session_id": o.session_id, "reader_binding": binding,
             "profile": CU.UL_READ.profile, "profile_sha256": CU.UL_READ.profile_sha256,
             "firmware_commit": CU.UL_READ.firmware_commit, "firmware_claim_verified": False,
             "identity": _identity_data(o.identity), "family": o.family, "policy_profile": POLICY_PROFILE,
             "page_read_performed": False, "read_requests": 0, "version_requests": 1,
             "steps_complete": True, "host_crc_verified": False, "reselection_atomic": False}

        def final(entries):
            check()
            scans, _ = _ul_index(entries, case, check)
            if ref in scans:
                raise error("nfc_scan_invalid")
            ul_require(runtime, case.id, o.family, digest, expected_id=attestation_id)
            check()

        entry = runtime.provenance.record_device_fact(case, UL_SCAN_FACT, d, dict(SCAN_SOURCE),
                                                      attestation_id=attestation_id, check_entries=final,
                                                      **_bounds(deadline, check))
        return UlScanRef(ref, o.family, digest, entry["seq"], _entry_hash(entry), attestation_id,
                         getattr(entry, "warnings", ()))
    except Exception as exc:
        failure = _fixed(exc)
    raise failure from None


def resolve_ul_scan(runtime, case, ul_scan_ref, *, deadline, cancel=None) -> UlScanTarget:
    """검증한 원장의 명시 UL scan 행에서 증명 대상(계열·지문)을 다시 계산한다. 인자로 UID·계열을 받지 않는다."""
    try:
        case.require_authorization()
        check = _control(deadline, cancel)
        if not _matches(_UL_SCAN, ul_scan_ref):
            raise error("nfc_input_invalid")
        entries = runtime.provenance.entries(case, **_bounds(deadline, check))
        scans, _ = _ul_index(entries, case, check)
        scan = scans.get(ul_scan_ref)
        if scan is None:
            raise error("nfc_scan_required")
        identity = _ul_scan(scan, case.id)
        family = scan["data"]["family"]
        target = UlScanTarget(ul_scan_ref, family, ul_identity_digest(runtime, case.id, identity, family),
                              scan["seq"], _entry_hash(scan))
        check()
        return target
    except Exception as exc:
        failure = _fixed(exc)
    raise failure from None


class _ExistingUlInventory(Exception):
    def __init__(self, bound):
        self.bound = bound
        super().__init__("existing_ul_inventory")


def add_ul_inventory(runtime, case, ul_scan_ref, attestation_id, *, deadline, cancel=None) -> UlBoundTag:
    """명시 UL scan을 원장 잠금 안에서 결속한다. 같은 scan의 중복 추가는 기존 행을 돌려준다.

    잠금 안에서 같은 증명 id를 다시 확인한다. NTAG inventory cache(nfc/inventory.json)는 쓰지 않는다.
    """
    try:
        case.require_authorization()
        check = _control(deadline, cancel)
        if not _matches(_UL_SCAN, ul_scan_ref):
            raise error("nfc_input_invalid")
        if not _matches(_ATT, attestation_id):
            raise error("nfc_attestation_required")
        entries = runtime.provenance.entries(case, **_bounds(deadline, check))
        scans, _ = _ul_index(entries, case, check)
        scan = scans.get(ul_scan_ref)
        if scan is None:
            raise error("nfc_scan_required")
        identity = _ul_scan(scan, case.id)
        family = scan["data"]["family"]
        digest = ul_identity_digest(runtime, case.id, identity, family)
        scan_hash = _entry_hash(scan)
        tag = "UT-" + uuid.uuid4().hex
        d = {"ul_tag_ref": tag, "ul_scan_ref": ul_scan_ref, "scan_seq": scan["seq"], "scan_entry_sha256": scan_hash,
             "ul_identity_digest": digest, "family": family, "policy_profile": POLICY_PROFILE}

        def final(current):
            check()
            fresh_scans, fresh_inv = _ul_index(current, case, check)
            found = fresh_scans.get(ul_scan_ref)
            if found is None or _entry_hash(found) != scan_hash:
                raise error("nfc_scan_invalid")
            ul_require(runtime, case.id, family, digest, expected_id=attestation_id)
            for inv in fresh_inv.values():
                if inv["data"]["ul_scan_ref"] == ul_scan_ref:
                    raise _ExistingUlInventory(_bound(runtime, case, found, inv))
                if inv["data"]["ul_tag_ref"] == tag:
                    raise error("nfc_scan_invalid")
            check()

        try:
            entry = runtime.provenance.record_device_fact(case, UL_INVENTORY_FACT, d, dict(INVENTORY_SOURCE),
                                                          attestation_id=attestation_id, check_entries=final,
                                                          **_bounds(deadline, check))
            bound = UlBoundTag(tag, ul_scan_ref, family, digest, scan["seq"], scan_hash, entry["seq"],
                               _entry_hash(entry), identity, attestation_id, getattr(entry, "warnings", ()))
        except _ExistingUlInventory as reuse:
            bound = reuse.bound
        return bound
    except Exception as exc:
        failure = _fixed(exc)
    raise failure from None


def resolve_ul_inventory(runtime, case, ul_tag_ref, *, deadline, cancel=None) -> UlBoundTag:
    """검증된 원장의 명시 UL tag/scan 결속만 반환한다. 지문은 scan identity에서 다시 계산해 같아야 한다.

    증명 확인은 호출자가 ``ul_attest``·``ul_require``로 따로 한다.
    """
    try:
        case.require_authorization()
        check = _control(deadline, cancel)
        if not _matches(_UL_TAG, ul_tag_ref):
            raise error("nfc_input_invalid")
        entries = runtime.provenance.entries(case, **_bounds(deadline, check))
        scans, invs = _ul_index(entries, case, check)
        inv = invs.get(ul_tag_ref)
        if inv is None:
            raise error("nfc_scan_required")
        bound = _bound(runtime, case, scans[inv["data"]["ul_scan_ref"]], inv)
        check()
        return bound
    except Exception as exc:
        failure = _fixed(exc)
    raise failure from None


def check_ul_inventory_entries(runtime, case, bound, entries, *, check) -> None:
    """이미 잠금 안에서 검증한 항목으로 UL 결속을 재확인한다. 원장을 다시 열지 않는다."""
    try:
        if (type(bound) is not UlBoundTag or type(entries) is not list or len(entries) > MAX_LEDGER_ENTRIES
                or not callable(check) or any(type(entry) is not dict for entry in entries)):
            raise error("nfc_input_invalid")
        if check() is not None:
            raise error("nfc_input_invalid")
        scans, inventories = _ul_index(entries, case, check)
        inv = inventories.get(bound.tag_ref)
        if inv is None:
            raise error("nfc_scan_required")
        fresh = _bound(runtime, case, scans[inv["data"]["ul_scan_ref"]], inv)
        for name in ("tag_ref", "scan_ref", "family", "ul_identity_digest", "scan_seq", "scan_entry_sha256",
                     "inventory_seq", "inventory_entry_sha256", "identity", "inventory_attestation_id"):
            if type(getattr(bound, name)) is not type(getattr(fresh, name)) or getattr(bound, name) != getattr(fresh, name):
                raise error("nfc_identity_mismatch")
        if check() is not None:
            raise error("nfc_input_invalid")
    except Exception as exc:
        failure = _fixed(exc)
    else:
        return
    raise failure from None
