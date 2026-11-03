"""CU가 관찰한 Ultralight 계열 페이지 snapshot의 순수 검증·집계·비교. 파일·태그·원장은 열지 않는다.

NTAG snapshot(``nfc_cu_snapshot``)과 다른 schema·profile·binding namespace(UT-/US-)를 쓰며 서로의 파일을 받지 않는다.
JSON 제한(깊이8·value 2048개·정수 토큰 20자리 미만·중복 key·실수 금지)은 NTAG 검사기의 같은 함수를 읽기 전용으로 쓴다.

불변 관계(``_checked``):
  - 계열은 ``UL_SPECS``의 다섯 행 중 하나이고 pages_total·read_last_target·withheld_pages가 그 행과 같다.
    원조 UL/UL C ⇔ version 없음, EV1은 그 계열의 정확8B version이다.
  - null이 아닌 페이지는 정확히 0..k-1이며 3 ≤ k ≤ last_target+1이다. 보류 페이지와 k 이상은 null이다.
    page0–2는 UID·BCC0·BCC1을 만족한다.
  - read_end: end_of_targets ⇒ k = last_target+1·page null, NAK 두 종류 ⇒ page = k·3 ≤ page ≤ last_target,
    stopped ⇒ page = k·stop_reason ∈ {time_limit, nfc_scan_invalid}.
    read_complete ⇔ stop_reason null ⇔ end_of_targets·nak_with_rollover, nak_without_rollover ⇔ tag_nak.
  - observed_variant는 읽기 동작의 추정 규칙(EV1은 계열, 원조는 0x10 초과 관찰 또는 3 ≤ page < 0x10 roll-over NAK면 ultralight_c)을 따른다.
결과에는 원시 UID·페이지 값을 넣지 않는다. inspect의 표준 필드(``standard_fields``)는 잠금·설정 비트와 AUTH0·AUTHLIM·VCTID 해석 값,
OTP 켜진 비트 수, 사용자 영역의 빈/기록 page 번호만 싣고 사용자 영역·OTP의 값은 싣지 않는다.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Callable

from . import cu_protocol as CU
from .nfc_cu_snapshot import (FALSE_FIELDS as NTAG_FALSE_FIELDS, UNOBSERVED_FIELDS, _Control, _InvalidJson,
                              _error, _hex, _not_integer, _object, _pairs, _preflight, _require, _tree)

SNAPSHOT_SCHEMA = "pweh.nfc-cu-ul-snapshot/v1"
SNAPSHOT_PROFILE = "cu-ultralight-pages-v1"
ANALYSIS_PROFILE = "cu-ultralight-snapshot-analysis-v2"
REPORT_SCHEMA = "pweh.nfc-ul-file-analysis/v1"
MAX_INPUT_BYTES = 65536
OWNERSHIP_KIND = "tag-ownership"
BINDING_FIELDS = ("ul_tag_ref", "ul_scan_ref", "ul_identity_digest", "scan_seq", "scan_entry_sha256",
                  "inventory_seq", "inventory_entry_sha256")
FALSE_FIELDS = NTAG_FALSE_FIELDS + ("read_sig_sent", "read_cnt_sent")
READ_END_KINDS = ("end_of_targets", "nak_with_rollover", "nak_without_rollover", "stopped")
VARIANTS = tuple(sorted(CU.UL_FAMILIES)) + ("ultralight_c",)
LIMITATIONS = ("stored_page_responses_only", "validated_prefix_pages_only", "signature_counters_tearing_unobserved",
               "withheld_pages_not_observed", "per_page_activation_not_atomic", "nak_boundary_inferred_unverified",
               "variant_inferred_from_read_behaviour", "physical_same_tag_not_verified",
               "console_causality_not_verified", "tag_ownership_is_human_statement",
               "standard_fields_are_stored_values")
LEGACY = "ultralight_or_ultralight_c"
# 데이터시트 표준 필드 위치: 계열 → (사용자 영역 마지막 page, (동적 잠금 page, 잠금 byte 수) 또는 None,
# (CFG0 page, CFG1 page) 또는 None). EV1은 NXP MF0ULX1, 원조 UL은 MF0ICU1, UL C는 MF0ICU2다.
_USER_FIRST = 4
_STATIC_LOCK_PAGE = 2
_OTP_PAGE = 3
_FIELD_LAYOUT = {
    "ultralight_ev1_mf0ul11": (0x0F, None, (0x10, 0x11)),
    "ultralight_ev1_mf0ulh11": (0x0F, None, (0x10, 0x11)),
    "ultralight_ev1_mf0ul21": (0x23, (0x24, 3), (0x25, 0x26)),
    "ultralight_ev1_mf0ulh21": (0x23, (0x24, 3), (0x25, 0x26)),
}
_LEGACY_LAYOUT = (0x0F, None, None)
_ULC_LAYOUT = (0x27, (0x28, 2), None)
# MF0ULX1 CFG0 byte0(MOD)·CFG1 byte0(ACCESS) 비트. 나머지 비트와 RFUI byte는 rfui_nonzero로만 보고한다.
_MOD_STRG_MOD_EN = 0x04  # MF0ULX1 Table 6 MOD bit 2. Table 8 각주: 50 pF(H) 부품에만 있고 17 pF 부품은 0b 고정
_STRG_MOD_FAMILIES = frozenset({"ultralight_ev1_mf0ulh11", "ultralight_ev1_mf0ulh21"})
_ACCESS_PROT = 0x80
_ACCESS_CFGLCK = 0x40
_ACCESS_AUTHLIM = 0x07
_LEGACY_SPLIT = 0x10
_MIN_PAGES = 3
_TOP = {"schema", "profile", "binding", "attestation", "reader", "identity", "pages_total", "read_last_target",
        "withheld_pages", "pages", "pages_observed", "read_end", "observed_variant", "read_complete", "stop_reason",
        "activation_per_page", "unobserved_fields", *FALSE_FIELDS}
_PATTERNS = {"ul_tag_ref": r"UT-[0-9a-f]{32}", "ul_scan_ref": r"US-[0-9a-f]{32}",
             "ul_identity_digest": r"sha256:[0-9a-f]{16}",
             "scan_entry_sha256": r"[0-9a-f]{64}", "inventory_entry_sha256": r"[0-9a-f]{64}"}
_ATT = re.compile(r"att-[0-9a-f]{10}")
_TYPED_FIELDS = {"family", "uid", "atqa_msb", "sak", "version", "pages", "binding", "attestation_id",
                 "pages_total", "read_last_target", "pages_observed", "read_end", "observed_variant",
                 "read_complete", "stop_reason", "input_size", "reader_profile"}


@dataclass(frozen=True, repr=False)
class CuUlSnapshot:
    """검사한 내부 값만 보유한다. 원시 UID·페이지·binding을 repr로 내보내지 않는다."""

    family: str
    uid: bytes
    atqa_msb: bytes
    sak: bytes
    version: bytes | None
    pages: tuple
    binding: tuple
    attestation_id: str
    pages_total: int
    read_last_target: int
    pages_observed: int
    read_end: tuple
    observed_variant: str
    read_complete: bool
    stop_reason: str | None
    input_size: int
    reader_profile: str


def binding_of(bound) -> dict:
    """UL inventory 결속(UlBoundTag)의 공개 7값. snapshot·원장 extra·승인 action·분석이 같은 이름을 쓴다."""
    return {"ul_tag_ref": bound.tag_ref, "ul_scan_ref": bound.scan_ref,
            "ul_identity_digest": bound.ul_identity_digest, "scan_seq": bound.scan_seq,
            "scan_entry_sha256": bound.scan_entry_sha256, "inventory_seq": bound.inventory_seq,
            "inventory_entry_sha256": bound.inventory_entry_sha256}


def withheld_dict(spec) -> dict:
    """spec의 보류 페이지를 snapshot·원장 extra·승인 action이 쓰는 {이유: [번호]} 형태로 만든다."""
    return {reason: list(pages) for reason, pages in spec.withheld}


def expected_variant(family: str, read_end: tuple, pages_observed: int) -> str:
    """§6.4 추정 규칙. EV1은 계열 그대로, 원조 UL/UL C는 0x10을 넘게 읽었거나 3 ≤ page < 0x10 roll-over NAK면 ultralight_c."""
    if family != LEGACY:
        return family
    kind, page = read_end
    if pages_observed > _LEGACY_SPLIT or (kind == "nak_with_rollover" and _MIN_PAGES <= page < _LEGACY_SPLIT):
        return "ultralight_c"
    return LEGACY


def _binding(value: object, control: _Control) -> tuple:
    _object(value, BINDING_FIELDS)
    for key in BINDING_FIELDS:
        control.check()
        item = value[key]
        if key in ("scan_seq", "inventory_seq"):
            _require(type(item) is int and 1 <= item <= (1 << 63) - 1)
        else:
            _require(type(item) is str and re.fullmatch(_PATTERNS[key], item) is not None)
    _require(value["scan_seq"] < value["inventory_seq"])
    return tuple((key, value[key]) for key in BINDING_FIELDS)


def _reader(value: object) -> str:
    """reader 객체는 Ultralight 닫힌 프로필 집합(UL_KNOWN)의 정확한 이름 하나와 다섯 값 전체가 같아야 한다."""
    _object(value, CU.READER_FIELDS)
    _require(all(type(value[key]) is str for key in CU.READER_FIELDS))
    row = CU.known_ul_profile(value["profile"])
    _require(row is not None and value == row.reader())
    return row.profile


def _read_end(value: object) -> tuple:
    _object(value, ("kind", "page"))
    kind, page = value["kind"], value["page"]
    _require(type(kind) is str and kind in READ_END_KINDS)
    _require(page is None or (type(page) is int and 0 <= page <= 0xff))
    return kind, page


def _checked(snapshot: CuUlSnapshot, control: _Control) -> None:
    """typed 생성자를 우회한 값도 같은 유한 관계 검사로 닫는다."""
    _require(type(snapshot) is CuUlSnapshot, "nfc_input_invalid")
    control.check()
    _require(set(vars(snapshot)) == _TYPED_FIELDS)
    _require(type(snapshot.reader_profile) is str and CU.known_ul_profile(snapshot.reader_profile) is not None)
    _require(type(snapshot.family) is str and snapshot.family in CU.UL_SPECS)
    spec = CU.UL_SPECS[snapshot.family]
    _require(type(snapshot.pages_total) is int and snapshot.pages_total == spec.pages_total)
    _require(type(snapshot.read_last_target) is int and snapshot.read_last_target == spec.last_target)
    _require(type(snapshot.input_size) is int and 1 <= snapshot.input_size <= MAX_INPUT_BYTES)
    _require(type(snapshot.attestation_id) is str and _ATT.fullmatch(snapshot.attestation_id) is not None)
    uid = snapshot.uid
    _require(type(uid) is bytes and len(uid) == 7 and type(snapshot.atqa_msb) is bytes
             and snapshot.atqa_msb == b"\x00\x44" and type(snapshot.sak) is bytes and snapshot.sak == b"\x00")
    if spec.version is None:
        _require(snapshot.version is None)
    else:
        _require(type(snapshot.version) is bytes and snapshot.version == spec.version)
    _require(type(snapshot.binding) is tuple and len(snapshot.binding) == len(BINDING_FIELDS))
    for pair, key in zip(snapshot.binding, BINDING_FIELDS):
        _require(type(pair) is tuple and len(pair) == 2 and type(pair[0]) is str and pair[0] == key)
    _binding(dict(snapshot.binding), control)
    observed = snapshot.pages_observed
    _require(type(observed) is int and _MIN_PAGES <= observed <= spec.last_target + 1)
    _require(type(snapshot.pages) is tuple and len(snapshot.pages) == spec.pages_total)
    withheld = spec.withheld_pages
    for index, page in enumerate(snapshot.pages):
        control.check()
        if index < observed and index not in withheld:
            _require(type(page) is bytes and len(page) == 4)
        else:
            _require(page is None)
    first, second, third = snapshot.pages[:3]
    _require(first[:3] == uid[:3] and first[3] == (0x88 ^ uid[0] ^ uid[1] ^ uid[2])
             and second == uid[3:7] and third[0] == (uid[3] ^ uid[4] ^ uid[5] ^ uid[6]))
    _require(type(snapshot.read_end) is tuple and len(snapshot.read_end) == 2)
    kind, page = snapshot.read_end
    _require(type(kind) is str and kind in READ_END_KINDS)
    reason = snapshot.stop_reason
    if kind == "end_of_targets":
        _require(page is None and observed == spec.last_target + 1)
    else:
        _require(type(page) is int and page == observed and _MIN_PAGES <= page <= spec.last_target)
    if kind == "stopped":
        _require(type(reason) is str and reason in ("time_limit", "nfc_scan_invalid"))
    elif kind == "nak_without_rollover":
        _require(reason == "tag_nak")
    else:
        _require(reason is None)
    _require(type(snapshot.read_complete) is bool
             and snapshot.read_complete is (reason is None)
             and snapshot.read_complete is (kind in ("end_of_targets", "nak_with_rollover")))
    _require(type(snapshot.observed_variant) is str
             and snapshot.observed_variant == expected_variant(snapshot.family, snapshot.read_end, observed))
    control.check()


def parse_cu_ul_snapshot(data: bytes, *, deadline: float,
                         cancel: Callable[[], bool] | None = None) -> CuUlSnapshot:
    """닫힌 서버 Ultralight snapshot 전체를 검증해 내부 불변 값만 반환한다."""
    control = _Control(deadline, cancel)
    _require(type(data) is bytes, "nfc_input_invalid")
    _require(len(data) <= MAX_INPUT_BYTES, "nfc_input_limit")
    control.check()
    _preflight(data, control)
    invalid = False
    value = None
    try:
        value = json.loads(data.decode("ascii"), object_pairs_hook=_pairs,
                           parse_float=_not_integer, parse_constant=_not_integer)
    except (ValueError, UnicodeError, _InvalidJson, RecursionError):
        invalid = True
    if invalid:
        raise _error()
    _tree(value, control)
    _object(value, _TOP)
    _require(value["schema"] == SNAPSHOT_SCHEMA and value["profile"] == SNAPSHOT_PROFILE)
    reader_profile = _reader(value["reader"])
    _require(value["unobserved_fields"] == list(UNOBSERVED_FIELDS))
    _require(value["activation_per_page"] is True)
    _require(all(value[key] is False for key in FALSE_FIELDS))
    attestation = value["attestation"]
    _object(attestation, ("kind", "attestation_id"))
    _require(attestation["kind"] == OWNERSHIP_KIND and type(attestation["attestation_id"]) is str)
    identity = value["identity"]
    _object(identity, ("family", "uid", "atqa_msb", "sak", "mifare_version"))
    family = identity["family"]
    _require(type(family) is str and family in CU.UL_SPECS)
    spec = CU.UL_SPECS[family]
    _require(value["withheld_pages"] == withheld_dict(spec))
    _require(type(value["pages"]) is list and len(value["pages"]) == spec.pages_total)
    pages = []
    for page in value["pages"]:
        control.check()
        pages.append(None if page is None else _hex(page, 4))
    version = None if identity["mifare_version"] is None else _hex(identity["mifare_version"], 8)
    result = CuUlSnapshot(
        family, _hex(identity["uid"], 7), _hex(identity["atqa_msb"], 2), _hex(identity["sak"], 1), version,
        tuple(pages), _binding(value["binding"], control), attestation["attestation_id"], value["pages_total"],
        value["read_last_target"], value["pages_observed"], _read_end(value["read_end"]),
        value["observed_variant"], value["read_complete"], value["stop_reason"], len(data), reader_profile,
    )
    _checked(result, control)
    return result


def _report(operation: str, partial: bool, summary: dict, coverage: dict) -> dict:
    return {"schema_version": 1, "operation": operation, "status": "partial" if partial else "ok",
            "profile": ANALYSIS_PROFILE, "summary": summary, "coverage": coverage,
            "limitations": list(LIMITATIONS)}


def _read_end_public(snapshot: CuUlSnapshot) -> dict:
    return {"kind": snapshot.read_end[0], "page": snapshot.read_end[1]}


def _read_summary(snapshot: CuUlSnapshot) -> dict:
    return {"pages_observed": snapshot.pages_observed, "read_end": _read_end_public(snapshot),
            "read_complete": snapshot.read_complete, "stop_reason": snapshot.stop_reason,
            "observed_variant": snapshot.observed_variant}


def _withheld_count(snapshot: CuUlSnapshot) -> int:
    return snapshot.pages_total - snapshot.read_last_target - 1


def _bits_set(data: bytes) -> int:
    return sum(bin(value).count("1") for value in data)


def _field_layout(snapshot: CuUlSnapshot) -> tuple:
    if snapshot.family in _FIELD_LAYOUT:
        return _FIELD_LAYOUT[snapshot.family]
    return _ULC_LAYOUT if snapshot.observed_variant == "ultralight_c" else _LEGACY_LAYOUT


def standard_fields(snapshot: CuUlSnapshot) -> dict:
    """관찰한 page에서 데이터시트가 정한 필드만 해석한다. UID·사용자 영역·OTP의 값은 넣지 않는다(개수·번호만).

    - static_lock(page 2 byte2·3): L-OTP·block-lock 세 비트와 잠긴 사용자 page 번호(4–15).
    - otp(page 3): 켜진 비트 수.
    - user_memory: 계열의 사용자 영역 중 관찰한 page를 모두 0x00인 것과 아닌 것의 번호로 나눈다.
    - dynamic_lock(MF0UL21/H21 page 0x24, UL C page 0x28): 잠금 byte의 켜진 비트 수만(page 대응은 해석하지 않는다).
    - configuration(EV1 CFG0·CFG1): AUTH0과 비밀번호 보호 범위, STRG_MOD_EN(50 pF H 부품만, 아니면 null), PROT, CFGLCK,
      AUTHLIM, VCTID, RFUI 비트 여부(두 page 모두 관찰했을 때).
      원조 UL·UL C는 null이다. 저장 값이며 명령으로 보호 동작을 확인하지 않는다.
    """
    pages = snapshot.pages

    def seen(index: int):
        return pages[index] if index < len(pages) else None

    last_user, dynamic, config = _field_layout(snapshot)
    lock = pages[_STATIC_LOCK_PAGE][2] | (pages[_STATIC_LOCK_PAGE][3] << 8)
    static = {"page": _STATIC_LOCK_PAGE, "otp_locked": bool(lock & 0x08), "block_lock_otp": bool(lock & 0x01),
              "block_lock_pages_4_9": bool(lock & 0x02), "block_lock_pages_10_15": bool(lock & 0x04),
              "locked_pages": [page for page in range(_USER_FIRST, 16) if lock >> page & 1]}
    otp = seen(_OTP_PAGE)
    user_pages = [(page, seen(page)) for page in range(_USER_FIRST, last_user + 1)]
    observed_user = [(page, value) for page, value in user_pages if value is not None]
    fields = {
        "static_lock": static,
        "otp": {"page": _OTP_PAGE, "observed": otp is not None, "bits_set": None if otp is None else _bits_set(otp)},
        "user_memory": {"first_page": _USER_FIRST, "last_page": last_user, "pages_observed": len(observed_user),
                        "blank_pages": [page for page, value in observed_user if value == b"\x00" * 4],
                        "nonblank_pages": [page for page, value in observed_user if value != b"\x00" * 4]},
        "dynamic_lock": None,
        "configuration": None,
    }
    if dynamic is not None:
        page, width = dynamic
        value = seen(page)
        fields["dynamic_lock"] = {"page": page, "observed": value is not None,
                                  "bits_set": None if value is None else _bits_set(value[:width])}
    if config is not None:
        cfg0, cfg1 = seen(config[0]), seen(config[1])
        auth0 = None if cfg0 is None else cfg0[3]
        strg = snapshot.family in _STRG_MOD_FAMILIES
        mod_rfui = 0xff & ~(_MOD_STRG_MOD_EN if strg else 0)  # 17 pF 부품은 MOD 전체가 RFUI다
        rfui = None
        if cfg0 is not None and cfg1 is not None:
            rfui = bool(cfg0[0] & mod_rfui or cfg0[1] or cfg0[2]
                        or cfg1[0] & ~(_ACCESS_PROT | _ACCESS_CFGLCK | _ACCESS_AUTHLIM) & 0xff or cfg1[2] or cfg1[3])
        fields["configuration"] = {
            "cfg0_page": config[0], "cfg0_observed": cfg0 is not None,
            "cfg1_page": config[1], "cfg1_observed": cfg1 is not None,
            "auth0": auth0,
            # AUTH0가 마지막 page 주소보다 크면 비밀번호 보호가 사실상 꺼진다(MF0ULX1).
            "password_protection_enabled": None if auth0 is None else auth0 <= snapshot.pages_total - 1,
            "strg_mod_en": None if cfg0 is None or not strg else bool(cfg0[0] & _MOD_STRG_MOD_EN),
            "prot_read_and_write": None if cfg1 is None else bool(cfg1[0] & _ACCESS_PROT),
            "cfglck": None if cfg1 is None else bool(cfg1[0] & _ACCESS_CFGLCK),
            "authlim": None if cfg1 is None else cfg1[0] & _ACCESS_AUTHLIM,
            "vctid": None if cfg1 is None else cfg1[1],
            "rfui_nonzero": rfui,
        }
    return fields


def inspect_cu_ul_snapshot(snapshot: CuUlSnapshot, *, deadline: float,
                           cancel: Callable[[], bool] | None = None) -> dict:
    """전체 JSON 검증과 관찰·보류 페이지 수, 데이터시트 표준 필드 해석을 원시 UID·page 값 없이 반환한다."""
    control = _Control(deadline, cancel)
    _checked(snapshot, control)
    summary = {"family": snapshot.family, "observed_variant": snapshot.observed_variant,
               "pages_total": snapshot.pages_total, "read_last_target": snapshot.read_last_target,
               "pages_observed": snapshot.pages_observed, "withheld_pages_count": _withheld_count(snapshot),
               "read_end": _read_end_public(snapshot), "read_complete": snapshot.read_complete,
               "stop_reason": snapshot.stop_reason, "unobserved_fields": list(UNOBSERVED_FIELDS),
               "fields": standard_fields(snapshot)}
    coverage = {"input_bytes": snapshot.input_size, "consumed_bytes": snapshot.input_size,
                "unexamined_bytes": 0, "input_exhausted": True,
                "pages_unobserved": snapshot.read_last_target + 1 - snapshot.pages_observed,
                "pages_withheld": _withheld_count(snapshot),
                "reasons": [] if snapshot.read_complete else ["read_partial"]}
    control.check()
    return _report("inspect", not snapshot.read_complete, summary, coverage)


def diff_cu_ul_snapshots(before: CuUlSnapshot, after: CuUlSnapshot, *, deadline: float,
                         cancel: Callable[[], bool] | None = None) -> dict:
    """양쪽에서 관찰한 보류되지 않은 페이지의 변경 위치만 비교한다. 비교 중 시간 한도만 partial로 마감한다.

    같은 계열·identity·binding·reader 프로필·snapshot 프로필·read_last_target이어야 한다(아니면 nfc_source_mismatch).
    pages_compared + before_only + after_only + neither_observed + withheld + comparison_unexamined = pages_total이다.
    """
    control = _Control(deadline, cancel)
    _checked(before, control)
    _checked(after, control)
    _require(before.family == after.family and before.pages_total == after.pages_total
             and before.read_last_target == after.read_last_target and before.binding == after.binding
             and (before.uid, before.atqa_msb, before.sak, before.version)
             == (after.uid, after.atqa_msb, after.sak, after.version)
             and before.reader_profile == after.reader_profile, "nfc_source_mismatch")
    targets = before.read_last_target + 1
    compared = before_only = after_only = neither = processed = 0
    changed = []
    for index in range(targets):
        if not control.check(partial=True):
            break
        old, new = before.pages[index], after.pages[index]
        if old is not None and new is not None:
            compared += 1
            if old != new:
                changed.append(index)
        elif old is not None:
            before_only += 1
        elif new is not None:
            after_only += 1
        else:
            neither += 1
        processed += 1
    # 끝난 비교를 늦은 시각으로 뒤집지 않되 취소/실패는 계속 확인한다.
    control.check(time_limit=False)
    remaining = targets - processed
    complete = remaining == 0
    read_complete = before.read_complete and after.read_complete
    end_changed = before.read_end != after.read_end
    summary = {"family": before.family, "pages_total": before.pages_total,
               "read_last_target": before.read_last_target,
               "before": _read_summary(before), "after": _read_summary(after),
               "pages_compared": compared, "before_only_pages": before_only, "after_only_pages": after_only,
               "neither_observed_pages": neither, "withheld_pages": _withheld_count(before),
               "comparison_unexamined_pages": remaining, "changed_pages": changed,
               "read_end_changed": end_changed,
               "stored_pages_equal": (not changed) if complete and read_complete and not end_changed else None}
    size = before.input_size + after.input_size
    coverage = {"input_bytes": size, "consumed_bytes": size, "unexamined_bytes": 0,
                "comparison_complete": complete, "changes_complete": complete,
                "changed_pages_count_is_lower_bound": not complete,
                "reasons": ([] if read_complete else ["read_partial"]) + ([] if complete else ["time_limit"])}
    return _report("diff", not (read_complete and complete), summary, coverage)
