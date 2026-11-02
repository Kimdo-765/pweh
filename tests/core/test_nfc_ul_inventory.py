"""합성 Ultralight scan 사실·tag-ownership 증명·UL inventory 원장 결속과 NTAG namespace 분리를 검사한다.

사람 증명은 격리 상태의 저장소 API(request/decide)로만 만든다. 실제 `pweh attest`는 실행하지 않는다.
"""
from __future__ import annotations

import functools
import hashlib
import importlib.util
import json
import sys
from dataclasses import replace
from types import MappingProxyType

import anyio
import pytest
from pathlib import Path

from pweh import cu_protocol as C, nfc_inventory as N, nfc_ul_inventory as U, schemas
import pweh.safety.attestations as att
from pweh.errors import PwehError
from pweh.nfc_formats import _NfcFileIdentity
from pweh.safety.attestations import attestation_fingerprint
from .test_nfc_inventory import setup, end, rewrite  # noqa: F401 - fixture 재사용
from .test_cu_ultralight_protocol import profile_from, ul_recipe

# 독립 literal 고정값. 구현 상수를 읽지 않는다.
QUESTIONS_SHA256 = "dc25a3def996c4057831e39976a03c307c19a782949f9b7be179349f7085ec39"
UL_PROFILE = {"profile": "cu-ultralight-v2.3.0-v1",
              "profile_sha256": "fde75c1da05251b816628e491b9e554d556857f455b39dc439df46a78225b728",
              "firmware_commit": "4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1"}
FLIPPER_PROFILE_SHA256 = "ded22bea4a319977da1d1ab47965f9b46572efa6d7ac56cf32c003a9febae37e"
UID = b"SYNUL07"
OTHER_UID = b"SYNUL08"
VERSIONS = {"ultralight_ev1_mf0ul11": "0004030101000b03", "ultralight_ev1_mf0ulh11": "0004030201000b03",
            "ultralight_ev1_mf0ul21": "0004030101000e03", "ultralight_ev1_mf0ulh21": "0004030201000e03",
            "ultralight_or_ultralight_c": None}
BINDING = {"backend": "posix-tty", "lock_key": "tty:synthetic", "device_id": "synthetic-device",
           "scope_keys": ["tty:synthetic"]}
EV1 = "ultralight_ev1_mf0ul11"
LEGACY = "ultralight_or_ultralight_c"


def identity(family=EV1, uid=UID):
    version = VERSIONS[family]
    return U.UlIdentity(uid, b"\x00\x44", b"\x00", None if version is None else bytes.fromhex(version))


def observation(family=EV1, uid=UID, **changes):
    value = U.UlScanObservation("synthetic-cu-session", dict(BINDING), identity(family, uid), family)
    return replace(value, **changes)


def digest(rt, case, family=EV1, uid=UID):
    return U.ul_identity_digest(rt, case.id, identity(family, uid), family)


def request(rt, case, family=EV1, uid=UID, *, kind=None):
    k, subject, binding = U.ul_ownership_target(case.id, family, digest(rt, case, family, uid))
    return rt.attestations.request(kind or k, subject, binding, U.ul_questions(), case.id)


def attest(rt, case, family=EV1, uid=UID, *, answer="yes", via="cli-tty", kind=None):
    rec = request(rt, case, family, uid, kind=kind)
    return rt.attestations.decide(rec["id"], {"owned_tag": answer}, via=via)["id"]


def scan(rt, case, family=EV1, uid=UID):
    aid = attest(rt, case, family, uid)
    return U.record_ul_scan(rt, case, observation(family, uid), aid, deadline=end()), aid


def code_of(call):
    with pytest.raises(PwehError) as exc:
        call()
    assert exc.value.data == {} and UID.hex() not in str(exc.value) and "SYNUL" not in str(exc.value)
    return exc.value.code


def ntag_observation():
    ident = _NfcFileIdentity(b"SYNTH01", b"\0\x44", b"\0", C.NtagFamily.NTAG213.mifare_version, "iso14443-3a")
    return N.CuScanObservation("synthetic-cu-session", dict(BINDING), ident, True, True, True)


@pytest.mark.parametrize("family", sorted(VERSIONS))
def test_scan_inventory_resolve_roundtrip_and_closed_schemas(setup, family):
    rt, case = setup
    ref, aid = scan(rt, case, family)
    assert type(ref) is U.UlScanRef and ref.scan_ref.startswith("US-") and ref.attestation_id == aid
    target = U.resolve_ul_scan(rt, case, ref.scan_ref, deadline=end())
    assert (target.family, target.ul_identity_digest) == (family, ref.ul_identity_digest)
    bound = U.add_ul_inventory(rt, case, ref.scan_ref, aid, deadline=end())
    assert type(bound) is U.UlBoundTag and bound.tag_ref.startswith("UT-") and bound.inventory_attestation_id == aid
    again = U.add_ul_inventory(rt, case, ref.scan_ref, aid, deadline=end())
    assert again.tag_ref == bound.tag_ref and again.inventory_seq == bound.inventory_seq
    resolved = U.resolve_ul_inventory(rt, case, bound.tag_ref, deadline=end())
    assert resolved.to_dict(aid) == bound.to_dict(aid) and resolved.identity == identity(family)
    schemas.validate("nfc-ul-scan", ref.to_dict())
    schemas.validate("nfc-ul-inventory", bound.to_dict(aid))
    entries = rt.provenance.entries(case)
    assert [e["fact_kind"] for e in entries] == [U.UL_SCAN_FACT, U.UL_INVENTORY_FACT]
    assert [e["attestation_id"] for e in entries] == [aid, aid]
    assert entries[0]["source"] == {"server": "nfc-mcp", "tool": "nfc_cu_ul_scan"}
    assert entries[1]["source"] == {"server": "nfc-mcp", "tool": "nfc_tag_inventory_add"}
    data = entries[0]["data"]
    assert {key: data[key] for key in UL_PROFILE} == UL_PROFILE
    assert (data["page_read_performed"], data["read_requests"], data["version_requests"]) == (False, 0, 1)
    assert data["identity"] == {"uid": UID.hex(), "atqa_msb": "0044", "sak": "00", "mifare_version": VERSIONS[family]}
    # 원조 UL/UL C ⇔ version null.
    assert (data["identity"]["mifare_version"] is None) == (family == LEGACY)
    assert not ({"scan_ref", "tag_ref"} & set(data)) and not ({"scan_ref", "tag_ref"} & set(entries[1]["data"]))
    # UL inventory는 NTAG cache를 쓰지 않는다.
    assert not (case.dir / "nfc" / "inventory.json").exists()
    public = json.dumps([ref.to_dict(), bound.to_dict(aid)]) + repr(ref) + repr(bound) + repr(observation(family))
    for secret in (UID.hex(), "SYNUL07", "synthetic-device"):
        assert secret not in public


@pytest.mark.parametrize("mode", ["none", "pending", "denied", "revoked", "expired", "wrong_id", "tag_purpose",
                                  "other_family", "other_uid"])
def test_scan_fact_requires_current_matching_ownership(setup, mode):
    rt, case = setup
    aid = None
    if mode == "pending":
        aid = request(rt, case)["id"]
    elif mode == "denied":
        aid = attest(rt, case, answer="no")
    elif mode in ("revoked", "expired", "wrong_id"):
        aid = attest(rt, case)
        if mode == "revoked":
            rt.attestations.revoke(aid)
        elif mode == "wrong_id":
            aid = "att-0000000000"
    elif mode == "tag_purpose":
        # 같은 subject·binding이어도 tag-purpose 기록은 UL 증명이 아니다.
        aid = attest(rt, case, kind="tag-purpose")
    elif mode == "other_family":
        aid = attest(rt, case, "ultralight_ev1_mf0ul21")
    elif mode == "other_uid":
        aid = attest(rt, case, uid=OTHER_UID)
    call = lambda: U.record_ul_scan(rt, case, observation(), aid or "att-1111111111", deadline=end())  # noqa: E731
    if mode == "expired":
        original = att._now
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(att, "_now", lambda: original() + att._dt.timedelta(days=8))
            assert code_of(call) == "nfc_attestation_required"
    else:
        assert code_of(call) == "nfc_attestation_required"
    assert rt.provenance.entries(case) == []


def test_elicitation_decided_record_is_accepted_like_the_store(setup):
    rt, case = setup
    aid = attest(rt, case, via="elicitation")
    assert U.ul_require(rt, case.id, EV1, digest(rt, case)) == aid
    ref = U.record_ul_scan(rt, case, observation(), aid, deadline=end())
    assert rt.provenance.entries(case)[0]["attestation_id"] == aid == ref.attestation_id


def test_other_case_record_and_scan_do_not_transfer(setup, auth):
    rt, case = setup
    other = rt.cases.create(title="합성 다른 케이스", authorization=auth, case_id="nfc-core-other")
    ref, aid = scan(rt, case)
    # 같은 UID라도 다른 케이스는 솔트·바인딩이 달라 증명을 쓸 수 없다.
    assert digest(rt, other) != digest(rt, case)
    assert code_of(lambda: U.ul_require(rt, other.id, EV1, digest(rt, case))) == "nfc_attestation_required"
    assert code_of(lambda: U.record_ul_scan(rt, other, observation(), aid, deadline=end())) == "nfc_attestation_required"
    assert code_of(lambda: U.resolve_ul_scan(rt, other, ref.scan_ref, deadline=end())) == "nfc_scan_required"
    assert code_of(lambda: U.add_ul_inventory(rt, other, ref.scan_ref, aid, deadline=end())) == "nfc_scan_required"


def test_inventory_add_rechecks_ownership_under_lock(setup):
    rt, case = setup
    ref, aid = scan(rt, case)
    rt.attestations.revoke(aid)
    assert code_of(lambda: U.add_ul_inventory(rt, case, ref.scan_ref, aid, deadline=end())) == "nfc_attestation_required"
    assert [e["fact_kind"] for e in rt.provenance.entries(case)] == [U.UL_SCAN_FACT]
    fresh = attest(rt, case)
    assert fresh != aid
    bound = U.add_ul_inventory(rt, case, ref.scan_ref, fresh, deadline=end())
    assert bound.inventory_attestation_id == fresh
    # 그 뒤 다시 철회되면 같은 scan의 기존 행도 돌려주지 않는다.
    rt.attestations.revoke(fresh)
    assert code_of(lambda: U.add_ul_inventory(rt, case, ref.scan_ref, fresh, deadline=end())) == "nfc_attestation_required"
    # 현재 증명 id가 inventory 행과 달라도(재증명) 기존 행을 돌려준다.
    newer = attest(rt, case)
    reused = U.add_ul_inventory(rt, case, ref.scan_ref, newer, deadline=end())
    assert reused.tag_ref == bound.tag_ref and reused.inventory_attestation_id == fresh
    schemas.validate("nfc-ul-inventory", reused.to_dict(newer))
    assert reused.to_dict(newer)["attestation"] == {"kind": "tag-ownership", "attestation_id": newer,
                                                     "inventory_attestation_id": fresh}


@pytest.mark.parametrize("changes", [
    {"session_id": ""}, {"session_id": "private\n"}, {"session_id": "x" * 129}, {"reader_binding": {}},
    {"reader_binding": {"backend": "posix-tty", "lock_key": "x", "device_id": "d", "scope_keys": ["y"]}},
    {"family": "ultralight_ev1_mf0ul21"}, {"family": LEGACY}, {"family": "ntag213"}, {"family": "type2_other_version"},
    {"identity": U.UlIdentity(UID, b"\x00\x44", b"\x00", None)},
    {"identity": U.UlIdentity(UID, b"\x00\x44", b"\x00", bytes.fromhex("0004030201000b03"))},
    {"identity": _NfcFileIdentity(UID, b"\x00\x44", b"\x00", bytes.fromhex("0004030101000b03"), "iso14443-3a")},
])
def test_inconsistent_observation_never_creates_fact(setup, changes):
    rt, case = setup
    aid = attest(rt, case)
    assert code_of(lambda: U.record_ul_scan(rt, case, replace(observation(), **changes), aid, deadline=end())) in (
        "nfc_scan_invalid", "nfc_attestation_required")
    assert rt.provenance.entries(case) == []


@pytest.mark.parametrize("kwargs", [
    {"uid": b"SHORT"}, {"uid": bytearray(UID)}, {"atqa_msb": b"\x44\x00"}, {"sak": b"\x08"}, {"sak": 0},
    {"version": b"\x00" * 7}, {"version": "0004030101000b03"},
])
def test_identity_constructor_is_closed(kwargs):
    base = dict(uid=UID, atqa_msb=b"\x00\x44", sak=b"\x00", version=None)
    base.update(kwargs)
    with pytest.raises(PwehError):
        U.UlIdentity(**base)
    assert UID.hex() not in repr(U.UlIdentity(UID, b"\x00\x44", b"\x00", None))


@pytest.mark.parametrize("mutation", ["source", "fact_kind", "profile", "profile_sha", "commit", "flag", "reads",
                                      "reads_bool", "versions", "attestation_none", "attestation_approval",
                                      "uid_upper", "legacy_version", "family_swap", "policy", "extra", "ntag_key"])
def test_chain_valid_ul_scan_forgery_is_rejected(setup, mutation):
    rt, case = setup
    ref, aid = scan(rt, case)
    entries = rt.provenance.entries(case)
    row = entries[0]
    d = row["data"]
    if mutation == "source": row["source"]["tool"] = "nfc_cu_scan"
    elif mutation == "fact_kind": row["fact_kind"] = "other"
    elif mutation == "profile": d["profile"] = "cu-ntag21x-v2.3.0-v1"
    elif mutation == "profile_sha": d["profile_sha256"] = C.IDENTIFY.profile_sha256
    elif mutation == "commit": d["firmware_commit"] = "0" * 40
    elif mutation == "flag": d["page_read_performed"] = True
    elif mutation == "reads": d["read_requests"] = 2
    elif mutation == "reads_bool": d["read_requests"] = False
    elif mutation == "versions": d["version_requests"] = 0
    elif mutation == "attestation_none": row["attestation_id"] = None
    elif mutation == "attestation_approval": row["attestation_id"] = "ap-0123456789"
    elif mutation == "uid_upper": d["identity"]["uid"] = UID.hex().upper()
    elif mutation == "legacy_version": d["family"] = LEGACY
    elif mutation == "family_swap": d["family"] = "ultralight_ev1_mf0ulh11"
    elif mutation == "policy": d["policy_profile"] = "ntag21x-only-v1"
    elif mutation == "extra": d["private"] = "SENTINEL"
    elif mutation == "ntag_key": d["scan_ref"] = "NS-" + "0" * 32
    rewrite(rt, case, entries)
    for call in (lambda: U.resolve_ul_scan(rt, case, ref.scan_ref, deadline=end()),
                 lambda: U.add_ul_inventory(rt, case, ref.scan_ref, aid, deadline=end())):
        assert code_of(call) in ("nfc_scan_invalid", "nfc_scan_required")
    if mutation == "ntag_key":
        # UL 행이 NTAG 키를 가지면 NTAG 색인도 오염으로 거부한다.
        with pytest.raises(PwehError):
            N._index(rt.provenance.entries(case), case)
    elif mutation != "fact_kind":
        # UL 필드만 바꾼 행은 NTAG 색인이 그대로 건너뛴다.
        assert N._index(rt.provenance.entries(case), case) == ({}, {})


def test_data_hash_mismatch_is_rejected(setup):
    rt, case = setup
    ref, aid = scan(rt, case)
    entries = rt.provenance.entries(case)
    entries[0]["sha256"] = "0" * 64
    rewrite(rt, case, entries, data_hash=False)
    assert code_of(lambda: U.resolve_ul_scan(rt, case, ref.scan_ref, deadline=end())) == "nfc_scan_invalid"


@pytest.mark.parametrize("mutation", ["scan_seq", "scan_hash", "family", "digest", "policy", "attestation",
                                      "duplicate_scan", "duplicate_tag", "hidden_ref", "second_link", "ntag_tag_key"])
def test_ul_inventory_refs_and_whole_entry_hash_are_authoritative(setup, mutation):
    rt, case = setup
    ref, aid = scan(rt, case)
    bound = U.add_ul_inventory(rt, case, ref.scan_ref, aid, deadline=end())
    entries = rt.provenance.entries(case)
    row = entries[1]["data"]
    if mutation == "scan_seq": row["scan_seq"] = True
    elif mutation == "scan_hash": row["scan_entry_sha256"] = entries[0]["sha256"]
    elif mutation == "family": row["family"] = LEGACY
    elif mutation == "digest": row["ul_identity_digest"] = "sha256:" + "0" * 16
    elif mutation == "policy": row["policy_profile"] = "ntag21x-only-v1"
    elif mutation == "attestation": entries[1]["attestation_id"] = None
    elif mutation == "duplicate_scan": entries.append(json.loads(json.dumps(entries[0])))
    elif mutation == "duplicate_tag": entries.append(json.loads(json.dumps(entries[1])))
    elif mutation == "hidden_ref":
        entries.append(json.loads(json.dumps(entries[0])))
        entries[-1]["fact_kind"] = "different"
    elif mutation == "second_link":
        entries.append(json.loads(json.dumps(entries[1])))
        entries[-1]["data"]["ul_tag_ref"] = "UT-" + "1" * 32
    elif mutation == "ntag_tag_key":
        row["tag_ref"] = "NT-" + "0" * 32
    rewrite(rt, case, entries)
    assert code_of(lambda: U.resolve_ul_inventory(rt, case, bound.tag_ref, deadline=end())) in (
        "nfc_scan_invalid", "nfc_scan_required")
    if mutation == "ntag_tag_key":
        with pytest.raises(PwehError):
            N._index(rt.provenance.entries(case), case)


def test_ntag_row_with_ul_key_poisons_ul_and_ntag_indexes(setup):
    rt, case = setup
    N.record_cu_scan(rt, case, ntag_observation(), deadline=end())
    entries = rt.provenance.entries(case)
    entries[0]["data"]["ul_scan_ref"] = "US-" + "0" * 32
    rewrite(rt, case, entries)
    with pytest.raises(PwehError):
        N._index(rt.provenance.entries(case), case)
    with pytest.raises(PwehError):
        U._ul_index(rt.provenance.entries(case), case)


def test_ntag_functions_are_unchanged_by_valid_ul_rows(setup):
    rt, case = setup
    ntag = N.record_cu_scan(rt, case, ntag_observation(), deadline=end())
    ntag_bound = N.add_inventory(rt, case, ntag.scan_ref, deadline=end())
    before = N.resolve_inventory(rt, case, ntag_bound.tag_ref, deadline=end()).to_dict()
    cache = (case.dir / "nfc" / "inventory.json").read_bytes()
    for family in sorted(VERSIONS):
        ref, aid = scan(rt, case, family)
        U.add_ul_inventory(rt, case, ref.scan_ref, aid, deadline=end())
    entries = rt.provenance.entries(case)
    without = [e for e in entries if e["fact_kind"] not in U.UL_FACTS]
    assert len(without) == 2 and len(entries) == 12
    assert N._index(entries, case) == N._index(without, case)
    assert N.resolve_inventory(rt, case, ntag_bound.tag_ref, deadline=end()).to_dict() == before
    assert N.add_inventory(rt, case, ntag.scan_ref, deadline=end()).tag_ref == ntag_bound.tag_ref
    # 새 NTAG scan·inventory도 UL 행이 있는 원장에서 그대로 동작하고 cache에는 NTAG 행만 남는다.
    later = N.add_inventory(rt, case, N.record_cu_scan(rt, case, ntag_observation(), deadline=end()).scan_ref,
                            deadline=end())
    payload = json.loads((case.dir / "nfc" / "inventory.json").read_text())
    assert payload["total_inventory_count"] == 2 and cache != (case.dir / "nfc" / "inventory.json").read_bytes()
    assert {row["tag_ref"] for row in payload["entries"]} == {ntag_bound.tag_ref, later.tag_ref}
    # UL 색인도 NTAG 행을 건너뛴다.
    scans, invs = U._ul_index(rt.provenance.entries(case), case)
    assert len(scans) == len(invs) == 5 and all(key.startswith("US-") for key in scans)


def test_literal_ntag_and_flipper_pins_are_unchanged():
    assert N.VERSION_FAMILIES == {bytes.fromhex("0004040201000f03"): "ntag213",
                                  bytes.fromhex("0004040201001103"): "ntag215",
                                  bytes.fromhex("0004040201001303"): "ntag216"}
    assert N.POLICY_PROFILE == "ntag21x-only-v1" and N.PROFILE_SHA256 == FLIPPER_PROFILE_SHA256
    assert (N.SCAN_FACT, N.CU_SCAN_FACT, N.INVENTORY_FACT) == (
        "nfc-ntag21x-scan-v1", "nfc-ntag21x-cu-scan-v1", "nfc-inventory-v1")
    assert U.UL_FACTS == {"nfc-ultralight-cu-scan-v1", "nfc-ultralight-inventory-v1"}
    assert not U.UL_FACTS & {N.SCAN_FACT, N.CU_SCAN_FACT, N.INVENTORY_FACT}


def test_ntag_identify_and_ul_digests_are_pairwise_distinct_and_never_raw(setup):
    rt, case = setup
    version = bytes.fromhex(VERSIONS[EV1])
    ntag = N._digest(rt, case, _NfcFileIdentity(UID, b"\x00\x44", b"\x00", version, "iso14443-3a"))
    hf = rt.secret_digest(case.id, C.HF_DIGEST_DOMAIN + b"\0" + EV1.encode() + b"\0" + b"\x07" + UID
                          + b"\x00\x44" + b"\x00" + bytes((len(version),)) + version)
    ul = digest(rt, case)
    assert len({ntag, hf, ul}) == 3
    for value in (ntag, hf, ul):
        assert value.startswith("sha256:") and len(value) == 23 and UID.hex() not in value
    # 같은 UID의 다른 UL 계열·다른 UID는 다른 지문이다.
    assert digest(rt, case, "ultralight_ev1_mf0ul21") != ul != digest(rt, case, uid=OTHER_UID)
    assert digest(rt, case, LEGACY) not in (ul, digest(rt, case, LEGACY, OTHER_UID))
    # 독립 계산과 같다.
    assert ul == rt.secret_digest(case.id, b"pweh.nfc-ultralight-tag/v1\0" + EV1.encode() + b"\0\x07" + UID
                                  + b"\x00\x44\x00" + b"\x08" + version)
    assert digest(rt, case, LEGACY) == rt.secret_digest(
        case.id, b"pweh.nfc-ultralight-tag/v1\0" + LEGACY.encode() + b"\0\x07" + UID + b"\x00\x44\x00" + b"\x00")


def test_requester_and_verifier_fingerprints_match_and_subject_is_masked(setup):
    rt, case = setup
    value = digest(rt, case)
    decision = anyio.run(functools.partial(U.ul_attest, rt, case.id, EV1, value, tool="synthetic"))
    assert not decision.satisfied and decision.status == "attestation_required"
    rec = rt.attestations.get(decision.attestation_id)
    target = U.ul_ownership_target(case.id, EV1, value)
    assert rec["fingerprint"] == attestation_fingerprint(*target)
    assert rec["kind"] == "tag-ownership" and rec["subject"] == {
        "tag_family": EV1, "ul_identity_digest": value, "policy_profile": "ultralight-attested-v1"}
    assert rec["binding"] == {"scope": "case", "case_id": case.id}
    assert [q["id"] for q in rec["questions"]] == ["owned_tag"] and rec["valid_seconds"] == 7 * 86400
    mirror = (case.dir / "attestations.json").read_text(encoding="utf-8")
    for text in (json.dumps(rec, ensure_ascii=False), mirror, decision.summary or ""):
        assert UID.hex() not in text and "SYNUL07" not in text
    assert code_of(lambda: U.ul_require(rt, case.id, EV1, value)) == "nfc_attestation_required"
    rt.attestations.decide(rec["id"], {"owned_tag": "yes"}, via="cli-tty")
    assert U.ul_require(rt, case.id, EV1, value) == rec["id"]
    assert U.ul_require(rt, case.id, EV1, value, expected_id=rec["id"]) == rec["id"]
    assert code_of(lambda: U.ul_require(rt, case.id, EV1, value, expected_id="att-0000000000")) == (
        "nfc_attestation_required")
    again = anyio.run(functools.partial(U.ul_attest, rt, case.id, EV1, value, tool="synthetic"))
    assert again.satisfied and again.attestation_id == rec["id"] and again.kind == "tag-ownership"


def test_questions_are_pinned_and_copied():
    assert U.QUESTIONS_SHA256 == QUESTIONS_SHA256 == C.UL_OWNERSHIP["questions_sha256"]
    questions = U.ul_questions()
    assert questions == [{"id": "owned_tag", "type": "yesno", "expected": "yes",
                          "text": "방금 CU 리더에 올려 스캔한 태그 한 장(위 대상의 계열·지문)은 내가 소유했거나 "
                                  "소유자의 서면 허가를 받은 것이다"}]
    assert hashlib.sha256(att.canonical_json(questions).encode("utf-8")).hexdigest() == QUESTIONS_SHA256
    questions[0]["expected"] = None
    assert U.ul_questions()[0]["expected"] == "yes" and U.ul_questions() is not U.ul_questions()


@pytest.mark.parametrize("args", [
    ("../escape", EV1, "sha256:" + "0" * 16), ("nfc-core", "ntag213", "sha256:" + "0" * 16),
    ("nfc-core", "type2_other_version", "sha256:" + "0" * 16), ("nfc-core", EV1, "sha256:" + "0" * 15),
    ("nfc-core", EV1, UID.hex()), ("nfc-core", ["x"], "sha256:" + "0" * 16), (None, EV1, "sha256:" + "0" * 16),
])
def test_target_inputs_are_closed(args):
    assert code_of(lambda: U.ul_ownership_target(*args)) == "nfc_input_invalid"


def test_reference_inputs_are_closed(setup):
    rt, case = setup
    ref, aid = scan(rt, case)
    for bad in ("NS-" + ref.scan_ref[3:], ref.scan_ref.upper(), ref.scan_ref + "0", None, 1):
        assert code_of(lambda: U.resolve_ul_scan(rt, case, bad, deadline=end())) == "nfc_input_invalid"
        assert code_of(lambda: U.add_ul_inventory(rt, case, bad, aid, deadline=end())) == "nfc_input_invalid"
    for bad in ("NT-" + "0" * 32, "UT-" + "0" * 31, None):
        assert code_of(lambda: U.resolve_ul_inventory(rt, case, bad, deadline=end())) == "nfc_input_invalid"
    assert code_of(lambda: U.resolve_ul_inventory(rt, case, "UT-" + "0" * 32, deadline=end())) == "nfc_scan_required"
    assert code_of(lambda: U.resolve_ul_scan(rt, case, "US-" + "0" * 32, deadline=end())) == "nfc_scan_required"
    for bad in (None, "ap-0123456789", "att-XYZ"):
        assert code_of(lambda: U.add_ul_inventory(rt, case, ref.scan_ref, bad, deadline=end())) == (
            "nfc_attestation_required")
        assert code_of(lambda: U.record_ul_scan(rt, case, observation(), bad, deadline=end())) == (
            "nfc_attestation_required")


def test_check_entries_rebinds_inventory_and_detects_changes(setup):
    rt, case = setup
    ref, aid = scan(rt, case)
    bound = U.add_ul_inventory(rt, case, ref.scan_ref, aid, deadline=end())
    entries = rt.provenance.entries(case)
    assert U.check_ul_inventory_entries(rt, case, bound, entries, check=lambda: None) is None
    for changed in (replace(bound, inventory_attestation_id="att-0000000000"),
                    replace(bound, identity=identity(uid=OTHER_UID)), replace(bound, scan_seq=2)):
        assert code_of(lambda: U.check_ul_inventory_entries(rt, case, changed, entries, check=lambda: None)) == (
            "nfc_identity_mismatch")
    assert code_of(lambda: U.check_ul_inventory_entries(rt, case, bound, entries[:1], check=lambda: None)) == (
        "nfc_scan_required")


def _other_question_record(rt, case, *, questions):
    """같은 UL 대상(kind·subject·binding)에 다른 질문으로 사람 결정을 만든다(격리 저장소 API)."""
    k, subject, binding = U.ul_ownership_target(case.id, EV1, digest(rt, case))
    rec = rt.attestations.request(k, subject, binding, questions, case.id)
    answers = {q["id"]: "yes" for q in questions}
    return rt.attestations.decide(rec["id"], answers, via="cli-tty")["id"]


def _all_ul_entry_points_refuse(rt, case, scan_ref, aid):
    before = rt.provenance.entries(case)
    assert code_of(lambda: U.ul_require(rt, case.id, EV1, digest(rt, case))) == "nfc_attestation_required"
    assert code_of(lambda: U.record_ul_scan(rt, case, observation(), aid, deadline=end())) == (
        "nfc_attestation_required")
    assert code_of(lambda: U.add_ul_inventory(rt, case, scan_ref, aid, deadline=end())) == (
        "nfc_attestation_required")
    assert rt.provenance.entries(case) == before


def test_record_that_asked_another_question_does_not_satisfy_ul_gate(setup):
    rt, case = setup
    ref, aid = scan(rt, case)
    rt.attestations.revoke(aid)
    other = _other_question_record(rt, case, questions=[
        {"id": "other_q", "type": "yesno", "expected": "yes", "text": "합성 다른 질문"}])
    # 저장소는 질문 조건 없이는 이 기록을 받지만 UL 확인 지점은 owned_tag를 물은 기록만 받는다.
    k, subject, binding = U.ul_ownership_target(case.id, EV1, digest(rt, case))
    assert rt.attestations.require(k, subject, binding)["id"] == other
    _all_ul_entry_points_refuse(rt, case, ref.scan_ref, other)
    decision = anyio.run(functools.partial(U.ul_attest, rt, case.id, EV1, digest(rt, case), tool="synthetic"))
    assert not decision.satisfied and decision.attestation_id not in (aid, other)
    assert [q["id"] for q in rt.attestations.get(decision.attestation_id)["questions"]] == ["owned_tag"]


def test_record_with_reworded_owned_tag_text_does_not_satisfy_ul_gate(setup):
    rt, case = setup
    ref, aid = scan(rt, case)
    rt.attestations.revoke(aid)
    # 같은 id·type·expected이지만 문구가 다른 기록. 저장소 대조는 통과하지만 UL은 고정 문구만 받는다.
    reworded = [{**U.ul_questions()[0], "text": "이 태그는 게임·장난감 태그이며 자격증명이 아니다"}]
    other = _other_question_record(rt, case, questions=reworded)
    k, subject, binding = U.ul_ownership_target(case.id, EV1, digest(rt, case))
    assert rt.attestations.require(k, subject, binding, questions=U.ul_questions())["id"] == other
    _all_ul_entry_points_refuse(rt, case, ref.scan_ref, other)
    with pytest.raises(PwehError) as exc:
        anyio.run(functools.partial(U.ul_attest, rt, case.id, EV1, digest(rt, case), tool="synthetic"))
    assert exc.value.code == "nfc_attestation_required"


def test_decided_via_outside_recipe_is_rejected_even_if_store_accepts_it(setup, monkeypatch):
    rt, case = setup
    ref, aid = scan(rt, case)
    rt.attestations.revoke(aid)
    # 저장소 목록에 새 경로가 생긴 상황(이 모듈이 import한 이름까지 바꾼다). UL은 recipe 목록만 받는다.
    monkeypatch.setattr(att, "DECIDED_VIA", ("cli-tty", "elicitation", "web"))
    monkeypatch.setattr(U, "DECIDED_VIA", ("cli-tty", "elicitation", "web"))
    rec = request(rt, case)
    rt.attestations.decide(rec["id"], {"owned_tag": "yes"}, via="web")
    k, subject, binding = U.ul_ownership_target(case.id, EV1, digest(rt, case))
    assert rt.attestations.require(k, subject, binding, questions=U.ul_questions())["id"] == rec["id"]
    _all_ul_entry_points_refuse(rt, case, ref.scan_ref, rec["id"])
    with pytest.raises(PwehError) as exc:
        anyio.run(functools.partial(U.ul_attest, rt, case.id, EV1, digest(rt, case), tool="synthetic"))
    assert exc.value.code == "nfc_attestation_required"


def _import_ul_inventory_copy(name):
    path = Path(U.__file__)
    spec = importlib.util.spec_from_file_location(f"pweh.{name}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        return module
    finally:
        sys.modules.pop(spec.name, None)


def test_store_gaining_a_decided_via_value_does_not_break_import(monkeypatch):
    # 저장소 목록이 늘어도(부분집합 관계) 모듈은 import 되고 UL 목록은 recipe 그대로다.
    monkeypatch.setattr(att, "DECIDED_VIA", ("cli-tty", "elicitation", "web"))
    copy = _import_ul_inventory_copy("_nfc_ul_inventory_superset")
    assert copy.UL_DECIDED_VIA == {"cli-tty", "elicitation"}
    # recipe 값이 저장소 목록 밖이면(저장소가 경로를 없애면) import가 명시적으로 실패한다.
    monkeypatch.setattr(att, "DECIDED_VIA", ("cli-tty",))
    with pytest.raises(RuntimeError, match="Ultralight"):
        _import_ul_inventory_copy("_nfc_ul_inventory_subset")
    assert sys.modules["pweh.nfc_ul_inventory"] is U


# 이 단계(stage A)의 nfc_cu_ul_scan이 남기는 scan 사실 data 전체를 그대로 적은 literal이다. 구현 상수나 writer를
# 거치지 않으므로 UL recipe를 다시 고정해도(새 이름) 이미 기록한 이 행은 그대로 검증되어야 한다.
STAGE_A_SCAN_REF = "US-" + "0123456789abcdef" * 2
STAGE_A_TAG_REF = "UT-" + "fedcba9876543210" * 2


def stage_a_scan_data(family=EV1, *, uid=UID.hex()):
    return {"ul_scan_ref": STAGE_A_SCAN_REF, "session_id": "stage-a-cu-session",
            "reader_binding": {"backend": "posix-tty", "lock_key": "tty:stage-a", "device_id": "stage-a-device",
                               "scope_keys": ["tty:stage-a"]},
            "profile": "cu-ultralight-v2.3.0-v1",
            "profile_sha256": "fde75c1da05251b816628e491b9e554d556857f455b39dc439df46a78225b728",
            "firmware_commit": "4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1", "firmware_claim_verified": False,
            "identity": {"uid": uid, "atqa_msb": "0044", "sak": "00", "mifare_version": VERSIONS[family]},
            "family": family, "policy_profile": "ultralight-attested-v1", "page_read_performed": False,
            "read_requests": 0, "version_requests": 1, "steps_complete": True, "host_crc_verified": False,
            "reselection_atomic": False}


def record_stage_a_rows(rt, case, family=EV1):
    """literal stage-A UL scan 사실과 inventory 행을 원장 API로 직접 기록한다."""
    aid = attest(rt, case, family)
    rt.provenance.record_device_fact(case, "nfc-ultralight-cu-scan-v1", stage_a_scan_data(family),
                                     {"server": "nfc-mcp", "tool": "nfc_cu_ul_scan"}, attestation_id=aid)
    scan_entry = rt.provenance.entries(case)[-1]
    inventory = {"ul_tag_ref": STAGE_A_TAG_REF, "ul_scan_ref": STAGE_A_SCAN_REF, "scan_seq": scan_entry["seq"],
                 "scan_entry_sha256": N._entry_hash(scan_entry), "ul_identity_digest": digest(rt, case, family),
                 "family": family, "policy_profile": "ultralight-attested-v1"}
    rt.provenance.record_device_fact(case, "nfc-ultralight-inventory-v1", inventory,
                                     {"server": "nfc-mcp", "tool": "nfc_tag_inventory_add"}, attestation_id=aid)
    return aid


@pytest.mark.parametrize("family", sorted(VERSIONS))
def test_literal_stage_a_rows_stay_valid(setup, family):
    rt, case = setup
    aid = record_stage_a_rows(rt, case, family)
    assert rt.provenance.entries(case)[0]["data"] == stage_a_scan_data(family)
    bound = U.resolve_ul_inventory(rt, case, STAGE_A_TAG_REF, deadline=end())
    assert (bound.scan_ref, bound.family, bound.inventory_attestation_id) == (STAGE_A_SCAN_REF, family, aid)
    assert U.resolve_ul_scan(rt, case, STAGE_A_SCAN_REF, deadline=end()).ul_identity_digest == bound.ul_identity_digest
    again = U.add_ul_inventory(rt, case, STAGE_A_SCAN_REF, aid, deadline=end())
    assert again.tag_ref == STAGE_A_TAG_REF
    schemas.validate("nfc-ul-inventory", again.to_dict(aid))
    # 지문은 reader 프로필과 무관하므로 같은 태그의 live scan과 같은 값이며 같은 증명을 쓴다.
    live = U.record_ul_scan(rt, case, observation(family), aid, deadline=end())
    assert live.ul_identity_digest == bound.ul_identity_digest and live.scan_ref != STAGE_A_SCAN_REF


def test_repinned_ul_profile_keeps_stage_a_rows_valid_and_same_name_repin_poisons(setup, monkeypatch):
    rt, case = setup
    record_stage_a_rows(rt, case)
    original = C.UL_KNOWN[UL_PROFILE["profile"]]
    recipe = ul_recipe()
    recipe["profile"] = "cu-ultralight-v2.3.0-v2"
    recipe["stop"]["nak_min_page"] = recipe["min_retained_pages"] = 4
    v2 = profile_from(recipe)
    # 새 이름으로 다시 고정하고 이전 행을 검증 전용으로 남긴 경우: 이전 행·새 scan이 함께 검증된다.
    monkeypatch.setattr(C, "UL_READ", v2)
    monkeypatch.setattr(C, "UL_KNOWN", MappingProxyType({original.profile: original, v2.profile: v2}))
    assert U.resolve_ul_inventory(rt, case, STAGE_A_TAG_REF, deadline=end()).scan_ref == STAGE_A_SCAN_REF
    ref, aid = scan(rt, case, uid=OTHER_UID)
    assert rt.provenance.entries(case)[-1]["data"]["profile"] == "cu-ultralight-v2.3.0-v2"
    assert U.add_ul_inventory(rt, case, ref.scan_ref, aid, deadline=end()).scan_ref == ref.scan_ref
    # 같은 이름에 다른 hash를 두면(이전 행을 남기지 않은 재고정) 이전 행이 UL 색인 전체를 오염시킨다.
    same_name = profile_from({**recipe, "profile": UL_PROFILE["profile"]})
    assert same_name.profile_sha256 != UL_PROFILE["profile_sha256"]
    monkeypatch.setattr(C, "UL_KNOWN", MappingProxyType({same_name.profile: same_name, v2.profile: v2}))
    assert code_of(lambda: U.resolve_ul_inventory(rt, case, STAGE_A_TAG_REF, deadline=end())) == "nfc_scan_invalid"
    assert code_of(lambda: U.resolve_ul_scan(rt, case, ref.scan_ref, deadline=end())) == "nfc_scan_invalid"


@pytest.mark.parametrize("values", [
    {"profile": "cu-ultralight-v2.3.0-v2"}, {"profile": "CU-ULTRALIGHT-V2.3.0-V1"},
    {"profile": "cu-ultralight-v2.3.0-v1 "}, {"profile": None}, {"profile": 1},
    {"profile": ["cu-ultralight-v2.3.0-v1"]}, {"profile": {"cu-ultralight-v2.3.0-v1": 1}},
    {"profile": "cu-hf14a-identify-v2.3.0-v1", "profile_sha256": C.IDENTIFY.profile_sha256},
    {"profile": "cu-ntag21x-v2.3.0-v1", "profile_sha256": C.V230.profile_sha256},
    {"profile_sha256": UL_PROFILE["profile_sha256"].upper()}, {"profile_sha256": None},
    {"profile_sha256": "0" * 64}, {"firmware_commit": 1}, {"firmware_commit": "f349dbeeaa315776b272ae8fb851cc4042d55f07"},
])
def test_cross_paired_or_unknown_ul_profile_rows_poison_ul_index(setup, values):
    rt, case = setup
    record_stage_a_rows(rt, case)
    entries = rt.provenance.entries(case)
    entries[0]["data"].update(values)
    rewrite(rt, case, entries)
    assert code_of(lambda: U.resolve_ul_scan(rt, case, STAGE_A_SCAN_REF, deadline=end())) == "nfc_scan_invalid"
    assert code_of(lambda: U.resolve_ul_inventory(rt, case, STAGE_A_TAG_REF, deadline=end())) == "nfc_scan_invalid"
