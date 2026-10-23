"""합성 scan 사실과 strict NFC 파일의 결속·캐시·원장 경계."""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import time
from dataclasses import replace

import pytest

from pweh import nfc_formats as F, nfc_inventory as N
from pweh.errors import PwehError
from pweh.provenance import _genesis
from pweh.runtime import get_runtime
from pweh.safety.attestations import canonical_json
from core.test_nfc_formats import _header, _ntag


def end():
    return time.monotonic() + 5


@pytest.fixture
def setup(workspace, auth):
    rt = get_runtime("test")
    case = rt.cases.create(title="합성 NFC", authorization=auth, case_id="nfc-core")
    return rt, case


def observation(family="ntag213", **overrides):
    version = next(k for k, v in N.VERSION_FAMILIES.items() if v == family)
    identity = F._NfcFileIdentity(b"SYNTH01", b"\x00\x44", b"\0", version, "iso14443-3a")
    value = N.ScanObservation("synthetic-session", {"backend": "posix-tty", "lock_key": "tty:synthetic",
        "device_id": "synthetic-device", "scope_keys": ["tty:synthetic"]}, identity,
        hashlib.sha256(b"synthetic probe").hexdigest(), 100, True, True, True)
    return replace(value, **overrides)


def scan(rt, case, family="ntag213"):
    return N.record_flipper_scan(rt, case, observation(family), deadline=end())


def add(rt, case, ref):
    return N.add_inventory(rt, case, ref.scan_ref, deadline=end())


def rewrite(rt, case, entries, *, data_hash=True):
    # 합성 원장의 전체 체인을 다시 만들어 의미 검증과 단순 chain 검증을 구분한다.
    previous = _genesis(case.id)
    lines = []
    for seq, entry in enumerate(entries, 1):
        entry.update(seq=seq, prev=previous)
        if data_hash and entry.get("kind") == "device-fact":
            entry["sha256"] = hashlib.sha256(canonical_json(entry["data"]).encode()).hexdigest()
        line = canonical_json(entry)
        lines.append(line)
        previous = hashlib.sha256(line.encode()).hexdigest()
    rt.provenance.ledger_path(case).write_text("\n".join(lines) + "\n")


@pytest.mark.parametrize("family,model", [("ntag213", 213), ("ntag215", 215), ("ntag216", 216)])
@pytest.mark.parametrize("partial", [False, True])
def test_scan_inventory_private_binding_and_public_parser_unchanged(setup, family, model, partial):
    rt, case = setup
    ref = scan(rt, case, family)
    bound = add(rt, case, ref)
    raw = _ntag(model, read=1 if partial else None).replace(
        b"Mifare version: 00 00 00 00 00 00 00 00", b"Mifare version: " + observation(family).identity.mifare_version.hex(" ").upper().encode())
    public = F.inspect_nfc(raw, deadline=end())
    result, identity = F._inspect_nfc_bound(raw, deadline=end())
    assert result == public
    assert result["status"] == ("partial" if partial else "ok")
    N.match_file_identity(bound, identity)
    resolved = N.resolve_inventory(rt, case, bound.tag_ref, deadline=end())
    assert resolved.to_dict() == bound.to_dict()
    assert add(rt, case, ref).tag_ref == bound.tag_ref
    assert len(rt.provenance.entries(case)) == 2
    assert bound.scan_entry_sha256 != rt.provenance.entries(case)[0]["sha256"]
    visible = json.dumps([result, ref.to_dict(), bound.to_dict()]) + repr(identity) + repr(bound)
    assert "SYNTH01" not in visible and "53594e54483031" not in visible
    assert bound.to_dict()["physical_same_tag_verified"] is False


@pytest.mark.parametrize("uid", [b"ABCD", b"SYNTH01", b"ABCDEFGHIJ"])
def test_private_iso_identity_keeps_public_uid_lengths(uid):
    raw = ("\n".join(_header(uid)) + "\n").encode()
    report, identity = F._inspect_nfc_bound(raw, deadline=end())
    assert report == F.inspect_nfc(raw, deadline=end())
    assert identity.uid == uid and identity.mifare_version is None


@pytest.mark.parametrize("variant", ["duplicate", "missing", "uid_length", "invalid_utf8", "unsupported", "line_limit", "time_limit", "output_time"])
def test_private_identity_never_survives_invalid_or_unexamined_input(variant, monkeypatch):
    raw = _ntag()
    kw = {}
    if variant == "duplicate":
        raw += b"UID: 53 59 4E 54 48 30 31\n"
    elif variant == "missing":
        raw = raw.replace(b"Page 5: 00 00 00 00\n", b"")
    elif variant == "uid_length":
        raw = raw.replace(b"UID: 53 59 4E 54 48 30 31", b"UID: 01 02 03 04")
    elif variant == "invalid_utf8":
        raw += b"\xff\n"
    elif variant == "unsupported":
        raw = raw.replace(b"Version: 4", b"Version: 3")
    elif variant == "line_limit":
        kw["limits"] = replace(F.NfcLimits(), max_lines=3)
    elif variant == "time_limit":
        kw["deadline"] = time.monotonic() - 1
    else:
        original = F._output
        def changed(report, limits, control):
            report = original(report, limits, control)
            report["status"] = "partial"
            report["coverage"]["truncated_reasons"].append("time_limit")
            return report
        monkeypatch.setattr(F, "_output", changed)
    _, identity = F._inspect_nfc_bound(raw, **{"deadline": end(), **kw})
    assert identity is None


def test_unknown_field_and_partial_read_can_keep_identity():
    raw = _ntag(read=1) + b"Unknown synthetic field: private\n"
    result, identity = F._inspect_nfc_bound(raw, deadline=end())
    assert identity is not None
    assert result["status"] == "partial"
    assert set(result["coverage"]["truncated_reasons"]) == {"unknown_field", "partial_read_mapping_unknown"}
    assert F.diff_nfc(raw, raw, deadline=end())["summary"]["pages_compared"] == 0


@pytest.mark.parametrize("change", [
    {"probe_identity_match": False}, {"probe_identity_match": 1}, {"version_crc_valid": False},
    {"scratch_cleanup_confirmed": False}, {"probe_size": True}, {"probe_size": 4097},
    {"probe_sha256": "private"}, {"session_id": "private\n"},
    {"reader_binding": {}}, {"reader_binding": {"backend": "posix-tty", "lock_key": "x", "device_id": "d", "scope_keys": ["y"]}},
])
def test_incomplete_observations_cannot_create_scan(setup, change):
    rt, case = setup
    with pytest.raises(PwehError) as exc:
        N.record_flipper_scan(rt, case, observation(**change), deadline=end())
    assert "private" not in str(exc.value)
    assert rt.provenance.entries(case) == []


@pytest.mark.parametrize("field,value", [("uid", b"ABCD"), ("atqa_msb", b"\0"), ("sak", b"\x08"),
    ("mifare_version", bytes(8)), ("mifare_version", None), ("profile", "desfire"), ("profile", "ntag216")])
def test_scan_family_and_identity_are_checked_again(setup, field, value):
    rt, case = setup
    obs = observation()
    with pytest.raises(PwehError):
        N.record_flipper_scan(rt, case, replace(obs, identity=replace(obs.identity, **{field: value})), deadline=end())
    assert rt.provenance.entries(case) == []


@pytest.mark.parametrize("field,value", [("uid", b"OTHER01"), ("atqa_msb", b"\x44\0"), ("sak", b"\x08"),
    ("mifare_version", bytes(8)), ("profile", "ntag216")])
def test_file_identity_mismatch_is_fixed(setup, field, value):
    rt, case = setup
    bound = add(rt, case, scan(rt, case))
    identity = replace(observation().identity, profile="ntag213")
    with pytest.raises(PwehError) as exc:
        N.match_file_identity(bound, replace(identity, **{field: value}))
    assert "OTHER01" not in str(exc.value)


def test_iso_file_binding_does_not_claim_page_layout(setup):
    rt, case = setup
    bound = add(rt, case, scan(rt, case))
    raw = ("\n".join(_header()) + "\n").encode()
    _, identity = F._inspect_nfc_bound(raw, deadline=end())
    N.match_file_identity(bound, identity)
    result = F.diff_nfc(raw, raw, deadline=end())
    assert result["status"] == "unsupported"
    assert "no_page_layout" in result["coverage"]["truncated_reasons"]


@pytest.mark.parametrize("mutation", ["source", "fact_kind", "profile", "commit", "flag", "binding", "data_hash", "extra", "seq_bool"])
def test_chain_valid_scan_forgery_is_rejected(setup, mutation):
    rt, case = setup
    ref = scan(rt, case)
    entries = rt.provenance.entries(case)
    row = entries[0]
    if mutation == "source": row["source"]["tool"] = "private"
    elif mutation == "fact_kind": row["fact_kind"] = "other"
    elif mutation == "profile": row["data"]["profile"] = "private"
    elif mutation == "commit": row["data"]["firmware_commit"] = "0" * 40
    elif mutation == "flag": row["data"]["page_read_performed"] = True
    elif mutation == "binding": row["data"]["reader_binding"]["scope_keys"] *= 2
    elif mutation == "data_hash": row["sha256"] = "0" * 64
    elif mutation == "extra": row["data"]["private"] = "SENTINEL"
    rewrite(rt, case, entries, data_hash=mutation != "data_hash")
    if mutation == "seq_bool":
        path = rt.provenance.ledger_path(case)
        path.write_text(path.read_text().replace('"seq":1', '"seq":true'))
    with pytest.raises(PwehError) as exc:
        add(rt, case, ref)
    assert "SENTINEL" not in str(exc.value) and "private" not in str(exc.value)


@pytest.mark.parametrize("mutation", ["scan_seq", "scan_hash", "family", "digest", "policy", "duplicate_scan", "duplicate_tag", "hidden_ref"])
def test_inventory_refs_and_whole_entry_hash_are_authoritative(setup, mutation):
    rt, case = setup
    bound = add(rt, case, scan(rt, case))
    entries = rt.provenance.entries(case)
    row = entries[1]["data"]
    if mutation == "scan_seq": row["scan_seq"] = True
    elif mutation == "scan_hash": row["scan_entry_sha256"] = entries[0]["sha256"]
    elif mutation == "family": row["family"] = "ntag216"
    elif mutation == "digest": row["identity_digest"] = "sha256:" + "0" * 16
    elif mutation == "policy": row["policy_profile"] = "other"
    elif mutation == "duplicate_scan": entries.append(json.loads(json.dumps(entries[0])))
    elif mutation == "duplicate_tag": entries.append(json.loads(json.dumps(entries[1])))
    else:
        entries.append(json.loads(json.dumps(entries[0])))
        entries[-1]["fact_kind"] = "different"
    rewrite(rt, case, entries)
    with pytest.raises(PwehError):
        N.resolve_inventory(rt, case, bound.tag_ref, deadline=end())


def test_cache_never_authorizes_and_other_case_cannot_reuse_scan(setup, auth):
    rt, case = setup
    ref = scan(rt, case)
    other = rt.cases.create(title="다른 합성 NFC", authorization=auth, case_id="nfc-other")
    (other.dir / "nfc" / "inventory.json").write_text(json.dumps({"scan_ref": ref.scan_ref, "tag_ref": "NT-" + "a" * 32}))
    with pytest.raises(PwehError): add(rt, other, ref)
    with pytest.raises(PwehError): N.resolve_inventory(rt, other, "NT-" + "a" * 32, deadline=end())
    bound = add(rt, case, ref)
    (case.dir / "nfc" / "inventory.json").unlink()
    assert N.resolve_inventory(rt, case, bound.tag_ref, deadline=end()).tag_ref == bound.tag_ref


def test_cache_recent32_is_descending_and_reports_truncation(setup):
    rt, case = setup
    for _ in range(33):
        add(rt, case, scan(rt, case))
    cache = json.loads((case.dir / "nfc" / "inventory.json").read_bytes())
    assert cache["total_inventory_count"] == 33 and cache["truncated"] is True
    assert len(cache["entries"]) == 32
    assert [v["source"]["inventory_seq"] for v in cache["entries"]] == list(range(66, 2, -2))
    assert "53594e54483031" not in json.dumps(cache)


@pytest.mark.parametrize("failure", ["cache", "late_cancel"])
def test_committed_inventory_survives_auxiliary_failure(setup, monkeypatch, failure):
    rt, case = setup
    ref = scan(rt, case)
    cancelled = [False]
    if failure == "cache":
        def fail(*a, **kw): raise OSError("PRIVATE")
        monkeypatch.setattr(N, "_write_cache", fail)
    else:
        original = rt.provenance.record_device_fact
        def late(*a, **kw):
            result = original(*a, **kw)
            cancelled[0] = True
            return result
        monkeypatch.setattr(rt.provenance, "record_device_fact", late)
    bound = N.add_inventory(rt, case, ref.scan_ref, deadline=end(), cancel=lambda: cancelled[0])
    assert bound.warnings == ("inventory_cache_write_failed",)
    assert len(rt.provenance.entries(case)) == 2
    assert N.resolve_inventory(rt, case, bound.tag_ref, deadline=end()).tag_ref == bound.tag_ref


@pytest.mark.parametrize("operation", ["scan", "inventory", "inventory_cache"])
def test_provenance_close_warning_keeps_masked_committed_ref(setup, monkeypatch, operation):
    from pweh.schemas import validate
    rt, case = setup
    rt.provenance.record_device_fact(case, "synthetic", {"value": 1}, {"server": "test", "tool": "test"})
    ref = scan(rt, case) if operation != "scan" else None
    inode = rt.provenance.ledger_path(case).stat().st_ino
    original = os.close
    failed = [False]
    def close(fd):
        current = os.fstat(fd).st_ino
        original(fd)
        if current == inode and not failed[0]:
            failed[0] = True
            raise OSError("SYNTHETIC_CLOSE_PRIVATE")
    # inventory의 첫 조회는 정상, append의 held fd 정리만 실패시킨다.
    original_append = rt.provenance._append
    def append(*args, **kwargs):
        with monkeypatch.context() as scoped:
            scoped.setattr(os, "close", close)
            return original_append(*args, **kwargs)
    monkeypatch.setattr(rt.provenance, "_append", append)
    if operation == "inventory_cache":
        def cache_fail(*args): raise OSError("SYNTHETIC_CACHE_PRIVATE")
        monkeypatch.setattr(N, "_write_cache", cache_fail)
    result = scan(rt, case) if ref is None else add(rt, case, ref)
    expected = ("provenance_close_unconfirmed",)
    if operation == "inventory_cache": expected += ("inventory_cache_write_failed",)
    assert result.warnings == expected
    projection = result.to_dict()
    validate("nfc-scan" if operation == "scan" else "nfc-inventory", projection)
    assert "PRIVATE" not in json.dumps(projection)
    assert len(rt.provenance.entries(case)) == (2 if operation == "scan" else 3)


def test_parallel_add_is_idempotent_inside_same_ledger_lock(setup):
    rt, case = setup
    ref = scan(rt, case)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        values = list(pool.map(lambda _: add(rt, case, ref).tag_ref, range(4)))
    assert len(set(values)) == 1
    assert len(rt.provenance.entries(case)) == 2


def test_final_checked_append_rejects_changed_scan(setup, monkeypatch):
    rt, case = setup
    ref = scan(rt, case)
    original = rt.provenance.record_device_fact
    def changed(*args, **kw):
        entries = rt.provenance.entries(case)
        entries[0]["data"]["session_id"] = "changed-synthetic"
        rewrite(rt, case, entries)
        return original(*args, **kw)
    monkeypatch.setattr(rt.provenance, "record_device_fact", changed)
    with pytest.raises(PwehError): add(rt, case, ref)
    assert len(rt.provenance.entries(case)) == 1


@pytest.mark.parametrize("cancel,deadline,code", [(lambda: True, None, "cancelled"),
    (lambda: 1, None, "nfc_provenance_invalid"), (None, -1, "time_limit"), (None, float("nan"), "nfc_input_invalid")])
def test_cancel_deadline_callback_fail_closed(setup, cancel, deadline, code):
    rt, case = setup
    with pytest.raises(PwehError) as exc:
        N.record_flipper_scan(rt, case, observation(), deadline=end() if deadline is None else deadline, cancel=cancel)
    assert exc.value.code == code
    assert rt.provenance.entries(case) == []


def test_masked_projection_matches_registered_schemas(setup):
    from pweh.schemas import validate
    rt, case = setup
    ref = scan(rt, case)
    validate("nfc-scan", ref.to_dict())
    validate("nfc-inventory", add(rt, case, ref).to_dict())
