"""출처 원장(pweh.provenance) 테스트: 해시 체인·fail closed·가져온 파일의 증명·producer 무시."""

from __future__ import annotations

import hashlib
import json
import threading

import pytest

from pweh.errors import PwehError, ValidationFailed
from pweh.provenance import (
    CHAIN_BROKEN,
    PROVENANCE_IMPORT_QUESTIONS,
    READ_MISMATCH,
    ProvenanceError,
    _genesis,
    parse_ledger,
    provenance_import_target,
)
from pweh.runtime import get_runtime

SRC = {"server": "esp-mcp", "tool": "esp_read_flash_start", "port": "COM3", "chip": "ESP32-S3", "mac": "f4:12:fa:12:34:56",
       "esptool_version": "5.4.0", "verify": "double-read", "match": True}
FACT_SRC = {"server": "esp-mcp", "tool": "esp_security_info", "port": "COM3", "chip": "ESP32-S3"}


def _case(rt, auth, cid: str = "prov-case"):
    return rt.cases.create(title="출처 시험", authorization=auth, case_id=cid)


def _write(case, rel: str, data: bytes) -> str:
    p = case.resolve_path(rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _ledger(workspace, cid: str):
    return workspace["state_dir"] / "provenance" / f"{cid}.jsonl"


def test_device_read_trusted_until_file_changes(workspace, auth):
    rt = get_runtime("test")
    case = _case(rt, auth)
    sha = _write(case, "dumps/fw.bin", b"\x01" * 4096)
    e = rt.provenance.record_device_read(case, "dumps/fw.bin", SRC, {"role": "primary"}, sha256=sha)
    assert e["seq"] == 1 and e["kind"] == "device-read" and e["path"] == "dumps/fw.bin" and e["sha256"] == sha
    assert e["prev"] == _genesis(case.id) and e["source"]["server"] == "esp-mcp" and e["extra"] == {"role": "primary"}
    ledger = _ledger(workspace, case.id)
    assert ledger.is_file() and (ledger.stat().st_mode & 0o777) == 0o600
    v = rt.provenance.verify(case, "dumps/fw.bin")
    assert v["trusted"] is True and v["kind"] == "device-read" and v["reason"] == "device-read" and v["record"]["seq"] == 1
    assert rt.provenance.verify(case, str(case.dir / "dumps" / "fw.bin"))["trusted"]  # 케이스 안 절대 경로도 같다
    # 기록한 뒤 바뀐 파일은 신뢰하지 않는다
    (case.dir / "dumps" / "fw.bin").write_bytes(b"\x02" * 4096)
    v = rt.provenance.verify(case, "dumps/fw.bin")
    assert v["trusted"] is False and v["reason"] == "sha256-mismatch" and v["kind"] == "device-read"
    (case.dir / "dumps" / "fw.bin").unlink()
    assert rt.provenance.verify(case, "dumps/fw.bin")["reason"] == "file-missing"
    _write(case, "dumps/other.bin", b"x")
    assert rt.provenance.verify(case, "dumps/other.bin")["reason"] == "not-recorded"
    with pytest.raises(PwehError):
        rt.provenance.verify(case, "/etc/passwd")
    with pytest.raises(PwehError):
        rt.provenance.verify(case, "../../etc/passwd")


def test_read_hash_must_match_file_at_record_time(workspace, auth):
    rt = get_runtime("test")
    case = _case(rt, auth)
    _write(case, "dumps/a.bin", b"swapped content")
    with pytest.raises(ProvenanceError) as ei:
        rt.provenance.record_device_read(case, "dumps/a.bin", SRC, sha256=hashlib.sha256(b"what esptool wrote").hexdigest())
    assert ei.value.code == "provenance_sha256_mismatch"
    assert rt.provenance.entries(case) == []
    with pytest.raises(ValidationFailed):
        rt.provenance.record_device_read(case, "dumps/missing.bin", SRC)
    with pytest.raises(ValidationFailed):
        rt.provenance.record_device_read(case, "dumps/a.bin", {"server": "esp-mcp"})  # tool 없음
    with pytest.raises(ValidationFailed):
        rt.provenance.record_device_read(case, "dumps/a.bin", SRC, sha256="not-a-hash")


def _three_entries(rt, case):
    s1 = _write(case, "dumps/r1.bin", b"A" * 100)
    s2 = _write(case, "dumps/r2.bin", b"A" * 100)
    rt.provenance.record_device_read(case, "dumps/r1.bin", SRC, sha256=s1)
    rt.provenance.record_device_read(case, "dumps/r2.bin", SRC, sha256=s2)
    rt.provenance.record_device_fact(case, "esp-security-info", {"flash_encryption": False, "secure_download_mode": False}, FACT_SRC)


def _edit_field(lines):
    e = json.loads(lines[0])
    e["path"] = "dumps/r2.bin"
    lines[0] = json.dumps(e, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return lines


def _edit_kind(lines):  # 가져온 파일 항목을 device-read 로 바꾸는 위조
    e = json.loads(lines[1])
    e["source"]["server"] = "case-mcp"
    lines[1] = json.dumps(e, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return lines


def _insert_forged(lines):  # 그럴듯한 device-read 줄을 중간에 끼워 넣기 (prev 를 앞 줄 해시로 맞춰도 뒤가 깨진다)
    first = json.loads(lines[0])
    forged = {**first, "path": "dumps/downloaded.bin", "seq": 2,
              "prev": hashlib.sha256(lines[0].encode()).hexdigest()}
    return [lines[0], json.dumps(forged, sort_keys=True, ensure_ascii=False, separators=(",", ":"))] + lines[1:]


MUTATIONS = {
    "edit-field": _edit_field,
    "edit-source": _edit_kind,
    "delete-middle": lambda lines: [lines[0], lines[2]],
    "reorder": lambda lines: [lines[1], lines[0], lines[2]],
    "garbage-line": lambda lines: lines[:1] + ["{not json"] + lines[1:],
    "pretty-printed": lambda lines: [json.dumps(json.loads(lines[0]), indent=1).replace("\n", " ")] + lines[1:],
    "insert-forged": _insert_forged,
    "blank-line": lambda lines: lines[:1] + [""] + lines[1:],
}


@pytest.mark.parametrize("mutation", sorted(MUTATIONS))
def test_tampered_ledger_fails_closed(workspace, auth, mutation):
    rt = get_runtime("test")
    case = _case(rt, auth)
    _three_entries(rt, case)
    assert rt.provenance.verify(case, "dumps/r1.bin")["trusted"] and rt.provenance.verify_chain(case)["ok"]
    ledger = _ledger(workspace, case.id)
    lines = ledger.read_text(encoding="utf-8").split("\n")[:-1]
    ledger.write_text("\n".join(MUTATIONS[mutation](lines)) + "\n", encoding="utf-8")
    for rel in ("dumps/r1.bin", "dumps/r2.bin"):
        v = rt.provenance.verify(case, rel)
        assert v["trusted"] is False and v["reason"] == CHAIN_BROKEN and v["record"] is None, (mutation, v)
    assert rt.provenance.verify_chain(case)["ok"] is False
    with pytest.raises(ProvenanceError):
        rt.provenance.entries(case)
    with pytest.raises(ProvenanceError):
        rt.provenance.facts(case)
    # 깨진 원장에는 덧붙이지 않는다
    s3 = _write(case, "dumps/r3.bin", b"C")
    before = ledger.read_bytes()
    with pytest.raises(ProvenanceError):
        rt.provenance.record_device_read(case, "dumps/r3.bin", SRC, sha256=s3)
    assert ledger.read_bytes() == before


def test_truncated_last_line_and_foreign_ledger_are_broken(workspace, auth):
    rt = get_runtime("test")
    a = _case(rt, auth, "prov-a")
    b = _case(rt, auth, "prov-b")
    _three_entries(rt, a)
    raw = _ledger(workspace, a.id).read_bytes()
    assert parse_ledger(a.id, raw)[1] is None
    assert parse_ledger(a.id, raw[:-1])[1]  # 마지막 줄바꿈이 없으면(잘린 쓰기) 깨짐
    assert parse_ledger(a.id, raw[:-10])[1]
    # 다른 케이스의 원장을 복사해도(같은 파일·같은 내용) 시작값·case_id 가 달라 깨진다
    for rel in ("dumps/r1.bin", "dumps/r2.bin"):
        p = a.dir / rel
        _write(b, rel, p.read_bytes())
    _ledger(workspace, b.id).write_bytes(raw)
    v = rt.provenance.verify(b, "dumps/r1.bin")
    assert v["trusted"] is False and v["reason"] == CHAIN_BROKEN


def test_import_needs_provenance_import_attestation(workspace, auth):
    rt = get_runtime("test")
    case = _case(rt, auth)
    other = _case(rt, auth, "prov-other")
    sha = _write(case, "dumps/vendor.bin", b"vendor image")
    e = rt.provenance.record_import(case, "dumps/vendor.bin", {"server": "case-mcp", "tool": "case_import_file",
                                                               "imported_from": "/tmp/vendor.bin"}, sha256=sha)
    assert e["kind"] == "imported-unattested"
    v = rt.provenance.verify(case, "dumps/vendor.bin")
    assert v["trusted"] is False and v["kind"] == "imported-unattested" and v["reason"] == "imported-unattested"
    st = rt.attestations
    qs = list(PROVENANCE_IMPORT_QUESTIONS)
    answers = {"source_known": "yes", "how_obtained": "SOIC 클립 + CH341A"}
    # 다른 sha256 에 대한 증명, 다른 케이스의 같은 sha256 증명은 쓸 수 없다
    k, s, b = provenance_import_target(case.id, "ab" * 32)
    st.decide(st.request(k, s, b, qs, case.id)["id"], answers, via="cli-tty")
    k, s, b = provenance_import_target(other.id, sha)
    st.decide(st.request(k, s, b, qs, other.id)["id"], answers, via="cli-tty")
    assert rt.provenance.verify(case, "dumps/vendor.bin")["trusted"] is False
    # 같은 케이스·같은 sha256 의 증명이 있어도 '예'가 아니면(거부) 신뢰하지 않는다
    k, s, b = provenance_import_target(case.id, sha)
    denied = st.request(k, s, b, qs, case.id)
    st.decide(denied["id"], {"source_known": "no"}, via="cli-tty")
    assert rt.provenance.verify(case, "dumps/vendor.bin")["trusted"] is False
    good = st.request(k, s, b, qs, case.id)
    st.decide(good["id"], answers, via="cli-tty")
    v = rt.provenance.verify(case, "dumps/vendor.bin")
    assert v["trusted"] is True and v["reason"] == "imported-attested" and v["attestation_id"] == good["id"]
    st.revoke(good["id"])
    assert rt.provenance.verify(case, "dumps/vendor.bin")["trusted"] is False


def test_case_json_producer_is_ignored(workspace, auth):
    rt = get_runtime("test")
    case = _case(rt, auth)
    _write(case, "dumps/esp-flash.bin", b"from the internet")
    # 에이전트가 producer 를 'esp-mcp' 로 등록해도 원장에 없으면 신뢰하지 않는다
    case.register_artifact("dumps/esp-flash.bin", kind="flash-dump", producer="esp-mcp",
                           extra={"method": "esptool-read-flash", "role": "primary"})
    v = rt.provenance.verify(case, "dumps/esp-flash.bin")
    assert v["trusted"] is False and v["reason"] == "not-recorded"
    # 가져온 파일의 case.json producer 를 고쳐도 마찬가지
    src = case.dir.parent / "outside.bin"
    src.write_bytes(b"imported")
    art = case.import_file(src, "dumps", kind="flash-dump", producer="case-mcp")
    rt.provenance.record_import(case, art["path"], {"server": "case-mcp", "tool": "case_import_file"}, sha256=art["sha256"])
    meta = json.loads(case.meta_path.read_text(encoding="utf-8"))
    for a in meta["artifacts"]:
        a["producer"] = "esp-mcp"
        a.setdefault("extra", {})["provenance"] = "device-read"
    case.meta_path.write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    assert rt.provenance.verify(case, art["path"])["reason"] == "imported-unattested"


def test_deleted_dump_replaced_by_import_is_untrusted(workspace, auth, tmp_path):
    rt = get_runtime("test")
    case = _case(rt, auth)
    sha = _write(case, "dumps/esp-flash.bin", b"real device bytes")
    rt.provenance.record_device_read(case, "dumps/esp-flash.bin", SRC, sha256=sha)
    assert rt.provenance.verify(case, "dumps/esp-flash.bin")["trusted"]
    (case.dir / "dumps" / "esp-flash.bin").unlink()
    src = tmp_path / "esp-flash.bin"
    src.write_bytes(b"downloaded dump")
    art = case.import_file(src, "dumps", kind="flash-dump", producer="case-mcp")
    rt.provenance.record_import(case, art["path"], {"server": "case-mcp", "tool": "case_import_file"}, sha256=art["sha256"])
    v = rt.provenance.verify(case, "dumps/esp-flash.bin")
    assert v["trusted"] is False and v["kind"] == "imported-unattested"
    # 같은 내용으로 되돌려 놓아도 마지막 항목(가져온 파일)과 해시가 달라 신뢰하지 않는다
    (case.dir / "dumps" / "esp-flash.bin").write_bytes(b"real device bytes")
    assert rt.provenance.verify(case, "dumps/esp-flash.bin")["reason"] == "sha256-mismatch"


def test_device_facts_are_stored_in_ledger(workspace, auth):
    rt = get_runtime("test")
    case = _case(rt, auth)
    data = {"status": "ok", "flash_encryption": True, "secure_boot": False, "key_blocks": [{"block": "BLOCK_KEY0", "purpose": "XTS_AES_128_KEY"}]}
    e = rt.provenance.record_device_fact(case, "esp-security-info", data, FACT_SRC)
    assert e["kind"] == "device-fact" and e["path"] is None and e["data"] == data
    assert e["sha256"] == hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    rt.provenance.record_device_fact(case.id, "esp-chip-info", {"chip": "ESP32-S3", "mac": "f4:12:fa:12:34:56"}, FACT_SRC)
    assert [f["fact_kind"] for f in rt.provenance.facts(case)] == ["esp-security-info", "esp-chip-info"]
    assert rt.provenance.facts(case, "esp-chip-info")[0]["data"]["mac"] == "f4:12:fa:12:34:56"
    with pytest.raises(ValidationFailed):
        rt.provenance.record_device_fact(case, "", data, FACT_SRC)
    with pytest.raises(ValidationFailed):
        rt.provenance.record_device_fact(case, "x", {"v": {1, 2}}, FACT_SRC)
    with pytest.raises(ValidationFailed):
        rt.provenance.record_device_fact("../escape", "x", data, FACT_SRC)


def test_concurrent_appends_keep_one_chain(workspace, auth):
    rt = get_runtime("test")
    case = _case(rt, auth)
    errors: list[BaseException] = []

    def worker(n: int) -> None:
        try:
            for i in range(10):
                rt.provenance.record_device_fact(case, "esp-chip-info", {"worker": n, "i": i}, FACT_SRC)
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    chain = rt.provenance.verify_chain(case)
    assert chain == {"ok": True, "count": 40}
    assert [e["seq"] for e in rt.provenance.entries(case)] == list(range(1, 41))


def test_mismatched_double_read_is_recorded_but_not_trusted(workspace, auth):
    """device-read 는 출처이지 무결성이 아니다: 이중 읽기가 어긋난 덤프(source.match=false)는 기록되지만 verify 는 신뢰하지 않는다.
    검증하지 않은 단일 읽기(match=null)는 출처로 신뢰한다 — 무결성이 필요한 쪽은 record.source.verify 를 따로 본다."""
    rt = get_runtime("test")
    case = _case(rt, auth)
    bad = {**SRC, "match": False}
    sha1 = _write(case, "dumps/a.bin", b"\x01" * 64)
    sha2 = _write(case, "dumps/a.read2.bin", b"\x01" * 63 + b"\x02")
    rt.provenance.record_device_read(case, "dumps/a.bin", bad, {"role": "primary"}, sha256=sha1)
    rt.provenance.record_device_read(case, "dumps/a.read2.bin", bad, {"role": "verification-read"}, sha256=sha2)
    for rel in ("dumps/a.bin", "dumps/a.read2.bin"):
        v = rt.provenance.verify(case, rel)
        assert v["trusted"] is False and v["kind"] == "device-read" and v["reason"] == READ_MISMATCH, v
    sha3 = _write(case, "dumps/b.bin", b"\x03" * 64)
    rt.provenance.record_device_read(case, "dumps/b.bin", {**SRC, "verify": "none", "match": None}, sha256=sha3)
    v = rt.provenance.verify(case, "dumps/b.bin")
    assert v["trusted"] is True and v["reason"] == "device-read" and v["record"]["source"]["verify"] == "none"


def test_state_dirs_are_private_even_with_open_umask(workspace, auth):
    """출처 원장·증명 디렉터리는 umask 와 무관하게 0700 이다(솔트 디렉터리와 같은 규칙)."""
    import os

    rt = get_runtime("test")
    case = _case(rt, auth)
    old = os.umask(0)
    try:
        sha = _write(case, "dumps/fw.bin", b"\x01" * 16)
        rt.provenance.record_device_read(case, "dumps/fw.bin", SRC, sha256=sha)
        rt.attestations.request("console-offline", {"console": "SN-U"}, {"scope": "case", "case_id": case.id},
                                [{"id": "offline", "text": "네트워크를 끊었다", "type": "yesno", "expected": "yes"}], case.id)
        rt.secret_digest(case.id, "pin")
    finally:
        os.umask(old)
    for sub in ("provenance", "attestations", "salts"):
        assert (workspace["state_dir"] / sub).stat().st_mode & 0o777 == 0o700, sub


def test_verify_with_data_hashes_the_given_bytes_and_never_opens_the_path(workspace, auth, monkeypatch):
    """verify(data=…): sha256 을 호출자가 이미 읽은 바이트에서 계산하고 경로로 파일을 열지 않는다(존재 확인도 하지 않는다).
    emu_start 가 safeio 로 한 번 읽은 펌웨어를 확인한 그대로 실행하게 하려는 것 — 판정은 '이 바이트가 그 경로의 마지막 원장 항목과 같은가'."""
    import os

    import pweh.provenance as provenance_mod

    rt = get_runtime("test")
    case = _case(rt, auth)
    original = b"\x10" * 4096
    sha = _write(case, "dumps/fw.bin", original)
    rt.provenance.record_device_read(case, "dumps/fw.bin", SRC, sha256=sha)

    def no_open(*_a, **_k):
        raise AssertionError("verify(data=…) 가 경로로 파일을 해시했다")

    monkeypatch.setattr(provenance_mod, "sha256_file", no_open)
    v = rt.provenance.verify(case, "dumps/fw.bin", data=original)
    assert v["trusted"] is True and v["reason"] == "device-read" and v["sha256"] == sha and v["path"] == "dumps/fw.bin", v
    assert v["record"]["seq"] == 1 and v["kind"] == "device-read"
    assert rt.provenance.verify(case, str(case.dir / "dumps" / "fw.bin"), data=original)["trusted"]  # 케이스 안 절대 경로도 같다
    # bytes 같은 객체(bytearray·memoryview, 이어지지 않은 memoryview 포함)
    for buf in (bytearray(original), memoryview(original), memoryview(b"\x10\x00" * 4096)[::2]):
        assert rt.provenance.verify(case, "dumps/fw.bin", data=buf)["sha256"] == sha
    # 디스크의 파일이 바뀌거나 없어지거나 FIFO 로 바뀌어도 판정은 넘긴 바이트로 한다(열지 않으므로 FIFO 앞에서 멈추지 않는다)
    (case.dir / "dumps" / "fw.bin").write_bytes(b"\x20" * 4096)
    assert rt.provenance.verify(case, "dumps/fw.bin", data=original)["trusted"] is True
    (case.dir / "dumps" / "fw.bin").unlink()
    assert rt.provenance.verify(case, "dumps/fw.bin", data=original)["trusted"] is True
    os.mkfifo(case.dir / "dumps" / "fw.bin")
    assert rt.provenance.verify(case, "dumps/fw.bin", data=original)["trusted"] is True
    # 원장과 다른 바이트는 불신 (sha256 은 넘긴 바이트의 것)
    other = b"\x20" * 4096
    v = rt.provenance.verify(case, "dumps/fw.bin", data=other)
    assert v["trusted"] is False and v["reason"] == "sha256-mismatch" and v["sha256"] == hashlib.sha256(other).hexdigest()
    # 원장에 없는 경로, 빈 바이트
    assert rt.provenance.verify(case, "dumps/never.bin", data=original)["reason"] == "not-recorded"
    assert rt.provenance.verify(case, "dumps/fw.bin", data=b"")["reason"] == "sha256-mismatch"
    # 경로 규칙과 인자 형식은 그대로
    with pytest.raises(PwehError):
        rt.provenance.verify(case, "/etc/passwd", data=original)
    with pytest.raises(PwehError):
        rt.provenance.verify(case, "../../etc/passwd", data=original)
    for bad in ("text", 123, [1, 2]):
        with pytest.raises(ValidationFailed):
            rt.provenance.verify(case, "dumps/fw.bin", data=bad)  # type: ignore[arg-type]


def test_verify_with_data_keeps_the_trust_rules(workspace, auth):
    """data= 로 불러도 신뢰 규칙은 같다: 가져온 파일은 같은 바이트(sha256)·같은 케이스의 provenance-import 증명이 있어야 하고,
    이중 읽기 불일치는 불신, 깨진 원장은 무엇보다 먼저 불신."""
    rt = get_runtime("test")
    case = _case(rt, auth)
    blob = b":00000001FF\n"
    sha = _write(case, "dumps/fw.hex", blob)
    rt.provenance.record_import(case, "dumps/fw.hex", {"server": "case-mcp", "tool": "case_import_file"}, sha256=sha)
    v = rt.provenance.verify(case, "dumps/fw.hex", data=blob)
    assert v["trusted"] is False and v["reason"] == "imported-unattested" and v["sha256"] == sha
    k, s, b = provenance_import_target(case.id, sha)
    att = rt.attestations.request(k, s, b, list(PROVENANCE_IMPORT_QUESTIONS), case.id)
    rt.attestations.decide(att["id"], {"source_known": "yes", "how_obtained": "avrdude 로 내 보드에서 읽음"}, via="cli-tty")
    v = rt.provenance.verify(case, "dumps/fw.hex", data=blob)
    assert v["trusted"] is True and v["reason"] == "imported-attested" and v["attestation_id"] == att["id"], v
    assert rt.provenance.verify(case, "dumps/fw.hex", data=blob + b"\n")["reason"] == "sha256-mismatch"
    bad = b"\x01" * 64
    sha_bad = _write(case, "dumps/bad.bin", bad)
    rt.provenance.record_device_read(case, "dumps/bad.bin", {**SRC, "match": False}, sha256=sha_bad)
    assert rt.provenance.verify(case, "dumps/bad.bin", data=bad)["reason"] == READ_MISMATCH
    ledger = _ledger(workspace, case.id)
    ledger.write_bytes(ledger.read_bytes()[:-1])  # 잘린 마지막 줄
    v = rt.provenance.verify(case, "dumps/fw.hex", data=blob)
    assert v["trusted"] is False and v["reason"] == CHAIN_BROKEN and v["record"] is None and v["sha256"] is None
