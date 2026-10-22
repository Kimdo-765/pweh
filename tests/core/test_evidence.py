"""pweh.evidence: 보관 기록 해시 체인, 이미징 로그 해석, 입력 검사, 지문, 경로 판정."""

from __future__ import annotations

import errno
import hashlib
import json
import logging
import os
import shutil
import stat
import threading
import time
from pathlib import Path

import pytest

from pweh import evidence as E
from pweh import safeio
from pweh.case import CaseStore
from pweh.errors import ValidationFailed
from pweh.safety.attestations import canonical_json


@pytest.fixture
def case(workspace, auth):
    return CaseStore(workspace["cases_dir"]).create(title="SD 카드", authorization=auth, case_id="sdcase")


def test_custody_chain_append_and_verify(case):
    log = E.CustodyLog(case)
    assert log.verify() == {"ok": True, "count": 0, "head": None}
    a = log.append("intake", evidence_id="EV-0001", data={"x": 1})
    b = log.append("verify", evidence_id="EV-0001", data={"result": "match"})
    assert (a["seq"], b["seq"]) == (1, 2) and b["prev"] == a["hash"]
    v = log.verify()
    assert v["ok"] and v["count"] == 2 and v["head"] == b["hash"]
    st = E.replay_status(log.entries(), "EV-0001")
    assert st["intake"] and st["status"] == "ok" and st["last_verify"]["result"] == "match"


@pytest.mark.parametrize("mutate,why", [
    (lambda lines: lines[:-1] + [lines[-1][:-5]], "잘림"),
    (lambda lines: [lines[0].replace('"x":1', '"x":2')] + lines[1:], "prev"),
    (lambda lines: [json.dumps(json.loads(lines[0]), indent=1).replace("\n", "")] + lines[1:], "정규화"),
    (lambda lines: lines[1:], "seq"),
    (lambda lines: lines + [lines[-1]], "seq"),
])
def test_custody_tamper_is_fail_closed(case, mutate, why):
    log = E.CustodyLog(case)
    log.append("intake", evidence_id="EV-0001", data={"x": 1})
    log.append("verify", evidence_id="EV-0001", data={"result": "match"})
    lines = log.path.read_text(encoding="utf-8").split("\n")[:-1]
    new = mutate(lines)
    log.path.write_text("\n".join(new) + ("\n" if not new[-1].endswith("…") else ""), encoding="utf-8")
    v = log.verify()
    assert not v["ok"] and v["count"] == 0, why
    with pytest.raises(E.EvidenceError) as ei:
        log.append("note", evidence_id=None, data={})
    assert ei.value.code == "custody_broken"
    with pytest.raises(E.EvidenceError):
        log.entries()


def test_custody_copied_from_another_case_breaks(workspace, auth, case):
    other = CaseStore(workspace["cases_dir"]).create(title="다른", authorization=auth, case_id="othercase")
    E.CustodyLog(other).append("intake", evidence_id="EV-0001", data={})
    E.ensure_forensics_dir(case)
    E.CustodyLog(case).path.write_bytes(E.CustodyLog(other).path.read_bytes())
    assert not E.CustodyLog(case).verify()["ok"], "시작값(genesis)이 케이스 id 에 묶여 있다"


def test_custody_rejects_unknown_event_and_bad_ids(case):
    log = E.CustodyLog(case)
    with pytest.raises(ValidationFailed):
        log.append("delete", evidence_id=None, data={})
    with pytest.raises(ValidationFailed):
        log.append("note", evidence_id="../EV-1", data={})
    with pytest.raises(ValidationFailed):
        log.append("note", evidence_id=None, data={}, actor="root")
    # 정규화 JSON 이지만 사건 종류가 잘못된 줄
    E.ensure_forensics_dir(case)
    entry = {"schema": E.SCHEMA_CUSTODY, "seq": 1, "ts": "2026-01-01T00:00:00Z", "case_id": case.id, "event": "wipe",
             "evidence_id": None, "actor": "server", "data": {}, "prev": hashlib.sha256(f"pweh-custody:{case.id}".encode()).hexdigest()}
    log.path.write_text(canonical_json(entry) + "\n", encoding="utf-8")
    assert not log.verify()["ok"]


FTK = """Created By AccessData® FTK® Imager 4.7.1.2
[Computed Hashes]
 MD5 checksum:    {md5}
 SHA1 checksum:   {sha1}
Image Verification Results:
 MD5 checksum:    {md5} : verified
 SHA1 checksum:   {sha1} : verified
"""


def test_imaging_log_formats_and_comparison():
    data = b"sd-card-image" * 100
    h = {a: hashlib.new(a, data).hexdigest() for a in E.HASH_ALGORITHMS}
    ftk = E.parse_imaging_log(FTK.format(**h))
    assert ftk["tool"] == "ftk-imager" and ftk["hashes"] == {"md5": [h["md5"]], "sha1": [h["sha1"]]} and not ftk["conflicts"]
    assert E.compare_log_hashes(ftk, h) == {"status": "match", "details": {"md5": "match", "sha1": "match"}}
    bad = E.parse_imaging_log(FTK.format(md5="0" * 32, sha1=h["sha1"]))
    assert E.compare_log_hashes(bad, h)["status"] == "mismatch"
    dc3dd = E.parse_imaging_log(f"dc3dd 7.2.646\n   {h['md5']} (md5)\n   {h['sha256']} (sha256)\n")
    assert dc3dd["tool"] == "dc3dd" and dc3dd["hashes"]["sha256"] == [h["sha256"]]
    ewf = E.parse_imaging_log(f"ewfacquire 20140807\nMD5 hash calculated over data:\t\t{h['md5']}\n")
    assert ewf["tool"] == "ewfacquire" and ewf["hashes"]["md5"] == [h["md5"]]
    conflict = E.parse_imaging_log(f"MD5: {h['md5']}\nMD5: {'1' * 32}\n")
    assert conflict["conflicts"] == ["md5"]
    assert E.compare_log_hashes(E.parse_imaging_log("no hashes here"), h)["status"] == "no-hashes"
    # 길이가 맞지 않는 값은 버린다 (SHA1 이라면서 32자)
    assert E.parse_imaging_log(f"SHA1: {h['md5']}\n")["hashes"] == {}


def test_check_image_source_rejects_non_files(tmp_path):
    with pytest.raises(ValidationFailed):
        E.check_image_source("/dev/null")
    with pytest.raises(ValidationFailed):
        E.check_image_source(str(tmp_path))
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValidationFailed):
        E.check_image_source(str(fifo))
    empty = tmp_path / "empty.img"
    empty.write_bytes(b"")
    with pytest.raises(ValidationFailed):
        E.check_image_source(str(empty))
    e01 = tmp_path / "card.E01"
    e01.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 100)
    with pytest.raises(ValidationFailed) as ei:
        E.check_image_source(str(e01))
    assert "E01" in ei.value.message
    for raw in ("\\\\.\\PhysicalDrive1", "//./E:", "\\\\?\\Volume{x}"):
        with pytest.raises(ValidationFailed):
            E.check_image_source(raw)
    link = tmp_path / "null-link"
    link.symlink_to("/dev/null")
    with pytest.raises(ValidationFailed):
        E.check_image_source(str(link))
    ok = tmp_path / "card.img"
    ok.write_bytes(b"\x00" * 1024)
    assert E.check_image_source(str(ok)) == ok.resolve()
    with pytest.raises(ValidationFailed, match="NUL"):
        E.check_image_source(str(ok) + "\x00.img")


def test_open_image_source_reads_only_the_opened_object(tmp_path):
    """한 번 연 fd 가 접수의 근거다: 그 뒤 경로가 FIFO 로 바뀌어도 fd 로는 처음 확인한 파일을 읽는다(경로를 다시 열지 않는다)."""
    p = tmp_path / "card.img"
    data = os.urandom(5000)
    p.write_bytes(data)
    link = tmp_path / "link.img"
    link.symlink_to(p)
    fd, st, real = E.open_image_source(str(link))  # 링크는 한 번 풀고, 푼 경로를 일반 파일로만 연다
    try:
        assert real == p.resolve() and st.st_size == 5000
        p.unlink()
        os.mkfifo(p)
        assert safeio.hash_fd(fd, st.st_size)["sha256"] == hashlib.sha256(data).hexdigest()
    finally:
        os.close(fd)
    t0 = time.monotonic()
    with pytest.raises(ValidationFailed):
        E.open_image_source(str(p))  # FIFO 는 열지 않는다
    assert time.monotonic() - t0 < 2


def test_read_imaging_log_refuses_before_reading_and_caps(tmp_path):
    fifo = tmp_path / "log.fifo"
    os.mkfifo(fifo)
    seen: list[Path] = []

    def refuse(p: Path) -> None:
        seen.append(p)
        raise ValidationFailed("케이스 폴더 안")

    t0 = time.monotonic()
    with pytest.raises(ValidationFailed, match="케이스 폴더"):
        E.read_imaging_log(fifo, refuse=refuse)  # 거부 검사는 열기 전에
    assert seen == [Path(os.path.realpath(fifo))]
    with pytest.raises(ValidationFailed):
        E.read_imaging_log(fifo)  # FIFO 는 열지 않는다
    assert time.monotonic() - t0 < 2
    big = tmp_path / "big.txt"
    big.write_bytes(b"a" * (E.IMAGING_LOG_MAX + 1))
    with pytest.raises(ValidationFailed, match="너무 큽니다"):
        E.read_imaging_log(big)
    ok = tmp_path / "ftk.txt"
    ok.write_text("FTK Imager\nMD5: " + "a" * 32 + "\n", encoding="utf-8")
    p, text = E.read_imaging_log(ok)
    assert p == ok.resolve() and "FTK" in text
    with pytest.raises(ValidationFailed, match="NUL"):
        E.read_imaging_log(str(ok) + "\x00")


def test_fingerprint_detects_changes(tmp_path):
    p = tmp_path / "img"
    p.write_bytes(os.urandom(3 << 20))
    fp = E.fingerprint(p)
    os.chmod(p, 0o444)
    assert E.fingerprint_problems(fp, p) == []
    os.chmod(p, 0o644)
    assert any("쓰기 권한" in x for x in E.fingerprint_problems(fp, p))
    data = bytearray(p.read_bytes())
    data[10] ^= 1
    st = p.stat()
    p.write_bytes(bytes(data))
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
    os.chmod(p, 0o444)
    assert "head_sha256 다름" in E.fingerprint_problems(fp, p)


def test_forensics_path_predicates(case, tmp_path):
    fdir = E.ensure_forensics_dir(case)
    (fdir / "recovered").mkdir()
    assert E.is_forensics_path(case, fdir / "recovered" / "x.mp4")
    assert not E.is_forensics_path(case, case.dir / "dumps" / "x.bin")
    link = case.dir / "dumps" / "sneaky"
    link.parent.mkdir(exist_ok=True)
    link.symlink_to(fdir / "recovered")
    assert E.is_forensics_path(case, link), "심볼릭 링크를 풀어 판단한다"
    assert E.contains_forensics_dir(case, case.dir) and not E.contains_forensics_dir(case, case.dir / "dumps")
    cases_root = case.dir.parent
    assert E.under_any_case_forensics(fdir / "images" / "EV-0001" / "x.img", cases_root)
    assert not E.under_any_case_forensics(case.dir / "dumps" / "a.bin", cases_root)
    assert not E.under_any_case_forensics(tmp_path / "elsewhere", cases_root)
    # forensics/ 자체가 케이스 밖을 가리키는 링크여도 그 아래 경로로 부르면 막는다(링크를 풀기 전 경로도 본다)
    other = CaseStore(cases_root).create(title="링크", case_id="linked")
    outside = tmp_path / "outside-forensics"
    outside.mkdir()
    (other.dir / "forensics").symlink_to(outside)
    assert E.under_any_case_forensics(other.dir / "forensics" / "recovered" / "a.mp4", cases_root)


def test_strict_rel_fails_closed_outside_or_through_links(case, tmp_path):
    E.ensure_forensics_dir(case)
    assert E.strict_rel(case, case.dir / "forensics" / "images" / "x") == "forensics/images/x"
    with pytest.raises(E.EvidenceError) as ei:
        E.strict_rel(case, tmp_path / "elsewhere")
    assert ei.value.code == "path_outside_base"
    with pytest.raises(E.EvidenceError):
        E.strict_rel(case, case.dir / ".." / "other")
    outside = tmp_path / "out"
    outside.mkdir()
    (case.dir / "forensics" / "analysis").symlink_to(outside)
    with pytest.raises(E.EvidenceError, match="심볼릭 링크"):
        E.strict_rel(case, case.dir / "forensics" / "analysis" / "fs-list.json")
    with pytest.raises(E.EvidenceError) as ei:
        os.close(E.open_forensics(case, "analysis", create=True))  # 쓰기 위치도 링크를 따르지 않는다
    assert ei.value.code == "path_outside_base" and not any(outside.iterdir())


def test_claim_evidence_id_and_record_roundtrip(case):
    c1 = E.claim_evidence_id(case)
    c2 = E.claim_evidence_id(case)  # c1 이 접수 잠금을 잡고 있으므로 정리(reconcile)가 EV-0001 을 건드리지 않는다
    try:
        ev, ev2 = c1.evidence_id, c2.evidence_id
        assert (ev, ev2) == ("EV-0001", "EV-0002")
        safeio.write_new(c1.dir_fd, "card.img", b"\x01" * 4096, final_mode=0o444)
        img = E.evidence_dir(case, ev) / "card.img"
        hashes = {a: hashlib.new(a, img.read_bytes()).hexdigest() for a in E.HASH_ALGORITHMS}
        rec = {"schema": E.SCHEMA_EVIDENCE, "evidence_id": ev, "case_id": case.id, "stored": {"path": f"forensics/images/{ev}/card.img", "size": 4096},
               "hashes": hashes, "fingerprint": E.fingerprint(img)}
        p = E.write_record(case, ev, rec)
        assert stat.S_IMODE(p.stat().st_mode) == 0o444
        with pytest.raises(FileExistsError):
            E.write_record(case, ev, rec)
        assert E.load_record(case, ev)["hashes"] == hashes
        # 저장 경로가 증거 디렉터리 밖을 가리키는 기록은 거부
        bad = dict(rec, evidence_id=ev2, stored={"path": "dumps/x.bin", "size": 1})
        E.write_record(case, ev2, bad)
        with pytest.raises(E.EvidenceError) as ei:
            E.load_record(case, ev2)
        assert ei.value.code == "integrity_failed"
    finally:
        c1.close()
        c2.close()
    with pytest.raises(ValidationFailed):
        E.evidence_dir(case, "../../etc")


def test_claim_quarantines_uncommitted_dirs_and_never_reuses_numbers(case, tmp_path):
    """#17·#27: 번호 = (디렉터리·보관 기록의 번호 중 최대) + 1. 지운 증거의 번호는 다시 쓰지 않고, 커밋하지 못한 디렉터리(intake 없음,
    중단된 접수의 흔적 — 여기서는 복사 중 이름 *.partial)는 aborted-intakes/ 로 옮기고 intake-aborted 로 번호를 소비한다.
    같은 번호의 두 번째 접수는 거부."""
    log = E.CustodyLog(case, tmp_path / "state" / "custody")
    c = E.claim_evidence_id(case, log)
    log.append("intake", evidence_id=c.evidence_id, data={"x": 1})
    c.commit()
    c.close()
    d1 = E.evidence_dir(case, "EV-0001")
    assert stat.S_IMODE(d1.stat().st_mode) == 0o555 and not (d1 / E.INTAKE_LOCK).exists()
    os.chmod(d1, 0o755)
    shutil.rmtree(d1)  # 사람이 디스크를 비우려고 지움
    orphan = E.evidence_dir(case, "EV-0002")  # 되돌리기가 잠금 파일만 지우고 끝난 흔적 (잠금 파일 없음, 부분 사본 0644)
    orphan.mkdir()
    (orphan / "card.img.partial").write_bytes(b"\x00" * 100)
    c3 = E.claim_evidence_id(case, log)
    try:
        assert c3.evidence_id == "EV-0003"
        q = list((E.forensics_dir(case) / E.QUARANTINE_DIR).iterdir())
        assert len(q) == 1 and q[0].name.startswith("EV-0002-")
        assert stat.S_IMODE((q[0] / "card.img.partial").stat().st_mode) == 0o444 and stat.S_IMODE(q[0].stat().st_mode) == 0o555
        assert [(e["event"], e["evidence_id"]) for e in log.entries()] == [("intake", "EV-0001"), ("intake-aborted", "EV-0002")]
        assert log.entries()[1]["data"]["quarantine_path"] == f"forensics/aborted-intakes/{q[0].name}"
        assert log.entries()[1]["data"]["basis"] == "partial-copy"
        for ev in ("EV-0001", "EV-0002"):
            with pytest.raises(E.EvidenceError, match="같은 번호"):
                log.append("intake", evidence_id=ev, data={}, check=E.refuse_second_intake(ev))
    finally:
        assert c3.rollback() == []  # 실패·취소: 만든 디렉터리를 지우고 번호를 돌려놓는다
        c3.close()
    assert not E.evidence_dir(case, "EV-0003").exists()
    c4 = E.claim_evidence_id(case, log)
    assert c4.evidence_id == "EV-0003"
    c4.rollback()
    c4.close()
    items = E.evidence_items(case, tmp_path / "state" / "custody")
    assert [(i["evidence_id"], i["status"]) for i in items["items"]] == [("EV-0001", "missing")]
    assert items["aborted"][0]["evidence_id"] == "EV-0002"


def test_uncommitted_dir_status_in_progress_vs_abandoned(case, tmp_path):
    anchors = tmp_path / "state" / "custody"
    log = E.CustodyLog(case, anchors)
    c = E.claim_evidence_id(case, log)
    try:
        assert [(i["evidence_id"], i["status"]) for i in E.evidence_items(case, anchors)["items"]] == [("EV-0001", "intake-in-progress")]
        assert E.reconcile_orphans(case, log) == []  # 다른 job 이 잡고 있는 접수는 옮기지 않는다
    finally:
        c._release_lock()  # 프로세스가 죽은 것처럼 잠금만 풀린다
        c.close()
    it = E.evidence_items(case, anchors)["items"][0]
    assert it["status"] == "record-without-intake" and "hashes" not in it
    moved = E.reconcile_orphans(case, log)
    assert [m["evidence_id"] for m in moved] == ["EV-0001"] and E.evidence_ids(case) == []


def test_reconcile_finishes_a_commit_interrupted_after_the_custody_intake(case, tmp_path):
    """보관 기록에 intake 를 남긴 직후(commit() 전) 프로세스가 죽은 흔적: 디렉터리 0755·잠금 파일이 남는다. 다음 접수·서버 시작의 정리는
    이 디렉터리를 옮기지 않고(커밋됨) commit() 을 마저 한다(잠금 파일 삭제, 디렉터리 0555)."""
    anchors = tmp_path / "state" / "custody"
    log = E.CustodyLog(case, anchors)
    c = E.claim_evidence_id(case, log)
    log.append("intake", evidence_id=c.evidence_id, data={"x": 1})
    c._release_lock()  # commit() 전에 죽은 것처럼
    c.close()
    d1 = E.evidence_dir(case, "EV-0001")
    assert (d1 / E.INTAKE_LOCK).exists() and stat.S_IMODE(d1.stat().st_mode) == 0o755
    assert E.reconcile_orphans(case, log) == []
    assert not (d1 / E.INTAKE_LOCK).exists() and stat.S_IMODE(d1.stat().st_mode) == 0o555
    assert [e["event"] for e in log.entries()] == ["intake"]
    held = E.claim_evidence_id(case, log)  # 진행 중인(잠금을 잡은) 커밋된 디렉터리는 건드리지 않는다
    try:
        log.append("intake", evidence_id=held.evidence_id, data={"x": 2})
        E.reconcile_orphans(case, log)
        d2 = E.evidence_dir(case, held.evidence_id)
        assert (d2 / E.INTAKE_LOCK).exists() and stat.S_IMODE(d2.stat().st_mode) == 0o755
        held.commit()
    finally:
        held.close()


def _commit_intake(case, log, data: bytes = b"\x01" * 4096, name: str = "card.img", copy_verified: bool | None = True) -> str:
    """서버의 접수와 같은 순서로 커밋한 증거 하나를 만든다: 확보 → 사본(0444) → 접수 기록 → 보관 기록 intake → commit()."""
    c = E.claim_evidence_id(case, log)
    try:
        ev = c.evidence_id
        safeio.write_new(c.dir_fd, name, data, final_mode=0o444)
        fd, st = safeio.open_regular(name, dir_fd=c.dir_fd)
        try:
            fp = E.fingerprint_fd(fd, st)
        finally:
            os.close(fd)
        hashes = {a: hashlib.new(a, data).hexdigest() for a in E.HASH_ALGORITHMS}
        stored = f"forensics/images/{ev}/{name}"
        rec = {"schema": E.SCHEMA_EVIDENCE, "evidence_id": ev, "case_id": case.id, "stored": {"path": stored, "size": len(data)},
               "hashes": hashes, "fingerprint": fp}
        raw = E.record_bytes(rec)
        safeio.write_new(c.dir_fd, f"{ev}.json", raw, final_mode=0o444)
        log.append("intake", evidence_id=ev, check=E.refuse_second_intake(ev),
                   data={"stored_path": stored, "size": len(data), "hashes": hashes, "fingerprint": fp,
                         "record_sha256": hashlib.sha256(raw).hexdigest(), "copy_verified": copy_verified})
        c.commit()
        return ev
    finally:
        c.close()


def _remove_ev_dir(case, ev: str) -> None:
    d = E.evidence_dir(case, ev)
    os.chmod(d, 0o755)
    shutil.rmtree(d)


@pytest.mark.parametrize("kill_point", ["after-claim", "mid-copy", "after-record", "after-pending"])
def test_reconcile_quarantines_every_uncommitted_kill_point(case, tmp_path, kill_point):
    """#27·G-N1: 커밋(보관 기록 intake) 전에 프로세스가 죽은 접수는 늘 접수 잠금 파일을 남긴다(확보 때 만들고 커밋 뒤에야 지움).
    잡은 쪽이 없는 잠금 파일 = 중단된 접수 → aborted-intakes/ 로 옮기고 intake-aborted(basis intake-lock)로 번호를 소비한다.
    '기록 중' 고정점 줄만 남은 경우(보관 기록을 쓰기 전에 죽음)도 같고, 그 줄은 다음 덧붙이기에 흡수된다."""
    anchors = tmp_path / "state" / "custody"
    log = E.CustodyLog(case, anchors)
    c = E.claim_evidence_id(case, log)
    assert c.evidence_id == "EV-0001"
    if kill_point == "mid-copy":
        fd = safeio.create_excl(c.dir_fd, "card.img.partial", 0o644)
        safeio.write_all(fd, b"\x00" * 3000)
        os.close(fd)
    if kill_point in ("after-record", "after-pending"):
        safeio.write_new(c.dir_fd, "card.img", b"\x02" * 4096, final_mode=0o444)
        safeio.write_new(c.dir_fd, "EV-0001.json", b"{}\n", final_mode=0o444)
    if kill_point == "after-pending":
        anchors.mkdir(parents=True, exist_ok=True)
        log.anchor_path.write_bytes(canonical_json({"seq": 1, "hash": "a" * 64, "pending": True}).encode() + b"\n")
    c._release_lock()  # 프로세스가 죽은 것처럼: 잠금 파일은 남고 잡은 쪽은 없다
    c.close()
    d1 = E.evidence_dir(case, "EV-0001")
    assert (d1 / E.INTAKE_LOCK).exists()
    assert [(i["evidence_id"], i["status"]) for i in E.evidence_items(case, anchors)["items"]] == [("EV-0001", "record-without-intake")]
    moved = E.reconcile_orphans(case, log)
    assert [(m["evidence_id"], m["basis"]) for m in moved] == [("EV-0001", "intake-lock")]
    assert not d1.exists()
    q = E.forensics_dir(case) / E.QUARANTINE_DIR
    (qd,) = list(q.iterdir())
    assert qd.name.startswith("EV-0001-") and stat.S_IMODE(qd.stat().st_mode) == 0o555
    assert not (qd / E.INTAKE_LOCK).exists(), "잠금 파일은 옮긴 뒤에 지운다"
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o444 for p in qd.iterdir())
    ev = log.entries()
    assert [(e["event"], e["evidence_id"], e["data"]["reason"], e["data"]["basis"]) for e in ev] == [
        ("intake-aborted", "EV-0001", "uncommitted-intake", "intake-lock")]
    assert ev[0]["data"]["had_record"] is (kill_point in ("after-record", "after-pending"))
    assert log.verify()["ok"] and b"pending" not in log.anchor_path.read_bytes(), "남은 '기록 중' 줄은 흡수된다"
    c2 = E.claim_evidence_id(case, log)
    try:
        assert c2.evidence_id == "EV-0002", "옮긴 번호는 다시 쓰지 않는다"
    finally:
        c2.rollback()
        c2.close()
    items = E.evidence_items(case, anchors)
    assert items["items"] == [] and [a["evidence_id"] for a in items["aborted"]] == ["EV-0001"]


def test_reconcile_leaves_committed_evidence_when_custody_and_anchor_are_lost(case, tmp_path):
    """G-N1: 보관 기록(custody.jsonl)과 고정점을 함께 잃으면 커밋한 EV 디렉터리(잠금 파일 없음, 0555, 접수 기록·사본)와 중단된 접수를
    구별할 근거가 없다. 정리는 이 디렉터리를 옮기지 않고(intake-aborted 사건도 쓰지 않음) 증거 목록에 record-without-intake 로 남겨
    사람이 판단하게 한다. 디렉터리가 있으므로 다음 접수는 EV-0002 다. 대조: 고정점이 남아 있으면 깨짐(custody_broken)으로 아무것도 안 한다."""
    anchors = tmp_path / "state" / "custody"
    log = E.CustodyLog(case, anchors)
    assert _commit_intake(case, log) == "EV-0001"
    d1 = E.evidence_dir(case, "EV-0001")
    before = sorted((p.name, stat.S_IMODE(p.stat().st_mode)) for p in d1.iterdir())
    log.path.unlink()
    with pytest.raises(E.EvidenceError) as ei:  # 대조: 고정점이 남아 있으면 잘림 = 깨짐 → 정리하지 않는다
        E.reconcile_orphans(case, log)
    assert ei.value.code == "custody_broken" and d1.is_dir()
    log.anchor_path.unlink()
    assert E.reconcile_orphans(case, log) == []
    assert d1.is_dir() and stat.S_IMODE(d1.stat().st_mode) == 0o555
    assert sorted((p.name, stat.S_IMODE(p.stat().st_mode)) for p in d1.iterdir()) == before
    assert not (E.forensics_dir(case) / E.QUARANTINE_DIR).exists()
    assert not log.path.exists() and log.verify() == {"ok": True, "count": 0, "head": None}, "보관 기록에 아무것도 쓰지 않는다"
    items = E.evidence_items(case, anchors)
    assert [(i["evidence_id"], i["status"], i["status_label"]) for i in items["items"]] == [
        ("EV-0001", "record-without-intake", "record-without-intake")]
    assert items["aborted"] == [] and "hashes" not in items["items"][0]
    with pytest.raises(E.IntegrityProblem) as ip:  # 내용 도구는 계속 거부한다(보관 기록 근거가 없다)
        E.open_checked(case, "EV-0001", log.entries())
    assert ip.value.reason == "no-intake" and "그대로 둔다" in (ip.value.hint or "")
    c2 = E.claim_evidence_id(case, log)  # 확보 때의 정리도 같은 규칙
    try:
        assert c2.evidence_id == "EV-0002" and d1.is_dir()
        assert not (E.forensics_dir(case) / E.QUARANTINE_DIR).exists()
    finally:
        c2.rollback()
        c2.close()


def test_reconcile_quarantines_an_empty_dir_but_not_lockless_dirs_without_traces(case, tmp_path):
    """확보가 mkdir 과 잠금 파일 만들기 사이에 끝나면 빈 디렉터리가 남는다(둘 다 확보 잠금 안이라 진행 중일 수 없다) → 옮긴다(basis empty-dir).
    잠금 파일도 *.partial 도 없는 비지 않은 디렉터리(사람이 만든 것 등)는 옮기지 않는다 — record-without-intake, 번호는 다시 쓰지 않는다."""
    anchors = tmp_path / "state" / "custody"
    log = E.CustodyLog(case, anchors)
    images = E.forensics_dir(case) / E.IMAGES_DIR
    images.mkdir(parents=True)
    (images / "EV-0001").mkdir()
    (images / "EV-0002").mkdir()
    (images / "EV-0002" / "notes.txt").write_bytes(b"human")
    moved = E.reconcile_orphans(case, log)
    assert [(m["evidence_id"], m["basis"], m["had_record"], m["files"]) for m in moved] == [("EV-0001", "empty-dir", False, 0)]
    assert [(e["event"], e["evidence_id"], e["data"]["basis"]) for e in log.entries()] == [("intake-aborted", "EV-0001", "empty-dir")]
    assert (images / "EV-0002" / "notes.txt").read_bytes() == b"human"
    assert [(i["evidence_id"], i["status"]) for i in E.evidence_items(case, anchors)["items"]] == [("EV-0002", "record-without-intake")]
    c = E.claim_evidence_id(case, log)
    try:
        assert c.evidence_id == "EV-0003" and (images / "EV-0002").is_dir()
    finally:
        c.rollback()
        c.close()


def test_reconcile_never_opens_a_non_regular_intake_lock(case, tmp_path):
    """접수 잠금 자리에 FIFO 가 있으면 열지 않고(멈추지 않고) 판단하지 않는다 — 옮기지도, 커밋을 마저 하지도 않는다. 확보는 막히지 않는다."""
    anchors = tmp_path / "state" / "custody"
    log = E.CustodyLog(case, anchors)
    images = E.forensics_dir(case) / E.IMAGES_DIR
    images.mkdir(parents=True)
    (images / "EV-0001").mkdir()
    (images / "EV-0001" / "card.img.partial").write_bytes(b"\x00" * 10)
    os.mkfifo(images / "EV-0001" / E.INTAKE_LOCK)
    t0 = time.monotonic()
    assert E.reconcile_orphans(case, log) == []
    assert [(i["evidence_id"], i["status"]) for i in E.evidence_items(case, anchors)["items"]] == [("EV-0001", "record-without-intake")]
    c = E.claim_evidence_id(case, log)
    try:
        assert c.evidence_id == "EV-0002" and (images / "EV-0001").is_dir()
    finally:
        c.rollback()
        c.close()
    assert time.monotonic() - t0 < 5 and log.entries() == []


def test_reconcile_retries_a_failed_move_into_the_recorded_place(case, tmp_path, monkeypatch):
    """옮기기(rename)가 실패하면 intake-aborted 사건은 남고 접수 잠금 파일도 남는다(옮긴 뒤에 지운다). 다음 정리는 사건을 다시 쓰지 않고
    기록한 자리(quarantine_path)로 옮긴다."""
    anchors = tmp_path / "state" / "custody"
    log = E.CustodyLog(case, anchors)
    c = E.claim_evidence_id(case, log)
    c._release_lock()
    c.close()
    real_rename = os.rename
    calls = {"n": 0}

    def failing_rename(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError(errno.EACCES, "Permission denied")
        return real_rename(*a, **kw)

    monkeypatch.setattr(E.os, "rename", failing_rename)
    with pytest.raises(OSError):
        E.reconcile_orphans(case, log)
    d1 = E.evidence_dir(case, "EV-0001")
    assert d1.is_dir() and (d1 / E.INTAKE_LOCK).exists()
    (entry,) = log.entries()
    assert entry["event"] == "intake-aborted"
    moved = E.reconcile_orphans(case, log)
    monkeypatch.setattr(E.os, "rename", real_rename)
    assert [m["quarantine_path"] for m in moved] == [entry["data"]["quarantine_path"]]
    assert (case.dir / entry["data"]["quarantine_path"]).is_dir() and not d1.exists()
    assert [e["event"] for e in log.entries()] == ["intake-aborted"], "사건은 한 번만"


def test_status_label_shows_integrity_failure_of_a_missing_item(case, tmp_path):
    """G-N3: 디렉터리가 지워진 증거(missing)에 앞선 무결성 실패가 있으면 status_label 은 'missing (integrity-failed)' 다(status 는 missing).
    다른 항목은 status_label == status. 보고서 §8.1 의 상태 칸은 status_label 을 쓴다."""
    from pweh.report import render_report

    anchors = tmp_path / "state" / "custody"
    log = E.CustodyLog(case, anchors)
    a = _commit_intake(case, log, b"\x0a" * 4096)  # 무결성 실패 기록 뒤 지움 (S4)
    log.append("integrity-failed", evidence_id=a, data={"reason": "fingerprint-mismatch"})
    _remove_ev_dir(case, a)
    b = _commit_intake(case, log, b"\x0b" * 4096, copy_verified=False)  # 사본 재해시 불일치(사건 없이도 실패) 뒤 지움
    _remove_ev_dir(case, b)
    c = _commit_intake(case, log, b"\x0c" * 4096)  # 실패 없이 지움
    _remove_ev_dir(case, c)
    d = _commit_intake(case, log, b"\x0d" * 4096)  # 멀쩡함 (사본 재해시 일치 → ok)
    held = E.claim_evidence_id(case, log)  # 진행 중
    try:
        items = {i["evidence_id"]: i for i in E.evidence_items(case, anchors)["items"]}
        assert {k: (v["status"], v["status_label"]) for k, v in items.items()} == {
            a: ("missing", "missing (integrity-failed)"),
            b: ("missing", "missing (integrity-failed)"),
            c: ("missing", "missing"),
            d: ("ok", "ok"),
            held.evidence_id: ("intake-in-progress", "intake-in-progress"),
        }
        assert items[a]["integrity_failures"] and items[b]["integrity_failures"][0]["reason"] == "copy-verify-mismatch"
        text = render_report(case, anchors)
        rows = {ln.split("|")[1].strip(): [x.strip() for x in ln.split("|")[1:-1]] for ln in text.splitlines() if ln.startswith("| EV-")}
        assert rows[a][4] == "missing (integrity-failed)" and rows[b][4] == "missing (integrity-failed)"
        assert rows[c][4] == "missing" and rows[d][4] == "ok" and rows[held.evidence_id][4] == "intake-in-progress"
    finally:
        held.rollback()
        held.close()
    assert E.status_label("missing", "integrity-failed") == "missing (integrity-failed)"
    assert E.status_label("integrity-failed", "integrity-failed") == "integrity-failed" and E.status_label("missing", "ok") == "missing"
    log.path.write_bytes(log.path.read_bytes()[:-1])  # 보관 기록이 깨지면 모든 항목 custody-broken (status_label 도)
    broken = E.evidence_items(case, anchors)
    assert not broken["custody"]["ok"] and {(i["status"], i["status_label"]) for i in broken["items"]} == {("custody-broken", "custody-broken")}


def test_anchor_pending_line_survives_interrupted_appends(case, tmp_path, monkeypatch):
    """#18·#31: 고정점은 '기록 중' → 보관 기록 → 확정 순서. 보관 기록·고정점 쓰기가 도중에 실패해도(디스크 가득·강제 종료) 케이스의 보관 기록이
    영구히 깨지지 않는다. 확정된 줄을 잘라 내는 것은 여전히 깨짐."""
    log = E.CustodyLog(case, tmp_path / "state" / "custody")
    log.append("intake", evidence_id="EV-0001", data={"x": 1})
    real = safeio.atomic_write_at

    def fail_custody(dir_fd, name, data, mode=0o644):
        if name == E.CUSTODY_FILE:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real(dir_fd, name, data, mode)

    monkeypatch.setattr(E.safeio, "atomic_write_at", fail_custody)
    with pytest.raises(OSError):
        log.append("note", evidence_id=None, data={})
    monkeypatch.setattr(E.safeio, "atomic_write_at", real)
    assert log.verify()["ok"] and log.verify()["count"] == 1
    anchor_writes: list[bytes] = []

    def fail_final_anchor(dir_fd, name, data, mode=0o644):
        if name != E.CUSTODY_FILE and name.endswith(".jsonl"):
            anchor_writes.append(bytes(data))
            if len(anchor_writes) == 2:
                raise OSError(errno.ENOSPC, "No space left on device")
        return real(dir_fd, name, data, mode)

    monkeypatch.setattr(E.safeio, "atomic_write_at", fail_final_anchor)
    log.append("note", evidence_id=None, data={"n": 2})  # 기록은 됐다 — 확정 표시만 못 함
    monkeypatch.setattr(E.safeio, "atomic_write_at", real)
    assert b'"pending":true' in log.anchor_path.read_bytes()
    v = log.verify()
    assert v["ok"] and v["count"] == 2
    log.append("note", evidence_id=None, data={"n": 3})  # 다음 덧붙이기가 '기록 중' 줄을 확정한다
    assert b"pending" not in log.anchor_path.read_bytes() and log.verify()["count"] == 3
    raw_anchor = log.anchor_path.read_bytes()
    # 강제 종료 흉내: '기록 중' 줄만 남고 보관 기록은 못 씀 → 기록 전 중단으로 본다
    log.anchor_path.write_bytes(raw_anchor + canonical_json({"seq": 4, "hash": "0" * 64, "pending": True}).encode() + b"\n")
    assert log.verify()["ok"] and log.verify()["count"] == 3
    log.anchor_path.write_bytes(raw_anchor)
    lines = log.path.read_bytes().split(b"\n")[:-1]
    log.path.write_bytes(b"\n".join(lines[:-1]) + b"\n")
    assert "짧다" in log.verify()["detail"]


class _Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def test_append_never_raises_after_the_custody_write_commits(case, tmp_path, monkeypatch):
    """B-N5: 보관 기록 쓰기(둘째 단계)가 커밋 지점이다. 그 뒤의 고정점 확정 쓰기나 고정점 디렉터리 fd 닫기에서 OSError 가 아닌 예외
    (RuntimeError 등)가 나도 append() 는 사건을 돌려주고(로그만 남김), 보관 기록은 검증을 통과하며 다음 덧붙이기도 된다.
    커밋 전(첫째·둘째 단계)의 예외는 그대로 올라가고 사건은 남지 않는다 — '기록 중' 줄을 거두다 실패해도 원래 예외가 올라간다."""
    log = E.CustodyLog(case, tmp_path / "state" / "custody")
    log.append("intake", evidence_id="EV-0001", data={"x": 1})
    real = safeio.atomic_write_at
    anchor_name = f"{case.id}.jsonl"
    rec = _Records()
    logging.getLogger("pweh.evidence").addHandler(rec)
    try:
        def fail_confirm(dir_fd, name, data, mode=0o644):
            if name == anchor_name and b"pending" not in bytes(data):
                raise RuntimeError("확정 쓰기 실패 주입")
            return real(dir_fd, name, data, mode)

        monkeypatch.setattr(E.safeio, "atomic_write_at", fail_confirm)
        entry = log.append("verify", evidence_id="EV-0001", data={"result": "match"})
        monkeypatch.setattr(E.safeio, "atomic_write_at", real)
        assert entry["seq"] == 2 and entry["hash"] == E.entry_hash({k: v for k, v in entry.items() if k != "hash"})
        assert b'"pending":true' in log.anchor_path.read_bytes()
        v = log.verify()
        assert v["ok"] and v["count"] == 2 and v["head"] == entry["hash"]
        assert any("확정 쓰기 실패" in m for m in rec.messages)
        assert log.append("note", evidence_id=None, data={})["seq"] == 3  # 다음 덧붙이기가 '기록 중' 줄을 확정 줄로 다시 쓴다
        assert b"pending" not in log.anchor_path.read_bytes() and log.verify()["count"] == 3

        # 고정점 디렉터리 fd 닫기에서 RuntimeError
        real_anchor_fd = E.CustodyLog._anchor_fd
        opened: list[int] = []

        def anchor_fd(self, *, create):
            fd = real_anchor_fd(self, create=create)
            if create and fd is not None:
                opened.append(fd)
            return fd

        real_close = os.close

        def close(fd):
            real_close(fd)
            if opened and fd == opened[-1]:
                opened.clear()
                raise RuntimeError("fd 닫기 실패 주입")

        monkeypatch.setattr(E.CustodyLog, "_anchor_fd", anchor_fd)
        monkeypatch.setattr(E.os, "close", close)
        entry = log.append("note", evidence_id=None, data={"n": 4})
        monkeypatch.setattr(E.os, "close", real_close)
        monkeypatch.setattr(E.CustodyLog, "_anchor_fd", real_anchor_fd)
        assert entry["seq"] == 4 and log.verify()["count"] == 4 and any("fd 닫기 실패" in m for m in rec.messages)

        # 커밋 전: '기록 중' 줄 쓰기의 RuntimeError 는 그대로 올라가고 아무것도 바뀌지 않는다
        def fail_pending(dir_fd, name, data, mode=0o644):
            if name == anchor_name:
                raise RuntimeError("기록 중 줄 실패 주입")
            return real(dir_fd, name, data, mode)

        monkeypatch.setattr(E.safeio, "atomic_write_at", fail_pending)
        with pytest.raises(RuntimeError, match="기록 중 줄"):
            log.append("note", evidence_id=None, data={"n": 5})
        # 커밋 전: 보관 기록 쓰기가 실패하고 '기록 중' 줄 거두기도 실패해도 원래 예외(ENOSPC)가 올라간다
        anchor_calls = {"n": 0}

        def fail_custody_and_withdraw(dir_fd, name, data, mode=0o644):
            if name == E.CUSTODY_FILE:
                raise OSError(errno.ENOSPC, "No space left on device")
            if name == anchor_name:
                anchor_calls["n"] += 1
                if anchor_calls["n"] == 2:
                    raise RuntimeError("거두기 실패 주입")
            return real(dir_fd, name, data, mode)

        monkeypatch.setattr(E.safeio, "atomic_write_at", fail_custody_and_withdraw)
        with pytest.raises(OSError) as ei:
            log.append("note", evidence_id=None, data={"n": 6})
        assert ei.value.errno == errno.ENOSPC
        monkeypatch.setattr(E.safeio, "atomic_write_at", real)
        v = log.verify()
        assert v["ok"] and v["count"] == 4, "커밋하지 못한 사건은 남지 않는다(남은 '기록 중' 줄은 기록 전 중단으로 본다)"
        assert log.append("note", evidence_id=None, data={"n": 7})["seq"] == 5
    finally:
        logging.getLogger("pweh.evidence").removeHandler(rec)


def test_custody_reads_do_not_race_appends(case, tmp_path):
    """#20: 읽기는 공유 잠금 안에서 — 덧붙이는 도중(보관 기록과 고정점 사이)을 읽어 깨짐으로 오판하지 않는다."""
    anchors = tmp_path / "state" / "custody"
    log = E.CustodyLog(case, anchors)
    log.append("intake", evidence_id="EV-0001", data={})
    stop = threading.Event()
    broken: list[str] = []
    reads = [0]

    def reader() -> None:
        r = E.CustodyLog(case, anchors)
        while not stop.is_set():
            _, why = r.read()
            reads[0] += 1
            if why:
                broken.append(why)

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    try:
        for i in range(40):
            log.append("note", evidence_id=None, data={"i": i})
    finally:
        stop.set()
        t.join(10)
    assert reads[0] > 0 and not broken, broken[:3]


def test_custody_and_anchor_never_open_fifos_or_follow_links(case, tmp_path):
    """#15: 보관 기록·고정점 자리에 FIFO·링크가 있어도 열지 않고(멈추지 않고) 깨짐으로 본다. forensics/ 가 링크면 쓰지 않는다."""
    log = E.CustodyLog(case, tmp_path / "state" / "custody")
    log.append("intake", evidence_id="EV-0001", data={})
    raw = log.path.read_bytes()
    t0 = time.monotonic()
    log.path.unlink()
    os.mkfifo(log.path)
    assert not log.verify()["ok"]
    with pytest.raises(E.EvidenceError):
        log.append("note", evidence_id=None, data={})
    log.path.unlink()
    log.path.write_bytes(raw)
    assert log.verify()["ok"]
    araw = log.anchor_path.read_bytes()
    log.anchor_path.unlink()
    os.mkfifo(log.anchor_path)
    assert not log.verify()["ok"]
    log.anchor_path.unlink()
    log.anchor_path.write_bytes(araw)
    assert time.monotonic() - t0 < 5
    outside = tmp_path / "outside.jsonl"
    outside.write_bytes(raw)
    log.path.unlink()
    log.path.symlink_to(outside)
    assert not log.verify()["ok"]
    log.path.unlink()
    log.path.write_bytes(raw)
    fdir = E.forensics_dir(case)
    moved = tmp_path / "moved-forensics"
    fdir.rename(moved)
    fdir.symlink_to(moved)
    assert not log.verify()["ok"]
    with pytest.raises(E.EvidenceError):
        log.append("note", evidence_id=None, data={})
    assert (moved / "custody.jsonl").read_bytes() == raw


def test_hash_stream_cancel(tmp_path):
    p = tmp_path / "big"
    p.write_bytes(b"\x00" * (E.HASH_BLOCK * 2 + 10))
    calls = {"n": 0}

    def cancel():
        calls["n"] += 1
        return calls["n"] > 1

    with pytest.raises(E.EvidenceError) as ei:
        E.hash_stream(p, cancel=cancel)
    assert ei.value.code == "cancelled"
    full = E.hash_stream(p)
    assert full["size"] == p.stat().st_size and full["sha256"] == hashlib.sha256(p.read_bytes()).hexdigest()


def test_anchor_detects_last_line_edit_truncation_and_foreign_append(case, tmp_path):
    anchors = tmp_path / "state" / "custody"
    log = E.CustodyLog(case, anchors)
    log.append("intake", evidence_id="EV-0001", data={"role": "owner"})
    log.append("verify", evidence_id="EV-0001", data={"result": "match"})
    assert log.verify()["ok"] and stat.S_IMODE(log.anchor_path.stat().st_mode) == 0o600
    raw = log.path.read_bytes()
    # 1) 마지막 줄 값 바꾸기: 체인만으로는 못 잡지만 고정점이 잡는다
    log.path.write_bytes(raw.replace(b'"result":"match"', b'"result":"other"'))
    assert E.CustodyLog(case).verify()["ok"], "고정점 없이는 마지막 줄 수정이 보이지 않는다(문서화된 한계)"
    v = log.verify()
    assert not v["ok"] and "고정점과 다르다" in v["detail"]
    # 2) 끝 줄 잘라 내기
    log.path.write_bytes(raw.split(b"\n")[0] + b"\n")
    assert "짧다" in log.verify()["detail"]
    # 3) 서버 밖에서(고정점 없이) 올바른 체인으로 덧붙이기
    log.path.write_bytes(raw)
    E.CustodyLog(case).append("note", evidence_id=None, data={"forged": True})
    assert "고정점이 없는" in log.verify()["detail"]
    with pytest.raises(E.EvidenceError):
        log.append("note", evidence_id=None, data={})
    # 고정점 파일 자체가 망가져도 fail closed
    log.path.write_bytes(raw)
    log.anchor_path.write_bytes(b"{not json}\n")
    assert not log.verify()["ok"]


def test_sd_forensics_schema_follows_evidence_list_statuses():
    """요약 스키마의 증거 상태는 evidence_items 의 어휘와 같고, 보관 기록에 근거가 없는 상태에는 sha256 이 없어도 된다."""
    from pweh import schemas

    base = {"mode": "evidence", "legal": {"site_type": "home", "role": "owner", "legal_basis": "소유자 본인 기기"}, "custody_ok": True,
            "privacy": {"audio_decoded": False, "face_plate_processing": False, "uploads": False, "recording_content_viewed": False}}
    sha = "a" * 64
    for status in E.ANCHORED_STATUSES:
        assert not schemas.errors("sd-forensics", {**base, "evidence": [{"evidence_id": "EV-0001", "sha256": sha, "status": status}]}), status
        assert schemas.errors("sd-forensics", {**base, "evidence": [{"evidence_id": "EV-0001", "status": status}]}), f"{status} 는 sha256 이 필요"
    for status in ("custody-broken", "record-without-intake", "intake-in-progress"):
        assert not schemas.errors("sd-forensics", {**base, "evidence": [{"evidence_id": "EV-0002", "status": status}]}), status
    assert not schemas.errors("sd-forensics", {**base, "evidence": [{"evidence_id": "EV-0001", "sha256": sha, "status": "ok", "write_blocker": "revoked"}]})
    assert schemas.errors("sd-forensics", {**base, "evidence": [{"evidence_id": "EV-0001", "sha256": sha, "status": "aborted"}]})


def test_replay_copy_verify_mismatch_is_failure_even_without_event(case):
    log = E.CustodyLog(case)
    log.append("intake", evidence_id="EV-0001", data={"copy_verified": False})
    st = E.replay_status(log.entries(), "EV-0001")
    assert st["status"] == "integrity-failed" and st["integrity_failures"][0]["reason"] == "copy-verify-mismatch"
    log.append("integrity-failed", evidence_id="EV-0001", data={"reason": "copy-verify-mismatch"})
    assert len(E.replay_status(log.entries(), "EV-0001")["integrity_failures"]) == 1


def _hint_preview():
    """저장 계층은 PNG 를 해독하지 않는다. 고정 합성 바이트의 해시 결속을 시험한다."""
    data = b"synthetic normalized preview"
    return {"role": "overview", "mime_type": "image/png", "data": data, "sha256": hashlib.sha256(data).hexdigest(),
            "width": 1, "height": 1, "crop": None}


def test_store_image_hints_commit_failure_removes_only_own_outputs(case):
    outdir = case.dir / "forensics/analysis"
    outdir.mkdir(parents=True)
    prior = outdir / "image-hints-EV-0001-001.json"
    prior.write_bytes(b"earlier report")

    def fail(data):
        raise RuntimeError("synthetic custody failure")

    with pytest.raises(RuntimeError):
        E.store_image_hints(case, {"status": "ok"}, [_hint_preview()], forensic=True, evidence_id="EV-0001", commit=fail)
    assert list(outdir.iterdir()) == [prior]
    assert prior.read_bytes() == b"earlier report"


def test_store_image_hints_post_commit_index_failure_preserves_files(case, monkeypatch):
    log = E.CustodyLog(case)

    def fail_index(*args, **kwargs):
        raise RuntimeError("synthetic index failure")

    monkeypatch.setattr(case, "register_artifact", fail_index)
    out = E.store_image_hints(case, {"status": "ok", "source": {"kind": "evidence"}}, [_hint_preview()],
                              forensic=True, evidence_id="EV-0001",
                              commit=lambda data: log.append("image-hints", evidence_id="EV-0001", data=data))
    assert out["warnings"] and out["analysis"]["custody_seq"] == 1
    for item in [out["analysis"], *out["report"]["artifacts"]["previews"]]:
        p = case.dir / item["path"]
        assert p.is_file() and stat.S_IMODE(p.stat().st_mode) == 0o444
        assert hashlib.sha256(p.read_bytes()).hexdigest() == item["sha256"]
    assert E.replay_status(log.entries(), "EV-0001")["image_hints"] == 1


def test_store_image_hints_rejects_output_link_and_wrong_preview_hash(case, tmp_path):
    outdir = tmp_path / "outside-analysis"
    outdir.mkdir()
    analysis = case.dir / "analysis"
    analysis.rmdir()
    analysis.symlink_to(outdir, target_is_directory=True)
    with pytest.raises(safeio.UnsafeFile):
        E.store_image_hints(case, {"status": "ok"}, [_hint_preview()])
    assert not list(outdir.iterdir())
    analysis.unlink()
    with pytest.raises(ValidationFailed, match="해시"):
        E.store_image_hints(case, {"status": "ok"}, [{**_hint_preview(), "sha256": "0" * 64}])
    assert not list(analysis.iterdir())


@pytest.mark.parametrize("seconds", [0, -1, 46, float("nan"), float("inf"), True])
def test_image_hints_deadline_bounds(seconds):
    with pytest.raises(ValidationFailed):
        E.image_hints_deadline(seconds)


def test_source_hardlink_refused_before_read(tmp_path, monkeypatch):
    image = tmp_path / "source.img"
    image.write_bytes(b"synthetic" * 100)
    os.link(image, tmp_path / "alias.img")
    monkeypatch.setattr(E.safeio, "read_fd", lambda *a, **k: pytest.fail("하드링크 파일 내용을 읽음"))
    with pytest.raises(ValidationFailed):
        E.open_image_source(image)


@pytest.mark.parametrize("which", ["copy", "record"])
def test_open_checked_rejects_hardlinked_evidence_or_record(case, tmp_path, which):
    log = E.CustodyLog(case, tmp_path / "state" / "custody")
    ev = _commit_intake(case, log)
    source = E.evidence_dir(case, ev) / ("card.img" if which == "copy" else f"{ev}.json")
    os.link(source, tmp_path / "outside-alias")
    with pytest.raises(E.IntegrityProblem):
        E.open_checked(case, ev, log.entries())


def test_reference_hardlink_refused_without_mount_probe(tmp_path, monkeypatch):
    image = tmp_path / "source.img"
    image.write_bytes(b"synthetic" * 100)
    os.link(image, tmp_path / "alias.img")
    monkeypatch.setattr(os, "fstatvfs", lambda *a: pytest.fail("거부할 하드링크의 마운트 조사"))
    with pytest.raises(E.EvidenceError, match="안전하게 열 수 없습니다"):
        E.open_reference(image, [tmp_path])


def test_opened_evidence_recheck_detects_new_hardlink(case, tmp_path):
    log = E.CustodyLog(case, tmp_path / "state" / "custody")
    ev = _commit_intake(case, log)
    with E.open_checked(case, ev, log.entries()) as opened:
        os.link(E.evidence_dir(case, ev) / "card.img", tmp_path / "alias")
        with pytest.raises(E.IntegrityProblem):
            E.recheck_opened(case, opened, log.entries())
