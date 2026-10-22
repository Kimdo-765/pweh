"""pweh-forensics: 접수·보관 기록·검증·사람 증명·증거 목록 (이미지 내용 해석 도구는 test_forensics_fs.py)."""

from __future__ import annotations

import asyncio
import datetime as dt
import errno
import hashlib
import json
import os
import shutil
import stat
import threading
import time

import pytest
from mcp import Client

from mcp_helpers import call

pytestmark = pytest.mark.anyio

ATT_ANSWERS = {"blocker_used": "yes", "blocker_model": "테스트 쓰기 방지 리더", "blocker_tested": "yes", "imaging_tool": "FTK Imager 4.7"}
LEGAL = {"purpose": "도난 사건 녹화 확인", "legal_basis": "소유자 본인 기기·본인 의뢰", "site_type": "home",
         "business_purpose": "없음(개인 가정용)", "role": "owner"}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def fcase(workspace, auth):
    from pweh.case import CaseStore

    return CaseStore(workspace["cases_dir"]).create(title="SD 카드", authorization=auth, case_id="sdcase")


@pytest.fixture
def image(tmp_path):
    p = tmp_path / "evidence" / "card.img"
    p.parent.mkdir()
    p.write_bytes(os.urandom(3 << 20) + b"\x00" * (1 << 20))
    return p


async def _wait(c, job_id: str) -> dict:
    for _ in range(200):
        st = await call(c, "forensics_job_status", job_id=job_id, wait_seconds=5)
        if st.get("status") in ("succeeded", "failed", "cancelled"):
            return st
        await asyncio.sleep(0.05)
    raise AssertionError("job 이 끝나지 않음")


async def _intake(c, case, image, **kw):
    r = await call(c, "forensics_intake_start", case_id=case.id, image_path=str(image), **{**LEGAL, **kw})
    assert r.get("ok") and r.get("job_id"), r
    return await _wait(c, r["job_id"])


async def test_intake_hashes_copy_custody_provenance(fcase, image):
    from forensics_mcp.server import server
    from pweh import evidence as E
    from pweh.runtime import get_runtime

    data = image.read_bytes()
    async with Client(server) as c:
        st = await _intake(c, fcase, image, label="거실 카메라")
        res = st["result"]
        assert st["status"] == "succeeded" and res["ok"] and res["evidence_id"] == "EV-0001", st
        assert res["hashes"] == {a: hashlib.new(a, data).hexdigest() for a in E.HASH_ALGORITHMS}
        assert res["copy_verified"] is True and res["size"] == len(data)
        stored = fcase.dir / res["stored_path"]
        assert stored.read_bytes() == data and stat.S_IMODE(stored.stat().st_mode) == 0o444
        assert stat.S_IMODE(stored.parent.stat().st_mode) == 0o555
        rec = E.load_record(fcase, "EV-0001")
        assert rec["intake"]["site_type"] == "home" and rec["intake"]["role"] == "owner" and rec["label"] == "거실 카메라"
        assert "evidence" not in json.dumps(rec["source"]), "원본의 전체 경로는 기록하지 않는다(파일 이름·크기만)"
        entries = E.CustodyLog(fcase).entries()
        assert [e["event"] for e in entries] == ["intake"] and entries[0]["data"]["legal"]["purpose"] == LEGAL["purpose"]
        prov = get_runtime("forensics-mcp").provenance.entries(fcase, "imported-unattested")
        assert prov and prov[-1]["path"] == "forensics/images/EV-0001/EV-0001.json" and prov[-1]["extra"]["image_sha256"] == res["hashes"]["sha256"]
        assert any(a["kind"] == "evidence-image" for a in fcase.artifacts())
        lst = await call(c, "forensics_evidence_list", case_id=fcase.id)
        it = lst["items"][0]
        assert it["status"] == "ok" and it["last_verify"]["kind"] == "intake-copy" and it["attestation"] is None
        md = (fcase.dir / lst["files"]["markdown"]).read_text(encoding="utf-8")
        assert "해시값 확인서" in md and res["hashes"]["sha256"] in md and "인증·검증된 포렌식 도구가 아니다" in md
        assert E.CustodyLog(fcase).entries()[-1]["event"] == "evidence-list"


async def test_intake_validation_and_refusals(fcase, image, workspace, tmp_path):
    from forensics_mcp.server import server

    async with Client(server) as c:
        bad = await call(c, "forensics_intake_start", case_id=fcase.id, image_path=str(image), **{**LEGAL, "site_type": "street"})
        assert "validation_failed" in bad["_error"]
        bad = await call(c, "forensics_intake_start", case_id=fcase.id, image_path=str(image), **{**LEGAL, "purpose": " "})
        assert "validation_failed" in bad["_error"]
        dev = await call(c, "forensics_intake_start", case_id=fcase.id, image_path="/dev/zero", **LEGAL)
        assert "validation_failed" in dev["_error"]
        inside = fcase.dir / "dumps" / "card.img"
        inside.parent.mkdir(exist_ok=True)
        inside.write_bytes(b"\x00" * 4096)
        r = await call(c, "forensics_intake_start", case_id=fcase.id, image_path=str(inside), **LEGAL)
        assert "validation_failed" in r["_error"] and "케이스 폴더" in r["_error"]
        state = workspace["state_dir"] / "x.img"
        state.parent.mkdir(parents=True, exist_ok=True)
        state.write_bytes(b"\x00" * 4096)
        r = await call(c, "forensics_intake_start", case_id=fcase.id, image_path=str(state), **LEGAL)
        assert "validation_failed" in r["_error"]


async def test_intake_requires_authorization(workspace, image):
    from forensics_mcp.server import server
    from pweh.case import CaseStore

    noauth = CaseStore(workspace["cases_dir"]).create(title="허가 없음", case_id="noauth")
    async with Client(server) as c:
        r = await call(c, "forensics_intake_start", case_id=noauth.id, image_path=str(image), **LEGAL)
        assert "_error" in r and "authoriz" in r["_error"].lower() or "허가" in r.get("_error", "")


async def test_imaging_log_match_mismatch_and_duplicate(fcase, image, tmp_path):
    from forensics_mcp.server import server

    data = image.read_bytes()
    md5, sha1 = hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest()
    good = tmp_path / "evidence" / "ftk.txt"
    good.write_text(f"Created By AccessData FTK Imager 4.7\n MD5 checksum:    {md5}\n SHA1 checksum:   {sha1}\n", encoding="utf-8")
    badlog = tmp_path / "evidence" / "ftk-bad.txt"
    badlog.write_text(f"FTK Imager\n MD5 checksum:    {'0' * 32}\n", encoding="utf-8")
    async with Client(server) as c:
        st = await _intake(c, fcase, image, imaging_log_path=str(good))
        assert st["result"]["imaging_log"]["comparison"]["status"] == "match"
        assert (fcase.dir / "forensics/images/EV-0001/imaging-log.txt").read_text(encoding="utf-8").startswith("Created By")
        st2 = await _intake(c, fcase, image, imaging_log_path=str(badlog))
        r2 = st2["result"]
        assert r2["evidence_id"] == "EV-0002" and r2["imaging_log"]["comparison"]["status"] == "mismatch"
        assert r2["duplicate_of"] == ["EV-0001"] and "이미징 로그" in r2["warning"]


async def test_verify_detects_silent_change_and_locks_evidence(fcase, image):
    from forensics_mcp.server import server
    from pweh import evidence as E

    async with Client(server) as c:
        await _intake(c, fcase, image)
        v = await call(c, "forensics_verify_start", case_id=fcase.id, evidence_id="EV-0001")
        vs = await _wait(c, v["job_id"])
        assert vs["result"]["result"] == "match"
        # 가운데 바이트를 몰래 바꾸고 mtime·권한을 되돌린다 → 빠른 지문은 통과, 전체 재해시가 잡는다
        stored = fcase.dir / "forensics/images/EV-0001/card.img"
        st = stored.stat()
        os.chmod(stored.parent, 0o755)
        os.chmod(stored, 0o644)
        with open(stored, "r+b") as fh:
            fh.seek(2 << 20)
            b = fh.read(1)
            fh.seek(2 << 20)
            fh.write(bytes([b[0] ^ 0xFF]))
        os.utime(stored, ns=(st.st_atime_ns, st.st_mtime_ns))
        os.chmod(stored, 0o444)
        os.chmod(stored.parent, 0o555)
        v2 = await call(c, "forensics_verify_start", case_id=fcase.id, evidence_id="EV-0001")
        vs2 = await _wait(c, v2["job_id"])
        assert vs2["result"]["result"] == "mismatch" and not vs2["result"]["ok"]
        assert E.replay_status(E.CustodyLog(fcase).entries(), "EV-0001")["status"] == "integrity-failed"
        again = await call(c, "forensics_verify_start", case_id=fcase.id, evidence_id="EV-0001")
        assert "integrity_failed" in again["_error"], "무결성 실패는 되돌리지 않는다"


async def test_fingerprint_mismatch_records_integrity_failure(fcase, image):
    from forensics_mcp.server import server
    from pweh import evidence as E

    async with Client(server) as c:
        await _intake(c, fcase, image)
        stored = fcase.dir / "forensics/images/EV-0001/card.img"
        os.chmod(stored.parent, 0o755)
        os.chmod(stored, 0o644)
        with open(stored, "r+b") as fh:
            fh.write(b"X")
        r = await call(c, "forensics_verify_start", case_id=fcase.id, evidence_id="EV-0001")
        assert "integrity_failed" in r["_error"]
        events = [e["event"] for e in E.CustodyLog(fcase).entries()]
        assert events[-1] == "integrity-failed"


async def test_custody_tamper_blocks_tools(fcase, image):
    from forensics_mcp.server import server
    from pweh import evidence as E

    async with Client(server) as c:
        await _intake(c, fcase, image)
        p = E.CustodyLog(fcase).path
        p.write_text(p.read_text(encoding="utf-8").replace('"role":"owner"', '"role":"investigator"'), encoding="utf-8")
        r = await call(c, "forensics_verify_start", case_id=fcase.id, evidence_id="EV-0001")
        assert "custody_broken" in r["_error"]
        lst = await call(c, "forensics_evidence_list", case_id=fcase.id)
        assert lst["custody"]["ok"] is False and lst["items"][0]["status"] == "custody-broken"


async def test_write_blocker_attestation_flow(fcase, image):
    from forensics_mcp.server import server
    from pweh import evidence as E
    from pweh.runtime import get_runtime

    async with Client(server) as c:
        await _intake(c, fcase, image)
        first = await call(c, "forensics_acquisition_attest", case_id=fcase.id, evidence_id="EV-0001")
        assert first["status"] == "attestation_required" and first["kind"] == "write-blocker", first
        assert {q["id"] for q in first["questions"]} >= {"blocker_used", "blocker_model", "blocker_tested", "imaging_tool"}
        get_runtime("forensics-mcp").attestations.decide(first["attestation_id"], ATT_ANSWERS, via="cli-tty", by="tester")
        second = await call(c, "forensics_acquisition_attest", case_id=fcase.id, evidence_id="EV-0001")
        assert second["ok"] and second["status"] == "approved" and second["blocker_tested"] == "yes"
        third = await call(c, "forensics_acquisition_attest", case_id=fcase.id, evidence_id="EV-0001")
        assert third["ok"]
        att_events = [e for e in E.CustodyLog(fcase).entries() if e["event"] == "attest"]
        assert len(att_events) == 1 and att_events[0]["data"]["answers"]["blocker_model"] == "테스트 쓰기 방지 리더", "같은 증명은 한 번만 기록"
        lst = await call(c, "forensics_evidence_list", case_id=fcase.id, write_files=False)
        assert lst["items"][0]["attestation"]["status"] == "approved" and "files" not in lst


async def test_write_blocker_denied_is_recorded(fcase, image):
    from forensics_mcp.server import server
    from pweh import evidence as E
    from pweh.runtime import get_runtime

    async with Client(server) as c:
        await _intake(c, fcase, image)
        first = await call(c, "forensics_acquisition_attest", case_id=fcase.id, evidence_id="EV-0001")
        get_runtime("forensics-mcp").attestations.decide(first["attestation_id"], {**ATT_ANSWERS, "blocker_used": "no"}, via="cli-tty", by="tester")
        second = await call(c, "forensics_acquisition_attest", case_id=fcase.id, evidence_id="EV-0001")
        # 다시 부르면 새 요청이 생기고, 앞의 거부는 previous 로 알려 준다 — 보관 기록에는 거부가 남는다
        assert not second["ok"] and second["status"] == "attestation_required" and second["previous"]["status"] == "denied"
        st = E.replay_status(E.CustodyLog(fcase).entries(), "EV-0001")
        assert st["attestation"] == {"status": "denied", "attestation_id": first["attestation_id"], "ts": st["attestation"]["ts"]}
        await call(c, "forensics_acquisition_attest", case_id=fcase.id, evidence_id="EV-0001")
        assert sum(e["event"] == "attest" for e in E.CustodyLog(fcase).entries()) == 1, "같은 거부는 한 번만 기록"


async def test_evidence_list_empty_case(fcase):
    from forensics_mcp.server import server

    async with Client(server) as c:
        lst = await call(c, "forensics_evidence_list", case_id=fcase.id)
        assert lst["items"] == [] and "hint" in lst and "files" not in lst


async def test_report_has_evidence_section_and_detects_last_line_edit(fcase, image):
    from case_mcp.server import server as case_server
    from forensics_mcp.server import server
    from pweh import evidence as E

    async with Client(server) as c:
        await _intake(c, fcase, image, label="현관")
    async with Client(case_server) as cc:
        r = await call(cc, "report_generate", case_id=fcase.id)
        text = (fcase.dir / r["relative_path"]).read_text(encoding="utf-8")
        assert "## 8.1 SD 카드 증거" in text and "EV-0001" in text and "현관" in text
        assert "보호 위치의 고정점과 대조함" in text and E.FORENSICS_NOTICE in text and "깨짐" not in text
        # 마지막 줄만 고치면 체인은 통과하지만 보호 위치의 고정점과 다르다 → 보고서에 깨짐으로 나온다
        p = E.CustodyLog(fcase).path
        p.write_text(p.read_text(encoding="utf-8").replace('"site_type":"home"', '"site_type":"public"'), encoding="utf-8")
        r2 = await call(cc, "report_generate", case_id=fcase.id)
        text2 = (fcase.dir / r2["relative_path"]).read_text(encoding="utf-8")
        assert "깨짐" in text2 and "고정점과 다르다" in text2


async def test_report_without_forensics_has_no_evidence_section(fcase):
    from case_mcp.server import server as case_server

    async with Client(case_server) as cc:
        r = await call(cc, "report_generate", case_id=fcase.id)
        assert "SD 카드 증거" not in (fcase.dir / r["relative_path"]).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 검토 회귀 시험 (I3b): 비정규 파일·바꿔치기·기록 위조·번호 재사용·중단된 접수·늦은 취소·증거 목록 진실성
# ---------------------------------------------------------------------------


def _chmod_ev(case, ev: str, mode: int) -> None:
    os.chmod(case.dir / "forensics" / "images" / ev, mode)


class _FifoSentinel:
    """FIFO 를 누가 읽으려고 열면(서버가 열면 안 된다) 그 사실을 기록하고 바로 쓰기 쪽을 열었다 닫아 풀어 준다 —
    회귀가 생겨도 시험이 멈추지 않고(이벤트 루프를 막는 open 도 풀린다) opened 로 실패한다."""

    def __init__(self, *paths) -> None:
        self.paths = [str(p) for p in paths]
        self.opened: list[str] = []
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self._stop.is_set():
            for p in self.paths:
                try:
                    if not stat.S_ISFIFO(os.lstat(p).st_mode):
                        continue  # 아직 FIFO 가 아니다(일반 파일은 건드리지 않는다)
                    fd = os.open(p, os.O_WRONLY | os.O_NONBLOCK)
                except OSError:
                    continue  # ENXIO = 읽는 쪽 없음(정상), ENOENT = 이미 바뀜
                self.opened.append(p)
                os.close(fd)
            time.sleep(0.002)

    def __enter__(self) -> "_FifoSentinel":
        self._t.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self._t.join(5)


async def test_fifo_in_place_of_copy_record_or_custody_never_blocks(fcase, image):
    """#15·#29: 사본·접수 기록·보관 기록 자리의 FIFO 를 열고 기다리지 않는다 — 바로 integrity_failed/custody_broken, 서버는 계속 응답한다."""
    from forensics_mcp.server import server
    from pweh import evidence as E

    async with Client(server) as c:
        await _intake(c, fcase, image)
        await _intake(c, fcase, image)
        evdir = fcase.dir / "forensics/images/EV-0001"
        stored = evdir / "card.img"
        rec = fcase.dir / "forensics/images/EV-0002/EV-0002.json"
        cp = E.CustodyLog(fcase).path
        with _FifoSentinel(stored, rec, cp) as sentinel:
            _chmod_ev(fcase, "EV-0001", 0o755)
            stored.unlink()
            os.mkfifo(stored, 0o444)
            _chmod_ev(fcase, "EV-0001", 0o555)
            r = await asyncio.wait_for(call(c, "forensics_partitions", case_id=fcase.id, evidence_id="EV-0001"), 10)
            assert "integrity_failed" in r["_error"] and "일반 파일이 아닙니다" in r["_error"], r
            last = E.CustodyLog(fcase).entries()[-1]
            assert last["event"] == "integrity-failed" and last["data"]["reason"] == "stored-copy-not-regular"
            assert (await asyncio.wait_for(call(c, "forensics_jobs"), 5))["ok"]
            _chmod_ev(fcase, "EV-0002", 0o755)
            rec.unlink()
            os.mkfifo(rec)
            _chmod_ev(fcase, "EV-0002", 0o555)
            r = await asyncio.wait_for(call(c, "forensics_verify_start", case_id=fcase.id, evidence_id="EV-0002"), 10)
            assert "integrity_failed" in r["_error"], r
            raw = cp.read_bytes()
            cp.unlink()
            os.mkfifo(cp)
            r = await asyncio.wait_for(call(c, "forensics_partitions", case_id=fcase.id, evidence_id="EV-0002"), 10)
            assert "custody_broken" in r["_error"], r
            lst = await asyncio.wait_for(call(c, "forensics_evidence_list", case_id=fcase.id, write_files=False), 10)
            assert lst["custody"]["ok"] is False
        assert sentinel.opened == [], "서버가 FIFO 를 열었다"
        cp.unlink()
        cp.write_bytes(raw)


async def test_intake_copies_only_the_validated_source_fd(fcase, image, monkeypatch):
    """#16·#26: 검증한 뒤 원본 경로가 FIFO 로 바뀌어도 접수는 처음 연 fd 에서 확인한 크기만큼만 복사한다(경로를 다시 열지 않음)."""
    from forensics_mcp import server as S

    data = image.read_bytes()
    real_claim = S.E.claim_evidence_id

    def swap_then_claim(*a, **kw):
        image.unlink()
        os.mkfifo(image)  # 쓰는 쪽이 없는 FIFO — 경로로 다시 열면 영원히 멈춘다
        return real_claim(*a, **kw)

    monkeypatch.setattr(S.E, "claim_evidence_id", swap_then_claim)
    with _FifoSentinel(image) as sentinel:
        async with Client(S.server) as c:
            st = await asyncio.wait_for(_intake(c, fcase, image), 30)
    assert sentinel.opened == [], "접수가 원본 경로를 다시 열었다"
    res = st["result"]
    assert st["status"] == "succeeded" and res["hashes"]["sha256"] == hashlib.sha256(data).hexdigest()
    assert (fcase.dir / res["stored_path"]).read_bytes() == data
    assert sorted(p.name for p in (fcase.dir / "forensics/images/EV-0001").iterdir()) == ["EV-0001.json", "card.img"]


async def test_intake_source_changed_during_copy_rolls_back_and_returns_number(fcase, image, monkeypatch):
    from forensics_mcp import server as S

    real = S.safeio.hash_fd

    def grow(fd, size, **kw):
        if kw.get("out_fd") is not None:
            with open(image, "ab") as fh:
                fh.write(b"appended while copying")
        return real(fd, size, **kw)

    monkeypatch.setattr(S.safeio, "hash_fd", grow)
    async with Client(S.server) as c:
        r = await call(c, "forensics_intake_start", case_id=fcase.id, image_path=str(image), **LEGAL)
        st = await _wait(c, r["job_id"])
        assert st["status"] == "failed" and st["error"]["code"] == "integrity_failed" and "바뀌었습니다" in st["error"]["message"]
        assert not (fcase.dir / "forensics/images/EV-0001").exists()
        monkeypatch.setattr(S.safeio, "hash_fd", real)
        st2 = await _intake(c, fcase, image)
        assert st2["result"]["evidence_id"] == "EV-0001", "실패한 접수는 번호를 돌려놓는다"


async def test_imaging_log_refused_before_reading_and_capped(fcase, image, tmp_path):
    """#26·#34: 이미징 로그는 거부 검사(케이스·상태 폴더) 뒤에 fd 로 4 MiB 상한까지만 읽는다 — FIFO·큰 파일은 열거나 읽지 않는다."""
    from forensics_mcp.server import server

    inside = fcase.dir / "dumps" / "ftk.fifo"
    inside.parent.mkdir(exist_ok=True)
    os.mkfifo(inside)
    big = tmp_path / "evidence" / "big.txt"
    big.write_bytes(b"x" * ((4 << 20) + 1))
    fifo = tmp_path / "evidence" / "log.fifo"
    os.mkfifo(fifo)
    with _FifoSentinel(inside, fifo) as sentinel:
        async with Client(server) as c:
            r = await asyncio.wait_for(call(c, "forensics_intake_start", case_id=fcase.id, image_path=str(image), imaging_log_path=str(inside), **LEGAL), 10)
            assert "validation_failed" in r["_error"] and "케이스 폴더" in r["_error"]
            r = await asyncio.wait_for(call(c, "forensics_intake_start", case_id=fcase.id, image_path=str(image), imaging_log_path=str(fifo), **LEGAL), 10)
            assert "validation_failed" in r["_error"]
            r = await call(c, "forensics_intake_start", case_id=fcase.id, image_path=str(image), imaging_log_path=str(big), **LEGAL)
            assert "validation_failed" in r["_error"] and "너무 큽니다" in r["_error"]
    assert sentinel.opened == [], "이미징 로그 자리의 FIFO 를 열었다"
    assert not (fcase.dir / "forensics").exists()


async def test_intake_input_robustness(fcase, image, tmp_path, monkeypatch):
    """#34: NUL → validation_failed, 예약 이름(EV-NNNN.json·imaging-log.txt) 원본 거부, 여유 공간 거부는 디렉터리를 만들기 전, job 기록에 원본 경로 없음."""
    from forensics_mcp import server as S

    async with Client(S.server) as c:
        r = await call(c, "forensics_intake_start", case_id=fcase.id, image_path=str(image) + "\x00x", **LEGAL)
        assert "validation_failed" in r["_error"] and "NUL" in r["_error"]
        for name in ("EV-0001.json", "imaging-log.txt", "card.img.partial"):
            p = tmp_path / "evidence" / name
            p.write_bytes(b"\x00" * 4096)
            r = await call(c, "forensics_intake_start", case_id=fcase.id, image_path=str(p), **LEGAL)
            assert "validation_failed" in r["_error"] and "예약 이름" in r["_error"], (name, r)
        monkeypatch.setattr(S.shutil, "disk_usage", lambda p: shutil._ntuple_diskusage(1 << 40, (1 << 40) - 1000, 1000))
        r = await call(c, "forensics_intake_start", case_id=fcase.id, image_path=str(image), **LEGAL)
        assert "validation_failed" in r["_error"] and "여유 공간" in r["_error"]
        assert not (fcase.dir / "forensics").exists(), "여유 공간 거부는 디렉터리를 만들기 전에"
        monkeypatch.undo()
        st = await _intake(c, fcase, image)
        assert str(image.parent) not in json.dumps(st, ensure_ascii=False)
        job_file = fcase.dir / "jobs" / f"{st['job_id']}.json"
        assert str(image.parent) not in job_file.read_text(encoding="utf-8"), "원본 경로는 job 기록에 남기지 않는다(해시만)"
        assert st["meta"]["exclusive_key"].startswith("intake:")


async def test_record_forgery_is_caught_against_anchored_intake(fcase, image):
    """#13: 접수 기록 파일만 고쳐(사본 바꿔치기 + 해시·크기·지문 다시 씀) 통과하지 못한다 — 보관 기록 intake 사건(고정점)과 대조, 증명서는 고정점 해시."""
    from forensics_mcp.server import server
    from pweh import evidence as E

    async with Client(server) as c:
        orig = (await _intake(c, fcase, image))["result"]["hashes"]
        evdir = fcase.dir / "forensics/images/EV-0001"
        stored, recp = evdir / "card.img", evdir / "EV-0001.json"
        os.chmod(evdir, 0o755)
        os.chmod(stored, 0o644)
        forged = os.urandom(len(image.read_bytes()) + 4096)
        stored.write_bytes(forged)
        os.chmod(stored, 0o444)
        rec = json.loads(recp.read_text(encoding="utf-8"))
        rec["hashes"] = {a: hashlib.new(a, forged).hexdigest() for a in E.HASH_ALGORITHMS}
        rec["stored"]["size"] = len(forged)
        rec["fingerprint"] = E.fingerprint(stored)
        os.chmod(recp, 0o644)
        recp.write_text(json.dumps(rec, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(recp, 0o444)
        os.chmod(evdir, 0o555)
        for tool in ("forensics_partitions", "forensics_verify_start", "forensics_acquisition_attest"):
            r = await call(c, tool, case_id=fcase.id, evidence_id="EV-0001")
            assert "integrity_failed" in r.get("_error", ""), (tool, r)
        fails = [e["data"] for e in E.CustodyLog(fcase).entries() if e["event"] == "integrity-failed"]
        assert fails[0]["reason"] == "record-mismatch" and any("sha256" in p for p in fails[0]["problems"])
        lst = await call(c, "forensics_evidence_list", case_id=fcase.id)
        it = lst["items"][0]
        assert it["status"] == "integrity-failed" and it["hashes"]["sha256"] == orig["sha256"]
        md = (fcase.dir / lst["files"]["markdown"]).read_text(encoding="utf-8")
        assert orig["sha256"] in md and rec["hashes"]["sha256"] not in md, "해시값 확인서는 보관 기록(고정점)의 해시를 싣는다"


async def test_deleted_evidence_is_missing_number_not_reused_attestation_bound(fcase, image, tmp_path):
    """#17: 지운 EV 디렉터리는 missing 으로 남고 번호를 다시 쓰지 않는다. 다른 이미지는 앞 증거의 검증·증명을 물려받지 않는다."""
    from forensics_mcp.server import server
    from pweh.runtime import get_runtime

    img_b = tmp_path / "evidence" / "cardB.img"
    img_b.write_bytes(os.urandom(2 << 20))
    async with Client(server) as c:
        sha_a = (await _intake(c, fcase, image))["result"]["hashes"]["sha256"]
        first = await call(c, "forensics_acquisition_attest", case_id=fcase.id, evidence_id="EV-0001")
        get_runtime("forensics-mcp").attestations.decide(first["attestation_id"], ATT_ANSWERS, via="cli-tty", by="tester")
        assert (await call(c, "forensics_acquisition_attest", case_id=fcase.id, evidence_id="EV-0001"))["ok"]
        evdir = fcase.dir / "forensics/images/EV-0001"
        os.chmod(evdir, 0o755)
        shutil.rmtree(evdir)  # 사람이 디스크를 비우려고 지움
        lst = await call(c, "forensics_evidence_list", case_id=fcase.id, write_files=False)
        assert [(i["evidence_id"], i["status"]) for i in lst["items"]] == [("EV-0001", "missing")]
        assert lst["items"][0]["hashes"]["sha256"] == sha_a
        r = await call(c, "forensics_partitions", case_id=fcase.id, evidence_id="EV-0001")
        assert "integrity_failed" in r["_error"] and "지워짐" in r["_error"]
        st_b = await _intake(c, fcase, img_b, verify_copy=False)
        assert st_b["result"]["evidence_id"] == "EV-0002"
        lst = await call(c, "forensics_evidence_list", case_id=fcase.id, write_files=False)
        b = next(i for i in lst["items"] if i["evidence_id"] == "EV-0002")
        assert b["status"] == "unverified" and b["attestation"] is None and b["last_verify"] is None


async def test_attestation_shows_live_revoked_and_expired_status(fcase, image, monkeypatch, tmp_path):
    """#19: 사람이 철회했거나 만료된 증명은 증거 목록에 지금 상태로 보인다(보관 기록의 approved 를 그대로 믿지 않는다)."""
    from forensics_mcp.server import server
    from pweh.runtime import get_runtime
    from pweh.safety import attestations as A

    store = get_runtime("forensics-mcp").attestations
    img_b = tmp_path / "evidence" / "cardB.img"
    img_b.write_bytes(os.urandom(2 << 20))
    async with Client(server) as c:
        await _intake(c, fcase, image)
        await _intake(c, fcase, img_b)
        ids = {}
        for ev in ("EV-0001", "EV-0002"):
            first = await call(c, "forensics_acquisition_attest", case_id=fcase.id, evidence_id=ev)
            store.decide(first["attestation_id"], ATT_ANSWERS, via="cli-tty", by="tester")
            assert (await call(c, "forensics_acquisition_attest", case_id=fcase.id, evidence_id=ev))["ok"]
            ids[ev] = first["attestation_id"]
        store.revoke(ids["EV-0001"], by="tester")
        lst = await call(c, "forensics_evidence_list", case_id=fcase.id, write_files=False)
        att = {i["evidence_id"]: (i["attestation"] or {}).get("status") for i in lst["items"]}
        assert att == {"EV-0001": "revoked", "EV-0002": "approved"}
        later = A._now() + dt.timedelta(days=91)
        monkeypatch.setattr(A, "_now", lambda: later)
        lst = await call(c, "forensics_evidence_list", case_id=fcase.id)
        att = {i["evidence_id"]: (i["attestation"] or {}).get("status") for i in lst["items"]}
        assert att == {"EV-0001": "revoked", "EV-0002": "expired"}
        md = (fcase.dir / lst["files"]["markdown"]).read_text(encoding="utf-8")
        assert "| revoked |" in md and "| expired |" in md


async def test_custody_checked_before_copy_and_append_failure_rolls_back(fcase, image, monkeypatch):
    """#18·#31: 보관 기록이 깨졌으면 복사하기 전에 거부한다. intake 를 덧붙이지 못하면(디스크 가득 등) EV 디렉터리를 지우고 번호를 돌려놓는다."""
    from forensics_mcp import server as S
    from pweh import evidence as E

    images = fcase.dir / "forensics/images"
    async with Client(S.server) as c:
        await _intake(c, fcase, image)
        p = E.CustodyLog(fcase).path
        raw = p.read_bytes()
        p.write_bytes(raw.replace(b'"role":"owner"', b'"role":"investigator"'))
        r = await call(c, "forensics_intake_start", case_id=fcase.id, image_path=str(image), **LEGAL)
        assert "custody_broken" in r["_error"] and "job_id" not in r
        assert sorted(x.name for x in images.iterdir() if x.name.startswith("EV-")) == ["EV-0001"]
        p.write_bytes(raw)
        real_append = E.CustodyLog.append

        def failing(self, event, **kw):
            if event == "intake":
                raise OSError(errno.ENOSPC, "No space left on device")
            return real_append(self, event, **kw)

        monkeypatch.setattr(E.CustodyLog, "append", failing)
        r = await call(c, "forensics_intake_start", case_id=fcase.id, image_path=str(image), **LEGAL)
        st = await _wait(c, r["job_id"])
        assert st["status"] == "failed" and not (images / "EV-0002").exists()
        monkeypatch.setattr(E.CustodyLog, "append", real_append)
        assert (await _intake(c, fcase, image))["result"]["evidence_id"] == "EV-0002"


async def test_uncommitted_intake_dir_is_quarantined_and_number_consumed(fcase, image):
    """#27: 서버가 복사 중 끝나 남은 EV 디렉터리(intake 없음, 잠금 풀림)는 다음 접수·서버 시작 때 aborted-intakes/ 로 옮기고 번호를 소비한다."""
    from forensics_mcp.server import _startup_reconcile, server
    from pweh import evidence as E

    images = fcase.dir / "forensics/images"
    (images / "EV-0001").mkdir(parents=True)
    (images / "EV-0001" / "card.img.partial").write_bytes(b"\x00" * 1000)
    async with Client(server) as c:
        lst = await call(c, "forensics_evidence_list", case_id=fcase.id, write_files=False)
        assert lst["items"][0]["status"] == "record-without-intake" and "hashes" not in lst["items"][0]
        st = await _intake(c, fcase, image)
        assert st["result"]["evidence_id"] == "EV-0002"
        q = list((fcase.dir / "forensics/aborted-intakes").iterdir())
        assert len(q) == 1 and q[0].name.startswith("EV-0001-") and stat.S_IMODE((q[0] / "card.img.partial").stat().st_mode) == 0o444
        assert [(e["event"], e["evidence_id"]) for e in E.CustodyLog(fcase).entries()][:2] == [("intake-aborted", "EV-0001"), ("intake", "EV-0002")]
        lst = await call(c, "forensics_evidence_list", case_id=fcase.id)
        assert [(i["evidence_id"], i["status"]) for i in lst["items"]] == [("EV-0002", "ok")] and lst["aborted"][0]["evidence_id"] == "EV-0001"
        md = (fcase.dir / lst["files"]["markdown"]).read_text(encoding="utf-8")
        assert "중단된 접수" in md
    (images / "EV-0003").mkdir()
    moved = _startup_reconcile()
    assert [(m["case_id"], m["evidence_id"]) for m in moved] == [(fcase.id, "EV-0003")]


async def test_shutdown_cancels_running_intake_and_removes_partial_copy(fcase, image, monkeypatch):
    """#27: 서버를 끝낼 때(main 의 finally) 실행 중인 접수를 취소하고 기다린다 — 커밋 전이면 만든 파일을 지운다."""
    import anyio

    from forensics_mcp import server as S

    started = threading.Event()
    real = S.safeio.hash_fd

    def slow(fd, size, **kw):
        if kw.get("out_fd") is not None:
            started.set()
            end = time.monotonic() + 20
            while time.monotonic() < end:
                kw["check"]()  # 취소되면 JobCancelled
                time.sleep(0.01)
        return real(fd, size, **kw)

    monkeypatch.setattr(S.safeio, "hash_fd", slow)
    async with Client(S.server) as c:
        r = await call(c, "forensics_intake_start", case_id=fcase.id, image_path=str(image), **LEGAL)
        assert await anyio.to_thread.run_sync(started.wait, 10)
        assert (fcase.dir / "forensics/images/EV-0001").exists()
        await anyio.to_thread.run_sync(S._shutdown_cleanup)
        st = await call(c, "forensics_job_status", job_id=r["job_id"])
        assert st["status"] == "cancelled" and not (fcase.dir / "forensics/images/EV-0001").exists()


async def test_cancel_after_commit_reports_succeeded(fcase, image, monkeypatch):
    """#33: 보관 기록에 커밋한 뒤 도착한 취소는 결과를 바꾸지 않는다(succeeded)."""
    from forensics_mcp import server as S

    real_append = S.E.CustodyLog.append

    def append_then_cancel(self, event, **kw):
        entry = real_append(self, event, **kw)
        if event == "intake":
            for j in S.rt().jobs.list(active_only=True):
                S.rt().jobs.cancel(j["job_id"])
        return entry

    monkeypatch.setattr(S.E.CustodyLog, "append", append_then_cancel)
    async with Client(S.server) as c:
        st = await _intake(c, fcase, image)
    assert st["status"] == "succeeded" and st["result"]["evidence_id"] == "EV-0001"


async def test_evidence_list_fingerprints_copies_before_writing_certificate(fcase, image, tmp_path):
    """#21: 증거 목록은 사본마다 지문을 보고 문제를 무결성 실패로 남긴 뒤 증명서를 쓴다(잘린·지운 사본이 ok 로 나오지 않는다)."""
    from forensics_mcp.server import server
    from pweh import evidence as E

    img_b = tmp_path / "evidence" / "cardB.img"
    img_b.write_bytes(os.urandom(3 << 20))
    async with Client(server) as c:
        await _intake(c, fcase, image)
        await _intake(c, fcase, img_b)
        s1 = fcase.dir / "forensics/images/EV-0001/card.img"
        st = s1.stat()
        _chmod_ev(fcase, "EV-0001", 0o755)
        os.chmod(s1, 0o644)
        os.truncate(s1, 1 << 20)
        os.utime(s1, ns=(st.st_atime_ns, st.st_mtime_ns))
        os.chmod(s1, 0o444)
        _chmod_ev(fcase, "EV-0001", 0o555)
        _chmod_ev(fcase, "EV-0002", 0o755)
        (fcase.dir / "forensics/images/EV-0002/cardB.img").unlink()
        _chmod_ev(fcase, "EV-0002", 0o555)
        lst = await call(c, "forensics_evidence_list", case_id=fcase.id)
        assert {i["evidence_id"]: i["status"] for i in lst["items"]} == {"EV-0001": "integrity-failed", "EV-0002": "integrity-failed"}
        reasons = {e["evidence_id"]: e["data"]["reason"] for e in E.CustodyLog(fcase).entries() if e["event"] == "integrity-failed"}
        assert reasons == {"EV-0001": "fingerprint-mismatch", "EV-0002": "stored-copy-missing"}
        md = (fcase.dir / lst["files"]["markdown"]).read_text(encoding="utf-8")
        assert "| integrity-failed |" in md and "| ok |" not in md


async def test_derived_outputs_compared_with_custody_and_bad_manifest_skipped(fcase, image):
    """#22: recovered/ 매니페스트를 보관 기록 extract 사건과 대조한다(recorded/mismatch/unrecorded/missing). 객체가 아닌 매니페스트는 error 로 건너뛴다."""
    from forensics_mcp.server import custody, server

    async with Client(server) as c:
        await _intake(c, fcase, image)
        rec = fcase.dir / "forensics/recovered"

        def put(name: str, payload: bytes) -> str:
            (rec / name).mkdir(parents=True)
            (rec / name / "manifest.json").write_bytes(payload)
            return hashlib.sha256(payload).hexdigest()

        good = put("clip-001", json.dumps({"evidence_id": "EV-0001", "files": [{"size": 10}]}).encode())
        custody(fcase).append("extract", evidence_id="EV-0001", data={"output_dir": "forensics/recovered/clip-001", "manifest_sha256": good})
        put("clip-002", json.dumps({"evidence_id": "EV-0001", "files": [{"size": 123456789}]}).encode())
        custody(fcase).append("extract", evidence_id="EV-0001", data={"output_dir": "forensics/recovered/clip-002", "manifest_sha256": "0" * 64})
        put("planted-001", json.dumps({"evidence_id": "EV-0001", "files": [{"size": "x"}]}).encode())
        put("list-001", b"[1, 2]")
        custody(fcase).append("extract", evidence_id="EV-0001", data={"output_dir": "forensics/recovered/gone-001", "manifest_sha256": "1" * 64})
        lst = await call(c, "forensics_evidence_list", case_id=fcase.id)
        assert lst["ok"], lst
        d = {x["path"].rsplit("/", 1)[-1]: x for x in lst["derived"]}
        assert d["clip-001"]["custody"] == "recorded" and d["clip-001"]["bytes"] == 10
        assert d["clip-002"]["custody"] == "mismatch"
        assert d["planted-001"]["custody"] == "unrecorded" and d["planted-001"]["bytes"] == 0
        assert "error" in d["list-001"] and d["list-001"]["custody"] == "unrecorded"
        assert d["gone-001"]["custody"] == "missing"


async def test_symlinked_forensics_dir_refused_nothing_written_outside(fcase, image, tmp_path):
    """#7·#28: forensics/ 가 링크면 따라가 쓰지 않는다 — 접수는 보관 기록을 믿을 수 없어 거부(custody_broken), 밖에는 아무것도 생기지 않는다."""
    from forensics_mcp.server import server

    outside = tmp_path / "outside"
    outside.mkdir()
    (fcase.dir / "forensics").symlink_to(outside)
    async with Client(server) as c:
        r = await call(c, "forensics_intake_start", case_id=fcase.id, image_path=str(image), **LEGAL)
        assert "custody_broken" in r["_error"], r
        lst = await call(c, "forensics_evidence_list", case_id=fcase.id)
        assert lst["custody"]["ok"] is False
    assert not any(outside.iterdir())


# ---------------------------------------------------------------------------
# 검증 재실행 회귀 시험 (I3b batch 2): verify 의 늦은 취소, 커밋 뒤 보조 기록 실패, 증거 목록 md 의 status_label
# ---------------------------------------------------------------------------


async def test_verify_late_cancel_after_hashing_is_recorded_and_succeeds(fcase, image, monkeypatch):
    """재해시가 끝난 뒤(보관 기록 verify 를 덧붙이기 전·후)에 온 취소는 결과를 바꾸지 않는다 — job succeeded, verify 사건이 남는다."""
    from forensics_mcp import server as S
    from pweh import evidence as E

    responses: list[str] = []

    def cancel_jobs() -> None:
        for j in S.rt().jobs.list(active_only=True):
            responses.append(S.rt().jobs.cancel(j["job_id"]).status)

    async with Client(S.server) as c:
        await _intake(c, fcase, image)
        real_hash = S.safeio.hash_fd

        def hash_then_cancel(fd, size, **kw):
            out = real_hash(fd, size, **kw)
            cancel_jobs()  # 재해시는 끝났고 verify 는 아직 기록하지 않았다
            return out

        monkeypatch.setattr(S.safeio, "hash_fd", hash_then_cancel)
        v = await call(c, "forensics_verify_start", case_id=fcase.id, evidence_id="EV-0001")
        st = await _wait(c, v["job_id"])
        assert responses == ["cancelling"] and st["status"] == "succeeded" and st["result"]["result"] == "match", st
        monkeypatch.setattr(S.safeio, "hash_fd", real_hash)

        real_append = E.CustodyLog.append

        def append_then_cancel(self, event, **kw):
            entry = real_append(self, event, **kw)
            if event == "verify":
                cancel_jobs()
            return entry

        monkeypatch.setattr(E.CustodyLog, "append", append_then_cancel)
        v = await call(c, "forensics_verify_start", case_id=fcase.id, evidence_id="EV-0001")
        st = await _wait(c, v["job_id"])
        assert responses[1:] == ["running"] and st["status"] == "succeeded", (responses, st)
        events = [(e["event"], e["data"].get("result")) for e in E.CustodyLog(fcase).entries()]
        assert events == [("intake", None), ("verify", "match"), ("verify", "match")]


async def test_intake_post_commit_failures_return_committed_result(fcase, image, monkeypatch):
    """I-N2: 커밋(보관 기록 intake) 뒤의 보조 기록 실패는 접수를 실패로 만들지 않는다 — evidence_id 와 무엇을 남기지 못했는지를 돌려준다.
    사본 재해시 불일치 + integrity-failed 사건 기록 실패(ENOSPC)면 ok=false 이고, 상태는 intake 사건(copy_verified=false)만으로 integrity-failed."""
    from forensics_mcp import server as S
    from pweh import evidence as E
    from pweh.case import Case

    real_hash = S.safeio.hash_fd
    real_append = E.CustodyLog.append

    def corrupt_verify(fd, size, **kw):  # 이미지 사본 재해시만 다른 값을 낸다(접수 기록 해시에는 영향 없음)
        out = real_hash(fd, size, **kw)
        if kw.get("out_fd") is None and size == image.stat().st_size:
            return {a: "0" * len(h) for a, h in out.items()}
        return out

    def no_space_for_integrity(self, event, **kw):
        if event == "integrity-failed":
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_append(self, event, **kw)

    def index_boom(self, *a, **kw):
        raise RuntimeError("case.json 쓰기 흉내 오류")

    async with Client(S.server) as c:
        monkeypatch.setattr(S.safeio, "hash_fd", corrupt_verify)
        monkeypatch.setattr(E.CustodyLog, "append", no_space_for_integrity)
        monkeypatch.setattr(Case, "register_artifact", index_boom)
        st = await _intake(c, fcase, image)
        monkeypatch.undo()
        res = st["result"]
        assert st["status"] == "succeeded" and res["evidence_id"] == "EV-0001", st
        assert res["ok"] is False and res["copy_verified"] is False and res["custody_seq"] == 1
        assert "integrity-failed 사건은 기록하지 못했습니다" in res["error"]
        errs = res["post_commit_errors"]
        assert len(errs) == 2 and errs[0].startswith("보관 기록 integrity-failed 사건: OSError") and errs[1].startswith("아티팩트 색인")
        assert "커밋됐습니다" in res["note"]
        assert [e["event"] for e in E.CustodyLog(fcase).entries()] == ["intake"]
        lst = await call(c, "forensics_evidence_list", case_id=fcase.id, write_files=False)
        assert [(i["evidence_id"], i["status"]) for i in lst["items"]] == [("EV-0001", "integrity-failed")]
        r = await call(c, "forensics_partitions", case_id=fcase.id, evidence_id="EV-0001")
        assert "integrity_failed" in r["_error"]

        monkeypatch.setattr(Case, "register_artifact", index_boom)  # 사본은 맞고 보조 기록만 실패 → ok 는 그대로
        st2 = await _intake(c, fcase, image)
        monkeypatch.undo()
        r2 = st2["result"]
        assert st2["status"] == "succeeded" and r2["ok"] is True and r2["evidence_id"] == "EV-0002" and "error" not in r2
        assert len(r2["post_commit_errors"]) == 1 and r2["post_commit_errors"][0].startswith("아티팩트 색인") and r2["note"]


async def test_verify_mismatch_integrity_event_failure_keeps_recorded_result(fcase, image, monkeypatch):
    """verify 불일치는 기록됐는데 뒤따르는 integrity-failed 사건만 못 남기면 job 을 실패로 만들지 않는다(상태는 verify 사건만으로 integrity-failed)."""
    from forensics_mcp import server as S
    from pweh import evidence as E

    async with Client(S.server) as c:
        await _intake(c, fcase, image)
        real_hash = S.safeio.hash_fd
        real_append = E.CustodyLog.append
        monkeypatch.setattr(S.safeio, "hash_fd", lambda fd, size, **kw: {a: "0" * len(h) for a, h in real_hash(fd, size, **kw).items()})

        def no_space_for_integrity(self, event, **kw):
            if event == "integrity-failed":
                raise OSError(errno.ENOSPC, "No space left on device")
            return real_append(self, event, **kw)

        monkeypatch.setattr(E.CustodyLog, "append", no_space_for_integrity)
        v = await call(c, "forensics_verify_start", case_id=fcase.id, evidence_id="EV-0001")
        st = await _wait(c, v["job_id"])
        monkeypatch.undo()
        res = st["result"]
        assert st["status"] == "succeeded" and res["result"] == "mismatch" and res["ok"] is False, st
        assert res["post_commit_errors"][0].startswith("보관 기록 integrity-failed 사건: OSError") and res["note"]
        assert [e["event"] for e in E.CustodyLog(fcase).entries()] == ["intake", "verify"]
        assert E.replay_status(E.CustodyLog(fcase).entries(), "EV-0001")["status"] == "integrity-failed"


def test_evidence_markdown_renders_status_label(fcase):
    """G-N3: 증거 목록 md 는 evidence_items 의 status_label(예: 'missing (integrity-failed)')을 싣고, 없으면 status 를 싣는다."""
    from forensics_mcp.server import _evidence_markdown

    items = {
        "custody": {"ok": True, "count": 3, "head": "ab" * 32},
        "items": [
            {"evidence_id": "EV-0001", "status": "missing", "status_label": "missing (integrity-failed)", "size": 10,
             "hashes": {"sha256": "1" * 64, "md5": "2" * 32, "sha1": "3" * 40}, "last_verify": {"result": "match", "ts": "t"}},
            {"evidence_id": "EV-0002", "status": "unverified", "size": 20, "hashes": {"sha256": "4" * 64}},
        ],
        "aborted": [],
    }
    md = _evidence_markdown(fcase, items, [])
    assert "| missing (integrity-failed) | match (t) |" in md and "| unverified | 없음 |" in md
    assert "(상태: missing (integrity-failed))" in md and "(상태: unverified)" in md
