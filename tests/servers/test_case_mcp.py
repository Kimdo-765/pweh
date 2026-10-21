"""case-mcp 참조 서버 테스트: in-memory + stdio."""

from __future__ import annotations

import os

import pytest
from mcp import Client

from mcp_helpers import call, stdio_params

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def test_case_lifecycle_inmemory(workspace, auth):
    from case_mcp.server import server

    async with Client(server) as c:
        tools = {t.name for t in (await c.list_tools()).tools}
        for name in ("case_create", "case_record_step", "case_add_finding", "report_generate", "case_paths", "approval_status"):
            assert name in tools

        # authorization 없이 생성하면 실패
        r = await call(c, "case_create", title="t", authorization={"basis": "owned"})
        assert "_error" in r and "owner" in r["_error"]

        r = await call(c, "case_create", title="랩 카메라", authorization=auth, target={"vendor": "Acme", "model": "IPC-1"}, profile="generic-ipcam")
        assert r["ok"] is True
        cid = r["case"]["id"]
        assert r["case"]["authorized"] is True

        paths = await call(c, "case_paths", case_id=cid, purpose="extract", label="rea")
        assert paths["new_output_dir"].endswith("rea-001")
        assert not os.path.exists(paths["new_output_dir"])

        # summary 단계는 스키마 검증
        bad = await call(c, "case_record_step", case_id=cid, skill="uart-shell-acquisition", step="summary", status="success", summary="x", data={"port": "/dev/ttyUSB0"})
        assert "_error" in bad and "uart-recon" in bad["_error"]
        good = await call(
            c, "case_record_step", case_id=cid, skill="uart-shell-acquisition", step="summary", status="success",
            summary="U-Boot 획득", data={"port": "/dev/ttyUSB0", "baudrate": 115200, "console_type": "uboot", "access_level": "uboot"},
        )
        assert good["ok"] and good["seq"] == 1

        res = await call(c, "case_get_step_results", case_id=cid)
        assert "uart-shell-acquisition" in res["summaries"]
        assert "firmware-dump-via-uart" in res["missing"]

        f = await call(
            c, "case_add_finding", case_id=cid,
            finding={
                "title": "하드코딩된 root 비밀번호 해시",
                "category": "hardcoded-credential", "severity": "high", "confidence": "confirmed",
                "summary": "/etc/shadow 에 고정 해시", "location": {"file": "/etc/shadow"},
                "evidence": [{"type": "file", "ref": "extract/run-001/etc/shadow", "excerpt": "root:$1$abc$..."}],
                "reasoning": "모든 기기에 동일 해시가 배포되는 구조",
            },
        )
        assert f["finding_id"] == "F-001"
        dup = await call(c, "case_add_finding", case_id=cid, finding={**f["finding"], "id": None})
        assert dup.get("duplicate") is True

        rep = await call(c, "report_generate", case_id=cid)
        assert rep["ok"] and rep["findings"] == 1
        text = open(rep["path"], encoding="utf-8").read()
        assert "하드코딩된 root 비밀번호 해시" in text and "본인 소유" in text

        pol = await call(c, "pipeline_safety_policy")
        assert pol["effective"]["destructive"] == "deny"


async def test_case_mcp_stdio(workspace, auth):
    params = stdio_params("case_mcp", env={"PWEH_CONFIG": str(workspace["config"])})
    async with Client(params, read_timeout_seconds=60) as c:
        tools = {t.name for t in (await c.list_tools()).tools}
        assert "case_create" in tools
        r = await call(c, "case_create", title="stdio", authorization=auth)
        assert r["ok"], r
        lst = await call(c, "case_list")
        assert any(x["id"] == r["case"]["id"] for x in lst["cases"])


async def test_report_uses_latest_summary_only(workspace, auth):
    from case_mcp.server import server

    async with Client(server) as c:
        r = await call(c, "case_create", title="dup", authorization=auth)
        cid = r["case"]["id"]
        data = {"vendor_family": "generic", "web_components": [], "checks": [], "finding_ids": [], "coverage_gaps": ["게이트-중복-확인"]}
        for summary in ("첫 번째 요약", "두 번째 요약"):
            await call(c, "case_record_step", case_id=cid, skill="cctv-auth-bypass-hunt", step="summary", status="success", summary=summary, data=data)
        rep = await call(c, "report_generate", case_id=cid)
        text = open(rep["path"], encoding="utf-8").read()
        assert "두 번째 요약" in text and "첫 번째 요약" not in text
        assert text.count("게이트-중복-확인") == 1


async def test_case_hash_file(workspace, auth):
    import hashlib
    import zlib

    from case_mcp.server import server

    async with Client(server) as c:
        r = await call(c, "case_create", title="hash", authorization=auth)
        cid = r["case"]["id"]
        data = bytes(range(256)) * 512
        (workspace["cases_dir"] / cid / "dumps" / "x.bin").write_bytes(data)
        h = await call(c, "case_hash_file", case_id=cid, path="dumps/x.bin", offset="0x100", length="64k")
        part = data[0x100 : 0x100 + 0x10000]
        assert h["sha256"] == hashlib.sha256(part).hexdigest() and h["md5"] == hashlib.md5(part).hexdigest()
        assert h["crc32"] == f"{zlib.crc32(part) & 0xFFFFFFFF:08x}"
        bad = await call(c, "case_hash_file", case_id=cid, path="dumps/x.bin", offset=0, length=len(data) + 1)
        assert "_error" in bad
        esc = await call(c, "case_hash_file", case_id=cid, path="/etc/passwd")
        assert "_error" in esc


async def test_case_import_file(workspace, auth, tmp_path):
    """케이스 밖 파일(벤더 공식 펌웨어·SPI 클립 덤프)을 케이스로 복사·등록한다. 허용 목록 밖 dest_subdir·없는 원본·같은 이름은 거부."""
    import hashlib

    from case_mcp.server import server

    src = tmp_path / "vendor_fw.bin"
    data = b"PWEHFW" + bytes(range(256)) * 64
    src.write_bytes(data)
    async with Client(server) as c:
        cid = (await call(c, "case_create", title="import", authorization=auth))["case"]["id"]
        r = await call(c, "case_import_file", case_id=cid, source_path=str(src), kind="firmware-image", dest_subdir="dumps",
                       description="벤더 공식 펌웨어")
        assert r["ok"], r
        assert r["artifact"]["path"] == "dumps/vendor_fw.bin" and r["artifact"]["sha256"] == hashlib.sha256(data).hexdigest()
        assert (workspace["cases_dir"] / cid / "dumps" / "vendor_fw.bin").read_bytes() == data
        h = await call(c, "case_hash_file", case_id=cid, path="dumps/vendor_fw.bin")
        assert h["sha256"] == r["artifact"]["sha256"]
        got = await call(c, "case_get", case_id=cid, include_artifacts=True)
        art = next(a for a in got["artifacts"] if a.get("path") == "dumps/vendor_fw.bin")
        assert art["kind"] == "firmware-image" and art["extra"]["imported_from"].endswith("vendor_fw.bin")
        again = await call(c, "case_import_file", case_id=cid, source_path=str(src))
        assert "_error" in again  # 같은 이름의 파일이 이미 있음
        bad_dir = await call(c, "case_import_file", case_id=cid, source_path=str(src), dest_subdir="steps")
        assert "_error" in bad_dir
        missing = await call(c, "case_import_file", case_id=cid, source_path=str(tmp_path / "nope.bin"))
        assert "_error" in missing


async def test_case_import_file_refuses_case_forensics_folders(workspace, auth):
    """카드 이미지·복구 녹화(cases/<id>/forensics/)를 dumps/ 로 복사해 자동 허용 도구가 읽게 하는 우회를 막는다(링크도 풀어서 판단)."""
    from case_mcp.server import server

    async with Client(server) as c:
        cid = (await call(c, "case_create", title="sd", authorization=auth))["case"]["id"]
        other = (await call(c, "case_create", title="sd2", authorization=auth))["case"]["id"]
        rec = workspace["cases_dir"] / other / "forensics" / "recovered" / "clip-001"
        rec.mkdir(parents=True)
        (rec / "000001.mp4").write_bytes(b"\x00\x00\x00\x18ftypmp42")
        r = await call(c, "case_import_file", case_id=cid, source_path=str(rec / "000001.mp4"))
        assert "validation_failed" in r["_error"] and "forensics" in r["_error"]
        own = workspace["cases_dir"] / cid / "forensics" / "images" / "EV-0001"
        own.mkdir(parents=True)
        (own / "card.img").write_bytes(b"\x00" * 512)
        link = workspace["root"] / "innocent.img"
        link.symlink_to(own / "card.img")
        r = await call(c, "case_import_file", case_id=cid, source_path=str(link))
        assert "validation_failed" in r["_error"]


async def test_step_results_survive_server_restart(workspace, auth):
    """세션·서버가 끊겨도 케이스 파일만으로 이전 Skill 결과(hand-off)를 이어 읽는다."""
    from case_mcp.server import server
    from pweh.runtime import reset_runtimes

    async with Client(server) as c:
        cid = (await call(c, "case_create", title="resume", authorization=auth))["case"]["id"]
        rec = await call(c, "case_record_step", case_id=cid, skill="uart-shell-acquisition", step="summary", status="success",
                         summary="U-Boot 획득", data={"port": "/dev/ttyUSB0", "baudrate": 115200, "console_type": "uboot",
                                                     "access_level": "uboot"})
        assert rec["ok"], rec
    reset_runtimes()  # 서버 프로세스 재시작과 같은 효과: 메모리 상태 없이 디스크의 케이스만 남는다
    async with Client(server) as c2:
        listed = await call(c2, "case_list")
        assert any(x.get("id") == cid for x in listed.get("cases", [])), listed
        res = await call(c2, "case_get_step_results", case_id=cid)
        summ = res["summaries"]["uart-shell-acquisition"]
        assert summ["data"]["baudrate"] == 115200 and summ["status"] == "success"
        assert "firmware-dump-via-uart" in res["missing"]


async def test_case_import_file_records_only_unattested_provenance(workspace, auth, tmp_path):
    """case_import_file 은 출처 원장에 imported-unattested 만 남긴다: 덤프처럼 보이는 이름·kind·producer 로도 기기 읽기(device-read)가 되지 않고,
    사람의 provenance-import 증명(같은 sha256·같은 케이스)이 있을 때만 신뢰된다."""
    import json

    from case_mcp.server import server
    from pweh.provenance import PROVENANCE_IMPORT_QUESTIONS, provenance_import_target
    from pweh.runtime import get_runtime

    src = tmp_path / "esp-flash.bin"
    src.write_bytes(b"DOWNLOADED-DUMP" * 512)
    async with Client(server) as c:
        cid = (await call(c, "case_create", title="import provenance", authorization=auth))["case"]["id"]
        r = await call(c, "case_import_file", case_id=cid, source_path=str(src), kind="flash-dump", dest_subdir="dumps",
                       description="esptool 플래시 덤프 (esp-mcp)")
        assert r["ok"], r
        prov = r["provenance"]
        assert prov["recorded"] is True and prov["kind"] == "imported-unattested" and prov["sha256"] == r["artifact"]["sha256"]
        # producer 를 바꿔 등록해도(case_register_artifact) 출처는 바뀌지 않는다
        reg = await call(c, "case_register_artifact", case_id=cid, path="dumps/esp-flash.bin", kind="flash-dump", producer="esp-mcp")
        assert reg["ok"], reg
    rt = get_runtime("case-mcp")
    case = rt.cases.get(cid)
    entries = rt.provenance.entries(case)
    assert [e["kind"] for e in entries] == ["imported-unattested"]
    assert entries[0]["source"]["server"] == "case-mcp" and entries[0]["source"]["tool"] == "case_import_file"
    assert entries[0]["source"]["imported_from"] == str(src.resolve())
    v = rt.provenance.verify(case, "dumps/esp-flash.bin")
    assert v["trusted"] is False and v["kind"] == "imported-unattested" and v["reason"] == "imported-unattested"
    meta = json.loads(case.meta_path.read_text(encoding="utf-8"))
    assert meta["artifacts"][0]["producer"] == "esp-mcp"  # case.json 은 에이전트 값 그대로 — 출처 확인은 보지 않는다
    assert rt.provenance.verify(case, "dumps/esp-flash.bin")["trusted"] is False
    # 사람 증명 (서버 도우미 → pweh attest 대신 저장소에 사람의 결정을 기록)
    kind, subject, binding = provenance_import_target(cid, v["sha256"])
    dec = await rt.attest(kind, subject, binding, list(PROVENANCE_IMPORT_QUESTIONS), cid, None, "가져온 덤프 출처 확인")
    assert dec.status == "attestation_required"
    rt.attestations.decide(dec.attestation_id, {"source_known": "yes", "how_obtained": "SOIC 클립 + CH341A"}, via="cli-tty", by="tester")
    v2 = rt.provenance.verify(case, "dumps/esp-flash.bin")
    assert v2["trusted"] is True and v2["reason"] == "imported-attested" and v2["attestation_id"] == dec.attestation_id
    # 증명이 있어도 원장 항목은 여전히 imported-unattested 하나뿐 (device-read 를 만드는 경로가 없다)
    assert [e["kind"] for e in rt.provenance.entries(case)] == ["imported-unattested"]


async def test_case_import_file_survives_broken_ledger(workspace, auth, tmp_path):
    """원장이 깨져 있으면 기록하지 않고(fail closed) 알리기만 한다 — 가져오기 자체는 된다."""
    from case_mcp.server import server

    src = tmp_path / "fw.bin"
    src.write_bytes(b"fw")
    async with Client(server) as c:
        cid = (await call(c, "case_create", title="broken ledger", authorization=auth))["case"]["id"]
        ledger = workspace["state_dir"] / "provenance" / f"{cid}.jsonl"
        ledger.parent.mkdir(parents=True, exist_ok=True)
        ledger.write_text("{garbage\n", encoding="utf-8")
        r = await call(c, "case_import_file", case_id=cid, source_path=str(src))
    assert r["ok"] and r["provenance"]["recorded"] is False and "provenance_ledger_broken" in r["provenance"]["reason"], r
    assert ledger.read_text(encoding="utf-8") == "{garbage\n"


async def test_case_import_file_refuses_protected_state(workspace, auth, tmp_path):
    """보호 상태(state_dir)의 파일은 가져올 수 없다 — 솔트·승인 레코드를 케이스로 복사한 뒤 case_hash_file 로 바이트를 읽어 내는 경로를 막는다.
    링크나 '..' 로 돌아가도 실제 경로로 판단하고, 케이스에는 아무 파일도 생기지 않는다."""
    from case_mcp.server import server
    from pweh.runtime import get_runtime

    state = workspace["state_dir"]
    async with Client(server) as c:
        cid = (await call(c, "case_create", title="state import", authorization=auth))["case"]["id"]
        rt = get_runtime("case-mcp")
        rt.salts.salt(cid)  # 솔트를 만든다
        salt = rt.salts.salt_path(cid)
        appr = state / "approvals" / "ap-0123456789.json"
        appr.parent.mkdir(parents=True, exist_ok=True)
        appr.write_text('{"code": "WHAE"}', encoding="utf-8")
        link = tmp_path / "innocent.bin"
        link.symlink_to(salt)
        dotted = state / "salts" / ".." / "salts" / salt.name
        for src in (salt, appr, link, dotted):
            r = await call(c, "case_import_file", case_id=cid, source_path=str(src), kind="other", dest_subdir="notes")
            assert "[validation_failed]" in r.get("_error", ""), (src, r)
        notes = rt.cases.get(cid).dir / "notes"
        assert sorted(x.name for x in notes.iterdir()) == []
        assert rt.cases.get(cid).artifacts() == []
        # 케이스 밖의 일반 파일은 그대로 가져온다
        ok = tmp_path / "board.jpg"
        ok.write_bytes(b"jpeg")
        r = await call(c, "case_import_file", case_id=cid, source_path=str(ok), kind="other", dest_subdir="notes")
        assert r["ok"] and r["artifact"]["path"] == "notes/board.jpg", r


def test_import_file_never_writes_through_destination_link(workspace, auth, tmp_path):
    """대상 이름에 (끊어진) 심볼릭 링크가 있으면 링크를 따라 케이스 밖에 쓰지 않고 거부한다(O_EXCL). 복사하면서 계산한 sha256 이 아티팩트에 실린다."""
    import hashlib

    from pweh.errors import CaseError
    from pweh.runtime import get_runtime

    rt = get_runtime("test")
    case = rt.cases.create(title="link", authorization=auth, case_id="link-case")
    outside = tmp_path / "outside" / "att-00000000aa.json"
    outside.parent.mkdir()
    src = tmp_path / "att-00000000aa.json"
    src.write_text('{"forged": true}', encoding="utf-8")
    (case.dir / "notes" / "att-00000000aa.json").symlink_to(outside)  # 끊어진 링크
    with pytest.raises(CaseError):
        case.import_file(src, "notes", kind="other", producer="test")
    assert not outside.exists()
    data = b"\x5a" * 3_000_000  # 여러 블록
    big = tmp_path / "fw.bin"
    big.write_bytes(data)
    art = case.import_file(big, "dumps", kind="firmware-image", producer="test")
    assert art["sha256"] == hashlib.sha256(data).hexdigest() and art["size"] == len(data)
    assert (case.dir / "dumps" / "fw.bin").read_bytes() == data


async def test_step_results_missing_counts_only_pipeline_and_started_optional_skills(workspace, auth):
    """missing 은 보안 분석 파이프라인 Skill 과 이 케이스에서 시작한 선택 Skill 만 센다(CCTV 케이스에 게임 Skill 이 끼지 않음)."""
    from case_mcp.server import server

    async with Client(server) as c:
        cid = (await call(c, "case_create", title="missing", authorization=auth))["case"]["id"]
        r = await call(c, "case_get_step_results", case_id=cid)
        assert "game-save-unlock-analysis" not in r["missing"] and "firmware-static-analysis" in r["missing"], r
        await call(c, "case_set_phase", case_id=cid, phase="game-save-unlock-analysis", status="in-progress")
        r = await call(c, "case_get_step_results", case_id=cid)
        assert "game-save-unlock-analysis" in r["missing"], r
        r = await call(c, "case_get_step_results", case_id=cid, skill="game-save-unlock-analysis")
        assert r["missing"] == ["game-save-unlock-analysis"]


async def test_pipeline_environment_reports_env_and_routes(workspace, monkeypatch):
    """pipeline_environment: 주입한 가짜 probe 로 보고서 + routes 를 돌려준다(실제 호스트를 읽지 않음). 휘발 목록은 없다."""
    from case_mcp.server import server
    from core.hostenv_fixtures import wsl2
    from pweh import hostenv

    from pweh.runtime import reset_runtimes

    probe = wsl2(mode="bridged")
    monkeypatch.setattr(hostenv, "_default_probe", lambda: probe)
    monkeypatch.delenv("PWEH_ESPTOOL_WIN", raising=False)  # 설정의 ${PWEH_ESPTOOL_WIN} 이 실제 값으로 확장되지 않게
    reset_runtimes()
    async with Client(server) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
        assert tools["pipeline_environment"].annotations.read_only_hint is True
        r = await call(c, "pipeline_environment")
        assert r["ok"] and r["report"]["kind"] == "WSL2_INTEROP" and r["report"]["schema"] == "pweh.hostenv/v1"
        assert r["report"]["wsl"]["networking_mode"] == "bridged"
        assert {row["device"] for row in r["routes"]} >= {"serial", "esptool", "openocd", "sigrok", "block"}
        assert not ({"ports", "listeners", "com_ports"} & set(r["report"]))
        n = len(probe.calls)
        again = await call(c, "pipeline_environment")
        assert again["report"]["kind"] == "WSL2_INTEROP" and len(probe.calls) == n  # 캐시
        fresh = await call(c, "pipeline_environment", refresh=True)
        assert fresh["ok"] and len(probe.calls) > n


async def test_case_hash_and_register_refuse_forensics_and_fifo(workspace, auth):
    """case_hash_file·case_register_artifact(자동 허용)는 증거 폴더를 읽지 않는다 — 짧은 구간의 crc32 로 녹화 바이트를 되살리는 우회를 막는다.
    링크로 가리켜도(dumps/ 의 심볼릭 링크) 막고, FIFO 앞에서 멈추지 않는다."""
    import time

    from case_mcp.server import server

    async with Client(server) as c:
        cid = (await call(c, "case_create", title="sd", authorization=auth))["case"]["id"]
        cdir = workspace["cases_dir"] / cid
        rec = cdir / "forensics" / "recovered" / "clip-001"
        rec.mkdir(parents=True)
        (rec / "0001-clip.mp4").write_bytes(b"SYNTH-REC-FRAME-7731" * 10)
        for path in ("forensics/recovered/clip-001/0001-clip.mp4", str(rec / "0001-clip.mp4")):
            r = await call(c, "case_hash_file", case_id=cid, path=path, offset=0, length=4)
            assert "validation_failed" in r["_error"] and "forensics" in r["_error"], r
            r = await call(c, "case_register_artifact", case_id=cid, path=path, kind="other")
            assert "validation_failed" in r["_error"], r
        (cdir / "dumps").mkdir(exist_ok=True)
        (cdir / "dumps" / "innocent.bin").symlink_to(rec / "0001-clip.mp4")
        r = await call(c, "case_hash_file", case_id=cid, path="dumps/innocent.bin", offset=0, length=1)
        assert "validation_failed" in r["_error"], r
        os.mkfifo(cdir / "dumps" / "pipe.bin")
        t0 = time.monotonic()
        r = await call(c, "case_hash_file", case_id=cid, path="dumps/pipe.bin")
        assert "validation_failed" in r["_error"] and time.monotonic() - t0 < 5, r
        t0 = time.monotonic()
        r = await call(c, "case_register_artifact", case_id=cid, path="dumps/pipe.bin", kind="other")
        assert "validation_failed" in r["_error"] and time.monotonic() - t0 < 5, r
        (cdir / "dumps" / "ok.bin").write_bytes(b"hello world")
        r = await call(c, "case_hash_file", case_id=cid, path="dumps/ok.bin", offset=6, length=5)
        assert r["ok"] and r["length"] == 5 and r["sha256"] == __import__("hashlib").sha256(b"world").hexdigest(), r
        r = await call(c, "case_register_artifact", case_id=cid, path="dumps/ok.bin", kind="other")
        assert r["ok"] and r["artifact"]["sha256"] == __import__("hashlib").sha256(b"hello world").hexdigest(), r
        r = await call(c, "case_register_artifact", case_id=cid, path="dumps", kind="extracted-tree")
        assert r["ok"] and r["artifact"]["is_dir"] is True and "sha256" not in r["artifact"], r


async def test_case_import_file_refuses_the_case_path_when_forensics_is_a_link(workspace, auth):
    """forensics/ 를 케이스 밖으로 옮기고 링크로 되돌려도, 케이스의 forensics/ 아래 경로로 부르면 가져오지 않는다
    (링크를 푼 경로만 보면 케이스 밖이라 통과하던 우회)."""
    from case_mcp.server import server

    async with Client(server) as c:
        cid = (await call(c, "case_create", title="sd", authorization=auth))["case"]["id"]
        cdir = workspace["cases_dir"] / cid
        rec = cdir / "forensics" / "recovered" / "clip-001"
        rec.mkdir(parents=True)
        (rec / "0001-clip.mp4").write_bytes(b"SYNTH-REC-FRAME-7731" * 10)
        moved = workspace["root"] / "moved-forensics"
        os.rename(cdir / "forensics", moved)
        (cdir / "forensics").symlink_to(moved)
        r = await call(c, "case_import_file", case_id=cid, source_path=str(cdir / "forensics" / "recovered" / "clip-001" / "0001-clip.mp4"))
        assert "validation_failed" in r["_error"] and "forensics" in r["_error"], r
        assert not (cdir / "dumps" / "0001-clip.mp4").exists()


def test_pweh_report_compares_custody_with_the_anchor(workspace, auth, monkeypatch):
    """`pweh report` 도 SD 카드 보관 기록을 보호 위치의 고정점과 대조한다 (report_generate 와 같게)."""
    import argparse
    from pathlib import Path

    from pweh import cli, report
    from pweh.runtime import get_runtime

    rt = get_runtime("test")
    case = rt.cases.create(title="sd", authorization=auth)
    seen = {}

    def fake_write_report(c, anchor_dir=None):
        seen["anchor"] = anchor_dir
        return {"ok": True}

    monkeypatch.setattr(report, "write_report", fake_write_report)
    monkeypatch.setattr(cli, "_runtime", lambda: rt)
    assert cli.cmd_report(argparse.Namespace(case_id=case.id)) == 0
    assert seen["anchor"] == Path(rt.config.state_dir) / "custody"
