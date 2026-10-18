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
