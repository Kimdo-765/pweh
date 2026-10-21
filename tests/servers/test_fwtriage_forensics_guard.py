"""pweh-fwtriage 는 케이스의 증거 폴더(forensics/)를 읽지 않는다 — 자동 허용 서버로 녹화 내용이 문맥에 들어가는 우회를 막는다."""

from __future__ import annotations

import pytest
from mcp import Client

from mcp_helpers import call

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def gcase(workspace, auth):
    from pweh.case import CaseStore

    case = CaseStore(workspace["cases_dir"]).create(title="guard", authorization=auth, case_id="guardcase")
    ev = case.dir / "forensics" / "images" / "EV-0001"
    ev.mkdir(parents=True)
    (ev / "card.img").write_bytes(b"\x00" * 4096 + b"password=hunter2\n")
    rec = case.dir / "forensics" / "recovered" / "clip-001"
    rec.mkdir(parents=True)
    (rec / "0001-a.mp4").write_bytes(b"\x00\x00\x00\x18ftypmp42" + b"secret-recording")
    (case.dir / "extract" / "rootfs-001" / "etc").mkdir(parents=True)
    (case.dir / "extract" / "rootfs-001" / "etc" / "passwd").write_text("root::0:0:root:/root:/bin/sh\n", encoding="utf-8")
    return case


async def test_fwtriage_refuses_forensics_files_links_and_parent_dirs(gcase):
    from fwtriage_mcp.server import server

    async with Client(server) as c:
        for path in ("forensics/images/EV-0001/card.img", "forensics/recovered/clip-001/0001-a.mp4"):
            r = await call(c, "fw_identify", case_id=gcase.id, path=path)
            assert "validation_failed" in r["_error"] and "forensics" in r["_error"], r
        # 케이스 안의 링크로 돌아가도 막는다
        link = gcase.dir / "dumps" / "innocent.bin"
        link.parent.mkdir(exist_ok=True)
        link.symlink_to(gcase.dir / "forensics" / "recovered" / "clip-001" / "0001-a.mp4")
        r = await call(c, "fw_entropy", case_id=gcase.id, path="dumps/innocent.bin")
        assert "validation_failed" in r["_error"]
        # forensics/ 를 품은 디렉터리(케이스 루트)는 훑지 않는다
        r = await call(c, "fw_strings_hunt", case_id=gcase.id, path_or_dir=".")
        assert "validation_failed" in r["_error"] and "forensics" in r["_error"]
        r = await call(c, "fw_elf_info", case_id=gcase.id, path=".")
        assert "validation_failed" in r["_error"]
        # 펌웨어 추출 트리는 그대로
        ok = await call(c, "fw_strings_hunt", case_id=gcase.id, path_or_dir="extract/rootfs-001")
        assert ok.get("ok"), ok
        assert "secret-recording" not in str(ok) and "hunter2" not in str(ok)


async def test_case_without_forensics_folder_is_unchanged(workspace, auth):
    from fwtriage_mcp.server import server
    from pweh.case import CaseStore

    case = CaseStore(workspace["cases_dir"]).create(title="plain", authorization=auth, case_id="plaincase")
    (case.dir / "dumps").mkdir(exist_ok=True)
    (case.dir / "dumps" / "a.txt").write_text("hello telnetd -l /bin/sh\n", encoding="utf-8")
    async with Client(server) as c:
        r = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir=".")
        assert r.get("ok"), r
