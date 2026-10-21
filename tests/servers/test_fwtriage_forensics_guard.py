"""pweh-fwtriage 는 케이스의 보호 폴더를 읽지 않는다 — 자동 허용 서버로 녹화 내용(forensics/)이나 에뮬레이터의 마스킹하지 않은
원시 콘솔(emu/)이 전용 도구를 거치지 않고 문맥에 들어가는 우회를 막는다."""

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


SENTINEL = "EMU-SENTINEL-7731"


def _emu_session(case, sid: str = "emu-001"):
    """pweh-emu 세션 디렉터리 모양만 흉내 낸다(서버 없이): 원시 콘솔에 비밀값, stderr 로그."""
    d = case.dir / "emu" / sid
    d.mkdir(parents=True)
    (d / "console.bin").write_bytes(f"ESP-ROM:esp32s3-20210327\r\nwifi_password={SENTINEL}\r\nlogin: ".encode())
    (d / "emulator.stderr.log").write_text(f"qemu-system-xtensa: {SENTINEL}\n", encoding="utf-8")
    return d


@pytest.fixture
def ecase(workspace, auth):
    """emu/ 만 있는 케이스(forensics/ 없음)."""
    from pweh.case import CaseStore

    case = CaseStore(workspace["cases_dir"]).create(title="emu guard", authorization=auth, case_id="emucase")
    _emu_session(case)
    (case.dir / "extract" / "rootfs-001" / "etc").mkdir(parents=True)
    (case.dir / "extract" / "rootfs-001" / "etc" / "passwd").write_text("root::0:0:root:/root:/bin/sh\n", encoding="utf-8")
    return case


def _emu_refused(r: dict) -> bool:
    return "validation_failed" in r.get("_error", "") and "emu/" in r["_error"] and "emu_read" in r["_error"] and SENTINEL not in str(r)


async def test_fwtriage_refuses_emu_session_files_links_and_parent_dirs(ecase, workspace):
    from fwtriage_mcp.server import server
    from pweh.case import CaseStore

    sess = ecase.dir / "emu" / "emu-001"
    async with Client(server) as c:
        for path in ("emu/emu-001/console.bin", "emu/emu-001/emulator.stderr.log", str(sess / "console.bin")):
            r = await call(c, "fw_identify", case_id=ecase.id, path=path)
            assert _emu_refused(r), r
        # 자동 허용 도구의 정규식 패턴으로 원시 콘솔을 그대로 읽어 내는 우회(설계 검토의 경로)
        r = await call(c, "fw_strings_hunt", case_id=ecase.id, path_or_dir="emu/emu-001/console.bin", patterns=["re:.{1,200}"])
        assert _emu_refused(r), r
        # emu/ 자체·세션 디렉터리
        for d in ("emu", "emu/emu-001"):
            r = await call(c, "fw_strings_hunt", case_id=ecase.id, path_or_dir=d)
            assert _emu_refused(r), r
        # 케이스 안의 링크로 돌아가도 막는다 (파일 링크·디렉터리 링크)
        (ecase.dir / "dumps" / "innocent.bin").symlink_to(sess / "console.bin")
        r = await call(c, "fw_entropy", case_id=ecase.id, path="dumps/innocent.bin")
        assert _emu_refused(r), r
        (ecase.dir / "dumps" / "sessions").symlink_to(ecase.dir / "emu")
        r = await call(c, "fw_strings_hunt", case_id=ecase.id, path_or_dir="dumps/sessions", patterns=["re:.{1,200}"])
        assert _emu_refused(r), r
        # emu/ 를 품은 디렉터리(케이스 루트)는 훑지 않는다 — forensics/ 가 없는 케이스에서도
        for d in (".", str(ecase.dir)):
            r = await call(c, "fw_strings_hunt", case_id=ecase.id, path_or_dir=d, patterns=["re:.{1,200}"])
            assert _emu_refused(r), r
        r = await call(c, "fw_elf_info", case_id=ecase.id, path=".")
        assert _emu_refused(r), r
        # 다른 케이스의 emu/ 는 케이스 경계에서 막힌다(절대 경로·링크 모두)
        other = CaseStore(workspace["cases_dir"]).create(title="other", case_id="othercase")
        theirs = _emu_session(other) / "console.bin"
        r = await call(c, "fw_identify", case_id=ecase.id, path=str(theirs))
        assert "_error" in r and SENTINEL not in str(r), r
        (ecase.dir / "dumps" / "theirs.bin").symlink_to(theirs)
        r = await call(c, "fw_identify", case_id=ecase.id, path="dumps/theirs.bin")
        assert "_error" in r and SENTINEL not in str(r), r
        # 펌웨어 추출 트리는 그대로
        ok = await call(c, "fw_strings_hunt", case_id=ecase.id, path_or_dir="extract/rootfs-001")
        assert ok.get("ok"), ok
        assert SENTINEL not in str(ok)


async def test_forensics_message_wins_when_both_protected_folders_exist(gcase):
    """forensics/ 와 emu/ 가 모두 있는 케이스의 루트: 지금까지와 같은 forensics 문구(보호 폴더 순서 forensics → emu)."""
    from fwtriage_mcp.server import server

    _emu_session(gcase)
    async with Client(server) as c:
        r = await call(c, "fw_strings_hunt", case_id=gcase.id, path_or_dir=".")
        assert "validation_failed" in r["_error"] and "forensics" in r["_error"] and "emu_read" not in r["_error"], r
        r = await call(c, "fw_identify", case_id=gcase.id, path="emu/emu-001/console.bin")
        assert _emu_refused(r), r


async def test_case_without_forensics_folder_is_unchanged(workspace, auth):
    from fwtriage_mcp.server import server
    from pweh.case import CaseStore

    case = CaseStore(workspace["cases_dir"]).create(title="plain", authorization=auth, case_id="plaincase")
    (case.dir / "dumps").mkdir(exist_ok=True)
    (case.dir / "dumps" / "a.txt").write_text("hello telnetd -l /bin/sh\n", encoding="utf-8")
    async with Client(server) as c:
        r = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir=".")
        assert r.get("ok"), r
