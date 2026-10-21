"""pweh-forensics 이미지 해석 도구: forensics_partitions·forensics_image_check·forensics_fs_list·forensics_extract (합성 카드 이미지)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import time

import pytest
from mcp import Client

from fs.builders import exfat_small, fat32_small, pattern, put_mbr
from mcp_helpers import call

pytestmark = pytest.mark.anyio

LEGAL = {"purpose": "녹화 확인", "legal_basis": "소유자 본인 기기", "site_type": "home", "business_purpose": "없음(가정용)", "role": "owner"}
START_LBA = 2048


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def fcase(workspace, auth):
    from pweh.case import CaseStore

    return CaseStore(workspace["cases_dir"]).create(title="SD 카드", authorization=auth, case_id="sdfs")


def _fat_card(tmp_path, *, contaminate: bool = False):
    """MBR(파티션 1 = FAT32) 카드: 녹화 둘, 삭제한 녹화 하나(연속 → 정확히 복구), 선택적으로 호스트 흔적."""
    b = fat32_small(label="CAMSD")
    b.mkdir("/record")
    b.add_file("/record/20261001_100000.mp4", pattern(5000, 1))
    b.add_file("/record/20261001_110000.mp4", pattern(7000, 2))
    b.add_file("/record/20261001_090000.mp4", pattern(6000, 3))
    b.delete("/record/20261001_090000.mp4")
    if contaminate:
        b.mkdir("/$RECYCLE.BIN")
        b.add_file("/.DS_Store", b"\x00\x00\x00\x01Bud1")
    vol = b.image()
    img = bytearray(START_LBA * 512 + len(vol))
    put_mbr(img, [(0x0C, START_LBA, len(vol) // 512)])
    img[START_LBA * 512:] = vol
    p = tmp_path / "evidence" / "card.img"
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(bytes(img))
    return p


def _exfat_card(tmp_path):
    """파티션 표 없는 exFAT: ValidDataLength 뒤에 이전 녹화 잔여 바이트가 있는 파일."""
    b = exfat_small(label="CAMEX")
    b.add_file("/clip.h264", pattern(3000, 7), residual=pattern(5000, 8))
    p = tmp_path / "evidence" / "exfat.img"
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(b.image())
    return p


async def _wait(c, job_id: str) -> dict:
    for _ in range(400):
        st = await call(c, "forensics_job_status", job_id=job_id, wait_seconds=5)
        if st.get("status") in ("succeeded", "failed", "cancelled"):
            return st
        await asyncio.sleep(0.05)
    raise AssertionError("job 이 끝나지 않음")


async def _intake(c, case, image) -> str:
    r = await call(c, "forensics_intake_start", case_id=case.id, image_path=str(image), **LEGAL)
    assert r.get("job_id"), r
    st = await _wait(c, r["job_id"])
    assert st["status"] == "succeeded", st
    return st["result"]["evidence_id"]


async def test_partitions_list_and_extract_deleted_recording(fcase, tmp_path):
    from forensics_mcp.server import server
    from pweh import evidence as E

    image = _fat_card(tmp_path)
    async with Client(server) as c:
        ev = await _intake(c, fcase, image)
        parts = await call(c, "forensics_partitions", case_id=fcase.id, evidence_id=ev)
        assert parts["scheme"] == "mbr" and parts["partitions"][0]["index"] == 1 and parts["partitions"][0]["fs_hint"] == "fat32", parts
        vol = parts["volumes"][0]["volume"]
        assert vol["fs_type"] == "fat32" and vol["volume_label"] == "CAMSD" and vol["dirty"] is False

        lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        v = lst["volumes"][0]
        assert v["stats"]["files"] == 2 and v["stats"]["deleted_files"] == 1 and v["stats"]["dirs"] == 1, v
        assert v["time_basis"] == "local-unknown-tz" and any(r["state"] == "deleted" for r in v["time_ranges"])
        assert {"ext": "mp4", "files": 3} in v["extensions"]
        full = json.loads((fcase.dir / lst["result_path"]).read_text(encoding="utf-8"))
        assert hashlib.sha256((fcase.dir / lst["result_path"]).read_bytes()).hexdigest() == lst["result_sha256"]
        entries = full["volumes"][0]["walk"]["entries"]
        deleted = [e for e in entries if e["deleted"] and not e["is_dir"]]
        assert len(deleted) == 1 and deleted[0]["size"] == 6000
        assert stat.S_IMODE((fcase.dir / lst["result_path"]).stat().st_mode) == 0o444

        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, refs=[deleted[0]["ref"]], label="del")
        st = await _wait(c, ex["job_id"])
        res = st["result"]
        assert st["status"] == "succeeded" and res["ok"] and len(res["files"]) == 1, st
        f = res["files"][0]
        out = fcase.dir / res["output_dir"] / f["file"]
        assert out.read_bytes() == pattern(6000, 3), "연속 할당 삭제 파일은 정확히 복구된다"
        assert f["sha256"] == hashlib.sha256(pattern(6000, 3)).hexdigest() and f["deleted"] and f["complete"]
        assert stat.S_IMODE(out.stat().st_mode) == 0o444 and stat.S_IMODE(out.parent.stat().st_mode) == 0o555
        man = json.loads((fcase.dir / res["manifest"]).read_text(encoding="utf-8"))
        assert man["files"][0]["path"] and man["files"][0]["confidence"] and man["evidence_sha256"]
        allowed = {"seq", "file", "path", "deleted", "method", "confidence", "status", "size", "complete", "sha256", "limit_reason",
                   "requested_path"}
        assert all(set(x) <= allowed for x in res["files"]), "응답에는 해시·크기·방법·상태만 — 내용 필드가 없다"
        assert f["status"] == "ok" and "limit_reason" not in f
        assert pattern(6000, 3)[:64].hex() not in json.dumps(st), "내용 바이트가 응답에 섞이지 않는다"
        events = [e["event"] for e in E.CustodyLog(fcase).entries()]
        assert events == ["intake", "list", "extract"], events

        # 살아 있는 파일을 경로로, 디렉터리 ref 는 건너뛴다
        dir_ref = next(e["ref"] for e in entries if e["is_dir"])
        ex2 = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, refs=[dir_ref], paths=["/record/20261001_110000.mp4"])
        r2 = (await _wait(c, ex2["job_id"]))["result"]
        assert len(r2["files"]) == 1 and r2["files"][0]["size"] == 7000 and r2["skipped"][0]["reason"].startswith("디렉터리")
        assert (fcase.dir / r2["output_dir"] / r2["files"][0]["file"]).read_bytes() == pattern(7000, 2)


async def test_image_check_reports_host_artifacts(fcase, tmp_path):
    from forensics_mcp.server import server

    async with Client(server) as c:
        ev = await _intake(c, fcase, _fat_card(tmp_path, contaminate=True))
        chk = await call(c, "forensics_image_check", case_id=fcase.id, evidence_id=ev)
        inds = {i["indicator"]: i for i in chk["volumes"][0]["indicators"]}
        assert inds["$recycle.bin"]["strength"] == "strong" and inds[".ds_store"]["strength"] == "strong"
        assert chk["strong_indicators"] >= 2 and "사람에게 알리고" in chk["note"]
        # 빌더의 접근 날짜(기본 시각)를 획득일로 주면 weak 흔적
        acc = await call(c, "forensics_image_check", case_id=fcase.id, evidence_id=ev, acquisition_date="2026-10-01")
        assert "acquisition_date" in acc
        bad = await call(c, "forensics_image_check", case_id=fcase.id, evidence_id=ev, acquisition_date="01/10/2026")
        assert "validation_failed" in bad["_error"]


async def test_exfat_residual_listing_and_extract(fcase, tmp_path):
    from forensics_mcp.server import server

    async with Client(server) as c:
        ev = await _intake(c, fcase, _exfat_card(tmp_path))
        parts = await call(c, "forensics_partitions", case_id=fcase.id, evidence_id=ev)
        assert parts["scheme"] == "superfloppy" and parts["volumes"][0]["volume"]["fs_type"] == "exfat"
        lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        v = lst["volumes"][0]
        assert v["files_with_residual"] == 1 and v["stats"]["files"] == 1
        full = json.loads((fcase.dir / lst["result_path"]).read_text(encoding="utf-8"))
        e = next(x for x in full["volumes"][0]["walk"]["entries"] if not x["is_dir"])
        assert e["valid_data_length"] == 3000 and e["residual_bytes"] == 5000
        data = (await _wait(c, (await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, refs=[e["ref"]]))["job_id"]))["result"]
        resid = (await _wait(c, (await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, refs=[e["ref"]], region="residual"))["job_id"]))["result"]
        assert (fcase.dir / data["output_dir"] / data["files"][0]["file"]).read_bytes() == pattern(3000, 7), "본문은 ValidDataLength 에서 자른다"
        rf = resid["files"][0]
        assert rf["file"].endswith(".residual") and (fcase.dir / resid["output_dir"] / rf["file"]).read_bytes() == pattern(5000, 8)


async def test_unsupported_and_argument_errors(fcase, tmp_path):
    from forensics_mcp.server import server

    junk = tmp_path / "evidence" / "junk.img"
    junk.parent.mkdir(exist_ok=True)
    junk.write_bytes(os.urandom(1 << 20))
    async with Client(server) as c:
        ev = await _intake(c, fcase, junk)
        parts = await call(c, "forensics_partitions", case_id=fcase.id, evidence_id=ev)
        assert parts["ok"] and not parts["volumes"]
        lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        assert "validation_failed" in lst["_error"]
        none = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev)
        assert "validation_failed" in none["_error"]
        badp = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev, partition=0)
        assert "validation_failed" in badp["_error"]
        badev = await call(c, "forensics_partitions", case_id=fcase.id, evidence_id="EV-9999")
        assert "_error" in badev


async def test_content_tools_check_fingerprint_first(fcase, tmp_path):
    from forensics_mcp.server import server
    from pweh import evidence as E

    async with Client(server) as c:
        ev = await _intake(c, fcase, _fat_card(tmp_path))
        stored = fcase.dir / f"forensics/images/{ev}/card.img"
        os.chmod(stored.parent, 0o755)
        os.chmod(stored, 0o644)
        with open(stored, "r+b") as fh:
            fh.seek(10)
            fh.write(b"\xff")
        r = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        assert "integrity_failed" in r["_error"]
        assert E.CustodyLog(fcase).entries()[-1]["event"] == "integrity-failed"
        again = await call(c, "forensics_partitions", case_id=fcase.id, evidence_id=ev)
        assert "integrity_failed" in again["_error"]


# ---------------------------------------------------------------------------
# 서버 회귀 시험 (I3b 검토): 호출 전체 예산·중복 구간·응답 크기, ref 검증, 추출 정리·잘림, 링크 거부, GPT 이름
# ---------------------------------------------------------------------------


def _small_fat(label: str, files: int, seed: int = 1) -> bytes:
    from fs.builders import fat12_small

    b = fat12_small(label=label)
    b.mkdir("/rec")
    for i in range(files):
        b.add_file(f"/rec/clip{i:03d}.mp4", pattern(700 + i, seed + i))
    return b.image()


def _gpt_card(tmp_path, vols: list[bytes], layout: list[int], *, names: list[str] | None = None, name: str = "gpt.img"):
    """vols 를 차례로 놓고 GPT 항목 k 는 vols[layout[k]] 의 구간을 가리킨다(같은 번호 = 같은 시작·크기)."""
    from fs.builders import GptPart, put_gpt

    places, off = [], START_LBA
    for v in vols:
        places.append((off, off + len(v) // 512 - 1))
        off = (off + len(v) // 512 + 2047) // 2048 * 2048
    img = bytearray((off + 2048) * 512)
    for (first, _), v in zip(places, vols):
        img[first * 512:first * 512 + len(v)] = v
    parts = [GptPart(places[i][0], places[i][1], name=(names[k] if names else f"P{k}"), unique_guid=f"11111111-2222-3333-4444-{k:012d}")
             for k, i in enumerate(layout)]
    put_gpt(img, parts)
    p = tmp_path / "evidence" / name
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(bytes(img))
    return p


async def test_fs_list_call_budget_dedup_and_streamed_listing(fcase, tmp_path, monkeypatch):
    """#0: 같은 구간을 가리키는 GPT 항목은 한 번만 순회, 항목 수·파티션 수는 호출 전체 한도, 목록 파일은 볼륨별로 흘려 쓴다(sha256 = 쓴 바이트)."""
    import dataclasses

    from forensics_mcp import server as S

    card = _gpt_card(tmp_path, [_small_fat("VOLA", 6), _small_fat("VOLB", 4, seed=50)], [0, 0, 0, 1])
    async with Client(S.server) as c:
        ev = await _intake(c, fcase, card)
        lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        assert lst["call"]["partitions_walked"] == 2 and lst["call"]["partitions_skipped"]["duplicate"]["count"] == 2, lst["call"]
        assert [v["volume"]["volume_label"] for v in lst["volumes"]] == ["VOLA", "VOLB"] and not lst["truncated"]
        raw = (fcase.dir / lst["result_path"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == lst["result_sha256"]
        full = json.loads(raw)
        assert [len(v["walk"]["entries"]) for v in full["volumes"]] == [7, 5] and full["call"]["entries_used"] == 12
        # 항목 수 상한은 파티션마다가 아니라 호출 전체
        lim = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev, max_entries=5)
        assert lim["call"]["entries_used"] <= 5 and lim["truncated"], lim["call"]
        full = json.loads((fcase.dir / lim["result_path"]).read_bytes())
        assert sum(len(v["walk"]["entries"]) for v in full["volumes"] if "walk" in v) <= 5
        # 순회할 파티션 수 상한 (Limits.max_partitions)
        real = S.fsops.limits_for
        monkeypatch.setattr(S.fsops, "limits_for", lambda *a, **k: dataclasses.replace(real(*a, **k), max_partitions=1))
        one = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        assert one["call"]["partitions_walked"] == 1 and one["call"]["partitions_skipped"]["partitions"]["count"] == 1 and one["truncated"]
        chk = await call(c, "forensics_image_check", case_id=fcase.id, evidence_id=ev)
        assert len(chk["volumes"]) == 1 and chk["truncated"] and "한도" in chk["note"]


async def test_partitions_bounded_dedup_and_gpt_name_guid(fcase, tmp_path, monkeypatch):
    """#2·#11: 같은 구간은 한 번만 열고(duplicate_of), 열 파티션 수·응답 크기에 상한, GPT 이름·GUID 를 돌려준다."""
    import dataclasses

    from forensics_mcp import server as S

    card = _gpt_card(tmp_path, [_small_fat("VOLA", 2), _small_fat("VOLB", 2, seed=9)], [0, 0, 0, 1],
                     names=["CAMERA-SD", "COPY1", "COPY2", "SPARE"])
    async with Client(S.server) as c:
        ev = await _intake(c, fcase, card)
        parts = await call(c, "forensics_partitions", case_id=fcase.id, evidence_id=ev)
        p0 = parts["partitions"][0]
        assert p0["name"] == "CAMERA-SD" and p0["guid"].upper() == "11111111-2222-3333-4444-000000000000", p0
        assert [v.get("duplicate_of") for v in parts["volumes"]] == [None, 1, 1, None] and not parts["truncated"]
        monkeypatch.setattr(S, "RESPONSE_MAX_PARTITIONS", 2)
        small = await call(c, "forensics_partitions", case_id=fcase.id, evidence_id=ev)
        assert len(small["partitions"]) == 2 and small["partitions_total"] == 4 and small["truncated"] and small["truncated_reason"] == "response"
        monkeypatch.setattr(S, "RESPONSE_MAX_PARTITIONS", 128)
        real = S.fsops.limits_for
        monkeypatch.setattr(S.fsops, "limits_for", lambda *a, **k: dataclasses.replace(real(*a, **k), max_partitions=1))
        capped = await call(c, "forensics_partitions", case_id=fcase.id, evidence_id=ev)
        assert capped["partitions_omitted"] == 1 and capped["truncated_reason"] == "partitions"
        assert capped["volumes"][3].get("omitted") == "partitions" and "volume" not in capped["volumes"][3]


async def test_extract_refs_validated_deduplicated_and_original_path_kept(fcase, tmp_path, monkeypatch):
    """#3·#5·#10·#12: ref 는 중복을 없애고, 목록 순회가 검증한 디렉터리의 것만 받는다(지어낸 dirspec 은 읽지 않는다).
    매니페스트·응답의 path 는 디렉터리 경로를 포함한 원래 경로. 확인 순회는 요청한 dirspec 을 targets 로 받아 다 찾으면 멈춘다.
    B-N4(정책 변경): 순회가 잘렸으면(status truncated) 찾은 dirspec 의 ref 는 받고 나머지만 refs_unverifiable — 검증된 ref 가
    하나도 없고 paths 도 없을 때만 job 이 실패한다."""
    from pweh.fs.base import VolumeBase

    image = _fat_card(tmp_path)
    real_reach = VolumeBase.reachable_dirspecs
    seen: dict = {}

    def spy_reach(self, limits=None, **kw):
        seen["targets"] = kw.get("targets")
        seen["budget"] = kw.get("budget")
        return real_reach(self, limits, **kw)

    async with Client(__import__("forensics_mcp.server", fromlist=["server"]).server) as c:
        ev = await _intake(c, fcase, image)
        lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        entries = json.loads((fcase.dir / lst["result_path"]).read_text(encoding="utf-8"))["volumes"][0]["walk"]["entries"]
        deleted = next(e for e in entries if e["deleted"] and not e["is_dir"])
        live = next(e for e in entries if not e["deleted"] and not e["is_dir"])
        forged = f"c{live['first_cluster']}/0"  # 녹화 데이터 클러스터를 디렉터리로 읽게 하는 지어낸 ref
        monkeypatch.setattr(VolumeBase, "reachable_dirspecs", spy_reach)
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, refs=[deleted["ref"]] * 3 + [forged, "garbage"],
                        label="dedup")
        res = (await _wait(c, ex["job_id"]))["result"]
        assert len(res["files"]) == 1 and res["files"][0]["path"] == "/record/20261001_090000.mp4", res
        bad = [s for s in res["skipped"] if s.get("ref") == forged]
        assert len(bad) == 1 and set(bad[0]) == {"ref", "reason", "code"} and bad[0]["code"] == "bad_ref" and "bad_ref" in bad[0]["reason"]
        assert [s["code"] for s in res["skipped"] if s.get("ref") == "garbage"] == ["bad_ref"]
        assert not res["truncated"] and res["truncated_reasons"] == [], "지어낸 ref 는 한도가 아니다"
        assert sorted(seen["targets"]) == sorted({deleted["ref"].rsplit("/", 1)[0], forged.rsplit("/", 1)[0]}), "모양이 맞는 ref 의 dirspec 만"
        assert seen["budget"] is not None and seen["budget"].cancel is not None, "확인 순회에 job 의 취소 함수가 간다"
        man = json.loads((fcase.dir / res["manifest"]).read_text(encoding="utf-8"))
        assert man["files"][0]["path"] == "/record/20261001_090000.mp4"

        dspec = deleted["ref"].rsplit("/", 1)[0]
        assert dspec != "root", "삭제 녹화는 /record 안에 있다"

        def truncated_reach(found):
            return lambda self, limits=None, **kw: {"dirspecs": set(found), "paths": {s: "/record" for s in found}, "status": "truncated",
                                                    "truncated": True, "truncated_reason": "time", "truncated_reasons": ["time"]}

        # (1) 아무 ref 도 검증하지 못했고 paths 도 없음 → job 실패(refs_unverifiable)
        monkeypatch.setattr(VolumeBase, "reachable_dirspecs", truncated_reach([]))
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, refs=[deleted["ref"]])
        st = await _wait(c, ex["job_id"])
        assert st["status"] == "failed" and st["error"]["data"]["reason"] == "refs_unverifiable", st
        assert "ref 를 받지 않습니다" in st["error"]["message"]
        # (2) 찾은 dirspec 의 ref 는 검증된 것 — 받고, 나머지만 refs_unverifiable (truncated_reasons 에 더한다)
        monkeypatch.setattr(VolumeBase, "reachable_dirspecs", truncated_reach([dspec]))
        other = f"c{int(live['first_cluster']) + 7}/1"
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, refs=[deleted["ref"], other], label="part")
        st = await _wait(c, ex["job_id"])
        res = st["result"]
        assert st["status"] == "succeeded" and [f["path"] for f in res["files"]] == ["/record/20261001_090000.mp4"], st
        unv = [s for s in res["skipped"] if s.get("ref") == other]
        assert len(unv) == 1 and unv[0]["code"] == "refs_unverifiable" and "time" in unv[0]["reason"]
        assert res["truncated"] and res["truncated_reasons"] == ["refs_unverifiable"]
        assert any("refs_unverifiable" in s for s in res["next_steps"])
        # (3) 검증된 ref 는 없지만 paths 가 있으면 job 은 성공하고 ref 는 refs_unverifiable
        monkeypatch.setattr(VolumeBase, "reachable_dirspecs", truncated_reach([]))
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, refs=[deleted["ref"]],
                        paths=["/record/20261001_110000.mp4"], label="withpaths")
        st = await _wait(c, ex["job_id"])
        res = st["result"]
        assert st["status"] == "succeeded" and [f["path"] for f in res["files"]] == ["/record/20261001_110000.mp4"], st
        assert [(s.get("ref"), s["code"]) for s in res["skipped"]] == [(deleted["ref"], "refs_unverifiable")]
        # (4) 순회가 complete 인데 없으면 bad_ref (한도가 아니다)
        monkeypatch.setattr(VolumeBase, "reachable_dirspecs",
                            lambda self, limits=None, **kw: {"dirspecs": {"root"}, "paths": {"root": "/"}, "status": "complete",
                                                             "truncated": False, "truncated_reason": None, "truncated_reasons": []})
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, refs=[deleted["ref"]], paths=["/nope.mp4"], label="cpl")
        res = (await _wait(c, ex["job_id"]))["result"]
        assert [(s.get("ref") or s.get("path"), s["code"]) for s in res["skipped"]] == [(deleted["ref"], "bad_ref"), ("/nope.mp4", "not_found")]
        assert not res["truncated"]


async def test_extract_truncated_by_max_bytes_and_failed_extract_leaves_nothing(fcase, tmp_path, monkeypatch):
    """#9·#8: max_bytes 가 파일을 자르면 truncated=true. 쓰다가 실패한 추출은 출력 디렉터리를 지운다(기록 없는 부분 출력 없음),
    실패·중단한 목록은 확보한 파일을 지운다."""
    import errno

    from forensics_mcp import server as S
    from pweh import evidence as E
    from pweh import safeio

    image = _fat_card(tmp_path)
    async with Client(S.server) as c:
        ev = await _intake(c, fcase, image)
        lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        entries = json.loads((fcase.dir / lst["result_path"]).read_text(encoding="utf-8"))["volumes"][0]["walk"]["entries"]
        ref = next(e["ref"] for e in entries if e["deleted"] and not e["is_dir"])
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, refs=[ref], max_bytes=1000, label="cut")
        res = (await _wait(c, ex["job_id"]))["result"]
        assert res["truncated"] and res["truncated_reasons"] == ["max_bytes"] and res["files"][0]["size"] == 1000
        assert res["files"][0]["complete"] is False

        real_write = safeio.write_all

        def disk_full(fd, data):
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(safeio, "write_all", disk_full)
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, refs=[ref], label="enospc")
        st = await _wait(c, ex["job_id"])
        monkeypatch.setattr(safeio, "write_all", real_write)
        assert st["status"] == "failed"
        assert sorted(p.name for p in (fcase.dir / "forensics/recovered").iterdir()) == ["cut-001"]
        assert [e["event"] for e in E.CustodyLog(fcase).entries()].count("extract") == 1

        def boom(w, v):
            raise RuntimeError("목록 쓰기 실패 흉내")

        before = sorted(p.name for p in (fcase.dir / "forensics/analysis").iterdir())
        monkeypatch.setattr(S, "_write_volume", boom)
        r = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        assert "_error" in r
        assert sorted(p.name for p in (fcase.dir / "forensics/analysis").iterdir()) == before


async def test_outputs_never_follow_links_in_forensics(fcase, tmp_path, monkeypatch):
    """#7·#28: analysis/·recovered/ 가 링크면 쓰지 않고, 매니페스트 자리에 링크를 심어도 따라가 쓰지 않는다(O_EXCL|O_NOFOLLOW)."""
    from forensics_mcp import server as S
    from pweh import evidence as E

    image = _fat_card(tmp_path)
    outside = tmp_path / "outside"
    (outside / "ana").mkdir(parents=True)
    (outside / "rec").mkdir()
    victim = outside / "victim.txt"
    victim.write_text("keep")
    async with Client(S.server) as c:
        ev = await _intake(c, fcase, image)
        ana = fcase.dir / "forensics/analysis"
        ana.symlink_to(outside / "ana")
        r = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        assert "path_outside_base" in r["_error"], r
        ana.unlink()
        rec = fcase.dir / "forensics/recovered"
        rec.symlink_to(outside / "rec")
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, paths=["/record/20261001_110000.mp4"])
        st = await _wait(c, ex["job_id"])
        assert st["status"] == "failed" and st["error"]["code"] == "path_outside_base", st
        rec.unlink()
        real = S.fsops.extract_entries

        def plant_then_extract(vol, entries, out_fd, **kw):
            res = real(vol, entries, out_fd, **kw)
            os.symlink(victim, "manifest.json", dir_fd=out_fd)  # 매니페스트를 쓰기 직전에 링크를 심는 경쟁 흉내
            return res

        monkeypatch.setattr(S.fsops, "extract_entries", plant_then_extract)
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, paths=["/record/20261001_110000.mp4"], label="race")
        st = await _wait(c, ex["job_id"])
        assert st["status"] == "failed" and st["error"]["code"] == "path_outside_base", st
        assert not any((fcase.dir / "forensics/recovered").iterdir()), "실패한 추출은 출력 디렉터리를 지운다"
    assert victim.read_text() == "keep" and stat.S_IMODE(victim.stat().st_mode) != 0o444
    assert not any((outside / "ana").iterdir()) and not any((outside / "rec").iterdir())
    assert [e["event"] for e in E.CustodyLog(fcase).entries()] == ["intake"]


async def test_extract_candidate_budget_marks_truncated(fcase, tmp_path, monkeypatch):
    """#3: 후보 계산은 job 예산 안에서 — 예산이 다 되면(budget_exceeded) 그 파일은 건너뛰고 truncated_reasons 에 'time'/'steps',
    남은 시간이 1초 미만이면 후보를 만들지 않고 건너뛴다."""
    from forensics_mcp import server as S
    from pweh.fs import FsError
    from pweh.fs.base import VolumeBase

    image = _fat_card(tmp_path)
    async with Client(S.server) as c:
        ev = await _intake(c, fcase, image)

        def over_budget(self, ref, method="auto", region="data", **kw):
            raise FsError("내용 계획: 작업 단계 예산이 다 돼 멈췄습니다.", reason="budget_exceeded", data={"limit": "steps"})

        monkeypatch.setattr(VolumeBase, "content_plan", over_budget)
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, paths=["/record/20261001_110000.mp4"], label="steps")
        res = (await _wait(c, ex["job_id"]))["result"]
        assert res["files"] == [] and res["truncated"] and res["truncated_reasons"] == ["steps"]
        assert "예산" in res["skipped"][0]["reason"]
        monkeypatch.undo()
        monkeypatch.setattr(S.fsops, "EXTRACT_MAX_SECONDS", 2.0)  # 경로 찾기(1.3초) 뒤에는 1초 미만만 남는다
        real_lookup = VolumeBase.lookup

        def slow_lookup(self, path, **kw):
            import time as _t

            _t.sleep(1.3)
            return real_lookup(self, path, **kw)

        monkeypatch.setattr(VolumeBase, "lookup", slow_lookup)
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, paths=["/record/20261001_110000.mp4"], label="late")
        res = (await _wait(c, ex["job_id"]))["result"]
        assert res["files"] == [] and res["truncated_reasons"] == ["time"] and res["skipped"][0]["reason"] == "작업 시간 한도"


# ---------------------------------------------------------------------------
# 검증 재실행 회귀 시험 (I3b batch 2): 해석하지 못한 볼륨·작은 max_seconds·추출 취소·추출 커밋 지점
# ---------------------------------------------------------------------------


def _open_image(path):
    """시험용: 이미지 파일을 fd 로 열어 ImageReader 로 (fsops.image_reader 와 같은 경로)."""
    from forensics_mcp import fsops

    fd = os.open(path, os.O_RDONLY)
    try:
        return fsops.image_reader(fd, path=str(path))
    finally:
        os.close(fd)  # ImageReader.from_fd 가 dup 한다


async def test_errored_volume_counts_as_incomplete(fcase, tmp_path, monkeypatch):
    """A-N2: 오류가 난 볼륨(엔진 FsError·엔진이 바꾸지 못한 예외)은 결과를 불완전하게 만든다 — truncated=true, call.volumes_failed,
    image_check 는 '흔적 없음'이라고 말하지 않고, fs_list next_steps 가 알린다. 나머지 볼륨은 계속 본다."""
    from forensics_mcp import server as S
    from pweh.fs import FsError
    from pweh.fs.base import VolumeBase

    card = _gpt_card(tmp_path, [_small_fat("VOLA", 3), _small_fat("VOLB", 2, seed=40)], [0, 1])
    real_open = S.fsops.open_volume
    state = {"n": 0}

    def first_fails(src, **kw):  # 호출(도구) 하나에서 처음 여는 볼륨만 실패 — 엔진에 budget= 같은 인자가 늘어도 받는다
        state["n"] += 1
        if state["n"] == 1:
            raise FsError("손상된 볼륨 흉내", reason="malformed")
        return real_open(src, **kw)

    async with Client(S.server) as c:
        ev = await _intake(c, fcase, card)
        ok = await call(c, "forensics_image_check", case_id=fcase.id, evidence_id=ev)
        assert not ok["truncated"] and ok["call"]["volumes_failed"] == {"count": 0, "examples": []}
        assert "찾지 못했다" in ok["note"]

        monkeypatch.setattr(S.fsops, "open_volume", first_fails)
        chk = await call(c, "forensics_image_check", case_id=fcase.id, evidence_id=ev)
        assert chk["ok"] and chk["truncated"], chk
        assert chk["call"]["volumes_failed"] == {"count": 1, "examples": [{"partition": 1, "reason": "malformed"}]}
        assert chk["volumes"][0]["error"]["data"]["reason"] == "malformed" and "indicators" in chk["volumes"][1]
        assert "찾지 못했다" not in chk["note"] and "해석하지 못해" in chk["note"], chk["note"]

        state["n"] = 0
        lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        assert lst["truncated"] and lst["call"]["volumes_failed"]["count"] == 1, lst
        assert "error" in lst["volumes"][0] and lst["volumes"][1]["stats"]["files"] == 2
        assert "해석하지 못해" in lst["next_steps"][0] and not any("한도에서 잘렸다" in s for s in lst["next_steps"])
        full = json.loads((fcase.dir / lst["result_path"]).read_bytes())
        assert full["call"]["volumes_failed"]["count"] == 1 and full["volumes"][0]["error"]["data"]["reason"] == "malformed"
        monkeypatch.setattr(S.fsops, "open_volume", real_open)

        def walk_boom(self, **kw):  # 엔진의 guard 밖에서 난 예상하지 못한 예외
            raise RuntimeError("walk 흉내 오류")

        monkeypatch.setattr(VolumeBase, "walk", walk_boom)
        chk = await call(c, "forensics_image_check", case_id=fcase.id, evidence_id=ev)
        assert chk["ok"] and chk["truncated"] and chk["call"]["volumes_failed"]["count"] == 2, chk
        err = chk["volumes"][0]["error"]
        assert err["data"]["reason"] == "internal_error" and err["data"]["exception"] == "RuntimeError"
        assert "찾지 못했다" not in chk["note"]
        lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        assert lst["truncated"] and lst["call"]["volumes_failed"]["examples"] == [{"partition": 1, "reason": "internal_error"},
                                                                                  {"partition": 2, "reason": "internal_error"}]


async def test_small_max_seconds_walks_the_first_volume(fcase, tmp_path):
    """S-1: max_seconds 가 하한(1초)이어도 처음 여는 볼륨은 순회한다(시간이 조금이라도 남으면). 두 번째 볼륨부터는
    LATER_VOLUME_MIN_SECONDS 미만이면 건너뛰고, 시간이 없으면 첫 볼륨도 건너뛴다 — 보고(truncated·partitions_skipped)는 그대로."""
    from forensics_mcp import fsops
    from forensics_mcp.server import server
    from pweh import fs as pfs

    async with Client(server) as c:
        ev = await _intake(c, fcase, _fat_card(tmp_path))
        for ms in (1, 0.5, -5):
            lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev, max_seconds=ms)
            assert lst["call"]["partitions_walked"] == 1 and lst["call"]["entries_used"] == 4, (ms, lst["call"])
            assert not lst["truncated"] and lst["volumes"][0]["stats"]["files"] == 2

    card = _gpt_card(tmp_path, [_small_fat("VOLA", 2), _small_fat("VOLB", 2, seed=9)], [0, 1], name="two.img")
    lim = fsops.limits_for(None, 1)
    with _open_image(card) as img:
        layout = pfs.detect_partitions(img, limits=lim)
        budget = fsops.CallBudget.from_limits(lim)
        budget.deadline = time.monotonic() + fsops.LATER_VOLUME_MIN_SECONDS * 0.8
        got = list(fsops.iter_volumes(img, layout, None, lim, budget, include_deleted=True))
        assert [v["partition"]["index"] for v in got] == [1] and "walk" in got[0]
        assert budget.walked == 1 and budget.summary()["partitions_skipped"] == {"time": {"count": 1, "examples": [2]}}
        late = fsops.CallBudget.from_limits(lim)
        late.deadline = time.monotonic() - 0.01
        assert list(fsops.iter_volumes(img, layout, None, lim, late, include_deleted=True)) == []
        assert late.walked == 0 and late.limited == ["time"] and late.skipped["time"] == 2


async def test_extract_cancel_lists_unattempted_entries(fcase, tmp_path):
    """S-3: 취소되면 시도하지 않은 항목도 skipped(사유 '취소됨')에 남긴다 — truncated_reasons 에 'cancelled'."""
    from forensics_mcp import fsops

    card = tmp_path / "evidence" / "small.img"
    card.parent.mkdir(exist_ok=True)
    card.write_bytes(_small_fat("VOLA", 4))
    lim = fsops.limits_for(None, 60)
    out = tmp_path / "out"
    out.mkdir()
    with _open_image(card) as img:
        _, vol = fsops.open_partition_volume(img, None, lim)
        paths = [f"/rec/clip{i:03d}.mp4" for i in range(4)]
        targets, unresolved = fsops.resolve_targets(vol, [], paths, limits=lim, deadline=time.monotonic() + 60)
        assert len(targets) == 4 and not unresolved
        done = {"files": 0}
        real_iter = vol.iter_plan

        def counting_iter(plan, **kw):  # 파일 하나의 내용을 다 돌려준 뒤에 센다
            yield from real_iter(plan, **kw)
            done["files"] += 1

        vol.iter_plan = counting_iter
        dfd = os.open(out, os.O_RDONLY | os.O_DIRECTORY)
        try:
            res = fsops.extract_entries(vol, targets, dfd, method="auto", region="data", max_bytes_total=1 << 20, max_files=10,
                                        limits=lim, deadline=time.monotonic() + 60, cancel=lambda: done["files"] >= 1)
        finally:
            os.close(dfd)
    assert [f["path"] for f in res["files"]] == ["/rec/clip000.mp4"] and res["files"][0]["complete"]
    assert [(s["path"], s["reason"]) for s in res["skipped"]] == [(p, "취소됨") for p in paths[1:]]
    assert res["truncated"] and res["truncated_reasons"] == ["cancelled"]
    assert sorted(os.listdir(out)) == ["0001-clip000.mp4"]


async def test_extract_cancel_and_commit_point(fcase, tmp_path, monkeypatch):
    """B-N5·S-3: (1) 추출이 취소를 받아들여 멈추면 job 은 cancelled 로 끝나고, 출력·매니페스트(시도하지 않은 항목 '취소됨')·보관 기록이 남는다.
    (2) 보관 기록 extract 를 덧붙인 뒤 도착한 취소는 결과를 바꾸지 않는다(succeeded). (3) 덧붙인 뒤에 무엇이 실패해도 출력 디렉터리를
    지우지 않는다(보관 기록이 가리킨다)."""
    from forensics_mcp import server as S
    from pweh import evidence as E

    card = tmp_path / "evidence" / "small.img"
    card.parent.mkdir(exist_ok=True)
    card.write_bytes(_small_fat("VOLA", 3))
    paths = [f"/rec/clip{i:03d}.mp4" for i in range(3)]

    def cancel_jobs() -> None:
        for j in S.rt().jobs.list(active_only=True):
            S.rt().jobs.cancel(j["job_id"])

    async with Client(S.server) as c:
        ev = await _intake(c, fcase, card)
        real_extract = S.fsops.extract_entries

        def cancel_before_second(vol, entries, out_fd, **kw):
            real_iter = vol.iter_plan

            def iter_then_cancel(plan, **ikw):  # 첫 파일을 다 쓴 뒤, 두 번째 항목을 시작하기 전에 사람이 취소
                yield from real_iter(plan, **ikw)
                cancel_jobs()

            vol.iter_plan = iter_then_cancel
            return real_extract(vol, entries, out_fd, **kw)

        monkeypatch.setattr(S.fsops, "extract_entries", cancel_before_second)
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, paths=paths, label="cx")
        st = await _wait(c, ex["job_id"])
        res = st["result"]
        assert st["status"] == "cancelled" and res["truncated_reasons"] == ["cancelled"], st
        assert [(s["path"], s["reason"]) for s in res["skipped"]] == [(p, "취소됨") for p in paths[1:]]
        man = json.loads((fcase.dir / res["manifest"]).read_text(encoding="utf-8"))
        assert [s["reason"] for s in man["skipped"]] == ["취소됨", "취소됨"] and len(man["files"]) == 1
        assert stat.S_IMODE((fcase.dir / res["output_dir"]).stat().st_mode) == 0o555
        monkeypatch.setattr(S.fsops, "extract_entries", real_extract)

        real_append = E.CustodyLog.append

        def append_then_cancel(self, event, **kw):
            entry = real_append(self, event, **kw)
            if event == "extract":
                cancel_jobs()  # 기록한 직후에 도착한 취소
            return entry

        monkeypatch.setattr(E.CustodyLog, "append", append_then_cancel)
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, paths=paths[:1], label="late")
        st = await _wait(c, ex["job_id"])
        assert st["status"] == "succeeded" and st["result"]["truncated_reasons"] == [], st
        monkeypatch.setattr(E.CustodyLog, "append", real_append)

        def audit_boom(case, entry):  # 덧붙인 뒤의 실패(흉내) — 출력은 남아야 한다
            raise RuntimeError("감사 기록 흉내 오류")

        monkeypatch.setattr(S, "_audit_custody", audit_boom)
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, paths=paths[:1], label="kept")
        st = await _wait(c, ex["job_id"])
        monkeypatch.undo()
        assert st["status"] == "failed", st
        lst = await call(c, "forensics_evidence_list", case_id=fcase.id, write_files=False)
        derived = {d["path"].rsplit("/", 1)[-1]: d["custody"] for d in lst["derived"]}
        assert derived == {"cx-001": "recorded", "late-001": "recorded", "kept-001": "recorded"}, lst["derived"]


# ---------------------------------------------------------------------------
# 검증 재실행 회귀 시험 (I3b batch 2, 엔진 의존 부분): 볼륨 하나에 엔진 예산 하나, 호출 전체의 경로 글자 수, 확인 순회의
# targets·취소·정책, 잘림 사유 노출, paths= 의 디스크 이름·모호함, 계획의 limit_reason
# ---------------------------------------------------------------------------


def _mbr_wrap(tmp_path, vol: bytes, name: str):
    img = bytearray(START_LBA * 512 + len(vol))
    put_mbr(img, [(0x0C, START_LBA, len(vol) // 512)])
    img[START_LBA * 512:] = vol
    p = tmp_path / "evidence" / name
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(bytes(img))
    return p


def _names_card(tmp_path):
    """긴 이름·8.3 별칭·대소문자만 다른 이름·ß 가 있는 FAT32 카드."""
    b = fat32_small(label="NAMES")
    b.mkdir("/Record Files")
    b.add_file("/Record Files/Clip 001.MP4", pattern(1500, 11))
    b.mkdir("/d")
    b.add_file("/d/Case.txt", b"upper-first")
    b.add_file("/d/CASE.txt", b"all-upper")
    b.add_file("/d/straße.txt", "content straße".encode())
    b.add_file("/d/strasse.txt", b"content strasse")
    return _mbr_wrap(tmp_path, b.image(), "names.img")


async def test_iter_volumes_shares_one_engine_budget_per_volume(fcase, tmp_path, monkeypatch):
    """A-N3·S-4: 볼륨마다 엔진 예산 하나를 새로 만들어 open_volume·info·walk 에 함께 넘긴다(호출의 마감 시각, 그 볼륨의 단계 상한).
    볼륨끼리는 같은 예산을 쓰지 않는다. 엔진 예산이 다 돼 난 볼륨 오류는 한도(skipped[time])이지 해석 실패(volumes_failed)가 아니다."""
    from forensics_mcp import fsops
    from forensics_mcp import server as S
    from pweh import fs as pfs
    from pweh.fs import FsError
    from pweh.fs.base import VolumeBase
    from pweh.fs.fat import FatVolume

    card = _gpt_card(tmp_path, [_small_fat("VOLA", 3), _small_fat("VOLB", 2, seed=40)], [0, 1], name="shared.img")
    calls: list = []
    real_open, real_info, real_walk = fsops.open_volume, FatVolume.info, VolumeBase.walk

    def spy_open(src, **kw):
        vol = real_open(src, **kw)
        calls.append(("open", kw.get("budget"), vol))
        return vol

    def spy_info(self, **kw):
        calls.append(("info", kw.get("budget"), self))
        return real_info(self, **kw)

    def spy_walk(self, **kw):
        calls.append(("walk", kw.get("budget"), self, kw.get("limits")))
        return real_walk(self, **kw)

    monkeypatch.setattr(fsops, "open_volume", spy_open)
    monkeypatch.setattr(FatVolume, "info", spy_info)
    monkeypatch.setattr(VolumeBase, "walk", spy_walk)
    lim = fsops.limits_for(None, 60)
    with _open_image(card) as img:
        layout = pfs.detect_partitions(img, limits=lim)
        budget = fsops.CallBudget.from_limits(lim)
        got = list(fsops.iter_volumes(img, layout, None, lim, budget, include_deleted=True))
    assert [len(v["walk"]["entries"]) for v in got] == [4, 3]
    assert [c[0] for c in calls] == ["open", "info", "walk"] * 2
    for k in (0, 3):
        b = calls[k][1]
        assert b is not None and calls[k + 1][1] is b and calls[k + 2][1] is b, "열기·정보·순회가 같은 예산"
        assert abs(b.deadline - budget.deadline) < 1e-6, "호출 전체의 마감 시각"
        assert b.max_steps >= calls[k][2].step_cap(lim), "open_volume 이 그 볼륨의 단계 상한까지 올렸다"
        assert b.cancel is None, "동기 도구에는 취소 함수가 없다(문서화된 한계)"
    assert calls[0][1] is not calls[3][1], "볼륨마다 새 예산"
    w1, w2 = calls[2][3], calls[5][3]
    assert w1.max_path_chars == budget.max_path_chars and w2.max_path_chars == budget.max_path_chars - got[0]["walk"]["path_chars"]
    assert budget.used_path_chars == sum(v["walk"]["path_chars"] for v in got) and budget.summary()["path_chars_used"] == budget.used_path_chars
    monkeypatch.setattr(FatVolume, "info", real_info)  # undo() 는 작업공간 격리(환경 변수)까지 되돌리므로 하나씩 되돌린다
    monkeypatch.setattr(VolumeBase, "walk", real_walk)

    def first_over_budget(src, **kw):  # 처음 여는 볼륨만 엔진 예산이 다 돼 오류
        if not calls:
            calls.append("x")
            raise FsError("열기: 시간 예산이 다 돼 멈췄습니다.", reason="budget_exceeded", data={"limit": "time"})
        return real_open(src, **kw)

    calls.clear()
    monkeypatch.setattr(S.fsops, "open_volume", first_over_budget)
    async with Client(S.server) as c:
        ev = await _intake(c, fcase, card)
        calls.clear()
        chk = await call(c, "forensics_image_check", case_id=fcase.id, evidence_id=ev)
    assert chk["truncated"] and chk["call"]["volumes_failed"]["count"] == 0, chk["call"]
    assert chk["call"]["partitions_skipped"]["time"] == {"count": 1, "examples": [1]} and chk["truncated_reasons"] == ["time"]
    assert chk["volumes"][0]["error"]["data"]["limit"] == "time" and "indicators" in chk["volumes"][1]
    assert "해석하지 못해" not in chk["note"] and "보고하지 않는다" in chk["note"]


async def test_path_chars_budget_is_per_call_across_volumes(fcase, tmp_path, monkeypatch):
    """A-N1: 경로 글자 수 상한은 호출 전체 — 앞 볼륨이 쓴 만큼(walk.path_chars) 뒤 볼륨에 남은 몫만 넘기고, 순회가 max_path_chars 로
    멈추면 뒤 파티션은 건너뛴다(path_chars). 잘림 사유·다음 단계 안내가 응답에 나온다."""
    import dataclasses

    from forensics_mcp import server as S

    card = _gpt_card(tmp_path, [_small_fat("VOLA", 6), _small_fat("VOLB", 4, seed=50)], [0, 1], name="chars.img")
    real = S.fsops.limits_for
    async with Client(S.server) as c:
        ev = await _intake(c, fcase, card)
        # VOLA: '/rec'(4) + '/rec/clip00N.mp4'(16) × 6 = 100 글자 → 50 이면 VOLA 가 3 항목에서 멈추고 VOLB 는 건너뛴다
        monkeypatch.setattr(S.fsops, "limits_for", lambda *a, **k: dataclasses.replace(real(*a, **k), max_path_chars=50))
        lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        v = lst["volumes"]
        assert len(v) == 1 and v[0]["truncated_reason"] == "max_path_chars" and v[0]["stats"]["files"] == 2, lst
        assert lst["call"]["partitions_skipped"]["path_chars"] == {"count": 1, "examples": [2]}
        assert lst["call"]["max_path_chars"] == 50 and lst["call"]["path_chars_used"] == 36
        assert lst["truncated"] and lst["truncated_reasons"] == ["max_path_chars"]
        assert any("경로 글자 수 상한" in s for s in lst["next_steps"]), lst["next_steps"]
        full = json.loads((fcase.dir / lst["result_path"]).read_bytes())
        assert full["call"]["partitions_skipped"]["path_chars"]["count"] == 1 and full["volumes"][0]["walk"]["path_chars"] == 36
        # 120 이면 VOLA(100)는 끝까지, VOLB 는 남은 20 글자만큼('/rec' + 파일 하나)
        monkeypatch.setattr(S.fsops, "limits_for", lambda *a, **k: dataclasses.replace(real(*a, **k), max_path_chars=120))
        lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        a, b = lst["volumes"]
        assert not a["truncated"] and b["truncated_reason"] == "max_path_chars" and b["stats"]["files"] == 1, lst["volumes"]
        assert lst["call"]["path_chars_used"] == 120 and "path_chars" not in lst["call"]["partitions_skipped"]
        chk = await call(c, "forensics_image_check", case_id=fcase.id, evidence_id=ev)
        assert chk["truncated"] and chk["truncated_reasons"] == ["max_path_chars"] and "찾지 못했다(없음을" not in chk["note"]


async def test_max_depth_cut_is_surfaced_in_fs_list_image_check_and_extract(fcase, tmp_path, monkeypatch):
    """E4 서버 쪽: 디렉터리 깊이 한도로 내려가지 않은 디렉터리는 truncated·truncated_reasons·cut_dirs 로 드러나고, 다음 단계는 고정
    한도라고 알린다(max_seconds 를 늘리라고 하지 않는다). image_check 는 '흔적 없음'이라 하지 않는다. 너무 깊은 paths= 는 code
    max_depth 로 남고 추출 결과도 잘림이다."""
    import dataclasses

    from forensics_mcp import server as S

    real = S.fsops.limits_for
    async with Client(S.server) as c:
        ev = await _intake(c, fcase, _fat_card(tmp_path))
        monkeypatch.setattr(S.fsops, "limits_for", lambda *a, **k: dataclasses.replace(real(*a, **k), max_depth=1))
        lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        v = lst["volumes"][0]
        assert v["truncated"] and v["truncated_reasons"] == ["max_depth"] and v["stats"]["dirs"] == 1 and v["stats"]["files"] == 0, v
        assert v["cut_dirs"] == [{"path": "/record", "reason": "max_depth"}] and v["cut_dirs_total"] == 1
        assert lst["truncated"] and lst["truncated_reasons"] == ["max_depth"]
        assert any("깊이 한도" in s and "고정" in s for s in lst["next_steps"]) and not any("늘리" in s for s in lst["next_steps"])
        chk = await call(c, "forensics_image_check", case_id=fcase.id, evidence_id=ev)
        vol = chk["volumes"][0]
        assert vol["walk_truncated_reasons"] == ["max_depth"] and vol["cut_dirs"][0]["path"] == "/record"
        assert chk["truncated"] and "보고하지 않는다" in chk["note"] and "찾지 못했다(없음을" not in chk["note"], chk["note"]
        assert any("깊이 한도" in s for s in chk["next_steps"])
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, paths=["/record/20261001_110000.mp4"], label="deep")
        res = (await _wait(c, ex["job_id"]))["result"]
        assert res["files"] == [] and [s["code"] for s in res["skipped"]] == ["max_depth"], res
        assert res["truncated"] and res["truncated_reasons"] == ["max_depth"]


async def test_extract_paths_record_on_disk_names_and_refuse_ambiguity(fcase, tmp_path):
    """S-2·E1 서버 쪽: paths= 는 디스크의 이름(긴 이름)으로 매니페스트·응답에 남고 호출자 철자는 requested_path 로. 대소문자만 다른
    이름이 둘이면 정확히 같은 이름만 받고, 대소문자 무시로 여럿이 맞으면 code ambiguous_path 로 거부한다. ß 는 ss 로 접지 않는다."""
    from forensics_mcp import server as S

    async with Client(S.server) as c:
        ev = await _intake(c, fcase, _names_card(tmp_path))
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, label="names",
                        paths=["/record files/CLIP 001.mp4", "/d/case.txt", "/d/Case.txt", "/d/STRASSE.TXT", "/d/straße.txt"])
        st = await _wait(c, ex["job_id"])
        res = st["result"]
        assert st["status"] == "succeeded", st
        got = {f["path"]: f for f in res["files"]}
        assert set(got) == {"/Record Files/Clip 001.MP4", "/d/Case.txt", "/d/straße.txt", "/d/strasse.txt"}, sorted(got)
        assert got["/Record Files/Clip 001.MP4"]["requested_path"] == "/record files/CLIP 001.mp4"
        assert got["/d/strasse.txt"]["requested_path"] == "/d/STRASSE.TXT" and "requested_path" not in got["/d/Case.txt"]
        out = fcase.dir / res["output_dir"]
        assert (out / got["/d/strasse.txt"]["file"]).read_bytes() == b"content strasse", "strasse 는 straße 가 아니다"
        assert (out / got["/d/straße.txt"]["file"]).read_bytes() == "content straße".encode()
        assert (out / got["/d/Case.txt"]["file"]).read_bytes() == b"upper-first"
        amb = [s for s in res["skipped"] if s.get("path") == "/d/case.txt"]
        assert len(amb) == 1 and amb[0]["code"] == "ambiguous_path" and "대소문자" in amb[0]["reason"], res["skipped"]
        assert "Case" not in amb[0]["reason"] and "CASE" not in amb[0]["reason"], "후보 이름을 되풀이하지 않는다"
        assert not res["truncated"] and any("ambiguous_path" in s for s in res["next_steps"])
        man = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        assert {f["path"]: f.get("requested_path") for f in man["files"]}["/Record Files/Clip 001.MP4"] == "/record files/CLIP 001.mp4"
        # 8.3 별칭으로 고른 것도 디스크의 긴 이름으로 남는다
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, paths=["/RECORD~1/CLIP00~1.MP4"], label="sfn")
        res = (await _wait(c, ex["job_id"]))["result"]
        assert [(f["path"], f.get("requested_path")) for f in res["files"]] == [("/Record Files/Clip 001.MP4", "/RECORD~1/CLIP00~1.MP4")]
        assert (fcase.dir / res["output_dir"] / res["files"][0]["file"]).read_bytes() == pattern(1500, 11)


async def test_extract_plan_limit_reason_reaches_truncated_reasons(fcase, tmp_path, monkeypatch):
    """A-N4 서버 쪽: 예산 때문에 덜 만든 계획(limit_reason)은 있는 만큼 쓰고 그 사유를 truncated_reasons 에 더하며, 응답 files[] 에
    status·limit_reason 이 있다."""
    from forensics_mcp import server as S
    from pweh.fs.base import VolumeBase

    real_plan = VolumeBase.content_plan

    def capped(self, ref, method="auto", region="data", **kw):
        p = real_plan(self, ref, method, region, **kw)
        p.status = "limit"
        p.extra["limit_reason"] = "steps"
        return p

    async with Client(S.server) as c:
        ev = await _intake(c, fcase, _fat_card(tmp_path))
        monkeypatch.setattr(VolumeBase, "content_plan", capped)
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, paths=["/record/20261001_110000.mp4"], label="cap")
        res = (await _wait(c, ex["job_id"]))["result"]
    f = res["files"][0]
    assert f["status"] == "limit" and f["limit_reason"] == "steps" and res["truncated"] and res["truncated_reasons"] == ["steps"], res
    man = json.loads((fcase.dir / res["manifest"]).read_text(encoding="utf-8"))
    assert man["truncated_reasons"] == ["steps"] and man["files"][0]["status"] == "limit" and man["files"][0]["limit_reason"] == "steps"


def test_extract_entries_engine_cancel_lists_rest_and_writes_nothing(tmp_path):
    """B-N4·A-N4: 엔진이 후보를 만드는 도중 취소를 보면(budget_exceeded limit=cancelled, 또는 limit_reason 'cancelled' 계획) 그 항목과
    나머지를 '취소됨'으로 남기고 'cancelled' 를 기록한다 — 취소로 덜 만든 계획은 쓰지 않는다. 후보 계산에는 취소 함수를 넘긴다."""
    from forensics_mcp import fsops
    from pweh.fs import FsError

    card = tmp_path / "evidence" / "small.img"
    card.parent.mkdir(exist_ok=True)
    card.write_bytes(_small_fat("VOLA", 3))
    lim = fsops.limits_for(None, 60)
    paths = [f"/rec/clip{i:03d}.mp4" for i in range(3)]

    def run(mode: str) -> tuple[dict, list, list]:
        out = tmp_path / f"out-{mode}"
        out.mkdir()
        seen: dict = {"n": 0, "cancel": []}
        with _open_image(card) as img:
            _, vol = fsops.open_partition_volume(img, None, lim)
            targets, _ = fsops.resolve_targets(vol, [], paths, limits=lim, deadline=time.monotonic() + 60)
            real_plan = vol.content_plan

            def plan(ref, method="auto", region="data", **kw):
                seen["n"] += 1
                seen["cancel"].append(kw["budget"].cancel)
                p = real_plan(ref, method, region, **kw)
                if seen["n"] == 2:
                    if mode == "raise":
                        raise FsError("내용 계획: 취소돼 멈췄습니다.", reason="budget_exceeded", data={"limit": "cancelled"})
                    p.status = "limit"
                    p.extra["limit_reason"] = "cancelled"
                return p

            vol.content_plan = plan
            dfd = os.open(out, os.O_RDONLY | os.O_DIRECTORY)
            try:
                res = fsops.extract_entries(vol, targets, dfd, method="auto", region="data", max_bytes_total=1 << 20, max_files=10,
                                            limits=lim, deadline=time.monotonic() + 60, cancel=lambda: False)
            finally:
                os.close(dfd)
        return res, sorted(os.listdir(out)), seen["cancel"]

    for mode in ("raise", "plan"):
        res, written, cancels = run(mode)
        assert [f["path"] for f in res["files"]] == ["/rec/clip000.mp4"], (mode, res)
        assert [(s["path"], s["reason"]) for s in res["skipped"]] == [(p, "취소됨") for p in paths[1:]], (mode, res["skipped"])
        assert res["truncated_reasons"] == ["cancelled"] and written == ["0001-clip000.mp4"], mode
        assert all(callable(x) for x in cancels), "후보 계산의 예산에 취소 함수가 간다"


async def test_extract_cancel_during_ref_check_ends_cancelled_without_output(fcase, tmp_path, monkeypatch):
    """B-N4: 확인 순회(reachable_dirspecs)가 취소로 멈추면 job 은 바로 cancelled 로 끝난다 — 출력 디렉터리·보관 기록 없음
    (refs_unverifiable 로 실패하지 않는다)."""
    from forensics_mcp import server as S
    from pweh import evidence as E
    from pweh.fs.base import VolumeBase

    def cancel_jobs() -> None:
        for j in S.rt().jobs.list(active_only=True):
            S.rt().jobs.cancel(j["job_id"])

    def reach_cancelled(self, limits=None, *, budget=None, targets=None):
        cancel_jobs()
        assert budget is not None and budget.expired() and budget.reason == "cancelled", "엔진 예산이 job 의 취소를 본다"
        return {"dirspecs": {"root"}, "paths": {"root": "/"}, "status": "truncated", "truncated": True,
                "truncated_reason": "cancelled", "truncated_reasons": ["cancelled"]}

    async with Client(S.server) as c:
        ev = await _intake(c, fcase, _fat_card(tmp_path))
        lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        entries = json.loads((fcase.dir / lst["result_path"]).read_text(encoding="utf-8"))["volumes"][0]["walk"]["entries"]
        ref = next(e["ref"] for e in entries if e["deleted"] and not e["is_dir"])
        monkeypatch.setattr(VolumeBase, "reachable_dirspecs", reach_cancelled)
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, refs=[ref], label="cx")
        st = await _wait(c, ex["job_id"])
    assert st["status"] == "cancelled" and not st.get("error"), st
    assert not (fcase.dir / "forensics/recovered").exists() or not any((fcase.dir / "forensics/recovered").iterdir())
    assert [e["event"] for e in E.CustodyLog(fcase).entries()] == ["intake", "list"]


def test_extract_entries_max_bytes_only_when_the_cap_cut_the_file(tmp_path):
    """바이트 상한(max_bytes)은 상한까지 썼는데 계획에 더 있었을 때만 잘림 사유다 — 내용이 이미지 끝에서 끊겨 덜 읽은 것(잘린 이미지)은
    상한 탓이 아니다(파일은 complete=false 로 남는다)."""
    from forensics_mcp import fsops

    card = tmp_path / "evidence" / "small.img"
    card.parent.mkdir(exist_ok=True)
    card.write_bytes(_small_fat("VOLA", 1))
    lim = fsops.limits_for(None, 60)
    for short_image in (False, True):
        out = tmp_path / f"out-{short_image}"
        out.mkdir()
        with _open_image(card) as img:
            _, vol = fsops.open_partition_volume(img, None, lim)
            targets, _ = fsops.resolve_targets(vol, [], ["/rec/clip000.mp4"], limits=lim, deadline=time.monotonic() + 60)
            real_iter = vol.iter_plan

            def iter_plan(plan, *, max_bytes=None, _short=short_image, _real=real_iter):
                for chunk in _real(plan, max_bytes=max_bytes):
                    yield chunk[:100] if _short else chunk  # 이미지가 100 바이트 뒤에서 끝난 것처럼
                    if _short:
                        return

            vol.iter_plan = iter_plan
            dfd = os.open(out, os.O_RDONLY | os.O_DIRECTORY)
            try:
                res = fsops.extract_entries(vol, targets, dfd, method="auto", region="data", max_bytes_total=300, max_files=10,
                                            limits=lim, deadline=time.monotonic() + 60)
            finally:
                os.close(dfd)
        f = res["files"][0]
        assert f["size"] == (100 if short_image else 300) and f["complete"] is False, (short_image, f)
        assert res["truncated_reasons"] == ([] if short_image else ["max_bytes"]), (short_image, res["truncated_reasons"])


async def test_max_dir_slots_cut_is_surfaced_and_refs_beyond_the_cut_are_coded(fcase, tmp_path, monkeypatch):
    """E2 서버 쪽: 슬롯 한도에서 잘린 디렉터리는 fs_list·image_check 의 truncated_reasons·cut_dirs 로 드러나고(고정 한도 안내),
    잘린 뒤쪽을 가리키는 ref 는 skipped 에 code max_dir_slots 로 남아 추출 결과의 잘림 사유가 된다(앞쪽 ref 는 추출된다)."""
    import dataclasses

    from forensics_mcp import server as S

    b = fat32_small(label="SLOTS")
    b.mkdir("/rec")
    for i in range(40):
        b.add_file(f"/rec/clip number {i:03d}.mp4", pattern(600 + i, 70 + i))  # LFN 2 + SFN 1 = 3 슬롯
    card = _mbr_wrap(tmp_path, b.image(), "slots.img")
    real = S.fsops.limits_for
    async with Client(S.server) as c:
        ev = await _intake(c, fcase, card)
        full = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        assert not full["truncated"] and full["volumes"][0]["stats"]["files"] == 40
        entries = json.loads((fcase.dir / full["result_path"]).read_text(encoding="utf-8"))["volumes"][0]["walk"]["entries"]
        files = sorted((e for e in entries if not e["is_dir"]), key=lambda e: int(e["ref"].rsplit("/", 1)[1]))
        monkeypatch.setattr(S.fsops, "limits_for", lambda *a, **k: dataclasses.replace(real(*a, **k), max_dir_slots=64))
        lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        v = lst["volumes"][0]
        assert v["truncated_reasons"] == ["max_dir_slots"] and v["cut_dirs"] == [{"path": "/rec", "reason": "max_dir_slots"}], v
        assert 0 < v["stats"]["files"] < 40 and lst["truncated_reasons"] == ["max_dir_slots"]
        assert any("슬롯 한도" in s and "고정" in s for s in lst["next_steps"]) and not any("늘리" in s for s in lst["next_steps"])
        chk = await call(c, "forensics_image_check", case_id=fcase.id, evidence_id=ev)
        assert chk["volumes"][0]["walk_truncated_reasons"] == ["max_dir_slots"] and "보고하지 않는다" in chk["note"]
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, refs=[files[0]["ref"], files[-1]["ref"]], label="cut")
        res = (await _wait(c, ex["job_id"]))["result"]
        assert [f["path"] for f in res["files"]] == [files[0]["display_path"]], res
        assert [(s["ref"], s["code"]) for s in res["skipped"]] == [(files[-1]["ref"], "max_dir_slots")], res["skipped"]
        assert res["truncated"] and res["truncated_reasons"] == ["max_dir_slots"]


async def test_truncated_image_and_directories_cut_by_the_image_end_are_incomplete(fcase, tmp_path):
    """잘린 이미징: 볼륨이 이미지 끝 너머까지 이어지면(image_truncated) fs_list·image_check 는 truncated 이고 '흔적 없음'이라 하지
    않는다. 살아 있는 디렉터리가 이미지 끝에서 끊기면 cut_dirs 에 beyond_image 로 남고, 그 안의 paths= 는 not_found 가 아니라
    code beyond_image 다. 다음 단계는 시간을 늘리라고 하지 않고 사람에게 알리게 한다."""
    from forensics_mcp import server as S

    b = fat32_small(label="CAMSD")
    b.mkdir("/record")
    b.add_file("/record/20261001_100000.mp4", pattern(5000, 1))
    far = b.max_cluster - 10
    b.mkdir("/FAR", clusters=[far])
    b.add_file("/FAR/x.mp4", pattern(3000, 2))
    full = _mbr_wrap(tmp_path, b.image(), "full.img")
    cut = tmp_path / "evidence" / "cut.img"
    cut.write_bytes(full.read_bytes()[:START_LBA * 512 + b.coff(far)])
    async with Client(S.server) as c:
        ev_full = await _intake(c, fcase, full)
        ok = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev_full)
        assert not ok["truncated"] and ok["truncated_reasons"] == [] and not ok["volumes"][0]["volume"]["truncated"]
        ev = await _intake(c, fcase, cut)
        lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        v = lst["volumes"][0]
        assert v["volume"]["truncated"] and v["truncated"] and v["truncated_reasons"] == ["beyond_image", "image_truncated"], v
        assert v["cut_dirs"] == [{"path": "/FAR", "reason": "beyond_image"}] and v["stats"]["files"] == 1
        assert lst["truncated"] and lst["truncated_reasons"] == ["beyond_image", "image_truncated"]
        steps = " ".join(lst["next_steps"])
        assert "이미징" in steps and "사람에게 알리" in steps and "max_seconds 를 늘리" not in steps, steps
        chk = await call(c, "forensics_image_check", case_id=fcase.id, evidence_id=ev)
        assert chk["truncated"] and chk["truncated_reasons"] == ["beyond_image", "image_truncated"]
        assert "보고하지 않는다" in chk["note"] and "찾지 못했다(없음을" not in chk["note"], chk["note"]
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, label="cut",
                        paths=["/FAR/x.mp4", "/record/20261001_100000.mp4"])
        res = (await _wait(c, ex["job_id"]))["result"]
        assert [f["path"] for f in res["files"]] == ["/record/20261001_100000.mp4"], res
        assert [(s["path"], s["code"]) for s in res["skipped"]] == [("/FAR/x.mp4", "beyond_image")], res["skipped"]
        assert res["truncated"] and res["truncated_reasons"] == ["beyond_image"]


async def test_unvalidated_live_directory_is_incomplete_but_a_deleted_one_is_only_noted(fcase, tmp_path):
    """검증하지 못한 살아 있는 디렉터리(그 뒤쪽 항목은 목록에 없다)는 truncated_reasons 의 dir_unvalidated 다 — image_check 도 '흔적
    없음'이라 하지 않는다. 삭제된 디렉터리만 검증하지 못했으면(클러스터 재사용 — 흔하다) 잘림이 아니고 next_steps 에 적는다."""
    from forensics_mcp import server as S

    live = fat32_small(label="CAMSD")
    live.mkdir("/DCIM")
    live.add_file("/DCIM/A.MP4", pattern(700, 3))
    vol = bytearray(live.image())
    c0 = live.dirs["/DCIM"].clusters[0]
    vol[live.coff(c0) + 64:live.coff(c0) + live.cs] = b"\xff" * (live.cs - 64)
    dead = fat32_small(label="CAMSD")
    dead.mkdir("/OLD")
    dead.add_file("/OLD/X.TXT", b"x")
    dead.delete("/OLD/X.TXT")
    c1 = dead.delete("/OLD").clusters[0]
    dead.add_file("/KEEP.MP4", pattern(800, 4))
    vol2 = bytearray(dead.image())
    vol2[dead.coff(c1) + 64:dead.coff(c1) + dead.cs] = b"\xff" * (dead.cs - 64)
    async with Client(S.server) as c:
        ev = await _intake(c, fcase, _mbr_wrap(tmp_path, bytes(vol), "live.img"))
        lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        v = lst["volumes"][0]
        assert v["unvalidated_dirs"] == 1 and v["unvalidated_dirs_live"] == 1, v
        assert v["truncated"] and v["truncated_reasons"] == ["dir_unvalidated"] and lst["truncated_reasons"] == ["dir_unvalidated"]
        assert any("검증되지 않아" in s and "사람에게 알리" in s for s in lst["next_steps"]), lst["next_steps"]
        chk = await call(c, "forensics_image_check", case_id=fcase.id, evidence_id=ev)
        assert chk["truncated"] and "보고하지 않는다" in chk["note"] and "찾지 못했다(없음을" not in chk["note"], chk["note"]
        ex = await call(c, "forensics_extract", case_id=fcase.id, evidence_id=ev, paths=["/DCIM/B.MP4"], label="unval")
        res = (await _wait(c, ex["job_id"]))["result"]
        assert [(s["path"], s["code"]) for s in res["skipped"]] == [("/DCIM/B.MP4", "dir_unvalidated")], res["skipped"]
        ev2 = await _intake(c, fcase, _mbr_wrap(tmp_path, bytes(vol2), "dead.img"))
        lst2 = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev2)
        v2 = lst2["volumes"][0]
        assert v2["unvalidated_dirs"] == 1 and v2["unvalidated_dirs_live"] == 0 and not v2["truncated"], v2
        assert not lst2["truncated"] and lst2["truncated_reasons"] == []
        assert any("삭제된 디렉터리 중 검증하지 못한 것" in s for s in lst2["next_steps"]), lst2["next_steps"]
        chk2 = await call(c, "forensics_image_check", case_id=fcase.id, evidence_id=ev2)
        assert not chk2["truncated"]


def _two_part_card(tmp_path, name: str, *, cut_at_p2: bool):
    """MBR: 파티션 1·2 = FAT16(녹화 하나씩). cut_at_p2 면 이미지를 파티션 2 시작에서 자른다(파티션 2 가 통째로 이미지 끝 너머)."""
    from fs.builders import fat16_small

    v1 = fat16_small(label="P1")
    v1.add_file("/A.MP4", pattern(3000, 1))
    v2 = fat16_small(label="P2")
    v2.add_file("/B.MP4", pattern(3000, 2))
    vol1, vol2 = v1.image(), v2.image()
    s1, n1 = START_LBA, len(vol1) // 512
    s2, n2 = s1 + n1, len(vol2) // 512
    img = bytearray((s2 + n2) * 512)
    put_mbr(img, [(0x06, s1, n1), (0x06, s2, n2)])
    img[s1 * 512:s1 * 512 + len(vol1)] = vol1
    img[s2 * 512:] = vol2
    p = tmp_path / "evidence" / name
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(bytes(img[:s2 * 512]) if cut_at_p2 else bytes(img))
    return p


async def test_partition_beyond_the_image_end_makes_the_result_incomplete(fcase, tmp_path):
    """잘린 이미징이 파티션을 통째로 지웠다: 볼 수 있는 파티션이 온전해도 fs_list·image_check 는 image_truncated 로 불완전하다.
    forensics_partitions 는 그 파티션을 '지원하지 않는 파일 시스템'이 아니라 이미지 끝 너머라고 알리고, 그 파티션을 고르면
    beyond_image 다. 고른 파티션이 온전하면(partition=1) 그 목록은 완전하다."""
    from forensics_mcp import server as S

    full = _two_part_card(tmp_path, "two.img", cut_at_p2=False)
    cut = _two_part_card(tmp_path, "two-cut.img", cut_at_p2=True)
    async with Client(S.server) as c:
        ev_full = await _intake(c, fcase, full)
        ok = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev_full)
        assert not ok["truncated"] and ok["truncated_reasons"] == [] and len(ok["volumes"]) == 2
        ev = await _intake(c, fcase, cut)
        parts = await call(c, "forensics_partitions", case_id=fcase.id, evidence_id=ev)
        p2 = next(p for p in parts["partitions"] if p["index"] == 2)
        assert "partition_beyond_image" in [w["code"] for w in p2["warnings"]]
        v2 = next(v for v in parts["volumes"] if v["index"] == 2)
        assert v2["error"]["data"]["reason"] == "beyond_image" and "이미지 끝 너머" in v2["error"]["message"], v2
        assert "지원하지 않는" not in v2["error"]["message"]
        lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        assert [v["partition"] for v in lst["volumes"]] == [1] and not lst["volumes"][0]["truncated"]
        assert lst["truncated"] and lst["truncated_reasons"] == ["image_truncated"], lst
        assert any("이미지가 카드보다 짧다" in s for s in lst["next_steps"]) and not any("max_seconds 를 늘리" in s for s in lst["next_steps"])
        chk = await call(c, "forensics_image_check", case_id=fcase.id, evidence_id=ev)
        assert chk["truncated"] and chk["truncated_reasons"] == ["image_truncated"]
        assert "보고하지 않는다" in chk["note"] and "찾지 못했다(없음을" not in chk["note"], chk["note"]
        one = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev, partition=1)
        assert not one["truncated"] and one["truncated_reasons"] == [], "고른 파티션 1 은 온전하다"
        two = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev, partition=2)
        assert "validation_failed" in two["_error"] and "이미지 끝 너머" in two["_error"] and "지원" not in two["_error"], two


async def test_image_cut_before_its_only_partition_is_not_called_unsupported_or_clean(fcase, tmp_path):
    """하나뿐인 파티션 앞에서 잘린 이미지: fs_list 는 '지원하지 않는 파일 시스템'이 아니라 이미지 끝 너머라고 알리고, image_check 는
    본 볼륨이 없으니 '흔적을 찾지 못했다'가 아니라 '보지 못했다'(image_truncated, truncated)."""
    from forensics_mcp import server as S

    p = _fat_card(tmp_path)
    cut = tmp_path / "evidence" / "precut.img"
    cut.write_bytes(p.read_bytes()[:START_LBA * 512])
    async with Client(S.server) as c:
        ev = await _intake(c, fcase, cut)
        lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        assert "validation_failed" in lst["_error"] and "이미지 끝 너머" in lst["_error"] and "ext4" not in lst["_error"], lst
        chk = await call(c, "forensics_image_check", case_id=fcase.id, evidence_id=ev)
        assert chk["volumes"] == [] and chk["truncated"] and chk["truncated_reasons"] == ["image_truncated"], chk
        assert "보지 못했다" in chk["note"] and "찾지 못했다(없음을" not in chk["note"], chk["note"]


async def test_image_check_with_no_supported_volume_says_nothing_was_examined(fcase, tmp_path):
    """FAT/exFAT 파티션이 없는 카드(예: 다른 파일 시스템): 검사 범위가 불완전하다고 표시하고 '흔적 없음'처럼 말하지 않는다."""
    from forensics_mcp import server as S

    img = bytearray(START_LBA * 512 + 4 * 1024 * 1024)
    put_mbr(img, [(0x83, START_LBA, (len(img) // 512) - START_LBA)])
    img[START_LBA * 512:START_LBA * 512 + 4096] = pattern(4096, 9)
    p = tmp_path / "evidence" / "other.img"
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(bytes(img))
    async with Client(S.server) as c:
        ev = await _intake(c, fcase, p)
        chk = await call(c, "forensics_image_check", case_id=fcase.id, evidence_id=ev)
        assert chk["volumes"] == [] and chk["truncated"] and "unsupported_partitions" in chk["truncated_reasons"], chk
        assert chk["call"]["partitions_unexamined"], chk
        assert "본 볼륨이 없어" in chk["note"] and "unsupported_partitions" in chk["note"], chk["note"]


async def test_file_system_larger_than_its_partition_entry_is_not_blamed_on_imaging(fcase, tmp_path):
    """이미지는 온전한데 파티션 표 항목이 파일 시스템보다 작다: 불완전(항목 밖은 읽지 않음)이지만 사유는 volume_exceeds_partition 이고
    안내는 이미징이 끊겼다고 하지 않는다."""
    from forensics_mcp import server as S
    from fs.builders import fat16_small

    b = fat16_small(label="BIGFS")
    b.add_file("/A.MP4", pattern(3000, 5))
    vol = b.image()
    img = bytearray(START_LBA * 512 + len(vol))
    put_mbr(img, [(0x06, START_LBA, (len(vol) // 512) * 3 // 4)])  # 항목은 파일 시스템의 3/4
    img[START_LBA * 512:] = vol
    p = tmp_path / "evidence" / "fsgt.img"
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(bytes(img))
    async with Client(S.server) as c:
        ev = await _intake(c, fcase, p)
        lst = await call(c, "forensics_fs_list", case_id=fcase.id, evidence_id=ev)
        v = lst["volumes"][0]
        assert v["volume"]["truncated"] and v["truncated_reasons"] == ["volume_exceeds_partition"], v
        assert lst["truncated"] and lst["truncated_reasons"] == ["volume_exceeds_partition"]
        steps = " ".join(lst["next_steps"])
        assert "파티션 표 항목보다 크다" in steps and "이미징이 중간에 끊겼" not in steps, steps


def test_ebr_beyond_the_image_end_is_an_image_truncation():
    """확장 파티션의 EBR 이 이미지 끝 너머(논리 파티션을 잃음): layout_reasons 는 partition=None 일 때 image_truncated. 경고가 어느
    목록에 남는지(레이아웃 warnings)도 확인한다."""
    from forensics_mcp import fsops
    from pweh.fs import BytesReader, detect_partitions

    img = bytearray(START_LBA * 512 + 8 * 1024 * 1024)
    ext_start = START_LBA + 4096
    put_mbr(img, [(0x06, START_LBA, 4096), (0x0F, ext_start, 8192)])
    data = bytes(img[:ext_start * 512])  # 확장 파티션 시작(첫 EBR)에서 자른다
    layout = detect_partitions(BytesReader(data))
    layout_codes = [w["code"] for w in layout.get("warnings") or []]
    part_codes = [w["code"] for p in layout["partitions"] for w in p.get("warnings") or []]
    assert "ebr_beyond_image" in layout_codes + part_codes
    assert "ebr_beyond_image" in layout_codes, f"EBR 경고는 레이아웃 warnings 에 남는다: {layout_codes} / {part_codes}"
    assert fsops.layout_reasons(layout) == ["image_truncated"]
    assert fsops.layout_reasons(layout, 1) == [], "파티션 1 만 볼 때는 잃은 논리 파티션이 사유가 아니다"


def test_unreadable_directory_codes_count_as_incomplete_in_extract(monkeypatch):
    """paths=·refs 의 디렉터리를 읽지 못하면 code 는 dir_unreadable 이고 LIMIT_CODES 에 있어 매니페스트가 잘림이 된다."""
    from forensics_mcp import fsops
    from pweh.fs import BytesReader, FsError, open_volume

    b = fat32_small(label="CAMSD")
    b.mkdir("/A")
    b.add_file("/A/a.txt", b"a")
    v = open_volume(BytesReader(b.image()))
    spec = v.lookup("/A")["child_dir"]
    ref = v.lookup("/A/a.txt")["ref"]
    real = type(v)._parse_dir

    def boom(self, s, budget=None, **kw):
        if s == spec:
            raise FsError("읽기 오류(시험)", reason="io_error")
        return real(self, s, budget, **kw)

    monkeypatch.setattr(type(v), "_parse_dir", boom)
    v._dir_cache.clear()
    codes = []
    for fn in (lambda: v.lookup("/A/a.txt"), lambda: v.entry(ref)):
        with pytest.raises(FsError) as ei:
            fn()
        codes.append(fsops._err_code(ei.value))
    assert codes == ["dir_unreadable", "dir_unreadable"] and "dir_unreadable" in fsops.LIMIT_CODES
    assert fsops.merge_reasons([], [{"path": "/A/a.txt", "code": "dir_unreadable"}]) == ["dir_unreadable"]


async def test_mixed_fat_unsupported_partitions_are_reported(fcase, tmp_path):
    """지원 볼륨에 흔적이 없어도 미지원 볼륨을 빠뜨려 완전한 검사처럼 보고하지 않는다."""
    from forensics_mcp import server as S
    card = _gpt_card(tmp_path, [_small_fat("FATOK", 2), pattern(4096, 9)], [0, 1], name="mixed.img")
    async with Client(S.server) as c:
        ev = await _intake(c, fcase, card)
        for tool in ("forensics_fs_list", "forensics_image_check"):
            result = await call(c, tool, case_id=fcase.id, evidence_id=ev)
            assert result["truncated"] and "unsupported_partitions" in result["truncated_reasons"], result
            assert result["call"]["partitions_unexamined"][0]["index"] == 2
            scoped = await call(c, tool, case_id=fcase.id, evidence_id=ev, partition=1)
            assert "unsupported_partitions" not in scoped["truncated_reasons"], scoped
