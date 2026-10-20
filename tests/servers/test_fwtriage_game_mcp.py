"""fwtriage-mcp 게임 세이브·해금 도구의 MCP 경로 테스트 (in-memory Client, 합성 ESP 플래시·세이브).

fw_esp_partitions → fw_esp_image_info → fw_esp_to_elf → fw_esp_nvs → fw_save_diff(nvs·bytes) → fw_checksum_find → fw_find_seq_tables.
라이브러리 단위 시험은 test_fwtriage_esp.py·test_fwtriage_saves.py 에 있고, 여기서는 도구 인자·범위(partition/offset)·결과 파일·
비밀값 마스킹(응답·결과 파일·감사 로그 어디에도 원문 없음)·오류 응답을 확인한다. 값은 모두 합성이다.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest
from mcp import Client

from fwtriage.esp_builders import (
    CHIP_C3,
    NvsImage,
    build_esp_flash,
    c3_app_image,
    rich_nvs,
    s3_app_image,
)
from mcp_helpers import call

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "mcp-servers" / "fwtriage-mcp"))

from fwtriage_mcp import saves  # noqa: E402

pytestmark = pytest.mark.anyio

WIFI_PASS = "not-a-real-pass"
API_TOKEN = "tok-synthetic-0000"
KONAMI = bytes([1, 1, 2, 2, 3, 4, 3, 4, 6, 5])  # 위 위 아래 아래 왼 오 왼 오 B A (버튼 id)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def game_case(workspace, auth):
    from pweh.case import CaseStore

    store = CaseStore(workspace["cases_dir"])
    case = store.create(title="게임 세이브 분석", authorization=auth, case_id="gamecase")
    nv, _ = rich_nvs()
    flash, layout = build_esp_flash(nvs=nv.build(total_pages=6), app=s3_app_image(extra=b"\x00" * 8 + KONAMI + b"\x00" * 8))
    (case.subdir("dumps") / "esp-flash.bin").write_bytes(flash)
    return {"case": case, "layout": layout}


def _nvs_snapshot(score: int, coins: int) -> bytes:
    nv = NvsImage(version=2)
    nv.put("game", "hiscore", "U32", score)
    nv.put("game", "coins", "U16", coins)
    nv.put("game", "level", "U8", 3)
    nv.put_str("nvs.net80211", "sta.pswd", WIFI_PASS)
    return nv.build(total_pages=6)


def _texts(case) -> str:
    """케이스의 결과 파일·감사 로그 전체 텍스트 (비밀값 원문 검사용)."""
    out = []
    for p in list((case.dir / "analysis").glob("*.json")) + [case.dir / "audit.jsonl"]:
        if p.exists():
            out.append(p.read_text(encoding="utf-8"))
    return "\n".join(out)


async def test_esp_flash_tools_flow(game_case):
    from fwtriage_mcp.server import server

    case = game_case["case"]
    async with Client(server) as c:
        r = await call(c, "fw_esp_partitions", case_id=case.id, path="dumps/esp-flash.bin")
        assert r["ok"] and r["found"] and r["table_offset"] == "0x8000", r
        by = {p["label"]: p for p in r["partitions"]}
        assert by["nvs"]["write_class"] == "nvs" and by["factory"]["write_class"] == "not-a-save"
        assert (case.dir / r["result_path"]).is_file()
        assert any("fw_esp_nvs" in s for s in r["next_steps"]) and any("fw_esp_image_info" in s for s in r["next_steps"])

        r = await call(c, "fw_esp_image_info", case_id=case.id, path="dumps/esp-flash.bin", partition="factory")
        assert r["ok"] and r["valid"] and r["chip"] == "ESP32-S3" and r["arch"] == "xtensa", r
        assert r["checksum"]["ok"] and r["sha256"]["ok"] and r["app_desc"]["project_name"] == "toy-arcade"
        assert r["range"]["start_hex"] == "0x10000" and r["range"]["partition"]["label"] == "factory"

        r = await call(c, "fw_esp_to_elf", case_id=case.id, path="dumps/esp-flash.bin", partition="factory")
        assert r["ok"] and r["e_machine"] == 94 and r["elf_path"].startswith("extract/esp-app-001/"), r
        elf = (case.dir / r["elf_path"]).read_bytes()
        assert elf[:4] == b"\x7fELF" and struct.unpack_from("<H", elf, 18)[0] == 94
        assert any("Xtensa" in n for n in r["notes"])  # REA 는 Xtensa 를 열지 못한다는 안내
        arts = {a["path"]: a for a in case.artifacts()}
        assert arts[r["elf_path"]]["kind"] == "firmware-image" and arts[r["elf_path"]]["extra"]["type"] == "esp-app-elf"

        r = await call(c, "fw_esp_nvs", case_id=case.id, path="dumps/esp-flash.bin", partition="nvs", max_results=200)
        assert r["ok"] and r["crc_summary"]["entry"]["bad"] == 0, r
        items = {(i["namespace"], i["key"]): i for i in r["items"]}
        assert items[("game", "hiscore")]["value"] == 98765 and items[("game", "hiscore")]["live"]
        assert items[("game", "credits")]["value"] == "C" * 70 and not items[("game", "credits")].get("secret")  # 게임 값은 가리지 않는다
        pswd = items[("nvs.net80211", "sta.pswd")]
        assert pswd["secret"] and set(pswd["value"]) == {"masked", "digest"} and pswd["value"]["digest"].startswith("sha256:")
        assert items[("cloud", "api_token")]["secret"]
        assert any("game/hiscore" in s for s in r["next_steps"])
        # 지운 옛 값(이력)
        r2 = await call(c, "fw_esp_nvs", case_id=case.id, path="dumps/esp-flash.bin", partition="nvs", namespace="game", key="hiscore",
                        include_erased=True)
        vals = sorted((i["value"], i["live"]) for i in r2["items"])
        assert vals == [(1200, False), (98765, True)], r2["items"]
        # blob 내보내기 (비밀 아님)
        r3 = await call(c, "fw_esp_nvs", case_id=case.id, path="dumps/esp-flash.bin", partition="nvs", namespace="game", export_blobs=True)
        slot = [p for p in r3["exported_blobs"] if p.endswith("game.slot0.bin")]
        assert slot and (case.dir / slot[0]).read_bytes() == bytes(range(200)) * 2, r3["exported_blobs"]
    text = json.dumps(r, ensure_ascii=False) + _texts(case)
    assert WIFI_PASS not in text and API_TOKEN not in text


async def test_c3_elf_rea_compat_flags(workspace, auth):
    from fwtriage_mcp.server import server
    from pweh.case import CaseStore

    case = CaseStore(workspace["cases_dir"]).create(title="c3", authorization=auth, case_id="c3case")
    flash, _ = build_esp_flash(chip_id=CHIP_C3, app=c3_app_image())
    (case.subdir("dumps") / "c3.bin").write_bytes(flash)
    async with Client(server) as c:
        plain = await call(c, "fw_esp_to_elf", case_id=case.id, path="dumps/c3.bin", partition="factory")
        compat = await call(c, "fw_esp_to_elf", case_id=case.id, path="dumps/c3.bin", partition="factory", rea_compat=True)
    assert plain["ok"] and compat["ok"] and plain["e_machine"] == compat["e_machine"] == 243
    e1 = (case.dir / plain["elf_path"]).read_bytes()
    e2 = (case.dir / compat["elf_path"]).read_bytes()
    assert struct.unpack_from("<I", e1, 36)[0] == 0x1 and struct.unpack_from("<I", e2, 36)[0] == 0x5
    assert e1[:36] == e2[:36] and e1[40:] == e2[40:]  # e_flags 만 다르다
    assert any("rea_compat" in n for n in compat["notes"]) and any("REA open_binary" in s for s in compat["next_steps"])
    assert any("rea_compat=true" in n for n in plain["notes"])


async def test_save_diff_nvs_mode_finds_observed_score(workspace, auth):
    from fwtriage_mcp.server import server
    from pweh.case import CaseStore

    case = CaseStore(workspace["cases_dir"]).create(title="nvs diff", authorization=auth, case_id="nvsdiff")
    paths = []
    for i, (score, coins) in enumerate([(100, 5), (250, 9), (400, 2)]):
        flash, _ = build_esp_flash(nvs=_nvs_snapshot(score, coins), app=s3_app_image())
        (case.subdir("dumps") / f"snap{i}.bin").write_bytes(flash)
        paths.append(f"dumps/snap{i}.bin")
    async with Client(server) as c:
        r = await call(c, "fw_save_diff", case_id=case.id, paths=paths, partition="nvs", labels=["시작", "1판", "2판"],
                       observations=[{"label": "score", "values": [100, 250, 400]}])
    assert r["ok"] and r["mode"] == "nvs", r
    changed = {(x["namespace"], x["key"]): x for x in r["changed"]}
    assert changed[("game", "hiscore")]["values"] == [100, 250, 400] and ("game", "coins") in changed
    assert ("game", "level") not in changed and r["unchanged_count"] >= 1
    assert [(m["label"], m["namespace"], m["key"]) for m in r["observation_matches"]] == [("score", "game", "hiscore")]
    assert WIFI_PASS not in json.dumps(r, ensure_ascii=False) + _texts(case)


def _raw_save(score: int, level: int) -> bytes:
    """512 바이트 원시 세이브(EEPROM 형): 0x40 에 u32le 점수, 0x44 에 레벨, 끝 2바이트에 [0, 0x1FE) 의 crc16-ccitt-false (빅엔디언)."""
    b = bytearray(b"\x00" * 0x200)
    b[0:4] = b"SAV1"
    struct.pack_into("<I", b, 0x40, score)
    b[0x44] = level
    crc = saves.checksum_compute("crc16-ccitt-false", bytes(b[:0x1FE]))
    struct.pack_into(">H", b, 0x1FE, crc)
    return bytes(b)


async def test_save_diff_bytes_and_checksum_find(workspace, auth):
    from fwtriage_mcp.server import server
    from pweh.case import CaseStore

    case = CaseStore(workspace["cases_dir"]).create(title="raw save", authorization=auth, case_id="rawsave")
    paths = []
    for i, (score, level) in enumerate([(1000, 1), (1750, 2), (2600, 2), (9100, 4)]):
        (case.subdir("dumps") / f"eeprom{i}.bin").write_bytes(_raw_save(score, level))
        paths.append(f"dumps/eeprom{i}.bin")
    async with Client(server) as c:
        d = await call(c, "fw_save_diff", case_id=case.id, paths=paths, observations=[{"label": "score", "values": [1000, 1750, 2600, None]}])
        assert d["ok"] and d["mode"] == "bytes" and d["changed_bytes"] > 0, d
        assert {"offset_abs": "0x40", "encoding": "u32le"}.items() <= next(m for m in d["observation_matches"] if m["encoding"] == "u32le").items()
        k = await call(c, "fw_checksum_find", case_id=case.id, paths=paths)
        assert k["ok"] and k["tested"] > 0, k
        strong = [x for x in k["candidates"] if x["strength"] == "strong"]
        assert strong and strong[0]["algorithm"] == "crc16-ccitt-false" and strong[0]["location_abs"] == "0x1fe", k["candidates"][:3]
        assert strong[0]["range_abs"] == ["0x0", "0x1fe"] and strong[0]["endian"] == "be"
        # 범위를 offset/length 로 좁혀도 절대 오프셋으로 보고한다
        k2 = await call(c, "fw_checksum_find", case_id=case.id, paths=paths, offset="0x100", length="0x100", algorithms=["crc16-ccitt-false"])
        assert k2["ok"] and all(int(x["location_abs"], 16) >= 0x100 for x in k2["candidates"]), k2
        # 백그라운드 job
        j = await call(c, "fw_checksum_find", case_id=case.id, paths=paths, background=True)
        assert j["background"] and j["job_id"]
        st = await call(c, "fwtriage_job_status", job_id=j["job_id"], wait_seconds=30)
        assert st["status"] == "succeeded" and st["result"]["candidates"], st


async def test_find_seq_tables_in_app_segments(game_case):
    from fwtriage_mcp.server import server

    case = game_case["case"]
    async with Client(server) as c:
        r = await call(c, "fw_find_seq_tables", case_id=case.id, path="dumps/esp-flash.bin", partition="factory")
    assert r["ok"] and r["mode"] == "esp-app-segments", r
    top = r["candidates"][0]
    assert top["konami_like"] and top["values"][:10] == list(KONAMI), r["candidates"][:3]
    assert 0x3C000000 <= int(top["address_hex"], 16) < 0x3E000000  # S3 DROM 주소(디컴파일러 주소)
    assert all(s.get("kind") not in ("flash-text", "iram", "rtc-text") for s in r["scanned"])


async def test_argument_errors(game_case):
    from fwtriage_mcp.server import server

    case = game_case["case"]
    async with Client(server) as c:
        one = await call(c, "fw_save_diff", case_id=case.id, paths=["dumps/esp-flash.bin"])
        both = await call(c, "fw_esp_nvs", case_id=case.id, path="dumps/esp-flash.bin", partition="nvs", offset=0x9000)
        nopart = await call(c, "fw_esp_nvs", case_id=case.id, path="dumps/esp-flash.bin", partition="saves")
        badalg = await call(c, "fw_checksum_find", case_id=case.id, paths=["dumps/esp-flash.bin"] * 2, algorithms=["md5"])
        outside = await call(c, "fw_esp_image_info", case_id=case.id, path="/etc/passwd")
        notapp = await call(c, "fw_esp_to_elf", case_id=case.id, path="dumps/esp-flash.bin", partition="nvs")
    for r in (one, both, nopart, badalg, notapp):
        assert "[validation_failed]" in r.get("_error", ""), r
    assert "nvs" in nopart["_error"] and "factory" in nopart["_error"]  # 있는 파티션 안내
    assert outside.get("_error"), outside


async def test_snapshot_size_limits(workspace, auth, monkeypatch):
    """스냅샷 합계·입력 크기 상한(메모리 보호): 넘으면 읽기 전에 validation_failed."""
    from fwtriage_mcp import server as srv
    from pweh.case import CaseStore

    case = CaseStore(workspace["cases_dir"]).create(title="limits", authorization=auth, case_id="limits")
    for i in range(3):
        (case.subdir("dumps") / f"s{i}.bin").write_bytes(bytes([i]) * 4096)
    monkeypatch.setattr(srv, "CHECKSUM_MAX_TOTAL", 8192)
    monkeypatch.setattr(srv, "SEQ_TABLES_MAX_BYTES", 1024)
    async with Client(srv.server) as c:
        k = await call(c, "fw_checksum_find", case_id=case.id, paths=["dumps/s0.bin", "dumps/s1.bin", "dumps/s2.bin"])
        ok = await call(c, "fw_checksum_find", case_id=case.id, paths=["dumps/s0.bin", "dumps/s1.bin"])
        q = await call(c, "fw_find_seq_tables", case_id=case.id, path="dumps/s0.bin")
    assert "[validation_failed]" in k.get("_error", "") and "MiB" in k["_error"], k
    assert ok["ok"], ok
    assert "[validation_failed]" in q.get("_error", ""), q


# ---------------------------------------------------------------------------
# 반박 검토에서 나온 회귀 시험 (비밀값 우회 경로·NVS 바이트 비교 거부·인자 처리)
# ---------------------------------------------------------------------------


async def test_save_diff_added_removed_secrets_are_masked(workspace, auth):
    """비밀 키가 첫 스냅샷에만(removed) 또는 마지막 스냅샷에만(added) 있어도 응답·결과 파일에 원문이 없다."""
    from fwtriage_mcp.server import server
    from pweh.case import CaseStore

    case = CaseStore(workspace["cases_dir"]).create(title="added removed", authorization=auth, case_id="addrem")
    d = case.subdir("dumps")
    plain = NvsImage(version=2)
    plain.put("game", "hiscore", "U32", 10)
    (d / "a.bin").write_bytes(plain.build(total_pages=4))
    sec = NvsImage(version=2)
    sec.put("game", "hiscore", "U32", 20)
    sec.put_str("nvs.net80211", "sta.pswd", WIFI_PASS)
    sec.put_str("cloud", "api_token", API_TOKEN)
    (d / "b.bin").write_bytes(sec.build(total_pages=4))
    async with Client(server) as c:
        fwd = await call(c, "fw_save_diff", case_id=case.id, paths=["dumps/a.bin", "dumps/b.bin"], mode="nvs")
        back = await call(c, "fw_save_diff", case_id=case.id, paths=["dumps/b.bin", "dumps/a.bin"], mode="nvs")
    assert fwd["ok"] and back["ok"], (fwd, back)
    assert {x["key"] for x in fwd["added"]} >= {"sta.pswd", "api_token"} and all(x["secret"] for x in fwd["added"] if x["key"] != "hiscore")
    assert {x["key"] for x in back["removed"]} >= {"sta.pswd", "api_token"}
    text = json.dumps([fwd, back], ensure_ascii=False) + _texts(case)
    assert WIFI_PASS not in text and API_TOKEN not in text


async def test_bytes_diff_and_checksum_refuse_nvs(workspace, auth):
    """NVS 를 담은 범위는 바이트 비교·체크섬 찾기를 거부한다(비밀값을 가릴 수 없으므로). auto 는 NVS 면 nvs 로 간다 — 지운 페이지가 맨 앞이어도."""
    from fwtriage_mcp.server import server
    from pweh.case import CaseStore

    case = CaseStore(workspace["cases_dir"]).create(title="nvs bytes", authorization=auth, case_id="nvsbytes")
    d = case.subdir("dumps")
    paths, flashes = [], []
    for i, score in enumerate([100, 250, 400]):
        flash, _ = build_esp_flash(nvs=_nvs_snapshot(score, i), app=s3_app_image())
        (d / f"f{i}.bin").write_bytes(flash)
        paths.append(f"dumps/f{i}.bin")
        flashes.append(flash)
    # NVS 파티션만 담은 파일, 맨 앞 페이지는 지움(0xFFFFFFFF 빈 페이지가 아닌 '빈 페이지' 상태)
    nvs_only = []
    for i, score in enumerate([1, 2, 3]):
        img = bytearray(_nvs_snapshot(score, i))
        blank = bytearray(b"\xff" * 4096)
        (d / f"n{i}.bin").write_bytes(bytes(blank + img))
        nvs_only.append(f"dumps/n{i}.bin")
    async with Client(server) as c:
        whole = await call(c, "fw_save_diff", case_id=case.id, paths=paths)  # 전체 플래시 bytes → NVS 겹침
        part = await call(c, "fw_save_diff", case_id=case.id, paths=paths, partition="nvs", mode="bytes")
        auto = await call(c, "fw_save_diff", case_id=case.id, paths=nvs_only)
        ck = await call(c, "fw_checksum_find", case_id=case.id, paths=nvs_only)
        ck2 = await call(c, "fw_checksum_find", case_id=case.id, paths=paths, partition="nvs")
        app_only = await call(c, "fw_save_diff", case_id=case.id, paths=paths, partition="factory")  # NVS 가 아닌 파티션은 그대로
    for r in (whole, part, ck, ck2):
        assert "[validation_failed]" in r.get("_error", "") and "NVS" in r["_error"], r
    assert auto["ok"] and auto["mode"] == "nvs", auto
    assert app_only["ok"] and app_only["mode"] == "bytes", app_only
    assert WIFI_PASS not in json.dumps([whole, part, auto, ck, ck2], ensure_ascii=False) + _texts(case)


async def test_secret_inside_other_value_is_masked_and_not_exported(workspace, auth):
    """sta.pswd 와 같은 비밀번호를 평범한 이름의 설정 blob·문자열이 담고 있어도 그 값까지 가리고 내보내지 않는다."""
    from fwtriage_mcp.server import server
    from pweh.case import CaseStore

    case = CaseStore(workspace["cases_dir"]).create(title="config blob", authorization=auth, case_id="cfgblob")
    nv = NvsImage(version=2)
    nv.put_str("nvs.net80211", "sta.pswd", WIFI_PASS)
    nv.put_blob("app", "config", b'{"ssid":"toy","pw":"' + WIFI_PASS.encode() + b'"}')
    nv.put_str("app", "note", "wifi=" + WIFI_PASS)
    nv.put_blob("game", "slot0", b"\x01\x02\x03\x04" * 8)
    (case.subdir("dumps") / "nvs.bin").write_bytes(nv.build(total_pages=4))
    async with Client(server) as c:
        r = await call(c, "fw_esp_nvs", case_id=case.id, path="dumps/nvs.bin", export_blobs=True, max_results=100)
    assert r["ok"], r
    items = {(i["namespace"], i["key"]): i for i in r["items"]}
    assert items[("app", "note")]["secret"]
    assert not any(p.endswith("app.config.bin") for p in r["exported_blobs"]) and any(p.endswith("game.slot0.bin") for p in r["exported_blobs"])
    files = "".join((case.dir / p).read_bytes().decode("latin1") for p in r["exported_blobs"])
    assert WIFI_PASS not in json.dumps(r, ensure_ascii=False) + _texts(case) + files


async def test_game_pack_hits_mask_values(workspace, auth):
    """게임 팩 히트의 key=값·URL 자격증명·JWT 값은 <masked> 로 바뀐다(응답·결과 파일)."""
    from fwtriage_mcp.server import server
    from pweh.case import CaseStore

    case = CaseStore(workspace["cases_dir"]).create(title="game hits", authorization=auth, case_id="gamehits")
    secrets = ["ABCD-1234-ZZ", "LIC-9F8E-7D6C", "S3cretPW", "eyJhbGciOiJIUzI1NiJ9.SECRETJWT"]
    (case.subdir("dumps") / "conf.txt").write_text(
        "activation_code=ABCD-1234-ZZ\nlicense_key: LIC-9F8E-7D6C\nmqtt_uri=mqtt://user:S3cretPW@broker.local/dlc\n"
        "access_token=eyJhbGciOiJIUzI1NiJ9.SECRETJWT\npurchase_dlc_unlock=1\n", encoding="utf-8")
    async with Client(server) as c:
        r = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir="dumps/conf.txt", patterns="game", max_results=200)
    assert r["ok"] and r["hits"], r
    text = json.dumps(r, ensure_ascii=False) + _texts(case)
    assert not [s for s in secrets if s in text], [s for s in secrets if s in text]
    assert any(h.get("masked") for h in r["hits"])


async def test_argument_and_offset_fixes(game_case):
    """partition+length 거부, 입력 파일 기준 오프셋(file_offset_abs·offset_abs), 정상 덤프에 잘림 경고 없음, 음수 관찰값."""
    from fwtriage_mcp.server import server

    case = game_case["case"]
    async with Client(server) as c:
        both = await call(c, "fw_esp_nvs", case_id=case.id, path="dumps/esp-flash.bin", partition="nvs", length=4096)
        img = await call(c, "fw_esp_image_info", case_id=case.id, path="dumps/esp-flash.bin", partition="factory")
        nvs = await call(c, "fw_esp_nvs", case_id=case.id, path="dumps/esp-flash.bin", partition="nvs", key="hiscore")
        parts = await call(c, "fw_esp_partitions", case_id=case.id, path="dumps/esp-flash.bin")
        parts_at = await call(c, "fw_esp_partitions", case_id=case.id, path="dumps/esp-flash.bin", offset="0x8000")
    assert "[validation_failed]" in both.get("_error", ""), both
    seg0 = img["segments"][0]
    assert int(seg0["file_offset_abs"], 16) == 0x10000 + int(seg0["file_offset"], 16)
    it = nvs["items"][0]
    assert int(it["offset_abs"], 16) == 0x9000 + int(it["offset"], 16)
    assert not any("넘음" in w for w in parts["warnings"]), parts["warnings"]
    assert parts_at["found"] and parts_at["table_offset"] == "0x8000" and not any("넘음" in w for w in parts_at["warnings"]), parts_at


async def test_observation_negative_and_added_key(workspace, auth):
    """음수 관찰값(I8 등)과 중간 스냅샷에 처음 생긴 키도 관찰값으로 찾는다."""
    from fwtriage_mcp.server import server
    from pweh.case import CaseStore

    case = CaseStore(workspace["cases_dir"]).create(title="obs", authorization=auth, case_id="obs")
    d = case.subdir("dumps")
    for i, (temp, bonus) in enumerate([(-3, None), (-7, 200), (5, 300)]):
        nv = NvsImage(version=2)
        nv.put("game", "temp", "I8", temp)
        if bonus is not None:
            nv.put("game", "bonus", "U16", bonus)
        (d / f"o{i}.bin").write_bytes(nv.build(total_pages=4))
    paths = [f"dumps/o{i}.bin" for i in range(3)]
    async with Client(server) as c:
        r = await call(c, "fw_save_diff", case_id=case.id, paths=paths, mode="nvs",
                       observations=[{"label": "temp", "values": [-3, -7, "5"]}, {"label": "bonus", "values": [None, 200, 300]}])
    assert r["ok"], r
    got = {(m["label"], m["key"]) for m in r["observation_matches"]}
    assert got == {("temp", "temp"), ("bonus", "bonus")}, r["observation_matches"]


async def test_export_blob_name_collisions_get_suffix(workspace, auth):
    """정리한 이름이 겹치는 blob 은 번호를 붙여 모두 내보낸다(덮어쓰거나 버리지 않음)."""
    from fwtriage_mcp.server import server
    from pweh.case import CaseStore

    case = CaseStore(workspace["cases_dir"]).create(title="collide", authorization=auth, case_id="collide")
    nv = NvsImage(version=2)
    nv.put_blob("game", "a b", b"\x01" * 8)
    nv.put_blob("game", "a_b", b"\x02" * 8)
    (case.subdir("dumps") / "nvs.bin").write_bytes(nv.build(total_pages=4))
    async with Client(server) as c:
        r = await call(c, "fw_esp_nvs", case_id=case.id, path="dumps/nvs.bin", export_blobs=True)
    assert len(r["exported_blobs"]) == 2 and len(set(r["exported_blobs"])) == 2, r["exported_blobs"]
    contents = sorted((case.dir / p).read_bytes() for p in r["exported_blobs"])
    assert contents == [b"\x01" * 8, b"\x02" * 8]
    assert any("번호" in w for w in r["warnings"])
