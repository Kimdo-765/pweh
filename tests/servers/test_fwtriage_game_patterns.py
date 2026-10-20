"""fwtriage-mcp 게임 패턴 팩(src/pweh/data/game-hunt-patterns.yaml)과 save-analysis 요약 스키마 테스트.

- 팩 로더: load_patterns(pack='game'), 기본 CCTV 팩은 예전 그대로, 팩·파일별 캐시, 알 수 없는 팩 → ValidationFailed
- YAML 규칙: 정규식 컴파일, 빈 문자열 불일치, 사전 필터 리터럴, id 유일·'game-' 접두사, category 고정 9종, severity info/low,
  entitlement rationale 의 '보고만 (패치·우회 금지)', 패턴마다 양성 예시, 비게임 라이브러리에서 본 오탐 문자열 회귀
- 선택: split_pack_spec('game' / 'game:<x>' / 다른 팩 선택자와 섞기 → 오류), 게임 팩의 엄격한 선택(오타 → 오류)
- MCP(in-memory Client): 문자열을 심은 합성 펌웨어로 fw_strings_hunt(patterns='game'), CCTV 기본값과 섞이지 않음,
  fw_hunt_patterns(pack='game'), 알 수 없는 팩 → validation_failed
- 스키마: save-analysis 유효 예시 통과, 잘못된 예시 실패
합성 데이터만 쓴다 (실제 펌웨어·기기 없음).
"""

from __future__ import annotations

import collections
import copy
import json
import re
import sys
from pathlib import Path

import pytest
import yaml
from mcp import Client

from mcp_helpers import call

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "mcp-servers" / "fwtriage-mcp"))

from fwtriage_mcp.common import Ctl  # noqa: E402
from fwtriage_mcp.hunt import hunt  # noqa: E402
from fwtriage_mcp.patterns import (  # noqa: E402
    DEFAULT_PACK,
    PACKS,
    custom_id,
    data_file_path,
    load_patterns,
    matches_empty,
    pack_name,
    required_literals,
    split_pack_spec,
)
from pweh import schemas  # noqa: E402
from pweh.errors import ValidationFailed  # noqa: E402

pytestmark = pytest.mark.anyio

GAME_YAML = REPO / "src" / "pweh" / "data" / "game-hunt-patterns.yaml"
CCTV_YAML = REPO / "src" / "pweh" / "data" / "cctv-hunt-patterns.yaml"
GAME_CATEGORIES = {"debug-menu", "cheat-input", "unlock-condition", "save-format", "save-integrity", "nfc-tag", "clock", "online-sync", "entitlement"}
GAME_VENDORS = {"generic", "esp-idf", "arduino", "nxp", "posix"}
REPORT_ONLY = "보고만 (패치·우회 금지)"
NTAG215_VERSION = b"\x00\x04\x04\x02\x01\x00\x11\x03"

# 패턴마다 반드시 잡아야 하는 예시 (새 패턴을 더하면 예시도 더한다). raw 패턴은 bytes.
POSITIVE: dict[str, list] = {
    "game-debug-menu": ["DEBUG MENU", "enter_test_mode", "Service Mode"],
    "game-level-sound-select": ["Level Select", "sound_test", "stageSkip"],
    "game-god-mode": ["God Mode ON", "infinite_lives", "INVINCIBLE"],
    "game-debug-console": ["Type 'help' to get the list of commands.", "esp_console_cmd_register", "Unrecognized command"],
    "game-cheat-keywords": ["Cheat code accepted", "konami", "easter_egg"],
    "game-konami-sequence": ["UP UP DOWN DOWN LEFT RIGHT LEFT RIGHT B A", "uuddlrlrba"],
    "game-input-sequence": ["button_sequence", "combo matched", "KeySeq"],
    "game-unlock-keywords": ["Secret stage unlocked!", "g_unlock_flags", "isUnlocked", "UNLOCKABLES"],
    "game-hidden-content": ["Bonus Stage", "secret_character", "hidden ending"],
    "game-progress-counters": ["games_played", "Total Wins", "max_level", "getPlayCount"],
    "game-highscore": ["HISCORE", "saveHighScore", "Leaderboard", "best_time"],
    "game-save-keywords": ["savegame", "Save failed", "factory reset", "load_slot"],
    "game-nvs-api": ["nvs_get_u32", "ESP_ERR_NVS_NOT_FOUND", "/IDF/components/nvs_flash/src/nvs_api.cpp"],
    "game-arduino-storage": ["/libraries/Preferences/src/Preferences.cpp", "EEPROM.h"],
    "game-fs-save-paths": ["/spiffs/save.bin", "/littlefs/progress.dat"],
    "game-save-file-ext": ["slot1.sav", "game.srm", "quick.state1"],
    "game-currency": ["coin_count", "gems balance"],
    "game-eeprom-storage": ["EEPROM", "AT24C256", "FRAM init", "battery backed"],
    "game-checksum-keywords": ["save checksum mismatch", "Bad CRC", "save data corrupted"],
    "game-crc-hash-api": ["esp_rom_crc32_le", "mbedtls_md_hmac_starts", "HMAC-SHA256", "crc32"],
    "game-nfc-chips": ["NTAG215", "MFRC522", "ISO/IEC 14443-3", "NDEF message"],
    "game-nfc-commands": ["PWD_AUTH failed", "READ_SIG"],
    "game-ntag-version-raw": [NTAG215_VERSION, b"\x00\x04\x03\x01\x01\x00\x0b\x03"],
    "game-tag-uid-checks": ["tag detected", "figure_uid", "uid whitelist", "card uid"],
    "game-amiibo": ["amiibo"],
    "game-time-api": ["localtime_r", "gettimeofday"],
    "game-sntp-ntp": ["esp_sntp_setservername", "pool.ntp.org", "time.google.com"],
    "game-rtc-chips": ["DS3231", "rtc_alarm", "PCF8563"],
    "game-date-events": ["daily bonus", "Christmas", "login_streak"],
    "game-date-format": ["%Y-%m-%d", "%04d/%02d/%02d"],
    "game-net-client-api": ["esp_http_client_perform", "HTTP_CLIENT", "MQTT_EVENT_CONNECTED"],
    "game-arduino-net": ["/libraries/HTTPClient/src/HTTPClient.cpp"],
    "game-wifi-ble": ["nvs.net80211", "esp_wifi_connect", "WIFI_EVENT_STA_DISCONNECTED"],
    "game-urls": ["https://api.example.invalid/v1/scores"],
    "game-sync-keywords": ["cloud save", "score upload", "online ranking"],
    "game-ota-update": ["ota_url", "firmware update url"],
    "game-dlc-purchase": ["DLC pack", "in-app purchase", "premium_unlock"],
    "game-license-token": ["license check failed", "unlock key"],
}

# 비게임 라이브러리(libc·OpenSSL·CPython)에서 실제로 본 오탐 문자열: 어느 게임 패턴과도 일치하면 안 된다
NOISE = ["fputs_unlocked", "getc_unlocked", "X509_NAME_ENTRY", "BIO_new_NDEF", "ndef_prefix", "undefined", "configure", "display time",
         "TAG_MISMATCH", "OSSL_STORE_unlock", "code input", "frame", "invalid input sequence", "Sequence_Index", "name_entry"]


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _game():
    return load_patterns(pack="game")


def _hits(h, sample) -> bool:
    if h.rx_bytes is not None:
        return h.rx_bytes.search(sample if isinstance(sample, bytes) else sample.encode("latin-1")) is not None
    return h.rx is not None and isinstance(sample, str) and h.rx.search(sample) is not None


# ---------------------------------------------------------------------------
# 팩 로더
# ---------------------------------------------------------------------------


def test_game_pack_loads_separately_and_cctv_default_is_unchanged():
    g = _game()
    c = load_patterns()
    assert g.pack == "game" and c.pack == DEFAULT_PACK == "cctv"
    assert g.errors == [] and c.errors == []
    assert Path(g.source).name == "game-hunt-patterns.yaml" and g.source == str(data_file_path("game"))
    assert Path(c.source).name == "cctv-hunt-patterns.yaml" and c.source == str(data_file_path()) == str(data_file_path("cctv"))
    assert list(PACKS) == ["cctv", "game"]
    # 팩별 캐시: 같은 팩은 같은 객체, 팩 이름은 정규화
    assert load_patterns(pack="cctv") is c and load_patterns(pack=" GAME ") is g and load_patterns(pack=None) is c
    # 기본 CCTV 팩은 YAML 그대로 (게임 팩과 섞이지 않음)
    raw_cctv = yaml.safe_load(CCTV_YAML.read_text(encoding="utf-8"))
    assert [h.id for h in c.string_heuristics] == [x["id"] for x in raw_cctv["string_heuristics"]]
    assert c.function_heuristics and c.credential_patterns and c.known_hashes and c.candidate_passwords
    gids, cids = {h.id for h in g.string_heuristics}, {h.id for h in c.string_heuristics}
    assert not gids & cids and all(i.startswith("game-") for i in gids) and not any(i.startswith("game-") for i in cids)
    # 게임 팩은 string_heuristics 만 — fw_rootfs_audit / fw_elf_info / fw_crack_hashes 에 섞여 들어가지 않는다
    assert g.credential_patterns == [] and g.function_heuristics == [] and g.known_hashes == {} and g.candidate_passwords == []
    assert g.web_server_binaries == {} and g.interesting_paths == []
    assert g.categories() == sorted(GAME_CATEGORIES)


def test_unknown_pack_is_a_validation_error_and_never_builds_a_path():
    for bad in ("nope", "../../etc/passwd", "rf", "cctv/../game"):
        with pytest.raises(ValidationFailed) as ei:
            load_patterns(pack=bad)
        assert "알 수 없는 패턴 팩" in str(ei.value) and "cctv, game" in str(ei.value)
        with pytest.raises(ValidationFailed):
            data_file_path(bad)
    assert pack_name("") == pack_name(None) == "cctv" and pack_name("Game") == "game"


def test_pack_cache_is_keyed_by_pack_and_file(tmp_path):
    f = tmp_path / "mini.yaml"
    f.write_text("version: 1\nstring_heuristics:\n  - id: game-mini\n    pattern: 'PWEH-MINI'\n    category: debug-menu\n"
                 "    severity_hint: low\n    scope: any\n    vendor: generic\n", encoding="utf-8")
    a = load_patterns(f, pack="game")
    b = load_patterns(f, pack="cctv")
    assert a is not b and a.pack == "game" and b.pack == "cctv" and load_patterns(f, pack="game") is a
    # 전체 선택 키워드는 그 팩의 이름: game 팩에서 'cctv' 는 전체가 아니고(엄격 모드면 오류), cctv 팩에서 'game' 은 전체가 아니다
    assert [h.id for h in a.select("game")[0]] == ["game-mini"]
    with pytest.raises(ValidationFailed):
        a.select(["cctv"], strict=True)
    sel, notes = b.select(["game"])
    assert [h.id for h in sel] == [custom_id("lit", "game")] and notes  # 기존 CCTV 동작(라우팅 전 직접 호출): 리터럴


# ---------------------------------------------------------------------------
# YAML 규칙
# ---------------------------------------------------------------------------


def test_game_yaml_entries_follow_conventions():
    raw = yaml.safe_load(GAME_YAML.read_text(encoding="utf-8"))
    entries = raw["string_heuristics"]
    ids = [e["id"] for e in entries]
    assert [i for i, n in collections.Counter(ids).items() if n > 1] == [], "id 중복"
    assert len(entries) == len(_game().string_heuristics) >= 30
    for e in entries:
        assert set(e) == {"id", "pattern", "category", "severity_hint", "scope", "vendor", "rationale", "references"}, e["id"]
        assert e["id"].startswith("game-") and re.fullmatch(r"game-[a-z0-9-]+", e["id"]), e["id"]
        assert isinstance(e["pattern"], str) and e["pattern"], e["id"]
        assert e["category"] in GAME_CATEGORIES, e["id"]
        assert e["severity_hint"] in ("info", "low"), e["id"]
        assert e["scope"] in ("any", "text", "strings", "raw"), e["id"]
        assert e["vendor"] in GAME_VENDORS, e["id"]
        assert isinstance(e["references"], list), e["id"]
        # 한국어 rationale, fw_strings_hunt checks[].description(160자에서 자름)에 다 보이게
        assert re.search("[가-힣]", e["rationale"]) and len(e["rationale"]) <= 160, e["id"]
        if e["category"] == "entitlement":
            assert REPORT_ONLY in e["rationale"], e["id"]
        # 범위 플래그는 쓰지 않는다 (사전 필터 리터럴이 전역 플래그 기준)
        assert "(?i:" not in e["pattern"] and "(?-i" not in e["pattern"], e["id"]
    assert {e["category"] for e in entries} == GAME_CATEGORIES, "모든 category 에 패턴이 하나 이상"
    assert any(REPORT_ONLY in n for n in raw["notes"])
    # 경계 문구: amiibo 류 태그 암호는 존재만, 온라인 동기화되는 서명·HMAC 은 재계산하지 않음
    by_id = {e["id"]: e for e in entries}
    assert "존재만 보고" in by_id["game-amiibo"]["rationale"] and "재암호" in by_id["game-amiibo"]["rationale"]
    assert "보고만" in by_id["game-crc-hash-api"]["rationale"] and "온라인 동기화" in by_id["game-crc-hash-api"]["rationale"]
    assert "보고만" in by_id["game-currency"]["rationale"]


def test_every_game_regex_compiles_has_prefilter_and_never_matches_empty():
    for h in _game().string_heuristics:
        assert (h.rx is not None) or (h.rx_bytes is not None), h.id
        assert not matches_empty(h), f"{h.id}: 빈 문자열과 일치"
        if h.scope == "raw":
            assert h.rx_bytes is not None and h.rx_bytes.search(b"\x00" * 64 + b"\xff" * 64) is None, h.id
            continue
        # 사전 필터 리터럴이 있어야 큰 바이너리에서 관련 없는 파일을 건너뛴다
        assert h.literals and all(len(lit) >= 3 for lit in h.literals), f"{h.id}: 사전 필터 리터럴 없음 {h.literals}"


def test_every_game_pattern_hits_its_samples_and_none_hits_known_noise():
    hs = {h.id: h for h in _game().string_heuristics}
    assert set(POSITIVE) == set(hs), f"예시 없는 패턴: {sorted(set(hs) - set(POSITIVE))}, 없는 id: {sorted(set(POSITIVE) - set(hs))}"
    for hid, samples in POSITIVE.items():
        for s in samples:
            assert _hits(hs[hid], s), f"{hid} 가 {s!r} 를 놓침"
            # 사전 필터도 통과해야 실제 탐색에서 잡힌다
            if hs[hid].rx is not None:
                assert hs[hid].prefilter(s, lambda s=s: s.lower()), f"{hid}: 사전 필터가 {s!r} 를 건너뜀"
    for s in NOISE:
        bad = [h.id for h in hs.values() if h.rx is not None and h.rx.search(s)]
        assert not bad, f"{s!r} 가 {bad} 와 일치 (비게임 라이브러리 오탐 회귀)"


def test_scoped_inline_flags_do_not_make_the_prefilter_skip(tmp_path):
    """회귀: 're:(?i:secret)' 의 리터럴 'secret' 을 대소문자 구분으로 비교해 'SECRET' 만 있는 파일을 건너뛰었다."""
    assert required_literals(r"(?i:secret)")[0] is None
    assert required_literals(r"(?i)fo(?-i:BARX)")[0] is None
    assert required_literals(r"\bNetKeyboard\b") == (["NetKeyboard"], False)  # 범위 플래그가 없으면 그대로
    case = tmp_path / "case"
    f = case / "dumps" / "blob.bin"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"\x00\x00THE SECRET VALUE\x00\x00")
    sel, _ = load_patterns().select(["re:(?i:secret)"])
    res = hunt(f, False, case, Ctl(max_seconds=60), sel, max_hits=10, per_pattern_cap=10, max_file_size=1 << 20)
    assert res["summary"]["hits_total"] == 1


# ---------------------------------------------------------------------------
# 선택 (split_pack_spec + 엄격한 선택)
# ---------------------------------------------------------------------------


def test_split_pack_spec_routes_game_and_keeps_cctv_untouched():
    spec = ["xm-*", "lit:a"]
    assert split_pack_spec(spec) == ("cctv", spec) and split_pack_spec(spec)[1] is spec
    assert split_pack_spec(None) == ("cctv", None) and split_pack_spec("cctv") == ("cctv", "cctv") and split_pack_spec("") == ("cctv", "")
    assert split_pack_spec("game") == ("game", ["game"])
    assert split_pack_spec("game:nfc-tag") == ("game", ["nfc-tag"])
    assert split_pack_spec(["GAME:Save-Format", " game ", "lit:PWEH", "re:x\\d+", "raw:\\x00"]) == ("game", ["Save-Format", "game", "lit:PWEH", "re:x\\d+", "raw:\\x00"])
    for bad, msg in ((["game", "xm-*"], "섞을 수 없습니다"), (["game:debug-menu", "cctv"], "섞을 수 없습니다"),
                     (["game", "plainword"], "섞을 수 없습니다"), ("game:", "선택자가 없습니다"), ("game:  ", "선택자가 없습니다")):
        with pytest.raises(ValidationFailed) as ei:
            split_pack_spec(bad)
        assert msg in str(ei.value), bad


def test_game_selection_is_strict_and_supports_category_id_vendor_severity_prefix():
    g = _game()
    everything = {h.id for h in g.string_heuristics}
    assert {h.id for h in g.select(["game"], strict=True)[0]} == everything
    assert {h.id for h in g.select(["all"], strict=True)[0]} == everything
    nfc, _ = g.select(["nfc-tag"], strict=True)
    assert nfc and {h.category for h in nfc} == {"nfc-tag"}
    assert [h.id for h in g.select(["game-amiibo"], strict=True)[0]] == ["game-amiibo"]
    assert {h.id for h in g.select(["game-nfc-*"], strict=True)[0]} == {"game-nfc-chips", "game-nfc-commands"}
    assert {h.vendor for h in g.select(["esp-idf"], strict=True)[0]} == {"esp-idf"}
    low, _ = g.select(["low"], strict=True)
    assert low and {h.severity for h in low} == {"low"}
    assert {h.severity for h in g.select(["game"], min_severity="low", strict=True)[0]} == {"low"}
    assert g.select(["game"], min_severity="medium", strict=True)[0] == []
    mixed, _ = g.select(["entitlement", "lit:PWEH-GAME-MARK"], strict=True)
    assert {h.id for h in mixed} == {"game-dlc-purchase", "game-license-token", custom_id("lit", "PWEH-GAME-MARK")}
    for typo in ("no-such-category", "cctv", "xm-*", "debug_menu"):
        with pytest.raises(ValidationFailed) as ei:
            g.select([typo], strict=True)
        assert f"'game:{typo}'" in str(ei.value) and "debug-menu" in str(ei.value)


# ---------------------------------------------------------------------------
# MCP (in-memory Client)
# ---------------------------------------------------------------------------

PLANTED = [
    "DEBUG MENU", "Level Select", "God Mode ON", "Type 'help' to get the list of commands.",
    "Cheat code accepted", "UUDDLRLRBA", "combo matched",
    "Secret stage unlocked!", "Bonus Stage", "games_played",
    "hiscore", "Save failed", "nvs_set_u32", "/libraries/Preferences/src/Preferences.cpp", "/spiffs/save.bin", "slot1.sav",
    "coin_count", "AT24C256",
    "save checksum mismatch", "esp_rom_crc32_le",
    "NTAG215", "PWD_AUTH failed", "tag detected", "amiibo",
    "localtime_r", "pool.ntp.org", "DS3231", "daily bonus", "%Y-%m-%d",
    "esp_http_client_perform", "/libraries/HTTPClient/src/HTTPClient.cpp", "nvs.net80211", "https://api.example.invalid/v1/scores",
    "cloud save", "ota_url",
    "DLC pack", "license check failed",
    "PWEH-GAME-MARK",
]


def _blob() -> bytes:
    out = bytearray(b"\xff" * 4096)
    for i, s in enumerate(PLANTED):
        out += s.encode("ascii") + b"\x00" * (3 + i % 5)
        out += b"\xff" * 61
    out += NTAG215_VERSION + b"\xff" * 64
    out += b"\x00\x00OpenTelnet:OpenOnce\x00\x00"  # CCTV 앵커(xm-opentelnet-cmd): 게임 팩 결과에 나오면 안 된다
    out += "high score".encode("utf-16-le") + b"\x00\x00"
    out += b"\xff" * 4096
    return bytes(out)


@pytest.fixture
def game_case(workspace, auth):
    from pweh.case import CaseStore

    store = CaseStore(workspace["cases_dir"])
    case = store.create(title="게임 패턴 팩", authorization=auth, case_id="gamecase", profile="hisilicon-ipcam")
    blob = _blob()
    (case.subdir("dumps") / "game-fw.bin").write_bytes(blob)
    return {"case": case, "blob": blob}


def _full(case, r) -> dict:
    return json.loads((case.dir / r["result_path"]).read_text(encoding="utf-8"))


async def test_strings_hunt_game_pack_over_synthetic_firmware(game_case):
    from fwtriage_mcp.server import server

    case, blob = game_case["case"], game_case["blob"]
    g = _game()
    async with Client(server) as c:
        r = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir="dumps/game-fw.bin", patterns="game", max_results=500)
    assert r["ok"], r
    assert r["patterns"]["pack"] == "game" and Path(r["patterns"]["source"]).name == "game-hunt-patterns.yaml"
    assert r["patterns"]["selected"] == len(g.string_heuristics)
    ids = {h["pattern_id"] for h in r["hits"]}
    assert ids and all(i.startswith("game-") for i in ids), ids
    assert "xm-opentelnet-cmd" not in ids
    assert {h["category"] for h in r["hits"]} == GAME_CATEGORIES
    assert all(h["finding_category"] == "other" for h in r["hits"])
    assert all(h["severity"] in ("info", "low") for h in r["hits"])
    # 오프셋은 파일 오프셋 (strings·raw·UTF-16LE 모두)
    kon = [h for h in r["hits"] if h["pattern_id"] == "game-konami-sequence"]
    assert kon and kon[0]["offset"] == blob.index(b"UUDDLRLRBA") and kon[0]["file"] is None and kon[0]["path"] == "dumps/game-fw.bin"
    raw = [h for h in r["hits"] if h["pattern_id"] == "game-ntag-version-raw"]
    assert raw and raw[0]["offset"] == blob.index(NTAG215_VERSION) and raw[0]["scope"] == "raw"
    u16 = [h for h in r["hits"] if h["pattern_id"] == "game-highscore" and h["encoding"] == "utf16le"]
    assert u16 and u16[0]["offset"] == blob.index("high score".encode("utf-16-le"))
    full = _full(case, r)
    assert full["params"]["pack"] == "game" and full["params"]["patterns"] == "game"
    assert Path(full["params"]["pattern_source"]).name == "game-hunt-patterns.yaml"
    assert full["summary"]["vendor_family_guess"] is None  # CCTV 전용 추정은 게임 팩에서 비운다
    assert full["summary"]["vendor_scores"].get("esp-idf", 0) >= 1
    checks = {ch["id"]: ch for ch in full["checks"]}
    assert set(checks) == {h.id for h in g.string_heuristics}
    assert all(checks[i]["result"] == "match" for i in POSITIVE)  # 심은 문자열로 모든 패턴이 일치
    for hid in ("game-dlc-purchase", "game-license-token"):
        assert REPORT_ONLY in checks[hid]["description"]


async def test_strings_hunt_game_selectors_errors_and_custom_patterns(game_case):
    from fwtriage_mcp.server import server

    case = game_case["case"]
    path = "dumps/game-fw.bin"
    async with Client(server) as c:
        nfc = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir=path, patterns="game:nfc-tag")
        two = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir=path, patterns=["game:save-format", "game:save-integrity"], max_results=200)
        cus = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir=path, patterns=["game:game-konami-*", "lit:PWEH-GAME-MARK"])
        low = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir=path, patterns="game", min_severity="low", max_results=500)
        mix = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir=path, patterns=["game", "xm-*"])
        mix2 = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir=path, patterns=["game:debug-menu", "cctv"])
        typo = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir=path, patterns="game:no-such-category")
        none = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir=path, patterns="game", min_severity="medium")
    assert nfc["ok"] and nfc["patterns"]["pack"] == "game" and nfc["patterns"]["selected"] == 5
    assert nfc["hits"] and {h["category"] for h in nfc["hits"]} == {"nfc-tag"}
    assert two["ok"] and {h["category"] for h in two["hits"]} == {"save-format", "save-integrity"}
    assert cus["ok"] and {h["pattern_id"] for h in cus["hits"]} == {"game-konami-sequence", custom_id("lit", "PWEH-GAME-MARK")}
    assert _full(case, cus)["params"]["pack"] == "game"
    assert low["ok"] and low["hits"] and {h["severity"] for h in low["hits"]} == {"low"}
    for r in (mix, mix2):
        assert "_error" in r and "validation_failed" in r["_error"] and "섞을 수 없습니다" in r["_error"], r
    assert "_error" in typo and "일치하는 game 팩 휴리스틱이 없습니다" in typo["_error"] and "internal_error" not in typo["_error"]
    assert "_error" in none and "선택된 패턴이 없습니다" in none["_error"] and "fw_hunt_patterns(pack='game')" in none["_error"]


async def test_cctv_default_unchanged_on_the_same_blob(game_case):
    from fwtriage_mcp.server import server

    case = game_case["case"]
    c_ps = load_patterns()
    async with Client(server) as c:
        default = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir="dumps/game-fw.bin")
        explicit = await call(c, "fw_strings_hunt", case_id=case.id, path_or_dir="dumps/game-fw.bin", patterns="cctv")
    for r in (default, explicit):
        assert r["ok"], r
        assert r["patterns"]["pack"] == "cctv" and Path(r["patterns"]["source"]).name == "cctv-hunt-patterns.yaml"
        assert r["patterns"]["selected"] == len(c_ps.string_heuristics)
        ids = {h["pattern_id"] for h in r["hits"]}
        assert "xm-opentelnet-cmd" in ids and not any(i.startswith("game-") for i in ids)
        full = _full(case, r)
        assert full["params"]["pack"] == "cctv" and full["summary"]["vendor_family_guess"] == "xiongmai-like"
        assert not any(ch["id"].startswith("game-") for ch in full["checks"])


async def test_hunt_patterns_tool_lists_each_pack(workspace):
    from fwtriage_mcp.server import server

    g = _game()
    async with Client(server) as c:
        cctv = await call(c, "fw_hunt_patterns")
        game = await call(c, "fw_hunt_patterns", pack="game")
        ent = await call(c, "fw_hunt_patterns", pack="game", category="entitlement")
        esp = await call(c, "fw_hunt_patterns", pack="game", vendor="esp-idf")
        bad = await call(c, "fw_hunt_patterns", pack="nope")
    assert cctv["ok"] and cctv["pack"] == "cctv" and cctv["packs"] == ["cctv", "game"] and cctv["errors"] == []
    assert Path(cctv["source"]).name == "cctv-hunt-patterns.yaml" and cctv["function_heuristics"] and cctv["web_server_binaries"]
    assert "xm-opentelnet-cmd" in {h["id"] for h in cctv["string_heuristics"]}
    assert game["ok"] and game["pack"] == "game" and game["errors"] == [] and Path(game["source"]).name == "game-hunt-patterns.yaml"
    assert [h["id"] for h in game["string_heuristics"]] == [h.id for h in g.string_heuristics]
    assert game["credential_patterns"] == [] and game["function_heuristics"] == [] and game["web_server_binaries"] == {}
    assert game["known_hashes"] == 0 and game["candidate_passwords"] == 0
    assert {h["id"] for h in ent["string_heuristics"]} == {"game-dlc-purchase", "game-license-token"}
    assert esp["string_heuristics"] and {h["vendor"] for h in esp["string_heuristics"]} == {"esp-idf"}
    assert "_error" in bad and "validation_failed" in bad["_error"] and "알 수 없는 패턴 팩" in bad["_error"] and "internal_error" not in bad["_error"]


# ---------------------------------------------------------------------------
# save-analysis 요약 스키마 (game-save-unlock-analysis 용, 아직 Skill 에 등록하지 않음)
# ---------------------------------------------------------------------------

SAVE_EXAMPLE = {
    "device": {"kind": "esp32-toy", "chip": "ESP32-S3", "model": "합성 장난감", "firmware_sha256": "0" * 64},
    "firmware": {"path": "dumps/esp-flash.bin", "partitions_path": "analysis/strings-hunt-001.json", "elf_path": None},
    "saves": [
        {
            "location": {"partition": "nvs", "nvs_namespace": "game", "nvs_key": "hiscore", "offset": "0x9000", "length": 4},
            "value_label": "high score",
            "encoding": "nvs-u32",
            "checksum": None,
            "evidence": ["analysis/strings-hunt-001.json", "dumps/esp-flash.bin@0x1a2b0"],
            "confidence": "likely",
        },
        {
            "location": {"file": "/spiffs/save.bin"},
            "value_label": "stage progress",
            "encoding": "u16le",
            "checksum": {"algorithm": "crc16-ccitt", "range": {"offset": 0, "length": 60}, "location": {"offset": 60, "length": 2}, "strength": "non-cryptographic"},
            "evidence": ["analysis/rea-evidence-001.json#ev_0123abcd"],
            "confidence": "possible",
        },
    ],
    "unlock_conditions": [
        {"kind": "counter", "unlock_source": "in-device", "description": "클리어 10회 이상이면 보너스 스테이지", "evidence": ["/app@0x400d1234"], "confidence": "likely", "finding_id": "F-001"},
        {"kind": "owned-tag", "unlock_source": "owned-tag", "description": "인벤토리의 내 NTAG215 태그 UID 비교 뒤 캐릭터 해금", "confidence": "possible"},
        {"kind": "sold-token", "unlock_source": "sold-token", "description": "판매용 피규어 태그로 여는 의상 — 보고만", "confidence": "possible"},
        {"kind": "date", "unlock_source": "unknown", "description": "12월 25일 이벤트 (시계 출처 미확인)", "confidence": "possible"},
    ],
    "online_capable": "unknown",
    "online_evidence": ["game-wifi-ble: nvs.net80211"],
    "patches": [],
    "finding_ids": ["F-001"],
    "limitations": ["SPIFFS 내부는 파일 시스템 수준 분석 전까지 위치만"],
    "next_actions": ["점수가 바뀐 뒤 덤프를 두 번 더 떠서 비교"],
}

MINIMAL_SAVE = {
    "device": {"kind": "other"},
    "firmware": {"path": "dumps/flash.bin"},
    "saves": [],
    "unlock_conditions": [],
    "online_capable": "no",
}


def test_save_analysis_schema_accepts_valid_examples():
    assert "save-analysis" in schemas.list_schemas()
    schemas.validate("save-analysis", SAVE_EXAMPLE)
    schemas.validate("save-analysis", MINIMAL_SAVE)
    # 다른 요약 스키마와 같이 최상위 추가 필드는 허용
    schemas.validate("save-analysis", dict(MINIMAL_SAVE, extra_info={"x": 1}))


def _mutate(path: str, value):
    obj = copy.deepcopy(SAVE_EXAMPLE)
    keys = path.split(".")
    cur = obj
    for k in keys[:-1]:
        cur = cur[int(k)] if k.isdigit() else cur[k]
    last = keys[-1]
    if value is _DELETE:
        del cur[last]
    elif last.isdigit():
        cur[int(last)] = value
    else:
        cur[last] = value
    return obj


_DELETE = object()


@pytest.mark.parametrize("path,value", [
    ("online_capable", _DELETE),
    ("unlock_conditions", _DELETE),
    ("online_capable", "maybe"),
    ("device.kind", "toaster"),
    ("device.firmware_sha256", "XYZ"),
    ("firmware.path", ""),
    ("saves.0.location", {}),
    ("saves.0.encoding", _DELETE),
    ("saves.0.confidence", "high"),
    ("saves.1.checksum", {"algorithm": "crc32"}),
    ("saves.1.checksum.strength", "strong"),
    ("unlock_conditions.0.unlock_source", "purchased"),
    ("unlock_conditions.0.unlock_source", "sold-token"),  # counter 해금의 출처는 in-device|unknown
    ("unlock_conditions.1.unlock_source", "in-device"),   # owned-tag ↔ owned-tag
    ("unlock_conditions.2.unlock_source", "in-device"),   # sold-token 은 출처도 sold-token (보고만)
    ("unlock_conditions.3.kind", "online-purchase"),      # online-purchase 인데 출처 unknown
    ("unlock_conditions.0.description", "x"),
    ("patches", [{"purpose": "score"}]),                  # 패치 빌드 단계 전까지 빈 목록
])
def test_save_analysis_schema_rejects_invalid(path, value):
    with pytest.raises(ValidationFailed):
        schemas.validate("save-analysis", _mutate(path, value))
