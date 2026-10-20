"""fwtriage-mcp saves 단위 테스트: 값 인코딩, 스냅샷 비교, 관측값 대조, 체크섬 후보, 치트 입력 표, 원시 편집.

모든 데이터는 시드를 고정한 합성 데이터다. 하드웨어·네트워크·케이스 디렉터리를 쓰지 않는다.
빠른 경로(누적값·사전 조회·CRC 패스)는 checksum_compute / decode_value 만 쓰는 전수 대조(oracle)로 확인한다.
"""

from __future__ import annotations

import functools
import json
import operator
import random
import struct
import sys
import threading
import time
import tracemalloc
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "mcp-servers" / "fwtriage-mcp"))

from fwtriage_mcp import saves  # noqa: E402
from fwtriage_mcp.common import Cancelled, Ctl  # noqa: E402
from fwtriage_mcp.saves import (  # noqa: E402
    CHECKSUM_ALGORITHMS,
    ENCODINGS,
    SaveFormatError,
    apply_raw_edits,
    checksum_compute,
    decode_value,
    diff_snapshots,
    encode_value,
    find_checksums,
    find_seq_tables,
    match_observations,
)

# ---------------------------------------------------------------------------
# 합성 세이브: 4 KiB 블록, u32le 점수, BCD 최고 점수, 레벨 바이트, 플레이 시간, crc16 트레일러
# ---------------------------------------------------------------------------

SAVE_SIZE = 0x1000
SCORE_OFF = 0x40  # u32le
HISCORE_OFF = 0x48  # bcd4be
LEVEL_OFF = 0x50  # u8 (앞뒤에 상수 바이트를 둬서 u16/u32/BCD 해석과 구분)
PLAYTIME_OFF = 0x60  # u16le
TRAILER_OFF = 0xFFE  # u16le, crc16-ccitt-false over [0, 0xFFE)

_RNG = random.Random(20261020)
INVENTORY = bytes(_RNG.randrange(256) for _ in range(0x80))

# (score, hiscore, level, playtime) — 점수가 바뀔 때마다 받은 스냅샷 (시간 순서)
PROGRESS = [
    (100, 5000, 1, 600),
    (2500, 5000, 2, 1800),
    (70000, 70000, 3, 4000),
    (123456, 123456, 5, 9000),
]


def build_save(score: int, hiscore: int, level: int, playtime: int, *, trailer: str | None = "crc16-ccitt-false") -> bytes:
    b = bytearray(SAVE_SIZE)
    b[0:4] = b"SAV1"
    b[0x10:0x1A] = b"PWEH-TEST\x00"
    struct.pack_into("<I", b, SCORE_OFF, score)
    b[HISCORE_OFF : HISCORE_OFF + 4] = encode_value(hiscore, "bcd4be")
    b[LEVEL_OFF - 1] = 0x7F
    b[LEVEL_OFF] = level
    b[LEVEL_OFF + 1] = 0x80
    struct.pack_into("<H", b, PLAYTIME_OFF, playtime)
    b[0x100:0x180] = INVENTORY
    if trailer:
        struct.pack_into("<H", b, TRAILER_OFF, checksum_compute(trailer, bytes(b[:TRAILER_OFF])))
    return bytes(b)


def snapshots(n: int = 4, **kw) -> list[bytes]:
    return [build_save(*p, **kw) for p in PROGRESS[:n]]


def build_sum8_save(score: int, level: int) -> bytes:
    b = bytearray(SAVE_SIZE)
    struct.pack_into("<I", b, SCORE_OFF, score)
    b[LEVEL_OFF] = level
    b[0x100:0x180] = INVENTORY
    b[SAVE_SIZE - 1] = checksum_compute("sum8", bytes(b[: SAVE_SIZE - 1]))
    return bytes(b)


def build_header_save(score: int, level: int) -> bytes:
    """헤더 체크섬: sum16(바이트 합) big-endian @0x08 이 [0x0A, 0x400) 를 덮는다. 0x600 은 체크섬 밖에서 바뀌는 다른 블록."""
    b = bytearray(0x800)
    b[0:8] = b"HDR0\x01\x00\x00\x00"
    struct.pack_into("<I", b, 0x20, score)
    b[0x30] = level
    b[0x40:0xC0] = INVENTORY
    b[0x600] = (level * 37) & 0xFF
    b[0x08:0x0A] = checksum_compute("sum16", bytes(b[0x0A:0x400])).to_bytes(2, "big")
    return bytes(b)


# ---------------------------------------------------------------------------
# 값 인코딩
# ---------------------------------------------------------------------------


def _samples(enc: str) -> list[int]:
    w, kind, _order, signed = saves._ENC[enc]
    if kind == "bcd":
        return [0, 7, 42, 10 ** (2 * w) - 1, int("12345678"[: 2 * w])]
    bits = 8 * w
    if signed:
        return [-(1 << (bits - 1)), -1, 0, 1, (1 << (bits - 1)) - 1]
    return [0, 1, 0x5A, (1 << bits) - 1]


@pytest.mark.parametrize("enc", ENCODINGS)
def test_encode_decode_roundtrip(enc):
    for v in _samples(enc):
        raw = encode_value(v, enc)
        assert len(raw) == saves.encoding_width(enc)
        assert decode_value(raw, 0, enc) == v
        assert decode_value(b"\xaa" + raw + b"\x55", 1, enc) == v
        assert decode_value(bytearray(raw), 0, enc) == v
        assert decode_value(memoryview(raw), 0, enc) == v


def test_encoding_layouts_and_limits():
    assert encode_value(1234, "bcd2be") == b"\x12\x34"
    assert encode_value(1234, "bcd2le") == b"\x34\x12"
    assert encode_value(12345678, "bcd4be") == bytes.fromhex("12345678")
    assert encode_value(12345678, "bcd4le") == bytes.fromhex("78563412")
    assert encode_value(-2, "i16be") == b"\xff\xfe"
    assert encode_value(0x01020304, "u32le") == b"\x04\x03\x02\x01"
    assert decode_value(b"\x1a\x00", 0, "bcd2be") is None  # 니블 > 9 는 BCD 아님
    assert decode_value(b"\x12", 0, "u16le") is None  # 범위 밖
    assert decode_value(b"\x12\x34", -1, "u8") is None
    assert decode_value(b"\x12\x34", 2, "u8") is None
    assert decode_value(b"\x12\x34", True, "u8") is None
    for value, enc in [(256, "u8"), (-1, "u8"), (128, "i8"), (10000, "bcd2le"), (-5, "bcd4be"), (1 << 32, "u32be"), (True, "u8"), (1.0, "u8"), ("5", "u8")]:
        with pytest.raises(SaveFormatError):
            encode_value(value, enc)
    with pytest.raises(SaveFormatError):
        encode_value(1, "u24le")
    with pytest.raises(SaveFormatError):
        decode_value(b"\x00", 0, "float32")
    for garbage in (12345, "text", {"a": 1}, [300, 1], None):
        with pytest.raises(SaveFormatError):
            decode_value(garbage, 0, "u8")
    assert decode_value([1, 2], 0, "u16le") == 0x0201  # 0..255 정수 목록은 바이트처럼 읽힘


# ---------------------------------------------------------------------------
# 체크섬 알고리즘 정의
# ---------------------------------------------------------------------------

# reveng 카탈로그의 공개 검사값 (b"123456789") — 구현이 아니라 문서에서 가져온 값
PUBLISHED_CHECKS = {
    "crc8": 0xF4,
    "crc8-maxim": 0xA1,
    "crc16-ccitt-false": 0x29B1,
    "crc16-xmodem": 0x31C3,
    "crc16-kermit": 0x2189,
    "crc16-x25": 0x906E,
    "crc16-modbus": 0x4B37,
    "crc16-arc": 0xBB3D,
    "crc32": 0xCBF43926,
    "crc32-jamcrc": 0x340BC6D9,
    "crc32-mpeg2": 0x0376E6E7,
    "crc32-bzip2": 0xFC891918,
    "adler32": 0x091E01DE,
}


@pytest.mark.parametrize("name", sorted(PUBLISHED_CHECKS))
def test_checksum_published_check_values(name):
    assert checksum_compute(name, b"123456789") == PUBLISHED_CHECKS[name]
    assert CHECKSUM_ALGORITHMS[name]["check"] == PUBLISHED_CHECKS[name]


def test_checksum_catalog_and_sum_family_definitions():
    required = {"sum8", "sum16le", "sum16be", "sum32le", "sum32be", "xor8", "negsum8", "crc8", "crc8-maxim", "crc16-ccitt-false",
                "crc16-xmodem", "crc16-modbus", "crc16-arc", "crc32", "adler32", "fletcher16"}
    assert required <= set(CHECKSUM_ALGORITHMS)
    assert all(spec["width"] in (1, 2, 4) for spec in CHECKSUM_ALGORITHMS.values())
    json.dumps(CHECKSUM_ALGORITHMS, allow_nan=False)
    data = bytes([0x01, 0x02, 0x03, 0xFF])
    assert checksum_compute("sum8", data) == 0x05  # 261 mod 256
    assert (sum(data) + checksum_compute("negsum8", data)) % 256 == 0
    assert checksum_compute("notsum8", data) == 0xFF - 0x05
    assert checksum_compute("xor8", data) == 0x01 ^ 0x02 ^ 0x03 ^ 0xFF
    assert checksum_compute("sum16", data) == 261  # 바이트 합
    assert checksum_compute("sum32", data) == 261
    assert checksum_compute("sum16le", data) == (0x0201 + 0xFF03) & 0xFFFF  # 워드 합
    assert checksum_compute("sum16be", data) == (0x0102 + 0x03FF) & 0xFFFF
    assert checksum_compute("sum32le", data) == 0xFF030201
    assert checksum_compute("sum32be", data) == 0x010203FF
    assert checksum_compute("sum16le", b"\x01\x02\x03") == 0x0201 + 0x0003  # 홀수 길이: 0 으로 채운 워드
    assert checksum_compute("fletcher16", b"abcde") == 0xC8F0  # Wikipedia Fletcher-16 예
    assert checksum_compute("fletcher16", b"abcdef") == 0x2057
    assert checksum_compute("fletcher16", b"abcdefgh") == 0x0627
    assert checksum_compute("crc32", bytearray(b"123456789")) == 0xCBF43926
    with pytest.raises(SaveFormatError):
        checksum_compute("md5", data)
    with pytest.raises(SaveFormatError):
        checksum_compute("sum8", "text")


# ---------------------------------------------------------------------------
# diff_snapshots
# ---------------------------------------------------------------------------


def test_diff_snapshots_ranges_and_trends():
    snaps = snapshots()
    d = diff_snapshots(snaps, labels=["boot", "lv2", "lv3", "lv5"])
    assert d["snapshot_count"] == 4 and d["length"] == SAVE_SIZE
    assert d["labels"] == ["boot", "lv2", "lv3", "lv5"]
    assert not d["warnings"] and not d["truncated"]
    by_off = {r["offset"]: r for r in d["ranges"]}

    score = by_off[SCORE_OFF]  # 100 → 123456: 아래 3바이트만 바뀜
    assert score["length"] == 3 and score["values_hex"][0] == "640000"
    first = score["interpretations"][0]
    assert (first["encoding"], first["offset"], first["trend"], first["aligned"]) == ("u32le", SCORE_OFF, "increasing", True)
    assert first["values"] == [p[0] for p in PROGRESS]

    hi_range = next(r for r in d["ranges"] if HISCORE_OFF <= r["offset"] < HISCORE_OFF + 4)
    hi = {(i["encoding"], i["offset"]): i for i in hi_range["interpretations"]}
    assert hi[("bcd4be", HISCORE_OFF)]["values"] == [p[1] for p in PROGRESS]
    assert hi[("bcd4be", HISCORE_OFF)]["trend"] == "increasing"

    level = by_off[LEVEL_OFF]
    assert level["length"] == 1
    lv = {(i["encoding"], i["offset"]): i for i in level["interpretations"]}
    assert lv[("u8", LEVEL_OFF)]["values"] == [1, 2, 3, 5] and lv[("u8", LEVEL_OFF)]["trend"] == "increasing"

    pt = {(i["encoding"], i["offset"]): i for i in by_off[PLAYTIME_OFF]["interpretations"]}
    assert pt[("u16le", PLAYTIME_OFF)]["trend"] == "increasing"
    assert TRAILER_OFF in by_off  # 체크섬도 바뀐다
    assert d["changed_bytes"] == sum(r["length"] for r in d["ranges"])
    json.dumps(d, allow_nan=False)


def test_diff_snapshots_edge_cases():
    a, b = build_save(*PROGRESS[0]), build_save(*PROGRESS[1])
    single = diff_snapshots([a])
    assert single["ranges"] == [] and single["warnings"]
    same = diff_snapshots([a, a])
    assert same["ranges"] == [] and same["changed_bytes"] == 0 and same["warnings"]

    mism = diff_snapshots([a, b + b"\xaa" * 7], labels=["x"])
    assert mism["length"] == SAVE_SIZE and mism["labels"] == ["x", "s1"]
    assert any("길이" in w for w in mism["warnings"]) and any("labels" in w for w in mism["warnings"])
    assert all(r["offset"] + r["length"] <= SAVE_SIZE for r in mism["ranges"])

    base, other = bytearray(64), bytearray(64)
    other[10] = other[13] = 1
    assert len(diff_snapshots([bytes(base), bytes(other)])["ranges"]) == 2
    merged = diff_snapshots([bytes(base), bytes(other)], merge_gap=2)
    assert [(r["offset"], r["length"]) for r in merged["ranges"]] == [(10, 4)]

    noisy = bytearray(64)
    noisy[0::4] = b"\x01" * 16
    cut = diff_snapshots([bytes(64), bytes(noisy)], max_ranges=5)
    assert cut["truncated"] and len(cut["ranges"]) == 5 and cut["ranges_total"] == 16

    big = diff_snapshots([bytes(512), b"\xff" * 512])["ranges"]
    assert len(big) == 1 and big[0]["length"] == 512 and big[0]["interpretations"] == []
    assert big[0]["values_hex_truncated"] and len(big[0]["values_hex"][1]) == 2 * saves._MAX_HEX_BYTES

    with pytest.raises(SaveFormatError):
        diff_snapshots(b"not a list")
    with pytest.raises(SaveFormatError):
        diff_snapshots([b"ok", "text"])


# ---------------------------------------------------------------------------
# match_observations
# ---------------------------------------------------------------------------


def test_match_observations_finds_exactly_planted():
    snaps = snapshots()
    r = match_observations(
        snaps,
        [
            {"label": "score", "values": [100, 2500, None, 123456]},
            {"label": "hiscore", "values": [5000, "5000", 70000, None]},
            {"label": "level", "values": [1, 2, 3, 5]},
        ],
    )
    got = {(m["label"], m["offset"], m["encoding"]) for m in r["matches"]}
    assert got == {("score", SCORE_OFF, "u32le"), ("hiscore", HISCORE_OFF, "bcd4be"), ("level", LEVEL_OFF, "u8")}
    score = next(m for m in r["matches"] if m["label"] == "score")
    assert score["values"] == [100, 2500, 70000, 123456]  # 모름 칸도 읽어 준다
    assert score["aligned"] and score["width"] == 4
    assert not r["truncated"] and r["tested"] > 0 and not r["warnings"]
    json.dumps(r, allow_nan=False)


def _naive_matches(snaps: list[bytes], values: list[int | None]) -> set[tuple[int, str]]:
    known = [(i, v) for i, v in enumerate(values) if v is not None]
    negative = any(v < 0 for _, v in known)
    out = set()
    for enc in ENCODINGS:
        if saves._ENC[enc][3] and not negative:
            continue  # 문서화된 규칙: 음수가 없으면 부호 있는 인코딩 생략
        for off in range(max(len(s) for s in snaps)):
            if all(decode_value(snaps[i], off, enc) == v for i, v in known):
                out.add((off, enc))
    return out


def test_match_observations_agrees_with_brute_force():
    rng = random.Random(3)
    base = bytes(rng.randrange(256) for _ in range(300))
    plans = [
        {"u16be@0x21": 300, "i16le@0x80": -5, "u8@0x90": 9},
        {"u16be@0x21": 301, "i16le@0x80": 10, "u8@0x90": 9},
        {"u16be@0x21": 1000, "i16le@0x80": -300, "u8@0x90": 12},
    ]
    snaps = []
    for k, plan in enumerate(plans):
        b = bytearray(base)
        for key, v in plan.items():
            enc, off = key.split("@")
            off = int(off, 16)
            b[off : off + saves.encoding_width(enc)] = encode_value(v, enc)
        for p in rng.sample(range(150, 300), 20):  # 다른 곳의 잡음 변화
            b[p] = (b[p] + k + 1) & 0xFF
        snaps.append(bytes(b))
    observations = [
        [300, 301, 1000],
        [-5, 10, None],
        [9, None, 12],
        [plans[0]["u16be@0x21"] & 0xFF, None, 1000 & 0xFF],
    ]
    for values in observations:
        r = match_observations(snaps, [{"label": "x", "values": values}], max_results=10_000)
        assert {(m["offset"], m["encoding"]) for m in r["matches"]} == _naive_matches(snaps, values)
    assert (0x21, "u16be") in _naive_matches(snaps, observations[0])
    assert (0x80, "i16le") in _naive_matches(snaps, observations[1])


def test_match_observations_needs_distinct_values_and_handles_garbage():
    snaps = snapshots(3)
    r = match_observations(
        snaps,
        [
            {"label": "const", "values": [7, 7, 7]},
            {"label": "one", "values": [None, 3, None]},
            {"label": "junk", "values": ["abc", 2.5, True]},
            "nope",
            {"label": "nolist"},
            {"label": "short", "values": [100]},
        ],
    )
    assert r["matches"] == [] and not r["truncated"]
    assert len(r["warnings"]) >= 7
    with pytest.raises(SaveFormatError):
        match_observations(snaps, {"label": "x", "values": [1, 2]})


def test_match_observations_truncation_is_fair_between_labels():
    a = bytes(200)
    b = bytearray(200)
    b[::2] = b"\x01" * 100
    r = match_observations([a, bytes(b)], [{"label": "f1", "values": [0, 1]}, {"label": "f2", "values": [0, 1]}], max_results=10)
    assert r["truncated"] and len(r["matches"]) == 10
    assert {m["label"] for m in r["matches"]} == {"f1", "f2"}


# ---------------------------------------------------------------------------
# find_checksums
# ---------------------------------------------------------------------------


def test_find_checksums_planted_crc16_trailer_strong_with_all_algorithms():
    r = find_checksums(snapshots())
    top = r["candidates"][0]
    assert (top["algorithm"], top["endian"], top["location"], top["range"]) == ("crc16-ccitt-false", "le", TRAILER_OFF, [0, TRAILER_OFF])
    assert top["strength"] == "strong" and top["distinct_values"] == 4 and top["matches"] == 4
    assert top["shape"] == "before" and top["expected_false_positives"] < 1e-6
    assert [c for c in r["candidates"] if c["strength"] == "strong"] == [top]
    assert set(r["algorithms"]) == set(CHECKSUM_ALGORITHMS)
    assert not r["truncated"] and not r["budget_exhausted"] and r["tested"] > 0 and r["bytes_hashed"] > 0
    json.dumps(r, allow_nan=False)


def test_find_checksums_header_sum16_after_location():
    snaps = [build_header_save(s, lv) for s, lv in [(10, 1), (400, 2), (9000, 3)]]
    algs = ["sum16", "sum16le", "fletcher16", "crc16-arc", "sum8"]
    r = find_checksums(snaps, region=(0, 0x400), algorithms=algs)
    top = r["candidates"][0]
    assert (top["algorithm"], top["endian"], top["location"], top["range"], top["shape"]) == ("sum16", "be", 0x08, [0x0A, 0x400], "after")
    assert top["strength"] == "strong"
    assert r["region"] == [0, 0x400]
    # 영역을 주지 않으면 0 패딩 때문에 끝을 정할 수 없다: 변형 수로 알리고 가장 큰 2의 거듭제곱 경계(0x400)를 대표로
    whole = find_checksums(snaps, algorithms=algs)
    top2 = next(c for c in whole["candidates"] if c["algorithm"] == "sum16" and c["location"] == 0x08)
    assert top2["range"] == [0x0A, 0x400] and top2["range_variants"] > 1 and top2["strength"] == "strong"
    # sum16 의 하위 바이트 = sum8 인 좁은 후보는 빠진다
    assert not any(c["algorithm"] == "sum8" and c["location"] == 0x09 and c["range"] == [0x0A, 0x400] for c in r["candidates"])


def test_find_checksums_too_few_snapshots_are_absent_or_weak():
    one = find_checksums(snapshots(1))
    assert one["candidates"] == [] and one["notes"]
    algs = ["sum8", "xor8", "crc8"]
    two = find_checksums([build_sum8_save(100, 1), build_sum8_save(2500, 2)], algorithms=algs)
    planted = [c for c in two["candidates"] if c["algorithm"] == "sum8" and c["location"] == SAVE_SIZE - 1]
    assert planted and planted[0]["range"] == [0, SAVE_SIZE - 1]
    assert all(c["strength"] == "weak" for c in two["candidates"])
    four_snaps = [build_sum8_save(s, lv) for s, lv in [(100, 1), (2500, 2), (70000, 3), (123456, 7)]]
    four = find_checksums(four_snaps, algorithms=algs)
    top = four["candidates"][0]
    assert (top["algorithm"], top["endian"], top["location"], top["range"], top["strength"]) == ("sum8", None, SAVE_SIZE - 1, [0, SAVE_SIZE - 1], "strong")
    # 폭 1 후보(endian=None)도 apply_raw_edits 에 그대로 넘어간다
    new, changes = apply_raw_edits(four_snaps[-1], [{"offset": LEVEL_OFF, "encoding": "u8", "value": 99}], checksum=top)
    assert new == build_sum8_save(123456, 99)
    assert changes[-1]["checksum"]["endian"] is None


def test_find_checksums_identical_and_mismatched_lengths():
    a = build_save(*PROGRESS[0])
    same = find_checksums([a, a, a])
    assert same["candidates"] == [] and same["changed_bytes"] == 0 and any("같습니다" in n for n in same["notes"])
    s = snapshots(3)
    r = find_checksums([s[0], s[1] + b"\x00" * 5, s[2]], algorithms=["crc16-ccitt-false", "sum16"])
    assert r["length"] == SAVE_SIZE and any("길이" in n for n in r["notes"])
    top = r["candidates"][0]
    assert (top["algorithm"], top["location"], top["strength"]) == ("crc16-ccitt-false", TRAILER_OFF, "strong")


def test_find_checksums_random_noise_has_no_strong_candidates():
    rng = random.Random(99)
    noise = [bytes(rng.randrange(256) for _ in range(512)) for _ in range(3)]
    r = find_checksums(noise)
    assert not any(c["strength"] == "strong" for c in r["candidates"])
    assert r["tested"] > 100_000 and r["changed_bytes"] > 400


def test_find_checksums_budget_truncation_keeps_region_bound_passes():
    r = find_checksums(snapshots(3), algorithms=["crc16-ccitt-false", "crc16-modbus", "crc32"], max_bytes_hashed=20_000)
    assert r["truncated"] and r["budget_exhausted"] and r["crc_passes"]["skipped"] > 0
    assert any("예산" in n for n in r["notes"])
    top = r["candidates"][0]
    assert (top["algorithm"], top["location"], top["range"], top["strength"]) == ("crc16-ccitt-false", TRAILER_OFF, [0, TRAILER_OFF], "strong")
    assert r["bytes_hashed"] < 40_000


def test_find_checksums_argument_errors():
    s = snapshots(2)
    for kw in ({"algorithms": ["nope"]}, {"algorithms": []}, {"region": (5, 3)}, {"region": "0:10"}, {"region": (-1, 10)}):
        with pytest.raises(SaveFormatError):
            find_checksums(s, **kw)
    clipped = find_checksums(s, region=(0, SAVE_SIZE * 2), algorithms=["crc16-ccitt-false"])
    assert clipped["region"] == [0, SAVE_SIZE] and any("줄였습니다" in n for n in clipped["notes"])


ORACLE_ALGS = list(CHECKSUM_ALGORITHMS)
CRC_ALGS = [a for a, spec in CHECKSUM_ALGORITHMS.items() if spec["kind"] == "crc"]


def _oracle(snaps: list[bytes], names: list[str], r0: int = 0, r1: int | None = None) -> set[tuple]:
    """문서화된 탐색 공간을 checksum_compute 로 전부 계산한다 (끝점 = 영역 경계·4의 배수, 범위 ≥ 2×폭, 워드 합은 워드 정렬)."""
    size = min(len(s) for s in snaps)
    r1 = size if r1 is None else r1
    diff = [p for p in range(r0, r1) if len({s[p] for s in snaps}) > 1]
    eps = sorted({r0, r1} | {x for x in range(r0 + 1, r1) if x % 4 == 0})
    out = set()
    for name in names:
        spec = CHECKSUM_ALGORITHMS[name]
        w = spec["width"]
        ws = spec.get("word_size")
        locs = sorted({loc for p in diff for loc in range(p - w + 1, p + 1) if r0 <= loc and loc + w <= r1})
        for loc in locs:
            if ws and loc % ws:
                continue
            for endian in [None] if w == 1 else ["le", "be"]:
                stored = [s[loc] if w == 1 else int.from_bytes(s[loc : loc + w], "little" if endian == "le" else "big") for s in snaps]
                ranges = [(s0, loc) for s0 in eps if s0 <= loc - 2 * w] + [(loc + w, e) for e in eps if e >= loc + 3 * w]
                for s0, e in ranges:
                    if ws and (s0 % ws or e % ws):
                        continue
                    if all(checksum_compute(name, snap[s0:e]) == stored[k] for k, snap in enumerate(snaps)):
                        out.add((name, endian, loc, s0, e))
    return out


def _library_raw(snaps: list[bytes], names: list[str], r0: int = 0, r1: int | None = None) -> set[tuple]:
    r1 = min(len(s) for s in snaps) if r1 is None else r1
    srch = saves._Search(snaps, r0, r1, saves._diff_mask(snaps, r0, r1), names, 1 << 40, None, [], 10**9)
    srch.run_crcs(max_tier=0)  # find_checksums 와 같은 순서
    srch.run_sums()
    srch.run_crcs()
    assert not srch.budget_exhausted and not srch.timed_out and not srch.stage2_capped and not srch.raw_capped
    assert srch.passes_skipped == 0 and srch.verify_dropped == 0
    return {(alg, endian, loc, s, e) for (alg, endian, loc), (_cnt, rngs) in srch.raw.items() for (s, e) in rngs}


# 오라클용 합성 이미지 (0xA0 바이트): 빠른 경로마다 맞는 체크섬을 하나씩 심는다 — (알고리즘, 엔디언, 위치, s, e)
ORACLE_PLANTS = [
    ("sum8", None, 0x08, 0x09, 0x20),  # 폭 1, 위치 뒤
    ("sum16le", "be", 0x20, 0x04, 0x20),  # 워드 합, 위치 앞, 저장은 반대 엔디언
    ("adler32", "be", 0x40, 0x44, 0x58),  # 2단계(Adler), 위치 뒤
    ("fletcher16", "le", 0x58, 0x30, 0x58),  # 2단계(Fletcher), 위치 앞
    ("crc16-xmodem", "be", 0x70, 0x60, 0x70),  # 그룹 첫 알고리즘이 아님 → 초기값 보정(0 바이트 표)
    ("crc16-x25", "le", 0x7C, 0x74, 0x7C),  # 초기값 보정 + xorout
    ("crc16-arc", "be", 0x80, 0x82, 0x90),  # 초기값 보정, 위치 뒤
    ("crc32-bzip2", "le", 0x90, 0x60, 0x90),  # 비반사 32비트 + xorout 변형
    ("notsum8", None, 0x9B, 0x94, 0x9B),  # 비정렬 위치
    ("crc32-jamcrc", "le", 0x00, 0x04, 0xA0),  # 헤더 CRC: 범위가 영역 끝까지 (마지막에 계산)
]
# 미끼: 마지막 스냅샷에서만 갱신되지 않은 CRC (스냅샷이 3개 이상이면 후보가 아니어야 함 — 나머지 스냅샷 확인을 건너뛰면 잡힌다)
ORACLE_DECOY = ("crc16-modbus", "le", 0x2C, 0x24, 0x2C)


def _oracle_snapshots(seed: int, n: int = 3, size: int = 0xA0) -> list[bytes]:
    rng = random.Random(seed)
    base = bytes(rng.randrange(256) for _ in range(size))
    out = []
    for k in range(n):
        b = bytearray(base)
        struct.pack_into("<I", b, 0x10, 1000 + 7919 * k)  # 카운터
        b[0x31] = (3 * k + 1) & 0xFF  # 비정렬 레벨 바이트
        for pos, mul in ((0x26, 41), (0x50, 29), (0x64, 53), (0x78, 71), (0x88, 97), (0x96, 13)):
            b[pos] = (base[pos] + mul * (k + 1)) & 0xFF  # 각 체크섬 범위 안의 변화
        for alg, endian, loc, s0, e in ORACLE_PLANTS:  # 의존 순서대로 (뒤 항목이 앞 항목을 덮음)
            if alg == "crc32-jamcrc":  # 헤더 CRC 는 미끼까지 덮으므로 미끼를 먼저 쓴다
                dalg, _dend, dloc, ds, de = ORACLE_DECOY
                v = checksum_compute(dalg, bytes(b[ds:de]))
                if n >= 3 and k == n - 1:
                    v ^= 0x5A5A  # 마지막 스냅샷만 틀린 값
                b[dloc : dloc + 2] = v.to_bytes(2, "little")
            w = CHECKSUM_ALGORITHMS[alg]["width"]
            b[loc : loc + w] = checksum_compute(alg, bytes(b[s0:e])).to_bytes(w, "big" if endian == "be" else "little")
        out.append(bytes(b))
    return out


@pytest.mark.parametrize("seed", [1, 2])
def test_find_checksums_fast_paths_match_brute_force_oracle(seed):
    snaps = _oracle_snapshots(seed)
    expected = _oracle(snaps, ORACLE_ALGS)
    got = _library_raw(snaps, ORACLE_ALGS)
    assert got == expected
    assert set(ORACLE_PLANTS) <= got
    assert ORACLE_DECOY not in got  # 마지막 스냅샷에서 틀린 미끼는 후보가 아님


def test_find_checksums_oracle_with_two_snapshots_and_unaligned_region():
    snaps = _oracle_snapshots(5, n=2)
    expected = _oracle(snaps, ORACLE_ALGS)
    assert set(ORACLE_PLANTS) | {ORACLE_DECOY} <= expected and _library_raw(snaps, ORACLE_ALGS) == expected
    snaps = _oracle_snapshots(7)
    expected = _oracle(snaps, ORACLE_ALGS, 3, 158)  # 영역 시작·끝 모두 비정렬
    assert len(expected) >= 5 and _library_raw(snaps, ORACLE_ALGS, 3, 158) == expected


def test_find_checksums_unshared_crc_registers_match_oracle(monkeypatch):
    assert len(saves._build_engines(CRC_ALGS)) == 7  # 초기값만 다른 CRC 는 레지스터를 함께 쓴다
    assert len(saves._build_engines(CRC_ALGS, share_init=False)) == 10
    monkeypatch.setattr(saves, "_SHARE_INIT_MAX", 0)  # 큰 영역처럼: 초기값별 레지스터 (0 바이트 표 없음)
    snaps = _oracle_snapshots(4)
    expected = _oracle(snaps, CRC_ALGS)
    assert {p for p in ORACLE_PLANTS if p[0] in CRC_ALGS} <= expected and _library_raw(snaps, CRC_ALGS) == expected


@pytest.mark.parametrize("step", [4, 16, 64])
def test_prefix_grid_matches_naive_sums(step):
    rng = random.Random(step)
    snap = bytes(rng.randrange(256) for _ in range(1000))
    r0, r1 = 5, 997
    ss = saves._SnapSums(snap, r0, r1, step)
    for x in sorted({r0, r0 + 1, 64, 255, 256, 600, r1 - 1, r1, *rng.sample(range(r0, r1 + 1), 40)}):
        assert ss.bsum(x) == sum(snap[r0:x])
        assert ss.qsum(x) == sum((y - r0) * snap[y] for y in range(r0, x))
        assert ss.xsum(x) == functools.reduce(operator.xor, snap[r0:x], 0)
        for ws in (2, 4):
            if x % ws == 0:
                a = -(-r0 // ws) * ws
                for order in ("little", "big"):
                    assert ss.wsum(ws, order, x) == sum(int.from_bytes(snap[i : i + ws], order) for i in range(a, x, ws))


def test_checksum_candidate_roundtrips_into_apply_raw_edits():
    snaps = snapshots()
    cand = find_checksums(snaps, algorithms=["crc16-ccitt-false", "sum16"])["candidates"][0]
    new, changes = apply_raw_edits(snaps[-1], [{"offset": SCORE_OFF, "encoding": "u32le", "value": 999_999}], checksum=cand)
    assert new == build_save(999_999, 123456, 5, 9000)  # 다시 만든 세이브와 체크섬까지 같다
    s, e = cand["range"]
    assert int.from_bytes(new[TRAILER_OFF : TRAILER_OFF + 2], "little") == checksum_compute("crc16-ccitt-false", new[s:e])
    first = changes[0]
    assert first["offset"] == SCORE_OFF and first["encoding"] == "u32le"
    assert (first["before_value"], first["after_value"], first["before_hex"], first["after_hex"]) == (123456, 999_999, "40e20100", "3f420f00")
    assert first["in_checksum_range"] is True
    cs = changes[-1]["checksum"]
    assert cs["after"] == checksum_compute("crc16-ccitt-false", new[s:e]) and cs["before"] == int.from_bytes(snaps[-1][TRAILER_OFF:], "little")
    json.dumps(changes, allow_nan=False)


# ---------------------------------------------------------------------------
# apply_raw_edits
# ---------------------------------------------------------------------------


def test_apply_raw_edits_without_checksum_and_input_untouched():
    src = bytearray(build_save(*PROGRESS[0], trailer=None))
    keep = bytes(src)
    new, changes = apply_raw_edits(src, [{"offset": LEVEL_OFF, "encoding": "u8", "value": 9}, {"offset": HISCORE_OFF, "encoding": "bcd4be", "value": 99_999_999}])
    assert bytes(src) == keep and isinstance(new, bytes)
    assert new[LEVEL_OFF] == 9 and new[HISCORE_OFF : HISCORE_OFF + 4] == b"\x99\x99\x99\x99"
    assert [c["offset"] for c in changes] == [LEVEL_OFF, HISCORE_OFF] and "in_checksum_range" not in changes[0]


def test_apply_raw_edits_refusals_change_nothing():
    good = build_save(*PROGRESS[1])
    buf = bytearray(good)
    cs = {"algorithm": "crc16-ccitt-false", "endian": "le", "location": TRAILER_OFF, "range": [0, TRAILER_OFF]}
    ok_edit = [{"offset": SCORE_OFF, "encoding": "u8", "value": 1}]
    cases = [
        ([], None, "비어"),
        ([{"offset": SAVE_SIZE - 2, "encoding": "u32le", "value": 1}], None, "끝"),
        ([{"offset": -1, "encoding": "u8", "value": 1}], None, "offset"),
        ([{"offset": True, "encoding": "u8", "value": 1}], None, "offset"),
        ([{"offset": SCORE_OFF, "encoding": "u8", "value": 256}], None, "표현"),
        ([{"offset": SCORE_OFF, "encoding": "u8", "value": True}], None, "정수"),
        ([{"offset": SCORE_OFF, "encoding": "u24", "value": 1}], None, "인코딩"),
        (["edit"], None, "사전"),
        ([{"offset": SCORE_OFF, "encoding": "u32le", "value": 1}, {"offset": SCORE_OFF + 2, "encoding": "u16le", "value": 1}], None, "겹칩니다"),
        ([{"offset": TRAILER_OFF, "encoding": "u16le", "value": 1}], cs, "체크섬 필드"),
        ([{"offset": TRAILER_OFF - 1, "encoding": "u16le", "value": 1}], cs, "체크섬 필드"),
        (ok_edit, {**cs, "algorithm": "crc16-xmodem"}, "재현되지 않음"),
        (ok_edit, {**cs, "endian": "be"}, "재현되지 않음"),
        (ok_edit, {**cs, "range": [0, TRAILER_OFF + 2]}, "겹칩니다"),
        (ok_edit, {**cs, "endian": None}, "endian"),
        (ok_edit, {**cs, "algorithm": "sha1"}, "알 수 없는"),
        (ok_edit, {**cs, "location": SAVE_SIZE}, "location"),
        (ok_edit, {**cs, "range": [10, 5]}, "range"),
        (ok_edit, {**cs, "width": 4}, "width"),
        (ok_edit, "crc", "사전"),
    ]
    for edits, chk, msg in cases:
        with pytest.raises(SaveFormatError, match=msg):
            apply_raw_edits(buf, edits, checksum=chk)
        assert bytes(buf) == good


# ---------------------------------------------------------------------------
# find_seq_tables
# ---------------------------------------------------------------------------

BASE_ADDR = 0x3F400000
KONAMI_U8 = [0x08, 0x08, 0x04, 0x04, 0x02, 0x01, 0x02, 0x01, 0x40, 0x80]  # NES 패드 비트
KONAMI_U16 = [0x0800, 0x0800, 0x0400, 0x0400, 0x0200, 0x0100, 0x0200, 0x0100, 0x8000, 0x0080]  # SNES 패드 비트
KONAMI_U32 = [0, 0, 1, 1, 2, 3, 2, 3, 5, 4]  # enum 버튼 번호 (ESP32 류 int 배열)
TABLE_SPANS = {"padding": (0x200, 0x300), "ids0to7": (0x400, 0x408), "bitmasks": (0x480, 0x488), "u32ids": (0x500, 0x520)}


def build_rodata() -> tuple[bytes, dict[str, int]]:
    rng = random.Random(5)
    buf = bytearray(rng.randrange(256) for _ in range(8192))
    buf[0x100:0x120] = b"Press START to continue\x00".ljust(0x20, b"\x00")
    buf[0x200:0x300] = bytes(256)
    buf[0x400:0x409] = bytes(range(8)) + b"\xff"  # 0,1,2,…,7 조회 테이블
    buf[0x480:0x489] = bytes([1, 2, 4, 8, 16, 32, 64, 128, 0])  # 비트 마스크 표
    buf[0x500:0x520] = b"".join(struct.pack("<I", i) for i in range(8))
    off = {"k8": 0x1233, "k16": 0x1800, "k32": 0x1A00}
    k8 = bytes(KONAMI_U8) + b"\x00"
    buf[off["k8"] : off["k8"] + len(k8)] = k8
    k16 = b"".join(struct.pack("<H", v) for v in KONAMI_U16 + [0])
    buf[off["k16"] : off["k16"] + len(k16)] = k16
    k32 = b"".join(struct.pack("<I", v) for v in KONAMI_U32 + [0xFFFFFFFF])
    buf[off["k32"] : off["k32"] + len(k32)] = k32
    return bytes(buf), off


def _overlaps(c: dict, span: tuple[int, int]) -> bool:
    s = c["offset"]
    e = s + c["length"] * c["element_size"]
    return s < span[1] and span[0] < e


def test_find_seq_tables_finds_planted_konami_in_noisy_rodata():
    data, off = build_rodata()
    r = find_seq_tables(data, base_addr=BASE_ADDR)
    top = r["candidates"][:3]
    assert {(c["offset"], c["element_size"]) for c in top} == {(off["k8"], 1), (off["k16"], 2), (off["k32"], 4)}
    for c in top:
        assert c["konami_like"] and c["shape"] == "AABBCDCDEF" and c["length"] == 10
        assert c["address"] == BASE_ADDR + c["offset"] and c["reasons"]
    by_size = {c["element_size"]: c for c in top}
    assert by_size[1]["values"] == KONAMI_U8 and by_size[1]["alphabet_kind"] == "bitmask" and by_size[1]["terminator"] == "0"
    assert by_size[2]["values"] == KONAMI_U16 and by_size[2]["alphabet_kind"] == "bitmask"
    assert by_size[4]["values"] == KONAMI_U32 and by_size[4]["alphabet_kind"] == "button-id" and by_size[4]["terminator"] == "all-ones"
    floor = min(c["score"] for c in top)
    for c in r["candidates"][3:]:
        assert c["score"] < floor
    for name, span in TABLE_SPANS.items():
        hits = [c for c in r["candidates"] if _overlaps(c, span)]
        if name in ("padding", "ids0to7", "bitmasks"):
            assert hits == [], name  # 패딩·단조 표는 후보로 내지 않는다
        assert all(c["score"] < floor for c in hits), name
    assert r["scanned_bytes"] == len(data) and not r["truncated"]
    json.dumps(r, allow_nan=False)


def test_find_seq_tables_terminators_and_length_prefix():
    code = [1, 2, 1, 2, 3, 3, 4, 4]  # 1부터 세는 버튼 번호, 0 종결 + 0 패딩 (번호 런이 패딩까지 이어짐)
    data = b"\xee" * 16 + bytes(code) + bytes(8) + b"\xee" * 16
    c = find_seq_tables(data)["candidates"][0]
    assert (c["offset"], c["length"], c["values"], c["terminator"], c["alphabet_kind"]) == (16, 8, code, "0", "button-id")
    masks = [0x10, 0x10, 0x20, 0x20, 0x01, 0x02, 0x01, 0x02]
    data2 = b"\xee" * 8 + bytes([len(masks)]) + bytes(masks) + b"\xff" + b"\xee" * 8  # 길이 접두 8 도 비트 마스크라 런에 섞인다
    c2 = find_seq_tables(data2)["candidates"][0]
    assert (c2["offset"], c2["length"], c2["length_prefix"], c2["terminator"]) == (9, 8, True, "all-ones")
    assert find_seq_tables(bytes(4096))["candidates"] == []  # 패딩뿐
    assert find_seq_tables(bytes(range(16)) * 4)["candidates"] == []  # 0..15 반복 (알파벳 16 > 8)
    with pytest.raises(SaveFormatError):
        find_seq_tables(data, min_len=-1)
    with pytest.raises(SaveFormatError):
        find_seq_tables("text")


# ---------------------------------------------------------------------------
# 작업 제어 (취소·시간 예산)
# ---------------------------------------------------------------------------


def test_ctl_cancel_and_time_budget():
    ev = threading.Event()
    ev.set()
    snaps = snapshots(3)
    rodata = build_rodata()[0]
    with pytest.raises(Cancelled):
        find_checksums(snaps, ctl=Ctl(ev))
    with pytest.raises(Cancelled):
        find_seq_tables(rodata, ctl=Ctl(ev))
    with pytest.raises(Cancelled):
        match_observations(snaps, [{"label": "s", "values": [100, 2500, 70000]}], ctl=Ctl(ev))
    r = find_checksums(snaps, ctl=Ctl(max_seconds=1e-9))
    assert r["truncated"] and any("시간" in n for n in r["notes"])
    r = find_seq_tables(rodata, ctl=Ctl(max_seconds=1e-9))
    assert r["truncated"] and any("시간" in n for n in r["notes"])
    r = match_observations(snaps, [{"label": "s", "values": [100, 2500, 70000]}], ctl=Ctl(max_seconds=1e-9))
    assert r["truncated"] and any("시간" in w for w in r["warnings"])
    seen = []
    find_checksums(snaps, algorithms=["crc16-ccitt-false"], ctl=Ctl(progress=lambda d, t, m: seen.append(m)))
    assert seen


# ---------------------------------------------------------------------------
# 큰 입력의 한도: 시간 예산·해시 예산·메모리 (적대적 검토 I2a 재현 모양을 작게 줄인 것)
# ---------------------------------------------------------------------------


class _ExpireAfter:
    """expired() 가 n 번째 호출부터 True 인 가짜 Ctl — 긴 루프 안에서도 시간 예산을 확인하는지 결정적으로 시험한다."""

    def __init__(self, n: int) -> None:
        self.n = n
        self.calls = 0

    def check(self) -> None:
        pass

    def expired(self) -> bool:
        self.calls += 1
        return self.calls >= self.n


def _alternating(n: int, i: int) -> bytes:
    """한 바이트 걸러 스냅샷마다 다른 값 (바뀐 구간이 n/2 개)."""
    return bytes([0, (i + 1) & 0xFF]) * (n // 2)


def _naive_merged(mask: bytes, gap: int) -> list[tuple[int, int]]:
    runs: list[list[int]] = []
    for i, b in enumerate(mask):
        if b:
            if runs and i - runs[-1][1] <= gap:
                runs[-1][1] = i + 1
            else:
                runs.append([i, i + 1])
    return [(a, b) for a, b in runs]


def test_mask_range_counting_matches_naive_merge():
    rng = random.Random(8)
    cases = [b"", b"\x00", b"\x07", b"\x00" * 9, b"\x05" * 9, b"\x01\x00\x01", b"\x00\x01\x00\x00\x01\x00", b"\x00\x00\x03"]
    for _ in range(300):
        density = rng.random()
        cases.append(bytes((rng.randrange(1, 256) if rng.random() < density else 0) for _ in range(rng.randrange(1, 200))))
    for mask in cases:
        nz = mask.translate(saves._T_NONZERO)
        for gap in (0, 1, 2, 3, 7, 64, 1000):
            expected = _naive_merged(mask, gap)
            assert saves._count_ranges(nz, gap) == len(expected), (mask, gap)
            assert list(saves._iter_merged(nz, gap, 0)) == expected, (mask, gap)


def test_change_counters_match_naive_count():
    rng = random.Random(9)
    for step in (4, 16, 64):
        mask = bytes((rng.randrange(1, 256) if rng.random() < 0.3 else 0) for _ in range(1500))
        r0 = 7
        cc = saves._ChangeCount(mask, r0, step)
        runs = list(saves._iter_runs(mask, r0))
        a = bytes(len(mask) + r0)
        b = bytes(r0) + mask
        assert saves._diff_runs([a, b], r0, r0 + len(mask)) == runs == [(x + r0, y + r0) for x, y in _naive_merged(mask, 0)]
        for _ in range(300):
            s0 = rng.randrange(r0, r0 + len(mask) + 1)
            e = rng.randrange(s0, r0 + len(mask) + 1)
            naive = sum(1 for x in mask[s0 - r0 : e - r0] if x)
            assert cc.count(s0, e) == naive == saves._changed_in(runs, s0, e)


def test_diff_snapshots_counts_every_range_without_materialising_them():
    n = 2 << 20
    a, b = bytes(n), _alternating(n, 0)
    tracemalloc.start()
    try:
        d = diff_snapshots([a, b], max_ranges=5)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert d["ranges_total"] == n // 2 and d["changed_bytes"] == n // 2  # 자른 뒤가 아닌 전체 수
    assert d["truncated"] and [(r["offset"], r["length"]) for r in d["ranges"]] == [(1, 1), (3, 1), (5, 1), (7, 1), (9, 1)]
    assert peak < 8 * n  # 예전 구현은 구간 목록 때문에 입력의 수십 배
    merged = diff_snapshots([a, b], max_ranges=5, merge_gap=1)
    assert merged["ranges_total"] == 1 and [(r["offset"], r["length"]) for r in merged["ranges"]] == [(1, n - 1)]
    assert not merged["truncated"] and merged["ranges"][0]["values_hex_truncated"]
    late = diff_snapshots([a, b], ctl=Ctl(max_seconds=1e-9))
    assert late["truncated"] and late["ranges_total"] is None and late["changed_bytes"] is None
    assert any("시간" in w for w in late["warnings"])
    json.dumps(d, allow_nan=False)


@pytest.mark.parametrize("shape", ["alternating", "random"])
def test_find_checksums_honours_small_time_budget(shape):
    rng = random.Random(4)
    if shape == "alternating":
        snaps = [_alternating(64 << 10, i) for i in range(2)]
    else:
        snaps = [rng.randbytes(256 << 10) for _ in range(2)]
    t0 = time.monotonic()
    r = find_checksums(snaps, ctl=Ctl(max_seconds=0.5))
    elapsed = time.monotonic() - t0
    assert elapsed < 5.0  # 예전 구현: 2×64 KiB 에서 sum8 만으로 마감 뒤 224 s
    assert r["timed_out"] and r["truncated"] and any("시간" in x for x in r["notes"])
    assert r["budget_used"] <= 64 << 20
    json.dumps(r, allow_nan=False)


def test_find_checksums_ticks_inside_a_single_long_crc_pass():
    rng = random.Random(5)
    snaps = [rng.randbytes(1 << 20) for _ in range(2)]
    ctl = _ExpireAfter(3)  # 마스크(1회) → 첫 패스 직전(2회) → 패스 첫 조각 뒤(3회) 에서 만료
    r = find_checksums(snaps, algorithms=["crc16-modbus"], ctl=ctl)
    assert r["timed_out"] and r["truncated"]
    assert r["bytes_hashed"] <= 2 * saves._PASS_CHUNK  # 1 MiB 패스를 끝까지 돌지 않았다
    assert r["crc_passes"]["skipped"] > 0


def test_find_checksums_never_exceeds_hash_budget():
    rng = random.Random(6)
    snaps = [rng.randbytes(64 << 10) for _ in range(3)]
    for budget in (10_000, 300_000, 2_000_000):
        r = find_checksums(snaps, algorithms=["crc8", "crc16-modbus", "crc32"], max_bytes_hashed=budget)
        assert r["budget_used"] <= budget and r["bytes_hashed"] <= budget  # 확인 패스·0 바이트 표까지 미리 계산
        assert r["budget_exhausted"] and r["truncated"] and any("예산" in x for x in r["notes"])


def test_find_checksums_raw_cap_is_per_width_and_keeps_region_bound_crc(monkeypatch):
    monkeypatch.setattr(saves, "_MAX_RAW_PER_WIDTH", 5)
    n = 16 << 10
    snaps = []
    for i in range(2):
        b = bytearray(_alternating(n, i))
        struct.pack_into("<H", b, n - 2, checksum_compute("crc16-ccitt-false", bytes(b[: n - 2])))
        snaps.append(bytes(b))
    r = find_checksums(snaps, algorithms=["sum8", "sum16", "crc16-ccitt-false"], max_bytes_hashed=1 << 20)
    assert r["truncated"] and any("묶음" in x for x in r["notes"])
    assert any(c["algorithm"] == "crc16-ccitt-false" and c["location"] == n - 2 and c["range"] == [0, n - 2] for c in r["candidates"])


@pytest.mark.parametrize("kind", ["konami", "zerosplit"])
def test_find_seq_tables_bounds_long_runs(kind):
    n = 1 << 20
    pat = bytes([1, 1, 2, 2, 3, 4, 3, 4, 6, 5]) if kind == "konami" else bytes([0, 3, 1, 4, 1, 5, 9, 2, 6])
    data = (pat * (n // len(pat) + 1))[:n]
    tracemalloc.start()
    try:
        t0 = time.monotonic()
        r = find_seq_tables(data, max_results=20)
        elapsed = time.monotonic() - t0
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert len(r["candidates"]) == 20 and r["truncated"] and any("앞쪽" in x for x in r["notes"])
    assert peak < 40 * n  # 예전 구현은 런 하나의 후보를 다 들고 있어 입력의 약 220배
    assert elapsed < 10
    late = find_seq_tables(data, max_results=20, ctl=_ExpireAfter(2))  # 런 하나 안에서도 시간 예산 확인
    assert late["truncated"] and any("시간" in x for x in late["notes"])


def test_match_observations_negative_values():
    base = bytearray(b"\x5a" * 128)

    def snap(i8: int, i16: int, i32: int) -> bytes:
        b = bytearray(base)
        b[0x10] = i8 & 0xFF
        b[0x20:0x22] = encode_value(i16, "i16le")
        b[0x30:0x34] = encode_value(i32, "i32be")
        return bytes(b)

    snaps = [snap(-3, -300, -100000), snap(-1, -2, 5), snap(2, 7, -7), snap(5, -32768, 2**31 - 1)]
    r = match_observations(
        snaps,
        [
            {"label": "lv", "values": [-3, "-1", 2, None]},  # 부호 섞임, 문자열 음수, 모름 칸
            {"label": "hp", "values": [-300, -2, None, -32768]},
            {"label": "gold", "values": [-100000, 5, -7, 2**31 - 1]},
        ],
    )
    got = {(m["label"], m["offset"], m["encoding"]) for m in r["matches"]}
    assert got == {("lv", 0x10, "i8"), ("hp", 0x20, "i16le"), ("gold", 0x30, "i32be")}
    assert next(m for m in r["matches"] if m["label"] == "lv")["values"] == [-3, -1, 2, 5]
    assert not r["warnings"] and not r["truncated"]
    neg_only = match_observations(snaps, [{"label": "hp", "values": [-300, -2]}])
    assert {(m["offset"], m["encoding"]) for m in neg_only["matches"]} == {(0x20, "i16le")}
