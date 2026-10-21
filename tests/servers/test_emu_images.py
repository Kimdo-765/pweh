"""emu-mcp 입력 준비 시험 (순수 함수 — 서버·에뮬레이터 없음).

ESP: 패딩 표, 칩 판정(원장 칩 접두 정규화·부트로더 헤더 chip_id·불일치·지원 밖·매직 없음·가져온 이미지 경로), eFuse 블롭 sha256,
PSRAM 자동, 옥탈 플래시·보안 상태 경고, NVS 비밀값 수집(tests/fwtriage/esp_builders). AVR: Intel HEX 정규화(체크섬·겹침·EEPROM
유지·퓨즈 버림·범위 밖·유형 02/04/03/05·EOF), ELF 거부, 바이너리 → HEX 왕복, 오류 메시지에 레코드 글이 없음.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO / "mcp-servers" / "emu-mcp") not in sys.path:
    sys.path.insert(0, str(REPO / "mcp-servers" / "emu-mcp"))

from fwtriage.esp_builders import (  # noqa: E402
    CHIP_C3,
    CHIP_C6,
    CHIP_ESP32,
    CHIP_S2,
    CHIP_S3,
    DEFAULT_PARTITIONS,
    NvsImage,
    build_app_image,
    build_esp_flash,
    dense_nvs,
    rich_nvs,
    s3_app_image,
)
from pweh.errors import PwehError, ValidationFailed  # noqa: E402

from emu_mcp import backends as B  # noqa: E402
from emu_mcp import images as I  # noqa: E402

MiB = 1 << 20
MAC = "f4:12:fa:12:34:56"


def boot_image(chip_id: int, spi_size: int = 2) -> bytes:
    """부트로더 자리에 둘 작은 ESP 이미지 (spi_size 니블: 1=2MB, 2=4MB, 3=8MB, 4=16MB, 5=32MB)."""
    return build_app_image(chip_id=chip_id, entry=0x40080400, segments=[(0x40080400, b"\x36\x41\x00\x1d\xf0\x00\x00\x00" * 4)],
                           spi_size=spi_size)


def flash_with(chip_id: int, offset: int, size: int = MiB, spi_size: int = 2) -> bytes:
    img = bytearray(b"\xFF" * size)
    b = boot_image(chip_id, spi_size)
    img[offset:offset + len(b)] = b
    return bytes(img)


def device_rec(chip: str | None, *, offset=0, verify: str = "double-read", mac: str | None = MAC) -> dict:
    src = {"server": "esp-mcp", "tool": "esp_read_flash_start", "verify": verify, "match": True}
    if chip is not None:
        src["chip"] = chip
    if mac is not None:
        src["mac"] = mac
    return {"seq": 3, "kind": "device-read", "source": src, "extra": {"offset": offset}}


def sec_fact(fe, mac: str = MAC) -> dict:
    return {"fact_kind": "esp-security-info", "source": {"mac": mac}, "data": {"flash_encryption": fe}}


def chip_fact(features: list[str], flash_type: str | None = None, mac: str = MAC) -> dict:
    data: dict = {"features": features}
    if flash_type is not None:
        data["flash"] = {"type_efuse": flash_type}
    return {"fact_kind": "esp-chip-info", "source": {"mac": mac.upper()}, "data": data}


def code_of(exc_info) -> str:
    return exc_info.value.code


# ---------------------------------------------------------------------------
# 패딩·크기
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("dump,declared,expected", [
    (1 * MiB, None, 2 * MiB),
    (2 * MiB, None, 2 * MiB),
    (3 * MiB, None, 4 * MiB),
    (4 * MiB + 1, None, 8 * MiB),
    (4 * MiB, 8 * MiB, 8 * MiB),
    (100, 1 * MiB, 2 * MiB),
    (16 * MiB, 16 * MiB, 16 * MiB),
])
def test_flash_padding_table(dump: int, declared: int | None, expected: int) -> None:
    assert I.flash_target_size(dump, declared) == expected


@pytest.mark.parametrize("dump,declared", [(17 * MiB, None), (4 * MiB, 32 * MiB), (16 * MiB + 1, None)])
def test_flash_too_large_is_refused_not_truncated(dump: int, declared: int | None) -> None:
    with pytest.raises(PwehError) as ei:
        I.flash_target_size(dump, declared)
    assert code_of(ei) == "emu_flash_too_large"


def test_plan_pads_with_ff_and_keeps_both_hashes() -> None:
    data = flash_with(CHIP_S3, 0x0, size=3 * MiB, spi_size=1)  # 헤더 2MB 선언, 덤프 3 MiB → 4 MiB
    p = I.plan_esp(data, provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None)
    assert p.flash_size == 4 * MiB and len(p.image) == 4 * MiB
    assert p.image[:len(data)] == data and set(p.image[len(data):]) == {0xFF}
    assert p.image_sha256 == hashlib.sha256(p.image).hexdigest() != hashlib.sha256(data).hexdigest()
    assert p.dump_size == 3 * MiB and p.declared_size == 2 * MiB
    assert "partial_dump" not in p.warning_codes


def test_header_declared_size_drives_padding_and_partial_warning() -> None:
    data = flash_with(CHIP_S3, 0x0, size=4 * MiB, spi_size=3)  # 8MB 선언 + 4 MiB 덤프
    p = I.plan_esp(data, provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None)
    assert p.flash_size == 8 * MiB
    assert "partial_dump" in p.warning_codes
    big = flash_with(CHIP_S3, 0x0, size=1 * MiB, spi_size=5)  # 32MB 선언
    with pytest.raises(PwehError) as ei:
        I.plan_esp(big, provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None)
    assert code_of(ei) == "emu_flash_too_large"


# ---------------------------------------------------------------------------
# 칩 판정
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("text,chip,unsupported", [
    ("ESP32-S3", "esp32s3", None),
    ("esp32s3", "esp32s3", None),
    ("ESP32-S3R8", "esp32s3", None),
    ("ESP32-C3", "esp32c3", None),
    ("ESP32-C3FH4", "esp32c3", None),
    ("ESP32", "esp32", None),
    ("ESP32-D0WD-V3", "esp32", None),
    ("ESP32-PICO-D4", "esp32", None),
    ("ESP32-S2", None, "ESP32-S2"),
    ("ESP32-C2", None, "ESP32-C2"),
    ("ESP32-C5", None, "ESP32-C5"),
    ("ESP32-C6", None, "ESP32-C6"),
    ("ESP32-C61", None, "ESP32-C61"),
    ("ESP32-H2", None, "ESP32-H2"),
    ("ESP32-P4", None, "ESP32-P4"),
    ("ESP8266EX", None, "ESP8266"),
    ("auto", None, None),
    ("", None, None),
    (None, None, None),
])
def test_chip_prefix_normalization(text, chip, unsupported) -> None:
    assert I.normalize_chip(text) == (chip, unsupported)


@pytest.mark.parametrize("chip_id,offset,ledger,expected", [
    (CHIP_ESP32, 0x1000, "ESP32-D0WD-V3", "esp32"),
    (CHIP_S3, 0x0, "ESP32-S3", "esp32s3"),
    (CHIP_C3, 0x0, "ESP32-C3", "esp32c3"),
    (CHIP_S3, 0x0, "auto", "esp32s3"),
    (CHIP_C3, 0x0, None, "esp32c3"),
])
def test_chip_from_ledger_and_header(chip_id: int, offset: int, ledger, expected: str) -> None:
    p = I.plan_esp(flash_with(chip_id, offset), provenance_reason="device-read", record=device_rec(ledger), chip_arg=None)
    assert p.chip == expected and p.boot_offset == offset and p.chip_id == chip_id


def test_chip_argument_must_match_evidence() -> None:
    data = flash_with(CHIP_S3, 0x0)
    p = I.plan_esp(data, provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg="ESP32-S3")
    assert p.chip == "esp32s3"
    with pytest.raises(PwehError) as ei:
        I.plan_esp(data, provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg="esp32c3")
    assert code_of(ei) == "emu_machine_mismatch"
    with pytest.raises(ValidationFailed):
        I.plan_esp(data, provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg="banana")


def test_ledger_header_mismatch() -> None:
    with pytest.raises(PwehError) as ei:
        I.plan_esp(flash_with(CHIP_C3, 0x0), provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None)
    assert code_of(ei) == "emu_machine_mismatch"


def test_unsupported_chips_from_ledger_and_header() -> None:
    with pytest.raises(PwehError) as ei:
        I.plan_esp(flash_with(CHIP_S3, 0x0), provenance_reason="device-read", record=device_rec("ESP32-C6"), chip_arg=None)
    assert code_of(ei) == "emu_unsupported_chip"
    with pytest.raises(PwehError) as ei:
        I.plan_esp(flash_with(CHIP_S2, 0x1000), provenance_reason="device-read", record=device_rec(None), chip_arg=None)
    assert code_of(ei) == "emu_unsupported_chip"
    with pytest.raises(PwehError) as ei:
        I.plan_esp(flash_with(CHIP_C6, 0x0), provenance_reason="device-read", record=device_rec("auto"), chip_arg=None)
    assert code_of(ei) == "emu_unsupported_chip"


def test_not_a_full_image() -> None:
    erased = b"\xFF" * MiB
    with pytest.raises(PwehError) as ei:
        I.plan_esp(erased, provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None)
    assert code_of(ei) == "emu_not_full_image"
    # S3 부트로더가 0x1000 에 있으면(어긋난 덤프) 전체 이미지가 아니다
    with pytest.raises(PwehError) as ei:
        I.plan_esp(flash_with(CHIP_S3, 0x1000), provenance_reason="device-read", record=device_rec(None), chip_arg=None)
    assert code_of(ei) == "emu_not_full_image"
    # 원장 오프셋이 0 이 아니면 거부
    for off in (0x10000, "0x8000", None):
        with pytest.raises(PwehError) as ei:
            I.plan_esp(flash_with(CHIP_S3, 0x0), provenance_reason="device-read", record=device_rec("ESP32-S3", offset=off), chip_arg=None)
        assert code_of(ei) == "emu_not_full_image"
    assert I.plan_esp(flash_with(CHIP_S3, 0x0), provenance_reason="device-read", record=device_rec("ESP32-S3", offset="0x0"),
                      chip_arg=None).chip == "esp32s3"


def test_elf_is_refused() -> None:
    with pytest.raises(PwehError) as ei:
        I.plan_esp(b"\x7fELF" + b"\0" * 100, provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None)
    assert code_of(ei) == "emu_elf_refused"


def test_imported_image_uses_header_only_and_needs_valid_checksum() -> None:
    data = flash_with(CHIP_C3, 0x0)
    p = I.plan_esp(data, provenance_reason="imported-attested", record={"source": {"server": "case-mcp"}}, chip_arg=None)
    assert p.chip == "esp32c3"
    assert "security_state_unknown" in p.warning_codes and "single_read" not in p.warning_codes
    with pytest.raises(PwehError) as ei:
        I.plan_esp(data, provenance_reason="imported-attested", record={}, chip_arg="esp32s3")
    assert code_of(ei) == "emu_machine_mismatch"
    broken = bytearray(data)
    hdr = boot_image(CHIP_C3)
    broken[len(hdr) - 33] ^= 0xFF  # 체크섬 바이트(SHA256 앞)를 깨뜨린다
    with pytest.raises(PwehError) as ei:
        I.plan_esp(bytes(broken), provenance_reason="imported-attested", record={}, chip_arg=None)
    assert code_of(ei) == "emu_not_full_image"
    # 가져온 이미지는 오프셋 검사가 없고, PSRAM 은 기본값(기기 사실을 보지 않음)
    s3 = flash_with(CHIP_S3, 0x0)
    p3 = I.plan_esp(s3, provenance_reason="imported-attested", record={}, chip_arg=None,
                    chip_facts=[chip_fact(["Embedded PSRAM 8MB (AP_3v3)"])])
    assert p3.psram == ("quad", 32) and p3.psram_source == "default"


# ---------------------------------------------------------------------------
# eFuse · PSRAM · 경고
# ---------------------------------------------------------------------------


def test_efuse_blobs_match_esp_idf_defaults() -> None:
    assert hashlib.sha256(I.efuse_blob("esp32")).hexdigest() == "96405fb1e2f3ffa576ca85e08cf03a4be82153ac407ceb7eb9971d091b254fda"
    assert hashlib.sha256(I.efuse_blob("esp32s3")).hexdigest() == "2054600a17c72426ac024ae851e7ea26f9cf612f31140b445ff713ba15ac09c8"
    assert hashlib.sha256(I.efuse_blob("esp32c3")).hexdigest() == "2054600a17c72426ac024ae851e7ea26f9cf612f31140b445ff713ba15ac09c8"
    assert len(I.efuse_blob("esp32")) == B.CHIPS["esp32"].efuse_size == 124
    assert len(I.efuse_blob("esp32s3")) == B.CHIPS["esp32s3"].efuse_size == 1024
    for chip, sha in I.EFUSE_SHA256.items():
        p = I.plan_esp(flash_with(B.CHIPS[chip].chip_id, B.CHIPS[chip].boot_offset), provenance_reason="device-read",
                       record=device_rec(None), chip_arg=None)
        assert p.efuse_sha256 == sha


@pytest.mark.parametrize("features,expected,source", [
    (["Wi-Fi", "BLE", "Embedded PSRAM 8MB (AP_3v3)"], ("octal", 8), "device-fact"),
    (["Embedded PSRAM 16MB (AP_1v8)"], ("octal", 16), "device-fact"),
    (["Embedded PSRAM 2MB (AP_3v3)"], ("quad", 2), "device-fact"),
    (["Embedded PSRAM 4MB (AP_3v3)"], ("quad", 4), "device-fact"),
    (["Wi-Fi", "BLE"], ("quad", 32), "default"),
])
def test_psram_auto_for_s3_from_chip_facts(features, expected, source) -> None:
    p = I.plan_esp(flash_with(CHIP_S3, 0x0), provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None,
                   chip_facts=[chip_fact(features)])
    assert (p.psram, p.psram_source) == (expected, source)


def test_psram_auto_other_chips_and_other_mac() -> None:
    assert I.choose_psram("esp32", "auto", None) == (("quad", 4), "default")
    assert I.choose_psram("esp32c3", "auto", None) == (("none", None), "default")
    # 다른 기기(MAC)의 사실은 쓰지 않는다
    p = I.plan_esp(flash_with(CHIP_S3, 0x0), provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None,
                   chip_facts=[chip_fact(["Embedded PSRAM 8MB (AP_3v3)"], mac="00:11:22:33:44:55")])
    assert p.psram == ("quad", 32)


def test_psram_arguments_validated_per_chip() -> None:
    assert I.choose_psram("esp32s3", "octal", None) == (("octal", 32), "argument")
    assert I.choose_psram("esp32s3", "octal", 8) == (("octal", 8), "argument")
    assert I.choose_psram("esp32s3", "quad", 16) == (("quad", 16), "argument")
    assert I.choose_psram("esp32", "quad", 2) == (("quad", 2), "argument")
    assert I.choose_psram("esp32s3", "none", None) == (("none", None), "argument")
    assert I.choose_psram("esp32s3", "auto", 8) == (("quad", 8), "argument")
    for chip, mode, mb in (("esp32", "octal", None), ("esp32", "quad", 8), ("esp32c3", "quad", None), ("esp32c3", "auto", 4),
                           ("esp32s3", "octal", 2), ("esp32s3", "none", 4), ("esp32s3", "quad", 3), ("esp32s3", "weird", None)):
        with pytest.raises(ValidationFailed):
            I.choose_psram(chip, mode, mb)


def test_security_and_read_warnings() -> None:
    data = flash_with(CHIP_S3, 0x0)
    ok = I.plan_esp(data, provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None,
                    security_facts=[sec_fact(False)])
    assert "security_state_unknown" not in ok.warning_codes and "single_read" not in ok.warning_codes
    single = I.plan_esp(data, provenance_reason="device-read", record=device_rec("ESP32-S3", verify="none"), chip_arg=None,
                        security_facts=[sec_fact(False)])
    assert "single_read" in single.warning_codes
    unknown = I.plan_esp(data, provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None,
                         security_facts=[sec_fact(None)])
    assert "security_state_unknown" in unknown.warning_codes
    nomac = I.plan_esp(data, provenance_reason="device-read", record=device_rec("ESP32-S3", mac=None), chip_arg=None,
                       security_facts=[sec_fact(True)])
    assert "security_state_unknown" in nomac.warning_codes
    with pytest.raises(PwehError) as ei:
        I.plan_esp(data, provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None,
                   security_facts=[sec_fact(False), sec_fact(True)])
    assert code_of(ei) == "emu_flash_encrypted"
    other = I.plan_esp(data, provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None,
                       security_facts=[sec_fact(True, mac="00:00:00:00:00:01"), sec_fact(False)])
    assert other.chip == "esp32s3"


def test_octal_flash_warning() -> None:
    data = flash_with(CHIP_S3, 0x0)
    p = I.plan_esp(data, provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None,
                   chip_facts=[chip_fact(["Embedded PSRAM 8MB"], "octal (8 data lines)")])
    assert "octal_flash_unsupported" in p.warning_codes
    q = I.plan_esp(data, provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None,
                   chip_facts=[chip_fact([], "quad (4 data lines)")])
    assert "octal_flash_unsupported" not in q.warning_codes


# ---------------------------------------------------------------------------
# NVS 비밀값 수집
# ---------------------------------------------------------------------------


def test_nvs_secret_harvest_from_esp_builders_flash() -> None:
    nv, _r = rich_nvs()
    flash, _layout = build_esp_flash(chip_id=CHIP_S3, nvs=nv.build(total_pages=6), app=s3_app_image())
    p = I.plan_esp(flash, provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None, security_facts=[sec_fact(False)])
    values = set(p.known_secret_values)
    assert b"not-a-real-pass" in values  # nvs.net80211 sta.pswd
    assert b"tok-synthetic-0000" in values  # cloud/api_token
    assert b"toy-net" in values  # nvs.net80211 네임스페이스 전체가 비밀 표시
    assert not any(v.endswith(b"\0") for v in values)
    assert all(len(v) >= 4 for v in values)
    assert b"PLAYER-ONE" not in b"".join(values)  # 비밀이 아닌 값은 거두지 않는다
    assert p.nvs_encrypted is False
    assert p.partition_table["found"] and p.partition_table["count"] == len(DEFAULT_PARTITIONS)
    assert p.app and p.app.get("project_name") == "toy-arcade"


def test_nvs_harvest_includes_erased_and_values_containing_secrets() -> None:
    nv = NvsImage()
    old = nv.put_str("cloud", "api_token", "tok-old-value-1234")
    nv.erase(old)
    nv.put_str("cloud", "api_token", "tok-new-value-5678")
    nv.put_str("app", "config", "url=https://x;key=tok-new-value-5678;")
    flash, _ = build_esp_flash(chip_id=CHIP_S3, nvs=nv.build(total_pages=6))
    p = I.plan_esp(flash, provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None)
    values = set(p.known_secret_values)
    assert b"tok-old-value-1234" in values  # 지운 옛 값도
    assert b"tok-new-value-5678" in values
    assert b"url=https://x;key=tok-new-value-5678;" in values  # 다른 비밀의 원문이 든 값


def test_nvs_short_values_are_not_harvested() -> None:
    flash, _ = build_esp_flash(chip_id=CHIP_S3, nvs=dense_nvs(2, secret_keys=True))
    p = I.plan_esp(flash, provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None)
    assert p.known_secret_values == []  # pass{p}_{i} 키지만 U8 값(1바이트)


def test_nvs_keys_partition_means_encrypted_nvs() -> None:
    parts = DEFAULT_PARTITIONS + [("nvs_key", 0x01, 0x04, 0x40000 - 0x1000, 0x1000)]
    nv, _r = rich_nvs()
    flash, _ = build_esp_flash(chip_id=CHIP_S3, nvs=nv.build(total_pages=6), partitions=parts)
    p = I.plan_esp(flash, provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None)
    assert p.nvs_encrypted is True and p.known_secret_values == []
    assert p.partition_table["nvs_keys_present"] is True


def test_missing_partition_table_is_a_warning() -> None:
    p = I.plan_esp(flash_with(CHIP_S3, 0x0), provenance_reason="device-read", record=device_rec("ESP32-S3"), chip_arg=None)
    assert "partition_table_missing" in p.warning_codes and p.known_secret_values == []


# ---------------------------------------------------------------------------
# AVR
# ---------------------------------------------------------------------------


def rec(count_addr_type_data: bytes) -> str:
    return ":" + (count_addr_type_data + bytes([(-sum(count_addr_type_data)) & 0xFF])).hex().upper()


def data_rec(addr: int, payload: bytes) -> str:
    return rec(bytes([len(payload), (addr >> 8) & 0xFF, addr & 0xFF, 0]) + payload)


def ela(upper: int) -> str:
    return rec(bytes([2, 0, 0, 4, (upper >> 8) & 0xFF, upper & 0xFF]))


def esa(seg: int) -> str:
    return rec(bytes([2, 0, 0, 2, (seg >> 8) & 0xFF, seg & 0xFF]))


EOF_REC = ":00000001FF"


def hexfile(*lines: str) -> bytes:
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def test_hex_roundtrip_and_hashes() -> None:
    code = bytes(range(40))
    p = I.normalize_avr(hexfile(data_rec(0, code[:16]), data_rec(16, code[16:]), EOF_REC), "atmega328p")
    assert p.input_kind == "hex" and p.flash_used == 40 and p.flash_size == 32 * 1024 and p.eeprom_bytes == 0
    flash, eeprom, _ = I.parse_ihex(p.hex_bytes, "atmega328p")
    assert bytes(flash[a] for a in range(40)) == code and eeprom == {}
    assert I.ihex_record_checksums_ok(p.hex_bytes)
    image = code + b"\xFF" * (32 * 1024 - 40)
    assert p.flash_sha256 == hashlib.sha256(image).hexdigest()
    assert p.hex_sha256 == hashlib.sha256(p.hex_bytes).hexdigest()
    assert p.hex_bytes.endswith(b":00000001FF\n")


def test_binary_to_hex_roundtrip_keeps_trailing_ff() -> None:
    blob = bytes([0x0C, 0x94, 0x34, 0x00]) + bytes(range(256)) * 3 + b"\xFF" * 64
    p = I.normalize_avr(blob, "atmega328p")
    assert p.input_kind == "bin" and p.flash_used == len(blob)
    flash, _, _ = I.parse_ihex(p.hex_bytes, "atmega328p")
    assert bytes(flash[a] for a in range(len(blob))) == blob
    assert any("raw 바이너리" in n for n in p.notes)
    with pytest.raises(PwehError) as ei:
        I.normalize_avr(b"\x0c\x94" * (16 * 1024 + 1), "atmega328p")
    assert code_of(ei) == "emu_bad_hex"


def test_hex_over_64k_uses_extended_linear_records() -> None:
    lines = [ela(1), data_rec(0x0000, b"\xAA" * 16), ela(0), data_rec(0x0000, b"\x0C\x94\x00\x00"), EOF_REC]
    p = I.normalize_avr(hexfile(*lines), "atmega2560")
    flash, _, _ = I.parse_ihex(p.hex_bytes, "atmega2560")
    assert flash[0x10000] == 0xAA and flash[0] == 0x0C
    assert b":020000040001F9" in p.hex_bytes
    with pytest.raises(PwehError) as ei:  # 328p 플래시(32 KiB) 밖
        I.normalize_avr(hexfile(*lines), "atmega328p")
    assert code_of(ei) == "emu_bad_hex"


def test_hex_segment_address_and_start_records() -> None:
    start_rec = rec(bytes([4, 0, 0, 3, 0, 0, 0, 0]))
    lin_start = rec(bytes([4, 0, 0, 5, 0, 0, 0, 0]))
    p = I.normalize_avr(hexfile(esa(0x1000), data_rec(0x0000, b"\x01\x02"), start_rec, lin_start, EOF_REC), "atmega2560")
    flash, _, _ = I.parse_ihex(p.hex_bytes, "atmega2560")
    assert flash[0x10000] == 1 and flash[0x10001] == 2
    assert any("시작 주소" in n for n in p.notes)


def test_hex_keeps_eeprom_and_drops_fuse_lock_signature() -> None:
    lines = [data_rec(0, b"\x0C\x94\x34\x00"), ela(0x0081), data_rec(0x0000, b"cfg!"), ela(0x0082), data_rec(0, b"\xFF\xDE\xFD"),
             ela(0x0083), data_rec(0, b"\xFC"), ela(0x0084), data_rec(0, b"\x1E\x95\x0F"), EOF_REC]
    p = I.normalize_avr(hexfile(*lines), "atmega328p")
    assert p.eeprom_bytes == 4 and p.eeprom_sha256 is not None
    flash, eeprom, _ = I.parse_ihex(p.hex_bytes, "atmega328p")
    assert bytes(eeprom[i] for i in range(4)) == b"cfg!" and len(flash) == 4
    notes = " ".join(p.notes)
    assert "퓨즈" in notes and "잠금" in notes and "서명" in notes and "EEPROM" in notes
    assert b"0081" in p.hex_bytes  # EEPROM 은 0x810000 에 남는다
    over = [data_rec(0, b"\x00\x00"), ela(0x0081), data_rec(1023, b"\x01\x02"), EOF_REC]  # 328p EEPROM 1024 바이트를 넘음
    with pytest.raises(PwehError) as ei:
        I.normalize_avr(hexfile(*over), "atmega328p")
    assert code_of(ei) == "emu_bad_hex"
    assert I.normalize_avr(hexfile(*over), "atmega2560").eeprom_bytes == 2  # 2560 은 4096 바이트


@pytest.mark.parametrize("lines,needle", [
    ([":10000000" + "00" * 16 + "00", EOF_REC], "체크섬"),
    ([data_rec(0, b"\x01\x02"), data_rec(1, b"\x03"), EOF_REC], "겹치는"),
    ([data_rec(0, b"\x01")], "EOF"),
    ([data_rec(0, b"\x01"), EOF_REC, data_rec(2, b"\x01")], "EOF"),
    ([data_rec(0, b"\x01"), "garbage", EOF_REC], "':'"),
    ([data_rec(0, b"\x01"), ":0G", EOF_REC], "형식"),
    ([":05000000010203", EOF_REC], "길이"),
    ([rec(bytes([1, 0, 0, 6, 0])), EOF_REC], "유형"),
    ([ela(0x0080), data_rec(0, b"\x01"), EOF_REC], "범위 밖"),
    ([EOF_REC], "데이터"),
    ([":" + "00" * 400, EOF_REC], "600"),
])
def test_bad_hex_cites_line_numbers_not_content(lines: list[str], needle: str) -> None:
    secret = "SECRETVALUE"
    data = hexfile(*lines).replace(b"garbage", secret.encode())
    with pytest.raises(PwehError) as ei:
        I.normalize_avr(data, "atmega328p")
    assert code_of(ei) == "emu_bad_hex"
    msg = str(ei.value)
    assert needle in msg
    assert secret not in msg
    for ln in lines:
        if len(ln) > 12:
            assert ln not in msg  # 레코드 글을 메시지에 싣지 않는다


def test_non_ascii_hex_is_bad_hex_with_offset() -> None:
    data = hexfile(data_rec(0, b"\x01"), EOF_REC)
    data = data[:5] + b"\xc3\xa9" + data[5:]
    assert I.detect_input_kind(data) == "bin"  # ASCII 가 아니면 HEX 로 보지 않는다
    with pytest.raises(PwehError) as ei:
        I.parse_ihex(data, "atmega328p")
    assert code_of(ei) == "emu_bad_hex" and "오프셋" in str(ei.value)


def test_elf_refused_and_empty_input() -> None:
    with pytest.raises(PwehError) as ei:
        I.normalize_avr(b"\x7fELF\x01\x01\x01" + b"\0" * 64, "atmega328p")
    assert code_of(ei) == "emu_elf_refused"
    with pytest.raises(PwehError) as ei:
        I.normalize_avr(b"", "atmega328p")
    assert code_of(ei) == "emu_bad_hex"
    with pytest.raises(ValidationFailed):
        I.normalize_avr(hexfile(data_rec(0, b"\x01"), EOF_REC), "attiny85")


def test_input_kind_detection() -> None:
    assert I.detect_input_kind(hexfile(data_rec(0, b"\x01"), EOF_REC)) == "hex"
    assert I.detect_input_kind(b"  \n" + hexfile(data_rec(0, b"\x01"), EOF_REC)) == "hex"
    assert I.detect_input_kind(b":\xc3\x00") == "bin"  # rjmp 로 시작하는 바이너리
    assert I.detect_input_kind(b"\x7fELF") == "elf"
    assert I.looks_like_hex(b":1") is False


def test_board_table_resolution() -> None:
    assert I.resolve_avr_target("uno", None, None) == ("uno", "atmega328p", 16_000_000, 0)
    assert I.resolve_avr_target("pro-mini-3v3", None, None) == ("pro-mini-3v3", "atmega328p", 8_000_000, 0)
    assert I.resolve_avr_target("mega2560", "atmega2560", 16_000_000) == ("mega2560", "atmega2560", 16_000_000, 0)
    assert I.resolve_avr_target("leonardo", None, None) == ("leonardo", "atmega32u4", 16_000_000, 1)
    assert I.resolve_avr_target("custom", "atmega168", 8_000_000) == ("custom", "atmega168", 8_000_000, 0)
    assert I.resolve_avr_target("custom", "atmega32u4", 16_000_000)[3] == 1
    for args in ((None, None, None), ("due", None, None), ("custom", None, 16_000_000), ("custom", "atmega328p", None),
                 ("custom", "atmega328p", 100), ("uno", "atmega2560", None), ("uno", None, 8_000_000), ("uno", "attiny85", None),
                 ("custom", "atmega328p", True)):
        with pytest.raises(ValidationFailed):
            I.resolve_avr_target(*args)


def test_committed_avr_fixture_normalizes_if_present() -> None:
    fx = REPO / "tests" / "fixtures" / "emu" / "avr_uart_echo_m328p.hex"
    if not fx.is_file():
        pytest.skip("픽스처가 아직 없다")
    data = fx.read_bytes()
    assert I.ihex_record_checksums_ok(data)
    p = I.normalize_avr(data, "atmega328p")
    assert p.input_kind == "hex" and p.flash_used > 0 and p.eeprom_bytes == 0
    flash, _, _ = I.parse_ihex(data, "atmega328p")
    flash2, _, _ = I.parse_ihex(p.hex_bytes, "atmega328p")
    assert flash == flash2
