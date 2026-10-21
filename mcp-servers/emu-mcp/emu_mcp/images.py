"""emu-mcp 입력 준비 (순수 함수 — 프로세스·파일·로그 없음): ESP 전체 플래시 덤프 계획과 AVR Intel HEX·바이너리 정규화.

ESP (설계 §5.3 + 계약):
- 칩: device-read 는 원장 ``source.chip`` 을 접두로 정규화(ESP32-S3* → esp32s3, ESP32-C3* → esp32c3, S2·C2·C5·C6·C61·H2·P4·ESP8266 →
  지원 안 함, 그 밖의 ESP32* → esp32, 'auto'·없음 → 헤더만)하고 부트 오프셋(esp32 0x1000, s3·c3 0x0)의 2단계 부트로더 헤더
  ``chip_id``(0 = ESP32, 9 = ESP32-S3, 5 = ESP32-C3)와 맞춰 본다. 출처를 증명한 가져온 이미지는 헤더만 쓰고(매직 0xE9 + 해석되는
  헤더·체크섬), 보안 상태는 경고 ``security_state_unknown``, PSRAM 은 기본값, 오프셋 검사 없음. 에이전트의 ``chip`` 은 결과와 같아야 한다.
- 크기: {2, 4, 8, 16} MiB 중 max(덤프 크기, 헤더 선언 크기) 이상인 가장 작은 값으로 0xFF 채움. 16 MiB 를 넘으면 자르지 않고 거부.
- eFuse: ESP-IDF qemu_ext.py 의 칩별 기본 블롭(장치 eFuse 는 쓰지 않는다).
- PSRAM auto, 옥탈 플래시 경고, NVS 의 알려진 비밀값 수집(``include_erased=True`` — 거른 값은 메모리에만, 낮은 엔트로피 값은
  ``pweh.safety.redact.KnownSecrets`` 가 버린다), nvs_keys 파티션 → ``nvs_encrypted``.

AVR (설계 §5.4 + 계약): ELF 거부, Intel HEX(체크섬·유형 00/01/02/04, 03/05 무시) 또는 raw 바이너리(≤ 플래시 크기)를 받아 16 바이트
레코드의 정규화 HEX 로 다시 쓴다. EEPROM(0x810000+, MCU EEPROM 크기 안)은 남기고 퓨즈·잠금·서명(0x820000·0x830000·0x840000)은
버리고 메모로 남긴다. 오류는 줄 번호·오프셋만 말한다(레코드 글·값을 메시지에 넣지 않는다).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from pweh.errors import PwehError, ValidationFailed

from . import backends as B
from . import limits

MiB = 1 << 20
FLASH_SIZES = (2 * MiB, 4 * MiB, 8 * MiB, 16 * MiB)
#: 부트로더 헤더 3번째 바이트 상위 니블 → 선언 플래시 크기 (esptool FLASH_SIZES)
HEADER_FLASH_SIZES = {0: 1 * MiB, 1: 2 * MiB, 2: 4 * MiB, 3: 8 * MiB, 4: 16 * MiB, 5: 32 * MiB, 6: 64 * MiB, 7: 128 * MiB}
ESP_IMAGE_MAGIC = 0xE9
EFUSE_SHA256 = {
    "esp32": "96405fb1e2f3ffa576ca85e08cf03a4be82153ac407ceb7eb9971d091b254fda",
    "esp32s3": "2054600a17c72426ac024ae851e7ea26f9cf612f31140b445ff713ba15ac09c8",
    "esp32c3": "2054600a17c72426ac024ae851e7ea26f9cf612f31140b445ff713ba15ac09c8",
}
#: 알려진 비밀값 후보 상한 (KnownSecrets 가 다시 거른다 — 최대 256 개·각 256 바이트)
SECRET_CANDIDATES_MAX = 1024
SECRET_VALUE_MAX = 4096
PSRAM_DEFAULT_MB = {"esp32": 4, "esp32s3": 32}
_EMBEDDED_PSRAM_RX = re.compile(r"Embedded PSRAM (\d{1,3}) ?MB", re.I)
_CHIP_PREFIX_RX = re.compile(r"^ESP32-?(S3|C3|S2|C2|C5|C61|C6|H2|P4)(?![0-9])", re.I)


def _err(code: str, message: str, hint: str | None = None, data: dict[str, Any] | None = None) -> PwehError:
    return PwehError(message, code=code, hint=hint, data=data)


# ---------------------------------------------------------------------------
# ESP: 칩 이름·헤더
# ---------------------------------------------------------------------------


def normalize_chip(text: Any) -> tuple[str | None, str | None]:
    """칩 문자열 정규화 → (지원 칩 이름 | None, 지원 안 하는 칩 이름 | None). 'auto'·빈 값은 (None, None) — 헤더만 쓴다.

    ESP32-S3* → esp32s3, ESP32-C3* → esp32c3, ESP32-S2/C2/C5/C6/C61/H2/P4 와 ESP8266 → 지원 안 함, 그 밖의 ESP32*
    (ESP32-D0WD-V3, ESP32-PICO-D4 …) → esp32. 'esp32s3' 같은 소문자·붙여 쓴 이름도 받는다."""
    if text is None:
        return None, None
    s = str(text).strip().upper().replace("_", "-")
    if not s or s == "AUTO":
        return None, None
    if s.startswith("ESP8266"):
        return None, "ESP8266"
    m = _CHIP_PREFIX_RX.match(s)
    if m:
        sub = m.group(1).upper()
        if sub == "S3":
            return "esp32s3", None
        if sub == "C3":
            return "esp32c3", None
        return None, f"ESP32-{sub}"
    if s.startswith("ESP32"):
        return "esp32", None
    return None, None


def efuse_blob(chip: str) -> bytes:
    """ESP-IDF qemu_ext.py 의 칩별 기본 eFuse 블롭 (esp32 124 B: 13=0x80, 22=0x10 / s3·c3 1024 B: 0x26=0x0c)."""
    if chip == "esp32":
        b = bytearray(124)
        b[13] = 0x80
        b[22] = 0x10
        return bytes(b)
    if chip in ("esp32s3", "esp32c3"):
        b = bytearray(1024)
        b[0x26] = 0x0C
        return bytes(b)
    raise ValueError(f"unknown chip {chip!r}")


def _espfmt():
    from pweh import espfmt  # 코어 (결정 D1)

    return espfmt


def header_at(data: bytes, offset: int) -> dict[str, Any] | None:
    """offset 의 ESP 이미지 헤더 (매직 0xE9 와 해석되는 확장 헤더가 있을 때만). 쓰레기 입력에도 끝난다."""
    if offset < 0 or len(data) < offset + 24 or data[offset] != ESP_IMAGE_MAGIC:
        return None
    try:
        p = _espfmt().parse_app_image(data, offset)
    except Exception:  # noqa: BLE001 - 펌웨어 바이트로 만든 예외 메시지를 밖으로 내지 않는다
        return None
    if p.get("chip_id") is None:
        return None
    return p


def declared_flash_size(header: dict[str, Any] | None) -> int | None:
    if not header:
        return None
    nib = header.get("spi_size")
    return HEADER_FLASH_SIZES.get(nib) if isinstance(nib, int) else None


def flash_target_size(dump_size: int, declared: int | None) -> int:
    """{2, 4, 8, 16} MiB 중 max(덤프 크기, 선언 크기) 이상인 가장 작은 값. 16 MiB 를 넘으면 emu_flash_too_large."""
    need = max(int(dump_size), int(declared or 0))
    for size in FLASH_SIZES:
        if need <= size:
            return size
    raise _err("emu_flash_too_large", f"플래시가 16 MiB 를 넘습니다 (덤프 {dump_size} 바이트, 헤더 선언 {declared or 0} 바이트).",
               hint="Espressif QEMU 는 2·4·8·16 MiB 플래시만 지원한다 — 자르지 않는다. 지원하지 않음을 보고한다.")


def detect_header_chip(data: bytes) -> dict[str, Any]:
    """부트 오프셋의 2단계 부트로더 헤더로 칩을 정한다 → {chip, chip_id, boot_offset, header}.

    esp32 오프셋(0x1000)과 s3·c3 오프셋(0x0)을 둘 다 본다. 지원 안 하는 chip_id 는 emu_unsupported_chip, 아무 데도 없으면
    emu_not_full_image."""
    found: list[tuple[str, int, int, dict[str, Any]]] = []
    unsupported: list[tuple[str, int]] = []
    for off in (0x0, 0x1000, 0x2000):
        h = header_at(data, off)
        if h is None:
            continue
        cid = int(h["chip_id"])
        chip = next((c for c, s in B.CHIPS.items() if s.chip_id == cid), None)
        if chip is not None and B.CHIPS[chip].boot_offset == off:
            found.append((chip, cid, off, h))
        elif cid in B.UNSUPPORTED_CHIP_IDS and (off == 0x1000 if cid == 2 else (off == 0x2000 if cid == 18 else off == 0x0)):
            unsupported.append((B.UNSUPPORTED_CHIP_IDS[cid], off))
    if found:
        if len(found) > 1:
            return {"ambiguous": [f[0] for f in found], "candidates": found}
        chip, cid, off, h = found[0]
        return {"chip": chip, "chip_id": cid, "boot_offset": off, "header": h}
    if unsupported:
        name, off = unsupported[0]
        raise _err("emu_unsupported_chip", f"{name} 펌웨어입니다(부트 오프셋 0x{off:x} 의 이미지 헤더) — 이 서버는 ESP32·ESP32-S3·ESP32-C3 만 실행합니다.",
                   hint="지원하지 않음을 보고한다.")
    raise _err("emu_not_full_image", "부트 오프셋(esp32 0x1000, ESP32-S3·C3 0x0)에 2단계 부트로더 이미지(매직 0xE9)가 없습니다.",
               hint="전체 플래시 덤프(오프셋 0)인지, 플래시 암호화로 암호문인지 확인한다. 앱 파티션만 뽑은 이미지는 실행하지 않는다.")


# ---------------------------------------------------------------------------
# ESP: 계획
# ---------------------------------------------------------------------------


@dataclass
class EspPlan:
    chip: str
    chip_id: int
    boot_offset: int
    dump_size: int
    declared_size: int | None
    flash_size: int
    image: bytes
    image_sha256: str
    efuse: bytes
    efuse_sha256: str
    psram: tuple[str, int | None]
    psram_source: str
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    known_secret_values: list[bytes] = field(default_factory=list, repr=False)
    nvs_encrypted: bool = False
    partition_table: dict[str, Any] = field(default_factory=dict)
    app: dict[str, Any] | None = None

    @property
    def warning_codes(self) -> list[str]:
        return [w.split(":", 1)[0] for w in self.warnings]


def _offset_value(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v.strip(), 0)
        except ValueError:
            return None
    return None


def _same_mac(facts: Iterable[dict[str, Any]], mac: str) -> list[dict[str, Any]]:
    return [f for f in facts or [] if str((f.get("source") or {}).get("mac") or "").lower() == mac]


def _psram_from_facts(chip_facts: Sequence[dict[str, Any]]) -> int | None:
    for f in reversed(list(chip_facts)):
        for feat in (f.get("data") or {}).get("features") or []:
            m = _EMBEDDED_PSRAM_RX.search(str(feat)[:200])
            if m:
                return int(m.group(1))
    return None


def _octal_flash(chip_facts: Sequence[dict[str, Any]]) -> bool:
    for f in reversed(list(chip_facts)):
        flash = (f.get("data") or {}).get("flash") or {}
        t = flash.get("type_efuse") if isinstance(flash, dict) else None
        if t is not None:
            return "octal" in str(t).lower()
    return False


def choose_psram(chip: str, psram: str, psram_mb: int | None, *, chip_facts: Sequence[dict[str, Any]] = (),
                 imported: bool = False) -> tuple[tuple[str, int | None], str]:
    """PSRAM 결정 → ((mode, mb), source: argument | device-fact | default). 잘못된 조합은 validation_failed.

    auto: esp32 quad 4 MiB, esp32s3 은 같은 MAC 의 esp-chip-info 사실의 'Embedded PSRAM <N>MB' 로 N ≥ 8 → octal N, N ∈ {2, 4} →
    quad N, 없으면 quad 32 MiB (ESP-IDF 기본), esp32c3 none. 가져온 이미지는 기본값."""
    spec = B.CHIPS[chip]
    if psram not in B.PSRAM_MODES:
        raise ValidationFailed(f"잘못된 psram: {psram!r}", hint=f"허용: {', '.join(B.PSRAM_MODES)}")
    if psram_mb is not None and (isinstance(psram_mb, bool) or not isinstance(psram_mb, int)):
        raise ValidationFailed("psram_mb 는 정수여야 합니다.")
    if psram == "none":
        if psram_mb is not None:
            raise ValidationFailed("psram='none' 이면 psram_mb 를 주지 않는다.")
        return ("none", None), "argument"
    if psram != "auto" and psram not in spec.psram_modes:
        raise ValidationFailed(f"{chip} 은 psram={psram!r} 을 쓸 수 없습니다.", hint=f"{chip} 허용: auto, {', '.join(spec.psram_modes)}")
    if psram == "auto":
        if chip == "esp32c3":
            if psram_mb is not None:
                raise ValidationFailed("esp32c3 에는 PSRAM 이 없습니다 (psram_mb 를 주지 않는다).")
            return ("none", None), "default"
        if psram_mb is not None:
            sizes = spec.quad_sizes
            if psram_mb not in sizes:
                raise ValidationFailed(f"{chip} quad PSRAM 크기는 {sizes} MiB 중 하나입니다.")
            return ("quad", psram_mb), "argument"
        if chip == "esp32s3" and not imported:
            n = _psram_from_facts(chip_facts)
            if n is not None:
                if n >= 8 and n in spec.octal_sizes:
                    return ("octal", n), "device-fact"
                if n in (2, 4):
                    return ("quad", n), "device-fact"
        return ("quad", PSRAM_DEFAULT_MB[chip]), "default"
    sizes = spec.octal_sizes if psram == "octal" else spec.quad_sizes
    mb = psram_mb if psram_mb is not None else (PSRAM_DEFAULT_MB[chip] if PSRAM_DEFAULT_MB[chip] in sizes else max(sizes))
    if mb not in sizes:
        raise ValidationFailed(f"{chip} {psram} PSRAM 크기는 {sizes} MiB 중 하나입니다 (받은 {mb}).")
    return (psram, mb), "argument"


def _as_raw(v: Any) -> bytes:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if v is None or isinstance(v, (bool, int)):
        return b""
    return str(v).encode("utf-8", "surrogatepass")


def harvest_nvs_secrets(data: bytes, table: dict[str, Any]) -> tuple[list[bytes], bool, list[str]]:
    """파티션 표의 NVS 파티션(type data, subtype nvs)마다 비밀 항목(secret 표시·secret_hint — nvs.net80211 전체 포함)과,
    값에 다른 비밀 항목의 원문이 든 항목의 값을 거둔다 (fwtriage _secret_raws/_is_secret 와 같은 규칙, 지운 옛 값 포함).

    반환: (후보 값 — 끝 NUL 제거, 4 바이트 이상, 메모리에만), nvs_encrypted(nvs_keys 파티션 있음 — 값을 읽을 수 없어 거두지 않음), 메모.
    값·키 이름은 메모에 넣지 않는다."""
    notes: list[str] = []
    if not table or not table.get("found"):
        return [], False, notes
    if table.get("nvs_keys_present"):
        return [], True, ["nvs_keys 파티션이 있다(NVS 암호화) — 알려진 비밀값 수집 없이 패턴 마스킹만 한다"]
    espfmt = _espfmt()
    out: list[bytes] = []
    seen: set[bytes] = set()
    for e in table.get("entries") or []:
        if e.get("type") != 0x01 or e.get("subtype") != 0x02:
            continue
        off, size = int(e.get("offset") or 0), int(e.get("size") or 0)
        if size <= 0 or off < 0 or off + size > len(data):
            notes.append(f"NVS 파티션 #{e.get('index')} 이 덤프 범위 밖이라 비밀값을 거두지 못했다")
            continue
        try:
            nvs = espfmt.parse_nvs(data[off:off + size], include_erased=True)
        except Exception:  # noqa: BLE001 - 예외 메시지에 키 이름이 들어갈 수 있어 버린다
            notes.append(f"NVS 파티션 #{e.get('index')} 을 해석하지 못했다(비밀값 수집 건너뜀)")
            continue
        entries = list(nvs.get("items") or []) + list(nvs.get("blobs") or [])
        raws: list[bytes] = []
        for it in entries:
            if it.get("secret") or espfmt.secret_hint(it.get("namespace"), it.get("key")):
                b = _as_raw(it.get("value"))
                if len(b) >= 4:
                    raws.append(b)
        for it in entries:
            secret = bool(it.get("secret") or espfmt.secret_hint(it.get("namespace"), it.get("key")))
            b = _as_raw(it.get("value"))
            if not secret and not (b and any(r in b for r in raws)):
                continue
            b = b.rstrip(b"\0")
            if len(b) < 4 or len(b) > SECRET_VALUE_MAX or b in seen:
                continue
            seen.add(b)
            out.append(b)
            if len(out) >= SECRET_CANDIDATES_MAX:
                notes.append("비밀값 후보가 상한에 닿아 나머지를 거두지 않았다")
                return out, False, notes
    return out, False, notes


def _partition_summary(table: dict[str, Any]) -> dict[str, Any]:
    entries = table.get("entries") or []
    return {
        "found": bool(table.get("found")),
        "offset": table.get("offset"),
        "count": len(entries),
        "entries": [{"label": e.get("label"), "type": e.get("type_name"), "subtype": e.get("subtype_name"),
                     "offset": e.get("offset"), "size": e.get("size"), "encrypted": bool(e.get("encrypted"))} for e in entries[:32]],
        "nvs_keys_present": bool(table.get("nvs_keys_present")),
    }


def _app_summary(data: bytes, table: dict[str, Any]) -> dict[str, Any] | None:
    for e in table.get("entries") or []:
        if e.get("type") == 0x00 and e.get("subtype") in (0x00, 0x10):
            h = header_at(data, int(e.get("offset") or 0))
            desc = (h or {}).get("app_desc") or {}
            if desc.get("magic_ok"):
                return {"partition": e.get("label"), "project_name": desc.get("project_name"), "version": desc.get("version"),
                        "idf_ver": desc.get("idf_ver")}
            return None
    return None


def plan_esp(data: bytes, *, provenance_reason: str, record: dict[str, Any] | None, chip_arg: str | None, psram: str = "auto",
             psram_mb: int | None = None, security_facts: Sequence[dict[str, Any]] = (), chip_facts: Sequence[dict[str, Any]] = ()) -> EspPlan:
    """ESP 전체 플래시 덤프 실행 계획 (메모리 바이트만 — 파일을 다시 열지 않는다)."""
    if data[:4] == b"\x7fELF":
        raise _err("emu_elf_refused", "ELF 파일은 받지 않습니다 — 전체 플래시 덤프(오프셋 0)만 실행합니다.",
                   hint="esptool 로 읽은 전체 플래시 덤프(esp_read_flash_start, size='all')를 쓴다.")
    if len(data) > limits.ESP_FLASH_MAX:
        raise _err("emu_flash_too_large", f"덤프가 16 MiB 를 넘습니다 ({len(data)} 바이트).",
                   hint="Espressif QEMU 는 16 MiB 까지만 지원한다. 지원하지 않음을 보고한다.")
    imported = provenance_reason == "imported-attested"
    rec = record or {}
    src = rec.get("source") or {}
    warnings: list[str] = []
    notes: list[str] = []
    want, unsupported_arg = normalize_chip(chip_arg) if chip_arg is not None else (None, None)
    if chip_arg is not None and want is None:
        if unsupported_arg:
            raise _err("emu_unsupported_chip", f"{unsupported_arg} 는 지원하지 않습니다 (esp32·esp32s3·esp32c3 만).", hint="지원하지 않음을 보고한다.")
        raise ValidationFailed(f"잘못된 chip: {str(chip_arg)[:40]!r}", hint="esp32 | esp32s3 | esp32c3 (생략 권장 — 서버가 증거로 정한다)")
    ledger_chip = None
    if not imported:
        off = _offset_value((rec.get("extra") or {}).get("offset"))
        if off != 0:
            raise _err("emu_not_full_image", "원장의 덤프 기록이 오프셋 0 의 전체 플래시 덤프가 아닙니다 (extra.offset ≠ 0).",
                       hint="esp_read_flash_start(offset=0, size='all') 로 전체 덤프를 만든다.")
        ledger_chip, unsupported = normalize_chip(src.get("chip"))
        if unsupported:
            raise _err("emu_unsupported_chip", f"{unsupported} 기기의 덤프입니다 — 이 서버는 ESP32·ESP32-S3·ESP32-C3 만 실행합니다.",
                       hint="지원하지 않음을 보고한다.")
    det = detect_header_chip(data)
    if "ambiguous" in det:
        pick = [c for c in det["candidates"] if c[0] == (ledger_chip or want)]
        if len(pick) != 1:
            raise _err("emu_not_full_image", "두 부트 오프셋 모두에 부트로더 헤더가 있어 칩을 정할 수 없습니다.",
                       hint="chip 인자를 주거나 덤프가 맞는지 확인한다.")
        chip, cid, boot_off, header = pick[0]
    else:
        chip, cid, boot_off, header = det["chip"], det["chip_id"], det["boot_offset"], det["header"]
    if ledger_chip is not None and ledger_chip != chip:
        raise _err("emu_machine_mismatch", f"원장의 칩({ledger_chip})과 덤프의 부트로더 헤더 칩({chip})이 다릅니다.",
                   hint="덤프가 이 기기의 것인지 확인한다.", data={"ledger": ledger_chip, "header": chip})
    if want is not None and want != chip:
        raise _err("emu_machine_mismatch", f"chip 인자({want})가 증거로 정한 칩({chip})과 다릅니다.", hint="chip 을 빼고 다시 호출한다.",
                   data={"argument": want, "evidence": chip})
    if imported and not (header.get("segments_complete") and (header.get("checksum") or {}).get("ok")):
        raise _err("emu_not_full_image", f"부트 오프셋 0x{boot_off:x} 의 이미지 헤더·체크섬을 확인할 수 없습니다(가져온 이미지는 헤더가 온전해야 한다).",
                   hint="전체 플래시 덤프인지 확인한다(암호화된 덤프는 실행하지 않는다).")
    if not imported and (header.get("errors") or []):
        notes.append(f"부트 오프셋 0x{boot_off:x} 의 부트로더 이미지에 해석 경고가 있다(체크섬 등)")
    declared = declared_flash_size(header)
    flash_size = flash_target_size(len(data), declared)
    if declared and len(data) < declared:
        warnings.append(f"partial_dump: 덤프({len(data)} 바이트)가 헤더 선언 크기({declared} 바이트)보다 작다 — 앱 파티션이 빠졌을 수 있다")
    # 보안 상태 (같은 MAC 의 esp-security-info 사실만)
    mac = str(src.get("mac") or "").lower()
    if imported:
        warnings.append("security_state_unknown: 가져온 이미지라 기기의 플래시 암호화 상태를 확인할 수 없다")
        chip_facts_same: list[dict[str, Any]] = []
    else:
        if src.get("verify") != "double-read":
            warnings.append("single_read: 이중 읽기로 확인하지 않은 덤프다(verify≠double-read) — 읽기 오류가 섞였을 수 있다")
        if not mac:
            warnings.append("security_state_unknown: 덤프 기록에 MAC 이 없어 같은 기기의 보안 사실을 찾을 수 없다")
            chip_facts_same = []
        else:
            sec = _same_mac(security_facts, mac)
            if any((f.get("data") or {}).get("flash_encryption") is True for f in sec):
                raise _err("emu_flash_encrypted", "같은 기기(MAC)의 esp_security_info 가 플래시 암호화 켜짐을 보고합니다 — 덤프는 암호문이라 실행할 수 없습니다.",
                           hint="우회하지 않는다(키는 칩의 읽기 보호 eFuse 에 있다). 사용자에게 보고한다.")
            last = sec[-1] if sec else None
            if last is None or (last.get("data") or {}).get("flash_encryption") is not False:
                warnings.append("security_state_unknown: 같은 기기의 플래시 암호화 상태를 확인하지 못했다(esp_security_info 없음 또는 미지원 칩)")
            chip_facts_same = _same_mac(chip_facts, mac)
    if chip == "esp32s3" and _octal_flash(chip_facts_same):
        warnings.append("octal_flash_unsupported: 기기의 플래시가 옥탈이다 — QEMU S3 SPI 모델은 표준 SPI-NOR 명령만 처리해 부팅하지 않을 수 있다")
    (pmode, pmb), psource = choose_psram(chip, psram, psram_mb, chip_facts=chip_facts_same, imported=imported)
    # 파티션 표·NVS 비밀값
    try:
        table = _espfmt().parse_partition_table(data)
    except Exception:  # noqa: BLE001
        table = {"found": False}
    if not table.get("found"):
        warnings.append("partition_table_missing: 파티션 표를 찾지 못했다(0x8000 등) — 알려진 비밀값 수집 없이 패턴 마스킹만 한다")
    secrets_, nvs_encrypted, nvs_notes = harvest_nvs_secrets(data, table) if table.get("found") else ([], False, [])
    notes += nvs_notes
    image = data + b"\xFF" * (flash_size - len(data))
    efuse = efuse_blob(chip)
    return EspPlan(
        chip=chip, chip_id=cid, boot_offset=boot_off, dump_size=len(data), declared_size=declared, flash_size=flash_size,
        image=image, image_sha256=hashlib.sha256(image).hexdigest(), efuse=efuse, efuse_sha256=hashlib.sha256(efuse).hexdigest(),
        psram=(pmode, pmb), psram_source=psource, warnings=warnings, notes=notes, known_secret_values=secrets_,
        nvs_encrypted=nvs_encrypted, partition_table=_partition_summary(table) if table.get("found") else {"found": False},
        app=_app_summary(data, table) if table.get("found") else None,
    )


# ---------------------------------------------------------------------------
# AVR
# ---------------------------------------------------------------------------

EEPROM_BASE = 0x810000
FUSE_BASE, LOCK_BASE, SIG_BASE = 0x820000, 0x830000, 0x840000
HEX_LINE_MAX = 600
_HEX_FIRST_LINE_RX = re.compile(r"^:[0-9A-Fa-f]{10}")


def looks_like_hex(data: bytes) -> bool:
    """Intel HEX 로 보이는가: 전부 ASCII 이고 첫 글자(공백 뒤)가 ':' 이며 첫 줄이 레코드 모양."""
    head = data[:4096]
    if not head or any(b > 0x7F for b in head):
        return False
    text = head.decode("ascii", "replace").lstrip()
    return bool(_HEX_FIRST_LINE_RX.match(text))


def detect_input_kind(data: bytes) -> str:
    if data[:4] == b"\x7fELF":
        return "elf"
    return "hex" if looks_like_hex(data) else "bin"


@dataclass
class AvrPlan:
    mcu: str
    input_kind: str  # hex | bin
    hex_bytes: bytes = field(repr=False)
    hex_sha256: str
    flash_sha256: str  # 플래시 전체(0xFF 채움) 내용
    flash_used: int  # 데이터가 있는 바이트 수
    flash_size: int
    eeprom_bytes: int
    eeprom_sha256: str | None
    notes: list[str] = field(default_factory=list)


def _bad_hex(message: str, line: int | None = None) -> PwehError:
    where = f" (줄 {line})" if line is not None else ""
    return _err("emu_bad_hex", f"Intel HEX 오류{where}: {message}",
                hint="HEX 를 다시 만들거나(사람이 PWEH 밖에서) raw 바이너리로 가져온다. 레코드 내용은 오류에 싣지 않는다.")


def parse_ihex(data: bytes, mcu: str) -> tuple[dict[int, int], dict[int, int], list[str]]:
    """Intel HEX → (플래시 {주소: 바이트}, EEPROM {오프셋: 바이트}, 메모). 오류는 emu_bad_hex(줄 번호·주소만)."""
    spec = B.MCUS[mcu]
    if len(data) > limits.AVR_HEX_MAX:
        raise _bad_hex(f"파일이 상한({limits.AVR_HEX_MAX} 바이트)보다 크다")
    for i, b in enumerate(data):
        if b > 0x7F:
            raise _bad_hex(f"ASCII 가 아닌 바이트 (오프셋 {i})")
    text = data.decode("ascii")
    flash: dict[int, int] = {}
    eeprom: dict[int, int] = {}
    notes: list[str] = []
    base = 0
    eof = False
    dropped = {"fuse": 0, "lock": 0, "signature": 0}
    start_records = 0
    for lineno, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        if not line:
            continue
        if eof:
            raise _bad_hex("EOF 레코드 뒤에 내용이 있다", lineno)
        if len(line) > HEX_LINE_MAX:
            raise _bad_hex(f"줄이 {HEX_LINE_MAX}자를 넘는다", lineno)
        if line[0] != ":":
            raise _bad_hex("':' 로 시작하지 않는 줄", lineno)
        body = line[1:]
        if len(body) < 10 or len(body) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", body):
            raise _bad_hex("레코드 형식(16진 글자 수)이 맞지 않는다", lineno)
        rec = bytes.fromhex(body)
        count, addr16, rtype = rec[0], (rec[1] << 8) | rec[2], rec[3]
        if len(rec) != count + 5:
            raise _bad_hex("레코드 길이 바이트가 실제 길이와 다르다", lineno)
        if sum(rec) & 0xFF:
            raise _bad_hex("레코드 체크섬이 맞지 않는다", lineno)
        payload = rec[4:4 + count]
        if rtype == 0x00:
            for k, byte in enumerate(payload):
                a = base + addr16 + k
                if a < spec.flash_size:
                    if a in flash:
                        raise _bad_hex(f"겹치는 주소 0x{a:x}", lineno)
                    flash[a] = byte
                elif EEPROM_BASE <= a < EEPROM_BASE + spec.eeprom_size:
                    o = a - EEPROM_BASE
                    if o in eeprom:
                        raise _bad_hex(f"겹치는 EEPROM 주소 0x{a:x}", lineno)
                    eeprom[o] = byte
                elif FUSE_BASE <= a < LOCK_BASE:
                    dropped["fuse"] += 1
                elif LOCK_BASE <= a < SIG_BASE:
                    dropped["lock"] += 1
                elif SIG_BASE <= a < SIG_BASE + 0x10000:
                    dropped["signature"] += 1
                else:
                    raise _bad_hex(f"{mcu} 의 플래시({spec.flash_size} 바이트)·EEPROM({spec.eeprom_size} 바이트) 범위 밖 주소 0x{a:x}", lineno)
        elif rtype == 0x01:
            if count != 0:
                raise _bad_hex("EOF 레코드에 데이터가 있다", lineno)
            eof = True
        elif rtype == 0x02:
            if count != 2:
                raise _bad_hex("확장 세그먼트 주소 레코드 길이가 2 가 아니다", lineno)
            base = ((payload[0] << 8) | payload[1]) << 4
        elif rtype == 0x04:
            if count != 2:
                raise _bad_hex("확장 선형 주소 레코드 길이가 2 가 아니다", lineno)
            base = ((payload[0] << 8) | payload[1]) << 16
        elif rtype in (0x03, 0x05):
            if count != 4:
                raise _bad_hex("시작 주소 레코드 길이가 4 가 아니다", lineno)
            start_records += 1
        else:
            raise _bad_hex(f"알 수 없는 레코드 유형 0x{rtype:02x}", lineno)
    if not eof:
        raise _bad_hex("EOF 레코드(:00000001FF)가 없다")
    if not flash:
        raise _bad_hex("플래시 데이터 레코드가 없다")
    if start_records:
        notes.append(f"시작 주소 레코드(유형 03·05) {start_records}개는 무시했다(실행기는 PC=0 에서 시작)")
    for kind, n in dropped.items():
        if n:
            notes.append({"fuse": "퓨즈", "lock": "잠금", "signature": "서명"}[kind] + f" 바이트 {n}개는 버렸다(실행기가 쓰지 않음)")
    if eeprom:
        notes.append(f"EEPROM 바이트 {len(eeprom)}개를 실행기에 넘긴다(시뮬레이션 EEPROM)")
    return flash, eeprom, notes


def _ihex_records(segments: Iterable[tuple[int, bytes]]) -> list[str]:
    """(절대 주소, 바이트) 연속 구간 → 16 바이트 데이터 레코드 + 상위 16비트가 바뀔 때 유형 04."""
    lines: list[str] = []
    upper = 0
    for start, chunk in segments:
        pos = 0
        while pos < len(chunk):
            a = start + pos
            if (a >> 16) != upper:
                upper = a >> 16
                rec = bytes([2, 0, 0, 4, (upper >> 8) & 0xFF, upper & 0xFF])
                lines.append(":" + (rec + bytes([(-sum(rec)) & 0xFF])).hex().upper())
            n = min(16, len(chunk) - pos, 0x10000 - (a & 0xFFFF))
            rec = bytes([n, (a >> 8) & 0xFF, a & 0xFF, 0]) + chunk[pos:pos + n]
            lines.append(":" + (rec + bytes([(-sum(rec)) & 0xFF])).hex().upper())
            pos += n
    return lines


def _runs(mapping: dict[int, int]) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    cur_start: int | None = None
    buf = bytearray()
    prev = None
    for a in sorted(mapping):
        if cur_start is None or a != prev + 1:  # type: ignore[operator]
            if cur_start is not None:
                out.append((cur_start, bytes(buf)))
            cur_start, buf = a, bytearray()
        buf.append(mapping[a])
        prev = a
    if cur_start is not None:
        out.append((cur_start, bytes(buf)))
    return out


def write_ihex(flash: dict[int, int], eeprom: dict[int, int] | None = None) -> bytes:
    """정규화 HEX: 플래시 구간 → EEPROM 구간(0x810000+) → EOF. 줄 끝은 \\n."""
    segs = _runs(flash) + [(EEPROM_BASE + o, b) for o, b in _runs(eeprom or {})]
    lines = _ihex_records(segs) + [":00000001FF"]
    return ("\n".join(lines) + "\n").encode("ascii")


def normalize_avr(data: bytes, mcu: str) -> AvrPlan:
    """AVR 입력(Intel HEX 또는 raw 바이너리) → 정규화 HEX 계획. ELF 는 emu_elf_refused."""
    if mcu not in B.MCUS:
        raise ValidationFailed(f"허용 목록 밖의 MCU: {mcu!r}", hint=f"허용: {', '.join(B.MCUS)}")
    spec = B.MCUS[mcu]
    kind = detect_input_kind(data)
    if kind == "elf":
        raise _err("emu_elf_refused", "ELF 파일은 받지 않습니다(simavr 의 ELF 메타데이터 처리에 펌웨어가 정하는 무제한 복사·파일 경로가 있다).",
                   hint="사람이 PWEH 밖에서 Intel HEX(avr-objcopy -O ihex)나 raw 바이너리로 바꿔 case_import_file 로 다시 가져온다.")
    if not data:
        raise _bad_hex("빈 입력")
    notes: list[str] = []
    if kind == "hex":
        flash, eeprom, notes = parse_ihex(data, mcu)
    else:
        if len(data) > spec.flash_size:
            raise _bad_hex(f"raw 바이너리({len(data)} 바이트)가 {mcu} 플래시({spec.flash_size} 바이트)보다 크다")
        flash = {i: b for i, b in enumerate(data)}
        eeprom = {}
        notes.append("raw 바이너리를 주소 0 부터의 플래시로 보고 Intel HEX 로 바꿨다(뒤쪽 0xFF 도 그대로)")
    hex_bytes = write_ihex(flash, eeprom)
    image = bytearray(b"\xFF" * spec.flash_size)
    for a, b in flash.items():
        image[a] = b
    ee_sha = None
    if eeprom:
        ee = bytearray(b"\xFF" * spec.eeprom_size)
        for o, b in eeprom.items():
            ee[o] = b
        ee_sha = hashlib.sha256(bytes(ee)).hexdigest()
    return AvrPlan(mcu=mcu, input_kind=kind, hex_bytes=hex_bytes, hex_sha256=hashlib.sha256(hex_bytes).hexdigest(),
                   flash_sha256=hashlib.sha256(bytes(image)).hexdigest(), flash_used=len(flash), flash_size=spec.flash_size,
                   eeprom_bytes=len(eeprom), eeprom_sha256=ee_sha, notes=notes)


def resolve_avr_target(board: str | None, mcu: str | None, freq_hz: int | None) -> tuple[str, str, int, int]:
    """보드 표 → (board, mcu, freq_hz, uart). custom 은 mcu·freq_hz 필수, 그 밖에는 주면 보드 값과 같아야 한다."""
    if board is None:
        raise ValidationFailed("AVR 은 board 가 필요합니다.", hint=f"허용: {', '.join(B.BOARDS)} (custom 이면 mcu·freq_hz 도)")
    spec = B.BOARDS.get(str(board))
    if spec is None:
        raise ValidationFailed(f"알 수 없는 board: {str(board)[:40]!r}", hint=f"허용: {', '.join(B.BOARDS)}")
    if freq_hz is not None and (isinstance(freq_hz, bool) or not isinstance(freq_hz, int)):
        raise ValidationFailed("freq_hz 는 정수여야 합니다.")
    if mcu is not None and mcu not in B.MCUS:
        raise ValidationFailed(f"허용 목록 밖의 MCU: {str(mcu)[:40]!r}", hint=f"허용: {', '.join(B.MCUS)}")
    if spec.mcu is None:  # custom
        if mcu is None or freq_hz is None:
            raise ValidationFailed("board='custom' 이면 mcu 와 freq_hz 가 필요합니다.")
        if not (B.FREQ_MIN_HZ <= freq_hz <= B.FREQ_MAX_HZ):
            raise ValidationFailed(f"freq_hz 는 {B.FREQ_MIN_HZ}–{B.FREQ_MAX_HZ} 입니다.")
        return spec.name, mcu, int(freq_hz), B.MCUS[mcu].default_uart
    if mcu is not None and mcu != spec.mcu:
        raise ValidationFailed(f"board={spec.name} 의 MCU 는 {spec.mcu} 입니다 (다른 MCU 는 board='custom').")
    if freq_hz is not None and freq_hz != spec.freq_hz:
        raise ValidationFailed(f"board={spec.name} 의 주파수는 {spec.freq_hz} Hz 입니다 (다른 값은 board='custom').")
    return spec.name, str(spec.mcu), int(spec.freq_hz or 0), int(spec.uart or 0)


def ihex_record_checksums_ok(data: bytes) -> bool:
    """HEX 파일의 모든 레코드 체크섬이 맞는가 (픽스처 시험용)."""
    for raw in data.decode("ascii").splitlines():
        line = raw.strip()
        if not line:
            continue
        rec = bytes.fromhex(line[1:])
        if sum(rec) & 0xFF:
            return False
    return True


__all__ = [
    "AvrPlan", "EFUSE_SHA256", "EspPlan", "FLASH_SIZES", "choose_psram", "declared_flash_size", "detect_header_chip",
    "detect_input_kind", "efuse_blob", "flash_target_size", "harvest_nvs_secrets", "header_at", "ihex_record_checksums_ok",
    "looks_like_hex", "normalize_avr", "normalize_chip", "parse_ihex", "plan_esp", "resolve_avr_target", "write_ihex",
]

