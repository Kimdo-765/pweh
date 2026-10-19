"""esp-mcp 안전 정책: esptool argv 분류기와 인자 검증.

이 서버는 Espressif 칩(ESP32 계열)의 **읽기 전용** 분석만 한다. 허용하는 esptool 명령은 아래 여섯 가지뿐이다.

- ``version``                                  OBSERVE  (기기 미접촉)
- ``chip-id`` / ``read-mac`` / ``flash-id`` / ``get-security-info``   MODIFY
- ``read-flash``                               MODIFY

MODIFY 인 이유: esptool 은 연결할 때 DTR/RTS(또는 USB-Serial/JTAG 리셋)로 칩을 리셋해 ROM 다운로드 모드에 넣고,
보통 RAM 에 플래셔 스텁을 올리며, USB-Serial/JTAG 연결이면 워치독 레지스터를 끄고, SPI 플래시에 리셋(0x66/0x99) 같은
휘발성 명령을 보낸다. 끝나면 ``--after`` 에 따라 다시 리셋한다. 모두 전원을 껐다 켜면 사라지는 상태 변화이고
플래시·eFuse 에는 쓰지 않는다 (PWEH 안전 모델에서 리셋/DTR 토글은 MODIFY, 기본 허용).

``--after`` 는 이 조건을 지키는 것만 쓴다 (허용: ``hard-reset``, ``no-reset-stub``, ``watchdog-reset``).

- ``no-reset`` 은 스텁을 빠져나와 ROM 으로 돌아가려고 ``FLASH_BEGIN(0, 0)`` + ``FLASH_END`` 를 보낸다(esptool 4.8.1
  ``__init__.py`` 의 no_reset 분기 → ``soft_reset(True)``, 5.4.0 ``cmds.py`` reset_chip). 레거시 스텁(esptool 4.8~5.2 의 기본,
  ``ESPTOOL_STUB_VERSION=1``)은 FLASH_BEGIN 에서 ``SPIUnlock()`` 으로 SPI 플래시 **상태 레지스터를 다시 쓴다**(비휘발성,
  쓰기 보호 해제). 또 ``--chip auto`` 연결은 칩에 스텁이 이미 돌고 있으면 ``--no-stub`` 이어도 스텁으로 다룬다(4.8.1·5.4.0
  ``detect_chip``). 그래서 서버는 plain ``no-reset`` 을 **절대 넘기지 않는다**: 사용자가 ``after='no-reset'`` 을 주면
  ``no-reset-stub`` 으로 바꾼다(ROM 세션에서는 둘 다 아무것도 보내지 않아 같은 동작이고, 스텁 세션이면 스텁에 머문다).
  이중 읽기의 1차 읽기도 ``no-reset-stub`` 이다. 분류기는 ``--after no-reset`` 을 DESTRUCTIVE(``esp.after.no-reset``)로 거부한다.
- ``soft-reset`` 도 끝날 때 FLASH_BEGIN 을 보내므로(``soft_reset(False)``) 허용하지 않는다(``esp.after.soft-reset``).
- ``watchdog-reset`` 은 esptool v5 와 v4.12 이상에만 있다.

``--no-stub`` (ROM 로더와 직접)은 ESP8266 이 아닌 칩을 ``--chip`` 으로 **명시**할 때만 쓴다. ESP8266 ROM 에는 플래시 연결 명령이
없어 esptool 이 대신 ``FLASH_BEGIN(0, 0)`` 을 보낸다(4.8.1·5.4.0 ``targets/esp8266.py`` flash_spi_attach — 4.8.1 은
``--no-stub`` 이면 모든 명령에서, 5.x 는 flash-id·read-flash 의 attach_flash 에서). 위 FLASH_BEGIN 과 같은 위험(상태 레지스터
다시 쓰기 가능, 하드웨어 미확인)이라 거부한다. ``--chip auto`` 는 ESP8266 으로 판정될 수 있으므로 함께 거부한다
(인자 검증 ``validate_no_stub`` 과 분류기 규칙 ``esp.nostub.esp8266``).

그 밖의 모든 것은 DESTRUCTIVE 로 분류한다: ``write-flash``, ``erase-flash``, ``erase-region``, ``write-mem``,
``load-ram``, ``run``, ``write-flash-status``, ``read-mem``/``dump-mem``(임의 MMIO 읽기는 부작용 가능),
``merge-bin``/``image-info``/``elf2image``(이 서버 범위 밖의 파일 쓰기), 알 수 없는 명령·옵션, espefuse/espsecure 실행 파일,
``@파일`` 인자 확장, 검증된 포트와 다른 ``--port``, 케이스 dumps/ 밖의 출력 경로. 서버는 DESTRUCTIVE 를 안전 게이트에
넘기지 않고 바로 거부한다(approve 정책으로도 승인 경로가 없다).

분류기 ``classify_esptool_argv`` 는 서버가 실제로 실행할 argv 를 그대로 검사한다. 서버는 검증한 인자로 argv 를
직접 조립하고(원시 인자 전달 없음), 백그라운드 작업은 프로세스를 띄우기 직전에 같은 분류기로 다시 검사한다.
"""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from pweh.errors import ValidationFailed
from pweh.fsutil import parse_size
from pweh.safety import Classification, Risk

#: --chip 허용 값 (esptool v4.8 / v5.x 공통으로 쓰이는 이름. 오래된 esptool 이 모르는 칩이면 esptool 이 거부한다)
CHIPS: tuple[str, ...] = (
    "auto", "esp8266", "esp32", "esp32s2", "esp32s3", "esp32c2", "esp32c3", "esp32c5", "esp32c6", "esp32c61",
    "esp32h2", "esp32p4",
)
#: --before (연결 전 리셋). no-reset-no-sync 는 쓰지 않는다.
BEFORE_MODES: tuple[str, ...] = ("default-reset", "usb-reset", "no-reset")
#: --after 로 받는 값 (끝난 뒤 리셋). no-reset 은 받되 실행할 때는 항상 no-reset-stub 으로 바꾼다(stub_safe_after).
#: soft-reset 은 FLASH_BEGIN 을 보내므로 받지 않는다. watchdog-reset 은 esptool v5 와 v4.12 이상.
AFTER_MODES: tuple[str, ...] = ("hard-reset", "no-reset", "no-reset-stub", "watchdog-reset")
AFTER_MODES_V4: tuple[str, ...] = ("hard-reset", "no-reset", "no-reset-stub")  # esptool v4.12 미만
#: watchdog-reset 이 있는 가장 낮은 v4 (4.12.0 __init__.py 의 --after choices)
WATCHDOG_RESET_MIN_V4 = 12
BAUD_MIN = 9600
BAUD_MAX = 4_000_000
CONNECT_ATTEMPTS_DEFAULT = 7
CONNECT_ATTEMPTS_MAX = 20
MAX_FLASH_BYTES = 256 * 1024 * 1024
VERIFY_MODES: tuple[str, ...] = ("double", "none")
#: --no-stub 과 함께 쓰지 않는 --chip 값: ESP8266 ROM 은 플래시 연결 때 FLASH_BEGIN(0, 0) 을 받는다. auto 는 ESP8266 일 수 있다.
NOSTUB_REFUSED_CHIPS: tuple[str, ...] = ("auto", "esp8266")

#: 기기 정보 명령 (연결 + 조회)
INFO_COMMANDS = frozenset({"chip-id", "read-mac", "flash-id", "get-security-info"})
#: 플래시 읽기 명령
READ_COMMANDS = frozenset({"read-flash"})

_INFO_DESC = {
    "chip-id": "칩 ID 조회(ESP32-S3 등은 칩 ID 가 없어 MAC 을 대신 출력)",
    "read-mac": "eFuse 의 MAC 주소 조회",
    "flash-id": "SPI 플래시 제조사/장치 ID·감지 크기 조회",
    "get-security-info": "보안 설정(Secure Boot·플래시 암호화·Secure Download Mode·키 용도) 조회",
}

#: 알려진 비허용 명령 → (규칙 id, 사유). 표에 없는 명령은 esp.cmd.unknown.
_REFUSED_COMMANDS: dict[str, tuple[str, str]] = {
    "write-flash": ("esp.cmd.flash-write", "플래시 쓰기(영구 변경)"),
    "erase-flash": ("esp.cmd.flash-write", "플래시 전체 삭제(영구 변경)"),
    "erase-region": ("esp.cmd.flash-write", "플래시 영역 삭제(영구 변경)"),
    "write-flash-status": ("esp.cmd.flash-write", "SPI 플래시 상태 레지스터 쓰기(--non-volatile 이면 영구 변경, 쓰기 보호 해제 가능)"),
    "write-nand-spare": ("esp.cmd.flash-write", "NAND 스페어 영역 쓰기(배드 블록 표시, 영구 변경)"),
    "load-ram": ("esp.cmd.ram-exec", "RAM 에 이미지를 올려 실행(임의 코드 실행)"),
    "run": ("esp.cmd.ram-exec", "플래시의 앱 실행 명령"),
    "write-mem": ("esp.cmd.mem-write", "임의 메모리/주변장치 레지스터 쓰기(eFuse 컨트롤러 등 영구 변경 가능)"),
    "read-mem": ("esp.cmd.mem-read", "임의 주소 읽기(MMIO 레지스터 읽기는 플래그를 지우는 등 부작용 가능)"),
    "dump-mem": ("esp.cmd.mem-read", "임의 메모리 덤프(MMIO 영역 읽기 부작용 가능)"),
    "merge-bin": ("esp.cmd.offline", "이미지 병합 도구 — 이 서버 범위 밖(임의 파일 쓰기)"),
    "image-info": ("esp.cmd.offline", "이미지 분석 도구 — 이 서버 범위 밖(fwtriage/REA 를 사용)"),
    "elf2image": ("esp.cmd.offline", "이미지 생성 도구 — 이 서버 범위 밖(임의 파일 쓰기)"),
    "make-image": ("esp.cmd.offline", "이미지 생성 도구 — 이 서버 범위 밖(임의 파일 쓰기)"),
    "verify-flash": ("esp.cmd.unsupported", "이 서버가 쓰지 않는 명령(입력 파일 경로를 받음)"),
    "read-flash-status": ("esp.cmd.unsupported", "이 서버가 쓰지 않는 명령"),
    "read-flash-sfdp": ("esp.cmd.unsupported", "이 서버가 쓰지 않는 명령"),
    "read-nand-spare": ("esp.cmd.unsupported", "이 서버가 쓰지 않는 명령"),
    "dump-bbm": ("esp.cmd.unsupported", "이 서버가 쓰지 않는 명령(NAND 배드 블록 스캔)"),
    "verify-sdc-certificate": ("esp.cmd.unsupported", "보안 디버그 컨트롤러 인증서 명령 — 범위 밖"),
    "read-sdc-chip-info": ("esp.cmd.unsupported", "보안 디버그 컨트롤러 명령 — 범위 밖"),
}

#: 값을 받는 전역 옵션 (서버는 항상 '--name value' 두 토큰으로 조립한다)
_VALUE_OPTS = frozenset({"--chip", "--port", "--baud", "--before", "--after", "--connect-attempts"})
_FLAG_OPTS = frozenset({"--no-stub"})
#: 알려진 위험/금지 옵션의 구체적 사유 (허용 목록 밖은 어차피 모두 거부)
_FORBIDDEN_OPTS: dict[str, str] = {
    "--override-vddsdio": "VDDSDIO 전압 레귤레이터 강제 설정(하드웨어 손상 가능)",
    "--port-filter": "포트 자동 선택 필터 — 다른 장치를 리셋할 수 있어 금지(항상 --port 로 하나만 지정)",
    "--spi-connection": "SPI 플래시 핀 재설정 — 이 서버는 쓰지 않음",
    "--trace": "추적 출력은 출력 형식을 바꿈(파서 고정)",
    "-t": "추적 출력은 출력 형식을 바꿈(파서 고정)",
    "--verbose": "출력 형식 변경 옵션은 쓰지 않음",
    "-v": "출력 형식 변경 옵션은 쓰지 않음",
    "--silent": "출력을 숨기면 결과를 검증할 수 없음",
    "-s": "출력을 숨기면 결과를 검증할 수 없음",
    "--stub-version": "숨은 내부 옵션",
    "--encrypt": "쓰기 전용 옵션",
    "--force": "보안 검사 우회 옵션",
}

_EXE_FORBIDDEN_RE = re.compile(r"espefuse|espsecure|rfc2217", re.I)
_HEX_RE = re.compile(r"^0[xX][0-9a-fA-F]{1,8}$")
_DEC_RE = re.compile(r"^[0-9]{1,10}$")
OUTPUT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_WIN_PORT_RE = re.compile(r"^COM([1-9][0-9]{0,2})$")
_LINUX_PORT_RE = re.compile(r"^/dev/(?:tty(?:ACM|USB|S)[0-9]{1,3}|serial/by-id/[A-Za-z0-9._:+@-]{1,200})$")


# ---------------------------------------------------------------------------
# 값 검증 (도구 인자 → 정규화된 값)
# ---------------------------------------------------------------------------


def norm_name(name: str) -> str:
    """명령/모드 이름의 밑줄 형식(v4)을 하이픈 형식(v5)으로."""
    return str(name).strip().replace("_", "-")


def validate_chip(chip: Any) -> str:
    c = str(chip if chip is not None else "auto").strip().lower().replace("-", "")
    if c not in CHIPS:
        raise ValidationFailed(f"알 수 없는 chip: {chip!r}", hint=f"허용: {', '.join(CHIPS)} (모르면 'auto')")
    return c


def validate_before(value: Any) -> str:
    v = norm_name(value or "default-reset").lower()
    if v not in BEFORE_MODES:
        raise ValidationFailed(
            f"잘못된 before: {value!r}",
            hint="default-reset(기본, DTR/RTS 자동 리셋) | usb-reset(USB-Serial/JTAG) | no-reset(사람이 BOOT+RESET 으로 다운로드 모드에 넣은 경우)",
        )
    return v


def after_modes(major: int | None = None, minor: int | None = None) -> tuple[str, ...]:
    """그 esptool 버전이 받는 --after 값 (버전을 모르면 전부). watchdog-reset 은 v5 와 v4.12 이상."""
    if major is None or major >= 5:
        return AFTER_MODES
    if major == 4 and minor is not None and minor >= WATCHDOG_RESET_MIN_V4:
        return AFTER_MODES
    return AFTER_MODES_V4


def validate_after(value: Any, major: int | None = None, minor: int | None = None) -> str:
    """사용자가 준 after 검증 (정규화한 이름). 실행할 값은 stub_safe_after 로 정한다."""
    v = norm_name(value or "hard-reset").lower()
    allowed = after_modes(major, minor)
    if v not in allowed:
        why = ""
        if v == "watchdog-reset":
            why = " (watchdog-reset 은 esptool v5 또는 v4.12 이상)"
        elif v == "soft-reset":
            why = " (soft-reset 은 끝날 때 FLASH_BEGIN 을 보내 레거시 스텁·ROM 이 SPI 플래시 상태 레지스터를 다시 쓸 수 있어 쓰지 않는다)"
        raise ValidationFailed(
            f"잘못된 after: {value!r}{why}",
            hint=f"허용: {', '.join(allowed)}. hard-reset 은 끝난 뒤 앱을 다시 실행시킨다. no-reset 은 no-reset-stub 으로 바꿔 실행한다.",
        )
    return v


def stub_safe_after(after: str) -> str:
    """실제로 넘길 --after: no-reset → no-reset-stub (나머지는 그대로).

    no-reset 은 스텁 세션을 끝낼 때 FLASH_BEGIN 을 보낸다(레거시 스텁은 SPI 플래시 상태 레지스터를 다시 씀 — 비휘발성).
    ``--chip auto`` 연결은 칩에 남아 있던 스텁을 ``--no-stub`` 이어도 스텁으로 다루므로 no_stub 여부와 관계없이 바꾼다.
    ROM 세션에서는 no-reset 과 no-reset-stub 모두 아무 명령도 보내지 않는다(같은 동작).
    """
    a = norm_name(after).lower()
    return "no-reset-stub" if a == "no-reset" else a


def validate_no_stub(no_stub: Any, chip: str) -> bool:
    """no_stub 검증: True 면 chip 이 ESP8266 이 아닌 칩으로 명시돼 있어야 한다 (auto·esp8266 거부).

    ESP8266 ROM 에는 플래시 연결 명령이 없어 esptool 이 ``FLASH_BEGIN(0, 0)`` 을 대신 보낸다. FLASH_BEGIN 은 SPI 플래시 상태
    레지스터를 다시 쓸 수 있으므로(no-reset/soft-reset 을 막는 이유와 같다) 스텁 없는 ESP8266 연결을 만들지 않는다.
    """
    if isinstance(no_stub, str):
        raise ValidationFailed(f"no_stub 은 true/false 여야 합니다: {no_stub!r}")
    flag = bool(no_stub)
    if flag and chip in NOSTUB_REFUSED_CHIPS:
        raise ValidationFailed(
            f"no_stub=True 는 chip 을 ESP8266 이 아닌 칩으로 명시해야 합니다 (받은 chip={chip!r})",
            hint="ESP8266 ROM 은 스텁 없이 연결하면 esptool 이 FLASH_BEGIN 을 보낸다(SPI 플래시 상태 레지스터 쓰기 가능 — 비휘발성). "
                 "esp_chip_info(no_stub=False) 로 칩 종류를 확인한 뒤 chip='esp32s3' 처럼 명시하라. ESP8266 은 no_stub=False(기본)만 쓴다.",
        )
    return flag


def validate_baud(value: Any, default: int) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise ValidationFailed(f"baud 는 정수여야 합니다: {value!r}")
    try:
        b = int(str(value).strip(), 10)
    except ValueError:
        raise ValidationFailed(f"baud 는 정수여야 합니다: {value!r}")
    if not BAUD_MIN <= b <= BAUD_MAX:
        raise ValidationFailed(f"baud 범위를 벗어났습니다: {b} ({BAUD_MIN}~{BAUD_MAX})",
                               hint="보통 115200(연결), 460800/921600(읽기). 전송 오류가 나면 낮춘다.")
    return b


def validate_offset(value: Any) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, bool):
        raise ValidationFailed(f"offset 형식이 잘못되었습니다: {value!r}")
    if isinstance(value, int):
        off = value
    else:
        s = str(value).strip().lower()
        try:
            off = int(s, 16) if s.startswith("0x") else int(s, 10)
        except ValueError:
            raise ValidationFailed(f"offset 형식이 잘못되었습니다: {value!r}", hint="정수 또는 '0x10000' 같은 16진수")
    if not 0 <= off < 2**32:
        raise ValidationFailed(f"offset 범위를 벗어났습니다: {off}")
    return off


def validate_size(value: Any) -> int | str:
    """'all' 또는 바이트 수(정수, '0x400000', '4M', '16MB', '512K')."""
    if value is None or (isinstance(value, str) and value.strip().lower() == "all"):
        return "all"
    if isinstance(value, bool):
        raise ValidationFailed(f"size 형식이 잘못되었습니다: {value!r}")
    try:
        n = parse_size(value if isinstance(value, int) else str(value).strip())
    except Exception:
        raise ValidationFailed(f"size 형식이 잘못되었습니다: {value!r}", hint="'all', 정수, '0x400000', '4M', '16MB', '512K'")
    if n <= 0 or n > MAX_FLASH_BYTES:
        raise ValidationFailed(f"size 범위를 벗어났습니다: {n} (1 ~ {MAX_FLASH_BYTES})")
    return n


def validate_verify(value: Any) -> str:
    v = str(value or "double").strip().lower()
    if v in ("single", "off"):
        v = "none"
    if v not in VERIFY_MODES:
        raise ValidationFailed(f"잘못된 verify: {value!r}", hint="double(두 번 읽어 sha256 비교, 기본) | none(한 번 읽기)")
    return v


def validate_output_name(value: Any) -> str | None:
    if value is None or value == "":
        return None
    name = str(value).strip()
    if name.lower().endswith(".bin"):
        name = name[:-4]
    if not OUTPUT_NAME_RE.match(name) or ".." in name or name.lower().endswith((".read2", ".json", ".partial")):
        raise ValidationFailed(
            f"잘못된 output_name: {value!r}",
            hint="영문/숫자/._- 만 사용 (최대 80자, 경로 구분자 금지). 확장자 .bin 은 자동으로 붙는다. '.read2' 로 끝나는 이름은 예약됨.",
        )
    return name


def validate_connect_attempts(value: Any) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValidationFailed(f"connect_attempts 는 정수여야 합니다: {value!r}")
    if not 1 <= n <= CONNECT_ATTEMPTS_MAX:
        raise ValidationFailed(f"connect_attempts 범위를 벗어났습니다: {n} (1~{CONNECT_ATTEMPTS_MAX}, 0=무한은 금지)")
    return n


# ---------------------------------------------------------------------------
# argv 분류기
# ---------------------------------------------------------------------------


def _refuse(rule: str, reason: str, shown: str, details: Sequence[str] = ()) -> Classification:
    return Classification(Risk.DESTRUCTIVE, rule, reason, matched=shown, details=tuple(str(d) for d in details))


def display_argv(argv: Sequence[Any]) -> list[str]:
    """감사/표시용 argv (실행 파일은 이름만)."""
    if not argv:
        return []
    exe = str(argv[0]).replace("\\", "/").rsplit("/", 1)[-1]
    return [exe, *[str(a) for a in argv[1:]]]


def _exe_name(argv0: str) -> str:
    return str(argv0).replace("\\", "/").rsplit("/", 1)[-1]


def _within(path: str, base: str | os.PathLike[str]) -> bool:
    try:
        Path(path).resolve().relative_to(Path(base).resolve())
        return True
    except (ValueError, OSError):
        return False


def _port_ok(port: str) -> bool:
    return bool(_WIN_PORT_RE.match(port) or _LINUX_PORT_RE.match(port))


def _int_token(tok: str) -> int | None:
    if _HEX_RE.match(tok):
        return int(tok, 16)
    if _DEC_RE.match(tok):
        return int(tok, 10)
    return None


def classify_esptool_argv(
    argv: Sequence[Any],
    *,
    port: str | None = None,
    allowed_output_dir: str | os.PathLike[str] | None = None,
    output_map: Mapping[str, str] | None = None,
    esptool_major: int | None = None,
    esptool_minor: int | None = None,
) -> Classification:
    """실행할 esptool argv 의 위험도 분류.

    - ``port``: 서버가 검증한 포트. argv 의 ``--port`` 값과 정확히 같아야 한다(없으면 esptool 이 모든 포트를 훑는다 → 거부).
    - ``allowed_output_dir``: read-flash 출력이 들어가야 할 케이스 dumps/ 디렉터리.
    - ``output_map``: argv 의 출력 토큰 → 리눅스 경로. Windows 백엔드는 ``wslpath -w`` 로 바꾼 UNC 경로를 쓰므로,
      서버가 argv 를 만들 때 기록한 원래 리눅스 경로로 dumps/ 안인지 확인한다.
    - ``esptool_major`` / ``esptool_minor``: 알면 그 버전에 없는 모드(v4.12 미만의 watchdog-reset)를 거부한다.
    - ``--after no-reset``(FLASH_BEGIN 으로 스텁을 빠져나감)과 ``--after soft-reset``(FLASH_BEGIN)은 DESTRUCTIVE.
    - ``--no-stub`` + ``--chip esp8266|auto``(ESP8266 ROM 플래시 연결 = FLASH_BEGIN)도 DESTRUCTIVE(``esp.nostub.esp8266``).
    """
    shown = " ".join(display_argv(argv))
    if not argv or any(not isinstance(a, str) for a in argv):
        return _refuse("esp.argv.unparsed", "argv 는 문자열 목록이어야 함", shown)
    bad = [a for a in argv[1:] if a.startswith("@") or any(ch in a for ch in "\x00\r\n")]
    if bad:
        return _refuse("esp.argv.unparsed", "'@파일' 인자 확장(esptool 이 파일 내용을 인자로 펼침) 또는 제어 문자가 섞인 인자", shown, bad)
    exe = _exe_name(argv[0])
    if not exe or _EXE_FORBIDDEN_RE.search(exe):
        return _refuse("esp.exe.forbidden", f"허용되지 않은 실행 파일 {exe!r} (espefuse/espsecure/rfc2217 서버는 이 서버 범위 밖 — eFuse 영구 변경 가능)", shown)

    tokens = [str(a) for a in argv[1:]]
    opts: dict[str, str | bool] = {}
    i = 0
    while i < len(tokens) and tokens[i].startswith("-"):
        name = tokens[i]
        if name in _VALUE_OPTS:
            if i + 1 >= len(tokens) or tokens[i + 1].startswith("-"):
                return _refuse("esp.opt.missing-value", f"{name} 에 값이 없음", shown)
            if name in opts:
                return _refuse("esp.opt.duplicate", f"{name} 중복", shown)
            opts[name] = tokens[i + 1]
            i += 2
        elif name in _FLAG_OPTS:
            if name in opts:
                return _refuse("esp.opt.duplicate", f"{name} 중복", shown)
            opts[name] = True
            i += 1
        else:
            base = name.split("=", 1)[0]
            reason = _FORBIDDEN_OPTS.get(base) or _FORBIDDEN_OPTS.get(base.replace("_", "-"))
            if reason:
                return _refuse("esp.opt.forbidden", f"금지된 옵션 {base}: {reason}", shown)
            return _refuse("esp.opt.unknown", f"허용 목록 밖의 옵션 {base} (이 서버는 --chip/--port/--baud/--before/--after/--no-stub/--connect-attempts 만 조립)", shown)
    if i >= len(tokens):
        return _refuse("esp.cmd.missing", "esptool 명령이 없음", shown)
    raw_cmd = tokens[i]
    cmd = norm_name(raw_cmd)
    rest = tokens[i + 1:]

    if cmd == "version":
        if opts or rest:
            return _refuse("esp.version.args", "version 은 옵션 없이 실행", shown)
        return Classification(Risk.OBSERVE, "esp.version", "esptool 버전 조회 (기기 미접촉)", matched=shown)
    if cmd in _REFUSED_COMMANDS:
        rule, why = _REFUSED_COMMANDS[cmd]
        return _refuse(rule, f"esptool '{raw_cmd}': {why} — 이 서버는 읽기 전용(flash-id/get-security-info/read-flash 등)만 실행", shown)
    if cmd not in INFO_COMMANDS and cmd not in READ_COMMANDS:
        return _refuse("esp.cmd.unknown", f"허용 목록 밖의 esptool 명령 {raw_cmd!r}", shown)

    # --- 기기 명령: 포트·칩·속도·리셋 모드를 모두 명시해야 한다 (환경변수/설정 파일 기본값에 맡기지 않음) ---
    p = opts.get("--port")
    if not isinstance(p, str):
        return _refuse("esp.port.missing", "--port 없음 — esptool 이 모든 시리얼 포트를 훑으며 다른 장치를 리셋할 수 있음", shown)
    if not _port_ok(p):
        return _refuse("esp.port.invalid", f"허용되지 않은 포트 형식 {p!r} (COMn, /dev/ttyACMn, /dev/ttyUSBn, /dev/ttySn, /dev/serial/by-id/… 만)", shown)
    if port is not None and p != port:
        return _refuse("esp.port.mismatch", f"argv 의 --port {p!r} 가 검증한 포트 {port!r} 와 다름", shown)
    chip = opts.get("--chip")
    if not isinstance(chip, str) or chip not in CHIPS:
        return _refuse("esp.opt.value", f"--chip 값이 없거나 허용 목록 밖: {chip!r}", shown)
    baud = opts.get("--baud")
    if not isinstance(baud, str) or not _DEC_RE.match(baud) or not BAUD_MIN <= int(baud) <= BAUD_MAX:
        return _refuse("esp.opt.value", f"--baud 값이 없거나 범위 밖: {baud!r}", shown)
    before = opts.get("--before")
    if not isinstance(before, str) or norm_name(before) not in BEFORE_MODES:
        return _refuse("esp.opt.value", f"--before 값이 없거나 허용 목록 밖: {before!r}", shown)
    after = opts.get("--after")
    if not isinstance(after, str):
        return _refuse("esp.opt.value", f"--after 값이 없음: {after!r}", shown)
    after_n = norm_name(after)
    if after_n == "soft-reset":
        return _refuse("esp.after.soft-reset",
                       "--after soft-reset 은 끝날 때 FLASH_BEGIN 을 보낸다(레거시 스텁·ROM 은 SPI 플래시 상태 레지스터를 다시 쓸 수 있음 — "
                       "비휘발성 변경). 이 서버는 hard-reset / no-reset-stub / watchdog-reset 만 쓴다", shown)
    if after_n == "no-reset":
        return _refuse("esp.after.no-reset",
                       "--after no-reset 은 스텁 세션을 끝낼 때 FLASH_BEGIN 을 보낸다(레거시 스텁은 이때 SPI 플래시 상태 레지스터를 다시 써 "
                       "쓰기 보호를 푼다 — 비휘발성 변경. --chip auto 는 칩에 남은 스텁을 --no-stub 이어도 스텁으로 다룬다). no-reset-stub 을 쓴다",
                       shown)
    if after_n not in after_modes(esptool_major, esptool_minor):
        return _refuse("esp.opt.value", f"--after 값이 허용 목록 밖(또는 이 esptool 버전에 없음): {after!r}", shown)
    ca = opts.get("--connect-attempts")
    if ca is not None and (not isinstance(ca, str) or not _DEC_RE.match(ca) or not 1 <= int(ca) <= CONNECT_ATTEMPTS_MAX):
        return _refuse("esp.opt.value", f"--connect-attempts 는 1~{CONNECT_ATTEMPTS_MAX} (0=무한 재시도 금지): {ca!r}", shown)
    if "--no-stub" in opts and chip in NOSTUB_REFUSED_CHIPS:
        return _refuse("esp.nostub.esp8266",
                       f"--chip {chip} 과 --no-stub: ESP8266 ROM 은 플래시 연결 때 esptool 이 FLASH_BEGIN(0, 0) 을 보낸다(SPI 플래시 상태 "
                       "레지스터를 다시 쓸 수 있음 — 비휘발성 변경). auto 는 ESP8266 으로 판정될 수 있다. --no-stub 은 ESP8266 이 아닌 칩을 "
                       "--chip 으로 명시할 때만 쓴다", shown)
    stub = "--no-stub" not in opts
    connect = (
        f"DTR/RTS(또는 USB-Serial/JTAG) 리셋({norm_name(before)})으로 칩을 ROM 다운로드 모드에 넣고"
        + (" RAM 에 플래셔 스텁을 올린 뒤" if stub else " (스텁 없이 ROM 로더와 직접)")
    )
    after_desc = after_n + (" — 칩을 다운로드 모드(스텁)에 그대로 둠, 스텁을 빠져나가는 FLASH_BEGIN 을 보내지 않음"
                            if after_n == "no-reset-stub" else "")
    tail = f" — 휘발성 상태 변경(리셋·RAM·워치독/SPI 리셋 명령), 플래시·eFuse 쓰기 없음. 끝나면 --after {after_desc}."

    if cmd in INFO_COMMANDS:
        if rest:
            return _refuse("esp.argv.extra", f"{raw_cmd} 뒤의 추가 인자는 허용하지 않음: {rest}", shown)
        return Classification(Risk.MODIFY, f"esp.info.{cmd}", f"esptool 연결: {connect} {_INFO_DESC[cmd]}{tail}", matched=shown)

    # --- read-flash <address> <size> <output> ---
    if len(rest) != 3:
        return _refuse("esp.argv.extra", "read-flash 는 정확히 <주소> <크기> <출력파일> 만 허용(뒤따르는 옵션 금지)", shown, rest)
    addr_tok, size_tok, out_tok = rest
    addr = _int_token(addr_tok)
    if addr is None or not 0 <= addr < 2**32:
        return _refuse("esp.read.address", f"read-flash 주소 형식 오류: {addr_tok!r}", shown)
    if size_tok.lower() == "all":
        if addr != 0:
            return _refuse("esp.read.size", "size=all 은 주소 0 에서만 (esptool 이 감지 크기를 넘는 읽기를 거부)", shown)
        size_desc = "전체(감지 크기)"
    else:
        size = _int_token(size_tok)
        if size is None or size <= 0 or size > MAX_FLASH_BYTES or addr + size > 2**32:
            return _refuse("esp.read.size", f"read-flash 크기 형식/범위 오류: {size_tok!r}", shown)
        size_desc = f"{size} 바이트"
    if output_map is None and allowed_output_dir is None:
        return _refuse("esp.output.unverified", "출력 경로를 검증할 기준(케이스 dumps/)이 없음", shown)
    linux_path: str | None
    if output_map is not None and out_tok in output_map:
        linux_path = output_map[out_tok]
    elif PurePosixPath(out_tok).is_absolute():
        linux_path = out_tok
    else:
        linux_path = None
    if linux_path is None or not PurePosixPath(linux_path).is_absolute():
        return _refuse("esp.output.outside", f"출력 경로를 확인할 수 없음 (서버가 예약한 경로만 허용): {out_tok!r}", shown)
    if allowed_output_dir is not None and not _within(linux_path, allowed_output_dir):
        return _refuse("esp.output.outside", f"출력 파일이 케이스 dumps/ 밖: {linux_path}", shown)
    return Classification(
        Risk.MODIFY,
        "esp.read-flash",
        f"esptool 연결: {connect} SPI 플래시 읽기(주소 0x{addr:x}, {size_desc}) → 케이스 dumps/{tail}",
        matched=shown,
    )


__all__ = [
    "AFTER_MODES",
    "AFTER_MODES_V4",
    "WATCHDOG_RESET_MIN_V4",
    "after_modes",
    "stub_safe_after",
    "BAUD_MAX",
    "BAUD_MIN",
    "BEFORE_MODES",
    "CHIPS",
    "CONNECT_ATTEMPTS_DEFAULT",
    "INFO_COMMANDS",
    "MAX_FLASH_BYTES",
    "NOSTUB_REFUSED_CHIPS",
    "READ_COMMANDS",
    "VERIFY_MODES",
    "classify_esptool_argv",
    "display_argv",
    "norm_name",
    "validate_after",
    "validate_baud",
    "validate_before",
    "validate_chip",
    "validate_connect_attempts",
    "validate_offset",
    "validate_no_stub",
    "validate_output_name",
    "validate_size",
    "validate_verify",
]
