"""sigrok-mcp 안전 정책: 드라이버 허용/거부 목록, 인자 검증, sigrok-cli argv 분류기.

이 서버는 **로직 애널라이저/오실로스코프의 수동(입력 전용) 캡처와 파일 디코딩 전용**이다.
sigrok(libsigrok)은 전원공급기·전자부하·신호발생기·릴레이처럼 대상 보드에 전압/전류/신호를
가할 수 있는 장치도 제어하므로, 그런 드라이버와 출력을 바꾸는 config 키는 무조건 거부한다.

- 거부 목록(DENY)은 설정으로도 풀 수 없다. 안전 게이트(approve 정책)로도 승인 불가 — 아예 게이트에 넘기지 않는다.
- 허용 목록(ALLOW)은 libsigrok 0.5.2 와 master 소스의 ``drvopts``(드라이버 기능: Logic analyzer /
  Oscilloscope) 를 기준으로 만들었다. 목록에 없는 드라이버는 실패-닫힘(fail closed)으로 거부하며,
  사람(운영자)이 ``pipeline-config.yaml`` 의 ``sigrok.capture_drivers_allow`` 에 추가해야만 쓸 수 있다.
- 캡처에 쓰는 config 키는 ``samplerate``, ``captureratio`` 뿐이다 (값은 항상 정수).

분류기 ``classify_sigrok_argv`` 는 실제로 실행할 argv 를 그대로 검사한다 (도구 인자가 아니라).
백그라운드 작업도 프로세스를 띄우기 직전에 같은 분류기로 다시 검사한다.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterable, Sequence

from pweh.errors import ValidationFailed
from pweh.safety import Classification, Risk

# ---------------------------------------------------------------------------
# 드라이버 목록
# ---------------------------------------------------------------------------

#: 출력(구동) 가능 장치 — 항상 거부. 키: ``sigrok-cli -L`` 의 드라이버 이름(디렉터리 별칭 포함).
#: 출처: libsigrok 0.5.2 / master ``src/hardware/*/api.c`` 의 drvopts(SR_CONF_POWER_SUPPLY,
#: SR_CONF_ELECTRONIC_LOAD, SR_CONF_SIGNAL_GENERATOR, SR_CONF_MULTIPLEXER) 와 출력 키(enabled,
#: voltage_target, current_limit, output_frequency, amplitude, power_off 등) grep.
OUTPUT_CAPABLE_DRIVERS: dict[str, str] = {
    # 전원공급기
    "atten-pps3203": "전원공급기(PSU)",
    "atten-pps3xxx": "전원공급기(PSU)",
    "conrad-digi-35-cpu": "전원공급기(PSU)",
    "gwinstek-gpd": "전원공급기(PSU)",
    "gwinstek-psp": "전원공급기(PSU)",
    "hpib-pps": "전원공급기(PSU, HP-IB)",
    "korad-kaxxxxp": "전원공급기(PSU)",
    "manson-hcs-3xxx": "전원공급기(PSU)",
    "motech-lps-301": "전원공급기(PSU)",
    "motech-lps-30x": "전원공급기(PSU)",
    "rdtech-dps": "전원공급기(PSU)",
    "rdtech-rd": "전원공급기(PSU)",
    "scpi-pps": "전원공급기(PSU, SCPI)",
    # 전자부하
    "arachnid-labs-re-load-pro": "전자부하",
    "atorch": "전자부하",
    "itech-it8500": "전자부하",
    "maynuo-m97": "전자부하",
    "siglent-sdl10x0": "전자부하",
    "zketech-ebd-usb": "전자부하",
    # 신호발생기
    "juntek-jds6600": "신호발생기",
    "rigol-dg": "신호발생기",
    "rohde-schwarz-sme-0x": "신호발생기",
    # 릴레이/멀티플렉서 (회로 개폐)
    "dcttech-usbrelay": "USB 릴레이(회로 개폐)",
    "devantech-eth008": "이더넷 릴레이(회로 개폐)",
    "hp-59306a": "릴레이 액추에이터/멀티플렉서",
    "icstation-usbrelay": "USB 릴레이(회로 개폐)",
    # 대상 전원 제어
    "baylibre-acme": "프로브가 DUT 전원을 끊고 복구할 수 있는 전력 측정기(power_off)",
}

#: 캡처 허용 드라이버 (드라이버 기능이 Logic analyzer / Oscilloscope 인 것 + demo).
CAPTURE_ALLOWED_DRIVERS: dict[str, str] = {
    "demo": "데모 드라이버(가상 장치, 테스트용)",
    # 로직 애널라이저 (0.5.2)
    "fx2lafw": "FX2 기반 저가 LA (Saleae Logic 클론 24MHz 8CH, USBee 클론 등)",
    "dreamsourcelab-dslogic": "DreamSourceLab DSLogic",
    "saleae-logic16": "Saleae Logic16",
    "saleae-logic-pro": "Saleae Logic Pro 8/16",
    "ols": "Openbench Logic Sniffer / SUMP 호환 (시리얼 conn 필요)",
    "p-ols": "Pipistrello OLS",
    "asix-sigma": "ASIX SIGMA/SIGMA2",
    "beaglelogic": "BeagleLogic",
    "chronovu-la": "ChronoVu LA8/LA16",
    "hantek-4032l": "Hantek 4032L",
    "ikalogic-scanalogic2": "IKALOGIC Scanalogic-2",
    "ikalogic-scanaplus": "IKALOGIC ScanaPLUS",
    "ipdbg-la": "IPDBG LA (FPGA 내장 LA)",
    "lecroy-logicstudio": "LeCroy LogicStudio",
    "link-mso19": "Link Instruments MSO-19",
    "microchip-pickit2": "Microchip PICkit2 (LA 모드, 외부 Vdd 가정 — 드라이버가 Vdd 를 공급하지 않음)",
    "sysclk-lwla": "Sysclk LWLA",
    "sysclk-sla5032": "Sysclk SLA5032",
    "zeroplus-logic-cube": "ZEROPLUS Logic Cube",
    # 로직 애널라이저 (master/nightly 전용)
    "asix-omega-rtm-cli": "ASIX OMEGA (RTM CLI)",
    "greatfet": "GreatFET (LA 모드)",
    "raspberrypi-pico": "Raspberry Pi Pico (sigrok-pico 펌웨어)",
    "kingst-la2016": "Kingst LA1010/LA2016 — 보조 PWM 출력이 있으나 이 서버는 PWM 채널 그룹/키를 절대 보내지 않음(열 때 기본 비활성)",
    # 오실로스코프 (측정 전용으로만 사용)
    "gwinstek-gds-800": "GW Instek GDS-800 오실로스코프",
    "hameg-hmo": "Hameg/R&S HMO 오실로스코프",
    "hantek-6xxx": "Hantek 6xxx USB 오실로스코프",
    "hantek-dso": "Hantek DSO",
    "hung-chang-dso-2100": "Hung-Chang DSO-2100",
    "lecroy-xstream": "LeCroy X-Stream 오실로스코프",
    "rigol-ds": "Rigol DS 오실로스코프",
    "siglent-sds": "Siglent SDS 오실로스코프",
    "yokogawa-dlm": "Yokogawa DL/DLM 오실로스코프",
}

#: 측정 전용 LA 이지만 기본 허용 목록에서 뺀 드라이버 — 운영자가 ``sigrok.capture_drivers_allow`` 에 넣어야만 쓸 수 있다.
#: ftdi-la 는 제품 문자열 확인 없이 범용 FTDI VID/PID(FT232R 0403:6001, FT2232H 6010, FT4232H 6011, FT232H 6014)만으로
#: 장치를 잡고(libsigrok 0.5.2/master src/hardware/ftdi-la/api.c), 열 때 커널 ftdi_sio 를 떼고 모든 핀을 bitbang 입력으로
#: 바꾼다. 하드웨어 분석 작업대에서는 같은 칩을 쓰는 USB-UART 어댑터(대상 콘솔)·FT2232H JTAG 어댑터·JTAGulator(FT232RL,
#: DTR 이 Propeller 리셋 → VADJ 꺼짐)가 먼저 잡힐 수 있어, '입력 전용 캡처(OBSERVE)' 라는 분류와 실제 영향이 다르다.
SHARED_ADAPTER_DRIVERS: dict[str, str] = {
    "ftdi-la": (
        "범용 FTDI 칩(FT232R/FT2232H/FT4232H/FT232H)을 VID/PID 만으로 잡는 드라이버 — 같은 칩을 쓰는 USB-UART 어댑터(대상 콘솔)·"
        "JTAG 어댑터·JTAGulator 를 LA 로 열어 커널 드라이버를 떼고 핀을 bitbang 입력으로 바꿀 수 있어 기본 허용하지 않음 "
        "(전용 FTDI LA 보드만 연결된 환경이면 운영자가 sigrok.capture_drivers_allow 에 추가)"
    ),
}

#: 캡처 argv 에 허용되는 config 키(``--config=k=v``). 값은 정수만.
CAPTURE_CONFIG_KEYS = frozenset({"samplerate", "captureratio"})

#: 출력/상태를 바꾸는 키 (거부 사유 메시지용; allowlist 정책이라 어차피 모두 거부됨)
OUTPUT_CONFIG_KEYS = frozenset({
    "voltage_target", "current_limit", "enabled", "channel_config", "ovp_enabled", "ovp_threshold",
    "ocp_enabled", "ocp_threshold", "otp", "uvc", "uvc_threshold", "regulation", "output_frequency",
    "output_frequency_target", "amplitude", "offset", "power_off", "datalog", "power_target",
    "resistance_target", "phase", "duty_cycle", "pattern",
})

DRIVER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
# conn: 콜론/쉼표/등호/공백 금지 (sigrok-cli 가 ':' 로 드라이버 옵션을 나누므로 주입 방지)
CONN_RE = re.compile(r"^[A-Za-z0-9_./+-]{1,128}$")
USB_CONN_RE = re.compile(r"^(?:\d{1,3}\.\d{1,3}|[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})$")
CHANNEL_NAME_RE = re.compile(r"^[A-Za-z0-9_.]{1,32}$")
CHANNEL_RANGE_RE = re.compile(r"^(\d{1,3})-(\d{1,3})$")
RENAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
TRIGGER_MATCH_RE = re.compile(r"^[01rfeou]{1,16}$")
OUTPUT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")

MAX_SAMPLERATE_HZ = 10_000_000_000  # 10 GHz
MAX_DURATION_MS = 6 * 3600 * 1000
MAX_SAMPLES = 100_000_000_000
MAX_CHANNELS = 64


@dataclass
class DriverPolicy:
    """설정 확장(``sigrok.capture_drivers_allow/deny``)을 반영한 드라이버 정책."""

    extra_allow: frozenset[str] = frozenset()
    extra_deny: frozenset[str] = frozenset()

    @classmethod
    def from_config_raw(cls, raw: dict[str, Any] | None) -> "DriverPolicy":
        sec = (raw or {}).get("sigrok") or {}
        if not isinstance(sec, dict):
            return cls()

        def names(key: str) -> frozenset[str]:
            vals = sec.get(key) or []
            if isinstance(vals, str):
                vals = [vals]
            out = set()
            for v in vals if isinstance(vals, (list, tuple)) else []:
                v = str(v).strip().lower()
                if DRIVER_RE.match(v):
                    out.add(v)
            return frozenset(out)

        return cls(extra_allow=names("capture_drivers_allow"), extra_deny=names("capture_drivers_deny"))

    def deny_reason(self, driver: str) -> str | None:
        if driver in OUTPUT_CAPABLE_DRIVERS:
            return OUTPUT_CAPABLE_DRIVERS[driver]
        if driver in self.extra_deny:
            return "운영자 설정(sigrok.capture_drivers_deny)으로 금지된 드라이버"
        return None

    def is_allowed(self, driver: str) -> bool:
        if self.deny_reason(driver):
            return False
        return driver in CAPTURE_ALLOWED_DRIVERS or driver in self.extra_allow

    def describe(self, driver: str) -> dict[str, Any]:
        reason = self.deny_reason(driver)
        if reason:
            return {"capture_allowed": False, "output_capable": driver in OUTPUT_CAPABLE_DRIVERS, "policy": "denied", "reason": reason}
        if driver in CAPTURE_ALLOWED_DRIVERS:
            return {"capture_allowed": True, "output_capable": False, "policy": "allowed", "note": CAPTURE_ALLOWED_DRIVERS[driver]}
        if driver in self.extra_allow:
            return {"capture_allowed": True, "output_capable": False, "policy": "allowed-by-config"}
        return {
            "capture_allowed": False,
            "output_capable": False if driver in SHARED_ADAPTER_DRIVERS else None,
            "policy": "not-allowlisted",
            "reason": self.not_allowed_reason(driver),
        }

    def not_allowed_reason(self, driver: str) -> str:
        """허용 목록에 없는 드라이버의 거부 사유 (기본 제외 드라이버는 구체적인 사유)."""
        return SHARED_ADAPTER_DRIVERS.get(
            driver, "로직 애널라이저/오실로스코프 허용 목록에 없음 (운영자가 sigrok.capture_drivers_allow 에 추가해야 사용 가능)"
        )


# ---------------------------------------------------------------------------
# 값 검증
# ---------------------------------------------------------------------------

_RATE_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([kKmMgG]?)\s*(?:[hH][zZ])?\s*$")
_RATE_MULT = {"": 1, "k": 10**3, "m": 10**6, "g": 10**9}


def parse_samplerate(value: str | int | float) -> int:
    """'1m', '24MHz', '500k', '1.5 MHz', 1000000 → 정수 Hz.

    sigrok 관례대로 소문자 m 도 mega 이다. sigrok-cli 0.7.2 의 ``sr_parse_sizestring`` 은 '1.5m' 를 1 Hz 로
    잘못 해석하므로(소수부 버그) 이 서버는 항상 Python 에서 정수 Hz 로 바꿔 넘긴다.
    """
    if isinstance(value, bool):
        raise ValidationFailed(f"samplerate 형식이 잘못되었습니다: {value!r}")
    if isinstance(value, int):
        hz = Decimal(value)
    elif isinstance(value, float):
        hz = Decimal(str(value))
    else:
        m = _RATE_RE.match(str(value))
        if not m:
            raise ValidationFailed(
                f"samplerate 형식을 해석할 수 없습니다: {value!r}",
                hint="예: '1m'(=1 MHz), '24MHz', '500k', '2000000'. 소문자 m 도 MHz 이다.",
            )
        try:
            hz = Decimal(m.group(1)) * _RATE_MULT[m.group(2).lower()]
        except InvalidOperation:
            raise ValidationFailed(f"samplerate 형식을 해석할 수 없습니다: {value!r}")
    if hz != hz.to_integral_value():
        raise ValidationFailed(f"samplerate 는 정수 Hz 여야 합니다: {value!r} → {hz} Hz")
    out = int(hz)
    if out < 1 or out > MAX_SAMPLERATE_HZ:
        raise ValidationFailed(f"samplerate 범위를 벗어났습니다: {out} Hz (1 Hz ~ {MAX_SAMPLERATE_HZ} Hz)")
    return out


def validate_driver(driver: Any) -> str:
    d = str(driver or "").strip()
    if not DRIVER_RE.match(d):
        raise ValidationFailed(
            f"잘못된 드라이버 이름: {driver!r}",
            hint="sigrok_list(kind='drivers') 의 이름(소문자/숫자/하이픈)만 사용. 드라이버 옵션은 conn 인자로만 지정.",
        )
    return d


def validate_conn(conn: Any) -> str | None:
    if conn is None or conn == "":
        return None
    c = str(conn).strip()
    if not CONN_RE.match(c):
        raise ValidationFailed(
            f"잘못된 conn 값: {conn!r}",
            hint="USB 'bus.address'(예 1.6) / 'VID.PID'(예 0925.3881), 시리얼 '/dev/ttyACM0', 네트워크 'tcp-raw/host/port'. ':' ',' '=' 공백 금지.",
        )
    return c


def conn_kind(conn: str | None) -> str:
    """'none' | 'usb' | 'serial' | 'network'."""
    if not conn:
        return "none"
    if USB_CONN_RE.match(conn):
        return "usb"
    if conn.startswith("/dev/") or re.match(r"^(tty|cu\.)", conn) or re.match(r"^COM\d+$", conn, re.I):
        return "serial"
    return "network"


def validate_duration_ms(value: Any) -> int | None:
    if value is None:
        return None
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise ValidationFailed(f"duration_ms 는 정수(ms)여야 합니다: {value!r}")
    if isinstance(value, float) and value != v:
        raise ValidationFailed(f"duration_ms 는 정수(ms)여야 합니다: {value!r}")
    if v < 1 or v > MAX_DURATION_MS:
        raise ValidationFailed(f"duration_ms 범위를 벗어났습니다: {v} (1 ~ {MAX_DURATION_MS})")
    return v


def validate_samples(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            v = parse_samplerate(value)  # 같은 접미사 규칙(k/m/g)
        except ValidationFailed:
            raise ValidationFailed(f"samples 형식이 잘못되었습니다: {value!r}", hint="정수 또는 '2m'(=2,000,000) 형식")
    else:
        try:
            v = int(value)
        except (TypeError, ValueError):
            raise ValidationFailed(f"samples 는 정수여야 합니다: {value!r}")
    if v < 1 or v > MAX_SAMPLES:
        raise ValidationFailed(f"samples 범위를 벗어났습니다: {v}")
    return v


def validate_capture_ratio(value: Any) -> int | None:
    if value is None:
        return None
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise ValidationFailed(f"capture_ratio 는 0~100 정수(%)여야 합니다: {value!r}")
    if not 0 <= v <= 100:
        raise ValidationFailed(f"capture_ratio 는 0~100 정수(%)여야 합니다: {v}")
    return v


@dataclass
class ChannelSelection:
    tokens: list[str] = field(default_factory=list)  # sigrok -C 토큰 (예 'D0=RX', 'D1')
    final_names: list[str] = field(default_factory=list)  # rename 반영 후 이름
    source_names: list[str] = field(default_factory=list)  # 장치 원래 이름(범위 토큰은 펼침)
    warnings: list[str] = field(default_factory=list)

    @property
    def arg(self) -> str:
        return ",".join(self.tokens)


def _split_list(value: Any, what: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        items = [x.strip() for x in value.split(",")]
    elif isinstance(value, (list, tuple)):
        items = []
        for x in value:
            if not isinstance(x, (str, int)) or isinstance(x, bool):
                raise ValidationFailed(f"{what} 항목은 문자열이어야 합니다: {x!r}")
            items.append(str(x).strip())
    else:
        raise ValidationFailed(f"{what} 은 문자열 또는 문자열 목록이어야 합니다: {value!r}")
    if any(not x for x in items):
        raise ValidationFailed(f"{what} 에 빈 항목이 있습니다: {value!r}")
    return items


def validate_channels(value: Any) -> ChannelSelection | None:
    """채널 선택/이름 바꾸기. 항목: 'D0', 'D0=RX', 숫자 이름 범위 '0-7'."""
    items = _split_list(value, "channels")
    if not items:
        return None
    if len(items) > MAX_CHANNELS:
        raise ValidationFailed(f"채널이 너무 많습니다 ({len(items)} > {MAX_CHANNELS})")
    sel = ChannelSelection()
    seen_final: set[str] = set()
    for it in items:
        if "=" in it:
            src, _, new = it.partition("=")
            if not CHANNEL_NAME_RE.match(src) or not RENAME_RE.match(new):
                raise ValidationFailed(
                    f"잘못된 채널 rename 항목: {it!r}",
                    hint="'D0=RX' 형식. 원래 이름은 영문/숫자/_/. , 새 이름은 영문으로 시작하는 영문/숫자/_ (최대 32자).",
                )
            sel.tokens.append(f"{src}={new}")
            sel.source_names.append(src)
            final = new
            names = [final]
        else:
            rm = CHANNEL_RANGE_RE.match(it)
            if rm:
                a, b = int(rm.group(1)), int(rm.group(2))
                if a >= b:
                    raise ValidationFailed(f"잘못된 채널 범위: {it!r} (시작 < 끝)")
                sel.tokens.append(it)
                names = [str(i) for i in range(a, b + 1)]
                sel.source_names.extend(names)
                sel.warnings.append(f"범위 '{it}' 는 채널 이름이 숫자인 장치에서만 동작한다 (fx2lafw 는 D0..D7 이므로 나열해야 함).")
            elif CHANNEL_NAME_RE.match(it):
                sel.tokens.append(it)
                sel.source_names.append(it)
                names = [it]
            else:
                raise ValidationFailed(
                    f"잘못된 채널 이름: {it!r}",
                    hint="장치의 채널 이름(sigrok_scan 결과, 예 D0, D1 또는 0, 1)을 쉼표 없이 목록으로 전달. '-' 는 숫자 범위에만 사용.",
                )
        for n in names:
            if n in seen_final:
                raise ValidationFailed(f"채널 이름이 중복됩니다: {n!r}")
            seen_final.add(n)
            sel.final_names.append(n)
    # 비연속/앞쪽이 아닌 선택 경고 (드라이버에 따라 .sr 의 비트 위치와 probeN 이 어긋날 수 있음)
    pat = [re.match(r"^([A-Za-z]*)(\d+)$", s) for s in sel.source_names]
    if all(pat) and len({m.group(1) for m in pat}) == 1:  # type: ignore[union-attr]
        idx = sorted(int(m.group(2)) for m in pat)  # type: ignore[union-attr]
        if idx != list(range(idx[0], idx[0] + len(idx))) or idx[0] not in (0, 1):
            sel.warnings.append(
                "선택한 채널이 0번부터 연속이 아니다. 일부 드라이버(demo 등)는 비연속 선택 시 .sr 의 비트 위치가 probeN 과 "
                "어긋날 수 있으므로, 가능하면 앞쪽 채널부터 연속으로(예 D0..D3) 선택하고 이름만 바꾸는 것을 권장한다."
            )
    return sel


def validate_triggers(value: Any, channels: ChannelSelection | None) -> str | None:
    """트리거 '<채널>=<문자열>[,...]'. 문자: 0 1 r f e o u (n 번째 문자 = n 번째 스테이지)."""
    if value is None:
        return None
    if isinstance(value, dict):
        items = [f"{k}={v}" for k, v in value.items()]
    else:
        items = _split_list(value, "triggers")
    if not items:
        return None
    out = []
    seen = set()
    for it in items:
        name, sep, match = it.partition("=")
        name, match = name.strip(), match.strip()
        if not sep or not CHANNEL_NAME_RE.match(name) or not TRIGGER_MATCH_RE.match(match):
            raise ValidationFailed(
                f"잘못된 트리거 항목: {it!r}",
                hint="'RX=f' 형식. 문자: 0(low) 1(high) r(상승) f(하강) e(양쪽 에지) o/u(아날로그). n 번째 문자는 n 번째 스테이지.",
            )
        if channels is not None and name not in channels.final_names:
            raise ValidationFailed(
                f"트리거 채널 {name!r} 이 선택한 채널 목록에 없습니다: {channels.final_names}",
                hint="채널을 rename 했다면 새 이름으로 지정해야 한다 (sigrok-cli 규칙).",
            )
        if name in seen:
            raise ValidationFailed(f"트리거 채널이 중복됩니다: {name!r}")
        seen.add(name)
        out.append(f"{name}={match}")
    return ",".join(out)


def validate_output_name(value: Any) -> str | None:
    if value is None or value == "":
        return None
    name = str(value).strip()
    for ext in (".sr", ".srzip"):
        if name.lower().endswith(ext):
            name = name[: -len(ext)]
    if not OUTPUT_NAME_RE.match(name) or ".." in name:
        raise ValidationFailed(
            f"잘못된 output_name: {value!r}",
            hint="영문/숫자/._- 만 사용 (최대 80자, 경로 구분자 금지). 확장자 .sr 은 자동으로 붙는다.",
        )
    return name


# ---------------------------------------------------------------------------
# argv 분류기
# ---------------------------------------------------------------------------

#: 분류기가 인식하는 sigrok-cli 롱 옵션 (우리는 항상 '--name=value' 형식으로만 조립한다)
_VALUE_OPTS = {
    "driver", "config", "channels", "triggers", "samples", "time", "output-file", "output-format",
    "input-file", "input-format", "protocol-decoders", "protocol-decoder-annotations", "loglevel",
}
_FLAG_OPTS = {"version", "list-supported", "scan", "show", "dont-scan", "protocol-decoder-samplenum"}
#: 이 서버가 절대 쓰지 않는 옵션 (상태 변경, 무한 캡처, 채널 그룹 설정 등)
_FORBIDDEN_OPTS = {
    "set": "장치 옵션 설정(--set) 금지",
    "get": "장치 옵션 조회(--get)는 이 서버 범위 밖",
    "continuous": "무한 캡처(--continuous) 금지 — 항상 유한 캡처",
    "frames": "--frames 는 사용하지 않음",
    "channel-group": "채널 그룹 지정(-g) 금지 (출력 채널 그룹 설정 경로 차단)",
    "transform-module": "변환 모듈 금지",
    "wait-trigger": "--wait-trigger 는 사용하지 않음",
    "protocol-decoder-binary": "바이너리 출력은 사용하지 않음",
    "protocol-decoder-meta": "메타 출력은 사용하지 않음",
    "protocol-decoder-jsontrace": "jsontrace 는 이스케이프 결함으로 사용하지 않음",
    "list-serial": "--list-serial 은 사용하지 않음",
    "list-supported-wiki": "사용하지 않음",
}


def _refuse(rule: str, reason: str, matched: str, details: Iterable[str] = ()) -> Classification:
    return Classification(Risk.DESTRUCTIVE, rule, reason, matched=matched, details=tuple(details))


def parse_argv(argv: Sequence[str]) -> tuple[list[tuple[str, str | None]], list[str]]:
    """argv[1:] 를 [(name, value|None)] 로. 인식할 수 없는 토큰 목록도 반환."""
    opts: list[tuple[str, str | None]] = []
    bad: list[str] = []
    for tok in list(argv)[1:]:
        if not isinstance(tok, str) or not tok.startswith("--") or "\x00" in tok or "\n" in tok or "\r" in tok:
            bad.append(str(tok))
            continue
        body = tok[2:]
        if "=" in body:
            name, _, val = body.partition("=")
            opts.append((name, val))
        else:
            opts.append((body, None))
    return opts, bad


def classify_sigrok_argv(
    argv: Sequence[str],
    *,
    policy: DriverPolicy | None = None,
    allowed_output_dir: str | os.PathLike[str] | None = None,
) -> Classification:
    """실행할 sigrok-cli argv 의 위험도 분류.

    - 장치를 건드리지 않는 명령(버전/목록/디코더 정보/파일 디코드·변환): OBSERVE ``sigrok.offline``
    - 허용 목록 드라이버의 스캔/정보/캡처: OBSERVE (USB 또는 conn 없음) / INTERACT (시리얼·네트워크 conn:
      드라이버가 식별 바이트를 그 포트로 보냄)
    - 그 밖의 모든 것(출력 장치, 허용 목록 밖 드라이버, 금지 옵션, 허용 밖 config 키, 케이스 밖 출력 경로,
      해석 불가 토큰): DESTRUCTIVE 로 분류 → 호출자는 게이트에 넘기지 않고 즉시 거부해야 한다.
    """
    policy = policy or DriverPolicy()
    shown = " ".join(str(a) for a in argv)
    opts, bad = parse_argv(argv)
    if bad:
        return _refuse("sigrok.argv.unparsed", "해석할 수 없는 인자(이 서버는 --name=value 형식만 생성)", shown, bad)
    names = [n for n, _ in opts]
    for n, _v in opts:
        if n in _FORBIDDEN_OPTS:
            return _refuse(f"sigrok.forbidden.{n}", _FORBIDDEN_OPTS[n], shown)
        if n not in _VALUE_OPTS and n not in _FLAG_OPTS:
            return _refuse("sigrok.argv.unknown_option", f"알 수 없는 옵션 --{n}", shown)
        if n in _VALUE_OPTS and _v is None:
            return _refuse("sigrok.argv.missing_value", f"--{n} 에 값이 없음", shown)
        if n in _FLAG_OPTS and _v is not None:
            return _refuse("sigrok.argv.flag_value", f"--{n} 은 값을 받지 않음", shown)
    single = {"driver", "channels", "triggers", "samples", "time", "output-file", "output-format", "input-file",
              "input-format", "protocol-decoder-annotations", "loglevel"}
    for n in single:
        if names.count(n) > 1:
            return _refuse("sigrok.argv.duplicate", f"--{n} 중복", shown)
    vals = {n: v for n, v in opts}
    loglevel = vals.get("loglevel")
    if loglevel is not None and loglevel not in ("0", "1", "2"):
        return _refuse("sigrok.argv.loglevel", "loglevel 은 0~2 만 허용(출력 형식 고정)", shown)

    driver_spec = vals.get("driver")
    acquires = any(n in names for n in ("samples", "time"))
    touches = driver_spec is not None or acquires or "scan" in names or ("show" in names and "protocol-decoders" not in names and "input-file" not in names and "input-format" not in names and "output-format" not in names)

    if not touches:
        if "output-file" in vals and allowed_output_dir is not None and not _within(vals["output-file"] or "", allowed_output_dir):
            return _refuse("sigrok.output.outside_case", "출력 파일이 케이스 디렉터리 밖", shown)
        if "config" in names or "triggers" in names or ("channels" in names and "input-file" not in names):
            return _refuse("sigrok.argv.config_without_driver", "드라이버 없는 장치 옵션", shown)
        return Classification(Risk.OBSERVE, "sigrok.offline", "sigrok-cli 오프라인 명령(장치 미접촉)", matched=shown)

    # --- 장치를 건드리는 명령 ---
    if driver_spec is None and "scan" in names and not acquires and not (
        set(names) & {"config", "channels", "triggers", "output-file", "output-format", "show", "input-file", "protocol-decoders", "dont-scan"}
    ):
        # 드라이버 미지정 전체 스캔: 각 드라이버가 USB 등에서 식별만 수행 (시리얼 드라이버는 conn 없이는 포트를 열지 않음)
        return Classification(Risk.OBSERVE, "sigrok.scan.all", "모든 드라이버로 연결된 장치 식별 스캔 (읽기 전용)", matched=shown)
    if driver_spec is None:
        return _refuse(
            "sigrok.driver.missing",
            "드라이버 미지정 장치 명령 금지 (sigrok-cli 가 스캔된 장치를 자동 선택 — 전원공급기 등 출력 장치가 선택될 위험)",
            shown,
        )
    if "input-file" in names or "protocol-decoders" in names:
        return _refuse("sigrok.argv.mixed", "캡처와 파일 입력/디코더를 한 명령에 섞지 않음", shown)
    parts = driver_spec.split(":")
    drv = parts[0]
    if not DRIVER_RE.match(drv):
        return _refuse("sigrok.driver.invalid", f"잘못된 드라이버 이름 {drv!r}", shown)
    deny = policy.deny_reason(drv)
    if deny:
        return _refuse(
            "sigrok.driver.output_capable",
            f"출력(구동) 가능 장치 드라이버 '{drv}' ({deny}) — 대상에 전압/전류/신호를 가할 수 있어 이 서버는 다루지 않음",
            shown,
        )
    if not policy.is_allowed(drv):
        return _refuse(
            "sigrok.driver.not_allowlisted",
            f"드라이버 '{drv}' 는 캡처 허용 목록에 없음: {policy.not_allowed_reason(drv)}",
            shown,
        )
    conn = None
    for p in parts[1:]:
        k, sep, v = p.partition("=")
        if k != "conn" or not sep or conn is not None:
            return _refuse("sigrok.driver.option", f"드라이버 옵션은 conn 하나만 허용 (받은 값: {p!r})", shown)
        if not CONN_RE.match(v):
            return _refuse("sigrok.driver.conn", f"잘못된 conn 값 {v!r}", shown)
        conn = v
    for n, v in opts:
        if n != "config":
            continue
        for item in (v or "").split(":"):
            k, sep, val = item.partition("=")
            if k not in CAPTURE_CONFIG_KEYS:
                why = "출력/상태를 바꾸는 키" if k in OUTPUT_CONFIG_KEYS else "허용되지 않은 config 키"
                return _refuse("sigrok.config.key", f"{why}: {k!r} (허용: {sorted(CAPTURE_CONFIG_KEYS)})", shown)
            if not sep or not val.isdigit():
                return _refuse("sigrok.config.value", f"config 값은 정수만 허용: {item!r}", shown)
    for n in ("samples", "time"):
        if n in vals and not (vals[n] or "").isdigit():
            return _refuse("sigrok.limit.value", f"--{n} 값은 정수만 허용", shown)
    if acquires:
        if vals.get("output-format") != "srzip" or not vals.get("output-file"):
            return _refuse("sigrok.output.format", "캡처는 반드시 srzip 파일(--output-file, --output-format=srzip)로 저장", shown)
        if allowed_output_dir is not None and not _within(vals["output-file"] or "", allowed_output_dir):
            return _refuse("sigrok.output.outside_case", "캡처 출력 파일이 케이스 signals 디렉터리 밖", shown)
    elif "output-file" in vals or "config" in names or "triggers" in names:
        return _refuse("sigrok.argv.no_limit", "샘플/시간 제한 없는 캡처 옵션", shown)

    kind = conn_kind(conn)
    action = "캡처" if acquires else ("스캔" if "scan" in names else "장치 정보 조회")
    if kind in ("serial", "network"):
        return Classification(
            Risk.INTERACT,
            f"sigrok.{('capture' if acquires else 'probe')}.{kind}_conn",
            f"로직 애널라이저 {action} (conn={conn}: 드라이버가 이 포트/주소로 식별 질의를 보냄 — 대상 콘솔 포트가 아닌지 확인 필요)",
            matched=shown,
        )
    return Classification(
        Risk.OBSERVE,
        "sigrok.capture" if acquires else "sigrok.probe",
        f"로직 애널라이저 {action} (입력 전용, 대상에 신호를 가하지 않음)",
        matched=shown,
    )


def _within(path: str, base: str | os.PathLike[str]) -> bool:
    try:
        Path(path).resolve().relative_to(Path(base).resolve())
        return True
    except (ValueError, OSError):
        return False


def device_users(dev_path: str, limit_pids: int = 20000) -> list[int]:
    """해당 장치 파일(예 /dev/ttyUSB0)을 열고 있는 다른 프로세스 PID 목록 (Linux /proc 기반, 최선 노력)."""
    try:
        target = os.path.realpath(dev_path)
    except OSError:
        return []
    me = os.getpid()
    users: list[int] = []
    proc = Path("/proc")
    if not proc.is_dir():
        return []
    n = 0
    for p in proc.iterdir():
        if not p.name.isdigit():
            continue
        n += 1
        if n > limit_pids:
            break
        pid = int(p.name)
        if pid == me:
            continue
        try:
            for fd in (p / "fd").iterdir():
                try:
                    if os.readlink(fd) == target:
                        users.append(pid)
                        break
                except OSError:
                    continue
        except OSError:
            continue
    return users
