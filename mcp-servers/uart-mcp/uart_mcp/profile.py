"""pipeline-config.yaml 프로필의 ``uart.*`` 값을 컴파일한 콘솔 프로필.

프로필 정규식은 수신 버퍼의 "마지막 줄"(줄바꿈 뒤 미완성 줄)에 대해 검사한다 (설정 파일 주석 참고).
프로필에 값이 없으면 generic-ipcam 과 같은 내장 기본값을 쓴다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from pweh.config import PwehConfig
from pweh.errors import ConfigError

from .textutil import normalize_line_ending

# 내장 기본값 (orchestrator/pipeline-config.yaml 의 generic-ipcam 과 같은 값; 설정 파일이 없을 때 사용)
DEFAULT_UART: dict[str, Any] = {
    "line_ending": "\r",
    "framing": "8N1",
    "uboot_prompts": [
        r"^(hisilicon|goke|xmedia|SigmaStar|MStar|GM|A320|OpenIPC) ?# ?$",
        r"^isvp(_t\w+)?# ?$",
        r"^nvt@\w+: ?$",
        r"^amboot> ?$",
        r"^=> ?$",
        r"^U-Boot ?> ?$",
        r"^[A-Za-z][A-Za-z0-9_.@-]{1,31} ?# ?$",
        r"^[A-Za-z][A-Za-z0-9_.@-]{1,31} ?> ?$",
    ],
    "hush_ps2_prompts": [r"^ ?> ?$"],
    "linux_shell_prompts": [r"(^|[\s:/~\]])[#$] ?$"],
    "login_prompts": [r"(?i)login: ?$"],
    "password_prompts": [r"(?i)password: ?$"],
    "autoboot_patterns": [
        r"Hit any key to stop autoboot",
        r"Hit key to stop autoboot\('CTRL\+C'\)",
        r"(?i)press ctrl-?c to (stop|abort) autoboot",
        r"(?i)press enter to interrupt boot",
        r"(?i)autoboot in \d+ seconds",
        r"(?i)press .{0,20}(key|ctrl).{0,30}(stop|abort|interrupt)",
    ],
    "interrupt_sequences": ["\x03"],
    "autoboot_silent": False,
    "interrupt_window_s": 30,
    "boot_markers": {
        "uboot": [r"U-Boot \d{4}\.\d{2}", r"U-Boot SPL", r"DRAM:", r"Check spi flash controller", r"Check Flash Memory Controller", r"SF: Detected"],
        "kernel": [r"Starting kernel", r"Uncompressing Linux", r"Linux version \d", r"## Booting kernel from Legacy Image"],
        "userspace": [r"Freeing unused kernel memory", r"Please press Enter to activate this console", r"BusyBox v"],
        "flash_write_warning": [r"Saving Environment to", r"Erasing SPI flash", r"Write default environment to flash", r"RECOVERY: kernel/rootfs invalid"],
    },
}

# U-Boot 줄 버퍼(CONFIG_SYS_CBSIZE) − 2 를 넘으면 문자가 버려져 분류한 줄과 다른 줄이 실행된다.
# 카메라 SDK CBSIZE 는 256~1024 → 가장 작은 값 기준으로 보수적으로 제한한다.
DEFAULT_UBOOT_MAX_LINE = 250
# BusyBox lineedit MAX_LINELEN 기본 1024
DEFAULT_LINUX_MAX_LINE = 1000


def _compile_list(values: Any, key: str, profile: str) -> list[re.Pattern[str]]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    out = []
    for v in values:
        try:
            out.append(re.compile(str(v)))
        except re.error as exc:
            raise ConfigError(f"프로필 {profile} 의 uart.{key} 정규식 오류: {v!r}: {exc}")
    return out


@dataclass
class ConsoleProfile:
    name: str
    line_ending: str
    framing: str
    uboot_prompts: list[re.Pattern[str]]
    hush_ps2: list[re.Pattern[str]]
    linux_prompts: list[re.Pattern[str]]
    login_prompts: list[re.Pattern[str]]
    password_prompts: list[re.Pattern[str]]
    autoboot: list[re.Pattern[str]]
    interrupt_sequences: list[str]
    autoboot_silent: bool
    interrupt_window_s: float
    markers: dict[str, list[re.Pattern[str]]]
    baud_candidates: list[int]
    uboot_max_line: int = DEFAULT_UBOOT_MAX_LINE
    linux_max_line: int = DEFAULT_LINUX_MAX_LINE
    vendor: str | None = None
    soc_family: str | None = None
    flash: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "vendor": self.vendor,
            "soc_family": self.soc_family,
            "line_ending": self.line_ending,
            "interrupt_sequences": list(self.interrupt_sequences),
            "autoboot_silent": self.autoboot_silent,
            "baud_candidates": list(self.baud_candidates),
        }


def build_profile(name: str, prof: dict[str, Any], baud_candidates: list[int] | None = None) -> ConsoleProfile:
    uart = dict(DEFAULT_UART)
    uart.update({k: v for k, v in (prof.get("uart") or {}).items() if v is not None})
    markers_cfg = dict(DEFAULT_UART["boot_markers"])
    markers_cfg.update((prof.get("uart") or {}).get("boot_markers") or {})
    seqs = uart.get("interrupt_sequences") or ["\x03"]
    if isinstance(seqs, str):
        seqs = [seqs]
    try:
        le = normalize_line_ending(uart.get("line_ending") or "\r")
    except Exception:
        le = "\r"
    return ConsoleProfile(
        name=name,
        line_ending=le,
        framing=str(uart.get("framing") or "8N1"),
        uboot_prompts=_compile_list(uart.get("uboot_prompts"), "uboot_prompts", name),
        hush_ps2=_compile_list(uart.get("hush_ps2_prompts"), "hush_ps2_prompts", name),
        linux_prompts=_compile_list(uart.get("linux_shell_prompts"), "linux_shell_prompts", name),
        login_prompts=_compile_list(uart.get("login_prompts"), "login_prompts", name),
        password_prompts=_compile_list(uart.get("password_prompts"), "password_prompts", name),
        autoboot=_compile_list(uart.get("autoboot_patterns"), "autoboot_patterns", name),
        interrupt_sequences=[str(s) for s in seqs if str(s)],
        autoboot_silent=bool(uart.get("autoboot_silent", False)),
        interrupt_window_s=float(uart.get("interrupt_window_s") or 30),
        markers={k: _compile_list(v, f"boot_markers.{k}", name) for k, v in markers_cfg.items()},
        baud_candidates=[int(b) for b in (baud_candidates or uart.get("baud_candidates") or [115200])],
        uboot_max_line=int(uart.get("uboot_max_line") or DEFAULT_UBOOT_MAX_LINE),
        linux_max_line=int(uart.get("linux_max_line") or DEFAULT_LINUX_MAX_LINE),
        vendor=prof.get("vendor"),
        soc_family=prof.get("soc_family"),
        flash=dict(prof.get("flash") or {}),
        raw=prof,
    )


def load_profile(config: PwehConfig, name: str | None) -> ConsoleProfile:
    """설정의 프로필(extends 해석)을 콘솔 프로필로 컴파일. 없는 이름이면 ConfigError."""
    prof = config.profile(name)
    real = prof.get("name") or name or "generic-ipcam"
    return build_profile(real, prof, config.baud_candidates(real))
