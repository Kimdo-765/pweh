"""emu-mcp 백엔드: 칩·보드·MCU 표, 실행 파일 찾기, 버전·머신 조회(shim 아래, 캐시), argv 조립, rlimit, 종료 분류.

- ``esp-qemu``: Espressif QEMU ``esp_develop_9.2.2_20260417`` (결정 D9 — 정확히 이 버전만). 머신 esp32·esp32s3(qemu-system-xtensa),
  esp32c3(qemu-system-riscv32). 서버가 만드는 고정 argv 만 실행한다(에이전트 인자 통과 0, 설계 §5.2).
- ``avr-simavr``: PWEH 가 소유한 C 실행기 ``pweh_avr_run``(simavr 고정 커밋을 정적 링크). 입력은 봉인한 memfd 의 Intel HEX(``--hex-fd``,
  결정 D7). qemu-system-avr 는 쓰지 않는다(결정 D10).
- 실행 파일은 설정(``tools.qemu_xtensa``·``tools.qemu_riscv32``·``tools.avr_run``) → 환경 변수(``PWEH_QEMU_XTENSA``·``PWEH_QEMU_RISCV32``·
  ``PWEH_AVR_RUN``) → 도구 디렉터리의 고정 상대 경로 순으로 찾는다(``pweh.toolsdir.emu_binary_candidates``). 값은 절대 경로여야 하고
  basename 이 허용 목록(qemu-system-xtensa·qemu-system-riscv32·pweh_avr_run)과 정확히 같아야 한다. PATH 이름 찾기는 하지 않는다
  (배포판 QEMU 를 잘못 잡지 않게).

이 모듈은 ``pweh.console``·``pweh.safety.redact`` 를 import 하지 않는다(정책·이미지 시험이 서버 없이 돈다).
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import signal
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from pweh.errors import PwehError, ToolMissing

from . import limits

log = logging.getLogger("pweh.emu")

ESP_BACKEND = "esp-qemu"
AVR_BACKEND = "avr-simavr"
BACKENDS = (ESP_BACKEND, AVR_BACKEND)

EXE_XTENSA = "qemu-system-xtensa"
EXE_RISCV32 = "qemu-system-riscv32"
EXE_AVR = "pweh_avr_run"
#: 실행 파일 basename 허용 목록 (설정 값의 basename 이 정확히 이것이어야 한다)
EXE_BASENAMES = (EXE_XTENSA, EXE_RISCV32, EXE_AVR)
QEMU_EXES = (EXE_XTENSA, EXE_RISCV32)

#: 설정 키(pipeline-config.yaml tools.*)와 환경 변수
CONFIG_KEYS: Mapping[str, str] = {EXE_XTENSA: "qemu_xtensa", EXE_RISCV32: "qemu_riscv32", EXE_AVR: "avr_run"}
ENV_KEYS: Mapping[str, str] = {EXE_XTENSA: "PWEH_QEMU_XTENSA", EXE_RISCV32: "PWEH_QEMU_RISCV32", EXE_AVR: "PWEH_AVR_RUN"}

#: 고정 QEMU 버전 (``-no-user-config -nodefaults -version`` 의 정확한 첫 줄 — 다르면 emu_tool_version)
QEMU_VERSION_LINE = "QEMU emulator version 9.2.2 (esp_develop_9.2.2_20260417)"
#: simavr 고정 커밋 (pweh_avr_run --version 이 보여야 한다)
SIMAVR_COMMIT = "5b08da60497f7564f50941f74a549fe2851db030"
_AVR_VERSION_RX = re.compile(r"^pweh_avr_run (\S{1,40}) simavr ([0-9a-f]{40})$")
_AVR_SOURCE_VERSION_RX = re.compile(r'^#define\s+PWEH_AVR_RUN_VERSION\s+"([^"\s]{1,40})"', re.M)

#: 풀린 실행 파일의 참고 sha256 (다르면 경고만 — emu_status·emu_start)
PINNED_BINARY_SHA256: Mapping[str, str] = {
    EXE_XTENSA: "50813d894756c1448b8742e1d8db21e3cce0f4e85b56fe53e36760b941cb7f17",
    EXE_RISCV32: "834699a726720f5273b79bb1e8b3f735f6e0540f17fdf466dfd20055605f2b4d",
}
#: <bin>/../share/qemu 의 ROM 참고 sha256 (두 릴리스 모두 같은 네 파일을 담는다 — 다르거나 없으면 경고만)
PINNED_ROM_SHA256: Mapping[str, str] = {
    "esp32s3_rev0_rom.bin": "b5c7090cc22efce51c1323cef31ca96fcd673a5b1d1b1017e219d393f2659913",
    "esp32-v3-rom.bin": "9115bbcd03da9f54d3baca5ad94d588a43da54ed332347137ba3dc9010df258b",
    "esp32-v3-rom-app.bin": "6d3240e7cdb1ec9c1d683515e0a8578e9fb8ece3e7736cb9a996512c656e8442",
    "esp32c3-rom.bin": "0de1e65020e803bea0d7443dca149d61895e01fca3bb9c82d073234eebd73f99",
}

REPO_ROOT = Path(__file__).resolve().parents[3]
AVR_RUNNER_SOURCE = REPO_ROOT / "native" / "emu" / "pweh_avr_run.c"
SHIM_PATH = Path(__file__).resolve().with_name("_exec_shim.py")

#: 자식 환경의 고정 값 (TMPDIR·HOME 은 세션마다 정한다). 이 밖의 변수는 넘기지 않는다.
BASE_ENV: Mapping[str, str] = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
ENV_KEYS_CHILD = ("PATH", "LANG", "LC_ALL", "TMPDIR", "HOME")


# ---------------------------------------------------------------------------
# 표
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChipSpec:
    name: str
    exe: str
    machine: str
    chip_id: int  # 2단계 부트로더 이미지 헤더의 chip_id
    boot_offset: int  # 2단계 부트로더 위치
    efuse_driver: str
    efuse_size: int
    wdt_driver: str
    psram_modes: tuple[str, ...]
    quad_sizes: tuple[int, ...]
    octal_sizes: tuple[int, ...]
    vcpus: int


CHIPS: Mapping[str, ChipSpec] = {
    "esp32": ChipSpec("esp32", EXE_XTENSA, "esp32", 0, 0x1000, "nvram.esp32.efuse", 124, "timer.esp32.timg",
                      ("none", "quad"), (2, 4), (), 2),
    "esp32s3": ChipSpec("esp32s3", EXE_XTENSA, "esp32s3", 9, 0x0, "nvram.esp32s3.efuse", 1024, "timer.esp32s3.timg",
                        ("none", "quad", "octal"), (2, 4, 8, 16, 32), (4, 8, 16, 32), 2),
    "esp32c3": ChipSpec("esp32c3", EXE_RISCV32, "esp32c3", 5, 0x0, "nvram.esp32c3.efuse", 1024, "timer.esp32c3.timg",
                        ("none",), (), (), 1),
}
CHIP_NAMES = tuple(CHIPS)
#: 지원하지 않는 Espressif 칩 (chip_id → 이름) — emu_unsupported_chip
UNSUPPORTED_CHIP_IDS: Mapping[int, str] = {2: "ESP32-S2", 12: "ESP32-C2", 13: "ESP32-C6", 16: "ESP32-H2", 18: "ESP32-P4",
                                            20: "ESP32-C61", 23: "ESP32-C5"}
PSRAM_MODES = ("auto", "none", "quad", "octal")
WATCHDOG_MODES = ("disabled", "emulated")
ON_RESET_MODES = ("exit", "reboot")


@dataclass(frozen=True)
class McuSpec:
    name: str
    flash_size: int  # FLASHEND + 1
    eeprom_size: int
    uarts: tuple[int, ...]  # 있는 USART 번호
    default_uart: int


MCUS: Mapping[str, McuSpec] = {
    "atmega8": McuSpec("atmega8", 8 * 1024, 512, (0,), 0),
    "atmega168": McuSpec("atmega168", 16 * 1024, 512, (0,), 0),
    "atmega328p": McuSpec("atmega328p", 32 * 1024, 1024, (0,), 0),
    "atmega32u4": McuSpec("atmega32u4", 32 * 1024, 1024, (1,), 1),
    "atmega644p": McuSpec("atmega644p", 64 * 1024, 2048, (0, 1), 0),
    "atmega1280": McuSpec("atmega1280", 128 * 1024, 4096, (0, 1, 2, 3), 0),
    "atmega1284p": McuSpec("atmega1284p", 128 * 1024, 4096, (0, 1), 0),
    "atmega2560": McuSpec("atmega2560", 256 * 1024, 4096, (0, 1, 2, 3), 0),
}


@dataclass(frozen=True)
class BoardSpec:
    name: str
    mcu: str | None
    freq_hz: int | None
    uart: int | None
    note: str = ""


BOARDS: Mapping[str, BoardSpec] = {
    "uno": BoardSpec("uno", "atmega328p", 16_000_000, 0),
    "nano": BoardSpec("nano", "atmega328p", 16_000_000, 0, "옛 nano(ATmega168)는 board='custom', mcu='atmega168'"),
    "pro-mini-5v": BoardSpec("pro-mini-5v", "atmega328p", 16_000_000, 0),
    "pro-mini-3v3": BoardSpec("pro-mini-3v3", "atmega328p", 8_000_000, 0),
    "mega2560": BoardSpec("mega2560", "atmega2560", 16_000_000, 0),
    "leonardo": BoardSpec("leonardo", "atmega32u4", 16_000_000, 1, "Arduino Serial 은 USB CDC(에뮬레이션 안 됨) — Serial1(USART1)만 보인다"),
    "micro": BoardSpec("micro", "atmega32u4", 16_000_000, 1, "Arduino Serial 은 USB CDC(에뮬레이션 안 됨) — Serial1(USART1)만 보인다"),
    "custom": BoardSpec("custom", None, None, None, "mcu·freq_hz 필수"),
}
FREQ_MIN_HZ = 1_000_000
FREQ_MAX_HZ = 32_000_000


@dataclass(frozen=True)
class Target:
    """계획 결과 — argv 조립과 분류기가 같은 값을 쓴다."""

    backend: str  # esp-qemu | avr-simavr
    name: str  # esp32 | esp32s3 | esp32c3 | <board>
    machine: str | None = None  # QEMU -machine
    mcu: str | None = None
    freq_hz: int | None = None
    uart: int | None = None
    vcpus: int = 1
    psram: tuple[str, int | None] = ("none", None)  # (none|quad|octal, MiB)
    watchdog: str = "disabled"
    on_reset: str = "exit"
    handoff: str = "memfd"

    @property
    def exe_name(self) -> str:
        return CHIPS[self.name].exe if self.backend == ESP_BACKEND else EXE_AVR

    def public(self) -> dict[str, Any]:
        if self.backend == ESP_BACKEND:
            return {"chip": self.name, "machine": self.machine, "vcpus": self.vcpus}
        return {"board": self.name, "mcu": self.mcu, "freq_hz": self.freq_hz, "uart": self.uart, "vcpus": self.vcpus}


def esp_target(chip: str, *, psram: tuple[str, int | None] = ("none", None), watchdog: str = "disabled",
               on_reset: str = "exit") -> Target:
    spec = CHIPS[chip]
    return Target(ESP_BACKEND, chip, machine=spec.machine, vcpus=spec.vcpus, psram=psram, watchdog=watchdog, on_reset=on_reset)


def avr_target(board: str, mcu: str, freq_hz: int, uart: int) -> Target:
    return Target(AVR_BACKEND, board, mcu=mcu, freq_hz=int(freq_hz), uart=int(uart), vcpus=1)


# ---------------------------------------------------------------------------
# argv · 환경 · rlimit
# ---------------------------------------------------------------------------


def drive_flash(fd: int) -> str:
    return f"file=/proc/self/fd/{int(fd)},if=mtd,format=raw"


def drive_efuse(fd: int) -> str:
    return f"file=/proc/self/fd/{int(fd)},if=none,format=raw,id=efuse"


def global_efuse(chip: str) -> str:
    return f"driver={CHIPS[chip].efuse_driver},property=drive,value=efuse"


def global_wdt(chip: str) -> str:
    return f"driver={CHIPS[chip].wdt_driver},property=wdt_disable,value=true"


GLOBAL_OCTAL = "driver=ssi_psram,property=is_octal,value=true"


def build_esp_argv(exe: str, target: Target, flash_fd: int, efuse_fd: int) -> list[str]:
    """ESP QEMU 의 정확한 argv (설계 §5.2, 순서 고정). flash_fd·efuse_fd 는 봉인한 memfd 의 fd 번호(pass_fds 로 같은 번호가 넘어간다)."""
    chip = target.name
    spec = CHIPS[chip]
    argv = [exe, "-no-user-config", "-nodefaults", "-machine", spec.machine, "-accel", "tcg,tb-size=64",
            "-display", "none", "-monitor", "none", "-nic", "none", "-serial", "stdio",
            "-drive", drive_flash(flash_fd), "-drive", drive_efuse(efuse_fd), "-global", global_efuse(chip)]
    if target.watchdog == "disabled":
        argv += ["-global", global_wdt(chip)]
    mode, mb = target.psram
    if mode in ("quad", "octal") and mb:
        argv += ["-m", f"{int(mb)}M"]
        if mode == "octal":
            argv += ["-global", GLOBAL_OCTAL]
    argv += ["-snapshot"]
    if target.on_reset == "exit":
        argv += ["-no-reboot"]
    return argv


def build_avr_argv(exe: str, target: Target, hex_fd: int) -> list[str]:
    """AVR 실행기의 정확한 argv: ``<abs>/pweh_avr_run --mcu M --freq F --uart N --realtime --hex-fd H`` (--max-cycles 는 넣지 않는다)."""
    return [exe, "--mcu", str(target.mcu), "--freq", str(int(target.freq_hz or 0)), "--uart", str(int(target.uart or 0)),
            "--realtime", "--hex-fd", str(int(hex_fd))]


def build_argv(exe: str, target: Target, fds: Mapping[str, int]) -> list[str]:
    if target.backend == ESP_BACKEND:
        return build_esp_argv(exe, target, fds["flash"], fds["efuse"])
    return build_avr_argv(exe, target, fds["hex"])


def child_env(session_dir: str) -> dict[str, str]:
    """자식 환경: 정확히 PATH·LANG·LC_ALL·TMPDIR·HOME (TMPDIR 은 이미 있는 0700 절대 경로)."""
    return {**BASE_ENV, "TMPDIR": os.path.join(session_dir, "tmp"), "HOME": session_dir}


def rlimits(target: Target, timeout_s: int) -> dict[str, Any]:
    soft, hard = limits.rlimit_cpu(timeout_s, target.vcpus)
    if target.backend == ESP_BACKEND:
        return {"as": limits.RLIMIT_AS_QEMU, "cpu": [soft, hard], "core": limits.RLIMIT_CORE, "nofile": limits.RLIMIT_NOFILE,
                "fsize": limits.RLIMIT_FSIZE_QEMU}
    return {"as": limits.RLIMIT_AS_AVR, "cpu": [soft, hard], "core": limits.RLIMIT_CORE, "nofile": limits.RLIMIT_NOFILE,
            "fsize": limits.RLIMIT_FSIZE_AVR}


def shim_argv(argv: list[str], *, ppid: int, session_dir: str, status_fd: int, rl: Mapping[str, Any], netns: bool) -> list[str]:
    """``[python, -I, -S, <shim>, …, --, <에뮬레이터 argv>]`` (설계 §5.6)."""
    out = [sys.executable, "-I", "-S", str(SHIM_PATH), "--ppid", str(int(ppid)), "--session-dir", session_dir,
           "--status-fd", str(int(status_fd)), "--as", str(int(rl["as"])), "--cpu", str(int(rl["cpu"][0])),
           "--cpu-hard", str(int(rl["cpu"][1])), "--core", str(int(rl["core"])), "--nofile", str(int(rl["nofile"])),
           "--fsize", str(int(rl["fsize"]))]
    if netns:
        out.append("--netns")
    return out + ["--"] + list(argv)


def classify_exit(backend: str, returncode: int | None, stop_reason: str | None, *, on_reset: str = "exit") -> str:
    """종료 → stopped_by (설계 §4.1·§5.4). 서버가 이유를 먼저 기록하고 신호를 보냈으면 그 이유가 이긴다(rc 로는 '게스트 리셋'과
    '서버의 SIGTERM'을 가릴 수 없다 — 둘 다 rc 0)."""
    if stop_reason:
        return stop_reason
    if returncode is None:
        return "killed"
    if returncode < 0:
        sig = -returncode
        if sig == signal.SIGXCPU:
            return "rlimit-cpu"
        if sig == signal.SIGXFSZ:
            return "rlimit-fsize"
        return "killed"
    if backend == ESP_BACKEND:
        if returncode == 0:
            return "guest-reset" if on_reset == "exit" else "guest-exit"
        if returncode in (1, 2):
            return "config-error"
        return "guest-exit"
    if returncode == 0:
        return "guest-halt"
    if returncode in (1, 2):
        return "config-error"
    if returncode == 3:
        return "guest-crash"
    if returncode == 4:
        return "max-cycles"
    if returncode == 5:
        return "server-gone"
    return "guest-exit"


def exit_info(returncode: int | None) -> dict[str, Any] | None:
    if returncode is None:
        return None
    if returncode < 0:
        try:
            name = signal.Signals(-returncode).name
        except ValueError:
            name = None
        return {"code": None, "signal": -returncode, "signal_name": name}
    return {"code": returncode, "signal": None}


# ---------------------------------------------------------------------------
# 실행 파일 찾기
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BinaryInfo:
    name: str  # qemu-system-xtensa | qemu-system-riscv32 | pweh_avr_run
    path: str  # 설정된 절대 경로 (basename 허용 목록 검사 대상)
    realpath: str
    source: str  # config | env | pweh-tools
    size: int
    mtime_ns: int
    ino: int

    @property
    def cache_key(self) -> tuple[str, int, int, int]:
        return (self.path, self.size, self.mtime_ns, self.ino)


def _candidates(name: str, config: Any) -> list[tuple[str, str]]:
    from pweh import toolsdir

    configured = str((getattr(config, "tools", None) or {}).get(CONFIG_KEYS[name]) or "").strip()
    configured = os.path.expanduser(configured) if configured else ""
    env_value = (os.environ.get(ENV_KEYS[name]) or "").strip()
    return list(toolsdir.emu_binary_candidates(name, configured or None, env_value or None, toolsdir.tools_dir()))


def _check_candidate(name: str, path: str) -> tuple[BinaryInfo | None, str | None]:
    if not os.path.isabs(path):
        return None, "절대 경로가 아니다(PATH 이름 찾기는 하지 않는다)"
    if os.path.basename(path) != name:
        return None, f"실행 파일 이름이 {name} 이 아니다(basename 허용 목록)"
    try:
        st = os.stat(path)
    except OSError:
        return None, "파일이 없다"
    import stat as _stat

    if not _stat.S_ISREG(st.st_mode):
        return None, "일반 파일이 아니다"
    if not os.access(path, os.X_OK):
        return None, "실행 권한이 없다"
    return BinaryInfo(name, path, os.path.realpath(path), "", st.st_size, st.st_mtime_ns, st.st_ino), None


def locate(name: str, config: Any) -> tuple[BinaryInfo | None, list[dict[str, str]]]:
    """(첫 유효 후보 | None, 거른 후보와 이유). 파일이 있는지·이름·실행 권한을 본다(실행은 하지 않는다)."""
    rejected: list[dict[str, str]] = []
    for path, source in _candidates(name, config):
        info, why = _check_candidate(name, path)
        if info is not None:
            return BinaryInfo(info.name, info.path, info.realpath, source, info.size, info.mtime_ns, info.ino), rejected
        rejected.append({"path": path, "source": source, "reason": why or ""})
    return None, rejected


INSTALL_HINT = {
    EXE_XTENSA: "사람에게 `scripts/install.sh --only qemu_esp` 를 요청한다 (또는 PWEH_QEMU_XTENSA 에 절대 경로).",
    EXE_RISCV32: "사람에게 `scripts/install.sh --only qemu_esp` 를 요청한다 (또는 PWEH_QEMU_RISCV32 에 절대 경로).",
    EXE_AVR: "사람에게 `scripts/install.sh --only simavr` 를 요청한다 (C 컴파일러 또는 PWEH zig 필요, 또는 PWEH_AVR_RUN 에 절대 경로).",
}


def require_binary(name: str, config: Any) -> BinaryInfo:
    info, rejected = locate(name, config)
    if info is None:
        raise ToolMissing(f"{name} 을(를) 찾을 수 없습니다.", hint=INSTALL_HINT[name], data={"rejected": rejected})
    return info


# ---------------------------------------------------------------------------
# 조회 (shim 아래, 캐시)
# ---------------------------------------------------------------------------

_PROBE_CACHE: dict[tuple[str, int, int, int], dict[str, Any]] = {}
_PROBE_LOCK = threading.Lock()
_NETNS_STATE: dict[str, str] = {}  # {"netns": available|unavailable}
_NETNS_LOCK = threading.Lock()


def _run_probe(argv: list[str], rl: Mapping[str, Any]) -> tuple[int | None, str, str]:
    """shim(rlimit·PDEATHSIG·최소 환경) 아래에서 짧게 실행 → (rc, stdout, stderr). 표준 입력은 /dev/null."""
    cmd = [sys.executable, "-I", "-S", str(SHIM_PATH), "--ppid", str(os.getpid()), "--as", str(int(rl["as"])),
           "--cpu", str(int(rl["cpu"])), "--cpu-hard", str(int(rl["cpu"]) + 5), "--core", "0", "--nofile", str(limits.RLIMIT_NOFILE),
           "--fsize", str(1 << 20), "--"] + argv
    try:
        cp = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/",
                            env=dict(BASE_ENV), timeout=limits.PROBE_TIMEOUT_S, start_new_session=True, close_fds=True)
    except subprocess.TimeoutExpired:
        return None, "", "timeout"
    except OSError as exc:
        return None, "", f"{type(exc).__name__}: errno {exc.errno}"
    return cp.returncode, cp.stdout.decode("utf-8", "replace"), cp.stderr.decode("utf-8", "replace")


def _sha256_path(path: str | Path) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                b = f.read(1 << 20)
                if not b:
                    break
                h.update(b)
    except OSError:
        return None
    return h.hexdigest()


def _rom_report(binary: BinaryInfo) -> dict[str, Any]:
    rom_dir = Path(binary.realpath).parent.parent / "share" / "qemu"
    out: dict[str, Any] = {}
    for name, pinned in PINNED_ROM_SHA256.items():
        p = rom_dir / name
        actual = _sha256_path(p) if p.is_file() else None
        out[name] = {"present": actual is not None, "sha256": actual, "expected_sha256": pinned,
                     "sha256_ok": actual == pinned if actual else False}
    return out


def expected_avr_driver_version() -> str | None:
    """저장소 소스(native/emu/pweh_avr_run.c)의 PWEH_AVR_RUN_VERSION (없으면 None). 가짜 실행기 시험은 이 값을 --version 에 쓴다."""
    try:
        text = AVR_RUNNER_SOURCE.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = _AVR_SOURCE_VERSION_RX.search(text)
    return m.group(1) if m else None


def _probe_qemu(binary: BinaryInfo) -> dict[str, Any]:
    rl = {"as": limits.RLIMIT_AS_QEMU, "cpu": int(limits.PROBE_TIMEOUT_S) + 5}
    out: dict[str, Any] = {"path": binary.path, "realpath": binary.realpath, "source": binary.source,
                           "expected_version": QEMU_VERSION_LINE, "version": None, "version_ok": False, "machines": []}
    rc, so, se = _run_probe([binary.path, "-no-user-config", "-nodefaults", "-version"], rl)
    first = so.splitlines()[0].strip() if so.strip() else ""
    out["version"] = first[:200] or None
    out["version_ok"] = rc == 0 and first == QEMU_VERSION_LINE
    if rc != 0:
        out["error"] = f"-version 실패 (rc={rc})" + (" — 공유 라이브러리가 없을 수 있다(scripts/install.sh --only qemu_esp 의 안내)"
                                                       if rc in (126, 127) else "")
    rc2, so2, _se2 = _run_probe([binary.path, "-no-user-config", "-nodefaults", "-machine", "help"], rl)
    if rc2 == 0:
        machines = []
        for line in so2.splitlines()[1:]:
            tok = line.split(maxsplit=1)[0] if line.strip() else ""
            if tok and re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", tok):
                machines.append(tok)
        out["machines"] = machines
    pinned = PINNED_BINARY_SHA256.get(binary.name)
    actual = _sha256_path(binary.realpath)
    out["sha256"] = actual
    out["expected_sha256"] = pinned
    out["sha256_ok"] = bool(pinned and actual == pinned)
    out["roms"] = _rom_report(binary)
    return out


def _probe_avr(binary: BinaryInfo) -> dict[str, Any]:
    rl = {"as": limits.RLIMIT_AS_AVR, "cpu": int(limits.PROBE_TIMEOUT_S) + 5}
    out: dict[str, Any] = {"path": binary.path, "realpath": binary.realpath, "source": binary.source, "version": None,
                           "driver_version": None, "simavr_commit": None, "expected_commit": SIMAVR_COMMIT,
                           "expected_driver_version": expected_avr_driver_version(), "version_ok": False}
    rc, so, _se = _run_probe([binary.path, "--version"], rl)
    first = so.splitlines()[0].strip() if so.strip() else ""
    out["version"] = first[:200] or None
    m = _AVR_VERSION_RX.match(first)
    if rc == 0 and m:
        out["driver_version"], out["simavr_commit"] = m.group(1), m.group(2)
        out["version_ok"] = m.group(2) == SIMAVR_COMMIT
        exp = out["expected_driver_version"]
        if exp and m.group(1) != exp:
            out["warning"] = (f"pweh_avr_run 드라이버 버전 {m.group(1)} 이 저장소 소스({exp})와 다르다 — 사람에게 "
                              "`scripts/install.sh --force --only simavr` 재설치를 권한다")
    elif rc != 0:
        out["error"] = f"--version 실패 (rc={rc})"
    return out


def probe(binary: BinaryInfo) -> dict[str, Any]:
    """버전·머신 조회 (경로·크기·mtime·inode 로 캐시)."""
    with _PROBE_LOCK:
        hit = _PROBE_CACHE.get(binary.cache_key)
    if hit is not None:
        return dict(hit)
    res = _probe_qemu(binary) if binary.name in QEMU_EXES else _probe_avr(binary)
    with _PROBE_LOCK:
        _PROBE_CACHE[binary.cache_key] = res
    return dict(res)


def clear_probe_cache() -> None:
    with _PROBE_LOCK:
        _PROBE_CACHE.clear()
    with _NETNS_LOCK:
        _NETNS_STATE.clear()


def require_version(binary: BinaryInfo, chip: str | None = None) -> tuple[dict[str, Any], list[str]]:
    """고정 버전 확인 (다르면 emu_tool_version). 반환: (조회 결과, 경고 — 실행 파일·ROM sha256 불일치는 경고만)."""
    info = probe(binary)
    warnings: list[str] = []
    if binary.name in QEMU_EXES:
        if not info.get("version_ok"):
            raise PwehError(f"{binary.name} 이 고정 버전이 아닙니다 (기대: {QEMU_VERSION_LINE}).", code="emu_tool_version",
                            hint="사람에게 `scripts/install.sh --force --only qemu_esp` 재설치를 요청한다.",
                            data={"version": info.get("version"), "path": binary.path})
        if chip and info.get("machines") and CHIPS[chip].machine not in info["machines"]:
            raise PwehError(f"{binary.name} 의 머신 목록에 {CHIPS[chip].machine} 이 없습니다.", code="emu_tool_version",
                            hint="사람에게 `scripts/install.sh --force --only qemu_esp` 재설치를 요청한다.")
        if not info.get("sha256_ok"):
            warnings.append(f"binary_sha256_mismatch: {binary.name} 의 sha256 이 고정 릴리스 값과 다르다(경고만)")
        for rom, st in (info.get("roms") or {}).items():
            if not st.get("present"):
                warnings.append(f"rom_missing: <bin>/../share/qemu/{rom} 이 없다(경고만)")
            elif not st.get("sha256_ok"):
                warnings.append(f"rom_sha256_mismatch: {rom} 의 sha256 이 고정 값과 다르다(경고만)")
    else:
        if not info.get("version_ok"):
            raise PwehError(f"pweh_avr_run 이 고정 simavr 커밋({SIMAVR_COMMIT[:12]})으로 빌드한 것이 아닙니다.", code="emu_tool_version",
                            hint="사람에게 `scripts/install.sh --force --only simavr` 재설치를 요청한다.",
                            data={"version": info.get("version"), "path": binary.path})
        if info.get("warning"):
            warnings.append("avr_driver_version: " + str(info["warning"]))
    return info, warnings


def netns_state(refresh: bool = False) -> str:
    """빈 네트워크 네임스페이스 가용성: available | unavailable | unknown (shim --probe 로 한 번 확인하고 캐시)."""
    with _NETNS_LOCK:
        cur = _NETNS_STATE.get("netns")
    if cur and not refresh:
        return cur
    cmd = [sys.executable, "-I", "-S", str(SHIM_PATH), "--ppid", str(os.getpid()), "--probe", "--netns", "--"]
    try:
        cp = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd="/",
                            env=dict(BASE_ENV), timeout=limits.PROBE_TIMEOUT_S, start_new_session=True, close_fds=True)
        state = "available" if cp.returncode == 0 else ("unavailable" if cp.returncode == 94 else "unknown")
    except (OSError, subprocess.SubprocessError):
        state = "unknown"
    if state != "unknown":
        with _NETNS_LOCK:
            _NETNS_STATE["netns"] = state
    return state


def note_netns(state: str) -> None:
    """세션을 띄우며 알게 된 가용성(94 → unavailable)을 캐시에 반영."""
    if state in ("available", "unavailable"):
        with _NETNS_LOCK:
            _NETNS_STATE["netns"] = state


def core_pattern_piped() -> bool:
    """/proc/sys/kernel/core_pattern 이 파이프(|…)면 RLIMIT_CORE=0 이 지켜지지 않는다(core(5)) — 경고만(결정 D18)."""
    try:
        return Path("/proc/sys/kernel/core_pattern").read_text(encoding="ascii", errors="replace").lstrip().startswith("|")
    except OSError:
        return False


def backend_status(config: Any) -> dict[str, Any]:
    """emu_status 의 backends (게스트를 실행하지 않는다)."""
    esp: dict[str, Any] = {"available": False, "chips": list(CHIP_NAMES)}
    for key, name in (("xtensa", EXE_XTENSA), ("riscv32", EXE_RISCV32)):
        info, rejected = locate(name, config)
        if info is None:
            esp[key] = {"path": None, "source": None, "version": None, "expected_version": QEMU_VERSION_LINE, "version_ok": False,
                        "machines": [], "error": "실행 파일 없음", "rejected": rejected}
            continue
        esp[key] = probe(info)
    esp["available"] = bool(esp["xtensa"].get("version_ok") or esp["riscv32"].get("version_ok"))
    esp["chips_available"] = [c for c in CHIP_NAMES
                              if esp["xtensa" if CHIPS[c].exe == EXE_XTENSA else "riscv32"].get("version_ok")]
    avr: dict[str, Any] = {"available": False, "boards": list(BOARDS), "mcus": list(MCUS), "expected_commit": SIMAVR_COMMIT}
    info, rejected = locate(EXE_AVR, config)
    if info is None:
        avr.update({"path": None, "source": None, "version": None, "driver_version": None, "simavr_commit": None,
                    "version_ok": False, "error": "실행 파일 없음", "rejected": rejected})
    else:
        avr.update(probe(info))
    avr["available"] = bool(avr.get("version_ok"))
    return {ESP_BACKEND: esp, AVR_BACKEND: avr}


__all__ = [
    "AVR_BACKEND", "BOARDS", "BinaryInfo", "CHIPS", "CHIP_NAMES", "ESP_BACKEND", "EXE_AVR", "EXE_BASENAMES", "EXE_RISCV32",
    "EXE_XTENSA", "MCUS", "QEMU_VERSION_LINE", "SIMAVR_COMMIT", "Target", "avr_target", "backend_status", "build_argv",
    "build_avr_argv", "build_esp_argv", "child_env", "classify_exit", "core_pattern_piped", "esp_target", "exit_info",
    "expected_avr_driver_version", "locate", "netns_state", "probe", "require_binary", "require_version", "rlimits", "shim_argv",
]
