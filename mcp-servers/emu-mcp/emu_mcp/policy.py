"""emu-mcp 안전 정책: 에뮬레이터 argv 분류기 ``classify_emu_argv`` 와 게이트 분류(``emu.start``·``emu.write``).

- ``emu_start`` = MODIFY ``emu.start`` (호스트에서 확보한 펌웨어를 실행하는 프로세스 시작 — 휘발성, 기기 미접촉). ``rt().authorize`` 를 거친다.
- ``emu_write`` = INTERACT ``emu.write`` (에뮬레이션된 장치에만 영향 — 늘 허용, 감사에 남는다. 원문·다이제스트 없이 바이트 수만).
- argv 허용 목록 위반은 DESTRUCTIVE ``emu.argv.*`` 로 분류하고, 서버는 게이트에 넘기지 않고 승인 경로 없이 거부한다
  (``{ok: false, status: "denied", gate: {via: "emu-policy", rule_id, reason}}``). 정상 경로에서는 늘 통과한다 — 걸리면 서버 버그다.

분류기는 서버가 실제로 실행할 argv 를 그대로 검사한다:
1. 금지 토큰을 독립적으로 훑는다(설계 §5.5 — 규칙 id 가 구체적이다). QEMU 는 ``--opt`` 를 ``-opt`` 와 같게 받으므로 맞춰서 본다.
   모든 토큰에서 ``mon:``·``mux=on`` 을 찾는다. ``-no-user-config``·``-nodefaults`` 가 빠지면 ``emu.argv.config``.
2. 실행 파일: 절대 경로이고 basename 이 허용 목록(qemu-system-xtensa·qemu-system-riscv32·pweh_avr_run)과 정확히 같아야 한다.
3. 고정 템플릿(순서·값) 문법 — 벗어난 모든 토큰·순서는 ``emu.argv.unexpected``.
4. ``expected`` 를 주면(서버는 계획에서 다시 만든 argv 를 준다) 정확히 같아야 한다.
"""

from __future__ import annotations

import os
import re
from typing import Sequence

from pweh.safety import Classification, Risk

from . import backends as B

RULE_START = "emu.start"
RULE_WRITE = "emu.write"
RULE_MONITOR = "emu.argv.monitor"
RULE_GDB = "emu.argv.gdb"
RULE_NETWORK = "emu.argv.network"
RULE_SEMIHOSTING = "emu.argv.semihosting"
RULE_HOST_FILE = "emu.argv.host-file"
RULE_DEVICE = "emu.argv.device"
RULE_CONFIG = "emu.argv.config"
RULE_DETACH = "emu.argv.detach"
RULE_EXE = "emu.argv.exe"
RULE_UNEXPECTED = "emu.argv.unexpected"
RULE_AVR_INPUT = "emu.argv.avr-input"
RULE_AVR_TARGET = "emu.argv.avr-target"

ARGV_RULES = (RULE_MONITOR, RULE_GDB, RULE_NETWORK, RULE_SEMIHOSTING, RULE_HOST_FILE, RULE_DEVICE, RULE_CONFIG, RULE_DETACH,
              RULE_EXE, RULE_UNEXPECTED, RULE_AVR_INPUT, RULE_AVR_TARGET)

_REASON = {
    RULE_MONITOR: "QEMU 모니터(HMP/QMP)·다중화 콘솔 — 모니터는 호스트 명령 실행(migrate exec:)·파일 쓰기로 이어진다",
    RULE_GDB: "gdbstub — QEMU gdbstub 의 qRcmd 는 HMP 다(아무 클라이언트나 모니터 명령)",
    RULE_NETWORK: "네트워크 장치·백엔드(slirp 는 LAN·인터넷·호스트 루프백에 닿는다)",
    RULE_SEMIHOSTING: "semihosting — 게스트가 호스트 파일 open/read/write·system() 을 부를 수 있다",
    RULE_HOST_FILE: "허용 형태 밖의 호스트 파일·문자 장치·로그·추적 옵션",
    RULE_DEVICE: "장치·객체·플러그인·허용 밖의 -global·-machine 속성·-display",
    RULE_CONFIG: "설정 파일 읽기(-readconfig·-set) 또는 -no-user-config·-nodefaults 빠짐",
    RULE_DETACH: "프로세스 그룹 밖으로 나가거나 권한을 바꾸는 옵션(-daemonize·-runas·-run-with)",
    RULE_EXE: "실행 파일이 절대 경로가 아니거나 basename 이 허용 목록 밖",
    RULE_UNEXPECTED: "서버의 고정 템플릿과 다른 토큰·순서",
    RULE_AVR_INPUT: "AVR 입력이 봉인한 memfd(--hex-fd N)가 아님(파일 경로·ELF 등)",
    RULE_AVR_TARGET: "허용 밖의 AVR MCU·주파수·USART",
}

#: 값 없이 그 자체로 금지인 QEMU 옵션 → 규칙 id
_QEMU_FORBIDDEN: dict[str, str] = {
    **{o: RULE_MONITOR for o in ("-mon", "-qmp", "-qmp-pretty", "-nographic", "-S", "-preconfig", "-qtest", "-qtest-log")},
    **{o: RULE_GDB for o in ("-gdb", "-s")},
    **{o: RULE_NETWORK for o in ("-netdev", "-net", "-vnc", "-spice", "-incoming")},
    **{o: RULE_SEMIHOSTING for o in ("-semihosting", "-semihosting-config")},
    **{o: RULE_HOST_FILE for o in (
        "-blockdev", "-mtdblock", "-sd", "-pflash", "-hda", "-hdb", "-hdc", "-hdd", "-cdrom", "-fda", "-fdb", "-bios", "-kernel",
        "-initrd", "-dtb", "-append", "-L", "-option-rom", "-fw_cfg", "-smbios", "-acpitable", "-boot", "-mem-path", "-D", "-d",
        "-dfilter", "-trace", "-pidfile", "-dump-vmstate", "-perfmap", "-jitdump", "-audiodev", "-tpmdev")},
    # -curses·-sdl 은 -display curses·sdl 의 옛 이름, -usb·-usbdevice 는 장치를 만든다
    **{o: RULE_DEVICE for o in ("-device", "-object", "-virtfs", "-fsdev", "-plugin", "-add-fd", "-curses", "-sdl", "-usb",
                                "-usbdevice")},
    **{o: RULE_CONFIG for o in ("-readconfig", "-set", "-writeconfig")},
    # -chroot 는 -run-with chroot= 의 옛 이름
    **{o: RULE_DETACH for o in ("-daemonize", "-runas", "-run-with", "-chroot")},
}
_DRIVE_FLASH_RX = re.compile(r"^file=/proc/self/fd/(\d{1,4}),if=mtd,format=raw$")
_DRIVE_EFUSE_RX = re.compile(r"^file=/proc/self/fd/(\d{1,4}),if=none,format=raw,id=efuse$")
_CHIP_ALT = "|".join(re.escape(c) for c in B.CHIP_NAMES)
_GLOBAL_ALLOWED_RX = (
    re.compile(rf"^driver=nvram\.(?:{_CHIP_ALT})\.efuse,property=drive,value=efuse$"),
    re.compile(rf"^driver=timer\.(?:{_CHIP_ALT})\.timg,property=wdt_disable,value=true$"),
    re.compile(r"^driver=ssi_psram,property=is_octal,value=true$"),
)
_MEM_RX = re.compile(r"^(\d{1,3})M$")
_AVR_OPTS_WITH_VALUE = ("--mcu", "--freq", "--uart", "--hex-fd")
_AVR_FLAGS = ("--realtime",)


def classify_start(summary: str) -> Classification:
    return Classification(Risk.MODIFY, RULE_START, "호스트에서 확보한 펌웨어를 실행하는 에뮬레이터 프로세스 시작 (휘발성, 기기 미접촉)",
                          matched=summary)


def classify_write(nbytes: int, printable: bool) -> Classification:
    return Classification(Risk.INTERACT, RULE_WRITE, "에뮬레이터 콘솔 입력 (에뮬레이션된 장치에만 영향)",
                          matched=f"{int(nbytes)} 바이트{'' if printable else ' (제어 문자 포함)'}")


def _deny(rule: str, token: str | None = None, detail: str | None = None) -> Classification:
    reason = _REASON[rule] + (f" — {detail}" if detail else "")
    return Classification(Risk.DESTRUCTIVE, rule, reason, matched=None if token is None else str(token)[:120])


def _ok(argv: Sequence[str]) -> Classification:
    return Classification(Risk.MODIFY, RULE_START, "서버의 고정 템플릿과 같은 에뮬레이터 argv", matched=os.path.basename(str(argv[0])))


def _norm_opt(tok: str) -> str:
    """QEMU 는 '--opt' 를 '-opt' 와 같게 받는다."""
    return tok[1:] if tok.startswith("--") and len(tok) > 2 else tok


def _scan_qemu(argv: Sequence[str]) -> Classification | None:
    toks = [str(t) for t in argv[1:]]
    for t in toks:
        if "mon:" in t or "mux=on" in t:
            return _deny(RULE_MONITOR, t)
    norm = [_norm_opt(t) for t in toks]
    for i, t in enumerate(norm):
        if not t.startswith("-"):
            continue
        nxt = toks[i + 1] if i + 1 < len(toks) else None
        rule = _QEMU_FORBIDDEN.get(t)
        if rule is not None:
            return _deny(rule, toks[i])
        if t == "-monitor" and nxt != "none":
            return _deny(RULE_MONITOR, toks[i], "값이 none 이 아님")
        if t == "-nic" and nxt != "none":
            return _deny(RULE_NETWORK, toks[i], "값이 none 이 아님")
        if t == "-display" and nxt != "none":
            return _deny(RULE_DEVICE, toks[i], "값이 none 이 아님")
        if t in ("-serial", "-parallel", "-debugcon") and nxt != "stdio":
            return _deny(RULE_HOST_FILE, toks[i], "값이 stdio 가 아님")
        if t == "-chardev":
            return _deny(RULE_HOST_FILE, toks[i])
        if t == "-drive" and (nxt is None or not (_DRIVE_FLASH_RX.match(nxt) or _DRIVE_EFUSE_RX.match(nxt))):
            return _deny(RULE_HOST_FILE, toks[i], "허용 형태(file=/proc/self/fd/N,…,format=raw) 밖의 -drive")
        if t == "-global" and (nxt is None or not any(rx.match(nxt) for rx in _GLOBAL_ALLOWED_RX)):
            return _deny(RULE_DEVICE, toks[i], "허용한 세 형태 밖의 -global")
        if t in ("-machine", "-M") and (nxt is None or "," in nxt or "=" in nxt):
            return _deny(RULE_DEVICE, toks[i], "-machine 속성")
        if t == "-icount" and nxt is not None and "rr" in nxt:
            return _deny(RULE_HOST_FILE, toks[i], "기록·재생(rr)")
    return None


def _missing_defaults(argv: Sequence[str]) -> Classification | None:
    norm = [_norm_opt(str(t)) for t in argv[1:]]
    if "-no-user-config" not in norm or "-nodefaults" not in norm:
        return _deny(RULE_CONFIG, None, "-no-user-config·-nodefaults 가 모두 있어야 한다")
    return None


def _qemu_grammar(argv: Sequence[str]) -> str | None:
    """고정 템플릿과 맞는지 (맞으면 None, 아니면 이유). 순서: 설계 §5.2."""
    exe = os.path.basename(str(argv[0]))
    toks = [str(t) for t in argv[1:]]
    pos = 0

    def take(expected: str) -> bool:
        nonlocal pos
        if pos < len(toks) and toks[pos] == expected:
            pos += 1
            return True
        return False

    for tok in ("-no-user-config", "-nodefaults", "-machine"):
        if not take(tok):
            return f"{pos + 1}번째 토큰이 {tok} 이 아님"
    if pos >= len(toks):
        return "-machine 값 없음"
    machine = toks[pos]
    spec = B.CHIPS.get(machine)
    if spec is None or spec.machine != machine or spec.exe != exe:
        return f"머신 {machine!r} 이 실행 파일 {exe} 과 맞지 않음"
    pos += 1
    for tok in ("-accel", "tcg,tb-size=64", "-display", "none", "-monitor", "none", "-nic", "none", "-serial", "stdio", "-drive"):
        if not take(tok):
            return f"{pos + 1}번째 토큰이 {tok} 이 아님"
    m = _DRIVE_FLASH_RX.match(toks[pos]) if pos < len(toks) else None
    if not m:
        return "플래시 -drive 형태가 아님"
    flash_fd = int(m.group(1))
    pos += 1
    if not take("-drive"):
        return "eFuse -drive 가 없음"
    m = _DRIVE_EFUSE_RX.match(toks[pos]) if pos < len(toks) else None
    if not m:
        return "eFuse -drive 형태가 아님"
    efuse_fd = int(m.group(1))
    pos += 1
    if flash_fd < 3 or efuse_fd < 3 or flash_fd == efuse_fd:
        return "memfd 번호가 잘못됨"
    if not (take("-global") and take(B.global_efuse(machine))):
        return "eFuse -global 이 없거나 칩과 맞지 않음"
    if pos + 1 < len(toks) and toks[pos] == "-global" and toks[pos + 1] == B.global_wdt(machine):
        pos += 2
    mem = None
    if pos + 1 < len(toks) and toks[pos] == "-m":
        mm = _MEM_RX.match(toks[pos + 1])
        if not mm:
            return "-m 값 형태가 아님"
        mem = int(mm.group(1))
        pos += 2
    octal = False
    if pos + 1 < len(toks) and toks[pos] == "-global" and toks[pos + 1] == B.GLOBAL_OCTAL:
        octal = True
        pos += 2
    if mem is not None:
        allowed = spec.octal_sizes if octal else spec.quad_sizes
        if mem not in allowed:
            return f"PSRAM {mem}M 은 {machine} {'octal' if octal else 'quad'} 에서 허용되지 않음"
    elif octal:
        return "octal PSRAM 인데 -m 이 없음"
    if not take("-snapshot"):
        return "-snapshot 이 없거나 자리가 다름"
    take("-no-reboot")
    if pos != len(toks):
        return f"템플릿 밖의 토큰 {toks[pos]!r}"
    return None


def _classify_qemu(argv: Sequence[str], expected: Sequence[str] | None) -> Classification:
    exe = str(argv[0])
    if not os.path.isabs(exe) or os.path.basename(exe) not in B.QEMU_EXES:
        return _deny(RULE_EXE, os.path.basename(exe))
    hit = _missing_defaults(argv)
    if hit is not None:
        return hit
    why = _qemu_grammar(argv)
    if why is not None:
        return _deny(RULE_UNEXPECTED, None, why)
    if expected is not None and list(map(str, argv)) != list(map(str, expected)):
        return _deny(RULE_UNEXPECTED, None, "계획에서 다시 만든 argv 와 다름")
    return _ok(argv)


def _classify_avr(argv: Sequence[str], expected: Sequence[str] | None) -> Classification:
    toks = [str(t) for t in argv[1:]]
    vals: dict[str, str] = {}
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in _AVR_FLAGS:
            vals[t] = ""
            i += 1
            continue
        if t in _AVR_OPTS_WITH_VALUE:
            if i + 1 >= len(toks):
                return _deny(RULE_AVR_INPUT if t == "--hex-fd" else RULE_AVR_TARGET, t, "값 없음")
            if t in vals:
                return _deny(RULE_UNEXPECTED, t, "옵션이 두 번")
            vals[t] = toks[i + 1]
            i += 2
            continue
        if t.startswith("-"):
            return _deny(RULE_UNEXPECTED, t, "실행기 허용 옵션 밖")
        return _deny(RULE_AVR_INPUT, t, "파일 경로 입력(봉인한 memfd 만 받는다)")
    hexfd = vals.get("--hex-fd")
    if hexfd is None or not re.fullmatch(r"\d{1,4}", hexfd) or int(hexfd) < 3:
        return _deny(RULE_AVR_INPUT, hexfd, "--hex-fd N(N ≥ 3) 이 아님")
    mcu = B.MCUS.get(vals.get("--mcu", ""))
    if mcu is None:
        return _deny(RULE_AVR_TARGET, vals.get("--mcu"), "MCU 허용 목록 밖")
    freq = vals.get("--freq", "")
    if not re.fullmatch(r"\d{1,9}", freq) or not (B.FREQ_MIN_HZ <= int(freq) <= B.FREQ_MAX_HZ):
        return _deny(RULE_AVR_TARGET, freq, "주파수 범위 밖")
    uart = vals.get("--uart", "")
    if not re.fullmatch(r"\d", uart) or int(uart) not in mcu.uarts:
        return _deny(RULE_AVR_TARGET, uart, f"{mcu.name} 에 없는 USART")
    exe = str(argv[0])
    if not os.path.isabs(exe) or os.path.basename(exe) != B.EXE_AVR:
        return _deny(RULE_EXE, os.path.basename(exe))
    if "--realtime" not in vals:
        return _deny(RULE_UNEXPECTED, None, "--realtime 이 없음")
    template = [exe, "--mcu", mcu.name, "--freq", freq, "--uart", uart, "--realtime", "--hex-fd", hexfd]
    if list(map(str, argv)) != template:
        return _deny(RULE_UNEXPECTED, None, "순서나 값이 고정 템플릿과 다름")
    if expected is not None and list(map(str, argv)) != list(map(str, expected)):
        return _deny(RULE_UNEXPECTED, None, "계획에서 다시 만든 argv 와 다름")
    return _ok(argv)


def classify_emu_argv(argv: Sequence[str], expected: Sequence[str] | None = None) -> Classification:
    """에뮬레이터 argv 분류: 허용 템플릿이면 MODIFY ``emu.start``, 아니면 DESTRUCTIVE ``emu.argv.*`` (승인 경로 없음)."""
    if not argv:
        return _deny(RULE_EXE, None, "빈 argv")
    base = os.path.basename(str(argv[0]))
    if base == B.EXE_AVR:
        return _classify_avr(argv, expected)
    hit = _scan_qemu(argv)
    if hit is not None:
        return hit
    return _classify_qemu(argv, expected)


__all__ = [
    "ARGV_RULES",
    "RULE_AVR_INPUT",
    "RULE_AVR_TARGET",
    "RULE_CONFIG",
    "RULE_DETACH",
    "RULE_DEVICE",
    "RULE_EXE",
    "RULE_GDB",
    "RULE_HOST_FILE",
    "RULE_MONITOR",
    "RULE_NETWORK",
    "RULE_SEMIHOSTING",
    "RULE_START",
    "RULE_UNEXPECTED",
    "RULE_WRITE",
    "classify_emu_argv",
    "classify_start",
    "classify_write",
]
