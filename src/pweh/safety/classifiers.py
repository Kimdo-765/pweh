"""콘솔/디버거 명령 위험도 분류기.

에이전트가 보내는 텍스트 명령(U-Boot, BusyBox/Linux 셸, OpenOCD TCL)을 정적으로 분석해
Risk 를 매긴다. 목적은 '협조적이지만 성급한' 에이전트의 실수로 기기를 벽돌로 만드는 일을
막는 것이며, 적대적 우회를 완벽히 막는 샌드박스가 아니다(docs/safety.md 참고).

보수적 원칙:
- 실제 실행될 내용을 확정할 수 없으면(변수/글롭이 명령 위치에 있음, eval/source, 줄 편집 키,
  알 수 없는 run 대상 등) DESTRUCTIVE + uncertain 으로 분류한다.
- 알 수 없는 명령은 설정값 unknown_command_risk(기본 MODIFY)로 분류한다.
- U-Boot 는 명령 약어(유일 접두어)를 허용하므로, 약어 후보 중 가장 위험한 것으로 분류한다.
- U-Boot 에서 빈 Enter 는 직전 명령을 반복하므로 직전 명령의 위험도를 상속한다.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from .risk import Classification, Risk, worst

O, I, M, D = Risk.OBSERVE, Risk.INTERACT, Risk.MODIFY, Risk.DESTRUCTIVE

# ---------------------------------------------------------------------------
# 공통 유틸
# ---------------------------------------------------------------------------


def _risk_from_setting(value: str | Risk | None) -> Risk:
    if value is None:
        return M
    if isinstance(value, Risk):
        return value
    return Risk.parse(value)


def split_outside_quotes(text: str, separators: Sequence[str]) -> list[str]:
    """따옴표/백슬래시 바깥의 구분자(긴 것 우선)로 문자열을 나눈다."""
    seps = sorted(separators, key=len, reverse=True)
    parts: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            buf.append(ch)
            buf.append(text[i + 1])
            i += 2
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        matched = None
        for sep in seps:
            if text.startswith(sep, i):
                matched = sep
                break
        if matched:
            parts.append("".join(buf))
            buf = []
            i += len(matched)
            continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return [p for p in (s.strip() for s in parts) if p]


def tokenize(segment: str) -> tuple[list[str], bool]:
    """shlex(posix) 토큰화. 실패(따옴표 불균형 등)하면 공백 분리 + uncertain=True."""
    try:
        return shlex.split(segment, comments=False, posix=True), False
    except ValueError:
        return segment.split(), True


_GLOB_CHARS = set("*?[")


def _name_lookup(token: str, table: Mapping[str, Risk], min_abbrev: int = 2) -> tuple[Risk | None, list[str]]:
    """정확 일치 → 접미사(.b/.raw 등) → 약어(유일/다중 접두어) 순으로 찾는다.

    약어가 여러 후보와 일치하면 가장 위험한 후보의 위험도를 반환한다.
    반환: (risk 또는 None, 일치한 후보 이름들)
    """
    if token in table:
        return table[token], [token]
    base = token.split(".", 1)[0]
    if base and base in table:
        return table[base], [base]
    if len(token) >= min_abbrev:
        cands = [k for k in table if k.startswith(token) and not k.startswith("_")]
        if cands:
            return max(table[c] for c in cands), sorted(cands)
    return None, []


# ---------------------------------------------------------------------------
# U-Boot
# ---------------------------------------------------------------------------

# 단일 명령 위험도 (서브커맨드가 없는 것)
UBOOT_COMMANDS: dict[str, Risk] = {
    # 정보 조회 / RAM 으로 읽기
    "help": I, "?": I, "version": I, "bdinfo": I, "printenv": I, "coninfo": I, "md": I,
    "crc32": I, "cmp": I, "echo": I, "test": I, "true": I, "false": I, "sleep": I, "itest": I,
    "iminfo": I, "imls": I, "flinfo": I, "dm": I, "clk": I, "meminfo": I, "loady": I, "loadb": I,
    "loadx": I, "loads": I, "tftp": I, "tftpboot": I, "tftpput": I, "nfs": I, "ping": I,
    "fatls": I, "fatinfo": I, "fatload": I, "fatsize": I, "ext4ls": I, "ext4load": I, "ext4size": I,
    "ext2ls": I, "ext2load": I, "ls": I, "load": I, "size": I, "hash": I, "md5sum": I,
    "sha1sum": I, "unzip": I, "lzmadec": I, "loop": I, "exit": I, "bmp": I, "showvar": I, "time": I,
    "nboot": M, "getinfo": I, "license": I, "pinmux": I, "irq": I, "mii": I, "ver": I,
    # 휘발성 변경
    "setenv": M, "editenv": M, "askenv": M, "setexpr": M, "base": M, "bootm": M, "bootz": M,
    "booti": M, "bootelf": M, "bootvx": M, "go": M, "reset": M, "poweroff": M, "dcache": M,
    "icache": M, "dhcp": M, "bootp": M, "chpart": M, "mtest": M, "rarpboot": M, "sntp": M,
    "boot": M, "bootd": M, "run": M, "source": D, "autoscr": D,
    # 영구 변경 / 위험
    "saveenv": D, "erase": D, "protect": D, "cp": D, "mw": D, "mm": D, "nm": D, "mwc": D,
    "fatwrite": D, "fatrm": D, "fatmkdir": D, "fatmv": D, "ext4write": D, "otp": D,
    "efuse": D, "dfu": D, "fastboot": D, "ums": D, "sspi": D, "gzwrite": D, "bmode": M,
    "upgrade": D, "update": D, "flwrite": D, "snor": D, "sfcnor": D,
}

# 서브커맨드가 있는 명령: {명령: {서브커맨드: 위험도, "_default": 위험도, "_none": 인자 없을 때}}
UBOOT_SUBCOMMANDS: dict[str, dict[str, Risk]] = {
    "sf": {"probe": I, "read": I, "write": D, "erase": D, "update": D, "protect": D, "test": D, "_default": M, "_none": I},
    "nand": {"info": I, "device": I, "bad": I, "read": I, "dump": I, "erase": D, "write": D, "scrub": D,
             "torture": D, "markbad": D, "biterr": D, "lock": D, "unlock": D, "_default": M, "_none": I},
    "mmc": {"info": I, "list": I, "dev": I, "part": I, "read": I, "rescan": I, "erase": D, "write": D,
            "swrite": D, "hwpartition": D, "bootbus": D, "bootpart-resize": D, "partconf": D,
            "rst-function": D, "setdsr": D, "_default": M, "_none": I},
    "mtd": {"list": I, "read": I, "dump": I, "bad": I, "write": D, "erase": D, "torture": D,
            "markbad": D, "_default": M, "_none": I},
    "env": {"print": I, "info": I, "exists": I, "grep": I, "flags": I, "callbacks": I, "set": M,
            "default": M, "delete": M, "edit": M, "import": M, "export": M, "ask": M, "select": M,
            "load": M, "run": M, "save": D, "erase": D, "_default": M, "_none": I},
    "fdt": {"print": I, "list": I, "header": I, "addr": M, "set": M, "mknode": M, "rm": M,
            "resize": M, "boardsetup": M, "apply": M, "move": M, "_default": M, "_none": I},
    "usb": {"info": I, "tree": I, "storage": I, "start": I, "dev": I, "part": I, "read": I,
            "reset": M, "stop": M, "write": D, "_default": M, "_none": I},
    "i2c": {"probe": I, "md": I, "dev": I, "bus": I, "crc32": I, "read": I, "speed": M, "reset": M,
            "mw": D, "mm": D, "nm": D, "write": D, "_default": M, "_none": I},
    "eeprom": {"read": I, "write": D, "_default": M, "_none": I},
    "fuse": {"read": I, "sense": I, "prog": D, "override": D, "_default": D, "_none": I},
    "ubi": {"info": I, "read": I, "check": I, "part": M, "detach": M, "write": D, "create": D,
            "remove": D, "_default": M, "_none": I},
    "mtdparts": {"default": M, "add": M, "del": M, "delall": M, "spread": M, "_default": M, "_none": I},
    "gpio": {"status": I, "input": I, "set": M, "clear": M, "toggle": M, "_default": M, "_none": I},
    "sata": {"info": I, "device": I, "part": I, "read": I, "init": M, "write": D, "_default": M, "_none": I},
    "scsi": {"info": I, "device": I, "part": I, "read": I, "scan": I, "reset": M, "write": D, "_default": M, "_none": I},
    "ide": {"info": I, "device": I, "part": I, "read": I, "reset": M, "write": D, "_default": M, "_none": I},
    "nvme": {"info": I, "device": I, "part": I, "read": I, "scan": I, "write": D, "_default": M, "_none": I},
    "gpt": {"verify": I, "read": I, "guid": I, "setenv": M, "write": D, "swap": D, "rename": D, "_default": D, "_none": I},
    "mbr": {"verify": I, "write": D, "_default": D, "_none": I},
    "pmic": {"list": I, "dev": I, "dump": I, "read": I, "write": D, "_default": M, "_none": I},
    "regulator": {"list": I, "dev": I, "info": I, "status": I, "value": D, "current": D, "mode": D,
                  "enable": D, "disable": D, "_default": M, "_none": I},
    "flash": {"info": I, "_default": D, "_none": I},
    "spi": {"_default": D, "_none": D},
}

_UBOOT_ALL_NAMES: dict[str, Risk] = {**UBOOT_COMMANDS, **{k: max(v.values()) for k, v in UBOOT_SUBCOMMANDS.items()}}
_UBOOT_KEYWORDS = {"if", "then", "else", "elif", "fi", "for", "in", "do", "done", "while", "until", "!"}

_UBOOT_REASONS = {
    "saveenv": "환경 변수를 플래시에 영구 저장",
    "erase": "NOR 플래시 영구 삭제",
    "protect": "플래시 보호 비트 변경",
    "cp": "메모리 복사 (대상이 플래시 매핑 영역이면 플래시에 기록됨)",
    "mw": "임의 메모리 쓰기 (MMIO 레지스터 포함 가능)",
    "mm": "대화형 메모리 수정",
    "nm": "대화형 메모리 수정",
    "source": "RAM 에 있는 스크립트 실행 (내용 확인 불가)",
    "autoscr": "RAM 에 있는 스크립트 실행 (내용 확인 불가)",
    "otp": "OTP 영구 기록",
    "efuse": "eFuse 영구 기록",
}


@dataclass
class UBootContext:
    """세션이 추적하는 U-Boot 상태."""

    env: dict[str, str] | None = None  # 알려진 환경 변수 (printenv 결과 + 이 세션에서 보낸 setenv)
    last_command: str | None = None  # 마지막으로 보낸 비어 있지 않은 명령 (빈 Enter 반복 대응)


def _uboot_segment(seg: str, ctx: UBootContext, unknown: Risk, depth: int, _as_time: bool = True) -> Classification:
    tokens, bad_quote = tokenize(seg)
    if bad_quote:
        return Classification(D, "uboot.unbalanced-quotes", "따옴표가 짝이 맞지 않아 실제 명령을 확정할 수 없음", seg, True)
    while tokens and tokens[0] in _UBOOT_KEYWORDS:
        tokens = tokens[1:]
    if not tokens:
        return Classification(I, "uboot.keyword", "제어 키워드만 있음", seg)
    cmd = tokens[0]
    args = tokens[1:]

    if cmd != "?" and (cmd.startswith("$") or any(c in _GLOB_CHARS for c in cmd)):  # '?' 단독은 help 별칭
        resolved = _resolve_uboot_var(cmd, ctx)
        if resolved is not None and depth < 6:
            return classify_uboot(" ".join([resolved, *args]), ctx=ctx, unknown_risk=unknown, _depth=depth + 1)
        return Classification(D, "uboot.indirect-command", "명령 위치에 변수/패턴이 있어 실제 명령을 확정할 수 없음", seg, True)

    # time <명령 …> (CONFIG_CMD_TIME): 안쪽 명령을 그대로 실행한다. 약어(t/ti/tim)는 다른 t* 명령일 수도 있으므로
    # 두 해석 중 더 위험한 쪽을 쓴다.
    if _as_time and args and "time".startswith(cmd.split(".", 1)[0]):
        if depth >= 6:
            return Classification(D, "uboot.time.recursion", "time 중첩이 너무 깊음", seg, True)
        inner = classify_uboot(" ".join(args), ctx=ctx, unknown_risk=unknown, _depth=depth + 1)
        as_time = Classification(inner.risk, f"uboot.time>{inner.rule_id}", f"time 이 안쪽 명령을 실행: {inner.reason}", seg, inner.uncertain)
        if cmd == "time":
            return as_time
        return worst([as_time, _uboot_segment(seg, ctx, unknown, depth, _as_time=False)])

    # run / boot: 환경 변수 내용을 재귀적으로 분류
    if cmd == "run":
        if not args:
            return Classification(I, "uboot.run.noargs", "run 인자 없음", seg)
        results = []
        for var in args:
            value = (ctx.env or {}).get(var)
            if value is None:
                results.append(Classification(
                    D, "uboot.run.unknown-var",
                    f"run 대상 변수 '{var}' 의 내용을 알 수 없음 — 먼저 printenv 로 확인한 뒤 다시 시도",
                    seg, True))
            elif depth >= 6:
                results.append(Classification(D, "uboot.run.recursion", "run 재귀 깊이 초과", seg, True))
            else:
                inner = classify_uboot(value, ctx=ctx, unknown_risk=unknown, _depth=depth + 1)
                results.append(Classification(max(inner.risk, M), f"uboot.run>{inner.rule_id}",
                                              f"run {var}: {inner.reason}", seg, inner.uncertain))
        return worst(results)
    if cmd in ("boot", "bootd"):
        value = (ctx.env or {}).get("bootcmd")
        if value is not None and depth < 6:
            inner = classify_uboot(value, ctx=ctx, unknown_risk=unknown, _depth=depth + 1)
            if inner.risk >= D:
                return Classification(D, f"uboot.boot>{inner.rule_id}", f"bootcmd 실행: {inner.reason}", seg, inner.uncertain)
        return Classification(M, "uboot.boot", "bootcmd 실행(부팅)", seg)

    # 서브커맨드가 있는 명령
    sub_table = None
    sub_name = None
    if cmd in UBOOT_SUBCOMMANDS:
        sub_table, sub_name = UBOOT_SUBCOMMANDS[cmd], cmd
    else:
        base = cmd.split(".", 1)[0]
        if base in UBOOT_SUBCOMMANDS:
            sub_table, sub_name = UBOOT_SUBCOMMANDS[base], base
    if sub_table is not None and sub_name is not None:
        if not args:
            risk = sub_table.get("_none", sub_table.get("_default", unknown))
            return Classification(risk, f"uboot.{sub_name}", f"{sub_name} (인자 없음)", seg)
        sub = args[0]
        if sub.startswith("$"):
            return Classification(D, f"uboot.{sub_name}.indirect", "서브커맨드가 변수라 확정 불가", seg, True)
        table = {k: v for k, v in sub_table.items() if not k.startswith("_")}
        risk, cands = _name_lookup(sub, table, min_abbrev=1)
        if risk is None:
            # nand read.raw / write.oob 처럼 '.' 접미사, 또는 'erase.chip'
            risk = sub_table.get("_default", unknown)
            return Classification(risk, f"uboot.{sub_name}.other", f"{sub_name} {sub} (분류 규칙 없음)", seg)
        rule = f"uboot.{sub_name}.{cands[0] if len(cands) == 1 else '|'.join(cands)}"
        reason = f"{sub_name} {sub}"
        if risk >= D:
            reason += " — 영구 저장장치/하드웨어 상태를 변경"
        plain = Classification(risk, rule, reason, seg)
        if sub_name == "env" and "run" in cands:
            # env run <var> … 는 run <var> … 와 같다 → 변수 내용을 재귀적으로 분류 (모르는 변수면 DESTRUCTIVE)
            as_run = _uboot_segment(" ".join(["run", *args[1:]]), ctx, unknown, depth + 1)
            as_run = Classification(max(as_run.risk, risk), f"uboot.env.run>{as_run.rule_id}", f"env run (= run): {as_run.reason}",
                                    seg, as_run.uncertain)
            return as_run if len(cands) == 1 else worst([as_run, plain])
        return plain

    risk, cands = _name_lookup(cmd, _UBOOT_ALL_NAMES, min_abbrev=1)
    if risk is None:
        return Classification(unknown, "uboot.unknown", f"분류 규칙에 없는 U-Boot 명령 '{cmd}'", seg)
    if len(cands) == 1:
        name = cands[0]
        if name in UBOOT_SUBCOMMANDS:
            # 서브커맨드 명령의 약어 (예: 'nan erase' → 'nand erase')
            return _uboot_segment(" ".join([name, *args]), ctx, unknown, depth + 1)
        if name == "run" and name != cmd:
            return _uboot_segment(" ".join([name, *args]), ctx, unknown, depth + 1)
        reason = _UBOOT_REASONS.get(name, f"U-Boot '{name}'")
        if name != cmd and name != cmd.split(".", 1)[0]:
            reason = f"약어 '{cmd}' → {name}: {reason}"
        stores = _uboot_result_store(name, args)
        if stores:
            return Classification(max(UBOOT_COMMANDS[name], M), f"uboot.{name}.store", f"{reason} — {stores}", seg)
        return Classification(UBOOT_COMMANDS[name], f"uboot.{name}", reason, seg)
    return Classification(risk, "uboot.abbrev", f"약어 '{cmd}' 후보: {', '.join(cands)} (가장 위험한 후보 기준)", seg)


_UBOOT_NUM_OR_VAR_RE = re.compile(r"(0x)?[0-9a-fA-F]+|\$\{?[A-Za-z0-9_]+\}?")


def _uboot_result_store(name: str, args: list[str]) -> str | None:
    """체크섬 명령이 결과를 메모리/환경 변수에 저장하는 형태면 그 설명 (조회 형태면 None).

    U-Boot 형태(주소 크기 [대상])일 때만 본다: 주소·크기 자리가 숫자/변수가 아니면(예: 리눅스 `md5sum /dev/mtd1 /dev/mtd2 …`) None.
    """
    pos = [a for a in args if not a.startswith("-")]
    if "-v" in args:
        return None
    first = 1 if name == "hash" else 0  # hash <알고리즘> <주소> <크기> [대상]
    if len(pos) < first + 3 or not all(_UBOOT_NUM_OR_VAR_RE.fullmatch(p) for p in pos[first:first + 2]):
        return None
    dest = pos[first + 2]
    if name == "crc32":
        return f"CRC 결과를 메모리 {dest} 에 기록"
    if name in ("md5sum", "sha1sum", "hash"):
        return f"결과를 {'메모리 ' + dest[1:] if dest.startswith('*') else '환경 변수 ' + dest} 에 저장"
    return None


def _resolve_uboot_var(token: str, ctx: UBootContext) -> str | None:
    m = re.fullmatch(r"\$\{?([A-Za-z0-9_]+)\}?", token)
    if not m or not ctx.env:
        return None
    return ctx.env.get(m.group(1))


def classify_uboot(
    line: str,
    *,
    ctx: UBootContext | None = None,
    unknown_risk: str | Risk = "modify",
    _depth: int = 0,
) -> Classification:
    """U-Boot 프롬프트에 보낼 한 줄을 분류."""
    ctx = ctx or UBootContext()
    unknown = _risk_from_setting(unknown_risk)
    text = line.strip()
    if not text:
        if ctx.last_command and _depth == 0:
            inner = classify_uboot(ctx.last_command, ctx=UBootContext(env=ctx.env), unknown_risk=unknown, _depth=1)
            return Classification(
                inner.risk, f"uboot.repeat>{inner.rule_id}",
                f"U-Boot 에서 빈 Enter 는 직전 명령('{ctx.last_command}')을 반복할 수 있음: {inner.reason}",
                "", inner.uncertain)
        return Classification(I, "uboot.empty", "빈 줄", "")
    segments = split_outside_quotes(text, [";", "&&", "||"])
    results = [_uboot_segment(seg, ctx, unknown, _depth) for seg in segments]
    return worst(results)


def uboot_setenv_effect(line: str) -> dict[str, str | None]:
    """한 줄에서 setenv/env set 으로 바뀌는 변수 → 값(None 이면 삭제) 추출. 세션의 env 추적용."""
    changes: dict[str, str | None] = {}
    for seg in split_outside_quotes(line.strip(), [";", "&&", "||"]):
        tokens, _ = tokenize(seg)
        while tokens and tokens[0] in _UBOOT_KEYWORDS:
            tokens = tokens[1:]
        if not tokens:
            continue
        if tokens[0] in ("setenv", "env") or (tokens[0].startswith("sete") and "setenv".startswith(tokens[0])):
            if tokens[0] == "env":
                if len(tokens) >= 2 and tokens[1] in ("set", "delete"):
                    if tokens[1] == "delete":
                        for name in tokens[2:]:
                            if not name.startswith("-"):
                                changes[name] = None
                        continue
                    tokens = ["setenv", *tokens[2:]]
                else:
                    continue
            rest = [t for t in tokens[1:] if not t.startswith("-") or len(t) > 2]
            if not rest:
                continue
            name = rest[0]
            value = " ".join(rest[1:]) if len(rest) > 1 else None
            changes[name] = value
    return changes


# ---------------------------------------------------------------------------
# Linux / BusyBox 셸
# ---------------------------------------------------------------------------

LINUX_DESTRUCTIVE = {
    "flash_erase", "flash_eraseall", "flashcp", "flash_lock", "flash_unlock", "nandwrite", "nandtest",
    "ubiformat", "ubimkvol", "ubirmvol", "ubiupdatevol", "ubirename", "mkfs", "mke2fs", "mkdosfs",
    "mkfs.vfat", "mkfs.ext2", "mkfs.ext3", "mkfs.ext4", "mkfs.jffs2", "mkfs.ubifs", "mkswap", "fdisk",
    "sfdisk", "parted", "fw_setenv", "passwd", "chpasswd", "adduser", "deluser", "addgroup",
    "delgroup", "i2cset", "spidev_test", "sysupgrade", "fwupdate", "firmwareupdate", "flash_update",
    "update_firmware", "upgrade_firmware", "eraseall", "shred", "wipefs", "blkdiscard", "nvram_commit",
}
LINUX_MODIFY = {
    "reboot", "poweroff", "halt", "shutdown", "init", "telinit", "kill", "killall", "pkill",
    "insmod", "rmmod", "modprobe", "iptables", "ip6tables", "ebtables", "umount", "swapon", "swapoff",
    "telnetd", "dropbear", "sshd", "httpd", "inetd", "udhcpc", "dhclient", "ntpd", "ntpclient",
    "crond", "crontab", "stty", "setsid", "start-stop-daemon", "chroot", "exec", "exit", "logout",
    "su", "sudo", "ulimit", "renice", "nice", "hwclock", "memtester", "ubiattach", "ubidetach",
    "brctl", "vconfig", "iwconfig", "wpa_supplicant", "hostapd", "watchdog", "touch", "mkdir",
    "rmdir", "ln", "chmod", "chown", "chgrp", "mv", "cp", "tee", "truncate", "install", "rm",
    "mknod", "mkfifo", "sync_time", "date_set", "export", "unset", "alias", "unalias", "trap",
    "wget", "curl", "ftpget", "tftp", "nc", "netcat", "socat", "sysctl", "mount", "ifconfig",
    "ip", "route", "date", "hostname", "nvram", "setprop", "wpa_cli",
}
LINUX_READONLY = {
    "cat", "ls", "ll", "ps", "top", "df", "du", "free", "uptime", "uname", "dmesg", "id", "whoami",
    "pwd", "echo", "printf", "true", "false", "test", "[", "[[", "sleep", "usleep", "env", "printenv",
    "set", "cut", "grep", "egrep", "fgrep", "head", "tail", "sort", "uniq", "wc", "tr", "hexdump",
    "hd", "od", "xxd", "strings", "md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum", "crc32",
    "base64", "uuencode", "uudecode", "which", "type", "command", "file", "stat", "readlink",
    "realpath", "basename", "dirname", "netstat", "ss", "arp", "lsmod", "lsof", "nanddump", "ping",
    "ping6", "traceroute", "nslookup", "busybox", "help", "history", "fw_printenv", "i2cdetect",
    "i2cget", "i2cdump", "lspci", "lsusb", "getprop", "logread", "ubinfo", "mtdinfo", "cd",
    "find", "awk", "sed", "dd", "mtd_debug", "devmem", "devmem2", "himm", "himd", "himc", "xargs",
    "time", "timeout", "nohup", "seq", "expr", "let", "read", "local", "return", "break",
    "continue", "shift", "wait", "jobs", "fg", "bg", "sync", "zcat", "gunzip", "gzip", "tar",
    "cpio", "unsquashfs", "less", "more", "vi", "diff", "cmp", "comm", "join", "paste", "rev",
    "fold", "nl", "tac", "yes", "clear", "reset", "tty", "nproc", "getconf", "locale", "cal",
    "iostat", "vmstat", "mpstat", "pidof", "pgrep", "pstree", "watch", "flash_info", "nandinfo",
    "lscpu", "lsblk", "blkid", "fdisk-l", "sh", "ash", "bash", "hush", ".", "source", "eval",
}
_LINUX_PREFIX_WRAPPERS = {"nohup", "time", "nice", "sudo", "busybox", "env", "command", "timeout", "setsid", "stdbuf", "chrt", "taskset", "ionice"}
_LINUX_DEVICE_RE = re.compile(r"^/dev/(mtd|mtdblock|mmcblk|sd[a-z]|hd[a-z]|nand|ubi|mem$|kmem$|port$|nvme|vd[a-z]|loop|ram\d|sda)", re.I)
_SAFE_SINKS = {"/dev/null", "-", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/console", "&1", "&2"}
# 경로로 지정한 실행 파일을 이름(basename)으로 분류해도 되는 디렉터리. 그 밖(/tmp, /mnt, 상대 경로 등)의 파일은
# 에이전트나 누군가가 써 넣었을 수 있으므로 이름이 cat/ls 여도 내용을 알 수 없다.
_LINUX_SYSTEM_BIN_DIRS = frozenset({"/bin", "/sbin", "/usr/bin", "/usr/sbin"})
# 쓰기 대상이 되면 이후 실행되는 시스템 실행 파일·라이브러리·설정이 바뀌는 경로 (쓰기 가능한 rootfs 에서는 영구 변경)
_LINUX_SYSTEM_WRITE_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib", "/usr/lib", "/etc")
# 바꾸면 이후 명령이 실제로 어떤 파일을 실행·적재하는지 바뀌는 환경 변수
_LINUX_HIJACK_VARS = frozenset({"PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "ENV", "BASH_ENV"})


def _is_system_binary_path(raw: str) -> bool:
    """'/' 가 들어간 명령 경로가 시스템 실행 파일 디렉터리 바로 아래의 절대 경로인지 (상대 경로는 항상 False)."""
    if not raw.startswith("/"):
        return False
    return posixpath.dirname(posixpath.normpath(raw)) in _LINUX_SYSTEM_BIN_DIRS


def _assigned_hijack_var(token: str) -> str | None:
    """`NAME=value` 토큰이 실행 경로/동적 링커 변수를 바꾸면 그 이름."""
    m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)(\+?=).*", token, re.S)
    if m and m.group(1) in _LINUX_HIJACK_VARS:
        return m.group(1)
    return None


@dataclass
class LinuxPolicy:
    persistent_paths: tuple[str, ...] = ()
    unknown_risk: Risk = M
    cwd: str | None = None  # 알려진 현재 디렉터리 (상대 경로 쓰기·삭제 대상 해석용, 모르면 None)


def _resolve_path(path: str, policy: LinuxPolicy) -> str:
    """쓰기/삭제 대상을 절대 경로로 정규화한다. 상대 경로는 알려진 cwd 기준, cwd 를 모르면 그대로 둔다."""
    p = path.strip().strip("'\"")
    if p.startswith("/"):
        return posixpath.normpath(p)
    if policy.cwd and p and not p.startswith(("$", "~", "&", "-")):
        return posixpath.normpath(posixpath.join(policy.cwd, p))
    return p


def _is_persistent(path: str, policy: LinuxPolicy) -> bool:
    p = path.strip().strip("'\"")
    return any(p == base or p.startswith(base.rstrip("/") + "/") for base in policy.persistent_paths)


def _classify_write_target(path: str, policy: LinuxPolicy, seg: str, how: str) -> Classification:
    p = path.strip().strip("'\"")
    if p in _SAFE_SINKS or p.startswith("&"):
        return Classification(I, "linux.write.safe-sink", f"{how} → {p}", seg)
    rp = _resolve_path(p, policy)  # 상대 경로 + 알려진 cwd → 절대 경로 (cd /usr/bin; cp x md5sum)
    shown = p if rp == p else f"{p} (= {rp})"
    if _LINUX_DEVICE_RE.match(p) or _LINUX_DEVICE_RE.match(rp):
        return Classification(D, "linux.write.block-device", f"{how} → 저장장치/메모리 디바이스 {shown} (영구 손상 가능)", seg)
    if p.startswith("$") or any(c in _GLOB_CHARS for c in p):
        return Classification(D, "linux.write.indirect-target", f"{how} 대상 경로를 확정할 수 없음: {p}", seg, True)
    if _is_persistent(rp, policy):
        return Classification(D, "linux.write.persistent", f"{how} → 영구 파티션 경로 {shown}", seg)
    if any(rp == d or rp.startswith(d + "/") for d in _LINUX_SYSTEM_WRITE_DIRS):
        return Classification(D, "linux.write.system", f"{how} → 시스템 실행 파일/라이브러리/설정 경로 {shown} (이후 실행 내용이 바뀌고, 쓰기 가능한 rootfs 면 영구 변경)", seg)
    if rp.startswith("/sys/") or rp.startswith("/proc/"):
        return Classification(M, "linux.write.sysfs", f"{how} → 커널 인터페이스 {shown}", seg)
    if not rp.startswith("/"):
        return Classification(M, "linux.write.file", f"{how} → 파일 {p} (현재 디렉터리를 몰라 실제 위치를 확정할 수 없음)", seg, True)
    return Classification(M, "linux.write.file", f"{how} → 파일 {shown}", seg)


def _cd_effect(tokens: list[str], cwd: str | None) -> tuple[bool, str | None]:
    """cd/pushd/popd 면 (True, 새 cwd). cd 는 성공한다고 본다. 홈·이전 디렉터리·변수·글롭 대상은 모름(None)."""
    if not tokens or tokens[0] not in ("cd", "chdir", "pushd", "popd"):
        return False, cwd
    if tokens[0] == "popd":
        return True, None
    args = [a for a in tokens[1:] if a == "-" or not a.startswith("-")]  # cd -P / -L 옵션 제외
    if not args:
        return True, None  # 홈 디렉터리 (어디인지 모름)
    target = args[0]
    if target == "-" or target.startswith(("~", "$")) or any(c in _GLOB_CHARS for c in target):
        return True, None
    if target.startswith("/"):
        return True, posixpath.normpath(target)
    return True, (posixpath.normpath(posixpath.join(cwd, target)) if cwd else None)


def linux_cwd_effect(line: str, cwd: str | None) -> str | None:
    """셸에 실제로 보낸 한 줄이 현재 디렉터리를 어떻게 바꾸는지 (세션 추적용, cd 는 성공한다고 본다)."""
    text = line.strip()
    if not text or text.startswith("#"):
        return cwd
    for seg in split_outside_quotes(text, ["&&", "||", ";", "|", "&", "\n"]):
        tokens, bad = tokenize(_extract_redirections(seg)[0])
        if bad:
            return None
        while tokens and tokens[0] in ("if", "then", "else", "elif", "do", "while", "until", "!", "{", "("):
            tokens = tokens[1:]
        _, cwd = _cd_effect(_strip_wrappers(tokens)[0], cwd)
    return cwd


_REDIR_RE = re.compile(r"(?<![<>&\d])(\d*|&)(>>|>\||>)(?!&)\s*([^\s;|&<>]+)")


def _extract_redirections(segment: str) -> tuple[str, list[str]]:
    """따옴표 밖의 출력 리다이렉션 대상 추출. (리다이렉션 제거한 세그먼트, 대상 목록)"""
    targets: list[str] = []
    out: list[str] = []
    quote: str | None = None
    i = 0
    n = len(segment)
    while i < n:
        ch = segment[i]
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == ">":
            # 앞의 fd 숫자/& 는 이미 out 에 들어가 있음 → 제거
            while out and (out[-1].isdigit() or out[-1] == "&"):
                out.pop()
            j = i + 1
            if j < n and segment[j] in (">", "|"):
                j += 1
            if j < n and segment[j] == "&":  # 2>&1 같은 fd 복제
                j += 1
                while j < n and segment[j].isdigit():
                    j += 1
                i = j
                continue
            while j < n and segment[j] == " ":
                j += 1
            k = j
            tq: str | None = None
            while k < n and (tq or segment[k] not in " ;|&<>"):
                if segment[k] in ("'", '"'):
                    tq = None if tq == segment[k] else (segment[k] if tq is None else tq)
                k += 1
            target = segment[j:k]
            if target:
                targets.append(target)
            i = k
            continue
        out.append(ch)
        i += 1
    return "".join(out), targets


def _strip_wrappers(tokens: list[str]) -> tuple[list[str], list[str]]:
    """접두 할당(VAR=value)과 래퍼(nohup, env, timeout …)를 벗긴 실제 명령 토큰과, 그 과정에서 본 위험 변수 할당 목록."""
    toks = list(tokens)
    hijacks: list[str] = []
    changed = True
    while toks and changed:
        changed = False
        # VAR=value 접두 할당 (env 뒤의 할당 포함). PATH/LD_PRELOAD 같은 변수는 따로 기록한다.
        while toks and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\+?=.*", toks[0], re.S):
            var = _assigned_hijack_var(toks[0])
            if var:
                hijacks.append(var)
            toks = toks[1:]
            changed = True
        if toks:
            t0 = toks[0]
            if "/" in t0 and not t0.startswith("$"):
                # 시스템 디렉터리 밖의 /tmp/nohup 같은 파일은 래퍼 이름을 믿지 않는다 (그대로 두면 경로 실행으로 분류됨)
                head = t0.rsplit("/", 1)[-1] if _is_system_binary_path(t0) else ""
            else:
                head = t0
            if head in _LINUX_PREFIX_WRAPPERS and len(toks) > 1:
                toks = toks[1:]
                # timeout 10 cmd / nice -n 5 cmd / taskset 0x1 cmd 등의 옵션·숫자 인자 제거
                while toks and (toks[0].startswith("-") or re.fullmatch(r"[\d.]+[smhd]?|0x[0-9a-fA-F]+", toks[0])):
                    toks = toks[1:]
                changed = True
    return toks, hijacks


# 읽기만 해도 부작용이 있는 장치: 워치독은 여는 순간 타이머가 켜져 기기가 재부팅되고, /dev/mem·kmem·port 읽기는
# MMIO 레지스터 읽기 부작용이나 버스 오류(멈춤)를 낼 수 있다.
_SIDE_EFFECT_DEV_RE = re.compile(r"(?:^|[<=])(/dev/(?:watchdog\d*|mem|kmem|port))$")
# 경로를 열지 않고 이름/속성만 다루는 명령 (위 장치를 인자로 받아도 부작용 없음)
_NO_OPEN_CMDS = {"ls", "ll", "stat", "readlink", "realpath", "basename", "dirname", "echo", "printf", "test", "[", "[[",
                 "file", "which", "type", "lsof", "du"}
_FIND_EXEC_FLAGS = ("-exec", "-execdir", "-ok", "-okdir")


def _classify_linux_command(tokens: list[str], seg: str, policy: LinuxPolicy, depth: int) -> Classification:
    c = _classify_linux_command_inner(tokens, seg, policy, depth)
    if c.risk >= M:
        return c
    devs = [m.group(1) for m in (_SIDE_EFFECT_DEV_RE.search(t.strip("'\"")) for t in tokens) if m]
    if devs:
        toks, _ = _strip_wrappers(tokens)
        head = toks[0].rsplit("/", 1)[-1] if toks else ""
        find_stat_only = head == "find" and not any(a in _FIND_EXEC_FLAGS for a in toks[1:])  # find 자체는 stat 만
        if head not in _NO_OPEN_CMDS and not find_stat_only:
            return Classification(M, "linux.read.side-effect-device",
                                  f"{', '.join(dict.fromkeys(devs))} 를 열기만 해도 부작용 (워치독 시작 → 재부팅, MMIO 읽기 부작용·멈춤)",
                                  seg, c.uncertain)
    return c


def _classify_linux_command_inner(tokens: list[str], seg: str, policy: LinuxPolicy, depth: int) -> Classification:
    toks, hijacks = _strip_wrappers(tokens)
    if hijacks:
        names = ", ".join(dict.fromkeys(hijacks))
        return Classification(D, "linux.env-hijack", f"{names} 변경 — 이후 명령이 실제로 실행·적재하는 파일을 확정할 수 없음", seg, True)
    if not toks:
        return Classification(I, "linux.assign", "변수 할당/래퍼만 있음", seg)
    raw_cmd = toks[0]
    args = toks[1:]
    if raw_cmd not in ("[", "[[") and (raw_cmd.startswith("$") or any(c in _GLOB_CHARS for c in raw_cmd)):  # '[' 단독은 test
        return Classification(D, "linux.indirect-command", "명령 위치에 변수/글롭이 있어 실제 명령을 확정할 수 없음", seg, True)
    if "/" in raw_cmd and not _is_system_binary_path(raw_cmd):
        # 이름 표(cat, sh, dd …)보다 먼저 본다: /tmp/cat 은 cat 이 아닐 수 있다.
        return Classification(D, "linux.exec-nonsystem",
                              f"시스템 디렉터리(/bin, /sbin, /usr/bin, /usr/sbin) 밖의 실행 파일 '{raw_cmd}' — 이름과 무관하게 내용을 확인할 수 없음",
                              seg, True)
    cmd = raw_cmd.rsplit("/", 1)[-1] if "/" in raw_cmd else raw_cmd
    if cmd == "exec":
        rest = list(args)
        while rest and rest[0].startswith("-"):  # bash: exec -a NAME / -c / -l
            rest = rest[2:] if rest[0] == "-a" else rest[1:]
        if not rest:
            return Classification(M, "linux.exec", "exec (fd 조작)", seg)
        if depth >= 6:
            return Classification(D, "linux.exec.deep", "exec 대상을 확정할 수 없음", seg, True)
        inner = _classify_linux_command(rest, seg, policy, depth + 1)
        return Classification(max(M, inner.risk), f"linux.exec>{inner.rule_id}", f"exec 로 셸을 '{rest[0]}' 로 대체: {inner.reason}", seg, inner.uncertain)
    if cmd in ("export", "readonly", "declare", "typeset", "local"):
        bad = [v for v in (_assigned_hijack_var(a) for a in args) if v]
        if bad:
            return Classification(D, "linux.env-hijack", f"{', '.join(dict.fromkeys(bad))} 변경 — 이후 명령이 실제로 실행·적재하는 파일을 확정할 수 없음", seg, True)
    if cmd in ("chroot", "pivot_root", "switch_root"):
        return Classification(D, f"linux.{cmd}", f"{cmd} — 다른 루트의 실행 파일을 실행 (내용 확인 불가, 루트 전환은 복구 어려움)", seg, True)
    if cmd.endswith("()") or raw_cmd == "function":
        body = seg.split("{", 1)[1] if "{" in seg else ""
        inner = classify_linux(body, persistent_paths=policy.persistent_paths, unknown_risk=policy.unknown_risk, cwd=policy.cwd, _depth=depth + 1) if body else None
        return Classification(max(M, inner.risk) if inner else M, "linux.function-def", "셸 함수 정의 (본문 기준 분류)", seg, bool(inner and inner.uncertain))

    # 셸 재진입 / 스크립트 실행
    if cmd in ("sh", "ash", "bash", "hush", "dash", "ksh"):
        if "-c" in args:
            idx = args.index("-c")
            if idx + 1 < len(args) and depth < 6:
                inner = classify_linux(args[idx + 1], persistent_paths=policy.persistent_paths, unknown_risk=policy.unknown_risk, cwd=policy.cwd, _depth=depth + 1)
                return Classification(inner.risk, f"linux.sh-c>{inner.rule_id}", f"sh -c: {inner.reason}", seg, inner.uncertain)
            return Classification(D, "linux.sh-c.unknown", "sh -c 인자를 확정할 수 없음", seg, True)
        if args and not args[0].startswith("-"):
            return Classification(D, "linux.script", f"스크립트 '{args[0]}' 실행 (내용 확인 불가)", seg, True)
        if any("<" in a for a in args):
            return Classification(D, "linux.script-stdin", "셸에 파일/here-doc 을 표준 입력으로 넘김 (내용 확인 불가)", seg, True)
        return Classification(M, "linux.subshell", "대화형 서브셸 진입", seg)
    if cmd in (".", "source"):
        return Classification(D, "linux.source", "스크립트 source (내용 확인 불가)", seg, True)
    if cmd == "eval":
        if args and depth < 6:
            inner = classify_linux(" ".join(args), persistent_paths=policy.persistent_paths, unknown_risk=policy.unknown_risk, cwd=policy.cwd, _depth=depth + 1)
            return Classification(max(inner.risk, M), f"linux.eval>{inner.rule_id}", f"eval: {inner.reason}", seg, True)
        return Classification(D, "linux.eval", "eval 내용을 확정할 수 없음", seg, True)
    if cmd == "alias" and args:
        results = []
        for a in args:
            if "=" in a:
                value = a.split("=", 1)[1]
                inner = classify_linux(value, persistent_paths=policy.persistent_paths, unknown_risk=policy.unknown_risk, cwd=policy.cwd, _depth=depth + 1)
                results.append(Classification(max(M, inner.risk), f"linux.alias>{inner.rule_id}", f"alias 정의: {inner.reason}", seg))
        return worst(results, Classification(M, "linux.alias", "alias 정의", seg))
    if cmd == "xargs":
        rest = [a for a in args if not a.startswith("-")]
        if rest and depth < 6:
            inner = _classify_linux_command(rest, seg, policy, depth + 1)
            if inner.risk >= M:
                return Classification(max(inner.risk, D if inner.risk >= M and rest[0] in ("rm", "dd", "mv", "cp", "tee") else inner.risk),
                                      f"linux.xargs>{inner.rule_id}", f"xargs 로 대상이 정해지지 않은 '{rest[0]}' 실행", seg, True)
            return Classification(inner.risk, f"linux.xargs>{inner.rule_id}", inner.reason, seg)
        return Classification(I, "linux.xargs", "xargs", seg)
    if cmd == "find":
        if "-delete" in args:
            return Classification(D, "linux.find.delete", "find -delete (대상 확정 불가)", seg, True)
        for flag in ("-exec", "-execdir", "-ok", "-okdir"):
            if flag in args:
                idx = args.index(flag)
                sub = [a for a in args[idx + 1:] if a not in (";", "+", "\\;", "{}")]
                inner = _classify_linux_command(sub, seg, policy, depth + 1) if sub else Classification(M, "linux.find.exec", "find -exec", seg)
                risk = inner.risk
                if risk >= M and sub and sub[0] in ("rm", "dd", "mv", "cp", "tee", "chmod", "chown", "sed"):
                    risk = D
                return Classification(risk, f"linux.find.exec>{inner.rule_id}", f"find {flag}: {inner.reason}", seg, True)
        return Classification(I, "linux.find", "find (조회)", seg)

    # 경로 인지형 명령
    if cmd == "dd":
        ofs = [a[3:] for a in args if a.startswith("of=")]
        if not ofs:
            return Classification(I, "linux.dd.read", "dd (출력은 stdout)", seg)
        return worst([_classify_write_target(of, policy, seg, "dd of=") for of in ofs])
    if cmd in ("rm", "rmdir", "shred", "unlink"):
        paths = [a for a in args if not a.startswith("-")]
        if not paths:
            return Classification(M, f"linux.{cmd}", f"{cmd}", seg)
        results = []
        for p in paths:
            raw = p.strip("'\"")
            pp = raw if raw.startswith("$") else _resolve_path(raw, policy)  # cd / 뒤의 rm -rf * → /*
            if pp in ("/", "/*") or pp.startswith("/dev/") or pp.startswith("$") or any(c in _GLOB_CHARS for c in pp) and pp.startswith("/") and pp.count("/") <= 2:
                results.append(Classification(D, f"linux.{cmd}.dangerous", f"{cmd} {pp} — 광범위/확정 불가 삭제", seg, pp.startswith("$")))
            elif _is_persistent(pp, policy) or pp.startswith("/etc") or pp.startswith("/usr") or pp.startswith("/bin") or pp.startswith("/sbin") or pp.startswith("/lib"):
                results.append(Classification(D, f"linux.{cmd}.persistent", f"{cmd} {pp} — 영구/시스템 경로 삭제", seg))
            else:
                results.append(Classification(M, f"linux.{cmd}", f"{cmd} {pp}", seg))
        return worst(results)
    if cmd in ("cp", "mv", "install", "ln"):
        paths = [a for a in args if not a.startswith("-")]
        if len(paths) >= 2:
            return _classify_write_target(paths[-1], policy, seg, cmd)
        return Classification(M, f"linux.{cmd}", cmd, seg)
    if cmd in ("tee", "truncate", "touch", "mkdir", "chmod", "chown", "chgrp", "mknod", "mkfifo"):
        paths = [a for a in args if not a.startswith("-")]
        if cmd in ("chmod", "chown", "chgrp") and paths:
            paths = paths[1:]
        if cmd == "truncate":
            paths = [a for a in paths if not re.fullmatch(r"[\d]+[KMG]?", a)]
        if paths:
            return worst([_classify_write_target(p, policy, seg, cmd) for p in paths])
        return Classification(M, f"linux.{cmd}", cmd, seg)
    if cmd == "sed":
        script_args = " ".join(args)
        if any(a == "-i" or a.startswith("-i") or a == "--in-place" for a in args):
            files = [a for a in args if not a.startswith("-")][1:]
            return worst([_classify_write_target(f, policy, seg, "sed -i") for f in files] or [Classification(M, "linux.sed-i", "sed -i", seg)])
        if re.search(r"(^|[;\s'\"])w\s+\S|\be\b", script_args):
            return Classification(D, "linux.sed.write-or-exec", "sed 스크립트에 파일 쓰기(w)/실행(e) 명령 포함 가능", seg, True)
        return Classification(I, "linux.sed", "sed (stdout 출력)", seg)
    if cmd == "awk":
        script = " ".join(args)
        if "system(" in script or re.search(r"print[^;]*>\s*", script) or "|" in script:
            return Classification(D, "linux.awk.side-effect", "awk 스크립트에 system()/파일 출력이 포함됨", seg, True)
        return Classification(I, "linux.awk", "awk (조회)", seg)
    if cmd == "mtd_debug":
        sub = args[0] if args else ""
        if sub in ("write", "erase"):
            return Classification(D, f"linux.mtd_debug.{sub}", f"mtd_debug {sub} — 플래시 영구 변경", seg)
        return Classification(I, "linux.mtd_debug.read", f"mtd_debug {sub}", seg)
    if cmd == "mtd":  # OpenWrt mtd
        sub = args[0] if args else ""
        if sub in ("write", "erase", "unlock", "jffs2write", "fixtrx", "refresh", "resetbc"):
            return Classification(D, f"linux.mtd.{sub}", f"mtd {sub} — 플래시 영구 변경", seg)
        return Classification(M, "linux.mtd", "mtd", seg)
    if cmd in ("devmem", "devmem2"):
        positional = [a for a in args if not a.startswith("-")]
        if (cmd == "devmem" and len(positional) >= 3) or (cmd == "devmem2" and len(positional) >= 3):
            return Classification(D, f"linux.{cmd}.write", f"{cmd} 물리 메모리/MMIO 쓰기", seg)
        return Classification(I, f"linux.{cmd}.read", f"{cmd} 읽기", seg)
    if cmd == "himm":
        positional = [a for a in args if not a.startswith("-")]
        if len(positional) >= 2:
            return Classification(D, "linux.himm.write", "himm 레지스터/메모리 쓰기 (HiSilicon)", seg)
        return Classification(I, "linux.himm.read", "himm 읽기", seg)
    if cmd == "nanddump":
        out = None
        for idx, a in enumerate(args):
            if a in ("-f", "--file") and idx + 1 < len(args):
                out = args[idx + 1]
            elif a.startswith("--file="):
                out = a.split("=", 1)[1]
        if out:
            return _classify_write_target(out, policy, seg, "nanddump -f")
        return Classification(I, "linux.nanddump", "nanddump (읽기)", seg)
    if cmd == "nvram":
        sub = args[0] if args else ""
        if sub in ("commit", "erase", "restore", "clear"):
            return Classification(D, f"linux.nvram.{sub}", f"nvram {sub} — 설정 영구 변경", seg)
        if sub in ("set", "unset"):
            return Classification(M, f"linux.nvram.{sub}", f"nvram {sub}", seg)
        return Classification(I, "linux.nvram", f"nvram {sub}", seg)
    if cmd == "mount":
        if not args:
            return Classification(I, "linux.mount.list", "마운트 목록 조회", seg)
        joined = " ".join(args)
        if re.search(r"(^|[\s,=])(-B|-R|-M|--bind|--rbind|--move|bind|rbind|move)(?=$|[\s,])", joined) or re.search(r"\b(overlay|overlayfs|aufs|unionfs)\b", joined):
            return Classification(D, "linux.mount.bind", "바인드/오버레이 마운트 — 이후 실행·읽기되는 파일을 다른 내용으로 바꿀 수 있음", seg, True)
        if any("remount" in a for a in args):
            return Classification(M, "linux.mount.remount", "remount (rw 전환 가능)", seg)
        return Classification(M, "linux.mount", "mount", seg)
    if cmd == "ifconfig":
        positional = [a for a in args if not a.startswith("-")]
        if len(positional) <= 1:
            return Classification(I, "linux.ifconfig.show", "인터페이스 조회", seg)
        return Classification(M, "linux.ifconfig.set", "네트워크 인터페이스 설정 변경", seg)
    if cmd == "ip":
        joined = " ".join(args)
        if re.search(r"\b(add|del|delete|set|flush|change|replace|append)\b", joined):
            return Classification(M, "linux.ip.set", "ip 설정 변경", seg)
        return Classification(I, "linux.ip.show", "ip 조회", seg)
    if cmd == "route":
        if any(a in ("add", "del", "delete") for a in args):
            return Classification(M, "linux.route.set", "라우팅 변경", seg)
        return Classification(I, "linux.route.show", "라우팅 조회", seg)
    if cmd == "date":
        if any(a == "-s" or a.startswith("--set") for a in args) or [a for a in args if not a.startswith("-") and not a.startswith("+")]:
            return Classification(M, "linux.date.set", "시스템 시간 변경", seg)
        return Classification(I, "linux.date", "날짜 조회", seg)
    if cmd == "hostname":
        return Classification(M if [a for a in args if not a.startswith("-")] else I, "linux.hostname", "hostname", seg)
    if cmd in ("wget", "curl"):
        if any(a in ("-O-", "-") for a in args) or ("-O" in args and args.index("-O") + 1 < len(args) and args[args.index("-O") + 1] == "-"):
            return Classification(I, f"linux.{cmd}.stdout", f"{cmd} → stdout", seg)
        outs = []
        for idx, a in enumerate(args):
            if a in ("-O", "-o", "--output") and idx + 1 < len(args):
                outs.append(args[idx + 1])
        if outs:
            return worst([_classify_write_target(o, policy, seg, cmd) for o in outs])
        return Classification(M, f"linux.{cmd}", f"{cmd} 다운로드(파일 생성)", seg)
    if cmd == "tftp":
        if "-p" in args or "--put" in args:
            return Classification(I, "linux.tftp.put", "tftp 업로드 (기기 → 분석 PC)", seg)
        local = None
        for idx, a in enumerate(args):
            if a in ("-l", "--local") and idx + 1 < len(args):
                local = args[idx + 1]
        if local:
            return _classify_write_target(local, policy, seg, "tftp -g")
        return Classification(M, "linux.tftp.get", "tftp 다운로드", seg)
    if cmd in ("nc", "netcat"):
        if "-l" in args or "-ll" in args or "-e" in args:
            return Classification(M, f"linux.{cmd}.listen", f"{cmd} 리슨/실행 (-l/-e)", seg)
        return Classification(I, f"linux.{cmd}.connect", f"{cmd} 연결 (데이터 전송)", seg)
    if cmd == "sysctl":
        if "-w" in args or any("=" in a for a in args):
            return Classification(M, "linux.sysctl.set", "sysctl 값 변경", seg)
        return Classification(I, "linux.sysctl", "sysctl 조회", seg)
    if cmd == "hwclock":
        if any(a in ("-w", "--systohc", "-s", "--hctosys") for a in args):
            return Classification(M, "linux.hwclock.set", "RTC/시스템 시간 변경", seg)
        return Classification(I, "linux.hwclock", "hwclock 조회", seg)
    if cmd == "crontab":
        return Classification(I if args == ["-l"] else D, "linux.crontab", "crontab (변경 시 영구)", seg)
    if cmd == "top":
        return Classification(I, "linux.top", "top", seg)
    if cmd == "tar":
        if any(a.startswith("-x") or a.startswith("x") or a == "--extract" for a in args):
            return Classification(M, "linux.tar.extract", "tar 압축 해제(파일 생성)", seg)
        return Classification(I, "linux.tar", "tar", seg)
    if cmd in ("gzip", "gunzip"):
        if "-c" in args or "-d" in args and "-c" in args:
            return Classification(I, f"linux.{cmd}.stdout", cmd, seg)
        return Classification(M, f"linux.{cmd}", f"{cmd} (파일 변경)", seg)

    if cmd == "fdisk" and args[:1] == ["-l"] and all(a.startswith("/dev/") for a in args[1:]):
        return Classification(I, "linux.fdisk.list", "fdisk -l (파티션 표 조회)", seg)
    if cmd in LINUX_DESTRUCTIVE or cmd.startswith("mkfs"):
        return Classification(D, f"linux.{cmd}", f"'{cmd}' — 저장장치/계정/설정 영구 변경", seg)
    if cmd in LINUX_MODIFY:
        return Classification(M, f"linux.{cmd}", f"'{cmd}' — 휘발성 상태 변경", seg)
    if cmd in LINUX_READONLY:
        return Classification(I, f"linux.{cmd}", f"'{cmd}' (조회)", seg)
    if "/" in raw_cmd:  # 여기까지 오면 시스템 디렉터리 안의 표에 없는 실행 파일
        return Classification(policy.unknown_risk, "linux.exec-path", f"경로 지정 실행 파일 '{raw_cmd}' (동작 미상)", seg)
    return Classification(policy.unknown_risk, "linux.unknown", f"분류 규칙에 없는 명령 '{cmd}'", seg)


_SUBST_RE = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")


def classify_linux(
    line: str,
    *,
    persistent_paths: Iterable[str] = (),
    unknown_risk: str | Risk = "modify",
    cwd: str | None = None,
    _depth: int = 0,
) -> Classification:
    """BusyBox/Linux 셸에 보낼 한 줄을 분류.

    cwd: 세션이 추적한 현재 디렉터리(모르면 None). 상대 경로 쓰기·삭제 대상을 이 기준으로 해석하고,
    같은 줄 안의 ``cd`` 도 뒤 세그먼트에 반영한다 (``cd /usr/bin && cp /tmp/x md5sum`` = 시스템 경로 쓰기).
    """
    policy = LinuxPolicy(tuple(persistent_paths), _risk_from_setting(unknown_risk), posixpath.normpath(cwd) if cwd and cwd.startswith("/") else None)
    text = line.strip()
    if not text:
        return Classification(O, "linux.empty", "빈 줄")
    if text.startswith("#"):
        return Classification(O, "linux.comment", "주석")
    results: list[Classification] = []

    # 명령 치환 $(...) / `...` 은 안쪽을 따로 분류하고 자리표시자로 치환
    def _subst(m: re.Match[str]) -> str:
        inner = m.group(1) if m.group(1) is not None else m.group(2)
        if _depth < 6:
            results.append(classify_linux(inner, persistent_paths=policy.persistent_paths, unknown_risk=policy.unknown_risk, cwd=policy.cwd, _depth=_depth + 1))
        return "$SUBST"

    if "$(" in text or "`" in text:
        text2 = _SUBST_RE.sub(_subst, text)
        if "$(" in text2 or "`" in text2:
            results.append(Classification(D, "linux.nested-substitution", "중첩된 명령 치환은 정적으로 확정 불가", line, True))
        text = text2

    # 파이프로 셸에 넘기면 내용 확인 불가
    if re.search(r"\|\s*(busybox\s+)?(sh|ash|bash|hush|dash|ksh)\b", text):
        results.append(Classification(D, "linux.pipe-to-shell", "파이프로 셸에 명령을 전달 (내용 확인 불가)", line, True))

    for seg in split_outside_quotes(text, ["&&", "||", ";", "|", "&", "\n"]):
        seg_no_redir, targets = _extract_redirections(seg)
        for t in targets:
            results.append(_classify_write_target(t, policy, seg, "출력 리다이렉션"))
        tokens, bad = tokenize(seg_no_redir)
        if bad:
            results.append(Classification(D, "linux.unbalanced-quotes", "따옴표 불균형 — 명령 확정 불가", seg, True))
            continue
        if tokens and tokens[0] in ("if", "then", "else", "elif", "do", "while", "until", "for", "!", "{", "(", "case"):
            # 제어 구문 키워드 제거 후 나머지 분류
            while tokens and tokens[0] in ("if", "then", "else", "elif", "do", "while", "until", "!", "{", "("):
                tokens = tokens[1:]
            if tokens and tokens[0] in ("for", "case"):
                results.append(Classification(I, "linux.control", "제어 구문", seg))
                continue
        if not tokens or tokens[0] in ("fi", "done", "esac", "}", ")"):
            continue
        results.append(_classify_linux_command(tokens, seg, policy, _depth))
        moved, new_cwd = _cd_effect(_strip_wrappers(tokens)[0], policy.cwd)
        if moved:
            policy.cwd = new_cwd

    return worst(results, Classification(I, "linux.noop", "실행할 명령 없음", line))


# ---------------------------------------------------------------------------
# OpenOCD TCL
# ---------------------------------------------------------------------------

OPENOCD_COMMANDS: dict[str, Risk] = {
    # 조회
    "version": I, "help": I, "usage": I, "scan_chain": I, "targets": I, "mdw": I, "mdh": I, "mdb": I,
    "mdd": I, "read_memory": I, "poll": I, "echo": I, "capture": I, "puts": I, "set": I, "expr": I,
    "format": I, "list": I, "lindex": I, "llength": I, "lappend": I, "string": I, "return": I,
    "if": I, "else": I, "elseif": I, "while": I, "for": I, "foreach": I, "incr": I, "append": I,
    "catch": I, "info": I, "dict": I, "join": I, "split": I, "concat": I, "regexp": I, "regsub": I,
    "lsearch": I, "lrange": I, "lsort": I, "verify_image": I, "verify_image_checksum": I,
    "test_image": I, "sleep": I, "exit": I, "jtag_khz": M, "adapter_khz": M, "flush_count": I,
    "transport": I, "log_output": M, "debug_level": I, "measure_clk": I, "power": D,
    "fast_load": M, "fast_load_image": M, "bp": M, "rbp": M, "wp": M, "rwp": M, "halt": M, "resume": M,
    "step": M, "reset": M, "soft_reset_halt": M, "init": M, "shutdown": M, "reg": I, "arp_halt": M,
    "irscan": M, "drscan": M, "runtest": M, "pathmove": M, "statemove": M, "jtag_reset": M,
    "wait_halt": I, "virt2phys": I, "rtt": M,
    # 'profile <초> <파일> [시작 끝]': PC 샘플을 호스트 임의 경로 파일(gmon)로 기록 — dump_image 와 같은 호스트 파일 쓰기
    "profile": D,
    # 영구 변경 / 임의 쓰기
    "mww": D, "mwh": D, "mwb": D, "mwd": D, "write_memory": D, "load_image": D, "program": D,
    # Espressif OpenOCD 포크 전용 플래시 프로그래밍 proc (tcl/target/esp_common.cfg: reset init → flash write_image erase →
    # 선택적 verify/reset/shutdown). 아래 _OPENOCD_PROGRAM_PROC 이 다른 program_* 이름까지 같은 규칙으로 잡는다.
    "program_esp": D, "program_esp_bins": D, "program_esp32": D,
    "dump_image": D,  # 호스트 파일을 임의 경로에 씀 → 전용 도구 사용
    "fast_load_image_check": I,
    # 메타/간접 실행 (내용 확정 불가)
    "eval": D, "source": D, "proc": D, "uplevel": D, "upvar": D, "subst": D, "interp": D,
    "rename": D, "namespace": D, "apply": D, "after": D, "trace": D, "unknown": D, "exec": D,
    "open": D, "file": D, "add_script_search_dir": M, "find": I,
}

OPENOCD_SUBCOMMANDS: dict[str, dict[str, Risk]] = {
    "flash": {"banks": I, "list": I, "info": I, "probe": I, "read_bank": D, "verify_bank": I,
              "read_memory": I, "mdw": I, "mdh": I, "mdb": I, "mdd": I,
              "erase_check": I, "padded_value": M, "write_image": D, "write_bank": D,
              "erase_sector": D, "erase_address": D, "fillw": D, "fillh": D, "fillb": D,
              "filld": D, "fillwr": D, "protect": D, "_default": D, "_none": I},
    "nand": {"list": I, "info": I, "probe": I, "check_bad_blocks": I, "verify": I, "dump": D,
             "erase": D, "write": D, "raw_access": M, "_default": D, "_none": I},
    "jtag": {"names": I, "tapisenabled": I, "cget": I, "init": M, "arp_init": M, "arp_init-reset": M,
             "newtap": M, "configure": M, "tapenable": M, "tapdisable": M, "_default": M, "_none": I},
    "target": {"names": I, "current": I, "types": I, "count": I, "create": M, "_default": M, "_none": I},
    "adapter": {"name": I, "list": I, "transports": I, "speed": M, "driver": M, "assert": M,
                "deassert": M, "srst": M, "_default": M, "_none": I},
    "transport": {"list": I, "select": M, "_default": M, "_none": I},
    "arm": {"mrc": I, "mcr": M, "core_state": I, "disassemble": I, "reg": I, "semihosting": M, "_default": M, "_none": I},
    "mips32": {"cp0": I, "scan_delay": M, "_default": M, "_none": I},
    "reset_config": {"_default": M, "_none": I},
    # Espressif 'esp' 그룹 (업스트림 esp32/esp32s2/esp32s3 타깃 + Espressif 포크의 esp_flash.c/esp32_apptrace.c/esp_xtensa.c).
    # 표에 없는 하위 명령은 unknown_command_risk, 이름이 쓰기/지우기/퓨즈 꼴이면 DESTRUCTIVE(_TCL_DESTRUCTIVE_SUB).
    "esp": {
        # 트레이스를 호스트 파일(file://<경로>)·TCP(tcp://<호스트>:<포트>)로 기록 — status/stop 은 _OPENOCD_SUB_ACTIONS 로 낮춘다
        "apptrace": D, "sysview": D, "sysview_mcore": D,
        "gcov": D,  # 타깃 펌웨어가 보낸 경로·모드로 호스트 파일을 연다 (esp32_apptrace.c: fopen(fname, mode), '..' 검사 없음)
        "verify_bank_hash": M,  # 호스트 파일과 플래시의 SHA256 비교(읽기) — 타깃에서 해시 스텁을 실행한다
        "flash_stub_clock_boost": M,  # 스텁으로 CPU 클럭을 바꿈 (플래시는 건드리지 않음)
        "compression": M, "encrypt_binary": M, "stub_log": M, "appimage_offset": M, "semihost_basedir": M,  # 설정
        "process_lazy_breakpoints": M, "disable_lazy_breakpoints": M, "halted_event_handler": M,
        "stub_lib_test": M, "stub_apptrace_wr_test": M, "stub_apptrace_rd_test": M,  # 타깃에서 시험 스텁 실행
        "_none": I,
    },
    # Xtensa 코어 명령 (업스트림 xtensa.c). 나머지(maskisr, smpbreak, xtdef … 설정)는 unknown_command_risk.
    "xtensa": {"tracedump": D, "exe": D, "perfmon_dump": I, "_none": I},
}

# 인자 없이 쓰면 현재 값만 출력하는 조회 형태
_OPENOCD_QUERY_WHEN_BARE = {("adapter", "speed"), ("adapter", "driver"), ("transport", "select")}

# 두 번째 인자(동작)에 따라 위험도가 달라지는 하위 명령: 표에 있는 동작만 낮추고 start/dump 등은 표 값(DESTRUCTIVE) 그대로
_OPENOCD_TRACE_ACTIONS = {"status": I, "stop": M}
_OPENOCD_SUB_ACTIONS = {("esp", "apptrace"): _OPENOCD_TRACE_ACTIONS, ("esp", "sysview"): _OPENOCD_TRACE_ACTIONS,
                        ("esp", "sysview_mcore"): _OPENOCD_TRACE_ACTIONS}

_OPENOCD_TRACE_REASON = "트레이스를 호스트 파일(file://)·TCP 대상으로 기록 — 경로/주소를 서버가 관리하지 않음"
_OPENOCD_SUB_REASONS = {
    ("flash", "read_bank"): "호스트의 임의 경로에 파일을 기록 — 경로를 관리하는 openocd_flash_read 도구를 사용하세요",
    ("nand", "dump"): "호스트의 임의 경로에 파일을 기록 — 전용 도구를 사용하세요",
    ("esp", "apptrace"): _OPENOCD_TRACE_REASON,
    ("esp", "sysview"): _OPENOCD_TRACE_REASON,
    ("esp", "sysview_mcore"): _OPENOCD_TRACE_REASON,
    ("esp", "gcov"): "타깃 펌웨어가 정한 경로·모드로 호스트 파일을 열어 씀 (gcov 덤프)",
    ("xtensa", "tracedump"): "트레이스 메모리를 호스트 임의 경로 파일로 기록",
    ("xtensa", "exe"): "임의 Xtensa 명령어를 타깃에서 실행 — 메모리·레지스터 임의 변경 가능",
}

# 플래시 프로그래밍 proc: Espressif 포크 program_esp / program_esp_bins (예전 program_esp32), 그 밖의 program_* 이름
_OPENOCD_PROGRAM_PROC = re.compile(r"program_\w+")

# ESP 칩 명령 그룹 (esp32, esp32s2, esp32s3, esp32c2, esp32c3, esp32c5, esp32c6, esp32c61, esp32h2, esp32h4, esp32p4 …):
# '<칩> flashbootstrap …' / '<타깃> <칩> flashbootstrap …' 의 <칩> 자리
_ESP_CHIP_GROUP = re.compile(r"esp32(?:[a-z]\d+)?")

# semihosting 을 켜는 표준 proc (xPack/Espressif target/esp_common.cfg): examine-end 핸들러('arm semihosting enable')를
# 감싸지 않은 채 다시 설치한다 (configure_openocd_events → configure_event_examine_end, create_esp_target → configure_openocd_events).
# 이름에 'semihost' 가 들어 있는 명령/proc 도 같은 규칙으로 DESTRUCTIVE 다(_OPENOCD_SEMIHOST_NAME).
OPENOCD_SEMIHOST_PROCS = frozenset({"configure_event_examine_end", "configure_openocd_events", "create_esp_target"})
_OPENOCD_SEMIHOST_NAME = re.compile(r"semihost", re.I)

_TCL_DESTRUCTIVE_SUB = re.compile(
    r"^(mass_erase|chip_erase|chip-erase|erase.*|unlock|lock|options_write|options_load|otp.*|.*fuse.*|"
    r"program|write.*|fill.*|protect|gpnvm|set_security|bootloader|eeprom.*|mdm)$",
    re.I,
)


def _tcl_commands(text: str) -> list[list[str]]:
    """TCL 텍스트를 명령 단위(단어 리스트)로 대략 나눈다. 중괄호/대괄호 내부도 명령으로 취급."""
    # 주석 제거 (줄 시작의 #). Jim Tcl 의 줄 끝은 '\n' 뿐이다: splitlines() 는 \r \v \f \x1c-\x1e \x85   에서도
    # 끊어 '#' 뒤에 숨긴 명령을 주석으로 지워 버리므로 쓰지 않는다.
    lines = [ln for ln in text.split("\n") if not ln.strip().startswith("#")]
    text = "\n".join(lines)
    chunks = re.split(r"[;\n\[\]{}]", text)
    cmds: list[list[str]] = []
    for chunk in chunks:
        words = re.findall(r'"[^"]*"|\S+', chunk)
        words = [w.strip('"') for w in words]
        if words:
            cmds.append(words)
    return cmds


def classify_openocd(text: str, *, unknown_risk: str | Risk = "modify") -> Classification:
    """OpenOCD TCL 명령(문자열)을 분류.

    단어 단위의 근사 분류기라 이것만으로는 Jim Tcl 의 모든 실행 경로를 다루지 못한다
    (따옴표 안 줄바꿈 뒤의 '#', 식 이중 치환 ``expr $x``, ``-event`` 핸들러, catch 옵션, ``-command`` 접두어 등).
    기기에 보내는 명령은 반드시 Tcl 파서를 가진 ``openocd_mcp.guard.classify_command`` (= 이 함수와 로컬 규칙 중
    더 엄격한 쪽)를 거친다.
    """
    unknown = _risk_from_setting(unknown_risk)
    stripped = text.strip()
    if not stripped:
        return Classification(O, "openocd.empty", "빈 명령")
    results: list[Classification] = []
    for words in _tcl_commands(stripped):
        cmd = words[0]
        args = words[1:]
        if cmd.startswith("ocd_"):
            cmd = cmd[4:]
        if cmd.startswith("$"):
            results.append(Classification(D, "openocd.indirect", "명령 위치에 변수가 있어 확정 불가", " ".join(words), True))
            continue
        if re.fullmatch(r"[-+]?(0x[0-9a-fA-F]+|\d+)|[<>=!&|+\-*/%()]+|else|elseif|then", cmd):
            continue  # 표현식 조각
        # ESP32 플래시 전압 스트랩: '<칩> flashbootstrap 1.8|3.3|none' / '<타깃> <칩> flashbootstrap …' (업스트림 esp32.c — TMS
        # 유휴 상태가 리셋 때 플래시 전압 선택). 칩 이름(esp32 …)은 단일 코어 cfg 의 점 없는 타깃 이름이기도 해서 하위 명령 표로
        # 만들지 않고, 바로 앞 단어가 ESP 칩 그룹일 때만 이 명령으로 본다. 여기서 끝내지 않는다(continue 없음): 아래 표·명령
        # 규칙도 그대로 적용해 worst 로 정한다 ('program flashbootstrap', 'load_image flashbootstrap' 은 여전히 DESTRUCTIVE).
        fb = next((i for i in (1, 2) if i < len(words) and words[i] == "flashbootstrap" and _ESP_CHIP_GROUP.fullmatch(words[i - 1])), None)
        if fb is not None:
            if len(words) > fb + 1:
                results.append(Classification(D, "openocd.esp.flashbootstrap",
                                              "ESP32 플래시 전압 스트랩 설정 — 1.8V 플래시에 3.3V 를 주는 등 하드웨어 손상 가능", " ".join(words)))
            else:
                results.append(Classification(I, "openocd.esp.flashbootstrap.query", "플래시 전압 스트랩 설정 조회", " ".join(words)))
        # semihosting 을 켜는 proc (표준 ESP proc, 이름에 semihost) — 표에 없는 이름이라 DESTRUCTIVE 로 끝낸다(더 위험한 분류는 없다)
        if cmd in OPENOCD_SEMIHOST_PROCS:
            results.append(Classification(D, "openocd.esp.semihosting-proc",
                                          f"'{cmd}' — ESP 표준 proc: semihosting 을 켜는 examine-end 핸들러를 감싸지 않은 채 다시 설치함", " ".join(words)))
            continue
        if _OPENOCD_SEMIHOST_NAME.search(cmd):
            results.append(Classification(D, "openocd.semihosting-proc",
                                          f"'{cmd}' — 이름으로 보아 semihosting 을 켜거나 바꾸는 proc/명령", " ".join(words)))
            continue
        # 트레이스(TPIU/SWO) 출력 대상: '<tpiu|swo> create … -output <파일|:포트|->', '<이름> configure -output …',
        # 옛 'tpiu config internal <파일|:포트|-> …' — 호스트 임의 경로 파일 쓰기/TCP 포트 열기 (dump_image 와 같은 부류)
        if (cmd in ("tpiu", "swo") or (args and args[0] in ("configure", "create"))) and "-output" in args[:-1]:
            results.append(Classification(D, "openocd.trace.output",
                                          "트레이스(TPIU/SWO) 출력을 호스트 임의 경로 파일·TCP 포트로 보냄 — 경로를 서버가 관리하지 않음", " ".join(words)))
        if cmd == "tpiu" and len(args) >= 3 and args[0] == "config" and args[1] == "internal":
            results.append(Classification(D, "openocd.tpiu.config.internal",
                                          "TPIU 트레이스를 호스트 임의 경로 파일·TCP 포트로 기록 (tpiu config internal)", " ".join(words)))
        # target 이름 접두 (예: stm32f1x.cpu mww 0x0 0) → 두 번째 단어를 명령으로
        if "." in cmd and args and (args[0] in OPENOCD_COMMANDS or args[0] in OPENOCD_SUBCOMMANDS):
            cmd, args = args[0], args[1:]
        if cmd in OPENOCD_SUBCOMMANDS:
            table = OPENOCD_SUBCOMMANDS[cmd]
            if not args:
                results.append(Classification(table.get("_none", I), f"openocd.{cmd}", f"{cmd} (인자 없음)", " ".join(words)))
                continue
            sub = args[0]
            if len(args) == 1 and (cmd, sub) in _OPENOCD_QUERY_WHEN_BARE:
                results.append(Classification(I, f"openocd.{cmd}.{sub}.query", f"{cmd} {sub} (조회)", " ".join(words)))
                continue
            actions = _OPENOCD_SUB_ACTIONS.get((cmd, sub))
            if actions and len(args) >= 2 and args[1] in actions:
                results.append(Classification(actions[args[1]], f"openocd.{cmd}.{sub}.{args[1]}", f"{cmd} {sub} {args[1]}", " ".join(words)))
                continue
            sub_risk = table.get(sub)
            if sub_risk is None:
                sub_risk = D if _TCL_DESTRUCTIVE_SUB.match(sub) else table.get("_default", unknown)
            reason = _OPENOCD_SUB_REASONS.get((cmd, sub), f"{cmd} {sub}")
            if sub_risk >= D and (cmd, sub) not in _OPENOCD_SUB_REASONS:
                reason += " — 플래시/저장장치 영구 변경 가능"
            results.append(Classification(sub_risk, f"openocd.{cmd}.{sub}", reason, " ".join(words)))
            continue
        if _OPENOCD_PROGRAM_PROC.fullmatch(cmd):
            esp = cmd.startswith("program_esp")
            reason = ("Espressif 포크의 플래시 프로그래밍 proc — reset init 후 플래시를 지우고 쓴다(선택적으로 verify/reset/shutdown)" if esp
                      else f"'{cmd}' — 플래시 프로그래밍 proc 계열(program_*)로 보아 영구 변경 가능")
            results.append(Classification(D, "openocd.flash.program_esp" if esp else "openocd.flash.program_proc", reason, " ".join(words)))
            continue
        if cmd == "reg":
            # reg <name> <value> 는 레지스터 쓰기
            risk = M if len(args) >= 2 else I
            results.append(Classification(risk, "openocd.reg.write" if risk == M else "openocd.reg", "레지스터 쓰기" if risk == M else "레지스터 조회", " ".join(words)))
            continue
        if cmd == "targets":
            results.append(Classification(I, "openocd.targets", "타깃 목록/선택", " ".join(words)))
            continue
        if cmd in OPENOCD_COMMANDS:
            risk = OPENOCD_COMMANDS[cmd]
            reason = {
                "mww": "임의 메모리/MMIO 쓰기",
                "mwh": "임의 메모리/MMIO 쓰기",
                "mwb": "임의 메모리/MMIO 쓰기",
                "mwd": "임의 메모리/MMIO 쓰기",
                "write_memory": "임의 메모리/MMIO 쓰기",
                "load_image": "타깃 메모리에 이미지 기록",
                "program": "플래시 프로그래밍",
                "dump_image": "호스트 임의 경로에 파일 기록 — openocd_dump_memory 도구를 사용",
                "profile": "PC 샘플을 호스트 임의 경로 파일(gmon)로 기록",
                "power": "타깃 전원 제어",
            }.get(cmd, f"'{cmd}'")
            uncertain = cmd in ("eval", "source", "proc", "uplevel", "upvar", "subst", "interp", "rename", "namespace", "apply", "after", "trace", "unknown", "exec")
            results.append(Classification(risk, f"openocd.{cmd}", reason + (" (내용 확정 불가)" if uncertain else ""), " ".join(words), uncertain))
            continue
        # 알 수 없는 벤더 플래시 드라이버 명령 (stm32f1x unlock 등)
        if args and _TCL_DESTRUCTIVE_SUB.match(args[0]):
            results.append(Classification(D, f"openocd.vendor.{cmd}.{args[0]}", f"벤더 명령 '{cmd} {args[0]}' — 플래시/보안 설정 영구 변경 가능", " ".join(words)))
            continue
        if re.search(r"(fuse|otp|mass_erase|chip_erase)", cmd, re.I):
            results.append(Classification(D, f"openocd.vendor.{cmd}", f"'{cmd}' — 영구 변경 가능", " ".join(words)))
            continue
        results.append(Classification(unknown, "openocd.unknown", f"분류 규칙에 없는 OpenOCD 명령 '{cmd}'", " ".join(words)))
    return worst(results, Classification(O, "openocd.noop", "실행할 명령 없음"))


# ---------------------------------------------------------------------------
# 콘솔 줄 조립 (분할 쓰기/줄 편집 우회 방지)
# ---------------------------------------------------------------------------


@dataclass
class AssembledLine:
    text: str
    uncertain: bool
    reason: str | None
    terminator: str


class LineAssembler:
    """원시 바이트 쓰기를 기기 측 라인 버퍼처럼 조립한다.

    에이전트가 "sf er" 와 "ase 0 100\\n" 을 나눠 보내도 줄 끝(CR/LF)에서 완성된 한 줄로 분류할 수 있게 한다.
    Ctrl-C/Ctrl-U 는 줄을 버리고, Backspace/DEL/Ctrl-W 는 편집을 반영한다.
    Tab(자동완성), ESC 시퀀스(방향키/히스토리), 기타 제어문자가 섞이면 실제 실행될 명령을 확정할 수 없으므로
    uncertain 으로 표시한다.
    """

    def __init__(self) -> None:
        self._buf: list[str] = []
        self._uncertain_reason: str | None = None
        self._in_escape = False
        self._esc_len = 0
        self._last_term: str | None = None

    @property
    def pending(self) -> str:
        return "".join(self._buf)

    @property
    def pending_uncertain(self) -> str | None:
        return self._uncertain_reason

    def reset(self) -> None:
        self._buf = []
        self._uncertain_reason = None
        self._in_escape = False

    def mark_uncertain(self, reason: str) -> bool:
        """기기가 앞서 보낸 입력의 일부를 소비했거나 버렸을 수 있을 때 남은 입력을 uncertain 으로 표시한다.

        표시된 뒤 완성되는 줄은 uncertain 이 되고, Ctrl-C/Ctrl-U 로 비우면 풀린다. 이미 표시돼 있으면 그대로 두고 False.
        """
        if self._uncertain_reason is not None:
            return False
        self._uncertain_reason = reason
        return True

    def feed(self, data: str) -> list[AssembledLine]:
        done: list[AssembledLine] = []
        for ch in data:
            if self._in_escape:
                # CSI: ESC [ ... (0x40-0x7E 로 끝남). SS3: ESC O x. 그 외 ESC x.
                if ch in "[O" and self._esc_len == 1:
                    self._esc_len += 1
                    continue
                self._esc_len += 1
                if "\x40" <= ch <= "\x7e" or self._esc_len > 16:
                    self._in_escape = False
                continue
            if ch in ("\r", "\n"):
                if ch == "\n" and self._last_term == "\r" and not self._buf and self._uncertain_reason is None:
                    self._last_term = ch
                    continue
                done.append(AssembledLine("".join(self._buf), self._uncertain_reason is not None, self._uncertain_reason, ch))
                self._buf = []
                self._uncertain_reason = None
                self._last_term = ch
                continue
            self._last_term = None
            if ch in ("\x03", "\x15"):  # Ctrl-C, Ctrl-U: 줄 버림
                self._buf = []
                self._uncertain_reason = None
            elif ch in ("\x08", "\x7f"):
                if self._buf:
                    self._buf.pop()
            elif ch == "\x17":  # Ctrl-W: 단어 삭제
                while self._buf and self._buf[-1] == " ":
                    self._buf.pop()
                while self._buf and self._buf[-1] != " ":
                    self._buf.pop()
            elif ch == "\t":
                self._uncertain_reason = "탭(자동완성)이 포함되어 실제 명령을 확정할 수 없음"
                self._buf.append(" ")
            elif ch == "\x1b":
                self._in_escape = True
                self._esc_len = 1
                self._uncertain_reason = "ESC 시퀀스(방향키/히스토리 호출 등)가 포함되어 실제 명령을 확정할 수 없음"
            elif ord(ch) < 0x20:
                self._uncertain_reason = f"제어 문자 0x{ord(ch):02x} 가 포함되어 실제 명령을 확정할 수 없음"
            else:
                self._buf.append(ch)
        return done


CONTROL_CHAR_RISK: dict[str, tuple[Risk, str]] = {
    "\x03": (I, "Ctrl-C (인터럽트/줄 취소)"),
    "\x04": (M, "Ctrl-D (EOF — 셸 종료 가능)"),
    "\x1a": (M, "Ctrl-Z (작업 일시정지)"),
    "\x1c": (M, "Ctrl-\\ (SIGQUIT)"),
    "\x15": (I, "Ctrl-U (줄 지우기)"),
}


def classify_console_line(
    line: str,
    context: str,
    *,
    uboot_ctx: UBootContext | None = None,
    persistent_paths: Iterable[str] = (),
    unknown_risk: str | Risk = "modify",
    cwd: str | None = None,
) -> Classification:
    """콘솔 문맥(uboot / linux-shell / login / unknown 등)에 따라 분류기를 선택. cwd 는 리눅스 해석에만 쓴다."""
    ctx = (context or "unknown").lower()
    if ctx == "uboot":
        return classify_uboot(line, ctx=uboot_ctx, unknown_risk=unknown_risk)
    if ctx in ("linux-shell", "linux", "shell"):
        return classify_linux(line, persistent_paths=persistent_paths, unknown_risk=unknown_risk, cwd=cwd)
    if ctx in ("login", "linux-login", "password"):
        return Classification(I, "console.login-input", "로그인 프롬프트 입력(계정/비밀번호)", line)
    # 알 수 없는 문맥: 두 분류기 중 더 위험한 쪽
    a = classify_uboot(line, ctx=uboot_ctx, unknown_risk=unknown_risk)
    b = classify_linux(line, persistent_paths=persistent_paths, unknown_risk=unknown_risk, cwd=cwd)
    w = a if a.risk >= b.risk else b
    return Classification(w.risk, f"console.unknown-context>{w.rule_id}", f"콘솔 문맥 미확정(U-Boot/Linux 둘 다 고려): {w.reason}", w.matched, w.uncertain)
