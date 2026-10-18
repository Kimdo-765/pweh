"""U-Boot 콘솔 흉내.

출력 형식과 동작은 프로필의 ``uboot.dialect`` 가 가리키는 실제 U-Boot 베이스 버전 소스를 따른다:

- 명령 줄 편집: common/main.c ``cread_line`` (에코, Backspace="\\b \\b", Ctrl-C 는 에코 없이 -1 반환,
  ``\\r`` 과 ``\\n`` 은 각각 Enter, 히스토리, 줄 길이 CONFIG_SYS_CBSIZE 초과 시 BEL)
- simple 파서 (2010.06 run_command / 2013.07 builtin_run_command): 작은따옴표만 인용, ``;`` 분리
  (토큰 맨 앞의 ``;`` 와 ``\\;`` 는 분리자가 아님), ``$(var)``/``${var}`` 치환, 공백 분리,
  실패한 명령이 있으면 줄 전체가 반복 불가, 빈 Enter 는 직전 명령을 CMD_FLAG_REPEAT 로 반복,
  Ctrl-C 뒤에도 직전 명령은 기억됨.
- hush 파서 (2016.11 cli_hush.c): 작은/큰따옴표, ``$var``/``${var}``, ``;`` ``&&`` ``||``, if/for/while,
  지역 변수 대입, 미완성 입력은 PS2 프롬프트로 이어 받기, Ctrl-C/구문 오류/반복 불가 명령이 반복 상태를 지움.
- 명령 약어: common/command.c ``find_cmd_tbl`` (``.`` 앞까지 비교, 유일 접두어만 허용)
- 명령 출력 형식: cmd_mem.c(md/mw/cp/cmp/crc32/base), display_options.c(print_buffer/print_size),
  cmd_sf.c(벤더별), cmd_nvedit.c(printenv/setenv/saveenv/env), cmd_bdinfo.c, cmd_bootm.c/image.c, hash.c
"""

from __future__ import annotations

import gzip
import lzma
import re
import struct
import time
import zlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable

from ..formats import UIMAGE_MAGIC, build_uboot_env, parse_mtdparts, parse_uboot_env
from .device import RX_DROP, RX_UART, ResetEvent
from .fmt import c_hash_x, print_buffer_lines, print_size, ultohstr
from .memory import ADDR_MASK, parse_hex_strict, simple_strtoul

if TYPE_CHECKING:  # pragma: no cover
    from .device import MockDevice

CMD_FLAG_REPEAT = 0x0001
USAGE = "usage"  # 핸들러가 이 값을 돌려주면 cmd_usage 출력 (CMD_RET_USAGE)

_ARCH_NAMES = {2: "ARM", 5: "MIPS", 22: "AArch64"}
_OS_NAMES = {5: "Linux", 17: "U-Boot"}
_TYPE_NAMES = {1: "Standalone Program", 2: "Kernel Image", 3: "RAMDisk Image", 4: "Multi-File Image",
               5: "Firmware", 6: "Script", 7: "Filesystem Image", 8: "Flat Device Tree"}
_COMP_NAMES = {0: "uncompressed", 1: "gzip compressed", 2: "bzip2 compressed", 3: "lzma compressed",
               4: "lzo compressed", 5: "lz4 compressed"}
_ARCH_FROM_PROFILE = {"arm": 2, "mips": 5}


@dataclass
class BootKernel:
    """bootm 이 커널로 제어를 넘길 때 리눅스 흉내에 전달하는 정보."""

    bootargs: str
    image_name: str
    load_addr: int
    entry: int
    data_size: int
    comp: str


@dataclass
class UCommand:
    name: str
    maxargs: int
    repeatable: bool
    func: Callable[..., Any]
    usage: str
    help: str | None = None


class _HushIncomplete(Exception):
    pass


class _HushSyntax(Exception):
    pass


# ---------------------------------------------------------------------------
# 명령 사용법 문자열 (U_BOOT_CMD 의 usage/help 원문)
# ---------------------------------------------------------------------------

_MD_USAGE = "[.b, .w, .l] address [# of objects]"
_SF_HELP_2010 = (
    "probe [bus:]cs [hz] [mode]\t- init flash device on given SPI bus\n"
    "\t\t\t\t  and chip select\n"
    "sf read addr offset len\t- read `len' bytes starting at\n"
    "\t\t\t\t  `offset' to memory at `addr'\n"
    "sf write addr offset len\t- write `len' bytes from memory\n"
    "\t\t\t\t  at `addr' to flash at `offset'\n"
    "sf erase offset len\t\t- erase `len' bytes from `offset'"
)
_SF_HELP_2013 = (
    "probe [[bus:]cs] [hz] [mode]\t- init flash device on given SPI bus\n"
    "\t\t\t\t  and chip select\n"
    "sf read addr offset len \t- read `len' bytes starting at\n"
    "\t\t\t\t  `offset' to memory at `addr'\n"
    "sf write addr offset len\t- write `len' bytes from memory\n"
    "\t\t\t\t  at `addr' to flash at `offset'\n"
    "sf erase offset [+]len\t\t- erase `len' bytes from `offset'\n"
    "\t\t\t\t  `+len' round up `len' to block size\n"
    "sf update addr offset len\t- erase and write `len' bytes from memory\n"
    "\t\t\t\t  at `addr' to flash at `offset'"
)
_PRINTENV_HELP_2013 = ("[-a]\n    - print [all] values of all environment variables\n"
                       "printenv name ...\n    - print value of environment variable 'name'")
_SETENV_HELP_2013 = ("[-f] name value ...\n    - [forcibly] set environment variable 'name' to 'value ...'\n"
                     "setenv [-f] name\n    - [forcibly] delete environment variable 'name'")
_ENV_HELP = ("default [-f] -a - [forcibly] reset default environment\n"
             "env default [-f] var [...] - [forcibly] reset variable(s) to their default values\n"
             "env delete [-f] var [...] - [forcibly] delete variable(s)\n"
             "env print [-a | name ...] - print environment\n"
             "env run var [...] - run commands in an environment variable\n"
             "env save - save environment\n"
             "env set [-f] name [arg ...]\n")
_BOOTM_HELP = ("[addr [arg ...]]\n    - boot application image stored in memory\n"
               "\tpassing arguments 'arg ...'; when booting a Linux kernel,\n"
               "\t'arg' can be the address of an initrd image\n")
_NET_HELP = "[loadAddress] [[hostIPaddr:]bootfilename]"


class UBoot:
    """한 번의 부팅 동안의 U-Boot 상태 (env, sf probe 여부, md 의 직전 인자, 히스토리 ...)."""

    def __init__(self, dev: "MockDevice") -> None:
        self.dev = dev
        self.prof = dev.profile
        self.ub: dict[str, Any] = dev.profile["uboot"]
        self.dialect: str = self.ub["dialect"]
        self.little = dev.profile.get("endianness", "little") == "little"
        self.env: dict[str, str] = {}
        self.env_valid = False
        self.local_vars: dict[str, str] = {}
        self.history: list[str] = []
        self.flash_probed = False
        self.dp_last_addr = 0
        self.dp_last_size = 4
        self.dp_last_length = 0x40
        self.mm_last_addr = 0
        self.mm_last_size = 4
        self.base_address = 0
        self.had_ctrlc = False
        self.flag_repeat = False
        self.last_return_code = 0
        self.run_depth = 0
        self.sim_clock = 0.0
        self.cur_destructive: dict[str, Any] | None = None
        self.prompt: str = self.ub["prompt"]
        self.commands = self._build_commands()

    # ------------------------------------------------------------------
    # 출력/시간 헬퍼
    # ------------------------------------------------------------------
    def out(self, text: str) -> None:
        self.dev.write(text)

    def t(self, key: str, default: float) -> float:
        return float((self.ub.get("timings") or {}).get(key, default))

    def busy(self, seconds: float, *, ctrlc_poll: bool = False) -> bool:
        """기기 시간으로 seconds 만큼 일한다 (실제 대기는 × time_scale). sim_clock 은 결정적 소요 시간 표시용."""
        if seconds <= 0:
            return self.dev.ctrlc() if ctrlc_poll else False
        self.sim_clock += seconds
        return self.dev.sleep(seconds, ctrlc_poll=ctrlc_poll)

    def mark_destructive(self, op: str, **detail: Any) -> None:
        """현재 명령의 파괴적 이벤트를 '실제로 적용됨'으로 갱신 (없으면 새로 기록)."""
        ev = self.cur_destructive
        if ev is None:
            self.cur_destructive = self.dev.record_destructive(op, applied=True, **detail)
            return
        ev["op"] = op
        ev.setdefault("applied", False)
        detail.setdefault("applied", True)
        ev.update(detail)

    def ctrlc(self) -> bool:
        if self.dev.ctrlc():
            self.had_ctrlc = True
            return True
        return False

    def version_string(self) -> str:
        return f"{self.ub.get('version', 'U-Boot')}{self.ub.get('version_tag', '') or ''}"

    # ------------------------------------------------------------------
    # 부팅
    # ------------------------------------------------------------------
    def run(self) -> BootKernel | None:
        dev = self.dev
        dev.set_rx_mode(RX_DROP)
        dev.set_state("bootrom")
        dev.sleep(self.t("bootrom", 0.2))
        spl = self.ub.get("spl_banner")
        if spl:
            self._emit_template(spl, self.t("spl_line", 0.002))
        self._load_env()
        self._emit_template(self.ub.get("banner") or "", self.t("banner_line", 0.004))
        # console_init_r: stdin/stdout/stderr 등 실행 중에 정해지는 변수
        for k, v in (self.ub.get("runtime_env") or {}).items():
            self._env_set(k, v.replace("{version}", self.version_string()))
        self._apply_env_baud()
        dev.set_rx_mode(RX_UART)
        dev.set_state("uboot-autoboot")
        try:
            s = self.env.get("bootdelay")
            if s is None:
                bootdelay = int(self.ub["autoboot"].get("delay", 1))
            else:
                bootdelay = _simple_strtol10(s)
            bootcmd = self.env.get("bootcmd")
            if bootdelay >= 0 and bootcmd and not self._abortboot(bootdelay):
                self.dev.enter_busy()
                self.dev.record({"type": "autoboot", "bootcmd": bootcmd})
                if self.dialect == "hisilicon-2010":
                    self.run_command_simple(bootcmd, 0)
                else:
                    self.run_command_list(bootcmd, 0)
            dev.set_state("uboot")
            if self.ub["parser"] == "hush":
                self._cli_loop_hush()
            else:
                self._cli_loop_simple()
        except _BootHandoff as h:
            return h.kernel
        return None

    def _emit_template(self, template: str, line_delay: float) -> None:
        env_warning = self._env_warning_text() if "{env_warning}" in template else ""
        lines = template.split("\n")
        if template.endswith("\n"):
            lines = lines[:-1]
        for line in lines:
            if line.strip() == "{env_warning}":
                # 단독 줄 자리표시자: (probe 가 남긴) 빈 줄 + 경고 + 빈 줄
                self.out("\n" + env_warning if env_warning else "\n")
                continue
            text = (line.replace("{version}", self.ub.get("version", ""))
                    .replace("{version_tag}", self.ub.get("version_tag", "") or "")
                    .replace("{spl_version}", self.ub.get("spl_version", ""))
                    .replace("{env_warning}", env_warning))
            self.out(text + "\n")
            if line_delay:
                self.dev.sleep(line_delay)

    def _apply_env_baud(self) -> None:
        b = self.env.get("baudrate")
        if b:
            try:
                val = int(b, 10)
            except ValueError:
                return
            if val > 0 and val != self.dev.baud:
                self.dev.set_baud(val)

    def _abortboot(self, bootdelay: int) -> bool:
        ab = self.ub["autoboot"]
        keys = ab.get("keys")
        if ab.get("mode", "any-key") == "keyed":
            return self._abortboot_keyed(bootdelay)
        dev = self.dev

        def accept(c: int) -> bool:
            return keys is None or chr(c) in keys

        self.out(ab.get("prompt", "Hit any key to stop autoboot: %2d ") % bootdelay)
        abort = False
        if ab.get("zero_check", True) and bootdelay >= 0 and dev.tstc():
            c = dev.getc(0, reading=False)
            if c is not None and accept(c):
                self.out("\b\b\b 0")
                abort = True
        step = max(1.0 * dev.time_scale, dev.autoboot_floor)
        while bootdelay > 0 and not abort:
            bootdelay -= 1
            end = time.monotonic() + step
            while not abort:
                if dev.tstc():
                    c = dev.getc(0, reading=False)
                    if c is not None and accept(c):
                        abort = True
                        bootdelay = 0
                        break
                if time.monotonic() >= end:
                    break
                dev.sleep(0.01)
            self.out("\b\b\b%2d " % bootdelay)
        self.out("\n")
        if abort:
            dev.record({"type": "autoboot_interrupted"})
        return abort

    def _abortboot_keyed(self, bootdelay: int) -> bool:
        ab = self.ub["autoboot"]
        prompt = ab.get("prompt") or ""
        if prompt:
            self.out(prompt % bootdelay if "%" in prompt else prompt)
        stops = [s.encode("latin-1").decode("unicode_escape") if "\\" in s else s
                 for s in ([ab.get("stop_str")] if ab.get("stop_str") else []) + list(ab.get("keys") or [])]
        pressed = ""
        end = time.monotonic() + bootdelay * max(self.dev.time_scale, self.dev.autoboot_floor)
        while time.monotonic() < end or self.dev.tstc():
            if self.dev.tstc():
                c = self.dev.getc(0, reading=False)
                if c is None:
                    continue
                pressed = (pressed + chr(c))[-32:]
                if any(s and pressed.endswith(s) for s in stops):
                    self.dev.record({"type": "autoboot_interrupted"})
                    return True
            else:
                self.dev.sleep(0.01)
        return False

    # ------------------------------------------------------------------
    # 환경 변수
    # ------------------------------------------------------------------
    def _load_env(self) -> None:
        off = self.ub["env_offset"]
        size = self.ub["env_size"]
        try:
            block = self.dev.flash.read(off, size)
        except ValueError:
            block = b""
        res = parse_uboot_env(block) if block else None
        self.env_auto_write = False
        if res and (not self.ub.get("env_redundant") or res["redundant"]) and res["env"]:
            self.env = dict(res["env"])
            self.env_valid = True
        else:
            self.env = dict(self.ub.get("default_env") or {})
            self.env_valid = False
            # HiSilicon V1~V3 env_sf.c: CRC 워드가 0xFFFFFFFF(지워진 플래시)면 기본 env 를 스스로 플래시에 쓴다
            self.env_auto_write = self.dialect == "hisilicon-2010" and block[:4] == b"\xff\xff\xff\xff"
        self.dev.record({"type": "env_loaded", "valid": self.env_valid, "vars": len(self.env)})

    def _env_warning_text(self) -> str:
        if self.env_valid:
            return ""
        text = "*** Warning - bad CRC, using default environment\n\n"
        if self.env_auto_write:
            self.env_auto_write = False
            off = self.ub["env_offset"]
            size = self.ub["env_size"]
            fl = self.dev.flash
            erase_len = max(size, fl.erase_size)
            text += "*** Write default environment to flash\n"
            text += f"Erasing SPI flash, offset 0x{off:08x} size {ultohstr(erase_len)} ..."
            text += f"done\nWriting to SPI flash, offset 0x{off:08x} size {ultohstr(size)} ...done\n"
            fl.erase(off, erase_len)
            fl.program(off, self.env_block())
            self.dev.record({"type": "device_autonomous_write", "what": "default environment", "offset": off,
                             "size": size, "note": "HiSilicon 2010.06 env_sf.c 동작 (사람/에이전트 입력 없음)"})
        return text

    def _env_set(self, name: str, value: str | None) -> None:
        if self.ub["printenv_order"] == "insertion":
            # 2010.06: 기존 항목을 지우고 끝에 덧붙인다
            self.env.pop(name, None)
            if value is not None:
                self.env[name] = value
        else:
            if value is None:
                self.env.pop(name, None)
            else:
                self.env[name] = value

    def getenv(self, name: str) -> str | None:
        return self.env.get(name)

    def _env_items_for_print(self) -> list[tuple[str, str]]:
        items = list(self.env.items())
        if self.ub["printenv_order"] == "sorted":
            items.sort(key=lambda kv: kv[0].encode("latin-1", "replace"))
        return items

    def _env_data_size(self) -> int:
        size = self.ub["env_size"] - (5 if self.ub.get("env_redundant") else 4)
        return size

    def env_block(self) -> bytes:
        items = self._env_items_for_print() if self.ub["printenv_order"] == "sorted" else list(self.env.items())
        return build_uboot_env(dict(items), size=self.ub["env_size"], redundant=bool(self.ub.get("env_redundant")))

    # ------------------------------------------------------------------
    # 명령 표
    # ------------------------------------------------------------------
    def _build_commands(self) -> dict[str, UCommand]:
        d = self.dialect
        lh = bool(self.ub["longhelp"])
        maxargs = int(self.ub["maxargs"])
        defs: list[UCommand] = [
            UCommand("?", maxargs, True, self.do_help, "alias for 'help'", "" if lh else None),
            UCommand("help", maxargs, True, self.do_help, "print command description/usage",
                     "\n\t- print brief description of all commands\nhelp command ...\n\t- print detailed usage of 'command'"),
            UCommand("version", 1, True, self.do_version,
                     "print monitor version" if d == "hisilicon-2010" else "print monitor, compiler and linker version", ""),
            UCommand("bdinfo", 1, True, self.do_bdinfo, "print Board Info structure", ""),
            UCommand("printenv", maxargs, True, self.do_printenv, "print environment variables",
                     "\n    - print values of all environment variables\nprintenv name ...\n    - print value of environment variable 'name'"
                     if d == "hisilicon-2010" else _PRINTENV_HELP_2013),
            UCommand("setenv", maxargs, False, self.do_setenv, "set environment variables",
                     "name value ...\n    - set environment variable 'name' to 'value ...'\nsetenv name\n    - delete environment variable 'name'"
                     if d == "hisilicon-2010" else _SETENV_HELP_2013),
            UCommand("saveenv", 1, False, self.do_saveenv, "save environment variables to persistent storage", ""),
            UCommand("env", maxargs, True, self.do_env, "environment handling commands", _ENV_HELP),
            UCommand("sf", 5, True, self.do_sf, "SPI flash sub-system",
                     _SF_HELP_2010 if d == "hisilicon-2010" else _SF_HELP_2013),
            UCommand("md", 3, True, self.do_md, "memory display", _MD_USAGE),
            UCommand("mm", 2, True, self.do_mm, "memory modify (auto-incrementing address)", "[.b, .w, .l] address"),
            UCommand("nm", 2, True, self.do_nm, "memory modify (constant address)", "[.b, .w, .l] address"),
            UCommand("mw", 4, True, self.do_mw, "memory write (fill)", "[.b, .w, .l] address value [count]"),
            UCommand("cp", 4, True, self.do_cp, "memory copy", "[.b, .w, .l] source target count"),
            UCommand("cmp", 4, True, self.do_cmp, "memory compare", "[.b, .w, .l] addr1 addr2 count"),
            UCommand("crc32", 4, True, self.do_crc32, "checksum calculation",
                     "address count [addr]\n    - compute CRC32 checksum [save at addr]"),
            UCommand("base", 2, True, self.do_base, "print or set address offset",
                     "\n    - print address offset for memory commands\nbase off\n    - set address offset for memory commands to 'off'"),
            UCommand("loop", 3, True, self.do_loop, "infinite loop on address range", "[.b, .w, .l] address number_of_objects"),
            UCommand("mtest", 5, True, self.do_mtest, "simple RAM read/write test", "[start [end [pattern [iterations]]]]"),
            UCommand("mtdparts", 6, False, self.do_mtdparts, "define flash/nand partitions",
                     "\n    - list partition table\nmtdparts delall\n    - delete all partitions"),
            UCommand("boot", 1, True, self.do_boot, "boot default, i.e., run 'bootcmd'", ""),
            UCommand("bootd", 1, True, self.do_boot, "boot default, i.e., run 'bootcmd'", ""),
            UCommand("bootm", maxargs, True, self.do_bootm, "boot application image from memory", _BOOTM_HELP),
            UCommand("iminfo", maxargs, True, self.do_iminfo, "print header information for application image",
                     "addr [addr ...]\n    - print header information for application image starting at\n"
                     "      address 'addr' in memory; this includes verification of the\n"
                     "      image contents (magic number, header and payload checksums)"),
            UCommand("go", maxargs, True, self.do_go, "start application at address 'addr'",
                     "addr [arg ...]\n    - start application at address 'addr'\n      passing 'arg' as arguments"),
            UCommand("reset", 1, False, self.do_reset, "Perform RESET of the CPU", ""),
            UCommand("run", maxargs, True, self.do_run, "run commands in an environment variable",
                     "var [...]\n    - run the commands in the environment variable(s) 'var'"),
            UCommand("echo", maxargs, True, self.do_echo, "echo args to console",
                     "[args..]\n    - echo args to console; \\c suppresses newline"),
            UCommand("sleep", 2, True, self.do_sleep, "delay execution for some time",
                     "N\n    - delay execution for N seconds (N is _decimal_ !!!)"),
            UCommand("coninfo", 3, True, self.do_coninfo, "print console devices and information", ""),
            UCommand("tftpboot", 3 if d != "hisilicon-2010" else 4, True, self.do_tftp,
                     "boot image via network using TFTP protocol" if d != "hisilicon-2010"
                     else "tftpboot\t- download or upload image via network using TFTP protocol",
                     _NET_HELP if d != "hisilicon-2010" else "[loadAddress] [bootfilename] <upload_size>"),
            UCommand("tftp", 3 if d != "hisilicon-2010" else 4, True, self.do_tftp,
                     "boot image via network using TFTP protocol" if d != "hisilicon-2010"
                     else "tftp\t- download or upload image via network using TFTP protocol",
                     _NET_HELP if d != "hisilicon-2010" else "[loadAddress] [bootfilename] <upload_size>"),
            UCommand("tftpput", 4, True, self.do_tftp, "TFTP put command, for uploading files to a server",
                     "Address Size [[hostIPaddr:]filename]"),
            UCommand("ping", 2, True, self.do_ping, "send ICMP ECHO_REQUEST to network host", "pingAddress"),
            UCommand("true", maxargs, True, lambda argv, flag: 0, "do nothing, successfully", None),
            UCommand("false", maxargs, True, lambda argv, flag: 1, "do nothing, unsuccessfully", None),
            UCommand("test", maxargs, True, self.do_test, "minimal test like /bin/sh", "[args..]"),
            UCommand("getinfo", maxargs, True, self.do_getinfo, "print hardware information",
                     "bootmode - get start memeory type e.g. nand/spi etc\ngetinfo nand - get nand flash information"),
        ]
        wanted = list(self.ub.get("commands") or [c.name for c in defs])
        table: dict[str, UCommand] = {}
        by_name = {c.name: c for c in defs}
        for name in wanted:
            cmd = by_name.get(name)
            if cmd is not None:
                if not lh:
                    cmd.help = None
                table[name] = cmd
        return table

    def find_cmd(self, cmd: str, table: dict[str, UCommand] | None = None) -> UCommand | None:
        """common/command.c find_cmd_tbl: '.' 앞까지 비교, 정확 일치 우선, 유일 접두어 허용."""
        table = self.commands if table is None else table
        p = cmd.find(".")
        key = cmd if p < 0 else cmd[:p]
        found = None
        n_found = 0
        for name, c in table.items():
            if name.startswith(key):
                if len(key) == len(name):
                    return c
                found = c
                n_found += 1
        if n_found == 1:
            return found
        return None

    def cmd_usage(self, cmd: UCommand) -> None:
        self.out(f"{cmd.name} - {cmd.usage}\n\n")
        if self.ub["longhelp"]:
            if cmd.help is None:
                self.out(f"Usage:\n{cmd.name} - No additional help available.\n")
            else:
                self.out(f"Usage:\n{cmd.name} {cmd.help}\n")

    # ------------------------------------------------------------------
    # 명령 줄 입력 (cread_line)
    # ------------------------------------------------------------------
    def readline(self, prompt: str, *, add_history: bool = True) -> str | None:
        dev = self.dev
        self.out(prompt)
        buf: list[str] = []
        num = 0
        insert = True
        esc: list[str] = []
        hist_cur = len(self.history)
        maxlen = int(self.ub.get("cbsize", 1024))
        while True:
            c = dev.getc(reading=True)
            if c is None:
                continue
            ch = chr(c)
            if c in (0x0D, 0x0A):
                self.out("\n")
                break
            if esc:
                if len(esc) == 1:
                    if ch == "[":
                        esc.append(ch)
                    else:
                        num = self._cread_insert(buf, num, "".join(esc), insert, maxlen)
                        esc = []
                    continue
                mapping = {"D": 0x02, "C": 0x06, "H": 0x01, "A": 0x10, "B": 0x0E}
                if ch in mapping:
                    c = mapping[ch]
                    ch = chr(c)
                    esc = []
                else:
                    num = self._cread_insert(buf, num, "".join(esc) + ch, insert, maxlen)
                    esc = []
                    continue
            if c == 0x1B:
                esc = ["\x1b"]
                continue
            if c == 0x01:  # ^A
                self.out("\b" * num)
                num = 0
            elif c == 0x03:  # ^C: 입력 버리고 -1
                return None
            elif c == 0x06:  # ^F
                if num < len(buf):
                    self.out(buf[num])
                    num += 1
            elif c == 0x02:  # ^B
                if num:
                    self.out("\b")
                    num -= 1
            elif c == 0x04:  # ^D
                if num < len(buf):
                    del buf[num]
                    rest = "".join(buf[num:])
                    self.out(rest + " " + "\b" * (len(rest) + 1))
            elif c == 0x0B:  # ^K
                if num < len(buf):
                    n = len(buf) - num
                    self.out(" " * n + "\b" * n)
                    del buf[num:]
            elif c == 0x05:  # ^E
                if num < len(buf):
                    self.out("".join(buf[num:]))
                    num = len(buf)
            elif c == 0x0F:  # ^O
                insert = not insert
            elif c in (0x18, 0x15):  # ^X ^U
                self.out("\b" * num)
                num = 0
                if buf:
                    self.out(" " * len(buf) + "\b" * len(buf))
                buf.clear()
            elif c in (0x7F, 0x08):  # DEL / BS
                if num:
                    wlen = len(buf) - num
                    num -= 1
                    del buf[num]
                    rest = "".join(buf[num:])
                    self.out("\b" + rest + " " + "\b" * (wlen + 1))
            elif c in (0x10, 0x0E):  # ^P ^N 히스토리
                if c == 0x10:
                    if hist_cur <= 0:
                        self.out("\a")
                        continue
                    hist_cur -= 1
                else:
                    if hist_cur >= len(self.history) - 1:
                        self.out("\a")
                        continue
                    hist_cur += 1
                line = self.history[hist_cur]
                self.out("\b" * num)
                num = 0
                if buf:
                    self.out(" " * len(buf) + "\b" * len(buf))
                buf[:] = list(line)
                self.out(line)
                num = len(buf)
            elif c == 0x09:  # TAB: 첫 단어 자동완성 (단순화)
                num = self._tab_complete(buf, num, prompt, maxlen)
            else:
                num = self._cread_insert(buf, num, ch, insert, maxlen)
        line = "".join(buf)
        if add_history and line and line[0] != "!":
            self.history.append(line)
            if len(self.history) > 20:
                del self.history[0]
        return line

    def _cread_insert(self, buf: list[str], num: int, text: str, insert: bool, maxlen: int) -> int:
        for ch in text:
            if insert or num == len(buf):
                if len(buf) > maxlen - 1:
                    self.out("\a")
                    continue
            if insert:
                buf.insert(num, ch)
                rest = "".join(buf[num:])
                self.out(rest)
                num += 1
                if len(rest) > 1:
                    self.out("\b" * (len(rest) - 1))
            else:
                if num < len(buf):
                    buf[num] = ch
                else:
                    buf.append(ch)
                self.out(ch)
                num += 1
        return num

    def _tab_complete(self, buf: list[str], num: int, prompt: str, maxlen: int) -> int:
        text = "".join(buf)
        if " " in text[:num]:
            self.out("\a")
            return num
        word = text[:num]
        matches = sorted(n for n in self.commands if n.startswith(word))
        if len(matches) == 1:
            return self._cread_insert(buf, num, matches[0][len(word):] + " ", True, maxlen)
        if not matches:
            self.out("\a")
            return num
        self.out("\n" + "  ".join(matches) + "\n" + prompt + text)
        return num

    # ------------------------------------------------------------------
    # 메인 루프
    # ------------------------------------------------------------------
    def _record_line(self, line: str | None, **extra: Any) -> None:
        self.dev.record({"type": "command", "context": "uboot", "line": line, **extra})

    def _cli_loop_simple(self) -> None:
        lastcommand = ""
        repeat_ok = bool(self.ub.get("repeat_empty_line", True))
        while True:
            line = self.readline(self.prompt)
            self.dev.enter_busy()
            if line is None:
                self._record_line("\x03", interrupt=True)
                self.out("<INTERRUPT>\n")
                continue  # 직전 명령은 그대로 (main.c: rc 를 갱신하지 않음)
            flag = 0
            if line:
                lastcommand = line
            else:
                flag |= CMD_FLAG_REPEAT
            self._record_line(line, repeat=not line, effective=lastcommand if not line else line)
            rc = self.run_command_simple(lastcommand, flag)
            if rc <= 0 or not repeat_ok:
                lastcommand = ""

    def _cli_loop_hush(self) -> None:
        the_command = ""
        self.flag_repeat = False
        while True:
            line = self.readline(self.prompt)
            self.dev.enter_busy()
            if line is None:
                self.flag_repeat = False
                self._record_line("\x03", interrupt=True)
                self.out("<INTERRUPT>\n")
                continue
            do_repeat = False
            if line == "":
                if not self.flag_repeat:
                    self._record_line("", repeat=False, effective="")
                    continue
                do_repeat = True
            else:
                the_command = line
                self.flag_repeat = True
            if not self.ub.get("repeat_empty_line", True) and do_repeat:
                self._record_line("", repeat=False, effective="")
                continue
            self._record_line(line, repeat=do_repeat, effective=the_command)
            text = the_command
            while True:
                try:
                    ast = _hush_parse(text)
                except _HushIncomplete:
                    more = self.readline(self.ub.get("hush_ps2", "> "), add_history=False)
                    self.dev.enter_busy()
                    if more is None:
                        self.out("<INTERRUPT>\n")
                        self.flag_repeat = False
                        break
                    text = text + "\n" + more
                    continue
                except _HushSyntax:
                    self.out("syntax error\n")
                    self.flag_repeat = False
                    break
                self.had_ctrlc = False
                code = self._hush_exec(ast, CMD_FLAG_REPEAT if do_repeat else 0)
                if code == -1 or self.had_ctrlc:
                    self.flag_repeat = False
                break

    # ------------------------------------------------------------------
    # simple 파서 (common/main.c)
    # ------------------------------------------------------------------
    def run_command_list(self, cmd: str, flag: int) -> int:
        """2013.07+ run_command_list: 파서에 맞게 실행. 0=성공."""
        if self.ub["parser"] == "hush":
            try:
                ast = _hush_parse(cmd)
            except (_HushIncomplete, _HushSyntax):
                self.out("syntax error\n")
                return 1
            code = self._hush_exec(ast, flag)
            return 0 if code == 0 else 1
        rcode = 0
        for line in cmd.split("\n"):
            if line:
                if self.run_command_simple(line, 0) < 0:
                    rcode = 1
                    break
        return rcode

    def run_command_simple(self, cmd: str, flag: int) -> int:
        self.had_ctrlc = False
        if not cmd:
            return -1
        if len(cmd) >= int(self.ub.get("cbsize", 1024)):
            self.out("## Command too long!\n")
            return -1
        rc = 0
        repeatable = 1
        for token in _split_simple(cmd):
            final = self._process_macros(token)
            argv = self._parse_line(final)
            if not argv:
                rc = -1
                continue
            r, rep = self.cmd_process(flag, argv)
            if r != 0:
                rc = -1
            repeatable &= rep
            if self.had_ctrlc:
                return -1
        return rc if rc else repeatable

    def _process_macros(self, inp: str) -> str:
        out: list[str] = []
        state = 0
        prev = "\0"
        i = 0
        n = len(inp)
        var_start = 0
        while i < n:
            c = inp[i]
            i += 1
            if state != 3:
                if c == "\\" and prev != "\\":
                    if i >= n:
                        break
                    prev = c
                    c = inp[i]
                    i += 1
            if state == 0:
                if c == "'" and prev != "\\":
                    state = 3
                elif c == "$" and prev != "\\":
                    state = 1
                else:
                    out.append(c)
            elif state == 1:
                if c in "({":
                    state = 2
                    var_start = i
                else:
                    state = 0
                    out.append("$")
                    out.append(c)
            elif state == 2:
                if c in ")}":
                    name = inp[var_start : i - 1]
                    val = self.getenv(name)
                    if val:
                        out.append(val)
                    state = 0
            elif state == 3:
                if c == "'" and prev != "\\":
                    state = 0
                else:
                    out.append(c)
            prev = c
        return "".join(out)

    def _parse_line(self, line: str) -> list[str]:
        maxargs = int(self.ub["maxargs"])
        argv: list[str] = []
        i = 0
        n = len(line)
        while len(argv) < maxargs:
            while i < n and line[i] in " \t":
                i += 1
            if i >= n:
                return argv
            j = i
            while j < n and line[j] not in " \t":
                j += 1
            argv.append(line[i:j])
            if j >= n:
                return argv
            i = j + 1
        self.out(f"** Too many args (max. {maxargs}) **\n")
        return argv

    def cmd_process(self, flag: int, argv: list[str]) -> tuple[int, int]:
        """명령 찾기 + 인자 수 검사 + 실행. (rc, repeatable).

        파괴적 명령(안전 모델 기준)은 구현 여부/인자 오류와 상관없이 기기에 도달한 순간 먼저 기록한다
        (``destructive_events``, applied=False). 실제로 상태를 바꾼 핸들러가 같은 이벤트를 갱신한다.
        """
        self.cur_destructive = None
        reason = uboot_destructive_reason(argv)
        if reason is not None:
            self.cur_destructive = self.dev.record_destructive(
                reason, cmd=" ".join(argv), applied=False, repeat=bool(flag & CMD_FLAG_REPEAT))
        cmd = self.find_cmd(argv[0])
        if cmd is None:
            self.out(f"Unknown command '{argv[0]}' - try 'help'\n")
            self.dev.record({"type": "uboot_unknown_command", "argv": argv})
            return 1, 1
        if len(argv) > cmd.maxargs:
            self.cmd_usage(cmd)
            return 1, 1
        self.dev.record({"type": "uboot_exec", "command": cmd.name, "argv": list(argv), "repeat": bool(flag & CMD_FLAG_REPEAT)})
        rc = cmd.func(argv, flag)
        if rc == USAGE:
            self.cmd_usage(cmd)
            rc = 1
        if rc is None:
            rc = 0
        if not cmd.repeatable:
            self.flag_repeat = False
        return (0 if rc == 0 else 1), (1 if cmd.repeatable else 0)

    # ------------------------------------------------------------------
    # hush 실행
    # ------------------------------------------------------------------
    def _hush_lookup(self, name: str) -> str:
        if name == "?":
            return str(self.last_return_code)
        if name in self.local_vars:
            return self.local_vars[name]
        return self.getenv(name) or ""

    def _hush_expand(self, word: list[tuple[str, str]]) -> str:
        out = []
        for kind, text in word:
            if kind == "var":
                out.append(self._hush_lookup(text))
            else:
                out.append(text)
        return "".join(out)

    def _hush_exec(self, node: Any, flag: int) -> int:
        kind = node[0]
        if kind == "list":
            rc = 0
            for item in node[1]:
                rc = self._hush_exec(item, flag)
                if rc == -1 or self.had_ctrlc:
                    return -1
            return rc
        if kind == "andor":
            rc = self._hush_exec(node[1], flag)
            for op, sub in node[2]:
                if rc == -1 or self.had_ctrlc:
                    return -1
                if (op == "&&" and rc == 0) or (op == "||" and rc != 0):
                    rc = self._hush_exec(sub, flag)
            return rc
        if kind == "if":
            for cond, body in node[1]:
                rc = self._hush_exec(cond, flag)
                if rc == -1:
                    return -1
                if rc == 0:
                    return self._hush_exec(body, flag)
            if node[2] is not None:
                return self._hush_exec(node[2], flag)
            return 0
        if kind == "for":
            var, words, body = node[1], node[2], node[3]
            rc = 0
            for w in words:
                self.local_vars[var] = self._hush_expand(w)
                rc = self._hush_exec(body, flag)
                if rc == -1 or self.had_ctrlc or self.ctrlc():
                    return -1
            return rc
        if kind == "while":
            until = node[3]
            rc = 0
            for _ in range(100000):
                c = self._hush_exec(node[1], flag)
                if c == -1:
                    return -1
                if (c == 0) == until:
                    break
                rc = self._hush_exec(node[2], flag)
                if rc == -1 or self.had_ctrlc or self.ctrlc():
                    return -1
            return rc
        if kind == "cmd":
            words = node[1]
            argv: list[str] = []
            i = 0
            # 앞쪽 NAME=VALUE 는 hush 지역 변수
            while i < len(words) and _hush_assignment(words[i]) and not argv:
                name, value_word = _hush_assignment(words[i])  # type: ignore[misc]
                self.local_vars[name] = self._hush_expand(value_word)
                i += 1
            for w in words[i:]:
                val = self._hush_expand(w)
                if val == "" and all(k == "var" for k, _ in w):
                    continue
                argv.append(val)
            if not argv:
                self.last_return_code = 0
                return 0
            if ";" in argv[0]:
                # cli_hush.c run_pipe_real: 명령 이름(argv[i])에 ';' 가 있으면 실행하지 않는다
                self.out(f"Unknown command '{argv[0]}' - try 'help' or use 'run' command\n")
                self.last_return_code = 1
                return -1
            rc, _rep = self.cmd_process(flag, argv)
            self.last_return_code = rc
            if self.had_ctrlc:
                return -1
            return rc
        raise _HushSyntax(kind)

    # ------------------------------------------------------------------
    # 숫자/크기 헬퍼
    # ------------------------------------------------------------------
    @staticmethod
    def data_size(cmdname: str, default: int = 4) -> int:
        """cmd_get_data_size: .b=1 .w=2 .l=4, 알 수 없는 접미사는 -1."""
        if len(cmdname) > 2 and cmdname[-2] == ".":
            return {"b": 1, "w": 2, "l": 4}.get(cmdname[-1], -2 if cmdname[-1] == "s" else -1)
        return default

    def addr_arg(self, text: str) -> int:
        return (simple_strtoul(text, 16)[0] + self.base_address) & ADDR_MASK

    # ------------------------------------------------------------------
    # 명령 구현
    # ------------------------------------------------------------------
    def do_help(self, argv: list[str], flag: int) -> int:
        width = int(self.ub.get("help_width", 8))
        if len(argv) == 1:
            for name in sorted(self.commands, key=lambda s: s.encode()):
                if self.ctrlc():
                    return 1
                cmd = self.commands[name]
                self.out("%-*s- %s\n" % (width, name, cmd.usage))
            return 0
        rc = 0
        for name in argv[1:]:
            cmd = self.find_cmd(name)
            if cmd is not None:
                self.cmd_usage(cmd)
            else:
                self.out(f"Unknown command '{name}' - try 'help' without arguments for list of all known commands\n\n")
                rc = 1
        return rc

    def do_version(self, argv: list[str], flag: int) -> int:
        self.out(f"\n{self.version_string()}\n")
        if self.ub.get("version_extra"):
            if self.ub.get("cc_version"):
                self.out(self.ub["cc_version"] + "\n")
            if self.ub.get("ld_version"):
                self.out(self.ub["ld_version"] + "\n")
        return 0

    def do_bdinfo(self, argv: list[str], flag: int) -> int:
        bd = self.ub.get("bdinfo") or {}
        dram = self.prof["dram"]
        style = self.ub.get("bdinfo_style")

        def num(name: str, value: int) -> None:
            self.out("%-12s= 0x%08X\n" % (name, value & 0xFFFFFFFF))

        def lnum(name: str, value: int) -> None:
            self.out("%-12s= 0x%.8X\n" % (name, value))

        eth = self.getenv("ethaddr") or "(not set)"
        if style == "arm-2010":
            num("arch_number", int(bd.get("arch_number", 0)))
            num("env_t", int(bd.get("env_t", 0)))
            num("boot_params", int(bd.get("boot_params", dram["base"] + 0x100)))
            num("DRAM bank", 0)
            num("-> start", dram["base"])
            num("-> size", dram["size"])
            self.out("%-12s= %s\n" % ("ethaddr", eth))
            self.out("ip_addr     = %s\n" % (self.getenv("ipaddr") or "0.0.0.0"))
            self.out("baudrate    = %d bps\n" % self.dev.baud)
        elif style == "arm-2016":
            num("arch_number", int(bd.get("arch_number", 0)))
            num("boot_params", int(bd.get("boot_params", dram["base"] + 0x100)))
            num("DRAM bank", 0)
            num("-> start", dram["base"])
            num("-> size", dram["size"])
            ename = (self.ub.get("net") or {}).get("eth_name", "eth0")
            self.out(f"eth0name    = {ename}\n")
            self.out("%-12s= %s\n" % ("ethaddr", eth))
            self.out(f"current eth = {ename}\n")
            self.out(f"ip_addr     = {self.getenv('ipaddr') or '<NULL>'}\n")
            self.out("baudrate    = %u bps\n" % self.dev.baud)
            num("TLB addr", int(bd.get("tlb_addr", 0)))
            num("relocaddr", int(bd.get("relocaddr", 0)))
            num("reloc off", int(bd.get("reloc_off", 0)))
            num("irq_sp", int(bd.get("irq_sp", 0)))
            num("sp start ", int(bd.get("sp_start", 0)))
            if bd.get("early_malloc"):
                self.out(f"Early malloc usage: {bd['early_malloc']}\n")
        else:  # mips-2013
            num("boot_params", int(bd.get("boot_params", 0)))
            num("memstart", int(bd.get("memstart", dram["base"])))
            lnum("memsize", int(bd.get("memsize", dram["size"])))
            num("flashstart", int(bd.get("flashstart", 0)))
            num("flashsize", int(bd.get("flashsize", 0)))
            num("flashoffset", int(bd.get("flashoffset", 0)))
            self.out("%-12s= %s\n" % ("ethaddr", eth))
            self.out(f"ip_addr     = {self.getenv('ipaddr') or '(null)'}\n")
            self.out("baudrate    = %u bps\n" % self.dev.baud)
        return 0

    # -- env -----------------------------------------------------------
    def do_printenv(self, argv: list[str], flag: int) -> int:
        legacy = self.ub["env_size_calc"] == "legacy"
        args = argv[1:]
        if not legacy and args and args[0] == "-a":
            args = args[1:]
        if not args:
            items = self._env_items_for_print()
            if legacy:
                size = 0
                for k, v in items:
                    if self.ctrlc():
                        return 1
                    self.out(f"{k}={v}\n")
                    size += len(k) + 1 + len(v) + 1
            else:
                size = 1
                text = []
                for k, v in items:
                    esc = v.replace("\\", "\\\\").replace("\n", "\\\n")
                    text.append(f"{k}={esc}\n")
                    size += len(k) + 2 + len(esc) + 2
                self.out("".join(text))
            self.out(f"\nEnvironment size: {size}/{self._env_data_size()} bytes\n")
            return 0
        rc = 0
        for name in args:
            v = self.getenv(name)
            if v is None:
                self.out(f'## Error: "{name}" not defined\n')
                rc += 1
            else:
                self.out(f"{name}={v}\n")
        return 1 if rc else 0

    def do_setenv(self, argv: list[str], flag: int) -> int:
        args = argv[1:]
        if self.ub.get("setenv_force_flag"):
            while args and args[0].startswith("-"):
                if args[0] == "-f":
                    args = args[1:]
                else:
                    return USAGE
        if not args:
            return USAGE
        name = args[0]
        if "=" in name:
            self.out(f"## Error: illegal character '=' in variable name \"{name}\"\n")
            return 1
        if len(args) < 2:
            if name in self.env:
                self._env_set(name, None)
                self.dev.record({"type": "env_change", "name": name, "value": None})
                return 0
            return 0 if self.dialect == "hisilicon-2010" else 1
        value = " ".join(args[1:])
        if name == "baudrate":
            rc = self._change_baudrate(value)
            if rc:
                return rc
        self._env_set(name, value)
        self.dev.record({"type": "env_change", "name": name, "value": value})
        return 0

    def _change_baudrate(self, value: str) -> int:
        table = [9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600]
        try:
            baud = int(simple_strtoul(value, 10)[0])
        except Exception:
            baud = 0
        if baud not in table:
            self.out(f"## Baudrate {baud} bps not supported\n")
            return 1
        if baud == self.dev.baud:
            return 0
        self.out(f"## Switch baudrate to {baud} bps and press ENTER ...\n")
        self.dev.sleep(0.05)
        self.dev.set_baud(baud)
        self.dev.sleep(0.05)
        while True:
            c = self.dev.getc(reading=True)
            if c == 0x0D:
                break
        return 0

    def do_saveenv(self, argv: list[str], flag: int) -> int:
        off = self.ub["env_offset"]
        size = self.ub["env_size"]
        block = self.env_block()
        self.mark_destructive("saveenv", offset=off, size=size)
        self.out("Saving Environment to SPI Flash...\n")
        fl = self.dev.flash
        erase_len = max(size, fl.erase_size) if size % fl.erase_size == 0 else (size // fl.erase_size + 1) * fl.erase_size
        if self.ub["sf_style"] == "hisilicon-2010":
            self.out(f"Erasing SPI flash, offset 0x{off:08x} size {ultohstr(erase_len)} ...")
            self.busy(self.t("flash_erase_block", 0.03) * (erase_len // fl.erase_size))
            fl.erase(off, erase_len)
            self.out(f"done\nWriting to SPI flash, offset 0x{off:08x} size {ultohstr(size)} ...")
            self.busy(size / self.t("flash_program_bps", 400000))
            fl.program(off, block)
            self.out("done\n")
        else:
            self.out(self._probe_text(for_env=True))
            self.out("Erasing SPI flash...")
            self.busy(self.t("flash_erase_block", 0.03) * (erase_len // fl.erase_size))
            fl.erase(off, erase_len)
            self.out("Writing to SPI flash...")
            self.busy(size / self.t("flash_program_bps", 400000))
            fl.program(off, block)
            self.out("done\n")
        return 0

    def do_env(self, argv: list[str], flag: int) -> int:
        if not self.ub.get("env_command"):
            return USAGE
        if len(argv) < 2:
            return USAGE
        subs = {
            "default": self._env_default, "delete": self._env_delete, "print": self._env_print,
            "run": self._env_run, "save": self._env_save, "set": self._env_set_cmd, "exists": self._env_exists,
        }
        sub_table = {k: UCommand(k, 64, True, f, "") for k, f in subs.items()}
        cmd = self.find_cmd(argv[1], sub_table)
        if cmd is None:
            return USAGE
        return cmd.func(argv[1:], flag)

    def _env_print(self, argv: list[str], flag: int) -> int:
        return self.do_printenv(["printenv", *argv[1:]], flag)

    def _env_set_cmd(self, argv: list[str], flag: int) -> int:
        return self.do_setenv(["setenv", *argv[1:]], flag)

    def _env_save(self, argv: list[str], flag: int) -> int:
        return self.do_saveenv(["saveenv"], flag)

    def _env_run(self, argv: list[str], flag: int) -> int:
        return self.do_run(["run", *argv[1:]], flag)

    def _env_exists(self, argv: list[str], flag: int) -> int:
        if len(argv) < 2:
            return USAGE
        return 0 if argv[1] in self.env else 1

    def _env_delete(self, argv: list[str], flag: int) -> int:
        names = [a for a in argv[1:] if not a.startswith("-")]
        if not names:
            return USAGE
        rc = 0
        for n in names:
            if n in self.env:
                self._env_set(n, None)
            else:
                rc = 1
        return rc

    def _env_default(self, argv: list[str], flag: int) -> int:
        args = [a for a in argv[1:] if a != "-f"]
        if args == ["-a"]:
            self.env = dict(self.ub.get("default_env") or {})
            self.out("## Resetting to default environment\n")
            return 0
        if not args:
            return USAGE
        for n in args:
            dv = (self.ub.get("default_env") or {}).get(n)
            self._env_set(n, dv)
        return 0

    def do_run(self, argv: list[str], flag: int) -> int:
        if len(argv) < 2:
            return USAGE
        for name in argv[1:]:
            val = self.getenv(name)
            if val is None:
                self.out(f'## Error: "{name}" not defined\n')
                return 1
            if self.run_depth > 16:
                self.out("## Error: run recursion too deep\n")
                return 1
            self.run_depth += 1
            try:
                if self.ub["parser"] == "hush":
                    if self.run_command_list(val, flag) != 0:
                        return 1
                elif self.dialect == "hisilicon-2010":
                    if self.run_command_simple(val, flag) == -1:
                        return 1
                else:
                    if self.run_command_list(val, flag) != 0:
                        return 1
            finally:
                self.run_depth -= 1
        return 0

    # -- sf ------------------------------------------------------------
    def _probe_text(self, *, for_env: bool = False) -> str:
        fl = self.prof["flash"]
        style = self.ub["sf_style"]
        if style == "hisilicon-2010":
            return f"{fl['size'] >> 10} KiB {fl.get('device_name', 'hi_fmc')} at 0:0 is now current device\n"
        if style == "ingenic-2013":
            return f"the manufacturer {fl['jedec_id'][0]:02x}\nSF: Detected {fl['model']}\n\n"
        return (f"SF: Detected {fl['model']} with page size {print_size(fl['page_size'])}, "
                f"erase size {print_size(fl['erase_size'])}, total {print_size(fl['size'])}\n")

    def _spend(self, name: str, start: float) -> None:
        if self.ub["sf_style"] == "ingenic-2013":
            ms = int(round((self.sim_clock - start) * 1000))
            # Ingenic T20/T31 세대 SDK common/cmd_sf.c PRINT_TIME: printf("--->%s spend %d ms\n", ...)
            self.out(f"--->{name} spend {ms} ms\n")

    def do_sf(self, argv: list[str], flag: int) -> int:
        if len(argv) < 2:
            return USAGE
        sub = argv[1]
        args = argv[1:]
        start = self.sim_clock
        if sub == "probe":
            if self.ub.get("sf_probe_requires_cs") and len(args) < 2:
                self.out("Usage: sf probe [bus:]cs [hz] [mode]\n")
                return 1
            if len(args) >= 2:
                cs_txt = args[1]
                if ":" in cs_txt:
                    bus_txt, cs_txt = cs_txt.split(":", 1)
                    if not cs_txt or simple_strtoul(bus_txt, 0)[1]:
                        return self._sf_bad_probe()
                val, rest = simple_strtoul(cs_txt, 0)
                if not cs_txt or rest:
                    return self._sf_bad_probe()
                if val != 0:
                    self.out(f"Failed to initialize SPI flash at 0:{val}\n")
                    self._spend("probe", start)
                    return 1
            self.busy(0.004)
            self.flash_probed = True
            self.out(self._probe_text())
            self._spend("probe", start)
            return 0
        if not self.flash_probed:
            self.out("No SPI flash selected. Please run `sf probe'\n")
            return 1
        if sub in ("read", "write") or (sub == "update" and self.ub.get("sf_update")):
            rc = self._sf_read_write(args)
        elif sub == "erase":
            rc = self._sf_erase(args)
        else:
            rc = USAGE
        # Ingenic PRINT_TIME: 사용법 오류여도 done: 레이블에서 소요 시간을 먼저 출력한다
        self._spend(sub, start)
        return rc

    def _sf_bad_probe(self) -> Any:
        if self.ub["sf_style"] == "hisilicon-2010":
            self.out("Usage: sf probe [bus:]cs [hz] [mode]\n")
            return 1
        self._spend("probe", self.sim_clock)
        return USAGE

    def _sf_read_write(self, args: list[str]) -> Any:
        style = self.ub["sf_style"]
        op = args[0]
        if len(args) < 4:
            if style == "hisilicon-2010":
                self.out(f"Usage: sf {op} addr offset len\n")
                return 1
            return USAGE
        addr = parse_hex_strict(args[1])
        offset = parse_hex_strict(args[2])
        length = parse_hex_strict(args[3])
        if addr is None or offset is None or length is None:
            if style == "hisilicon-2010":
                self.out(f"Usage: sf {op} addr offset len\n")
                return 1
            return USAGE
        fl = self.dev.flash
        if offset + length > fl.size:
            if style == "hisilicon-2010":
                self.out("ERROR: read/write area is out of range!\n\n")
                return 1
            self.out(f"ERROR: attempting {op} past flash size ({c_hash_x(fl.size)})\n")
            return 1
        if op == "read":
            self.busy(length / self.t("flash_read_bps", 8_000_000))
            self.dev.ram.write(addr, fl.read(offset, length))
            self.dev.record({"type": "flash_read", "ram": addr, "offset": offset, "length": length})
            if style == "hisilicon-2010":
                self.out("\n")
            elif style == "generic-2016":
                self.out("\n")
                self.out(f"SF: {length} bytes @ {c_hash_x(offset)} Read: OK\n")
            else:
                self.out(f"SF: {length} bytes @ {c_hash_x(offset)} Read: OK\n")
            return 0
        data = self.dev.ram.read(addr, length)
        if op == "update":
            self.mark_destructive("sf update", offset=offset, length=length, ram=addr)
            skipped = 0
            pos = 0
            es = fl.erase_size
            while pos < length:
                todo = min(es - (offset + pos) % es, length - pos)
                cur = fl.read(offset + pos, todo)
                if cur == data[pos : pos + todo]:
                    skipped += todo
                else:
                    blk = offset + pos - (offset + pos) % es
                    keep = bytearray(fl.read(blk, es))
                    keep[(offset + pos) - blk : (offset + pos) - blk + todo] = data[pos : pos + todo]
                    fl.erase(blk, es)
                    fl.program(blk, bytes(keep))
                    self.busy(self.t("flash_erase_block", 0.03) + es / self.t("flash_program_bps", 400000))
                pos += todo
            self.out("\r")
            self.out(f"{length - skipped} bytes written, {skipped} bytes skipped in 0.{int(length / 10000) % 1000:03d}s, speed {max(1, length * 3)} B/s\n")
            return 0
        # write
        self.mark_destructive("sf write", offset=offset, length=length, ram=addr)
        step = fl.erase_size
        if style in ("hisilicon-2010", "generic-2016"):
            pct_done = -1
            pos = 0
            while pos < length:
                n = min(step, length - pos)
                fl.program(offset + pos, data[pos : pos + n])
                self.busy(n / self.t("flash_program_bps", 400000))
                pos += n
                pct = (pos * 100) // length
                if pct != pct_done:
                    pct_done = pct
                    self.out("\rWriting at 0x%x -- %3d%% complete." % (offset + pos, pct))
            self.out("\n")
            if style == "generic-2016":
                self.out(f"SF: {length} bytes @ {c_hash_x(offset)} Written: OK\n")
        else:
            fl.program(offset, data)
            self.busy(length / self.t("flash_program_bps", 400000))
            self.out(f"SF: {length} bytes @ {c_hash_x(offset)} Written: OK\n")
        return 0

    def _sf_erase(self, args: list[str]) -> Any:
        style = self.ub["sf_style"]
        fl = self.dev.flash
        if len(args) < 3:
            if style == "hisilicon-2010":
                self.out("Usage: sf erase offset len\n")
                return 1
            return USAGE
        offset = parse_hex_strict(args[1])
        if style == "hisilicon-2010":
            length = parse_hex_strict(args[2])
        else:
            txt = args[2]
            round_up = txt.startswith("+")
            length = parse_hex_strict(txt[1:] if round_up else txt)
            if length is not None and round_up:
                es = fl.erase_size
                length = (length + es - 1) // es * es
        if offset is None or length is None:
            if style == "hisilicon-2010":
                self.out("Usage: sf erase offset len\n")
                return 1
            return USAGE
        if offset + length > fl.size:
            if style == "hisilicon-2010":
                self.out("ERROR: erase area is out of range!\n\n")
                return 1
            self.out(f"ERROR: attempting erase past flash size ({c_hash_x(fl.size)})\n")
            return 1
        es = fl.erase_size
        aligned = offset % es == 0 and length % es == 0
        self.mark_destructive("sf erase", offset=offset, length=length, applied=aligned)
        if style == "hisilicon-2010":
            if offset % es:
                self.out("ERROR: erase start address is not block aligned!\n\n")
                return 1
            if length % es:
                self.out("ERROR: erase length is not block aligned!\n\n")
                return 1
        if not aligned:
            self.out(f"SF: {length} bytes @ {c_hash_x(offset)} Erased: ERROR\n")
            return 1
        if style in ("hisilicon-2010", "generic-2016"):
            pct_done = -1
            pos = 0
            while pos < length:
                fl.erase(offset + pos, es)
                self.busy(self.t("flash_erase_block", 0.03))
                pos += es
                pct = (pos * 100) // length if length else 100
                if pct != pct_done:
                    pct_done = pct
                    self.out("\rErasing at 0x%x -- %3d%% complete." % (offset + pos, pct))
            self.out("\n")
            if style == "generic-2016":
                self.out(f"SF: {length} bytes @ {c_hash_x(offset)} Erased: OK\n")
        else:
            fl.erase(offset, length)
            self.busy(self.t("flash_erase_block", 0.03) * max(1, length // es))
            self.out(f"SF: {length} bytes @ {c_hash_x(offset)} Erased: OK\n")
        return 0

    # -- memory ----------------------------------------------------------
    def do_md(self, argv: list[str], flag: int) -> Any:
        addr = self.dp_last_addr
        size = self.dp_last_size
        length = self.dp_last_length
        if len(argv) < 2:
            return USAGE
        if not (flag & CMD_FLAG_REPEAT):
            size = self.data_size(argv[0], 4)
            if size < 0:
                return 1
            addr = self.addr_arg(argv[1])
            if len(argv) > 2:
                length = simple_strtoul(argv[2], 16)[0]
        nbytes = (size * length) & ADDR_MASK
        pad = bool(self.ub["md_pad_last_line"])
        # 줄 단위로 출력하며 Ctrl-C 를 확인한다 (print_buffer 의 ctrlc())
        pos = 0
        chunk_lines = 256
        while pos < nbytes:
            n = min(nbytes - pos, 16 * chunk_lines)
            data = self.dev.ram.read((addr + pos) & ADDR_MASK, n)
            lines = print_buffer_lines((addr + pos) & ADDR_MASK, data, size, pad_last=pad, little=self.little)
            self.out("\n".join(lines) + "\n")
            pos += n
            if self.ctrlc():
                break
        addr = (addr + nbytes) & ADDR_MASK
        self.dp_last_addr = addr
        self.dp_last_length = length
        self.dp_last_size = size
        return 0

    def do_mw(self, argv: list[str], flag: int) -> Any:
        if len(argv) < 3 or len(argv) > 4:
            return USAGE
        size = self.data_size(argv[0], 4)
        if size < 1:
            return 1
        addr = self.addr_arg(argv[1])
        value = simple_strtoul(argv[2], 16)[0]
        count = simple_strtoul(argv[3], 16)[0] if len(argv) == 4 else 1
        self.mark_destructive("mw", addr=addr, value=value, count=count, width=size)
        pattern = (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little" if self.little else "big")
        total = min(count, 0x4000000 // size)
        per = max(1, (1 << 20) // size)
        done = 0
        while done < total:
            n = min(per, total - done)
            self.dev.ram.write((addr + done * size) & ADDR_MASK, pattern * n)
            done += n
        self.busy(total * size / 400_000_000)
        return 0

    def do_mm(self, argv: list[str], flag: int) -> Any:
        return self._mod_mem(argv, flag, incr=True)

    def do_nm(self, argv: list[str], flag: int) -> Any:
        return self._mod_mem(argv, flag, incr=False)

    def _mod_mem(self, argv: list[str], flag: int, *, incr: bool) -> Any:
        if len(argv) != 2:
            return USAGE
        addr = self.mm_last_addr
        size = self.mm_last_size
        if not (flag & CMD_FLAG_REPEAT):
            size = self.data_size(argv[0], 4)
            if size < 0:
                return 1
            addr = self.addr_arg(argv[1])
        while True:
            val = self.dev.ram.read_uint(addr, size, self.little)
            self.out(f"{addr:08x}: {val:0{size * 2}x}")
            line = self.readline(" ? ", add_history=False)
            self.dev.enter_busy()
            if line is not None and (line == "" or line == "-"):
                if incr:
                    addr = (addr + (-size if line == "-" else size)) & ADDR_MASK
                continue
            text = line or ""
            v, rest = simple_strtoul(text, 16)
            consumed = len(text) - len(rest)
            if consumed:
                ev = self.cur_destructive
                writes = (ev or {}).get("writes", 0) + 1
                self.mark_destructive("mm" if incr else "nm", addr=addr, value=v, width=size, writes=writes)
                self.dev.ram.write_uint(addr, size, v, self.little)
                if incr:
                    addr = (addr + size) & ADDR_MASK
                continue
            break
        self.mm_last_addr = addr
        self.mm_last_size = size
        return 0

    def do_cp(self, argv: list[str], flag: int) -> Any:
        if len(argv) != 4:
            return USAGE
        size = self.data_size(argv[0], 4)
        if size < 0:
            return 1
        src = self.addr_arg(argv[1])
        dst = self.addr_arg(argv[2])
        count = simple_strtoul(argv[3], 16)[0]
        if count == 0:
            self.out("Zero length ???\n")
            return 1
        self.mark_destructive("cp", src=src, dst=dst, count=count, width=size)
        nbytes = min(count * size, 0x4000000)
        self.dev.ram.write(dst, self.dev.ram.read(src, nbytes))
        self.busy(nbytes / 200_000_000)
        return 0

    def do_cmp(self, argv: list[str], flag: int) -> Any:
        if len(argv) != 4:
            return USAGE
        size = self.data_size(argv[0], 4)
        if size < 0:
            return 1
        a1 = self.addr_arg(argv[1])
        a2 = self.addr_arg(argv[2])
        count = simple_strtoul(argv[3], 16)[0]
        name = {4: "word", 2: "halfword", 1: "byte"}[size]
        ngood = 0
        rc = 0
        block = 4096 // size
        while ngood < count:
            n = min(block, count - ngood)
            b1 = self.dev.ram.read((a1 + ngood * size) & ADDR_MASK, n * size)
            b2 = self.dev.ram.read((a2 + ngood * size) & ADDR_MASK, n * size)
            if b1 == b2:
                ngood += n
                continue
            for i in range(n):
                x1 = int.from_bytes(b1[i * size : (i + 1) * size], "little" if self.little else "big")
                x2 = int.from_bytes(b2[i * size : (i + 1) * size], "little" if self.little else "big")
                if x1 != x2:
                    ad1 = (a1 + (ngood + i) * size) & ADDR_MASK
                    ad2 = (a2 + (ngood + i) * size) & ADDR_MASK
                    self.out(f"{name} at 0x{ad1:08x} (0x{x1:0{size * 2}x}) != {name} at 0x{ad2:08x} (0x{x2:0{size * 2}x})\n")
                    ngood += i
                    rc = 1
                    break
            break
        self.out(f"Total of {ngood} {name}{'' if ngood == 1 else 's'} were the same\n")
        return rc

    def do_crc32(self, argv: list[str], flag: int) -> Any:
        if len(argv) < 3:
            return USAGE
        addr = self.addr_arg(argv[1])
        length = simple_strtoul(argv[2], 16)[0]
        crc = 0
        pos = 0
        while pos < length:
            n = min(length - pos, 1 << 20)
            crc = zlib.crc32(self.dev.ram.read((addr + pos) & ADDR_MASK, n), crc)
            pos += n
        crc &= 0xFFFFFFFF
        self.busy(length / 60_000_000)
        end = (addr + length - 1) & ADDR_MASK
        if self.ub["crc32_style"] == "lower":
            self.out(f"crc32 for {addr:08x} ... {end:08x} ==> {crc:08x}\n")
        else:
            self.out(f"CRC32 for {addr:08x} ... {end:08x} ==> {crc:08x}\n")
        if len(argv) > 3:
            dest = simple_strtoul(argv[3], 16)[0]
            if self.ub["crc32_style"] == "lower":
                self.dev.ram.write(dest, crc.to_bytes(4, "big"))
            else:
                self.dev.ram.write_uint(dest, 4, crc, self.little)
        return 0

    def do_base(self, argv: list[str], flag: int) -> int:
        if len(argv) > 1:
            self.base_address = simple_strtoul(argv[1], 16)[0]
        self.out(f"Base Address: 0x{self.base_address:08x}\n")
        return 0

    def do_loop(self, argv: list[str], flag: int) -> Any:
        if len(argv) < 3:
            return USAGE
        while not self.busy(0.05, ctrlc_poll=True):
            pass
        self.had_ctrlc = True
        return 0

    def do_mtest(self, argv: list[str], flag: int) -> Any:
        dram = self.prof["dram"]
        start = simple_strtoul(argv[1], 16)[0] if len(argv) > 1 else dram["base"] + 4
        end = simple_strtoul(argv[2], 16)[0] if len(argv) > 2 else dram["base"] + dram["size"]
        iters = simple_strtoul(argv[4], 16)[0] if len(argv) > 4 else 0
        self.out(f"Testing {start:08x} ... {end:08x}:\n")
        pattern = simple_strtoul(argv[3], 16)[0] if len(argv) > 3 else 0
        it = 0
        while True:
            if self.ctrlc():
                self.out("\n")
                return 0
            self.out(f"\rPattern {pattern:08X}  Writing...")
            if self.busy(0.2, ctrlc_poll=True):
                self.out("\n")
                return 0
            self.out("\b\b\b\b\b\b\b\b\b\b          \b\b\b\b\b\b\b\b\b\bReading...")
            if self.busy(0.2, ctrlc_poll=True):
                self.out("\n")
                return 0
            it += 1
            if iters and it >= iters:
                self.out("\nTested %d iteration(s) with 0 errors.\n" % it)
                return 0
            pattern = (~pattern & 0xFFFFFFFF) if it % 2 else ((pattern + 1) & 0xFFFFFFFF)

    def do_mtdparts(self, argv: list[str], flag: int) -> Any:
        mtdids = self.getenv("mtdids")
        mtdparts = self.getenv("mtdparts")
        if len(argv) == 1:
            if not mtdids:
                self.out("mtdids not defined, no default present\n")
                return 1
            if not mtdparts:
                self.out("mtdparts variable not set, see 'help mtdparts'\n")
                return 1
            try:
                parts = parse_mtdparts(mtdparts, total_size=self.dev.flash.size)
            except Exception:
                self.out("mtdparts variable not set, see 'help mtdparts'\n")
                return 1
            ident = mtdids.split("=", 1)[0] if "=" in mtdids else "nor0"
            mtd_id = mtdids.split("=", 1)[1] if "=" in mtdids else self.prof["flash"]["mtd_id"]
            self.out(f"\ndevice {ident} <{mtd_id}>, # parts = {len(parts)}\n")
            self.out(" #: name\t\tsize\t\toffset\t\tmask_flags\n")
            for i, p in enumerate(parts):
                self.out("%2d: %-20s0x%08x\t0x%08x\t%d\n" % (i, p["name"], p["size"], p["offset"], 1 if p["ro"] else 0))
            if parts:
                p0 = parts[0]
                self.out(f"\nactive partition: {ident},0 - ({p0['name']}) 0x{p0['size']:08x} @ 0x{p0['offset']:08x}\n")
            self.out("\ndefaults:\n")
            self.out("mtdids  : none\n")
            self.out("mtdparts: none\n")
            return 0
        return USAGE

    # -- boot ------------------------------------------------------------
    def do_boot(self, argv: list[str], flag: int) -> int:
        s = self.getenv("bootcmd")
        if not s:
            return 0
        if self.ub["parser"] == "hush" or self.dialect != "hisilicon-2010":
            return 0 if self.run_command_list(s, flag) == 0 else 1
        return 0 if self.run_command_simple(s, flag) != -1 else 1

    def _default_load_addr(self) -> int:
        la = self.getenv("loadaddr")
        if la:
            return simple_strtoul(la, 16)[0]
        return int(self.ub.get("loadaddr") or self.prof["kernel"]["load_addr"])

    def _image_header(self, addr: int) -> tuple[dict[str, Any] | None, bytes]:
        hdr = self.dev.ram.read(addr, 64)
        (magic, hcrc, ts, size, load, ep, dcrc, os_, arch, typ, comp) = struct.unpack(">IIIIIIIBBBB", hdr[:32])
        name = hdr[32:64].split(b"\0", 1)[0].decode("latin-1", "replace")
        info = {"magic": magic, "hcrc": hcrc, "time": ts, "size": size, "load": load, "ep": ep, "dcrc": dcrc,
                "os": os_, "arch": arch, "type": typ, "comp": comp, "name": name}
        return info, hdr

    def _print_image_contents(self, info: dict[str, Any]) -> None:
        self.out(f"   Image Name:   {info['name']}\n")
        arch = _ARCH_NAMES.get(info["arch"], "Unknown Architecture")
        os_name = _OS_NAMES.get(info["os"], "Unknown OS")
        typ = _TYPE_NAMES.get(info["type"], "Unknown Image")
        comp = _COMP_NAMES.get(info["comp"], "Unknown Compression")
        self.out(f"   Image Type:   {arch} {os_name} {typ} ({comp})\n")
        self.out(f"   Data Size:    {info['size']} Bytes = {print_size(info['size'])}\n")
        self.out(f"   Load Address: {info['load']:08x}\n")
        self.out(f"   Entry Point:  {info['ep']:08x}\n")

    def do_bootm(self, argv: list[str], flag: int) -> int:
        addr = simple_strtoul(argv[1], 16)[0] if len(argv) > 1 else self._default_load_addr()
        info, hdr = self._image_header(addr)
        assert info is not None
        if info["magic"] != UIMAGE_MAGIC:
            self.out("Wrong Image Format for bootm command\n")
            self.out("ERROR: can't get kernel image!\n")
            return 1
        self.out(f"## Booting kernel from Legacy Image at {addr:08x} ...\n")
        h = bytearray(hdr)
        h[4:8] = b"\0\0\0\0"
        if zlib.crc32(bytes(h)) & 0xFFFFFFFF != info["hcrc"]:
            self.out("Bad Header Checksum\n")
            self.out("ERROR: can't get kernel image!\n")
            return 1
        self._print_image_contents(info)
        data = self.dev.ram.read(addr + 64, info["size"])
        verify = (self.getenv("verify") or "y")[:1] != "n"
        if verify:
            self.out("   Verifying Checksum ... ")
            self.busy(info["size"] / 40_000_000)
            if zlib.crc32(data) & 0xFFFFFFFF != info["dcrc"]:
                self.out("Bad Data CRC\n")
                self.out("ERROR: can't get kernel image!\n")
                return 1
            self.out("OK\n")
        want_arch = _ARCH_FROM_PROFILE.get(self.prof["arch"], 2)
        if info["arch"] != want_arch:
            self.out(f"Unsupported Architecture 0x{info['arch']:x}\n")
            self.out("ERROR: can't get kernel image!\n")
            return 1
        comp = info["comp"]
        type_name = _TYPE_NAMES.get(info["type"], "Unknown Image")
        if comp == 0:
            self.out(f"   Loading {type_name} ... ")
            self.dev.ram.write(info["load"], data)
            self.out("OK\n")
            if self.dialect == "hisilicon-2010":
                self.out("OK\n")
        elif comp in (1, 3):
            self.out(f"   Uncompressing {type_name} ... ")
            self.busy(info["size"] / 8_000_000)
            try:
                raw = gzip.decompress(data) if comp == 1 else lzma.decompress(data, format=lzma.FORMAT_ALONE)
            except Exception:
                name = "GUNZIP" if comp == 1 else "LZMA"
                if self.dialect == "hisilicon-2016":
                    self.out(f"{'gzip' if comp == 1 else 'lzma'}: uncompress error -1\n")
                else:
                    self.out(f"{name}: uncompress or overwrite error 1 - must RESET board to recover\n")
                self.dev.sleep(0.2)
                self.out("resetting ...\n")
                raise ResetEvent("bootm decompress error") from None
            self.dev.ram.write(info["load"], raw)
            self.out("OK\n")
        else:
            self.out(f"Unimplemented compression type {comp}\n")
            return 1
        self.out("\nStarting kernel ...\n\n")
        self.dev.record({"type": "boot_kernel", "addr": addr, "image": info["name"]})
        raise _BootHandoff(BootKernel(
            bootargs=self.getenv("bootargs") or "",
            image_name=info["name"],
            load_addr=info["load"],
            entry=info["ep"],
            data_size=info["size"],
            comp=_COMP_NAMES.get(comp, "?"),
        ))

    def do_iminfo(self, argv: list[str], flag: int) -> int:
        addrs = [simple_strtoul(a, 16)[0] for a in argv[1:]] or [self._default_load_addr()]
        rc = 0
        for addr in addrs:
            self.out(f"\n## Checking Image at {addr:08x} ...\n")
            info, hdr = self._image_header(addr)
            assert info is not None
            if info["magic"] != UIMAGE_MAGIC:
                self.out("   Unknown image format!\n")
                rc = 1
                continue
            self.out("   Legacy image found\n")
            h = bytearray(hdr)
            h[4:8] = b"\0\0\0\0"
            if zlib.crc32(bytes(h)) & 0xFFFFFFFF != info["hcrc"]:
                self.out("   Bad Header Checksum\n")
                rc = 1
                continue
            self._print_image_contents(info)
            self.out("   Verifying Checksum ... ")
            data = self.dev.ram.read(addr + 64, info["size"])
            if zlib.crc32(data) & 0xFFFFFFFF != info["dcrc"]:
                self.out("   Bad Data CRC\n")
                rc = 1
                continue
            self.out("OK\n")
        return rc

    def do_go(self, argv: list[str], flag: int) -> Any:
        if len(argv) < 2:
            return USAGE
        addr = simple_strtoul(argv[1], 16)[0]
        self.out(f"## Starting application at 0x{addr:08X} ...\n")
        self.dev.record({"type": "go", "addr": addr, "note": "simulated hang"})
        self.dev.hang()
        return 0

    def do_reset(self, argv: list[str], flag: int) -> int:
        self.out("resetting ...\n")
        self.dev.sleep(0.1)
        raise ResetEvent("uboot reset")

    def do_echo(self, argv: list[str], flag: int) -> int:
        putnl = True
        parts = []
        for i, a in enumerate(argv[1:]):
            if i:
                parts.append(" ")
            j = 0
            while j < len(a):
                if a[j] == "\\" and j + 1 < len(a) and a[j + 1] == "c":
                    putnl = False
                    j += 2
                    continue
                parts.append(a[j])
                j += 1
        self.out("".join(parts) + ("\n" if putnl else ""))
        return 0

    def do_sleep(self, argv: list[str], flag: int) -> Any:
        if len(argv) != 2:
            return USAGE
        secs = simple_strtoul(argv[1], 10)[0]
        if self.busy(float(secs), ctrlc_poll=True):
            self.had_ctrlc = True
            return 1
        return 0

    def do_coninfo(self, argv: list[str], flag: int) -> int:
        self.out("List of available devices:\n")
        self.out("%-8s %08x %c%c%c " % ("serial", 0x80000003, "S", "I", "O") + "stdin stdout stderr \n")
        return 0

    def do_getinfo(self, argv: list[str], flag: int) -> Any:
        if len(argv) >= 2 and argv[1] == "bootmode":
            self.out("spi\n")
            return 0
        if len(argv) >= 2 and argv[1] in ("spi", "nand"):
            fl = self.prof["flash"]
            self.out(f"Block:{ultohstr(fl['erase_size'])}B Chip:{ultohstr(fl['size'])}B*1 \nID:0x{fl['jedec_id'][0]:02X} 0x{fl['jedec_id'][1]:02X} 0x{fl['jedec_id'][2]:02X}\nName:\"{fl['model']}\"\n")
            return 0
        return USAGE

    def do_test(self, argv: list[str], flag: int) -> int:
        a = argv[1:]
        neg = False
        if a and a[0] == "!":
            neg = True
            a = a[1:]
        res = False
        if not a:
            res = False
        elif len(a) == 1:
            res = a[0] != ""
        elif len(a) == 2 and a[0] in ("-n", "-z"):
            res = (a[1] != "") if a[0] == "-n" else (a[1] == "")
        elif len(a) == 3:
            x, op, y = a
            if op == "=":
                res = x == y
            elif op == "!=":
                res = x != y
            elif op in ("-eq", "-ne", "-lt", "-gt", "-le", "-ge"):
                xi, yi = _simple_strtol10(x), _simple_strtol10(y)
                res = {"-eq": xi == yi, "-ne": xi != yi, "-lt": xi < yi, "-gt": xi > yi,
                       "-le": xi <= yi, "-ge": xi >= yi}[op]
        if neg:
            res = not res
        return 0 if res else 1

    # -- network (시뮬레이션: 링크 없음) ----------------------------------
    def _net_down(self, kind: str) -> None:
        net = self.ub.get("net") or {}
        self.dev.record({"type": "network", "op": kind, "simulated": True, "detail": "link down / no server"})
        for line in net.get("link_down") or []:
            self.out(line + "\n")

    def do_ping(self, argv: list[str], flag: int) -> Any:
        if len(argv) < 2:
            return USAGE
        self._net_down("ping")
        if self.busy(1.0, ctrlc_poll=True):
            self.had_ctrlc = True
        self.out(f"ping failed; host {argv[1]} is not alive\n")
        return 1

    def do_tftp(self, argv: list[str], flag: int) -> Any:
        """tftpboot/tftpput: 링크가 없는 환경을 흉내 낸다 (SIMULATED). Ctrl-C 로만 멈춘다."""
        self._net_down(argv[0])
        server = self.getenv("serverip")
        ip = self.getenv("ipaddr")
        if not server:
            self.out("*** ERROR: `serverip' not set\n")
            return 1
        if not ip:
            self.out("*** ERROR: `ipaddr' not set\n")
            return 1
        put = self.find_cmd(argv[0]) is self.commands.get("tftpput")
        load = simple_strtoul(argv[1], 16)[0] if len(argv) > 1 and not put else self._default_load_addr()
        filename = argv[2] if len(argv) > 2 and not put else (argv[3] if put and len(argv) > 3 else (self.getenv("bootfile") or "uImage"))
        eth = (self.ub.get("net") or {}).get("eth_name", "eth0")
        while True:
            self.out(f"Using {eth} device\n")
            self.out(f"TFTP {'to' if put else 'from'} server {server}; our IP address is {ip}\n")
            self.out(f"Filename '{filename}'.\n")
            if put:
                self.out(f"Save address: 0x{load:x}\n")
                self.out("Saving: ")
            else:
                self.out(f"Load address: 0x{load:x}\n")
                self.out("Loading: ")
            for _ in range(10):
                if self.busy(self.t("tftp_timeout", 5.0), ctrlc_poll=True):
                    self.out("\nAbort\n")
                    self.had_ctrlc = True
                    return 1
                self.out("T ")
            self.out("\nRetry count exceeded; starting again\n")


# ---------------------------------------------------------------------------
# 파괴적 명령 판정 (destructive_events 기록용)
#
# pweh.safety.classifiers 의 U-Boot DESTRUCTIVE 항목을 **독립적으로** 옮겨 적은 표다. 분류기를 import 하지 않는
# 이유: destructive_events 는 "안전 게이트가 막았어야 할 명령이 기기에 도달했는가"를 판정하는 오라클이므로,
# 검사 대상(분류기)과 같은 데이터를 공유하면 분류기 회귀를 잡지 못한다.
# ---------------------------------------------------------------------------
_U_D_SIMPLE = {
    "saveenv", "erase", "protect", "cp", "mw", "mm", "nm", "mwc", "fatwrite", "fatrm", "fatmkdir", "fatmv",
    "ext4write", "otp", "efuse", "dfu", "fastboot", "ums", "sspi", "gzwrite", "upgrade", "update", "flwrite",
    "snor", "sfcnor", "source", "autoscr", "loopw",
}
# 이름 → (전체 하위 명령 이름, 그중 파괴적인 것, 모르는 하위 명령이면 파괴적, 하위 명령 없으면 파괴적)
_U_SUB: dict[str, tuple[set[str], set[str], bool, bool]] = {
    "sf": ({"probe", "read", "write", "erase", "update", "protect", "test"}, {"write", "erase", "update", "protect", "test"}, False, False),
    "nand": ({"info", "device", "bad", "read", "dump", "erase", "write", "scrub", "torture", "markbad", "biterr", "lock", "unlock"},
             {"erase", "write", "scrub", "torture", "markbad", "biterr", "lock", "unlock"}, False, False),
    "mmc": ({"info", "list", "dev", "part", "read", "rescan", "erase", "write", "swrite", "hwpartition", "bootbus",
             "bootpart-resize", "partconf", "rst-function", "setdsr"},
            {"erase", "write", "swrite", "hwpartition", "bootbus", "bootpart-resize", "partconf", "rst-function", "setdsr"}, False, False),
    "mtd": ({"list", "read", "dump", "bad", "write", "erase", "torture", "markbad"}, {"write", "erase", "torture", "markbad"}, False, False),
    "env": ({"print", "info", "exists", "grep", "flags", "callbacks", "set", "default", "delete", "edit", "import", "export",
             "ask", "select", "load", "run", "save", "erase"}, {"save", "erase"}, False, False),
    "usb": ({"info", "tree", "storage", "start", "dev", "part", "read", "reset", "stop", "write"}, {"write"}, False, False),
    "i2c": ({"probe", "md", "dev", "bus", "crc32", "read", "speed", "reset", "mw", "mm", "nm", "write"}, {"mw", "mm", "nm", "write"}, False, False),
    "eeprom": ({"read", "write"}, {"write"}, False, False),
    "fuse": ({"read", "sense", "prog", "override"}, {"prog", "override"}, True, False),
    "ubi": ({"info", "read", "check", "part", "detach", "write", "create", "remove"}, {"write", "create", "remove"}, False, False),
    "gpt": ({"verify", "read", "guid", "setenv", "write", "swap", "rename"}, {"write", "swap", "rename"}, True, False),
    "mbr": ({"verify", "write"}, {"write"}, True, False),
    "pmic": ({"list", "dev", "dump", "read", "write"}, {"write"}, False, False),
    "regulator": ({"list", "dev", "info", "status", "value", "current", "mode", "enable", "disable"},
                  {"value", "current", "mode", "enable", "disable"}, False, False),
    "flash": ({"info"}, set(), True, False),
    "spi": (set(), set(), True, True),
    "sata": ({"info", "device", "part", "read", "init", "write"}, {"write"}, False, False),
    "scsi": ({"info", "device", "part", "read", "scan", "reset", "write"}, {"write"}, False, False),
    "ide": ({"info", "device", "part", "read", "reset", "write"}, {"write"}, False, False),
    "nvme": ({"info", "device", "part", "read", "scan", "write"}, {"write"}, False, False),
}
# 파괴적이지 않은 알려진 최상위 이름 (정확히 일치하면 접두어 판정을 하지 않는다: 예) "loop" ≠ "loopw")
_U_KNOWN_SAFE = {
    "help", "?", "version", "bdinfo", "printenv", "coninfo", "md", "crc32", "cmp", "echo", "test", "true", "false",
    "sleep", "itest", "iminfo", "imls", "flinfo", "dm", "clk", "meminfo", "loady", "loadb", "loadx", "loads", "tftp",
    "tftpboot", "tftpput", "nfs", "ping", "fatls", "fatinfo", "fatload", "fatsize", "ext4ls", "ext4load", "ext4size",
    "ext2ls", "ext2load", "ls", "load", "size", "hash", "md5sum", "sha1sum", "unzip", "lzmadec", "loop", "exit", "bmp",
    "showvar", "nboot", "getinfo", "license", "pinmux", "irq", "mii", "ver", "setenv", "editenv", "askenv", "setexpr",
    "base", "bootm", "bootz", "booti", "bootelf", "bootvx", "go", "reset", "poweroff", "dcache", "icache", "dhcp",
    "bootp", "chpart", "mtest", "rarpboot", "sntp", "boot", "bootd", "run", "bmode", "mtdparts", "gpio",
}


def _sub_destructive(name: str, args: list[str]) -> str | None:
    subs, dsubs, default_d, none_d = _U_SUB[name]
    if not args:
        return name if none_d else None
    sub = args[0]
    if sub in subs:
        return f"{name} {sub}" if sub in dsubs else None
    base = sub.split(".", 1)[0]
    if base in subs:
        return f"{name} {base}" if base in dsubs else None
    cands = [x for x in subs if x.startswith(sub)] if sub else []
    if cands:
        hit = sorted(c for c in cands if c in dsubs)
        return f"{name} {hit[0]}" if hit else None
    return f"{name} {sub}" if default_d else None


def uboot_destructive_reason(argv: list[str]) -> str | None:
    """안전 모델이 DESTRUCTIVE 로 보는 U-Boot 명령이면 대표 이름, 아니면 None (약어/'.'접미사 포함)."""
    if not argv:
        return None
    token = argv[0]
    base = token.split(".", 1)[0]
    for name in (token, base):
        if name in _U_D_SIMPLE:
            return name
        if name in _U_SUB:
            return _sub_destructive(name, argv[1:])
        if name in _U_KNOWN_SAFE:
            return None
    if not base:
        return None
    for name in sorted(_U_D_SIMPLE):
        if name.startswith(base):
            return name
    for name in sorted(_U_SUB):
        if name.startswith(base):
            r = _sub_destructive(name, argv[1:])
            if r is not None:
                return r
            _subs, dsubs, default_d, _none = _U_SUB[name]
            if dsubs or default_d:
                # 약어가 파괴적 하위 명령을 가진 명령과 겹치면 가장 위험한 후보 기준
                return name
    return None


class _BootHandoff(BaseException):
    def __init__(self, kernel: BootKernel) -> None:
        super().__init__("boot")
        self.kernel = kernel


# ---------------------------------------------------------------------------
# simple 파서 분리 (run_command 의 ';' 처리)
# ---------------------------------------------------------------------------


def _split_simple(cmd: str) -> list[str]:
    tokens: list[str] = []
    s = cmd
    pos = 0
    n = len(s)
    while pos < n:
        inquotes = False
        sep = pos
        while sep < n:
            ch = s[sep]
            prev = s[sep - 1] if sep > 0 else "\0"
            if ch == "'" and prev != "\\":
                inquotes = not inquotes
            if not inquotes and ch == ";" and sep != pos and prev != "\\":
                break
            sep += 1
        tokens.append(s[pos:sep])
        pos = sep + 1 if sep < n else n
    return tokens


def _simple_strtol10(text: str) -> int:
    t = text.strip()
    neg = t.startswith("-")
    if neg:
        t = t[1:]
    v, _ = simple_strtoul(t, 10)
    return -v if neg else v


# ---------------------------------------------------------------------------
# hush 파서 (U-Boot cli_hush.c 의 부분 집합)
# ---------------------------------------------------------------------------

_RESERVED = {"if", "then", "elif", "else", "fi", "for", "in", "do", "done", "while", "until"}
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _hush_tokens(text: str) -> list[tuple[str, Any]]:
    """토큰: ('word', [(kind, text), ...], plain_text_or_None) / ('op', ';'|'&&'|'||'|'\\n')."""
    toks: list[tuple[str, Any]] = []
    i = 0
    n = len(text)
    word: list[tuple[str, str]] = []
    plain = True
    started = False

    def flush() -> None:
        nonlocal word, plain, started
        if started:
            raw = "".join(t for k, t in word if k == "lit") if plain and all(k == "lit" for k, _ in word) else None
            toks.append(("word", word, raw))
        word = []
        plain = True
        started = False

    def add(kind: str, s: str) -> None:
        nonlocal started
        started = True
        if kind == "lit" and word and word[-1][0] == "lit":
            word[-1] = ("lit", word[-1][1] + s)
        else:
            word.append((kind, s))

    def read_var(j: int) -> tuple[str | None, int]:
        # text[j] == '$'
        if j + 1 < n and text[j + 1] == "{":
            k = text.find("}", j + 2)
            if k < 0:
                raise _HushIncomplete()
            return text[j + 2 : k], k + 1
        if j + 1 < n and text[j + 1] == "?":
            return "?", j + 2
        m = _NAME_RE.match(text, j + 1)
        if m:
            return m.group(0), m.end()
        return None, j + 1

    while i < n:
        c = text[i]
        if c in " \t":
            flush()
            i += 1
            continue
        if c == "\n":
            flush()
            toks.append(("op", "\n"))
            i += 1
            continue
        if c == "#" and not started:
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == ";":
            flush()
            toks.append(("op", ";"))
            i += 1
            continue
        if c == "&":
            flush()
            if text.startswith("&&", i):
                toks.append(("op", "&&"))
                i += 2
                continue
            raise _HushSyntax("&")
        if c == "|":
            flush()
            if text.startswith("||", i):
                toks.append(("op", "||"))
                i += 2
                continue
            raise _HushSyntax("|")
        if c == "\\":
            if i + 1 >= n:
                raise _HushIncomplete()
            if text[i + 1] == "\n":
                i += 2
                continue
            plain = False
            add("lit", text[i + 1])
            i += 2
            continue
        if c == "'":
            k = text.find("'", i + 1)
            if k < 0:
                raise _HushIncomplete()
            plain = False
            add("lit", text[i + 1 : k])
            i = k + 1
            continue
        if c == '"':
            plain = False
            started = True
            j = i + 1
            buf = []
            while True:
                if j >= n:
                    raise _HushIncomplete()
                ch = text[j]
                if ch == '"':
                    j += 1
                    break
                if ch == "\\" and j + 1 < n and text[j + 1] in '"\\$`\n':
                    buf.append(text[j + 1])
                    j += 2
                    continue
                if ch == "$":
                    name, nj = read_var(j)
                    if name is None:
                        buf.append("$")
                        j = nj
                        continue
                    if buf:
                        add("lit", "".join(buf))
                        buf = []
                    add("var", name)
                    j = nj
                    continue
                buf.append(ch)
                j += 1
            if buf:
                add("lit", "".join(buf))
            else:
                add("lit", "")
            i = j
            continue
        if c == "$":
            name, nj = read_var(i)
            if name is None:
                add("lit", "$")
            else:
                plain = False
                add("var", name)
            i = nj
            continue
        add("lit", c)
        i += 1
    flush()
    return toks


def _hush_assignment(word: list[tuple[str, str]]) -> tuple[str, list[tuple[str, str]]] | None:
    if not word or word[0][0] != "lit":
        return None
    first = word[0][1]
    m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)=", first)
    if not m:
        return None
    rest = [("lit", first[m.end():])] + list(word[1:])
    return m.group(1), rest


class _HushParser:
    def __init__(self, toks: list[tuple[str, Any]]) -> None:
        self.toks = toks
        self.pos = 0

    def peek(self) -> tuple[str, Any] | None:
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def is_word(self, value: str) -> bool:
        t = self.peek()
        return t is not None and t[0] == "word" and t[2] == value

    def skip_seps(self) -> None:
        while True:
            t = self.peek()
            if t is not None and t[0] == "op" and t[1] in (";", "\n"):
                self.pos += 1
            else:
                break

    def expect_word(self, value: str) -> None:
        self.skip_seps()
        t = self.peek()
        if t is None:
            raise _HushIncomplete()
        if not (t[0] == "word" and t[2] == value):
            raise _HushSyntax(value)
        self.pos += 1

    def parse_list(self, terminators: tuple[str, ...] = ()) -> Any:
        items = []
        while True:
            self.skip_seps()
            t = self.peek()
            if t is None:
                break
            if t[0] == "word" and t[2] in terminators:
                break
            if t[0] == "op":
                raise _HushSyntax(t[1])
            items.append(self.parse_andor(terminators))
        return ("list", items)

    def parse_andor(self, terminators: tuple[str, ...]) -> Any:
        first = self.parse_command(terminators)
        rest = []
        while True:
            t = self.peek()
            if t is not None and t[0] == "op" and t[1] in ("&&", "||"):
                self.pos += 1
                while self.peek() is not None and self.peek()[0] == "op" and self.peek()[1] == "\n":  # type: ignore[index]
                    self.pos += 1
                if self.peek() is None:
                    raise _HushIncomplete()
                rest.append((t[1], self.parse_command(terminators)))
            else:
                break
        return ("andor", first, rest)

    def parse_command(self, terminators: tuple[str, ...]) -> Any:
        t = self.peek()
        if t is None:
            raise _HushIncomplete()
        if t[0] == "word" and t[2] == "if":
            self.pos += 1
            clauses = []
            cond = self.parse_list(("then",))
            self.expect_word("then")
            body = self.parse_list(("elif", "else", "fi"))
            clauses.append((cond, body))
            else_body = None
            while True:
                self.skip_seps()
                if self.peek() is None:
                    raise _HushIncomplete()
                if self.is_word("elif"):
                    self.pos += 1
                    c2 = self.parse_list(("then",))
                    self.expect_word("then")
                    b2 = self.parse_list(("elif", "else", "fi"))
                    clauses.append((c2, b2))
                    continue
                if self.is_word("else"):
                    self.pos += 1
                    else_body = self.parse_list(("fi",))
                self.expect_word("fi")
                break
            return ("if", clauses, else_body)
        if t[0] == "word" and t[2] == "for":
            self.pos += 1
            nt = self.peek()
            if nt is None:
                raise _HushIncomplete()
            if nt[0] != "word" or not nt[2] or not _NAME_RE.fullmatch(nt[2]):
                raise _HushSyntax("for")
            var = nt[2]
            self.pos += 1
            words = []
            if self.is_word("in"):
                self.pos += 1
                while True:
                    w = self.peek()
                    if w is None:
                        raise _HushIncomplete()
                    if w[0] == "op":
                        break
                    words.append(w[1])
                    self.pos += 1
            self.expect_word("do")
            body = self.parse_list(("done",))
            self.expect_word("done")
            return ("for", var, words, body)
        if t[0] == "word" and t[2] in ("while", "until"):
            until = t[2] == "until"
            self.pos += 1
            cond = self.parse_list(("do",))
            self.expect_word("do")
            body = self.parse_list(("done",))
            self.expect_word("done")
            return ("while", cond, body, until)
        if t[0] == "word" and t[2] in _RESERVED and t[2] not in terminators:
            raise _HushSyntax(t[2])
        words = []
        while True:
            w = self.peek()
            if w is None or w[0] == "op":
                break
            if w[2] in terminators and not words:
                break
            words.append(w[1])
            self.pos += 1
        if not words:
            raise _HushSyntax("empty")
        return ("cmd", words)


def _hush_parse(text: str) -> Any:
    toks = _hush_tokens(text)
    p = _HushParser(toks)
    node = p.parse_list(())
    if p.peek() is not None:
        t = p.peek()
        raise _HushSyntax(str(t))
    return node


__all__ = ["BootKernel", "UBoot", "CMD_FLAG_REPEAT"]
