"""테스트용 가짜 OpenOCD (TCL RPC 서버 + 실행 파일 흉내).

docs/references/openocd-tcl-rpc.md §7.3 의 fake 서버 계약과, 실제 xPack OpenOCD 0.12.0+dev 에서 실측한 바이트
(~/pweh-tools/INSTALL_REPORT.md, verify/results/openocd_*.jsonl)를 따른다.

- 0x1a 프레이밍, 다중 연결, 4 MiB 줄 제한(종결자 없는 ``line too long\\n\\x00`` 응답까지 재현)
- 작은 Tcl 인터프리터: set / list / catch / capture / $var / [cmd] / {braces} / "quotes" — 원시 봉투
  ``list [catch {capture {CMD}} r] $r`` 와 데이터 봉투, 참고 문서의 ``set _pweh_rc [catch ...]`` 봉투 모두 그대로 해석
- 결과 리스트는 jim.c 의 ListElementQuotingType/BackslashQuoteString 을 **독립적으로** 옮긴 인코더로 만든다
  (클라이언트 파서와 같은 코드를 쓰지 않기 위해)
- 프로파일: ``xpack`` (기본, 끝 개행 제거, 실패 rc=1, capture=로그+결과), ``v0.12.0`` (끝 개행 유지, 실패 rc=-4,
  capture=로그가 있으면 로그만, flash list 한 줄 10진), ``v0.11.0`` (+ read_memory/write_memory 없음)
- 장치 모델: TAP/타깃/레지스터/메모리 영역/플래시 뱅크, 장애 주입(읽기 실패, 일시 오류, 지연, 파일 미가시, 크래시)

실행 파일로도 동작한다: ``python fake_openocd.py -f interface/x.cfg -c "tcl port 0" ...``
(환경변수 FAKE_OPENOCD_MODE=ok|adapter_fail|jtag_all_ones|hang|crash_after_first, FAKE_OPENOCD_PROFILE=...)
"""

from __future__ import annotations

import os
import re
import signal
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

TERM = b"\x1a"
TCL_LINE_MAX = 4 * 1024 * 1024

# ---------------------------------------------------------------------------
# Jim 리스트 인코딩 (jim.c ListElementQuotingType / BackslashQuoteString 이식)
# ---------------------------------------------------------------------------

_SIMPLE, _BRACE, _QUOTE = 0, 1, 2
_SPECIAL = set(' $"[];\\\r\n\t\f\v')


def _quoting_type(s: str) -> int:
    n = len(s)
    if n == 0:
        return _BRACE
    try_simple = True
    if s[0] in '"{':
        try_simple = False
    else:
        for ch in s:
            if ch in _SPECIAL:
                try_simple = False
                break
            if ch in "{}":
                break
        else:
            return _SIMPLE
    # testbrace
    if s[-1] == "\\":
        return _QUOTE
    level = blevel = 0
    i = 0
    while i < n:
        ch = s[i]
        if ch == "{":
            level += 1
        elif ch == "}":
            level -= 1
            if level < 0:
                return _QUOTE
        elif ch == "[":
            blevel += 1
        elif ch == "]":
            blevel -= 1
        elif ch == "\\":
            if i + 1 < n and s[i + 1] == "\n":
                return _QUOTE
            if i + 1 < n:
                i += 1
        i += 1
    if blevel < 0:
        return _QUOTE
    if level == 0:
        if not try_simple:
            return _BRACE
        for ch in s:
            if ch in _SPECIAL:
                return _BRACE
        return _SIMPLE
    return _QUOTE


_BS_MAP = {"\n": "\\n", "\r": "\\r", "\t": "\\t", "\f": "\\f", "\v": "\\v"}


def _backslash_quote(s: str) -> str:
    out = []
    for ch in s:
        if ch in ' $"[]{};\\':
            out.append("\\" + ch)
        elif ch in _BS_MAP:
            out.append(_BS_MAP[ch])
        else:
            out.append(ch)
    return "".join(out)


def jim_list(items: list[str]) -> str:
    parts = []
    for i, s in enumerate(items):
        q = _quoting_type(s)
        if q == _SIMPLE and i == 0 and s.startswith("#"):
            q = _BRACE
        if q == _SIMPLE:
            parts.append(s)
        elif q == _BRACE:
            parts.append("{" + s + "}")
        else:
            parts.append(("\\" if i == 0 and s.startswith("#") else "") + _backslash_quote(s))
    return " ".join(parts)


# ---------------------------------------------------------------------------
# 미니 Tcl 인터프리터
# ---------------------------------------------------------------------------


class TclError(Exception):
    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class TclExit(Exception):
    """shutdown/exit (JIM_EXIT): catch 로 잡히지 않는다."""

    def __init__(self, shutdown: bool) -> None:
        super().__init__("exit")
        self.shutdown = shutdown


class CmdFail(Exception):
    """OpenOCD C 명령 실패: output 은 command_print 로 쌓인 출력."""

    def __init__(self, output: str = "", syntax: bool = False) -> None:
        super().__init__(output)
        self.output = output
        self.syntax = syntax


_ESC = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}


def _find_brace(s: str, i: int) -> int:
    depth = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise TclError("missing close-brace")


def _find_bracket(s: str, i: int) -> int:
    """s[i] == '[' 에 대응하는 ']' (중첩/중괄호/따옴표 고려)."""
    depth = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "{":
            i = _find_brace(s, i) + 1
            continue
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise TclError("missing close-bracket")


class Interp:
    def __init__(self, device: "Device") -> None:
        self.dev = device
        self.vars: dict[str, str] = {}

    # -- 파싱 + 치환 -----------------------------------------------------
    def _subst_word(self, s: str, i: int, quoted: bool) -> tuple[str, int]:
        n = len(s)
        buf: list[str] = []
        while i < n:
            c = s[i]
            if quoted and c == '"':
                return "".join(buf), i + 1
            if not quoted and c in " \t\r\n;":
                break
            if c == "\\":
                if i + 1 < n:
                    d = s[i + 1]
                    if d == "\n":
                        buf.append(" ")
                        i += 2
                        continue
                    buf.append(_ESC.get(d, d))
                    i += 2
                    continue
                buf.append("\\")
                i += 1
                continue
            if c == "[":
                j = _find_bracket(s, i)
                buf.append(self.eval(s[i + 1 : j]))
                i = j + 1
                continue
            if c == "$":
                m = re.match(r"\$(?:\{([^}]*)\}|((?:::)?[A-Za-z0-9_]+))", s[i:])
                if m:
                    name = (m.group(1) or m.group(2)).lstrip(":")
                    if name not in self.vars:
                        raise TclError(f'can\'t read "{name}": no such variable')
                    buf.append(self.vars[name])
                    i += m.end()
                    continue
            buf.append(c)
            i += 1
        if quoted:
            raise TclError("missing quote")
        return "".join(buf), i

    def _commands(self, script: str):
        """문장 단위로 (치환된 단어 목록) 을 만들며 순서대로 내보낸다."""
        s = script
        n = len(s)
        i = 0
        while i < n:
            while i < n and s[i] in " \t\r\n;":
                i += 1
            if i >= n:
                return
            if s[i] == "#":
                while i < n and s[i] != "\n":
                    i += 1
                continue
            words: list[str] = []
            while i < n and s[i] not in "\n;":
                if s[i] in " \t\r":
                    i += 1
                    continue
                if s[i] == "{":
                    j = _find_brace(s, i)
                    words.append(s[i + 1 : j])
                    i = j + 1
                elif s[i] == '"':
                    w, i = self._subst_word(s, i + 1, quoted=True)
                    words.append(w)
                else:
                    w, i = self._subst_word(s, i, quoted=False)
                    words.append(w)
            if words:
                yield words

    def eval(self, script: str) -> str:
        result = ""
        for words in self._commands(script):
            result = self.call(words)
        return result

    # -- 명령 디스패치 -----------------------------------------------------
    def call(self, words: list[str]) -> str:
        name = words[0].lstrip(":") if words[0].startswith("::") else words[0]
        args = words[1:]
        if name == "set":
            if len(args) == 1:
                if args[0] not in self.vars:
                    raise TclError(f'can\'t read "{args[0]}": no such variable')
                return self.vars[args[0]]
            if len(args) != 2:
                raise TclError('wrong # args: should be "set varName ?newValue?"')
            self.vars[args[0].lstrip(":")] = args[1]
            return args[1]
        if name == "list":
            return jim_list(args)
        if name == "catch":
            if not args:
                raise TclError('wrong # args: should be "catch ?-?no?code ... --? script ?resultVarName? ?optionVarName?"')
            try:
                res = self.eval(args[0])
                code = 0
            except TclError as e:
                res, code = e.message, e.code
            if len(args) >= 2:
                self.vars[args[1].lstrip(":")] = res
            return str(code)
        if name == "capture":
            if len(args) != 1:
                raise TclError("capture: wrong # args")
            return self.dev.capture(lambda: self.eval(args[0]))
        if name == "return":
            return args[-1] if args else ""
        if name == "error":
            raise TclError(args[0] if args else "")
        return self.dev.command(name, args, self)


# ---------------------------------------------------------------------------
# 장치 모델
# ---------------------------------------------------------------------------


@dataclass
class Tap:
    name: str
    idcode: int
    expected: list[int]
    irlen: int = 4
    ircap: int = 0x01
    irmask: int = 0x0F
    enabled: bool = True
    mfg_name: str = "ARM Ltd"


@dataclass
class Target:
    name: str
    type: str
    tap: str
    endian: str = "little"
    state: str = "running"
    regs: list[tuple[str, int, int]] = field(default_factory=list)  # (이름, 비트, 값)
    regs_valid: bool = False
    supports_memory: bool = True
    require_halt: bool = True
    halt_fails: bool = False


@dataclass
class Region:
    base: int
    data: bytearray
    name: str = "ram"
    writable: bool = True


@dataclass
class Bank:
    name: str
    driver: str
    base: int
    data: bytearray
    target: str
    sector_size: int = 0x10000
    probed: bool = True


def _pattern(n: int, seed: int = 0) -> bytearray:
    """결정적이지만 반복되지 않는 내용 (청크 위치 오류를 잡기 위해)."""
    import random

    return bytearray(random.Random(seed).randbytes(n))


ARM_REGS = [(f"r{i}", 32, 0x1000 + i) for i in range(13)] + [("sp", 32, 0x80F00000), ("lr", 32, 0x80001234), ("pc", 32, 0x80008000), ("cpsr", 32, 0x600001D3)]


class Device:
    def __init__(self, profile: str = "xpack") -> None:
        self.profile = profile
        self.lock = threading.RLock()
        self.taps = [Tap("cam.cpu", 0x07926F0F, [0x07926F0F], irlen=4, ircap=0x1, irmask=0xF, mfg_name="ARM Ltd")]
        self.targets = [Target("cam.cpu", "arm926ejs", "cam.cpu", regs=list(ARM_REGS))]
        self.current = 0
        self.regions = [Region(0x80000000, _pattern(4 * 1024 * 1024), "ddr")]
        self.banks: list[Bank] = [Bank("cam.flash", "fake_spi", 0x00000000, _pattern(256 * 1024, seed=0x55), "cam.cpu")]
        self.adapter_khz = 1000
        self.log_lines: list[str] = []  # 'Info : ...' 형식 (실행 파일 모드에서 stderr 로)
        self._captures: list[list[str]] = []
        self.executed: list[list[str]] = []
        self.log_sink: Callable[[str], None] | None = None
        # 장애 주입
        self.fail_read_ranges: list[tuple[int, int]] = []  # [start, end)
        self.transient_read_failures = 0
        self.dump_delay_per_kib = 0.0
        self.dump_image_writes_file = True
        self.corrupt_next_reads = 0
        self.crash_on: set[str] = set()
        self.crash_hook: Callable[[], None] | None = None
        self.on_command: Callable[[str, list[str]], None] | None = None

    # -- 로그 / capture ---------------------------------------------------
    def log(self, level: str, msg: str) -> None:
        prefix = {"info": "Info : ", "warn": "Warn : ", "error": "Error: ", "user": ""}[level]
        line = prefix + msg
        self.log_lines.append(line)
        if self.log_sink:
            self.log_sink(line)
        for cap in self._captures:
            cap.append(msg + "\n")

    def capture(self, fn: Callable[[], str]) -> str:
        buf: list[str] = []
        self._captures.append(buf)
        err: TclError | None = None
        try:
            try:
                result = fn()
            except TclError as e:
                err = e
                result = e.message
        finally:
            self._captures.remove(buf)
        logs = "".join(buf)
        if self.profile == "xpack":
            out = ""
            if logs:
                out += logs + "\n"
            if result:
                out += result + "\n"
            out = out[:-1] if out.endswith("\n") else out
        else:
            out = logs if logs else result
        if err is not None:
            # xPack/master: capture 는 C 명령이라 실패하면 ERROR_FAIL → catch 는 1. 0.12.0/0.11: 내부 코드 그대로 전달
            raise TclError(out, code=1 if self.profile == "xpack" else err.code)
        return out

    # -- 결과 포장 (C 명령) ---------------------------------------------------
    def _finish(self, out: str) -> str:
        if self.profile == "xpack":
            return out[:-1] if out.endswith("\n") else out
        return out

    def _fail(self, out: str = "", syntax: bool = False):
        out = self._finish(out) if self.profile == "xpack" else out
        code = 1 if self.profile == "xpack" else (-601 if syntax else -4)
        raise TclError(out, code=code)

    # -- 메모리 -------------------------------------------------------------
    def _tgt(self, name: str | None = None) -> Target:
        if name:
            for t in self.targets:
                if t.name == name:
                    return t
            raise TclError(f'invalid command name "{name}"')
        return self.targets[self.current]

    def read_mem(self, addr: int, n: int, tgt: Target) -> bytes:
        if not tgt.supports_memory:
            self.log("error", f"Target {tgt.name} doesn't support read_memory")
            raise CmdFail()
        if tgt.require_halt and tgt.state != "halted":
            self.log("error", f"[{tgt.name}] not halted")
            raise CmdFail()
        for a, b in self.fail_read_ranges:
            if addr < b and addr + n > a:
                self.log("error", f"Failed to read memory at 0x{max(addr, a):08x}")
                raise CmdFail()
        if self.transient_read_failures > 0:
            self.transient_read_failures -= 1
            self.log("error", f"Failed to read memory at 0x{addr:08x}")
            raise CmdFail()
        for r in self.regions:
            if r.base <= addr and addr + n <= r.base + len(r.data):
                data = bytes(r.data[addr - r.base : addr - r.base + n])
                if self.corrupt_next_reads > 0 and data:
                    self.corrupt_next_reads -= 1
                    data = bytes([data[0] ^ 0xFF]) + data[1:]
                return data
        for bk in self.banks:  # 메모리 맵 플래시 창
            if bk.base <= addr and addr + n <= bk.base + len(bk.data) and bk.base != 0:
                return bytes(bk.data[addr - bk.base : addr - bk.base + n])
        self.log("error", f"Failed to read memory at 0x{addr:08x}")
        raise CmdFail()

    def write_mem(self, addr: int, data: bytes, tgt: Target) -> None:
        if not tgt.supports_memory:
            self.log("error", f"Target {tgt.name} doesn't support write_memory")
            raise CmdFail()
        for r in self.regions:
            if r.base <= addr and addr + len(data) <= r.base + len(r.data) and r.writable:
                r.data[addr - r.base : addr - r.base + len(data)] = data
                return
        self.log("error", f"Failed to write memory at 0x{addr:08x}")
        raise CmdFail()

    def _bank(self, ident: str) -> Bank:
        for i, b in enumerate(self.banks):
            if ident == str(i) or ident == b.name:
                return b
        raise CmdFail(syntax=True)

    # -- 출력 포맷 (OpenOCD 소스의 포맷 문자열) ----------------------------------
    def fmt_scan_chain(self) -> str:
        lines = [
            "   TapName             Enabled  IdCode     Expected   IrLen IrCap IrMask",
            "-- ------------------- -------- ---------- ---------- ----- ----- ------",
        ]
        for i, t in enumerate(self.taps):
            exp = f"0x{t.expected[0]:08x}" if t.expected else "0x00000000"
            lines.append(f"{i:2d} {t.name:<18s}     {'Y' if t.enabled else 'n'}     0x{t.idcode:08x} {exp} {t.irlen:5d} 0x{t.ircap:02x}  0x{t.irmask:02x}")
            for e in t.expected[1:]:
                lines.append(" " * 43 + f"0x{e:08x}")
        return "\n".join(lines) + "\n"

    def fmt_targets(self) -> str:
        lines = [
            "    TargetName         Type       Endian TapName            State       ",
            "--  ------------------ ---------- ------ ------------------ ------------",
        ]
        for i, t in enumerate(self.targets):
            mark = "*" if i == self.current else " "
            lines.append(f"{i:2d}{mark} {t.name:<18s} {t.type:<10s} {t.endian:<6s} {t.tap:<18s} {t.state}")
        return "\n".join(lines) + "\n"

    def fmt_md(self, addr: int, size: int, data: bytes, endian: str) -> str:
        per_line = 32 // size
        out = []
        cur = ""
        count = len(data) // size
        for i in range(count):
            if i % per_line == 0:
                cur = f"0x{addr + i * size:08x}: "
            v = int.from_bytes(data[i * size : (i + 1) * size], "big" if endian == "big" else "little")
            cur += f"{v:0{size * 2}x} "
            if i % per_line == per_line - 1 or i == count - 1:
                out.append(cur)
        return "\n".join(out) + "\n"

    def _halted_msg(self, t: Target) -> None:
        pfx = f"[{t.name}] " if self.profile == "xpack" else ""
        pc = next((v for n, _, v in t.regs if n == "pc"), 0)
        self.log("user", f"{pfx}target halted in ARM state due to debug-request, current mode: Supervisor")
        self.log("user", f"cpsr: 0x600001d3 pc: 0x{pc:08x}")
        self.log("user", "MMU: disabled, D-Cache: disabled, I-Cache: enabled")

    # -- 명령 ----------------------------------------------------------------
    def command(self, name: str, args: list[str], interp: Interp) -> str:
        with self.lock:
            self.executed.append([name, *args])
            if self.on_command:
                self.on_command(name, args)
            if name in self.crash_on and self.crash_hook:
                self.crash_hook()
            # 타깃 접두 형태: <target> <subcmd>
            for t in self.targets:
                if name == t.name and args:
                    return self._target_sub(t, args[0], args[1:], interp)
            fn = getattr(self, "c_" + name.replace("-", "_"), None) if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) else None
            if fn is None:
                if self.profile == "v0.11.0" and name in ("read_memory", "write_memory"):
                    raise TclError(f'invalid command name "{name}"')
                raise TclError(f'invalid command name "{name}"')
            try:
                return fn(args, interp)
            except CmdFail as cf:
                self._fail(cf.output, syntax=cf.syntax)
                raise AssertionError("unreachable")

    def _target_sub(self, t: Target, sub: str, args: list[str], interp: Interp) -> str:
        if sub == "curstate":
            return t.state
        if sub == "cget" and args == ["-endian"]:
            return t.endian
        if sub in ("read_memory", "mdw", "mdh", "mdb", "mdd", "write_memory"):
            saved = self.current
            self.current = self.targets.index(t)
            try:
                return self.command(sub, args, interp)
            finally:
                self.current = saved
        raise TclError(f"Unknown target subcommand {sub}")

    def c_version(self, args, interp):
        return {
            "xpack": "xPack Open On-Chip Debugger 0.12.0+dev-02228-ge5888bda3-dirty (2025-10-04-22:42)",
            "v0.12.0": "Open On-Chip Debugger 0.12.0\n",
            "v0.11.0": "Open On-Chip Debugger 0.11.0\n",
        }[self.profile]

    def c_scan_chain(self, args, interp):
        return self._finish(self.fmt_scan_chain())

    def c_targets(self, args, interp):
        if args:
            for i, t in enumerate(self.targets):
                if t.name == args[0]:
                    self.current = i
                    return ""
            raise CmdFail(f"Target: {args[0]} is unknown, try one of:\n")
        return self._finish(self.fmt_targets())

    def c_target(self, args, interp):
        if args and args[0] == "names":
            sep = "\n" if self.profile == "xpack" else " "
            return sep.join(t.name for t in self.targets)
        if args and args[0] == "current":
            return self._tgt().name
        raise CmdFail(syntax=True)

    def c_jtag(self, args, interp):
        if args and args[0] == "names":
            return ("\n" if self.profile == "xpack" else " ").join(t.name for t in self.taps)
        raise CmdFail(syntax=True)

    def c_adapter(self, args, interp):
        if args and args[0] == "speed":
            if len(args) > 1:
                self.adapter_khz = int(args[1])
            return self._finish(f"adapter speed: {self.adapter_khz} kHz\n")
        if args and args[0] == "name":
            return "dummy"
        raise CmdFail(syntax=True)

    def c_transport(self, args, interp):
        return "jtag"

    def c_echo(self, args, interp):
        self.log("user", args[-1] if args else "")
        return ""

    def c_poll(self, args, interp):
        return self._finish("background polling: on\n" + "".join(f"TAP: {t.name} (enabled)\n" for t in self.taps))

    def c_halt(self, args, interp):
        t = self._tgt()
        if t.halt_fails:
            self.log("error", "timed out while waiting for target halted")
            raise CmdFail()
        if t.state != "halted":
            t.state = "halted"
            t.regs_valid = True
            self._halted_msg(t)
            self.dev_notify("event halted")
        return ""

    def c_resume(self, args, interp):
        t = self._tgt()
        t.state = "running"
        t.regs_valid = False
        self.dev_notify("event resumed")
        return ""

    def c_reset(self, args, interp):
        mode = args[0] if args else "run"
        if mode not in ("run", "halt", "init"):
            raise CmdFail(syntax=True)
        for tap in self.taps:
            self.log("info", f"JTAG tap: {tap.name} tap/device found: 0x{tap.idcode:08x} (mfg: 0x{(tap.idcode >> 1) & 0x7ff:03x} ({tap.mfg_name}), part: 0x{(tap.idcode >> 12) & 0xffff:04x}, ver: 0x{tap.idcode >> 28:x})")
        for t in self.targets:
            if mode == "run":
                t.state = "running"
                t.regs_valid = False
            else:
                t.state = "halted"
                t.regs_valid = True
                self._halted_msg(t)
        return ""

    def c_wait_halt(self, args, interp):
        return ""

    def c_reg(self, args, interp):
        t = self._tgt()
        if not args:
            lines = [f"===== {t.type} registers"]
            for i, (n, bits, v) in enumerate(t.regs):
                if t.regs_valid:
                    lines.append(f"({i}) {n} (/{bits}): 0x{v:0{bits // 4}x}")
                else:
                    lines.append(f"({i}) {n} (/{bits})")
            return self._finish("\n".join(lines) + "\n") if t.regs else ""
        for i, (n, bits, v) in enumerate(t.regs):
            if n == args[0]:
                if len(args) >= 2 and args[1] != "force":
                    t.regs[i] = (n, bits, int(args[1], 0))
                    return self._finish(f"{n} (/{bits}): 0x{int(args[1], 0):0{bits // 4}x}\n")
                if t.state != "halted":
                    self.log("error", f"[{t.name}] not halted")
                    self.log("error", f"Could not read register '{n}'")
                    raise CmdFail()
                return self._finish(f"{n} (/{bits}): 0x{v:0{bits // 4}x}\n")
        raise CmdFail(f"register {args[0]} not found in current target\n")

    def _md(self, size: int, args):
        phys = bool(args) and args[0] == "phys"
        if phys:
            args = args[1:]
        if not (1 <= len(args) <= 2):
            raise CmdFail(syntax=True)
        addr = int(args[0], 0)
        count = int(args[1], 0) if len(args) == 2 else 1
        t = self._tgt()
        data = self.read_mem(addr, count * size, t)
        return self._finish(self.fmt_md(addr, size, data, t.endian))

    def c_mdw(self, args, interp):
        return self._md(4, args)

    def c_mdh(self, args, interp):
        return self._md(2, args)

    def c_mdb(self, args, interp):
        return self._md(1, args)

    def c_mdd(self, args, interp):
        return self._md(8, args)

    def c_read_memory(self, args, interp):
        if self.profile == "v0.11.0":
            raise TclError('invalid command name "read_memory"')
        if len(args) not in (3, 4):
            raise CmdFail(syntax=True)
        addr, width, count = int(args[0], 0), int(args[1], 0), int(args[2], 0)
        if width not in (8, 16, 32, 64):
            raise CmdFail("invalid width, must be 8, 16, 32 or 64\n")
        if count > 65536:
            raise CmdFail("too large read request, exceeds 64K elements\n")
        wb = width // 8
        t = self._tgt()
        out = []
        pos = 0
        while pos < count:
            chunk = min(count - pos, 4096 // wb)
            try:
                data = self.read_mem(addr + pos * wb, chunk * wb, t)
            except CmdFail:
                msg = "failed to read memory" if self.profile == "xpack" else "read_memory: failed to read memory"
                raise CmdFail(" ".join(out) + msg + "\n")
            for i in range(chunk):
                v = int.from_bytes(data[i * wb : (i + 1) * wb], "big" if t.endian == "big" else "little")
                out.append(f"0x{v:x}")
            pos += chunk
        return " ".join(out)

    def c_write_memory(self, args, interp):
        if self.profile == "v0.11.0":
            raise TclError('invalid command name "write_memory"')
        addr, width = int(args[0], 0), int(args[1], 0)
        vals = [int(x, 0) for x in args[2].split()]
        t = self._tgt()
        wb = width // 8
        data = b"".join(v.to_bytes(wb, "big" if t.endian == "big" else "little") for v in vals)
        self.write_mem(addr, data, t)
        return ""

    def _mw(self, size, args):
        if args and args[0] == "phys":
            args = args[1:]
        addr, value = int(args[0], 0), int(args[1], 0)
        count = int(args[2], 0) if len(args) > 2 else 1
        t = self._tgt()
        self.write_mem(addr, value.to_bytes(size, "big" if t.endian == "big" else "little") * count, t)
        return ""

    def c_mww(self, args, interp):
        return self._mw(4, args)

    def c_mwb(self, args, interp):
        return self._mw(1, args)

    def c_dump_image(self, args, interp):
        if len(args) != 3:
            raise CmdFail(syntax=True)
        path, addr, size = args[0], int(args[1], 0), int(args[2], 0)
        t = self._tgt()
        if self.dump_delay_per_kib:
            time.sleep(self.dump_delay_per_kib * size / 1024)
        target_path = path if self.dump_image_writes_file else path + ".elsewhere-remote"
        fh = open(target_path, "wb")  # 실제 OpenOCD 처럼 읽기 전에 열고(잘라내고) 시작
        try:
            done = 0
            while done < size:
                n = min(4096, size - done)
                data = self.read_mem(addr + done, n, t)
                fh.write(data)
                done += n
        finally:
            fh.close()
        if not self.dump_image_writes_file:
            os.unlink(target_path)
        return self._finish(f"dumped {size} bytes in 0.001000s ({size / 1024 / 0.001:.3f} KiB/s)\n")

    def c_load_image(self, args, interp):
        return self._finish("0 bytes written at address 0x00000000\ndownloaded 0 bytes in 0.000018s (0.000 KiB/s)\n")

    def c_verify_image(self, args, interp):
        path = args[0]
        addr = int(args[1], 0) if len(args) > 1 else 0
        data = open(path, "rb").read()
        for b in self.banks:
            if b.base <= addr and addr + len(data) <= b.base + len(b.data):
                cur = bytes(b.data[addr - b.base : addr - b.base + len(data)])
                if cur == data:
                    return self._finish(f"verified {len(data)} bytes in 0.001000s (1.000 KiB/s)\n")
                self.log("error", "checksum mismatch - attempting binary compare")
                raise CmdFail("diff 0 address 0x00000000. Was 0x00 instead of 0x01\n")
        raise CmdFail()

    def c_flash(self, args, interp):
        if not args:
            raise CmdFail(syntax=True)
        sub, rest = args[0], args[1:]
        if sub == "banks":
            return self._finish("".join(
                f"#{i} : {b.name} ({b.driver}) at 0x{b.base:08x}, size 0x{len(b.data):08x}, buswidth 0, chipwidth 0\n" for i, b in enumerate(self.banks)
            ))
        if sub == "list":
            if self.profile == "xpack":
                return self._finish("".join(
                    "{\n" f"    name       {b.name}\n" f"    driver     {b.driver}\n" f"    base       0x{b.base:08x}\n"
                    f"    size       0x{len(b.data):x}\n" "    bus_width  0\n" "    chip_width 0\n" f"    target     {b.target}\n" "}\n"
                    for b in self.banks
                ))
            return " ".join(f"{{name {b.name} driver {b.driver} base {b.base} size {len(b.data)} bus_width 0 chip_width 0 target {b.target}}}" for b in self.banks)
        if sub == "info":
            b = self._bank(rest[0])
            idx = self.banks.index(b)
            lines = [f"#{idx} : {b.driver} at 0x{b.base:08x}, size 0x{len(b.data):08x}, buswidth 0, chipwidth 0"]
            for i in range(len(b.data) // b.sector_size):
                lines.append(f"\t#{i:3d}: 0x{i * b.sector_size:08x} (0x{b.sector_size:x} {b.sector_size >> 10}kB) not protected")
            lines.append("fake spi flash driver")
            self.log("info", "Flash protection check is not implemented.")
            return self._finish("\n".join(lines) + "\n")
        if sub == "probe":
            b = self._bank(rest[0])
            b.probed = True
            return self._finish(f"flash '{b.driver}' found at 0x{b.base:08x}\n")
        if sub == "read_bank":
            b = self._bank(rest[0])
            path = rest[1]
            off = int(rest[2], 0) if len(rest) > 2 else 0
            if off > len(b.data):
                self.log("error", f"Offset 0x{off:08x} is out of range of the flash bank")
                raise CmdFail()
            length = int(rest[3], 0) if len(rest) > 3 else len(b.data) - off
            if off + length > len(b.data):
                self.log("error", f"Length of {length} bytes with offset 0x{off:08x} is out of range of the flash bank")
                raise CmdFail()
            if self.transient_read_failures > 0:
                self.transient_read_failures -= 1
                self.log("error", "Read error")
                raise CmdFail()
            data = bytes(b.data[off : off + length])
            if self.corrupt_next_reads > 0 and data:
                self.corrupt_next_reads -= 1
                data = bytes([data[0] ^ 0xFF]) + data[1:]
            if self.dump_image_writes_file:
                with open(path, "wb") as fh:
                    fh.write(data)
            idx = self.banks.index(b)
            return self._finish(f"wrote {length} bytes to file {path} from flash bank {idx} at offset 0x{off:08x} in 0.001000s (1.000 KiB/s)\n")
        if sub == "verify_bank":
            b = self._bank(rest[0])
            path = rest[1]
            off = int(rest[2], 0) if len(rest) > 2 else 0
            data = open(path, "rb").read()
            idx = self.banks.index(b)
            cur = bytes(b.data[off : off + len(data)])
            head = f"read {len(data)} bytes from file {path} and flash bank {idx} at offset 0x{off:08x} in 0.001000s (1.000 KiB/s)\n"
            if cur == data:
                return self._finish(head + "contents match\n")
            raise CmdFail(head + "contents differ\n")
        if sub == "write_image":
            opts = [x for x in rest if x in ("erase", "unlock")]
            rest2 = [x for x in rest if x not in ("erase", "unlock")]
            path = rest2[0]
            off = int(rest2[1], 0) if len(rest2) > 1 else 0
            data = open(path, "rb").read()
            b = self.banks[0]
            b.data[off - b.base : off - b.base + len(data)] = data
            pre = "auto erase enabled\n" if "erase" in opts else ""
            return self._finish(pre + f"wrote {len(data)} bytes from file {path} in 0.001000s (1.000 KiB/s)\n")
        raise CmdFail(syntax=True)

    def c_shutdown(self, args, interp):
        self.log("user", "shutdown command invoked")
        raise TclExit(shutdown=True)

    def c_exit(self, args, interp):
        raise TclExit(shutdown=False)

    def c_tcl_notifications(self, args, interp):
        interp.vars["__notify"] = args[0] if args else "off"
        return ""

    def c_tcl(self, args, interp):
        if args and args[0] == "notifications":
            interp.vars["__notify"] = args[1] if len(args) > 1 else "off"
            return ""
        raise CmdFail(syntax=True)

    # 알림 (연결별 플래그 → 서버가 전달)
    def dev_notify(self, what: str) -> None:
        if self._notify_cb:
            self._notify_cb(what)

    _notify_cb: Callable[[str], None] | None = None


# ---------------------------------------------------------------------------
# TCL 서버
# ---------------------------------------------------------------------------


class FakeOpenOCD:
    """스레드 기반 가짜 OpenOCD TCL RPC 서버."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, profile: str = "xpack", device: Device | None = None) -> None:
        self.host = host
        self.req_port = port
        self.profile = profile
        self.dev = device or Device(profile)
        self.dev._notify_cb = self._broadcast
        self.frames: list[str] = []  # 받은 원문 프레임
        self._sock: socket.socket | None = None
        self._threads: list[threading.Thread] = []
        self._conns: dict[socket.socket, Interp] = {}
        self._conns_lock = threading.Lock()
        self._stop = threading.Event()
        self.shutdown_requested = threading.Event()
        self.port = 0

    def start(self) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.req_port))
        s.listen(16)
        s.settimeout(0.2)
        self._sock = s
        self.port = s.getsockname()[1]
        t = threading.Thread(target=self._accept_loop, name="fake-openocd-accept", daemon=True)
        t.start()
        self._threads.append(t)
        return self.port

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        with self._conns_lock:
            conns = list(self._conns)
        for c in conns:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                c.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=2.0)

    def __enter__(self) -> "FakeOpenOCD":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            interp = Interp(self.dev)
            with self._conns_lock:
                self._conns[conn] = interp
            self.dev.log("info", f"accepting 'tcl' connection on tcp/{self.port}")
            t = threading.Thread(target=self._serve, args=(conn, interp), name="fake-openocd-conn", daemon=True)
            t.start()
            self._threads.append(t)

    def _broadcast(self, what: str) -> None:
        with self._conns_lock:
            items = list(self._conns.items())
        for c, interp in items:
            if interp.vars.get("__notify") == "on":
                try:
                    c.sendall(f"type target_{'event event ' + what.split(' ', 1)[1] if what.startswith('event') else what}\r\n".encode() + TERM)
                except OSError:
                    pass

    def _serve(self, conn: socket.socket, interp: Interp) -> None:
        buf = b""
        dropped = False
        try:
            conn.settimeout(0.2)
            while not self._stop.is_set():
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if not chunk:
                    return
                buf += chunk
                while True:
                    idx = buf.find(TERM)
                    if idx < 0:
                        if len(buf) > TCL_LINE_MAX:
                            dropped = True
                            buf = b""
                        break
                    frame, buf = buf[:idx], buf[idx + 1 :]
                    if dropped or len(frame) > TCL_LINE_MAX:
                        dropped = False
                        conn.sendall(b"line too long\n\x00")  # 실제 OpenOCD 처럼 종결자 없음
                        continue
                    text = frame.decode("utf-8", errors="replace")
                    self.frames.append(text)
                    try:
                        with self.dev.lock:  # OpenOCD 는 단일 스레드: 한 프레임이 끝날 때까지 다른 연결은 대기
                            result = interp.eval(text)
                    except TclExit as ex:
                        conn.sendall(TERM)
                        if ex.shutdown:
                            self.shutdown_requested.set()
                            threading.Thread(target=self.stop, daemon=True).start()
                        return
                    except TclError as e:
                        result = e.message
                        if self.profile != "xpack":
                            result = f"/tmp/fake.cfg:12: Error: {e.message}\nat file \"/tmp/fake.cfg\", line 12"
                    self.dev.log("user", result)  # 실제 OpenOCD 도 RPC 결과를 로그에 찍는다
                    conn.sendall(result.encode("utf-8") + TERM)
        finally:
            with self._conns_lock:
                self._conns.pop(conn, None)
            try:
                conn.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# 실행 파일 모드 (process manager 테스트용)
# ---------------------------------------------------------------------------

BANNER = [
    "xPack Open On-Chip Debugger 0.12.0+dev-02228-ge5888bda3-dirty (2025-10-04-22:42)",
    "Licensed under GNU GPL v2",
    "For bug reports, read",
    "\thttp://openocd.org/doc/doxygen/bugs.html",
]


def main(argv: list[str]) -> int:
    err = sys.stderr
    mode = os.environ.get("FAKE_OPENOCD_MODE", "ok")
    profile = os.environ.get("FAKE_OPENOCD_PROFILE", "xpack")

    def say(line: str) -> None:
        err.write(line + "\n")
        err.flush()

    if any(a in ("--version", "-v") for a in argv):
        for b in BANNER:
            say(b)
        return 0
    for b in BANNER:
        say(b)
    cmds: list[str] = []
    files: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-c", "-f", "-s") and i + 1 < len(argv):
            (cmds if a == "-c" else files if a == "-f" else []).append(argv[i + 1])
            i += 2
            continue
        i += 1
    for f in files:
        if "missing" in f or (os.path.isabs(f) and not os.path.exists(f)):
            say(f"embedded:startup.tcl:28: Error: Can't find {f}")
            say("in procedure 'script'")
            return 1
    port = 6666
    for c in cmds:
        m = re.search(r"tcl[ _]port (\d+)", c)
        if m:
            port = int(m.group(1))
            break
    if mode == "adapter_fail":
        say("Error: unable to open ftdi device with description '*', serial '*' at bus location '*'")
        return 1
    if mode == "hang":
        while True:
            time.sleep(1)
    dev = Device(profile)
    dev.log_sink = say
    say("adapter speed: 1000 kHz")
    say("Info : clock speed 1000 kHz")
    if mode == "jtag_all_ones":
        say("Error: JTAG scan chain interrogation failed: all ones")
        say("Error: Check JTAG interface, timings, target power, etc.")
        say("Error: Trying to use configured scan chain anyway...")
        say("Warn : Bypassing JTAG setup events due to errors")
        say("Error: [cam.cpu] Examination failed")
        dev.taps[0].idcode = 0xFFFFFFFF
    else:
        tap = dev.taps[0]
        say(f"Info : JTAG tap: {tap.name} tap/device found: 0x{tap.idcode:08x} (mfg: 0x{(tap.idcode >> 1) & 0x7ff:03x} ({tap.mfg_name}), part: 0x{(tap.idcode >> 12) & 0xffff:04x}, ver: 0x{tap.idcode >> 28:x})")
        say("Info : [cam.cpu] Examination succeed")
    srv = FakeOpenOCD(port=port, profile=profile, device=dev)
    try:
        srv.start()
    except OSError as exc:
        say(f"Error: couldn't bind tcl to socket on port {port}: {exc.strerror}")
        return 1
    if mode == "crash_after_first":
        def crash() -> None:
            # 실제 OpenOCD 는 단일 스레드라 명령 처리 중 SIGSEGV 로 죽으면 응답을 절대 보내지 못한다.
            # os.kill(getpid()) 는 '프로세스' 대상 신호라 커널이 (sleep 중인) 메인 스레드에 배달하고, 그 스레드가
            # 스케줄될 때까지 이 연결 스레드는 계속 달려 halt 응답을 보낼 수 있었다(부하가 크면 재현되는 플래키의 원인).
            # 호출 스레드 대상 신호(pthread_kill)는 시스템 호출에서 돌아오기 전에 이 스레드에 배달되어 즉시 종료된다.
            signal.pthread_kill(threading.get_ident(), signal.SIGSEGV)
            while True:  # 방어: 신호가 늦게 배달되더라도 응답을 보내지 않는다
                time.sleep(1)
        dev.crash_on = {"halt"}
        dev.crash_hook = crash
    say(f"Info : Listening on port {srv.port} for tcl connections")
    say("Info : telnet server disabled")
    try:
        while not srv.shutdown_requested.is_set():
            time.sleep(0.05)
    except KeyboardInterrupt:
        pass
    srv.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
