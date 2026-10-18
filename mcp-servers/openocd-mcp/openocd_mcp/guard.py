"""openocd-mcp 의 명령 위험도 분류 (코어 classify_openocd + 더 엄격한 로컬 규칙).

원칙: 로컬 규칙은 **더 엄격하게만** 작동한다. 최종 위험도는 항상 ``worst(코어 분류, 로컬 분류)`` 이다.

로컬 규칙이 메우는 코어 분류기의 빈틈 (실제 xPack OpenOCD 0.12.0+dev 에서 실행되는 것을 확인):
- 명령 이름 우회: ``::mww 0 0``, ``m\\ww 0 0`` 는 mww 를 실행하지만 코어는 '알 수 없는 명령'(MODIFY)으로 본다.
- 명령 위치의 명령 치환/확장: ``[string cat m ww] 0 0``, ``{*}[list mww 0 0]``.
- 따옴표로 감싼 스크립트 본문: ``capture "flash erase_sector 0 0 last"`` (OpenOCD 매뉴얼 예제가 이 형태다),
  ``catch "mww 0 0"``, ``if 1 "..."`` — 코어는 중괄호 안만 명령으로 본다.
- 코어 표에 없어 MODIFY 로 떨어지는 호스트 탈출/영구 변경 명령: ``popen``, ``socket``, ``load``, ``script``,
  ``os.fork``, ``pipe``, ``kill``, ``package``, ``log_output <path>``(호스트 파일 생성), ``svf``/``xsvf``,
  ``irscan``/``drscan``(바운더리 스캔으로 핀 구동 가능), ``mmw``/``memwrite*``/``array2mem``(메모리 쓰기),
  ``<dap> apreg`` 쓰기(MEM-AP 경유 임의 메모리 쓰기), ``arm semihosting enable`` 등.

또한 덤프 작업이 내부적으로 만드는 ``dump_image {케이스경로} ...`` / ``flash read_bank N {케이스경로} ...`` 는
코어에서 DESTRUCTIVE(호스트 임의 경로 쓰기)로 분류되지만, 서버가 경로를 케이스 디렉터리 안으로 강제하므로
``classify_managed`` 에서 기기 측 동작(읽기 = INTERACT)으로 분류한다. 이 예외는 정확한 정규식 + 경로 검사로만 적용된다.

검토 단계에서 추가한 규칙 (모두 xPack OpenOCD 0.12.0-7 의 Jim 에서 본문이 실제로 실행됨을 확인):
- 문장별 코어 분류: 코어는 줄을 나눠 ``#`` 로 시작하는 줄을 지운다. 지금은 Jim 처럼 ``\\n`` 에서만 나누지만(예전에는
  splitlines 라 ``\\r \\v \\f \\x1c-\\x1e \\x85`` 에서도 나눴다), 따옴표 안의 개행 뒤 ``#`` 는 여전히 주석으로 지운다
  (``set x "<LF># "; mww 0 0`` 의 mww 가 코어 눈에서 사라짐). 로컬 파서가 나눈 문장마다 코어 분류를 다시 돌려 막는다.
- 스크립트 본문 위치: ``catch -error -- "본문"``(옵션 뒤 본문), ``dict for/with/update/map ... 본문``, ``loop ... 본문``,
  OpenOCD 이벤트 핸들러 ``-event <이름> 본문``(target configure/create, jtag configure), 명령 접두를 받는
  ``-command <명령>``(lsort/lsearch/regsub/switch). 본문이 동적(``$x``, ``[...]``)이면 확정 불가로 DESTRUCTIVE.
- 식(expr) 위치: ``expr``, ``if``/``elseif`` 조건, ``while`` 조건, ``for`` 검사식. 중괄호 없는 식의 변수/명령 치환은
  expr 가 치환 결과를 다시 해석하므로(이중 치환: ``set x "\\x5bmww 0 0\\x5d"; expr $x``) DESTRUCTIVE + uncertain,
  중괄호 식 안의 ``[...]`` 명령 치환도 재귀 분류한다.
- 코어 표에 없는(알 수 없는) 명령의 따옴표/중괄호/백슬래시 인자는 스크립트 본문일 수 있으므로 재귀 분류한다
  (예: Jim aio ``stdout readable "..."``). 이벤트 루프를 돌리는 ``update``/``vwait``, 매 명령 전 훅을 거는 ``xtrace``,
  람다를 만드는 ``curry`` 는 간접 실행으로 DESTRUCTIVE.
- 이 서버가 끈 telnet/GDB 명령 서버를 다시 여는 ``telnet port N``/``gdb port N``/``-gdb-port N`` (``disabled`` 제외)은
  그 포트로 들어오는 명령(GDB ``monitor`` 포함)이 게이트를 거치지 않으므로 DESTRUCTIVE (시작 명령으로 연 telnet 에서 실행 확인).

점 없는 타깃 이름 (mem_ap, cpu0 — 실측: xPack 0.12.0-7 에서 ``cpu0 read_memory …`` 는 타깃 명령으로 디스패치된다):
- 에이전트 원시 명령: 코어는 점 있는 첫 단어만 타깃 접두로 보므로, 코어 표에 없는 첫 단어 뒤의 단어를 하위 명령으로도
  분류해 worst 로 합친다 (더 엄격하게만: ``cpu0 mww …`` = DESTRUCTIVE, ``cpu0 read_memory …`` 는 그대로 MODIFY).
- 서버가 만든 ``<타깃> read_memory …`` / ``<타깃> md* …`` 만 ``classify_target_read`` 로, 서버가 실제 ``target names``
  목록에서 확인했고 명령 이름과 겹치지 않는 타깃이면 접두를 떼고 분류한다 (덤프 작업은 ``trusted_targets`` 로 전달).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from pweh.errors import SafetyDenied
from pweh.fsutil import is_within
from pweh.safety import Classification, Risk, classify_openocd, worst
from pweh.safety.classifiers import OPENOCD_COMMANDS, OPENOCD_SUBCOMMANDS

from .tcl import TclParseError, _find_close_brace, backslash_subst

O, I, M, D = Risk.OBSERVE, Risk.INTERACT, Risk.MODIFY, Risk.DESTRUCTIVE

_MAX_DEPTH = 8


# ---------------------------------------------------------------------------
# 최소 Tcl 문장 파서 (분류 전용)
# ---------------------------------------------------------------------------


@dataclass
class TWord:
    text: str
    value: str
    braced: bool = False
    quoted: bool = False
    expand: bool = False
    has_var: bool = False
    has_backslash: bool = False
    subscripts: list[str] = field(default_factory=list)  # [ ] 명령 치환 스크립트 원문

    @property
    def has_cmd_subst(self) -> bool:
        return bool(self.subscripts)


@dataclass
class TStatement:
    words: list[TWord]
    text: str  # 원문 구간


def _skip_spaces(s: str, i: int) -> int:
    n = len(s)
    while i < n:
        if s[i] in " \t\r\f\v":
            i += 1
        elif s[i] == "\\" and i + 1 < n and s[i + 1] == "\n":
            i += 2
        else:
            break
    return i


def _parse_word(s: str, i: int, close: str | None) -> tuple[TWord, int]:
    n = len(s)
    start = i
    expand = False
    if s.startswith("{*}", i) and i + 3 < n and s[i + 3] not in " \t\r\n;":
        expand = True
        i += 3
    if s[i] == "{":
        j = _find_close_brace(s, i)
        w = TWord(text=s[start : j + 1], value=s[i + 1 : j], braced=True, expand=expand)
        return w, j + 1
    quoted = s[i] == '"'
    if quoted:
        i += 1
    buf: list[str] = []
    w = TWord(text="", value="", quoted=quoted, expand=expand)
    while i < n:
        c = s[i]
        if quoted and c == '"':
            i += 1
            break
        if not quoted and (c in " \t\r\f\v\n;" or (close is not None and c == close)):
            break
        if c == "\\":
            if i + 1 < n and s[i + 1] == "\n" and not quoted:
                break  # 단어 구분자
            sub, i = backslash_subst(s, i)
            w.has_backslash = True
            buf.append(sub)
            continue
        if c == "[":
            _, j = _parse_script(s, i + 1, close="]", depth=1)
            w.subscripts.append(s[i + 1 : j - 1])
            buf.append(s[i:j])
            i = j
            continue
        if c == "$":
            w.has_var = True
        buf.append(c)
        i += 1
    else:
        if quoted:
            raise TclParseError("짝이 맞지 않는 큰따옴표")
    w.text = s[start:i]
    w.value = "".join(buf)
    return w, i


def _parse_script(s: str, i: int, close: str | None = None, depth: int = 0) -> tuple[list[TStatement], int]:
    if depth > 32:
        raise TclParseError("중첩이 너무 깊음")
    n = len(s)
    stmts: list[TStatement] = []
    while True:
        # 문장 사이 공백/구분자
        while i < n and (s[i] in " \t\r\f\v\n;" or (s[i] == "\\" and i + 1 < n and s[i + 1] == "\n")):
            i += 2 if s[i] == "\\" else 1
        if i >= n:
            if close is not None:
                raise TclParseError("짝이 맞지 않는 여는 대괄호")
            return stmts, i
        if close is not None and s[i] == close:
            return stmts, i + 1
        if s[i] == "#":
            while i < n and s[i] != "\n":
                i += 2 if (s[i] == "\\" and i + 1 < n) else 1
            continue
        st = i
        words: list[TWord] = []
        while True:
            i = _skip_spaces(s, i)
            if i >= n or s[i] in "\n;" or (close is not None and s[i] == close):
                break
            w, i = _parse_word(s, i, close)
            words.append(w)
        if words:
            stmts.append(TStatement(words=words, text=s[st:i].strip()))
        if i < n and s[i] in "\n;":
            i += 1


def parse_statements(script: str) -> list[TStatement]:
    stmts, _ = _parse_script(script, 0)
    return stmts


# ---------------------------------------------------------------------------
# 로컬 규칙
# ---------------------------------------------------------------------------

_HOST_ESCAPE = {
    "popen": "외부 프로세스 실행 (호스트 코드 실행)",
    "socket": "호스트 네트워크 소켓 생성",
    "load": "공유 라이브러리 로드 (호스트 코드 실행)",
    "script": "호스트의 Tcl 스크립트 파일 실행 (source 와 동일)",
    "os.fork": "프로세스 fork",
    "pipe": "호스트 파이프 생성",
    "kill": "호스트 프로세스에 시그널 전송",
    "signal": "시그널 처리 변경",
    "package": "Tcl 패키지 로드",
    "bindto": "디버그 서버 바인딩 주소 변경 (네트워크 노출 위험)",
    "exec": "외부 프로세스 실행 (호스트 코드 실행)",
    "open": "호스트 파일 열기/쓰기",
    "file": "호스트 파일 조작",
    "source": "호스트의 Tcl 스크립트 실행",
}
_INDIRECTION = {"alias", "tailcall", "upcall", "local", "ref", "finalize", "defer", "lambda", "curry", "xtrace", "update", "vwait"}
_INDIRECTION_REASONS = {
    "xtrace": "'xtrace' — 이후 모든 명령 실행 전에 호출될 훅(명령 접두)을 건다 (실행 내용 확정 불가)",
    "update": "'update' — 이벤트 루프를 돌려 등록된 after/aio 핸들러(내용 확정 불가)를 실행",
    "vwait": "'vwait' — 이벤트 루프를 돌려 등록된 after/aio 핸들러(내용 확정 불가)를 실행",
    "curry": "'curry' — 다른 명령을 부르는 람다를 만든다 (간접 실행)",
}
_MEM_WRITERS = {
    "mmw": "메모리 read-modify-write (쓰기)",
    "array2mem": "메모리 쓰기",
    "memwrite32": "메모리 쓰기", "memwrite16": "메모리 쓰기", "memwrite8": "메모리 쓰기",
    "memwrite32_phys": "메모리 쓰기", "memwrite16_phys": "메모리 쓰기", "memwrite8_phys": "메모리 쓰기",
}
_JTAG_LOWLEVEL = {
    "irscan": "임의 IR 명령(EXTEST 등) — 바운더리 스캔으로 핀을 구동하거나 비공개 TAP 기능 실행 가능 (하드웨어 손상 위험)",
    "drscan": "임의 DR 시프트 — EXTEST 상태에서는 핀을 실제로 구동 (하드웨어 손상 위험)",
    "svf": "SVF 벡터 재생 — CPLD/FPGA/플래시 영구 프로그래밍 가능",
    "xsvf": "XSVF 벡터 재생 — CPLD/FPGA/플래시 영구 프로그래밍 가능",
}
# 스크립트를 인자로 받아 실행하는 명령: 본문 인자 위치 ("all" = 모든 인자, 그 밖의 문자열은 전용 규칙)
_SCRIPT_TAKERS: dict[str, object] = {
    "capture": "all", "catch": "catch", "while": [1], "for": [0, 2, 3], "foreach": [-1], "lmap": [-1],
    "try": "all", "time": [0], "timerate": [0], "switch": "all", "eval": "all", "uplevel": "all",
    "after": "all", "apply": "all", "tailcall": "all", "upcall": "all", "local": "all", "if": "if",
    "loop": "last", "dict": "dict", "xtrace": "all",
}
_COMMAND_SERVER_REASON = (
    "telnet/GDB 명령 서버를 연다 — 그 포트로 들어오는 명령(GDB 'monitor …' 포함)은 이 서버의 안전 게이트를 거치지 않는다 "
    "(이 서버는 TCL 포트만 127.0.0.1 에 연다)"
)
# 마지막 인자가 본문인 dict 하위 명령 (Jim: dict for {k v} d body / dict with v ?key ...? body / dict update v k var ... body)
_DICT_SCRIPT_SUBS = {"for", "map", "with", "update"}
# 다음 인자(들)가 스크립트/명령 접두인 옵션: -event <이름> <본문>, -command <명령 접두>
_OPTION_SCRIPT_OFFSET = {"-event": 2, "-command": 1}
_NUMERIC = re.compile(r"[-+]?(0x[0-9a-fA-F]+|\d+)")


def _catch_script(args: list[TWord]) -> list[TWord]:
    """Jim ``catch ?-?no?code ... --? script ?resultVar? ?optionsVar?`` 의 본문 인자.

    Jim 은 마지막 인자 앞까지의 ``-`` 로 시작하는 단어를 옵션으로 소비한다(``--`` 이면 다음이 본문).
    옵션 위치에 동적 단어(``$opt``)가 오면 본문으로 간주해 보수적으로 분류된다.
    """
    i = 0
    n = len(args)
    while i < n - 1:
        v = args[i].value
        if v == "--":
            i += 1
            break
        if not v.startswith("-"):
            break
        i += 1
    return [args[i]] if i < n else []


def _if_conditions(args: list[TWord]) -> list[TWord]:
    """if expr ?then? body ?elseif expr ?then? body ...? ... 에서 조건식만."""
    out: list[TWord] = []
    n = len(args)
    if n:
        out.append(args[0])
    i = 1
    while i < n:
        if args[i].value == "then":
            i += 1
        i += 1  # 본문
        if i < n and args[i].value == "elseif":
            if i + 1 < n:
                out.append(args[i + 1])
            i += 2
            continue
        break
    return out


def _expr_words(name: str, args: list[TWord]) -> list[TWord]:
    """expr 가 식으로 해석하는 인자: expr 전체, if/elseif 조건, while 조건, for 검사식."""
    if name == "expr":
        return list(args)
    if name == "if":
        return _if_conditions(args)
    if name == "while":
        return args[:1]
    if name == "for":
        return args[1:2]
    return []


def _bracket_scripts(s: str) -> list[str]:
    """문자열 안의 (백슬래시로 이스케이프되지 않은) ``[...]`` 명령 치환 스크립트 원문 목록. 짝이 안 맞으면 TclParseError."""
    out: list[str] = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            _, j = _parse_script(s, i + 1, close="]", depth=1)
            out.append(s[i + 1 : j - 1])
            i = j
            continue
        i += 1
    return out


def _is_known_command(name: str, args: list[TWord]) -> bool:
    """코어 분류표에 있는 명령인지 (타깃 접두 형태 ``<target> <명령>`` 포함)."""
    if name in OPENOCD_COMMANDS or name in OPENOCD_SUBCOMMANDS:
        return True
    if "." in name and args:
        sub = _cmd_name(args[0])
        return sub in OPENOCD_COMMANDS or sub in OPENOCD_SUBCOMMANDS
    return False


def _if_bodies(args: list[TWord]) -> list[TWord]:
    """if expr ?then? body ?elseif expr ?then? body ...? ?else? ?body? 에서 본문만."""
    out: list[TWord] = []
    i = 0
    n = len(args)
    i += 1  # 조건
    while i < n:
        if args[i].value == "then":
            i += 1
        if i < n:
            out.append(args[i])
            i += 1
        if i < n and args[i].value == "elseif":
            i += 2  # elseif + 조건
            continue
        if i < n and args[i].value == "else":
            i += 1
            if i < n:
                out.append(args[i])
            break
        if i < n:  # else 생략형: 마지막 본문
            out.append(args[i])
        break
    return out


def _script_args(name: str, args: list[TWord]) -> list[TWord]:
    spec = _SCRIPT_TAKERS.get(name)
    if spec is None:
        return []
    if spec == "all":
        return list(args)
    if spec == "if":
        return _if_bodies(args)
    if spec == "catch":
        return _catch_script(args)
    if spec == "last":
        return args[-1:]
    if spec == "dict":
        if len(args) >= 3 and args[0].value in _DICT_SCRIPT_SUBS:
            return args[-1:]
        return []
    out = []
    for pos in spec:  # type: ignore[union-attr]
        if -len(args) <= pos < len(args):
            out.append(args[pos])
    return out


def _cmd_name(word: TWord) -> str:
    name = word.value
    if name.startswith("::"):
        name = name.lstrip(":")
    if name.startswith("ocd_"):
        name = name[4:]
    return name


def _local_rules(stmt: TStatement, *, unknown_risk: str | Risk, depth: int) -> list[Classification]:
    words = stmt.words
    if not words:
        return []
    res: list[Classification] = []
    cmdw = words[0]
    args = words[1:]
    text = stmt.text

    if any(w.expand for w in words):
        res.append(Classification(D, "openocd.local.expand", "{*} 확장 — 실제 실행될 명령을 정적으로 확정할 수 없음", text, True))
    if cmdw.has_cmd_subst or cmdw.has_var:
        res.append(Classification(D, "openocd.local.dynamic-command", "명령 위치에 명령/변수 치환 — 실제 명령을 확정할 수 없음", text, True))
    if cmdw.has_backslash:
        res.append(Classification(D, "openocd.local.escaped-command", "명령 이름에 백슬래시 이스케이프 — 이름 기반 분류 우회 가능", text, True))

    name = _cmd_name(cmdw)
    if cmdw.value.startswith("::") and name:
        # 네임스페이스 접두를 뗀 형태로 코어 분류를 다시 수행 (::mww → mww)
        normalized = " ".join([name] + [w.text for w in args])
        c = classify_openocd(normalized, unknown_risk=unknown_risk)
        res.append(Classification(c.risk, f"openocd.local.ns:{c.rule_id}", f"'::' 접두 명령 — {c.reason}", text, c.uncertain))

    # 타깃 접두 형태 (<target> <subcmd> ...) 도 함께 검사.
    # 코어는 점(.) 있는 첫 단어만 타깃 접두로 본다. 점 없는 타깃(mem_ap, cpu0)의 'cpu0 mww …' 는 그 타깃의 메모리 쓰기인데
    # 코어에는 '알 수 없는 명령'(MODIFY, 기본 허용)이었다 → 코어 표에 없는 첫 단어 뒤의 (고정) 단어를 하위 명령으로도
    # 분류한다. 결과는 worst 로 합쳐지므로 더 엄격해지기만 한다 ('cpu0 read_memory …' 는 그대로 MODIFY).
    candidates = [(name, args)]
    dotless_prefix = bool(args) and "." not in name and not _is_known_command(name, args)
    if args and ("." in name or dotless_prefix):
        candidates.append((_cmd_name(args[0]), args[1:]))
    if dotless_prefix and not (args[0].has_var or args[0].has_cmd_subst):
        sub = classify_openocd(" ".join(w.text for w in args), unknown_risk=unknown_risk)
        res.append(Classification(
            sub.risk, f"openocd.local.dotless-target:{sub.rule_id}",
            f"'{name}' 은 점 없는 타깃 이름일 수 있음 — '{name} <하위 명령>' 으로 보면: {sub.reason}", text, sub.uncertain,
        ))

    for nm, av in candidates:
        if nm in _HOST_ESCAPE:
            res.append(Classification(D, f"openocd.local.host.{nm}", _HOST_ESCAPE[nm], text))
        if nm in _INDIRECTION:
            reason = _INDIRECTION_REASONS.get(nm, f"'{nm}' — 다른 명령을 간접 실행/정의")
            res.append(Classification(D, f"openocd.local.indirect.{nm}", reason, text, True))
        if nm in _MEM_WRITERS:
            res.append(Classification(D, f"openocd.local.memwrite.{nm}", _MEM_WRITERS[nm], text))
        if nm in _JTAG_LOWLEVEL:
            res.append(Classification(D, f"openocd.local.jtag.{nm}", _JTAG_LOWLEVEL[nm], text))
        if nm == "log_output" and av:
            res.append(Classification(D, "openocd.local.log_output", "OpenOCD 로그를 호스트 임의 경로 파일로 (생성/덮어쓰기)", text))
        if nm == "jtag" and av and av[0].value in ("irscan", "drscan"):
            res.append(Classification(D, f"openocd.local.jtag.{av[0].value}", _JTAG_LOWLEVEL[av[0].value], text))
        if nm == "pld" and av and av[0].value == "load":
            res.append(Classification(D, "openocd.local.pld.load", "FPGA/CPLD 비트스트림 로드 (영구 프로그래밍 가능)", text))
        if nm == "etm" and av and av[0].value == "dump":
            res.append(Classification(D, "openocd.local.etm.dump", "호스트 임의 경로에 파일 기록", text))
        if (nm == "dap" or nm.endswith(".dap")) and av:
            sub = av[0].value
            rest = [w for w in av[1:] if w.value != "-ap-num"]
            if sub == "apreg" and len(rest) >= 3:
                res.append(Classification(D, "openocd.local.dap.apreg-write", "AP 레지스터 쓰기 — MEM-AP 경유 임의 메모리/MMIO 쓰기와 동등", text))
            elif sub == "dpreg" and len(rest) >= 2:
                res.append(Classification(M, "openocd.local.dap.dpreg-write", "DP 레지스터 쓰기", text))
        if nm == "mips32" and av and av[0].value == "cp0":
            rest = av[1:]
            is_write = (len(rest) >= 3) if (rest and _NUMERIC.fullmatch(rest[0].value)) else (len(rest) >= 2)
            if is_write:
                res.append(Classification(M, "openocd.local.mips32.cp0-write", "MIPS CP0 레지스터 쓰기", text))
        if nm in ("set_reg",):
            res.append(Classification(M, "openocd.local.set_reg", "레지스터 쓰기", text))
        # 이 서버가 끈 telnet/GDB 서버를 다시 여는 명령: 그 포트로 들어오는 명령은 게이트를 거치지 않는다
        # (xPack 실측: 시작 명령 'telnet port N' 으로 연 telnet 에서 임의 명령이 실행됨)
        port_val = None
        if nm in ("telnet", "gdb") and len(av) >= 2 and av[0].value == "port":
            port_val = av[1]
        elif nm in ("telnet_port", "gdb_port") and av:
            port_val = av[0]
        if port_val is not None and port_val.value != "disabled":
            res.append(Classification(D, f"openocd.local.command-server.{nm}", _COMMAND_SERVER_REASON, text))
    for i, w in enumerate(args):
        if w.value == "-gdb-port" and i + 1 < len(args) and args[i + 1].value != "disabled":
            res.append(Classification(D, "openocd.local.command-server.gdb-port", _COMMAND_SERVER_REASON, text))
    if any("semihosting" in w.value for w in words) and any(w.value == "enable" for w in words):
        res.append(Classification(D, "openocd.local.semihosting", "semihosting 활성화 — 타깃 프로그램이 호스트 파일/명령에 접근 가능", text))

    # 스크립트 본문 인자 재귀 분류 (따옴표 본문 대응). 본문 단어의 value 는 백슬래시만 치환하고 $/[ ] 는 원문 그대로라
    # 동적 본문($x, [cmd])은 명령 위치의 변수/치환으로 다시 분류되어 DESTRUCTIVE(확정 불가)가 된다.
    bodies = list(_script_args(name, args))
    # 옵션 뒤 스크립트: -event <이름> <본문> (OpenOCD 이벤트 핸들러), -command <명령 접두> (lsort/lsearch/regsub/switch)
    for i, w in enumerate(args):
        off = _OPTION_SCRIPT_OFFSET.get(w.value)
        if off is not None and i + off < len(args):
            bodies.append(args[i + off])
    # 코어 표에 없는 명령: 따옴표/중괄호/백슬래시 인자는 스크립트 본문일 수 있다 (예: Jim aio 'stdout readable "..."')
    if not _is_known_command(name, args):
        bodies.extend(w for w in args if w.braced or w.quoted or w.has_backslash)
    seen: set[int] = set()
    for w in bodies:
        if id(w) in seen or not w.value.strip():
            continue
        seen.add(id(w))
        res.append(_classify(w.value, unknown_risk=unknown_risk, depth=depth + 1))
    # 식 위치(expr, if/elseif/while 조건, for 검사식): 이중 치환과 식 안의 [ ] 명령 치환
    for w in _expr_words(name, args):
        if not w.braced and (w.has_var or w.has_cmd_subst):
            res.append(Classification(
                D, "openocd.local.expr-double-subst",
                "중괄호 없는 식 인자의 변수/명령 치환 결과를 expr 가 다시 해석함(이중 치환) — 실행될 명령을 확정할 수 없음. "
                "식은 중괄호로 감싸세요 (예: expr {...}, if {...})",
                text, True,
            ))
        try:
            scripts = _bracket_scripts(w.value)
        except TclParseError as exc:
            res.append(Classification(D, "openocd.local.unparsable", f"식 안의 명령 치환을 해석할 수 없음 ({exc})", text[:200], True))
            scripts = []
        for sub in scripts:
            if sub.strip():
                res.append(_classify(sub, unknown_risk=unknown_risk, depth=depth + 1))
    # 단어 안의 [ ] 명령 치환 재귀 분류 (로컬 규칙 적용을 위해)
    for w in words:
        for sub in w.subscripts:
            if sub.strip():
                res.append(_classify(sub, unknown_risk=unknown_risk, depth=depth + 1))
    return res


def _classify(text: str, *, unknown_risk: str | Risk, depth: int) -> Classification:
    core = classify_openocd(text, unknown_risk=unknown_risk)
    if depth > _MAX_DEPTH:
        return worst([core, Classification(D, "openocd.local.too-deep", "중첩이 너무 깊어 분류 불가", text[:200], True)])
    try:
        stmts = parse_statements(text)
    except TclParseError as exc:
        return worst([core, Classification(D, "openocd.local.unparsable", f"Tcl 구문을 해석할 수 없음 ({exc})", text[:200], True)])
    results = [core]
    whole = text.strip()
    for st in stmts:
        # 문장별 코어 분류: 코어의 줄 단위 주석 제거(splitlines)가 Jim 과 달라 숨겨지는 문장을 막는다
        if st.text != whole:
            results.append(classify_openocd(st.text, unknown_risk=unknown_risk))
        results.extend(_local_rules(st, unknown_risk=unknown_risk, depth=depth))
    return worst(results, core)


def classify_command(text: str, *, unknown_risk: str | Risk = "modify") -> Classification:
    """OpenOCD Tcl 명령 위험도 = worst(코어 classify_openocd, 로컬 엄격 규칙)."""
    return _classify(text, unknown_risk=unknown_risk, depth=0)


# ---------------------------------------------------------------------------
# 서버가 만든 '<타깃> <읽기 명령>' (점 없는 타깃 이름)
# ---------------------------------------------------------------------------

_TARGET_NAME = r"[A-Za-z0-9_][A-Za-z0-9_.\-]{0,63}"
_TARGET_NAME_RE = re.compile(_TARGET_NAME)
# openocd_read_memory(+ md* 대체), 덤프 작업의 read_memory/md 루프, write_memory 확인 읽기가 만드는 정확한 형식만.
# 이름 뒤는 서버가 만든 숫자 인자뿐이라 Tcl 특수 문자(; [ ] $ { } " \\ 개행)가 끼어들 수 없다.
_TARGET_READ = re.compile(
    r"(?P<target>" + _TARGET_NAME + r") "
    r"(?P<rest>read_memory 0x[0-9a-f]+ (?:8|16|32|64) [0-9]+(?: phys)?|md[bhwd](?: phys)? 0x[0-9a-f]+ [0-9]+)"
)
# 분류 표 밖이지만 명령 자리에서 따로 다뤄지는 이름 (인자가 있어야 규칙이 걸리는 것 포함)
_SPECIAL_COMMAND_NAMES = frozenset({
    "jtag", "dap", "pld", "etm", "mips32", "log_output", "telnet", "gdb", "telnet_port", "gdb_port", "tcl", "tcl_port",
    "targets", "reg", "set_reg", "get_reg", "semihosting", "arm", "program", "init_reset", "ocd_process_reset",
    "ocd_process_reset_inner", "power_restore", "power_dropout", "srst_asserted", "srst_deasserted", "ocd_gdb_restart",
    "jtag_init", "init_board", "init_targets", "init_target_events", "set_default_target_event", "test_mem_access",
    "mem2array", "array2mem", "command", "help", "usage", "version", "ms",
})
# Jim Tcl 내장/확장 명령 (실측: xPack OpenOCD 0.12.0-7 의 'info commands'). 실제 OpenOCD 는 이 이름으로
# 타깃을 만들지 못한다('Command/target: time Exists') — 목록에 나타나면 비정상 상태이므로 접두로 떼지 않는다.
_JIM_BUILTINS = frozenset("""
after alarm alias append apply array break catch cd class clock close collect concat continue curry defer dict env eof error
errorInfo eval exec exists exit expr fconfigure file fileevent finalize flush for foreach format function getref gets glob
glob.explode glob.glob glob.globdir global history if incr info interp join kill lambda lambda.finalizer lappend lassign
lindex linsert list llength lmap load local loop lrange lrepeat lreplace lreverse lsearch lset lsort lsubst namespace open
os.fork os.gethostname os.getids os.umask os.uptime os.wait pack package parray pid pipe popen proc ps puts pwd rand range
read readdir ref regexp regsub rename return scan seek set setref signal sleep socket source split stacktrace stderr stdin
stdout string subst super switch syslog tailcall taint tell throw time timerate tree try unknown unpack unset untaint upcall
update uplevel upvar variable vwait wait while xtrace
""".split())


def target_name_conflict(name: str) -> str | None:
    """``<name> <읽기 명령>`` 에서 name 을 타깃 접두로 떼면 안 되는 이유. 문제가 없으면 None.

    name 이 그 자체로 명령으로 해석될 수 있으면(코어/로컬 분류 표, Jim 내장 명령, 숫자·then 같은 식 조각,
    fuse/otp 같은 위험 이름 휴리스틱) 접두를 떼지 않는다. 실측(xPack 0.12.0-7): ``target create mww …`` /
    ``target create reset …`` 은 허용되고 전역 명령을 가리지만, 그 동작은 OpenOCD 버전에 따라 다를 수 있다.
    """
    if not _TARGET_NAME_RE.fullmatch(name):
        return "타깃 이름 형식이 아님 (영문/숫자/_.- 만, 최대 64자)"
    base = name[4:] if name.startswith("ocd_") else name
    for nm in {name, base}:
        if (nm in OPENOCD_COMMANDS or nm in OPENOCD_SUBCOMMANDS or nm in _HOST_ESCAPE or nm in _INDIRECTION
                or nm in _MEM_WRITERS or nm in _JTAG_LOWLEVEL or nm in _SCRIPT_TAKERS or nm in _SPECIAL_COMMAND_NAMES):
            return f"OpenOCD/Tcl 명령 이름 '{nm}' 과 같음"
        if nm in _JIM_BUILTINS:
            return f"Jim Tcl 내장 명령 이름 '{nm}' 과 같음"
    if name.endswith(".dap"):
        return "DAP 명령 이름 형식(<이름>.dap)"
    alone = classify_command(name)
    if alone.rule_id != "openocd.unknown":
        return f"이름만으로도 분류 규칙에 걸림 ({alone.rule_id}: {alone.reason})"
    return None


def classify_target_read(text: str, *, trusted_targets: Iterable[str] = (), unknown_risk: str | Risk = "modify") -> Classification:
    """서버가 직접 만든 ``<타깃> read_memory …`` / ``<타깃> md[bhwd] …`` 분류.

    코어는 점(.) 있는 첫 단어만 타깃 접두로 보므로 점 없는 타깃(mem_ap, cpu0)의 읽기가 '알 수 없는 명령'(MODIFY)이 된다.
    서버가 실제 OpenOCD ``target names`` 목록에서 확인한 이름(trusted_targets)이고, 정확히 서버 형식이며, 이름이 명령과
    겹치지 않을 때만(:func:`target_name_conflict`) 접두를 떼고 나머지를 ``classify_command`` 로 분류한다. 그 밖에는
    ``classify_command(text)`` 그대로다. 접두를 떼더라도 '알 수 없는 명령' 평가만 빠지고 다른 규칙은 모두 남는다
    (원문을 unknown_risk=observe 로 다시 분류해 worst 로 합친다).

    에이전트가 쓴 원시 명령(openocd_command)에는 쓰지 않는다 — 그 경로는 ``classify_command`` 만 쓴다.
    """
    m = _TARGET_READ.fullmatch(text)
    trusted = set(trusted_targets)
    if m is None or m.group("target") not in trusted or target_name_conflict(m.group("target")):
        return classify_command(text, unknown_risk=unknown_risk)
    name = m.group("target")
    inner = classify_command(m.group("rest"), unknown_risk=unknown_risk)
    others = classify_command(text, unknown_risk=O)  # '알 수 없는 명령' 평가만 뺀 원문 분류
    best = worst([inner, others])
    return Classification(
        best.risk, f"openocd.target-verified:{best.rule_id}",
        f"OpenOCD 타깃 목록에서 확인한 타깃 '{name}' 의 {best.reason}", text, best.uncertain,
    )


# ---------------------------------------------------------------------------
# 서버가 생성한 덤프 명령 (케이스 경로 강제)
# ---------------------------------------------------------------------------

_PATH = r"\{(?P<path>/[^{}\\\x00-\x1f\x7f]+)\}"
_MANAGED: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"^dump_image " + _PATH + r" 0x[0-9a-f]+ 0x[0-9a-f]+$"),
     "openocd.managed.dump_image", "메모리 읽기 → 서버가 관리하는 케이스 경로 파일"),
    (re.compile(r"^flash read_bank [A-Za-z0-9_.\-]+ " + _PATH + r" 0x[0-9a-f]+ 0x[0-9a-f]+$"),
     "openocd.managed.flash_read_bank", "플래시 읽기 → 서버가 관리하는 케이스 경로 파일"),
    # 아래 둘은 코어에서도 읽기(INTERACT)지만, 코어가 중괄호로 감싼 경로를 '알 수 없는 명령'으로 오인하므로 정확한 형식만 허용
    (re.compile(r"^flash verify_bank [A-Za-z0-9_.\-]+ " + _PATH + r" 0x[0-9a-f]+$"),
     "openocd.managed.flash_verify_bank", "플래시 재읽기 비교 (케이스 파일과)"),
    (re.compile(r"^verify_image " + _PATH + r" 0x[0-9a-f]+ bin$"),
     "openocd.managed.verify_image", "이미지 검증 (케이스 파일과 타깃 메모리/플래시 비교)"),
]


def classify_managed(
    text: str, *, allowed_dirs: Iterable[Path], unknown_risk: str | Risk = "modify", trusted_targets: Iterable[str] = ()
) -> Classification:
    """덤프 작업이 보내는 명령 분류.

    문장 단위로 나눠, 정확히 서버 생성 형식이고 경로가 allowed_dirs(케이스 dumps/ 또는 jtag/) 안인
    ``dump_image`` / ``flash read_bank`` 는 기기 측 동작(읽기)인 INTERACT 로, 그 밖의 문장은
    ``classify_target_read`` 로 분류한다 (trusted_targets 가 비어 있으면 ``classify_command`` 와 같다).
    trusted_targets 는 서버가 실제 OpenOCD 타깃 목록에서 확인한 이름만 넘긴다.
    """
    trusted = frozenset(trusted_targets)
    dirs = [Path(d) for d in allowed_dirs]
    try:
        stmts = parse_statements(text)
    except TclParseError as exc:
        return Classification(D, "openocd.local.unparsable", f"Tcl 구문을 해석할 수 없음 ({exc})", text[:200], True)
    if not stmts:
        return Classification(O, "openocd.noop", "실행할 명령 없음")
    results: list[Classification] = []
    for st in stmts:
        matched = False
        for rx, rule, reason in _MANAGED:
            m = rx.match(st.text)
            if not m:
                continue
            p = Path(m.group("path"))
            if p.is_absolute() and any(is_within(d, p) for d in dirs):
                results.append(Classification(I, rule, reason, st.text))
                matched = True
            break
        if not matched:
            results.append(classify_target_read(st.text, trusted_targets=trusted, unknown_risk=unknown_risk))
    return worst(results)


def ensure_job_commands_safe(
    commands: Iterable[str], *, allowed_dirs: Iterable[Path], unknown_risk: str | Risk = "modify", trusted_targets: Iterable[str] = ()
) -> list[Classification]:
    """백그라운드 작업이 보낼 명령이 모두 INTERACT 이하인지 확인. 아니면 SafetyDenied.

    trusted_targets: 작업 시작 전에 서버가 OpenOCD 타깃 목록에서 확인한 타깃 이름 (``<타깃> read_memory …`` 용).
    """
    out = []
    dirs = list(allowed_dirs)
    trusted = frozenset(trusted_targets)
    for cmd in commands:
        c = classify_managed(cmd, allowed_dirs=dirs, unknown_risk=unknown_risk, trusted_targets=trusted)
        if c.risk > I:
            raise SafetyDenied(
                f"백그라운드 작업 명령이 INTERACT 를 넘습니다: {cmd!r} (위험도={c.risk.label}, 규칙={c.rule_id}, 사유={c.reason})",
                hint="덤프 작업은 읽기 명령만 보낼 수 있습니다. 경로가 케이스의 dumps/ 또는 jtag/ 안인지 확인하세요.",
            )
        out.append(c)
    return out


__all__ = [
    "TStatement", "TWord", "classify_command", "classify_managed", "classify_target_read", "ensure_job_commands_safe",
    "parse_statements", "target_name_conflict",
]
