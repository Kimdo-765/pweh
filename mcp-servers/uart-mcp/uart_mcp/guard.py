"""uart-mcp 송신 계획과 위험도 분류 (안전 게이트 입력).

기기로 가는 모든 바이트는 ``plan_payload()`` 로 계획을 세우고, 도구는 그 분류로 ``rt().authorize(...)`` 를
통과한 뒤에만 ``UartSession.commit()`` 으로 쓴다. 백그라운드 작업은 같은 계획 함수로 명령마다 다시 분류하고
INTERACT 를 넘으면 멈춘다.

줄 조립: 세션이 지금까지 보낸 바이트를 기억하는 코어 ``LineAssembler`` 의 **사본**에 페이로드를 한 글자씩 넣는다.
그래서 ``uart_write("sf er")`` 다음 ``uart_send_command("ase 0 100")`` 는 기기 줄 버퍼처럼 ``sf erase 0 100``
한 줄로 분류된다. Backspace/Ctrl-U/Ctrl-C 편집도 코어 규칙대로 반영된다.

로컬 규칙 (코어 분류기 위에 얹는 더 엄격한 규칙 — 결과를 더 엄격하게만 만든다):

1. U-Boot 가 받을 수 있는 문맥(uboot/unknown/booting)에서 ``\\r\\n`` 의 ``\\n`` 은 별도의 빈 줄(= 직전 명령 반복)이다.
   코어 조립기는 CRLF 를 한 줄 끝으로 합치므로 여기서 빈 줄을 하나 더 만들어 분류한다.
2. 탭(자동완성)/ESC(히스토리)/기타 제어 문자가 섞인 줄(uncertain)은 DESTRUCTIVE.
3. U-Boot 문맥에서 CBSIZE 를 넘을 수 있는 긴 줄(기본 250자)은 DESTRUCTIVE — 기기가 남는 문자를 버리고
   분류한 줄과 다른 줄을 실행한다. 리눅스 문맥은 1000자.
4. 문맥 오판 대비 교차 검사:
   - uboot 문맥: 리눅스로 해석했을 때 DESTRUCTIVE 이거나(예: ``echo x > /dev/mtd0``), U-Boot 가 모르는 명령이 섞여
     있으면 리눅스 분류와 worst.
   - linux-shell 문맥: 리눅스가 모르는 명령(예: ``saveenv``, ``sf erase``, ``nan e``)이거나 ``cp 0x.. 0x.. 0x..`` 처럼
     U-Boot 메모리 명령 모양이면 U-Boot 분류와 worst. (빈 줄은 리눅스에서 안전하므로 교차 검사하지 않는다.)
5. login/password/booting/unknown 문맥의 일반 송신은 unknown(두 분류기의 worst)으로 분류한다. 로그인 입력을
   INTERACT 로 보는 경로는 ``shell_login`` 만 쓰고, 그때도 프롬프트가 지금 수신 끝에 있을 때만 보낸다.
6. BREAK 직후 5초 안의 첫 바이트는 리눅스 SysRq 명령(b=즉시 재부팅 등)일 수 있어 최소 MODIFY.
7. 한 페이로드 안의 여러 줄은 순서대로 분류하며 줄마다 last_command·setenv 효과를 반영한다
   (``printenv\\r\\r`` 의 두 번째 줄은 printenv 반복으로 분류된다).
8. ``\\r`` 로 끝난 이전 송신 뒤의 ``\\n`` 도 U-Boot 에서는 빈 줄(반복)이다 — 직전 송신의 마지막 문자(``prev_char``)를
   이어 받아 호출 경계를 넘는 CRLF 도 규칙 1 로 분류한다.
9. **기기 준비 상태**: 조립기는 보낸 모든 바이트가 기기 줄 편집기에 들어간다고 가정한다. 기기가 프롬프트에 있지 않을 때
   (부팅 중 — autoboot 중단 키로 한 글자 소비, 커널 초기화 중 입력 버림 / 앞서 보낸 명령 실행 중 — U-Boot ctrlc() 폴링이
   입력을 읽어 버림)에 보낸 입력은 앞부분이 빠질 수 있다(``xsaveenv`` 의 ``x`` 만 소비되면 ``saveenv`` 실행).
   그래서 그 상태에서 완성되는 비어 있지 않은 줄은 DESTRUCTIVE(uncertain)이고, 남는 미완성 입력은 조립기에 uncertain 으로
   표시해 Ctrl-C 로 비울 때까지 다음 줄도 DESTRUCTIVE 로 만든다. 한 페이로드 안에서도 앞 줄이 완성되면 그 뒤 입력은
   "실행 중에 보낸 입력"이다.
10. 이 세션 전에 기기에서 실행된 명령을 모르면(보낸 줄도 없고 재부팅도 보지 못함) U-Boot 가 받을 수 있는 문맥의 빈 줄은
    "알 수 없는 명령의 반복"이라 DESTRUCTIVE 다.
11. 다른 명령을 실행하는 U-Boot 명령(``env run <var>`` = ``run``, ``time <명령>``)은 안쪽 명령 기준으로 분류한다
    (지금은 코어도 같은 규칙을 갖지만 — ``uboot.env.run>…``, ``uboot.time>…`` — uart 경로의 보호가 코어 변경에 흔들리지 않도록 이중으로 둔다).
12. 데이터 비트가 8 보다 적은 세션은 기기가 받는 하위 비트로 분류하고, 8비트 세션에서 상위 비트가 켜진 바이트는
    하위 7비트로도 분류한다(7E1 기기를 8N1 로 연 경우·ISTRIP 이면 ``\\xf3\\xe1…\\x8d`` 가 ``sa…\\r`` 이 된다).
    상위 비트 문자가 섞인 완성 줄은 실제 명령을 확정할 수 없어 DESTRUCTIVE 다.

U-Boot env 추적: ``uboot_printenv`` 결과를 기준으로 하고, 실제로 보낸 setenv/env set/env delete 는
``uboot_setenv_effect`` 로 반영한다. env 를 바꿀 수 있지만 추적할 수 없는 명령(run, boot, env default/import,
setexpr, tftp, 알 수 없는 명령 …)을 보내면 추적 env 를 버린다(None → ``run`` 은 다시 printenv 할 때까지
DESTRUCTIVE). last_command 는 실제로 보낸 비어 있지 않은 줄로만 바뀌고 수신 텍스트로는 절대 지우지 않는다.
"""

from __future__ import annotations

import copy
import re
import shlex
from dataclasses import dataclass, field, replace
from typing import Any, Iterable

from pweh.safety import (
    CONTROL_CHAR_RISK,
    AssembledLine,
    Classification,
    LineAssembler,
    Risk,
    UBootContext,
    classify_console_line,
    classify_linux,
    classify_uboot,
    linux_cwd_effect,
    uboot_setenv_effect,
    worst,
)
from pweh.safety.classifiers import split_outside_quotes, tokenize

UBOOT_CAPABLE = frozenset({"uboot", "unknown", "booting", "login", "password"})
CONTEXTS = ("uboot", "linux-shell", "login", "password", "booting", "unknown")

# 코어 classify_uboot 가 앞에서 떼어 내는 hush 제어 키워드 (같은 집합)
_UBOOT_KEYWORDS = frozenset({"if", "then", "else", "elif", "fi", "for", "in", "do", "done", "while", "until", "!"})

# env 를 바꾸지 않는(또는 setenv 처럼 추적 가능한) U-Boot 명령의 분류 규칙 id.
# 이 목록 밖의 명령을 보내면 추적 env 를 버린다 (보수적).
ENV_PRESERVING_RULES = frozenset({
    "uboot.printenv", "uboot.md", "uboot.crc32", "uboot.crc32.store", "uboot.version", "uboot.ver", "uboot.help", "uboot.?",
    "uboot.bdinfo", "uboot.echo", "uboot.test", "uboot.itest", "uboot.true", "uboot.false", "uboot.sleep",
    "uboot.coninfo", "uboot.iminfo", "uboot.imls", "uboot.cmp", "uboot.flinfo", "uboot.meminfo",
    "uboot.getinfo", "uboot.showvar", "uboot.md5sum", "uboot.sha1sum", "uboot.hash", "uboot.keyword",
    "uboot.empty", "uboot.base", "uboot.mw", "uboot.cp", "uboot.mm", "uboot.nm", "uboot.mwc", "uboot.saveenv",
    "uboot.sf", "uboot.sf.probe", "uboot.sf.read", "uboot.sf.write", "uboot.sf.erase", "uboot.sf.update",
    "uboot.nand", "uboot.nand.read", "uboot.nand.info", "uboot.nand.device", "uboot.nand.bad", "uboot.nand.dump",
    "uboot.mmc", "uboot.mmc.read", "uboot.mmc.info", "uboot.mmc.list", "uboot.mmc.dev", "uboot.mmc.part",
    "uboot.mmc.rescan", "uboot.env", "uboot.env.print", "uboot.env.info", "uboot.env.exists", "uboot.env.grep",
    "uboot.env.flags", "uboot.env.callbacks", "uboot.env.save",
    # 아래 셋은 uboot_setenv_effect 로 추적한다
    "uboot.setenv", "uboot.env.set", "uboot.env.delete",
})

# linux-shell 문맥에서 U-Boot 메모리 명령처럼 보이는 줄 (인자가 모두 주소/크기 모양: 16진수·10진수·$var·${var})
_UBOOT_HEXARG_VERBS = frozenset({"cp", "mw", "mm", "nm", "md", "cmp", "crc32", "go"})
_HEX_RE = re.compile(r"^((0[xX])?[0-9a-fA-F]+|\$\{?[A-Za-z0-9_]+\}?)$")
# 리눅스에서는 조회(INTERACT)지만 U-Boot 에서는 더 위험한 명령 (문맥 오판 시 느슨해지지 않게 U-Boot 해석과 worst)
_UBOOT_RISKIER_VERBS = frozenset({"reset"})

UNCERTAIN_RULE = "uart.uncertain-input"
BUSY_RULE = "uart.device-busy"
REPEAT_UNKNOWN_RULE = "uart.repeat-unknown"
HIGH_BIT_RULE = "uart.high-bit"
SYSRQ_WINDOW_S = 5.0


def mark_uncertain(assembler: LineAssembler, reason: str) -> bool:
    """조립기의 미완성 줄을 uncertain 으로 표시한다 (완성되면 DESTRUCTIVE, Ctrl-C/Ctrl-U 로 비우면 풀림).

    기기가 앞서 보낸 입력의 일부를 소비했거나 버렸을 수 있을 때 쓴다 (코어 ``LineAssembler.mark_uncertain``).
    이미 표시돼 있으면 그대로 두고 False.
    """
    return assembler.mark_uncertain(reason)


def device_view(payload: bytes, bytesize: int) -> bytes:
    """기기가 실제로 받는 바이트: 데이터 비트가 8 보다 적으면 상위 비트는 선로에 실리지 않는다."""
    if int(bytesize) >= 8:
        return payload
    mask = (1 << max(5, int(bytesize))) - 1
    return bytes(b & mask for b in payload)


@dataclass
class GuardState:
    """분류에 필요한 세션 안전 상태의 스냅샷."""

    context: str = "unknown"
    env: dict[str, str] | None = None
    last_command: str | None = None
    persistent_paths: tuple[str, ...] = ()
    unknown_risk: str = "modify"
    uboot_max_line: int = 250
    linux_max_line: int = 1000
    sysrq_until: float = 0.0
    now: float = 0.0
    prev_char: str = ""  # 직전 송신의 마지막 문자(기기 기준) — 호출 경계를 넘는 \r\n (로컬 규칙 8)
    device_ready: bool = True  # 기기가 줄 편집기(프롬프트)에서 입력을 받는 중으로 볼 수 있나 (로컬 규칙 9)
    busy_reason: str | None = None  # device_ready=False 인 이유
    last_command_known: bool = True  # False: 이 세션 전에 기기에서 실행된 명령을 모름 (로컬 규칙 10)
    bytesize: int = 8  # 세션 데이터 비트 (로컬 규칙 12)
    cwd: str | None = None  # 세션이 보낸 cd 로 추적한 리눅스 셸 현재 디렉터리 (모르면 None)


@dataclass
class PlannedLine:
    text: str
    terminator: str
    classification: Classification
    uncertain: bool = False
    synthetic: bool = False  # 로컬 규칙 1 로 만든 빈 줄

    def to_dict(self, mask: bool = False) -> dict[str, Any]:
        out = {"line": "<masked>" if mask else self.text, "risk": self.classification.risk.label,
               "rule_id": self.classification.rule_id}
        if self.synthetic:
            out["synthetic_empty_line"] = True
        if self.uncertain:
            out["uncertain"] = True
        return out


@dataclass
class Plan:
    payload: bytes
    context: str
    lines: list[PlannedLine] = field(default_factory=list)
    controls: list[tuple[str, Classification]] = field(default_factory=list)
    extras: list[Classification] = field(default_factory=list)
    classification: Classification = field(default_factory=lambda: Classification(Risk.OBSERVE, "uart.no-command", "완성된 명령 줄 없음"))
    assembler_after: LineAssembler | None = None
    env_after: dict[str, str] | None = None
    last_command_after: str | None = None
    env_invalidated: bool = False
    cwd_after: str | None = None  # 이 페이로드의 cd 를 반영한 현재 디렉터리
    cwd_tracked: bool = False  # cwd_after 를 계산했는가 (False 면 세션 cwd 를 바꾸지 않음)
    masked: bool = False
    last_char: str = ""  # 이 페이로드의 마지막 문자 (기기 기준, 다음 계획의 prev_char)

    @property
    def pending_after(self) -> str:
        return self.assembler_after.pending if self.assembler_after is not None else ""

    def line_texts(self) -> list[str]:
        return [ln.text for ln in self.lines]

    def summary(self) -> str:
        if self.masked:
            return "<masked login input>"
        if self.lines:
            return " | ".join(repr(ln.text) for ln in self.lines)
        return f"raw {self.payload!r}"[:200]

    def to_dict(self) -> dict[str, Any]:
        return {
            "context": self.context,
            "risk": self.classification.risk.label,
            "rule_id": self.classification.rule_id,
            "reason": self.classification.reason,
            "lines": [ln.to_dict(self.masked) for ln in self.lines],
            "controls": [{"char": f"0x{ord(c):02x}", "risk": cl.risk.label} for c, cl in self.controls],
            "pending_input": "<masked>" if self.masked else self.pending_after,
        }


# ---------------------------------------------------------------------------
# 줄 분류
# ---------------------------------------------------------------------------


def classification_context(context: str) -> str:
    """일반 송신의 분류 문맥 (로컬 규칙 5)."""
    if context in ("uboot", "linux-shell"):
        return context
    return "unknown"


def _uboot_has_unknown(text: str, uctx: UBootContext, unknown: str) -> bool:
    for seg in split_outside_quotes(text.strip(), [";", "&&", "||"]):
        if classify_uboot(seg, ctx=UBootContext(env=uctx.env), unknown_risk=unknown).rule_id == "uboot.unknown":
            return True
    return False


def _linux_has_unknown(text: str, persistent: Iterable[str], unknown: str) -> bool:
    for seg in split_outside_quotes(text.strip(), ["&&", "||", ";", "|", "&", "\n"]):
        if classify_linux(seg, persistent_paths=persistent, unknown_risk=unknown).rule_id == "linux.unknown":
            return True
    return False


def _looks_like_uboot_memcmd(text: str) -> bool:
    for seg in split_outside_quotes(text.strip(), ["&&", "||", ";", "|", "&", "\n"]):
        tokens, _ = tokenize(seg)
        if len(tokens) >= 2 and tokens[0].split(".", 1)[0] in _UBOOT_HEXARG_VERBS and all(_HEX_RE.match(t) for t in tokens[1:]):
            return True
    return False


def _has_uboot_riskier_verb(text: str) -> bool:
    for seg in split_outside_quotes(text.strip(), ["&&", "||", ";", "|", "&", "\n"]):
        tokens, _ = tokenize(seg)
        if tokens and tokens[0].split(".", 1)[0] in _UBOOT_RISKIER_VERBS:
            return True
    return False


def _stricter(base: Classification, other: Classification | None) -> Classification:
    return other if other is not None and other.risk > base.risk else base


def _quote_join(tokens: Iterable[str]) -> str:
    return " ".join(shlex.quote(t) for t in tokens)


def uboot_local_rules(text: str, uctx: UBootContext, unknown_risk: str, _depth: int = 0) -> Classification | None:
    """다른 명령을 실행하는 U-Boot 명령을 안쪽 명령 기준으로 분류한다 (로컬 규칙 11, 코어보다 엄격하게만).

    - ``env run <var> …`` (``env r`` 같은 약어 포함) = ``run <var> …``.
    - ``time <명령 …>`` (CONFIG_CMD_TIME, 약어 ``t``/``ti``/``tim`` 포함) — 안쪽 명령 기준.
    - 코어가 재귀로 분류하는 ``run <var>``·``boot``(bootcmd)·명령 위치의 ``$var`` 값 안에도 위 두 형태가 있는지 본다.
    지금은 코어 classify_uboot 도 같은 규칙을 갖지만(``uboot.env.run>…``, ``uboot.time>…``), 코어가 바뀌어도 uart 경로의
    보호가 남도록 이중으로 둔다. 해당하는 것이 없으면 None.
    """
    results: list[Classification] = []
    env = uctx.env or {}
    plain = UBootContext(env=uctx.env)
    for seg in split_outside_quotes(text.strip(), [";", "&&", "||"]):
        tokens, bad = tokenize(seg)
        if bad:
            continue  # 코어가 따옴표 불균형을 DESTRUCTIVE 로 본다
        while tokens and tokens[0] in _UBOOT_KEYWORDS:
            tokens = tokens[1:]
        if not tokens:
            continue
        cmd, args = tokens[0], tokens[1:]
        base = cmd.split(".", 1)[0]
        core_rule = classify_uboot(seg, ctx=plain, unknown_risk=unknown_risk).rule_id
        runners: list[tuple[str, str]] = []  # (종류, 안쪽 명령 줄) — 안쪽을 직접 분류
        values: list[tuple[str, str]] = []  # (종류, env 값) — 코어가 이미 분류한 값에 로컬 규칙만 더 적용
        if args and base and "time".startswith(base):
            runners.append(("time", _quote_join(args)))
        elif core_rule == "uboot.env.run":
            runners.append(("env-run", " ".join(["run", _quote_join(args[1:])]).strip()))
        elif core_rule == "uboot.run" or core_rule.startswith(("uboot.run>", "uboot.run.")):
            values += [("run", env[v]) for v in args if v in env]
        elif (core_rule == "uboot.boot" or core_rule.startswith("uboot.boot>")) and "bootcmd" in env:  # boot/bootd (bootm 아님)
            values.append(("boot", env["bootcmd"]))
        elif cmd.startswith("$"):
            m = re.fullmatch(r"\$\{?([A-Za-z0-9_]+)\}?", cmd)
            if m and m.group(1) in env:
                values.append(("var", " ".join([env[m.group(1)], _quote_join(args)]).strip()))
        if (runners or values) and _depth >= 6:
            results.append(Classification(Risk.DESTRUCTIVE, "uart.uboot.recursion", "명령 실행 명령이 너무 깊게 중첩됨", seg, True))
            continue
        for label, inner_text in runners:
            inner = _stricter(classify_uboot(inner_text, ctx=plain, unknown_risk=unknown_risk),
                              uboot_local_rules(inner_text, uctx, unknown_risk, _depth + 1))
            risk = max(inner.risk, Risk.MODIFY) if label == "env-run" else inner.risk
            what = "env run (= run)" if label == "env-run" else "time (안쪽 명령을 실행)"
            results.append(Classification(risk, f"uart.uboot.{label}>{inner.rule_id}", f"{what} '{inner_text}': {inner.reason}",
                                          seg, inner.uncertain))
        for label, value in values:
            local = uboot_local_rules(value, uctx, unknown_risk, _depth + 1)
            if local is not None:
                results.append(Classification(max(local.risk, Risk.MODIFY), f"uart.uboot.{label}>{local.rule_id}",
                                              f"{label} 이 실행할 '{value[:80]}' 안: {local.reason}", seg, local.uncertain))
    return worst(results) if results else None


def _classify_uboot_strict(text: str, uctx: UBootContext, unknown_risk: str) -> Classification:
    """코어 classify_uboot + 로컬 규칙 11 (더 엄격한 쪽)."""
    return _stricter(classify_uboot(text, ctx=uctx, unknown_risk=unknown_risk), uboot_local_rules(text, uctx, unknown_risk))


def classifier_env(env: dict[str, str] | None) -> dict[str, str] | None:
    """분류용 env 사본: 값 안의 줄바꿈을 ';' 로 바꾼다.

    hush 파서와 2013.07+ run_command_list 는 줄바꿈을 명령 구분자로 쓰는데 코어 classify_uboot 는 ';'/'&&'/'||' 로만
    나누므로, 'printenv\nsaveenv' 같은 값이 한 명령으로 보여 `run` 분류가 느슨해질 수 있다 (더 엄격하게만 만든다).
    """
    if env is None:
        return None
    return {k: (v.replace("\r\n", ";").replace("\r", ";").replace("\n", ";") if ("\n" in v or "\r" in v) else v) for k, v in env.items()}


def _escalate(base: Classification, other: Classification, label: str) -> Classification:
    if other.risk > base.risk:
        return Classification(other.risk, f"uart.cross-check>{other.rule_id}",
                              f"문맥 오판 대비 교차 검사({label}): {other.reason}", other.matched, other.uncertain, other.details)
    return base


def classify_line(text: str, context: str, *, env: dict[str, str] | None, last_command: str | None,
                  persistent_paths: Iterable[str], unknown_risk: str, last_command_known: bool = True,
                  cwd: str | None = None) -> Classification:
    """완성된 한 줄을 문맥에 맞게 분류 (로컬 규칙 4·5·10·11 포함)."""
    ctx = classification_context(context)
    uctx = UBootContext(env=classifier_env(env), last_command=last_command)
    pp = tuple(persistent_paths)
    if ctx in ("uboot", "unknown") and not text.strip():
        if last_command is None and not last_command_known:
            return Classification(Risk.DESTRUCTIVE, REPEAT_UNKNOWN_RULE,
                                  "U-Boot 에서 빈 Enter 는 직전 명령을 반복하는데, 이 세션을 열기 전에 기기에서 실행된 명령을 알 수 없음 — "
                                  "새 프롬프트는 uart_sync(Ctrl-C), askfirst 콘솔 활성화는 shell_login 을 쓰세요", "", True)
        base = classify_console_line(text, ctx, uboot_ctx=uctx, persistent_paths=pp, unknown_risk=unknown_risk, cwd=cwd)
        rep = uboot_local_rules(last_command, UBootContext(env=uctx.env), unknown_risk) if last_command else None
        if rep is not None and rep.risk > base.risk:
            return Classification(rep.risk, f"uboot.repeat>{rep.rule_id}",
                                  f"U-Boot 에서 빈 Enter 는 직전 명령('{last_command}')을 반복할 수 있음: {rep.reason}", "", rep.uncertain)
        return base
    if ctx == "uboot":
        c = _classify_uboot_strict(text, uctx, unknown_risk)
        if text.strip():
            lin = classify_linux(text, persistent_paths=pp, unknown_risk=unknown_risk, cwd=cwd)
            if lin.risk >= Risk.DESTRUCTIVE or _uboot_has_unknown(text, uctx, unknown_risk):
                c = _escalate(c, lin, "리눅스 해석")
        return c
    if ctx == "linux-shell":
        c = classify_linux(text, persistent_paths=pp, unknown_risk=unknown_risk, cwd=cwd)
        if text.strip() and (_linux_has_unknown(text, pp, unknown_risk) or _looks_like_uboot_memcmd(text)
                             or _has_uboot_riskier_verb(text)):
            u = _classify_uboot_strict(text, UBootContext(env=uctx.env), unknown_risk)
            c = _escalate(c, u, "U-Boot 해석")
        return c
    c = classify_console_line(text, "unknown", uboot_ctx=uctx, persistent_paths=pp, unknown_risk=unknown_risk, cwd=cwd)
    local = uboot_local_rules(text, uctx, unknown_risk)
    if local is not None and local.risk > c.risk:
        c = Classification(local.risk, f"console.unknown-context>{local.rule_id}",
                           f"콘솔 문맥 미확정(U-Boot/Linux 둘 다 고려): {local.reason}", local.matched, local.uncertain)
    return c


def uboot_line_effects(text: str, env: dict[str, str] | None, last_command: str | None,
                       unknown_risk: str, _depth: int = 0) -> tuple[dict[str, str] | None, bool]:
    """U-Boot 에 실제로 보낸 한 줄이 추적 env 에 주는 효과. (새 env, env 를 버렸는지)"""
    stripped = text.strip()
    if not stripped:
        if last_command and _depth == 0:
            return uboot_line_effects(last_command, env, None, unknown_risk, _depth=1)
        return env, False
    rules: list[str] = []
    cenv = classifier_env(env)
    for seg in split_outside_quotes(stripped, [";", "&&", "||"]):
        rules.append(classify_uboot(seg, ctx=UBootContext(env=cenv), unknown_risk=unknown_risk).rule_id)
    if any(r not in ENV_PRESERVING_RULES for r in rules):
        return None, True
    changes = uboot_setenv_effect(stripped)
    if not changes:
        return env, False
    new_env = dict(env) if env is not None else {}
    for k, v in changes.items():
        if v is None:
            new_env.pop(k, None)
        else:
            new_env[k] = v
    return new_env, False


def _line_classification(al: AssembledLine, st: GuardState, env: dict[str, str] | None, last: str | None,
                         last_known: bool = True, cwd: str | None = None) -> Classification:
    if al.uncertain:
        return Classification(Risk.DESTRUCTIVE, UNCERTAIN_RULE,
                              f"{al.reason or '편집 키가 섞여 실제 명령을 확정할 수 없음'} — Ctrl-C(0x03)로 줄을 비운 뒤 일반 문자만 다시 보내세요",
                              al.text, True)
    ctx = classification_context(st.context)
    if ctx in ("uboot", "unknown") and len(al.text) > st.uboot_max_line:
        return Classification(Risk.DESTRUCTIVE, "uart.line-too-long",
                              f"U-Boot 줄 버퍼(CONFIG_SYS_CBSIZE) 초과 가능({len(al.text)}자 > {st.uboot_max_line}자) — 기기가 문자를 버려 "
                              f"다른 명령이 실행될 수 있음", al.text[:120])
    if ctx == "linux-shell" and len(al.text) > st.linux_max_line:
        return Classification(Risk.DESTRUCTIVE, "uart.line-too-long", f"줄이 너무 깁니다({len(al.text)}자 > {st.linux_max_line}자)", al.text[:120])
    return classify_line(al.text, st.context, env=env, last_command=last, persistent_paths=st.persistent_paths,
                         unknown_risk=st.unknown_risk, last_command_known=last_known, cwd=cwd)


def _finish(plan: Plan) -> None:
    plan.classification = worst(
        [ln.classification for ln in plan.lines] + [c for _, c in plan.controls] + plan.extras,
        Classification(Risk.OBSERVE, "uart.no-command", "완성된 명령 줄 없음 (줄 끝을 보내기 전까지 실행되지 않음)"),
    )


def _plan_text(payload: bytes, data: bytes, assembler: LineAssembler, st: GuardState) -> Plan:
    """data(기기가 받는 바이트)를 조립·분류한다. payload 는 실제로 쓸 바이트(Plan.payload)."""
    asm = copy.deepcopy(assembler)
    text = data.decode("latin-1")
    ctx = st.context
    uboot_capable = ctx in UBOOT_CAPABLE
    plan = Plan(payload=payload, context=classification_context(ctx))
    env = dict(st.env) if st.env is not None else None
    last = st.last_command
    last_known = st.last_command_known or last is not None
    cwd = st.cwd
    invalidated = False
    prev = st.prev_char  # 로컬 규칙 8: 직전 송신이 \r 로 끝났으면 이번 첫 \n 은 별도의 빈 줄
    ready = st.device_ready
    busy_reason = st.busy_reason or "기기가 프롬프트에 있지 않을 때 보낸 입력"
    for ch in text:
        if ch in CONTROL_CHAR_RISK:
            risk, reason = CONTROL_CHAR_RISK[ch]
            plan.controls.append((ch, Classification(risk, "console.control-char", reason, f"0x{ord(ch):02x}")))
        produced = asm.feed(ch)
        if not produced and ch == "\n" and prev == "\r" and uboot_capable:
            produced = [AssembledLine("", False, None, "\n")]
            synthetic = True
        else:
            synthetic = False
        for al in produced:
            cls = _line_classification(al, st, env, last, last_known, cwd)
            busy = bool(al.text.strip()) and not ready and not al.uncertain
            if busy:  # 로컬 규칙 9
                cls = _stricter(cls, Classification(
                    Risk.DESTRUCTIVE, BUSY_RULE,
                    f"{busy_reason}이라 기기가 앞부분을 소비하거나 버려 분류한 줄과 다른 줄(예: 첫 글자가 빠진 줄)을 실행할 수 있음 — "
                    "프롬프트가 다시 보인 뒤(uart_read/uart_sync) 한 줄씩 보내세요", al.text, True))
            plan.lines.append(PlannedLine(al.text, al.terminator, cls, al.uncertain or busy, synthetic))
            if uboot_capable:
                if not al.text.strip() and last is None and not last_known:
                    env, wiped = None, True  # 알 수 없는 명령의 반복은 env 를 바꿀 수 있다
                else:
                    env, wiped = uboot_line_effects(al.text, env, last, st.unknown_risk)
                invalidated = invalidated or wiped
                if al.text.strip():
                    last = al.text
                    last_known = True
            if al.text.strip() and plan.context != "uboot":
                cwd = linux_cwd_effect(al.text, cwd)  # 리눅스 셸이면 cd 가 다음 줄의 상대 경로 기준을 바꾼다
            if ready:
                ready = False  # 줄이 완성되면 기기는 그 명령을 실행한다 → 이 페이로드의 나머지는 실행 중에 보낸 입력
                busy_reason = "같은 페이로드의 앞 줄을 기기가 실행하는 동안 보낸 입력"
        prev = ch
    if not ready and asm.pending:
        mark_uncertain(asm, f"{busy_reason}이라 기기가 일부를 소비·버렸을 수 있음 — Ctrl-C(uart_sync)로 줄을 비운 뒤 다시 보내세요")
    if payload and st.now and st.now < st.sysrq_until:
        plan.extras.append(Classification(Risk.MODIFY, "uart.sysrq-window",
                                          "BREAK 직후 5초 안의 첫 문자는 리눅스 Magic SysRq 명령(b=즉시 재부팅, c=크래시 등)으로 해석될 수 있음",
                                          text[:1]))
    _finish(plan)
    plan.assembler_after = asm
    plan.env_after = env
    plan.last_command_after = last
    plan.env_invalidated = invalidated
    plan.cwd_after, plan.cwd_tracked = cwd, True
    plan.last_char = text[-1:] if text else st.prev_char
    return plan


def plan_payload(payload: bytes, assembler: LineAssembler, st: GuardState) -> Plan:
    """페이로드를 보냈을 때 기기에서 완성될 줄과 제어 문자를 분류한다 (세션 상태는 바꾸지 않음)."""
    plan = _plan_text(payload, device_view(payload, st.bytesize), assembler, st)
    if int(st.bytesize) >= 8 and any(b >= 0x80 for b in payload):
        # 로컬 규칙 12: 7비트 기기(7E1 을 8N1 로 연 경우)·ISTRIP 이면 하위 7비트가 도착한다
        alt = _plan_text(payload, bytes(b & 0x7F for b in payload), assembler, replace(st, bytesize=7))
        if alt.classification.risk > plan.classification.risk:
            c = alt.classification
            plan.extras.append(Classification(c.risk, f"{HIGH_BIT_RULE}>{c.rule_id}",
                                              f"상위 비트가 켜진 바이트를 기기가 하위 7비트로 받으면: {c.reason}", c.matched, True))
        for i, ln in enumerate(plan.lines):
            if any(ord(ch) >= 0x80 for ch in ln.text):
                plan.lines[i] = PlannedLine(ln.text, ln.terminator, _stricter(ln.classification, Classification(
                    Risk.DESTRUCTIVE, HIGH_BIT_RULE,
                    "상위 비트가 켜진 문자가 섞인 줄 — 기기(7비트 콘솔·프레이밍 불일치·ISTRIP)가 다른 문자로 읽을 수 있어 실제 명령을 확정할 수 없음",
                    ln.text, True)), True, ln.synthetic)
        if plan.assembler_after is not None and plan.assembler_after.pending:
            mark_uncertain(plan.assembler_after, "상위 비트가 켜진 바이트를 보내 기기 줄 버퍼가 조립한 것과 다를 수 있음 — Ctrl-C(uart_sync)로 줄을 비우세요")
        _finish(plan)
    return plan


def plan_login_input(payload: bytes, assembler: LineAssembler, st: GuardState, *, masked: bool) -> Plan:
    """shell_login 전용: 로그인/비밀번호 프롬프트에 보내는 한 줄 (호출자가 프롬프트가 수신 끝에 있는지 확인한 뒤).

    입력은 일반 문자 + 줄 끝 하나여야 한다. 비밀번호는 분류 결과·감사 기록에 남지 않게 마스킹한다.
    """
    text = payload.decode("latin-1")
    body = text.rstrip("\r\n")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in body):
        raise ValueError("로그인 입력에 제어 문자를 넣을 수 없습니다.")
    if asm_pending_nonempty(assembler):
        raise ValueError("이전에 보낸 미완성 입력이 남아 있습니다. 먼저 Ctrl-C(uart_write data=\"\\u0003\")로 줄을 비우세요.")
    asm = copy.deepcopy(assembler)
    lines = asm.feed(text)
    if len(lines) != 1 or asm.pending:
        raise ValueError("로그인 입력은 정확히 한 줄이어야 합니다.")
    shown = "<masked>" if masked else body
    cls = Classification(Risk.INTERACT, "uart.login-input", "로그인/비밀번호 프롬프트 입력 (프롬프트 확인 후 전송)", shown)
    plan = Plan(payload=payload, context=st.context, masked=masked)
    plan.lines.append(PlannedLine(shown if masked else lines[0].text, lines[0].terminator, cls))
    plan.classification = cls
    plan.assembler_after = asm
    plan.env_after = st.env
    plan.last_command_after = st.last_command
    plan.cwd_after, plan.cwd_tracked = st.cwd, True
    plan.last_char = text[-1:]
    return plan


def asm_pending_nonempty(assembler: LineAssembler) -> bool:
    return bool(assembler.pending) or assembler.pending_uncertain is not None


_VAR_REF_RE = re.compile(r"\$\{?([A-Za-z0-9_]+)\}?")
_WORD_RE = re.compile(r"[A-Za-z0-9_]+")
_BOOT_WORD_RE = re.compile(r"(?<![\w.$])bootd?(?![\w.])")


def approval_refs(lines: list[str], context: str, *, env: dict[str, str] | None, last_command: str | None,
                  last_command_known: bool, cwd: str | None = None) -> dict[str, Any]:
    """승인 지문(action)에 더할 실행 의미. U-Boot 가 받을 수 있는 문맥에서만 의미가 있다.

    같은 줄이라도 실행 내용이 바뀌면 다른 작업이다: ``run x`` 를 승인받은 뒤 ``setenv x …`` 로 x 를 바꾸거나,
    ``sf erase 0 $len`` 의 len 을 바꾸거나, 빈 Enter 의 반복 대상(직전 명령)이 바뀌면 승인을 다시 받아야 한다.
    - ``repeat_of``: 빈 줄이 있으면 반복 대상 (모르면 ``"<unknown>"``)
    - ``env_refs``: 줄(과 반복 대상)이 참조하는 env 이름 → 지금 추적 중인 값(모르면 None). run/boot/$var 값 안의 참조도 따라간다.
    """
    ctxs = context.replace("auto:", "").split("+")
    out: dict[str, Any] = {}
    if cwd and any(c in ("linux-shell", "unknown") for c in ctxs):
        out["cwd"] = cwd  # 상대 경로 명령의 실제 대상이 cwd 에 따라 달라진다
    if not any(c in UBOOT_CAPABLE for c in ctxs):
        return out
    texts = [t for t in lines if t.strip()]
    if any(not t.strip() for t in lines):
        out["repeat_of"] = last_command if last_command is not None else (None if last_command_known else "<unknown>")
        if last_command:
            texts.append(last_command)
    names: set[str] = set()
    todo = list(texts)
    steps = 0
    while todo and steps < 64:
        steps += 1
        t = todo.pop()
        found = set(_VAR_REF_RE.findall(t))
        if env:
            found.update(w for w in _WORD_RE.findall(t) if w in env)
        if _BOOT_WORD_RE.search(t):
            found.add("bootcmd")
        for name in sorted(found - names):
            names.add(name)
            if env and name in env:
                todo.append(env[name])
    if names:
        out["env_refs"] = {n: (env.get(n) if env is not None else None) for n in sorted(names)}
    return out


def static_check(lines: Iterable[str], context: str, *, env: dict[str, str] | None, last_command: str | None,
                 persistent_paths: Iterable[str], unknown_risk: str, limit: Risk = Risk.INTERACT) -> list[tuple[str, Classification]]:
    """백그라운드 작업 시작 전 검사: 계획된 명령 줄 중 limit 를 넘는 것들을 돌려준다 (빈 목록이면 통과)."""
    bad: list[tuple[str, Classification]] = []
    seen: set[str] = set()
    for line in lines:
        if line in seen:
            continue
        seen.add(line)
        c = classify_line(line, context, env=env, last_command=last_command, persistent_paths=persistent_paths, unknown_risk=unknown_risk)
        if c.risk > limit:
            bad.append((line, c))
    return bad
