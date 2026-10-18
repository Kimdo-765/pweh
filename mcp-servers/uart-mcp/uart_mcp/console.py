"""세션 위의 콘솔 동작 (블로킹, 워커 스레드/작업 스레드에서 실행).

- ``run_planned``: 분류·승인된 계획을 쓰고 에코 → 프롬프트(또는 expect 정규식)까지 기다려 출력만 돌려준다.
- ``job_command``: 백그라운드 작업용. 명령마다 같은 분류기로 다시 분류해 INTERACT 를 넘거나 문맥이 바뀌면 멈춘다.
- ``sync``: Ctrl-C(0x03) 한 번으로 새 프롬프트를 받고 문맥 증거를 얻는다 (U-Boot 는 ``<INTERRUPT>`` 를 출력).
  빈 Enter 로 프롬프트를 "깨우지" 않는다 — U-Boot 에서 빈 줄은 직전 명령을 반복한다.
- ``interrupt``: 사람이 전원을 넣는 동안 autoboot 를 멈춘다.
- ``login``: BusyBox askfirst/login/Password 처리 (비밀번호 마스킹, 프롬프트가 수신 끝에 있을 때만 송신).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from pweh.errors import DeviceError, SafetyDenied
from pweh.jobs import JobCancelled
from pweh.safety import Risk

from .guard import Plan
from .parsers import is_not_found
from .session import StateChanged, UartSession, WaitResult
from .textutil import decode_bytes, key_display, printable_ratio, render_text

Cancel = Callable[[], bool] | None


@dataclass
class CommandResult:
    line: str
    output: str
    raw: bytes
    cursor_start: int
    output_start: int
    output_end: int
    cursor_end: int
    wait: WaitResult
    echo_found: bool
    elapsed: float
    context: str
    lost: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def timed_out(self) -> bool:
        return self.wait.kind == "timeout"

    @property
    def cancelled(self) -> bool:
        return self.wait.kind == "cancelled"

    @property
    def disconnected(self) -> bool:
        return self.wait.kind == "disconnected"

    @property
    def matched(self) -> bool:
        return self.wait.kind in ("prompt", "expect")

    def to_dict(self, max_output: int = 20000, mask_line: bool = False) -> dict[str, Any]:
        out_text = self.output
        truncated = False
        if max_output and len(out_text) > max_output:
            out_text = out_text[:max_output]
            truncated = True
        d: dict[str, Any] = {
            "output": out_text,
            "matched": self.matched,
            "match": self.wait.match_text if self.wait.kind == "expect" else (self.wait.prompt.text if self.wait.prompt else None),
            "match_kind": self.wait.kind,
            "timed_out": self.timed_out,
            "context": self.context,
            "prompt": self.wait.prompt.text if self.wait.prompt else None,
            "echo_found": self.echo_found,
            "cursor_start": self.cursor_start,
            "output_start": self.output_start,
            "output_end": self.output_end,
            "cursor_end": self.cursor_end,
            "elapsed_seconds": round(self.elapsed, 3),
        }
        if self.wait.kind == "expect" and self.wait.groups:
            d["groups"] = self.wait.groups
        if truncated:
            d["output_truncated"] = True
            d["output_chars"] = len(self.output)
            d["hint"] = "출력이 잘렸습니다. 전체는 uart_read(since_cursor=output_start, max_bytes=…) 로 이어 읽으세요."
        if self.lost:
            d["output_lost"] = True
        if self.disconnected:
            d["disconnected"] = True
        if self.cancelled:
            d["cancelled"] = True
        if self.notes:
            d["notes"] = self.notes
        return d


def find_echo_end(raw: bytes, typed: str | None) -> int | None:
    """방금 보낸 명령의 에코가 끝나는 위치(에코 줄의 줄바꿈 다음). 에코가 보이지 않으면 None."""
    if typed is None:
        return None
    text = raw.decode("latin-1")
    if typed == "":
        nl = text.find("\n")
        return nl + 1 if 0 <= nl <= 8 else None
    probe = typed[-24:]
    window = text[: len(typed) * 3 + 256]
    idx = window.find(probe)
    if idx < 0:
        return None
    nl = text.find("\n", idx + len(probe))
    if nl < 0:
        return len(raw)
    return nl + 1


def run_planned(session: UartSession, plan: Plan, authorized: Risk, *, echo_text: str | None, timeout: float,
                expect: re.Pattern[str] | None = None, cancel: Cancel = None, settle: float | None = None,
                source: str = "tool", note: str = "") -> CommandResult:
    t0 = time.monotonic()
    cursor = session.commit(plan, authorized, note=note, source=source)
    after = cursor
    if expect is not None and echo_text:
        # expect 가 명령 에코 줄 안에서 맞지 않도록, 에코 줄이 끝난 뒤부터 검색한다 (에코가 없으면 처음부터)
        echo_re = re.compile(re.escape(echo_text[-24:]) + r"[^\n]*\n")
        ew = session.wait_response(cursor, min(timeout, 2.0), expect=echo_re, cancel=cancel)
        if ew.kind == "expect":
            after = ew.end
    res = session.wait_response(after, max(0.0, timeout - (time.monotonic() - t0)), expect=expect, cancel=cancel, settle=settle)
    if res.kind == "prompt" and res.prompt is not None:
        region_end = res.prompt.start
    elif res.kind == "expect":
        region_end = res.end
    else:
        region_end = session.total()
    with session.cond:
        lost = cursor < session.rx.start
    raw = session.slice(cursor, region_end)
    echo_end = find_echo_end(raw, echo_text)
    body = raw[echo_end:] if echo_end is not None else raw
    output = render_text(decode_bytes(body))
    if output.endswith("\n"):
        output = output[:-1]
    out_start = cursor + (echo_end or 0)
    return CommandResult(
        line=echo_text or "",
        output=output,
        raw=body,
        cursor_start=cursor,
        output_start=out_start,
        output_end=region_end,
        cursor_end=res.end,
        wait=res,
        echo_found=echo_end is not None,
        elapsed=time.monotonic() - t0,
        context=session.context,
        lost=lost,
    )


def job_command(session: UartSession, line: str, *, timeout: float, cancel: Cancel = None,
                contexts: tuple[str, ...] = ("uboot",), source: str = "job") -> CommandResult:
    """백그라운드 작업의 명령 한 줄: 문맥 확인 + 같은 분류기로 재분류(INTERACT 이하만) + 실행."""
    ctx = session.context
    if ctx not in contexts:
        raise DeviceError(f"기기 문맥이 바뀌었습니다 (현재 {ctx}, 필요 {'/'.join(contexts)}). 작업을 멈춥니다.", code="context_changed",
                          hint="uart_read 로 상태를 확인하세요(재부팅?). 같은 인자로 다시 시작하면 이어서 받습니다(resume).")
    # 앞 명령의 프롬프트를 잠깐 기다린다 — 준비되지 않은 기기에 보낸 줄은 guard 가 DESTRUCTIVE 로 분류해 작업이 멈춘다
    session.wait_ready(min(3.0, max(0.5, timeout)), cancel)
    payload = (line + session.line_ending_for(ctx)).encode("latin-1")
    plan = session.plan(payload)
    if plan.classification.risk > Risk.INTERACT:
        raise SafetyDenied(f"작업 명령이 INTERACT 를 넘어 중단합니다: {line!r} → {plan.classification.risk.label} ({plan.classification.rule_id}: "
                           f"{plan.classification.reason})", code="job_command_denied")
    return run_planned(session, plan, Risk.INTERACT, echo_text=line, timeout=timeout, cancel=cancel, source=source)


def send_ctrl_c(session: UartSession, *, source: str, note: str = "ctrl-c") -> int:
    plan = session.plan(b"\x03")
    if plan.classification.risk > Risk.INTERACT:  # pragma: no cover - CONTROL_CHAR_RISK 상 INTERACT
        raise SafetyDenied("Ctrl-C 가 INTERACT 를 넘는 것으로 분류되었습니다.")
    return session.commit(plan, Risk.INTERACT, note=note, source=source)


def sync(session: UartSession, *, timeout: float = 3.0, cancel: Cancel = None, source: str = "tool") -> dict[str, Any]:
    """Ctrl-C 한 번 → 새 프롬프트. 응답으로 문맥 증거를 얻는다."""
    idle = session.prompt_at_tail()
    cursor = send_ctrl_c(session, source=source, note="sync (ctrl-c)")
    res = session.wait_response(cursor, timeout, cancel=cancel)
    raw = session.slice(cursor)
    evidence = None
    if b"<INTERRUPT>" in raw:
        evidence = "uboot"
    elif res.kind == "prompt" and res.prompt is not None and idle is not None and idle.context != "uboot":
        if any(p.search(res.prompt.text) for p in session.profile.linux_prompts) and res.prompt.kind == "prompt":
            with session.cond:
                session.tracker.set_phase_evidence("linux", "Ctrl-C 응답에 <INTERRUPT> 없이 셸 프롬프트", session.rx.total)
            evidence = "linux"
    pm = session.prompt_at_tail()
    out = {
        "context": session.context,
        "prompt": pm.text if pm else None,
        "prompt_kind": pm.kind if pm else None,
        "evidence": evidence,
        "reply": render_text(decode_bytes(raw))[-400:],
        "timed_out": res.kind == "timeout",
        "cursor_end": session.total(),
    }
    if res.kind == "timeout":
        out["hint"] = "Ctrl-C 뒤에 프롬프트가 나오지 않았습니다. 기기가 부팅 중이거나 명령 실행 중일 수 있습니다 — uart_read 로 확인하세요."
    session.event({"type": "sync", "evidence": evidence, "context": out["context"], "prompt": out["prompt"]})
    return out


# ---------------------------------------------------------------------------
# autoboot 인터럽트
# ---------------------------------------------------------------------------

_KEYED_HINTS = (
    (re.compile(r"(?i)press enter"), "keyed autoboot (Enter/CR 키 필요) — keys=[\"enter\"] 로, 전원 투입 직후부터 다시 시도하세요 (빈 Enter 는 부팅 직후에만 안전)."),
    (re.compile(r"(?i)ctrl-?c"), "Ctrl-C 로만 멈추는 빌드입니다 — keys=[\"ctrl-c\"] 로 다시 시도하세요."),
    (re.compile(r"(?i)autoboot in \d+ seconds"), "keyed autoboot (특정 문자열 필요, CONFIG_AUTOBOOT_STOP_STR) — 벤더 문서/소스로 중단 문자열을 확인하세요."),
)


def interrupt(session: UartSession, keys: list[str], window: float, cancel: Cancel = None, *, period: float = 0.05) -> dict[str, Any]:
    """사람이 전원을 넣는 동안 autoboot 를 멈춘다.

    판단 규칙 (호출 시점에 기기가 이미 부팅 중/리눅스 출력 중일 수 있다 — 사람이 전원을 조금 늦게 재투입하는 현실적 상황):
    - 커널/리눅스 프롬프트 출력은 **이번 부팅의 U-Boot 단계를 본 뒤**에만 판단에 쓴다. U-Boot 단계 증거 = 호출 뒤 새 부팅
      시작(boot_seq 증가) 또는 autoboot 메시지, 또는 호출 시점에 이미 키로 멈출 수 있는 U-Boot 단계(uboot/autoboot)에 있음.
      그 전의 리눅스 출력은 이전 부팅의 잔여 출력이므로 창(window) 동안 새 부팅을 계속 기다린다.
    - 새 부팅이 시작되면 그 시작 커서(tracker.boot_start_at) 이후의 출력만 본다.
    - 커널 시작 전에 나온 Password: 는 리눅스 로그인이 아니라 부트로더 잠금이다 → outcome ``uboot_password``.
    - 리눅스가 돌고 있는 동안(새 부팅 전)에는 키를 보내지 않는다. autoboot_silent 프로필은 전원 투입 순간의 키가 필요해 예외.
    """
    prof = session.profile
    t0 = time.monotonic()
    start = session.total()
    keys_used = [key_display(k) for k in keys]
    pm = session.prompt_at_tail()
    if pm is not None and pm.context == "uboot":
        s = sync(session, timeout=2.0, cancel=cancel, source="uboot_interrupt")
        if session.context == "uboot":
            return {"interrupted": True, "outcome": "prompt", "already_at_prompt": True, "new_boot_seen": False,
                    "prompt": s["prompt"], "autoboot_message": None, "keys_used": ["ctrl-c"], "keys_sent": 1,
                    "elapsed_seconds": round(time.monotonic() - t0, 2), "context": session.context, "cursor_end": session.total(),
                    "sync": s}
    with session.cond:
        tr0 = session.tracker
        boot_seq0 = tr0.boot_seq
        # 호출 시점에 키로 멈출 수 있는 U-Boot 부팅 단계(카운트다운 전/중)에 있으면 이후 출력은 이번 부팅의 것이다.
        # 커널 적재 중(kernel-load)은 이미 autoboot 가 끝난 것이라 '부팅 중인 기기'와 같게 보고 새 부팅을 기다린다.
        uboot_stage0 = tr0.phase == "uboot" and tr0.boot_stage in ("uboot", "autoboot")
    started = bool(prof.autoboot_silent)
    fresh_boot = False  # 호출 뒤 새 부팅 시작(또는 autoboot 메시지)을 봤다
    boot_ref = start  # 판단에 쓰는 출력의 시작 커서 (새 부팅을 보면 그 시작 커서)
    stale_seen = False  # 새 부팅 전의 리눅스/커널 출력(이전 부팅)을 봤다 — 진단용
    sent = 0
    skipped: list[str] = []
    key_i = 0
    last_key = 0.0
    outcome = "window_expired"
    while True:
        now = time.monotonic()
        if now - t0 >= window:
            break
        if cancel is not None and cancel():
            outcome = "cancelled"
            break
        with session.cond:
            session.cond.wait(0.02)
            total = session.rx.total
            tr = session.tracker
            lp = tr.last_prompt
            state = session.state
            kernel_at = tr.kernel_at
            boot_seq = tr.boot_seq
            boot_start_at = tr.boot_start_at
            autoboot_at = tr.autoboot_at
            phase = tr.phase
            tail_prompt = tr.prompt if (tr.prompt is not None and tr.prompt.end == total) else None
        if state != "open":
            outcome = "disconnected"
            break
        if not started and total > start:
            started = True
        if boot_seq != boot_seq0:
            fresh_boot = True
            if boot_start_at is not None and boot_start_at > boot_ref:
                boot_ref = boot_start_at
        elif autoboot_at is not None and autoboot_at >= start:
            fresh_boot = True
        current_boot = fresh_boot or uboot_stage0  # 이번 부팅의 U-Boot 단계를 봤다 → 리눅스 출력도 판단에 쓴다
        kernel_since = kernel_at is not None and kernel_at >= boot_ref
        if lp is not None and lp.start >= boot_ref:
            if lp.context == "uboot":
                outcome = "prompt"
                break
            if lp.kind == "password" and not kernel_since and phase == "uboot":
                outcome = "uboot_password"
                break
            if lp.kind in ("login", "askfirst", "password") or lp.context == "linux-shell":
                if current_boot:
                    outcome = "linux"
                    break
                stale_seen = True
        if kernel_since:
            if current_boot:
                outcome = "kernel"
                break
            stale_seen = True
        if not current_boot and phase == "linux":
            stale_seen = stale_seen or total > start
            if not prof.autoboot_silent:
                continue  # 리눅스가 아직 돌고 있다 → 새 부팅(U-Boot 출력)이 보일 때까지 키를 보내지 않는다
        if started and now - last_key >= period:
            key = keys[key_i % len(keys)]
            key_i += 1
            if ("\r" in key or "\n" in key) and (not fresh_boot or tail_prompt is not None):
                # 빈 Enter 는 직전 명령을 반복할 수 있다 → 새 부팅을 확인했고 프롬프트가 아직 없을 때만
                continue
            plan = session.plan(key.encode("latin-1"))
            if plan.classification.risk > Risk.INTERACT:
                if len(skipped) < 5:
                    skipped.append(f"{key_display(key)}: {plan.classification.risk.label} ({plan.classification.rule_id})")
                continue
            try:
                session.commit(plan, Risk.INTERACT, note="autoboot interrupt key", source="uboot_interrupt")
            except StateChanged:
                continue
            sent += 1
            last_key = time.monotonic()
    result: dict[str, Any] = {
        "interrupted": False,
        "keys_used": keys_used,
        "keys_sent": sent,
        "boot_output_bytes": session.total() - start,
        "new_boot_seen": fresh_boot,
        "autoboot_message": None,
        "bootdelay": None,
    }
    with session.cond:
        tr = session.tracker
        if tr.autoboot_at is not None and tr.autoboot_at >= start:
            result["autoboot_message"] = tr.autoboot_message
            result["bootdelay"] = tr.facts.get("bootdelay_seen")
    if outcome == "prompt":
        session.wait_quiet(0.25, 3.0, cancel)
        s = sync(session, timeout=3.0, cancel=cancel, source="uboot_interrupt")
        result.update({"interrupted": session.context == "uboot", "prompt": s["prompt"], "sync": s})
        if not result["interrupted"]:
            result["explanation"] = "U-Boot 프롬프트를 봤지만 Ctrl-C 동기화 뒤 문맥을 확정하지 못했습니다 — uart_read 로 확인하세요."
    else:
        data = session.slice(start)
        result["explanation"] = _diagnose_interrupt(outcome, data, result["autoboot_message"], started, prof.autoboot_silent,
                                                    stale=stale_seen and not fresh_boot)
        if outcome == "uboot_password":
            result["prompt"] = lp.text if lp is not None else None
    if skipped:
        result["skipped_keys"] = skipped
    result.update({"outcome": outcome, "elapsed_seconds": round(time.monotonic() - t0, 2), "context": session.context,
                   "cursor_end": session.total()})
    session.event({"type": "uboot_interrupt", "outcome": outcome, "interrupted": result["interrupted"], "keys_sent": sent,
                   "keys": keys_used, "autoboot_message": result["autoboot_message"]})
    return result


def _diagnose_interrupt(outcome: str, data: bytes, autoboot_msg: str | None, started: bool, silent: bool, *,
                        stale: bool = False) -> str:
    if outcome == "cancelled":
        return "요청이 취소되었습니다."
    if outcome == "disconnected":
        return "포트 연결이 끊어졌습니다 (USB 분리?)."
    if outcome == "uboot_password":
        return ("커널이 시작되기 전에 비밀번호 프롬프트가 나왔습니다 — 리눅스 로그인이 아니라 U-Boot(부트로더)가 비밀번호/중단 문자열로 "
                "잠긴 빌드입니다. 키 송신을 멈췄고, 입력이 없으면 기기는 잠시 뒤 그대로 부팅합니다. 비밀번호를 추측하거나 대입하지 말고 "
                "사용자에게 알고 있는 값이 있는지 물으세요. 없으면 리눅스 셸 경로(shell_login, 사용자가 준 계정)나 외부 SPI 프로그래머를 고려하세요.")
    if outcome == "window_expired" and stale:
        return ("창 동안 이전 부팅의 리눅스 출력(커널 로그/로그인 프롬프트)만 보였고 새 부팅(U-Boot 배너·DRAM·autoboot)은 보지 못했습니다 — "
                "호출 시점에 기기가 이미 부팅 중이었고 전원 재투입이 창 안에 일어나지 않았습니다. 사람에게 전원을 먼저 꺼 두게 하고 "
                "'준비' 답을 받은 뒤 이 도구를 다시 호출하세요 — 사람은 호출이 시작되면 전원을 넣습니다 (이전 부팅의 출력은 판단에 쓰지 않습니다).")
    if not data:
        if outcome == "window_expired":
            return ("창 동안 수신 데이터가 전혀 없었습니다. 사람이 전원을 꺼 둔 상태에서 호출이 시작된 뒤 전원을 넣었는지 확인하세요. 계속 아무것도 안 나오면 "
                    "TX/RX 뒤바뀜, GND 미연결, 보드레이트 불일치(uart_detect_baud), 전압 레벨을 점검하세요.")
        return "수신 데이터 없음."
    if printable_ratio(data) < 0.6:
        return "수신 데이터가 대부분 깨져 있습니다 — 보드레이트가 맞지 않을 가능성이 큽니다 (uart_detect_baud 로 확인)."
    if outcome == "kernel":
        if autoboot_msg:
            for rx, hint in _KEYED_HINTS:
                if rx.search(autoboot_msg):
                    return f"autoboot 메시지({autoboot_msg!r})를 봤지만 커널이 시작됐습니다. {hint}"
            return (f"autoboot 메시지({autoboot_msg!r})를 봤지만 커널이 시작됐습니다. 키가 늦었거나 이 빌드가 다른 키만 받습니다. "
                    "keys 를 바꾸거나(예: [\"ctrl-c\", \"space\"]) 다시 전원을 넣어 시도하세요.")
        return ("autoboot 메시지 없이 커널이 시작됐습니다. bootdelay=0 이거나 메시지 없는(keyed/silent) 빌드일 수 있습니다. "
                "프로필의 autoboot_silent/interrupt_sequences 를 확인하고(예: sigmastar-ipcam), 전원 투입 순간부터 키를 보내도록 다시 시도하세요. "
                "U-Boot 가 잠긴 기기라면 리눅스 셸 경로(shell_login)나 외부 SPI 프로그래머를 고려하세요.")
    if outcome == "linux":
        return "U-Boot 프롬프트 없이 리눅스 로그인/셸 프롬프트에 도달했습니다 (autoboot 를 놓쳤거나 이미 부팅된 기기)."
    if not started:
        return "부팅 출력을 기다리다 창이 끝났습니다 — 전원 재투입이 안 됐을 수 있습니다."
    return "창 안에 U-Boot 프롬프트를 얻지 못했습니다. uart_read 로 부팅 로그를 확인하세요."


# ---------------------------------------------------------------------------
# 로그인
# ---------------------------------------------------------------------------


def login(session: UartSession, username: str | None, password: str | None, *, timeout: float, cancel: Cancel = None) -> dict[str, Any]:
    """askfirst → login: → Password: → 셸 프롬프트.

    - username 이 None 이면 askfirst 콘솔 활성화(Enter)만 한다. login: 이 나오면 username_required 로 멈춘다
      (``::askfirst:-/bin/sh`` 처럼 로그인 없는 콘솔을 계정을 지어내지 않고 활성화하기 위해).
    - 이번 호출이 계정을 보내지 않았는데 프롬프트가 문맥 unknown(U-Boot/리눅스 정규식 둘 다에 맞거나 phase 증거 없음)이면
      리눅스로 단정하지 않고 context_unknown 으로 돌려준다 — 'hisilicon # ' 같은 U-Boot 프롬프트를 셸로 오인하면
      빈 Enter(U-Boot 에서는 직전 명령 반복) 같은 송신이 느슨하게 분류된다.
    """
    t0 = time.monotonic()
    deadline = t0 + timeout
    steps: list[str] = []
    sent_user = sent_pass = False
    askfirst = 0
    last_send: int | None = None
    after: int | None = None
    le = "\r" if session.settings.line_ending == "\r\n" else session.settings.line_ending

    def result(status: str, ok: bool, **extra: Any) -> dict[str, Any]:
        out = {"logged_in": ok, "status": status, "steps": steps, "context": session.context,
               "elapsed_seconds": round(time.monotonic() - t0, 2), "cursor_end": session.total()}
        pm = session.prompt_at_tail()
        out["prompt"] = pm.text if pm else None
        out.update(extra)
        session.event({"type": "login", "status": status, "user": username, "steps": steps})
        return out

    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            return result("timeout", False, message="로그인 프롬프트/셸 프롬프트를 시간 안에 얻지 못했습니다.")
        pm = session.prompt_at_tail() if after is None else None
        if pm is None:
            res = session.wait_response(after if after is not None else session.total(), left, cancel=cancel)
            if res.kind != "prompt" or res.prompt is None:
                if last_send is not None and b"Login incorrect" in session.slice(last_send):
                    session.login_failures += 1
                    return result("login_incorrect", False, message="Login incorrect — 계정/비밀번호가 틀렸습니다. 추측으로 다시 시도하지 말고 사용자에게 확인하세요.")
                return result(res.kind, False, message=f"프롬프트를 기다리다 끝남: {res.kind}")
            pm = res.prompt
        if last_send is not None and b"Login incorrect" in session.slice(last_send):
            session.login_failures += 1
            return result("login_incorrect", False, message="Login incorrect — 계정/비밀번호가 틀렸습니다. 추측으로 다시 시도하지 말고 사용자에게 확인하세요.")
        if pm.kind == "askfirst":
            if askfirst >= 2:
                return result("stuck_askfirst", False, message="askfirst 화면에서 진행되지 않습니다.")
            plan = session.plan_login(le.encode(), masked=False, kinds=("askfirst",))
            last_send = after = session.commit(plan, Risk.INTERACT, note="askfirst enter", source="shell_login")
            askfirst += 1
            steps.append("askfirst-enter")
            continue
        if pm.kind == "login":
            if sent_user:
                session.login_failures += 1
                return result("login_failed", False, message="다시 login 프롬프트가 나왔습니다 (로그인 실패).")
            if username is None:
                return result("username_required", False,
                              message="login 프롬프트가 나왔습니다. 사용자에게 받은 계정으로 username(필요하면 password)을 주어 다시 호출하세요.")
            plan = session.plan_login((username + le).encode("utf-8"), masked=False, kinds=("login",))
            last_send = after = session.commit(plan, Risk.INTERACT, note="username", source="shell_login")
            sent_user = True
            steps.append("username")
            continue
        if pm.kind == "password":
            with session.cond:
                bootloader_lock = session.tracker.phase == "uboot" and session.tracker.kernel_at is None
            if bootloader_lock and not sent_user:
                # 커널 시작 전(U-Boot phase)의 Password: 는 부트로더 잠금이다 — 리눅스 비밀번호를 보내면 추측이 된다
                return result("uboot_password_prompt", False,
                              message="커널이 시작되기 전의 비밀번호 프롬프트입니다 (U-Boot 잠금, 리눅스 로그인이 아님). 아무것도 보내지 않았습니다.",
                              hint="추측·대입하지 마세요. 입력이 없으면 기기는 잠시 뒤 리눅스로 부팅합니다 — login: 이 보이면 다시 호출하세요.")
            if password is None:
                return result("password_required", False, message="비밀번호 프롬프트가 나왔습니다. 사용자에게 받은 비밀번호로 password 를 주어 다시 호출하세요.")
            if sent_pass:
                session.login_failures += 1
                return result("login_failed", False, message="비밀번호 프롬프트가 다시 나왔습니다.")
            plan = session.plan_login((password + le).encode("utf-8"), masked=True, kinds=("password",))
            last_send = after = session.commit(plan, Risk.INTERACT, note="password (masked)", source="shell_login")
            sent_pass = True
            steps.append("password")
            continue
        if pm.context == "uboot":
            return result("uboot_prompt", False, message="U-Boot 프롬프트입니다. 리눅스로 부팅한 뒤 로그인하세요.")
        if pm.context == "unknown" and not (sent_user or sent_pass):
            return result("context_unknown", False,
                          message=(f"프롬프트 {pm.text!r} 의 문맥을 확정할 수 없습니다 (후보: {', '.join(pm.ambiguous) or '없음'}) — "
                                   "U-Boot 프롬프트일 수 있어 리눅스 셸로 단정하지 않았습니다."),
                          hint="uart_sync(Ctrl-C)로 문맥을 확정하세요 (U-Boot 는 <INTERRUPT> 를 출력). 리눅스 셸로 확인되면 다시 호출하세요.")
        if pm.context == "linux-shell" or (pm.context == "unknown" and "linux-shell" in pm.ambiguous):
            if pm.context == "unknown":
                # 이번 호출이 login:/Password: 에 계정을 보낸 직후의 프롬프트 → 리눅스 로그인 성공 증거
                with session.cond:
                    session.tracker.set_phase_evidence("linux", "로그인 뒤 셸 프롬프트", session.rx.total)
            session.login_failures = 0
            banner = ""
            if last_send is not None:
                banner = render_text(decode_bytes(session.slice(last_send, pm.start))).strip()
            already = not steps
            return result("already_logged_in" if already else "ok", True, user=username if sent_user else None,
                          banner=banner[-1000:] or None)
        return result("unknown_prompt", False, message=f"알 수 없는 프롬프트: {pm.text!r}")


def not_found(res: CommandResult, command: str) -> bool:
    return is_not_found(res.output, command)


def raise_if_cancelled(cancel: Cancel) -> None:
    if cancel is not None and cancel():
        raise JobCancelled()
