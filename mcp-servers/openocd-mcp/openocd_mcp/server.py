"""openocd-mcp: OpenOCD 프로세스 관리 + TCL RPC 로 JTAG/SWD 디버그 프로브를 다루는 PWEH MCP 서버.

계약: docs/architecture.md 6.4. 참조 자료: docs/references/openocd-tcl-rpc.md, ~/pweh-tools/INSTALL_REPORT.md.

안전 (모든 기기 조작 공통):
- 케이스는 ``rt().case(case_id, hardware=True)`` 로 열어 소유/허가 증명을 강제한다.
- 보내는 명령 텍스트는 ``guard.classify_command`` (= worst(코어 classify_openocd, 더 엄격한 로컬 규칙)) 로 분류하고
  ``rt().authorize`` 를 통과해야 OpenOCD 로 보낸다. INTERACT 명령도 감사 기록을 위해 authorize 를 거친다.
- halt/resume/reset 은 MODIFY, write_memory/flash write 는 DESTRUCTIVE (기본 거부).
- 호스트 파일을 쓰는 dump_image / flash read_bank 는 덤프 작업만, 케이스의 jtag/ 또는 dumps/ 경로로만 보낸다.
- 백그라운드 덤프 작업은 시작 전 계획 명령 전체와 매 명령을 다시 검사해 INTERACT 를 넘으면 거부/중단한다.
- target 인자로 서버가 만드는 ``<타깃> read_memory|md* …`` 는 ``_trusted_target`` 이 실제 ``target names`` 목록에서 확인하고
  (세션 캐시, 불일치 시 재조회) 명령 이름과 겹치지 않는 이름일 때만 접두를 떼고 분류한다(점 없는 mem_ap/cpu0 용).
  목록에 없거나 명령 이름과 겹치면 보내기 전에 거부한다. 에이전트 원시 명령(openocd_command)에는 적용하지 않는다.
- openocd_start 는 semihosting 을 항상 꺼 둔 채 끝낸다(``semihosting`` 모듈): 신뢰 scripts 의 표준 cfg 는 내용을 분류하지
  않는데, ESP32 계열 cfg 의 ``examine-end`` 핸들러가 semihosting 을 켜면 타깃 펌웨어가 호스트 파일·명령에 접근할 수 있다.
  init 전에 semihosting 관련 이벤트 핸들러를 감싸고, init 직후 타깃마다 확인해 끄고, TCL 연결 직후 RPC 로 다시 확인한다(필수).
  가드보다 먼저 init 이 실행됐거나(``init-before-semihosting-guard``) 끄지/확인하지 못하면 OpenOCD 를 종료하고 ``start_failed``.
  ``-f`` 하나하나와 extra_commands 하나하나 뒤의 init 조기 실행 검사(``semihosting.EARLY_CHECK_SCRIPT``)는 init 이 먼저 돌았으면
  그 자리에서 semihosting 을 끄고 OpenOCD 를 오류로 끝내 다음 시작 명령이 semihosting 이 켜진 채 실행되지 않게 한다.
  extra_commands 의 init 계열 명령은 거부하고, 사용자 cfg 의 init 계열 명령은 DESTRUCTIVE 다.
  시작 뒤에도 MODIFY 이상 명령·halt/resume/reset·쓰기 뒤마다 RPC 로 다시 감싸고 끈다(켜져 있었으면 ``semihosting_reneutralized``,
  끄지 못하면 OpenOCD 를 종료 — fail closed). 결과는 응답·상태 파일·감사 로그와 ``openocd_status`` 의 ``semihosting`` 에 남는다.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import signal
import tempfile
import time
from pathlib import Path
from typing import Any

from pweh.errors import Busy, DeviceError, NotFound, PwehError, SafetyDenied, TimeoutExpired, ValidationFailed
from pweh.fsutil import atomic_write_json, atomic_write_text, parse_size, read_json, sha256_file, utcnow_iso
from pweh.jobs import JobCancelled
from pweh.mcpkit import (
    META_REQUIRE_HUMAN,
    ANN_DESTRUCTIVE,
    ANN_DEVICE,
    ANN_LOCAL_WRITE,
    ANN_READ_ONLY,
    Context,
    create_server,
    gate_response,
    register_job_tools,
    run_blocking,
    safe_tool,
)
from pweh.runtime import Runtime, get_runtime
from pweh.portlock import LeaseHandoff
from pweh.safety import Classification, Risk, worst

from . import dumps, guard, parsers, process, semihosting, windows_start
from .rpc import TclConnectionClosed, TclRpcClient
from .rpc_pipe import TclPipeClient
from .session import REGISTRY, OcdSession
from .tcl import TclReply, brace_quote_path, braces_balanced

SERVER_NAME = "openocd-mcp"
log = logging.getLogger("pweh.openocd")

server = create_server(
    SERVER_NAME,
    title="PWEH OpenOCD (JTAG/SWD)",
    instructions=(
        "OpenOCD 프로세스를 띄우고 TCL RPC 로 JTAG/SWD 프로브를 제어하는 서버. 사람이 프로브 배선(TCK/TMS/TDI/TDO/GND, "
        "가능하면 VREF/TRST/SRST)을 마친 뒤 사용한다. 기본 흐름: openocd_list_configs 로 interface cfg 확인 → "
        "openocd_start(case_id, interface_cfg, target_cfg 또는 extra_commands) 또는 openocd_attach → openocd_scan_chain / "
        "openocd_targets 로 TAP·타깃 확인 → (필요 시) openocd_halt → openocd_read_memory 로 작은 범위 확인 → "
        "openocd_dump_memory_start / openocd_flash_read_start (job) → openocd_job_status(job_id, wait_seconds=30) 폴링 → "
        "openocd_stop. 카메라 SoC 는 OpenOCD 트리에 전용 target cfg 가 없고 SPI NOR 컨트롤러 드라이버도 없는 경우가 많다 "
        "(→ U-Boot 에서 sf read 로 RAM 에 올린 뒤 halt + 메모리 덤프). 원시 Tcl(openocd_command)은 위험도 분류 후 실행되며, "
        "halt/resume/reset 은 MODIFY, 메모리/플래시 쓰기는 DESTRUCTIVE(기본 거부)다."
    ),
)


def rt() -> Runtime:
    return get_runtime(SERVER_NAME)


DEFAULT_TIMEOUT = 30.0
REG_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
IDENT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,63}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.\-:\[\]]{1,253}$")
LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}
MAX_READ_BYTES = 4096
MAX_CUSTOM_CFG_BYTES = 1024 * 1024  # 사용자 cfg 는 전체 내용을 분류한다 — 이보다 크면 거부 (일반 cfg 는 수 KB)


# ---------------------------------------------------------------------------
# 공통 헬퍼
# ---------------------------------------------------------------------------


def _read_custom_cfg(path: Path) -> bytes:
    """사용자 cfg 의 전체 바이트. 크기 상한을 넘으면 거부(앞부분만 분류하면 나머지가 분류 없이 실행되므로)."""
    try:
        size = path.stat().st_size
        if size > MAX_CUSTOM_CFG_BYTES:
            raise ValidationFailed(
                f"사용자 cfg 가 너무 큽니다 ({size} 바이트 > {MAX_CUSTOM_CFG_BYTES}): {path}",
                hint="전체 내용을 분류할 수 없는 cfg 는 실행하지 않습니다. 표준 cfg + extra_commands 를 쓰거나 cfg 를 나누세요.",
            )
        with open(path, "rb") as fh:
            raw = fh.read(MAX_CUSTOM_CFG_BYTES + 1)
    except OSError as exc:
        raise NotFound(f"cfg 파일을 읽을 수 없습니다: {path} ({exc})")
    if len(raw) > MAX_CUSTOM_CFG_BYTES:  # stat 이후 커진 경우
        raise ValidationFailed(f"사용자 cfg 가 너무 큽니다 (> {MAX_CUSTOM_CFG_BYTES} 바이트): {path}")
    return raw


def _unknown_risk() -> str:
    return rt().config.safety.unknown_command_risk


def _classify(cmd: str, sess: OcdSession | None = None) -> Classification:
    """명령 분류. 세션이 있으면 그 OpenOCD 에서 semihosting 가드가 찾은 'semihosting 을 켜는 proc' 호출도 DESTRUCTIVE 로 본다."""
    procs = sess.semihost_procs if sess is not None else frozenset()
    return guard.classify_command(cmd, unknown_risk=_unknown_risk(), semihost_procs=procs)


def _parse_int(value: Any, name: str, *, minimum: int = 0, maximum: int | None = None, size: bool = False) -> int:
    if isinstance(value, bool) or value is None:
        raise ValidationFailed(f"{name} 값이 필요합니다")
    try:
        if isinstance(value, int):
            v = value
        elif size:
            v = parse_size(str(value))
        else:
            v = int(str(value).strip().replace("_", ""), 0)
    except (ValueError, PwehError):
        raise ValidationFailed(f"{name} 를 정수로 해석할 수 없습니다: {value!r}", hint="10진수 또는 0x 접두 16진수 (크기는 64k, 16M 도 가능)")
    if v < minimum or (maximum is not None and v > maximum):
        raise ValidationFailed(f"{name} 범위 밖: {v} (허용 {minimum}~{maximum if maximum is not None else '∞'})")
    return v


def _check_ident(value: str | None, name: str) -> str | None:
    if value is None:
        return None
    v = str(value).strip()
    if not IDENT_RE.match(v):
        raise ValidationFailed(f"잘못된 {name}: {value!r}", hint="영문/숫자/_.- 만 사용 (예: hi3518.cpu)")
    return v


def _session(case_id: str) -> OcdSession:
    sess = REGISTRY.get(case_id)
    if sess.windows and (sess.starting or sess.closing or sess.cleanup_pending):
        raise Busy("Windows OpenOCD 세션이 시작 또는 정리 중입니다.")
    if sess.semihosting_failsafe is not None:
        raise _failsafe_error(sess)
    if sess.process_exited():
        raise sess.exit_error()
    return sess


def _active_jobs(case_id: str) -> list[dict[str, Any]]:
    return [j for j in rt().jobs.list(active_only=True) if j.get("case_id") == case_id]


def _ensure_no_job(case_id: str, what: str) -> None:
    jobs = _active_jobs(case_id)
    if jobs:
        j = jobs[0]
        raise Busy(
            f"이 케이스에서 덤프 작업이 실행 중이라 {what} 을(를) 할 수 없습니다: {j['job_id']} ({j['description']})",
            hint="덤프 결과가 망가지지 않도록 막았습니다. openocd_job_status 로 완료를 기다리거나 openocd_job_cancel 로 취소하세요.",
        )


async def _authorize(case_id: str, tool: str, commands: list[str], *, ctx: Any, approval_id: str | None = None,
                     extra: dict[str, Any] | None = None, classification: Classification | None = None):
    """명령 목록을 분류하고(가장 위험한 것 기준) 안전 게이트를 통과시킨다. (decision, classification) 반환."""
    cls = classification or worst([_classify(c) for c in commands])
    action: dict[str, Any] = {"commands": list(commands)} if len(commands) != 1 else {"command": commands[0]}
    sess = REGISTRY.find(case_id)
    if sess is not None:
        action.update(windows_start.action_fields(sess))
    if extra:
        action.update(extra)
    decision = await rt().authorize(tool=tool, action=action, classification=cls, case_id=case_id, approval_id=approval_id, ctx=ctx)
    return decision, cls


async def _call(sess: OcdSession, cmd: str, *, timeout: float = DEFAULT_TIMEOUT, raw: bool = False) -> TclReply:
    if sess.semihosting_check_pending:
        # 이전 명령이 시간 초과 등으로 끝을 확인하지 못했다 → 새 명령을 보내기 전에 semihosting 부터 다시 확인한다
        res = await _semihosting_enforce(sess, trigger="pending")
        if res is not None and res.get("status") == "failsafe":
            raise _failsafe_error(sess)
        if sess.semihosting_check_pending:
            raise Busy(
                "이전 명령 뒤 semihosting 재확인을 아직 마치지 못해 명령을 보내지 않았습니다 (OpenOCD 가 이전 명령을 처리 중일 수 있음).",
                hint="잠시 뒤 다시 호출하세요. 계속되면 openocd_status 로 확인하고 openocd_stop 으로 정리하세요.",
                data={"semihosting_check": res},
            )

    if sess.windows:
        return await windows_start.call_session(sess, cmd, timeout=timeout, raw=raw)

    def run() -> TclReply:
        try:
            if raw:
                return sess.client.call_raw(cmd, timeout=timeout)
            return sess.client.call(cmd, timeout=timeout)
        except TclConnectionClosed as exc:
            if sess.died_after_disconnect():
                raise sess.exit_error("명령 실행 중") from exc
            raise

    return await run_blocking(run)


def _reply_error(reply: TclReply, *, command: str) -> dict[str, Any]:
    err = reply.error_text or "(OpenOCD 가 오류 메시지 없이 실패 — 자세한 원인은 openocd_status 의 로그 참고)"
    return {"ok": False, "status": "tcl_error", "command": command, "code": reply.code, "error": err, "diagnosis": parsers.diagnose(err)}


# ---------------------------------------------------------------------------
# semihosting 재확인 (semihosting.py 의 Tcl 가드를 RPC 로 다시 실행)
# ---------------------------------------------------------------------------

SEMIHOSTING_CHECK_TIMEOUT = 20.0


def _semihosting_wanted(cls: Classification) -> bool:
    """명령 뒤 semihosting 재확인이 필요한지: MODIFY 이상, 또는 알 수 없는 명령을 INTERACT 로 두는 설정(그 proc 이 켤 수 있다)."""
    return cls.risk >= Risk.MODIFY or _unknown_risk() == "interact"


def _public_procs(procs: Any) -> list[str]:
    """응답에 보여 줄 'semihosting 을 켜는 proc' (가드 자신의 pweh_semihosting_* 는 뺀다)."""
    return sorted(p for p in procs if not str(p).startswith("pweh_semihosting_"))


def _failsafe_error(sess: OcdSession) -> DeviceError:
    fs = sess.semihosting_failsafe or {}
    return DeviceError(
        "semihosting 을 끄지(확인하지) 못해 서버가 OpenOCD 를 종료했습니다: " + "; ".join(fs.get("reasons") or [])[:300],
        hint="openocd_status 로 기록을 확인하고 사람에게 알린 뒤 openocd_stop → (cfg·OpenOCD 를 확인하고) openocd_start 로 다시 시작하세요.",
        data={"semihosting_failsafe": fs},
    )


def _save_semihosting_state(sess: OcdSession) -> None:
    try:
        _write_session_state(sess, rt().case(sess.case_id), semihosting=sess.semihosting)
    except PwehError:  # pragma: no cover - 케이스가 사라진 경우
        pass


async def _semihosting_failsafe(sess: OcdSession, problems: list[str], report: dict[str, Any], *, trigger: str) -> dict[str, Any]:
    """semihosting 을 끄지(확인하지) 못함 → OpenOCD 를 종료한다(fail closed). 세션은 남겨 두어 openocd_status/openocd_stop 으로 본다."""
    method = "not-owned"
    if sess.owned and sess.proc is not None:
        method = await run_blocking(sess.proc.terminate, 2.0) if sess.proc.alive else "already-exited"
    if sess.windows:
        cleanup = await run_blocking(windows_start.close_session, sess)
        method = "windows-confirmed" if cleanup["ok"] else "windows-cleanup-pending"
    else:
        sess.client.close()
    fs = {"at": utcnow_iso(), "trigger": trigger, "reasons": problems, "stop_method": method,
          "targets": report.get("targets") or {}, "process": sess.process_info()}
    sess.semihosting_failsafe = fs
    sess.semihosting_check_pending = False
    sess.semihosting["failsafe"] = fs
    sess.semihosting["verified"] = False
    rt().audit({"event": "openocd_semihosting_failsafe", **fs}, sess.case_id)
    _save_semihosting_state(sess)
    log.warning("semihosting failsafe: stopped OpenOCD for case %s (%s)", sess.case_id, problems)
    return {"status": "failsafe", **fs}


async def _semihosting_enforce(sess: OcdSession, *, trigger: str) -> dict[str, Any] | None:
    """semihosting 가드를 RPC 로 다시 실행한다 (관련 이벤트 핸들러 다시 감싸기 + 모든 타깃 확인·끄기).

    policy 가 ``enabled-by-approval`` (사람이 승인한 명령이 켰음)이면 끄지 않고 읽기 전용 ``status`` 로 상태만 보고한다.
    반환: None(가드를 관리하지 않는 세션 — attached) 또는 ``{status, …}``:
    - ``ok`` / ``reneutralized``: 켜진 타깃이나 감싸지 않은 핸들러를 찾아 무력화했으면 reneutralized (감사 기록 + 상태 파일)
    - ``failsafe``: 가드가 실패를 보고했거나(끄지/감싸지 못함, 스크립트 오류) 가드 호출이 실패했거나 결과가 불완전함 → OpenOCD 종료
    - ``pending``: 시간 초과/연결 문제로 확인하지 못함 → 다음 RPC 전에 다시 확인한다(진행 중일 수 있는 쓰기를 끊지 않도록 죽이지 않는다)
    - ``skipped``: 프로세스가 이미 종료됨, ``reported``: 읽기 전용 보고
    """
    if not sess.semihosting_managed or sess.semihosting_failsafe is not None:
        return None
    if sess.process_exited():
        sess.semihosting_check_pending = False
        return {"status": "skipped", "reason": "OpenOCD 프로세스가 종료됨"}
    readonly = sess.semihosting_policy != "disabled"
    phase = "status" if readonly else "check"
    sess.semihosting_check_pending = True
    try:
        command = semihosting.STATUS_CALL if readonly else semihosting.CHECK_CALL
        if sess.windows:
            reply = await windows_start.call_session(sess, command, timeout=SEMIHOSTING_CHECK_TIMEOUT, internal=True)
        else:
            reply = await run_blocking(sess.client.call, command, timeout=SEMIHOSTING_CHECK_TIMEOUT)
    except TclConnectionClosed as exc:
        if await run_blocking(sess.died_after_disconnect):
            sess.semihosting_check_pending = False
            return {"status": "skipped", "reason": "OpenOCD 프로세스가 종료됨"}
        return {"status": "pending", "error": str(exc)}
    except (TimeoutExpired, PwehError) as exc:
        return {"status": "pending", "error": str(exc)}
    report = semihosting.parse_report(reply.output if reply.ok else "", required=(phase,), startup_only=False)
    problems = [] if reply.ok else [f"semihosting 가드 호출 실패: {(reply.error_text or '(오류 메시지 없음)')[:200]}"]
    problems += semihosting.verification_problems(report, (phase,)) if reply.ok else []
    if sess.windows and report["targets"]:
        problems.append("고정 adapter 프로필에 예상하지 않은 target이 있습니다.")
    if report["procs"]:
        sess.semihost_procs = frozenset(report["procs"])
    now = utcnow_iso()
    state = sess.semihosting
    if readonly:
        sess.semihosting_check_pending = False
        last = {"phase": phase, "trigger": trigger, "at": now, "targets": report["targets"], "unwrapped": report["unwrapped"],
                "problems": problems}
        state["last_check"] = last
        state["targets"] = report["targets"]
        return {"status": "reported", "policy": sess.semihosting_policy, **last}
    if problems:
        return await _semihosting_failsafe(sess, problems, report, trigger=trigger)
    sess.semihosting_check_pending = False
    renewed = semihosting.neutralized_list(report)
    last = {"phase": phase, "trigger": trigger, "at": now, "verified": True, "targets": report["targets"], "reneutralized": renewed}
    state["last_check"] = last
    state["targets"] = report["targets"]
    state["verified"] = True
    wrapped = state.setdefault("handlers_wrapped", [])
    for h in report["handlers_wrapped"]:
        if h not in wrapped:
            wrapped.append(h)
    state["procs"] = _public_procs(sess.semihost_procs)
    if renewed:
        state.setdefault("reneutralized", []).append({"at": now, "trigger": trigger, "items": renewed})
        rt().audit({"event": "openocd_semihosting_reneutralized", "trigger": trigger, "items": renewed, "targets": report["targets"]},
                   sess.case_id)
        _save_semihosting_state(sess)
        return {"status": "reneutralized", **last}
    return {"status": "ok", **last}


def _semihosting_fields(res: dict[str, Any] | None) -> dict[str, Any]:
    """도구 응답에 붙일 semihosting 재확인 결과 필드."""
    if res is None:
        return {}
    out: dict[str, Any] = {"semihosting_check": res}
    if res.get("status") == "reneutralized":
        out["semihosting_reneutralized"] = list(res.get("reneutralized") or [])
        out["semihosting_warning"] = (
            "명령 뒤 semihosting 이 다시 켜져 있었거나 감싸지 않은 관련 핸들러가 있어 다시 무력화했습니다: "
            + ", ".join(out["semihosting_reneutralized"]) + " — 같은 명령을 반복하지 말고 사람에게 알리세요."
        )
    elif res.get("status") == "failsafe":
        out["semihosting_failsafe"] = {k: res.get(k) for k in ("reasons", "stop_method", "process", "trigger", "at")}
    elif res.get("status") == "pending":
        out["semihosting_warning"] = "명령 뒤 semihosting 재확인을 마치지 못했습니다 — 다음 명령 전에 다시 확인합니다."
    elif res.get("status") == "reported" and any(v == "enabled" for v in (res.get("targets") or {}).values()):
        out["semihosting_warning"] = "사람이 승인한 명령으로 semihosting 이 켜져 있습니다 (이 세션은 끄지 않고 보고만 함)."
    return out


def _failsafe_response(res: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "ok": False, "status": "semihosting_failsafe", **extra, **_semihosting_fields(res),
        "message": "명령 뒤 semihosting 을 끄지(확인하지) 못해 OpenOCD 를 종료했습니다 (fail closed).",
        "hint": "사람에게 알리고 openocd_status 로 기록을 확인한 뒤 openocd_stop → openocd_start 로 다시 시작하세요.",
    }


async def _call_checked(sess: OcdSession, cmd: str, *, timeout: float, check: bool, trigger: str, raw: bool = False,
                        on_reply: Any = None) -> tuple[TclReply, dict[str, Any] | None]:
    """명령을 보내고 check 이면 semihosting 을 다시 확인한다. 명령이 예외(시간 초과 등)로 끝나면 확인을 다음 RPC 로 미룬다.

    on_reply(reply): 확인 전에 부른다 (승인된 semihosting 켜기가 성공했는지 보고 정책을 바꾸는 데 쓴다).
    """
    want = check and sess.semihosting_managed
    try:
        reply = await _call(sess, cmd, timeout=timeout, raw=raw)
    except BaseException:
        if want:
            sess.semihosting_check_pending = True
        raise
    if on_reply is not None:
        on_reply(reply)
    res = await _semihosting_enforce(sess, trigger=trigger) if want and not reply.closed else None
    return reply, res


async def _query_targets(case_id: str, sess: OcdSession, ctx: Any, *, timeout: float = 10.0) -> list[dict[str, Any]] | None:
    """targets 조회 (INTERACT). 실패하면 None."""
    decision, _ = await _authorize(case_id, "openocd_targets", ["targets"], ctx=ctx)
    if not decision.allowed:
        return None
    try:
        reply = await _call(sess, "targets", timeout=timeout)
    except PwehError:
        return None
    if not reply.ok:
        return None
    rows = parsers.parse_targets(reply.output)
    sess.last_targets = rows
    return rows


async def _fetch_target_names(case_id: str, sess: OcdSession, *, ctx: Any, tool: str) -> frozenset[str] | None:
    """``target names`` 조회 (INTERACT, 감사 기록) → 이름 집합. 세션에 캐시한다. 얻지 못하면 None."""
    decision, _ = await _authorize(case_id, tool, ["target names"], ctx=ctx)
    if not decision.allowed:
        return None
    try:
        reply = await _call(sess, "target names", timeout=10.0)
    except PwehError:
        return None
    if not reply.ok:
        return None
    names = frozenset(n for n in parsers.parse_target_names(reply.output) if IDENT_RE.fullmatch(n))
    sess.target_names = names
    return names


async def _trusted_target(case_id: str, sess: OcdSession, target: str | None, *, ctx: Any, tool: str) -> frozenset[str]:
    """서버가 ``<target> <읽기 명령>`` 을 만들기 전에 target 이 실제 OpenOCD 타깃인지 확인한다.

    - 명령 이름과 겹치는 이름(``guard.target_name_conflict``)은 거부한다 (ValidationFailed, 아무것도 보내지 않음).
    - 세션 캐시(OpenOCD 프로세스 시작/연결 단위)에 없으면 ``target names`` 를 다시 조회하고, 그래도 없으면 거부한다.
    - 목록을 얻지 못하면 빈 집합 → 접두를 떼지 않는 기존 분류 (점 없는 이름은 MODIFY, 덤프 작업은 시작 거부).

    반환: 접두를 떼고 분류해도 되는 이름 집합(``{target}``) — ``guard.classify_target_read`` / 덤프 작업에 넘긴다.
    """
    if not target:
        return frozenset()
    conflict = guard.target_name_conflict(target)
    if conflict:
        raise ValidationFailed(
            f"타깃 이름 '{target}' 은 '<타깃> <명령>' 형태로 쓸 수 없습니다: {conflict}",
            hint="명령 이름과 같은 타깃은 OpenOCD 버전에 따라 그 명령으로 해석될 수 있어 서버가 접두로 쓰지 않습니다. "
            "openocd_targets 로 이름을 확인하고, 필요하면 사람에게 cfg 의 'target create' 이름(예: cam.ahb)을 바꿔 달라고 요청하세요.",
        )
    names = sess.target_names
    if names is None or target not in names:  # 캐시 없음/불일치 → 다시 조회
        fresh = await _fetch_target_names(case_id, sess, ctx=ctx, tool=tool)
        if fresh is None:
            return frozenset()
        names = fresh
    if target not in names:
        raise ValidationFailed(
            f"타깃 '{target}' 이 OpenOCD 타깃 목록(target names)에 없습니다",
            hint=f"사용 가능: {', '.join(sorted(names)) or '(정의된 타깃 없음)'} — openocd_targets 로 확인하세요.",
        )
    return frozenset({target})


def _classify_read(cmd: str, trusted: frozenset[str]) -> Classification:
    """서버가 만든 읽기 명령 분류: 확인된 타깃의 ``<타깃> read_memory|md*`` 만 접두를 떼고 분류한다."""
    return guard.classify_target_read(cmd, trusted_targets=trusted, unknown_risk=_unknown_risk())


def _target_state(rows: list[dict[str, Any]] | None, target: str | None = None) -> str | None:
    if not rows:
        return None
    t = parsers.current_target(rows, target)
    return t["state"] if t else None


def _endian(rows: list[dict[str, Any]] | None, target: str | None = None) -> str:
    t = parsers.current_target(rows or [], target)
    if t and t.get("endian") in ("big", "little"):
        return t["endian"]
    return "little"


def _next_index(directory: Path, prefix: str, suffix: str) -> int:
    n = 1
    rx = re.compile(re.escape(prefix) + r"(\d+)" + re.escape(suffix) + r"$")
    if directory.exists():
        for p in directory.iterdir():
            m = rx.match(p.name)
            if m:
                n = max(n, int(m.group(1)) + 1)
    return n


def _hexdump(data: bytes, base: int, max_lines: int = 256) -> list[str]:
    lines = []
    for off in range(0, len(data), 16):
        if len(lines) >= max_lines:
            lines.append("...")
            break
        chunk = data[off : off + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + off:08x}  {hx:<47}  |{asc}|")
    return lines


def _write_session_state(sess: OcdSession, case, **extra: Any) -> None:
    if sess.state_file is None:
        return
    doc = read_json(sess.state_file) or {}
    doc.update(
        {
            "schema": "pweh.openocd-session/v1",
            "case_id": sess.case_id,
            "mode": sess.mode,
            "pid": sess.proc.pid if sess.proc else None,
            "host": sess.host,
            "tcl_port": sess.port,
            "argv": sess.argv,
            "log": case.rel(sess.log_path) if sess.log_path else None,
            "started_at": sess.started_at,
            "version": (sess.version or {}).get("raw"),
        }
    )
    if sess.windows:
        doc.update(transport="windows-pipe", backend="windows", windows_profile=sess.windows_profile,
                   starting=sess.starting, closing=sess.closing, cleanup_pending=sess.cleanup_pending,
                   cleanup_reason=sess.cleanup_reason, bundle=windows_start.action_fields(sess),
                   semihosting=dict(sess.semihosting))
    doc.update(extra)
    try:
        atomic_write_json(sess.state_file, doc)
    except OSError as exc:  # pragma: no cover
        log.warning("session state write failed: %s", exc)


# ---------------------------------------------------------------------------
# 프로세스 / 연결
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "OpenOCD 프로세스를 시작하고 TCL RPC 로 연결한다 (MODIFY: JTAG 초기화가 타깃 상태에 영향 가능). telnet/GDB 포트는 끄고 "
        "TCL 포트만 127.0.0.1 에 연다. interface_cfg 는 scripts 기준 상대경로(예: 'interface/ftdi/tigard.cfg', "
        "'interface/jlink.cfg') 또는 절대경로. target_cfg 는 문자열 또는 목록. 카메라 SoC 는 전용 target cfg 가 없는 경우가 많아 "
        "target_cfg 없이 extra_commands 로 'jtag newtap ...', 'target create ...' 를 주거나 아예 생략해 자동 탐색(AUTO 힌트)한다. "
        "transport: jtag|swd. adapter_speed_khz: 처음엔 100~1000 권장. tcl_port=0 이면 빈 포트 자동 선택. "
        "케이스 밖 사용자 cfg 파일은 내용을 위험도 분류기로 검사한다. 로그는 jtag/openocd-<n>.log. "
        "반환: tcl_port, version, startup(TAP 검출, 오류/경고), diagnosis(배선/전원 힌트), scan_chain, targets, health. "
        "backend 기본 linux. windows는 등록 번들과 WSL interop에서 windows_profile='dummy-noinit-v1', "
        "interface_cfg='interface/dummy.cfg', tcl_port=0이면 USB 초기화 없이 조회한다. "
        "windows_profile='tigard-jtag-v1', interface_cfg='interface/ftdi/tigard.cfg', tcl_port=0은 "
        "유일한 0403:6010 전체 USB 범위를 잠그고 JTAG 100kHz 초기화·자동 TAP 탐색을 수행한다(MODIFY). "
        "Tigard는 target/추가 cfg·명령 없이 version/scan_chain/targets와 상태·종료만 지원한다. "
        "hardware_initialized=true는 adapter 초기화만 뜻하며 target_communication_verified=false이다. "
        "Windows 메모리·레지스터·flash·덤프 작업·수정은 거부한다. ready_timeout은 0초 초과 30초 이하. "
        "Windows 반환 transport='windows-pipe', tcl_port=null이며 초기화 경고와 degraded health를 보존한다."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def openocd_start(
    case_id: str,
    interface_cfg: str,
    ctx: Context,
    target_cfg: str | list[str] | None = None,
    transport: str | None = None,
    adapter_speed_khz: int | None = None,
    extra_commands: list[str] | None = None,
    tcl_port: int = 6666,
    extra_cfgs: list[str] | None = None,
    ready_timeout: float = 30.0,
    approval_id: str | None = None,
    backend: str = "linux",
    windows_profile: str | None = None,
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id, hardware=True)
    if backend not in ("linux", "windows"):
        raise ValidationFailed("backend는 linux 또는 windows여야 합니다.")
    if backend == "windows":
        return await windows_start.start(r, case, ctx=ctx, approval_id=approval_id, ready_timeout=ready_timeout,
            windows_profile=windows_profile, interface_cfg=interface_cfg, target_cfg=target_cfg,
            extra_cfgs=extra_cfgs, extra_commands=extra_commands, transport=transport,
            adapter_speed_khz=adapter_speed_khz, tcl_port=tcl_port)
    if windows_profile is not None:
        raise ValidationFailed("windows_profile은 Windows backend에서만 사용합니다.")
    if REGISTRY.find(case_id) is not None:
        cur = REGISTRY.get(case_id)
        if cur.process_exited():
            REGISTRY.remove(case_id)
        else:
            raise Busy(
                f"케이스 {case_id} 에 이미 OpenOCD 세션이 있습니다 (mode={cur.mode}, port={cur.port}).",
                hint="openocd_status 로 확인하고, 다시 시작하려면 openocd_stop 을 먼저 호출하세요.",
            )
    if transport is not None:
        transport = str(transport).strip().lower()
        if transport not in process.TRANSPORTS:
            raise ValidationFailed(f"지원하지 않는 transport: {transport!r}", hint=f"허용: {', '.join(process.TRANSPORTS)}")
    if adapter_speed_khz is not None:
        adapter_speed_khz = _parse_int(adapter_speed_khz, "adapter_speed_khz", minimum=0, maximum=1_000_000)
    tcl_port = _parse_int(tcl_port, "tcl_port", minimum=0, maximum=65535)
    ready_timeout = max(3.0, min(float(ready_timeout), 300.0))
    cmds: list[str] = []
    for c in extra_commands or []:
        if not isinstance(c, str) or not c.strip():
            raise ValidationFailed("extra_commands 의 각 항목은 비어 있지 않은 문자열이어야 합니다")
        if any(ch in c for ch in "\x00\x1a") or len(c) > 8192:
            raise ValidationFailed(f"extra_commands 항목이 너무 길거나 제어문자를 포함합니다: {c[:60]!r}")
        if not braces_balanced(c):
            raise ValidationFailed(f"extra_commands 항목의 중괄호 짝이 맞지 않습니다: {c[:80]!r}")
        inits = guard.init_family_commands(c)
        if inits:
            raise ValidationFailed(
                f"extra_commands 에 init 계열 명령을 넣을 수 없습니다: {inits[0][:80]!r}",
                hint="openocd_start 는 semihosting 무력화 가드를 실행한 뒤 init 을 직접 실행한다. 그보다 먼저 init(target/transport/jtag/dap "
                "init 등)을 하면 cfg 의 이벤트 핸들러(예: ESP32 examine-end 의 'arm semihosting enable')가 감싸지지 않은 채 실행된다. "
                "init 을 빼고, init 뒤에 할 일(reset, halt …)은 시작 후 openocd_reset/openocd_halt/openocd_command 로 보내세요.",
            )
        cmds.append(c.strip())

    binary = process.find_openocd(r.config.tool_path("openocd"))
    configured_scripts = (r.config.tools.get("openocd_scripts") or os.environ.get("PWEH_OPENOCD_SCRIPTS") or "").strip()
    dirs = process.scripts_dirs(configured_scripts or None, binary)
    # OpenOCD 가 더 찾아보는 사용자 쓰기 가능 위치(~/.openocd 등)에서 찾은 cfg 도 내용 분류 대상으로 (이름만 넘기면 분류 없이 실행됨)
    untrusted = process.openocd_search_dirs(binary, exclude=dirs)
    iface = process.resolve_cfg(interface_cfg, dirs, untrusted)
    tlist = [target_cfg] if isinstance(target_cfg, str) else list(target_cfg or [])
    targets = [process.resolve_cfg(t, dirs, untrusted) for t in tlist]
    extras = [process.resolve_cfg(e, dirs, untrusted) for e in (extra_cfgs or [])]

    # --- 위험도: 기본(MODIFY) + 추가 명령 + 사용자 cfg 내용 ---------------------------------
    results = [Classification(Risk.MODIFY, "openocd.start", "OpenOCD 시작 — JTAG/SWD 초기화(TAP 리셋, 체인 검사, 타깃 examine)가 타깃 상태에 영향을 줄 수 있음",
                              f"interface={iface.arg} target={[t.arg for t in targets]}")]
    generated = []
    if transport:
        generated.append(f"transport select {transport}")
    if adapter_speed_khz is not None:
        generated.append(f"adapter speed {adapter_speed_khz}")
    for c in generated + cmds:
        results.append(_classify(c))
    custom_cfgs = []
    custom_sha: dict[str, str] = {}
    for ref in [iface, *targets, *extras]:
        if ref.kind == "custom" and ref.path is not None:
            raw = _read_custom_cfg(ref.path)
            # 앞부분만 잘라 분류하면 나머지가 분류 없이 실행된다 → 전체를 분류하고, 너무 크면 거부한다
            text = raw.decode("utf-8", errors="replace")
            c = _classify(text)
            inits = guard.init_family_commands(text)
            if inits:
                # cfg 가 init 을 직접 하면 semihosting 가드보다 먼저 cfg 의 핸들러가 실행된다 (실행하면 init-before-semihosting-guard 로 종료)
                c = worst([c, Classification(
                    Risk.DESTRUCTIVE, "openocd.local.init-before-guard",
                    f"init 계열 명령 '{inits[0][:60]}' — semihosting 무력화 가드보다 먼저 init 하면 이벤트 핸들러가 감싸지지 않은 채 실행됨 "
                    "(openocd_start 가 가드 뒤에 init 을 직접 실행하니 cfg 에서 init 을 빼세요)",
                    inits[0][:200],
                )])
            results.append(Classification(c.risk, f"openocd.cfg:{c.rule_id}", f"사용자 cfg {ref.path.name}: {c.reason}", str(ref.path), c.uncertain))
            sha = hashlib.sha256(raw).hexdigest()
            custom_sha[str(ref.path)] = sha
            custom_cfgs.append({"path": str(ref.path), "sha256": sha, "classification": c.to_dict()})
    cls = worst(results)

    if tcl_port > 0 and process.port_in_use("127.0.0.1", tcl_port):
        raise Busy(
            f"127.0.0.1:{tcl_port} 포트가 이미 사용 중입니다 (다른 OpenOCD 가 실행 중일 수 있음).",
            hint="이미 실행 중인 OpenOCD 를 쓰려면 openocd_attach, 새로 띄우려면 다른 tcl_port(0=자동)를 지정하세요.",
        )

    action = {
        "interface_cfg": iface.arg,
        "target_cfgs": [t.arg for t in targets],
        "extra_cfgs": [e.arg for e in extras],
        "transport": transport,
        "adapter_speed_khz": adapter_speed_khz,
        "extra_commands": cmds,
        "tcl_port": tcl_port,
    }
    if custom_sha:
        # 승인은 사람이 본 cfg 내용에 묶인다 (승인 뒤 같은 경로의 내용이 바뀌면 지문이 달라 무효)
        action["custom_cfg_sha256"] = custom_sha
    decision = await r.authorize(tool="openocd_start", action=action, classification=cls, case_id=case_id, approval_id=approval_id, ctx=ctx)
    if not decision.allowed:
        return gate_response(decision, custom_cfgs=custom_cfgs)
    # 분류·승인 이후 프로세스를 띄우기 직전에 사용자 cfg 가 바뀌지 않았는지 다시 확인 (TOCTOU)
    for path_s, sha in custom_sha.items():
        if hashlib.sha256(_read_custom_cfg(Path(path_s))).hexdigest() != sha:
            raise SafetyDenied(
                f"분류(승인) 이후 사용자 cfg 내용이 바뀌었습니다: {path_s}. 실행하지 않습니다.",
                hint="내용을 확정한 뒤 다시 호출해 새로 분류(필요하면 승인)받으세요.",
            )

    version = await run_blocking(process.openocd_version, binary)
    jtag_dir = case.subdir("jtag")
    n = _next_index(jtag_dir, "openocd-", ".log")
    log_path = jtag_dir / f"openocd-{n}.log"
    scripts_arg = Path(configured_scripts).expanduser() if configured_scripts and Path(configured_scripts).expanduser().is_dir() else None
    argv = process.build_argv(
        binary, scripts_dir=scripts_arg, interface=iface, transport=transport, targets=targets, extra_cfgs=extras,
        adapter_speed_khz=adapter_speed_khz, extra_commands=cmds, tcl_port=tcl_port, search_dirs=dirs,
    )
    # 비어 있는 전용 작업 디렉터리: OpenOCD 는 상대 cfg/스크립트 경로를 cwd 에서 먼저 찾으므로(find_file),
    # 케이스 안에 손으로 쓴 파일이 표준 cfg 나 그 안의 'source [find ...]' 를 가로채지 못하게 한다.
    run_cwd = Path(tempfile.mkdtemp(prefix=f".openocd-{n}-cwd-", dir=str(jtag_dir)))
    proc = process.spawn(argv, cwd=run_cwd, log_path=log_path)
    r.audit({"event": "openocd_spawned", "pid": proc.pid, "argv": argv, "log": case.rel(log_path)}, case_id)
    try:
        return await _finish_start(
            r, case, case_id, ctx, proc=proc, argv=argv, log_path=log_path, jtag_dir=jtag_dir, n=n, tcl_port=tcl_port,
            ready_timeout=ready_timeout, version=version, cls=cls, custom_cfgs=custom_cfgs,
        )
    except BaseException:
        # 취소/예기치 못한 오류로 세션 등록 전에 빠져나가면 띄운 프로세스를 남기지 않는다
        if REGISTRY.find(case_id) is None and proc.alive:
            proc.terminate(grace=2.0)
        raise


async def _finish_start(r, case, case_id: str, ctx: Any, *, proc, argv, log_path: Path, jtag_dir: Path, n: int, tcl_port: int,
                        ready_timeout: float, version: dict[str, Any], cls: Classification, custom_cfgs: list) -> dict[str, Any]:
    ready = await run_blocking(process.wait_ready, proc, log_offset=0, timeout=ready_timeout)

    def failure(reason: str, extra_info: dict[str, Any] | None = None, extra_diagnosis: list[dict[str, str]] | None = None) -> dict[str, Any]:
        method = proc.terminate(grace=2.0) if proc.alive else "already-exited"
        proc.cleanup_cwd()  # 실행 전용 작업 디렉터리가 비어 있으면 정리 (openocd_stop 과 같음 — 무언가 남았으면 증거로 보존)
        text = process.read_log_since(log_path, 0)
        summary = parsers.parse_log_summary(text)
        out = {
            "ok": False,
            "status": "start_failed",
            "reason": reason,
            "process": proc.returncode_info(),
            "stop_method": method,
            "errors": summary["errors"],
            "diagnosis": (extra_diagnosis or []) + parsers.diagnose(text),
            "log_path": case.rel(log_path),
            "log_tail": process.tail_lines(log_path, 30),
            "argv": argv,
            "version": version.get("raw"),
        }
        if extra_info:
            out.update(extra_info)
        r.audit({"event": "openocd_start_failed", "reason": reason, "errors": summary["errors"][-5:]}, case_id)
        try:
            case.register_artifact(log_path, kind="other", producer=SERVER_NAME, description="OpenOCD 로그 (시작 실패)")
        except PwehError:
            pass
        return out

    def semihosting_failure(report: dict[str, Any], problems: list[str], log_text: str) -> dict[str, Any]:
        reason, extra, diag_entries = _semihosting_start_failure(report, problems, log_text)
        r.audit({"event": "openocd_semihosting_failed", "reason": reason, "reasons": problems}, case_id)
        return failure(reason, extra, extra_diagnosis=diag_entries)

    if not ready.ready:
        # init 조기 실행 검사(semihosting.EARLY_CHECK_SCRIPT)는 semihosting 을 끄고 OpenOCD 를 오류로 끝낸다 → 프로세스 종료 대신
        # 로그 표식의 치명 사유(init-before-semihosting-guard 등)로 실패를 돌려준다
        early_text = process.read_log_since(log_path, 0)
        early_report = semihosting.parse_report(early_text)
        early_fatal = semihosting.fatal_reasons(early_report)
        if early_fatal:
            return semihosting_failure(early_report, early_fatal, early_text)
        return failure(ready.reason)

    # (1) 시작 로그의 표식(-d3 접두 포함): TCL 서버가 연결을 받기 전에 끝난 가드의 결과. 실패가 보이면 연결하지 않고 끝낸다.
    startup_text = process.read_log_since(log_path, 0)
    log_report = semihosting.parse_report(startup_text)
    log_fatal = semihosting.fatal_reasons(log_report)
    if log_fatal:
        return semihosting_failure(log_report, log_fatal, startup_text)
    port = ready.port or tcl_port
    client = TclRpcClient("127.0.0.1", port, name=f"{case_id}-main")
    deadline_left = max(5.0, ready_timeout - ready.elapsed)
    try:
        vreply = await run_blocking(client.call, "version", timeout=deadline_left)
    except PwehError as exc:
        client.close()
        return failure("version-rpc-failed", {"rpc_error": str(exc)})
    if not vreply.ok:
        client.close()
        return failure("version-rpc-error", {"rpc_error": vreply.error_text})
    # (2) 필수: TCL RPC 로 가드를 다시 실행해 확인한다. 가드가 전역 변수에 남긴 시작 단계 기록(로그 형식·리다이렉트와 무관) +
    # 지금 상태. 가드 proc 이 없거나(가드가 실행되지 않은 OpenOCD) 결과가 불완전하거나 실패가 있으면 실행하지 않는다.
    required = (*semihosting.STARTUP_PHASES, "verify")
    try:
        gr = await run_blocking(client.call, semihosting.VERIFY_CALL, timeout=max(5.0, min(30.0, deadline_left)))
    except PwehError as exc:
        client.close()
        return semihosting_failure(log_report, [f"semihosting 가드 확인(RPC) 실패: {exc}"], startup_text)
    sh_report = semihosting.parse_report(gr.output if gr.ok else "", required=required, startup_only=False)
    problems = (semihosting.verification_problems(sh_report, required) if gr.ok
                else [f"semihosting 가드 확인(RPC) 실패: {(gr.error_text or '(오류 메시지 없음)')[:200]}"])
    if problems:
        client.close()
        return semihosting_failure(sh_report, problems, startup_text)
    sh_report["source"] = "rpc"
    sh_report["log_markers"] = bool(log_report["phases"])  # 시작 로그에서도 표식을 찾았는지 (-d3/리다이렉트면 없을 수 있음)

    sess = OcdSession(
        case_id=case_id, mode="spawned", host="127.0.0.1", port=port, client=client, proc=proc, log_path=log_path,
        log_offset=0, argv=argv, version=parsers.parse_version(vreply.output),
    )
    sess.state_file = jtag_dir / f"openocd-{n}.json"
    sess.semihosting_managed = True
    sess.semihost_procs = frozenset(sh_report["procs"])
    sh_report["procs"] = _public_procs(sh_report["procs"])
    sh_neutralized = semihosting.neutralized_list(sh_report)
    sess.semihosting = {
        "policy": "disabled", "verified": True, "targets": sh_report["targets"], "handlers_wrapped": list(sh_report["handlers_wrapped"]),
        "procs": sh_report["procs"], "neutralized_at_start": sh_neutralized, "reneutralized": [],
        "last_check": {"phase": "verify", "trigger": "openocd_start", "at": utcnow_iso(), "verified": True, "targets": sh_report["targets"]},
    }
    text = sess.run_log()
    summary = parsers.parse_log_summary(text)
    diag = parsers.diagnose(text) + semihosting.diagnosis_entries(sh_report, startup_text)
    sess.startup = {"summary": summary, "diagnosis": diag, "semihosting": sh_report}
    REGISTRY.add(sess)
    _write_session_state(sess, case, semihosting=sess.semihosting)
    r.audit({"event": "openocd_semihosting", "verified": sh_report["verified"], "neutralized": sh_neutralized,
             "targets": sh_report["targets"], "source": "rpc"}, case_id)

    warnings = []
    for svc in ("telnet", "gdb"):
        if svc in summary["listening"]:
            warnings.append(f"{svc} 포트({summary['listening'][svc]})가 열려 있습니다 — cfg 파일이 포트 설정을 바꿨을 수 있습니다.")

    scan: list[dict[str, Any]] | None = None
    tgts: list[dict[str, Any]] | None = None
    d1, _ = await _authorize(case_id, "openocd_scan_chain", ["scan_chain"], ctx=ctx)
    if d1.allowed:
        try:
            rep = await _call(sess, "scan_chain", timeout=10.0)
            if rep.ok:
                scan = _enrich_taps(parsers.parse_scan_chain(rep.output), summary)
        except PwehError as exc:
            warnings.append(f"scan_chain 조회 실패: {exc}")
    tgts = await _query_targets(case_id, sess, ctx)

    health = "ok"
    if summary["errors"] or any(d["code"] in ("jtag_all_ones", "jtag_all_zeroes", "examine_failed", "ir_capture_error") for d in diag):
        health = "degraded"
    r.audit({"event": "openocd_started", "pid": proc.pid, "tcl_port": port, "health": health}, case_id)
    return {
        "ok": True,
        "status": "running",
        "health": health,
        "session": sess.describe(),
        "tcl_port": port,
        "pid": proc.pid,
        "version": sess.version.get("raw"),
        "log_path": case.rel(log_path),
        "argv": argv,
        "startup": summary,
        "diagnosis": diag,
        "scan_chain": scan,
        "targets": tgts,
        "warnings": warnings,
        "custom_cfgs": custom_cfgs,
        "classification": cls.to_dict(),
        # 무력화한 것: '<타깃>:<이벤트>'(감싼 핸들러), 'tap:<TAP>:<이벤트>', '<타깃>:after-init'(init 직후 켜져 있어 끔),
        # '<타깃>:after-start'(연결 직후 RPC 확인에서 켜져 있어 끔)
        "semihosting_neutralized": sh_neutralized,
        "semihosting": sh_report,
        "next": "openocd_scan_chain / openocd_targets 로 확인 → openocd_halt → openocd_read_memory",
    }


def _semihosting_start_failure(report: dict[str, Any], problems: list[str], log_text: str) -> tuple[str, dict[str, Any], list[dict[str, str]]]:
    """semihosting 가드 문제로 시작을 실패시킬 때의 (reason, 응답 추가 필드, 진단 항목)."""
    if report.get("init_before_guard"):
        reason = "init-before-semihosting-guard"
        hint = ("cfg(신뢰 scripts 포함)나 시작 명령이 init 을 직접 실행해 semihosting 무력화 가드보다 init 이 먼저 돌았습니다(그동안 cfg 의 "
                "이벤트 핸들러가 감싸지지 않은 채 실행됨). init 을 하지 않는 cfg 로 시작하세요 — openocd_start 가 가드 뒤에 init 을 실행합니다.")
    elif any(f["kind"] in ("wrap-failed", "disable-failed", "error") for f in report.get("failures", [])):
        reason = "semihosting-neutralization-failed"
        hint = "semihosting 이 꺼졌다고 확인할 수 없어 OpenOCD 를 종료했습니다. cfg 와 OpenOCD 버전을 사람에게 확인받으세요."
    else:
        reason = "semihosting-verification-failed"
        hint = ("OpenOCD 가 semihosting 가드 확인(RPC)에 제대로 답하지 않았습니다 — 가드 스크립트가 실행되지 않은 실행 파일일 수 있어 실행하지 "
                "않습니다. OpenOCD 실행 파일(PWEH_OPENOCD)과 버전(xPack 0.12.0-7 로 검증)을 사람에게 확인받으세요.")
    diag = semihosting.diagnosis_entries(report, log_text)
    if not any(d["code"] == "semihosting_neutralization_failed" for d in diag):
        diag.insert(0, {"code": "semihosting_neutralization_failed", "message": "semihosting 이 꺼졌다고 확인하지 못해 OpenOCD 를 종료함",
                        "evidence": "; ".join(problems)[:200], "hint": hint})
    return reason, {"semihosting": report, "semihosting_failures": problems, "hint": hint}, diag


def _enrich_taps(taps: list[dict[str, Any]], summary: dict[str, Any] | None) -> list[dict[str, Any]]:
    """OpenOCD 로그의 제조사 이름(jep106 전체 표)을 scan_chain 결과에 붙인다."""
    by_tap = {}
    for t in (summary or {}).get("taps", []):
        by_tap[t["tap_name"]] = t
    for tap in taps:
        lt = by_tap.get(tap["tap_name"])
        if lt and lt.get("idcode") == tap["idcode"] and lt.get("manufacturer") not in (None, "<invalid>", "<unknown>"):
            tap["decoded"]["manufacturer"] = lt["manufacturer"]
    return taps


@server.tool(
    description=(
        "이미 실행 중인 OpenOCD 의 TCL 포트에 연결한다 (예: 사람이 직접 띄운 OpenOCD, 원격 Raspberry Pi). 이 케이스에서 전에 "
        "openocd_start 로 띄운 프로세스(서버 재시작 등)면 상태 파일로 찾아 '입양'해 openocd_stop 으로 종료할 수 있게 한다. "
        "원격 호스트면 dump_image 파일을 읽을 수 없으므로 메모리 덤프는 read_memory 방식으로 자동 전환되고 플래시 덤프는 불가."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def openocd_attach(case_id: str, ctx: Context, host: str = "127.0.0.1", tcl_port: int = 6666, approval_id: str | None = None) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id, hardware=True)
    host = str(host).strip()
    if not HOST_RE.match(host):
        raise ValidationFailed(f"잘못된 host: {host!r}")
    tcl_port = _parse_int(tcl_port, "tcl_port", minimum=1, maximum=65535)
    if REGISTRY.find(case_id) is not None:
        cur = REGISTRY.get(case_id)
        if not cur.process_exited():
            raise Busy(f"케이스 {case_id} 에 이미 OpenOCD 세션이 있습니다 (mode={cur.mode}, port={cur.port}).", hint="openocd_stop 후 다시 시도하세요.")
        REGISTRY.remove(case_id)
    decision, cls = await _authorize(case_id, "openocd_attach", ["version"], ctx=ctx, approval_id=approval_id, extra={"host": host, "tcl_port": tcl_port})
    if not decision.allowed:
        return gate_response(decision)
    client = TclRpcClient(host, tcl_port, name=f"{case_id}-main")
    try:
        reply = await run_blocking(client.call, "version", timeout=10.0)
    except PwehError:
        client.close()
        raise
    ver = parsers.parse_version(reply.output)
    if not reply.ok or not ver.get("parsed"):
        client.close()
        raise DeviceError(
            f"{host}:{tcl_port} 의 응답이 OpenOCD TCL RPC 로 보이지 않습니다: {reply.raw[:200]!r}",
            hint="포트 번호(기본 6666, telnet 4444 아님)를 확인하세요.",
        )
    # 입양: 이 케이스에서 띄웠던 프로세스인지 상태 파일로 확인
    adopted = None
    jtag_dir = case.subdir("jtag")
    if host in LOOPBACK:
        for sf in sorted(jtag_dir.glob("openocd-*.json")):
            doc = read_json(sf) or {}
            if doc.get("transport") == "windows-pipe":
                continue  # 과거 Windows owner는 TCP PID/포트로 입양하지 않는다.
            pid = doc.get("pid")
            if doc.get("tcl_port") == tcl_port and isinstance(pid, int) and doc.get("stopped_at") is None and process.pid_alive(pid):
                cmd = process.pid_cmdline(pid)
                if cmd and any("openocd" in os.path.basename(x).lower() for x in cmd[:2]):
                    adopted = (sf, doc)
    proc = None
    log_path = None
    mode = "attached"
    state_file = None
    argv: list[str] = []
    if adopted is not None:
        sf, doc = adopted
        log_rel = doc.get("log")
        log_path = case.resolve_path(log_rel) if log_rel else None
        argv = list(doc.get("argv") or [])
        proc = process.OpenOcdProcess(popen=None, argv=argv, log_path=log_path or jtag_dir / "unknown.log", adopted_pid=doc["pid"])
        mode = "adopted"
        state_file = sf
    sess = OcdSession(case_id=case_id, mode=mode, host=host, port=tcl_port, client=client, proc=proc, log_path=log_path,
                      log_offset=0, argv=argv, version=ver)
    sess.state_file = state_file
    if log_path is not None:
        text = sess.run_log()
        # 입양: 이 서버가 띄운 프로세스라 시작 로그에 semihosting 무력화 표식이 있다
        sh_report = semihosting.parse_report(text)
        sess.startup = {"summary": parsers.parse_log_summary(text),
                        "diagnosis": parsers.diagnose(text) + semihosting.diagnosis_entries(sh_report, text),
                        "semihosting": sh_report}
    REGISTRY.add(sess)
    if state_file is not None:
        _write_session_state(sess, case, adopted_at=utcnow_iso())
    sh_fields: dict[str, Any] = {}
    if mode == "adopted":
        # 이 서버가 띄운 프로세스: 가드 proc 이 있으면 관리 대상으로 삼아 지금 바로 다시 확인·무력화한다(없으면 attached 처럼 안내만)
        try:
            probe = await run_blocking(client.call, f"info procs {semihosting.GUARD_PROC}", timeout=10.0)
            has_guard = probe.ok and probe.output.strip() == semihosting.GUARD_PROC
        except PwehError:
            has_guard = False
        if has_guard:
            sess.semihosting_managed = True
            sess.semihosting = {"policy": "disabled", "verified": False, "handlers_wrapped": [], "reneutralized": []}
            res = await _semihosting_enforce(sess, trigger="openocd_attach")
            sh_fields = _semihosting_fields(res)
            if res is not None and res.get("status") == "failsafe":
                return _failsafe_response(res, mode=mode, session=sess.describe())
        else:
            sh_fields = {"semihosting_warning": "입양한 OpenOCD 에 semihosting 가드가 없습니다(예전 서버가 띄움) — 무력화를 확인할 수 없으니 "
                                                "openocd_stop 후 openocd_start 로 다시 시작하는 것을 권장합니다."}
    tgts = await _query_targets(case_id, sess, ctx)
    r.audit({"event": "openocd_attached", "host": host, "tcl_port": tcl_port, "mode": mode}, case_id)
    out = {
        "ok": True,
        "status": "connected",
        "mode": mode,
        "session": sess.describe(),
        "version": ver.get("raw"),
        "targets": tgts,
        "remote": host not in LOOPBACK,
        **sh_fields,
    }
    if host not in LOOPBACK:
        out["note"] = "원격 OpenOCD: 메모리 덤프는 read_memory 방식(느림)으로만, 플래시 read_bank 덤프는 불가."
    return out


@server.tool(
    description=(
        "OpenOCD 세션 종료. 이 서버가 띄운(또는 입양한) 프로세스는 TCL 'shutdown' → SIGTERM → SIGKILL 순서로 종료하고 로그를 "
        "아티팩트로 등록한다. 실행 중인 덤프 작업은 먼저 취소된다(부분 결과 보존). 외부에서 띄운 OpenOCD(attach)는 연결만 끊으며, "
        "shutdown_attached=true 일 때만 'shutdown' 을 보낸다(MODIFY 게이트). Windows dummy는 실제 Windows owner 종료와 "
        "진행 중 조회 종료를 모두 확인한 뒤 run을 제거한다. 확인 불가이면 cleanup_pending=true로 보존하며 다시 stop한다."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def openocd_stop(case_id: str, ctx: Context, shutdown_attached: bool = False, approval_id: str | None = None) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id)
    sess = REGISTRY.get(case_id)
    if sess.windows:
        # 등록 직전인 작업도 첫 RPC 전에 closing을 보게 한다. 사용권은 worker만 반환한다.
        sess.begin_close()
        cancelled = []
        for j in _active_jobs(case_id):
            r.jobs.cancel(j["job_id"])
            cancelled.append(j["job_id"])
        result = await run_blocking(windows_start.close_session, sess)
        result["cancelled_jobs"] = cancelled
        if result["stopped"] and sess.log_path is not None and sess.log_path.exists():
            result["log_artifact"] = case.register_artifact(sess.log_path, kind="other", producer=SERVER_NAME,
                                                          description="Windows dummy OpenOCD 로그")
        r.audit({"event": "openocd_stopped", "backend": "windows", "cleanup_pending": result["cleanup_pending"],
                 "cancelled_jobs": cancelled}, case_id)
        return result
    cancelled = []
    for j in _active_jobs(case_id):
        r.jobs.cancel(j["job_id"])
        cancelled.append(j["job_id"])
    for jid in cancelled:
        await run_blocking(r.jobs.wait, jid, 15.0)
    method = "disconnect"
    if sess.owned and sess.proc is not None:
        if sess.proc.alive:
            try:
                await run_blocking(sess.client.send_unwrapped, "shutdown", timeout=5.0)
            except PwehError:
                pass
            exited = await run_blocking(sess.proc.wait, 6.0)
            method = "shutdown" if exited else await run_blocking(sess.proc.terminate, 3.0)
            if exited:
                sess.proc.mark_exited()
        else:
            method = "already-exited"
            sess.proc.mark_exited()
    elif shutdown_attached:
        decision, _ = await _authorize(case_id, "openocd_stop", ["shutdown"], ctx=ctx, approval_id=approval_id, extra={"host": sess.host, "tcl_port": sess.port})
        if not decision.allowed:
            return gate_response(decision)
        try:
            await run_blocking(sess.client.send_unwrapped, "shutdown", timeout=5.0)
            method = "shutdown-attached"
        except PwehError as exc:
            method = f"shutdown-attached-failed: {exc}"
    sess.client.close()
    REGISTRY.remove(case_id)
    if sess.owned and sess.proc is not None:
        sess.proc.cleanup_cwd()
    exit_info = sess.process_info()
    _write_session_state(sess, case, stopped_at=utcnow_iso(), exit=exit_info, stop_method=method)
    art = None
    if sess.log_path is not None and sess.log_path.exists():
        try:
            art = case.register_artifact(sess.log_path, kind="other", producer=SERVER_NAME, description="OpenOCD 로그")
        except PwehError:
            art = None
    r.audit({"event": "openocd_stopped", "mode": sess.mode, "method": method, "exit": exit_info, "cancelled_jobs": cancelled}, case_id)
    return {
        "ok": True,
        "stopped": True,
        "mode": sess.mode,
        "method": method,
        "process": exit_info,
        "cancelled_jobs": cancelled,
        "log_path": case.rel(sess.log_path) if sess.log_path else None,
        "log_tail": process.tail_lines(sess.log_path, 15),
        "log_artifact": art,
    }


@server.tool(
    description=(
        "OpenOCD 세션 상태: 연결/프로세스(종료 코드·시그널), 버전, 포트, 가동 시간, 최근 로그(log_lines 줄), 기동 요약, 진단 힌트, "
        "실행 중인 작업, 그리고 살아 있으면 targets 조회로 현재 타깃 상태(halted/running 등). 세션이 없으면 이 케이스의 이전 실행 기록."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
async def openocd_status(case_id: str, ctx: Context, log_lines: int = 40) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id, hardware=True)
    log_lines = max(0, min(int(log_lines), 500))
    sess = REGISTRY.find(case_id)
    if sess is None:
        runs = []
        jdir = case.dir / "jtag"
        if jdir.exists():
            for sf in sorted(jdir.glob("openocd-*.json")):
                doc = read_json(sf) or {}
                if doc.get("transport") == "windows-pipe":
                    runs.append({"state_file": case.rel(sf), "transport": "windows-pipe", "tcl_port": None,
                                 "state": "previous_owner_unverified", "still_running": None,
                                 "cleanup_confirmed_at_stop": doc.get("cleanup_confirmed") is True,
                                 "started_at": doc.get("started_at"), "stopped_at": doc.get("stopped_at")})
                    continue
                pid = doc.get("pid")
                runs.append(
                    {
                        "state_file": case.rel(sf),
                        "tcl_port": doc.get("tcl_port"),
                        "pid": pid,
                        "started_at": doc.get("started_at"),
                        "stopped_at": doc.get("stopped_at"),
                        "still_running": bool(isinstance(pid, int) and doc.get("stopped_at") is None and process.pid_alive(pid)),
                        "log": doc.get("log"),
                    }
                )
        hint = None
        if any(x["still_running"] for x in runs):
            hint = "이 케이스에서 띄운 OpenOCD 가 아직 실행 중입니다 — openocd_attach(tcl_port=...) 로 다시 연결(입양)할 수 있습니다."
        return {"ok": True, "active": False, "message": "OpenOCD 세션 없음 (openocd_start 또는 openocd_attach)", "previous_runs": runs, "hint": hint}
    out: dict[str, Any] = {"ok": True, "active": True, **sess.describe()}
    if sess.windows:
        out["semihosting"] = dict(sess.semihosting)
        out["active_jobs"] = []
        if sess.startup:
            out.update(startup=sess.startup.get("summary"), diagnosis=sess.startup.get("diagnosis"),
                       health=sess.startup.get("health"))
        out["diagnostics"] = sess.windows_owner.diagnostics() if sess.windows_owner else {}
        if sess.log_path:
            out["log_path"] = case.rel(sess.log_path)
        if not (sess.starting or sess.closing or sess.cleanup_pending) and sess.client and sess.client.connected:
            if sess.semihosting_managed:
                out.update(await _semihosting_live(sess))
                out["semihosting"] = dict(sess.semihosting)
            targets = None if sess.closing else await _query_targets(case_id, sess, ctx, timeout=5.0)
            out["targets"] = targets
            out["target_state"] = _target_state(targets)
        return out
    if sess.startup:
        out["startup"] = sess.startup.get("summary")
        out["startup_diagnosis"] = sess.startup.get("diagnosis")
        if sess.startup.get("semihosting") is not None:
            out["semihosting"] = sess.startup["semihosting"]
    if sess.semihosting_managed and not sess.process_exited() and sess.semihosting_failsafe is None:
        # 가드의 읽기 전용 status 로 지금 상태를 본다 (위반이 보이면 그 자리에서 다시 무력화 — 끄지 못하면 fail closed)
        out.update(await _semihosting_live(sess))
    if sess.semihosting_managed:
        # 시작 때 보고가 아니라 세션의 최신 상태: 마지막 확인 결과(last_check), 다시 무력화한 기록, 정책, 시작 보고(startup)
        out["semihosting"] = {**sess.semihosting, "policy": sess.semihosting_policy, "check_pending": sess.semihosting_check_pending,
                              **({"startup": sess.startup["semihosting"]} if sess.startup.get("semihosting") is not None else {})}
    if sess.semihosting_failsafe is not None:
        out["semihosting_failsafe"] = sess.semihosting_failsafe
    text = process.read_log_tail_text(sess.log_path)
    if text:
        summary = parsers.parse_log_summary(text)
        out["recent_errors"] = summary["errors"][-20:]
        out["recent_warnings"] = summary["warnings"][-20:]
        out["diagnosis"] = parsers.diagnose(text)
    out["log_tail"] = process.tail_lines(sess.log_path, log_lines) if sess.log_path else []
    out["active_jobs"] = _active_jobs(case_id)
    if sess.semihosting_failsafe is not None:
        out["alive"] = False
        out["message"] = "semihosting 을 끄지(확인하지) 못해 서버가 OpenOCD 를 종료했습니다 (fail closed). 사람에게 알리고 openocd_stop 으로 정리하세요."
        return out
    if sess.process_exited():
        out["alive"] = False
        out["message"] = "OpenOCD 프로세스가 종료되었습니다. openocd_stop 으로 세션을 정리한 뒤 다시 시작하세요."
        return out
    out["alive"] = True
    tgts = await _query_targets(case_id, sess, ctx, timeout=5.0)
    if tgts is None:
        out["live_error"] = "targets 조회 실패 (OpenOCD 가 긴 명령을 처리 중이거나 연결 문제)"
    else:
        out["targets"] = tgts
        out["target_state"] = _target_state(tgts)
    return out


async def _semihosting_live(sess: OcdSession) -> dict[str, Any]:
    """openocd_status 용: 가드의 읽기 전용 ``status`` 로 지금 상태를 본다. 확인이 밀려 있거나(pending) policy 가 disabled 인데 켜진 타깃·
    감싸지 않은 관련 핸들러가 보이면 그 자리에서 다시 무력화한다(끄지 못하면 fail closed)."""
    if sess.semihosting_check_pending:
        res = await _semihosting_enforce(sess, trigger="openocd_status")
        return {"semihosting_live": res, **_semihosting_fields(res)}
    try:
        if sess.windows:
            reply = await windows_start.call_session(sess, semihosting.STATUS_CALL, timeout=10.0, internal=True)
        else:
            reply = await run_blocking(sess.client.call, semihosting.STATUS_CALL, timeout=10.0)
    except PwehError as exc:
        return {"semihosting_live": {"status": "unavailable", "error": str(exc)}}
    if not reply.ok:
        res = await _semihosting_enforce(sess, trigger="openocd_status")  # 가드 호출 실패 → 확인 단계에서 판정(fail closed)
        return {"semihosting_live": res, **_semihosting_fields(res)}
    report = semihosting.parse_report(reply.output, required=("status",), startup_only=False)
    live = {"status": "reported", "targets": report["targets"], "unwrapped": report["unwrapped"],
            "problems": semihosting.verification_problems(report, ("status",))}
    violated = sess.semihosting_policy == "disabled" and (
        any(v == "enabled" for v in report["targets"].values()) or report["unwrapped"] or live["problems"]
        or (sess.windows and bool(report["targets"])))
    if violated:
        res = await _semihosting_enforce(sess, trigger="openocd_status")
        return {"semihosting_live": live, **_semihosting_fields(res)}
    return {"semihosting_live": live}


# ---------------------------------------------------------------------------
# 원시 명령
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "원시 OpenOCD Tcl 명령 실행. 명령 텍스트 전체를 위험도 분류(코어 classify_openocd + 엄격한 로컬 규칙)한 뒤 게이트를 "
        "통과해야 실행된다: 조회(scan_chain, targets, mdw, read_memory, flash banks/info …)=허용, halt/reset/resume 등=MODIFY, "
        "mww/write_memory/flash write·erase/program/OTP·eFuse·옵션바이트 등=DESTRUCTIVE(기본 거부), dump_image/flash read_bank(호스트 "
        "파일 쓰기)=거부(→ openocd_dump_memory_start / openocd_flash_read_start 사용). 응답: output(capture 된 로그+결과), "
        "실패면 ok=false, status='tcl_error', error, diagnosis. 긴 출력은 jtag/command-output-*.txt 로 저장된다. "
        "Windows dummy는 version/targets/scan_chain/jtag names/adapter name의 정확한 단일 조회만 허용한다."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def openocd_command(
    case_id: str, command: str, ctx: Context, approval_id: str | None = None, timeout: float = DEFAULT_TIMEOUT, max_output_chars: int = 20000
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id, hardware=True)
    sess = _session(case_id)
    if sess.windows:
        windows_start.require_query(command, sess)
    if not isinstance(command, str) or not command.strip():
        raise ValidationFailed("command 가 비었습니다")
    if len(command) > 65536:
        raise ValidationFailed("command 가 너무 깁니다 (최대 64 KiB)")
    if "\x1a" in command or "\x00" in command:
        raise ValidationFailed("command 에 0x1a/NUL 문자를 넣을 수 없습니다")
    if not braces_balanced(command):
        raise ValidationFailed("중괄호 짝이 맞지 않거나 백슬래시로 끝납니다", hint="Tcl 중괄호 { } 의 짝을 맞추세요.")
    timeout = max(1.0, min(float(timeout), 600.0))
    cls = _classify(command, sess)
    if cls.risk >= Risk.MODIFY:
        _ensure_no_job(case_id, "MODIFY 이상 명령")
    decision = await r.authorize(tool="openocd_command", action={"command": command, **windows_start.action_fields(sess)}, classification=cls, case_id=case_id, approval_id=approval_id, ctx=ctx)
    if not decision.allowed:
        return gate_response(decision)
    check = _semihosting_wanted(cls)
    # 사람이 승인한(또는 운영자 정책이 허용한) DESTRUCTIVE 명령이 semihosting 을 켜고 성공하면 → 이 세션은 끄지 않고 상태만 보고
    # (openocd_stop 까지). 실패하면 그대로 끄기 정책으로 확인한다.
    approved_enable = (check and sess.semihosting_managed and cls.risk >= Risk.DESTRUCTIVE and sess.semihosting_policy == "disabled"
                       and guard.semihosting_intent(command, semihost_procs=sess.semihost_procs))

    def on_reply(rp: TclReply) -> None:
        if approved_enable and rp.ok:
            sess.semihosting_policy = "enabled-by-approval"
            sess.semihosting["policy"] = sess.semihosting_policy
            r.audit({"event": "openocd_semihosting_enabled_by_approval", "command": command, "approval_id": approval_id}, case_id)

    t0 = time.monotonic()
    reply, sh = await _call_checked(sess, command, timeout=timeout, raw=True, check=check, trigger="openocd_command", on_reply=on_reply)
    dt = round(time.monotonic() - t0, 3)
    out: dict[str, Any] = {"classification": cls.to_dict(), "duration_seconds": dt, "code": reply.code, **_semihosting_fields(sh)}
    if sess.semihosting_policy != "disabled":
        out["semihosting_policy"] = sess.semihosting_policy
    output = reply.output
    max_output_chars = max(1000, min(int(max_output_chars), 1_000_000))
    if len(output) > max_output_chars:
        jdir = case.subdir("jtag")
        n = _next_index(jdir, "command-output-", ".txt")
        p = jdir / f"command-output-{n}.txt"
        atomic_write_text(p, f"# {command}\n{output}")
        out["output_truncated"] = True
        out["output_path"] = case.rel(p)
        output = output[:max_output_chars]
    out["output"] = output
    if reply.closed:
        out["connection_closed"] = True
        if sess.process_exited():
            out["process"] = sess.process_info()
            out["note"] = "명령 후 OpenOCD 프로세스가 종료되었습니다 (shutdown 이었거나 비정상 종료)."
    if sh is not None and sh.get("status") == "failsafe":
        return _failsafe_response(sh, **{k: v for k, v in out.items() if not k.startswith("semihosting_")}, command=command)
    if reply.code is None and not reply.closed:
        return {"ok": False, "status": "unparsed", **out, "notes": reply.notes}
    if reply.closed:
        return {"ok": True, "status": "closed", **out}
    if not reply.ok:
        err = reply.output or "(OpenOCD 가 오류 메시지 없이 실패)"
        return {"ok": False, "status": "tcl_error", "error": err, "diagnosis": parsers.diagnose(err), **out}
    return {"ok": True, "status": "ok", **out}


# ---------------------------------------------------------------------------
# 조회
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "JTAG 스캔체인 TAP 목록 (scan_chain 파싱): tap_name, enabled, idcode, expected(목록), irlen, ircap, irmask, mismatch, "
        "decoded(제조사 코드/이름, part, version, 유효성). IDCODE 가 0x00000000/0xffffffff 면 배선·전원 문제 힌트를 준다."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
async def openocd_scan_chain(case_id: str, ctx: Context) -> dict[str, Any]:
    rt().case(case_id, hardware=True)
    sess = _session(case_id)
    decision, _ = await _authorize(case_id, "openocd_scan_chain", ["scan_chain"], ctx=ctx)
    if not decision.allowed:
        return gate_response(decision)
    reply = await _call(sess, "scan_chain", timeout=15.0)
    if not reply.ok:
        return _reply_error(reply, command="scan_chain")
    taps = _enrich_taps(parsers.parse_scan_chain(reply.output), (sess.startup or {}).get("summary"))
    hints = []
    if not taps:
        hints.append("정의된 TAP 이 없습니다. target cfg 없이 시작하면 OpenOCD 가 체인을 자동 탐색(auto0.tap …)하고 로그에 AUTO 힌트를 남깁니다.")
    elif all(not t["decoded"]["valid"] for t in taps):
        hints.append("유효한 IDCODE 가 없습니다 — 배선(TDO/TDI 뒤바뀜, GND), 타깃 전원, VREF, JTAG 비활성(퓨즈/핀 먹스)을 확인하세요.")
    if any(t.get("mismatch") for t in taps):
        hints.append("IDCODE 가 cfg 의 expected 와 다른 TAP 이 있습니다 — 다른 칩용 cfg 일 수 있습니다.")
    if sess.windows:
        hints = ["고정 dummy TAP 조회이며 실제 체인·배선·IDCODE 검증은 수행하지 않았습니다."]
    return {"ok": True, "count": len(taps), "taps": taps, "hints": hints, "raw": reply.output}


@server.tool(
    description="타깃 목록 (targets 파싱): index, current(*), name, type(arm926ejs/cortex_a/mips_m4k/mem_ap…), endian, tap_name, state(running/halted/reset/unknown/examine deferred/tap-disabled).",
    annotations=ANN_READ_ONLY,
)
@safe_tool
async def openocd_targets(case_id: str, ctx: Context) -> dict[str, Any]:
    rt().case(case_id, hardware=True)
    sess = _session(case_id)
    decision, _ = await _authorize(case_id, "openocd_targets", ["targets"], ctx=ctx)
    if not decision.allowed:
        return gate_response(decision)
    reply = await _call(sess, "targets", timeout=10.0)
    if not reply.ok:
        return _reply_error(reply, command="targets")
    rows = parsers.parse_targets(reply.output)
    sess.last_targets = rows
    cur = parsers.current_target(rows)
    return {"ok": True, "count": len(rows), "targets": rows, "current": cur["name"] if cur else None, "raw": reply.output}


# ---------------------------------------------------------------------------
# 실행 제어 (MODIFY)
# ---------------------------------------------------------------------------


async def _modify_and_report(case_id: str, tool: str, cmd: str, *, ctx: Any, approval_id: str | None, timeout: float, target: str | None = None) -> dict[str, Any]:
    rt().case(case_id, hardware=True)
    sess = _session(case_id)
    if sess.windows:
        raise windows_start.unsupported()
    _ensure_no_job(case_id, tool)
    decision, cls = await _authorize(case_id, tool, [cmd], ctx=ctx, approval_id=approval_id)
    if not decision.allowed:
        return gate_response(decision)
    # halt/resume/reset 은 이벤트 핸들러(reset-*, examine-end, halted …)를 실행한다 → 뒤에 semihosting 을 다시 확인
    reply, sh = await _call_checked(sess, cmd, timeout=timeout, check=True, trigger=tool)
    if sh is not None and sh.get("status") == "failsafe":
        return _failsafe_response(sh, command=cmd, messages=reply.log, classification=cls.to_dict())
    tgts = await _query_targets(case_id, sess, ctx)
    base = {"command": cmd, "messages": reply.log, "targets": tgts, "state": _target_state(tgts, target), "classification": cls.to_dict(),
            **_semihosting_fields(sh)}
    if not reply.ok:
        return {**_reply_error(reply, command=cmd), **base}
    return {"ok": True, "status": "ok", **base}


@server.tool(
    description="타깃 CPU 정지 (halt, MODIFY). target 을 주면 그 타깃을 현재 타깃으로 바꾼 뒤 정지한다. messages 에 'target halted …, pc: …' 같은 OpenOCD 메시지, state 에 정지 후 상태.",
    annotations=ANN_DEVICE,
)
@safe_tool
async def openocd_halt(case_id: str, ctx: Context, target: str | None = None, approval_id: str | None = None, timeout: float = 15.0) -> dict[str, Any]:
    target = _check_ident(target, "target")
    cmd = f"targets {target}; halt" if target else "halt"
    return await _modify_and_report(case_id, "openocd_halt", cmd, ctx=ctx, approval_id=approval_id, timeout=max(2.0, min(float(timeout), 120.0)), target=target)


@server.tool(
    description="타깃 CPU 실행 재개 (resume, MODIFY). address 를 주면 그 주소에서 실행. 실제 기기의 펌웨어가 다시 돌기 시작하므로 덤프/분석 중에는 주의.",
    annotations=ANN_DEVICE,
)
@safe_tool
async def openocd_resume(case_id: str, ctx: Context, address: int | str | None = None, target: str | None = None, approval_id: str | None = None) -> dict[str, Any]:
    target = _check_ident(target, "target")
    cmd = "resume" if address is None else f"resume 0x{_parse_int(address, 'address'):x}"
    if target:
        cmd = f"targets {target}; {cmd}"
    return await _modify_and_report(case_id, "openocd_resume", cmd, ctx=ctx, approval_id=approval_id, timeout=15.0, target=target)


@server.tool(
    description="타깃 리셋 (MODIFY). mode: halt(리셋 직후 정지 — 부트 초기에 붙을 때), run(정상 부팅), init(reset-init 이벤트 스크립트 실행 후 정지). 리셋 라인(SRST)이 없으면 cfg 의 reset_config 에 따라 동작이 다르다.",
    annotations=ANN_DEVICE,
)
@safe_tool
async def openocd_reset(case_id: str, ctx: Context, mode: str = "halt", approval_id: str | None = None, timeout: float = 30.0) -> dict[str, Any]:
    mode = str(mode).strip().lower()
    if mode not in ("halt", "run", "init"):
        raise ValidationFailed(f"잘못된 mode: {mode!r}", hint="halt | run | init")
    return await _modify_and_report(case_id, "openocd_reset", f"reset {mode}", ctx=ctx, approval_id=approval_id, timeout=max(5.0, min(float(timeout), 180.0)))


# ---------------------------------------------------------------------------
# 레지스터 / 메모리 읽기
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "레지스터 읽기 ('reg' 파싱). names 를 주면 'reg <name>' 으로 개별 조회(값을 타깃에서 읽음). names 가 없으면 전체 목록을 "
        "읽고, 타깃이 halted 이고 refresh=true 면 캐시 값이 없는 첫 레지스터 그룹(코어 레지스터)을 개별 조회로 채운다. "
        "실행 중(running)인 타깃은 값이 없을 수 있으니 openocd_halt 먼저. 결과는 jtag/registers-<n>.json 으로 저장·등록된다."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
async def openocd_read_registers(
    case_id: str, ctx: Context, names: list[str] | None = None, target: str | None = None, refresh: bool = True, max_refresh: int = 64, save: bool = True
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id, hardware=True)
    sess = _session(case_id)
    if sess.windows:
        raise windows_start.unsupported()
    target = _check_ident(target, "target")
    prefix = f"targets {target}; " if target else ""
    notes: list[str] = []
    regs: list[dict[str, Any]] = []
    if names:
        clean = []
        for nm in names:
            if not isinstance(nm, str) or not REG_NAME_RE.match(nm.strip()):
                raise ValidationFailed(f"잘못된 레지스터 이름: {nm!r}")
            clean.append(nm.strip())
        cmds = [f"{prefix}reg {nm}" for nm in clean[:256]]
        decision, _ = await _authorize(case_id, "openocd_read_registers", cmds, ctx=ctx)
        if not decision.allowed:
            return gate_response(decision)
        for nm, cmd in zip(clean, cmds):
            rep = await _call(sess, cmd, timeout=10.0)
            one = parsers.parse_reg_single(rep.output) if rep.ok else None
            if one:
                regs.append({"name": one["name"], "bits": one["bits"], "value": one["value"]})
            else:
                regs.append({"name": nm, "value": None, "error": rep.error_text or rep.output})
    else:
        cmd = f"{prefix}reg"
        decision, _ = await _authorize(case_id, "openocd_read_registers", [cmd], ctx=ctx)
        if not decision.allowed:
            return gate_response(decision)
        rep = await _call(sess, cmd, timeout=15.0)
        if not rep.ok:
            return _reply_error(rep, command=cmd)
        regs = parsers.parse_reg_list(rep.output)
        if not regs:
            notes.append("레지스터 목록이 비었습니다 (레지스터 캐시가 없는 타깃 유형이거나 아직 examine 되지 않음).")
    tgts = await _query_targets(case_id, sess, ctx)
    state = _target_state(tgts, target)
    if not names and refresh and regs:
        first_cache = regs[0].get("cache")
        missing = [x for x in regs if x.get("value") is None and x.get("cache") == first_cache][: max(0, min(int(max_refresh), 256))]
        if missing and state == "halted":
            cmds = [f"{prefix}reg {x['name']}" for x in missing if REG_NAME_RE.match(x["name"])]
            decision, _ = await _authorize(case_id, "openocd_read_registers", cmds, ctx=ctx)
            if decision.allowed:
                by_name = {x["name"]: x for x in regs}
                for c in cmds:
                    rep = await _call(sess, c, timeout=10.0)
                    one = parsers.parse_reg_single(rep.output) if rep.ok else None
                    if one and one["name"] in by_name:
                        by_name[one["name"]]["value"] = one["value"]
        elif missing:
            notes.append(f"타깃 상태가 '{state}' 라 캐시 없는 레지스터 {len(missing)}개는 값을 읽지 않았습니다 (openocd_halt 후 다시 호출).")
    result: dict[str, Any] = {"ok": True, "count": len(regs), "registers": regs, "target_state": state, "notes": notes}
    if save and regs:
        jdir = case.subdir("jtag")
        n = _next_index(jdir, "registers-", ".json")
        p = jdir / f"registers-{n}.json"
        atomic_write_json(p, {"schema": "pweh.openocd-registers/v1", "case_id": case_id, "captured_at": utcnow_iso(), "target": target,
                              "target_state": state, "registers": regs})
        art = case.register_artifact(p, kind="jtag-dump", producer=SERVER_NAME, description="OpenOCD 레지스터 스냅샷")
        result["snapshot_path"] = case.rel(p)
        result["artifact"] = art
    return result


@server.tool(
    description=(
        "작은 메모리 범위 읽기 (read_memory; 0.11 은 md* 로 대체). width: 8|16|32|64, count*width/8 ≤ 4096 바이트 (큰 범위는 "
        "openocd_dump_memory_start). 값은 타깃 엔디언 정수(values), bytes_hex/hexdump 는 메모리 순서 바이트. target 을 주면 그 "
        "타깃으로 읽는다(예: Cortex-A SoC 의 mem_ap 타깃은 CPU 를 멈추지 않고 읽을 수 있음). MMIO 레지스터는 읽기만으로도 부작용이 "
        "있을 수 있으니 RAM/플래시 창 위주로 읽는다."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
async def openocd_read_memory(
    case_id: str, address: int | str, count: int, ctx: Context, width: int = 32, target: str | None = None, phys: bool = False
) -> dict[str, Any]:
    rt().case(case_id, hardware=True)
    sess = _session(case_id)
    if sess.windows:
        raise windows_start.unsupported()
    addr = _parse_int(address, "address", maximum=0xFFFFFFFFFFFFFFFF)
    width = _parse_int(width, "width")
    if width not in (8, 16, 32, 64):
        raise ValidationFailed("width 는 8, 16, 32, 64 중 하나여야 합니다")
    count = _parse_int(count, "count", minimum=1)
    wb = width // 8
    if count * wb > MAX_READ_BYTES:
        raise ValidationFailed(f"한 번에 {MAX_READ_BYTES} 바이트까지만 읽습니다 (요청 {count * wb})", hint="큰 범위는 openocd_dump_memory_start(job)를 쓰세요.")
    if addr + count * wb - 1 > 0xFFFFFFFFFFFFFFFF:
        raise ValidationFailed("주소 범위가 64비트를 넘습니다")
    target = _check_ident(target, "target")
    trusted = await _trusted_target(case_id, sess, target, ctx=ctx, tool="openocd_read_memory")
    prefix = f"{target} " if target else ""
    cmd = f"{prefix}read_memory 0x{addr:x} {width} {count}" + (" phys" if phys else "")
    decision, _ = await _authorize(case_id, "openocd_read_memory", [cmd], ctx=ctx, classification=_classify_read(cmd, trusted))
    if not decision.allowed:
        return gate_response(decision)
    rep = await _call(sess, cmd, timeout=30.0)
    method = "read_memory"
    values: list[int] | None = None
    if not rep.ok and "invalid command name" in rep.error_text and "read_memory" in rep.error_text:
        md = {8: "mdb", 16: "mdh", 32: "mdw", 64: "mdd"}[width]
        cmd2 = f"{prefix}{md} {'phys ' if phys else ''}0x{addr:x} {count}"
        decision, _ = await _authorize(case_id, "openocd_read_memory", [cmd2], ctx=ctx, classification=_classify_read(cmd2, trusted))
        if not decision.allowed:
            return gate_response(decision)
        rep = await _call(sess, cmd2, timeout=30.0)
        method, cmd = md, cmd2
        if rep.ok:
            values = [v for _, v in parsers.parse_md(rep.output)]
    if not rep.ok:
        return _reply_error(rep, command=cmd)
    if values is None:
        values, perr = parsers.parse_read_memory(rep.output)
        if perr:
            return {"ok": False, "status": "parse_error", "command": cmd, "error": perr, "raw": rep.output[:2000]}
    if len(values) != count:
        return {"ok": False, "status": "parse_error", "command": cmd, "error": f"값 개수 불일치 {len(values)}/{count}", "raw": rep.output[:2000]}
    rows = await _query_targets(case_id, sess, ctx) or sess.last_targets or []
    endian = _endian(rows, target)
    data = parsers.values_to_bytes(values, wb, endian)
    return {
        "ok": True,
        "address": f"0x{addr:x}",
        "width": width,
        "count": count,
        "method": method,
        "endian": endian,
        "values": [f"0x{v:0{wb * 2}x}" for v in values],
        "bytes_hex": data.hex(),
        "hexdump": _hexdump(data, addr),
    }


# ---------------------------------------------------------------------------
# 덤프 작업
# ---------------------------------------------------------------------------


def _start_dump_job(spec: dumps.DumpSpec, sess: OcdSession, *, description: str, kind: str) -> Any:
    r = rt()
    case_id = spec.case.id
    unknown = _unknown_risk()
    borrowed_pipe = sess.windows
    handoff = LeaseHandoff() if borrowed_pipe else None
    borrowed_client = None
    if borrowed_pipe:
        # 공개 Windows 입구는 계속 거부한다. 내부 연결은 read_memory 한 방법만 다룬다.
        if spec.kind != "memory" or spec.method != "read_memory" or type(sess.client) is not TclPipeClient:
            raise DeviceError("내부 pipe 작업은 read_memory 메모리 덤프만 지원합니다.", code="openocd_pipe_job_unsupported")
        if sess.cleanup_pending:
            raise Busy("Windows OpenOCD 세션이 정리 중입니다.")
        if not sess.client.connected:
            raise DeviceError("OpenOCD pipe RPC가 종료 상태입니다.", code="openocd_pipe_terminal")
        borrowed_client = sess.client
        sess.reserve_use()

    def fn(jctx):
        if handoff is not None and not handoff.claim_worker():
            raise JobCancelled()
        client = None
        try:
            jctx.check_cancelled()
            if borrowed_pipe and sess.closing:
                raise JobCancelled()
            client = borrowed_client if borrowed_pipe else sess.new_client(name=f"{case_id}-{jctx.job.id}")
            runner = dumps.DumpRunner(
                spec, jctx, client, unknown_risk=unknown,
                process_alive=lambda: not sess.died_after_disconnect(),
                audit=lambda ev: r.audit(ev, case_id),
                borrowed_pipe=borrowed_pipe,
            )
            return runner.run()
        finally:
            if borrowed_pipe:
                sess.finish_use()
            elif client is not None:
                client.close()

    try:
        return r.jobs.start(
            kind, fn, description=description, case_id=case_id,
            meta={"output": spec.case.rel(spec.final), "resume_from": spec.start_offset, "length": spec.length},
            exclusive_key=f"openocd:{case_id}",
        )
    except BaseException:
        # 시작 예외가 실제 worker 실행 뒤에 와도 caller가 사용권을 중복 반환하지 않는다.
        if handoff is not None and handoff.abandon_caller():
            sess.finish_use()
        raise


@server.tool(
    description=(
        "메모리 덤프 백그라운드 작업 시작 → job_id. 청크(chunk_size, 기본 64KiB)마다 dump_image 를 케이스 경로로만 실행해 "
        "jtag/<name>.part 에 이어 붙이고 .state.json 으로 재개 가능 (같은 output_name 으로 다시 호출하면 이어받음). OpenOCD 가 "
        "쓴 파일이 보이지 않으면(원격 OpenOCD) read_memory 방식으로 자동 전환. verify=true 면 청크마다 두 번 읽어 비교(시간 2배, "
        "신호 품질이 의심될 때). 완료 시 jtag/<name>.bin + <name>.json(메타데이터) + sha256 + 아티팩트 등록. kind='flash-dump' "
        "이면(메모리 맵 플래시 창을 읽는 경우) dumps/ 에 저장. 대부분의 코어는 먼저 openocd_halt 가 필요하다. "
        "진행 확인: openocd_job_status(job_id, wait_seconds=30)."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def openocd_dump_memory_start(
    case_id: str,
    address: int | str,
    length: int | str,
    ctx: Context,
    output_name: str | None = None,
    chunk_size: int | str = 65536,
    target: str | None = None,
    method: str = "auto",
    verify: bool = False,
    resume: bool = True,
    kind: str = "memory-dump",
    retries: int = 2,
    chunk_timeout_s: float | None = None,
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id, hardware=True)
    sess = _session(case_id)
    if sess.windows:
        raise windows_start.unsupported()
    _ensure_no_job(case_id, "새 덤프 작업 시작")  # RPC 를 보내기 전에 확인 (작업 중인 OpenOCD 를 기다리지 않도록)
    addr = _parse_int(address, "address", maximum=0xFFFFFFFFFFFFFFFF)
    length_i = _parse_int(length, "length", minimum=1, maximum=4 * 1024 * 1024 * 1024, size=True)
    chunk = _parse_int(chunk_size, "chunk_size", minimum=dumps.MIN_CHUNK, maximum=dumps.MAX_CHUNK, size=True)
    method = str(method).strip().lower()
    if method not in ("auto", "dump_image", "read_memory"):
        raise ValidationFailed("method 는 auto | dump_image | read_memory")
    if kind not in ("memory-dump", "flash-dump", "jtag-dump"):
        raise ValidationFailed("kind 는 memory-dump | flash-dump | jtag-dump")
    target = _check_ident(target, "target")
    remote = sess.host not in LOOPBACK
    if remote and method == "dump_image":
        raise ValidationFailed("원격 OpenOCD 에서는 dump_image 결과 파일을 읽을 수 없습니다", hint="method='read_memory' 또는 'auto' 를 쓰세요.")
    name = dumps.sanitize_name(output_name or f"mem-{addr:08x}-{length_i:x}")
    out_dir = case.subdir("dumps" if kind == "flash-dump" else "jtag")
    rows = await _query_targets(case_id, sess, ctx) or sess.last_targets or []
    # 점 없는 타깃의 '<타깃> read_memory …' 는 실제 목록에서 확인한 이름일 때만 작업 안에서 접두를 떼고 분류된다
    trusted = await _trusted_target(case_id, sess, target, ctx=ctx, tool="openocd_dump_memory_start")
    if target and rows and not parsers.current_target(rows, target):
        raise ValidationFailed(f"타깃 '{target}' 이 없습니다", hint=f"사용 가능: {', '.join(x['name'] for x in rows)}")
    spec = dumps.DumpSpec(
        kind="memory", case=case, out_dir=out_dir, name=name, length=length_i, chunk_size=chunk, address=addr, target=target,
        method=method, verify=bool(verify), retries=max(0, min(int(retries), 10)),
        chunk_timeout=float(chunk_timeout_s) if chunk_timeout_s else None, artifact_kind=kind, endian=_endian(rows, target),
        resume=bool(resume), remote=remote,
        openocd={"version": (sess.version or {}).get("raw"), "host": sess.host, "tcl_port": sess.port},
        trusted_targets=trusted,
    )
    _ensure_no_job(case_id, "새 덤프 작업 시작")  # prepare() 가 .part 를 지울 수 있으므로 먼저 확인
    dumps.prepare(spec)
    planned = dumps.planned_commands(spec)
    cls_list = guard.ensure_job_commands_safe(planned, allowed_dirs=[out_dir], unknown_risk=_unknown_risk(), trusted_targets=trusted)
    cls = worst(cls_list)
    decision = await r.authorize(
        tool="openocd_dump_memory_start",
        action={"address": f"0x{addr:x}", "length": length_i, "output": case.rel(spec.final), "target": target, "method": method, "verify": bool(verify)},
        classification=cls, case_id=case_id, ctx=ctx,
    )
    if not decision.allowed:
        return gate_response(decision)
    job = _start_dump_job(spec, sess, description=f"메모리 덤프 0x{addr:x} +{length_i} → {case.rel(spec.final)}", kind="openocd-dump-memory")
    r.audit({"event": "openocd_job_started", "job_id": job.id, "kind": "dump-memory", "planned": planned[:3]}, case_id)
    return {
        "ok": True,
        "job_id": job.id,
        "output": case.rel(spec.final),
        "resume_from": spec.start_offset,
        "length": length_i,
        "chunk_size": chunk,
        "classification": cls.to_dict(),
        "poll": f"openocd_job_status(job_id='{job.id}', wait_seconds=30)",
    }


@server.tool(
    description=(
        "플래시 뱅크 목록 (flash banks 파싱 + flash list 의 타깃 정보): bank, name, driver, base, size, bus/chip width. "
        "probe=true 면 각 뱅크를 flash probe 후 다시 조회(크기가 0 인 SPI 뱅크), info=true 면 flash info 로 섹터/보호 상태까지. "
        "카메라 SoC(HiSilicon/Ingenic/SigmaStar)의 SPI NOR 컨트롤러는 OpenOCD 드라이버가 없어 뱅크가 비어 있는 경우가 많다."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
async def openocd_flash_banks(case_id: str, ctx: Context, probe: bool = False, info: bool = False) -> dict[str, Any]:
    rt().case(case_id, hardware=True)
    sess = _session(case_id)
    if sess.windows:
        raise windows_start.unsupported()
    decision, _ = await _authorize(case_id, "openocd_flash_banks", ["flash banks"], ctx=ctx)
    if not decision.allowed:
        return gate_response(decision)
    rep = await _call(sess, "flash banks", timeout=15.0)
    if not rep.ok:
        return _reply_error(rep, command="flash banks")
    banks = parsers.parse_flash_banks(rep.output)
    notes: list[str] = []
    if probe and banks:
        cmds = [f"flash probe {b['bank']}" for b in banks]
        decision, _ = await _authorize(case_id, "openocd_flash_banks", cmds, ctx=ctx)
        if decision.allowed:
            for b, c in zip(banks, cmds):
                pr = await _call(sess, c, timeout=60.0)
                b["probe"] = {"ok": pr.ok, "output": pr.output or pr.error_text}
            rep2 = await _call(sess, "flash banks", timeout=15.0)
            if rep2.ok:
                probed = {b["bank"]: b.get("probe") for b in banks}
                banks = parsers.parse_flash_banks(rep2.output)
                for b in banks:
                    if b["bank"] in probed:
                        b["probe"] = probed[b["bank"]]
    # flash list: 타깃 이름 등 보조 정보 (실패해도 무시)
    d2, _ = await _authorize(case_id, "openocd_flash_banks", ["flash list"], ctx=ctx)
    if d2.allowed and banks:
        try:
            lr = await _call(sess, "flash list", timeout=10.0)
            if lr.ok:
                lst = parsers.parse_flash_list(lr.output)
                for b, extra in zip(banks, lst):
                    if extra.get("target"):
                        b["target"] = extra["target"]
        except PwehError:
            pass
    if info and banks:
        cmds = [f"flash info {b['bank']}" for b in banks]
        decision, _ = await _authorize(case_id, "openocd_flash_banks", cmds, ctx=ctx)
        if decision.allowed:
            for b, c in zip(banks, cmds):
                ir = await _call(sess, c, timeout=60.0)
                b["info"] = parsers.parse_flash_info(ir.output) if ir.ok else {"error": ir.error_text}
    if not banks:
        notes.append("정의된 플래시 뱅크가 없습니다. 카메라 SoC 의 SPI NOR 는 OpenOCD 드라이버가 없는 경우가 많습니다 → U-Boot 에서 "
                     "'sf probe; sf read <RAM> <off> <len>' 로 RAM 에 올린 뒤 openocd_halt + openocd_dump_memory_start 로 RAM 을 덤프하세요.")
    elif any(b["size"] == 0 for b in banks):
        notes.append("크기가 0 인 뱅크가 있습니다 — probe=true 로 다시 조회하세요.")
    return {"ok": True, "count": len(banks), "banks": banks, "notes": notes, "raw": rep.output}


@server.tool(
    description=(
        "플래시 뱅크 읽기 백그라운드 작업 → job_id. 청크마다 'flash read_bank <bank> {dumps/.이름.chunk} offset len' 을 실행해 "
        "dumps/<name>.part 에 이어 붙이고(.state.json 으로 재개), 완료 시 dumps/<name>.bin + .json + sha256 + flash-dump 아티팩트. "
        "bank 는 번호 또는 이름, offset 은 뱅크 시작 기준, length 생략 시 끝까지. verify=true 면 청크마다 flash verify_bank 로 재확인. "
        "OpenOCD 가 로컬에서 실행 중이어야 한다(원격 attach 는 불가)."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def openocd_flash_read_start(
    case_id: str,
    bank: int | str,
    ctx: Context,
    offset: int | str = 0,
    length: int | str | None = None,
    output_name: str | None = None,
    chunk_size: int | str = 65536,
    verify: bool = False,
    resume: bool = True,
    retries: int = 2,
    chunk_timeout_s: float | None = None,
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id, hardware=True)
    sess = _session(case_id)
    if sess.windows:
        raise windows_start.unsupported()
    if sess.host not in LOOPBACK:
        raise ValidationFailed("원격 OpenOCD 에서는 flash read_bank 결과 파일을 읽을 수 없습니다",
                               hint="로컬에서 openocd_start 로 OpenOCD 를 실행하거나, 메모리 맵 플래시는 openocd_dump_memory_start(kind='flash-dump')를 쓰세요.")
    _ensure_no_job(case_id, "새 덤프 작업 시작")  # RPC 를 보내기 전에 확인
    bank_s = str(bank).strip()
    if not re.fullmatch(r"\d+|[A-Za-z_][A-Za-z0-9_.\-]{0,63}", bank_s):
        raise ValidationFailed(f"잘못된 bank: {bank!r}")
    off = _parse_int(offset, "offset", size=True)
    chunk = _parse_int(chunk_size, "chunk_size", minimum=dumps.MIN_CHUNK, maximum=dumps.MAX_CHUNK, size=True)
    icmd = f"flash info {bank_s}"
    decision, _ = await _authorize(case_id, "openocd_flash_read_start", [icmd, "flash banks"], ctx=ctx)
    if not decision.allowed:
        return gate_response(decision)
    irep = await _call(sess, icmd, timeout=60.0)
    finfo = parsers.parse_flash_info(irep.output) if irep.ok else None
    if not finfo:
        out = _reply_error(irep, command=icmd) if not irep.ok else {"ok": False, "status": "parse_error", "command": icmd, "raw": irep.output[:2000]}
        out["hint"] = "openocd_flash_banks 로 뱅크 번호/이름을 확인하세요."
        return out
    brep = await _call(sess, "flash banks", timeout=15.0)
    for b in parsers.parse_flash_banks(brep.output) if brep.ok else []:
        if str(b["bank"]) == bank_s or b["name"] == bank_s:
            finfo["name"] = b["name"]
            if not finfo.get("size"):
                finfo["size"] = b["size"]
    size = int(finfo.get("size") or 0)
    if size <= 0:
        return {"ok": False, "status": "bank_size_unknown", "flash_info": finfo, "hint": "뱅크 크기가 0 입니다. openocd_flash_banks(probe=true) 로 probe 를 확인하세요."}
    if off >= size:
        raise ValidationFailed(f"offset 0x{off:x} 이 뱅크 크기 0x{size:x} 이상입니다")
    length_i = size - off if length is None else _parse_int(length, "length", minimum=1, size=True)
    if off + length_i > size:
        raise ValidationFailed(f"offset+length(0x{off + length_i:x}) 가 뱅크 크기 0x{size:x} 를 넘습니다")
    label = finfo.get("name") or f"bank{bank_s}"
    name = dumps.sanitize_name(output_name or re.sub(r"[^A-Za-z0-9._-]", "-", f"flash-{label}-{off:x}-{length_i:x}"))
    out_dir = case.subdir("dumps")
    spec = dumps.DumpSpec(
        kind="flash", case=case, out_dir=out_dir, name=name, length=length_i, chunk_size=chunk, bank=bank_s, offset=off,
        flash_info=finfo | {"sectors": len(finfo.get("sectors") or [])}, verify=bool(verify), retries=max(0, min(int(retries), 10)),
        chunk_timeout=float(chunk_timeout_s) if chunk_timeout_s else None, artifact_kind="flash-dump", resume=bool(resume),
        openocd={"version": (sess.version or {}).get("raw"), "host": sess.host, "tcl_port": sess.port},
    )
    _ensure_no_job(case_id, "새 덤프 작업 시작")  # prepare() 가 .part 를 지울 수 있으므로 먼저 확인
    dumps.prepare(spec)
    planned = dumps.planned_commands(spec)
    cls = worst(guard.ensure_job_commands_safe(planned, allowed_dirs=[out_dir], unknown_risk=_unknown_risk()))
    decision = await r.authorize(
        tool="openocd_flash_read_start",
        action={"bank": bank_s, "offset": off, "length": length_i, "output": case.rel(spec.final), "verify": bool(verify)},
        classification=cls, case_id=case_id, ctx=ctx,
    )
    if not decision.allowed:
        return gate_response(decision)
    job = _start_dump_job(spec, sess, description=f"플래시 읽기 bank {bank_s} +0x{off:x} {length_i} 바이트 → {case.rel(spec.final)}", kind="openocd-flash-read")
    r.audit({"event": "openocd_job_started", "job_id": job.id, "kind": "flash-read", "planned": planned[:2]}, case_id)
    return {
        "ok": True,
        "job_id": job.id,
        "output": case.rel(spec.final),
        "flash": {k: finfo.get(k) for k in ("bank", "name", "driver", "base", "size")},
        "offset": off,
        "length": length_i,
        "resume_from": spec.start_offset,
        "classification": cls.to_dict(),
        "poll": f"openocd_job_status(job_id='{job.id}', wait_seconds=30)",
    }


# ---------------------------------------------------------------------------
# 쓰기 (DESTRUCTIVE — 기본 거부)
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "메모리 쓰기 (write_memory, DESTRUCTIVE — 기본 정책 거부). 임의 메모리/MMIO 쓰기는 플래시·eFuse·OTP 컨트롤러를 건드려 "
        "기기를 영구 손상시킬 수 있다. 정책이 approve 일 때만 사람 승인(pweh approve <id>) 후 같은 인자 + approval_id 로 1회 실행. "
        "values: 정수 또는 16진 문자열 목록(최대 1024개). verify=true 면 다시 읽어 비교."
    ),
    annotations=ANN_DESTRUCTIVE,
    meta=META_REQUIRE_HUMAN,
)
@safe_tool
async def openocd_write_memory(
    case_id: str, address: int | str, values: list[int | str], ctx: Context, width: int = 32, target: str | None = None, phys: bool = False,
    verify: bool = True, approval_id: str | None = None,
) -> dict[str, Any]:
    rt().case(case_id, hardware=True)
    sess = _session(case_id)
    if sess.windows:
        raise windows_start.unsupported()
    addr = _parse_int(address, "address", maximum=0xFFFFFFFFFFFFFFFF)
    width = _parse_int(width, "width")
    if width not in (8, 16, 32, 64):
        raise ValidationFailed("width 는 8, 16, 32, 64 중 하나여야 합니다")
    if not isinstance(values, list) or not (1 <= len(values) <= 1024):
        raise ValidationFailed("values 는 1~1024 개 목록이어야 합니다")
    maxv = (1 << width) - 1
    vals = [_parse_int(v, "values[]", maximum=maxv) for v in values]
    target = _check_ident(target, "target")
    prefix = f"{target} " if target else ""
    cmd = f"{prefix}write_memory 0x{addr:x} {width} {{{' '.join(f'0x{v:x}' for v in vals)}}}" + (" phys" if phys else "")
    _ensure_no_job(case_id, "메모리 쓰기")
    # 없는/명령 이름과 겹치는 타깃은 사람에게 승인을 묻기 전에 거부. 쓰기 자체의 분류(DESTRUCTIVE)는 그대로다.
    trusted = await _trusted_target(case_id, sess, target, ctx=ctx, tool="openocd_write_memory")
    decision, cls = await _authorize(case_id, "openocd_write_memory", [cmd], ctx=ctx, approval_id=approval_id)
    if not decision.allowed:
        return gate_response(decision)
    rep, sh = await _call_checked(sess, cmd, timeout=60.0, check=True, trigger="openocd_write_memory")
    if sh is not None and sh.get("status") == "failsafe":
        return _failsafe_response(sh, command=cmd, classification=cls.to_dict(), written=rep.ok)
    if not rep.ok:
        return {**_reply_error(rep, command=cmd), **_semihosting_fields(sh)}
    out: dict[str, Any] = {"ok": True, "status": "written", "address": f"0x{addr:x}", "width": width, "count": len(vals), "classification": cls.to_dict(),
                           **_semihosting_fields(sh)}
    if verify:
        rcmd = f"{prefix}read_memory 0x{addr:x} {width} {len(vals)}" + (" phys" if phys else "")
        d2, _ = await _authorize(case_id, "openocd_write_memory", [rcmd], ctx=ctx, classification=_classify_read(rcmd, trusted))
        if d2.allowed:
            rr = await _call(sess, rcmd, timeout=30.0)
            got, err = parsers.parse_read_memory(rr.output) if rr.ok else ([], rr.error_text)
            out["verified"] = (not err) and got == vals
            if not out["verified"]:
                out["readback"] = [f"0x{v:x}" for v in got]
                out["readback_error"] = err
    return out


@server.tool(
    description=(
        "플래시에 이미지 쓰기 (flash write_image [erase] [unlock] {파일} 주소 bin, DESTRUCTIVE — 기본 정책 거부). 기기를 벽돌로 "
        "만들 수 있다. path 는 케이스 디렉터리 안의 파일만 허용. 승인 지문에 파일 sha256 이 포함되어, 승인 후 파일이 바뀌면 실행되지 "
        "않는다. 정책이 approve 일 때만 사람 승인 후 approval_id 로 1회 실행. verify=true 면 verify_image 로 확인."
    ),
    annotations=ANN_DESTRUCTIVE,
    meta=META_REQUIRE_HUMAN,
)
@safe_tool
async def openocd_flash_write(
    case_id: str, path: str, address: int | str, ctx: Context, erase: bool = True, unlock: bool = False, verify: bool = True,
    approval_id: str | None = None, timeout: float = 600.0,
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id, hardware=True)
    sess = _session(case_id)
    if sess.windows:
        raise windows_start.unsupported()
    p = case.resolve_path(path)
    if not p.is_file() or p.stat().st_size == 0:
        raise NotFound(f"쓸 이미지 파일이 없거나 비었습니다: {p}")
    if sess.host not in LOOPBACK:
        raise ValidationFailed("원격 OpenOCD 는 이 서버의 케이스 파일을 읽을 수 없습니다")
    addr = _parse_int(address, "address", maximum=0xFFFFFFFFFFFFFFFF)
    try:
        qpath = brace_quote_path(str(p))
    except ValueError as exc:
        raise ValidationFailed(str(exc))
    opts = ("erase " if erase else "") + ("unlock " if unlock else "")
    cmd = f"flash write_image {opts}{qpath} 0x{addr:x} bin"
    sha = await run_blocking(sha256_file, p)
    size = p.stat().st_size
    _ensure_no_job(case_id, "플래시 쓰기")
    decision, cls = await _authorize(case_id, "openocd_flash_write", [cmd], ctx=ctx, approval_id=approval_id, extra={"file_sha256": sha, "file_size": size})
    if not decision.allowed:
        return gate_response(decision)
    # 승인 이후 파일이 바뀌지 않았는지 다시 확인 (TOCTOU)
    if await run_blocking(sha256_file, p) != sha:
        raise SafetyDenied("승인 이후 이미지 파일 내용이 바뀌었습니다. 실행하지 않습니다.", hint="새 내용으로 다시 승인을 받으세요.")
    timeout = max(10.0, min(float(timeout), 3600.0))
    rep, sh = await _call_checked(sess, cmd, timeout=timeout, check=True, trigger="openocd_flash_write")
    if sh is not None and sh.get("status") == "failsafe":
        return _failsafe_response(sh, command=cmd, classification=cls.to_dict(), written=rep.ok, messages=rep.log)
    if not rep.ok:
        return {**_reply_error(rep, command=cmd), **_semihosting_fields(sh)}
    out: dict[str, Any] = {"ok": True, "status": "written", "output": rep.output, "messages": rep.log, "file_sha256": sha, "file_size": size,
                           "classification": cls.to_dict(), **_semihosting_fields(sh)}
    if verify:
        vcmd = f"verify_image {qpath} 0x{addr:x} bin"
        vcls = guard.classify_managed(vcmd, allowed_dirs=[case.dir], unknown_risk=_unknown_risk())
        d2, _ = await _authorize(case_id, "openocd_flash_write", [vcmd], ctx=ctx, classification=vcls)
        if d2.allowed:
            vr = await _call(sess, vcmd, timeout=timeout)
            out["verify"] = {"ok": vr.ok, "output": vr.output if vr.ok else vr.error_text}
    r.audit({"event": "openocd_flash_written", "path": case.rel(p), "sha256": sha, "address": f"0x{addr:x}"}, case_id)
    return out


# ---------------------------------------------------------------------------
# 보조
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "OpenOCD scripts 디렉터리의 cfg 파일 목록 (interface|target|board|all). pattern 으로 부분 문자열 필터. "
        "예: kind='interface', pattern='ftdi' → interface/ftdi/tigard.cfg 등. openocd_start 의 interface_cfg/target_cfg 에 그대로 쓴다."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
def openocd_list_configs(kind: str = "interface", pattern: str | None = None, limit: int = 200) -> dict[str, Any]:
    r = rt()
    if kind not in ("interface", "target", "board", "all"):
        raise ValidationFailed("kind 는 interface | target | board | all")
    try:
        binary = process.find_openocd(r.config.tool_path("openocd"))
    except PwehError:
        binary = None
    configured = (r.config.tools.get("openocd_scripts") or os.environ.get("PWEH_OPENOCD_SCRIPTS") or "").strip() or None
    dirs = process.scripts_dirs(configured, binary)
    if not dirs:
        return {"ok": True, "scripts_dir": None, "configs": [], "note": "OpenOCD scripts 디렉터리를 찾지 못했습니다 (PWEH_OPENOCD_SCRIPTS 설정)."}
    base = dirs[0]
    kinds = ["interface", "target", "board"] if kind == "all" else [kind]
    items: list[str] = []
    pat = (pattern or "").lower()
    for k in kinds:
        d = base / k
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*.cfg")):
            rel = str(p.relative_to(base))
            if pat and pat not in rel.lower():
                continue
            items.append(rel)
    limit = max(1, min(int(limit), 2000))
    return {"ok": True, "scripts_dir": str(base), "count": len(items), "configs": items[:limit], "truncated": len(items) > limit}


register_job_tools(server, rt, "openocd")


def _install_signal_handlers() -> None:
    def _term(signum, frame):  # noqa: ARG001
        raise SystemExit(0)

    try:
        signal.signal(signal.SIGTERM, _term)
    except (ValueError, OSError):  # pragma: no cover - 메인 스레드가 아닐 때
        pass


def main() -> None:
    _install_signal_handlers()
    try:
        server.run()
    finally:
        REGISTRY.shutdown_all()


if __name__ == "__main__":
    main()
