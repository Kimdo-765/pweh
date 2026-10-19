"""uart-mcp: UART 콘솔 MCP 서버 (pweh-uart).

포트·세션·수신 버퍼·로그, U-Boot(autoboot 중단, printenv/info, md.b 덤프 job), 리눅스 셸(로그인, 식별, dd 덤프 job),
보드레이트 탐지, 부팅 로그 수집을 제공한다. 세션은 서버 프로세스 메모리에 있고 포트당 수신 스레드가 링 버퍼와
케이스 로그(uart/<session>.log/.raw/.events.jsonl)에 계속 기록한다.

안전 (docs/architecture.md §4):
- 기기에 영향을 주는 도구는 rt().case(case_id, hardware=True) 로 소유/허가 증명을 확인하고, 보낼 바이트를
  ``guard.plan_payload``(코어 classify_console_line + LineAssembler + 더 엄격한 로컬 규칙)로 분류해
  ``rt().authorize(...)`` 를 통과한 뒤에만 쓴다. 허용되지 않으면 gate_response(decision) 를 그대로 돌려준다.
- 승인 지문(action)에는 실제로 기기에서 완성될 줄과 분류 문맥을 넣는다. 타임아웃·approval_id 같은 실행 옵션은 넣지 않는다.
- 백그라운드 덤프 job 은 시작 전에 계획된 모든 명령이 INTERACT 이하인지 확인하고, 실행 중에도 명령마다 다시 분류한다.
- U-Boot 프롬프트를 얻을 때 빈 Enter 를 쓰지 않는다(직전 명령 반복). Ctrl-C(0x03)를 쓴다.
"""

from __future__ import annotations

import atexit
import contextlib
import errno
import logging
import re
import threading
import time
from pathlib import Path
from typing import Any

import anyio

from pweh.errors import Busy, DeviceError, NotFound, PwehError, SafetyDenied, ValidationFailed
from pweh.fsutil import atomic_write_text, utcnow_iso
from pweh.jobs import ACTIVE_STATES, JobContext
from pweh.mcpkit import (
    ANN_DEVICE,
    ANN_LOCAL_WRITE,
    ANN_READ_ONLY,
    META_LARGE_OUTPUT,
    Context,
    create_server,
    gate_response,
    register_job_tools,
    run_blocking,
    run_blocking_cancellable,
    safe_tool,
)
from pweh.runtime import Runtime, get_runtime
from pweh.safety import Classification, GateDecision, Risk, worst

from . import baud as baudmod
from . import console, dumps
from .guard import BUSY_RULE, HIGH_BIT_RULE, REPEAT_UNKNOWN_RULE, UNCERTAIN_RULE, static_check
from .parsers import (
    env_load_addresses,
    env_mtdparts,
    flash_size_from_facts,
    is_not_found,
    parse_bdinfo,
    parse_busybox_list,
    parse_cpuinfo,
    parse_help,
    parse_id,
    parse_mounts,
    parse_netstat,
    parse_printenv,
    parse_ps,
    parse_sf_probe,
    parse_uname,
    parse_version,
    partitions_from_mtdparts,
    proc_mtd,
    propose_safe_ram,
    summarize_boot_text,
    uboot_has,
)
from .profile import load_profile
from .session import PortSettings, UartSession, is_url, port_key, validate_port
from .textutil import decode_bytes, decode_keys, key_display, normalize_line_ending, normalize_newlines, parse_int, slugify

SERVER_NAME = "uart-mcp"
log = logging.getLogger("pweh.uart")

server = create_server(
    SERVER_NAME,
    title="PWEH UART Console",
    instructions=(
        "UART 콘솔 서버. 순서: (1) 사람이 GND/TX/RX 를 연결(어댑터 VCC 는 연결 안 함) → uart_list_ports → "
        "(보드레이트를 모르면 uart_detect_baud(probe='none')) → uart_open(case_id, port, baudrate) → "
        "(2) U-Boot: uboot_interrupt → uboot_printenv → uboot_info(safe_ram_addr) → "
        "uboot_dump_start(job, uart_job_status 로 폴링) / 리눅스: uart_capture_boot 또는 uart_read → shell_login(사용자가 준 계정만) → "
        "shell_identify → shell_dump_start(job). (3) 끝나면 uart_close(로그 아티팩트 등록). "
        "uart_read 의 커서는 누적 수신 바이트 오프셋이며 도구 호출 사이에 온 출력도 잃지 않는다. "
        "U-Boot 프롬프트에서 빈 Enter 를 보내지 말 것(직전 명령 반복) — 새 프롬프트는 uart_sync(Ctrl-C). "
        "전원 투입 타이밍이 필요한 도구(uart_detect_baud, uart_capture_boot, uboot_interrupt)는 사람에게 전원을 먼저 꺼 두게 하고, "
        "'준비' 답을 받은 뒤 도구를 호출하며, 사람은 호출이 시작되면 전원을 넣는다 (켜져 있던 기기의 이전 부팅 출력은 판단에 쓰지 않는다). "
        "문맥이 unknown 이면 두 분류기 중 더 엄격한 쪽으로 분류되니 uart_sync 로 확정하라. "
        "16 MiB 플래시를 115200 baud 로 md.b 덤프하면 약 2시간 걸린다 — job 은 취소·재개(resume)할 수 있다."
    ),
)


def rt() -> Runtime:
    return get_runtime(SERVER_NAME)


# ---------------------------------------------------------------------------
# 세션 레지스트리
# ---------------------------------------------------------------------------

_SESSIONS: dict[str, UartSession] = {}
_RESERVED: dict[str, str] = {}  # port_key → 용도 (열기 중/보드레이트 탐지 중)
# (case_id, port_key) → 닫힌 세션이 마지막으로 보낸 U-Boot 명령. 같은 포트를 다시 열면(예: setenv baudrate 뒤 새 속도로)
# 기기의 '직전 명령'을 알고 있으므로 빈 Enter 를 '알 수 없는 명령의 반복'(DESTRUCTIVE) 대신 그 명령의 반복으로 분류한다.
# 추적 env 는 넘기지 않는다 (세션 사이에 본 적 없는 재부팅이 있었으면 낡은 값이라 run 분류가 느슨해진다).
_PORT_MEMORY: dict[tuple[str, str], dict[str, Any]] = {}
_LOCK = threading.Lock()

USB_UART_VIDS = {0x0403: "FTDI", 0x067B: "Prolific", 0x10C4: "Silicon Labs", 0x1A86: "WCH", 0x04E2: "Exar", 0x04D8: "Microchip",
                 0x0557: "ATEN", 0x0BDA: "Realtek", 0x2E8A: "Raspberry Pi", 0x1D50: "OpenMoko/BMP", 0x0483: "STMicro"}
CONTEXT_CHOICES = ("uboot", "linux-shell", "login", "password", "booting", "unknown", "auto")
READY_WAIT_S = 0.5  # 줄을 보내기 전에 기기가 프롬프트로 돌아오기를 기다리는 시간 (expect 로 일찍 끝난 명령 뒤 등)
# shell_dump_start 가 읽을 수 있는 /dev 경로: 저장장치 블록/문자 장치만. /dev/watchdog(여는 순간 타이머 시작 → 재부팅),
# /dev/mem·/dev/port(MMIO 읽기 부작용·버스 오류) 같은 장치는 'dd if=' 읽기라도 기기 상태를 바꿀 수 있다.
SHELL_DEV_RE = re.compile(r"^/dev/(mtd\d+(ro)?|mtdblock\d+|mmcblk\d+(p\d+|boot[01])?|ubi\d+_\d+|ubiblock\d+_\d+|sd[a-z]\d*|nand[a-z]?\d*)$")


def _get(session_id: str) -> UartSession:
    with _LOCK:
        s = _SESSIONS.get(session_id)
    if s is None:
        raise NotFound(f"세션을 찾을 수 없습니다: {session_id}",
                       hint="uart_sessions 로 열린 세션을 확인하세요. 서버가 재시작되면 세션은 사라지고 로그는 케이스 uart/ 에 남습니다.")
    return s


def _port_in_use(key: str) -> str | None:
    for s in _SESSIONS.values():
        if s.port_key == key and s.state in ("open", "opening", "disconnected"):
            return s.id
    return _RESERVED.get(key)


def _new_session_id(case_dir: Path, label: str | None) -> str:
    base = slugify(label or "uart", 24, "uart")
    n = 1
    while True:
        sid = f"{base}-{n:03d}"
        if sid not in _SESSIONS and not (case_dir / "uart" / f"{sid}.log").exists():
            return sid
        n += 1


def _job_active(jid: str) -> bool:
    try:
        return rt().jobs.get(jid).status in ACTIVE_STATES
    except Exception:  # noqa: BLE001
        return False


def _register_logs(s: UartSession) -> list[dict[str, Any]]:
    out = []
    try:
        case = rt().cases.get(s.case_id)
    except Exception:  # noqa: BLE001
        return out
    desc = f"UART 세션 {s.id} ({s.port} @ {s.settings.baudrate} {s.settings.framing})"
    for path, kind, what in ((s.log_path, "uart-log", "텍스트 로그(RX/TX)"), (s.raw_path, "uart-raw", "수신 원시 바이트"),
                             (s.events_path, "uart-events", "송신·안전 결정·문맥 이벤트")):
        if path.exists():
            try:
                out.append(case.register_artifact(path, kind=kind, producer=SERVER_NAME, description=f"{desc} — {what}",
                                                  extra={"session_id": s.id, "port": s.port, "baudrate": s.settings.baudrate}))
            except Exception as exc:  # noqa: BLE001
                log.warning("artifact registration failed for %s: %s", path, exc)
    return out


def _remember_port(s: UartSession) -> None:
    """닫는 세션이 마지막으로 보낸 U-Boot 명령을 기억한다 (같은 케이스·포트의 다음 세션이 이어 받음)."""
    with s.cond:
        last = s.last_command
    with _LOCK:
        if last is not None:
            _PORT_MEMORY[(s.case_id, s.port_key)] = {"last_command": last, "session_id": s.id, "closed_at": utcnow_iso()}
        else:
            _PORT_MEMORY.pop((s.case_id, s.port_key), None)


def shutdown_all(reason: str = "server shutdown") -> None:
    """모든 세션을 닫고(실행 중 job 취소) 로그 아티팩트를 등록한다. atexit 와 테스트 정리에서 부른다."""
    with _LOCK:
        sessions = list(_SESSIONS.values())
        _SESSIONS.clear()
        _RESERVED.clear()
        _PORT_MEMORY.clear()
    for s in sessions:
        jid = s.active_job()
        if jid:
            with contextlib.suppress(Exception):
                rt().jobs.cancel(jid)
                rt().jobs.wait(jid, 8.0)
        with contextlib.suppress(Exception):
            s.close(reason)
        with contextlib.suppress(Exception):
            _register_logs(s)


atexit.register(shutdown_all)


# ---------------------------------------------------------------------------
# 공통 도우미
# ---------------------------------------------------------------------------


class GateBlocked(Exception):
    def __init__(self, decision: GateDecision, extra: dict[str, Any] | None = None) -> None:
        super().__init__(decision.status)
        self.decision = decision
        self.extra = extra or {}


@contextlib.asynccontextmanager
async def _op(s: UartSession, what: str, wait: float = 15.0):
    """세션당 고수준 동작 하나만 (같은 세션에 명령이 섞이지 않게)."""
    deadline = time.monotonic() + wait
    while not s.op_lock.acquire(blocking=False):
        if time.monotonic() > deadline:
            raise Busy(f"세션 {s.id} 에서 다른 명령이 실행 중입니다 ({what}).", hint="앞 호출이 끝난 뒤 다시 시도하세요.")
        await anyio.sleep(0.05)
    try:
        # 잠금을 기다리는 동안 덤프 job 이 시작됐을 수 있다 → 다시 확인
        s.ensure_open()
        s.ensure_idle()
        yield
    finally:
        s.op_lock.release()


def _device_session(session_id: str, *, need_idle: bool = True) -> UartSession:
    s = _get(session_id)
    rt().case(s.case_id, hardware=True)
    s.ensure_open()
    if need_idle:
        s.ensure_idle()
    return s


def _require_pending_clear(s: UartSession) -> None:
    if s.assembler.pending or s.assembler.pending_uncertain:
        raise ValidationFailed(
            f"세션에 줄 끝 없이 보낸 미완성 입력이 남아 있습니다: {s.assembler.pending!r}",
            hint="uart_sync(Ctrl-C)로 기기 줄 버퍼를 비운 뒤 다시 호출하세요.")


def _log_decision(s: UartSession, tool: str, decision: GateDecision, *, plan: Any = None, extra: dict[str, Any] | None = None) -> None:
    """게이트 결정을 세션 이벤트 로그(uart/<session>.events.jsonl)에도 남긴다 (감사 로그와 별도)."""
    c = decision.classification
    ev: dict[str, Any] = {"type": "safety", "tool": tool, "status": decision.status, "allowed": decision.allowed, "policy": decision.policy,
                          "risk": c.risk.label, "rule_id": c.rule_id, "reason": c.reason}
    if decision.via:
        ev["via"] = decision.via
    if decision.approval_id:
        ev["approval_id"] = decision.approval_id
    if plan is not None:
        ev["context"] = plan.context
        ev["lines"] = ["<masked>" if plan.masked else ln for ln in plan.line_texts()]
    if extra:
        ev.update(extra)
    with contextlib.suppress(Exception):
        s.event(ev)


async def _authorize_plan(s: UartSession, tool: str, plan: Any, action: dict[str, Any], ctx: Context | None,
                          approval_id: str | None) -> GateDecision:
    decision = await rt().authorize(tool=tool, action=action, classification=plan.classification, case_id=s.case_id,
                                    approval_id=approval_id, ctx=ctx, summary=f"{s.id} [{plan.context}] {plan.summary()}")
    _log_decision(s, tool, decision, plan=plan)
    return decision


def _deny_hint(c: Classification) -> str | None:
    """거부된 송신의 다음 행동 안내 (분류 규칙별)."""
    rid = c.rule_id
    if BUSY_RULE in rid:
        return "기기가 부팅 중이거나 앞 명령을 실행 중입니다(프롬프트 없음). uart_read 로 프롬프트를 확인하거나 uart_sync(Ctrl-C)로 프롬프트를 되찾은 뒤 한 줄씩 보내세요."
    if UNCERTAIN_RULE in rid:
        return "기기 줄 버퍼를 확정할 수 없습니다. uart_sync(Ctrl-C)로 줄을 비운 뒤 일반 문자만 다시 보내세요."
    if REPEAT_UNKNOWN_RULE in rid:
        return "빈 Enter 는 이 세션 전에 기기에서 실행된 알 수 없는 명령을 반복할 수 있습니다. 프롬프트만 필요하면 uart_sync, 콘솔 활성화는 shell_login 을 쓰세요."
    if HIGH_BIT_RULE in rid:
        return "기기 콘솔은 ASCII 만 씁니다. 상위 비트가 켜진 바이트(UTF-8 등)를 빼고 보내세요."
    if "repeat" in rid:
        return "U-Boot 에서 빈 줄은 직전 명령을 반복합니다. 프롬프트만 필요하면 uart_sync(Ctrl-C)를 쓰세요."
    return None


async def _send_internal(s: UartSession, command: str, *, tool: str, timeout: float, ctx: Context | None,
                         approval_id: str | None = None) -> console.CommandResult:
    """도구 내부에서 보내는 읽기 명령 한 줄 (명령마다 분류 + 게이트)."""
    _require_pending_clear(s)
    await run_blocking(s.wait_ready, READY_WAIT_S)
    payload = (command + s.line_ending_for()).encode("utf-8")
    plan = s.plan(payload)
    action = {"session_id": s.id, "port": s.port, "context": plan.context, "command": command, "lines": plan.line_texts()}
    decision = await _authorize_plan(s, tool, plan, action, ctx, approval_id)
    if not decision.allowed:
        raise GateBlocked(decision, {"command": command, "plan": plan.to_dict()})
    ev = threading.Event()
    res: console.CommandResult = await run_blocking_cancellable(
        console.run_planned, s, plan, plan.classification.risk, echo_text=command, timeout=timeout, cancel=ev.is_set,
        source=tool, on_cancel=ev.set)
    s.agent_cursor = max(s.agent_cursor, res.cursor_end)
    if res.disconnected:
        s.ensure_open()
    return res


def _risk_info(c: Classification) -> dict[str, Any]:
    return {"risk": c.risk.label, "rule_id": c.rule_id, "reason": c.reason}


def _rel(s: UartSession, p: Path) -> str:
    return s.case.rel(p)


# ---------------------------------------------------------------------------
# 포트 / 세션
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "시리얼 포트 목록 (OBSERVE). ports[{device, description, hwid, vid, pid, serial_number, manufacturer, likely_usb_uart, in_use_by}]. "
        "include_links=true 면 /dev/serial/by-id/… 링크도 포함. TCP 시리얼(ser2net, 시뮬레이터)은 목록에 없고 uart_open 에 socket://host:port 로 준다."
    ),
    annotations=ANN_READ_ONLY,
)
@safe_tool
def uart_list_ports(include_links: bool = False) -> dict[str, Any]:
    from serial.tools import list_ports

    ports = []
    with _LOCK:
        in_use = {s.port_key: s.id for s in _SESSIONS.values() if s.state in ("open", "disconnected")}
    for p in sorted(list_ports.comports(include_links=include_links), key=lambda x: x.device):
        desc = p.description or ""
        likely = bool(p.vid in USB_UART_VIDS or re.search(r"(?i)uart|cp210|ch34|ch910|ft232|ft2232|pl2303|usb.?serial|ttl", f"{desc} {p.hwid}"))
        ports.append({
            "device": p.device,
            "description": desc,
            "hwid": p.hwid,
            "vid": None if p.vid is None else f"0x{p.vid:04x}",
            "pid": None if p.pid is None else f"0x{p.pid:04x}",
            "serial_number": p.serial_number,
            "manufacturer": p.manufacturer or USB_UART_VIDS.get(p.vid or -1),
            "likely_usb_uart": likely,
            "in_use_by": in_use.get(port_key(p.device)),
        })
    out: dict[str, Any] = {"ok": True, "ports": ports, "count": len(ports)}
    if not ports:
        out["hint"] = "시리얼 포트가 없습니다. USB-UART 어댑터를 연결하세요 (WSL2 는 usbipd 로 장치를 붙여야 함). TCP 시리얼은 socket://host:port."
    return out


@server.tool(
    description=(
        "UART 세션 열기 (INTERACT, dtr/rts=true 면 MODIFY — 보드 리셋/부트모드 핀일 수 있음). port 는 장치 경로 또는 pyserial URL "
        "(socket://host:port, rfc2217://, loop://). DTR/RTS 는 열기 전에 설정하며 기본 False. line_ending 기본 \"\\r\" (U-Boot 문맥은 항상 \\r). "
        "profile 은 pipeline_profiles 이름(생략 시 케이스 프로필) — 프롬프트/autoboot 정규식과 인터럽트 키를 정한다. "
        "반환: session_id, log_path/raw_path/events_path(케이스 상대), context, cursor. 세션이 열려 있는 동안 수신 스레드가 계속 기록한다."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def uart_open(
    case_id: str,
    port: str,
    ctx: Context,
    baudrate: int = 115200,
    bytesize: int = 8,
    parity: str = "N",
    stopbits: float = 1,
    line_ending: str = "\r",
    dtr: bool = False,
    rts: bool = False,
    profile: str | None = None,
    label: str | None = None,
    approval_id: str | None = None,
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id, hardware=True)
    port = validate_port(port)
    if not (50 <= int(baudrate) <= 20_000_000):
        raise ValidationFailed(f"잘못된 baudrate: {baudrate}")
    if bytesize not in (5, 6, 7, 8):
        raise ValidationFailed(f"잘못된 bytesize: {bytesize}")
    parity = str(parity or "N").upper()[:1]
    if parity not in ("N", "E", "O", "M", "S"):
        raise ValidationFailed(f"잘못된 parity: {parity}")
    if float(stopbits) not in (1.0, 1.5, 2.0):
        raise ValidationFailed(f"잘못된 stopbits: {stopbits}")
    le = normalize_line_ending(line_ending)
    prof = load_profile(r.config, profile or case.meta.get("profile"))
    key = port_key(port)
    settings = PortSettings(port=port, baudrate=int(baudrate), bytesize=int(bytesize), parity=parity,
                            stopbits=int(stopbits) if float(stopbits).is_integer() else float(stopbits), line_ending=le,
                            dtr=bool(dtr), rts=bool(rts))
    if dtr or rts:
        cls = Classification(Risk.MODIFY, "uart.open.signals", "DTR/RTS 를 켠 채 포트 열기 — 보드의 리셋/부트모드 핀에 연결돼 있으면 기기가 리셋될 수 있음")
    else:
        cls = Classification(Risk.INTERACT, "uart.open", "UART 포트 열기 (DTR/RTS 끔, 수신 기록 시작)")
    with _LOCK:
        used = _port_in_use(key)
    if used:
        raise Busy(f"포트 {port} 는 이미 사용 중입니다 ({used}).", hint="기존 세션을 쓰거나 uart_close 후 다시 여세요.")
    decision = await r.authorize(tool="uart_open", action={"port": port, "baudrate": settings.baudrate, "framing": settings.framing,
                                                            "dtr": settings.dtr, "rts": settings.rts},
                                 classification=cls, case_id=case_id, approval_id=approval_id, ctx=ctx,
                                 summary=f"uart_open {port} @ {settings.baudrate} dtr={settings.dtr} rts={settings.rts}")
    if not decision.allowed:
        return gate_response(decision)
    with _LOCK:
        used = _port_in_use(key)
        if used:
            raise Busy(f"포트 {port} 는 이미 사용 중입니다 ({used}).")
        sid = _new_session_id(case.dir, label)
        _RESERVED[key] = sid
    try:
        s = UartSession(session_id=sid, case=case, settings=settings, profile=prof, label=label,
                        buffer_bytes=int(r.config.uart.get("read_buffer_bytes", 4 * 1024 * 1024)),
                        persistent_paths=list(r.config.safety.persistent_paths), unknown_risk=r.config.safety.unknown_command_risk,
                        audit=lambda ev, _cid=case_id: rt().audit(ev, _cid))
        s.job_lookup = _job_active
        with _LOCK:
            inherited = _PORT_MEMORY.get((case_id, key))
        if inherited:
            s.last_command = inherited["last_command"]
        await run_blocking(s.open)
        _log_decision(s, "uart_open", decision, extra={"port": port, "dtr": settings.dtr, "rts": settings.rts})
        if inherited:
            s.event({"type": "inherited_last_command", "from_session": inherited["session_id"], "last_command": inherited["last_command"]})
        with _LOCK:
            _SESSIONS[sid] = s
    finally:
        with _LOCK:
            _RESERVED.pop(key, None)
    arts = _register_logs(s)
    r.audit({"event": "uart_open", "session_id": sid, "port": port, "baudrate": settings.baudrate, "framing": settings.framing,
             "dtr": settings.dtr, "rts": settings.rts, "profile": prof.name}, case_id)
    await anyio.sleep(0.15)  # 바로 들어오는 출력(프롬프트 등)으로 문맥을 잡을 시간
    snap = s.snapshot()
    out = {
        "ok": True,
        "session_id": sid,
        "port": port,
        "baudrate": settings.baudrate,
        "framing": settings.framing,
        "line_ending": snap["line_ending"],
        "dtr": settings.dtr,
        "rts": settings.rts,
        "profile": prof.summary(),
        "log_path": snap["log_path"],
        "raw_path": snap["raw_path"],
        "events_path": snap["events_path"],
        "context": snap["context"],
        "phase": snap["phase"],
        "cursor": snap["rx_bytes"],
        "artifacts": [a.get("id") for a in arts],
        "next_steps": [
            "출력이 없으면: 사람에게 전원을 꺼 두게 한 뒤 uart_capture_boot 를 호출하고, 호출이 시작되면 전원을 넣게 한다",
            "U-Boot 가 필요하면: 전원을 꺼 둔 상태에서 uboot_interrupt 를 호출하고, 호출이 시작되면 사람이 전원을 넣는다",
            "이미 프롬프트에 있는 기기면: uart_sync 로 문맥 확정",
        ],
    }
    if is_url(port) and port.startswith("socket://"):
        out["note"] = "socket:// 연결은 보드레이트를 전달하지 않습니다 (서버 쪽 설정을 따름)."
    if inherited:
        out["inherited_last_command"] = inherited["last_command"]  # 빈 Enter 는 이 명령의 반복으로 분류된다
    return out


@server.tool(
    description="UART 세션 닫기: 실행 중인 job 취소, 수신 스레드 정지, 포트 닫기, 로그(uart-log/uart-raw/uart-events) 아티팩트 등록. 끊어진(disconnected) 세션도 닫을 수 있다.",
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
async def uart_close(session_id: str) -> dict[str, Any]:
    s = _get(session_id)
    cancelled = None
    jid = s.active_job()
    if jid:
        rt().jobs.cancel(jid)
        await run_blocking(rt().jobs.wait, jid, 15.0)
        cancelled = jid
    await run_blocking(s.close, "uart_close")
    with _LOCK:
        _SESSIONS.pop(session_id, None)
    _remember_port(s)
    arts = _register_logs(s)
    rt().audit({"event": "uart_close", "session_id": session_id, "rx_bytes": s.rx.total, "tx_bytes": s.tx_bytes}, s.case_id)
    return {
        "ok": True,
        "session_id": session_id,
        "rx_bytes": s.rx.total,
        "tx_bytes": s.tx_bytes,
        "log_path": _rel(s, s.log_path),
        "raw_path": _rel(s, s.raw_path),
        "events_path": _rel(s, s.events_path),
        "artifacts": [{"id": a.get("id"), "path": a.get("path"), "kind": a.get("kind")} for a in arts],
        "job_cancelled": cancelled,
    }


@server.tool(description="열린 UART 세션 목록: 상태(open/disconnected), 문맥/phase/프롬프트, rx/tx 바이트, 로그 경로, 미완성 입력, 실행 중 job.", annotations=ANN_READ_ONLY)
@safe_tool
def uart_sessions(case_id: str | None = None) -> dict[str, Any]:
    with _LOCK:
        sessions = list(_SESSIONS.values())
    rows = [s.snapshot() for s in sessions if case_id is None or s.case_id == case_id]
    return {"ok": True, "sessions": rows, "count": len(rows)}


@server.tool(
    description=(
        "수신 버퍼 읽기 (OBSERVE). 커서는 누적 수신 바이트 오프셋. since_cursor 생략 시 에이전트 읽기 위치(직전 uart_read/명령의 cursor_end)부터. "
        "tail=true 면 마지막 max_bytes. wait_seconds>0 이면 새 데이터를 최대 그만큼 기다린다(최대 50). "
        "반환: text(CRLF→LF), cursor_start, cursor_end, more, context, prompt, state, lost_bytes(버퍼에서 밀려난 양)."
    ),
    annotations=ANN_READ_ONLY,
    meta=META_LARGE_OUTPUT,
)
@safe_tool
async def uart_read(session_id: str, since_cursor: int | None = None, max_bytes: int = 8192, wait_seconds: float = 0, tail: bool = False) -> dict[str, Any]:
    s = _get(session_id)
    wait = max(0.0, min(float(wait_seconds or 0), 50.0))
    ev = threading.Event()
    res = await run_blocking_cancellable(s.read, since_cursor, int(max_bytes), wait, bool(tail), ev.is_set, on_cancel=ev.set)
    return {"ok": True, "session_id": session_id, **res}


@server.tool(
    description=(
        "원시 쓰기. data 는 text(JSON 이스케이프로 \\r, \\u0003 등) 또는 encoding=\"hex\". 세션이 지금까지 보낸 입력과 이어서 "
        "기기 줄 버퍼처럼 조립(LineAssembler)해 완성되는 줄마다 문맥 분류기로 검사한다 — 나눠 보내기('sa'+'veenv\\r')도 한 줄로 분류. "
        "제어 문자는 CONTROL_CHAR_RISK, 탭/ESC(자동완성·히스토리)가 섞인 줄은 DESTRUCTIVE. U-Boot 문맥에서 \\r\\n 은 명령+빈 줄(반복)로 본다. "
        "최대 4096 바이트. 일반 명령은 uart_send_command 를 쓴다."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def uart_write(session_id: str, data: str, ctx: Context, encoding: str = "text", approval_id: str | None = None) -> dict[str, Any]:
    s = _device_session(session_id)
    if encoding == "hex":
        try:
            payload = bytes.fromhex(re.sub(r"\s+", "", data or ""))
        except ValueError as exc:
            raise ValidationFailed(f"hex 를 해석할 수 없습니다: {exc}")
    elif encoding == "text":
        payload = (data or "").encode("utf-8")
    else:
        raise ValidationFailed(f"잘못된 encoding: {encoding!r}", hint="text 또는 hex")
    if not payload:
        raise ValidationFailed("보낼 데이터가 없습니다.")
    if len(payload) > 4096:
        raise ValidationFailed(f"한 번에 최대 4096 바이트 (받은 {len(payload)}).")
    async with _op(s, "uart_write"):
        if any(b >= 0x20 or b in (0x0A, 0x0D) for b in payload):  # 제어 문자만(Ctrl-C 등)이면 기다릴 이유가 없다
            await run_blocking(s.wait_ready, READY_WAIT_S)
        plan = s.plan(payload)
        action = {"session_id": s.id, "port": s.port, "context": plan.context, "data_hex": payload.hex(), "lines": plan.line_texts(),
                  **s.approval_refs(plan)}
        decision = await _authorize_plan(s, "uart_write", plan, action, ctx, approval_id)
        if not decision.allowed:
            hint = _deny_hint(plan.classification)
            return gate_response(decision, plan=plan.to_dict(), **({"hint": hint} if hint else {}))
        cursor = await run_blocking(s.commit, plan, plan.classification.risk, source="uart_write")
    out = {"ok": True, "bytes_written": len(payload), "cursor": cursor, "plan": plan.to_dict(), "context": s.context}
    if plan.pending_after:
        out["pending_input"] = plan.pending_after
        out["note"] = "줄 끝이 없어 기기 줄 버퍼에 남은 입력이 있습니다. 다음 송신과 이어서 한 줄로 분류됩니다 (지우려면 uart_sync)."
    return out


@server.tool(
    description=(
        "명령 한 줄 + 줄끝 전송 후 에코와 다음 프롬프트(또는 expect 정규식, 줄마다 ^$ 적용, CRLF 무관)까지 대기. "
        "현재 문맥(uboot/linux-shell/unknown…)의 분류기로 검사하며 unknown·login 문맥은 두 분류기 중 엄격한 쪽. "
        "반환: output(에코·프롬프트 제거), matched, match, timed_out(시간 초과는 오류가 아님), context, prompt, cursor_end(이어서 uart_read). "
        "U-Boot 에서 빈 command 는 직전 명령 반복으로 분류된다 — 프롬프트를 깨우려면 uart_sync. 로그인은 shell_login 을 쓴다. "
        "timeout 은 최대 600초지만 MCP 클라이언트 제한(대개 60초)을 고려하라."
    ),
    annotations=ANN_DEVICE,
    meta=META_LARGE_OUTPUT,
)
@safe_tool
async def uart_send_command(session_id: str, command: str, ctx: Context, timeout: float = 10, expect: str | None = None,
                            approval_id: str | None = None, max_output: int = 20000) -> dict[str, Any]:
    s = _device_session(session_id)
    if "\r" in command or "\n" in command:
        raise ValidationFailed("command 에 줄바꿈을 넣지 마세요 (한 번에 한 줄).", hint="여러 줄은 명령마다 따로 호출하세요.")
    expect_re = None
    if expect:
        try:
            expect_re = re.compile(expect, re.M)
        except re.error as exc:
            raise ValidationFailed(f"expect 정규식 오류: {exc}")
    timeout = max(0.5, min(float(timeout), 600.0))
    async with _op(s, "uart_send_command"):
        await run_blocking(s.wait_ready, READY_WAIT_S)
        ctx_now = s.context
        le = s.line_ending_for(ctx_now)
        plan = s.plan((command + le).encode("utf-8"))
        action: dict[str, Any] = {"session_id": s.id, "port": s.port, "context": plan.context, "command": command, "lines": plan.line_texts(),
                                  **s.approval_refs(plan)}
        decision = await _authorize_plan(s, "uart_send_command", plan, action, ctx, approval_id)
        if not decision.allowed:
            hint = _deny_hint(plan.classification)
            return gate_response(decision, plan=plan.to_dict(), **({"hint": hint} if hint else {}))
        ev = threading.Event()
        res: console.CommandResult = await run_blocking_cancellable(
            console.run_planned, s, plan, plan.classification.risk, echo_text=command, timeout=timeout, expect=expect_re,
            cancel=ev.is_set, source="uart_send_command", on_cancel=ev.set)
        s.agent_cursor = res.cursor_end
    out = {"ok": True, "session_id": s.id, **res.to_dict(int(max_output or 0)), "classification": _risk_info(plan.classification)}
    assembled = plan.line_texts()
    if assembled and assembled[0] != command:
        out["assembled_line"] = assembled[0]
        out["warning"] = "이전에 보낸 미완성 입력과 이어져 다른 줄이 실행되었습니다."
    if le != s.settings.line_ending:
        out["line_ending_used"] = "\\r (U-Boot 문맥)"
    if re.search(r"\b(setenv|env\s+set)\s+baudrate\b", command):
        out["warning"] = ("U-Boot 콘솔 속도가 바뀝니다. 기기는 새 속도에서 Enter(\\r)를 기다립니다 — 같은 서버 프로세스에서 uart_close 후 "
                          "uart_open(같은 case·포트, baudrate=새 값)으로 다시 열고, 응답에 inherited_last_command 가 있을 때만 "
                          "uart_write(data=\"\\r\")를 보내세요. 없으면(서버 재시작 등) 빈 Enter 는 uart.repeat-unknown 으로 거부되므로 "
                          "사람에게 전원 재투입을 요청해 원래 속도로 돌아가세요 (CONFIG_SYS_BAUDRATE_TABLE 밖의 값은 거부됨).")
    if res.timed_out:
        out["hint"] = ("프롬프트가 나오지 않았습니다(명령이 계속 실행 중이거나 문맥이 바뀜). uart_read 로 이어 읽거나, 멈추려면 uart_sync(Ctrl-C). "
                       "프롬프트가 특이하면 expect 를 주거나 uart_set_context(prompt=…).")
    if res.disconnected:
        out["ok"] = False
        out["error"] = f"세션 연결이 끊어졌습니다: {s.error}"
    return out


@server.tool(
    description=(
        "정규식이 수신 데이터에 나타날 때까지 대기 (OBSERVE, 기기에 아무것도 보내지 않음). since_cursor 생략 시 에이전트 읽기 위치부터 검색 → "
        "호출 사이에 온 출력도 놓치지 않는다. 줄마다 ^$ 적용(CR 은 LF 로 취급). 반환: matched, match, groups, text(검색 구간, 최대 8000자), "
        "cursor_end(매치 끝), timed_out. timeout 최대 600초 (MCP 클라이언트 제한 고려)."
    ),
    annotations=ANN_READ_ONLY,
    meta=META_LARGE_OUTPUT,
)
@safe_tool
async def uart_wait_for(session_id: str, pattern: str, timeout: float = 30, since_cursor: int | None = None) -> dict[str, Any]:
    s = _get(session_id)
    try:
        rx = re.compile(pattern, re.M)
    except re.error as exc:
        raise ValidationFailed(f"정규식 오류: {exc}")
    since = s.agent_cursor if since_cursor is None else max(0, int(since_cursor))
    timeout = max(0.0, min(float(timeout), 600.0))
    ev = threading.Event()
    res = await run_blocking_cancellable(s.wait_response, since, timeout, expect=rx, cancel=ev.is_set, on_cancel=ev.set)
    end = res.end
    text = normalize_newlines(decode_bytes(s.slice(since, end)))
    clipped = len(text) > 8000
    s.agent_cursor = end
    out = {
        "ok": True,
        "matched": res.kind == "expect",
        "match": res.match_text,
        "groups": res.groups,
        "text": text[-8000:],
        "text_clipped": clipped,
        "cursor_start": since,
        "match_start": res.match_start,
        "cursor_end": end,
        "timed_out": res.kind == "timeout",
        "context": s.context,
        "state": s.state,
    }
    if res.kind == "disconnected":
        out["disconnected"] = True
    return out


@server.tool(
    description=(
        "문맥 수동 지정: uboot / linux-shell / login / password / booting / unknown, auto 는 수동 지정 해제. prompt 를 주면 그 문자열을 그 문맥의 "
        "프롬프트로 학습한다(특이한 프롬프트). 안전: 분류는 수동 문맥과 자동 감지 문맥 둘 다로 해서 더 엄격한 쪽을 쓴다(수동 지정으로 완화 불가). "
        "재부팅·phase 변화 증거가 나오면 수동 지정은 풀린다."
    ),
    annotations=ANN_LOCAL_WRITE,
)
@safe_tool
def uart_set_context(session_id: str, context: str, prompt: str | None = None) -> dict[str, Any]:
    s = _get(session_id)
    if context not in CONTEXT_CHOICES:
        raise ValidationFailed(f"잘못된 context: {context!r}", hint=f"허용: {CONTEXT_CHOICES}")
    with s.cond:
        prev = s.manual_context
        s.manual_context = None if context == "auto" else context
        if prompt and context in ("uboot", "linux-shell"):
            s.tracker.learned[context] = prompt
            if context == "uboot":
                s.tracker.uboot_prompts_seen.add(prompt)  # 더 엄격하게만: 이 문자열은 리눅스 증거만으로 셸이 되지 않는다
            s.tracker._evaluate_tail(s.rx.total, s.rx.total)  # noqa: SLF001 - 학습한 프롬프트로 다시 평가
        auto = s.tracker.context
        phase = s.tracker.phase
    s.event({"type": "manual_context", "from": prev, "to": s.manual_context, "prompt": prompt})
    out = {"ok": True, "context": s.context, "manual_context": s.manual_context, "auto_context": auto, "phase": phase}
    if s.manual_context and s.manual_context != auto:
        out["warning"] = (f"자동 감지 문맥({auto})과 다릅니다. 송신 분류는 둘 중 더 엄격한 쪽을 씁니다. "
                          "문맥 증거가 필요하면 uart_sync(Ctrl-C: U-Boot 는 <INTERRUPT> 출력)를 쓰세요.")
    return out


@server.tool(
    description=(
        "Ctrl-C(0x03) 한 번으로 새 프롬프트를 받고 문맥을 확정한다 (INTERACT, 추가 도구). U-Boot 는 '<INTERRUPT>' 를 출력하고(입력 줄 비움), "
        "리눅스 셸은 새 프롬프트만 출력한다. 미완성 입력도 지운다. 빈 Enter 대신 이것을 쓴다."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def uart_sync(session_id: str, ctx: Context, timeout: float = 3, approval_id: str | None = None) -> dict[str, Any]:
    s = _device_session(session_id)
    async with _op(s, "uart_sync"):
        plan = s.plan(b"\x03")
        decision = await _authorize_plan(s, "uart_sync", plan, {"session_id": s.id, "port": s.port, "data_hex": "03"}, ctx, approval_id)
        if not decision.allowed:
            return gate_response(decision)
        ev = threading.Event()
        res = await run_blocking_cancellable(console.sync, s, timeout=max(0.5, min(float(timeout), 30.0)), cancel=ev.is_set,
                                             source="uart_sync", on_cancel=ev.set)
        s.agent_cursor = res["cursor_end"]
    return {"ok": True, "session_id": s.id, **res}


@server.tool(
    description="BREAK 신호 전송 (MODIFY). 리눅스 시리얼 콘솔에서는 BREAK 다음 5초 안의 문자가 Magic SysRq 명령(b=즉시 재부팅 등)이 되므로, 그 창 동안의 다음 송신은 최소 MODIFY 로 분류된다.",
    annotations=ANN_DEVICE,
)
@safe_tool
async def uart_send_break(session_id: str, ctx: Context, duration: float = 0.25, approval_id: str | None = None) -> dict[str, Any]:
    s = _device_session(session_id)
    duration = max(0.01, min(float(duration), 2.0))
    cls = Classification(Risk.MODIFY, "uart.break", "BREAK 신호 (리눅스 콘솔에서 Magic SysRq 를 시작할 수 있음)")
    decision = await rt().authorize(tool="uart_send_break", action={"session_id": s.id, "port": s.port, "duration": duration},
                                    classification=cls, case_id=s.case_id, approval_id=approval_id, ctx=ctx)
    _log_decision(s, "uart_send_break", decision, extra={"duration": duration})
    if not decision.allowed:
        return gate_response(decision)
    async with _op(s, "uart_send_break"):
        try:
            await run_blocking(s.raw_signal, lambda ser: ser.send_break(duration), f"break {duration}s")
        except (OSError, NotImplementedError) as exc:
            return {"ok": False, "status": "unsupported", "message": f"이 포트는 BREAK 를 지원하지 않습니다: {exc}"}
        s.sysrq_until = time.monotonic() + 5.0
    out = {"ok": True, "duration": duration, "sysrq_window_seconds": 5.0}
    if is_url(s.port):
        out["note"] = "네트워크 시리얼(socket:// 등)은 BREAK 를 전달하지 않을 수 있습니다."
    return out


@server.tool(
    description="DTR/RTS 신호 설정 (MODIFY — 보드의 리셋/부트모드 핀에 연결돼 있으면 기기가 리셋된다). PTY·socket:// 등 신호가 없는 포트는 status=unsupported.",
    annotations=ANN_DEVICE,
)
@safe_tool
async def uart_set_signals(session_id: str, ctx: Context, dtr: bool | None = None, rts: bool | None = None,
                           approval_id: str | None = None) -> dict[str, Any]:
    s = _device_session(session_id)
    if dtr is None and rts is None:
        raise ValidationFailed("dtr 또는 rts 중 하나는 지정해야 합니다.")
    cls = Classification(Risk.MODIFY, "uart.signals", "DTR/RTS 변경 — 리셋/부트모드 핀이면 기기가 리셋될 수 있음")
    decision = await rt().authorize(tool="uart_set_signals", action={"session_id": s.id, "port": s.port, "dtr": dtr, "rts": rts},
                                    classification=cls, case_id=s.case_id, approval_id=approval_id, ctx=ctx)
    _log_decision(s, "uart_set_signals", decision, extra={"dtr": dtr, "rts": rts})
    if not decision.allowed:
        return gate_response(decision)
    if is_url(s.port) and s.port.split("://", 1)[0] in ("socket", "loop"):
        return {"ok": False, "status": "unsupported", "message": f"{s.port.split('://', 1)[0]}:// 포트는 모뎀 신호를 전달하지 않습니다."}

    def fn(ser: Any) -> None:
        if dtr is not None:
            ser.dtr = bool(dtr)
        if rts is not None:
            ser.rts = bool(rts)

    async with _op(s, "uart_set_signals"):
        try:
            await run_blocking(s.raw_signal, fn, f"dtr={dtr} rts={rts}")
        except OSError as exc:
            if exc.errno in (errno.ENOTTY, errno.EINVAL, errno.ENOTSUP if hasattr(errno, "ENOTSUP") else -1):
                return {"ok": False, "status": "unsupported", "message": f"이 포트는 DTR/RTS 제어를 지원하지 않습니다 (예: PTY): {exc}"}
            raise DeviceError(f"신호 설정 실패: {exc}")
    return {"ok": True, "dtr": dtr, "rts": rts}


@server.tool(
    description=(
        "보드레이트 탐지: 후보마다 포트를 열고(DTR/RTS 끔) probe=\"ctrl-c\" 면 0x03 을 한 번 보낸 뒤 listen_seconds 동안 읽어 점수화(출력 가능 문자 비율, "
        "부팅 키워드, 0x00/0xFF 연속 감점) → candidates(점수순), best, confidence, hint(데이터 없음: TX/RX 뒤바뀜·GND·무출력·전압). "
        "기기가 출력 중이어야 하므로 사람에게 전원을 먼저 꺼 두게 하고 '준비' 답을 받은 뒤 호출한다 — 사람은 호출이 시작되면 전원을 넣는다 (전원 투입 중에는 probe=\"none\" 권장: ctrl-c 가 autoboot 를 멈출 수 있음). probe=ctrl-c 는 MODIFY(다른 속도로 보낸 0x03 은 기기에서 다른 "
        "바이트로 읽힐 수 있음), probe=none 은 INTERACT. 이 포트로 열린 세션이 없어야 한다. 총 50초 제한."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def uart_detect_baud(case_id: str, port: str, ctx: Context, candidates: list[int] | None = None, listen_seconds: float = 2.5,
                           probe: str = "ctrl-c", approval_id: str | None = None) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id, hardware=True)
    port = validate_port(port)
    if probe not in ("ctrl-c", "none"):
        raise ValidationFailed(f"잘못된 probe: {probe!r}", hint="ctrl-c 또는 none")
    cands = [int(b) for b in (candidates or r.config.baud_candidates(case.meta.get("profile")))]
    if not cands or any(not (50 <= b <= 20_000_000) for b in cands):
        raise ValidationFailed(f"잘못된 candidates: {cands}")
    cands = list(dict.fromkeys(cands))
    listen = max(0.2, min(float(listen_seconds), 10.0))
    key = port_key(port)
    with _LOCK:
        used = _port_in_use(key)
    if used:
        raise Busy(f"포트 {port} 는 사용 중입니다 ({used}).", hint="uart_close 로 세션을 닫은 뒤 탐지하세요.")
    if probe == "ctrl-c":
        cls = Classification(Risk.MODIFY, "uart.detect-baud.probe",
                             "후보 보드레이트마다 0x03 을 한 번 보냄 — 속도가 다르면 기기에서 다른 바이트(예: 0x04 Ctrl-D)로 읽혀 셸이 종료되는 등 휘발성 변화 가능")
    else:
        cls = Classification(Risk.INTERACT, "uart.detect-baud", "포트를 여러 속도로 열어 수신만 함 (DTR/RTS 끔)")
    decision = await r.authorize(tool="uart_detect_baud", action={"port": port, "candidates": cands, "probe": probe},
                                 classification=cls, case_id=case_id, approval_id=approval_id, ctx=ctx)
    if not decision.allowed:
        return gate_response(decision)
    with _LOCK:
        used = _port_in_use(key)
        if used:
            raise Busy(f"포트 {port} 는 사용 중입니다 ({used}).")
        _RESERVED[key] = "uart_detect_baud"
    try:
        ev = threading.Event()
        res = await run_blocking_cancellable(baudmod.detect, port, cands, listen, probe, cancel=ev.is_set, on_cancel=ev.set)
    finally:
        with _LOCK:
            _RESERVED.pop(key, None)
    r.audit({"event": "uart_detect_baud", "port": port, "best": res.get("best"), "tested": res.get("tested")}, case_id)
    return {"ok": True, "port": port, "probe": probe, "listen_seconds": listen, **res}


@server.tool(
    description=(
        "부팅 로그 수집 (OBSERVE, 기기에 아무것도 보내지 않음): 사람에게 전원을 꺼 두게 한 뒤 호출하고, 호출이 시작되면 전원을 넣게 한다. "
        "duration 초(최대 300, MCP 클라이언트 제한 고려) "
        "또는 until 정규식까지 수집. stop_on_prompt=true 면 이 창에서 부팅이 시작된 뒤 로그인/셸/U-Boot 프롬프트가 나오고 1.5초 조용하면 멈춘다. "
        "파싱 결과: uboot_version, autoboot_message, bootdelay, kernel_version, cmdline, mtdparts, partitions, login_prompt, shell_prompt, "
        "flash, flash_write_warnings, stages. 발췌는 uart/<session>-boot-NN.log 로 저장·등록."
    ),
    annotations=ANN_READ_ONLY,
    meta=META_LARGE_OUTPUT,
)
@safe_tool
async def uart_capture_boot(session_id: str, duration: float = 30, until: str | None = None, stop_on_prompt: bool = True) -> dict[str, Any]:
    s = _get(session_id)
    rt().case(s.case_id, hardware=True)
    s.ensure_open()
    until_re = None
    if until:
        try:
            until_re = re.compile(until, re.M)
        except re.error as exc:
            raise ValidationFailed(f"until 정규식 오류: {exc}")
    duration = max(0.5, min(float(duration), 300.0))
    start = s.total()
    with s.cond:
        boot_seq0 = s.tracker.boot_seq
    ev = threading.Event()

    def worker() -> tuple[int, str]:
        deadline = time.monotonic() + duration
        scan = start
        pending = False
        while True:
            if ev.is_set():
                return s.total(), "cancelled"
            with s.cond:
                if until_re is not None:
                    # 미완성 줄 끝에서의 매치(예: until='^Kernel command line: .*$')는 줄이 끝나거나 조용해질 때까지 보류
                    m, base, pending, scan = s.search_stable(until_re, start, scan)
                    if m is not None:
                        return base + m.end(), "until"
                    if pending and time.monotonic() >= deadline:
                        hit = s._search(until_re, start, scan)  # noqa: SLF001
                        if hit is not None:
                            return hit[1] + hit[0].end(), "until"
                s.cond.wait(0.05 if pending else 0.2)
                tr = s.tracker
                booted = tr.boot_seq != boot_seq0 or (tr.kernel_at is not None and tr.kernel_at >= start) or \
                    (tr.autoboot_at is not None and tr.autoboot_at >= start)
                pm = tr.prompt if (tr.prompt is not None and tr.prompt.end == s.rx.total and tr.prompt.start >= start) else None
                quiet = time.monotonic() - s.last_rx_mono
                state = s.state
                total = s.rx.total
            if state != "open":
                return total, "disconnected"
            if stop_on_prompt and booted and pm is not None and quiet >= 1.5:
                return total, f"prompt:{pm.kind}:{pm.context}"
            if time.monotonic() >= deadline:
                return total, "duration"

    end, stopped_by = await run_blocking_cancellable(worker, on_cancel=ev.set)
    data = s.slice(start, end)
    text = decode_bytes(data)
    summary = summarize_boot_text(text, s.profile)
    excerpt_rel = None
    if data:
        udir = s.case.subdir("uart")
        n = 1
        while (udir / f"{s.id}-boot-{n:02d}.log").exists():
            n += 1
        p = udir / f"{s.id}-boot-{n:02d}.log"
        atomic_write_text(p, normalize_newlines(text))
        with contextlib.suppress(Exception):
            rt().cases.get(s.case_id).register_artifact(p, kind="uart-log", producer=SERVER_NAME,
                                                       description=f"부팅 로그 발췌 ({s.id}, {len(data)} 바이트)",
                                                       extra={"session_id": s.id, "type": "boot-capture", "cursor_start": start, "cursor_end": end})
        excerpt_rel = s.case.rel(p)
    s.agent_cursor = end
    out = {
        "ok": True,
        "session_id": s.id,
        "captured_bytes": len(data),
        "stopped_by": stopped_by,
        "cursor_start": start,
        "cursor_end": end,
        "excerpt_path": excerpt_rel,
        "context": s.context,
        **summary,
        "text_tail": normalize_newlines(text)[-3000:],
    }
    if not data:
        out["hint"] = "수신 데이터가 없습니다. 사람이 전원을 꺼 둔 상태에서 호출이 시작된 뒤 전원을 넣었는지, 배선(TX/RX/GND)과 보드레이트를 확인하세요 (uart_detect_baud)."
    if summary.get("flash_write_warnings"):
        out["warning"] = "부팅 중 플래시 쓰기 징후(예: Saving Environment, Write default environment)가 보였습니다. 케이스 기록에 남기세요."
    return out


# ---------------------------------------------------------------------------
# U-Boot
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "autoboot 중단 (INTERACT). 사람에게 기기 전원을 먼저 꺼 두게 하고 '준비' 답을 받은 뒤 호출한다 — 사람은 호출이 시작되면 전원을 넣는다. "
        "부팅 출력(또는 autoboot 메시지)이 보이면 "
        "인터럽트 키(keys 또는 프로필 interrupt_sequences, 기본 Ctrl-C — 빈 Enter 는 새 부팅 확인 뒤에만)를 약 50ms 마다 보내고, "
        "U-Boot 프롬프트가 나오면 멈춘 뒤 Ctrl-C 로 깨끗한 프롬프트를 받는다. keys 예: [\"ctrl-c\", \"space\"], [\"\\u0003\"]. "
        "반환: interrupted, outcome(prompt/kernel/linux/uboot_password/window_expired/…), new_boot_seen, prompt, autoboot_message, bootdelay, "
        "keys_used, keys_sent, explanation(실패 원인: bootdelay=0, 보드레이트, keyed autoboot, 부트로더 비밀번호 잠금 …). 호출 시점에 이미 "
        "부팅 중이던 기기의 이전 출력은 판단에 쓰지 않고 새 부팅을 기다린다(그동안 리눅스에 키를 보내지 않음). "
        "window_seconds 최대 120 (MCP 클라이언트 제한 고려, 기본 30)."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def uboot_interrupt(session_id: str, ctx: Context, keys: list[str] | None = None, window_seconds: float = 30) -> dict[str, Any]:
    s = _device_session(session_id)
    key_list = decode_keys(keys) if keys else (list(s.profile.interrupt_sequences) or ["\x03", " "])
    window = max(1.0, min(float(window_seconds), 120.0))
    async with _op(s, "uboot_interrupt"):
        # Enter 키는 새 부팅을 본 뒤에만 보낸다(console.interrupt) → 사전 승인은 그 상태를 가정하고, 키마다 보낼 때 다시 분류한다
        plans = [s.plan(k.encode("latin-1"), assume_history_known=True) for k in dict.fromkeys(key_list)]
        cls = worst([p.classification for p in plans])
        decision = await rt().authorize(tool="uboot_interrupt", action={"session_id": s.id, "port": s.port,
                                                                         "keys": [k.encode("latin-1").hex() for k in key_list]},
                                        classification=cls, case_id=s.case_id, ctx=ctx,
                                        summary=f"{s.id} autoboot 인터럽트 키 {[key_display(k) for k in key_list]}")
        _log_decision(s, "uboot_interrupt", decision, extra={"keys": [key_display(k) for k in key_list]})
        if not decision.allowed:
            return gate_response(decision, hint="키 중 위험도가 높은 것이 있습니다(예: 직전 명령이 있는 상태의 Enter). keys=[\"ctrl-c\"] 를 쓰세요.")
        ev = threading.Event()
        res = await run_blocking_cancellable(console.interrupt, s, key_list, window, ev.is_set, on_cancel=ev.set)
        s.agent_cursor = res.get("cursor_end", s.agent_cursor)
    rt().audit({"event": "uboot_interrupt", "session_id": s.id, "interrupted": res.get("interrupted"), "outcome": res.get("outcome")}, s.case_id)
    return {"ok": True, "session_id": s.id, **res}


def _require_uboot(s: UartSession) -> None:
    if s.context != "uboot":
        raise ValidationFailed(
            f"U-Boot 프롬프트 문맥이 아닙니다 (현재 {s.context}).",
            hint="uboot_interrupt 로 autoboot 를 멈추거나, 이미 U-Boot 라면 uart_sync(Ctrl-C → <INTERRUPT>)로 문맥을 확정하세요.")


def _flash_size_hint(s: UartSession) -> tuple[int | None, str | None]:
    """알려진 플래시 크기와 출처: uboot_info(sf probe) → 이 세션이 본 부팅 로그. 모르면 (None, None).

    uboot_printenv 는 보통 uboot_info 보다 먼저 부르므로, 부팅 로그만으로도 mtdparts 의 '-'(나머지 전체) 크기를 채울 수 있게 한다.
    """
    size = s.uboot_info.get("flash_size")
    if size:
        fl = s.uboot_info.get("flash") or {}
        return int(size), str(fl.get("size_source") or fl.get("source") or "uboot_info")
    with s.cond:
        facts = dict(s.tracker.facts)
    size = flash_size_from_facts(facts)
    return (size, "부팅 로그") if size else (None, None)


def _gate_or_raise(exc: GateBlocked) -> dict[str, Any]:
    return gate_response(exc.decision, **exc.extra)


@server.tool(
    description=(
        "U-Boot printenv 실행·파싱 (INTERACT): env{}, bootargs, bootcmd, bootdelay, mtdparts, partitions[{name, offset, size}], loadaddr, "
        "load_addresses, environment_size, flash_size/flash_size_source('-' 파티션 크기 계산에 쓴 값: uboot_info 또는 부팅 로그, 모르면 null). "
        "출력이 완전할 때(Environment size 줄)만 세션의 env 추적에 반영 — run/boot 분류가 이 값을 쓴다."
    ),
    annotations=ANN_DEVICE,
    meta=META_LARGE_OUTPUT,
)
@safe_tool
async def uboot_printenv(session_id: str, ctx: Context) -> dict[str, Any]:
    s = _device_session(session_id)
    _require_uboot(s)
    async with _op(s, "uboot_printenv"):
        try:
            res = await _send_internal(s, "printenv", tool="uboot_printenv", timeout=20.0, ctx=ctx)
        except GateBlocked as exc:
            return _gate_or_raise(exc)
    parsed = parse_printenv(res.output)
    env = parsed["env"]
    complete = parsed["complete"] and not res.timed_out
    if complete:
        with s.cond:
            s.uboot_env = dict(env)
            s.env_source = "printenv"
        s.event({"type": "env_tracked", "count": len(env)})
    flash_size, flash_size_source = _flash_size_hint(s)
    mtdparts = env_mtdparts(env)
    parts = partitions_from_mtdparts(mtdparts, flash_size)
    loads = env_load_addresses(env)
    out = {
        "ok": True,
        "env": env,
        "count": len(env),
        "bootargs": env.get("bootargs"),
        "bootcmd": env.get("bootcmd"),
        "bootdelay": env.get("bootdelay"),
        "mtdparts": mtdparts,
        "partitions": parts,
        "flash_size": flash_size,
        "flash_size_source": flash_size_source,
        "loadaddr": f"0x{loads[0][1]:x}" if loads else None,
        "load_addresses": [{"source": n, "address": f"0x{a:x}"} for n, a in loads],
        "environment_size": {"used": parsed["size_used"], "total": parsed["size_total"]},
        "complete": complete,
        "tracked": complete,
        "context": s.context,
        "cursor_end": res.cursor_end,
    }
    if parsed["errors"]:
        out["errors"] = parsed["errors"]
    if not complete:
        out["warning"] = "printenv 출력이 완전하지 않아(시간 초과 또는 'Environment size' 줄 없음) env 추적에 반영하지 않았습니다."
    if any(p.get("size") is None for p in parts):
        out["note"] = "플래시 크기를 아직 몰라 '-'(나머지 전체) 파티션 크기가 null 입니다 — uboot_info 를 부르면 partitions 를 다시 계산해 돌려줍니다."
    return out


@server.tool(
    description=(
        "U-Boot 정보 수집 (INTERACT, 명령마다 게이트): version, bdinfo{dram_start, dram_size, relocaddr, sp_start, …}, help 의 commands[], "
        "has{}(help 기준 사용 가능 여부, U-Boot 약어 규칙 포함 — 약어로만 되면 has_via{}, help 를 못 읽으면 null), "
        "probe_flash=true 면 'sf probe 0' 으로 flash{type, model, size_bytes}, 추적 env 가 있으면 partitions[](플래시 크기로 '-' 채움). "
        "DRAM 안에서 U-Boot 자신(relocaddr/malloc/스택)과 하위 1 MiB 를 "
        "피한 safe_ram_addr 과 ram_window 를 제안한다 (env loadaddr/bootcmd 주소 우선). uboot_dump_start 는 ram_addr 을 생략하면 이 값을 쓴다."
    ),
    annotations=ANN_DEVICE,
    meta=META_LARGE_OUTPUT,
)
@safe_tool
async def uboot_info(session_id: str, ctx: Context, probe_flash: bool = True) -> dict[str, Any]:
    s = _device_session(session_id)
    _require_uboot(s)
    notes: list[str] = []
    async with _op(s, "uboot_info"):
        try:
            rv = await _send_internal(s, "version", tool="uboot_info", timeout=10.0, ctx=ctx)
            rb = await _send_internal(s, "bdinfo", tool="uboot_info", timeout=10.0, ctx=ctx)
            rh = await _send_internal(s, "help", tool="uboot_info", timeout=20.0, ctx=ctx)
            help_info = parse_help(rh.output)
            rs = None
            if probe_flash:
                if "sf" in help_info["commands"] or not help_info["commands"]:
                    rs = await _send_internal(s, "sf probe 0", tool="uboot_info", timeout=15.0, ctx=ctx)
                else:
                    notes.append("help 에 sf 명령이 없어 SPI NOR probe 를 건너뜀 (NAND/eMMC 기기일 수 있음).")
        except GateBlocked as exc:
            return _gate_or_raise(exc)
    version = parse_version(rv.output)
    bd = parse_bdinfo(rb.output)
    facts = dict(s.tracker.facts)
    flash: dict[str, Any] = {"type": None, "model": None, "size_bytes": None, "source": None}
    if rs is not None:
        sf = parse_sf_probe(rs.output)
        if sf.get("ok"):
            flash.update({"type": "spi-nor", "model": sf.get("model") or sf.get("device"), "size_bytes": sf.get("size_bytes"),
                          "page_size": sf.get("page_size"), "erase_size": sf.get("erase_size"), "source": "sf probe",
                          "manufacturer_id": sf.get("manufacturer_id")})
        else:
            notes.append(f"sf probe 실패: {sf.get('errors') or rs.output[-200:]}")
        flash["sf_probe_output"] = rs.output[-500:]
    if not flash.get("size_bytes"):
        size = flash_size_from_facts(facts)
        if size:
            flash["size_bytes"] = size
            flash["size_source"] = "부팅 로그"
            flash["model"] = flash.get("model") or facts.get("flash_name") or facts.get("flash_detected")
        elif s.uboot_env:
            parts = partitions_from_mtdparts(env_mtdparts(s.uboot_env))
            if parts and all(p["size"] for p in parts):
                flash["size_bytes_lower_bound"] = max(p["offset"] + p["size"] for p in parts)
                notes.append("플래시 크기를 확정하지 못해 mtdparts 합계를 하한으로 보고합니다.")
    safe = propose_safe_ram(bd, s.uboot_env, facts)
    commands = help_info["commands"]
    # help 목록 기준. 8자 이름('printenv-')도 파싱하고, U-Boot 약어 규칙(유일한 접두어)으로 되는 것은 has_via 에 적는다.
    # help 를 파싱하지 못했으면 None(모름).
    has, has_via = uboot_has(commands, ("sf", "md", "crc32", "echo", "nand", "mmc", "tftp", "tftpboot", "tftpput", "fatwrite",
                                        "printenv", "setenv", "saveenv"))
    env_parts = partitions_from_mtdparts(env_mtdparts(s.uboot_env), flash.get("size_bytes")) if s.uboot_env else []
    s.uboot_info.update({
        "version": version.get("version"),
        "bdinfo": bd,
        "flash": flash,
        "flash_size": flash.get("size_bytes"),
        "safe_ram": safe,
        "dram": (bd.get("dram_start"), bd.get("dram_size")) if bd.get("dram_start") is not None else None,
        "commands": commands,
    })
    if s.uboot_env is None:
        notes.append("env 를 아직 추적하지 않습니다 — run/boot 분류를 위해 uboot_printenv 를 먼저 호출하세요.")
    bd_out = {k: (f"0x{v:x}" if isinstance(v, int) and k not in ("dram_size", "baudrate") else v) for k, v in bd.items() if k not in ("raw",)}
    return {
        "ok": True,
        "version": version.get("version"),
        "version_info": version,
        "bdinfo": bd_out,
        "bdinfo_raw": {k: (f"0x{v:x}" if isinstance(v, int) else v) for k, v in bd.get("raw", {}).items()},
        "flash": flash,
        "commands": commands,
        "has": has,
        "has_via": has_via,
        "partitions": env_parts,
        "safe_ram_addr": safe.get("safe_ram_addr"),
        "ram_window": safe.get("ram_window"),
        "safe_ram": safe,
        "boot_facts": {k: v for k, v in facts.items() if k not in ("mtd_parts",)},
        "notes": notes,
        "context": s.context,
    }


@server.tool(
    description=(
        "U-Boot 플래시/메모리 덤프 job 시작 → job_id (uart_job_status 로 폴링, uart_job_cancel 로 취소). 청크마다 'sf read <ram> <off> <len>' "
        "(source=nand: nand read, mmc: mmc read(512B 블록), ram: 적재 없이 offset 이 RAM 주소) → 'md.b <ram> <len>' 파싱(주소·바이트 수 검증) → "
        "'crc32 <ram> <len>' 과 호스트 crc32 비교, 실패 청크는 retries 번 재시도. 좋은 청크마다 dumps/<name>.bin.part + .state.json 을 갱신해 "
        "같은 인자로 다시 부르면 이어 받는다(resume). 끝나면 dumps/<name>.bin + dumps/<name>.json(firmware-dump 스키마 필드) + 아티팩트"
        "(flash-dump/memory-dump). 시작 전에 모든 계획 명령이 INTERACT 이하인지 검사한다. offset/length 는 정수 또는 '0x50000', '16M'. "
        "ram_addr 생략 시 uboot_info 의 safe_ram_addr. chunk_size 최대 256 KiB. 처리량: 115200 baud 에서 약 2.3 KB/s (16 MiB ≈ 2시간)."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def uboot_dump_start(
    case_id: str,
    session_id: str,
    offset: int | str,
    length: int | str,
    ctx: Context,
    source: str = "sf",
    ram_addr: int | str | None = None,
    chunk_size: int | str = 65536,
    output_name: str | None = None,
    verify: str = "crc32",
    resume: bool = True,
    retries: int = 3,
    final_check: bool = True,
    sf_probe: str | None = "0",
) -> dict[str, Any]:
    case = rt().case(case_id, hardware=True)
    s = _device_session(session_id)
    if s.case_id != case_id:
        raise ValidationFailed(f"세션 {session_id} 은 케이스 {s.case_id} 의 세션입니다.")
    if source not in ("sf", "nand", "mmc", "ram"):
        raise ValidationFailed(f"잘못된 source: {source!r}", hint="sf | nand | mmc | ram")
    if verify not in ("crc32", "double", "none"):
        raise ValidationFailed(f"잘못된 verify: {verify!r}", hint="crc32(기본) | double(두 번 읽어 비교) | none")
    off = int(parse_int(offset, name="offset"))
    ln = int(parse_int(length, name="length"))
    chunk = int(parse_int(chunk_size, name="chunk_size"))
    retries = max(0, min(int(retries), 10))
    if off < 0 or ln <= 0:
        raise ValidationFailed("offset 은 0 이상, length 는 1 이상이어야 합니다.")
    if not (dumps.MIN_CHUNK <= chunk <= dumps.MAX_CHUNK):
        raise ValidationFailed(f"chunk_size 는 {dumps.MIN_CHUNK}~{dumps.MAX_CHUNK} 바이트 (md.b 출력은 데이터의 약 5배).")
    if source == "mmc" and (off % 512 or chunk % 512 or ln % 512):
        raise ValidationFailed("mmc 는 offset/length/chunk_size 가 512 바이트 블록 단위여야 합니다.")
    if sf_probe is not None and not re.fullmatch(r"[0-9]{1,2}(:[0-9]{1,2})?( [0-9]{1,9})?( [0-3])?|", sf_probe):
        raise ValidationFailed(f"잘못된 sf_probe 인자: {sf_probe!r}", hint="예: \"0\" (bus:cs), 생략하려면 null")
    info = s.uboot_info
    notes: list[str] = []
    window_end = None
    dram = info.get("dram")
    safe = info.get("safe_ram") or {}
    if safe.get("ram_window"):
        window_end = int(safe["ram_window"]["end"], 16)
    ram: int | None = None
    if source != "ram":
        if ram_addr is None:
            if not safe.get("safe_ram_addr"):
                raise ValidationFailed("ram_addr 이 필요합니다.", hint="먼저 uboot_info 로 safe_ram_addr 을 받거나 ram_addr 을 직접 주세요.")
            ram = int(safe["safe_ram_addr"], 16)
            notes.append(f"ram_addr 생략 → uboot_info 제안값 0x{ram:x} 사용")
        else:
            ram = int(parse_int(ram_addr, name="ram_addr"))
        if dram and dram[0] is not None and dram[1]:
            if not (dram[0] <= ram and ram + chunk <= dram[0] + dram[1]):
                raise ValidationFailed(f"ram_addr 0x{ram:x}+0x{chunk:x} 이 DRAM(0x{dram[0]:x}, {dram[1]} 바이트) 밖입니다.")
        else:
            notes.append("DRAM 범위를 모릅니다 (uboot_info 미실행) — ram_addr 을 검증하지 못했습니다.")
        if window_end is not None and safe.get("ram_window"):
            wstart_floor = int(safe["dram"]["start"], 16) if safe.get("dram") else None
            if ram + chunk > window_end:
                raise ValidationFailed(
                    f"ram_addr 0x{ram:x}+청크 0x{chunk:x} 가 U-Boot 영역(약 0x{window_end:x} 이상: relocaddr/malloc/스택)을 침범합니다.",
                    hint=f"uboot_info 의 safe_ram_addr({safe.get('safe_ram_addr')}) 이나 그보다 낮은 주소를 쓰세요.")
            if wstart_floor is not None and ram < wstart_floor + 0x100000:
                notes.append("ram_addr 이 DRAM 하위 1 MiB 안에 있습니다 (벡터/부트 파라미터 영역).")
    flash_size = _flash_size_hint(s)[0]
    if source == "sf" and flash_size and off + ln > flash_size:
        raise ValidationFailed(f"범위 0x{off:x}+0x{ln:x} 가 플래시 크기(0x{flash_size:x})를 넘습니다.")
    partition = None
    if s.uboot_env:
        for p in partitions_from_mtdparts(env_mtdparts(s.uboot_env), flash_size):
            if p["offset"] == off and p["size"] == ln:
                partition = p["name"]
    name = dumps.sanitize_name(output_name or f"uboot-{source}-{off:08x}-{ln:x}")
    files = dumps.DumpFiles(case, name)
    if files.final.exists():
        raise ValidationFailed(f"이미 완료된 덤프가 있습니다: dumps/{name}.bin", hint="다른 output_name 을 쓰세요 (기존 결과는 덮어쓰지 않습니다).")
    spec = dumps.UBootDumpSpec(case=case, files=files, source=source, offset=off, length=ln, chunk_size=chunk, ram_addr=ram,
                               verify=verify, retries=retries, resume=bool(resume), final_check=bool(final_check),
                               sf_probe=sf_probe if source == "sf" else None, ram_window_end=window_end, dram=dram,
                               flash_size=flash_size, partition=partition, kind="memory-dump" if source == "ram" else "flash-dump",
                               notes=notes)
    # 같은 이름의 진행 중 덤프가 다른 인자로 시작됐으면 job 을 띄우기 전에 거부한다 (job 안에서 늦게 실패하지 않게)
    prior = dumps.check_resume_identity(files, spec.identity(), resume=bool(resume))
    async with _op(s, "uboot_dump_start"):
        if s.tracker.context != "uboot":
            # 문맥 증거 확보: Ctrl-C → <INTERRUPT> + 프롬프트
            plan = s.plan(b"\x03")
            decision = await _authorize_plan(s, "uboot_dump_start", plan, {"session_id": s.id, "port": s.port, "data_hex": "03"}, ctx, None)
            if not decision.allowed:
                return gate_response(decision)
            await run_blocking(console.sync, s, timeout=3.0, source="uboot_dump_start")
        if s.tracker.context != "uboot":
            raise ValidationFailed(f"U-Boot 프롬프트를 확인하지 못했습니다 (자동 감지 문맥 {s.tracker.context}).",
                                   hint="uboot_interrupt 로 U-Boot 를 얻은 뒤 다시 시도하세요.")
        lines = spec.planned_lines()
        bad = static_check(lines, "uboot", env=s.uboot_env, last_command=s.last_command, persistent_paths=s.persistent_paths,
                           unknown_risk=s.unknown_risk)
        if bad:
            line, c = bad[0]
            raise SafetyDenied(f"계획된 명령 중 INTERACT 를 넘는 것이 있어 작업을 시작하지 않습니다: {line!r} → {c.risk.label} ({c.rule_id}: {c.reason})",
                               code="job_plan_denied", data={"offending": [{"line": ln_, **c_.to_dict()} for ln_, c_ in bad[:5]]})
        cls = Classification(Risk.INTERACT, "uart.dump.uboot", f"U-Boot md.b 덤프 계획 {len(lines)}개 명령 (모두 INTERACT 이하)")
        decision = await rt().authorize(tool="uboot_dump_start", action={"session_id": s.id, "port": s.port, "source": source, "offset": off,
                                                                          "length": ln, "ram_addr": ram, "chunk_size": chunk, "verify": verify},
                                        classification=cls, case_id=case_id, ctx=ctx,
                                        summary=f"{s.id} U-Boot 덤프 {source} 0x{off:x}+0x{ln:x}")
        _log_decision(s, "uboot_dump_start", decision, extra={"source": source, "offset": off, "length": ln, "planned_commands": len(lines)})
        if not decision.allowed:
            return gate_response(decision)

        def job_fn(jctx: JobContext) -> dict[str, Any]:
            try:
                return dumps.run_uboot_dump(jctx, s, spec, register=lambda path, **kw: case.register_artifact(path, producer=SERVER_NAME, **kw),
                                            check_auth=lambda: rt().case(case_id, hardware=True))
            finally:
                with contextlib.suppress(Exception):
                    _register_logs(s)

        job = rt().jobs.start("uart-uboot-dump", job_fn, description=f"U-Boot 덤프 {source} 0x{off:x}+0x{ln:x} → dumps/{name}.bin",
                              case_id=case_id, exclusive_key=f"uart:{s.port_key}",
                              meta={"session_id": s.id, "output": f"dumps/{name}.bin", "source": source})
        s.job_id = job.id
    est = ln * (79 / 16 + (60 / max(chunk, 1))) * s.settings.bits_per_char / max(300, s.settings.baudrate)
    rt().audit({"event": "uart_dump_started", "job_id": job.id, "session_id": s.id, "source": source, "offset": off, "length": ln}, case_id)
    return {
        "ok": True,
        "status": "started",
        "job_id": job.id,
        "output": f"dumps/{name}.bin",
        "part_path": f"dumps/{name}.bin.part",
        "state_path": f"dumps/{name}.state.json",
        "metadata_path": f"dumps/{name}.json",
        "chunks": spec.chunks(),
        "chunk_size": chunk,
        "ram_addr": None if ram is None else f"0x{ram:x}",
        "resume_from_chunk": prior,
        "estimated_seconds": round(est),
        "notes": notes,
        "next": "uart_job_status(job_id, wait_seconds=30) 로 진행을 확인하세요.",
    }


# ---------------------------------------------------------------------------
# 리눅스 셸
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "BusyBox 로그인 처리 (INTERACT): askfirst('Please press Enter')면 Enter, 'login:' 이면 username, 'Password:' 면 password 를 "
        "프롬프트가 수신 끝에 보일 때만 보낸다. 비밀번호는 로그·이벤트·감사 기록에서 마스킹된다. 사용자가 알려 준 계정만 쓰고 추측·무차별 대입 금지 — "
        "세션당 3회 실패하면 더 시도하지 않는다. username 을 생략하면 askfirst 콘솔 활성화만 한다(로그인 없는 콘솔; login: 이 나오면 "
        "username_required). 반환: logged_in, status(ok/already_logged_in/password_required/username_required/login_incorrect/"
        "context_unknown(U-Boot 일 수 있는 프롬프트 → uart_sync)/uboot_prompt/uboot_password_prompt(커널 전 Password: = 부트로더 잠금, "
        "아무것도 보내지 않음)/…), prompt, steps."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def shell_login(session_id: str, ctx: Context, username: str | None = None, password: str | None = None,
                      timeout: float = 15) -> dict[str, Any]:
    s = _device_session(session_id)
    if username is not None and (not username or any(ord(c) < 0x20 for c in username) or len(username) > 64):
        raise ValidationFailed("잘못된 username.")
    if password is not None and (any(ord(c) < 0x20 for c in password) or len(password) > 128):
        raise ValidationFailed("password 에 제어 문자를 넣을 수 없습니다 (최대 128자).")
    if s.login_failures >= 3:
        raise SafetyDenied(f"세션 {s.id} 에서 로그인이 {s.login_failures}회 실패했습니다. 더 시도하지 않습니다.", code="login_attempts_exceeded",
                           hint="사용자에게 올바른 계정을 확인받으세요. 다시 시도하려면 uart_close 후 새 세션을 여세요.")
    _require_pending_clear(s)
    cls = Classification(Risk.INTERACT, "uart.login-input", "로그인 프롬프트 입력 (askfirst Enter / 사용자 이름 / 비밀번호, 프롬프트 확인 후 전송)")
    decision = await rt().authorize(tool="shell_login", action={"session_id": s.id, "port": s.port, "username": username,
                                                                 "password": "<given>" if password is not None else None},
                                    classification=cls, case_id=s.case_id, ctx=ctx,
                                    summary=f"{s.id} 로그인 {username if username is not None else '(콘솔 활성화만)'}")
    _log_decision(s, "shell_login", decision, extra={"username": username, "password": "<masked>" if password is not None else None})
    if not decision.allowed:
        return gate_response(decision)
    async with _op(s, "shell_login"):
        ev = threading.Event()
        res = await run_blocking_cancellable(console.login, s, username, password, timeout=max(1.0, min(float(timeout), 120.0)),
                                             cancel=ev.is_set, on_cancel=ev.set)
        s.agent_cursor = res.get("cursor_end", s.agent_cursor)
    rt().audit({"event": "shell_login", "session_id": s.id, "user": username, "status": res.get("status")}, s.case_id)
    return {"ok": bool(res.get("logged_in")), "session_id": s.id, **res}


def _require_shell(s: UartSession) -> None:
    if s.context != "linux-shell":
        raise ValidationFailed(f"리눅스 셸 문맥이 아닙니다 (현재 {s.context}).",
                               hint="shell_login 으로 로그인하거나, 이미 셸이면 uart_sync 로 문맥을 확정하세요.")


@server.tool(
    description=(
        "리눅스 셸 식별 (읽기 전용 명령 묶음, 명령마다 게이트): uname -a, /proc/cpuinfo, /proc/mtd(파싱 → mtd[]), /proc/cmdline(mtdparts → "
        "partitions), /proc/mounts, ps, netstat -tuln(listening), busybox(applets), id. 반환: uname, kernel_version, arch, cpu, mtd[], cmdline, "
        "mounts, processes, listening, busybox_applets, has_base64/has_hexdump/has_md5sum."
    ),
    annotations=ANN_DEVICE,
    meta=META_LARGE_OUTPUT,
)
@safe_tool
async def shell_identify(session_id: str, ctx: Context) -> dict[str, Any]:
    s = _device_session(session_id)
    _require_shell(s)
    cmds = [("uname", "uname -a"), ("cpuinfo", "cat /proc/cpuinfo"), ("mtd", "cat /proc/mtd"), ("cmdline", "cat /proc/cmdline"),
            ("mounts", "cat /proc/mounts"), ("ps", "ps"), ("netstat", "netstat -tuln"), ("busybox", "busybox"), ("id", "id")]
    outs: dict[str, str] = {}
    missing: list[str] = []
    async with _op(s, "shell_identify"):
        try:
            for key, cmd in cmds:
                res = await _send_internal(s, cmd, tool="shell_identify", timeout=15.0, ctx=ctx)
                if is_not_found(res.output, cmd.split()[0]):
                    missing.append(cmd.split()[0])
                    if key == "netstat":
                        res = await _send_internal(s, "netstat -an", tool="shell_identify", timeout=15.0, ctx=ctx)
                    elif key == "mounts":
                        res = await _send_internal(s, "mount", tool="shell_identify", timeout=15.0, ctx=ctx)
                outs[key] = res.output
        except GateBlocked as exc:
            return _gate_or_raise(exc)
    uname = parse_uname(outs.get("uname", ""))
    cpu = parse_cpuinfo(outs.get("cpuinfo", ""))
    mtd = proc_mtd(outs.get("mtd", ""))
    cmdline = (outs.get("cmdline") or "").strip().splitlines()[0] if (outs.get("cmdline") or "").strip() else None
    mtdparts = None
    if cmdline:
        m = re.search(r"(mtdparts=\S+)", cmdline)
        mtdparts = m.group(1) if m else None
    total = sum(r["size"] for r in mtd) or None
    bb = parse_busybox_list(outs.get("busybox", ""))
    applets = bb["applets"]
    info = {
        "uname": uname.get("raw"),
        "kernel_version": uname.get("release"),
        "arch": uname.get("machine"),
        "hostname": uname.get("nodename"),
        "cpu": cpu.get("model"),
        "cpuinfo": cpu,
        "mtd": mtd,
        "cmdline": cmdline,
        "mtdparts": mtdparts,
        "partitions": partitions_from_mtdparts(mtdparts, total),
        "mounts": parse_mounts(outs.get("mounts", "")),
        "processes": parse_ps(outs.get("ps", "")),
        "listening": parse_netstat(outs.get("netstat", "")),
        "busybox": bb["version"],
        "busybox_applets": applets,
        "user": parse_id(outs.get("id", "")),
        "has_base64": ("base64" in applets) if applets else None,
        "has_hexdump": ("hexdump" in applets) if applets else None,
        "has_md5sum": ("md5sum" in applets) if applets else None,
        "missing_commands": missing,
    }
    s.shell_info = info
    return {"ok": True, "session_id": s.id, **info, "context": s.context}


@server.tool(
    description=(
        "리눅스 셸 덤프 job 시작 → job_id. 청크마다 'dd if=<path> bs=… skip=… count=… 2>/dev/null | base64'(없으면 '| hexdump -C') 를 파싱하고 "
        "같은 범위의 '| md5sum' 과 비교, 실패 청크는 재시도. path 는 /dev/mtdN · /dev/mtdblockN 또는 일반 파일(절대 경로). length 생략 시 "
        "/proc/mtd 크기(또는 wc -c). .part/.state.json 으로 재개, 끝나면 dumps/<name>.bin + .json(method linux-base64/linux-hexdump, "
        "verification md5-device) + 아티팩트(partition). 처리량: base64 ≈ 8 KB/s, hexdump ≈ 2.3 KB/s @115200."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def shell_dump_start(case_id: str, session_id: str, path: str, ctx: Context, offset: int | str = 0, length: int | str | None = None,
                           method: str = "auto", chunk_size: int | str = 65536, output_name: str | None = None, resume: bool = True,
                           retries: int = 3) -> dict[str, Any]:
    case = rt().case(case_id, hardware=True)
    s = _device_session(session_id)
    if s.case_id != case_id:
        raise ValidationFailed(f"세션 {session_id} 은 케이스 {s.case_id} 의 세션입니다.")
    if not dumps.SHELL_PATH_RE.match(path or "") or ".." in path.split("/"):
        raise ValidationFailed(f"잘못된 path: {path!r}", hint="절대 경로, 문자 [A-Za-z0-9_./+-] 만 (예: /dev/mtd3)")
    if path.startswith("/dev/") and not SHELL_DEV_RE.match(path):
        raise ValidationFailed(
            f"이 장치는 덤프하지 않습니다: {path!r}",
            hint="저장장치(/dev/mtdN, /dev/mtdblockN, /dev/mmcblkN[pM], /dev/ubiX_Y, /dev/sdX) 만 읽습니다. "
                 "/dev/watchdog 은 여는 순간 타이머가 시작돼 기기가 재부팅되고, /dev/mem 같은 메모리 장치는 읽기만으로도 부작용이 있습니다.")
    if method not in ("auto", "base64", "hexdump"):
        raise ValidationFailed(f"잘못된 method: {method!r}", hint="auto | base64 | hexdump")
    off = int(parse_int(offset, name="offset"))
    ln = parse_int(length, name="length", allow_none=True)
    chunk = int(parse_int(chunk_size, name="chunk_size"))
    if off < 0 or (ln is not None and ln <= 0):
        raise ValidationFailed("offset 은 0 이상, length 는 1 이상이어야 합니다.")
    if not (dumps.MIN_CHUNK <= chunk <= dumps.MAX_CHUNK):
        raise ValidationFailed(f"chunk_size 는 {dumps.MIN_CHUNK}~{dumps.MAX_CHUNK} 바이트.")
    base = path.rstrip("/").rsplit("/", 1)[-1]
    name = dumps.sanitize_name(output_name or f"shell-{base}-{off:x}")
    files = dumps.DumpFiles(case, name)
    if files.final.exists():
        raise ValidationFailed(f"이미 완료된 덤프가 있습니다: dumps/{name}.bin", hint="다른 output_name")
    kind = "partition" if re.match(r"^/dev/mtd(block)?\d+$", path) else "other"
    spec = dumps.ShellDumpSpec(case=case, files=files, path=path, offset=off, length=ln, chunk_size=chunk, method=method,
                               retries=max(0, min(int(retries), 10)), resume=bool(resume), kind=kind)
    # 길이(/proc/mtd)와 auto 방식은 job 안에서 정해지므로, 지금 아는 값(path/offset/chunk_size, 준 경우 length/method)만 미리 대조한다
    known: dict[str, Any] = {"path": path, "offset": off, "chunk_size": chunk}
    if ln is not None:
        known["length"] = ln
    if method != "auto":
        known["method"] = f"linux-{method}"
    prior = dumps.check_resume_identity(files, known, resume=bool(resume), partial=True)
    async with _op(s, "shell_dump_start"):
        _require_shell(s)
        if s.tracker.context != "linux-shell":
            raise ValidationFailed("자동 감지 문맥이 linux-shell 이 아닙니다 (수동 지정만으로는 작업을 시작하지 않습니다).",
                                   hint="uart_sync 로 셸 프롬프트 증거를 얻으세요.")
        bad = static_check(dumps.representative_shell_lines(path), "linux-shell", env=None, last_command=None,
                           persistent_paths=s.persistent_paths, unknown_risk=s.unknown_risk)
        if bad:
            line, c = bad[0]
            raise SafetyDenied(f"계획된 명령 중 INTERACT 를 넘는 것이 있어 시작하지 않습니다: {line!r} → {c.risk.label} ({c.rule_id})", code="job_plan_denied")
        cls = Classification(Risk.INTERACT, "uart.dump.shell", f"리눅스 셸 dd 덤프 ({path}, 읽기 전용)")
        decision = await rt().authorize(tool="shell_dump_start", action={"session_id": s.id, "port": s.port, "path": path, "offset": off,
                                                                          "length": ln, "method": method, "chunk_size": chunk},
                                        classification=cls, case_id=case_id, ctx=ctx, summary=f"{s.id} 셸 덤프 {path}")
        _log_decision(s, "shell_dump_start", decision, extra={"path": path, "offset": off, "length": ln})
        if not decision.allowed:
            return gate_response(decision)

        def job_fn(jctx: JobContext) -> dict[str, Any]:
            try:
                return dumps.run_shell_dump(jctx, s, spec, register=lambda p, **kw: case.register_artifact(p, producer=SERVER_NAME, **kw),
                                            check_auth=lambda: rt().case(case_id, hardware=True))
            finally:
                with contextlib.suppress(Exception):
                    _register_logs(s)

        job = rt().jobs.start("uart-shell-dump", job_fn, description=f"셸 덤프 {path} → dumps/{name}.bin", case_id=case_id,
                              exclusive_key=f"uart:{s.port_key}", meta={"session_id": s.id, "output": f"dumps/{name}.bin", "path": path})
        s.job_id = job.id
    rt().audit({"event": "uart_shell_dump_started", "job_id": job.id, "session_id": s.id, "path": path}, case_id)
    return {"ok": True, "status": "started", "job_id": job.id, "output": f"dumps/{name}.bin", "part_path": f"dumps/{name}.bin.part",
            "state_path": f"dumps/{name}.state.json", "metadata_path": f"dumps/{name}.json", "chunk_size": chunk,
            "resume_from_chunk": prior, "next": "uart_job_status(job_id, wait_seconds=30) 로 진행을 확인하세요."}


register_job_tools(server, rt, "uart")


def main() -> None:
    import signal

    def _term(signum: int, frame: Any) -> None:  # noqa: ARG001
        raise SystemExit(0)

    with contextlib.suppress(ValueError, OSError):
        signal.signal(signal.SIGTERM, _term)
    try:
        server.run()
    finally:
        shutdown_all()


if __name__ == "__main__":
    main()
