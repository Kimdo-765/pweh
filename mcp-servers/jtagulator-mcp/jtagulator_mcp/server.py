"""jtagulator-mcp: JTAGulator 핀아웃 스캔 MCP 서버 (pweh-jtagulator).

JTAGulator(USB-시리얼 115200 8N1 텍스트 메뉴)를 드라이버로 조작해 JTAG(IDCODE/BYPASS/Combined)·UART 핀아웃을 찾는다.

안전:
- 하드웨어 도구는 모두 rt().case(case_id, hardware=True) 로 소유/허가 증명을 강제한다.
- 보낼 키 계획 전체를 JTAGulator 분류기로 분류해 rt().authorize(...) 를 통과한 뒤에만 장치에 쓴다.
  드라이버 가드는 송신 직전 실제 장치 상태로 다시 분류해, 승인된 계획에 없는 INTERACT 초과 키를 막는다.
- jtagulator_set_voltage 는 DESTRUCTIVE(기본 거부). 잘못된 전압은 타깃 I/O 를 손상시킬 수 있다.
  사람이 멀티미터로 타깃 I/O 전압을 측정한 뒤 승인해야 한다.
- 스캔(MODIFY)은 이 연결에서 장치가 전압 설정을 확인한 뒤에만 시작한다.
- 스캔 대화(채널·옵션 답, 스페이스바)는 도구 호출 안에서 게이트 통과 직후 보내고, 백그라운드 작업은 출력 감시와
  중단 키(LF, INTERACT)만 보낸다. 작업은 시작 전에 자기 계획(중단 키)이 INTERACT 이하인지 확인한다.
"""

from __future__ import annotations

import atexit
import contextlib
import secrets
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from pweh.errors import Busy, DeviceError, NotFound, PwehError, SafetyDenied, TimeoutExpired, ValidationFailed
from pweh.fsutil import atomic_write_json, utcnow_iso
from pweh.jobs import ACTIVE_STATES, JobContext
from pweh.mcpkit import (
    META_REQUIRE_HUMAN,
    ANN_DESTRUCTIVE,
    ANN_DEVICE,
    ANN_READ_ONLY,
    Context,
    create_server,
    gate_response,
    register_job_tools,
    run_blocking,
    safe_tool,
)
from pweh.runtime import Runtime, get_runtime
from pweh.safety import Risk

from . import protocol as P
from .classify import classify_jtagulator
from .driver import (
    JTAGulatorDriver,
    ScanOutcome,
    ScanRun,
    ScanSpec,
    SerialLink,
    Transcript,
    VoltageNotDefined,
    build_known_pins_plan,
    build_scan_plan,
    build_voltage_plan,
)
from .parsers import (
    parse_bypass_test,
    parse_device_id_listing,
    parse_gpio_reads,
    parse_jtag_blocks,
    parse_status,
    parse_txd_hits,
    parse_uart_hits,
    summarize_gpio,
    summarize_jtag,
    summarize_txd,
    summarize_uart,
)

SERVER_NAME = "jtagulator-mcp"
log = logging.getLogger("pweh.jtagulator")

server = create_server(
    SERVER_NAME,
    title="PWEH JTAGulator",
    instructions=(
        "JTAGulator 로 JTAG/UART 핀아웃을 찾는 서버(선택 장비). 순서: (1) 사람이 타깃 전원을 끈 상태에서 GND 를 먼저 잇고 "
        "후보 테스트포인트를 CH0 부터 차례로 연결, VADJ 핀은 절대 타깃에 연결하지 않음 → (2) jtagulator_connect(case_id, port) → "
        "(3) 사람이 멀티미터로 타깃 I/O 전압을 측정해 알려 줌 → (4) jtagulator_set_voltage(case_id, volts) — DESTRUCTIVE, 사람 승인 "
        "필요(approval_required 이면 사용자가 `pweh approve <id>` 후 approval_id 로 재호출) → (5) 사람이 타깃 전원을 켬 → "
        "(6) 수동 관찰부터: jtagulator_gpio_read, jtagulator_uart_txd_scan(입력만 감시), 그다음 능동 스캔 jtagulator_uart_scan / jtagulator_idcode_scan / "
        "jtagulator_jtag_scan / jtagulator_bypass_scan (job_id 반환 → jtagulator_job_status 로 폴링, jtagulator_job_cancel 로 중단) → "
        "(7) jtagulator_get_device_ids / jtagulator_bypass_test 로 확인 → (8) 타깃 전원을 끈 뒤 jtagulator_disconnect. "
        "전압을 추정하거나 임의로 정하지 말 것. 연결할 때마다(포트 열기 시 DTR 리셋) 전압을 다시 설정해야 한다. "
        "결과·원시 기록은 케이스의 jtag/jtagulator-*.log/.json 에 저장된다."
    ),
)


def rt() -> Runtime:
    return get_runtime(SERVER_NAME)


# ---------------------------------------------------------------------------
# 연결 레지스트리
# ---------------------------------------------------------------------------


@dataclass
class Connection:
    case_id: str
    port: str
    baudrate: int
    link: SerialLink
    driver: JTAGulatorDriver
    transcript: Transcript
    transcript_rel: str
    session_n: int
    opened_at: str
    firmware: str | None = None
    firmware_supported: bool = False
    allow_untested_firmware: bool = False
    voltage: str | None = None  # 이 연결에서 장치가 확인한 전압 ("3.3"; "0" 은 끔)
    voltage_set_at: str | None = None
    voltage_via: str | None = None
    active_job_id: str | None = None
    scan_seq: int = 0
    connect_info: dict[str, Any] = field(default_factory=dict)
    # 연결(재사용 포함)마다 새로 만드는 토큰. 승인 지문(action)에 넣어, 다시 연결한 뒤에는 이전 승인을 쓸 수 없게 한다
    # (타깃을 바꿨을 수 있으므로 재측정·재승인 필요). 서버 재시작 후에도 겹치지 않도록 무작위.
    token: str = field(default_factory=lambda: "jc-" + secrets.token_hex(4))
    closed: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def busy_job(self) -> str | None:
        jid = self.active_job_id
        if not jid:
            return None
        try:
            job = rt().jobs.get(jid)
        except NotFound:
            return None
        return jid if job.status in ACTIVE_STATES else None

    @property
    def voltage_ready(self) -> bool:
        return bool(self.voltage) and self.voltage != "0" and self.driver.voltage == self.voltage

    def status(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "port": self.port,
            "baudrate": self.baudrate,
            "connected": not self.closed and self.link.alive,
            "link_error": str(self.link.error) if self.link.error else None,
            "firmware": self.firmware,
            "firmware_supported": self.firmware_supported,
            "menu": self.driver.menu,
            "voltage": {
                "confirmed_volts": self.voltage if self.voltage not in (None, "0") else None,
                "off": self.voltage == "0",
                "set_at": self.voltage_set_at,
                "approved_via": self.voltage_via,
                "scans_allowed": self.voltage_ready,
            },
            "active_job_id": self.busy_job(),
            "connection_token": self.token,
            "transcript": self.transcript_rel,
            "opened_at": self.opened_at,
            "rx_bytes": self.link.rx_bytes,
            "tx_bytes": self.link.tx_bytes,
        }


_CONNS: dict[str, Connection] = {}
_CONNS_LOCK = threading.Lock()
# port_key → case_id: 승인 뒤 연결(열기·재동기화)이 끝나 _CONNS 에 들어가기 전까지 그 끝점을 예약한다.
# socket://·rfc2217:// 는 pyserial 이 exclusive 를 무시하므로 같은 서버 안의 동시 연결은 이 예약과 _CONNS 비교로만 막는다.
_CONNECTING: dict[str, str] = {}


def _port_holder(key: str, case_id: str) -> str | None:
    """같은 끝점(P.port_key)을 다른 케이스가 쓰고 있거나 누군가 연결 중이면 그 케이스 id. _CONNS_LOCK 안에서 부른다."""
    for c in _CONNS.values():
        if not c.closed and c.case_id != case_id and P.port_key(c.port) == key:
            return c.case_id
    return _CONNECTING.get(key)


def _get_conn(case_id: str) -> Connection:
    with _CONNS_LOCK:
        conn = _CONNS.get(case_id)
    if conn is None or conn.closed:
        raise NotFound(
            f"케이스 {case_id} 에 연결된 JTAGulator 가 없습니다.",
            hint="jtagulator_connect(case_id, port) 로 먼저 연결하세요.",
        )
    return conn


@contextlib.contextmanager
def _op(conn: Connection, *, allow_dead: bool = False) -> Iterator[None]:
    """연결 단위 직렬화 + 실행 중 스캔이 있으면 Busy."""
    if not conn.lock.acquire(timeout=3.0):
        raise Busy("JTAGulator 가 다른 작업에 사용 중입니다.", hint="잠시 후 다시 시도하세요.")
    try:
        jid = conn.busy_job()
        if jid:
            raise Busy(
                f"JTAGulator 스캔이 실행 중입니다 (job {jid}).",
                hint="jtagulator_job_status 로 기다리거나 jtagulator_job_cancel 로 중단하세요. 실행 중 스캔에 키를 보내면 스캔이 중단됩니다.",
            )
        if conn.closed:
            raise NotFound("연결이 이미 닫혔습니다.")
        if not allow_dead:
            conn.link.check()
        yield
    finally:
        conn.lock.release()


def _require_firmware(conn: Connection) -> None:
    if not conn.firmware_supported and not conn.allow_untested_firmware:
        raise DeviceError(
            f"지원하지 않는 JTAGulator 펌웨어입니다 (FW {conn.firmware}). 자동 조작은 FW 1.10–1.12 만 지원합니다.",
            code="firmware_unsupported",
            hint="JTAGulator 펌웨어를 1.12 로 업데이트하는 것을 권장합니다. 위험을 이해하고 시험하려면 jtagulator_connect(allow_untested_firmware=true).",
        )


def _require_scan_ready(conn: Connection) -> None:
    _require_firmware(conn)
    if not conn.voltage_ready:
        raise SafetyDenied(
            "타깃 I/O 전압이 이 연결에서 설정·확인되지 않아 스캔을 거부합니다.",
            code="voltage_not_set",
            hint=(
                "사람이 멀티미터로 타깃의 I/O 전압(VCC/VCCIO)을 측정해 알려 주면 jtagulator_set_voltage(case_id, volts) 를 호출하세요 "
                "(DESTRUCTIVE — 사람 승인 필요). 연결할 때마다(DTR 리셋) 다시 설정해야 합니다."
            ),
            data={"voltage": conn.voltage},
        )


def _register(case: Any, path: Path | str, description: str, extra: dict[str, Any] | None = None) -> dict[str, Any] | None:
    try:
        return case.register_artifact(path, kind="other", producer=SERVER_NAME, description=description, extra=extra)
    except Exception:  # noqa: BLE001 - 기록 실패가 장치 정리를 막지 않게
        log.exception("artifact registration failed: %s", path)
        return None


def _next_session_n(case: Any) -> int:
    jdir = case.subdir("jtag")
    n = 1
    while (jdir / f"jtagulator-{n:03d}.log").exists() or any(jdir.glob(f"jtagulator-{n:03d}-*")):
        n += 1
    return n


def _openocd_scripts() -> str | None:
    val = (rt().config.tools.get("openocd_scripts") or "").strip() or os.environ.get("PWEH_OPENOCD_SCRIPTS", "").strip()
    return os.path.expanduser(val) if val else None


def _safety_kw() -> dict[str, Any]:
    s = rt().config.safety
    return {"persistent_paths": s.persistent_paths, "unknown_risk": s.unknown_command_risk}


def _close_conn(conn: Connection, note: str) -> None:
    conn.closed = True
    try:
        conn.transcript.note(note)
    except Exception:  # noqa: BLE001
        pass
    try:
        conn.driver.close()
    finally:
        conn.transcript.close()


# ---------------------------------------------------------------------------
# 연결
# ---------------------------------------------------------------------------


@server.tool(
    description=(
        "JTAGulator 에 연결(USB-시리얼, 기본 115200 8N1). port 는 장치 경로(/dev/ttyUSB0) 또는 루프백 pyserial URL"
        "(socket://127.0.0.1:<포트> — LAN 호스트는 validation_failed). "
        "포트를 열면 FT232 DTR 로 JTAGulator 가 리셋될 수 있으므로 Ctrl-X 재동기화로 메뉴 프롬프트를 찾고 펌웨어 버전을 읽는다. "
        "영속 모드(OpenOCD/로직 분석기)였다면 빠져나오며 경고한다. 연결할 때마다 서버의 전압 상태는 '미설정'으로 초기화된다. "
        "세션 원시 기록은 jtag/jtagulator-<n>.log. 지원 펌웨어 1.10–1.12."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def jtagulator_connect(
    case_id: str,
    port: str,
    baudrate: int = 115200,
    timeout_seconds: float = 12.0,
    allow_untested_firmware: bool = False,
    ctx: Context | None = None,
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id, hardware=True)
    port = P.validate_port(port)
    try:
        baudrate = int(baudrate)
    except (TypeError, ValueError):
        raise ValidationFailed("baudrate 는 정수여야 합니다.")
    if not 1200 <= baudrate <= 3_000_000:
        raise ValidationFailed(f"baudrate 범위 밖: {baudrate}")
    timeout_seconds = max(3.0, min(float(timeout_seconds), 60.0))

    # 같은 끝점의 다른 표기(socket://127.0.0.1:P = socket://localhost:P = rfc2217://[::1]:P, by-id 링크 = /dev/ttyUSB0)는 한 포트로 본다
    key = P.port_key(port)
    with _CONNS_LOCK:
        existing = _CONNS.get(case_id)
        holder = _port_holder(key, case_id)
    if holder is not None:
        raise Busy(f"포트 {port} 는 이미 케이스 {holder} 가 사용 중입니다(같은 끝점의 다른 표기 포함).",
                   hint="그 케이스에서 jtagulator_disconnect 를 먼저 하세요.")
    if existing is not None and not existing.closed and P.port_key(existing.port) != key and existing.link.alive:
        raise Busy(
            f"이 케이스는 이미 {existing.port} 에 연결되어 있습니다.",
            hint="jtagulator_disconnect 후 다시 연결하세요.",
        )

    resync_cls = classify_jtagulator(P.RESYNC_FIRST, P.DeviceContext("unknown"))
    decision = await r.authorize(
        tool="jtagulator_connect", action={"port": port, "baudrate": baudrate}, classification=resync_cls,
        case_id=case_id, ctx=ctx, summary=f"JTAGulator 연결·재동기화 ({port})",
    )
    if not decision.allowed:
        return gate_response(decision)

    if existing is not None and not existing.closed and existing.link.alive:
        def rework() -> dict[str, Any]:
            with _op(existing):
                # 다시 연결 = 타깃이 바뀌었을 수 있음 → 전압 상태를 항상 '미설정'으로 (재측정·재승인 필요)
                existing.voltage = None
                existing.driver.voltage = None
                existing.token = "jc-" + secrets.token_hex(4)  # 이전 연결 시점의 승인 무효화
                existing.transcript.note("connect (reuse): voltage state cleared")
                info = existing.driver.resync(timeout_seconds)
                existing.connect_info = {**info, "version_lines": existing.connect_info.get("version_lines")}
                return info

        info = await run_blocking(rework)
        return {
            "ok": True, "reused": True, "connection": existing.status(), "firmware": existing.firmware, "resync": info,
            "warnings": _resync_warnings(info) + ["기존 연결을 재사용했습니다. 서버의 전압 상태는 초기화되었으므로 전압을 다시 설정해야 합니다."],
        }
    if existing is not None:
        with _CONNS_LOCK:
            _CONNS.pop(case_id, None)
        with contextlib.suppress(Exception):
            _close_conn(existing, "stale connection replaced")
        _register(case, existing.transcript_rel, f"JTAGulator 세션 원시 기록 ({existing.port}, 끊긴 연결)",
                  {"type": "session-transcript", "port": existing.port})

    with _CONNS_LOCK:  # 승인을 기다리는 동안 다른 케이스가 같은 끝점에 붙었을 수 있다 → 다시 확인하고 예약
        holder = _port_holder(key, case_id)
        if holder is not None:
            raise Busy(f"포트 {port} 는 이미 케이스 {holder} 가 사용 중이거나 연결 중입니다.",
                       hint="그 케이스에서 jtagulator_disconnect 를 먼저 하세요.")
        _CONNECTING[key] = case_id

    def work() -> Connection:
        n = _next_session_n(case)
        rel = f"jtag/jtagulator-{n:03d}.log"
        transcript = Transcript(case.path(rel), {"case_id": case_id, "port": port, "baudrate": baudrate, "server": SERVER_NAME})
        try:
            link = SerialLink(port, baudrate, transcript=transcript)
        except Exception as exc:
            transcript.note(f"open failed: {exc}")
            transcript.close()
            _register(case, rel, f"JTAGulator 세션 원시 기록 (연결 실패: {port})", {"type": "session-transcript", "port": port})
            raise
        driver = JTAGulatorDriver(link, **_safety_kw())
        try:
            info = driver.resync(timeout_seconds)
            ver = driver.version()
        except Exception as exc:
            transcript.note(f"connect failed: {exc}")
            driver.close()
            transcript.close()
            _register(case, rel, f"JTAGulator 세션 원시 기록 (연결 실패: {port})", {"type": "session-transcript", "port": port})
            raise
        conn = Connection(
            case_id=case_id, port=port, baudrate=baudrate, link=link, driver=driver, transcript=transcript,
            transcript_rel=rel, session_n=n, opened_at=utcnow_iso(), firmware=ver["firmware"],
            firmware_supported=bool(ver["supported"]), allow_untested_firmware=bool(allow_untested_firmware),
            connect_info={**info, "version_lines": ver["lines"]},
        )
        with _CONNS_LOCK:
            _CONNS[case_id] = conn
        _register(case, rel, f"JTAGulator 세션 원시 기록 ({port}, FW {ver['firmware']})", {"type": "session-transcript", "port": port})
        return conn

    try:
        conn = await run_blocking(work)
    finally:
        with _CONNS_LOCK:
            _CONNECTING.pop(key, None)
    r.audit(
        {"event": "jtagulator_connected", "port": port, "firmware": conn.firmware, "resync": conn.connect_info,
         "transcript": conn.transcript_rel},
        case_id,
    )
    warnings = _resync_warnings(conn.connect_info)
    if not conn.firmware_supported:
        warnings.append(
            f"FW {conn.firmware} 은 지원 범위(1.10–1.12) 밖입니다. 펌웨어 업데이트를 권장하며, allow_untested_firmware 없이는 "
            "전압 설정·스캔을 거부합니다."
        )
    if baudrate != 115200:
        warnings.append("JTAGulator 호스트 링크는 115200 bps 고정입니다. 다른 보드레이트로는 통신되지 않을 수 있습니다.")
    return {
        "ok": True,
        "reused": False,
        "connection": conn.status(),
        "firmware": conn.firmware,
        "version_lines": conn.connect_info.get("version_lines"),
        "resync": {k: v for k, v in conn.connect_info.items() if k != "version_lines"},
        "warnings": warnings,
        "next_steps": [
            "사람이 멀티미터로 타깃의 I/O 전압을 측정해 알려 달라고 요청한다(추정 금지).",
            "jtagulator_set_voltage(case_id, volts) — DESTRUCTIVE, 사람 승인 필요.",
            "수동 관찰부터: jtagulator_uart_txd_scan → 능동 스캔(jtagulator_uart_scan / jtagulator_idcode_scan 등).",
        ],
    }


def _resync_warnings(info: dict[str, Any]) -> list[str]:
    out = []
    mode = info.get("persistent_mode_exited")
    if mode:
        out.append(
            f"JTAGulator 가 영속 모드({mode})였고 Ctrl-X 로 빠져나왔습니다. 이 모드는 저장된 VADJ 를 리셋 후에도 출력하며, 빠져나온 뒤에도 "
            "VADJ 노드에 이전 전압이 남아 있을 수 있습니다(화면에는 Undefined). 다른 타깃에 연결하기 전에 전압을 다시 설정하세요."
        )
    if info.get("passthrough_exited"):
        out.append("UART 패스스루 모드였고 Ctrl-X 로 빠져나왔습니다.")
    if info.get("aborted_running_scan"):
        out.append(f"실행 중이던 {info['aborted_running_scan']} 스캔을 중단시켰습니다.")
    if info.get("eeprom_error"):
        out.append("JTAGulator 가 'EEPROM not responding!' 을 보고했습니다 — 장치 점검이 필요합니다.")
    return out


@server.tool(
    description=(
        "JTAGulator 연결 종료. 실행 중인 스캔이 있으면 먼저 중단(LF)하고 끝날 때까지 기다린 뒤 포트를 닫고 세션 기록을 등록한다. "
        "권장 순서: 타깃 전원을 먼저 끈 다음 호출 (포트를 닫으면 DTR 리셋으로 VADJ 가 꺼질 수 있음)."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def jtagulator_disconnect(case_id: str) -> dict[str, Any]:
    r = rt()
    conn = _get_conn(case_id)
    try:
        case: Any = r.cases.get(case_id)  # 정리 작업이므로 권한 증명 없이도 허용 (장치를 안전한 쪽으로만 바꿈)
    except PwehError:
        case = None  # 케이스가 사라졌어도 포트는 닫는다

    def work() -> dict[str, Any]:
        out: dict[str, Any] = {}
        jid = conn.busy_job()
        if jid:
            r.jobs.cancel(jid)
            r.jobs.wait(jid, 30.0)
            out["cancelled_job"] = jid
            out["cancelled_job_status"] = r.jobs.get(jid).status
        got = conn.lock.acquire(timeout=10.0)
        try:
            with _CONNS_LOCK:
                if _CONNS.get(case_id) is conn:
                    _CONNS.pop(case_id, None)
            _close_conn(conn, "disconnect")
        finally:
            if got:
                conn.lock.release()
        if case is not None:
            _register(case, conn.transcript_rel, f"JTAGulator 세션 원시 기록 ({conn.port}, FW {conn.firmware})",
                      {"type": "session-transcript", "port": conn.port})
        return out

    out = await run_blocking(work)
    r.audit({"event": "jtagulator_disconnected", "port": conn.port, **out}, case_id)
    return {
        "ok": True,
        "port": conn.port,
        "transcript": conn.transcript_rel,
        **out,
        "note": "포트를 닫았습니다. JTAGulator 가 리셋되면 전압은 Undefined 가 됩니다. 다시 연결하면 전압을 다시 설정해야 합니다.",
    }


@server.tool(
    description="JTAGulator 펌웨어 버전/배너 정보 (메인 메뉴 'I'). 지원 범위(1.10–1.12) 여부도 반환.",
    annotations=ANN_DEVICE,
)
@safe_tool
async def jtagulator_version(case_id: str, ctx: Context | None = None) -> dict[str, Any]:
    r = rt()
    r.case(case_id, hardware=True)
    conn = _get_conn(case_id)
    cls = classify_jtagulator("I\r", P.DeviceContext("menu", menu="main"))
    decision = await r.authorize(
        tool="jtagulator_version", action={"port": conn.port, "command": "I"}, classification=cls, case_id=case_id, ctx=ctx,
    )
    if not decision.allowed:
        return gate_response(decision)

    def work() -> dict[str, Any]:
        with _op(conn):
            v = conn.driver.version()
            conn.firmware = v["firmware"]
            conn.firmware_supported = bool(v["supported"])
            return v

    v = await run_blocking(work)
    return {"ok": True, "firmware": v["firmware"], "supported": v["supported"], "version_lines": v["lines"], "port": conn.port}


@server.tool(
    description="JTAGulator 연결 상태(장치 I/O 없음): 포트, 펌웨어, 현재 메뉴, 이 연결에서 확인된 전압, 실행 중 작업. case_id 생략 시 전체.",
    annotations=ANN_READ_ONLY,
)
@safe_tool
def jtagulator_status(case_id: str | None = None) -> dict[str, Any]:
    with _CONNS_LOCK:
        conns = [c for c in _CONNS.values() if not c.closed and (case_id is None or c.case_id == case_id)]
    if case_id is not None and not conns:
        return {"ok": True, "connected": False, "case_id": case_id, "connections": []}
    return {"ok": True, "connected": bool(conns), "connections": [c.status() for c in conns]}


# ---------------------------------------------------------------------------
# 전압 (DESTRUCTIVE)
# ---------------------------------------------------------------------------

OPERATOR_VOLTAGE_CHECKLIST = [
    "타깃 전원을 끈 상태에서 GND 를 먼저 연결했는가",
    "멀티미터로 타깃의 I/O 전압(디버그 헤더 VCC/VREF, SoC VCCIO, UART 레벨)을 직접 측정했는가 — 추정 금지",
    "요청한 전압이 측정값과 같은가 (예: 3.3 V / 1.8 V)",
    "JTAGulator 의 VADJ 핀이 타깃에 연결되어 있지 않은가 (VADJ 는 타깃 전원이 아님)",
]


@server.tool(
    description=(
        "JTAGulator 타깃 I/O 전압(VADJ) 설정 — DESTRUCTIVE(기본 거부). 잘못된 전압은 타깃 I/O 를 손상시킬 수 있다. "
        "사람이 멀티미터로 타깃 I/O 전압을 측정한 값만 사용한다(1.4–3.3 V, 0.1 V 단위; 0 = 끄기). "
        "status=approval_required 이면 사용자에게 측정값 확인과 `pweh approve <id>` 를 요청하고 같은 인자 + approval_id 로 재호출. "
        "장치가 'New target I/O voltage set: x.y' 로 확인해야 스캔이 허용된다."
    ),
    annotations=ANN_DESTRUCTIVE,
    meta=META_REQUIRE_HUMAN,
)
@safe_tool
async def jtagulator_set_voltage(
    case_id: str, volts: float, approval_id: str | None = None, ctx: Context | None = None
) -> dict[str, Any]:
    r = rt()
    r.case(case_id, hardware=True)
    v = P.normalize_volts(volts)  # 게이트 전에 검증 (잘못된 값으로 승인 레코드가 생기지 않게)
    conn = _get_conn(case_id)
    _require_firmware(conn)
    if conn.busy_job():
        raise Busy("스캔이 실행 중이라 전압을 바꿀 수 없습니다.", hint="jtagulator_job_cancel 로 먼저 중단하세요.")
    plan = build_voltage_plan(v)
    cls = plan.steps[1].classification  # 전압 답 단계(DESTRUCTIVE) — 승인 화면에 가장 정확한 설명
    summary = (
        f"JTAGulator({conn.port}) 타깃 I/O 전압을 {v} V 로 {'끄기' if v == '0' else '설정'} — "
        "사람이 멀티미터로 타깃 I/O 전압을 측정해 일치함을 확인한 경우에만 승인하세요. VADJ 핀은 타깃에 연결하지 않습니다."
    )
    decision = await r.authorize(
        tool="jtagulator_set_voltage", action={"port": conn.port, "connection": conn.token, "volts": v}, classification=cls,
        case_id=case_id, approval_id=approval_id, ctx=ctx, summary=summary,
    )
    if not decision.allowed:
        return gate_response(decision, volts=v, operator_checklist=OPERATOR_VOLTAGE_CHECKLIST)
    plan.authorize(max(s.classification.risk for s in plan.steps))

    def work() -> dict[str, Any]:
        with _op(conn):
            conn.voltage = None
            try:
                res = conn.driver.set_voltage(v, plan)
            except Exception:
                conn.voltage = None
                raise
            conn.voltage = res["volts"]
            conn.voltage_set_at = utcnow_iso()
            conn.voltage_via = decision.via
            return res

    res = await run_blocking(work)
    r.audit(
        {"event": "jtagulator_voltage_set", "port": conn.port, "volts": res["volts"], "previous": res["previous"],
         "via": decision.via, "approval_id": decision.approval_id},
        case_id,
    )
    warnings = ["VADJ 핀을 타깃에 연결하지 마세요 (펌웨어 경고: Ensure VADJ is NOT connected to target!)."]
    if res["volts"] != "0":
        warnings.append("권장 순서: 전압 설정 → 타깃 전원 켜기 → 스캔 → 타깃 전원 끄기 → 연결 해제.")
    else:
        warnings.append("VADJ 를 껐습니다. 스캔은 전압을 다시 설정해야 가능합니다. 타깃 전원이 켜져 있으면 클램프 다이오드로 전류가 흐를 수 있습니다.")
    return {
        "ok": True,
        "volts": res["volts"],
        "previous": res["previous"],
        "scans_allowed": conn.voltage_ready,
        "device_output": res["device_output"],
        "approved_via": decision.via,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# 스캔 (MODIFY, 백그라운드 작업)
# ---------------------------------------------------------------------------

SCAN_TITLES = {
    "idcode": "IDCODE 스캔",
    "bypass": "BYPASS 스캔",
    "jtag": "JTAG Combined 스캔",
    "uart": "UART 스캔",
    "uart_txd": "UART TXD(수동) 스캔",
}


def _validate_pins_low(pins_low: bool, pins_low_ms: int, pins_high_ms: int) -> tuple[bool, int, int]:
    return bool(pins_low), P.validate_ms("pins_low_ms", pins_low_ms, 1, 1000), P.validate_ms("pins_high_ms", pins_high_ms, 1, 1000)


def _scan_paths(case: Any, conn: Connection, kind: str) -> tuple[str, str]:
    conn.scan_seq += 1
    base = f"jtag/jtagulator-{conn.session_n:03d}-{kind.replace('_', '-')}-{conn.scan_seq}"
    jdir = case.subdir("jtag")
    while (jdir / Path(base).name).with_suffix(".log").exists():
        conn.scan_seq += 1
        base = f"jtag/jtagulator-{conn.session_n:03d}-{kind.replace('_', '-')}-{conn.scan_seq}"
    return base + ".log", base + ".json"


async def _start_scan(
    tool: str,
    case_id: str,
    spec: ScanSpec,
    *,
    approval_id: str | None,
    ctx: Context | None,
    idle_timeout: float,
    max_duration: float | None,
    duration: float | None = None,
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id, hardware=True)
    conn = _get_conn(case_id)
    _require_scan_ready(conn)
    if conn.busy_job():
        raise Busy(f"이미 스캔이 실행 중입니다 (job {conn.busy_job()}).", hint="jtagulator_job_status / jtagulator_job_cancel")
    plan = build_scan_plan(spec, **_safety_kw())
    cls = plan.worst()
    if cls.risk >= Risk.DESTRUCTIVE:
        # 핀 스캔에 DESTRUCTIVE 단계(예: 'sf erase …' 같은 UART 프로브)가 필요한 정당한 경우는 없다 → 승인 요청 없이 거부
        r.audit({"event": "jtagulator_scan_refused", "scan": spec.kind, "classification": cls.to_dict()}, case_id)
        raise SafetyDenied(
            f"스캔 계획에 DESTRUCTIVE 단계가 있어 실행하지 않습니다: {cls.reason}",
            hint="UART 프로브 문자열(text)은 대상 콘솔로 반복 전송됩니다. 무해한 값(기본 '\\r')을 쓰세요.",
            data={"classification": cls.to_dict()},
        )
    perms = spec.expected_permutations()
    summary = (
        f"JTAGulator {SCAN_TITLES[spec.kind]} — CH{spec.start}–CH{spec.end}"
        + (f", 순열 {perms}" if perms else "") + f", 전압 {conn.voltage} V ({conn.port})"
    )
    decision = await r.authorize(
        tool=tool, action={"port": conn.port, "connection": conn.token, "volts": conn.voltage, **spec.action()}, classification=cls,
        case_id=case_id, approval_id=approval_id, ctx=ctx, summary=summary,
    )
    if not decision.allowed:
        return gate_response(decision, plan=plan.describe())
    plan.authorize(cls.risk)

    # 작업(job)이 보낼 키는 중단 키(LF)뿐이다 — 시작 전에 INTERACT 이하인지 확인
    job_plan_cls = classify_jtagulator(P.KEY_ABORT_SCAN, P.DeviceContext("scanning"))
    if job_plan_cls.risk > Risk.INTERACT:  # pragma: no cover - 분류 규칙이 바뀌면 시작 거부
        raise SafetyDenied("백그라운드 작업의 계획 명령이 INTERACT 를 넘어 시작을 거부합니다.")

    min_idle = 3.0 * spec.dash_interval_lower_bound() + 30.0
    idle = max(float(idle_timeout), min_idle)

    def work() -> tuple[Any, ScanRun, str, str]:
        with _op(conn):
            _require_scan_ready(conn)
            raw_rel, json_rel = _scan_paths(case, conn, spec.kind)
            raw_path = case.path(raw_rel)
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_fh = raw_path.open("ab")

            def sink(data: bytes) -> None:
                try:
                    raw_fh.write(data)
                    raw_fh.flush()
                except (OSError, ValueError):
                    pass

            conn.link.add_sink(sink)
            conn.transcript.note(f"scan start: {spec.kind} {spec.to_dict()}")
            try:
                run = conn.driver.start_scan(spec, plan)
            except BaseException as exc:
                conn.link.remove_sink(sink)
                raw_fh.close()
                if isinstance(exc, VoltageNotDefined):
                    conn.voltage = None
                _register(case, raw_rel, f"JTAGulator {SCAN_TITLES[spec.kind]} 원시 출력 (시작 실패)",
                          {"type": "scan-raw", "scan": spec.kind, "status": "start_failed"})
                raise

            def job_fn(jctx: JobContext) -> dict[str, Any]:
                return _scan_job(jctx, conn, case_id, run, raw_rel, json_rel, raw_fh, sink, idle, max_duration, duration)

            try:
                job = r.jobs.start(
                    f"jtagulator-{spec.kind}-scan", job_fn,
                    description=f"JTAGulator {SCAN_TITLES[spec.kind]} CH{spec.start}-{spec.end} ({conn.port})",
                    case_id=case_id,
                    meta={"port": conn.port, "scan": spec.kind, "permutations": run.permutations, "raw_log": raw_rel, "result_json": json_rel},
                    exclusive_key=f"port:{P.port_key(conn.port)}",
                )
            except BaseException:
                with contextlib.suppress(Exception):
                    conn.driver.send(P.KEY_ABORT_SCAN)
                conn.link.remove_sink(sink)
                raw_fh.close()
                raise
            conn.active_job_id = job.id
            return job, run, raw_rel, json_rel

    job, run, raw_rel, json_rel = await run_blocking(work)
    r.audit(
        {"event": "jtagulator_scan_started", "scan": spec.kind, "job_id": job.id, "port": conn.port,
         "options": spec.to_dict(), "permutations": run.permutations, "voltage": conn.voltage, "via": decision.via},
        case_id,
    )
    lb = spec.lower_bound_seconds()
    out: dict[str, Any] = {
        "ok": True,
        "job_id": job.id,
        "scan": spec.kind,
        "channels": {"start": spec.start, "end": spec.end},
        "permutations": run.permutations,
        "target_voltage": conn.voltage,
        "raw_log": raw_rel,
        "result_json": json_rel,
        "idle_timeout_seconds": round(idle, 1),
        "poll": f"jtagulator_job_status(job_id='{job.id}', wait_seconds=30)",
        "cancel": f"jtagulator_job_cancel(job_id='{job.id}')",
    }
    if lb is not None:
        out["lower_bound_seconds"] = lb
        out["estimate_note"] = (
            "lower_bound_seconds 는 펌웨어 코드와 문서화된 JTAG 클럭 상한(25 kHz)으로 계산한 '최소' 시간이며 실측이 아니다. "
            "실제 남은 시간은 job_status 의 eta_seconds(진행률 기반)를 본다."
        )
    if duration is not None:
        out["duration_seconds"] = duration
    if spec.kind == "uart":
        out["text_hex"] = (spec.uart_probe or b"").hex().upper()
    return out


def _scan_job(
    jctx: JobContext,
    conn: Connection,
    case_id: str,
    run: ScanRun,
    raw_rel: str,
    json_rel: str,
    raw_fh: Any,
    sink: Any,
    idle_timeout: float,
    max_duration: float | None,
    duration: float | None,
) -> dict[str, Any]:
    r = rt()
    spec = run.spec
    jctx.log(f"{spec.kind} 스캔 감시 시작 (순열 {run.permutations})")

    def on_progress(p: dict[str, Any]) -> None:
        if spec.kind == "uart_txd" and duration:
            jctx.progress(min(p["elapsed_seconds"], duration), duration, f"TXD 감시 중 — 활동 채널 {p.get('found', 0)}개")
        else:
            jctx.progress(p["done"], p["total"] or None, f"진행 표시 {p['dashes']}개, 결과 {p['found']}건")
        jctx.update_meta(found=p.get("found"))

    monitor_error: BaseException | None = None
    try:
        outcome = conn.driver.monitor_scan(
            run, should_cancel=lambda: jctx.cancelled, on_progress=on_progress,
            idle_timeout=idle_timeout, max_seconds=max_duration, duration=duration,
        )
    except Exception as exc:  # noqa: BLE001 - 부분 결과라도 저장한 뒤 다시 올린다
        monitor_error = exc
        log.exception("scan monitor failed")
        conn.transcript.note(f"scan monitor failed: {exc!r}")
        outcome = ScanOutcome(
            reason="error", ended=False, scan_text=conn.link.text_since(run.scan_offset),
            full_text=conn.link.text_since(run.dialog_offset), elapsed=round(time.monotonic() - run.t0, 2), sent=[],
        )
    finally:
        conn.link.remove_sink(sink)
        with contextlib.suppress(Exception):
            raw_fh.close()

    result = _build_scan_result(conn, case_id, run, outcome, raw_rel, json_rel)
    found = (result.get("summary") or {}).get("count", 0)
    if outcome.reason in (None, "duration") and outcome.ended:
        total = float(run.permutations or duration or 1)
        jctx.progress(total, total, f"완료 — 결과 {found}건")
    else:
        jctx.update_meta(found=found)
    case = r.cases.get(case_id)
    try:
        atomic_write_json(case.path(json_rel), result)
    except Exception:  # noqa: BLE001
        log.exception("scan result write failed")
    extra = {"type": "scan-raw", "scan": spec.kind, "status": result["status"], "job_id": jctx.job.id}
    _register(case, raw_rel, f"JTAGulator {SCAN_TITLES[spec.kind]} 원시 출력 ({result['status']})", extra)
    _register(case, json_rel, f"JTAGulator {SCAN_TITLES[spec.kind]} 결과 ({result['status']})", {**extra, "type": "scan-result"})
    _register(case, conn.transcript_rel, f"JTAGulator 세션 원시 기록 ({conn.port}, FW {conn.firmware})",
              {"type": "session-transcript", "port": conn.port})
    r.audit(
        {"event": "jtagulator_scan_finished", "scan": spec.kind, "job_id": jctx.job.id, "status": result["status"],
         "best": (result.get("summary") or {}).get("best"), "result_json": json_rel},
        case_id,
    )
    brief = {"status": result["status"], "result_json": json_rel, "raw_log": raw_rel, "best": (result.get("summary") or {}).get("best")}
    if monitor_error is not None:
        if isinstance(monitor_error, PwehError):
            monitor_error.data = {**(monitor_error.data or {}), **brief}
            raise monitor_error
        raise DeviceError(f"스캔 감시 중 오류: {type(monitor_error).__name__}: {monitor_error}", data=brief) from monitor_error
    reason = outcome.reason
    if reason in (None, "duration", "cancelled"):
        jctx.log(f"스캔 종료: {result['status']}")
        return result
    if reason == "timeout":
        raise TimeoutExpired(f"max_duration_seconds({max_duration}) 를 넘어 스캔을 중단했습니다.", data=brief)
    if reason == "stalled":
        raise DeviceError(
            f"{idle_timeout:.0f}초 동안 JTAGulator 출력이 없어 스캔을 중단했습니다.", code="device_stalled",
            hint="USB 연결/전원을 확인하세요. 장치가 리셋되었다면 다시 연결하고 전압을 재설정해야 합니다.", data=brief,
        )
    raise DeviceError(f"스캔 중 연결 문제: {reason}", code="disconnected", data=brief)


def _build_scan_result(
    conn: Connection, case_id: str, run: ScanRun, outcome: ScanOutcome, raw_rel: str, json_rel: str
) -> dict[str, Any]:
    spec = run.spec
    text = outcome.scan_text
    status = parse_status(text, spec.kind)
    if spec.kind in ("idcode", "bypass", "jtag"):
        summary = summarize_jtag(parse_jtag_blocks(text), spec.kind, _openocd_scripts())
    elif spec.kind == "uart":
        summary = summarize_uart(parse_uart_hits(text))
    else:
        summary = summarize_txd(parse_txd_hits(text))
    reason = outcome.reason
    if reason is None:
        st = "completed" if status["completed"] else ("aborted" if status["aborted"] else "ended")
    else:
        st = {"duration": "completed", "cancelled": "cancelled", "timeout": "timed_out", "stalled": "stalled"}.get(reason, reason)
    warnings: list[str] = []
    if spec.pins_low and spec.kind == "uart" and "pins_low" not in run.asked:
        warnings.append(f"FW {conn.firmware} 의 UART 스캔에는 '채널 LOW' 옵션이 없어 pins_low 가 적용되지 않았습니다.")
    if status["banner_seen"] or "Target I/O voltage must be defined!" in status["errors"]:
        conn.voltage = None
        warnings.append("스캔 도중 장치 리셋 흔적 — 전압 설정이 사라졌을 수 있어 서버 전압 상태를 초기화했습니다.")
    if reason in ("stalled", "disconnected", "abort_failed"):
        warnings.append("장치 상태를 확신할 수 없습니다. 연결을 다시 하고 전압을 재설정하세요.")
    return {
        "schema": "pweh.jtagulator-scan/v1",
        "scan": spec.kind,
        "case_id": case_id,
        "port": conn.port,
        "firmware": conn.firmware,
        "target_voltage": conn.voltage,
        "channels": {"start": spec.start, "end": spec.end},
        "options": spec.to_dict(),
        "permutations": run.permutations,
        "status": st,
        "device": {
            "completed": status["completed"],
            "aborted": status["aborted"],
            "no_device_found": status["no_device_found"],
            "errors": status["errors"],
        },
        "started_at": run.started_at,
        "finished_at": utcnow_iso(),
        "duration_seconds": outcome.elapsed,
        "summary": summary,
        "dialog_answers_sent": run.asked,
        "warnings": warnings,
        "tx": run.sent + outcome.sent,
        "artifacts": {"raw_log": raw_rel, "result_json": json_rel, "session_transcript": conn.transcript_rel},
    }


_SCAN_COMMON_DOC = (
    "채널 번호는 JTAGulator 의 CH0–CH23. 스캔은 범위 안의 모든 채널을 출력 HIGH 로 구동한다(MODIFY) — 채널이 전원 레일·리셋·부트모드 "
    "핀에 물려 있지 않은지 확인. 이 연결에서 jtagulator_set_voltage 로 전압이 확인되어야 시작한다. pins_low=true 면 순열마다 채널을 "
    "LOW 로 pins_low_ms 동안 내렸다가 올리고 pins_high_ms 기다린다(타깃 리셋용, 훨씬 느려짐). job_id 를 반환하며 "
    "jtagulator_job_status 로 진행률/결과, jtagulator_job_cancel 로 중단. idle_timeout_seconds 동안 장치 출력이 없으면 중단, "
    "max_duration_seconds 를 주면 그 시간 뒤 중단. 결과: jtag/jtagulator-<n>-<scan>-<k>.json, 원시 출력 .log."
)


@server.tool(
    description=(
        "JTAG IDCODE 스캔(JTAG 메뉴 'I'): TDO/TCK/TMS(+TRST# 후보)와 Device ID 를 찾는다(TDI 는 찾지 못함 → bypass/jtag 스캔). "
        "IDCODE 는 JEP106 제조사로 해석. 순열 = n!/(n-3)!. " + _SCAN_COMMON_DOC
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def jtagulator_idcode_scan(
    case_id: str,
    start_channel: int,
    end_channel: int,
    pins_low: bool = False,
    pins_low_ms: int = 100,
    pins_high_ms: int = 100,
    idle_timeout_seconds: float = 120.0,
    max_duration_seconds: float | None = None,
    approval_id: str | None = None,
    ctx: Context | None = None,
) -> dict[str, Any]:
    s, e = P.validate_channels("idcode", start_channel, end_channel)
    pl, lo, hi = _validate_pins_low(pins_low, pins_low_ms, pins_high_ms)
    spec = ScanSpec(kind="idcode", start=s, end=e, pins_low=pl, pins_low_ms=lo, pins_high_ms=hi)
    return await _start_scan("jtagulator_idcode_scan", case_id, spec, approval_id=approval_id, ctx=ctx,
                             idle_timeout=idle_timeout_seconds, max_duration=_opt_seconds(max_duration_seconds))


@server.tool(
    description=(
        "JTAG BYPASS 스캔(JTAG 메뉴 'B'): TDI/TDO/TCK/TMS(+TRST# 후보)와 체인 장치 수를 찾는다. IDCODE 미지원 타깃도 찾을 수 있다. "
        "known_pins 로 이미 아는 핀을 고정하면 훨씬 빠르다(예: IDCODE 스캔 결과 {\"tdo\":2,\"tck\":0,\"tms\":1} → TDI 만 탐색). "
        "순열 = (n-k)!/(n-4)!, 24채널 전체는 255,024 순열로 매우 오래 걸린다. " + _SCAN_COMMON_DOC
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def jtagulator_bypass_scan(
    case_id: str,
    start_channel: int,
    end_channel: int,
    known_pins: dict[str, int] | None = None,
    pins_low: bool = False,
    pins_low_ms: int = 100,
    pins_high_ms: int = 100,
    idle_timeout_seconds: float = 120.0,
    max_duration_seconds: float | None = None,
    approval_id: str | None = None,
    ctx: Context | None = None,
) -> dict[str, Any]:
    s, e = P.validate_channels("bypass", start_channel, end_channel)
    known = P.validate_known_pins(known_pins, ("tdi", "tdo", "tck", "tms"), s, e, 4)
    pl, lo, hi = _validate_pins_low(pins_low, pins_low_ms, pins_high_ms)
    spec = ScanSpec(kind="bypass", start=s, end=e, known_pins=known, pins_low=pl, pins_low_ms=lo, pins_high_ms=hi)
    return await _start_scan("jtagulator_bypass_scan", case_id, spec, approval_id=approval_id, ctx=ctx,
                             idle_timeout=idle_timeout_seconds, max_duration=_opt_seconds(max_duration_seconds))


@server.tool(
    description=(
        "JTAG Combined 스캔(JTAG 메뉴 'J', FW 1.8+): IDCODE 순열을 돌다 유효한 IDCODE 가 나오면 남은 채널로 TDI 를 BYPASS 시험한다. "
        "TDI/TDO/TCK/TMS 와 Device ID 를 한 번에 찾으며 BYPASS 스캔보다 훨씬 빠르다(IDCODE 를 지원하는 타깃). " + _SCAN_COMMON_DOC
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def jtagulator_jtag_scan(
    case_id: str,
    start_channel: int,
    end_channel: int,
    pins_low: bool = False,
    pins_low_ms: int = 100,
    pins_high_ms: int = 100,
    idle_timeout_seconds: float = 120.0,
    max_duration_seconds: float | None = None,
    approval_id: str | None = None,
    ctx: Context | None = None,
) -> dict[str, Any]:
    s, e = P.validate_channels("jtag", start_channel, end_channel)
    pl, lo, hi = _validate_pins_low(pins_low, pins_low_ms, pins_high_ms)
    spec = ScanSpec(kind="jtag", start=s, end=e, pins_low=pl, pins_low_ms=lo, pins_high_ms=hi)
    return await _start_scan("jtagulator_jtag_scan", case_id, spec, approval_id=approval_id, ctx=ctx,
                             idle_timeout=idle_timeout_seconds, max_duration=_opt_seconds(max_duration_seconds))


@server.tool(
    description=(
        "UART 핀아웃 스캔(UART 메뉴 'U'): (TXD,RXD) 순열마다 보드레이트 21개(300–307200)로 text 를 후보 RXD 로 보내고 응답(최대 16바이트)을 "
        "받는다. TXD = 타깃 송신 핀, RXD = 타깃 수신 핀. text 기본 '\\r'(CR), 최대 16바이트, 정확히 그 바이트만 송신(hex 입력, "
        "백슬래시 이스케이프 \\r \\n \\xHH 해석 — 응답의 text_hex 로 실제 바이트 확인). "
        "text 는 대상 콘솔로 여러 번 전송되므로 콘솔 분류기로 검사한다(위험 명령 거부). known_pins={\"txd\":N} 로 TXD 고정 가능. "
        "delay_ms = 송신 후 응답 확인 전 대기(0–1000), printable_only=true 면 비출력 문자가 섞인 응답은 버림. "
        "셸이 열린 기기에서는 jtagulator_uart_txd_scan(수동)을 먼저 쓰는 것이 안전. " + _SCAN_COMMON_DOC
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def jtagulator_uart_scan(
    case_id: str,
    start_channel: int,
    end_channel: int,
    text: str = "\r",
    known_pins: dict[str, int] | None = None,
    delay_ms: int = 10,
    printable_only: bool = False,
    pins_low: bool = False,
    pins_low_ms: int = 100,
    pins_high_ms: int = 100,
    idle_timeout_seconds: float = 180.0,
    max_duration_seconds: float | None = None,
    approval_id: str | None = None,
    ctx: Context | None = None,
) -> dict[str, Any]:
    s, e = P.validate_channels("uart", start_channel, end_channel)
    known = P.validate_known_pins(known_pins, ("txd", "rxd"), s, e, 2)
    answer, probe = P.uart_probe_answer(P.decode_text_escapes(text))
    d = P.validate_ms("delay_ms", delay_ms, 0, 1000)
    pl, lo, hi = _validate_pins_low(pins_low, pins_low_ms, pins_high_ms)
    spec = ScanSpec(
        kind="uart", start=s, end=e, known_pins=known, pins_low=pl, pins_low_ms=lo, pins_high_ms=hi,
        uart_text=text, uart_answer=answer, uart_probe=probe, uart_delay_ms=d, printable_only=bool(printable_only),
    )
    return await _start_scan("jtagulator_uart_scan", case_id, spec, approval_id=approval_id, ctx=ctx,
                             idle_timeout=idle_timeout_seconds, max_duration=_opt_seconds(max_duration_seconds))


@server.tool(
    description=(
        "UART TXD 전용 수동 스캔(UART 메뉴 'T', FW 1.10+): 채널을 입력으로만 두고 duration_seconds 동안 UART 활동을 감시해 TXD 채널과 "
        "보드레이트(측정값/표준값)를 찾는다. 타깃에 아무것도 보내지 않아 가장 안전한 첫 단계 — 스캔 중에 사람이 타깃 전원을 다시 넣어 "
        "부팅 로그가 나오게 하면 좋다. ignore_nonstandard=true 면 표준 보드레이트에 맞지 않는 측정값은 버림. 레벨 변환기를 켜므로 "
        "전압 설정이 필요하다. job 으로 실행되며 기간이 끝나면 자동으로 멈춘다."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def jtagulator_uart_txd_scan(
    case_id: str,
    start_channel: int,
    end_channel: int,
    duration_seconds: float = 20.0,
    ignore_nonstandard: bool = False,
    idle_timeout_seconds: float = 60.0,
    approval_id: str | None = None,
    ctx: Context | None = None,
) -> dict[str, Any]:
    s, e = P.validate_channels("uart_txd", start_channel, end_channel)
    try:
        dur = float(duration_seconds)
    except (TypeError, ValueError):
        raise ValidationFailed("duration_seconds 는 숫자여야 합니다.")
    if not 1.0 <= dur <= 3600.0:
        raise ValidationFailed("duration_seconds 는 1–3600 초여야 합니다.")
    spec = ScanSpec(kind="uart_txd", start=s, end=e, ignore_nonstandard=bool(ignore_nonstandard))
    return await _start_scan("jtagulator_uart_txd_scan", case_id, spec, approval_id=approval_id, ctx=ctx,
                             idle_timeout=max(float(idle_timeout_seconds), dur + 30.0), max_duration=None, duration=dur)


def _opt_seconds(v: float | None) -> float | None:
    if v is None:
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        raise ValidationFailed("max_duration_seconds 는 숫자여야 합니다.")
    if f <= 0:
        raise ValidationFailed("max_duration_seconds 는 0 보다 커야 합니다.")
    return f


# ---------------------------------------------------------------------------
# 핀아웃을 알 때 (동기)
# ---------------------------------------------------------------------------


def _validate_distinct_pins(pins: dict[str, int]) -> dict[str, int]:
    out = {}
    for k, v in pins.items():
        try:
            ch = int(v)
        except (TypeError, ValueError):
            raise ValidationFailed(f"{k} 는 채널 번호(정수)여야 합니다.")
        if not 0 <= ch <= P.MAX_CHAN - 1:
            raise ValidationFailed(f"{k}={ch} 는 0–{P.MAX_CHAN - 1} 이어야 합니다.")
        out[k] = ch
    if len(set(out.values())) != len(out):
        raise ValidationFailed("핀 번호가 서로 겹칩니다 (펌웨어: 'Pin numbers must be unique!').")
    return out


async def _known_pins_command(
    tool: str, case_id: str, command: str, pins: dict[str, int], approval_id: str | None, ctx: Context | None
) -> tuple[Connection, str, str, str]:
    r = rt()
    case = r.case(case_id, hardware=True)
    conn = _get_conn(case_id)
    _require_scan_ready(conn)
    plan = build_known_pins_plan(command, pins)
    cls = plan.worst()
    decision = await r.authorize(
        tool=tool, action={"port": conn.port, "connection": conn.token, "volts": conn.voltage, "command": command, **pins}, classification=cls,
        case_id=case_id, approval_id=approval_id, ctx=ctx,
        summary=f"JTAGulator JTAG '{command}' (핀 {pins}) — 24채널 전부를 출력 HIGH 로 만든 뒤 지정 핀 구동 ({conn.port})",
    )
    if not decision.allowed:
        raise _GateBlocked(gate_response(decision, plan=plan.describe()))
    plan.authorize(cls.risk)

    def work() -> tuple[str, str]:
        with _op(conn):
            _require_scan_ready(conn)
            kind = "device-ids" if command == "D" else "bypass-test"
            conn.scan_seq += 1
            base = f"jtag/jtagulator-{conn.session_n:03d}-{kind}-{conn.scan_seq}"
            try:
                text = conn.driver.run_known_pins(command, pins, plan)
            except VoltageNotDefined:
                conn.voltage = None
                raise
            case.path(base + ".log").write_bytes(text.encode("latin-1"))
            return text, base

    text, base = await run_blocking(work)
    return conn, text, base, decision.via or ""


class _GateBlocked(Exception):
    def __init__(self, response: dict[str, Any]) -> None:
        super().__init__("gate blocked")
        self.response = response


@server.tool(
    description=(
        "핀아웃을 알 때 Device ID 읽기(JTAG 메뉴 'D'): TDO/TCK/TMS 를 지정해 체인의 IDCODE 를 상세(제조사/파트/버전)와 함께 읽는다. "
        "주의: 펌웨어가 24채널 전부를 출력 HIGH 로 만든 뒤 실행한다(MODIFY). 전압 설정 필요. 결과는 jtag/jtagulator-<n>-device-ids-<k>.json."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def jtagulator_get_device_ids(
    case_id: str, tdo: int, tck: int, tms: int, approval_id: str | None = None, ctx: Context | None = None
) -> dict[str, Any]:
    pins = _validate_distinct_pins({"tdo": tdo, "tck": tck, "tms": tms})
    try:
        conn, text, base, via = await _known_pins_command("jtagulator_get_device_ids", case_id, "D", pins, approval_id, ctx)
    except _GateBlocked as gb:
        return gb.response
    devices = parse_device_id_listing(text)
    scripts = _openocd_scripts()
    if scripts:
        from .jep106 import openocd_target_hints

        for d in devices:
            if d.get("plausible"):
                h = openocd_target_hints(int(d["idcode"], 16), scripts)
                if h and h.get("count"):
                    d["openocd_configs"] = h
    result = {
        "schema": "pweh.jtagulator-device-ids/v1", "case_id": case_id, "port": conn.port, "firmware": conn.firmware,
        "target_voltage": conn.voltage, "pins": pins, "devices": devices, "count": len(devices), "at": utcnow_iso(),
        "artifacts": {"raw_log": base + ".log", "result_json": base + ".json", "session_transcript": conn.transcript_rel},
    }
    return _finish_known(case_id, conn, base, result, "Device ID 목록", {"type": "device-ids", "count": len(devices)})


@server.tool(
    description=(
        "핀아웃을 알 때 BYPASS 시험(JTAG 메뉴 'T'): TDI/TDO/TCK/TMS 로 체인 장치 수를 세고 32비트 무작위 패턴이 BYPASS 를 통해 그대로 "
        "돌아오는지(Match!) 확인한다 — 찾은 핀아웃 검증용. 주의: 24채널 전부를 출력 HIGH 로 만든 뒤 실행(MODIFY). 전압 설정 필요."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def jtagulator_bypass_test(
    case_id: str, tdi: int, tdo: int, tck: int, tms: int, approval_id: str | None = None, ctx: Context | None = None
) -> dict[str, Any]:
    pins = _validate_distinct_pins({"tdi": tdi, "tdo": tdo, "tck": tck, "tms": tms})
    try:
        conn, text, base, via = await _known_pins_command("jtagulator_bypass_test", case_id, "T", pins, approval_id, ctx)
    except _GateBlocked as gb:
        return gb.response
    bt = parse_bypass_test(text) or {}
    status = parse_status(text)
    result = {
        "schema": "pweh.jtagulator-bypass-test/v1", "case_id": case_id, "port": conn.port, "firmware": conn.firmware,
        "target_voltage": conn.voltage, "pins": pins, "device_count": bt.get("device_count"), "match": bool(bt.get("match")),
        "pattern_in": bt.get("pattern_in"), "pattern_out": bt.get("pattern_out"),
        "no_device_found": status["no_device_found"], "at": utcnow_iso(),
        "artifacts": {"raw_log": base + ".log", "result_json": base + ".json", "session_transcript": conn.transcript_rel},
    }
    return _finish_known(case_id, conn, base, result, "BYPASS 시험", {"type": "bypass-test", "match": result["match"]})


@server.tool(
    description=(
        "모든 채널의 논리 레벨 읽기(GPIO 메뉴 'R', 수동): 채널을 입력으로 두고 samples 번(간격 interval_ms) 읽어 채널별 레벨, "
        "LOW 로 고정된 채널, 표본 사이에 값이 바뀐(활동 있는) 채널을 보고한다. 타깃을 구동하지 않는 관찰 단계(레벨 변환기의 약한 풀업만). "
        "전압 설정 필요. UART TXD 후보(유휴 HIGH, 송신 중 변화)나 GND/고정 신호를 빠르게 가늠할 때 쓴다."
    ),
    annotations=ANN_DEVICE,
)
@safe_tool
async def jtagulator_gpio_read(
    case_id: str, samples: int = 1, interval_ms: int = 100, ctx: Context | None = None
) -> dict[str, Any]:
    r = rt()
    case = r.case(case_id, hardware=True)
    try:
        n = int(samples)
        gap = int(interval_ms)
    except (TypeError, ValueError):
        raise ValidationFailed("samples/interval_ms 는 정수여야 합니다.")
    if not 1 <= n <= 50:
        raise ValidationFailed("samples 는 1–50 이어야 합니다.")
    if not 0 <= gap <= 5000:
        raise ValidationFailed("interval_ms 는 0–5000 이어야 합니다.")
    conn = _get_conn(case_id)
    _require_scan_ready(conn)
    cls = classify_jtagulator("R\r", P.DeviceContext("menu", menu="gpio"))
    decision = await r.authorize(
        tool="jtagulator_gpio_read", action={"port": conn.port, "connection": conn.token, "volts": conn.voltage, "command": "R", "samples": n},
        classification=cls, case_id=case_id, ctx=ctx,
    )
    if not decision.allowed:
        return gate_response(decision)

    def work() -> tuple[str, str]:
        with _op(conn):
            _require_scan_ready(conn)
            conn.scan_seq += 1
            base = f"jtag/jtagulator-{conn.session_n:03d}-gpio-{conn.scan_seq}"
            chunks = []
            for i in range(n):
                if i and gap:
                    time.sleep(gap / 1000.0)
                try:
                    chunks.append(conn.driver.read_gpio())
                except VoltageNotDefined:
                    conn.voltage = None
                    raise
            text = "".join(chunks)
            case.path(base + ".log").write_bytes(text.encode("latin-1"))
            return text, base

    text, base = await run_blocking(work)
    summary = summarize_gpio(parse_gpio_reads(text))
    result = {
        "schema": "pweh.jtagulator-gpio/v1", "case_id": case_id, "port": conn.port, "firmware": conn.firmware,
        "target_voltage": conn.voltage, "interval_ms": gap, **summary, "at": utcnow_iso(),
        "artifacts": {"raw_log": base + ".log", "result_json": base + ".json", "session_transcript": conn.transcript_rel},
    }
    if summary["samples"] != n:
        result["warning"] = f"표본 {n}개 중 {summary['samples']}개만 해석했습니다(출력 손상 가능)."
    return _finish_known(case_id, conn, base, result, "GPIO 읽기", {"type": "gpio-read", "samples": summary["samples"]})


def _finish_known(case_id: str, conn: Connection, base: str, result: dict[str, Any], title: str, extra: dict[str, Any]) -> dict[str, Any]:
    r = rt()
    case = r.cases.get(case_id)
    atomic_write_json(case.path(base + ".json"), result)
    _register(case, base + ".log", f"JTAGulator {title} 원시 출력", extra)
    _register(case, base + ".json", f"JTAGulator {title} 결과", extra)
    _register(case, conn.transcript_rel, f"JTAGulator 세션 원시 기록 ({conn.port}, FW {conn.firmware})",
              {"type": "session-transcript", "port": conn.port})
    r.audit({"event": "jtagulator_" + extra["type"].replace("-", "_"), **{k: v for k, v in result.items() if k not in ("devices",)}}, case_id)
    return {"ok": True, **result}


register_job_tools(server, rt, "jtagulator")


# ---------------------------------------------------------------------------
# 종료 처리: 실행 중 스캔을 멈추고 포트를 닫는다
# ---------------------------------------------------------------------------


def _shutdown_all() -> None:
    with _CONNS_LOCK:
        conns = list(_CONNS.values())
        _CONNS.clear()
    for conn in conns:
        try:
            if conn.busy_job() and conn.link.alive:
                conn.driver.send(P.KEY_ABORT_SCAN)
                time.sleep(0.2)
        except Exception:  # noqa: BLE001
            pass
        with contextlib.suppress(Exception):
            _close_conn(conn, "server shutdown")


atexit.register(_shutdown_all)


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
