"""UART 세션: 포트 + 수신 스레드 + 링 버퍼 + 케이스 로그 + 문맥 추적 + 송신 계획/커밋.

- 포트는 ``serial.serial_for_url(port, do_not_open=True, ...)`` 로 만들고 DTR/RTS 를 **열기 전에** 설정한다
  (기본 False → 보드 리셋 방지). 장치 경로는 ``exclusive=True``(flock)로 다른 프로세스와 공유하지 않는다.
- 수신 스레드 하나가 계속 읽어 링 버퍼(절대 바이트 커서)와 ``uart/<session>.log``(타임스탬프, RX/TX 표시),
  ``uart/<session>.raw``(수신 원시 바이트), ``uart/<session>.events.jsonl``(송신·안전 결정·문맥 변화)에 쓴다.
- 읽기 오류(USB 분리, 소켓 끊김)는 세션 상태를 ``disconnected`` 로 바꾸고 대기 중인 호출을 깨운다.
- 기기로 가는 바이트는 ``plan()`` → (도구: rt().authorize / 작업: INTERACT 이하 확인) → ``commit()`` 으로만 쓴다.
  ``commit()`` 은 쓰기 직전에 현재 상태로 다시 계획해 줄이 달라졌거나 위험도가 승인된 것보다 높으면 거부한다(TOCTOU).
- 기기 준비 상태(``device_ready``): 부팅 중이거나, 앞서 보낸 줄 뒤에 아직 프롬프트가 나오지 않았거나, 마지막 프롬프트 뒤에
  재부팅·커널 시작 증거가 있으면 기기는 줄 편집기에 있지 않다 → 그때 보낸 입력은 일부가 소비·버려질 수 있어 guard 가
  더 엄격하게 분류한다. 재부팅·커널 시작 증거가 보이면 남아 있던 미완성 입력도 uncertain 으로 표시한다.
- 보낸 줄은 문맥 추적기에도 알려 준다(``tracker.note_tx``) — 기기가 우리 입력을 되풀이한 텍스트(에코, echo 출력)는
  phase/부팅 증거로 쓰지 않는다.
"""

from __future__ import annotations

import codecs
import contextlib
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import serial

from pweh.case import Case
from pweh.errors import Busy, DeviceError, PwehError
from pweh.fsutil import utcnow_iso
from pweh.safety import Classification, LineAssembler, Risk

from .guard import (
    UBOOT_CAPABLE,
    GuardState,
    Plan,
    approval_refs,
    classification_context,
    mark_uncertain,
    plan_login_input,
    plan_payload,
)
from .profile import ConsoleProfile
from .textutil import decode_bytes, escape_for_log, normalize_newlines, utf8_safe_cut
from .tracker import ContextTracker, PromptInfo

log = logging.getLogger("pweh.uart")

PROMPT_SETTLE_S = 0.06  # 프롬프트가 수신 끝에 보인 뒤 이만큼 조용해야 완료로 본다
EXPECT_OVERLAP = 8192
LOG_IDLE_FLUSH_S = 0.5


class StateChanged(PwehError):
    code = "state_changed"


# ---------------------------------------------------------------------------
# 링 버퍼
# ---------------------------------------------------------------------------


class RxBuffer:
    """절대 커서(누적 수신 바이트 오프셋)로 접근하는 링 버퍼. 잠금은 세션이 한다."""

    def __init__(self, capacity: int) -> None:
        self.capacity = max(64 * 1024, int(capacity))
        self._buf = bytearray()
        self._start = 0

    @property
    def start(self) -> int:
        return self._start

    @property
    def total(self) -> int:
        return self._start + len(self._buf)

    def append(self, data: bytes) -> None:
        self._buf += data
        # 용량을 1/8 넘게 초과했을 때 한 번에 잘라 memmove 비용을 분산한다
        if len(self._buf) > self.capacity + self.capacity // 8:
            over = len(self._buf) - self.capacity
            del self._buf[:over]
            self._start += over

    def slice(self, a: int, b: int) -> bytes:
        a = max(a, self._start)
        b = min(b, self.total)
        if b <= a:
            return b""
        return bytes(self._buf[a - self._start: b - self._start])

    def rfind(self, sub: bytes, a: int, b: int) -> int:
        a = max(a, self._start)
        b = min(b, self.total)
        idx = self._buf.rfind(sub, a - self._start, b - self._start)
        return -1 if idx < 0 else idx + self._start


# ---------------------------------------------------------------------------
# 케이스 로그 파일
# ---------------------------------------------------------------------------


class SessionLogs:
    def __init__(self, log_path: Path, raw_path: Path, events_path: Path) -> None:
        self.log_path, self.raw_path, self.events_path = log_path, raw_path, events_path
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log = open(log_path, "a", encoding="utf-8", newline="\n")
        self._raw = open(raw_path, "ab")
        self._ev = open(events_path, "a", encoding="utf-8", newline="\n")
        self._lock = threading.Lock()
        self._dec = codecs.getincrementaldecoder("utf-8")("replace")
        self._partial = ""
        self._partial_ts: str | None = None
        self._partial_flushed = False
        self._last_rx = 0.0
        self.closed = False

    def header(self, text: str) -> None:
        with self._lock:
            if not self.closed:
                self._log.write(f"# {text}\n")
                self._log.flush()

    def rx(self, data: bytes) -> None:
        now_iso = utcnow_iso()
        with self._lock:
            if self.closed:
                return
            self._raw.write(data)
            text = self._dec.decode(data)
            self._last_rx = time.monotonic()
            if self._partial_ts is None and text:
                self._partial_ts = now_iso
            parts = text.split("\n")
            for i, piece in enumerate(parts):
                if i < len(parts) - 1:
                    line = (self._partial + piece).rstrip("\r")
                    tag = "RX+" if self._partial_flushed else "RX "
                    self._log.write(f"{self._partial_ts or now_iso} {tag}| {escape_for_log(line)}\n")
                    self._partial = ""
                    self._partial_flushed = False
                    self._partial_ts = now_iso
                else:
                    self._partial += piece
            if not self._partial:
                self._partial_ts = None
            self._raw.flush()
            self._log.flush()

    def idle(self) -> None:
        """조용할 때 미완성 줄(프롬프트 등)을 로그에 내보낸다."""
        with self._lock:
            if self.closed or not self._partial or time.monotonic() - self._last_rx < LOG_IDLE_FLUSH_S:
                return
            tag = "RX+" if self._partial_flushed else "RX~"
            self._log.write(f"{self._partial_ts or utcnow_iso()} {tag}| {escape_for_log(self._partial)}\n")
            self._log.flush()
            self._partial = ""
            self._partial_flushed = True
            self._partial_ts = None

    def tx(self, payload: bytes, *, mask: bool = False, note: str = "") -> None:
        with self._lock:
            if self.closed:
                return
            if self._partial:
                tag = "RX+" if self._partial_flushed else "RX~"
                self._log.write(f"{self._partial_ts or utcnow_iso()} {tag}| {escape_for_log(self._partial)}\n")
                self._partial = ""
                self._partial_flushed = True
                self._partial_ts = None
            shown = "******" + ("\\r" if payload.endswith(b"\r") else "") if mask else escape_for_log(payload.decode("latin-1"))
            self._log.write(f"{utcnow_iso()} TX | {shown}{('  # ' + note) if note else ''}\n")
            self._log.flush()

    def note(self, text: str) -> None:
        with self._lock:
            if not self.closed:
                self._log.write(f"{utcnow_iso()} -- | {text}\n")
                self._log.flush()

    def event(self, ev: dict[str, Any]) -> None:
        rec = {"ts": utcnow_iso(), **ev}
        line = json.dumps(rec, ensure_ascii=False, default=str)
        with self._lock:
            if not self.closed:
                self._ev.write(line + "\n")
                self._ev.flush()

    def close(self) -> None:
        with self._lock:
            if self.closed:
                return
            if self._partial:
                self._log.write(f"{self._partial_ts or utcnow_iso()} RX~| {escape_for_log(self._partial)}\n")
            self.closed = True
            for fh in (self._log, self._raw, self._ev):
                with contextlib.suppress(Exception):
                    fh.flush()
                    os.fsync(fh.fileno())
                with contextlib.suppress(Exception):
                    fh.close()


# ---------------------------------------------------------------------------
# 대기 결과
# ---------------------------------------------------------------------------


@dataclass
class WaitResult:
    kind: str  # prompt | expect | timeout | cancelled | disconnected
    end: int  # 결과의 절대 끝 오프셋 (prompt/expect 끝, 아니면 그때의 수신 총량)
    prompt: PromptInfo | None = None
    match_text: str | None = None
    match_start: int | None = None
    groups: list[str | None] = field(default_factory=list)


@dataclass
class PortSettings:
    port: str
    baudrate: int = 115200
    bytesize: int = 8
    parity: str = "N"
    stopbits: float = 1
    line_ending: str = "\r"
    dtr: bool = False
    rts: bool = False

    @property
    def framing(self) -> str:
        sb = int(self.stopbits) if float(self.stopbits).is_integer() else self.stopbits
        return f"{self.bytesize}{self.parity}{sb}"

    @property
    def bits_per_char(self) -> float:
        """문자 하나의 선로 비트 수 (start + data + parity + stop). 8N1 = 10, 8E1·8N2 = 11 — 시간 초과·예상 시간 계산용."""
        return 1 + int(self.bytesize) + (0 if str(self.parity).upper() == "N" else 1) + float(self.stopbits)


def is_url(port: str) -> bool:
    return "://" in port


def port_key(port: str) -> str:
    """같은 물리 포트를 가리키는 다른 표기(/dev/serial/by-id/… 링크)를 하나로."""
    if is_url(port):
        return port.strip()
    with contextlib.suppress(OSError):
        return os.path.realpath(port)
    return port


def open_serial(settings: PortSettings, *, timeout: float = 0.05) -> serial.SerialBase:
    """DTR/RTS 를 열기 전에 설정하고 포트를 연다. 실패는 DeviceError(+힌트)."""
    kwargs: dict[str, Any] = dict(baudrate=settings.baudrate, bytesize=settings.bytesize, parity=settings.parity,
                                  stopbits=settings.stopbits, timeout=timeout, write_timeout=5)
    if not is_url(settings.port):
        kwargs["exclusive"] = True
    try:
        ser = serial.serial_for_url(settings.port, do_not_open=True, **kwargs)
    except (ValueError, serial.SerialException) as exc:
        raise DeviceError(f"포트 설정 실패: {settings.port}: {exc}",
                          hint="장치 경로(/dev/ttyUSB0) 또는 pyserial URL(socket://host:port, rfc2217://, loop://)을 확인하세요.")
    try:
        ser.dtr = bool(settings.dtr)
        ser.rts = bool(settings.rts)
    except Exception:  # noqa: BLE001 - 일부 URL 핸들러는 신호를 지원하지 않는다
        pass
    try:
        ser.open()
    except Exception as exc:  # noqa: BLE001 - SerialException, OSError, termios.error(지원하지 않는 프레이밍 등)
        with contextlib.suppress(Exception):
            ser.close()
        msg = f"{exc}" if isinstance(exc, serial.SerialException) else f"{type(exc).__name__}: {exc}"
        hint = "uart_list_ports 로 포트를 확인하세요."
        if "termios" in type(exc).__module__ or "Invalid argument" in msg:
            hint = "포트가 이 설정(보드레이트·데이터 비트·패리티·정지 비트)을 지원하지 않습니다. 8N1 같은 다른 프레이밍으로 여세요 (PTY 는 7비트·패리티를 지원하지 않을 수 있음)."
        if "Permission denied" in msg or "Errno 13" in msg:
            hint = "포트 권한이 없습니다. 사용자를 dialout 그룹에 추가하고 다시 로그인하세요 (sudo usermod -aG dialout $USER)."
        elif "busy" in msg.lower() or "lock" in msg.lower() or "Errno 16" in msg or "Errno 11" in msg:
            hint = "다른 프로그램(minicom/screen/다른 MCP 서버)이 포트를 쓰고 있습니다. 그 프로그램을 닫으세요."
        elif "No such file" in msg or "Errno 2" in msg:
            hint = "장치가 없습니다. USB-UART 어댑터 연결과 장치 이름을 확인하세요 (uart_list_ports)."
        elif "Connection refused" in msg:
            hint = "TCP 포트에 연결할 수 없습니다. ser2net/시뮬레이터가 실행 중인지 확인하세요."
        raise DeviceError(f"포트를 열 수 없습니다: {settings.port}: {msg}", hint=hint)
    return ser


# ---------------------------------------------------------------------------
# 세션
# ---------------------------------------------------------------------------


class UartSession:
    def __init__(
        self,
        *,
        session_id: str,
        case: Case,
        settings: PortSettings,
        profile: ConsoleProfile,
        label: str | None,
        buffer_bytes: int,
        persistent_paths: list[str],
        unknown_risk: str,
        audit: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.id = session_id
        self.case = case
        self.case_id = case.id
        self.settings = settings
        self.port = settings.port
        self.port_key = port_key(settings.port)
        self.profile = profile
        self.label = label
        self.persistent_paths = tuple(persistent_paths)
        self.unknown_risk = unknown_risk
        self._audit = audit
        self.cond = threading.Condition(threading.RLock())
        self.rx = RxBuffer(buffer_bytes)
        self.tracker = ContextTracker(profile)
        self.assembler = LineAssembler()
        self.uboot_env: dict[str, str] | None = None
        self.env_source: str | None = None
        self.last_command: str | None = None
        self.linux_cwd: str | None = None  # 이 세션이 보낸 cd 로 추적한 리눅스 셸 현재 디렉터리 (모르면 None)
        self.manual_context: str | None = None
        self.state = "opening"
        self.error: str | None = None
        self.agent_cursor = 0
        self.tx_bytes = 0
        self.last_rx_mono = 0.0
        self.last_tx_mono = 0.0
        self.opened_at = utcnow_iso()
        self.closed_at: str | None = None
        self.write_lock = threading.Lock()
        self.op_lock = threading.Lock()
        self.job_id: str | None = None
        self.job_lookup: Callable[[str], bool] | None = None  # job_id → 아직 실행 중인가 (서버가 주입)
        self.sysrq_until = 0.0
        self.login_failures = 0
        self.uboot_info: dict[str, Any] = {}
        self.shell_info: dict[str, Any] = {}
        self.last_tx_char = ""  # 마지막으로 보낸 문자 (기기 기준) — 호출 경계를 넘는 \r\n 판단
        self.last_eol_cursor: int | None = None  # 줄 끝을 보낸 시점의 수신 커서 (그 뒤 프롬프트가 나와야 다시 준비)
        self._boot_seq_seen = 0
        self._kernel_at_seen: int | None = None
        self._phase_seen = "unknown"
        self.ser: serial.SerialBase | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        udir = case.subdir("uart")
        self.log_path = udir / f"{session_id}.log"
        self.raw_path = udir / f"{session_id}.raw"
        self.events_path = udir / f"{session_id}.events.jsonl"
        self.logs = SessionLogs(self.log_path, self.raw_path, self.events_path)

    # ------------------------------------------------------------------
    # 열기/닫기
    # ------------------------------------------------------------------
    def open(self) -> None:
        self.logs.header(f"pweh uart session {self.id} port={self.port} baud={self.settings.baudrate} framing={self.settings.framing} "
                         f"dtr={self.settings.dtr} rts={self.settings.rts} profile={self.profile.name} opened={self.opened_at}")
        try:
            self.ser = open_serial(self.settings)
        except Exception:
            self.state = "closed"
            self.logs.close()
            for p in (self.log_path, self.raw_path, self.events_path):
                with contextlib.suppress(OSError):
                    if p.stat().st_size < 4096:
                        p.unlink()
            raise
        self.state = "open"
        self.event({"type": "open", "port": self.port, "baudrate": self.settings.baudrate, "framing": self.settings.framing,
                    "dtr": self.settings.dtr, "rts": self.settings.rts, "profile": self.profile.name})
        self._thread = threading.Thread(target=self._reader, name=f"pweh-uart-{self.id}", daemon=True)
        self._thread.start()

    def close(self, reason: str = "closed") -> None:
        self._stop.set()
        ser = self.ser
        if ser is not None:
            with contextlib.suppress(Exception):
                ser.cancel_read()
        th = self._thread
        if th is not None and th is not threading.current_thread():
            th.join(timeout=2.0)
        if ser is not None:
            with contextlib.suppress(Exception):
                ser.close()
        with self.cond:
            prev = self.state
            self.state = "closed"
            self.closed_at = utcnow_iso()
            self.cond.notify_all()
        self.event({"type": "close", "reason": reason, "previous_state": prev, "rx_bytes": self.rx.total, "tx_bytes": self.tx_bytes})
        self.logs.close()

    @property
    def alive(self) -> bool:
        return self.state == "open"

    def ensure_open(self) -> None:
        if self.state == "disconnected":
            raise DeviceError(
                f"세션 {self.id} 의 포트 연결이 끊어졌습니다: {self.error}",
                code="disconnected",
                hint="USB-UART 어댑터가 빠졌거나 TCP 연결이 끊겼습니다. 연결을 확인한 뒤 uart_close 후 uart_open 으로 다시 여세요. "
                     "끊기기 전까지의 수신 데이터는 uart_read 로 계속 읽을 수 있습니다.",
            )
        if self.state != "open":
            raise DeviceError(f"세션 {self.id} 이 열려 있지 않습니다 (state={self.state}).", code="session_closed")

    # ------------------------------------------------------------------
    # 수신 스레드
    # ------------------------------------------------------------------
    def _reader(self) -> None:
        ser = self.ser
        assert ser is not None
        # pyserial socket:// 의 in_waiting 은 0/1 만 돌려준다 → 바이트 단위로 읽지 않도록 큰 읽기(타임아웃 0.05초)를 쓴다
        socket_like = self.port.startswith("socket://")
        while not self._stop.is_set():
            try:
                n = int(ser.in_waiting or 0)
                size = min(n, 65536) if n > 1 else (4096 if socket_like else 1)
                data = ser.read(size)
            except Exception as exc:  # noqa: BLE001 - SerialException/OSError/TypeError(닫힌 포트)
                if self._stop.is_set():
                    break
                self._on_disconnect(exc)
                break
            if data:
                self._on_rx(data)
            else:
                self.logs.idle()

    def _on_rx(self, data: bytes) -> None:
        now = time.monotonic()
        with self.cond:
            base = self.rx.total
            self.rx.append(data)
            self.tracker.feed(data, base)
            self.last_rx_mono = now
            events = self.tracker.drain_events()
            if self.tracker.boot_seq != self._boot_seq_seen:
                # 재부팅 증거: RAM 의 env 는 플래시에서 다시 읽힌다 → 추적 env 폐기(더 엄격), 수동 문맥 해제
                self._boot_seq_seen = self.tracker.boot_seq
                if self.uboot_env is not None:
                    events.append({"type": "env_tracking_reset", "reason": "재부팅 증거"})
                self.uboot_env = None
                self.env_source = None
                self.linux_cwd = None  # 새 셸은 홈/루트에서 시작한다 (어디인지 모름)
                if self.manual_context:
                    events.append({"type": "manual_context_cleared", "reason": "재부팅 증거", "was": self.manual_context})
                self.manual_context = None
                self._pending_maybe_lost("재부팅 증거", events)
            if self.tracker.kernel_at is not None and self.tracker.kernel_at != self._kernel_at_seen:
                # 커널이 시작되면 U-Boot 줄 버퍼는 사라지고 커널 초기화 중 입력은 버려진다
                self._kernel_at_seen = self.tracker.kernel_at
                self._pending_maybe_lost("커널 시작", events)
            if self.tracker.phase != self._phase_seen:
                self._phase_seen = self.tracker.phase
                if self.manual_context:
                    events.append({"type": "manual_context_cleared", "reason": f"phase 변경 → {self.tracker.phase}", "was": self.manual_context})
                    self.manual_context = None
            self.cond.notify_all()
        self.logs.rx(data)
        for ev in events:
            self.event(ev)
            if ev.get("type") == "flash_write_warning" and self._audit:
                with contextlib.suppress(Exception):
                    self._audit({"event": "uart_flash_write_warning", "session_id": self.id, "line": ev.get("line")})

    def _pending_maybe_lost(self, why: str, events: list[dict[str, Any]]) -> None:
        """기기가 미완성 입력을 버렸거나 일부만 받았을 수 있다 → 조립기 줄을 uncertain 으로 (잠금은 호출자)."""
        if not self.assembler.pending and self.assembler.pending_uncertain is None:
            return
        if mark_uncertain(self.assembler, f"{why}: 기기가 앞서 보낸 미완성 입력을 버렸거나 일부만 받았을 수 있음 — "
                                          "Ctrl-C(uart_sync)로 줄을 비운 뒤 다시 보내세요"):
            events.append({"type": "pending_input_uncertain", "reason": why, "pending": escape_for_log(self.assembler.pending)[:80]})

    def _on_disconnect(self, exc: BaseException) -> None:
        with self.cond:
            if self.state != "open":
                return
            self.state = "disconnected"
            self.error = f"{type(exc).__name__}: {exc}"
            self.cond.notify_all()
        log.warning("uart session %s disconnected: %s", self.id, self.error)
        self.event({"type": "disconnected", "error": self.error})
        self.logs.note(f"DISCONNECTED: {self.error}")
        with contextlib.suppress(Exception):
            if self.ser is not None:
                self.ser.close()
        if self._audit:
            with contextlib.suppress(Exception):
                self._audit({"event": "uart_disconnected", "session_id": self.id, "port": self.port, "error": self.error})

    # ------------------------------------------------------------------
    # 상태 조회
    # ------------------------------------------------------------------
    def event(self, ev: dict[str, Any]) -> None:
        self.logs.event({"session_id": self.id, **ev})

    @property
    def context(self) -> str:
        """보고·도구 동작용 문맥 (수동 지정이 있으면 그것)."""
        return self.manual_context or self.tracker.context

    def line_ending_for(self, context: str | None = None) -> str:
        ctx = context or self.context
        if ctx in UBOOT_CAPABLE and ctx not in ("login", "password"):
            return "\r"  # U-Boot: \r 만 (\r\n 은 명령 + 빈 줄 = 반복 실행)
        return self.settings.line_ending

    def prompt_at_tail(self) -> PromptInfo | None:
        with self.cond:
            p = self.tracker.prompt
            if p is not None and p.end == self.rx.total:
                return p
            return None

    def snapshot(self) -> dict[str, Any]:
        with self.cond:
            snap = self.tracker.snapshot()
            pending = self.assembler.pending
            pend_unc = self.assembler.pending_uncertain
            ready, busy_why = self.device_ready()
            out = {
                "session_id": self.id,
                "case_id": self.case_id,
                "label": self.label,
                "port": self.port,
                "baudrate": self.settings.baudrate,
                "framing": self.settings.framing,
                "line_ending": escape_for_log(self.settings.line_ending),
                "state": self.state,
                "error": self.error,
                "context": self.context,
                "auto_context": snap["context"],
                "manual_context": self.manual_context,
                "phase": snap["phase"],
                "boot_stage": snap["boot_stage"],
                "prompt": snap["prompt"]["text"] if snap["prompt"] and snap["prompt"]["end"] == self.rx.total else None,
                "learned_prompts": snap["learned_prompts"],
                "rx_bytes": self.rx.total,
                "tx_bytes": self.tx_bytes,
                "buffer_start": self.rx.start,
                "agent_cursor": self.agent_cursor,
                "pending_input": pending if pending else None,
                "pending_uncertain": pend_unc,
                "device_ready": ready,
                "device_busy_reason": busy_why,
                "uboot_env_tracked": None if self.uboot_env is None else len(self.uboot_env),
                "env_source": self.env_source,
                "last_uboot_command": self.last_command,
                "linux_cwd": self.linux_cwd,
                "profile": self.profile.name,
                "job_id": self.active_job(),
                "opened_at": self.opened_at,
                "closed_at": self.closed_at,
                "log_path": self.case.rel(self.log_path),
                "raw_path": self.case.rel(self.raw_path),
                "events_path": self.case.rel(self.events_path),
                "flash_write_warnings": len(self.tracker.flash_warnings),
            }
        return out

    def active_job(self) -> str | None:
        jid = self.job_id
        if not jid:
            return None
        if self.job_lookup is None:
            return jid
        try:
            return jid if self.job_lookup(jid) else None
        except Exception:  # noqa: BLE001
            return None

    def ensure_idle(self, job_ok: str | None = None) -> None:
        jid = self.active_job()
        if jid and jid != job_ok:
            raise Busy(f"세션 {self.id} 에서 백그라운드 작업 {jid} 이 실행 중입니다.",
                       hint="uart_job_status 로 진행을 확인하거나 uart_job_cancel 로 취소한 뒤 다시 시도하세요. uart_read 는 계속 쓸 수 있습니다.")

    # ------------------------------------------------------------------
    # 계획 / 커밋
    # ------------------------------------------------------------------
    def device_ready(self) -> tuple[bool, str | None]:
        """기기가 줄 편집기(프롬프트)에서 입력을 받는 중으로 볼 수 있나. (준비됨, 아니면 그 이유). 잠금은 호출자.

        아니라고 보는 경우(보낸 문자의 일부가 소비·버려질 수 있음):
        - 자동 감지 문맥이 booting (autoboot 중단 키로 한 글자 소비, 커널 초기화 중 입력 버림)
        - 마지막 프롬프트 뒤에 재부팅·autoboot·커널 시작 증거가 있음
        - 줄 끝을 보낸 뒤 아직 새 프롬프트가 나오지 않음 (명령 실행 중 — U-Boot ctrlc() 폴링이 입력을 읽어 버린다)
        """
        tr = self.tracker
        if tr.context == "booting":
            return False, "기기가 부팅 중일 때(autoboot·커널 초기화 단계) 보낸 입력"
        lp = tr.last_prompt
        marks = [m for m in (tr.boot_start_at, tr.kernel_at, tr.autoboot_at) if m is not None]
        if lp is not None and marks and max(marks) > lp.start:
            return False, "마지막 프롬프트 뒤에 재부팅·커널 시작 증거가 있는 상태에서 보낸 입력"
        if self.last_eol_cursor is not None and (lp is None or lp.start < self.last_eol_cursor):
            return False, "앞서 보낸 명령이 끝나지 않은(그 뒤 프롬프트가 나오지 않은) 상태에서 보낸 입력"
        return True, None

    def wait_ready(self, timeout: float, cancel: Callable[[], bool] | None = None) -> bool:
        """기기가 프롬프트로 돌아올 때까지 잠깐 기다린다 (expect 로 일찍 끝난 명령 뒤의 프롬프트 등)."""
        deadline = time.monotonic() + max(0.0, timeout)
        with self.cond:
            while True:
                ready, _ = self.device_ready()
                # 부팅 중이면 기다려도 소용없다 (autoboot 중단 키처럼 지금 보내야 하는 입력을 늦추지 않는다)
                if ready or self.tracker.context == "booting" or self.state != "open" or (cancel is not None and cancel()):
                    return ready
                left = deadline - time.monotonic()
                if left <= 0:
                    return False
                self.cond.wait(min(left, 0.05))

    def last_command_known(self) -> bool:
        """기기 U-Boot 의 '직전 명령'을 아는가: 이 세션이 줄을 보냈거나 재부팅을 봤으면 안다 (잠금은 호출자)."""
        return self.last_command is not None or self.tracker.boot_seq > 0

    def _guard_state(self, context: str, *, assume_history_known: bool = False) -> GuardState:
        ready, why = self.device_ready()
        return GuardState(
            context=context,
            env=dict(self.uboot_env) if self.uboot_env is not None else None,
            last_command=self.last_command,
            persistent_paths=self.persistent_paths,
            unknown_risk=self.unknown_risk,
            uboot_max_line=self.profile.uboot_max_line,
            linux_max_line=self.profile.linux_max_line,
            sysrq_until=self.sysrq_until,
            now=time.monotonic(),
            prev_char=self.last_tx_char,
            device_ready=ready,
            busy_reason=why,
            last_command_known=assume_history_known or self.last_command_known(),
            bytesize=int(self.settings.bytesize),
            cwd=self.linux_cwd,
        )

    def approval_refs(self, plan: Plan) -> dict[str, Any]:
        """승인 지문에 넣을 실행 의미(참조 env 값, 빈 줄의 반복 대상) — 같은 줄이라도 이것이 바뀌면 다른 작업이다."""
        with self.cond:
            return approval_refs(plan.line_texts(), plan.context, env=self.uboot_env, last_command=self.last_command,
                                 last_command_known=self.last_command_known(), cwd=self.linux_cwd)

    def plan(self, payload: bytes, *, assume_history_known: bool = False) -> Plan:
        """페이로드 분류. 수동 문맥이 자동 감지와 다르면 둘 다로 분류해 더 위험한 쪽을 쓴다 (수동 지정은 완화 불가).

        assume_history_known: uboot_interrupt 의 사전 승인 전용 — Enter 키는 새 부팅(기기 직전 명령이 비워짐)을 본 뒤에만
        보내므로 '모르는 직전 명령의 반복' 규칙을 적용하지 않는다. 실제 송신은 그때의 상태로 다시 분류한다(commit).
        """
        with self.cond:
            auto = self.tracker.context
            manual = self.manual_context
            p = plan_payload(payload, self.assembler, self._guard_state(auto, assume_history_known=assume_history_known))
            if manual and manual != auto:
                p2 = plan_payload(payload, self.assembler, self._guard_state(manual, assume_history_known=assume_history_known))
                state_src = p2 if (auto == "linux-shell" and manual != "linux-shell") else p
                chosen = p2 if p2.classification.risk > p.classification.risk else p
                if chosen is not state_src:
                    chosen.env_after = state_src.env_after
                    chosen.last_command_after = state_src.last_command_after
                    chosen.env_invalidated = chosen.env_invalidated or state_src.env_invalidated
                chosen.context = f"{classification_context(manual)}+auto:{classification_context(auto)}"
                p = chosen
            return p

    def plan_login(self, payload: bytes, *, masked: bool, kinds: tuple[str, ...]) -> Plan:
        with self.cond:
            pm = self.tracker.prompt
            if pm is None or pm.end != self.rx.total or pm.kind not in kinds:
                raise StateChanged(
                    f"{'/'.join(kinds)} 프롬프트가 수신 끝에 보이지 않아 입력을 보내지 않았습니다.",
                    hint="uart_read 로 현재 화면을 확인하세요. 로그인 입력은 프롬프트가 보일 때만 보낸다.")
            p = plan_login_input(payload, self.assembler, self._guard_state(self.tracker.context), masked=masked)
            p.require_prompt_kinds = kinds  # type: ignore[attr-defined]
            return p

    def commit(self, plan: Plan, authorized: Risk, *, note: str = "", source: str = "tool") -> int:
        """계획을 기기에 쓴다. 쓰기 직전 현재 상태로 다시 계획해 달라졌으면 StateChanged. 반환: 쓰기 직전 수신 커서."""
        with self.write_lock:
            with self.cond:
                self.ensure_open()
                kinds = getattr(plan, "require_prompt_kinds", None)
                if kinds:
                    fresh = self.plan_login(plan.payload, masked=plan.masked, kinds=kinds)
                else:
                    fresh = self.plan(plan.payload)
                if fresh.line_texts() != plan.line_texts():
                    raise StateChanged("승인 이후 세션의 입력 상태가 바뀌어 보낼 줄이 달라졌습니다.",
                                       hint="같은 도구를 다시 호출해 새로 분류·승인받으세요.",
                                       data={"planned": plan.line_texts(), "now": fresh.line_texts()})
                if fresh.classification.risk > authorized:
                    raise StateChanged(
                        f"문맥이 바뀌어 위험도가 {fresh.classification.risk.label} 로 올라갔습니다 (승인: {authorized.label}).",
                        hint="uart_read 로 현재 상태를 확인한 뒤 다시 호출하세요.",
                        data={"classification": fresh.classification.to_dict()})
                prev_pending = self.assembler.pending
                self.assembler = fresh.assembler_after or self.assembler
                if fresh.cwd_tracked:
                    self.linux_cwd = fresh.cwd_after
                if any(c in UBOOT_CAPABLE for c in fresh.context.replace("auto:", "").split("+")):
                    self.last_command = fresh.last_command_after
                    if fresh.env_invalidated and self.uboot_env is not None:
                        self.env_source = None
                    self.uboot_env = fresh.env_after
                    if fresh.env_after is not None and self.env_source is None:
                        self.env_source = "partial (setenv 추적)"
                cursor = self.rx.total
                self.last_tx_mono = time.monotonic()
                if fresh.lines:
                    self.last_eol_cursor = cursor  # 기기는 이제 명령을 실행한다 → 새 프롬프트가 보일 때까지 준비 안 됨
                if fresh.last_char:
                    self.last_tx_char = fresh.last_char
                # 문맥 추적기: 기기가 우리 입력을 되풀이한 텍스트는 증거로 쓰지 않는다 (비밀번호는 넘기지 않음).
                # 이어지지 않은 이전 미완성 입력(Ctrl-C/Ctrl-U 로 버림)의 에코도 '<INTERRUPT>' 줄에 남는다.
                texts = [] if fresh.masked else fresh.line_texts()
                after = "" if fresh.masked else fresh.pending_after
                continued = any(t.startswith(prev_pending) for t in [*texts, after]) if prev_pending else True
                self.tracker.note_tx(texts, after, "" if continued else prev_pending)
                if plan.payload:
                    self.sysrq_until = 0.0  # SysRq 창은 BREAK 뒤 첫 바이트에만 적용
            ser = self.ser
            try:
                assert ser is not None
                ser.write(plan.payload)
                with contextlib.suppress(Exception):
                    ser.flush()
            except Exception as exc:  # noqa: BLE001
                self._on_disconnect(exc)
                raise DeviceError(f"쓰기 실패 (포트 연결 끊김?): {exc}", code="disconnected",
                                  hint="연결을 확인한 뒤 uart_close → uart_open 으로 다시 여세요.")
            self.tx_bytes += len(plan.payload)
        self.logs.tx(plan.payload, mask=plan.masked, note=note)
        self.event({"type": "tx", "source": source, "bytes": len(plan.payload),
                    "payload": "<masked>" if plan.masked else escape_for_log(plan.payload.decode("latin-1"))[:400],
                    **{k: v for k, v in plan.to_dict().items() if k in ("context", "risk", "rule_id", "lines", "pending_input")}})
        return cursor

    def raw_signal(self, fn: Callable[[serial.SerialBase], Any], what: str) -> Any:
        """BREAK/DTR/RTS 같은 신호 조작 (게이트는 호출자). 미지원이면 그대로 예외."""
        with self.write_lock:
            self.ensure_open()
            assert self.ser is not None
            res = fn(self.ser)
        self.event({"type": "signal", "what": what})
        self.logs.note(f"SIGNAL {what}")
        return res

    # ------------------------------------------------------------------
    # 읽기 / 대기
    # ------------------------------------------------------------------
    def slice(self, a: int, b: int | None = None) -> bytes:
        with self.cond:
            return self.rx.slice(a, self.rx.total if b is None else b)

    def total(self) -> int:
        with self.cond:
            return self.rx.total

    def read(self, since: int | None, max_bytes: int, wait_seconds: float, tail: bool,
             cancel: Callable[[], bool] | None = None) -> dict[str, Any]:
        max_bytes = max(1, min(int(max_bytes), 1024 * 1024))
        deadline = time.monotonic() + max(0.0, wait_seconds)
        with self.cond:
            if tail:
                start = max(self.rx.start, self.rx.total - max_bytes)
            else:
                start = self.agent_cursor if since is None else int(since)
            if start < 0:
                start = 0
            if start > self.rx.total:
                start = self.rx.total
            if wait_seconds > 0 and not tail:
                # 새 데이터를 기다리고, 오기 시작하면 잠깐 더 모은다
                while self.rx.total <= start and self.state == "open":
                    left = deadline - time.monotonic()
                    if left <= 0 or (cancel and cancel()):
                        break
                    self.cond.wait(min(left, 0.1))
                while self.rx.total > start and self.rx.total - start < max_bytes and self.state == "open":
                    quiet = time.monotonic() - self.last_rx_mono
                    left = deadline - time.monotonic()
                    if quiet >= 0.15 or left <= 0 or (cancel and cancel()):
                        break
                    self.cond.wait(min(0.15 - quiet, max(left, 0.01), 0.1))
            lost = max(0, self.rx.start - start)
            start = max(start, self.rx.start)
            end = min(self.rx.total, start + max_bytes)
            data = self.rx.slice(start, end)
            if end < self.rx.total:
                cut = utf8_safe_cut(data)
                if cut > 0:
                    data = data[:cut]
                    end = start + cut
            more = end < self.rx.total
            self.agent_cursor = end
            ctx = self.context
            state = self.state
            prompt = self.tracker.prompt.text if (self.tracker.prompt and self.tracker.prompt.end == self.rx.total) else None
        out = {
            "text": normalize_newlines(decode_bytes(data)),
            "bytes": len(data),
            "cursor_start": start,
            "cursor_end": end,
            "more": more,
            "context": ctx,
            "prompt": prompt,
            "state": state,
        }
        if lost:
            out["lost_bytes"] = lost
            out["note"] = f"요청한 커서 이전 {lost} 바이트는 링 버퍼에서 밀려났습니다 (전체는 {self.case.rel(self.raw_path)} 에 있음)."
        return out

    def _search(self, rx: re.Pattern[str], since: int, scan_from: int) -> tuple[re.Match[str], int, bool] | None:
        """since 이후 데이터에서 정규식 검색 (scan_from 앞쪽은 이미 검사함 — EXPECT_OVERLAP 만큼 겹쳐 다시 본다).

        검색 문자열은 latin-1 로 1:1 디코드하고 CR 을 LF 로 바꾼다(길이 불변) → ``(?m)^…$`` 가 CRLF 줄에도 맞는다.
        반환: (match, base, provisional). provisional 은 매치가 지금까지 받은 데이터 끝에 닿아 있고 그 줄이 아직 끝나지 않은
        경우다 — 나머지가 오면 매치가 사라지거나(``$`` 가 미완성 줄 끝에서 맞음) 길어질 수 있다(``.*``, ``\\d+``).
        호출자는 줄이 끝나거나 수신이 조용해질 때까지(settle) 기다린 뒤에 받아들인다.
        """
        lo = max(since, scan_from - EXPECT_OVERLAP, self.rx.start)
        total = self.rx.total
        if lo >= total:
            return None
        win_start = max(self.rx.start, lo - 4096)
        nl = self.rx.rfind(b"\n", win_start, lo)
        base = nl + 1 if nl >= 0 else win_start
        text = self.rx.slice(base, total).decode("latin-1").replace("\r", "\n")
        for m in rx.finditer(text, lo - base):
            if base + m.start() >= since:
                provisional = m.end() >= len(text) and (not text.endswith("\n") or m.start() == m.end())
                return m, base, provisional
        return None

    def search_stable(self, rx: re.Pattern[str], since: int, scan_from: int,
                      settle: float = PROMPT_SETTLE_S) -> tuple[re.Match[str] | None, int, bool, int]:
        """``_search`` + 미완성 줄 처리. 반환: (확정 매치|None, base, 보류 중인 매치가 있나, 다음 scan_from). 잠금은 호출자."""
        hit = self._search(rx, since, scan_from)
        if hit is None:
            return None, 0, False, self.rx.total
        m, base, provisional = hit
        if not provisional or time.monotonic() - self.last_rx_mono >= settle:
            return m, base, False, self.rx.total
        # 보류: 다음 검사에서 이 매치 시작부터 다시 본다 (EXPECT_OVERLAP 창 안)
        return None, base, True, max(scan_from, base + m.start())

    def wait_response(self, after: int, timeout: float, *, expect: re.Pattern[str] | None = None,
                      cancel: Callable[[], bool] | None = None, settle: float | None = None,
                      prompt_filter: Callable[[PromptInfo], bool] | None = None) -> WaitResult:
        """after 이후 새 프롬프트(수신 끝, settle 초 조용) 또는 expect 정규식을 기다린다.

        expect 매치가 아직 끝나지 않은 줄의 끝에 닿아 있으면(``^bootargs=.*$`` 가 'bootargs=' 까지만 받은 줄에 맞는 경우)
        줄이 끝나거나 settle 초 조용해질 때까지 기다린다. 시간이 끝나면 그때의 매치를 돌려준다.
        """
        settle = PROMPT_SETTLE_S if settle is None else settle
        deadline = time.monotonic() + max(0.0, timeout)
        scan_from = after
        with self.cond:
            while True:
                now = time.monotonic()
                wait_t = 0.1
                if expect is not None:
                    m, base, pending, scan_from = self.search_stable(expect, after, scan_from, settle)
                    if m is not None:
                        return WaitResult("expect", base + m.end(), match_text=m.group(0), match_start=base + m.start(),
                                          groups=list(m.groups()))
                    if pending:
                        wait_t = max(0.005, settle - (now - self.last_rx_mono))
                        if deadline - now <= 0:
                            hit = self._search(expect, after, scan_from)
                            if hit is not None:
                                m2, base2, _ = hit
                                return WaitResult("expect", base2 + m2.end(), match_text=m2.group(0),
                                                  match_start=base2 + m2.start(), groups=list(m2.groups()))
                else:
                    pm = self.tracker.prompt
                    if pm is not None and pm.start >= after and pm.end == self.rx.total and (prompt_filter is None or prompt_filter(pm)):
                        quiet = now - self.last_rx_mono
                        if quiet >= settle:
                            return WaitResult("prompt", pm.end, prompt=pm)
                        wait_t = max(0.005, settle - quiet)
                if self.state != "open":
                    return WaitResult("disconnected", self.rx.total)
                if cancel is not None and cancel():
                    return WaitResult("cancelled", self.rx.total)
                left = deadline - now
                if left <= 0:
                    return WaitResult("timeout", self.rx.total)
                self.cond.wait(min(wait_t, left))

    def wait_quiet(self, quiet: float, timeout: float, cancel: Callable[[], bool] | None = None) -> bool:
        deadline = time.monotonic() + timeout
        with self.cond:
            while True:
                now = time.monotonic()
                if now - max(self.last_rx_mono, self.last_tx_mono) >= quiet:
                    return True
                if now >= deadline or self.state != "open" or (cancel and cancel()):
                    return False
                self.cond.wait(min(0.05, deadline - now))
