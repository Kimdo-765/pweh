"""JTAGulator USB-시리얼 텍스트 메뉴 드라이버.

구성:
- ``Transcript``  : 연결(세션) 원시 기록 — 타임스탬프 + RX/TX 태그 + JSON 이스케이프(손실 없음), 계속 flush.
- ``SerialLink``  : pyserial 포트(장치 경로 또는 socket:// 등 URL). 수신 스레드가 모든 바이트를 버퍼·기록·싱크로 보낸다.
- ``KeyPlan``     : 안전 게이트가 승인한 '보낼 키 계획'. INTERACT 를 넘는 키는 계획에 있는 것만 1회 보낼 수 있다.
- ``JTAGulatorDriver`` : 재동기화, 메뉴 이동, 버전, 전압 대화, 스캔 대화(프롬프트 표 기반), 스캔 감시/중단.

안전 원칙(가드):
- 모든 송신은 ``send()`` 를 거친다. send 는 송신 직전의 '실제 장치 상태'(수신 버퍼 끝)를 판별해
  ``classify_jtagulator`` 로 분류하고, INTERACT 를 넘으면 승인된 KeyPlan 에 같은 (상태, 위치, 키) 단계가 있을 때만 보낸다.
  드라이버 로직이 상태를 잘못 알아도(예: 채널 번호를 전압 프롬프트에 답하려 함) 여기서 막힌다.
- 대화는 lock-step: 프롬프트가 완전히 도착하고 조용해진 뒤에만 답한다. 답을 미리 몰아 보내지 않는다.
- 값 프롬프트는 label 로 판별해 미리 계산한 답을 보낸다. 표에 없는 질문이면 Ctrl-X 로 취소하고 오류.
- 실행 중인 스캔에는 중단 키(LF 1바이트) 외에는 아무것도 보내지 않는다(어떤 바이트든 스캔을 중단시킴).
"""

from __future__ import annotations

import contextlib
import json
import logging
import select
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

import serial

from pweh.errors import DeviceError, SafetyDenied, TimeoutExpired, ValidationFailed
from pweh.fsutil import utcnow_iso
from pweh.safety import Classification, Risk, worst

from . import protocol as P
from .classify import classify_jtagulator, classify_scan_start, classify_uart_probe
from .parsers import (
    RE_ABORTED,
    RE_PERMS,
    RE_V_CURRENT,
    RE_V_OFF,
    RE_V_SET,
    RE_VERSION,
    count_progress,
    first_error,
    normalize,
    parse_jtag_blocks,
    parse_status,
    parse_txd_hits,
    parse_uart_hits,
)

log = logging.getLogger("pweh.jtagulator")

# 메뉴 명령 → 스캔 종류 (스페이스바 단계에서 어떤 스캔이 시작되는지)
SCAN_COMMANDS = {
    ("jtag", "I"): "idcode",
    ("jtag", "B"): "bypass",
    ("jtag", "J"): "jtag",
    ("uart", "U"): "uart",
    ("uart", "T"): "uart_txd",
}

# 분류용 대표 label (계획을 미리 분류할 때 쓰는 값 프롬프트 문구)
_KIND_LABEL = {v: k for k, v in P.VALUE_PROMPT_KINDS.items()}


class VoltageNotDefined(DeviceError):
    """장치가 'Target I/O voltage must be defined!' 로 거부 — 리셋 등으로 전압 설정이 사라짐."""

    code = "voltage_not_defined"


# ---------------------------------------------------------------------------
# 기록 / 링크
# ---------------------------------------------------------------------------


class Transcript:
    """연결 세션 원시 기록. 한 줄 = ``<UTC 타임스탬프> <RX|TX|--|#> <JSON 문자열>``."""

    def __init__(self, path: Path, header: dict[str, Any]) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")
        self._lock = threading.Lock()
        self._write("#", json.dumps({"format": "pweh.jtagulator-transcript/v1", **header}, ensure_ascii=False))

    def _write(self, tag: str, payload: str) -> None:
        with self._lock:
            if self._fh.closed:
                return
            try:
                self._fh.write(f"{utcnow_iso()} {tag} {payload}\n")
                self._fh.flush()
            except (OSError, ValueError):  # 디스크 문제로 장치 조작이 멈추지 않게
                log.exception("transcript write failed")

    def rx(self, data: bytes) -> None:
        self._write("RX", json.dumps(data.decode("latin-1")))

    def tx(self, data: bytes) -> None:
        self._write("TX", json.dumps(data.decode("latin-1")))

    def note(self, text: str) -> None:
        self._write("--", json.dumps(text, ensure_ascii=False))

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.close()


class SerialLink:
    """pyserial 포트 + 수신 스레드. 수신 바이트는 절대 오프셋으로 접근한다."""

    MAX_BUFFER = 4 * 1024 * 1024

    def __init__(self, url: str, baudrate: int = 115200, *, transcript: Transcript | None = None) -> None:
        self.url = url
        self.baudrate = baudrate
        self.transcript = transcript
        try:
            # exclusive=True(flock): 다른 프로세스(예: uart-mcp 콘솔 세션도 exclusive 로 연다)가 쓰는 포트는 열지 않는다.
            # 잘못 고른 포트가 대상 콘솔이면 재동기화 키(Ctrl-X, Ctrl-X+CR = U-Boot 의 빈 Enter → 직전 명령 반복)가
            # 그 콘솔로 들어가기 때문이다. socket:// 등 URL 처리기는 이 옵션을 무시한다.
            ser = serial.serial_for_url(
                url, baudrate=baudrate, bytesize=8, parity="N", stopbits=1, timeout=0.05,
                write_timeout=3.0, xonxoff=False, rtscts=False, dsrdtr=False, do_not_open=True, exclusive=True,
            )
            try:
                # FT232RL 의 DTR 은 Propeller 리셋에 연결되어 있다. 열기 전에 내려 두지만, Linux 는 open 시 DTR 을
                # 올리므로 대개 한 번은 리셋된다(연결할 때마다 재동기화·전압 재설정 필요).
                ser.dtr = False
                ser.rts = False
            except Exception:  # noqa: BLE001 - URL 핸들러에 따라 미지원
                pass
            ser.open()
        except (serial.SerialException, OSError, ValueError) as exc:
            raise DeviceError(
                f"JTAGulator 포트를 열 수 없습니다: {url}: {exc}",
                hint="포트 경로(/dev/ttyUSB*), 권한(dialout 그룹), 다른 프로그램(터미널, sigrok 등)이 포트를 쓰고 있는지 확인하세요.",
            ) from exc
        self._ser = ser
        self._buf = bytearray()
        self._base = 0
        self._cond = threading.Condition()
        self._last_rx = time.monotonic()
        self._error: BaseException | None = None
        self._closing = False
        self._sinks: list[Callable[[bytes], None]] = []
        self._write_lock = threading.Lock()
        self.rx_bytes = 0
        self.tx_bytes = 0
        self._thread = threading.Thread(target=self._reader, name=f"jtagulator-rx[{url}]", daemon=True)
        self._thread.start()

    # -- 수신 ------------------------------------------------------------------
    def _reader(self) -> None:
        ser = self._ser
        # fd 가 있으면(posix 시리얼, socket://) select 로 기다렸다가 비차단 읽기로 쌓인 바이트를 한 번에 가져온다.
        # (socket 핸들러의 in_waiting 은 0/1 만 돌려줘 1바이트씩 읽게 되므로)
        try:
            fd: int | None = ser.fileno()
        except Exception:  # noqa: BLE001 - loop:// 등 fileno 없는 핸들러
            fd = None
        if fd is not None:
            ser.timeout = 0
        while not self._closing:
            try:
                if fd is not None:
                    ready, _, _ = select.select([fd], [], [], 0.05)
                    if not ready:
                        continue
                    data = ser.read(65536)
                else:
                    n = ser.in_waiting
                    data = ser.read(n if n and n > 0 else 1)
            except Exception as exc:  # noqa: BLE001 - 끊김/USB 분리
                if not self._closing:
                    self._error = exc
                    log.warning("jtagulator link error on %s: %r", self.url, exc)
                    if self.transcript:
                        self.transcript.note(f"link error: {exc!r}")
                with self._cond:
                    self._cond.notify_all()
                return
            if not data:
                continue
            with self._cond:
                self._buf += data
                self.rx_bytes += len(data)
                if len(self._buf) > self.MAX_BUFFER:
                    drop = len(self._buf) - self.MAX_BUFFER // 2
                    del self._buf[:drop]
                    self._base += drop
                self._last_rx = time.monotonic()
                self._cond.notify_all()
            if self.transcript:
                self.transcript.rx(data)
            for sink in list(self._sinks):
                try:
                    sink(data)
                except Exception:  # noqa: BLE001
                    log.exception("rx sink failed")

    @property
    def end(self) -> int:
        with self._cond:
            return self._base + len(self._buf)

    @property
    def last_rx(self) -> float:
        return self._last_rx

    @property
    def error(self) -> BaseException | None:
        return self._error

    @property
    def alive(self) -> bool:
        return self._error is None and not self._closing

    def text_since(self, offset: int) -> str:
        with self._cond:
            start = max(0, offset - self._base)
            return bytes(self._buf[start:]).decode("latin-1")

    def tail(self, n: int = 4096) -> str:
        with self._cond:
            return bytes(self._buf[-n:]).decode("latin-1")

    def wait_for_data(self, end: int, timeout: float) -> bool:
        """수신 끝이 end 를 넘거나(새 데이터) 오류가 나거나 timeout 이 지날 때까지 대기."""
        deadline = time.monotonic() + max(0.0, timeout)
        with self._cond:
            while self._base + len(self._buf) <= end and self._error is None and not self._closing:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._cond.wait(remaining)
            return self._base + len(self._buf) > end

    def check(self) -> None:
        if self._error is not None:
            raise DeviceError(
                f"JTAGulator 연결이 끊어졌습니다: {self._error}",
                code="disconnected",
                hint="USB 케이블/전원을 확인하고 jtagulator_disconnect 후 다시 jtagulator_connect 하세요 (재연결 시 전압 재설정 필요).",
            )
        if self._closing:
            raise DeviceError("JTAGulator 연결이 이미 닫혔습니다.", code="disconnected")

    # -- 송신 ------------------------------------------------------------------
    def write(self, data: bytes) -> None:
        self.check()
        with self._write_lock:
            try:
                self._ser.write(data)
            except Exception as exc:  # noqa: BLE001
                self._error = exc
                raise DeviceError(f"JTAGulator 로 쓰기 실패: {exc}", code="disconnected") from exc
            self.tx_bytes += len(data)
        if self.transcript:
            self.transcript.tx(data)

    def add_sink(self, fn: Callable[[bytes], None]) -> None:
        self._sinks.append(fn)

    def remove_sink(self, fn: Callable[[bytes], None]) -> None:
        try:
            self._sinks.remove(fn)
        except ValueError:
            pass

    def close(self) -> None:
        self._closing = True
        try:
            self._ser.close()
        except Exception:  # noqa: BLE001
            pass
        with self._cond:
            self._cond.notify_all()
        if threading.current_thread() is not self._thread:
            self._thread.join(timeout=2.0)


# ---------------------------------------------------------------------------
# 안전 계획
# ---------------------------------------------------------------------------


@dataclass
class PlannedStep:
    state: str  # menu | value | voltage | space
    where: str  # 메뉴 이름 | 값 프롬프트 종류 | 스캔 종류 | '' | '*'(아무 메뉴)
    keys: str
    classification: Classification
    used: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"state": self.state, "where": self.where, "keys": self.keys, **self.classification.to_dict()}


class KeyPlan:
    """도구 호출이 게이트로 승인받은 키 계획. INTERACT 초과 키는 계획의 단계와 정확히 일치할 때 1회만 허용."""

    def __init__(self, steps: list[PlannedStep], *, name: str) -> None:
        self.name = name
        self.steps = steps
        self.ceiling: Risk | None = None

    def worst(self) -> Classification:
        return worst([s.classification for s in self.steps], Classification(Risk.OBSERVE, "jtagulator.plan.empty", "빈 계획"))

    def authorize(self, risk: Risk) -> None:
        self.ceiling = risk

    def consume(self, state: str, where: str, keys: str, cls: Classification) -> bool:
        if self.ceiling is None or cls.risk > self.ceiling:
            return False
        for s in self.steps:
            if s.used or s.state != state or s.keys != keys:
                continue
            if s.where not in ("*", where):
                continue
            if cls.risk > s.classification.risk:
                continue
            s.used = True
            return True
        return False

    def describe(self) -> list[dict[str, Any]]:
        return [s.to_dict() for s in self.steps]


def _cls(keys: str, ctx: P.DeviceContext, **kw: Any) -> Classification:
    return classify_jtagulator(keys, ctx, **kw)


# ---------------------------------------------------------------------------
# 스캔 명세
# ---------------------------------------------------------------------------


@dataclass
class ScanSpec:
    kind: str  # idcode | bypass | jtag | uart | uart_txd
    start: int
    end: int
    known_pins: dict[str, int] = field(default_factory=dict)
    pins_low: bool = False
    pins_low_ms: int = 100
    pins_high_ms: int = 100
    uart_text: str | None = None
    uart_answer: str | None = None  # '\x0D' 형식
    uart_probe: bytes | None = None
    uart_delay_ms: int = 10
    printable_only: bool = False
    ignore_nonstandard: bool = False

    @property
    def menu(self) -> str:
        return str(P.SCAN_SPECS[self.kind]["menu"])

    @property
    def key(self) -> str:
        return str(P.SCAN_SPECS[self.kind]["key"])

    @property
    def pin_names(self) -> tuple[str, ...]:
        if self.kind == "bypass":
            return ("tdi", "tdo", "tck", "tms")
        if self.kind == "uart":
            return ("txd", "rxd")
        return ()

    def answers(self) -> dict[str, str]:
        a = {"start_channel": str(self.start), "end_channel": str(self.end)}
        if self.kind in ("bypass", "uart"):
            a["pins_known"] = "y" if self.known_pins else "n"
            if self.known_pins:
                for name in self.pin_names:
                    a[f"pin_{name}"] = str(self.known_pins[name]) if name in self.known_pins else "x"
        if self.kind != "uart_txd":
            a["pins_low"] = "y" if self.pins_low else "n"
            if self.pins_low:
                a["pins_low_ms"] = str(self.pins_low_ms)
                a["pins_high_ms"] = str(self.pins_high_ms)
        if self.kind == "uart":
            assert self.uart_answer is not None
            a["uart_text"] = self.uart_answer
            a["uart_delay"] = str(self.uart_delay_ms)
            a["uart_printable"] = "y" if self.printable_only else "n"
        if self.kind == "uart_txd":
            a["uart_ignore_nonstandard"] = "y" if self.ignore_nonstandard else "n"
        return a

    def expected_permutations(self) -> int | None:
        if self.kind == "uart_txd":
            return None
        n = self.end - self.start + 1
        r = int(P.SCAN_SPECS[self.kind]["pins"])  # type: ignore[arg-type]
        k = len(self.known_pins)
        return P.permutations(n - k, r - k)

    def action(self) -> dict[str, Any]:
        """승인 지문용 작업 내용 (실행 옵션·타임아웃 제외, 재시도 시 동일해야 함)."""
        a: dict[str, Any] = {"scan": self.kind, "start_channel": self.start, "end_channel": self.end}
        if self.known_pins:
            a["known_pins"] = {k: self.known_pins[k] for k in sorted(self.known_pins)}
        if self.kind != "uart_txd":
            a["pins_low"] = self.pins_low
            if self.pins_low:
                a["pins_low_ms"] = self.pins_low_ms
                a["pins_high_ms"] = self.pins_high_ms
        if self.kind == "uart":
            a["text_hex"] = (self.uart_probe or b"").hex().upper()
            a["delay_ms"] = self.uart_delay_ms
            a["printable_only"] = self.printable_only
        if self.kind == "uart_txd":
            a["ignore_nonstandard"] = self.ignore_nonstandard
        return a

    def to_dict(self) -> dict[str, Any]:
        d = self.action()
        if self.kind == "uart":
            d["text"] = self.uart_text
        return d

    def lower_bound_seconds(self) -> float | None:
        perms = self.expected_permutations()
        if perms is None:
            return None
        return P.lower_bound_seconds(
            self.kind, perms, pins_low=self.pins_low, pins_low_ms=self.pins_low_ms, pins_high_ms=self.pins_high_ms,
            uart_delay_ms=self.uart_delay_ms, probe_len=len(self.uart_probe or b"\r"),
        )

    def dash_interval_lower_bound(self) -> float:
        """진행 표시 '-' 하나가 나오는 최소 간격(초) 하한 — 정지 감시 시간 계산용."""
        perms = self.expected_permutations() or 1
        lb = self.lower_bound_seconds() or 0.0
        per = lb / perms if perms else 0.0
        mod = dash_mod(self.kind, self.pins_low) or 1
        return per * mod


def dash_mod(kind: str, pins_low: bool) -> int | None:
    if kind in ("idcode", "jtag"):
        return 1 if pins_low else 100
    if kind == "bypass":
        return 1 if pins_low else 10
    if kind == "uart":
        return 1
    return None


def build_scan_plan(spec: ScanSpec, *, persistent_paths: Any = (), unknown_risk: Any = "modify") -> KeyPlan:
    kw = {"persistent_paths": persistent_paths, "unknown_risk": unknown_risk}
    steps = [PlannedStep("menu", spec.menu, spec.key + "\r", _cls(spec.key + "\r", P.DeviceContext("menu", menu=spec.menu), **kw))]
    for kind, ans in spec.answers().items():
        ctx = P.DeviceContext("value", label=_KIND_LABEL.get(kind, kind), kind=kind)
        steps.append(PlannedStep("value", kind, ans + "\r", _cls(ans + "\r", ctx, **kw)))
    probe = classify_uart_probe(spec.uart_probe, **kw) if spec.kind == "uart" else None
    steps.append(PlannedStep("space", spec.kind, P.KEY_START_SCAN, classify_scan_start(spec.kind, probe)))
    return KeyPlan(steps, name=f"scan:{spec.kind}")


def build_voltage_plan(volts: str) -> KeyPlan:
    menu_cls = _cls("V\r", P.DeviceContext("menu", menu="main"))
    ans_cls = _cls(volts + "\r", P.DeviceContext("voltage", vmin=1.4, vmax=3.3))
    return KeyPlan(
        [PlannedStep("menu", "*", "V\r", menu_cls), PlannedStep("voltage", "", volts + "\r", ans_cls)],
        name=f"set_voltage:{volts}",
    )


def build_known_pins_plan(command: str, pins: dict[str, int]) -> KeyPlan:
    """JTAG 'D'(Get Device IDs, TDO/TCK/TMS) 또는 'T'(Test BYPASS, TDI/TDO/TCK/TMS) 계획."""
    steps = [PlannedStep("menu", "jtag", command + "\r", _cls(command + "\r", P.DeviceContext("menu", menu="jtag")))]
    for name, ch in pins.items():
        kind = f"pin_{name}"
        ctx = P.DeviceContext("value", label=_KIND_LABEL[kind], kind=kind)
        steps.append(PlannedStep("value", kind, f"{ch}\r", _cls(f"{ch}\r", ctx)))
    return KeyPlan(steps, name=f"jtag:{command}")


# ---------------------------------------------------------------------------
# 드라이버
# ---------------------------------------------------------------------------


@dataclass
class DialogResult:
    start_offset: int
    started: bool = False
    started_offset: int | None = None
    ended: bool = False
    asked: list[str] = field(default_factory=list)
    permutations: int | None = None
    text: str = ""


@dataclass
class ScanRun:
    spec: ScanSpec
    dialog_offset: int
    scan_offset: int
    permutations: int | None
    asked: list[str]
    started_at: str
    t0: float
    sent: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ScanOutcome:
    reason: str | None  # None(정상 완료) | cancelled | duration | timeout | stalled | disconnected | abort_failed
    ended: bool  # 메뉴 프롬프트로 돌아왔는지
    scan_text: str  # 스캔 시작 표식 이후 출력
    full_text: str  # 대화 시작부터의 출력
    elapsed: float
    sent: list[dict[str, Any]]


class JTAGulatorDriver:
    def __init__(self, link: SerialLink, *, persistent_paths: Any = (), unknown_risk: Any = "modify") -> None:
        self.link = link
        self.persistent_paths = tuple(persistent_paths or ())
        self.unknown_risk = unknown_risk
        self.firmware: str | None = None
        self.menu: str | None = None
        self.voltage: str | None = None  # 이 연결에서 장치가 확인한 값 ("3.3", "0") — 리셋/오류 시 None
        self.sent: list[dict[str, Any]] = []
        self._io_lock = threading.RLock()
        self._scan_kind: str | None = None  # 직전에 보낸 스캔 메뉴 명령 (스페이스바 단계 분류용)
        self._scan_offset: int | None = None  # 실행 중 스캔의 시작 표식 직후 오프셋

    # -- 상태 판별 / 가드 송신 --------------------------------------------------
    def context(self) -> P.DeviceContext:
        tail = self.link.tail(4096)
        ctx = P.detect_context(tail)
        if ctx.state == "unknown" and self._scan_offset is not None:
            since = self.link.text_since(self._scan_offset)
            if not P.RE_MENU_PROMPT_ANY.search(since):
                return P.DeviceContext("scanning", text=tail[-80:])
        return ctx

    @staticmethod
    def _where(ctx: P.DeviceContext, scan_kind: str | None) -> str:
        if ctx.state == "menu":
            return ctx.menu or ""
        if ctx.state == "value":
            return ctx.kind or (ctx.label or "")
        if ctx.state == "space":
            return scan_kind or ""
        return ""

    def send(self, keys: str, *, plan: KeyPlan | None = None, scan_kind: str | None = None) -> Classification:
        """안전 가드를 거쳐 키를 보낸다. INTERACT 초과 키는 승인된 계획의 단계와 일치해야 한다."""
        with self._io_lock:
            self.link.check()
            ctx = self.context()
            sk = scan_kind or self._scan_kind
            cls = classify_jtagulator(keys, ctx, scan_kind=sk, persistent_paths=self.persistent_paths, unknown_risk=self.unknown_risk)
            if cls.risk > Risk.INTERACT:
                where = self._where(ctx, sk)
                if plan is None or not plan.consume(ctx.state, where, keys, cls):
                    if self.link.transcript:
                        self.link.transcript.note(f"BLOCKED {keys!r} at {ctx.describe()}: {cls.rule_id}")
                    raise SafetyDenied(
                        f"JTAGulator 키 입력이 승인된 계획에 없어 차단했습니다: {keys!r} ({cls.risk.label}, {cls.reason}).",
                        code="jtagulator_key_blocked",
                        hint="장치 상태가 예상과 다릅니다. 상태를 확인(jtagulator_status)하고 필요하면 연결을 다시 하세요. 우회하지 마세요.",
                        data={"classification": cls.to_dict(), "device_state": ctx.describe(), "plan": plan.name if plan else None},
                    )
            if ctx.state == "menu":
                line, _ = P.effective_line(keys)
                self._scan_kind = SCAN_COMMANDS.get((ctx.menu or "", line.upper()))
            self.link.write(keys.encode("latin-1"))
            self.sent.append({"at": utcnow_iso(), "keys": keys, "state": ctx.state, "rule": cls.rule_id, "risk": cls.risk.label})
            if len(self.sent) > 500:
                del self.sent[:100]
            return cls

    # -- 대기 -------------------------------------------------------------------
    def wait_settled(
        self, since: int, timeout: float, *, quiet: float = 0.08, want_started: bool = False
    ) -> tuple[str, P.DeviceContext]:
        """since 이후 출력이 프롬프트로 끝나고 quiet 초 동안 조용해질 때까지(또는 스캔 시작 표식까지) 대기."""
        deadline = time.monotonic() + timeout
        while True:
            self.link.check()
            text = self.link.text_since(since)
            if want_started and P.RE_SCAN_STARTED.search(text):
                return text, P.DeviceContext("scanning")
            if text:
                ctx = P.detect_context(text[-4096:])
                if ctx.state in ("menu", "value", "voltage", "space"):
                    idle = time.monotonic() - self.link.last_rx
                    if idle >= quiet:
                        if ctx.state == "menu":
                            self.menu = ctx.menu
                            self._scan_kind = None
                        return text, ctx
                    self.link.wait_for_data(self.link.end, quiet - idle)
                    continue
            now = time.monotonic()
            if now >= deadline:
                raise TimeoutExpired(
                    f"JTAGulator 응답 대기 시간 초과({timeout:.1f}초)",
                    hint="케이블·전원·포트(보드레이트 115200)를 확인하세요. 장치가 영속 모드(OpenOCD/로직 분석기)일 수도 있습니다.",
                    data={"last_output": text[-400:]},
                )
            self.link.wait_for_data(self.link.end, min(0.1, deadline - now))

    # -- 재동기화 / 메뉴 ---------------------------------------------------------
    def resync(self, timeout: float = 12.0) -> dict[str, Any]:
        """어떤 상태에서든 메뉴 프롬프트로 돌아온다 (Ctrl-X → 대기 → Ctrl-X CR)."""
        start = self.link.end
        deadline = time.monotonic() + max(2.0, timeout)
        attempts = 0
        while True:
            attempts += 1
            first_mark = self.link.end
            self.send(P.RESYNC_FIRST)
            # 영속 모드에서 빠져나올 때 펌웨어가 시리얼을 다시 시작하며 1초 기다린다 → 프롬프트가 보이거나 1.5초
            t_end = min(deadline, time.monotonic() + 1.5)
            while time.monotonic() < t_end:
                txt = self.link.text_since(first_mark)
                idle = time.monotonic() - self.link.last_rx
                if txt and P.RE_MENU_PROMPT.search(txt) and idle >= 0.15:
                    break
                if txt == "\x18" and idle >= 0.1:
                    break  # 줄 입력 중(메뉴/값 프롬프트)이라 원시 에코만 돌아옴 — 더 기다릴 필요 없음
                self.link.wait_for_data(self.link.end, 0.05)
            ctx: P.DeviceContext | None = None
            keys = P.RESYNC_SECOND
            # 메인 'A'(전체 스캔)가 돌고 있었다면 취소할 때마다 다음 하위 스캔이 첫 질문을 낸다(최대 7번).
            # 값/스페이스바 프롬프트에 머무는 동안 취소를 되풀이한다. 스페이스바 대기에는 Ctrl-X 만 보낸다.
            for _ in range(10):
                mark = self.link.end
                self.send(keys)
                try:
                    _, ctx = self.wait_settled(mark, max(0.5, min(3.0, deadline - time.monotonic())), quiet=0.15)
                except TimeoutExpired:
                    ctx = None
                if ctx is None or ctx.state not in ("value", "space", "voltage") or time.monotonic() >= deadline:
                    break
                keys = P.RESYNC_FIRST if ctx.state == "space" else P.RESYNC_SECOND
            if ctx is not None and ctx.state == "menu":
                self._scan_offset = None
                self._scan_kind = None
                return self._analyze_resync(self.link.text_since(start), attempts, ctx)
            if time.monotonic() >= deadline:
                raise DeviceError(
                    "JTAGulator 메뉴 프롬프트를 찾지 못했습니다.",
                    hint=(
                        "USB 연결과 포트(115200)를 확인하세요. 펌웨어가 부팅 중이면 몇 초 뒤 다시 시도하세요. "
                        "OpenOCD 영속 모드에서 명령이 중간에 끊긴 경우 장치가 최대 수 분 동안 입력을 인자로 소비할 수 있습니다. "
                        "그래도 응답이 없으면 사람이 JTAGulator 를 리셋(리셋 버튼 또는 전원 재투입)한 뒤 다시 연결하세요."
                    ),
                    data={"attempts": attempts, "last_output": self.link.text_since(start)[-500:]},
                )

    def _analyze_resync(self, text: str, attempts: int, ctx: P.DeviceContext) -> dict[str, Any]:
        norm = normalize(text)
        info: dict[str, Any] = {"menu": ctx.menu, "attempts": attempts, "banner_seen": bool(P.RE_BANNER.search(text))}
        m = P.RE_PERSISTENT_EXIT.search(text)
        if m:
            info["persistent_mode_exited"] = "openocd" if m.group("mode") == "OpenOCD" else "logic-analyzer"
        if P.RE_PASSTHRU_EXIT.search(text):
            info["passthrough_exited"] = True
        ab = RE_ABORTED.search(norm)
        if ab:
            info["aborted_running_scan"] = ab.group("scan")
        if "EEPROM not responding!" in norm:
            info["eeprom_error"] = True
        v = P.RE_VERSION.search(text)
        if v:
            info["firmware_seen"] = v.group("ver")
        return info

    def ensure_menu(self, target: str) -> None:
        ctx = self.context()
        if ctx.state != "menu":
            self.resync()
            ctx = self.context()
            if ctx.state != "menu":
                raise DeviceError(f"메뉴 프롬프트가 아닙니다: {ctx.describe()}")
        if ctx.menu == target:
            self.menu = target
            return
        if ctx.menu != "main":
            self._nav("M", "main")
        if target != "main":
            self._nav(P.MENU_ENTER_KEY[target], target)

    def _nav(self, key: str, expect: str) -> None:
        mark = self.link.end
        self.send(key + "\r")
        _, ctx = self.wait_settled(mark, 5.0)
        if ctx.state != "menu" or ctx.menu != expect:
            raise DeviceError(f"메뉴 이동 실패: '{key}' 뒤 {ctx.describe()} (기대: {expect})")

    @contextlib.contextmanager
    def _dialog_cleanup(self) -> Iterator[None]:
        """대화 도중 예외(가드 차단 포함)가 나면 장치를 프롬프트에 남겨 두지 않고 취소한 뒤 예외를 다시 올린다."""
        try:
            yield
        except BaseException:
            if self.link.alive:
                try:
                    if self.context().state in ("value", "voltage", "space"):
                        self._cancel_dialog()
                except Exception:  # noqa: BLE001
                    log.warning("dialog cleanup failed", exc_info=True)
            raise

    def _cancel_dialog(self) -> None:
        """값/스페이스바 프롬프트를 취소하고 메뉴로 돌아온다 (Ctrl-X CR → 펌웨어가 무효 입력으로 거부)."""
        try:
            mark = self.link.end
            self.send(P.RESYNC_SECOND)
            _, ctx = self.wait_settled(mark, 3.0, quiet=0.15)
            if ctx.state == "menu":
                return
        except Exception:  # noqa: BLE001
            log.info("dialog cancel fell back to resync")
        self.resync()

    # -- 명령 -------------------------------------------------------------------
    def version(self) -> dict[str, Any]:
        with self._io_lock:
            self.ensure_menu("main")
            mark = self.link.end
            self.send("I\r")
            text, _ = self.wait_settled(mark, 5.0)
        norm = normalize(text)
        m = RE_VERSION.search(norm)
        if not m:
            raise DeviceError("JTAGulator 버전 정보를 읽지 못했습니다.", data={"output": norm[-400:]})
        lines = []
        for ln in norm.split("\n"):
            s = ln.strip()
            if not s or s == "I" or s.endswith(">"):  # 에코, 빈 줄, 메뉴 프롬프트 제외
                continue
            lines.append(s)
        self.firmware = m.group("ver")
        return {"firmware": self.firmware, "lines": lines, "supported": P.fw_supported(self.firmware)}

    def set_voltage(self, volts: str, plan: KeyPlan) -> dict[str, Any]:
        """승인된 계획으로만 호출한다. 장치가 'New target I/O voltage set: x.y' 로 확인해야 성공."""
        with self._io_lock, self._dialog_cleanup():
            ctx = self.context()
            if ctx.state != "menu":
                self.resync()
            mark = self.link.end
            self.send("V\r", plan=plan)
            text, ctx = self.wait_settled(mark, 5.0)
            norm = normalize(text)
            prev = RE_V_CURRENT.search(norm)
            previous = prev.group("v") if prev else None
            if ctx.state != "voltage":
                if ctx.state != "menu":
                    self._cancel_dialog()
                raise DeviceError("전압 입력 프롬프트가 나오지 않았습니다.", data={"output": norm[-400:]})
            if volts != "0":
                t = int(round(float(volts) * 10))
                lo, hi = round((ctx.vmin or 1.4) * 10), round((ctx.vmax or 3.3) * 10)
                if not lo <= t <= hi:
                    self._cancel_dialog()
                    raise ValidationFailed(f"장치가 허용하는 전압 범위({ctx.vmin}–{ctx.vmax} V) 밖입니다: {volts} V")
            mark2 = self.link.end
            self.send(volts + "\r", plan=plan)
            text2, _ = self.wait_settled(mark2, 5.0)
        norm2 = normalize(text2)
        out_lines = [ln.strip() for ln in norm2.split("\n") if ln.strip() and not ln.strip().endswith(">") and ln.strip() != volts]
        if volts == "0":
            if not RE_V_OFF.search(norm2):
                self.voltage = None
                raise DeviceError("장치가 전압 끄기를 확인하지 않았습니다.", data={"output": out_lines})
            confirmed = "0"
        else:
            m = RE_V_SET.search(norm2)
            if not m:
                self.voltage = None
                err = first_error(norm2)
                raise DeviceError(f"장치가 전압 설정을 확인하지 않았습니다: {err or '알 수 없는 응답'}", data={"output": out_lines})
            confirmed = m.group("v")
            if confirmed != volts:
                self.voltage = None
                raise DeviceError(f"장치가 요청과 다른 전압을 확인했습니다: 요청 {volts} V, 장치 {confirmed} V", data={"output": out_lines})
        self.voltage = confirmed
        return {
            "previous": previous,
            "volts": confirmed,
            "device_output": out_lines,
            "vadj_warning": "Ensure VADJ is NOT connected to target!" in norm2,
        }

    def run_dialog(
        self,
        *,
        menu: str,
        key: str,
        answers: dict[str, str],
        plan: KeyPlan,
        scan_kind: str | None,
        expect_space: bool,
        expected_perms: int | None = None,
        step_timeout: float = 8.0,
    ) -> DialogResult:
        """메뉴 명령을 보내고 값 프롬프트를 label 표로 답한다. 스페이스바 단계에서 스캔을 시작한다(expect_space)."""
        with self._io_lock, self._dialog_cleanup():
            self.ensure_menu(menu)
            res = DialogResult(start_offset=self.link.end)
            mark = res.start_offset
            self.send(key + "\r", plan=plan)
            for _ in range(48):
                text, ctx = self.wait_settled(mark, step_timeout, want_started=expect_space)
                if ctx.state == "scanning":
                    full = self.link.text_since(res.start_offset)
                    mm = P.RE_SCAN_STARTED.search(full)
                    res.started = True
                    res.started_offset = res.start_offset + (mm.end() if mm else len(full))
                    perms = RE_PERMS.search(normalize(full))
                    res.permutations = int(perms.group("n")) if perms else res.permutations
                    res.text = full
                    self._scan_offset = res.started_offset
                    return res
                if ctx.state == "menu":
                    res.ended = True
                    res.text = self.link.text_since(res.start_offset)
                    return res
                if ctx.state == "value":
                    kind = ctx.kind
                    if kind is None or kind not in answers:
                        self._cancel_dialog()
                        raise DeviceError(
                            f"예상하지 못한 JTAGulator 질문이라 취소했습니다: {ctx.label!r}",
                            hint="지원 펌웨어(1.10–1.12)인지 jtagulator_version 으로 확인하세요.",
                            data={"label": ctx.label, "default": ctx.default},
                        )
                    res.asked.append(kind)
                    mark = self.link.end
                    self.send(answers[kind] + "\r", plan=plan)
                    continue
                if ctx.state == "space":
                    if not expect_space:
                        self._cancel_dialog()
                        raise DeviceError("예상하지 못한 스캔 시작 대기 프롬프트라 취소했습니다.")
                    full = normalize(self.link.text_since(res.start_offset))
                    perms = RE_PERMS.search(full)
                    res.permutations = int(perms.group("n")) if perms else None
                    if expected_perms is not None and res.permutations is not None and res.permutations != expected_perms:
                        self._cancel_dialog()
                        raise DeviceError(
                            f"장치가 계산한 순열 수({res.permutations})가 요청과 다릅니다({expected_perms}) — 입력이 잘못 해석되어 취소했습니다.",
                            data={"asked": res.asked},
                        )
                    mark = self.link.end
                    self.send(P.KEY_START_SCAN, plan=plan, scan_kind=scan_kind)
                    continue
                # 전압 프롬프트 등 예상 밖
                self._cancel_dialog()
                raise DeviceError(f"예상하지 못한 장치 상태라 취소했습니다: {ctx.describe()}")
            self._cancel_dialog()
            raise DeviceError("JTAGulator 대화가 끝나지 않아 취소했습니다.")

    def start_scan(self, spec: ScanSpec, plan: KeyPlan) -> ScanRun:
        sent_before = len(self.sent)
        res = self.run_dialog(
            menu=spec.menu, key=spec.key, answers=spec.answers(), plan=plan, scan_kind=spec.kind,
            expect_space=True, expected_perms=spec.expected_permutations(),
        )
        if not res.started:
            status = parse_status(res.text, spec.kind)
            if "Target I/O voltage must be defined!" in status["errors"]:
                self.voltage = None
                raise VoltageNotDefined(
                    "JTAGulator 가 'Target I/O voltage must be defined!' 로 거부했습니다 — 장치가 리셋되어 전압 설정이 사라졌습니다.",
                    hint="사람이 측정한 타깃 I/O 전압으로 jtagulator_set_voltage 를 다시 수행해야 합니다(승인 필요).",
                )
            raise DeviceError(
                f"스캔이 시작되지 않았습니다: {', '.join(status['errors']) or '알 수 없는 응답'}",
                data={"output": normalize(res.text)[-500:]},
            )
        return ScanRun(
            spec=spec, dialog_offset=res.start_offset, scan_offset=res.started_offset or self.link.end,
            permutations=res.permutations, asked=res.asked, started_at=utcnow_iso(), t0=time.monotonic(),
            sent=list(self.sent[sent_before:]),
        )

    def scan_progress(self, run: ScanRun, text: str) -> dict[str, Any]:
        kind = run.spec.kind
        out: dict[str, Any] = {"elapsed_seconds": round(time.monotonic() - run.t0, 1)}
        if kind == "uart_txd":
            out["found"] = len({h["txd"] for h in parse_txd_hits(text)})
            return out
        dashes = count_progress(text)
        mod = dash_mod(kind, run.spec.pins_low) or 1
        perms = run.permutations or run.spec.expected_permutations() or 0
        out["dashes"] = dashes
        out["total"] = perms
        out["done"] = min(dashes * mod, max(perms - 1, 0)) if perms else dashes * mod
        if kind == "uart":
            out["found"] = len(parse_uart_hits(text))
        else:
            out["found"] = len(parse_jtag_blocks(text))
        return out

    def monitor_scan(
        self,
        run: ScanRun,
        *,
        should_cancel: Callable[[], bool],
        on_progress: Callable[[dict[str, Any]], None] | None = None,
        idle_timeout: float = 120.0,
        max_seconds: float | None = None,
        duration: float | None = None,
        abort_wait: float = 15.0,
        poll: float = 0.25,
    ) -> ScanOutcome:
        """스캔 출력을 읽으며 끝날 때까지 감시. 취소/시간 제한/정지/기간 만료 시 중단 키(LF) 1바이트를 보낸다."""
        reason: str | None = None
        abort_sent_at: float | None = None
        resent = False
        last_emit = 0.0
        sent_before = len(self.sent)
        ended = False
        while True:
            text = self.link.text_since(run.scan_offset)
            tail = self.link.tail(64)
            if P.RE_MENU_PROMPT.search(tail) and P.RE_MENU_PROMPT_ANY.search(text):
                ended = True
                break
            now = time.monotonic()
            if self.link.error is not None:
                reason = reason or "disconnected"
                break
            if abort_sent_at is None:
                if should_cancel():
                    reason = "cancelled"
                elif duration is not None and now - run.t0 >= duration:
                    reason = "duration"
                elif max_seconds is not None and now - run.t0 >= max_seconds:
                    reason = "timeout"
                elif now - max(self.link.last_rx, run.t0) >= idle_timeout:
                    reason = "stalled"
                if reason is not None:
                    try:
                        self.send(P.KEY_ABORT_SCAN)
                    except Exception as exc:  # noqa: BLE001
                        log.warning("abort key send failed: %r", exc)
                        if self.link.error is not None:
                            reason = "disconnected"
                            break
                    abort_sent_at = now
            elif now - abort_sent_at > abort_wait:
                if not resent:
                    resent = True
                    abort_sent_at = now
                    try:
                        self.send(P.KEY_ABORT_SCAN)
                    except Exception:  # noqa: BLE001
                        pass
                else:
                    reason = "abort_failed"
                    break
            if on_progress is not None and now - last_emit >= 0.5:
                last_emit = now
                try:
                    on_progress(self.scan_progress(run, text))
                except Exception:  # noqa: BLE001
                    log.exception("progress callback failed")
            self.link.wait_for_data(self.link.end, poll)
        self._scan_offset = None
        self._scan_kind = None
        if ended:
            self.menu = P.detect_context(self.link.tail(64)).menu or self.menu
        return ScanOutcome(
            reason=reason,
            ended=ended,
            scan_text=self.link.text_since(run.scan_offset),
            full_text=self.link.text_since(run.dialog_offset),
            elapsed=round(time.monotonic() - run.t0, 2),
            sent=list(self.sent[sent_before:]),
        )

    def read_gpio(self) -> str:
        """GPIO 메뉴 'R': 모든 채널을 입력으로 1회 읽는다(INTERACT, 계획 불필요). 명령 출력 텍스트를 반환."""
        with self._io_lock:
            self.ensure_menu("gpio")
            mark = self.link.end
            self.send("R\r")
            text, _ = self.wait_settled(mark, 5.0)
        status = parse_status(text)
        if "Target I/O voltage must be defined!" in status["errors"]:
            self.voltage = None
            raise VoltageNotDefined(
                "JTAGulator 가 'Target I/O voltage must be defined!' 로 거부했습니다 — 장치가 리셋되어 전압 설정이 사라졌습니다.",
                hint="사람이 측정한 타깃 I/O 전압으로 jtagulator_set_voltage 를 다시 수행해야 합니다(승인 필요).",
            )
        return text

    def run_known_pins(self, command: str, pins: dict[str, int], plan: KeyPlan) -> str:
        """JTAG 'D' / 'T' 명령(핀아웃을 알 때) — 짧게 끝나므로 동기 실행. 대화 시작부터의 출력을 반환."""
        answers = {f"pin_{k}": str(v) for k, v in pins.items()}
        res = self.run_dialog(menu="jtag", key=command, answers=answers, plan=plan, scan_kind=None, expect_space=False, step_timeout=15.0)
        if not res.ended:
            raise DeviceError("명령이 메뉴로 돌아오지 않았습니다.")
        status = parse_status(res.text)
        if "Target I/O voltage must be defined!" in status["errors"]:
            self.voltage = None
            raise VoltageNotDefined(
                "JTAGulator 가 'Target I/O voltage must be defined!' 로 거부했습니다 — 장치가 리셋되어 전압 설정이 사라졌습니다.",
                hint="사람이 측정한 타깃 I/O 전압으로 jtagulator_set_voltage 를 다시 수행해야 합니다(승인 필요).",
            )
        for err in ("Pin numbers must be unique!", "Value out of range!"):
            if err in status["errors"]:
                raise DeviceError(f"JTAGulator 가 입력을 거부했습니다: {err}")
        return res.text

    def close(self) -> None:
        self.link.close()
