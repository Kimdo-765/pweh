"""카메라 UART 콘솔 시뮬레이터 본체.

``MockDevice`` 는 가상 카메라 한 대다. 전송 계층(PTY/TCP)으로 들어온 바이트를 받아, 부트ROM → U-Boot →
리눅스 커널 → BusyBox 로그인/셸 순서로 동작하는 펌웨어 흉내(``uboot.UBoot``, ``linux.Linux``)를 자체
스레드에서 실행한다.

사용 예::

    from pweh.mocktarget import MockDevice
    dev = MockDevice("hisilicon-like", time_scale=0.05, autostart=False)
    path = dev.start_pty()            # pyserial 로 path 를 연다
    dev.power_on()                    # 사람이 전원을 꽂는 것과 같다 → 부팅 시작
    ...
    dev.destructive_events            # 기기까지 도달한 파괴적 작업 (안전 게이트 테스트용)
    dev.stop()

스레드 모델: 펌웨어 로직은 ``pweh-mock-device`` 스레드 하나에서 순차 실행되며, 전원 차단/재투입은
그 스레드의 모든 대기 지점에서 ``PowerEvent`` 예외로 즉시 끼어든다.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Mapping

from ..errors import ConfigError
from .memory import FlashChip, SparseMemory
from .profiles import load_profile
from .transport import PtyTransport, TcpTransport

log = logging.getLogger("pweh.mocktarget")

STATES = ("off", "bootrom", "uboot-autoboot", "uboot", "kernel-boot", "linux-login", "linux-shell")

# 입력 처리 모드
RX_DROP = "drop"      # 전원 꺼짐/부트ROM/커널 초기화 중: 입력 무시
RX_UART = "uart"      # U-Boot: 하드웨어 RX FIFO (명령 실행 중에는 rx_fifo 바이트만 보관)
RX_TTY = "tty"        # 리눅스: tty 라인 버퍼 (linux_rx_buffer)


class PowerEvent(BaseException):
    """전원이 꺼지거나 다시 켜졌을 때 펌웨어 스레드를 풀어내기 위한 예외 (BaseException: except Exception 에 안 잡힘)."""


class ResetEvent(BaseException):
    """소프트 리셋(U-Boot reset, 리눅스 reboot). DRAM 내용은 유지되고 부팅을 다시 시작한다."""

    def __init__(self, reason: str = "reset") -> None:
        super().__init__(reason)
        self.reason = reason


class ShutdownEvent(BaseException):
    """시뮬레이터 종료."""


class MockDevice:
    """가상 IP 카메라 (UART 콘솔 + SPI NOR 플래시 + DRAM)."""

    def __init__(
        self,
        profile: str | os.PathLike[str] | Mapping[str, Any] = "hisilicon-like",
        *,
        flash_image: bytes | bytearray | str | os.PathLike[str] | None = None,
        time_scale: float = 1.0,
        seed: int = 0,
        baud: int | None = None,
        overrides: Mapping[str, Any] | None = None,
        autostart: bool = True,
        pace_output: bool = False,
        log_limit: int = 8 * 1024 * 1024,
        firmware_cache: bool = True,
        autoboot_floor: float = 0.25,
    ) -> None:
        """
        profile      : 내장 프로필 이름(``hisilicon-like``/``ingenic-like``/...), YAML 경로, 또는 딕셔너리
        flash_image  : 16MiB 플래시 이미지 (bytes 또는 파일 경로). None 이면 외부 도구 없이 즉석 생성한
                       빠른 합성 이미지(``firmware.build_image_bytes(fast=True)``)를 쓴다.
        time_scale   : 모든 지연(부팅 로그, autoboot 카운트다운, 플래시 읽기 시간 ...)에 곱하는 배율. 테스트는 0.01~0.05.
        seed         : 초기화되지 않은 RAM 내용(의사난수)의 시드
        baud         : 기기 보드레이트 (기본: 프로필 baud)
        overrides    : 프로필 깊은 병합 덮어쓰기
        autostart    : True 면 첫 전송 계층을 시작할 때 자동으로 전원을 켠다
        pace_output  : True 면 출력 속도를 실제 보드레이트(× time_scale)로 제한한다 (Ctrl-C 중단 테스트용)
        autoboot_floor: autoboot 카운트다운 1초당 최소 실제 대기 시간(초). time_scale 이 아주 작아도 인터럽트 키를
                       보낼 시간을 보장한다 (0 이면 순수하게 time_scale 만 적용).
        """
        self.profile: dict[str, Any] = load_profile(profile, overrides)
        if time_scale < 0:
            raise ConfigError("time_scale 은 0 이상이어야 합니다.")
        self.time_scale = float(time_scale)
        self.seed = int(seed)
        self.default_baud = int(baud or self.profile["baud"])
        self.baud = self.default_baud
        self.autostart = autostart
        self.pace_output = pace_output
        self.autoboot_floor = max(0.0, float(autoboot_floor))
        self.events: list[dict[str, Any]] = []
        self.destructive_events: list[dict[str, Any]] = []
        self.firmware_manifest: dict[str, Any] | None = None
        self._log_limit = int(log_limit)
        self._console = bytearray()
        self._console_lock = threading.Lock()
        self._events_lock = threading.Lock()
        self._t0 = time.monotonic()

        fl = self.profile["flash"]
        image = self._load_flash_image(flash_image, firmware_cache)
        if len(image) != fl["size"]:
            raise ConfigError(
                f"플래시 이미지 크기({len(image)})가 프로필 flash.size({fl['size']})와 다릅니다.",
                hint="pweh-mock-device --build-firmware 로 같은 프로필의 이미지를 만드세요.",
            )
        self.flash = FlashChip(image, erase_size=fl["erase_size"], page_size=fl["page_size"])
        self.ram = SparseMemory(seed=self.seed)
        if fl.get("memory_window"):
            self.ram.add_window(fl["memory_window"], fl["size"], self.flash.read)

        # 전원/상태
        self._state = "off"
        self._state_cond = threading.Condition()
        self._power_on = False
        self._power_gen = 0
        self._shutdown = False

        # 입력 큐 (전송 스레드 → 펌웨어 스레드)
        self._rx: deque[int] = deque()
        self._rx_cond = threading.Condition()
        self._rx_mode = RX_DROP
        self._rx_reading = False
        self.rx_overruns = 0
        self.rx_dropped = 0

        self._transports: list[Any] = []
        self._thread: threading.Thread | None = None
        self._gen_seen = 0
        self.uboot: Any = None
        self.linux: Any = None
        self.boot_count = 0
        self.crashed: str | None = None

    # ------------------------------------------------------------------
    # 플래시 이미지
    # ------------------------------------------------------------------
    def _load_flash_image(self, flash_image: Any, firmware_cache: bool) -> bytes:
        from . import firmware

        if flash_image is None:
            data, manifest = firmware.build_image_bytes(self.profile, fast=True, use_cache=firmware_cache)
            self.firmware_manifest = manifest
            return data
        if isinstance(flash_image, (bytes, bytearray, memoryview)):
            return bytes(flash_image)
        path = Path(os.fspath(flash_image)).expanduser()
        if not path.is_file():
            raise ConfigError(f"플래시 이미지 파일이 없습니다: {path}")
        man = path.with_name(path.name + ".manifest.json")
        if man.is_file():
            import json

            try:
                self.firmware_manifest = json.loads(man.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self.firmware_manifest = None
        return path.read_bytes()

    # ------------------------------------------------------------------
    # 전송 계층
    # ------------------------------------------------------------------
    def start_pty(self, link: str | None = None) -> str:
        """원시 모드 PTY 를 열고 슬레이브 경로(예: /dev/pts/5)를 돌려준다. link 를 주면 그 경로에 심볼릭 링크."""
        t = PtyTransport(on_input=self.feed_input, device_baud=lambda: self.baud, on_event=self._transport_event,
                         link=link)
        path = t.start()
        self._transports.append(t)
        self.record({"type": "transport", "kind": "pty", "path": path})
        self._ensure_thread()
        if self.autostart and not self._power_on and self.boot_count == 0:
            self.power_on()
        return path

    def start_tcp(self, host: str = "127.0.0.1", port: int = 0) -> tuple[str, int]:
        """TCP 서버를 연다. pyserial URL ``socket://host:port`` 로 접속한다. (host, port) 반환."""
        t = TcpTransport(on_input=self.feed_input, on_event=self._transport_event, host=host, port=port)
        addr = t.start()
        self._transports.append(t)
        self.record({"type": "transport", "kind": "tcp", "url": t.url})
        self._ensure_thread()
        if self.autostart and not self._power_on and self.boot_count == 0:
            self.power_on()
        return addr

    def stop(self) -> None:
        """전원을 끄고 펌웨어 스레드와 모든 전송 계층을 정리한다."""
        with self._rx_cond:
            self._shutdown = True
            self._power_on = False
            self._power_gen += 1
            self._rx_cond.notify_all()
        th = self._thread
        if th is not None and th is not threading.current_thread():
            th.join(timeout=5.0)
        for t in self._transports:
            try:
                t.stop()
            except Exception:  # pragma: no cover
                log.exception("transport stop failed")
        self._transports.clear()
        self._set_state("off")

    def __enter__(self) -> "MockDevice":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    def transports_info(self) -> list[dict[str, Any]]:
        return [t.info() for t in self._transports]

    @property
    def pty_path(self) -> str | None:
        for t in self._transports:
            if t.kind == "pty":
                return t.slave_path
        return None

    @property
    def tcp_url(self) -> str | None:
        for t in self._transports:
            if t.kind == "tcp":
                return t.url
        return None

    def _transport_event(self, ev: dict[str, Any]) -> None:
        self.record(ev)

    # ------------------------------------------------------------------
    # 전원
    # ------------------------------------------------------------------
    @property
    def state(self) -> str:
        return self._state

    @property
    def powered(self) -> bool:
        return self._power_on

    def power_on(self) -> None:
        """전원 투입 → 부팅 시작 (이미 켜져 있으면 무시)."""
        self._ensure_thread()
        with self._rx_cond:
            if self._power_on:
                return
            self._power_on = True
            self._power_gen += 1
            self._rx.clear()
            self._rx_cond.notify_all()
        self.record({"type": "power", "action": "on"})

    def power_off(self) -> None:
        """전원 차단. 펌웨어 스레드는 즉시 멈추고 RAM 내용은 사라진다."""
        with self._rx_cond:
            if not self._power_on:
                return
            self._power_on = False
            self._power_gen += 1
            self._rx.clear()
            self._rx_cond.notify_all()
        self.record({"type": "power", "action": "off"})
        # 상태 전환은 펌웨어 스레드가 PowerEvent 를 받으면서 한다. 아직 스레드가 없으면 직접.
        if self._thread is None:
            self._set_state("off")

    def power_cycle(self, off_seconds: float = 0.1) -> None:
        """사람이 전원 케이블을 뽑았다 꽂는 것과 같다 (부팅 시퀀스 재시작)."""
        self.power_off()
        self.wait_for_state("off", timeout=5.0)
        if off_seconds:
            time.sleep(max(0.0, off_seconds * min(1.0, self.time_scale or 1.0)))
        self.power_on()

    def wait_for_state(self, state: str | tuple[str, ...], timeout: float = 10.0) -> bool:
        """상태가 state(들 중 하나)가 될 때까지 기다린다 (테스트 헬퍼)."""
        wanted = (state,) if isinstance(state, str) else tuple(state)
        deadline = time.monotonic() + timeout
        with self._state_cond:
            while self._state not in wanted:
                left = deadline - time.monotonic()
                if left <= 0:
                    return False
                self._state_cond.wait(left)
            return True

    def _set_state(self, state: str) -> None:
        assert state in STATES, state
        with self._state_cond:
            if self._state == state:
                return
            old = self._state
            self._state = state
            self._state_cond.notify_all()
        self.record({"type": "state", "from": old, "to": state})

    # ------------------------------------------------------------------
    # 이벤트
    # ------------------------------------------------------------------
    def record(self, event: dict[str, Any]) -> dict[str, Any]:
        ev = {"t": round(time.monotonic() - self._t0, 4), **event}
        with self._events_lock:
            self.events.append(ev)
            if len(self.events) > 20000:
                del self.events[:5000]
        return ev

    def record_destructive(self, op: str, **detail: Any) -> dict[str, Any]:
        """플래시/메모리/영구 저장소를 바꾸는 작업이 기기에 도달했음을 기록 (안전 게이트 검증용)."""
        ev = {"type": "destructive", "op": op, "state": self._state, **detail}
        ev = self.record(ev)
        with self._events_lock:
            self.destructive_events.append(ev)
        log.info("mock device: destructive op reached device: %s %s", op, detail)
        return ev

    def commands(self, context: str | None = None) -> list[dict[str, Any]]:
        with self._events_lock:
            return [e for e in self.events if e.get("type") == "command" and (context is None or e.get("context") == context)]

    # ------------------------------------------------------------------
    # 콘솔 로그
    # ------------------------------------------------------------------
    @property
    def console_output(self) -> bytes:
        """기기가 지금까지 출력한 모든 바이트 (보드레이트 변환 전, 최대 log_limit)."""
        with self._console_lock:
            return bytes(self._console)

    def console_text(self) -> str:
        return self.console_output.decode("utf-8", "replace")

    def clear_console(self) -> None:
        with self._console_lock:
            self._console.clear()

    def snapshot_flash(self) -> bytes:
        return self.flash.snapshot()

    # ------------------------------------------------------------------
    # 입력 (전송 스레드에서 호출)
    # ------------------------------------------------------------------
    def feed_input(self, data: bytes) -> None:
        with self._rx_cond:
            if not self._power_on or self._rx_mode == RX_DROP:
                self.rx_dropped += len(data)
                return
            if self._rx_mode == RX_UART:
                limit = None if self._rx_reading else int(self.profile["uart"].get("rx_fifo", 64))
            else:
                limit = int(self.profile["uart"].get("linux_rx_buffer", 4096))
            for b in data:
                if limit is not None and len(self._rx) >= limit:
                    self.rx_overruns += 1
                    continue
                self._rx.append(b)
            self._rx_cond.notify_all()

    # ------------------------------------------------------------------
    # 펌웨어 스레드용 기본 동작 (반드시 펌웨어 스레드에서만 호출)
    # ------------------------------------------------------------------
    def _check_power(self) -> None:
        if self._shutdown:
            raise ShutdownEvent()
        if self._power_gen != self._gen_seen or not self._power_on:
            raise PowerEvent()

    def set_rx_mode(self, mode: str, *, flush: bool = False) -> None:
        with self._rx_cond:
            self._rx_mode = mode
            if mode == RX_DROP or flush:
                self._rx.clear()

    def flush_input(self) -> None:
        with self._rx_cond:
            self._rx.clear()

    def enter_busy(self) -> None:
        """U-Boot 가 명령 실행을 시작: 이미 들어온 입력 중 RX FIFO 크기를 넘는 부분은 실제처럼 손실된다."""
        with self._rx_cond:
            self._rx_reading = False
            if self._rx_mode == RX_UART:
                limit = int(self.profile["uart"].get("rx_fifo", 64))
                while len(self._rx) > limit:
                    self._rx.pop()
                    self.rx_overruns += 1

    def getc(self, timeout: float | None = None, *, reading: bool = True) -> int | None:
        """입력 1바이트. timeout(실제 초, time_scale 미적용)이 지나면 None."""
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._rx_cond:
            self._rx_reading = reading
            try:
                while True:
                    self._check_power()
                    if self._rx:
                        return self._rx.popleft()
                    if deadline is not None:
                        left = deadline - time.monotonic()
                        if left <= 0:
                            return None
                        self._rx_cond.wait(min(left, 0.25))
                    else:
                        self._rx_cond.wait(0.25)
            finally:
                if not reading:
                    self._rx_reading = False

    def tstc(self) -> bool:
        self._check_power()
        with self._rx_cond:
            return bool(self._rx)

    def peek_input(self) -> bytes:
        with self._rx_cond:
            return bytes(self._rx)

    def take_input(self) -> bytes:
        with self._rx_cond:
            data = bytes(self._rx)
            self._rx.clear()
            return data

    def ctrlc(self) -> bool:
        """U-Boot ``ctrlc()``: 대기 중인 입력을 모두 읽어 0x03 이 있으면 True. 나머지 바이트는 버려진다."""
        self._check_power()
        with self._rx_cond:
            hit = False
            while self._rx:
                if self._rx.popleft() == 0x03:
                    hit = True
                    break
            return hit

    def sleep(self, seconds: float, *, ctrlc_poll: bool = False) -> bool:
        """time_scale 을 곱한 시간만큼 대기. ctrlc_poll 이면 Ctrl-C 수신 시 True 를 돌려주고 즉시 끝난다."""
        dur = max(0.0, seconds * self.time_scale)
        deadline = time.monotonic() + dur
        while True:
            self._check_power()
            if ctrlc_poll and self.ctrlc():
                return True
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            with self._rx_cond:
                self._rx_cond.wait(min(left, 0.05))

    def write(self, data: str | bytes) -> None:
        """콘솔 출력. ``\\n`` 은 ``\\r\\n`` 으로 바뀐다 (U-Boot serial_putc / 리눅스 tty ONLCR 와 같다)."""
        self._check_power()
        raw = data.encode("utf-8", "replace") if isinstance(data, str) else bytes(data)
        if not raw:
            return
        raw = raw.replace(b"\n", b"\r\n")
        with self._console_lock:
            self._console += raw
            if len(self._console) > self._log_limit:
                del self._console[: len(self._console) - self._log_limit]
        if self.pace_output:
            self._paced_send(raw)
        else:
            self._send(raw)

    def _send(self, raw: bytes) -> None:
        # 전송 큐가 너무 쌓이면 잠깐 기다린다 (수신자가 느려도 메모리가 무한정 늘지 않게; 결국 전송 쪽이 버린다)
        waited = 0
        while self._transports and max(t.pending() for t in self._transports) > 2 * 1024 * 1024 and waited < 400:
            self._check_power()
            time.sleep(0.005)
            waited += 1
        for t in self._transports:
            t.write(raw)

    def _paced_send(self, raw: bytes) -> None:
        bps = max(1.0, self.baud / 10.0)
        step = 64
        for i in range(0, len(raw), step):
            chunk = raw[i : i + step]
            self._send(chunk)
            dur = len(chunk) / bps * self.time_scale
            if dur > 0:
                end = time.monotonic() + dur
                while time.monotonic() < end:
                    self._check_power()
                    time.sleep(min(0.01, max(0.0, end - time.monotonic())))

    def set_state(self, state: str) -> None:
        self._set_state(state)

    def set_baud(self, baud: int) -> None:
        old = self.baud
        self.baud = int(baud)
        self.record({"type": "baud_change", "from": old, "to": self.baud})

    def hang(self) -> None:
        """펌웨어가 멈춘 상태 (출력/입력 없음). 전원 사이클만이 빠져나오는 길이다."""
        self.set_rx_mode(RX_DROP)
        while True:
            self._check_power()
            with self._rx_cond:
                self._rx_cond.wait(0.25)

    # ------------------------------------------------------------------
    # 펌웨어 스레드
    # ------------------------------------------------------------------
    def _ensure_thread(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._thread_main, name="pweh-mock-device", daemon=True)
        self._thread.start()

    def _thread_main(self) -> None:
        from .linux import Linux
        from .uboot import BootKernel, UBoot

        while True:
            with self._rx_cond:
                while not self._power_on and not self._shutdown:
                    self._rx_cond.wait(0.25)
                if self._shutdown:
                    break
                self._gen_seen = self._power_gen
            cold = True
            while True:
                try:
                    self._check_power()
                    if cold:
                        self.ram.clear()
                        self.baud = self.default_baud
                    self.boot_count += 1
                    self.crashed = None
                    self.uboot = UBoot(self)
                    kernel = self.uboot.run()
                    if isinstance(kernel, BootKernel):
                        self.linux = Linux(self, kernel)
                        self.linux.run()
                    # run() 은 정상 반환하지 않는다; 반환되면 멈춘 것으로 본다
                    self.hang()
                except ResetEvent as ev:
                    self.record({"type": "reset", "reason": ev.reason})
                    cold = False
                    continue
                except PowerEvent:
                    break
                except ShutdownEvent:
                    self._set_state("off")
                    return
                except Exception as exc:  # pragma: no cover - 시뮬레이터 버그를 숨기지 않고 기록
                    log.exception("mock device firmware crashed")
                    self.crashed = f"{type(exc).__name__}: {exc}"
                    self.record({"type": "crash", "error": self.crashed})
                    try:
                        self.hang()
                    except PowerEvent:
                        break
                    except ShutdownEvent:
                        self._set_state("off")
                        return
            self.set_rx_mode(RX_DROP)
            self._set_state("off")
        self._set_state("off")

    # ------------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        return {
            "profile": self.profile["name"],
            "state": self._state,
            "powered": self._power_on,
            "baud": self.baud,
            "boot_count": self.boot_count,
            "time_scale": self.time_scale,
            "transports": self.transports_info(),
            "destructive_events": len(self.destructive_events),
            "rx_overruns": self.rx_overruns,
            "crashed": self.crashed,
        }


__all__ = ["MockDevice", "PowerEvent", "ResetEvent", "STATES", "ShutdownEvent", "RX_DROP", "RX_TTY", "RX_UART"]
