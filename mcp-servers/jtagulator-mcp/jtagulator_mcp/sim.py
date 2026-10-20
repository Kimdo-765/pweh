"""JTAGulator 시뮬레이터 (테스트·데모용).

펌웨어(grandideastudio/jtagulator, FW 1.12 / 1.11.1 / 1.10)의 메뉴 상태 기계를 Spin 소스에서 그대로 옮겼다.
문자열은 펌웨어 DAT 섹션과 ``pst.Str(String(...))`` 호출에서 **직접** 옮겨 적었고, 드라이버 쪽 상수(protocol.py)를
import 하지 않는다 — 한쪽의 오타가 다른 쪽에 숨어 테스트가 거짓으로 통과하는 일을 막기 위함이다.

모델링한 동작:
- 리셋 직후 침묵 → 아무 키나 받으면(CharIn: 에코) 배너 출력 → 메인 프롬프트
- 줄 입력(StrInMax): 받은 글자와 CR 을 원시 에코, LF 버림, BS 편집, 최대 길이 초과분 버림
- y/N 기본값 기억, 채널 범위/핀/지연 검증과 'Value out of range!' 취소
- 전압 미설정 시 'Target I/O voltage must be defined!'
- 스페이스바 대기: 1.12 는 에코 없음 + CR/LF 무시, ≤1.11.1 은 CharIn(에코) + 스페이스 외 모든 키 중단
- 스캔: 펌웨어와 같은 순열 순서·진행 표시('-') 주기·결과 형식, 순열 사이마다 수신 바이트가 있으면 중단
- 가상 타깃: 설정한 JTAG 핀아웃/IDCODE, UART 핀/보드레이트/응답에서만 결과를 낸다(잘못된 보드레이트는 깨진 바이트 옵션)
- 영속 모드(OpenOCD/로직 분석기)로 부팅 → Ctrl-X 로 종료
- 리셋(DTR) 모델: reset() 또는 TCP 접속 시 reset_on_connect

전송: TCP(pyserial ``socket://host:port``) 또는 PTY(``/dev/pts/N``).
TCP 는 IPv4 루프백 주소(127.0.0.0/8, localhost)에만 바인드한다(IPv6 주소는 거부 — AF_INET 전용). ``--tcp 0.0.0.0:N`` 처럼
루프백이 아닌 주소는 ``--allow-lan``(라이브러리는 ``allow_lan=True``)이 없으면 거부하고, 있으면 stderr 로 LAN 노출을
경고한다(인증 없는 시리얼 — 브리지 모드 WSL 이면 LAN 전체; port-routing 설계 G13).

CLI::

    python -m jtagulator_mcp.sim --tcp 127.0.0.1:7777 --jtag 3,2,0,1 --trst 4 --uart 6,7,115200
    python -m jtagulator_mcp.sim --pty --firmware 1.11.1 --time-scale 0.05
"""

from __future__ import annotations

import argparse
import collections
import errno
import os
import random
import select
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from pweh.errors import ValidationFailed
from pweh.ports import check_listen_host, lan_listen_warning

CR = "\r"
LF = "\n"
BS = 0x08
CAN = 0x18
PROP_SDA = 29  # 채널이 아닌 임시 핀 (IDCODE 스캔에서 TDI 대신)
MAX_CHAN = 24
MAX_DEVICES_LEN = 32

# ---------------------------------------------------------------------------
# 펌웨어 문자열 (JTAGulator.spin FW 1.12 DAT 섹션에서 옮김)
# ---------------------------------------------------------------------------

INIT_HEADER = (
    "\r\n\n"
    "                                    UU  LLL\r\n"
    " JJJ  TTTTTTT AAAAA  GGGGGGGGGGG   UUUU LLL   AAAAA TTTTTTTT OOOOOOO  RRRRRRRRR\r\n"
    " JJJJ TTTTTTT AAAAAA GGGGGGG       UUUU LLL  AAAAAA TTTTTTTT OOOOOOO  RRRRRRRR\r\n"
    " JJJJ  TTTT  AAAAAAA GGG      UUU  UUUU LLL  AAA AAA   TTT  OOOO OOO  RRR RRR\r\n"
    " JJJJ  TTTT  AAA AAA GGG  GGG UUUU UUUU LLL AAA  AAA   TTT  OOO  OOO  RRRRRRR\r\n"
    " JJJJ  TTTT  AAA  AA GGGGGGGGG UUUUUUUU LLLLLLLL AAAA  TTT OOOOOOOOO  RRR RRR\r\n"
    "  JJJ  TTTT AAA   AA GGGGGGGGG UUUUUUUU LLLLLLLLL AAA  TTT OOOOOOOOO  RRR RRR\r\n"
    "  JJJ  TT                  GGG             AAA                         RR RRR\r\n"
    " JJJ                        GG             AA                              RRR\r\n"
    "JJJ                          G             A                                 RR\r\n\n\n"
    "           Welcome to JTAGulator. Press 'H' for available commands.\r\n"
    "         Warning: Use of this tool may affect target system behavior!"
)

MENU_MAIN = (
    "\r\nTarget Interfaces:\r\n"
    "J   JTAG\r\n"
    "U   UART\r\n"
    "G   GPIO\r\n"
    "S   SWD\r\n"
    "A   All (GPIO, JTAG, SWD, UART)\r\n"
    "\n"
    "General Commands:\r\n"
    "V   Set target I/O voltage\r\n"
    "I   Display version information\r\n"
    "H   Display available commands"
)
MENU_JTAG = (
    "\r\nJTAG Commands:\r\n"
    "J   Identify JTAG pinout (Combined Scan)\r\n"
    "I   Identify JTAG pinout (IDCODE Scan)\r\n"
    "B   Identify JTAG pinout (BYPASS Scan)\r\n"
    "R   Identify RTCK (adaptive clocking)\r\n"
    "D   Get Device ID(s)\r\n"
    "T   Test BYPASS (TDI to TDO)\r\n"
    "Y   Instruction/Data Register (IR/DR) discovery\r\n"
    "P   Pin mapper (EXTEST Scan)\r\n"
    "O   OpenOCD interface"
)
MENU_UART = (
    "\r\nUART Commands:\r\n"
    "U   Identify UART pinout\r\n"
    "T   Identify UART pinout (TXD only, continuous)\r\n"
    "P   UART passthrough"
)
MENU_GPIO = (
    "\r\nGPIO Commands:\r\n"
    "R   Read all channels (input, one shot)\r\n"
    "C   Read all channels (input, continuous)\r\n"
    "W   Write all channels (output)\r\n"
    "L   Logic analyzer (OLS/SUMP)"
)
MENU_SWD = "\r\nSWD Commands:\r\nI   Identify SWD pinout (IDCODE Scan)\r\nD   Get Device ID"
MENU_SHARED = "\r\n\nGeneral Commands:\r\nV   Set target I/O voltage\r\nH   Display available commands\r\nM   Return to main menu"

MSG_JTAGULATING = "\r\nJTAGulating! Press any key to abort...\r\n"
MSG_DEVICES_DETECTED = "Number of devices detected: "
MSG_UNKNOWN_PIN = "\r\nEnter X for any unknown pin."
MSG_SCAN_COMPLETE = " scan complete."
MSG_IDCODE_LISTING_COMPLETE = "\r\nIDCODE listing complete."
MSG_ENTER_TDI = "\r\nEnter TDI pin ["
MSG_ENTER_TDO = "\r\nEnter TDO pin ["
MSG_ENTER_TCK = "\r\nEnter TCK pin ["
MSG_ENTER_TMS = "\r\nEnter TMS pin ["

ERR_TARGET_IO_VOLTAGE = "\r\nTarget I/O voltage must be defined!"
ERR_OUT_OF_RANGE = "\r\nValue out of range!"
ERR_PIN_COLLISION = "\r\nPin numbers must be unique!"
ERR_NO_DEVICE_FOUND = "\r\nNo target device(s) found!"
ERR_IDCODE_ABORTED = "\r\nIDCODE scan aborted!"
ERR_BYPASS_ABORTED = "\r\nBYPASS scan aborted!"
ERR_UART_ABORTED = "\r\nUART scan aborted!"

VOLTAGE_TABLE_MIN, VOLTAGE_TABLE_MAX = 14, 33

BAUD_RATES = (300, 600, 1200, 1800, 2400, 3600, 4800, 7200, 9600, 14400, 19200, 28800,
              31250, 38400, 57600, 76800, 115200, 153600, 230400, 250000, 307200)

BEST_FIT = ((2280, 2520, 2400), (3420, 3780, 3600), (4560, 5040, 4800), (6840, 7560, 7200),
            (9120, 10080, 9600), (13680, 15120, 14400), (18240, 20160, 19200), (27360, 30240, 28800),
            (30241, 32813, 31250), (36480, 40320, 38400), (54720, 60480, 57600), (72960, 80640, 76800),
            (109440, 120960, 115200), (145920, 161280, 153600), (218880, 241920, 230400),
            (241921, 262500, 250000), (291840, 322560, 307200), (328320, 362880, 345600),
            (437760, 483840, 460800), (875520, 949248, 921600), (949249, 988800, 960000),
            (988801, 1050000, 1000000), (1140000, 1260000, 1200000), (1425000, 1575000, 1500000))

MENU_PREFIX = {"main": "", "jtag": "JTAG", "uart": "UART", "gpio": "GPIO", "swd": "SWD"}

SUPPORTED_SIM_FIRMWARE = ("1.12", "1.11.1", "1.10")


class _Fail(Exception):
    """명령을 끝내고 메뉴 프롬프트로 돌아감 (펌웨어의 '오류 메시지 출력 후 return')."""


class _Reset(Exception):
    pass


class _Stop(Exception):
    pass


@dataclass
class SimJTAGTarget:
    """가상 JTAG 타깃: 이 핀아웃에서만 IDCODE/BYPASS 가 응답한다."""

    tdi: int
    tdo: int
    tck: int
    tms: int
    trst: int | None = None
    idcodes: list[int] = field(default_factory=lambda: [0x4BA00477])


@dataclass
class SimUARTTarget:
    """가상 UART 타깃: txd 로 송신, rxd 로 수신, baud 에서만 올바르게 통신."""

    txd: int
    rxd: int
    baud: int = 115200
    response: bytes = b"\r\nlogin: "
    respond_to: bytes | None = None  # 프로브에 이 바이트열이 있을 때만 응답 (None 이면 아무 프로브에나)
    garbage_on_wrong_baud: bool = True  # 맞는 핀·틀린 보드레이트에서 깨진 바이트를 돌려줌
    active: bool = True  # TXD 스캔에서 계속 송신 중(부팅 로그 등)인지


@dataclass
class SimConfig:
    firmware: str = "1.12"
    start_state: str = "wake"  # wake | menu | ocd | sump
    jtag: SimJTAGTarget | None = None
    uart: SimUARTTarget | None = None
    false_idcodes: dict[tuple[int, int, int], int] = field(default_factory=dict)  # (tdo,tck,tms) → 오탐 IDCODE
    time_scale: float = 0.0  # 펌웨어 지연 모델(순열당 시간, TRST 100ms, LOW 펄스 등)에 곱하는 계수
    perm_delay: float = 0.0  # 순열마다 추가로 기다릴 시간(초, 배율 미적용) — 취소 시험용
    boot_delay: float = 0.0  # 리셋 후 키를 받기 전 침묵 시간(초). 이 동안 받은 바이트는 버림
    mode_exit_delay: float = 1.0  # 영속 모드에서 Ctrl-X 후 메시지까지(펌웨어는 pst.Start 의 1초 대기)
    txd_report_interval: float = 0.05  # TXD 스캔 결과 보고 간격(초)
    stored_vtarget: int = 33  # 영속 모드 부팅 시 EEPROM 에 저장된 전압(0.1 V 단위)
    gpio_value: int = 0xFFFFFF  # GPIO 'R' 이 읽는 24채널 레벨 (입력은 레벨 변환기 때문에 기본 HIGH)


def _fw_tuple(fw: str) -> tuple[int, ...]:
    return tuple(int(x) for x in fw.split("."))


class JTAGulatorSim:
    """펌웨어 메인 루프를 스레드 하나에서 돌린다. 전송 계층은 feed()/attach() 로 연결한다."""

    def __init__(self, config: SimConfig | None = None) -> None:
        self.cfg = config or SimConfig()
        if self.cfg.firmware not in SUPPORTED_SIM_FIRMWARE:
            # 버전 문자열만 다른 펌웨어(예: 1.9 거부 시험)는 1.10 대화로 동작시킨다
            self._dialect = (1, 10)
        else:
            self._dialect = _fw_tuple(self.cfg.firmware)
        self._rx: collections.deque[int] = collections.deque()
        self._cond = threading.Condition()
        self._writer: Callable[[bytes], None] | None = None
        self._writer_lock = threading.Lock()
        self._stop = False
        self._reset_req = False
        self._thread: threading.Thread | None = None
        self._sleep_debt = 0.0
        self.events: list[str] = []
        self.output_log = bytearray()
        self.boots = 0
        self._persistent = self.cfg.start_state if self.cfg.start_state in ("ocd", "sump") else None
        self._first_boot = True
        self._defaults()

    # -- 상태 -------------------------------------------------------------------
    def _defaults(self) -> None:
        self.menu = "main"
        self.vtarget = -1
        self.ch_start = 0
        self.ch_end = 0
        self.pins_low = 0
        self.pins_low_delay = 100
        self.pins_high_delay = 100
        self.j = {"tdi": 0, "tdo": 0, "tck": 0, "tms": 0, "trst": 0}
        self.j_pins_known = 0
        self.u_txd = 0
        self.u_rxd = 0
        self.u_baud = 0
        self.u_str = b""
        self.u_hex = 0
        self.u_pins_known = 0
        self.u_printable = 0
        self.u_wait_delay = 10
        self.u_baud_ignore = 0

    def state(self) -> dict[str, object]:
        return {
            "menu": self.menu,
            "vtarget": None if self.vtarget == -1 else f"{self.vtarget // 10}.{self.vtarget % 10}",
            "ch_start": self.ch_start,
            "ch_end": self.ch_end,
            "pins_low": self.pins_low,
            "j_pins_known": self.j_pins_known,
            "u_pins_known": self.u_pins_known,
            "persistent": self._persistent,
            "boots": self.boots,
        }

    @property
    def voltage(self) -> str | None:
        return None if self.vtarget == -1 else f"{self.vtarget // 10}.{self.vtarget % 10}"

    # -- 전송 연결 ----------------------------------------------------------------
    def attach(self, writer: Callable[[bytes], None]) -> None:
        with self._writer_lock:
            self._writer = writer

    def detach(self) -> None:
        with self._writer_lock:
            self._writer = None

    def feed(self, data: bytes) -> None:
        with self._cond:
            self._rx.extend(data)
            self._cond.notify_all()

    def start(self) -> "JTAGulatorSim":
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="jtagulator-sim", daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        with self._cond:
            self._stop = True
            self._cond.notify_all()
        if self._thread is not None:
            self._thread.join(timeout=3.0)

    def reset(self) -> None:
        """DTR/전원 리셋: 입력 버퍼를 비우고 부팅부터 다시."""
        with self._cond:
            self._reset_req = True
            self._rx.clear()
            self._cond.notify_all()

    # -- 펌웨어 입출력 프리미티브 ---------------------------------------------------
    def _check(self) -> None:
        if self._stop:
            raise _Stop()
        if self._reset_req:
            raise _Reset()

    def _emit(self, text: str) -> None:
        data = text.encode("latin-1")
        self.output_log += data
        if len(self.output_log) > 2_000_000:
            del self.output_log[:1_000_000]
        with self._writer_lock:
            w = self._writer
        if w is not None:
            try:
                w(data)
            except Exception:  # noqa: BLE001 - 클라이언트가 끊어도 장치는 계속
                pass

    def _rx_byte(self) -> int:
        with self._cond:
            while True:
                self._check()
                if self._rx:
                    return self._rx.popleft()
                self._cond.wait(0.1)

    def _rx_pending(self) -> bool:
        with self._cond:
            self._check()
            return bool(self._rx)

    def _rx_flush(self) -> None:
        with self._cond:
            self._rx.clear()

    def _sleep(self, seconds: float) -> None:
        """펌웨어 지연 모델 (time_scale 배율). 아주 짧은 지연은 모아서 잔다."""
        self._sleep_debt += seconds * self.cfg.time_scale
        if self._sleep_debt >= 0.002:
            self._real_sleep(self._sleep_debt)
            self._sleep_debt = 0.0

    def _real_sleep(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        with self._cond:
            while True:
                self._check()
                rem = end - time.monotonic()
                if rem <= 0:
                    return
                self._cond.wait(min(rem, 0.05))

    def _perm_cost(self, seconds: float) -> None:
        self._sleep(seconds)
        if self.cfg.perm_delay:
            self._real_sleep(self.cfg.perm_delay)
        else:
            self._check()

    def _char_in(self) -> int:
        c = self._rx_byte()
        self._emit(chr(c) if c in (10, 13) or 0x20 <= c <= 0x7E else ".")
        return c

    def _char_in_noecho(self) -> int:
        return self._rx_byte()

    def _str_in_max(self, maxcount: int) -> str:
        buf: list[str] = []
        while True:
            c = self._rx_byte()
            if c == BS:
                if buf:
                    buf.pop()
                    self._emit("\x08 \x08")
            elif c == 13:
                if len(buf) < maxcount:
                    self._emit("\r")
                s = "".join(buf)
                return s.split("\x00", 1)[0]  # strsize 는 NUL 에서 멈춤
            elif c == 10:
                pass
            elif len(buf) < maxcount:
                buf.append(chr(c))
                self._emit(chr(c))

    @staticmethod
    def _dec_pin_value(s: str) -> int:
        if s == "":
            return -1
        v = 0
        for ch in s:
            if "0" <= ch <= "9":
                v = v * 10 + (ord(ch) - 48)
            elif ch in ".,":
                continue
            else:
                return -3
        return v

    def _get_decimal_pin(self) -> int:
        return self._dec_pin_value(self._str_in_max(12))

    def _get_pin(self) -> int:
        s = self._str_in_max(12)
        if s == "":
            return -1
        if s[0] in "Xx":
            return -2 if len(s) == 1 else -3
        return self._dec_pin_value(s)

    def _yes_no(self, prefix: str, cur: int) -> int:
        self._emit(prefix + ("Y/n]: " if cur else "y/N]: "))
        s = self._str_in_max(12)
        if len(s) > 1:
            raise _Fail(ERR_OUT_OF_RANGE)
        if s == "":
            return cur
        if s in "Nn":
            return 0
        if s in "Yy":
            return 1
        raise _Fail(ERR_OUT_OF_RANGE)

    # -- 메인 루프 ----------------------------------------------------------------
    def _run(self) -> None:
        while True:
            try:
                with self._cond:
                    self._reset_req = False
                self.boots += 1
                self._boot()
                self._main_loop()
            except _Reset:
                continue
            except _Stop:
                return

    def _boot(self) -> None:
        if self.cfg.boot_delay and not self._first_boot:
            # 부트로더/EEPROM 로딩 동안 받은 바이트는 버려진다
            self._real_sleep(self.cfg.boot_delay)
            self._rx_flush()
        first = self._first_boot
        self._first_boot = False
        if self._persistent == "ocd":
            self._defaults()
            self.vtarget = self.cfg.stored_vtarget  # DAC 출력 (vTargetIO 는 EEPROM 값)
            self._ocd_mode()
            return
        if self._persistent == "sump":
            self._defaults()
            self.vtarget = self.cfg.stored_vtarget
            self._sump_mode()
            return
        self._defaults()
        if first and self.cfg.start_state == "menu":
            return  # 이미 깨어 있는 상태로 시작 (배너 없이 메인 루프)
        self._char_in()  # 아무 키나 기다림 (에코)
        self._emit(INIT_HEADER)

    def _main_loop(self) -> None:
        while True:
            self._emit("\r\n\n" + MENU_PREFIX[self.menu] + "> ")
            line = self._str_in_max(12)
            if len(line) != 1:
                self._invalid()
                continue
            try:
                self._dispatch(line.upper())
            except _Fail as f:
                self._emit(str(f))

    def _invalid(self) -> None:
        if self._dialect >= (1, 12):
            self._emit("\r\n? Press 'H' for available commands.")
        else:
            self._emit("\r\n?")

    NEEDS_V = {
        ("main", "A"), ("jtag", "J"), ("jtag", "I"), ("jtag", "B"), ("jtag", "R"), ("jtag", "D"), ("jtag", "T"),
        ("jtag", "Y"), ("jtag", "P"), ("jtag", "O"), ("uart", "U"), ("uart", "T"), ("uart", "P"),
        ("gpio", "R"), ("gpio", "C"), ("gpio", "W"), ("gpio", "L"), ("swd", "I"), ("swd", "D"),
    }

    def _dispatch(self, k: str) -> None:
        m = self.menu
        if (m, k) in self.NEEDS_V and self.vtarget == -1:
            raise _Fail(ERR_TARGET_IO_VOLTAGE)
        if m == "main":
            if k in "JUGS":
                self.menu = {"J": "jtag", "U": "uart", "G": "gpio", "S": "swd"}[k]
            elif k == "V":
                self._set_voltage()
            elif k == "I":
                self._emit(self._version_info())
            elif k == "H":
                self._emit(MENU_MAIN)
            elif k == "A" and self._dialect >= (1, 12):
                self._all_scan()
            else:
                self._invalid()
            return
        if m == "jtag" and k in "JIBDT":
            {"J": lambda: self._idcode_scan(1), "I": lambda: self._idcode_scan(0), "B": self._bypass_scan,
             "D": self._idcode_known, "T": self._bypass_known}[k]()
            return
        if m == "jtag" and k in "RYPO":
            self._not_simulated(k)
            return
        if m == "uart" and k == "U":
            self._uart_scan()
            return
        if m == "uart" and k == "T":
            self._uart_scan_txd()
            return
        if m == "uart" and k == "P":
            self._not_simulated(k)
            return
        if m == "gpio" and k == "R":
            self._read_io_pins()
            return
        if m == "gpio" and k in "CWL":
            self._not_simulated(k)
            return
        if m == "swd" and k in "ID":
            self._not_simulated(k)
            return
        # 공통
        if k == "V":
            self._set_voltage()
        elif k == "H":
            self._emit({"jtag": MENU_JTAG, "uart": MENU_UART, "gpio": MENU_GPIO, "swd": MENU_SWD}[m] + MENU_SHARED)
        elif k == "M":
            self.menu = "main"
        else:
            self._invalid()

    def _all_scan(self) -> None:
        """메인 'A' (FW 1.12): 하위 스캔을 차례로 실행. 하위 스캔의 오류/중단은 그 하위 스캔만 끝내고 다음으로 넘어간다."""
        spacer = "\r\n\n-----"
        subs = [
            self._read_io_pins,
            lambda: self._idcode_scan(1),
            lambda: self._idcode_scan(0),
            self._bypass_scan,
            lambda: self._not_simulated("R"),  # RTCK
            lambda: self._not_simulated("I"),  # SWD IDCODE
            self._uart_scan_txd,
            self._uart_scan,
        ]
        for i, sub in enumerate(subs):
            if i:
                self._emit(spacer)
            try:
                sub()
            except _Fail as f:
                self._emit(str(f))

    def _read_io_pins(self) -> None:
        """Read_IO_Pins + Display_IO_Pins: pst.Char(CR) 후 'CH23..CH0: ' + 8비트×3 (각각 뒤 공백) + ' (0x' + hex6 + ')'."""
        self._emit("\r")
        value = self.cfg.gpio_value & 0xFFFFFF
        t = self.cfg.uart
        self._gpio_reads = getattr(self, "_gpio_reads", 0) + 1
        if t is not None and t.active and self._gpio_reads % 2 == 0:
            value &= ~(1 << t.txd)  # 송신 중인 TXD 는 읽는 순간에 따라 LOW 로 보임 (결정적으로 번갈아)
        self.events.append("gpio_read")
        groups = "".join(f"{(value >> c) & 0xFF:08b} " for c in (16, 8, 0))
        self._emit(f"\r\nCH23..CH0: {groups} (0x{value:06X})")

    def _not_simulated(self, k: str) -> None:
        self.events.append(f"not_simulated:{self.menu}:{k}")
        self._emit(f"\r\n[sim] command '{k}' is not simulated")

    def _version_info(self) -> str:
        text = (
            f"\r\nJTAGulator FW {self.cfg.firmware}\r\n"
            "Designed by Joe Grand, Grand Idea Studio, Inc.\r\n"
            "Main: jtagulator.com\r\n"
            "Source: github.com/grandideastudio/jtagulator"
        )
        if self._dialect < (1, 12):
            text += "\r\nSupport: www.parallax.com/support"
        return text

    # -- 전압 ---------------------------------------------------------------------
    def _volts_str(self) -> str:
        return "Undefined" if self.vtarget == -1 else f"{self.vtarget // 10}.{self.vtarget % 10}"

    def _set_voltage(self) -> None:
        self._emit("\r\nCurrent target I/O voltage: " + self._volts_str())
        self._emit("\r\nEnter new target I/O voltage (1.4 - 3.3, 0 for off): ")
        value = self._get_decimal_pin()
        if value == 2:
            value = 20
        if value == 3:
            value = 30
        if value == 0:
            self.vtarget = -1
            self.events.append("voltage:off")
            self._emit("\r\nTarget I/O voltage off.")
        elif value < VOLTAGE_TABLE_MIN or value > VOLTAGE_TABLE_MAX:
            self._emit(ERR_OUT_OF_RANGE)
        else:
            self.vtarget = value
            self.events.append(f"voltage:{self._volts_str()}")
            self._emit("\r\nNew target I/O voltage set: " + self._volts_str())
            self._emit("\r\nWarning: Ensure VADJ is NOT connected to target!")

    # -- 공통 대화 ------------------------------------------------------------------
    def _get_channels(self, min_chan: int) -> None:
        self._emit(f"\r\nEnter starting channel [{self.ch_start}]: ")
        x = self._get_decimal_pin()
        if x == -1:
            x = self.ch_start
        if x < 0 or x > MAX_CHAN - 1:
            raise _Fail(ERR_OUT_OF_RANGE)
        d = x if self.ch_end < x else self.ch_end
        self._emit(f"\r\nEnter ending channel [{d}]: ")
        y = self._get_decimal_pin()
        if y == -1:
            y = d
        if y < x + min_chan - 1 or y > MAX_CHAN - 1:
            raise _Fail(ERR_OUT_OF_RANGE)
        self.ch_start, self.ch_end = x, y

    def _display_permutations(self, n: int, r: int) -> None:
        v = 1
        if r != 0:
            for i in range(n - r + 1, n + 1):
                v *= i
        self._emit(f"\r\nPossible permutations: {v}")

    def _get_settings(self) -> None:
        word = "before" if self._dialect >= (1, 11) else "between"
        self.pins_low = self._yes_no(f"\r\n\nBring channels LOW {word} each permutation? [", self.pins_low)
        if self.pins_low:
            self._emit(f"\r\nEnter length of time for channels to remain LOW (in ms, 1 - 1000) [{self.pins_low_delay}]: ")
            v = self._get_decimal_pin()
            if v != -1:
                if v < 1 or v > 1000:
                    raise _Fail(ERR_OUT_OF_RANGE)
                self.pins_low_delay = v
            self._emit(
                f"\r\nEnter length of time after channels return HIGH before proceeding (in ms, 1 - 1000) [{self.pins_high_delay}]: "
            )
            v = self._get_decimal_pin()
            if v != -1:
                if v < 1 or v > 1000:
                    raise _Fail(ERR_OUT_OF_RANGE)
                self.pins_high_delay = v

    def _get_pins_known(self, kind: int) -> None:
        cur = self.j_pins_known if kind == 0 else self.u_pins_known
        val = self._yes_no("\r\nAre any pins already known? [", cur)
        if kind == 0:
            self.j_pins_known = val
        else:
            self.u_pins_known = val

    def _wait_for_space(self, err: str) -> None:
        if self._dialect >= (1, 12):
            self._emit("\r\nPress spacebar to begin (any other key besides Enter to abort)...")
            while True:
                c = self._char_in_noecho()
                if c in (10, 13):
                    continue
                if c != 0x20:
                    raise _Fail(err)
                return
        self._emit("\r\nPress spacebar to begin (any other key to abort)...")
        if self._char_in() != 0x20:
            raise _Fail(err)

    def _progress(self, ctr: int, mod: int, dash: bool) -> None:
        if ctr % mod == 0 and dash:
            self._emit("-")

    def _pins_low_pulse(self) -> None:
        if self.pins_low:
            self._sleep((self.pins_low_delay + self.pins_high_delay) / 1000.0)

    # -- 가상 타깃 ------------------------------------------------------------------
    def _jtag_match3(self, tdo: int, tck: int, tms: int) -> bool:
        t = self.cfg.jtag
        return t is not None and (tdo, tck, tms) == (t.tdo, t.tck, t.tms)

    def _read_first_id(self, tdo: int, tck: int, tms: int, trst_low: int | None = None) -> int:
        t = self.cfg.jtag
        if self._jtag_match3(tdo, tck, tms):
            assert t is not None
            if trst_low is not None and t.trst is not None and trst_low == t.trst:
                return 0x00000000  # TAP 이 리셋에 묶여 IDCODE 대신 다른 값
            return t.idcodes[0] if t.idcodes else 0xFFFFFFFF
        fp = self.cfg.false_idcodes.get((tdo, tck, tms))
        if fp is not None:
            return fp  # 오탐(잡음) 응답은 TRST 와 무관하게 같은 값
        return 0xFFFFFFFF

    def _read_ids(self, tdo: int, tck: int, tms: int, n: int) -> list[int]:
        t = self.cfg.jtag
        if self._jtag_match3(tdo, tck, tms):
            assert t is not None
            ids = list(t.idcodes)
        else:
            fp = self.cfg.false_idcodes.get((tdo, tck, tms))
            ids = [fp] if fp is not None else []
        ids = ids[:n]
        return ids + [0xFFFFFFFF] * (n - len(ids))

    def _bypass_ok(self, tdi: int, tdo: int, tck: int, tms: int) -> bool:
        t = self.cfg.jtag
        return t is not None and (tdi, tdo, tck, tms) == (t.tdi, t.tdo, t.tck, t.tms)

    def _detect_devices(self, tdi: int, tdo: int, tck: int, tms: int, trst_low: int | None = None) -> int:
        t = self.cfg.jtag
        if not self._bypass_ok(tdi, tdo, tck, tms):
            return 0
        assert t is not None
        if trst_low is not None and t.trst is not None and trst_low == t.trst:
            return 0
        return len(t.idcodes) or 1

    # -- 출력 형식 ------------------------------------------------------------------
    def _display_jtag_pins(self) -> None:
        tdi = "N/A" if self.j["tdi"] >= MAX_CHAN else str(self.j["tdi"])
        self._emit(f"\r\nTDI: {tdi}\r\nTDO: {self.j['tdo']}\r\nTCK: {self.j['tck']}\r\nTMS: {self.j['tms']}\r\n")

    def _display_device_id(self, value: int, num: int, details: int) -> None:
        value &= 0xFFFFFFFF
        if value == 0xFFFFFFFF or (value & 1) != 1:
            return
        if details:
            self._emit("\r\n\n")
        ver = (value >> 28) & 0xF
        part = (value >> 12) & 0xFFFF
        mfr = (value >> 1) & 0x7FF
        self._emit(f"Device ID #{num}: {ver:04b} {part:016b} {mfr:011b} {value & 1:01b} (0x{value:08X})")
        if details:
            self._emit(f"\r\n-> Manufacturer ID: 0x{mfr:03X}\r\n-> Part Number: 0x{part:04X}\r\n-> Version: 0x{ver:01X}")
        self._emit("\r\n")

    def _jtag_cleanup(self, num: int, tdi: int, tdo: int, tck: int, tms: int) -> None:
        if num == 0:
            for k in self.j:
                self.j[k] = 0
        else:
            self.j.update(tdi=tdi, tdo=tdo, tck=tck, tms=tms)

    # -- JTAG 스캔 ------------------------------------------------------------------
    def _idcode_scan(self, typ: int) -> None:
        if typ == 0:
            self._get_channels(3)
            self._display_permutations(self.ch_end - self.ch_start + 1, 3)
        else:
            self._get_channels(4)
            self._display_permutations(self.ch_end - self.ch_start + 1, 4)
        self._get_settings()
        if typ == 0:
            err = ERR_IDCODE_ABORTED
        else:
            err = "\r\nJTAG combined scan aborted!" if self._dialect >= (1, 12) else "\r\nJTAG scan aborted!"
        self._wait_for_space(err)
        self.events.append("scan_start:" + ("idcode" if typ == 0 else "jtag"))
        self._emit(MSG_JTAGULATING)
        mod = 1 if self.pins_low else 100
        self.j["tdi"] = PROP_SDA
        num = ctr = match = 0
        x = {"tdi": 0, "tdo": 0, "tck": 0, "tms": 0}
        rng = range(self.ch_start, self.ch_end + 1)
        id0 = 0xFFFFFFFF

        def abort() -> None:
            self._jtag_cleanup(num, 0 if typ == 0 else x["tdi"], x["tdo"], x["tck"], x["tms"])
            self._emit(err)
            self._rx_flush()
            self.events.append("scan_aborted:" + ("idcode" if typ == 0 else "jtag"))
            raise _Fail("")

        for tdo in rng:
            for tck in rng:
                if tck == tdo:
                    continue
                for tms in rng:
                    if tms in (tck, tdo):
                        continue
                    if self._rx_pending():
                        abort()
                    self._pins_low_pulse()
                    self.j.update(tdo=tdo, tck=tck, tms=tms)
                    self._perm_cost(0.0025)
                    value = self._read_first_id(tdo, tck, tms)
                    if value != 0xFFFFFFFF and value & 1:
                        if typ == 0:
                            self._display_jtag_pins()
                            num += 1
                            x.update(tdo=tdo, tck=tck, tms=tms)
                            self.j_pins_known = 1
                            ids = self._read_ids(tdo, tck, tms, MAX_DEVICES_LEN)
                            id0 = ids[0]
                            for i, v in enumerate(ids):
                                self._display_device_id(v, i + 1, 0)
                        else:
                            for tdi in rng:
                                if tdi in (tms, tck, tdo):
                                    continue
                                if self._rx_pending():
                                    abort()
                                self._pins_low_pulse()
                                self._sleep(0.045)
                                ndev = self._detect_devices(tdi, tdo, tck, tms)
                                if self._bypass_ok(tdi, tdo, tck, tms):
                                    self.j.update(tdi=tdi)
                                    self._display_jtag_pins()
                                    num += 1
                                    x.update(tdi=tdi, tdo=tdo, tck=tck, tms=tms)
                                    self.j_pins_known = 1
                                    match = 1
                                    self._pins_low_pulse()
                                    ids = self._read_ids(tdo, tck, tms, ndev)
                                    id0 = ids[0] if ids else 0xFFFFFFFF
                                    for i, v in enumerate(ids):
                                        self._display_device_id(v, i + 1, 0)
                                    break
                                match = 0
                                ctr += 1
                                self._progress(ctr, mod, True)
                        if typ == 0 or (typ == 1 and match != 0):
                            cur_tdi = self.j["tdi"]
                            for trst in rng:
                                if trst in (tms, tck, tdo, cur_tdi):
                                    continue
                                if self._rx_pending():
                                    abort()
                                self._pins_low_pulse()
                                self._sleep(0.1)
                                value_new = self._read_first_id(tdo, tck, tms, trst_low=trst)
                                if value_new != id0:
                                    self._emit(f"TRST#: {trst}\r\n")
                                ctr += 1
                                self._progress(ctr, mod, False)
                            self._emit("\r\n")
                    ctr += 1
                    self._progress(ctr, mod, True)
        if num == 0:
            self._emit(ERR_NO_DEVICE_FOUND)
            self.j_pins_known = 0
        self._jtag_cleanup(num, 0 if typ == 0 else x["tdi"], x["tdo"], x["tck"], x["tms"])
        if typ == 0:
            self._emit("\r\nIDCODE")
        else:
            self._emit("\r\nJTAG combined" if self._dialect >= (1, 12) else "\r\nJTAG")
        self._emit(MSG_SCAN_COMPLETE)
        self.events.append("scan_complete:" + ("idcode" if typ == 0 else "jtag"))

    def _set_jtag_partial(self) -> None:
        vals = {}
        for name, msg in (("tdi", MSG_ENTER_TDI), ("tdo", MSG_ENTER_TDO), ("tck", MSG_ENTER_TCK), ("tms", MSG_ENTER_TMS)):
            self._emit(f"{msg}{self.j[name]}]: ")
            v = self._get_pin()
            if v == -1:
                v = self.j[name]
            if v < -2 or v > self.ch_end:
                raise _Fail(ERR_OUT_OF_RANGE)
            vals[name] = v
        known = [v for v in vals.values() if v != -2]
        if len(set(known)) != len(known):
            raise _Fail(ERR_PIN_COLLISION)
        self.j.update(vals)

    def _bypass_scan(self) -> None:
        num_pins = 4
        self._get_channels(num_pins)
        ranges = {k: (self.ch_start, self.ch_end) for k in ("tdi", "tdo", "tck", "tms")}
        self._get_pins_known(0)
        if self.j_pins_known == 1:
            self._emit(MSG_UNKNOWN_PIN)
            self._set_jtag_partial()
            for k in ("tdi", "tdo", "tms", "tck"):
                if self.j[k] != -2:
                    ranges[k] = (self.j[k], self.j[k])
                    num_pins -= 1
                else:
                    self.j[k] = 0
        self._display_permutations((self.ch_end - self.ch_start + 1) - (4 - num_pins), num_pins)
        self._get_settings()
        self._wait_for_space(ERR_BYPASS_ABORTED)
        self.events.append("scan_start:bypass")
        self._emit(MSG_JTAGULATING)
        mod = 1 if self.pins_low else 10
        num = ctr = 0
        x = {"tdi": 0, "tdo": 0, "tck": 0, "tms": 0}

        def rr(k: str) -> range:
            a, b = ranges[k]
            return range(a, b + 1)

        def abort() -> None:
            self._jtag_cleanup(num, x["tdi"], x["tdo"], x["tck"], x["tms"])
            self._emit(ERR_BYPASS_ABORTED)
            self._rx_flush()
            self.events.append("scan_aborted:bypass")
            raise _Fail("")

        for tdi in rr("tdi"):
            for tdo in rr("tdo"):
                if tdo == tdi:
                    continue
                for tck in rr("tck"):
                    if tck in (tdo, tdi):
                        continue
                    for tms in rr("tms"):
                        if tms in (tck, tdo, tdi):
                            continue
                        if self._rx_pending():
                            abort()
                        self._pins_low_pulse()
                        self.j.update(tdi=tdi, tdo=tdo, tck=tck, tms=tms)
                        self._perm_cost(0.045)
                        value = self._detect_devices(tdi, tdo, tck, tms)
                        if self._bypass_ok(tdi, tdo, tck, tms):
                            self._display_jtag_pins()
                            num += 1
                            x.update(tdi=tdi, tdo=tdo, tck=tck, tms=tms)
                            self.j_pins_known = 1
                            for trst in range(self.ch_start, self.ch_end + 1):
                                if trst in (tms, tck, tdo, tdi):
                                    continue
                                if self._rx_pending():
                                    abort()
                                self._pins_low_pulse()
                                self._sleep(0.1)
                                value_new = self._detect_devices(tdi, tdo, tck, tms, trst_low=trst)
                                if value_new != value and value_new <= MAX_DEVICES_LEN:
                                    self._emit(f"TRST#: {trst}\r\n")
                                ctr += 1
                                self._progress(ctr, mod, False)
                            self._emit(MSG_DEVICES_DETECTED + str(value) + "\r\n")
                        ctr += 1
                        self._progress(ctr, mod, True)
        if num == 0:
            self._emit(ERR_NO_DEVICE_FOUND)
            self.j_pins_known = 0
        self._jtag_cleanup(num, x["tdi"], x["tdo"], x["tck"], x["tms"])
        self._emit("\r\nBYPASS")
        self._emit(MSG_SCAN_COMPLETE)
        self.events.append("scan_complete:bypass")

    def _set_jtag(self, get_tdi: bool) -> dict[str, int]:
        vals: dict[str, int] = {}
        if get_tdi:
            self._emit(f"{MSG_ENTER_TDI}{self.j['tdi']}]: ")
            v = self._get_decimal_pin()
            if v == -1:
                v = self.j["tdi"]
            if v < 0 or v > MAX_CHAN - 1:
                raise _Fail(ERR_OUT_OF_RANGE)
            vals["tdi"] = v
        else:
            self._emit("\r\nTDI not needed to retrieve Device ID.\r\n")
            vals["tdi"] = PROP_SDA
        for name, msg in (("tdo", MSG_ENTER_TDO), ("tck", MSG_ENTER_TCK), ("tms", MSG_ENTER_TMS)):
            self._emit(f"{msg}{self.j[name]}]: ")
            v = self._get_decimal_pin()
            if v == -1:
                v = self.j[name]
            if v < 0 or v > MAX_CHAN - 1:
                raise _Fail(ERR_OUT_OF_RANGE)
            vals[name] = v
        if len(set(vals.values())) != 4:
            raise _Fail(ERR_PIN_COLLISION)
        self.j.update(vals)
        return vals

    def _idcode_known(self) -> None:
        xtdi = self.j["tdi"]
        p = self._set_jtag(False)
        self.events.append("device_ids")
        ids = self._read_ids(p["tdo"], p["tck"], p["tms"], MAX_DEVICES_LEN)
        for i, v in enumerate(ids):
            self._display_device_id(v, i + 1, 1)
        # 펌웨어의 'if (i == 0)' 검사는 루프 뒤 i=32 라 'No target device(s) found!' 를 내지 않는다
        self.j["tdi"] = xtdi
        self._emit(MSG_IDCODE_LISTING_COMPLETE)

    def _bypass_known(self) -> None:
        p = self._set_jtag(True)
        self.events.append("bypass_test")
        num = self._detect_devices(p["tdi"], p["tdo"], p["tck"], p["tms"])
        self._emit("\r\n")
        self._emit(MSG_DEVICES_DETECTED + str(num))
        if num == 0:
            self._emit(ERR_NO_DEVICE_FOUND)
            self.j_pins_known = 0
            return
        data_in = random.getrandbits(32)
        data_out = data_in if self._bypass_ok(p["tdi"], p["tdo"], p["tck"], p["tms"]) else (data_in ^ 0xFFFFFFFF)
        self._emit(f"\r\nPattern in to TDI:    {data_in:032b}")
        self._emit(f"\r\nPattern out from TDO: {data_out:032b}")
        self._emit("\r\nMatch!" if data_in == data_out else "\r\nNo Match!")

    # -- UART 스캔 -----------------------------------------------------------------
    def _uart_note(self) -> None:
        if self._dialect >= (1, 11):
            self._emit("\r\nNote: UART pin naming is from the target's perspective.")
        else:
            self._emit("\r\nUART pin naming is from the target's perspective.")

    def _uart_probe_bytes(self) -> bytes:
        return self.u_str[: self.u_hex] if self.u_hex else self.u_str + b"\r"

    def _uart_response(self, txd: int, rxd: int, baud: int, probe: bytes) -> bytes:
        t = self.cfg.uart
        if t is None or txd != t.txd:
            return b""
        if baud == t.baud:
            if rxd == t.rxd and (t.respond_to is None or t.respond_to in probe):
                return t.response[:16]
            return b""
        if t.garbage_on_wrong_baud and rxd == t.rxd:
            rnd = random.Random((baud << 10) ^ (txd << 5) ^ rxd)
            n = rnd.randint(1, 6)
            return bytes(rnd.randint(0x80, 0xFF) if rnd.random() < 0.7 else rnd.randint(0x20, 0x7E) for _ in range(n))
        return b""

    def _uart_scan(self) -> None:
        self._uart_note()
        num_pins = 2
        self._get_channels(num_pins)
        rng_txd = (self.ch_start, self.ch_end)
        rng_rxd = (self.ch_start, self.ch_end)
        self._get_pins_known(1)
        if self.u_pins_known == 1:
            self._emit(MSG_UNKNOWN_PIN)
            self._emit(f"\r\nEnter TXD pin [{self.u_txd}]: ")
            xt = self._get_pin()
            if xt == -1:
                xt = self.u_txd
            if xt < -2 or xt > MAX_CHAN - 1:
                raise _Fail(ERR_OUT_OF_RANGE)
            self._emit(f"\r\nEnter RXD pin [{self.u_rxd}]: ")
            xr = self._get_pin()
            if xr == -1:
                xr = self.u_rxd
            if xr < -2 or xr > MAX_CHAN - 1:
                raise _Fail(ERR_OUT_OF_RANGE)
            if xt == xr:
                raise _Fail(ERR_PIN_COLLISION)
            self.u_txd, self.u_rxd = xt, xr
            if self.u_txd != -2:
                rng_txd = (self.u_txd, self.u_txd)
                num_pins -= 1
            else:
                self.u_txd = 0
            if self.u_rxd != -2:
                rng_rxd = (self.u_rxd, self.u_rxd)
                num_pins -= 1
            else:
                self.u_rxd = 0
        self._display_permutations((self.ch_end - self.ch_start + 1) - (2 - num_pins), num_pins)
        shown = "CR" if (not self.u_str and self.u_hex == 0) else (
            self.u_str.decode("latin-1") if self.u_hex == 0 else "\\x" + "".join(f"{b:02X}" for b in self.u_str[: self.u_hex])
        )
        self._emit("\r\nEnter text string to output (prefix with \\x for hex) [" + shown + "]: ")
        xstr = self._str_in_max(34)
        i = len(xstr)
        if i != 0:
            if any(ord(c) < 0x20 or ord(c) > 0x7E for c in xstr):
                raise _Fail(ERR_OUT_OF_RANGE)
            if xstr[:2] == "\\x":
                if i == 2:
                    raise _Fail(ERR_OUT_OF_RANGE)
                if i % 2 != 0:
                    raise _Fail(ERR_OUT_OF_RANGE)
                if any(c not in "0123456789abcdefABCDEF" for c in xstr[2:]):
                    raise _Fail(ERR_OUT_OF_RANGE)
                data = bytes(int(xstr[j:j + 2], 16) for j in range(2, i, 2))
                self.u_str = data
                self.u_hex = len(data)
            else:
                if i > 16:
                    raise _Fail(ERR_OUT_OF_RANGE)
                self.u_hex = 0
                self.u_str = xstr.encode("latin-1")
        self._emit(f"\r\nEnter delay before checking for target response (in ms, 0 - 1000) [{self.u_wait_delay}]: ")
        v = self._get_decimal_pin()
        if v != -1:
            if v < 0 or v > 1000:
                raise _Fail(ERR_OUT_OF_RANGE)
            self.u_wait_delay = v
        self.u_printable = self._yes_no("\r\n\nIgnore non-printable characters? [", self.u_printable)
        if self._dialect >= (1, 11):
            self._get_settings()
        self._wait_for_space(ERR_UART_ABORTED)
        self.events.append("scan_start:uart")
        self._emit(MSG_JTAGULATING)
        probe = self._uart_probe_bytes()
        self.events.append("uart_probe:" + probe.hex())
        num = ctr = 0
        x = (0, 0, 0)

        def cleanup() -> None:
            if num == 0:
                self.u_txd = self.u_rxd = self.u_baud = 0
            else:
                self.u_txd, self.u_rxd, self.u_baud = x

        for txd in range(rng_txd[0], rng_txd[1] + 1):
            for rxd in range(rng_rxd[0], rng_rxd[1] + 1):
                if rxd == txd:
                    continue
                if self._dialect >= (1, 11):
                    self._pins_low_pulse()
                for baud in BAUD_RATES:
                    if self._rx_pending():
                        cleanup()
                        self._emit(ERR_UART_ABORTED)
                        self._rx_flush()
                        self.events.append("scan_aborted:uart")
                        raise _Fail("")
                    self._sleep(0.010 + self.u_wait_delay / 1000.0 + 0.020 + 10.0 * len(probe) / baud)
                    if self.cfg.uart is not None and rxd == self.cfg.uart.rxd and baud == self.cfg.uart.baud:
                        self.events.append(f"uart_probe_received:{txd}")
                    resp = self._uart_response(txd, rxd, baud, probe)
                    if resp:
                        display = True
                        if self.u_printable == 1:
                            if any((b < 0x20 or b > 0x7E) and b not in (13, 10) for b in resp):
                                display = False
                        if display:
                            self.u_txd, self.u_rxd, self.u_baud = txd, rxd, baud
                            self._emit(f"\r\nTXD: {txd}\r\nRXD: {rxd}\r\nBaud: {baud}\r\n")
                            ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in resp)
                            hex_part = "".join(f"{b:02X} " for b in resp)
                            self._emit(f"Data: {ascii_part} [ {hex_part}]\r\n")
                            num += 1
                            self.u_pins_known = 1
                            x = (txd, rxd, baud)
                if self.cfg.perm_delay:
                    self._real_sleep(self.cfg.perm_delay)
                ctr += 1
                self._progress(ctr, 1, True)
        if num == 0:
            self._emit(ERR_NO_DEVICE_FOUND)
            self.u_pins_known = 0
        cleanup()
        self._emit("\r\nUART")
        self._emit(MSG_SCAN_COMPLETE)
        self.events.append("scan_complete:uart")

    def _uart_scan_txd(self) -> None:
        self._uart_note()
        self._get_channels(1)
        self.u_baud_ignore = self._yes_no("\r\n\nIgnore non-standard baud rates? [", self.u_baud_ignore)
        self._wait_for_space(ERR_UART_ABORTED)
        if self._dialect >= (1, 12):
            self._emit("\r\nNote: This scan will continuously monitor all channels for UART\r\nactivity until aborted.")
        self.events.append("scan_start:uart_txd")
        self._emit(MSG_JTAGULATING)
        t = self.cfg.uart
        num = 0
        last = (0, 0)
        jitter = random.Random(1234)
        next_report = time.monotonic() + self.cfg.txd_report_interval
        next_dash = time.monotonic() + 0.2
        while True:
            if self._rx_pending():
                break
            now = time.monotonic()
            if now >= next_dash:
                next_dash = now + 0.2
                self._emit("-")
            if t is not None and t.active and self.ch_start <= t.txd <= self.ch_end and now >= next_report:
                next_report = now + self.cfg.txd_report_interval
                ticks = round(80_000_000 / t.baud) + jitter.randint(-3, 3)
                measured = 80_000_000 // max(1, ticks)
                best = 0
                for lo, hi, val in BEST_FIT:
                    if lo <= measured <= hi:
                        best = val
                        break
                if not (best == 0 and self.u_baud_ignore == 1):
                    self._emit(
                        f"\r\nTXD: {t.txd}\r\nBaud (Measured): {measured}\r\nBaud (Best Fit): "
                        + ("N/A" if best == 0 else str(best)) + "\r\n"
                    )
                    num += 1
                    self.u_pins_known = 1
                    last = (t.txd, best)
            self._real_sleep(0.01)
        if num == 0:
            self.u_pins_known = 0
            self.u_txd = self.u_rxd = self.u_baud = 0
        else:
            self.u_txd, self.u_rxd, self.u_baud = last[0], 0, last[1]
        self._rx_flush()
        self._emit("\r\nUART TXD")
        self._emit(MSG_SCAN_COMPLETE)
        self.events.append("scan_complete:uart_txd")

    # -- 영속 모드 -----------------------------------------------------------------
    def _ocd_mode(self) -> None:
        while True:
            c = self._rx_byte()
            if c == CAN:
                break
            if c == 0x00:
                self._emit("BBIO1")
            elif c == 0x06:
                self._emit("OCD1")
        self._real_sleep(self.cfg.mode_exit_delay)
        self._rx_flush()
        self._persistent = None  # EEPROM 모드를 NORMAL 로 기록
        self._defaults()  # 부팅 경로로 들어왔으므로 Set_Config_Defaults (DAC 출력은 그대로 — 표시만 Undefined)
        self.menu = "jtag"
        self.events.append("persistent_exit:ocd")
        self._emit("\r\nOpenOCD mode complete.")

    def _sump_mode(self) -> None:
        while True:
            c = self._rx_byte()
            if c == CAN:
                break
            if c == 0x02:
                self._emit("1ALS")
        self._real_sleep(self.cfg.mode_exit_delay)
        self._rx_flush()
        self._persistent = None
        self._defaults()
        self.menu = "gpio"
        self.events.append("persistent_exit:sump")
        self._emit("\r\nLogic analyzer mode complete.")


# ---------------------------------------------------------------------------
# 전송 계층
# ---------------------------------------------------------------------------


class SimTCPServer:
    """TCP 서버: 한 번에 클라이언트 하나. pyserial URL ``socket://127.0.0.1:<port>`` 로 접속."""

    def __init__(self, sim: JTAGulatorSim, host: str = "127.0.0.1", port: int = 0, *, reset_on_connect: bool = False,
                 allow_lan: bool = False) -> None:
        # 소켓을 만들기 전에: 루프백이 아니면 allow_lan 없이는 거부 (G13)
        try:
            self.lan_exposed = check_listen_host(host, allow_lan=allow_lan)
        except ValidationFailed as exc:
            raise ValueError(f"{exc.message} ({exc.hint})") from None
        self.sim = sim
        self.reset_on_connect = reset_on_connect
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(1)
        self._sock.settimeout(0.2)
        self.host, self.port = self._sock.getsockname()[:2]
        self.url = f"socket://{self.host}:{self.port}"
        self._stop = threading.Event()
        self._conn: socket.socket | None = None
        self.connections = 0
        self._thread = threading.Thread(target=self._serve, name="jtagulator-sim-tcp", daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.connections += 1
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.settimeout(0.2)
            self._conn = conn
            if self.reset_on_connect:
                self.sim.reset()

            def writer(data: bytes, c: socket.socket = conn) -> None:
                c.sendall(data)

            self.sim.attach(writer)
            try:
                while not self._stop.is_set():
                    try:
                        data = conn.recv(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not data:
                        break
                    self.sim.feed(data)
            finally:
                self.sim.detach()
                try:
                    conn.close()
                except OSError:
                    pass
                self._conn = None

    def drop_client(self) -> None:
        """현재 클라이언트 연결을 끊는다 (USB 분리 시험용)."""
        c = self._conn
        if c is not None:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def close(self) -> None:
        self._stop.set()
        self.drop_client()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2.0)


class SimPTY:
    """PTY: 클라이언트는 ``self.path``(/dev/pts/N)를 시리얼 포트처럼 연다."""

    def __init__(self, sim: JTAGulatorSim) -> None:
        import termios
        import tty

        self.sim = sim
        self._master, self._slave = os.openpty()
        tty.setraw(self._slave, termios.TCSANOW)
        self.path = os.ttyname(self._slave)
        os.set_blocking(self._master, False)
        self._stop = threading.Event()
        sim.attach(self._write)
        self._thread = threading.Thread(target=self._pump, name="jtagulator-sim-pty", daemon=True)
        self._thread.start()

    def _write(self, data: bytes) -> None:
        deadline = time.monotonic() + 2.0
        view = memoryview(data)
        while view and not self._stop.is_set():
            try:
                n = os.write(self._master, view)
                view = view[n:]
            except BlockingIOError:
                if time.monotonic() > deadline:
                    return  # 아무도 읽지 않으면 버림
                time.sleep(0.005)
            except OSError:
                return

    def _pump(self) -> None:
        while not self._stop.is_set():
            try:
                r, _, _ = select.select([self._master], [], [], 0.1)
            except (OSError, ValueError):
                return
            if not r:
                continue
            try:
                data = os.read(self._master, 4096)
            except BlockingIOError:
                continue
            except OSError as exc:
                if exc.errno == errno.EIO:  # 슬레이브를 연 쪽이 없음
                    time.sleep(0.05)
                    continue
                return
            if data:
                self.sim.feed(data)

    def close(self) -> None:
        self._stop.set()
        self.sim.detach()
        self._thread.join(timeout=2.0)
        for fd in (self._master, self._slave):
            try:
                os.close(fd)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_ints(text: str, n_min: int, n_max: int) -> list[int]:
    vals = [int(x, 0) for x in text.split(",") if x.strip()]
    if not n_min <= len(vals) <= n_max:
        raise argparse.ArgumentTypeError(f"값 {n_min}–{n_max}개가 필요합니다: {text!r}")
    return vals


def _serve_until_interrupted() -> None:
    """Ctrl-C(KeyboardInterrupt)까지 기다린다 (시험은 이 함수를 바꿔 끼워 바로 돌아오게 한다)."""
    while True:
        time.sleep(1.0)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m jtagulator_mcp.sim", description="JTAGulator 시뮬레이터 (테스트·데모용)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--tcp", metavar="HOST:PORT",
                   help="TCP 로 서비스 (예: 127.0.0.1:7777, 포트 0 이면 임의). IPv4 루프백 주소만 — 그 밖은 --allow-lan 필요, IPv6 는 쓸 수 없음")
    g.add_argument("--pty", action="store_true", help="PTY 로 서비스 (/dev/pts/N 출력)")
    ap.add_argument("--firmware", default="1.12", help="흉내 낼 펌웨어 (1.12, 1.11.1, 1.10)")
    ap.add_argument("--start", default="wake", choices=("wake", "menu", "ocd", "sump"))
    ap.add_argument("--jtag", metavar="TDI,TDO,TCK,TMS", help="가상 JTAG 핀아웃")
    ap.add_argument("--trst", type=int, default=None)
    ap.add_argument("--idcode", action="append", default=None, help="IDCODE (여러 번 지정하면 체인)")
    ap.add_argument("--uart", metavar="TXD,RXD[,BAUD]", help="가상 UART 타깃")
    ap.add_argument("--uart-response", default="\\r\\nlogin: ", help="UART 응답 (파이썬 이스케이프)")
    ap.add_argument("--time-scale", type=float, default=0.0, help="펌웨어 지연 모델 배율 (1.0 ≈ 실제 하한)")
    ap.add_argument("--reset-on-connect", action="store_true", help="TCP 접속마다 리셋(DTR 모델)")
    ap.add_argument("--allow-lan", action="store_true",
                    help="루프백이 아닌 --tcp 주소(예: 0.0.0.0)를 허용한다. 인증 없는 시리얼이 LAN 에 열린다(브리지 모드 WSL 이면 LAN 전체)")
    args = ap.parse_args(argv)
    tcp_host, tcp_port = "127.0.0.1", 0
    lan_exposed = False
    if not args.pty:
        host, _, port = (args.tcp or "127.0.0.1:0").rpartition(":")
        tcp_host, tcp_port = host or "127.0.0.1", int(port or 0)
        try:  # 시뮬레이터를 띄우기 전에 거부 (종료 코드 2)
            lan_exposed = check_listen_host(tcp_host, allow_lan=args.allow_lan)
        except ValidationFailed as exc:
            ap.error(f"{exc.message} — {exc.hint}")

    cfg = SimConfig(firmware=args.firmware, start_state=args.start, time_scale=args.time_scale)
    if args.jtag:
        tdi, tdo, tck, tms = _parse_ints(args.jtag, 4, 4)
        ids = [int(x, 0) for x in (args.idcode or ["0x4BA00477"])]
        cfg.jtag = SimJTAGTarget(tdi=tdi, tdo=tdo, tck=tck, tms=tms, trst=args.trst, idcodes=ids)
    if args.uart:
        vals = _parse_ints(args.uart, 2, 3)
        resp = args.uart_response.encode("latin-1").decode("unicode_escape").encode("latin-1")
        cfg.uart = SimUARTTarget(txd=vals[0], rxd=vals[1], baud=vals[2] if len(vals) > 2 else 115200, response=resp)
    sim = JTAGulatorSim(cfg).start()
    if args.pty:
        pty = SimPTY(sim)
        print(f"JTAGulator 시뮬레이터 PTY: {pty.path}", flush=True)
        closer: Callable[[], None] = pty.close
    else:
        srv = SimTCPServer(sim, tcp_host, tcp_port, reset_on_connect=args.reset_on_connect, allow_lan=args.allow_lan)
        print(f"JTAGulator 시뮬레이터 URL: {srv.url}", flush=True)
        if lan_exposed:
            print(lan_listen_warning(srv.host, srv.port), file=sys.stderr, flush=True)
        closer = srv.close
    try:
        _serve_until_interrupted()
    except KeyboardInterrupt:
        pass
    finally:
        closer()
        sim.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
