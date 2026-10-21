"""emu-mcp 세션: 케이스 세션 파일(emu/<sid>/), 감독 스레드(띄우기·exec 확인·출력 배수·한도·정지·거두기·마감), 읽기·쓰기.

- 세션 파일은 디렉터리 fd 기준(``pweh.safeio``)으로만 만든다: 디렉터리 0700, 파일 O_EXCL 0600. 플래시·eFuse·HEX 사본은 두지 않는다
  (meta.json 에 sha256·크기만 — 에뮬레이터는 봉인한 memfd 로 받는다, 결정 D6·D7).
- **신호와 거두기는 감독 스레드 하나만 한다.** emu_stop·벽시계·무활동·서버 종료는 이유를 기록하고 자기 파이프로 감독 스레드를 깨운다.
  감독 스레드는 SIGTERM(pidfd + killpg) → STOP_GRACE_S → SIGKILL 을 보내는 동안에도 stdout·stderr 를 계속 비운다.
  끝남은 pidfd 의 POLLIN(없으면 waitid WNOWAIT)으로 알고, 리더가 아직 좀비일 때(그룹 id 가 재사용될 수 없을 때) 그룹에 남은 것을
  killpg(SIGKILL) 한 뒤 파이프를 짧게 비우고 그다음에야 거둔다. ``Popen.poll()``·``wait()`` 는 그 전에 부르지 않는다.
- PDEATHSIG 는 프로세스가 아니라 **만든 스레드**를 따른다 — 그래서 감독 스레드(세션이 끝날 때까지 산다)에서 띄운다. anyio 작업 스레드
  (run_blocking, 유휴 뒤 끝남)에서 띄우면 그 스레드가 끝날 때 에뮬레이터가 죽는다.
- 콘솔 글은 줄 기록기(``pweh.console.LineTranscript`` + ``pweh.safety.redact.ConsoleRedactor``) 하나로 마스킹한다. 레코드가 더 바뀌지
  않게 되면 기록기의 sink 가 그 표시 글을 transcript.masked.txt 에 덧붙이고 진단 힌트를 센다. emu_read 는 같은 기록기를 읽는다
  (넘긴 레코드는 동결된다 — 기다리는 동안의 until 확인은 상태를 바꾸지 않는 ``find_until`` 로 한다).
  로그·오류 메시지·events.jsonl 에는 콘솔 글·stderr 글·입력 데이터를 넣지 않는다.
"""

from __future__ import annotations

import collections
import contextlib
import errno
import hashlib
import json
import logging
import os
import select
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from pweh import procutil, safeio
from pweh.console import LineTranscript
from pweh.errors import PwehError
from pweh.fsutil import utcnow_iso
from pweh.safety.redact import ConsoleRedactor, KnownSecrets, redact_line

from . import backends as B
from . import limits

log = logging.getLogger("pweh.emu")

META_SCHEMA = "pweh.emu-session/v1"
LIVE_STATES = ("starting", "running", "stopping")
FINAL_STATES = ("ended", "failed", "reaped")
FILE_NAMES = {
    "meta": "meta.json",
    "raw": "console.bin",
    "transcript": "transcript.masked.txt",
    "events": "events.jsonl",
    "stderr": "emulator.stderr.log",
}
ARTIFACT_TYPES = {
    "raw": "emu-console-raw",
    "transcript": "emu-transcript",
    "events": "emu-events",
    "meta": "emu-session",
    "stderr": "emu-stderr",
}
_ARTIFACT_DESC = {
    "raw": "에뮬레이터 게스트 UART 원시 바이트(마스킹 안 함 — 터미널에 cat 하지 말 것, less 나 cat -v 로)",
    "transcript": "에뮬레이터 콘솔의 마스킹·이스케이프·반복 접기 기록",
    "events": "에뮬레이터 세션 수명·안전 사건(콘솔 글·입력 데이터 없음)",
    "meta": "에뮬레이터 세션 기록 pweh.emu-session/v1",
    "stderr": "에뮬레이터 자신의 stderr (마스킹 안 함)",
}
#: emu_read 기다림: 출력이 쉬지 않을 때 첫 새 바이트·until 맞음 뒤 이만큼만 더 모은다 / until 확인 주기
_SETTLE_CAP_S = 0.35
_UNTIL_EVERY_S = 0.25
_STDERR_KEEP_LINES = 200
_STDERR_LINE_MAX = 512
_POLL_MS = 100
_DRAIN_AFTER_EXIT_S = 1.0


def _now_iso() -> str:
    return utcnow_iso()


# ---------------------------------------------------------------------------
# 세션 파일 (디렉터리 fd 기준)
# ---------------------------------------------------------------------------


class SessionFiles:
    """emu/<sid>/ 의 파일들. 만든 뒤 fd 를 들고 쓰기만 한다(경로로 다시 열지 않는다). 덧붙이는 파일은 sha256 을 함께 센다."""

    def __init__(self, dir_fd: int, fds: dict[str, int]) -> None:
        self.dir_fd = dir_fd
        self.fds = fds  # raw, transcript, events, stderr
        self.hash = {k: hashlib.sha256() for k in fds}
        self.size = {k: 0 for k in fds}
        self.meta_sha256: str | None = None
        self.meta_size = 0
        self.lock = threading.Lock()
        self.closed = False

    @classmethod
    def create(cls, emu_fd: int, sid: str) -> tuple["SessionFiles", int]:
        """emu/ 디렉터리 fd 안에 <sid>/ 를 **이미 있으면 실패하는** mkdir 로 만들고 tmp/ 와 파일(0600, O_EXCL)을 만든다 → (파일, sid fd)."""
        os.mkdir(sid, 0o700, dir_fd=emu_fd)  # FileExistsError 면 호출자가 다음 번호로
        dfd = os.open(sid, safeio.DIR_FLAGS, dir_fd=emu_fd)
        try:
            os.fchmod(dfd, 0o700)
            os.mkdir("tmp", 0o700, dir_fd=dfd)
            tfd = os.open("tmp", safeio.DIR_FLAGS, dir_fd=dfd)
            try:
                os.fchmod(tfd, 0o700)
            finally:
                os.close(tfd)
            fds: dict[str, int] = {}
            try:
                for key in ("raw", "transcript", "events", "stderr"):
                    fds[key] = safeio.create_excl(dfd, FILE_NAMES[key], 0o600)
                    os.fchmod(fds[key], 0o600)
            except BaseException:
                for fd in fds.values():
                    os.close(fd)
                raise
        except BaseException:
            os.close(dfd)
            raise
        return cls(dfd, fds), dfd

    def append(self, key: str, data: bytes, cap: int | None = None) -> int:
        """덧붙인다(상한까지) → 실제로 쓴 바이트 수."""
        if not data:
            return 0
        with self.lock:
            if self.closed:
                return 0
            if cap is not None:
                room = max(0, cap - self.size[key])
                data = data[:room]
            if not data:
                return 0
            try:
                safeio.write_all(self.fds[key], data)
            except OSError:
                log.warning("세션 파일 쓰기 실패 (%s)", FILE_NAMES[key])
                return 0
            self.hash[key].update(data)
            self.size[key] += len(data)
            return len(data)

    def event(self, ev: dict[str, Any]) -> None:
        line = json.dumps({"ts": _now_iso(), **ev}, ensure_ascii=False, sort_keys=True) + "\n"
        self.append("events", line.encode("utf-8"))

    def write_meta(self, meta: dict[str, Any]) -> None:
        data = (json.dumps(meta, ensure_ascii=False, indent=1, sort_keys=False) + "\n").encode("utf-8")
        with self.lock:
            if self.closed:
                return
            safeio.atomic_write_at(self.dir_fd, FILE_NAMES["meta"], data, mode=0o600)
            self.meta_sha256 = hashlib.sha256(data).hexdigest()
            self.meta_size = len(data)

    def fsync_all(self) -> None:
        with self.lock:
            for fd in self.fds.values():
                with contextlib.suppress(OSError):
                    os.fsync(fd)
            with contextlib.suppress(OSError):
                os.fsync(self.dir_fd)

    def sha256(self, key: str) -> str | None:
        if key == "meta":
            return self.meta_sha256
        return self.hash[key].hexdigest()

    def close(self) -> None:
        with self.lock:
            if self.closed:
                return
            self.closed = True
            for fd in self.fds.values():
                with contextlib.suppress(OSError):
                    os.close(fd)
            with contextlib.suppress(OSError):
                os.close(self.dir_fd)


# ---------------------------------------------------------------------------
# 진단 힌트·stderr (마스킹한 글에서만)
# ---------------------------------------------------------------------------


class HintTracker:
    """마스킹한 콘솔 줄에서 진단 힌트를 만든다 (설계 §6.4 + 계약: USB 콘솔 힌트). 정규식 없이 부분 문자열만 본다."""

    def copy(self) -> "HintTracker":
        h = HintTracker()
        h.__dict__.update(self.__dict__)
        return h

    def __init__(self) -> None:
        self.invalid_header = 0
        self.guru = 0
        self.psram_fail = 0
        self.rst3 = 0
        self.wifi = False
        self.boot_entry_seen = False
        self.lines_after_entry = 0

    def feed(self, text: str) -> None:
        for line in text.split("\n"):
            if not line:
                continue
            weight = 3 if "⟪위 줄 ×" in line else 1
            low = line.lower()
            if "invalid header: 0xffffffff" in low:
                self.invalid_header += weight
            if "guru meditation error" in low:
                self.guru += 1
            if "rst:0x3" in low:
                self.rst3 += weight
            if "psram" in low and ("fail" in low or "not found" in low or "error" in low or "bailing" in low):
                self.psram_fail += 1
            if "wifi:" in low or "wifi_init" in low or "esp_wifi" in low:
                self.wifi = True
            if "loaded app" in low or "entry 0x" in low:
                self.boot_entry_seen = True
                self.lines_after_entry = 0
            elif self.boot_entry_seen and line.strip():
                self.lines_after_entry += 1

    def hints(self, silence_s: float, backend: str) -> list[str]:
        out: list[str] = []
        if backend != B.ESP_BACKEND:
            return out
        if self.invalid_header >= 3:
            out.append("'invalid header: 0xffffffff' 가 반복된다 — 빈 플래시이거나 부트 오프셋이 다르다(전체 덤프인지, 플래시 암호화인지 확인).")
        if self.guru:
            out.append("'Guru Meditation Error' — 펌웨어가 패닉했다. 바로 위 줄의 원인(PSRAM·미구현 주변장치)을 본다.")
        if self.psram_fail:
            out.append(f"PSRAM 초기화 실패로 보인다 — emu_stop 뒤 다른 psram(none·quad·octal)으로 다시 시작한다(PSRAM 재시작은 최대 "
                       f"{limits.PSRAM_RESTARTS_MAX}번).")
        if self.rst3 >= 3:
            out.append("'rst:0x3' 가 반복된다 — 리셋 루프다(on_reset='exit' 이면 첫 리셋에서 끝난다). 리셋 직전 줄이 원인이다.")
        if self.wifi:
            out.append("Wi-Fi 초기화가 보인다 — Wi-Fi·Bluetooth 는 에뮬레이션되지 않는다(그 뒤의 대기·실패는 예상된 한계).")
        if self.boot_entry_seen and self.lines_after_entry <= 5 and silence_s >= limits.HINT_SILENCE_AFTER_BOOT_S:
            out.append("부트로더가 앱으로 넘어간 뒤('Loaded app'/'entry 0x') 조용하다 — 앱 콘솔이 USB-Serial-JTAG·USB-CDC·UART1 에 있을 수 있고 "
                       "그것은 에뮬레이션되지 않는다. PSRAM 문제가 아니다.")
        return out


def _stderr_allowed(backend: str, line: str) -> bool:
    if line.startswith("pweh-emu-shim:"):
        return True
    if backend == B.AVR_BACKEND:
        return line.startswith("pweh_avr_run:")
    low = line.lower()
    return ((line.startswith("qemu-system-") and ":" in line) or "terminating on signal" in low or "drive size error" in low
            or "only 2, 4, 8, and 16mb" in low or "does not support if=mtd" in low or "invalid class name" in low
            or ("efuse" in low and ("error" in low or "not writeable" in low or "not writable" in low)))


def _stderr_category(backend: str, line: str) -> str:
    if backend == B.AVR_BACKEND:
        return "simavr-log"
    if line.startswith("Adding SPI flash device"):
        return "flash-model"
    return "other"


# ---------------------------------------------------------------------------
# 세션
# ---------------------------------------------------------------------------


@dataclass
class SpawnSpec:
    argv: list[str]
    rlimits: dict[str, Any]
    handoff_fds: dict[str, int]  # 봉인한 memfd (감독 스레드가 exec 확인 뒤 닫는다)
    netns: bool  # 처음에 --netns 를 붙일지


class EmuSession:
    def __init__(self, *, sid: str, case_id: str, case_dir: str, session_dir: str, files: SessionFiles, backend: str,
                 target: B.Target, binary: B.BinaryInfo, spawn: SpawnSpec, timeout_s: int, idle_timeout_s: int,
                 known: KnownSecrets | None, meta: dict[str, Any], label: str | None,
                 register_artifact: Callable[[str, str, str, dict[str, Any], str | None], dict[str, Any] | None] | None = None,
                 on_finished: Callable[["EmuSession"], None] | None = None) -> None:
        self.id = sid
        self.case_id = case_id
        self.case_dir = case_dir
        self.dir = session_dir
        self.rel_dir = f"emu/{sid}"
        self.files = files
        self.backend = backend
        self.target = target
        self.binary = binary
        self.spawn = spawn
        self.timeout_s = int(timeout_s)
        self.idle_timeout_s = int(idle_timeout_s)
        self.known = known
        self.meta = meta
        self.label = label
        self._register_artifact = register_artifact
        self._on_finished = on_finished

        self.cond = threading.Condition()
        self.write_lock = threading.Lock()
        self.state = "starting"
        self.stopped_by: str | None = None
        self.exit: dict[str, Any] | None = None
        self.stop_reason: str | None = None
        self.failure: dict[str, Any] | None = None  # {"reason", "stderr_tail", "exit"} — 띄우기 실패
        self.netns_used: bool | None = None
        self.proc: subprocess.Popen[bytes] | None = None
        self.pid: int | None = None
        self.pgid: int | None = None
        self.pidfd: int | None = None
        self.child: dict[str, Any] | None = None
        self.ready = threading.Event()
        self.finished = threading.Event()
        self.thread: threading.Thread | None = None
        self._wake_r, self._wake_w = os.pipe()
        os.set_blocking(self._wake_w, False)

        self.hints = HintTracker()
        self._sunk_end = 0  # sink 가 넘긴 마지막 레코드의 원시 끝 (그 뒤는 아직 바뀔 수 있는 레코드)
        self.transcript_lines = 0
        self.tr = LineTranscript(ConsoleRedactor(known), max_records=limits.TRANSCRIPT_MAX_RECORDS,
                                 max_text_bytes=limits.TRANSCRIPT_MAX_TEXT_BYTES, max_line_bytes=limits.TRANSCRIPT_MAX_LINE_BYTES,
                                 sink=self._sink)
        self.agent_cursor = 0
        self.delivered_raw_end = 0

        self.raw_total = 0
        self.raw_dropped = 0
        self.transcript_dropped = 0
        self.stderr_total = 0
        self.stderr_dropped = 0
        self.writes = 0
        self.bytes_written = 0
        self.last_rx_mono = 0.0
        self.last_byte_nl = True
        self._stderr_buf = b""
        self._stderr_lock = threading.Lock()
        self._stderr_lines: collections.deque[tuple[bytes, bool]] = collections.deque(maxlen=_STDERR_KEEP_LINES)
        self._stderr_other: dict[str, int] = {}
        self._cap_events: set[str] = set()

        self.created_mono = time.monotonic()
        self.started_mono: float | None = None
        self.exec_mono: float | None = None
        self.exit_mono: float | None = None  # 감독 스레드가 프로세스 끝남을 안 시각
        self.start_reported = False  # emu_start 가 '시작됨'으로 돌려줬는가 (그 전에 rc 1·2 로 끝나면 failed)
        self.ended_mono: float | None = None
        self.last_activity = self.created_mono
        self.started_at: str | None = None
        self.ended_at: str | None = None
        self.artifacts: list[dict[str, Any]] = []

    # -- 공개 상태 ------------------------------------------------------
    @property
    def live(self) -> bool:
        return self.state in LIVE_STATES

    def touch(self) -> None:
        with self.cond:
            self.last_activity = time.monotonic()

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, name=f"pweh-emu-{self.id}", daemon=True)
        try:
            self.thread.start()
        except BaseException:
            # 감독 스레드를 만들지 못했다: 띄우지 않고 실패로 마감한다(memfd·파일을 닫고 meta 를 failed 로)
            self.failure = {"reason": "supervisor-start-failed"}
            try:
                self._finalize()
            finally:
                self.ready.set()
                self.finished.set()
                if self._on_finished is not None:
                    with contextlib.suppress(Exception):
                        self._on_finished(self)
            raise

    def wait_ready(self, timeout: float) -> bool:
        return self.ready.wait(timeout)

    def wait_settled(self, timeout: float) -> None:
        """exec 뒤: 프로세스가 끝나거나, 첫 출력 바이트가 오거나, START_SETTLE_S 가 지날 때까지."""
        deadline = time.monotonic() + max(0.0, timeout)
        with self.cond:
            while True:
                if not self.live or self.raw_total > 0 or self.exit_mono is not None or self.failure is not None:
                    return
                base = self.exec_mono or time.monotonic()
                if time.monotonic() - base >= limits.START_SETTLE_S or time.monotonic() >= deadline:
                    return
                self.cond.wait(0.02)

    def report_started(self) -> bool:
        """emu_start 가 '시작됨'으로 돌려주기 직전에 부른다: 아직 끝나지 않았으면 표시하고 True. 이미 끝났으면 False
        (그때 rc 1·2 면 세션은 failed — emu_start 는 마감을 기다려 emu_spawn_failed 를 낸다). 잠금 안에서 끝남과 한 줄로 세운다."""
        with self.cond:
            if self.exit_mono is None and self.failure is None and self.state in LIVE_STATES:
                self.start_reported = True
                return True
            return False

    def request_stop(self, reason: str) -> bool:
        """정지 이유를 먼저 기록하고 감독 스레드를 깨운다 (신호는 감독 스레드가 보낸다). 이미 끝났으면 False."""
        with self.cond:
            if self.state in FINAL_STATES:
                return False
            if self.stop_reason is None:
                self.stop_reason = reason
        self._wake()
        return True

    def stop(self, reason: str, join_timeout: float | None = None) -> bool:
        """정지 요청 + 감독 스레드가 마감할 때까지 기다림 → 끝났는가."""
        self.request_stop(reason)
        return self.finished.wait(limits.SUPERVISOR_JOIN_S if join_timeout is None else join_timeout)

    def _wake(self) -> None:
        with contextlib.suppress(OSError):
            os.write(self._wake_w, b"x")

    # -- 감독 스레드 -----------------------------------------------------
    def _run(self) -> None:
        try:
            self._spawn_and_confirm()
            if self.proc is not None and self.failure is None:
                self._loop()
        except BaseException:  # noqa: BLE001
            log.exception("감독 스레드 오류 (세션 %s)", self.id)  # 콘솔 글은 로그에 넣지 않는다
            if self.failure is None and self.stop_reason is None:
                self.stop_reason = "killed"
        finally:
            try:
                self._finalize()
            except BaseException:  # noqa: BLE001
                log.exception("세션 마감 실패 (%s)", self.id)
            finally:
                self.ready.set()
                self.finished.set()
                with self.cond:
                    self.cond.notify_all()
                if self._on_finished is not None:
                    with contextlib.suppress(Exception):
                        self._on_finished(self)

    def _read_status(self, r: int, timeout: float) -> bytes | None:
        """상태 파이프: b'' = EOF(exec 성공), 바이트 = 실패 내용, None = 시간 초과."""
        buf = b""
        deadline = time.monotonic() + timeout
        p = select.poll()
        p.register(r, select.POLLIN | select.POLLHUP)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return None if not buf else buf
            ev = p.poll(max(1, int(left * 1000)))
            if not ev:
                continue
            try:
                chunk = os.read(r, 512)
            except OSError:
                return buf
            if not chunk:
                return buf
            buf += chunk
            if len(buf) > 4096:
                return buf

    def _spawn_and_confirm(self) -> None:
        netns = self.spawn.netns
        attempts = 2 if netns else 1
        for attempt in range(attempts):
            with self.cond:
                if self.stop_reason is not None:
                    self.failure = {"reason": "stopped-before-start"}
                    return
            r, w = os.pipe()
            cmd = B.shim_argv(self.spawn.argv, ppid=os.getpid(), session_dir=self.dir, status_fd=w, rl=self.spawn.rlimits,
                              netns=netns)
            try:
                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.dir,
                                        env=B.child_env(self.dir), start_new_session=True, close_fds=True,
                                        pass_fds=(*self.spawn.handoff_fds.values(), w))
            except OSError as exc:
                os.close(r)
                os.close(w)
                self.failure = {"reason": "spawn-error", "errno": exc.errno}
                self.files.event({"type": "spawn_failed", "errno": exc.errno})
                return
            os.close(w)
            try:
                status = self._read_status(r, limits.EXEC_CONFIRM_TIMEOUT_S)
            finally:
                os.close(r)
            if status == b"":
                self.proc = proc
                self.netns_used = netns
                if netns:
                    B.note_netns("available")
                self._on_exec(proc)
                return
            # 실패: shim 이 상태를 쓰고 끝났거나(코드:내용), exec 확인 시간이 지났다
            code, _, detail = (status or b"").decode("ascii", "replace").strip().partition(":")
            if status is None:
                self._kill_unreaped(proc, signal.SIGKILL)
            rc = self._reap_quick(proc)
            stderr = self._drain_pipe_once(proc.stderr)
            self._close_proc_pipes(proc)
            if code == "94" and netns and attempt == 0:
                netns = False
                B.note_netns("unavailable")
                self.files.event({"type": "netns_unavailable", "retry": True})
                with self._stderr_lock:
                    self._stderr_lines.clear()
                continue
            self._ingest_stderr_once(stderr)
            self.failure = {"reason": "exec-timeout" if status is None else f"shim-{code or 'unknown'}",
                            "detail": detail[:80] if code in ("94", "95", "96", "97", "98", "127") else None, "exit": B.exit_info(rc)}
            self.exit = B.exit_info(rc)
            self.files.event({"type": "spawn_failed", "reason": self.failure["reason"], "exit": self.exit})
            return

    def _on_exec(self, proc: subprocess.Popen[bytes]) -> None:
        pid = proc.pid
        exe = None
        with contextlib.suppress(OSError):
            exe = os.readlink(f"/proc/{pid}/exe")
            if exe.endswith(" (deleted)"):
                exe = exe[: -len(" (deleted)")]
        st = procutil.proc_stat(pid)
        try:
            pgid = os.getpgid(pid)
        except OSError:
            pgid = None
        self.pid, self.pgid = pid, pgid
        self.pidfd = procutil.open_pidfd(pid)
        self.child = {"pid": pid, "start_ticks": st[1] if st else None, "pgid": pgid, "exe_realpath": exe}
        for fd in (proc.stdout, proc.stderr, proc.stdin):
            if fd is not None:
                os.set_blocking(fd.fileno(), False)
        for fd in list(self.spawn.handoff_fds.values()):
            with contextlib.suppress(OSError):
                os.close(fd)
        self.spawn.handoff_fds.clear()
        now = time.monotonic()
        with self.cond:
            self.exec_mono = self.started_mono = now
            self.last_activity = now
            self.started_at = _now_iso()
            if self.state == "starting":
                self.state = "running"
            self.cond.notify_all()
        self.meta.update({"state": "running", "started_at": self.started_at, "child": self.child})
        self.meta.setdefault("isolation", {})["netns"] = bool(self.netns_used)
        self._write_meta()
        self.files.event({"type": "ready", "pid": pid, "netns": bool(self.netns_used)})
        self.ready.set()

    def _write_meta(self) -> None:
        self.meta["counters"] = {"raw_bytes": self.raw_total, "raw_dropped_bytes": self.raw_dropped,
                                 "transcript_lines": self.transcript_lines,
                                 "transcript_dropped_bytes": self.transcript_dropped, "stderr_bytes": self.stderr_total,
                                 "stderr_dropped_bytes": self.stderr_dropped, "writes": self.writes, "bytes_written": self.bytes_written}
        try:
            self.files.write_meta(self.meta)
        except OSError:
            log.warning("meta.json 쓰기 실패 (%s)", self.id)

    def _signal_group(self, sig: int) -> None:
        """리더(pidfd)와 그룹(killpg)에 신호 — 리더를 거두기 전에만 부른다(그룹 id 가 재사용될 수 없다)."""
        if self.pidfd is not None:
            with contextlib.suppress(OSError):
                procutil.pidfd_signal(self.pidfd, sig)
        elif self.pid is not None:
            with contextlib.suppress(OSError):
                os.kill(self.pid, sig)
        if self.pgid is not None and self.pgid == self.pid:
            with contextlib.suppress(OSError):
                os.killpg(self.pgid, sig)

    @staticmethod
    def _kill_unreaped(proc: subprocess.Popen[bytes], sig: int) -> None:
        with contextlib.suppress(OSError):
            os.killpg(proc.pid, sig)  # start_new_session: pgid == pid, 아직 거두지 않았다
        with contextlib.suppress(OSError):
            proc.send_signal(sig)

    @staticmethod
    def _reap_quick(proc: subprocess.Popen[bytes]) -> int | None:
        try:
            return proc.wait(timeout=limits.EXEC_CONFIRM_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            EmuSession._kill_unreaped(proc, signal.SIGKILL)
            try:
                return proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                return None

    @staticmethod
    def _drain_pipe_once(f: Any) -> bytes:
        if f is None:
            return b""
        out = b""
        try:
            os.set_blocking(f.fileno(), False)
            while len(out) < (64 << 10):
                chunk = os.read(f.fileno(), 65536)
                if not chunk:
                    break
                out += chunk
        except (BlockingIOError, OSError):
            pass
        return out

    @staticmethod
    def _close_proc_pipes(proc: subprocess.Popen[bytes]) -> None:
        for f in (proc.stdin, proc.stdout, proc.stderr):
            if f is not None:
                with contextlib.suppress(Exception):
                    f.close()

    def _exited_now(self) -> bool:
        if self.pid is None:
            return True
        try:
            info = os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            return True
        return info is not None

    def _loop(self) -> None:
        proc = self.proc
        assert proc is not None and proc.stdout is not None and proc.stderr is not None
        out_fd, err_fd = proc.stdout.fileno(), proc.stderr.fileno()
        poller = select.poll()
        poller.register(out_fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        poller.register(err_fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        poller.register(self._wake_r, select.POLLIN)
        if self.pidfd is not None:
            poller.register(self.pidfd, select.POLLIN)
        open_fds = {out_fd, err_fd}
        term_at: float | None = None
        killed = False
        exited = False
        while not exited:
            now = time.monotonic()
            with self.cond:
                if self.stop_reason is None and self.state == "running":
                    if self.started_mono is not None and now - self.started_mono >= self.timeout_s:
                        self.stop_reason = "wall-timeout"
                        self.files.event({"type": "timeout", "kind": "wall", "timeout_s": self.timeout_s})
                    elif now - self.last_activity >= self.idle_timeout_s:
                        self.stop_reason = "idle-timeout"
                        self.files.event({"type": "timeout", "kind": "idle", "idle_timeout_s": self.idle_timeout_s})
                reason = self.stop_reason
            if reason is not None and term_at is None:
                term_at = now
                with self.cond:
                    self.state = "stopping"
                    self.cond.notify_all()
                self.files.event({"type": "stop_request", "reason": reason})
                self.meta.update({"state": "stopping", "stop_reason": reason})
                self._write_meta()
                self._signal_group(signal.SIGTERM)
            elif term_at is not None and not killed and now - term_at >= limits.STOP_GRACE_S:
                killed = True
                self.files.event({"type": "kill", "after_s": round(now - term_at, 2)})
                self._signal_group(signal.SIGKILL)
            for fd, _ev in poller.poll(_POLL_MS):
                if fd == self._wake_r:
                    with contextlib.suppress(OSError):
                        os.read(self._wake_r, 4096)
                elif fd == self.pidfd:
                    exited = True
                    self._mark_exit()
                elif fd in open_fds:
                    if not self._drain(fd, out_fd):
                        open_fds.discard(fd)
                        with contextlib.suppress(KeyError, ValueError):
                            poller.unregister(fd)
            if self.pidfd is None and self._exited_now():
                exited = True
                self._mark_exit()
        # 리더는 좀비(아직 거두지 않음): 그룹에 남은 것을 끝내고 파이프를 짧게 비운 뒤 거둔다
        if self.pgid is not None and self.pgid == self.pid:
            with contextlib.suppress(OSError):
                os.killpg(self.pgid, signal.SIGKILL)
        for fd in (self.pidfd, self._wake_r):  # 끝난 뒤에는 늘 읽을 수 있어 poll 이 헛돈다
            if fd is not None:
                with contextlib.suppress(KeyError, ValueError):
                    poller.unregister(fd)
        deadline = time.monotonic() + _DRAIN_AFTER_EXIT_S
        while open_fds and time.monotonic() < deadline:
            for fd, _ev in poller.poll(50):
                if fd in open_fds and not self._drain(fd, out_fd):
                    open_fds.discard(fd)
                    with contextlib.suppress(KeyError, ValueError):
                        poller.unregister(fd)

    def _mark_exit(self) -> None:
        with self.cond:
            if self.exit_mono is None:
                self.exit_mono = time.monotonic()
            self.cond.notify_all()

    def _drain(self, fd: int, out_fd: int) -> bool:
        """fd 에서 읽을 수 있는 만큼 읽는다 → 아직 열려 있는가(False = EOF)."""
        for _ in range(64):
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                return True
            except OSError as exc:
                if exc.errno in (errno.EAGAIN, errno.EINTR):
                    return True
                return False
            if not chunk:
                return False
            if fd == out_fd:
                self._on_stdout(chunk)
            else:
                self._on_stderr(chunk)
        return True

    def _cap_event(self, what: str) -> None:
        if what not in self._cap_events:
            self._cap_events.add(what)
            self.files.event({"type": "cap", "what": what})

    def _on_stdout(self, data: bytes) -> None:
        now = time.monotonic()
        written = self.files.append("raw", data, cap=limits.RAW_LOG_CAP)
        with self.cond:
            self.raw_total += len(data)
            if written < len(data):
                self.raw_dropped += len(data) - written
            self.last_rx_mono = now
            self.last_byte_nl = data.endswith(b"\n")
            self.tr.feed(data, now)
            self.cond.notify_all()
        if written < len(data):
            self._cap_event("raw")

    def _on_stderr(self, data: bytes) -> None:
        written = self.files.append("stderr", data, cap=limits.STDERR_LOG_CAP)
        self.stderr_total += len(data)
        if written < len(data):
            self.stderr_dropped += len(data) - written
            self._cap_event("stderr")
        buf = self._stderr_buf + data
        lines = buf.split(b"\n")
        # 긴 열린 줄의 뒤쪽만 남기면 앞의 자격증명 키·비밀 접두부를 잃는다. 첫 부분과 잘림 표식 1바이트만 보존한다.
        self._stderr_buf = lines.pop()[:_STDERR_LINE_MAX + 1]
        for ln in lines:
            self._stderr_line(ln.rstrip(b"\r"))

    def _ingest_stderr_once(self, data: bytes) -> None:
        for ln in data.split(b"\n"):
            if ln.strip():
                self._stderr_line(ln.rstrip(b"\r"))

    def _stderr_line(self, ln: bytes) -> None:
        truncated = len(ln) > _STDERR_LINE_MAX
        ln = ln[:_STDERR_LINE_MAX]
        text = ln.decode("utf-8", "replace")
        if _stderr_allowed(self.backend, text):
            with self._stderr_lock:
                self._stderr_lines.append((ln, truncated))
            if "invalid class name" in text.lower() and self.state == "running":
                self.request_stop("config-error")
        elif text.strip():
            cat = _stderr_category(self.backend, text)
            with self._stderr_lock:
                self._stderr_other[cat] = self._stderr_other.get(cat, 0) + 1

    def _sink(self, text: str, raw_start: int, raw_end: int, t_first: float, t_last: float) -> None:
        """줄 기록기가 더 바뀌지 않는 레코드를 넘길 때(기록기 잠금 안): transcript.masked.txt 에 덧붙이고 힌트를 센다(마스킹한 글만)."""
        self.hints.feed(text)
        self._sunk_end = max(self._sunk_end, raw_end)
        self.transcript_lines += 1
        data = (text + "\n").encode("utf-8", "backslashreplace")
        w = self.files.append("transcript", data, cap=limits.TRANSCRIPT_CAP)
        if w < len(data):
            self.transcript_dropped += len(data) - w
            self._cap_event("transcript")

    # -- 마감 --------------------------------------------------------------
    def _finalize(self) -> None:
        proc = self.proc
        rc: int | None = None
        if proc is not None:
            if proc.returncode is None:
                if not self._exited_now():
                    self._signal_group(signal.SIGKILL)
                try:
                    rc = proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    log.warning("세션 %s: 에뮬레이터를 거두지 못했다 (pid %s)", self.id, proc.pid)
                    rc = None
            else:
                rc = proc.returncode
            with self.write_lock:
                self._close_proc_pipes(proc)
        for fd in list(self.spawn.handoff_fds.values()):
            with contextlib.suppress(OSError):
                os.close(fd)
        self.spawn.handoff_fds.clear()
        if self.pidfd is not None:
            with contextlib.suppress(OSError):
                os.close(self.pidfd)
            self.pidfd = None
        now = time.monotonic()
        with self.cond:
            if self.stderr_total and self._stderr_buf.strip():
                self._stderr_line(self._stderr_buf.rstrip(b"\r"))
                self._stderr_buf = b""
            self.tr.close(now)
        failed_early = self.failure is not None
        if failed_early and (self.failure or {}).get("reason") == "stopped-before-start" and self.stop_reason:
            stopped_by = self.stop_reason  # exec 전에 정지 요청(emu_stop·서버 종료) — 띄우지 않았다
            state = "ended"
        elif failed_early:
            stopped_by = "spawn-failed"
            state = "failed"
        else:
            stopped_by = B.classify_exit(self.backend, rc, self.stop_reason, on_reset=self.target.on_reset)
            with self.cond:
                quick = not self.start_reported and rc in (1, 2) and self.stop_reason is None
            state = "failed" if quick else "ended"
        with self.cond:
            self.state = state
            self.stopped_by = stopped_by
            if not failed_early:
                self.exit = B.exit_info(rc)
            self.ended_mono = now
            self.ended_at = _now_iso()
            self.cond.notify_all()
        self.files.event({"type": "exit", "stopped_by": stopped_by, "exit": self.exit,
                          "duration_s": round(now - (self.started_mono or self.created_mono), 3)})
        self.files.fsync_all()
        self.meta.update({"state": state, "stopped_by": stopped_by, "ended_at": self.ended_at, "exit": self.exit})
        if self.failure is not None:
            self.meta["failure"] = {k: v for k, v in self.failure.items() if k != "stderr_tail"}
        self._write_meta()
        self.files.fsync_all()
        self._register_all()
        self.files.close()
        for fd in (self._wake_r, self._wake_w):
            with contextlib.suppress(OSError):
                os.close(fd)

    def _register_all(self) -> None:
        if self._register_artifact is None:
            return
        extra = {"session_id": self.id, "backend": self.backend, "target": self.target.public()}
        for key in ("raw", "transcript", "events", "meta", "stderr"):
            try:
                art = self._register_artifact(f"{self.rel_dir}/{FILE_NAMES[key]}", ARTIFACT_TYPES[key], _ARTIFACT_DESC[key],
                                              {"type": ARTIFACT_TYPES[key], **extra}, self.files.sha256(key))
            except Exception:  # noqa: BLE001 - 등록 실패가 정리를 막지 않게
                log.warning("아티팩트 등록 실패 (%s %s)", self.id, FILE_NAMES[key])
                art = None
            self.artifacts.append({"path": f"{self.rel_dir}/{FILE_NAMES[key]}", "kind": "other", "type": ARTIFACT_TYPES[key],
                                   "id": (art or {}).get("id")})

    # -- 읽기·쓰기 ----------------------------------------------------------
    def stderr_tail(self) -> tuple[str, dict[str, int]]:
        """허용한 진단 줄만(마스킹·이스케이프, 줄 경계로 자름, ≤ STDERR_TAIL_CHARS) + 나머지 줄의 분류별 수."""
        with self._stderr_lock:
            lines = list(self._stderr_lines)
            other = dict(self._stderr_other)
        rendered: list[str] = []
        total = 0
        for ln, truncated in reversed(lines):
            # 상한이 비밀값 중간을 자를 수 있다. 잘린 끝은 열린 줄로 마스킹해 알려진 비밀의 접두부도 보류한다.
            masked = redact_line(ln.decode("utf-8", "surrogateescape"), self.known, open_tail=truncated)[0]
            if total + len(masked) + 1 > limits.STDERR_TAIL_CHARS:
                break
            rendered.append(masked)
            total += len(masked) + 1
        return "\n".join(reversed(rendered)), other

    def _settle_s(self) -> float:
        if self.last_byte_nl:
            return limits.READ_SETTLE_S
        return max(limits.READ_SETTLE_S, limits.OPEN_QUIET_S) + 0.02

    def read(self, since: int | None, max_chars: int, wait_s: float, until: list[str] | None, ignore_case: bool, tail: bool,
             cancel: Callable[[], bool] | None = None) -> dict[str, Any]:
        """emu_read 의 본체.

        기다림(wait_s > 0): max(since, delivered_raw_end) 뒤의 새 바이트(until 이 없을 때) 또는 until 맞음을 기다린 뒤 조금 더 모은다 —
        READ_SETTLE_S(열린 줄이면 OPEN_QUIET_S) 만큼 조용해지거나, 첫 새 바이트·맞음 뒤 ``_SETTLE_CAP_S`` 가 지나거나(출력이 쉬지 않을 때),
        새 바이트가 max_chars 만큼 쌓이면 돌아온다. until 은 상태를 바꾸지 않는 ``find_until`` 로 ``_UNTIL_EVERY_S`` 마다 본다
        (이미 맞으면 바로 돌아온다). 마지막에 한 번만 read() 한다(넘긴 레코드가 동결된다)."""
        tr = self.tr
        with self.cond:
            self.last_activity = time.monotonic()
            if tail:
                r = tr.tail(max_chars, now=time.monotonic(), open_quiet_s=limits.OPEN_QUIET_S)
            else:
                start = self.agent_cursor if since is None else max(0, int(since))
                kw: dict[str, Any] = {"until": until, "until_ignore_case": ignore_case} if until else {}
                if wait_s > 0:
                    self._wait_for_read(start, max_chars, wait_s, until, ignore_case, cancel)
                r = tr.read(start, max_chars, open_quiet_s=limits.OPEN_QUIET_S, now=time.monotonic(), **kw)
            self.agent_cursor = int(r.get("cursor_end") or 0)
            pend = r.get("pending_raw_end")
            self.delivered_raw_end = max(self.agent_cursor, int(pend) if pend is not None else 0)
            self.last_activity = time.monotonic()
            out = {k: v for k, v in r.items() if k != "pending_raw_end"}
            out.update(self._status_fields())
        return out

    def _wait_for_read(self, start: int, max_chars: int, wait_s: float, until: list[str] | None, ignore_case: bool,
                       cancel: Callable[[], bool] | None) -> None:
        """read 의 기다림 (self.cond 를 쥔 채 부른다 — cond.wait 동안 감독 스레드가 바이트를 넣는다)."""
        tr = self.tr

        def hit(now: float) -> bool:
            return tr.find_until(until, since=start, until_ignore_case=ignore_case, open_quiet_s=limits.OPEN_QUIET_S,
                                 now=now) is not None

        now = time.monotonic()
        if until and hit(now):
            return  # 이미 맞는 글이 있다
        deadline = now + wait_s
        target = max(start, self.delivered_raw_end)
        anchor: float | None = None  # 첫 새 바이트(until 없음) 또는 맞음(until)을 본 시각
        last_check = now
        while True:
            if self.state not in LIVE_STATES or (cancel is not None and cancel()):
                return
            now = time.monotonic()
            total = int(tr.raw_total)
            if anchor is None:
                if until:
                    if now - last_check >= _UNTIL_EVERY_S:
                        last_check = now
                        if hit(now):
                            anchor = now
                elif total > target:
                    anchor = now
            if anchor is not None:
                quiet = now - self.last_rx_mono
                if quiet >= self._settle_s() or now - anchor >= _SETTLE_CAP_S or total - target >= max_chars:
                    return
            if now >= deadline:
                return
            self.cond.wait(min(0.05, max(0.001, deadline - now)))

    def _status_fields(self) -> dict[str, Any]:
        """state·raw_total·raw_dropped·(끝났으면) stopped_by·exit·hints. 잠금 안에서 부른다."""
        now = time.monotonic()
        silence = now - self.last_rx_mono if self.last_rx_mono else now - (self.started_mono or now)
        out: dict[str, Any] = {"state": self.state, "raw_total": self.raw_total, "raw_dropped": self.raw_dropped}
        if self.state in FINAL_STATES:
            out["stopped_by"] = self.stopped_by
            out["exit"] = self.exit
        # sink 가 아직 넘기지 않은(바뀔 수 있는) 레코드도 힌트에 넣는다 — 동결하지 않는 peek 로 본다
        ht = self.hints.copy()
        try:
            pk = self.tr.read(self._sunk_end, 8192, open_quiet_s=limits.OPEN_QUIET_S, now=now, peek=True)
            ht.feed(pk.get("text") or "")
        except Exception:  # noqa: BLE001 - 힌트는 보조 정보다
            pass
        out["hints"] = ht.hints(silence if self.live else 0.0, self.backend)
        return out

    def write(self, payload: bytes) -> dict[str, Any]:
        """비차단 쓰기 + poll(POLLOUT), 합계 WRITE_TIMEOUT_S. 일부만 쓸 수 있다(감독 스레드를 막지 않는다)."""
        with self.write_lock:
            with self.cond:
                if self.state != "running" or self.proc is None or self.proc.stdin is None or self.proc.stdin.closed:
                    raise PwehError(f"세션 {self.id} 은 실행 중이 아닙니다 (state={self.state}).", code="emu_not_running",
                                    hint="필요하면 emu_start 로 새 세션을 시작한다.")
                fd = self.proc.stdin.fileno()
                cursor = self.raw_total
                self.last_activity = time.monotonic()
            written = 0
            deadline = time.monotonic() + limits.WRITE_TIMEOUT_S
            broken = False
            while written < len(payload):
                try:
                    written += os.write(fd, payload[written:])
                    continue
                except BlockingIOError:
                    pass
                except OSError as exc:
                    if exc.errno == errno.EINTR:
                        continue
                    broken = True
                    break
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                p = select.poll()
                p.register(fd, select.POLLOUT | select.POLLERR)
                p.poll(max(1, int(min(left, 0.1) * 1000)))
            printable = all(0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) for b in payload)
            with self.cond:
                self.writes += 1
                self.bytes_written += written
                self.last_activity = time.monotonic()
                state = self.state
            self.files.event({"type": "tx", "session_id": self.id, "bytes": written, "requested": len(payload), "printable": printable,
                              "data": "<given>"})
        out: dict[str, Any] = {"bytes_written": written, "bytes_requested": len(payload), "partial": written < len(payload),
                               "cursor": cursor, "state": state}
        if written < len(payload):
            out["note"] = ("게스트가 입력을 읽지 않아(파이프·UART 수신 FIFO 가 참) 일부만 썼다 — emu_read 로 상태를 보고 나머지를 다시 보낸다."
                           if not broken else "에뮬레이터 입력이 닫혔다(끝나는 중일 수 있다).")
        return out

    def summary(self) -> dict[str, Any]:
        """emu_stop·emu_sessions 용 요약 (콘솔 글 없음 — stderr_tail 은 마스킹한 허용 줄만)."""
        with self.cond:
            now = self.ended_mono or time.monotonic()
            dur = now - (self.started_mono or self.created_mono)
            out: dict[str, Any] = {
                "session_id": self.id, "case_id": self.case_id, "backend": self.backend, "target": self.target.public(),
                "state": self.state, "stopped_by": self.stopped_by, "exit": self.exit, "duration_s": round(dur, 3),
                "raw_bytes": self.raw_total, "raw_dropped_bytes": self.raw_dropped,
                "transcript_lines": self.transcript_lines,
                "writes": self.writes, "bytes_written": self.bytes_written, "dir": self.rel_dir,
                "meta_path": f"{self.rel_dir}/{FILE_NAMES['meta']}",
            }
        tail, other = self.stderr_tail()
        out["stderr_tail"] = tail
        out["stderr_suppressed"] = other
        if self.artifacts:
            out["artifacts"] = list(self.artifacts)
        return out

    def listing(self) -> dict[str, Any]:
        with self.cond:
            now = time.monotonic()
            started = self.started_mono
            row: dict[str, Any] = {
                "session_id": self.id, "case_id": self.case_id, "backend": self.backend, "target": self.target.public(),
                "state": self.state, "stopped_by": self.stopped_by, "started_at": self.started_at,
                "uptime_s": round(((self.ended_mono or now) - started), 1) if started else 0.0,
                "raw_bytes": self.raw_total, "cursor_end": self.agent_cursor,
                "firmware": {k: (self.meta.get("firmware") or {}).get(k) for k in ("path", "sha256")}, "dir": self.rel_dir,
            }
            if self.live and started:
                row["timeout_in_s"] = round(max(0.0, self.timeout_s - (now - started)), 1)
                row["idle_timeout_in_s"] = round(max(0.0, self.idle_timeout_s - (now - self.last_activity)), 1)
        return row


__all__ = ["ARTIFACT_TYPES", "EmuSession", "FILE_NAMES", "FINAL_STATES", "HintTracker", "LIVE_STATES", "META_SCHEMA",
           "SessionFiles", "SpawnSpec"]
