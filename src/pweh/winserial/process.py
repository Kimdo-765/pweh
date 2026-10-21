"""고정 helper 실행·프레임 dispatch·정리 증명. import 시 환경/Windows를 보지 않는다."""
from __future__ import annotations

import os
import re
import secrets
import selectors
import signal
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .. import procutil
from ..errors import DeviceError, ValidationFailed
from . import pin, protocol as P
from .binary import HelperBinary, Snapshot, snapshot

_RUNS: dict[str, "HelperRun"] = {}
_RUNS_LOCK = threading.Lock()


class HelperError(DeviceError):
    code = "serial_helper_error"


class HelperCleanupError(HelperError):
    """run은 내부 재시도용이며 JSON data에는 live 객체/token을 넣지 않는다."""
    code = "serial_helper_cleanup_unverified"

    def __init__(self, run: "HelperRun"):
        self.run = run
        super().__init__("직렬 helper의 실제 종료를 확인하지 못했습니다.",
                         data={"cleanup_verified": False, "state": "cleanup-pending"})


@dataclass
class Pending:
    kind: str
    event: threading.Event = field(default_factory=threading.Event)
    result: dict | None = None
    error: BaseException | None = None


def _environment() -> dict:
    from ..hostenv import detect
    return detect(smoke=False)


def check_environment(provider=None) -> dict:
    """주입은 Python 시험 seam뿐이다. 사용자 설정으로 Windows 실행을 넓히지 않는다."""
    env = (provider or _environment)()
    if not isinstance(env, dict):
        raise ValidationFailed("helper 환경 보고서 형식 오류")
    wsl = env.get("wsl") or {}
    disabled = set(env.get("overridden") or [])
    denied = {"hostenv.disable.interop", "hostenv.disable.serial_helper", "hostenv.disable.windows_tools"}
    if (env.get("kind") not in ("WSL1", "WSL2_INTEROP", "WSL_UNKNOWN")
            or not (wsl.get("interop") or {}).get("usable") or disabled & denied
            or ((env.get("windows") or {}).get("serial_helper") or {}).get("disabled")):
        raise DeviceError("WSL interop 직렬 helper 경로가 꺼져 있거나 사용할 수 없습니다.", code="serial_helper_unavailable")
    return env


class HelperRun:
    """한 실행 세대의 강한 소유자. stdout EOF나 POSIX leader 종료만으로 닫힘을 확정하지 않는다."""
    def __init__(self, helper: HelperBinary, *, port: str | None = None, mode: str = "normal",
                 environment_provider=None, process_factory=None, windows_lifecycle=None,
                 runtime_root: Path | None = None, on_data: Callable | None = None,
                 on_error: Callable | None = None, on_response: Callable | None = None):
        if mode not in ("normal", "version", "echo"):
            raise ValidationFailed("helper 실행 모드 오류")
        if mode == "normal" and (not isinstance(port, str) or not re.fullmatch(r"COM[1-9][0-9]{0,3}", port) or int(port[3:]) > 4096):
            raise ValidationFailed("helper COM 인자 오류")
        if mode != "normal" and port is not None:
            raise ValidationFailed("no-COM 실행에 port를 넘길 수 없습니다.")
        self.helper, self.port, self.mode = helper, port, mode
        self.environment_provider = environment_provider
        self.process_factory = process_factory or subprocess.Popen
        if windows_lifecycle is None:
            from .windows import WindowsLifecycle
            windows_lifecycle = WindowsLifecycle()
        self.windows_lifecycle = windows_lifecycle
        if runtime_root is None:
            from ..portlock import get_manager
            runtime_root = get_manager().runtime_root
        self.runtime_root = Path(runtime_root)
        self.on_data, self.on_error, self.on_response = on_data, on_error, on_response
        self.token = secrets.token_hex(16)
        self.copy: Snapshot | None = None
        self.proc = None
        self.ticks = None
        self.thread = None
        self._attempted = False
        self._spawn_lock = threading.RLock()
        self._close_lock = threading.Lock()
        self._lock = threading.RLock()
        self.command_lock = threading.RLock()
        self._write_lock = threading.Lock()
        self._hello_event = threading.Event()
        self._stop = threading.Event()
        self._stdout_eof = threading.Event()
        self._hello: dict | None = None
        self._error: BaseException | None = None
        self._pending: dict[int, Pending] = {}
        self._next_id = 1
        self._opened = False
        self._closing = False
        self._quit_ack = False
        self.normal_completion = False
        self.cleanup_verified = True  # 아직 실행 자원이 없음
        self.stderr = bytearray()

    def _fail(self, exc: BaseException) -> None:
        with self._lock:
            if self._error is None:
                self._error = exc
            for pending in self._pending.values():
                if not pending.event.is_set():
                    pending.error = exc; pending.event.set()
            self._hello_event.set()
        if self.on_error:
            self.on_error(exc)

    def start(self, *, deadline: float) -> dict:
        """source 재검증→사본→환경/점유 확인→Popen→H. 예외도 같은 실행 소유자가 정리한다."""
        with self._spawn_lock:
            if self._attempted or self._closing:
                raise HelperError("helper는 한 번만 시작할 수 있습니다.")
            check_environment(self.environment_provider)
            self.copy = snapshot(self.helper, runtime_root=self.runtime_root)
            try:
                if self.port:
                    self.windows_lifecycle.check_port(self.port, deadline)
                check_environment(self.environment_provider)
                if time.monotonic() >= deadline:
                    raise TimeoutError("helper 시작 예산 초과")
                argv = [str(self.copy.path)]
                argv += ["--port", self.port] if self.mode == "normal" else ["--" + self.mode]
                argv += ["--token", self.token]
                with _RUNS_LOCK:
                    _RUNS[self.token] = self
                self.cleanup_verified = False
                self._attempted = True
                self.proc = self.process_factory(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                 start_new_session=True, close_fds=True, bufsize=0)
                st = procutil.proc_stat(self.proc.pid)
                self.ticks = st[1] if st else None
                for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
                    os.set_blocking(stream.fileno(), False)
                self.thread = threading.Thread(target=self._reader, name="pweh-serial-helper-rx", daemon=True)
                self.thread.start()
            except BaseException:
                if not self._attempted:
                    self.copy.remove(); self.copy = None
                else:
                    self.close(deadline=max(time.monotonic(), deadline), send_quit=False)
                raise
        if not self._hello_event.wait(max(0, deadline - time.monotonic())):
            self._fail(TimeoutError("helper HELLO 시간 초과"))
        with self._lock:
            if self._error:
                raise self._error
            if self._hello is None:
                raise HelperError("helper HELLO가 없습니다.")
            return dict(self._hello)

    def _reader(self) -> None:
        decoder = P.Decoder("helper")
        partial_since = None
        try:
            with selectors.DefaultSelector() as sel:
                sel.register(self.proc.stdout, selectors.EVENT_READ, "out")
                sel.register(self.proc.stderr, selectors.EVENT_READ, "err")
                while sel.get_map() and not self._stop.is_set():
                    if partial_since is not None and time.monotonic() - partial_since >= 5:
                        raise P.ProtocolError("helper 반 프레임 시간 초과")
                    for key, _ in sel.select(.05):
                        try:
                            chunk = os.read(key.fd, 65536)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            sel.unregister(key.fileobj)
                            if key.data == "out":
                                decoder.eof(); self._stdout_eof.set()
                                with self._lock:
                                    waiting = any(not p.event.is_set() for p in self._pending.values())
                                if not self._hello or waiting or (self.mode != "version" and not self._quit_ack):
                                    self._fail(HelperError("helper stdout 연결이 끊어졌습니다."))
                            continue
                        if key.data == "err":
                            if len(self.stderr) + len(chunk) > 8192:
                                raise HelperError("helper stderr 상한 초과")
                            self.stderr.extend(c if 32 <= c < 127 or c in (10, 13) else 63 for c in chunk)
                        else:
                            frames = decoder.feed(chunk)
                            for frame in frames:
                                self._dispatch(frame)
                            if not decoder.buffer:
                                partial_since = None
                            elif frames or partial_since is None:
                                partial_since = time.monotonic()
        except BaseException as exc:
            self._fail(exc)
        finally:
            if self._error is not None and not self._closing:
                def cleanup():
                    try: self.close()
                    except Exception: pass  # strong registry가 미확인 실행을 유지한다.
                try:
                    threading.Thread(target=cleanup, name="pweh-serial-helper-cleanup", daemon=True).start()
                except Exception:
                    pass

    def _dispatch(self, frame: P.Frame) -> None:
        value = P.validate(frame, "helper")
        with self._lock:
            if self._hello is None:
                if frame.type != "H":
                    raise P.ProtocolError("H 이전 프레임")
                if (value["protocol"] != pin.PROTOCOL_VERSION or value["version"] != self.helper.version
                        or value["source_commit"] != self.helper.source_commit
                        or value["mode"] != {"normal": 0, "echo": 1, "version": 2}[self.mode]):
                    raise P.ProtocolError("helper HELLO 핀/프로토콜 불일치")
                self._hello = value; self._hello_event.set(); return
            if frame.type == "H" or self.mode == "version":
                raise P.ProtocolError("중복 H/no-COM 추가 프레임")
            if frame.type == "D":
                if not self._opened:
                    raise P.ProtocolError("OPEN 성공 전 DATA")
                if self.on_data:
                    self.on_data(value["epoch"], value["data"])
                return
            if frame.type == "E" and value["id"] == 0:
                raise HelperError("helper 자발 오류", data={"status": value["status"], "winerr": value["winerr"]})
            pending = self._pending.get(value["id"])
            if pending is None or pending.event.is_set():
                raise P.ProtocolError("알 수 없거나 완료한 request id")
            wanted = "o" if pending.kind == "O" else "s" if pending.kind == "S" else "A"
            if frame.type not in (wanted, "E") or (frame.type in ("A", "E") and value["request_type"] != pending.kind):
                raise P.ProtocolError("요청/응답 type 불일치")
            if frame.type == "E" and pending.kind in ("O", "S"):
                raise P.ProtocolError("O/S는 고유 실패 응답이 필요합니다.")
            if pending.kind == "O" and value["status"] == 0:
                self._opened = True
            if pending.kind == "Q" and value["status"] == 0:
                self._quit_ack = True
            if self.on_response:
                self.on_response(pending.kind, value)
            pending.result = value; pending.event.set()

    def _send(self, data: bytes, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not self._write_lock.acquire(timeout=remaining):
            raise TimeoutError("helper stdin 쓰기 잠금 시간 초과")
        try:
            if self.proc is None or self.proc.stdin.closed:
                raise HelperError("helper stdin 닫힘")
            view = memoryview(data)
            with selectors.DefaultSelector() as sel:
                sel.register(self.proc.stdin, selectors.EVENT_WRITE)
                while view:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("helper stdin 쓰기 시간 초과")
                    if not sel.select(min(.05, remaining)):
                        continue
                    try:
                        n = os.write(self.proc.stdin.fileno(), view)
                    except BlockingIOError:
                        continue
                    if n <= 0:
                        raise HelperError("helper stdin 쓰기 실패")
                    view = view[n:]
        finally:
            self._write_lock.release()

    def request(self, kind: str, body: bytes = b"", *, deadline: float, closing: bool = False) -> dict:
        """일반 요청 하나와 cleanup Q 하나만 보낸다. timeout은 실행을 poisoned로 만든다."""
        if closing != (kind == "Q"):
            raise ValidationFailed("Q는 cleanup 경로로만 보냅니다.")
        locked = False
        if not closing:
            remaining = deadline - time.monotonic()
            locked = remaining > 0 and self.command_lock.acquire(timeout=remaining)
            if not locked:
                raise TimeoutError("helper 명령 잠금 시간 초과")
        rid = None
        try:
            with self._lock:
                if self._error and not closing:
                    raise self._error
                if self._closing and not closing:
                    raise HelperError("helper 정리 중")
                if self._next_id > 0xffffffff or len(self._pending) >= (2 if closing else 1):
                    raise P.ProtocolError("request id/동시 요청 상한")
                rid = self._next_id; self._next_id += 1
                payload = struct.pack("<I", rid) + body
                P.validate(P.Frame(kind, payload), "host")
                pending = Pending(kind)
                self._pending[rid] = pending
            self._send(P.encode(kind, payload), deadline)
            if not pending.event.wait(max(0, deadline - time.monotonic())):
                raise TimeoutError("helper 응답 시간 초과")
            if pending.error:
                raise pending.error
            if pending.result is None:
                raise HelperError("helper 빈 응답")
            result = pending.result
            if result["status"]:
                raise HelperError("helper 요청 실패", data={"request": kind, **{k: result[k] for k in ("status", "winerr")},
                                                           "transferred": result.get("transferred", 0)})
            return result
        except BaseException as exc:
            if not isinstance(exc, HelperError) or not getattr(exc, "data", {}).get("status"):
                self._fail(exc)
            raise
        finally:
            if rid is not None:
                with self._lock:
                    self._pending.pop(rid, None)
            if locked:
                self.command_lock.release()

    def _exit_info(self):
        if self.proc is None:
            return None
        if self.proc.returncode is not None:
            return None  # 이 모듈이 확인 전에 reap하면 정상 증명으로 사용하지 않는다.
        try:
            return os.waitid(os.P_PID, self.proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            return None

    def _normal_ended(self) -> bool:
        info = self._exit_info()
        return bool(info and info.si_code == os.CLD_EXITED and info.si_status == 0 and self._stdout_eof.is_set()
                    and (self._quit_ack or (self.mode == "version" and self._hello is not None and self._error is None)))

    def _signal(self, sig: int) -> None:
        if self.proc is None or self.ticks is None:
            return
        st = procutil.proc_stat(self.proc.pid)
        if st is not None and st[1] == self.ticks:
            try:
                if os.getpgid(self.proc.pid) == self.proc.pid:
                    os.killpg(self.proc.pid, sig)
            except ProcessLookupError:
                pass

    def close(self, *, deadline: float | None = None, send_quit: bool = True) -> None:
        """Q+EOF+정상 종료 또는 Windows 실제 종료와 POSIX 그룹 회수. 미확인은 run을 보존한다."""
        deadline = time.monotonic() + 10 if deadline is None else deadline
        with self._spawn_lock, self._close_lock:
            if self.cleanup_verified:
                return
            self._closing = True
            if send_quit and self.proc is not None and self._hello and not self._quit_ack and not self._stdout_eof.is_set():
                try:
                    self.request("Q", deadline=min(deadline, time.monotonic() + 1), closing=True)
                except BaseException:
                    pass
            if self.proc is not None and self.proc.stdin is not None:
                try: self.proc.stdin.close()
                except OSError: pass
            grace = min(deadline, time.monotonic() + 2)
            while self.proc is not None and not self._exit_info() and time.monotonic() < grace:
                time.sleep(.01)
            normal = self._normal_ended()
            self.normal_completion = self.normal_completion or normal
            posix_closed = self.proc is None
            if self.proc is not None:
                empty = procutil.process_group_empty(self.proc.pid, expect_start_ticks=self.ticks)
                if empty is not True:
                    self._signal(signal.SIGTERM)
                    grace = min(deadline, time.monotonic() + .1)
                    while not self._exit_info() and time.monotonic() < grace:
                        time.sleep(.01)
                    self._signal(signal.SIGKILL)
                    grace = min(deadline, time.monotonic() + .2)
                    while not self._exit_info() and time.monotonic() < grace:
                        time.sleep(.01)
                    empty = procutil.process_group_empty(self.proc.pid, expect_start_ticks=self.ticks)
                posix_closed = empty is True and self._exit_info() is not None
            # interop wrapper가 아직 launch 중이면 Windows '없음' 뒤에 helper가 생길 수 있다.
            # 비정상 경로는 spawn 가능한 POSIX 그룹을 먼저 끝내고 Windows를 마지막에 본다.
            windows_closed = normal and posix_closed
            if not windows_closed and posix_closed and self.copy and time.monotonic() < deadline:
                try:
                    windows_closed = self.windows_lifecycle.terminate_and_confirm(self.token, str(self.copy.path), deadline) is True
                except Exception:
                    windows_closed = False
            if windows_closed and posix_closed:
                self._stop.set()
                if self.thread is not None and self.thread.ident is not None and self.thread is not threading.current_thread():
                    self.thread.join(max(0, deadline - time.monotonic()))
                if self.thread is not None and self.thread.is_alive():
                    raise HelperCleanupError(self)
                if self.proc is not None:
                    self.proc.wait(timeout=0)
                    for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
                        try: stream.close()
                        except OSError: pass
                self.cleanup_verified = True
                if self.copy:
                    try:
                        self.copy.remove(); self.copy = None
                    except OSError:
                        pass  # 사본 삭제 실패는 이미 확인한 실제 종료를 되돌리지 않는다.
                with _RUNS_LOCK:
                    if _RUNS.get(self.token) is self:
                        _RUNS.pop(self.token)
                self._fail(HelperError("helper가 닫혔습니다."))
                return
            self._fail(HelperError("helper 정리 미확인"))
            raise HelperCleanupError(self)

    def metadata(self) -> dict:
        return {"helper_version": list(self.helper.version), "helper_sha256": self.helper.sha256,
                "cleanup_verified": self.cleanup_verified,
                "state": "closed" if self.cleanup_verified else "cleanup-pending" if self._closing else "open"}


def probe_version(helper: HelperBinary, *, timeout: float = 5.0, environment_provider=None,
                  process_factory=None, windows_lifecycle=None, runtime_root: Path | None = None) -> dict:
    """doctor용 no-COM H/EOF/exit 확인. 모든 단계가 한 예산을 공유한다."""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 15:
        raise ValidationFailed("helper version 시간 상한은 15초입니다.")
    deadline = time.monotonic() + timeout
    run = HelperRun(helper, mode="version", environment_provider=environment_provider, process_factory=process_factory,
                    windows_lifecycle=windows_lifecycle, runtime_root=runtime_root)
    try:
        info = run.start(deadline=deadline)
        run.close(deadline=deadline, send_quit=False)
        if not run.normal_completion or run.proc.returncode != 0:
            raise HelperError("helper version의 H/EOF/정상 종료를 확인하지 못했습니다.")
        return {"protocol": list(info["protocol"]), "version": list(info["version"]), "mode": "version",
                "source_commit": info["source_commit"], "sha256": helper.sha256, "cleanup_verified": True}
    finally:
        if not run.cleanup_verified:
            run.close(deadline=deadline, send_quit=False)
