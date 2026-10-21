"""emu-mcp 실행 shim — 에뮬레이터를 exec 하기 직전의 프로세스 설정 (표준 라이브러리만, ``python -I -S`` 로 실행).

``-I -S`` 이므로 스크립트 디렉터리·현재 디렉터리의 모듈, 사용자 site, ``PYTHON*`` 환경 변수를 읽지 않고 site 모듈도 읽지 않는다.
서버(emu_mcp.session)가 세션마다 감독 스레드에서 이렇게 띄운다::

    [python, -I, -S, <이 파일의 절대 경로>, --ppid PID, --session-dir ABS, --status-fd N, --as N, --cpu SOFT, --cpu-hard HARD,
     --core 0, --nofile 256, --fsize N, (--netns), --, <에뮬레이터 argv…>]

순서:
1. setrlimit (AS·CPU soft/hard·CORE·NOFILE·FSIZE — 지금 hard 보다 높게는 올리지 않는다).
2. prctl(PR_SET_PDEATHSIG, SIGKILL) — 이 프로세스를 만든 **스레드**(서버의 감독 스레드)가 끝나면 커널이 SIGKILL 을 보낸다.
3. getppid() == --ppid 확인 (아니면 부모가 이미 죽어 init·subreaper 로 입양된 것 — exec 하지 않는다).
4. (--netns) unshare(CLONE_NEWUSER | CLONE_NEWNET) → /proc/self/setgroups = deny → 자기 uid/gid 만 매핑.
   실패하면 상태 94 를 쓰고 rc 94 로 끝난다 (서버가 --netns 없이 한 번 다시 띄우고 isolation.netns=false 로 기록 — 결정 D4).
5. 잡을 수 있는 모든 신호(1..NSIG-1, SIGKILL·SIGSTOP 제외)를 SIG_DFL 로 되돌리고 신호 마스크를 비운다
   (CPython 은 SIGPIPE·SIGXFSZ 를 SIG_IGN 으로 두고, 무시 상태는 execve 를 넘어 이어진다 — 되돌리지 않으면 RLIMIT_FSIZE 가
   신호 대신 EFBIG 이 된다. 서버를 띄운 쪽이 무시해 둔 다른 신호도 함께 되돌린다).
6. 상태 fd 에 FD_CLOEXEC → execv (PID 그대로). exec 가 성공하면 상태 fd 가 닫혀 서버는 EOF 를 읽는다(= exec 확인).

상태 파이프 규약: 실패한 경로는 **모두** ``<코드>:<내용>\\n`` 을 쓰고 그 코드로 끝난다(아무것도 쓰지 않고 끝나면 서버가 exec 성공으로
오해할 수 있으므로). 94 netns 불가, 95 부모 확인 실패, 96 prctl 실패, 97 사용법·작업 디렉터리, 98 setrlimit 실패,
127 exec 실패(내용 = errno). ``--probe`` 는 2–4 단계만 해 보고 ``0:probe`` 를 쓰고 0 으로 끝난다(netns 를 못 쓰면 94) —
emu_status 의 ``isolation.netns``.
"""

import ctypes
import fcntl
import os
import resource
import signal
import sys

PR_SET_PDEATHSIG = 1
CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000

_INT_OPTS = ("--ppid", "--status-fd", "--as", "--cpu", "--cpu-hard", "--core", "--nofile", "--fsize")
_STR_OPTS = ("--session-dir",)
_FLAGS = ("--netns", "--probe")


class _State:
    status_fd = -1


def _status(code, detail):
    """상태 파이프에 한 줄 쓴다 (실패해도 조용히 — 파이프가 이미 닫혔을 수 있다)."""
    fd = _State.status_fd
    if fd < 0:
        return
    try:
        os.write(fd, ("%d:%s\n" % (code, detail)).encode("ascii", "replace"))
    except OSError:
        pass


def _fail(code, detail):
    _status(code, detail)
    try:
        os.write(2, ("pweh-emu-shim: %d %s\n" % (code, detail)).encode("ascii", "replace"))
    except OSError:
        pass
    os._exit(code)


def _parse(argv):
    if "--" not in argv:
        return None, None, None
    i = argv.index("--")
    opts, cmd = argv[:i], argv[i + 1:]
    vals = {}
    flags = set()
    j = 0
    while j < len(opts):
        name = opts[j]
        if name in _FLAGS:
            flags.add(name)
            j += 1
            continue
        if name in _INT_OPTS or name in _STR_OPTS:
            if j + 1 >= len(opts):
                return None, None, None
            raw = opts[j + 1]
            if name in _INT_OPTS:
                try:
                    vals[name] = int(raw, 10)
                except ValueError:
                    return None, None, None
            else:
                vals[name] = raw
            j += 2
            continue
        return None, None, None
    return vals, flags, cmd


def _setrlimit(res, soft, hard):
    cur_soft, cur_hard = resource.getrlimit(res)
    if cur_hard != resource.RLIM_INFINITY:
        hard = min(hard, cur_hard)
    soft = min(soft, hard)
    resource.setrlimit(res, (soft, hard))


def _write_proc(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    try:
        os.write(fd, text.encode("ascii"))
    finally:
        os.close(fd)


def _netns(libc):
    uid, gid = os.getuid(), os.getgid()
    if libc.unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0:
        _fail(94, "unshare errno=%d" % ctypes.get_errno())
    try:
        _write_proc("/proc/self/setgroups", "deny")
        _write_proc("/proc/self/uid_map", "%d %d 1" % (uid, uid))
        _write_proc("/proc/self/gid_map", "%d %d 1" % (gid, gid))
    except OSError as exc:
        _fail(94, "idmap errno=%d" % (exc.errno or 0))


def _reset_signals():
    for sig in range(1, signal.NSIG):
        if sig in (signal.SIGKILL, signal.SIGSTOP):
            continue
        try:
            signal.signal(sig, signal.SIG_DFL)
        except (OSError, ValueError, RuntimeError):
            pass  # glibc 예약 실시간 신호(32·33) 등
    signal.pthread_sigmask(signal.SIG_SETMASK, [])


def main(argv):
    vals, flags, cmd = _parse(argv)
    if vals is None:
        os.write(2, b"pweh-emu-shim: usage error\n")
        os._exit(97)
    _State.status_fd = vals.get("--status-fd", -1)
    probe = "--probe" in flags
    if not probe and (not cmd or not os.path.isabs(cmd[0])):
        _fail(97, "argv")
    session_dir = vals.get("--session-dir")
    if session_dir is not None:
        try:
            if os.path.realpath(os.getcwd()) != os.path.realpath(session_dir):
                _fail(97, "cwd")
        except OSError as exc:
            _fail(97, "cwd errno=%d" % (exc.errno or 0))
    # 1. 자원 한도
    limits = (("--as", resource.RLIMIT_AS), ("--core", resource.RLIMIT_CORE), ("--nofile", resource.RLIMIT_NOFILE),
              ("--fsize", resource.RLIMIT_FSIZE))
    try:
        for name, res in limits:
            if name in vals:
                _setrlimit(res, vals[name], vals[name])
        if "--cpu" in vals:
            _setrlimit(resource.RLIMIT_CPU, vals["--cpu"], vals.get("--cpu-hard", vals["--cpu"]))
    except (OSError, ValueError) as exc:
        _fail(98, "setrlimit %s" % (getattr(exc, "errno", None) or type(exc).__name__))
    # 2. 부모(를 만든 스레드)가 죽으면 SIGKILL
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        _fail(96, "prctl errno=%d" % ctypes.get_errno())
    # 3. 부모 확인 (prctl 전에 부모가 죽었으면 이미 입양됨)
    if "--ppid" not in vals or os.getppid() != vals["--ppid"]:
        _fail(95, "ppid")
    # 4. 빈 네트워크 네임스페이스 (선택)
    if "--netns" in flags:
        _netns(libc)
    if probe:
        _status(0, "probe")
        os._exit(0)
    # 5. 신호 처리 복원
    _reset_signals()
    # 6. exec (성공하면 상태 fd 가 닫힌다)
    if _State.status_fd >= 0:
        try:
            flags_fd = fcntl.fcntl(_State.status_fd, fcntl.F_GETFD)
            fcntl.fcntl(_State.status_fd, fcntl.F_SETFD, flags_fd | fcntl.FD_CLOEXEC)
        except OSError as exc:
            _fail(97, "status-fd errno=%d" % (exc.errno or 0))
    try:
        os.execv(cmd[0], cmd)
    except OSError as exc:
        _fail(127, "%d" % (exc.errno or 0))


if __name__ == "__main__":
    main(sys.argv[1:])
