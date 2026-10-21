"""가짜 에뮬레이터 (시험 전용). emu_testutil.make_fake_emulator() 가 venv python shebang 을 붙여
``qemu-system-xtensa``·``qemu-system-riscv32``·``pweh_avr_run`` 이름의 실행 파일(0755)로 만든다.

서버는 에뮬레이터를 최소 환경(PATH·LANG·LC_ALL·TMPDIR·HOME)으로 띄우므로 동작은 환경 변수가 아니라 **가짜 실행 파일 옆의
``fake-mode.json``** 으로 고른다(시작할 때마다 읽는다)::

    {"mode": "boot" | "echo" | "hang" | "flood" | "split" | "exit0" | "exit1" | "crash3" | "noread" | "grandchild",
     "ignore_term": false,          # true 면 SIGTERM 을 무시 (서버의 SIGKILL 단계 시험)
     "lines": [...],                # boot: 줄마다 \\r\\n 을 붙여 쓴다 (기본 배너)
     "prompt": "login: ",           # boot: 마지막의 줄 끝 없는 글
     "script": [...],               # 모드의 단계를 바꿔 쓴다: {"out"}, {"out_hex"}, {"err"}, {"sleep"}, {"exit"}, {"flood"}, {"grandchild"}
     "then": "idle" | "echo" | "hang" | "noread" | "exit:N",   # 단계가 끝난 뒤
     "stderr": [...],               # 시작할 때 stderr 에 쓸 줄
     "flood": {"line": "...", "bytes": N},
     "exit_after": 0.0,             # exit0 의 대기
     "qemu_version": "...", "machines": [...], "avr_version": "...", "avr_commit": "..."}   # 조회 답 바꾸기

- 조회: ``-no-user-config -nodefaults -version`` → 고정 QEMU 버전 줄, ``-no-user-config -nodefaults -machine help`` → esp32·esp32s3·
  esp32c3 를 담은 목록, ``--version``(pweh_avr_run) → ``pweh_avr_run <ver> simavr <고정 커밋>``. 조회마다 실행 파일 옆 ``probe.log`` 에
  한 줄(환경 이름·cwd·RLIMIT_AS)을 남긴다(서버가 shim·최소 환경으로 조회하는지, 캐시가 듣는지 시험).
- 시작하면 **첫 출력 전에** cwd(= 세션 디렉터리)의 ``fake.log`` 에 JSON 한 줄을 덧붙인다: argv, cwd, 환경, getrlimit, pid·ppid·pgid·sid,
  열린 fd(memfd 이름·소켓 수), stdin/stdout/stderr 가 파이프인지, 네트워크 장치(/proc/self/net/dev), 넘겨받은 fd(``-drive file=/proc/self/fd/N``·
  ``--hex-fd N``)를 QEMU 처럼 ``/proc/self/fd/N`` 으로 다시 열어 잰 크기·sha256·봉인(F_GET_SEALS)·쓰기 막힘.
  SigIgn/SigBlk 도 적지만 시험은 단언하지 않는다 (CPython 이 SIGPIPE·SIGXFSZ 를 다시 무시한다 — 그것은 external 시험의 몫).
- 설계 §5.5 의 금지 토큰(또는 서버 템플릿 밖의 AVR 옵션)을 받으면 stderr 에 ``FAKE-FORBIDDEN-TOKEN`` 표식을 쓰고 99 로 끝난다.
- ``qemu-system-*`` 이름이면 SIGTERM·SIGINT·SIGHUP 에 QEMU 처럼 ``<이름>: terminating on signal N from pid P`` 를 stderr 에 쓰고 0 으로 끝난다.
  ``pweh_avr_run`` 이름은 기본 동작(신호로 죽음)이다. AVR 의 echo 는 0x04 를 받으면 ``state=done`` 줄을 쓰고 0 으로 끝난다(펌웨어 멈춤 흉내).
- 표준 라이브러리만 쓰고 스레드를 만들지 않는다(AVR 의 RLIMIT_AS 64 MiB 안에서 돈다). 출력은 ``os.write`` 로 바로 쓴다.
- 이 프로세스의 /proc/<pid>/exe 는 파이썬 인터프리터다 — 서버의 시작 정리는 cmdline[1](이 파일 경로)로 알아본다.
"""

import hashlib
import json
import os
import re
import resource
import select
import signal
import stat
import sys
import time

EXE = os.path.basename(sys.argv[0])
HERE = os.path.dirname(os.path.abspath(sys.argv[0]))
ARGV = sys.argv[1:]
AVR = EXE == "pweh_avr_run"
QEMU = EXE.startswith("qemu-system-")

QEMU_VERSION = "QEMU emulator version 9.2.2 (esp_develop_9.2.2_20260417)"
SIMAVR_COMMIT = "5b08da60497f7564f50941f74a549fe2851db030"
AVR_DRIVER_VERSION = "@AVR_DRIVER_VERSION@"  # make_fake_emulator 가 저장소 실행기 소스의 PWEH_AVR_RUN_VERSION 으로 바꿔 넣는다
MACHINES = ["esp32", "esp32s3", "esp32c3", "none"]

#: 설계 §5.5 — 값 없이 그 자체로 금지인 QEMU 옵션
FORBIDDEN_QEMU = {
    "-mon", "-qmp", "-qmp-pretty", "-nographic", "-S", "-preconfig", "-qtest", "-qtest-log", "-gdb", "-s", "-netdev", "-net", "-vnc",
    "-spice", "-incoming", "-semihosting", "-semihosting-config", "-blockdev", "-mtdblock", "-sd", "-pflash", "-hda", "-hdb", "-hdc",
    "-hdd", "-cdrom", "-fda", "-fdb", "-bios", "-kernel", "-initrd", "-dtb", "-append", "-L", "-option-rom", "-fw_cfg", "-smbios",
    "-acpitable", "-boot", "-mem-path", "-D", "-d", "-dfilter", "-trace", "-pidfile", "-dump-vmstate", "-perfmap", "-jitdump",
    "-audiodev", "-tpmdev", "-chardev", "-device", "-object", "-virtfs", "-fsdev", "-plugin", "-add-fd", "-readconfig", "-set",
    "-writeconfig", "-daemonize", "-runas", "-run-with", "-chroot", "-parallel", "-debugcon", "-usb", "-usbdevice", "-curses", "-sdl",
}
DRIVE_OK = (re.compile(r"^file=/proc/self/fd/\d{1,4},if=mtd,format=raw$"),
            re.compile(r"^file=/proc/self/fd/\d{1,4},if=none,format=raw,id=efuse$"))
GLOBAL_OK = (re.compile(r"^driver=nvram\.esp32(s3|c3)?\.efuse,property=drive,value=efuse$"),
             re.compile(r"^driver=timer\.esp32(s3|c3)?\.timg,property=wdt_disable,value=true$"),
             re.compile(r"^driver=ssi_psram,property=is_octal,value=true$"))
AVR_OPTS = ("--mcu", "--freq", "--uart", "--hex-fd")


def load_cfg():
    try:
        with open(os.path.join(HERE, "fake-mode.json"), encoding="utf-8") as f:
            cfg = json.load(f)
        return cfg if isinstance(cfg, dict) else {}
    except (OSError, ValueError):
        return {}


CFG = load_cfg()


def append_json(path, rec):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))
    finally:
        os.close(fd)


def write_fd(fd, data):
    """끝까지 쓴다. 읽는 쪽이 사라지면(EPIPE) 조용히 끝낸다 (AVR 실행기처럼 rc 5)."""
    view = memoryview(data)
    while view:
        try:
            n = os.write(fd, view)
        except BlockingIOError:
            select.select([], [fd], [], 0.5)
            continue
        except BrokenPipeError:
            os._exit(5 if AVR else 0)
        view = view[n:]


def out(data):
    write_fd(1, data if isinstance(data, bytes) else str(data).encode("utf-8", "surrogateescape"))


def err(text):
    write_fd(2, (str(text) + "\n").encode("utf-8", "surrogateescape"))


def probe_log(kind):
    try:
        append_json(os.path.join(HERE, "probe.log"), {
            "exe": EXE, "kind": kind, "argv": ARGV, "cwd": os.getcwd(), "env": sorted(os.environ),
            "rlimit_as": list(resource.getrlimit(resource.RLIMIT_AS)), "pid": os.getpid(), "pgid": os.getpgid(0)})
    except OSError:
        pass


# --- 조회 ---------------------------------------------------------------------

if QEMU and ARGV == ["-no-user-config", "-nodefaults", "-version"]:
    probe_log("version")
    out((CFG.get("qemu_version") or QEMU_VERSION) + "\nCopyright (c) 2003-2024 Fabrice Bellard and the QEMU Project developers\n")
    sys.exit(int(CFG.get("version_rc", 0)))
if QEMU and ARGV == ["-no-user-config", "-nodefaults", "-machine", "help"]:
    probe_log("machines")
    lines = ["Supported machines are:"] + [f"{m:<20} Fake {m} machine" for m in (CFG.get("machines") or MACHINES)]
    out("\n".join(lines) + "\n")
    sys.exit(0)
if AVR and ARGV == ["--version"]:
    probe_log("version")
    out(f"pweh_avr_run {CFG.get('avr_version') or AVR_DRIVER_VERSION} simavr {CFG.get('avr_commit') or SIMAVR_COMMIT}\n")
    sys.exit(0)


# --- 금지 토큰 (분류기의 이중 확인) ----------------------------------------------

def forbidden_token(argv):
    """설계 §5.5 의 금지 토큰 또는 서버 템플릿 밖의 AVR 옵션 → 그 토큰, 아니면 None."""
    if AVR:
        i = 0
        while i < len(argv):
            t = argv[i]
            if t == "--realtime":
                i += 1
            elif t in AVR_OPTS and i + 1 < len(argv):
                i += 2
            else:
                return t
        return None
    if "-no-user-config" not in argv or "-nodefaults" not in argv:
        return "(-no-user-config/-nodefaults 빠짐)"
    for i, tok in enumerate(argv):
        t = tok[1:] if tok.startswith("--") and len(tok) > 2 else tok
        nxt = argv[i + 1] if i + 1 < len(argv) else None
        if "mon:" in tok or "mux=on" in tok or t in FORBIDDEN_QEMU:
            return tok
        if (t == "-monitor" and nxt != "none") or (t == "-nic" and nxt != "none") or (t == "-display" and nxt != "none"):
            return tok
        if t == "-serial" and nxt != "stdio":
            return tok
        if t == "-drive" and not (nxt and any(rx.match(nxt) for rx in DRIVE_OK)):
            return tok
        if t == "-global" and not (nxt and any(rx.match(nxt) for rx in GLOBAL_OK)):
            return tok
        if t in ("-machine", "-M") and (nxt is None or "," in nxt or "=" in nxt):
            return tok
    return None


bad = forbidden_token(ARGV)
if bad is not None:
    err(f"FAKE-FORBIDDEN-TOKEN {bad}")
    sys.exit(99)


# --- 시작 기록 (첫 출력 전에) ---------------------------------------------------

def handoff_fds(argv):
    """넘겨받은 fd 번호 (QEMU: -drive file=/proc/self/fd/N, AVR: --hex-fd N)."""
    out_ = []
    for i, tok in enumerate(argv):
        nxt = argv[i + 1] if i + 1 < len(argv) else ""
        if not AVR and tok == "-drive":
            m = re.match(r"^file=/proc/self/fd/(\d+),", nxt)
            if m:
                out_.append(("efuse" if "id=efuse" in nxt else "flash", int(m.group(1))))
        elif AVR and tok == "--hex-fd" and nxt.isdigit():
            out_.append(("hex", int(nxt)))
    return out_


def describe_handoff(role, n):
    """QEMU 처럼 /proc/self/fd/N 을 다시 열어 읽는다. 봉인·쓰기 막힘도 잰다."""
    import fcntl

    rec = {"role": role, "fd": n}
    path = f"/proc/self/fd/{n}"
    try:
        rec["name"] = os.readlink(path)
        rec["seals"] = fcntl.fcntl(n, fcntl.F_GET_SEALS)
        h = hashlib.sha256()
        size = 0
        with open(path, "rb") as f:
            while True:
                b = f.read(1 << 20)
                if not b:
                    break
                h.update(b)
                size += len(b)
        rec["sha256"] = h.hexdigest()
        rec["size"] = size
        try:
            os.pwrite(n, b"\0", 0)
            rec["write_blocked"] = False
        except OSError:
            rec["write_blocked"] = True
    except OSError as exc:
        rec["error"] = f"{type(exc).__name__}: errno {exc.errno}"
    return rec


def facts():
    fds = []
    for name in sorted(os.listdir("/proc/self/fd"), key=lambda s: int(s) if s.isdigit() else -1):
        try:
            fds.append([int(name), os.readlink(f"/proc/self/fd/{name}")])
        except (OSError, ValueError):
            pass
    status = {}
    try:
        with open("/proc/self/status", encoding="ascii", errors="replace") as f:
            for line in f:
                if line.startswith(("SigIgn:", "SigBlk:")):
                    k, v = line.split(":", 1)
                    status[k] = v.strip()
    except OSError:
        pass
    net = []
    try:
        with open("/proc/self/net/dev", encoding="ascii", errors="replace") as f:
            net = [ln.split(":", 1)[0].strip() for ln in f.read().splitlines()[2:] if ":" in ln]
    except OSError:
        net = None
    rl = {}
    for key in ("RLIMIT_AS", "RLIMIT_CPU", "RLIMIT_CORE", "RLIMIT_NOFILE", "RLIMIT_FSIZE"):
        rl[key] = list(resource.getrlimit(getattr(resource, key)))
    pipes = {}
    for i, name in enumerate(("stdin", "stdout", "stderr")):
        try:
            pipes[name] = stat.S_ISFIFO(os.fstat(i).st_mode)
        except OSError:
            pipes[name] = None
    links = [t for _n, t in fds]
    return {
        "exe": EXE, "argv": sys.argv, "cwd": os.getcwd(), "env": dict(os.environ), "pid": os.getpid(), "ppid": os.getppid(),
        "pgid": os.getpgid(0), "sid": os.getsid(0), "uid": os.getuid(), "rlimits": rl, "fds": fds,
        "memfds": sorted(t for t in links if t.startswith("/memfd:pweh-emu-")),
        "sockets": sum(1 for t in links if t.startswith("socket:")), "pipes": pipes, "net": net, "status": status,
        "handoff": [describe_handoff(role, n) for role, n in handoff_fds(ARGV)], "mode": CFG.get("mode", "boot"),
    }


try:
    append_json("fake.log", facts())
except OSError as exc:  # pragma: no cover - 세션 디렉터리에 못 쓰면 시험이 fake.log 없음으로 실패한다
    err(f"fake: fake.log 쓰기 실패 errno {exc.errno}")


# --- 신호 ---------------------------------------------------------------------

def _qemu_terminate(signum, frame):
    err(f"{EXE}: terminating on signal {signum} from pid {os.getppid()} (<unknown process>)")
    os._exit(0)


if CFG.get("ignore_term"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
elif QEMU:
    for _sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(_sig, _qemu_terminate)


# --- 동작 ---------------------------------------------------------------------

def preset(mode):
    """모드 → (단계, 다음 동작)."""
    if mode == "boot":
        lines = CFG.get("lines")
        if lines is None:
            lines = ["ESP-ROM:fake-20260417", "PWEH-FAKE-BOOT"] if not AVR else ["OK"]
        steps = [{"out": str(line) + "\r\n"} for line in lines]
        if CFG.get("prompt"):
            steps.append({"out": str(CFG["prompt"])})
        return steps, "idle"
    if mode == "echo":
        return [{"out": "OK\r\n" if AVR else "PWEH-ECHO>\r\n"}], "echo"
    if mode == "hang":
        return [], "hang"
    if mode == "flood":
        return [{"flood": CFG.get("flood") or {}}], "idle"
    if mode == "split":
        # 비밀(NVS 의 합성 값 'not-a-real-pass')의 앞부분 → 틈 → 나머지 + 'login: ' 프롬프트 → 틈 → 줄 끝 + 끝에 닿은 자격증명 값
        return [{"out": "I (7) app: joining with not-a-r"}, {"sleep": 1.2}, {"out": "eal-pass\r\n"}, {"out": "login: "},
                {"sleep": 3.0}, {"out": "\r\n"}, {"out": "I (9) app: psk=hunter2-open-val"}], "idle"
    if mode == "exit0":
        return [{"out": "PWEH-FAKE-BOOT\r\n"}, {"sleep": float(CFG.get("exit_after", 0.0))}, {"exit": 0}], "idle"
    if mode == "exit1":
        line = ("pweh_avr_run: cannot load HEX (line 3)" if AVR
                else f"{EXE}: -drive file=/proc/self/fd/9,if=mtd,format=raw: fake configuration failure")
        return [{"err": line}, {"exit": 1}], "idle"
    if mode == "crash3":
        return [{"out": "OK\r\n"}, {"err": "pweh_avr_run: state=crashed cycles=4242 pc=0x8000"}, {"exit": 3}], "idle"
    if mode == "noread":
        return [{"out": "NOREAD>\r\n"}], "noread"
    if mode == "grandchild":
        return [{"grandchild": True}, {"out": "GRANDCHILD-STARTED\r\n"}], "hang"
    err(f"fake: unknown mode {mode!r}")
    return [{"exit": 98}], "idle"


def flood(spec):
    line = str(spec.get("line") or "FLOOD-LINE 0123456789\r\n").encode("utf-8")
    total = int(spec.get("bytes") or (1 << 20))
    chunk = line * max(1, 65536 // len(line))
    sent = 0
    while sent < total:
        part = chunk[: total - sent]
        out(part)
        sent += len(part)


def grandchild():
    import subprocess  # 이 모드에서만 (AVR 의 주소 공간 한도를 아끼려고)

    p = subprocess.Popen([sys.executable, "-c", "import time\nwhile True: time.sleep(60)"], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
    append_json("fake.log", {"grandchild": p.pid, "parent": os.getpid()})


def run_step(step):
    if "out" in step:
        out(step["out"])
    elif "out_hex" in step:
        out(bytes.fromhex(step["out_hex"]))
    elif "err" in step:
        err(step["err"])
    elif "sleep" in step:
        time.sleep(float(step["sleep"]))
    elif "exit" in step:
        os._exit(int(step["exit"]))
    elif "flood" in step:
        flood(step["flood"])
    elif step.get("grandchild"):
        grandchild()


def sleep_forever():
    while True:
        time.sleep(3600)


def serve(then):
    if then.startswith("exit:"):
        os._exit(int(then.split(":", 1)[1]))
    if then in ("hang", "noread"):
        sleep_forever()
    p = select.poll()
    p.register(0, select.POLLIN | select.POLLHUP)
    while True:
        p.poll()
        try:
            data = os.read(0, 4096)
        except BlockingIOError:
            continue
        if not data:  # stdin 이 닫혔다 (QEMU 처럼 계속 돈다)
            sleep_forever()
        if then == "echo":
            if AVR and b"\x04" in data:
                out(data[: data.index(b"\x04")])
                err("pweh_avr_run: state=done cycles=123456 pc=0x00c2")
                os._exit(0)
            out(data)


mode = str(CFG.get("mode") or "boot")
steps, then = preset(mode)
if isinstance(CFG.get("script"), list):
    steps = CFG["script"]
if CFG.get("then"):
    then = str(CFG["then"])
for line in CFG.get("stderr") or []:
    err(line)
for step in steps:
    run_step(step)
serve(then)
