"""가짜 esptool (테스트 전용). esp_testutil.make_fake_esptool() 가 venv python shebang 을 붙여 실행 파일로 만든다.

이름이 ``.exe`` 로 끝나면 Windows 빌드처럼 동작한다: 줄 끝 CRLF, ASCII 진행 막대('='/'>'), 출력 경로 ``\\\\wsl.localhost\\<배포판>\\…``
를 리눅스 경로로 되돌려 쓴다(WSL 9P 공유를 흉내), OS 오류 메시지는 cp949 바이트. 포트는 절대 열지 않는다.

환경변수:
  FAKE_ESPTOOL_LOG          호출마다 {"argv", "cwd", "env", "pid", "stub", "after", "flash_begin"} 한 줄(JSON)을 추가할 파일
  FAKE_ESPTOOL_MODE         normal | v4 | sdm | encrypted | busy | noconn | wrongboot | digest | mismatch | slow | baudstall | stubfail | hang
  FAKE_ESPTOOL_VERSION      5.4.0(기본) | 4.8.1 | 4.12.0 … (mode=v4 이면 4.8.1)
  FAKE_ESPTOOL_CHIP         esp32s3(기본) | esp32(원조: get-security-info 미지원) | esp32c6(EUI-64 MAC)
  FAKE_ESPTOOL_FLASH_BYTES  감지될 플래시 크기(기본 262144 = 256KB, esptool 의 크기 이름이 있는 값만)
  FAKE_ESPTOOL_STATE        read-flash 호출 횟수를 세는 파일 (mismatch: 짝수 번째 호출에서 1바이트 바꿈)
  FAKE_ESPTOOL_SLOW_CALL    slow 모드에서 느리게 할 read-flash 호출 번호(기본 0 = 모든 호출)
  FAKE_ESPTOOL_DELAY        slow 모드 청크당 대기 초 (기본 0.2)
  FAKE_ESPTOOL_FAIL_CALL    digest 모드에서 실패시킬 read-flash 호출 번호(기본 0 = 모든 호출)
  FAKE_ESPTOOL_PIDFILE      read-flash 시작 시 자기 PID 를 쓸 파일
  FAKE_ESPTOOL_FOREIGN_CFG  esptool 이 이 경로의 설정을 읽은 것처럼 'Loaded custom configuration from …' 을 찍고 2초 쉰 뒤 연결
  FAKE_ESPTOOL_CONNECT_MARK 연결 단계(Connecting...)에 들어가면 이 파일에 PID 를 덧붙인다
  FAKE_ESPTOOL_CHIPSTATE    칩 상태 파일 {"mode": rom|stub|app, "baud"} — 호출 사이 스텁 잔류·baud 를 흉내(없으면 상태 없음)
  FAKE_ESPTOOL_NO_AUTORESET 1 이면 DTR/RTS 리셋이 듣지 않는 보드 (before=default-reset 이 칩 상태를 바꾸지 않음)
  FAKE_ESPTOOL_NATIVE_USB   1 이면 네이티브 USB(baud 무관)
  FAKE_ESPTOOL_ONEFILE      1 이면(.exe) PyInstaller onefile 흉내: 부트로더가 FAKE_ESPTOOL_MEI_ROOT/_MEI<pid>1 을 만들고 같은 argv 로
                            자식을 새 세션(= interop 프로세스 그룹 밖)으로 띄워 기다린 뒤 _MEI 를 지운다. 부트로더만 죽으면 자식이 남는다.
출력 문자열은 esptool 5.4.0(esp-pylib 1.2 비대화형 출력)·4.8.1 소스의 print 문을 그대로 따른다.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

ARGV = sys.argv[1:]
EXE = os.path.basename(sys.argv[0])
WINDOWS = EXE.lower().endswith(".exe")

# --- PyInstaller onefile 부트로더 흉내 (자식만 실제 일을 한다) ---
if WINDOWS and os.environ.get("FAKE_ESPTOOL_ONEFILE") == "1" and os.environ.get("FAKE_ESPTOOL_ONEFILE_CHILD") != "1":
    mei = os.path.join(os.environ.get("FAKE_ESPTOOL_MEI_ROOT") or os.getcwd(), f"_MEI{os.getpid()}1")
    os.makedirs(mei, exist_ok=True)
    child = subprocess.Popen([sys.argv[0], *ARGV], env=dict(os.environ, FAKE_ESPTOOL_ONEFILE_CHILD="1"), start_new_session=True)
    rc = child.wait()
    shutil.rmtree(mei, ignore_errors=True)
    sys.exit(rc if rc >= 0 else 1)

MODE = os.environ.get("FAKE_ESPTOOL_MODE", "normal")
VERSION = os.environ.get("FAKE_ESPTOOL_VERSION") or ("4.8.1" if MODE == "v4" else "5.4.0")
VPARTS = tuple(int(x) for x in VERSION.split(".")[:2])
V5 = VPARTS[0] >= 5
NL = "\r\n" if WINDOWS else "\n"
FLASH_BYTES = int(os.environ.get("FAKE_ESPTOOL_FLASH_BYTES", "262144"))
SIZE_NAMES = {256 * 1024: "256KB", 512 * 1024: "512KB", 1 << 20: "1MB", 2 << 20: "2MB", 4 << 20: "4MB", 8 << 20: "8MB", 16 << 20: "16MB"}
TROUBLESHOOTING = "https://docs.espressif.com/projects/esptool/en/latest/troubleshooting.html"
CHIP = os.environ.get("FAKE_ESPTOOL_CHIP", "esp32s3")
CHIPS = {
    "esp32s3": {"name": "ESP32-S3", "desc": "ESP32-S3 (QFN56) (revision v0.2)", "mac": "f4:12:fa:12:34:56",
                "features5": "Wi-Fi, BT 5 (LE), Dual Core + LP Core, 240MHz, Embedded PSRAM 8MB (AP_3v3)",
                "features4": "WiFi, BLE, Embedded PSRAM 8MB (AP_3v3)", "secinfo": True},
    "esp32": {"name": "ESP32", "desc": "ESP32-D0WDQ6 (revision v1.0)", "mac": "24:0a:c4:12:34:56",
              "features5": "Wi-Fi, BT, Dual Core + LP Core, 240MHz, Coding Scheme None",
              "features4": "WiFi, BT, Dual Core, 240MHz, Coding Scheme None", "secinfo": False},
    "esp32c6": {"name": "ESP32-C6", "desc": "ESP32-C6 (QFN40) (revision v0.1)", "mac": "60:55:f9:ff:fe:f7:2c:a2",
                "base_mac": "60:55:f9:f7:2c:a2", "mac_ext": "ff:fe",
                "features5": "Wi-Fi 6, BT 5 (LE), IEEE802.15.4, Single Core + LP Core, 160MHz",
                "features4": "WiFi 6, BT 5, IEEE802.15.4", "secinfo": True},
}[CHIP]
CHIP_ARG_NAME = CHIP  # --chip 값으로 이 칩을 가리키는 이름
RECORD = {"stub": False, "after": None, "flash_begin": False, "stub_reused": False, "baud_at_end": None}


def out(text="", end=None):
    data = (text + (NL if end is None else end))
    sys.stdout.buffer.write(data.encode("utf-8"))
    sys.stdout.buffer.flush()


def out_bytes(data: bytes):
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def err(text):
    sys.stderr.buffer.write((text + NL).encode("utf-8"))
    sys.stderr.buffer.flush()


def log_call(extra=None):
    path = os.environ.get("FAKE_ESPTOOL_LOG")
    if not path:
        return
    env = {k: os.environ.get(k) for k in ("NO_COLOR", "WSLENV", "PYTHONIOENCODING", "PYTHONUNBUFFERED", "FORCE_COLOR", "HOME",
                                          "TTY_COMPATIBLE", "TTY_INTERACTIVE")}
    env["ESPTOOL_vars"] = sorted(k for k in os.environ if k.startswith("ESPTOOL_"))
    env["ESPTOOL"] = {k: v for k, v in os.environ.items() if k.startswith("ESPTOOL_")}
    rec = {"argv": ARGV, "exe": EXE, "cwd": os.getcwd(), "cwd_files": sorted(os.listdir(".")), "env": env, "pid": os.getpid(),
           "ppid": os.getppid()}
    rec.update(extra or {})
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def end_log():
    log_call({"phase": "end", **RECORD})


def fatal(msg, rc=2):
    """v5: 빈 줄 + stderr 'ERROR: A fatal error occurred: …' / v4: stdout '\\nA fatal error occurred: …'."""
    if V5:
        out("")
        err(f"ERROR: A fatal error occurred: {msg}")
    else:
        out("")
        out(f"A fatal error occurred: {msg}")
    end_log()
    sys.exit(rc)


def traceback_exit(exc_qualname, msg):
    """esptool 4.x 의 UnsupportedCommandError(RuntimeError) 처럼 _main 밖으로 나가는 예외: traceback + rc=1."""
    err("Traceback (most recent call last):")
    err('  File "/usr/lib/python3/site-packages/esptool/__init__.py", line 1382, in _main')
    err("    main()")
    err('  File "/usr/lib/python3/site-packages/esptool/cmds.py", line 1311, in flash_id')
    err("    detect_flash_id(esp)")
    err(f"{exc_qualname}: {msg}")
    end_log()
    sys.exit(1)


def usage_error(msg):
    if V5:
        err("Usage: esptool [OPTIONS] COMMAND [ARGS]...")
        err("Try 'esptool -h' for help")
        err("")
        err(f"Error: {msg}")
    else:
        err("usage: esptool [-h] [--chip {auto,esp8266,esp32,...}] ...")
        err(f"esptool: error: {msg}")
    end_log()
    sys.exit(2)


def config_line():
    """esptool 은 시작할 때 설정 파일을 찾아 'Loaded custom configuration from …' 을 찍는다 (ESPTOOL_CFGFILE → cwd → 홈)."""
    foreign = os.environ.get("FAKE_ESPTOOL_FOREIGN_CFG")
    if foreign:
        out(f"Loaded custom configuration from {foreign}")
        time.sleep(2.0)
        return
    env_path = os.environ.get("ESPTOOL_CFGFILE")
    if env_path and os.path.isfile(env_path) and "[esptool]" in open(env_path, encoding="utf-8").read():
        out(f"Loaded custom configuration from {os.path.abspath(env_path)} (set with ESPTOOL_CFGFILE)")
        return
    home = os.environ.get("HOME") or ""
    for d in (os.getcwd(), os.path.join(home, ".config", "esptool"), home):
        p = os.path.join(d, "esptool.cfg")
        if d and os.path.isfile(p) and "[esptool]" in open(p, encoding="utf-8").read():
            out(f"Loaded custom configuration from {p}")
            return


# --- 칩 상태 (호출 사이) ---
STATE_PATH = os.environ.get("FAKE_ESPTOOL_CHIPSTATE")


def load_state():
    if not STATE_PATH:
        return None
    try:
        with open(STATE_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"mode": "rom", "baud": 115200}


def save_state(st):
    if STATE_PATH and st is not None:
        with open(STATE_PATH, "w", encoding="utf-8") as fh:
            json.dump(st, fh)


# ---------------------------------------------------------------------------
log_call({"phase": "start"})
if ARGV == ["version"]:
    out(f"esptool v{VERSION}" if V5 else f"esptool.py v{VERSION}")
    config_line()
    out(VERSION)
    sys.exit(0)

opts = {}
i = 0
while i < len(ARGV) and ARGV[i].startswith("--"):
    name = ARGV[i]
    if name == "--no-stub":
        opts[name] = True
        i += 1
        continue
    if name not in ("--chip", "--port", "--baud", "--before", "--after", "--connect-attempts"):
        usage_error(f"No such option: {name}")
    opts[name] = ARGV[i + 1]
    i += 2
if i >= len(ARGV):
    usage_error("Missing command.")
cmd = ARGV[i]
rest = ARGV[i + 1:]

deprecations = []
AFTER_V4 = ["hard_reset", "soft_reset", "no_reset", "no_reset_stub"] + (["watchdog_reset"] if VPARTS >= (4, 12) else [])
if V5:
    if "_" in cmd:
        deprecations.append(f"Deprecated: Command '{cmd}' is deprecated. Use '{cmd.replace('_', '-')}' instead.")
        cmd = cmd.replace("_", "-")
    for opt in ("--before", "--after"):
        v = opts.get(opt)
        if v and "_" in v:
            deprecations.append(f"Deprecated: Choice '{v}' for option '{opt}' is deprecated. Use '{v.replace('_', '-')}' instead.")
            opts[opt] = v.replace("_", "-")
else:
    if "-" in cmd:
        usage_error(f"argument operation: invalid choice: '{cmd}' (choose from 'load_ram', 'dump_mem', 'read_mem', ...)")
    for opt in ("--before", "--after"):
        v = opts.get(opt)
        if v and "-" in v:
            usage_error(f"argument --{opt[2:]}: invalid choice: '{v}'")
    if opts.get("--after") and opts["--after"] not in AFTER_V4:
        usage_error(f"argument --after/-a: invalid choice: '{opts['--after']}' (choose from {', '.join(AFTER_V4)})")
    cmd = cmd.replace("_", "-")
    opts = {k: (v.replace("_", "-") if isinstance(v, str) and k in ("--before", "--after") else v) for k, v in opts.items()}

if cmd not in ("flash-id", "get-security-info", "read-flash", "chip-id", "read-mac"):
    usage_error(f"No such command '{cmd}'.")
port = opts.get("--port")
chip_arg = opts.get("--chip", "auto")
baud = int(opts.get("--baud", "115200"))
before = opts.get("--before", "default-reset")
after = opts.get("--after", "hard-reset")
no_stub = "--no-stub" in opts
RECORD["after"] = after
native_usb = os.environ.get("FAKE_ESPTOOL_NATIVE_USB") == "1"

# --- 배너 (v5 의 사용 중단 경고는 배너보다 먼저 찍힌다) ---
for d in deprecations:
    err(f"WARNING: {d}")
out(f"esptool v{VERSION}" if V5 else f"esptool.py v{VERSION}")
config_line()
out(f"Serial port {port}:" if V5 else f"Serial port {port}")

if MODE == "hang":  # ESPTOOL_OPEN_PORT_ATTEMPTS=0 처럼 포트 열기를 끝없이 재시도 (출력은 계속 나옴)
    pidfile = os.environ.get("FAKE_ESPTOOL_PIDFILE")
    if pidfile:
        with open(pidfile, "w") as fh:
            fh.write(str(os.getpid()))
    out("Retrying failed connection", end="")
    while True:
        out(".", end="")
        time.sleep(0.2)

if MODE == "busy":
    if WINDOWS:
        os_msg = "액세스가 거부되었습니다.".encode("cp949")
        detail = b"(could not open port '" + port.encode() + b"': PermissionError(13, '" + os_msg + b"', None, 5))"
        hint = b"Hint: Check if the port is not used by another task"
    else:  # pyserial exclusive=True 의 flock 실패 (esptool 은 이 경우 힌트를 붙이지 않음)
        detail = f"([Errno 11] Could not exclusively lock port {port}: [Errno 11] Resource temporarily unavailable)".encode()
        hint = b""
    nl = NL.encode()
    if V5:
        out("")
        sys.stderr.buffer.write(b"ERROR: A fatal error occurred: Could not open " + port.encode() + b", the port is busy or doesn't exist." + nl
                                + detail + nl + nl + (hint + nl + nl if hint else b""))
        sys.stderr.buffer.flush()
    else:
        out("")
        out_bytes(b"A fatal error occurred: Could not open " + port.encode() + b", the port is busy or doesn't exist." + nl + detail + nl + nl)
    end_log()
    sys.exit(2)

mark = os.environ.get("FAKE_ESPTOOL_CONNECT_MARK")
if mark:
    with open(mark, "a", encoding="utf-8") as fh:
        fh.write(f"{os.getpid()}\n")

state = load_state()
if state is not None and before in ("default-reset", "usb-reset") and os.environ.get("FAKE_ESPTOOL_NO_AUTORESET") != "1":
    state = {"mode": "rom", "baud": 115200}  # 리셋 → ROM 다운로드 모드(115200 자동 감지)

chip_name_conn = "Espressif device" if chip_arg == "auto" else CHIPS["name"]
stub_running = False
conn_fail = None
if MODE in ("noconn", "wrongboot"):
    conn_fail = "No serial data received." if MODE == "noconn" else "Wrong boot mode detected (0x2b)! The chip needs to be in download mode."
elif state is not None:
    if state.get("mode") == "app":
        conn_fail = "Wrong boot mode detected (0x13)! The chip needs to be in download mode."
    elif state.get("mode") == "stub":
        if int(state.get("baud") or 115200) != 115200 and not native_usb:
            conn_fail = "No serial data received."  # 스텁이 바꾼 baud 에 남아 있어 115200 동기화가 맞지 않음
        else:
            stub_running = True
if conn_fail:
    out("Connecting...", end="")
    for _ in range(int(opts.get("--connect-attempts", "7")) * 5):
        out(".", end="")
        time.sleep(0.005)
    out("")
    fatal(f"Failed to connect to {chip_name_conn}: {conn_fail}{NL}For troubleshooting steps visit: {TROUBLESHOOTING}")

out("Connecting...", end="")
out(".", end="")
out("")
if chip_arg not in ("auto", CHIP_ARG_NAME):
    if V5:
        fatal(f"This chip is {CHIPS['name']}, not {chip_arg.upper()}. Wrong --chip argument?")
    fatal(f"This chip is {CHIPS['name']} not {chip_arg.upper()}. Wrong --chip argument?")
if chip_arg == "auto":
    out("Detecting chip type...", end="")
    out(f" {CHIPS['name']}")

SDM = MODE == "sdm"
DESC = CHIPS["desc"]
MAC = CHIPS["mac"]


def print_macs():
    if V5:
        out(f"{'MAC:':<20}{MAC}")
        if "base_mac" in CHIPS:
            out(f"{'BASE MAC:':<20}{CHIPS['base_mac']}")
            out(f"{'MAC_EXT:':<20}{CHIPS['mac_ext']}")
    else:
        out(f"MAC: {MAC}")
        if "base_mac" in CHIPS:
            out(f"BASE MAC: {CHIPS['base_mac']}")
            out(f"MAC_EXT: {CHIPS['mac_ext']}")


if V5:
    out(f"Connected to {CHIPS['name']} on {port}:")
    if SDM:
        out(f"{'Chip type:':<20}{CHIPS['name']} in Secure Download Mode")
    else:
        out(f"{'Chip type:':<20}{DESC}")
        out(f"{'Features:':<20}{CHIPS['features5']}")
        out(f"{'Crystal frequency:':<20}40MHz")
        if WINDOWS:
            out(f"{'USB mode:':<20}USB-Serial/JTAG")
        print_macs()
    out("")
    if SDM and cmd not in ("get-security-info",):
        fatal(f"The '{cmd}' command is not available in Secure Download Mode.")
else:
    if SDM:
        out(f"Chip is {CHIPS['name']} in Secure Download Mode")
    else:
        out(f"Chip is {DESC}")
        out(f"Features: {CHIPS['features4']}")
        out("Crystal is 40MHz")
        print_macs()

stub = False
if SDM:
    if V5:
        if not no_stub:
            err("WARNING: Stub flasher is not supported in Secure Download Mode, it has been disabled. Set --no-stub to suppress this warning.")
    else:
        if not no_stub:
            out("WARNING: Stub loader is not supported in Secure Download Mode, setting --no-stub")
elif stub_running:
    # esptool 은 동기화 때 스텁을 알아보면 --chip auto 에서 --no-stub 이어도 스텁 객체로 다룬다(detect_chip)
    if not no_stub:
        out("Stub flasher is already running. No upload is necessary." if V5 else "Stub is already running. No upload is necessary.")
    stub = True
    RECORD["stub_reused"] = True
elif not no_stub:
    if MODE == "stubfail":
        if V5:
            out("Uploading stub flasher...")
            out("Running stub flasher...")
            fatal("Failed to start stub flasher. There was no response. Try running with --no-stub.")
        out("Uploading stub...")
        out("Running stub...")
        fatal("Failed to start stub. There was no response.")
    if V5:
        out("Uploading stub flasher...")
        out("Running stub flasher...")
        out("Stub flasher running.")
    else:
        out("Uploading stub...")
        out("Running stub...")
        out("Stub running...")
    stub = True
RECORD["stub"] = stub
cur_baud = 115200
if baud > 115200:  # ESP32-S3 는 ROM 로더(SDM 포함)도 CHANGE_BAUDRATE 를 지원한다
    out(f"Changing baud rate to {baud}..." if V5 else f"Changing baud rate to {baud}")
    out("Changed.")
    cur_baud = baud
    if MODE == "baudstall":  # baud 를 바꾼 뒤 브리지가 따라오지 못함 (esptool 5.4.0 실측 문구)
        if V5:
            out("")
            out("")
            out("Hard resetting via RTS pin..." if after == "hard-reset" else "Staying in bootloader.")
            fatal("Unable to verify flash chip connection (No more data to read from the serial port. This can have many causes, "
                  f"for troubleshooting steps visit: {TROUBLESHOOTING}).")
        fatal("Unable to verify flash chip connection (Serial data stream stopped: Possible serial noise or corruption.).")
if V5:
    out("")
elif no_stub or SDM:
    out("Enabling default SPI flash mode...")


def finish(rc=0):
    st = load_state()
    if V5:
        out("")
    RECORD["baud_at_end"] = cur_baud
    if after == "hard-reset":
        out("Hard resetting via RTS pin...")
        st = {"mode": "app", "baud": 115200}
    elif after == "no-reset":
        out("Staying in bootloader.")
        if stub:  # soft_reset(True): FLASH_BEGIN(0,0) + FLASH_END(reboot) — 레거시 스텁은 이때 SPI 플래시 상태 레지스터를 다시 쓴다
            RECORD["flash_begin"] = True
            st = {"mode": "rom", "baud": 115200}
        else:
            st = {"mode": "rom", "baud": cur_baud}
    elif after == "no-reset-stub":
        out("Staying in flasher stub.")
        st = {"mode": "stub" if stub else "rom", "baud": cur_baud}
    elif after == "soft-reset":
        out("Soft resetting...")
        RECORD["flash_begin"] = True
        st = {"mode": "app", "baud": 115200}
    elif after == "watchdog-reset":
        out("Hard resetting with a watchdog...")
        st = {"mode": "app", "baud": 115200}
    save_state(st if STATE_PATH else None)
    end_log()
    sys.exit(rc)


size_name = SIZE_NAMES.get(FLASH_BYTES, "Unknown")

if cmd == "flash-id":
    if SDM:  # v4: SPI 레지스터 접근이 거부됨 — UnsupportedCommandError(RuntimeError) 가 _main 밖으로 나간다
        traceback_exit("esptool.util.UnsupportedCommandError", "This command (0xa) is not supported in Secure Download Mode")
    if V5:
        out("Flash Memory Information:")
        out("=" * len("Flash Memory Information:"))
    out("Manufacturer: c8")
    out("Device: 4017")
    out(f"Detected flash size: {size_name}")
    out("Flash type set in eFuse: quad (4 data lines)")
    out("Flash voltage set by a strapping pin: 3.3V" if V5 else "Flash voltage set by a strapping pin to 3.3V")
    finish()

if cmd == "get-security-info":
    if not CHIPS["secinfo"]:  # 원조 ESP32: 새 스텁은 0xFF00(Command not implemented), ROM 은 0x14 미지원
        if stub:
            fatal("Failed to get security info (result was FF00: Command not implemented)")
        if V5:
            fatal("This command (0x14) is not supported in the current download mode")
        traceback_exit("esptool.util.UnsupportedCommandError", "Invalid (unsupported) command 0x14")
    if MODE == "encrypted":
        flags, crypt, purposes = 0x00000001, 0x1, (4, 9, 0, 0, 0, 0, 0)
    elif SDM:
        flags, crypt, purposes = 0x00000005, 0x1, (4, 9, 0, 0, 0, 0, 0)
    else:
        flags, crypt, purposes = 0x00000000, 0x0, (0, 0, 0, 0, 0, 0, 0)
    names = {0: "USER/EMPTY", 4: "XTS_AES_128_KEY", 9: "SECURE_BOOT_DIGEST0"}
    if not V5:
        out("")
    out("Security Information:")
    out("=" * len("Security Information:"))
    out("Flags: {:#010x} ({})".format(flags, bin(flags)))
    out(f"Key Purposes: {purposes}")
    out("  " + (NL + "  ").join(f"BLOCK_KEY{n} - {names.get(p, 'UNKNOWN')}" for n, p in enumerate(purposes) if n <= 5))
    out("Chip ID: 9")
    out("API Version: 0")
    out("Secure Boot: Enabled" if flags & 1 else "Secure Boot: Disabled")
    out("Flash Encryption: Enabled" if bin(crypt).count("1") % 2 else "Flash Encryption: Disabled")
    out(f"SPI Boot Crypt Count (SPI_BOOT_CRYPT_CNT): {crypt:#x}")
    finish()

if cmd in ("chip-id", "read-mac"):
    if V5:
        if cmd == "chip-id":
            err(f"WARNING: {CHIPS['name']} has no chip ID. Reading MAC address instead.")
    else:
        if cmd == "chip-id":
            out(f"Warning: {CHIPS['name']} has no Chip ID. Reading MAC instead.")
    print_macs()
    finish()

# --- read-flash ---
if len(rest) != 3:
    usage_error("read-flash needs ADDRESS SIZE OUTPUT")
address = int(rest[0], 0)
size_tok = rest[1]
output = rest[2]
state_count = os.environ.get("FAKE_ESPTOOL_STATE")
call_no = 1
if state_count:
    try:
        call_no = int(open(state_count).read().strip() or "0") + 1
    except (OSError, ValueError):
        call_no = 1
    with open(state_count, "w") as fh:
        fh.write(str(call_no))
pidfile = os.environ.get("FAKE_ESPTOOL_PIDFILE")
if pidfile:
    with open(pidfile, "w") as fh:
        fh.write(str(os.getpid()))
if SDM and not V5:  # v4 SDM: 크기 감지 거부(FatalError) 또는 READ_FLASH_SLOW 거부(traceback)
    out("Configuring flash size...")
    out("WARNING: In case of failure, please set a specific --flash_size.")
    if size_tok.lower() == "all":
        fatal("Detecting flash size is not supported in secure download mode. Set an exact size value.")
    traceback_exit("esptool.util.UnsupportedCommandError", "This command (0xe) is not supported in Secure Download Mode")
if V5:
    if size_tok.lower() == "all":
        length = FLASH_BYTES
        out(f"Detected flash size: {size_name}")
    else:
        length = int(size_tok, 0)
        if length > FLASH_BYTES:
            fatal(f"Specified size {length:#x} is greater than detected flash size {FLASH_BYTES:#x}.")
    out("Configuring flash size...")
else:
    out("Configuring flash size...")
    if size_tok.lower() == "all":
        length = FLASH_BYTES
        out(f"Detected flash size: {size_name}")
    else:
        length = int(size_tok, 0)
if address + length > FLASH_BYTES:
    fatal(f"Can't access flash regions larger than detected flash size (set size {length:#x} from address {address:#010x} goes past {size_name} by {address + length - FLASH_BYTES:#x} bytes).")


def flash_bytes(start, n):
    buf = bytearray()
    blk = start // 32
    while len(buf) < (start % 32) + n:
        buf += hashlib.sha256(b"pweh-fake-flash" + blk.to_bytes(4, "little")).digest()
        blk += 1
    return bytes(buf[start % 32:start % 32 + n])


data = bytearray(flash_bytes(address, length))
if MODE == "mismatch" and call_no % 2 == 0:
    data[len(data) // 2] ^= 0x5A
slow = MODE == "slow" and int(os.environ.get("FAKE_ESPTOOL_SLOW_CALL", "0") or 0) in (0, call_no)
delay = float(os.environ.get("FAKE_ESPTOOL_DELAY", "0.2")) if slow else 0.0
t0 = time.time()


def fmt_bytes(v):
    if v < 1024:
        return f"{v}B"
    s = float(v)
    for suf in ("kB", "MB", "GB"):
        s /= 1024.0
        if s < 1024.0:
            return f"{s:.2f}{suf}"
    return f"{s:.2f}GB"


def bar(cur, total, width=30):
    full, half = ("=", ">") if WINDOWS else ("━", "╸")
    if total <= 0 or cur >= total:
        return full * width
    halves = int(width * 2 * cur / total)
    n, h = divmod(halves, 2)
    return full * n + (half if h else "") + " " * (width - n - h)


chunk = 4096 if V5 else 1024
done = 0
while done < length:
    step = min(chunk, length - done)
    done += step
    if delay:
        time.sleep(delay)
    if MODE == "digest" and done >= length // 2 and int(os.environ.get("FAKE_ESPTOOL_FAIL_CALL", "0") or 0) in (0, call_no):
        fatal("Digest mismatch: expected 9B2F6E2C47E7A5D3C0A1B2C3D4E5F601, got 1A3C5E7090B2D4F6081A2B3C4D5E6F70")
    if V5:
        pct = f"{100 * done / length:.1f}"
        out(f"Reading from {address + done:#010x} {bar(done, length)} {pct:>5}% {fmt_bytes(done)}/{fmt_bytes(length)} [{int(time.time() - t0)}s] ")
    else:
        msg = "%d (%d %%)" % (done, done * 100.0 / length)
        out(msg, end=("\n" if done == length else "\b" * len(msg)))
secs = max(time.time() - t0, 0.05)
speed = f" ({length / secs * 8 / 1000:.1f} kbit/s)"
if V5:
    out(f"Read {length} bytes from {address:#010x} in {secs:.1f} seconds{speed} to '{output}'.")
else:
    out("Read {:d} bytes at {:#010x} in {:.1f} seconds{}...".format(length, address, secs, speed))
target = output
if output.startswith("\\\\wsl.localhost\\") or output.startswith("\\\\wsl$\\"):
    parts = output.split("\\")  # ['', '', 'wsl.localhost', '<distro>', ...]
    target = "/" + "/".join(parts[4:])
with open(target, "wb") as fh:
    fh.write(data)
finish()
