"""실행 환경 감지 — ``pweh.hostenv`` (설계: docs/design/port-routing.md §3).

결정 트리 H0–H9 로 실행 환경의 종류(``kind``)를 정하고, 보고서 ``pweh.hostenv/v1`` 와 장치 종류별 추천 경로(routes)를 만든다.
esp-mcp 의 ``ports.is_wsl``·``ports.interop_status``, doctor, ``pweh env``, pweh-case 의 ``pipeline_environment()`` 가 이 모듈을 쓰고,
``scripts/install.sh`` 의 ``wsl_interop`` 은 같은 규칙(smoke 제외)을 셸로 구현한다.

규칙:
- 감지는 읽기만 한다(§3.4): 파일 읽기·stat, ``wslinfo``·``wslpath``·``systemctl is-active``·``systemd-detect-virt``·``dpkg-query``(brltty),
  macOS 의 ``sysctl``. Windows 쪽 실행 파일은 C: 의 고정 경로를 H5 로 바꾸고 실제 경로(realpath)가 C: drvfs 마운트 아래인지 확인한
  것만 실행한다(:func:`trusted_windows_exes`): System32 의 powershell.exe 는 코드에 박힌 고정 스크립트만, Program Files 의 usbipd.exe 는
  ``--version``·``state``·``policy list`` 만. $PATH 에서 찾은 실행 파일은 표시만 하고 실행하지 않는다. 모두 시간 제한이 있다.
  ``wsl.exe``·``cmd.exe``·``reg.exe``·``usbip.exe`` 는 실행하지 않는다. 허용 목록은 :func:`check_argv` 이고 기본 :class:`Probe` 의 ``run`` 이 강제한다.
- 환경 변수로 감지를 바꾸지 않는다(시험용 분기 없음). 시험은 :class:`Probe` 와 같은 속성을 가진 객체를 주입한다(§13.1·§14).
  ``WSL_DISTRO_NAME`` 은 표시용일 뿐 판정에 쓰지 않는다. 시스템 도구는 ``$PATH`` 가 아니라 고정 디렉터리에서 찾는다.
- 설정 ``hostenv.disable: [interop, serial_helper, windows_tools]`` 는 좁히기만 한다(§3.3). 적용한 키는 보고서의 ``overridden`` 에 남는다.
  ``interop`` 을 끄면 Windows 쪽 프로그램을 아예 실행하지 않는다.
- 모르는 값은 ``null`` 이다. 모르는 것(null)과 없는 것(false·"absent")을 구별한다.
- 캐시(§3.3)는 probe 객체에 붙는다(기본 probe 는 프로세스 수명 동안 하나). 정적 값은 probe 수명 동안, interop 판정(H4: 등록 파일,
  /init, wslpath)은 부를 때마다 다시 보고, smoke 결과와 usbipd 정보는 300 초. **실패한 결과**(wslpath·wslinfo·smoke 의 실패나 시간
  초과, C: 마운트를 못 찾음)는 NEGATIVE_TTL_S(30 초)만 기억한다 — 한 번의 일시 실패가 프로세스 수명 동안 남지 않게.
  휘발 값(COM 목록, 0.0.0.0 리스너)은 보고서에 넣지 않는다 — doctor 전용 함수(:func:`windows_com_ports`, :func:`wildcard_listeners`)가 읽는다.
- interop(H4) = WSLInterop(-late) 첫 줄 enabled + /init + ``wslpath -w /`` 실행 (+ smoke). C: 드라이브 마운트는 H5 다: 없으면 powershell·
  Windows 정보·usbipd 확인이 없을 뿐 interop 을 끄지 않는다(리눅스 파일 시스템의 esptool.exe 는 C: 없이 돈다).
- 모든 플랫폼에서 import 할 수 있어야 한다(win32 시작 거부 안내 :func:`unsupported_platform`). POSIX 전용 모듈은 함수 안에서 import 한다.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import sysconfig
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

log = logging.getLogger("pweh.hostenv")

SCHEMA = "pweh.hostenv/v1"
KINDS = ("WSL2_INTEROP", "WSL2_NO_INTEROP", "WSL1", "WSL_UNKNOWN", "NATIVE_LINUX", "MACOS", "NATIVE_WINDOWS", "CYGWIN", "MSYS", "CONTAINER")
WSL_KINDS = frozenset({"WSL2_INTEROP", "WSL2_NO_INTEROP", "WSL1", "WSL_UNKNOWN"})
UNSUPPORTED_KINDS = frozenset({"NATIVE_WINDOWS", "CYGWIN", "MSYS"})
#: wslinfo --networking-mode 가 찍는 값 (옛 WSL 은 consomme 대신 virtioproxy)
NETWORKING_MODES = ("nat", "bridged", "mirrored", "consomme", "virtioproxy", "none", "wsl1")
#: 설정 hostenv.disable 에 쓸 수 있는 값 (경로를 끄기만 한다)
DISABLE_KEYS = ("interop", "serial_helper", "windows_tools")

SMOKE_TTL_S = 300.0
TOOLS_TTL_S = 300.0
#: 실패한 결과(시간 초과·실행 실패)를 기억하는 시간. 한 번의 일시 실패가 프로세스 수명 동안 남지 않게 짧게 둔다.
NEGATIVE_TTL_S = 30.0
SMOKE_TIMEOUT_S = 10.0
PS_INFO_TIMEOUT_S = 30.0
PS_LIST_TIMEOUT_S = 45.0
LINUX_TOOL_TIMEOUT_S = 10.0
USBIPD_TIMEOUT_S = 15.0
#: 시간 초과를 나타내는 run() 종료 코드 (coreutils timeout 과 같은 값)
RC_TIMEOUT = 124

POWERSHELL_WIN = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
USBIPD_WIN = "C:\\Program Files\\usbipd-win\\usbipd.exe"
#: usbip-win2 클라이언트(반대 방향). usbipd 로 보지 않고 실행하지도 않는다.
USBIP_WIN2_CLIENTS = ("C:\\Program Files\\USBip\\usbip.exe", "C:\\Program Files\\USBip\\wusbip.exe")
BINFMT_DIR = "/proc/sys/fs/binfmt_misc"
INTEROP_ENTRIES = ("WSLInterop", "WSLInterop-late")
#: 시스템 도구를 찾는 고정 디렉터리 ($PATH 를 쓰지 않는다)
SYSTEM_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")
#: 직렬·USB 장치에 관계된 그룹 (표시용 — 장치를 열 때의 권한 오류가 진실이다)
DEVICE_GROUPS = ("dialout", "uucp", "plugdev", "video")
#: root 와 같은 권한을 주는 그룹 (경고)
ROOT_EQUIVALENT_GROUPS = ("docker", "disk", "lxd")
UDEV_RULE_DIRS = ("/etc/udev/rules.d", "/usr/lib/udev/rules.d", "/lib/udev/rules.d")
_UDEV_RULE_RE = re.compile(r"(openocd|sigrok|pweh|rtl-?sdr|hackrf|brltty)", re.I)
_BRLTTY_RULE = "85-brltty.rules"

# ---------------------------------------------------------------------------
# 고정 PowerShell 스크립트 (이 밖의 스크립트는 실행하지 않는다)
# ---------------------------------------------------------------------------

_PS_PREFIX = ("$ProgressPreference='SilentlyContinue';$ErrorActionPreference='{eap}';"
              "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;")
#: H4 smoke: MS 서명 실행 파일이 interop 으로 실제로 뜨는지
PS_SMOKE = _PS_PREFIX.format(eap="Stop") + "exit 0"
#: H5: OSVersion + 레지스트리 UBR·DisplayVersion, UAC(EnableLUA), Smart App Control 상태, 이 프로세스가 관리자 토큰인지. 읽기만 한다.
PS_WINDOWS_INFO = _PS_PREFIX.format(eap="SilentlyContinue") + (
    "$v=[Environment]::OSVersion.Version;"
    "$cv=Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion';"
    "$pol=Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System';"
    "$ci=Get-ItemProperty -LiteralPath 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy';"
    "$adm=$null;try{$adm=(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()))"
    ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}catch{};"
    "[pscustomobject]@{major=$v.Major;minor=$v.Minor;build=$v.Build;ubr=$cv.UBR;display_version=$cv.DisplayVersion;"
    "enable_lua=$pol.EnableLUA;sac=$ci.VerifiedAndReputablePolicyState;elevated=$adm} | ConvertTo-Json -Compress"
)
#: doctor 전용: 이름에 (COMn) 이 있는 PnP 장치와 드라이버 Service (읽기 전용 CIM 질의 — 포트는 열지 않는다)
PS_LIST_COM = _PS_PREFIX.format(eap="Stop") + (
    "$d=@(Get-CimInstance -ClassName Win32_PnPEntity -Filter \"Name LIKE '%(COM%'\" | "
    "Select-Object Name,PNPDeviceID,Status,Service);"
    "ConvertTo-Json -InputObject $d -Compress -Depth 3"
)
FIXED_PS_SCRIPTS: dict[str, str] = {"smoke": PS_SMOKE, "windows-info": PS_WINDOWS_INFO, "list-com": PS_LIST_COM}

# ---------------------------------------------------------------------------
# 실행 허용 목록 (§3.4·§11)
# ---------------------------------------------------------------------------

#: 이름만 봐도 거부하는 Windows 실행 파일 (이유를 분명히 남기려고 따로 둔다 — 목록에 없는 것도 모두 거부한다)
_DENIED_EXES = frozenset({"wsl.exe", "wslconfig.exe", "wslg.exe", "bash.exe", "cmd.exe", "reg.exe", "usbip.exe", "wusbip.exe",
                          "pwsh.exe", "diskpart.exe", "mountvol.exe"})
_USBIPD_ARGS = frozenset({("--version",), ("state",), ("policy", "list")})
_LINUX_TOOL_ARGS: dict[str, frozenset[tuple[str, ...]]] = {
    "wslinfo": frozenset({("--networking-mode",), ("--version",)}),
    "systemd-detect-virt": frozenset({("-c",), ("-v",)}),
    "systemctl": frozenset({("is-active", "systemd-udevd")}),
    "dpkg-query": frozenset({("-W", "-f=${Status}", "brltty")}),
    "sysctl": frozenset({("-n", "sysctl.proc_translated")}),
}
_PS_FLAGS = ("-NoProfile", "-NonInteractive", "-Command")
#: wslpath 가 실행되는지 보는 무해한 호출 (리눅스 / → UNC 경로. C: 마운트가 없어도 된다)
WSLPATH_PROBE_ARGS = ("-w", "/")
_WIN_ABS_RE = re.compile(r"^([A-Za-z]):[\\/]")


def _basename(exe: str) -> str:
    return exe.replace("\\", "/").rsplit("/", 1)[-1].lower()


def check_argv(argv: Sequence[str], trusted: Mapping[str, str] | None = None) -> str | None:
    """hostenv 가 실행해도 되는 명령인지 확인한다(허용 목록). 되면 None, 아니면 거부 이유.

    - 리눅스 도구는 이름만 받는다(실행할 때 고정 디렉터리에서 찾는다): wslinfo, wslpath -u <Windows 절대 경로> | -w /,
      systemd-detect-virt -c|-v, systemctl is-active systemd-udevd, dpkg-query (brltty), sysctl -n sysctl.proc_translated.
    - Windows 실행 파일은 ``trusted``(:func:`trusted_windows_exes`)에 든 **정확한 경로**만 받는다. 이름·접미사로는 받지 않는다.
      powershell.exe = H5 의 System32\\WindowsPowerShell\\v1.0 경로 + ``-NoProfile -NonInteractive -Command <고정 스크립트>``,
      usbipd.exe = C:\\Program Files\\usbipd-win 경로 + ``--version`` | ``state`` | ``policy list``. 둘 다 C: drvfs 아래로
      realpath 를 확인한 경로이고, $PATH 에서 찾은 실행 파일은 들어가지 않는다. ``trusted`` 가 없으면 Windows 실행 파일은 모두 거부한다.
    """
    if not argv or not all(isinstance(a, str) for a in argv):
        return "빈 명령이거나 문자열이 아닌 인자"
    if any("\x00" in a for a in argv):
        return "NUL 문자가 든 인자"
    exe, args = argv[0], tuple(argv[1:])
    base = _basename(exe)
    if base in _DENIED_EXES:
        return f"{base} 는 실행하지 않는다 (port-routing §3.4·§11)"
    if base.endswith(".exe"):
        t = trusted or {}
        if base == "powershell.exe":
            if not t.get("powershell") or exe != t["powershell"]:
                return "powershell.exe 는 H5 로 찾아 확인한 System32\\WindowsPowerShell\\v1.0 의 정확한 경로로만 실행한다"
            if len(args) != 4 or args[:3] != _PS_FLAGS or args[3] not in FIXED_PS_SCRIPTS.values():
                return "powershell.exe 는 -NoProfile -NonInteractive -Command <코드에 박힌 고정 스크립트> 만 실행한다"
            return None
        if base == "usbipd.exe":
            if not t.get("usbipd") or exe != t["usbipd"]:
                return "usbipd.exe 는 확인한 C:\\Program Files\\usbipd-win 경로로만 실행한다 ($PATH 에서 찾은 것은 실행하지 않음)"
            if args not in _USBIPD_ARGS:
                return "usbipd.exe 는 --version · state · policy list 만 실행한다"
            return None
        return f"허용 목록에 없는 Windows 실행 파일: {base}"
    if "/" in exe:
        return "시스템 도구는 이름으로만 준다 (고정 디렉터리에서 찾는다)"
    if exe == "wslpath":
        if args == WSLPATH_PROBE_ARGS:
            return None
        if len(args) == 2 and args[0] == "-u" and _WIN_ABS_RE.match(args[1]) and not any(c in args[1] for c in "\r\n"):
            return None
        return "wslpath 는 -u <Windows 절대 경로> 또는 -w / 만"
    allowed = _LINUX_TOOL_ARGS.get(exe)
    if allowed is None:
        return f"허용 목록에 없는 명령: {exe}"
    if args not in allowed:
        return f"{exe} 의 허용되지 않은 인자: {list(args)}"
    return None


def _system_tool(name: str) -> str | None:
    for d in SYSTEM_DIRS:
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


# ---------------------------------------------------------------------------
# Probe — 시스템을 읽는 유일한 통로 (시험은 같은 속성을 가진 가짜를 주입한다)
# ---------------------------------------------------------------------------


class Probe:
    """실제 시스템을 읽는 기본 probe. 읽기 전용 동작만 한다(§3.4).

    속성: ``sys_platform``, ``machine``, ``sysconfig_platform``, ``python_version``.
    메서드: ``read_text``, ``exists``, ``is_executable``, ``realpath``, ``listdir``, ``run``, ``env``, ``groups``, ``which``, ``now``.
    ``run`` 은 :func:`check_argv` 를 통과한 명령만 실행한다(Windows 실행 파일은 이 probe 로 확인한 :func:`trusted_windows_exes` 의
    정확한 경로만). 시험용 가짜는 이 클래스를 상속해 메서드를 바꾼다.
    """

    def __init__(self) -> None:
        self.sys_platform = sys.platform
        self.machine = platform.machine() or None
        try:
            self.sysconfig_platform: str | None = sysconfig.get_platform()
        except Exception:  # pragma: no cover - 방어
            self.sysconfig_platform = None
        self.python_version = platform.python_version()

    def read_text(self, path: str) -> str | None:
        """파일 내용(UTF-8, 깨진 바이트는 대체, 최대 4 MiB). 없거나 읽을 수 없으면 None.

        procfs 도 읽는다. /proc/sys 는 read() 크기만큼 커널 버퍼를 잡으므로(4 MiB 한 번에 읽으면 ENOMEM) 64 KiB 씩 읽는다.
        """
        chunks: list[bytes] = []
        total = 0
        try:
            with open(path, "rb", buffering=0) as fh:
                while total < 4 * 1024 * 1024:
                    b = fh.read(64 * 1024)
                    if not b:
                        break
                    chunks.append(b)
                    total += len(b)
        except (OSError, ValueError):
            return None
        return b"".join(chunks).decode("utf-8", "replace")

    def exists(self, path: str) -> bool:
        try:
            return os.path.exists(path)
        except (OSError, ValueError):
            return False

    def is_executable(self, path: str) -> bool:
        try:
            return os.path.isfile(path) and os.access(path, os.X_OK)
        except (OSError, ValueError):
            return False

    def realpath(self, path: str) -> str:
        """심볼릭 링크와 '..' 를 푼 실제 경로 (접두어 비교 전에 쓴다)."""
        try:
            return os.path.realpath(path)
        except (OSError, ValueError):
            return os.path.normpath(path)

    def listdir(self, path: str) -> list[str] | None:
        try:
            return sorted(os.listdir(path))
        except (OSError, ValueError):
            return None

    def run(self, argv: Sequence[str], timeout: float, cwd: str | None = None) -> tuple[int, str] | None:
        """허용 목록의 명령을 실행해 (종료 코드, stdout) 를 돌려준다. 실행할 수 없으면 None, 시간 초과면 (RC_TIMEOUT, "").

        Windows 실행 파일(.exe)이면 그때 이 probe 로 :func:`trusted_windows_exes` 를 구해 정확한 경로인지 본다.
        """
        trusted = trusted_windows_exes(self) if argv and _basename(str(argv[0])).endswith(".exe") else None
        why = check_argv(argv, trusted)
        if why:
            log.warning("hostenv: 실행 거부 %r: %s", list(argv)[:1], why)
            return None
        exe = argv[0]
        if not exe.startswith("/"):
            found = _system_tool(exe)
            if not found:
                return None
            exe = found
        try:
            out = subprocess.run([exe, *argv[1:]], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 timeout=timeout, cwd=cwd if cwd and os.path.isdir(cwd) else None, check=False)
        except subprocess.TimeoutExpired:
            return RC_TIMEOUT, ""
        except (OSError, ValueError, subprocess.SubprocessError):
            return None
        return out.returncode, out.stdout.decode("utf-8", "replace")

    def env(self, name: str) -> str | None:
        return os.environ.get(name) or None

    def groups(self) -> list[str]:
        """이 프로세스의 그룹 이름 (보조 그룹 + 기본 그룹). grp 가 없는 플랫폼은 빈 목록."""
        try:
            import grp
        except ImportError:
            return []
        try:
            gids = set(os.getgroups()) | {os.getgid()}
        except (AttributeError, OSError):
            return []
        names: set[str] = set()
        for g in gids:
            try:
                names.add(grp.getgrgid(g).gr_name)
            except (KeyError, OverflowError):
                continue
        return sorted(names)

    def which(self, name: str) -> str | None:
        """$PATH 에서 찾기. usbipd.exe·usbip.exe 표시에만 쓰고, 결과는 drvfs 아래일 때만 받는다."""
        return shutil.which(name)

    def now(self) -> float:
        return time.monotonic()


class _Cache:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.reset()

    def reset(self) -> None:
        self.static: dict[str, Any] | None = None
        self.static_t = 0.0
        #: 키 → (기억한 시각, 값, 성공 여부). 실패 값은 NEGATIVE_TTL_S 동안만 쓴다.
        self.memo: dict[Any, tuple[float, Any, bool]] = {}
        self.smoke: tuple[float, str] | None = None
        self.windows_info: tuple[float, dict[str, Any] | None] | None = None
        self.usbipd: tuple[float, dict[str, Any]] | None = None


_GUARD = threading.Lock()
_DEFAULT: Probe | None = None


def _default_probe() -> Probe:
    """프로세스에 하나인 기본 probe (캐시도 여기에 붙는다). 시험은 이 함수를 monkeypatch 해 가짜 probe 를 돌려준다."""
    global _DEFAULT
    if _DEFAULT is None:
        with _GUARD:
            if _DEFAULT is None:
                _DEFAULT = Probe()
    return _DEFAULT


def _cache_of(probe: Any) -> _Cache:
    c = getattr(probe, "_hostenv_cache", None)
    if c is None:
        with _GUARD:
            c = getattr(probe, "_hostenv_cache", None)
            if c is None:
                c = _Cache()
                try:
                    setattr(probe, "_hostenv_cache", c)
                except AttributeError:  # pragma: no cover - __slots__ 가짜
                    pass
    return c


def _not_none(v: Any) -> bool:
    return v is not None


def _memo(probe: Any, key: Any, fn: Callable[[], Any], ok: Callable[[Any], bool] = _not_none) -> Any:
    """probe 캐시에 값을 기억한다. 성공 값(ok(v))은 probe 수명 동안, 실패 값은 NEGATIVE_TTL_S 동안만 쓴다
    (wslpath·wslinfo 의 일시 실패나 시간 초과가 프로세스가 끝날 때까지 남지 않게)."""
    c = _cache_of(probe)
    with c.lock:
        now = probe.now()
        hit = c.memo.get(key)
        if hit is not None and (hit[2] or 0 <= now - hit[0] < NEGATIVE_TTL_S):
            return hit[1]
        v = fn()
        c.memo[key] = (now, v, bool(ok(v)))
        return v


def _run(probe: Any, argv: list[str], timeout: float, cwd: str | None = None) -> tuple[int, str] | None:
    try:
        return probe.run(argv, timeout, cwd=cwd)
    except Exception as exc:  # pragma: no cover - 가짜 probe 방어
        log.warning("hostenv: probe.run 실패 %r: %s", argv[:1], exc)
        return None


def _first_line(text: str | None) -> str | None:
    if text is None:
        return None
    for line in text.splitlines():
        s = line.strip()
        if s:
            return s
    return None


def _evidence(step: str, signal: str, value: Any) -> dict[str, Any]:
    return {"step": step, "signal": signal, "value": value}


# ---------------------------------------------------------------------------
# H5: drvfs (Windows 드라이브) 와 Windows 경로 변환 — /mnt/c 를 가정하지 않는다
# ---------------------------------------------------------------------------

_OCTAL_RE = re.compile(r"\\([0-7]{3})")
_DRIVE_DEV_RE = re.compile(r"^([A-Za-z]):\\?$")
_PATH_OPT_RE = re.compile(r"(?:^|[,;])path=([A-Za-z]):\\?(?=[;,]|$)")


def _unescape_mount(s: str) -> str:
    """/proc/mounts 의 8진 이스케이프(\\040 공백, \\134 역슬래시 등)를 푼다."""
    return _OCTAL_RE.sub(lambda m: chr(int(m.group(1), 8)), s)


def _drvfs_mounts(probe: Any) -> dict[str, str]:
    """{드라이브 문자(대문자): 마운트 지점}. WSL2 의 9p(aname=drvfs;path=C:\\), WSL1 의 drvfs(원본 C:), virtiofs 원본 C:\\ 를 받는다."""
    text = probe.read_text("/proc/mounts")
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        dev, mnt, fstype, opts = (_unescape_mount(parts[0]), _unescape_mount(parts[1]), parts[2], _unescape_mount(parts[3]))
        drive = None
        m = _PATH_OPT_RE.search(opts)
        if m and fstype in ("9p", "drvfs", "virtiofs"):
            drive = m.group(1)
        else:
            md = _DRIVE_DEV_RE.match(dev)
            if md and fstype in ("drvfs", "9p", "virtiofs"):
                drive = md.group(1)
        if drive and mnt.startswith("/"):
            out.setdefault(drive.upper(), mnt.rstrip("/") or "/")
    return out


def _wslpath_u(probe: Any, win_path: str) -> str | None:
    def go() -> str | None:
        r = _run(probe, ["wslpath", "-u", win_path], LINUX_TOOL_TIMEOUT_S)
        if not r or r[0] != 0:
            return None
        s = _first_line(r[1])
        return s if s and s.startswith("/") else None

    return _memo(probe, ("wslpath-u", win_path), go)


def drvfs_root(drive: str = "C", probe: Any = None) -> str | None:
    """Windows 드라이브의 WSL 마운트 지점 (예: 'C' → '/mnt/c', automount root 를 바꿨으면 그 아래).

    /proc/mounts 의 drvfs 항목(``path=C:\\``)을 먼저 보고, 없으면 ``wslpath -u 'C:\\'`` 를 쓴다. 둘 다 안 되면 None.
    """
    probe = probe or _default_probe()
    d = str(drive or "").strip().rstrip(":\\/").upper()
    if len(d) != 1 or not d.isalpha():
        return None

    def go() -> str | None:
        found = _drvfs_mounts(probe).get(d)
        if found:
            return found
        via = _wslpath_u(probe, f"{d}:\\")
        return (via.rstrip("/") or "/") if via else None

    return _memo(probe, ("drvfs", d), go)


def windows_path_to_wsl(win_path: str, probe: Any = None) -> str | None:
    """Windows 절대 경로('C:\\Windows\\…') → WSL 경로. drvfs 마운트 지점을 쓰고, 모르면 ``wslpath -u`` 를 쓴다.

    드라이브 문자로 시작하는 절대 경로만 받는다(UNC·상대 경로·'..'·제어 문자는 None).
    """
    probe = probe or _default_probe()
    s = str(win_path or "")
    m = _WIN_ABS_RE.match(s)
    if not m or any(ord(c) < 32 for c in s):
        return None
    parts = [p for p in re.split(r"[\\/]+", s[3:]) if p]
    if any(p in ("..", ".") for p in parts):
        return None
    root = drvfs_root(m.group(1), probe)
    if root:
        return root.rstrip("/") + ("/" + "/".join(parts) if parts else "") or "/"
    return _wslpath_u(probe, s)


def _within(path: str, root: str | None, probe: Any) -> bool:
    """path 의 실제 경로가 root 의 실제 경로 아래인가 (realpath 뒤에 비교 — '/mnt/c/../..' 나 밖을 가리키는 링크는 거짓)."""
    if not root or root == "/":
        return False
    rp, rr = probe.realpath(path), probe.realpath(root).rstrip("/")
    return bool(rr) and rr != "/" and rp.startswith(rr + "/")


def _under_drvfs(path: str, probe: Any) -> bool:
    """path 가 (실제 경로로) Windows 드라이브 마운트 아래인가. 표시용 판단에만 쓴다(실행 허용은 trusted_windows_exes)."""
    roots = list(_drvfs_mounts(probe).values())
    c = drvfs_root("C", probe)
    if c:
        roots.append(c)
    return any(_within(path, r, probe) for r in roots)


def _verified_c_file(win_path: str, probe: Any) -> str | None:
    """C: 의 고정 Windows 경로 → 실제로 있고 realpath 가 C: drvfs 마운트 아래인 WSL 경로. 아니면 None."""
    p = windows_path_to_wsl(win_path, probe)
    if not p or not probe.exists(p):
        return None
    if not _within(p, drvfs_root("C", probe), probe):
        return None
    return probe.realpath(p)


def powershell_path(probe: Any = None) -> str | None:
    """H5: Windows PowerShell 5.1 의 실제 경로(C:\\Windows\\System32\\WindowsPowerShell\\v1.0, realpath 가 C: drvfs 아래).

    $PATH 의 powershell.exe 는 쓰지 않는다. 없으면 None(실패는 NEGATIVE_TTL_S 동안만 기억).
    """
    probe = probe or _default_probe()
    return _memo(probe, "powershell", lambda: _verified_c_file(POWERSHELL_WIN, probe))


def _usbipd_fixed(probe: Any) -> str | None:
    """usbipd-win 의 표준 설치 위치(C:\\Program Files\\usbipd-win\\usbipd.exe)의 확인한 실제 경로. 실행해도 되는 유일한 usbipd 다."""
    return _memo(probe, "usbipd-fixed", lambda: _verified_c_file(USBIPD_WIN, probe))


def trusted_windows_exes(probe: Any = None) -> dict[str, str]:
    """hostenv 가 실행해도 되는 Windows 실행 파일의 정확한 경로 {"powershell": …, "usbipd": …} (찾은 것만).

    H5 로 만든 고정 경로가 실제로 있고 realpath 가 C: drvfs 마운트 아래일 때만 넣는다. $PATH(which) 결과는 넣지 않는다.
    :func:`check_argv` 의 ``trusted`` 인자이고, 기본 :class:`Probe` 의 ``run`` 이 쓴다.
    """
    probe = probe or _default_probe()
    out: dict[str, str] = {}
    ps = powershell_path(probe)
    if ps:
        out["powershell"] = ps
    u = _usbipd_fixed(probe)
    if u:
        out["usbipd"] = u
    return out


def _wslpath_runs(probe: Any) -> bool:
    """H4 의 'wslpath 실행': 무해한 ``wslpath -w /`` 가 성공하는가 (C: 마운트와 무관 — esp 는 출력 경로를 wslpath -w 로 바꾼다).
    실패는 NEGATIVE_TTL_S 동안만 기억한다(한 번의 시간 초과가 interop 을 프로세스 수명 동안 끄지 않게)."""
    def go() -> bool:
        r = _run(probe, ["wslpath", *WSLPATH_PROBE_ARGS], LINUX_TOOL_TIMEOUT_S)
        return bool(r and r[0] == 0 and (r[1] or "").strip())

    return bool(_memo(probe, "wslpath-runs", go, ok=bool))


# ---------------------------------------------------------------------------
# esptool.exe 해석 (esp 와 같은 규칙: 설정 → 환경 변수 → 도구 디렉터리 후보)
# ---------------------------------------------------------------------------


def _tools_dir(probe: Any) -> Path:
    v = probe.env("PWEH_TOOLS_DIR")
    if v:
        return Path(v).expanduser()
    from .toolsdir import tools_dir

    return tools_dir()


def resolve_esptool_win(configured: str | None, env_value: str | None, tools_dir: Path | None, probe: Any = None) -> dict[str, Any]:
    """Windows esptool.exe 찾기 — esp 서버의 ``_find_windows_exe`` 와 같은 판단(실행하지 않는다).

    반환: {present, path, source(config|env|pweh-tools), problem}. 설정·환경 변수로 준 경로가 없거나 .exe 가 아니거나 실행 권한이
    없으면 ``problem`` 에 이유를 적는다(doctor 의 [!!]). 도구 디렉터리 후보가 없으면 다음 후보로 넘어간다.
    """
    from .toolsdir import esptool_win_candidates

    probe = probe or _default_probe()
    for cand, source in esptool_win_candidates(configured, env_value, tools_dir):
        path: str | None = cand
        if _WIN_ABS_RE.match(cand):
            path = windows_path_to_wsl(cand, probe)
            if not path:
                if source != "pweh-tools":
                    return {"present": False, "path": cand, "source": source, "problem": f"Windows 경로를 WSL 경로로 바꿀 수 없음: {cand}"}
                continue
        path = os.path.expanduser(path)
        if not probe.exists(path):
            if source != "pweh-tools":
                return {"present": False, "path": path, "source": source, "problem": f"설정된 Windows esptool.exe 가 없음 (출처: {source})"}
            continue
        if not path.lower().endswith(".exe"):
            return {"present": False, "path": path, "source": source, "problem": "Windows esptool 경로는 .exe 여야 함"}
        if not probe.is_executable(path):
            return {"present": False, "path": path, "source": source, "problem": "실행 권한이 없음 (chmod +x 는 사람이)"}
        return {"present": True, "path": path, "source": source, "problem": None}
    return {"present": False, "path": None, "source": None, "problem": None}


def resolve_serial_helper(configured: str | None, env_value: str | None, tools_root: Path | None,
                          probe: Any = None) -> dict[str, Any]:
    """helper의 정적 위치만 보고한다. 신뢰 판정·해시·Windows 실행·경로 변환은 하지 않는다.

    present는 설치 흔적이다. 실행 전에 winserial.binary가 불변 pin과 파일을 다시 대조한다.
    명시한 잘못된 경로를 관리 위치로 대체하지 않는다.
    """
    from .toolsdir import serial_helper_candidates
    probe = probe or _default_probe()
    result = {"present": False, "path": None, "source": None, "problem": None,
              "trusted": None, "trust_check": "pre-execution"}
    for path, source in serial_helper_candidates(configured, env_value, tools_root):
        item = {**result, "path": path, "source": source}
        if not os.path.isabs(path) or not path.lower().endswith(".exe") or any(ord(c) < 32 for c in path):
            return {**item, "problem": "COM helper는 WSL에서 보이는 절대 .exe 경로여야 함"}
        if not probe.exists(path):
            if source != "pweh-tools":
                return {**item, "problem": "설정된 COM helper 파일이 없음"}
            continue
        if not probe.is_executable(path):
            return {**item, "problem": "COM helper가 실행 가능한 일반 파일이 아님"}
        return {**item, "present": True}
    return result


# ---------------------------------------------------------------------------
# 결정 트리 — 정적 부분 (probe 수명 동안 캐시)
# ---------------------------------------------------------------------------


def _h0(probe: Any) -> str | None:
    p = str(getattr(probe, "sys_platform", "") or "")
    if p.startswith("win32"):
        return "NATIVE_WINDOWS"
    if p.startswith("cygwin"):
        return "CYGWIN"
    if p.startswith("msys"):
        return "MSYS"
    if p.startswith("darwin"):
        return "MACOS"
    if p.startswith("linux"):
        return "linux"
    return None


def _h1_container(probe: Any) -> tuple[str | None, bool]:
    """(컨테이너 표지, 일시 실패 여부). WSL 커널 문자열이 보여도 컨테이너면 WSL 로 보지 않는다(WSL 안의 docker).

    systemd-detect-virt 가 시간 초과면 판정을 오래 기억하지 않도록 일시 실패로 알린다(정적 캐시를 NEGATIVE_TTL_S 뒤 다시 만든다).
    """
    for path in ("/.dockerenv", "/run/.containerenv"):
        if probe.exists(path):
            return path, False
    v = probe.env("container")
    if v:
        return f"container={v}", False
    r = _run(probe, ["systemd-detect-virt", "-c"], LINUX_TOOL_TIMEOUT_S)
    if r is not None:
        out = (_first_line(r[1]) or "").lower()
        if out and out not in ("none", "wsl"):
            return f"systemd-detect-virt -c={out}", False
    return None, bool(r is not None and r[0] == RC_TIMEOUT)


def _wslinfo(probe: Any, flag: str) -> tuple[int, str] | None:
    return _memo(probe, ("wslinfo", flag), lambda: _run(probe, ["wslinfo", flag], LINUX_TOOL_TIMEOUT_S),
                 ok=lambda r: r is not None and r[0] == 0)


def _os_release(probe: Any) -> str | None:
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        text = probe.read_text(path)
        if text is None:
            continue
        m = re.search(r'^PRETTY_NAME=(?:"([^"\n]*)"|\'([^\'\n]*)\'|(\S+))', text, re.M)
        if m:
            return next(g for g in m.groups() if g is not None) or None
    return None


def _brltty(probe: Any) -> dict[str, Any]:
    r = _run(probe, ["dpkg-query", "-W", "-f=${Status}", "brltty"], LINUX_TOOL_TIMEOUT_S)
    if r is not None and r[0] in (0, 1):
        installed: bool | None = r[0] == 0 and "install ok installed" in r[1]
    else:
        installed = probe.exists("/usr/bin/brltty") or probe.exists("/bin/brltty")
    etc = probe.read_text(f"/etc/udev/rules.d/{_BRLTTY_RULE}")
    lib = None
    for d in ("/usr/lib/udev/rules.d", "/lib/udev/rules.d"):
        lib = probe.read_text(f"{d}/{_BRLTTY_RULE}")
        if lib is not None:
            break
    masked = etc is not None and not etc.strip()  # /etc 의 같은 이름 빈 파일(/dev/null 링크)이 규칙을 가린다
    effective = etc if etc is not None else lib
    ch340: bool | None = None
    if effective is not None:
        ch340 = bool(re.search(r"1a86/7523|idVendor\}==\"1a86\".{0,120}idProduct\}==\"7523\"", effective, re.I | re.S))
    return {"installed": installed, "ch340_rule": ch340, "masked": masked if (etc is not None or lib is not None) else None}


def _linux_section(probe: Any, osrelease: str | None, container: str | None, native: bool) -> dict[str, Any]:
    pid1 = _first_line(probe.read_text("/proc/1/comm"))
    systemd = None if pid1 is None else pid1 == "systemd"
    udevd: bool | None = None
    if systemd:
        r = _run(probe, ["systemctl", "is-active", "systemd-udevd"], LINUX_TOOL_TIMEOUT_S)
        udevd = None if r is None else _first_line(r[1]) == "active"
    groups = set(probe.groups() or [])
    rules: set[str] = set()
    for d in UDEV_RULE_DIRS:
        for name in probe.listdir(d) or []:
            if name.endswith(".rules") and _UDEV_RULE_RE.search(name):
                rules.add(name)
    virt = None
    if native:
        r = _run(probe, ["systemd-detect-virt", "-v"], LINUX_TOOL_TIMEOUT_S)
        virt = (_first_line(r[1]) or None) if r is not None else None
    return {
        "distro": _os_release(probe),
        "kernel": osrelease,
        "container": container is not None,
        "container_signal": container,
        "virt": virt,
        "systemd": systemd,
        "udevd": udevd,
        "groups": [g for g in DEVICE_GROUPS if g in groups],
        "root_equivalent_groups": [g for g in ROOT_EQUIVALENT_GROUPS if g in groups],
        "udev_rules": sorted(rules),
        "brltty": _brltty(probe),
        "usb_nodes": "present" if probe.exists("/dev/bus/usb") else "absent",
        "ssh_session": bool(probe.env("SSH_CONNECTION") or probe.env("SSH_TTY")),
    }


def _macos_section(probe: Any) -> dict[str, Any]:
    r = _run(probe, ["sysctl", "-n", "sysctl.proc_translated"], LINUX_TOOL_TIMEOUT_S)
    rosetta = None
    if r is not None and r[0] == 0:
        v = _first_line(r[1])
        rosetta = v == "1" if v in ("0", "1") else None
    plist = probe.read_text("/System/Library/CoreServices/SystemVersion.plist") or ""
    m = re.search(r"<key>ProductVersion</key>\s*<string>([^<]{1,32})</string>", plist)
    return {"product_version": m.group(1) if m else None, "rosetta": rosetta}


def _detect_static(probe: Any) -> dict[str, Any]:
    ev: list[dict[str, Any]] = []
    base = _h0(probe)
    st: dict[str, Any] = {
        "base": base,
        "python": {
            "sys_platform": getattr(probe, "sys_platform", None),
            "machine": getattr(probe, "machine", None),
            "version": getattr(probe, "python_version", None),
        },
        "linux": None, "macos": None, "wsl": None, "evidence": ev,
    }
    ev.append(_evidence("H0", "sys.platform", st["python"]["sys_platform"]))
    if base == "NATIVE_WINDOWS":
        st["python"]["mingw"] = str(getattr(probe, "sysconfig_platform", "") or "").startswith("mingw")
    if base == "MACOS":
        st["macos"] = _macos_section(probe)
        st["kind"] = "MACOS"
        return st
    if base != "linux":
        st["kind"] = base  # NATIVE_WINDOWS / CYGWIN / MSYS / None(알 수 없는 플랫폼)
        return st

    osrelease = _first_line(probe.read_text("/proc/sys/kernel/osrelease"))
    container, soft = _h1_container(probe)
    st["_soft_fail"] = soft
    if container:
        ev.append(_evidence("H1", "container", container))
        st["linux"] = _linux_section(probe, osrelease, container, native=False)
        st["kind"] = "CONTAINER"
        return st

    markers: list[str] = []
    if osrelease and "microsoft" in osrelease.lower():
        markers.append("osrelease")
    if probe.exists("/run/WSL"):
        markers.append("/run/WSL")
    for name in INTEROP_ENTRIES:
        if probe.exists(f"{BINFMT_DIR}/{name}"):
            markers.append(f"binfmt_misc/{name}")
    cmdline = probe.read_text("/proc/cmdline") or ""
    if any(tok.startswith("WSL_ROOT_INIT") for tok in cmdline.split()):
        markers.append("cmdline:WSL_ROOT_INIT")
    if not markers:
        st["linux"] = _linux_section(probe, osrelease, None, native=True)
        st["kind"] = "NATIVE_LINUX"
        ev.append(_evidence("H2", "wsl_markers", []))
        return st
    ev.append(_evidence("H2", "wsl_markers", markers))

    # H3: WSL1 / WSL2
    version: int | None = None
    source: str | None = None
    net = _wslinfo(probe, "--networking-mode")
    mode = None
    if net is not None and net[0] == 0:
        mode = (_first_line(net[1]) or "").lower() or None
    if osrelease and re.search(r"-Microsoft$", osrelease):
        version, source = 1, "osrelease"
    elif osrelease and re.search(r"microsoft-standard", osrelease, re.I):
        version, source = 2, "osrelease"
    elif mode:
        version, source = (1 if mode == "wsl1" else 2), "wslinfo"
    ev.append(_evidence("H3", "/proc/sys/kernel/osrelease", osrelease))
    if source == "wslinfo":
        ev.append(_evidence("H3", "wslinfo --networking-mode", mode))
    ev.append(_evidence("H6", "wslinfo --networking-mode", mode if net is not None and net[0] == 0 else
                        (None if net is None else f"exit {net[0]}")))
    rel = _wslinfo(probe, "--version")
    release = _first_line(rel[1]) if rel is not None and rel[0] == 0 else None
    # wslinfo 가 실패·시간 초과면(실행 불가 = 옛 WSL 은 제외) 버전·네트워킹 모드를 오래 기억하지 않는다
    if net is not None and net[0] != 0:
        st["_soft_fail"] = True
    st["wsl"] = {
        "version": version,
        "version_source": source,
        "release": release,
        "distro": probe.env("WSL_DISTRO_NAME"),  # 표시용 (판정에 쓰지 않는다)
        "networking_mode": mode,
        "drvfs_c": None,  # 부를 때마다 채운다 (_assemble — 실패는 짧게 기억)
        "markers": markers,
    }
    st["linux"] = _linux_section(probe, osrelease, None, native=False)
    st["kind"] = "WSL"
    return st


# ---------------------------------------------------------------------------
# 결정 트리 — 매번 보는 부분 (interop 등록, smoke, Windows 정보, usbipd)
# ---------------------------------------------------------------------------


def _interop_entry(probe: Any) -> tuple[str | None, str]:
    """(항목 이름, enabled|disabled|absent). WSLInterop 과 WSLInterop-late 중 하나라도 첫 줄이 enabled 면 enabled."""
    disabled: str | None = None
    for name in INTEROP_ENTRIES:
        text = probe.read_text(f"{BINFMT_DIR}/{name}")
        if text is None:
            continue
        if _first_line(text) == "enabled":
            return name, "enabled"
        disabled = disabled or name
    return (disabled, "disabled") if disabled else (None, "absent")


def _smoke(probe: Any, drvfs_c: str | None) -> str:
    ps = powershell_path(probe)
    if not ps:
        return "no-powershell"
    r = _run(probe, [ps, *_PS_FLAGS, PS_SMOKE], SMOKE_TIMEOUT_S, cwd=drvfs_c)
    if r is None:
        return "cannot-run"
    if r[0] == 0:
        return "ok"
    return "timeout" if r[0] == RC_TIMEOUT else "failed"


def _as_int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().lstrip("-").isdigit():
        return int(v.strip())
    return None


def _windows_info(probe: Any, drvfs_c: str | None) -> dict[str, Any] | None:
    ps = powershell_path(probe)
    if not ps:
        return None
    r = _run(probe, [ps, *_PS_FLAGS, PS_WINDOWS_INFO], PS_INFO_TIMEOUT_S, cwd=drvfs_c)
    if not r or r[0] != 0:
        return None
    try:
        data = json.loads((r[1] or "").strip().lstrip("\ufeff") or "null")
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    major, minor, build, ubr = (_as_int(data.get(k)) for k in ("major", "minor", "build", "ubr"))
    build_s = None
    if None not in (major, minor, build):
        build_s = f"{major}.{minor}.{build}" + (f".{ubr}" if ubr is not None else "")
    lua = _as_int(data.get("enable_lua"))
    elevated = data.get("elevated")
    disp = data.get("display_version")
    return {
        "build": build_s,
        "display_version": str(disp) if isinstance(disp, (str, int)) and str(disp).strip() else None,
        "uac_enabled": None if lua is None else lua != 0,
        "interop_elevated": elevated if isinstance(elevated, bool) else None,
        "smart_app_control": {0: "off", 1: "on", 2: "evaluation"}.get(_as_int(data.get("sac"))),  # type: ignore[arg-type]
    }


def _usbipd_elsewhere(probe: Any) -> str | None:
    """$PATH 에서 찾은 usbipd.exe 의 실제 경로 (표준 위치가 아닌 것). **실행하지 않고** 보고서에 표시만 한다."""
    w = probe.which("usbipd.exe")
    return probe.realpath(w) if w else None


def _usbipd_info(probe: Any, path: str) -> dict[str, Any]:
    out: dict[str, Any] = {"version": None, "autobind_policies": None}
    r = _run(probe, [path, "--version"], USBIPD_TIMEOUT_S)
    if r and r[0] == 0:
        out["version"] = _first_line(r[1])
    r = _run(probe, [path, "policy", "list"], USBIPD_TIMEOUT_S)
    if r and r[0] == 0:
        # 출력 형식은 실행해 보지 않았다(설계 §3.4 [중간]): 'AutoBind' 가 든 줄을 정책 행으로 센다
        out["autobind_policies"] = sum(1 for line in r[1].splitlines() if "autobind" in line.lower())
    return out


def _ignored_clients(probe: Any) -> list[str]:
    out: list[str] = []
    for win in USBIP_WIN2_CLIENTS:
        p = windows_path_to_wsl(win, probe)
        if p and probe.exists(p):
            out.append(f"{win} (usbip-win2 클라이언트 — usbipd 로 보지 않고 실행하지 않음)")
    for name in ("usbip.exe", "wusbip.exe"):
        w = probe.which(name)
        if w and _under_drvfs(w, probe) and not any(name in x for x in out):
            out.append(f"{w} (usbip-win2 클라이언트 — usbipd 로 보지 않고 실행하지 않음)")
    return out


_CFG_MEMO: dict[str, Any] = {}


def _lazy_hostenv_section() -> dict[str, Any]:
    """PWEH 설정(PWEH_CONFIG 또는 위로 찾기)의 ``hostenv`` 절만. (경로, mtime, 크기)로 기억한다(esp 가 자주 부른다)."""
    from .config import find_config_file, load_config

    path = find_config_file()
    key: Any = None
    if path is not None:
        st = os.stat(path)
        key = (str(path), st.st_mtime_ns, st.st_size)
    with _GUARD:
        if "raw" in _CFG_MEMO and _CFG_MEMO.get("key") == key:
            return copy.deepcopy(_CFG_MEMO["raw"])
    sec = (load_config(path).raw or {}).get("hostenv") if path is not None else None
    raw = {"hostenv": copy.deepcopy(sec)} if isinstance(sec, Mapping) else {}
    with _GUARD:
        _CFG_MEMO.update(key=key, raw=raw)
    return copy.deepcopy(raw)


def _config_raw(config: Any) -> tuple[dict[str, Any], str | None, bool]:
    """(설정 raw dict, 경고, 명시적으로 받았는지). config=None 이면 PWEH 설정의 ``hostenv`` 절(override)만 쓴다."""
    if config is None:
        try:
            return _lazy_hostenv_section(), None, False
        except Exception as exc:  # noqa: BLE001 - 설정이 깨져도 감지는 한다
            return {}, f"설정을 읽지 못해 hostenv override 를 적용하지 않음: {exc}", False
    raw = getattr(config, "raw", config)
    return (dict(raw) if isinstance(raw, Mapping) else {}), None, True


def _overrides(raw: Mapping[str, Any]) -> tuple[set[str], list[str]]:
    sec = raw.get("hostenv") if isinstance(raw, Mapping) else None
    disable = sec.get("disable") if isinstance(sec, Mapping) else None
    if isinstance(disable, str):
        disable = [disable]
    vals = {str(x).strip().lower() for x in (disable or []) if isinstance(x, str) and x.strip()} if isinstance(disable, (list, tuple)) else set()
    return vals & set(DISABLE_KEYS), sorted(vals - set(DISABLE_KEYS))


def detect(probe: Any = None, *, refresh: bool = False, smoke: bool = True, config: Any = None) -> dict[str, Any]:
    """실행 환경 보고서(``pweh.hostenv/v1``)를 만든다.

    - ``probe``: 시스템을 읽는 객체(기본: 프로세스에 하나인 :class:`Probe`). 캐시는 probe 에 붙는다.
    - ``refresh``: 모든 캐시를 버리고 다시 감지한다.
    - ``smoke``: False 면 Windows 쪽 프로그램을 실행하지 않는다(powershell smoke·Windows 정보·usbipd 생략). 신선한 smoke 결과가
      캐시에 있으면 그것을 쓰고, 없으면 smoke 를 뺀 조건(등록 enabled + /init + wslpath)으로 interop 을 판정한다(``smoke: "skipped"``).
    - ``config``: PwehConfig 또는 설정 dict. ``hostenv.disable`` 과 ``tools.esptool_win/serial_helper`` 를 읽는다. None 이면 PWEH 설정을 찾아
      ``hostenv.disable`` 만 쓴다(실행 파일은 환경 변수·도구 디렉터리 후보만).
    돌려주는 dict 는 매번 새로 만든 사본이다(고쳐도 캐시에 영향이 없다).
    """
    probe = probe or _default_probe()
    raw, cfg_warning, explicit = _config_raw(config)
    disable, unknown_disable = _overrides(raw)
    cache = _cache_of(probe)
    with cache.lock:
        if refresh:
            cache.reset()
        now = probe.now()
        if cache.static is None or (cache.static.get("_soft_fail") and not 0 <= now - cache.static_t < NEGATIVE_TTL_S):
            cache.static = _detect_static(probe)
            cache.static_t = now
        st = copy.deepcopy(cache.static)
        st.pop("_soft_fail", None)
        report = _assemble(probe, cache, st, smoke=smoke, disable=disable, raw=raw, explicit=explicit)
    if cfg_warning:
        report["warnings"].insert(0, cfg_warning)
    if unknown_disable:
        report["warnings"].append(f"알 수 없는 hostenv.disable 값 무시: {', '.join(unknown_disable)} (가능: {', '.join(DISABLE_KEYS)})")
    return report


def _assemble(probe: Any, cache: _Cache, st: dict[str, Any], *, smoke: bool, disable: set[str], raw: Mapping[str, Any],
              explicit: bool) -> dict[str, Any]:
    kind = st.get("kind")
    ev: list[dict[str, Any]] = st["evidence"]
    base = st.get("base")
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "kind": kind,
        "python": st["python"],
        "linux": st.get("linux"),
        "macos": st.get("macos"),
        "wsl": None,
        "windows": None,
        "serial": {
            "pyserial": _pyserial_version(),
            "backend": "posix" if base in ("linux", "MACOS") else ("win32" if base == "NATIVE_WINDOWS" else None),
            "busy_check": "proc" if base == "linux" else "none",
        },
        "overridden": [f"hostenv.disable.{k}" for k in DISABLE_KEYS if k in disable],
        "warnings": [],
        "evidence": ev,
    }
    if kind != "WSL":
        report["warnings"] = _warnings(report)
        return report

    w = st["wsl"]
    now = probe.now()
    # H4 는 부를 때마다 본다: 등록(파일), /init, wslpath 실행(실패는 NEGATIVE_TTL_S 만 기억). C: 마운트는 H5(Windows 쪽 경로)일 뿐이다.
    entry, entry_state = _interop_entry(probe)
    status_adv = _first_line(probe.read_text(f"{BINFMT_DIR}/status"))
    init = probe.exists("/init")
    wslpath_ok: bool | None = _wslpath_runs(probe) if entry_state == "enabled" and init else None  # None = 보지 않음
    w["drvfs_c"] = drvfs_c = drvfs_root("C", probe)
    reason: str | None = None
    if entry_state == "absent":
        reason = "binfmt_misc 에 WSLInterop 등록이 없음 (사람이 /etc/wsl.conf [interop] enabled 를 확인하고 Windows 에서 wsl --shutdown)"
    elif entry_state == "disabled":
        reason = f"{BINFMT_DIR}/{entry} 가 enabled 가 아님 (wsl.conf [interop] enabled=false?)"
    elif not init:
        reason = "/init 이 없음 (WSL init 이 아님)"
    elif not wslpath_ok:
        reason = "wslpath 가 실행되지 않음 (wslpath -w / 실패 또는 시간 초과 — 잠시 뒤 다시 확인한다)"
    smoke_state = "not-run"
    if reason is None:
        if "interop" in disable:
            smoke_state = "disabled"
            reason = "설정 hostenv.disable 에 interop 이 있음 (좁히기 — Windows 쪽 프로그램을 실행하지 않음)"
        else:
            fresh = None
            if cache.smoke:
                t0, s0 = cache.smoke
                if 0 <= now - t0 < (SMOKE_TTL_S if s0 == "ok" else NEGATIVE_TTL_S):
                    fresh = s0
            if fresh:
                smoke_state = fresh
            elif smoke:
                smoke_state = _smoke(probe, drvfs_c)
                cache.smoke = (now, smoke_state)
            else:
                smoke_state = "skipped"
            # powershell 이 없으면(C: 마운트 없음 등) smoke 를 못 했을 뿐이다 — interop 은 끄지 않고 Windows 쪽 정보만 없다
            if smoke_state not in ("ok", "skipped", "no-powershell"):
                reason = f"powershell.exe smoke 실패({smoke_state}) — interop 이 멈췄거나 Smart App Control·보안 제품이 막았을 수 있음"
    usable = reason is None
    w["interop"] = {
        "usable": usable,
        "entry": entry,
        "entry_state": entry_state,
        "init": init,
        "wslpath": wslpath_ok,
        "smoke": smoke_state,
        "binfmt_status_advisory": status_adv,
        "reason": reason,
    }
    ev.append(_evidence("H4", "interop", {"entry": entry, "state": entry_state, "smoke": smoke_state}))
    version = w.get("version")
    if version == 1:
        kind = "WSL1"
    elif version == 2:
        kind = "WSL2_INTEROP" if usable else "WSL2_NO_INTEROP"
    else:
        kind = "WSL_UNKNOWN"
    report["kind"] = kind
    report["wsl"] = w

    # Windows 쪽 (WSL 이면 Windows 호스트가 있다). 실행은 smoke 가 실제로 통과했을 때만, 확인한 고정 경로로만 한다.
    win: dict[str, Any] = {
        "build": None, "display_version": None, "uac_enabled": None, "interop_elevated": None, "smart_app_control": None,
        "powershell": powershell_path(probe),
        "usbipd": {"present": None, "path": None, "version": None, "autobind_policies": None, "found_elsewhere": None},
        "ignored": _ignored_clients(probe),
        "serial_helper": {},
        "tools": {},
    }
    # smoke=False 면 캐시에 있는 값만 쓴다(실행하지 않음). 실패한 질의는 NEGATIVE_TTL_S 만 기억한다.
    ran_ok = usable and smoke_state == "ok"
    if ran_ok:
        cached = cache.windows_info
        info = None
        if cached and (cached[1] is not None or 0 <= now - cached[0] < NEGATIVE_TTL_S):
            info = cached[1]
        elif smoke:
            info = _windows_info(probe, drvfs_c)
            cache.windows_info = (now, info)
        if info:
            win.update(info)
    upath = _usbipd_fixed(probe)
    if upath:
        win["usbipd"].update(present=True, path=upath)
        if ran_ok:
            cu = cache.usbipd
            ttl = TOOLS_TTL_S if cu and cu[1].get("version") is not None else NEGATIVE_TTL_S
            if cu and cu[1].get("path") == upath and 0 <= now - cu[0] < ttl:
                win["usbipd"].update({k: v for k, v in cu[1].items() if k != "path"})
            elif smoke:
                info_u = _usbipd_info(probe, upath)
                cache.usbipd = (now, {**info_u, "path": upath})
                win["usbipd"].update(info_u)
    else:
        if drvfs_c:
            win["usbipd"]["present"] = False  # C: 를 볼 수 있는데 표준 위치에 없다
        win["usbipd"]["found_elsewhere"] = _usbipd_elsewhere(probe)  # $PATH 에서 찾은 것 — 표시만, 실행하지 않는다
    ev.append(_evidence("H7", "usbipd", win["usbipd"]["path"]))
    configured = helper_configured = None
    if explicit:
        tools = raw.get("tools") if isinstance(raw.get("tools"), Mapping) else {}
        configured = str(tools.get("esptool_win") or "").strip() or None
        helper_configured = str(tools.get("serial_helper") or "").strip() or None
    esp = resolve_esptool_win(configured, probe.env("PWEH_ESPTOOL_WIN"), _tools_dir(probe), probe)
    if "windows_tools" in disable:
        esp["disabled"] = True
    win["tools"]["esptool_win"] = esp
    win["serial_helper"] = resolve_serial_helper(helper_configured, probe.env("PWEH_SERIAL_HELPER"), _tools_dir(probe), probe)
    if disable & {"interop", "serial_helper", "windows_tools"}:
        win["serial_helper"]["disabled"] = True
    report["windows"] = win
    report["warnings"] = _warnings(report)
    return report


def _pyserial_version() -> str | None:
    try:
        import serial  # type: ignore[import-untyped]
    except Exception:  # noqa: BLE001
        return None
    v = getattr(serial, "__version__", None) or getattr(serial, "VERSION", None)
    return str(v) if v else None


# ---------------------------------------------------------------------------
# 경고
# ---------------------------------------------------------------------------


def _warnings(report: Mapping[str, Any]) -> list[str]:
    kind = report.get("kind")
    out: list[str] = []
    lin = report.get("linux") or {}
    wsl = report.get("wsl") or {}
    win = report.get("windows") or {}
    if kind in UNSUPPORTED_KINDS:
        out.append(unsupported_platform(str((report.get("python") or {}).get("sys_platform") or "")) or "지원하지 않는 플랫폼")
    if kind is None:
        out.append(f"알 수 없는 플랫폼({(report.get('python') or {}).get('sys_platform')}) — 지원 대상이 아니다")
    if kind == "CONTAINER":
        out.append("컨테이너 안이다: 통과된 /dev 노드만 쓸 수 있다(최선 노력). WSL 커널이어도 WSL interop·usbipd 경로로 보지 않는다")
    if kind == "WSL_UNKNOWN":
        out.append("WSL 버전을 정하지 못했다(사용자 커널 + wslinfo 실패) — usbipd 경로는 WSL2 에서만 된다")
    if kind in WSL_KINDS:
        it = wsl.get("interop") or {}
        if not it.get("usable") and kind != "WSL2_NO_INTEROP":
            out.append(f"interop 을 쓸 수 없음: {it.get('reason')}")
        if kind == "WSL2_NO_INTEROP":
            out.append(f"interop 을 쓸 수 없어 Windows 쪽 경로(방법 A 등)가 없다 — USB 장치는 usbipd attach 로만 쓴다 ({it.get('reason')})")
        mode = wsl.get("networking_mode")
        if mode == "bridged":
            out.append("networking_mode=bridged: WSL 의 0.0.0.0 리스너는 LAN 에 열린다(PWEH 는 리스너를 만들지 않음). "
                       "usbipd 대체 경로는 attach 마다 --host-ip <Windows LAN IP> 가 필요하다")
        elif mode == "consomme":
            out.append("networking_mode=consomme: NAT 가 실패하면 WSL 이 조용히 바꾸는 모드다. usbipd ≤5.3.0 attach 는 --host-ip 127.0.0.1 이 필요하다")
        elif mode is None and kind != "WSL1":
            out.append("networking_mode 를 모른다(wslinfo 실패) — usbipd 는 nat 로 가정한다")
        if win.get("uac_enabled") is False or win.get("interop_elevated") is True:
            out.append("interop 으로 띄운 Windows 프로세스가 관리자 권한(High IL)으로 돈다"
                       + (" (uac_enabled=false)" if win.get("uac_enabled") is False else "")
                       + " — PWEH 가 실행하는 Windows 프로그램은 허용 목록으로 묶는다. UAC 설정은 사용자 결정이다")
        if it.get("usable") and it.get("smoke") == "no-powershell":
            out.append("powershell.exe 를 찾지 못함 — C: 드라이브 drvfs 마운트가 없거나(/etc/wsl.conf [automount]) Windows PowerShell 이 없다. "
                       "interop 은 등록·/init·wslpath 로만 판정했고 Windows 쪽 정보(UAC·빌드)·COM 목록·usbipd 확인은 없다")
        elsewhere = (win.get("usbipd") or {}).get("found_elsewhere")
        if elsewhere:
            out.append(f"usbipd.exe 가 표준 위치(C:\\Program Files\\usbipd-win)가 아닌 $PATH 에서 보인다: {elsewhere} — 실행하지 않았다(확인 안 함)")
        if win.get("smart_app_control") in ("on", "evaluation"):
            out.append(f"Smart App Control={win.get('smart_app_control')}: 서명 없는 실행 파일(이후 단계의 직렬 헬퍼 등)이 막힐 수 있다")
        n = (win.get("usbipd") or {}).get("autobind_policies")
        if n:
            out.append(f"usbipd AutoBind 정책 {n}개: 원격 요청에도 장치를 자동 bind 하고 공유를 영구 저장한다(LAN 의 다른 PC 가 가져갈 수 있음). "
                       "사람이 Windows 관리자 터미널에서 지운다 — PWEH 는 AutoBind 를 쓰지 않는다")
    if lin:
        if lin.get("root_equivalent_groups"):
            out.append(f"root 와 같은 그룹에 속해 있다: {', '.join(lin['root_equivalent_groups'])} (이 계정의 프로그램은 root 권한을 얻을 수 있다)")
        b = lin.get("brltty") or {}
        if b.get("installed") and b.get("ch340_rule") and not b.get("masked"):
            out.append("brltty 가 CH340(1a86:7523)을 점자 장치로 잡는다 — 리눅스 쪽에 붙은 CH340 의 /dev/ttyUSB0 이 사라질 수 있다 "
                       "(사람이 [root] brltty 를 지우거나 85-brltty.rules 를 무력화)")
        if kind == "NATIVE_LINUX" and lin.get("ssh_session"):
            out.append("SSH 세션이다: 배선·전원 같은 물리 작업은 이 원격 기계에서 한다")
    mac = report.get("macos") or {}
    if mac.get("rosetta"):
        out.append("Rosetta 로 x86_64 Python 이 돈다 — 도구는 arm64 판이 아닐 수 있다")
    return out


# ---------------------------------------------------------------------------
# 공개 도우미
# ---------------------------------------------------------------------------


def disabled_keys(config: Any = None) -> set[str]:
    """설정 ``hostenv.disable`` 에서 알아본 값 ({interop, serial_helper, windows_tools} 의 부분집합). config=None 이면 PWEH 설정을 찾는다.

    좁히기만 하는 값이다: 서버·doctor 는 이 값이 있으면 그 경로를 쓰지 않는다(예: windows_tools → Windows esptool.exe 를 실행하지 않음).
    설정을 읽지 못하면 빈 집합이다.
    """
    raw, _warning, _explicit = _config_raw(config)
    return _overrides(raw)[0]


def is_wsl(report: Mapping[str, Any] | None = None) -> bool:
    """WSL(1·2·버전 모름) 인가. 컨테이너는 WSL 커널이어도 아니다. report 가 없으면 smoke 없이 감지한다."""
    rep = report if report is not None else detect(smoke=False)
    return rep.get("kind") in WSL_KINDS


def interop_usable(report: Mapping[str, Any] | None = None) -> bool:
    """WSL interop 으로 Windows 프로그램을 실행할 수 있는가 (``wsl.interop.usable`` — WSL1 도 될 수 있다)."""
    rep = report if report is not None else detect()
    if rep.get("kind") not in WSL_KINDS:
        return False
    return bool(((rep.get("wsl") or {}).get("interop") or {}).get("usable"))


def interop_reason(report: Mapping[str, Any]) -> str | None:
    """interop 을 쓸 수 없는 이유 (쓸 수 있으면 None)."""
    if report.get("kind") not in WSL_KINDS:
        return "WSL 이 아님" if report.get("kind") != "CONTAINER" else "컨테이너 안에서는 WSL interop 을 쓰지 않음"
    return ((report.get("wsl") or {}).get("interop") or {}).get("reason")


def unsupported_platform(sys_platform: str | None = None, *, launcher: str = "pweh-<서버>-mcp") -> str | None:
    """서버를 실행하지 않는 플랫폼(win32·cygwin·msys)이면 안내 문구, 아니면 None (§12 — 시작 거부는 mcpkit.create_server 가 이 문구로 한다).

    이유(G9): 이식하지 않은 채 돌면 PID 생존 확인(``os.kill(pid, 0)`` → Windows 에서는 콘솔 Ctrl-C 이벤트)이 모든 pid 를
    살아 있다고 보거나 OSError 를 내고, ``killpg``·``SIGKILL`` 은 AttributeError, ``/proc`` 없는 점유 검사는 fail-open 이다.
    """
    p = sys.platform if sys_platform is None else str(sys_platform)
    for prefix, label, extra in (("win32", "네이티브 Windows", ""), ("cygwin", "Cygwin", ""),
                                 ("msys", "MSYS", " — pyserial list_ports 가 동작하지 않음")):
        if p.startswith(prefix):
            return (f"{label}(sys.platform={p!r})에서는 PWEH MCP 서버를 실행하지 않습니다(미지원{extra}). 서버는 WSL2 안에서 실행하세요. "
                    f"Windows 의 MCP 클라이언트는 `wsl.exe -d <배포판> -e <저장소>/.venv/bin/{launcher}` 형식으로 WSL 안의 서버를 띄웁니다"
                    "(`-u root` 는 넣지 마세요). 장치는 Windows 에 둔 채 쓴다(방법 A 등). "
                    "이유: PID 생존 확인(os.kill(pid, 0))·프로세스 그룹 종료(killpg)·/proc 기반 포트 점유 검사가 Windows 에서는 안전하게 동작하지 않습니다.")
    return None


def is_ghost_port(p: Any) -> bool:
    """가짜 직렬 포트인가 — esp 의 규칙(``hwid`` 가 'n/a' 또는 없음이고 vid 가 없음). WSL 의 /dev/ttyS0-7 같은 포트."""
    get = p.get if isinstance(p, Mapping) else (lambda k, d=None: getattr(p, k, d))
    return get("hwid") in ("n/a", None) and not get("vid")


def split_ghost_ports(ports: Iterable[Any]) -> tuple[list[Any], int]:
    """(보이는 포트, 숨긴 가짜 포트 수)."""
    visible, hidden = [], 0
    for p in ports:
        if is_ghost_port(p):
            hidden += 1
        else:
            visible.append(p)
    return visible, hidden


_COM_IN_NAME_RE = re.compile(r"\((COM\d+)\)")
_VIDPID_RE = re.compile(r"VID_([0-9A-Fa-f]{4})[&+]PID_([0-9A-Fa-f]{4})")


def windows_com_ports(report: Mapping[str, Any] | None = None, probe: Any = None) -> dict[str, Any]:
    """Windows 의 COM 포트와 드라이버 Service (doctor 전용 휘발 목록 — 캐시하지 않고 보고서에도 넣지 않는다).

    interop 을 쓸 수 있을 때만 고정 CIM 스크립트(PS_LIST_COM)를 돌린다. 반환: {available, ports[{port, name, service, status, vid, pid}], note}.
    """
    probe = probe or _default_probe()
    rep = report if report is not None else detect(probe)
    if not interop_usable(rep):
        return {"available": False, "ports": [], "note": interop_reason(rep)}
    ps = powershell_path(probe)
    if not ps:
        return {"available": False, "ports": [], "note": "powershell.exe 를 찾지 못함"}
    r = _run(probe, [ps, *_PS_FLAGS, PS_LIST_COM], PS_LIST_TIMEOUT_S, cwd=drvfs_root("C", probe))
    if not r or r[0] != 0:
        return {"available": False, "ports": [], "note": "powershell.exe CIM 질의 실패" + (f" (rc={r[0]})" if r else "")}
    try:
        data = json.loads((r[1] or "").strip().lstrip("\ufeff") or "[]")
    except ValueError:
        return {"available": False, "ports": [], "note": "PowerShell 출력 해석 실패"}
    if isinstance(data, dict):
        data = [data]
    ports = []
    for d in data if isinstance(data, list) else []:
        if not isinstance(d, dict):
            continue
        m = _COM_IN_NAME_RE.search(str(d.get("Name") or ""))
        if not m:
            continue
        mv = _VIDPID_RE.search(str(d.get("PNPDeviceID") or ""))
        ports.append({"port": m.group(1).upper(), "name": d.get("Name"), "service": d.get("Service"), "status": d.get("Status"),
                      "vid": f"0x{mv.group(1).lower()}" if mv else None, "pid": f"0x{mv.group(2).lower()}" if mv else None})
    ports.sort(key=lambda e: int(e["port"][3:]))
    return {"available": True, "ports": ports, "note": None}


def wildcard_listeners(probe: Any = None) -> list[dict[str, Any]] | None:
    """0.0.0.0·:: 에서 듣는 TCP 포트 (/proc/net/tcp·tcp6 읽기 — 스캔이 아니다). 읽을 수 없으면 None. doctor 전용."""
    probe = probe or _default_probe()
    found: set[tuple[str, int]] = set()
    seen = False
    for proto, path, zero in (("tcp", "/proc/net/tcp", "0" * 8), ("tcp6", "/proc/net/tcp6", "0" * 32)):
        text = probe.read_text(path)
        if text is None:
            continue
        seen = True
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4 or parts[3] != "0A":
                continue
            addr, _, port_hex = parts[1].partition(":")
            if addr == zero:
                try:
                    found.add((proto, int(port_hex, 16)))
                except ValueError:
                    continue
    if not seen:
        return None
    return [{"proto": p, "port": n} for p, n in sorted(found, key=lambda x: (x[1], x[0]))]


# ---------------------------------------------------------------------------
# 추천 경로 (§9 표의 행) — now 는 지금 되는 경로, target 은 그 단계에서 생기는 경로
# ---------------------------------------------------------------------------

_DEVICE_LABELS = {
    "serial": "직렬 (USB-UART 콘솔·JTAGulator·Flipper)",
    "esptool": "ESP ROM (esptool)",
    "openocd": "JTAG/SWD (OpenOCD)",
    "sigrok": "로직 애널라이저 (sigrok)",
    "sdr": "SDR (수신 전용)",
    "video": "영상 캡처",
    "block": "블록 장치 (SD 리더)",
    "all": "모든 장치",
}


def usbipd_attach(mode: str | None) -> dict[str, Any]:
    """usbipd ≤5.3.0 의 attach 안내 (§10 표, ``wslinfo --networking-mode`` 값 기준). {possible, command, note}."""
    cmd = "usbipd attach --wsl --busid <BUSID>"
    if mode == "nat":
        return {"possible": True, "command": cmd, "note": "기본 게이트웨이로 자동"}
    if mode in ("mirrored", "virtioproxy"):
        return {"possible": True, "command": cmd, "note": "루프백으로 자동"}
    if mode == "consomme":
        return {"possible": True, "command": cmd + " --host-ip 127.0.0.1",
                "note": "usbipd 5.3.0 은 --host-ip 없이는 'not supported' 로 거부한다. NAT 가 실패하면 WSL 이 조용히 consomme 로 떨어진다"}
    if mode == "bridged":
        return {"possible": True, "command": cmd + " --host-ip <Windows LAN IP>",
                "note": "DHCP 라 IP 가 바뀔 수 있다. bridged 는 WSL 2.4.5 부터 deprecated"}
    if mode == "none":
        return {"possible": False, "command": None, "note": "네트워크가 없어 usbipd 를 쓸 수 없다"}
    if mode == "wsl1":
        return {"possible": False, "command": None, "note": "WSL1 은 usbipd 를 지원하지 않는다"}
    what = "모른다(wslinfo 실패)" if mode is None else f"알 수 없는 값({mode})"
    return {"possible": True, "command": cmd, "note": f"네트워킹 모드를 {what} — usbipd 는 nat 로 가정하고 경고한다"}


def _usbipd_steps(mode: str | None, present: bool | None, libusb: bool = False) -> list[str]:
    a = usbipd_attach(mode)
    steps = []
    if present is not True:
        steps.append("usbipd-win 설치 [관리자] (선택 — 이 경로에만 필요)")
    steps.append("usbipd bind --busid <BUSID> [관리자] — 세션 동안만 bind 하고 끝나면 usbipd unbind (bind 된 장치는 TCP 3240 으로 LAN 에 인증 없이 노출된다). "
                 "AutoBind 정책은 쓰지 않는다")
    if libusb:
        steps.append("udev 규칙 설치 [root] — attach 전에")
    if a["possible"]:
        steps.append(f"{a['command']} (일반 사용자 — {a['note']})")
    else:
        steps.append(f"attach 불가: {a['note']}")
    return steps


def _row(device: str, ref: str | None, now: dict[str, Any], target: dict[str, Any] | None = None,
         alternatives: list[str] | None = None, notes: list[str] | None = None) -> dict[str, Any]:
    return {"device": device, "label": _DEVICE_LABELS[device], "ref": ref, "now": now, "target": target,
            "alternatives": alternatives or [], "notes": notes or []}


def _now(route: str | None, status: str, available: bool | None = None, human_steps: list[str] | None = None) -> dict[str, Any]:
    return {"route": route, "status": status, "available": available, "human_steps": human_steps or []}


def _block_row() -> dict[str, Any]:
    return _row("block", "R18", _now("사람이 자기 도구로 이미징 → case_import_file + sha256", "현행", True,
                                     ["SD 카드 이미징(쓰기 방지 장치) — 사람"]),
                notes=["에이전트 백엔드는 없다. /dev/sd*·PhysicalDrive·wsl --mount·usbipd usb-storage 는 거부한다"])


def recommend_routes(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    """장치 종류별 추천 경로 (설계 §9 표의 행). 각 행: {device, label, ref, now{route, status, available, human_steps},
    target{route, phase}|None, alternatives, notes}. ``now`` 는 지금 실제로 되는 경로만 적는다(헬퍼 같은 다음 단계 경로는 target)."""
    kind = report.get("kind")
    lin = report.get("linux") or {}
    wsl = report.get("wsl") or {}
    win = report.get("windows") or {}
    if kind in UNSUPPORTED_KINDS:
        msg = unsupported_platform(str((report.get("python") or {}).get("sys_platform") or "")) or "미지원"
        return [_row("all", "R16" if kind == "NATIVE_WINDOWS" else "R17", _now(None, "거부", False, ["MCP 클라이언트를 WSL 의 서버로 설정 (사람)"]),
                     notes=[msg]), _block_row()]
    if kind is None:
        return [_row("all", None, _now(None, "없음", False), notes=["알 수 없는 플랫폼 — 지원 대상이 아니다"]), _block_row()]
    if kind == "CONTAINER":
        return [_row("all", "R17", _now("통과된 /dev 노드만 (최선 노력)", "최선 노력", None, ["컨테이너에 장치 노드를 넘기는 설정 (사람)"]),
                     notes=["WSL 커널이어도 interop·usbipd 경로로 보지 않는다. 컨테이너는 portlock 을 공유하지 않는다(P1)"]), _block_row()]
    if kind == "MACOS":
        p5 = "macOS 는 요청이 있을 때 P5 에서 최선 노력으로 지원한다(실기 시험 없음)"
        return [
            _row("serial", "R13", _now(None, "없음 (P5 예정)"), {"route": "/dev/cu.* (tty.* 거부), posix-tty", "phase": "P5"},
                 notes=[p5, "첫 open 에 DTR/RTS 가 올라간다(리셋 배선 위험)"]),
            _row("esptool", "R13", _now(None, "없음 (P5 예정)"), {"route": "venv esptool --port /dev/cu.*", "phase": "P5"}, notes=[p5]),
            _row("openocd", "R14", _now(None, "없음 (P5 예정)"), {"route": "xPack darwin openocd", "phase": "P5"}, notes=[p5]),
            _row("sigrok", "R14", _now(None, "없음 (P5 예정)"), {"route": "Homebrew sigrok-cli (있으면)", "phase": "P5"}, notes=[p5]),
            _row("sdr", "R14", _now(None, "없음 (서버 없음)"), {"route": "conda/Homebrew rtl-sdr", "phase": "P5"}),
            _row("video", "R15", _now(None, "없음 (서버 없음)"), {"route": "ffmpeg -f avfoundation (TCC 카메라 권한)", "phase": "P5"}),
            _block_row(),
        ]
    if kind == "NATIVE_LINUX":
        steps = []
        groups = set(lin.get("groups") or [])
        if not groups & {"dialout", "uucp"}:
            steps.append("dialout 그룹 추가 [root 1회] 후 다시 로그인")
        b = lin.get("brltty") or {}
        if b.get("installed") and b.get("ch340_rule") and not b.get("masked"):
            steps.append("brltty 처리 [root] — CH340(1a86:7523)을 점자 장치로 잡는다 (brltty 를 지우거나 85-brltty.rules 무력화)")
        dtr = "열 때마다 DTR/RTS 펄스가 생긴다(리셋 배선 보드 주의) — TIOCEXCL·portlock 은 P1"
        return [
            _row("serial", "R10", _now("/dev/serial/by-id/* (권장)·/dev/ttyUSB*·/dev/ttyACM*", "현행", None, steps), notes=[dtr]),
            _row("esptool", "R10", _now("Linux esptool --port /dev/ttyACM*·/dev/ttyUSB*", "현행", None, list(steps))),
            _row("openocd", "R11", _now("Linux openocd (xPack) + udev 규칙 (plugdev 0660, 쓰는 VID:PID 만)", "현행", None,
                                        ["udev 규칙 설치 [root 1회]"])),
            _row("sigrok", "R11", _now("Linux sigrok-cli + udev 규칙 (61-libsigrok-plugdev.rules)", "현행", None, ["udev 규칙 설치 [root 1회]"])),
            _row("sdr", "R11", _now(None, "없음 (서버 없음)"), {"route": "Linux rtl_*·hackrf (dvb_usb_rtl28xxu blacklist [root])", "phase": "P4"}),
            _row("video", "R12", _now(None, "없음 (서버 없음)"), {"route": "ffmpeg -f v4l2 (video 그룹 [root 1회])", "phase": "P4"}),
            _block_row(),
        ]

    interop = bool(((wsl.get("interop") or {}).get("usable")))
    mode = wsl.get("networking_mode")
    upresent = (win.get("usbipd") or {}).get("present")
    attach = usbipd_attach(mode)
    esp = (win.get("tools") or {}).get("esptool_win") or {}
    esp_ok = bool(esp.get("present")) and not esp.get("disabled")
    helper = win.get("serial_helper") or {}
    helper_route = "Windows COM 을 pweh-serial-helper.exe 가 연다 (win-helper, usbipd 불필요)"
    helper_enabled = interop and not helper.get("disabled")
    helper_now = _now(helper_route, "현행 · 실행 전 pin 검증" if helper.get("present") else "현행 · 설치 필요",
                      None if helper.get("present") else False,
                      [] if helper.get("present") else ["scripts/install.sh --only winserial"])

    if kind == "WSL1":
        esp_now = (_now("Windows esptool.exe --port COMn (방법 A)", "현행 (최선 노력)", esp_ok,
                        [] if esp_ok else ["scripts/install.sh --only esptool"])
                   if interop and not esp.get("disabled") else
                   _now("Linux esptool --port /dev/ttyS<n> (= COM<n>)", "최선 노력", None))
        no_usb = "WSL1 은 USB 장치·usbipd 를 쓸 수 없다"
        return [
            _row("serial", "R8", _now("COM1–COM191 → /dev/ttyS<n> 자동 해석 (posix-tty)", "최선 노력", None),
                 alternatives=[f"COM192–COM4096 → {helper_route}"] if helper_enabled else [],
                 notes=["COM1–191의 tty가 없어도 helper로 자동 전환하지 않는다", no_usb,
                        "COM192 이상은 설치된 helper와 interop이 필요하다"]),
            _row("esptool", "R8", esp_now, alternatives=["Linux esptool --port /dev/ttyS<n>"] if interop else []),
            _row("openocd", "R9", _now(None, "없음"), {"route": "openocd.exe (win-exe)", "phase": "P3"}, notes=[no_usb]),
            _row("sigrok", "R9", _now(None, "없음"), {"route": "sigrok-cli.exe (win-exe)", "phase": "P3"}, notes=[no_usb]),
            _row("sdr", "R9", _now(None, "없음 (서버 없음)"), {"route": "rtl_*.exe (win-exe)", "phase": "P4"}, notes=[no_usb]),
            _row("video", "R9", _now(None, "없음 (서버 없음)"), {"route": "ffmpeg.exe -f dshow (win-exe)", "phase": "P4"}, notes=[no_usb]),
            _block_row(),
        ]

    # WSL2_INTEROP / WSL2_NO_INTEROP / WSL_UNKNOWN
    unknown_note = ["WSL 버전을 정하지 못했다 — usbipd 경로는 WSL2 에서만 된다"] if kind == "WSL_UNKNOWN" else []
    ser_steps = _usbipd_steps(mode, upresent)
    lib_steps = _usbipd_steps(mode, upresent, libusb=True)
    avail = (upresent if attach["possible"] else False)
    usb_status = "현행 · 사람 단계"
    reenable = "interop 다시 켜기 (/etc/wsl.conf [interop] enabled=true 후 Windows 에서 wsl --shutdown — 사람) → Windows 쪽 경로"
    if interop:
        if esp_ok:
            esp_now = _now("Windows esptool.exe --port COMn (방법 A, usbipd 불필요)", "현행", True, ["자동 리셋이 안 되면 BOOT+RESET (사람)"])
        elif esp.get("disabled"):
            esp_now = _now("usbipd attach → Linux esptool --port /dev/ttyACM*", usb_status, avail, ser_steps)
        else:
            esp_now = _now("Windows esptool.exe --port COMn (방법 A, usbipd 불필요)", "현행 · 설치 필요", False,
                           ["scripts/install.sh --only esptool (Windows esptool.exe)", "자동 리셋이 안 되면 BOOT+RESET (사람)"])
        rows = [
            _row("serial", "R1", helper_now if helper_enabled else
                 _now("usbipd attach → /dev/ttyACM*·/dev/ttyUSB* (posix-tty)", usb_status, avail, ser_steps),
                 alternatives=["usbipd attach → /dev/ttyACM*·/dev/ttyUSB* (사람)"] if helper_enabled else [],
                 notes=["helper 파일 존재만으로 신뢰를 보장하지 않는다. 실행 전 SHA256·프로토콜을 확인한다",
                        "PowerShell 직렬 relay 대체 경로는 구현하지 않았다",
                        "attach 하는 동안 Windows 에서는 그 COM 포트가 사라진다", *unknown_note]),
            _row("esptool", "R2", esp_now, alternatives=["usbipd attach → Linux esptool --port /dev/ttyACM*"],
                 notes=(["설정 hostenv.disable 로 Windows 도구를 껐다"] if esp.get("disabled") else []) + unknown_note),
            _row("openocd", "R3", _now("usbipd attach → Linux openocd (xPack) + udev 규칙", "현행 유일 · 사람 단계", avail, lib_steps),
                 {"route": "openocd.exe + tcl port pipe (win-exe)", "phase": "P3"}, notes=list(unknown_note)),
            _row("sigrok", "R4", _now("usbipd attach (--auto-attach) → Linux sigrok-cli", "현행 유일 · 사람 단계", avail, lib_steps),
                 {"route": "sigrok-cli.exe 포터블 (win-exe)", "phase": "P3"},
                 notes=["fx2lafw 는 펌웨어를 올린 뒤 재열거한다 — attach 를 다시 해야 한다", *unknown_note]),
            _row("sdr", "R5", _now(None, "없음 (서버 없음)"), {"route": "rtl_*.exe·hackrf (win-exe, 파일 출력)", "phase": "P4"}),
            _row("video", "R6", _now(None, "없음 (서버 없음)"), {"route": "ffmpeg.exe -f dshow (win-exe)", "phase": "P4"}),
            _block_row(),
        ]
        return rows
    rows = [
        _row("serial", "R7", _now("usbipd attach → /dev/ttyACM*·/dev/ttyUSB* (posix-tty)", usb_status, avail, ser_steps),
             alternatives=[reenable], notes=list(unknown_note)),
        _row("esptool", "R7", _now("usbipd attach → Linux esptool --port /dev/ttyACM*", usb_status, avail, ser_steps),
             alternatives=["interop 을 다시 켜면 방법 A (Windows esptool.exe --port COMn)"], notes=list(unknown_note)),
        _row("openocd", "R7", _now("usbipd attach → Linux openocd (xPack) + udev 규칙", usb_status, avail, lib_steps), notes=list(unknown_note)),
        _row("sigrok", "R7", _now("usbipd attach (--auto-attach) → Linux sigrok-cli", usb_status, avail, lib_steps), notes=list(unknown_note)),
        _row("sdr", "R7", _now(None, "없음 (서버 없음)"), {"route": "usbipd → Linux rtl_*·hackrf", "phase": "P4"}),
        _row("video", "R7", _now(None, "없음 (서버 없음)"), {"route": "usbipd → uvcvideo + v4l2", "phase": "P4"}),
        _block_row(),
    ]
    return rows


__all__ = [
    "DISABLE_KEYS",
    "FIXED_PS_SCRIPTS",
    "KINDS",
    "NETWORKING_MODES",
    "Probe",
    "SCHEMA",
    "UNSUPPORTED_KINDS",
    "WSL_KINDS",
    "check_argv",
    "detect",
    "disabled_keys",
    "drvfs_root",
    "interop_reason",
    "interop_usable",
    "is_ghost_port",
    "is_wsl",
    "powershell_path",
    "recommend_routes",
    "resolve_esptool_win",
    "split_ghost_ports",
    "trusted_windows_exes",
    "unsupported_platform",
    "usbipd_attach",
    "wildcard_listeners",
    "windows_com_ports",
    "windows_path_to_wsl",
]
