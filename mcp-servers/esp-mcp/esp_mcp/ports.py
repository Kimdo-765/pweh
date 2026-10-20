"""포트 검증, WSL interop 감지, 경로 변환(wslpath), 시리얼 포트 목록.

백엔드는 포트 형식으로 정한다.

- ``COM<n>`` (대소문자 무관, n=1~256) → **windows** 백엔드: WSL interop 으로 Windows 용 esptool.exe 를 실행한다(방법 A).
  usbipd 가 필요 없고, 장치는 Windows 에 붙은 그대로다. 출력 파일 경로는 ``wslpath -w`` 로 바꿔 넘긴다.
- ``/dev/ttyACM<n>``, ``/dev/ttyUSB<n>``, ``/dev/ttyS<n>``, ``/dev/serial/by-id/<이름>`` → **linux** 백엔드
  (usbipd 로 WSL 에 attach 한 장치 또는 네이티브 리눅스). 장치가 있어야 하고, 심볼릭 링크의 실제 대상도 /dev 아래여야 한다.
- 그 밖(rfc2217://, socket://, 임의 경로)은 거부한다.

이 모듈은 포트를 **열지 않는다**. 목록은 Windows 쪽 PnP 정보(powershell.exe, 읽기 전용 CIM 질의)와 pyserial
``list_ports``(sysfs 읽기)로만 만든다.

WSL·interop 판정과 Windows 쪽 경로(powershell.exe 위치, C: 드라이브 마운트 지점)는 코어 ``pweh.hostenv`` 의 규칙을 쓴다
(컨테이너 제외, WSL1/2, ``/mnt/c`` 를 가정하지 않음). 이 모듈의 함수 이름은 그대로 두며, 서로를 모듈 전역으로 늦게 불러
시험이 ``monkeypatch.setattr(ports, "...")`` 로 바꿔 끼울 수 있다.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from pweh import hostenv
from pweh.errors import ToolMissing, ValidationFailed

WIN_COM_RE = re.compile(r"^COM([1-9][0-9]{0,2})$", re.I)
LINUX_TTY_RE = re.compile(r"^/dev/tty(?:ACM|USB|S)[0-9]{1,3}$")
LINUX_BYID_RE = re.compile(r"^/dev/serial/by-id/[A-Za-z0-9._:+@-]{1,200}$")
UNC_OK_RE = re.compile(r"^(?:\\\\wsl(?:\.localhost|\$)\\[^\\/:*?\"<>|\r\n]+\\|[A-Za-z]:\\)")

#: 알려진 USB VID:PID (소문자 4자리 16진수)
KNOWN_USB_IDS: dict[str, tuple[str, str]] = {
    "303a:1001": ("esp-usb-serial-jtag", "ESP 내장 USB-Serial/JTAG (ESP32-S3/C3/C6/H2 네이티브 USB — esptool 은 USB-JTAG 리셋 사용)"),
    # ROM USB-OTG 다운로드 모드: 칩이 이미 ROM 다운로드 모드다(before='no-reset', 끝나면 사람이 RESET)
    "303a:0009": ("esp-usb-otg-rom", "ESP32-S3 ROM USB-OTG 다운로드 모드 (TinyUSB CDC)"),
    "303a:0002": ("esp-usb-otg-rom", "ESP32-S2 ROM USB-OTG 다운로드 모드 (TinyUSB CDC)"),
    "10c4:ea60": ("usb-uart-bridge", "Silicon Labs CP210x USB-UART 브리지"),
    "1a86:7523": ("usb-uart-bridge", "WCH CH340 USB-UART 브리지"),
    "1a86:55d3": ("usb-uart-bridge", "WCH CH343 USB-UART 브리지"),
    "1a86:55d4": ("usb-uart-bridge", "WCH CH9102 USB-UART 브리지"),
    "0403:6001": ("usb-uart-bridge", "FTDI FT232R USB-UART"),
    "0403:6010": ("usb-uart-bridge", "FTDI FT2232 (2채널 — 한 채널이 JTAG 일 수 있음)"),
    "0403:6014": ("usb-uart-bridge", "FTDI FT232H"),
    "0403:6015": ("usb-uart-bridge", "FTDI FT-X (FT231X/FT230X)"),
}


@dataclass(frozen=True)
class PortSpec:
    port: str  # esptool 에 넘길 값 (COM3 / /dev/ttyACM0 / /dev/serial/by-id/…)
    backend: str  # windows | linux
    lock_key: str  # 같은 물리 포트를 가리키는 키 (리눅스는 realpath)
    resolved: str | None = None  # 리눅스: 실제 장치 경로

    def to_dict(self) -> dict[str, Any]:
        out = {"port": self.port, "backend": self.backend}
        if self.resolved and self.resolved != self.port:
            out["resolved"] = self.resolved
        return out


# 테스트에서 바꿔 끼우는 훅 (실제 장치 없이 검증 경로를 시험하기 위함)
path_exists: Callable[[str], bool] = os.path.exists
realpath: Callable[[str], str] = os.path.realpath


def validate_port(port: Any) -> PortSpec:
    p = str(port or "").strip()
    if not p:
        raise ValidationFailed("port 가 필요합니다.", hint="esp_list_ports 로 확인: Windows 방법 A 는 'COM3', WSL 에 attach 한 장치는 '/dev/ttyACM0'")
    m = WIN_COM_RE.match(p)
    if m:
        n = int(m.group(1))
        if not 1 <= n <= 256:
            raise ValidationFailed(f"COM 포트 번호 범위 밖: {p}", hint="COM1 ~ COM256")
        norm = f"COM{n}"
        return PortSpec(port=norm, backend="windows", lock_key=f"win:{norm}")
    if LINUX_TTY_RE.match(p) or LINUX_BYID_RE.match(p):
        if not path_exists(p):
            raise ValidationFailed(
                f"시리얼 장치가 없습니다: {p}",
                hint="WSL2 이면 Windows 에서 usbipd attach --wsl 후 다시 확인하거나, 방법 A 로 Windows COM 포트(port='COM3')를 쓴다. esp_list_ports 로 확인.",
            )
        rp = realpath(p)
        if not rp.startswith("/dev/") or ".." in rp:
            raise ValidationFailed(f"장치 링크가 /dev 밖을 가리킵니다: {p} → {rp}")
        return PortSpec(port=p, backend="linux", lock_key=f"linux:{rp}", resolved=rp)
    if "://" in p:
        raise ValidationFailed(f"네트워크/URL 포트는 지원하지 않습니다: {p}", hint="rfc2217:// · socket:// 는 거부한다. COMn 또는 /dev/tty* 를 쓴다.")
    raise ValidationFailed(
        f"지원하지 않는 포트 형식: {p!r}",
        hint="Windows 방법 A: 'COM3' / 리눅스: '/dev/ttyACM0', '/dev/ttyUSB0', '/dev/ttyS0', '/dev/serial/by-id/…'",
    )


# ---------------------------------------------------------------------------
# WSL / interop
# ---------------------------------------------------------------------------


def is_wsl() -> bool:
    """WSL(1·2) 안인가 — ``pweh.hostenv`` 규칙(컨테이너는 WSL 커널이어도 아님, ``WSL_DISTRO_NAME`` 은 판정에 쓰지 않음)."""
    return hostenv.is_wsl(hostenv.detect(smoke=False))


def interop_status() -> dict[str, Any]:
    """{wsl, interop, reason}. ``pweh.hostenv`` 의 interop 판정(H4)에서 smoke 만 뺀 규칙 — install.sh 의 ``wsl_interop`` 과 같다.

    WSLInterop 또는 WSLInterop-late 첫 줄이 enabled, ``/init`` 있음, ``wslpath`` 실행됨(설정 ``hostenv.disable: [interop]`` 이면 거짓).
    Windows 프로그램을 띄워 보지는 않는다(실제 실행 가능 여부는 esptool.exe 버전 확인이 본다).
    """
    wsl = is_wsl()
    if not wsl:
        return {"wsl": False, "interop": False, "reason": "WSL 이 아님 (Windows esptool.exe 를 실행할 수 없음)"}
    rep = hostenv.detect(smoke=False)
    if hostenv.interop_usable(rep):
        return {"wsl": True, "interop": True, "reason": None}
    return {"wsl": True, "interop": False,
            "reason": hostenv.interop_reason(rep) or "WSL interop 을 쓸 수 없음 (wsl.conf [interop] 확인 후 wsl --shutdown)"}


def _wslpath_exe() -> str:
    exe = shutil.which("wslpath") or ("/usr/bin/wslpath" if os.path.exists("/usr/bin/wslpath") else None)
    if not exe:
        raise ToolMissing("wslpath 를 찾을 수 없습니다 (WSL 환경이 아님).", hint="Windows 백엔드는 WSL 안에서만 쓸 수 있다.")
    return exe


def to_windows_path(path: str | os.PathLike[str]) -> str:
    """리눅스 절대 경로 → Windows 경로(``\\\\wsl.localhost\\<배포판>\\…`` 또는 ``C:\\…``). 실패하면 오류.

    테스트는 이 함수를 monkeypatch 한다(서버와 분류기가 같은 변환 결과를 쓴다).
    """
    p = os.path.abspath(os.fspath(path))
    try:
        out = subprocess.run([_wslpath_exe(), "-w", p], stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ToolMissing(f"wslpath 실행 실패: {exc}", hint="WSL 환경과 interop 설정을 확인하라.")
    win = out.stdout.decode("utf-8", "replace").strip()
    if out.returncode != 0 or not win:
        raise ValidationFailed(f"경로를 Windows 경로로 바꿀 수 없습니다: {p} ({out.stderr.decode('utf-8', 'replace').strip()[:200]})")
    check_windows_path(win)
    return win


def check_windows_path(win: str) -> str:
    """esptool.exe 에 넘길 Windows 경로 검사.

    Win32 경로 정규화는 경로 요소 끝의 '.' 과 공백을 지운다. 그래서 ``…\\cases\\esp-lab.\\dumps\\…`` 는 실제로
    ``…\\cases\\esp-lab\\dumps\\…``(다른 케이스)에 쓰인다(실측: 실제 esptool.exe merge-bin). 그런 요소가 있으면 거부한다.
    """
    if not UNC_OK_RE.match(win) or any(c in win for c in "\r\n\x00\"") or win.startswith("@"):
        raise ValidationFailed(f"예상하지 못한 Windows 경로 형식: {win!r}", hint="\\\\wsl.localhost\\<배포판>\\… 또는 C:\\… 형식이어야 한다.")
    bad = [part for part in win.split("\\") if part and part.endswith((".", " "))]
    if bad:
        raise ValidationFailed(
            f"Windows 경로 요소가 '.' 또는 공백으로 끝납니다: {bad[0]!r} ({win})",
            hint="Windows 는 경로 요소 끝의 '.'·공백을 지워 다른 경로(예: 케이스 'esp-lab.' → 'esp-lab')에 쓴다. "
                 "이름이 '.'·공백으로 끝나지 않는 케이스(case_id)와 작업공간 경로를 쓴다.",
        )
    return win


def to_linux_path(win: str) -> str:
    """Windows 경로('C:\\tools\\esptool.exe') → 리눅스 경로(/mnt/c/tools/esptool.exe)."""
    out = subprocess.run([_wslpath_exe(), "-u", win], stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
    lin = out.stdout.decode("utf-8", "replace").strip()
    if out.returncode != 0 or not lin.startswith("/"):
        raise ValidationFailed(f"Windows 경로를 리눅스 경로로 바꿀 수 없습니다: {win}")
    return lin


# ---------------------------------------------------------------------------
# 포트 목록
# ---------------------------------------------------------------------------

_VIDPID_RE = re.compile(r"VID_([0-9A-Fa-f]{4})[&+]PID_([0-9A-Fa-f]{4})")
_COM_IN_NAME_RE = re.compile(r"\((COM\d+)\)")

#: Win32_PnPEntity 중 이름에 (COMn) 이 있는 장치만 JSON 으로 (읽기 전용 CIM 질의)
_PS_LIST_COM = (
    "$ErrorActionPreference='Stop';"
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
    "$d=@(Get-CimInstance -ClassName Win32_PnPEntity -Filter \"Name LIKE '%(COM%'\" | "
    "Select-Object Name,PNPDeviceID,Manufacturer,Status,Service);"
    "ConvertTo-Json -InputObject $d -Compress -Depth 3"
)


def annotate_usb(vid: int | None, pid: int | None) -> dict[str, Any]:
    if vid is None or pid is None:
        return {"usb_id": None, "kind": "unknown", "description_ko": None}
    key = f"{vid:04x}:{pid:04x}"
    kind, desc = KNOWN_USB_IDS.get(key, ("unknown", None))
    if kind == "unknown" and vid == 0x303A:
        kind, desc = "esp-usb", "Espressif USB 장치 (앱의 TinyUSB CDC 등)"
    return {"usb_id": key, "kind": kind, "description_ko": desc}


def powershell_exe() -> str | None:
    """Windows PowerShell 절대 경로 — ``pweh.hostenv`` H5(/proc/mounts 의 drvfs ``path=C:\\`` 또는 ``wslpath -u``).

    ``/mnt/c`` 를 가정하지 않고, $PATH 의 powershell.exe 도 쓰지 않는다(System32 의 고정 위치만). 없으면 None.
    """
    return hostenv.powershell_path()


def run_powershell(script: str, timeout: float = 45.0) -> tuple[int, str, str]:
    """powershell.exe -NoProfile -NonInteractive -Command <script> (진행률 출력 끔).

    현재 디렉터리는 C: 드라이브의 마운트 지점이다(hostenv H5 — UNC 현재 디렉터리 경고 회피). 모르면 상속한다.
    설정 ``hostenv.disable: [interop]`` 이면 실행하지 않고 ToolMissing 이다(부르는 쪽은 '확인 불가'로 다룬다 — 예약 파일은 지우지 않음).
    """
    if "interop" in hostenv.disabled_keys():
        raise ToolMissing("설정 hostenv.disable 에 interop 이 있어 powershell.exe 를 실행하지 않습니다.",
                          hint="Windows 쪽 확인(프로세스·COM 목록)이 필요하면 사람이 pipeline-config.yaml 의 hostenv.disable 을 고친다.")
    exe = powershell_exe()
    if not exe:
        raise ToolMissing("powershell.exe 를 찾을 수 없습니다.",
                          hint="WSL interop 과 C: 드라이브 drvfs 마운트(/etc/wsl.conf [automount])를 확인하라 — `pweh env` 로 볼 수 있다.")
    cwd = hostenv.drvfs_root("C")
    out = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", "$ProgressPreference='SilentlyContinue';" + script],
                         stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, cwd=cwd if cwd and os.path.isdir(cwd) else None)
    return out.returncode, out.stdout.decode("utf-8", "replace"), out.stderr.decode("utf-8", "replace")


def parse_windows_ports(json_text: str) -> list[dict[str, Any]]:
    text = (json_text or "").strip().lstrip("\ufeff")
    if not text:
        return []
    data = json.loads(text)
    if isinstance(data, dict):
        data = [data]
    out = []
    for d in data or []:
        if not isinstance(d, dict):
            continue
        name = str(d.get("Name") or "")
        m = _COM_IN_NAME_RE.search(name)
        if not m:
            continue
        pnp = str(d.get("PNPDeviceID") or "")
        mv = _VIDPID_RE.search(pnp)
        vid = int(mv.group(1), 16) if mv else None
        pid = int(mv.group(2), 16) if mv else None
        serial = None
        parts = pnp.split("\\")
        if pnp.upper().startswith("USB\\") and len(parts) >= 3 and "MI_" not in parts[1].upper() and "&" not in parts[2]:
            serial = parts[2]
        entry = {
            "port": m.group(1).upper(),
            "backend": "windows",
            "name": name,
            "pnp_device_id": pnp,
            "vid": None if vid is None else f"0x{vid:04x}",
            "pid": None if pid is None else f"0x{pid:04x}",
            "serial_number": serial,
            "manufacturer": d.get("Manufacturer"),
            "status": d.get("Status"),
            "service": d.get("Service"),
        }
        entry.update(annotate_usb(vid, pid))
        out.append(entry)
    out.sort(key=lambda e: int(e["port"][3:]))
    return out


def list_windows_ports() -> dict[str, Any]:
    st = interop_status()
    if not st["interop"]:
        return {"available": False, "ports": [], "note": st["reason"]}
    try:
        rc, out, err = run_powershell(_PS_LIST_COM)
    except ToolMissing as exc:
        return {"available": False, "ports": [], "note": str(exc)}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "ports": [], "note": f"powershell.exe 실행 실패: {exc}"}
    if rc != 0:
        return {"available": False, "ports": [], "note": f"powershell.exe 오류(rc={rc}): {err.strip()[:300]}"}
    try:
        ports = parse_windows_ports(out)
    except (ValueError, TypeError) as exc:
        return {"available": False, "ports": [], "note": f"PowerShell 출력 해석 실패: {exc}: {out[:200]!r}"}
    return {"available": True, "ports": ports, "note": None}


def list_linux_ports(device_users: Callable[[str], list[int]] | None = None) -> list[dict[str, Any]]:
    from serial.tools import list_ports

    out = []
    for p in sorted(list_ports.comports(), key=lambda x: x.device):
        entry: dict[str, Any] = {
            "port": p.device,
            "backend": "linux",
            "name": p.description,
            "hwid": p.hwid,
            "vid": None if p.vid is None else f"0x{p.vid:04x}",
            "pid": None if p.pid is None else f"0x{p.pid:04x}",
            "serial_number": p.serial_number,
            "manufacturer": p.manufacturer,
        }
        entry.update(annotate_usb(p.vid, p.pid))
        if device_users is not None and p.vid is not None:
            try:
                entry["in_use_by"] = device_users(p.device)
            except Exception:  # pragma: no cover
                entry["in_use_by"] = None
        out.append(entry)
    return out


def device_users(dev_path: str, limit_pids: int = 20000) -> list[int]:
    """그 장치 파일(예 /dev/ttyACM0)을 열고 있는 다른 프로세스 PID (Linux /proc 기반, 최선 노력)."""
    try:
        target = os.path.realpath(dev_path)
    except OSError:
        return []
    me = os.getpid()
    users: list[int] = []
    proc = Path("/proc")
    if not proc.is_dir():
        return []
    for n, p in enumerate(proc.iterdir()):
        if n > limit_pids:
            break
        if not p.name.isdigit() or int(p.name) == me:
            continue
        try:
            for fd in (p / "fd").iterdir():
                try:
                    if os.readlink(fd) == target:
                        users.append(int(p.name))
                        break
                except OSError:
                    continue
        except OSError:
            continue
    return users


__all__ = [
    "KNOWN_USB_IDS",
    "PortSpec",
    "annotate_usb",
    "check_windows_path",
    "device_users",
    "interop_status",
    "is_wsl",
    "list_linux_ports",
    "list_windows_ports",
    "parse_windows_ports",
    "powershell_exe",
    "run_powershell",
    "to_linux_path",
    "to_windows_path",
    "validate_port",
]
