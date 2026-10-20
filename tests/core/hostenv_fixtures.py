"""pweh.hostenv 시험용 가짜 probe 와 환경 fixture (설계 port-routing §14).

실제 호스트를 읽지 않는다. 값은 모두 합성값이다(커널·빌드·배포판·경로는 일부러 가짜로 보이게 만든다).
- ``FakeProbe``: 파일(경로 → 내용), 존재하는 경로, 디렉터리 목록, 명령 결과(라벨 → (rc, stdout) | None | 함수), 환경 변수, 그룹,
  $PATH 찾기(which), 실제 경로(realpaths — 없으면 os.path.normpath 로 '..' 만 푼다), 시계를 주입한다.
  실행한 명령은 ``calls``(+ ``cwds``) 에, 읽은 파일은 ``reads`` 에 남는다.
- 명령 라벨: powershell 은 ``ps:<스크립트 이름>``(hostenv.FIXED_PS_SCRIPTS 의 키), usbipd 는 ``usbipd <인자>``, 그 밖은 argv 를 공백으로 이은 것.
- ``FIXTURES``: 이름 → 가짜 probe 를 만드는 함수 (§14 의 10종 + 함정 사례는 시험에서 인자로 만든다).
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable

from pweh import hostenv

#: 합성 값 (실제 기기·호스트 값이 아님)
WSL2_KERNEL = "6.99.0.1-microsoft-standard-WSL2"
WSL1_KERNEL = "4.4.0-99999-Microsoft"
CUSTOM_KERNEL = "6.99.0-fixture-custom"
NATIVE_KERNEL = "6.99.0-99-generic"
DISTRO = 'PRETTY_NAME="Testix GNU/Linux 9 (fixture)"\nNAME="Testix"\n'
TOOLS_DIR = "/opt/pweh-fixture-tools"
WIN_INFO = {"major": 10, "minor": 0, "build": 99999, "ubr": 4321, "display_version": "99H9", "enable_lua": 1, "sac": 0, "elevated": False}
INTEROP_ON = "enabled\ninterpreter /init\nflags: PF\noffset 0\nmagic 4d5a\n"
INTEROP_OFF = "disabled\ninterpreter /init\nflags: PF\noffset 0\nmagic 4d5a\n"


def mounts(root: str = "/mnt", style: str = "9p", drives: str = "C") -> str:
    """합성 /proc/mounts. style: 9p(WSL2), drvfs(WSL1), virtiofs, none."""
    lines = ["none / ext4 rw,relatime 0 0", "proc /proc proc rw,nosuid,nodev,noexec 0 0"]
    for d in drives:
        mp = f"{root}/{d.lower()}"
        if style == "9p":
            lines.append(f"{d}:\\134 {mp} 9p rw,noatime,aname=drvfs;path={d}:\\;uid=1000;gid=1000;symlinkroot=/mnt/,cache=5,access=client,"
                         "msize=65536,trans=fd,rfd=5,wfd=5 0 0")
        elif style == "drvfs":
            lines.append(f"{d}:\\134 {mp} drvfs rw,noatime,uid=1000,gid=1000,case=off 0 0")
        elif style == "virtiofs":
            lines.append(f"{d}:\\134 {mp} virtiofs rw,relatime 0 0")
    return "\n".join(lines) + "\n"


class FakeProbe(hostenv.Probe):
    def __init__(self, *, sys_platform: str = "linux", machine: str = "x86_64", files: dict[str, str] | None = None,
                 paths: set[str] | None = None, dirs: dict[str, list[str]] | None = None, runs: dict[str, Any] | None = None,
                 env: dict[str, str] | None = None, groups: list[str] | None = None, which: dict[str, str] | None = None,
                 sysconfig_platform: str | None = None, not_executable: set[str] | None = None,
                 realpaths: dict[str, str] | None = None) -> None:
        self.sys_platform = sys_platform
        self.machine = machine
        self.sysconfig_platform = sysconfig_platform or ("win-amd64" if sys_platform == "win32" else "linux-x86_64")
        self.python_version = "3.10.99"
        self.files = dict(files or {})
        self.paths = set(paths or set())
        self.dirs = dict(dirs or {})
        self.runs = dict(runs or {})
        self.envs = dict(env or {})
        self.group_list = list(groups or [])
        self.which_map = dict(which or {})
        self.not_executable = set(not_executable or set())
        self.realpaths = dict(realpaths or {})
        self.calls: list[list[str]] = []
        self.cwds: list[str | None] = []
        self.reads: list[str] = []
        self.t = 1000.0

    # --- Probe 메서드 ---
    def read_text(self, path: str) -> str | None:
        self.reads.append(path)
        return self.files.get(path)

    def exists(self, path: str) -> bool:
        return path in self.files or path in self.paths or path in self.dirs

    def is_executable(self, path: str) -> bool:
        return self.exists(path) and path not in self.not_executable

    def realpath(self, path: str) -> str:
        return self.realpaths.get(path) or os.path.normpath(path)

    def listdir(self, path: str) -> list[str] | None:
        v = self.dirs.get(path)
        return sorted(v) if v is not None else None

    def run(self, argv, timeout, cwd=None):
        self.calls.append(list(argv))
        self.cwds.append(cwd)
        r = self.runs.get(self.label(argv), None)
        return r(argv) if callable(r) else r

    def env(self, name: str) -> str | None:
        return self.envs.get(name) or None

    def groups(self) -> list[str]:
        return list(self.group_list)

    def which(self, name: str) -> str | None:
        return self.which_map.get(name)

    def now(self) -> float:
        return self.t

    # --- 시험 도우미 ---
    @staticmethod
    def label(argv) -> str:
        base = str(argv[0]).replace("\\", "/").rsplit("/", 1)[-1].lower()
        if base == "powershell.exe":
            script = argv[-1]
            name = next((k for k, v in hostenv.FIXED_PS_SCRIPTS.items() if v == script), "?")
            return f"ps:{name}"
        if base == "usbipd.exe":
            return "usbipd " + " ".join(argv[1:])
        return " ".join(argv)

    def labels(self) -> list[str]:
        return [self.label(a) for a in self.calls]

    def exe_calls(self) -> list[list[str]]:
        return [a for a in self.calls if str(a[0]).lower().endswith(".exe")]


# ---------------------------------------------------------------------------
# fixture 빌더
# ---------------------------------------------------------------------------


def _ps_path(root: str = "/mnt") -> str:
    return f"{root}/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"


def wsl2(*, mode: str | None = "bridged", interop: str | None = "WSLInterop", interop_state: str = "on", status: str = "enabled",
         kernel: str = WSL2_KERNEL, smoke: Any = (0, ""), info: Any = None, mount_style: str = "9p", root: str = "/mnt",
         wslinfo_rc: int = 0, init: bool = True, usbipd: bool = False, usbip_client: bool = False, esptool: bool = True,
         autobind: int = 0, extra_files: dict[str, str] | None = None, env: dict[str, str] | None = None,
         wslpath_ok: bool = True, c_mapped: bool = True) -> FakeProbe:
    """WSL2(또는 버전을 바꾼 WSL) 가짜. mode=None 이면 wslinfo 가 실패한다(wslinfo_rc).

    wslpath_ok=False: wslpath 가 실행되지 않는다(``wslpath -w /`` 실패 — H4). c_mapped=False: ``wslpath -u 'C:\\'`` 가 실패한다
    (C: 가 마운트되지 않은 실제 wslpath 처럼 rc=1). C: 가 /proc/mounts 에도 없게 하려면 mount_style="none" 을 함께 준다.
    """
    files = {
        "/proc/sys/kernel/osrelease": kernel + "\n",
        "/proc/sys/fs/binfmt_misc/status": status + "\n",
        "/proc/cmdline": "initrd=\\initrd.img WSL_ROOT_INIT=1 panic=-1 nr_cpus=4\n",
        "/proc/mounts": mounts(root, mount_style),
        "/etc/os-release": DISTRO,
        "/proc/1/comm": "systemd\n",
    }
    if interop:
        files[f"/proc/sys/fs/binfmt_misc/{interop}"] = INTEROP_ON if interop_state == "on" else INTEROP_OFF
    paths = {"/run/WSL"}
    if init:
        paths.add("/init")
    ps = _ps_path(root)
    paths.add(ps)
    runs: dict[str, Any] = {
        "systemd-detect-virt -c": (0, "wsl\n"),
        "systemctl is-active systemd-udevd": (0, "active\n"),
        "dpkg-query -W -f=${Status} brltty": (1, ""),
        "wslinfo --version": (0, "9.9.9.9\n"),
        "wslpath -w /": (0, "\\\\wsl.localhost\\FixtureDistro\\\n") if wslpath_ok else (1, ""),
        "wslpath -u C:\\": (0, f"{root}/c/\n") if c_mapped else (1, ""),
        "ps:smoke": smoke,
        "ps:windows-info": (0, json.dumps(info if info is not None else WIN_INFO)),
        "ps:list-com": (0, json.dumps([{"Name": "USB Serial Device (COM3)", "PNPDeviceID": "USB\\VID_303A&PID_1001&MI_00\\7&FAKE&0&0000",
                                        "Status": "OK", "Service": "usbser"}])),
    }
    runs["wslinfo --networking-mode"] = (0, mode + "\n") if mode is not None else (wslinfo_rc, "")
    which: dict[str, str] = {}
    if usbipd:
        upath = f"{root}/c/Program Files/usbipd-win/usbipd.exe"
        paths.add(upath)
        runs["usbipd --version"] = (0, "9.9.9+fixture\n")
        policy = "Policy rules:\nGUID  EFFECT  OPERATION  BUSID  VID:PID  HWID\n"
        policy += "".join(f"00000000-0000-0000-0000-00000000000{i}  Allow  AutoBind  1-{i}  1234:000{i}\n" for i in range(autobind))
        runs["usbipd policy list"] = (0, policy)
    if usbip_client:
        paths.add(f"{root}/c/Program Files/USBip/usbip.exe")
        which["usbip.exe"] = f"{root}/c/Program Files/USBip/usbip.exe"
    e = {"WSL_DISTRO_NAME": "FixtureDistro", "PWEH_TOOLS_DIR": TOOLS_DIR}
    e.update(env or {})
    if esptool:
        paths.add(f"{TOOLS_DIR}/esptool-win/esptool-windows-amd64/esptool.exe")
    files.update(extra_files or {})
    return FakeProbe(files=files, paths=paths, runs=runs, env=e, groups=["dialout", "plugdev", "video", "fixtureuser"], which=which)


def wsl2_interop_bridged() -> FakeProbe:
    return wsl2(mode="bridged")


def wsl2_interop_nat() -> FakeProbe:
    return wsl2(mode="nat")


def wsl2_consomme() -> FakeProbe:
    return wsl2(mode="consomme")


def wsl2_no_interop() -> FakeProbe:
    return wsl2(mode="nat", interop_state="off")


def wsl1() -> FakeProbe:
    p = wsl2(mode="wsl1", kernel=WSL1_KERNEL, mount_style="drvfs")
    p.files["/proc/cmdline"] = "BOOT_IMAGE=/kernel init=/init\n"  # WSL_ROOT_INIT 은 WSL2 전용
    p.files["/proc/1/comm"] = "init\n"  # WSL1 의 PID1 은 /init (systemd 아님)
    return p


def wsl_unknown_version() -> FakeProbe:
    return wsl2(mode=None, wslinfo_rc=1, kernel=CUSTOM_KERNEL)


def native_linux_brltty() -> FakeProbe:
    files = {
        "/proc/sys/kernel/osrelease": NATIVE_KERNEL + "\n",
        "/proc/cmdline": "BOOT_IMAGE=/vmlinuz root=UUID=00000000 ro quiet\n",
        "/proc/mounts": mounts(style="none"),
        "/etc/os-release": DISTRO,
        "/proc/1/comm": "systemd\n",
        "/usr/lib/udev/rules.d/85-brltty.rules": 'ENV{PRODUCT}=="1a86/7523/*", ENV{BRLTTY_BRAILLE_DRIVER}="bm", GOTO="brltty_usb_run"\n',
    }
    runs = {
        "systemd-detect-virt -c": (1, "none\n"),
        "systemd-detect-virt -v": (1, "none\n"),
        "systemctl is-active systemd-udevd": (0, "active\n"),
        "dpkg-query -W -f=${Status} brltty": (0, "install ok installed"),
    }
    return FakeProbe(files=files, paths={"/dev/bus/usb"}, runs=runs, dirs={"/usr/lib/udev/rules.d": ["85-brltty.rules", "99-other.rules"]},
                     groups=["plugdev", "fixtureuser"], env={"PWEH_TOOLS_DIR": TOOLS_DIR})


def macos_arm64() -> FakeProbe:
    plist = "<plist><dict><key>ProductName</key><string>macOS</string><key>ProductVersion</key><string>99.1</string></dict></plist>"
    return FakeProbe(sys_platform="darwin", machine="arm64", files={"/System/Library/CoreServices/SystemVersion.plist": plist},
                     runs={"sysctl -n sysctl.proc_translated": (0, "0\n")}, env={"PWEH_TOOLS_DIR": TOOLS_DIR})


def windows_native() -> FakeProbe:
    return FakeProbe(sys_platform="win32", machine="AMD64", env={"PWEH_TOOLS_DIR": TOOLS_DIR})


def container_on_wsl_kernel() -> FakeProbe:
    """WSL 커널 문자열과 켜진 WSLInterop(binfmt_misc 는 커널 전체라 컨테이너에도 보인다)이 있어도 CONTAINER 여야 한다."""
    p = wsl2(mode="nat")
    p.paths.add("/.dockerenv")
    p.runs["systemd-detect-virt -c"] = (0, "docker\n")
    p.files["/proc/1/comm"] = "sh\n"
    return p


FIXTURES: dict[str, Callable[[], FakeProbe]] = {
    "wsl2-interop-bridged": wsl2_interop_bridged,
    "wsl2-interop-nat": wsl2_interop_nat,
    "wsl2-consomme": wsl2_consomme,
    "wsl2-no-interop": wsl2_no_interop,
    "wsl1": wsl1,
    "wsl-unknown-version": wsl_unknown_version,
    "native-linux-brltty": native_linux_brltty,
    "macos-arm64": macos_arm64,
    "windows-native": windows_native,
    "container-on-wsl-kernel": container_on_wsl_kernel,
}

EXPECTED_KIND = {
    "wsl2-interop-bridged": "WSL2_INTEROP",
    "wsl2-interop-nat": "WSL2_INTEROP",
    "wsl2-consomme": "WSL2_INTEROP",
    "wsl2-no-interop": "WSL2_NO_INTEROP",
    "wsl1": "WSL1",
    "wsl-unknown-version": "WSL_UNKNOWN",
    "native-linux-brltty": "NATIVE_LINUX",
    "macos-arm64": "MACOS",
    "windows-native": "NATIVE_WINDOWS",
    "container-on-wsl-kernel": "CONTAINER",
}


def detect(probe: FakeProbe, **kw: Any) -> dict[str, Any]:
    """설정을 읽지 않는 감지 (config={} — 시험이 실제 설정·환경 변수에 기대지 않게)."""
    kw.setdefault("config", {})
    return hostenv.detect(probe, **kw)
