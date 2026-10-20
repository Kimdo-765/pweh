"""pweh.hostenv 시험 (설계 port-routing §3·§14): 주입한 가짜 probe 로만 돈다 — 실제 호스트를 읽거나 실행하지 않는다.

- fixture 10종의 kind 와 보고서 필드, 함정 사례(WSLInterop-late 만, binfmt status disabled, 사용자 커널 + wslinfo, virtioproxy,
  usbip.exe 만, UBR 합성, 컨테이너 안의 WSL 커널)
- 실행 허용 목록(wsl/cmd/reg/usbip 없음, usbipd 는 세 동사만, powershell 은 절대 경로 + 고정 스크립트)
- 캐시(정적 값, interop 등록 다시 읽기, smoke 300 초, refresh), override 는 좁히기만
- drvfs·Windows 경로 변환(/mnt/c 를 가정하지 않음), 추천 경로, esp ports 의 늦은 묶기 seam
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.hostenv_fixtures import EXPECTED_KIND, FIXTURES, TOOLS_DIR, FakeProbe, detect, mounts, native_linux_brltty, wsl2
from pweh import hostenv

TOP_KEYS = {"schema", "kind", "python", "linux", "macos", "wsl", "windows", "serial", "overridden", "warnings", "evidence"}
DENIED = {"wsl.exe", "cmd.exe", "reg.exe", "usbip.exe", "wusbip.exe", "wslconfig.exe", "bash.exe"}


def _base(argv) -> str:
    return str(argv[0]).replace("\\", "/").rsplit("/", 1)[-1].lower()


# ---------------------------------------------------------------------------
# fixture 10종
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", list(FIXTURES))
def test_fixture_kind_and_shape(name):
    rep = detect(FIXTURES[name]())
    assert rep["schema"] == "pweh.hostenv/v1"
    assert rep["kind"] == EXPECTED_KIND[name]
    assert set(rep) == TOP_KEYS  # 모든 kind 에서 최상위 키가 같다 (해당 없으면 null)
    assert rep["kind"] in hostenv.KINDS
    json.dumps(rep)  # JSON 으로 바꿀 수 있다
    assert (rep["wsl"] is not None) == (rep["kind"] in hostenv.WSL_KINDS)
    assert (rep["windows"] is not None) == (rep["kind"] in hostenv.WSL_KINDS)


@pytest.mark.parametrize("name", list(FIXTURES))
def test_every_command_is_allowlisted(name):
    p = FIXTURES[name]()
    rep = detect(p)
    hostenv.windows_com_ports(rep, p)
    hostenv.wildcard_listeners(p)
    trusted = hostenv.trusted_windows_exes(p)
    for argv in p.calls:
        assert hostenv.check_argv(argv, trusted) is None, argv
        base = _base(argv)
        assert base not in DENIED, argv
        if base == "usbipd.exe":
            assert argv[0] == trusted["usbipd"] and tuple(argv[1:]) in {("--version",), ("state",), ("policy", "list")}, argv
        if base == "powershell.exe":
            assert argv[0] == trusted["powershell"] and argv[1:4] == ["-NoProfile", "-NonInteractive", "-Command"], argv
            assert argv[4] in hostenv.FIXED_PS_SCRIPTS.values()
            assert "$ProgressPreference='SilentlyContinue'" in argv[4] and "UTF8" in argv[4]
    if rep["kind"] in ("CONTAINER", "WSL2_NO_INTEROP", "NATIVE_LINUX", "MACOS", "NATIVE_WINDOWS"):
        assert p.exe_calls() == [], p.exe_calls()  # Windows 쪽 프로그램을 하나도 띄우지 않는다


def test_check_argv_allows_and_refuses():
    ps = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
    usbipd = "/mnt/c/Program Files/usbipd-win/usbipd.exe"
    trusted = {"powershell": ps, "usbipd": usbipd}
    ok = [
        ["wslinfo", "--networking-mode"], ["wslinfo", "--version"], ["wslpath", "-u", "C:\\"], ["wslpath", "-w", "/"],
        ["systemd-detect-virt", "-c"], ["systemctl", "is-active", "systemd-udevd"], ["dpkg-query", "-W", "-f=${Status}", "brltty"],
        ["sysctl", "-n", "sysctl.proc_translated"],
        [ps, "-NoProfile", "-NonInteractive", "-Command", hostenv.PS_SMOKE],
        [usbipd, "policy", "list"], [usbipd, "--version"],
    ]
    for argv in ok:
        assert hostenv.check_argv(argv, trusted) is None, argv
    bad = [
        [], ["wsl.exe", "-u", "root"], ["/mnt/c/Windows/System32/wsl.exe", "--list"], ["/mnt/c/Windows/System32/cmd.exe", "/c", "ver"],
        ["/mnt/c/Windows/System32/reg.exe", "query", "HKLM"], ["/mnt/c/Program Files/USBip/usbip.exe", "list"],
        [usbipd, "bind", "--busid", "1-1"], [usbipd, "policy", "add"],
        ["usbipd.exe", "--version"],  # 이름만
        ["/tmp/anything/usbipd.exe", "policy", "list"],  # 확인한 경로가 아님 (이름만 같다)
        ["/mnt/c/Tools/usbipd.exe", "--version"],  # drvfs 아래여도 표준 위치가 아니면 거부
        [ps, "-NoProfile", "-NonInteractive", "-Command", "Get-Process"],  # 고정 스크립트가 아님
        [ps, "-Command", hostenv.PS_SMOKE],  # 플래그 빠짐
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", hostenv.PS_SMOKE],  # $PATH 이름
        ["/tmp/x/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "-NoProfile", "-NonInteractive", "-Command", hostenv.PS_SMOKE],
        ["/mnt/c/windows/system32/WindowsPowerShell/v1.0/powershell.exe", "-NoProfile", "-NonInteractive", "-Command", hostenv.PS_SMOKE],
        ["/mnt/c/../../tmp/x/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         hostenv.PS_SMOKE],
        ["/usr/bin/wslinfo", "--networking-mode"],  # 시스템 도구는 이름으로만
        ["wslinfo", "--vm-id"], ["wslpath", "-w", "/etc"], ["wslpath", "-u", "relative"], ["systemctl", "stop", "systemd-udevd"],
        ["/mnt/c/tools/other.exe"], ["sh", "-c", "id"], ["wslinfo\x00", "--version"],
    ]
    for argv in bad:
        assert hostenv.check_argv(argv, trusted), argv
    # trusted 가 없으면(확인한 경로 없음) Windows 실행 파일은 하나도 받지 않는다 — 접미사·이름으로 받지 않는다
    assert hostenv.check_argv([ps, "-NoProfile", "-NonInteractive", "-Command", hostenv.PS_SMOKE])
    assert hostenv.check_argv([usbipd, "--version"], {"powershell": ps})


class _SyntheticFsProbe(hostenv.Probe):
    """실제 Probe.run(허용 목록·trusted 계산)을 쓰되 파일 시스템은 합성값인 probe (실제 호스트를 읽지 않는다)."""

    PS = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"

    def read_text(self, path):
        return mounts() if path == "/proc/mounts" else None

    def exists(self, path):
        return path == self.PS

    def realpath(self, path):
        import os

        return os.path.normpath(path)

    def which(self, name):
        return None


def test_default_probe_run_enforces_trusted_paths(monkeypatch):
    """기본 Probe.run 은 허용 목록 밖(이름·접미사만 맞는 것 포함)을 subprocess 에 넘기지 않고, 확인한 정확한 경로만 실행한다."""
    import subprocess as sp

    seen = []

    def fake_run(argv, **kw):
        seen.append(argv)
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(sp, "run", fake_run)
    probe = _SyntheticFsProbe()
    smoke = ["-NoProfile", "-NonInteractive", "-Command", hostenv.PS_SMOKE]
    assert probe.run(["/mnt/c/Windows/System32/wsl.exe", "-u", "root"], 5) is None
    assert probe.run(["cmd.exe", "/c", "dir"], 5) is None
    assert probe.run(["/x/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", *smoke], 5) is None  # 접미사만 같음
    assert probe.run(["/mnt/c/../../tmp/x/usbipd.exe", "--version"], 5) is None  # 확인한 usbipd 없음
    assert probe.run([probe.PS, "-NoProfile", "-NonInteractive", "-Command", "Get-Date"], 5) is None  # 고정 스크립트가 아님
    assert seen == []
    assert probe.run([probe.PS, *smoke], 5) == (0, "")
    assert seen == [[probe.PS, *smoke]]


def test_default_probe_reads_procfs_in_small_chunks(monkeypatch, tmp_path):
    """/proc/sys 는 read() 크기만큼 커널 버퍼를 잡아 큰 read 가 ENOMEM 으로 실패한다 → 64 KiB 씩 읽어야 한다(실기에서 찾은 결함)."""
    import errno

    class SysctlFile:
        def __init__(self) -> None:
            self.data = b"6.99.0.1-microsoft-standard-WSL2\n"

        def read(self, n: int) -> bytes:
            if n > 1024 * 1024:
                raise OSError(errno.ENOMEM, "Cannot allocate memory")
            out, self.data = self.data[:n], self.data[n:]
            return out

        def __enter__(self):
            return self

        def __exit__(self, *a) -> None:
            return None

    monkeypatch.setattr(hostenv, "open", lambda *a, **k: SysctlFile(), raising=False)
    assert hostenv.Probe().read_text("/proc/sys/kernel/osrelease") == "6.99.0.1-microsoft-standard-WSL2\n"
    monkeypatch.undo()
    big = tmp_path / "big.txt"
    big.write_bytes(b"x" * (5 * 1024 * 1024))
    assert len(hostenv.Probe().read_text(str(big))) == 4 * 1024 * 1024  # 4 MiB 에서 자른다
    assert hostenv.Probe().read_text(str(tmp_path / "missing")) is None


def test_hostenv_imports_are_portable():
    """win32 에서도 import 할 수 있어야 한다(unsupported_platform 안내): 최상위에서 POSIX 전용·순환 모듈을 import 하지 않는다."""
    tree = ast.parse(Path(hostenv.__file__).read_text(encoding="utf-8"))
    names = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(("." * node.level) + (node.module or ""))
    assert not names & {"grp", "pwd", "fcntl", "termios", "pty", ".config", ".mcpkit", ".runtime", "pweh.config", "pweh.mcpkit", "serial"}, names


# ---------------------------------------------------------------------------
# 보고서 필드
# ---------------------------------------------------------------------------


def test_wsl2_bridged_report_fields():
    p = FIXTURES["wsl2-interop-bridged"]()
    rep = detect(p)
    w, win, lin = rep["wsl"], rep["windows"], rep["linux"]
    assert (w["version"], w["version_source"], w["networking_mode"], w["drvfs_c"]) == (2, "osrelease", "bridged", "/mnt/c")
    assert w["release"] == "9.9.9.9" and w["distro"] == "FixtureDistro"
    it = w["interop"]
    assert it == {"usable": True, "entry": "WSLInterop", "entry_state": "enabled", "init": True, "wslpath": True, "smoke": "ok",
                  "binfmt_status_advisory": "enabled", "reason": None}
    assert win["build"] == "10.0.99999.4321" and win["display_version"] == "99H9"
    assert win["uac_enabled"] is True and win["interop_elevated"] is False and win["smart_app_control"] == "off"
    assert win["powershell"] == "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
    assert win["usbipd"] == {"present": False, "path": None, "version": None, "autobind_policies": None, "found_elsewhere": None}
    assert win["serial_helper"] == {"present": False} and win["ignored"] == []
    assert win["tools"]["esptool_win"] == {"present": True, "path": f"{TOOLS_DIR}/esptool-win/esptool-windows-amd64/esptool.exe",
                                           "source": "pweh-tools", "problem": None}
    assert lin["groups"] == ["dialout", "plugdev", "video"] and lin["root_equivalent_groups"] == []
    assert lin["systemd"] is True and lin["udevd"] is True and lin["container"] is False
    assert rep["serial"]["backend"] == "posix" and rep["serial"]["busy_check"] == "proc"
    assert any("bridged" in x and "0.0.0.0" in x and "--host-ip" in x for x in rep["warnings"])
    assert rep["overridden"] == []
    steps = {e["step"] for e in rep["evidence"]}
    assert {"H0", "H2", "H3", "H4", "H6", "H7"} <= steps
    # smoke 와 Windows 정보 질의는 C: 마운트 지점을 현재 디렉터리로 쓴다 (UNC cwd 경고 회피)
    assert all(c == "/mnt/c" for a, c in zip(p.calls, p.cwds) if _base(a) == "powershell.exe")


@pytest.mark.parametrize("info,build", [
    ({"major": 10, "minor": 0, "build": 99999, "ubr": 4321}, "10.0.99999.4321"),
    ({"major": 10, "minor": 0, "build": 99999, "ubr": None}, "10.0.99999"),
    ({"major": "10", "minor": "0", "build": "99999", "ubr": "17"}, "10.0.99999.17"),
    ({"major": 10, "minor": None, "build": 99999, "ubr": 1}, None),
])
def test_build_is_osversion_plus_registry_ubr(info, build):
    assert detect(wsl2(info=info))["windows"]["build"] == build


@pytest.mark.parametrize("info,uac,warn", [
    ({**{"major": 10, "minor": 0, "build": 1}, "enable_lua": 0, "elevated": True}, False, True),
    ({**{"major": 10, "minor": 0, "build": 1}, "enable_lua": 1, "elevated": True}, True, True),
    ({**{"major": 10, "minor": 0, "build": 1}, "enable_lua": 1, "elevated": False}, True, False),
    ({**{"major": 10, "minor": 0, "build": 1}}, None, False),
])
def test_uac_and_high_il_warning(info, uac, warn):
    rep = detect(wsl2(info=info))
    assert rep["windows"]["uac_enabled"] is uac
    assert any("High IL" in w for w in rep["warnings"]) == warn


def test_unknown_is_null_not_false():
    rep = detect(FIXTURES["wsl2-no-interop"]())
    win = rep["windows"]
    assert win["uac_enabled"] is None and win["build"] is None and win["smart_app_control"] is None  # 읽지 않았다(모름)
    assert win["usbipd"]["present"] is False and win["usbipd"]["version"] is None  # C: 는 보이는데 파일이 없다(없음)
    nodrv = wsl2(mount_style="none", c_mapped=False)
    rep = detect(nodrv)
    assert rep["wsl"]["drvfs_c"] is None and rep["windows"]["powershell"] is None
    assert rep["windows"]["usbipd"]["present"] is None  # C: 를 못 보니 모른다
    assert rep["windows"]["uac_enabled"] is None  # 읽지 못했다(모름)


def test_networking_none_is_a_mode_and_failure_is_null():
    rep = detect(wsl2(mode="none"))
    assert rep["wsl"]["networking_mode"] == "none"
    serial = next(r for r in hostenv.recommend_routes(rep) if r["device"] == "serial")
    assert serial["now"]["available"] is False and any("attach 불가" in s for s in serial["now"]["human_steps"])
    rep = detect(wsl2(mode=None, wslinfo_rc=1))
    assert rep["wsl"]["networking_mode"] is None and rep["kind"] == "WSL2_INTEROP"  # osrelease 로 WSL2
    assert any("wslinfo 실패" in w for w in rep["warnings"])


def test_native_linux_brltty_and_groups():
    rep = detect(native_linux_brltty())
    lin = rep["linux"]
    assert rep["kind"] == "NATIVE_LINUX" and rep["wsl"] is None and rep["windows"] is None
    assert lin["brltty"] == {"installed": True, "ch340_rule": True, "masked": False}
    assert lin["udev_rules"] == ["85-brltty.rules"] and lin["usb_nodes"] == "present" and lin["virt"] == "none"
    assert any("brltty" in w and "1a86:7523" in w for w in rep["warnings"])
    masked = native_linux_brltty()
    masked.files["/etc/udev/rules.d/85-brltty.rules"] = ""  # /dev/null 로 가린 규칙
    assert detect(masked)["linux"]["brltty"]["masked"] is True
    assert not any("brltty" in w for w in detect(masked)["warnings"])
    eq = native_linux_brltty()
    eq.group_list = ["docker", "dialout"]
    eq.envs["SSH_CONNECTION"] = "192.0.2.1 50000 192.0.2.2 22"
    rep = detect(eq)
    assert rep["linux"]["root_equivalent_groups"] == ["docker"]
    assert any("root 와 같은 그룹" in w for w in rep["warnings"]) and any("SSH" in w for w in rep["warnings"])


def test_macos_and_windows_native():
    rep = detect(FIXTURES["macos-arm64"]())
    assert rep["macos"] == {"product_version": "99.1", "rosetta": False} and rep["linux"] is None
    assert rep["serial"]["busy_check"] == "none"
    rosetta = FIXTURES["macos-arm64"]()
    rosetta.runs["sysctl -n sysctl.proc_translated"] = (0, "1\n")
    assert any("Rosetta" in w for w in detect(rosetta)["warnings"])
    rep = detect(FIXTURES["windows-native"]())
    assert rep["kind"] == "NATIVE_WINDOWS" and rep["python"]["mingw"] is False
    assert any("WSL" in w for w in rep["warnings"])
    mingw = FakeProbe(sys_platform="win32", sysconfig_platform="mingw_x86_64")
    assert detect(mingw)["python"]["mingw"] is True
    for plat, kind in (("cygwin", "CYGWIN"), ("msys", "MSYS"), ("freebsd14", None)):
        rep = detect(FakeProbe(sys_platform=plat))
        assert rep["kind"] == kind and set(rep) == TOP_KEYS


# ---------------------------------------------------------------------------
# 함정 사례 (§14)
# ---------------------------------------------------------------------------


def test_interop_late_only_is_accepted():
    rep = detect(wsl2(interop="WSLInterop-late"))
    assert rep["kind"] == "WSL2_INTEROP" and rep["wsl"]["interop"]["entry"] == "WSLInterop-late"


def test_binfmt_status_disabled_is_only_advisory():
    rep = detect(wsl2(status="disabled"))
    assert rep["kind"] == "WSL2_INTEROP" and rep["wsl"]["interop"]["binfmt_status_advisory"] == "disabled"


@pytest.mark.parametrize("mode,rc,kind,source", [
    ("wsl1", 0, "WSL1", "wslinfo"),
    ("nat", 0, "WSL2_INTEROP", "wslinfo"),
    (None, 1, "WSL_UNKNOWN", None),
])
def test_user_kernel_decides_version_by_wslinfo(mode, rc, kind, source):
    """'wslinfo 가 있으면 WSL2' 가 아니다: wsl1 출력은 WSL1, 다른 값은 WSL2, 실패는 버전 모름."""
    rep = detect(wsl2(kernel="6.99.0-fixture-custom", mode=mode, wslinfo_rc=rc))
    assert rep["kind"] == kind and rep["wsl"]["version_source"] == source


def test_wsl1_without_interop_keeps_kind():
    p = FIXTURES["wsl1"]()
    p.files["/proc/sys/fs/binfmt_misc/WSLInterop"] = "disabled\n"
    rep = detect(p)
    assert rep["kind"] == "WSL1" and rep["wsl"]["interop"]["usable"] is False and p.exe_calls() == []
    assert rep["wsl"]["interop"]["wslpath"] is None and "wslpath -w /" not in p.labels()  # 등록이 꺼져 있으면 보지 않는다(모름)


def test_virtioproxy_mode():
    rep = detect(wsl2(mode="virtioproxy"))
    assert rep["kind"] == "WSL2_INTEROP" and rep["wsl"]["networking_mode"] == "virtioproxy"
    assert hostenv.usbipd_attach("virtioproxy") == hostenv.usbipd_attach("mirrored")
    assert "--host-ip" not in hostenv.usbipd_attach("virtioproxy")["command"]


def test_usbip_client_is_not_usbipd():
    p = wsl2(usbipd=False, usbip_client=True)
    rep = detect(p)
    u = rep["windows"]["usbipd"]
    assert u["present"] is False and u["version"] is None
    assert len(rep["windows"]["ignored"]) == 1 and "usbip.exe" in rep["windows"]["ignored"][0] and "usbip-win2" in rep["windows"]["ignored"][0]
    assert not any(_base(a) in ("usbip.exe", "wusbip.exe") for a in p.calls)


def test_usbipd_present_version_and_autobind_warning():
    p = wsl2(usbipd=True, autobind=2)
    rep = detect(p)
    u = rep["windows"]["usbipd"]
    assert u["present"] is True and u["version"] == "9.9.9+fixture" and u["autobind_policies"] == 2
    assert u["path"].endswith("/usbipd-win/usbipd.exe")
    assert any("AutoBind" in w for w in rep["warnings"])
    assert {tuple(a[1:]) for a in p.calls if _base(a) == "usbipd.exe"} == {("--version",), ("policy", "list")}
    assert not any("AutoBind" in w for w in detect(wsl2(usbipd=True, autobind=0))["warnings"])


def test_usbipd_on_path_outside_drvfs_is_ignored():
    p = wsl2(usbipd=False)
    p.which_map["usbipd.exe"] = "/home/fixture/bin/usbipd.exe"  # drvfs 밖 — 받지 않는다
    p.paths.add("/home/fixture/bin/usbipd.exe")
    rep = detect(p)
    assert rep["windows"]["usbipd"]["present"] is False and not any(_base(a) == "usbipd.exe" for a in p.calls)


@pytest.mark.parametrize("how", ["dockerenv", "containerenv", "env", "detect-virt"])
def test_container_signals_beat_wsl_kernel(how):
    p = wsl2(mode="nat")
    if how == "dockerenv":
        p.paths.add("/.dockerenv")
    elif how == "containerenv":
        p.paths.add("/run/.containerenv")
    elif how == "env":
        p.envs["container"] = "podman"
    else:
        p.runs["systemd-detect-virt -c"] = (0, "lxc\n")
    rep = detect(p)
    assert rep["kind"] == "CONTAINER" and rep["wsl"] is None and rep["windows"] is None
    assert rep["linux"]["container"] is True and rep["linux"]["kernel"].endswith("microsoft-standard-WSL2")
    assert p.exe_calls() == [] and not hostenv.is_wsl(rep) and not hostenv.interop_usable(rep)
    assert "컨테이너" in hostenv.interop_reason(rep)


def test_wsl_detect_virt_is_not_a_container():
    p = wsl2(mode="nat")
    p.runs["systemd-detect-virt -c"] = (0, "wsl\n")
    assert detect(p)["kind"] == "WSL2_INTEROP"


def test_env_and_hyperv_do_not_make_native_linux_wsl():
    """WSL_DISTRO_NAME 은 표시용이고, systemd-detect-virt -v 의 'microsoft'(Hyper-V VM)는 WSL 표지가 아니다."""
    p = native_linux_brltty()
    p.envs["WSL_DISTRO_NAME"] = "Ubuntu"
    p.runs["systemd-detect-virt -v"] = (0, "microsoft\n")
    rep = detect(p)
    assert rep["kind"] == "NATIVE_LINUX" and rep["linux"]["virt"] == "microsoft"


@pytest.mark.parametrize("smoke,state", [((1, ""), "failed"), ((hostenv.RC_TIMEOUT, ""), "timeout"), (None, "cannot-run")])
def test_failed_smoke_short_circuits_windows_launches(smoke, state):
    p = wsl2(smoke=smoke, usbipd=True)
    rep = detect(p)
    assert rep["kind"] == "WSL2_NO_INTEROP" and rep["wsl"]["interop"]["smoke"] == state
    assert p.labels().count("ps:smoke") == 1
    assert [p.label(a) for a in p.exe_calls()] == ["ps:smoke"]  # UAC 질의·usbipd 실행 없음
    assert rep["windows"]["uac_enabled"] is None and rep["windows"]["usbipd"]["version"] is None
    assert "smoke" in rep["wsl"]["interop"]["reason"]


def test_missing_powershell_keeps_interop_without_windows_info():
    p = wsl2(usbipd=True)
    p.paths.discard("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
    rep = detect(p)
    it = rep["wsl"]["interop"]
    assert rep["kind"] == "WSL2_INTEROP" and it["usable"] is True and it["smoke"] == "no-powershell" and it["reason"] is None
    assert p.exe_calls() == [] and rep["windows"]["uac_enabled"] is None and rep["windows"]["usbipd"]["version"] is None
    assert any("powershell.exe 를 찾지 못함" in w for w in rep["warnings"])


def test_missing_init_or_wslpath_fails_interop_without_smoke():
    for p, why in ((wsl2(init=False), "/init"), (wsl2(wslpath_ok=False), "wslpath -w /")):
        rep = detect(p)
        it = rep["wsl"]["interop"]
        assert it["usable"] is False and it["smoke"] == "not-run" and why in it["reason"] and p.exe_calls() == []


# ---------------------------------------------------------------------------
# drvfs 와 Windows 경로 (/mnt/c 를 가정하지 않는다 — G7)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("text,drive,expect", [
    (mounts("/mnt", "9p"), "C", "/mnt/c"),
    (mounts("/mnt", "drvfs"), "C", "/mnt/c"),
    (mounts("/mnt", "virtiofs"), "C", "/mnt/c"),
    (mounts("/win", "9p", "CD"), "d", "/win/d"),
    ("D:\\134 /mnt/my\\040drive 9p rw,aname=drvfs;path=D:\\;uid=1000 0 0\n", "D", "/mnt/my drive"),
    ("drvfs /mnt/c 9p rw,aname=drvfs;path=c:\\;uid=1000 0 0\n", "C", "/mnt/c"),
    ("C:\\134Users\\134x /mnt/sub 9p rw,aname=drvfs;path=C:\\Users\\x;uid=1000 0 0\n", "C", None),  # 하위 폴더 마운트는 드라이브 루트가 아니다
])
def test_drvfs_root_from_proc_mounts(text, drive, expect):
    p = FakeProbe(files={"/proc/mounts": text}, runs={"wslpath -u C:\\": None, "wslpath -u D:\\": None})
    assert hostenv.drvfs_root(drive, p) == expect


def test_drvfs_root_falls_back_to_wslpath_then_none():
    p = FakeProbe(files={"/proc/mounts": mounts(style="none")}, runs={"wslpath -u C:\\": (0, "/auto/c/\n")})
    assert hostenv.drvfs_root("C", p) == "/auto/c"
    assert p.labels() == ["wslpath -u C:\\"]
    assert hostenv.drvfs_root("C", p) == "/auto/c" and p.labels() == ["wslpath -u C:\\"]  # 기억한다
    q = FakeProbe(files={"/proc/mounts": mounts(style="none")}, runs={"wslpath -u C:\\": (1, "")})
    assert hostenv.drvfs_root("C", q) is None
    assert hostenv.drvfs_root("CC", q) is None and hostenv.drvfs_root("1", q) is None


def test_windows_path_to_wsl():
    p = FakeProbe(files={"/proc/mounts": mounts("/win", "9p")}, runs={"wslpath -u E:\\x\\y": (0, "/win/e/x/y\n"), "wslpath -u E:\\": None})
    assert hostenv.windows_path_to_wsl(hostenv.POWERSHELL_WIN, p) == "/win/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
    assert hostenv.windows_path_to_wsl("c:/tools//esptool.exe", p) == "/win/c/tools/esptool.exe"
    assert hostenv.windows_path_to_wsl("C:\\", p) == "/win/c"
    assert hostenv.windows_path_to_wsl("E:\\x\\y", p) == "/win/e/x/y"  # 마운트 표에 없으면 wslpath
    for bad in ("\\\\server\\share\\x", "C:relative", "C:\\a\\..\\b", "C:\\a\nb", "", "/etc/passwd"):
        assert hostenv.windows_path_to_wsl(bad, p) is None, bad


def test_powershell_resolves_under_custom_automount_root():
    """automount root 를 /win 으로 바꾼 배포판: powershell·cwd 가 /win/c 아래로 잡힌다(/mnt/c 하드코딩 없음)."""
    p = wsl2(root="/win")
    rep = detect(p)
    ps = "/win/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
    assert rep["kind"] == "WSL2_INTEROP" and rep["windows"]["powershell"] == ps and rep["wsl"]["drvfs_c"] == "/win/c"
    for argv, cwd in zip(p.calls, p.cwds):
        if _base(argv) == "powershell.exe":
            assert argv[0] == ps and cwd == "/win/c"
    assert not any("/mnt/c" in " ".join(a) for a in p.calls)


# ---------------------------------------------------------------------------
# 캐시 (§3.3)
# ---------------------------------------------------------------------------


def test_static_values_cached_but_interop_entry_reread():
    p = wsl2()
    detect(p)
    detect(p)
    assert p.labels().count("wslinfo --networking-mode") == 1 and p.labels().count("ps:windows-info") == 1
    assert p.reads.count("/proc/sys/fs/binfmt_misc/WSLInterop") == 2  # 부를 때마다 다시 읽는다
    p.files["/proc/sys/fs/binfmt_misc/WSLInterop"] = "disabled\n"  # systemd-binfmt 가 실행 중에 지운 경우
    rep = detect(p)
    assert rep["kind"] == "WSL2_NO_INTEROP" and rep["windows"]["uac_enabled"] is None


def test_smoke_cached_300_seconds():
    p = wsl2()
    detect(p)
    p.t += 299
    detect(p)
    assert p.labels().count("ps:smoke") == 1
    p.t += 2
    detect(p)
    assert p.labels().count("ps:smoke") == 2


def test_smoke_false_launches_nothing_then_smoke_true_runs():
    p = wsl2(usbipd=True)
    rep = detect(p, smoke=False)
    assert p.exe_calls() == [] and rep["wsl"]["interop"]["smoke"] == "skipped" and rep["kind"] == "WSL2_INTEROP"
    assert rep["windows"]["uac_enabled"] is None and rep["windows"]["usbipd"]["version"] is None
    rep = detect(p)
    assert rep["wsl"]["interop"]["smoke"] == "ok" and rep["windows"]["uac_enabled"] is True
    assert "ps:smoke" in p.labels() and "usbipd --version" in p.labels()


def test_smoke_false_uses_cached_failure():
    p = wsl2(smoke=(1, ""))
    detect(p)
    rep = detect(p, smoke=False)
    assert rep["kind"] == "WSL2_NO_INTEROP" and rep["wsl"]["interop"]["smoke"] == "failed"


def test_refresh_reruns_everything_and_reports_are_copies():
    p = wsl2()
    rep = detect(p)
    rep["windows"]["build"] = "tampered"
    rep["wsl"]["interop"]["usable"] = False
    rep["evidence"].clear()
    again = detect(p)
    assert again["windows"]["build"] == "10.0.99999.4321" and again["wsl"]["interop"]["usable"] is True and again["evidence"]
    detect(p, refresh=True)
    assert p.labels().count("wslinfo --networking-mode") == 2 and p.labels().count("ps:smoke") == 2


def test_default_probe_is_used_and_patchable(monkeypatch):
    p = wsl2()
    monkeypatch.setattr(hostenv, "_default_probe", lambda: p)
    rep = hostenv.detect(config={})
    assert rep["kind"] == "WSL2_INTEROP" and p.calls
    assert hostenv.is_wsl() is True  # report 없이: smoke=False 감지
    assert hostenv.drvfs_root() == "/mnt/c" and hostenv.powershell_path().endswith("/powershell.exe")


# ---------------------------------------------------------------------------
# override 는 좁히기만 (§3.3)
# ---------------------------------------------------------------------------


def test_disable_interop_narrows_and_launches_nothing():
    p = wsl2(usbipd=True)
    rep = detect(p, config={"hostenv": {"disable": ["interop"]}})
    assert rep["kind"] == "WSL2_NO_INTEROP" and rep["overridden"] == ["hostenv.disable.interop"]
    assert rep["wsl"]["interop"]["smoke"] == "disabled" and "hostenv.disable" in rep["wsl"]["interop"]["reason"]
    assert p.exe_calls() == []
    assert detect(p, config={})["kind"] == "WSL2_INTEROP"  # 캐시를 더럽히지 않는다


def test_disable_windows_tools_and_serial_helper():
    p = wsl2()
    rep = detect(p, config={"hostenv": {"disable": ["windows_tools", "serial_helper"]}})
    assert rep["overridden"] == ["hostenv.disable.serial_helper", "hostenv.disable.windows_tools"]
    assert rep["windows"]["tools"]["esptool_win"]["disabled"] is True and rep["windows"]["serial_helper"]["disabled"] is True
    routes = {r["device"]: r for r in hostenv.recommend_routes(rep)}
    assert "esptool.exe" not in routes["esptool"]["now"]["route"] and "usbipd" in routes["esptool"]["now"]["route"]
    assert routes["serial"]["target"]["disabled"] is True


@pytest.mark.parametrize("cfg", [
    {"hostenv": {"disable": []}}, {"hostenv": {"enable": ["interop"]}}, {"hostenv": {"disable": "nonsense"}},
    {"hostenv": {"interop": True, "disable": ["nonsense", "interop_force"]}}, {"hostenv": "interop"}, {"hostenv": {"disable": [1, None]}},
])
def test_overrides_cannot_widen(cfg):
    p = FIXTURES["wsl2-no-interop"]()
    rep = detect(p, config=cfg)
    assert rep["kind"] == "WSL2_NO_INTEROP" and rep["wsl"]["interop"]["usable"] is False and p.exe_calls() == []
    assert rep["overridden"] == []
    if "nonsense" in json.dumps(cfg):
        assert any("알 수 없는 hostenv.disable" in w for w in rep["warnings"])


def test_lazy_config_applies_hostenv_section(tmp_path, monkeypatch):
    cfg = tmp_path / "pipeline-config.yaml"
    cfg.write_text("hostenv:\n  disable: [interop]\n", encoding="utf-8")
    monkeypatch.setenv("PWEH_CONFIG", str(cfg))
    p = wsl2()
    rep = hostenv.detect(p)  # config=None → PWEH 설정의 hostenv 절만 읽는다
    assert rep["kind"] == "WSL2_NO_INTEROP" and rep["overridden"] == ["hostenv.disable.interop"] and p.exe_calls() == []
    cfg.write_text("hostenv:\n  disable: []\n# changed\n", encoding="utf-8")
    assert hostenv.detect(p)["kind"] == "WSL2_INTEROP"
    monkeypatch.setenv("PWEH_CONFIG", str(tmp_path / "missing.yaml"))
    rep = hostenv.detect(wsl2())
    assert rep["kind"] == "WSL2_INTEROP" and any("설정을 읽지 못해" in w for w in rep["warnings"])


def test_esptool_win_resolution_matches_esp_rules():
    p = wsl2(esptool=False)
    rep = detect(p, config={"tools": {"esptool_win": "/nonexistent/esptool.exe"}})
    e = rep["windows"]["tools"]["esptool_win"]
    assert e["present"] is False and e["source"] == "config" and "없음" in e["problem"]
    p = wsl2(esptool=False)
    p.paths.add("/mnt/c/tools/esptool.exe")
    e = detect(p, config={"tools": {"esptool_win": "C:\\tools\\esptool.exe"}})["windows"]["tools"]["esptool_win"]
    assert e == {"present": True, "path": "/mnt/c/tools/esptool.exe", "source": "config", "problem": None}
    p = wsl2(esptool=False, env={"PWEH_ESPTOOL_WIN": "/opt/x/esptool.exe"})
    p.paths.add("/opt/x/esptool.exe")
    p.not_executable.add("/opt/x/esptool.exe")
    e = detect(p)["windows"]["tools"]["esptool_win"]
    assert e["source"] == "env" and "실행 권한" in e["problem"]
    e = detect(wsl2(esptool=False))["windows"]["tools"]["esptool_win"]
    assert e == {"present": False, "path": None, "source": None, "problem": None}  # 도구 디렉터리 후보가 없으면 그냥 없음


# ---------------------------------------------------------------------------
# 추천 경로 (§9·§10)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", list(FIXTURES))
def test_routes_shape(name):
    routes = hostenv.recommend_routes(detect(FIXTURES[name]()))
    assert routes and routes[-1]["device"] == "block"
    for r in routes:
        assert set(r) == {"device", "label", "ref", "now", "target", "alternatives", "notes"}
        assert set(r["now"]) == {"route", "status", "available", "human_steps"}
        assert r["target"] is None or {"route", "phase"} <= set(r["target"])
        if r["now"]["route"] is None:
            assert r["now"]["status"].startswith(("없음", "거부")), r


def test_wsl2_interop_routes_never_offer_future_paths_as_now():
    routes = {r["device"]: r for r in hostenv.recommend_routes(detect(FIXTURES["wsl2-interop-bridged"]()))}
    ser = routes["serial"]
    assert "usbipd" in ser["now"]["route"] and "helper" not in ser["now"]["route"] and "헬퍼" not in ser["now"]["route"]
    assert ser["target"]["phase"] == "P2" and "pweh-serial-helper.exe" in ser["target"]["route"]
    assert any("--host-ip <Windows LAN IP>" in s for s in ser["now"]["human_steps"])
    assert any("세션 동안만" in s and "unbind" in s for s in ser["now"]["human_steps"])
    assert ser["now"]["available"] is False  # usbipd 가 없다
    esp = routes["esptool"]
    assert "esptool.exe" in esp["now"]["route"] and esp["now"]["status"] == "현행" and esp["now"]["available"] is True
    assert routes["openocd"]["target"]["phase"] == "P3" and "usbipd" in routes["openocd"]["now"]["route"]
    assert any("udev" in s for s in routes["openocd"]["now"]["human_steps"])
    assert routes["sdr"]["now"]["route"] is None and routes["sdr"]["target"]["phase"] == "P4"


@pytest.mark.parametrize("mode,possible,needle", [
    ("nat", True, None), ("mirrored", True, None), ("virtioproxy", True, None), ("consomme", True, "--host-ip 127.0.0.1"),
    ("bridged", True, "--host-ip <Windows LAN IP>"), ("none", False, None), ("wsl1", False, None), (None, True, None), ("future-mode", True, None),
])
def test_usbipd_attach_by_mode(mode, possible, needle):
    a = hostenv.usbipd_attach(mode)
    assert a["possible"] is possible
    if possible:
        assert a["command"].startswith("usbipd attach --wsl --busid <BUSID>")
        assert (needle in a["command"]) if needle else ("--host-ip" not in a["command"])
    else:
        assert a["command"] is None
    if mode in (None, "future-mode"):
        assert "nat 로 가정" in a["note"]


def test_consomme_fixture_routes_use_loopback_host_ip():
    routes = {r["device"]: r for r in hostenv.recommend_routes(detect(FIXTURES["wsl2-consomme"]()))}
    assert any("--host-ip 127.0.0.1" in s for s in routes["serial"]["now"]["human_steps"])


def test_routes_for_other_kinds():
    no = {r["device"]: r for r in hostenv.recommend_routes(detect(FIXTURES["wsl2-no-interop"]()))}
    assert no["serial"]["ref"] == "R7" and "interop 다시 켜기" in no["serial"]["alternatives"][0]
    assert "usbipd" in no["esptool"]["now"]["route"] and "esptool.exe" not in no["esptool"]["now"]["route"]
    w1 = {r["device"]: r for r in hostenv.recommend_routes(detect(FIXTURES["wsl1"]()))}
    assert "/dev/ttyS<n>" in w1["serial"]["now"]["route"] and w1["serial"]["now"]["status"] == "최선 노력"
    assert w1["openocd"]["now"]["route"] is None and "esptool.exe" in w1["esptool"]["now"]["route"]
    unk = hostenv.recommend_routes(detect(FIXTURES["wsl-unknown-version"]()))
    assert any("WSL 버전을 정하지 못했다" in n for n in unk[0]["notes"])
    nat = {r["device"]: r for r in hostenv.recommend_routes(detect(native_linux_brltty()))}
    steps = nat["serial"]["now"]["human_steps"]
    assert any("dialout" in s for s in steps) and any("brltty" in s for s in steps) and nat["serial"]["now"]["status"] == "현행"
    for name in ("windows-native",):
        rows = hostenv.recommend_routes(detect(FIXTURES[name]()))
        assert rows[0]["device"] == "all" and rows[0]["now"]["status"] == "거부" and "WSL" in rows[0]["notes"][0]
    rows = hostenv.recommend_routes(detect(FIXTURES["container-on-wsl-kernel"]()))
    assert rows[0]["ref"] == "R17" and "통과된 /dev 노드" in rows[0]["now"]["route"]
    mac = {r["device"]: r for r in hostenv.recommend_routes(detect(FIXTURES["macos-arm64"]()))}
    assert mac["serial"]["now"]["route"] is None and mac["serial"]["target"]["phase"] == "P5"


# ---------------------------------------------------------------------------
# 공개 도우미
# ---------------------------------------------------------------------------


def test_unsupported_platform_messages():
    for plat in ("win32", "cygwin", "msys"):
        msg = hostenv.unsupported_platform(plat)
        assert msg and "WSL2" in msg and "wsl.exe -d <배포판> -e" in msg and "`-u root` 는 넣지 마세요" in msg and repr(plat) in msg
    for plat in ("linux", "darwin"):
        assert hostenv.unsupported_platform(plat) is None
    assert hostenv.unsupported_platform() is None  # 시험 환경(리눅스)


def test_interop_helpers_on_reports():
    w1 = detect(FIXTURES["wsl1"]())
    assert hostenv.is_wsl(w1) and hostenv.interop_usable(w1)  # WSL1 도 interop 을 쓸 수 있다(방법 A)
    no = detect(FIXTURES["wsl2-no-interop"]())
    assert hostenv.is_wsl(no) and not hostenv.interop_usable(no) and "enabled 가 아님" in hostenv.interop_reason(no)
    nat = detect(native_linux_brltty())
    assert not hostenv.is_wsl(nat) and hostenv.interop_reason(nat) == "WSL 이 아님"


def test_ghost_port_rule_matches_esp():
    ports = [
        {"device": "/dev/ttyS0", "hwid": "n/a", "vid": None},
        SimpleNamespace(device="/dev/ttyS1", hwid=None, vid=None),
        {"device": "/dev/ttyACM0", "hwid": "USB VID:PID=303A:1001", "vid": 0x303A},
        {"device": "/dev/ttyS4", "hwid": "n/a", "vid": 0x1A86},  # vid 가 있으면 보인다
    ]
    visible, hidden = hostenv.split_ghost_ports(ports)
    assert hidden == 2 and [p["device"] for p in visible] == ["/dev/ttyACM0", "/dev/ttyS4"]


def test_wildcard_listeners_reads_proc_net_only():
    tcp = ("  sl  local_address rem_address   st tx_queue rx_queue\n"
           "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000\n"   # 0.0.0.0:8080 LISTEN
           "   1: 0100007F:0035 00000000:0000 0A 00000000:00000000\n"   # 127.0.0.1:53 — 루프백
           "   2: 00000000:0016 0200000A:C350 01 00000000:00000000\n")  # ESTABLISHED
    tcp6 = ("  sl  local_address remote_address st\n"
            "   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 0\n")
    p = FakeProbe(files={"/proc/net/tcp": tcp, "/proc/net/tcp6": tcp6})
    assert hostenv.wildcard_listeners(p) == [{"proto": "tcp6", "port": 22}, {"proto": "tcp", "port": 8080}]
    assert hostenv.wildcard_listeners(FakeProbe()) is None
    assert p.calls == []


def test_windows_com_ports_only_with_interop():
    p = wsl2()
    rep = detect(p)
    out = hostenv.windows_com_ports(rep, p)
    assert out["available"] and out["ports"] == [{"port": "COM3", "name": "USB Serial Device (COM3)", "service": "usbser", "status": "OK",
                                                  "vid": "0x303a", "pid": "0x1001"}]
    q = FIXTURES["wsl2-no-interop"]()
    out = hostenv.windows_com_ports(detect(q), q)
    assert out["available"] is False and out["ports"] == [] and q.exe_calls() == []


# ---------------------------------------------------------------------------
# esp ports: hostenv 를 쓰되 늦은 묶기 seam 은 그대로 (§13.1)
# ---------------------------------------------------------------------------


def test_esp_ports_use_hostenv_and_keep_seams(monkeypatch):
    from esp_mcp import ports

    p = wsl2(root="/win")
    monkeypatch.setattr(hostenv, "_default_probe", lambda: p)
    monkeypatch.setattr(hostenv, "_lazy_hostenv_section", lambda: {})
    assert ports.is_wsl() is True
    assert ports.interop_status() == {"wsl": True, "interop": True, "reason": None}
    assert p.exe_calls() == []  # esp 의 판정은 smoke 없는 규칙(install.sh 와 같음)
    assert ports.powershell_exe() == "/win/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
    # interop_status 는 ports.is_wsl 을 늦게 부른다 (시험이 바꿔 끼울 수 있다)
    monkeypatch.setattr(ports, "is_wsl", lambda: False)
    assert ports.interop_status()["wsl"] is False
    # 컨테이너 안에서는 WSL 커널이어도 WSL 이 아니다 (G6)
    monkeypatch.undo()  # ports.is_wsl 을 되돌린다
    c = FIXTURES["container-on-wsl-kernel"]()
    monkeypatch.setattr(hostenv, "_default_probe", lambda: c)
    monkeypatch.setattr(hostenv, "_lazy_hostenv_section", lambda: {})
    assert ports.is_wsl() is False and ports.interop_status()["interop"] is False
    off = FIXTURES["wsl2-no-interop"]()
    monkeypatch.setattr(hostenv, "_default_probe", lambda: off)
    st = ports.interop_status()
    assert st["wsl"] is True and st["interop"] is False and "enabled 가 아님" in st["reason"]


def test_esp_run_powershell_uses_drvfs_cwd(monkeypatch):
    import subprocess as sp

    from esp_mcp import ports

    p = wsl2(root="/win")
    monkeypatch.setattr(hostenv, "_default_probe", lambda: p)
    seen = {}

    def fake_run(argv, **kw):
        seen.update(argv=argv, cwd=kw.get("cwd"))
        return SimpleNamespace(returncode=0, stdout=b"ok", stderr=b"")

    monkeypatch.setattr(sp, "run", fake_run)
    monkeypatch.setattr(ports.os.path, "isdir", lambda d: d == "/win/c")
    rc, out, _err = ports.run_powershell("Write-Output 1", timeout=5)
    assert rc == 0 and out == "ok"
    assert seen["argv"][0] == "/win/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe" and seen["cwd"] == "/win/c"
    assert seen["argv"][1:4] == ["-NoProfile", "-NonInteractive", "-Command"] and seen["argv"][4].endswith("Write-Output 1")
    assert seen["argv"][4].startswith("$ProgressPreference='SilentlyContinue';")
    # powershell 을 못 찾으면 ToolMissing (seam: ports.powershell_exe)
    from pweh.errors import ToolMissing

    monkeypatch.setattr(ports, "powershell_exe", lambda: None)
    with pytest.raises(ToolMissing):
        ports.run_powershell("exit 0")


def test_esp_candidates_delegate_to_core(monkeypatch, tmp_path):
    from esp_mcp.esptool_cli import windows_exe_candidates

    from pweh.toolsdir import esptool_win_candidates

    monkeypatch.setenv("PWEH_ESPTOOL_WIN", "/opt/env/esptool.exe")
    got = windows_exe_candidates("/opt/cfg/esptool.exe", tmp_path)
    assert got == esptool_win_candidates("/opt/cfg/esptool.exe", "/opt/env/esptool.exe", tmp_path)
    assert [s for _, s in got] == ["config", "env", "pweh-tools", "pweh-tools"]
    monkeypatch.setenv("PWEH_ESPTOOL_WIN", "/opt/cfg/esptool.exe")  # 같은 값은 한 번만
    assert [s for _, s in windows_exe_candidates("/opt/cfg/esptool.exe", None)] == ["config"]


# ---------------------------------------------------------------------------
# 검토 후속 (F2–F5): $PATH 실행 파일, realpath, 일시 실패, C: 없음, windows_tools 끄기
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("planted,real", [
    ("/mnt/c/../../tmp/planted/usbipd.exe", "/tmp/planted/usbipd.exe"),  # drvfs 접두어로 시작하지만 '..' 로 밖을 가리킨다
    ("/mnt/c/Tools/usbipd.exe", "/mnt/c/Tools/usbipd.exe"),  # drvfs 아래지만 표준 위치가 아니다
])
def test_planted_path_usbipd_is_never_executed(planted, real):
    """F2: $PATH(which)로 찾은 usbipd.exe 는 어디에 있든 실행하지 않고 표시만 한다."""
    p = wsl2(usbipd=False)
    p.which_map["usbipd.exe"] = planted
    p.paths.add(planted)
    rep = detect(p)
    u = rep["windows"]["usbipd"]
    assert not any(_base(a) == "usbipd.exe" for a in p.calls), p.calls
    assert u["present"] is False and u["path"] is None and u["version"] is None and u["autobind_policies"] is None
    assert u["found_elsewhere"] == real
    assert any("실행하지 않았다" in w and real in w for w in rep["warnings"])
    assert "usbipd" not in hostenv.trusted_windows_exes(p)


def test_drvfs_containment_uses_realpath():
    p = FakeProbe(files={"/proc/mounts": mounts()}, realpaths={"/mnt/c/link/x.exe": "/tmp/elsewhere/x.exe"})
    assert hostenv._under_drvfs("/mnt/c/Tools/x.exe", p) is True
    assert hostenv._under_drvfs("/mnt/c/../../tmp/x.exe", p) is False  # '..' 를 푼 뒤 비교
    assert hostenv._under_drvfs("/mnt/c/link/x.exe", p) is False  # 밖을 가리키는 링크
    assert hostenv._under_drvfs("/mnt/cfake/x.exe", p) is False  # 접두어만 같은 다른 디렉터리
    assert hostenv._under_drvfs("/mnt/c", p) is False


def test_fixed_paths_resolving_outside_drvfs_are_not_trusted():
    """표준 위치의 usbipd.exe·powershell.exe 가 drvfs 밖으로 풀리면(링크) 믿지 않는다 — 실행하지 않는다."""
    p = wsl2(usbipd=True)
    p.realpaths["/mnt/c/Program Files/usbipd-win/usbipd.exe"] = "/tmp/evil/usbipd.exe"
    rep = detect(p)
    assert rep["windows"]["usbipd"]["present"] is False and not any(_base(a) == "usbipd.exe" for a in p.calls)
    q = wsl2()
    q.realpaths["/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"] = "/tmp/evil/powershell.exe"
    rep = detect(q)
    assert rep["windows"]["powershell"] is None and q.exe_calls() == [] and rep["wsl"]["interop"]["smoke"] == "no-powershell"
    assert hostenv.trusted_windows_exes(q) == {}


def _flaky(first, then):
    n = {"calls": 0}

    def answer(argv):
        n["calls"] += 1
        return first if n["calls"] == 1 else then

    answer.n = n  # type: ignore[attr-defined]
    return answer


def test_transient_wslpath_failure_is_not_sticky(monkeypatch):
    """F3: 한 번의 wslpath 시간 초과가 프로세스 수명 동안 interop 을 끄지 않는다 (실패는 NEGATIVE_TTL_S 만 기억)."""
    from esp_mcp import ports

    p = wsl2(mode="nat")
    flaky = _flaky((hostenv.RC_TIMEOUT, ""), (0, "\\\\wsl.localhost\\FixtureDistro\\\n"))
    p.runs["wslpath -w /"] = flaky
    monkeypatch.setattr(hostenv, "_default_probe", lambda: p)
    monkeypatch.setattr(hostenv, "_lazy_hostenv_section", lambda: {})
    st = ports.interop_status()
    assert st["interop"] is False and "wslpath" in st["reason"]
    p.t += hostenv.NEGATIVE_TTL_S - 1
    assert ports.interop_status()["interop"] is False and flaky.n["calls"] == 1  # 짧게는 기억한다
    p.t += 2
    assert ports.interop_status() == {"wsl": True, "interop": True, "reason": None}
    assert flaky.n["calls"] == 2
    p.t += 10_000
    assert ports.interop_status()["interop"] is True and flaky.n["calls"] == 2  # 성공은 계속 기억한다


def test_transient_c_mapping_failure_is_not_sticky():
    p = wsl2(mount_style="none")
    flaky = _flaky((1, ""), (0, "/mnt/c/\n"))
    p.runs["wslpath -u C:\\"] = flaky
    rep = detect(p)
    assert rep["wsl"]["drvfs_c"] is None and rep["windows"]["powershell"] is None and rep["kind"] == "WSL2_INTEROP"
    p.t += hostenv.NEGATIVE_TTL_S + 1
    rep = detect(p)
    assert rep["wsl"]["drvfs_c"] == "/mnt/c" and rep["windows"]["powershell"].endswith("/powershell.exe")
    assert rep["wsl"]["interop"]["smoke"] == "ok" and rep["windows"]["uac_enabled"] is True


def test_transient_wslinfo_failure_is_retried():
    p = wsl2(kernel="6.99.0-fixture-custom", mode="nat")
    flaky = _flaky((1, ""), (0, "nat\n"))
    p.runs["wslinfo --networking-mode"] = flaky
    rep = detect(p, smoke=False)
    assert rep["kind"] == "WSL_UNKNOWN" and rep["wsl"]["networking_mode"] is None
    p.t += 5
    assert detect(p, smoke=False)["kind"] == "WSL_UNKNOWN" and flaky.n["calls"] == 1
    p.t += hostenv.NEGATIVE_TTL_S
    rep = detect(p, smoke=False)
    assert rep["kind"] == "WSL2_INTEROP" and rep["wsl"]["networking_mode"] == "nat" and rep["wsl"]["version_source"] == "wslinfo"
    p.t += 10_000
    detect(p, smoke=False)
    assert flaky.n["calls"] == 2  # 성공한 뒤로는 정적 값으로 기억한다


def test_failed_smoke_has_short_negative_ttl():
    p = wsl2()
    p.runs["ps:smoke"] = _flaky((1, ""), (0, ""))
    assert detect(p)["kind"] == "WSL2_NO_INTEROP"
    p.t += 10
    assert detect(p)["kind"] == "WSL2_NO_INTEROP" and p.labels().count("ps:smoke") == 1
    p.t += hostenv.NEGATIVE_TTL_S
    rep = detect(p)
    assert rep["kind"] == "WSL2_INTEROP" and p.labels().count("ps:smoke") == 2


def test_missing_c_drive_keeps_interop(monkeypatch):
    """F4: C: 가 마운트되지 않아도(wslpath -u 'C:\\' 실패) interop 은 켜져 있다 — powershell·Windows 정보만 없다."""
    from esp_mcp import ports

    p = wsl2(mode="nat", mount_style="none", c_mapped=False)
    rep = detect(p)
    it = rep["wsl"]["interop"]
    assert rep["kind"] == "WSL2_INTEROP" and it["usable"] is True and it["wslpath"] is True and it["reason"] is None
    assert it["smoke"] == "no-powershell" and p.exe_calls() == []
    assert rep["wsl"]["drvfs_c"] is None and rep["windows"]["powershell"] is None and rep["windows"]["usbipd"]["present"] is None
    assert any("C: 드라이브" in w for w in rep["warnings"])
    esp = next(r for r in hostenv.recommend_routes(rep) if r["device"] == "esptool")
    assert "esptool.exe" in esp["now"]["route"] and esp["now"]["available"] is True  # 리눅스 쪽 esptool.exe 는 C: 없이 돈다
    monkeypatch.setattr(hostenv, "_default_probe", lambda: p)
    monkeypatch.setattr(hostenv, "_lazy_hostenv_section", lambda: {})
    assert ports.interop_status() == {"wsl": True, "interop": True, "reason": None}
    assert ports.powershell_exe() is None


def test_disabled_keys_helper(tmp_path, monkeypatch):
    assert hostenv.disabled_keys({"hostenv": {"disable": ["windows_tools", "nonsense"]}}) == {"windows_tools"}
    assert hostenv.disabled_keys({}) == set()
    cfg = tmp_path / "pipeline-config.yaml"
    cfg.write_text("hostenv:\n  disable: [interop, serial_helper]\n", encoding="utf-8")
    monkeypatch.setenv("PWEH_CONFIG", str(cfg))
    assert hostenv.disabled_keys() == {"interop", "serial_helper"}
    monkeypatch.setenv("PWEH_CONFIG", str(tmp_path / "missing.yaml"))
    assert hostenv.disabled_keys() == set()  # 설정을 읽지 못하면 빈 집합


def test_esp_find_windows_exe_honours_disable_windows_tools(workspace, monkeypatch):
    """F5: hostenv.disable: [windows_tools] 면 esp 는 Windows esptool.exe 를 찾지도 실행하지도 않는다(이유를 분명히)."""
    import yaml

    from esp_mcp import ports
    from esp_mcp import server as es
    from pweh.errors import ToolMissing
    from pweh.runtime import reset_runtimes

    cfg = yaml.safe_load(workspace["config"].read_text(encoding="utf-8"))
    cfg["hostenv"] = {"disable": ["windows_tools"]}
    workspace["config"].write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
    reset_runtimes()
    monkeypatch.setattr(ports, "interop_status", lambda: {"wsl": True, "interop": True, "reason": None})
    with pytest.raises(ToolMissing, match="windows_tools"):
        es._find_windows_exe()
    rep = es._backend_report("windows")
    assert rep["available"] is False and "windows_tools" in rep["error"]


def test_esp_owner_alive_uses_pid_alive(monkeypatch):
    """esp 소유 기록의 생존 확인은 pweh.procutil.pid_alive 를 쓴다 (아주 큰 pid 도 예외 없이 False)."""
    import os
    import socket

    from esp_mcp import server as es

    base = {"host": socket.gethostname(), "boot_id": None}
    assert es._owner_alive({**base, "pid": 2 ** 80}) is False  # 예전에는 OverflowError
    assert es._owner_alive({**base, "pid": 0}) is False and es._owner_alive({**base, "pid": "x"}) is False
    assert es._owner_alive({**base, "pid": os.getpid()}) is True
    seen = []
    monkeypatch.setattr(es, "pid_alive", lambda pid: seen.append(pid) or False)
    assert es._owner_alive({**base, "pid": 4242}) is False and seen == [4242]


def test_esp_run_powershell_refused_when_interop_disabled(monkeypatch):
    """hostenv.disable: [interop] 이면 esp 는 어떤 경로(예약 파일 확인 등)로도 powershell.exe 를 띄우지 않는다 — '확인 불가'가 된다."""
    import subprocess as sp

    from esp_mcp import ports, winproc
    from pweh.errors import ToolMissing

    def boom(*a, **k):  # pragma: no cover - 불리면 실패
        raise AssertionError("subprocess.run 이 불렸다")

    monkeypatch.setattr(sp, "run", boom)
    monkeypatch.setattr(hostenv, "_lazy_hostenv_section", lambda: {"hostenv": {"disable": ["interop"]}})
    with pytest.raises(ToolMissing, match="interop"):
        ports.run_powershell("exit 0")
    assert winproc.pids_alive([4242], ["esptool.exe"]) is None  # 예약 파일은 'held'(지우지 않음)로 남는다
    assert winproc.token_holders(["\\\\wsl.localhost\\x\\y.bin"], ["esptool.exe"]) is None
