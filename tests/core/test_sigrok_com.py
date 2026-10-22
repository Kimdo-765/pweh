"""고정 OLS 명령과 합성 COM route. 실제 PnP·포트·Windows 프로세스를 쓰지 않는다."""

from dataclasses import FrozenInstanceError, replace
import os
import stat
from types import SimpleNamespace

import pytest

from pweh import ports
from pweh.errors import PwehError, ValidationFailed
from pweh.portidentity import PortIdentity, unknown
from pweh.sigrok_com import ComCommand, DRIVER, PROFILE_ID, PROFILE_SHA256, from_argv_tail


WINDOWS = {"kind": "WSL2_INTEROP", "wsl": {"interop": {"usable": True}}}


def _identity(conn="COM31", *, wired=False):
    vid, pid = ("303a", "1001") if wired else ("10c4", "ea60")
    parent = f"USB\\VID_{vid.upper()}&PID_{pid.upper()}\\SYNTHETIC"
    return PortIdentity(conn, "known", present=True, backend="windows", vid=vid, pid=pid,
                        usb_ancestor=parent, parent_instance=parent,
                        device_instance=parent + "-child", interface_number="00",
                        serial="SYNTHETIC", observed_at=0)


def _probe(identity=None, calls=None):
    def observe(conn):
        if calls is not None:
            calls.append(conn)
        return identity or _identity(conn)
    return ports.PortProbe(
        identity=observe,
        stat=lambda _: pytest.fail("COM 경로에 POSIX stat 금지"),
        realpath=lambda _: pytest.fail("COM 경로에 POSIX realpath 금지"),
    )


@pytest.mark.parametrize("mode", ["scan", "show"])
@pytest.mark.parametrize("conn,canonical", [("COM1", "COM1"), ("com10", "COM10"),
                                           ("Com4096", "COM4096")])
def test_closed_command_canonical_roundtrip_and_approval(mode, conn, canonical):
    command = ComCommand(PROFILE_ID, mode, conn)
    assert command.conn == canonical
    assert command.argv_tail == (f"--driver=ols:conn={canonical}", "--dont-scan", f"--{mode}")
    assert from_argv_tail(command.argv_tail) == command
    assert command.approval_identity() == {
        "profile_id": "ols-serial-v1", "profile_sha256": PROFILE_SHA256,
        "driver": "ols", "mode": mode, "conn": canonical,
    }
    assert command.profile_sha256 == PROFILE_SHA256 and DRIVER == "ols"


def test_command_is_frozen_and_approval_projection_cannot_change_it():
    first = ComCommand(PROFILE_ID, "scan", "COM31")
    with pytest.raises(FrozenInstanceError):
        first.conn = "COM32"
    projection = first.approval_identity()
    projection["conn"] = "COM32"
    assert first.conn == "COM31"
    assert len(PROFILE_SHA256) == 64 and set(PROFILE_SHA256) <= set("0123456789abcdef")
    for other in (ComCommand(PROFILE_ID, "show", "COM31"), ComCommand(PROFILE_ID, "scan", "COM32")):
        assert first.approval_identity() != other.approval_identity()
        assert first.profile_sha256 == other.profile_sha256


@pytest.mark.parametrize("conn", [None, True, 1, "", "COM0", "COM01", "COM4097", "COM99999",
                                  " COM1", "COM1 ", "COM1\n", "COM1\x00", "COM１", "ＣＯＭ1",
                                  "\\\\.\\COM1", "/dev/ttyACM1", "1.2", "1234.5678",
                                  "socket://127.0.0.1:1", "COM1:serialcomm=1/8n1", "x" * 100000])
def test_invalid_conn_has_fixed_error_without_raw_input(conn):
    with pytest.raises(ValidationFailed) as exc:
        ComCommand(PROFILE_ID, "scan", conn)
    assert exc.value.to_dict() == {
        "code": "sigrok_com_invalid", "message": "고정 OLS profile의 scan/show와 COM1–COM4096만 허용합니다.",
    }


@pytest.mark.parametrize("profile,mode", [(None, "scan"), (True, "scan"), ("p-ols", "scan"),
                                         (PROFILE_ID, None), (PROFILE_ID, True),
                                         (PROFILE_ID, "SCAN"), (PROFILE_ID, "capture"),
                                         (PROFILE_ID, "scan --time=1")])
def test_profile_and_mode_are_not_arbitrary_strings(profile, mode):
    with pytest.raises(ValidationFailed, match="sigrok_com_invalid"):
        ComCommand(profile, mode, "COM31")


@pytest.mark.parametrize("tail", [
    None, [], ["--driver=ols:conn=COM31", "--dont-scan", "--scan"],
    ("--version",), ("--list-supported",),
    ("--driver=ols:conn=COM31", "--scan"),
    ("--driver=ols:conn=COM31", "--dont-scan", "--scan", "--show"),
    ("--driver=ols:conn=com31", "--dont-scan", "--scan"),
    ("--driver=p-ols:conn=COM31", "--dont-scan", "--scan"),
    ("--driver=ols:conn=COM31:serialcomm=9600/8n1", "--dont-scan", "--scan"),
    ("--driver=ols:conn=COM31", "--scan", "--dont-scan"),
    ("-d=ols:conn=COM31", "--dont-scan", "--scan"),
    ("--driver=ols:conn=COM31", "--dont-scan=true", "--scan"),
    ("--driver=ols:conn=COM31", "--dont-scan", "--scan\n"),
    (b"--driver=ols:conn=COM31", "--dont-scan", "--show"),
    ("--driver=ols:conn=" + "x" * 100000, "--dont-scan", "--show"),
])
def test_process_tail_admission_rejects_aliases_extensions_and_noncanonical_values(tail):
    with pytest.raises(ValidationFailed, match="sigrok_com_invalid"):
        from_argv_tail(tail)


@pytest.mark.parametrize("kind", ["WSL1", "WSL2_INTEROP", "WSL_UNKNOWN"])
@pytest.mark.parametrize("conn", ["COM1", "COM4096"])
def test_sigrok_com_route_is_windows_exe_and_never_ttys_or_helper(kind, conn):
    calls = []
    route = ports.resolve({**WINDOWS, "kind": kind}, conn.lower(), "sigrok-serial",
                          config={}, probe=_probe(calls=calls))
    assert (route.backend, route.side, route.device_path, route.lock_key) == (
        "win-exe", "windows", conn, f"win:{conn}")
    assert route.ref == conn and route.node_identity is None and calls == [conn]
    assert route.reset_risk == "possible"


@pytest.mark.parametrize("env", [
    {"kind": "WSL1"}, {"kind": "WSL2_INTEROP"},
    {"kind": "WSL2_INTEROP", "wsl": {"interop": {"usable": False}}},
    {**WINDOWS, "kind": "WSL2_NO_INTEROP"}, {**WINDOWS, "kind": "NATIVE_LINUX"},
    {**WINDOWS, "kind": "MACOS"}, {**WINDOWS, "kind": "CONTAINER"},
    {**WINDOWS, "kind": "NATIVE_WINDOWS"}, {**WINDOWS, "kind": "CYGWIN"},
    {**WINDOWS, "kind": "MSYS"},
])
def test_sigrok_com_environment_rejection_precedes_identity(env):
    with pytest.raises(ValidationFailed):
        ports.resolve(env, "COM31", "sigrok-serial", config={},
                      probe=ports.PortProbe(identity=lambda _: pytest.fail("거부 뒤 조회 금지")))


@pytest.mark.parametrize("disabled", ["interop", "windows_tools"])
def test_sigrok_com_disabled_before_identity(disabled):
    with pytest.raises(ValidationFailed, match="disable"):
        ports.resolve(WINDOWS, "COM31", "sigrok-serial",
                      config={"hostenv": {"disable": [disabled]}},
                      probe=ports.PortProbe(identity=lambda _: pytest.fail("거부 뒤 조회 금지")))


def test_disabled_serial_helper_does_not_disable_independent_sigrok_exe():
    report = {**WINDOWS, "windows": {"serial_helper": {"disabled": True}}}
    route = ports.resolve(report, "COM31", "sigrok-serial", probe=_probe(),
                          config={"hostenv": {"disable": ["serial_helper"]}})
    assert route.backend == "win-exe"


def test_windows_com_uses_same_lease_identity_as_other_consumers():
    routes = [ports.resolve(WINDOWS, "COM31", purpose, probe=_probe(), config={})
              for purpose in ("sigrok-serial", "esptool", "serial-session")]
    assert {route.lock_key for route in routes} == {"win:COM31"}
    assert len({route.device_id for route in routes}) == 1
    assert [route.backend for route in routes] == ["win-exe", "win-exe", "win-helper"]


@pytest.mark.parametrize("changed", ["device", "parent", "interface", "unknown", "disabled"])
def test_sigrok_com_revalidation_rejects_changed_identity_or_environment(changed):
    original = _identity()
    route = ports.resolve(WINDOWS, "COM31", "sigrok-serial", probe=_probe(original), config={})
    observed = original
    config = {}
    if changed == "device":
        observed = replace(original, device_instance=original.device_instance + "-new")
    elif changed == "parent":
        observed = replace(original, parent_instance=original.parent_instance + "-new")
    elif changed == "interface":
        observed = replace(original, interface_number="01")
    elif changed == "unknown":
        observed = unknown("COM31", "synthetic_missing")
    elif changed == "disabled":
        config = {"hostenv": {"disable": ["windows_tools"]}}
    with pytest.raises(PwehError, match="route_changed"):
        ports.revalidate(route, env=WINDOWS, probe=_probe(observed), config=config)


def test_protocol_profile_does_not_replace_wired_reset_scope_evidence():
    command = ComCommand(PROFILE_ID, "scan", "COM31")
    ordinary = ports.resolve(WINDOWS, command.conn, "sigrok-serial", probe=_probe(), config={})
    wired = ports.resolve(WINDOWS, command.conn, "sigrok-serial", probe=_probe(_identity(wired=True)), config={})
    assert ordinary.reset_risk == "possible" and wired.reset_risk == "wired"
    assert ports.reset_scope(ordinary) == ("win:COM31",)
    scope = ports.SiblingScope(("win:COM31", "win:COM32"), wired.identity.usb_ancestor, True)
    assert ports.reset_scope(wired, whole_device=True, siblings_provider=lambda _: scope) == scope.keys
    with pytest.raises(PwehError, match="port_scope_unknown"):
        ports.reset_scope(wired, whole_device=True, siblings_provider=lambda _: replace(scope, complete=False))


def test_sigrok_local_tty_route_remains_posix_without_windows_dependency():
    node = SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_dev=3, st_ino=9, st_rdev=os.makedev(166, 7))
    probe = ports.PortProbe(stat=lambda _: node, realpath=lambda p: p,
                            identity=lambda p: PortIdentity(p, backend="linux"))
    route = ports.resolve({"kind": "NATIVE_LINUX"}, "/dev/ttyACM7", "sigrok-serial", probe=probe, config={})
    assert route.backend == "posix-tty" and route.lock_key == "tty:166:7" and route.node_identity == (3, 9, node.st_rdev)
