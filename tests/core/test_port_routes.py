"""합성 route/전체 sibling. 실제 PnP·포트·sysfs 조회를 하지 않는다."""
import copy
import json
import os
import stat
from dataclasses import replace
from types import SimpleNamespace

import pytest

from pweh import ports as P, portidentity as I
from pweh.errors import PwehError, ValidationFailed

LINUX = {"kind": "NATIVE_LINUX"}
WINDOWS = {"kind": "WSL2_INTEROP", "wsl": {"interop": {"usable": True}}}


def st(ino=7):
    return SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_dev=3, st_ino=ino, st_rdev=os.makedev(166, 7))


def identity(ref="/dev/ttyACM7"):
    return I.PortIdentity(ref, "known", present=True, backend="linux", vid="303a", pid="1001",
                          serial="SYNTHETIC", usb_ancestor="devices/usb1/1-2", parent_instance="devices/usb1/1-2",
                          interface_number="0a", device_instance="devices/usb1/1-2/1-2:1.10/tty/ttyACM7")


def probe(ident=None, ino=7):
    return P.PortProbe(stat=lambda _: st(ino), realpath=lambda _: "/dev/ttyACM7", identity=lambda _: ident or identity())


def test_route_alias_immutable_json_and_continuity():
    a = P.resolve(LINUX, "/dev/serial/by-id/fixture", "serial-session", probe=probe())
    b = P.resolve(LINUX, "/dev/ttyACM7", "esptool", probe=probe())
    assert a.lock_key == b.lock_key == "tty:166:7"
    assert a.reset_risk == "wired"
    assert a.continuity_key() == b.continuity_key()
    out = a.to_dict(); out["identity"]["serial"] = "changed"; out["warnings"].append("mutation")
    assert a.identity.serial == "SYNTHETIC" and a.to_dict()["warnings"] == []
    assert set(a.approval_identity()) == {"backend", "lock_key", "device_id"}
    assert "node_identity" not in a.to_dict()


@pytest.mark.parametrize("ref", ["spy:///dev/ttyUSB0", "loop://?x=y", "/dev/../tmp/file", "/tmp/file", "COM01", "/dev/x\t"])
def test_bad_route_does_not_probe(ref):
    with pytest.raises(ValidationFailed):
        P.resolve(LINUX, ref, "serial-session", probe=P.PortProbe(identity=lambda _: pytest.fail("조회 금지")))


def test_loopback_key_and_unknown_continuity():
    unknown = P.PortProbe(identity=lambda x: I.unknown(x, "synthetic"))
    a = P.resolve(LINUX, "socket://127.0.0.2:9911", "serial-session", probe=unknown)
    b = P.resolve(LINUX, "rfc2217://[::1]:9911", "serial-session", probe=unknown)
    assert a.lock_key == b.lock_key == "net-loopback:9911"
    assert a.continuity_key() is b.continuity_key() is None
    assert P.resolve(LINUX, "loop://", "serial-session", probe=unknown).lock_key is None


def test_wsl1_com_tty_alias_and_helper_selection():
    q = P.PortProbe(stat=lambda _: st(), realpath=lambda x: x, identity=lambda x: I.unknown(x, "synthetic"))
    env = {"kind": "WSL1"}
    a = P.resolve(env, "COM3", "serial-session", probe=q)
    b = P.resolve(env, "/dev/ttyS3", "serial-session", probe=q)
    assert a.lock_key == b.lock_key == "win:COM3" and a.device_path == b.device_path
    for report, ref, purpose in [(env, "COM192", "serial-session"),
                                  (env, "COM3", "sigrok-serial"), (LINUX, "COM3", "esptool")]:
        with pytest.raises(ValidationFailed):
            P.resolve(report, ref, purpose, probe=q)


@pytest.mark.parametrize("kind,ref", [("WSL1", "COM192"), ("WSL1", "COM4096"),
                                     ("WSL2_INTEROP", "COM1"), ("WSL_UNKNOWN", "COM4096")])
def test_helper_routes_do_not_stat_com(kind, ref):
    q = P.PortProbe(stat=lambda _: pytest.fail("COM에 POSIX stat 금지"), identity=lambda x: I.unknown(x, "synthetic"))
    route = P.resolve({**WINDOWS, "kind": kind}, ref, "serial-session", probe=q, config={})
    assert route.backend == "win-helper" and route.side == "windows"
    assert route.device_path == ref and route.lock_key == f"win:{ref}" and route.node_identity is None


@pytest.mark.parametrize("disabled", ["interop", "serial_helper", "windows_tools"])
def test_helper_disabled_before_identity(disabled):
    with pytest.raises(ValidationFailed, match="disable"):
        P.resolve(WINDOWS, "COM3", "serial-session", config={"hostenv": {"disable": [disabled]}},
                  probe=P.PortProbe(identity=lambda _: pytest.fail("거부 뒤 조회 금지")))


def test_wsl1_missing_tty_never_falls_back_to_helper():
    def missing(_): raise FileNotFoundError()
    with pytest.raises(ValidationFailed, match="문자장치"):
        P.resolve({**WINDOWS, "kind": "WSL1"}, "COM3", "serial-session", probe=P.PortProbe(stat=missing))


def test_fresh_revalidation_rejects_inode_identity_loss_and_keeps_strength_out():
    route = P.resolve(LINUX, "/dev/ttyACM7", "serial-session", probe=probe())
    for q in (probe(ino=8), probe(I.unknown("x", "query_failed")), probe(replace(identity(), serial="other"))):
        with pytest.raises(PwehError, match="route_changed"):
            P.revalidate(route, env=LINUX, probe=q)
    fresh = P.revalidate(route, env=LINUX, probe=probe(replace(identity(), status="unknown", reasons=("duplicate",))))
    assert fresh.approval_identity() == route.approval_identity()


def windows_route():
    parent = "USB\\VID_303A&PID_1001\\SYNTHETIC"
    ident = I.PortIdentity("COM31", "known", present=True, backend="windows", usb_ancestor=parent,
                          parent_instance=parent, device_instance=parent + "-child", vid="303a", pid="1001",
                          serial="SYNTHETIC", interface_number="02")
    return P.resolve(WINDOWS, "COM31", "esptool", probe=P.PortProbe(identity=lambda _: ident))


def win_scope():
    parent = windows_route().identity.usb_ancestor
    def node(ident, par, com=None, cls="USB"):
        return {"instance_id": ident, "parent": par, "parent_state": "ok", "com": com, "pnp_class": cls}
    nodes = [node(parent, "HTREE\\ROOT\\0"), node(parent + "&MI_00", parent),
             node(parent + "&MI_02", parent, "COM31", "Ports"),
             node("USB\\VID_1234&PID_5678\\OTHER", "HTREE\\ROOT\\0")]
    snap = {"present_count": len(nodes), "nodes": nodes, "errors": []}
    return {"schema": "pweh.pnp-usb-scope/v1", "snapshots": [snap, copy.deepcopy(snap)]}


def test_default_windows_scope_includes_non_com_and_succeeds(monkeypatch):
    route = windows_route()
    calls = []
    def runner(config, *, script):
        calls.append((config, script)); return json.dumps(win_scope())
    monkeypatch.setattr(I, "_windows_output", runner)
    keys = P.reset_scope(route, whole_device=True, config={"synthetic": True})
    assert "win:COM31" in keys and any("MI_00" in x for x in keys)
    assert not any("OTHER" in x for x in keys)
    assert calls == [({"synthetic": True}, I.PS_USB_SCOPE)]


@pytest.mark.parametrize("fault", ["old", "gap", "changed", "count", "duplicate", "cycle", "unknown-com", "errors", "large"])
def test_windows_scope_partial_never_complete(fault):
    data = win_scope()
    a = data["snapshots"][0]
    if fault == "old": data = []
    elif fault == "gap": a["nodes"][1]["parent"] = "MISSING"
    elif fault == "changed": a["nodes"][1]["instance_id"] += "CHANGED"
    elif fault == "count": a["present_count"] += 1
    elif fault == "duplicate": a["nodes"][1] = a["nodes"][0]
    elif fault == "cycle": a["nodes"][0]["parent"] = a["nodes"][1]["instance_id"]
    elif fault == "unknown-com":
        for s in data["snapshots"]: s["nodes"][1]["pnp_class"] = "Ports"
    elif fault == "errors": a["errors"] = ["query failed"]
    raw = " " * (I.MAX_OUTPUT + 1) if fault == "large" else json.dumps(data)
    result = I.parse_windows_scope(windows_route(), raw)
    assert not result.complete and result.keys == () and result.reasons


def sysfs_scope(tmp_path):
    root = tmp_path / "sys"
    parent = root / "devices/usb1/1-2"
    parent.mkdir(parents=True)
    for name, value in {"idVendor": "303a", "idProduct": "1001", "serial": "SYNTHETIC", "bConfigurationValue": "1", "bNumInterfaces": "2"}.items():
        (parent / name).write_text(value)
    for number in (0, 10):
        interface = parent / f"1-2:1.{number}"
        interface.mkdir(); (interface / "bInterfaceNumber").write_text(f"{number:02x}")
    tty = parent / "1-2:1.10/ttyUSB7/tty/ttyUSB7"
    tty.mkdir(parents=True); (tty / "dev").write_text("166:7")
    cls = root / "class/tty"; cls.mkdir(parents=True)
    (cls / "ttyUSB7").symlink_to(tty)
    route = P.resolve(LINUX, "/dev/ttyACM7", "esptool", probe=probe())
    return root, parent, cls, tty, route


def test_linux_scope_has_complete_interfaces_and_deep_tty(tmp_path):
    root, parent, cls, tty, route = sysfs_scope(tmp_path)
    (cls / "alias").symlink_to(tty)
    result = P.probe_siblings(route, sysfs_root=root, stat_port=lambda _: st())
    assert result.complete and result.keys == ("tty:166:7", "usbif:1-2:1.0", "usbif:1-2:1.10")
    assert P.reset_scope(route, whole_device=True, siblings_provider=lambda _: result) == result.keys


@pytest.mark.parametrize("fault", ["count", "config", "mi", "escape", "dev", "inode", "serial", "large"])
def test_linux_scope_incomplete_is_rejected(tmp_path, fault):
    root, parent, cls, tty, route = sysfs_scope(tmp_path)
    if fault == "count": (parent / "bNumInterfaces").write_text("3")
    if fault == "config": (parent / "bConfigurationValue").write_text("2")
    if fault == "mi": (parent / "1-2:1.10/bInterfaceNumber").write_text("01")
    if fault == "escape": (cls / "outside").symlink_to(tmp_path)
    if fault == "dev": (tty / "dev").write_text("invalid")
    if fault == "serial": (parent / "serial").write_text("replacement")
    if fault == "large": (parent / "serial").write_text("x" * 4097)
    result = P.probe_siblings(route, sysfs_root=root, stat_port=lambda _: st(8 if fault == "inode" else 7))
    assert not result.complete
    with pytest.raises(PwehError, match="port_scope_unknown"):
        P.reset_scope(route, whole_device=True, siblings_provider=lambda _: result)


def test_scope_changes_during_second_read(tmp_path, monkeypatch):
    root, parent, cls, tty, route = sysfs_scope(tmp_path)
    original = I.Path.open
    calls = []
    def changing(path, *args, **kwargs):
        if path == parent / "bNumInterfaces":
            calls.append(1)
            if len(calls) == 2:
                with original(path, "w") as stream: stream.write("3")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(I.Path, "open", changing)
    assert not P.probe_siblings(route, sysfs_root=root, stat_port=lambda _: st()).complete


def test_usb_hints_preserve_generic_uncertainty():
    assert P.usb_device_info("303a", "1001")["reset_wiring"] == "chip-reset-on-lines"
    assert P.usb_device_info(0x10c4, 0xea60)["reset_wiring"] == "unknown"
    value = P.usb_device_info("303a", "1001"); value["reset_wiring"] = "changed"
    assert P.usb_device_info("303a", "1001")["reset_wiring"] != "changed"


def test_explicit_holder_scan_empty_missing_and_mac(tmp_path):
    route = P.resolve(LINUX, "/dev/ttyACM7", "serial-session", probe=probe())
    empty = tmp_path / "proc"; empty.mkdir()
    assert P.check_holders(route, env=LINUX, proc_root=empty)["busy_check"] == "proc-fd"
    with pytest.raises(PwehError, match="port_holders_unknown"):
        P.check_holders(route, env=LINUX, proc_root=tmp_path / "missing")
    assert P.check_holders(route, env={"kind": "MACOS"}, proc_root=empty)["busy_check"] == "portlock-only"


def test_synthetic_proc_fd_points_to_test_created_pty(tmp_path):
    import pty
    from pweh.errors import Busy
    master, keeper = pty.openpty()
    try:
        tty = os.ttyname(keeper)
        route = P.resolve(LINUX, tty, "serial-session", probe=P.PortProbe(identity=lambda p: I.PortIdentity(p)))
        root = tmp_path / "proc"; fd = root / "123456789" / "fd"; fd.mkdir(parents=True)
        (fd / "3").symlink_to(tty)
        with pytest.raises(Busy) as err:
            P.check_holders(route, env=LINUX, proc_root=root)
        assert err.value.data["pids"] == [123456789]
        (fd / "3").unlink()
        own = root / str(os.getpid()) / "fd"; own.mkdir(parents=True)
        (own / "3").symlink_to(tty)
        assert P.check_holders(route, env=LINUX, proc_root=root)["busy_check"] == "proc-fd"
    finally:
        os.close(keeper); os.close(master)


def test_linux_scope_deadline_after_last_unrelated_tty(tmp_path, monkeypatch):
    root, parent, cls, tty, route = sysfs_scope(tmp_path)
    unrelated = root / "devices/virtual/tty/fixture"; unrelated.mkdir(parents=True)
    last = cls / "zz-unrelated"; last.symlink_to(unrelated)
    original = I.Path.resolve; visits = []; clock = [0.0]
    def slow(path, *args, **kwargs):
        value = original(path, *args, **kwargs)
        if path == last:
            visits.append(1)
            if len(visits) == 2: clock[0] = 6.0
        return value
    monkeypatch.setattr(I.Path, "resolve", slow)
    monkeypatch.setattr(I.time, "monotonic", lambda: clock[0])
    result = P.probe_siblings(route, sysfs_root=root, stat_port=lambda _: st())
    assert len(visits) == 2 and not result.complete and "sysfs_scope_limit" in result.reasons


def test_windows_query_and_parse_share_deadline(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(I.time, "monotonic", lambda: clock[0])
    def slow():
        clock[0] = 6.0
        return json.dumps(win_scope())
    result = P.probe_siblings(windows_route(), windows_runner=slow)
    assert not result.complete and "pnp_scope_time_limit" in result.reasons


def test_list_preserves_rows_and_reports_helper_com_route():
    local = [{"device": "/dev/ttyACM7", "description": "synthetic", "hwid": "USB", "vid": 0x303a},
             {"device": "/dev/ttyS0", "hwid": "n/a", "vid": None}]
    win = {"available": True, "ports": [{"port": "COM31", "service": "usbser"}], "note": None}
    q = P.PortProbe(stat=lambda _: st(), realpath=lambda p: p,
                    identity=lambda p: windows_route().identity if P.parse_win_com(p) else identity())
    locks = SimpleNamespace(held_by=lambda key: {"state": "awaiting_approval", "key": key})
    result = P.list_serial(WINDOWS, probe=q, local_provider=lambda **k: local, windows_provider=lambda: win, locks=locks)
    assert result["env_kind"] == "WSL2_INTEROP" and result["local"]["hidden_legacy_ports"] == 1
    assert result["local"]["ports"][0]["description"] == "synthetic"
    row = result["windows"]["ports"][0]
    assert row["service"] == "usbser" and row["route"]["backend"] == "win-helper"
    assert row["device_id"] == windows_route().device_id and row["held_by"]["key"] == "win:COM31"
