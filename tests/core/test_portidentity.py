"""Windows 고정 JSON·합성 sysfs의 읽기 전용 식별. 실제 포트/PnP 조회 없음."""
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from pweh import portidentity as P


def rows(serial='020000000001', mi='00'):
    parent = 'USB\\VID_303A&PID_4001\\' + serial
    child = 'USB\\VID_303A&PID_4001&MI_' + mi + '\\fixture'
    return [{'port': 'COM31', 'nodes': [{'instance_id': child, 'parent': parent, 'present': True, 'location_paths': ['child']},
                                      {'instance_id': parent, 'parent': 'ROOT\\USB', 'present': True, 'location_paths': ['usb/1-2']}]}]


def test_windows_composite_parent_is_identity():
    a = P.parse_windows('COM31', json.dumps(rows()))
    b = P.parse_windows('com31', json.dumps(rows(mi='01')))
    assert a.status == b.status == 'known' and a.serial == '020000000001'
    assert a.parent_instance == b.parent_instance and a.interface_number != b.interface_number
    assert a.location_paths == ('usb/1-2',)


@pytest.mark.parametrize('fault', ['missing', 'duplicate', 'ghost', 'cycle', 'gap', 'large', 'bad-type'])
def test_windows_malformed_is_unknown(fault):
    data = rows()
    if fault == 'missing': data[0]['nodes'].pop()
    if fault == 'duplicate': data += data[:]
    if fault == 'ghost': data[0]['nodes'][1]['present'] = False
    if fault == 'cycle': data[0]['nodes'][1] = data[0]['nodes'][0]
    if fault == 'gap': data[0]['nodes'][0]['parent'] = 'unexpected'
    if fault == 'bad-type': data[0]['nodes'][1]['location_paths'] = 'bad'
    raw = json.dumps(data) if fault != 'large' else ' ' * (P.MAX_OUTPUT + 1)
    assert P.parse_windows('COM31', raw).status == 'unknown'


def test_location_tail_not_claimed_serial():
    found = P.parse_windows('COM31', json.dumps(rows(serial='6&1234&0&2')))
    assert found.status == 'known' and found.serial is None and found.serial_basis == 'location-derived'


@pytest.mark.parametrize('value', ['X020000000001', '02:00:00:00:00:01junk', '02-00:00-00:00-01', '02000000000g'])
def test_mac_has_strict_shape(value):
    assert P.mac_text(value) is None


@pytest.mark.parametrize('endpoint', [None, 'socket://127.0.0.1:9000', 'rfc2217://[::1]:9000', 'tcp-raw/localhost/9000', '1.7', '303a.1001'])
def test_unresolved_route_does_not_call_runner(endpoint):
    result = P.probe_identity(endpoint, runner=lambda: pytest.fail('OS 조회 금지'))
    assert result.status == 'unknown'


def test_exact_loop_memory_only():
    assert P.probe_identity('loop://').kind == 'memory'
    assert P.probe_identity('loop://?logging=debug').status == 'unknown'


def sysfs(tmp_path):
    root = tmp_path / 'sys'; root.mkdir()
    usb = root / 'devices' / 'usb1' / '1-2'; usb.mkdir(parents=True)
    tty = usb / '1-2:1.0' / 'ttyACM0'; tty.mkdir(parents=True)
    for name, text in [('idVendor', '303a'), ('idProduct', '4001'), ('serial', '020000000001')]:
        (usb / name).write_text(text)
    (usb / '1-2:1.0' / 'bInterfaceNumber').write_text('00')
    dev = root / 'dev' / 'char' / '166:0'; dev.mkdir(parents=True)
    (dev / 'device').symlink_to(tty)
    return root, usb


def portstat(_):
    return SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_rdev=os.makedev(166, 0), st_ino=1)


def test_linux_sysfs_without_port_open(tmp_path):
    root, usb = sysfs(tmp_path)
    found = P.probe_identity('/dev/ttyACM0', sysfs_root=root, stat_port=portstat)
    assert found.status == 'known' and found.serial == '020000000001' and found.tty_devnum == (166, 0)
    assert found.interface_number == '00'


def test_linux_alias_change_rejected(tmp_path):
    root, usb = sysfs(tmp_path)
    calls = []
    def changing(path):
        calls.append(path)
        s = portstat(path); s.st_ino = len(calls)
        return s
    assert P.probe_identity('/dev/fixture', sysfs_root=root, stat_port=changing).status == 'unknown'


@pytest.mark.parametrize('fault', ['escape', 'size', 'missing-parent', 'not-char'])
def test_linux_boundaries(tmp_path, fault):
    root, usb = sysfs(tmp_path)
    statfn = portstat
    if fault == 'escape':
        (usb / 'serial').unlink(); (usb / 'serial').symlink_to(tmp_path / 'outside')
        (tmp_path / 'outside').write_text('must-not-read')
    if fault == 'size': (usb / 'serial').write_bytes(b'x' * 4097)
    if fault == 'missing-parent': (usb / 'idVendor').unlink()
    if fault == 'not-char': statfn = lambda p: SimpleNamespace(st_mode=stat.S_IFREG, st_rdev=0)
    assert P.probe_identity('/dev/fixture', sysfs_root=root, stat_port=statfn).status == 'unknown'


def test_linux_same_topology_attribute_replug(tmp_path, monkeypatch):
    root, usb = sysfs(tmp_path)
    original = Path.open
    reads = []
    def changing(path, *args, **kwargs):
        if path == usb / 'serial':
            reads.append(1)
            if len(reads) == 2:
                with original(path, 'w') as out: out.write('replacement-fixture')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', changing)
    found = P.probe_identity('/dev/fixture', sysfs_root=root, stat_port=portstat)
    assert found.status == 'unknown' and 'usb_identity_changed' in found.reasons


def test_windows_pipe_survivor_does_not_block_cleanup(tmp_path, monkeypatch):
    """가짜 interop 부모가 끝난 뒤 자식이 pipe를 잡아도 reader close가 무한 대기하지 않는다."""
    import signal
    import subprocess
    import sys
    import time
    from pweh import hostenv
    pidfile = tmp_path / 'child.pid'
    original = subprocess.Popen
    script = '''import os, sys, time
pid = os.fork()
if pid == 0:
 os.setsid()
 with open(sys.argv[1], 'w') as out: out.write(str(os.getpid()))
 time.sleep(30)
else:
 os._exit(0)
'''
    def launch(argv, **kwargs):
        assert argv[-1] == P.PS_IDENTITIES
        return original([sys.executable, '-c', script, str(pidfile)], **kwargs)
    monkeypatch.setattr(hostenv, 'disabled_keys', lambda config: set())
    monkeypatch.setattr(hostenv, 'powershell_path', lambda: '/synthetic/powershell.exe')
    monkeypatch.setattr(P.subprocess, 'Popen', launch)
    monkeypatch.setattr(P, 'PNP_TIMEOUT_S', 0.3)
    start = time.monotonic()
    try:
        with pytest.raises(ValueError, match='pnp_timeout_windows_child_unverified'):
            P._windows_output({})
        assert time.monotonic() - start < 2
    finally:
        if pidfile.exists():
            os.kill(int(pidfile.read_text()), signal.SIGKILL)
