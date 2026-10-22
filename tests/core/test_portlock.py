"""격리 namespace/runtime에서 OS 배타·취소 인계·role 파일 경계를 검증한다."""
import errno
import gc
import json
import os
import signal
import subprocess
import sys
import threading
import uuid

import pytest

from pweh import portlock as L, ports as P
from pweh.errors import Busy, PwehError
from pweh.portidentity import PortIdentity


@pytest.fixture
def manager(tmp_path):
    m = L.PortLockManager(namespace="pweh-unit-" + uuid.uuid4().hex, runtime_root=tmp_path / "runtime")
    yield m
    for lease in list(m._leases.values()):
        lease.close()


def owner():
    return L.PortOwner("synthetic", "case-unit", "/dev/synthetic")


def test_owner_metadata_and_strong_reference(manager):
    lease = manager.acquire(["tty:7:8"], owner=owner())
    lease.set_state("awaiting_approval")
    token = lease._token
    assert manager.held_by("tty:7:8")["state"] == "awaiting_approval"
    del lease; gc.collect()
    with pytest.raises(Busy): manager.acquire(["tty:7:8"], owner=owner())
    manager._leases[token].close()
    assert manager.held_by("tty:7:8") is None
    # 오래된 표시 JSON만으로 busy를 만들지 않는다.
    manager._records.put(manager._name("tty:7:8"), {"schema": "pweh.port-owner/v1", "key": "tty:7:8", "state": "orphan"})
    assert manager.held_by("tty:7:8") is None


def test_all_or_none_sorted_and_orphan_not_expired(manager):
    held = manager.acquire(["b"], owner=owner())
    with pytest.raises(Busy): manager.acquire(["a", "b"], owner=owner())
    free = manager.acquire(["a"], owner=owner()); free.close()
    held.set_state("orphan")
    with pytest.raises(Busy): manager.acquire(["b"], owner=owner())
    held.close()
    lease = manager.acquire(["b", "a", "a"], owner=owner())
    assert lease.keys == ("a", "b")
    lease.close(); lease.close()


def test_missing_owner_remains_busy(manager):
    lease = manager.acquire(["x"], owner=owner())
    path = manager.runtime_root / "port-owners" / manager._name("x")
    path.unlink()
    assert manager.held_by("x")["state"] == "unknown"
    with pytest.raises(Busy): manager.acquire(["x"], owner=owner())
    lease.close()


def test_different_process_and_workspace_share_kernel_lock(manager, tmp_path):
    code = '''import sys
from pathlib import Path
from pweh.portlock import PortLockManager,PortOwner
m=PortLockManager(namespace=sys.argv[1],runtime_root=Path(sys.argv[2]))
l=m.acquire(["tty:99:8"],owner=PortOwner("child","unit","synthetic"))
print("ready",flush=True)
sys.stdin.readline()
'''
    child = subprocess.Popen([sys.executable, "-c", code, manager.namespace, str(tmp_path / "other-workspace")],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "ready"
        with pytest.raises(Busy): manager.acquire(["tty:99:8"], owner=owner())
        child.kill(); child.wait(timeout=5)
        lease = manager.acquire(["tty:99:8"], owner=owner()); lease.close()
    finally:
        if child.poll() is None: child.kill()
        child.communicate(timeout=5)


def test_exec_does_not_inherit_lease(manager):
    lease = manager.acquire(["x"], owner=owner())
    assert all(not h.get_inheritable() for h in lease._handles)
    child = subprocess.Popen([sys.executable, "-c", "import sys;print('ready',flush=True);sys.stdin.readline()"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, close_fds=False)
    try:
        assert child.stdout.readline().strip() == "ready"
        lease.close()
        other = manager.acquire(["x"], owner=owner()); other.close()
    finally:
        child.communicate("done\n", timeout=5)


def test_abstract_permission_does_not_fallback(tmp_path):
    def forbidden(*args): raise PermissionError(errno.EACCES, "synthetic denied")
    manager = L.PortLockManager(runtime_root=tmp_path / "runtime", socket_factory=forbidden)
    with pytest.raises(PermissionError): manager.acquire(["x"], owner=owner())
    assert not manager.runtime_root.exists()


def test_unsupported_abstract_flock_not_unlinked(tmp_path):
    def unsupported(*args): raise OSError(errno.EAFNOSUPPORT, "synthetic unsupported")
    manager = L.PortLockManager(runtime_root=tmp_path / "runtime", socket_factory=unsupported)
    lease = manager.acquire(["x"], owner=owner())
    try:
        with pytest.raises(Busy): manager.acquire(["x"], owner=owner())
    finally: lease.close()
    files = list((manager.runtime_root / "port-locks").iterdir())
    assert len(files) == 1
    inode = files[0].stat().st_ino
    other = manager.acquire(["x"], owner=owner()); other.close()
    assert files[0].stat().st_ino == inode


def test_owner_directory_symlink_fails_before_publish_and_rolls_back(tmp_path):
    root = tmp_path / "runtime"; root.mkdir(mode=0o700)
    outside = tmp_path / "outside"; outside.mkdir(mode=0o700)
    (root / "port-owners").symlink_to(outside)
    manager = L.PortLockManager(namespace="pweh-unit-" + uuid.uuid4().hex, runtime_root=root)
    with pytest.raises(OSError): manager.acquire(["x"], owner=owner())
    assert not list(outside.iterdir())
    (root / "port-owners").unlink()
    lease = manager.acquire(["x"], owner=owner()); lease.close()


def test_handoff_only_one_cleanup_owner():
    for _ in range(100):
        latch = L.LeaseHandoff()
        gate = threading.Barrier(3)
        results = []
        def run(fn): gate.wait(); results.append(fn())
        a = threading.Thread(target=run, args=(latch.claim_worker,))
        b = threading.Thread(target=run, args=(latch.abandon_caller,))
        a.start(); b.start(); gate.wait(); a.join(); b.join()
        assert sorted(results) == [False, True]
        assert not latch.claim_worker() and not latch.abandon_caller()


def route():
    return P.resolve({"kind": "NATIVE_LINUX"}, "socket://127.0.0.1:17777", "serial-session",
                     probe=P.PortProbe(identity=lambda ref: PortIdentity(ref)))


def test_role_unknown_denies_and_separate_from_instrument_tags(manager):
    store = L.PortRoleStore(runtime_root=manager.runtime_root)
    store.mark_target(route(), case_id="synthetic", server="uart")
    with pytest.raises(PwehError, match="port_role_conflict"):
        store.assert_probe_allowed(route())
    assert not (manager.runtime_root / "tags").exists()
    path = next((manager.runtime_root / "port-roles").iterdir())
    path.write_text("{}")
    with pytest.raises(PwehError, match="port_role_unknown"):
        store.assert_probe_allowed(route())


def usb_scope():
    import copy
    import time
    from pweh.usb_binding import parse_windows_usb_scope
    parent = r'USB\VID_0403&PID_6010\SYNTHETIC'
    mi = r'USB\VID_0403&PID_6010&MI_01\SYNTHETIC-B'
    nodes = [dict(instance_id=parent, parent=r'HTREE\ROOT\0', parent_state='ok', com=None, pnp_class='USB'),
             dict(instance_id=mi, parent=parent, parent_state='ok', com='COM32', pnp_class='Ports')]
    snap = dict(present_count=2, nodes=nodes, errors=[])
    raw = json.dumps(dict(schema='pweh.pnp-usb-scope/v1', snapshots=[snap, copy.deepcopy(snap)])).encode()
    return parse_windows_usb_scope(raw, vid='0403', pid='6010', deadline=time.monotonic() + 5)


def role_record():
    return dict(schema='pweh.port-role/v1', role='target', lock_key='win:COM99', device_id=None,
                identity=dict(status='known', serial='synthetic-old'), case_id='synthetic', server='uart')


def put_role(store, rec):
    store._records.put(L.PortLockManager._name('synthetic-role'), rec)


@pytest.mark.parametrize('match', ['com', 'interface', 'device_id', 'parent_instance',
                                   'usb_ancestor', 'device_instance'])
@pytest.mark.parametrize('role', ['target', 'bridge'])
def test_usb_role_whole_scope_matches_every_alias_and_parent(manager, match, role):
    store = L.PortRoleStore(runtime_root=manager.runtime_root)
    scope, rec = usb_scope(), role_record()
    rec['role'] = role
    if match == 'com': rec['lock_key'] = 'win:com32'
    elif match == 'interface': rec['lock_key'] = next(key.lower() for key in scope.claim_keys if '&MI_' in key)
    elif match == 'device_id': rec['device_id'] = 'win-pnp:' + scope.usb_parent.lower() + '/MI_00'
    else: rec['identity'][match] = scope.usb_parent.lower()
    put_role(store, rec)
    with pytest.raises(PwehError) as exc:
        store.assert_usb_scope_allowed(scope)
    assert exc.value.code == 'port_role_conflict' and exc.value.data == {'role': role}


def test_usb_role_other_parent_allowed_and_no_records_created(manager):
    store = L.PortRoleStore(runtime_root=manager.runtime_root)
    scope = usb_scope()
    store.assert_usb_scope_allowed(scope)
    assert not manager.runtime_root.exists()
    rec = role_record()
    rec['identity']['parent_instance'] = r'USB\VID_1234&PID_5678\SYNTHETIC-OTHER'
    rec['device_id'] = 'win-pnp:' + rec['identity']['parent_instance'] + '/-'
    put_role(store, rec)
    store.assert_usb_scope_allowed(scope)
    assert not (manager.runtime_root / 'tags').exists()


@pytest.mark.parametrize('fault', ['root', 'identity', 'status', 'role', 'key', 'device_id', 'parent', 'serial', 'mode'])
def test_usb_role_malformed_records_fail_closed(manager, fault):
    store = L.PortRoleStore(runtime_root=manager.runtime_root)
    rec = role_record()
    if fault == 'root': rec = []
    elif fault == 'identity': rec['identity'] = []
    elif fault == 'status': rec['identity']['status'] = 'present'
    elif fault == 'role': rec['role'] = 'allow'
    elif fault == 'key': rec['lock_key'] = ''
    elif fault == 'device_id': rec['device_id'] = 42
    elif fault == 'parent': rec['identity']['parent_instance'] = ['private']
    elif fault == 'serial': rec['identity']['serial'] = 42
    put_role(store, rec)
    if fault == 'mode': next((manager.runtime_root / 'port-roles').iterdir()).chmod(0o644)
    with pytest.raises(PwehError) as exc:
        store.assert_usb_scope_allowed(usb_scope())
    assert exc.value.code == 'port_role_unknown'
    assert exc.value.__suppress_context__


def test_usb_role_rejects_non_scope_without_creating_runtime(manager):
    store = L.PortRoleStore(runtime_root=manager.runtime_root)
    with pytest.raises(PwehError, match='port_role_unknown'):
        store.assert_usb_scope_allowed(object())
    assert not manager.runtime_root.exists()
