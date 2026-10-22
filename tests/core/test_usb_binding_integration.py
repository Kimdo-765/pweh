"""합성 Windows graph를 기존 COM scope·OS lease에 연결한다. 실제 PnP 조회는 없다."""

import copy
import json
import time
import uuid

import pytest

from pweh import portidentity as I, portlock as L, ports as P
from pweh.errors import Busy, PwehError
from pweh.usb_binding import parse_windows_usb_scope, revalidate_windows_usb_scope


PARENT = r"USB\VID_0403&PID_6010\SYNTHETIC"
MI0 = r"USB\VID_0403&PID_6010&MI_00\SYNTHETIC-A"
MI1 = r"USB\VID_0403&PID_6010&MI_01\SYNTHETIC-B"
COM31_NODE = r"FTDIBUS\SYNTHETIC-A\0000"
COM32_NODE = r"FTDIBUS\SYNTHETIC-B\0000"
OTHER = r"USB\VID_1234&PID_5678\OTHER"
OTHER_COM = r"USB\VID_1234&PID_5678&MI_00\OTHER-COM"
WINDOWS = {"kind": "WSL2_INTEROP", "wsl": {"interop": {"usable": True}}}


def _node(ident, parent, com=None, pnp_class="USB"):
    return {"instance_id": ident, "parent": parent, "parent_state": "ok",
            "com": com, "pnp_class": pnp_class}


def _document(*, with_com=True):
    """MI는 device ID에 두며 instance tail에 붙이는 legacy 축약형을 쓰지 않는다."""
    nodes = [_node(PARENT, r"HTREE\ROOT\0"), _node(MI0, PARENT), _node(MI1, PARENT)]
    if with_com:
        nodes += [_node(COM31_NODE, MI0, "COM31", "Ports"),
                  _node(COM32_NODE, MI1, "COM32", "Ports")]
    nodes += [_node(OTHER, r"HTREE\ROOT\0"), _node(OTHER_COM, OTHER, "COM99", "Ports")]
    snapshot = {"present_count": len(nodes), "nodes": nodes, "errors": []}
    return {"schema": "pweh.pnp-usb-scope/v1",
            "snapshots": [copy.deepcopy(snapshot), copy.deepcopy(snapshot)]}


def _raw(document):
    return json.dumps(document, ensure_ascii=True).encode("utf-8")


def _scope(document=None):
    return parse_windows_usb_scope(_raw(_document() if document is None else document),
                                   vid="0403", pid="6010", deadline=time.monotonic() + 5)


def _route(com):
    ident = I.PortIdentity(com, "known", present=True, backend="windows", vid="0403", pid="6010",
                           usb_ancestor=PARENT, parent_instance=PARENT,
                           device_instance={"COM31": COM31_NODE, "COM32": COM32_NODE}[com])
    return P.resolve(WINDOWS, com, "esptool", probe=P.PortProbe(identity=lambda _: ident))


def _owner(server="synthetic-usb"):
    return L.PortOwner(server, "synthetic-case", "synthetic-reference")


@pytest.fixture(autouse=True)
def no_pnp(monkeypatch):
    def denied(*args, **kwargs):
        pytest.fail("통합시험은 합성 graph 외 PnP/identity 조회를 하지 않습니다.")
    monkeypatch.setattr(I, "_windows_output", denied)
    monkeypatch.setattr(I, "probe_identity", denied)


@pytest.fixture
def managers(tmp_path):
    """서로 다른 workspace도 같은 namespace의 OS 잠금으로 충돌해야 한다."""
    namespace = "pweh-usb-it-" + uuid.uuid4().hex
    pair = tuple(L.PortLockManager(namespace=namespace, runtime_root=tmp_path / name)
                 for name in ("workspace-a", "workspace-b"))
    yield pair
    for manager in pair:
        for lease in list(manager._leases.values()):
            lease.close()
        assert not manager._leases


@pytest.mark.parametrize("com", ["COM31", "COM32"])
def test_canonical_graph_matches_existing_selected_com_scope(com):
    raw = _raw(_document())
    usb = _scope()
    serial = I.parse_windows_scope(_route(com), raw, deadline=time.monotonic() + 5)
    expected = tuple(sorted(["winif:" + node for node in (PARENT, MI0, MI1, COM31_NODE, COM32_NODE)]
                            + ["win:COM31", "win:COM32"]))
    assert serial.complete
    assert usb.claim_keys == serial.keys == expected
    assert usb.usb_parent == serial.parent_id == PARENT
    assert usb.com_aliases == (("COM31", COM31_NODE), ("COM32", COM32_NODE))
    assert usb.whole_device and usb.backend == "windows"
    assert not any(OTHER in key or "COM99" in key for key in usb.claim_keys)


@pytest.mark.parametrize("com", ["COM31", "COM32"])
def test_existing_com_endpoint_blocks_whole_usb_scope(managers, com):
    serial_manager, usb_manager = managers
    endpoint = serial_manager.acquire((_route(com).lock_key,), owner=_owner("synthetic-serial"))
    try:
        with pytest.raises(Busy):
            usb_manager.acquire(_scope().claim_keys, owner=_owner())
        assert not usb_manager._leases
    finally:
        endpoint.close()


@pytest.mark.parametrize("key", ["win:COM31", "win:COM32", "winif:" + MI0])
def test_whole_usb_scope_blocks_com_and_non_com_sibling(managers, key):
    usb_manager, serial_manager = managers
    lease = usb_manager.acquire(_scope().claim_keys, owner=_owner())
    try:
        with pytest.raises(Busy):
            serial_manager.acquire((key,), owner=_owner("synthetic-serial"))
    finally:
        lease.close()
    reopened = serial_manager.acquire((key,), owner=_owner("synthetic-serial"))
    reopened.close()


def test_unrelated_parent_is_independent(managers):
    usb_manager, other_manager = managers
    lease = usb_manager.acquire(_scope().claim_keys, owner=_owner())
    other = None
    try:
        other = other_manager.acquire(("win:COM99", "winif:" + OTHER), owner=_owner("synthetic-other"))
        other.assert_held(("win:COM99", "winif:" + OTHER))
        lease.assert_held(_scope().claim_keys)
    finally:
        if other is not None:
            other.close()
        lease.close()


def test_last_key_busy_rolls_back_all_earlier_keys(managers):
    blocker_manager, applicant = managers
    keys = _scope().claim_keys
    blocker = blocker_manager.acquire(keys[-1:], owner=_owner("synthetic-blocker"))
    prefix = None
    try:
        with pytest.raises(Busy):
            applicant.acquire(keys, owner=_owner())
        assert not applicant._leases
        prefix = blocker_manager.acquire(keys[:-1], owner=_owner("synthetic-prefix"))
        prefix.assert_held(keys[:-1])
        with pytest.raises(Busy):
            applicant.acquire(keys[-1:], owner=_owner())
    finally:
        if prefix is not None:
            prefix.close()
        blocker.close()
    complete = applicant.acquire(keys, owner=_owner())
    complete.close()


@pytest.mark.parametrize("change", ["com-alias", "non-com-sibling", "second-parent"])
def test_failed_fresh_check_does_not_expand_or_release_existing_lease(managers, change):
    manager, contender = managers
    original = _scope()
    changed = _document()
    if change == "com-alias":
        added = _node(r"FTDIBUS\SYNTHETIC-NEW\0000", MI1, "COM33", "Ports")
        new_key = "win:COM33"
    elif change == "non-com-sibling":
        ident = r"USB\VID_0403&PID_6010&MI_02\SYNTHETIC-C"
        added = _node(ident, PARENT)
        new_key = "winif:" + ident
    else:
        ident = r"USB\VID_0403&PID_6010\SECOND"
        added = _node(ident, r"HTREE\ROOT\0")
        new_key = "winif:" + ident
    for snapshot in changed["snapshots"]:
        snapshot["nodes"].append(copy.deepcopy(added))
        snapshot["present_count"] += 1
    lease = manager.acquire(original.claim_keys, owner=_owner())
    fresh_key = None
    try:
        with pytest.raises(PwehError) as error:
            revalidate_windows_usb_scope(original, _raw(changed), deadline=time.monotonic() + 5)
        assert error.value.code == "usb_scope_changed"
        assert lease.keys == original.claim_keys and not lease.closed
        lease.assert_held(original.claim_keys)
        with pytest.raises(Busy):
            contender.acquire(("win:COM31",), owner=_owner("synthetic-contender"))
        # fresh 실패가 새 범위의 잠금을 자동 취득하지 않는다.
        fresh_key = contender.acquire((new_key,), owner=_owner("synthetic-new"))
    finally:
        if fresh_key is not None:
            fresh_key.close()
        lease.close()


@pytest.mark.parametrize("fault", ["parent-gap", "snapshot-mismatch"])
def test_incomplete_graph_never_reaches_lock_acquisition(managers, monkeypatch, fault):
    document = _document()
    if fault == "parent-gap":
        for snapshot in document["snapshots"]:
            snapshot["nodes"][1]["parent"] = "SYNTHETIC-MISSING"
    else:
        document["snapshots"][1]["nodes"][1]["pnp_class"] = "ChangedClass"
    calls = []
    manager = managers[0]
    acquire = manager.acquire
    def recording(keys, **kwargs):
        calls.append(keys)
        return acquire(keys, **kwargs)
    monkeypatch.setattr(manager, "acquire", recording)
    with pytest.raises(PwehError):
        scope = _scope(document)
        manager.acquire(scope.claim_keys, owner=_owner())
    assert calls == [] and not manager._leases


def test_comless_parent_has_real_nonempty_exclusive_scope(managers):
    scope = _scope(_document(with_com=False))
    assert scope.claim_keys == tuple(sorted("winif:" + node for node in (PARENT, MI0, MI1)))
    assert scope.com_aliases == ()
    first, second = managers
    lease = first.acquire(scope.claim_keys, owner=_owner())
    try:
        with pytest.raises(Busy):
            second.acquire(scope.claim_keys, owner=_owner("synthetic-other"))
    finally:
        lease.close()
    reopened = second.acquire(scope.claim_keys, owner=_owner("synthetic-other"))
    reopened.close()
