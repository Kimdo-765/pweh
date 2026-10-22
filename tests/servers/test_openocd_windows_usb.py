"""고정 PnP 질의 접점에 합성 graph만 주입한다. 실제 Windows/장치 조회는 금지한다."""
import copy
from dataclasses import replace
import json
import time
import traceback

import pytest

from openocd_mcp import windows_usb as W
from openocd_mcp.tigard_profile import TIGARD_PROFILE as PROFILE
from pweh import portidentity as I, usb_binding as U
from pweh.errors import PwehError

PARENT = r"USB\VID_0403&PID_6010\SYNTHETIC"
MI = r"USB\VID_0403&PID_6010&MI_01\SYNTHETIC"
FIXED_READ_SCOPE = W._read_scope


def graph(*, extra=None, com="COM31"):
    nodes = [{"instance_id": PARENT, "parent": r"HTREE\ROOT\0", "parent_state": "ok", "com": None, "pnp_class": "USB"},
             {"instance_id": MI, "parent": PARENT, "parent_state": "ok", "com": com, "pnp_class": "Ports"}]
    if extra:
        nodes.append(extra)
    snap = {"present_count": len(nodes), "nodes": nodes, "errors": []}
    return {"schema": "pweh.pnp-usb-scope/v1", "snapshots": [snap, copy.deepcopy(snap)]}


def raw(value=None):
    return json.dumps(graph() if value is None else value, separators=(",", ":")).encode()


def observe(**kwargs):
    options = dict(deadline=time.monotonic() + 5)
    options.update(kwargs)
    return W.observe_tigard_scope(PROFILE, {}, **options)


def assert_error(code, fn):
    with pytest.raises(PwehError) as caught:
        fn()
    assert caught.value.code == code
    assert caught.value.data == {} and caught.value.hint is None
    assert "PRIVATE" not in "".join(traceback.format_exception(caught.value))


@pytest.fixture(autouse=True)
def no_live(monkeypatch):
    def forbidden(*a, **kw):
        pytest.fail("실제 PnP/장치 조회 금지")
    monkeypatch.setattr(I, "_windows_output", forbidden)
    monkeypatch.setattr(I, "probe_identity", forbidden)
    monkeypatch.setattr(W, "_read_scope", lambda *a, **kw: raw())


def test_default_reader_uses_only_fixed_script_with_same_deadline(monkeypatch):
    calls = []
    def reader(config, **kwargs):
        calls.append((config, kwargs))
        return raw()
    monkeypatch.setattr(I, "_windows_output", reader)
    # 운영 접점 자체도 고정 script/인자를 전달하는지만 확인한다.
    cancel = lambda: False
    deadline = time.monotonic() + 3
    monkeypatch.setattr(W, "_read_scope", FIXED_READ_SCOPE)
    scope = W.observe_tigard_scope(PROFILE, {"synthetic": True}, deadline=deadline, cancel=cancel)
    assert scope.claim_keys == tuple(sorted(("winif:" + PARENT, "winif:" + MI, "win:COM31")))
    assert len(calls) == 1
    assert calls[0] == ({"synthetic": True}, {"script": I.PS_USB_SCOPE, "deadline": deadline, "cancel": cancel})


def test_equal_fresh_returns_value_without_new_keys():
    before = observe()
    after = W.revalidate_tigard_scope(before, PROFILE, {}, deadline=time.monotonic() + 5)
    assert after == before and after is not before
    assert after.com_aliases == (("COM31", MI),)


@pytest.mark.parametrize("profile", [None, "PRIVATE", replace(PROFILE, pid="0000"), replace(PROFILE, channel=0)])
def test_unregistered_profile_is_rejected_before_query(monkeypatch, profile):
    monkeypatch.setattr(W, "_read_scope", lambda *a, **kw: pytest.fail("잘못된 profile 질의"))
    assert_error("usb_scope_invalid", lambda: W.observe_tigard_scope(profile, {}, deadline=time.monotonic() + 5))


@pytest.mark.parametrize("deadline", [None, True, float("nan"), float("inf"), 10**400])
def test_invalid_budget_is_fixed_and_query_zero(monkeypatch, deadline):
    monkeypatch.setattr(W, "_read_scope", lambda *a, **kw: pytest.fail("잘못된 예산 질의"))
    assert_error("usb_scope_invalid", lambda: observe(deadline=deadline))


@pytest.mark.parametrize("kind,code", [("expired", "usb_scope_timeout"), ("cancelled", "usb_scope_cancelled"),
                                       ("callback", "usb_scope_unknown"), ("nonbool", "usb_scope_unknown")])
def test_prequery_budget_and_cancel(monkeypatch, kind, code):
    monkeypatch.setattr(W, "_read_scope", lambda *a, **kw: pytest.fail("중단 이후 질의"))
    def callback():
        raise ValueError("PRIVATE callback")
    opts = {"deadline": time.monotonic() - 1} if kind == "expired" else {
        "cancel": callback if kind == "callback" else (lambda: True) if kind == "cancelled" else (lambda: 1)}
    assert_error(code, lambda: observe(**opts))


@pytest.mark.parametrize("failure,code", [(ValueError("PRIVATE query"), "usb_scope_unknown"),
    (OSError("PRIVATE path"), "usb_scope_unknown"), (ValueError("pnp_query_cancelled"), "usb_scope_cancelled"),
    (ValueError("pnp_timeout_windows_child_unverified"), "usb_scope_timeout")])
def test_query_errors_are_closed(monkeypatch, failure, code):
    def fail(*a, **kw):
        raise failure
    monkeypatch.setattr(W, "_read_scope", fail)
    assert_error(code, observe)


@pytest.mark.parametrize("value", [b'{"PRIVATE":', b'\xffPRIVATE', raw().decode(), b"x" * ((1 << 20) + 1)])
def test_incomplete_or_nonbytes_query_is_not_empty_success(monkeypatch, value):
    monkeypatch.setattr(W, "_read_scope", lambda *a, **kw: value)
    assert_error("usb_scope_unknown", observe)


def test_query_and_parser_share_absolute_end(monkeypatch):
    clock = [100.0]
    ends = []
    monkeypatch.setattr(W.time, "monotonic", lambda: clock[0])
    def reader(*a, deadline, **kw):
        ends.append(deadline)
        clock[0] = 103.0
        return raw()
    parse = U.parse_windows_usb_scope
    def parser(value, **kwargs):
        ends.append(kwargs["deadline"])
        return parse(value, **kwargs)
    monkeypatch.setattr(W, "_read_scope", reader)
    monkeypatch.setattr(U, "parse_windows_usb_scope", parser)
    assert observe(deadline=120).vid == "0403"
    assert ends == [105.0, 105.0]


def test_query_finally_time_cannot_grant_new_parse_budget(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(W.time, "monotonic", lambda: clock[0])
    def reader(*a, deadline, **kw):
        clock[0] = deadline
        return raw()
    monkeypatch.setattr(W, "_read_scope", reader)
    monkeypatch.setattr(U, "parse_windows_usb_scope", lambda *a, **kw: pytest.fail("만료 뒤 파싱"))
    assert_error("usb_scope_timeout", lambda: observe(deadline=104))


@pytest.mark.parametrize("kind", ["changed", "ambiguous", "failed", "partial"])
def test_fresh_failure_does_not_replace_previous_binding(monkeypatch, kind):
    previous = observe()
    original = previous.claim_keys
    data = graph(com="COM32") if kind == "changed" else graph(extra={
        "instance_id": r"USB\VID_0403&PID_6010\OTHER", "parent": r"HTREE\ROOT\0",
        "parent_state": "ok", "com": None, "pnp_class": "USB"})
    def reader(*a, **kw):
        if kind == "failed":
            raise ValueError("PRIVATE unavailable")
        return b'{' if kind == "partial" else raw(data)
    monkeypatch.setattr(W, "_read_scope", reader)
    assert_error("usb_scope_changed", lambda: W.revalidate_tigard_scope(
        previous, PROFILE, {}, deadline=time.monotonic() + 5))
    assert previous.claim_keys == original


def test_initial_absence_and_ambiguity_preserve_pure_meaning(monkeypatch):
    data = graph()
    for snap in data["snapshots"]:
        snap["nodes"] = [{"instance_id": r"USB\VID_1234&PID_5678\OTHER", "parent": r"HTREE\ROOT\0",
                          "parent_state": "ok", "com": None, "pnp_class": "USB"}]
        snap["present_count"] = 1
    monkeypatch.setattr(W, "_read_scope", lambda *a, **kw: raw(data))
    assert_error("usb_scope_absent", observe)
    extra = {"instance_id": r"USB\VID_0403&PID_6010\OTHER", "parent": r"HTREE\ROOT\0",
             "parent_state": "ok", "com": None, "pnp_class": "USB"}
    monkeypatch.setattr(W, "_read_scope", lambda *a, **kw: raw(graph(extra=extra)))
    assert_error("usb_scope_ambiguous", observe)
