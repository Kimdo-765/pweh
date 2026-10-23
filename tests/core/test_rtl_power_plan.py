"""전력 계획은 유한한 정수만 받고 실행물/임의 인자를 만들지 않는다."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import time

import pytest

from pweh import rtl_power_plan as P


def request(**changes):
    return replace(P.PowerSweepRequest(0, 100000000, 101000000, 10000, 1, 2), **changes)


def test_exact_plan_and_frozen_request():
    req = request()
    plan = P.build_power_plan(req)
    assert plan.argv_tail == ("-d", "0", "-f", "100000000:101000000:10000", "-i", "1", "-e", "2", "-")
    assert plan.profile == "rtl-power-fake-plan-v1"
    assert plan.simulator_only is True and plan.hardware_verified is False
    with pytest.raises(FrozenInstanceError):
        req.device_index = 1
    with pytest.raises(FrozenInstanceError):
        plan.argv_tail = ()


@pytest.mark.parametrize("field", tuple(P.PowerSweepRequest.__dataclass_fields__))
@pytest.mark.parametrize("value", [True, False, 1.0, "1", None, 10 ** 1000])
def test_non_integer_and_unbounded_request(field, value):
    with pytest.raises(P.PowerFakeError) as caught:
        P.build_power_plan(request(**{field: value}))
    assert caught.value.code == "rf_power_fake_invalid" and caught.value.data == {}


@pytest.mark.parametrize("change", [
    {"device_index": -1}, {"device_index": 256}, {"low_hz": 0}, {"high_hz": 1 << 31},
    {"low_hz": 101000000}, {"max_bin_hz": 0}, {"max_bin_hz": 1000001},
    {"integration_seconds": 0}, {"integration_seconds": 3}, {"duration_seconds": 61},
    {"duration_seconds": 0}, {"low_hz": 1, "high_hz": 10000000, "max_bin_hz": 2800001},
])
def test_exact_numeric_relations(change):
    with pytest.raises(P.PowerFakeError, match="rf_power_fake_invalid"):
        P.build_power_plan(request(**change))


@pytest.mark.parametrize("req", [
    P.PowerSweepRequest(0, 1, 2, 1, 1, 1),
    P.PowerSweepRequest(255, 1, (1 << 31) - 1, 2800000, 60, 60),
])
def test_boundary_values(req):
    plan = P.build_power_plan(req)
    assert len(plan.argv_tail) == 9
    assert all(type(arg) is str and arg.isascii() for arg in plan.argv_tail)


@pytest.mark.parametrize("value", [None, {}, object.__new__(P.PowerSweepRequest)])
def test_exact_request_object(value):
    with pytest.raises(P.PowerFakeError, match="rf_power_fake_invalid"):
        P.build_power_plan(value)


@pytest.mark.parametrize("change", [
    {"profile": "PRIVATE"}, {"argv_tail": ("-d", "0", "--shell")},
    {"argv_tail": []}, {"simulator_only": False}, {"hardware_verified": True},
    {"simulator_only": 1}, {"hardware_verified": 0}, {"request": {}},
])
def test_forged_plan_never_reaches_factory(change):
    plan = replace(P.build_power_plan(request()), **change)
    with pytest.raises(P.PowerFakeError, match="rf_power_fake_invalid"):
        P.run_power_plan_fake(plan, process_factory=lambda *a, **k: pytest.fail("factory 호출"),
                              deadline=time.monotonic() + 5)


@pytest.mark.parametrize("value", [True, "5", None, float("nan"), float("inf"), 10 ** 1000])
def test_invalid_deadline_before_factory(value):
    with pytest.raises(P.PowerFakeError, match="rf_power_fake_invalid"):
        P.run_power_plan_fake(P.build_power_plan(request()), process_factory=lambda *a, **k: pytest.fail(), deadline=value)


@pytest.mark.parametrize("cancel,deadline,code", [
    (lambda: True, None, "cancelled"), (lambda: 1, None, "failed"),
    (lambda: False, 0, "timeout"), (False, None, "invalid"),
])
def test_preflight_before_factory(cancel, deadline, code):
    with pytest.raises(P.PowerFakeError) as caught:
        P.run_power_plan_fake(P.build_power_plan(request()), process_factory=lambda *a, **k: pytest.fail(),
                              deadline=deadline if deadline is not None else time.monotonic() + 5, cancel=cancel)
    assert caught.value.code == "rf_power_fake_" + code


def test_no_default_factory_or_platform_fallback(monkeypatch):
    plan = P.build_power_plan(request())
    with pytest.raises(TypeError):
        P.run_power_plan_fake(plan, deadline=time.monotonic() + 5)
    with pytest.raises(P.PowerFakeError, match="rf_power_fake_invalid"):
        P.run_power_plan_fake(plan, process_factory=None, deadline=time.monotonic() + 5)
    monkeypatch.setattr(P.sys, "platform", "win32")
    with pytest.raises(P.PowerFakeError, match="rf_power_fake_invalid"):
        P.run_power_plan_fake(plan, process_factory=lambda *a, **k: pytest.fail(), deadline=time.monotonic() + 5)


def test_uninitialized_plan_is_fixed_error():
    with pytest.raises(P.PowerFakeError, match="rf_power_fake_invalid"):
        P.run_power_plan_fake(object.__new__(P.PowerPlan), process_factory=lambda *a, **k: pytest.fail(),
                              deadline=time.monotonic() + 5)
