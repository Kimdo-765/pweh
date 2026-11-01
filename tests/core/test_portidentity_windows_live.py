"""고정 PS_USB_SCOPE 의 실제 Windows PnP 회귀 검사 (WSL interop 이 있을 때만 실행).

장치가 많은 PC(실측 253개)에서 Get-PnpDeviceProperty -InstanceId <여러 ID> 는 WMI '할당량 위반'(0x8004106c)을 냈고,
나눠 보내도 결과 장치 집합이 틀렸다(중복·누락). 그 결과 whole-device scope 가 늘 pnp_query_failed 로
불완전해져 CU·직렬 장비 연결이 cu_identity_unknown/port_scope_unknown 으로 막혔다.
"""
import json

import pytest

from pweh import hostenv, portidentity as I


def test_usb_scope_does_not_use_multi_id_property_cmdlet():
    """여러 ID 를 받는 cmdlet 은 장치 집합이 틀릴 수 있으므로 장치별 CIM 호출을 유지하고,
    귀속은 입력을 되돌린 DeviceID 가 아니라 장치가 돌려준 DEVPKEY_Device_InstanceId 로 확인한다."""
    assert "Get-PnpDeviceProperty" not in I.PS_USB_SCOPE
    assert "GetDeviceProperties" in I.PS_USB_SCOPE and "'property attribution'" in I.PS_USB_SCOPE
    assert "DEVPKEY_Device_InstanceId" in I.PS_USB_SCOPE and "$q.DeviceID" not in I.PS_USB_SCOPE
    for guard in ("'duplicate property'", "'missing parent property'", "'invalid parent property'",
                  "'device limit'", "'property limit'", "$ErrorActionPreference='Stop'"):
        assert guard in I.PS_USB_SCOPE


@pytest.mark.external
def test_usb_scope_reads_every_parent_on_real_windows():
    """두 스냅샷 모두 모든 비루트 노드의 부모를 읽고 PNP_TIMEOUT_S 안에 끝나야 한다."""
    if not hostenv.powershell_path():
        pytest.skip("WSL interop PowerShell 이 없음")
    data = json.loads(I._windows_output(script=I.PS_USB_SCOPE))
    assert data["schema"] == "pweh.pnp-usb-scope/v1" and len(data["snapshots"]) == 2
    for snap in data["snapshots"]:
        nodes = snap["nodes"]
        assert snap["present_count"] == len(nodes) > 0 and snap["errors"] == []
        ids = [n["instance_id"] for n in nodes]
        assert len(ids) == len(set(ids))
        roots = [n for n in nodes if n["parent_state"] == "root"]
        assert len(roots) <= 1 and all(n["parent"] is None for n in roots)
        for n in nodes:
            if n["parent_state"] != "root":
                assert n["parent_state"] == "ok" and isinstance(n["parent"], str) and n["parent"]
