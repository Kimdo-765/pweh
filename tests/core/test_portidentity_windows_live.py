"""Windows PnP 고정 질의(PS_IDENTITIES·PS_USB_SCOPE)의 회귀 검사.

장치가 많은 PC 에서 예전 Get-PnpDeviceProperty -InstanceId <여러 ID> 는 WMI '할당량 위반'(0x8004106c)을 냈고,
나눠 보내도 결과 장치 집합이 틀렸다(중복·누락). 그 결과 whole-device scope 가 늘 pnp_query_failed 로 불완전해져
CU·직렬 장비 연결이 막혔다. 장치별 cmdlet/CIM 호출은 정확했지만 명령 프레임마다 다시 하는 관찰로는 너무 느려
(CU 프레임 예산 2초) cfgmgr32 직접 호출로 바꿨다. 실제 Windows 시험은 WSL interop 이 있을 때만 실행한다.
"""
import functools
import json
import re
import subprocess
import time

import pytest

from pweh import hostenv, portidentity as I

_COM = re.compile(r"\((COM[1-9][0-9]{0,3})\)$", re.I)


@functools.lru_cache(maxsize=1)
def _windows_runs() -> bool:
    """고정 경로의 powershell.exe 가 WSL interop 으로 실제 실행되는가(세션에 한 번만 확인).

    파일만 있고 실행되지 않는 호스트(interop 꺼짐·실행 불가 파일)에서는 실패가 아니라 skip 이어야 한다.
    """
    exe = hostenv.powershell_path()
    if not exe:
        return False
    try:
        out = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", "exit 0"],
                             capture_output=True, timeout=60, cwd="/")
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0


def _need_windows():
    if not _windows_runs():
        pytest.skip("WSL interop 으로 PowerShell 을 실행할 수 없음")


@pytest.fixture(autouse=True)
def _stop_resident_worker():
    """실제 상주 powershell.exe 작업자를 시험마다 끝내 다음 시험·세션에 남기지 않는다."""
    I._shutdown_worker()
    yield
    I._shutdown_worker()


def test_pnp_queries_use_fixed_native_calls_and_keep_guards():
    """두 질의는 같은 고정 cfgmgr32 라이브러리를 쓰고 여러 ID 를 받는 cmdlet 으로 돌아가지 않는다."""
    for script in (I.PS_IDENTITIES, I.PS_USB_SCOPE):
        assert script.startswith(I._PS_CM_LIB) and "$ErrorActionPreference='Stop'" in script
        assert "Get-PnpDevice" not in script and "Add-Type" not in script and "Invoke-Expression" not in script
        assert "CM_Get_Device_ID_ListW" in script and "0x100" in script and "ToUpperInvariant()" in script
        for guard in ("'device limit'", "'duplicate device'", 'throw "cm prop $r"', 'throw "cm locate $r"'):
            assert guard in script
    for guard in ("'port limit'", "'parent cycle'", "'parent absent'"):
        assert guard in I.PS_IDENTITIES
    assert "'invalid parent property'" in I.PS_USB_SCOPE and "snapshots=@($one,$two)" in I.PS_USB_SCOPE


# 예전(cmdlet 기반) 신원 질의. 느리지만 독립 기준으로 쓴다(location_paths 포함).
_LEGACY_IDENTITIES = r"""$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);
$all=@(Get-PnpDevice -PresentOnly);if($all.Count -gt 8192){throw 'device limit'};
$ports=@($all | Where-Object {$_.FriendlyName -match '\(COM[1-9][0-9]{0,3}\)$'});
if($ports.Count -gt 512){throw 'port limit'};$out=@();
foreach($d in $ports){$id=$d.InstanceId;$nodes=@();$seen=@{};
for($i=0;$i -lt 8;$i++){if($seen.ContainsKey($id)){throw 'parent cycle'};$seen[$id]=$true;
$present=@($all | Where-Object {$_.InstanceId -eq $id});if($present.Count -ne 1){throw 'parent absent'};
$p=(Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_Parent').Data;
$loc=@((Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_LocationPaths' -ErrorAction SilentlyContinue).Data);
$nodes+=@{instance_id=$id;parent=$p;present=$true;location_paths=$loc};
if($id -match '^USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}\\'){break};
if(-not $p){break};$id=$p};
$out+=@{port=([regex]::Match($d.FriendlyName,'\((COM[1-9][0-9]{0,3})\)$').Groups[1].Value);nodes=$nodes}};
ConvertTo-Json -InputObject $out -Depth 6 -Compress"""


def _powershell(script):
    out = subprocess.run([hostenv.powershell_path(), "-NoProfile", "-NonInteractive", "-Command", script],
                         capture_output=True, timeout=120, cwd="/")
    assert out.returncode == 0, out.stderr.decode("utf-8", "replace")[:500]
    return out.stdout


def _rows(raw):
    rows = json.loads(raw or b"[]")
    return rows if isinstance(rows, list) else [rows]


def _reference():
    """느리지만 독립적인 기준: Get-PnpDevice 집합·이름·Class 와 장치별 WMI GetDeviceProperties 부모."""
    script = r"""$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);
$rows=@(foreach($d in @(Get-PnpDevice -PresentOnly)){$p=$null;if($d.InstanceId -ne 'HTREE\ROOT\0'){
$r=Invoke-CimMethod -InputObject $d -MethodName GetDeviceProperties -Arguments @{devicePropertyKeys=[string[]]@('DEVPKEY_Device_Parent')};
$p=[string]@($r.deviceProperties)[0].Data};@{id=[string]$d.InstanceId;name=[string]$d.FriendlyName;cls=[string]$d.Class;parent=$p}});
ConvertTo-Json -InputObject $rows -Compress"""
    out = subprocess.run([hostenv.powershell_path(), "-NoProfile", "-NonInteractive", "-Command", script],
                         capture_output=True, timeout=120, cwd="/")
    assert out.returncode == 0, out.stderr.decode("utf-8", "replace")[:500]
    return {r["id"]: r for r in json.loads(out.stdout)}


@pytest.mark.external
def test_native_pnp_queries_match_cmdlet_reference_on_real_windows():
    """실제 PnP 에서 장치 집합(대소문자 포함)·COM·Class·부모가 기존 cmdlet/WMI 관찰과 같아야 한다."""
    _need_windows()
    scope = json.loads(I._windows_output(script=I.PS_USB_SCOPE))
    ref = _reference()
    assert scope["schema"] == "pweh.pnp-usb-scope/v1" and len(scope["snapshots"]) == 2
    for snap in scope["snapshots"]:
        nodes = {n["instance_id"]: n for n in snap["nodes"]}
        assert snap["present_count"] == len(snap["nodes"]) == len(nodes) and snap["errors"] == []
        assert set(nodes) == set(ref)
        for key, node in nodes.items():
            want = ref[key]
            assert node["pnp_class"] == want["cls"]
            com = _COM.search(want["name"])
            assert node["com"] == (com.group(1).upper() if com else None)
            if node["parent_state"] == "root":
                assert key == "HTREE\\ROOT\\0" and node["parent"] is None
            else:
                assert node["parent_state"] == "ok" and node["parent"] == want["parent"]
    native = I._windows_output(script=I.PS_IDENTITIES)
    rows = _rows(native)
    want_ports = sorted(_COM.search(r["name"]).group(1) for r in ref.values() if _COM.search(r["name"]))
    assert sorted(r["port"] for r in rows) == want_ports
    for row in rows:
        chain = row["nodes"]
        assert 1 <= len(chain) <= 8 and all(n["present"] is True for n in chain)
        for a, b in zip(chain, chain[1:]):
            assert a["parent"] == b["instance_id"]
        for n in chain:
            assert n["parent"] == ref[n["instance_id"].upper()]["parent"]
    # 예전 cmdlet 질의와 원시 행(location_paths 포함)·route 신원 해석이 같아야 한다.
    legacy = _powershell(_LEGACY_IDENTITIES)
    assert sorted(json.dumps(r, sort_keys=True) for r in rows) == sorted(json.dumps(r, sort_keys=True) for r in _rows(legacy))
    for row in rows:
        new, old = I.parse_windows(row["port"], native).to_dict(), I.parse_windows(row["port"], legacy).to_dict()
        new.pop("observed_at"), old.pop("observed_at")
        assert new == old


@pytest.mark.external
def test_native_pnp_queries_survive_small_property_buffer():
    """속성 버퍼가 부족할 때(CR_BUFFER_SMALL) 다시 읽는 분기가 같은 결과를 내야 한다."""
    _need_windows()
    initial = "$B=New-Object byte[] 2048;"
    assert I._PS_CM_LIB.count(initial) == 1
    for script in (I.PS_IDENTITIES, I.PS_USB_SCOPE):
        small = script.replace(initial, "$B=New-Object byte[] 4;")
        assert json.loads(_powershell(small) or b"[]") == json.loads(_powershell(script) or b"[]")


@pytest.mark.external
def test_resident_worker_matches_one_shot_queries():
    """상주 작업자의 두 응답은 같은 고정 질의를 한 번 실행한 JSON 과 같다(끝 CRLF 만 다르다)."""
    _need_windows()
    for script in (I.PS_IDENTITIES, I.PS_USB_SCOPE):
        worker = I._windows_output(script=script)
        assert not worker.endswith(b"\n")
        assert json.loads(worker or b"[]") == json.loads(_powershell(script) or b"[]")


@pytest.mark.external
@pytest.mark.parametrize("line", [b"Get-Process\n", b"IDE\x00NT\n", b"IDENT\x00\n", b"\x00SCOPE\n", b"ident\n"],
                         ids=["command", "inner-nul", "trailing-nul", "leading-nul", "lowercase"])
def test_resident_worker_garbage_token_exits_and_next_call_recovers(line):
    """서수 비교로 고정 토큰과 다른 줄(문화권 비교가 무시하는 NUL 포함)을 받은 작업자는 exit 3 으로 끝나고,
    다음 호출은 새 작업자로 정상 응답한다."""
    _need_windows()
    first = json.loads(I._windows_output(script=I.PS_USB_SCOPE))
    proc = I._MANAGER.worker.proc
    with I._MANAGER.lock:
        proc.stdin.write(line)
    assert proc.wait(timeout=15) == 3
    again = json.loads(I._windows_output(script=I.PS_USB_SCOPE))
    assert I._MANAGER.worker.proc is not proc and again["schema"] == first["schema"] == "pweh.pnp-usb-scope/v1"


@pytest.mark.external
def test_resident_worker_exits_on_stdin_eof():
    """stdin EOF(서버 종료)에 작업자가 스스로 exit 0 한다 — 유휴 종료가 SIGKILL 없이 끝난다."""
    _need_windows()
    I._windows_output(script=I.PS_IDENTITIES)
    with I._MANAGER.lock:
        worker, I._MANAGER.worker = I._MANAGER.worker, None
    I._stop_proc(worker.proc, graceful=True)
    assert worker.proc.returncode == 0


@pytest.mark.external
def test_resident_worker_scope_calls_fit_budget():
    """연속 형제 관찰 10회가 각각 PNP_TIMEOUT_S 보다 훨씬 짧다(첫 회는 작업자 시작 포함). 넉넉한 상한으로 본다."""
    _need_windows()
    spent = []
    for _ in range(10):
        start = time.monotonic()
        json.loads(I._windows_output(script=I.PS_USB_SCOPE))
        spent.append(time.monotonic() - start)
    assert max(spent) < 1.5, spent
