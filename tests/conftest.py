"""공통 pytest fixture.

모든 테스트는 임시 작업공간(케이스/상태 디렉터리 + 테스트용 pipeline-config.yaml)에서 실행되어
실제 저장소의 cases/ 나 .pweh/ 를 건드리지 않는다.
"""

from __future__ import annotations

import os
import importlib
import shutil
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tests"))


@pytest.fixture(autouse=True)
def isolated_ports(tmp_path, monkeypatch, request):
    """합성 시험의 포트 잠금/역할과 기본 경로 관찰을 실제 호스트에서 분리한다.

    개별 시험은 PortProbe 또는 서버 환경 seam을 명시적으로 덮어쓴다. 자체 생성한
    PTY의 stat은 그대로 사용하고, 기본 route 식별에서 실제 sysfs/PnP를 조회하지 않는다.
    """
    if "hardware" in request.node.keywords:
        yield None
        return
    from pweh import portlock, ports
    from pweh.portidentity import PortIdentity
    from serial.tools import list_ports

    runtime_root = tmp_path / "port-runtime"
    manager = portlock.PortLockManager(namespace="pweh-test-" + uuid.uuid4().hex, runtime_root=runtime_root)
    roles = portlock.PortRoleStore(runtime_root=runtime_root)
    monkeypatch.setattr(portlock, "get_manager", lambda: manager)
    monkeypatch.setattr(portlock, "get_role_store", lambda: roles)
    monkeypatch.setattr(list_ports, "comports", lambda *args, **kwargs: [])

    def synthetic_identity(ref, **kwargs):
        return PortIdentity(str(ref), status="unknown", reasons=("synthetic_route_identity",))

    monkeypatch.setattr(ports, "_probe_identity", synthetic_identity)
    check_holders = getattr(ports, "check_holders", None)
    def synthetic_holders(*args, **kwargs):
        if kwargs.get("proc_root") is not None and check_holders is not None:
            return check_holders(*args, **kwargs)
        return {"busy_check": "synthetic", "warnings": []}
    monkeypatch.setattr(ports, "check_holders", synthetic_holders, raising=False)
    for name in ("uart_mcp.server", "jtagulator_mcp.server", "esp_mcp.server", "sigrok_mcp.server"):
        module = importlib.import_module(name)
        monkeypatch.setattr(module, "_port_environment", lambda: {"kind": "NATIVE_LINUX"}, raising=False)
    context = {"manager": manager, "roles": roles, "runtime_root": runtime_root, "allow_orphans": False}
    yield context
    # 오류 수명을 검증한 시험만 합성 orphan을 남길 수 있다. 운영 정리 경로는 완화하지 않는다.
    remaining = list(manager._leases.values())
    for lease in remaining:
        lease.close()
    uart = sys.modules["uart_mcp.server"]
    jtag = sys.modules["jtagulator_mcp.server"]
    for module, registry in ((uart, uart._SESSIONS), (jtag, jtag._CONNS)):
        for key, entry in list(registry.items()):
            lease = getattr(entry, "lease", None)
            if lease is not None and lease._manager is manager and lease.closed:
                registry.pop(key, None)
        for key, entry in list(module._CLEANUP_PENDING.items()):
            lease = entry[0]
            if lease._manager is manager and lease.closed:
                module._CLEANUP_PENDING.pop(key, None)
                if module is uart and uart._RESERVED.get(entry[2]) == entry[3]:
                    uart._RESERVED.pop(entry[2], None)
    if remaining and not context["allow_orphans"]:
        pytest.fail("합성 포트 lease가 남았습니다. 정상 정리를 검증하거나 의도한 orphan 시험으로 명시하세요.", pytrace=False)


def write_config(root: Path, safety: dict[str, Any] | None = None, extra: dict[str, Any] | None = None) -> Path:
    """임시 작업공간에 orchestrator/pipeline-config.yaml 생성 (저장소 설정의 profiles 를 재사용)."""
    repo_cfg = REPO_ROOT / "orchestrator" / "pipeline-config.yaml"
    base: dict[str, Any] = {}
    if repo_cfg.exists():
        base = yaml.safe_load(repo_cfg.read_text(encoding="utf-8")) or {}
    base.setdefault("workspace", {})
    base["workspace"]["cases_dir"] = "cases"
    base["workspace"]["state_dir"] = ".pweh/state"
    base.setdefault("safety", {})
    base["safety"].update(safety or {})
    if extra:
        for k, v in extra.items():
            base[k] = v
    cfg = root / "orchestrator" / "pipeline-config.yaml"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(yaml.safe_dump(base, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return cfg


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """격리된 PWEH 작업공간. 반환: dict(root, config, cases_dir, state_dir, set_safety)."""
    from pweh.runtime import reset_runtimes

    root = tmp_path / "ws"
    root.mkdir()
    cfg = write_config(root)
    monkeypatch.setenv("PWEH_CONFIG", str(cfg))
    monkeypatch.delenv("PWEH_CASES_DIR", raising=False)
    monkeypatch.delenv("PWEH_STATE_DIR", raising=False)
    reset_runtimes()

    def set_safety(**safety: Any) -> None:
        write_config(root, safety=safety)
        reset_runtimes()

    yield {
        "root": root,
        "config": cfg,
        "cases_dir": root / "cases",
        "state_dir": root / ".pweh" / "state",
        "set_safety": set_safety,
    }
    reset_runtimes()


AUTH = {
    "basis": "owned",
    "owner": "테스트 랩",
    "statement": "이 카메라는 제가 직접 구매한 제 소유 기기입니다.",
}


@pytest.fixture
def auth() -> dict[str, Any]:
    return dict(AUTH)


def which_or_env(env: str, name: str) -> str | None:
    val = os.environ.get(env)
    if val and Path(val).exists():
        return val
    return shutil.which(name)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--run-hardware", action="store_true", default=False,
                     help="실제 하드웨어가 필요한 테스트(@pytest.mark.hardware)도 실행 (기본 skip, 환경 변수 PWEH_HARDWARE=1 과 같음)")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """@pytest.mark.hardware 테스트는 --run-hardware 또는 PWEH_HARDWARE=1 일 때만 실행한다 (pyproject 의 마커 설명대로 기본 skip)."""
    if config.getoption("--run-hardware") or os.environ.get("PWEH_HARDWARE") == "1":
        return
    skip = pytest.mark.skip(reason="실제 하드웨어 테스트: --run-hardware 또는 PWEH_HARDWARE=1 로 실행")
    for item in items:
        if "hardware" in item.keywords:
            item.add_marker(skip)
