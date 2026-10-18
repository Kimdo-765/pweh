"""공통 pytest fixture.

모든 테스트는 임시 작업공간(케이스/상태 디렉터리 + 테스트용 pipeline-config.yaml)에서 실행되어
실제 저장소의 cases/ 나 .pweh/ 를 건드리지 않는다.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tests"))


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
