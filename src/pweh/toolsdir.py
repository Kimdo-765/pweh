"""외부 도구 디렉터리(기본 ~/pweh-tools)와 그 env.sh 의 위치.

`scripts/install.sh` 와 `scripts/mcp-launch.sh` 와 같은 규칙을 쓴다 (우선순위 순):
1. 환경변수 `PWEH_TOOLS_ENV` (env.sh 경로) / `PWEH_TOOLS_DIR` (도구 디렉터리)
2. 설치 스크립트가 남긴 저장소의 `.pweh/tools-env.path` (`--prefix` 로 다른 곳에 설치했을 때, 한 줄짜리 env.sh 경로)
3. `~/pweh-tools`
"""

from __future__ import annotations

import os
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
POINTER = _REPO / ".pweh" / "tools-env.path"


def _pointer() -> Path | None:
    """포인터의 첫 줄 (scripts/mcp-launch.sh 의 head -n 1 과 같음). 가리키는 env.sh 가 없으면 무시한다."""
    try:
        lines = POINTER.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    text = lines[0].strip() if lines else ""
    p = Path(text).expanduser() if text else None
    return p if p is not None and p.is_file() else None


def tools_env() -> Path:
    """외부 도구 env.sh 경로 (있는지는 확인하지 않는다)."""
    v = os.environ.get("PWEH_TOOLS_ENV")
    if v:
        return Path(v).expanduser()
    if os.environ.get("PWEH_TOOLS_DIR"):
        return Path(os.environ["PWEH_TOOLS_DIR"]).expanduser() / "env.sh"
    return _pointer() or (Path.home() / "pweh-tools" / "env.sh")


def tools_dir() -> Path:
    """외부 도구 디렉터리 (있는지는 확인하지 않는다)."""
    v = os.environ.get("PWEH_TOOLS_DIR")
    if v:
        return Path(v).expanduser()
    return tools_env().parent


__all__ = ["POINTER", "tools_dir", "tools_env"]
