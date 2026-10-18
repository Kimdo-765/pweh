"""MCP 테스트 헬퍼: in-memory Client 와 stdio Client 를 같은 방식으로 다룬다."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp import Client, StdioServerParameters

REPO_ROOT = Path(__file__).resolve().parents[1]
VENV_PY = REPO_ROOT / ".venv" / "bin" / "python"


def result_data(res: Any) -> dict[str, Any]:
    """CallToolResult → dict. 오류면 AssertionError 대신 {'_error': text} 반환."""
    if getattr(res, "is_error", False):
        text = "".join(getattr(c, "text", "") for c in res.content)
        return {"_error": text}
    sc = getattr(res, "structured_content", None)
    if sc is not None:
        # dict 반환 도구는 그대로, 래핑된 경우 result 키
        if isinstance(sc, dict) and set(sc) == {"result"}:
            return sc["result"]
        return sc
    text = "".join(getattr(c, "text", "") for c in res.content)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"_text": text}


async def call(client: Client, tool: str, **args: Any) -> dict[str, Any]:
    res = await client.call_tool(tool, args)
    return result_data(res)


def stdio_params(module: str, env: dict[str, str] | None = None) -> StdioServerParameters:
    full_env = {k: v for k, v in os.environ.items()}
    full_env.update(env or {})
    py = str(VENV_PY if VENV_PY.exists() else Path(sys.executable))
    return StdioServerParameters(command=py, args=["-m", module], env=full_env, cwd=str(REPO_ROOT))
