"""JSON Schema 로더/검증기.

스키마 파일은 이 패키지 디렉터리(src/pweh/schemas/*.schema.json)에 있으며, 저장소 루트의
``schemas/`` 는 이 디렉터리를 가리키는 심볼릭 링크다.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from ..errors import ValidationFailed

SCHEMA_DIR = Path(__file__).resolve().parent

# Skill 이름 → 최종 요약(step=='summary')의 data 스키마
SKILL_DATA_SCHEMAS: dict[str, str] = {
    "uart-shell-acquisition": "uart-recon",
    "firmware-dump-via-uart": "firmware-dump",
    "firmware-static-analysis": "static-analysis",
    "logic-analyzer-protocol-decode": "signal-capture",
    "cctv-auth-bypass-hunt": "auth-hunt",
    "game-save-unlock-analysis": "save-analysis",
}


def list_schemas() -> list[str]:
    return sorted(p.name[: -len(".schema.json")] for p in SCHEMA_DIR.glob("*.schema.json"))


@lru_cache(maxsize=None)
def load(name: str) -> dict[str, Any]:
    path = SCHEMA_DIR / f"{name}.schema.json"
    if not path.exists():
        raise ValidationFailed(f"알 수 없는 스키마: {name}", hint=f"사용 가능: {', '.join(list_schemas())}")
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=None)
def _validator(name: str) -> Draft202012Validator:
    schema = load(name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def errors(name: str, instance: Any, limit: int = 8) -> list[str]:
    out = []
    for err in sorted(_validator(name).iter_errors(instance), key=lambda e: list(e.absolute_path)):
        loc = "/".join(str(p) for p in err.absolute_path) or "(root)"
        out.append(f"{loc}: {err.message}")
        if len(out) >= limit:
            break
    return out


def validate(name: str, instance: Any, label: str | None = None) -> None:
    errs = errors(name, instance)
    if errs:
        raise ValidationFailed(
            f"{label or name} 스키마 검증 실패 ({name}.schema.json): " + "; ".join(errs),
            hint=f"스키마 파일: schemas/{name}.schema.json",
            data={"errors": errs, "schema": name},
        )
