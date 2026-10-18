"""감사 로그 (JSON Lines).

- 전역: ``<state_dir>/audit.jsonl`` — 모든 서버의 안전 결정, 승인, 오류
- 케이스별: ``cases/<id>/audit.jsonl`` — 해당 케이스에서 일어난 모든 기기 조작
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from .fsutil import utcnow_iso

_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def _lock_for(path: Path) -> threading.Lock:
    key = str(path)
    with _LOCKS_GUARD:
        if key not in _LOCKS:
            _LOCKS[key] = threading.Lock()
        return _LOCKS[key]


class AuditLog:
    def __init__(self, path: Path, *, server: str | None = None) -> None:
        self.path = Path(path)
        self.server = server

    def write(self, event: dict[str, Any]) -> None:
        record = {"ts": utcnow_iso(), "pid": os.getpid()}
        if self.server and "server" not in event:
            record["server"] = self.server
        record.update(event)
        line = json.dumps(record, ensure_ascii=False, default=str)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _lock_for(self.path):
            # O_APPEND 쓰기는 한 줄 단위로 원자적이므로 프로세스 간에도 줄이 섞이지 않는다
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def tail(self, n: int = 50) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()[-n:]
        out = []
        for ln in lines:
            try:
                out.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
        return out
