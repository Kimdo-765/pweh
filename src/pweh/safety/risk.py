"""위험도 모델.

- OBSERVE     : 관찰만 함 (포트 목록, 수신 버퍼 읽기, 로직 캡처)
- INTERACT    : 기기에 명령을 보내지만 상태를 바꾸지 않음 (printenv, md, cat /proc/mtd, sf read → RAM)
- MODIFY      : 휘발성 상태 변경 (setenv(저장 안 함), boot, reset, halt, 네트워크 설정, 서비스 시작)
- DESTRUCTIVE : 영구 변경 또는 하드웨어 손상 가능 (플래시 쓰기/삭제, saveenv, eFuse/OTP, 전압 인가,
                임의 MMIO 쓰기, 영구 파티션 파일 쓰기) — 기본 정책은 거부(deny)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Iterable


class Risk(IntEnum):
    OBSERVE = 0
    INTERACT = 1
    MODIFY = 2
    DESTRUCTIVE = 3

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: "Risk | int | str") -> "Risk":
        if isinstance(value, Risk):
            return value
        if isinstance(value, int):
            return cls(value)
        text = str(value).strip().upper()
        try:
            return cls[text]
        except KeyError:
            raise ValueError(f"알 수 없는 위험도: {value!r}") from None


@dataclass(frozen=True)
class Classification:
    """명령 하나(또는 줄 하나)의 위험도 분류 결과."""

    risk: Risk
    rule_id: str
    reason: str
    matched: str | None = None  # 규칙을 촉발한 부분 문자열(세그먼트)
    uncertain: bool = False  # 정적 분석으로 실제 동작을 확정할 수 없어 보수적으로 분류함
    details: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "risk": self.risk.label,
            "rule_id": self.rule_id,
            "reason": self.reason,
        }
        if self.matched is not None:
            out["matched"] = self.matched
        if self.uncertain:
            out["uncertain"] = True
        if self.details:
            out["details"] = list(self.details)
        return out


def worst(items: Iterable[Classification], default: Classification | None = None) -> Classification:
    """가장 위험한 분류를 반환 (동률이면 먼저 나온 것)."""
    best: Classification | None = None
    for c in items:
        if best is None or c.risk > best.risk:
            best = c
    if best is None:
        if default is None:
            return Classification(Risk.OBSERVE, "empty", "빈 입력")
        return default
    return best
