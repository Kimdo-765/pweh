"""PWEH 공통 예외.

모든 예외는 기계가 읽을 수 있는 ``code``와 사람이/에이전트가 읽을 ``hint``를 가진다.
MCP 서버에서는 mcpkit 이 이 예외를 ToolError 로 변환해 에이전트에게 메시지를 그대로 전달한다
(SDK 2.x 는 일반 예외의 메시지를 클라이언트에 숨기기 때문).
"""

from __future__ import annotations

from typing import Any


class PwehError(Exception):
    """PWEH 기본 예외."""

    code: str = "pweh_error"

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        hint: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        self.hint = hint
        self.data = data or {}

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.hint:
            out["hint"] = self.hint
        if self.data:
            out["data"] = self.data
        return out

    def __str__(self) -> str:  # 에이전트가 보는 문자열
        text = f"[{self.code}] {self.message}"
        if self.hint:
            text += f"\n힌트: {self.hint}"
        return text


class ConfigError(PwehError):
    code = "config_error"


class CaseError(PwehError):
    code = "case_error"


class NotFound(PwehError):
    code = "not_found"


class ValidationFailed(PwehError):
    code = "validation_failed"


class AuthorizationRequired(PwehError):
    """케이스에 소유/허가 증명(authorization)이 기록되지 않았을 때."""

    code = "authorization_required"


class SafetyDenied(PwehError):
    """안전 정책에 의해 거부된 작업."""

    code = "safety_denied"


class DeviceError(PwehError):
    """하드웨어/포트/외부 프로세스와의 통신 실패."""

    code = "device_error"


class TimeoutExpired(PwehError):
    code = "timeout"


class ToolMissing(PwehError):
    """필요한 외부 도구(sigrok-cli, openocd 등)를 찾을 수 없음."""

    code = "tool_missing"


class Busy(PwehError):
    """리소스(포트, 세션)가 다른 작업에 사용 중."""

    code = "busy"
