"""OLS의 명시 COM scan/show에 쓰는 순수 고정 명령 계약.

포트·환경·파일을 조회하지 않는다. profile 지문은 명령 의미를 승인 입력에 결속할
상수이며 장치 신원이나 공급자 바이너리의 생성 증명을 대신하지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from .errors import ValidationFailed
from .ports import parse_win_com


PROFILE_ID = "ols-serial-v1"
DRIVER = "ols"

# libsigrok 0.5.2의 OLS scan은 같은 conn에 reset 5회와 ID/metadata를 보낸다.
# 이 정의를 바꾸면 승인 지문도 달라진다. 런타임 경로·관찰 시각·COM은 넣지 않는다.
_PROFILE = {
    "profile_id": PROFILE_ID,
    "driver": DRIVER,
    "modes": ["scan", "show"],
    "argv": ["--driver=ols:conn={conn}", "--dont-scan", "--{mode}"],
    "serialcomm": "115200/8n1",
    "probe": {"reset_hex": "00", "reset_count": 5, "id_hex": "02", "metadata_hex": "04"},
}
PROFILE_SHA256 = hashlib.sha256(
    (json.dumps(_PROFILE, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
).hexdigest()
del _PROFILE


def _invalid() -> ValidationFailed:
    return ValidationFailed(
        "고정 OLS profile의 scan/show와 COM1–COM4096만 허용합니다.",
        code="sigrok_com_invalid",
    )


@dataclass(frozen=True)
class ComCommand:
    """정규 COM 한 개와 닫힌 조회 동작. 포트 열기·위험도 승인 자체는 수행하지 않는다."""

    profile_id: str
    mode: str
    conn: str

    def __post_init__(self) -> None:
        if (type(self.profile_id) is not str or self.profile_id != PROFILE_ID
                or type(self.mode) is not str or self.mode not in ("scan", "show")
                or type(self.conn) is not str or not 4 <= len(self.conn) <= 7):
            raise _invalid()
        number = parse_win_com(self.conn)
        if number is None:
            raise _invalid()
        object.__setattr__(self, "conn", f"COM{number}")

    @property
    def argv_tail(self) -> tuple[str, str, str]:
        """공백 분리나 shell 해석 없이 전달할 정확한 세 인자."""
        return (f"--driver=ols:conn={self.conn}", "--dont-scan", f"--{self.mode}")

    @property
    def profile_sha256(self) -> str:
        return PROFILE_SHA256

    def approval_identity(self) -> dict[str, str]:
        """가변 호출자 dict와 내부 명령을 분리한 안정적인 승인 투영."""
        return {"profile_id": self.profile_id, "profile_sha256": PROFILE_SHA256,
                "driver": DRIVER, "mode": self.mode, "conn": self.conn}


def from_argv_tail(tail: tuple[str, ...]) -> ComCommand:
    """제어 프로세스 신원 검증용 역해석. 별칭·재정렬·옵션 확장은 허용하지 않는다."""
    prefix = "--driver=ols:conn="
    if (type(tail) is not tuple or len(tail) != 3
            or any(type(arg) is not str for arg in tail)
            or len(tail[0]) > len(prefix) + 7
            or not tail[0].startswith(prefix)
            or tail[1] != "--dont-scan" or tail[2] not in ("--scan", "--show")):
        raise _invalid()
    command = ComCommand(PROFILE_ID, tail[2][2:], tail[0][len(prefix):])
    if command.argv_tail != tail:
        raise _invalid()
    return command
