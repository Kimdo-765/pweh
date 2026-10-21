"""핀 순열 계산·공통 결과 형식. lower_bound_seconds 기본 시간표는 JTAGulator 전용이다.

다른 프로브의 처리량 추정에 이 기본 시간표를 적용하지 않는다. 기존 계산과 import 계약을 유지한다.
"""

from __future__ import annotations

import math

SCAN_SCHEMA = "pweh.pinout-scan/v1"

BAUD_TABLE: tuple[int, ...] = (
    300, 600, 1200, 1800, 2400, 3600, 4800, 7200, 9600, 14400, 19200, 28800,
    31250, 38400, 57600, 76800, 115200, 153600, 230400, 250000, 307200,
)

def permutations(n: int, r: int) -> int:
    """n! / (n-r)! (펌웨어 Display_Permutations 와 같은 계산)."""
    if r <= 0:
        return 1
    if n < r:
        return 0
    return math.perm(n, r)


# 하한 추정의 근거 (실측이 아님):
#  - JTAG 클럭은 최대 25 kHz (CHANGES 1.9). IDCODE 1순열 = Get_Device_IDs(1) ≈ 47 TCK.
#  - BYPASS 1순열 = Detect_Devices 가 IR 체인에 1024비트 + DR 64비트 이상 시프트 ≈ 1100 TCK.
#  - UART 1순열 = 보드레이트 21개 × (cog 준비 10 ms + 응답 대기 delay ms + 첫 바이트 대기 20 ms) + 프로브 송신 시간.
JTAG_TCK_HZ_MAX = 25_000
TCK_PER_PERM = {"idcode": 47, "jtag": 47, "bypass": 1100}


def lower_bound_seconds(
    kind: str,
    perms: int,
    *,
    pins_low: bool = False,
    pins_low_ms: int = 100,
    pins_high_ms: int = 100,
    uart_delay_ms: int = 10,
    probe_len: int = 1,
) -> float | None:
    """스캔 소요 시간의 '하한' 추정(초). 펌웨어 코드와 문서화된 클럭 상한으로 계산한 값이며 실측이 아니다."""
    if kind == "uart_txd":
        return None
    extra = (pins_low_ms + pins_high_ms) / 1000.0 if pins_low else 0.0
    if kind in TCK_PER_PERM:
        per = TCK_PER_PERM[kind] / JTAG_TCK_HZ_MAX
    elif kind == "uart":
        per = 0.0
        for baud in BAUD_TABLE:
            per += (10 + uart_delay_ms + 20) / 1000.0 + (10.0 * probe_len) / baud
    else:
        return None
    return round(perms * (per + extra), 1)


