"""espprobe-mcp: I5 1a의 in-process HELLO/HB 시뮬레이터 전용 서버."""

from __future__ import annotations

import atexit
from contextlib import asynccontextmanager

from pweh.mcpkit import ANN_LOCAL_WRITE, ANN_READ_ONLY, create_server, run_blocking, safe_tool
from pweh.runtime import Runtime, get_runtime

from .driver import MAX_LIFETIME_SECONDS, MAX_SESSIONS, PORT, SessionManager

SERVER_NAME = "espprobe-mcp"
manager = SessionManager()
atexit.register(manager.close_all)


@asynccontextmanager
async def lifespan(_server):
    try:
        yield {}
    finally:
        await run_blocking(manager.close_all)


server = create_server(
    SERVER_NAME, title="PWEH espprobe simulator", lifespan=lifespan,
    instructions=(
        "ESP 계측기 I5 1a 오프라인 시뮬레이터. espprobe_connect(case_id, port='sim://probe-hello') → "
        "espprobe_self_test → espprobe_disconnect 순서로 HELLO와 HB 왕복을 검증한다. 케이스 소유/허가가 필요하다. "
        "실제 포트·소켓·기기·플래시 전송 계층은 없다. 모든 결과는 simulator_only=true, hardware_verified=false이며 "
        "합성 식별·hash는 실제 펌웨어 출처가 아니다. 세션은 최대 600초·16개, 하트비트 만료 후 자동 재접속하지 않는다. "
        "probe/에 결과를 기록한다. release/disconnect는 케이스 허가가 철회된 뒤에도 정리할 수 있다."
    ),
)


def rt() -> Runtime:
    return get_runtime(SERVER_NAME)


@server.tool(description="시뮬레이터 백엔드·프로토콜 버전과 한도 조회. 장치 열거·외부 프로세스 실행 없음.", annotations=ANN_READ_ONLY)
@safe_tool
def espprobe_version() -> dict:
    return {"ok": True, "backend": "in-process", "protocol_version": 1, "profile": "probe-hello",
            "ports": [PORT], "simulator_only": True, "hardware_verified": False,
            "limits": {"sessions": MAX_SESSIONS, "lifetime_seconds": MAX_LIFETIME_SECONDS}}


@server.tool(description=(
    "케이스의 합성 HELLO/HB 시뮬레이터 연결. port는 정확히 sim://probe-hello만 허용하며 실제 포트는 열지 않는다. "
    "nonce·세션·USB 식별·빈 핀/버스/무선 정책을 고정 합성 기대값과 대조하고 HB를 시작한다. "
    "케이스당 한 세션, 전체 16개, 최대 600초. 반환 hello의 hash/MAC은 실제 기기 증거가 아니다."
), annotations=ANN_LOCAL_WRITE)
@safe_tool
async def espprobe_connect(case_id: str, port: str = PORT) -> dict:
    case = rt().case(case_id)
    return {"ok": True, **await run_blocking(manager.connect, case, port)}


@server.tool(description="현재 프로세스의 시뮬레이터 세션 상태·해제 사유·카운터 조회. case_id 생략 시 전체(최대16개).", annotations=ANN_READ_ONLY)
@safe_tool
async def espprobe_status(case_id: str | None = None) -> dict:
    return {"ok": True, "simulator_only": True, "hardware_verified": False,
            "sessions": await run_blocking(manager.status, case_id)}


@server.tool(description=(
    "연결된 모델의 HELLO 정책과 새 HB 왕복을 확인하고 결과를 케이스에 기록한다. "
    "실제 USB·핀·전압·펌웨어 부팅을 시험한 결과가 아니다. 해제된 세션을 자동으로 다시 연결하지 않는다."
), annotations=ANN_LOCAL_WRITE)
@safe_tool
async def espprobe_self_test(case_id: str) -> dict:
    return {"ok": True, **await run_blocking(manager.get(case_id).self_test)}


@server.tool(description="시뮬레이터에 RELEASE를 보내고 HB를 끝낸다. 반복 호출해도 해제 상태를 유지한다. 실제 핀 제어 없음.", annotations=ANN_LOCAL_WRITE)
@safe_tool
async def espprobe_release_all(case_id: str) -> dict:
    return {"ok": True, **await run_blocking(manager.get(case_id).close, op=2)}


@server.tool(description="모델에 BYE를 보내고 시뮬레이터·HB worker를 종료한다. 최종 JSON을 아티팩트로 기록하며 반복 호출 가능.", annotations=ANN_LOCAL_WRITE)
@safe_tool
async def espprobe_disconnect(case_id: str) -> dict:
    return {"ok": True, **await run_blocking(manager.disconnect, case_id)}


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
