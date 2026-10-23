# pweh-espprobe — 오프라인 프로토콜 시험

공개 도구는 I5 1a의 `probe-hello` 시뮬레이터만 제공한다. `sim://probe-hello`는 서버 내부 모델의 고정 이름이다.
공개 COM·tty·소켓 연결과 임의 프레임 송신 도구는 없다. 프로토콜은
[espprobe-protocol.md](../../docs/references/espprobe-protocol.md), 서버 계약은
[architecture.md](../../docs/architecture.md) §6.10을 따른다.

케이스 소유/허가 확인 뒤 `espprobe_connect` → `espprobe_self_test` → `espprobe_disconnect` 순서로 쓴다.
`espprobe_version`은 백엔드·한도, `espprobe_status`는 현재 프로세스의 세션을 보여 준다.
`espprobe_release_all`은 모델에 RELEASE를 보내고 하트비트를 멈춘다.

HELLO의 nonce·세션·합성 식별·빈 핀/버스/무선 정책을 호스트의 독립 기대값과 비교하고, HB는 정확한 프레임
왕복으로 확인한다. 결과에는 항상 `simulator_only=true`, `hardware_verified=false`가 있다.
모델의 MAC·hash·commit은 합성 값이며 실제 릴리스나 기기 출처 증명이 아니다.

케이스당 한 세션, 프로세스당 16개, 최대 600초다. HB 간격은 1초 기한의 1/3이고, 스케줄 지연으로 기한을
넘으면 먼저 해제한다. 해제된 세션을 자동 재연결하지 않는다. 종료·MCP lifespan 정리 때 모델과 HB worker를
닫으며, `probe/espprobe-sim-*.json`을 케이스 아티팩트로 등록한다. 허가 철회 뒤에도 정리는 가능하다.

실제 `probe-hello` 펌웨어의 USB 열거·부팅·해제 지연·전기적 상태는 이후 1b에서 사람이 확인할 항목이다.
현재 분석 대상 ESP 보드의 역할을 바꾸거나 플래시하는 절차는 이 서버에 없다.

내부 소프트웨어에는 [고정 릴리스 입장·직렬 owner](../../docs/references/espprobe-serial-owner.md)와
[호스트 시험용 SPI/I²C 코어](../../docs/references/espprobe-bus-core.md)가 있다. 합성 transport/HAL로
수명과 제한을 시험하며 실제 admission 생산자·GPIO/버스 wire·운영 job은 연결하지 않는다.
고정 `probe-hello` 이미지와 공개 여섯 도구의 의미는 그대로다.
