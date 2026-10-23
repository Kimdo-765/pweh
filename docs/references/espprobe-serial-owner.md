# ESP 계측기 내부 직렬 연결 수명

`espprobe_release`, `espprobe_admission`, `espprobe_mcp.serial_owner`는 등록 릴리스와
입장 사실을 소비하고 HELLO·하트비트·종료를 같은 직렬 핸들에서 처리하는 내부 코드다.
공개 MCP는 계속 `sim://probe-hello` 전용 여섯 도구다. 내부 코드를 추가했다고 COM/tty
연결을 공개하거나 실제 장치 검증이 끝난 것으로 표시하지 않는다.

## 등록 릴리스와 입장 사실

릴리스 로더는 패키지의 `pweh.data/espprobe-releases.json`에서
`0.1.0 / probe-hello / esp32s3-devkitc1-hello` 한 항목을 검증한다.
호출자가 catalog 경로·버전·프로필·신뢰 루트를 바꾸는 인자는 없다. 등록 catalog는
최대 1 MiB·100개이며, 기존 릴리스 검사에 더해 USB metadata와 정확한 숫자형을 확인한다.
USB 정책은 VID/PID `303a:4002`, 제품 `PWEH espprobe`, base MAC에서 만든 12자리 대문자
serial, CDC 두 기능이다. 이미지 digest와 앱 파일 전체 SHA·merged 파일 SHA는 서로 구분한다.
정책 SHA는 catalog의 policy blob 검증에 사용하며 HELLO에 없는 정책 hash 필드를 요구하지 않는다.

입장 검사는 같은 케이스·MAC의 chip/security 사실, 두 전체 플래시 백업, 현재
`instrument-pin` 증명과 완전한 USB 관찰을 frozen 값 객체로 받는다. 검증하는 관계는 다음과 같다.

- ESP32-S3 chip·revision·플래시 크기와 보안 상태가 일치한다. Secure Boot·플래시 암호화·
  Secure Download Mode는 꺼져 있고 읽기 가능 사실이 확인돼야 한다.
- primary/verification은 서로 다른 전체 device-read 기록이며 offset 0, 같은 크기·SHA,
  double/match 조건과 현재 보유 바이트의 해시가 일치해야 한다.
- pin은 현재 질문·바인딩과 맞는 증명에서 온 값이어야 한다. 오래된 pin을 다른 도구에서
  보호하기 위한 `load_pins()`의 active 값만으로 신규 연결을 허용하지 않는다.
- 선택 포트는 native control MI_00이다. 같은 USB 부모의 제품·서비스·전체 interface와
  scope, boot/aux 관찰이 완전해야 한다. MI_02·ROM·USB-UART·네트워크 경로를 대신 받지 않는다.

값 객체의 생성자나 SHA 일치는 외부 사실의 진위를 증명하지 않는다. 운영 어댑터는 보호 원장
체인과 개별 사실 digest, 백업의 같은 FD 바이트, 현재 증명 및 실제 OS 관찰을 먼저 검증해야 한다.
현재는 실제 pin subject/flash 계획과 완전한 descriptor·service·aux 관찰을 생산하는 운영
경로가 없다. `PortIdentity`만으로 이 사실을 채울 수 없으며 누락 입력은 lease·open·TX 전에
거부한다. 시험의 합성 projection을 운영 사실로 등록하는 경로도 없다.

## 한 worker가 소유하는 연결

`reserve_probe_owner`는 입장 값과 기존 whole USB scope의 lease를 인수한다.
케이스당 하나, 프로세스당 16개 한도에는 정리 미확인 owner도 포함한다.
`start_probe_worker`와 `LeaseHandoff`는 worker가 자원을 인수하기 전·후의 취소를 구별한다.

| 시점 | 동작 |
|---|---|
| worker 인수 전 취소 | 늦게 시작한 worker의 open을 막고 미개방 lease를 정리한다 |
| open 직전 | fresh 신원·scope·pin·역할과 lease를 callback으로 다시 확인한다 |
| 열린 핸들 확인 | 같은 worker가 after-open 검사를 마친 뒤에만 HELLO를 보낸다 |
| 정상 세션 | 한 I/O worker가 read/write/HB를 소유하고 caller는 제한된 요청만 전달한다 |
| 취소·오류·수명 종료 | 같은 owner에 stop을 기록하며 자동 재연결하지 않는다 |
| 종료 확인 | worker를 실제 join하고 transport의 물리 정리를 확인한 뒤 lease를 반환한다 |

공통 `SerialTransport`와 Windows `HelperSerial`을 사용한다. DTR/RTS는 open 전부터 false,
115200/8N1, read chunk는 최대 16 KiB다. 매 write의 timeout은 남은 예산 이하로 전달한다.
새 flush·BREAK·buffer purge·일반 프레임 송신 기능은 없다.

start와 self-test의 작업 예산은 각각 최대 5초, cleanup은 최대 10초, 세션 수명은 최대 600초다.
start 실패 뒤에는 별도의 cleanup 대기가 붙을 수 있다. 이 값은 caller의 유한 대기와 협력 checkpoint다. 기존 OS open/write/close를 그 시각에 강제로
끝낸다는 보장은 아니다. 늦은 open·write·close를 소유한 worker가 남으면 owner와 lease도
보존하고, 늦게 open이 반환했을 때에는 HELLO 없이 정리한다.

## HELLO·하트비트·종료

HELLO는 새 random nonce 16바이트, request seq 1/session 0이다. 응답의 envelope,
nonce·nonzero token·boot ID·USB generation을 검사하고 등록 릴리스·정책·권위 신원과
대조한다. 장치가 돌려준 hash/MAC은 자기 보고이며 암호학적 remote attestation은 아니다.

하트비트는 요청 seq와 독립된 u32 sequence로 1000 ms의 1/3마다 전송한다.
outstanding은 하나이며 정확히 같은 프레임 echo만 ACK로 인정한다. self-test는 호출 이후의
새 HB 왕복을 기다린다. stale seq/token·CRC·길이·예상 밖 프레임·부분 수신 마감·시계 역행은
terminal이며 수신 조각마다 마감을 늘리지 않는다.

첫 RELEASE 또는 BYE 선택은 request seq 2의 고정 bytes가 된다. ACK가 유실되면 최초
cleanup deadline 안에서 동일 요청을 최대 한 번 재전송한다. 프로토콜 해제 ACK와 실제
worker/transport/lease 정리는 별도로 반환한다. 잘못된 HELLO 뒤에는 유효 envelope·nonce·
token을 확보한 경우에만 제한된 BYE 정리가 가능하고, 이를 입장 성공으로 사용하지 않는다.

정리 결과는 `protocol_released`, `workers_stopped`, `transport_closed`, `lease_closed`,
`cleanup_confirmed`, 고정 `reason`이다. `cleanup_confirmed`는 뒤의 세 자원 조건이 모두
확인됐을 때만 true다. ACK가 없어도 물리 정리가 확인될 수 있고, ACK가 있어도 물리 정리는
미확인일 수 있다. helper wrapper 종료나 `is_open=false`만으로 잠금을 반환하지 않는다.

## 시험 범위와 실제 사용의 잔여

합성 권위·USB 관찰과 실제 공통 transport/helper 코드를 연결하여 분할 응답, 취소·늦은
open, HB, Q/EOF·child 정리, 잠금 충돌과 정리 재시도를 시험한다. 원시 nonce·token·MAC·
PnP·포트·callback 예외는 상태나 오류에 그대로 넣지 않는다.

별도 보드의 소유/허가, 보안 상태와 독립 백업, 사람의 flash·증명, 실제 descriptor/aux,
Hi-Z·글리치·전압·하트비트 지터 확인은 여전히 필요하다. 현재 분석 대상 ESP 보드의 역할을
바꾸지 않는다. 빌드·릴리스는 [기존 1a 절차](espprobe-build.md), 실제 운영 단계는
[ESP 계측기 설계](../design/esp32-instrument.md)를 따른다.
