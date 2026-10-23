# ESP 계측기의 호스트 시험용 SPI/I²C 코어

`firmware/espprobe/bus/`는 제한된 읽기 계획, 흐름 제어와 해제를 처리하는 C11 코드다.
실제 C를 합성 HAL에 연결해 시험하며 동적 할당·ESP-IDF·파일·네트워크를 사용하지 않는다.
init은 새 저장소의 초기화에만 사용하며 살아 있는 context나 HAL callback에서 다시 호출하지 않는다.
현재 `probe-hello` 이미지의 빌드 입력에는 이 파일들을 넣지 않는다. 공개 MCP, 새 wire op,
버스 기능 광고·GPIO adapter·덤프 파일과 출처 원장은 이 코어에 포함되지 않는다.

## 내부 세션과 읽기 계획

호출자는 기존 HELLO에서 얻은 session·USB generation·sequence·boot identity와
하트비트 기한을 내부 binding으로 전달한다. 이 계층은 nonce를 다시 만들거나 외부
binding의 진위를 증명하지 않는다. 같은 세대의 해제된 세션을 되살리지 않는다.

내부 wiring은 한 버스의 논리 핀, 허용·제외 mask와 전압, I²C의 장치 주소·주소 폭·용량을
고정한다. 실제 보드 핀 표와 사람 증명으로 이 값을 생산하는 운영 adapter는 별도다.
읽기 계획은 종류, device index 0, offset·length, 1회 또는 2회 패스만 받는다.
호출자가 BEGIN에 opcode·송신 바이트·클럭·I²C 주소 폭을 넣을 수 없다.
범위 계산은 u64 중간값으로 검사하며 정한 용량을 넘어 wrap하지 않는다.

상태는 RELEASED → BOUND → READY → RUNNING → DONE이다. 같은 seq·같은 계획은
이전 응답만 반환하고 버스를 다시 실행하지 않는다. 같은 seq의 다른 계획과 cache 밖의
옛 seq는 거부한다. cache 4개와 REQ high-water를 구분하고, HB sequence도 따로 유지한다.
향후 wire dispatcher는 기존 전체 canonical 요청의 동일성과 전역 sequence를 먼저
검사해야 한다. typed 계획의 동일성이 wire 동일성을 대신하지 않는다.

## SPI 읽기 제한

모든 SPI 송신은 `probe_spi_xfer` 한 경계를 거친다. 내부에서 만든 descriptor의 첫 송신 바이트와
주소·dummy·읽기 길이를 검사한 뒤 CS를 활성화한다. 같은 순수 검사 함수로 오염된 descriptor의
거부도 시험하며, caller가 임의 descriptor를 전송하는 입구는 제공하지 않는다. 임의 raw TX 배열을 받지 않는다.

| opcode | 허용 형식 |
|---|---|
| `03`, `0B` | 3바이트 주소, 확인된 용량과 24비트 범위 안. `0B`만 dummy 1바이트 |
| `9F` | 주소·dummy 없이 JEDEC ID 3바이트 |
| `90` | 고정 주소 0의 3바이트, ID 2바이트 |
| `AB` | dummy 3바이트, ID 1바이트. deep-power-down 해제 효과가 있음 |
| `5A` | 3바이트 SFDP 주소, dummy 1바이트, 제한된 표 읽기 |
| `05` | 주소·dummy 없이 SR1 1바이트 |
| `13`, `0C` | 장치에서 읽은 SFDP가 큰 용량과 해당 4바이트 명령을 확인한 경우. `0C`만 dummy 1바이트 |

일반 probe 순서는 `9F → 05 → SFDP`이며 `90/AB`를 자동으로 추가하지 않는다.
범위 읽기는 `03` 또는 `13`을 선택한다. `35`, 쓰기·지우기·상태 변경·4바이트 모드
진입/해제 등 나머지 명령은 거부한다. 실제 칩의 SPI/QPI·주소 모드를 이 목록만으로
확인했다고 하지 않는다.

SFDP는 `5A`로 받은 데이터에서만 해석한다. 외부 `supports_4byte` 입력이나 RDID 용량
바이트로 읽기 권한을 올리지 않는다. header 최대 16개, 전체 읽기 4096바이트,
한 읽기 256바이트 한도에서 BFPT의 처음 9 DWORD와 4BAIT의 처음 2 DWORD만 해석해
주소 폭·density와 READ/FAST 지원을 확인한다. 표의 나머지 필드를 검증했다는 뜻은 아니다.
중복·모순·잘림·overflow·미지원 형식은 범위 읽기 권한을 만들지 않는다.
16 MiB 초과인데 필요한 4BAIT가 없으면 모드 전환이나 3바이트 우회 읽기를 하지 않는다.
구조 근거는 [Linux v6.12 SFDP 해석](https://github.com/torvalds/linux/blob/v6.12/drivers/mtd/spi-nor/sfdp.c)이다.
구현 코드를 복사하거나 제조사별 쓰기 예외를 가져오지 않는다.

## I²C EEPROM 읽기

한 24Cxx 장치의 명시된 7비트 주소 `08..77h`, 주소 폭 1 또는 2바이트와 용량만 받는다.
자동 scan·bank-select·quick-write·10비트 주소는 없다. 청크는 최대 32바이트이며 순서는
`START → addr+W → 주소 bytes → repeated START → addr+R → 읽기 → STOP`이다.
주소는 MSB-first이고 마지막 읽기 바이트에만 NACK를 보낸다. 데이터 쓰기와 주소 단계
중간의 STOP은 없다.

주소 단계 NACK, 취소, 전압·HB 상실에서는 정상 STOP 복구나 bus-clear clock을 보내지
않고 해제한다. 오류 뒤 남은 바이트를 재시도하거나 다른 장치 주소로 wrap하지 않는다.
실제 24Cxx 모델·배선·전압·주소 폭은 합성 trace로 확인할 수 없는 운영 사실이다.

## 시간·전압·흐름 제어와 해제

모든 API와 실제 byte/버스 phase의 전후에서 같은 guard를 사용한다. HAL의 clock과 VREF
표본을 읽고 clock을 다시 확인한다. 시계 역행·HB 만료·미래/오래된 표본·invalid 전압이면
다음 phase를 실행하지 않는다. VREF는 age 1 ms 이하, 3000..3600 mV와 선언값 ±10%의
교집합이어야 한다. callback 자체는 유한·동기 실행 계약이며 이 코어가 선점하지 않는다.

credit은 청크 단위이며 최대 4개다. 새 유효 HB sequence만 liveness와 credit을 한 번
갱신한다. 중복 HB가 기한을 늘리거나 이미 끝난 작업을 재시작하지 않는다. 한 step은
credit 한 개를 먼저 차감하고 SPI 최대 256바이트 또는 I²C 최대 32바이트만 읽는다.

읽기·정상 CS 해제/STOP 뒤 필수 `deliver_chunk` callback이 한 번 데이터를 소비한다.
false면 credit 복구·재읽기·재전달 없이 해제한다. true 직후 guard가 실패하면 이미 한
청크가 전달됐을 수 있지만 작업은 실패다. 정상 소비와 guard 유지가 확인돼야 cursor와
DONE을 확정한다. 두 패스는 같은 범위를 읽는 계약이며 SHA 일치나 실제 버스 신뢰성
검증을 대신하지 않는다.

해제는 session·연산·credit·SPI 권한을 먼저 무효화한 뒤 기록한 claim mask에 대해 HAL
abort를 한 번 호출한다. 반복 해제는 다른 핀을 건드리지 않는다. partial claim도 같은
정리 대상에 포함한다. abort는 정상 STOP/CS 전송이나 유효 전압에 의존하지 않는다.

## 검증 범위

호스트 시험은 기존 C HELLO/session과 새 코어를 명시적으로 링크하고, 256개 SPI opcode,
SFDP·주소 경계, I²C trace, 두 패스·중복·credit, 각 phase의 전압/시간/해제 사건과 출력
소비 실패를 검사한다. 고정 입력·trace·프로세스 상한과 canary를 사용한다.

실제 GPIO/ADC·DMA·USB dispatch, 1 ms 표본 갱신·2 ms Hi-Z, 전기적 글리치와 하트비트
지터는 이 시험의 보장이 아니다. 현재 hello-only wire의 credit 0과 빈 버스 정책도 그대로다.
운영 연결은 [내부 직렬 owner](espprobe-serial-owner.md)의 미완료 사실과
[계측기 설계의 1b·1c 관문](../design/esp32-instrument.md)을 먼저 충족해야 한다.
