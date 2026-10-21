# espprobe wire v1 — probe-hello

이 문서는 I5 1a의 C 펌웨어, Python codec, in-process simulator가 공유하는 wire 계약이다.
현재 MCP transport는 `sim://probe-hello` 한 이름뿐이다. firmware는 오프라인 빌드 산출물이며
실제 포트 연결·플래시·타깃 버스 연산은 제공하지 않는다. `probe-hello`는 capabilities와
pin claim이 모두 없는 별도 프로필이다.

## 프레임

모든 다중 바이트 정수는 little-endian이다. header 16바이트는 Python `<BBBBIIHH>`와 같다.

| 오프셋 | 크기 | 필드 | 제약 |
| --- | --- | --- | --- |
| 0 | 1 | version | 1 |
| 1 | 1 | type | REQ=1, RSP=2, EVT=3, DATA=4, HB=5 |
| 2 | 1 | op | HELLO=1, RELEASE_ALL=2, BYE=3, ABORT=4, HB=0 |
| 3 | 1 | flags | RSP 오류 bit0만 허용, 나머지 0 |
| 4 | 4 | seq | 양의 uint32, wrap 금지 |
| 8 | 4 | session | HELLO 요청만 0, 이후 응답에서 받은 양의 토큰 |
| 12 | 2 | len | payload 바이트 수, 0..4096 |
| 14 | 2 | credit | probe-hello는 0 |

`header + payload`에 CRC32/ISO-HDLC를 계산해 uint32로 덧붙인다. CRC는 reflected polynomial
`0xedb88320`, initial/final xor `0xffffffff`이며 Python `zlib.crc32`와 같다. 전체 decoded
바이트를 canonical COBS로 인코딩하고 `00` delimiter를 하나 붙인다. 상한은 decoded 4116,
COBS 4133, delimiter 포함 4134바이트다. CRC·length·header·canonical 재인코딩을 모두 검사한다.
단일 decode는 잘림·합쳐진 프레임을 거부한다. stream reader는 초과 입력을 delimiter까지 버린 뒤
복구한다. feed 한 번의 입력 상한은 16384바이트다.

REQ/HB만 장치 입력으로 처리한다. EVT/DATA/RSP 수신은 실행하지 않는다. framing·CRC 오류는
응답 없이 invalid counter만 올린다. unsupported op는 HAL bus 호출 없이 오류 응답한다.
정수·counter 상한을 넘어 wrap하지 않으며 통계 counter는 uint64 최댓값에서 포화한다.

## TLV와 HELLO

TLV header는 `tag:uint16, length:uint16`이고 value는 선언 길이만큼이다. tag는 양수·오름차순·중복
없음, 최대 64개다. 재귀 TLV는 없다. HELLO 요청 payload는 tag1/len16 nonce 하나뿐이다.
HELLO 응답은 `status:uint16=0` 뒤 아래 tag1..27을 모두 포함한다. 알 수 없는 optional tag는
건너뛰고 high bit `0x8000`가 켜진 unknown critical tag는 거부한다.

| tag | 필드 | wire 값 |
| --- | --- | --- |
| 1 | nonce | 요청의 16바이트 그대로 |
| 2 | fw_name | printable ASCII 1..32, `PWEH espprobe` |
| 3 | fw_version | ASCII 1..32, `0.1.0` |
| 4 | build_profile | ASCII 1..32, `probe-hello` |
| 5 | board | ASCII 1..48, `esp32s3-devkitc1-hello` |
| 6 | git_commit | 소문자 hex 40글자 ASCII |
| 7 | image_sha256 | 32바이트 |
| 8 | app_elf_sha256 | 32바이트 |
| 9 | idf_version | ASCII 1..32 |
| 10 | chip | `<BHIHB>`: model, revision, psram_bytes, flash_voltage_mv, known_mask |
| 11 | base_mac | 6바이트 |
| 12 | usb VID/PID | uint16 두 개, `303a:4002` |
| 13 | usb product | ASCII 1..32, `PWEH espprobe` |
| 14 | usb serial | base_mac의 대문자 hex ASCII 12글자 |
| 15 | boot_id | 부팅 instance별 random 16바이트 |
| 16 | usb_session | 양의 uint32 |
| 17 | reset_reason | 아래 uint16 enum |
| 18 | last_release_reason | 아래 uint16 enum |
| 19 | caps | uint32=0 |
| 20 | limits | uint16 3개: max_payload=4096, hb_ms=1000, max_credit=0 |
| 21 | pins_allowed | H0/H1/H1a uint64 mask 세 개, 모두 0 |
| 22 | pclk_pad | uint8=255 (없음) |
| 23 | pin_drive | uint8=0 (없음) |
| 24 | spi_read_opcodes | 길이 0 |
| 25 | radio | uint8=0 (none) |
| 26 | tx_caps | uint32=0 |
| 27 | session_token | 양의 uint32, 응답 header.session과 같음 |

chip model은 unknown=0, esp32s3=1이다. known_mask bit0/1/2/3은 각각 model/revision/PSRAM/전압의
확인 여부다. unknown 숫자 slot은 wire 0이며 typed 결과는 null이다. 보드 enum은 hello-only 빌드
대상을 나타내며 실제 보드 판·VDD_SPI를 측정했다는 뜻이 아니다. 실제 앱도 PSRAM·flash 전압을
추정하지 않는다. typed 결과의 hashes/nonce/boot_id는 소문자 hex, MAC은 콜론 없는 소문자 hex12,
serial은 대문자 hex다. 비어 있는 caps/tx_caps/opcodes는 `[]`, pins는 `{H0:[],H1:[],H1a:[]}`,
pclk_pad/pin_drive는 null이다. hb_ms codec 범위는 250..3000이고 고정 릴리스 프로필은 1000이다.

reset_reason은 `0 unknown, 1 power-on, 2 software, 3 panic, 4 watchdog, 5 brownout,
6 deep-sleep, 7 external`이다. release reason은 `0 none, 1 boot, 2 request-release, 3 bye,
4 abort, 5 heartbeat-timeout, 6 usb-reset, 7 usb-detach, 8 usb-suspend, 9 dtr-fall,
10 transport-error, 11 internal-error, 12 sequence-exhausted, 13 clock-error, 14 host-close`다.
알 수 없는 enum은 typed decode 오류다. 모든 reserve enum이 현재 펌웨어에서 발생하는 것은 아니다.

실제 firmware image_sha256은 `esp_partition_get_sha256`의 앱 digest다. 덧붙은 이미지 digest가
있을 때 그 자체를 포함하는 app.bin 전체 SHA256과 구별한다. app_elf_sha256은 IDF 앱 설명자의 값이다.
빌드 manifest는 별도의 app.bin 전체 SHA256도 보관한다. simulator의 commit `00…00`, image hash
`11…11`, ELF hash `22…22`, MAC `020000000001`, IDF `simulator`는 합성 fixture이며 릴리스 출처가 아니다.

## 응답과 세션

RSP는 요청의 op/seq를 유지하고 `status:uint16`로 시작한다. status0이면 flags0, 오류면 flags1이다.
`0 OK, 1 POLICY, 2 UNSUPPORTED, 3 RELEASED, 4 SESSION, 5 SEQUENCE, 6 BUSY, 7 INVALID,
8 REPLAY`를 쓴다. cleanup 요청 payload는 비어야 한다. 성공 cleanup 응답은 이전 토큰과 `0000`
payload를 유지하므로 host가 ACK를 검증할 수 있다.

초기는 RELEASED이고 HELLO 성공 뒤 ACTIVE다. 토큰은 같은 boot instance에서 증가하는 혼동 방지
값이며 인증 비밀이 아니다. ACTIVE에서 동일 HELLO 재전송은 원래 응답을 돌려주고 deadline을
갱신하지 않는다. 같은 seq의 변경 요청은 SEQUENCE, 다른 새 HELLO는 BUSY다. 한 USB generation의
HELLO high-water를 보존해 만료 후 이전 HELLO가 세션을 살리지 못하게 한다.

일반 REQ는 별도 seq high-water와 4개의 정확한 canonical wire 요청/응답 cache를 쓴다. 동일 요청
재전송은 실행 없이 응답만 재송신하고, 같은 seq의 다른 요청은 SEQUENCE, cache에서 밀려난 old seq는
REPLAY다. cache eviction은 high-water를 지우지 않는다. cleanup은 session을 먼저 무효화한 뒤
HAL release를 한 번 호출하고 ACK를 tombstone 하나로 보관한다. 반복 cleanup은 ACK만 재전송한다.

HB는 type5/op0/len0/flags0/credit0, 현재 session과 별도 단조 증가 HB seq를 요구한다. 유효 HB의
ACK는 요청 canonical wire와 정확히 같다. duplicate/old HB는 ACK 없이 버리고 deadline도 연장하지
않는다. 모든 교환 전에 `now_ms >= deadline_ms`이면 먼저 release한다. Python 모델과 C fake clock은
정확한 경계에서 검사하며 실제 firmware worker는 10ms 간격 및 각 입력 처리 전에 poll한다. host는
333ms마다 HB를 보내고 ACK에 다시 응답하지 않는다. 시간 역행/overflow는 거부·release한다.

USB reset/detach는 parser·cache·tombstone을 지우고 usb_session을 올린다. 이전의 nonzero session
토큰은 무효지만 새 generation에서는 session0 HELLO를 다시 허용한다. 이전 generation의 HELLO
바이트 자체가 재생되지 않는다는 보장은 하지 않는다. suspend/DTR fall/transport error도 release하며
resume/attach/DTR 상승은 자동으로 세션을 활성화하지 않는다. generation/token uint32 소진 뒤 wrap하지
않는다. close는 idempotent이고 이미 released라면 최초 release reason을 보존한다.

## 구현과 검사

`pweh.espprobe_protocol`은 frozen `Frame`, `encode/decode`, `StreamDecoder`, `encode_tlvs/decode_tlvs`,
`encode_hello/decode_hello`를 제공한다. `ProbeSimulator`는 `exchange`, `advance`, `snapshot`, `close`를
제공하고 fault용 `transport_event`는 단위시험에서만 쓴다. 모델의 허용 opcode 정책은 driver 상수표를
import하지 않는다. snapshot에는 state/session/generation/clock/deadline/reason과 포화 counter가 있다.

C 진입점은 `pweh_probe_init/feed/poll/release/transport_reset`이다. HAL은 bounded emit과 release뿐이고
타깃 bus 함수가 없다. IDF adapter는 static RX/frame/cache/TX buffer를 사용한다. TinyUSB callback은
원자적 사건 latch만 갱신하고 worker가 상태를 소유한다. bus reset은 `tud_event_hook_cb`에서도 받아
처리한다. TX flush는 timeout0이고 queue 실패는 release한다. CDC1 입력은 버리며 DTR/RTS/baud를
타깃 신호로 사용하지 않는다. worker는 bounded 입력 예산 후 양보하고 task watchdog에 등록한다.
claim한 타깃 핀이 없으므로 release는 USB/예약 GPIO를 재설정하지 않는다.

고정 golden 예: HB(type5/op0/seq1/session1)의 wire는
`0301050102010101020101010101010105be285b2600`이다. 시험은 고정 HELLO/HB/cleanup 바이트,
최대 payload/COBS 경계, 변조/잘림/overflow 복구, Python/C differential, cache/replay/만료/USB 사건,
HAL 실패와 메모리 canary를 검사한다. 외부 C 시험은 Zig를 사용하며 실제 하드웨어는 필요하지 않다.

근거 API는 [esp_tinyusb 2.4.0 CDC header](https://github.com/espressif/esp-usb/blob/fc9bead/device/esp_tinyusb/include/tinyusb_cdc_acm.h),
[TinyUSB 설정과 lifecycle](https://github.com/espressif/esp-usb/blob/fc9bead/device/esp_tinyusb/include/tinyusb.h),
[TinyUSB device event 처리](https://github.com/hathach/tinyusb/blob/0.21.0/src/device/usbd.c),
[IDF 앱 이미지 digest API](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32s3/api-reference/storage/partition.html)다.
