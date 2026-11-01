# ChameleonUltra LF 125 kHz 카드 식별

`pweh-nfc`의 `nfc_cu_lf_identify`는 이미 연결한 CU Ultra reader로 125 kHz 카드의 계열을 닫힌 표로 분류한다.
[설계 §6.2](../design/game-console-flipper-rf.md#62-태그-계열-정책-서버-자신의-스캔-결과로만-판정)의 정책 칸도 함께 돌려준다.
고정 LF scan만 보내며 쓰기·인증·스니프는 하지 않는다. 원시 ID는 돌려주지 않는다.
연결·세션·정리는 [고정 CU 계약](cu-ntag-read-provider.md)의 `nfc_cu_connect` 세션 규칙을 그대로 따른다.
HF 식별·상태 조회는 [HF 식별·상태 계약](cu-hf-identify.md)에 있다.
구현 검증은 가짜 transport와 합성 응답으로만 했다. 실제 125 kHz 안테나·실물 카드에서의 동작은 아직 확인하지 않았다.

125 kHz 출입 카드(EM4100/EM-Marin, HID Prox, ioProx, Viking, PAC/Stanley, Jablotron, Pyramid)는
[설계 §1.3](../design/game-console-flipper-rf.md#13-범위-밖-항상-거부--코드-규칙으로-만든다)에 따라 출입 자격증명이므로 범위 밖이다.
교통·결제·출입·호텔·신분 자격증명은 policy와 관계없이 항상 범위 밖이다.
감지한 LF 계열은 모두 `refused`이고 원시 ID도, ID에서 만든 케이스 솔트 지문 같은 파생 값도 돌려주지 않는다(`identity_digest`는 항상 null이다. 이유는 [식별 결과](#식별-결과)에 있다). §6.2의 예외("ID마다 장난감·동물·시험용 태그" 사람 증명)는 이 증분에 구현하지 않았다.
그래서 감지 결과를 보고하고 멈춘다. 식별은 "무슨 계열인가"만 알려 주며 그 카드를 더 다뤄도 된다는 허가가 아니다.

## 공개 흐름

| 도구 | 입력 | 동작 |
|---|---|---|
| `nfc_cu_lf_identify` | `case_id, session_id, approval_id=None` | 같은 ready 세션에서 MODIFY 게이트(규칙 `cu.lf-identify`) 뒤 mode1002와 고정 LF scan을 첫 감지까지 보내 계열과 정책을 분류 |

순서는 `nfc_cu_connect` → (선택) `nfc_cu_status` → `nfc_cu_lf_identify` → `nfc_cu_disconnect`다.
같은 세션에서 HF 식별(`nfc_cu_identify`)과 섞어 호출할 수 있다.
도구는 scan 사실·inventory·artifact를 만들지 않는다. 결과는 Skill이 `case_record_step`으로 기록한다.

## 식별 프로필과 승인 지문

LF 식별 프로필은 reader 프로필 두 행(`cu_protocol.KNOWN`)과 HF 식별 프로필 밖의 별도 행이다.

| profile (`profile_sha256` 앞 8자리) | 공식 소스 | 내용 |
|---|---|---|
| `cu-lf125-identify-v2.3.0-v1` (`fefb6e77`) | tag `v2.3.0` = `4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1` | 명령 1002와 아래 scan 일곱 개의 순서·payload·성공 길이, EM410x tag_type 표, §6.2 정책 표, ID 파생 출력 없음(`id_derived_outputs="none"`, 지문 domain 없음) |

recipe는 canonical JSON literal이고 import 때 기록된 hash와 대조한다. 분류 코드는 이 recipe에서 표를 만들므로 표와 hash가 따로 바뀔 수 없다.
hash를 함께 고쳐도 `id_derived_outputs`가 `"none"`이 아니거나 `digest_domain`을 되살린 recipe는 분류표 검사에서 import가 실패한다.
기존 v2.2.0·v2.3.0 reader 프로필과 HF 식별 프로필의 recipe·hash는 바꾸지 않았다.
승인 지문에는 다음 값이 들어간다.

- 연결 action: 포트, live reader profile/hash, DTR
- `operation=lf_identify`와 정확 `session_id`
- LF 식별 profile과 hash
- `lf_scan_commands=[3000,3002,3010,3004,3014,3019,3021]`, `stop_at_first_found=true`
- `authentication=false`, `tag_writes=0`

그래서 `nfc_cu_identify`나 `nfc_cu_scan`의 승인으로 LF 식별을 실행할 수 없고, 반대도 같다.

## 확인한 firmware 사실

모든 줄 번호는 tag `v2.3.0` 커밋 `4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1`의 파일이다.
파일은 raw.githubusercontent.com에서 받아 git blob SHA-1을 그 커밋의 tree와 대조했다.
아래 `N/`은 `https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/`의 줄임이다.

공통 사실은 다음과 같다.

- 일곱 scan은 모두 명령 표에서 `before_reader_run`만 쓰고 after hook이 없다([N/app_cmd.c L3293-L3306](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L3293-L3306)).
  `before_reader_run`은 reader mode가 아니면 `0x66` DEVICE_MODE_ERROR 빈 frame을 낸다([L2076-L2082](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L2076-L2082)).
  before hook이 frame을 내면 processor는 실행되지 않는다([dispatcher L3434-L3471](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L3434-L3471)).
  그래서 mode 오류에서는 125 kHz radio를 켜지 않는다. HF field hook도 없다.
- 상태 코드는 `0x40` LF_TAG_OK, `0x41` LF_TAG_NO_FOUND, `0x42` LF_TAG_LOGIN_REQUIRED, `0x66` DEVICE_MODE_ERROR다([app_status.h L20-L28](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_status.h#L20-L28)).
- 각 `scan_*`은 read 함수가 성공하면 `0x40`, 아니면 `0x41`을 낸다. 탐색 시간은 `g_timeout_readem_ms = 500`ms다
  ([lf_reader_main.c L26-L126](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/lf/lf_reader_main.c#L26-L126)).
  이 값을 바꾸는 `set_scan_tag_timeout`([L257](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/lf/lf_reader_main.c#L257))은 app_cmd.c·app_main.c 어디에서도 부르지 않는다.
- processor는 실패하면 status만 담은 빈 payload를 낸다. 성공하면 아래 표의 고정 크기 버퍼를 `0x40`으로 낸다.
- payload가 0B인 요청은 processor에 `data=NULL`로 전달된다([utils/dataframe.c L149](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/utils/dataframe.c#L149)).
- 명령 ID는 공식 host enum이 아니라 firmware `data_cmd.h`를 기준으로 한다([data_cmd.h L103-L123](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/data_cmd.h#L103-L123)).

### scan 표

송신 순서는 표의 위에서 아래이며 숫자 순서가 아니다. 앞 scan이 `0x41`이면 다음 scan으로 넘어가고, 첫 `0x40`에서 멈춘다.

| 순서 | 명령 | 요청 payload | `0x40` 길이 | processor | read 함수와 radio 정지 | family |
|---|---|---|---|---|---|---|
| 1 | 3000 EM410X_SCAN ([data_cmd.h L103](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/data_cmd.h#L103), 표 [L3293](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L3293)) | 0B | 7 또는 15(아래 EM410x 표) | [app_cmd.c L832-L843](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L832-L843): tag_type u16 BE + ID. data를 읽지 않는다 | [lf_em410x_data.c L44-L84](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/lf/lf_em410x_data.c#L44-L84): L53 radio 켬, L75 끔 | `em410x` |
| 2 | 3002 HIDPROX_SCAN ([L106](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/data_cmd.h#L106), 표 [L3296](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L3296)) | 1B `00`(아래 참고) | 16 | [L896-L903](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L896-L903): 길이 검사 없이 `data[0]`을 format hint로 읽는다. `card_data[16]` | [lf_hidprox_data.c L42-L70](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/lf/lf_hidprox_data.c#L42-L70): L48 켬, L64 끔 | `hidprox` |
| 3 | 3010 IOPROX_SCAN ([L115](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/data_cmd.h#L115), 표 [L3300](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L3300)) | 1B `00`(아래 참고) | 16 | [L905-L914](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L905-L914): `data != NULL`이면 `data[0]`을 hint로 읽고 아니면0. `card_data[16]` | [lf_ioprox_data.c L82-L111](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/lf/lf_ioprox_data.c#L82-L111): 시작 때 L47 끔·50ms·L61 켬·10ms([L42-L66](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/lf/lf_ioprox_data.c#L42-L66)), 끝 L75 끔 | `ioprox` |
| 4 | 3004 VIKING_SCAN ([L110](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/data_cmd.h#L110), 표 [L3298](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L3298)) | 0B | 4 | [L986-L993](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L986-L993): `card_buffer[4]` | [lf_viking_data.c L44-L72](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/lf/lf_viking_data.c#L44-L72): L50 켬, L66 끔 | `viking` |
| 5 | 3014 PAC_SCAN ([L108](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/data_cmd.h#L108), 표 [L3302](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L3302)) | 0B | 8 | [L995-L1002](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L995-L1002): `card_id[8]` | [lf_pac_data.c L42-L75](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/lf/lf_pac_data.c#L42-L75): L49 켬·10ms, L69 끔 | `pac` |
| 6 | 3019 JABLOTRON_SCAN ([L121](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/data_cmd.h#L121), 표 [L3304](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L3304)) | 0B | 5 | [L1034-L1041](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L1034-L1041): `card_buffer[5]` | [lf_jablotron_data.c L43-L71](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/lf/lf_jablotron_data.c#L43-L71): L49 켬, L65 끔 | `jablotron` |
| 7 | 3021 PYRAMID_SCAN ([L123](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/data_cmd.h#L123), 표 [L3306](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L3306)) | 0B | 16 | [L1043-L1050](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L1043-L1050): 원시 128bit frame `card_data[16]` | [lf_pyramid_data.c L82-L111](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/lf/lf_pyramid_data.c#L82-L111): 시작 때 L47 끔·50ms·L61 켬·10ms([L42-L66](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/lf/lf_pyramid_data.c#L42-L66)), 끝 L75 끔 | `pyramid` |

모든 read 함수는 감지 여부와 관계없이 끝에서 `stop_lf_125khz_radio`를 부른다. 그래서 결과의 `lf_field_off_by_firmware`는 true다.
이것은 firmware 처리 경로를 읽은 사실이며 물리 측정이 아니다. 한 scan의 firmware 시간은 약 0.5–0.56초다.
ioProx·Pyramid는 50+10ms를 더 쓰고 PAC는 10ms를 더 쓴다. 일곱 scan이 모두 미감지면 125 kHz field를 켜는 시간은 합해서 약 3.6초다.
각 frame은 명령 2초 예산 안에 끝난다. 도구 전체 예산은 20초다.

### 요청 payload

- **3002 HID Prox**: processor가 길이를 검사하지 않고 `data[0]`을 읽는다([L898](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L896-L903)).
  0B 요청은 `data=NULL`이 되므로([dataframe.c L149](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/utils/dataframe.c#L149)) 항상 1B를 보낸다.
  `0x00`은 "모든 형식"이다. `unpack`은 hint가0이면 형식을 거르지 않는다([wiegand.c L870-L889](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/nfctag/lf/protocols/wiegand.c#L870-L889)).
- **3010 ioProx**: processor는 payload가 있으면 `data[0]`을 hint로 읽는다([L907](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L905-L914)).
  그래서 1B `0x00`을 보낸다. 0B 요청도 `data=NULL`이라 hint0이 되고 decoder는 hint를 쓰지 않는다([ioprox.c L304-L305](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/nfctag/lf/protocols/ioprox.c#L304-L305)).
  공식 host는 payload 없이 보낸다([chameleon_cmd.py L692-L699](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/software/script/chameleon_cmd.py#L692-L699)). 1B와 0B는 firmware에서 같은 동작이다.
  PWEH는 processor가 읽는 바이트를 직접 보낸 값으로 고정하려고 1B를 쓴다.
- 나머지 다섯 scan의 processor는 `data`를 읽지 않으므로 0B다.

### EM410x tag_type 표

EM410x decoder는 Electra, /64, /32, /16 순서로 시도한다([em410x.c L59-L64](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/nfctag/lf/protocols/em410x.c#L59-L64)).
성공한 protocol의 tag_type(u16 BE)과 ID를 버퍼에 넣는다([lf_em410x_data.c L65-L67](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/lf/lf_em410x_data.c#L65-L67)).
ID 크기는 Electra만 13B이고 나머지는 5B다([lf_tag_em.h L8-L9](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/nfctag/lf/lf_tag_em.h#L8-L9), [em410x.c L18-L20](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/nfctag/lf/protocols/em410x.c#L18-L20)).

| tag_type ([tag_base_type.h L37-L41](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/nfctag/tag_base_type.h#L37-L41)) | `variant` | `0x40` 길이 |
|---|---|---|
| 101 TAG_TYPE_EM410X_16 | `em410x_16` | 7 (2 + 5) |
| 102 TAG_TYPE_EM410X_32 | `em410x_32` | 7 |
| 103 TAG_TYPE_EM410X_64 | `em410x_64` | 7 |
| 104 TAG_TYPE_EM410X_ELECTRA | `em410x_electra` | 15 (2 + 13) |

tag_type 100(TAG_TYPE_EM410X)은 어떤 decoder protocol의 tag_type도 아니라서([em410x.c L352-L410](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/nfctag/lf/protocols/em410x.c#L352-L410)) scan 응답에 나오지 않는다.
그래서 100과 105 이상은 `nfc_scan_invalid`다. 104에 7B나 101–103에 15B가 오는 길이 불일치도 같다.

## 응답 분류

scan 응답 하나를 다음 순서로 판정한다.

| 응답 | 판정 | 세션 |
|---|---|---|
| `0x41`, 빈 payload | 미감지. 다음 scan으로 계속(일곱 개 모두면 family `none`) | ready |
| `0x40`, 위 표의 정확 길이 | 감지. 그 scan의 family로 끝내고 뒤 scan은 보내지 않는다 | ready |
| `0x66`, 빈 payload | reader mode 아님 `cu_reader_required` | terminal |
| 그 밖의 status(`0x42`·`0x60`·`0x67`·`0x68` 등), payload 있는 `0x41`·`0x66`, 길이가 틀린 `0x40`, EM410x tag_type 100·105 이상, Electra 길이 불일치 | `nfc_scan_invalid` | terminal |

mode1002가 reader(1)가 아니면 scan을 보내지 않고 `cu_reader_required` terminal이다([1002](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L91-L94)).
frame마다 2초 안에 응답이 없으면 `time_limit`, 취소는 `cancelled`, route·scope·역할·허가·lease 재검증 실패는 고정 오류이며 모두 terminal이다.
terminal 뒤에는 명령을 보내지 않는다. `nfc_cu_disconnect`로 정리하고 새로 연결한다.

## 보내지 않는 명령

다음 명령은 encoder 허용 목록 밖이라 만들 수 없다. 합성 시험의 가짜 CU는 이 명령이 나오면 실패한다.

| 명령 | 이유 |
|---|---|
| 3001/3003/3005/3006/3011/3015/3018/3020 `*_WRITE_TO_T55XX`, 3016 LF_T55XX_WRITE | T55xx 태그 쓰기·비밀번호 변경([표 L3294-L3308](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L3294-L3308)) |
| 3030 EM4X05_SCAN | RL bit가 서면 비밀번호0으로 LOGIN(인증)을 시도한다([lf_em4x05_data.c L304-L311](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/lf/lf_em4x05_data.c#L304-L311), [L342-L343](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/lf/lf_em4x05_data.c#L342-L343)) |
| 3031 LF_SNIFF, 3009 ADC_GENERIC_READ, 3007/3008/3032 | 원시 신호 수집. 스니프는 기본2000ms·최대10000ms라 명령 예산도 넘는다([L2213-L2229](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L2213-L2229)). 3007/3008/3032는 정의만 있고 표에 없다 |
| 3012/3013 ioProx 변환 | ID를 입력으로 받는 host 보조 명령([표 L3317-L3318](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L3317-L3318)) |
| 5000–5013 `*_SET_EMU_ID`/`*_GET_EMU_ID` | slot emulator ID 설정·조회([표 L3369-L3382](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L3369-L3382)) |
| 1001 모드 변경, slot·setter 명령 | 장치 상태를 바꾼다 |

IDTECK·Indala·AWID·FDX-B·Paradox·Keri·Gallagher·Nexwatch용 scan 명령은 v2.3.0 firmware에 없다. 그래서 이 계열은 감지하지 못하고 `none`에 섞인다.

## 식별 결과

`{ok, case_id, session_id, profile, family, variant, policy, scans_sent, id_returned=false, identity_digest,
physical_same_tag_verified=false, lf_field_off_by_firmware=true, authentication_attempted=false}`다.

- `family`: `em410x`, `hidprox`, `ioprox`, `viking`, `pac`, `jablotron`, `pyramid`, `none` 중 하나다.
- `variant`: family가 `em410x`일 때만 위 표의 값이고 그 밖에는 null이다.
- `policy`: 감지한 일곱 계열은 모두 `refused`이고 `none`은 `not_applicable`이다.
- `scans_sent`: 실제로 보낸 scan 이름 목록이다(`em410x_scan`, `hidprox_scan`, `ioprox_scan`, `viking_scan`, `pac_scan`, `jablotron_scan`, `pyramid_scan` 순서의 앞부분).
- `identity_digest`: 모든 계열(감지 일곱 계열과 `none`)에서 항상 null이다. 결과 모양을 HF 식별과 맞추려고 키만 둔다.
  LF 식별은 원시 ID에서 나온 값을 지문을 포함해 하나도 만들지 않는다. 이유는 다음과 같다.
  - 125 kHz 출입 ID는 24–40비트 자격증명이다. Viking(4B=32비트)·PAC(8자 ID, 16진 문자면 32비트)·HID 26비트(H10301은 FC 8비트+CN 16비트=24비트)는
    물론 EM410x·Jablotron(5B=40비트)도 전용 계산이면 전수 대입 범위 안이다.
  - 케이스 솔트 지문(SHA256(salt || value) 앞16 hex)은 솔트를 읽을 수 있는 같은 OS 계정([안전 §3.5 비밀값](../safety.md#35-사람-증명attestation과-출처-원장provenance-sd-카드-보관-기록-보호-상태))이
    작은 ID 공간을 전수 대입해 원시 ID로 되돌릴 수 있다. 그러면 지문은 설계 §6.2의 "거부(ID 마스킹)"가 요구하는 마스킹이 아니다.
  - 감지 계열은 모두 `refused`라 scan 사실·inventory를 만들지 않는다. 같은 카드를 다시 찾아 결속할 일이 없으므로 지문이 쓰일 곳도 없다.
  계열·EM410x 변형마다 고정인 응답 길이만 분류에 쓰며, 그 길이도 따로 돌려주지 않는다(family·variant에서 정해지는 값이다).
- `none`은 일곱 scan이 각각 500ms 안에 해독하지 못했다는 뜻이다. 카드가 없다는 증명이 아니다(위의 scan 없는 계열·배치·결합 거리).

원시 ID·EM410x ID·HID FC/CN·issue level·OEM·ioProx version/FC/CN·PAC 문자열·Pyramid frame과 원시 frame, 그리고 이 값들의 지문·조각은
결과·로그·예외·승인 action·감사 기록에 넣지 않는다. 원시 ID 바이트는 응답 길이 검사 동안에만 메모리에 있고 공개 투영이 버린다.
HID format 바이트(`data[0]`, [hidprox.c L89-L99](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/nfctag/lf/protocols/hidprox.c#L89-L99))도 일부러 돌려주지 않는다.
값은 `card_format_t` enum([wiegand.h L33-L76](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/nfctag/lf/protocols/wiegand.h#L33-L76))의 위치 번호인데,
명시 숫자가 첫 항목에만 있어 고정 label 표를 위치를 세서 만들어야 한다. 그래서 recipe에 넣지 않았다(`hid_format_returned=false`).

## 한계

- 125 kHz 출입 카드는 대부분 인증 없이 같은 ID를 반복 송신하므로 ID 자체가 자격증명이다. 그래서 원시 ID도 지문도 남기지 않는다(위 `identity_digest` 항목).
  그 대가로 LF 식별 결과끼리 같은 카드인지 비교할 수 없다. 두 결과의 family·variant가 같아도 같은 카드라는 뜻이 아니다.
- 다른 ChameleonUltra·T55xx 복제 카드·에뮬레이터는 어떤 계열의 신호도 낼 수 있다. 분류는 신호 형식의 표시이지 진품이나 같은 실물의 증명이 아니다.
- 순서가 앞인 decoder가 먼저 성공하면 그 계열로 끝난다. 두 계열 신호를 함께 내는 카드나 여러 장의 카드는 첫 감지 계열만 보고한다.
- radio 정지는 firmware 처리 경로를 읽은 사실이다. 실제 안테나 출력은 측정하지 않았다.
- NFC·125 kHz 리더 field도 자계유도식 무선 방사다([설계 §6.1](../design/game-console-flipper-rf.md#61-rf-수신-pwehsafetyrf)). 짧게·가까이 쓰며, 실행마다 MODIFY 게이트를 거친다.

## 기록

LF 식별 결과는 `nfc-analysis` 요약의 mode `cu-lf-identify`로 `case_record_step(skill="nfc-behavior-analysis", step="summary", ...)`에 기록한다.
`lf_identifications`(최소 1개)에 반환값의 `profile`·`family`·`variant`·`policy`·`scans_sent`·`identity_digest`·`id_returned`를 그대로 옮기고 `operation`은 "cu-lf-identify"다. tags·results는 빈 배열이다.
스키마는 `identity_digest`를 모든 계열에서 null만 받고(지문 문자열은 거부), 항목마다 family에 맞춰 `policy`(감지 `refused`·`none` `not_applicable`),
`scans_sent`(고정 순서의 앞부분이고 마지막이 그 계열 scan, `none`은 일곱 개 전부)를 강제한다.
같은 실행에서 HF 식별도 했다면 mode는 `cu-hf-identify`나 `cu-lf-identify` 중 하나로 두고 `identifications`와 `lf_identifications`를 함께 넣는다.
mode `scan-bound-offline` 요약은 기존대로이며 `identifications`·`lf_identifications`를 받지 않는다. 기록 방법은 [Skill](../../skills/nfc-behavior-analysis/SKILL.md)을 따른다.
