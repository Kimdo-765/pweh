# ChameleonUltra HF 카드 식별·장치 상태 조회

`pweh-nfc`의 `nfc_cu_identify`는 이미 연결한 CU Ultra reader로 HF 카드의 계열을 닫힌 표로 분류하고
[설계 §6.2](../design/game-console-flipper-rf.md#62-태그-계열-정책-서버-자신의-스캔-결과로만-판정)의 정책 칸을 함께 돌려준다.
페이지 READ·인증·쓰기는 하지 않는다. `nfc_cu_status`는 RF 없이 배터리·활성 slot·HF14A 설정 같은 장치 상태만 읽는다.
두 도구 모두 [고정 CU 계약](cu-ntag-read-provider.md)의 `nfc_cu_connect` 세션을 그대로 쓰며 연결·정리 규칙은 그 문서를 따른다.
구현 검증은 가짜 transport·합성 응답으로 했다. 실제 RC522·실물 카드에서의 동작은 아직 확인하지 않았다.

교통·결제·출입·호텔·신분 자격증명은 [설계 §1.3](../design/game-console-flipper-rf.md#13-범위-밖-항상-거부--코드-규칙으로-만든다)에 따라
항상 범위 밖이다. `policy`가 `attestation_required`여도 그런 카드에는 사람 증명으로 범위를 넓히지 않는다.
식별은 "무슨 계열인가"만 알려 주며, 그 카드를 더 다뤄도 된다는 허가가 아니다.

## 공개 흐름

| 도구 | 입력 | 동작 |
|---|---|---|
| `nfc_cu_identify` | `case_id, session_id, approval_id=None` | 같은 ready 세션에서 MODIFY 게이트 뒤 mode·scan2000·(Type 2 후보만) GET_VERSION 한 번으로 계열과 정책을 분류 |
| `nfc_cu_status` | `case_id, session_id` | 같은 ready 세션에서 INTERACT 게이트(항상 허용·감사 기록) 뒤 mode·배터리·활성 slot·HF14A 설정 getter만 조회 |

순서는 `nfc_cu_connect` → `nfc_cu_status`(선택) → `nfc_cu_identify` → (NTAG213/215/216이면 기존 `nfc_cu_scan`) → `nfc_cu_disconnect`다.
두 도구는 scan 사실·inventory·artifact를 만들지 않는다. 결과는 Skill이 `case_record_step`으로 기록한다.

## 식별 프로필과 승인 지문

식별 프로필은 reader 프로필 두 행(`cu_protocol.KNOWN`) 밖의 별도 행이다.

| profile (`profile_sha256` 앞 8자리) | 공식 소스 | 내용 |
|---|---|---|
| `cu-hf14a-identify-v2.3.0-v1` (`d420c720`) | tag `v2.3.0` = `4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1` | 명령 1002/2000/2010, RAW option `f4`, 아래 두 분류표, §6.2 정책 표, 지문 domain |

recipe는 canonical JSON literal이고 import 때 기록된 hash와 대조한다. 분류 코드는 이 recipe를 읽어 표를 만들므로
표와 hash가 따로 바뀔 수 없다. 원장·snapshot 검증기(`known_reader_profile`)는 이 이름을 찾지 못한다.
승인 지문에는 연결 action(포트·live reader profile/hash·DTR)과 `operation=hf_identify`, 정확 `session_id`,
식별 profile/hash, `version_requests_max=1`, `page_reads=0`, `authentication=false`가 들어간다.
그래서 `nfc_cu_scan`의 승인으로 식별을 실행할 수 없고, 반대도 같다.

## wire 순서와 HF field

식별은 mode1002 → scan2000 → (Type 2 후보만) GET_VERSION 순서이며 그 밖의 명령은 없다.

- mode1002가 reader(1)가 아니면 `cu_reader_required`로 끝난다([1002](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L91-L94)).
- scan2000은 HF hook이 field를 켜고 after hook이 성공·실패 모두 field를 끈다([processor](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L280-L300), [hook](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L2076-L2105)).
- GET_VERSION은 `f4`(auto-select, keep=0)·100ms·CRC append/check의 고정 frame이다. 기존 `nfc_cu_scan`과 같은 builder다.
  firmware는 keep=0 RAW의 끝에서 성공·timeout·CRC 오류·4bit NAK와 관계없이 field를 끈다([L1670-L1672](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/hf/rc522.c#L1670-L1672)).
  auto-select가 실패해도 field를 끈다([L1592-L1599](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/hf/rc522.c#L1592-L1599)).
- 0x30 READ, 0x1A/0x1B 인증, RATS 직접 송신, 2016·2018–2022·2100·2101·1001은 보내지 않는다.

이 field 해제는 firmware 처리 경로의 관찰이며 물리 측정이 아니다. 결과의 `rf_off_verified`는 항상 false다.
scan firmware는 SAK bit0x20이면 호스트 분류 전에 RATS(`E0 40`)를 보낸다([L797-L885](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/hf/rc522.c#L797-L885)).
그래서 거부 계열 카드에도 SELECT 외의 RF가 있었을 수 있다.

## scan 기록 분류표

2000 응답 하나를 위에서부터 차례로 판정한다. ATQA는 MSB 순서로 바꾼 값이다(wire는 LSB 먼저).
NXP는 ATQA로 칩을 식별하지 말라고 한다(AN10833 Rev 3.9 §2.3 "Never use ATQA to identify a chip").
그래서 ATQA는 기존 Type 2 문의 조건으로만 쓰고 Classic 판정에는 쓰지 않는다. SAK는 마지막 cascade의 값이다.

| 조건 | 분류 | 근거 |
|---|---|---|
| status `0x01`, 빈 payload | `none` | firmware 상태 코드 `0x01` TAG_NO([app_status.h](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_status.h#L7-L37)), scan 실패 시 빈 payload([processor](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L280-L300)). 깨끗한 2B ATQA를 받지 못했다는 뜻이며 카드가 없다는 증명이 아니다(아래 참고) |
| status `0x04`, 빈 payload | `multiple` | 상태 코드 `0x04` COLLISION(같은 파일). anticollision 응답의 RC522 오류가 CollErr일 때 충돌을 풀지 않고 이 상태를 낸다([scan_once](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/hf/rc522.c#L682-L916), [bytes_transfer](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/hf/rc522.c#L271-L404)) |
| status `0x00`, 레코드 정확 하나, SAK bit `0x20` | `iso14443_4` | AN10833 Rev 3.9 §2.4 Table 4(SAK coding: bit 6 = ISO/IEC 14443-4), Fig. 1(0x20·SmartMX 0x28/0x38 → RATS) |
| SAK `0x09` | `mifare_classic_mini` | AN10833 Rev 3.9 Fig. 1(인쇄 값 0x09, bit 4=1·bit 5=0·bit 1=1) |
| SAK `0x08` | `mifare_classic_1k` | AN10833 Rev 3.9 §2.4 Table 4(Classic 1K 08h), Fig. 1(0x08) |
| SAK `0x18` | `mifare_classic_4k` | AN10833 Rev 3.9 §2.4 Table 4(Classic 4K 18h), Fig. 1(0x18) |
| SAK `0x19` | `mifare_classic_2k` | AN10833 Rev 3.9 Fig. 1(인쇄 값 0x19, bit 4=1·bit 5=1·bit 1=1) |
| SAK `0x01` | `mifare_classic_tnp3xxx` | AN10833 Rev 3.9 Fig. 1의 TagNPlay 잎. 값이 인쇄되어 있지 않아 경로(bit 2=0 → bit 4=0 → bit 5=0 → bit 1=1)에서 정확 `0x01`로 도출했다 |
| SAK `0x10`, `0x11` | `mifare_plus_sl2` | AN10833 Rev 3.9 §2.4 Table 4(MIFARE Plus SL2: 2K 10h, 4K 11h). 설계 §6.2의 Plus 거부 행이다 |
| UID7·ATQA `0044`·SAK `00`·ATS 길이0 | `type2` → GET_VERSION | MF0ICU1 Rev 3.9 §7.6, MF0ULX1 Rev 3.3 §9.4, MF0ICU2 Rev 3.5 §8.4·§9.1, NTAG213_215_216 Rev 3.2 §9.4(모두 ATQA 0044h·SAK 00h), AN10833 Rev 3.9 §2.1 note(p.5) "The whole MIFARE Ultralight family uses the same ATQA and SAK" |
| 그 밖의 잘 형성된 레코드 | `other` | 위 표에 근거가 없는 값은 추측하지 않는다 |
| 그 밖의 status·길이·레코드 둘 이상 이어 붙임 | `nfc_scan_invalid`(terminal) | v2.3.0 2000은 레코드 정확 하나 또는 빈 payload의 실패 상태만 낸다([processor](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L280-L300)) |

TagNPlay 경로는 Fig. 1의 그림 요소 위치와 연결선으로 확인했다. 오른쪽 열 표시(Bit 2, Bit 4, Bit 5, Bit 1, Bit 6)가 판정 순서다.
Fig. 1은 TagNPlay 갈래에서 bit 6을 보지 않는다. PWEH는 bit `0x20`을 먼저 보므로 `0x21`은 `iso14443_4`(거부)가 된다.
SAK `0x02`(RFU, Fig. 1 "SAK bit 2 is reserved"), `0x12`처럼 Plus SL2 값에 다른 bit가 섞인 값, `0x40`·`0x80`이 섞인 값 등은 정확 표에 없으므로 `other`다.
MIFARE Plus SL3(`0x20`)는 bit `0x20` 행에서 `iso14443_4`(거부)가 된다.
status `0x02`(SAK 없음)·`0x05`(BCC 오류)·`0x08`(ATS 254B 초과)는 카드 일부가 응답한 RF·anticollision 오류다.
이 경우도 분류로 추측하지 않고 기존 규칙대로 `nfc_scan_invalid` terminal로 끝낸다.

카드가 여러 장이면 `multiple`만 나오는 것이 아니다. 소스에서 확인한 경로와 확인하지 못한 경로는 다음과 같다.

- 소스에서 확인함: WUPA 응답에 RC522 오류가 나면 bytes_transfer가 길이를 0으로 둔다. [atqa_request](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/hf/rc522.c#L892-L916)는 10번 재시도한 뒤 `0x01`을 낸다.
  ATQA가 서로 다른 두 장(예: NTAG `0044`와 Classic `0004`)은 ATQA bit가 충돌하므로, RC522가 이를 오류로 알리면 이 경로를 타고 `none`으로 보인다.
- 확인하지 못함(RC522 실물 미확인): ATQA가 같은 두 장은 anticollision에서 갈린다.
  bytes_transfer는 ErrorReg를 ProtocolErr(`0x02`)·ParityErr(`0x07`)·CRCErr(`0x03`)·CollErr(`0x04`) 순서로 읽는다.
  충돌 때 ParityErr가 함께 서면 `0x07`이 되어 `multiple`이 아니라 `nfc_scan_invalid` terminal이 될 수 있다.

그래서 `none`을 "카드 없음"으로, terminal 오류를 "카드 고장"으로 단정하지 않는다. 카드가 정확히 한 장인지 사람에게 확인받는다.

## GET_VERSION 분류표

`type2` 후보에만 GET_VERSION 한 번을 보낸다. check CRC 아래 응답은 CRC를 뺀 payload다
([raw_cmd](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/hf/rc522.c#L1554-L1675)).

| 응답 | 분류 | 근거 |
|---|---|---|
| status0x00, `0004040201000F03` | `ntag213` | NTAG213_215_216 Rev 3.2 §10.1 Table 28 |
| status0x00, `0004040201001103` | `ntag215` | 같은 표 |
| status0x00, `0004040201001303` | `ntag216` | 같은 표 |
| status0x00, `0004030101000B03` | `ultralight_ev1_mf0ul11` | MF0ULX1 Rev 3.3 §10.1 Table 15(subtype 01h = 17 pF MF0ULx1, storage 0Bh) |
| status0x00, `0004030201000B03` | `ultralight_ev1_mf0ulh11` | 같은 표(subtype 02h = 50 pF). 17 pF는 MF0ULx1, 50 pF는 MF0ULHx1이다(§4 Table 2) |
| status0x00, `0004030101000E03` | `ultralight_ev1_mf0ul21` | 같은 표(storage 0Eh) |
| status0x00, `0004030201000E03` | `ultralight_ev1_mf0ulh21` | 같은 표 |
| status0x00, 그 밖의 정확8B | `type2_other_version` | 표에 근거가 없는 값(NTAG210/212·Ultralight AES·Nano 등)은 계열을 추측하지 않는다 |
| status0x00, 빈 payload(4bit NAK) | `ultralight_or_ultralight_c` | check CRC 아래 3B 미만 응답은 status0x00·빈 payload([L1639-L1658](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/hf/rc522.c#L1639-L1658)). MF0ICU1 Rev 3.9 §7.6·MF0ICU2 Rev 3.5 §8.1 Table 14의 명령표에는 GET_VERSION이 없다 |
| status0x01(timeout), 빈 payload | `ultralight_or_ultralight_c` | 같은 raw_cmd 경로. 100ms 안에 응답이 없었거나 auto-select가 카드를 찾지 못했다(아래 한계). 위 두 datasheet 명령표에는 GET_VERSION이 없다 |
| status0x03(CRC 오류), 빈 payload | `type2_version_unreadable` | check CRC 아래 `0x03`은 3B 이상을 받았고 CRC가 틀렸을 때만 나온다([L1639-L1658](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/hf/rc522.c#L1639-L1658), RC522 하드웨어 CRC는 켜지 않는다). 원조 UL·UL C는 GET_VERSION에 3B 이상 답하지 않으므로 그 근거가 아니다. 응답한 태그(EV1·NTAG21x·호환 카드)의 손상 응답일 수 있어 계열을 정하지 않는다 |
| 그 밖의 명령·상태·길이 | `nfc_scan_invalid`(terminal) | 기존 `nfc_cu_scan`과 같은 규칙 |

원조 Ultralight(MF0ICU1)와 Ultralight C(MF0ICU2)를 READ로 나누지 않는다. NXP의 구분 방법은 AUTHENTICATE(AN10833 Fig. 1 "Auth")이고,
인증 없이 나누려면 교통 티켓의 내용 페이지를 READ해야 한다(§1.3·§6.2). 그래서 둘은 하나의 `ultralight_or_ultralight_c`로 둔다.
GET_VERSION에 응답하지 않은 원조 Ultralight·UL C는 IDLE/HALT로 돌아간다(MF0ICU1 §7.2, MF0ICU2 §7.2·§8.3). 식별은 그 뒤 명령을 보내지 않는다.

## §6.2 정책 칸

| family | `policy` |
|---|---|
| `ntag213`, `ntag215`, `ntag216` | `allowed` |
| `ultralight_ev1_mf0ul11`, `ultralight_ev1_mf0ulh11`, `ultralight_ev1_mf0ul21`, `ultralight_ev1_mf0ulh21`, `ultralight_or_ultralight_c`, `type2_other_version`, `type2_version_unreadable` | `attestation_required` |
| `mifare_classic_mini`, `mifare_classic_1k`, `mifare_classic_tnp3xxx` | `attestation_required` |
| `mifare_classic_2k`, `mifare_classic_4k`, `mifare_plus_sl2`, `iso14443_4` | `refused` |
| `none`, `multiple`, `other` | `not_applicable` |

`policy`는 정보다. 현재 PWEH는 NTAG213/215/216만 scan·inventory·읽기를 지원한다. `attestation_required` 계열을
다루는 도구나 사람 증명 종류는 아직 없으므로 그런 카드에서는 식별 결과를 보고하고 멈춘다.
`refused`는 더 조작하지 않는다. `allowed`도 기존 `nfc_cu_scan`의 별도 MODIFY 게이트를 다시 거친다.

## 식별 결과

`{ok, case_id, session_id, profile, family, policy, uid_length, ats_present, get_version_sent, page_reads_sent=false,
authentication_attempted=false, identity_digest, physical_same_tag_verified=false, rf_off_verified=false}`다.

- `uid_length`와 `ats_present`는 레코드가 있을 때만 값이 있고 `none`·`multiple`이면 null이다.
- `get_version_sent`는 `type2` 후보일 때만 true다.
- `identity_digest`는 케이스 솔트 지문이다. 입력은 domain `pweh.cu-hf-identify/v1`과 family를 먼저 넣고 UID 길이·UID·ATQA·SAK·version 길이·version을 이어 붙인 값이다.
  같은 카드의 inventory 지문과 다르고, 같은 UID라도 family가 다르면 다른 지문이다. 레코드가 없으면 null이다. 익명성 보장은 아니다.
- 원시 UID·ATQA·SAK·ATS·GET_VERSION 값은 결과·로그·승인 action에 넣지 않는다.

## 세션 상태

잘 형성된 분류(`none`·`multiple`·`other` 포함)는 세션을 `ready`로 두므로 카드를 바꿔 다시 식별할 수 있다.
다음 경우는 기존 규칙대로 terminal이며 그 뒤 명령을 보내지 않는다.

- 잘못된 frame·상태·길이, 2초 안에 frame이 없는 transport timeout(`time_limit`)
- 취소, 각 frame 직전 route·scope·역할·허가·lease 재검증 실패
- reader mode 변화(`cu_reader_required`)

firmware status `0x01`(RF timeout)은 transport timeout과 다르며 위 표의 분류 결과다.

## 한계

- AN10833 Rev 3.9 §2.2(IMPORTANT NOTE)는 ATQA·SAK로 칩을 식별하지 말라고 권한다. §2.1 note에 따르면 DESFire EV3·Plus EV2는 ATQA·SAK를 설정으로 바꿀 수 있다.
  매직 카드·에뮬레이터(다른 ChameleonUltra 포함)는 어떤 ATQA·SAK·UID·GET_VERSION도 보일 수 있다. 분류는 진품 NXP 동작을 가정한 표시다.
- SAK `0x08`은 Classic 1K 외에 MIFARE Plus SL1 2K/SE(1K)도, `0x18`은 Plus SL1 4K도 같은 값이다(Table 4).
  `0x18`은 어느 쪽이든 거부지만 `0x08`의 Plus SL1은 §6.2의 Plus 거부 행에 해당할 수 있다. `mifare_classic_1k`는 "Classic 1K 또는 Plus SL1"로 읽는다.
- GET_VERSION의 status `0x01`에는 scan과 auto-select 사이에 카드가 field를 벗어난 경우도 섞인다. 그 경우도 `ultralight_or_ultralight_c`로 보인다.
- `type2_version_unreadable`은 응답 손상이라 같은 카드로 다시 식별하면 다른 계열이 나올 수 있다. 첫 결과와 다시 식별한 결과를 모두 보고한다.
- scan과 GET_VERSION은 서로 다른 선택(WUPA)이다. version을 낸 카드가 scan의 카드와 같은 실물인지는 검증하지 않는다.
- 4bit NAK가 status0x00·빈 payload가 되는 경로는 소스에서 확인했지만 실제 RC522에서는 확인하지 않았다.
- HF14A 설정(2200)이 기본값이 아니면(forcebcc·forcecl2·forcecl3·forcerats) scan과 auto-select 동작이 달라진다.
  이 설정은 RAM에만 있고 재부팅하면 기본값으로 돌아간다. 식별 전에 `nfc_cu_status`의 `hf14a_config_default`를 확인한다.

## 장치 상태 조회

`nfc_cu_status`는 mode1002를 다시 확인한 뒤 세 getter를 보낸다. 모두 hook·mode 검사·RF가 없고 일반 성공 `0x68`이다
([명령 표의 hook 열](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L3224-L3401)).

| 명령 | 응답 | 결과 필드 | 근거 |
|---|---|---|---|
| 1002 GET_DEVICE_MODE | 1B, reader=1 | `mode="reader"`. reader가 아니면 `cu_reader_required` terminal | [app_cmd.c L91-L94](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L91-L94) |
| 1025 GET_BATTERY_INFO | 3B: mV u16 BE, percent u8(0..100) | `battery_mv`, `battery_percent`, `battery_percent_is_estimate=true` | [app_cmd.c L172-L180](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L172-L180), [ble_main.c L235-L300](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/ble_main.c#L235-L300) |
| 1018 GET_ACTIVE_SLOT | 1B, 0부터 센 slot 0..7 | `active_slot`(0부터, 공식 CLI는 +1로 표시) | [app_cmd.c L1220-L1223](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L1220-L1223) |
| 2200 HF14A_GET_CONFIG | 4B: forcebcc·forcecl2·forcecl3·forcerats, 각 0..2 | `hf14a_config_default`(네 값 모두0) | [app_cmd.c L765-L768](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L765-L768), [rc522.h L172-L177](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/hf/rc522.h#L172-L177), [rc522.c L52](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/hf/rc522.c#L52) |

결과는 `{ok, case_id, session_id, battery_mv, battery_percent, battery_percent_is_estimate=true, active_slot, mode="reader",
hf14a_config_default, app_version, git_version, model}`이고 앞의 세 값은 연결 때 확인한 고정 사실이다(자기 보고).
길이·범위·상태 코드가 다르면 `cu_protocol_invalid` terminal이다. 세 getter 응답을 모두 받은 뒤 한 번에 검사한다.
성공하면 세션은 ready로 남는다.

- 배터리 percent는 전압을 조각 선형 곡선으로 바꾼 추정이며 연료계가 아니다. v2.3.0은 4160 mV를 100%로 보정했다.
  값은 5초 timer로 갱신되며 부팅 직후 첫 측정 전에는 mV·percent 모두 0이다([ble_main.c L65·L81-L92](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/ble_main.c#L81-L92), [L737-L784](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/ble_main.c#L737-L784)).
- 2201(설정 변경)은 값0..2만 받으므로 2200 값도 0..2만 유효하다([rc522.c L1677-L1697](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/hf/rc522.c#L1677-L1697)).
- 보내지 않는 getter도 있다. 1031·1034는 BLE pairing PIN, 1011·1012는 고정 장치 식별자를 돌려준다.
  1008·1038은 사용자가 쓴 slot 별명이고 1019와 emulator getter는 slot 내용 정보다. 1041·1042·1043도 쓰지 않는다
  (공식 v2.3.0 host enum에서 1041이 겹친다). 1001과 모든 setter도 보내지 않는다.

상태 조회의 분류는 `Risk.INTERACT`(규칙 `cu.status`)다. `modify_policy`와 관계없이 허용되고 감사 기록에 남는다.
다른 CU 장치 도구는 MODIFY지만 상태 조회는 의도적으로 INTERACT로 두었다. MODIFY 대신 INTERACT를 고른 근거는 다음과 같다.

- `src/pweh/safety/risk.py`는 INTERACT를 "기기에 명령을 보내지만 상태를 바꾸지 않음"으로 정의한다.
  [설계 부록 A의 위험도](../design/game-console-flipper-rf.md#부록-a-도구-목록)도 `INTERACT(계측기 상태만)`이다. 네 getter는 hook·RF·setter가 없다.
- OBSERVE보다 한 단계 엄격하다. 명령을 보낸다는 사실을 숨기지 않고 매 호출을 감사 기록에 남긴다.
- MODIFY로 두면 `modify_policy=approve`에서 `approval_id` 인자가 필요하다. 공개 서명 `nfc_cu_status(case_id, session_id)`에는 그 인자가 없다.
- 포트 열기와 DTR 영향은 `nfc_cu_connect`의 MODIFY 게이트에서 이미 승인받았다. 세션은 그 뒤에만 생긴다.
  getter frame마다 식별과 같은 `_fresh`(케이스 허가·route·lease·역할) 재검증을 거친다.

사람이 MODIFY를 원하면 `approval_id` 인자를 더하고 tool-set·주석 시험을 함께 바꾸는 별도 변경으로 다룬다.

## 기록

식별·상태 결과는 `nfc-analysis` 요약의 mode `cu-hf-identify`로 `case_record_step(skill="nfc-behavior-analysis", step="summary", ...)`에 기록한다.
`identifications`(최소 1개)에 식별 반환값의 분류 필드를, 선택 `device_status`에 상태 반환값을 그대로 옮기고 tags·results는 빈 배열이다.
mode `scan-bound-offline` 요약은 기존대로 tags가 최소 1개이며 `identifications`를 받지 않는다. 기록 방법은 [Skill](../../skills/nfc-behavior-analysis/SKILL.md)을 따른다.
