# ChameleonUltra 고정 NTAG 읽기 경로

`pweh-nfc`는 ChameleonUltra의 고정 USB 프로토콜로 연결·NTAG213/215/216 스캔과
기존 inventory 연결·유한 페이지 스냅샷 읽기를 제공한다. 구현 검증은 가짜 transport·합성 태그로 수행한다.
실제 USB 채널·RF 동작·진품이나 물리적으로 같은 태그를 확인했다는 뜻은 아니다.

## 공개 흐름

| 도구 | 입력 | 동작 |
|---|---|---|
| `nfc_cu_connect` | `case_id, port, approval_id=None` | 허가·현재 포트 신원·전체 USB 잠금·MODIFY 게이트 뒤 고정 네 조회로 Ultra·정확 v2.3.0·reader 모드를 확인 |
| `nfc_cu_scan` | `case_id, session_id, approval_id=None` | 같은 세션의 MODIFY 게이트 뒤 새 scan·단독 GET_VERSION·새 선택 READ0/1과 식별값 일치를 확인하고 보호 scan 사실 기록 |
| `nfc_cu_read_start` | `case_id, session_id, tag_ref, approval_id=None` | 같은 inventory·세션·MODIFY 게이트 뒤 유한 페이지 snapshot job 시작 |
| `nfc_cu_disconnect` | `case_id, session_id` | 사용권 종료·물리 close·lease 해제를 확인. 허가 철회 뒤에도 같은 세션 정리 가능 |

같은 세션의 `nfc_cu_identify`(READ 없는 HF 계열 분류)와 `nfc_cu_status`(RF 없는 배터리·slot·설정 조회)는
[HF 식별·상태 계약](cu-hf-identify.md)을 따른다.

connect의 실제 `session_id`로 scan을 호출하고, 실제 `scan_ref`를
`nfc_tag_inventory_add`에 전달한다. 기존 `nfc_parse_file`/`nfc_diff_dumps`의 파일
출처 증명·같은 FD 검증은 [NFC 분석 계약](nfc-inventory-analysis.md)을 그대로 따른다.
CU scan을 사용해도 가져온 파일을 CU에서 읽었다고 기록하지 않는다.
read job의 조회·취소, snapshot의 전용 출처·등록과 분석은 [스냅샷 계약](cu-read-snapshot.md)을 따른다.

connect 성공의 `device`는 고정 모델·live 버전(APP2.3·GIT v2.3.0)·reader 모드만 표시한다.
`firmware_claim_verified=false`이며 버전 자기 보고는 펌웨어 서명 검증이 아니다.
원시 USB 신원·UID·페이지·임의 버전 응답을 공개 결과에 넣지 않는다.

## 포트와 수명

명시한 COM 또는 tty의 현재 신원이 확인되어야 한다. VID/PID `6868:8686`, 같은
USB 부모·CDC 선택 근거와 전체 sibling scope를 대조하며, VID/PID만으로 허용하지 않는다.
POSIX interface00 또는 Windows MI00 관찰을 사용한다. MI 없는 Windows 표현은
같은 직접 USB 부모와 유일한 COM의 완전한 결속 관찰이 있어야 하며 interface00으로
임의 보정하지 않는다. 관찰이 불완전하면 포트를 열기 전에 거부한다.

기존 역할 표지·instrument guard와 공통 lease를 사용한다. 설정은115200/8N1,
DTR=true/RTS=false이며 DTR 영향을 MODIFY 승인 지문에 포함한다. 새 연결 때마다
만드는 session token은 wire nonce가 아니며 connect 승인 지문에 넣지 않는다.
URL·BLE·자동 포트 선택·다른 backend로의 자동 전환은 제공하지 않는다.

한 케이스당 owner 하나, 전체16개이며 준비 중이거나 정리 미확인인 owner도 센다.
한 사용권이 요청 전체와 scan fact 기록까지 유지되고 각 frame 직전에 현재 route·scope·
역할·허가·lease를 다시 확인한다. claim한 worker만 transport를 사용한다.

시작은5초, probe와 내부 읽기는45초, frame마다 남은 전체 시간과2초 중 작은 예산을
사용한다. 취소·timeout·잘못된 응답은 terminal이며 새 명령·재선택·RF-off·재연결을
자동으로 보내지 않는다. close는 최대10초 동안 종료를 확인하고, 미확인 worker·
transport·lease를 보존한다. 늦은 open/write가 외부 deadline에 물리적으로 종료된다는
보장은 없다. 호스트 close와 장치 명령 종료·RF field off는 별도 사실이다.

## reader 프로필

reader 프로필은 닫힌 두 행이며 live 경로는 그중 하나만 사용한다.

| profile (`profile_sha256` 앞 8자리) | 공식 소스 | 연결 응답 | 용도 |
|---|---|---|---|
| `cu-ntag21x-v2.3.0-v1` (`95132f6c`) | tag `v2.3.0` = [`4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1`](https://github.com/RfidResearchGroup/ChameleonUltra/tree/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1) | APP `02 03`, GIT 정확 `v2.3.0` | live: 연결·scan·읽기 |
| `cu-ntag21x-v2.2.0-v1` (`d7e590dc`) | tag `v2.2.0` = [`f349dbeeaa315776b272ae8fb851cc4042d55f07`](https://github.com/RfidResearchGroup/ChameleonUltra/tree/f349dbeeaa315776b272ae8fb851cc4042d55f07) | APP `02 02`, GIT `v2.2.0` | 이전 기록의 검증 전용 |

`nfc_cu_connect`는 v2.3.0 행만 받는다. 1000 APP이 `02 03`이고 1017 GIT이 6B `v2.3.0`과
정확히 같아야 하며 Ultra·reader mode1이어야 한다. 공식 build는 APP을 마지막 tag에서, GIT을
`git describe`에서 만든다([Makefile.defs](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/Makefile.defs#L29-L32)). 그래서 tag 뒤
dev build(예: `v2.3.0-14-g4c5bc2c`)는 APP2.3과 명령표가 release와 같고 GIT 전체 문자열만 다르다.
v2.2.0·dev·`-dirty`·접미사·다른 버전은 RF 명령 전에 `cu_firmware_unsupported`다. 공개 결과는
관찰한 원래 버전 문자열을 돌려주지 않는다. 다른 버전·Lite·emulator 모드에서는 태그 명령을 보내지
않으며 모드·slot 변경 명령은 없다. 버전 응답은 자기 보고이며 서명 증명이 아니다.

v2.2.0 행은 이전에 기록한 scan 사실·snapshot·원장 extra를 계속 검증하기 위해서만 남긴다.
두 recipe는 canonical JSON literal로 고정하고 import 때 기록된 hash와 다시 대조한다. v2.2.0 recipe는
이전 증분과 byte 단위로 같다. 검증기는 profile 이름을 정확한 문자열 key로만 찾고, 찾은 행과
hash·commit(snapshot은 APP/GIT까지) 전체가 같을 때만 받는다. 접두사·정규식·버전·hash로 행을 추론하지
않으며 두 행의 값을 섞은 기록은 거부한다. 승인 지문은 live profile/hash를 담으므로 이전 CU 승인은 더 이상
맞지 않는다. 기존 승인·상태를 옮기지 않으며 사람이 새로 승인한다.

## 고정 프로토콜

frame은 SOF/LRC1/CMD/STATUS/LEN/LRC2/DATA/LRC3이고 다중 바이트 정수는 BE다
([netdata.h](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/utils/netdata.h#L8-L36),
[dataframe.c](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/utils/dataframe.c#L23-L80), 두 tag에서 같은 blob).
세 LRC를 각각 검증한다. PWEH의 DATA 상한은512B, frame522B, decoder 보유1044B다.
이512B를 공식 host 전체의 최대치라고 해석하지 않는다. 한 요청에는 응답 정확 하나와
미소비 바이트0을 요구한다. 잡음 제거·재동기화·자동 재전송은 없다.

연결 조회는1000/1017/1033/1002 순서이며 일반 성공은0x0068이다
([1000](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L49-L57), [1017](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L60-L62), [1033](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L65-L68),
[1002](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L91-L94)). probe/read 시작에도 mode1002를 다시 확인한다. 태그 scan2000과 고정
RAW2010의 성공0x0000 및 payload 길이를 별도로 검사한다. 같은2010의 지연 중복에는 wire seq/page
echo가 없어 완전한 구별이 불가능하며, idle 잔여 검사를 원자적 동기화로 표시하지 않는다.

### 명령 허용 목록

PWEH가 만드는 명령은1000/1017/1033/1002/2000/2010과 상태 조회 getter1025/1018/2200뿐이며 encoder가 그 밖의 ID를 거부한다.
getter 셋은 `nfc_cu_status` 전용이며 HF 식별 `nfc_cu_identify`는 1002/2000/2010(`f4` GET_VERSION)만 쓴다([HF 식별 계약](cu-hf-identify.md)).
2010 option은 아래 네 값(`f4`/`fc`/`ec`/`e4`)만 쓴다. v2.3.0에 새로 생긴 Ultralight C 3DES
AUTH/READ/WRITE/SET_KEY(2018/2019/2021/2022, [app_cmd.c](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L558-L679))는 payload 검사 전에
HF field를 켜고 인증·쓰기·키 변경을 수행하므로 보내지 않는다. BLE pairing PIN을 돌려주는 1031/1034,
고정 장치 식별자1011/1012, 모드 변경1001, field 직접 제어2100/2101, scan-keep2016, LF Pyramid scan3021도
보내지 않는다. 명령 ID는 공식 host enum이 아니라 firmware `data_cmd.h`를 기준으로 한다.

### activation 순서와 HF field

probe 순서는 mode→scan2000→GET_VERSION→READ0→READ1이다. scan은 레코드 정확 하나,
UID7·ATQA wire4400·SAK00·ATS0을 요구한다([2000](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L280-L300), hook
[L2076-L2105](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L2076-L2105)). scan firmware는 SAK bit0x20에서 호스트 거부 이전에 RATS를
수행할 수 있으므로 거부 태그에 SELECT 외 RF0을 보장하지 않는다. scan의 after hook은 항상 field를 끈다.

RAW2010([processor](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L708-L763), [raw_cmd](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/hf/rc522.c#L1554-L1675))는 고정100ms RF timeout과
CRC append/check·wait·activate를 쓴다. option bit는 `0x10` auto-select, `0x08` keep field다.

| 단계 | option | 의미 |
|---|---|---|
| GET_VERSION (첫 activation 단독) | `f4` | auto-select, keep=0 |
| READ0 (둘째 activation 시작) | `fc` | auto-select로 다시 선택, keep=1 |
| 내부 읽기의 READ1·page2..N-2 | `ec` | 선택 유지, keep=1 |
| probe READ1·내부 읽기 마지막 page | `e4` | 선택 유지, keep=0 |

firmware는 keep=0 RAW의 끝에서 성공·timeout·CRC 오류·4bit NAK와 관계없이 field를 끄고
([L1670-L1672](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/hf/rc522.c#L1670-L1672)), auto-select 실패도 field를 끈다
([L1592-L1599](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/hf/rc522.c#L1592-L1599)). 그래서 GET_VERSION은 성공이든 실패든 field가 꺼진 상태로
끝난다. 응답은 다음 닫힌 표로 분류한다.

| GET_VERSION 응답 | 결과 |
|---|---|
| status0x00, CRC 제거 정확8B, NTAG213/215/216의 세 NXP 값 | 계속 |
| status0x00, 다른 8B (예: Ultralight EV1) | `nfc_family_unsupported` |
| status0x00, 빈 payload (check CRC 아래 4bit NAK: 원조 Ultralight·Ultralight C) | `nfc_family_unsupported` |
| status0x01(timeout)·0x03(CRC 오류), 빈 payload | `nfc_family_unsupported` |
| 그 밖의 명령·상태·길이 조합 | `nfc_scan_invalid` |

원조 Ultralight(MF0ICU1)와 Ultralight C는 NTAG와 같은 UID7·ATQA0044·SAK00이라 scan을 통과하고
이 단계에서 갈린다. 거부는 terminal이며 그 태그에 0x30 READ를 보내지 않는다. 0x01에는 선택 뒤
태그가 field를 벗어난 경우도 섞인다. 4bit NAK가 status0x00·빈 payload가 되는 경로는 소스에서
확인했지만([L1639-L1658](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/hf/rc522.c#L1639-L1658)) 실제 RC522로 확인하지 않았다.

READ는 새 activation이다. READ0이 `fc`로 태그를 다시 깨워 선택하고 READ1을 이어 읽는다.
probe의 READ1은 `e4`로 정상 응답 후 field를 해제하는 경로다. reader CRC 성공 관찰은
`reader_crc_check_succeeded=true`, 호스트 RF CRC 검산은 `host_crc_verified=false`로 구분한다.
외부 frame LRC를 RF CRC 증명으로 바꾸지 않는다.

version과 UID page는 서로 다른 선택(WUPA)에서 관찰된다. version을 확인한 태그와 READ0/1의 태그가
같은 실물이라는 결속은 같은 선택 안의 관찰보다 약하며, `reselection_atomic=false`와
`physical_same_tag_verified=false`를 유지한다. READ16B 중 첫4B만 요청 시작 page에 귀속한다.
READ0의 UID 앞3B·BCC0와 READ1의 UID 뒤4B를 앞선 scan과 비교한다. AUTH0·물리 끝에서 READ가 돌아갈
수 있어 나머지12B로 다른 page를 채우지 않는다. 이 비교는 재선택 원자성·복제 없음·진품을 증명하지 않는다.

내부 읽기 provider는 새 admission 뒤45/135/231개 시작 page에서 각각4B를 수집하고
실패 뒤 나머지를 unread로 남긴다. admission READ1(`ec`)은 field를 유지하여 page2로
이어간다. 이미 field를 해제한 공개 probe 결과를 재사용하지 않는다. 공개 read job은 이
provider를 소비하며 별도 snapshot·원장·등록 단계에서 부분성과 receipt를 보존한다. Signature·Counter·Tearing을 만들어
완전한 Flipper 파일을 생성하지 않으며, PWD/PACK의0도 자격증명0으로 해석하지 않는다.

남는 위험(이번에 고치지 않음): keep=1 READ(`fc`·`ec`)가 timeout·CRC 오류·취소로 실패하거나, 성공한 keep=1
frame(`fc`·`ec`) 뒤 다음 frame 전에 호스트 time_limit·취소로 멈추거나, READ1(`ec`) 뒤 호스트의 UID/BCC 대조가 실패하면 field가
켜진 채 남을 수 있다. terminal은 추가 명령을 보내지 않는다는
계약 때문에 자동2101·field-off RAW·재시도·재선택은 없다. host close도 field를 끄지 않는다.
`rf_off_verified=false`, `device_command_termination_verified=false`다.

## scan 사실과 한계

CU scan은 `nfc-ntag21x-cu-scan-v1`과 `nfc-mcp/nfc_cu_scan` source에 결속한다. 새 scan은
live profile/hash·commit을, 이전 v2.2.0 기록은 그 행의 값을 그대로 가지며 fact kind는 같다.
firmware claim·private 식별값·reader binding 및 두 페이지 검증 사실을 기존 bounded 보호 원장에
남긴다. `read_requests=2,pages_retained=2`는 검증에 사용한 두 시작 페이지의 수이며 원장에 page
bytes를 저장했다는 뜻은 아니다. 알 수 없는 profile이나 섞인 hash/commit의 scan 행은
`nfc_scan_invalid`이며 그 케이스의 NFC 도구가 닫힌 실패로 멈춘다.

`nfc-scan`은 Flipper와 CU의 배타적 형식을 검증한다. CU profile은 두 이름 중 하나이며 새 scan은
live 이름인지 코드에서 따로 확인한다. CU의 page READ·reader CRC 조건을 Flipper의 page READ 없음·
scratch 정리·호스트 CRC 조건에 섞지 않는다. 기존 inventory/tag_ref·케이스 솔트 지문·파일 admission·요약
의미는 유지한다. inventory 지문은 identity만 덮으므로 v2.2.0 scan으로 만든 tag_ref도 live reader로 다시
admission해 읽을 수 있다. 등록 후 늦은 취소나 정리 미확인에도 이미 commit한 receipt는 보존한다.

태그 쓰기·PWD_AUTH·Ultralight C 인증·키 탐색·Classic·slot·에뮬레이션·스니프·임의 RAW는 제공하지 않는다.
정상 마지막 응답은 고정 firmware의 field 해제 처리 경로에 대한 관찰이며 물리 RF 측정이
아니다. `physical_same_tag_verified`, `device_command_termination_verified`,
`rf_off_verified`는 false로 유지한다.

프로토콜 근거는 tag `v2.3.0`의 [공식 host](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/software/script/chameleon_com.py),
[명령 형식](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/software/script/chameleon_cmd.py#L369-L410),
[명령 표](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L3224-L3401), [dispatcher](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_cmd.c#L3434-L3471),
[상태 코드](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/app_status.h#L7-L37),
[reader 구현](https://github.com/RfidResearchGroup/ChameleonUltra/blob/4e1a5b267b9ed33559e0e2c9dad61d61eaf64ba1/firmware/application/src/rfid/reader/hf/rc522.c),
[NXP NTAG213/215/216 자료](https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf)다.
tag `v2.3.0`의 공식 Python host는 `chameleon_enum`의 중복 값1041 때문에 import되지 않을 수 있으므로
명령 ID 근거로 쓰지 않는다. v2.2.0 검증 행의 근거는 같은 함수의 이전 위치다
([RAW processor](https://github.com/RfidResearchGroup/ChameleonUltra/blob/f349dbeeaa315776b272ae8fb851cc4042d55f07/firmware/application/src/app_cmd.c#L548-L603), [raw_cmd](https://github.com/RfidResearchGroup/ChameleonUltra/blob/f349dbeeaa315776b272ae8fb851cc4042d55f07/firmware/application/src/rfid/reader/hf/rc522.c#L1459-L1580)). 두 tag 사이에 PWEH가 보내는
명령의 처리 함수·상태 코드·frame codec·USB VID/PID6868:8686은 바뀌지 않았고 응답 버전 값만 다르다.
