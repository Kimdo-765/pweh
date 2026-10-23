# ChameleonUltra 고정 NTAG 읽기 경로

`pweh-nfc`는 ChameleonUltra의 고정 USB 프로토콜로 연결·NTAG213/215/216 스캔과
기존 inventory 연결·유한 페이지 스냅샷 읽기를 제공한다. 구현 검증은 가짜 transport·합성 태그로 수행한다.
실제 USB 채널·RF 동작·진품이나 물리적으로 같은 태그를 확인했다는 뜻은 아니다.

## 공개 흐름

| 도구 | 입력 | 동작 |
|---|---|---|
| `nfc_cu_connect` | `case_id, port, approval_id=None` | 허가·현재 포트 신원·전체 USB 잠금·MODIFY 게이트 뒤 고정 네 조회로 모델·버전·reader 모드를 확인 |
| `nfc_cu_scan` | `case_id, session_id, approval_id=None` | 같은 세션의 MODIFY 게이트 뒤 새 scan·GET_VERSION·READ0/1과 식별값 일치를 확인하고 보호 scan 사실 기록 |
| `nfc_cu_read_start` | `case_id, session_id, tag_ref, approval_id=None` | 같은 inventory·세션·MODIFY 게이트 뒤 유한 페이지 snapshot job 시작 |
| `nfc_cu_disconnect` | `case_id, session_id` | 사용권 종료·물리 close·lease 해제를 확인. 허가 철회 뒤에도 같은 세션 정리 가능 |

connect의 실제 `session_id`로 scan을 호출하고, 실제 `scan_ref`를
`nfc_tag_inventory_add`에 전달한다. 기존 `nfc_parse_file`/`nfc_diff_dumps`의 파일
출처 증명·같은 FD 검증은 [NFC 분석 계약](nfc-inventory-analysis.md)을 그대로 따른다.
CU scan을 사용해도 가져온 파일을 CU에서 읽었다고 기록하지 않는다.
read job의 조회·취소, snapshot의 전용 출처·등록과 분석은 [스냅샷 계약](cu-read-snapshot.md)을 따른다.

connect 성공의 `device`는 고정 모델·허용 버전·reader 모드만 표시한다.
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

## 고정 프로토콜

profile은 `cu-ntag21x-v2.2.0-v1`이다. 공식 소스
[`f349dbeeaa315776b272ae8fb851cc4042d55f07`](https://github.com/RfidResearchGroup/ChameleonUltra/tree/f349dbeeaa315776b272ae8fb851cc4042d55f07)의
APP2.2·GIT 정확 `v2.2.0`·Ultra·reader mode1만 허용한다. 다른 버전·Lite·emulator
모드에서는 태그 명령을 보내지 않는다. 모드·slot 변경 명령은 없다.

frame은 SOF/LRC1/CMD/STATUS/LEN/LRC2/DATA/LRC3이고 다중 바이트 정수는 BE다.
세 LRC를 각각 검증한다. PWEH의 DATA 상한은512B, frame522B, decoder 보유1044B다.
이512B를 공식 host 전체의 최대치라고 해석하지 않는다. 한 요청에는 응답 정확 하나와
미소비 바이트0을 요구한다. 잡음 제거·재동기화·자동 재전송은 없다.

연결 조회는1000/1017/1033/1002 순서이며 일반 성공은0x0068이다. probe/read 시작에도
mode1002를 다시 확인한다. 태그 scan2000과 고정 RAW2010의 성공0x0000 및 payload
길이를 별도로 검사한다. 같은2010의 지연 중복에는 wire seq/page echo가 없어 완전한
구별이 불가능하며, idle 잔여 검사를 원자적 동기화로 표시하지 않는다.

probe 순서는 mode→scan2000→GET_VERSION→READ0→READ1이다. scan은 레코드
정확 하나, UID7·ATQA wire4400·SAK00·ATS0을 요구한다. scan firmware는 SAK bit0x20에서
호스트 거부 이전에 RATS를 수행할 수 있으므로 거부 태그에 SELECT 외 RF0을 보장하지 않는다.

GET_VERSION은 정확8B의 세 NXP version만 받는다. RAW는 고정100ms RF timeout,
CRC append/check·wait·activate를 사용한다. GET_VERSION만 auto-select=true이며
READ는 auto-select=false다. probe의 READ1은 정상 응답 후 field를 해제하는 경로다.
reader CRC 성공 관찰은 `reader_crc_check_succeeded=true`, 호스트 RF CRC 검산은
`host_crc_verified=false`로 구분한다. 외부 frame LRC를 RF CRC 증명으로 바꾸지 않는다.

READ16B 중 첫4B만 요청 시작 page에 귀속한다. READ0의 UID 앞3B·BCC0와 READ1의
UID 뒤4B를 앞선 scan과 비교한다. AUTH0·물리 끝에서 READ가 돌아갈 수 있어 나머지12B로
다른 page를 채우지 않는다. 이 비교는 재선택 원자성·복제 없음·진품을 증명하지 않는다.

내부 읽기 provider는 새 admission 뒤45/135/231개 시작 page에서 각각4B를 수집하고
실패 뒤 나머지를 unread로 남긴다. 이때 admission READ1은 field를 유지하여 page2로
이어간다. 이미 field를 해제한 공개 probe 결과를 재사용하지 않는다. 공개 read job은 이
provider를 소비하며 별도 snapshot·원장·등록 단계에서 부분성과 receipt를 보존한다. Signature·Counter·Tearing을 만들어
완전한 Flipper 파일을 생성하지 않으며, PWD/PACK의0도 자격증명0으로 해석하지 않는다.

## scan 사실과 한계

CU scan은 `nfc-ntag21x-cu-scan-v1`과 `nfc-mcp/nfc_cu_scan` source에 결속한다.
고정 profile/hash·firmware claim·private 식별값·reader binding 및 두 페이지 검증 사실을
기존 bounded 보호 원장에 남긴다. `read_requests=2,pages_retained=2`는 검증에 사용한
두 시작 페이지의 수이며 원장에 page bytes를 저장했다는 뜻은 아니다.

`nfc-scan`은 Flipper와 CU의 배타적 형식을 검증한다. CU의 page READ·reader CRC
조건을 Flipper의 page READ 없음·scratch 정리·호스트 CRC 조건에 섞지 않는다.
기존 inventory/tag_ref·케이스 솔트 지문·파일 admission·요약 의미는 유지한다.
등록 후 늦은 취소나 정리 미확인에도 이미 commit한 receipt는 보존한다.

태그 쓰기·PWD_AUTH·키 탐색·Classic·slot·에뮬레이션·스니프·임의 RAW는 제공하지 않는다.
정상 마지막 응답은 고정 firmware의 field 해제 처리 경로에 대한 관찰이며 물리 RF 측정이
아니다. `physical_same_tag_verified`, `device_command_termination_verified`,
`rf_off_verified`는 false로 유지한다.

프로토콜 근거는 고정 [공식 host](https://github.com/RfidResearchGroup/ChameleonUltra/blob/f349dbeeaa315776b272ae8fb851cc4042d55f07/software/script/chameleon_com.py),
[명령 형식](https://github.com/RfidResearchGroup/ChameleonUltra/blob/f349dbeeaa315776b272ae8fb851cc4042d55f07/software/script/chameleon_cmd.py),
[reader 구현](https://github.com/RfidResearchGroup/ChameleonUltra/blob/f349dbeeaa315776b272ae8fb851cc4042d55f07/firmware/application/src/rfid/reader/hf/rc522.c),
[NXP NTAG213/215/216 자료](https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf)다.
