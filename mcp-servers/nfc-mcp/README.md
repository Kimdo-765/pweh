# pweh-nfc

CU 고정 연결·스캔·HF/LF 계열 식별·Ultralight 소유 증명 scan·장치 상태 조회·페이지 스냅샷 읽기와 같은 케이스의 Flipper/CU scan 사실에 결속한 파일 분석 서버다. NTAG213/215/216과, 사람이 `tag-ownership`으로 소유(또는 소유자 서면 허가)를 증명한 Ultralight 계열 태그만 inventory에 등록하며, 파일 내용을 태그에 쓰거나 인증·키 탐색·에뮬레이션을 수행하지 않는다.

| 도구 | 입력 | 결과 |
|---|---|---|
| `nfc_cu_connect` | `case_id`, `port`, `approval_id=None` | 공식 v2.3.0 Ultra reader(APP2.3·GIT 정확 v2.3.0) 확인·실제 session_id |
| `nfc_cu_scan` | `case_id`, `session_id`, `approval_id=None` | 새 scan·단독 GET_VERSION·새 선택 READ0/1 검증 뒤 마스킹 scan_ref |
| `nfc_cu_identify` | `case_id`, `session_id`, `approval_id=None` | READ·인증 없는 HF 계열 분류(family·§6.2 policy·UID 길이·ATS 유무·계열별 솔트 지문). 세션은 ready 유지 |
| `nfc_cu_lf_identify` | `case_id`, `session_id`, `approval_id=None` | 125 kHz 고정 scan을 첫 감지에서 멈추며 LF 계열 분류(family·EM410x variant·§6.2 policy·scans_sent). 감지 계열은 모두 refused, 원시 ID·지문 등 ID 파생 값은 반환하지 않음(`identity_digest`는 항상 null). 세션은 ready 유지 |
| `nfc_cu_ul_scan` | `case_id`, `session_id`, `approval_id=None` | READ·인증 없는 Ultralight 계열 확인 뒤 `tag-ownership` 증명이 있으면 UL scan 사실과 `US-` scan_ref(`nfc-ul-scan`), 없으면 기다리지 않고 `attestation_required`(계열·`ul_identity_digest`만). Ultralight가 아니면 `nfc_family_unsupported`. 세션은 ready 유지 |
| `nfc_cu_status` | `case_id`, `session_id` | RF 없는 배터리 mV·추정 percent·0부터 센 활성 slot·HF14A 설정 기본값 여부와 연결 때의 모델·APP·GIT |
| `nfc_cu_read_start` | `case_id`, `session_id`, `tag_ref`, `approval_id=None` | 유한 페이지 snapshot job·전용 device-read 원장·artifact 등록. `UT-` tag_ref는 예약 전 `tag-ownership` 증명 재확인 뒤 Ultralight snapshot(없으면 frame 없이 `attestation_required`) |
| `nfc_job_status` | `job_id`, `wait_seconds=0.0`, `case_id=None` | 작업·저장 기록과 실제 결과 조회 |
| `nfc_job_cancel` | `job_id` | 취소 요청, 실제 commit 결과 보존 |
| `nfc_jobs` | `active_only=False`, `case_id=None` | 작업 목록·저장 기록 복구 상태 |
| `nfc_cu_disconnect` | `case_id`, `session_id` | 같은 세션의 worker·transport·lease 정리 결과 |
| `nfc_tag_inventory_add` | `case_id`, `scan_ref` | `tag_ref`, `scan_ref`, family, 케이스 솔트 지문, scan/inventory 원장 seq·SHA. `US-` scan_ref는 `tag-ownership` 증명을 다시 확인한 뒤 `UT-` tag_ref(`nfc-ul-inventory`), 증명이 철회·만료되면 `attestation_required` |
| `nfc_parse_file` | `case_id`, `artifact_id`, `tag_ref`, `max_seconds=5` | 기존 순수 검사 결과와 출처 결속, 실제 저장 경로·SHA. `UT-` tag_ref는 Ultralight snapshot만 받고 증명을 다시 확인한 뒤 `nfc-ul-file-analysis` |
| `nfc_diff_dumps` | `case_id`, `before_artifact_id`, `after_artifact_id`, `tag_ref`, `max_seconds=5` | 저장 페이지 비교 결과와 두 파일의 출처 결속, 실제 저장 경로·SHA. CU snapshot은 같은 reader 프로필끼리만. `UT-` tag_ref는 Ultralight snapshot 둘만 |

CU는 명시 COM/tty와 현재 USB CDC 신원·전체 sibling 잠금 아래 MODIFY 게이트를 거친다. [고정 CU 계약](../../docs/references/cu-ntag-read-provider.md)의 시작5초·스캔45초·명령2초·close10초를 따르며 실패 뒤 자동 RF-off/재접속을 하지 않는다. v2.2.0 reader 프로필은 이전 scan·snapshot의 검증 전용이다.
`nfc_cu_identify`는 MODIFY 게이트 뒤 scan2000과 Type 2 후보의 단독 GET_VERSION 하나로 닫힌 표를 적용하며 scan 사실·inventory를 만들지 않는다. `nfc_cu_status`는 RF 없는 getter만 보내는 INTERACT다. 분류표·근거·한계는 [HF 식별·상태 계약](../../docs/references/cu-hf-identify.md)을 따른다. 교통·결제·출입 자격증명은 policy와 관계없이 범위 밖이다. 예외(설계 §1.3·§6.2의 2026-11-02 개정): 사용자 소유(또는 소유자 서면 허가) Ultralight 계열 태그는 사용한 교통 승차권도 `nfc_cu_ul_scan`의 `tag-ownership` 증명 뒤 scan·inventory(읽기 전용 페이지 스냅샷 대상)에 올릴 수 있다.
`nfc_cu_ul_scan`은 MODIFY 게이트(`cu.ul-scan`) 뒤 `nfc_cu_identify`와 같은 mode·scan2000·keep=0 GET_VERSION 하나만 보내고 0x30 READ·PWD_AUTH·UL C 인증·쓰기는 보내지 않는다. CU 사용권을 놓은 뒤 ctx 없이 증명을 찾아 호출 안에서 사람을 기다리지 않는다. 사람이 `pweh attest <id>`로 답한 뒤 같은 인자로 다시 부르면 frame을 새로 보내 같은 계열·지문·케이스일 때만 원장 잠금 안의 증명 재확인 뒤 기록한다. 증명 subject에는 원시 UID가 없다. GET_VERSION status0x01·빈 응답은 원조 UL의 무응답과 scan 뒤 태그가 field를 벗어난 경우가 섞여 원조 UL/UL C로 보이므로 그 결과는 `nfc_cu_identify`로 다시 확인한다. UL 원장 행(`nfc-ultralight-cu-scan-v1`·`nfc-ultralight-inventory-v1`)은 NTAG 행과 키가 겹치지 않아 NTAG 흐름과 NTAG cache(`nfc/inventory.json`)를 바꾸지 않는다.
UT- tag_ref의 `nfc_cu_read_start`는 CU 사용권 예약 전에 같은 증명을 ctx 없이 다시 확인하고, job 안에서도 frame 전·원장 append 직전·등록 직전에 같은 id를 확인한다. wire는 mode·scan2000·keep=0 GET_VERSION 뒤 page마다 `f4` 단독 activation READ(0x30) 하나이며 PWD/PACK·UL C 키 페이지는 요청하지 않는다(null). 인증·쓰기·READ_SIG/READ_CNT/FAST_READ·keep=1 option은 없다. NAK는 정상 끝이다(roll-over 근거가 있으면 완료, 없으면 `tag_nak` 부분). 결과는 `nfc/cu-ul-read-NNN.json`(0444, 증명 id를 담은 device-read 원장)이고 `nfc_parse_file`·`nfc_diff_dumps`의 UT- 분기는 같은 증명을 다시 확인해 `analysis/nfc-ul-file|diff-NNN.json`(`nfc-ul-file-analysis`)에 구조·관찰 범위와 inspect 데이터시트 표준 필드(잠금 비트·OTP 켜진 비트 수·사용자 영역 빈/기록 page 번호·EV1 설정 AUTH0·PROT·CFGLCK·AUTHLIM·VCTID)를 원시 값 없이 저장한다. 규칙 전체는 [Ultralight 스냅샷 계약](../../docs/references/cu-ultralight-read.md)이다.
`nfc_cu_lf_identify`는 MODIFY 게이트(`cu.lf-identify`) 뒤 mode1002와 EM410x→HID Prox→ioProx→Viking→PAC→Jablotron→Pyramid scan을 첫 감지에서 멈추며 보낸다. scan마다 125 kHz field를 약0.5초 켜고 firmware가 끈다(물리 미측정). T55xx·EM4x05(LOGIN)·쓰기·스니프·emulator 명령은 없다. ID는 지문으로도 남기지 않는다(24–40비트 125 kHz ID는 솔트를 읽는 같은 OS 계정이 솔트 지문을 전수 대입으로 되돌릴 수 있어서 `identity_digest`는 항상 null이다). 근거 줄은 [LF 식별 계약](../../docs/references/cu-lf-identify.md)을 따른다.
GET_VERSION은 단독 keep=0 activation이며 NTAG213/215/216이 아니면 READ 없이 거부한다. 읽기 job은 새 admission 뒤 같은 field에서 시작 페이지4B를 모으고 [스냅샷 계약](../../docs/references/cu-read-snapshot.md)의 전용 원장·파일 등록으로 연결한다. wire45초 뒤 host 검증/저장5초를 한 번 사용한다.

`flipper_nfc_probe`는 별도 `pweh-flipper` 서버에서 실행한다. 두 provider의 검증 조건은 독립 유지한다. 성공한 같은 케이스 `scan_ref`를 inventory에 등록한 뒤, `case_import_file` 또는 허용된 Flipper 파일 복사로 등록한 artifact id를 사용한다. 사용자가 제출한 UID·family, cache, 임의 producer 문자열은 scan 사실을 대신하지 않는다. 기존 `provenance-import` 사람 증명을 요구하면 사람이 별도 터미널의 `pweh attest <id>`로 답한다. 에이전트가 증명을 대신하지 않는다.

각 입력은 1 MiB 이하의 단일 링크 일반 파일이다. `forensics/`, `emu/`, 보호 경로, 심볼릭 링크·하드 링크·디렉터리는 거부한다. 증명 요청 전 입력 FD를 모두 닫고, 만족한 뒤 다시 열어 최초 SHA와 scan/inventory 결속을 비교한다. 최종 등록 직전에도 현재 원장·증명과 같은 FD의 내용·이름·부모 신원을 재확인한다. atime는 신원 비교에 쓰지 않는다.

`max_seconds`는 0초 초과 5초 이하이며 각 입구·최종 분석 worker의 읽기·원장·파싱에 적용한다. 분석 결과 생성 뒤 최종 검증·저장에는 별도 5초를 사용한다. 원장 검사는 16 MiB·10,000 entries, 파일 읽기는 64 KiB chunk, 결과는 128 KiB 이하다. 이 한도는 협력적 검사이며 모든 Python·커널 호출의 즉시 중단 보장은 아니다.

성공 반환은 `{ok, report, analysis:{path,sha256,size,artifact_id}, warnings}`다. 결과는 `analysis/nfc-file-NNN.json` 또는 `analysis/nfc-diff-NNN.json`에 0444로 등록한다. import 원장 commit 뒤 FD 정리 불확실성은 `provenance_close_unconfirmed` 경고로 증명 대기/최종 응답에 보존한다. 출력 commit 뒤 오류는 산출물을 보존하고 `post_commit_callback_failed` 또는 `output_close_unconfirmed` 고정 경고로 알린다. commit 전 정리는 이번 생성 inode만 대상으로 하며 확인되지 않은 교체 파일은 보존한다.

공개 결과에는 raw UID·ATQA·SAK·GET_VERSION·페이지·Counter·PWD/PACK이 없다. 보호 scan 원장과 전용 CU snapshot에 내부 신원 bytes를 기록하므로 에이전트는 snapshot을 직접 열지 않는다. 전체 입력 SHA와 케이스 솔트 지문은 익명성 보장이 아니다. `inventory_binding_verified=true`는 기록의 결속이며 `physical_same_tag_verified=false`는 유지한다. 기존 core의 `device_association_verified=false`도 변경하지 않는다.

부분 읽기(`Pages read < Pages total`)의 0값을 실제 읽은 메모리로 해석하지 않는다. ISO 헤더의 검사 결과는 허용하지만 페이지 diff는 `no_page_layout`으로 비교 불가다. 불완전 layout의 null·partial/unsupported 의미를 그대로 보존한다. Skill은 실제 반환된 출력 경로와 해시로 `nfc-analysis` 요약을 기록한다.

CU snapshot은 `nfc/cu-read-NNN.json`·최대64KiB·0444로 저장한다. 원장 commit 뒤 등록 실패는 파일과 실제 원장 receipt를 보존하며 `registered=false` partial_result를 반환한다. `registered=true`의 artifact ID로만 분석한다. imported와 CU snapshot은 각각 기존 사람 증명과 전용 device-read 원장을 요구하고 혼합 diff는 거부한다. 양쪽 관찰 페이지만 비교하며 양쪽 읽기와 전체 비교가 끝나야 `stored_pages_equal`이 bool이다. read receipt는 inspect/diff 요약으로 대신하지 않는다.

개발 시험은 합성 Flipper/CU wire와 격리 케이스만 사용한다: `tests/servers/test_nfc_mcp.py`, `tests/servers/test_nfc_analysis.py`, `tests/servers/test_nfc_cu_identify.py`, `tests/core/test_cu_identify_protocol.py`, `tests/servers/test_nfc_cu_lf_identify.py`, `tests/core/test_cu_lf_identify_protocol.py`, `tests/servers/test_nfc_cu_ul_scan.py`, `tests/core/test_cu_ultralight_protocol.py`, `tests/core/test_nfc_ul_inventory.py`. 전체 공용 계약은 [architecture](../../docs/architecture.md), 운영 흐름은 [NFC 분석](../../docs/references/nfc-inventory-analysis.md)을 따른다.
