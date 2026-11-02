# NFC 요약 필드 연결

도구의 실제 반환만 옮긴다. 아래 참조와 해시는 형식을 보여 주는 자리표시자다.

| 요약 필드 | 근거 |
|---|---|
| `tags[].tag_ref/scan_ref/family/identity_digest` | `nfc_tag_inventory_add`의 성공 결과 |
| `results[].artifact_id/path/sha256` | parse/diff 응답의 `analysis.artifact_id/path/sha256` |
| `results[].operation/status/tag_ref` | `report.operation/status/source.tag_ref` |
| `mode` | `scan-bound-offline` 고정 |
| 네 false flag | 이 Skill이 확인하지 않거나 수행하지 않은 범위를 그대로 유지 |

각 배열은 최대32개다. 결과가 더 있으면 선택한 범위를 summary 설명에 명시하고, 도구 결과나 입력을 임의로 잘라 완전한 검사처럼 보고하지 않는다. 원 UID·ATQA·SAK·GET_VERSION·페이지·키·PWD/PACK는 요약에 넣지 않는다.

요약 JSON 예시는 [SKILL.md](SKILL.md)의 정리와 요약 절을 따른다.

`inventory_binding_verified=true`는 보호 원장의 명시 스캔·inventory와 파일 식별값이 일치했다는 뜻이다. 진품·복제 없음·항상 같은 실물·원자적인 태그 선택을 뜻하지 않는다. `identity_digest`는 케이스 솔트가 적용된 표시값이며 권위는 private exact 식별값과 검증된 원장 기록이다.

ISO14443-3A 헤더는 유효한 scan에 결속하여 구조 검사할 수 있으나 페이지 배치가 없으므로 diff의 `no_page_layout`을 유지한다. `Pages read < Pages total`은 기존 partial이며 저장된 0바이트로 읽기 범위를 추정하지 않는다. 같은 UID claim만으로 부분 파일의 페이지 대응을 복원하지 않는다.

일반 복사 파일의 출처 증명은 기존 `provenance-import`의 케이스·전체 SHA에 묶인다. 파일 내용·원장·증명 중 하나가 바뀌면 도구가 재검증하며, 한쪽 파일의 증명으로 다른 SHA를 허용하지 않는다. `nfc/inventory.json`은 마스킹 조회 사본이며 손상·삭제되어도 보호 원장 대신 신뢰하지 않는다.

CU scan은 `nfc_cu_connect`의 실제 세션으로 `nfc_cu_scan`을 호출해 얻는다. 기존 요약 필드는 동일하며 provider별 원시 식별값을 추가하지 않는다. Flipper의 page READ 없음과 CU의 두 시작 페이지 검증을 혼동하지 않으며, 두 경로 모두 물리 동일 태그 검증은 false다.

CU read job의 실제 snapshot은 [CU 스냅샷 계약](../../docs/references/cu-read-snapshot.md)에 따른다. `registered=true`의 artifact_id로 parse/diff한 뒤 그 분석 receipt만 results에 넣는다. read receipt의 job 상태·read_complete·registered는 각각 구분한다. CU snapshot은 전용 device-read 원장으로 검증하고 일반 가져온 파일의 사람 증명을 대신하지 않는다. v2.2.0 reader 프로필의 이전 snapshot은 검증·단독 parse와 같은 프로필끼리의 diff만 가능하며 v2.3.0 snapshot과의 diff는 nfc_source_mismatch로 거부된다. 양쪽 읽기와 전체 비교가 완료되지 않은 `stored_pages_equal=null`과 미비교 페이지 수를 보존한다.

## CU 식별·상태 기록

`nfc_cu_identify`와 `nfc_cu_status`의 결과는 inventory 결속 결과가 아니므로 tags/results에 넣지 않는다.
식별·상태만 한 실행은 `nfc-analysis` 요약의 mode `cu-hf-identify`로 `step="summary"`에 기록한다(tags·results는 빈 배열).
inventory·파일 결과가 함께 있는 실행은 mode `scan-bound-offline` 요약을 쓰고, 식별 결과는 같은 요약에 넣지 않고 설명(summary 문장)에만 적는다.

| 요약 필드 | 근거 |
|---|---|
| `identifications[].operation` | "cu-identify" 고정 |
| `identifications[].profile/family/policy/uid_length/ats_present/get_version_sent/identity_digest` | 식별 반환값 그대로(UID 없는 none·multiple 은 uid_length·ats_present·identity_digest가 null) |
| `identifications[].page_reads_sent` | 식별 반환값의 false를 그대로 둔다 |
| `device_status.battery_mv/battery_percent/battery_percent_is_estimate/active_slot/mode/hf14a_config_default/app_version/git_version/model` | 상태 반환값 그대로. percent는 추정, slot은 0부터 |

식별의 `identity_digest`는 계열별 domain을 분리한 케이스 솔트 지문이다. inventory의 `identity_digest`와 같은 값이 아니다.
같은 카드라도 두 값을 비교해 결속하지 않는다. NTAG를 inventory에 올리려면 `nfc_cu_scan`의 실제 scan_ref를 쓴다.
`policy`는 설계 §6.2 표의 정보이며 사람 증명이나 다른 도구를 대신하지 않는다. 표의 근거와 한계는 [HF 식별 계약](../../docs/references/cu-hf-identify.md)에 있다.

## CU LF 식별 기록

`nfc_cu_lf_identify`의 결과도 inventory 결속 결과가 아니므로 tags/results에 넣지 않는다.
LF 식별(과 상태 조회)만 한 실행은 `nfc-analysis` 요약의 mode `cu-lf-identify`로 `step="summary"`에 기록한다(tags·results는 빈 배열).
HF와 LF 식별을 함께 했다면 둘 중 한 식별 mode를 쓰고 `identifications`와 `lf_identifications`를 같은 요약에 넣는다.
`scan-bound-offline` 요약은 `lf_identifications`를 받지 않는다.

| 요약 필드 | 근거 |
|---|---|
| `lf_identifications[].operation` | "cu-lf-identify" 고정 |
| `lf_identifications[].profile/family/variant/policy/scans_sent/identity_digest` | LF 식별 반환값 그대로(variant는 em410x만 값, identity_digest는 모든 계열에서 null) |
| `lf_identifications[].id_returned` | 반환값의 false를 그대로 둔다 |

LF `identity_digest`는 항상 null이다. 125 kHz 출입 ID는 24–40비트라 케이스 솔트 지문도 솔트를 읽는 같은 OS 계정이 전수 대입으로 되돌릴 수 있으므로
LF 식별은 지문을 포함한 ID 파생 값을 만들지 않는다. 그래서 LF 결과끼리나 HF 식별·inventory 지문과 같은 카드인지 비교·결속하지 않는다.
감지 계열의 `policy`는 모두 refused다. §6.2의 장난감·동물·시험 태그 사람 증명 예외는 아직 없으므로 사람 증명으로 바꾸지 않는다.
원시 ID·FC/CN·HID format은 반환되지 않으므로 요약에도 넣지 않는다. 근거와 한계는 [LF 식별 계약](../../docs/references/cu-lf-identify.md)에 있다.

## CU Ultralight scan·inventory·snapshot 기록

Ultralight 결과는 `nfc-analysis` 요약 mode `scan-bound-offline`의 tags·results에 **UL 항목**으로 넣는다(NTAG 항목과 섞이지 않는 닫힌 형식).
UL 흐름은 `nfc_cu_ul_scan` 전에 처음 호출한 `nfc_cu_identify` 반환값을 `step="ul-identify"`(`data.identifications`, 아래 HF 식별 항목과 같은 필드)로
먼저 기록한다. 이 기록 없이 `nfc_cu_ul_scan`을 부르지 않는다. inventory까지 성공했으면 결과가 없어도(results 빈 배열) tags 하나로 요약할 수 있고,
`scan-bound-offline`은 식별 배열을 받지 않으므로 식별 근거는 `ul-identify` 기록에 남는다. inventory 전에 멈췄으면(denied·계열 불일치·오류)
`ul-identify` 기록의 `identifications`로 mode `cu-hf-identify` 요약을 쓰고, 멈춘 이유와 고정 오류를 summary 문장과 `step="attempt"`에 남긴다.

| 요약 필드 | 근거 |
|---|---|
| `tags[].tag_ref` | US- scan_ref로 호출한 `nfc_tag_inventory_add` 결과의 UT- 참조 |
| `tags[].scan_ref` | 같은 결과의 US- 참조(`nfc_cu_ul_scan` 성공 결과와 같다) |
| `tags[].family`·`tags[].ul_identity_digest` | inventory 결과의 같은 이름 필드 |
| `tags[].tag_ownership_attestation_id` | inventory 결과 `attestation.attestation_id`(그 호출에서 다시 확인한 현재 tag-ownership 증명 id) |
| `results[].artifact_id/path/sha256` | UT- tag_ref로 부른 parse/diff 응답의 `analysis.artifact_id/path/sha256`(`analysis/nfc-ul-file|diff-NNN.json`) |
| `results[].operation/status/tag_ref` | `report.operation/status/source.tag_ref`(status는 ok·partial) |

`ul_identity_digest`는 Ultralight 전용 domain의 케이스 솔트 지문이며 HF 식별·NTAG inventory의 `identity_digest`와 같은 값이 아니다. 서로 비교해 결속하지 않는다.
UL 항목에 `identity_digest`를 넣거나 NT-/NS- 참조를 UL 항목에 넣지 않는다. 식별 배열(`identifications`)은 `scan-bound-offline` 요약에 넣지 않는다.
inventory 결과의 `inventory_attestation_id`, read receipt의 `attestation_id`·`read_end`·`observed_variant`, 보고서의 `files[].read_attestation_id`는
요약 칸이 아니므로 summary 문장이나 일반 단계 기록(`step="ul-read"` 등)에 반환값 그대로 적는다. read receipt를 results로 대신하지 않는다.
증명은 사람이 `pweh attest <id>`로 답한 기록이며 태그 소유를 서버가 확인한 사실이 아니다. 원시 UID·페이지·PWD/PACK은 어디에도 넣지 않는다.
