---
name: nfc-behavior-analysis
description: 소유·허가된 PWEH 케이스에서 NTAG213/215/216 스캔을 inventory에 등록하고 CU 페이지 스냅샷을 읽거나 보유 NFC 파일의 구조·저장 페이지 차이를 검사한다. CU로 READ 없이 HF 카드 계열이나 125 kHz LF 카드 계열(ID 마스킹)을 식별하거나 배터리·slot 같은 장치 상태를 확인할 때도 쓴다. NFC 파일 분석, CU 읽기, 카드 종류 확인, NTAG inventory, 두 덤프 비교에 사용한다. 쓰기·인증·에뮬레이션과 게임 반응 확인은 수행하지 않는다.
---

# 스캔 기록에 결속한 NFC 파일 분석

현재 지원 범위는 NTAG213/215/216의 서버 스캔 기록, CU 페이지 스냅샷 읽기와 보유 파일의 저장 표현 검사다. Skill 이름의 “동작”을 실제 콘솔 반응·게임 해금·실물 진품 확인으로 해석하지 않는다. [입구 계약](../../docs/references/nfc-inventory-analysis.md)과 기존 [파일 프로필](../../docs/references/nfc-file-profile.md)을 따른다.

## 준비와 스캔

1. `case_get`으로 소유·허가된 케이스를 확인하고 `case_get_step_results`로 이전 결과를 읽는다. 이미 확인한 허가를 다시 묻지 않는다. 케이스가 없으면 `pweh-start`의 접수를 따른다. 태그와 reader가 허가 범위에 포함되어야 한다.
2. 같은 케이스의 실제 `scan_ref` 또는 `tag_ref`가 있으면 재사용한다. 사용자 UID·파일의 선언·producer 표기로 스캔을 대신하지 않는다. 기존 inventory 파일만 분석하면 장비 연결을 요구하지 않는다.
3. 새 스캔이 필요하면 명시된 Flipper 포트와 공식1.5.1 호환성을 확인하고 `flipper_connect`를 호출한다. 허용 루트 `/ext/pweh/<case_id>/`는 사용자가 미리 준비한다. 포트 열기는 DTR 변경을 포함한다. 필요한 물리 연결·태그 배치는 사람이 하고 완료를 확인한 뒤 진행한다.
4. `flipper_nfc_probe(case_id)`로 고정 SELECT·GET_VERSION을 수행한다. 이 작업은 Flipper SD에 작은 임시 파일을 만들고 제거하므로 MODIFY다. 페이지 READ나 태그 메모리 쓰기는 하지 않는다. 정상 응답의 실제 `scan_ref`만 `nfc_tag_inventory_add`에 전달하고 반환 `tag_ref`를 보존한다.
5. `approval_required`이면 반환 id와 영향을 설명하고 사람이 별도 터미널에서 `pweh approve <id>`로 승인한 뒤 같은 인자와 `approval_id`로 재호출한다. 에이전트가 승인 명령을 실행하지 않는다. `denied`·지원 밖 계열은 우회하지 않으며 raw 명령·다른 앱으로 대신하지 않는다.

CU Ultra를 사용하는 새 스캔은 [CU 계약](../../docs/references/cu-ntag-read-provider.md)을 따른다. 허가된 reader의 명시 포트로 `nfc_cu_connect(case_id, port)`를 호출하고 실제 반환한 `session_id`로 `nfc_cu_scan(case_id, session_id)`을 호출한다. 두 도구는 MODIFY 게이트를 적용하며 위 승인 규칙을 따른다. CU는 현재 reader 모드의 공식 v2.3.0(APP2.3·GIT 정확 `v2.3.0`)만 받으며 mode/slot을 변경하지 않는다. `cu_firmware_unsupported`(v2.2.0이나 dev build 등)이면 우회하지 않고 사람이 공식 release를 확인하게 한다. scan은 단독 GET_VERSION과 새 선택 READ0/1의 UID/BCC를 확인하고, 실제 scan_ref를 같은 `nfc_tag_inventory_add`로 등록한다. 원조 Ultralight·Ultralight C·EV1처럼 NTAG가 아닌 태그는 고정 오류 nfc_family_unsupported로 끝나며 인증·다른 명령으로 대신하지 않는다. CU 페이지 읽기가 필요하면 아래 절로 진행한다.

## CU HF 카드 식별과 장치 상태

사용자가 카드 종류를 알고 싶거나 `nfc_cu_scan`이 지원 밖 계열 오류(nfc_family_unsupported)로 끝났으면 [HF 식별 계약](../../docs/references/cu-hf-identify.md)을 따른다. 같은 연결 세션을 쓰며 페이지를 읽지 않는다.

1. `nfc_cu_status(case_id, session_id)`로 장치 상태를 먼저 확인한다. RF가 없는 INTERACT라 승인 없이 실행된다. battery_percent는 전압으로 추정한 값이고, 부팅 직후 약5초는 0일 수 있다. active_slot은 0부터 센다(공식 CLI 표시는 +1). hf14a_config_default가 false면 scan 동작이 달라지므로 식별 결과와 함께 그 사실을 보고한다. 설정은 바꾸지 않는다.
2. 사람에게 다른 카드를 치우고 카드 한 장만 reader에 올려 달라고 요청하고, 완료 확인 뒤 `nfc_cu_identify(case_id, session_id)`를 호출한다. 이 도구는 MODIFY 게이트를 따르며 위 승인 규칙이 같다. scan2000과, Type 2 후보일 때만 GET_VERSION 하나를 보낸다.
3. 반환된 family와 policy를 그대로 보고한다. family를 추측해 바꾸거나 READ·인증·다른 명령으로 더 나누지 않는다.
   - allowed(NTAG213/215/216)이면 필요할 때 위의 `nfc_cu_scan`으로 이어간다.
   - attestation_required이면 이 계열을 다루는 도구가 아직 없다. 결과만 보고하고 멈춘다. ultralight_or_ultralight_c는 원조 Ultralight와 Ultralight C를 나누지 않은 결과다. type2_version_unreadable은 GET_VERSION 응답이 손상되어 계열을 정하지 못한 결과다.
   - refused(Classic 2K/4K, MIFARE Plus SL2, ISO14443-4)이면 더 조작하지 않는다.
   - none·multiple은 배치 문제일 수 있다. 카드가 정확히 한 장인지 사람에게 확인받은 뒤 같은 세션으로 다시 식별할 수 있다. none을 "카드가 없다"는 사실로 보고하지 않는다. ATQA가 다른 카드 여러 장도 none이 될 수 있다.
   - other는 잘 형성된 레코드가 표에 없는 값이었다는 뜻이다. 배치를 바꿔 다시 시도하지 않고 그대로 보고하고 멈춘다.
4. 교통·결제·출입·호텔·신분 자격증명(예: 교통 티켓)은 policy와 관계없이 범위 밖이다. 사람 증명으로도 넓히지 않는다.
5. 잘 형성된 분류는 세션을 ready로 둔다. 고정 오류(잘못된 응답·timeout·취소·mode 변화)는 세션을 terminal로 만든다. 그러면 `nfc_cu_disconnect`로 정리하고 새로 연결한다. 여러 장의 카드도 nfc_scan_invalid가 될 수 있으므로 다시 연결하기 전에 카드가 한 장인지 확인받는다. physical_same_tag_verified와 rf_off_verified는 false로 보고한다.
6. 결과는 아래 "정리와 요약"의 `nfc-analysis` 요약에 mode `cu-hf-identify`로 기록한다. 식별 반환값의 operation·profile·family·policy·uid_length·ats_present·get_version_sent·page_reads_sent·identity_digest를 `identifications`에, 상태 반환값의 배터리·slot·mode·hf14a_config_default·버전·model을 `device_status`에 그대로 옮긴다(operation은 "cu-identify"). 원시 UID나 사용자가 말한 카드 이름을 family 대신 쓰지 않는다.

## CU LF 125 kHz 카드 식별

사용자가 125 kHz 카드(출입 카드·키 fob 등)의 계열을 알고 싶으면 [LF 식별 계약](../../docs/references/cu-lf-identify.md)을 따른다. 같은 연결 세션을 쓴다.

1. 사람에게 다른 카드를 치우고 카드 한 장만 reader의 LF 안테나 위에 올려 달라고 요청하고, 완료 확인 뒤 `nfc_cu_lf_identify(case_id, session_id)`를 호출한다. 이 도구는 MODIFY 게이트를 따르며 위 승인 규칙이 같다. 125 kHz field를 scan마다 약0.5초, 모두 미감지면 합해서 약3.6초 방사한다.
2. 도구는 EM410x→HID Prox→ioProx→Viking→PAC→Jablotron→Pyramid 순서로 scan하고 첫 감지에서 멈춘다. scans_sent는 실제로 보낸 scan 목록이다. 다른 scan·쓰기·EM4x05·스니프 명령으로 더 나누지 않는다.
3. 반환된 family·variant·policy를 그대로 보고한다.
   - 감지된 계열(em410x·hidprox·ioprox·viking·pac·jablotron·pyramid)은 모두 refused다. 125 kHz 출입 자격증명이므로 더 조작하지 않는다. 원시 ID·FC/CN도 ID에서 만든 지문도 돌려주지 않으며(`identity_digest`는 항상 null) 사용자에게 다른 방법으로 ID를 읽거나 되살리자고 제안하지 않는다. 케이스 솔트 파일도 읽지 않는다.
   - 설계 §6.2의 "장난감·동물·시험용 태그" 사람 증명 예외는 아직 구현되지 않았다. 사용자가 장난감 태그라고 말해도 결과를 보고하고 멈춘다.
   - none은 일곱 scan이 모두 해독하지 못했다는 뜻이다. 카드가 없다는 증명이 아니다. firmware에 scan이 없는 계열(Indala·AWID·FDX-B 등)도 none이다. 배치를 확인한 뒤 같은 세션으로 다시 식별할 수 있다.
4. 교통·결제·출입·호텔·신분 자격증명은 policy와 관계없이 범위 밖이다.
5. 감지·none은 세션을 ready로 둔다. 고정 오류(잘못된 응답·mode 오류·timeout·취소)는 세션을 terminal로 만든다. 그러면 `nfc_cu_disconnect`로 정리하고 새로 연결한다. physical_same_tag_verified는 false, lf_field_off_by_firmware는 true(firmware 소스 경로이며 물리 측정이 아님)로 보고한다.
6. 결과는 아래 "정리와 요약"의 `nfc-analysis` 요약에 mode `cu-lf-identify`로 기록한다. 반환값의 profile·family·variant·policy·scans_sent·identity_digest(항상 null)·id_returned를 `lf_identifications`에 그대로 옮긴다(operation은 "cu-lf-identify"). identity_digest에 다른 값을 채우지 않는다. 같은 실행의 HF 식별 결과는 `identifications`, 상태 조회는 `device_status`에 함께 넣는다.

## CU 페이지 스냅샷 읽기

[스냅샷 계약](../../docs/references/cu-read-snapshot.md)을 읽고 실제 session_id와 tag_ref로 `nfc_cu_read_start`를 호출한다. 이 도구도 MODIFY 게이트를 따른다. `nfc_job_status`로 실제 job_id를 조회하고 필요하면 `nfc_job_cancel`로 취소한다. 작업 목록은 `nfc_jobs`로 확인한다.

`registered=true` 결과의 실제 artifact_id만 아래 parse/diff에 사용한다. 원장 기록 뒤 등록이 실패하면 파일·원장 receipt는 보존되지만 `registered=false`이며 분석 가능한 artifact로 꾸미지 않는다. snapshot은 원시 신원과 페이지를 담으므로 에이전트가 직접 열지 않는다.

미관찰 페이지는 null이다. 모든 페이지가 있어도 `read_complete=false`일 수 있으며 페이지 수로 완료를 추정하지 않는다. 사용자가 콘솔 전후 비교를 원하면 사람이 태그를 콘솔에 제시하고 완료를 알린 뒤 다시 읽는다. 같은 reader 프로필의 CU snapshot끼리만 비교하고 관찰된 변화가 콘솔 때문에 발생했다고 단정하지 않는다.

## 파일 검사와 비교

1. 일반 보유 파일은 `case_import_file(..., dest_subdir="nfc", kind="other")`로 가져오고 실제 artifact ID를 쓴다. Flipper 허용 폴더에 있으면 기존 `flipper_storage_pull_start`와 job 완료 결과의 artifact ID를 쓸 수 있다. 일반 파일 복사는 태그 읽기 출처나 inventory 증명이 아니다. `forensics/`·`emu/`·보호 상태를 복사해 우회하지 않는다.
2. 하나는 `nfc_parse_file(case_id, artifact_id, tag_ref)`, 둘은 시간 순서대로 `nfc_diff_dumps(case_id, before_artifact_id, after_artifact_id, tag_ref)`를 호출한다. 파일 하나는 최대1MiB, 두 파일 합은 최대2MiB다. UID·계열·비밀번호·키·정책 예외를 인자로 보내지 않는다.
3. `attestation_required`이면 기존 출처 질문을 설명하고 사람이 별도 터미널에서 `pweh attest <id>`로 답하게 한다. 에이전트는 사실을 대신 답하거나 증명을 만들지 않는다. 증명 후 같은 요청을 다시 호출한다. 가져온 파일의 두 SHA가 다르면 각각 증명이 필요하다. CU snapshot은 전용 device-read 원장을 검증하며 import 증명을 새로 만들지 않는다. imported와 CU snapshot의 혼합 비교는 거부한다. 도구가 최신 파일·스캔·증명을 다시 검사하므로 이전 성공을 강제로 재사용하지 않는다.
4. `report.status`, `inspection.coverage`, `inspection.limitations`와 반환된 분석 artifact를 함께 확인한다. 부분 읽기의 0값은 읽힌 페이지나 빈 비밀번호의 증거가 아니다. `same_uid_claim`은 기존 파일 선언 비교이며 `physical_same_tag_verified`는 false다. CU diff는 양쪽 관찰 페이지만 비교하고 양쪽 읽기·전체 비교가 완료되지 않으면 `stored_pages_equal=null`이다.

## 정리와 요약

이 Skill에서 Flipper 세션을 열었다면 성공·실패·취소 뒤 항상 `flipper_close`를 호출한다. CU 세션을 열었다면 같은 `case_id/session_id`로 `nfc_cu_disconnect`를 호출하고 cleanup 확인 결과를 보존한다. `cleanup_pending`이면 같은 close로 다시 확인한다. 자동 ETX·Enter·재접속이나 실패 뒤 임시 파일 삭제 명령을 보내지 않는다. 임시 파일 정리가 미확인이면 그 상태를 그대로 보고한다. host close는 장치 명령 종료·RF field off의 증거가 아니다.

`schema_get(name="nfc-analysis")`를 확인한 뒤 `case_record_step(skill="nfc-behavior-analysis", step="summary", ...)`로 실제 inventory와 검사 결과를 기록한다. inventory·파일 결과가 있으면 mode `scan-bound-offline`(tags 최소 1개)이고, CU 식별·상태만 했다면 mode `cu-hf-identify`로 `identifications`(최소 1개)와 선택 `device_status`를 넣고 tags·results는 빈 배열로 둔다. LF 식별만 했거나 LF 식별이 중심이면 mode `cu-lf-identify`로 `lf_identifications`(최소 1개)를 넣는다. 두 식별 mode 모두 다른 쪽 식별 배열과 `device_status`를 함께 넣을 수 있다. `scan-bound-offline` 요약에는 두 식별 배열을 넣지 않는다. tags를 꾸며 넣지 않는다. [reference.md](reference.md)의 필드 연결을 쓰며, 실제 수행한 단계만 success/partial로 정리한다. usable scan이나 분석 결과가 없는 오류는 `step="attempt"`에 고정 오류와 다음 조치를 기록하고 결과를 꾸미지 않는다.

`physical_same_tag_verified`, `tag_content_written`, `authentication_attempted`, `emulation_performed`는 false로 유지한다. 원래 읽기 완료도·미관찰 범위를 보존하고 스니프·게임 동작·해금 조건을 검증했다고 보고하지 않는다. read receipt는 일반 단계 기록이나 artifact 참조로 남기고 inspect/diff 결과로 넣지 않는다. CU의 reader CRC 성공은 host RF CRC 검산이나 진품·동일 실물 증명이 아니다. 취소 뒤에는 commit된 결과가 남을 수 있으므로 `case_get(include_artifacts=true)`로 확인하고, 최종 보고서는 `report_generate`로 만든다.

요약의 합성 예시이며, 실행 시 실제 반환값으로 채운다.

```json
{
  "schema": "pweh.nfc-analysis/v1",
  "mode": "scan-bound-offline",
  "tags": [{
    "tag_ref": "NT-00000000000000000000000000000000",
    "scan_ref": "NS-00000000000000000000000000000000",
    "family": "ntag213",
    "identity_digest": "sha256:0000000000000000"
  }],
  "results": [{
    "artifact_id": "A-0003",
    "path": "analysis/nfc-file-001.json",
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "operation": "inspect",
    "status": "ok",
    "tag_ref": "NT-00000000000000000000000000000000"
  }],
  "physical_same_tag_verified": false,
  "tag_content_written": false,
  "authentication_attempted": false,
  "emulation_performed": false
}
```

CU 식별·상태만 한 실행의 요약 합성 예시이며, 실행 시 실제 반환값으로 채운다.

```json
{
  "schema": "pweh.nfc-analysis/v1",
  "mode": "cu-hf-identify",
  "tags": [],
  "results": [],
  "identifications": [{
    "operation": "cu-identify",
    "profile": "cu-hf14a-identify-v2.3.0-v1",
    "family": "ultralight_or_ultralight_c",
    "policy": "attestation_required",
    "uid_length": 7,
    "ats_present": false,
    "get_version_sent": true,
    "page_reads_sent": false,
    "identity_digest": "sha256:0000000000000000"
  }],
  "device_status": {
    "battery_mv": 4000,
    "battery_percent": 80,
    "battery_percent_is_estimate": true,
    "active_slot": 0,
    "mode": "reader",
    "hf14a_config_default": true,
    "app_version": "2.3",
    "git_version": "v2.3.0",
    "model": "chameleon-ultra"
  },
  "physical_same_tag_verified": false,
  "tag_content_written": false,
  "authentication_attempted": false,
  "emulation_performed": false
}
```

CU LF 식별(과 상태 조회)만 한 실행의 요약 합성 예시이며, 실행 시 실제 반환값으로 채운다.

```json
{
  "schema": "pweh.nfc-analysis/v1",
  "mode": "cu-lf-identify",
  "tags": [],
  "results": [],
  "lf_identifications": [{
    "operation": "cu-lf-identify",
    "profile": "cu-lf125-identify-v2.3.0-v1",
    "family": "em410x",
    "variant": "em410x_64",
    "policy": "refused",
    "scans_sent": ["em410x_scan"],
    "identity_digest": null,
    "id_returned": false
  }],
  "device_status": {
    "battery_mv": 4000,
    "battery_percent": 80,
    "battery_percent_is_estimate": true,
    "active_slot": 0,
    "mode": "reader",
    "hf14a_config_default": true,
    "app_version": "2.3",
    "git_version": "v2.3.0",
    "model": "chameleon-ultra"
  },
  "physical_same_tag_verified": false,
  "tag_content_written": false,
  "authentication_attempted": false,
  "emulation_performed": false
}
```
