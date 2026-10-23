---
name: nfc-behavior-analysis
description: 소유·허가된 PWEH 케이스에서 Flipper 또는 ChameleonUltra의 고정 NTAG213/215/216 스캔을 inventory에 등록하고 같은 태그 식별값에 결속된 NFC 파일의 구조·저장 페이지 차이를 검사한다. NFC 파일 분석, NTAG inventory, 두 덤프 비교에 사용한다. 기존 스캔 참조를 재사용할 수 있으며 태그 전체 덤프·쓰기·인증·에뮬레이션은 수행하지 않는다.
---

# 스캔 기록에 결속한 NFC 파일 분석

현재 지원 범위는 NTAG213/215/216의 서버 스캔 기록과 보유 파일의 저장 표현 검사다. Skill 이름의 “동작”을 실제 콘솔 반응·게임 해금·실물 진품 확인으로 해석하지 않는다. [입구 계약](../../docs/references/nfc-inventory-analysis.md)과 기존 [파일 프로필](../../docs/references/nfc-file-profile.md)을 따른다.

## 준비와 스캔

1. `case_get`으로 소유·허가된 케이스를 확인하고 `case_get_step_results`로 이전 결과를 읽는다. 이미 확인한 허가를 다시 묻지 않는다. 케이스가 없으면 `pweh-start`의 접수를 따른다. 태그와 reader가 허가 범위에 포함되어야 한다.
2. 같은 케이스의 실제 `scan_ref` 또는 `tag_ref`가 있으면 재사용한다. 사용자 UID·파일의 선언·producer 표기로 스캔을 대신하지 않는다. 기존 inventory 파일만 분석하면 장비 연결을 요구하지 않는다.
3. 새 스캔이 필요하면 명시된 Flipper 포트와 공식1.5.1 호환성을 확인하고 `flipper_connect`를 호출한다. 허용 루트 `/ext/pweh/<case_id>/`는 사용자가 미리 준비한다. 포트 열기는 DTR 변경을 포함한다. 필요한 물리 연결·태그 배치는 사람이 하고 완료를 확인한 뒤 진행한다.
4. `flipper_nfc_probe(case_id)`로 고정 SELECT·GET_VERSION을 수행한다. 이 작업은 Flipper SD에 작은 임시 파일을 만들고 제거하므로 MODIFY다. 페이지 READ나 태그 메모리 쓰기는 하지 않는다. 정상 응답의 실제 `scan_ref`만 `nfc_tag_inventory_add`에 전달하고 반환 `tag_ref`를 보존한다.
5. `approval_required`이면 반환 id와 영향을 설명하고 사람이 별도 터미널에서 `pweh approve <id>`로 승인한 뒤 같은 인자와 `approval_id`로 재호출한다. 에이전트가 승인 명령을 실행하지 않는다. `denied`·지원 밖 계열은 우회하지 않으며 raw 명령·다른 앱으로 대신하지 않는다.

CU Ultra를 사용하는 새 스캔은 [CU 계약](../../docs/references/cu-ntag-read-provider.md)을 따른다. 허가된 reader의 명시 포트로 `nfc_cu_connect(case_id, port)`를 호출하고 실제 반환한 `session_id`로 `nfc_cu_scan(case_id, session_id)`을 호출한다. 두 도구는 MODIFY 게이트를 적용하며 위 승인 규칙을 따른다. CU는 현재 reader 모드의 고정2.2만 받으며 mode/slot을 변경하지 않는다. scan은 GET_VERSION과 READ0/1의 UID/BCC를 확인하고, 실제 scan_ref를 같은 `nfc_tag_inventory_add`로 등록한다. 공개 전체 태그 읽기나 파일 생성 도구는 없다.

## 파일 검사와 비교

1. 일반 보유 파일은 `case_import_file(..., dest_subdir="nfc", kind="other")`로 가져오고 실제 artifact ID를 쓴다. Flipper 허용 폴더에 있으면 기존 `flipper_storage_pull_start`와 job 완료 결과의 artifact ID를 쓸 수 있다. 일반 파일 복사는 태그 읽기 출처나 inventory 증명이 아니다. `forensics/`·`emu/`·보호 상태를 복사해 우회하지 않는다.
2. 하나는 `nfc_parse_file(case_id, artifact_id, tag_ref)`, 둘은 시간 순서대로 `nfc_diff_dumps(case_id, before_artifact_id, after_artifact_id, tag_ref)`를 호출한다. 파일 하나는 최대1MiB, 두 파일 합은 최대2MiB다. UID·계열·비밀번호·키·정책 예외를 인자로 보내지 않는다.
3. `attestation_required`이면 기존 출처 질문을 설명하고 사람이 별도 터미널에서 `pweh attest <id>`로 답하게 한다. 에이전트는 사실을 대신 답하거나 증명을 만들지 않는다. 증명 후 같은 요청을 다시 호출한다. 두 SHA가 다르면 각각 증명이 필요하다. 도구가 최신 파일·스캔·증명을 다시 검사하므로 이전 성공을 강제로 재사용하지 않는다.
4. `report.status`, `inspection.coverage`, `inspection.limitations`와 반환된 분석 artifact를 함께 확인한다. 부분 읽기의 0값은 읽힌 페이지나 빈 비밀번호의 증거가 아니다. `same_uid_claim`은 파일 선언 비교이며 `physical_same_tag_verified`는 false다.

## 정리와 요약

이 Skill에서 Flipper 세션을 열었다면 성공·실패·취소 뒤 항상 `flipper_close`를 호출한다. CU 세션을 열었다면 같은 `case_id/session_id`로 `nfc_cu_disconnect`를 호출하고 cleanup 확인 결과를 보존한다. `cleanup_pending`이면 같은 close로 다시 확인한다. 자동 ETX·Enter·재접속이나 실패 뒤 임시 파일 삭제 명령을 보내지 않는다. 임시 파일 정리가 미확인이면 그 상태를 그대로 보고한다. host close는 장치 명령 종료·RF field off의 증거가 아니다.

`schema_get(name="nfc-analysis")`를 확인한 뒤 `case_record_step(skill="nfc-behavior-analysis", step="summary", ...)`로 실제 inventory와 검사 결과를 기록한다. [reference.md](reference.md)의 필드 연결을 쓰며, 실제 수행한 단계만 success/partial로 정리한다. usable scan이나 분석 결과가 없는 오류는 `step="attempt"`에 고정 오류와 다음 조치를 기록하고 결과를 꾸미지 않는다.

`physical_same_tag_verified`, `tag_content_written`, `authentication_attempted`, `emulation_performed`는 false로 유지한다. 태그 전체 읽기·스니프·게임 동작·해금 조건을 검증했다고 보고하지 않는다. CU의 reader CRC 성공은 host RF CRC 검산이나 진품·동일 실물 증명이 아니다. 취소 뒤에는 commit된 결과가 남을 수 있으므로 `case_get(include_artifacts=true)`로 확인하고, 최종 보고서는 `report_generate`로 만든다.

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
