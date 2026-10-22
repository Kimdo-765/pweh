# 저장 파일 목록의 비밀값 자동 검사

`forensics_scan_secrets_from_list`는 같은 EV의 저장 FAT/exFAT 파일 목록에서 검사할 파일을
자동 선정하고, 기존 UTF-8 비밀값 패턴을 적용한다. 파일별 후보와 함께 목록 누락, 정책 제외,
처리 한도로 읽지 못한 항목을 보고한다. 원래 파일명·경로·시각·키·값·본문은 결과에 복사하지 않는다.

## 입력과 사용 순서

먼저 `forensics_fs_list`로 목록을 만든 뒤 응답의 `result_path`를 전달한다.

```text
forensics_scan_secrets_from_list(
    case_id="<id>", evidence_id="EV-0001",
    fs_list_path="forensics/analysis/fs-list-EV-0001-001.json"
)
```

| 인자 | 의미 |
|---|---|
| case_id / evidence_id | 소유·허가와 무결성 입구를 통과한 케이스/EV |
| fs_list_path | 같은 EV의 유일한 `list` 보관 사건에 해시로 결속된 전체 JSON |
| partition=None | 저장 목록 안의 모든 지원 FAT/exFAT 볼륨. 정수로 지정하면 해당 볼륨만 선택 |
| xor_key=None | 기본 UTF-8 보기. 근거가 있을 때 정수144를 명시해 0x90 보기만 검사 |
| max_seconds=45 | 0 초과·45초 이하의 유한한 수. 목록 읽기·선정·파일 읽기·검사의 공통 시간 |

목록 생성 시 이미 파티션을 제한했다면 그 밖을 새로 탐색하지 않는다. 표본20개, 임의 JSON,
TAR/ZIP 목록은 이 도구의 입력이 아니다. 입력 JSON은 최대16 MiB이며 깊이·노드·문자열 한도도
적용한다. 목록 생성 도구의 최대256 MiB와 다르다. 한도를 넘으면 파티션이나 항목 한도를 줄여
목록을 다시 만들고, 그 목록에 생긴 누락을 그대로 보고한다.

한 파일을 직접 지정하거나 TAR/ZIP 멤버를 검사할 때는 기존 `forensics_scan_secrets`를 쓴다.

## 자동 선정과 상한

저장된 볼륨·항목 순서로 regular file을 분류한다. 기존 영상·음성 확장자, 실제 데이터가 없는
파일, 데이터가4 MiB를 넘는 파일을 각각 `media_name`, `empty_data`, `file_too_large`로 제외한다.
그 외 파일은 검사 대상 후보(eligible)이며 아직 텍스트로 확인된 것은 아니다.

| 한도 | 범위 |
|---|---|
| 파일당4 MiB | FAT 파일 크기 또는 검증된 exFAT ValidDataLength |
| 최대32파일·합16 MiB | 순서대로 예정한 데이터 길이. 다음 파일이 넘으면 거기서 중단 |
| 총200후보 | 저장한 모든 파일의 마스킹 후보 합계 |
| 파일별128범위·24 KiB | 기존 scanner 결과의 낮춘 범위/출력 상한 |
| 최종 JSON1 MiB | 출처·집계·파일별 결과와 마지막 개행 포함 |

전체 저장 목록의 분류를 먼저 끝내므로 상한 뒤에 남은 eligible 파일 수도 보고한다. 읽기에
실패한 파일 대신 뒤의 파일을 추가 선정하지 않는다. 파일 시스템 metadata 접근·목록 해시
재검증까지 합쳐 물리 I/O가16 MiB라는 뜻은 아니다.

실제 파일을 루트에서 다시 찾아 도달성과 목록 metadata를 확인하고 완전한 복구 계획만 읽는다.
삭제 파일은 실제 복구 방법·신뢰도를 남긴다. exFAT의 예약 공간(DataLength)과 데이터 길이를
구분하고 ValidDataLength 뒤 잔여는 검사하지 않는다. 원래 부모 삭제 상태가 미확인이면 그
불확실성을 보존한다. 일부만 읽은 바이트는 scanner에 넘기지 않는다.

## 결과를 읽는 방법

응답의 `ok`는 호출 성공이고 `report.status`가 `ok`, `partial`, `unsupported` 검사 상태다.
보고서는 `pweh.secrets-survey/v1`, profile은 `fat-exfat-listed-text-v1`이다.

| 결과 부분 | 해석 |
|---|---|
| source | EV 접수 SHA와 입력 목록의 경로·전체 SHA·크기·보관 사건 seq/hash |
| listing | 원래 목록의 완료도, 파티션 범위, 실패·미검사 볼륨·디렉터리 누락 |
| selection | 정책 제외, eligible·예정·보류 파일 수/바이트, exFAT 잔여 미검사 |
| coverage | 시도·완전 읽기·실패·미시도, 패턴 검사 완료·부분·미지원, 읽은/검사한/미검사 바이트 |
| files | 최대32개 참조와 완전 선택 SHA·크기·방법·신뢰도, 마스킹 scanner 결과 또는 고정 실패 사유 |
| summary | 저장 후보 수·종류별 수·솔트 지문 중복 제거 수와 검사 범위에 한정된 결과 |
| analysis | 저장 결과의 path/sha256/size/custody_seq/custody_hash |

`selection.complete`는 목록의 정책 분류 완료다. `coverage.analysis_complete`는 eligible
전체의 지원 패턴 검사 완료만 뜻한다. 정책 제외·목록 밖·미할당 영역·잔여 공간까지 확인했다는
뜻이 아니며 `whole_card_examined`는 항상false다. `eligible_files_unread`에는 보류·미시도·읽기
실패가 포함된다. 실패한 읽기가 실제0바이트였다는 뜻은 아니므로 완전 읽기 합계는
`read_complete_bytes`로 구분한다.

후보0건, `no_eligible_files`, `no_text_examined`, `no_candidates_in_examined_scope`는 비밀 없음이나
카드 안전을 증명하지 않는다. UTF-8/BOM, 기존 고정 패턴,16 KiB 이하 줄만 지원하며 미디어·바이너리·
지원하지 않는 인코딩은 미검사로 남긴다. 후보의 케이스 솔트 지문은 자격증명 유효성 검증이 아니다.

## 보관 기록과 실패 경계

목록을 readonly 일반 파일로 한 번 열고 같은 EV의 보관 사건·전체 SHA와 대조한다. 마지막
custody 잠금 안에서도 열린 목록의 전체 SHA, 이름·부모·파일 신원, 원래 사건과 EV/출력 신원을
확인한다. 결과 JSON 하나를0444로 저장하고 `secrets-survey` 사건에 해시를 결속한다.
목록의 원문 경로나 파일 내용은 보관 사건에도 복사하지 않는다.

목록 읽기·분류가 시간 안에 끝나지 않으면 결과를 만들지 않는다. 선정 후 시간·후보 상한에
닿으면 정확한 미검사 범위와 부분 결과를 기록할 수 있다. 이 기록에 필요한 최종 목록 재해시는
최대16 MiB를64 KiB씩 읽으며, 검사 시간 만료 뒤에도 취소·신원 검사를 유지해 완료한다.
따라서 결과 저장까지 벽시계45초로 제한된다는 뜻은 아니다.

목록/EV 무결성 문제와 알려진 파일 metadata 모순은 전체 실패다. 제한된 도달성 검증이나
불완전 읽기는 파일별 미검사로 남는다. 커밋 전 실패·취소는 자기 출력만 정리하고 커밋 뒤 늦은
취소·보조 색인 오류는 이미 기록한 결과를 보존한다. 같은 OS 계정의 최종 확인 이후 조작까지
막는 경계는 아니며 접수 SHA 표시는 EV 전체를 매번 새로 재해시했다는 뜻도 아니다.

## SD 요약

`secret_survey_results[]`에 아래 값만 옮기고 `privacy.secret_plaintext_returned=false`를 유지한다.

| 요약 필드 | 응답 출처 |
|---|---|
| evidence_id | report.source.evidence_id |
| analysis_path / analysis_sha256 | analysis.path / analysis.sha256 |
| fs_list_path | report.source.fs_list.path |
| status | report.status |
| files_scheduled | report.selection.scheduled_files |
| files_read_complete / eligible_files_unread | report.coverage의 같은 필드 |
| hits | report.summary.hits |
| scanned_bytes / unscanned_read_bytes / whole_card_examined / reasons | report.coverage의 같은 필드 |

목록·정책 제외·불확실성의 세부 내용은 결과와 `notes`에 보존한다. 별도 Skill/phase는 만들지
않으며 복구한 자격증명으로 로그인하지 않는다. [개발 계약](../architecture.md#68-pweh-forensics-선택),
[증거 분석 한계](../safety.md#36-sd-카드-증거의-알려진-한계-pweh-forensics),
[SD Skill 참고](../../skills/sd-card-forensics/reference.md#15-저장-목록의-자동-비밀값-검사)를 따른다.
