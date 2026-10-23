# 저장된 미디어 후보 한 단위의 추출

명시 exFAT partition/ref의 ValidDataLength 뒤 선택은 별도 [잔여 계약](exfat-residual-candidates.md)을 따른다.
잔여 source19필드와 전용 profile을 사용하며 아래의 기존 파일·EV 구간 계약은 유지한다.

`forensics_extract_media_unit(case_id, evidence_id, analysis_path, candidate_index)`는
같은 EV에 결속된 [미디어 단위 후보 보고서](media-unit-candidates.md)의 한 행을 추출하는
job이다. format·선택 파일·offset·길이·복구 방법·출력 이름을 새로 지정하지 않는다.

analysis_path는 같은 EV의 생성된 media-unit-candidates JSON, candidate_index는 저장된
0..127 중 존재하는 번호다. BMFF/DHAV/stream 보고서나 임의 JSON을 이 입구에 넘길 수 없다.
형식을 다시 추측하거나 scanner를 재실행하여 후보를 바꾸지 않는다.

## 입력 검증과 범위

소유/허가·EV 무결성 확인 후 유일한 후보 사건·전체 report SHA·엄격한 스키마·회계를
대조한다. report의 source/params/status는 그 사건과 같아야 한다. 형식/profile과
후보의 format/unit/종료 조건도 닫힌 조합으로 검사한다. 보고서1 MiB, 선택64 MiB,
manifest64 KiB, worker 전체45초 상한이다.

원래 파일/아카이브/ref·복구 방법 또는 명시 구간으로 선택 전체 bytes를 다시 읽어 SHA·
크기·출처를 대조한다. 구간은 원래 offset/length와 실제 EV 크기도 확인한다.
slice는 선택 상대 candidate.offset/length뿐이다. source.offset을 다시 더하지 않는다.
기존 BMFF/DHAV 재선택의 기본 하한은 그대로이며 새 형식의 검증된 최소 선택만 따로 적용한다.

| 형식 | 최소 선택 / 단위 bytes | 추출 근거 |
|---|---|---|
| JPEG | 28 / 28 | EOI를 포함한 baseline 단일 scan 경계 |
| AVC Annex B | 8 / 4 | 다음 시작 표지·header로 닫힌 NAL, type10/11은 header-only 가능 |
| MPEG-2 PS | 24 / 24 | 길이 검사를 마친 pack prefix, 부분 상태 보존 |
| XM | 9 / 9 | 양수 선언 길이의 header+payload |

이는 parser subset의 하한이지 모든 실제 미디어의 최소 크기 정의가 아니다.
JPEG/AVC의 열린 tail은 후보가 아니며 PS는 검증된 prefix만 추출할 수 있다.

## 출력과 보관 기록

출력은 `forensics/recovered/media-unit-NNN/unit-000.bin` 및 `manifest.json` 두 파일이다.
파일0444/디렉터리0555이며 원래 이름·권한·경로를 복사하지 않는다. manifest schema는
`pweh.media-unit-extract/v1`, method는 media_unit이다. 원래 format/source_profile,
source/status/coverage, 선택한 candidate, 분석 경로·SHA·custody seq/hash를 보존한다.

단위 bytes를 최대64 KiB씩 쓰고 실제 파일 SHA를 확인한다. 동일 custody 잠금 안에서
EV·report·원래 사건·출력 fd/부모/이름/전체 해시·정확한 두 파일 tree를 재확인한다.
마지막 취소·deadline 검사 뒤 기존 `extract` 사건에 method=media_unit으로 결속한다.
보고서 FD와 EV FD는 이 커밋까지 유지된다.

커밋 전 취소/실패는 확인된 자기 inode만 정리한다. 교체물·알 수 없는 추가 파일은 지우지
않고 정리 불완전 오류를 남긴다. 커밋 뒤 job을 mark_committed한 다음 보조 감사를 남기며
늦은 취소·보조 오류는 저장 결과를 되돌리지 않는다. 호출을 기다리던 작업의 취소와
forensics_job_cancel에 의한 job 취소는 구분한다. 같은 EV의 추출은 공통 독점 키를 사용한다.

## 결과 해석과 요약

files[0].complete=true는 지정 bytes를 모두 썼다는 뜻이다. 원래 source의 complete나
candidate.framing_status, 전체 파일·녹화·재생 검증과 바꾸어 읽지 않는다.
원래 partial·선택 불확실성·컨테이너 목록 미완료와 새 선택의 불확실성은 보존한다.
PS prefix 또는 원래 partial을 완전 녹화로 바꾸지 않는다.

응답은 job이며 완료 후 생성 경로·해시·크기·status·보관 기록 참조와 고정 경고만 받는다.
원시 단위·header·영상·오디오는 반환하지 않는다. 에이전트는 추출물을 직접 열지 않는다.
사람이 자기 플레이어로 확인하더라도 이 도구가 재생을 검증한 것으로 기록하지 않는다.

SD 요약은 기존 recovered·notes를 사용하며, 증거 목록의 derived에서 manifest/custody 결속을
확인한다. derived의 recorded는 이후 binary 전체를 다시 해시했다는 뜻이 아니다.
후보 보고서의 고정 false 검증 필드는 manifest에서도 유지한다. 조각 재조립·시각·채널·
암호화·원본 파일 경계·전체 형식 적합성은 검증하지 않는다.
