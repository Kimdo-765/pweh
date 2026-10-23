# 저장된 DHAV 후보 한 record의 추출

`forensics_extract_dhav_candidate(case_id, evidence_id, analysis_path, candidate_index)`는
`forensics_dhav_candidates`가 저장한 구조 후보 한 개의 바이트를 파생 파일로 만든다.
`analysis_path`는 후보 분석 응답의 `analysis.path`, `candidate_index`는 해당 보고서에
실제로 있는 정수 0–127이다. 항상 job으로 실행하며 `forensics_job_status`로 완료를 확인하고
`forensics_job_cancel`로 취소한다.

큰 EV의 [`forensics_dhav_scan`](dhav-scan.md) 보고서는 직접 받지 않는다. 그 row의 절대
offset/record_length로 같은 EV의 `forensics_dhav_candidates` 구간 검사를 먼저 수행하고,
새 후보 보고서의 analysis.path/번호를 전달한다.

## 선택과 출처

같은 EV의 유일한 `dhav-candidates` 보관 사건과 결속된 보고서만 받는다. 보고서 전체의
해시·크기·닫힌 스키마·수치와 완료 관계를 확인한다. 일반 파일 등록이나 경로 일치만으로
입력을 신뢰하지 않는다. 기존 BMFF 후보 보고서는 받지 않는다.

원래의 완전한 선택 파일 또는 명시 EV 구간을 다시 읽어 전체 선택 SHA-256·크기·선택 신원을
대조한다. FAT/exFAT는 저장된 ref·파티션·구체 복구 방법을 사용하고 TAR/ZIP는 같은 멤버를
읽는다. 구간은 저장된 offset·길이와 EV 크기까지 대조한다. 새 범위·복구 방법·출력 이름을
지정하는 인자는 없다. 후보 검색을 다시 실행하거나 주변 record를 합치지 않는다.

추출 범위는 선택 bytes의 `[candidate.offset, candidate.offset + record_length)`다.
offset은 선택 상대이며, 이미 읽은 EV 구간에 source.offset을 다시 더하지 않는다.
비연속 클러스터·삭제 복구·아카이브의 논리 위치를 카드의 물리 위치로 해석하지 않는다.

후보의 `confidence=possible`은 유지한다. 원래 source/status/coverage와 재선택 때의
불확실성을 합쳐 보존하며, 원래 partial이거나 유효 불확실성 두 값 중 하나가 true이면
추출 결과도 partial이다. 완전한 record 복사가 이전의 미검사 범위를 없애지 않는다.

## 출력과 보관 기록

새 `forensics/recovered/dhav-record-NNN/`에 `record-000.bin`과 `manifest.json`만 만든다.
파일은 0444, 디렉터리는 0555다. 응답은 생성 경로·해시·크기·상태를 주고 본문은 반환하지
않는다. 에이전트는 추출물을 직접 열지 않는다.

매니페스트 스키마는 `pweh.dhav-record-extract/v1`, method는 `dhav_record`다.
원래 source·candidate·source_status·source_coverage, 보고서의 path/sha256/size/custody_seq/
custody_hash와 유효 선택·컨테이너 불확실성을 기록한다. `files[0].sha256`은 추출 record의
해시이며 전체 선택 bytes 해시 및 접수 때의 EV 해시와 구별한다.

`files[0].complete=true`는 지정 record_length의 복사 완료다. payload 의미·extension 내부·
checksum·미디어 해독·재생·녹화 시각·암호화·원본 파일 경계·완전 녹화 검증의 9개 값은
모두 false다. 원시 시각·채널·본문은 바이너리에 남지만 JSON·오류·감사·job에는 공개하지 않는다.

기존 `extract` 사건의 method로 결속한다. 같은 custody 잠금에서 EV와 보고서의 열린 FD,
부모·이름·해시, 원래 사건, 정확히 두 출력 파일과 그 전체 해시를 최종 대조한다.
커밋 전 실패·취소·시간 초과는 부분 산출물을 성공으로 게시하지 않는다. 확인한 자기 inode만
정리하며 교체물이나 알 수 없는 항목은 보존하고 `cleanup_incomplete`로 알린다.
커밋 뒤 늦은 취소·보조 기록 실패는 기록한 출력을 지우지 않는다.

`forensics_evidence_list.derived`의 recorded는 매니페스트와 보관 사건의 결속이다.
목록 호출이 추출 바이너리를 다시 전체 해시한 보증은 아니다. 요약에는 기존 `recovered`의
파일 수·바이트·매니페스트를 합산하고 부분성과 미확인 사항을 `notes`에 쓴다.
`dhav_candidate_results`는 후보 분석 참조로 유지하며 새 요약 배열을 만들지 않는다.

## 한도와 해석

| 항목 | 고정 한도 |
|---|---|
| 보고서 | 1 MiB, 엄격한 UTF-8 JSON·중복 키/비유한 수 거부 |
| 완전한 선택 입력 | 33 bytes–64 MiB |
| 출력 record | 저장된 후보 한 개, 33 bytes–64 MiB |
| 매니페스트 | 64 KiB |
| 작업 시간 | worker 시작부터 같은 45초 마감 |
| 읽기·쓰기·해시 조각 | 최대 64 KiB |

마감은 협력적으로 검사하며 전체 RSS나 커널 I/O의 강제 시간 제한은 아니다. 같은 OS 계정이
최종 검사 직후 파일을 바꿀 가능성도 공통 한계다. 이 기능은 구조 후보 하나의 출처 결속
복사이며 DHAV 전체 지원·카드 전체 카빙·조각 재조립·영상 복구나 재생 검증을 뜻하지 않는다.
지원하는 고정 record subset과 판정 근거는 [후보 분석 계약](dhav-candidates.md)을 따른다.
