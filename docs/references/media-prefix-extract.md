# 저장된 미디어 후보의 prefix 추출

`forensics_extract_media_candidate(case_id, evidence_id, analysis_path, candidate_index)`는
`forensics_media_candidates`가 저장한 후보 하나의 검증된 연속 앞부분(prefix)을 파생 파일로 만든다.
`analysis_path`는 앞 도구가 반환한 `analysis.path`, `candidate_index`는 그 보고서의 후보 번호다.
항상 작업을 시작하며 기존 `forensics_job_status`·`forensics_job_cancel`로 확인·취소한다.

## 입력과 출처

같은 케이스·EV의 보관 기록 `media-candidates` 사건이 유일하게 결속한 보고서만 받는다.
보고서의 전체 해시·크기·스키마·후보 범위를 검사하고, 같은 EV 파일 기술자에서 원래 선택 파일을
실제 ref·파티션·복구 방법으로 다시 읽어 선택 바이트 전체의 해시·크기·출처를 대조한다.
명시 EV 구간 보고서는 저장된 offset/length 전체를 다시 읽어 구간 해시와 EV 크기까지 대조한다.
구간 source의18필드를 그대로 보존하며 기존 파일 source16필드와 섞지 않는다.
새 offset·length·ref·path·복구 방법을 입력하는 인자는 없다. 후보 탐색도 다시 실행하지 않는다.

위치는 선택 파일 또는 구간의 바이트 기준이다. EV 구간에서만 source.offset을 더해 이미지 내
위치를 구하며, 실제 추출은 이미 읽은 구간 bytes에 후보 상대 위치만 적용한다. 비연속 클러스터나 삭제 파일의 복구 방법으로 구성한 바이트를
EV의 물리 주소나 원래 녹화 경계로 해석하지 않는다. 예전 보고서의 상태·검사 범위는 그대로
보존하며, 재선택 때 관찰한 불확실성도 합쳐 결과가 더 확실한 것으로 바뀌지 않게 한다.

## 출력과 커밋

출력은 새 `forensics/recovered/media-prefix-NNN/` 안의 `candidate-000.bin`과
`manifest.json` 두 파일뿐이다. 원래 이름이나 MP4 확정 이름을 쓰지 않는다.
파일은 0444, 디렉터리는 0555다. 응답은 경로·해시·크기·상태만 주며 내용은 반환하지 않는다.
에이전트는 추출물을 직접 열지 않는다.

매니페스트 스키마는 `pweh.media-prefix-extract/v1`이다. 원래 보고서의
`analysis{path,sha256,size,custody_seq,custody_hash}`, `source`, `candidate`,
`source_status`, `source_coverage`와 유효 불확실성 두 값을 기록한다.
`files[0].complete=true`는 요청한 prefix를 전부 썼다는 뜻이며 녹화 전체 복구 성공이 아니다.
영상·음성 해독, 재생, 녹화 시각, 암호화, 표준 적합성, 원본 경계, 완전한 녹화의 검증 값은 false다.

기존 `extract` 사건의 `method="media_candidate_prefix"`로 보관 기록에 결속한다.
같은 보관 기록 잠금 안에서 EV·입력 보고서·원래 사건·출력 이름/부모/파일 기술자/해시를 다시 확인한다.
커밋 전 실패는 확인한 자기 inode만 정리하며, 바뀌었거나 모르는 항목은 보존하고 정리 한계를 알린다.
커밋 뒤 취소·보조 기록 오류는 이미 기록한 출력을 지우지 않는다.

`forensics_evidence_list.derived`의 `recorded`는 매니페스트와 `extract` 사건의 해시가 맞는다는
뜻이다. 목록을 부를 때 추출 바이너리를 전체 재해시했다는 뜻은 아니다.
요약에는 기존 `recovered`의 파일 수·바이트·매니페스트를 쓰고, 불완전 상태와 한계는 `notes`에 적는다.

## 한도와 범위

| 항목 | 고정 한도 |
|---|---|
| 후보 번호 | 정수 0–127, 보고서에 실제 존재하는 번호만 |
| 보고서 | 1 MiB, 엄격한 UTF-8 JSON·중복 키/비유한 수 거부 |
| 재선택 입력·출력 | 완전히 읽은 최대64 MiB 파일 또는 명시 EV 구간, 후보 prefix 한 개 |
| 매니페스트 | 64 KiB |
| 작업 시간 | worker 시작부터 같은45초 마감, 모든 단계가 공유 |
| 쓰기·해시 조각 | 최대64 KiB |

일부만 쓴 prefix는 성공으로 남기지 않는다. 전체 prefix를 썼어도 원래 후보 탐색·복구·부모 상태·
컨테이너 목록이 불완전하면 결과 상태는 `partial`일 수 있다.
파일 크기·협력적 마감은 전체 RSS나 커널 I/O의 강제 시간 상한이 아니다.
같은 OS 계정의 최종 검사 직후 변경 가능성은 공통 한계다.

명시 구간의 입력·좌표·완료도는 [구간 계약](media-evidence-range.md)을 따른다.
이 기능은 저장된 후보의 바이트 추출이다. 원시 카드 전체 카빙, 벤더 인덱스 복구,
영상·음성 재생 가능성이나 완전한 녹화 복구를 검증하지 않는다.
