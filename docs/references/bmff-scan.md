# EV 바이트의 BMFF 스트리밍 prefix 검색

`forensics_bmff_scan(case_id, evidence_id, start_offset=0, max_scan_bytes=1073741824,
max_seconds=45)`는 접수된 EV의 같은 읽기 전용 fd에서 ftyp 시작점과 연속 최상위 상자
prefix 후보를 찾는다. 큰 이미지 전체를 메모리에 올리지 않는다. 검색한 후보는 기존
구간 후보 검사와 prefix 추출에 연결하며, 파일 시스템의 할당 상태나 원본 파일 경계는
판정하지 않는다.

## 입력과 예산

케이스 소유/허가·접수/보관 기록·EV 무결성 확인 뒤에만 실행한다. 원시 디스크나 파일
경로를 받지 않는다. ref/path/partition/복구 method도 없으며 실제 파일·아카이브 멤버의
선택 분석은 기존 `forensics_media_candidates`가 맡는다.

| 항목 | 기본·고정 상한 |
|---|---|
| EV 크기 | 1..2^63−1 bytes |
| start_offset | 정수 0..EV 크기, 기본0 |
| max_scan_bytes | 정수 8..1 GiB, 기본1 GiB |
| max_seconds | 유한 양수, 최대45초 |
| 검색 읽기 | 창≤64 KiB, 연속 읽기 합계≤max_scan_bytes |
| 별도 구조 읽기 | 호출 전체≤1 MiB |
| anchor probe / 후보 | 1024 / 128 |
| 상자 | anchor당1024 / 호출 전체8192 |
| brand 검사 | anchor당64 / 호출 전체4096 |
| 후보 prefix / JSON | 64 MiB / 1 MiB |

8byte 상자 헤더의 창 경계를 위해 마지막7bytes를 메모리에 유지한다. 같은 호출에서
overlap을 다시 읽거나 검색 예산 뒤를 미리 읽지 않는다. 구조 검사는 별도 예산을 써서
검색창 밖의 header/brand도 EV 안이면 읽을 수 있다. 이 읽기를 검색 완료 위치에 더하지
않으며 상자·brand·구조 예산을 창이나 anchor마다 초기화하지 않는다.
접수 지문·보관 기록 등 공통 무결성 확인의 I/O는 이 검색 회계와 별개다.

[기존 BMFF 후보](media-candidates.md)의 header/brand/연속 상자 검사를 재사용한다.
큰 mdat 본문은 선언 길이로 건너뛰고 다음 header만 확인한다. 검색 창 자체는 payload
bytes도 지나므로 본문 bytes를 전혀 읽지 않는 기능으로 설명하지 않는다. 내용 의미나
프레임·음성을 해독하지 않는다.

## prefix 경계

후보 길이는 검증한 **완전한 상자들의 연속 prefix**다. 다음 상자를 포함하면64 MiB를
넘는 경우 그 상자의 일부를 넣지 않고 직전 상자까지 partial로 남긴다. 첫 ftyp부터
상한을 넘으면 후보 행을 만들지 않고 제한된 anchor로 센다. 정확히64 MiB는 허용한다.

size0을 EV의 남은 bytes로 확장하지 않는다. 첫 ftyp의 size0은 기각하며, 후속 상자의
size0은 이미 검증한 prefix의 partial 종결이다. EV 끝에 닿아도 원래 파일의 EOF가
확인된 것은 아니다. 다음 ftyp, 미지원/손상된 다음 상자, 한도로 못 본 chain을 구분한다.

## 보고서와 완료 의미

schema는 `pweh.bmff-scan/v1`, profile은 `ftyp-stream-prefix-v1`이다.

- source는 kind=evidence, evidence_id, evidence_sha256, evidence_size 네 필드다.
  SHA는 접수 해시이며 이번 호출의 전체 EV 재해시나 후보 bytes의 해시가 아니다.
- params는 start_offset/max_scan_bytes/max_seconds 세 필드다.
- 후보 행은 index, offset, validated_prefix_length, boxes_validated, box_counts,
  known_brands, end_reason, framing_status, confidence, complete_recording이다.
  offset은 **EV 절대 상자 헤더 위치**이고 confidence는 possible이다. 고정 분류만
  반환하며 원시 type/brand/UUID·시각·본문·개별 prefix 해시는 반환하지 않는다.
- status는 ok/partial/unsupported다. 한도·시간·불완전 framing이 있으면 partial이다.
  검사 범위에서 후보가 없다는 unsupported는 미디어 부재 판정이 아니다.

coverage의 검색 위치는 EV 크기 N에 대해 `[0,max(0,N−7))`다. 시작 위치 앞의 수,
처리한 연속 prefix의 수, 미처리 tail의 수를 분리한다. 미리 읽은 bytes나 구조 조회가
더 멀리 도달했다는 이유로 처리 완료 prefix를 늘리지 않는다.

`next_offset`은 그 미처리 tail의 시작이며 끝까지 처리했으면 null이다. 다음 호출의
start_offset에 그대로 사용한다. 예산 끝의7bytes는 다음 호출에서 다시 읽을 수 있다.
아직 ftyp 검사가 끝나지 않은 anchor는 pending으로 그 위치에 남긴다. 이미 유효 prefix
행을 얻은 뒤 chain 한도가 끝나면 그 행을 partial로 보고하고 다음 시작점으로 진행한다.
이때 미완료 chain이 완료된 것은 아니며 기본 재개에서 같은 행을 다시 만들지 않는다.

`search_complete`는 요청 시작 이후의 검색 완료다. start_offset=0인 한 호출이 전체
가능한 시작 위치를 처리했을 때만 `whole_evidence_search_complete=true`다.
`candidate_checks_complete`는 관찰한 anchor의 제한 검사 완료이고,
`candidate_list_complete`는 요청 시작 이후의 검색·검사·목록 완료다. 이 값들과 행의
framing_status는 별개다. 여러 보고서를 자동 합쳐 전체 완료로 승격하지 않는다.

media_decoded, playback_verified, recording_time_verified, encryption_assessed,
format_conformance_assessed, original_file_boundary_verified, physical_carving_performed와 relations_assessed는
모두 false다. 각 후보의 complete_recording도 false다. 후보 사이 포함·중첩 관계도 이 stream 보고서에서
평가하지 않는다. 복구율·재생·녹화 길이·시각·암호화·조각 연결을 확인한 결과가 아니다.

## 기존 구간 검사와 추출로 연결

목적에 필요한 행 하나를 골라 다음 세 단계를 따른다.

1. scan 행의 offset=A, validated_prefix_length=L을 같은 EV의
   `forensics_media_candidates(offset=A, length=L)`에 전달한다.
2. 새 구간 보고서가 선택 전체 SHA·EV 크기/시작·길이를 결속하면, 그 보고서에 실제로
   존재하는 candidate_index를 고른다. 새 후보 offset은 **구간 상대**다.
3. `forensics_extract_media_candidate`에 새 구간 보고서의 analysis.path와 후보 번호를
   전달한다. job 완료를 확인하고 recovered·notes·증거 목록에 남긴다. 추출물은 직접 열지 않는다.

scan 보고서는 extractor에 직접 전달할 수 없다. scan의 index/끝 사유를 새 구간 보고서에
그대로 적용하지 않는다. 새 구간은 독립 검사라 예컨대 크기 제한 prefix의 끝이
selection_end가 될 수 있다. 원래 stream의 partial·미검사 한계는 원보고서에 남는다.

## 저장과 요약

결과는 `forensics/analysis/bmff-scan-EV-NNNN-NNN.json`에0444로 저장하고 `bmff-scan`
보관 사건에 해시를 결속한다. 같은 EV fd를 commit까지 유지하며 최종 입력/출력 seal과
보관 기록을 대조한다. core 시간 한도의 partial은 취소·무결성 검사를 거쳐 저장할 수
있다. 취소·짧은 읽기·무결성 실패는 성공 보고서로 게시하지 않는다. 커밋 뒤 늦은 취소나
보조 기록 오류는 이미 저장한 결과를 보존한다. 응답은 report/analysis/warnings다.

`sd-forensics.bmff_scan_results[]`에는 evidence_id, analysis_path/sha256(analysis),
status(report.status), evidence_size(report.source), candidates_reported(report.summary)의
6필드만 기록한다. 최대100개 참조이며 evidence_size는 검색량이 아니다. 재개 위치·
미검색 범위·완료도는 원보고서 coverage를 따르고 필요한 한계는 notes에 적는다.
기존 media_candidate_results와 prefix 추출 결과의 의미는 유지한다.

소프트웨어 한도는 전체 RSS·커널 I/O의 강제 시간 제한이 아니다. 같은 OS 계정의 최종
검사 직후 변경, 실제 카드의 복구율·속도·벤더 변형 검증은 보장하지 않는다.
