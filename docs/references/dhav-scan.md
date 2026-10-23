# EV 바이트의 DHAV 스트리밍 구조 검색

`forensics_dhav_scan(case_id, evidence_id, start_offset=0, max_scan_bytes=1073741824,
max_seconds=45)`는 접수된 EV를 같은 읽기 전용 fd로 순차 검색한다. FAT/exFAT 목록이나
파일 경계를 몰라도 큰 이미지 안의 제한된 DHAV record 구조 후보를 찾을 수 있다.
일반 파일/구간을 완전히 읽는 `forensics_dhav_candidates`와 별도 도구이며 영상 해독·
조각 재조립·미할당 영역 판정은 하지 않는다.

## 입력과 읽기 예산

케이스 소유/허가·접수/보관 기록·EV 무결성 확인 뒤에만 읽는다. 원시 디스크·장치 경로를
받지 않으며 ref/path/partition/복구 method도 받지 않는다. 실제 파일 시스템 파일이나
아카이브 멤버를 찾으려면 기존 파일 선택 도구를 쓴다.

| 항목 | 기본·고정 상한 |
|---|---|
| EV 크기 | 1..2^63−1 bytes |
| start_offset | 정수 0..EV 크기, 기본0 |
| max_scan_bytes | 정수 4..1 GiB, 기본1 GiB |
| max_seconds | 유한 양수, 최대45초 |
| 검색 읽기 | 한 번에 최대64 KiB, 연속 읽기 합계≤max_scan_bytes |
| 구조 필드 읽기 | 검색량과 별도 합계≤1 MiB |
| anchor probe / 후보 row | 최대1024 / 128 |
| 반환 record 길이 / JSON | 최대64 MiB / 1 MiB |

검색 창 끝의3bytes는 메모리에 유지한다. 같은 호출에서 overlap을 다시 읽거나 검색 예산
밖의 lookahead를 읽지 않는다. 헤더/type/길이/extension 길이/footer 확인은 **별도 구조
읽기**이므로 검색창 밖의 footer도 EV 안이면 읽을 수 있다. 검색·구조 callback의 읽기 합계는
최대 max_scan_bytes+1 MiB이며 구조 읽기가 도달한 위치를 검색 완료 범위에 넣지 않는다.
접수 지문·보관 기록 등 공통 무결성 확인의 I/O는 이 검색 회계와 별개다.

기존 [DHAV 후보 subset](dhav-candidates.md)의 f0/fc/fd·고정 헤더와 양수 payload·끝 표지·
반복 길이 조건을 그대로 쓴다. EV 밖으로 끝나는 record는 incomplete이고, EV 안이지만
선언 길이가64 MiB를 넘으면 `record_size_limit` partial로 남긴다. 초과 record의 footer나
본문을 읽어 구조 검증을 끝냈다고 하지 않는다. 반환 행은 모두 기존 구간 입구가 받을 수 있다.

## 보고서와 좌표

schema는 `pweh.dhav-scan/v1`, profile은 `dhav-stream-framing-v1`이다.

- source는 kind=evidence, evidence_id, evidence_sha256, evidence_size 네 필드다.
  evidence_sha256은 **접수 해시**이며 이번 호출이 전체 EV를 재해시한 결과가 아니다.
- params는 start_offset/max_scan_bytes/max_seconds 세 필드다.
- 후보는 index/offset/record_length/header_length/extension_length/payload_length/
  record_type/footer_length_matches/confidence다. **offset은 EV 절대 위치**이고 confidence는
  possible이다. 원시 header·시각·채널·확장값·본문·개별 record 해시는 반환하지 않는다.
- status는 ok/partial/unsupported다. 이유가 있으면 partial, 이유 없이 후보가 있으면 ok,
  이유 없이 후보가 없으면 unsupported다. 미디어 부재·정상 녹화 판정이 아니다.

순차 검색은 payload 안의 bytes도 지날 수 있다. `payload_semantics_examined=false`는
내용 의미를 해석하지 않았다는 뜻이다. extension_fields_examined, checksum_verified,
media_decoded, playback_verified, recording_time_verified, encryption_assessed,
original_file_boundary_verified, complete_recording도 모두 false다. 기록 시간·채널·codec을
해석하지 않고, record 해시·파일 경계·연속성·삭제/미할당 상태를 추정하지 않는다.

## 완료와 재개

coverage는 읽은 바이트와 처리한 magic 시작 위치를 구분한다. EV 크기를 N이라 하면
가능한4byte 시작 위치는 `[0,max(0,N−3))`다.

- `positions_before_start`는 이번 시작 위치 앞의 미대상 위치 수다.
- `search_positions_examined`는 시작 위치부터 **처리를 완료한 연속 prefix**의 길이다.
  선행 읽기된 bytes가 있다고 그 범위까지 완료라고 하지 않는다.
- `unexamined_positions`는 그 뒤 미처리 tail이며, pending_anchor_offset은 검사 도중 멈춘
  anchor다. 시작 전 수+검사 prefix 수+미처리 tail 수가 search_positions_total과 같다.
- `next_offset`은 미처리 tail의 첫 위치이며 완료 시 null이다. 검색 예산 끝의 마지막3bytes나
  pending anchor에서 재개할 수 있다. 다시 호출할 때는 이 값을 start_offset으로 그대로 쓴다.
- `search_complete`는 **요청한 시작 이후**의 검색 완료다. 한 호출의 start_offset=0이고 끝까지
  처리했을 때만 `whole_evidence_search_complete=true`다. 여러 보고서를 자동 합쳐 전체 완료로
  승격하지 않으며, 이 flag도 녹화·원본 파일·record 내용의 완전성은 아니다.
- `candidate_checks_complete`는 관찰한 anchor의 제한 구조 검사 완료, `candidate_list_complete`는
  요청 시작 이후 검색·검사·목록의 완료다. prefix·pending·초과 record·잘린 record를 구분한다.

reasons는 scan_byte_limit/probe_limit/candidate_limit/structure_byte_limit/output_limit/
time_limit/record_framing_incomplete/record_size_limit의 닫힌 값이다. 시간·상한에 걸린
보고서는 검사 범위를 보존해 저장할 수 있다. 취소·짧은 read·무결성 실패는 성공으로 게시하지
않는다. 일부 후보를 이미 저장했더라도 재개 호출과 보고서 간 중복·전체 완료를 자동 합치지 않는다.

## 기존 구간 검증과 추출로 연결

scan의 row는 **추출 권위가 아니다**. 같은 EV에서 필요한 row 하나를 고른 다음 다음 순서를 따른다.

1. `forensics_dhav_candidates`에 offset=row.offset, length=row.record_length를 전달한다.
   구간 전체 bytes를 다시 읽고 SHA·EV 크기/시작·길이와 새로운 후보 보고서를 결속한다.
2. 새 구간 보고서에서 실제 존재하는 후보 번호 하나를 골라
   `forensics_extract_dhav_candidate`에 그 **후보 보고서**의 analysis.path를 전달한다.
3. 추출은 job 완료를 확인하고 recovered·notes와 증거 목록에 기록한다. 추출물을 직접 열지 않는다.

새 후보 offset은 구간 상대다. scan의 절대 offset을 새 후보 offset으로 혼동하거나 두 번 더하지
않는다. scan analysis.path를 extractor에 직접 주면 거부된다. scan 행과 다음 검증 사이의 변경을
기존 구간 해시/출처·최종 commit 검사로 처리하며 scan 단계의 미검사/partial을 지우지 않는다.

## 저장과 요약

분석 JSON은 `forensics/analysis/dhav-scan-EV-NNNN-NNN.json`에0444로 저장하고 `dhav-scan`
보관 사건·해시와 결속한다. 같은 EV fd를 검사부터 commit까지 유지하고 이름/부모/FD·접수
기록·출력 seal을 최종 대조한다. 커밋 전 취소/실패는 새 보고서를 게시하지 않고, 커밋 후
늦은 취소·보조 기록 오류는 저장 결과를 보존한다. 응답은 report/analysis/warnings다.

`sd-forensics.dhav_scan_results[]`는 evidence_id, analysis_path/sha256(analysis),
status(report.status), evidence_size(source), candidates_reported(summary)의6필드만 쓴다.
최대100개 참조이며 evidence_size는 검색량이 아니다. next_offset·완료도·미검색 범위는
보고서 coverage를 참조하고 notes에 필요한 한계를 쓴다. 기존 dhav_candidate_results와
recovered의 의미는 바꾸지 않는다.

전체 RSS·커널 I/O의 강제 시간 제한이나 같은 OS 계정의 최종 검사 직후 변경까지 보장하지
않는다. 소프트웨어 완료 범위는 bounded 구조 검색→기존 구간 검증→단일 record 추출 연결이며,
파일 재조립·Dahua 인덱스·녹화 타임라인·암호화·벤더 변형/실모델 검증은 남아 있다.
