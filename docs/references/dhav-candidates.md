# 선택 bytes의 DHAV record 구조 후보

명시 exFAT partition/ref의 ValidDataLength 뒤 선택은 별도 [잔여 계약](exfat-residual-candidates.md)을 따른다.
잔여 source19필드와 전용 profile을 사용하며 아래의 기존 파일·EV 구간 계약은 유지한다.

`forensics_dhav_candidates`는 같은 케이스의 EV 전체, FAT/exFAT·TAR/ZIP에서 선택한 완전한
파일 하나, 또는 EV의 명시 구간에서 DHAV record 구조 후보를 찾는다. 입력은 최대64 MiB다.
파일·구간 안의 앞뒤 표지와 길이를 대조한 메타데이터이며 영상 복구·재생 결과는 아니다.

큰 EV에서 먼저 위치를 찾으려면 별도 [`forensics_dhav_scan`](dhav-scan.md)을 쓴다. 그 row의
EV 절대 offset/record_length를 이 도구의 offset/length에 넣어 구간 전체 SHA를 결속한 뒤
저장된 새 후보를 추출한다. scan 보고서 자체는 추출 입력이 아니다.

## 선택과 출처

```text
forensics_dhav_candidates(case_id=..., evidence_id=..., ref=...)
forensics_dhav_candidates(case_id=..., evidence_id=..., offset=1048576, length=4194304)
```

`ref`와 `path`는 함께 쓰지 않는다. EV 자체를 검사하려면 둘 다 생략하고 partition 없이
method=auto를 쓴다. FS의 삭제 항목은 ref와 복구 method로 고른다. 불완전하게 읽힌 파일의
앞부분을 성공으로 처리하지 않는다. 빈 파일은 후보 없는 unsupported 결과가 될 수 있다.

명시 구간은 정수 `offset/length`를 함께 지정한다. offset≥0, length는1..64 MiB이고 EV 안에
있어야 한다. 이때 ref/path/partition은 생략하고 method=auto를 유지한다. 큰 EV를 자동으로
잘라 읽거나 전체 카드를 순회하지 않는다. 구간은 미할당·삭제·잔여 영역이라는 판정이 아니다.

| 저장 profile | 선택 계약 |
|---|---|
| `dhav-record-framing-v1` | 기존 파일 source16필드와 params3필드(partition/method/max_seconds) |
| `dhav-record-ev-range-v1` | source에 evidence_size/offset, params에 offset/length를 더한 닫힌 구간 계약 |

source.evidence_sha256은 접수 때 기록한 EV 해시, source.selected_sha256은 실제 읽은 선택
bytes 전체의 SHA-256이다. 구간 source.selected_size는 params.length와 같고 evidence_size는
접수 크기와 열린 EV 크기를 대조한 값이다. complete=true/high는 완전 읽기와 선택 신원을
뜻하며 DHAV 후보·녹화의 확신이 아니다. 이 호출이 전체 EV를 다시 해시한 것도 아니다.

후보 offset과 검색 위치는 **선택 bytes 상대**다. 구간 모드에서만 source.offset을 더하면
EV 내 위치가 된다. 파일 시스템·삭제 복구·아카이브의 논리 위치에 이 계산을 적용하지 않는다.
구간 밖과 앞 구간에서 시작한 record는 이 호출의 검사 범위가 아니다.

## 고정 subset과 후보 행

지원 subset은 `DHAV` 표지, type f0/fc/fd, 고정24byte 헤더와 extension 길이, 양수 payload,
끝의 소문자 `dhav` 표지와 반복 길이다. 모든 record bytes가 선택 안에 있어야 한다.
f1의 별도 경로·DAHUA wrapper·추가 변형을 해석하지 않는다.

후보 행은 index/offset/record_length/header_length/extension_length/payload_length,
record_type(type_f0/type_fc/type_fd),footer_length_matches=true,confidence=possible만 담는다.
header_length=24+extension_length, record_length=header_length+payload_length+8이며
최소 record 크기는33bytes다. 임의 payload 속 표지도 후보가 될 수 있고, 중첩 anchor를
독립 검사하므로 후보 수는 녹화·프레임·파일 수가 아니다. 후보끼리 연속성·겹침 관계도 계산하지 않는다.

고정 헤더 중 표지/type/길이와 extension **길이**만 읽는다. 나머지 header의 subtype/channel/
시각/counter/checksum, extension 내부와 payload 의미는 해석·반환하지 않는다. 원시 bytes에서
표지를 찾는 검색은 payload 내부를 지날 수 있으므로 payload_semantics_examined=false는
의미 해석을 하지 않았다는 뜻이며 payload bytes에 전혀 접근하지 않았다는 뜻은 아니다.

## 상태와 검사 범위

보고서 schema는 `pweh.dhav-candidates/v1`이다. status는 ok/partial/unsupported다.
ok도 고정 subset의 구조 후보가 있다는 뜻일 뿐 미디어 종류·재생·완전 녹화를 확인하지 않는다.
후보가 없고 검색을 끝냈으면 unsupported가 가능하다. 범위가 부족한 anchor, 시간·상한 또는
선택 불확실성은 후보0건이어도 partial로 남는다.

- summary는 관찰 anchor, 완전 기각, 범위 부족, 지원 anchor, 저장·생략 후보를 구분한다.
  잘린 헤더/record_beyond_selection은 완전 기각과 다른 incomplete_anchors다.
- coverage.search_positions_examined는 가능한4byte 표지 시작 위치를 처리한 연속 prefix다.
  읽은 bytes 수가 아니다. 전체 위치 수는 max(0,input_bytes−3)이다.
- pending_anchor_offset은 판정 중 멈춘 anchor다. 반대로 완전히 검증했지만 출력/후보 한도로
  행을 못 남긴 경우 candidates_omitted=1이며 pending은 null이다.
- search_complete는 전체 위치 검색, candidate_checks_complete는 **이미 관찰한** anchor 검사,
  candidate_list_complete는 전체 검색·검사 및 지원 후보 저장 완료다. 서로 바꾸어 읽지 않는다.
- coverage.reasons와 unexamined_positions를 확인한다. 삭제·부모 상태 미확인·복구 confidence와
  알려진 컨테이너 목록 잘림은 보존하며, container_examined=false는 전체 컨테이너 검사를
  주장하지 않음을 뜻한다. 원문 이름·시각·본문·오류 문자열은 결과에 추가하지 않는다.

다음 값은 항상 false다: payload_semantics_examined, extension_fields_examined,
checksum_verified, media_decoded, playback_verified, recording_time_verified,
encryption_assessed, original_file_boundary_verified, complete_recording.

## 상한·보관·요약

선택·읽기·검색은 max_seconds(유한 양수, 최대45초)의 같은 deadline을 쓴다. anchor probe1024,
후보128, 구조 필드 판독 합1 MiB, 최종 JSON1 MiB 상한이 있다. 구조 판독량은 표지 검색량과
별개다. 검색은64 KiB 창과3byte 겹침으로 수행하며 record 길이만큼 검색을 건너뛰지 않는다.

시간 한도로 검색이 덜 끝나면 coverage를 가진 partial 보고서를 저장할 수 있다. 취소·파일
변경·불완전 읽기는 성공으로 바꾸지 않는다. report/source/params를 `dhav-candidates` 사건과
해시로 결속하고 JSON을0444로 저장한다. 커밋 뒤 늦은 취소나 보조 기록 실패는 저장 결과를 보존한다.
응답은 report/analysis/warnings이며 analysis의 생성 경로·해시는 evidence-list derived로 확인한다.

`sd-forensics.dhav_candidate_results[]`에는 다음6필드만 기록한다.

| 요약 필드 | 응답 출처 |
|---|---|
| evidence_id | 검사한 EV |
| analysis_path / sha256 | analysis.path / analysis.sha256 |
| status | report.status |
| selected_size | report.source.selected_size |
| candidates_reported | report.summary.candidates_reported |

최대100행, 선택 크기0..64 MiB, 후보 수0..128이다. 후보 좌표·길이·type·raw 시각/채널/파일명을
요약에 더하지 않는다. 상세 coverage는 보고서를 참조하고 partial/unsupported 한계는 notes에 쓴다.
기존 privacy.audio_decoded·recording_content_viewed는 false로 유지한다.

기존 BMFF inventory/candidates/prefix 추출과 독립 도구다. `forensics_extract_media_candidate`는
BMFF 보고서만 받는다. DHAV 후보 하나의 파생 추출은 별도
[`forensics_extract_dhav_candidate`](dhav-record-extract.md)를 사용한다. 전체 카드 카빙·조각 재조립·
Dahua 인덱스·녹화 타임라인·암호화 판정·영상 해독도 이 기능의 완료 범위가 아니다.

## 소스 근거와 해석의 한계

고정 헤더·길이·type 배치는 [FFmpeg n7.1의 dhav.c](https://github.com/FFmpeg/FFmpeg/blob/n7.1/libavformat/dhav.c)의
read_chunk에 근거한다. footer 반복 길이의 일치는 같은 소스 get_duration의 역방향 이동 의미를
바탕으로 정한 **PWEH의 보수적 오탐 억제 조건**이다. FFmpeg의 모든 packet 경로가 앞뒤 길이
일치를 강제하거나 제조사가 보증한 규격이라고 설명하지 않는다. 양수 payload 조건도 첫 subset의
선택이다. 모든 DAV 변형·카메라 모델 지원이나 실제 녹화의 정상 여부는 확인하지 않았다.
