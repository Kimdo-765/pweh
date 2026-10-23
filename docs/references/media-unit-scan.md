# EV의 JPEG·AVC·PS·XM 스트리밍 검색

`forensics_media_unit_scan`은 접수한 EV의 바이트에서 명시한 형식의 구조 후보를 검색한다.
EV 전체를 메모리에 올리지 않고 같은 열린 증거 fd에서 유한한 창으로 읽는다.
후보를 추출하려면 기존 구간 검사에서 선택 전체 해시를 새로 결속해야 한다.

```text
forensics_media_unit_scan(case_id=..., evidence_id=..., format="jpeg",
                         start_offset=0, max_scan_bytes=1073741824, max_seconds=45)
```

## 입력과 한도

format은 `jpeg`, `avc-annexb`, `mpeg2-ps`, `xm` 중 하나다. 자동 감지·별칭·파일 ref·partition은
받지 않는다. evidence_size는1..2**63-1, start_offset은0..evidence_size의 정수다.
max_scan_bytes는4 bytes..1 GiB이며 연속 검색 읽기 합계의 상한이다. max_seconds는 양수..45초다.
케이스 조회부터 검색·구조 검사에 같은 마감을 쓰고 취소·증거 변경은 실패로 처리한다.
시간 때문에 partial인 결과도 최종 증거·보관 기록 검증과 취소 확인을 통과해야 저장된다.

| 예산 | 호출 전체 상한 |
|---|---|
| 검색 읽기 | max_scan_bytes, 최대1 GiB |
| 구조 읽기 / 논리 작업량 | 각각128 MiB |
| 한 번의 실제 읽기 | 64 KiB |
| anchor 검사 / 구조 단계 | 1024 / 8192 |
| 후보 / 선택 범위 | 128개 / 후보마다64 MiB |
| 출력 JSON | 1 MiB |

창 경계의 표지는 메모리 carry로 이어 검사한다. 구조 확인은 검색창 밖에도 닿을 수 있고
그 읽기는 별도 예산에 센다. 물리 읽기 총량은 검색 읽기+구조 읽기, 최대1 GiB+128 MiB다.
logical work는 읽은 물리 bytes와 별도다. 긴 payload·중첩 표지·오탐도 이 예산을 소비한다.

## 형식과 보고 행

schema는 `pweh.media-unit-scan/v1`이며 네 profile을 섞지 않는다.
지원 문법 자체는 [선택 미디어 단위](media-unit-candidates.md)의 subset과 같다.

| format | profile | 단위 최소 / 재검증 선택 최소 |
|---|---|---|
| jpeg | jpeg-baseline-marker-stream-v1 | 28 / 28 bytes |
| avc-annexb | avc-annexb-delimited-nal-stream-v1 | 4 / 8 bytes |
| mpeg2-ps | mpeg2-ps-bounded-pack-prefix-stream-v1 | 24 / 24 bytes |
| xm | xm-length-delimited-frame-stream-v1 | 9 / 9 bytes |

각 행은 index, offset, length, format, unit, unit_subtype, boundary_kind, framing_status,
end_reason, confidence, selection_offset, selection_length의12필드다. offset과
selection_offset은 같은 **EV 절대 위치**다. length는 검증된 단위의 길이이고 selection_length는
같은 후보를 구간에서 재검증하는 데 필요한 범위다. length≤selection_length≤64 MiB이며
선택 끝은 실제 EV 안에 있다. 선행 읽기의 끝을 선택 길이로 쓰지 않는다.

AVC는 다음 prefix/header를 선택에 포함하지만 단위에는 포함하지 않는다. 마지막 열린 NAL은
후보가 아니다. PS는 다음 pack·종료 표지·검사에 필요한 후속 header/선언 끝까지 선택할 수 있다.
실제 EV 끝에 의존한 PS prefix의 end_reason은 evidence_end다.64 MiB 선택 상한은 EOF가 아니다.
지원 subset 밖이거나 한 후보의 선택 상한에 걸린 anchor는 별도 분류하며 완료로 숨기지 않는다.

## 완료·부분성·재개

coverage의 완료 값은 각각 다음 의미다.

- search_complete: 요청 start_offset 이후 시작 위치를 모두 처리했다.
- whole_evidence_search_complete: start_offset=0인 이번 호출이 전체 시작 위치를 처리했다.
- candidate_checks_complete: 관찰한 anchor에 pending·불완전 framing·선택 크기 제한이 없다.
- candidate_list_complete: search_complete와 candidate_checks_complete가 모두 true다.

후보가 PS prefix이면 위 완료 값이 모두 true여도 status는 partial일 수 있다.
status는 사유가 있으면 partial, 사유가 없고 후보가 있으면 ok, 후보가 없으면 unsupported다.
후보0개는 미디어 부재 증명이 아니다. selection_size_limit·unit_framing_incomplete·
candidate_prefix_partial과 검색/시간/자원 중단을 구분한다.

next_offset은 다음 호출에서 처리할 시작 위치이며 물리 읽기의 끝과 다르다. pending anchor는
그 위치에서 다시 검사한다. 한도를 늘리거나 충분한 시간으로 재호출해도 같은 위치에서 멈추면
진전했다고 표시하지 않는다. next_offset=null이면 이번 요청 뒤에 미처리 시작 위치가 없다.
이전 호출들의 완료를 합쳐 단일 호출의 whole_evidence_search_complete로 바꾸지 않는다.
unexamined_positions와 positions_before_start도 보고한다. 검색 위치의 최소 표지 폭은
JPEG2, AVC3, PS4, XM3bytes이며 payload 의미는 해석하지 않는다.

## 저장과 기존 추출 연결

source는 kind=evidence, evidence_id, evidence_sha256, evidence_size의4필드다.
SHA는 **접수 EV 해시**이며 이번 전체 재해시나 단위 해시가 아니다. params는 format,
start_offset, max_scan_bytes, max_seconds의4필드다. 보고서는 analysis에0444로 저장하고
media-unit-scan 사건에 결속한다. 원시 header·본문·시각·키·단위 해시는 반환하지 않는다.

1. 필요한 scan 행의 selection_offset/selection_length를 같은 format의
   `forensics_media_unit_candidates(offset=..., length=...)`에 넘긴다.
2. 새 보고서에서 source.offset+candidate.offset이 원래 offset과 같고 length,
   unit_subtype, boundary_kind, framing_status, end_reason이 맞는 행을 고른다.
   stream의 evidence_end는 구간의 selection_end에 대응한다. index=0을 가정하지 않는다.
3. **그 새 구간 보고서**의 analysis.path와 실제 candidate_index를
   `forensics_extract_media_unit`에 넘긴다. scan 보고서 직접 추출은 받지 않는다.

AVC의 선택 범위 끝에는 다음 열린 NAL이 있어 구간 보고서가 partial일 수 있다. 일치하는 행과
원래 불확실성을 보존하여 기존 추출 계약을 따른다. 추출물은 사람이 확인하며 에이전트가 열지 않는다.
검색은 파일 시스템·할당·삭제·이전 파일 소속을 판정하거나 조각을 재조립하지 않는다.
media_decoded, playback_verified, recording_time_verified, encryption_assessed,
format_conformance_assessed, original_file_boundary_verified, complete_recording,
payload_semantics_examined, physical_carving_performed는 모두 false다.

SD 요약의 optional media_unit_scan_results는 다음6필드 참조만 남긴다. 부분성·재개·미검사
범위는 원보고서와 notes에 남기며 기존 candidate 요약과 recovered는 유지한다.

```json
{
  "evidence_id": "EV-0001",
  "analysis_path": "forensics/analysis/media-unit-scan-EV-0001-001.json",
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "status": "partial",
  "format": "avc-annexb",
  "candidates_reported": 1
}
```
