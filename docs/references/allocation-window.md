# FAT/exFAT 구간의 현재 할당 상태

`forensics_allocation_window(case_id, evidence_id, partition, offset, length, max_seconds=45)`는
접수된 EV의 명시한 데이터 클러스터 구간을 현재 할당 metadata로 분류한다. 카드·장치는 열지 않는다.
`partition`은 1부터 시작하는 파티션 index이며 파티션 표 없는 볼륨은 1이다.
`offset`은 EV 절대 위치, `length`는 1~64 MiB의 정수다. bool·실수·문자열은 받지 않는다.
창은 EV와 선택 FAT12/16/32 또는 exFAT의 데이터 영역 안에 있어야 한다.
처음·끝의 부분 클러스터는 요청 경계로 잘라 기록한다.

## 분류와 완료 상태

| state | 관찰한 근거 |
|---|---|
| `unallocated` | FAT 항목의 0 또는 검증된 활성 exFAT bitmap의 0 |
| `allocated` | FAT의 정상 next/EOC 또는 활성 bitmap의 1 |
| `bad` | FAT의 bad marker. exFAT bitmap에서는 추정하지 않는다 |
| `unknown` | metadata 불일치·손상·지원하지 않는 값 때문에 현재 할당 상태를 확정할 수 없음 |

FAT12/16은 선언된 사본을, FAT32는 mirroring 설정에 따른 사본 또는 유효한 활성 사본을 확인한다.
요청 창에 대응하는 항목만 비교하며 사본 전체가 같다고 주장하지 않는다.
exFAT는 부트 metadata, 완결된 root의 단일 활성 bitmap, 선언된 길이를 덮는 FAT chain을 검증한다.
첫 사본·첫 bitmap으로 대체하거나 끊긴 bitmap을 연속 파일로 추정하지 않는다.
전체 bitmap popcount, up-case 적재, 파일 도달성 순회는 수행하지 않는다.

같은 state·reason의 인접 행은 합친다. `rows`는 요청 시작에서 이어지는 연속 prefix다.
`coverage.processed_bytes`와 상태별 바이트 합은 같고, 여기에 `unexamined_bytes`를 더하면 요청 길이가 된다.
`window_complete`는 모든 요청 바이트가 행으로 표현됐다는 뜻이다.
`allocation_complete`는 창이 완료됐으며 unknown 바이트가 없을 때만 true다.
따라서 모두 unknown인 완료 창도 `status=partial`이다. `status=ok`는 allocation_complete일 때만 사용한다.
미검사 suffix가 있으면 `next_offset`과 `unexamined_offset`은 그 시작이며, 완료됐으면 둘 다 null이다.

고정 unknown 사유는 `active_fat_invalid`, `fat_copies_disagree`, `fat_entry_unreadable`,
`fat_entry_invalid`, `bitmap_missing`, `bitmap_ambiguous`, `bitmap_active_mismatch`,
`bitmap_chain_invalid`, `bitmap_bit_unreadable`, `root_metadata_incomplete`,
`volume_metadata_inconsistent`다. 판정을 끝내지 못한 한도 중단은 unknown 행으로 대신하지 않는다.

## 예산과 증거 결속

선택·해석은 최대 45초, metadata 읽기는 합계 4 MiB, 한 번의 leaf 읽기는 64 KiB다.
파티션 표·부트·FAT·root·bitmap 읽기를 모두 센다. 캐시 hit는 더하지 않고 재읽기는 다시 센다.
단계 1,048,576, root 슬롯 32,768, bitmap run 8,192, 결과 행 128, JSON 1 MiB로 제한한다.
중단 사유는 `time_limit`, `step_limit`, `metadata_bytes_limit`, `root_slots_limit`,
`bitmap_runs_limit`, `rows_limit`, `output_limit` 중 하나다.
유효 geometry를 만들기 전의 한도는 오류이며, 그 뒤의 한도는 검사하지 못한 suffix를 남긴다.
시간 때문에 partial이 된 결과도 최종 취소·같은 FD 무결성 검사를 통과해야 기록한다.

공통 `open_checked`가 연 같은 FD를 읽고 저장 완료까지 유지한다. 읽기 전후 신원·크기·변경 여부를
검사하며 취소·무결성 실패·짧은 읽기를 FS의 unknown 결과로 숨기지 않는다.
스키마 `pweh.allocation-window/v1`, profile `fat-exfat-allocation-window-v1`의 JSON은
`forensics/analysis/allocation-window-EV-…-NNN.json`에 0444로 저장한다.
`allocation-window` 보관 사건에 입수 EV 해시·크기와 결과 해시를 결속한다.
커밋 전 실패·취소는 결과를 게시하지 않고, 커밋 후 취소는 기록한 산출물을 보존한다.

원문 이름·시각·부트/FAT/bitmap 값은 반환하지 않는다. 손상된 metadata가 내용 영역을 가리킬 수 있으므로
물리적으로 읽은 모든 바이트를 내용과 무관하다고 주장하지 않는다. 의미 해석은 metadata에 한정한다.
`whole_evidence_examined`, `file_ownership_verified`, `historical_allocation_verified`,
`media_decoded`, `playback_verified`, `payload_semantics_examined`는 모두 false다.

## 후속 검색과 요약

unallocated는 접수 이미지의 현재 free 표시다. 삭제 파일의 소속·과거 할당 상태·원래 파일 경계·복구 성공을
뜻하지 않는다. allocated인 orphan 여부도 판정하지 않는다. 전체 카드 자동 검색은 수행하지 않는다.

필요한 행의 EV 절대 `offset/length`를 기존 `forensics_dhav_candidates` 또는
`forensics_media_candidates`의 명시 구간으로 전달할 수 있다. 후보 도구가 해당 구간을 새로 읽어
구간 SHA와 출처를 결속한 뒤, 그 저장 후보를 기존 추출 도구로 선택한다.
할당 보고서 자체는 추출 권위가 아니다. allocated/unknown 행을 자동 제외하거나 자동 추출하지 않는다.

SD summary의 `allocation_window_results[]`에는 evidence_id, analysis_path, sha256, status,
window_complete, allocation_complete의 여섯 필드만 기록한다(최대 100개).
원문·상세 행을 요약에 복사하지 않고 미검사 범위·사유·재개 위치는 상세 보고서와 notes에 남긴다.
