# FAT/exFAT의 현재 참조와 할당 일관성

`forensics_cluster_report(case_id, evidence_id, partition, max_seconds=45)`는 접수된 EV의
명시 FAT12/16/32 또는 exFAT 파티션 하나에서 현재 살아 있는 항목의 클러스터 참조와
현재 할당 metadata를 대조한다. `partition`은 `forensics_partitions`의 index이며,
파티션 표 없는 볼륨은 1이다. 1..4096의 정수만 받고 bool·실수·문자열은 받지 않는다.
TAR/ZIP과 지원하지 않는 파일 시스템은 거부한다.

기존 `forensics_allocation_window`가 지정한 창의 할당 상태를 확인한다면, 이 도구는
살아 있는 파일·디렉터리와 시스템 항목의 참조까지 대조한다. 삭제 항목은 순회하지 않는다.
원문 이름·경로·시각·FAT 값·bitmap·진단 문자열은 보고서에 넣지 않는다.

## 관찰 수치와 완료 상태

`counts`의 값은 실제 검사한 부분에 한정한다. FAT의 `allocation_examined`는 allocated,
free, bad의 합이고, exFAT에서는 allocated와 free의 합이다. exFAT의 bad와 invalid_values는
null이다. 읽지 못한 bitmap 꼬리를 free로 채우지 않는다.
`observed_referenced_clusters`는 실제 표시한 유효 클러스터의 고유 수다.
`overlap_reference_events`는 이미 표시된 참조를 다시 표시한 횟수이며 파일쌍의 수가 아니다.
`unallocated_reference_count`의 단위는 FAT에서 `fat-chain-heads`, exFAT에서
`exfat-clusters`다. 두 종류의 수치를 같은 단위로 합치지 않는다.

| coverage 필드 | 의미 |
|---|---|
| `reference_walk_complete` | 살아 있는 항목 순회가 끝났고 검증하지 못한 live 디렉터리가 없음 |
| `reference_map_complete` | 순회와 root·시스템·파일 체인 표시까지 모두 끝나 미해결 참조가 없음 |
| `allocation_complete` | 선언된 클러스터 전부를 분류했고 필요한 할당 metadata 일관성 검사를 마침 |
| `rows_complete` | 검사한 부분에서 발견한 공개 종류의 표본을 생략하지 않음 |

`status=ok`는 네 완료 값이 모두 true이고 `reasons=[]`일 때만 사용한다. 관찰한 overlap이
있어도 모든 검사가 끝났다면 ok일 수 있다. 따라서 ok는 파일 시스템에 이상이 없다는 뜻이 아니다.
`allocation_clusters_examined + allocation_clusters_unexamined`는 원래 선언 cluster_count다.
한도로 처리하지 못한 부분, 짧거나 잘못된 체인, metadata fallback·사본 불일치·불완전 bitmap은
해당 완료 값을 false로 남긴다. 일부 양의 관찰 수치를 보존해도 전체 검사를 증명하지 않는다.

`allocated_without_live_reference`는 참조 지도와 할당 검사가 모두 완료된 경우에만 숫자다.
하나라도 불완전하면 null이며 해당 종류 행도 없다. 숫자가 있더라도 현재 live 참조 모델에서
참조가 관찰되지 않았다는 뜻이다. 고아 파일·삭제된 파일의 과거 소속을 확정하지 않는다.

## 행과 검사 한도

`rows`는 최대 128개이며 다음 고정 순서로 기록한다.

| kind | 관찰한 항목 |
|---|---|
| `allocated-without-live-reference` | 완전한 대조에서 현재 참조가 없는 할당 연속 구간 |
| `unallocated-reference` | 할당되지 않은 클러스터를 가리키는 참조 |
| `overlap-reference` | 이미 표시된 클러스터를 다시 표시한 참조 |
| `chain-anomaly` | 체인 상태와 길이 대조의 이상; 물리 연속 구간은 만들지 않음 |

검증한 FS ref 또는 null만 기록하며 root·bitmap·upcase 이름을 ref로 출력하지 않는다.
구간 행의 offset은 EV 절대 위치이고 length는 실제 클러스터 길이다. 분산된 이상 체인을
하나의 연속 구간으로 표현하지 않는다. 표본이 잘리면 rows_complete=false와 rows_limit를 남긴다.

파티션 탐지 전부터 metadata 읽기는 합계 32 MiB, leaf 한 번은 64 KiB로 제한한다.
재읽기도 합계에 포함한다. 클러스터 1,048,576개, live 항목 16,384개, 경로 글자 4 MiB,
디렉터리 슬롯 262,144개, 깊이 64, run 8,192개, 단계 1,048,576, 결과 JSON 1 MiB가 상한이다.
캐시에서 처리하는 긴 루프도 같은 단계·시간 예산을 사용한다.

원래 선언 클러스터 수가 검사 상한을 넘으면 검사 수 0과 cluster_limit를 기록한다.
선언 geometry가 EV·파티션·볼륨 범위와 모순되거나 내부 보정 수와 다르면 검사 수 0,
metadata_inconsistent로 남기며 그 geometry에서 물리 구간 행을 만들지 않는다.
유효 geometry를 얻기 전 한도는 오류이고, 그 뒤의 시간·단계·읽기 한도는 실제 관찰과
미검사 수를 보존한 partial 보고서로 남길 수 있다.

## 증거 결속과 저장

소유/허가·보관 기록·무결성 확인 후 `open_checked`가 연 같은 FD를 끝까지 사용한다.
각 leaf 읽기 전후와 최종에 신원·크기·변경 여부를 검사한다. 최초 취소·무결성 실패·짧은 읽기를
FS가 내부에서 처리해도 partial 성공으로 바꾸지 않는다. 실패 때 원문 진단은 노출하지 않는다.

시간은 케이스 조회 전 한 번 정한 최대 45초를 선택·해석에 함께 사용한다. 시간 때문에 partial이
된 뒤의 제한된 스키마·집계·직렬화·최종 seal·저장은 새 45초를 부여하지 않고 수행한다.
취소 검사는 계속 유지한다. 전체 저장까지 반드시 45초 안에 끝난다는 보장은 아니다.

`pweh.cluster-report/v1`, profile `fat-exfat-live-reference-v1` 보고서는
`forensics/analysis/cluster-report-EV-…-NNN.json`에 0444로 저장한다.
`cluster-report` 사건에 접수 EV 해시·크기와 결과 해시를 결속한다. source의 EV 해시는
접수 기록값이며 이번 호출에서 전체 EV를 재해시한 값이 아니다. 커밋 전 실패는 자기 출력만
정리하고, 커밋 후 보조 기록 실패는 기존 receipt와 경고를 보존한다.

손상 metadata가 내용 영역을 가리킬 수 있으므로 물리적 내용 읽기 0을 주장하지 않는다.
의미 해석은 metadata에 한정한다. `whole_evidence_examined`, `orphan_files_verified`,
`historical_allocation_verified`, `file_ownership_verified`, `media_decoded`,
`playback_verified`, `payload_semantics_examined`는 항상 false다.

## 필요한 구간의 후속 검사와 요약

목적에 필요한 구간 행 하나의 offset/length를 같은 EV의 `forensics_dhav_candidates` 또는
`forensics_media_candidates`에 명시할 수 있다. 후보 도구가 구간 전체 SHA와 출처를 새로
결속한 뒤 해당 저장 후보만 기존 추출 도구로 선택한다. cluster 보고서를 직접 추출 입력으로
사용하지 않으며, 자동 후보 검색·추출·조각 재조립도 하지 않는다. 파일 ref의 추출은 기존
목록과 선택 도구의 도달성·무결성 확인을 따른다.

SD summary의 `cluster_report_results[]`에는 최대 100개의 결과 참조를 기록한다.
필드는 evidence_id, analysis_path, sha256, status, reference_map_complete,
allocation_complete 여섯 개다. status가 ok이면 두 완료 값은 true다. partial은 행 표본 제한
등으로 두 값이 모두 true일 수도 있다. 상세 범위·사유·미검사 수는 원보고서와 notes에 남긴다.

```json
{
  "cluster_report_results": [{
    "evidence_id": "EV-0001",
    "analysis_path": "forensics/analysis/cluster-report-EV-0001-001.json",
    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "status": "partial",
    "reference_map_complete": false,
    "allocation_complete": true
  }]
}
```
