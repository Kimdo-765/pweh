# 제공된 숫자 관찰의 케이스 분석

`pweh-play`의 `vision_validate`는 사용자가 제공한 수열을 기존 [숫자 합의 코어](numeric-observations.md)로 요약하고, 케이스에 닫힌 보고서와 artifact를 남긴다. 현재 지원 입력은 `numeric-observations` 하나다. 장비·파일 입력·화면 캡처·OCR·자동 플레이는 수행하지 않는다.

## 입력과 시간축

```text
vision_validate(case_id, input_kind="numeric-observations", observations, now, policy=None)
```

| 입력 | 허용 값 |
|---|---|
| observations | 0..256개의 JSON 배열. 원소는 정확히 timestamp/value/confidence 세 필드 |
| timestamp, now | int 또는 유한한 float, 0..2**53초. timestamp는 엄격 증가하고 모두 now 이하 |
| value | null 또는 부호 있는64비트 int. 음수·감소·0으로 리셋 허용 |
| confidence | int 또는 유한한 float, 0..1. value=null에도 필수 |
| policy | null/생략 또는 아래 필드 중 일부만 가진 객체 |
| window_size | int1..256, 기본5 |
| votes_required, min_valid | 각각 int1..window_size, 기본3 |
| min_confidence | 유한한 수0..1, 기본0.8 |
| ttl_seconds | 유한한 수0 초과..86400, 기본2.0 |

모든 숫자에서 bool·문자열을 거부한다. value의 float도 정수로 바꾸지 않는다. 배열/정책을 JSON 문자열로 포장하거나 추가 필드를 넣을 수 없다. 최근 창 밖의 표본도 전부 검증한다. window_size만2로 낮추면 기본 votes_required/min_valid=3과 모순되므로 함께 유효한 정책을 지정해야 한다.

now는 사용자가 표본과 **같은 monotonic seconds 축**으로 공급한 평가점이다. 서버 UTC나 호스트 시계로 대체하지 않는다. stale은 이 공급 시간축의 TTL 결과이며 실제 영상이 오래됐다는 판정이 아니다. 호스트 시계는 작업 예산에만 쓴다.

## 반환과 해석

성공 반환의 키는 `ok`, `report`, `artifact_id`, `analysis_path`, `sha256`, `size`, `warnings`다.

```text
report = {
  schema: "pweh.numeric-validation/v1",
  profile: "supplied-numeric-observations-v1",
  source: {kind: "supplied-observations", input_kind: "numeric-observations",
           observation_count, canonicalization: "pweh-numeric-json-v1",
           canonical_size, canonical_sha256},
  params: {now},
  analysis: <pweh.numeric-observations/v1 코어 결과 전체>,
  limitations: ["user_time_axis_only", "input_digest_not_acquisition_provenance",
                "raw_observations_not_stored"]
}
```

analysis에는 status/reason/value, evidence의7개 집계, 확장 policy5개와 false3개가 있다. 상태 우선순위와 투표 규칙은 [숫자 모델](numeric-observations.md#창ttl투표)을 따른다.

| 상태 | 이유 | 값 |
|---|---|---|
| stable | vote_consensus | 정책을 만족한 유일한 최다값 |
| unknown | no_observations / insufficient_valid / tied_votes / insufficient_votes | null |
| stale | no_recent_observations | null |

새 호출이 unknown/stale이면 이전 stable 값을 재사용하지 않는다. `frame_freshness_verified`, `game_semantics_verified`, `action_generated`는 항상 false다. 합의는 실제 점수·멈춘 화면·게임 규칙·버튼 입력 허용을 확인하지 않는다.

## 입력 digest와 비저장 범위

검증·정책 기본값 확장 뒤 canonical 입력은 schema=`pweh.numeric-input/v1`, input_kind, now, 확장 policy, 원래 순서의 observations를 가진다. `sort_keys=True`, `separators=(',', ':')`, `ensure_ascii=True`, `allow_nan=False`의 UTF-8 JSON이며 줄끝 없이 최대65536bytes다. 이 bytes의 SHA256과 크기만 source에 보존한다.

정수/float 표현을 보존한다. 따라서1과1.0,0.0과-0.0의 digest는 다를 수 있다. 생략 정책과 **같은 숫자 타입을 사용한** 명시 기본값은 같다. 기본 ttl_seconds=2.0과 명시2를 수학적으로 같다고 강제 정규화하지 않는다. 다른 언어의 canonical JSON 표준 준수를 주장하지 않는다.

원 표본 배열·개별 timestamp/confidence와 canonical bytes는 worker 메모리에서만 사용하고 보고서·artifact metadata·감사·오류에 저장하지 않는다. 합의 value·공급 now·policy·latest_age_seconds와 집계는 의도한 출력이다. 작은 표본에서는 이 출력으로 입력 일부를 유추할 수 있다. digest는 익명화·독립 획득·실제 프레임 출처의 증거가 아니며, 보고서만으로 원 표본을 재계산할 수도 없다. 사용자가 재현하려면 원 입력을 별도로 보유해야 한다. MCP 클라이언트의 원 요청·대화 기록까지 비저장을 보장하지 않는다.

## 파일·취소·오류

소유·허가된 케이스의 `analysis/numeric-observations-NNN.json`에 LF 포함 최대65536bytes,0444로 쓴다. producer는 `pweh-play`, kind는 `other`, extra.type은 `numeric-validation`이다. 처리·직렬화·출력·최종 등록은 worker 시작부터 같은5초 예산이며 커널 I/O 강제 중단 보장은 아니다.

같은 작성 FD의 SHA와 부모/파일 신원, 등록 entry를 metadata commit 직전에 재검증한다. commit 전 취소·실패는 동일 inode의 자기 출력만 정리하고 교체된 파일은 보존한다. commit 뒤 취소·감사 오류는 게시 결과를 되돌리지 않는다. `post_commit_audit_failed` 경고는 등록이 끝난 결과와 함께 반환한다. 응답이 취소됐다면 `case_get(include_artifacts=true)`로 등록 여부를 확인한다.

SDK 입력 오류는 표본·추가 키·오류 위치 원문을 노출하지 않는 고정 오류다. worker 오류도 입력 repr·원 예외를 싣지 않는다. core의 `invalid_policy`, `invalid_observation`, `observation_limit`와 입구/출력의 `numeric_input_invalid`, `numeric_output_invalid`, `numeric_analysis_failed`, `cleanup_incomplete`, `time_limit`, `cancelled`를 구분한다. 실패한 요청의 결과나 표본을 성공 보고서로 보충하지 않는다.

## 요약과 완료

`numeric-observation-analysis` Skill/선택 phase는 `numeric-analysis` 스키마로 기록한다. results의 각 row는 반환 artifact_id/analysis_path/sha256 및 report의 status/reason/observation_count를 사용한다. [매핑과 예시](../../skills/numeric-observation-analysis/reference.md)를 따른다.

stable/unknown/stale는 모두 유효 계산 결과이므로 단계 status는 success다. 입구 오류로 보고서가 없으면 row를 만들지 않는다. 숫자 관찰만 분석한 경로는 이 요약으로 끝나며 play-run·펌웨어·세이브 분석 결과를 요구하지 않는다. 실제 화면이나 자동 플레이를 검증한 경우의 후속 계약과 구분한다.
