---
name: numeric-observation-analysis
description: 소유·허가된 PWEH 케이스에서 사용자가 제공한 숫자 관찰 수열을 vision_validate로 요약하고 numeric-analysis 결과를 기록한다. 숫자 표본의 시간 창·신뢰도·투표 합의, unknown·stale 상태 분석에 사용한다. 화면 캡처·OCR·자동 플레이는 수행하지 않는다.
---

# 제공된 숫자 관찰 분석

사용자가 제공한 표본의 합의를 계산하고 케이스에 기록한다. 장비·펌웨어·화면 세션은 필요하지 않다. 입력·저장 계약은 [numeric-validation](../../docs/references/numeric-validation.md), 투표 규칙은 [숫자 모델](../../docs/references/numeric-observations.md)을 따른다.

## 실행

1. `case_get`으로 소유·허가된 케이스를 확인하고 `case_get_step_results`로 이전 결과를 읽는다. 이미 확인한 허가를 다시 묻지 않는다. 케이스가 없으면 `pweh-start`의 접수 절차를 따른다.
2. `observations`와 평가점 `now`가 같은 사용자 제공 monotonic seconds 축인지 확인한다. 표본은 최대256개이며 각 원소는 `timestamp`, `value`, `confidence`를 모두 가진다. 없는 표본·시각·신뢰도를 측정한 사실처럼 채우거나 정렬·잘라내기로 잘못된 입력을 숨기지 않는다. 정책은 생략하면 도구 기본값을 사용한다.
3. `vision_validate(case_id, input_kind="numeric-observations", observations=..., now=..., policy=...)`를 호출한다. `now`를 현재 UTC나 호스트 시각으로 바꾸지 않는다. 별도 파일 가져오기·캡처·포트 연결은 없다.
4. `report.analysis`의 `status`, `reason`, `value`, `evidence`, `policy`를 함께 설명한다. 생성된 경로·SHA·artifact ID는 실제 응답 값을 사용한다.

## 결과 해석

- `stable`은 공급 표본에서 정책을 만족한 유일한 최다 득표값이다. 실제 점수·화면 상태·입력 허용의 증거로 쓰지 않는다. 정책이 과반수보다 낮으면 소수 표의 최다값도 통과할 수 있다.
- `unknown`은 표본 없음·유효 표 부족·동률·득표 부족이다. `stale`은 제공된 시간축에서 최근 창의 표본이 모두 TTL을 넘었다는 뜻이다. 두 상태의 value는 null이며 이전 stable 값을 가져오지 않는다.
- 원 표본 배열·개별 timestamp/confidence는 이 결과에 저장되지 않는다. 합의 value, 공급 now, 확장 policy, 마지막 표본의 나이·집계는 의도한 출력이다. digest를 익명화·독립 획득·실제 화면 신선도 증명이라고 설명하지 않는다.
- `frame_freshness_verified`, `game_semantics_verified`, `action_generated`는 항상 false다. 이 결과로 자동 입력이나 새 플레이 작업을 시작하지 않는다.

## 요약

`schema_get(name="numeric-analysis")`를 확인하고 `case_record_step(skill="numeric-observation-analysis", step="summary", status="success", ...)`로 마친다. stable/unknown/stale는 모두 계산을 마친 정상 결과이며 원래 상태·이유를 그대로 기록한다. 이 경로의 완료 조건은 numeric-analysis 요약이고 미래의 play-run이나 세이브·펌웨어 요약을 만들지 않는다.

실제 응답과 요약 필드의 연결은 [reference.md](reference.md)에 있다. 입구 오류로 결과가 없으면 `step="attempt"`에 고정 오류를 기록하고 결과 row를 꾸미지 않는다. 취소된 호출은 commit 뒤 결과가 남을 수 있으므로 `case_get(include_artifacts=true)`로 등록 여부를 확인한다. 최종 보고서가 필요하면 `report_generate`로 케이스 기록을 모은다.

아래 ID·경로·해시는 자리표시자이며 실제 응답으로 대체한다.

```json
{
  "schema": "pweh.numeric-analysis/v1",
  "mode": "supplied-numeric-observations",
  "results": [{
    "artifact_id": "A-0001",
    "analysis_path": "analysis/numeric-observations-001.json",
    "report_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "status": "stable",
    "reason": "vote_consensus",
    "observation_count": 5
  }],
  "frame_freshness_verified": false,
  "game_semantics_verified": false,
  "action_generated": false
}
```
