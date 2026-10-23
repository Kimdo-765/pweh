# 숫자 분석 결과와 요약 연결

도구 반환은 `ok`, `report`, `artifact_id`, `analysis_path`, `sha256`, `size`, `warnings`다.
`report.source.canonical_sha256`는 입력 digest, 반환 `sha256`은 **저장된 보고서**의 SHA256이므로 구분한다.

| numeric-analysis의 results row | 실제 응답 |
|---|---|
| `artifact_id` | `artifact_id` |
| `analysis_path` | `analysis_path` |
| `report_sha256` | `sha256` |
| `status` | `report.analysis.status` |
| `reason` | `report.analysis.reason` |
| `observation_count` | `report.source.observation_count` |

results는1..128개이며 원 표본·now·합의값을 요약에 다시 저장하지 않는다. [Skill의 요약 예시](SKILL.md#요약)에 있는 자리표시자는 실제 응답으로 대체한다.

`unknown`과`stale`도 유효한 분석 결과다. 다음 조합만 사용한다.

| status | reason |
|---|---|
| `stable` | `vote_consensus` |
| `unknown` | `no_observations`, `insufficient_valid`, `tied_votes`, `insufficient_votes` |
| `stale` | `no_recent_observations` |

`post_commit_audit_failed`는 이미 등록된 결과를 보존한 채 감사 후처리가 실패했다는 경고다. 경로·SHA·artifact ID를 보존하고, 실패한 입력으로 다시 분류하거나 출력 파일을 삭제하지 않는다. 분석·저장 전체는 worker 시작부터 같은5초 예산을 사용한다. 커널 I/O를 강제로 중단한다는 보장은 아니다.
