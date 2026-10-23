# pweh-play

사용자가 제공한 숫자 관찰 수열을 오프라인 요약하는 MCP 서버다. 현재 공개 도구는 `vision_validate` 하나다. 소유 또는 서면 허가가 기록된 케이스에 기존 숫자 합의 코어의 결과와 입력 digest를 저장한다.

등록 이름은 `pweh-play`, 실행 명령은 `pweh-play-mcp`(stdio)다. 프로젝트 Python 패키지 설치에 포함된다. 카메라·캡처 카드·OCR·입력 브리지·외부 실행 파일은 필요하지 않다.

## 사용

다음은 합성 표본이다. timestamp와 now는 같은 사용자 제공 초 단위 시간축이다.

```text
vision_validate(
  case_id=<소유·허가된 케이스>, input_kind="numeric-observations",
  observations=[
    {"timestamp":10.0,"value":120,"confidence":0.95},
    {"timestamp":10.5,"value":121,"confidence":0.90},
    {"timestamp":11.0,"value":120,"confidence":0.95},
    {"timestamp":11.5,"value":null,"confidence":0.90},
    {"timestamp":12.0,"value":120,"confidence":0.95}
  ], now=12.0
)
```

기본 정책이면 `stable/vote_consensus`, value120이다. `observations=[]`도 허용하며 `unknown/no_observations`를 저장한다.

| 인자 | 계약 |
|---|---|
| `case_id` | 소유·허가된 케이스 ID |
| `input_kind` | 필수, `numeric-observations`만 지원 |
| `observations` | 0..256개의 `{timestamp,value,confidence}`. 시각은 엄격 증가, 모두 now 이하 |
| `now` | 필수, 사용자가 표본과 같은 시간축으로 준 유한한 0..2**53초 |
| `policy` | null/생략 또는 닫힌 부분 정책. 생략 필드만 기존 기본값으로 확장 |

숫자 필드는 bool·숫자 문자열을 거부하며 value는 null 또는 int64만 받는다. JSON 문자열로 포장한 배열/정책 객체나 추가 필드도 거부한다. 정책·표본의 정확 범위는 [numeric-validation](../../docs/references/numeric-validation.md)에 있다.

## 결과와 저장

반환은 `{ok,report,artifact_id,analysis_path,sha256,size,warnings}`다. 보고서는 `pweh.numeric-validation/v1`, profile은 `supplied-numeric-observations-v1`이며 `analysis`에 기존 코어 결과 전체를 담는다.

- `analysis/numeric-observations-NNN.json`에 LF 포함 최대64KiB의0444 파일로 저장·등록한다. 처리·직렬화·저장은 worker 시작부터 같은5초 예산을 쓴다.
- 원 표본 배열·개별 timestamp/confidence는 결과·artifact metadata·감사에 저장하지 않는다. 합의 value·공급 now·정책·마지막 표본의 나이와 집계는 반환한다. 클라이언트의 원 요청 기록까지 통제한다는 뜻은 아니다.
- `source.canonical_sha256`는 제공된 입력의 결속이다. 익명화나 실제 화면 취득 출처의 증거가 아니다. 반환 `sha256`은 저장 보고서의 SHA다.
- commit 전 실패는 자신이 만든 동일 출력만 정리한다. commit 뒤 취소·감사 실패는 등록 결과를 보존하며 `post_commit_audit_failed` 경고가 있을 수 있다.
- stable/unknown/stale 모두 정상 계산 결과다. [numeric-observation-analysis Skill](../../skills/numeric-observation-analysis/SKILL.md)의 `numeric-analysis` 요약으로 기록한다. 실제 화면·게임 의미·자동 입력 검증을 뜻하지 않는다.

## 검증 범위

합성 숫자의 실제 MCP 호출→저장→요약→보고서, strict 입력·SDK 오류 원문 차단, canonical digest, 출력 FD 교체·취소·원자 등록을 검사한다. 코어는 `tests/core/test_vision_sequence.py`, 새 연결은 `tests/servers/test_numeric_validation_output.py`·`test_numeric_validation_mcp.py`, schema는 `tests/core/test_numeric_validation_schema.py`에서 검증한다. 화면 캡처·OCR·게임패드 입력·자동 플레이는 현재 지원 범위에 포함되지 않는다.
