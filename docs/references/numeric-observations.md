# 숫자 관찰 수열의 합의 모델

`pweh.vision_sequence`는 이미 공급된 숫자 표본을 요약하는 순수 내부 코어다.
파일·화면·카메라·시계·장치·네트워크를 읽지 않고 OCR·프로세스·게임 입력을 실행하지 않는다.
MCP 도구나 `pweh-play` 연결은 없다. 호출자가 같은 monotonic seconds 축의 표본과 `now`를 제공한다.

## API와 입력

```python
from pweh.vision_sequence import (
    NumericObservation,
    NumericPolicy,
    summarize_numeric_observations,
)

observations = (
    NumericObservation(10.0, 120, 0.95),
    NumericObservation(10.5, 121, 0.90),
    NumericObservation(11.0, 120, 0.95),
    NumericObservation(11.5, None, 0.90),
    NumericObservation(12.0, 120, 0.95),
)
result = summarize_numeric_observations(observations, now=12.0)
assert (result["status"], result["value"]) == ("stable", 120)
```

두 dataclass는 frozen이며 값 검증은 요약 호출에서 수행한다.
exact `tuple`·`list`의 최대 256개 exact `NumericObservation`만 받는다. 하위 클래스·dict·generator·임의 iterable은 거부한다.
최근 창에서 제외될 표본도 모두 검증하며 원래 입력을 변경하지 않는다.

| 입력 | 허용 범위 |
|---|---|
| `timestamp`, `now` | exact int/float, 유한한 0..2**53초. 표본 시각은 엄격 증가하고 모두 `now` 이하 |
| `value` | `None` 또는 부호 있는 64비트 exact int. 음수·감소·0으로 리셋도 허용 |
| `confidence` | exact int/float, 유한한 0..1. `value=None`에도 필요 |
| `window_size` | exact int 1..256, 기본 5 |
| `votes_required`, `min_valid` | exact int 1..window_size, 각각 기본 3 |
| `min_confidence` | 유한한 exact int/float 0..1, 기본 0.8 |
| `ttl_seconds` | 유한한 exact int/float 0 초과..86400초, 기본 2.0 |

모든 숫자 필드에서 bool을 거부한다. 큰 정수를 float로 변환하지 않고 범위부터 검사한다.
시간은 공급된 Python 숫자의 비교·뺄셈 의미를 사용하며 실세계 시각이나 증거 획득 시각으로 해석하지 않는다.

## 창·TTL·투표

1. 전체 입력을 검증한 뒤 가장 최근 `window_size`개를 고른다.
2. 그 안에서 `now - timestamp <= ttl_seconds`인 표본만 남긴다. 경계와 같은 나이는 포함한다.
3. `None`과 낮은 confidence는 창의 자리를 차지하지만 투표하지 않는다. 창 밖의 오래된 표본으로 빈자리를 채우지 않는다.
4. 아래 우선순위로 상태를 정한다. 최다 득표가 유일하고 두 개수 조건을 만족하면 그 입력 값을 그대로 반환한다. 평균·중간값은 만들지 않는다.

| 우선순위 | 조건 | status / reason |
|---|---|---|
| 1 | 입력 없음 | `unknown` / `no_observations` |
| 2 | 시간 창에 남은 표본 없음 | `stale` / `no_recent_observations` |
| 3 | 유효 투표 수 < min_valid | `unknown` / `insufficient_valid` |
| 4 | 최다 득표 값이 둘 이상 | `unknown` / `tied_votes` |
| 5 | 유일한 최다 득표 < votes_required | `unknown` / `insufficient_votes` |
| 6 | 그 외 | `stable` / `vote_consensus` |

`votes_required`는 명시적인 표 수 기준이다. 사용자 정책이 과반수보다 작으면 유일한 최다값이 소수 표로도 통과할 수 있다.
동률은 최근 값·작은 값·먼저 등장한 값으로 해소하지 않는다. unknown/stale의 `value`는 항상 null이며 이전 stable 값을 재사용하지 않는다.

## 반환과 한계

닫힌 dict의 `schema`는 `pweh.numeric-observations/v1`이다. `status`·`reason`·`value`와 검증한 `policy`, 다음 `evidence`만 반환한다.

| evidence 필드 | 의미 |
|---|---|
| `received_count` | 검증한 전체 표본 수 |
| `window_count` | TTL 적용 전 최근 M개 수 |
| `recent_count` | TTL 이내의 표본 수(None·낮은 신뢰도 포함) |
| `valid_count` | 실제 투표 수 |
| `winning_votes` | 최다 득표 수, 투표가 없으면 0 |
| `tied_leaders` | 최다 득표 값의 개수. 유일하면 1, 투표가 없으면 0 |
| `latest_age_seconds` | 마지막 입력의 나이. stale이어도 표시하고 빈 입력만 null |

원시 표본·후보 값 목록은 반환하지 않는다. `frame_freshness_verified`, `game_semantics_verified`, `action_generated`는 항상 false다.
숫자 합의는 동일 화면의 반복 여부·멈춘 영상·실제 점수·버튼 입력 허용을 판정하지 않는다.
단조 증가 같은 게임별 규칙은 이 코어의 전제가 아니다. ROI·영상 소스·입력 브리지·게임별 정책은 후속 범위다.

잘못된 정책은 `ValidationFailed(code="invalid_policy")`, 잘못된 표본/시각은 `invalid_observation`, 256개 초과는 `observation_limit`이다.
오류 문구는 고정이며 표본·값·입력 repr를 포함하지 않는다. 캐시·전역 누적·상태 저장은 없다.
