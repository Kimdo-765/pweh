"""이미 공급된 숫자 관찰의 유한 창에서 합의만 계산한다.

화면·파일·장치·시계를 읽지 않으며 OCR이나 입력 명령을 실행하지 않는다.
``stable``은 표본 숫자의 합의이고 프레임 신선도나 게임 의미의 검증이 아니다.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import ValidationFailed


MAX_OBSERVATIONS = 256
MAX_TIMESTAMP = 2**53
MAX_TTL_SECONDS = 86400
MIN_VALUE = -(2**63)
MAX_VALUE = 2**63 - 1
SCHEMA = "pweh.numeric-observations/v1"


@dataclass(frozen=True, slots=True)
class NumericPolicy:
    """숫자 합의의 조건. 실제 값 검증은 요약 호출마다 수행한다."""

    window_size: int = 5
    votes_required: int = 3
    min_valid: int = 3
    min_confidence: float = 0.8
    ttl_seconds: float = 2.0


@dataclass(frozen=True, slots=True)
class NumericObservation:
    """같은 monotonic seconds 축의 시각·숫자·신뢰도 표본."""

    timestamp: float
    value: int | None
    confidence: float


def _invalid(code: str) -> ValidationFailed:
    """원문·값·입력 객체의 표현을 포함하지 않는 고정 오류를 만든다."""
    messages = {
        "invalid_policy": "숫자 관찰 정책이 허용된 형식이나 범위를 벗어났습니다.",
        "invalid_observation": "숫자 관찰 입력이 허용된 형식·범위·시간 순서를 벗어났습니다.",
        "observation_limit": "숫자 관찰 입력 개수가 상한을 넘었습니다.",
    }
    return ValidationFailed(messages[code], code=code)


def _integer(value: object, lower: int, upper: int) -> bool:
    # bool·숫자 하위 클래스의 비교/변환을 실행하지 않는다.
    return type(value) is int and lower <= value <= upper


def _number(value: object, lower: int, upper: int) -> bool:
    # float 변환 전에 검사한다. NaN/Inf·거대한 int도 이 비교로 거부된다.
    return type(value) in (int, float) and lower <= value <= upper


def _policy_values(policy: NumericPolicy) -> dict:
    if type(policy) is not NumericPolicy:
        raise _invalid("invalid_policy")
    try:
        values = {
            "window_size": policy.window_size,
            "votes_required": policy.votes_required,
            "min_valid": policy.min_valid,
            "min_confidence": policy.min_confidence,
            "ttl_seconds": policy.ttl_seconds,
        }
    except AttributeError:
        raise _invalid("invalid_policy") from None
    size = values["window_size"]
    if (
        not _integer(size, 1, MAX_OBSERVATIONS)
        or not _integer(values["votes_required"], 1, size)
        or not _integer(values["min_valid"], 1, size)
        or not _number(values["min_confidence"], 0, 1)
        or not _number(values["ttl_seconds"], 0, MAX_TTL_SECONDS)
        or values["ttl_seconds"] == 0
    ):
        raise _invalid("invalid_policy")
    return values


def summarize_numeric_observations(
    observations: tuple[NumericObservation, ...] | list[NumericObservation],
    *,
    now: float,
    policy: NumericPolicy = NumericPolicy(),
) -> dict:
    """최근 M개→TTL→유효 투표 순으로 bounded snapshot을 요약한다.

    exact tuple/list와 exact dataclass만 받는다. 입력 전체를 검증한 뒤
    낮은 신뢰도·None도 차지하는 최근 M개에서 TTL 이내의 유효 값만 센다.
    동일 최다 득표는 unknown이며 동률이 없는 최다값만 임계값을 적용한다.
    """
    settings = _policy_values(policy)
    if type(observations) not in (tuple, list) or not _number(now, 0, MAX_TIMESTAMP):
        raise _invalid("invalid_observation")
    if len(observations) > MAX_OBSERVATIONS:
        raise _invalid("observation_limit")
    # exact list의 bounded slice를 복사하므로 외부 iterable을 소비하지 않는다.
    snapshot = tuple(observations[: MAX_OBSERVATIONS + 1])
    if len(snapshot) > MAX_OBSERVATIONS:
        raise _invalid("observation_limit")

    checked: list[tuple[int | float, int | None, int | float]] = []
    previous = None
    for observation in snapshot:
        if type(observation) is not NumericObservation:
            raise _invalid("invalid_observation")
        try:
            timestamp = observation.timestamp
            value = observation.value
            confidence = observation.confidence
        except AttributeError:
            raise _invalid("invalid_observation") from None
        if (
            not _number(timestamp, 0, MAX_TIMESTAMP)
            or (value is not None and not _integer(value, MIN_VALUE, MAX_VALUE))
            or not _number(confidence, 0, 1)
            or timestamp > now
            or (previous is not None and timestamp <= previous)
        ):
            raise _invalid("invalid_observation")
        checked.append((timestamp, value, confidence))
        previous = timestamp

    window = checked[-settings["window_size"] :]
    recent = [row for row in window if now - row[0] <= settings["ttl_seconds"]]
    votes: dict[int, int] = {}
    for _, value, confidence in recent:
        if value is not None and confidence >= settings["min_confidence"]:
            votes[value] = votes.get(value, 0) + 1
    valid_count = sum(votes.values())
    winning_votes = max(votes.values(), default=0)
    leaders = [value for value, count in votes.items() if count == winning_votes]

    status, reason, value = "unknown", "no_observations", None
    if checked:
        if not recent:
            status, reason = "stale", "no_recent_observations"
        elif valid_count < settings["min_valid"]:
            reason = "insufficient_valid"
        elif len(leaders) > 1:
            reason = "tied_votes"
        elif winning_votes < settings["votes_required"]:
            reason = "insufficient_votes"
        else:
            status, reason, value = "stable", "vote_consensus", leaders[0]

    return {
        "schema": SCHEMA,
        "status": status,
        "reason": reason,
        "value": value,
        "evidence": {
            "received_count": len(checked),
            "window_count": len(window),
            "recent_count": len(recent),
            "valid_count": valid_count,
            "winning_votes": winning_votes,
            "tied_leaders": len(leaders),
            "latest_age_seconds": now - checked[-1][0] if checked else None,
        },
        "policy": settings,
        "frame_freshness_verified": False,
        "game_semantics_verified": False,
        "action_generated": False,
    }
