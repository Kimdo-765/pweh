"""숫자 수열의 입력 경계·TTL·합의 의미를 합성 표본으로 확인한다."""

from dataclasses import FrozenInstanceError, replace
import json

import pytest

from pweh.errors import ValidationFailed
from pweh.vision_sequence import (
    MAX_OBSERVATIONS,
    MAX_TIMESTAMP,
    MAX_VALUE,
    MIN_VALUE,
    NumericObservation as Observation,
    NumericPolicy as Policy,
    summarize_numeric_observations as summarize,
)


def observations(values, *, start=0, confidence=1):
    return tuple(Observation(start + index, value, confidence) for index, value in enumerate(values))


def assert_error(call, code):
    with pytest.raises(ValidationFailed) as caught:
        call()
    assert caught.value.code == code
    assert caught.value.data == {}
    assert caught.value.hint is None
    assert set(caught.value.to_dict()) == {"code", "message"}


def test_empty_snapshot_is_unknown_with_closed_output():
    result = summarize((), now=0)
    assert set(result) == {
        "schema", "status", "reason", "value", "evidence", "policy",
        "frame_freshness_verified", "game_semantics_verified", "action_generated",
    }
    assert result["schema"] == "pweh.numeric-observations/v1"
    assert (result["status"], result["reason"], result["value"]) == (
        "unknown", "no_observations", None,
    )
    assert result["evidence"] == {
        "received_count": 0, "window_count": 0, "recent_count": 0,
        "valid_count": 0, "winning_votes": 0, "tied_leaders": 0,
        "latest_age_seconds": None,
    }


def test_reference_example_outlier_and_none():
    rows = (
        Observation(10.0, 120, 0.95),
        Observation(10.5, 121, 0.90),
        Observation(11.0, 120, 0.95),
        Observation(11.5, None, 0.90),
        Observation(12.0, 120, 0.95),
    )
    result = summarize(rows, now=12.0)
    assert (result["status"], result["reason"], result["value"]) == (
        "stable", "vote_consensus", 120,
    )
    assert result["evidence"] == {
        "received_count": 5, "window_count": 5, "recent_count": 5,
        "valid_count": 4, "winning_votes": 3, "tied_leaders": 1,
        "latest_age_seconds": 0.0,
    }
    assert result["frame_freshness_verified"] is False
    assert result["game_semantics_verified"] is False
    assert result["action_generated"] is False


def test_one_outlier_does_not_change_winner():
    result = summarize(observations([12, 12, 999, 12, 12]), now=4, policy=Policy(ttl_seconds=10))
    assert result["value"] == 12
    assert result["evidence"]["winning_votes"] == 4


@pytest.mark.parametrize("values", [(1, 1, 2, 2), (2, 2, 1, 1), (1, 2, 1, 2)])
def test_tie_never_prefers_recency_order_or_smallest_value(values):
    result = summarize(
        observations(values), now=3,
        policy=Policy(window_size=4, min_valid=4, votes_required=2, ttl_seconds=4),
    )
    assert (result["status"], result["reason"], result["value"]) == ("unknown", "tied_votes", None)
    assert result["evidence"]["winning_votes"] == 2
    assert result["evidence"]["tied_leaders"] == 2


def test_insufficient_valid_precedes_tie_and_votes():
    result = summarize(observations([1, 2, None]), now=2)
    assert result["reason"] == "insufficient_valid"
    assert result["evidence"]["tied_leaders"] == 2


def test_tie_precedes_insufficient_votes():
    result = summarize(observations([1, 2, 3]), now=2)
    assert result["reason"] == "tied_votes"


def test_unique_leader_below_votes_is_unknown():
    result = summarize(observations([5, 5, 6]), now=2)
    assert (result["reason"], result["value"]) == ("insufficient_votes", None)
    assert result["evidence"]["valid_count"] == 3
    assert result["evidence"]["winning_votes"] == 2


def test_explicit_policy_can_allow_plurality_below_majority():
    result = summarize(
        observations([1, 2, 3, 4, 4]), now=4,
        policy=Policy(votes_required=2, min_valid=5, ttl_seconds=4),
    )
    assert result["status"] == "stable"
    assert result["value"] == 4


def test_confidence_boundary_and_none_are_not_replaced_with_older_votes():
    rows = (
        Observation(0, 7, 1), Observation(1, 7, 1), Observation(2, 7, 1),
        Observation(3, 7, 0.799), Observation(4, None, 1), Observation(5, 7, 0.8),
    )
    result = summarize(rows, now=5, policy=Policy(window_size=3, ttl_seconds=10))
    assert result["reason"] == "insufficient_valid"
    assert result["evidence"]["window_count"] == 3
    assert result["evidence"]["recent_count"] == 3
    assert result["evidence"]["valid_count"] == 1


def test_ttl_boundary_is_inclusive_then_expired_values_are_not_reused():
    rows = observations([7, 7, 7])
    assert summarize(rows, now=2)["status"] == "stable"
    partial = summarize(rows, now=2.5)
    assert partial["reason"] == "insufficient_valid"
    assert partial["evidence"]["recent_count"] == 2
    expired = summarize(rows, now=5)
    assert (expired["status"], expired["reason"], expired["value"]) == (
        "stale", "no_recent_observations", None,
    )
    assert expired["evidence"]["latest_age_seconds"] == 3
    assert expired["evidence"]["winning_votes"] == 0


def test_recent_none_is_unknown_instead_of_old_stable_or_stale():
    result = summarize(observations([7, 7, 7, None, None, None]), now=5)
    assert (result["status"], result["reason"], result["value"]) == (
        "unknown", "insufficient_valid", None,
    )
    assert result["evidence"]["recent_count"] == 3
    assert result["evidence"]["valid_count"] == 0


@pytest.mark.parametrize("value", [MIN_VALUE, -10, 0, MAX_VALUE])
def test_signed_extreme_negative_and_reset_values_are_preserved(value):
    rows = observations([MAX_VALUE, 1, value, value, value])
    result = summarize(rows, now=4)
    assert result["value"] == value
    assert type(result["value"]) is int


def test_maximum_input_is_bounded_and_recent_window_wins():
    rows = observations(list(range(253)) + [-1, -1, -1])
    result = summarize(rows, now=255)
    assert result["value"] == -1
    assert result["evidence"]["received_count"] == MAX_OBSERVATIONS
    assert result["evidence"]["window_count"] == 5
    assert result["evidence"]["recent_count"] == 3
    assert len(json.dumps(result, allow_nan=False).encode()) < 2048


def test_maximum_policy_and_timestamp_are_accepted():
    rows = observations([MIN_VALUE] * 256, start=MAX_TIMESTAMP - 255)
    result = summarize(
        rows, now=MAX_TIMESTAMP,
        policy=Policy(window_size=256, min_valid=256, votes_required=256,
                      min_confidence=1, ttl_seconds=86400),
    )
    assert result["value"] == MIN_VALUE
    assert result["evidence"]["winning_votes"] == 256
    assert len(json.dumps(result, allow_nan=False).encode()) < 2048


def test_single_zero_time_and_zero_confidence_can_meet_explicit_policy():
    result = summarize(
        (Observation(0, 0, 0),), now=0,
        policy=Policy(window_size=1, votes_required=1, min_valid=1, min_confidence=0),
    )
    assert result["status"] == "stable"
    assert result["value"] == 0


@pytest.mark.parametrize("rows", [
    (Observation(1, 1, 1), Observation(1, 1, 1)),
    (Observation(2, 1, 1), Observation(1, 1, 1)),
    (Observation(4, 1, 1),),
])
def test_equal_backward_or_future_timestamp_is_invalid(rows):
    assert_error(lambda: summarize(rows, now=3), "invalid_observation")


def test_invalid_old_observation_is_not_hidden_outside_window():
    rows = (Observation(-1, 9, 1),) + observations([7, 7, 7])
    assert_error(lambda: summarize(rows, now=2, policy=Policy(window_size=3)), "invalid_observation")


INVALID_NUMBERS = [True, False, None, "0.5", float("nan"), float("inf"), -float("inf"), 2**100000]
NUMBER_IDS = ["true", "false", "none", "string", "nan", "inf", "negative-inf", "huge-int"]


@pytest.mark.parametrize("bad", INVALID_NUMBERS, ids=NUMBER_IDS)
@pytest.mark.parametrize("field", ["timestamp", "confidence"])
def test_invalid_observation_numbers_are_fixed_errors(field, bad):
    row = replace(Observation(0, None, 1), **{field: bad})
    assert_error(lambda: summarize((row,), now=1), "invalid_observation")


@pytest.mark.parametrize("bad", INVALID_NUMBERS, ids=NUMBER_IDS)
def test_invalid_now_numbers_are_fixed_errors(bad):
    assert_error(lambda: summarize((), now=bad), "invalid_observation")


@pytest.mark.parametrize("bad", [True, False, 0.0, "123", MIN_VALUE - 1, MAX_VALUE + 1])
def test_value_requires_exact_signed_64bit_int(bad):
    assert_error(lambda: summarize((Observation(0, bad, 1),), now=0), "invalid_observation")


@pytest.mark.parametrize("field,bad", [
    ("timestamp", -0.1), ("timestamp", MAX_TIMESTAMP + 1),
    ("confidence", -0.1), ("confidence", 1.1),
])
def test_observation_number_range(field, bad):
    row = replace(Observation(0, 1, 1), **{field: bad})
    assert_error(lambda: summarize((row,), now=MAX_TIMESTAMP), "invalid_observation")


@pytest.mark.parametrize("bad", [-1, MAX_TIMESTAMP + 1])
def test_now_range(bad):
    assert_error(lambda: summarize((), now=bad), "invalid_observation")


@pytest.mark.parametrize("field,bad", [
    ("window_size", 0), ("window_size", 257), ("window_size", True), ("window_size", 5.0),
    ("votes_required", 0), ("votes_required", 6), ("votes_required", False), ("votes_required", 3.0),
    ("min_valid", 0), ("min_valid", 6), ("min_valid", True), ("min_valid", 3.0),
    ("min_confidence", -0.1), ("min_confidence", 1.1),
    ("ttl_seconds", 0), ("ttl_seconds", -1), ("ttl_seconds", 86401),
])
def test_policy_integer_and_numeric_ranges(field, bad):
    assert_error(lambda: summarize((), now=0, policy=replace(Policy(), **{field: bad})), "invalid_policy")


@pytest.mark.parametrize("bad", INVALID_NUMBERS, ids=NUMBER_IDS)
@pytest.mark.parametrize("field", ["min_confidence", "ttl_seconds"])
def test_policy_rejects_invalid_numeric_types_and_nonfinite(field, bad):
    assert_error(lambda: summarize((), now=0, policy=replace(Policy(), **{field: bad})), "invalid_policy")


def test_overlong_sequence_is_rejected_before_elements_are_examined():
    assert_error(lambda: summarize([object()] * 257, now=0), "observation_limit")


def test_arbitrary_iterable_and_subclasses_never_run_callbacks():
    class Poison:
        def __iter__(self):
            raise AssertionError("임의 반복 실행")

        def __repr__(self):
            raise AssertionError("원문 표현 실행")

    class PoisonList(list):
        def __len__(self):
            raise AssertionError("하위 클래스 접근")

    class PoisonInt(int):
        def __le__(self, other):
            raise AssertionError("하위 클래스 비교")

    for rows in (Poison(), PoisonList(), {}, "private-value", None):
        assert_error(lambda: summarize(rows, now=0), "invalid_observation")
    for field in ("timestamp", "value", "confidence"):
        row = replace(Observation(0, 1, 1), **{field: PoisonInt(1)})
        assert_error(lambda: summarize((row,), now=1), "invalid_observation")
    assert_error(lambda: summarize((Poison(),), now=0), "invalid_observation")
    assert_error(lambda: summarize((), now=0, policy=Poison()), "invalid_policy")


def test_generator_is_not_consumed():
    reached = []

    def generate():
        reached.append(True)
        yield Observation(0, 1, 1)

    assert_error(lambda: summarize(generate(), now=0), "invalid_observation")
    assert reached == []


def test_dataclass_subclasses_and_uninitialized_instances_are_rejected():
    class OtherObservation(Observation):
        pass

    class OtherPolicy(Policy):
        pass

    for row in (OtherObservation(0, 1, 1), object.__new__(Observation)):
        assert_error(lambda: summarize((row,), now=0), "invalid_observation")
    for policy in (OtherPolicy(), object.__new__(Policy)):
        assert_error(lambda: summarize((), now=0, policy=policy), "invalid_policy")


def test_error_does_not_include_supplied_secret_or_repr():
    secret = "PWEH-SYNTHETIC-PRIVATE-123456"
    with pytest.raises(ValidationFailed) as caught:
        summarize((Observation(0, secret, 1),), now=0)
    assert secret not in str(caught.value)
    assert secret not in json.dumps(caught.value.to_dict())


def test_frozen_inputs_list_tuple_equivalence_and_no_result_state():
    rows = list(observations([7, 7, 7]))
    original = rows.copy()
    policy = Policy()
    with pytest.raises(FrozenInstanceError):
        rows[0].value = 100
    with pytest.raises(FrozenInstanceError):
        policy.window_size = 1
    first = summarize(rows, now=2, policy=policy)
    assert first == summarize(tuple(rows), now=2, policy=policy)
    assert rows == original
    first["policy"]["votes_required"] = 1
    first["evidence"]["winning_votes"] = 99
    second = summarize(rows, now=2, policy=policy)
    assert second["policy"]["votes_required"] == 3
    assert second["evidence"]["winning_votes"] == 3
    assert summarize((), now=2)["value"] is None
