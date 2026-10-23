"""CU가 관찰한 페이지 snapshot의 순수 검증·집계·비교. 파일·태그·원장은 열지 않는다."""
from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass
from typing import Callable

from . import cu_protocol as CU
from .errors import PwehError
from .nfc_formats import _NfcFileIdentity

SNAPSHOT_SCHEMA = "pweh.nfc-cu-snapshot/v1"
SNAPSHOT_PROFILE = "cu-ntag21x-pages-v1"
ANALYSIS_PROFILE = "cu-ntag21x-snapshot-analysis-v1"
MAX_INPUT_BYTES = 65536
BINDING_FIELDS = ("tag_ref", "scan_ref", "identity_digest", "scan_seq", "scan_entry_sha256",
                  "inventory_seq", "inventory_entry_sha256")
UNOBSERVED_FIELDS = ("signature", "counters", "tearing")
FALSE_FIELDS = ("snapshot_atomic", "physical_same_tag_verified", "device_command_termination_verified",
                "rf_off_verified", "host_crc_verified", "tag_content_written",
                "authentication_attempted", "emulation_performed")
LIMITATIONS = ("stored_page_responses_only", "validated_prefix_pages_only",
               "signature_counters_tearing_unobserved", "password_pack_readback_not_observable",
               "snapshot_not_atomic", "physical_same_tag_not_verified",
               "console_causality_not_verified", "no_tag_authorization_inferred")
_FAMILIES = {item.family: item for item in CU.NtagFamily}
_READER = {"profile": CU.PROFILE, "profile_sha256": CU.PROFILE_SHA256,
           "firmware_commit": CU.FIRMWARE_COMMIT, "app_version": CU.FIRMWARE_VERSION,
           "git_version": CU.FIRMWARE_GIT_VERSION}
_TOP = {"schema", "profile", "binding", "reader", "identity", "pages_total", "pages",
        "pages_observed", "read_complete", "stop_reason", "unobserved_fields", *FALSE_FIELDS}
_TYPED_FIELDS = {"identity", "pages", "binding", "family", "pages_total", "pages_observed",
                 "read_complete", "stop_reason", "input_size"}
_clock = time.monotonic


@dataclass(frozen=True, repr=False)
class CuSnapshot:
    """검사한 내부 값만 보유한다. 원문 identity/pages/binding을 repr로 내보내지 않는다."""

    identity: _NfcFileIdentity
    pages: tuple[bytes | None, ...]
    binding: tuple[tuple[str, str | int], ...]
    family: str
    pages_total: int
    pages_observed: int
    read_complete: bool
    stop_reason: str | None
    input_size: int


def _error(code: str = "nfc_snapshot_invalid") -> PwehError:
    return PwehError("CU 페이지 snapshot 검사를 완료하지 못했습니다.", code=code)


def _require(value: bool, code: str = "nfc_snapshot_invalid") -> None:
    if not value:
        raise _error(code)


class _Control:
    def __init__(self, deadline: float, cancel: Callable[[], bool] | None):
        finite = False
        if type(deadline) in (int, float):
            try:
                finite = math.isfinite(deadline)
            except OverflowError:
                pass
        _require(finite and (cancel is None or callable(cancel)), "nfc_input_invalid")
        self.deadline, self.cancel = deadline, cancel

    def check(self, *, partial: bool = False, time_limit: bool = True) -> bool:
        failed, cancelled = False, False
        if self.cancel is not None:
            try:
                result = self.cancel()
                if type(result) is bool:
                    cancelled = result
                else:
                    failed = True
            except Exception:
                failed = True
        # callback 예외 문맥을 벗어난 뒤 고정 오류만 만든다.
        if failed:
            raise _error("nfc_failed")
        if cancelled:
            raise _error("cancelled")
        if time_limit and _clock() >= self.deadline:
            if partial:
                return False
            raise _error("time_limit")
        return True


class _InvalidJson(Exception):
    """JSON hook에서 원문 없이 실패한 사실만 옮긴다."""


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise _InvalidJson()
        result[key] = value
    return result


def _not_integer(value: str) -> None:
    raise _InvalidJson()


def _preflight(data: bytes, control: _Control) -> None:
    """decode 전에 문자열/escape와 container를 구분해 깊이·value 수·숫자 폭을 제한한다."""
    stack: list[int] = []
    quoted, escaped, previous, nodes, cursor, next_check = False, False, None, 0, 0, 0
    while cursor < len(data):
        if cursor >= next_check:
            control.check()
            next_check = cursor + 4096
        char = data[cursor]
        _require(char < 128)
        if quoted:
            _require(char >= 32)
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted, previous = False, 34
            cursor += 1
            continue
        if char in (32, 9, 10, 13):
            cursor += 1
            continue
        if char == 34:
            # 문법상 객체 key인 문자열은 value node에 중복 산입하지 않는다.
            if not (stack and stack[-1] == 123 and previous in (123, 44)):
                nodes += 1
            quoted = True
        elif char in (123, 91):
            nodes += 1
            stack.append(char)
            _require(len(stack) <= 8, "nfc_input_limit")
            previous = char
        elif char in (125, 93):
            _require(bool(stack) and stack[-1] == (123 if char == 125 else 91))
            stack.pop()
            previous = char
        elif char in (58, 44):
            previous = char
        elif char == 45 or 48 <= char <= 57:
            end = cursor + 1
            while end < len(data) and data[end] not in b" \t\r\n,]}:":
                _require(end - cursor < 20, "nfc_input_limit")
                end += 1
            token = data[cursor:end]
            _require(re.fullmatch(rb"-?(?:0|[1-9][0-9]*)", token) is not None)
            nodes += 1
            previous, cursor = 48, end
            _require(nodes <= 2048, "nfc_input_limit")
            continue
        else:
            literal = next((x for x in (b"true", b"false", b"null")
                            if data.startswith(x, cursor)), None)
            _require(literal is not None)
            nodes += 1
            previous, cursor = char, cursor + len(literal)
            _require(nodes <= 2048, "nfc_input_limit")
            continue
        _require(nodes <= 2048, "nfc_input_limit")
        cursor += 1
    _require(not quoted and not stack)
    control.check()


def _tree(value: object, control: _Control, *, depth: int = 0) -> int:
    control.check()
    _require(depth <= 8, "nfc_input_limit")
    if type(value) is dict:
        children = value.values()
        _require(all(type(key) is str for key in value))
    elif type(value) is list:
        children = value
    else:
        _require(value is None or type(value) in (str, int, bool))
        return 1
    nodes = 1
    for item in children:
        nodes += _tree(item, control, depth=depth + 1)
        _require(nodes <= 2048, "nfc_input_limit")
    return nodes


def _object(value: object, keys: tuple[str, ...] | set[str]) -> None:
    _require(type(value) is dict and set(value) == set(keys))


def _hex(value: object, size: int) -> bytes:
    _require(type(value) is str and len(value) == size * 2
             and re.fullmatch(r"[0-9a-f]+", value) is not None)
    return bytes.fromhex(value)


def _binding(value: object, control: _Control) -> tuple[tuple[str, str | int], ...]:
    _object(value, BINDING_FIELDS)
    patterns = {"tag_ref": r"NT-[0-9a-f]{32}", "scan_ref": r"NS-[0-9a-f]{32}",
                "identity_digest": r"sha256:[0-9a-f]{16}",
                "scan_entry_sha256": r"[0-9a-f]{64}", "inventory_entry_sha256": r"[0-9a-f]{64}"}
    for key in BINDING_FIELDS:
        control.check()
        item = value[key]
        if key in ("scan_seq", "inventory_seq"):
            _require(type(item) is int and 1 <= item <= (1 << 63) - 1)
        else:
            _require(type(item) is str and re.fullmatch(patterns[key], item) is not None)
    return tuple((key, value[key]) for key in BINDING_FIELDS)


def _checked(snapshot: CuSnapshot, control: _Control) -> None:
    """typed 생성자를 우회한 값도 같은 유한 관계 검사로 닫는다."""
    _require(type(snapshot) is CuSnapshot, "nfc_input_invalid")
    control.check()
    _require(set(vars(snapshot)) == _TYPED_FIELDS)
    _require(type(snapshot.family) is str and len(snapshot.family) == 7 and snapshot.family in _FAMILIES)
    model = _FAMILIES[snapshot.family]
    _require(type(snapshot.pages_total) is int and snapshot.pages_total == model.pages_total)
    _require(type(snapshot.pages_observed) is int and 2 <= snapshot.pages_observed <= snapshot.pages_total)
    _require(type(snapshot.input_size) is int and 1 <= snapshot.input_size <= MAX_INPUT_BYTES)
    _require(type(snapshot.read_complete) is bool)
    if snapshot.read_complete:
        _require(snapshot.stop_reason is None and snapshot.pages_observed == snapshot.pages_total)
    else:
        _require(type(snapshot.stop_reason) is str and snapshot.stop_reason in ("time_limit", "nfc_scan_invalid"))
    identity = snapshot.identity
    _require(type(identity) is _NfcFileIdentity)
    _require(set(vars(identity)) == {"uid", "atqa_msb", "sak", "mifare_version", "profile"})
    _require(type(identity.uid) is bytes and len(identity.uid) == 7
             and type(identity.atqa_msb) is bytes and identity.atqa_msb == b"\x00\x44"
             and type(identity.sak) is bytes and identity.sak == b"\x00"
             and type(identity.mifare_version) is bytes and identity.mifare_version == model.mifare_version
             and type(identity.profile) is str and identity.profile == snapshot.family)
    _require(type(snapshot.binding) is tuple and len(snapshot.binding) == len(BINDING_FIELDS))
    for pair, key in zip(snapshot.binding, BINDING_FIELDS):
        _require(type(pair) is tuple and len(pair) == 2 and type(pair[0]) is str and pair[0] == key)
    _binding(dict(snapshot.binding), control)
    _require(type(snapshot.pages) is tuple and len(snapshot.pages) == snapshot.pages_total)
    for index, page in enumerate(snapshot.pages):
        control.check()
        if index < snapshot.pages_observed:
            _require(type(page) is bytes and len(page) == 4)
        else:
            _require(page is None)
    first, second = snapshot.pages[:2]
    _require(first[:3] + second == identity.uid)
    _require(first[3] == (0x88 ^ identity.uid[0] ^ identity.uid[1] ^ identity.uid[2]))
    control.check()


def parse_cu_snapshot(data: bytes, *, deadline: float,
                      cancel: Callable[[], bool] | None = None) -> CuSnapshot:
    """닫힌 서버 snapshot 전체를 검증해 내부 불변 값만 반환한다."""
    control = _Control(deadline, cancel)
    _require(type(data) is bytes, "nfc_input_invalid")
    _require(len(data) <= MAX_INPUT_BYTES, "nfc_input_limit")
    control.check()
    _preflight(data, control)
    invalid = False
    value = None
    try:
        value = json.loads(data.decode("ascii"), object_pairs_hook=_pairs,
                           parse_float=_not_integer, parse_constant=_not_integer)
    except (ValueError, UnicodeError, _InvalidJson, RecursionError):
        invalid = True
    if invalid:
        raise _error()
    _tree(value, control)
    _object(value, _TOP)
    _require(value["schema"] == SNAPSHOT_SCHEMA and value["profile"] == SNAPSHOT_PROFILE)
    _object(value["reader"], set(_READER))
    _require(value["reader"] == _READER)
    _require(value["unobserved_fields"] == list(UNOBSERVED_FIELDS))
    _require(all(value[key] is False for key in FALSE_FIELDS))
    identity = value["identity"]
    _object(identity, {"family", "uid", "atqa_msb", "sak", "mifare_version"})
    _require(type(value["pages"]) is list and len(value["pages"]) <= 231)
    pages = []
    for page in value["pages"]:
        control.check()
        pages.append(None if page is None else _hex(page, 4))
    result = CuSnapshot(
        _NfcFileIdentity(_hex(identity["uid"], 7), _hex(identity["atqa_msb"], 2),
                         _hex(identity["sak"], 1), _hex(identity["mifare_version"], 8), identity["family"]),
        tuple(pages), _binding(value["binding"], control), identity["family"], value["pages_total"],
        value["pages_observed"], value["read_complete"], value["stop_reason"], len(data),
    )
    _checked(result, control)
    return result


def _report(operation: str, partial: bool, summary: dict, coverage: dict) -> dict:
    return {"schema_version": 1, "operation": operation, "status": "partial" if partial else "ok",
            "profile": ANALYSIS_PROFILE, "summary": summary, "coverage": coverage,
            "limitations": list(LIMITATIONS)}


def _read_summary(snapshot: CuSnapshot) -> dict:
    return {"pages_observed": snapshot.pages_observed, "read_complete": snapshot.read_complete,
            "stop_reason": snapshot.stop_reason}


def inspect_cu_snapshot(snapshot: CuSnapshot, *, deadline: float,
                        cancel: Callable[[], bool] | None = None) -> dict:
    """전체 JSON 검증과 관찰 페이지 수를 구별한 원문 없는 집계를 반환한다."""
    control = _Control(deadline, cancel)
    _checked(snapshot, control)
    summary = {"family": snapshot.family, "pages_total": snapshot.pages_total,
               **_read_summary(snapshot), "unobserved_fields": list(UNOBSERVED_FIELDS)}
    coverage = {"input_bytes": snapshot.input_size, "consumed_bytes": snapshot.input_size,
                "unexamined_bytes": 0, "input_exhausted": True,
                "pages_unobserved": snapshot.pages_total - snapshot.pages_observed,
                "reasons": [] if snapshot.read_complete else ["read_partial"]}
    control.check()
    return _report("inspect", not snapshot.read_complete, summary, coverage)


def diff_cu_snapshots(before: CuSnapshot, after: CuSnapshot, *, deadline: float,
                      cancel: Callable[[], bool] | None = None) -> dict:
    """공통 관찰 페이지의 변경 위치만 비교한다. 비교 중 시간 한도만 partial로 마감한다."""
    control = _Control(deadline, cancel)
    _checked(before, control)
    _checked(after, control)
    _require(before.family == after.family and before.pages_total == after.pages_total
             and before.binding == after.binding and before.identity == after.identity,
             "nfc_source_mismatch")
    compared = before_only = after_only = neither = processed = 0
    changed = []
    for index, (old, new) in enumerate(zip(before.pages, after.pages)):
        if not control.check(partial=True):
            break
        if old is not None and new is not None:
            compared += 1
            if old != new:
                changed.append(index)
        elif old is not None:
            before_only += 1
        elif new is not None:
            after_only += 1
        else:
            neither += 1
        processed += 1
    # 끝난 비교를 늦은 시각으로 뒤집지 않되 취소/실패는 계속 확인한다.
    control.check(time_limit=False)
    remaining = before.pages_total - processed
    complete = remaining == 0
    read_complete = before.read_complete and after.read_complete
    summary = {"family": before.family, "pages_total": before.pages_total,
               "before": _read_summary(before), "after": _read_summary(after),
               "pages_compared": compared, "before_only_pages": before_only,
               "after_only_pages": after_only, "neither_observed_pages": neither,
               "comparison_unexamined_pages": remaining, "changed_pages": changed,
               "stored_pages_equal": not changed if complete and read_complete else None}
    size = before.input_size + after.input_size
    coverage = {"input_bytes": size, "consumed_bytes": size, "unexamined_bytes": 0,
                "comparison_complete": complete, "changes_complete": complete,
                "changed_pages_count_is_lower_bound": not complete,
                "reasons": ([] if read_complete else ["read_partial"]) + ([] if complete else ["time_limit"])}
    return _report("diff", not (read_complete and complete), summary, coverage)
