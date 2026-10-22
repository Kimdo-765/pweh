"""후보 구간의 입구·고정 오류와 실제 합성 MCP의 마지막 seal을 검증한다."""
from __future__ import annotations

import json
import os
import time

import pytest
from mcp import Client

from forensics_mcp import media_candidate_tools as T
from mcp_helpers import call
from pweh import evidence as E
from pweh.errors import PwehError
from pweh.media_candidate_input import input_error

from .test_forensics_media_candidates_mcp import (
    CONTENT, PRIVATE, analyses, anyio_backend, mcase, prepare,
)

pytestmark = pytest.mark.anyio


def arguments(**updates):
    values = dict(evidence_id="EV-0001", partition=None, ref=None, path=None,
                  method="auto", max_seconds=45, offset=0, length=1)
    values.update(updates)
    return values


@pytest.mark.parametrize("updates", [
    {"offset": None}, {"length": None}, {"offset": True}, {"length": True},
    {"offset": 0.0}, {"length": 1.0}, {"offset": "0"}, {"length": PRIVATE},
    {"offset": -1}, {"length": 0}, {"length": -1}, {"length": (64 << 20) + 1},
    {"offset": 10**400}, {"length": 10**400}, {"offset": (1 << 63) - 1},
    {"offset": (1 << 63) - 2, "length": 2}, {"ref": "root/0"}, {"path": PRIVATE},
    {"partition": 1}, {"method": "chain"}, {"max_seconds": 0}, {"max_seconds": 46},
])
async def test_bad_range_is_rejected_before_case_and_read(updates):
    async def forbidden(*args):
        pytest.fail("잘못된 구간이 case 입구에 도달함")
    with pytest.raises(PwehError) as exc:
        await T._candidates_run(T._ServerAPI({"_case": forbidden}), case_id="synthetic", **arguments(**updates))
    assert exc.value.code == "validation_failed"
    assert PRIVATE not in str(exc.value) and not exc.value.data


@pytest.mark.parametrize("updates", [
    {}, {"offset": None, "length": None}, {"length": 64 << 20},
    {"offset": (1 << 63) - 2}, {"max_seconds": 1.5},
    {"offset": None, "length": None, "ref": "root/0", "partition": 1, "method": "chain"},
])
def test_valid_ingress_preserves_existing_and_exact_int_range(updates):
    before = time.monotonic()
    supplied = arguments(**updates)
    deadline = T._arguments(**supplied)
    assert before + supplied["max_seconds"] <= deadline <= time.monotonic() + supplied["max_seconds"]


@pytest.mark.parametrize(("internal", "public"), [
    ("media_prefix_input_invalid", "invalid_selection"),
    ("media_prefix_input_changed", "invalid_selection"),
    ("media_prefix_input_limit", "input_too_large"), ("timeout", "time_limit"),
    ("cancelled", "cancelled"), ("unregistered", "media_candidates_failed"),
])
def test_shared_reader_errors_have_fixed_candidate_projection(internal, public):
    error = T._fixed_error(PwehError(PRIVATE, code=internal, data={"raw": PRIVATE}))
    assert error.code == public and PRIVATE not in str(error) and not error.data


@pytest.mark.parametrize("key,value", [("offset", True), ("offset", 0.0), ("offset", PRIVATE),
                                       ("length", False), ("length", 1.0), ("length", PRIVATE)])
async def test_sdk_range_types_reject_without_input_echo(mcase, monkeypatch, key, value):
    from forensics_mcp import server as S
    async def forbidden(*args):
        pytest.fail("strict SDK 거부 전 case 접근")
    monkeypatch.setattr(S, "_case", forbidden)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_candidates", case_id=mcase.id,
                            evidence_id="EV-0001", **{"offset": 0, "length": 1, key: value})
    assert "_error" in result and PRIVATE not in json.dumps(result)


async def test_range_final_custody_seal_failure_leaves_no_report(mcase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    ev, _, _ = await prepare(mcase, tmp_path)
    original = E.store_analysis
    seen = []
    def changed(case, opened, *args, **kwargs):
        seen.append(opened.fd)
        os.fchmod(opened.fd, 0o644)
        return original(case, opened, *args, **kwargs)
    monkeypatch.setattr(E, "store_analysis", changed)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_candidates", case_id=mcase.id, evidence_id=ev,
                            offset=0, length=len(CONTENT))
    assert "integrity_failed" in result.get("_error", "")
    assert seen and not analyses(mcase)
    assert S.custody(mcase).entries()[-1]["event"] == "integrity-failed"
    with pytest.raises(OSError):
        os.fstat(seen[0])


async def test_range_partial_deadline_keeps_cancel_and_seal_at_commit(mcase, tmp_path, monkeypatch):
    from forensics_mcp import server as S
    from pweh import media_candidates as scanner
    ev, _, _ = await prepare(mcase, tmp_path)
    original_scan = scanner.scan_bmff_candidates
    original_check = T.selection.check_candidate_range
    checks = []
    def expire(data, **kwargs):
        kwargs["deadline"] = time.monotonic() - 1
        return original_scan(data, **kwargs)
    def check(opened, source, **kwargs):
        checks.append(kwargs["time_limit"] if "time_limit" in kwargs else True)
        return original_check(opened, source, **kwargs)
    monkeypatch.setattr(scanner, "scan_bmff_candidates", expire)
    monkeypatch.setattr(T.selection, "check_candidate_range", check)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_candidates", case_id=mcase.id, evidence_id=ev,
                            offset=0, length=len(CONTENT))
    assert result.get("ok"), result
    assert result["report"]["status"] == "partial"
    assert result["report"]["coverage"]["search_complete"] is False
    assert checks[0] is True and checks.count(False) >= 3
    assert len(analyses(mcase)) == 1


@pytest.mark.parametrize(("code", "expected"), [("media_prefix_input_changed", "invalid_selection"),
                                                 ("cancelled", "cancelled"), ("timeout", "time_limit")])
async def test_read_failure_saves_nothing_and_hides_raw_error(mcase, tmp_path, monkeypatch, code, expected):
    from forensics_mcp import server as S
    ev, _, _ = await prepare(mcase, tmp_path)
    def fail(*args, **kwargs):
        raise input_error(code)
    monkeypatch.setattr(T.selection, "read_candidate_range", fail)
    async with Client(S.server) as client:
        result = await call(client, "forensics_media_candidates", case_id=mcase.id, evidence_id=ev,
                            offset=0, length=len(CONTENT))
    assert expected in result.get("_error", ""), result
    assert not analyses(mcase) and PRIVATE not in json.dumps(result)
