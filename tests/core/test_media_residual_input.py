"""보관 사건에 결속된 residual 후보의 의미 검사와 기존 report fd 수명 시험."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
import time
from types import SimpleNamespace

import pytest

from core.test_evidence import _commit_intake
from core.test_media_residual_schema import KINDS, report_for, sample, schema_name
from pweh import evidence as E, media_candidate_input as B, dhav_candidate_input as D, media_unit_input as U
from pweh.case import CaseStore
from pweh.errors import PwehError


@pytest.fixture
def prepared(workspace, auth):
    case = CaseStore(workspace["cases_dir"]).create(
        title="합성 residual 입력", authorization=auth, case_id="residual-input")
    log = E.CustodyLog(case, workspace["state_dir"] / "custody")
    with contextlib.ExitStack() as stack:
        def make(kind, mutate=None, *, partial=False):
            data = sample(kind)
            ev = _commit_intake(case, log, b"synthetic-evidence" + data)
            opened = stack.enter_context(E.open_checked(case, ev, log.entries()))
            report = report_for(kind, data=data, ev=ev, evidence_sha=opened.intake["hashes"]["sha256"])
            if partial:
                report["source"]["parent_deleted"] = None
                report["coverage"]["selection_uncertain"] = True
                report["coverage"]["reasons"].append("selection_uncertain")
                report["status"] = "partial"
            stored = E.store_analysis(case, opened, report, event=schema_name(kind), custody_log=log)
            relative = stored["analysis"]["path"]
            entries = log.entries()
            if mutate is not None:
                mutate(report)
                raw = (json.dumps(report) + "\n").encode()
                target = case.dir / relative
                target.chmod(0o644)
                target.write_bytes(raw)
                target.chmod(0o444)
                entries[-1]["data"]["analysis"].update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                entries[-1]["data"].update(source=copy.deepcopy(report["source"]),
                                            params=copy.deepcopy(report["params"]), status=report["status"])
            return SimpleNamespace(case=case, log=log, opened=opened, kind=kind,
                                   report=report, path=relative, entries=entries)
        yield make


def load(value, **updates):
    opener = B.open_media_candidate if value.kind == "bmff" else (
        D.open_dhav_candidate if value.kind == "dhav" else U.open_media_unit_candidate)
    args = dict(analysis_path=value.path, candidate_index=0, entries=value.entries,
                deadline=time.monotonic() + 20, cancel=lambda: False)
    args.update(updates)
    return opener(value.case, value.opened, **args)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("explicit_method", [False, True])
def test_real_custody_bound_residual_keeps_relative_coordinates(prepared, kind, explicit_method):
    mutate = (lambda r: r["params"].update(method=r["source"]["method"])) if explicit_method else None
    value = prepared(kind, mutate)
    with load(value) as candidate:
        assert candidate.source == value.report["source"] and len(candidate.source) == 19
        assert candidate.candidate == value.report["candidates"][0]
        assert candidate.candidate["offset"] == 0
        assert candidate.source["valid_data_length"] == 37
        assert "offset" not in candidate.source and "evidence_size" not in candidate.source
        assert candidate.coverage == value.report["coverage"]
        candidate.check()
        candidate.check_entries(value.entries)
        fd = candidate._fd
    with pytest.raises(OSError):
        os.fstat(fd)
    assert os.fstat(value.opened.fd).st_size > 0


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("change", [
    "dl", "vdl", "equal-vdl", "float-dl", "float-vdl", "float-size", "float-partition",
    "bool-vdl", "partition", "method", "range-key", "region", "missing-region", "profile", "limitation",
])
def test_schema_valid_numbers_and_source_params_relations_are_checked(prepared, kind, change):
    def mutate(report):
        source, params = report["source"], report["params"]
        if change == "dl":
            source["data_length"] += 1
        elif change == "vdl":
            source["valid_data_length"] -= 1
        elif change == "equal-vdl":
            source["valid_data_length"] = source["data_length"]
        elif change.startswith("float-"):
            key = {"float-dl": "data_length", "float-vdl": "valid_data_length", "float-size": "selected_size"}.get(change)
            if key:
                source[key] = float(source[key])
            else:
                params["partition"] = 1.0
        elif change == "bool-vdl":
            source["valid_data_length"] = True
        elif change == "partition":
            params["partition"] = 2
        elif change == "method":
            params["method"] = "chain"
        elif change == "range-key":
            source["offset"] = 0
        elif change == "region":
            params["region"] = "data"
        elif change == "missing-region":
            del source["region"]
        elif change == "profile":
            report["profile"] = report_for(kind, mode="file")["profile"]
        else:
            report["limitations"][-1] = "outside_range_unexamined"
    value = prepared(kind, mutate)
    with pytest.raises(PwehError) as error:
        with load(value):
            pass
    assert error.value.code == ("media_prefix_input_invalid" if kind == "bmff" else (
        "dhav_record_input_invalid" if kind == "dhav" else "media_unit_input_invalid"))


@pytest.mark.parametrize("kind", KINDS)
def test_original_selection_uncertainty_is_not_promoted_by_residual(prepared, kind):
    value = prepared(kind, partial=True)
    with load(value) as candidate:
        assert candidate.source["parent_deleted"] is None
        assert candidate.upstream_status == "partial"
        assert candidate.coverage["selection_uncertain"] is True
        assert "selection_uncertain" in candidate.coverage["reasons"]


@pytest.mark.parametrize("kind", KINDS)
def test_final_report_name_swap_keeps_old_fd_and_rejects_commit(prepared, kind):
    value = prepared(kind)
    with load(value) as candidate:
        target = value.case.dir / value.path
        original_inode = os.fstat(candidate._fd).st_ino
        contents = target.read_bytes()
        target.unlink()
        target.write_bytes(contents)
        target.chmod(0o444)
        assert os.fstat(candidate._fd).st_ino == original_inode
        with pytest.raises(PwehError) as error:
            candidate.check()
        assert error.value.code.endswith("input_changed")
