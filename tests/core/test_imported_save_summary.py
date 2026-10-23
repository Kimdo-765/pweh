"""로컬 계획 요약은 기존 ESP 쓰기 결과와 구분되고 참조만 보존된다."""

import pytest

from pweh import schemas
from pweh.errors import ValidationFailed


def summary():
    return {"device": {"kind": "mcu-eeprom"}, "firmware": {"path": "dumps/save.bin"},
            "saves": [], "unlock_conditions": [], "online_capable": "unknown", "patches": []}


def result():
    return {"analysis_path": "patches/imported-save-plan-001/manifest.json",
            "report_sha256": "a" * 64, "patch_path": "patches/imported-save-plan-001/planned.bin",
            "patch_sha256": "b" * 64, "input_artifact_id": "A-0001", "stage": "planned"}


def test_old_esp_summary_and_optional_local_plans_remain_valid():
    old = summary()
    old["patches"] = [{"result_path": "analysis/patch-build-001.json", "stage": "ready",
                       "purpose": "score", "unlock_source": "in-device", "ledger_seq": 4}]
    old["existing_extension"] = "기존 추가 필드 호환"
    schemas.validate("save-analysis", old)
    schemas.validate("save-analysis", {**old, "local_plans": []})
    schemas.validate("save-analysis", {**old, "local_plans": [result()]})


@pytest.mark.parametrize("field", tuple(result()))
def test_local_plan_requires_all_reference_fields(field):
    row = result()
    del row[field]
    assert schemas.errors("save-analysis", {**summary(), "local_plans": [row]})


@pytest.mark.parametrize("field,value", [
    ("stage", "ready"), ("stage", "applied"), ("stage", "not-applied"), ("stage", "differs"),
    ("analysis_path", "analysis/patch-build-001.json"),
    ("analysis_path", "patches/imported-save-plan-000/manifest.json"),
    ("analysis_path", "patches/imported-save-plan-065/manifest.json"),
    ("analysis_path", "patches/imported-save-plan-001/manifest.json\n"),
    ("patch_path", "forensics/recovered/planned.bin"),
    ("patch_path", "patches/imported-save-plan-001/planned.bin\n"),
    ("input_artifact_id", "A-001"), ("input_artifact_id", "A-0001\n"),
    ("report_sha256", "A" * 64), ("report_sha256", "a" * 64 + "\n"),
    ("patch_sha256", None), ("patch_sha256", "b" * 63),
    ("write_ready", True), ("ledger_seq", 7), ("command", "private-command"),
    ("before_hex", "01020304"), ("after_hex", "05060708"), ("raw_path", "private-path"),
])
def test_local_plan_rejects_operational_claims_raw_values_and_bad_references(field, value):
    row = {**result(), field: value}
    assert schemas.errors("save-analysis", {**summary(), "local_plans": [row]})


def test_local_plan_reference_count_is_bounded():
    row = {**result(), "analysis_path": "patches/imported-save-plan-064/manifest.json",
           "patch_path": "patches/imported-save-plan-064/planned.bin", "input_artifact_id": "A-12345678"}
    schemas.validate("save-analysis", {**summary(), "local_plans": [row] * 64})
    with pytest.raises(ValidationFailed):
        schemas.validate("save-analysis", {**summary(), "local_plans": [row] * 65})


def test_case_summary_preserves_local_receipt_without_promoting_operational_state(workspace, auth):
    from pweh.runtime import get_runtime

    case = get_runtime("test").cases.create(title="합성 세이브 계획", authorization=auth)
    data = {**summary(), "local_plans": [result()]}
    recorded = case.record_step(skill="game-save-unlock-analysis", step="summary", status="success",
                                summary="로컬 계획 생성", data=data)
    assert recorded["data"] == data
    assert case.latest_summary("game-save-unlock-analysis")["data"] == data
    assert case.load()["phases"]["game-save-unlock-analysis"]["status"] == "done"
    bad = {**data, "local_plans": [{**result(), "stage": "ready"}]}
    with pytest.raises(ValidationFailed):
        case.record_step(skill="game-save-unlock-analysis", step="summary", status="success",
                         summary="잘못된 쓰기 준비 주장", data=bad)
    assert case.latest_summary("game-save-unlock-analysis")["data"] == data
