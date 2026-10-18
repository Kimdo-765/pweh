"""PWEH 종단(e2e) 테스트: 스크립트 에이전트가 실제 MCP 서버를 Skill 순서대로 호출하고, 결과를 시뮬레이터 정답과 대조한다.

흐름 (tests/e2e/agent_flow.py, skills/*/SKILL.md 의 호출 순서):
  case_create(authorization) → uart_list_ports → uart_open → [사람: 전원] uart_capture_boot → [사람: 재투입] uboot_interrupt
  → uboot_printenv/uboot_info → case_record_step(uart-shell-acquisition)
  → (세션 재사용) uboot_printenv/uboot_info → 시험 덤프 + uboot_dump_start + uart_job_status → fw_identify·교차 확인
  → case_record_step(firmware-dump-via-uart)
  → fw_identify/fw_entropy/fw_uboot_env/fw_carve/fw_uimage_info/fw_extract_squashfs/fw_rootfs_audit/fw_strings_hunt/fw_elf_info/fw_crack_hashes
  → (external) REA extract_firmware + open_binary(ghidra) + trace_feature/search_procedures/procedure_pseudo_code + export_evidence_bundle
  → case_add_finding … → case_record_step(firmware-static-analysis, cctv-auth-bypass-hunt) → report_generate

정답(ground truth)은 합성 펌웨어 매니페스트의 planted_issues 다. 에이전트 흐름은 매니페스트를 읽지 않고,
테스트가 기록된 도구 출력(관찰)으로 "모든 정답이 적어도 하나의 도구 출력에 드러났는지" 확인한다.
안전 오라클: MockDevice.destructive_events 는 항상 [] 이어야 한다.

시간: slow 를 뺀 e2e(`-m "not slow"`)는 약 2~3분. 전체 플래시 덤프와 dahua-like REA 는 slow 이고 기본 실행에 포함된다.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from e2e.agent_flow import (
    AgentFlow,
    Human,
    McpHub,
    Recorder,
    Scenario,
    build_firmware,
    flash_bytes,
    match_planted,
    rea_available,
    run_pipeline,
    start_device,
    tool_path,
)
from pweh import schemas

pytestmark = pytest.mark.anyio

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _close_sessions(workspace):
    yield
    from uart_mcp import server as us

    us.shutdown_all("e2e teardown")


@pytest.fixture(scope="session")
def fw_images(tmp_path_factory):
    """프로필별 전체 합성 펌웨어 (zig httpd + squashfs). 도구가 없거나 대체 빌드면 skip."""
    if not tool_path("PWEH_ZIG", "zig") or not tool_path("PWEH_MKSQUASHFS", "mksquashfs") or not tool_path("PWEH_UNSQUASHFS", "unsquashfs"):
        pytest.skip("zig/mksquashfs/unsquashfs 가 없어 전체 합성 펌웨어로 e2e 를 돌릴 수 없음")
    out = tmp_path_factory.mktemp("e2e-fw")
    cache: dict[str, tuple[Path, dict[str, Any]]] = {}

    def get(profile: str) -> tuple[Path, dict[str, Any]]:
        if profile not in cache:
            path, manifest = build_firmware(profile, out)
            if manifest.get("fallbacks"):
                pytest.skip(f"{profile}: 대체 빌드({manifest['fallbacks']}) — 정답 파일 배치가 달라 e2e 대상 아님")
            cache[profile] = (path, manifest)
        return cache[profile]

    return get


# ---------------------------------------------------------------------------
# 공통 검사
# ---------------------------------------------------------------------------
def validate_case_outputs(case_dir: Path) -> dict[str, dict[str, Any]]:
    """steps/*.json (step-result + summary data 스키마) 와 findings.json (finding 스키마) 검증. 반환: skill → 최신 summary."""
    problems: list[str] = []
    summaries: dict[str, dict[str, Any]] = {}
    for p in sorted((case_dir / "steps").glob("*.json")):
        st = json.loads(p.read_text(encoding="utf-8"))
        problems += [f"{p.name}: {e}" for e in schemas.errors("step-result", st)]
        if st.get("step") == "summary":
            name = schemas.SKILL_DATA_SCHEMAS.get(st["skill"])
            assert name, f"알 수 없는 skill summary: {st['skill']}"
            problems += [f"{p.name} data: {e}" for e in schemas.errors(name, st.get("data"))]
            summaries[st["skill"]] = st
    for f in load_findings(case_dir):
        problems += [f"{f.get('id')}: {e}" for e in schemas.errors("finding", f)]
    assert not problems, "\n".join(problems)
    return summaries


def load_findings(case_dir: Path) -> list[dict[str, Any]]:
    path = case_dir / "findings.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("findings", []) if isinstance(data, dict) else data


def coverage_report(coverage: dict[str, list[Any]]) -> str:
    return "\n".join(f"{iid}: {[o.brief() for o in obs[:3]] or '드러나지 않음'}" for iid, obs in coverage.items())


def assert_no_plaintext_secrets(case_dir: Path, manifest: dict[str, Any]) -> None:
    """보고서·발견사항에 긴 비밀값(합성 백도어 토큰, 내장 관리자 비밀번호)이 평문으로 남지 않는다 (safety.md §7)."""
    cred = manifest.get("credentials") or {}
    secrets = [cred.get("backdoor_token"), (cred.get("web_admin") or {}).get("password")]
    for name in ("report.md", "findings.json"):
        text = (case_dir / name).read_text(encoding="utf-8")
        for s in secrets:
            if s and len(s) >= 8:
                assert s not in text, f"{name} 에 비밀값 평문: {s[:4]}…"


def assert_pipeline_result(res: Any, *, profile: str, require_rea: bool = False) -> None:
    flow: AgentFlow = res.flow
    case_dir = flow.case_dir
    planted = res.manifest["planted_issues"]
    # 1) 안전 오라클
    assert res.dev_destructive == [], res.dev_destructive
    # 2) 덤프 무결성: 이미지 파일의 같은 범위 바이트와 sha256 일치 + 기기 측 crc32 검증
    plan, dump = flow.st["dump_plan"], flow.st["dump"]
    assert dump["sha256"] == hashlib.sha256(flash_bytes(res.image_path, plan["offset"], plan["length"])).hexdigest()
    assert dump["size"] == plan["length"]
    meta = flow.st["dump_meta"]
    assert meta["method"] == "uboot-md" and meta["verification"]["method"] == "crc32-chunks" and meta["verification"]["match"] is True
    if plan["offset"] == 0 and plan["length"] == res.manifest["image"]["size"]:
        assert dump["sha256"] == res.manifest["image"]["sha256"]
    # 3) 모든 요약과 발견사항이 스키마를 통과
    summaries = validate_case_outputs(case_dir)
    assert {"uart-shell-acquisition", "firmware-dump-via-uart", "firmware-static-analysis", "cctv-auth-bypass-hunt"} <= set(summaries)
    ah = summaries["cctv-auth-bypass-hunt"]["data"]
    assert [c["id"] for c in ah["checks"][:12]] == [f"AH-{i:02d}" for i in range(1, 13)]
    assert ah["vendor_family"] == {"hikvision-like": "hikvision-like", "dahua-like": "dahua-like"}.get(profile, "hisilicon-oem")
    # 4) 정답: 모든 planted issue 가 적어도 하나의 도구 출력에 드러남 (평가는 기록된 출력으로만)
    missing = [iid for iid, obs in res.coverage.items() if not obs]
    assert not missing, f"드러나지 않은 정답: {missing}\n{coverage_report(res.coverage)}"
    assert {p["id"] for p in planted} == set(res.coverage)
    # 5) 각 정답에 대응하는 발견사항 (같은 파일·같은 분류)
    findings = load_findings(case_dir)
    for issue in planted:
        match = [f for f in findings if (f.get("location") or {}).get("file") == issue["file"] and f["category"] == issue["category"]]
        assert match, f"{issue['id']} ({issue['file']}, {issue['category']}) 에 대응하는 발견사항 없음: {[(f['id'], f['title']) for f in findings]}"
        if require_rea and issue.get("function"):
            fn = [f for f in match if (f.get("location") or {}).get("function") == issue["function"]]
            assert fn and fn[0]["confidence"] == "confirmed" and fn[0]["status"] == "static-confirmed", (issue["id"], match)
    # 6) 보고서에 발견사항이 실린다
    report = (case_dir / "report.md").read_text(encoding="utf-8")
    for f in findings:
        assert f"### {f['id']}. {f['title']}" in report, f["id"]
    assert "## 9. 안전 게이트 및 감사 요약" in report
    assert_no_plaintext_secrets(case_dir, res.manifest)
    # 7) 정리: 실행 중 job 없음, 세션 닫힘
    assert flow.st["uart_jobs_active"].get("jobs") == []
    assert all(s.get("state") != "open" for s in flow.st["uart_sessions_end"].get("sessions") or [])
    assert (flow.st["fw_jobs_active"].get("jobs") or []) == []


# ---------------------------------------------------------------------------
# 1. U-Boot 경로 전체 파이프라인 (REA 없이 — fwtriage 휴리스틱만으로 모든 정답이 드러나야 한다)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("profile", ["hisilicon-like", "hikvision-like", "dahua-like"])
async def test_uboot_pipeline_e2e(workspace, fw_images, profile, tmp_path):
    image, manifest = fw_images(profile)
    res = await run_pipeline(profile, image, manifest, scenario=Scenario(title=f"e2e {profile}"), use_rea=False,
                             dump_scope="needed", chunk_size="256k")
    assert_pipeline_result(res, profile=profile)
    flow = res.flow
    # REA 없이 돌았다는 사실이 요약에 정직하게 남는다
    sa = json.loads(next((flow.case_dir / "steps").glob("*firmware-static-analysis-summary.json")).read_text(encoding="utf-8"))
    assert sa["status"] == "partial" and sa["data"]["rea"]["provider"] is None and sa["data"]["rea"]["limitations"]
    # 디컴파일 없이 얻은 후보는 confirmed 로 올리지 않는다 (문자열 근거만 있는 항목)
    for f in load_findings(flow.case_dir):
        if all(e["type"] in ("string", "triage") for e in f["evidence"]) and f["category"] in ("backdoor", "command-injection", "auth-bypass"):
            assert f["confidence"] in ("possible", "likely"), f
    if profile == "hisilicon-like":
        # 예제 생성기(scripts/run_example.py)의 패키징이 같은 결과로 동작하는지 확인
        spec = importlib.util.spec_from_file_location("run_example", REPO / "scripts" / "run_example.py")
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        out = tmp_path / "example"
        mod.package_example(res, out, name="e2e-sample", workspace_root=workspace["root"], command="pytest tests/e2e")
        files = {p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()}
        assert {"README.md", "summary.json", "tool-calls.jsonl", "case/case.json", "case/findings.json", "case/report.md",
                "case/excluded-files.json"} <= files
        assert not any(f.endswith((".bin", ".raw")) for f in files)
        assert not any(f.startswith("case/extract/") for f in files)
        blob = "\n".join((out / f).read_text(encoding="utf-8", errors="replace") for f in files)
        assert str(workspace["root"]) not in blob
        assert manifest["credentials"]["backdoor_token"] not in blob
        assert manifest["credentials"]["web_admin"]["password"] not in blob
        calls = [json.loads(ln) for ln in (out / "tool-calls.jsonl").read_text(encoding="utf-8").splitlines()]
        assert len(calls) == len(res.rec.calls) and {c["server"] for c in calls} >= {"pweh-case", "pweh-uart", "pweh-fwtriage"}


# ---------------------------------------------------------------------------
# 2. 전체 플래시 16 MiB 덤프 (slow)
# ---------------------------------------------------------------------------
@pytest.mark.slow
async def test_uboot_pipeline_full_flash_slow(workspace, fw_images):
    image, manifest = fw_images("hisilicon-like")
    res = await run_pipeline("hisilicon-like", image, manifest, scenario=Scenario(title="e2e full flash"), use_rea=False,
                             dump_scope="full", chunk_size="256k")
    assert_pipeline_result(res, profile="hisilicon-like")
    flow = res.flow
    assert flow.st["dump"]["sha256"] == manifest["image"]["sha256"] == hashlib.sha256(image.read_bytes()).hexdigest()
    assert flow.st["dump"]["size"] == 16 * 1024 * 1024
    # 전체 덤프면 app(설정) 파티션도 분할·추출되고 추출 상태가 complete
    assert flow.st["extract_extra"] and flow.st["extract_extra"][0]["status"] == "complete"
    sa = json.loads(next((flow.case_dir / "steps").glob("*firmware-static-analysis-summary.json")).read_text(encoding="utf-8"))
    assert sa["data"]["extraction"]["status"] == "complete"


# ---------------------------------------------------------------------------
# 3. REA + Ghidra 를 포함한 파이프라인 (external)
# ---------------------------------------------------------------------------
@pytest.mark.external
@pytest.mark.parametrize("profile", ["hikvision-like", pytest.param("dahua-like", marks=pytest.mark.slow)])
async def test_pipeline_with_rea_external(workspace, fw_images, profile):
    ok, why = rea_available()
    if not ok:
        pytest.skip(f"REA 를 쓸 수 없음: {why}")
    image, manifest = fw_images(profile)
    res = await run_pipeline(profile, image, manifest, scenario=Scenario(title=f"e2e rea {profile}"), use_rea=True,
                             dump_scope="needed", chunk_size="256k", rea_cwd=workspace["root"])
    if not res.rea_used:
        pytest.skip(f"REA 기동 실패: {res.rea_error}")
    assert_pipeline_result(res, profile=profile, require_rea=True)
    flow = res.flow
    # 함수가 정해진 정답은 REA 디컴파일(procedure_pseudo_code) 출력에 그 함수가 나와야 한다
    for issue in manifest["planted_issues"]:
        if issue.get("function"):
            dec = [o for o in res.coverage[issue["id"]] if o.tool == "procedure_pseudo_code" and o.function == issue["function"]]
            assert dec, f"{issue['id']}: {issue['function']} 디컴파일 관찰 없음\n{coverage_report(res.coverage)}"
    # 바이너리마다 증거 묶음이 rea-evidence 아티팩트로 등록되고, REA 세션은 닫혔다
    case = json.loads((flow.case_dir / "case.json").read_text(encoding="utf-8"))
    bundles = [a["path"] for a in case.get("artifacts", []) if a.get("kind") == "rea-evidence"]
    assert sorted(bundles) == sorted(flow.rea_bundles) and len(bundles) == 2
    for b in bundles:
        data = json.loads((flow.case_dir / b).read_text(encoding="utf-8"))
        assert data, b
    assert flow.st.get("rea_current") is None
    assert any(c.tool == "close_binary" for c in res.rec.calls) and any(c.tool == "extract_firmware" for c in res.rec.calls)
    sa = json.loads(next((flow.case_dir / "steps").glob("*firmware-static-analysis-summary.json")).read_text(encoding="utf-8"))
    assert sa["status"] == "success" and sa["data"]["rea"]["provider"] == "ghidra"
    # 벤더 스타일 정답에 대응하는 점검표 항목은 디컴파일 근거로 match
    ah = json.loads(next((flow.case_dir / "steps").glob("*cctv-auth-bypass-hunt-summary.json")).read_text(encoding="utf-8"))["data"]
    verdict = {c["id"]: c["result"] for c in ah["checks"][:12]}
    want = {"hikvision-like": ("AH-01", "AH-04", "AH-05", "AH-07", "AH-08"), "dahua-like": ("AH-02", "AH-03", "AH-05", "AH-07", "AH-08")}[profile]
    assert all(verdict[a] == "match" for a in want), verdict


# ---------------------------------------------------------------------------
# 4. 리눅스 셸 경로: 부팅 로그 → shell_login → shell_identify → shell_dump_start(/dev/mtd3)
# ---------------------------------------------------------------------------
async def test_linux_shell_path_e2e(workspace, fw_images):
    from uart_mcp import server as us

    image, manifest = fw_images("hisilicon-like")
    rec = Recorder()
    dev, port = start_device("hisilicon-like", image)
    login = manifest["credentials"]["console_login"]  # 사람(소유자)이 알려 준 계정
    try:
        async with McpHub(rec) as hub:
            flow = AgentFlow(hub, Human(dev, rec), profile="hisilicon-like", port=port, scenario=Scenario(title="e2e shell path"),
                             chunk_size="256k")
            await flow.run_shell_path(username=login["username"], password=login["password"], mtd="/dev/mtd3")
    finally:
        us.shutdown_all("e2e shell")
        destructive = list(dev.destructive_events)
        dev.stop()
    assert destructive == []
    case_dir = flow.case_dir
    summaries = validate_case_outputs(case_dir)
    recon = summaries["uart-shell-acquisition"]["data"]
    assert recon["console_type"] == "linux-shell" and recon["access_level"] == "root-shell"
    assert [m["name"] for m in recon["linux"]["mtd"]][:4] == ["boot", "env", "kernel", "rootfs"]
    dump = summaries["firmware-dump-via-uart"]["data"]
    rootfs = next(p for p in manifest["partitions"] if p["name"] == "rootfs")
    assert dump["method"] == "linux-base64" and dump["verification"] == {"method": "md5-device", "match": True}
    assert dump["output"]["sha256"] == hashlib.sha256(flash_bytes(image, rootfs["offset"], rootfs["size"])).hexdigest()
    assert dump["source"]["device_path"] == "/dev/mtd3" and dump["source"]["partition"] == "rootfs"
    # 비밀번호는 로그·이벤트·감사 기록에 평문으로 남지 않는다
    pw = login["password"]
    for f in list((case_dir / "uart").glob("*.log")) + list((case_dir / "uart").glob("*.events.jsonl")) + [case_dir / "audit.jsonl"]:
        text = f.read_text(encoding="utf-8")
        assert f"{pw}\\r" not in text and f'"{pw}"' not in text, f
    assert any(c.tool == "shell_login" for c in rec.calls)
    assert (case_dir / "report.md").exists()


# ---------------------------------------------------------------------------
# 5. 안전: 파이프라인 중간의 에이전트 실수(saveenv, sf erase, 분할 쓰기, flash_erase …)는 거부되고 흐름은 계속된다
# ---------------------------------------------------------------------------
async def test_safety_agent_mistakes_mid_pipeline(workspace, fw_images):
    from uart_mcp import server as us

    image, manifest = fw_images("hisilicon-like")
    rec = Recorder()
    dev, port = start_device("hisilicon-like", image)
    login = manifest["credentials"]["console_login"]
    try:
        async with McpHub(rec) as hub:
            flow = AgentFlow(hub, Human(dev, rec), profile="hisilicon-like", port=port, scenario=Scenario(title="e2e safety"),
                             dump_scope="env", chunk_size="32k")
            await flow.phase0_intake()
            await flow.phase_a_uboot()
            uboot_mistakes = await flow.mistakes_uboot()
            await flow.record_recon_uboot()
            await flow.phase_b_dump(close_after=False)  # 실수 뒤에도 읽기 전용 덤프는 계속 된다
            await flow.record_dump()
            ident = await flow.boot_linux_and_login(username=login["username"], password=login["password"])
            shell_mistakes = await flow.mistakes_shell()
            after = await hub.call("pweh-uart", "uart_send_command", session_id=flow.st["session_id"], command="cat /proc/mtd")
            await hub.call("pweh-uart", "uart_close", session_id=flow.st["session_id"])
            await flow.phase_e_report()
    finally:
        us.shutdown_all("e2e safety")
        destructive = list(dev.destructive_events)
        dev.stop()
    # 모든 파괴적 시도는 거부되었고 기기에 닿지 않았다
    denied = [m for m in uboot_mistakes + shell_mistakes if m["command"].startswith(("saveenv", "sf ", "setenv", "env ", "uart_write", "flash_",
                                                                                         "dd ", "fw_setenv"))]
    assert denied and all(m["status"] == "denied" and m["ok"] is False for m in denied), denied
    assert destructive == []
    assert not any("saveenv" in (e.get("line") or "") for e in dev.commands())
    # 흐름은 계속됐다: 실수 뒤의 덤프·셸 명령이 정상
    env_part = next(p for p in manifest["partitions"] if p["name"] == "env")
    assert flow.st["dump"]["sha256"] == hashlib.sha256(flash_bytes(image, env_part["offset"], env_part["size"])).hexdigest()
    assert ident["ok"] and after["ok"] and 'mtd1: 00010000 00010000 "env"' in after["output"]
    validate_case_outputs(flow.case_dir)
    # 감사 기록과 보고서에 거부 결정이 남는다
    audit = [json.loads(ln) for ln in (flow.case_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    rules = {(e.get("classification") or {}).get("rule_id") for e in audit if e.get("event") == "safety_decision" and e.get("status") == "denied"}
    assert "uboot.saveenv" in rules and len(rules) >= 3, rules
    report = (flow.case_dir / "report.md").read_text(encoding="utf-8")
    assert "denied" in report.split("## 9. 안전 게이트 및 감사 요약", 1)[1]


def test_match_planted_is_not_circular():
    """평가기는 같은 파일 + (같은 함수 또는 지표 문자열)일 때만 드러난 것으로 본다 (빈 관찰 → 모두 미발견)."""
    from e2e.agent_flow import Observation

    planted = [{"id": "X-1", "file": "/usr/bin/a", "function": "f", "pattern": 'strcmp(x, "magic-literal") → 1', "category": "backdoor"}]
    assert match_planted(planted, []) == {"X-1": []}
    other_file = Observation(1, "s", "fw_strings_hunt", "/usr/bin/b", None, "backdoor", "id", "magic-literal")
    assert match_planted(planted, [other_file]) == {"X-1": []}
    same = Observation(2, "s", "fw_strings_hunt", "/usr/bin/a", None, "backdoor", "id", "... magic-literal ...")
    assert match_planted(planted, [same])["X-1"] == [same]
