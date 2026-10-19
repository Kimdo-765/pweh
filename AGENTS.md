# PWEH 프로젝트 규칙 (모든 에이전트 공통)

PWEH 는 에이전트가 MCP 서버와 Skill 로 CCTV/IoT 기기의 하드웨어 보안 분석을 수행하는 파이프라인이다.
대상은 **사용자가 소유했거나 서면 허가를 받은 기기**뿐이다.

## 기기를 분석하는 경우 (운영 모드)
- 시작점: `orchestrator/master-prompt.md` (Claude Code `/pweh-start`, Codex `$pweh-start`). 그 안의 절대 규칙을 따른다.
- 소유/허가를 사용자에게 확인받고 `case_create` 하기 전에는 하드웨어 도구를 쓰지 않는다.
- 서버 응답이 `approval_required` 이면 사용자에게 설명하고, 사람이 별도 터미널에서 `pweh approve <id>` 하도록 요청한다.
  `attestation_required`(사람 증명)이면 확인할 사실을 설명하고 사람이 `pweh attest <id>` 로 답하게 한다. `denied` 이면 우회하지 않는다.
  - 에이전트는 `pweh approve`·`pweh attest` 를 실행하지 않는다.
  - `.pweh/state/` 의 승인·증명(attestations)·출처(provenance)·솔트·감사 로그와 `orchestrator/pipeline-config.yaml` 의 `safety` 를 수정하지 않는다.
- U-Boot 프롬프트에서 빈 Enter 를 보내지 않는다 (직전 명령 반복). 새 프롬프트는 Ctrl-C(`uart_sync`)로 얻는다.
- 물리 작업(배선·전원·클립)은 사람에게 구체적으로 요청하고 완료 확인 후 진행한다.
  근거 문서: `docs/hardware-setup.md`, `docs/safety.md`.
- 모든 결과는 케이스(`cases/<id>/`)에 기록한다. 각 Skill 은 끝날 때 `case_record_step(step="summary")` 를 호출한다.

## 이 저장소를 개발하는 경우 (개발 모드)
- 계약 문서: `docs/architecture.md` (서버별 도구 이름/인자/반환, 케이스 구조, 안전 모델, 코딩·테스트 규칙).
- 주석·docstring·도구 설명·문서는 한국어, 식별자와 기술 용어는 영어.
- 서버 패턴: `mcp-servers/case-mcp/case_mcp/server.py`.
  - `create_server`, `@server.tool` + `@safe_tool`.
  - 기기 영향 도구는 `rt().case(case_id, hardware=True)` → 분류기 → `await rt().authorize(...)` → `gate_response`.
  - 블로킹 I/O 는 `run_blocking`, 장시간 작업은 `rt().jobs` + `register_job_tools`.
- stdout 은 MCP 채널이다 (`print` 금지).
- 도구를 추가·변경하면 `.venv/bin/python scripts/dump_tool_catalog.py` 로 `docs/references/pweh-mcp-tools.{json,md}` 를 다시 만들고,
  `--check` 로 `.claude/settings.json` 권한 규칙과 Skill 문서의 도구 이름을 검사한다. `docs/architecture.md` §6 표도 함께 고친다.
- 테스트: `.venv/bin/pytest -q`. 하드웨어 없이 `pweh.mocktarget` 시뮬레이터, 가짜 OpenOCD 서버, 합성 신호를 쓴다.
  외부 도구 테스트는 `@pytest.mark.external` 로 표시하고, 도구가 없으면 skip 한다.
  실제 하드웨어가 필요한 테스트는 `@pytest.mark.hardware` 로 표시한다(기본 skip, `--run-hardware` 또는 `PWEH_HARDWARE=1` 로 실행).
- 외부 도구는 `~/pweh-tools/env.sh` 에 있다 (`scripts/install.sh` 로 sudo 없이 설치, 위치 규칙은 `src/pweh/toolsdir.py`).
- `cases/`, `.pweh/` 는 커밋하지 않는다.
