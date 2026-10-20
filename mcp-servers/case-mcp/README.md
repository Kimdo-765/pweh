# pweh-case (case-mcp)

PWEH 오케스트레이션 레이어의 MCP 서버다. 분석 작업 하나를 **케이스**(`cases/<case_id>/`)로 만들고,
소유/허가 증명, Skill 단계 결과, 아티팩트, 발견사항, 보고서를 관리한다. Skill 사이의 데이터 전달은 이 서버가 관리하는
케이스 파일로 이루어진다. 세션이 끊겨도 케이스만 있으면 이어서 할 수 있다.

- 코드: `case_mcp/server.py`(도구). 케이스 저장소·스키마·보고서는 공통 코어 `src/pweh/case.py`, `src/pweh/schemas/`, `src/pweh/report.py` 에 있다.
- 계약: `docs/architecture.md` §3(케이스 디렉터리), §6.1(도구). 인자·설명 원문: `docs/references/pweh-mcp-tools.md`
- 실행: `pweh-case-mcp` 또는 `python -m case_mcp` (stdio)
- 테스트: `tests/servers/test_case_mcp.py`
- 다른 PWEH 서버가 따르는 **참조 구현**이다(`create_server`, `@server.tool` + `@safe_tool`, 반환은 항상 `{"ok": True, ...}` 딕셔너리).

---

## 1. 도구

| 도구 | 설명 / 반환 |
|---|---|
| `case_create(title, authorization, target=None, profile=None, case_id=None, notes=None)` | 새 케이스. `authorization` 필수: `{basis: "owned"\|"written-authorization", owner, statement, scope?, document_ref?}`. `statement` 는 사용자가 소유/허가를 확인한 말을 그대로 인용하고, 서면 허가면 `document_ref` 가 필수다. `profile` 생략 시 `generic-ipcam` |
| `case_set_authorization(case_id, authorization)` | 소유/허가 증명 기록·갱신 (`case_create` 와 같은 형식) |
| `case_list()` | 케이스 목록 (읽기 전용) |
| `case_get(case_id, include_artifacts=False, include_steps=False)` | 케이스 요약(대상, 권한 여부, 단계 상태, 아티팩트/단계/발견사항 수) (읽기 전용) |
| `case_update_target(case_id, target)` | 대상 정보 갱신 (예: UART 로 알아낸 SoC/플래시/펌웨어 버전) |
| `case_set_phase(case_id, phase, status, note=None)` | 단계 상태 수동 갱신. `phase`: `uart-shell-acquisition`, `firmware-dump-via-uart`, `logic-analyzer-protocol-decode`, `firmware-static-analysis`, `cctv-auth-bypass-hunt`, `report`(파이프라인 단계 — 새 케이스에 `pending` 으로 있음) 또는 선택 단계(`pweh.case.OPTIONAL_PHASES` — 다른 목표의 Skill 용, 처음 기록할 때 생김. architecture §3). 이름은 검사하지 않는다. `status`: `pending`, `in-progress`, `done`, `partial`, `failed`, `skipped`, `blocked` |
| `case_add_note(case_id, text, author="agent")` | 자유 형식 메모 (사람이 한 물리 작업, 관찰 등). `case.json` 의 `notes` 에 저장 |
| `case_paths(case_id, purpose="extract", label="run")` | 케이스 표준 하위 경로(절대 경로)와 외부 도구에 넘길 **아직 없는** 새 출력 디렉터리 `new_output_dir` (`<purpose>/<label>-NNN`). REA `extract_firmware` 의 `output_directory` 에 쓴다 (읽기 전용) |
| `case_record_step(case_id, skill, step, status, summary, data=None, artifacts=None, next_actions=None, blockers=None, started_at=None)` | Skill 단계 결과 저장 → `steps/NNNN-<skill>-<step>.json`. `step="summary"` 면 `data` 를 그 Skill 의 출력 스키마로 검증하고, 맞지 않으면 거부한다. `status`: `success`\|`partial`\|`failed`\|`blocked`\|`skipped`\|`in-progress`. `artifacts` 는 케이스 상대 경로 목록 |
| `case_get_step_results(case_id, skill=None, summaries_only=True)` | 이전 Skill 결과 (다음 Skill 의 입력). `skill` 생략 시 모든 Skill 의 최신 summary 와 `missing`(summary 가 없는 Skill — 보안 분석 파이프라인 Skill 과, 다른 목표의 Skill 은 이 케이스에서 시작한 것만) (읽기 전용) |
| `case_register_artifact(case_id, path, kind, description=None, producer="agent")` | 케이스 안 파일/디렉터리를 아티팩트로 등록(sha256). `kind` 어휘는 `docs/architecture.md` §3 |
| `case_import_file(case_id, source_path, kind="firmware-image", dest_subdir="dumps", description=None)` | 케이스 밖 파일(벤더 공식 펌웨어, SPI 클립 덤프, 보드 사진)을 케이스로 복사·등록 → `artifact`, `absolute_path`, `provenance{recorded, kind: "imported-unattested", seq, sha256, note}`(출처 원장 기록 — 가져온 파일은 기기에서 읽은 것으로 취급하지 않는다. 기록에 실패하면 `recorded: false`, `reason` 이고 가져오기는 그대로 된다). `dest_subdir` 허용 값: `dumps`, `extract`, `analysis`, `signals`, `jtag`, `notes`, `uart` (다른 값은 `validation_failed`, 같은 이름의 파일이나 링크가 이미 있으면 거부). 보호 상태 디렉터리(state_dir — 승인·증명·출처 원장·솔트·감사 로그) 안의 파일은 가져오지 않는다(`validation_failed`) |
| `case_hash_file(case_id, path, offset=0, length=None)` *(추가)* | 케이스 안 파일 또는 구간의 `sha256`, `md5`, `crc32`(+ `file_size`, `offset`, `length`). `offset`/`length` 는 정수 또는 `"0x50000"`·`"64k"`. 덤프 교차 검증용: SPI 클립·tftpput 으로 받은 파일과 UART 덤프의 같은 구간 비교, 기기 측 `md5sum`/`crc32` 값과 대조 (읽기 전용) |
| `case_add_finding(case_id, finding)` | 발견사항 추가 (`schema_get("finding")`). 필수: `title`, `category`, `severity`, `confidence`, `summary`, `location`, `evidence[]`(1개 이상), `reasoning`. id 는 자동 부여되고, 중복이면 기존 항목을 `duplicate: true` 로 돌려준다 |
| `case_update_finding(case_id, finding_id, patch)` | 발견사항 수정 (예: `status` 를 `static-confirmed` 로, 증거 추가) |
| `case_list_findings(case_id, min_severity=None)` | 발견사항 목록 (심각도순) (읽기 전용) |
| `report_generate(case_id)` | 단계 요약·발견사항·아티팩트·안전 감사 요약을 모아 `cases/<id>/report.md` 생성 |
| `pipeline_profiles()` / `pipeline_profile(name)` | `pipeline-config.yaml` 의 대상 기기 프로필 목록 / 상세(`extends` 해석 완료) (읽기 전용) |
| `pipeline_safety_policy()` | 현재 안전 정책(위험도별 allow/approve/deny, 승인 방법, 영구 경로) (읽기 전용) |
| `approval_status(approval_id)` / `approvals_pending()` | 승인 요청 상태(`pending`\|`approved`\|`denied`\|`consumed`\|`expired`) / 대기 목록(확인 코드 제외) (읽기 전용) |
| `schema_get(name)` | JSON 스키마: `case`, `step-result`, `finding`, `uart-recon`, `firmware-dump`, `static-analysis`, `signal-capture`, `auth-hunt` (읽기 전용) |

Skill 별 summary 스키마: uart-shell-acquisition → `uart-recon`, firmware-dump-via-uart → `firmware-dump`,
logic-analyzer-protocol-decode → `signal-capture`, firmware-static-analysis → `static-analysis`, cctv-auth-bypass-hunt → `auth-hunt`.

## 2. 안전 관련 동작

- 이 서버는 기기를 건드리지 않으므로 안전 게이트 대상이 아니다. 대신 하드웨어 서버가 `rt().case(case_id, hardware=True)` 로
  이 서버가 기록한 소유/허가 증명을 확인한다. 에이전트는 사용자에게 직접 확인받은 뒤에만 `case_create`/`case_set_authorization` 을 호출한다.
- 승인은 **조회만** 한다. 승인/거부하는 도구는 없고, 사람이 별도 터미널에서 `pweh approve <id>` / `pweh deny <id>` 를 실행한다.
- 경로 인자(`path`)는 케이스 안으로 제한된다(`case.resolve_path`). `case_import_file` 의 `source_path` 만 케이스 밖을 읽는다.
- `case_import_file` 은 가져온 파일을 출처 원장(`.pweh/state/provenance/<case_id>.jsonl`)에 `imported-unattested` 로 기록한다(architecture §4).
  이 서버에는 기기 읽기(`device-read`)로 기록하는 경로가 없고, 출처는 `case_register_artifact` 의 `producer` 같은 자유 인자로 바뀌지 않는다.
  출처가 중요한 작업은 사람의 `provenance-import` 증명이 있을 때만 그 파일을 쓴다(그런 작업을 하는 도구는 아직 없다).
- 사람 증명(`att-…`)도 결정·조회하는 도구가 없다. `approval_status`·`approvals_pending` 은 승인(`ap-…`)만 보고, 증명은 사람이 별도 터미널에서
  `pweh attest <id>` 로 답한다. 케이스의 `attestations.json` 은 보고서용 읽기 전용 사본이라 증거가 아니다.
- `case_hash_file`, `case_paths` 를 포함한 읽기 전용 도구는 `readOnlyHint` 가 붙어 있다. `.claude/settings.json` 은 이 서버 도구 전체를 허용한다(`mcp__pweh-case__*`).
