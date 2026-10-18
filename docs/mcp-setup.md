# MCP 설정 가이드 (Claude Code · Codex · Cursor)

PWEH 는 MCP 서버 7개를 쓴다. 6개는 이 저장소에 있고, 1개는 외부 REA 다.

| 서버 이름 | 실행 파일 | 역할 |
|---|---|---|
| `pweh-case` | `.venv/bin/pweh-case-mcp` | 케이스, 단계 결과, 발견사항, 보고서, 프로필, 승인 상태 |
| `pweh-uart` | `.venv/bin/pweh-uart-mcp` | UART 콘솔 (U-Boot, Linux 셸, 덤프 job) |
| `pweh-sigrok` | `.venv/bin/pweh-sigrok-mcp` | 로직 애널라이저 (sigrok-cli) |
| `pweh-openocd` | `.venv/bin/pweh-openocd-mcp` | JTAG/SWD (OpenOCD) |
| `pweh-jtagulator` | `.venv/bin/pweh-jtagulator-mcp` | JTAGulator 핀아웃 스캔 (선택) |
| `pweh-fwtriage` | `.venv/bin/pweh-fwtriage-mcp` | 오프라인 펌웨어 트리아지 |
| `rea` | `rea --mcp` (rea-agents 6.5.x) | binwalk/unblob 추출, Ghidra 디컴파일, sigrok 디코딩 |

도구 목록과 인자는 [architecture.md](architecture.md) §6 과 각 서버의 `mcp-servers/<name>/README.md` 에 있다.
서버가 실제로 내보내는 도구 전체(인자, annotation)는 [references/pweh-mcp-tools.md](references/pweh-mcp-tools.md) 에 있다.
서버 도구가 바뀌면 `.venv/bin/python scripts/dump_tool_catalog.py` 로 다시 만들고 `--check` 로 권한 규칙과 Skill 문서를 검사한다.

## 1. 설치

```bash
cd ~/pweh
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q                    # 하드웨어 없이 전체 테스트 (외부 도구가 없으면 일부 skip)
.venv/bin/pweh doctor                  # 환경 점검
```

외부 도구 위치 (`~/pweh-tools/env.sh`):
- sigrok-cli 0.7.2
- OpenOCD 0.12 (xPack)
- binwalk 3.1.0
- unblob 26.6.4
- squashfs-tools, u-boot-tools
- Zig
- JDK 21 + Ghidra 12.1.4

MCP 서버는 `scripts/mcp-launch.sh` 를 거쳐 실행된다. 이 런처가 위 env.sh 를 자동으로 불러온다.
다른 위치에 설치했다면 `PWEH_TOOLS_ENV=/path/to/env.sh` 로 알려 준다.

## 2. Claude Code

### 2.1 서버 등록
저장소 루트의 `.mcp.json` 이 프로젝트 범위로 7개 서버를 등록한다. 다시 만들려면 다음을 실행한다.
```bash
.venv/bin/pweh mcp-config --client claude --write --force
```
생성되는 형식 (이식 가능한 형태: 저장소를 옮겨도 동작):
```json
{
  "mcpServers": {
    "pweh-uart": {
      "type": "stdio",
      "command": "bash",
      "args": ["-c", "d=\"$CLAUDE_PROJECT_DIR\"; [ -n \"$d\" ] || d=\"$PWD\"; exec \"$d/scripts/mcp-launch.sh\" pweh-uart-mcp"]
    }
  }
}
```
- Claude Code 는 `.mcp.json` 안의 `${VAR}` 만 확장한다. 중괄호 없는 `$CLAUDE_PROJECT_DIR` 는 그대로 두고, 런타임에 bash 가 확장한다.
  `CLAUDE_PROJECT_DIR` 는 Claude Code 가 서버 프로세스에만 넣어 주는 변수다.
- 처음 `claude` 를 실행하면 프로젝트 MCP 서버 승인 다이얼로그가 뜬다. 승인한 뒤 `/mcp` 로 상태를 확인한다.
  `claude -p` 같은 비대화형 실행은 이 승인 없이 서버를 로드한다.
- 절대 경로 형태를 원하면 `--style absolute` 를 쓴다. 이 형태는 env.sh 값을 `env` 에 직접 박아 넣는다.

### 2.2 Skill
`.claude/skills/<name>` 은 `skills/<name>` 을 가리키는 심볼릭 링크다 (Claude Code 는 Skill 폴더 단위 심볼릭 링크를 지원한다).
링크가 없으면 다시 만든다.
```bash
.venv/bin/pweh skills install --target claude-project
```
파이프라인 시작: Claude Code 에서 `/pweh-start <기기 설명>` 을 입력한다.

### 2.3 권한과 승인
- `.claude/settings.json` 에 권한 규칙이 있다. 도구 카탈로그에서 다음 규칙으로 만든다.
  - `ask`: 원시 쓰기(`uart_write`), DTR/RTS·BREAK(`uart_set_signals`, `uart_send_break`), 원시 TCL(`openocd_command`),
    플래시·메모리 쓰기(`openocd_flash_write`, `openocd_write_memory`), JTAGulator 전압 설정(`jtagulator_set_voltage`),
    REA 의 런타임·기기 도구(프로세스·디버거·Frida·Cutter·앱·브라우저 세션을 시작·조작·종료하거나 adb 기기에 쓰기·설치·실행·파일 가져오기),
    임의 Rizin 명령을 실행하는 `execute_rizin_command`(셸 탈출 `!` 로 호스트 명령 실행 가능).
    **bypassPermissions 모드에서도 묻는다.**
  - `allow`: pweh 서버의 조회 전용 도구(`readOnlyHint`), `pweh-case`·`pweh-fwtriage` 전체(`mcp__pweh-case__*`, `mcp__pweh-fwtriage__*`),
    REA 정적 분석 도구. 기본 모드에서 묻지 않는다(bypass 모드에서는 원래 묻지 않으므로 의미가 없다).
    프로젝트 `allow` 는 workspace trust 를 수락한 뒤에만 적용되고, `ask`/`deny` 는 trust 와 무관하게 적용된다.
  - 둘 다 아닌 도구(예: `uart_send_command`, `uboot_dump_start`, `sigrok_capture`, `openocd_halt`)는 기본 모드에서 처음 쓸 때 묻는다.
- `anthropic/requiresUserInteraction` 메타는 항상 파괴적인 세 도구(`openocd_flash_write`, `openocd_write_memory`,
  `jtagulator_set_voltage`)에만 붙어 있어, 이 도구들은 allow 규칙과 무관하게 bypassPermissions 모드에서도 매번 확인을 띄운다.
  사람에게 물을 수 없는 경로(`dontAsk` 모드, `--permission-prompt-tool`)에서는 묻는 대신 거부된다.
- 그래도 **최종 판단은 서버 측 안전 게이트**가 한다 ([safety.md](safety.md) §3).
  게이트가 사람 승인을 요구하면 두 경로 중 하나로 승인한다.
  - **elicitation 확인 폼**: Claude Code v2.1.76+ 에서 다이얼로그가 뜬다. 확인 코드를 입력하고 Accept 한다.
  - **CLI**: 별도 터미널에서 `.venv/bin/pweh approve <approval_id>` 를 실행한다.

### 2.4 타임아웃·출력 한도 (Claude Code 기본값)

| 변수 | 기본 | PWEH 에 미치는 영향 |
|---|---|---|
| `MCP_TIMEOUT` | 30 s | 서버 시작 시간 제한. 충분하다 |
| `MCP_TOOL_TIMEOUT` | 약 28 h | 도구 호출 총 시간 제한 |
| `CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT` | stdio 30 min | 응답이나 progress 없이 30분이 지나면 중단된다 |
| `CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS` | 2 min | 2분이 넘는 호출은 백그라운드 태스크로 옮겨진다 |
| `MAX_MCP_OUTPUT_TOKENS` | 25000 | 큰 출력은 파일로 빠진다. PWEH 도구는 요약과 파일 경로를 돌려준다 |

장시간 작업(UART 덤프, 긴 캡처, 핀아웃 스캔)은 PWEH 가 job 으로 실행한다.
`*_job_status(job_id, wait_seconds≤50)` 로 폴링하므로 어떤 클라이언트 타임아웃에도 걸리지 않는다.

## 3. Codex CLI

```bash
.venv/bin/pweh mcp-config --client codex >> ~/.codex/config.toml   # 내용 확인 후 추가
```
- 생성되는 항목: 절대 경로의 `command`, `cwd`, `env`(PWEH_CONFIG + env.sh 값), `startup_timeout_sec = 60`,
  `tool_timeout_sec = 600` (rea 는 900).
- Codex 문서상 기본 도구 타임아웃은 60 s 다 (소스 기준 300 s). 명시 설정을 권장한다.
- Skill: `.agents/skills/<name>` 심볼릭 링크를 Codex 가 프로젝트 Skill 로 읽는다. `$pweh-start` 로 시작한다.
- `AGENTS.md` 에 프로젝트 규칙이 있다.
- 주의: Codex 를 `-a never` + full access 로 실행하면 도구 호출이 자동 승인된다.
  이때 Codex 는 필드가 있는 elicitation 을 자동 거절(decline)한다. PWEH 의 확인 폼은 필드가 있어 자동 수락되지 않고,
  거절되면 게이트가 CLI 승인으로 넘어가지 않고 `denied` 로 끝난다(fail-closed).
  그런 환경에서 위험 작업 승인이 필요하면 사람이 `pipeline-config.yaml` 의 `safety.approval_methods` 를 `[cli]` 로 바꾸고
  서버를 재시작한 뒤 CLI 승인(`pweh approve`)을 쓴다.

## 4. Cursor

```bash
.venv/bin/pweh mcp-config --client cursor --write     # .cursor/mcp.json (${workspaceFolder} 사용)
```
- Skill: Cursor 는 `.agents/skills` 와 `.claude/skills` 를 읽는다. 같은 Skill 이 두 번 보이면 한쪽만 남긴다.
- Cursor 의 도구 타임아웃은 문서화되어 있지 않다. 60초를 넘는 동기 호출을 피하고 job 폴링을 쓴다 (PWEH 기본 동작).

## 5. REA 연동

- `.mcp.json` 의 `rea` 항목은 `scripts/mcp-launch.sh rea` 로 `rea --mcp` 를 실행한다. env.sh 에서 다음 값이 전달된다.
  - `GHIDRA_INSTALL_DIR`, `JAVA_HOME` — Ghidra 엔진.
  - `REA_BINWALK_COMMAND`, `REA_UNBLOB_COMMAND` — 펌웨어 영역 분석과 추출.
  - `REA_SIGROK_COMMAND` — 녹화된 신호 디코딩.
  - `REA_GHIDRA_STARTUP_TIMEOUT_MS=600000` (런처 기본값).
- **`rea setup` 을 실행하지 않는다.** 이 명령은 Claude Code 외에 Codex/Grok 등 다른 클라이언트 설정까지 바꾼다.
  PWEH 는 프로젝트 `.mcp.json` 만으로 REA 를 등록한다.
- 점검:
  ```bash
  . ~/pweh-tools/env.sh && rea doctor --provider ghidra
  ```
  이 환경에서는 Ghidra 첫 분석이 6~7초에 끝난다 (작은 ELF 기준). 큰 바이너리는 수 분이 걸릴 수 있다.
- 자주 쓰는 REA 도구와 제약은 [architecture.md](architecture.md) §7 에 있다.
  - 입력은 128 MiB 이하.
  - `extract_firmware` 의 출력 디렉터리는 존재하지 않는 절대 경로여야 한다 (`case_paths` 의 `new_output_dir`).
  - `export_evidence_bundle` 의 출력 경로는 부모 디렉터리가 이미 있어야 한다 (케이스 `analysis/` 아래).
  - MIPS raw 이미지는 받지 않는다 (rootfs 안의 ELF 를 분석한다).
  - REA 가 Ghidra 대상으로 받지 않는 ELF 는 `inspect_with_objdump` / `execute_rizin_command` 나 fwtriage 로 대체한다.

### 5.1 REA 예제 프롬프트

파이프라인은 `firmware-static-analysis`·`cctv-auth-bypass-hunt` Skill 안에서 REA 를 부른다. 케이스가 이미 있을 때 REA 단계만 따로
시킬 수 있는 예제다(대상은 소유하거나 서면 허가를 받은 기기의 펌웨어). REA 에는 케이스 디렉터리 기준 **절대 경로**를 넘긴다(`case_paths` 의 `case_dir`).

```text
케이스 cam-001 의 dumps/flash-full.bin 을 REA inspect_firmware_regions 로 훑고, fw_identify 의 영역 지도와 다른 점만
identification.regions_crosscheck 로 정리해 줘. binwalk 결과는 가설로만 다뤄.
```
```text
case_paths(purpose="extract", label="rea") 로 받은 새 출력 디렉터리에 REA extract_firmware 로 rootfs 파티션을 교차 추출하고,
fw_extract_squashfs 결과와 파일 목록이 어디서 다른지 알려 줘.
```
```text
extract/rootfs-001/usr/sbin/httpd 를 REA open_binary(provider_id="ghidra") 로 열어서 인증 판정 함수를 trace_feature 와
procedure_pseudo_code 로 찾아 줘. 근거가 된 의사코드 줄을 인용하고, 끝나면 export_evidence_bundle 을 analysis/ 아래에 남긴 뒤 close_binary 해 줘.
```
```text
같은 바이너리에서 system/popen 으로 이어지는 호출 경로를 trace_call_path 로 찾아, 요청 파라미터가 필터 없이 도달하는지 정적으로만 판단해 줘.
재현 요청이나 페이로드는 만들지 마.
```
```text
signals/boot-001.sr 을 REA decode_signal_recording 으로 UART 디코딩해서 sigrok_uart_autodecode 결과와 보드레이트·첫 줄이 같은지 비교해 줘.
```

## 6. 환경변수 요약

| 변수 | 용도 |
|---|---|
| `PWEH_CONFIG` | 설정 파일 경로 (설정하지 않으면 런처가 저장소의 `orchestrator/pipeline-config.yaml` 로 지정) |
| `PWEH_TOOLS_ENV` | 외부 도구 env.sh 경로 (기본 `~/pweh-tools/env.sh`) |
| `PWEH_REA` | 런처가 실행할 `rea` 실행 파일 (기본: `PATH` 의 `rea`, 없으면 `~/.local/bin/rea`) |
| `PWEH_CASES_DIR`, `PWEH_STATE_DIR` | 케이스/상태 디렉터리 강제 지정 (테스트·격리 실행) |
| `PWEH_SIGROK_CLI`, `PWEH_OPENOCD`, `PWEH_OPENOCD_SCRIPTS`, `PWEH_UNSQUASHFS`, `PWEH_MKSQUASHFS`, `PWEH_ZIG` … | 외부 도구 경로 (env.sh 가 설정) |

## 7. 문제 해결

| 증상 | 확인 |
|---|---|
| `/mcp` 에 서버가 `Failed to connect` | `bash scripts/mcp-launch.sh pweh-case-mcp < /dev/null` 로 직접 실행해 오류를 본다. `.venv` 설치 여부도 확인한다 |
| `Pending approval` | `claude` 를 대화형으로 실행해 승인한다. 또는 `claude mcp reset-project-choices` 후 다시 승인한다 |
| REA 도구가 Ghidra 없다고 함 | env.sh 의 `GHIDRA_INSTALL_DIR`/`JAVA_HOME` 을 확인하고 `rea doctor --provider ghidra` 를 실행한다 |
| 시리얼 포트 권한 오류 | `pweh doctor` → `dialout` 그룹, WSL 이면 `usbipd attach` |
| 게이트가 계속 `denied` | `pipeline_safety_policy` 로 정책을 확인한다. 정책 변경은 사람이 하고 서버를 재시작해야 반영된다 |
