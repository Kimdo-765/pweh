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
./scripts/install.sh                   # 원클릭: Python 가상환경 + 외부 도구 + REA (sudo 없음)
.venv/bin/pytest -q                    # 하드웨어 없이 전체 테스트 (외부 도구가 없으면 일부 skip)
```

`scripts/install.sh` 는 root 권한 없이 설치한다. 시스템 디렉터리와 셸 rc 파일은 바꾸지 않고, 설치물은 `~/pweh-tools`(외부 도구)와
`.venv`(Python)에만 둔다. 끝나면 `~/pweh-tools/env.sh` 를 만들고 `pweh doctor` 로 점검한다. 다시 실행하면 이미 설치된 구성요소는 건너뛴다.

| 구성요소 | 내용 | 설치 방법 |
|---|---|---|
| `python` | pweh 가상환경 (`pip install -e .[dev]`) | `python3 -m venv --without-pip` + sha256 고정 pip 26.2.1 휠 (python3-venv/ensurepip 불필요) |
| `sigrok` | sigrok-cli 0.7.2 + libsigrok/libsigrokdecode | 배포판 패키지를 `apt-get download` 로 받아 개인 경로에 풀고 래퍼로 실행 |
| `openocd` | xPack OpenOCD 0.12.0-7 + 하드웨어 없는 `openocd-dummy` | 릴리스 tar.gz (sha256 고정) |
| `squashfs`, `uboot` | mksquashfs/unsquashfs, mkimage/mkenvimage/dumpimage | 배포판 패키지 (개인 경로) |
| `zig` | Zig 0.17.0 (시뮬레이터 합성 펌웨어) | 공식 tar.xz (sha256 고정) |
| `jdk`, `ghidra` | Temurin JDK 21, Ghidra 12.1.4 (REA 디컴파일 엔진) | 공식 tar.gz / zip (sha256 고정) |
| `unblob`, `extractors` | unblob 26.6.4 + 7z, lz4, lzop, zstd, sasquatch, unar, simg2img … | 전용 venv(unblob 휠 sha256 고정, libmagic 이 없으면 개인 경로에) + 배포판 패키지, sasquatch .deb (sha256 고정) |
| `erofs` *(선택)* | erofs-utils 1.9.4 (EROFS 추출) | 태그 소스 빌드 (C 컴파일러·autotools 필요) |
| `binwalk` *(선택)* | binwalk 3.1.0 (REA 영역 식별) | `cargo install --locked` (cargo 가 없으면 `~/pweh-tools/_rust` 에 rustup 1.29.1(sha256 고정) + Rust 1.98.0, 개발 파일이 없으면 `binwalk/root` 에 -dev 패키지를 풀어 씀. C 컴파일러 필요) |
| `rea` *(선택)* | REA `rea-agents` 6.5.0 | 이미 설치된 REA 6.x 가 있으면 그대로 쓴다. 없으면 `npm install --prefix ~/pweh-tools/rea` (Node 22.19+ 가 없으면 Node 22 를 개인 경로에 받음). REA 의 Ghidra 분석에 필요한 `ps`(procps)가 없으면(Debian 최소 설치 등) 개인 경로에 풀어 `bin/ps` 로 둔다. `rea setup` 은 실행하지 않는다 |

- **전제 조건:** Linux x86_64, bash, curl(또는 wget), tar, xz, Python 3.10 이상, git.
  배포판 패키지 구성요소는 Debian/Ubuntu(apt)에서만 받는다. apt 가 없으면 해당 도구를 직접 설치하고 `PWEH_*` 환경변수로 알려 준다.
  선택 구성요소(erofs, binwalk)는 C 컴파일러가 없으면 이유를 출력하고 건너뛴다. 관리자가 `build-essential` 을 설치해 두면 함께 설치된다.
- **검증:** 스크립트가 직접 받는 파일(OpenOCD·Zig·JDK·Ghidra·Node 압축 파일, pip·unblob 휠, rustup-init, sasquatch .deb)은
  스크립트에 고정한 sha256 으로, 배포판 패키지는 apt 의 서명된 색인에 있는 해시로 검증한다.
  압축 해제 전에 절대 경로·`..`·밖을 가리키는 링크·장치 파일을 거부하고, 배포판 패키지의 설치 스크립트는 실행하지 않는다.
  - 한계: pip(pweh·unblob 의 의존성)와 npm(rea-agents 의 의존성)이 받는 패키지는 최상위 버전만 고정하고 해시는 고정하지 않는다.
    npm 패키지의 설치 스크립트(예: 네이티브 모듈 prebuild)는 실행된다. binwalk 의 crates 는 `Cargo.lock`(`--locked`)의 체크섬으로 검증된다.
- **점검:** 설치 끝에 `pweh doctor` 를 돌린다. 실행 파일이 있어도 버전 확인이 실패하면(공유 라이브러리 없음, Traceback 등) `!!` 로 표시한다.
- **옵션:** `--minimal`, `--only a,b`, `--skip a,b`, `--check`(점검만), `--list`, `--force`(다시 설치), `--prefix DIR`,
  `--seed DIR`, `--no-link`.
  - `--seed DIR`: 해시가 고정된 파일(압축 파일·휠·.deb)을 이 디렉터리에서 먼저 찾아 이름과 해시가 맞으면 쓴다(여러 대 설치·재설치용).
    다른 머신의 `~/pweh-tools/_downloads` 를 그대로 넘기면 된다. pip·npm·cargo 의존성은 여전히 네트워크에서 받으므로 완전한 오프라인 설치는 아니다.
- **다른 위치에 설치:** `--prefix DIR` 로 설치하면 스크립트가 저장소에 `.pweh/tools-env.path`(git 제외)를 남긴다.
  `scripts/mcp-launch.sh` 와 테스트가 그 env.sh 를 찾는다. 순서는 `PWEH_TOOLS_ENV` → `PWEH_TOOLS_DIR/env.sh` → `.pweh/tools-env.path` → `~/pweh-tools/env.sh` 다.
- **prefix 밖에 쓰는 것:** 시스템 cargo 를 쓰면 `~/.cargo` 레지스트리 캐시, Ghidra 를 처음 실행하면 `~/.config/ghidra`.
  pip·npm 캐시는 `~/pweh-tools/_cache` 에 둔다. 로그는 `~/pweh-tools/_logs/install-*.log`.
- **디스크:** 설치 후 약 3 GB(내려받기 캐시 `_downloads` 약 0.8 GB 포함). 시스템 cargo 가 없으면 개인 Rust 툴체인(`_rust`) 약 0.7 GB 가 더 든다.
  `_downloads`(재설치용 캐시)와 `_build`(빌드 중간 파일)는 설치 뒤 지워도 된다.
- **지우기:** `rm -rf ~/pweh-tools .venv` (그리고 `--prefix`/`--venv` 를 썼다면 `.pweh/tools-env.path`, `.pweh/venv.path`).

MCP 서버는 `scripts/mcp-launch.sh` 를 거쳐 실행된다. 이 런처가 위 env.sh 를 자동으로 불러온다.

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
| `PWEH_TOOLS_ENV`, `PWEH_TOOLS_DIR` | 외부 도구 env.sh 경로 / 도구 디렉터리 (기본 `~/pweh-tools`. `--prefix` 로 설치했으면 `.pweh/tools-env.path` 가 가리킴) |
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
| REA 의 Ghidra 분석이 `spawn ps ENOENT` 로 실패 | `ps`(procps)가 없는 시스템이다. `scripts/install.sh --only rea` 가 개인 경로에 `ps` 를 둔다 (MCP 서버는 env.sh 의 PATH 로 찾음) |
| `pweh doctor` 가 도구를 `!!` (종료 코드 …) 로 표시 | 실행 파일은 있지만 깨진 설치다. 표시된 명령을 직접 실행해 보고 `scripts/install.sh --force --only <구성요소>` 로 다시 설치한다. 로그는 `~/pweh-tools/_logs/` |
| 게이트가 계속 `denied` | `pipeline_safety_policy` 로 정책을 확인한다. 정책 변경은 사람이 하고 서버를 재시작해야 반영된다 |
