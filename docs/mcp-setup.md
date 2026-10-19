# MCP 설정 가이드 (Claude Code · Codex · Cursor)

PWEH 는 MCP 서버 8개를 쓴다. 7개는 이 저장소에 있고, 1개는 외부 REA 다.

| 서버 이름 | 실행 파일 | 역할 |
|---|---|---|
| `pweh-case` | `.venv/bin/pweh-case-mcp` | 케이스, 단계 결과, 발견사항, 보고서, 프로필, 승인 상태 |
| `pweh-uart` | `.venv/bin/pweh-uart-mcp` | UART 콘솔 (U-Boot, Linux 셸, 덤프 job) |
| `pweh-sigrok` | `.venv/bin/pweh-sigrok-mcp` | 로직 애널라이저 (sigrok-cli) |
| `pweh-openocd` | `.venv/bin/pweh-openocd-mcp` | JTAG/SWD (OpenOCD) |
| `pweh-jtagulator` | `.venv/bin/pweh-jtagulator-mcp` | JTAGulator 핀아웃 스캔 (선택) |
| `pweh-fwtriage` | `.venv/bin/pweh-fwtriage-mcp` | 오프라인 펌웨어 트리아지 |
| `pweh-esp` | `.venv/bin/pweh-esp-mcp` | ESP32 계열 esptool 읽기 전용: 칩·보안 정보, 플래시 덤프 job. WSL 에서는 Windows `esptool.exe` + COM 포트(방법 A, §6) (선택) |
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
| `esptool` *(선택)* | esptool 5.4.0 (ESP32 계열 칩·보안 정보, 플래시 읽기) + WSL 이면 Windows `esptool.exe` (방법 A: WSL 에서 interop 으로 실행해 Windows COM 포트를 씀) | Linux 판: 전용 venv `esptool/venv` 에 PyPI 소스 배포판(sha256 고정. PyPI 에 5.x 휠이 없음)을 설치하고 `bin/esptool` 래퍼로 실행한다. Windows 판: WSL interop 이 켜져 있으면 공식 Windows 빌드 zip(sha256 고정)을 `esptool-win/` 에 풀고, interop 으로 `esptool.exe version` 을 실행해 확인한다. WSL 이 아니면 Windows 판은 건너뛴다(실패 아님). 한쪽이 실패해도 다른 쪽은 설치하고, env.sh 는 실제로 실행되는 쪽만 `PWEH_ESPTOOL`(Linux 판)·`PWEH_ESPTOOL_WIN`(Windows 판 `.exe` 절대 경로)으로 알려 준다 |

- **전제 조건:** Linux x86_64, bash, curl(또는 wget), tar, xz, Python 3.10 이상, git.
  배포판 패키지 구성요소는 Debian/Ubuntu(apt)에서만 받는다. apt 가 없으면 해당 도구를 직접 설치하고 `PWEH_*` 환경변수로 알려 준다.
  선택 구성요소(erofs, binwalk)는 C 컴파일러가 없으면 이유를 출력하고 건너뛴다. 관리자가 `build-essential` 을 설치해 두면 함께 설치된다.
  선택 구성요소 esptool 의 Windows 판(방법 A)은 WSL interop(`/proc/sys/fs/binfmt_misc/WSLInterop` 또는 `WSLInterop-late` 가 `enabled`)일 때만 설치하고,
  그 밖의 환경에서는 Linux 판만 설치한다. `./scripts/install.sh --check --only esptool` 은 Linux 판 버전과, WSL interop 이면 Windows 판 버전도 보여 준다.
- **검증:** 스크립트가 직접 받는 파일(OpenOCD·Zig·JDK·Ghidra·Node·Windows esptool 압축 파일, pip·unblob 휠, esptool 소스 배포판, rustup-init, sasquatch .deb)은
  스크립트에 고정한 sha256 으로, 배포판 패키지는 apt 의 서명된 색인에 있는 해시로 검증한다.
  압축 해제 전에 절대 경로·`..`·밖을 가리키는 링크·장치 파일을 거부하고, 배포판 패키지의 설치 스크립트는 실행하지 않는다.
  - 한계: pip(pweh·unblob·esptool 의 의존성)와 npm(rea-agents 의 의존성)이 받는 패키지는 최상위 버전만 고정하고 해시는 고정하지 않는다.
    npm 패키지의 설치 스크립트(예: 네이티브 모듈 prebuild)는 실행된다. binwalk 의 crates 는 `Cargo.lock`(`--locked`)의 체크섬으로 검증된다.
    esptool 은 PyPI 에 휠이 없어 고정한 소스 배포판을 빌드하므로, 빌드 백엔드(setuptools)도 PyPI 에서 해시 없이 받아 빌드 중에 실행된다.
    Windows `esptool.exe` 는 의존성을 담은 단일 실행 파일이라 zip 의 해시로 전부 검증된다.
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
  esptool 은 Linux 판 venv 약 60 MB, WSL 이면 Windows 판 약 65 MB 와 내려받은 zip 66 MB 를 더 쓴다.
  `_downloads`(재설치용 캐시)와 `_build`(빌드 중간 파일)는 설치 뒤 지워도 된다.
- **지우기:** `rm -rf ~/pweh-tools .venv` (그리고 `--prefix`/`--venv` 를 썼다면 `.pweh/tools-env.path`, `.pweh/venv.path`).

MCP 서버는 `scripts/mcp-launch.sh` 를 거쳐 실행된다. 이 런처가 위 env.sh 를 자동으로 불러온다.

## 2. Claude Code

### 2.1 서버 등록
저장소 루트의 `.mcp.json` 이 프로젝트 범위로 8개 서버(`pweh-case`, `pweh-uart`, `pweh-openocd`, `pweh-sigrok`, `pweh-jtagulator`, `pweh-fwtriage`, `pweh-esp`, `rea`)를 등록한다.
`.claude/settings.json` 의 `enabledMcpjsonServers` 도 같은 8개다. 다시 만들려면 다음을 실행한다.
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
  저장소를 업데이트해 `.mcp.json` 에 서버가 새로 생기면(예: `pweh-esp`) Claude Code 를 다시 시작한다. 새 서버의 승인 다이얼로그가 뜨면 승인하고, `/mcp` 에서 연결됐는지 확인한다.
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
  - 둘 다 아닌 도구(예: `uart_send_command`, `uboot_dump_start`, `sigrok_capture`, `openocd_halt`, `esp_chip_info`, `esp_read_flash_start`)는 기본 모드에서 처음 쓸 때 묻는다.
    pweh-esp 는 `esp_version`, `esp_list_ports`, `esp_job_status`, `esp_jobs` 가 `allow` 에 있다.
- `anthropic/requiresUserInteraction` 메타는 항상 파괴적인 세 도구(`openocd_flash_write`, `openocd_write_memory`,
  `jtagulator_set_voltage`)에만 붙어 있어, 이 도구들은 allow 규칙과 무관하게 bypassPermissions 모드에서도 매번 확인을 띄운다.
  사람에게 물을 수 없는 경로(`dontAsk` 모드, `--permission-prompt-tool`)에서는 묻는 대신 거부된다.
- 그래도 **최종 판단은 서버 측 안전 게이트**가 한다 ([safety.md](safety.md) §3).
  게이트가 사람 승인을 요구하면 두 경로 중 하나로 승인한다.
  - **elicitation 확인 폼**: Claude Code v2.1.76+ 에서 다이얼로그가 뜬다. 확인 코드를 입력하고 Accept 한다.
  - **CLI**: 별도 터미널에서 `.venv/bin/pweh approve <approval_id>` 를 실행한다.
- 승인과 별도로, 에이전트가 확인할 수 없는 사실(콘솔 오프라인, 잰 전압, 가져온 파일의 출처 등)이 필요한 도구는 **사람 증명**을 요구할 수 있다
  (`status: attestation_required` + `attestation_id`. 지금은 그런 도구가 없다 — [safety.md](safety.md) §3.5).
  같은 두 경로(`safety.approval_methods`)를 쓴다: elicitation 확인 폼(항목마다 답 + 확인 코드) 또는 별도 터미널의 `.venv/bin/pweh attest <attestation_id>`(대화형 터미널 전용).
  증명은 소비되지 않고 재사용되며, 에이전트는 같은 인자로 다시 호출한다(`attestation_id` 를 넘기지 않는다).

### 2.4 타임아웃·출력 한도 (Claude Code 기본값)

| 변수 | 기본 | PWEH 에 미치는 영향 |
|---|---|---|
| `MCP_TIMEOUT` | 30 s | 서버 시작 시간 제한. 충분하다 |
| `MCP_TOOL_TIMEOUT` | 약 28 h | 도구 호출 총 시간 제한 |
| `CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT` | stdio 30 min | 응답이나 progress 없이 30분이 지나면 중단된다 |
| `CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS` | 2 min | 2분이 넘는 호출은 백그라운드 태스크로 옮겨진다 |
| `MAX_MCP_OUTPUT_TOKENS` | 25000 | 큰 출력은 파일로 빠진다. PWEH 도구는 요약과 파일 경로를 돌려준다 |

장시간 작업(UART 덤프, ESP32 플래시 덤프, 긴 캡처, 핀아웃 스캔)은 PWEH 가 job 으로 실행한다.
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
  사람 증명도 같은 설정을 따른다: 폼이 자동 거절되면 그 증명 요청은 거부(`denied`)로 기록되고, `[cli]` 면 사람이 `pweh attest <id>` 로 답한다.

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

## 6. ESP32 (esptool) 방법 A

`pweh-esp` 는 WSL 에서 Windows 에 연결된 ESP32 보드를 usbipd 없이 다룬다. 서버가 WSL interop 으로 Windows 용 `esptool.exe` 를 `--port COM3` 처럼 실행하고,
덤프는 `wslpath -w` 로 바꾼 경로(`\\wsl.localhost\<배포판>\…`)로 케이스 `dumps/` 에 바로 쓴다. 쓰는 esptool 명령은 읽기(`flash-id`, `get-security-info`, `read-flash`)뿐이다.
보드 연결과 BOOT/RESET 버튼은 [hardware-setup.md](hardware-setup.md) §8, 안전 정책은 [safety.md](safety.md) §3.3, 도구 계약은 [architecture.md](architecture.md) §6.7 에 있다.
에이전트용 절차는 `esp32-flash-dump` Skill 이다.

- **설치:** esptool 은 `./scripts/install.sh` 에 포함된 선택 구성요소다(실패해도 나머지 설치는 계속된다). 이미 설치한 환경에 더하려면 `./scripts/install.sh --only esptool` 을 실행한다.
  Linux esptool 5.4.0(`~/pweh-tools/bin/esptool`)과, WSL interop 이 켜져 있으면 Windows 판 `~/pweh-tools/esptool-win/esptool-windows-amd64/esptool.exe` 를 설치하고
  env.sh 에 실제로 실행되는 쪽만 `PWEH_ESPTOOL`·`PWEH_ESPTOOL_WIN` 으로 적는다. 확인은 `./scripts/install.sh --check --only esptool` 과 `pweh doctor` 다.
- **Windows 쪽:** `~/pweh-tools` 아래 파일 말고는 설치할 것이 없다. exe 가 리눅스 파일시스템에 있어도 interop 으로 실행된다.
  장치 관리자의 '포트(COM & LPT)' 에 보드가 COM 포트로 보이면 된다(보이지 않으면 데이터 케이블인지, USB-UART 브리지 드라이버가 있는지 확인한다).
- **WSL interop:** 켜져 있어야 한다(`/proc/sys/fs/binfmt_misc/WSLInterop` 또는 `WSLInterop-late` 의 첫 줄이 `enabled`). 꺼져 있으면 사람이 `/etc/wsl.conf` 의 `[interop]` 에서
  `enabled=true` 로 두고 Windows 에서 `wsl --shutdown` 한 뒤 WSL 을 다시 연다. 그동안은 usbipd attach 와 리눅스 포트(`/dev/ttyACM0`, 방법 B)를 쓴다.
- **MCP 서버 다시 시작:** env.sh 가 바뀌었으므로 Claude Code 를 다시 시작한다(`scripts/mcp-launch.sh` 가 env.sh 를 읽어 서버를 띄운다).
  새 프로젝트 MCP 서버 `pweh-esp` 의 승인 다이얼로그가 뜨면 승인하고 `/mcp` 에서 연결됐는지 확인한다. Codex 는 `pweh mcp-config --client codex` 출력의 `pweh-esp` 항목을 설정에 더한다.
- **포트 이름:** 에이전트는 `esp_version()` 으로 `backends.windows.available` 과 버전을 본 뒤 `esp_list_ports()` 의 `windows.ports[].port` 에서 COM 포트를 고른다(추측하지 않는다).
  `303a:1001` 은 ESP 내장 USB-Serial/JTAG 이고, 리셋 뒤 COM 번호가 바뀌면 다시 조회한다. 그다음 소유/허가 확인 → `case_create` → `esp_chip_info` → `esp_security_info` → `esp_read_flash_start` → `esp_job_status` 순서다.
- **같은 장치를 동시에 붙이지 않는다:** usbipd 로 WSL 에 attach 한 장치는 Windows 에서 COM 포트가 사라져 방법 A 로 열 수 없다. 방법 A 를 쓰려면 `usbipd detach` 한다.

## 7. 환경변수 요약

| 변수 | 용도 |
|---|---|
| `PWEH_CONFIG` | 설정 파일 경로 (설정하지 않으면 런처가 저장소의 `orchestrator/pipeline-config.yaml` 로 지정) |
| `PWEH_TOOLS_ENV`, `PWEH_TOOLS_DIR` | 외부 도구 env.sh 경로 / 도구 디렉터리 (기본 `~/pweh-tools`. `--prefix` 로 설치했으면 `.pweh/tools-env.path` 가 가리킴) |
| `PWEH_REA` | 런처가 실행할 `rea` 실행 파일 (기본: `PATH` 의 `rea`, 없으면 `~/.local/bin/rea`) |
| `PWEH_CASES_DIR`, `PWEH_STATE_DIR` | 케이스/상태 디렉터리 강제 지정 (테스트·격리 실행) |
| `PWEH_SIGROK_CLI`, `PWEH_OPENOCD`, `PWEH_OPENOCD_SCRIPTS`, `PWEH_UNSQUASHFS`, `PWEH_MKSQUASHFS`, `PWEH_ZIG` … | 외부 도구 경로 (env.sh 가 설정) |
| `PWEH_ESPTOOL`, `PWEH_ESPTOOL_WIN` | pweh-esp 의 리눅스 esptool / Windows 용 `esptool.exe` 절대 경로(방법 A). 설정 키는 `tools.esptool`·`tools.esptool_win`. env.sh 는 실제로 실행되는 쪽만 설정한다. `PWEH_ESPTOOL_WIN` 이 비어 있으면 외부 도구 디렉터리의 `esptool-win/esptool-windows-amd64/esptool.exe` 를 찾고, `C:\tools\esptool.exe` 같은 Windows 경로도 받는다(`wslpath -u` 로 변환). 바꾸면 MCP 서버를 다시 시작한다 |

## 8. 문제 해결

| 증상 | 확인 |
|---|---|
| `/mcp` 에 서버가 `Failed to connect` | `bash scripts/mcp-launch.sh pweh-case-mcp < /dev/null` 로 직접 실행해 오류를 본다. `.venv` 설치 여부도 확인한다 |
| `Pending approval` | `claude` 를 대화형으로 실행해 승인한다. 또는 `claude mcp reset-project-choices` 후 다시 승인한다 |
| REA 도구가 Ghidra 없다고 함 | env.sh 의 `GHIDRA_INSTALL_DIR`/`JAVA_HOME` 을 확인하고 `rea doctor --provider ghidra` 를 실행한다 |
| 시리얼 포트 권한 오류 | `pweh doctor` → `dialout` 그룹, WSL 이면 `usbipd attach` |
| REA 의 Ghidra 분석이 `spawn ps ENOENT` 로 실패 | `ps`(procps)가 없는 시스템이다. `scripts/install.sh --only rea` 가 개인 경로에 `ps` 를 둔다 (MCP 서버는 env.sh 의 PATH 로 찾음) |
| `pweh doctor` 가 도구를 `!!` (종료 코드 …) 로 표시 | 실행 파일은 있지만 깨진 설치다. 표시된 명령을 직접 실행해 보고 `scripts/install.sh --force --only <구성요소>` 로 다시 설치한다. 로그는 `~/pweh-tools/_logs/` |
| 게이트가 계속 `denied` | `pipeline_safety_policy` 로 정책을 확인한다. 정책 변경은 사람이 하고 서버를 재시작해야 반영된다 |
| pweh-esp 가 `gate.via: "esp-policy"` 로 `denied` | esptool 쓰기·삭제·eFuse 같은 명령이다. 정책과 무관하게 막히며 승인으로도 풀리지 않는다. 다시 시도하지 말고 사용자에게 보고한다 |
| esptool `esp_port_busy` (포트 사용 중·접근 거부) | 같은 COM 포트를 연 시리얼 모니터(Arduino IDE, `idf.py monitor`, PuTTY, Tera Term)나 다른 esptool 을 닫는다. 그 COM 포트를 인자로 받은 esptool.exe 가 남아 있으면 서버가 esptool 을 띄우기 전에 PID 와 함께 `busy` 로 거부한다(아래 `esp_orphan_process` 행). 그 장치를 usbipd 로 WSL 에 attach 해 두었으면 Windows 쪽에서 열 수 없으므로 `usbipd detach --busid <BUSID>` 한다. 리눅스 포트는 서버가 미리 확인해 `busy` 로 거부한다(그 tty 를 연 프로그램을 닫고, uart-mcp 세션이면 `uart_close`) |
| esptool `esp_orphan_process`, 또는 PID 를 알리는 `busy` (방법 A) | 취소·시간 초과·서버 종료 뒤 Windows esptool.exe(PyInstaller onefile 의 자식)가 남아 COM 포트를 잡고 있다. 사람이 작업 관리자에서 그 esptool.exe 를 끝내거나 Windows 터미널에서 `taskkill /F /PID <PID>` 를 실행한다(보드를 뽑았다 꽂아도 된다). 덤프의 숨은 예약 파일은 그 프로세스가 끝난 뒤 서버가 지운다 |
| esptool `esp_foreign_config` | esptool 이 서버가 만든 빈 설정이 아닌 설정 파일(`~/.config/esptool/esptool.cfg`, `%USERPROFILE%\AppData\Local\esptool\esptool.cfg` 등)을 읽었다. 사람이 그 파일의 `[esptool]` 섹션을 확인·제거하거나 파일을 옮긴 뒤 다시 시도한다 |
| esptool `esp_port_not_found`, `esp_port_open_failed` | `esp_list_ports` 로 실제 COM 번호를 다시 본다(ESP 내장 USB 는 리셋 뒤 번호가 바뀔 수 있다). usbipd attach 한 동안에는 Windows 에서 COM 포트가 사라지므로 `usbipd detach --busid <BUSID>` 로 떼거나 리눅스 포트(`/dev/ttyACM0`)를 쓴다 |
| esptool `esp_no_serial_data`, `esp_wrong_boot_mode` (칩이 다운로드 모드가 아님) | 사람이 BOOT 를 누른 채 RESET 을 눌렀다 떼고 BOOT 를 놓은 뒤 `before="no-reset"` 으로 다시 호출한다. 데이터 케이블인지, 보드의 네이티브 USB 포트와 UART 브리지 포트 중 맞는 쪽에 꽂았는지 확인한다 ([hardware-setup.md](hardware-setup.md) §8) |
| esptool `esp_secure_download_mode`, `read_flash_possible=false` | 칩이 Secure Download Mode 라 esptool 로 플래시를 읽을 수 없다. 우회하지 않고 사용자에게 보고한다 |
| `esp_version` 의 `backends.windows.interop=false`, Windows 백엔드 `tool_missing`(interop) | WSL interop 이 꺼져 있다. 사람이 `/etc/wsl.conf` 의 `[interop]` 을 확인하고 `wsl --shutdown` 후 WSL 을 다시 연다(§6). 그동안은 usbipd attach 와 리눅스 포트를 쓴다 |
| `Windows 용 esptool.exe 를 찾을 수 없습니다` (`tool_missing`) | `./scripts/install.sh --only esptool` 로 설치하거나(WSL interop 이 켜져 있어야 Windows 판을 받는다) `PWEH_ESPTOOL_WIN` 을 지정한 뒤 MCP 서버를 다시 시작한다. 리눅스 파일시스템에 직접 푼 exe 는 실행 권한이 필요하다(`chmod +x`) |
