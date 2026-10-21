# MCP 설정 가이드 (Claude Code · Codex · Cursor)

PWEH 는 MCP 서버 9개를 쓴다. 8개는 이 저장소에 있고, 1개는 외부 REA 다.

| 서버 이름 | 실행 파일 | 역할 |
|---|---|---|
| `pweh-case` | `.venv/bin/pweh-case-mcp` | 케이스, 단계 결과, 발견사항, 보고서, 프로필, 승인 상태 |
| `pweh-uart` | `.venv/bin/pweh-uart-mcp` | UART 콘솔 (U-Boot, Linux 셸, 덤프 job) |
| `pweh-sigrok` | `.venv/bin/pweh-sigrok-mcp` | 로직 애널라이저 (sigrok-cli) |
| `pweh-openocd` | `.venv/bin/pweh-openocd-mcp` | JTAG/SWD (OpenOCD) |
| `pweh-jtagulator` | `.venv/bin/pweh-jtagulator-mcp` | JTAGulator 핀아웃 스캔 (선택) |
| `pweh-fwtriage` | `.venv/bin/pweh-fwtriage-mcp` | 오프라인 펌웨어 트리아지 |
| `pweh-esp` | `.venv/bin/pweh-esp-mcp` | ESP32 계열 esptool 읽기 전용: 칩·보안 정보, 플래시 덤프 job. WSL 에서는 Windows `esptool.exe` + COM 포트(방법 A, §6) (선택) |
| `pweh-forensics` | `.venv/bin/pweh-forensics-mcp` | SD 카드 이미지 증거 분석: 사람이 쓰기 방지 장치로 만든 이미지 파일의 접수·해시·보관 기록, FAT/exFAT 목록, 삭제 파일 추출 job, 증거 목록. 기기·카드를 열지 않고 외부 도구가 필요 없다 (선택) |
| `rea` | `rea --mcp` (rea-agents 6.5.x) | binwalk/unblob 추출, Ghidra 디컴파일, sigrok 디코딩 |

도구 목록과 인자는 [architecture.md](architecture.md) §6 과 각 서버의 `mcp-servers/<name>/README.md` 에 있다.
서버가 실제로 내보내는 도구 전체(인자, annotation)는 [references/pweh-mcp-tools.md](references/pweh-mcp-tools.md) 에 있다.
서버 도구가 바뀌면 `.venv/bin/python scripts/dump_tool_catalog.py` 로 다시 만들고 `--check` 로 권한 규칙과 Skill 문서를 검사한다.

## 1. 설치

```bash
cd ~/pweh
./scripts/install.sh                   # 원클릭: Python 가상환경 + 외부 도구 + REA → MCP 등록 → Skill 링크 → 점검 (sudo 없음)
.venv/bin/pytest -q                    # 하드웨어 없이 전체 테스트 (외부 도구가 없으면 일부 skip)
```

`scripts/install.sh` 는 root 권한 없이 설치한다. 시스템 디렉터리와 셸 rc 파일은 바꾸지 않고, 설치물은 `~/pweh-tools`(외부 도구)와
`.venv`(Python)에만 둔다. 구성요소를 설치하고 `~/pweh-tools/env.sh` 를 만든 뒤 `mcp`(에이전트 클라이언트 MCP 등록)·`skills`(Skill 링크)·`verify`(점검) 단계를 돈다(§1.1).
MCP 단계가 저장소 밖에 쓰는 것은 Codex 홈의 trust 항목과 그 직전에 같은 디렉터리에 만드는 백업(`config.toml.bak-pweh-*`)뿐이고, 사람이 동의할 때만(대화형 터미널에서 묻거나 `--codex-trust`) 쓴다(`--codex-global` 을 주면 Codex 홈에 서버도 등록한다).
`codex` 는 있지만 `~/.codex` 가 아직 없으면 그 홈 디렉터리(0700)와 새 `config.toml` 을 만든다(백업할 기존 파일이 없다).
다시 실행하면 이미 설치된 구성요소는 건너뛰고, MCP·Skill 단계는 같은 결과를 다시 만든다.

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
- **점검:** 설치 끝의 `verify` 단계가 `pweh doctor` 와 `pweh mcp-check` 를 돌린다(§1.1). 실행 파일이 있어도 버전 확인이 실패하면(공유 라이브러리 없음, Traceback 등) `!!` 로 표시한다.
- **옵션:** `--minimal`, `--only a,b`, `--skip a,b`, `--check`(점검만), `--list`, `--force`(다시 설치), `--prefix DIR`,
  `--seed DIR`, `--no-link`. MCP 등록·Skill·점검 단계의 옵션(`--no-mcp`, `--dry-run`, `--codex-trust` 등)은 §1.1 에 있다.
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
  MCP 등록·trust 를 되돌리는 방법은 §1.2 에 있다.

Claude Code·Cursor 의 MCP 서버는 `scripts/mcp-launch.sh` 를 거쳐 실행된다. 이 런처가 위 env.sh 를 자동으로 불러온다.
Codex 설정은 PWEH 서버의 `env` 에 env.sh 의 도구 경로(`PWEH_*`)를 직접 넣으므로(§3.4), env.sh 의 경로가 바뀌면 Codex 설정을 다시 만든다(`pweh mcp-config --client codex --write`).
REA 는 Codex 에서도 런처로 실행돼 env.sh 를 실행할 때 불러온다(설정 파일에 셸의 `PATH` 를 적지 않는다).

### 1.1 MCP 등록·Skill·점검 단계

구성요소 다음에 세 단계가 돈다. 구성요소처럼 고를 수 있다(예: `./scripts/install.sh --only mcp,verify` 는 설치 없이 MCP 등록과 점검만 다시 한다).

| 단계 | 하는 일 | 쓰는 곳 |
|---|---|---|
| `mcp` | **Claude Code:** `.mcp.json` 과 `.claude/settings.json` 의 `enabledMcpjsonServers` 가 서버 9개와 맞는지 확인한다. 사용자 전역 설정(`~/.claude*`)은 건드리지 않는다. **Codex:** `pweh mcp-config --client codex --write`(프로젝트 범위, §3.2) 다음에 `pweh codex-trust`. **Cursor:** `--cursor` 를 줄 때만 `.cursor/mcp.json` 을 만든다(§4) | `<저장소>/.codex/config.toml`, 동의하면 Codex 홈마다 `config.toml` 의 trust 항목, `--cursor` 면 `.cursor/mcp.json` |
| `skills` | `pweh skills install --target claude-project` 와 `pweh skills install --target agents`. 이미 맞는 링크는 그대로 둔다 | `.claude/skills/<name>`, `.agents/skills/<name>` 링크 (저장소에 이미 들어 있다) |
| `verify` | `pweh doctor` 와 `pweh mcp-check`. 서버를 띄워 도구 목록만 받고 도구는 호출하지 않는다(§3.6). REA(선택 구성요소)가 설치되지 않았으면 `rea` 서버만 선택 서버로 넘겨(`--optional rea`) 그 실패는 경고로 본다. 다른 서버의 실패는 실패다 | 설정 파일은 없음. `pweh doctor` 가 저장소의 `cases/`·`.pweh/state` 가 없으면 만든다(어느 디렉터리에서 실행해도 저장소 설정 `PWEH_CONFIG` 로 돈다) |

- `--no-mcp`: `mcp` 단계를 건너뛴다. `--no-verify`: `verify` 단계를 건너뛴다.
- `--dry-run`: 실행 전체를 읽기 전용으로 바꾼다. 구성요소 설치·env.sh·`verify` 는 하지 않고, `skills` 는 링크 상태만 보여 주며,
  `mcp` 단계(Codex 설정·trust, `--cursor`)가 바꿀 파일과 diff 만 보여 준다. 아무것도 쓰지 않는다(예: `./scripts/install.sh --only mcp --dry-run`).
- `--codex-trust` / `--no-codex-trust`: trust 를 묻지 않고 더한다(`pweh codex-trust --yes`) / trust 단계를 건너뛴다.
  둘 다 없으면 대화형 터미널에서만 묻고, 대화형이 아니면(파이프·CI) 쓰지 않는다. 나중에 `pweh codex-trust` 로 따로 해도 된다.
- `--codex-global`: 프로젝트 범위 대신 Codex 홈의 `config.toml` 에 서버를 등록한다(`--scope global`, §3.3).
- `--codex-home DIR`: 자동 감지 대신 이 Codex 홈을 쓴다. 여러 번 줄 수 있고 `pweh mcp-config`·`pweh codex-trust` 에 그대로 넘긴다(§3.1).
- `--cursor`: `.cursor/mcp.json` 도 만든다.
- `--check`: 구성요소 점검에 더해 Codex 설정·trust 점검과 `pweh mcp-check` 를 돌린다. 아무것도 쓰지 않는다.
  예전 pweh 가 서버 `env` 에 넣던 `PATH` 만 다르면 최신으로 본다(지금 pweh 는 `PATH` 를 쓰지 않는다).
  trust 점검은 `pweh codex-trust --check` 의 종료 코드를 따른다(0 신뢰됨, 1 신뢰 없음, 2 확인하지 못함 — 읽지 못한 설정·이전 판 가상환경).
  trust 를 거절한 뒤에도 `--check` 는 1 로 끝난다(설치 실행은 0). 이 점검을 끄려면 `--no-codex-trust` 를 준다.
- 다시 실행해도 프로젝트 설정의 `--direct`·`--no-rea`·`--tools-env` 선택은 그대로다(§3.2). 전역 범위로 등록했으면 다시 실행할 때도 `--codex-global` 과 옵션을 준다.

### 1.2 MCP 등록 되돌리기

되돌리는 명령은 따로 없다. 다음 파일을 직접 고친다.
- **Codex 프로젝트 설정:** `<저장소>/.codex/config.toml` 을 지운다. 그 자리에 pweh 가 만들지 않은 파일이나 pweh 가 만든 뒤 사람이 고친 파일이 있었으면 덮어쓰기 전에 백업했고, 백업 경로는 실행할 때 출력됐다.
- **trust:** Codex 홈마다 `config.toml` 에서 `[projects."<저장소 실제 경로>"]` 표를 지운다(실제 경로 = 심볼릭 링크를 푼 경로).
  또는 쓰기 전에 같은 디렉터리에 만든 백업 `config.toml.bak-pweh-<UTC 시각>` 으로 되돌린다. 백업으로 되돌리면 그 뒤에 Codex 나 사람이 바꾼 내용도 함께 사라진다.
- **전역 범위(`--codex-global`, `--scope global`):** 백업으로 되돌리거나, 백업과 비교해 pweh 가 더한 것만 지운다.
  `[mcp_servers.pweh-*]` 표, pweh 가 관리하던 `[mcp_servers.rea]`, `[features.code_mode]` 의 `direct_only_tool_namespaces` 에서 `mcp__pweh_` 로 시작하는 항목, 원래 없던 `mcp_optional_startup_grace_ms` 가 그 대상이다.
- **Cursor:** 설치 스크립트가 `.cursor/mcp.json` 을 새로 만들었으면 지운다. 있던 파일의 PWEH 항목을 바꿨으면 바꾸기 전에 만든 백업
  `.cursor/mcp.json.bak-pweh-<UTC 시각>` 으로 되돌린다(지우면 사용자의 다른 서버 항목도 사라진다).
- 설치 스크립트는 끝에 이번 실행이 쓰거나 백업한 파일과 되돌리는 명령(`cp -p <백업> <파일>`, 새로 만든 파일은 `rm`)을 보여 준다. 명령은 보여 주기만 한다.
- Claude Code 설정(`.mcp.json`, `.claude/`)과 Skill 링크는 저장소에 들어 있는 파일이라 되돌릴 것이 없다.

## 2. Claude Code

### 2.1 서버 등록
저장소 루트의 `.mcp.json` 이 프로젝트 범위로 9개 서버(`pweh-case`, `pweh-uart`, `pweh-openocd`, `pweh-sigrok`, `pweh-jtagulator`, `pweh-fwtriage`, `pweh-esp`, `pweh-forensics`, `rea`)를 등록한다.
`.claude/settings.json` 의 `enabledMcpjsonServers` 도 같은 9개다. 다시 만들려면 다음을 실행한다.
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
  저장소를 업데이트해 `.mcp.json` 에 서버가 새로 생기면(예: `pweh-esp`, `pweh-forensics`) Claude Code 를 다시 시작한다. 새 서버의 승인 다이얼로그가 뜨면 승인하고, `/mcp` 에서 연결됐는지 확인한다.
- 절대 경로 형태를 원하면 `--style absolute` 를 쓴다. 이 형태는 PWEH 서버의 `env` 에 env.sh 의 도구 경로를 직접 넣고, REA 는 런처 절대 경로로 등록한다(실행한 셸의 `PATH` 는 넣지 않는다).

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
    임의 Rizin 명령을 실행하는 `execute_rizin_command`(셸 탈출 `!` 로 호스트 명령 실행 가능),
    pweh-forensics 의 쓰는 도구 7개(`forensics_intake_start`, `forensics_verify_start`, `forensics_acquisition_attest`, `forensics_fs_list`, `forensics_extract`,
    `forensics_evidence_list`, `forensics_job_cancel` — 카드 이미지는 제3자의 개인정보라 접수·검증·증명·목록·추출·증거 목록을 매번 사람이 확인한다).
    **bypassPermissions 모드에서도 묻는다.**
  - `allow`: pweh 서버의 조회 전용 도구(`readOnlyHint`), `pweh-case`·`pweh-fwtriage` 전체(`mcp__pweh-case__*`, `mcp__pweh-fwtriage__*`),
    REA 정적 분석 도구. 기본 모드에서 묻지 않는다(bypass 모드에서는 원래 묻지 않으므로 의미가 없다).
    프로젝트 `allow` 는 workspace trust 를 수락한 뒤에만 적용되고, `ask`/`deny` 는 trust 와 무관하게 적용된다.
  - 둘 다 아닌 도구(예: `uart_send_command`, `uboot_dump_start`, `sigrok_capture`, `openocd_halt`, `esp_chip_info`, `esp_read_flash_start`)는 기본 모드에서 처음 쓸 때 묻는다.
    pweh-esp 는 `esp_version`, `esp_list_ports`, `esp_job_status`, `esp_jobs` 가 `allow` 에 있다.
    pweh-forensics 는 조회 전용 `forensics_partitions`, `forensics_image_check`, `forensics_job_status`, `forensics_jobs` 만 `allow` 에 있고 나머지는 모두 위의 `ask` 다.
    이 서버는 기기에 아무것도 보내지 않아 서버 측 게이트가 없다. 증거는 보관 기록·무결성 확인·사람 증명으로 지킨다([safety.md](safety.md) §3.5·§7.1, 알려진 한계는 §3.6, [architecture.md](architecture.md) §6.8).
- `anthropic/requiresUserInteraction` 메타는 항상 파괴적인 세 도구(`openocd_flash_write`, `openocd_write_memory`,
  `jtagulator_set_voltage`)에만 붙어 있어, 이 도구들은 allow 규칙과 무관하게 bypassPermissions 모드에서도 매번 확인을 띄운다.
  사람에게 물을 수 없는 경로(`dontAsk` 모드, `--permission-prompt-tool`)에서는 묻는 대신 거부된다.
- 그래도 **최종 판단은 서버 측 안전 게이트**가 한다 ([safety.md](safety.md) §3).
  게이트가 사람 승인을 요구하면 두 경로 중 하나로 승인한다.
  - **elicitation 확인 폼**: Claude Code v2.1.76+ 에서 다이얼로그가 뜬다. 확인 코드를 입력하고 Accept 한다.
  - **CLI**: 별도 터미널에서 `.venv/bin/pweh approve <approval_id>` 를 실행한다.
- 승인과 별도로, 에이전트가 확인할 수 없는 사실(콘솔 오프라인, 잰 전압, 가져온 파일의 출처 등)이 필요한 도구는 **사람 증명**을 요구할 수 있다
  (`status: attestation_required` + `attestation_id`. 지금은 세이브 쓰기 명령을 보여 주기 전의 `fw_patch_build` 와 SD 카드 이미징의 쓰기 방지 장치를 묻는 `forensics_acquisition_attest` 다 — [safety.md](safety.md) §3.5).
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

장시간 작업(UART 덤프, ESP32 플래시 덤프, 긴 캡처, 핀아웃 스캔, SD 카드 이미지 접수·재해시·추출)은 PWEH 가 job 으로 실행한다.
`*_job_status(job_id, wait_seconds≤50)` 로 폴링하므로 어떤 클라이언트 타임아웃에도 걸리지 않는다.
예외로 pweh-forensics 의 `forensics_partitions`·`forensics_image_check`·`forensics_fs_list` 는 job 이 아닌 동기 도구다(호출 예산 60초·120초·`max_seconds` — 기본 180초, 최대 600초, 목록 파일 쓰기 시간은 따로.
`max_seconds` 를 600 으로 주면 아래 Codex 의 `tool_timeout_sec` 600초를 넘을 수 있다).
클라이언트가 그 전에 시간 초과·취소로 끊어도 서버의 작업은 예산까지 돌고 `forensics_fs_list` 는 목록 파일과 보관 기록을 남긴다([safety.md](safety.md) §3.6).

## 3. Codex (CLI · 데스크톱 앱)

Codex 설정은 `pweh mcp-config --client codex --write`(서버 등록)와 `pweh codex-trust`(프로젝트 trust)가 만든다. `./scripts/install.sh` 의 `mcp` 단계가 둘 다 실행한다(§1.1).
아래 Codex 동작은 Codex 0.162.0 의 소스와 실측 기준이다(근거: [agent-clients.md](references/agent-clients.md) §3). Codex 버전이 바뀌면 달라질 수 있다.

### 3.1 Codex 클라이언트 두 가지와 Codex 홈

한 PC 에 Codex 클라이언트가 둘 있을 수 있다. 각자 자기 **Codex 홈**의 `config.toml` 을 읽으므로, 한쪽에만 등록하면 다른 쪽에서는 PWEH 도구가 보이지 않는다.

| 클라이언트 | 에이전트가 도는 곳 | Codex 홈 (`config.toml` 이 있는 곳) | pweh 표시 |
|---|---|---|---|
| Codex CLI (WSL 터미널에서 `codex`) | WSL | `$CODEX_HOME`, 없으면 `~/.codex` | `cli` |
| Codex 데스크톱 앱 (Windows), WSL 모드 | WSL 안 | Windows 프로필의 `.codex` (WSL 경로 `/mnt/c/Users/<Windows 사용자>/.codex`). 앱이 `WSLENV` 의 `CODEX_HOME/p` 로 WSL 에 넘긴다 | `desktop-wsl` |
| `--codex-home` 으로 고른 홈 | — | 준 디렉터리 | `explicit` |

- 데스크톱 앱의 WSL 모드는 그 홈 `config.toml` 의 `[desktop] runCodexInWindowsSubsystemForLinux = true` 다. 에이전트는 WSL 안에서 돌지만 설정은 Windows 쪽 홈에서 읽는다.
- **자동 감지**(`--codex-home` 을 주지 않을 때)는 다음 홈을 대상으로 삼는다. 건너뛴 홈은 이유와 함께 보고된다.
  - `CODEX_HOME` 이 설정돼 있으면 그 디렉터리 (`cli`).
  - `~/.codex` 가 있거나 `codex` 가 `PATH` 에 있으면 `~/.codex` (`cli`).
  - Windows 프로필에 `.codex/config.toml` 이 있고 WSL 모드가 켜져 있으면 그 홈 (`desktop-wsl`). WSL 모드가 꺼져 있으면 건너뛴다(§3.5).
- Windows 프로필 위치는 실행할 때마다 알아낸다. Windows 사용자 이름을 저장소나 설정에 적어 두지 않는다.
  순서: 환경변수 `PWEH_WINDOWS_PROFILE`(직접 지정 — WSL 경로 또는 `C:\Users\…`) → WSL 경로로 넘어온 `USERPROFILE` → WSL interop
  (System32 `powershell.exe` 로 코드에 고정한 읽기 전용 스크립트만 실행. `hostenv.disable: [interop]` 이면 하지 않는다).
  찾지 못하거나 다른 홈을 쓰려면 `--codex-home` 으로 준다. 여러 번 줄 수 있고, 주면 자동 감지를 하지 않는다.

```bash
WIN_CODEX_HOME="/mnt/c/Users/<Windows 사용자>/.codex"    # 예: 데스크톱 앱의 Codex 홈
.venv/bin/pweh codex-trust --codex-home "$WIN_CODEX_HOME" --dry-run
```

### 3.2 권장: 프로젝트 범위 설정 + trust

```bash
.venv/bin/pweh mcp-config --client codex --write --dry-run   # 바뀔 내용을 diff 로만 보기
.venv/bin/pweh mcp-config --client codex --write             # <저장소>/.codex/config.toml 생성
.venv/bin/pweh codex-trust                                   # 감지한 Codex 홈마다 trust 추가 (대화형 터미널에서 묻는다)
.venv/bin/pweh codex-trust --check                           # trust 가 빠진 홈이 있으면 종료 코드 1 (쓰지 않음)
.venv/bin/pweh mcp-check --client codex                      # 서버마다 시작·도구 목록 확인 (§3.6)
```

- **프로젝트 범위인 이유:** `<저장소>/.codex/config.toml` 은 이 저장소에서 Codex 를 열 때만 읽힌다. 그래서 PWEH 서버(하드웨어 도구 포함)가 다른 프로젝트의 Codex 세션에 뜨지 않고, 거기서 도구 정의 토큰을 쓰지도 않는다.
  이 파일은 pweh 가 만드는 생성물이다(맨 위에 pweh 표시가 있다). 이 PC 의 절대 경로와 env.sh 의 도구 경로가 들어 있으므로 커밋하지 않는다(실행한 셸의 `PATH` 는 넣지 않는다).
- **다시 실행해도 된다:** `--write` 는 파일 전체를 새로 쓴다(같으면 쓰지 않는다). 쓴 파일과 백업은 모두 출력된다.
  - 파일 둘째 줄에 내용 지문(`# pweh-sha256:`)이 있다. pweh 가 쓴 그대로인 파일은 백업 없이 바꾸고, pweh 가 만들지 않은 파일이나
    만든 뒤 고친 파일(지문이 맞지 않음)은 먼저 백업한다. 이때 새 내용에 없어 백업에만 남는 표·키 이름을 알린다(`--dry-run` 에서도. 값은 보여 주지 않는다).
  - `--direct`·`--no-rea`·`--tools-env` 를 주지 않으면 기존 파일 머리의 `# pweh-options` 값을 이어 쓴다(설치 스크립트를 다시 돌려도 고른 옵션이 기본값으로 돌아가지 않는다).
    바꾸려면 직접 준다(`--direct all`, REA 를 다시 넣으려면 `--rea`).
  - 서버 `command` 는 지금 실행한 pweh 가 설치된 가상환경의 콘솔 스크립트다(`install.sh --venv DIR` 이면 `DIR/bin`). 그 스크립트가 없으면 쓰지 않고 종료 코드 1 로 끝난다.
  - `<저장소>/.codex` 나 그 `config.toml` 이 심볼릭 링크면 쓰지 않는다(링크가 가리키는 다른 파일 — 예: 사용자 Codex 홈의 `config.toml` — 을 덮어쓰지 않게).
- **trust 가 필요한 이유:** Codex 는 trusted 프로젝트의 `.codex/config.toml` 만 읽는다. trust 가 없으면 프로젝트의 `.codex/` 를 통째로 무시하므로 PWEH 서버가 하나도 보이지 않는다(가장 흔한 원인).
  - `pweh codex-trust` 는 Codex 홈마다 `config.toml` 에 `[projects."<저장소 실제 경로>"]` 표와 `trust_level = "trusted"` 를 더한다.
    키는 저장소의 실제 경로(심볼릭 링크를 푼 경로)다. 상위 디렉터리(예: 홈 디렉터리)를 trust 해도 저장소는 포함되지 않는다.
    이미 `trust_level = "untrusted"` 라고 정해 둔 홈도 `trusted` 로 바꾼다(그 결정을 되돌리려면 백업으로 되돌린다).
  - 기존 `config.toml` 은 주석·서식(CRLF 포함)을 지키며 고친다. 쓰기 전에 같은 디렉터리에 `config.toml.bak-pweh-<UTC 시각>` 백업을 남기고,
    고친 내용을 다시 읽어 검사한 뒤 원자적으로 바꾼다(파일 권한 유지). 기존 파일이 올바른 TOML 이 아니면 아무것도 쓰지 않고 종료 코드 1 로 끝난다.
  - `--yes` 가 없으면 대화형 터미널에서 묻고, 대화형이 아니면 쓰지 않는다. `--dry-run` 은 diff 만 보여 준다.
    사용자 설정의 diff 는 바뀌지 않는 줄의 값을 `…` 로 가린다(다른 서버의 토큰 같은 값이 화면·로그에 나오지 않게. 표 머리와 pweh 가 더하는 줄은 보인다).
  - `--check` 는 쓰지 않는다. 종료 코드 0 = 모두 신뢰됨, 1 = 신뢰 항목이 없는 홈이 있음, 2 = 읽지 못한 홈이 있어 확인하지 못함.
  - 같은 홈을 고치는 다른 pweh(설치 스크립트)와 겹치지 않게 읽기부터 바꾸기까지 그 디렉터리를 잠근다(잠글 수 없는 파일 시스템이면 건너뛴다).
    바꾸기 직전에 파일이 읽은 뒤 그대로인지, 바꾼 뒤 쓴 내용과 같은지 다시 확인하고, 다르면 쓰지 않거나 오류로 끝난다(Codex 앱이 같은 파일을 동시에 고친 경우).
  - `--codex-home` 은 이미 있는 디렉터리이거나 이름이 `.codex` 여야 한다(오타로 새 홈을 만들지 않게). 빈 값은 거부한다.
  - trust 는 PWEH 전용 설정이 아니라 'Codex 가 이 폴더를 믿는다'는 결정이다. Codex 0.162.0 소스 기준, 샌드박스를 따로 정하지 않았다면
    trust 된 폴더의 기본 권한은 workspace-write 다(trust 결정이 없는 폴더는 read-only). 이 점을 알고 동의한다.
- **출력을 `>>` 로 덧붙이지 않는다.** `--write` 없이 실행하면 같은 설정을 화면에 출력만 한다(검토용. 맨 위 주석이 `--write` 를 쓰라고 알려 준다). 이 출력을 `config.toml` 에 `>>` 로 덧붙이면 다음 문제가 생긴다.
  - 두 번 덧붙이면 같은 표가 두 번 생겨 Codex 가 시작하지 않는다(`duplicate key` 오류, 예: `[mcp_servers.pweh-case]`).
    그런 파일은 올바른 TOML 이 아니어서 `--scope global` 도 거부한다. 사람이 중복 표를 지운 뒤 다시 실행한다.
  - 표 뒤에 덧붙인 최상위 키(`mcp_optional_startup_grace_ms`)는 TOML 규칙상 바로 앞 표(예: `[mcp_servers.rea]`)의 키가 된다. Codex 는 모르는 키를 무시하므로 오류 없이 효과만 사라진다.
- 예전 안내대로 `~/.codex/config.toml` 에 PWEH 항목을 덧붙여 두었다면, 프로젝트 범위로 옮길 때 그 항목을 지운다. 남겨 두면 다른 프로젝트에서도 PWEH 서버가 뜬다.

### 3.3 전역 범위 (`--scope global`)

다른 디렉터리에서도 PWEH 를 쓰거나 프로젝트 trust 를 쓰지 않으려면 Codex 홈의 `config.toml` 에 직접 등록한다(설치 스크립트는 `--codex-global`).
그 홈을 쓰는 모든 Codex 세션에 PWEH 서버(하드웨어 도구 포함)가 뜨므로 기본은 프로젝트 범위다.

```bash
.venv/bin/pweh mcp-config --client codex --write --scope global --dry-run   # 홈마다 바뀔 내용(diff)
.venv/bin/pweh mcp-config --client codex --write --scope global
```

감지한(또는 `--codex-home` 으로 준) 홈마다 `config.toml` 을 주석·서식(CRLF 포함)을 지키며 고친다.
- `[mcp_servers.pweh-*]` 표는 새로 만든 것으로 바꾼다. 그 표 안에서 사람이 정한 `enabled`·`required`·`enabled_tools`·`disabled_tools`·`tools.<도구>`(도구별 `approval_mode` 등)는
  옮겨 둔다(REA 의 `enabled_tools` 는 pweh 가 만드는 값이라 옮기지 않는다). 그 밖에 새 표에 없어 빠지는 키는 이름을 알린다(백업에만 남는다). 표 안의 주석은 남지 않는다.
- pweh-managed 표식이 없는 `[mcp_servers.pweh-*]`(예전에 붙여 넣은 표)는 내용이 같아도 표식을 달아 바꾼다.
- `[mcp_servers.rea]` 는 없거나 이전에 pweh 가 관리한다고 표시해 둔 것일 때만 쓴다. 사람이 직접 만든 rea 항목은 그대로 둔다.
- `[features.code_mode]` 의 `direct_only_tool_namespaces` 는 합친다. 사용자의 항목은 남기고, 이제 쓰지 않는 pweh 항목은 뺀다.
- 최상위 `mcp_optional_startup_grace_ms` 는 없을 때만 넣는다. 이미 있으면 값이 작아도(예: 1000) 그대로 둔다. REA 가 첫 턴에 빠지면 사람이 15000 으로 올린다(§3.4).
- 백업, 다시 읽어 검사, 원자적 교체, 잘못된 TOML 거부는 trust 와 같다(§3.2).
- 바뀔 것이 없으면 파일을 쓰지 않는다(다시 실행해도 백업이 쌓이지 않는다).
- 이렇게 등록한 홈은 trust 가 없어도 PWEH 도구가 뜬다. `pweh doctor` 도 그 홈의 trust 가 없는 것을 문제(`!!`)로 보지 않는다.
  프로젝트 설정이 없는 것은 감지한 모든 홈이 이렇게 등록돼 있을 때만 문제로 보지 않는다(등록이 없는 홈에는 프로젝트 설정과 trust 가 필요하다).
  홈에 직접 있는 표의 실행 파일이 없으면(옮긴 저장소·가상환경, 예전에 붙여 넣은 표) 그 홈의 Codex 는 그 표로 서버를 띄우다 실패하므로 trust 가 없을 때 `!!` 로 보고,
  표식 없는 표는 실행 파일이 있어도 옮기는 방법(`--scope global --codex-home <홈>` 또는 그 표 지우기)을 알린다.
- `~/.codex` 가 WSL 모드가 아닌 Windows 데스크톱 앱의 홈과 같은 디렉터리(링크)면, 그 앱은 리눅스 경로의 서버를 실행하지 못하므로 자동 감지로는 서버를 쓰지 않고 이유를 알린다.
  그래도 쓰려면 `--codex-home` 으로 직접 준다(trust 항목은 그대로 더한다).

### 3.4 PWEH 가 설정하는 값

프로젝트 설정에 들어가는 순서와 값이다. 전역 범위는 §3.3 규칙으로 같은 값을 합친다.

| 위치 | 값 | 이유 |
|---|---|---|
| 최상위 (첫 표보다 앞) | `mcp_optional_startup_grace_ms = 15000` | Codex 는 첫 도구 목록을 만들 때 선택(optional) 서버를 이 시간까지만 기다린다(기본 1000 ms). REA 는 시작에 약 1.5초가 걸려 기본값이면 첫 턴에서 빠진다(PWEH 서버는 한 번 실행한 뒤 약 0.5~0.75초). 서버가 다 뜨면 그 전에 진행한다. 첫 표보다 앞에 있어야 최상위 키다 |
| `[features.code_mode]` | `direct_only_tool_namespaces`. 기본은 PWEH 서버 8개 전부(`mcp__pweh_case`, `mcp__pweh_uart`, …, `mcp__pweh_forensics`) | Codex 0.162.0 의 현재 모델은 Code Mode + tool search 로 돈다. MCP 도구는 지연 로딩되어 모델의 도구 목록에 나오지 않고, 모델이 `ALL_TOOLS` 나 tool search 로 찾아야 한다. 여기 적은 네임스페이스는 바로 보인다(Codex 는 서버 이름의 `-` 를 `_` 로 바꾼다). 대신 8개 전부면 요청마다 도구 정의가 약 112 KB 늘어난다. `--direct case` 는 `mcp__pweh_case` 만 넣고, `--direct none` 은 이 표를 넣지 않는다 |
| `[mcp_servers.pweh-*]` (8개) | 절대 경로 `command`(지금 실행한 pweh 가 설치된 가상환경의 콘솔 스크립트), `args = []`, `cwd`(저장소), `env`(`PWEH_CONFIG` + env.sh 의 `PWEH_*` 도구 경로 — `PATH` 는 넣지 않는다), `env_vars = ["WSL_DISTRO_NAME"]`, `startup_timeout_sec = 60`, `tool_timeout_sec = 600` | Codex 는 서버에 화이트리스트 환경변수(`HOME`, `LOGNAME`, `PATH`, `SHELL`, `USER`, `LANG`, `LC_ALL`, `TERM`, `TMPDIR`, `TZ` 등)와 `env`·`env_vars` 만 넘긴다. 그래서 env.sh 의 도구 경로를 `env` 에 넣는다. `WSL_DISTRO_NAME` 은 표시용(`pweh env` 의 배포판 이름)이라 없어도 된다. `WSL_INTEROP` 은 넘기지 않아도 interop(esptool.exe 등)이 동작한다. 기본 타임아웃은 문서(시작 10초·도구 60초)와 소스(30초·300초)가 달라 명시한다 |
| `[mcp_servers.rea]` (`--no-rea` 면 없음) | `command` = `<저장소>/scripts/mcp-launch.sh`, `args = ["rea"]`, `env`(Ghidra·JDK·추출 도구 경로, 불러올 env.sh `PWEH_TOOLS_ENV`), `enabled_tools`, `tool_timeout_sec = 900` | REA 는 env.sh 가 `PATH` 에 넣는 node·JDK·압축 해제 도구가 있어야 돈다. 런처가 실행할 때 env.sh 를 불러오므로 설정 파일에 셸의 `PATH`(WSL 이면 Windows 사용자 이름이 든 Windows PATH)를 적지 않는다. REA 6.5 는 도구 207개(tools/list 약 3 MB)를 내보낸다. `enabled_tools` 에는 `.claude/settings.json` 의 `mcp__rea__*` 규칙(allow·ask)에 있는 도구만 넣는다. 거기 없는 REA 도구는 Codex 에서 보이지 않는다 |

- Codex 는 `.claude/settings.json` 의 권한 규칙(§2.3)을 쓰지 않는다. pweh 가 REA 의 `enabled_tools` 를 만들 때 읽을 뿐이다.
  도구 호출 승인은 Codex 자체 판정(도구 annotation 기준)을 따른다([agent-clients.md](references/agent-clients.md) §3.5). 어느 클라이언트든 최종 판단은 서버 측 안전 게이트다.

### 3.5 클라이언트별 주의

- **설정을 바꾼 뒤:** 데스크톱 앱은 다시 시작하거나 적어도 새 스레드를 연다. 이미 열린 스레드는 시작할 때 읽은 MCP 설정을 계속 쓸 수 있다(앱이 설정을 언제 다시 읽는지는 확인하지 않았다). CLI 는 `codex` 를 다시 실행한다.
- **데스크톱 앱의 WSL 모드가 꺼진 경우(네이티브 Windows):** 에이전트가 Windows 에서 돌아 `/home/...` 같은 리눅스 경로의 서버를 실행할 수 없다. PWEH 서버도 네이티브 Windows 에서는 시작하지 않는다(§8).
  그래서 pweh 는 그 홈을 건너뛰었다고 보고하고 쓰지 않는다. 앱 설정에서 WSL 모드를 켜거나 WSL 안의 Codex CLI 를 쓴다.
  Windows 클라이언트가 `wsl.exe` 로 서버를 띄우는 방식(§8)은 pweh 가 만들어 주지 않고, Codex 데스크톱 앱에서는 시험하지 않았다.
- **`codex exec`(비대화형):** 승인 정책을 `never` 로 고정한다. 그래서 승인이 필요한 MCP 도구 호출(Codex 기본 판정에서 `openWorldHint` 가 켜진 기기 도구와 파괴적 도구)은 묻지 않고 거부된다.
  하드웨어 분석은 대화형 Codex(CLI 또는 앱)에서 한다. full access(`--sandbox danger-full-access`, `--dangerously-bypass-approvals-and-sandbox`)로 실행하면 거부되지 않고 아래처럼 자동 승인된다.
- **도구 이름:** Codex 에서는 `mcp__pweh_<서버>__<도구>` 다(예: `mcp__pweh_case__case_create`, REA 는 `mcp__rea__open_binary`).
  마스터 프롬프트와 `pweh-start` Skill 이 에이전트에게 이 이름과, 목록에 없을 때 `ALL_TOOLS` 에서 `mcp__pweh_` 로 찾는 방법을 알려 준다.
- Skill: `.agents/skills/<name>` 심볼릭 링크를 Codex 가 프로젝트 Skill 로 읽는다. `$pweh-start` 로 시작한다.
- `AGENTS.md` 에 프로젝트 규칙이 있다.
- 주의: Codex 를 `-a never` + full access 로 실행하면 도구 호출이 자동 승인된다.
  이때 Codex 는 필드가 있는 elicitation 을 자동 거절(decline)한다. PWEH 의 확인 폼은 필드가 있어 자동 수락되지 않고,
  거절되면 게이트가 CLI 승인으로 넘어가지 않고 `denied` 로 끝난다(fail-closed).
  그런 환경에서 위험 작업 승인이 필요하면 사람이 `pipeline-config.yaml` 의 `safety.approval_methods` 를 `[cli]` 로 바꾸고
  서버를 재시작한 뒤 CLI 승인(`pweh approve`)을 쓴다.
  사람 증명도 같은 설정을 따른다: 폼이 자동 거절되면 그 증명 요청은 거부(`denied`)로 기록되고, `[cli]` 면 사람이 `pweh attest <id>` 로 답한다.

### 3.6 문제 해결 (Codex)

먼저 PWEH 쪽에서 서버가 뜨는지 보고, 그다음 Codex 가 무엇을 읽었는지 본다.
1. `pweh mcp-check --client codex`: Codex 설정대로 서버마다 띄워(Codex 세션 시작처럼 동시에) `initialize` 와 `tools/list` 만 하고 도구는 호출하지 않는다.
   서버는 설정의 `env` 그대로(`PWEH_CONFIG` = 저장소 설정) 뜬다. 도구를 부르지 않으므로 케이스나 승인 상태를 만들거나 바꾸지 않는다.
   환경은 Codex 와 비슷하게 화이트리스트 변수(`HOME`, `LOGNAME`, `PATH`, `SHELL`, `USER`, `LANG`, `LC_ALL`, `TERM`, `TMPDIR`, `TZ`)와 설정의 `env`·`env_vars` 만 준다.
   서버마다 ok·걸린 시간·도구 수·오류를 보여 주고, 모두 ok 일 때만 종료 코드 0 이다. `--json`(기계용 출력), `--timeout S`, `--client claude`·`--client all` 도 쓸 수 있다.
   `--optional SERVER` 로 준 서버(설치 스크립트는 REA 가 없을 때 `rea`)의 실패는 보고만 하고 종료 코드에 넣지 않는다.
   Codex 는 실제로 띄울 설정을 점검한다: 프로젝트 설정(trust 한 홈이 없으면 'Codex 는 아직 읽지 않는다'고 알린다)과, 이 저장소를 trust 하지 않는 홈에
   직접 등록된 `[mcp_servers.pweh-*]`(`codex[<표시>]` — 그 홈의 Codex 는 프로젝트 설정 대신 이 표로 서버를 띄운다).
   중단(Ctrl-C, 설치 스크립트의 시간 제한)되면 띄운 서버를 프로세스 그룹째 정리한다.
   - `--deep`: `codex` 실행 파일이 있으면 Codex 자신의 MCP 클라이언트(`codex app-server` + `mcpServerStatus/list`)를 오프라인으로 돌린다.
     생성한 서버만 넣은 **임시** Codex 홈을 쓰므로(로그인·네트워크 없음) 사용자의 Codex 홈은 건드리지 않는다.
2. `pweh doctor`: Codex 줄에 프로젝트 설정이 있고 최신인지, 감지한 홈마다 trust 가 있는지(데스크톱 앱의 WSL 모드 안내 포함), 홈에 직접 등록된 PWEH 서버 표의 문제
   (실행 파일 없음, pweh-managed 표식 없음 — `codex:home-servers[…]`)가 나오고 `pweh mcp-check` 를 권한다.
3. `codex mcp list`: 저장소 디렉터리에서 실행하면 그 Codex 홈이 읽는 서버 목록이 나온다(프로젝트 설정은 trust 가 있을 때만 합쳐진다). CLI 홈 기준이다.
   CLI 세션 안에서는 `/mcp`(목록)와 `/mcp verbose`(진단)를 쓴다.
   데스크톱 앱 홈을 보려고 `CODEX_HOME` 을 Windows 쪽 홈으로 바꿔 Codex CLI 를 실행하는 것은 권하지 않는다(그 홈에 상태 DB 를 만들거나 고칠 수 있다 — 확인하지 않았다).
4. 데스크톱 앱: 앱 설정의 MCP 서버 상태 화면에서 서버별 연결 상태와 오류를 본다(메뉴 이름·위치는 앱 버전마다 달라 여기 적지 않는다).
5. 로그: Codex 는 진단 로그를 그 Codex 홈의 SQLite 파일(`logs_*.sqlite`)에 남기고, 스레드 상태는 `state_*.sqlite` 에 둔다(이름의 숫자는 Codex 버전마다 다르다).
   `CODEX_SQLITE_HOME` 이나 설정의 `sqlite_home` 으로 위치를 바꿨으면 그곳이다. 데스크톱 앱의 파일은 Windows 프로필의 `.codex` 아래에 있다. Codex 가 쓰고 있는 파일이므로 복사본을 열어 본다.

| 증상 | 확인 |
|---|---|
| PWEH 도구가 하나도 안 보임 | trust 가 없다(`pweh codex-trust --check`). 또는 다른 Codex 홈을 쓰는 클라이언트다(CLI 와 데스크톱 앱은 홈이 다르다, §3.1). 앱이면 다시 시작하거나 새 스레드를 연다 |
| Codex 가 시작하지 않고 `duplicate key` 오류 | `config.toml` 에 같은 표가 두 번 있다(`>>` 로 두 번 덧붙임). 중복 표를 지운다(§3.2) |
| REA 도구가 첫 턴에만 없음 | `mcp_optional_startup_grace_ms` 가 없거나 작다. 프로젝트 설정을 다시 만들거나, 전역 설정이면 15000 으로 올린다(§3.4) |
| 서버는 연결됐는데 모델이 도구를 못 찾음 | 지연 로딩이다. `direct_only_tool_namespaces` 를 확인하고(§3.4), 에이전트에게 `ALL_TOOLS` 에서 `mcp__pweh_` 로 시작하는 이름을 찾게 한다 |
| 특정 REA 도구만 없음 | `enabled_tools` 에 없다. `.claude/settings.json` 의 `mcp__rea__*` 규칙에 있는 도구만 들어간다(§3.4) |
| `codex exec` 에서 기기 도구가 거부됨 | 예상된 동작이다(§3.5). 대화형 Codex 로 실행한다 |
| 데스크톱 앱의 홈을 건너뜀 | WSL 모드가 꺼져 있다(§3.5) |
| 서버 하나가 시작하지 않음 | `pweh mcp-check --client codex` 가 그 서버의 오류를 보여 준다. `.venv` 설치와 env.sh 경로를 확인하고, 고친 뒤 설정을 다시 만든다(§8 첫 행도 참고) |

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
  새 프로젝트 MCP 서버 `pweh-esp` 의 승인 다이얼로그가 뜨면 승인하고 `/mcp` 에서 연결됐는지 확인한다.
  Codex 는 env.sh 값(`PWEH_ESPTOOL`·`PWEH_ESPTOOL_WIN`)이 설정의 `env` 에 직접 들어가므로 `pweh mcp-config --client codex --write` 로 설정을 다시 만든 뒤, CLI 는 `codex` 를 다시 실행하고 데스크톱 앱은 다시 시작하거나 새 스레드를 연다(§3.5).
- **포트 이름:** 에이전트는 `esp_version()` 으로 `backends.windows.available` 과 버전을 본 뒤 `esp_list_ports()` 의 `windows.ports[].port` 에서 COM 포트를 고른다(추측하지 않는다).
  `303a:1001` 은 ESP 내장 USB-Serial/JTAG 이고, 리셋 뒤 COM 번호가 바뀌면 다시 조회한다. `303a:4001` 같은 그 밖의 `303a` 는 앱(MicroPython 등)의 TinyUSB CDC 라 자동 리셋이 대개 안 된다.
  보드에 USB 커넥터가 둘이면(ESP32-S3-DevKitC-1 의 'USB'·'UART') 'UART'(USB-UART 브리지) 쪽에 꽂는 것이 자동 리셋에 확실하다. 그다음 소유/허가 확인 → `case_create` → `esp_chip_info` → `esp_security_info` → `esp_read_flash_start` → `esp_job_status` 순서다.
- **같은 장치를 동시에 붙이지 않는다:** usbipd 로 WSL 에 attach 한 장치는 Windows 에서 COM 포트가 사라져 방법 A 로 열 수 없다. 방법 A 를 쓰려면 `usbipd detach` 한다.

## 7. 환경변수 요약

| 변수 | 용도 |
|---|---|
| `PWEH_CONFIG` | 설정 파일 경로 (설정하지 않으면 런처가 저장소의 `orchestrator/pipeline-config.yaml` 로 지정) |
| `PWEH_TOOLS_ENV`, `PWEH_TOOLS_DIR` | 외부 도구 env.sh 경로 / 도구 디렉터리 (기본 `~/pweh-tools`. `--prefix` 로 설치했으면 `.pweh/tools-env.path` 가 가리킴) |
| `PWEH_REA` | 런처가 실행할 `rea` 실행 파일 (기본: `PATH` 의 `rea`, 없으면 `~/.local/bin/rea`) |
| `PWEH_CASES_DIR`, `PWEH_STATE_DIR` | 케이스/상태 디렉터리 강제 지정 (테스트·격리 실행) |
| `CODEX_HOME` | Codex CLI 의 홈(`config.toml` 위치, 없으면 `~/.codex`). `pweh mcp-config --client codex`·`pweh codex-trust` 의 자동 감지가 읽는다(§3.1). pweh 는 이 값을 바꾸지 않는다 |
| `PWEH_WINDOWS_PROFILE` | Windows 사용자 프로필 디렉터리를 직접 지정(WSL 경로 또는 `C:\Users\…`). Codex 데스크톱 앱 홈(`<프로필>/.codex`) 자동 감지가 interop 대신 쓴다(§3.1) |
| `PWEH_SIGROK_CLI`, `PWEH_OPENOCD`, `PWEH_OPENOCD_SCRIPTS`, `PWEH_UNSQUASHFS`, `PWEH_MKSQUASHFS`, `PWEH_ZIG` … | 외부 도구 경로 (env.sh 가 설정) |
| `PWEH_ESPTOOL`, `PWEH_ESPTOOL_WIN` | pweh-esp 의 리눅스 esptool / Windows 용 `esptool.exe` 절대 경로(방법 A). 설정 키는 `tools.esptool`·`tools.esptool_win`. env.sh 는 실제로 실행되는 쪽만 설정한다. `PWEH_ESPTOOL_WIN` 이 비어 있으면 외부 도구 디렉터리의 `esptool-win/esptool-windows-amd64/esptool.exe` 를 찾고, `C:\tools\esptool.exe` 같은 Windows 경로도 받는다(`wslpath -u` 로 변환). 바꾸면 MCP 서버를 다시 시작한다 |

## 8. 문제 해결

| 증상 | 확인 |
|---|---|
| `/mcp` 에 서버가 `Failed to connect` | `bash scripts/mcp-launch.sh pweh-case-mcp < /dev/null` 로 직접 실행해 오류를 본다. `.venv` 설치 여부도 확인한다 |
| `Pending approval` | `claude` 를 대화형으로 실행해 승인한다. 또는 `claude mcp reset-project-choices` 후 다시 승인한다 |
| Codex 에서 PWEH 도구가 보이지 않음, Codex 가 시작하지 않음 | §3.6 (`pweh mcp-check --client codex`, trust, Codex 홈) |
| REA 도구가 Ghidra 없다고 함 | env.sh 의 `GHIDRA_INSTALL_DIR`/`JAVA_HOME` 을 확인하고 `rea doctor --provider ghidra` 를 실행한다 |
| 시리얼 포트 권한 오류 | `pweh doctor`(맨 앞 환경 절)·`pweh env` → `dialout` 그룹, WSL 이면 네트워킹 모드별 `usbipd attach` |
| Windows(네이티브·Cygwin·MSYS)에서 서버가 바로 끝남 | 지원하지 않는다(안내 문구와 함께 종료 코드 1). 서버는 WSL 안에서 실행하고, Windows 의 MCP 클라이언트는 `wsl.exe -d <배포판> -e <저장소>/.venv/bin/pweh-<서버>-mcp` 형식으로 띄운다(`-u root` 는 넣지 않는다) |
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
