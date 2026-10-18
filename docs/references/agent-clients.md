# 에이전트 클라이언트 등록 레퍼런스: Claude Code · Codex CLI · Cursor

> 대상 독자: pweh MCP 서버/시뮬레이터 구현자, Skill 작성자
> 작성 기준일: **2026-10-18**
> 범위: 로컬 **stdio** MCP 서버 등록, 프로젝트 Skill 등록, "파이프라인 시작" 명령 등록, 장시간 도구 호출(타임아웃·progress·job/poll)

## 읽는 법: 확인 버전과 근거 라벨

| 대상 | 확인한 버전 / 근거 |
|---|---|
| Claude Code | 로컬 설치 `2.1.302 (Claude Code)`. 공식 문서 `code.claude.com/docs`의 Markdown 원문. 체인지로그 최신 항목은 2.1.302 (2026-10-16) |
| Codex CLI | 로컬 설치 `codex-cli 0.162.0`. 공식 문서는 `developers.openai.com/codex/*`에서 `learn.chatgpt.com/docs/*`로 308 리다이렉트된다. 소스는 GitHub `openai/codex` 태그 `rust-v0.162.0`에 고정. 최신 정식 릴리스는 `rust-v0.163.0` (2026-10-15) |
| Cursor | 공식 문서 `cursor.com/docs/*.md` (2026-10-18 조회). `docs.cursor.com`은 `cursor.com/docs`로 308 리다이렉트된다. 로컬 설치 없음 |
| MCP 사양 | `modelcontextprotocol.io/specification/2025-11-25`, `.../2026-07-28` |
| Python SDK | 프로젝트 `.venv`의 `mcp 2.3.0` (`mcp.server.mcpserver.MCPServer`) |

본문의 근거 라벨은 다음과 같다.

- **[문서]**: 해당 클라이언트의 공식 문서. 링크를 바로 옆에 붙인다.
- **[소스 rust-v0.162.0]**: Codex 소스 코드. 태그 고정 링크를 붙인다. 문서와 다를 수 있으며, 다르면 둘 다 적었다.
- **[실측 2.1.302]**: 이 문서 작성 중 로컬 Claude Code 2.1.302와 Codex 0.162.0으로 직접 관찰한 결과. 격리된 `CLAUDE_CONFIG_DIR`/`CODEX_HOME`을 썼고 모델은 호출하지 않았다. 관찰한 경로(예: `claude mcp list`의 health check)에 한정된 사실이다.
- **[포럼·미확인]**: 공식 포럼의 사용자 보고나 스태프 답변. 공식 문서가 아니다.
- **(미확인)**: 1차 출처를 찾지 못한 항목. 적힌 형태는 추정이다.

---

## 0. 한눈에 보기

| 항목 | Claude Code | Codex CLI | Cursor |
|---|---|---|---|
| 프로젝트 MCP 설정 | `.mcp.json` (프로젝트 루트) | `.codex/config.toml` (trusted 프로젝트만) | `.cursor/mcp.json` |
| 사용자 전역 MCP 설정 | `~/.claude.json` (local·user scope) | `~/.codex/config.toml` | `~/.cursor/mcp.json` |
| stdio 엔트리 형식 | JSON `mcpServers.<name>`: `type`, `command`, `args`, `env`, `timeout`, `alwaysLoad` | TOML `[mcp_servers.<name>]`: `command`, `args`, `env`, `env_vars`, `cwd`, `startup_timeout_sec`, `tool_timeout_sec`, `enabled` 등 | JSON `mcpServers.<name>`: `type`, `command`, `args`, `env`, `envFile` |
| 변수 치환 문법 | `${VAR}`, `${VAR:-default}` | MCP 설정용 문법은 문서에 없음. 환경변수는 `env_vars`로 전달 | `${env:NAME}`, `${workspaceFolder}`, `${userHome}` 등 |
| 작업 디렉터리 지정 | 키 없음 (문서). 실측으로는 프로젝트 루트에서 spawn | `cwd` 키 | 키 없음 (문서). `${workspaceFolder}`를 쓴다 |
| 부모 환경변수 상속 | 상속됨 [실측] | 화이트리스트만 전달 [소스] | (미확인) |
| 프로젝트 서버 승인 | 대화형 승인 다이얼로그, `enabledMcpjsonServers` 등 | 프로젝트 trust가 필요 | CLI는 `agent mcp enable`과 `--approve-mcps`. IDE는 (미확인) |
| 시작 타임아웃 기본값 | `MCP_TIMEOUT` = 30000 ms | 문서는 10 s, 소스는 30 s이므로 **명시 설정** 권장 | 문서 없음 |
| 도구 호출 타임아웃 기본값 | `MCP_TOOL_TIMEOUT` = 100000000 ms (약 28시간). stdio idle 타임아웃 30분 | 문서는 60 s, 소스는 300 s이므로 **명시 설정** 권장 | 문서 없음. 포럼에 따르면 IDE 약 60분, ACP 60 s |
| progress가 타임아웃을 연장하나 | idle 타이머만 리셋한다. 총 시간 제한은 연장하지 않는다 | 연장하지 않는다 [소스] | ACP 경로는 연장하지 않는다 [포럼] |
| Elicitation | 지원 (v2.1.76+). form/url 다이얼로그 | 지원. `never` 정책이면 거절, full access와 `never`가 겹치면 빈 스키마 form을 자동 수락 [소스] | "Supported" [문서] |
| 권한 판단에 tool annotations 사용 | 문서화되지 않음 (`/mcp` 화면 표시만 확인) | 사용함 (`auto`/`writes` 모드) | (미확인) |
| MCP 권한 규칙 | `.claude/settings.json`의 `permissions.allow/ask/deny`, `mcp__<server>__<tool>` | `default_tools_approval_mode`, `tools.<tool>.approval_mode`, `enabled_tools`/`disabled_tools` | CLI는 `.cursor/cli.json`의 `Mcp(server:tool)`. IDE는 Run Modes |
| 프로젝트 Skill 위치 | `.claude/skills/<name>/SKILL.md` | `.agents/skills/<name>/SKILL.md` (`.codex/skills`도 스캔 [소스]) | `.agents/skills`, `.cursor/skills`, 호환용 `.claude/skills`·`.codex/skills` |
| Skill 호출 | `/name` | `$name` 또는 `/skills` | `/name` |
| 커스텀 명령 | `.claude/commands/<name>.md` (skills에 통합됨) | `~/.codex/prompts/<name>.md`로 `/prompts:<name>` (deprecated) | `.cursor/commands` (레거시, skills로 마이그레이션) |
| 지침 파일 | `CLAUDE.md`. `AGENTS.md`는 CLAUDE.md가 없을 때만 읽는다 | `AGENTS.md` | `.cursor/rules/*.mdc`, `AGENTS.md`. CLI는 `CLAUDE.md`도 읽는다 |

---

## 1. pweh 공통 권장사항 (클라이언트 공통)

### 1.1 서버 이름

- **권장**: 짧은 소문자 이름을 쓴다. 예: `uart`, `openocd`, `sigrok`, `jtagulator`, `fwtriage`, `case`, `rea`. 이 값은 사용자 설정에서 정하는 값이다. 한 번 정하면 세 클라이언트 설정, 권한 규칙, Skill 본문에서 같은 이름을 쓴다.
- 근거:
  - Claude Code는 도구 전체 이름을 `mcp__<server>__<tool>`로 만든다. 이 이름이 128자를 넘으면 그 도구를 모델에 보내지 않는다 [문서](https://code.claude.com/docs/en/mcp#tools-with-names-longer-than-128-characters). 서버 이름 키에는 영문자, 숫자, `-`, `_`만 쓰라고 한다 [문서](https://code.claude.com/docs/en/mcp#add-a-server-from-an-mcpservers-json-block).
  - Claude Code 예약 이름은 `workspace`, `claude-in-chrome`, `computer-use`, `Claude Preview`, `Claude Browser`이다 [문서](https://code.claude.com/docs/en/mcp#configuration-warnings). 서버 이름을 `anthropic-skills`로 하면 그 서버의 MCP prompts가 표시되지 않는다 [문서](https://code.claude.com/docs/en/mcp#use-mcp-prompts-as-commands).
  - Codex는 서버 이름을 정규식 `^[a-zA-Z0-9_:@/.-]+$`로 검사한다 [소스](https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/codex-mcp/src/rmcp_client.rs).
  - 공통 안전 문자는 `[a-z0-9_-]`이다.

### 1.2 실행 커맨드와 경로 해석은 클라이언트마다 다르다

설정 파일 하나를 세 클라이언트가 공유할 수 없다. 변수 문법이 서로 다르기 때문이다.

| | Claude Code | Codex | Cursor |
|---|---|---|---|
| 프로젝트 루트 참조 | 서버 프로세스 환경변수 `CLAUDE_PROJECT_DIR` (Claude Code가 설정) [문서](https://code.claude.com/docs/en/mcp#option-3-add-a-local-stdio-server) | 없음. `cwd`에 절대경로를 쓴다 | `${workspaceFolder}` (`.cursor/mcp.json`이 들어 있는 폴더) [문서](https://cursor.com/docs/mcp.md) |
| 상대 `command` 경로 | 문서화되지 않음. 실측으로는 spawn cwd가 프로젝트 루트 | (미확인). 프로젝트 config의 상대경로는 `.codex/` 기준으로 해석된다고 하지만, 문서 예는 `model_instructions_file`뿐이다 [문서](https://learn.chatgpt.com/docs/config-file/config-advanced.md) | `${workspaceFolder}/...`를 쓴다 |

**권장 패턴은 "자기 위치를 찾는 런처 스크립트"이다.** 클라이언트별 설정은 이 스크립트만 가리키게 한다. 스크립트 경로와 엔트리포인트는 예시이므로 구현에 맞춰 바꾼다.

```bash
#!/usr/bin/env bash
# mcp-servers/uart-mcp/run.sh  (예시 경로)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
export PWEH_ROOT="${PWEH_ROOT:-$REPO_ROOT}"
cd "$REPO_ROOT"
# 엔트리포인트(모듈/스크립트)는 구현에 맞게 바꾼다
exec "$REPO_ROOT/.venv/bin/python" -m PWEH_UART_ENTRYPOINT "$@"
```

서버 쪽 루트 결정 순서는 `PWEH_ROOT` → `CLAUDE_PROJECT_DIR` → `os.getcwd()`를 권장한다 (pweh 내부 규약 제안).

### 1.3 환경변수 전달

| 클라이언트 | 동작 | 근거 |
|---|---|---|
| Claude Code | 부모 환경을 상속한다. 셸에서 export한 `PWEH_PROBE_INHERIT=yes`가 서버에 도달했다. `CLAUDE_PROJECT_DIR`도 설정된다 | [실측 2.1.302] |
| Codex | Unix에서는 아래 화이트리스트, 사용자 CA 관련 키, `env_vars`, `env`만 전달한다 | [소스](https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/rmcp-client/src/utils.rs#L163-L175) |
| Cursor | (미확인). `env`/`envFile`로 명시하는 것이 안전하다 | [문서](https://cursor.com/docs/mcp.md) |

Codex의 기본 화이트리스트 (rust-v0.162.0 `utils.rs`):

```text
HOME, LOGNAME, PATH, SHELL, USER, __CF_USER_TEXT_ENCODING, LANG, LC_ALL, TERM, TMPDIR, TZ
```

따라서 Codex에서는 `PWEH_*`, `VIRTUAL_ENV` 같은 변수가 자동으로 넘어가지 않는다. `env` 테이블에 직접 쓰거나 `env_vars = ["PWEH_ROOT"]`로 전달한다.

### 1.4 stdio 위생과 종료 처리

- stdout은 JSON-RPC 전용이다. 로그는 stderr로 보낸다. `src/pweh/mcpkit.py`가 이미 그렇게 한다.
- Claude Code는 stdio 서버를 다음 순서로 끈다 [문서](https://code.claude.com/docs/en/mcp#how-claude-code-stops-a-stdio-server).
  - macOS/Linux: `SIGINT`을 보내고, 100 ms 뒤에도 살아 있으면 `SIGTERM`, 그 뒤 400 ms가 더 지나면 `SIGKILL`.
  - Windows: stdin을 닫고 300 ms 뒤 프로세스 트리를 종료한다.
  - 시리얼 포트 해제와 lock 파일 정리는 이 시간 안에 끝나야 한다. 장시간 job 상태는 디스크(`jobs/<job_id>.json`)에 남긴다.
- Claude Code는 stdio 서버를 자동으로 재연결하지 않는다. 서버가 죽으면 사용자가 `/mcp`에서 다시 연결해야 한다 [문서](https://code.claude.com/docs/en/mcp#automatic-reconnection).

### 1.5 프로토콜 협상 (서버·시뮬레이터 구현자 참고)

**[실측 2.1.302]** Claude Code의 v2 런타임은 health check에서 다음 메시지를 먼저 보낸다.

```json
{"jsonrpc":"2.0","id":"server-discover-probe-1","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"claude-code","title":"Claude Code","version":"2.1.302","description":"Anthropic's agentic coding tool","websiteUrl":"https://claude.com/claude-code"},"io.modelcontextprotocol/clientCapabilities":{"roots":{"listChanged":true},"elicitation":{"form":{},"url":{}}}}}}
```

이 probe가 실패하면 기존 `initialize`로 다시 시도한다.

```json
{"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"roots":{"listChanged":true},"elicitation":{"form":{},"url":{}}},"clientInfo":{"name":"claude-code","title":"Claude Code","version":"2.1.302","description":"Anthropic's agentic coding tool","websiteUrl":"https://claude.com/claude-code"}},"jsonrpc":"2.0","id":0}
```

- 문서상 v2 런타임은 MCP TypeScript SDK 2.0 기반이며 revision 2026-07-28을 지원하는 서버에는 그 revision을 쓴다 [문서](https://code.claude.com/docs/en/mcp#mcp-client-runtimes).
- 호환 문제가 생기면 `MCP_PROTOCOL_NEGOTIATION=legacy`(어떤 서버도 probe하지 않음) 또는 `MCP_SDK_GENERATION=v1`을 쓴다 [문서](https://code.claude.com/docs/en/env-vars.md).
- mock-device 시뮬레이터가 MCP 클라이언트 흉내를 낼 일은 없지만, 서버 단위 테스트에서는 위 두 형태를 모두 재현해 볼 가치가 있다.

---

## 2. Claude Code

### 2.1 `claude mcp add` (stdio)

**[문서]** [mcp#option-3](https://code.claude.com/docs/en/mcp#option-3-add-a-local-stdio-server)

```bash
# Basic syntax
claude mcp add [options] <name> -- <command> [args...]
```

로컬 `claude mcp add --help` 출력 [실측 2.1.302]:

```text
  -e, --env <env...>           Set environment variables (e.g. -e KEY=value)
  -s, --scope <scope>          Configuration scope (local, user, or project)
                               (default: "local")
  -t, --transport <transport>  Transport type (stdio, sse, http). Defaults to
                               stdio if not specified.
```

- `--`는 Claude의 옵션과 서버 커맨드를 가른다. `--` 뒤는 그대로 서버에 전달된다.
- **함정**: `--env` 바로 뒤에 서버 이름을 쓰면 이름을 env 쌍으로 읽고 거부한다 [문서](https://code.claude.com/docs/en/mcp#option-3-add-a-local-stdio-server). 실제 오류 문자열 [실측 2.1.302]:

```text
Invalid environment variable format: uart, environment variables should be added as: -e KEY1=value1 -e KEY2=value2
```

올바른 순서: `--env`를 다른 옵션 앞에 두거나, `--env`와 이름 사이에 다른 옵션을 하나 넣는다.

```bash
claude mcp add --env PWEH_CASES_DIR=/home/user/pweh/cases --scope project --transport stdio uart -- /home/user/pweh/.venv/bin/python -m pweh.servers.uart
```

성공 출력 [실측 2.1.302]. 위 명령의 경로와 모듈명은 예시다.

```text
Added stdio MCP server uart with command: /home/user/pweh/.venv/bin/python -m pweh.servers.uart to project config
File modified: /…/ccproj/.mcp.json
```

이때 생성된 `.mcp.json` [실측 2.1.302]. `"type": "stdio"`가 명시된다.

```json
{
  "mcpServers": {
    "uart": {
      "type": "stdio",
      "command": "/home/user/pweh/.venv/bin/python",
      "args": [
        "-m",
        "pweh.servers.uart"
      ],
      "env": {
        "PWEH_CASES_DIR": "/home/user/pweh/cases"
      }
    }
  }
}
```

JSON으로 바로 추가할 수도 있다 [문서](https://code.claude.com/docs/en/mcp#add-mcp-servers-from-json-configuration). 실측으로 `timeout` 필드도 받아서 그대로 기록했다.

```bash
claude mcp add-json local-weather '{"type":"stdio","command":"/path/to/weather-cli","args":["--api-key","abc123"],"env":{"CACHE_DIR":"/tmp"}}'
```

관리 명령: `claude mcp list`, `claude mcp get <name>`, `claude mcp remove <name> [-s <scope>]`, `claude mcp reset-project-choices`, 세션 안에서는 `/mcp`.

### 2.2 scope와 저장 위치

**[문서]** [mcp#mcp-installation-scopes](https://code.claude.com/docs/en/mcp#mcp-installation-scopes)

| Scope | 로드 범위 | 팀 공유 | 저장 위치 |
|---|---|---|---|
| `local` (기본) | 현재 프로젝트만 | 아니오 | `~/.claude.json`의 `projects["<프로젝트 경로>"].mcpServers` |
| `project` | 현재 프로젝트만 | 예 (VCS) | 프로젝트 루트 `.mcp.json` |
| `user` | 모든 프로젝트 | 아니오 | `~/.claude.json` 최상위 |

- 같은 이름이 여러 곳에 있으면 우선순위가 가장 높은 정의 하나만 쓴다. 필드를 병합하지 않는다.
- 우선순위: Local > Project > User > 플러그인 제공 서버 > claude.ai connectors [문서](https://code.claude.com/docs/en/mcp#scope-hierarchy-and-precedence).
- MCP의 "local scope"(`~/.claude.json`)는 일반 설정의 local(`.claude/settings.local.json`)과 다른 개념이다.

### 2.3 `.mcp.json` 형식과 필드

| 필드 | 의미 | 근거 |
|---|---|---|
| `type` | `"stdio"`, `"http"`(`"streamable-http"`는 별칭), `"sse"`(deprecated), `"ws"`. **`type`이 없으면 stdio로 읽는다.** `url`만 있고 `type`이 없으면 오류 | [문서](https://code.claude.com/docs/en/mcp) |
| `command` | 실행 파일 | [문서](https://code.claude.com/docs/en/mcp#environment-variable-expansion-in-mcp-json) |
| `args` | 인자 배열 | 위와 같음 |
| `env` | 서버에 줄 환경변수 | 위와 같음 |
| `timeout` | 서버별 도구 호출 총 시간 제한 (ms). `MCP_TOOL_TIMEOUT`보다 우선. 1000 미만은 무시 | [문서](https://code.claude.com/docs/en/env-vars.md) (`MCP_TOOL_TIMEOUT` 항목), [문서](https://code.claude.com/docs/en/mcp) (설치 절의 Tips) |
| `alwaysLoad` | `true`면 tool search 지연 로딩에서 제외. 모든 서버 타입에서 쓸 수 있다. 시작 시 5초 connect 대기를 유발한다 | [문서](https://code.claude.com/docs/en/mcp#exempt-a-server-from-deferral) |
| `cwd` | **문서에 없음**. 프로젝트 루트는 `CLAUDE_PROJECT_DIR`로 얻는다 | (미확인) |

#### 환경변수 확장 문법

**[문서]** [mcp#environment-variable-expansion-in-mcp-json](https://code.claude.com/docs/en/mcp#environment-variable-expansion-in-mcp-json)

- `${VAR}`: 환경변수 `VAR`의 값.
- `${VAR:-default}`: `VAR`가 설정되어 있으면 그 값, 아니면 `default`.
- 확장 위치: `command`, `args`, `env`, `url`, `headers`.
- 기본값 없는 미설정 변수: 설정은 그대로 로드되고, `${VAR}` 문자열이 남으며, 경고가 뜬다. 경고 문자열 [실측 2.1.302]:

```text
MCP config diagnostics ⚠
...
[Contains warnings] Project config (shared via .mcp.json)
Location: /…/ccproj/.mcp.json
 └ [Warning] [envtest] mcpServers.envtest: Missing environment variables: PWEH_UNSET_VAR
```

- `claude mcp list`/`get`은 `${VAR}`를 이름으로만 보여 준다 (`${PWEH_PY:-/usr/bin/python3}`는 `${PWEH_PY}`로 표시) [실측 2.1.302].
- **`CLAUDE_PROJECT_DIR`의 함정** [문서](https://code.claude.com/docs/en/mcp#option-3-add-a-local-stdio-server):
  - 이 변수는 Claude Code 자신의 환경이 아니라 spawn된 서버의 환경에만 설정된다.
  - 그래서 `.mcp.json`의 `command`/`args`에서 `${CLAUDE_PROJECT_DIR:-.}`처럼 기본값을 붙이라고 문서가 안내한다.
  - 실측하면 `${CLAUDE_PROJECT_DIR:-.}`는 `.`으로 확장되었고, 서버의 cwd는 프로젝트 루트였다 [실측 2.1.302, health check 경로].
- **권장 우회** [실측 2.1.302]: `bash -c` 안에서 중괄호 없는 `$CLAUDE_PROJECT_DIR`를 쓴다.
  - Claude Code의 확장 문법은 `${...}`뿐이라 이 표기는 건드리지 않고, 런타임에 bash가 서버 환경의 값으로 확장한다.
  - 실측에서 절대경로로 확장되었고 경고도 없었다.

```json
{
  "mcpServers": {
    "uart": {
      "type": "stdio",
      "command": "bash",
      "args": ["-c", "exec \"$CLAUDE_PROJECT_DIR/mcp-servers/uart-mcp/run.sh\""],
      "env": { "PWEH_LOG_LEVEL": "INFO" }
    },
    "fwtriage": {
      "type": "stdio",
      "command": "bash",
      "args": ["-c", "exec \"$CLAUDE_PROJECT_DIR/mcp-servers/fwtriage-mcp/run.sh\""],
      "timeout": 1800000
    }
  }
}
```

(`run.sh` 경로와 `PWEH_LOG_LEVEL`은 예시다. §1.2 참조.)

- 원격 서버의 `url`/`headers`에서는 `ANTHROPIC_API_KEY` 같은 자격증명 변수가 빈 값으로 읽힌다 [문서](https://code.claude.com/docs/en/mcp#credential-variables-that-read-as-empty). stdio의 `env`에는 이 규칙이 적용된다는 서술이 없다.

### 2.4 프로젝트 서버(.mcp.json) 승인

**[문서]** [mcp#project-scope](https://code.claude.com/docs/en/mcp#project-scope) · [settings-reference](https://code.claude.com/docs/en/settings-reference#enableallprojectmcpservers)

- 대화형 세션은 `.mcp.json` 서버를 쓰기 전에 승인을 묻는다. 선택을 초기화하려면 `claude mcp reset-project-choices`를 실행한다.
- **중요**: `claude -p`, Agent SDK, 클라우드 세션은 이 승인을 띄울 수 없으므로 **묻지 않고 로드한다.** `bypassPermissions`로 시작했고 사용자/관리 설정에 `skipDangerousModePermissionPrompt`가 있으면 승인을 건너뛴다.
- 서버를 막는 방법:
  - `disabledMcpjsonServers`: 모든 모드에서 차단.
  - `--setting-sources`로 project 설정을 제외.
  - `--strict-mcp-config --mcp-config <file>`.

| 설정 키 | 타입 | 의미 |
|---|---|---|
| `enableAllProjectMcpServers` | Boolean | 모든 `.mcp.json` 서버를 묻지 않고 승인. 다이얼로그에서 "모두 승인"을 고르면 `.claude/settings.local.json`에 기록된다 |
| `enabledMcpjsonServers` | string[] | 지정한 서버만 승인. 예: `["memory", "github"]` |
| `disabledMcpjsonServers` | string[] | 지정한 서버 거부. **위 두 키보다 우선한다** |

- **workspace trust와의 관계** [문서](https://code.claude.com/docs/en/mcp#project-server-approvals-and-workspace-trust):
  - 저장소에 커밋된 `.claude/settings.json`의 승인은 신뢰하지 않은 폴더에서 무시된다. 저장소가 스스로 자기 서버를 승인할 수 없다는 뜻이다.
  - 신뢰하지 않은 폴더에서도 유효한 승인: 사용자 `~/.claude/settings.json`, managed settings, `--settings`.
- 상태 문자열 [문서](https://code.claude.com/docs/en/mcp#server-status):

```text
✔ Connected
! Needs authentication
✘ Failed to connect
⏸ Pending approval (run `claude` to approve)
✘ Rejected (see disabledMcpjsonServers in settings)
⊘ Disabled for this project (re-enable via /mcp)
```

실측 출력 예 [실측 2.1.302]:

```text
$ claude mcp list
Checking MCP server health…

uart: /home/user/pweh/.venv/bin/python -m pweh.servers.uart - ⏸ Pending approval (run `claude` to approve)
```

```text
$ claude mcp get uart
uart:
  Scope: Project config (shared via .mcp.json)
  Status: ⏸ Pending approval (run `claude` to approve)
  Type: stdio
  Command: /home/user/pweh/.venv/bin/python
  Args: -m pweh.servers.uart
  Environment:
    PWEH_CASES_DIR=/home/user/pweh/cases

To remove this server, run: claude mcp remove uart -s project
```

연결 실패 예 [실측 2.1.302]:

```text
probe1: /…/python -I /…/probe.py ${CLAUDE_PROJECT_DIR} - ✘ Failed to connect — CONNECTION_CLOSED: Connection closed
```

`get` 출력에는 `Issue: CONNECTION_CLOSED: Connection closed` 줄이 붙는다.

### 2.5 타임아웃·시작·출력 한도

**[문서]** [env-vars](https://code.claude.com/docs/en/env-vars.md) · [mcp](https://code.claude.com/docs/en/mcp#automatic-backgrounding-of-long-tool-calls)

| 변수 / 필드 | 기본값 | 의미 |
|---|---|---|
| `MCP_TIMEOUT` | `30000` (30초) | 서버 하나의 시작(connect) 타임아웃. 예: `MCP_TIMEOUT=10000 claude` |
| `MCP_TOOL_TIMEOUT` | `100000000` (약 28시간) | 도구 실행 총 시간 제한. stdio에는 per-request 타이머가 없다. 1000 미만은 1초로 올림 |
| `.mcp.json`의 `timeout` | 없음 | 서버별 총 시간 제한 (ms). 예: `"timeout": 600000`은 10분. **progress notification으로 연장되지 않는다.** 1000 미만은 무시된다 |
| `CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT` | stdio `1800000` (30분), 네트워크 `300000` (5분) | 응답도 progress notification도 없이 이 시간이 지나면 호출을 오류로 중단한다. `0`이면 끈다. 서버별 `timeout`(≥1000)이 idle 창의 하한이 된다. v2.1.187+ (stdio는 v2.1.203+) |
| `CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS` | `120000` (2분) | 메인 대화의 MCP 호출이 이 시간을 넘으면 백그라운드 태스크로 옮겨진다. `0`이면 끈다. v2.1.212+ |
| `MCP_CONNECTION_NONBLOCKING` | 비차단 | 서버는 백그라운드에서 연결된다. `0`이면 첫 쿼리 전에 대기 |
| `MCP_CONNECT_TIMEOUT_MS` | `5000` | 차단형 시작(`MCP_CONNECTION_NONBLOCKING=0` 또는 `alwaysLoad`)의 배치 대기 |
| `MCP_SERVER_CONNECTION_BATCH_SIZE` | `3` | 시작 시 병렬로 연결하는 stdio 서버 수 |
| `CLAUDE_CODE_MCP_STARTUP_WAIT_MS` | (기본 first-turn wait) | `-p` 첫 턴이 연결 중인 서버를 기다리는 시간. v2.1.274+ |
| `MAX_MCP_OUTPUT_TOKENS` | `25000` | MCP 도구 출력 토큰 상한. **10,000 토큰을 넘으면 경고**(임계값 고정) |

자동 백그라운드의 세부 동작 [문서](https://code.claude.com/docs/en/mcp#automatic-backgrounding-of-long-tool-calls):

- Claude는 task ID를 즉시 받고 일을 계속한다. 결과는 task notification으로 도착한다.
- `/tasks`에서 진행 상황을 보고 중지할 수 있다. 서버가 보고한 최신 progress가 거기 표시된다.
- 중지는 호출을 취소할 뿐이다. 서버가 작업을 실제로 멈춘다는 보장은 없다.
- 백그라운드로 가지 않는 호출:
  - subagent의 호출.
  - IDE 서버 호출.
  - `-p` 모드의 호출. 단 `CLAUDE_AUTO_BACKGROUND_TASKS=1`이면 옮겨진다.
- elicitation 다이얼로그가 열려 있는 동안에는 옮기지 않는다.

출력 한도 [문서](https://code.claude.com/docs/en/mcp#mcp-output-limits-and-warnings):

- 한도를 넘는 성공 결과(이미지 제외)는 세션의 `tool-results` 디렉터리(`~/.claude/projects/` 아래)에 파일로 저장된다. 대화에는 파일 경로만 남는다.
- foreground 호출에서 `anthropic/maxResultSizeChars`를 선언하지 않은 도구는 텍스트가 **50,000자**를 넘으면 토큰 수와 무관하게 파일로 저장된다.
- 서버가 도구별로 `_meta["anthropic/maxResultSizeChars"]`를 주면 그 도구의 임계값을 최대 **500,000자**까지 올릴 수 있다.
- `isError: true` 결과의 텍스트가 약 11,000자를 넘으면 앞 5,000자와 뒤 5,000자만 남긴다.

```json
{
  "name": "get_schema",
  "description": "Returns the full database schema",
  "_meta": {
    "anthropic/maxResultSizeChars": 200000
  }
}
```

설명 길이와 스키마 제약 [문서](https://code.claude.com/docs/en/mcp#tool-search-for-mcp-server-authors):

- 서버 instructions와 upfront 로드 도구 설명은 **4,096자**, tool search로 로드되는 도구 설명은 **16,384자**에서 잘린다. `CLAUDE_CODE_MAX_MCP_DESCRIPTION_LENGTH`(v2.1.280+)가 두 한도를 하나의 값으로 바꾼다.
- 입력 스키마의 최상위 property 이름은 1~64자, ASCII 영숫자와 `_`, `.`, `-`만 쓸 수 있다.
- 최상위 `anyOf`/`oneOf`/`allOf`는 Claude Code가 평탄화한다 [문서](https://code.claude.com/docs/en/mcp#tool-input-schemas-with-a-root-level-combinator).

### 2.6 MCP Elicitation (form mode)

- **지원한다.** v2.1.76 (2026-03-14) 체인지로그 원문 [문서](https://code.claude.com/docs/en/changelog.md):

```text
Added MCP elicitation support — MCP servers can now request structured input mid-task via an interactive dialog (form fields or browser URL)
Added new `Elicitation` and `ElicitationResult` hooks to intercept and override responses before they're sent back
```

- 사용자에게 보이는 방식 [문서](https://code.claude.com/docs/en/mcp#respond-to-mcp-elicitation-requests):
  - **Form mode**: 서버가 정의한 필드가 담긴 다이얼로그를 띄우고, 사용자가 채워서 제출한다. 별도 설정은 필요 없다.
  - **URL mode**: 링크를 브라우저로 열지 묻는다. 이스케이프 후 URL이 상한(문자 그대로면 약 8,000자)을 넘으면 거절만 할 수 있다.
  - 다이얼로그에서 **Decline**은 `decline`, **Esc**는 `cancel`을 서버에 보낸다 [문서](https://code.claude.com/docs/en/hooks.md#elicitation).
  - v2.1.239 체인지로그: fullscreen 모드에서 터미널보다 긴 폼이 잘리던 문제를 고쳤고, 이제 숨은 필드는 스크롤로 닿으며 Accept/Decline은 항상 보인다.
- 클라이언트 capability 선언:
  - 2026-07-28 연결에서는 `elicitation: {form: {}, url: {}}`를 선언한다 [문서].
  - 실측에서는 2025-11-25 `initialize`에서도 `"elicitation":{"form":{},"url":{}}`를 보냈다 (§1.5).
- 비대화형: `--permission-prompts none`(v2.1.259+)이면 `Elicitation` hook이 답하지 않은 요청을 취소한다 [문서](https://code.claude.com/docs/en/headless.md). `-p`에서 이 플래그가 없을 때 어떻게 되는지는 (미확인).
- `bypassPermissions`가 elicitation을 자동 수락한다는 서술은 없다 (미확인).
- v2.1.287 (2026-10-01) 체인지로그 원문. 업데이트 뒤 연결이 안 되는 서버를 위한 우회책이다.

```text
Added URL prompts from MCP servers on the 2025-11-25 protocol, for example to sign in. If a server no longer connects after this update, add "bareElicitationCapability": true to its MCP config entry
```
- `Elicitation` hook 출력 형식 [문서](https://code.claude.com/docs/en/hooks.md#elicitation-output):

```json
{
  "hookSpecificOutput": {
    "hookEventName": "Elicitation",
    "action": "accept",
    "content": {
      "username": "alice"
    }
  }
}
```

### 2.7 Tool annotations (readOnlyHint / destructiveHint)

- Claude Code 문서와 체인지로그에서 annotation을 **권한 판단에 쓴다는 서술을 찾지 못했다.** "무시한다"는 서술도 없다.
- 확인된 것은 표시 용도뿐이다. v1.0.44 (2025-07-07) 체인지로그: `MCP: tool annotations and tool titles now display in /mcp view`.
- 권한은 permission rules(§2.8)로 제어한다.
- 사람 확인을 강제하려면 Claude 전용 `_meta` 확장을 쓴다 [문서](https://code.claude.com/docs/en/mcp#require-approval-for-a-specific-tool).

```json
{
  "name": "grant_access",
  "description": "Requests access to a protected resource",
  "_meta": {
    "anthropic/requiresUserInteraction": true
  }
}
```

`anthropic/requiresUserInteraction`의 효과:

- 값은 JSON Boolean `true`여야 한다.
- 매 호출마다 권한 프롬프트를 띄운다. `acceptEdits`, `auto`, `bypassPermissions`에서도 마찬가지다.
- "don't ask again" 옵션이 없고, allow 규칙이나 PreToolUse hook의 `"allow"`로도 건너뛰지 못한다.

비용도 있다. 무인 경로에서는 오히려 실행할 수 없게 된다.

- `dontAsk` 모드에서는 **거부**된다.
- `--permission-prompt-tool`이 `allow`를 돌려줘도 다음 메시지와 함께 deny로 바뀐다.

```text
MCP tool requires user interaction; not supported via --permission-prompt-tool
```

pweh 서버는 Claude 전용 보조 장치로만 선택적으로 쓴다. 주 안전장치는 §7의 서버 측 게이트다.

### 2.8 권한 규칙 (`.claude/settings.json`)

**[문서]** [permissions#mcp](https://code.claude.com/docs/en/permissions#mcp) · [settings-reference#permissions-allow](https://code.claude.com/docs/en/settings-reference#permissions-allow)

| 규칙 | 매치 |
|---|---|
| `mcp__uart` | `uart` 서버의 모든 도구 |
| `mcp__uart__*` | 위와 같음 (와일드카드형) |
| `mcp__uart__uart_job_status` | 해당 도구 하나 |
| `mcp__uart__get_*` | `uart` 서버의 `get_`으로 시작하는 도구들 |
| `mcp__*` | 모든 MCP 도구. **deny/ask에서만** 의미가 있다 |

- 평가 순서는 **deny → ask → allow**이다. 첫 매치가 결정하며 구체성은 무관하다. allow로 deny 예외를 만들 수 없다.
- **allow 글롭은 리터럴 `mcp__<server>__` 접두사 뒤에서만** 쓸 수 있다. `"*"`, `"mcp__*"` 같은 앵커 없는 allow 글롭은 경고와 함께 무시된다.
- `mcp__`로 시작하는 규칙에 **괄호가 있으면 설정 파일 로드 시 건너뛴다**. 파라미터 매칭(`Tool(param:value)`)은 MCP에서 `--disallowedTools`로만 쓸 수 있다 [문서](https://code.claude.com/docs/en/permissions#match-by-input-parameter).
- 서버 이름에 `.`이나 공백이 있으면 `_`로 바뀐다 (`my.server`는 `mcp__my_server__*`). 이름에 `__`가 있거나 `_`로 끝나면 와일드카드형을 써야 한다.
- 프로젝트 `.claude/settings.json`의 `permissions.allow`는 **workspace trust를 수락한 뒤에만** 적용된다. deny/ask는 제한만 하므로 trust와 무관하다 [문서](https://code.claude.com/docs/en/permissions#project-allow-rules-and-workspace-trust).
- 세션 단위로는 `--allowedTools`(allow 추가)와 `--disallowedTools`(deny 추가)를 쓴다.

pweh 예시. 서버·도구 이름은 예시다.

```json
{
  "permissions": {
    "allow": [
      "mcp__fwtriage__*",
      "mcp__case__*"
    ],
    "ask": [
      "mcp__uart__*",
      "mcp__openocd__*",
      "mcp__sigrok__*",
      "mcp__jtagulator__*"
    ],
    "deny": []
  }
}
```

ask가 allow보다 먼저 평가된다. 그래서 `mcp__uart__*`를 ask에 두면, allow에 `mcp__uart__uart_job_status`를 따로 넣어도 그 도구는 여전히 묻는다. 장치 서버의 폴링·조회 도구만 묻지 않게 하려면 ask에 와일드카드 대신 위험한 도구 이름을 하나씩 나열하고, 조회 도구를 allow에 둔다.

#### 권한 모드별 동작

**[문서]** [permission-modes](https://code.claude.com/docs/en/permission-modes)

| 모드 | MCP 도구에 대한 효과 |
|---|---|
| `default` (UI 이름 Manual) | 처음 쓸 때 묻는다 |
| `acceptEdits` | 파일 편집과 일부 fs 명령만 자동. MCP는 규칙대로 |
| `plan` | 읽기 위주 |
| `auto` | 분류기가 검토. `requiresUserInteraction` 도구는 분류기를 거치지 않고 직접 묻는다 |
| `dontAsk` | 물어야 할 호출은 모두 **거부**한다. allow 규칙과 PreToolUse hook 승인은 실행된다 |
| `bypassPermissions` | 프롬프트를 건너뛴다. 단 아래 예외가 있다 |

`bypassPermissions`가 규칙에 미치는 영향 [문서](https://code.claude.com/docs/en/permission-modes#available-modes):

- "**Allow rules have no effect in `bypassPermissions`.**" 이미 모두 허용되므로 의미가 없다.
- "**Deny rules block in every mode, including `bypassPermissions`.**"
- 명시적 **ask 규칙**과 `requiresUserInteraction` MCP 도구는 이 모드에서도 묻는다 ("Actions no mode auto-approves").
- 시작 방법: `claude --permission-mode bypassPermissions` 또는 `--dangerously-skip-permissions`.
- 첫 대화형 실행 때 책임 수락 다이얼로그가 뜬다. 수락하면 `~/.claude/settings.json`에 `skipDangerousModePermissionPrompt: true`가 기록된다.
- Linux/macOS에서 root/sudo로 실행하면 다음 오류로 거부된다.

```text
--dangerously-skip-permissions cannot be used with root/sudo privileges for security reasons
```

### 2.9 프로젝트 Skills

**[문서]** [skills](https://code.claude.com/docs/en/skills)

위치:

| 위치 | 경로 | 로드 범위 |
|---|---|---|
| Personal | `~/.claude/skills/<skill-name>/SKILL.md` | 모든 프로젝트 |
| Project | `.claude/skills/<skill-name>/SKILL.md` | 이 저장소. 시작 디렉터리부터 저장소 루트까지의 부모 디렉터리도 스캔한다 |
| Nested | `<subdir>/.claude/skills/<skill-name>/SKILL.md` | 해당 하위 디렉터리 파일을 처음 다룰 때 로드 |
| `--add-dir` | 추가 디렉터리의 `.claude/skills/` | 그 세션 |

- **symlink**: enterprise/personal/project 위치의 `<skill-name>` 항목은 다른 디렉터리를 가리키는 **symlink여도 된다.** 여러 위치가 같은 대상을 가리켜도 한 번만 로드한다 [문서](https://code.claude.com/docs/en/skills#where-skills-live).
  - `.claude/skills` 디렉터리 자체를 symlink로 만드는 경우는 (미확인).
  - 참고: `.claude`가 symlink이면 `.claude/settings.local.json`을 저장소가 제공한 파일로 취급해 trust를 요구한다 [문서](https://code.claude.com/docs/en/permissions#when-your-local-settings-file-needs-trust).
  - 그래서 **skill 폴더 단위 symlink를 권장한다.**
- 예약 폴더 이름: `synced`(대소문자 무관), `anthropic-skills`, `anthropic-skills:`로 시작하는 이름.
- 변경은 세션 중 자동 반영된다 (SKILL.md 텍스트만). 세션 시작 뒤에 새로 만든 최상위 skills 디렉터리는 `/reload-skills`로 반영한다.
- frontmatter 검증: `claude plugin validate .claude/skills` (v2.1.233+).

#### SKILL.md frontmatter (Claude Code가 인식하는 전체 필드)

**[문서]** [skills#frontmatter-reference](https://code.claude.com/docs/en/skills#frontmatter-reference)

- 여는 `---`가 **파일의 첫 줄**이어야 frontmatter로 읽는다.
- YAML 파싱에 실패하면 필드 없이 로드된다. `/name`으로는 실행되지만 description 매칭은 안 된다.
- 모르는 필드는 오류 없이 무시한다. 필드명은 하이픈까지 정확해야 한다.
- Boolean은 `true`/`false` 외에 `yes`/`no`/`on`/`off`/`1`/`0`도 받는다 (v2.1.218+).

| 필드 | 요약 |
|---|---|
| `name` | `/` 메뉴의 명령 이름. 기본값은 디렉터리 이름 |
| `description` | 언제 쓰는지. `when_to_use`와 합쳐 **1,536자**에서 잘린다. 핵심 용도를 앞에 둔다 |
| `when_to_use` | 트리거 문구 추가. 1,536자 한도에 포함 |
| `argument-hint` | 자동완성 힌트. 예: `[issue-number]` |
| `arguments` | 이름 붙은 위치 인자 (`$name` 치환용) |
| `disable-model-invocation` | `true`면 Claude가 스스로 호출하지 못하고 `/name`으로만 실행. description도 컨텍스트에서 빠진다 |
| `user-invocable` | `false`면 `/` 메뉴에서 숨기고 Claude만 호출 |
| `allowed-tools` | 이 skill을 호출한 **그 턴 동안만** 묻지 않고 쓸 도구. 공백·쉼표 구분 문자열 또는 YAML 리스트. 다음 메시지를 보내면 해제된다 |
| `disallowed-tools` | skill 활성 동안 도구 풀에서 제거 |
| `model`, `effort` | 모델/effort 오버라이드 |
| `context` / `agent` / `background` | `context: fork`면 subagent에서 실행. `background: false`면 결과를 기다린다 |
| `hooks` | skill 호출 시 등록되는 hooks |
| `paths` | 글롭 범위 제한 |
| `shell` | `` !`cmd` ``에 쓸 셸 (`bash`/`powershell`) |
| `metadata`, `license`, `compatibility` | 표준 필드. Claude Code는 동작에 쓰지 않는다 |

- 문자열 치환 [문서](https://code.claude.com/docs/en/skills#available-string-substitutions): `$ARGUMENTS`, `$ARGUMENTS[N]`, `$N`(0부터), `$name`, `${CLAUDE_SESSION_ID}`, `${CLAUDE_EFFORT}`, `${CLAUDE_SKILL_DIR}`, `${CLAUDE_PROJECT_DIR}`.
  - 인자를 받을 placeholder가 본문에 하나도 없으면 Claude Code가 본문 끝에 `ARGUMENTS: <입력>`을 붙인다. 다른 클라이언트와 공유하는 skill은 placeholder 없이 이 동작에 기대는 편이 이식성이 좋다 (§5.3).
- **보안 주의**: 프로젝트 skill의 `allowed-tools`는 **workspace trust와 무관하게 적용된다.** 신뢰하지 않은 폴더의 `-p` 실행에서도 마찬가지다 [문서](https://code.claude.com/docs/en/skills#pre-approve-tools-for-a-skill). 그러니 pweh skill의 `allowed-tools`에 **장치에 영향을 주는 도구**(uart/openocd/sigrok/jtagulator의 쓰기·전송 계열)를 넣지 않는다.
- skill 목록은 컨텍스트 창의 1%를 예산으로 쓴다. 넘치면 덜 쓰는 skill의 description부터 빠진다. 조정 방법: `skillListingBudgetFraction` 또는 `SLASH_COMMAND_TOOL_CHAR_BUDGET`.
- SKILL.md는 500줄 이하로 유지하고, 상세 자료는 같은 폴더의 보조 파일로 분리한다.
- 권한 규칙으로 skill 자체를 제어할 수 있다: `Skill(name)`, `Skill(name *)`, `Skill`(전체).

### 2.10 커스텀 슬래시 명령 (`.claude/commands/`)과 skills 통합

**[문서]** [skills](https://code.claude.com/docs/en/skills) 첫머리 Note:

```text
Custom commands have been merged into skills. A file at `.claude/commands/deploy.md` and a skill at `.claude/skills/deploy/SKILL.md` both create `/deploy` and work the same way.
```

- `.claude/commands/<name>.md`는 기존 형식으로 계속 동작한다. skill과 **같은 frontmatter를 받되 `name`과 `paths`는 제외**한다.
- 하위 디렉터리는 `:`로 이어진다: `.claude/commands/frontend/component.md`는 `/frontend:component`.
- 같은 이름의 skill과 command가 있으면 **skill이 이긴다.**
- `$ARGUMENTS`, `$0`, `$1` 등 치환은 skill과 같다.
- `claude -p`나 Agent SDK에서는 메시지 맨 앞의 skill 하나만 로드하고, 나머지 줄을 인자로 넘긴다 [문서](https://code.claude.com/docs/en/skills#stack-several-skills-in-one-message).
- MCP 서버의 prompts도 명령이 된다. `/` 메뉴에는 `/servername:promptname (MCP)`로 보이고, `/mcp__<server>__<prompt> arg1 arg2`로 실행한다. 인자는 공백으로 나뉜다 [문서](https://code.claude.com/docs/en/mcp#use-mcp-prompts-as-commands).

### 2.11 지침 파일

- Claude Code v2.1.277+는 `AGENTS.md`를 직접 읽는다. 단 작업 디렉터리나 그 위에 `CLAUDE.md`, `.claude/CLAUDE.md`, `CLAUDE.local.md`가 **없을 때만** 읽는다 [문서](https://code.claude.com/docs/en/memory#agents-md).
- `CLAUDE.md`를 두려면 그 안에서 `@AGENTS.md`로 import한다. 이렇게 하면 두 번 읽히지 않는다.
- `/config`의 **Project instructions** 값으로 동작을 바꿀 수 있다: `claude-md-or-agents-md`(기본), `claude-md-and-agents-md`, `claude-md`, `managed-only`.

---

## 3. OpenAI Codex CLI

### 3.1 `codex mcp add`

**[문서]** [extend/mcp](https://learn.chatgpt.com/docs/extend/mcp.md) (구 URL `https://developers.openai.com/codex/mcp`는 308 리다이렉트)

```bash
codex mcp add <server-name> --env VAR1=VALUE1 --env VAR2=VALUE2 -- <stdio server-command>
```

로컬 `codex mcp add --help` 출력 [실측 0.162.0]:

```text
Usage: codex mcp add [OPTIONS] <NAME> (--url <URL> | -- <COMMAND>...)
...
      --env <KEY=VALUE>
          Environment variables to set when launching the server. Only valid with stdio servers
```

- **항상 사용자 전역 `~/.codex/config.toml`(`$CODEX_HOME`)에 쓴다.** 프로젝트 scope 플래그는 없다 [소스](https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/cli/src/mcp_cmd.rs#L466).
- 격리된 `CODEX_HOME`에서 실측한 출력과 기록 결과는 아래와 같다 [실측 0.162.0]. 임시 디렉터리 관련 `WARNING:` 줄은 생략했다.

```text
$ codex mcp add uart --env PWEH_CASES_DIR=/home/user/pweh/cases --env PYTHONUNBUFFERED=1 -- /home/user/pweh/.venv/bin/python -m pweh.servers.uart
Added global MCP server 'uart'.
```

```toml
[mcp_servers.uart]
command = "/home/user/pweh/.venv/bin/python"
args = ["-m", "pweh.servers.uart"]

[mcp_servers.uart.env]
PWEH_CASES_DIR = "/home/user/pweh/cases"
PYTHONUNBUFFERED = "1"
```

```text
$ codex mcp list
Name  Command                           Args                  Env                                           Cwd  Status   Auth
uart  /home/user/pweh/.venv/bin/python  -m pweh.servers.uart  PWEH_CASES_DIR=*****, PYTHONUNBUFFERED=*****  -    enabled  Unsupported
```

```text
$ codex mcp get uart
uart
  enabled: true
  transport: stdio
  command: /home/user/pweh/.venv/bin/python
  args: -m pweh.servers.uart
  cwd: -
  env: PWEH_CASES_DIR=*****, PYTHONUNBUFFERED=*****
  remove: codex mcp remove uart
```

- `codex mcp list --json`은 `"startup_timeout_sec": null`, `"tool_timeout_sec": null`을 보여 준다. 즉 `codex mcp add`는 타임아웃을 기록하지 않고 기본값에 맡긴다.
- 세션 안에서는 `/mcp`(목록)와 `/mcp verbose`(진단)를 쓴다 [문서](https://learn.chatgpt.com/docs/developer-commands.md?surface=cli).
- Codex의 `-p`는 `--profile`이다. Claude의 print 모드가 아니다.

### 3.2 `[mcp_servers.<name>]` 키 (stdio)

**[문서]** [extend/mcp](https://learn.chatgpt.com/docs/extend/mcp.md#stdio-servers) · [config-reference](https://learn.chatgpt.com/docs/config-file/config-reference.md)

| 키 | 타입 | 의미 |
|---|---|---|
| `command` | string (필수) | 서버 실행 커맨드 |
| `args` | array<string> | 인자 |
| `env` | map<string,string> | 서버에 설정할 환경변수 |
| `env_vars` | array<string 또는 { name, source = "local"/"remote" }> | Codex 환경에서 **추가로 전달**할 변수 이름 (화이트리스트 확장) |
| `cwd` | string | 서버 프로세스의 작업 디렉터리 |
| `experimental_environment` | `local`/`remote` | remote executor에서 stdio를 실행 (실험적) |
| `startup_timeout_sec` | number | 시작 타임아웃. 문서 기본값 **10**초 (§3.3 불일치 참조) |
| `startup_timeout_ms` | number | 위 값의 ms 별칭 |
| `tool_timeout_sec` | number | 도구 호출 타임아웃. 문서 기본값 **60**초 (§3.3 불일치 참조) |
| `enabled` | boolean | `false`면 설정을 지우지 않고 비활성 |
| `required` | boolean | `true`면 이 서버가 초기화에 실패할 때 시작·재개도 실패 |
| `enabled_tools` | array<string> | 도구 허용 목록 |
| `disabled_tools` | array<string> | 도구 거부 목록 (`enabled_tools` 다음에 적용) |
| `default_tools_approval_mode` | `auto` / `prompt` / `writes` / `approve` | 이 서버 도구의 기본 승인 방식 |
| `tools.<tool>.approval_mode` | 위와 같음 | 도구별 오버라이드 |
| `tools.<tool>.output_token_limit` | 양의 정수 | 도구 하나의 출력 토큰 예산 (20% 직렬화 여유분 별도) |

- 최상위 `mcp_optional_startup_grace_ms`(기본 `1000`)는 초기 도구 카탈로그를 만들 때 optional 서버를 기다리는 시간이다. `0`이면 각 서버의 `startup_timeout_sec`까지 기다린다.
- MCP 설정 안의 `${VAR}` 같은 변수 치환은 **문서에 없다** (미확인). 값은 리터럴로 쓰고, 셸 변수는 `env_vars`로 넘긴다.

pweh 예시 (프로젝트 `.codex/config.toml` 또는 `~/.codex/config.toml`). 경로는 예시이며, 상대경로 해석이 (미확인)이므로 **절대경로**를 쓴다.

```toml
[mcp_servers.uart]
command = "/home/USER/pweh/mcp-servers/uart-mcp/run.sh"
args = []
cwd = "/home/USER/pweh"
env_vars = ["PWEH_ROOT"]
startup_timeout_sec = 30
tool_timeout_sec = 120
default_tools_approval_mode = "prompt"

[mcp_servers.uart.env]
PWEH_LOG_LEVEL = "INFO"

# 폴링 도구는 묻지 않게 (도구 이름은 예시)
[mcp_servers.uart.tools.uart_job_status]
approval_mode = "approve"

[mcp_servers.fwtriage]
command = "/home/USER/pweh/mcp-servers/fwtriage-mcp/run.sh"
cwd = "/home/USER/pweh"
startup_timeout_sec = 60
tool_timeout_sec = 900
```

### 3.3 타임아웃: 문서와 소스가 다르다

| 항목 | 공식 문서 | 소스 rust-v0.162.0 / 0.163.0 | 과거 소스 |
|---|---|---|---|
| 시작 타임아웃 기본값 | **10초** ([extend/mcp](https://learn.chatgpt.com/docs/extend/mcp.md#other-configuration-options), [config-reference](https://learn.chatgpt.com/docs/config-file/config-reference.md)) | **30초** (`DEFAULT_STARTUP_TIMEOUT`) [소스](https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/codex-mcp/src/rmcp_client.rs#L106-L107) | rust-v0.100.0: 10초 [소스](https://github.com/openai/codex/blob/rust-v0.100.0/codex-rs/core/src/mcp_connection_manager.rs#L86-L89). rust-v0.130.0: 30초 [소스](https://github.com/openai/codex/blob/rust-v0.130.0/codex-rs/codex-mcp/src/rmcp_client.rs#L77-L78) |
| 도구 타임아웃 기본값 | **60초** | **300초** (`DEFAULT_TOOL_TIMEOUT`) | rust-v0.100.0: 60초. rust-v0.130.0: 120초 |

**결론: 기본값에 기대지 말고 `startup_timeout_sec`와 `tool_timeout_sec`를 항상 명시한다.** 참고로 `src/pweh/jobs.py` 주석의 "Codex 기본 60초"는 문서 기준 값이다. 설치된 0.162.0 소스의 실제 기본값은 300초다.

소스에서 확인한 동작 (rust-v0.162.0):

- 시작 타임아웃 오류 형식 [소스](https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/codex-mcp/src/rmcp_client.rs#L380):

  ```text
  MCP client startup timed out after {startup_timeout:?}
  ```

- 요청 타임아웃 오류 형식 [소스](https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/rmcp-client/src/rmcp_client.rs#L289). 같은 파일 L1737의 테스트 기대값은 `timed out awaiting tools/list after 30s`이므로, 도구 호출이면 `tools/call`이 들어간다:

  ```text
  timed out awaiting {label} after {duration:.0?}
  ```

- 도구 타임아웃은 Codex 자체 타이머(`active_time_timeout`)다. **elicitation이 열려 있는 동안 시계가 멈춘다** [소스](https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/rmcp-client/src/rmcp_client.rs#L239).
- `tools/call`은 `PeerRequestOptions::no_options()`로 보내므로 rmcp의 "progress가 오면 타임아웃 리셋" 옵션을 쓰지 않는다 [소스](https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/rmcp-client/src/rmcp_client.rs#L883).
- 받은 progress notification은 로그로만 남긴다 [소스](https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/rmcp-client/src/logging_client_handler.rs#L63-L72).
- progressToken 자체는 rmcp가 모든 요청에 자동으로 붙인다 (Codex 0.162.0이 고정한 rmcp rev `3e636cab…` `service.rs` L881/L893) [소스](https://github.com/modelcontextprotocol/rust-sdk/blob/3e636cab26c013eca5131103c03d20237f12c4df/crates/rmcp/src/service.rs#L881-L893).
- 따라서 **progress를 보내도 Codex의 `tool_timeout_sec`는 연장되지 않는다.**

### 3.4 프로젝트 설정 `.codex/config.toml`

**[문서]** [config-basic](https://learn.chatgpt.com/docs/config-file/config-basic.md) · [config-advanced#project-config-files](https://learn.chatgpt.com/docs/config-file/config-advanced.md)

- 저장소 안의 `.codex/config.toml`을 프로젝트 루트부터 현재 디렉터리까지 모두 로드한다. 같은 키는 **현재 디렉터리에 가까운 파일이 이긴다.**
- **trusted 프로젝트에서만** 로드한다. untrusted면 프로젝트 `.codex/` 레이어(config, hooks, rules)를 통째로 무시한다.
- 우선순위 (높은 순):
  1. CLI 플래그와 `-c`/`--config`
  2. 프로젝트 `.codex/config.toml`
  3. `--profile`
  4. `~/.codex/config.toml`
  5. cloud-managed
  6. `/etc/codex/config.toml`
  7. 내장 기본값
- 프로젝트 config의 상대경로는 해당 `.codex/` 폴더 기준이다. 문서 예는 `model_instructions_file`뿐이고, MCP `command`/`cwd`에 적용되는지는 (미확인).
- 프로젝트 config에서 무시되는 키: `openai_base_url`, `chatgpt_base_url`, `apps_mcp_product_sku`, `model_provider`, `model_providers`, `notify`, `profile`, `profiles`, `experimental_realtime_ws_base_url`, `otel`.

### 3.5 승인 정책과 tool annotations

**[문서]** [agent-approvals-security](https://learn.chatgpt.com/docs/agent-approvals-security.md):

```text
Destructive app/MCP tool calls always require approval when the tool advertises a destructive annotation (unless the tool advertises a read annotation, which takes priority).
```

**[소스 rust-v0.162.0]** 실제 판정 로직 ([mcp_tool_call.rs L2461–L2492](https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/core/src/mcp_tool_call.rs#L2461-L2492)):

- `auto` (기본):
  1. `destructiveHint == true`면 승인을 묻는다.
  2. 아니면 `readOnlyHint == true`면 묻지 않는다.
  3. 아니면 `destructiveHint`가 미지정(기본 true)이거나 `openWorldHint`가 미지정/true면 승인을 묻는다.
- `prompt`: 항상 승인을 묻는다.
- `writes`: `readOnlyHint`가 true가 아니면 승인을 묻는다.
- `approve`: 승인 요청 없이 자동 실행한다 (자동 승인).

> 문서는 "read annotation이 우선"이라고 하지만, 소스에서는 `destructiveHint: true`를 먼저 검사한다. 두 hint를 동시에 true로 두지 말라. MCP 사양상 `destructiveHint`는 `readOnlyHint == false`일 때만 의미가 있다 [사양](https://modelcontextprotocol.io/specification/2025-11-25/schema).

MCP 사양의 annotation 기본값 [사양](https://modelcontextprotocol.io/specification/2025-11-25/schema):

- `readOnlyHint` 기본 `false`
- `destructiveHint` 기본 `true`
- `idempotentHint` 기본 `false`
- `openWorldHint` 기본 `true`
- 사양은 신뢰하지 않는 서버의 annotation을 untrusted로 취급하라고 요구한다.

**pweh annotation 프리셋(`src/pweh/mcpkit.py`)이 Codex에서 어떻게 동작하는가**:

| 프리셋 | read_only / destructive / open_world | Codex `auto` | Codex `writes` | Claude Code | Cursor |
|---|---|---|---|---|---|
| `ANN_READ_ONLY` | T / F / F | 묻지 않음 | 묻지 않음 | 권한 반영이 문서화되지 않음. 규칙대로 | (미확인) |
| `ANN_LOCAL_WRITE` | F / F / F | **묻지 않음** | 물음 | 위와 같음 | (미확인) |
| `ANN_DEVICE` | F / F / **T** | 물음 (open_world 때문) | 물음 | 위와 같음 | (미확인) |
| `ANN_DESTRUCTIVE` | F / T / T | 물음 | 물음 | 위와 같음 | (미확인) |

**전체 자동 승인 조건** [소스](https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/codex-mcp/src/mcp/mod.rs#L91-L110). 아래 경우 위 표와 무관하게 MCP 승인 프롬프트가 **자동 승인**된다.

- 도구의 `approval_mode = "approve"`, 또는
- `approval_policy = never`이면서 권한 프로필이 Disabled/External이거나 full disk write인 경우 (예: `--sandbox danger-full-access -a never`, `--dangerously-bypass-approvals-and-sandbox`).

관련 CLI 플래그 (로컬 `codex --help` 발췌, 0.162.0):

```text
  -s, --sandbox <SANDBOX_MODE>
          Select the sandbox policy to use when executing model-generated shell commands
          
          [possible values: read-only, workspace-write, danger-full-access]

      --dangerously-bypass-approvals-and-sandbox
          Skip all confirmation prompts and execute commands without sandboxing. EXTREMELY
          DANGEROUS. Intended solely for running in environments that are externally sandboxed

  -a, --ask-for-approval <APPROVAL_POLICY>
          Configure when the model requires human approval before executing a command

          Possible values:
          - on-request: The model decides when to ask the user for approval
          - never:      Never ask for user approval Execution failures are immediately returned to
            the model
```

### 3.6 Elicitation (Codex)

**[문서]** [config-reference](https://learn.chatgpt.com/docs/config-file/config-reference.md): `approval_policy.granular.mcp_elicitations`의 설명은 "When `true`, MCP elicitation prompts are allowed to surface instead of being auto-rejected."

**[소스 rust-v0.162.0]** [elicitation.rs](https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/codex-mcp/src/elicitation.rs):

- `approval_policy = never`이면 elicitation을 **decline**한다. `granular`에서 `mcp_elicitations = false`여도 decline (L552–L559).
- `never` + full access 조합에서 **requestedSchema.properties가 빈 form elicitation은 자동 Accept**하고 `content = {}`를 돌려준다 (L420, L563–L577). 소스 주석: "Auto-accept confirm/approval elicitations without schema requirements."
- 그 밖의 경우에는 사용자에게 표시한다. TUI의 정확한 표시 형태는 (미확인).

**설계 시사점**: "빈 스키마 확인 대화상자"를 위험 작업의 유일한 확인 수단으로 쓰지 말라. 확인이 필요하면 장치 시리얼 등을 **입력하게 하는 필드**를 둔다. 그러면 Codex 자동 수락 대상(빈 스키마)에서 빠지고, `never`에서는 거절되므로 fail-safe가 된다. 다만 pweh의 기본 확인 수단은 §7의 서버 측 게이트다.

### 3.7 AGENTS.md

**[문서]** [agent-configuration/agents-md](https://learn.chatgpt.com/docs/agent-configuration/agents-md.md)

- 전역: `~/.codex/AGENTS.override.md`가 있으면 그것을, 없으면 `~/.codex/AGENTS.md`를 쓴다 (`CODEX_HOME` 기준). 비어 있지 않은 첫 파일 하나만 쓴다.
- 프로젝트: 프로젝트 루트(보통 git 루트)부터 현재 디렉터리까지 내려가며 각 디렉터리에서 다음 순서로 **최대 1개**를 쓴다.
  1. `AGENTS.override.md`
  2. `AGENTS.md`
  3. `project_doc_fallback_filenames`
- 루트에서 아래로 이어 붙이므로 가까운 파일이 뒤에 온다. 합계가 `project_doc_max_bytes`(기본 **32 KiB**)에 닿으면 멈춘다.
- 로드 확인용 예: `codex --ask-for-approval never "Summarize the current instructions."`

### 3.8 Codex Skills

**[문서]** [build-skills](https://learn.chatgpt.com/docs/build-skills.md) (구 URL `https://developers.openai.com/codex/skills`)

- 형식: `SKILL.md`가 들어 있는 디렉터리. **`name`과 `description`이 필수**이다. 선택 하위 폴더: `scripts/`, `references/`, `assets/`, `agents/openai.yaml`.
- 위치:

| Scope | 위치 |
|---|---|
| REPO | `$CWD/.agents/skills`, 그 위 폴더들의 `.agents/skills`, `$REPO_ROOT/.agents/skills` (CWD부터 저장소 루트까지 전부) |
| USER | `$HOME/.agents/skills` |
| ADMIN | `/etc/codex/skills` |
| SYSTEM | Codex 번들 |

- 소스 rust-v0.162.0에서 추가로 확인한 위치 [소스](https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/ext/skills/src/host_roots.rs#L85-L120):
  - trusted 프로젝트 config 레이어의 `.codex/skills` (REPO). 문서에는 없다.
  - deprecated 사용자 위치 `$CODEX_HOME/skills` (소스 주석: "Deprecated user skills location (`$CODEX_HOME/skills`), kept for backward compatibility"). 로컬에는 `~/.codex/skills/.system` 디렉터리가 있다 (시스템 skill 캐시로 보이지만 미확인).
- symlink: "Codex supports symlinked skill folders and follows the symlink target when scanning these locations."
- 같은 `name`의 skill 두 개는 병합하지 않고 둘 다 표시될 수 있다.
- 호출: 명시적으로는 `/skills` 또는 `$`로 언급(예: `$skill-creator`). 암시적으로는 description 매칭으로 고른다.
- 초기 목록 예산: 컨텍스트의 2%, 모를 때는 8,000자. `skills.max_context_tokens`로 최대 10,000 토큰까지 바꿀 수 있다.
- 변경은 자동 감지된다. 안 보이면 재시작한다.
- 비활성화:

```toml
[[skills.config]]
path = "/path/to/skill/SKILL.md"
enabled = false
```

- `agents/openai.yaml`의 암시적 호출 금지 설정. "파이프라인 시작" 같은 명시 실행 전용 skill에 쓴다.

```yaml
policy:
  allow_implicit_invocation: false
```

- skill 본문에서 `$ARGUMENTS` 같은 인자 치환을 하는지는 문서에 없다 (미확인).

### 3.9 Custom prompts (deprecated)

**[문서]** [custom-prompts](https://learn.chatgpt.com/docs/custom-prompts.md): "Custom prompts are deprecated. Use skills for reusable instructions..."

- 위치는 `~/.codex/prompts/<name>.md`이다. **최상위 `.md`만** 스캔하고 하위 디렉터리는 보지 않는다. 사용자 홈에 있으므로 저장소로 공유되지 않는다.
- 호출: `/prompts:<name>`. 예: `/prompts:draftpr FILES="src/a.ts src/b.ts" PR_TITLE="Add hero animation"`.
- frontmatter: `description`, `argument-hint`.
- placeholder:
  - `$1`~`$9`: 위치 인자.
  - `$ARGUMENTS`: 전부.
  - `$FILE` 같은 대문자 이름: `KEY=value`로 전달.
  - `$$`: 리터럴 `$`.
- 파일을 고친 뒤에는 Codex를 재시작하거나 새 채팅을 연다.

### 3.10 기타

- `/import`로 Claude Code나 Cursor 설정을 Codex로 가져올 수 있다 [문서](https://learn.chatgpt.com/docs/developer-commands.md?surface=cli). 가져오는 항목의 범위는 (미확인).
- Codex는 MCP 서버의 `instructions` 필드를 읽는다. "Keep the first 512 characters self-contained." [문서](https://learn.chatgpt.com/docs/extend/mcp.md#supported-mcp-features)

---

## 4. Cursor

### 4.1 `.cursor/mcp.json`

**[문서]** [cursor.com/docs/mcp](https://cursor.com/docs/mcp.md)

- 위치: 프로젝트 `.cursor/mcp.json`, 전역 `~/.cursor/mcp.json`.
- stdio 필드:

| 필드 | 필수 | 설명 |
|---|---|---|
| `type` | Yes | `"stdio"` |
| `command` | Yes | 시스템 PATH에 있거나 전체 경로 |
| `args` | No | 인자 배열 |
| `env` | No | 환경변수. 예: `{"API_KEY": "${env:api-key}"}` |
| `envFile` | No | 환경 파일. 예: `".env"`, `"${workspaceFolder}/.env"`. **stdio 전용** |

  표에는 `type`이 필수로 되어 있지만 같은 문서의 예제들은 `type`을 생략한다. **`"type": "stdio"`를 명시하는 것을 권장한다.**

- 변수 치환 위치: `command`, `args`, `env`, `url`, `headers`.
  - `${env:NAME}`
  - `${userHome}`
  - `${workspaceFolder}`: `.cursor/mcp.json`이 들어 있는 프로젝트 루트
  - `${workspaceFolderBasename}`
  - `${pathSeparator}`, `${/}`

pweh 예시 (런처 경로는 예시):

```json
{
  "mcpServers": {
    "uart": {
      "type": "stdio",
      "command": "${workspaceFolder}/mcp-servers/uart-mcp/run.sh",
      "args": [],
      "env": { "PWEH_ROOT": "${workspaceFolder}" }
    },
    "fwtriage": {
      "type": "stdio",
      "command": "${workspaceFolder}/mcp-servers/fwtriage-mcp/run.sh",
      "args": [],
      "envFile": "${workspaceFolder}/.env"
    }
  }
}
```

- 프로그래밍 방식 등록: 확장 API `vscode.cursor.mcp.registerServer()`.
- 지원 기능: Tools, Prompts, Resources, Roots, **Elicitation**, MCP Apps 모두 "Supported".
- 디버깅: Output 패널(Cmd+Shift+U)에서 "MCP Logs"를 고른다.
- CLI(`agent`)도 `mcp.json`을 그대로 읽는다 [문서](https://cursor.com/docs/cli/using.md).

### 4.2 승인과 권한

- IDE: 기본적으로 MCP 도구를 쓰기 전에 승인을 묻는다. MCP도 터미널 명령과 같은 **Run Modes**를 따른다 [문서](https://cursor.com/docs/agent/security/run-modes.md).

| Run Mode | 묻지 않고 실행되는 것 |
|---|---|
| Auto-review | allowlist에 있는 호출. 나머지는 분류기가 검토한다 |
| Allowlist | allowlist에 있는 호출만 |
| Run Everything | 모든 도구 호출 |

- Auto-review 지침 파일: `~/.cursor/permissions.json`, `<project>/.cursor/permissions.json`. 둘 다 있으면 병합한다. 팀 설정이 있으면 팀 설정이 우선한다.

```json
{
  "autoRun": {
    "allow_instructions": [],
    "block_instructions": [
      "Every AWS CLI command should go through approval first."
    ]
  }
}
```

- Cursor CLI 권한: `~/.cursor/cli-config.json`(전역) 또는 `<project>/.cursor/cli.json`(프로젝트에서는 permissions만 설정 가능) [문서](https://cursor.com/docs/cli/reference/permissions.md).
  - MCP 형식은 `Mcp(server:tool)`이다. 예: `Mcp(datadog:*)`, `Mcp(*:search)`, `Mcp(*:*)`.
  - deny가 allow보다 우선한다.

```json
{
  "permissions": {
    "allow": ["Mcp(fwtriage:*)", "Mcp(case:*)"],
    "deny": []
  }
}
```

- CLI의 MCP 서버 승인 [문서](https://cursor.com/docs/cli/reference/parameters.md):
  - `agent mcp enable <identifier>`: 로컬 승인 목록에 추가.
  - `agent mcp disable <identifier>`: 로드도 승인 질문도 하지 않음.
  - `agent mcp list`, `agent mcp list-tools <identifier>`.
  - 전역 플래그 `--approve-mcps`(모든 MCP 서버 자동 승인), `-f`/`--force`/`--yolo`("Force allow commands unless explicitly denied"), `--trust`(headless에서 workspace 신뢰).
- IDE에서 프로젝트 `.cursor/mcp.json` 서버를 처음 켤 때의 승인 UX는 문서에 없다 (미확인).
- Tool annotations를 승인 판단에 쓰는지는 (미확인).

### 4.3 타임아웃 (Cursor)

공식 문서에는 MCP 시작/도구 타임아웃 값이나 설정 방법이 **없다.** 아래는 모두 **[포럼·미확인]**이다.

| 경로 | 보고된 값 | 출처 |
|---|---|---|
| IDE `tools/call` | 약 60분 (스태프 답변, 2026-07-02) | [forum 163925](https://forum.cursor.com/t/agent-acp-mcp-tools-call-times-out-at-60s-with-no-way-to-configure-it/163925) |
| `agent acp` `tools/call` | 60초로 하드코딩된 SDK 기본값. progress notification으로 연장되지 않음 (스태프 확인, 2026-07-02). 오류 문자열 `MCP error -32001: Request timed out` | 위와 같음 |
| 원격 Streamable HTTP | 약 300초 (`UND_ERR_HEADERS_TIMEOUT`). per-server/global 설정 없음. 스태프가 start-job/poll 패턴을 권함 (2026-07-24) | [forum 166437](https://forum.cursor.com/t/remote-mcp-calls-fail-after-300s-with-und-err-headers-timeout-and-cancellation-does-not-abort-the-underlying-fetch/166437) |
| elicitation 응답 대기 | 약 60초, 설정 불가 (2025-12 답변) | [forum 145697](https://forum.cursor.com/t/mcp-timeout-happens-even-when-sending-back-updates-via-progress-token/145697) |

→ Cursor에서는 **60초 안에 끝나는 도구 + job/poll**만을 전제로 설계한다 (§6).

### 4.4 Rules (`.cursor/rules/*.mdc`)

**[문서]** [cursor.com/docs/rules](https://cursor.com/docs/rules.md)

- 프로젝트 rule은 `.cursor/rules/` 아래의 **`.mdc`** 파일이다. 하위 폴더를 써도 된다.
- **`.md`는 무시된다** ("A plain `.md` file in `.cursor/rules` is ignored by the rules system").
- frontmatter 세 필드의 조합으로 적용 방식이 정해진다:

| `alwaysApply` | `description` | `globs` | 동작 |
|---|---|---|---|
| `true` | — | — | 항상 포함 |
| `false` | — | 있음 | 매칭 파일이 컨텍스트에 있을 때 자동 첨부 |
| `false` | 있음 | 없음 | Agent가 description을 보고 판단 |
| `false` | 없음 | 없음 | `@rule-name`으로 언급할 때만 |

```md
---
description: RPC service conventions and patterns for the backend
alwaysApply: false
---
```

- `globs`는 쉼표로 여러 개를 쓴다 (예: `docs/**/*.md, docs/**/*.mdx`).
- 우선순위는 Team Rules → Project Rules → User Rules이다.
- `AGENTS.md`: 프로젝트 루트와 하위 디렉터리를 지원한다 (nested). Cursor CLI는 루트의 `AGENTS.md`와 `CLAUDE.md`를 rule로 함께 적용한다 [문서](https://cursor.com/docs/cli/using.md).
  - `CLAUDE.md` 안의 `@AGENTS.md` import를 Cursor가 해석하는지는 (미확인).

### 4.5 Skills (Cursor)

**[문서]** [cursor.com/docs/skills](https://cursor.com/docs/skills.md)

- 위치:
  - 프로젝트: `.agents/skills/`, `.cursor/skills/`
  - 사용자: `~/.agents/skills/`, `~/.cursor/skills/`
  - 호환: `.claude/skills/`, `.codex/skills/`, `~/.claude/skills/`, `~/.codex/skills/`
- 하위 카테고리 폴더를 재귀 탐색한다. 저장소 안 어디에 있는 `.cursor/skills/`나 `.agents/skills/`도 발견한다. 하위 폴더의 skill은 그 디렉터리 파일 작업 시에만 노출된다.
- frontmatter:

| 필드 | 필수 | 설명 |
|---|---|---|
| `name` | Yes | **소문자, 숫자, 하이픈만. 상위 폴더 이름과 같아야 한다** |
| `description` | Yes | 무엇을, 언제 |
| `paths` | No | 글롭 범위 (레거시 `globs`도 fallback으로 허용) |
| `disable-model-invocation` | No | `true`면 `/skill-name`으로 명시 호출할 때만 포함 |
| `icon`, `color` | No | Custom Mode 배지 |
| `metadata` | No | 임의 key-value |

- 호출: Agent 채팅에서 `/`를 입력하고 skill 이름을 고른다. 한 메시지에만 붙는다. 세션 내내 켜 두려면 Option+Enter(Mac) 또는 Alt+Enter(Windows)로 Custom Mode로 쓴다.
- symlink된 skill 폴더를 따라가는지는 문서에 없다 (미확인).
- 같은 skill이 `.agents/skills`와 `.claude/skills` 양쪽에 있을 때 중복 제거하는지는 (미확인).

### 4.6 커스텀 명령 (Cursor)

- 현재 문서에는 commands 전용 페이지가 없다. 예전 경로(`/docs/agent/chat/commands`, `/docs/context/commands`)는 404이다.
- Cursor 2.4의 내장 skill `/migrate-to-skills`는 "user-level and workspace-level commands"를 `disable-model-invocation: true` skill로 바꾼다 [문서](https://cursor.com/docs/skills.md#migrating-rules-and-commands-to-skills).
- **권장**: "명령"도 skill(`disable-model-invocation: true`)로 만든다. `.cursor/commands/*.md`가 현재 버전에서도 로드되는지는 (미확인).

---

## 5. Skills와 "파이프라인 시작" 명령: 교차 클라이언트 배치

### 5.1 디렉터리 배치 (권장)

정본은 이미 있는 `skills/<name>/SKILL.md`에 둔다. 클라이언트별 발견 위치에는 **skill 폴더 단위 symlink**를 만든다. 아래 목록의 `pweh-start`는 §5.3의 예시 skill이다. `skills/pweh-start/`를 먼저 만들지 않으면 깨진 링크가 생긴다.

```bash
# 저장소 루트에서 (예시)
mkdir -p .claude/skills .agents/skills
for s in uart-shell-acquisition firmware-dump-via-uart firmware-static-analysis \
         logic-analyzer-protocol-decode cctv-auth-bypass-hunt pweh-start; do
  ln -sfn "../../skills/$s" ".claude/skills/$s"   # Claude Code (문서상 symlink 지원)
  ln -sfn "../../skills/$s" ".agents/skills/$s"   # Codex (문서상 symlink 지원), Cursor도 스캔
done
```

- Claude Code는 `.claude/skills`, Codex는 `.agents/skills`, Cursor는 둘 다(그리고 `.cursor/skills`)를 읽는다.
- Cursor에서 같은 skill이 두 번 보일 수 있다 (중복 처리 미확인). 문제가 되면 Cursor 사용자는 `.cursor/skills`를 쓰지 말고, Customize → Skills에서 확인한다.
- `.claude` 디렉터리 전체를 symlink로 만들지 않는다 (§2.9의 trust 부작용).

### 5.2 공통 frontmatter 부분집합

세 클라이언트에서 모두 안전한 최소 집합은 다음과 같다.

```yaml
---
name: firmware-static-analysis   # 폴더 이름과 동일. 소문자, 숫자, 하이픈만 (Cursor 강제)
description: Analyze an extracted firmware image (authorized devices only) with REA + Ghidra to locate authentication logic, hardcoded credentials and backdoor candidates. Use when ...
---
```

- `description`의 앞부분에 핵심 용도와 트리거 단어를 둔다. Claude는 1,536자에서 자르고, Codex와 Cursor도 예산이 넘치면 줄인다.
- 클라이언트별 추가 기능:

| 기능 | Claude Code | Codex | Cursor |
|---|---|---|---|
| 자동 호출 금지 | `disable-model-invocation: true` | `agents/openai.yaml`의 `policy.allow_implicit_invocation: false` | `disable-model-invocation: true` |
| 인자 힌트 | `argument-hint` | (custom prompts의 `argument-hint`, deprecated) | — |
| 턴 단위 도구 사전 승인 | `allowed-tools` | — | — |
| 범위 제한 | `paths` | — | `paths` |

- Codex와 Cursor가 모르는 frontmatter 키(`allowed-tools`, `argument-hint` 등)를 조용히 무시하는지는 (미확인). Claude Code는 모르는 키를 무시한다고 명시한다.
- Claude의 skill 패키징 경로(claude.ai 업로드, `package_skill.py`)에서는 표준 6개 키 외의 키가 있으면 다음 하드 오류가 난다. 로컬 Claude Code 로드와는 별개다 [문서](https://code.claude.com/docs/en/skills#using-skill-frontmatter-outside-claude-code).

```text
Unexpected key(s) in SKILL.md frontmatter: argument-hint. Allowed properties are: allowed-tools, compatibility, description, license, metadata, name
```

### 5.3 "파이프라인 시작" 명령

이식성을 위해 **skill 하나**로 만든다. 본문에 `$ARGUMENTS`를 쓰지 않는다. Claude Code는 placeholder가 없으면 `ARGUMENTS: <입력>`을 덧붙이고, Codex·Cursor의 skill 인자 치환은 문서에 없기 때문이다.

`skills/pweh-start/SKILL.md` (예시. 아래 orchestrator 파일들은 project.md에 계획만 된 파일이다):

```markdown
---
name: pweh-start
description: Start the pweh hardware-analysis pipeline for a device the operator owns or is authorized in writing to test. Run only when the user explicitly invokes /pweh-start or $pweh-start.
disable-model-invocation: true
---

# pweh 파이프라인 시작

1. 사용자의 메시지(또는 마지막 줄의 `ARGUMENTS:`)에서 case-id 와 대상 프로파일을 읽는다. 없으면 묻는다.
2. 사용자에게 "이 기기를 소유했거나 서면 허가를 받았는가"를 확인받는다. 아니면 중단한다.
3. `orchestrator/master-prompt.md` 와 `orchestrator/pipeline-config.yaml` 을 읽고 단계 계획을 보여준다.
4. case 서버로 케이스 작업공간을 열거나 만든다.
5. 장치에 영향을 주는 도구가 `approval_required` 를 반환하면, 사용자에게 별도 터미널에서
   `pweh approve <id>` 를 실행하도록 안내하고 기다린다. 우회하지 않는다.
6. 오래 걸리는 작업은 job_id 를 받아 `<prefix>_job_status` 로 폴링한다.
```

같은 폴더에 Codex용 메타데이터를 둔다.

```yaml
# skills/pweh-start/agents/openai.yaml
policy:
  allow_implicit_invocation: false
```

클라이언트별 실행:

| 클라이언트 | 대화형 | 비대화형 / 기타 |
|---|---|---|
| Claude Code | `/pweh-start CASE-001 hikvision-ds2cd` | `claude -p "/pweh-start CASE-001"`. `-p`는 첫 skill만 로드한다. `.mcp.json` 서버가 **승인 없이** 로드되고, 묻는 도구는 거부된다는 점에 유의 |
| Codex | `$pweh-start CASE-001` 또는 `/skills`에서 선택 | 초기 프롬프트 인자 `codex "<프롬프트>"`에서 `$skill` 언급이 동작하는지는 (미확인). 대안은 deprecated `~/.codex/prompts/pweh-start.md`와 `/prompts:pweh-start` |
| Cursor | Agent 채팅에서 `/pweh-start` | CLI `agent`의 `/` 메뉴. 초기 프롬프트에서의 skill 호출은 (미확인) |

Claude 전용으로 더 다듬고 싶다면 `.claude/skills/pweh-start/`를 symlink 대신 실제 폴더로 두고 아래 키를 더할 수 있다. 다만 이 폴더를 Cursor도 읽으므로 내용이 갈라질 수 있다.

```yaml
argument-hint: "[case-id] [target-profile]"
allowed-tools: Read Grep Glob mcp__case__*   # 장치 서버(uart/openocd/sigrok/jtagulator)는 넣지 않는다
```

---

## 6. 장시간 MCP 도구 가이드 (Ghidra 콜드 스타트, 수 시간짜리 UART 덤프)

### 6.1 사양: progress와 cancellation

**[사양]** [progress (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/progress) · [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/utilities/progress)

- progress를 받고 싶은 쪽(클라이언트)이 요청의 `_meta.progressToken`(문자열 또는 정수, 활성 요청 사이에서 유일)을 넣는다.
- 서버는 다음 형식으로 progress를 보낼 수 있다.

```json
{
  "jsonrpc": "2.0",
  "method": "notifications/progress",
  "params": {
    "progressToken": "abc123",
    "progress": 50,
    "total": 100,
    "message": "Reticulating splines..."
  }
}
```

- `progress`는 매번 **증가해야 한다** (total을 몰라도). 실수를 써도 된다. 완료 뒤에는 보내면 안 된다. 양쪽 모두 rate limit을 두는 것이 바람직하다 (SHOULD).

취소 [사양](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation):

```json
{
  "jsonrpc": "2.0",
  "method": "notifications/cancelled",
  "params": {
    "requestId": "123",
    "reason": "User requested cancellation"
  }
}
```

- 수신자는 처리를 멈추고 자원을 풀며 응답을 보내지 않는 것이 바람직하다 (SHOULD). 이미 끝났으면 무시해도 된다. 경쟁 상태를 처리해야 한다.
- **MCP Tasks**: 2026-07-28에서 확장 `io.modelcontextprotocol/tasks`가 생겼다. `tools/call`이 `CreateTaskResult`(`resultType: "task"`)를 돌려주고, 클라이언트가 `tasks/get`으로 폴링하며, 입력은 `tasks/update`, 취소는 `tasks/cancel`로 한다 [사양](https://modelcontextprotocol.io/specification/2026-07-28/basic/utilities/tasks).
  - **세 클라이언트 모두 공식 문서에서 이 확장의 지원을 찾지 못했다** (미확인).
  - 따라서 서버 자체 job/poll 도구로 구현한다 (§6.3).

Python SDK 2.3 (프로젝트 `.venv`):

```python
# mcp/server/mcpserver/context.py
async def report_progress(self, progress: float, total: float | None = None, message: str | None = None) -> None
```

- `mcp/server/session.py`의 `ServerSession.report_progress` docstring: "A no-op when the caller did not request progress." 즉 클라이언트가 progressToken을 보내지 않으면 조용히 버려진다.
- elicitation: `await ctx.elicit(message, schema)` (Pydantic 모델, 원시 타입 필드), `await ctx.elicit_url(message, url, elicitation_id)`.

### 6.2 클라이언트별 장시간 호출 동작

| | Claude Code | Codex CLI | Cursor |
|---|---|---|---|
| 총 시간 제한 | `MCP_TOOL_TIMEOUT`(기본 약 28시간) 또는 서버별 `timeout` | `tool_timeout_sec` (문서 60 s, 소스 300 s) | 문서 없음. 포럼: IDE 약 60분, ACP 60 s, HTTP 약 300 s |
| idle 제한 | stdio 30분, 응답이나 progress가 오면 리셋 | 없음 | (미확인) |
| progress가 총 시간 제한을 연장하나 | 아니오 | 아니오 [소스] | ACP 아니오 [포럼] |
| progressToken 전송 | 문서에 "progressToken을 보낸다"는 직접 문장은 없다. 다만 progress로 idle을 리셋하고 `/tasks`에 표시하므로 보낸다고 해석된다 (추론) | 예 (rmcp가 자동) [소스] | (미확인) |
| 2분 넘는 호출 | 메인 대화에서는 자동 백그라운드 (subagent와 `-p` 제외) | 자동 백그라운드가 문서화되지 않음 (블로킹으로 가정) | 문서화되지 않음 (블로킹으로 가정, 미확인) |
| 사용자 중지 | `/tasks`에서 stop. 서버 중단은 보장되지 않음 | (미확인) | HTTP 경로에서 취소가 fetch를 끊지 않는다는 보고 [포럼] |

### 6.3 권장 패턴: job/poll (모든 클라이언트 공통)

`src/pweh/jobs.py`와 `mcpkit.register_job_tools`의 설계를 기준으로 한다.

1. **시작 도구는 즉시 반환한다.** 예: `{"ok": true, "job_id": "...", "status": "queued"}`. 위험 작업이면 승인 게이트를 **job 시작 전에** 통과시키고, 실행 중에는 승인을 요구하지 않는다.
2. **상태 조회는 롱폴로 한다.** `<prefix>_job_status(job_id, wait_seconds)`의 `wait_seconds` 상한은 **50초**를 유지한다. Codex 문서 기본값 60초와 Cursor ACP 60초 안에 들어가는 값이다.
   - 응답 필드: `status`(`queued`/`running`/`cancelling`/`succeeded`/`failed`/`cancelled`), `progress`(0~1), `eta_seconds`, `message`, `log_tail`.
3. **취소는 별도 도구로 한다** (`<prefix>_job_cancel`). 클라이언트의 취소(`notifications/cancelled`, Claude `/tasks` stop)는 "대기 중인 status 호출"만 끊는다고 가정한다.
4. **상태를 디스크에 남긴다** (`jobs/<job_id>.json`). Claude Code는 서버를 SIGINT부터 최대 0.5초 안에 강제 종료하고 stdio를 자동 재연결하지 않는다. 재시작 뒤에도 흔적이 남아야 한다.
5. **결과는 파일로 넘긴다.** 덤프 이미지나 긴 로그는 케이스 디렉터리에 저장하고 경로, 크기, 해시, 요약만 반환한다.
   - Claude는 25,000 토큰 또는 50,000자를 넘는 결과를 파일로 빼고 경고를 띄운다.
   - Codex는 `output_token_limit`으로 잘라낸다.
6. job 진행 중에도 `report_progress`를 보낸다. Claude의 idle 리셋과 `/tasks` 표시에 도움이 된다. 다만 **어떤 클라이언트에서도 이것으로 총 시간 제한을 늘릴 수 없다.**

### 6.4 작업별 설정 권장값 (pweh 제안)

| 작업 | 패턴 | Claude Code | Codex | Cursor |
|---|---|---|---|---|
| Ghidra 콜드 스타트 (REA, 외부 서버) | REA 도구가 동기 호출이면 넉넉한 타임아웃. 가능하면 REA의 비동기 기능 사용 (REA 동작은 미확인) | 서버별 `"timeout": 1800000`. 서버 시작이 느리면 `MCP_TIMEOUT=120000` | `startup_timeout_sec = 120`, `tool_timeout_sec = 1800` | 설정 불가. 60초를 넘는 동기 호출은 피한다 |
| UART `md.b` 플래시 덤프 (수 시간) | **반드시 job/poll** | 기본값으로 충분 (status 롱폴 ≤ 50 s) | `tool_timeout_sec = 120` | 롱폴 ≤ 50 s |
| sigrok 장시간 캡처 | job/poll | 위와 같음 | 위와 같음 | 위와 같음 |
| JTAGulator 핀아웃 스캔 (수 분) | job/poll | 위와 같음 | 위와 같음 | 위와 같음 |
| fwtriage 오프라인 분석 (수십 초~수 분) | 60초를 넘을 수 있으면 job/poll | `"timeout": 1800000` (안전마진) | `tool_timeout_sec = 900` | 롱폴 |

---

## 7. 안전: 클라이언트 프롬프트는 안전 경계가 아니다

| 클라이언트의 "전부 허용" 상태 | MCP 도구 프롬프트 | Elicitation |
|---|---|---|
| Claude `bypassPermissions` / `--dangerously-skip-permissions` | allow 규칙은 의미가 없고 대부분 묻지 않는다. 그래도 **deny 규칙은 차단하고, ask 규칙과 `requiresUserInteraction`은 여전히 묻는다** [문서] | 자동 수락한다는 서술은 없다 (미확인) |
| Claude `-p` (비대화형) | 묻는 호출은 거부된다. `.mcp.json` 서버는 **승인 없이 로드된다** | `--permission-prompts none`이면 취소 |
| Codex `-a never` + full access, `--dangerously-bypass-approvals-and-sandbox` | **자동 승인** [소스] | **빈 스키마 form은 자동 Accept**, 그 외는 decline [소스] |
| Codex 도구 `approval_mode = "approve"` | 자동 승인 | — |
| Cursor Run Everything / CLI `--force` (`--yolo`) | 모든 도구 호출 자동 실행 [문서] | (미확인) |

**결론**:

1. 세 클라이언트 모두에서 유지되는 유일한 통제는 **서버 측 안전 게이트**다. 대역 외에서 사람이 `pweh approve <id>`를 실행해야 통과한다 (`src/pweh/mcpkit.py`의 `SAFETY_NOTICE`, `gate_response`).
2. 클라이언트 쪽 장치는 보조로만 쓴다:
   - Claude: `ask` 규칙, 선택적으로 `anthropic/requiresUserInteraction`.
   - Codex: `default_tools_approval_mode = "prompt"`.
   - Cursor: Allowlist 모드.
3. 빈 스키마 elicitation을 확인 수단으로 쓰지 않는다 (§3.6).
4. annotation(`ANN_DEVICE`/`ANN_DESTRUCTIVE`)은 Codex `auto` 모드에서 프롬프트를 유발하는 효과가 있다. 그래도 annotation 자체는 "hint"이며 차단 수단이 아니다.

---

## 8. 미확인 항목 요약

- Claude Code
  - `.mcp.json`의 `cwd` 키 (문서에 없음). spawn cwd가 프로젝트 루트라는 것은 health check 경로에서만 실측했다.
  - `.claude/skills` 디렉터리 자체를 symlink로 만들 때의 동작.
  - `-p`에서 `--permission-prompts none` 없이 elicitation을 받으면 어떻게 되는가. `bypassPermissions`가 elicitation에 미치는 영향.
  - tool annotations를 권한에 쓰는가 (문서화되지 않음, 표시만 확인).
  - 문서에 "progressToken을 보낸다"는 직접 문장이 없다.
- Codex
  - 공식 문서의 타임아웃 기본값(10 s/60 s)과 소스(30 s/300 s)가 불일치한다.
  - MCP 설정의 `${VAR}` 치환 지원 여부.
  - 프로젝트 config에서 상대 `command`/`cwd`를 무엇 기준으로 해석하는가.
  - skill 인자 치환. 모르는 frontmatter 키를 무시하는가.
  - 초기 프롬프트에서 `$skill` 언급이 동작하는가.
  - elicitation TUI 표시 형태. `/import`가 가져오는 항목의 범위.
  - 문서("read annotation 우선")와 소스(destructive 먼저 검사)가 불일치한다.
- Cursor
  - MCP 타임아웃 값 (포럼에만 있음).
  - progressToken 전송 여부. 부모 환경변수 상속 여부.
  - IDE에서 프로젝트 MCP 서버 승인 UX.
  - tool annotations 사용 여부. elicitation UI.
  - skill symlink 추적. `.agents`/`.claude` 중복 skill 처리.
  - `.cursor/commands` 현행 지원. `CLAUDE.md`의 `@AGENTS.md` import 해석.
- 공통: MCP Tasks 확장(2026-07-28)의 클라이언트 지원.

---

## 9. 출처

### Claude Code (공식 문서, Markdown 원문)

- MCP: https://code.claude.com/docs/en/mcp (원문 https://code.claude.com/docs/en/mcp.md)
- 환경변수: https://code.claude.com/docs/en/env-vars
- 설정 키: https://code.claude.com/docs/en/settings-reference
- 권한: https://code.claude.com/docs/en/permissions
- 권한 모드: https://code.claude.com/docs/en/permission-modes
- Skills: https://code.claude.com/docs/en/skills
- Hooks (Elicitation): https://code.claude.com/docs/en/hooks
- Headless: https://code.claude.com/docs/en/headless
- CLI: https://code.claude.com/docs/en/cli-reference
- 메모리 / AGENTS.md: https://code.claude.com/docs/en/memory
- Subagents: https://code.claude.com/docs/en/sub-agents
- 체인지로그: https://code.claude.com/docs/en/changelog (GitHub `anthropics/claude-code` CHANGELOG.md 기반)

### Codex (공식 문서. `developers.openai.com/codex/*`는 `learn.chatgpt.com/docs/*`로 308 리다이렉트)

- MCP: https://learn.chatgpt.com/docs/extend/mcp.md
- 설정 레퍼런스: https://learn.chatgpt.com/docs/config-file/config-reference.md
- 설정 기본: https://learn.chatgpt.com/docs/config-file/config-basic.md
- 고급 설정: https://learn.chatgpt.com/docs/config-file/config-advanced.md
- 설정 샘플: https://learn.chatgpt.com/docs/config-file/config-sample.md
- Skills: https://learn.chatgpt.com/docs/build-skills.md
- Custom prompts: https://learn.chatgpt.com/docs/custom-prompts.md
- AGENTS.md: https://learn.chatgpt.com/docs/agent-configuration/agents-md.md
- 승인과 보안: https://learn.chatgpt.com/docs/agent-approvals-security.md
- CLI 명령: https://learn.chatgpt.com/docs/developer-commands.md?surface=cli

### Codex 소스 (태그 `rust-v0.162.0`)

- 기본 타임아웃: https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/codex-mcp/src/rmcp_client.rs#L106-L107
- 타임아웃 구현과 오류 형식: https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/rmcp-client/src/rmcp_client.rs
- progress 로깅: https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/rmcp-client/src/logging_client_handler.rs
- 승인 판정: https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/core/src/mcp_tool_call.rs#L2461-L2492
- 자동 승인 조건: https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/codex-mcp/src/mcp/mod.rs#L91-L110
- Elicitation 정책: https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/codex-mcp/src/elicitation.rs
- 승인 모드 enum: https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/config/src/mcp_types.rs#L28-L34
- 환경변수 화이트리스트: https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/rmcp-client/src/utils.rs#L163-L175
- Skill 위치: https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/ext/skills/src/host_roots.rs#L85-L120
- `codex mcp` 명령: https://github.com/openai/codex/blob/rust-v0.162.0/codex-rs/cli/src/mcp_cmd.rs
- 과거 기본값: https://github.com/openai/codex/blob/rust-v0.100.0/codex-rs/core/src/mcp_connection_manager.rs#L86-L89 , https://github.com/openai/codex/blob/rust-v0.130.0/codex-rs/codex-mcp/src/rmcp_client.rs#L77-L78
- rmcp 자동 progressToken: https://github.com/modelcontextprotocol/rust-sdk/blob/3e636cab26c013eca5131103c03d20237f12c4df/crates/rmcp/src/service.rs#L881-L893

### Cursor (공식 문서)

- MCP: https://cursor.com/docs/mcp.md
- Rules: https://cursor.com/docs/rules.md
- Skills: https://cursor.com/docs/skills.md
- Run Modes: https://cursor.com/docs/agent/security/run-modes.md
- CLI 권한: https://cursor.com/docs/cli/reference/permissions.md
- CLI 설정: https://cursor.com/docs/cli/reference/configuration.md
- CLI 파라미터: https://cursor.com/docs/cli/reference/parameters.md
- CLI 사용법: https://cursor.com/docs/cli/using.md
- 2.4 체인지로그: https://cursor.com/changelog/2-4

### Cursor 포럼 (미확인 정보)

- https://forum.cursor.com/t/agent-acp-mcp-tools-call-times-out-at-60s-with-no-way-to-configure-it/163925
- https://forum.cursor.com/t/remote-mcp-calls-fail-after-300s-with-und-err-headers-timeout-and-cancellation-does-not-abort-the-underlying-fetch/166437
- https://forum.cursor.com/t/mcp-timeout-happens-even-when-sending-back-updates-via-progress-token/145697

### MCP 사양

- progress: https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/progress
- cancellation: https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation
- tasks (2026-07-28): https://modelcontextprotocol.io/specification/2026-07-28/basic/utilities/tasks
- schema (ToolAnnotations 기본값): https://modelcontextprotocol.io/specification/2025-11-25/schema

### 로컬 실측 (2026-10-18)

- Claude Code 2.1.302: `claude mcp add/add-json/list/get`, probe 서버를 이용한 health check spawn 관찰. 격리된 `CLAUDE_CONFIG_DIR`을 썼다.
- Codex CLI 0.162.0: `codex mcp add/list/get`. 격리된 `CODEX_HOME`을 썼다.
- 두 경우 모두 모델은 호출하지 않았다.
