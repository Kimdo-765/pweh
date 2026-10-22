# PWEH — Play With Every Hardware

**에이전트 주도 임베디드 기기 하드웨어 분석 파이프라인** (CCTV / IP 카메라 / DVR·NVR / IoT)

사람은 배선·프로브·전원 같은 **물리 작업**만 한다. AI 에이전트(Claude Code / Codex / Cursor)는 MCP 서버와 Skill 을 통해
UART 콘솔, 로직 애널라이저, JTAG, ESP32 esptool 덤프, 펌웨어 분석(REA + Ghidra), MCU 펌웨어 에뮬레이션, 정지 이미지 힌트, SD 카드 이미지 증거 분석을 주도한다. 결과는 증거가 달린 구조화된 보고서로 남는다.

> ⚠️ **소유한 기기 또는 서면 허가를 받은 기기만** 분석한다. 모든 하드웨어 도구는 케이스에 소유/허가 증명이 있어야 동작한다.
> 플래시 쓰기·삭제, `saveenv`, 전압 인가 같은 위험 작업은 서버 측 안전 게이트가 기본으로 거부한다.
> 허용하더라도 사람이 에이전트 밖에서 승인해야 한다. 분석 결과는 연구·방어 목적으로만 쓴다. → [안전 가이드](docs/safety.md)

## 구조

```
[사람]  배선 · 프로브 · 전원 재투입 · SD 카드 이미징(쓰기 방지 장치) · 위험 작업 승인 (pweh approve) · 사람 증명 (pweh attest)
   │
[에이전트]  orchestrator/master-prompt.md  +  skills/*/SKILL.md
   │
   ├─ pweh-case        케이스 · 단계 결과 · 발견사항 · 보고서 · 프로필 · 승인 상태
   ├─ pweh-uart        UART: 포트/세션, U-Boot 진입, Linux 셸, md.b/dd 덤프(job, crc32/md5 검증, 재개)
   ├─ pweh-sigrok      로직 애널라이저: 스캔, 캡처, 디코딩, 보드레이트 추정
   ├─ pweh-openocd     OpenOCD: 스캔체인, 레지스터/메모리, 플래시 읽기(job)
   ├─ pweh-jtagulator  JTAGulator: JTAG/UART 핀아웃 스캔 (선택)
   ├─ pweh-fwtriage    오프라인 트리아지: 시그니처, 엔트로피, U-Boot env, mtdparts 분할, rootfs 감사, 문자열 휴리스틱
   ├─ pweh-esp         ESP32: esptool 칩·보안 정보, 플래시 덤프(job, 두 번 읽어 sha256 비교). WSL 에서는 Windows esptool.exe + COM 포트 (선택)
   ├─ pweh-forensics   SD 카드 이미지 증거 분석: 접수·해시·보관 기록, 파티션·FAT/exFAT 목록, 삭제 파일 추출(job), 증거 목록 — 기기·카드를 열지 않음 (선택)
   ├─ pweh-espprobe    HELLO·HB 오프라인 시뮬레이터, 실제 포트·핀 미지원 (I5 1a)
   ├─ pweh-emu         ESP32·S3·C3/Arduino AVR 펌웨어 실행, 출처 확인·마스킹 콘솔·세션 종료 — 기기 미접촉 (선택)
   └─ rea              REA(rea-agents): binwalk/unblob 추출, Ghidra 디컴파일, 참조 추적, 신호 디코딩
            │
      [대상 기기]  (또는 pweh-mock-device 시뮬레이터. pweh-forensics 는 사람이 만든 카드 이미지 파일만 받는다)
```

공통 코어(`src/pweh/`)는 모든 서버가 쓰는 계약을 구현한다.
- **케이스 작업공간**: Skill 사이의 데이터 전달.
- **JSON 스키마**: 단계 결과·발견사항 검증.
- **안전 게이트**: 명령 위험도 분류, 정책, 사람 승인. 게이트 밖의 공통 안전 기능으로 사람 증명(attestation), 출처 원장(provenance), 비밀값 마스킹.
- **백그라운드 job**: 장시간 작업.
- **보고서 생성기**.
- **SD 카드 증거**: 카드 이미지 파일 시스템 엔진(`pweh.fs` — MBR/GPT·FAT/exFAT 를 읽기 전용으로 해석하는 순수 파이썬)과 보관 기록·증거 목록(`pweh.evidence` — 해시 체인 + 보호 위치의 고정점).

자세한 계약은 [docs/architecture.md](docs/architecture.md) 에 있다.

## 파이프라인

| 단계 | Skill | 하는 일 | 산출물 (cases/<id>/) |
|---|---|---|---|
| 0 | `pweh-start` | 접수: **목표 선택**(보안 분석 / 게임 콘솔 분석·SD 카드 포렌식은 일부 지원 / RF·하드웨어는 준비 중), 기기 정보, **소유/허가 확인**, 장비 확인, 프로필 선택, 케이스 생성 | `case.json` |
| A | `uart-shell-acquisition` | 포트 탐색, 보드레이트 탐지, 부팅 로그, U-Boot 인터럽트, 셸 획득, 기본 정보 수집 | `uart/*.log`, `steps/*` |
| A′ | `logic-analyzer-protocol-decode` | 핀/보드레이트 모를 때 캡처·디코딩, SPI/I2C 관찰 | `signals/*` |
| B | `firmware-dump-via-uart` | U-Boot `sf read`+`md.b`(+crc32) 또는 셸 `dd`(+md5) 덤프, 재개 가능 | `dumps/*.bin` + 메타데이터 |
| B′ | `esp32-flash-dump` | ESP32 계열 보드: esptool 로 칩·보안 정보 확인 → 플래시를 두 번 읽어 sha256 비교(WSL 에서는 Windows esptool.exe + COM 포트). 요약은 firmware-dump 형식 | `dumps/*.bin`, `*.read2.bin` + 메타데이터 |
| C | `firmware-static-analysis` | fwtriage 1차 분석 → REA 추출/Ghidra 디컴파일 → 인증·하드코딩·백도어 후보 | `extract/`, `analysis/`, `findings.json` |
| C+ | `firmware-emulation` (선택) | 확보한 ESP32·S3·C3 전체 플래시 또는 Arduino AVR HEX/raw 를 PC 에서 실행, 마스킹 콘솔 확인. USB 콘솔·무선 미지원 | `emu/<session>/`, `steps/*` |
| D | `cctv-auth-bypass-hunt` | Hikvision/Dahua/XiongMai 스타일 공개 취약점 패턴 중심 집중 탐색 | `findings.json` |
| E | — | `report_generate` | `report.md` |

각 Skill 은 끝날 때 스키마에 맞는 `summary` 를 케이스에 저장한다 (`schemas/*.schema.json`).
다음 Skill 은 그 요약을 읽어서 이어서 진행한다. 세션이 끊겨도 케이스만 있으면 이어서 할 수 있다.

보안 분석이 아닌 목표는 일부만 지원한다(`orchestrator/master-prompt.md` §3·§3.1).
- **게임 콘솔 분석** — `game-save-unlock-analysis`: 세이브·해금 오프라인 분석과 사용자가 원한 세이브 값 변경(기기에는 사람이 쓴다). ESP32 기기는 `esp32-flash-dump` 로 먼저 덤프한다.
- **SD 카드 포렌식** — `sd-card-forensics`: 사람이 하드웨어 쓰기 방지 장치를 거쳐 만든 카드 이미지를 pweh-forensics 로 접수하고(해시·보관 기록·쓰기 방지 장치 사람 증명),
  파티션·FAT/exFAT 파일 목록·시각·호스트 오염 흔적, 필요한 파일만 삭제 파일까지 추출, 해시값 확인서가 붙은 증거 목록을 만든다. 영상·음성 내용은 열지 않는다. 정지 그림의 미리보기·OCR·QR은 `image-hints-analysis`로 분석한다.
  카메라 펌웨어가 SD 카드를 다루는 방식(SD-01~09)은 `firmware-static-analysis` 4b 단계에서 본다. 기존 펌웨어 보고서와 카드 목록은 `forensics_sd_ioc_scan`으로 이름 후보·검사 한계를 대조한다(실행·침해 증명 아님). 선택 파일의 BMFF 상자 구조는 `forensics_media_inventory`로 관찰한다(영상/음성 해독 없음). 카빙·녹화 인덱스·녹화 타임라인·ext4 는 아직 없다.
  알려진 한계(잘린 이미지·손상된 카드, 같은 계정 프로세스의 경합 창 등)는 [안전 가이드](docs/safety.md) §3.6 에 있다.
- **RF·하드웨어 분석** — 준비 중. 지금은 기존 Skill 로 보드 단위 콘솔·신호·덤프만 한다.

MCU 에뮬레이션은 확보한 펌웨어로 부팅 로그·UART 응답을 보는 선택 단계다. `firmware-emulation` Skill 이 출처를 확인하고 `emu_read` 로 마스킹한 콘솔을 읽은 뒤 `emu_stop` 으로 끝낸다.
가져온 파일의 출처는 사람이 증명한다. Wi-Fi·Bluetooth·USB 콘솔·대부분의 주변장치가 없어 앱이 조용하거나 멈출 수 있다. 지원 범위와 격리·마스킹 한계는 [설계](docs/design/emulation.md)와 [안전 가이드](docs/safety.md) §3.7 에 있다.

## 빠른 시작

```bash
# 1. 원클릭 설치 (sudo 없음): Python 가상환경 + 외부 도구(~/pweh-tools) + REA
#    → MCP 등록(Claude Code 확인, Codex 프로젝트 설정 + trust) → Skill 링크 → 점검(`pweh doctor`, `pweh mcp-check`)
git clone https://github.com/Kimdo-765/pweh.git ~/pweh && cd ~/pweh
./scripts/install.sh              # 처음엔 Ghidra·JDK 등 약 1 GB 를 내려받는다(설치 후 디스크 약 3~4 GB). 다시 실행하면 설치된 것은 건너뛴다
#   ./scripts/install.sh --minimal   Python + sigrok + OpenOCD + squashfs/u-boot 도구만
#   ./scripts/install.sh --only esptool   ESP32 용 esptool 5.4.0 만 추가 (선택 구성요소. WSL interop 이면 Windows esptool.exe 도)
#   ./scripts/install.sh --only winserial   WSL UART·JTAGulator COM helper 추가 (사전 빌드 검증·복사, 포트 열지 않음)
#   ./scripts/install.sh --only qemu_esp,simavr   MCU 펌웨어 에뮬레이션 백엔드 추가 (선택, --minimal 제외)
#   ./scripts/install.sh --only mcp,verify   설치 없이 MCP 등록과 점검만 다시
#   ./scripts/install.sh --only mcp --dry-run   MCP 등록·trust 가 바꿀 파일과 diff 만 보기 (쓰지 않음)
#   ./scripts/install.sh --codex-trust   Codex trust 를 묻지 않고 추가 (--no-codex-trust 는 건너뛰기, --no-mcp 는 MCP 단계 전체를 건너뛰기)
#   ./scripts/install.sh --check     설치·MCP 설정 상태만 점검 / --list 구성요소 목록 / --help 옵션 전체
#   되돌리기·옵션 전체: docs/mcp-setup.md §1.1·§1.2

# 2. 셸에서 외부 도구 쓰기 (MCP 서버는 scripts/mcp-launch.sh 가 env.sh 를 자동으로 읽는다. Codex 설정의 PWEH 서버에는 env.sh 의 도구 경로가 들어간다)
. ~/pweh-tools/env.sh

# 3. 테스트 (하드웨어 없이, 시뮬레이터 사용. 외부 도구가 없으면 일부 skip)
.venv/bin/pytest -q
.venv/bin/pytest -q -m "not slow"     # 빠르게: 전체 플래시 덤프 e2e 같은 slow 테스트 제외
# (선택) 실제 에이전트(Claude Code 헤드리스)가 시뮬레이터 카메라를 끝까지 분석하는지 확인 — Claude 계정 사용량을 쓴다
.venv/bin/python scripts/run_agent_e2e.py --profile hikvision-like --out <결과 디렉터리>

# 4. 에이전트 연결 (1 의 MCP 등록·Skill 단계가 이미 한다. 따로 다시 할 때만)
.venv/bin/pweh mcp-config --client claude --write --force   # Claude Code: .mcp.json (이미 포함됨)
.venv/bin/pweh skills install --target claude-project       # .claude/skills 링크 (이미 포함됨. Codex·Cursor 는 --target agents)
.venv/bin/pweh mcp-config --client codex --write            # Codex: <저장소>/.codex/config.toml (이 저장소에서만 읽힘)
.venv/bin/pweh codex-trust                                  # Codex: Codex 홈마다 이 저장소를 trusted 로 (묻고, 백업 후 씀)
.venv/bin/pweh mcp-check --client all                       # 서버마다 시작·도구 목록 확인 (도구는 호출하지 않음)
claude                                                      # 프로젝트 MCP 서버 승인 → /mcp 로 확인
```

Claude Code 에서 시작:
```
/pweh-start 책상 위의 내 IP 카메라 (HiSilicon Hi3518 기반으로 보임). UART 패드 4개 확인, CP2102 어댑터 있음
```

Codex(WSL 의 Codex CLI, WSL 모드의 Codex 데스크톱 앱)는 `$pweh-start` 로 시작한다.
설정은 설치 스크립트가 만든다: 프로젝트 설정(`pweh mcp-config --client codex --write`)과 trust(`pweh codex-trust`). CLI 와 데스크톱 앱은 Codex 홈이 달라 trust 를 홈마다 더한다.
설정을 바꾼 뒤 데스크톱 앱은 다시 시작하거나 새 스레드를 연다. 자세한 내용과 문제 해결은 [MCP 설정 가이드](docs/mcp-setup.md) §3 에 있다.
Cursor 는 `/pweh-start` 로 시작한다(`.cursor/mcp.json` 은 `./scripts/install.sh --cursor`).

실제 에이전트가 `/pweh-start` 와 이런 짧은 기기 설명만으로 끝까지 가는지는 시뮬레이터로 확인했다. 결과는 [examples/README.md](examples/README.md#실제-에이전트-실행-기록-agent-run-) 에 있다.
`agent-run-hikvision` 과 `agent-run-dahua` 두 실행 모두 다음을 통과했다.
- 기준 C1–C7 전부
- 심어 둔 문제 8/8 을 발견사항으로 기록
- 덤프 sha256 이 플래시 이미지와 일치
- 파괴 이벤트 0
→ [MCP 설정 가이드](docs/mcp-setup.md)

### 하드웨어 없이 체험하기

```bash
.venv/bin/pweh-mock-device --profile hisilicon-like --pty
# {"pty": "/dev/pts/N", ...} → 에이전트에게 "이 포트가 내 카메라 UART" 라고 알려 주면 된다
# 시뮬레이터 표준입력에 power-cycle 을 입력하면 "전원 재투입"이 된다
```

## 위험 작업 승인 흐름

1. 에이전트가 위험 도구를 호출한다 → 서버가 `status: approval_required` 와 `approval_id` 를 돌려준다.
   클라이언트가 지원하면 elicitation 확인 폼이 대신 뜬다.
2. 사람이 **별도 터미널**에서 `.venv/bin/pweh approve <approval_id>` 를 실행하고, 내용 확인 후 확인 코드를 입력한다.
3. 에이전트가 같은 인자 + `approval_id` 로 재시도하면 **한 번만** 실행된다. 승인은 정확한 작업에 묶이고 만료된다.

기본 정책은 `destructive_policy: deny` 라서 위 흐름 자체가 일어나지 않는다. 사람이
`orchestrator/pipeline-config.yaml` 에서 `approve` 로 바꿔야만 가능하다.

### 사람 증명 (`pweh attest`)

에이전트가 확인할 수 없는 사실(콘솔 오프라인, 배선과 잰 전압, 가져온 파일의 출처 등)이 필요한 도구는 `status: attestation_required` 와 `attestation_id` 를 돌려준다
(지금은 `fw_patch_build` 의 쓰기 준비, `forensics_acquisition_attest` 의 쓰기 방지 장치 확인, `emu_start` 의 가져온 펌웨어 출처 확인에 쓴다 — RF·계측기 서버도 쓸 기반이다).
사람이 **별도 터미널**에서 `.venv/bin/pweh attest <attestation_id>` 를 실행해 항목마다 직접 답하고, 승인이 되는 답이면 화면의 확인 코드를 입력한다(대화형 터미널 전용).
클라이언트가 지원하면 같은 항목이 확인 폼으로 뜬다.
승인과 달리 한 번 쓰고 사라지지 않고, 대상·범위(케이스·연결·job·계측기)와 만료에 묶여 재사용된다. 목록은 `pweh attest --list`, 철회는 `pweh attest --revoke <id>` 다.
케이스 소유/허가 증명(`pweh case attest <case_id>`)과는 다른 명령이다.
출처 원장은 지금도 기록된다: pweh-esp 의 덤프·칩·보안 정보는 기기에서 읽은 것으로, `case_import_file` 로 가져온 파일과 pweh-forensics 가 접수한 카드 이미지의 접수 기록은 출처 미확인으로 남는다([안전 가이드](docs/safety.md) §3.5).
카드 이미지의 접수·검증·추출은 따로 SD 카드 보관 기록(`forensics/custody.jsonl`, 해시 체인 + 보호 위치의 고정점)에도 남는다.

## 디렉터리

```
pweh/
├── README.md, project.md(명세), AGENTS.md, CLAUDE.md
├── pyproject.toml                  하나의 패키지로 코어 + 9개 서버 설치
├── src/pweh/                       공통 코어 (config, case, safety, provenance, evidence, fs, jobs, mcpkit, report, cli, formats, espfmt, console, schemas, mocktarget)
├── mcp-servers/
│   ├── case-mcp/  uart-mcp/  openocd-mcp/  sigrok-mcp/  jtagulator-mcp/  fwtriage-mcp/  esp-mcp/  forensics-mcp/  emu-mcp/
├── native/emu/                     simavr 기반 AVR 실행기 (로컬 빌드)
├── skills/                         pweh-start + 9개 Skill (.claude/skills, .agents/skills 에 링크)
├── orchestrator/
│   ├── master-prompt.md            파이프라인 전체 지침 (이 하나로 시작)
│   └── pipeline-config.yaml        안전 정책, 도구 경로, 대상 기기 프로필
├── schemas/                        JSON Schema (→ src/pweh/schemas)
├── scripts/                        mcp-launch.sh(MCP 서버 런처, env.sh 자동 로드), dump_tool_catalog.py(도구 카탈로그·권한 검사),
│                                   run_example.py(스크립트 흐름 예제), run_agent_e2e.py(실제 에이전트 e2e, 옵트인)
├── examples/                       시뮬레이터 예제: 스크립트 흐름 2개 + 실제 Claude Code 에이전트 실행 기록 2개
├── docs/                           safety, hardware-setup, mcp-setup, architecture, references/
├── tests/                          pytest (core, servers, uart, fwtriage, fs, mocktarget, e2e) + mock-targets/
└── cases/                          실제 분석 케이스 (git 제외)
```

## 기존 공개 MCP 서버와의 관계

명세는 기존 공개 서버를 최대한 재사용하라고 한다. 조사 결과와 판단은 다음과 같다.
- **REA**: 그대로 재사용한다 (펌웨어 영역·추출·Ghidra·신호 디코딩).
- **UART** ([mcserial](https://git.supported.systems/rsp2k/mcserial), [es617/serial-mcp-server](https://www.remoteopenclaw.com/mcp/es617/serial-mcp-server),
  [AdolphNB/uart-mcp](https://github.com/AdolphNB/uart-mcp) 등): 범용 시리얼 도구라서 다음 기능이 없다. 그래서 새로 작성했다.
  - U-Boot 문맥 인식, 명령 위험도 게이트.
  - 검증·재개 가능한 md.b 덤프.
  - 케이스 기반 로그.
- **OpenOCD** ([mcjtag](https://pypi.org/project/mcjtag/), [microhenrio/openocd-mcp](https://glama.ai/mcp/servers/microhenrio/openocd-mcp)):
  mcjtag 는 Python 3.11+ 요구, 둘 다 위험 명령 게이트가 없다. 같은 안전 계층을 쓰는 얇은 TCL RPC 래퍼로 작성했다.
  필요하면 위 서버를 함께 등록해도 된다 (그 서버들의 동작은 PWEH 게이트 밖이다).
- **sigrok** ([kenosinc/sigrok-mcp-server](https://mcpservers.org/servers/kenosinc/sigrok-mcp-server), [mcp-sigrok](https://pypi.org/project/mcp-sigrok/)):
  디코딩은 REA 의 `decode_signal_recording` 과 겹친다. PWEH 서버는 REA 에 없는 기능에 집중한다.
  - 캡처(취득).
  - 출력 장치(전원공급기 등) 차단.
  - 순수 Python 보드레이트 추정.

## 문서
- [안전 가이드](docs/safety.md) — 법적 범위, 전기 안전, 게이트, 승인, 사람 증명·출처 원장·SD 카드 보관 기록, 위협 모델, SD 카드 증거의 알려진 한계, 비상 정지, 백업, 데이터 취급(SD 카드 이미지 포함)
- [하드웨어 셋업](docs/hardware-setup.md) — 장비, UART 패드 찾기, 배선, WSL usbipd, 로직 애널라이저, JTAG, SPI 클립, ESP32 보드(esptool 방법 A/B)
- [MCP 설정](docs/mcp-setup.md) — Claude Code / Codex / Cursor 등록, 권한 규칙, REA 연동, ESP32 esptool 방법 A, 타임아웃
- [아키텍처와 계약](docs/architecture.md) — 서버별 도구, 케이스 구조, 안전 모델, 코딩·테스트 규칙
- [MCP 도구 카탈로그](docs/references/pweh-mcp-tools.md) — 서버가 실제로 내보내는 도구·인자·annotation (`scripts/dump_tool_catalog.py` 로 자동 생성)
- [참고 자료](docs/references/) — U-Boot/부트 콘솔, OpenOCD TCL RPC, sigrok-cli, JTAGulator 프로토콜, CCTV 공개 취약점 패턴, 에이전트 클라이언트

## 라이선스
MIT (외부 도구와 REA 는 각자의 라이선스를 따른다).

정지 그림의 단서는 `image-hints-analysis` Skill로 분석한다. 일반 기판·기기 사진/스크린샷/펌웨어 그림은 `case_image_hints`, 증거 사진은 `forensics_image_hints`를 사용한다. EXIF/XMP·OCR(kor+eng)·QR/바코드·숨은 데이터 후보와 실제 미리보기의 시각 관찰을 근거별로 기록한다. 영상·음성은 지원하지 않는다. 설치·지원 범위는 [설계](docs/design/image-hints.md)에 있다.

### Android 펌웨어·논리 증거

Android 펌웨어의 형식·raw GPT/LP 배치·AN 정적 점검과, 사람이 만든 TAR/ZIP 또는 FAT/exFAT 증거의 선택 SQLite·SMS·통화·연락처·브라우저·타임라인을 분석한다. WAL/freelist는 근거와 신뢰도를 갖는 후보로 보고한다. [지원 범위](docs/design/android-analysis.md), [android-forensics Skill](skills/android-forensics/SKILL.md)을 참고한다. ext4/EROFS/F2FS 파일 목록 엔진·잠금/암호화 우회·실기기 획득·영상/음성 해독은 제공하지 않는다.

ESP 계측기 I5 1a의 오프라인 프로토콜 시험은 [pweh-espprobe](mcp-servers/espprobe-mcp/README.md)를 쓴다.
실제 보드 연결·플래시는 포함하지 않으며, 시뮬레이터 결과를 실기 검증으로 취급하지 않는다.
고정 툴체인으로 펌웨어를 재현 빌드하고 사전 빌드를 설치하는 절차는 [빌드 문서](docs/references/espprobe-build.md)에 있다.
