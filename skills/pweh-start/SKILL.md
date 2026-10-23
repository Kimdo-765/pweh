---
name: pweh-start
description: Start an authorized PWEH case. Phase 0 selects security analysis (UART, flash dump, firmware static analysis, CCTV auth hunt), game save/unlock analysis, SD card evidence forensics, or RF/hardware work using available tools. Optional ESP32/AVR firmware emulation and still-image hints with OCR/QR and model vision. Hardware ownership or written authorization is required. 사용자가 /pweh-start 로 명시적으로 호출할 때만 실행.
disable-model-invocation: true
---

# PWEH 파이프라인 시작

이 Skill 은 파이프라인의 진입점이다. 실제 지침은 저장소의 `orchestrator/master-prompt.md` 에 있다.

1. `orchestrator/master-prompt.md` 를 **처음부터 끝까지** 읽고, 그 규칙(특히 §1 절대 규칙)을 이번 세션 내내 따른다.
2. 사용자 메시지(Claude Code 에서는 본문 끝의 `ARGUMENTS:` 줄)에 있는 기기 설명과 목표를 Phase 0 접수(master-prompt §3)의 출발점으로 쓴다.
   비어 있으면 목표와 기기 정보부터 묻는다. 목표는 넷이다: **보안 분석**(기본 — CCTV/IoT 기기, ESP32 보드) / 게임 콘솔 분석 / RF·하드웨어 분석 / SD 카드 포렌식.
   게임 콘솔 분석은 세이브·해금 분석과 사용자가 원한 세이브 값 변경(사람이 쓴다), 공급 숫자 관측값 검증까지 일부 지원한다(NFC·플레이 자동화는 아직).
   SD 카드 포렌식은 `sd-card-forensics` 로 카드 이미지 증거 분석(접수·해시·보관 기록, 파일 목록·삭제 파일 추출, 증거 목록)과 펌웨어의 SD 공격 표면까지 일부 지원한다(선택 BMFF 구조·저장된 후보 prefix 추출 지원, 녹화 내용 해석·녹화 타임라인·원시 카드 전체 카빙은 아직).
   RF·하드웨어 분석은 `flipper-rf-analysis`로 보유 RAW 파일의 구조·통계를 일부 지원한다. 장치 연결·수신·해독·송신은 준비 중이다. 보안 분석이 아닌 목표는 지금 있는 Skill·도구로 할 수 있는 일(master-prompt §3.1)만 한다는 것을 먼저 알린다.
   확보한 ESP32·S3·C3/Arduino AVR 펌웨어를 PC 에서 실행할 때는 선택 단계 `firmware-emulation` 을 쓴다(USB 콘솔·무선·대부분의 주변장치 미지원).
3. 진행 전에 필요한 MCP 서버가 연결되어 있는지 확인한다.
   - 보안 분석: `pweh-case`, `pweh-uart`, `pweh-fwtriage`, `rea` (선택: `pweh-sigrok`, `pweh-openocd`, `pweh-jtagulator`, ESP32 계열이면 `pweh-esp`).
   - 게임 콘솔 분석: 공급 숫자만 검증하면 `pweh-case`·`pweh-play`와 `numeric-observation-analysis`를 쓴다. 장비·환경 조회·펌웨어 확보를 요구하지 않는다. 세이브·해금 분석이면 `pweh-case`, `pweh-fwtriage`, `rea` (ESP32 기반이면 `pweh-esp`, 리눅스·MCU 기기면 보안 분석의 서버).
   - SD 카드 포렌식: `pweh-case`, `pweh-forensics` (펌웨어 쪽 SD 공격 표면도 보면 `pweh-fwtriage`·`rea`, 시험 카드 부팅 로그는 `pweh-uart`).
   - 정지 이미지 힌트(선택): `pweh-case`, 증거면 `pweh-forensics`. `image-hints-analysis`를 쓰며 영상·음성은 처리하지 않는다.
   - 펌웨어 에뮬레이션(선택): `pweh-case`, `pweh-emu`. 콘솔은 `emu_read` 로만 보며 `emu/` 세션 파일은 열지 않는다.
   - RF·하드웨어: RAW 파일 분석이면 `pweh-case`·`pweh-sdr`. 파일만 분석할 때 장비·환경 조회·펌웨어 확보는 요구하지 않는다. 보드 작업은 §3.1의 서버를 쓴다.
   Codex 에서는 도구 이름이 `mcp__pweh_<서버>__<도구>` 다(예: `mcp__pweh_case__case_create`, REA 는 `mcp__rea__<도구>`).
   도구 목록에 보이지 않아도 지연 로딩되었을 수 있으니, 없다고 판단하기 전에 `ALL_TOOLS` 에서 이름이 `mcp__pweh_`(REA 는 `mcp__rea__`)로 시작하는 항목을 찾는다.
   그래도 도구가 보이지 않으면 사용자에게 `docs/mcp-setup.md` 의 절차를 안내한다.
   예: Claude Code 에서 `/mcp` 로 서버 승인 확인, `.venv` 설치, `~/pweh-tools/env.sh`.
   Codex 에서는 사용자가 `pweh mcp-check --client codex`, 프로젝트 trust(`pweh codex-trust --check`), 쓰는 Codex 홈(CLI 와 데스크톱 앱은 홈이 다르다 — mcp-setup §3)을 확인하게 한다.
4. **기기 소유 또는 서면 허가를 사용자에게 확인받기 전에는** 어떤 하드웨어 도구도 호출하지 않는다. SD 카드 이미지도 소유·허가를 먼저 확인하고 케이스를 만든 뒤에 접수한다(`forensics_intake_start` — `case_import_file` 로 가져오지 않는다).
5. 이후 각 단계는 master-prompt 의 결정 트리(§4)와 §3.1 에 따라 다음 Skill 을 사용한다:
   `uart-shell-acquisition`, `logic-analyzer-protocol-decode`, `firmware-dump-via-uart`, `esp32-flash-dump`(ESP32 계열 MCU), `firmware-static-analysis`, `cctv-auth-bypass-hunt`,
   `game-save-unlock-analysis`(게임 콘솔 — 세이브·해금 오프라인 분석), `sd-card-forensics`(SD 카드 — 카드 이미지 증거 분석·펌웨어 SD 공격 표면 요약).
   `firmware-emulation`(확보한 MCU 펌웨어의 로컬 실행과 마스킹 콘솔), `image-hints-analysis`(정지 그림·OCR·QR·메타데이터와 시각 단서).
   Windows OpenOCD는 고정 dummy 진단과 `tigard-jtag-v1`의 어댑터 초기화·제한 조회만 지원한다. Tigard 실기 사용은 모델·소유/허가·배선·전압 확인 뒤 master-prompt §4와 `docs/references/windows-openocd-tigard.md`를 따른다. 타깃·메모리·덤프에는 기본 Linux 경로를 쓴다.
   `flipper-rf-analysis`는 케이스에 등록한 Flipper RAW 파일 검사와 `rf-analysis` 요약을 남긴다.
   `numeric-observation-analysis`는 공급 숫자의 합의와 `numeric-analysis` 요약을 남긴다. 게임 분석 완료에는 실제 수행한 경로의 요약만 요구하며 화면 신선도·게임 의미·버튼 동작을 확인했다고 보고하지 않는다. 없는 Skill 이름을 지어 쓰지 않는다.
