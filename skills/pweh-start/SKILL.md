---
name: pweh-start
description: Start a PWEH hardware-analysis case for a device the operator owns or is authorized in writing to test. Phase 0 intake first picks the goal - security analysis of a CCTV/IP camera/DVR/IoT/ESP32 device (UART console → firmware dump → REA/Ghidra static analysis → CCTV auth-bypass hunt → report), game console analysis (partly supported - offline save/unlock analysis with game-save-unlock-analysis - ESP partitions/app/NVS, save snapshot diff, checksum and cheat-input table search), or one of the goals still in preparation (RF/hardware, SD card forensics), which for now use only the existing Skills and tools (board-level console/signal/dump work, SD image import + hash check). 사용자가 /pweh-start 로 명시적으로 호출할 때만 실행.
disable-model-invocation: true
---

# PWEH 파이프라인 시작

이 Skill 은 파이프라인의 진입점이다. 실제 지침은 저장소의 `orchestrator/master-prompt.md` 에 있다.

1. `orchestrator/master-prompt.md` 를 **처음부터 끝까지** 읽고, 그 규칙(특히 §1 절대 규칙)을 이번 세션 내내 따른다.
2. 사용자 메시지(Claude Code 에서는 본문 끝의 `ARGUMENTS:` 줄)에 있는 기기 설명과 목표를 Phase 0 접수(master-prompt §3)의 출발점으로 쓴다.
   비어 있으면 목표와 기기 정보부터 묻는다. 목표는 넷이다: **보안 분석**(기본 — CCTV/IoT 기기, ESP32 보드) / 게임 콘솔 분석 / RF·하드웨어 분석 / SD 카드 포렌식.
   게임 콘솔 분석은 세이브·해금 오프라인 분석까지만 일부 지원하고, RF·하드웨어 분석과 SD 카드 포렌식은 준비 중이다. 보안 분석이 아닌 목표는 지금 있는 Skill·도구로 할 수 있는 일(master-prompt §3.1)만 한다는 것을 먼저 알린다.
3. 진행 전에 필요한 MCP 서버가 연결되어 있는지 확인한다.
   - 보안 분석: `pweh-case`, `pweh-uart`, `pweh-fwtriage`, `rea` (선택: `pweh-sigrok`, `pweh-openocd`, `pweh-jtagulator`, ESP32 계열이면 `pweh-esp`).
   - 게임 콘솔 분석: `pweh-case`, `pweh-fwtriage`, `rea` (ESP32 기반이면 `pweh-esp`, 리눅스·MCU 기기면 보안 분석의 서버).
   - 준비 중인 목표: `pweh-case` 와 §3.1 경로에 필요한 서버 (펌웨어·이미지 분석이면 `pweh-fwtriage`·`rea`, 보드 작업이면 보안 분석의 서버).
   도구가 보이지 않으면 사용자에게 `docs/mcp-setup.md` 의 절차를 안내한다.
   예: Claude Code 에서 `/mcp` 로 서버 승인 확인, `.venv` 설치, `~/pweh-tools/env.sh`.
4. **기기 소유 또는 서면 허가를 사용자에게 확인받기 전에는** 어떤 하드웨어 도구도 호출하지 않는다. SD 카드 이미지도 소유·허가를 먼저 확인하고 케이스를 만든 뒤에 가져온다.
5. 이후 각 단계는 master-prompt 의 결정 트리(§4)와 §3.1 에 따라 다음 Skill 을 사용한다:
   `uart-shell-acquisition`, `logic-analyzer-protocol-decode`, `firmware-dump-via-uart`, `esp32-flash-dump`(ESP32 계열 MCU), `firmware-static-analysis`, `cctv-auth-bypass-hunt`,
   `game-save-unlock-analysis`(게임 콘솔 — 세이브·해금 오프라인 분석). 준비 중인 목표(RF·SD)의 전용 Skill 은 아직 없다. 없는 Skill 이름을 지어 쓰지 않는다.
