---
name: pweh-start
description: Start the PWEH hardware-analysis pipeline (UART console → firmware dump → REA/Ghidra static analysis → CCTV auth-bypass hunt → report) for a CCTV/IoT device the operator owns or is authorized in writing to test. 사용자가 /pweh-start 로 명시적으로 호출할 때만 실행.
disable-model-invocation: true
---

# PWEH 파이프라인 시작

이 Skill 은 파이프라인의 진입점이다. 실제 지침은 저장소의 `orchestrator/master-prompt.md` 에 있다.

1. `orchestrator/master-prompt.md` 를 **처음부터 끝까지** 읽고, 그 규칙(특히 §1 절대 규칙)을 이번 세션 내내 따른다.
2. 사용자 메시지(Claude Code 에서는 본문 끝의 `ARGUMENTS:` 줄)에 있는 기기 설명을 Phase 0 접수의 출발점으로 쓴다.
   비어 있으면 기기 정보부터 묻는다.
3. 진행 전에 필요한 MCP 서버가 연결되어 있는지 확인한다: `pweh-case`, `pweh-uart`, `pweh-fwtriage`, `rea`
   (선택: `pweh-sigrok`, `pweh-openocd`, `pweh-jtagulator`, ESP32 계열이면 `pweh-esp`). 도구가 보이지 않으면 사용자에게 `docs/mcp-setup.md` 의 절차를 안내한다.
   예: Claude Code 에서 `/mcp` 로 서버 승인 확인, `.venv` 설치, `~/pweh-tools/env.sh`.
4. **기기 소유 또는 서면 허가를 사용자에게 확인받기 전에는** 어떤 하드웨어 도구도 호출하지 않는다.
5. 이후 각 단계는 master-prompt 의 결정 트리에 따라 다음 Skill 을 사용한다:
   `uart-shell-acquisition`, `logic-analyzer-protocol-decode`, `firmware-dump-via-uart`, `esp32-flash-dump`(ESP32 계열 MCU), `firmware-static-analysis`, `cctv-auth-bypass-hunt`.
