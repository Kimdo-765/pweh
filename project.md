# Embedded Device Hardware Analysis Pipeline with Agent + MCP + Skills

## 1. Project Overview

### 목표
중국산 CCTV / 일반 IoT·임베디드 기기를 대상으로 하는 **에이전트 주도 하드웨어 분석 파이프라인**을 구축한다.  
물리적 조작은 최소화하고, 소프트웨어로 제어 가능한 인터페이스(UART, JTAG/SWD, Logic Analyzer, 펌웨어 분석)는 MCP와 Skill을 통해 AI 에이전트가 주도적으로 수행하도록 한다.

### 핵심 컨셉
- **하이브리드 자동화**: 사람 = 물리적 연결·프로브 배치 / 에이전트 = 도구 제어·분석·의사결정
- **MCP 중심 오케스트레이션**: 각 하드웨어/분석 도구를 MCP 서버로 노출하고 에이전트가 호출
- **Skill 기반 워크플로**: 반복되는 분석 패턴을 Skill로 패키징
- **REA 연동**: 펌웨어 추출 이후 정적 분석은 REA + Ghidra를 활용

### 대상 사용자
- 보안 연구자, 레드팀, 임베디드 보안 엔지니어
- 본인이 소유하거나 명시적 허가를 받은 기기만 대상으로 함

---

## 2. High-Level Architecture

```
[Human]
  ↓ 물리적 연결 (프로브, 전원, UART 케이블 등)
[Agent (Claude Code / Codex / Cursor 등)]
  ├── Skills (워크플로 패키지)
  └── MCP Servers
        ├── uart-mcp / serial-mcp          → UART 콘솔 제어
        ├── openocd-mcp / jlink-mcp        → 디버그 프로브
        ├── sigrok-mcp                     → 로직 애널라이저
        ├── rea-mcp                        → 펌웨어·바이너리 분석
        └── (optional) jtagulator-mcp      → 핀아웃 스캔
              ↓
        [Target Device]
```

---

## 3. Core Components to Implement

### 3.1 MCP Servers (우선순위)

| 우선순위 | MCP Server | 역할 | 비고 |
|---------|------------|------|------|
| 필수 | `uart-mcp` | UART 포트 열기/닫기, 명령 전송, 로그 수집, 패턴 대기, U-Boot 진입 | 기존 구현 참고 또는 신규 작성 |
| 필수 | `rea-mcp` | 펌웨어 영역 식별, 추출, Ghidra 연동 분석 | 기존 REA 활용 |
| 권장 | `sigrok-mcp` | 로직 애널라이저 캡처 및 프로토콜 디코딩 | 기존 sigrok-mcp-server 참고 |
| 권장 | `openocd-mcp` | JTAG/SWD를 통한 메모리 덤프, 플래시, 레지스터 읽기 | 기존 구현 참고 |
| 선택 | `jtagulator-mcp` | 자동 핀아웃 스캔 | 있으면 유용 |

### 3.2 Skills (에이전트용 워크플로)

다음 Skill들을 작성한다. 각 Skill은 명확한 입력/출력과 단계별 지시를 포함한다.

1. **uart-shell-acquisition**  
   UART 포트를 탐색하고 셸 또는 U-Boot를 획득하는 절차.

2. **firmware-dump-via-uart**  
   UART/부트로더를 통해 펌웨어를 덤프하는 절차.

3. **firmware-static-analysis**  
   추출된 펌웨어를 REA + Ghidra로 분석하고 인증 로직·하드코딩·백도어 후보를 찾는 절차.

4. **logic-analyzer-protocol-decode**  
   sigrok을 이용해 UART/SPI/I2C 신호를 캡처하고 디코딩하는 절차.

5. **cctv-auth-bypass-hunt**  
   Hikvision/Dahua 스타일의 인증 우회 패턴을 집중 탐색하는 특화 Skill.

### 3.3 오케스트레이션 레이어

- 에이전트가 위 MCP와 Skill을 조합해 사용하는 **마스터 프롬프트 / 시스템 프롬프트** 또는 오케스트레이터 스크립트
- 각 단계의 결과를 구조화된 형태로 저장하고 다음 단계에 전달하는 메커니즘

---

## 4. Recommended Directory Structure

```
hardware-analysis-pipeline/
├── README.md
├── project.md                  # 이 파일
├── mcp-servers/
│   ├── uart-mcp/
│   ├── openocd-mcp/
│   └── sigrok-mcp/             # 또는 외부 레포 참조
├── skills/
│   ├── uart-shell-acquisition/
│   │   └── SKILL.md
│   ├── firmware-dump-via-uart/
│   │   └── SKILL.md
│   ├── firmware-static-analysis/
│   │   └── SKILL.md
│   ├── logic-analyzer-protocol-decode/
│   │   └── SKILL.md
│   └── cctv-auth-bypass-hunt/
│       └── SKILL.md
├── orchestrator/
│   ├── master-prompt.md
│   └── pipeline-config.yaml
├── examples/
│   ├── hikvision-sample/
│   └── dahua-sample/
├── docs/
│   ├── safety.md
│   ├── hardware-setup.md
│   └── mcp-setup.md
└── tests/
    └── mock-targets/
```

---

## 5. Implementation Tasks for Coding Agent

코딩 에이전트는 아래 순서로 작업을 진행한다.

### Phase 1: 기반 MCP 서버 구축
- [ ] UART MCP 서버 구현 또는 기존 구현을 프로젝트에 맞게 정리
  - 기능: 포트 목록, 열기/닫기, 읽기/쓰기, 패턴 대기, 세션 관리, 로그 저장
- [ ] REA MCP 연동 설정 문서화 및 예제 프롬프트 작성
- [ ] (선택) OpenOCD MCP, sigrok MCP 연동 또는 래퍼 작성

### Phase 2: Skill 작성
- [ ] 각 Skill의 `SKILL.md` 작성
  - 목적, 전제 조건, 단계별 지시, 사용할 MCP 도구, 성공/실패 기준, 출력 형식
- [ ] Skill 간 데이터 전달 방식 정의 (파일, 구조화된 JSON 등)

### Phase 3: 오케스트레이터 및 마스터 프롬프트
- [ ] 전체 파이프라인을 안내하는 `master-prompt.md` 작성
- [ ] 설정 파일(`pipeline-config.yaml`)로 대상 기기별 파라미터(보드레이트 후보, 예상 인터페이스 등)를 관리할 수 있게 설계

### Phase 4: 예제 및 문서
- [ ] 최소 1개의 완전한 예제 워크플로 (가상 또는 실제 허가된 기기 기준)
- [ ] 안전 가이드(`docs/safety.md`) 작성
  - 허가된 기기만 사용
  - 위험한 전압/핀 조작 주의
  - 에이전트 명령 실행 전 확인 옵션
- [ ] 하드웨어 셋업 가이드

### Phase 5: 테스트 및 검증
- [ ] Mock UART 또는 기록된 로그를 이용한 단위 테스트
- [ ] 에이전트가 Skill을 따라 파이프라인을 수행하는 end-to-end 시나리오 작성

---

## 6. Technical Requirements

- **언어**: Python (MCP 서버), Markdown (Skill)
- **MCP 프레임워크**: 공식 MCP SDK 또는 FastMCP 등 안정적인 구현 사용
- **의존성**:
  - pyserial (UART)
  - OpenOCD (디버그 프로브 사용 시)
  - sigrok-cli (로직 애널라이저 사용 시)
  - REA (rea-agents)
  - Ghidra (REA 백엔드)
- **에이전트 환경**: Claude Code, Codex, Cursor 등 MCP를 지원하는 환경

---

## 7. Safety & Legal Constraints

- 반드시 **본인이 소유하거나 명시적 서면 허가를 받은 기기**만 대상으로 한다.
- 에이전트가 하드웨어에 명령을 보내기 전에 위험한 작업(전압 인가, 플래시 쓰기 등)은 사용자 확인을 받도록 설계한다.
- 추출한 펌웨어나 분석 결과는 연구·방어 목적으로만 사용한다.
- 프로젝트 README와 Skill에 위 제약사항을 명시한다.

---

## 8. Success Criteria

- 에이전트가 UART MCP를 통해 대상 기기의 콘솔에 접속하고 기본 정보를 수집할 수 있다.
- 펌웨어 덤프(또는 공식 펌웨어)를 REA + Skill을 통해 분석하고, 인증 관련 의심 지점을 구조화된 보고서로 출력할 수 있다.
- 전체 파이프라인을 마스터 프롬프트 하나로 시작할 수 있다.
- 안전 가이드가 명확히 문서화되어 있다.

---

## 9. Future Extensions (Optional)

- 비전 모델을 활용한 PCB 사진 분석 → 핀 후보 추천
- ChipWhisperer 연동을 통한 사이드채널 분석 Skill
- 다중 기기 배치 분석 지원
- 분석 결과 자동 보고서 생성 (Markdown / PDF)

---

## 10. Notes for the Implementing Agent

- 기존에 공개된 MCP 서버(UART, OpenOCD, sigrok, REA 관련)가 있다면 최대한 재사용하고, 부족한 부분만 확장한다.
- Skill은 "에이전트가 따라하기 쉬운" 명확한 단계로 작성한다. 모호한 지시는 피한다.
- 모든 하드웨어 조작은 실패 가능성과 롤백/안전 중단 방법을 고려한다.
- 코드와 문서는 한국어 또는 영어 중 일관되게 작성하되, 기술 용어는 영어를 유지해도 무방하다.
