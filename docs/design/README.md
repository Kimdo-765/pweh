# PWEH 확장 설계 (개요)

> 상태: **제안 (구현 전 검토용)**. 여기 문서들은 계약(`docs/architecture.md`)이 아니다. 사용자가 방향과 결정(§5)을 확인하면 단계별로 구현하고,
> 구현한 부분만 architecture.md·safety.md·스키마·Skill 로 옮긴다. 모든 설계는 조사 → 설계 → 적대적 검증을 거쳤다(근거 조사 노트는 작업 환경 정보가 섞여 있어 저장소에 올리지 않는다 — 로컬 `docs/design/research/`).
> 작성: 2026-10-19. **하드웨어 실측은 아직 없다** — 각 문서의 "하드웨어로 확인할 것"에 모았다.

## 1. 문서 지도

| 문서 | 다루는 것 |
|---|---|
| [common-core.md](common-core.md) | 여러 기능이 함께 쓰는 기반: 사람 증명(attestation), 출처 원장, 비밀값 마스킹, 안전 설정 위치, master-prompt 목표 분기, 호스트 위험 규칙 |
| [port-routing.md](port-routing.md) | 실행 환경 감지(WSL2/WSL1/리눅스/macOS/Windows)와 물리 연결 라우팅(COM·USB·libusb·캡처·블록 장치), 포트 잠금, Windows COM 헬퍼 |
| [game-console-flipper-rf.md](game-console-flipper-rf.md) | 게임 콘솔 분석(NFC 동작, 해금 조건, 하이 스코어 — 저장값 수정·플레이 자동화)과 Flipper Zero·RTL-SDR 하드웨어·주파수 분석 |
| [sd-forensics.md](sd-forensics.md) | SD 카드 포렌식: 증거 분석(이미지·해시·보관 기록·복구·카빙·CCTV 인덱스·타임라인)과 보안 분석(SD 공격 표면, 카드의 민감 정보) |
| [image-hints.md](image-hints.md) | 정지 이미지: 공통 해독기, OCR·QR·메타데이터·구조 지표, 증거 보관 기록과 모델 시각 관찰 |
| [emulation.md](emulation.md) | 구현(증분 B): ESP32·S3·C3 QEMU, Arduino AVR simavr 펌웨어 실행. 출처 확인·봉인 memfd·마스킹 콘솔·세션 수명·고정 백엔드 설치 |
| [esp32-instrument.md](esp32-instrument.md) | ESP32 기반 계측기 MCP(pweh-espprobe): PWEH 전용 펌웨어로 SPI/I2C 읽기·핀 찾기·전압 조사·로직 캡처·UART 브리지, (선택) Wi-Fi/BLE 수동 분석 |

## 2. 요구 → 답

| 요구 | 답 (요약) | 단계 |
|---|---|---|
| 콘솔에 NFC 태그를 댔을 때 동작 | 내 태그 읽기 → 사람이 콘솔에 댐 → 다시 읽고 비교(1b). 에뮬레이션해 콘솔이 쓴 내용·주고받은 프레임 기록(2a) | 1b, 2a |
| 숨은 게임 해금 조건 | 펌웨어·세이브 정적 분석 + 스냅샷 비교 + 동적 확인. 범위는 기기 안 조건(카운터·날짜·치트·디버그 메뉴·내 태그)만 | 1a, 1b |
| 하이 스코어 — 저장값 수정 | 세이브 위치·인코딩·체크섬 → 검증된 이중 읽기 위에 패치 이미지 → 사람이 백업·쓰기 → PWEH 가 다시 읽어 검증. ESP32 NVS·원시 영역 | 1a |
| 하이 스코어 — 플레이 자동화 | 게임패드 전용 입력 브리지 + 화면 인식 + 계획 승인 플레이 job | 2b, 2c |
| 콘솔 밖 하드웨어·주파수 분석 | Flipper(수신·읽기만), RTL-SDR(수신 전용), ESP32 계측기 | 1b, 1c |
| SD 카드 포렌식 (증거·보안 둘 다) | 사람이 쓰기 방지 상태로 이미징 → PWEH 가 오프라인 분석. 펌웨어의 SD 공격 표면(SD-01~09) 점검 | F1~F3 |
| 환경별 포트 라우팅 | `hostenv` 감지 → `ports` 해석 → 백엔드(리눅스 tty / Windows COM 헬퍼 / Windows 판 도구 / usbipd 대체) | P0~P5 |
| ESP32 기반 MCP | PC 쪽 서버 + PWEH 전용 ESP32-S3 펌웨어(USB-CDC). ESP32 위에서 MCP 를 돌리는 방식·커뮤니티 공격 펌웨어는 기각 | 1c~3 |

## 3. 통합 로드맵

하드웨어 전송이 필요 없는 트랙을 먼저 하고, **Windows COM 헬퍼 실기 점검**을 관문으로 둔다(사용자 Flipper/CU/ESP32 보드 연결 필요).

| 단계 | 내용 | 사용자 장비 |
|---|---|---|
| **0 공통 기반** | common-core(증명·출처·마스킹·safety 설정·목표 분기·호스트 위험 규칙) + 포트 라우팅 P0(감지 통일, doctor 환경 절, 원격 URL 루프백, Windows 네이티브 시작 거부) + 테스트 기반 정리<br>**구현 상태: 일부 완료(I1, 2026-10-20)** — 증명·출처 원장·마스킹(코어, 소비자 서버는 아직 없음)·목표 분기·테스트 기반 정리(common-core §3·§4·§5·§7·§9 의 구현 상태). 포트 라우팅 P0 은 I4 에서 끝냈다(port-routing §13.2 구현 상태). 남음: safety 설정 위치(common-core §6 — 새 `safety.*` 키 없음). 호스트 위험 규칙(settings deny·AGENTS.md)은 넣지 않았다(사용자 결정, 2026-10-20) | 없음 |
| **1a 오프라인 트랙** | ESP32 세이브·해금 분석(fwtriage ESP 도구·패치 빌드·쓰기 검증)<br>**구현 상태: 게임 분석 부분 완료(I2a, 2026-10-20)** — ESP 파티션·앱 이미지·ELF·NVS, 세이브 비교·체크섬·치트 입력 표, 게임 문자열 팩, `game-save-unlock-analysis`(분석만). I2b: 패치 빌드·쓰기 검증(ESP NVS·사용자 데이터 파티션, 사람이 쓴다). 남음: 가져온 원시 세이브 패치. REA 는 Xtensa ELF 를 열지 못한다(game-console-flipper-rf §3.5 구현 상태)<br>SD 포렌식 F1(접수·해시·보관 기록·FAT/exFAT·삭제 복구·증거 목록 + 펌웨어 SD 표면)<br>**구현 상태: SD 포렌식 F1 대부분 완료(I3a 2026-10-20, I3b 2026-10-21)** — I3a: 펌웨어 SD 표면(`fw_sd_surface` SD-01~09, `fw_uboot_env` 의 sd_boot, `uart_capture_boot` 의 sd_events). I3b: `pweh-forensics`(접수·해시·보관 기록·검증·쓰기 방지 장치 사람 증명·파티션·호스트 오염 흔적·FAT/exFAT 목록·삭제 파일 추출·증거 목록), 코어 `pweh.fs`·`pweh.evidence`·`pweh.safeio`, `sd-forensics` 스키마, `sd-card-forensics` Skill, 보고서 증거 절. 남음: F2(CCTV 형식·카빙·타임라인·카드 쪽 비밀·암호화·침해 흔적 스캔)·F3(ext4 등), E01, 외부 증거 폴더 제자리 참조, 장치에서 카드 식별 정보 읽기(sd-forensics §4·§5.1 구현 상태). 알려진 한계는 safety.md §3.6<br>ESP32 계측기 펌웨어·프로토콜·시뮬레이터·재현 빌드(오프라인), espprobe 거부 규칙(pweh-esp/uart/sigrok/jtagulator)·코어 이동 | 없음(ESP32 덤프는 기존 pweh-esp) |
| **B 에뮬레이션** | 구현: `pweh-emu` 도구 6개, `firmware-emulation` Skill·요약 스키마, Espressif QEMU·simavr 선택 설치, 공용 ESP 형식·콘솔 마스킹·프로세스 신원·보호 하위 트리. 계약 architecture §6.9, 한계 safety §3.7 | 없음(이미 확보한 펌웨어 사용) |
| **관문** | 포트 라우팅 P1(portlock·식별) + P2 헬퍼 실기 점검: DTR → Flipper `>: `, 1 MB 왕복, CU 응답, USB-UART 루프백, ESP32 `probe-hello` 확인(MI_00/MI_02·부팅 창·다운로드 모드 핀·303a:1001 iSerial — esp32-instrument §9). 실패하면 즉시 대체(PowerShell 또는 usbipd) | Flipper/CU/ESP32/USB-UART |
| **1b·1c 장치 트랙** | pweh-uart Windows COM, pweh-flipper(CLI), pweh-nfc(오프라인 + CU 읽기), pweh-sdr(RTL-SDR), NFC 읽기·비교 흐름 / pweh-espprobe 1차 역할(전압 조사·핀 활동·로직 캡처·SPI·I2C 읽기) | 장비별 |
| **2 확장** | 2a NFC 에뮬레이션 캡처, 2b 자동화 MVP, 2c 플레이 job / SD F2(카빙·CCTV 인덱스·타임라인·비밀·암호화 판정) / 포트 P3(Windows 판 openocd·sigrok) / espprobe 2d(핀 스캔·UART 브리지) | 캡처 카드·브리지 보드 등 |
| **3 선택** | pweh-esp-write(별도 서버), SRAM 패치, 단일 IR 송신, espprobe 라디오 프로필, SD F3(ext4·원시 읽기 헬퍼·내보내기), macOS | opt-in |

각 단계의 끝: 도구 카탈로그 재생성, architecture §6·settings·.mcp.json·README, 일관성 테스트, 전체 테스트, 적대적 검토, 사용자 확인 후 커밋.

## 4. 이번 검토에서 이미 고친 것과 알게 된 것

- **고침(커밋 전)**: `pweh-uart` 의 `uart_open`·`uart_detect_baud` 가 모든 pyserial URL 을 받던 빈틈 — `spy://…?file=` 는 PC 파일을 덮어쓰고 `hwgrep://` 는 다른 포트를 잠금 없이 열어 보드를 리셋할 수 있었고,
  DTR/RTS 를 끄면 INTERACT 라 승인 없이 통과했다. 이제 게이트 전에 거부한다(장치 절대경로·`socket://`·`rfc2217://`·`loop://` 만). 회귀 테스트 포함.
- **호스트 위험**: UAC 가 꺼진 관리자 계정 Windows 호스트에서는 WSL 에서 띄운 Windows 프로그램이 모두 관리자 권한으로 돌고, `wsl.exe -u root` 는 어디서나 비밀번호 없이 root 가 된다(docker 그룹도 root 와 같다).
  "sudo 가 없다"는 전제가 아무것도 막지 못하므로 PWEH 쪽 거부 규칙을 제안한다(common-core §6). UAC 설정은 사용자 결정이다.
- **현재 하드웨어 경로**: 개발 환경(WSL2, usbipd 없음)에서 지금 장치에 닿는 경로는 pweh-esp 방법 A 하나뿐이다. uart·jtagulator·sigrok·openocd 는 usbipd(미설치)를 전제로 한다 → 포트 라우팅 설계가 해결한다.

## 5. 확인과 결정

**구현은 사용자가 "진행"이라고 한 뒤에만 시작한다**(설계 먼저 → 확인 → 구현). 그 뒤 소프트웨어 설계 선택은 답이 없으면 권장(기본값)대로 한다.
다만 **사용자 기기·시스템을 바꾸는 것은 항상 명시적 동의가 필요**하다: ESP32-S3 보드를 계측기로 플래시(백업 먼저), usbipd·Zadig·벤더 드라이버 설치, `.claude/settings.json`·AGENTS.md 거부 규칙 추가, UAC 등 Windows 설정, `safety:` 설정 변경, 장비 구매. 세부 결정은 각 문서의 결정 절에 있다.

### 5.1 사실 확인 (장비·환경)

- Flipper Zero: 펌웨어 버전·포크, 지역(KR 프로비저닝 여부), SD 카드와 CLI 플러그인.
- ChameleonUltra: Ultra 인지 Lite 인지, 펌웨어 버전.
- RTL-SDR/HackRF 보유 여부, 캡처 카드(HDMI) 보유 여부.
- 분석할 콘솔·컨트롤러 모델, 입력 브리지로 쓸 보드(ESP32-S3 추가 보드 또는 RP2040 + Debug Probe).
- SD: 대상 카메라 모델, 쓰기 방지 장치(카드 리더 일체형) 보유·구매 가능 여부, 본인 기기의 샘플(index00.bin·hiv*.mp4·.dav 등).
- 계측기용 ESP32-S3 보드(별도 준비 — 기존 보드는 대상으로 유지): DevKitC-1 버전·모듈(N8/N16R8 등).

### 5.2 지금 정할 것 (권장 기본값)

| # | 결정 | 권장 |
|---|---|---|
| 1 | 진행 순서 | 0단계 + 1a 오프라인 트랙(ESP32 세이브, SD 포렌식 F1, espprobe 펌웨어 오프라인)부터 → 헬퍼 실기 관문 → 1b·1c |
| 2 | 세이브 쓰기 방식 | 오프라인: PWEH 는 검증된 백업 위에 패치·정확한 쓰기 절차를 만들고 사람이 쓴 뒤 다시 읽어 검증(서버가 승인·백업을 강제하지는 못함). 대안: 별도 승인 서버 `pweh-esp-write`(나중) |
| 3 | 플레이 자동화 정책 | `safety.play_policy: approve` — 즉석 입력도 세션 예산을 사람이 승인, 플레이 job 은 계획 승인. 전원·리셋 채널은 호출마다 승인 |
| 4 | 송신 | Sub-GHz·IR·LF 에뮬레이션 송신 기능 없음(사용자 경계보다 좁힘 — KC 요건, 공식 Flipper KR 창과 KR 표의 교집합이 920.5–923.3 MHz 뿐). 재생 위험은 수신 증거로 판정 |
| 5 | NFC 의 PWD 보호 태그·파생 태그 | 둘 다 기본 거부(에뮬레이션은 콘솔의 PWD_AUTH 에서 멈추고 보고, NFC 조건 해금은 정적 분석이나 실제 내 태그로만 확인) |
| 6 | 125 kHz·iButton | 비자격증명 태그만(출입 계열은 거부, 장난감·동물·시험 태그는 ID 마다 증명) |
| 7 | SD 이미징·보관 | 하드웨어 쓰기 방지 장치 + 사람이 FTK Imager, 케이스로 복사(여유 공간 확인), 보고서는 개수·범위·해시만 |
| 8 | 포트 라우팅 | WSL2 기본 = Windows 쪽(헬퍼·Windows 판 도구), usbipd 는 사람이 고르는 대체(세션 동안만 bind, AutoBind 금지), 원격 시리얼은 루프백만, 1급 플랫폼 = WSL2+interop·네이티브 리눅스, 포트 잠금 = 호스트 전체 |
| 9 | ESP32 계측기 | **결정됨: 기존 S3 보드는 분석 대상으로 유지**, 계측기·입력 브리지는 각각 별도 보드(플래시 전 이중 읽기 백업). 무선 프로필은 3단계 opt-in. 하네스는 H0(3.3 V, 출력 GPIO21/41/42)부터, 1.8/5 V·JTAG 스캔은 H1. 배선 증명은 연결마다. 떼어 낸 칩은 외부 벤치 전원(세부 D1–D7: esp32-instrument §10) |
| 10 | 호스트 위험 규칙 | PWEH 거부 규칙 추가(`wsl.exe -u root`, docker 특권, `\\.\PhysicalDrive*`, diskpart/format/chkdsk 등). UAC 설정은 사용자 결정 |
| 11 | 이번 uart 수정 | 커밋·push(설계 문서와 별도 커밋) |

### 5.3 사용자 답 (2026-10-20)

- 구현: **0단계 + 1a 오프라인 트랙부터 진행**.
- pweh-uart 안전 수정: 커밋·push 완료(`ac11290`).
- 설계 문서: 승인 후 커밋(그때까지 로컬). 조사 노트(`research/`)는 올리지 않는다.
- 기존 ESP32-S3 보드: 분석 대상으로 유지(계측기는 별도 보드).
- 커밋 단위: 구현 단위마다 커밋·push. 설계 문서는 I1 과 함께 올린다.
- 호스트 위험 가드레일(`.claude/settings.json` deny 규칙, AGENTS.md 호스트 위험 규칙): 추가하지 않는다.

### 5.4 법적 열린 질문 (법률 자문 아님)

- Flipper·ChameleonUltra 리더 기능(13.56 MHz·125 kHz 자계유도)의 KC/개인 수입 상태.
- SD: 설치 형태(가정용·공개 장소·업무용)에 따라 개인정보 보호법 적용 여부가 달라진다 → 접수 때 기록.
- ESP32 Wi-Fi/BLE 수동 분석(3단계): 통신비밀보호법 시행령의 감청 설비 단서 등 — 켜기 전에 확인.
