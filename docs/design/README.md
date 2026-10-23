# PWEH 확장 설계 (개요)

> 상태: **구현 현황과 후속 설계**. 현재 동작의 계약은 [architecture.md](../architecture.md)이며, 구현된 범위는 §3에 구분했다. 이후 단계와 새 정책 키는 별도 결정이 필요한 제안이다.
> 구현한 부분은 architecture.md·safety.md·스키마·Skill 로 옮겼다. 설계의 조사·검증 근거는 각 문서에 적었다(조사 노트는 작업 환경 정보가 섞여 있어 저장소에 올리지 않는다 — 로컬 `docs/design/research/`).
> 작성: 2026-10-19. **하드웨어 실측은 아직 없다** — 각 문서의 "하드웨어로 확인할 것"에 모았다.

## 1. 문서 지도

| 문서 | 다루는 것 |
|---|---|
| [common-core.md](common-core.md) | 여러 기능이 함께 쓰는 기반: 사람 증명(attestation), 출처 원장, 비밀값 마스킹, 안전 설정 위치, master-prompt 목표 분기, 호스트 위험 규칙 |
| [port-routing.md](port-routing.md) | 실행 환경 감지(WSL2/WSL1/리눅스/macOS/Windows)와 물리 연결 라우팅(COM·USB·libusb·캡처·블록 장치), 포트 잠금, Windows COM 헬퍼 |
| [game-console-flipper-rf.md](game-console-flipper-rf.md) | 게임 콘솔 분석(NFC 동작, 해금 조건, 하이 스코어 — 저장값 수정·플레이 자동화)과 Flipper Zero·RTL-SDR 하드웨어·주파수 분석 |
| [sd-forensics.md](sd-forensics.md) | SD 카드 포렌식: 증거 분석(이미지·해시·보관 기록·복구·카빙·CCTV 인덱스·타임라인)과 보안 분석(SD 공격 표면, 카드의 민감 정보) |
| [android-analysis.md](android-analysis.md) | Android 펌웨어 형식·AN 점검, 논리 증거·SQLite·앱 내용·후보 복구·타임라인 |
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
| **0 공통 기반** | **일부 완료(I1·I4·B·I5)**: 증명·출처 원장·마스킹과 소비자 서버, 목표 분기·테스트 기반, 포트 라우팅 P0(환경 감지·doctor·루프백 URL·네이티브 Windows 시작 거부), 공용 ESP·콘솔·프로세스·JTAG·신호 형식. P1 공통 포트 라우팅·잠금·직렬 transport도 구현. P2 Windows COM helper, P3-A 내부 OpenOCD pipe와 P3-B Windows 실행 계획·신원 확인 기반, 고정 Windows 번들의 명시 로컬 설치·정적 doctor도 구현. 고정 Windows OpenOCD dummy 시작·조회·종료, sigrok 버전·지원 목록과 고정 OLS COM scan/show·유한 캡처와 job도 구현(합성 시험). Tigard 고정 USB 어댑터 초기화·전체 범위 잠금·제한 조회도 구현(합성 시험). 남음: 다른 USB 프로필·타깃/덤프 기능·실기 검증. common-core §6의 새 `safety.*` 키는 미승인 후속 제안이며 현재 설정에 없다. 호스트 위험 규칙(settings deny·AGENTS.md)은 넣지 않았다(사용자 결정) | 없음 |
| **1a 오프라인 트랙** | **ESP32 세이브·해금 분석 구현(I2a·I2b)**: ESP 파티션·앱·ELF·NVS, 세이브 비교·체크섬·치트 입력 표·게임 문자열 팩, `game-save-unlock-analysis`, 패치 빌드·쓰기 검증(ESP NVS·사용자 데이터 파티션, 사람이 쓴다). 가져온 원시 세이브의 비교·체크섬 분석도 지원한다. 가져온 파일의 패치는 대상 식별·독립 읽기·새 백업·쓰기 검증 계약이 남아 있다. 사용 예제와 REA의 Xtensa ELF 한계는 game-console-flipper-rf §3.5.<br>**SD 포렌식 F1 구현(I3a·I3b)**: 펌웨어 SD 표면·부팅 로그·제한된 FIT 서명 선언 구조 관찰, 접수·해시·보관 기록·증명·FAT/exFAT 목록·삭제 파일 추출·증거 목록, `sd-card-forensics`. C에서 정지 이미지 분석, D에서 파일·선택 앱 기록 타임라인과 읽기 전용 외부 증거 참조를 더했다. F2 중 선택 텍스트 파일·명시 EV 구간 및 저장 FAT/exFAT 목록의 자동 선정 비밀값 검사·보고서 이름 대조·선택 파일의 공개 BMFF 구조 inventory·제한된 길이/PSSH·sample-entry 보호 선언 prefix(실제 암호화/평문 판정 없음)·연속 prefix 후보 메타데이터와 저장된 후보 하나의 prefix 추출, 큰 EV의 명시 구간 선택·재검증을 구현했다. 선택 파일/구간의 제한된 DHAV record framing 후보와 저장된 후보 한 record의 출처 결속 파생 추출도 제공한다(재생·시각 검증 아님). 큰 EV의 bounded DHAV/BMFF 및 명시 JPEG/AVC/PS/XM streaming 검색은 절대 위치·재검증 범위·재개를 기록하고 기존 구간 검증/추출로 이어진다([네 subset 계약](../references/media-unit-scan.md)). FAT/exFAT의 명시 할당 창과 현재 live 참조 일관성 보고서는 각각 상태 판정·참조 지도·표본 완료를 구분하며 고아 파일을 확정하지 않는다. 명시 exFAT 파일의 VDL 뒤 잔여 후보·단일 추출은 DL/VDL과 선택 해시를 별도로 결속하며 이전 녹화를 확정하지 않는다([계약](../references/exfat-residual-candidates.md)). 남음: 지원 subset 제한 검색 밖의 범용 카드 카빙·벤더 CCTV 인덱스/타임라인·녹화 암호화 판정, F3(ext4 등), E01, 카드 식별 정보 읽기. 계약·한계는 sd-forensics §4·§5.1과 safety §3.6 | 없음(ESP32 덤프는 기존 pweh-esp) |
| **B 에뮬레이션** | 구현: `pweh-emu` 도구 6개, `firmware-emulation` Skill·요약 스키마, Espressif QEMU·simavr 선택 설치, 공용 ESP 형식·콘솔 마스킹·프로세스 신원·보호 하위 트리. 계약 architecture §6.9, 한계 safety §3.7 | 없음(이미 확보한 펌웨어 사용) |
| **C 이미지 힌트** | 구현: 일반 케이스·증거의 정지 이미지 분석, 정규화 미리보기·OCR·QR·메타데이터·구조 지표, 증거 보관 기록 결속, `image-hints-analysis`. 계약 [image-hints.md](image-hints.md) | 없음(이미 확보한 그림 사용) |
| **D Android** | 구현: Android 형식·raw GPT/LP 분할·AN 정적 점검, TAR/ZIP·SQLite·앱 기록·타임라인과 읽기 전용 외부 증거 참조. 파일 시스템 엔진은 FAT/exFAT이며 ext4/EROFS/F2FS 추출은 미지원. 계약 [android-analysis.md](android-analysis.md) | 없음(사람이 확보한 파일 사용) |
| **I5 1a 계측기 오프라인** | 구현: 프로토콜·C/HAL 경계·골든 벡터, `probe-hello` 펌웨어, in-process 시뮬레이터 전용 `pweh-espprobe` 도구 6개, 4개 기존 서버의 고정 계측기 거부 규칙, 공용 JTAG·신호 코드. 독립 2회 재현 빌드와 릴리스·설치 검증 완료. 실제 포트·핀·버스 동작은 미지원. 계약 architecture §6.10 | 없음(실기 확인은 다음 관문) |
| **관문** | 포트 라우팅 P1·P2는 하드웨어 없는 검증. 다음 실기 관문: DTR → Flipper `>: `, 1 MB 왕복, CU 응답, USB-UART 루프백, ESP32 `probe-hello` 확인(MI_00/MI_02·부팅 창·다운로드 모드 핀·303a:1001 iSerial — esp32-instrument §9). 실패하면 중단하고 usbipd 경로를 검토(PowerShell 직렬 relay 미구현) | Flipper/CU/ESP32/USB-UART |
| **I5 내부 소프트웨어** | 등록 릴리스·입장 값·직렬 owner와 합성 POSIX/helper 수명 시험, host C의 제한 SPI/SFDP·24Cxx·credit/해제 시험. 공개 sim6와 hello-only 릴리스는 유지. 실제 관찰 생산자·GPIO·bus wire/job은 별도 | 실제 보드 없이 소프트웨어 시험 |
| **1b·1c 장치 트랙** | pweh-uart Windows COM, pweh-flipper(CLI), pweh-nfc(오프라인 + CU 읽기), pweh-sdr(RTL-SDR), NFC 읽기·비교 흐름 / pweh-espprobe 1차 역할(전압 조사·핀 활동·로직 캡처·SPI·I2C 읽기) | 장비별 |
| **2 확장** | 2a NFC 에뮬레이션 캡처, 2b 자동화 MVP, 2c 플레이 job / SD F2(카빙·CCTV 인덱스·타임라인·비밀·암호화 판정) / 포트 P3(Windows 판 openocd·sigrok) / espprobe 2d(핀 스캔·UART 브리지) | 캡처 카드·브리지 보드 등 |
| **3 선택** | pweh-esp-write(별도 서버), SRAM 패치, 단일 IR 송신, espprobe 라디오 프로필, SD F3(ext4·원시 읽기 헬퍼·내보내기), macOS | opt-in |

장치 트랙의 선행 기반으로 RAW 파일 통계·NFC 파일 구조/변화 비교·숫자 관찰값 합의의 순수 코어를 구현했다.
범위는 [공통 코어 표](common-core.md#1-무엇을-코어로-올리나)를 따른다. 운영 입구로 RAW 파일 통계·[제한 OOK 변환](../references/rf-ook-conversion.md)(`pweh-sdr`)과 공급 숫자 검증·[저장 PNG 영역 비교](../references/stored-png-template.md)(`pweh-play`), Flipper 고정 CLI 읽기 전송 및 NTAG213/215/216 스캔 결속 파일 분석(`pweh-nfc`)을 구현했다. [NFC 계약](../references/nfc-inventory-analysis.md)의 Flipper 스캔은 페이지 READ 없이 SELECT·GET_VERSION과 임시 SD 파일 정리를 수행한다. CU 고정 연결·NTAG 스캔([전송 계약](../references/cu-ntag-read-provider.md))과 [페이지 스냅샷](../references/cu-read-snapshot.md)의 read job·전용 출처/등록·동일 inventory 분석·비교도 구현했다. 미관찰 페이지와 부분성을 보존하며 진품·게임 반응을 확인하지 않는다. 실제 RF 수신·플레이 입력은 후속 범위이며 실기 검증은 별도다.

[내부 RGB24 frame·owner](../references/rawvideo-frame-owner.md)는 명시 geometry와 주입 메모리 source에서
최신 pending·수신 시각·drop/EOF·정지 수명을 검증한다. 실제 영상 취득·PNG 게시·인식·입력 연결은 후속이다.

각 단계의 끝: 변경된 도구의 카탈로그·architecture §6·등록 문서를 맞추고 일관성·전체 테스트를 수행한다.
구현 단위별 커밋·push는 누적 사용자 승인에 따라 진행하며, 실제 기기·시스템 변경과 아직 확인되지 않은 사실은 별도 관문으로 남긴다.

## 4. 이번 검토에서 이미 고친 것과 알게 된 것

- **고침(커밋 전)**: `pweh-uart` 의 `uart_open`·`uart_detect_baud` 가 모든 pyserial URL 을 받던 빈틈 — `spy://…?file=` 는 PC 파일을 덮어쓰고 `hwgrep://` 는 다른 포트를 잠금 없이 열어 보드를 리셋할 수 있었고,
  DTR/RTS 를 끄면 INTERACT 라 승인 없이 통과했다. 이제 게이트 전에 거부한다(장치 절대경로·`socket://`·`rfc2217://`·`loop://` 만). 회귀 테스트 포함.
- **호스트 권한**: WSL interop·컨테이너·장치 드라이버의 유효 권한은 설치 환경에 따라 달라진다. 환경 보고서로 확인하고 필요한 시스템 변경은 사람이 결정한다. 저장소에 개발 PC의 상태를 기록하지 않는다.
- **하드웨어 경로**: pweh-esp는 Windows COM 백엔드와 Linux tty 백엔드를 지원한다. 나머지 장비는 환경 감지 결과와 포트 라우팅 설계에 따라 사용 가능한 경로를 선택한다.

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

### 5.2 초기 제안과 결정 항목

아래 표는 설계 당시 제안이다. 구현 상태는 §3, 사용자 결정은 §5.3과 각 설계의 결정 절을 따른다. 특히 새 `safety.*` 키는 현재 설정으로 지원하거나 승인한 값이 아니다.

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
