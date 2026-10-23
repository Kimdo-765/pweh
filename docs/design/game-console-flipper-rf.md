# 설계안: 게임 콘솔 분석 + Flipper Zero·RF(주파수) 분석

> 상태: **설계와 구현 현황 (2차 개정)**. §3.5의 세이브 분석·ESP 패치·가져온 원시 세이브의 로컬 계획, §3.3의 등록 RAW 파일 분석, §3.4의 공급 숫자 관찰 요약·저장 PNG 영역 비교·내부 합성 frame 수집과 §3.1의 Flipper 고정 파일 읽기·NTAG21x 스캔과 §3.2의 스캔 결속 NFC 파일 검사와 CU 고정 NTAG 스캔·페이지 스냅샷 읽기/등록/분석은 구현됐다. imported 세이브의 기기 쓰기 준비·실제 화면/플레이·RF 수신은 후속 설계다. 계약(`docs/architecture.md`)이 아니다. 개요·로드맵·결정 사항은 [README.md](README.md),
> 여러 서버가 함께 쓰는 기반(포트 라우팅, 증명, 출처 기록, 비밀 마스킹, 안전 설정 위치)은 [common-core.md](common-core.md), 환경 감지·포트 라우팅의 상세는 [port-routing.md](port-routing.md) 에 있다.
> 1차 초안을 네 관점(안전·법, 기술 실현성, PWEH 구조 적합성, 요구사항 충족)으로 적대적 검토한 결과(지적 59건, 반박 0건)를 반영했다.
> 근거: 공식 Flipper 펌웨어 **1.5.1** 소스, ChameleonUltra v2.2.0 소스, esptool·ESP-IDF NVS 형식, rtl-sdr-blog v1.4.0·rtl_433 25.12,
> 전파법·시행령·고시 제2026-9호/제2026-10호, 통신비밀보호법 원문(2026-10-19 조사). **하드웨어 실측은 아직 없다**(§9).

## 1. 목표와 범위

### 1.1 요구와 이 설계의 답

| 요구 | 답 | 단계 |
|---|---|---|
| 1a. NFC 태그를 댔을 때 콘솔 동작 | ① 내 태그 읽기 → 사람이 실제 태그를 콘솔에 댐 → 다시 읽기 → 페이지 비교(+UART 로그·사진). ② 에뮬레이션해 콘솔이 쓴 내용(.shd)·주고받은 프레임(CU 스니프) 기록 | ① 1b, ② 2a |
| 1b. 숨은 게임 해금 조건 | 펌웨어·세이브 정적 분석(카운터·날짜·치트 입력·디버그 메뉴·내 태그 분기) + 세이브 스냅샷 비교 + 동적 확인(1a 흐름, 화면 증거) | 1a(ESP32), 1b |
| 1c. 하이 스코어 — 저장값 수정 | 세이브 위치·인코딩·체크섬을 찾아 **패치 이미지**를 만든다. 쓰기는 §10 결정(기본: 사람이 쓰고 PWEH 가 검증) | 1a |
| 1c. 하이 스코어 — 플레이 자동화 | 입력 브리지(게임패드 전용) + 화면 인식 + 계획 승인 플레이 job | 2b·2c |
| 3. 콘솔 밖 하드웨어·주파수 분석 | Flipper(Sub-GHz OOK 수신, IR 수신, 비자격증명 125 kHz/iButton 읽기, GPIO 읽기, UART 브리지, SPI Mem 가져오기) + 선택적 RTL-SDR(수신 전용) | 1b |

### 1.2 콘솔 종류별 가능 범위 (기대치)

| 대상 | 1a NFC | 1b 해금 조건 | 1c 저장값 | 1c 플레이 | 필요한 것 |
|---|---|---|---|---|---|
| ESP32 장난감·휴대기 | 가능 | 가능(정적·동적) | **구현: NVS 정수·raw-user-data 파티션** — FAT/SPIFFS/LittleFS 는 파일 시스템 해석 전까지 분석만 | 가능 | pweh-esp(이미 있음), Flipper/CU |
| STM32 등 MCU + EEPROM | 가능 | 가능(덤프가 있으면) | 구현: 가져온 원시 덤프 비교·체크섬 후보 분석·명시 값의 로컬 계획. 기기 쓰기 준비는 후속 | 가능 | SPI/I2C 덤프(사람·JTAG) |
| 리눅스 휴대기(SD 세이브) | 가능 | 가능 | 구현: 가져온 일반 세이브 파일 비교·체크섬 후보 분석·명시 값의 로컬 계획. 기기 쓰기 준비는 후속 | 가능 | UART 셸 또는 케이스 밖 세이브 파일 |
| 시판 콘솔(Switch/PS/Xbox) | 가능(태그 쪽만) | 정적 분석 불가(암호화) | **불가** — 세이브가 암호화·서명돼 있어 수정은 복제 방지 우회 경계를 넘는다 | 가능(입력 경로가 맞으면) | 캡처 카드, 입력 방식 |
| 아케이드 기판 | 해당 없음이 많음 | 가능(덤프가 있으면) | 구현: NVRAM 원시 파일 비교·체크섬 후보 분석·명시 값의 로컬 계획. 기기 쓰기 준비는 후속 | 가능(free-play 설정, 동전 라인 금지) | JAMMA 접점 |

NFC·플레이 열의 “가능”은 후속 설계의 기대치다. 현재 NFC 구현은 NTAG21x 스캔과 등록 파일 검사·비교에 한정된다. 현재 세이브 도구의 입력·패치 제한은 §3.5를 따른다.

### 1.3 범위 밖 (항상 거부 — 코드 규칙으로 만든다)

- 사용자 소유(또는 서면 허가) 기기만. 결과는 로컬에만: 온라인 리더보드·대회·계정 제출 금지, 나중에 동기화되지 않게 안내.
- 결제·교통·출입·호텔·신분 자격증명: 14443-4 계열 NFC, 출입용 125 kHz·iButton 계열(§6.2). 남의 태그·피규어 복제, 다운로드한 덤프 에뮬레이션.
- 복제 방지·저작권 보호 우회: amiibo 류 콘솔 키 기반 태그 암호(복호·재암호·재서명), 따로 파는 토큰·DLC·온라인 구매로 여는 콘텐츠(entitlement), 온라인 동기화되는 서명·HMAC 위조. 플랫폼·DRM 키는 존재만 보고(값 마스킹, 내보내기·복호 금지).
- 키 복구(darkside/nested/hardnested/사전/mfkey32 'Detect Reader')와 PWD 무차별 대입·UID 기반 PWD 생성기, 매직 UID 태그 쓰기, 실물 태그 쓰기.
- **송신 축소(사용자 경계보다 좁힘)**: 사용자는 "허용 대역에서 승인 시 송신"을 허락했지만, 이 설계는 **Sub-GHz·IR·LF 에뮬레이션 송신을 넣지 않는다**.
  이유: 전파법 시행령 제25조 4호의 신고 불요 무선국은 적합성평가(KC)를 받은 기기를 요구하고, 공식 Flipper 의 KR 송신 창(312.000–315.250, 920.500–923.500 MHz)과 KR 특정소출력 표가 겹치는 곳은
  920.5–923.3 MHz(LBT/FHSS, 채널당 3/10/25 mW)뿐이다. Flipper KR 펌웨어는 315 MHz 도 송신하지만 KR 표에는 없으므로 기기 지역 잠금은 근거가 될 수 없다. 재생 위험은 수신 증거로 판정한다(§5).
- 재밍·연속 반송파·송신 스윕, 롤링코드 재생·RollJam·브루트포스, 남의 기기로 송신, 지역 잠금 해제 펌웨어 — 향후에도 거부.

### 1.4 숨은 콘텐츠의 범위 (긍정 정의)

해금 조건 탐색과 패치는 **기기 안의 조건**으로 열리는 콘텐츠만: 카운터, 날짜, 치트 입력, 디버그 메뉴, 이 케이스에서 인벤토리에 올린 **사용자 소유 태그**.
모든 발견사항과 패치 연산은 `unlock_source`(in-device / owned-tag / sold-token / online-purchase / unknown)를 가진다. sold-token·online-purchase 면 **보고만**(패치·합성 태그 없음).
패치 연산은 목적(score / progress / in-device-unlock)을 선언하고 manifest 에 보인다.

## 2. 구조

```
pweh-flipper (구현)  고정1.5.1 CLI 연결·파일 읽기·NTAG21x 스캔. RF/임의 앱/RPC는 후속
pweh-nfc     (구현)  CU 고정 NTAG 스캔·inventory·NFC v4 파일 검사/비교. .shd·프레임 해석은 후속
pweh-sdr     (구현)  등록 RAW·전력 CSV 파일 오프라인 분석. RTL-SDR 수신(1b)·HackRF 수신은 후속
pweh-play    (구현)  공급 숫자 관찰 요약·저장 PNG 영역 비교. 입력 브리지·화면 인식·플레이 job은 후속(2b·2c)
pweh-fwtriage(확장)  ESP 파티션·앱 이미지·NVS, 세이브 비교·체크섬·로컬 계획, ESP 패치·쓰기 검증, 게임 패턴 팩
pweh-uart    (변경)  Windows COM 전송(winserial 헬퍼) — Flipper UART 브리지·일반 USB-UART 어댑터를 usbipd 없이 (port-routing.md §5.2)
공통 코어            환경 감지(hostenv)·포트 라우팅(ports)·winserial·wininterop·portlock·증명·출처 원장·비밀 마스킹·safety.rf·nfc·rf 파서 (common-core)
```

`pweh-sdr`는 `sdr_analyze`·`sdr_peaks`를 제공하며 등록 RAW·전력 CSV 파일의 검사·저장·RF 요약을 연결한다.
`pweh-play`는 `vision_validate`로 공급 숫자의 계산·저장·numeric-analysis 요약을, `vision_template_match`로 저장 PNG 비교·template-analysis 요약을 연결한다.
`pweh-flipper`는 연결·종료·정보·목록·파일 읽기·고정 NTAG21x probe와 공통 job3개를 제공한다. 실기 전송은 미검증이며 일반 전송 artifact를 실제 캡처·태그 출처로 승격하지 않는다. `pweh-nfc`는 보호 스캔에 결속한 inventory·파일 검사·비교와 CU 연결·스캔·정리 여섯 도구를 제공한다. 선행 구현한 순수 코어는 `pweh.rf_formats`(RAW 통계), `pweh.nfc_formats`(NFC 구조·저장 페이지 비교),
`pweh.vision_sequence`(숫자 관찰값 합의)이며, 코어 자체는 외부 I/O를 하지 않는다. NFC 공개 입구는 기존 파서의 저장 표현 결과와 실제 스캔 기록의 결속을 구분한다.
파일 선언·저장값·공급 표본을 다루므로 실제 수신·태그 소유/허가·완전한 물리 읽기·화면/게임 상태를 확인하지 않는다.
계약은 [RAW 코어](../references/flipper-raw-profile.md)·[RAW 공개 입구](../references/rf-raw-analysis.md)·[NFC 코어](../references/nfc-file-profile.md)·[NFC 공개 입구](../references/nfc-inventory-analysis.md)·[숫자 모델](../references/numeric-observations.md)·[숫자 공개 입구](../references/numeric-validation.md)를 따른다.

기기 단위 서버인 이유: MCP 서버끼리는 서로 부를 수 없고 한 포트는 한 프로세스만 연다. Flipper 의 모든 앱은 pweh-flipper 가, CU 는 pweh-nfc 가 맡는다.
오프라인 NFC 분석은 장치가 없어도 쓰므로 pweh-nfc 에 둔다(Flipper 가 만든 파일도 해석). 화면 캡처와 입력은 한 루프에서 돌아야 하므로 pweh-play 한 프로세스다.

## 3. 서버별 동작 (도구 목록은 부록 A)

### 3.1 pweh-flipper

**현재 구현**은 `flipper-cli-1.5.1-read-v1`의 connect/close/device_info/storage_list/storage_pull와 job 조회·취소, 고정 nfc_probe다. [전송 계약](../references/flipper-read-transport.md)의 수동 배너·whole lease·DTR MODIFY gate·고정명령·최종 FD 검사를 따른다. 허용 루트는 사용자가 준비한 `/ext/pweh/<case_id>/`이고 파일은 최대1MiB다. GPIO·라디오·전체 태그 덤프·RPC·임의 앱 실행은 후속이며 현재 도구가 아니다.

- **지원 펌웨어**: 공식1.5.1의 고정 소스 문법만 받는다. 배너와 info는 호환성 관찰이며 정품·서명 검증이 아니고 실기 동작은 미검증이다. 다른 버전·포크를 경고만으로 허용하는 경로는 아직 없다.
- **연결 확인**: 포트는 Windows PnP 의 부모 장치(`USB\VID_0483&PID_5740\flip_*`)와 자식 인터페이스(`&MI_00`=CLI, `&MI_02`=브리지)로 식별한다(VID/PID 만으로는 안 된다 — 0483:5740 은 ST 범용).
  연결 직후에는 **아무것도 보내지 않고** CLI 배너(`Welcome to Flipper Zero Command Line Interface!`)와 `>: ` 프롬프트를 수동으로 확인한 뒤에야 쓴다
  (UART 브리지가 USB 채널 0 이면 같은 포트가 대상 기기 콘솔이 되므로, Ctrl-C 나 CR 이 대상 U-Boot 에 들어가지 않게).
  현재 고정 읽기 명령 전에는 `loader info`의 idle 응답을 확인한다. 이는 다음 명령 동안 앱 시작을 막는 원자적 잠금이 아니다. 배너의 제한된 ANSI SGR만 처리하며 일반 응답·binary를 ANSI 제거로 보정하지 않는다.
- **현재 NFC probe**: 사용자가 준비한 허용 case 폴더에서 고정 ISO14443-3A probe 파일 하나를 만들고, UID7/SAK0 후보만 별도 activation의 GET_VERSION을 진행한다. CRC·세 NTAG21x version·식별값 일치와 임시 파일 제거 뒤 부재까지 확인해야 scan 사실을 기록한다. 파일 생성/제거를 포함해 MODIFY다. 페이지 READ·scanner·mfu info/full dump·인증은 없다. 재선택은 원자적이지 않으며 실패 뒤 자동 cleanup 명령을 보내지 않는다. 상세는 [NFC 계약](../references/nfc-inventory-analysis.md)이다.
- **Sub-GHz 수신은 OOK 만**: `subghz rx` 는 OOK 650 kHz, `rx_raw` 는 OOK 270 kHz 프리셋 고정이고 프리셋·RSSI 인자가 없다.
  KR 의 FSK 전용 채널(424.7000–424.9500, 447.8625–447.9875 MHz 등)은 대상이 되면 거부하거나 경고하고, 대체 경로는 ① SDR(rtl_433 은 FSK 해석) ② 사람이 GUI Read RAW(2-FSK 프리셋)로 저장 → 가져오기(기기 지역이 프로비저닝돼 있어야 GUI 가 수신을 연다).
  수신 도구도 SDR 과 같은 **내용 대역·시간 한도·대상 등록**(§6.1)을 따른다.
- **주파수 찾기**: SDR 스윕이 기본. SDR 이 없으면 ① 사람이 Sub-GHz → Frequency Analyzer 를 열고 에이전트는 `log debug` 를 정해진 시간 동안 읽어 `=:<Hz>:<dBm>` 줄을 해석(입력 주입·sysctl 불필요)
  ② 앱이 열려 있지 않을 때 `sysctl debug 1` → 후보 주파수마다 `subghz rx_carrier` → `finally` 에서 `sysctl debug 0`(되돌리기 실패면 세션 종료, fail closed).
- **SD 파일**: 가져오기는 기본적으로 `/ext/pweh/<case_id>/` 와 SPI Mem Manager 디렉터리만. 사용자 기존 폴더(`/ext/nfc`, `/ext/lfrfid`, `/ext/ibutton`, `/ext/subghz`)는
  파일마다 출처 증명 + 계열 판정을 먼저 하고, 거부 계열은 저장하지 않는다. 올리기는 **`.nfc` 만**(2a 에뮬레이션 캡처용, 출처 원장 확인) — `.sub/.ir/.rfid` 는 GUI 에서 송신·에뮬레이션할 수 있으므로 올리지 않는다.
- **RPC**(2a 부터): 허용 목록만 — `app_start('NFC','RPC')`, `/ext/pweh/<case_id>/` 의 `.nfc` 에 대한 `app_load_file`, `app_exit`, `app_lock_status`, storage read/list/md5, 화면 프레임.
  다른 앱의 `app_start`, `app_button_press`/`press_release`/`release`/`data_exchange` 는 정책 거부(Sub-GHz RPC 의 버튼 이벤트는 송신이다).
  RPC→CLI 복귀: `StopSession` 뒤 1바이트를 보내 `>: ` 를 기다리고, 시간이 지나면 헬퍼를 다시 띄워(DTR 해제) 동기화한다. 앱 종료 확인은 RPC 안에서 `app_lock_status` 로.
- **UART 브리지 안내**: 사람에게 Config → **USB Channel = 1**, Flow pins = None 을 먼저 설정하게 하고, 브리지를 켜기 전에 pweh-flipper 세션을 닫는다(RPC 중이면 거부 — USB 잠금 중 브리지를 켜면 Flipper 가 멈춘다).
  PnP 에서 MI_02 가 나타난 것을 확인한 뒤 그 포트를 portlock 의 역할 표지("bridge" — port-routing.md §6.5)로 기록해 pweh-uart(winserial 헬퍼)에 넘긴다.
- **정책 거부(승인 경로 없음)**: 송신 전부(`subghz tx/tx_from_file/chat/tx_carrier`, `ir tx/universal`, `rfid emulate/write/raw_emulate`, `ikey emulate/write`, `bt tx_*`),
  `/int/**`(지역 데이터 포함)·`/ext/subghz/assets/**`·`/ext/apps/**`·`/ext/update/**`·`/ext/badusb/**`·`/ext/apps_data/cli/plugins/**` 쓰기, `storage format/extract`, 허용 루트 밖 삭제·이름 변경,
  `factory_reset`, `update`, `power reboot2dfu`, `crypto`, `js`, Bad USB·U2F, `.fap` 경로·허용 목록 밖 앱의 `loader open`, 일반 입력 주입(`input send`, RPC GUI 이벤트),
  외장 CC1101 송신(device 1 — 수신은 1번 핀 5 V 배선 증명이 있을 때만), `qFlipper-cli`.

### 3.2 pweh-nfc

현재는 `nfc_tag_inventory_add`, `nfc_parse_file`, `nfc_diff_dumps`와 `nfc_cu_connect`, `nfc_cu_scan`, `nfc_cu_read_start`, `nfc_job_status`, `nfc_job_cancel`, `nfc_jobs`, `nfc_cu_disconnect`를 제공한다. 같은 케이스의 보호 scan/inventory, 파일 식별값·SHA·기존 출처 증명을 대조하고 NFC v4 ISO 헤더/NTAG213·215·216의 기존 구조·저장 페이지 비교 결과를 기록한다. 파일 하나1MiB/두 개 합2MiB, 작업5초·최종 검증5초이며 원문 식별값·자격증명을 반환하지 않는다. `nfc-behavior-analysis`와 `nfc-analysis` 요약을 쓴다. CU는 [고정 NTAG 읽기 계약](../references/cu-ntag-read-provider.md)의 Ultra APP2.2/GIT v2.2.0·reader만 허용한다. 현재 CDC 신원·whole lease·DTR MODIFY gate 뒤 고정 조회와 새 scan/GET_VERSION/READ0/1을 검증한다. [CU 스냅샷 계약](../references/cu-read-snapshot.md)의 read job은 시작 page별4B를 유한 수집하고 미관찰 suffix를 null로 보존한다. 전용 device-read 원장을 먼저 기록한 뒤 artifact를 등록하고 같은 inventory의 스냅샷끼리 분석·비교한다. imported 파일과의 혼합 비교는 거부한다. 실제 장치·RF는 미검증이며 mode/slot 변경은 없다. 아래 slot/Classic/PWD/스니프/추가 형식은 후속 설계다.

- **ChameleonUltra 후속 slot·캡처**(현 고정 v2.2.0 읽기 외 추가 버전은 별도 검증): 문서화된 USB 프레임 프로토콜을 직접 구현(GPL 코드 미사용), 명령 ID 허용 목록.
  - 연결 시 현재 모드·활성 슬롯을 스냅샷한다. 슬롯 전환(SET_ACTIVE_SLOT)은 이전 슬롯 RAM 을 플래시에 저장하므로, 운영자가 지정한 슬롯만 쓰고 덮어쓰기 전에 형식별(MF0/MF1) 백업을 케이스에 남긴다.
  - **스니프는 창 단위로 초기화된다**: 매 2020 호출이 슬롯을 플래시에서 다시 읽으므로 창 N 의 콘솔 쓰기는 창 N+1 시작에서 사라진다 → 캡처 하나는 창 하나로 설계(≤30 s, 호스트에서 제한, 시리얼 타임아웃 = 창 + 여유).
    버퍼 3800 B 를 넘으면 조용히 잘리므로 ~3700 B 이상이면 "잘렸을 수 있음" 표시. 창 진행 중에는 취소할 수 없다.
  - `nfc_emulation_stop` 의 기본은 **슬롯 내용을 백업으로 복원(또는 지우기)하고 확인**까지다(CU 는 연결을 끊어도 응답하므로 덤프·PWD 가 남지 않게).
- **MIFARE Classic**(증명 계열): 사용자가 준 키만, 섹터·키 종류마다 정확히 그 키로 `MF1_AUTH_ONE_KEY_BLOCK`(2007)/`MF1_READ_ONE_BLOCK`(2008) — 반복 없음.
  키 탐색 명령(2001–2006, 2012–2015, 2017, 4004–4006)은 거부. Flipper 쪽은 `/ext/nfc/.cache/<UID>.keys` 가 GUI 키 복구 결과로 채워지므로, 기존 캐시는 "사용자 키"라는 사람 증명이 있을 때만 쓴다.
  CU 의 MFC 에뮬레이션(4000/4008/4009/4016/4017)은 1차 범위 밖("나중").
- **PWD 보호 태그**: 기본은 거부 — 에뮬레이션은 콘솔의 PWD_AUTH 에서 멈추고 그대로 보고한다. 대안(§10 결정): 같은 케이스·같은 UID 에뮬레이션 중 **콘솔이 보낸** 비밀번호로 실물 태그에 PWD_AUTH 한 번(사람 증명, ACCESS/AUTHLIM 을 먼저 읽을 수 있을 때).
- **오프라인 분석**: `.nfc`(v2~v4)/`.shd`/CU 덤프 해석, 페이지 비교(잠금·CFG 쓰기 표시), 방향별 패리티를 고려한 프레임 해석. 오프라인 도구도 계열 판정을 적용한다.
  로직 애널라이저 버스 해석(`nfc_bus_interpret`: NCI·PN532·MFRC522)은 실제 캡처가 생길 때까지 미룬다(사람이 Windows 에서 캡처 → `case_import_file` → `sigrok_decode` 경로는 문서로).

### 3.3 pweh-sdr (현재 오프라인 RAW·전력 CSV, 후속 RTL-SDR 수신)

**현재 구현**: `sdr_analyze(case_id, artifact_id, profile="flipper-subghz-raw-v1-strict", max_seconds=5)`.
소유·허가된 케이스의 등록 일반 파일 하나(최대 1 MiB)를 같은 FD에서 읽어 기존 strict RAW 코어로 검사하고,
입력 SHA와 전체 검사 결과를 `analysis/rf-raw-NNN.json`에 등록한다. `case_import_file` 응답의 `artifact.id`로 호출한다.
`complete/partial/malformed/unsupported`와 coverage를 보존하고 `flipper-rf-analysis` Skill의 `rf-analysis` 요약으로 연결한다.
기본·최대 작업 예산은 5초, 결과 생성 뒤 최종 저장은 별도의 고정 5초 예산이며 협력 취소를 적용한다.
원시 pulse·입력 이름·주석은 반환하지 않는다. 선언 주파수와 집계는 익명화나 실제 RF 검증을 뜻하지 않는다.
공개 계약은 [rf-raw-analysis.md](../references/rf-raw-analysis.md)다. 외부 도구·장치·decoder가 필요하지 않다.

**현재 전력 CSV 구현**: `sdr_peaks(case_id, artifact_id, max_seconds=5)`는 같은 케이스에
등록된 최대1MiB의 CSV를 고정 `rtl-power-blog-v1.4.0-csv` 문법으로 검사한다. 완전히 수용한
행의 통계와 보고된 유한 값 상위32개를 `analysis/rf-power-NNN.json`에 저장한다.
마지막 두 전력 열은 각각 세며 FFT bin·주파수 중심·보정 전력·행 시각을 복원하지 않는다.
내부 고정 스윕 인자와 수명 시험은 필수 합성 process factory만 받으며 실제 수신 경로에 연결하지 않는다.
계약은 [전력 CSV 분석](../references/rf-power-analysis.md)을 따른다.

아래 RTL-SDR·IQ·decoder 경로는 **후속 설계**다. 현재 `sdr_analyze`는 `.ook` 변환, `rtl_433 -r`,
프로토콜·키/ID·고정코드/롤링코드 판정, 실제 수신·송신·재생을 하지 않는다.

- Windows 공식 빌드(rtl-sdr-blog v1.4.0 `rtl_power.exe`/`rtl_sdr.exe`/`rtl_eeprom.exe`, `rtl_433_64bit_static.exe` 25.12)를 interop 으로. WinUSB 드라이버(Zadig)는 **Windows 관리자 권한**이 필요한 사람 단계다.
  HackRF 는 Windows 릴리스 zip 이 없어(radioconda·로그인 필요한 CI 산출물) 1b 에서 제외.
- **argv 는 도구별 허용 목록으로 서버가 조립한다**(금지 목록 glob 이 아니라): rtl_433 은 `-d -f -s -g -T(필수) -R(허용 목록) -M -F json:- -r` 만. `-t biastee`·`-F http|mqtt|influx|syslog|trigger|rtl_tcp` 거부
  (`-F http` 는 기본 0.0.0.0 — Windows LAN 에 열린다). 바이어스 티는 도구별로: `rtl_power/rtl_fm -T`, `rtl_biast`, `rtl_433 -t biastee`. 장치 정보는 `rtl_eeprom`(인자 없음, 읽기 전용).
- **내용 수신 규칙**: 디코드·IQ 는 KR 소출력·ISM 표 안에서만, 그리고 **캡처 폭 전체** `[fc − fs/2, fc + fs/2]` 가 허용 대역 안이어야 한다(RTL2832U 최저 샘플레이트 약 225 kS/s 라 좁은 채널 대역에서는 IQ 녹음을 거부하거나 채널화 후 저장).
  rtl_433 출력은 stdout 으로 받아 서버가 대상만 남기고 비대상은 모델별 개수만(또는 job 마다 버리는 무작위 키 HMAC) 디스크에 쓴다.
- IQ 를 `\\wsl.localhost` 에 바로 쓰는 처리량은 미확인 → 대체: Windows 로컬 임시 폴더에 쓰고 sha256·크기 확인 후 가져오기, 샘플 누락 감지.

### 3.4 pweh-play (현재 공급 숫자·저장 PNG 분석, 후속 입력 브리지·화면 인식)

**현재 구현**: `vision_validate(case_id, input_kind="numeric-observations", observations, now, policy=None)`.
사용자가 제공한 최대256개의 엄격한 timestamp/value/confidence와 같은 시간축의 now로 기존 숫자 코어를 호출한다.
입력 digest와 코어 결과 전체를 `analysis/numeric-observations-NNN.json`에 등록하고,
`numeric-observation-analysis` Skill의 `numeric-analysis` 요약으로 연결한다. 처리·저장까지 같은5초 예산이다.
stable/unknown/stale 모두 유효한 계산 결과이며 unknown/stale에서 이전 값을 재사용하지 않는다.
원 표본 배열·개별 timestamp/confidence는 저장하지 않지만 합의 value·공급 now·정책·집계는 반환한다.
digest는 취득 출처나 익명화의 증거가 아니며 화면 신선도·게임 의미·자동 입력 검증은 false로 남는다.
숫자만 분석할 때는 장비·펌웨어·화면 세션·입력 브리지·play-run이 필요하지 않다.
공개 계약은 [numeric-validation.md](../references/numeric-validation.md)다.

**저장 PNG 비교도 구현**: 같은 케이스의 등록 image-hints 보고서·preview index·동일 크기 ROI 두 개와
정수 threshold를 `vision_template_match`에 전달한다. 제한된 worker의 RGB 절대차 합을 정수식으로
판정하고, source ID/해시·ROI·집계를 analysis/template-match-NNN.json에 저장한다. 입력부터 등록까지
고정5초 하나를 쓴다. matched=false도 정상 성공이며 도구 전용 image-template-analysis 단계의
template-analysis 요약을 남긴다. 세 검증 flag는 false다. [선택·결과 계약](../references/stored-png-template.md).

**내부 합성 frame 수집도 구현**: 고정 RGB24의 명시 geometry1..1600, 최대16frame·16MiB·5초와
read64KiB 안에서 최신 pending 하나·drop·tail·EOF·수신 시각을 기록한다. producer가 주입 source를
독점하고 정리 미확정 owner를 보존한다. [내부 계약](../references/rawvideo-frame-owner.md).
같은 수신 시각을 허용하며 숫자 표본의 엄격 증가 시각으로 자동 변환하지 않는다.
실제 캡처 source·PNG 게시·OCR·template 자동 연결·입력 제어는 없다.

아래 입력 브리지·ffmpeg·OCR·플레이 job과 `safety.play_policy`는 **후속 설계**다.
현재 숫자 분석 입구에 새 safety 키나 실제 입력 권한을 추가한 것이 아니다.

- **입력은 세션 단위로 묶는다**: `input_connect` 는 사람 증명(콘솔 오프라인, 결제 수단 제거 또는 구매 PIN, 배선 = 채널 라벨, 게임패드 프로필)을 요구하고 세션을 그 증명에 묶는다.
  즉석 입력(`input_press`/`input_sequence`/`input_axis`)도 `safety.play_policy`(기본 approve) 아래 **세션 예산**(최대 누름 수·시간, 허용 채널, 매핑 해시)을 사람이 승인해야 한다.
  화면 세션이 묶여 있으면 사람이 준 금지 템플릿(시스템 메뉴·상점·계정·세이브 삭제·온라인/리더보드 화면)이 보이는 동안 입력을 거부한다(보조 수단). HOME·시스템 버튼은 즉석 사용 시 호출마다 승인.
- **채널 위험도**: 절연 접점·HID = MODIFY. **전원·리셋·꺼내기 채널은 절연과 무관하게 DESTRUCTIVE**(호출마다 승인, 플레이 스크립트 사용 불가, 펌웨어도 명시 플래그 없이는 거부).
  매핑은 모든 채널의 기능을 선언해야 하고 선언 없는 채널은 전원/리셋으로 본다. 비절연 구동(콘솔 라인 직접)은 DESTRUCTIVE(승인 지문에 사람이 잰 전압).
  coin/credit/payout/service/test/tilt 채널과 액세서리 인증 프로필은 정책 거부.
- **브리지 펌웨어**(PWEH 가 작성·배포, MIT — ESP32 계측기와 `firmware/common` 의 프로토콜·빌드·매니페스트·고정 흐름을 공유, esp32-instrument.md. 전송은 보드 USB-UART, 하트비트 300 ms 그대로): **게임패드 전용 HID 디스크립터만**(키보드·마우스·consumer·vendor·대용량 저장·composite 금지 — 키보드는 Bad USB 와 같다). HELLO 가 디스크립터 해시를 보고하고 다르면 거부.
  부팅 시 출력 해제, 300 ms 하트비트 끊기면 해제, 물리 비상정지, 호스트가 바꿀 수 없는 한도, µs 타임스탬프 보고, 1200 baud 리셋 비활성. PC 대상은 PWEH 를 돌리는 호스트와 다른 기계여야 한다(사람 증명).
- **브리지 식별**: 설정 때 사람이 기록·증명한 USB iSerial 로 열기 전에 고정한다(고유 시리얼이 없는 CH340 류는 거부). 열 때 DTR·RTS 를 모두 내린다(DevKit 은 DTR/RTS 가 EN·부트 핀에 연결).
  HELLO 는 고정된 포트에만, uart 세션이 쥔 포트가 아닐 때만 보낸다. 기본 보드: ESP32-S3-DevKitC-1(네이티브 USB=콘솔용, 보드 USB-UART=PC 용). 대안: RP2040 + Raspberry Pi Debug Probe(2e8a:000c).
- **입력 방식**: USB HID(인증 없는 유선 패드를 받는 기기 — Switch 는 커뮤니티 보고, §9 확인), 접근성 컨트롤러 잭(**PS5 Access 컨트롤러·Xbox Adaptive 만**, Access 는 3.5 mm 포트 4개), 정품 컨트롤러 PCB 접점(PS4 포함 모든 기기).
- **화면 인식**: Windows `ffmpeg.exe`(DirectShow) → rawvideo 파이프. **영상만 녹화(`-an`, DirectShow 오디오 장치를 열지 않음)**. HDMI 캡처를 열거나 녹화할 때 소스 종류 증명(콘솔 자체 설정으로 HDCP 끔·스트리퍼 없음 / HDMI 아님)이 필요하고 플레이 job 은 묶인 화면 세션의 증명을 물려받는다.
  숫자 인식은 순수 파이썬 템플릿을 제안한다(합성 벤치마크 0.25 ms/프레임 — 실제 캡처 경로에서 다시 검증). 선행 숫자 모델은 N-of-M 시간 투표와 신뢰도를 계산하지만 OCR·영상 상태를 검증하지 않는다.
  점수의 단조 증가는 게임별로 확인해야 할 선택 규칙이며 기본 가정이 아니다. 감소·리셋도 입력값으로 받는다. OpenCV 는 넣지 않는다.
- **플레이 job**: 계획 전체를 한 번 승인(스크립트·매핑·브리지 시리얼·펌웨어·채널·한도·정지 조건·감지기 해시·증명). architecture §4 의 job 규칙 예외로 명시하고,
  job 안에서 매 동작을 계획과 대조(`job_command_denied`), 주기적으로 케이스 승인 재확인(`authorization_required`), 브리지·캡처 배타 키를 쓴다. fail closed 규칙(모르는 화면 → 즉시 해제, 정지·검은 화면·캡처 끊김·하트비트 끊김 → 해제 + 정지, 저장 표시 중 전원·리셋 금지).

### 3.5 pweh-fwtriage 확장 (오프라인 세이브·해금 분석)

> **분석 구현 (I2a, 2026-10-20)**: `fw_esp_partitions`, `fw_esp_image_info`, `fw_esp_to_elf`, `fw_esp_nvs`, `fw_save_diff`, `fw_checksum_find`, `fw_find_seq_tables`,
> 게임 팩(`src/pweh/data/game-hunt-patterns.yaml`, `fw_strings_hunt(patterns="game")`, `fw_hunt_patterns(pack=...)`), `save-analysis` 스키마, `game-save-unlock-analysis` Skill. I2a는 분석만 지원했고 현재는 아래 I2b의 선택적 ESP 패치 흐름도 제공한다.
> 계약은 architecture §6.6, fwtriage README. 앱 이미지·ELF 는 esptool `image-info`·`elf2image` 와 대조해 시험했고 파티션 표·NVS 는 로컬 정답이 없어 합성 이미지로만 시험했다
> (NVS CRC 규칙 `zlib.crc32(x, 0xFFFFFFFF)` 는 실기 덤프로 확인 전 — `crc_summary` 로 드러난다).
> **REA 확인 결과**: REA 는 Xtensa ELF(e_machine 94 — ESP32·S2·S3)를 자체 ELF 검사에서 거부한다(지원 아키텍처 아님). RISC-V ELF 는 double-float ABI 표시가 있을 때만 받아서,
> `fw_esp_to_elf(rea_compat=true)` 가 e_flags 를 RVC|double-float(0x5)로 표시한다(실제 ESP 칩은 soft/single-float — 부동소수점 인자 해석만 틀릴 수 있다). 이 표시로 C3 ELF 가 열리고 디컴파일된다.
> 아래 설계의 Ghidra headless 대체(`fw_ghidra_decompile`)는 fwtriage 에 넣지 않는다 — Xtensa 디컴파일 경로는 따로 정할 일이다(사용자 결정).
> 설계와 다른 점: 비밀로 보이는 NVS 값은 응답·결과 파일 모두 마스킹 + 케이스 솔트 다이제스트(게임 값 credits·tokens·stage_passed 등은 가리지 않는다).
> 체크섬 찾기는 알고리즘 24종, 위치 후보는 스냅샷 사이에 바뀐 바이트에서만, 기대 오탐 수로 strong/weak 를 나눈다.
> **구현 상태 (I2b)**: `fw_patch_build`·`fw_verify_writeback`의 기기 쓰기 경로는 ESP NVS 정수 항목과 사용자 데이터 파티션(+체크섬) 대상이다. 가져온 원시 세이브(EEPROM·SD)는 별도 `fw_plan_imported_save`로 로컬 planned 사본만 만든다.
> 설계와 다른 점: base 의 '마지막 읽기 after=no-reset-stub' 조건은 쓰지 않고(기본 이중 읽기는 hard-reset 으로 끝남) **쓰기 직전 새 백업**에 건다(다른 job, 원장 seq 가 뒤, after=no-reset-stub,
> 같은 MAC, 대상 범위가 base 와 같음). 플래시 암호화를 모르면(원조 ESP32) 거부하지 않고 파티션 단위 근거(encrypted 플래그·nvs_keys 없음, 표 MD5, NVS CRC 자기검증)를 manifest 에 남긴다.
> 쓰기 명령은 사람이 WSL bash 에서 실행한다(케이스 폴더로 cd → `sha256sum -c` → esptool `--after no-reset-stub write-flash` — 읽기 확인 전에 게임이 세이브를 다시 쓰지 않게).
> 공개 기록은 출처 원장의 새 kind `patch-plan`(패치 sha256·base/백업 seq·대상·MAC·증명 id)이고 `fw_verify_writeback` 은 그것만 믿는다.

- ESP: `fw_esp_partitions`(쓰기 후보는 **NVS 와 원시 사용자 데이터만** — fat/spiffs/littlefs 는 "파일 시스템 수준 분석 필요"로 보고), `fw_esp_image_info`, `fw_esp_to_elf`, `fw_esp_nvs`.
- 공통 분석: `fw_save_diff`, `fw_checksum_find`. 펌웨어 없이 원시 세이브 파일만 확보한 경우에도 `case_import_file`로 가져온 뒤 응답의 `artifact.path`를 시간순으로 쓸 수 있다.
  스냅샷2~16개(3개 이상 권장), 같은 offset/length를 사용하며 선택 범위 합계는 비교64 MiB·체크섬8 MiB까지다. 일반 파일에는 ESP partition label을 쓰지 않는다.
  `location_abs`·`range_abs`는 파일 기준 절대 오프셋이고 범위 끝은 제외한다. 결과는 후보이며 `truncated`는 검색 미완료 또는 후보 표시 수 잘림이다.
  [합성 원시 세이브 예제](../../mcp-servers/fwtriage-mcp/README.md#가져온-원시-세이브-분석-예제)는 실제 MCP 가져오기→비교→체크섬 탐색으로 확인했다.
  가져온 파일은 `imported-unattested`로 기록되며 읽기 전용 분석에 별도의 출처 증명은 필요하지 않다. `forensics/` 증거·복구물과 `emu/` 기록을 fwtriage로 옮기는 경로는 제공하지 않는다.
- 현재 로컬 계획: 사용자가 값 수정을 명시하면 `fw_plan_imported_save`로 같은 케이스에 가져온 1바이트~8MiB 원시 파일의 정수 1~16개를 편집한다. `case_get(include_artifacts=true)`에서 입력 artifact ID를 고르고 명시한 파일 범위·인코딩·checksum 규칙을 사용한다.
  원본은 유지하고 전체 길이의 사본과 manifest를 `patches/imported-save-plan-NNN/`에 만든다. manifest 하나를 등록하며 별도 출처 증명·device-read/patch-plan 기록·쓰기 명령은 만들지 않는다.
  편집 숫자와 checksum 숫자는 보고서에 남는다. NVS·ESP 파티션 표는 거부하고 기존 비밀값·온라인/판매 콘텐츠 경계를 유지한다. [상세 계약](../references/imported-save-plan.md)의 local_plans 요약으로 끝내며 독립 백업·기기 쓰기·게임 수용을 주장하지 않는다.
- 현재 ESP 패치: `fw_patch_build`, `fw_verify_writeback`. 대상은 `{type: "nvs", partition: <label>}`의 기존 정수 항목 또는 `{type: "raw-region", partition: <label>, checksum?: <후보>}`의 ESP raw-user-data 파티션이다.
  - **base는 이 케이스의 `esp_read_flash_start`로 두 번 읽어 일치한 ESP 전체 플래시 덤프(offset0)**다. 출처 원장의 `device-read`·double-read·match·job id를 검증한다.
    가져온 원시 파일은 이중으로 가져오거나 출처를 증명해도 base가 되지 않는다. `after=no-reset-stub` 조건은 base가 아니라 **쓰기 직전 새 백업**에 적용한다.
  - `stage=planned`는 패치 이미지와 백업 절차를 만든다. base보다 뒤의 다른 job에서 얻은 같은 MAC의 새 백업(대상 범위가 base와 같음)과 사람 증명 뒤 `stage=ready`에서 사람이 실행할 WSL bash 명령을 보여 준다.
    이후 다시 읽어 `fw_verify_writeback`으로 확인한다. `online_capable=yes`와 판매 토큰·온라인 구매 해금은 거부하며, 에이전트는 쓰기 명령을 실행하지 않는다.
- 후속 설계(미구현): 일반 imported EEPROM/FRAM/NVRAM/SD 세이브의 기기 주소·독립 백업·쓰기/readback 준비 및 다른 획득기의 operational 패치 base 지원.
  현재 ESP 파티션 API를 그 경로로 사용할 수 있다는 뜻이 아니다.
- 게임 패턴 팩은 데이터 파일(`src/pweh/data/game-hunt-patterns.yaml`)로 두고 `fw_strings_hunt(patterns="game")` 로 쓴다. `fw_hunt_patterns` 는 목록 도구로 남기고 선택 인자 `pack` 만 더한다. CCTV 기본 팩과 섞지 않는다.
- 디컴파일: RISC-V는 `fw_esp_to_elf(rea_compat=true)` 결과를 REA `open_binary`로 연다. Xtensa는 REA 미지원이므로 문자열·표·세이브 비교의 후보와 한계를 기록한다.
  `fw_ghidra_decompile`는 구현하지 않았고 자동 대체 경로도 없다. 별도 Xtensa 디컴파일 경로는 미정이다.

## 4. 게임 콘솔 분석 흐름

1. **접수**: 목표 "게임 콘솔 분석" 선택(master-prompt Phase 0 목표 분기, common-core §7) → 소유 증명·케이스 생성 → 장비 확인(콘솔 모델, MCU, Flipper/CU, 캡처 카드, 브리지) → 보드 사진.
2. **입력 확보**: 펌웨어를 분석하면 ESP32는 esp32-flash-dump, 그 밖은 기존 UART/JTAG/SPI 경로를 쓴다(실제 사용 가능한 경로는 port-routing.md). 원시 세이브만 있으면 `case_import_file`로 등록하고 5단계로 갈 수 있으며, 펌웨어·디컴파일 확인은 미실시로 남긴다.
3. **정적 분석**: firmware-static-analysis + ESP 도구 + 게임 패턴 → 해금 조건 후보(카운터·날짜·버튼 시퀀스·NFC 페이지/UID 비교)와 세이브 위치를 발견사항(`unlock_source` 포함)으로.
4. **NFC 동작(1b)**: 내 태그 probe → 계열 판정 → 인증 없이 읽기 → [사람] 실제 태그를 콘솔에 댐 → 다시 읽기 → `nfc_diff_dumps`(콘솔 쓰기·카운터·잠금/CFG 변화) + UART 로그·사진 → 정적 분석 분기와 대조.
   한계: `-k` 없이는 AUTH0/PROT=1 뒤 페이지를 못 읽고, NTAG 카운터 변화에는 PWEH 자신의 읽기도 들어간다. 에뮬레이션 캡처(.shd·CU 스니프)는 2a.
5. **세이브 스냅샷**: 점수·진행이 바뀔 때마다 덤프(≥3회) → `fw_save_diff` → 인코딩·위치 → `fw_checksum_find` → 디컴파일로 확인.
6. **값 수정(명시 요청이 있을 때)**: imported 파일은 `fw_plan_imported_save` → 실제 manifest/binary 경로·SHA를 `local_plans[]`에 기록하고 `patches=[]`로 끝낸다. ESP 기기 쓰기는 `fw_patch_build`(목적·unlock_source 선언) → 서버가 새 백업·사람 증명을 확인 → 사람이 쓰기 → 다시 읽기 → `fw_verify_writeback` → 오프라인 상태에서 화면 확인. 분석만 수행하면 두 계획 배열은 비어 있다.
7. **공급 숫자 분석(현재 지원)**: 이미 제공된 숫자 표본·같은 시간축의 now → `vision_validate` → `numeric-analysis` 요약. 이 경로만 수행하면 접수 뒤 바로 호출하고, 펌웨어·세이브·실제 화면 검증이나 play-run을 완료한 것으로 기록하지 않는다.
8. **플레이 자동화(선택, 후속 2b·2c)**: 배선(사람) → 증명 → 점수 숫자·상태 화면 모델 학습·검증 → 선언형 스크립트 → 계획 승인 → 플레이 job → 점수 시계열·입력 로그·키프레임을 케이스에.
8. 각 Skill 은 `case_record_step(step="summary")` 로 끝내고 결과는 로컬 보고서에만.

## 5. RF·하드웨어 분석 흐름 (콘솔 밖)

1. 대상 확인: 라벨·FCC ID·설명서 → `sdr_band_lookup`(KR 대역·FSK 전용 여부).
2. **대상 등록**: 사람이 대상 기기 버튼을 수신기 가까이(가능하면 차폐함)에서 누르고, 서버가 프로토콜·ID 를 기록한다. 디코드 도구는 등록된 대상만 값으로 남긴다.
3. 스펙트럼: `sdr_sweep_start`(전력값만) 또는 SDR 이 없으면 §3.1 의 주파수 찾기.
4. 수신·디코드: OOK 는 Flipper `rx_raw`/`rx_decode` 또는 SDR, FSK 는 SDR 또는 사람의 GUI Read RAW → 가져오기.
5. **현재 오프라인 경로**: 사용자 지정 RAW 파일을 `case_import_file` → 반환 `artifact.id`로 명시 strict profile의 `sdr_analyze` → `flipper-rf-analysis` 요약. 파일 선언·펄스 집계·검사 범위만 기록한다. 전력 CSV는 같은 등록 ID로 `sdr_peaks`를 호출해 보고된 값 순위와 범위를 기록한다. `.ook` 변환·decoder 기반 판정은 후속이며 현재 도구의 인자·출력이 아니다.
6. 후속 재생 위험 분석은 **수신 증거로만** 한다. 현재 RAW 집계만으로 프레임 동일성·롤링코드 여부·재생 위험을 판정하지 않는다. 실제 decoder 경로를 구현한 뒤에도 verification_plan은 확인 방법만 기록한다(safety.md §1).
7. IR 수신, 비자격증명 125 kHz/iButton 읽기, GPIO 읽기, UART 브리지(→ uart-shell-acquisition), SPI Mem 가져오기(→ firmware-static-analysis).

## 6. 안전 규칙 (이 기능 고유분 — 공통 규칙은 common-core §3~§6)

### 6.1 RF 수신 (pweh.safety.rf)

- `safety.rf.region`(기본 KR)은 사람이 정한다. 송신 대역표는 설정으로 좁히기만 되고, 수신 내용 대역의 확장(`safety.rf.rx_extra_bands`)은 운영자만 넓힐 수 있는 명시 설정이다.
- 수신 분류: 스윕 = OBSERVE. 디코드·IQ = 내용 수신 → 대역(캡처 폭 전체)·시간·크기 한도 안에서만, 대상 등록 필수.
- **통신비밀보호법**: 감청은 내용의 지득·채록 자체다(제2조7호, 제3조). 마스킹은 공개를 줄일 뿐이므로 **수집을 최소화**한다 — 대상 등록, stdout 필터링 후 저장, 비대상은 개수만, 전사 기록도 같은 마스킹, 짧게·가까이.
  남는 위험이 있고 법률 자문이 아님을 문서에 적는다.
- 장비 보호: 바이어스 티 거부, HackRF 앰프(`-a 1`)·강제(`-F`, hackrf 만)는 설정이 허용할 때만. 송신기와 안테나 1 m 이상, 케이블 연결은 30–40 dB 감쇠.
- NFC·125 kHz 리더 필드도 자계유도식 무선 방사(고시 제3조의2)다. Flipper·CU 리더 기능의 KC/개인 수입 상태는 **열린 법적 질문**(README §결정·사실 확인)으로 둔다. 에뮬레이션(부하 변조)은 별도.

### 6.2 태그 계열 정책 (서버 자신의 스캔 결과로만 판정)

| 계열 | 판정 |
|---|---|
| NTAG21x (T2T, SAK 0x00, GET_VERSION 으로 확인) | 허용 |
| MIFARE Ultralight/UL-C/EV1 (교통·행사 티켓에도 쓰임) | 증명 후 허용 |
| MIFARE Classic Mini/1K/TNP3xxx (SAK 0x09/0x08/0x01), ISO15693/SLIX | 증명 후 허용 — 증명 문구는 **목적+소유**: "이 케이스의 콘솔과 쓰는 게임·장난감 태그이고 결제·교통·출입·호텔·신분 자격증명이 아님" |
| SAK bit 0x20(14443-4: EMV·DESFire·SEOS·JCOP), Classic 4K/2K(0x18/0x19)·Plus, 14443-B, FeliCa(아케이드 계정 카드 포함), ST25TB, Type 4 | 거부 — 더 조작하지 않고 probe 파일 삭제 |
| 125 kHz 출입 계열: EM4100/EM-Marin, HID Prox(H10301), Indala, AWID, ioProx, Paradox, Keri, Gallagher, Nexwatch, PAC/Stanley, Viking, Pyramid, Jablotron | 거부(ID 마스킹). 예외: ID 마다 "장난감·동물·시험용 태그" 사람 증명 |
| iButton DS1990A, Cyfral, Metakom (현관·인터폰 키) | 거부(같은 예외) |

- 가져온 태그 덤프는 이 케이스에서 실제로 스캔·인벤토리에 올린 태그와 UID/ATQA/SAK 가 같을 때만 받는다(소유 증명, 다운로드 덤프 차단).
- 에뮬레이션 입력은 인벤토리 태그 읽기 또는 그 읽기에 콘솔이 쓴 `.shd` 와 **sha256 이 같아야** 한다(편집·합성 이미지 금지 — 파생 변형은 §10 결정, 기본 없음). 출처는 출처 원장으로 확인한다(common-core §4).
- 키·비밀번호(콘솔 PWD_AUTH, MIFARE 키)·롤링코드는 케이스 파일에만 두고 응답·보고서·게이트 action·감사 기록에는 솔트 다이제스트만.

### 6.3 세이브 수정·플레이

- 오프라인 쓰기 경로도 safety.md §4 규칙 6(케이스 안의 검증된 전체 백업 없이 쓰기를 제안하지 않음)을 지킨다 — §3.5 write_plan.
- 첫 부팅 전 네트워크 차단(사람 증명) — ESP32 는 NVS 에 Wi-Fi 정보가 있어 바로 재연결될 수 있다.
- NOR 쓰기 횟수 한도: 케이스당 쓰기 예산(사람 설정), 자동 쓰기 반복 금지.
- 플레이: §3.4 (세션 증명, play_policy, 금지 템플릿, 전원/리셋 DESTRUCTIVE, 게임패드 전용).

## 7. 케이스·스키마·Skill

- 현재 RAW 분석: 기존 `analysis/`에 보고서, `kind="other"`·`extra.type="rf-raw-analysis"`로 등록한다. 전력 CSV는 `extra.type="rf-power-analysis"`이며 `flipper-rf-analysis`의 `rf-analysis`는 `offline-raw` 또는 `offline-power`의 닫힌 분기를 지원한다. 별도 `rf/` 생성이나 RF 장비 출처 증명은 없다.
- 후속 디렉터리 설계: `rf/`(스윕·디코드·IQ·Flipper 신호), `nfc/`(`tags/`, `sessions/NNN/`, `cu-backup/`, `probe/`), `play/`(`<session>.events.jsonl`, `vision/frames|models|recordings`, `runs/`), `patches/`(이미지 + manifest, ESP 패치는 이미 구현),
  Flipper 전사 기록은 `rf/flipper/<session>.log`. `STANDARD_DIRS`, `case_paths`, `case_import_file` 허용 목록에 추가. 태그 인벤토리는 서버가 쓰는 `nfc/inventory.json`(권위 기록은 `.pweh/state` 의 증명·원장, 케이스 파일은 사본).
- 아티팩트 kind: 처음에는 `other` + `extra.type`(`rf-sweep`, `rf-iq`, `rf-capture`, `nfc-tag-dump`, `nfc-session`, `screen-frame`, `input-log`, `save-patch`).
- 스키마는 Skill 과 **같은 단계**에 등록(SKILL_DATA_SCHEMAS = master-prompt §5 표):

| 단계 | Skill | 요약 스키마 |
|---|---|---|
| 1a | `game-save-unlock-analysis` | `save-analysis` |
| 1b | `flipper-rf-analysis` | `rf-analysis` |
| 오프라인 숫자(구현) | `numeric-observation-analysis` | `numeric-analysis` |
| 저장 PNG 비교(구현) | `image-template-analysis`(도구 전용) | `template-analysis` |
| 1b | `nfc-behavior-analysis`(읽기·비교 부분) | `nfc-analysis` |
| 2c | `game-play-automation` | `play-run` |

- firmware-dump `method` 에 `flipper-spi-mem-manager` 추가. 발견사항 카테고리 후보: `unlock-condition`, `save-integrity`, `hidden-content`, `rf-replay-risk`(아니면 `other` + 태그 — §10).
- master-prompt: Phase 0 목표 분기(보안 분석 / 게임 콘솔 / RF·하드웨어 / SD 포렌식), 목표별 결정 트리·장비 체크리스트·완료 기준. 현재 숫자 단독은 numeric-analysis, 세이브 단독은 save-analysis, 둘을 실제 수행했을 때만 둘 모두 기록한다. 숫자 선택 phase는 보안 기본 `PIPELINE_PHASES`에 넣지 않는다. 후속 플레이 요약은 play-run으로 구분한다.

## 8. 단계 계획

| 단계 | 내용 | 전제 | 하드웨어 없이 검증 |
|---|---|---|---|
| 0 | 공통 기반(common-core): 환경 감지·포트 라우팅(port-routing.md P0–P1), wininterop, portlock, 증명·출처 원장·비밀 마스킹, safety 설정 위치, 테스트 파서 정리 | 없음 | 단위 테스트, 가짜 PnP·가짜 헬퍼 |
| **1a** | ESP32 세이브·해금 오프라인 트랙: fwtriage ESP·세이브 도구, 게임 패턴 팩, REA 지원 ELF 확인·Xtensa 한계 기록, `game-save-unlock-analysis` | 새 전송 없음(기존 esp_read_flash_start) | 합성 NVS·파티션·체크섬 이미지 |
| **1b 오프라인 RAW·전력 CSV** | **구현**: 등록 파일 → 명시 strict RAW profile의 `sdr_analyze` 또는 고정 전력 CSV의 `sdr_peaks` → 분석 JSON·아티팩트 → `flipper-rf-analysis`/`rf-analysis` → 보고서. 실제 RF 수신·decoder 경로는 포함하지 않는다. | 소유·허가 케이스의 등록 RAW·전력 CSV 파일, 장비 불필요 | 합성 `.sub`·CSV, 실제 MCP 입구·FD/해시·취소/등록 수명·요약 |
| **1b 고정 CLI 파일 읽기** | **소프트웨어 구현**: pweh-flipper의 수동 배너·정보·허용 루트 목록·1MiB 파일 읽기/MD5·같은 FD 등록·물리 close/lease 확인. P2 공통 serialtransport를 소비한다. 실제 DTR·USB 매핑·전송은 미검증이다. | 소유/허가 케이스·명시 포트·고정1.5.1·준비한 허용 폴더 | 가짜 CLI 임의 분할·binary·loader·취소·종료·artifact→RAW 연결 |
| **1b 스캔 결속 NFC** | **소프트웨어 구현**: Flipper probe→보호 scan→inventory→출처 증명→등록 파일 구조/차이→요약. 실제 태그·USB/RF는 미검증이다. | 허가된 NTAG213/215/216·Flipper, 또는 기존 유효 inventory와 파일 | 합성 두 MCP Client·private 식별값·원장·증명·같은 FD·취소/등록 |
| **1b CU 고정 읽기** | **소프트웨어 구현**: 고정 codec·단일 owner·probe→CU fact→기존 inventory/파일 검사. 유한 READ의 첫4B 귀속·snapshot/원장/등록·분석/비교와 terminal/cleanup을 검증한다. | 허가된 Ultra2.2 reader·명시 포트, 또는 기존 inventory | 가짜 POSIX/helper·세 NTAG·같은 MCP Client·기존 Flipper 회귀 |
| **1b 후속 연결** | CU 페이지 스냅샷은 구현됐으며 pweh-sdr 실제 수신과 추가 태그 형식은 후속이다. 실기 DTR·1MiB md5와 CU GET_APP_VERSION 확인은 소프트웨어 시험과 별개다. | 사용자 Flipper/CU/수신기와 실제 사실 | 가짜 CU, 가짜 rtl 도구, 합성 NFC |
| 2a | NFC 에뮬레이션 캡처: Flipper RPC(.shd), CU 스니프(단일 창), 필수 정리 | 1b | 가짜 Flipper RPC 상태 기계, 가짜 CU 창 초기화 |
| **2b 선행 내부 frame** | **소프트웨어 구현**: 고정 RGB24 queue·최신 pending·수신 시각·유한 source owner와 close 확인. 공개 화면 도구·캡처·입력 브리지에는 연결하지 않는다. | 주입 메모리 source·명시 geometry, 장비 불필요 | 합성 bytes·Event/barrier·EOF/cap/late/종료 회계 |
| 2b | 자동화 MVP: 화면 OBSERVE 도구, 보드 하나의 브리지 펌웨어(빌드·배포·플래시 절차 — ESP32 계측기 1c 의 `firmware/common`·빌드·고정 흐름 재사용), 세션 예산 안 즉석 입력 | 1b + §10 보드 결정 | 브리지 시뮬레이터(하트비트·한도·디스크립터 해시), 합성 프레임 |
| 2c | 선언형 플레이 job(최대 2시간, play_policy) + `game-play-automation` | 2b | 합성 프레임 시퀀스, 시뮬레이터 |
| 3 | 선택: `pweh-esp-write`(별도 서버), SRAM 한정 `openocd_ram_patch`(같은 목적·entitlement 경계), 단일 IR 신호 송신(DESTRUCTIVE, 내 리모컨의 같은 케이스 캡처만). Sub-GHz 송신·RFID 에뮬레이션은 계획 없음 | 사용자 opt-in | 가짜 esptool 쓰기·MD5 모델, "검증 전 앱 부팅 없음" 테스트 |

각 단계의 끝: 도구 카탈로그 재생성, architecture §6 표, `.claude/settings.json`, `.mcp.json`, `pyproject` 스크립트, README, 스키마·Skill 일관성 테스트, 전체 테스트, 적대적 검토.

## 9. 하드웨어로 확인할 것

- Flipper: 펌웨어·포크·지역 프로비저닝, SD 의 CLI 플러그인(`cli_nfc`, `cli_subghz`, `cli_onewire`, `cli_ir`, `cli_lfrfid`), Windows PnP 모습(단일·이중 CDC, 부모 시리얼, Manufacturer), 헬퍼를 통한 열기 시 DTR/RTS, 이중 CDC 전환 때 COM 번호 변화·재열거,
  interop 프로세스를 끝냈을 때 COM 핸들 해제, RPC→CLI 복귀(1바이트 vs DTR 해제), `dump -p 14_3a` 출력과 `[nfc]` 프롬프트, 실제 RF 환경의 rx_raw 손실, Frequency Analyzer 로그 형식.
- ChameleonUltra: 모델·펌웨어, PnP 모습(composite 여부), 창 초기화가 쓰기 모드마다 이전 쓰기를 지우는지, 배터리 에뮬레이션 지속.
- 콘솔별 에뮬레이션 충실도(READ_SIG·PACK·타이밍·안테나 위치), 콘솔이 PWEH HID 디스크립터를 받는지.
- 입력: S3 DevKit 의 VBUS 경로(콘솔과 PC 동시 연결), 열기 시 리셋 여부, 접근성 잭 전기 사양, 캡처 카드 DirectShow·MJPEG 720p60, 실제 지연(LED 시험).
- SDR: Zadig 드라이버, `\\wsl.localhost` IQ 처리량, `rtl_433 -r` 의 `.ook` 해석(실제 Flipper 캡처).
- 헬퍼: 파이프 자체 시험(256 바이트 값 전부 + EOF 종료, external) 과 USB-UART 루프백(TX–RX, `@pytest.mark.hardware`).

## 부록 A. 도구 목록

위험도: OBSERVE < INTERACT(계측기 상태만) < MODIFY(휘발성 변화·계측기의 서버 소유 영역 지속 변화, 기본 허용) < DESTRUCTIVE(기본 거부, 사람 승인). 연결 도구는 신호·실제 영향에 따라 분류한다(현재 Flipper DTR open은 MODIFY). 정리 도구(`*_close`, `*_disconnect`, `nfc_emulation_stop`)는 게이트·승인 확인 없음(uart_close 원칙).

**pweh-flipper** (현재 고정 CLI 파일 읽기, 나머지는 후속)

| 도구 | 위험 | 비고 |
|---|---|---|
| `flipper_version()`, `flipper_list_ports()` | OBSERVE | 부모 장치·MI 자식 해석, 포트를 열지 않음 |
| `flipper_connect(case_id, port, approval_id=None)` / `flipper_close(case_id)` | MODIFY / 정리 | 구현. DTR=true open 게이트, 수동 배너·버전·프롬프트 전 명령0, whole lease·역할 검사·물리 close 확인 |
| `flipper_device_info(case_id)` | OBSERVE | 구현. loader idle 뒤 고정 정보 projection, firmware 주장은 호환성 관찰 |
| `flipper_region_policy(case_id)` | OBSERVE | 후속 지역·포크·플러그인 |
| `flipper_storage_list(case_id, path)`, `flipper_storage_pull_start(case_id, flipper_path, dest_name=None)` | OBSERVE(·job) | 구현. 정확 `/ext/pweh/<case_id>/`만, 최대1MiB·sameFD/MD5/SHA. 다른 사용자 폴더·SPI Mem 경로는 아직 없음 |
| `flipper_subghz_rx_raw_start(case_id, frequency_hz, duration_s, name, target)` / `flipper_subghz_rx_decode_start(...)` | OBSERVE · job | OOK 만, 내용 대역·대상 등록 |
| `flipper_subghz_rssi_probe_start(case_id, frequencies_hz, dwell_s)` / `flipper_freq_analyzer_log_start(case_id, duration_s)` | MODIFY(sysctl) / OBSERVE · job | §3.1 주파수 찾기 |
| `flipper_ir_rx_start(case_id, duration_s, raw=False)` | OBSERVE · job | |
| `flipper_rfid_read(case_id, timeout_s)` | INTERACT | 계열 판정·마스킹 |
| `flipper_nfc_probe(case_id, approval_id=None)` | MODIFY | 구현. 고정 SELECT·GET_VERSION·scratch SD 생성/정리, 완료한 scan 참조만 반환; 페이지 READ0 |
| `flipper_ibutton_read(case_id)`, `flipper_onewire_search(case_id)` | MODIFY + 배선 증명 | 5 V·버스 구동 |
| `flipper_gpio_read(case_id, pins)` | INTERACT | 입력 모드만 |
| `flipper_i2c_scan(case_id)` | MODIFY + 배선 증명 | |
| `flipper_uart_bridge_guide(case_id)`, `flipper_spi_dump_import(case_id, flipper_path, read_index)` | OBSERVE | 채널 1·세션 종료 확인, SPI Mem 설치 확인 |
| `flipper_storage_push(case_id, artifact, name)` (2a) | MODIFY | `.nfc` 만, 출처 원장 |
| `flipper_nfc_emulate_capture_start(case_id, artifact, duration_s)` (2a) | MODIFY(게이트 호출 안에서 시작), job 은 대기·읽기·정지 | RPC 허용 목록 |
| `flipper_screenshot(case_id)` (2a) | OBSERVE | |
| `flipper_job_status/cancel/jobs` | — | 구현. 취소 뒤 terminal·새 명령0, 고정 읽기 경로는 Ctrl-C를 보내지 않음 |

**pweh-nfc**

| 도구 | 위험 | 비고 |
|---|---|---|
| `nfc_version()`, `nfc_list_ports()` | OBSERVE | |
| `nfc_cu_connect(case_id, port, approval_id=None)` / `nfc_cu_disconnect(case_id, session_id)` | MODIFY / 정리 | 구현. 고정 Ultra2.2 reader 조회·동일 세션 cleanup |
| `nfc_cu_scan(case_id, session_id, approval_id=None)` | MODIFY | 구현. NTAG213/215/216의 GET_VERSION·READ0/1과 CU scan 사실 |
| `nfc_cu_read_start(case_id, session_id, tag_ref, approval_id=None)` | MODIFY | 구현. 같은 inventory의 유한 페이지 snapshot·전용 원장·artifact 등록. `nfc_job_status`/`nfc_job_cancel`/`nfc_jobs`로 조회·취소 |
| `nfc_cu_slot_load(case_id, session_id, artifact, write_mode)` (2a) | MODIFY | 지정 슬롯만, 백업 먼저 |
| `nfc_cu_sniff_start(case_id, session_id, artifact, window_s≤30)` (2a) | MODIFY(호출마다 한 창) | |
| `nfc_emulation_stop(case_id, session_id)` | 정리 | 슬롯 복원·확인 |
| `nfc_tag_inventory_add(case_id, scan_ref)` | 로컬 기록 | 구현. 같은 케이스 보호 scan 검증·동일 scan 반복 등록의 tag_ref 재사용 |
| `nfc_parse_file(case_id, artifact_id, tag_ref, max_seconds=5)` | 로컬 기록 | 구현. scan 식별값·파일 SHA·기존 import 증명 결속 |
| `nfc_diff_dumps(case_id, before_artifact_id, after_artifact_id, tag_ref, max_seconds=5)` | 로컬 기록 | 구현. 두 파일 독립 출처·같은 inventory·기존 partial 보존 |
| `nfc_decode_frames` | 후속 | 방향별 프레임 해석 |
| `nfc_job_status/cancel/jobs` | — | 취소 시 정리 실행 |

**pweh-sdr** (현재 오프라인 RAW·전력 CSV)

| 도구 | 영향 | 비고 |
|---|---|---|
| `sdr_analyze(case_id, artifact_id, profile, max_seconds=5)` | 로컬 보고서·아티팩트 등록 | 명시 strict RAW, 등록 파일 최대 1 MiB, 장치 I/O 없음 |
| `sdr_peaks(case_id, artifact_id, max_seconds=5)` | 로컬 보고서·아티팩트 등록 | 고정 rtl_power CSV, 등록 파일 최대1MiB, 보고된 전력 열 순위·수용 행 통계, 장치 I/O 없음 |

**pweh-sdr 후속 설계** (1b: RTL-SDR, 아래 도구는 미구현)

| 도구 | 위험 | 비고 |
|---|---|---|
| `sdr_version()`, `sdr_list_devices()` | OBSERVE | VID/PID PnP 조회 |
| `sdr_device_info(case_id, device)` | OBSERVE | `rtl_eeprom` |
| `sdr_band_lookup(frequency_hz, bandwidth_hz=None)` | OBSERVE | FSK 전용 표시 |
| `sdr_target_enroll(case_id, ...)` | INTERACT | 대상 등록 |
| `sdr_sweep_start`, `sdr_decode_start(..., target)`, `sdr_iq_capture_start` | OBSERVE · job | 캡처 폭·내용 대역 |
| `sdr_import_flipper_sub` | OBSERVE(오프라인) | `.ook` 변환·decoder 연결은 후속; 현재 등록 파일 분석 계약과 구분 |
| `sdr_job_status/cancel/jobs` | — | |

**pweh-play** (현재 숫자 관찰·저장 PNG 분석, 나머지는 후속2b·2c)

| 도구 | 위험 | 비고 |
|---|---|---|
| `vision_validate(case_id, input_kind="numeric-observations", observations, now, policy=None)` | 기기 I/O 없음, 로컬 결과 저장 | 구현. 공급 숫자 합의·digest·numeric-analysis 요약; 화면 검증 아님 |
| `vision_template_match` | 기기 I/O 없음, 로컬 결과 저장 | 구현. 등록 저장 PNG의 동일 크기 ROI 비교·template-analysis 요약 |
| `input_list_ports`, `bridge_info` | OBSERVE | |
| `input_connect(case_id, port, mapping, ...)` | INTERACT + 증명 | 고정 시리얼, 디스크립터 해시 |
| `input_press`, `input_sequence`, `input_axis` | MODIFY, play_policy 세션 예산(전원·리셋 채널은 DESTRUCTIVE) | 금지 템플릿 |
| `input_release_all`, `input_disconnect` | 정리 | |
| `vision_list_sources`, `vision_open`, `vision_close`, `vision_capture_frame`, `vision_view`, `vision_record_start/stop` | OBSERVE(HDMI 는 소스 증명) | `-an` |
| `vision_define_roi`, `vision_label_frames`, `vision_train_digits`, `vision_ocr_region`, `vision_template_add` | 기기 I/O 없음 | 후속 화면 모델 설계 |
| `vision_watch_start` | OBSERVE · job | |
| `input_script_validate`, `input_script_start` | MODIFY · job(계획 승인, §4 예외) | |
| `play_job_status/cancel/jobs` | — | 취소 = 전부 해제 |

**pweh-fwtriage 구현 도구**: `fw_esp_partitions`, `fw_esp_image_info`, `fw_esp_to_elf`, `fw_esp_nvs`, `fw_save_diff`, `fw_checksum_find`, `fw_plan_imported_save`, `fw_patch_build`, `fw_verify_writeback`, `fw_find_seq_tables`,
`fw_strings_hunt(patterns="game")`, `fw_hunt_patterns(pack=...)` — 모두 오프라인. 패치 입력 제한은 §3.5를 따른다. `fw_ghidra_decompile`는 등록된 도구가 아니다.

부록의 과거 `sdr_peaks(csv_path, threshold_db, min_width)` 형태는 연구안이다.
현재 공개 입력은 등록 artifact ID와 제한 시간뿐이며 임의 경로·threshold·width는 받지 않는다.
