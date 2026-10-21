# 설계안: ESP32 계측기 MCP (pweh-espprobe)

> 상태: **1a 오프라인 구현과 이후 단계 설계**. 현재 서버 계약은 [architecture.md](../architecture.md) §6.10을 따른다. 이후 단계 설명은 구현 계약이 아니다. 개요·로드맵·결정 사항은 [README.md](README.md), 증명·출처 원장·마스킹·안전 설정 위치는 [common-core.md](common-core.md),
> 환경 감지·포트 라우팅(`pweh.hostenv`·`pweh.ports`·`pweh-serial-helper.exe`·`pweh.portlock`·역할 표지)은 [port-routing.md](port-routing.md), 입력 브리지·Flipper 와의 관계는 [game-console-flipper-rf.md](game-console-flipper-rf.md) 에 있다.
> 요청: "esp32 기반 mcp도 추가해줘"(Flipper·RF 요청 직후). 조사 노트 셋(로컬 `research/esp32-instrument/` — 저장소에는 없음, 부록 B)을 합쳤고, 노트끼리 어긋난 곳은 이 문서에서 하나로 정했다.
> 초안을 두 관점(안전·구조 23건, 사실·라이선스 31건)으로 적대적 검증했다. 부분 수정 24건, 반박 1건, 확인 불가 1건, 누락 6건(1건은 두 관점 공통)을 반영했다(부록 B.3).
> 근거: ESP32-S3 TRM v1.8 33장·데이터시트 v2.2, esp-usb `esp_tinyusb` 2.4.0(`fc9bead`)·espressif/tinyusb 0.21.0~2·arduino-esp32, flashrom(`f1e5ed9`),
> 커뮤니티 펌웨어(ESP32 Bit Pirate v1.8 `8a91778`·Marauder v1.18.0·Bruce 1.16.1·GhostESP 2.2.2), esp-usb-bridge v1.2.1, ok-home logic_analyzer(`c76b900`), law.go.kr 원문(2026-10-19).
> **하드웨어 실측은 아직 없다**(§9). 포트·장치는 하나도 열지 않았다. 신뢰도: [높음] 1차 소스 직접 확인, [중간] 1차 소스 + 추론, [미확인] 확인 못함.

## 1. 해석과 범위

### 1.1 요청 해석

| 해석 | 판정 | 이유 |
|---|---|---|
| **A. ESP32-S3 보드 = 계측기, PC 의 PWEH MCP 서버가 조종** | **채택** | 보드는 USB CDC 로 Windows COM 이 되고 `pweh-serial-helper.exe`(port-routing §5.2)로 닿는다. 분류·게이트·증명·감사·케이스는 PC 에 남는다 |
| B. 커뮤니티 펌웨어(Bit Pirate·Marauder·Bruce·GhostESP)를 CLI 허용 목록으로 조종 | **계측기로는 거부** | §2.2. 공격 코드가 바이너리에 들어 있고, PC 쪽 허용 목록은 COM 을 직접 열면 사라진다 |
| C. ESP32 위의 MCP 서버(Wi-Fi·WebSocket·HTTP) | **거부** | 아래 |

C 를 거부하는 이유:
- 장치 위 서버는 `rt().case` → 분류기 → `rt().authorize` → 감사 밖에 있다. 인증 품질과 무관한 구조 문제다.
- LAN 리스너가 된다. Espressif `mcp-c-sdk` 2.0.1 은 평문 `esp_http_server` 로 `/<endpoint 이름>` 을 듣고(README 예는 포트 80), TLS 서버가 없으며, bearer 인증은 기본 꺼짐에 개발용 토큰이 `mcp-dev-token` 이다 [높음: `esp_mcp_http_server.c:3565,3647`, `Kconfig:100-113`].
- PWEH 는 어떤 리스너도 만들지 않는다(port-routing §11 규칙 5). rtl_433 `-F http` 도 같은 이유로 거부했다(game-console §3.3).
- 받아들일 수 있는 형태는 USB-CDC 위의 PWEH 프레임 프로토콜뿐이고, 그것이 A 다.

### 1.2 이 환경에서의 가치

- **핵심**: inbox `usbser.sys` 가 붙는 CDC 라서 COM 하나로 libusb 장비를 대신한다. 드라이버 교체·usbipd bind 같은 **사람 단계**(port-routing §10)가 없다.
  - UAC 가 꺼진 관리자 계정 호스트에서는 관리자 권한 자체는 막힘이 아니다(port-routing §1). 어느 쪽이든 막히는 것은 에이전트가 할 수 없는 사람 단계다.
  - fx2lafw 로직 애널라이저(Zadig 두 번)와 CH341A+flashrom(Zadig, 일부는 데이터선이 5 V — safety.md §2.5)은 여전히 사람 단계가 필요하다.
  - 모든 libusb 장비가 그런 것은 아니다. MS OS 디스크립터로 `WINUSB` 호환 ID 를 알리는 장치는 Windows 가 WinUSB 를 자동으로 붙인다(esp-usb-bridge 가 그렇다 — `main.c:100-113`) [높음: MS Learn].
- **가치 높음**:
  1. ADC 전압 조사 + 수동 TX·보드레이트 찾기(패드 식별).
  2. 저속 로직 캡처 → 기존 `sigrok_decode`.
  3. SPI NOR 읽기. 16 MiB 이중 읽기 약 40–70 s 추정 [미확인]. UART `md.b` 로는 약 2 h.
  4. I2C·25xx·93Cxx EEPROM 읽기.
- **가치 중간**:
  - JTAG/SWD 핀아웃 스캔: 3.3 V 고정·채널이 적어 H1 하네스가 필요하다.
  - 소유 기기의 Wi-Fi 관리 프레임·BLE 광고 관찰: ESP32 만 할 수 있지만 법적 열린 질문 때문에 3단계다.
- **가치 낮음**: UART 투명 브리지(USB-UART 어댑터 + 헬퍼로 이미 된다), IR 수신(Flipper 와 겹친다).
- **Flipper 가 있으면** GPIO 읽기·I2C 스캔·UART 브리지·SPI Mem 가져오기·IR 수신이 겹친다.
  그때 espprobe 만의 가치는 로직 캡처·ADC 조사·Wi-Fi/BLE 관찰, 그리고 에이전트가 이끄는 SPI 이중 읽기 검증과 출처 원장이다(결정 D6).

### 1.3 범위 밖 (항상 거부 — 펌웨어에 코드가 없고 도구도 없다)

- **쓰기**: SPI/I2C/Microwire 쓰기·지우기·상태 레지스터 쓰기·잠금, 4바이트 모드 진입(`B7`/`E9`), 계측기 자기 펌웨어 기록(사람 단계 §5.4).
- **구동**: 원시 버스 전송, 임의 GPIO 레벨·PWM, 전원·리셋 라인 구동(v1), 글리칭, 의도적인 임의 JTAG IR/DR(EXTEST 등), 계측기가 대상에 전원 공급(H2).
- **송신**:
  - raw 802.11: deauth·disassoc·beacon/probe 응답·karma·evil portal.
  - BLE: 광고·스푸핑·GATT 서버·HID·페어링·본딩.
  - IR·Sub-GHz 송신, USB HID·MSC.
  - IP 스택·리스너: SoftAP, STA 결합, httpd, mDNS.
- 커뮤니티 펌웨어를 PWEH 계측기로 쓰는 것, 장치 위 인터프리터(JS·Lua·바이트코드).
- 남의 데이터 프레임·EAPOL·PMKID 수집, 남의 AP 결합(§4).
- BLE 연결 스니핑은 ESP32 로 할 수 없다(광고 관찰만 된다). 필요하면 nRF52840(nRF Sniffer)·TI CC26x2(Sniffle)를 별도 계측기로 검토한다 [중간].

## 2. 구조

### 2.1 구성

```
[에이전트] ─MCP─> pweh-espprobe (신규, WSL Python) ─ espprobe_mcp.policy → rt().authorize → 감사·케이스·출처 원장
                    │ 에이전트는 "COM7" 만 넘긴다 → pweh.ports.resolve(env, "COM7", "serial-session")
                    │ → PortRoute{backend: win-helper, lock_key: win:COM7, device_id: win-pnp:USB\VID_303A&PID_4002\<MAC>/MI_00}
                    ▼
        pweh-serial-helper.exe (바이트 파이프)     portlock win:COM7 + 표지 instrument (/tmp/pweh-<uid>/tags/)
                    ▼
 ESP32-S3 계측기 — 네이티브 USB(USB-OTG + TinyUSB)   CDC0(MI_00): 프레임 프로토콜   CDC1(MI_02): 대상 UART 브리지(2d, 표지 bridge → pweh-uart)
   firmware/common (프레임·CRC·HELLO·하트비트·세션·해제)   firmware/espprobe (버스 연산 + 컴파일된 정책 표, HAL 경계)
                    ▼ 허용 핀만, 최약 구동력, VREF 창 안에서만 출력(연속 감시)
                [대상 보드]
```

- **이름**: 서버 `pweh-espprobe`, 도구 `espprobe_*`, 패키지 `mcp-servers/espprobe-mcp/espprobe_mcp`, job 접두 `espprobe`.
  도구 접두를 서버 이름과 맞추는 기존 규칙을 따른다. `probe` 단독은 이미 다른 뜻으로 쓰인다(`flipper_nfc_probe`, hostenv probe, SPI probe).
- **하는 일**: 식별 고정·HELLO 검증, 연산 분류·게이트, 배선 증명 요구, 도구 호출 하나에 펌웨어 연산 하나, 이중 읽기 검증, 출처 원장·케이스 기록, (3단계) 비대상 마스킹.
- **하지 않는 일**: esptool 실행(플래시는 사람), 콘솔 바이트 해석(pweh-uart guard), 신호 디코드(pweh-sigrok), JTAG 디버그·메모리 덤프(pweh-openocd + 실제 어댑터).

### 2.2 펌웨어 전략

**① 커뮤니티 펌웨어 + CLI 허용 목록 — 계측기로는 거부.** 사람이 PWEH 밖에서 쓴 결과는 `case_import_file` → `imported-unattested`(common-core §4)로 받는다. 근거 [높음]:
- 네 펌웨어 모두 Wi-Fi blob 의 `ieee80211_raw_frame_sanity_check` 를 덮어써 deauth 를 연다: Bit Pirate `platformio.ini:32` `-Wl,-zmuldefs`(정의 `WifiService.cpp:492`), Marauder `WiFiScan.cpp:63`, Bruce `patch.py:30,37`(`--weaken-symbol`), GhostESP `main/main.c:216`(무조건).
- 공격 기능은 거의 컴파일에서 뺄 수 없다. GhostESP 만 BadUSB·BadBLE·IR·NRF24·SubGHz 등을 Kconfig 로 뺄 수 있고, Wi-Fi raw 프레임·deauth 경로는 항상 들어간다.
- Bit Pirate: 별칭·`repeat`·`||` 줄 잇기가 명령별 허용 목록을 우회한다(`AliasManager.h:6-18`, `TerminalCommandTransformer.cpp:43-59`). 부팅 때 고르는 Wi-Fi 웹 터미널(`/ws`)은 인증이 없다(`WebSocketServer.cpp:10-18`).
  NVS 1회성 부팅 모드가 재부팅 뒤 장치 정체를 바꾸고(`BootModeConfigurator.cpp:104-166`), serprog 모드는 `O_SPIOP` 를 통과시켜 쓰기를 허용한다(`FlashromSerprogAdapter.cpp:30,247`).
  HID·MSC 를 전역 생성자로 등록해 열거될 가능성이 높다 [중간: `UsbS3Service.cpp:12-20`]. README 의 "3.3V or 5V"(`:184`)는 데이터시트와 어긋난다.
- USB ID: arduino-esp32 일반 S3 변형의 기본값은 대상과 같은 `303a:1001`(`variants/esp32s3/pins_arduino.h:7-8`)이지만 빌드가 바꿀 수 있다. Bit Pirate 는 `303a:1002` "ESP32 Bit Pirate"(esp-usb-bridge 기본 PID 와 겹침)다.
  그래서 303a:1001 만 보는 규칙은 Bit Pirate 를 놓치고, HID·MSC·벤더 인터페이스 거부 규칙(§5.5)이 잡는다.
- Bruce(JS)·GhostESP(Lua)는 인터프리터를 갖고 있다. 원시 패스스루다.
- **판단의 핵심은 바이너리 안의 공격 코드다.** "COM 을 직접 열면 PC 쪽 허용 목록이 사라진다"는 PWEH 의 CDC1 브리지(TX 켬)에도 해당한다. 그 경로는 USB-UART 어댑터와 같아 safety.md §3.4 의 위협 모델 안에서 받아들인다(§2.6).
  ①과 ②를 가르는 것은 공격 코드가 바이너리에 있느냐와, CDC0 연산마다 펌웨어가 허용 목록을 강제하느냐다.

**② PWEH 최소 펌웨어(MIT) + 프레임 프로토콜 — 채택.**
- 송신·쓰기 코드가 아예 없고(빌드 검사 §5.2, 호스트 시험 §8), 원시 바이트 경로도 없다.
- HELLO 가 이미지 해시·기능·한도를 보고한다. 하트비트가 끊기면 핀을 Hi-Z 로 푼다.
- pweh-play 입력 브리지 펌웨어와 `firmware/common` 을 함께 쓴다(전송 독립).
- 비용: 펌웨어 유지보수, ESP-IDF 빌드(로컬 Docker), 실기 검증. 아래 재사용으로 줄어든다.

**③ 표준 프로토콜 — 3단계 선택(§7), 사람 전용 호환 모드로만.**
- **serprog**: `O_SPIOP`(0x13)가 원시 SPI 를 나르므로 프로토콜만으로는 읽기 전용이 안 된다(펌웨어가 opcode 를 걸러야 한다).
  flashrom.org 는 Windows 바이너리를 내지 않지만 MSYS2 가 Win32 직렬 백엔드(`\\.\COMn`)를 가진 flashrom 1.8.0 을 배포한다 [높음].
  쓰려면 새 `win-exe` 허용 목록 항목(port-routing §11 규칙 6)과 쓰기 인자 거부가 필요하다. 리눅스 flashrom 은 WSL2 에서 Windows COM 에 닿지 못한다.
- **SUMP**: 입력 전용이다. Windows sigrok-cli 는 설치 프로그램뿐이고 리눅스 sigrok-cli 는 COM 을 못 연다. 자체 캡처를 `.sr` 로 쓰면 같은 결과다.
- **esp-usb-bridge**(Apache-2.0):
  - 벤더 클래스 USB 다. MS OS 2.0 디스크립터 덕에 WinUSB 가 자동으로 붙어 Zadig·관리자 단계는 없다.
    대신 Windows `openocd.exe`(openocd-esp32 포터블 zip, port-routing §5.4 의 `tcl port pipe`, P3) 또는 usbipd, 그리고 pweh-openocd 의 새 어댑터 허용 목록이 필요하다.
  - MSC UF2 로 대상에 쓰는 경로가 항상 빌드되고(`msc_init()` 무조건, `main.c:247`) Kconfig 로 끌 수 없다.
  - DTR/RTS 가 대상 BOOT·RST 를 구동하고(`serial_bridge.c:153-188`), 매직 baud(기본 1200)로 자기 자신을 ROM 다운로드 모드로 리셋한다(README:55-79).
  - GitHub 릴리스에 바이너리가 없고, 유일한 사전 빌드 `esp-prog2.bin`(ESP Launchpad)은 BOOT=GPIO33 이라 옥탈 PSRAM 보드와 충돌한다. 일반 S3 DevKit 에 올리지 않는다.

**코드 재사용**: MIT·Apache-2.0·CC0/퍼블릭 도메인만 쓰고 고지를 유지한다 [높음: LICENSE·파일 헤더].
- MIT: Bit Pirate 의 blueTag 파생 JTAG 스캔(`JtagService.cpp:1`, blueTag 도 MIT)·UART autobaud. Apache-2.0: esp-usb-bridge UART 코드. CC0: ESP-IDF `simple_sniffer`(3단계).
- ok-home logic_analyzer 는 저장소 LICENSE 가 없고 **파일별 CC0/퍼블릭 도메인**이다(33개 중 13개: S3 LCD_CAM 드라이버 `esp32s3/logic_analyzer_ll.c`, 트리거 ISR, HAL, SUMP 인코더). v1 로직 캡처와 3단계 SUMP 모드의 출발점이다.
  표시 없는 헤더(`logic_analyzer_const_definition.h`, `pin_definition.h`, `logic_analyzer_ws/*`)는 새로 쓰거나 작성자에게 LICENSE 를 요청한다.
- JTAGenum 은 비공식 허용 표시(`JTAGenum.ino:19` "whatever you want it to be")라 출처 표기를 유지하고 쓸 수 있다.
- 참고만(코드 미사용): GhostESP(GPL-3.0), Bruce(AGPL-3.0), esp32-serprog·pico-serprog(GPL-3.0), BMP(GPL-3.0, 보관됨).
  Ebiroll esp32_sigrok 은 파일별 혼재(`main/app_main.c` MIT, libscpi BSD-2-Clause, `esp32_sump.c` 는 Benjamin Vernoux 저작권)이고 표시 없는 파일은 권리 유보로 본다.

**Flipper Wi-Fi 개발 보드**(ESP32-S2): 공식 펌웨어는 BMP/DAPLink 이고 기본이 Wi-Fi AP(`blackmagic`/`iamwitcher`, `nvs-config.c:14-15,115-117`)다 [높음]. espprobe 대상이 아니다.
USB SWD 프로브로는 pweh-openocd 경로(3단계)이고, Marauder 를 올린 보드는 ① 규칙을 따른다.

### 2.3 링크와 USB 식별

- **네이티브 USB(GPIO19/20)를 USB-OTG + TinyUSB(esp_tinyusb) CDC-ACM 두 개로 쓴다.** CDC0(MI_00) = 프레임 프로토콜, CDC1(MI_02) = 대상 UART 브리지.
  - 브리지는 2d 에 켜지만 **디스크립터는 v1 부터 고정한다.** CDC 개수가 바뀌면 PID·인터페이스 번호가 바뀌고, Windows 는 PID 별로 드라이버·COM 을 기억한다(`usb_descriptors.c:14-16` 주석).
- **내장 USB-Serial/JTAG(303a:1001)는 링크로 쓰지 않는다.** 조사 노트 하나(pweh-fit-safety-legal §2.6)의 권고와 반대다.
  - TRM v1.8 표 33.3-2: RTS=1·DTR=0 → 칩 리셋, RTS=0·DTR=1 → 다운로드 플래그 설정, 0/0 → 플래그 해제 [높음]. 포트를 여는 어느 프로그램이든 계측기를 리셋할 수 있다.
  - ID 가 대상 S3 와 같은 303a:1001 이고 CDC 도 하나뿐이다.
- **부팅 창**: 기본(`phy_sel=0`)에서 내부 PHY 는 USB-Serial/JTAG 에 붙어 있고, 사용자 코드가 돈 뒤에야 바꿀 수 있다(TRM §33.4.1, `RTC_CNTL_SW_HW_USB_PHY_SEL`). 그 하드웨어는 스스로 초기화된다(§33.4.2).
  - 그래서 **모든 부팅(전원 투입·EN·패닉·워치독·브라운아웃)은 TinyUSB 가 PHY 를 넘겨받기 전에 잠깐 303a:1001 로 열거될 것**으로 본다 [중간: TRM + 추론, 미실측]. RTC 레지스터가 남는 CPU 리셋(패닉·MWDT)에서는 없을 수도 있다.
  - 이 창에서 포트를 RTS=1·DTR=0 으로 여는 프로그램은 칩을 리셋하고, DTR=1 은 다운로드 플래그를 세운다. 모든 서버의 거부 규칙과 `espprobe_list_ports` 는 이 과도 상태를 감안한다(§2.6, §5.5). 발생 조건과 길이는 1b 에서 잰다(§9).
- **USB ID**:
  - esp_tinyusb 기본값 `0x4000 | CDC개수` = **303a:4002** 를 쓴다(`usb_descriptors.c:21-23`, `tusb_config.h:260`) [높음]. MSC 전용 장치(`MSC<<1`)와 같은 값이라 **유일하지 않다.** 식별은 PID 가 아니라 고정(§5.5)이 한다.
  - 전용 PID 는 기대하지 않는다(D5). espressif/usb-pids README 는 표준 드라이버를 쓰는 TinyUSB 장치에는 전용 PID 가 필요 없다고 하고 거절할 권리를 둔다. **303a:4002 + MAC 고정을 영구 상태로 설계한다.**
  - 제품 문자열은 "PWEH espprobe".
  - **iSerial = base MAC 12자리 대문자 hex — esp_tinyusb 의 기본값이 아니다.** `CONFIG_TINYUSB_DESC_SERIAL_STRING` 의 기본은 `"123456"` 이고, **빈 문자열일 때만** eFuse base MAC 으로 만든다(`Kconfig:190-202`, `usb_descriptors.c:104-120`) [높음].
    기본값으로 빌드하면 모든 계측기가 `123456` 을 보고해 MAC 고정이 조용히 무너진다. 그래서 모든 프로필에 빈 값을 두고 빌드 검사가 확인하며(§5.2), HELLO·매니페스트 검증에 `usb.serial == upper_hex(base_mac)` 을 넣는다(§5.5).
- **빌드 설정**:
  - HID·MSC·벤더 인터페이스·DFU·1200 baud 리셋을 넣지 않는다.
  - TinyUSB 는 DTR 이 없어도 송신을 막지 않지만 TX FIFO 를 덮어쓰기로 둔다(espressif/tinyusb 0.21.0~2 `cdc_device.c:265-268`, `cdc_device.h:83-85`) [높음].
    `tud_cdc_configure()` 는 이제 아무 일도 하지 않으므로 `CFG_TUD_CDC_TX_OVERWRITABLE_IF_NOT_CONNECTED=0` 을 **전역 컴파일 정의**로 넣는다. esp_tinyusb 의 `tusb_config.h` 가 이 매크로를 정의하지 않아 `-D` 가 먹는다(빌드로 확인). 그러면 DTR=0 으로 열어도 프레임을 잃지 않는다.
- **장점**:
  - TinyUSB CDC 의 DTR/RTS 는 그냥 신호다. 리눅스(usbipd) 경로의 열기 펄스(port-routing §7)에도 리셋되지 않는다.
  - CDC 기기에는 inbox `usbser.sys` 가 INF 없이 자동으로 붙는다 [높음: MS Learn]. CDC 두 개(IAD 복합)는 1b 에서 확인한다.
- **보드의 USB-UART 포트(aux)**: DevKitC-1 의 USB-UART(CP210x/CH343, EN·IO0 자동 리셋)는 계측기로 쓰는 동안 **반드시 뽑는다**. 이유는 §3.0, 식별(`instrument-aux`)과 거부는 §5.5.
- **칩 범위**: v1 은 ESP32-S3 만. S2 는 OTG 만 있어 나중에 가능하다. C3/C6 은 USB-Serial/JTAG 뿐이라 대상과 구별할 수 없어 제외한다.

### 2.4 와이어 프로토콜 (요약 — 사양은 `docs/references/espprobe-protocol.md` + hex 골든 프레임)

- **프레임**: `COBS(header16 ‖ payload ‖ crc32_le)` + `0x00`.
  - CRC-32 는 zlib 다항식이다. I5는 portable C CRC와 Python zlib를 고정 골든 벡터로 대조하며 ROM API에 의존하지 않는다.
  - 헤더: `ver, type(REQ/RSP/EVT/DATA/HB), op, seq, flags, session, len(≤4096), credit`.
- **재시도·오류**: 같은 `seq` 면 장치가 저장한 RSP 를 다시 보낸다(다시 실행하지 않는다). `E_POLICY` 는 핀·opcode·한도 위반이고 **조용히 깎지 않는다.** `E_UNSUPPORTED_OP` 는 컴파일되지 않은 연산, `E_RELEASED` 는 해제 상태다.
- **HELLO(TLV)**:
  - 펌웨어: `fw_name`, `fw_version`, `build_profile`, `board`, `git_commit`, `image_sha256`, `app_elf_sha256`, `idf_version`.
  - 장치: `chip{model, revision, psram, flash_voltage}`, `base_mac`, `usb{vid, pid, product, serial}`.
  - 상태: `boot_id`(부팅마다 무작위), `usb_session`, `reset_reason`, `last_release_reason`.
  - 정책: `caps`, `limits`, `pins_allowed`(하네스별 표), `pclk_pad`, `pin_drive`, `spi_read_opcodes`, `radio`, `tx_caps`.
  - 세션 토큰·nonce 반향.
- **하트비트 1000 ms**(컴파일 범위 250–3000 ms). 호스트는 `hb_ms/3` 마다 HB(크레딧 포함)를 보낸다.
  - 1000 ms 인 이유: 연산이 모두 읽기·스캔이라 호스트가 죽은 뒤 1초 더 이어져도 새 위험이 없다. interop 파이프·Windows 스케줄 지연에서 오는 거짓 해제(덤프 중단)도 줄인다.
  - pweh-play 브리지의 300 ms 는 그 프로필 값이다(game-console §3.4). 그쪽은 눌린 버튼이 위험이다.
- **해제 조건**(하나라도 맞으면): 하트비트 없음, RELEASE/BYE/ABORT, USB 버스 리셋·서스펜드, **VREF 창 이탈**(§3.0), 패닉·워치독 리셋, 버스 상태를 알 수 없게 만든 오류.
  - BOOT 버튼(GPIO0)은 비상정지가 **아니다.** 다운로드 스트랩이라 누른 채 리셋되면 다운로드 모드에 들어간다(§3.0). 비상정지는 §3.0 의 순서를 따른다.
- **해제 내용**: 점유 핀 전부 입력·풀 없음·매트릭스 분리, 주변장치·LA·브리지 정지, 변환기 OE 끔, 세션 무효. 서버는 `bridge` 표지를 지운다(§2.6).
- **DTR 1→0** 은 보조 신호로만 쓴다. interop 자식이 COM 핸들을 쥔 채 남을 수 있기 때문이다(esptool.exe 사례, architecture §6.7).
- **흐름 제어(크레딧)**: DATA 는 호스트가 HB 로 준 크레딧만큼만 보낸다.
  - 크레딧은 **BEGIN 때 고정된 연산의 흐름 제어일 뿐 확장이 아니다.** 펌웨어는 `offset·length·passes` 를 BEGIN 에서 고정하고, DONE 뒤의 크레딧이나 길이를 넘는 크레딧으로는 버스 활동을 하지 않는다. 크레딧으로 새 연산을 시작할 수 없다.
  - 새 연산은 새 REQ 이고, REQ 는 게이트를 통과한 도구 호출 안에서만 보낸다.
  - job 은 크레딧을 주기 전에 케이스 소유/허가와 `boot_id`·`usb_session` 을 다시 확인하고, 다르면 ABORT 한다.

### 2.5 공통 기반 사용 (기반 문서 개정이 필요한 곳은 부록 C)

아래 표는 이후 실기 단계까지 포함한 설계다. 새 `safety.espprobe.*` 키와 `authorize(policy_key=...)`는 미승인 후속 제안이며 I5 1a의 설정에 없다. 현재 구현 범위는 §7과 문서 끝의 I5 1a 설명을 따른다.

| 기반 | espprobe 에서 |
|---|---|
| 포트 라우팅(port-routing §4) | 에이전트는 `COMn`(리눅스면 `/dev/serial/by-id/…`)만 넘긴다. 내부 표기는 없다. `resolve(env, ref, "serial-session")` → `PortRoute`. `device_id` = `win-pnp:<부모 인스턴스 id>/MI_00`, `lock_key` = `win:COMn`(§6.2). 부모 iSerial 은 `DEVPKEY_Device_Parent`, 물리 위치는 `DEVPKEY_Device_LocationPaths` 로 얻는다(§4.4). 지금 `esp_mcp/ports.py:250` 은 `MI_` 자식의 시리얼을 버리므로 이 조회가 **선행 조건**이다. 식별 표 `usb-ids.yaml` 에 `303a:4002` 항목(generic: true, interfaces MI_00=control/MI_02=bridge, reset_wiring none)을 넣고, `303a:1001` 항목의 `transitions` 에 "espprobe 부팅 창·ROM 다운로드"를 적는다. `reset_risk` 는 1b 확인 전 `possible`, 뒤 `none` |
| portlock(port-routing §6) | CDC0 은 세션 동안 `win:COMn` 잠금을 쥐고, 열기 전·게이트 전에 잡는다(§6.4 순서). 표지(`<runtime dir>/tags/` = `/tmp/pweh-<uid>/tags/`, §6.5): CDC0 = `instrument`, CDC1 = 브리지가 켜졌을 때만 `bridge`(case·세션·`rx_only`) 아니면 `instrument`, 보드 USB-UART = `instrument-aux`(새 역할). 표지는 재부팅에 지워지므로 **거부의 영구 근거는 `instrument-pin` 증명**이고 표지는 보조다. 열기·연결 지문에 `route` 를 넣는다(§4.3) |
| 증명(common-core §3) | 새 종류 `instrument-pin`, `wiring`, 3단계의 `radio-target`·`module-kc`. **기반 개정 둘**: 계측기 전역 바인딩(사람이 철회할 때까지)과, 사람이 **값을 직접 입력**하는 항목(잰 전압·I2C 주소 폭·무선 대상 식별자). y/n 만 받으면 에이전트가 넘긴 숫자를 승인하는 꼴이 된다. 커뮤니티 도구 산출물에는 기존 `provenance-import` 를 쓴다 |
| 출처 원장(common-core §4) | 기록: SPI 덤프·EEPROM 읽기·캡처 → `{sha256, sha256_read2, instrument_id, mac, fw_image_sha256, wiring_attestation_id, jedec_id 또는 i2c 주소, case_id, job_id, at}`. **기반 개정**: pweh-esp 가 `esp_chip_info`(MAC·PnP 식별)와 `esp_security_info`(플래시 암호화·Secure Boot·Secure Download Mode) 결과도 원장에 기록한다(산출물이 아닌 기기 사실). 확인하는 곳: `espprobe_flash_plan`(§5.4), game-console §3.5 `fw_patch_build` raw-region base(그 절 개정 필요 — 부록 C) |
| 마스킹(common-core §5) | 유선 경로에는 새 비밀이 없다(덤프 안 PSK 등은 기존 분석 규칙). 3단계 무선: 비대상 식별자는 장치를 떠나지 않는다(§3.4) |
| 안전 설정(common-core §6) | `safety.espprobe.{max_spi_hz, max_capture_hz}` 는 컴파일된 한도를 **좁히기만** 한다. `safety.espprobe.{allow_unreleased_firmware, radio_profile, wifi_active_scan}` 은 권한을 넓히는 **opt-in** 이라 운영자만 켠다(기본 꺼짐, game-console §6.1 `rx_extra_bands` 와 같은 급). 게이트는 INTERACT 이하를 늘 허용하므로(`gate.py:79-81`) opt-in 이 꺼져 있으면 분류기가 게이트 **전에** `denied`(`gate.via: "espprobe-policy"`)로 끝낸다. `authorize(policy_key=…)` 가 생기면 그쪽으로 옮긴다. 모르는 키는 거부한다 |

### 2.6 다른 서버와의 관계

**거부 규칙의 공통 조건**: 아래의 계측기 거부(pweh-esp·uart·sigrok·jtagulator)는 **유효한 `instrument-pin` 증명이 하나라도 있을 때만** 켜진다. 고정된 계측기가 없으면 지금 동작 그대로다(특히 유일한 하드웨어 경로인 pweh-esp 방법 A).

**pweh-esp**(대상 전용, 읽기 전용 그대로): 쓰기 거부(`esp-policy`)는 바뀌지 않는다. 계측기 거부를 더한다.
1. esptool 을 띄우기 전(PnP): 부모 iSerial 을 정규화한 MAC, 또는 고정 증명에 기록한 USB-Serial/JTAG iSerial·aux 식별·`LocationPaths` 가 유효한 `instrument-pin` 의 subject 와 맞으면 `instrument_port` 로 거부한다(승인 경로 없음).
2. **fail closed**: 303a:* 포트의 부모 iSerial 을 확인할 수 없으면(PnP 실패·시간 초과) flash-id 로 넘어가지 않고 안내와 함께 거부한다. 핀을 지키는 방어는 이 단계뿐이다. esptool 연결은 이미 리셋·스텁(MODIFY, architecture §4)이다.
3. `esp_chip_info` 의 `MAC:` 이 고정 목록에 있으면 덤프 전에 멈춘다. 증거 오염만 막는 2차 방어다.
- 이유: 계측기 이미지를 "대상 펌웨어"로 기록하면 증거가 오염된다. esptool 리셋은 버스를 잡은 계측기를 끊고 핀 글리치를 만든다.
- 예외는 고정 **전**의 역할 전환 백업뿐이다(§5.4).

**같은 보드가 303a:1001 로 보일 때**(부팅 창 §2.3, ROM 다운로드 모드, 다른 펌웨어):
- VID:PID 가 아니라 **고정 식별**로 정한다. MAC 정규화(예시 값): `F4:12:FA:12:34:56`·`F412FA123456`·esptool `MAC:` → `f412fa123456`.
  303a:1001 의 iSerial(콜론 MAC 형태)이 base MAC 인지는 [미확인]이라, 역할 전환 백업 때 PnP 에서 본 그 보드의 USB-Serial/JTAG iSerial 도 고정 증명에 묶는다(§5.5). 1b 에서 `read-mac` 과 대조한다.
- 고정된 계측기가 303a:1001 로 보이면 `pinned-instrument-boot-or-rom` 으로 표시하고 어느 서버도 열지 않는다. 몇 초 넘게 이어지면 ROM 다운로드 모드로 보고, 사람에게 **하네스를 먼저 분리한 뒤** 전원을 다시 넣게 안내한다.

**pweh-uart**:
- `instrument`·`instrument-aux` 표지 포트와 고정 식별이 맞는 포트는 거부한다. 브리지(2d)는 `bridge` 표지의 case·세션이 맞을 때만 연다.
- espprobe 가 `bridge_port: "COM9"`(OS 이름)을 돌려주면 에이전트가 `uart_open` 한다. 콘솔 바이트 분류는 pweh-uart guard 가 그대로 한다. MCP 서버끼리 부를 수 없으니 guard 를 복제하지 않는다.
- **TX 를 켠 CDC1 은 USB-UART 어댑터와 같다.** COM 을 직접 여는 프로그램에게는 분류 없는 바이트 경로이고, 지키는 것은 pweh-uart guard 뿐이다.
  `rx_only` 는 펌웨어가 강제하고(CDC1 입력을 버림), pweh-uart 도 `rx_only` 표지면 쓰기 도구를 명확한 오류로 거부한다.
- SET_LINE_CODING = 대상 baud, SEND_BREAK = UART break(pweh-uart 에서 지금처럼 MODIFY). CDC 의 DTR/RTS 는 대상에 연결하지 않는다.
- 하트비트를 잃으면 펌웨어가 TX 핀을 입력으로 돌린다. uart 세션에는 무응답으로 보인다(문서화). 서버는 브리지 정지·하트비트 상실·해제 때 `bridge` 표지를 지운다.

**pweh-jtagulator**:
- 호스트 코드를 코어로 옮겨 공유한다: JEP106 해석(`jtagulator_mcp/jep106.py` → `pweh.jtag.jep106`), 순열 수·`lower_bound_seconds`, 결과 형식 `pweh.pinout-scan/v1`(`pweh.jtagulator-scan/v1` 일반화), UART 프로브 분류 `classify_uart_probe`(`classify.py:103` → `pweh.safety.probes`).
- 스캔 자체는 각 펌웨어 안에서 돈다.
- 차이: espprobe 는 3.3 V 고정이다. VADJ 가 없으므로 DESTRUCTIVE 전압 설정 대신 `wiring` 증명(사람이 잰 전압) + 펌웨어 VREF 감시를 쓴다. 의도적으로 보내는 것은 IDCODE·BYPASS·전부 1 IR 뿐이고 채널이 적다.
- `jtagulator_connect` 는 `instrument` 표지·고정 식별 포트를 거부한다(Ctrl-X·CR 을 보내므로).

**pweh-sigrok**:
- 캡처는 코어로 옮긴 `write_srzip`(지금 `sigrok_mcp/writers.py:83`, sigrok-cli 0.7.2 가 읽음)으로 `signals/*.sr` 에 쓴다. 그다음은 `sigrok_file_info`·`sigrok_estimate_baud`·`sigrok_decode` 오프라인이다.
- 직렬 `conn` 이 `instrument`·`bridge` 표지나 고정 식별 포트면 거부한다(ols 탐색은 바이트를 보낸다).

**pweh-openocd**:
- espprobe 는 핀아웃만 찾는다. 디버그·메모리 덤프는 실제 어댑터 + pweh-openocd(usbipd 또는 port-routing P3 의 `openocd.exe` + `tcl port pipe`)로 한다.
- pweh-openocd 에는 어댑터 허용 목록이 없다(표준 cfg 는 그대로 통과, `openocd_mcp/process.py:175-215`). esp-usb-bridge 를 붙일 때(3단계) 새로 둔다. WinUSB 자동 설치 덕에 그 경로는 관리자 단계 없이 Windows 쪽에서 끝난다.

**pweh-play**:
- 같은 펌웨어 계열이다. `firmware/common` 은 **전송 독립**이어야 한다. play 는 PC 쪽이 보드 USB-UART 이고(game-console §3.4), probe 는 네이티브 USB CDC 다.
- 프로필·바이너리·USB 디스크립터·PID·HELLO `build_profile` 은 따로다. 각 서버는 자기 프로필만 받는다.
- 실행 중 역할 전환은 없다. 한 보드 = 한 역할(결정 D1).

**pweh-flipper**: 둘 다 있으면 Sub-GHz·NFC·125 kHz·IR 은 Flipper, 로직 캡처·ADC·에이전트 주도 SPI 이중 읽기는 espprobe.

## 3. 역할

### 3.0 공통 규칙

**전기** [높음: 데이터시트 v2.2]:
- GPIO 입력 한계는 VIH 최대 **VDD+0.3 V**(표 5-4)다. 표 5-1 의 −0.3–3.6 V 는 전원 핀 값이다. VIH 최소는 0.75×VDD ≈ 2.48 V, VIL 최대는 0.25×VDD 다.
- 5 V 입력은 계측기를 망가뜨린다. 1.8 V 신호는 VIH 최소보다 낮아 **HIGH 가 보장되지 않는다.** 3.3 V 출력은 1.8 V 대상을 망가뜨린다.

**하네스 프로필**(배선 증명에 기록하고 분류기·펌웨어 핀 표가 따른다. 펌웨어는 하네스를 확인할 수 없으므로 증명이 근거다. 단계 이름 P0… 와 겹치지 않게 H 로 쓴다):
- **H0** 맨 DevKit, 3.0–3.6 V 대상만. 출력은 직렬 330 Ω, 입력은 직렬 ≥1 kΩ, ADC 는 ≥100 kΩ 분압.
- **H1** 방향 제어형 레벨 변환기 + 직렬 저항 + 3V3·5V 핀이 없는 커넥터. 1.8 V·5 V 대상, 출력 채널 확장, JTAG/SWD 스캔에 쓴다(결정 D3).
  - 내부 풀업이 없고, 한쪽 전원이 0 이면 출력이 Hi-Z 가 되는(VCC 분리·Ioff) 부품을 쓴다. 예: 74LVC8T245·74AVC4T245 계열 [미확인: 부품 데이터시트로 확정]. VCCB = 대상 VREF.
  - 입력 전용 채널은 DIR 를 대상→계측기로 배선에서 고정한다. 방향을 바꾸는 채널(스캔)은 묶음별 DIR 를 펌웨어가 정한다.
  - 모든 묶음의 /OE 는 출력 허용선 하나가 연다. 그 선은 외부 저항으로 꺼짐이 기본이고, 리셋·다운로드 모드에서 입력(Hi-Z)인 GPIO21/41/42 중 하나가 구동한다(아래).
- **H1a** 자동 방향 변환기(TXS0108E·TXB0108 류). TXS 는 대상 쪽에 약한 풀업을 걸고, TXB 의 원샷은 에지를 구동한다.
  허용하지만 **변환기를 켜는 모든 역할을 MODIFY** 로 본다(JTAGulator 수동 TXD 스캔 = MODIFY 선례, `jtagulator_mcp/classify.py:66`).
- **H2** 계측기가 대상에 전원 공급 — 정책 거부.
- **떼어 낸 칩의 전원**: 기본은 **외부 벤치 전원**(전류 제한)이고 VREF 는 칩 VCC 에서 잰다.
  대안은 좁게 증명한 '소켓의 단독 칩' 프로필로, 계측기 3V3 를 칩 VCC 에 허용한다. 단독 칩에는 역전원 위험이 없고 3.3 V 칩만 된다(결정 D7).
  **'회로 내 칩 + 계측기 3V3 연결'은 증명 화면의 명시적 거부 항목**이다.

**리셋·다운로드 모드의 핀 상태**(배선된 채로 일어날 수 있다):
- ROM 의 USB-OTG 다운로드 모드는 기본으로 켜져 있고 Joint Download Boot 에 들어 있다(DS 표 3-3).
  그 모드에서 ROM 은 **GPIO40(MTDO) = 출력 HIGH, GPIO39(MTCK)·GPIO38 = 출력 LOW** 로 만들고, GPIO21/41/42 는 입력으로 둔다(TRM v1.8 표 33.4-2) [높음: 표 / 중간: 모든 진입 경로에 해당하는지].
  TRM 은 OTG 다운로드가 필요 없으면 eFuse 로 끄라고 권하지만, eFuse 굽기는 PWEH 범위 밖이다.
- 들어가는 경로: BOOT 를 누른 채 리셋, 재플래시·업그레이드의 BOOT+RESET, aux USB-UART 의 자동 리셋, 부팅 창 303a:1001 의 DTR=1.
- 그래서:
  - **GPIO38/39/40 은 대상에 배선하지 않는다**(핀 표에서 금지, 증명 화면에 '연결 금지'). OE 제어는 GPIO21/41/42 중 하나이고, 극성은 그 핀이 Hi-Z 일 때 외부 저항이 변환기를 끄는 쪽으로 정한다(능동 Low /OE 면 풀업, 능동 High OE 면 풀다운).
  - **다운로드 모드에 들어가는 모든 절차(재플래시·업그레이드·되돌리기) 앞에 하네스 분리 단계를 둔다**(§5.4). aux USB-UART 는 반드시 뽑고, 꽂혀 있으면 연결을 거부한다(§5.5).
  - 배선된 동안 BOOT·EN 을 누르지 않는다. **비상정지는 대상 전원 차단, 그다음 하네스 분리**다.
    계측기 USB 를 뽑으면 H1 은 VCC 분리로 출력이 Hi-Z 가 되지만, H0 은 대상 신호가 직렬 저항을 거쳐 꺼진 계측기로 흘러든다.

**핀 표**(보드 프로필마다 컴파일, HELLO `pins_allowed`. 펌웨어는 PINS_CLAIM 에 실린 하네스 값의 표를 적용한다):
- **절대 금지**:
  - 0·3·45·46: 스트래핑(45 는 VDD_SPI 전압).
  - 19·20: USB.
  - 26–32: 플래시·PSRAM. 33–37: 옥탈 모듈(모든 보드에서 뺀다).
  - 43·44: UART0. 43 은 ROM 부트 텍스트를 내보낸다 → 대상 U-Boot 에 줄바꿈 = 직전 명령 반복.
  - 38·39·40: 다운로드 모드에서 ROM 이 구동한다(위). 38 은 DevKitC-1 v1.1 의 RGB LED 이고, 39 는 리셋 때 약 풀업이 걸릴 수 있다(EFUSE_DIS_PAD_JTAG=0).
  - 48: v1.0 의 RGB LED. 47·48 은 R8V/R16V 에서 1.8 V VDD_SPI 영역이다(DS 표 2-1 각주 4).
  - LCD_CAM PCLK 전용 패드(아래).
- **H0 출력 가능**(전원 투입 글리치 없음, 리셋 때 IE, 다운로드 모드에서 입력): **GPIO21, 41, 42**. GPIO47 은 3.3 V VDD_SPI 모듈로 확인한 보드 프로필에서만 더한다(리셋 때 IE, 글리치 표에 없음).
  - H0 의 출력은 정확히 셋(+47)이다. SPI(CS·SCK·MOSI 출력 3 + MISO 입력)는 딱 맞고, I2C(SDA·SCL 오픈드레인 2)도 된다. JTAG/SWD 스캔은 후보 채널마다 출력이 필요하므로 H1/H1a 가 필수다.
- **입력 전용 허용**: GPIO1, 2, 4–18. 전원 투입 때 60 µs 글리치가 있으므로(DS 표 2-2: 1–17 은 Low, **18 은 Low·High 둘 다**) 직렬 ≥1 kΩ 또는 ≥100 kΩ 분압일 때만 쓴다.
  ADC1 = GPIO1, 2, 4–10(GPIO3 = ADC1_CH2 는 스트래핑이라 제외).
- H1/H1a 는 변환기 뒤에서 GPIO1–18 을 출력과 DIR 제어에도 쓴다. OE 가 꺼져 있는 동안의 글리치는 대상에 닿지 않는다.
- **LCD_CAM PCLK 패드**: S3 의 LCD_CAM 캡처는 패드 하나를 PCLK **출력**으로 구동하고 다시 입력으로 받는다(ok-home `logic_analyzer_ll.c:136-140`, README:28 "one GPIO pin not connected anywhere") [높음].
  그래서 '입력 전용' 캡처에도 출력 패드가 하나 생긴다. 보드 프로필은 아무 데도 연결하지 않는 전용 패드를 컴파일하고, 펌웨어는 그 패드를 PINS_CLAIM 에서 늘 거부한다.
  기본 후보는 GPIO40(어차피 대상 배선 금지)이다. 보드 회로가 그 핀을 쓰지 않는지는 1b 에서 확인한다 [중간].

**배선 순서**: 대상 전원을 끈 채 GND 먼저(safety.md §2) → 계측기를 USB 로 켜고 HELLO 확인 → 대상에 연결 → 대상 전원.
- 남는 위험: 배선된 상태에서 계측기가 패닉·워치독으로 리셋되면 입력 전용 핀의 전원 투입 글리치가 다시 생길 수 있다. 직렬 저항은 전류만 제한한다 [중간].
  그래서 리셋·스트랩·플래시 /CS·/WP·/HOLD·TRST 선은 제외 채널로 증명한다.

**`wiring` 증명** — 모든 핀 연결 도구에 필요하다(입력 전용 OBSERVE 포함).
- `espprobe_wiring_declare` 가 계획의 해시를 만들고 `attestation_required` 를 돌려준다.
- 계획: 채널→패드·역할, 하네스(H0/H1/H1a), **전압 도메인**(출력 묶음마다 하나: 이름·VREF 채널·분압비·채널 목록), 제외 채널, SPI 칩 문맥(떼어 냄: 벤치 전원 또는 소켓 / 회로 내: 대상 자체 전원·SoC 리셋 유지), I2C 장치 `{addr, kind}`.
  한 VREF 점으로는 3.3 V 레일 옆의 1.8 V 플래시·JTAG 영역 같은 혼합 전압 보드를 다룰 수 없어서 도메인을 나눈다.
- 사람이 증명 화면에서 **도메인마다 멀티미터로 잰 전압과 I2C 주소 폭을 직접 입력**하고, "보드 USB-UART 케이블 없음" 항목에 답한다. 연결된 세션이 있으면 서버는 VREF 채널의 ADC 값을 옆에 보여 주고 ±10% 넘게 다르면 거부한다.
- 바인딩 = 케이스 + 계측기 + `boot_id` + `usb_session` + 계획 해시, **연결마다**(결정 D4 — JTAGulator 와 같음). 연결 해제·`boot_id`·`usb_session` 변화로 무효다. 연결이 끊긴 동안 클립을 옮겨도 서버는 알 수 없기 때문이다.
- 이 증명(사람이 잰 전압) + 펌웨어 VREF 감시가 JTAGulator 의 DESTRUCTIVE 전압 설정 단계를 대신한다. 이 점을 safety.md §2.8 에 적는다.

**출력 활성 조건**(펌웨어):
- 다음이 모두 맞을 때만 그 도메인의 출력과 OE 를 켠다: 게이트를 통과한 연산의 PINS_CLAIM, 하트비트, VREF 가 증명값 ±10% 안(H0 는 3.0–3.6 V 안이기도 해야 한다).
- **VREF 는 연속으로 감시한다.** ADC1 연속(DMA) 모드로 ≤1 ms 마다 재고, 창을 벗어나면 해제한다(목표 ≤2 ms, §9 실측).
  작업 도중 대상이 꺼지면 330 Ω 출력이 꺼진 대상을 역전원하는데, 이것을 막는다. VREF 0 V(대상 꺼짐)에서는 처음부터 켜지 않는다.
- 구동력은 최약(약 5 mA 단계)으로 고정한다. GPIO 레벨 설정·PWM·전원 제어 연산은 없다.

**job**(JTAGulator 방식):
- 도구 호출이 PINS_CLAIM → *_BEGIN(매개변수 고정) → 연산 한 번(READ_RANGE passes=2 / CAPTURE / SCAN)을 보낸다.
- job 은 DATA/EVT 수신·파일 쓰기·HB·크레딧·ABORT(INTERACT)만 한다. 실제로는 크레딧마다 회로 내 MODIFY 버스 읽기가 이어지므로(openocd 청크 방식에 가깝다) BEGIN 고정이 안전의 근거다.
  그래서 크레딧 규칙(§2.4)을 architecture §4 의 job 규칙에 명시한다: "크레딧은 BEGIN 때 고정된 연산의 흐름 제어이고 확장이 아니다".
- 배타 키는 `espprobe:<instrument_id>` 다. 크레딧을 주기 전마다 케이스 소유/허가와 `boot_id`·`usb_session` 을 다시 확인하고, 다르면 ABORT → `released`.

**분류기** `espprobe_mcp.policy.classify_probe_op(op, args, hello, wiring)`:
- 규칙 id 는 `espprobe.<영역>.<동작>` 이다.
- 허용 목록 밖 연산은 펌웨어가 광고해도 `status: denied`(`gate.via: "espprobe-policy"`, 승인 경로 없음)다. 꺼진 opt-in(§2.5)도 같다.
- 승인 지문: `{tool, instrument_id, route{backend, lock_key, device_id}, fw_image_sha256, op, pins(정규화), harness, hz, offset, length, read_cmd, passes, output_name, wiring_attestation_id, safety_hash}`.
  타임아웃·approval_id 는 넣지 않는다. `safety_hash` 는 유효한 안전 설정의 해시다(common-core §6).

**위험도** — 대상 선에 주는 전기적 영향으로 정한다:
- 고임피던스 입력(H0 의 직렬 저항 입력, H1 의 DIR 고정 입력 묶음): **OBSERVE**. 로직 캡처·핀 활동이 여기에 든다.
- 고정된 약한 DC 부하(ADC 분압 ≥100 kΩ 가 대상 선을 GND 쪽으로 당김): **INTERACT**. 전압 조사가 여기에 든다. `jtagulator_gpio_read` 의 INTERACT 는 변환기 풀업 때문이라 근거로 쓰지 않는다.
- 풀(45 kΩ)·구동, 그리고 H1a 에서 변환기를 켜는 모든 역할: **MODIFY** + `wiring`. 떼어 낸 칩도 같다(서버는 칩을 떼어 냈는지 확인할 수 없다).
- **DESTRUCTIVE 도구는 없다.** 계측기 전원 공급(H2)·BLE 본딩은 정책 거부다.

### 3.1 역할 요약

| 역할 | 도구(부록 A) | 위험 | 펌웨어 강제 | 서버 강제 | 단계 |
|---|---|---|---|---|---|
| GPIO·ADC 패드 식별 | `espprobe_voltage_survey`, `espprobe_pull_test`(2d) | INTERACT / MODIFY | 입력·풀 없음, ADC1 만(ATTEN3 0–2.9 V, ±50 mV), 풀 시험은 45 kΩ 약 풀만 | `wiring`(분압비·채널 표), 분압비 환산, 후보 분류(GND·1.8/3.3 V·TX 출렁임·RX 유휴 HIGH). 멀티미터를 대신하지 않는다 | 1c |
| 로직 캡처 | `espprobe_logic_capture_start` | OBSERVE · job (H1a 면 MODIFY) | 입력 채널만 클레임, PCLK 는 전용 패드, LCD_CAM 8채널, 샘플레이트·길이 컴파일 상한(실측 전 ≤10 MHz. ok-home 표: PSRAM 8M 샘플 @10 MHz, 내부 RAM 140k 샘플 @80 MHz [중간]) | `signals/<name>.sr`, `samples`/`duration_ms` 중 정확히 하나(sigrok 규칙), 이후 `sigrok_*` 오프라인 | 1c |
| UART 핀·보드레이트 찾기 | `espprobe_pin_activity`(TX·보드레이트), `espprobe_uart_rx_scan_start`(2d) | OBSERVE / MODIFY · job | 활동 감시는 입력만, RX 스캔 문자열 길이 상한 | 수동 TX 찾기 먼저. RX 스캔 문자열은 코어 콘솔 분류기로 한 번 보낸 형태와 두 번 이어 붙인 형태를 모두 검사(jtagulator 와 같음). 대상이 U-Boot 프롬프트면 거부(빈 줄 = 직전 명령 반복) | 1c / 2d |
| UART 브리지 | `espprobe_uart_bridge_start`/`stop` | OBSERVE(rx 만) / MODIFY(tx) / 정리 | CDC1⇄UART, `rx_only` 면 CDC1 입력을 버림, 시작 때 TX 에 아무것도 안 보냄, 하트비트 상실 → TX 입력 | `bridge` 표지 → pweh-uart guard 가 바이트 분류, 정지·해제 때 표지 삭제. TX 를 켠 CDC1 = USB-UART 어댑터(§2.6) | 2d |
| SPI NOR 읽기 | `espprobe_spi_flash_probe`, `espprobe_spi_flash_read_start` | MODIFY / MODIFY · job | §3.2 opcode 허용 목록, 단일 송신 함수, raw `spi_master`, 클럭 상한, CS 유휴 HIGH | 칩 문맥 증명(회로 내 = 대상 자체 전원 + SoC 리셋 유지, 계측기 전원 없음 / 떼어 냄 = 벤치 전원 또는 소켓 프로필), 이중 읽기, 원장, `dumps/` | 1c |
| I2C·25xx·93Cxx EEPROM 읽기 | `espprobe_i2c_scan`, `espprobe_i2c_eeprom_read_start`, `espprobe_spi_eeprom_read_start`(2d), `espprobe_microwire_read_start`(2d) | MODIFY(·job) | I2C 쓰기 단계 = 정확히 증명된 주소 폭 → 반복 START → 읽기(데이터 바이트·중간 STOP 없음), quick-write 미컴파일. 25xx 는 `03`/`05` 만, 93Cxx 는 READ(110b)만이고 EWEN 코드가 없다 | 주소 폭은 사람이 입력한 `i2c_devices` 에서만, 스캔 범위는 사람이 지정(i2cdetect 의 read-byte 부작용 선례), 이중 읽기 | 1c / 2d |
| JTAG/SWD 핀아웃 스캔 | `espprobe_jtag_scan_start(kind)`, `espprobe_jtag_read_ids`, `espprobe_jtag_bypass_test`, `espprobe_swd_scan_start` | MODIFY · job / MODIFY | §3.3 | H1/H1a 필수, `wiring` 제외 채널, 순열 수·하한 미리 보고, `pweh.pinout-scan/v1` | 2d |
| Wi-Fi·BLE 수동 분석(소유 기기) | `espprobe_wifi_scan`, `espprobe_radio_target_enroll`, `espprobe_wifi_mgmt_capture_start`, `espprobe_ble_scan`, `espprobe_ble_adv_capture_start` | OBSERVE(·job). 능동 스캔은 INTERACT 이고 opt-in 없으면 거부 | 별도 프로필 `probe-radio-s3`(§3.4) | `module-kc`·`radio-target` 증명, 비대상은 개수만, 시간·크기 한도(§4) | 3(선택) |
| IR 수신 | `espprobe_ir_rx_start` | OBSERVE · job | RMT RX 만(RMT TX 미링크), 입력은 복조 수신 모듈 | `wiring` | 3(선택) |

**I2C 주소 폭이 두 겹인 이유**: 1바이트 주소인 24C02 에 2바이트 주소를 보내면 둘째 바이트가 페이지 버퍼에 데이터로 들어간다.
내부 쓰기 사이클은 STOP 에서만 시작되므로 펌웨어의 STOP 금지(반복 START)가 한 겹, 사람이 입력한 주소 폭이 또 한 겹이다. 둘은 서로 독립이다 [중간: 일반 데이터시트 동작].

### 3.2 SPI NOR 읽기 전용 (펌웨어가 버스 트랜잭션 단위로 강제)

- **허용 목록(v1)**: `03 READ`, `0B FAST_READ`, `9F RDID`, `90 REMS`, `AB RES`(깊은 절전 해제, 휘발성), `5A SFDP`, `05 RDSR1`.
  - `13`/`0C`(4바이트 주소 읽기)는 **펌웨어 자신의 SFDP 파싱**이 >128 Mbit + 4바이트 명령 지원을 보일 때만 쓴다. 호스트가 고르지 못한다.
- **`0x35` 는 어디서도 허용하지 않는다.**
  - ISSI·Macronix·AMIC 에서 `0x35` 는 QPI 진입이다(flashrom `flashchips/issi.c:376` "QPI enable 0x35, disable 0xF5", `macronix.c:2042,2246`, `amic.c:726`) [높음].
  - QPI 에 들어간 회로 내 칩은 단일 SPI 에 응답하지 않는다. 대상이 전원 재투입 전까지 부팅하지 못할 수 있다.
  - 조사 노트의 serprog 초안·JEDEC 게이트 표에 있던 `35`·`15` 는 가져오지 않는다. SR2/SR3 가 필요해지면 RDID 를 키로 한 제조사별 표로만 연다(3단계).
- **거부 목록 방식이 아닌 이유**: 같은 바이트의 뜻이 제조사마다 다르고(`0x35`), AT45 DataFlash 는 WREN 없이 버퍼 쓰기·지우기를 한다. `06`/`50` 은 2차 방어선으로 명시해서 막는다.
- **단일 송신 지점**:
  - 모든 송신은 `probe_spi_xfer(opcode, addr, len)` 하나다. 첫 줄에서 허용 목록을 검사하고, CS 를 내리는 최하위 HAL 함수가 첫 바이트를 다시 대조한다. 어긋나면 `E_INTERNAL`.
  - **ESP-IDF `esp_flash` 는 대상 버스에 쓰지 않는다.** `esp_flash_init()` 의 `set_io_mode` 는 QIO/QOUT 에서 QE 가 꺼져 있으면 WREN + 16비트 WRSR 로 상태 레지스터를 쓴다(`esp_flash_api.c:354`, `spi_flash_chip_generic.c:834-875`) [높음].
- **이중 읽기**는 한 펌웨어 연산 안의 두 패스다.
  - 패스마다 장치 SHA-256(하드웨어)과 호스트 sha256 을 비교한다(전송 무결성). 패스1 과 패스2 를 비교한다(버스 안정성).
  - 다르면 `match=false` 로 두 파일을 보존한다(pweh-esp 규칙). 회로 내 클럭은 기본 ≤10 MHz 를 권장한다.

### 3.3 JTAG/SWD 스캔 (2d)

- 펌웨어가 **의도적으로** 보내는 것은 TLR·IDCODE DR 읽기·전부 1 IR(BYPASS)뿐이다. SWD 는 라인 리셋 + DPIDR 읽기만 한다. 토글률·시간 상한이 있고 하트비트를 잃으면 해제한다.
- **"전부 1 이 아닌 IR 을 의도적으로 시프트하지 않는다"까지만 보장한다.** 순열 스캔에서 후보 TCK/TMS/TDI 가 엉뚱한 패드에 걸리면 실제 TAP 이 임의의 상태 순서로 클럭된다.
  그러면 전부 1 이 아닌 IR 값(EXTEST 류·벤더 비공개 포함)이 들어갈 수 있고, JTAG 이 아닌 패드도 토글된다.
  그래서 PWEH 는 JTAGulator 스캔을 MODIFY("충돌·동작 변화 가능")로, IR/DR 탐색·EXTEST 는 DESTRUCTIVE 로 둔다(`classify.py:39,54-61`). espprobe 도 스캔은 MODIFY 이고 IR/DR 탐색·EXTEST 도구는 없다.
- 완화: 순열마다 TMS=1 로 TCK 를 5회 이상 주고(Test-Logic-Reset) 핀을 Hi-Z 로 되돌린다. TRST·리셋·스트랩·플래시 선은 증명된 제외 채널로 둔다. 남는 위험은 safety.md §2.8 에 적는다.

### 3.4 Wi-Fi·BLE 수동 분석 (3단계, 별도 프로필)

- **두 프로필로 나눈다.** 기능 플래그 없는 한 빌드에 무선을 넣으면 유선 프로필의 "무선 없음"을 증명할 수 없다. ADC2·DMA·메모리도 Wi-Fi 와 겹친다.
  - `probe-wired-s3`(v1): Wi-Fi/BT 를 링크하지 않는다. 최종 ELF 에 `esp_wifi_init`·`esp_bt_controller_init`·`ieee80211_*` 이 없어야 한다(§5.2).
  - `probe-radio-s3`: 핀 구동 연산이 없는 수신 전용 계측기다. 무선 blob 안의 송신 코드는 뺄 수 없으므로 검사는 응용 오브젝트를 본다(§5.2).
  - `esp_wifi_80211_tx` 는 sanity check 를 덮어쓰지 않아도 beacon·probe request/response·action·non-QoS data 를 보낸다 [높음: ESP-IDF Wi-Fi Vendor Features]. beacon spam·karma 를 막으려면 API 자체를 참조하지 않아야 한다.
- **펌웨어**:
  - 무차별 필터는 **관리 프레임만** 받는다(ESP-IDF 기본은 MISC 를 뺀 전부).
  - 대상 BSSID/MAC 필터를 펌웨어에서 적용한다. 비대상 프레임은 버리고 개수만 센다.
  - **대상 프레임 안의 제3자 주소도 가린다.** addr1–3 중 등록 대상도 브로드캐스트도 아닌 주소는 USB 로 보내기 전에 고정 자리표시값으로 바꾼다(소유 AP 의 probe/assoc 응답·deauth 에 들어 있는 가족 기기 MAC 등).
  - 스캔은 수동을 명시한다(기본 국가 "01" 은 1–11 채널·정책 AUTO). 국가는 KR, 송신 출력·PHY·안테나는 기본값 그대로다.
  - IP 스택·결합·SoftAP 없음. BLE 는 observer 만(광고·GATT 서버·HID·SMP 없음). S3 Wi-Fi 는 2.4 GHz b/g/n 만이다.
- **대상 등록(`radio-target`)** — 비대상 식별자는 에이전트 응답·케이스·감사로 나가지 않는다(common-core §5):
  - 기본: 사람이 기기 라벨·설정 화면의 BSSID/MAC 을 **증명 화면에서 직접 입력**한다.
  - 대안(근접·전원 재투입, game-console §5.2 와 같음): 사람이 대상 기기를 끄고 켜는 동안 펌웨어가 그에 맞춰 나타났다 사라진 후보 몇 개만 고른다.
    후보는 서버의 대기 중 증명 레코드(`.pweh/state/attestations/`, 보호 대상)로만 가고 `pweh attest` TTY 화면에만 보인다. 결정 직후 지우고 에이전트 응답에는 넣지 않는다.
    비대상 식별자가 장치를 떠나는 유일한 예외이므로 기본값으로 두지 않는다.
  - `espprobe_wifi_scan`·`ble_scan` 은 채널별 개수·RSSI 분포와 등록 대상의 존재만 돌려준다.
  - **BLE RPA(주소가 바뀌는 대상)는 지원하지 않는다.** 풀려면 IRK 가 있어야 하고, 그것은 본딩(정책 거부)이 필요하다. 호스트 쪽 필터링으로 대체하지 않는다. 모든 주소를 내보내야 하기 때문이다.
- **서버**: `module-kc` 증명(모듈 표시·KC 번호 사진을 `notes/` 에), `radio-target` 증명, 캡처 시간·크기 한도.
  결과: `rf/wifi/<name>.pcap`(대상만, 제3자 주소는 가림), `rf/ble/<name>.jsonl`, 비대상 개수 `…counts.json`.
- **3단계에서 따로 정할 것**: GATT 연결·열거·읽기(대상 상태가 바뀐다 → MODIFY, central 링크 필요), 소유 SoftAP 프로비저닝 관찰(양쪽 소유 증명 필요).

## 4. Wi-Fi·BLE 역할의 법·개인정보 (법률 자문 아님)

원문은 law.go.kr 에서 2026-10-19 에 조회했다(MST·시행일·조문 모두 확인 [높음]). 판례는 대법원 2022. 10. 27. 선고 2022도9877.

| 법령 | MST | 시행일 |
|---|---|---|
| 전파법 | 276245 | 2026-01-02 |
| 전파법 시행령 | 278235 | 2025-10-01 |
| 통신비밀보호법 | 290003 | 2026-10-02 |
| 통신비밀보호법 시행령 | 290505 | 2026-10-02 |
| 정보통신망법 | 290001 | 2026-10-02 |
| 개인정보 보호법 | 283839 | 2026-09-11 |
| 위치정보법 | 277359 | 2025-10-01 |
| 형법 | 290185 | 2026-10-02 |

| 행위 | 조문 (요지) | PWEH 처리 |
|---|---|---|
| 계측기 자체(무선국) | ESP32-S3-WROOM-1 적합등록 R-R-es5-ESP32S3WROOM1(2022-03-31, "특정소출력 무선기기(무선데이터통신시스템용 무선기기)", 전파법 제58조의2제3항) [높음: Espressif KCC PDF]. 그 분류가 고시 제2026-9호 8호(2.4 GHz "10㎽ 이하 또는 10㎽/㎒ 이하")와 같으므로 기본 출력이면 시행령 제25조4호의 신고 불요로 본다 [높음: 분류 일치 / 결론은 추론]. WROOM-1U·WROOM-2·MINI-1U·DevKit 보드는 Espressif KC 목록에 없다. 제58조의10①(개조·변조, 제84조6호) | `module-kc` 증명 전에는 무선 프로필 연결 거부. 출력·PHY·안테나 불변. 유선 프로필은 무선을 켜지 않는다 |
| 수동 수신·비콘 관찰 | 수신 전용은 신고 불요(제19조의2, 시행령 제25조3호) | OBSERVE |
| 능동 스캔(프로브 요청 송신) | KC 기기 정상 동작 | INTERACT, 운영자 opt-in(`safety.espprobe.wifi_active_scan`) 없으면 게이트 전에 거부 |
| deauth·disassoc·재밍 | 전파법 제29조①②(혼신 금지)·제82조②(5년/5천만원, 미수 ③), 통비법 제2조7호("전기통신의 송ㆍ수신을 방해"도 감청), 정보통신망법 제48조③(제71조①12호), 형법 제314조② | 정책 거부 — 코드 없음 |
| beacon spam·probe response(karma)·evil portal | 혼신(제29조), 정보통신망법 제49조의2①(속이는 행위로 정보 수집, 제72조①2호) | 코드 없음 |
| BLE 광고 spam·스푸핑 | 정보통신망법 제48조③·형법 제314조② 소지 | 코드 없음 |
| 남의 데이터 프레임 내용 | 통비법 제3조①·제16조①(1–10년). 2022도9877 [1]: 제3자는 일방 동의만으로 부족 | 펌웨어 관리 프레임 필터 — 데이터 프레임 미수집 |
| EAPOL·PMKID | 형법 제316조②(비밀장치 전자기록), 통비법 | 정책 거부 |
| 남의 AP 결합·WPS | 정보통신망법 제48조①(제71조①11호). 2022도9877 [3]: 접근권한 주체 = 서비스제공자 | 결합 코드 없음 |
| 비대상 MAC·SSID(프로브 요청 등) | 개인정보 보호법 제2조1호나목(쉽게 결합해 식별), 제58조의2(익명정보 적용 제외), 위치정보법 제15조①(제40조4호) | **장치를 떠나지 않는다**: 비대상 프레임은 버리고 개수만, 대상 프레임 안의 제3자 주소는 가림, 등록은 사람이 입력한 식별자(§3.4). OUI 뒤 약 24비트라 솔트 HMAC 도 되돌릴 수 있다(common-core §5). 대상의 PNL SSID 는 케이스에만, 응답·보고서는 마스킹, 게이트 `action` 은 솔트 다이제스트 |
| 감청설비 | 통비법 제10조①(인가, 제17조①4호). 시행령 제3조: "감청목적으로 제조된 기기ㆍ기구가 아닌 것으로서 … 5. 「전파법」 제58조의2에 따라 적합성평가를 받은 방송통신기자재등"은 제외 | **열린 질문**: 스니퍼 목적 펌웨어를 올린 KC 보드가 이 단서를 잃는가 → 무선 프로필은 기본 꺼짐(`safety.espprobe.radio_profile`), 운영자 opt-in(D2) |

- 2022도9877 [2](비공개 조치 없는 방송의 시청자는 당사자)를 평문 브로드캐스트 관리 프레임에 유추해 "감청 아님" 쪽으로 본다. 추론이다 [중간].
- 남는 열린 질문(사람·법률 확인):
  - 시행령 제3조 단서.
  - 별표6의2 1.자 개인 반입 면제가 제25조4호의 "적합성평가를 받은"에 해당하는가.
  - 응용 펌웨어 교체가 제58조의10 개조·변조인가.
  - 소유 기기↔제조사 클라우드 통신의 당사자성(기본은 메타데이터만).
  - 고정 스니퍼 기록이 위치정보법의 "측위"인가.
  - 프로토콜 수준 deauth 판례 부재(제82조·제48조③).
  - BLE 20 dBm 의 KR 기준 분류.
- 유선 역할은 무선을 쓰지 않아 이 표의 대상이 아니다. 소유/허가 기기만이라는 PWEH 범위(safety.md §1)는 같다.

## 5. 펌웨어 빌드·배포·플래시와 식별 고정

### 5.1 소스·프로필

- **소스**: `firmware/common/`(프레임·CRC·HELLO·하트비트·세션·해제·정책 표 생성기, 전송 독립) + `firmware/espprobe/` + `firmware/input-bridge/`(2b, game-console §3.4).
  - `firmware/espprobe` 는 **HAL 경계**를 둔다. `probe_spi_xfer`·I2C 시퀀서·JTAG/SWD 엔진·VREF/OE 인터록·해제 경로는 HAL 만 부르고 ESP-IDF 를 직접 부르지 않는다. 그래야 진짜 C 코드를 호스트에서 시험할 수 있다(§8).
- **툴체인**: ESP-IDF v6.1 + esp_tinyusb 2.4.x.
  - Arduino/PlatformIO 는 쓰지 않는다. S3 변형 기본 PID 가 303a:1001 이고 재현성이 약하다.
  - zig 는 Xtensa 를 지원하지 않는다. 펌웨어 빌드에는 못 쓰고 C 코어·HAL 계층의 호스트 시험에만 쓴다.
- **프로필**: `probe-wired-s3`(v1, 보드 프로필 `esp32s3-devkitc1-v1.0`/`-v1.1` × 모듈 VDD_SPI 3.3 V/1.8 V), `probe-radio-s3`(3단계), `input-bridge-*`(2b). 기능 플래그 없이 프로필마다 한 빌드다.
- **모든 프로필의 `sdkconfig.defaults`**: `CONFIG_TINYUSB_DESC_SERIAL_STRING=""`, CDC 2·HID 0·MSC 꺼짐·벤더 없음, `CONFIG_APP_REPRODUCIBLE_BUILD=y`. 전역 정의 `CFG_TUD_CDC_TX_OVERWRITABLE_IF_NOT_CONNECTED=0`.

### 5.2 빌드 검사 (빌드 실패 조건 — 정확한 목록은 구현 때 ELF 를 보고 확정)

- **응용 오브젝트**(`firmware/common`·`firmware/espprobe` 의 오브젝트를 map 파일·`nm -u` 로)가 참조하면 안 되는 것:
  - `esp_wifi_80211_tx`, BLE 광고·GATT 서버·SMP·HID API.
  - `esp_flash_init`·`esp_flash_write*`·`esp_flash_erase*`, `spi_bus_add_flash_device`(외부 칩을 플래시 장치로 붙이는 길), `esp_efuse_write*`.
  - `rmt_new_tx_channel`, `tud_hid_*`·`tud_msc_*`, `httpd_start`·`lwip_listen`·mDNS.
- 최종 ELF 의 심볼 존재만으로는 어느 버스를 향한 호출인지 알 수 없다. IDF 구성요소가 계측기 자기 플래시(NVS·파티션, 무선 프로필의 PHY 데이터)를 위해 `esp_flash_write` 를 정당하게 링크할 수 있다. 그래서 응용 오브젝트를 본다.
- **어디에도 없어야 하는 것**: `ieee80211_raw_frame_sanity_check` 의 강한 정의, 링커 `-zmuldefs`·`--allow-multiple-definition`, objcopy `--weaken-symbol`.
- **유선 프로필 최종 ELF**: Wi-Fi/BT 초기화(`esp_wifi_init`·`esp_bt_controller_init`)와 `ieee80211_*` 가 없다. 무선 라이브러리를 링크하지 않으므로 최종 ELF 검사가 유효하다.
- **sdkconfig**: §5.1 값이 아니면 실패한다(특히 iSerial 문자열이 비어 있지 않으면).
- 핀 방향(예: PCLK 출력)·opcode·I2C 순서·IR 값은 심볼로 보이지 않는다 → 호스트 시험(§8)이 맡는다.
- 빌드 스크립트가 이 검사를 돌린다. 저장소에는 아직 CI 가 없다(`.github/` 없음). CI 가 생기면 같은 명령을 돌리고, 그 전에는 external pytest(§8)와 릴리스 절차가 돌린다.

### 5.3 빌드·배포

- **빌드**: 기본은 고정 다이제스트 `espressif/idf:v6.1@sha256:…` Docker 이미지 + `CONFIG_APP_REPRODUCIBLE_BUILD=y` 로컬 빌드(`scripts/build_firmware.sh`)다. 빌드 전에 Docker 데몬과 로컬 고정 이미지의 사용 가능 여부를 확인한다.
  - 산출물: 병합 이미지(오프셋 0x0 — S3 ROM 부트로더 오프셋 `ESP_ROM_BOOTLOADER_OFFSET_FLASH (0x0)`, `esp_rom_caps.h:41` [높음]), 개별 bin, ELF, map, `SHA256SUMS`, 빌드 검사 결과, 매니페스트.
- **배포**: sha256 을 고정한 사전 빌드를 저장소에 둔다(헬퍼 무결성 방식, port-routing §5.2). install.sh 구성요소 `espprobe-fw`(선택)가 대조한 뒤 `~/pweh-tools/firmware/espprobe/<ver>/` 에 둔다.
  - 로컬 ESP-IDF 설치(S3 도구 다운로드 약 652 MB [중간])는 개발자 선택이다. EIM 오프라인 모드는 Python ≥3.11 이 필요한 것으로 보여(v6.0 문서, 호스트 3.10.12) 쓰지 않는다 [중간].
- **매니페스트** `src/pweh/data/espprobe-releases.json`:
  ```
  {version, git_commit, idf_version, docker_digest, profile, board, files[{name, offset, sha256, size}], merged{name, sha256},
   image_sha256, usb{vid, pid, product, serial_rule: "upper_hex(base_mac)"}, caps, limits, pins_allowed, pclk_pad, spi_read_opcodes, radio, tx_caps}
  ```
  - `image_sha256` 은 펌웨어가 HELLO 에서 계산하는 값(앱 파티션의 `esp_partition_get_sha256`)으로 정의하고, 빌드가 같은 알고리즘으로 기록한다. appended digest는 digest 자신을 제외한 이미지 바이트의 해시이고, 배포 `app.bin` 전체 SHA256 및 ELF SHA256과 별도 필드다.

### 5.4 계측기 플래시 = 사람 단계 (pweh-esp 쓰기 거부는 그대로)

**결정(2026-10-20, D1)**: 사용자가 가진 기존 S3 보드는 분석 **대상**으로 유지한다(덮어쓰지 않음). 계측기는 사용자가 따로 준비하는 ESP32-S3 보드에 쓴다.
그 보드도 플래시 내용이 사용자 데이터일 수 있으므로 덮어쓰기 전에 검증된 백업이 케이스에 있어야 한다(safety.md §4 규칙 6) — 새 보드라도 같은 절차로 백업을 남긴다.

0. **하네스 분리**: 계측기에 대상 배선이 없음을 사람이 확인한다. 다운로드 모드는 GPIO38–40 을 구동한다(§3.0). 업그레이드·되돌리기도 이 단계로 시작한다.
1. **백업**: 케이스 하나(소유 증명 포함, 예 "내 ESP32-S3 계측기 준비")에서 `esp32-flash-dump`.
   - `esp_chip_info`(모듈·PSRAM·플래시 전압·MAC) → `esp_security_info` → `esp_read_flash_start(verify="double")`, `match=true`.
   - pweh-esp 는 chip-info(MAC, PnP 식별 — 네이티브 포트였다면 USB-Serial/JTAG iSerial, 보드 USB-UART 였다면 그 브리지 식별)와 security-info 를 원장에 기록한다(§2.5 기반 개정).
   - `cases/` 는 비어 있어 이전 덤프는 없다(2026-10-19 확인).
2. **`espprobe_flash_plan(case_id, port, board, version)`** — OBSERVE, 장치 I/O 없음.
   - **원장만 읽는다.** 그 MAC 의 `verify=double`·`match=true` 백업 기록과, 같은 MAC 의 security-info 기록(플래시 암호화·Secure Boot·Secure Download Mode 모두 꺼짐)이 있을 때만 정확한 명령을 보여 주고 감사 로그에 남긴다.
     케이스 파일·에이전트 인자는 믿지 않는다(common-core §3). game-console §3.5 `write_plan` 과 같은 방식이다.
   - 보안 상태가 켜져 있으면 그 보드는 계측기로 쓰지 않는다.
3. **사람이 자기 Windows 터미널에서 실행**한다. 에이전트는 실행하지 않는다(pweh-esp 거부 그대로, safety.md §4 규칙 11 확장).
   네이티브 포트 경로(명령마다 BOOT 를 누른 채 RESET → 303a:1001 ROM 모드, COM 번호가 바뀔 수 있다):
   ```
   sha256sum <merged.bin>                                                   # (WSL) 매니페스트와 대조
   esptool.exe --chip esp32s3 --port COMn --before no-reset read-mac       # 백업한 MAC 과 대조. 끝나면 기본 hard-reset 으로 앱이 돈다
   # 다시 BOOT 를 누른 채 RESET
   esptool.exe --chip esp32s3 --port COMn --before no-reset --after hard-reset --baud 460800 write-flash 0x0 <wslpath -w merged.bin>
   ```
   - 보드 USB-UART 포트로 하면 자동 리셋이 되므로 `--before default-reset` 이다. 끝나면 그 케이블을 뽑는다.
   - `--after no-reset`·`soft-reset` 은 쓰지 않는다. 레거시 스텁이 끝날 때 FLASH_BEGIN 으로 상태 레지스터를 다시 쓰기 때문이다(architecture §4 의 esp-policy 와 같은 이유). `--erase-all`·`--force`·eFuse 명령도 쓰지 않는다.
   - `write-flash` 의 자동 검증("Hash of data verified.")과 `--after hard-reset` 뒤 상태는 [미확인: 실기]다. 더 강한 확인이 필요하면 다시 BOOT+RESET 하고 `verify-flash` 를 돌린다.
   - 이미 고정된 계측기의 업그레이드는 백업 대신 HELLO 의 현재 릴리스로 확인한다.
4. **연결**: 보드 USB-UART 케이블을 뽑고 네이티브 USB 만 꽂는다 → `espprobe_connect` → 고정 증명 → HELLO.
- **되돌리기**: `pweh attest --revoke`(고정 해제) → 하네스 분리 → 사람이 백업 이미지를 같은 방식으로 기록한다. PWEH 는 명령만 보여 준다.

### 5.5 식별 고정 (고정 먼저, HELLO 는 나중)

1. **목록**: `espprobe_list_ports` 는 포트를 열지 않고 PnP(부모 iSerial·MI 번호·`LocationPaths`)로 분류한다.
   `pinned-instrument` / `pinned-instrument-boot-or-rom`(고정 식별이 303a:1001 로 보임) / `instrument-aux` / `esp-target-candidate` / `usb-uart` / `unresolved`(식별 실패, fail closed) / `unknown`.
2. **고정 증명**: 유효한 `instrument-pin` 이 없으면 `espprobe_connect` 는 **바이트 0개, DTR/RTS 조작 0회**로 `attestation_required` 를 돌려준다.
   - subject 는 서버 자신의 PnP·원장에서 만든다: base MAC(백업의 chip-info, 없으면 PnP 의 TinyUSB iSerial — HELLO 가 다시 대조), TinyUSB iSerial(= `upper_hex(base_mac)`), 백업 때 본 USB-Serial/JTAG iSerial(있으면), aux 식별(있으면), `LocationPaths`(보조 키 — 다른 USB 포트로 옮기면 갱신을 안내).
   - aux 식별을 모르면 고정할 때 사람에게 보드 USB-UART 케이블을 잠깐 꽂게 해 서버가 식별을 기록하고 다시 뽑게 한다(아직 배선 전이라 안전하다).
   - 증명 항목: ① 이 포트(COMn, VID:PID, 제품 문자열, iSerial, 인터페이스 집합)는 내 계측기이고 분석 대상이 아니다. ② 이 보드에 PWEH 릴리스 `<ver>`(sha256)를 기록했다. ③ 보드의 USB-UART 포트는 쓰지 않고 비워 둔다.
   - **고정 거부**: 인터페이스 집합에 HID·MSC·벤더 클래스가 있음, VID:PID 가 303a:1001, 제품 문자열이 "PWEH espprobe" 가 아님, iSerial 이 base MAC 형식이 아님(예: `123456`). 한 MAC 은 한 번에 한 역할이다(target / espprobe / play).
3. **aux 확인**: 기록된 aux 식별이 열거에 있으면 연결을 거부한다. 열거가 실패해도 거부한다. 식별을 끝내 모르면 연결마다 `wiring` 증명의 "보드 USB-UART 케이블 없음" 항목으로만 지킨다고 결과에 표시한다.
4. **열기 순서**(port-routing §6.4 의 순서 + 계측기 확인 두 번):
   1. 케이스 확인 → `resolve`(열지 않음) → portlock(`win:COMn`).
   2. **열기 직전 PnP 재확인**: 같은 `device_id`, 부모 iSerial = 고정 MAC, 303a:4002, 제품 문자열.
   3. 분류 → authorize(INTERACT) → 헬퍼 OPEN(`dtr=0`, `rts=0` — 첫 DCB 에서 정한다, port-routing §5.2).
   4. **핸들을 쥔 채 PnP 재확인**: 그 COMn 이 여전히 같은 인스턴스인지 본다. 2와 3 사이에 장치가 바뀌었다면 열린 핸들은 새 장치의 것이라 여기서 걸린다 → 한 바이트도 보내지 않고 닫는다.
   5. 그 뒤에야 HELLO.
   - 헬퍼가 직접 확인하는 OPEN 필드(`expect_parent_instance`, 조사 노트 안)는 쓰지 않는다. 헬퍼의 PE import 허용 목록(KERNEL32 + CRT, port-routing §5.2)에 SetupAPI·CfgMgr32 를 더해야 하기 때문이다. 필요하면 port-routing 개정으로 다룬다(부록 C).
   - TinyUSB 장치라 DTR=0/RTS=0 은 신호일 뿐이다. 혹시 USB-Serial/JTAG 여도 0/0 은 다운로드 플래그 해제뿐이다(표 33.3-2). usbser 가 CreateFile 때 스스로 선을 바꾸는지는 [미확인]이다(port-routing §7).
5. **HELLO 검증** — 하나라도 틀리면 BYE·닫기·`instrument_identity_mismatch`/`firmware_not_pinned`:
   - 프로토콜 범위, `fw_name`, `build_profile` 이 probe 계열(play 프로필 거부).
   - `(fw_version, build_profile, board, image_sha256)` 가 매니페스트에 있음.
   - `base_mac` = 고정값, `usb.serial == upper_hex(base_mac)`, `usb{vid, pid, product}` = 매니페스트.
   - `caps`·`limits`·`pins_allowed`·`pclk_pad`·`spi_read_opcodes` 가 매니페스트와 **정확히** 같음(부분 집합이 아님). 유선이면 `radio="none"`·`tx_caps=[]`.
   - nonce 반향.
   - 미릴리스 실기 빌드를 허용하는 도구·설정은 아직 없다. I5 1a는 내부 시뮬레이터만 받으며 새 safety 키를 만들지 않는다.
6. **시작**: `probe/espprobe-<n>-hello.json` 을 기록하고 하트비트를 시작한다.
- **위협 모델(정직하게)**:
  - HELLO 의 해시·MAC 은 자기 보고다. 잘못된·오래된 펌웨어와 다른 보드를 연 실수는 잡지만 위조 펌웨어는 못 막는다(safety.md §3.4 의 "협조적이지만 성급한 에이전트" 수준).
  - 진짜 보호는 펌웨어에 위험한 코드가 없다는 것이다(빌드 검사 §5.2 + 호스트 시험 §8). 에이전트가 COM 을 직접 열어도 CDC0 에는 쓰기·송신 경로가 없다. TX 를 켠 CDC1 은 USB-UART 어댑터와 같다(§2.6).
  - 더 강한 확인은 사람이 하네스를 분리한 뒤 `esptool verify-flash` 로 한다.

## 6. 케이스·스키마·Skill

- **디렉터리**:
  - 새 `probe/`(`STANDARD_DIRS`, `case_paths`, `case_import_file` 허용 목록):
    `espprobe-<n>.events.jsonl`(연산·인자 요약·결정·결과 코드만, 대량 데이터 없음), `espprobe-<n>-hello.json`, `wiring-<k>.json`(계획 + 증명 id + 입력된 도메인 전압), `voltage-survey-<k>.json`, `pin-activity-<k>.json`.
  - 결과는 의미별 기존 디렉터리에 둔다:
    - `dumps/<name>.bin`·`.read2.bin`·`.json`: kind `flash-dump`, 메타데이터 `pweh.espprobe-dump/v1`.
    - `signals/<name>.sr`: `signal-capture`.
    - `jtag/espprobe-<n>-<scan>-<k>.json`: `other` + `extra.type=scan-result`, 형식 `pweh.pinout-scan/v1`.
    - 3단계: `rf/wifi/`·`rf/ble/`(game-console 의 `rf/`).
  - `extra.type` 추가: `probe-hello`, `probe-events`, `wiring-plan`, `voltage-survey`, `pin-activity`.
- **스키마**:
  - firmware-dump `method` 에 `espprobe-spi`·`espprobe-i2c`(1c), `espprobe-microwire`(2d)를 추가한다. `verification.method` 는 기존 `double-read`·`sha256-device` 를 쓴다.
    espprobe 덤프도 `skill="firmware-dump-via-uart"` 로 요약을 남긴다(architecture §3 규칙). job `result.summary_hint` 가 스키마를 그대로 통과한다(pweh-esp 방식).
  - static-analysis `firmware.source` 에 `espprobe-dump` 를 추가한다. ESP 선례 `esptool-read-flash` ↔ `esptool-dump` 와 같은 짝이다. `spi-clip` 을 겸해 쓰면 I2C EEPROM 덤프까지 섞인다.
  - uart-recon `baud_detection.method` 는 기존 값을 쓴다: `pin_activity` 는 `manual` + notes "espprobe 측정"(JTAGulator 선례), 캡처 + `sigrok_estimate_baud` 는 `logic-analyzer`.
  - signal-capture 는 변경 없음(`capture.device` = `espprobe:<instrument_id>`).
  - **유선 역할에 새 요약 스키마는 없다.** 3단계 무선 결과는 game-console 1b 에서 등록될 `rf-analysis` 에 Wi-Fi/BLE 절을 더한다(스키마는 Skill 과 같은 단계에 등록).
- **Skill**:
  - `uart-shell-acquisition`: 패드 찾기에 "ESP32 계측기 있음" 분기 — `espprobe_voltage_survey`(VCC 1.8/3.3 V → H0/H1 판단, 대상 전압 기록) → `espprobe_pin_activity`(TX·보드레이트) → 배선 안내 → USB-UART 어댑터로 콘솔(2d 부터는 espprobe 브리지도).
  - `logic-analyzer-protocol-decode`: 이 환경의 기본 캡처원으로 espprobe 를 더한다(fx2lafw 는 Zadig 사람 단계). `espprobe_logic_capture_start` → `.sr` → 기존 `sigrok_*` 오프라인.
  - `firmware-dump-via-uart`(SPI 클립 경로): "사람에게 SPI 클립 읽기 요청" 앞에 espprobe 경로 — `espprobe_spi_flash_probe` → `espprobe_spi_flash_read_start(verify="double")` → 요약 `method: espprobe-spi`. EEPROM 도 같다.
  - `esp32-flash-dump`: 역할 전환 백업 절차(§5.4 1)와 "고정된 계측기 포트는 `instrument_port` 로 거부된다" 안내.
  - `firmware-static-analysis`: `firmware.source: espprobe-dump`.
  - **master-prompt**: Phase A "모른다 + ESP32 계측기 있음 → espprobe 순서(전압 조사 → TX·보드레이트 → uart-shell-acquisition)", Phase B "SPI 플래시 + ESP32 계측기 → espprobe SPI 읽기"를 사람 SPI 클립 앞에, JTAGulator 처럼 "espprobe 순서(전용 Skill 없음)".
    장비 체크리스트: 보드 판·모듈 각인, H0/H1/H1a 하네스, 무선 프로필이면 모듈 KC 사진. §4 규칙 11 확장: "계측기 플래시는 사람만, 에이전트는 `espprobe_flash_plan` 만".
- **계약·안내 문서**(구현 단계에서 고친다):
  - architecture: §6.8 pweh-espprobe 신설, §4 job 규칙에 크레딧 규칙, §3 `probe/`, `docs/references/espprobe-protocol.md`.
  - safety.md: §2.8 "ESP32 계측기"(3.3 V·VIH·분압·역전원·다운로드 모드 핀·핀 위생·배선 순서·남는 글리치·JTAG 스캔의 남는 위험·증명이 DESTRUCTIVE 전압 단계를 대신함), §3.3 espprobe-policy, §6 비상정지 행(대상 전원 차단 → 하네스 분리, BOOT 는 비상정지 아님).
  - hardware-setup.md §9(H0/H1/H1a 하네스·직렬 저항·SOIC 클립·벤치 전원·소켓 프로필).

## 7. 단계 계획

| 단계 | ESP32 계측기 작업 | 전제 | 하드웨어 없이 검증 |
|---|---|---|---|
| 0 | 공유 코어만: common-core 0단계 + port-routing P0. espprobe 가 기대는 P1 기능(PnP `DEVPKEY_Device_Parent`·`LocationPaths` 조회, `usb-ids.yaml`, portlock·역할 표지)은 관문 전에 들어온다(README §3) | 없음 | 단위 시험, 가짜 PnP |
| **1a 완료(I5)** | **오프라인 트랙**: 프로토콜 사양·골든 프레임, `firmware/common`·`firmware/espprobe`(HAL 경계), HELLO·하트비트·해제만 있는 `probe-hello` 이미지, in-process 시뮬레이터 대상 `pweh-espprobe` 도구 6개, zig cc 호스트 시험. 독립 2회 Docker 재현 빌드·빌드 검사·릴리스·설치 검증 완료. 전역 계측기 고정 증명과 기존 pweh-esp/uart/sigrok/jtagulator의 거부 규칙, 공용 `write_srzip`·JEP106·`classify_uart_probe`·`pweh.pinout-scan/v1` 구현. 실제 포트·핀·버스 기능은 미지원 | 0 | 시뮬레이터, 골든 벡터, 호스트 C 시험, 고정 툴체인 재현 빌드 |
| 1b | **관문(README §3 = port-routing P1·P2 = 게임 1b 의 진행/중단 관문)에 ESP32 항목 추가**. 계측기용 보드가 준비되면(D1 — 기존 보드는 대상으로 유지) 검증 백업 뒤 사람이 하네스 없이 `probe-hello` 를 기록하고 §9 의 1b 항목을 확인한다. 사용자가 아직 기록을 원하지 않으면 이 항목은 1c 시작으로 옮긴다. 실패 시 대체: PowerShell SerialPort(`win-powershell`) 또는 usbipd(TinyUSB 라 리눅스 열기 펄스에도 리셋 없음) | 1a ∥ 의 `probe-hello`(재현 빌드·고정 sha256)와 거부 규칙, 사용자 동의(D1) | 가짜 헬퍼 |
| **1c** | **유선 v1(하드웨어)**: 연결·고정·HELLO, `wiring` 증명, 전압 조사, 핀 활동(TX·보드레이트), 로직 캡처(`.sr`), SPI NOR probe·이중 읽기, I2C 스캔·24Cxx 읽기, `espprobe_flash_plan`, Skill·master-prompt 갱신, 스키마 값 추가 | 1b 통과, port-routing P1·P2 | 시뮬레이터, 가짜 헬퍼 |
| 2a·2c | 변경 없음 | | |
| 2b | 입력 브리지가 1c 의 `firmware/common`·빌드·매니페스트·고정 흐름을 재사용(전송은 보드 USB-UART) | 1c | 브리지 시뮬레이터 |
| **2d** | espprobe 확장: UART 브리지 → pweh-uart, RX 스캔, JTAG IDCODE/BYPASS 스캔·`read_ids`·`bypass_test`, SWD DPIDR, 25xx·93Cxx, 풀 시험 | 1c 실기 + H1/H1a 하네스(스캔) | 가상 TAP·EEPROM |
| 3 | 선택: `probe-radio-s3`(D2, §3.4·§4), IR 수신, ESP32-S2 보드, esp-usb-bridge 패치 빌드를 pweh-openocd 어댑터로(WinUSB 자동 + `openocd.exe` pipe 또는 usbipd, 새 어댑터 허용 목록), 사람 전용 serprog-ro(MSYS2 flashrom)·SUMP(ok-home 인코더) 호환 모드 | 사용자 opt-in | 가짜 무선 프레임 |

- 0은 일부러 작게 뒀다. 1a의 오프라인 구현·거부 규칙은 완료됐으며 1b의 실기 확인은 아직 하지 않았다.
- 각 단계의 끝은 game-console §8 과 같다: 카탈로그 재생성·`--check`, architecture §6 표, `.claude/settings.json`·`.mcp.json`·pyproject, 스키마·Skill 일관성 시험, 전체 시험, 적대적 검토.

## 8. 하드웨어 없이 시험

이 절은 이후 핀·버스·헬퍼 단계의 시험 계획도 포함한다. I5 1a에서 실제 수행한 범위는 프로토콜·HELLO·하트비트·해제, HAL 경계의 호스트 C 시험, 고정 계측기 거부 규칙과 재현 빌드다. 가상 SPI/I2C/JTAG 대상·실포트 전송 시험을 완료했다는 뜻은 아니다.

- **단위**:
  - COBS 경계(0x00 연속·254바이트·빈 payload), CRC 골든 벡터, 헤더·길이.
  - HELLO 검증 행렬(필드 하나씩 틀리게, `usb.serial` = `123456`·MAC 불일치 포함), MAC 정규화.
  - PnP 파싱(채집 픽스처): 복합 장치 부모 iSerial, 부팅 창 303a:1001 + 고정 MAC, 부모 미확인 303a:*.
  - portlock 역할·표지 충돌. 분류기: 허용 목록·`denied`·하네스별 위험도·DESTRUCTIVE 0개·꺼진 opt-in 은 게이트 전 거부.
  - 덤프 메타데이터·요약 스키마, `.sr` 를 `sigrok_file_info` 가 읽는지, 매니페스트와 컴파일된 정책 표의 일치.
- **펌웨어 강제의 호스트 시험**(external, zig cc 0.17.0): `firmware/common` + `firmware/espprobe` 의 버스·정책 계층(`probe_spi_xfer`, I2C 시퀀서, JTAG/SWD 엔진, VREF/OE 인터록, 해제 경로)을 가짜 HAL 위에서 빌드한다.
  256 opcode 전부와 무작위 프레임을 넣고 단언한다:
  - 허용 목록 바이트만 가짜 HAL 에 닿는다.
  - I2C 쓰기 단계는 증명된 주소 폭 이하이고, 그 뒤는 반복 START 다(STOP 없음).
  - 전부 1 이 아닌 IR 은 엔진이 만들지 않는다.
  - 해제·VREF 상실·하트비트 상실 → 모든 패드가 한도 안에 입력이 된다.
  - PCLK 패드·금지 핀은 PINS_CLAIM 이 거부한다.
  - 골든 프레임은 파이썬 시뮬레이터와 공유한다.
- **시뮬레이터** `espprobe_mcp/sim.py`:
  - 드라이버 상수를 import 하지 않는다(`jtagulator_mcp/sim.py:1-6` 원칙 — 기준은 사양 문서·골든 프레임).
  - 전송: pty, `socket://127.0.0.1`, `.exe` 이름의 파이썬 가짜 헬퍼(port-routing §14).
  - 가상 대상:
    - W25Q128 형 SPI NOR(JEDEC EF4018 + SFDP). **허용 밖 opcode 횟수 = 0 단언**.
    - 24C02/24C256: 쓰기는 **STOP 에서만 확정**하는 모델이다. 펌웨어 순서로는 주소 폭이 틀려도 확정되지 않음을 보이고, 증명 없는 주소 폭은 서버가 거부함을 본다.
    - JTAG TAP(IR 길이 4/5). **의도적인 전부 1 이 아닌 IR 쓰기 = 0 단언**.
    - 부팅 로그를 내는 UART TX 핀, 합성 LA 신호, VREF 값.
- **오류 주입**:
  - 바이트 손실·CRC 오류·잘린 프레임.
  - **하트비트 상실 → `hb_ms` 안에 모든 핀 입력**. **VREF 가 읽기 도중 떨어짐 → 한도 안에 모든 핀 Hi-Z**.
  - 호스트 강제 종료, `boot_id` 변화 → `wiring` 무효.
  - 같은 seq 재시도 = 재실행 없음. **DONE 뒤·길이를 넘는 크레딧 → 버스 활동 없음**. 크레딧만으로는 새 연산을 시작할 수 없음.
- **서버**:
  - 고정 전 연결은 `attestation_required` 이고 가짜 헬퍼 기록에 OPEN·DATA·`L` 프레임이 0개.
  - 열기 직전·직후 PnP 재확인에서 장치가 바뀌면 DATA 0개로 닫는다. aux 가 열거에 있으면 거부한다.
  - play 프로필 HELLO 거부, 이중 읽기 일치/불일치, job 취소 → ABORT·RELEASE.
  - 브리지 표지 → pweh-uart 열기 허용, `rx_only` 쓰기 거부, 정지·하트비트 상실 뒤 표지 삭제.
  - pweh-esp: 고정 식별 거부(PnP 몽키패치), 부모 미확인 303a:* 는 fail closed, **고정이 없으면 지금 동작 그대로**, `flash-id` MAC 경로.
  - 원장에 백업·security-info 가 없으면 `espprobe_flash_plan` 거부.
  - 무선: 비대상 식별자가 도구 응답·케이스·감사·승인 레코드에 없음.
- **external**(`@pytest.mark.external`, 없으면 skip): 위 호스트 C 시험, Docker ESP-IDF 빌드(느림, opt-in — 재현 sha256 = 매니페스트, 빌드 검사 통과), 리눅스 sigrok-cli 가 espprobe `.sr` 를 읽는지.
- **hardware**(`@pytest.mark.hardware`): S3 계측기 + W25Q 브레이크아웃(알려진 이미지), 24C256, UART 루프백(1 kΩ), 알려진 IDCODE 의 JTAG 대상(RP2040/STM32).

## 9. 하드웨어로 확인할 것

**1b 관문(하네스 없이, `probe-hello`)**:
- Windows 11 열거: TinyUSB CDC×2 의 MI_00/MI_02, usbser 자동 바인딩(IAD 복합), 부모 인스턴스 ID 의 iSerial = `upper_hex(base_mac)`, `DEVPKEY_Device_Parent`·`LocationPaths` 조회, 재연결·재부팅 때 COM 번호 유지.
  **"관리자 권한 없이" 되는지는 아직 확인하지 않았다.** UAC 가 켜진 일반 사용자 PC 에서 따로 보거나 [미확인]으로 둔다.
- 부팅 창: 전원 투입·esptool hard-reset·EN·패닉·MWDT·RTC WDT·브라운아웃마다 303a:1001 이 나타나는지와 그 길이(PnP 이벤트 기록).
- 303a:1001(ROM 다운로드·부팅 창)의 iSerial 이 base MAC 인지 — `esptool read-mac` 과 대조.
- 다운로드 모드·EN 리셋 때 GPIO21/38–42(+47, PCLK 후보)의 상태: 멀티미터(정적 레벨)와 LA·스코프(리셋 순간). 표 33.4-2 가 모든 진입 경로에 맞는지.
- 헬퍼 경유: DTR=0/RTS=0 열기에 리셋·부작용이 없는지, 1 MB 왕복 처리량, 하트비트 지터·거짓 해제.
- 사용자 보드: DevKitC-1 v1.0/v1.1, 모듈(N8/N8R8/N16R8/R8V…, VDD_SPI 전압), GPIO47·PCLK 후보가 헤더에 있고 보드 회로가 쓰지 않는지, KC 표시, 보안 상태(`esp_security_info`).

**1c**: 16 MiB 이중 읽기 시간, 해제 시간(LA 로 `hb_ms` 안인지), VREF 창 이탈 → 해제 시간(목표 ≤2 ms), 선택 핀의 전원 투입·패닉·워치독 리셋 글리치, 분압 VREF ADC 정확도(±10% 판단),
LCD_CAM 실제 샘플레이트·깊이(PSRAM 유무), 회로 내 SPI 10 MHz 안정성, 24Cxx 읽기, 플래시 절차(`image_sha256` 정의 = 릴리스 값?, esptool 5.4 `write-flash` 자동 검증·`--after hard-reset` 뒤 상태, 플래시 뒤 COM 번호).

**2d**: H1 변환기(DIR 고정·OE 기본 꺼짐·VCC 분리 시 Hi-Z), 알려진 IDCODE 대상의 JTAG/SWD 스캔.

**3**: 관리 프레임 필터·수동 스캔·대상 필터·제3자 주소 가림, 비대상이 개수만 나오는지.

## 10. 사용자 결정 (기본값 포함)

| # | 결정 | 기본값(권장) |
|---|---|---|
| D1 | 기존 ESP32-S3 보드의 역할 | **결정됨(2026-10-20): 분석 대상으로 유지**. 계측기는 별도 ESP32-S3 보드(사용자 준비, 플래시 전 이중 읽기 백업·보안 상태 확인), pweh-play 입력 브리지(2b)도 별도 보드. 한 보드 = 한 역할 |
| D2 | 무선 프로필(`probe-radio-s3`) | **보류**: 유선 v1·2d 뒤 3단계. §4 의 열린 질문(통비법 시행령 제3조 단서 등)을 읽고 운영자가 `safety.espprobe.radio_profile` 로 opt-in 할 때만 연다. 범위는 소유 기기의 관리 프레임·광고, 대상은 사람이 입력한 식별자로만 등록, BLE RPA 대상은 미지원, GATT 는 그때 따로 정한다 |
| D3 | 하네스 | H0(맨 DevKit + 직렬 저항, 출력 GPIO21/41/42)으로 3.3 V 대상의 SPI·I2C 읽기와 입력 역할부터 시작한다. 1.8 V/5 V 대상·출력 셋 초과·JTAG/SWD 스캔은 H1(방향 제어형 변환기, 풀업 없음, OE 기본 꺼짐). TXS/TXB 자동 방향 모듈만 있으면 H1a 로 쓰되 그 하네스의 모든 역할은 MODIFY |
| D4 | `wiring` 증명 바인딩 | **연결마다**(케이스 + 계측기 + `boot_id` + `usb_session` + 계획 해시, 연결 해제로 무효 — JTAGulator 와 같음). 대안: 같은 `boot_id`·`usb_session` 안에서는 재연결에도 유지(편하지만 그사이 클립 이동을 못 잡는다) |
| D5 | USB PID | **303a:4002 + MAC 고정을 영구 상태로** 둔다. 전용 PID 는 선택이다. 신청한다면 espressif/usb-pids 의 `allocated-pids-espressif-devboards.txt`(0x7000–0x7015)에 "대상(303a:1001/4001/4002)과 구별하는 계측기 식별"을 근거로 적고 거절을 예상한다 |
| D6 | Flipper Zero 보유 여부(역할 순서) | 모르면 §7 순서(전압·TX·캡처 → SPI → I2C → 2d). 있으면 SPI·I2C 우선순위를 낮추고 로직 캡처·ADC 를 먼저 하며, D2 를 2d 보다 먼저 검토한다 |
| D7 | 떼어 낸 칩 읽기의 전원 | 외부 벤치 전원(전류 제한, VREF 는 칩 VCC 에서 잼). 대안: '소켓의 단독 칩' 프로필 — 계측기 3V3 허용(3.3 V 칩만, 좁은 증명). 어느 쪽이든 '회로 내 칩 + 계측기 3V3' 은 거부 |

## 부록 A. 도구 목록 (pweh-espprobe)

위험도 정의는 game-console 부록 A 와 같다. 연결 = INTERACT, 정리 도구는 게이트·승인 확인 없이 항상 동작한다. 채널 인자는 배선 계획의 채널 이름이다. H1a 하네스에서는 OBSERVE 인 핀 도구도 MODIFY 다.

| 도구 | 위험 | 비고 |
|---|---|---|
| `espprobe_version()` | OBSERVE | 서버·프로토콜 버전, 매니페스트 릴리스, 헬퍼 상태 |
| `espprobe_list_ports()` | OBSERVE | 포트를 열지 않음. PnP 부모 iSerial·MI·`LocationPaths`, portlock `held_by`, 분류(§5.5) |
| `espprobe_flash_plan(case_id, port, board, version)` | OBSERVE(장치 I/O 없음) | 원장의 검증 백업 + security-info 꺼짐일 때만 사람용 명령(하네스 분리 단계 포함). 실행 경로 없음 |
| `espprobe_connect(case_id, port, approval_id=None)` / `espprobe_disconnect(case_id)` | INTERACT / 정리 | 고정 없으면 `attestation_required`(`instrument-pin`), aux 있으면 거부, PnP 재확인 두 번, DTR=0·RTS=0, HELLO 검증 / RELEASE+BYE·portlock·표지 해제 |
| `espprobe_status(case_id=None)` | OBSERVE(장치 I/O 없음) | 세션·하트비트·점유 핀·VREF 창·브리지·job |
| `espprobe_release_all(case_id)` | 정리 | 모든 핀 Hi-Z·OE 끔 |
| `espprobe_wiring_declare(case_id, channels, harness, domains, excluded, chip_context=None, i2c_devices=None)` | 증명 | 계획 해시 → `attestation_required`(`wiring`), 도메인 전압·주소 폭은 사람이 입력 |
| `espprobe_self_test(case_id)` | INTERACT | 대상 핀을 쓰지 않음 |
| `espprobe_voltage_survey(case_id, channels)` | INTERACT | ADC1, 분압비 환산(분압 = DC 부하) |
| `espprobe_pin_activity(case_id, channels, duration_s=5)` | OBSERVE | 에지 수·펄스 폭·유휴 레벨 → TX 후보·보드레이트 추정 |
| `espprobe_logic_capture_start(case_id, channels, samplerate, samples=None, duration_ms=None, trigger=None, output_name=None)` | OBSERVE · job | `signals/<name>.sr`, PCLK 는 전용 패드 |
| `espprobe_spi_flash_probe(case_id, freq_hz=1000000)` | MODIFY | JEDEC ID·SFDP·SR1(배선 계획의 CS/SCK/MOSI/MISO) |
| `espprobe_spi_flash_read_start(case_id, offset=0, size="all", output_name=None, freq_hz=None, read_cmd="auto", verify="double", approval_id=None)` | MODIFY · job | `dumps/`, 한 연산 두 패스, 원장 |
| `espprobe_i2c_scan(case_id, addr_lo, addr_hi, freq_hz=100000)` | MODIFY | read-byte 탐색만, 범위는 사람 지정 |
| `espprobe_i2c_eeprom_read_start(case_id, dev_addr, size, output_name=None, freq_hz=100000, verify="double")` | MODIFY · job | 주소 폭은 증명에서 |
| `espprobe_spi_eeprom_read_start(…)`, `espprobe_microwire_read_start(…)` (2d) | MODIFY · job | 25xx 03/05, 93Cxx READ |
| `espprobe_uart_bridge_start(case_id, rx_channel, tx_channel=None, baud=115200)` / `espprobe_uart_bridge_stop(case_id)` (2d) | OBSERVE(rx 만)·MODIFY(tx) / 정리 | `bridge_port`(COMn) → `uart_open`, 정지 때 표지 삭제 |
| `espprobe_uart_rx_scan_start(case_id, channels, text="\r", known_pins=None, …)` (2d) | MODIFY · job | 코어 콘솔 분류기, U-Boot 프롬프트면 거부 |
| `espprobe_jtag_scan_start(case_id, channels, kind="idcode"\|"bypass", known_pins=None, max_tck_hz=None, …)`, `espprobe_swd_scan_start(…)` (2d) | MODIFY · job | H1/H1a 필수, `pweh.pinout-scan/v1`, 순열 수·하한, 순열마다 TLR + Hi-Z |
| `espprobe_jtag_read_ids(case_id, tck, tms, tdo)` / `espprobe_jtag_bypass_test(case_id, tdi, tdo, tck, tms)` (2d) | MODIFY | |
| `espprobe_pull_test(case_id, channels)` (2d) | MODIFY | 45 kΩ 약 풀 |
| `espprobe_wifi_scan(case_id, passive=True)`, `espprobe_ble_scan(case_id, passive=True)` (3) | OBSERVE / INTERACT(능동, opt-in 없으면 거부) | 개수·RSSI 분포·등록 대상 존재만 |
| `espprobe_radio_target_enroll(case_id, label, method="typed")` (3) | 증명 | `typed`: 사람이 식별자 입력(기본). `proximity`: 후보는 TTY 화면에만, 결정 직후 삭제 |
| `espprobe_wifi_mgmt_capture_start(case_id, channel, duration_s)`, `espprobe_ble_adv_capture_start(case_id, duration_s)` (3) | OBSERVE · job | 대상만, 제3자 주소 가림, 비대상은 개수만 |
| `espprobe_ir_rx_start(case_id, channel, duration_s)` (3) | OBSERVE · job | RMT RX |
| `espprobe_job_status/cancel/jobs` | — | `register_job_tools(server, rt, "espprobe")`, 취소 = ABORT → RELEASE |

정책 거부(도구도 펌웨어 코드도 없음, 승인 경로 없음): §1.3 전부.

## 부록 B. 근거와 이 문서가 정한 것

**B.1 조사·검증 자료**(로컬 `research/esp32-instrument/`, 저장소에는 없음 — 노트와 이 문서가 다르면 이 문서가 우선):
- 조사 노트: `firmware-landscape.md`(펌웨어 지형·공격 기능 표·커밋 고정), `pweh-fit-safety-legal.md`(데이터시트 수치·핀 위생·법령 원문·판례), `protocol-integration.md`(USB 컨트롤러 비교·와이어 프로토콜·식별·빌드).
- 검증 정정 요약: `verification-digest.txt`. 두 관점의 전체 결과와 1차 소스 사본(TRM 33장·데이터시트 텍스트, esp-usb `fc9bead`, tinyusb, flashrom, ok-home, KCC PDF, 법령 XML, mcp-c-sdk)은 작성 세션의 작업 디렉터리에만 있고 저장소에는 없다.

**B.2 노트끼리 어긋나 이 문서가 정한 것**:
- 이름 `pweh-espprobe`/`espprobe_*`. 링크는 TinyUSB OTG(USB-Serial/JTAG 권고는 기각). 전송 표기는 `COMn` + `PortRoute`(내부 URL 없음).
- 핀: H0 출력은 GPIO21/41/42(+47), 그 밖은 변환기 OE 뒤. 38–40 은 금지. 하네스 이름 H0/H1/H1a/H2.
- 무선은 별도 프로필·3단계. SPI 허용 목록에서 `0x35` 제외.
- 위험도는 대상 선에 주는 전기적 영향으로 정한다(떼어 낸 칩도 MODIFY, DESTRUCTIVE 도구 없음). 하트비트 1000 ms.
- 고정 저장소는 새 보호 디렉터리 대신 `instrument-pin` 증명. 스키마 값은 `espprobe-dump`(`spi-clip` 겸용 안 함).
- 법령은 safety-legal 노트의 조문·MST·시행일을 쓴다.

**B.3 적대적 검증 반영**(정정마다 본문 위치):
- 안전·구조: 부팅 창 303a:1001(§2.3·§2.6) · 열기 직전·직후 PnP 재확인(§5.5) · 다운로드 모드 핀·OE 극성·하네스 분리·aux 필수 제거·BOOT 는 비상정지 아님(§3.0·§5.4) ·
  VREF 연속 감시·도메인·D4 연결마다(§3.0) · 하네스별 위험도·H1 방향 제어형·PCLK 패드(§3.0) · JTAG 보장 범위·TLR(§3.3) · 크레딧 BEGIN 고정(§2.4) · opt-in 키(§2.5) ·
  pweh-esp 조건부 fail closed·`LocationPaths`(§2.6) · 무선 등록·제3자 주소·RPA(§3.4) · 기반 개정·flash_plan 원장(§2.5·§5.4·부록 C) · 빌드 검사 범위(§5.2) · 떼어 낸 칩 전원(D7) ·
  CDC1 동등성·표지 삭제(§2.2·§2.6) · 단계·24Cxx STOP 모델·호스트 C 시험·`safety_hash`(§7·§8·§3.0).
- 사실·라이선스: iSerial 기본값 `123456`(반박, §2.3·§5.1) · ok-home·JTAGenum·Ebiroll 라이선스, Arduino/Bit Pirate PID, GhostESP BadBLE, esp-usb-bridge WinUSB·매직 baud, MSYS2 flashrom(§2.2) ·
  데이터시트 표 5-1/5-4·GPIO18(§3.0) · mcp-c-sdk(§1.1) · usb-pids(§2.3·D5) · `esp_rom_caps.h:41`, tinyusb 0.21.0~2 줄 번호 · usbser 문서·EIM [중간] · libusb 전제(§1.2).
- **판정이 엇갈린 것**: KC 등록을 안전 관점은 "확인 불가"(PDF 텍스트 추출 실패)로, 사실 관점은 "확인"(ToUnicode CMap 으로 PDF 디코드)으로 판정했다. 1차 소스를 해독한 쪽을 따라 [높음]으로 두었다.
- **근거를 붙여 유지한 것**: `voltage_survey` 를 INTERACT 로 둔다(분압 = DC 부하). 안전 관점이 `pin_activity`(OBSERVE)와의 불일치를 지적했고, 이를 부하 기준 규칙으로 풀었다.

**B.4 이 문서를 쓰며 1차 소스로 직접 확인한 것**:
- TRM v1.8 표 33.3-2·§33.4.1·표 33.4-2(p.1252–1253).
- esp_tinyusb 2.4.0 `Kconfig:190-202`·`usb_descriptors.c:104-120`.
- 데이터시트 v2.2 표 2-1(GPIO21/41/42/47/48 리셋 IE, 각주 4)·표 2-2(GPIO1–20 만 글리치).
- ok-home `esp32s3/logic_analyzer_ll.c:1-8,136-140`(CC0 표시, PCLK 출력)·README:20-28.
- PWEH `esp_mcp/ports.py:250`, `jtagulator_mcp/classify.py:39,54-70`, `src/pweh/safety/gate.py:79-81`, `src/pweh/schemas/{firmware-dump,static-analysis,uart-recon}.schema.json`, `docs/architecture.md` §4·§6.7, `docs/safety.md` §2·§3.4·§4·§6, `cases/`(비어 있음), `.github/`(없음).

## 부록 C. 다른 설계 문서에 필요한 개정 (이 문서는 그 문서들을 고치지 않는다)

- **common-core.md**
  - 머리말 "…이 이 기반 위에 선다"에 `ESP32 계측기([esp32-instrument.md](esp32-instrument.md))` 를 더한다.
  - §1 표에 행 넷을 더한다(제안 위치 | 역할 | 지금 상태):
    - `src/pweh/jtag/jep106.py` | JEP106 제조사 코드 해석(jtagulator·espprobe 공용) | `jtagulator_mcp/jep106.py` 에만
    - `src/pweh/jtag/pinout_scan.py` | 순열 수·`lower_bound_seconds`, 결과 형식 `pweh.pinout-scan/v1`(`pweh.jtagulator-scan/v1` 일반화) | jtagulator 서버 안(`jtagulator_mcp/server.py:862`)
    - `src/pweh/safety/probes.py` | UART 프로브 문자열 분류 `classify_uart_probe`(한 번·두 번 이어 붙인 형태) | `jtagulator_mcp/classify.py:103` 에만
    - `src/pweh/srzip.py` | sigrok `.sr` 쓰기 `write_srzip`(espprobe 캡처·sigrok 공용) | `sigrok_mcp/writers.py:83` 에만
  - §1 `portlock.py` 행의 역할 표지를 "(instrument / instrument-aux / target / bridge)"로 바꾼다.
  - §3: 바인딩에 "계측기 전역(철회할 때까지)"을, 레코드에 "사람이 입력한 값" 항목(y/n 외)을 더한다. 예시 `kind` 에 `instrument-pin`·`radio-target`·`module-kc` 를 더한다.
  - §4: 원장이 산출물 외에 기기 사실(pweh-esp `esp_chip_info`·`esp_security_info`)도 기록하게 하고, 확인하는 곳에 `espprobe_flash_plan` 을 더한다.
  - §6: `safety.espprobe.*`(좁히는 한도와 운영자 opt-in 구분)를 키 목록에 더한다.
  - §8: 크레딧 규칙("BEGIN 고정 연산의 흐름 제어, 확장 아님")을 job 규칙 옆에 더한다.
  - §9: 펌웨어 위치에 `firmware/common/`·`firmware/espprobe/` 를 더한다.
- **port-routing.md**
  - 머리말 "이 설계를 쓰는 곳"에 `[esp32-instrument.md](esp32-instrument.md)(계측기 COM 포트·식별 고정·역할 표지)` 를 더한다. §13.2 "어떤 도구가 Windows COM 을 얻나"에 "pweh-espprobe: 처음부터 헬퍼"를 더한다.
  - §4.4 `usb-ids.yaml`: `303a:4002`(espprobe) 항목, `303a:1001` 의 `transitions` 에 부팅 창.
  - §6.5: 역할 `instrument-aux`, "`instrument` 표지 포트는 그 계측기 서버만 연다", 표지와 별도로 `instrument-pin` 증명을 거부 근거로 본다.
  - §7 장치별 표: espprobe 행(TinyUSB CDC, `reset_wiring: none`, 둘 다 끔, 1b 확인 전 `reset_risk: possible`).
  - §15: ESP32-S3 계측기 행(부팅 창, 다운로드 모드 핀).
  - (선택) §5.2: 헬퍼 OPEN 의 `expect_parent_instance` 를 원하면 import 허용 목록에 CfgMgr32 를 더하는 개정.
- **game-console-flipper-rf.md**
  - §3.5: `fw_patch_build` base 로 "원장 기록이 있는 espprobe 이중 읽기 덤프"를 받는다.
  - §3.4·§8 2b: 입력 브리지가 `firmware/common`·빌드·매니페스트·고정 흐름을 공유한다(전송은 보드 USB-UART, 하트비트 300 ms 그대로).
- **README.md**(이미 이 문서를 링크하고 1a·관문·1c·2d·3 배치가 같다): §3 "관문" 행에 "ESP32 `probe-hello` 확인(MI_00/MI_02·부팅 창·다운로드 모드 핀·303a:1001 iSerial — esp32-instrument §9)"을, "1a" 행에 "espprobe 거부 규칙(pweh-esp/uart/sigrok/jtagulator)·코어 이동"을 더한다. §5.2 9번은 그대로 맞다(세부는 §10 D1–D7).

### I5 1a 구현 범위

현재 `pweh-espprobe`는 여섯 도구의 in-process 시뮬레이터 전용이다. 위 실기 도구·배선·flash-plan·포트라우팅은
이후 단계 설계다. 운영 계약은 [architecture.md](../architecture.md) §6.10, wire 규약은
[espprobe-protocol.md](../references/espprobe-protocol.md)를 따른다. 시뮬레이터와 C 호스트 시험은 실제
USB 열거·해제 지연·Hi-Z를 증명하지 않는다. 이 항목은 1b에서 사람이 확인한다.

`probe-hello` 0.1.0은 고정 소스와 툴체인으로 독립 2회 빌드한 산출물이 일치했고, 릴리스·설치 검증까지 끝났다.
산출물은 `firmware/releases/espprobe/0.1.0/`, 재현 절차와 검사는 [espprobe-build.md](../references/espprobe-build.md)에 있다.
