---
name: esp32-flash-dump
description: Dump the SPI flash of an ESP32-family MCU (ESP32, ESP32-S2/S3/C3/C6/H2) over USB with esptool through the pweh-esp MCP server, for authorized/owned devices only. On WSL it runs the Windows esptool.exe on the board's COM port (Method A, port COM3, no usbipd attach); the Linux esptool on /dev/ttyACM0 or /dev/ttyUSB0 after usbipd attach is the alternative. It checks chip, MAC and flash size (esp_chip_info) and the security state (esp_security_info - Secure Download Mode, flash encryption, Secure Boot), reads the whole flash twice and compares sha256 (esp_read_flash_start, verify double), guides BOOT+RESET download mode, and records the firmware-dump summary for firmware-static-analysis. Read-only - never write_flash, erase_flash, espefuse or espsecure, and never bypasses Secure Download Mode or flash encryption. Triggers - ESP32, esptool, read_flash, ESP32 flash dump, ESP32 firmware dump, COM3, download mode, Secure Download Mode, flash encryption. ESP32 펌웨어 덤프, ESP32 플래시 덤프, ESP32 플래시 읽기, 다운로드 모드, 플래시 암호화.
---

# ESP32 플래시 덤프 (esp32-flash-dump)

`orchestrator/master-prompt.md` Phase B 의 ESP32 경로다. 소유/서면 허가가 기록된 케이스에서만 쓴다. pweh-esp 서버(esptool)로 플래시를 **읽기만** 한다. 결과는 연구·방어용이다(공격 페이로드나 제3자 시스템 공격 없음).
포트 종류, 방법 B(리눅스 esptool + usbipd), 응답 필드와 요약 매핑, 파티션 표 읽기, 시간 계산은 [reference.md](reference.md) 에 있다.
서버 설명은 `mcp-servers/esp-mcp/README.md`, 물리 안전은 `docs/safety.md` §2.7 이 근거다.

## 목적

- ESP32 계열 칩(ESP32, ESP32-S2/S3/C3/C6/H2 …)을 USB 로 연결해 칩·MAC·플래시 크기와 보안 설정(Secure Download Mode, 플래시 암호화, Secure Boot)을 확인한다.
- SPI 플래시 전체를 esptool `read-flash` 로 **두 번** 읽어 sha256 이 같은 덤프를 `dumps/<name>.bin` 으로 남긴다(2차 읽기 `dumps/<name>.read2.bin`, 메타데이터 `dumps/<name>.json`).
- 다음 Skill(firmware-static-analysis)이 찾도록 firmware-dump 요약을 **skill="firmware-dump-via-uart"** 로 기록한다(master-prompt §5). 이 Skill 은 자기 요약 스키마가 없다.

## 언제 쓰나

- **쓴다**: 대상이 ESP32 계열 MCU 이고 보드에 USB 커넥터(ESP 내장 USB-Serial/JTAG 또는 USB-UART 브리지)가 있을 때. "ESP32 펌웨어 덤프", "esptool read_flash", "COM3 로 플래시 읽기" 요청.
- **쓰지 않는다**
  - 케이스나 소유/허가 증명이 없다 → master-prompt Phase 0.
  - 리눅스 SoC(카메라·DVR, U-Boot) 펌웨어 → uart-shell-acquisition → firmware-dump-via-uart.
  - 플래시 쓰기·삭제, eFuse, 복구·업데이트 → 범위 밖. pweh-esp 에는 그런 도구가 없다(ESP32 원복은 사람이 PWEH 밖에서 한다, `docs/safety.md` §5).
  - 공식 펌웨어 파일만 분석한다 → `case_import_file` 후 firmware-static-analysis.
- USB 커넥터가 없는 제품 보드(UART0 패드만 있음)의 배선 안내는 이 Skill 범위 밖이다. 사람이 `docs/safety.md` §2.2·§2.7(3.3V 로직, 어댑터 VCC 미연결)에 따라
  USB-UART 어댑터를 UART0 에 이미 연결했다면 그 어댑터의 포트로 같은 절차를 쓴다(자동 리셋 회로가 없으므로 템플릿 B).

## 전제 조건

- **case_id**: `case_get` 의 case.authorized 가 true 여야 한다. 아니면 멈춘다(master-prompt §1-1). 서버도 소유/허가 증명이 없는 케이스의 하드웨어 도구를 `authorization_required` 로 거부한다.
- **이전 요약** (`case_get_step_results(case_id)`): firmware-dump-via-uart 요약의 data.method 가 `esptool-read-flash` 이고 verification.match=true 면 검증된 덤프가 이미 있다 → 다시 읽지 않는다.
- **하드웨어**: ESP32 보드와 **데이터용** USB 케이블. WSL2 면 보드를 Windows 에 연결한 그대로 둔다(방법 A, usbipd attach 하지 않음).
- **소프트웨어**: esptool. 설치는 사람이 `scripts/install.sh --only esptool` 로 한다(리눅스 esptool 5.4.0, WSL interop 이면 Windows esptool.exe 도). `esp_version` 으로 확인한다.
- **MCP 서버**: pweh-case, pweh-esp, pweh-fwtriage(8단계 내용 확인, 선택).

## 안전 규칙

1. **소유/허가 확인과 `case_create` 가 먼저다.** 그 전에는 `esp_chip_info`·`esp_security_info`·`esp_read_flash_start` 를 부르지 않는다. `esp_version`·`esp_list_ports` 는 포트를 열지 않지만 이 Skill 은 케이스를 확인한 뒤에 쓴다.
2. **읽기 전용이다.** 다음은 실행하지도 제안하지도 않는다.
   - esptool `write-flash`, `erase-flash`, `erase-region`, `write-flash-status`, `write-mem`, `load-ram`, `run` (v4 이름 `write_flash`·`erase_flash` 도 같다).
   - espefuse 의 `burn-efuse`·`burn-key`·`burn-bit` 같은 `burn-*` 명령, `write-protect-efuse`, `read-protect-efuse` (eFuse 는 되돌릴 수 없다). espsecure 전체.
   - 서버에는 이런 명령을 보내는 도구가 없다. 만든 argv 가 읽기 명령이 아니면 게이트에 넘기지 않고 **바로 거부**한다(`status: "denied"`, `gate.via: "esp-policy"`). 승인 레코드가 생기지 않으므로 `pweh approve` 로도 풀 수 없다.
   - 호스트 셸에서 esptool·espefuse·espsecure 를 직접 실행하지 않는다(오프라인 `image-info` 포함, `docs/safety.md` §4-11). 앱 이미지 헤더는 pweh-fwtriage 의 `fw_esp_image_info` 로 본다.
3. **보안 기능을 우회하지 않는다.** Secure Download Mode, 플래시 암호화, Secure Boot 를 글리칭·전압 조작·eFuse 조작·키 추출·다른 도구로 다시 읽기로 넘으려 하지 않는다.
   Secure Download Mode 면 덤프하지 않고 템플릿 D 로 보고한다. 암호화된 덤프를 복호화하려 하지 않는다.
4. **게이트**: `status: approval_required`(예: `modify_policy: approve`)면 무엇을·왜·위험·되돌리는 법을 설명한다(템플릿 G). 사용자가 **별도 터미널**에서 `pweh approve <approval_id>` 하면 같은 인자 + `approval_id` 로 한 번만 재시도한다. 덤프는 호출 한 번의 승인이 두 번의 읽기를 덮는다.
   `status: denied` 면 우회하지 않는다. 다른 인자·포트 표기로 다시 보내기, 셸에서 esptool·pyserial 로 포트 직접 열기, 설정·승인 파일 수정은 모두 금지다. 템플릿 H 로 보고한다. 에이전트는 `pweh approve` 를 실행하지 않는다.
5. **연결은 MODIFY 다.** 하드웨어 도구를 부를 때마다 칩이 리셋되어 ROM 다운로드 모드로 들어가고 RAM 에 플래셔 스텁을 올린다(휘발성).
   플래시·eFuse 에 쓰는 명령은 보내지 않는다: 서버는 끝날 때 FLASH_BEGIN 을 보내는 `--after no-reset`·`soft-reset` 을 쓰지 않는다
   (레거시 스텁은 FLASH_BEGIN 때 SPI 플래시 상태 레지스터를 다시 쓴다). after="no-reset" 은 no-reset-stub 으로 바뀌어 실행되고 soft-reset 은 거부된다.
   no_stub=True 는 쓰지 않는 것이 기본이다. 꼭 써야 하면 esp_chip_info(no_stub=False)로 확인한 칩 이름을 chip 으로 명시한다(chip="auto"·"esp8266" 과 함께면
   validation_failed — ESP8266 ROM 은 스텁 없이 플래시에 연결할 때 FLASH_BEGIN 을 받는다).
   실행 중이던 펌웨어가 멈추고 재부팅되므로 템플릿 A 로 미리 알린다. 제품 안의 ESP32 면 제품 전체가 재부팅된다.
6. **한 포트에 한 작업.** 덤프 job 이 도는 동안 같은 포트로 다른 esp 도구를 부르지 않는다(`busy`). 사용자가 멈추라고 하면 즉시 `esp_job_cancel` 한다.
   Windows 에서 취소·시간 초과 뒤 esptool.exe 가 남아 그 COM 포트를 잡고 있으면 서버가 PID 를 알려 주고 같은 포트의 호출을 `busy` 로 거부한다 → 템플릿 J.
7. **증거를 덮어쓰지 않는다.** 다시 읽을 때는 output_name 을 생략(자동 번호 esp-flash-002 …)하거나 새 이름을 쓴다. 서버도 기존 파일을 덮어쓰지 않는다.
8. **덤프는 자격증명 저장소다.** NVS 의 Wi-Fi 비밀번호, 인증서·개인키, 클라우드 토큰이 들어 있을 수 있다. 케이스 밖으로 복사하거나 공유하지 않는다(`docs/safety.md` §7).

## 사용하는 MCP 도구

| 도구 | 용도 |
|---|---|
| `case_get`, `case_get_step_results`, `case_set_phase` | 권한·이전 요약·기존 덤프 아티팩트 확인, 단계 상태(phase 이름은 firmware-dump-via-uart) |
| `esp_version` | 백엔드(windows = 방법 A, linux = 방법 B)·esptool 버전·interop 확인. 기기 미접촉 |
| `esp_list_ports` | Windows COM 포트·리눅스 tty 와 USB ID 종류(kind). 포트를 열지 않는다 |
| `esp_chip_info` | esptool flash-id: 칩 종류·리비전, MAC, 플래시 제조사·크기 (MODIFY, 리셋) |
| `esp_security_info` | esptool get-security-info: Secure Download Mode, 플래시 암호화, Secure Boot, JTAG (MODIFY, 리셋) |
| `esp_read_flash_start` | read-flash job: 두 번 읽어 sha256 비교, 결과 파일·아티팩트 자동 등록 (MODIFY, 리셋) |
| `esp_job_status`, `esp_job_cancel`, `esp_jobs` | 덤프 진행 폴링(wait_seconds ≤ 50), 취소, 실행 중 job 확인 |
| `case_update_target`, `case_add_note` | soc·flash 갱신, 사람이 한 물리 작업 기록 |
| `case_hash_file` | 덤프 파일 sha256 재확인 (선택) |
| `fw_esp_partitions`, `fw_esp_image_info`, `fw_entropy` | 내용 확인: 파티션 표·앱 이미지 헤더 읽기, 암호문·잘못 읽은 덤프 판별 (선택, 오프라인) |
| `case_record_step`, `approval_status` | 실패 기록과 최종 summary(skill="firmware-dump-via-uart"), 승인 상태 확인 |

## 절차

### 1. 시작: 권한·이전 결과 확인

```
case_get(case_id="<id>", include_artifacts=true)   → case.authorized, target, artifacts[] (kind flash-dump, extra.method "esptool-read-flash")
case_get_step_results(case_id="<id>")              → summaries["firmware-dump-via-uart"]
esp_jobs(active_only=true)                         → 끊긴 세션에서 돌던 덤프 job
case_set_phase(case_id="<id>", phase="firmware-dump-via-uart", status="in-progress")
```
- 단계(phase) 이름은 firmware-dump-via-uart 다. 펌웨어 확보 단계를 여러 경로가 같이 쓰고, 9단계의 summary 저장이 이 단계 상태를 갱신한다.
- 같은 칩의 검증된 덤프(요약 method `esptool-read-flash`, verification.match=true)가 있으면 다시 읽지 않는다.
- 실행 중 job 이 있으면 7단계 폴링부터 한다. 끝난 덤프의 flash-dump 아티팩트(extra.role "primary")는 있는데 요약이 없으면(세션 끊김) `dumps/<name>.json` 을 먼저 본다.
  - status 가 "succeeded" 이고 verification.match 가 true 일 때만 다시 읽지 않고 8단계(검증)부터 한다. 값은 그 메타데이터와 두 아티팩트(primary, verification-read)의 sha256 에서 옮긴다.
  - 그 밖(status "failed"·"cancelled" 로 1차 읽기만 남음, match false·null)은 7단계 표대로 output_name 을 생략해 다시 두 번 읽고, 남은 파일은 증거로 둔다.
  - 이름은 `<name>-<job_id>` 일 수 있다(덤프 도중 같은 이름이 생겼을 때). 서버가 덤프 도중 끝났으면 다음 시작 때 그 job 기록(jobs/<id>.json)이 "abandoned" 가 되고 숨은 예약 파일은 지워진다 → 다시 읽는다.

### 2. 백엔드 고르기

```
esp_version()   → backends.windows{available, version, interop, error}, backends.linux{available, version, error}, recommended, hints
```
- WSL2 이고 backends.windows.available=true → **방법 A**(권장). Windows 에 연결된 보드를 port="COM3" 같은 Windows COM 포트로 다룬다.
  usbipd attach 가 필요 없고, 서버가 덤프 경로를 wslpath 로 바꿔 Windows esptool.exe 가 케이스 dumps/ 에 바로 쓴다.
- windows 는 안 되고 linux 만 available → 방법 B(리눅스 esptool + usbipd, [reference.md §2](reference.md#2-방법-b--리눅스-esptool--usbipd)).
- 둘 다 available=false(error 에 실행 파일 없음·interop 꺼짐) → 템플릿 I 로 설치를 요청하고 멈춘다.
- major 가 4 미만이거나 warning 이 있으면 알린다(v4.8 이상 권장).

### 3. 보드 연결과 포트 확인

먼저 템플릿 A 로 USB 연결을 요청하고(리셋 안내 포함) "완료" 를 기다린다(방법 B 는 reference §2 의 연결 템플릿). 그다음:
```
esp_list_ports()   → windows{available, ports[{port, name, usb_id, kind, description_ko}], note}, linux{ports[{port, kind, in_use_by}], hidden_legacy_ports}, hints
```

| kind (usb_id) | 연결 | 호출 방법 |
|---|---|---|
| esp-usb-serial-jtag (303a:1001) | ESP 내장 USB-Serial/JTAG (S3·C3·C6·H2 의 "USB" 커넥터) | 기본값(before="default-reset"). baud 는 속도와 무관. 리셋 때 다시 열거될 수 있다 |
| usb-uart-bridge (CP210x, CH34x, FTDI) | 보드의 USB-UART 브리지("UART"·"COM" 커넥터, 원조 ESP32 보드) | 기본값. 자동 리셋 회로가 없으면 템플릿 B. 전송 오류면 baud 를 낮춘다 |
| esp-usb-otg-rom (303a:0009, 303a:0002) | 칩이 이미 ROM USB-OTG 다운로드 모드(S2·S3) | before="no-reset", after="no-reset-stub"(after="no-reset" 도 서버가 no-reset-stub 으로 바꿔 실행). 끝나면 사람이 RESET |
| esp-usb (그 밖의 303a) | 앱이 USB 를 직접 쓴다(TinyUSB CDC) | 템플릿 B 로 다운로드 모드에 넣은 뒤 `esp_list_ports` 를 다시 부른다 |
| unknown, 포트 없음 | 충전 전용 케이블, 드라이버 없음, usbipd 로 WSL 에 붙어 있음 | 템플릿 A 를 다시 확인한다(Windows 장치 관리자) |

- 후보가 여럿이면 `[확인 필요]` 로 어느 포트가 대상 보드인지 묻는다. 추측하지 않는다.
- windows.available=false 면 note(interop·powershell 문제)를 알리고, 사람이 장치 관리자에서 읽은 COM 번호를 쓰거나 방법 B 로 간다.
- 리눅스 포트의 in_use_by 가 비어 있지 않으면 다른 프로세스(시리얼 모니터, uart-mcp 세션)가 연 것이다 → 닫게 한다.

### 4. 칩·플래시 정보

```
esp_chip_info(case_id="<id>", port="COM3")
  → chip "ESP32-S3", chip_description, chip_revision, features[], usb_mode, mac, flash{manufacturer, manufacturer_id, device_id, size "8MB", size_bytes},
    secure_download_mode, log_path(uart/esptool-chip-info-NNN.log), warnings, notes, next_steps
```
- `status: "secure_download_mode"`(ok=true, read_flash_possible=false)면 칩이 flash-id 를 거부한 것이다. 5단계(get-security-info 는 Secure Download Mode 에서도 동작)로 확인한 뒤 템플릿 D 로 보고하고 멈춘다.
- flash.size 가 null 이면 6단계에서 size 를 명시한다(모듈 마킹·데이터시트, 사람에게 확인). manufacturer_id 가 ff/00 이면 SPI 플래시와 통신하지 못한 것이다 → 덤프하지 않고 보고한다.
- 새로 안 정보만 갱신한다: `case_update_target(case_id="<id>", target={"soc": "ESP32-S3 (QFN56) rev v0.2", "flash": "GigaDevice c8/4017 8MB (quad)"})`.
- 연결 오류(`[esp_no_serial_data]`, `[esp_wrong_boot_mode]` …)는 실패 처리 표를 따른다.
- **수동 다운로드 모드**(템플릿 B)로 진행할 때는 이후 모든 하드웨어 도구에 before="no-reset", after="no-reset-stub" 을 준다.
  칩이 호출 뒤에도 다운로드 모드(스텁)에 머물러 다음 호출이 그대로 연결된다. after="no-reset" 을 줘도 서버가 no-reset-stub 으로 바꿔 실행한다(응답의 after_requested 와 notes).
  기본 after="hard-reset" 이면 호출이 끝날 때 펌웨어가 다시 실행되어 다음 호출 전에 BOOT+RESET 을 또 해야 한다. 마지막에 사람이 RESET 을 눌러 일반 부팅한다.
- after 로 실행되는 값은 hard-reset(기본)·no-reset-stub·watchdog-reset(esptool v5, v4.12 이상)뿐이다. soft-reset 은 `[validation_failed]` 다(끝날 때 FLASH_BEGIN 을 보낸다).

### 5. 보안 설정

```
esp_security_info(case_id="<id>", port="COM3")
  → status("ok" | "unsupported"), secure_download_mode, read_flash_possible, flash_encryption, crypt_cnt, ciphertext_expected, secure_boot, jtag_hard_disabled, jtag_soft_disabled,
    usb_disabled, key_blocks[{block, purpose}], assessment[], log_path(uart/esptool-security-info-NNN.log)
```

| 결과 | 조치 |
|---|---|
| read_flash_possible=false (Secure Download Mode) | 덤프하지 않는다. 템플릿 D 로 보고하고 `step="attempt"` 를 기록(9단계)한 뒤 멈춘다. 우회 시도 금지 |
| flash_encryption=true (ciphertext_expected=true) | 덤프는 되지만 부트로더·파티션 표·앱은 암호문이다. 템플릿 E 로 계속할지 묻는다. 원하지 않으면 `step="attempt"`(status "skipped")로 남기고 멈춘다 |
| secure_boot=true | 읽기에는 영향이 없다. 요약 data.security 에 적는다 |
| jtag_hard_disabled, usb_disabled 등 | 기록만 한다(다른 경로 판단 근거) |
| status "unsupported"(원조 ESP32·ESP8266 은 get-security-info 미지원. ok=true, 보안 필드·read_flash_possible 은 null) | 보안 상태를 "미확인" 으로 적고(data.security 에 status "unknown" 과 사유) 진행한다. 원조 ESP32·ESP8266 에는 Secure Download Mode 가 없다. 8단계 내용 확인(파티션 표 매직)으로 평문 여부를 판단한다 |

### 6. 덤프 시작

- 예상 시간(읽기 한 번): 921600 baud 에서 4 MB 는 보통 1~2분, 115200 이면 6분 이상이다(서버 안내 값). 이중 읽기는 두 배다. 내장 USB-Serial/JTAG 는 baud 와 무관하다.
  10분을 넘을 것 같으면(예: 16 MB 를 115200 으로) 템플릿 C 로 동의를 받는다. 그보다 짧으면 `[안내]` 한 줄로 알리고 시작한다.
```
esp_read_flash_start(case_id="<id>", port="COM3", size="all", verify="double")
  → status "started", job_id, planned_path "dumps/esp-flash.bin", planned_read2_path, metadata_path, reads 2, after, read1_after "no-reset-stub", read1_baud, timeout_s_per_read, notes
```
- size="all" 은 offset=0 일 때만 쓴다(감지한 플래시 크기). flash.size 가 null 이면 size="8MB" 처럼 명시한다. output_name 은 생략한다(자동 번호).
- baud 는 기본 921600 이다. 전송 오류가 나면 460800, 115200 순으로 낮춘다. verify 는 "double" 을 유지한다("none" 은 이중 읽기 검증이 없다).
- 1차 읽기는 서버가 --after no-reset-stub 으로 돌려(칩을 다운로드 모드에 둠) 두 읽기 사이에 앱이 실행되지 않게 한다(NVS 변경 방지). 2차 읽기 뒤에 요청한 after(기본 hard-reset)를 쓴다.
- 수동 다운로드 모드면 `esp_read_flash_start(case_id="<id>", port="COM3", size="all", verify="double", before="no-reset", after="no-reset-stub")`.
  이때 1차 읽기는 115200 baud(read1_baud), 2차는 요청한 baud 다. esptool 은 연결을 115200 으로 맞추므로 1차 뒤 칩이 그 속도에 남아야 2차 연결이 된다. 예상 시간은 1차를 115200 으로 잡는다.
- 시작 응답이 approval_required 나 denied 면 안전 규칙 4.

### 7. 폴링과 결과 판단

```
esp_job_status(job_id="<job_id>", wait_seconds=50)
```
- status 가 queued/running/cancelling 이면 같은 호출을 반복한다. progress(0~1, 읽기마다 절반)와 message("읽기 1/2: 45.0% (3.60 MiB/8.00 MiB)")를 본다.
  읽기가 끝날 때마다 한 줄로 알린다: `[진행] esp-flash 읽기 1/2 완료, 2차 읽기 중 (전체 50%)`.
- succeeded 면 result 에 path, read2_path, metadata_path, size, sha256, sha256_read2, match, verification, source, log_paths, artifacts, warnings, notes, summary_hint 가 있다. 파일은 이미 아티팩트로 등록돼 있다.
  최종 파일은 끝날 때 만들어지고 덮어쓰지 않는다. 계획한 이름이 그사이 생겼으면 `dumps/<name>-<job_id>.bin` 으로 저장되고 warnings 에 적힌다 → planned_path 가 아니라 result.path 를 쓴다.

| 결과 | 판단 |
|---|---|
| succeeded, match=true | 성공. 8단계 |
| succeeded, match=false (warnings 있음) | 두 읽기가 다르다. **분석으로 넘기지 않는다.** 템플릿 F 로 케이블·연결을 점검받고, baud 를 낮춰(460800 → 115200, 내장 USB-Serial/JTAG 는 baud 와 무관하니 케이블·커넥터를 바꾼다) output_name 없이 다시 두 번 읽는다. 두 파일은 증거로 남긴다 |
| failed, result 있음 | 2차 읽기만 실패했다. 1차 결과가 verification.method "none"(match null)으로 보존돼 있다. error.code 로 원인을 고친 뒤 다시 읽는다. 끝내 못 읽으면 그 결과로 status "partial" 을 기록한다 |
| failed, result 없음 | 남은 덤프 파일이 없다(숨은 예약 파일은 서버가 지움). error.code 로 실패 처리 표를 본다 |
| failed, error.code esp_orphan_process | 취소·시간 초과 뒤 Windows esptool.exe(error.data.pids)가 남았다. 숨은 예약 파일은 그 프로세스가 끝날 때까지 남고, 같은 포트의 호출은 `[busy]` 다. 템플릿 J 로 사람이 끝낸 뒤 output_name 없이 다시 읽는다 |
| cancelled | 사용자 중지. esptool 을 끝냈고(Windows 는 esptool.exe 가 하나도 남지 않았음을 확인한 뒤에만 cancelled), 취소된 읽기의 부분 데이터는 없다. 1차 읽기가 끝났으면 result 에 보존돼 있다. 칩이 다운로드 모드에 남았을 수 있다 → 일반 부팅이 필요하면 사람이 RESET 을 누른다 |

- 다시 읽어 일치했으면 그 덤프를 output 으로 쓰고, 앞의 불일치 쌍(경로·sha256)은 notes 에 남긴다.

### 8. 검증과 내용 확인

1. **job 결과**: verification.match=true, size == 4단계 flash.size_bytes(전체 덤프), source.chip == 4단계 chip.
2. **파일 재확인(선택)**: `case_hash_file(case_id="<id>", path="dumps/esp-flash.bin")` → sha256 이 result.sha256 과 같다(.read2.bin 은 sha256_read2).
3. **파티션 표(선택, 오프라인, 권장)**: `fw_esp_partitions(case_id="<id>", path="dumps/esp-flash.bin")` 로 읽는다(기본 0x8000, 없으면 4 KiB 경계를 찾고 MD5 항목을 검증한다).
   fw_identify 는 ESP 구조(앱 이미지 헤더 0xE9, 파티션 표, NVS)를 모르므로 결과가 비어도 실패가 아니다.
   - 응답 partitions[] 의 label·type·subtype·offset·size 를 요약 partitions[] 에 옮긴다(offset·size 는 플래시 기준 정수). 부트로더(ESP32·ESP32-S2 는 0x1000, ESP32-S3·C3·C6·H2 는 0x0)와 파티션 표 자체(0x8000, 0x1000)는 표의 항목이 아니므로 직접 넣는다.
   - 앱 이미지 헤더(빌드 버전·ESP-IDF 버전·엔트리)는 `fw_esp_image_info(case_id="<id>", path="dumps/esp-flash.bin", partition="<앱 label>")` 로 확인한다(선택).
   - found 가 false 면 플래시 암호화(암호문), 옮긴 파티션 표, 잘못 읽은 덤프 중 하나다(표를 직접 읽는 방법은 [reference.md §4](reference.md#4-파티션-표-읽기)). `fw_entropy(case_id="<id>", path="dumps/esp-flash.bin")` 에서
     균일 고엔트로피가 이미지 대부분이면 암호문, 거의 전부 0xFF/0x00 패딩이면 잘못 읽은 덤프로 보고 사용자에게 알린다.
4. 결과를 data.verification.content_checks 와 partitions[] 에 적는다. 확인하지 못한 것은 확인했다고 적지 않는다.

### 9. 요약 기록과 마무리

- 덤프가 있으면 출력 절의 data 로 `case_record_step(... skill="firmware-dump-via-uart", step="summary" ...)` 를 부른다. summary 저장이 firmware-dump-via-uart 단계 상태도 갱신한다.
- 덤프 파일이 하나도 없으면(Secure Download Mode, 사용자 거부, 포트·도구 없음) output 필수인 summary 를 만들 수 없다. 이렇게 남긴다.
  `case_record_step(case_id="<id>", skill="firmware-dump-via-uart", step="attempt", status="blocked", summary="…", data={"method": "esptool-read-flash", "error": "<code: message>", "security": {"secure_download_mode": true}}, blockers=["…"])`
  `case_set_phase(case_id="<id>", phase="firmware-dump-via-uart", status="blocked")` (사람 조치로 풀 수 없는 실패는 "failed", 사용자가 그만두기로 했으면 "skipped").
- `esp_jobs(active_only=true)` 가 비어 있는지 확인한다.
- 기기 상태를 알린다: "플래시·eFuse 변경 없음(쓰기 명령을 보내지 않음: flash-id·get-security-info·read-flash 만 실행했고, 끝날 때는 FLASH_BEGIN 을 보내지 않는 hard-reset·no-reset-stub 만 씀). 마지막 읽기 뒤 hard-reset 으로 펌웨어가 다시 실행됨".
  after 가 no-reset-stub(no-reset 요청 포함)이었거나 취소했으면 "다운로드 모드에 머묾 → RESET 버튼을 누르면 정상 부팅".
- 사람이 한 물리 작업(BOOT+RESET, 케이블 교체, usbipd detach)은 `case_add_note(case_id="<id>", text="…")` 로 남긴다.

## 사람에게 요청할 일 (템플릿)

**A. USB 연결 (시작 전 필수)**
```
[사람 작업 필요] ESP32 보드 USB 연결
1. 보드에 USB 말고 다른 전원(배터리, DC 잭, 외부 5V/3V3)이 연결돼 있으면 먼저 알려 주세요. 개발 보드는 USB 하나로 전원과 통신을 함께 받습니다.
   USB 와 외부 전원을 함께 넣어도 되는지는 보드 회로도로 확인해야 합니다. 보드 핀에는 아무것도 배선하지 않습니다.
2. 데이터용 USB 케이블(충전 전용 아님)로 보드를 PC 에 연결해 주세요. 커넥터가 둘이면 어느 쪽에 꽂았는지 알려 주세요.
   "USB" = ESP 내장 USB-Serial/JTAG, "UART"·"COM" = USB-UART 브리지(CP210x/CH34x).
3. WSL 이어도 usbipd attach 는 하지 않습니다(Windows esptool.exe 가 COM 포트를 그대로 씁니다). 이미 attach 했다면 관리자 PowerShell 에서 usbipd detach --busid <BUSID>.
4. 그 포트를 연 프로그램(Arduino IDE 시리얼 모니터, idf.py monitor, PuTTY, Tera Term)을 모두 닫아 주세요.
5. 알아 두실 것: 제가 도구를 부를 때마다 칩이 리셋되어 다운로드 모드로 들어갑니다. 실행 중인 펌웨어가 멈췄다가 끝나면 다시 시작합니다(플래시에는 쓰지 않음).
   제품 안의 ESP32 면 제품 전체가 재부팅됩니다. 지금 리셋되면 안 되는 상태면 알려 주세요.
6. Windows 장치 관리자 → 포트(COM & LPT) 의 COM 번호를 알려 주시고 "완료" 라고 해 주세요.
```

**B. 다운로드 모드 수동 진입 (자동 리셋 실패)**
```
[사람 작업 필요] 다운로드 모드 수동 진입
- 자동 리셋으로 다운로드 모드에 들어가지 않았습니다 (칩 응답 없음, 로그 uart/esptool-chip-info-001.log).
1. 보드의 BOOT 버튼(부트 스트랩 핀: ESP32·S2·S3 는 GPIO0, C3·C6·H2 는 GPIO9 — 그 밖은 데이터시트. "IO0"·"IO9"·"B" 로 표시되기도 함)을 누른 채로 있어 주세요.
2. 누른 채로 RESET 버튼(EN, "RST")을 눌렀다 뗍니다.
3. 1초 뒤 BOOT 를 놓습니다. 칩이 다운로드 모드에서 기다립니다. RESET 만 다시 누르거나 전원을 다시 넣으면 원래대로 부팅합니다.
4. 내장 USB 커넥터면 COM 번호가 바뀌었을 수 있습니다. 장치 관리자에서 확인해 알려 주시고 "완료" 라고 해 주세요.
```

**C. 덤프 계획 동의 (예상 10분 초과)**
```
[확인 필요] ESP32 플래시 덤프 계획
- 칩: ESP32-S3 rev v0.2, 플래시 16 MB, Secure Download Mode 꺼짐, 플래시 암호화 꺼짐
- 방법: esptool read-flash 로 전체를 두 번 읽어 sha256 비교 (port COM3, USB-UART 브리지 115200 baud)
- 예상 시간: 읽기 한 번 약 25분 × 2. 921600 baud 를 시도하면 몇 분으로 줄어듭니다.
- 진행 중에는 보드와 케이블을 건드리지 말아 주세요. 끝나면 보드가 리셋되어 펌웨어가 다시 실행됩니다. 어느 속도로 진행할까요?
```

**D. Secure Download Mode 보고**
```
[보고] Secure Download Mode — 플래시를 읽을 수 없음 (우회하지 않음)
- 확인: esp_security_info → secure_download_mode=true, read_flash_possible=false (uart/esptool-security-info-001.log)
- 의미: eFuse 설정으로 ROM 다운로드 모드의 플래시 읽기가 막혀 있습니다. esptool 로는 덤프할 수 없습니다.
- 하지 않는 것: 글리칭, eFuse 조작, 다른 도구로 다시 읽기.
- 대안: 소유자가 가진 펌웨어 원본이나 벤더 업데이트 파일(case_import_file), 또는 이 단계 생략. 결정은 사용자가 합니다.
```

**E. 플래시 암호화 확인**
```
[확인 필요] 플래시 암호화가 켜져 있습니다
- 확인: esp_security_info → flash_encryption=true (SPI_BOOT_CRYPT_CNT=0x1), ciphertext_expected=true
- 의미: 덤프는 되지만 부트로더·파티션 표·앱 파티션은 암호문입니다. 키는 읽기 보호된 eFuse 에 있고, 꺼내려 하지 않습니다.
  encrypted 플래그가 없는 데이터 파티션(NVS 암호화를 쓰지 않은 nvs 등)은 평문일 수 있지만, 파티션 표가 암호문이라 위치를 확정하기 어렵습니다.
- 정적 분석은 평문 영역으로 제한됩니다. 증거 보존용으로 덤프할까요, 여기서 멈출까요?
```

**F. 연결 점검 (불일치·전송 오류 반복)**
```
[사람 작업 필요] USB 연결 점검
- 두 번 읽은 결과가 다릅니다 (sha256 49e97f72… / 78281c1b…). 두 파일은 증거로 보존했습니다.
1. 짧은 데이터 케이블로 바꾸거나 다시 단단히 꽂아 주세요. USB 허브 대신 PC 포트에 직접 꽂아 주세요.
2. 보드 전원이 흔들리지 않는지(외부 전원, 느슨한 커넥터) 확인해 주세요.
3. 끝나면 "완료" 라고 알려 주세요. 460800 baud 로 다시 두 번 읽습니다.
```

**G. 승인 필요** (게이트가 approval_required 를 줄 때, master-prompt §6 형식)
```
[승인 필요] approval_id=ap-xxxx
- 작업: esp_read_flash_start (위험도 MODIFY, 규칙 esp.read-flash) — 칩 리셋 → ROM 다운로드 모드, 플래시 전체 읽기 두 번
- 이유: 펌웨어 확보   위험: 실행 중인 펌웨어가 재부팅됨(휘발성)   되돌리는 방법: 끝나면 hard-reset, 또는 RESET 버튼
- 승인하려면 별도 터미널에서: pweh approve ap-xxxx   (elicitation 폼이 뜨면 그 폼에서 직접 응답)
```

**H. 거부 보고** (master-prompt §6 거부 보고 형식. 응답의 gate.via, gate.policy, gate.classification.rule_id·risk 로 채운다)
```
[보고] 안전 게이트 거부 (우회하지 않음)
- 요청: <도구와 인자>
- 응답: status denied (규칙 <rule_id>, 위험도 <risk>, 정책 <gate.policy>, via <gate.via 또는 없음>) — <message 요약>
- 의미: <아래에서 원인에 맞는 한 줄>
- 대안: <아래에서 원인에 맞는 한 줄>. 정책 변경은 운영자가 직접 결정합니다.
```
- gate.via "esp-policy"(위험도 DESTRUCTIVE): 의미 "pweh-esp 는 flash-id·get-security-info·read-flash 만 실행합니다. 쓰기·삭제·eFuse·RAM 실행은 승인으로도 풀리지 않습니다." / 대안 "읽기 전용 경로로 계속하거나 이 단계를 생략합니다."
- via 없이 gate.policy "deny"(위험도 MODIFY — 읽기 도구도 해당): 의미 "운영자 정책(safety.modify_policy=deny)이 칩 리셋을 동반하는 연결을 막습니다. 요청한 것은 읽기 전용 작업입니다." / 대안 "운영자가 modify_policy 를 approve 로 바꾸고 MCP 서버를 재시작하면 호출마다 승인을 받아 진행할 수 있습니다(에이전트는 설정을 바꾸지 않음). 아니면 이 단계를 생략합니다."
- gate.policy "approve": 사람이 승인 폼을 거절했거나 승인이 만료·불일치했다. 의미 "승인되지 않았습니다." / 대안 "원하시면 같은 인자로 다시 요청해 새 승인을 받습니다."

**I. esptool 설치**
```
[사람 작업 필요] esptool 이 없습니다 (esp_version: windows/linux 모두 available=false)
1. 별도 터미널에서 저장소 루트로 가서 ./scripts/install.sh --only esptool 을 실행해 주세요 (sudo 불필요, WSL 이면 Windows esptool.exe 도 설치).
2. MCP 서버를 다시 시작한 뒤(Claude Code 는 /mcp) "완료" 라고 알려 주세요.
```

**J. 남은 esptool.exe 종료 (방법 A, esp_orphan_process 또는 남은 PID 를 알리는 `[busy]`)**
```
[사람 작업 필요] Windows 에 남은 esptool.exe 종료
- 취소(또는 시간 초과) 뒤에도 Windows 의 esptool.exe(PID 12345)가 COM3 를 잡고 있습니다. 끝나기 전에는 이 포트로 다시 읽을 수 없습니다.
1. Windows 작업 관리자에서 esptool.exe(PID 12345)를 끝내거나, Windows 터미널에서 taskkill /F /PID 12345 를 실행해 주세요. 보드 USB 를 뽑았다 꽂아도 됩니다.
2. 끝나면 "완료" 라고 알려 주세요. 제가 포트를 다시 확인한 뒤 새 이름으로 다시 읽습니다(남은 예약 파일은 서버가 정리).
```

## 실패 처리

동기 도구의 오류는 `[code] 메시지` + `힌트:` 텍스트로 온다. 덤프 job 의 오류는 esp_job_status 의 error{code, message, hint, data.log_path} 에 있다. 로그 경로의 정리본 로그를 함께 본다.

| 오류 / 상태 | 뜻 | 조치 |
|---|---|---|
| `[authorization_required]` (시작 또는 job 도중) | 케이스에 소유/허가 증명이 없다 | 멈추고 사용자에게 확인한다(master-prompt §1-1). 증명이 돌아오면 같은 인자로 다시 |
| status approval_required | modify_policy 가 approve | 템플릿 G → 사람의 pweh approve → 같은 인자 + approval_id 로 1회 |
| status denied | gate.via esp-policy = 읽기 명령이 아님(승인 경로 없음). via 없이 gate.policy deny = 운영자의 modify_policy=deny. gate.policy approve = 승인 거절·만료 | 우회하지 않고 템플릿 H(원인별 문구). 다른 형태로 다시 보내지 않는다 |
| `[tool_missing]` | esptool.exe·esptool 없음, interop 꺼짐, 실행 권한 없음 | 템플릿 I. 방법 A 가 안 되면 방법 B |
| `[validation_failed]` | 포트 형식(COMn·/dev/tty… 만), 리눅스 장치 없음, offset≠0 인데 size="all", before·after·baud 값(soft-reset 은 받지 않음, watchdog-reset 은 esptool v5·v4.12 이상), Windows 경로 요소가 '.'·공백으로 끝남 | 힌트대로 인자를 고친다. 리눅스 장치가 없으면 usbipd attach 확인(방법 B). 경로 문제는 사용자에게 알린다(case_id·작업 경로) |
| `[busy]` | 같은 포트의 job·다른 esp 호출이 실행 중, 다른 프로세스가 리눅스 tty 를 엶, Windows 에서 그 COM 포트를 인자로 받은 esptool.exe(PID)가 남음 | `esp_jobs(active_only=true)` 로 확인 → 기다리거나 사용자 동의 후 취소. 시리얼 모니터·uart-mcp 세션을 닫게 한다. 남은 esptool.exe 는 템플릿 J |
| `[case_error]` 같은 이름의 덤프 파일, 심볼릭 링크인 dumps/ | output_name 이 이미 있다, dumps/ 가 다른 곳을 가리킨다 | output_name 을 생략하거나 새 이름. 기존 파일은 지우지 않는다. dumps/ 링크는 사용자에게 보고한다 |
| esp_port_not_found, esp_port_open_failed | 포트가 없거나 열 수 없다. usbipd 로 WSL 에 붙인 동안 Windows 에서 사라진다 | `esp_list_ports` 로 다시 확인. 방법 A 면 usbipd detach. 내장 USB 는 번호가 바뀌었을 수 있다 |
| esp_port_busy | 다른 프로그램이 COM 포트를 잡고 있다 | 템플릿 A 의 4번(시리얼 모니터 닫기) |
| esp_port_permission | 리눅스 tty 권한이 없다 | 사람이 dialout 그룹을 추가한다(방법 B, `docs/hardware-setup.md` §2.3) |
| esp_no_serial_data, esp_wrong_boot_mode, esp_connect_failed, esp_app_running | 다운로드 모드에 들어가지 않았다 | 템플릿 B → before="no-reset", after="no-reset-stub". 커넥터(내장 USB / 브리지)와 데이터 케이블도 확인 |
| esp_tx_path_down | 다운로드 모드는 보이지만 동기화가 안 된다 | 브리지·케이블 문제. 다른 커넥터나 케이블로 다시 |
| esp_serial_noise, esp_digest_mismatch | 전송이 손상됐다 | baud 를 낮춘다(921600 → 460800 → 115200), 짧은 케이블(템플릿 F) |
| esp_baud_switch_failed | baud 를 바꾼 직후(로그의 `Changed.`) 통신이 끊겼다. USB-UART 브리지·케이블이 921600 을 버티지 못한다 | output_name 없이 baud=460800, 그래도 실패하면 baud=115200 으로 다시 덤프한다(예상 시간을 다시 알린다) |
| esp_secure_download_mode | Secure Download Mode | 템플릿 D. 우회하지 않는다 |
| esp_flash_size_unknown, esp_size_exceeds_flash | 플래시 크기 문제 | size 를 명시한다(4단계 flash.size, 사람 확인). offset+size 를 플래시 안으로 |
| esp_wrong_chip | chip 인자가 실제 칩과 다르다 | chip="auto" 로 다시 |
| esp_rom_unsupported | ESP8266 ROM 은 read-flash 를 지원하지 않는다(그 밖의 ESP32 계열 ROM 은 읽을 수 있다) | no_stub 을 기본값(False)으로 다시 |
| esp_stub_failed, esp_chip_stopped, esp_port_io_error | 스텁·연결 불안정, 장치 분리·재열거 | RESET 이나 USB 재연결 후 `esp_list_ports` → 다시 |
| esp_invalid_argument, esp_version_failed | esptool 버전·실행 문제 | `esp_version` 으로 확인. v4.8 이상이 아니면 템플릿 I |
| esp_foreign_config | esptool 이 서버가 만든 빈 설정이 아닌 설정 파일(error.data.config)을 읽어 연결 전에 멈췄다 | 사람에게 그 파일의 [esptool] 섹션을 확인·제거하거나 파일을 옮기게 한 뒤 다시. 에이전트가 그 파일을 고치지 않는다 |
| esp_orphan_process | 취소·시간 초과 뒤 Windows esptool.exe(error.data.pids)가 남아 COM 포트를 잡고 있다 | 템플릿 J. 끝나면 `esp_list_ports` 로 확인하고 다시 |
| esp_bad_output, esp_failed | 출력을 해석하지 못했거나 분류되지 않은 실패 | 로그를 읽고 사용자에게 보고(원조 ESP32·ESP8266 의 get-security-info 미지원은 오류가 아니라 5단계의 status "unsupported") |
| esp_output_size_mismatch | 출력 파일 크기가 예상과 다르다 | 다시 읽는다(output_name 생략) |
| `[timeout]` | 시간 초과, 덤프가 출력 없이 180초 멈춤 | 다운로드 모드와 baud 를 확인한다. 큰 플래시를 낮은 baud 로 읽으면 timeout_s 를 늘린다 |
| `[safety_denied]` | 실행 직전 재분류에서 거부, 덤프 도중 dumps/ 경로가 바뀜 | 우회하지 않고 보고한다 |
| `[cancelled]` | 요청이나 job 이 취소됐다 | 7단계 표의 cancelled |

## 성공·실패 기준

- **성공(success)**: 전체 플래시를 두 번 읽어 match=true, sha256·size 가 기록됐고 size 가 감지한 플래시 크기와 같다. 보안 상태(또는 미확인 사유)가 적혀 있다. summary 가 스키마를 통과했고 실행 중 job 이 없다.
- **부분(partial)**: 사용자가 정한 일부 범위만 읽었다, 1차 읽기만 남았다(verification "none", match null), 보안 상태를 확인하지 못했고 내용 확인도 못 했다. 빠진 것을 notes·next_actions 에 적는다.
- **실패(failed)**: 다시 읽어도 두 읽기가 계속 다르다(match=false). 파일은 남기고 summary 의 blockers 에 적으며 분석으로 넘기지 않는다. 덤프 파일이 없는 실패는 9단계의 `step="attempt"` 로 남긴다.
- **차단(blocked)**: Secure Download Mode, 포트·esptool 없음, 정책 거부. 9단계의 `step="attempt"` 로 남긴다.

## 출력 (요약 기록)

job result 의 summary_hint 를 뼈대로 쓰고, `dumps/<name>.json` 메타데이터와 4·5·8단계 결과를 더해 data 를 만든다(필드 출처는 [reference.md §3](reference.md#3-응답-필드와-summary-매핑)).
- method 는 `esptool-read-flash`, verification.method 는 `double-read` 다. expected/actual 은 두 읽기의 sha256(result.sha256, sha256_read2), match 는 둘이 같은지다.
- source.device_path 는 port 그대로("COM3" 또는 "/dev/ttyACM0"). flash_size·offset·length·flash_type 은 summary_hint.source 에서 옮긴다.
- 보안 결과는 data.security 에, 파티션 표는 partitions[](offset·size 는 플래시 기준 정수)에 넣는다. 1차 읽기만 남았으면 verification 은 method "none", match null 이다.

아래 예시의 덤프·검증·보안 값은 가짜 esptool(`tests/servers/esp_fake_esptool.py`, ESP32-S3·8 MiB 흉내)로 이 서버를 실제로 돌린 결과이고,
partitions 는 같은 크기의 합성 파티션 표를 8단계 방법으로 읽은 값이다. 실제 기기 값이 아니다. 이 data 는 firmware-dump 스키마 검증을 통과했다.

```json
{
  "method": "esptool-read-flash",
  "source": {"type": "esptool", "device_path": "COM3", "chip": "ESP32-S3", "chip_description": "ESP32-S3 (QFN56) (revision v0.2)", "mac": "f4:12:fa:12:34:56", "usb_mode": "USB-Serial/JTAG", "flash_type": "spi-nor", "flash_model": "GigaDevice c8/4017 (quad)", "flash_size": 8388608, "offset": 0, "length": 8388608, "partition": null, "ram_addr": null},
  "output": {"path": "dumps/esp-flash.bin", "sha256": "059f292ac5beebe86ad496fb91ec6956f479df01789827d8d7f25f93a60c08b0", "size": 8388608},
  "verification": {
    "method": "double-read", "expected": "059f292ac5beebe86ad496fb91ec6956f479df01789827d8d7f25f93a60c08b0", "actual": "059f292ac5beebe86ad496fb91ec6956f479df01789827d8d7f25f93a60c08b0", "match": true,
    "read2_path": "dumps/esp-flash.read2.bin",
    "detail": "같은 영역을 두 번 읽어 sha256 비교 (1차는 --after no-reset-stub 으로 칩을 다운로드 모드에 둬 앱이 실행되지 않게 함). esptool 스텁은 읽기마다 전송 MD5 를 검증한다.",
    "content_checks": ["파티션 표 @0x8000: 항목 6개, MD5 일치 (fw_esp_partitions)", "case_hash_file: dumps/esp-flash.bin sha256 일치"]
  },
  "partitions": [
    {"name": "bootloader", "offset": 0, "size": 32768, "note": "ESP32-S3 기본 위치 (파티션 표 밖)"},
    {"name": "partition-table", "offset": 32768, "size": 4096, "note": "기본 위치 0x8000"},
    {"name": "nvs", "offset": 36864, "size": 20480, "type": "data", "subtype": "nvs"},
    {"name": "otadata", "offset": 57344, "size": 8192, "type": "data", "subtype": "ota"},
    {"name": "app0", "offset": 65536, "size": 3342336, "type": "app", "subtype": "ota_0"},
    {"name": "app1", "offset": 3407872, "size": 3342336, "type": "app", "subtype": "ota_1"},
    {"name": "spiffs", "offset": 6750208, "size": 1572864, "type": "data", "subtype": "spiffs"},
    {"name": "coredump", "offset": 8323072, "size": 65536, "type": "data", "subtype": "coredump"}
  ],
  "baudrate": 921600,
  "metadata_path": "dumps/esp-flash.json",
  "security": {"secure_download_mode": false, "flash_encryption": false, "crypt_cnt": 0, "ciphertext_expected": false, "secure_boot": false, "jtag_hard_disabled": false, "log_path": "uart/esptool-security-info-001.log"},
  "tool": {"name": "esptool", "esptool_version": "5.4.0", "backend": "windows"},
  "notes": [
    "방법 A: WSL interop 으로 Windows esptool.exe 실행, port COM3 (usbipd attach 없음)",
    "1차 읽기는 --after no-reset-stub(칩을 다운로드 모드에 둬 앱이 실행되지 않게 — FLASH_BEGIN 을 보내는 no-reset 은 쓰지 않음), 2차 읽기 뒤 --after hard-reset.",
    "플래시·eFuse 쓰기 명령 없음(flash-id·get-security-info·read-flash 만 실행). 마지막 읽기 뒤 hard-reset 으로 펌웨어 재실행",
    "partitions: fw_esp_partitions 결과(analysis/esp-partitions-001.json) + 부트로더·파티션 표 위치"
  ]
}
```

```
case_record_step(case_id="<id>", skill="firmware-dump-via-uart", step="summary", status="success",
  summary="ESP32-S3 8 MB 플래시를 esptool read-flash 로 두 번 읽어 sha256 일치 (방법 A, COM3). Secure Download Mode·플래시 암호화 꺼짐",
  data=<위 JSON>,
  artifacts=["dumps/esp-flash.bin", "dumps/esp-flash.read2.bin", "dumps/esp-flash.json", "uart/esptool-security-info-001.log"],
  next_actions=["firmware-static-analysis: dumps/esp-flash.bin — fw_esp_image_info·fw_esp_nvs 로 ESP 형식 해석, 게임 기기면 game-save-unlock-analysis"],
  blockers=[])
```
서버가 스키마 검증에 실패하면 메시지대로 data 를 고쳐 다시 저장한다(`schema_get(name="firmware-dump")`).

## 다음 단계

- **firmware-static-analysis**: data.output.path 를 펌웨어로 쓴다(firmware.source 는 "esptool-dump").
  - ESP 형식은 pweh-fwtriage 의 ESP 도구로 본다: `fw_esp_partitions`(파티션 표), `fw_esp_image_info`(앱 헤더·세그먼트·앱 설명), `fw_esp_nvs`(NVS 설정 — Wi-Fi 비밀번호 같은 비밀은 마스킹된다), `fw_esp_to_elf`(ELF 변환).
    fw_identify·fw_carve 자동 레이아웃은 ESP 구조를 모르므로, 파티션 파일이 필요하면 fw_esp_partitions 의 값을 fw_carve 의 partitions 인자로 준다.
  - REA 는 Xtensa(ESP32·S2·S3) ELF 를 열지 못한다(지원 아키텍처 아님). RISC-V(C3·C6·H2 …)는 `fw_esp_to_elf(..., rea_compat=true)` 로 만든 ELF 를 open_binary 로 연다(e_flags 를 double-float ABI 로 표시 — 부동소수점 인자·반환값 해석만 틀릴 수 있다). 열 수 없으면 그 사유를 rea.limitations 에 적는다.
  - 일반 분석도 된다: fw_entropy, 사용자 패턴(`lit:`, `re:`)의 fw_strings_hunt, PEM 인증서·키, 압축 블롭.
  - cctv-auth-bypass-hunt 는 리눅스 rootfs 를 전제로 하므로 ESP 펌웨어에는 맞지 않는다.
- **game-save-unlock-analysis**: 게임 콘솔·장난감이면 해금 조건·세이브 위치·인코딩·체크섬을 오프라인으로 찾는다(master-prompt §3.1).
- verification.match 가 true 가 아니면 분석으로 넘기지 않는다. 다시 읽는 것이 먼저다.
- 사용자가 목표를 펌웨어 확보까지로 줄였으면 `report_generate(case_id="<id>")` 후 master-prompt §10 형식으로 보고한다.


## 참고

- [reference.md](reference.md): 포트 종류, 방법 B(리눅스 esptool + usbipd), 응답 필드와 summary 매핑, 파티션 표 읽기(항목 구조·풀이 예), 시간 계산.
- `orchestrator/master-prompt.md` §1 절대 규칙, §4 Phase B, §5 데이터 전달, §6 사람 협업, §7 장시간 작업.
- `mcp-servers/esp-mcp/README.md` (도구·결과 파일·안전 정책·오류 코드). `docs/safety.md` §2.7·§3.3·§4·§5·§7. `docs/hardware-setup.md` §2.2(usbipd).
