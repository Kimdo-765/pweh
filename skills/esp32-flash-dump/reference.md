# esp32-flash-dump 참고 자료

[SKILL.md](SKILL.md) 의 보조 자료다. 응답 모양은 가짜 esptool(`tests/servers/esp_fake_esptool.py`, esptool 5.4.0 출력 흉내)로 pweh-esp 서버를 돌려 확인했고,
파티션 표 풀이는 합성 플래시 이미지에 pweh-fwtriage 를 돌려 확인했다. 실제 기기 측정값이 아니다. 서버 동작의 근거는 `mcp-servers/esp-mcp/README.md` 다.

## 1. 포트 종류와 연결

`esp_list_ports` 는 포트를 열지 않고 USB VID:PID 로 kind 를 붙인다.

| kind | USB ID | 무엇인가 | 호출 |
|---|---|---|---|
| esp-usb-serial-jtag | 303a:1001 | ESP 내장 USB-Serial/JTAG. ESP32-S3·C3·C6·H2 의 "USB" 커넥터 | 기본값. esptool 이 USB-JTAG 리셋으로 다운로드 모드에 넣는다(before="default-reset" 또는 "usb-reset"). baud 는 속도와 무관 |
| usb-uart-bridge | 10c4:ea60 (CP210x), 1a86:7523 (CH340), 1a86:55d3 (CH343), 1a86:55d4 (CH9102), 0403:6001·6010·6014·6015 (FTDI) | 보드의 USB-UART 브리지. 원조 ESP32 보드는 이것뿐이다 | 기본값. DevKit 의 자동 리셋 회로(DTR/RTS → EN·GPIO0)를 쓴다. 921600 이 불안정하면 460800·115200 |
| esp-usb-otg-rom | 303a:0009 (S3), 303a:0002 (S2) | 칩이 이미 ROM 의 USB-OTG 다운로드 모드다 | before="no-reset", after="no-reset-stub"(after="no-reset" 을 줘도 서버가 no-reset-stub 으로 바꿔 실행). 끝나면 사람이 RESET |
| esp-usb | 그 밖의 303a | 앱이 USB 를 직접 쓴다(TinyUSB CDC 등). 다운로드 모드가 아니다 | 템플릿 B 로 다운로드 모드에 넣고 `esp_list_ports` 를 다시 부른다(ROM 포트로 바뀐다) |
| unknown | 그 밖 | 알 수 없는 장치 | 사람에게 보드·커넥터를 확인한다 |

- 내장 USB-Serial/JTAG 는 리셋 때 USB 가 다시 열거될 수 있다. Windows COM 번호가 바뀌면 `esp_list_ports` 로 다시 확인한다(서버도 notes 에 알린다).
  펌웨어가 USB 핀을 다른 용도로 쓰거나 USB-Serial/JTAG 를 끄면 자동 리셋이 안 된다 → 템플릿 B.
- FT2232(0403:6010)는 두 채널 중 하나가 JTAG 일 수 있다. 어느 COM 포트가 UART 채널인지 사람에게 확인한다.
- 커넥터가 둘인 보드(예: ESP32-S3 DevKitC)는 어느 쪽이든 된다. 한쪽에서 연결 실패가 계속되면 다른 커넥터로 바꿔 본다.
- 같은 포트를 여는 프로그램이 있으면 Windows 는 esptool 이 `[esp_port_busy]` 로 실패하고, 리셋 신호도 막힐 수 있다. 리눅스 포트는 서버가 미리 in_use_by 로 확인해 `[busy]` 로 거부한다.
  Windows 에서도 그 COM 포트를 인자로 받은 esptool.exe(취소·시간 초과 뒤 남은 것)는 서버가 Windows 프로세스 목록에서 찾아 PID 와 함께 `[busy]` 로 거부한다(SKILL 템플릿 J).

## 2. 방법 B — 리눅스 esptool + usbipd

Windows 백엔드를 쓸 수 없을 때(WSL interop 꺼짐, esptool.exe 없음)나 네이티브 리눅스 PC 에서 쓴다. 근거: [docs/hardware-setup.md §2.2](../../docs/hardware-setup.md#22-wsl2-에서-usb-장치-쓰기-usbipd-win), §2.3.

1. 사람이 Windows 에서 장치를 WSL 에 붙인다(아래 템플릿). attach 하는 동안 Windows 에서는 그 COM 포트가 사라지므로 방법 A 와 동시에 쓸 수 없다.
2. WSL 네트워킹 모드가 bridged 면 `--host-ip` 로 Windows 주소를 직접 준다(nat·mirrored 는 필요 없음).
3. 포트는 `/dev/ttyACM0`(내장 USB-Serial/JTAG) 또는 `/dev/ttyUSB0`(USB-UART 브리지)다. `esp_list_ports` 의 linux.ports 에서 확인한다.
4. **내장 USB 는 리셋 때 다시 열거되어 WSL 에서 떨어진다.** `--auto-attach` 로 다시 붙게 하고, 칩은 사람이 BOOT+RESET 으로 다운로드 모드에 넣은 뒤
   모든 호출에 before="no-reset", after="no-reset-stub" 을 줘 esptool 이 호출 중에 칩을 리셋하지 않게 한다(칩은 호출 뒤에도 다운로드 모드(스텁)에 머문다).
   ROM 다운로드 모드가 다른 VID:PID(303a:0009)로 보이면 그것도 bind 한다.
5. 권한 오류(`[esp_port_permission]`)는 사람이 dialout 그룹을 추가하고 다시 로그인(WSL 은 wsl --shutdown)해야 한다.
6. 다른 프로세스가 tty 를 열고 있으면(in_use_by, `[busy]`) 그 프로그램을 닫는다. uart-mcp 세션이면 `uart_close`.

```
[사람 작업 필요] ESP32 보드를 WSL 에 연결 (방법 B)
1. 관리자 PowerShell 에서 usbipd list 로 보드의 BUSID 를 찾고(예: 2-3  USB JTAG/serial debug unit), 처음이면 usbipd bind --busid 2-3 을 실행해 주세요.
2. 내장 USB(303a:1001) 보드: usbipd attach --wsl --busid 2-3 --auto-attach 를 실행하고 그 창을 열어 둡니다(리셋 때 다시 붙음).
   USB-UART 브리지 보드: usbipd attach --wsl --busid 2-3 (장치를 뽑았다 꽂으면 다시).
3. WSL 이 bridged 네트워킹이면 attach 에 --host-ip <'vEthernet (WSL External)' 의 IPv4> 를 붙입니다.
4. 끝나면 "완료" 라고 알려 주세요. attach 하는 동안 Windows 에서는 그 COM 포트가 보이지 않습니다.
```

```
esp_chip_info(case_id="<id>", port="/dev/ttyACM0", before="no-reset", after="no-reset-stub")
esp_security_info(case_id="<id>", port="/dev/ttyACM0", before="no-reset", after="no-reset-stub")
esp_read_flash_start(case_id="<id>", port="/dev/ttyACM0", size="all", verify="double", before="no-reset", after="no-reset-stub")
```
덤프의 1차 읽기는 115200 baud 로 돈다(before="no-reset" 이중 읽기, 시작 응답의 read1_baud). 내장 USB-Serial/JTAG 는 baud 와 무관하다.
끝나면 사람에게 RESET 을 눌러 일반 부팅하게 하고, 필요하면 usbipd detach 로 Windows 에 돌려준다.

## 3. 응답 필드와 summary 매핑

**`esp_read_flash_start` 시작 응답**: ok, status="started", job_id, planned_path, planned_read2_path(verify="none" 이면 null), metadata_path, reads(1 또는 2), backend, port, esptool_version,
after(실제로 쓸 값), after_requested(after="no-reset" 을 no-reset-stub 으로 바꿨을 때만), read1_after(이중 읽기면 "no-reset-stub", 아니면 null), read1_baud(이중 읽기의 1차 baud: 수동 다운로드 모드(before="no-reset")면 min(baud, 115200), 아니면 baud. 한 번 읽기면 null),
timeout_s_per_read, classification(rule_id "esp.read-flash"), notes, message. 정보 도구(`esp_chip_info`, `esp_security_info`)도 after 와 after_requested 를 돌려준다.

**`esp_job_status`**: status(queued/running/cancelling/succeeded/failed/cancelled), progress(0~1, 두 번 읽으면 읽기마다 절반), message, meta{planned_path, port, backend, read}, result, error{code, message, hint, data{log_path, problems}}, log_tail.

**완료 result**: path, absolute_path, read2_path, metadata_path, size, sha256, sha256_read2, match, verification{method, expected, actual, match, detail}, source{type, device_path, chip, chip_description, mac, base_mac, usb_mode, flash_size, flash_size_str, offset, length, requested_size, flash_type, partition, ram_addr},
backend, port, esptool_version, log_paths(`uart/esptool-<name>-readN-NNN.log`), artifacts{primary, read2, metadata}, warnings, notes, summary_hint{method, source{device_path, flash_size, offset, length, flash_type}, output, verification{method, expected, actual, match}, baudrate}.
`dumps/<name>.json` 에는 여기에 schema "pweh.esp-dump/v1", reads[](index, path, sha256, size, after, baud, seconds, kbit_s, log_path), tool{esptool_version, backend, argv}, status, duration_seconds, started_at, finished_at, job_id 가 더 있다.
mac 은 esptool 이 찍은 값 그대로다(ESP32-C6·H2 는 8바이트 EUI-64). base_mac 은 늘 6바이트 MAC 이다.
verification.detail 은 서버가 정한 문장 그대로 옮긴다(이중 읽기·1차 읽기 방식, 스텁 MD5 검증 여부 — no_stub=True 면 "ROM 직접 읽기(--no-stub): 전송 MD5 검증 없음").

| summary data | 가져올 곳 |
|---|---|
| method | summary_hint.method ("esptool-read-flash") |
| source.device_path, flash_size, offset, length, flash_type | summary_hint.source |
| source.chip, chip_description, mac, usb_mode | result.source |
| source.flash_model | `esp_chip_info` 의 flash.manufacturer, manufacturer_id/device_id, type_efuse |
| output | summary_hint.output (= result.path, sha256, size) |
| verification.method, expected, actual, match | summary_hint.verification. 1차 읽기만 남았으면 method "none", expected·actual·match 는 null |
| verification.read2_path, detail | result.read2_path, result.verification.detail |
| verification.content_checks | SKILL 8단계 (case_hash_file, 파티션 표) |
| partitions | SKILL 8단계 파티션 표 풀이(아래 §4). offset·size 는 플래시 기준 정수 |
| baudrate | summary_hint.baudrate. 내장 USB-Serial/JTAG 면 실제 속도와 무관하다고 notes 에 적는다 |
| duration_seconds | `dumps/<name>.json` 의 duration_seconds (선택) |
| metadata_path | result.metadata_path |
| security | `esp_security_info` 의 secure_download_mode, flash_encryption, crypt_cnt, ciphertext_expected, secure_boot, jtag_hard_disabled, log_path. status "unsupported"(원조 ESP32·ESP8266)거나 확인하지 못했으면 {"status": "unknown", "reason": "get-security-info 미지원(원조 ESP32)", "log_path": "…"} |
| tool | `dumps/<name>.json` 의 tool(esptool_version, backend) |
| notes | result.notes·warnings + 방법(A/B), 수동 다운로드 모드 여부, 불일치·재시도 이력 |

## 4. 파티션 표 읽기

ESP-IDF 파티션 표는 기본 0x8000 에 있는 32바이트 항목의 나열이다. 끝에는 MD5 항목(EB EB …)이 오고 나머지는 0xFF 다.
보통은 `fw_esp_partitions(case_id="<id>", path="dumps/esp-flash.bin")` 가 이 구조를 해석한다(MD5 항목 검증, 세이브 쓰기 분류 포함).
아래는 구조 설명과, 도구가 표를 찾지 못할 때(예: 표가 옮겨졌는데 위치를 알 때) 영역만 잘라 바이트 정규식으로 항목을 뽑는 직접 방법이다(덤프 전체에 돌리면 코드 속 우연한 AA 50 도 걸린다).

```
fw_carve(case_id="<id>", path="dumps/esp-flash.bin", partitions=[{"name": "bootloader", "offset": "0x0", "size": "0x8000"}, {"name": "partition-table", "offset": "0x8000", "size": "0x1000"}])
fw_strings_hunt(case_id="<id>", path_or_dir="extract/parts-001/01-partition-table.bin", patterns=["raw:\xaa\x50[\x00-\xff]{30}"])
```
- 패턴은 `raw:` 뒤의 바이트 정규식이고 백슬래시는 정규식 이스케이프 그대로 보낸다(JSON 으로 보낼 때만 `\\` 로 이스케이프).
- 원조 ESP32·ESP32-S2 는 부트로더가 0x1000 에 있으므로 bootloader 항목을 `{"name": "bootloader", "offset": "0x1000", "size": "0x7000"}` 로 바꾼다.
- 히트가 없으면: 플래시 암호화(파티션 표도 암호문), 프로젝트가 옮긴 파티션 표(사용자에게 CONFIG_PARTITION_TABLE_OFFSET 을 묻는다), 잘못 읽은 덤프 중 하나다(SKILL 8단계).

**항목 구조 (32바이트)**

| 바이트 | 필드 | 값 |
|---|---|---|
| 0~1 | magic | AA 50 (match 에서는 `\xaaP`) |
| 2 | type | 0x00 app, 0x01 data (그 밖의 값은 ESP-IDF 문서를 본다) |
| 3 | subtype | app: 0x00 factory, 0x10~0x1F ota_0~ota_15, 0x20 test. data: 0x00 ota, 0x01 phy, 0x02 nvs, 0x03 coredump, 0x04 nvs_keys, 0x05 efuse, 0x80 esphttpd, 0x81 fat, 0x82 spiffs, 0x83 littlefs |
| 4~7 | offset | 리틀 엔디언 32비트 |
| 8~11 | size | 리틀 엔디언 32비트 |
| 12~27 | label | NUL 로 채운 ASCII 16바이트 |
| 28~31 | flags | bit 0 = encrypted |

**match 문자열 풀기**: `\xHH` 는 바이트 하나다(16진 두 자리까지만 읽는다). 그 밖의 글자는 ASCII 코드 그대로다: `P`=0x50, 공백=0x20, `)`=0x29, `3`=0x33, `4`=0x34, `?`=0x3f, `g`=0x67.
그래서 `\x003` 은 0x00 과 0x33 두 바이트다. 바이트 0x5C 는 `\` 한 글자로 나온다(뒤에 x 와 16진 두 자리가 오지 않는다). 마지막이 `…` 로 잘렸으면 flags 만 잘린 것이다.
hits[].offset_hex 는 잘라 낸 파일 기준이다(플래시 오프셋 = 0x8000 + offset_hex).

합성 8 MB 이미지에서 실제로 나온 히트와 풀이:
```text
0x0  | \xaaP\x01\x02\x00\x90\x00\x00\x00P\x00\x00nvs\x00\x00…
0x20 | \xaaP\x01\x00\x00\xe0\x00\x00\x00 \x00\x00otadata\x00\x00…
0x40 | \xaaP\x00\x10\x00\x00\x01\x00\x00\x003\x00app0\x00\x00…
0x60 | \xaaP\x00\x11\x00\x004\x00\x00\x003\x00app1\x00\x00…
0x80 | \xaaP\x01\x82\x00\x00g\x00\x00\x00\x18\x00spiffs\x00\x00…
0xa0 | \xaaP\x01\x03\x00\x00\x7f\x00\x00\x00\x01\x00coredump\x00\x00…
```

| label | type / subtype | offset 바이트 → 값 | size 바이트 → 값 |
|---|---|---|---|
| nvs | data / nvs (01 02) | 00 90 00 00 → 0x9000 | 00 50 00 00 → 0x5000 |
| otadata | data / ota (01 00) | 00 e0 00 00 → 0xe000 | 00 20 00 00 → 0x2000 |
| app0 | app / ota_0 (00 10) | 00 00 01 00 → 0x10000 | 00 00 33 00 → 0x330000 |
| app1 | app / ota_1 (00 11) | 00 00 34 00 → 0x340000 | 00 00 33 00 → 0x330000 |
| spiffs | data / spiffs (01 82) | 00 00 67 00 → 0x670000 | 00 00 18 00 → 0x180000 |
| coredump | data / coredump (01 03) | 00 00 7f 00 → 0x7f0000 | 00 00 01 00 → 0x10000 |

마지막 항목의 끝(0x7f0000 + 0x10000 = 0x800000)이 플래시 크기(8 MB)와 맞는지, 항목끼리 겹치지 않는지 확인한다. 맞지 않으면 풀이를 다시 본다.
firmware-static-analysis 는 이 값을 그대로 fw_carve 에 넘긴다(부트로더·파티션 표 영역도 함께):
```
fw_carve(case_id="<id>", path="dumps/esp-flash.bin", partitions=[{"name": "bootloader", "offset": "0x0", "size": "0x8000"}, {"name": "partition-table", "offset": "0x8000", "size": "0x1000"}, {"name": "nvs", "offset": "0x9000", "size": "0x5000"}, {"name": "otadata", "offset": "0xe000", "size": "0x2000"}, {"name": "app0", "offset": "0x10000", "size": "0x330000"}, {"name": "app1", "offset": "0x340000", "size": "0x330000"}, {"name": "spiffs", "offset": "0x670000", "size": "0x180000"}, {"name": "coredump", "offset": "0x7f0000", "size": "0x10000"}])
```

**칩별 고정 위치**

| 칩 | 2단계 부트로더 | 파티션 표(기본) |
|---|---|---|
| ESP32, ESP32-S2 | 0x1000 | 0x8000 |
| ESP32-S3, ESP32-C3, ESP32-C6, ESP32-H2 | 0x0 | 0x8000 |
| 그 밖의 칩 | ESP-IDF 문서로 확인 | 0x8000 (CONFIG_PARTITION_TABLE_OFFSET 으로 바뀔 수 있음) |

**앱 이미지 확인(선택)**: 앱 파티션은 이미지 헤더 매직 0xE9 로 시작하고, 앱 시작 + 0x20 에 앱 설명(esp_app_desc_t, 매직 0xABCD5432 → 바이트 32 54 CD AB)이 있다.
`fw_strings_hunt(case_id="<id>", path_or_dir="dumps/esp-flash.bin", patterns=["raw:\x32\x54\xcd\xab"])` 의 히트가 앱 오프셋 + 0x20(예: 0x10020)에 있으면 앱 이미지가 평문이다.
히트의 context 에는 매직 뒤 48바이트가 나오므로 앱 버전 문자열을 볼 수 있다(합성 이미지: `2T\xcd\xab\x00…\x001.4.2\x00…` → 버전 1.4.2). 프로젝트 이름·ESP-IDF 버전은 그 뒤라 보이지 않는다.
버전은 펌웨어 식별 힌트로만 notes 에 적고, 확인되면 `case_update_target(case_id="<id>", target={"firmware_version": "1.4.2 (esp_app_desc)"})` 로 갱신한다.

## 5. 시간 계산

| 플래시 | 921600 baud, 읽기 1회 | 115200 baud, 읽기 1회 |
|---|---|---|
| 4 MB | 1~2분 | 6분 이상 |
| 8 MB | 2~4분 | 12분 이상 |
| 16 MB | 4~8분 | 24분 이상 |

- 921600 값은 서버 안내(4 MB 1~2분)를 크기에 비례해 늘린 어림값이고, 115200 값은 8N1 이론 하한(크기 × 10 / baud)이다. verify="double" 은 두 배 걸린다.
- 내장 USB-Serial/JTAG 는 baud 와 무관하다. 첫 덤프의 log_tail·result 의 읽기별 seconds(`dumps/<name>.json` 의 reads[])로 실제 속도를 확인한다.
- 서버의 읽기당 제한 시간(timeout_s_per_read)은 최악 처리량(baud 의 25%)으로 잡는다. size="all" 이면 32 MB 로 가정한다. 출력 없이 180초가 지나면 멈춘 것으로 보고 끝낸다(`[timeout]`).

## 6. 추가 예시: 덤프 없이 끝난 기록 (Secure Download Mode)

`esp_chip_info` 는 Secure Download Mode 칩에서 오류가 아니라 ok=true 와 status "secure_download_mode" 를 돌려준다(가짜 esptool sdm 모드에서 확인).
```text
esp_chip_info → ok true, status "secure_download_mode", read_flash_possible false, secure_download_mode true,
                error "The 'flash-id' command is not available in Secure Download Mode."
esp_security_info → secure_download_mode true, read_flash_possible false, flash_encryption true, secure_boot true, assessment[…]
```
이때는 `esp_read_flash_start` 를 부르지 않는다(불러도 job 이 error.code "esp_secure_download_mode" 로 실패한다). 템플릿 D 로 보고하고 다음처럼 남긴다.
```json
{
  "method": "esptool-read-flash",
  "error": "esp_secure_download_mode: ROM 로더가 flash-id·read-flash 를 거부 (Secure Download Mode)",
  "chip": "ESP32-S3",
  "port": "COM3",
  "security": {"secure_download_mode": true, "read_flash_possible": false, "flash_encryption": true, "secure_boot": true, "log_path": "uart/esptool-security-info-001.log"},
  "log_paths": ["uart/esptool-chip-info-001.log", "uart/esptool-security-info-001.log"]
}
```
```
case_record_step(case_id="<id>", skill="firmware-dump-via-uart", step="attempt", status="blocked",
  summary="ESP32-S3 Secure Download Mode — esptool 로 플래시를 읽을 수 없음 (우회하지 않음)", data=<위 JSON>,
  artifacts=["uart/esptool-chip-info-001.log", "uart/esptool-security-info-001.log"],
  next_actions=["사용자 결정: 소유자 펌웨어 원본·벤더 업데이트 파일 반입(case_import_file) 또는 이 단계 생략"],
  blockers=["Secure Download Mode (eFuse) — 정책상 우회 금지"])
case_set_phase(case_id="<id>", phase="firmware-dump-via-uart", status="blocked")
```
