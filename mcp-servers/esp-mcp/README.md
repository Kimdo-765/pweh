# pweh-esp (esp-mcp)

Espressif 칩(ESP32·ESP32-S3 등)을 [esptool](https://github.com/espressif/esptool) 로 **읽기 전용** 분석하는 PWEH MCP 서버다.
본인 소유 또는 서면 허가를 받은 기기에서 칩·플래시 정보와 보안 설정을 확인하고, SPI 플래시를 두 번 읽어 검증한 덤프를
케이스(`dumps/`)에 저장한다. 플래시 쓰기·삭제, eFuse, RAM 실행 같은 명령은 이 서버에 없고, 요청하면 거부한다.

실행 명령은 `pweh-esp-mcp` 또는 `python -m esp_mcp` (stdio)이다.

## 방법 A — WSL 에서 Windows 용 esptool.exe 쓰기 (권장)

WSL2 에서는 USB 장치를 쓰려면 보통 usbipd-win 으로 장치를 리눅스에 붙여야 한다. 방법 A 는 그 단계를 건너뛴다.

- 보드는 Windows 에 연결된 그대로 둔다(예: `COM3`).
- 서버가 WSL interop 으로 **Windows 용 esptool.exe** 를 `--port COM3` 으로 실행한다. exe 는 리눅스 파일시스템에 있어도 된다.
- 덤프 파일 경로는 `wslpath -w` 로 바꿔(`\\wsl.localhost\<배포판>\…\dumps\…`) esptool.exe 가 케이스에 바로 쓰게 한다.
- 장치가 Windows 에 붙어 있으므로 usbipd attach 가 필요 없고, Windows 에서 COM 포트가 사라지는 일도 없다.

포트 형식이 백엔드를 정한다.

| port | 백엔드 | 실행 파일 |
|---|---|---|
| `COM1` ~ `COM256` (대소문자 무관) | windows | `tools.esptool_win` (Windows 용 `esptool.exe`, WSL interop) |
| `/dev/ttyACM<n>`, `/dev/ttyUSB<n>`, `/dev/ttyS<n>`, `/dev/serial/by-id/<이름>` | linux | `tools.esptool` (리눅스 esptool. usbipd 로 attach 한 장치나 네이티브 리눅스) |

`rfc2217://`, `socket://` 같은 네트워크 포트와 그 밖의 경로는 거부한다. 리눅스 포트는 장치가 있어야 하고, 링크의 실제 대상도 `/dev` 아래여야 한다.

일반적인 순서:

1. `esp_version()` — 두 백엔드의 esptool 경로·버전과 interop 상태를 확인한다.
2. `esp_list_ports()` — Windows COM 포트와 USB ID 를 본다. `303a:1001` 은 ESP 내장 USB-Serial/JTAG 이다.
3. 사용자에게 기기 소유/허가를 확인받고 `case_create` 로 케이스를 만든다(pweh-case).
4. `esp_chip_info(case_id, port="COM3")` — 칩 종류·리비전, MAC, 플래시 제조사와 크기를 확인한다.
5. `esp_security_info(case_id, port="COM3")` — Secure Boot, 플래시 암호화, Secure Download Mode 를 확인한다.
   `read_flash_possible=false` 이면 덤프하지 않고, 우회하지 말고 사용자에게 보고한다.
6. `esp_read_flash_start(case_id, port="COM3", size="all", verify="double")` — 덤프 작업을 시작한다.
7. `esp_job_status(job_id, wait_seconds=30)` 으로 진행률을 본다. 끝나면 `dumps/<name>.bin`, `dumps/<name>.read2.bin`, `dumps/<name>.json` 이 생긴다.
8. `case_record_step(skill="firmware-dump-via-uart", step="summary")` 에 firmware-dump 스키마 형식으로 기록한다. 결과의 `summary_hint` 를 그대로 쓰면 된다
   (별도 Skill 스키마가 없다. firmware-static-analysis 와 보고서가 이 요약을 읽는다).

연결할 때마다 esptool 이 칩을 리셋해 ROM 다운로드 모드로 넣는다. 자동 리셋 회로가 없는 보드에서 연결에 실패하면(`esp_no_serial_data`, `esp_wrong_boot_mode`)
사람에게 BOOT 버튼(부트 스트랩 핀. ESP32·ESP32-S2·ESP32-S3 는 GPIO0, ESP32-C3·C6·H2 는 GPIO9 — 그 밖의 칩은 데이터시트로 확인)을 누른 채 RESET(EN)을 눌렀다 떼고 BOOT 를 놓도록 요청한 뒤 `before="no-reset"` 으로 다시 호출한다
(칩을 호출 사이에도 다운로드 모드에 두려면 `after="no-reset-stub"`).
물리 작업과 배선은 [`docs/hardware-setup.md`](../../docs/hardware-setup.md) §8(ESP32 보드), 안전 정책 요약은 [`docs/safety.md`](../../docs/safety.md) §3.3 을 따른다.

## 도구

시그니처는 실제 인자 전체다. 하드웨어 도구는 모두 `case_id` 가 필요하고, 케이스에 소유/허가 증명이 있어야 한다.

| 도구 | 설명 / 주요 반환 |
|---|---|
| `esp_version()` | 기기를 건드리지 않는다. `backends.windows`·`backends.linux` 마다 `{available, path, source, version, major, error}` 를 돌려준다(windows 에는 `wsl`, `interop` 도 붙는다). 그 밖에 `recommended`(windows/linux/None)와 `hints` 를 준다. 버전은 실행 파일 경로·mtime·크기별로 캐시한다 |
| `esp_list_ports()` | 포트를 열지 않는다. `windows["ports"]` 는 powershell.exe 로 Win32_PnPEntity 를 조회한 결과다(이름에 `(COMn)` 이 있는 장치만). 항목은 `{port, name, pnp_device_id, vid, pid, serial_number, usb_id, kind, description_ko}` 이다. `linux["ports"]` 는 pyserial 목록이고 `in_use_by`(그 장치를 연 다른 프로세스 PID)가 붙는다. sysfs 정보가 없는 레거시 `/dev/ttyS*` 는 숨기고 `hidden_legacy_ports` 로 센다. interop 이나 powershell 이 없으면 `windows["available"]=false` 와 `note` 를 준다. `hints` 는 종류별로 다르다: `esp-usb-serial-jtag`(303a:1001)는 esptool 의 USB-JTAG 리셋(`before="default-reset"` 또는 `"usb-reset"`), `esp-usb-otg-rom`(303a:0009·0002, 칩이 이미 ROM USB-OTG 다운로드 모드)은 `before="no-reset"`·`after="no-reset"`(서버가 `no-reset-stub` 으로 바꿔 실행)과 끝난 뒤 사람의 RESET |
| `esp_chip_info(case_id, port, chip="auto", baud=None, before="default-reset", after="hard-reset", no_stub=False, timeout_s=None, approval_id=None)` | esptool `flash-id` 를 실행한다. 반환: `chip`, `chip_description`, `chip_revision`, `features`, `crystal_mhz`, `usb_mode`, `mac`, `flash{manufacturer_id, manufacturer, device_id, size, size_bytes, type_efuse, voltage, voltage_source}`, `secure_download_mode`, `stub`, `log_path`(`uart/esptool-chip-info-NNN.log`), `backend`, `port`, `esptool_version`, `after`(실제로 쓴 값), `after_requested`(`no-reset` 을 바꿨을 때만), `warnings`, `notes`, `next_steps`. `mac` 은 esptool 이 찍은 값(ESP32-C6·H2 는 8바이트 EUI-64), `base_mac` 은 늘 6바이트 MAC, `mac_ext` 는 EUI-64 확장 바이트다. Secure Download Mode 면 flash-id 가 거부되므로 `status="secure_download_mode"`, `read_flash_possible=false` 와 칩 종류만 돌려준다. 두 경우 모두 `provenance{recorded, kind: "device-fact", fact_kind: "esp-chip-info", seq}` 가 붙는다(출처 원장에 칩 정보를 기기 사실로 기록. 실패하면 `recorded: false`, `reason`) |
| `esp_security_info(case_id, port, chip="auto", baud=None, before="default-reset", after="hard-reset", no_stub=False, timeout_s=None, approval_id=None)` | esptool `get-security-info` 를 실행한다. 반환: `status`(`"ok"` 또는 `"unsupported"`), `secure_boot`, `flash_encryption`(SPI_BOOT_CRYPT_CNT 의 1 비트 수가 홀수면 켜짐), `crypt_cnt`, `secure_download_mode`(플래그 비트 2), `read_flash_possible`, `ciphertext_expected`, `jtag_hard_disabled`, `jtag_soft_disabled`, `usb_disabled`, `download_dcache_disabled`, `download_icache_disabled`, `key_blocks[{block, purpose}]`, `flags_hex`, `parsed_flags`, `chip_id`, `api_version`, `assessment`(한국어 판단), `log_path`(`uart/esptool-security-info-NNN.log`), `after`, `after_requested`. Secure Download Mode 에서도 동작한다. 원조 ESP32·ESP8266 은 이 명령을 지원하지 않는다(esptool 스텁은 `FF00: Command not implemented`, ROM 은 `0x14` 미지원) → 오류 대신 `ok=true`, `status="unsupported"`, 보안 필드와 `read_flash_possible` 은 모두 `null`, `assessment` 는 '보안 상태 미확인', `error` 에 esptool 문구, notes 첫 줄이 '미확인'으로 기록하고 진행하라는 안내다(감사 이벤트 `esp_security_summary` 에도 `status`). 두 경우 모두 `provenance{recorded, kind: "device-fact", fact_kind: "esp-security-info", seq}` 가 붙는다(`unsupported` 면 보안 필드 null = 미확인으로 기록) |
| `esp_read_flash_start(case_id, port, chip="auto", offset=0, size="all", output_name=None, baud=921600, verify="double", before="default-reset", after="hard-reset", no_stub=False, timeout_s=None, approval_id=None)` | esptool `read-flash` 를 **job** 으로 돌리고 `{status: "started", job_id, planned_path, planned_read2_path, metadata_path, reads, after, after_requested(바꿨을 때만), read1_after(이중 읽기면 "no-reset-stub"), read1_baud, timeout_s_per_read}` 를 바로 돌려준다. 인자 형식은 아래와 같다. `offset`: 정수 또는 `"0x10000"`. `size`: `"all"`(감지한 플래시 크기, `offset=0` 일 때만), 정수, `"0x400000"`, `"4M"`, `"16MB"`, `"512K"`. `output_name`: 생략하면 `esp-flash`, `esp-flash-002` … 순서로 정한다(`.bin` 은 자동). `verify="double"`(기본)이면 두 번 읽어 sha256 을 비교하고, `"none"` 이면 한 번 읽는다. 1차 읽기는 `--after no-reset-stub` 으로 칩을 다운로드 모드에 둬 앱이 실행되지 않게 하고(NVS 변경 방지), 마지막 읽기 뒤에 요청한 `after` 를 쓴다(`after="no-reset"` 은 `no-reset-stub` 으로 바꿔 실행한다). `before="no-reset"`(수동 다운로드 모드)이면 1차 읽기는 115200 baud 다. 기존 파일은 덮어쓰지 않는다 |
| `esp_job_status(job_id, wait_seconds=0)`, `esp_job_cancel(job_id)`, `esp_jobs(active_only=False)` | `register_job_tools(..., "esp")`. 진행률은 esptool 출력의 % 로 계산한다(두 번 읽으면 읽기마다 절반). 끝난 job 의 `result` 는 아래 "결과 파일" 의 필드와 `provenance`(아래 "출처 원장")를 담는다 |

`baud` 기본값은 정보 도구가 115200, 덤프가 921600 이다. 전송 오류가 나면 460800, 115200 순으로 낮춘다.
ESP 내장 USB-Serial/JTAG 연결에서는 baud 가 속도에 영향을 주지 않는다.
`after` 는 `hard-reset`(기본, 끝나면 앱 재실행), `no-reset-stub`(리셋하지 않고 칩을 다운로드 모드(스텁)에 둠), `watchdog-reset`(esptool v5, v4.12 이상)을 실행한다.
`after="no-reset"` 도 받지만 **항상 `no-reset-stub` 으로 바꿔 실행**하고(응답 `after_requested`·notes) `soft-reset` 은 `validation_failed` 다 — 둘 다 끝날 때 FLASH_BEGIN 을 보내기 때문이다(아래 안전 정책).
`no_stub=True` 는 ROM 로더와 직접 통신한다(전송 MD5 검증 없음). `chip` 을 ESP8266 이 아닌 칩으로 명시해야 한다(`auto`·`esp8266` 이면 `validation_failed`,
아래 안전 정책). ESP8266 은 `no_stub=False`(기본)만 쓴다. ESP32 계열 ROM 은 read-flash 를 지원하지만 ROM 이 지원하지 않는 기능은 `esp_rom_unsupported` 다.
`modify_policy` 가 approve 면 하드웨어 도구가 `approval_required` 와 `approval_id` 를 돌려준다.
사람이 별도 터미널에서 `pweh approve <id>` 로 승인한 뒤 같은 인자에 `approval_id` 를 붙여 다시 호출한다.

## 결과 파일 (케이스)

| 경로 | 내용 | 아티팩트 kind |
|---|---|---|
| `dumps/<name>.bin` | 1차 읽기(대표 덤프) | `flash-dump` (`extra.role="primary"`, `extra.metadata`) |
| `dumps/<name>.read2.bin` | 2차 읽기 (`verify="double"`) | `flash-dump` (`extra.role="verification-read"`) |
| `dumps/<name>.json` | 메타데이터(아래) | `other` (`extra.type="dump-metadata"`) |
| `uart/esptool-chip-info-NNN.log`, `uart/esptool-security-info-NNN.log`, `uart/esptool-<name>-readN-NNN.log` | esptool 출력 로그(정리본). 헤더에 명령·백엔드·버전·종료 코드가 있고, Windows esptool.exe 가 남았거나 남았는지 확인하지 못했으면 그 줄도 있다. 빈 줄과 ANSI 코드는 빼고, 진행률 줄은 5% 단위로만 남긴다 | `other` (`extra.type="esptool-log"`) |

덤프하는 동안 `dumps/` 에는 숨은 예약 파일만 있다: esptool 이 쓰는 `dumps/.<name>.readN.partial` 과 소유 표식 `dumps/.<name>.owner.partial`(서버 PID 등).
esptool 은 **모든 데이터를 받은 뒤에만** 파일을 쓰고, 서버는 크기를 확인한 뒤 끝날 때 최종 파일을 O_EXCL(하드 링크)로 만든다 — 같은 이름이 그사이 생겼으면
덮어쓰지 않고 `<name>-<job_id>` 로 저장한다. 그래서 취소되거나 실패한 읽기에는 부분 데이터가 없고, 예약 파일은 지운다. 서버가 도중에 죽어 남은 예약은
다음 서버 시작 때(또는 같은 케이스의 다음 덤프 시작 때) 주인 프로세스가 끝난 것을 확인하고 지운다.
2차 읽기만 취소되거나 실패하면 1차 결과를 `verification.method="none"` 으로 보존한다. 이때 job 상태는 cancelled 또는 failed 이고,
`result` 에 보존한 1차 결과가 담긴다. 칩이 다운로드 모드(스텁)에 남아 있을 수 있으므로, 일반 부팅이 필요하면 사람이 RESET 을 누른다.

메타데이터는 firmware-dump 요약 스키마([`src/pweh/schemas/firmware-dump.schema.json`](../../src/pweh/schemas/firmware-dump.schema.json))와 같은 모양이다.

```json
{
  "schema": "pweh.esp-dump/v1",
  "method": "esptool-read-flash",
  "source": {"type": "esptool", "device_path": "COM3", "chip": "ESP32-S3", "mac": "f4:12:fa:…", "flash_size": 8388608,
             "flash_size_str": "8MB", "offset": 0, "length": 8388608, "flash_type": "spi-nor"},
  "output": {"path": "dumps/esp-flash.bin", "sha256": "…", "size": 8388608},
  "verification": {"method": "double-read", "expected": "<1차 sha256>", "actual": "<2차 sha256>", "match": true},
  "reads": [{"index": 1, "after": "no-reset-stub", "sha256": "…", "log_path": "uart/…"}, {"index": 2, "after": "hard-reset", "…": "…"}],
  "tool": {"esptool_version": "5.4.0", "backend": "windows", "argv": [["esptool.exe", "--chip", "auto", "…"]]},
  "baudrate": 921600, "status": "succeeded", "notes": [], "warnings": []
}
```

두 읽기의 sha256 이 다르면 job 은 succeeded 지만 `result.match=false` 이고 `warnings` 가 붙는다. 두 파일은 모두 남긴다.
이 경우 전송 오류를 의심해 낮은 baud 로 다시 읽거나, 플래시 불안정(전원·배선)을 의심한다.
`method` 값 `esptool-read-flash` 는 firmware-dump 스키마의 enum 에 있다. 요약은 `skill="firmware-dump-via-uart"` 로 남기고(`verification.method` `double-read`, `expected`/`actual` = 두 읽기의 sha256),
정적 분석 요약의 `firmware.source` 에는 `esptool-dump` 를 쓴다.

### 출처 원장

케이스 밖 `.pweh/state/provenance/<case_id>.jsonl`(코어 `src/pweh/provenance.py`, architecture §4)에 이 서버가 기기에서 읽은 것을 해시 체인으로 남긴다.
- `esp_chip_info`·`esp_security_info` 결과 → `device-fact`(`fact_kind` `esp-chip-info`·`esp-security-info`, source 에 포트·백엔드·칩·MAC·esptool 버전·로그 경로).
- 끝까지 성공한(`succeeded`) 덤프의 읽기 파일(이중 읽기면 두 파일, `verify="none"` 이면 한 파일) → `device-read`. job `result.provenance` 는
  `{recorded, kind: "device-read", entries[{path, seq, sha256}]}` 다. 워커가 esptool 이 쓴 직후 계산한 sha256 을 넘겨, 공개한 파일이 그사이 바뀌었으면 기록하지 않는다.
- 실패·취소 때 보존한 1차 읽기는 기록하지 않는다(`recorded: false`). 두 읽기가 달라도(`match=false`) 기록하고 source 에 `match` 를 남기지만,
  출처 확인(`verify`)은 그런 덤프를 신뢰하지 않는다(`device-read-mismatch` — 출처는 무결성이 아니다).
- 원장 기록에 실패해도 도구 결과와 덤프는 그대로다(`recorded: false`, `reason`. 덤프는 `warnings` 에도 적는다). 메타데이터를 쓴 뒤에 기록하므로 이 경고는 `dumps/<name>.json` 에는 없다.
- 출처 확인(예: 계측기로 플래시하기 전의 백업 확인)은 `case.json` 아티팩트의 `producer` 가 아니라 이 원장으로 한다. 지금 이 원장을 확인하는 도구는 없다.

## 안전 정책

분류기는 `esp_mcp.policy.classify_esptool_argv` 다. 서버는 검증한 인자로 argv 를 직접 조립하고(원시 인자를 그대로 넘기지 않음),
실행할 argv 그대로를 분류한다.

| 명령 | 위험도 | 이유 |
|---|---|---|
| `version` | OBSERVE | 기기 미접촉 |
| `flash-id`, `get-security-info`, `chip-id`, `read-mac` | MODIFY (기본 허용) | 연결 과정의 휘발성 상태 변화. DTR/RTS 또는 USB-Serial/JTAG 리셋으로 ROM 다운로드 모드에 들어가고, RAM 에 플래셔 스텁을 올린다. USB-Serial/JTAG 연결이면 워치독 레지스터를 끄고, SPI 플래시에 리셋 명령(0x66/0x99)을 보내며, `--after` 리셋을 한다. 플래시·eFuse 에 쓰는 명령은 보내지 않는다 — 끝날 때 FLASH_BEGIN 을 보내는 `--after no-reset`·`soft-reset` 은 거부한다(아래) |
| `read-flash` | MODIFY (기본 허용) | 위와 같고, 출력은 케이스 `dumps/` 안의 서버 예약 경로만 허용한다 |
| 그 밖의 모든 것 | DESTRUCTIVE | 아래 목록 참고 |

DESTRUCTIVE 로 분류하는 것은 다음과 같다.

- 플래시를 바꾸는 명령: `write-flash`, `erase-flash`, `erase-region`, `write-flash-status`
- 메모리와 실행 관련 명령: `write-mem`, `load-ram`, `run`, `read-mem`·`dump-mem`(임의 MMIO 읽기는 부작용이 있을 수 있음)
- 이 서버 범위 밖의 오프라인 도구: `merge-bin`, `image-info`, `elf2image`
- 알 수 없는 명령과 옵션. `--override-vddsdio`, `--port-filter`, `--spi-connection`, 짧은 옵션도 포함한다
- espefuse·espsecure·rfc2217 서버 실행 파일
- `@파일` 인자. esptool 이 파일 내용을 인자로 펼치기 때문이다
- 명시하지 않은 `--port`(esptool 이 모든 포트를 훑음)나 검증한 포트와 다른 `--port`
- `--connect-attempts 0`(무한 재시도)
- `--after no-reset`(`esp.after.no-reset`)과 `--after soft-reset`(`esp.after.soft-reset`): 끝날 때 FLASH_BEGIN 을 보낸다. 레거시 스텁(esptool 4.8~5.2 의 기본,
  `ESPTOOL_STUB_VERSION=1`)은 FLASH_BEGIN 에서 SPI 플래시 상태 레지스터를 다시 쓴다(비휘발성, 쓰기 보호 해제). `--chip auto` 는 칩에 남은 스텁을 `--no-stub` 이어도
  스텁으로 다루므로 서버는 plain `no-reset` 을 넘기지 않고 `no-reset-stub` 으로 바꾼다. 이중 읽기의 1차 읽기도 `--after no-reset-stub` 이다
- `--no-stub` 과 `--chip esp8266`·`--chip auto`(`esp.nostub.esp8266`): ESP8266 ROM 에는 플래시 연결 명령이 없어 esptool 이 대신 `FLASH_BEGIN(0, 0)` 을
  보낸다(4.8.1 은 `--no-stub` 이면 모든 명령, 5.x 는 flash-id·read-flash). 위와 같은 FLASH_BEGIN 위험이고(하드웨어로는 확인하지 않음) `auto` 는 ESP8266 으로
  판정될 수 있다. 인자 검증도 `no_stub=True` 에 `chip` 이 `auto`·`esp8266` 이면 `validation_failed` 로 거부한다
- `read-flash` 뒤의 추가 옵션, `offset` 이 0 이 아닌데 `size=all`, 케이스 `dumps/` 밖의 출력 경로

DESTRUCTIVE 는 안전 게이트에 넘기지 않고 `{ok: false, status: "denied", gate: {via: "esp-policy"}}` 로 바로 거부한다.
그래서 `destructive_policy: approve` 여도 승인할 방법이 없다. 재시도하지 말고 사용자에게 보고한다.

- 모든 명령에 `--chip`, `--port`, `--baud`, `--before`, `--after`, `--connect-attempts 7` 을 명시한다.
- esptool 은 매번 새로 만든 작업 디렉터리에서 실행하고, 그 안에 빈 `[esptool]` 설정(`esptool.cfg`)을 써서 `ESPTOOL_CFGFILE` 로 가리킨다.
  이 환경변수는 esptool 의 설정 파일 탐색(현재 디렉터리 → `~/.config/esptool` 또는 `%USERPROFILE%\AppData\Local\esptool` → 홈)보다 앞선다.
  리눅스 esptool 은 `ESPTOOL_*`·`FORCE_COLOR`·IDE 웹소켓 변수를 지운 환경에서 HOME 도 작업 디렉터리로 바꿔 돈다. Windows exe 는 Windows 쪽 사용자
  환경변수를 물려받으므로 `ESPTOOL_CFGFILE`(WSLENV `/p`), `ESPTOOL_STUB_VERSION`(esptool 5.3 이상 "2", 그 밖 "1"), `ESPTOOL_OPEN_PORT_ATTEMPTS=1`,
  `ESPTOOL_FS=keep` 같은 중립값을 WSLENV 로 넘겨 덮어쓴다.
  서버가 만든 것이 아닌 설정 파일을 읽었다는 줄(`Loaded custom configuration from …`)이 보이면 연결 전에 멈추고 `esp_foreign_config` 오류를 낸다.
- esptool v5 는 하이픈 이름(`read-flash`, `default-reset`)을, v4 는 밑줄 이름(`read_flash`, `default_reset`)을 쓴다.
  버전을 모르면 밑줄 이름을 쓴다(v5 도 경고와 함께 받아들인다). `after="watchdog-reset"` 은 v5 와 v4.12 이상에서만 허용한다.
- 백그라운드 읽기는 esptool 을 띄우기 직전마다 argv 를 다시 분류하고, 케이스의 소유/허가 증명도 다시 확인한다.
  도중에 증명이 철회되면 `authorization_required` 로 멈춘다.
- 같은 포트는 한 번에 한 작업만 쓴다. 포트 잠금과 job 배타 키(`esp-port:<포트>`)를 쓰며, 이 보호는 서버 프로세스 안에서만 유효하다.
  리눅스 포트는 realpath 로 묶는다. 다른 프로세스가 그 tty 를 열고 있으면 `busy` 로 거부한다(시리얼 모니터, uart-mcp 세션).
- 취소하거나 시간이 초과되면 프로세스 그룹을 SIGTERM, 이어서 SIGKILL 로 끝낸다. Windows esptool.exe 는 PyInstaller onefile 이라 WSL interop 프로세스를
  죽여도 자식(실제 esptool)이 COM 포트를 잡은 채 남는다(실측). 그래서 명령줄 표식(덤프는 UNC 출력 경로, 정보 명령은 `--port COMn` + 명령)으로 Windows
  프로세스를 찾아 자식부터 끝내고(부트로더가 `%TEMP%\_MEI*` 를 지우고 끝남) 남은 것이 없을 때만 취소로 보고한다. 남으면 PID 를 담은
  `esp_orphan_process` 오류를 내고, 그 COM 포트를 인자로 받은 esptool.exe 가 있는 동안 같은 포트의 호출은 `busy` 로 거부한다.
  덤프는 출력 없이 180초가 지나면 멈춘 것으로 본다.
- 서버가 SIGTERM 을 받으면 실행 중인 작업을 취소·정리한 뒤(최대 30초) 끝나고, stdin 이 닫혀도 정리한 뒤 끝난다. 서버가 그래도 도중에 죽으면 다음 시작 때
  주인 프로세스가 끝난 예약 파일을 모든 케이스에서 지우고(감사 이벤트 `esp_stale_reservations_removed`), 그 프로세스의 queued·running·cancelling 작업 기록
  (`jobs/<id>.json`)을 `abandoned` 로 고친다(`esp_jobs_abandoned`). 덤프 도중 `dumps/` 가 심볼릭 링크로 바뀌거나 실제 경로가 달라지면 `safety_denied` 로 멈춘다.
- 서버가 SIGKILL 로 죽으면 정리할 기회가 없다. 그때 Windows esptool.exe 는 자식이 남아 COM 포트를 잡고 예약 파일에 계속 쓸 수 있고, 부트로더가 먼저 끝나므로
  `%TEMP%\_MEI*` 압축 해제 디렉터리가 남는다(막을 수 없음 — 사람이 지운다). 그래서 Windows 백엔드 덤프는 첫 esptool.exe 를 띄우기 전에 출력 UNC 경로를
  소유 표식(`windows_tokens`, `windows_images`)에 적는다. 다음 서버의 정리는 명령줄에 그 경로가 있는 esptool.exe 가 살아 있으면(또는 확인할 수 없으면) 예약 파일을 지우지 않는다.
  같은 포트의 호출은 그 프로세스가 끝날 때까지 `busy` 다.
- 알려진 한계: powershell.exe 가 실패하면 Windows 프로세스 확인이 약해진다(포트 확인은 기록만 하고 진행, 취소는 경고와 함께 `cancelled`).
  IDE 웹소켓 로그 미러 변수(`ESP_IDE_WS`·`ESPRESSIF_IDE_WS`)는 리눅스 쪽에서는 지우지만, WSLENV 가 빈 값을 넘기지 못해 Windows exe 쪽에서는 중립화할 수 없다
  (esp-pylib 은 연결 실패를 조용히 무시하고 기기 동작은 바꾸지 않는다).
  esptool 4.8.1 의 `ESPTOOL_TESTING` 도 Windows 쪽에서 지울 수 없다(4.8.1 의 스트래핑 검사에만 영향). 버전 확인(`esptool version`)은 기기를 건드리지 않아
  남의 설정 파일 검사를 하지 않고, 첫 기기 호출이 검사한다.

Secure Download Mode 에서는 esptool 이 플래시를 읽을 수 없다(`esp_secure_download_mode`). 이 서버는 글리칭이나 eFuse 조작 같은 우회를 하지 않는다.
플래시 암호화가 켜져 있으면 덤프는 암호문이다(`ciphertext_expected=true`).

## 설정과 설치

| 설정 키 (`orchestrator/pipeline-config.yaml` 의 `tools`) | 환경변수 | 기본값 |
|---|---|---|
| `esptool` | `PWEH_ESPTOOL` | `esptool` (PATH. 없으면 `esptool.py`) |
| `esptool_win` | `PWEH_ESPTOOL_WIN` | 비어 있음 |

`esptool_win` 이 비어 있으면 외부 도구 디렉터리(기본 `~/pweh-tools`)의 `esptool-win/esptool-windows-amd64/esptool.exe` 를 찾는다.
값은 리눅스 경로나 `C:\tools\esptool.exe` 같은 Windows 경로로 줄 수 있다. Windows 경로는 `wslpath -u` 로 바꾼다.
리눅스 파일시스템에 푼 exe 는 실행 권한이 필요하다(`chmod +x`). 설치는 `scripts/install.sh` 의 esptool 항목(`--only esptool`)을 쓰거나
Espressif 공식 릴리스의 `esptool-vX.Y.Z-windows-amd64.zip` 을 풀어 경로를 지정한다. 변경 후에는 MCP 서버를 다시 시작한다.

Windows 백엔드의 조건은 셋이다. WSL 안이어야 하고, `/proc/sys/fs/binfmt_misc/WSLInterop` 이 `enabled` 여야 하며, `wslpath` 가 있어야 한다.
COM 포트 목록은 `powershell.exe -NoProfile -NonInteractive` 를 현재 디렉터리 `/mnt/c` 에서 실행해 얻는다. cmd.exe 는 UNC 현재 디렉터리를 거부하므로 쓰지 않는다.
Windows esptool.exe 의 출력은 조각마다 엄격한 UTF-8 로 읽고(조각 경계의 멀티바이트 문자는 이어 붙임), UTF-8 이 아니면 Windows ANSI 코드 페이지(레지스트리 ACP 를 한 번 조회, 한국어 Windows 는 cp949)로 읽는다.
OS 오류 문구는 Windows 언어로 나오므로 서버는 esptool 의 영어 문구와 오류 번호로 판정한다. PyInstaller 로 굳힌 exe 는 `PYTHONIOENCODING` 같은 PYTHON* 변수를 무시하므로 넘기지 않는다.

## 오류 코드

esptool 이 실패하면 아래 코드와 힌트를 담은 오류가 난다. 메시지에는 로그 경로가 들어간다. 덤프 job 이면 `error.code` 에 담긴다.

| 코드 | 상황 | 대처 |
|---|---|---|
| `esp_port_not_found`, `esp_port_open_failed` | 포트가 없거나 열 수 없다 | `esp_list_ports` 로 다시 확인한다. usbipd 로 attach 한 장치는 Windows 에서 사라진다. 열 수 없으면 아래 `esp_port_busy` 처럼 포트를 잡은 프로그램도 확인한다 |
| `esp_port_busy` | 포트를 쓰는 중이거나 접근이 거부됐다 | 시리얼 모니터(Arduino IDE, idf.py monitor, PuTTY), 다른 esptool, uart-mcp 세션을 닫는다. 서버가 그 COM 포트를 인자로 받은 esptool.exe(`--port COMn`·`--port=COMn`·`-p COMn`)를 Windows 프로세스 목록에서 찾으면 esptool 을 띄우기 전에 `busy`(`data.pids`, `taskkill /F /PID n` 안내)로 거부한다 |
| `esp_port_permission` | 리눅스 tty 권한이 없다 | 사람이 dialout 그룹 추가나 udev 규칙을 설정한다 |
| `esp_no_serial_data`, `esp_wrong_boot_mode`, `esp_connect_failed`, `esp_app_running` | 칩이 다운로드 모드가 아니다 | BOOT 를 누른 채 RESET 한 뒤 `before="no-reset"` 으로 재시도한다. 네이티브 USB 와 UART 브리지 포트를 확인하고, 데이터 케이블을 쓴다 |
| `esp_tx_path_down` | 다운로드 모드는 보이지만 동기화가 안 된다 | TX→RX 배선을 확인한다 |
| `esp_serial_noise`, `esp_digest_mismatch` | 전송이 손상됐다 | baud 를 낮추고 케이블을 짧게 한다 |
| `esp_baud_switch_failed` | baud 를 바꾼 직후 통신이 끊겼다(출력에 `Changed.` 가 있을 때만, 요약 'baud 변경 직후 통신 끊김'). USB-UART 브리지가 921600 을 버티지 못하는 경우가 많다 | `esp_read_flash_start` 를 `baud=460800`, 그래도 실패하면 `baud=115200` 으로 다시 시도한다 |
| `esp_secure_download_mode` | Secure Download Mode 다 | 덤프할 수 없다. 우회하지 말고 보고한다 |
| `esp_flash_size_unknown`, `esp_size_exceeds_flash` | 플래시 크기 문제다 | `size` 를 명시한다(`esp_chip_info` 의 `flash.size`) |
| `esp_wrong_chip` | `chip` 인자가 실제 칩과 다르다 | `chip="auto"` 로 다시 시도한다 |
| `esp_rom_unsupported` | ROM 로더가 지원하지 않는 기능이다(ESP8266 ROM 은 read-flash 미지원. 그 밖의 ESP32 계열 ROM 은 읽을 수 있다) | `no_stub=False`(기본)로 다시 시도한다 |
| `esp_stub_failed`, `esp_chip_stopped`, `esp_port_io_error` | 스텁이나 연결이 불안정하다 | RESET 이나 USB 재연결 후 다시 시도한다 |
| `esp_invalid_argument`, `esp_version_failed` | esptool 이 인자를 모른다(오래된 버전), `esptool version` 이 실패했다 | `esp_version` 으로 버전을 확인한다. v4.8 이상을 권장한다 |
| `esp_output_size_mismatch` | 출력 파일 크기가 다르다 | 다시 시도한다 |
| `esp_foreign_config` | esptool 이 서버가 만든 빈 설정이 아닌 설정 파일을 읽었다(`Loaded custom configuration from <다른 경로>`). 그 줄이 보이는 즉시 프로세스를 끝낸다(`data.config`, `data.expected`) | 사람이 그 파일의 `[esptool]` 섹션을 확인·제거하거나 파일을 옮긴 뒤 다시 시도한다 |
| `esp_orphan_process` | 취소·시간 초과·서버 종료 뒤 Windows esptool.exe 가 남았다(`data.pids`). 덤프면 숨은 예약 파일을 그 프로세스가 끝날 때까지 남긴다 | 사람이 작업 관리자나 `taskkill /F /PID n` 으로 끝내거나 보드를 다시 연결한다. 그동안 같은 COM 포트의 호출은 `busy` 다 |
| `esp_bad_output`, `esp_failed` | 출력을 해석하지 못했거나 분류되지 않은 실패 | 로그를 확인한다(원조 ESP32·ESP8266 의 get-security-info 미지원은 오류가 아니라 `status="unsupported"`) |
| `timeout` | 시간 초과 또는 출력 없이 멈췄다 | `timeout_s` 와 baud 를 확인한다. Windows 는 취소와 같은 방식으로 esptool.exe 를 끝낸다(남으면 `esp_orphan_process`) |

## 테스트

`tests/servers/test_esp_mcp.py` 는 기기 없이 돈다. 가짜 esptool(`tests/servers/esp_fake_esptool.py`)이 esptool 5.4.0 과 4.8.1 의 출력을 소스 그대로 흉내 낸다.
이름이 `.exe` 로 끝나면 Windows 빌드처럼 동작한다(CRLF 줄 끝, ASCII 진행 막대, UNC 출력 경로, cp949 OS 오류 문구).
테스트는 리눅스 포트 확인, interop 감지, `wslpath` 변환을 바꿔 끼운다. 포트는 열지 않는다.

Windows 프로세스 조회·종료(`winproc`)는 `/proc` 의 가짜 esptool.exe(PyInstaller onefile 흉내: 부트로더 + 새 세션의 자식)를 Windows 프로세스처럼 보여 주는 `FakeWinProcs` 로 바꾼다.

`@pytest.mark.external` 테스트는 실제 esptool 5.4.0 을 기기 없이 실행한다(Windows esptool.exe 는 WSL interop, `PWEH_ESPTOOL_WIN` 이나 `~/pweh-tools/esptool-win/…`). 없으면 건너뛴다.
- `esp_version` 이 5.4.0 을 보고하는지 확인한다.
- 케이스 `dumps/` 경로를 서버의 변환 함수로 바꾼 뒤 `esptool.exe merge-bin`(파일만 씀)으로 그 경로에 쓰게 한다. 공백이 든 경로와, 미리 예약한 빈 파일을 덮어쓰는 경우를 포함한다.
- 없는 `COM99` 를 `ESPTOOL_OPEN_PORT_ATTEMPTS=0` 으로 끝없이 재시도시키고 취소해, 부트로더와 자식이 모두 끝나고 새 `%TEMP%\_MEI*` 가 남지 않는지 본다.
- `…\x.\out.bin` 처럼 '.' 으로 끝나는 경로 요소는 Windows 가 `…\x\out.bin` 에 쓴다는 것을 실제 exe 로 확인하고, 서버의 경로 검사가 그런 경로를 거부하는지 본다.
- 홈(`~/.config/esptool`, `%USERPROFILE%\AppData\Local\esptool`)에 설정이 있어도 서버 환경에서는 실행 디렉터리의 빈 설정만 읽는지(대조 실행은 홈 설정을 읽음) 본다.
