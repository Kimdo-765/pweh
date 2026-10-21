# 펌웨어 에뮬레이션 참고 (firmware-emulation reference)

[SKILL.md](SKILL.md) 의 보충 자료다. 도구 이름·인자·기본값은 `docs/references/pweh-mcp-tools.md`(자동 생성 카탈로그)가 기준이고, 동작은 `mcp-servers/emu-mcp/README.md` 와 `docs/architecture.md` §6.9(계약),
설계 근거와 위협 모델은 `docs/design/emulation.md`, 알려진 한계는 `docs/safety.md` §3.7 이다. 아래 응답 모양은 그 계약에서 옮겼고, 예시 값은 모양을 보이는 합성 값이다(실제 기기 값이 아니다).

## 1. 도구 응답 필드와 경고

| 도구 | 동작 | 볼 필드 |
|---|---|---|
| `emu_status` | 조회 전용, 케이스 없음. 게스트를 실행하지 않는다. 실행 파일마다 버전·머신 목록을 서버의 실행 shim(자원 한도·최소 환경)으로 묻고 경로·크기·mtime·inode 로 캐시한다. 버전 문자열은 정확히 고정값이어야 한다 | `backends["esp-qemu"]{available, xtensa{path, source(config/env/pweh-tools), version, expected_version, version_ok, machines, error}, riscv32{…}, chips}`, `backends["avr-simavr"]{available, path, source, version, driver_version, simavr_commit, expected_commit, version_ok, boards, mcus, error}`, `isolation{netns(available/unavailable/unknown), seccomp(false), core_pattern_piped}`, `limits`, `sessions{this_process}`, `hints`. 실행 파일·ROM 의 sha256 이 고정값과 다르거나 ROM 이 없으면 경고만 붙는다 |
| `emu_start` | MODIFY `emu.start`. 인자 검증 → 실행 파일 → 경로 가드(`forensics/`·`emu/` 거부) → 바이트를 한 번 읽음 → 출처 확인(필요하면 provenance-import 증명) → 계획(칩·보드·PSRAM·패딩·eFuse·비밀값 수집) → argv 검사 → 세션 상한 → 게이트 → 감독 스레드가 실행 → exec 확인 | `session_id`, `state`("running"), `backend`(esp-qemu/avr-simavr), `target{chip 또는 board, mcu, freq_hz, machine, vcpus}`, `firmware{path, sha256, size, provenance_reason, verify, ledger_seq, attestation_id}`, `working_copy{sha256, size, padded_from, handoff}`(파일 경로 없음 — 세션에 펌웨어 사본을 두지 않고 봉인한 메모리 파일로 넘긴다), `psram{mode, mb, source}`, `limits{timeout_s, idle_timeout_s, rlimit_as, rlimit_cpu}`, `isolation{monitor "none", network "none", netns, snapshot, gdbstub false, semihosting false}`, `masking{patterns, known_secrets, nvs_encrypted}`, `cursor`(0), `dir`, `warnings`, `notes`, `next_steps` |
| `emu_read` | 조회 전용. 끝난 세션도 읽는다. 부를 때마다 무활동 시간을 다시 잰다. 인자 since_cursor (생략 = 에이전트 읽기 위치), max_chars (256~65536, 기본 8000), wait_seconds (0~50), until (문자열 하나 또는 1~8개 목록, 각 1~64자 — 글자 그대로 비교), until_ignore_case, tail, case_id (메모리에 없는 끝난 세션) | `session_id`, `state`, `source`(live/transcript), `text`, `cursor_start`, `cursor_end`, `more`, `pending_line`, `lines`, `collapsed`, `lost_bytes`, `note`, `matched`, `match`, `raw_total`, `raw_dropped`, 끝났으면 `stopped_by`·`exit{code, signal}`, `hints` |
| `emu_write` | INTERACT `emu.write`(늘 허용, 감사). encoding text(UTF-8 바이트 그대로) 또는 hex(공백 허용), 1~4096 바이트, 비차단 쓰기 합계 2초 — 일부만 쓸 수 있다. 감사·events.jsonl 에는 바이트 수와 인쇄 가능 여부만 | `bytes_written`, `bytes_requested`, `partial`, `cursor`(쓰기 시점의 원시 바이트 총량 — since_cursor 로 주면 레코드 시작으로 내려간다), `state`, partial 이면 `note` |
| `emu_stop` | 게이트 없는 정리. 이유를 먼저 기록 → SIGTERM → 3초 → SIGKILL(프로세스 그룹) → 기록 마감 → 아티팩트 등록 → state ended. 끝난 세션에 다시 불러도 된다 | `session_id`, `state`, `stopped_by`, `exit{code, signal}`, `duration_s`, `raw_bytes`, `raw_dropped_bytes`, `transcript_lines`, `artifacts[{path, kind, type}]`, `meta_path`, `stderr_tail`, 이미 끝났으면 `already_stopped` |
| `emu_sessions` | 조회 전용. 이 서버 프로세스의 세션(끝난 것 포함)과 디스크로 본 다른 프로세스의 살아 있는 세션 수. 콘솔 글은 없다 | `sessions[{session_id, case_id, backend, target, state, stopped_by, started_at, uptime_s, timeout_in_s, idle_timeout_in_s, raw_bytes, cursor_end, firmware{path, sha256}, dir}]`, `count`, `other_process_live{<case_id>: n}`, `limits` |

**`emu_start` 의 warnings** (거부가 아니다 — 경고마다 `<id>: <설명>` 문자열이다. 사용자에게 알리고 요약의 sessions[].warnings 에 그대로 옮긴다):

| 경고 id | 뜻 | 할 일 |
|---|---|---|
| single_read | device-read 덤프가 이중 읽기로 확인되지 않았다(원장 source.verify "none") | 실행은 된다. 결과가 이상하면 이중 읽기 덤프로 다시 |
| partial_dump | 덤프가 부트로더 헤더가 선언한 플래시 크기보다 작다(앱 파티션이 빠졌을 수 있다). 서버는 0xFF 로 채워 실행한다 | 부팅이 앱에서 멈추면 전체 덤프인지 확인한다 |
| octal_flash_unsupported | 같은 MAC 의 `esp_chip_info` 사실에서 플래시가 옥탈이다. 이 에뮬레이터는 표준 SPI-NOR 명령만 다룬다 | 부팅하지 않을 수 있다 — 예상된 실패로 적는다 |
| security_state_unknown | 같은 MAC 의 보안 사실이 없거나 값이 null(원조 ESP32), 덤프 기록에 MAC 이 없음, 또는 가져온 ESP 이미지 | 플래시 암호화를 확인하지 못했다. `invalid header` 로 멈추면 암호문일 수 있다 |
| partition_table_missing | 파티션 표를 찾지 못했다 — NVS 비밀값을 미리 거두지 못해 패턴 마스킹만 한다 | 마스킹이 약해졌음을 알고 읽는다. 표가 옮겨졌는지·암호문인지 정적 분석으로 확인 |
| binary_sha256_mismatch, rom_sha256_mismatch, rom_missing | 설치된 QEMU 실행 파일이나 ROM 파일이 설치 스크립트가 고정한 것과 다르거나 없다 | 사람에게 알리고 다시 설치(`--force --only qemu_esp`)를 권한다 |
| avr_driver_version | `pweh_avr_run` 의 드라이버 버전이 저장소 소스와 다르다(실행기 소스가 바뀐 뒤 다시 빌드하지 않음) | 사람에게 다시 빌드(`--force --only simavr`)를 권한다 |
| core_pattern 이 파이프라는 경고 | 호스트의 코어 덤프가 수집 프로그램으로 가는 설정이면 커널이 코어 덤프 한도(0)를 지키지 않는다 — 게스트 메모리(덤프의 비밀)가 호스트 크래시 저장소에 갈 수 있다(`emu_status` 의 isolation.core_pattern_piped) | 경고만이다. 사람에게 알린다 |

- isolation.netns 가 false 면 빈 네트워크 네임스페이스를 쓰지 못했다(비특권 사용자 네임스페이스를 막은 호스트). 네트워크 장치 없는 명령줄(`-nic none`)만 남는다 — 사람에게 알리고 sessions[].netns 에 적는다.
- masking.nvs_encrypted 가 true 면 NVS 가 암호화돼 비밀값을 미리 거두지 못했다 — 패턴 마스킹만 한다. known_secrets 는 거둔 비밀값 개수다(값은 어디에도 없다).

**PSRAM 값** (`psram` 은 auto·none·quad·octal, `psram_mb` 는 크기. 서버의 auto 규칙과 다시 시작할 때 고를 값):

| 칩 | auto 가 고르는 것 | 명시할 수 있는 값 |
|---|---|---|
| esp32 | quad 4 MiB | none, quad(psram_mb 2·4) |
| esp32s3 | 같은 MAC 의 `esp_chip_info` features 에 Embedded PSRAM N MB 가 있으면 N ≥ 8 → octal N, N 이 2·4 → quad N. 없으면 quad 32 MiB(ESP-IDF 기본) | none, quad(2·4·8·16·32), octal(4·8·16·32) |
| esp32c3 | none | none(auto 와 같음) |

- 다시 시작할 값은 근거로 고른다: 사람이 아는 모듈 표기(예: ESP32-S3-WROOM-1-N16R8 — R 뒤 숫자가 PSRAM MB 이고 R8·R16V 는 octal, R2 는 quad 로 알려져 있다. 모듈 데이터시트로 확인), 콘솔의 PSRAM 오류 문구, 정적 분석의 앱 설정 문자열.
- **PSRAM 재시작은 최대 2번**이다(세션 3개까지). 그래도 PSRAM 오류면 멈추고 limitations 에 "PSRAM 재시도 2회 소진" 을 적는다. 부트로더 뒤 조용함은 PSRAM 문제가 아니다(§3).

## 2. 요약 data 매핑

| 요약 필드 | 가져올 곳 |
|---|---|
| backends."esp-qemu" | `emu_status` 의 backends["esp-qemu"] 에서 쓴 쪽(xtensa 또는 riscv32)의 version. 쓸 수 없었으면 null |
| backends."avr-simavr" | `emu_status` 의 backends["avr-simavr"].version(`pweh_avr_run <버전> simavr <커밋>` 한 줄). 쓸 수 없었으면 null |
| sessions[].session_id · backend | `emu_start` 의 session_id · backend |
| sessions[].target · mcu · freq_hz | `emu_start` 의 target.chip(ESP) 또는 target.board(AVR), AVR 의 target.mcu · target.freq_hz. ESP 는 mcu·freq_hz 를 null 로 |
| sessions[].firmware.path · sha256 | `emu_start` 의 firmware.path · sha256 — 출처를 확인한 원본의 해시다(패딩한 작업 이미지의 working_copy.sha256 이 아니다) |
| sessions[].firmware.provenance · verify · ledger_seq · attestation_id | firmware.provenance_reason(device-read / imported-attested) · verify(device-read 는 double-read / none, 가져온 파일은 null) · ledger_seq · attestation_id(가져온 파일이면 필수) |
| sessions[].options | ESP: `emu_start` 의 psram{mode, mb, source} 와 쓴 watchdog · on_reset. AVR 은 생략 |
| sessions[].stopped_by · duration_s · exit | `emu_stop`(끝난 세션이면 그 응답 그대로, 또는 `emu_read` 의 stopped_by · exit) |
| sessions[].boot_stage | §3 표로 판단한 가장 먼 단계 |
| sessions[].observations | 마스킹한 `emu_read` 글에서 본 것을 짧게. 가림 표시는 그대로 두고 되살리지 않는다. 사용자가 보낸 비밀번호·계정은 적지 않는다 |
| sessions[].warnings · netns | `emu_start` 의 warnings · isolation.netns |
| sessions[].transcript_path | `emu_stop` 의 artifacts 중 type emu-transcript 의 path(경로만 — 열지 않는다) |
| limitations | Wi-Fi·BT·USB 미에뮬레이션, USB 콘솔 단서, PSRAM 재시도 소진, 옥탈 플래시, 한도로 끝남, 마스킹 한계(NVS 암호화) 등 |
| finding_ids | SKILL 9단계에서 기록한 발견사항 id |
| safety | 두 값 모두 false (항상) |
| notes | USB 콘솔 확인 결과, PSRAM 재시작 횟수, 사람 결정(증명·승인), 세션 정리 확인 |

AVR 세션 하나의 예시다(합성 값 — 펌웨어는 저장소의 UART 에코 시험 픽스처와 같은 sha256 을 쓴 가상의 반입 파일). emulation 스키마 검증을 통과한다.

```json
{
  "backends": {"esp-qemu": null, "avr-simavr": "pweh_avr_run 1.0 simavr 5b08da60497f7564f50941f74a549fe2851db030"},
  "sessions": [
    {"session_id": "uno-001", "backend": "avr-simavr", "target": "uno", "mcu": "atmega328p", "freq_hz": 16000000,
     "firmware": {"path": "dumps/uno-flash.hex", "sha256": "473124e258f7a86313fdb251e198a9ffaa5cbe9280c6da970eb86681ae31fafa", "provenance": "imported-attested", "verify": null, "ledger_seq": 2, "attestation_id": "att-0001"},
     "stopped_by": "guest-halt", "duration_s": 6.2, "exit": {"code": 0, "signal": null}, "boot_stage": "console",
     "observations": ["시작하자 OK 출력", "사용자가 원한 문자열 hello 를 보내자 그대로 에코", "0x04 를 보내자 펌웨어가 인터럽트를 끈 채 멈춤 (guest-halt, rc 0)"],
     "warnings": [], "netns": true, "transcript_path": "emu/uno-001/transcript.masked.txt"}
  ],
  "limitations": ["보드의 외부 회로(센서·디스플레이)는 없음 — USART 콘솔만 관찰"],
  "finding_ids": [],
  "safety": {"raw_console_opened": false, "monitor_or_network_used": false},
  "notes": ["case_import_file 로 가져온 HEX — 사람이 pweh attest 로 출처 증명 (provenance-import)", "emu_stop 으로 정리, emu_sessions 에 실행 중인 세션 없음"]
}
```

## 3. 부팅 단계와 진단 힌트

**부팅 단계 읽기** (ESP — 마스킹한 글로 판단, 요약의 boot_stage):

| boot_stage | ESP32 | ESP32-S3 | ESP32-C3 |
|---|---|---|---|
| rom (ROM 배너) | `ets Jul 29 2019 12:21:46`, `rst:0x1 (POWERON_RESET),boot:0x12 (SPI_FAST_FLASH_BOOT)` | `ESP-ROM:esp32s3-20210327`, `Build:Mar 27 2021`, `rst:0x1 (POWERON),boot:0x4 (SPI_FLASH_BOOT)` | `ESP-ROM:esp32c3-api1-20210207`, `Build:Feb  7 2021`, `rst:0x1 (POWERON),boot:0x8 (SPI_FAST_FLASH_BOOT)` |

- **rom**: ROM 배너 뒤 ROM 이 2단계 부트로더를 읽는 줄(`load:0x…,len:…`, 마지막에 `entry 0x…`)까지. 그 뒤가 `invalid header: 0xffffffff` 반복이면 부트로더가 없다(빈 플래시·잘못된 오프셋 — 전체 덤프인지 확인). `entry 0x…` 뒤 아무것도 없으면 rom 으로 적고 그 사실을 observations 에 적는다(부트로더가 조용히 돌았는지 알 수 없다).
- **bootloader**: ESP-IDF 2단계 부트로더의 로그(`boot:` 태그의 ESP-IDF 버전·칩·플래시 크기·파티션 표, `esp_image:` 세그먼트, `Loaded app from partition at offset 0x…`)가 보이고 앱 출력은 없다. Arduino 빌드는 부트로더가 조용한 경우가 많다.
- **app**: 앱의 로그(`cpu_start`·`app_init`·`main_task` 같은 태그, 앱 설명·ESP-IDF 버전, 작업 시작, Arduino 스케치의 Serial 출력)나 패닉(`Guru Meditation Error`)이 보인다.
- **console**: 앱의 대화형 프롬프트·메뉴(`esp32> `, `login: `, AT 명령 응답 등)가 보이고 입력에 답했다.
- **none**: 출력이 전혀 없다(세션이 바로 끝났거나 콘솔이 UART0 이 아님). **unknown**: 판단할 수 없다.
- AVR 은 ROM·부트로더 단계가 없다(실행기가 PC=0 에서 시작 — 플래시 끝의 Optiboot 같은 부트로더는 건너뛴다). 펌웨어 출력이 보이면 app, 대화형이면 console, 출력이 없으면 none 이다.

**진단 힌트** (`emu_read` 의 hints — 서버가 마스킹한 글에서만 만든다. 조치는 SKILL 7단계 표):

| 힌트가 붙는 때 | 뜻 |
|---|---|
| `invalid header: 0xffffffff` 가 반복된다 | 빈 플래시이거나 부트로더 오프셋이 다르다 — 전체 덤프(오프셋 0)인지 확인. C3 는 초당 수백 KB 를 쏟으므로 반복 접기·원시 로그 상한이 걸린다 |
| `Guru Meditation Error` | 패닉. 원인 줄(예외 종류·PC·레지스터·backtrace)을 본다. 미구현 주변장치·PSRAM 설정 때문일 수 있다 |
| PSRAM 초기화 실패 | PSRAM 이 없거나 모드·크기가 다르다 — 정지 후 다른 psram 으로 다시(최대 2번, 서버도 그렇게 알린다) |
| `rst:0x3` 이 반복된다 | 리셋 루프(on_reset "reboot" 일 때). "exit" 면 첫 리셋에서 세션이 끝난다(stopped_by guest-reset) |
| Wi-Fi 초기화 대기 | Wi-Fi 는 에뮬레이션되지 않는다 — 예상된 한계 |
| 부트로더 `Loaded app`·`entry 0x` 뒤 10초 이상 조용함 | 앱 콘솔이 USB-Serial-JTAG·USB-CDC·UART1 에 있을 수 있다(에뮬레이션 안 됨). PSRAM 문제가 아니다 — psram 을 바꿔 다시 시작하지 않는다 |

- 실제 펌웨어의 문구는 ESP-IDF·Arduino 버전마다 다르다. 힌트가 없어도 위 표의 문구가 보이면 같은 판단을 한다.
- stderr 는 `emu_stop` 의 stderr_tail(허용한 진단 줄만, 마스킹, 2000자 이하)로만 본다. 실행 중 stderr 에 `invalid class name` 이 나오면 서버가 세션을 config-error 로 끝낸다.

## 4. 오류 처리 전체

동기 도구의 오류는 `[code] 메시지` + `힌트:` 텍스트로 온다. 게이트는 오류가 아니라 응답의 status(attestation_required / approval_required / denied)다.

| 오류 / 상태 | 뜻 | 조치 |
|---|---|---|
| `[authorization_required]`, `[case_error]` | 케이스에 소유/허가 증명이 없다, 케이스 문제 | 멈추고 master-prompt §1-1·Phase 0 |
| `[validation_failed]` | 인자 범위·형식: timeout_s 10~3600, idle_timeout_s 30~1800(timeout_s 이하), label 형식(소문자·숫자·`-`, 24자까지), chip·psram·psram_mb 조합, board·mcu·freq_hz(1000000~32000000), max_chars 256~65536, wait_seconds 0~50, until(1~8개, 각 1~64자), 쓰기 데이터(1~4096 바이트, hex 형식), 케이스 밖 경로 | 메시지대로 인자를 고쳐 다시 |
| `[not_found]` | 세션 id 가 이 서버 프로세스에 없다(서버가 다시 시작됨) | `emu_sessions` 로 확인. 끝난 세션은 case_id 를 함께 주면 `emu_read`·`emu_stop` 이 디스크 기록으로 답한다 |
| `[tool_missing]` | 에뮬레이터 실행 파일이 없다(설정·환경 변수 값은 절대 경로여야 하고 PATH 에서 찾지 않는다) | SKILL 템플릿 E |
| `[emu_tool_version]` | 고정 버전이 아니다(다른 QEMU, 오래된 `pweh_avr_run`) | 템플릿 E 의 `--force` 다시 설치 |
| `[emu_input_rejected]` | `forensics/`·`emu/` 아래, 상태 폴더, 일반 파일 아님(링크·디렉터리) | 다른 입력을 고른다. 거부된 경로를 다른 도구로 열지 않는다 |
| `[emu_provenance]` (data.reason) | not-recorded(원장에 없음), sha256-mismatch(기록과 내용이 다름), device-read-mismatch(이중 읽기 불일치), file-missing, ledger-chain-broken(원장 깨짐) | 우회하지 않는다 — 템플릿 G. 다시 덤프(이중 읽기)하거나 사람이 원인을 확인한다. 깨진 원장은 사람이 조사한다 |
| status attestation_required | 가져온 파일의 provenance-import 증명이 필요하다 | 템플릿 B → `pweh attest <id>` → 같은 인자로 다시 |
| status approval_required | `modify_policy: approve` | 템플릿 C → `pweh approve <id>` → 같은 인자 + approval_id |
| status denied | gate.via "emu-policy"(argv 허용 목록 위반 — 서버 버그, 승인 경로 없음) / 운영자 정책 deny / 승인·증명 거절 | 우회하지 않는다 — 템플릿 D |
| `[emu_changed]` | 출처 확인과 읽기 사이에 파일이 바뀌었다 | 사람에게 알린다(같은 계정의 다른 프로세스가 바꿨을 수 있다). 원인을 확인한 뒤 다시 |
| `[emu_not_full_image]` | ESP: 원장의 오프셋이 0 이 아니다, 부트 오프셋(esp32 0x1000, s3·c3 0x0)에 이미지 매직 0xE9·헤더가 없다 | 전체 덤프(오프셋 0)로 |
| `[emu_unsupported_chip]` | ESP32-S2·C2·C5·C6·C61·H2·P4·ESP8266 | 지원하지 않는다고 보고 |
| `[emu_machine_mismatch]` | chip 인자가 증거와 다르다, 또는 원장의 칩과 부트로더 헤더의 칩이 다르다 | chip 을 빼고 다시. 원장과 헤더가 다르면 사람에게 알린다(다른 기기의 덤프일 수 있다) |
| `[emu_flash_encrypted]` | 같은 MAC 의 보안 사실이 플래시 암호화 켜짐 | 우회하지 않는다 — 템플릿 G |
| `[emu_flash_too_large]` | 덤프나 헤더가 선언한 크기가 16 MiB 를 넘는다(에뮬레이터 한계 — 자르지 않는다) | 지원하지 않는다고 보고 |
| `[emu_bad_hex]` | AVR HEX 의 형식·체크섬·겹침·범위 오류(줄 번호·오프셋만 알려 준다), 플래시보다 큰 raw 바이너리 | 사람에게 알리고 파일을 확인받는다 |
| `[emu_elf_refused]` | ELF 입력 | 사람이 PWEH 밖에서 Intel HEX 로 바꿔 다시 준다(SKILL 템플릿 F) |
| `[emu_session_limit]` | 케이스당 2·서버 프로세스당 4 초과(다른 서버 프로세스의 살아 있는 세션 포함) | `emu_sessions` 로 보고 필요 없는 세션을 `emu_stop` |
| `[emu_spawn_failed]` | 실행 실패·즉시 종료(data.stderr_tail 마스킹, data.exit) | 사람에게 보고한다(설치·호스트 라이브러리 문제일 수 있다). 다른 인자로 우회하지 않는다 |
| `[emu_not_running]` | 끝난 세션에 쓰기 | `emu_read` 로 끝난 이유를 보고, 필요하면 사용자와 상의해 새 세션 |
| pweh-fwtriage·pweh-case·pweh-sigrok 이 `emu/` 경로를 거부 | 원시 콘솔이 든 세션 디렉터리는 그 도구들이 읽지 않는다 | 정상이다. 콘솔은 `emu_read` 로 본다 |

## 5. AVR 보드와 MCU

| board | MCU | freq_hz | UART | 비고 |
|---|---|---|---|---|
| uno, nano, pro-mini-5v | atmega328p | 16000000 | USART0 | 옛 Nano(ATmega168)는 custom(mcu atmega168, freq_hz 16000000) |
| pro-mini-3v3 | atmega328p | 8000000 | USART0 | |
| mega2560 | atmega2560 | 16000000 | USART0 | |
| leonardo, micro | atmega32u4 | 16000000 | USART1 | Arduino `Serial` 은 USB CDC 라 보이지 않는다 — `Serial1` 만 |
| custom | mcu 필수 | freq_hz 필수 | USART0 | 보드 표에 없는 보드 |

- MCU 허용 목록(플래시 / EEPROM): atmega8 8 KiB / 512 B, atmega168 16 KiB / 512 B, atmega328p 32 KiB / 1 KiB, atmega32u4 32 KiB / 1 KiB, atmega644p 64 KiB / 2 KiB, atmega1280 128 KiB / 4 KiB, atmega1284p 128 KiB / 4 KiB, atmega2560 256 KiB / 4 KiB.
- 입력 정규화(서버): Intel HEX 의 데이터·끝·주소 레코드를 읽고 체크섬·겹침·범위를 검사한다. EEPROM 레코드(0x810000 부터)는 MCU 의 EEPROM 크기 안에서 함께 싣고, 퓨즈·잠금·서명 레코드는 버리고 notes 로 알린다. raw 바이너리(플래시 크기 이하)는 서버가 HEX 로 바꾼다. ELF 는 받지 않는다.
- 실행기는 게스트 시간을 벽시계에 맞추고(Arduino `delay()`·`millis()` 동작), 펌웨어가 USART 수신을 켤 때까지 입력을 4 KiB 까지 붙잡아 둔다. 외부 회로(센서·디스플레이·버튼)는 없다.
- 끝: rc 0 → guest-halt(인터럽트를 끈 sleep·제자리 점프), rc 1·2 → config-error, rc 3 → guest-crash(PC 가 플래시 밖), rc 5 → 서버가 정지 중이 아니었으면 server-gone.

## 6. 마스킹과 반복 표시 읽기

서버는 원시 바이트를 줄로 나눠 마스킹한 뒤에만 돌려준다(두 읽기에 걸친 비밀도 줄이 완성된 뒤 한 번에 가린다). 표시는 그대로 두고 되살리지 않는다.

| 표시 | 뜻 |
|---|---|
| `⟪비밀 N바이트⟫` | 덤프의 NVS 에서 미리 거둔 비밀값(원문·소문자/대문자 hex·공백 구분 hex)과 정확히 같은 글 |
| `ab…yz (N자)`, `<가림 N자>` | 자격증명 패턴의 값(`password=`·`psk:`·`token`·`Authorization: Bearer`/`Basic`·JWT 등): 16자 이상은 앞뒤 2자, 10~15자는 앞뒤 1자, 더 짧으면 길이만. 콘솔 키(password·psk·secret·token·api key·auth 등) 뒤의 `=`·`:`·공백 다음은 줄 끝까지 가린다(`password incorrect` 같은 과잉 가림은 의도다) |
| pending_line 끝의 `<가림 N자>` | 열린 줄 끝에 닿은 값 — 아직 덜 왔을 수 있어 길이만 보인다. 값이 없는 키(`Password:`)는 프롬프트라 그대로 보인다 |
| `⟪보류 N자⟫` | 열린 줄의 끝이 알려진 비밀값의 앞부분일 수 있어 줄이 끝날 때까지 보류 |
| `⟪개인키 줄⟫` | `-----BEGIN … PRIVATE KEY-----` 부터 END 줄까지(최대 256줄) |
| `⟪스택 N워드⟫` | ESP 패닉의 `Stack memory:` 블록(레지스터·MEPC·backtrace 줄은 보인다) |
| `⟪위 줄 ×N⟫` | 같은 줄이 N번 연속해 한 줄로 접혔다 |
| `⟪위 줄 ×k 더⟫` | 이미 읽은 줄이 그 뒤로 k번 더 반복됐다 |
| `\xNN`, `\uNNNN`, `\UNNNNNNNN` | 제어 문자, 서식 문자(양방향·폭 없는 문자·태그 문자), 사용자 정의 영역, 짝 없는 서로게이트, 변형 선택자 등의 이스케이프 — 화면에 보이지 않는 글자로 키를 나누거나 글을 숨기지 못하게 |

- 가리지 못하는 것(`docs/safety.md` §3.7): 패턴에 맞지 않고 NVS 에도 없는 비밀(키 없이 찍힌 하드코딩 문자열), 다른 인코딩(base64·XOR·여러 줄에 걸친 hexdump), 펌웨어가 나눠 찍어 줄이 바뀐 비밀,
  16 KiB 를 넘는 줄의 강제 경계에 걸친 비밀, 백스페이스 같은 터미널 편집으로 만든 글. NVS 암호화(masking.nvs_encrypted)면 알려진 값 수집이 없다.
- 비밀로 보이는 값이 `emu_read` 에 보이면 인용하지 않고 "콘솔에 비밀로 보이는 값이 출력됨(인용하지 않음)" 처럼 적는다.

## 7. 발견사항 예시

에뮬레이션에서 본 콘솔 동작이 정적 분석의 문자열 단서와 맞을 때다. excerpt 는 마스킹한 `emu_read` 글만 쓰고, 기기에서 확인하기 전이므로 possible·unverified 다.
```
case_add_finding(case_id="<id>", finding={
  "title": "UART 콘솔이 로그인 없이 nvs_dump 명령으로 저장된 설정을 출력 (에뮬레이션 관찰)",
  "category": "debug-interface", "severity": "medium", "confidence": "possible", "status": "unverified",
  "summary": "Espressif QEMU 로 실행한 덤프의 UART 콘솔 프롬프트 esp32> 에서 사용자가 원한 nvs_dump 를 보내자 인증 없이 NVS 설정을 출력했다. Wi-Fi 비밀번호 값은 서버 마스킹으로 가려졌다(NVS 비밀값과 일치).",
  "location": {"firmware": "dumps/esp-flash.bin", "interface": "uart", "emulation_session": "emu-002"},
  "evidence": [
    {"type": "log", "ref": "emu/emu-002/transcript.masked.txt", "excerpt": "esp32> nvs_dump → 설정 항목 14줄 출력, wifi.pass 줄의 값은 ⟪비밀 12바이트⟫ (emu_read 의 마스킹한 글)"},
    {"type": "triage", "ref": "analysis/strings-hunt-002.json", "excerpt": "lit:nvs_dump 히트 1건 (앱 파티션 영역)"}
  ],
  "reasoning": "콘솔 명령 표에 nvs_dump 가 있고 에뮬레이션에서 인증 없이 응답했다. 에뮬레이터에는 Wi-Fi·USB 가 없고 타이밍이 달라 실제 기기의 UART 콘솔이 같은지는 확인하지 않았다.",
  "verification_plan": "소유 기기의 UART 콘솔에서 같은 명령이 로그인 없이 동작하는지 사람이 확인한다(값은 기록하지 않는다). 명령 처리 함수는 REA 로 확인한다."
})
```

## 8. 세션을 시작하지 못했을 때의 기록

emulation 요약은 세션이 하나 이상이어야 하므로, 세션을 하나도 시작하지 못하면 summary 대신 attempt 로 남긴다(백엔드 없음, 출처 거부, 증명 거절, 플래시 암호화, 정책 거부, 지원하지 않는 칩).
```
case_record_step(case_id="<id>", skill="firmware-emulation", step="attempt", status="blocked",
  summary="ESP32-S3 덤프 에뮬레이션 안 함 — 기기에 플래시 암호화가 켜져 있음 (우회하지 않음)",
  data={"backend": "esp-qemu", "firmware": "dumps/esp-flash.bin", "error": "emu_flash_encrypted: 같은 MAC 의 보안 사실이 플래시 암호화 켜짐", "backends": {"esp-qemu": "QEMU emulator version 9.2.2 (esp_develop_9.2.2_20260417)", "avr-simavr": null}},
  next_actions=["사용자 결정: 정적 분석을 평문 영역으로 제한하거나 이 단계 생략"],
  blockers=["플래시 암호화 — 키는 칩의 읽기 보호 eFuse 에 있어 꺼내지 않음"])
case_set_phase(case_id="<id>", phase="firmware-emulation", status="blocked")
```
- 사람이 그만두기로 했으면 status "skipped", 사람 조치로 풀 수 없는 실패(지원하지 않는 칩·16 MiB 초과)는 "failed" 다.
