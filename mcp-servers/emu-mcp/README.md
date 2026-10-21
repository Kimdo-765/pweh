# pweh-emu (emu-mcp)

케이스가 **이미 가진** MCU 펌웨어를 PC 에서 실행해, 서버가 마스킹한 부팅 콘솔을 보여 주고 콘솔에 입력하게 하는 PWEH MCP 서버다(선택 구성요소).
기기는 건드리지 않는다. 본인 소유 또는 서면 허가를 받은 기기의 케이스에서만 쓴다. 설계는 [`docs/design/emulation.md`](../../docs/design/emulation.md).

실행 명령은 `pweh-emu-mcp` 또는 `python -m emu_mcp` (stdio)이다. 등록 이름은 `pweh-emu`, 서버 이름 상수는 `emu-mcp`, 도구 접두는 `emu_` 다.

## 백엔드

| 백엔드 | 실행 파일 | 대상 | 입력 |
|---|---|---|---|
| `esp-qemu` | Espressif QEMU `esp_develop_9.2.2_20260417` 정확히 이 버전 — `qemu-system-xtensa`(ESP32·ESP32-S3), `qemu-system-riscv32`(ESP32-C3) | UART0 콘솔 | 전체 플래시 덤프(오프셋 0). 서버가 0xFF 로 2·4·8·16 MiB 에 맞추고 ESP-IDF 기본 eFuse 블롭을 쓴다 |
| `avr-simavr` | PWEH 의 C 실행기 `pweh_avr_run`(simavr 고정 커밋 `5b08da60497f7564f50941f74a549fe2851db030` 정적 링크) | USART0(32u4 는 USART1) | Intel HEX 또는 raw 바이너리 — 서버가 정규화한 HEX 를 봉인한 memfd 로 넘긴다(`--hex-fd`) |

실행 파일은 설정 `tools.qemu_xtensa`·`tools.qemu_riscv32`·`tools.avr_run` → 환경 변수 `PWEH_QEMU_XTENSA`·`PWEH_QEMU_RISCV32`·`PWEH_AVR_RUN` →
도구 디렉터리의 `qemu-esp/xtensa/qemu/bin/qemu-system-xtensa`·`qemu-esp/riscv32/qemu/bin/qemu-system-riscv32`·`simavr/bin/pweh_avr_run` 순으로 찾는다
(`pweh.toolsdir.emu_binary_candidates`). 값은 절대 경로여야 하고 basename 이 정확히 위 세 이름이어야 한다. PATH 이름 찾기는 하지 않는다.
설치는 사람이 `scripts/install.sh --only qemu_esp`(ESP) / `--only simavr`(AVR, C 컴파일러 또는 PWEH zig)로 한다.

## 일반적인 순서

1. `emu_status()` — 백엔드·버전·격리 가용성을 본다. 없으면 사람에게 설치를 요청하고 멈춘다.
2. 사용자에게 알린다: PC 안에서만 실행되고 기기에 쓰지 않는다, Wi-Fi·Bluetooth·USB 콘솔은 에뮬레이션되지 않는다, 코어 1–2 개를 쓰고 `timeout_s` 뒤 끝난다.
3. `emu_start(case_id, firmware="dumps/esp-flash.bin")` — ESP 는 `chip`·`psram` 을 생략한다(원장·부트로더 헤더·기기 사실로 정한다). AVR 은
   `case_import_file` 로 가져온 HEX 에 `board="uno"` 등을 준다 — 첫 호출은 `attestation_required` 이고 사람이 별도 터미널에서 `pweh attest <id>` 로 출처를
   증명한 뒤 같은 인자로 다시 부른다.
4. `emu_read(session_id, wait_seconds=5)` 를 반복한다. 프롬프트를 기다릴 때는 `until=["login:", "esp32> "]`(리터럴, 정규식 아님).
5. 사용자가 원한 입력만 `emu_write(session_id, "help\r")`.
6. 끝나면 **늘** `emu_stop(session_id)` (한도로 이미 끝났어도 — 아티팩트가 등록된다).

## 도구

| 도구 | 설명 / 주요 반환 |
|---|---|
| `emu_status()` | OBSERVE, 케이스 없음, 게스트를 실행하지 않는다. 버전·머신 조회는 실행 shim 아래(rlimit·PDEATHSIG·최소 환경)에서 `-no-user-config -nodefaults -version`·`-machine help`(QEMU), `--version`(AVR)으로 하고 경로·크기·mtime·inode 로 캐시한다. 반환: `backends["esp-qemu"]{available, chips, chips_available, xtensa{path, source, version, expected_version, version_ok, machines, sha256, expected_sha256, sha256_ok, roms{<이름>: {present, sha256, expected_sha256, sha256_ok}}}, riscv32{…}}`, `backends["avr-simavr"]{available, path, source, version, driver_version, simavr_commit, expected_commit, expected_driver_version, version_ok, boards, mcus}`, `isolation{netns: available\|unavailable\|unknown, seccomp: false, core_pattern_piped}`, `limits`, `sessions{this_process}`, `hints`. 실행 파일·ROM sha256 불일치와 AVR 드라이버 버전 차이는 경고만 |
| `emu_start(case_id, firmware, backend="auto", chip=None, board=None, mcu=None, freq_hz=None, psram="auto", psram_mb=None, watchdog="disabled", on_reset="exit", timeout_s=600, idle_timeout_s=300, label=None, approval_id=None)` | MODIFY `emu.start`. 반환: `session_id`, `state`, `backend`, `target`, `firmware{path, sha256, size, provenance_reason, verify, ledger_seq, attestation_id?}`, `working_copy{sha256, size, padded_from, handoff: "memfd"}`(파일 경로 없음), `psram{mode, mb, source}`(ESP), `efuse{sha256, size}`(ESP), `avr{input_kind, flash_sha256, flash_used, flash_size, eeprom_bytes}`(AVR), `image`, `partition_table`·`app`(펌웨어에서 온 글은 마스킹·이스케이프), `limits{timeout_s, idle_timeout_s, rlimit_as, rlimit_cpu}`, `isolation{monitor: "none", network: "none", netns, snapshot, gdbstub: false, semihosting: false}`, `masking{patterns, known_secrets, nvs_encrypted}`, `cursor: 0`, `dir`, `warnings`, `notes`, `next_steps`. 첫 출력은 돌려주지 않는다(`emu_read` 로) |
| `emu_read(session_id, since_cursor=None, max_chars=8000, wait_seconds=0, until=None, until_ignore_case=False, tail=False, case_id=None)` | OBSERVE(대용량 출력). 반환: `text`, `cursor_start`, `cursor_end`, `more`, `pending_line`, `lines`, `collapsed`, `lost_bytes`, `note`, `matched`, `match`, `raw_total`, `raw_dropped`, `state`, (끝났으면) `stopped_by`·`exit`, `hints`, `source: "live"\|"transcript"` |
| `emu_write(session_id, data, encoding="text", approval_id=None)` | INTERACT `emu.write`. `text`(UTF-8 그대로) 또는 `hex`(공백 허용), 1–4096 바이트. 반환: `bytes_written`, `bytes_requested`, `partial`, `cursor`, `state`, `note`(일부만 썼을 때) |
| `emu_stop(session_id, case_id=None)` | 정리 도구(게이트 없음). 반환: `session_id`, `state`, `stopped_by`, `exit{code, signal}`, `duration_s`, `raw_bytes`, `raw_dropped_bytes`, `transcript_lines`, `artifacts[{path, kind, type, id}]`, `meta_path`, `stderr_tail`, `stderr_suppressed`, `already_stopped` |
| `emu_sessions(case_id=None)` | OBSERVE. 반환: `sessions[{session_id, case_id, backend, target, state, stopped_by, started_at, uptime_s, timeout_in_s, idle_timeout_in_s, raw_bytes, cursor_end, firmware{path, sha256}, dir}]`, `count`, `other_process_live{case_id: n}`, `limits`. 콘솔 글은 없다 |

job 도구는 없다(세션은 `uart_open`·`uart_close` 같은 오래 사는 자원이다).

### `emu_start` 처리 순서

1. 인자 검증 → 백엔드·실행 파일(`tool_missing`) → 고정 버전 확인(`emu_tool_version`).
2. `p = case.resolve_path(firmware)` 한 번. 어느 케이스든 `forensics/`·`emu/` 아래(`pweh.evidence.is_protected_path`·`under_any_case_protected`), 상태 폴더,
   일반 파일이 아님 → `emu_input_rejected`.
3. `safeio.open_regular` + `safeio.read_fd` 로 **한 번** 읽는다(ESP ≤ 16 MiB, AVR ≤ 2 MiB). 읽는 동안 크기·mtime 이 바뀌면 `emu_changed`
   (출처 확인이 다른 sha256 을 돌려줘도 `emu_changed`).
4. `rt().provenance.verify(case, rel, data=bytes)` — 그 바이트의 sha256 으로 확인한다(경로로 다시 열지 않는다). 가져온 파일이면 `provenance-import` 증명
   (`attestation_required`) — 그 전에 출처와 무관하게 거부할 내용(ELF·깨진 HEX·부트로더 헤더 없는 이미지)이면 증명을 요청하지 않고 바로 거부한다.
   믿지 않으면 `emu_provenance`(메시지에 `reason`).
5. 계획(`images.py`): 칩·패딩·eFuse·PSRAM·경고·NVS 비밀값(메모리에만) / AVR HEX 정규화.
6. 봉인한 memfd → 고정 argv → `classify_emu_argv`(벗어나면 `{ok: false, status: "denied", gate: {via: "emu-policy", rule_id, reason}}`, 승인 경로 없음).
7. 세션 상한 사전 확인 → `rt().authorize(MODIFY emu.start)`. 승인 지문: `{firmware, firmware_sha256, ledger_seq, provenance_reason, attestation_id, backend,
   chip|board, mcu, freq_hz, psram{mode, mb}, watchdog, on_reset, flash_size, timeout_s, idle_timeout_s}`(`label`·`approval_id` 는 넣지 않는다).
8. `emu/.lock`(flock) 안에서 상한 재확인 → 이미 있으면 실패하는 mkdir 로 `emu/<label|emu>-NNN` → 파일·`meta.json`(state `starting`, 주인 기록, argv,
   child null)·`events.jsonl` 첫 줄.
9. 감독 스레드 → shim → exec 확인(상태 파이프 EOF) → `/proc/<pid>/exe` 를 한 번 읽어 `child{pid, start_ticks, pgid, exe_realpath}` 기록 → `running`.
   exec 전 실패(errno 등), 또는 `emu_start` 가 '시작됨'으로 돌려주기 전에 rc 1·2 로 끝나면 `emu_spawn_failed`(메시지에 마스킹한 `stderr_tail`·종료 코드,
   세션 state `failed`). `emu_start` 는 exec 뒤 첫 출력·종료·`START_SETTLE_S`(0.5초) 가운데 먼저 오는 것까지 기다린다. 돌려준 뒤의 rc 1·2 는
   세션이 `ended`/`stopped_by: config-error` 로 끝난다(두 판단은 세션 잠금 안에서 한 줄로 세운다 — 응답과 세션 상태가 어긋나지 않는다).

### ESP 칩 판정과 이미지

- device-read: 원장 `source.chip` 을 접두로 정규화(ESP32-S3* → esp32s3, ESP32-C3* → esp32c3, ESP32-S2·C2·C5·C6·C61·H2·P4·ESP8266 → `emu_unsupported_chip`,
  그 밖의 ESP32* → esp32, `auto`·없음 → 헤더만)하고 부트로더 헤더 `chip_id`(esp32 0x1000 의 0, s3·c3 0x0 의 9·5)와 맞춘다. 다르면 `emu_machine_mismatch`.
  원장 `extra.offset` 이 0 이 아니면 `emu_not_full_image`. 같은 MAC 의 `esp-security-info` 사실에 플래시 암호화가 켜져 있으면 `emu_flash_encrypted`.
- 출처를 증명한 가져온 이미지: 헤더만(매직 0xE9 + 체크섬이 맞는 헤더), 보안 상태는 경고 `security_state_unknown`, PSRAM 기본값, 오프셋 검사 없음.
- `chip` 인자는 결과와 같아야 한다(`emu_machine_mismatch`). 16 MiB 를 넘으면 자르지 않고 `emu_flash_too_large`.
- 경고(`warnings` 의 앞 단어): `single_read`, `partial_dump`, `security_state_unknown`, `octal_flash_unsupported`, `partition_table_missing`, `core_pattern_piped`,
  `binary_sha256_mismatch`, `rom_missing`, `rom_sha256_mismatch`, `avr_driver_version`.
- PSRAM auto: esp32 quad 4 MiB, esp32s3 은 같은 MAC 의 `esp-chip-info` 사실 `Embedded PSRAM <N>MB` 로 N ≥ 8 → octal N, 2·4 → quad N, 없으면 quad 32 MiB,
  esp32c3 none.

### AVR 보드

| `board` | MCU | `freq_hz` | USART |
|---|---|---|---|
| `uno`, `nano`, `pro-mini-5v` | atmega328p | 16 000 000 | 0 |
| `pro-mini-3v3` | atmega328p | 8 000 000 | 0 |
| `mega2560` | atmega2560 | 16 000 000 | 0 |
| `leonardo`, `micro` | atmega32u4 | 16 000 000 | 1 (Arduino `Serial` 은 USB CDC — 에뮬레이션 안 됨) |
| `custom` | `mcu` 필수(atmega8·168·328p·32u4·644p·1280·1284p·2560) | `freq_hz` 필수(1–32 MHz) | MCU 기본 |

HEX 정규화: 체크섬, 유형 00·01·02·04(03·05 는 무시), 플래시 범위, EEPROM(0x810000+, MCU EEPROM 크기 안)은 남기고 퓨즈·잠금·서명은 버린다.
겹침·범위 밖·형식 오류는 `emu_bad_hex`(줄 번호·주소만 — 레코드 글은 싣지 않는다), ELF 는 `emu_elf_refused`.

## 고정 명령줄 (에이전트 인자 통과 0)

```
<abs>/qemu-system-xtensa -no-user-config -nodefaults -machine esp32s3 -accel tcg,tb-size=64 -display none -monitor none -nic none
  -serial stdio -drive file=/proc/self/fd/<F>,if=mtd,format=raw -drive file=/proc/self/fd/<E>,if=none,format=raw,id=efuse
  -global driver=nvram.esp32s3.efuse,property=drive,value=efuse [-global driver=timer.esp32s3.timg,property=wdt_disable,value=true]
  [-m <N>M] [-global driver=ssi_psram,property=is_octal,value=true] -snapshot [-no-reboot]

<abs>/pweh_avr_run --mcu <mcu> --freq <hz> --uart <n> --realtime --hex-fd <H>
```

`<F>`·`<E>`·`<H>` 는 봉인한 memfd(`F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL`)의 fd 번호다. 분류기 `policy.classify_emu_argv` 는 서버가 다시 만든 argv 와
정확히 같은지 보고, 금지 토큰을 따로 훑는다. 규칙 id: `emu.argv.monitor`, `emu.argv.gdb`, `emu.argv.network`, `emu.argv.semihosting`, `emu.argv.host-file`,
`emu.argv.device`, `emu.argv.config`, `emu.argv.detach`, `emu.argv.exe`, `emu.argv.unexpected`, `emu.argv.avr-input`, `emu.argv.avr-target`
(게이트 규칙은 `emu.start`·`emu.write`).

## 프로세스

- 세션마다 감독 스레드 하나가 `[python, -I, -S, emu_mcp/_exec_shim.py, --ppid, PID, --session-dir, ABS, --status-fd, N, --as, N, --cpu, SOFT,
  --cpu-hard, HARD, --core, 0, --nofile, 256, --fsize, N, (--netns), --, argv…]` 를 `start_new_session=True`, `close_fds=True`, `pass_fds=(memfd…, 상태 fd)`,
  환경 정확히 `PATH=/usr/bin:/bin LANG=C LC_ALL=C TMPDIR=<세션>/tmp HOME=<세션>`, stdin·stdout·stderr 파이프로 띄운다(stdin 은 세션 내내 열어 둔다).
- shim: setrlimit → `PR_SET_PDEATHSIG(SIGKILL)` → 부모 확인 → (가능하면) 빈 사용자·네트워크 네임스페이스(실패하면 94 → 서버가 `--netns` 없이 한 번 다시)
  → 잡을 수 있는 모든 신호를 SIG_DFL 로, 신호 마스크 비움 → 상태 fd 에 FD_CLOEXEC → `execv`. 실패한 경로는 모두 상태 파이프에 `<코드>:<내용>` 을 쓴다.
- **신호와 거두기는 감독 스레드만** 한다: 정지 이유를 먼저 기록 → SIGTERM(pidfd + killpg) → `STOP_GRACE_S` → SIGKILL. 끝나면 리더가 아직 좀비일 때
  그룹에 남은 것을 SIGKILL 한 뒤 파이프를 비우고 거둔다.
- 서버 시작(모든 케이스)과 `emu_start`(그 케이스) 때 `_startup_sweep()`: 주인이 죽은 세션의 에뮬레이터를 같은 uid·시작 시각·그룹 리더·cwd(=세션 디렉터리)·
  실행 파일(기록 값이면서 서버 허용 목록 안 — 파이썬이면 shim 표식 또는 `cmdline[1]` 이 설정된 에뮬레이터 실행 파일)로 확인하고 pidfd 를 연 뒤 끝낸다.
  `meta.json` 을 `reaped`/`server-gone` 으로 고치고 감사 `emu_orphans_reaped` 를 남긴다. 입양하지 않는다.
- 서버 종료: SIGTERM(정리 스레드, 최대 30초)·stdin 닫힘(`server.run()` 뒤 `finally`)·atexit 에서 모든 세션을 `server-shutdown` 으로 정지한다.
  서버가 SIGKILL 로 죽으면 PDEATHSIG 가 에뮬레이터를 끝낸다.

`stopped_by`: `agent-stop`, `wall-timeout`, `idle-timeout`, `server-shutdown`, `guest-reset`(QEMU rc 0 + `on_reset="exit"`), `guest-exit`, `guest-halt`(AVR rc 0),
`guest-crash`(AVR rc 3), `max-cycles`(AVR rc 4), `config-error`(rc 1·2, 또는 stderr 의 `invalid class name`), `rlimit-cpu`, `rlimit-fsize`, `killed`,
`spawn-failed`, `server-gone`(AVR rc 5 — 서버가 정지하던 중이 아닐 때, 또는 시작 정리).

## 콘솔 마스킹

- 원시 바이트 → `console.bin`(상한) 과 줄 기록기 두 개(`pweh.console.LineTranscript` + `pweh.safety.redact.ConsoleRedactor`): 에이전트용(`emu_read`)과 파일용
  (`transcript.masked.txt`). 마스킹은 자격증명 패턴 + 펌웨어 NVS 에서 미리 거둔 비밀값(`KnownSecrets`, 낮은 엔트로피 값은 버림)이다.
- 커서는 원시 바이트 오프셋이지만 레코드 경계에만 놓인다. 열린 줄(프롬프트)은 `OPEN_QUIET_S`(0.2초) 조용하면 `pending_line` 으로 보인다(`open_tail` 마스킹).
- `wait_seconds` 는 마지막 읽기가 넘긴 위치(`max(cursor_end, pending_raw_end)`) 뒤의 새 바이트(`until` 이 없을 때)나 `until` 맞음을 기다린 뒤
  조금 더 모은다: `READ_SETTLE_S`(열린 줄이면 `OPEN_QUIET_S`) 만큼 조용해지거나, 출력이 쉬지 않으면 첫 새 바이트·맞음 뒤 0.35초, 또는 새 바이트가
  `max_chars` 만큼 쌓이면 돌아온다. 프롬프트에서 기다려도 새 바이트가 없으면 바로 돌아오지 않는다. `until` 은 리터럴만(1–8개, 각 1–64자) —
  마스킹한 완성 줄과 조용한 열린 줄에 맞추고, 기다리는 동안은 레코드를 동결하지 않는 `find_until` 로 0.25초마다 본다(이미 맞으면 바로 돌아온다).
- `hints` 는 마스킹한 글에서만 만든다(`invalid header: 0xffffffff` 반복, `Guru Meditation Error`, PSRAM 실패 — 최대 2번 다시, `rst:0x3` 반복, Wi-Fi 초기화,
  부트로더 뒤 10초 조용 → USB 콘솔 가능성).
- `stderr_tail` 은 허용한 진단 줄만(QEMU: `qemu-system-…:` 로 시작하는 줄, `terminating on signal`, 플래시 크기·eFuse 오류, `invalid class name` / AVR:
  `pweh_avr_run:` 로 시작하는 줄 / shim: `pweh-emu-shim:`) 줄 경계로 잘라 마스킹·이스케이프한다(2000자 이하). 나머지 줄은 `stderr_suppressed` 에 분류별 수만.
- 로그·오류 메시지·`events.jsonl`·감사·승인 레코드에는 콘솔 글·stderr 글·입력 데이터·NVS 값을 넣지 않는다. `emu_write` 는 `{session_id, bytes, printable,
  data: "<given>"}` 만(다이제스트도 없음).

## 케이스 파일 (`cases/<id>/emu/<sid>/`, 0700 — 디렉터리 fd 기준, 파일은 O_EXCL 0600)

| 파일 | 내용 | 아티팩트 `extra.type` |
|---|---|---|
| `meta.json` | `pweh.emu-session/v1` — 상태가 바뀔 때마다 원자적으로 다시 쓴다. 펌웨어·작업 이미지·eFuse·정규화 HEX·AVR 플래시의 sha256·크기 | `emu-session` |
| `console.bin` | 게스트 UART 원시 바이트(마스킹 안 함, 32 MiB 상한) — 터미널에 `cat` 하지 말 것(`less`·`cat -v`) | `emu-console-raw` |
| `transcript.masked.txt` | 마스킹·이스케이프·반복 접기 기록(16 MiB 상한) — 끝난 세션은 `emu_read(session_id, case_id=…)` 가 이것을 돌려준다 | `emu-transcript` |
| `events.jsonl` | start·ready·tx{bytes, printable}·stop_request·timeout·kill·cap·exit·sweep — 콘솔 글·입력 데이터 없음 | `emu-events` |
| `emulator.stderr.log` | 에뮬레이터 자신의 stderr(1 MiB 상한, 서버가 파이프에서 읽어 쓴다) | `emu-stderr` |
| `tmp/` | 절대 경로 TMPDIR(QEMU `-snapshot` 덮어쓰기 파일) | — |

플래시·eFuse·HEX 사본은 두지 않는다(에뮬레이터는 봉인한 memfd 로 받는다). `emu/.lock`(0600)은 세션 상한·id 확보 잠금이며 지우지 않는다.
아티팩트는 세션이 끝날 때 `kind="other"` + `extra{type, session_id, backend, target}` 로 등록한다(`meta.json` 은 마지막으로 다시 쓴 뒤 그 sha256 으로).
pweh-fwtriage·pweh-case·pweh-sigrok 은 `emu/` 를 읽지 않는다. 에이전트는 이 파일을 Read·Bash·REA 로도 열지 않는다(에이전트 규칙).

## 한도 (`emu_mcp/limits.py` — 쓸 때마다 읽으므로 시험이 monkeypatch 할 수 있다)

| 상수 | 값 |
|---|---|
| `MAX_SESSIONS_PER_CASE` / `MAX_SESSIONS_PER_PROCESS` | 2 / 4 (`emu_session_limit`) |
| `timeout_s` / `idle_timeout_s` | 10–3600(600) / 30–1800(300, ≤ `timeout_s`) |
| `RAW_LOG_CAP` / `STDERR_LOG_CAP` / `TRANSCRIPT_CAP` | 32 MiB / 1 MiB / 16 MiB |
| `STOP_GRACE_S` / `EXEC_CONFIRM_TIMEOUT_S` / `START_SETTLE_S` | 3 / 5 / 0.5 초 |
| `OPEN_QUIET_S` / `READ_SETTLE_S` | 0.2 / 0.15 초 |
| `WRITE_MAX` / `WRITE_TIMEOUT_S` | 4096 바이트 / 2 초 |
| `RLIMIT_AS_QEMU` / `RLIMIT_AS_AVR` | 1 GiB / 64 MiB |
| `RLIMIT_FSIZE_QEMU` / `RLIMIT_FSIZE_AVR` / `RLIMIT_NOFILE` / `RLIMIT_CORE` | 64 MiB / 1 MiB / 256 / 0 |
| `RLIMIT_CPU` | soft = ⌈timeout_s × vCPU × 1.1⌉ + 5, hard = soft + 5 (vCPU: esp32·esp32s3 2, esp32c3·AVR 1) |
| `PROBE_TIMEOUT_S` | 10 초 |

## 오류 코드

`validation_failed`, `not_found`, `tool_missing`, `emu_tool_version`, `emu_input_rejected`, `emu_provenance`(메시지의 `reason`: `not-recorded`·`sha256-mismatch`·
`device-read-mismatch`·`file-missing`·`ledger-chain-broken`), `emu_changed`, `emu_not_full_image`, `emu_unsupported_chip`, `emu_machine_mismatch`,
`emu_flash_encrypted`, `emu_flash_too_large`, `emu_bad_hex`, `emu_elf_refused`, `emu_session_limit`, `emu_spawn_failed`, `emu_not_running`.
상태: `attestation_required`(사람이 `pweh attest <id>`), `approval_required`(`modify_policy: approve` — 사람이 `pweh approve <id>`), `denied`(우회하지 않는다).

## 시험과의 약속

- 가짜 에뮬레이터(venv 파이썬 shebang 스크립트)는 `/proc/<pid>/exe` 가 파이썬이다. 시작 정리는 `cmdline[1]` 의 실제 경로가 설정된 에뮬레이터 실행 파일일 때
  그것을 에뮬레이터로 본다. 가짜 `pweh_avr_run --version` 은 `pweh_avr_run <ver> simavr 5b08da60497f7564f50941f74a549fe2851db030` 을 내야 하며,
  `<ver>` 가 저장소 소스의 `PWEH_AVR_RUN_VERSION`(`emu_mcp.backends.expected_avr_driver_version()`)과 다르면 경고만 붙는다.
- `emu_mcp.backends.clear_probe_cache()` 는 버전·netns 조회 캐시를 비운다(시험이 가짜를 바꿀 때).
- 실제 QEMU 는 자기 memfd(`/memfd:displaysurface`)도 연다 — 넘긴 입력은 이름이 `pweh-emu-flash`·`pweh-emu-efuse`·`pweh-emu-hex` 인 memfd 로 센다.
- 부트로더 헤더가 없는 이미지(지운 0xFF 플래시 등)는 `emu_not_full_image` 로 거부하므로, 실제 에뮬레이터로 출력 홍수를 보려면 `reset` 이미지에
  `on_reset="reboot"`(리셋 루프)를 쓴다.

## 알려진 한계

에뮬레이터 탈출(QEMU·simavr 의 메모리 안전 버그)은 PWEH 샌드박스의 범위 밖이다 — 통제는 입력 제한(출처), argv 에서 호스트 접촉 기능 제거, rlimit·프로세스 그룹·
PDEATHSIG·(가능하면) 빈 네트워크 네임스페이스다. 빈 네트워크 네임스페이스도 경로 이름 UNIX 소켓(사용자 세션 버스 같은 것)은 막지 못한다. seccomp·Landlock 은 없다.
서버가 멈춰(SIGSTOP 등) 있으면 벽시계·무활동 한도를 강제하지 못한다. 같은 OS 계정의 다른 프로세스는 세션 파일을 읽고 에뮬레이터를 조작할 수 있다.
마스킹은 패턴에 맞지 않고 NVS 에도 없는 비밀, 다른 인코딩, 여러 번 나눠 찍은 비밀을 가리지 못한다. 전체 목록은 `docs/safety.md` 와 설계 문서 §6.7.
