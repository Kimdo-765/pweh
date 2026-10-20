---
name: uart-shell-acquisition
description: Acquire a UART serial console (U-Boot prompt or Linux shell) on a CCTV/IP camera/DVR/IoT board and collect basic device facts, for authorized/owned devices only. Finds the USB-UART port (WSL usbipd), guides GND/TX/RX wiring with a voltage check (3.3V vs 1.8V, never VCC), detects the baud rate, captures and parses the boot log, interrupts autoboot into U-Boot (printenv, bdinfo, flash, safe RAM address), logs in only with credentials the user supplies, identifies the Linux shell, and with explicit consent can boot once with a RAM-only init=/bin/sh (never saveenv). Records the uart-recon summary and hands the session to firmware-dump-via-uart. Triggers - UART, serial console, boot log, baud rate, autoboot, U-Boot prompt, printenv, root shell, login prompt, ttyUSB, 시리얼 콘솔, UART 접속, 부팅 로그, 보드레이트, U-Boot 진입, 셸 획득, 루트 셸, 로그인 프롬프트.
---

# uart-shell-acquisition: UART 콘솔 획득과 기본 정보 수집

## 목적

소유 기기나 서면 허가를 받은 기기의 UART 로 콘솔(U-Boot 프롬프트 또는 리눅스 셸)을 얻고, 기기를 영구히 바꾸지 않는 범위에서 기본 정보를 모은다. 결과는 연구·방어용이다(공격 페이로드나 제3자 시스템 공격 없음).
배선·전압 측정·전원 재투입은 사람이 하고, 에이전트는 `pweh-uart`·`pweh-case` 도구만 쓴다.

결과물:
1. 동작하는 UART 세션(포트, 보드레이트, 프레임)과 세션 로그 `uart/<session>.log`.
2. 부팅 로그 해석: U-Boot·커널 버전, autoboot 방식, 커널 cmdline, mtdparts, 로그인 요구 여부.
3. U-Boot 정보(진입했을 때): env, bootargs/bootcmd, 파티션, 플래시 칩·크기, 덤프용 안전 RAM 주소, 명령 목록.
4. 리눅스 정보(셸이 있을 때): 커널, CPU, `/proc/mtd`, 사용자, BusyBox 와 덤프용 애플릿 유무.
5. `case_update_target` 갱신과 `uart-recon` summary. 다음 Skill `firmware-dump-via-uart` 가 쓸 세션(열어 둠) 또는 재접속 정보.

## 언제 쓰나

- master-prompt §4 Phase A 에서 UART 패드 위치를 안다.
- `logic-analyzer-protocol-decode` 가 TX 패드와 보드레이트를 찾았거나, `jtagulator_uart_scan` 이 핀을 찾았다.
- 덤프 전에 U-Boot/셸 문맥을 다시 확보해야 한다(세션이 끊김, 서버 재시작).

**쓰지 않을 때**
- 소유/허가가 기록된 케이스가 없다. master-prompt §1-1 로 돌아간다.
- 패드를 모른다(→ `logic-analyzer-protocol-decode`/JTAGulator), 또는 전압 조건이 안 맞는다: 1.8V 인데 1.8V 어댑터·레벨 시프터가 없다, RS-232(DB9, ±전압)다, 아직 재지 않았다.
- 펌웨어 덤프 자체가 목적이다. 콘솔만 이 Skill 로 얻고 덤프는 `firmware-dump-via-uart` 가 한다.
- 부트로더가 비밀번호로 잠겨 있고 사용자가 비밀번호를 모른다. 우회하지 않고 대안(SPI 클립 읽기, 공식 이미지)으로 간다.

## 전제 조건

- **case_id**: `case_get` 의 authorized 가 true 여야 한다. 하드웨어 도구는 증명 없는 케이스를 거부한다.
- **이전 요약**: `case_get_step_results(case_id=…)` 로 읽는다.
  - `logic-analyzer-protocol-decode`: data.uart_estimate.baudrate(→ 3단계 생략)와 idle_level(0 이면 반전 라인이라 일반 USB-UART 로 못 읽는다 → 사람과 상의), conclusions 의 TX/RX 패드·프레임(8N1/7E1)·측정 전압.
  - 이전 `uart-shell-acquisition`: port, baudrate, session, notes 를 재사용한다.
  - 케이스 profile 의 `pipeline_profile(name=…)`: uart.baud_candidates, interrupt_sequences, autoboot_silent, 프롬프트 정규식.
- **사람이 준비할 것**: 3.3V(또는 1.8V 지원) USB-UART 어댑터, 점퍼선, 멀티미터, 사람이 직접 껐다 켤 수 있는 기기 전원(PoE 대신 DC 잭 권장). WSL2 면 usbipd attach.
- **사용자에게 한 번에 물을 것**(모르는 것만): 아는 콘솔 계정, 전원 재투입 3~4회 가능 여부, 목표(셸만/덤프까지).

## 안전 규칙

master-prompt §1 과 docs/safety.md §2.2·§3·§4 를 따른다. 이 Skill 에서 특히 지킬 것:

1. **배선은 사람이 한다.** GND–GND, 기기 TX → 어댑터 RX, 기기 RX → 어댑터 TX. **VCC 는 연결하지 않는다.** 5V TTL 어댑터와 RS-232 는 쓰지 않는다.
   1.8V 패드에 3.3V 어댑터를 물리지 않는다. 사람이 "완료" 라고 하기 전에는 진행하지 않는다.
2. **전원 재투입 타이밍**(`uart_detect_baud`, `uart_capture_boot`, `uboot_interrupt`): 먼저 알리고, 사람이 "준비" 라고 하면 도구를 호출하고, 호출이 시작되면 사람이 전원을 넣는다.
3. **U-Boot 와 unknown 문맥에서 빈 Enter 금지.** `uart_send_command(command="")`, `uart_write(data="\r")` 를 쓰지 않는다. 빈 줄은 직전 명령을 반복한다.
   새 세션(보낸 줄도, 본 재부팅도, 이어 받은 명령도 없음)의 빈 Enter 는 세션 전에 실행된 명령을 몰라 `uart.repeat-unknown`(DESTRUCTIVE)으로 거부된다.
   새 프롬프트·문맥 증거가 필요하면 `uart_sync`(Ctrl-C 한 번)를 쓴다. autoboot 중단 키는 `uboot_interrupt` 의 기본값(Ctrl-C)을 쓴다.
   유일한 예외는 프롬프트가 아니라 U-Boot 가 확인 Enter 를 기다리는 보드레이트 전환이다(firmware-dump-via-uart [reference.md §2](../firmware-dump-via-uart/reference.md#2-청크-크기-재시도-보드레이트-낮추기)). 그것도 `uart_open` 이 `inherited_last_command` 를 돌려줄 때만이다.
4. **문맥이 unknown 이면 명령을 보내지 않는다.** 분류가 두 분류기 중 엄격한 쪽이 되고, 보낸 줄의 Enter 가 askfirst/login 화면을 넘겨 버린다(시뮬레이터에서 확인). 먼저 `uart_sync` 나 부팅 로그로 증거를 얻는다.
   **프롬프트가 보일 때 한 줄씩 보낸다.** 다음은 모두 DESTRUCTIVE 로 거부된다: 앞 명령이 실행 중이거나(`timed_out` 뒤 포함) 부팅 중일 때 보낸 줄(`uart.device-busy`),
   `uart_write` 로 한 번에 보낸 여러 줄의 둘째 줄부터, 비 ASCII(상위 비트) 문자가 섞인 줄.
5. **영구 변경 금지.** `saveenv`/`env save`, `sf`·`nand`·`mmc` 쓰기·지우기, `mw`, `passwd`, rootfs 쓰기·`remount,rw` 를 보내지 않는다.
   `setenv` 는 RAM 에서만 하고 `boot` 로 시험한다. 다음 전원 재투입으로 원상 복구됨을 사용자에게 알린다.
   리눅스 셸에서는 /bin·/sbin·/usr/bin·/usr/sbin 의 표준 명령만 이름으로 실행한다. 다른 경로의 파일 실행(`./…`, `/mnt/…`), 도우미 스크립트 작성·실행,
   `PATH`·`LD_PRELOAD` 변경은 하지 않는다(게이트가 `linux.exec-nonsystem`, `linux.script`, `linux.env-hijack` 으로 거부, DESTRUCTIVE).
6. **계정은 사용자가 준 것만.** 추측·기본 계정 목록·무차별 대입 금지. `shell_login` 은 세션당 3회 실패하면 거부한다. 비밀번호를 summary·노트·대화에 쓰지 않는다.
7. **게이트를 존중한다.** `approval_required` 면 설명하고 사람이 별도 터미널에서 `pweh approve <id>` 를 실행한 뒤 같은 인자 + approval_id 로 한 번만 재시도한다.
   `denied` 면 다른 문법·약어·나눠 보내기·`uart_write`·외부 터미널(picocom 등)로 우회하지 않고 보고한다. `pweh approve` 를 직접 실행하거나 설정을 고치지 않는다.
8. **DTR/RTS 는 끈 채로 둔다.** `uart_open` 의 dtr/rts 기본값(false)을 유지하고, `uart_set_signals`·`uart_send_break` 는 이 Skill 에서 쓰지 않는다(리셋·부트모드 핀, Magic SysRq).
9. **init=/bin/sh 는 사용자 명시 동의 후 RAM 에서만.** 그 셸에서는 읽기만 한다(10단계).
10. **민감 정보.** 부팅 로그·env·셸 출력의 비밀번호·키·토큰은 summary 와 대화에 마스킹해 싣는다. 원문은 케이스 로그에만 둔다.
11. **확인과 추측을 구분한다.** 예: "SoC hi3516ev300 (U-Boot env soc + 커널 Machine model)" 과 "플래시 16 MiB (mtdparts 합계, 하한)".

## 사용하는 MCP 도구

| 도구 | 목적 |
|---|---|
| `case_get`, `case_get_step_results`, `pipeline_profile`, `pipeline_safety_policy` | 권한, 이전 요약, 프로필(보드레이트 후보·인터럽트 키), 현재 정책 |
| `uart_list_ports`, `uart_detect_baud` | USB-UART 포트 찾기(`likely_usb_uart`, `in_use_by`), 후보 보드레이트 점수화(세션 없는 포트에서만) |
| `uart_open`, `uart_sessions`, `uart_close` | 세션 열기(DTR/RTS 끔), 상태·문맥 조회, 닫기(로그 아티팩트 등록) |
| `uart_capture_boot` | 부팅 로그 수동 수집·파싱(아무것도 보내지 않음) |
| `uart_read`, `uart_wait_for` | 수신 버퍼 읽기, 정규식 대기(보내지 않음) |
| `uart_sync`, `uart_set_context` | Ctrl-C 로 문맥 증거 확보, 특이한 프롬프트 학습(더 엄격하게만) |
| `uboot_interrupt`, `uboot_printenv`, `uboot_info` | autoboot 중단, env·파티션, 버전·bdinfo·플래시·safe_ram_addr |
| `uart_send_command` | 한 줄 명령(`boot`, `setenv bootargs …`, `printenv bootargs`, `mount -t proc …`) |
| `shell_login`, `shell_identify` | 사용자 계정 로그인(마스킹·3회 제한), 리눅스 읽기 전용 식별 |
| `approval_status`, `case_update_target`, `case_add_note`, `case_record_step`, `case_set_phase` | 승인 확인, 대상 정보, 관찰 메모, summary, 실패 기록 |

## 절차

예시 케이스 `20261018-acme-ipc`, 포트 `/dev/ttyUSB0`, 세션 `console-001`. 응답의 `hint`·`explanation`·`next_steps` 도 함께 읽는다.
동기 도구의 대기는 50초 이하로 잡는다(MCP 클라이언트 제한). 판독표·필드 매핑·문제 해결은 [reference.md](reference.md).

### 0. 케이스와 이전 결과

```text
case_get(case_id="20261018-acme-ipc")
case_get_step_results(case_id="20261018-acme-ipc")
pipeline_profile(name="hisilicon-ipcam")          # case_get 의 profile 값
pipeline_safety_policy()
```
- authorized 가 false 면 멈춘다. modify_policy 가 `approve` 면 `setenv`·`boot`·`probe="ctrl-c"`·`mount` 가 승인 대상이 된다(11단계).
  계획을 짧게 알린다. 예: "포트 확인 → 배선 → 보드레이트 → 부팅 로그 → U-Boot 진입 → (필요 시) 로그인. 전원 재투입 3~4회".

### 1. 포트 찾기

```text
uart_list_ports(include_links=true)
```
- `likely_usb_uart: true` 인 `/dev/ttyUSB*`·`/dev/ttyACM*`(또는 `/dev/serial/by-id/…`)를 고른다.
  WSL2 의 `/dev/ttyS0`…`ttyS31` 은 가상 포트(likely_usb_uart false)라서 어댑터가 아니다.
- USB 포트가 없으면 H1 을 요청하고 다시 부른다. 두 번 실패하면 사람에게 `pweh doctor`(dialout 권한, WSL 점검)를 실행해 달라고 한다.
- `in_use_by` 가 있으면 이미 열린 세션이다. `uart_sessions(case_id=…)` 로 확인해 재사용하거나 `uart_close` 한다. 어댑터가 여럿이면 vid/pid/serial_number 로
  사람에게 확인받는다. 시뮬레이터·이 호스트의 ser2net 은 목록에 없다(`socket://127.0.0.1:<포트>` 나 PTY 경로를 그대로 쓴다. 원격 URL 은 루프백만 — LAN 의 ser2net 은 지원하지 않는다).

### 2. 배선과 전압

H2 를 요청하고 "완료" 와 측정 전압을 받는다.
- 3.3V → 진행. 1.8V → 1.8V 어댑터나 레벨 시프터가 있어야 진행. 5V 이상·음전압·DB9 → 연결하지 않고 멈춘다.
- 처음에는 기기 TX → 어댑터 RX 와 GND 만 연결해 관찰만 해도 된다(가장 안전). 7~10단계 전에는 어댑터 TX → 기기 RX 도 연결돼 있어야 한다.

### 3. 보드레이트 정하기

| 근거 | 처리 | summary 의 baud_detection.method |
|---|---|---|
| LA summary 의 uart_estimate.baudrate | 그 값으로 4단계 | `logic-analyzer` |
| 사용자가 알려 줌 | 그 값으로 4단계 | `manual` |
| JTAGulator 스캔의 `summary.best.baud` (master-prompt §4) | 그 값으로 4단계 | `manual` (notes 에 "JTAGulator 측정") |
| 프로필 후보가 하나(예: hisilicon 115200) | 바로 4·5단계, 부팅 로그가 읽히면 확정 | `profile` |
| 모름 또는 위 값으로 깨짐 | `uart_detect_baud` | `auto-scan` |

H3 을 알리고 "준비" 를 받은 뒤 호출한다. 사람은 호출이 시작되면 전원을 넣는다.
```text
uart_detect_baud(case_id="20261018-acme-ipc", port="/dev/ttyUSB0", candidates=[115200, 57600, 38400],
                 listen_seconds=3, probe="none")
```
- 후보를 차례로 열어 `listen_seconds` 씩 듣는다(총 50초 제한, 점수 ≥ 0.85 + 키워드면 조기 종료). 반환: `best`, `confidence`, `candidates[]`(baudrate, score, printable_ratio, high_bit_ratio, keyword_hits, sample), `hint`.
- **채택**: best 가 있고 confidence ≥ 0.8, 그 후보의 printable_ratio ≥ 0.9, keyword_hits 가 있고 sample 이 읽힌다.
- **보류**: confidence 0.5~0.8, high_bit_ratio > 0.05, sample 이 깨짐. 부팅 출력이 첫 창에 몰리면 틀린 속도가 best 가 될 수 있다(시뮬레이터 실측 0.705). best 하나만 `listen_seconds=8` 로 다시 재거나 5단계 부팅 로그로 판정한다.
- **best null + 데이터 없음 hint** → H4(TX/RX 교차, GND, 전원, 전압) 후 재시도. 두 번 실패하면 `logic-analyzer-protocol-decode` 로 넘긴다.
- **best null + 읽을 수 없는 데이터** → `[230400, 460800, 921600, 1500000]`, `[19200, 9600]` 순으로 다시 잰다(Rockchip 은 1500000). 그래도 안 되면 LA(반전, 비표준 속도, 7E1).
- 도구 기본값은 `probe="ctrl-c"` 다. 전원 재투입 탐지에는 **`probe="none"` 을 명시한다.** ctrl-c 프로브는 MODIFY 다: 틀린 속도의 0x03 이 다른 제어 바이트(예: 0x04 Ctrl-D → 셸 로그아웃)로 읽힐 수 있고, 부팅 중이면 autoboot 를 멈춘다. 기기가 이미 프롬프트에서 대기 중이고 재투입을 피하고 싶을 때만 쓴다.
- `[busy]` 면 그 포트에 세션이 열려 있다. `uart_close` 뒤에 탐지한다.

### 4. 세션 열기

```text
uart_open(case_id="20261018-acme-ipc", port="/dev/ttyUSB0", baudrate=115200, label="console")
```
- dtr/rts 는 기본 false 로 둔다(true 는 MODIFY). line_ending 기본 `"\r"`. LA 가 7E1 이라 했으면 `bytesize=7, parity="E"`. profile 을 생략하면 케이스 프로필이다.
  부팅 로그가 다른 계열(예: `isvp_t31# `)이면 `uart_close` 뒤 `profile="ingenic-t-series"` 로 다시 연다(프롬프트 정규식·인터럽트 키가 바뀜).
- 반환의 `session_id`, `log_path`(→ summary.session_log), `context` 를 적는다. 연 직후 `context: unknown` 은 정상이다.
  같은 케이스·포트의 앞 세션을 `uart_close` 로 닫았다면 `inherited_last_command`(그 세션이 마지막으로 보낸 U-Boot 명령)도 온다. 빈 Enter 는 그 명령의 반복으로 분류된다.

### 5. 부팅 로그 수집과 경로 결정

H3 을 알리고 "준비" 를 받은 뒤:
```text
uart_capture_boot(session_id="console-001", duration=45)
```
- OBSERVE 다(보내지 않음). 부팅이 시작된 뒤 프롬프트가 나오고 1.5초 조용하면 멈춘다. 발췌는 `excerpt_path`(`uart/console-001-boot-01.log`).
- 읽을 필드: captured_bytes, stopped_by(`prompt:<kind>:<context>`/`duration`), stages, uboot_version, autoboot_message, bootdelay, kernel_version,
  cmdline, mtdparts, partitions, console, flash, env_bad_crc, flash_write_warnings, text_tail, context.
- `stopped_by: duration` 인데 아직 부팅 중이면 `uart_read(session_id="console-001", wait_seconds=20)` 로 이어 읽는다.

| 관찰 | 다음 |
|---|---|
| captured_bytes 0 | H4 → 재시도. 두 번 실패하면 console_type `silent` 로 기록하고 LA 로 |
| 바이트는 많은데 text_tail 이 깨짐, 버전 필드가 모두 null | 보드레이트 오류 → 3단계 |
| autoboot_message 있음 (bootdelay ≥ 1) | 경로 A (7단계) |
| U-Boot 배너 뒤 메시지 없이 커널 시작 | bootdelay 0·keyed·silent 일 수 있음. 7단계를 1회 시도하고 안 되면 B/C |
| stopped_by `prompt:…:uboot` (커널 없이 프롬프트) | `uart_sync` 후 7단계의 A2 |
| stopped_by `prompt:askfirst:login` / `prompt:login:login` | 로그인 필요 → 가능하면 A 먼저, 그다음 경로 B (8단계) |
| stopped_by `prompt:prompt:linux-shell` | 경로 C (9단계) |
| flash_write_warnings 있음 / env_bad_crc true | 기기가 스스로 플래시를 썼거나 RAM 에 기본 env. `case_add_note` 로 남기고 사용자에게 알림. saveenv 는 계속 금지 |

여러 경로가 가능하면 **A(U-Boot 정보) → `boot` 로 리눅스 → B/C** 순서가 가장 많이 얻는다. D 는 로그인이 막고 사용자가 동의할 때만.

### 6. 문맥 판정 (어느 단계에서든)

- 모든 응답과 `uart_sessions(case_id="20261018-acme-ipc")` 에 `context`(uboot / linux-shell / login / password / booting / unknown)와 phase, prompt, pending_input 이 있다.
  `uart_sessions` 의 `device_ready` 가 false 면 지금 보낸 줄은 `uart.device-busy` 로 거부된다(`device_busy_reason`: 부팅 중, 명령 실행 중 등). 프롬프트가 다시 보일 때까지 기다린다.
- 증거는 `uart_sync(session_id="console-001")` 로 얻는다. U-Boot 는 `<INTERRUPT>` 로 답하고(evidence `uboot`), 셸은 새 프롬프트만 낸다(evidence `linux`).
  timed_out 이면 부팅 중이거나 askfirst 화면이다. 빈 Enter 를 보내지 말고 H3 으로 재투입 후 5단계나 7단계를 한다.
- `hisilicon # ` 처럼 U-Boot·셸 정규식에 둘 다 맞고 부팅 증거가 없으면 unknown 이다. `uboot_printenv`/`uboot_info` 는 uboot, `shell_identify` 는 linux-shell 에서만 동작한다.
- 프롬프트가 특이하면 `uart_set_context(session_id="console-001", context="linux-shell", prompt="/ # ")` 로 학습시킨다. 분류를 완화하지는 못하고 재부팅 증거가 나오면 풀린다.
  학습하기 전에는 명령 뒤의 프롬프트를 알아보지 못해 세션이 준비 안 됨으로 남고, 다음 줄이 `uart.device-busy` 로 거부된다.

### 7. 경로 A: U-Boot

**A1. autoboot 중단.** H3 을 알리고 "준비" 를 받은 뒤 호출한다. 도구가 먼저 감시를 시작하고, 사람은 호출이 시작되면 (H3 대로 꺼 둔) 전원을 넣는다.
```text
uboot_interrupt(session_id="console-001", window_seconds=30)
```
- 부팅 출력이 보이면 프로필 interrupt_sequences(기본 Ctrl-C)를 약 50ms 마다 보내고, 프롬프트에서 멈춘 뒤 Ctrl-C 로 동기화한다.
- 반환: interrupted, prompt, autoboot_message, bootdelay, keys_used, keys_sent, outcome(`prompt`/`kernel`/`linux`/`"uboot_password"`/`window_expired`/…), new_boot_seen(호출 뒤 새 부팅을 봤나), explanation, elapsed_seconds, sync.evidence.
  이미 U-Boot 프롬프트였으면 키 없이 Ctrl-C 동기화만 하고 outcome `prompt` + already_at_prompt true 로 끝난다.
- interrupted true + sync.evidence `uboot` → A2. 사용자에게 "U-Boot 에서 멈췄습니다. 전원은 그대로 두세요" 라고 알린다.
- outcome `kernel` + autoboot 메시지 → 키가 늦었거나 다른 키를 받는 빌드다. explanation 대로 `keys=["ctrl-c", "space"]`, 또는 keyed CR 빌드(OpenIPC Ingenic "Press ENTER to interrupt boot")만 `keys=["enter"]` 로 재시도한다(도구는 새 부팅을 본 뒤, 프롬프트가 없을 때만 Enter 를 보낸다). 총 3회까지.
- outcome `kernel` + 메시지 없음 → bootdelay 0/silent keyed 빌드(SigmaStar SDK 는 `sigmastar-ipcam` 프로필, CR)다. 프로필을 맞춰 1회 더, 아니면 B/C 와 대안으로.
- outcome `linux` → 이번 부팅에서 중단을 놓치고 리눅스 프롬프트에 도달했다. H3 대로 재투입 후 재시도.
- `outcome="uboot_password"` → 커널 시작 전에 `Password:` 가 나왔다. 리눅스 로그인이 아니라 부트로더(U-Boot) 잠금이고, 도구는 키 송신을 멈춘다.
  이 프롬프트에 `shell_login` 을 부르지 않는다. 비밀번호를 추측하거나 대입하지 않고, 사용자에게 아는 값이 있는지 묻거나(H5 원칙) 그대로 부팅된 뒤의 리눅스 셸 경로(B/C)·SPI 클립·공식 이미지로 간다.
  다른 outcome 이어도 `uart_read(session_id="console-001", tail=true)` 에 커널 로그 없이 `Password:` 만 있으면 같은 부트로더 잠금으로 다룬다.
- outcome `window_expired` → explanation 과 new_boot_seen 을 본다. 수신 데이터가 없으면 사람이 재투입하지 않았다. "이전 부팅의 리눅스 출력만 보였다"(new_boot_seen false)면 호출할 때 기기가 켜져 있었고 창 안에 새 부팅이 없었다(도구는 이전 부팅의 출력을 판단에 쓰지 않는다).
  어느 쪽이든 전원을 먼저 꺼 두게 한 뒤(H3) 다시 호출한다.

**A2. 환경 변수.** `uboot_info` 보다 먼저 부른다(safe_ram_addr 이 env 의 loadaddr·bootcmd 주소를 쓴다).
```text
uboot_printenv(session_id="console-001")
```
- env{}, bootargs, bootcmd, bootdelay, mtdparts, partitions[{name, offset, size}], loadaddr, environment_size, flash_size, flash_size_source, complete.
- complete false 면 한 번 더 부른다. 추적 env 가 없으면 `run X` 는 DESTRUCTIVE 로 거부되고 `boot` 의 재귀 검사도 못 한다.
- `-`(나머지) 파티션 size 는 서버가 아는 플래시 크기(flash_size, 출처는 flash_size_source: uboot_info 나 부팅 로그)로 채운다. 모르면 null 이고, A3 의 `uboot_info` 가 플래시 크기를 알아내면 크기를 채운 partitions 를 돌려준다.

**A3. 보드·플래시 정보.**
```text
uboot_info(session_id="console-001")
```
- `version`, `bdinfo`, `help`, `sf probe 0`(probe_flash 기본 true, 읽기 전용)을 보낸다. help 에 sf 가 없으면 probe 를 건너뛴다(NAND/eMMC).
- 반환: version, bdinfo{dram_start, dram_size, relocaddr, sp_start …}, flash{type, model, size_bytes, size_bytes_lower_bound}, commands, has{sf, md, crc32 …}, has_via, partitions, safe_ram_addr, ram_window, notes.
- flash.model 이 `hi_fmc`/`hi_sfc` 면 컨트롤러 이름이다. 칩 이름은 5단계 flash.flash_name 에서 가져온다.
- size_bytes 가 null 이면(Ingenic `SF: Detected BY25Q128AS`) size_bytes_lower_bound·부팅 로그·mtdparts 로 채우고 "하한" 이라고 적는다.
- partitions 는 추적 env 의 mtdparts 를 알아낸 플래시 크기로 다시 계산한 것이다(`-` 파티션 크기 포함). A2 에서 null 이던 크기는 이 값을 쓴다.
- `has` 는 help 목록 기준이라 힌트로만 본다. U-Boot 약어 규칙(유일한 접두어)으로만 되는 명령은 has_via 에 실제 이름이 있고, help 를 읽지 못했으면 값이 null(모름, 없음이 아님)이다. commands 에 md·crc32 가 없으면 notes 에 "덤프 명령 미확인" 으로 남긴다.
  실제 확인은 firmware-dump-via-uart 의 시험 덤프가 한다(crc32 가 정말 없으면 job 이 verify=double 로 바꾼다).

**A4. 다음 위치.** U-Boot 덤프를 할 예정이면 프롬프트에 머문다. 리눅스가 필요하면(B/C):
```text
uart_send_command(session_id="console-001", command="boot", timeout=45, expect="activate this console|login: ?$|^(/ )?[#$] $", max_output=4000)
```
- `boot` 는 MODIFY(기본 허용)이고 추적 env 의 bootcmd 로 재귀 분류된다. timed_out 은 오류가 아니다. `uart_read(session_id="console-001", wait_seconds=20)` 로 이어 읽는다. 사람이 전원을 재투입해도 된다.

### 8. 경로 B: 로그인 (사용자가 준 계정만)

계정을 모르면 H5 로 묻는다. 추측하지 않는다.
```text
shell_login(session_id="console-001", username="<사용자가 준 계정>", password="<사용자가 준 비밀번호>", timeout=20)
shell_login(session_id="console-001", timeout=20)      # 계정을 아직 모를 때: askfirst 활성화만
```
- askfirst(`Please press Enter…`)면 Enter, `login:` 이면 계정, `Password:` 면 비밀번호를, 그 프롬프트가 수신 끝에 있을 때만 보낸다. 비밀번호는 로그·감사에서 마스킹된다.
- username 을 생략하면 askfirst 에 Enter 만 보낸다. 로그인 없는 콘솔(askfirst 뒤 바로 셸)은 이것으로 열리고, `login:` 이 나오면 아무것도 보내지 않고 `username_required` 로 멈춘다.

| status | 조치 |
|---|---|
| `ok`, `already_logged_in` | 9단계 |
| `password_required` | 사용자에게 비밀번호를 받아 password 를 넣어 다시 호출 |
| `username_required` | `login:` 이 나왔다(실패로 세지 않음). H5 로 계정을 받아 username(필요하면 password)을 넣어 다시 호출 |
| `login_incorrect`, `login_failed` | 멈추고 사용자에게 확인. 변형해 보지 않는다(실패 누적) |
| `context_unknown` | 프롬프트가 U-Boot 일 수도 있어 아무것도 보내지 않았다. `uart_sync` 로 확정 → linux-shell 이면 9단계, uboot 이면 A4 |
| "uboot_prompt" (U-Boot 문맥) | A4 의 `boot` 로 리눅스 부팅 후 다시 |
| "uboot_password_prompt" | 커널 시작 전의 `Password:` = 부트로더 잠금(A1 의 "uboot_password" 와 같다). 아무것도 보내지 않았다. 추측하지 않고, 그대로 부팅해 `login:` 이 보이면 다시 호출하거나 B/C·SPI 경로 |
| `timeout` | 프롬프트가 안 보임. `uart_read(tail=true)` 확인 → 없으면 H3 재투입 + 5단계 |
| `stuck_askfirst` | askfirst Enter 를 두 번 보내도 넘어가지 않음. `uart_read(tail=true)` 로 보고 H3 재투입 + 5단계 |
| `unknown_prompt` | `uart_read` 로 보고, 셸이면 6단계처럼 프롬프트 학습 |
| `disconnected` | 11단계 표 |
| 오류 `[login_attempts_exceeded]` | 중단. 새 세션으로 재시도하지 않는다. 사용자가 확인한 계정이 생길 때만 |

- 계정이 없다고 하면 username 없이 부른다. 이름을 지어내 보내지 않고, `username_required` 가 오면 거기서 멈춘다. 비밀번호를 추측하지 않는다.
- 사용자가 계정을 모르면: A 의 정보만으로 기록하거나, 동의를 받아 경로 D, 또는 덤프 후 정적 분석으로 간다. 분석에서 나온 계정을 쓰려면 사용자의 명시적 허락이 필요하다.

### 9. 경로 C: 셸 식별

```text
uart_sync(session_id="console-001")          # evidence "linux", context linux-shell 확인
shell_identify(session_id="console-001")
```
- `uname -a`, `/proc/cpuinfo`, `/proc/mtd`, `/proc/cmdline`, `/proc/mounts`, `ps`, `netstat -tuln`, `busybox`, `id` 를 명령마다 게이트를 거쳐 보낸다.
- 반환: kernel_version, arch, hostname, cpu, mtd[]{dev, size, erasesize, name}, cmdline, mtdparts, mounts, processes, listening, busybox, busybox_applets, user{uid, user}, has_base64/has_hexdump/has_md5sum, missing_commands.
- user.uid 0 → access_level `root-shell`, 아니면 `user-shell`(mtd 읽기가 막힐 수 있음). has_md5sum false 면 셸 덤프 검증이 불가능하다. notes 에 남긴다.
- 더 볼 것이 있으면 읽기 전용 한 줄만 `uart_send_command` 로 보낸다(`cat /proc/version`, `ls /dev/mtd*`). 쓰기·설정 변경·서비스 조작은 하지 않는다.

### 10. 경로 D: RAM 한정 init=/bin/sh (사용자 동의 필수)

조건: 로그인이 막고, 계정이 없고, U-Boot 프롬프트와 완전한 printenv(A2)가 있다. H6 으로 설명하고 명시적 동의를 받는다.
init 대신 커널이 `/bin/sh` 를 PID 1 로 실행하므로 서비스와 로그인 없이 root 셸이 뜬다. RAM 의 env 만 바꾸므로 다음 전원 재투입에서 원래대로 부팅된다.
1. `case_add_note` 로 원래 bootargs·bootcmd 를 남긴다. bootcmd 안에 `setenv bootargs` 가 있으면 `boot` 가 우리 값을 덮어쓴다 → [reference.md §5](reference.md#5-경로-d-세부-initbinsh) 의 수동 순서를 쓴다.
2. RAM 에만 설정하고 확인한다(MODIFY, 기본 허용).
   ```text
   uart_send_command(session_id="console-001", command="setenv bootargs ${bootargs} init=/bin/sh")
   uart_send_command(session_id="console-001", command="printenv bootargs")
   ```
   출력 끝이 `init=/bin/sh` 인지 본다. 커널은 마지막 `init=` 을 쓴다. `${bootargs}` 는 줄을 짧게 유지한다(250자 초과 줄은 DESTRUCTIVE). saveenv 는 절대 보내지 않는다.
3. 부팅하고 커널이 받은 명령행을 확인한다.
   ```text
   uart_send_command(session_id="console-001", command="boot", timeout=40, expect="Kernel command line: .*init=/bin/sh")
   uart_wait_for(session_id="console-001", pattern="job control turned off|^/ # $|^# $", timeout=40)
   uart_sync(session_id="console-001")
   ```
   matched false(timed_out)거나 `login:`/askfirst 가 나오면 적용되지 않은 것이다(bootcmd 덮어쓰기, 커널 고정 cmdline). 기록하고 멈춘다.
   uart_sync 가 timed_out 이면(제어 터미널 없음) `uart_read(tail=true)` 로 프롬프트를 보고 6단계처럼 `prompt="/ # "` 를 학습시킨다.
4. init 이 돌지 않아 `/proc` 이 비어 있다. 휘발성 마운트만 한다(MODIFY).
   ```text
   uart_send_command(session_id="console-001", command="mount -t proc proc /proc")
   uart_send_command(session_id="console-001", command="mount -t sysfs sysfs /sys")
   ```
   `ls /dev/mtd*` 가 비면 `mount -t devtmpfs devtmpfs /dev` 도 한다. 그다음 `shell_identify`(9단계).
   금지: `mount -o remount,rw /`(게이트가 MODIFY 로 허용해도 하지 않는다), `passwd`, 파일 수정, `exec /sbin/init`, 서비스 시작.
5. 수십 초 안에 기기가 스스로 재부팅하면 하드웨어 워치독일 수 있다(정상 부팅으로 돌아옴). 노트에 남기고 U-Boot 덤프 경로를 권한다.
   끝나면 "전원을 다시 넣으면 원래 부팅으로 돌아갑니다. 플래시에는 아무것도 저장하지 않았습니다" 라고 알린다.

### 11. 게이트·오류 응답

| 응답 | 조치 |
|---|---|
| `status: approval_required` + `approval_id` | H7 로 무엇·왜·위험·복구를 설명 → 사람이 별도 터미널에서 `pweh approve <id>`(또는 elicitation 폼) → `approval_status(approval_id="ap-…")` 가 approved → 같은 인자 + `approval_id` 로 1회 재호출 |
| `status: denied` | 우회 금지(안전 규칙 7). H8 로 보고. `run X` 거부는 `uboot_printenv` 후 재판단, 긴 줄 거부는 `${var}` 로 줄인다 |
| denied, 규칙 `uart.device-busy` | 보낸 시점의 문제(명령 실행 중·부팅 중). `uart_read`/`uart_wait_for` 로 프롬프트가 다시 보이면(특이한 프롬프트는 6단계처럼 학습) 같은 명령을 한 줄로 한 번 보낸다. 우회가 아니라 정해진 복구다 |
| denied, 규칙 `uart.repeat-unknown`·`uart.uncertain-input` | 빈 Enter 나 편집 키 등으로 확정할 수 없는 입력. `uart_sync` 로 줄을 비우고 새 프롬프트를 받는다 |
| `[approval_mismatch]` | 승인 뒤 참조하는 env 값(`run`·`$var`·bootcmd)이나 빈 Enter 의 반복 대상이 바뀌어 다른 작업이 됐다. approval_id 없이 다시 불러 새 승인을 받는다 |
| `[state_changed]` | 승인과 전송 사이에 문맥이 바뀜. `uart_sync` 로 확인 후 다시 판단 |
| `[busy]` / `[validation_failed]` 문맥 힌트 | 포트·세션 사용 중이면 `uart_sessions`·`uart_jobs(active_only=true)`, 문맥 불일치면 힌트대로 `uart_sync`·`uboot_interrupt`·`shell_login` |
| `[disconnected]`, state `disconnected` | USB 분리. 사람에게 연결 확인 → `uart_close` → `uart_open` |
| `timed_out: true` | 오류 아님. `uart_read` 로 이어 읽고, 멈추려면 `uart_sync`. 프롬프트가 돌아오기 전에 보낸 다음 명령은 `uart.device-busy` 로 거부된다 |

### 12. 대상 정보 갱신과 세션 정리

```text
case_update_target(case_id="20261018-acme-ipc", target={"soc": "hi3516ev300 (U-Boot env soc + 커널 Machine model)",
    "flash": "W25Q128(B/F)V SPI NOR 16 MiB", "uboot_version": "U-Boot 2016.11", "kernel_version": "4.9.37", "arch": "armv7l"})
case_add_note(case_id="20261018-acme-ipc", text="UART J3: GND-J3-1, 기기 TX-J3-2, 기기 RX-J3-3, TX 3.3V 측정 (사람 보고)")
```
- soc 출처 우선순위: cpuinfo Hardware/system type → 커널 `Machine model:` → U-Boot env soc/board → 버전 태그. 이름만으로 정했으면 "(추정)" 을 붙인다.
- firmware_version 은 부팅 로그나 셸에서 실제로 본 경우에만 넣는다(벤더 앱 배너, 버전 파일). 추측하지 않는다.
- 세션: 같은 대화에서 `firmware-dump-via-uart` 로 이어 가면 **열어 둔다**(summary.session 에 session_id·context_at_end).
  아니면 `uart_close(session_id="console-001")` 로 닫는다(로그 3종 아티팩트 해시 갱신, 실행 중 job 취소). 서버가 재시작되면 세션은 사라지고 summary 의 port·baudrate 로 다시 연다.

## 사람에게 요청할 일

**H1. USB-UART 연결 (WSL2)**
```
[사람 작업 필요] USB-UART 어댑터 연결
1. 어댑터를 PC 에 꽂아 주세요. WSL2 라면 관리자 PowerShell 에서:
   usbipd list → usbipd bind --busid <BUSID>(최초 1회) → usbipd attach --wsl --busid <BUSID>
2. 어댑터 칩(CP2102/CH340/FT232 등)과 전압 설정(3.3V 점퍼)을 알려 주시고 "완료" 라고 해 주세요.
```

**H2. 배선과 전압 측정**
```
[사람 작업 필요] UART 배선
1. 기기 전원을 끕니다(PoE 대신 DC 어댑터 전원 권장).
2. 멀티미터 연속성 모드로 GND 패드를 확인합니다(DC 잭 바깥쪽/USB 실드와 통하는 패드). 예: J3-1.
3. 전원을 켜고 TX 후보 패드(부팅 중 전압이 출렁이는 패드) 전압을 재서 알려 주세요. 3.3V 면 진행, 1.8V 면 알려 주세요.
4. 전원을 끄고 연결합니다: 어댑터 GND → J3-1, 어댑터 RX → 기기 TX(J3-2), 어댑터 TX → 기기 RX(J3-3).
   어댑터 VCC 는 어디에도 연결하지 않습니다. 관찰만 할 때는 어댑터 TX 선을 빼 두어도 됩니다.
5. 전원은 꺼 둔 채 "완료" 라고 알려 주세요.
```

**H3. 전원 재투입 타이밍 (보드레이트 탐지·부팅 로그·U-Boot 진입 공통)**
```
[사람 작업 필요] 전원 재투입 타이밍
- 기기 전원을 꺼 두세요(켜져 있으면 지금 끄면 됩니다).
- "준비" 라고 하시면 제가 감시 도구를 먼저 호출합니다. 호출이 시작되면 바로 전원을 넣어 주세요.
- 키 입력은 제가 합니다(U-Boot 진입 시 Ctrl-C). 부팅이 끝날 때까지(최대 45초) 배선을 건드리지 말아 주세요.
```

**H5. 콘솔 계정 확인**
```
[확인 필요] 콘솔 로그인
- 기기가 "<login 프롬프트>" 에서 계정을 요구합니다. 이 기기의 콘솔 계정을 알고 계시면 알려 주세요.
- 저는 알려 주신 계정만 쓰고, 추측하거나 여러 비밀번호를 시도하지 않습니다(세션당 3회 실패 시 자동 중단).
- 모르시면: (a) U-Boot 정보만 기록, (b) RAM 한정 init=/bin/sh 부팅(별도 동의), (c) 덤프 후 분석 중에서 골라 주세요.
```

**H6. init=/bin/sh 동의**
```
[동의 필요] RAM 한정 부트 인자 변경
- 할 일: U-Boot 에서 setenv bootargs ${bootargs} init=/bin/sh 후 boot (saveenv 하지 않음).
- 효과: 로그인과 서비스 없이 root 셸 1회. 플래시에는 아무것도 쓰지 않습니다.
- 위험: 서비스가 뜨지 않아 기기가 정상 동작하지 않고, 워치독이 있으면 수십 초 뒤 재부팅될 수 있습니다.
- 복구: 전원을 다시 넣으면 원래대로 부팅됩니다. 진행할까요? (예/아니오)
```

H4(출력 없음·깨짐 점검), H7(승인 요청), H8(거부 보고) 템플릿은 [reference.md §4](reference.md#4-추가-템플릿).

## 성공·실패 기준

- **success**: 세션이 열리고 보드레이트가 확인됐으며(읽히는 부팅 로그 또는 프롬프트 응답), U-Boot 프롬프트(uboot_printenv complete + uboot_info) 또는 셸(shell_identify)을 얻었다. summary 가 스키마를 통과해 저장됐다.
- **partial**: 부팅 로그만 얻었다(boot-log-only), 로그인에서 멈췄다(login-required), U-Boot 는 얻었지만 플래시 크기가 하한뿐이다, init=/bin/sh 셸에서 일부 정보만 얻었다.
- **failed / blocked**: 재배선·재투입 2회 뒤에도 수신 없음(silent), 전압 조건상 연결 불가, 포트를 찾지 못함, 정책 거부로 진행 불가.
  포트·보드레이트 값이 있으면 summary(status `failed`)를 남긴다. 포트조차 없으면 summary 대신 `step="port-discovery"` 로 기록하고 `case_set_phase(case_id=…, phase="uart-shell-acquisition", status="failed")` 를 부른다.

## 출력

`console_type` 은 세션이 끝난 시점의 콘솔(닫았으면 마지막 문맥), `access_level` 은 얻은 것 중 가장 강한 것이다(root-shell > uboot > user-shell > login-required > boot-log > none).
필드 출처는 [reference.md §2](reference.md#2-응답-필드--uart-recon-매핑). 스키마는 `schema_get(name="uart-recon")`. 서버가 거부하면 메시지대로 고쳐 다시 저장한다.

```text
case_record_step(
  case_id="20261018-acme-ipc", skill="uart-shell-acquisition", step="summary", status="success",
  summary="UART 115200 8N1(/dev/ttyUSB0): U-Boot 2016.11 진입(Ctrl-C), env·W25Q128 16MiB·safe RAM 0x42000000 확보, 사용자 계정으로 root 셸, Linux 4.9.37 식별",
  data=<아래 JSON>,
  artifacts=["uart/console-001.log", "uart/console-001-boot-01.log", "uart/console-001.events.jsonl"],
  next_actions=["firmware-dump-via-uart: 세션 console-001(linux-shell) 재사용, base64 셸 덤프 또는 boot 재진입 후 U-Boot crc32 덤프"]
)
```

```json
{
  "port": "/dev/ttyUSB0",
  "baudrate": 115200,
  "framing": "8N1",
  "baud_detection": {"method": "auto-scan", "candidates": [{"baudrate": 115200, "score": 0.998, "printable_ratio": 0.999}], "score": 0.998},
  "console_type": "linux-shell",
  "access_level": "root-shell",
  "uboot": {
    "version": "U-Boot 2016.11 (Mar 23 2020 - 14:58:03 +0800)hi3516ev300",
    "prompt": "hisilicon # ",
    "autoboot": {"message": "Hit any key to stop autoboot:  2", "interrupt_keys": ["ctrl-c"], "bootdelay": 2},
    "env": {
      "arch": "arm", "baudrate": "115200", "board": "hi3516ev300", "board_name": "hi3516ev300", "bootdelay": "2", "bootfile": "uImage",
      "bootargs": "mem=40M console=ttyAMA0,115200 root=/dev/mtdblock3 rootfstype=squashfs init=linuxrc mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app)",
      "bootcmd": "sf probe 0; sf read 0x42000000 0x50000 0x200000; bootm 0x42000000",
      "cpu": "armv7", "ethaddr": "00:00:23:34:45:66", "ipaddr": "192.168.1.10", "netmask": "255.255.255.0", "serverip": "192.168.1.2",
      "soc": "hi3516ev300", "stderr": "serial", "stdin": "serial", "stdout": "serial", "vendor": "hisilicon", "verify": "n"
    },
    "bootargs": "mem=40M console=ttyAMA0,115200 root=/dev/mtdblock3 rootfstype=squashfs init=linuxrc mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app)",
    "bootcmd": "sf probe 0; sf read 0x42000000 0x50000 0x200000; bootm 0x42000000",
    "mtdparts": "mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app)",
    "partitions": [
      {"name": "boot", "offset": 0, "size": 262144}, {"name": "env", "offset": 262144, "size": 65536},
      {"name": "kernel", "offset": 327680, "size": 2097152}, {"name": "rootfs", "offset": 2424832, "size": 5242880},
      {"name": "app", "offset": 7667712, "size": 9109504}
    ],
    "flash": {"type": "spi-nor", "model": "W25Q128(B/F)V", "size_bytes": 16777216},
    "ram_load_addr": "0x42000000",
    "commands": ["?", "base", "bdinfo", "boot", "bootd", "bootm", "cmp", "coninfo", "cp", "crc32", "echo", "env", "false", "go", "help", "iminfo",
                 "loop", "md", "mm", "mtest", "mw", "nm", "ping", "reset", "run", "saveenv", "setenv", "sf", "sleep", "test", "true", "version"]
  },
  "linux": {
    "kernel_version": "4.9.37",
    "cmdline": "mem=40M console=ttyAMA0,115200 root=/dev/mtdblock3 rootfstype=squashfs init=linuxrc mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app)",
    "cpu": "ARMv7 Processor rev 5 (v7l)",
    "mtd": [
      {"dev": "mtd0", "size": 262144, "erasesize": 65536, "name": "boot"}, {"dev": "mtd1", "size": 65536, "erasesize": 65536, "name": "env"},
      {"dev": "mtd2", "size": 2097152, "erasesize": 65536, "name": "kernel"}, {"dev": "mtd3", "size": 5242880, "erasesize": 65536, "name": "rootfs"},
      {"dev": "mtd4", "size": 9109504, "erasesize": 65536, "name": "app"}
    ],
    "user": "root",
    "busybox": "BusyBox v1.26.2 (2020-03-23 15:10:41 CST)",
    "login_required": true
  },
  "device_info": {
    "soc": "hi3516ev300 (U-Boot env soc, kernel 'Machine model: Hisilicon HI3516EV300')",
    "arch": "armv7l", "dram": "64 MiB", "console": "ttyAMA0,115200", "rootfs_type": "squashfs", "listening_ports": [23, 80, 554, 3702],
    "shell_tools": {"base64": true, "hexdump": true, "md5sum": true}, "flash_write_warnings": []
  },
  "session_log": "uart/console-001.log",
  "boot_log": "uart/console-001-boot-01.log",
  "contexts_reached": ["uboot", "linux-shell"],
  "login_method": "user-credentials",
  "session": {"session_id": "console-001", "kept_open": true, "context_at_end": "linux-shell"},
  "notes": [
    "보드레이트 115200 8N1: uart_detect_baud(probe=none) score 0.998, 부팅 키워드 확인 (confirmed)",
    "autoboot 'Hit any key to stop autoboot: 2' 를 Ctrl-C 로 중단, <INTERRUPT> 로 U-Boot 문맥 확정",
    "로그인: 사용자가 알려 준 root 계정 1회 성공 (비밀번호는 기록하지 않음)",
    "uboot_printenv 의 '-'(app) 파티션 크기는 flash 16 MiB 로 계산 (0x8b0000)",
    "부팅 중 플래시 쓰기 징후 없음. 영구 변경 없음 (saveenv/setenv 보내지 않음)",
    "telnetd(23) 가 부팅 스크립트에서 시작됨 — 정적 분석에서 확인 필요"
  ]
}
```

스키마 밖 필드(`boot_log`, `contexts_reached`, `login_method`(user-credentials / init-sh-ram / none / not-attempted), `session`)는 additionalProperties 로 허용되며 다음 Skill 이 읽는다.
경로 D 를 썼다면 login_method `init-sh-ram`, notes 에 "init=/bin/sh (RAM, saveenv 안 함, 재투입으로 복구)" 를 넣는다. 실패·부분 성공 예는 [reference.md §6](reference.md#6-실패부분-성공-summary-예).

## 다음 단계

- **U-Boot 확보** → `firmware-dump-via-uart`(uboot_dump_start, crc32 검증). uboot.ram_load_addr, flash.size_bytes, partitions 를 넘긴다.
- **root 셸 확보** → `firmware-dump-via-uart`(shell_dump_start, md5 검증, base64 가 있으면 약 3.6배 빠름). linux.mtd 를 넘긴다.
- **로그인에서 막힘·U-Boot 불가** → 공식 펌웨어(`case_import_file`) 또는 SPI 클립 읽기(docs/hardware-setup.md §6) → `firmware-static-analysis`.
- **silent·깨짐 지속** → `logic-analyzer-protocol-decode`(TX 패드·보드레이트·반전 확인) 또는 JTAG(`pweh-openocd`).
- 사용자가 셸 획득만 원했다면 `report_generate` 로 보고서를 만들고 기기 상태(영구 변경 없음)를 알린다.

## 참고

- [reference.md](reference.md): 부팅 로그 판독표, 응답 필드 → uart-recon 매핑, 증상별 문제 해결, 추가 템플릿(H4·H7·H8), 경로 D 세부, 실패 summary 예, 시뮬레이터 연습
- `mcp-servers/uart-mcp/README.md`(도구·분류·호출 순서), `docs/references/uboot-and-boot-console.md` §0 R1–R12·§8·§10·§11
- `docs/hardware-setup.md` §2.2·§3, `docs/safety.md` §2.2·§3·§4, `orchestrator/master-prompt.md` §1·§4·§5·§6
