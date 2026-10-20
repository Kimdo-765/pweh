# pweh-uart (uart-mcp)

UART 콘솔 MCP 서버. 시리얼 포트를 열어 **수신 스레드가 계속 기록**하는 세션을 만들고, U-Boot(autoboot 중단, env/보드 정보,
md.b 덤프 job)와 BusyBox 리눅스 셸(로그인, 식별, dd 덤프 job), 보드레이트 탐지, 부팅 로그 수집을 제공한다.
기기로 가는 모든 바이트는 서버 측 안전 게이트를 거친다.

- 코드: `uart_mcp/` — `server.py`(도구), `session.py`(포트·수신 스레드·링 버퍼·로그·송신 커밋), `guard.py`(송신 분류),
  `tracker.py`(문맥 추적), `console.py`(명령 실행·Ctrl-C 동기화·autoboot 중단·로그인), `dumps.py`(덤프 엔진),
  `parsers.py`(출력 파서), `baud.py`(보드레이트 탐지), `profile.py`(pipeline-config 프로필 → 정규식)
- 계약: `docs/architecture.md` §6.2, 안전 모델 §4. 출력 형식 근거: `docs/references/uboot-and-boot-console.md`
- 실행: `pweh-uart-mcp` 또는 `python -m uart_mcp` (stdio)
- 테스트: `tests/servers/test_uart_mcp.py`(시뮬레이터 PTY/TCP, stdio 1개), `tests/servers/test_uart_gate_coverage.py`(송신 경로별 게이트·우회 회귀),
  `tests/servers/test_uart_dialects.py`(방언 회귀), `tests/uart/`(파서·분류·문맥 단위 테스트)

---

## 1. 도구

| 도구 | 위험도 | 설명 |
|---|---|---|
| `uart_list_ports(include_links=False)` | OBSERVE | 시리얼 포트 목록 + `likely_usb_uart`, `in_use_by` |
| `uart_open(case_id, port, baudrate=115200, bytesize=8, parity="N", stopbits=1, line_ending="\r", dtr=False, rts=False, profile=None, label=None, approval_id=None)` | INTERACT (dtr/rts=true 면 MODIFY) | 세션 시작 → `session_id`, `log_path`/`raw_path`/`events_path`, `context`. `port` 는 장치 절대경로 또는 `socket://`·`rfc2217://`·`loop://` 만(`spy://`·`hwgrep://` 같은 다른 pyserial URL·상대 경로·일반 파일은 `validation_failed` — `uart_detect_baud` 도 같다). `socket://`·`rfc2217://` 는 **루프백 호스트만**(정규형 `127.0.0.0/8`·`[::1]`·모든 주소가 루프백으로 풀리는 `localhost`) 포트(1–65535)와 함께 받고 `<scheme>://<host>:<port>`(소문자)로 정규화한다(`localhost` 는 확인한 루프백 주소 — IPv4 우선 — 로 바꿔 연결 때 다시 풀지 않는다). 같은 루프백 포트의 다른 표기(`127.0.0.1`·다른 `127.x`·`[::1]`·`localhost`, 두 스킴)는 **한 포트**로 본다: 세션이 열린 동안 다른 표기로 연 `uart_open`·`uart_detect_baud` 는 `busy`(세션 둘로 줄 조립기를 나눠 `sa` + `veenv\r` → `saveenv` 를 만드는 우회를 막는다). LAN·와일드카드 호스트, inet_aton 별칭(`127.1`·`2130706433`), 사용자 정보(`@`), zone(`%`), 경로·질의 옵션(`?logging=`·`?timeout=` 등)은 `validation_failed` — LAN 의 ser2net 은 지금 지원하지 않는다(설계 D4 의 운영자 허용 목록 `safety.ports.remote_serial_hosts` 는 아직 구현하지 않았다). Windows `COMn` 은 `validation_failed` — 서버가 네이티브 Windows 에서 시작하지 않으므로 WSL2 에서는 usbipd 로 어댑터를 attach 한 뒤 `/dev/ttyUSB0`·`/dev/ttyACM0`(ESP32 보드 덤프는 pweh-esp 방법 A). DTR/RTS 는 **열기 전에** 설정(기본 False). 장치 경로는 flock 으로 독점한다 — `socket://`·`rfc2217://` 는 pyserial 이 exclusive 를 무시하므로 독점하지 않는다(같은 서버 안에서만 위 규칙으로 `busy`, 다른 프로세스·서버가 같은 URL 에 붙는 것은 막지 못한다). 같은 케이스·포트의 앞 세션이 보낸 마지막 U-Boot 명령을 이어 받으면 `inherited_last_command` (§2.3) |
| `uart_close(session_id)` | — | job 취소 → 수신 스레드 정지 → 로그 3종 아티팩트 등록 (정리 작업이라 게이트 없음) |
| `uart_sessions(case_id=None)` | OBSERVE | 상태(open/disconnected), 문맥/phase/프롬프트, rx/tx, 미완성 입력(`pending_uncertain`), `device_ready`/`device_busy_reason`(§2.2 규칙 10), 실행 중 job |
| `uart_read(session_id, since_cursor=None, max_bytes=8192, wait_seconds=0, tail=False)` | OBSERVE | 링 버퍼 읽기. 커서 = 누적 수신 바이트. 생략 시 에이전트 읽기 위치부터 → `text, cursor_start, cursor_end, more, context, prompt, state, lost_bytes` |
| `uart_write(session_id, data, encoding="text"\|"hex", approval_id=None)` | 내용에 따라 | 원시 쓰기 (≤4096 B). LineAssembler 로 조립된 줄마다 분류 |
| `uart_send_command(session_id, command, timeout=10, expect=None, approval_id=None, max_output=20000)` | 내용에 따라 | 한 줄 + 줄끝 → 에코 → 프롬프트(또는 `expect`) → `output, matched, match, timed_out, context, prompt, cursor_end` |
| `uart_wait_for(session_id, pattern, timeout=30, since_cursor=None)` | OBSERVE | 정규식 대기 (호출 사이 출력 포함) → `matched, match, groups, text, cursor_end, timed_out` |
| `uart_set_context(session_id, context, prompt=None)` | — | 수동 문맥 (`auto` 로 해제). 분류는 수동·자동 중 **더 엄격한 쪽** |
| `uart_sync(session_id, timeout=3, approval_id=None)` *(추가)* | INTERACT | Ctrl-C 한 번 → 새 프롬프트, 문맥 증거(U-Boot 는 `<INTERRUPT>`), 미완성 입력 비움 |
| `uart_send_break(session_id, duration=0.25, approval_id=None)` | MODIFY | BREAK. 이후 5초 동안 첫 송신은 SysRq 가능성 때문에 최소 MODIFY |
| `uart_set_signals(session_id, dtr=None, rts=None, approval_id=None)` | MODIFY | PTY·`socket://` 는 `status: unsupported` |
| `uart_detect_baud(case_id, port, candidates=None, listen_seconds=2.5, probe="ctrl-c"\|"none", approval_id=None)` | MODIFY(probe) / INTERACT | 후보마다 열고 점수화 → `candidates`, `best`, `confidence`, `hint`. 총 50초 제한. 부팅 출력을 들으므로 사람이 전원을 먼저 꺼 두고 '준비' 한 뒤 호출하고, 호출이 시작되면 전원을 넣는다. 이때는 autoboot 를 멈추지 않게 `probe="none"` |
| `uart_capture_boot(session_id, duration=30, until=None, stop_on_prompt=True)` | OBSERVE | 사람이 전원을 먼저 꺼 두고 '준비' 한 뒤 호출, 호출이 시작되면 전원을 넣는다. 부팅 로그 수집·파싱(`uboot_version`, `autoboot_message`, `bootdelay`, `kernel_version`, `cmdline`, `mtdparts`, `partitions`, `login_prompt`, `shell_prompt`, `flash`, `flash_write_warnings`, `stages`) + `uart/<session>-boot-NN.log` |
| `uboot_interrupt(session_id, keys=None, window_seconds=30)` | INTERACT | 사람이 전원을 먼저 꺼 두고 '준비' → 이 도구 호출 → 호출이 시작되면 사람이 전원을 넣음 → 부팅 출력이 보이면 키를 ~50ms 마다 → 프롬프트 → Ctrl-C 동기화. `interrupted, outcome(prompt/kernel/linux/uboot_password/window_expired/cancelled/disconnected), new_boot_seen, prompt, autoboot_message, bootdelay, keys_used, keys_sent, explanation`(이미 프롬프트였으면 `already_at_prompt`). 이미 부팅 중이던 기기의 이전 부팅 출력은 판단에 쓰지 않고 새 부팅을 기다린다 (§2.5) |
| `uboot_printenv(session_id)` | INTERACT | `env{}`, `bootargs`, `bootcmd`, `mtdparts`, `partitions[]`, `loadaddr`, `flash_size`/`flash_size_source`. 완전한 출력일 때만 env 추적에 반영. `-`(나머지) 파티션 크기는 uboot_info 또는 부팅 로그의 플래시 크기로 채운다 |
| `uboot_info(session_id, probe_flash=True)` | INTERACT | `version`, `bdinfo{…}`, `commands[]`, `has{}`/`has_via{}`(help 기준, U-Boot 약어 규칙, 모르면 null), `flash{type, model, size_bytes}`, `partitions[]`(추적 env + 플래시 크기), `safe_ram_addr`, `ram_window` |
| `uboot_dump_start(case_id, session_id, offset, length, source="sf"\|"nand"\|"mmc"\|"ram", ram_addr=None, chunk_size=65536, output_name=None, verify="crc32"\|"double"\|"none", resume=True, retries=3, final_check=True, sf_probe="0")` | INTERACT (job) | 덤프 job → `job_id`. §4 |
| `shell_login(session_id, username=None, password=None, timeout=15)` | INTERACT | askfirst Enter → login → Password. `username` 생략 시 askfirst 콘솔 활성화만(`login:` 이 나오면 `username_required`). 비밀번호 마스킹, 세션당 3회 실패 후 거부. `status`: `ok`/`already_logged_in`/`password_required`/`username_required`/`login_incorrect`/`login_failed`/`context_unknown`/`uboot_prompt`/`uboot_password_prompt`/`stuck_askfirst`/`unknown_prompt`/`timeout`/`disconnected`/`cancelled` (§2.5) |
| `shell_identify(session_id)` | INTERACT | `uname`, `cpuinfo`, `mtd[]`, `cmdline`, `mounts`, `processes`, `listening`, `busybox_applets`, `has_base64` … |
| `shell_dump_start(case_id, session_id, path, offset=0, length=None, method="auto"\|"hexdump"\|"base64", chunk_size=65536, output_name=None, resume=True, retries=3)` | INTERACT (job) | `dd … \| base64`(또는 `hexdump -C`) + 청크별 `md5sum`. `/dev/` 경로는 저장장치(`mtdN[ro]`·`mtdblockN`·`mmcblkN[pM\|bootN]`·`ubiX_Y`·`ubiblockX_Y`·`sdX[N]`·`nand…`)만 — `/dev/watchdog`(여는 순간 타이머 시작)·`/dev/mem` 등은 거부 |
| `uart_job_status(job_id, wait_seconds=0)`, `uart_job_cancel(job_id)`, `uart_jobs(active_only=False)` | — | `register_job_tools(..., "uart")` |

`offset`/`length`/`chunk_size`/`ram_addr` 는 정수 또는 `"0x50000"`, `"64k"`, `"16M"` 문자열.

## 2. 안전 동작

### 2.1 게이트
- 기기에 영향을 주는 도구는 `rt().case(case_id, hardware=True)` 로 소유/허가 증명을 확인한 뒤, 보낼 바이트를 분류해
  `rt().authorize(...)` 를 통과해야 쓴다. 허용되지 않으면 `gate_response` 그대로(`status: denied | approval_required`).
- 승인 지문(`action`)에는 **기기에서 실제로 완성될 줄**과 분류 문맥을 넣는다. U-Boot 가 받을 수 있는 문맥이면 실행 의미도 넣는다:
  빈 줄의 반복 대상 `repeat_of`(모르면 `"<unknown>"`)와 줄이 참조하는 env 값 `env_refs`(`run x`·`boot`·`$len` → 지금 추적 중인 값,
  run 값 안의 참조까지). 그래서 `run x` 를 승인받은 뒤 `setenv x …` 로 내용을 바꾸면 같은 `approval_id` 는 맞지 않는다(`approval_mismatch`).
  타임아웃 같은 실행 옵션은 넣지 않는다. 승인 후 같은 인자 + `approval_id` 로 다시 부르면 1회 실행된다.
- 승인과 쓰기 사이에 상태가 바뀌면(문맥 변화, 다른 입력) 쓰기 직전에 다시 분류해서 줄이 다르거나 위험도가 올라갔으면
  `state_changed` 로 거부한다.

### 2.2 분류 (`guard.py`)
코어 `classify_console_line` / `classify_uboot` / `classify_linux` 위에 **더 엄격하게만** 만드는 로컬 규칙을 얹는다.

1. **줄 조립**: 세션이 보낸 모든 바이트를 기억하는 코어 `LineAssembler` 의 사본에 한 글자씩 넣어 기기 줄 버퍼처럼 조립한다.
   `uart_write("sa")` + `uart_write("veenv\r")` → `saveenv` 한 줄로 분류(거부). Backspace/Ctrl-U/Ctrl-C 편집 반영.
2. 탭(자동완성)·ESC(방향키/히스토리)·기타 제어 문자가 섞인 줄은 **DESTRUCTIVE**. 제어 문자는 `CONTROL_CHAR_RISK`.
3. U-Boot 가 받을 수 있는 문맥에서 `\r\n` 의 `\n` 은 **빈 줄 = 직전 명령 반복**으로 하나 더 분류한다.
4. U-Boot 문맥의 250자 초과 줄은 DESTRUCTIVE (CBSIZE 를 넘으면 기기가 문자를 버려 다른 명령이 실행됨).
5. **문맥 오판 교차 검사**: uboot 문맥에서도 리눅스로 해석해 DESTRUCTIVE 인 줄(`echo x > /dev/mtd0`)과 U-Boot 가 모르는
   명령은 리눅스 분류와 worst. linux-shell 문맥에서 리눅스가 모르는 명령(`saveenv`, `sf erase`, `nan e`)과
   `cp 0x.. 0x.. 0x..` 같은 U-Boot 메모리 명령 모양은 U-Boot 분류와 worst.
6. login/password/booting/unknown 문맥의 일반 송신은 **unknown(두 분류기의 worst)**. 로그인 입력을 INTERACT 로 보는 경로는
   `shell_login` 뿐이고, 그때도 `login:`/`Password:` 프롬프트가 지금 수신 끝에 있을 때만 보낸다.
7. 한 페이로드의 여러 줄은 순서대로 분류하며 줄마다 last_command·setenv 효과를 반영한다.
8. 수동 문맥(`uart_set_context`)은 자동 감지 문맥과 둘 다로 분류해 더 엄격한 쪽을 쓴다 — 수동 지정으로 완화할 수 없다.
9. 호출 경계를 넘는 CRLF: `uart_write("mw…\r")` 다음 `uart_write("\n")` 의 `\n` 도 U-Boot 에서는 빈 줄(반복)이다 — 직전 송신의
   마지막 문자를 이어 받아 규칙 3 으로 분류한다(1회용 승인을 `\n` 으로 다시 실행하지 못하게).
10. **기기 준비 상태**: 조립기는 보낸 바이트가 모두 기기 줄 편집기에 들어간다고 가정하는데, 기기가 프롬프트에 있지 않으면 틀린다 —
    autoboot 중단 키는 한 글자를 소비하고, 커널 초기화 중 입력은 버려지고, 명령 실행 중 U-Boot `ctrlc()` 폴링은 들어온 글자를 읽어 버린다
    (`xsaveenv` 의 `x` 만 먹히면 `saveenv` 실행). 그래서 (a) 자동 문맥이 `booting` 이거나, (b) 줄 끝을 보낸 뒤 새 프롬프트가 아직 없거나,
    (c) 마지막 프롬프트 뒤 재부팅·커널 시작 증거가 있으면 "준비 안 됨"이고, 그때 완성되는 비어 있지 않은 줄은 **DESTRUCTIVE**
    (`uart.device-busy`), 남는 미완성 입력은 조립기에 uncertain 으로 표시해 Ctrl-C 로 비울 때까지 다음 줄도 DESTRUCTIVE 다.
    한 페이로드에서 앞 줄이 완성된 뒤의 입력도 "실행 중에 보낸 입력"이다(`md.b …\rxsaveenv\r` 의 둘째 줄 거부). 재부팅·커널 시작
    증거가 보이면 남아 있던 미완성 입력도 uncertain 이 된다(`echo ` + 재부팅 + `saveenv` → 기기는 `saveenv` 만 받는다).
    줄을 보내는 도구는 프롬프트가 곧 돌아올 때(예: `expect` 로 일찍 끝난 명령)를 위해 최대 0.5초 기다린 뒤 분류한다.
11. **모르는 직전 명령의 반복**: 이 세션이 줄을 보낸 적도 재부팅을 본 적도 없으면, 기기에서 세션 전에 실행된 명령(사람이 친 `mw` …)을
    알 수 없다 → U-Boot 가 받을 수 있는 문맥의 빈 Enter 는 **DESTRUCTIVE** (`uart.repeat-unknown`). 새 프롬프트는 `uart_sync`,
    askfirst 활성화는 `shell_login`. `uboot_interrupt` 의 Enter 키는 새 부팅을 본 뒤에만 보내므로(그때 다시 분류) 사전 승인에서는 이 규칙을 빼고 본다.
12. **다른 명령을 실행하는 U-Boot 명령**: `env run <var>`(`env r` 같은 약어 포함) = `run <var>`, `time <명령>`(`t`/`ti`/`tim` 약어 포함)은
    안쪽 명령 기준으로 분류한다. `run`·`boot`(bootcmd)·명령 위치 `$var` 의 값 안과 빈 Enter 의 반복 대상에도 적용한다.
    지금은 코어 `classify_uboot` 도 같은 규칙을 갖지만(`uboot.env.run>…`, `uboot.time>…`), 코어가 바뀌어도 uart 경로의 보호가 남도록 이중으로 둔다.
13. 문맥 오판 교차 검사 보강: linux-shell 문맥에서 인자가 주소 모양(16진수·10진수·`$var`·`${var}`)인 `cp`/`mw`/… 와 `reset` 은
    U-Boot 해석과 worst (`cp ${loadaddr} 0 100` → DESTRUCTIVE, `reset` → MODIFY).
15. **리눅스 현재 디렉터리**: 세션이 보낸 `cd` 로 cwd 를 추적해(`uart_sessions` 의 `linux_cwd`, `cd` 는 성공한다고 봄, 재부팅을 보면 모름으로 되돌림)
    코어 `classify_linux(cwd=…)` 에 넘긴다. `cd /usr/bin` 다음 `cp /tmp/x md5sum` 은 시스템 경로 쓰기(`linux.write.system`, DESTRUCTIVE)다.
    cwd 가 승인 지문(`cwd`)에 들어가므로, 승인받은 상대 경로 명령도 cwd 가 바뀌면 다시 승인받는다.
14. **비트 폭**: 데이터 비트가 8 보다 적은 세션은 기기가 받는 하위 비트로 분류하고(`\xf3\xe1…\x8d` = 7비트에서 `sa…\r`),
    8비트 세션에서 상위 비트가 켜진 바이트는 하위 7비트로도 분류한다(7E1 기기를 8N1 로 연 경우·ISTRIP). 상위 비트 문자가 섞인 완성 줄은
    DESTRUCTIVE (`uart.high-bit`) — 기기 콘솔에는 ASCII 만 보낸다.

### 2.3 U-Boot 상태 추적
- **env**: `uboot_printenv` 의 완전한 출력이 기준. 실제로 보낸 `setenv`/`env set`/`env delete` 를 반영하고, 추적할 수 없는
  변경(run, boot, env default/import, setexpr, tftp, 알 수 없는 명령 …)을 보내면 추적 env 를 버린다 →
  `run X` 는 다시 printenv 할 때까지 DESTRUCTIVE(내용 미상). 재부팅 증거(DRAM:/SPL/autoboot)가 보여도 버린다.
- **last_command**: 실제로 보낸 비어 있지 않은 줄. 빈 Enter 는 이것의 반복으로 분류한다. **수신 텍스트로는 절대 지우지
  않는다**(예: `version` 출력의 U-Boot 배너, `echo` 로 찍은 문자열).
- 이 서버의 도구는 U-Boot 프롬프트를 깨우려고 빈 Enter 를 보내지 않는다. 새 프롬프트는 `uart_sync`(Ctrl-C).
- 세션을 닫으면 그 세션이 마지막으로 보낸 U-Boot 명령을 서버가 기억하고, 같은 케이스·포트를 다시 연 세션이 이어 받는다
  (`uart_open` 의 `inherited_last_command`). 예: `setenv baudrate 57600` → `uart_close` → 새 속도로 `uart_open` → `uart_write("\r")`
  은 `setenv baudrate …` 의 반복(MODIFY)으로 분류된다. 추적 env 는 이어 받지 않는다(세션 사이에 본 적 없는 재부팅이 있었을 수 있음).
  이 기억은 서버 프로세스 메모리에만 있다. 서버가 재시작됐거나 다른 포트로 열면 `inherited_last_command` 가 없고, 그때의 빈 Enter 는
  `uart.repeat-unknown`(DESTRUCTIVE)로 거부된다 → 사람에게 전원 재투입을 요청해 원래 속도로 돌아간다(U-Boot 의 속도 변경 확인 대기는 `\r` 만 받으므로 `uart_sync` 로는 끝낼 수 없다).
  `setenv baudrate …` 를 보내면 `uart_send_command` 응답의 `warning` 이 이 절차를 알려 준다.

### 2.4 문맥 추적 (`tracker.py`)
- 문맥: `uboot | linux-shell | login | password | booting | unknown`. 프롬프트 정규식은 `pipeline-config.yaml` 프로필의
  `uart.*` (세션 프로필 = `uart_open(profile)` 또는 케이스 프로필).
- **phase 증거**가 필요하다: U-Boot 증거(`<INTERRUPT>`, `Unknown command '…' - try 'help'`, autoboot, 배너 …) 또는 리눅스 증거
  (커널 부팅 마커, `-sh: …: not found`, BusyBox, login …). `hisilicon # ` 처럼 U-Boot/리눅스 정규식 둘 다에 맞거나 증거와 맞지
  않는 프롬프트는 `unknown`(더 엄격). 기기에 붙었는데 이미 프롬프트에 있으면 `uart_sync` 로 확정한다.
- 부팅 마커: U-Boot 시작 → `booting`, `Starting kernel` 이후 로그인/셸 프롬프트까지 `booting`, askfirst 메시지는 `login`.
- 줄바꿈 전의 `md.b`/`hexdump -C` 출력 줄(`42000000: …`, `00000000  …`)은 프롬프트 후보가 아니다 — ASCII 열이 `… # `, `|login: `
  처럼 끝나는 순간 수신이 끊겨도 문맥이 바뀌거나 덤프 명령이 일찍 끝나지 않는다.
- **우리 입력의 되풀이는 증거가 아니다**: 세션이 보낸 줄의 에코(`hisilicon # echo …`, Ctrl-C 로 버린 입력의 `…<INTERRUPT>` 줄 포함)와
  보낸 텍스트를 그대로 되풀이한 출력(U-Boot `echo Linux version 9.9` → `Linux version 9.9`)은 phase·부팅·사실 판단에 쓰지 않고,
  수신 끝에 보이는 입력 에코(줄바꿈 전)는 프롬프트·askfirst·login 판단에서 가린다. 그렇지 않으면 에이전트가 보낸 텍스트 때문에 U-Boot 를
  linux-shell 로 오판해 U-Boot `cp` 가 리눅스 기준(MODIFY)으로 통과한다. 변수 등으로 되풀이 검사를 피해도, 이미 U-Boot 프롬프트로
  학습한 문자열과 똑같은 프롬프트는 리눅스 phase 증거만으로 linux-shell 이 되지 않는다(`unknown` → 두 분류기의 worst, `uart_sync` 로 확정).
- 플래시 쓰기 징후(`Saving Environment to`, `Write default environment to flash` …)는 이벤트·감사 로그에 남긴다.

### 2.5 그 밖에
- `shell_login`: 사용자가 알려 준 계정만. 세션당 3회 실패하면 더 시도하지 않는다. 비밀번호는 `.log`(`******`),
  `.events.jsonl`, `audit.jsonl`, 승인 지문 어디에도 남지 않는다 (`.raw` 는 기기가 에코한 것만 — BusyBox 는 비밀번호를 에코하지 않음).
  이번 호출이 계정을 보내지 않았는데 프롬프트가 문맥 `unknown`(예: 증거 없는 `hisilicon # `)이면 리눅스로 단정하지 않고
  `context_unknown` 으로 돌려준다(아무것도 보내지 않음) → `uart_sync` 로 확정한다. 커널 시작 전(U-Boot phase)의 `Password:` 에는
  리눅스 비밀번호를 보내지 않고 `uboot_password_prompt` 로 멈춘다(부트로더 잠금 — 추측 금지).
- `uboot_interrupt` 판단 규칙: 커널/리눅스 프롬프트 출력은 **이번 부팅의 U-Boot 단계를 본 뒤**(호출 뒤 새 부팅 시작·autoboot, 또는
  호출 시점에 카운트다운 전/중)에만 쓴다. 이미 부팅 중이던 기기의 이전 출력이면 창 동안 새 부팅을 기다리고(그동안 리눅스에 키를
  보내지 않음 — `autoboot_silent` 프로필 제외), 새 부팅이 없으면 `window_expired` + 설명. 커널 시작 전의 `Password:` 는 부트로더
  잠금(`outcome=uboot_password`, 키 송신 중단) — 추측·대입하지 않는다.
- `uart_detect_baud` 의 Ctrl-C 프로브는 MODIFY 로 분류한다: 다른 속도로 보낸 0x03 은 기기에서 다른 바이트로 읽힐 수 있다
  (8N1 파형상 CR/LF 는 될 수 없지만 0x04 Ctrl-D 등은 가능).
- 연결이 끊기면(USB 분리, 소켓 종료) 세션은 `disconnected`. 쓰기 도구는 `disconnected` 오류, `uart_read` 는 계속 된다.
  `uart_close` 후 `uart_open` 으로 다시 연다.

## 3. 일반적인 호출 순서

```
case_create (사용자 소유/허가 확인)
uart_list_ports
※ 전원 투입 타이밍이 필요한 도구(uart_detect_baud, uart_capture_boot, uboot_interrupt):
   사람이 전원을 먼저 꺼 두고 "준비" → 도구 호출 → 호출이 시작되면 사람이 전원을 넣는다
(보드레이트 모름) 위 순서로 → uart_detect_baud(case_id, port, probe="none")
uart_open(case_id, port, baudrate)
── U-Boot 경로 ──
uboot_interrupt(session_id)          ← 위 순서 (꺼 둔 전원을 호출이 시작되면 넣음)
uboot_printenv(session_id)           ← env 추적 (run/boot 분류의 기준)
uboot_info(session_id)               ← safe_ram_addr, flash 크기
uboot_dump_start(case_id, session_id, offset=0, length="16M")  → job_id
uart_job_status(job_id, wait_seconds=30) … (취소: uart_job_cancel, 재개: 같은 인자로 다시 호출)
── 리눅스 경로 ──
uart_capture_boot(session_id, duration=40)   ← 위 순서 / 또는 이미 부팅된 기기면 uart_sync
shell_login(session_id, username, password)  ← 사용자에게 받은 계정
shell_identify(session_id)
shell_dump_start(case_id, session_id, path="/dev/mtd3") → job_id
── 끝 ──
uart_close(session_id)               ← 로그 아티팩트 등록
case_record_step(… summary …)        ← uart-recon / firmware-dump 스키마
```

## 4. 덤프 job

**U-Boot (`uboot_dump_start`)** — 청크마다:
1. `sf read <ram> <off> <len>` (`nand read …`, `mmc read <ram> <blk> <cnt>`(512B 블록), `source="ram"` 이면 적재 없이 `offset` 이 RAM 주소)
   적재 출력 확인: `SF: N bytes @ X Read: OK` 줄이 있으면(2016.11·Ingenic) N·오프셋·OK 가 요청과 같아야 하고, 없으면(2010.06 은
   빈 줄만) 오류 문구만 본다. `past flash size`/`out of range`/`Unknown command` 와 NAND `bad block`(건너뛴 블록만큼 뒤 청크와
   데이터가 겹쳐 1:1 이미지가 아님)은 재시도하지 않고 멈춘다
2. `md.b <ram> <len>` → 코어 `parse_md_b_output` 으로 주소 연속성·바이트 수 검증 + 줄마다 바이트 수 일정(ASCII 열이 16진 토큰처럼
   붙은 줄 거부). `\r\r\n` 줄 끝, 2010.06 의 패딩 없는 마지막 줄, 형식이 아닌 잡음 줄은 받는다
3. `crc32 <ram> <len>` (대소문자 무관 파싱) ↔ 호스트 `zlib.crc32`. `crc32` 명령이 없으면 같은 범위를 두 번 읽어 비교(`double`)
4. 실패하면 Ctrl-C 로 프롬프트를 되찾고 `retries` 번 다시. 그래도 실패하면 청크 번호·오프셋·사유가 담긴 오류로 끝난다

- 시작 전: Ctrl-C 동기화로 U-Boot 증거 확보, `sf probe 0`(모든 방언에서 유효), 계획된 **모든 명령이 INTERACT 이하**인지 검사.
  실행 중에도 명령마다 같은 분류기로 다시 검사하고, 문맥이 바뀌면(재부팅 등) 멈춘다.
- `ram_addr` 생략 시 `uboot_info` 의 `safe_ram_addr`. DRAM 밖이거나 U-Boot 영역(relocaddr/malloc/스택 − 1 MiB)을 침범하면 거부.
- 좋은 청크마다 `dumps/<name>.bin.part` + `dumps/<name>.state.json` 갱신 → 취소·실패·서버 재시작 뒤 **같은 인자로 다시 호출하면**
  다음 청크부터 이어 받는다(`resume=false` 면 처음부터, 완료된 `.bin` 은 덮어쓰지 않음). 같은 `output_name` 의 진행 중 덤프가
  다른 인자(source/offset/length/chunk_size, 셸은 path/offset/chunk_size + 준 경우 length/method)로 시작됐으면 job 을 띄우기 전에 거부한다.
- 취소·실패로 끝나도 `uart_job_status` 의 `result`(= `meta.partial_result`)에 `status: cancelled|failed`, 완료 청크·바이트가 남고,
  `.state.json` 의 `runs[]` 마지막 항목에 `status`, `duration_seconds`, `finished_at`(실패면 `error`)이 기록된다.
- 끝나면(sf + crc32 + 전체가 RAM 창에 들어가면) 전체 범위를 한 번 더 `sf read` + `crc32` 로 대조하고,
  `dumps/<name>.bin`, `dumps/<name>.json`, 아티팩트(`flash-dump` / `memory-dump`) 를 남긴다.

**리눅스 셸 (`shell_dump_start`)** — 청크마다 `dd if=<path> bs=… skip=… count=… 2>/dev/null | base64` (없으면 `| hexdump -C`,
`*` 접기와 BusyBox 끝 주소 버그, 16바이트 미만 0 데이터를 `*` 한 줄로만 찍는 동작까지 복원) → 같은 범위 `| md5sum` 비교.
길이 생략 시 `/proc/mtd`(또는 `wc -c`). 아티팩트 `partition`.

**메타데이터 `dumps/<name>.json`** (firmware-dump 스키마에 그대로 옮길 수 있음):
`method`(`uboot-md` / `linux-base64` / `linux-hexdump`), `source{type, flash_type, flash_size, offset, length, partition, ram_addr, device_path}`,
`output{path, sha256, size}`, `verification{method: crc32-chunks | md5-device | double-read(verify="double") | none, match, chunks_verified, full_range}`,
`chunks{size, count, retries, resumed_from, checks[]}`, `baudrate`, `duration_seconds`(마지막 실행), `duration_seconds_total`(재개 포함 합계), `runs[]`, `notes`.

**진행률**: `uart_job_status` 의 `progress`/`eta_seconds` 는 이번 실행(재개 포함)의 남은 작업 기준이고, 전체 진행은
`meta.overall_progress`, `meta.overall_done_bytes`, `message` 에 있다.

## 5. 처리량과 타이밍

- 8N1 = 문자당 10비트 → 115200 baud ≈ 11,520 문자/초.
  - `md.b`: 바이트당 약 4.94 문자 → **약 2.3 KB/s**. 64 KiB 청크 ≈ 28초, **16 MiB ≈ 2시간**, 8 MiB ≈ 1시간.
  - `hexdump -C`: 약 5 문자/바이트(0xFF 영역은 `*` 접기로 훨씬 빠름). `base64`: 1.37 문자/바이트 → 16 MiB ≈ 33분.
- 청크 타임아웃은 보드레이트와 프레이밍(문자당 비트: 8N1 = 10, 8E1·8N2 = 11)으로 계산한다(예상 시간 × 2.5 + 10초, 최소 15초).
  `chunk_size` 최대 256 KiB(md.b 출력이 링 버퍼 4 MiB 를 넘지 않게).
- 동기 도구의 대기(`uart_send_command`, `uart_wait_for`, `uart_capture_boot`, `uboot_interrupt`)는 MCP 클라이언트의 도구 타임아웃
  (흔히 60초)을 넘지 않게 잡는다. 긴 작업은 job 으로.
- 프롬프트 완료 판정: 프롬프트가 수신 끝에 있고 60 ms 동안 조용할 때. 그래서 출력 중간의 `# ` 같은 문자열에 속지 않는다.
- `expect`/`uart_wait_for`/`until` 정규식: 매치가 아직 끝나지 않은 줄의 끝에 닿아 있으면(`^bootargs=.*$` 가 `bootargs=` 까지만 온 줄에
  맞는 경우) 줄이 끝나거나 60 ms 조용해질 때까지 보류한다 → 값이 잘리지 않는다. 프롬프트 같은 꼬리(`login: $`)는 조용해지면 맞는다.
  시간이 끝나면 그때의 매치를 돌려준다.
- U-Boot 는 실행 중 받은 입력을 RX FIFO 만큼만 남기고, `ctrlc()` 를 폴링하는 명령은 Ctrl-C 가 아닌 입력을 버린다
  → 이 서버는 프롬프트가 돌아오기 전에 다음 명령을 보내지 않는다.

## 6. 로그 파일

| 파일 | 내용 |
|---|---|
| `uart/<session>.log` | `<ISO 시각> RX \| <줄>` (미완성 줄은 `RX~`, 이어진 줄은 `RX+`), `TX \| <이스케이프된 송신>`(비밀번호 `******`), `-- \|` 메모 |
| `uart/<session>.raw` | 수신 원시 바이트 그대로 |
| `uart/<session>.events.jsonl` | `open`/`close`/`tx`(분류·조립된 줄)/`context`/`phase`/`boot_start`/`autoboot`/`flash_write_warning`/`sync`/`uboot_interrupt`/`login`/`dump_retry`/`disconnected` … |
| `uart/<session>-boot-NN.log` | `uart_capture_boot` 발췌 |

열 때 세 파일을 아티팩트(`uart-log`, `uart-raw`, `uart-events`)로 등록하고, 닫을 때와 job 이 끝날 때 크기·해시를 갱신한다.

## 7. 시뮬레이터로 해 보기

```bash
.venv/bin/pweh-mock-device --profile hisilicon-like --pty --no-autostart   # 첫 줄 JSON 의 pty 경로
# 에이전트: uart_open(case_id, port="/dev/pts/N") → uboot_interrupt → (터미널에서) power-on
```
TCP: `--tcp --port 4321` → `port="socket://127.0.0.1:4321"`. 시뮬레이터는 IPv4 루프백에만 바인드한다(IPv6 주소는 거부, `--host 0.0.0.0` 같은 주소는 `--allow-lan` 없이는 거부, 있으면 stderr 경고 — 인증 없는 콘솔이 LAN 에 열린다). 프로필별 출력 차이는 `tests/mock-targets/README.md`.

## 8. 한계

- 프롬프트가 프로필 정규식과 전혀 다르면 `uart_set_context(prompt=…)` 로 알려 주거나 `expect` 를 써야 한다. 프롬프트를 못 알아보면
  첫 명령 뒤로 기기가 "준비 안 됨"(§2.2 규칙 10)으로 남아 다음 줄이 거부되므로 이때도 프롬프트를 알려 준다.
- 분류기는 협조적이지만 성급한 에이전트의 실수를 막는 장치이며 적대적 우회를 완벽히 막는 샌드박스가 아니다 (docs/safety.md).
  예: 되풀이 검사는 텍스트 비교라 `printf` 이스케이프·변수로 피할 수 있다(학습한 U-Boot 프롬프트 규칙이 일부를 막는다). Backspace(0x08)/DEL(0x7F)은
  편집으로 반영하는데, 줄 편집이 없는 리눅스 tty 에서 erase 문자가 아닌 쪽은 글자로 남는다 — 에이전트는 편집 키를 보내지 않는다.
- `inherited_last_command` 는 세션 사이에 사람이 콘솔에 직접 입력했으면 틀릴 수 있다(서버는 세션 밖 입력을 보지 못한다).
- `uboot_dump_start` 에 `ram_addr` 을 직접 주면서 `uboot_info` 를 부르지 않았으면 DRAM 범위를 몰라 주소를 검사하지 못한다(`notes` 에 기록).
  코어는 `sf read`/`nand read`/`mmc read` 를 대상 주소와 무관하게 INTERACT 로 보므로 `ram_addr` 은 `uboot_info` 의 `safe_ram_addr` 을 쓴다.
- 리눅스 init 중(부팅 스크립트가 콘솔을 쥔 동안) 보내는 Ctrl-C 는 INTERACT 다(코어 `CONTROL_CHAR_RISK`). `uboot_interrupt` 는 리눅스가 도는 동안 키를 보내지 않는다.
- `shell_dump_start` 의 `/dev` 제한은 경로 문자열 기준이라 `/dev/watchdog` 을 가리키는 심볼릭 링크나 다른 경로는 알아보지 못한다.
- 리눅스가 포트를 열 때 DTR 을 잠깐 올리는 어댑터/드라이버가 있다(pyserial 이 그 뒤에 내림). DTR 이 리셋에 연결된 보드는 주의.
- `mmc read` 는 2013.07 이후 문법(`mmc read <ram> <blk> <cnt>`, 장치는 미리 `mmc dev`)만 지원한다. `nand read` 는 배드 블록을
  건너뛰므로(OOB 없음) 범위 안에 배드 블록이 보이면 덤프를 멈춘다 — 배드 블록이 없는 범위로 나누거나 다른 경로(nand dump, SPI/NAND
  프로그래머)를 쓴다.
- 세션은 서버 프로세스 메모리에만 있다. 서버가 재시작되면 다시 열어야 하며, 덤프는 `.state.json` 으로 이어 받는다.
