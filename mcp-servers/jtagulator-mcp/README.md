# pweh-jtagulator (jtagulator-mcp)

[JTAGulator](https://github.com/grandideastudio/jtagulator)(Grand Idea Studio / EXPLIoT)를 USB-시리얼 텍스트 메뉴로
조작해 **JTAG(IDCODE/BYPASS/Combined)·UART 핀아웃**을 찾는 MCP 서버다. 파이프라인에서 "UART/JTAG 패드 위치를 모를 때"
쓰는 선택 장비이며, 찾은 핀아웃은 `pweh-uart`(콘솔)·`pweh-openocd`(JTAG 디버그)로 이어진다.

> **본인이 소유하거나 서면 허가를 받은 기기에서만 사용한다.** 모든 하드웨어 도구는 케이스의 소유/허가 증명을 요구한다.

- 펌웨어: **FW 1.10 – 1.12** 지원 (기준 1.12). 그보다 오래된 펌웨어는 대화 순서·문구가 달라 자동 조작을 거부한다
  (`allow_untested_firmware=true` 로만 강제 가능 — 권장하지 않음, 펌웨어 업데이트 권장).
- 프로토콜 근거: 펌웨어 소스(tag 1.12/1.11.1/1.10)와 [`docs/references/jtagulator-protocol.md`](../../docs/references/jtagulator-protocol.md).
- 실행: `pweh-jtagulator-mcp` 또는 `python -m jtagulator_mcp` (stdio).

---

## 1. 도구

시그니처는 주요 인자만 적었다(`approval_id`, 타임아웃, `active_only` 같은 선택 인자는 일부 생략). 전체 인자와 기본값은 [`docs/references/pweh-mcp-tools.md`](../../docs/references/pweh-mcp-tools.md) 를 본다.

| 도구 | 위험도 | 설명 |
|---|---|---|
| `jtagulator_connect(case_id, port, baudrate=115200, timeout_seconds=12, allow_untested_firmware=false, approval_id=None)` | INTERACT(새 reset 배선 open은 MODIFY) | 공용 OS lease → 역할·외부 보유자 확인 → gate → fresh 경로/guard → open → Ctrl-X 재동기화 → 버전. 문자장치·루프백 socket/RFC2217·loop 및 확인된 WSL1 COM1–191을 받으며 WSL COM1–COM4096은 검증된 helper를 사용한다(interop 필요, WSL1 COM1–191은 ttyS 고정). 다른 PWEH 서버가 같은 tty/URL을 점유하면 open 전에 busy. UART의 target/bridge 표지가 있거나 그 식별을 해소하지 못해도 프로브를 거부한다. POSIX TIOCEXCL을 적용하며 disconnected 연결은 명시 disconnect까지 lease를 유지한다. `connection.route`, `device_id`, `busy_check`, `warnings`를 반환하고 전압은 연결마다 미설정이다 |
| `jtagulator_disconnect(case_id)` | – | 실행 중 스캔을 중단(LF)하고 포트를 닫음, 세션 기록 등록 |
| `jtagulator_version(case_id)` | OBSERVE | 메인 메뉴 `I` — 버전/배너 |
| `jtagulator_status(case_id=None)` | 장치 I/O 없음 | 연결·펌웨어·메뉴·확인된 전압·실행 중 작업 |
| `jtagulator_set_voltage(case_id, volts, approval_id=None)` | **DESTRUCTIVE** (기본 거부) | 타깃 I/O 전압(VADJ) 1.4–3.3 V (0.1 V 단위), 0 = 끄기. 장치가 `New target I/O voltage set: x.y` 로 확인해야 스캔 허용 |
| `jtagulator_idcode_scan(case_id, start_channel, end_channel, pins_low=false, …)` | MODIFY · job | TDO/TCK/TMS(+TRST# 후보) + Device ID (TDI 는 못 찾음) |
| `jtagulator_bypass_scan(case_id, start_channel, end_channel, known_pins=None, …)` | MODIFY · job | TDI/TDO/TCK/TMS + 장치 수. `known_pins` 로 아는 핀 고정 |
| `jtagulator_jtag_scan(…)` | MODIFY · job | Combined(IDCODE→TDI BYPASS 시험). 4핀 + Device ID 를 한 번에 |
| `jtagulator_uart_scan(case_id, start_channel, end_channel, text="\r", known_pins=None, delay_ms=10, printable_only=false, …)` | MODIFY · job | TXD/RXD/보드레이트 + 응답 데이터 |
| `jtagulator_uart_txd_scan(case_id, start_channel, end_channel, duration_seconds=20, ignore_nonstandard=false)` | MODIFY(수동) · job | 입력만 감시해 TXD 와 보드레이트 측정 — **가장 안전한 첫 단계** (레벨 변환기의 약한 풀업만 걸림) |
| `jtagulator_gpio_read(case_id, samples=1, interval_ms=100)` | INTERACT(수동) | GPIO `R`: 24채널 레벨, LOW 고정 채널, 표본 사이 변화(활동) 채널 |
| `jtagulator_get_device_ids(case_id, tdo, tck, tms)` | MODIFY | JTAG `D`: 지정 핀으로 IDCODE 상세 |
| `jtagulator_bypass_test(case_id, tdi, tdo, tck, tms)` | MODIFY | JTAG `T`: BYPASS 패턴 일치 여부(핀아웃 검증) |
| `jtagulator_job_status(job_id, wait_seconds=0)` / `jtagulator_job_cancel(job_id)` / `jtagulator_jobs()` | – | 스캔 작업 폴링·취소 |

스캔 공통 옵션: `pins_low`(순열마다 채널을 LOW 로 내렸다 올림, 타깃 리셋용), `pins_low_ms`/`pins_high_ms`(1–1000),
`idle_timeout_seconds`(장치 출력이 이 시간 동안 없으면 중단), `max_duration_seconds`(전체 시간 제한), `approval_id`
(`modify_policy: approve` 일 때).

**노출하지 않는 명령** (분류기가 DESTRUCTIVE 로 막음): JTAG `Y`(IR/DR discovery — 모든 JTAG 명령어 실행),
`P`(EXTEST 핀 매퍼 — 타깃 칩 핀 구동), `O`(OpenOCD 영속 모드), GPIO `W`(24채널 출력)·`L`(로직 분석기 영속 모드),
메인 `A`(전체 스캔), UART `P`(패스스루 — 이후 입력이 분류 없이 콘솔로 감). 콘솔 작업은 `pweh-uart`, 디버깅은 `pweh-openocd` 를 쓴다.

---

## 2. 결선 (사람이 한다)

1. **타깃 전원을 끈다.**
2. **GND 를 먼저** 공통으로 연결한다 (JTAGulator 헤더의 GND ↔ 타깃 GND).
3. 후보 테스트포인트/패드를 **CH0 부터 차례로** 연결한다. 채널은 CH0–CH23 (8채널씩 헤더 3개).
   - 스캔 범위(`start_channel`–`end_channel`)는 연결한 채널만 포함하도록 좁힌다 → 순열 수가 급격히 줄어든다(아래 표).
   - 전원 레일(VCC), 리셋, 부트 모드, 플래시 write-protect, 전원 enable 같은 민감한 핀은 가능하면 빼고 연결한다.
     스캔은 범위 안의 **모든 채널을 출력 HIGH 로 구동**하고 TRST# 탐색 때는 후보 채널을 100 ms 동안 LOW 로 잡는다.
4. **VADJ 핀은 절대 타깃에 연결하지 않는다.** VADJ 는 레벨 변환용 전압 출력이지 타깃 전원이 아니다
   (펌웨어 경고: `Warning: Ensure VADJ is NOT connected to target!`).
5. **멀티미터로 타깃의 I/O 전압을 측정**한다 — 디버그 헤더의 VCC/VREF 핀, SoC VCCIO, UART 패드의 유휴 HIGH 레벨 등.
   에이전트는 전압을 추정하거나 데이터시트로 '아마 3.3 V' 라고 정하면 안 된다. 측정값을 사람이 알려 준다.
6. JTAGulator USB 를 PC 에 연결한다 (FTDI FT232RL, Linux 에서 `/dev/ttyUSB*`, 사용자에게 `dialout` 권한 필요).

### 채널 입력 한계 (중요)
HW Rev. C 의 채널 직렬 저항은 10 Ω 이라 채널 최대 입력은 **VADJ + 0.5 V** 로 봐야 한다(레퍼런스 §15.3).
5 V 신호선을 연결하면 JTAGulator 의 레벨 변환기가 손상될 수 있다. 1.4 V 미만(예: 1.2 V I/O) 타깃은 지원 범위 밖이다.

### 전원 순서 (레퍼런스 §15.4)
VADJ 가 0 V 인데 타깃 신호선에 전압이 걸리면 클램프 다이오드로 전류가 흐를 수 있다. 다음 순서를 지킨다.

1. 타깃 전원 OFF 상태에서 GND·채널 연결
2. `jtagulator_connect` → `jtagulator_set_voltage` (사람 승인)
3. 타깃 전원 ON
4. 스캔
5. 타깃 전원 OFF → `jtagulator_disconnect`

포트를 열거나 닫을 때 FT232 의 DTR 이 Propeller 를 **리셋**할 수 있다(리셋되면 전압이 `Undefined`, VADJ 꺼짐).
회로 해석상 DTR 을 *해제*하는 에지에서 리셋될 가능성이 높다(레퍼런스 §2, 미실측): 서버는 열 때 DTR 을 내리므로 연결 시,
그리고 포트를 닫을 때(HUPCL) 리셋될 수 있다. 그래서 서버는 연결할 때마다(같은 연결을 재사용해도) 전압 상태를 '미설정'으로 두고,
스캔 전에 이 연결에서의 전압 설정·확인을 요구한다. 재동기화는 리셋 직후 부팅 중인 장치를 위해 몇 초간 재시도한다.

---

## 3. 전압 설정과 승인 (DESTRUCTIVE)

잘못된 전압으로 채널을 구동하면 **타깃 I/O 가 손상**될 수 있다(예: 1.8 V SoC 에 3.3 V). 그래서 `jtagulator_set_voltage` 는
DESTRUCTIVE 이고 기본 정책(`safety.destructive_policy: deny`)에서는 거부된다. 0(끄기)도 DESTRUCTIVE 로 본다 — 타깃 전원이
켜진 채 VADJ 를 끄면 클램프로 전류가 흐를 수 있기 때문이다.

필요할 때의 절차:

1. **운영자(사람)** 가 `orchestrator/pipeline-config.yaml` 의 `safety.destructive_policy` 를 `approve` 로 바꾸고
   MCP 서버를 재시작한다 (에이전트가 스스로 바꾸면 안 된다).
2. 에이전트가 `jtagulator_set_voltage(case_id, volts=<측정값>)` 호출 → `status: approval_required`, `approval_id` 반환.
   응답의 `operator_checklist` 를 사용자에게 보여 준다.
3. 사람이 **멀티미터 측정값과 요청 전압이 같은지 확인**한 뒤 별도 터미널에서 `pweh approve <approval_id>` (확인 코드 입력).
   클라이언트가 MCP elicitation 을 지원하면 확인 폼으로 승인할 수도 있다.
4. 에이전트가 **같은 인자 + `approval_id`** 로 재호출 → 1회 실행. 다른 전압·다른 포트로는 그 승인이 쓰이지 않고,
   **다시 연결(같은 포트 재사용 포함)한 뒤에도 쓰이지 않는다** — 승인 지문에 연결마다 새로 만드는 토큰이 들어가므로
   보드를 바꾼 뒤 예전 승인으로 전압이 걸리는 일이 없다(재측정·재승인 필요). 스캔 승인(`modify_policy: approve`)도 같다.

입력 검증은 게이트 전에 한다: 0.1 V 단위가 아닌 값(예: 1.85)이나 범위 밖 값은 승인 요청 없이 바로 거부된다(반올림하지 않음).

---

## 4. 권장 흐름

```
jtagulator_connect(case_id, "/dev/ttyUSB0")
  → (사람: 타깃 I/O 전압 측정) → jtagulator_set_voltage(case_id, 3.3)   # 승인 필요
  → (사람: 타깃 전원 ON)
  → jtagulator_gpio_read(case_id, samples=10)                            # 수동: LOW 고정/활동 채널 가늠
  → jtagulator_uart_txd_scan(case_id, 0, 7, duration_seconds=30)        # 수동, 이때 타깃 재부팅하면 좋음
  → jtagulator_uart_scan(case_id, 0, 7, known_pins={"txd": N})          # RXD 탐색 (프로브 CR)
  → jtagulator_jtag_scan(case_id, 0, 7)  또는  jtagulator_idcode_scan → jtagulator_bypass_scan(known_pins={tdo,tck,tms})
  → jtagulator_get_device_ids / jtagulator_bypass_test 로 확인
  → (사람: 타깃 전원 OFF) → jtagulator_disconnect(case_id)
```

스캔은 즉시 `job_id` 를 돌려준다. `jtagulator_job_status(job_id, wait_seconds=30)` 로 폴링하면 `progress`(진행 표시 `-` 와
순열 수로 계산), `eta_seconds`, 끝나면 `result` 를 받는다. 결과의 `summary.best` 가 가장 그럴듯한 핀아웃이고, `summary.notes` 에
다음 단계 힌트가 있다. 여러 핀아웃이 나오면 오탐이 섞일 수 있으니 사람이 확인한다.

### UART 프로브 문자열(text)
`jtagulator_uart_scan` 은 후보 RXD 핀마다 보드레이트 21개(300–307200)로 `text` 를 보낸다. 맞는 핀·보드레이트에서는
대상 콘솔이 이 문자열을 **여러 번** 받는다(줄 끝 없는 꼬리가 다음 송신의 첫 줄과 이어질 수 있으므로 두 번 이어 붙인 입력까지 검사한다 — 예: `_erase X\rflash` → `flash_erase X`). 그래서 서버는 `text` 를 U-Boot/Linux 콘솔 분류기로 검사해 위험한 명령
(예: `sf erase …`, `saveenv`)이면 승인 요청 없이 거부한다. 기본값 `"\r"`(CR) 을 권장한다. 단 CR 하나는 코어 분류기에서 INTERACT(`uboot.empty`)이지만,
대상이 U-Boot 프롬프트에 머물러 있으면 맞는 핀·보드레이트에서 빈 Enter 가 되어 직전 명령을 반복한다(uart-mcp 는 같은 Enter 를 직전 명령을 모르면 `uart.repeat-unknown` 으로 거부한다).
그래서 수동 TXD 스캔(`jtagulator_uart_txd_scan`)을 먼저 쓰고, UART 스캔은 대상이 U-Boot 프롬프트에 있지 않을 때 한다([안전 가이드](../../docs/safety.md) §3.4). 서버는 항상 hex 형식(`\x0D`)으로
입력해 정확히 그 바이트만 보낸다(최대 16바이트, CR 자동 추가 없음). 백슬래시 이스케이프(`\r` `\n` `\xHH` `\\`)를 해석하므로
JSON 에서 이중 이스케이프(`"\\r"`)해도 CR 이 된다 — 응답의 `text_hex` 로 실제 바이트를 확인한다. 잘못된 보드레이트에서는 대상이
임의 바이트를 받으므로 셸이 열린 기기에서는 수동 TXD 스캔을 먼저 쓴다.

### 핀 이름 (UART)
JTAGulator 의 UART 핀 이름은 **타깃 기준**이다. TXD = 타깃이 송신하는 핀(USB-UART 의 RX 에 연결),
RXD = 타깃이 수신하는 핀(USB-UART 의 TX 에 연결).

---

## 5. 스캔 시간 (순열)

순열 수 = n! / (n − r)! (n = 스캔 채널 수 − 알려진 핀 수, r = 찾을 핀 수). 장치가 스캔 시작 전에
`Possible permutations: N` 으로 같은 값을 출력하며, 서버는 이 값이 요청과 다르면 시작 전에 취소한다.

| 채널 수 | r=1 (TXD) | r=2 (UART) | r=3 (IDCODE) | r=4 (BYPASS/Combined 표시값) |
|---|---|---|---|---|
| 8 (CH0–7) | 8 | 56 | 336 | 1,680 |
| 16 | 16 | 240 | 3,360 | 43,680 |
| 24 (전체) | 24 | 552 | 12,144 | 255,024 |

**실제 순열당 소요 시간은 실측되지 않았다**(레퍼런스 §18). 아래는 펌웨어 코드와 문서화된 JTAG 클럭 상한(25 kHz, CHANGES 1.9)으로
계산한 **하한**이다 — 실제는 더 길다. 도구 응답의 `lower_bound_seconds` 도 같은 계산이며, 진행 중에는 job 의 `eta_seconds`
(실제 진행률 기반)를 본다.

| 스캔 | 순열당 하한 근거 | 8채널 | 16채널 | 24채널 | `pins_low=true`(100+100 ms), 24채널 |
|---|---|---|---|---|---|
| IDCODE | ≈47 TCK ≥ 1.9 ms | ≥ 1초 | ≥ 6초 | ≥ 23초 | ≥ 41분 |
| BYPASS | ≈1100 TCK ≥ 44 ms | ≥ 74초 | ≥ 32분 | ≥ 3.1시간 | ≥ 17시간 |
| UART (delay 10 ms) | 보드레이트 21 × (10+delay+20 ms) | ≥ 51초 | ≥ 3.7분 | ≥ 8.4분 | ≥ 10분 |
| Combined | IDCODE 와 비슷 (+ IDCODE 가 나온 순열에서 TDI 후보마다 BYPASS 시험) | | | | |

실무 팁: 연결한 채널만 범위에 넣는다. BYPASS 를 전체 채널로 돌리지 말고 IDCODE/Combined 로 TDO/TCK/TMS 를 찾은 뒤
`known_pins` 로 TDI 만 찾는다(예: CH0–7 에서 3개 고정 → 5순열). UART 는 TXD 스캔으로 TXD 를 먼저 찾고 `known_pins={"txd": N}`.

---

## 6. 안전 설계 요약

- 하드웨어 도구는 `rt().case(case_id, hardware=True)` 로 소유/허가 증명을 강제한다(`jtagulator_disconnect` 는 정리 작업이라 예외).
- 도구는 보낼 **키 계획 전체**(메뉴 키, 모든 대화 답, 스페이스바)를 JTAGulator 분류기(`classify.py`)로 분류해
  `rt().authorize(...)` 를 통과한 뒤에만 장치에 쓴다. 승인 지문(action)은 포트 + 스캔 종류/채널/옵션(타임아웃 제외)이다.
- **드라이버 가드**: 모든 송신 직전 *실제 장치 상태*(수신 버퍼 끝의 프롬프트)로 다시 분류해, INTERACT 를 넘는 키는 승인된
  계획에 같은 (상태, 위치, 키) 단계가 있을 때만 1회 보낸다. 예: 상태가 어긋나 채널 번호를 전압 프롬프트에 답하려 하면 차단된다.
  `V` 키 자체도 DESTRUCTIVE 로 분류되어 `jtagulator_set_voltage` 의 승인된 계획 밖에서는 전압 대화에 들어갈 수 없다.
- 대화는 lock-step(프롬프트가 완전히 도착하고 조용해진 뒤 답함). 알 수 없는 질문이 나오면 Ctrl-X 로 취소하고 오류.
- 스캔 대화(채널·옵션·스페이스바)는 **도구 호출 안에서** 게이트 통과 직후 보낸다. 백그라운드 작업은 출력 감시와
  중단 키(LF 1바이트, INTERACT)만 보내며, 시작 전에 그 계획이 INTERACT 이하인지 확인한다.
- 스캔은 이 연결에서 장치가 전압 설정을 확인(`New target I/O voltage set`)한 경우에만 시작한다. 장치가 리셋된 흔적
  (`Target I/O voltage must be defined!`, 스캔 중 배너)이 보이면 전압 상태를 버린다.
- 실행 중인 스캔에는 중단 키 외에 아무것도 보내지 않는다(어떤 바이트든 스캔을 중단시킴). 스캔 중 다른 도구는 Busy.
- 서버 종료 시(atexit) 실행 중 스캔을 중단하고 포트를 닫는다.

---

## 7. 산출물 (케이스 디렉터리)

| 경로 | 내용 |
|---|---|
| `jtag/jtagulator-<n>.log` | 연결 세션 원시 기록. 한 줄 = `<UTC 시각> <RX\|TX\|--\|#> <JSON 문자열>` (latin-1 바이트를 손실 없이 이스케이프) |
| `jtag/jtagulator-<n>-<scan>-<k>.log` | 스캔 하나의 원시 수신 바이트(대화 에코 포함, 그대로) |
| `jtag/jtagulator-<n>-<scan>-<k>.json` | 스캔 결과 (`pweh.jtagulator-scan/v1`): 상태, 옵션, 순열, `summary`(핀아웃/IDCODE 해석/UART 후보), 송신 키 목록 |
| `jtag/jtagulator-<n>-device-ids-<k>.{log,json}`, `…-bypass-test-<k>.{log,json}`, `…-gpio-<k>.{log,json}` | `D`/`T`/GPIO `R` 결과 |

모두 `kind="other"` 아티팩트로 등록된다. 종류는 설명과 `extra.type`(`session-transcript`, `scan-raw`, `scan-result`, `device-ids`,
`bypass-test`, `gpio-read`)에 표시한다. `docs/architecture.md` §3 의 kind 어휘에는 핀아웃 스캔 기록용 `jtag-scan` 이 있지만 이 서버는 아직
`other` 를 쓴다. 안전 결정과 장치 조작은 케이스 `audit.jsonl` 에 남는다.

IDCODE 해석: 버전/파트/제조사(JEP106 bank·ID·원시 코드)와 선별 제조사 이름, 잘 알려진 파트 설명(예: `0x4BA00477` = ARM CoreSight
JTAG-DP, `0x07926F0F` = ARM926EJ-S). OpenOCD 스크립트 디렉터리(`tools.openocd_scripts`/`PWEH_OPENOCD_SCRIPTS`)가 있으면 같은
IDCODE 를 기대값으로 쓰는 cfg 파일 목록(`openocd_configs`)도 붙인다 — 범용 ARM DAP IDCODE 는 SoC 를 특정하지 못한다.

---

## 8. 시뮬레이터 (테스트·데모)

`jtagulator_mcp/sim.py` 는 펌웨어 메뉴 상태 기계를 Spin 소스에서 옮긴 시뮬레이터다(FW 1.12/1.11.1/1.10 문구 차이,
에코 규칙, y/N 기본값 기억, 순열 순서와 진행 표시 주기, 중단, 영속 모드 종료, 리셋 모델). 문자열은 드라이버와 **독립적으로**
옮겨 적었다.

```bash
# TCP (pyserial URL 로 접속: socket://127.0.0.1:7777)
python -m jtagulator_mcp.sim --tcp 127.0.0.1:7777 --jtag 3,2,0,1 --trst 5 --idcode 0x4BA00477 --uart 6,7,115200
# PTY (출력된 /dev/pts/N 을 port 로 사용)
python -m jtagulator_mcp.sim --pty --firmware 1.11.1 --time-scale 0.05
```

`--jtag TDI,TDO,TCK,TMS`, `--uart TXD,RXD[,BAUD]` 로 '진짜 핀아웃'을 정하면 그 순열에서만 결과가 나온다(잘못된 보드레이트에서는
깨진 바이트). `--time-scale` 은 펌웨어 지연 모델 배율, `--start ocd|sump` 는 영속 모드 부팅, `--reset-on-connect` 는 DTR 리셋 모델.
`--tcp` 는 IPv4 루프백 주소에만 바인드한다(IPv6 주소는 거부). `--tcp 0.0.0.0:N` 같은 주소는 `--allow-lan` 없이는 거부(종료 코드 2)하고, 있으면 stderr 로
LAN 노출을 경고한다(인증 없는 시리얼 — 브리지 모드 WSL 이면 LAN 전체). 그때도 서버에는 `socket://127.0.0.1:N` 으로 접속한다
(서버는 루프백 URL 만 받는다).

테스트: `tests/servers/test_jtagulator_units.py`(분류기·파서·JEP106), `test_jtagulator_sim.py`(드라이버↔시뮬레이터, TCP/PTY,
펌웨어 방언, 가드, 취소, 리셋/끊김), `test_jtagulator_mcp.py`(MCP 도구, 승인 흐름, job, 아티팩트, stdio).

---

## 9. 문제 해결

| 증상 | 확인 |
|---|---|
| `메뉴 프롬프트를 찾지 못했습니다` | 포트/권한(`dialout`), 다른 프로그램(터미널, sigrok)이 포트 점유, 115200. 장치를 껐다 켜거나 리셋 버튼 |
| 연결 시 `persistent_mode_exited` 경고 | JTAGulator 가 OpenOCD/로직 분석기 영속 모드였다. 빠져나와도 VADJ 에 이전 전압이 남을 수 있으니 전압을 다시 설정 |
| 재연결 후 스캔이 `voltage_not_set` | 정상 — 포트 열기(DTR)로 리셋되었을 수 있어 매 연결마다 전압을 다시 설정해야 한다 |
| 결과 없음 | GND 공통 연결, 채널 범위, 전압, 타깃 전원, JTAG 비활성(퓨즈) 가능성. UART 는 보드레이트가 표(≤307200)에 없을 수 있음 → TXD 스캔 |
| 결과가 여러 개 | 타깃이 엉뚱하게 응답한 오탐 가능. `jtagulator_bypass_test`/`get_device_ids` 로 확인, 사람 검토 |
| `device_stalled` | 장치 출력이 끊김(리셋/USB). 다시 연결하고 전압 재설정 |
