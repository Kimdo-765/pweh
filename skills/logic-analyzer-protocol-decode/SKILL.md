---
name: logic-analyzer-protocol-decode
description: Capture and decode UART/SPI/I2C board signals with a sigrok logic analyzer through the pweh-sigrok MCP server, for authorized/owned devices only. Use it to find an unknown UART TX pad and baud rate, to check whether a silent console really emits nothing, to sniff SPI-flash reads at boot (JEDEC ID, read addresses), or to watch I2C EEPROM traffic. It then hands the TX pad and baud to uart-shell-acquisition. Capture is passive and input-only; output-capable sigrok devices are refused. Triggers - logic analyzer, sigrok, PulseView, fx2lafw, Saleae clone, DSLogic, baud rate detection, UART pinout, TX pin, SPI flash sniffing, I2C EEPROM, protocol decode, 로직 애널라이저, 신호 캡처, 프로토콜 디코딩, 보드레이트 추정, UART 핀 찾기, TX 패드, SPI 플래시 스니핑, I2C EEPROM.
---

# logic-analyzer-protocol-decode: 로직 애널라이저로 UART/SPI/I2C 캡처와 디코딩

## 목적

소유 기기나 서면 허가를 받은 기기의 보드 신호를 로직 애널라이저(LA)로 **수동 캡처**하고, sigrok 디코더로 해석한다. 결과는 연구·방어용이다(공격 페이로드나 제3자 시스템 공격 없음).
보드 신호 캡처는 입력 전용이다. 시리얼형 계측기 탐색은 OLS reset·ID·metadata 같은 제어 바이트를 보내므로 계측기 포트를 정확히 고른다. 배선과 전원 재투입은 사람이 한다.

결과물은 넷이다.
1. **UART TX 패드, 보드레이트, 프레임, 극성.** 다음 Skill `uart-shell-acquisition` 이 이 값을 입력으로 쓴다.
2. **SPI 플래시 부팅 읽기 관찰.** JEDEC ID 와, 부트로더가 읽는 주소·길이.
3. **I2C EEPROM 트래픽.** 장치 주소와 읽고 쓴 바이트.
4. **summary 기록.** `signal-capture` 스키마를 따른다.

## 언제 쓰나

| 상황 | 얻는 것 |
|---|---|
| UART 패드 위치나 보드레이트를 모른다 (master-prompt §4 Phase A) | 부팅 중 활동하는 채널(= 대상 TX), 보드레이트, 8N1 여부, 극성 |
| USB-UART 에 아무것도 안 보이거나 깨진 문자만 나온다 (이전 summary 의 console_type 이 `silent`) | 패드가 실제로 토글하는가. 원인 구분: 어댑터·배선 / 보드레이트 / 전압 레벨 |
| 부팅 중 SPI NOR 읽기를 관찰하고 싶다 | RDID 로 칩 식별, 처음 읽는 오프셋으로 파티션 배치 추정 |
| I2C EEPROM(24Cxx) 접근을 보고 싶다 | 장치 주소, 읽고 쓴 바이트(설정, MAC, 시리얼 등) |

**쓰지 않을 때**
- UART 패드와 보드레이트를 이미 안다. 바로 `uart-shell-acquisition` 으로 간다.
- 펌웨어 전체를 확보하려고 한다. SPI 스니핑은 덤프가 아니다. 부팅 중 읽힌 부분만 보이고 dual/quad I/O 구간은 복원되지 않는다. `firmware-dump-via-uart` 를 쓰거나 SPI 클립으로 직접 읽는다(docs/hardware-setup.md §6).
- 신호가 LA 한계를 넘는다. samplerate 는 신호 클럭의 4배 이상이어야 하므로 fx2lafw(최대 24 MHz)는 약 6 MHz 이하만 믿을 수 있다. 카메라 SoC 의 SPI NOR 클럭은 보통 이보다 빠르다.
- 전압 조건이 맞지 않는다: 1.8 V 인데 레벨 시프터나 임계 조절 LA 가 없다, RS-232(±12 V)다, 아직 전압을 재지 않은 핀이다.
- 소유/허가가 기록된 케이스가 없다.

## 전제 조건

- **case_id**: 케이스에 소유/허가 증명이 있어야 한다. 없으면 서버가 하드웨어 도구를 거부한다(master-prompt §1-1).
- **이전 요약**: `case_get_step_results(case_id="<id>")` 로 읽는다.
  - `uart-shell-acquisition` 요약의 data.console_type(`silent`/`boot-log-only`), data.baudrate, data.notes 를 보고 무엇을 확인할지 정한다.
  - 이전 `logic-analyzer-protocol-decode` 요약이 있으면 이미 찾은 채널과 보드레이트를 재사용한다.
  - 선택: `pipeline_profile(name="<profile>")` 의 보드레이트 후보로 추정값을 교차 확인한다.
- **사람이 준비할 장비**: LA(fx2lafw 계열 8ch 24 MHz "Saleae 클론", DSLogic 등), 훅 클립과 점퍼선, 멀티미터, SPI 를 볼 때는 SOIC-8 클립(LA 에만 연결).
  대상 전원을 사람이 직접 껐다 켤 수 있어야 한다. DC 잭 구성을 권장한다.
- **WSL2**: Linux USB 캡처에는 `usbipd attach` 가 필요하다. fx2lafw 는 펌웨어 업로드 뒤 재열거되므로 attach 를 다시 해야 할 수 있다. Windows OLS COM scan/show만 별도 지원하며 Windows 캡처는 아직 지원하지 않는다.
- **sigrok-cli**: `sigrok_version()` 이 tool_missing 이면 설치 힌트를 전달한다(`. ~/pweh-tools/env.sh` 또는 `apt install sigrok-cli`).
  이미 있는 캡처 파일은 sigrok-cli 없이도 분석된다: `sigrok_file_info`, `sigrok_estimate_baud`, `sigrok_uart_autodecode(engine="python")`.

## 안전 규칙

master-prompt §1 과 docs/safety.md §2.3·§2.5·§7 을 따른다. 이 Skill 에서 특히 지킬 것:

1. **소유/허가가 먼저다.** 소유/허가가 기록된 케이스 없이는 `sigrok_device_info`, `sigrok_capture`, 시리얼/네트워크 conn 을 쓰는 `sigrok_scan` 을 호출하지 않는다.
2. **입력 전용이다.** 서버는 출력 가능 장치(전원공급기, 전자부하, 신호발생기, 릴레이, baylibre-acme), 허용 목록 밖 드라이버, samplerate/captureratio 외 설정을 **게이트 없이** 거부한다.
   응답은 `ok: false`, `status: denied`, `gate.via: sigrok-policy` 다. 다른 드라이버 이름으로 재시도하지 않고, `orchestrator/pipeline-config.yaml` 을 고치지 않고, 사용자에게 보고한다(T6).
3. **전기 안전.** GND 를 먼저 연결하고 프로브는 마지막에 붙인다. 연결 전에 사람이 멀티미터로 신호의 idle 전압을 잰다.
   fx2lafw 입력은 −0.5~5.25 V, 임계 VIH 2.0 V / VIL 0.8 V 이므로 3.3 V·5 V TTL 만 직접 연결한다. VCC 레일, PoE 48 V, AC 입력 DVR 의 SMPS 근처에는 프로브를 대지 않는다.
4. **SPI 클립.** 전원을 끈 상태에서 물리고, LA 에만 연결한다. 프로그래머(CH341A 등)와 클립의 VCC 핀은 연결하지 않는다(역전원, safety.md §2.5).
5. **물리 작업은 사람이 한다.** 아래 템플릿처럼 구체적으로 요청하고, "완료" 전에는 진행하지 않는다.
6. **시리얼형 LA(OLS 등).** conn 이 대상 콘솔 포트가 아닌지 확인한다. OLS scan/show는 reset 5회·질의와 포트 열기를 하므로 MODIFY이며 DTR/RTS LOW도 보장하지 않는다. 다른 프로세스가 포트를 열고 있거나 Windows 정리가 미확인이면 서버가 거부한다. 우회하지 않는다.
7. **긴 캡처는 job 으로.** 사용자가 멈추라고 하면 즉시 `sigrok_job_cancel` 을 호출한다. 부분 캡처는 `<name>-partial.sr` 로 보존된다.
8. **민감 정보.** EEPROM·SPI 데이터에 비밀번호, 키, Wi-Fi 정보가 있을 수 있다. 요약과 대화에는 마스킹해서 싣고 원문은 케이스 파일에만 둔다.
9. **확인과 추측을 구분한다.** 예: "TX = J3-2 (confidence 0.999, 부팅 배너로 확인)" 과 "J3-3 = RX (추정)".
10. **OLS 조회의 승인 게이트.** Linux/Windows의 OLS+명시 직렬 scan/show는 기존 `modify_policy`를 따른다.
    `approval_required`이면 위험과 승인 ID를 설명하고 사람이 별도 터미널에서 `pweh approve <id>`로 승인한 뒤 같은 인자에 `approval_id`를 붙여 재호출한다. 규칙 2의 정책 거부에는 승인 경로가 없다.
    어떤 경우에도 에이전트가 `pweh approve` 를 실행하거나 승인 파일·설정을 고치지 않는다(master-prompt §1-2).

## 사용하는 MCP 도구

| 도구 | 목적 |
|---|---|
| `case_get`, `case_get_step_results`, `pipeline_profile` | 권한, 이전 요약, 보드레이트 후보 확인 |
| `sigrok_version`, `sigrok_list` | sigrok-cli 버전, 드라이버·디코더 목록(drivers 에 capture_allowed 표시) |
| `sigrok_scan` | 연결된 LA, 채널 이름, capture_allowed |
| `sigrok_device_info` | 지원 samplerate(목록 또는 범위), 트리거 문자 |
| `sigrok_capture` | 캡처 → `signals/<name>.sr` 저장, 아티팩트 등록 |
| `sigrok_job_status`, `sigrok_job_cancel`, `sigrok_jobs` | 백그라운드 캡처·디코드 폴링과 취소 |
| `sigrok_file_info` | 채널별 활동(edges, high_ratio, initial_level, final_level), `uart_candidates[]` |
| `sigrok_estimate_baud` | 보드레이트, confidence, idle_level(극성), segments, per_channel |
| `sigrok_uart_autodecode` | UART 자동 디코드: text_preview, boot_hints, `data.uart_estimate` 에 넣을 값 |
| `sigrok_decoder_help` | 디코더의 채널·옵션·annotation 이름(버전마다 다르므로 여기서 확인) |
| `sigrok_decode` | 스택 지정 디코드(uart / spi,spiflash / i2c,eeprom24xx) → `signals/*.txt` |
| `sigrok_export` | PulseView/GTKWave 용 VCD 변환 |
| `inspect_signal_decoders`, `decode_signal_recording` (rea) | 대안 디코드, 교차 확인 |
| `case_add_note`, `case_update_target`, `case_add_finding`, `case_record_step`, `case_set_phase` | 기록 |

## 절차

예시의 케이스 ID 는 `20261018-acme-ipc` 다. 도구 응답의 `next_steps`/`message` 힌트도 함께 읽는다.

### 1. 케이스와 목표 확인

1. `case_get(case_id="20261018-acme-ipc")` 로 소유/허가 증명을 확인한다. 없으면 멈추고 master-prompt §1-1 로 돌아간다.
2. `case_get_step_results(case_id="20261018-acme-ipc")` 로 이전 요약을 읽는다.
3. 목표를 고른다: **A** UART TX·보드레이트 찾기, **B** silent 콘솔 확인, **C** SPI 플래시 관찰, **D** I2C EEPROM 관찰. 목표가 여럿이면 캡처를 목표마다 따로 한다.

### 2. 도구와 장치 확인

```text
sigrok_version()
sigrok_scan()                                   # 인자 없음 = USB 자동 탐지, case_id 불필요
sigrok_device_info(case_id="20261018-acme-ipc", driver="fx2lafw")
```

Windows의 OLS 조회는 소유/허가 케이스와 확인한 계측기 COM을 사용해 `sigrok_scan(case_id=…, driver="ols", conn="COMn", backend="windows")` 또는 `sigrok_device_info`를 호출한다. `COMn`은 실제 번호로 바꾼다. scan/show에만 지원하며 Windows 캡처나 자동 Linux fallback으로 이어가지 않는다. 상세 범위는 `docs/references/windows-sigrok-com.md`를 본다.

- `sigrok_scan` 응답은 `devices[{driver, conn, description, channels, capture_allowed}]` 다. capture_allowed 가 false 인 장치는 쓰지 않는다.
  드라이버별 허용 여부는 `sigrok_list(kind="drivers")` 의 capture_allowed·output_capable 로도 볼 수 있다.
- 장치가 없으면(count 0, note) 사람에게 USB, usbipd attach, udev 권한을 확인하게 한다(T1). fx2lafw 는 첫 스캔에서 펌웨어를 올린 뒤 재열거되므로 몇 초 뒤 다시 스캔한다.
- `sigrok_device_info` 에서는 samplerate 목록(`samplerates`, fx2lafw 는 20 kHz…24 MHz)이나 범위(`samplerate_range`), `triggers`(`0 1 r f e`), 채널 이름(fx2lafw D0..D7, DSLogic 0..15)을 본다.
- **연습(하드웨어 없음)**: driver 를 `"demo"` 로 쓴다. demo 신호는 UART 가 아니므로 캡처 → job → 파일 → file_info 흐름만 연습한다.
  **실측(libsigrok 0.5.2)**: demo 에 triggers 를 주면 트리거 뒤 약 4096 샘플만 저장된다("요청한 샘플(…)보다 적게 받음" 경고). 또 demo 는 실시간보다 느리게 생성해서(2 MHz × 15 s → 58 s, 8 MHz × 3 s → 37 s) 서버 제한 시간(예상 + 30 s)을 넘기 쉽다.
  그래서 demo 연습은 트리거 없이 `samplerate="1m", duration_ms=1000` 정도로 짧게 한다.

### 3. 채널 매핑과 배선

- 채널은 **0번부터 연속으로** 고르고 이름만 바꾼다. 비연속 선택은 일부 드라이버에서 비트 위치가 어긋난다.
  새 이름 규칙은 `^[A-Za-z][A-Za-z0-9_]{0,31}$` 이다. `J3-2` 는 거부되고 `J3_2` 는 된다.
- **UART 핀 모름**: 패드 이름으로 짓는다. 예: `["D0=J3_2","D1=J3_3"]`. GND 로 확인된 패드는 LA GND 에 연결하고, 늘 일정한 전압인 패드(VCC)에는 물리지 않는다.
- **UART 핀 앎**: `["D0=RX","D1=TX"]`. `RX` 채널 = **대상의 TX 신호**(LA 가 받는 쪽, uart 디코더의 `rx`).
- **SPI**: `["D0=CS","D1=CLK","D2=MOSI","D3=MISO"]`. **I2C**: `["D0=SCL","D1=SDA"]`.
- 채널마다 실제 패드·칩 핀 이름을 적어 둔다. summary 의 capture.channels[].pin_label 에 들어간다.
- 배선은 사람에게 요청한다: UART 는 T2, SPI 는 T4, I2C 는 T5.

### 4. samplerate 와 길이 정하기

- samplerate 는 신호 비트레이트나 클럭의 **4배 이상**, 권장은 **10배**다. 비트당 4샘플 미만이면 추정기가 경고한다.
  - 보드레이트를 모르면 **8 MHz** 로 시작한다(921600 bps 까지 8.7배). 115200 bps 로 확정됐으면 2 MHz 면 된다.
  - SPI 는 SCK 의 4배 이상, I2C 400 kHz 는 4 MHz 이상. 전체 표는 [reference.md §1](reference.md#1-samplerate-선택).
  - `sigrok_device_info` 목록에 있는 값만 쓴다. `"8m"`, `"24MHz"`, `"500k"` 를 받는다(소문자 m = MHz, 서버가 정수 Hz 로 변환).
- 길이: 핀·보드레이트 찾기는 15~20 s(U-Boot 배너는 전원 투입 후 수 초 안에 나온다). SPI 부팅 초기 읽기는 트리거 뒤 1~3 s 이고, 트리거 없이 찍으면 사람의 전원 투입 지연(3~5 s)까지 포함해 10 s 이상이다.
  `duration_ms` 와 `samples` 중 **정확히 하나**만 준다.
- 압축 전 데이터량은 samplerate × 길이 × ⌈채널 수/8⌉ 바이트다(8 MHz × 20 s ≈ 160 MB). 크면 디코드가 job 으로 넘어가고, `activity_truncated` 가 true 면 활동 분석이 잘린 것이다.

### 5. 캡처: 캡처를 먼저 시작하고 전원은 그다음에

부트 로그는 전원을 넣은 직후에만 나온다. 그래서 **캡처를 먼저 시작**한다.

1. 사람에게 타이밍을 먼저 알리고, 대상 전원이 꺼져 있는지 확인받는다(T3).
2. 캡처를 시작한다. 두 방식 모두 job 으로 돌고 `{"ok": true, "status": "started", "job_id": "job-…", "planned_path": "signals/<name>.sr"}` 를 즉시 돌려준다.
   - **(a) 기본: 트리거 없는 백그라운드 캡처.** 핀을 모르거나 여러 채널을 볼 때.
     ```text
     sigrok_capture(case_id="20261018-acme-ipc", driver="fx2lafw", samplerate="8m", duration_ms=20000,
                    channels=["D0=J3_2", "D1=J3_3"], background=true, output_name="uart-pads-boot")
     ```
     `background=true` 를 꼭 준다. 20 s 이하 캡처는 기본이 동기 호출인데, 동기 호출 중에는 "지금 전원" 이라고 말할 수 없다.
   - **(b) TX 채널을 알 때: 첫 하강 에지 트리거.** pre-trigger 1% 만 저장해 idle 구간을 줄인다.
     ```text
     sigrok_capture(case_id="20261018-acme-ipc", driver="fx2lafw", samplerate="8m", duration_ms=15000,
                    channels=["D0=RX", "D1=TX"], triggers="RX=f", capture_ratio=1, output_name="uart-boot")
     ```
     트리거는 rename 뒤 이름(`RX`)으로 쓴다. 문자는 `0 1 r f e` 이고, idle-low 라인이면 `r` 을 쓴다.
     트리거 캡처의 기본 제한 시간은 예상 시간 + 60 s 다. 전원 투입이 늦어질 것 같으면 `timeout_s` 를 늘린다.
3. `started` 를 받으면 "지금 전원을 넣어 주세요" 라고 말한다. (a) 에서는 3~5 s 뒤에 넣게 한다. fx2lafw 는 처음 쓸 때 펌웨어 업로드와 재열거로 몇 초가 걸린다.
4. `sigrok_job_status(job_id="job-…", wait_seconds=30)` 을 `status` 가 `succeeded` 가 될 때까지 반복한다(wait_seconds ≤ 50).
   `result` 는 동기 캡처와 같은 dict 다: `path`, `absolute_path`, `samplerate`(정수), `samples`, `duration_s`, `channels`, `activity[]`, `warnings[]`, `next_steps`.
5. 결과를 확인한다.
   - `result.samples` 가 요청(samplerate × 길이)보다 크게 적거나 warnings 에 "요청한 샘플(…)보다 적게 받음" 이 있으면 USB 대역폭이나 버퍼 한계다. samplerate 를 낮춘다. 트리거 캡처였다면 (a) 로 다시 캡처한다.
   - `activity` 에 에지가 있는 채널이 있으면 6단계로 간다.

| 실패 응답 | 조치 |
|---|---|
| job `failed`, error 에 "트리거 조건(…)이 N초 동안 발생하지 않음" | 채널 매핑, GND, 극성(`f`↔`r`), 전원을 실제로 넣었는지 확인하고 (a) 로 재캡처 |
| job `failed`, "…초 안에 끝나지 않아 종료함" (timeout) | 부분 캡처(`<name>-partial.sr`)가 보존된다. 그 파일로 6단계를 진행하거나, samplerate 를 낮추거나 `timeout_s` 를 늘려 재캡처 |
| 도구 오류 `[validation_failed] …` + 힌트 | 힌트대로 고친다(duration_ms/samples 중 하나만, rename 뒤 이름으로 트리거, rename 규칙) |
| `Busy` (장치 사용 중) | `sigrok_jobs(active_only=true)` 로 확인. 끝날 때까지 기다리거나 취소 |
| `no_device`, "No devices found" | USB, usbipd attach, udev 권한 확인(T1) |
| `status: denied` (sigrok-policy) | 안전 규칙 2. 우회하지 않고 보고(T6) |
| 사용자가 중지 요청 | `sigrok_job_cancel(job_id="job-…")` → 결과의 `partial.path` 기록 |

### 6. 채널 활동 확인

```text
sigrok_file_info(case_id="20261018-acme-ipc", input_path="signals/uart-pads-boot.sr")
→ activity [{"name":"J3_2","edges":1276,"high_ratio":0.634,"initial_level":1,"final_level":1},
            {"name":"J3_3","edges":0,"high_ratio":1.0,"initial_level":1,"final_level":1}],  uart_candidates ["J3_2"]
```

- 에지가 많고 처음/끝 레벨이 1 → idle-high UART TX 후보 → 7단계. 처음/끝 레벨이 0 → 반전 라인 후보.
- 에지 0 + high_ratio 1.0 → 풀업된 입력(대상 RX 후보) 또는 VCC. 에지 0 + 0.0 → GND, 미연결, 전원 꺼짐.
- 모든 채널이 에지 0 → 프로브와 GND, 캡처 시점(캡처 전에 전원을 넣었나), 1.8 V 레벨을 확인하고 재캡처. 두 번 연속 0 이면 목표 B 의 결론으로 간다.
- 여러 채널이 동시에 바쁘다 → SPI/I2C 같은 다른 버스이거나 노이즈. 9·10단계 디코더로 확인한다.
- 전체 증상표: [reference.md §4](reference.md#4-해석과-문제-해결).

### 7. UART: 보드레이트·극성 추정과 디코드 (목표 A)

**7-1. 추정**
```text
sigrok_estimate_baud(case_id="20261018-acme-ipc", input_path="signals/uart-pads-boot.sr")   # channel 생략 = 활동 채널 자동 평가
→ {"channel":"J3_2","baudrate":115200,"baudrate_raw":115214.455,"confidence":0.999,"idle_level":1,"inverted":false,
   "samples_per_bit":69.436,"per_channel":[…],"warnings":[],"suggested_decoder":"uart:rx=J3_2:baudrate=115200","recommended_samplerate":"2 MHz"}
```
- confidence ≥ 0.9 이고 warnings 가 없으면 7-2 로 간다.
- confidence < 0.5, samples_per_bit < 4, "4배 미만" 경고 중 하나라도 있으면 더 높은 samplerate 로 재캡처하고 이 값은 넘기지 않는다.
  실측: 115200 bps 를 400 kHz 로 캡처하면 115200 에 스냅되지만 confidence 0.49 에 경고가 붙는다.
- idle_level 0 이면 반전 라인이므로 디코드에 `invert_rx=yes` 를 쓴다. 단, 6단계에서 처음/끝 레벨이 1 이었다면 오판일 수 있다(실측: 짧은 BootROM 구간에 다른 보드레이트가 섞인 캡처). 7-4 로 확인한다.
- `segments[]` 의 baudrate 가 서로 다르면 7-4. `baudrate` 가 null 이면 에지 부족이나 노이즈이므로 채널과 캡처를 다시 본다.

**7-2. 자동 디코드**
```text
sigrok_uart_autodecode(case_id="20261018-acme-ipc", input_path="signals/uart-pads-boot.sr", channel="J3_2")
→ {"ok":true,"engine":"sigrok-cli","decoder":"uart:rx=J3_2:baudrate=115200:data_bits=8:parity=none:format=hex",
   "framing_errors":0,"printable_ratio":1.0,"text_preview":"\nU-Boot 2016.11 (Jan 01 2020 - 00:00:00 +0000)\n…",
   "boot_hints":[{"kind":"uboot_banner",…},{"kind":"autoboot_prompt","match":"Hit any key to stop autoboot:  1"},…],
   "decode_text_path":"signals/uart-pads-boot.J3_2.uart-115200.txt","bytes_path":"signals/uart-pads-boot.J3_2.uart-115200.bin",
   "uart_estimate":{"channel":"J3_2","baudrate":115200,"confidence":0.999,"idle_level":1}}
```
- 성공: printable_ratio ≥ 0.9, framing_errors ≈ 0, boot_hints 에 U-Boot 배너·커널 버전·`login:` 등.
- 입력이 크면 `status: started` + `job_id` 가 온다. `sigrok_job_status` 의 `result` 에 같은 dict 가 들어 있다.
- 텍스트가 깨지면(printable_ratio < 0.7 경고) estimate 의 `candidates[].baudrate` 를 하나씩 `baudrate=` 로 지정해 본다.
  b 와 2b 를 둘 다 시도한다. run 이 모두 짝수 배인 데이터는 절반 보드레이트로 오인될 수 있다([reference.md §4](reference.md#4-해석과-문제-해결)).
- 프레임 오류가 많고 텍스트가 반쯤 맞으면 `data_bits=7, parity="even"`(7E1)을 시도한다.
- autodecode 는 극성을 추정값으로 고정한다(`baudrate` 만 덮어쓸 수 있다). 극성이 의심되면 7-3 에서 `invert_rx` 를 직접 지정한다.

**7-3. 명시 디코드 (양방향 확인, 극성 지정)**
```text
sigrok_decoder_help(decoder="uart")     # decoder.options / decoder.annotation_classes 로 이름 확인 (0.5.3 rx-warnings, master rx-warning)
sigrok_decode(case_id="20261018-acme-ipc", input_path="signals/uart-boot.sr",
              decoders=["uart:rx=RX:baudrate=115200:format=ascii", "uart:rx=TX:baudrate=115200:format=ascii"],
              annotations="uart=rx-data", max_lines=50)
→ {"output_path":"signals/uart-boot.uart.txt","lines":["uart-1: [0D]","uart-1: [0A]","uart-1: U",…],"lines_total":217,"instances":{"uart-1":217}}
```
- 방향마다 스택을 따로 만든다(`uart-1` = 첫 스택 = RX 선, `uart-2` = TX 선). 극성 지정은 스택에 `:invert_rx=yes` 를 붙인다.
- 채널 매핑은 필수이고 입력 파일의 채널 이름이어야 한다(틀리면 `[validation_failed] 채널 'D0' … 입력 파일에 없습니다`).
- `annotations` 는 항상 준다. 생략하면 모든 클래스가 나와 매우 길어진다.

**7-4. 보드레이트 혼재 (BootROM 과 U-Boot/커널의 속도가 다를 때)**
```text
sigrok_decode(case_id="20261018-acme-ipc", input_path="signals/uart-boot.sr",
              decoders=["uart:rx=RX:baudrate=57600:format=ascii", "uart:rx=RX:baudrate=115200:format=ascii"],
              annotations="uart=rx-data:rx-warnings", samplenum=true)
```
인스턴스별로 깨끗하게 읽히는 샘플 구간(`<ss>-<es> uart-N: …`)을 비교해 구간별 보드레이트를 정한다.
다음 단계로 넘길 값은 **콘솔 구간**(U-Boot 프롬프트, 커널, 셸)의 보드레이트다.

### 8. silent 콘솔 확인 (목표 B)

USB-UART 로 출력을 받지 못한 패드와 그 주변 후보 패드에 프로브를 물리고, 5(a) 로 캡처한 뒤 6단계로 활동을 본다.
- **활동하는 채널이 있다** → 콘솔은 살아 있다. 어댑터 쪽 원인(TX/RX 반대, GND, 보드레이트, 1.8 V 레벨, 반전)을 결론에 적고, 찾은 패드·보드레이트로 `uart-shell-acquisition` 을 다시 시도한다.
- **"Starting kernel ..." 뒤가 조용하다** → 커널 콘솔이 다른 UART 로 가거나 꺼졌다(bootargs 의 `console=`, `quiet`). U-Boot 인터럽트 경로를 결론에 적는다.
- **어떤 패드도 토글하지 않는다(재캡처 2회)** → 콘솔 비활성이거나 UART 패드가 아니다. 결론에 기록하고 master-prompt §4 의 대안(JTAG, JTAGulator, Phase B)으로 간다.

### 9. SPI 플래시 부팅 관찰 (목표 C)

1. T4 로 클립을 연결하게 한다. 전원을 넣기 전에 CS# 첫 하강 에지 트리거로 캡처를 시작하고, T3 처럼 전원을 넣게 한 뒤 5단계처럼 폴링한다.
   무전원일 때 CS# 는 0 V 이고 전원이 들어오면 HIGH 가 되므로 첫 하강 에지가 첫 트랜잭션이다. samplerate 는 장치 최대(fx2lafw `"24m"`)로 한다.
   `sigrok_capture(case_id=…, driver="fx2lafw", samplerate="24m", duration_ms=2000, channels=["D0=CS","D1=CLK","D2=MOSI","D3=MISO"], triggers="CS=f", capture_ratio=1, output_name="spi-boot")`
   `result.samples` 가 요청보다 크게 적으면 트리거 없이 `background=true, duration_ms=10000` 이상으로 다시 캡처한다(전원 투입 지연 포함, 24 MHz × 10 s ≈ 240 MB).
2. 디코드한다.
   ```text
   sigrok_decode(case_id="20261018-acme-ipc", input_path="signals/spi-boot.sr",
                 decoders="spi:clk=CLK:mosi=MOSI:miso=MISO:cs=CS,spiflash", annotations="spiflash=commands")
   → ["spiflash-1: Read identification (RDID): Device = Adesto Unknown",
      "spiflash-1: Read data (addr 0x050000, 8 bytes): 27 05 19 56 8a 1b 22 10"]
   sigrok_decode(case_id="20261018-acme-ipc", input_path="signals/spi-boot.sr",
                 decoders="spi:clk=CLK:mosi=MOSI:miso=MISO:cs=CS", annotations="spi=mosi-transfer:miso-transfer", samplenum=true)
   → ["16-280 spi-1: FF EF 40 18", "16-280 spi-1: 9F 00 00 00", …]
   ```
3. 해석한다(명령·JEDEC 표: [reference.md §3](reference.md#3-spi-nor-참고)).
   - `Device = <vendor> Unknown` 은 spiflash 의 `chip` 옵션 이름일 뿐이다(기본 adesto). 칩은 RDID 응답으로 판단한다: MOSI `9F` 뒤 MISO 3바이트가 JEDEC ID 다(`EF 40 18` = Winbond W25Q128 계열, 16 MiB).
   - `Read data (addr …)` 의 주소·길이는 부트로더가 읽는 오프셋이다(0x050000 의 `27 05 19 56` = uImage 매직). `case_add_note` 로 남긴다.
   - `3B/6B/BB/EB`(dual/quad) 이후 구간은 spi 디코더가 복원하지 못한다. 깨지는 게 정상이다.
     쓰기 명령(`06` WREN, `02` PP, `20/D8` erase)이 보이면 관찰로만 기록하고 개입하지 않는다.
   - 0줄이거나 엉뚱한 명령이면: CS 매핑, MOSI/MISO 뒤바뀜(`9F`/`03` 이 MISO 쪽에 보임), samplerate ≥ 4×SCK, 모드(`cpol=1:cpha=1`)를 확인한다.

### 10. I2C EEPROM 관찰 (목표 D)

T5 로 연결하게 하고, 5(a) 처럼 트리거 없이 `background=true, duration_ms=15000` 으로 캡처를 먼저 시작한 뒤 전원을 넣게 한다(T3).
samplerate 는 100 kHz 버스면 2 MHz, 400 kHz 버스면 4~8 MHz 다. EEPROM 접근은 부팅 뒤 앱이 할 수도 있으니, 안 보이면 더 길게 캡처한다.
```text
sigrok_decode(case_id="20261018-acme-ipc", input_path="signals/i2c-boot.sr",
              decoders="i2c:scl=SCL:sda=SDA", annotations="i2c=addr-data", samplenum=true)
→ "45-185 i2c-1: Address write: 50", "225-385 i2c-1: Data write: 00", "425-565 i2c-1: Address read: 50", "605-765 i2c-1: Data read: 50", …
sigrok_decode(case_id="20261018-acme-ipc", input_path="signals/i2c-boot.sr",
              decoders="i2c:scl=SCL:sda=SDA,eeprom24xx", annotations="eeprom24xx=ops")
→ "eeprom24xx-1: Sequential random read (addr=00, 4 bytes): 50 57 45 48"
```
- 주소는 7비트(shifted) 표기다. 0x50–0x57 은 24Cxx EEPROM 인 경우가 흔하다.
- 출력 줄은 ss 순으로 정렬돼 있지 않다. `samplenum=true` 로 받아 정렬해서 읽는다. 자격증명·키가 보이면 마스킹한다(안전 규칙 8).

### 11. 대안: REA 로 같은 파일 디코드

교차 확인용이다. pweh-sigrok 디코드가 의심스럽거나 쓸 수 없을 때도 쓴다.
```text
inspect_signal_decoders(decoder="spiflash")
decode_signal_recording(path="/abs/.../cases/20261018-acme-ipc/signals/i2c-boot.sr",
                        decoders="i2c:scl=SCL:sda=SDA,eeprom24xx", annotations="eeprom24xx=ops", line_limit=50)
```
- `path` 는 절대 경로다(`sigrok_capture` 의 `absolute_path`, 또는 `case_paths(case_id=…, purpose="signals")`).
- `decoders`·`annotations` 는 **문자열**이다. 배열을 주면 입력 검증 오류가 난다. 출력은 50줄씩이고 `line_offset`/`line_limit` 으로 넘긴다.
- REA 는 케이스에 파일을 남기지 않는다. 응답의 `evidence_id` 를 `case_add_note` 로 기록한다. 기본 경로는 `sigrok_decode` 다.
- REA 는 채널 이름을 미리 검사하지 않는다. 실측: 없는 채널(`rx=D7`)을 주면 오류 없이 첫 채널을 디코드하고, `diagnostics` 에 `cli: No channel with name "D7" found.` 만 남긴다.
  `diagnostics` 가 비어 있지 않으면 그 결과는 버린다.

### 12. 결론과 기록

1. 결론은 다음 단계가 바로 쓸 수 있게 쓴다. 예: "대상 TX = 패드 J3-2 (LA 채널 J3_2), 115200 8N1, idle-high, 측정 전압 3.3 V".
2. 선택 기록: 사람이 한 배선·관찰·SPI 읽기 지도는 `case_add_note`, 플래시 JEDEC ID 는 `case_update_target`.
   사람이 PulseView 로 직접 보려 하면 `sigrok_export(case_id=…, input_path="signals/<name>.sr", output_format="vcd")` 로 변환해 준다.
   보안상 의미 있는 관찰(예: EEPROM 의 평문 자격증명)은 `case_add_finding` 1건([reference.md §5](reference.md#5-선택-발견사항-기록-예)).
3. `case_record_step` 으로 summary 를 남기고(출력 절), `sigrok_jobs(active_only=true)` 로 남은 job 이 없는지 확인한다.

## 사람에게 요청할 일

**T1. 장비와 USB 연결**
```
[사람 작업 필요] 로직 애널라이저 연결 확인
1. 로직 애널라이저 모델(예: 8채널 24MHz Saleae 클론, DSLogic)을 알려 주세요.
2. PC 에 USB 로 연결해 주세요. WSL2 라면 관리자 PowerShell 에서
   usbipd list → usbipd bind --busid <BUSID> → usbipd attach --wsl --busid <BUSID>
   (fx2lafw 는 첫 사용 때 재열거될 수 있습니다. 장치가 떨어지면 attach 를 한 번 더 해 주세요.)
3. 끝나면 "완료" 라고 알려 주세요.
```

**T2. 전압 측정과 UART 후보 배선**
```
[사람 작업 필요] UART 후보 패드에 로직 애널라이저 연결
1. 기기 전원을 끕니다(DC 잭 분리). PoE 대신 DC 어댑터 전원을 써 주세요.
2. 멀티미터 연속성 모드로 GND 패드를 찾습니다(DC 잭 바깥쪽/USB 실드와 통하는 패드). 예: J3-1.
3. 전원을 켜고 나머지 패드(J3-2, J3-3, J3-4)의 DC 전압을 재서 알려 주세요.
   3.3V/5V 면 진행, 1.8V 근처면 알려 주세요(일반 로직 애널라이저로 못 읽을 수 있음), 5V 초과·음전압이면 연결하지 마세요.
   부팅 중에도 늘 일정한 패드는 VCC 일 수 있으니 프로브를 물리지 않습니다.
4. 전원을 끕니다. LA GND → J3-1 을 먼저 연결합니다.
5. LA D0 → J3-2, D1 → J3-3 (VCC 로 보이는 패드 제외). 클립이 옆 패드에 닿지 않는지 확인해 주세요.
6. 전원은 아직 넣지 말고 "완료" 라고 알려 주세요.
```

**T3. 전원 재투입 타이밍 (2단계)**
```
[사람 작업 필요] 부팅 캡처 타이밍
- 지금 대상 전원이 꺼져 있는지 확인해 주세요.
- 제가 다음 메시지에서 "캡처 시작됨" 이라고 하면, 3~5초 뒤에 대상 전원을 넣어 주세요.
- 부팅이 끝날 때까지(약 20초) 그대로 두세요. 준비되면 "준비" 라고 알려 주세요.
```

**T4. SPI 플래시 스니핑 (SOIC-8 클립)**
```
[사람 작업 필요] SPI 플래시 신호 관찰 연결
1. 클립 없이 전원을 켜고, 멀티미터로 칩 8번(VCC)과 4번(GND) 사이 전압을 재서 알려 주세요(1.8V 칩이면 일반 LA 로 못 읽음).
   그다음 대상 전원을 끕니다. 전원이 들어간 상태에서는 클립을 물리지 않습니다.
2. 플래시 칩 마킹(예: W25Q128JV, MX25L12835F)을 알려 주세요.
3. 클립 1번(빨간 선)을 칩의 점(●)에 맞추고 정렬을 두 번 확인합니다.
4. 클립은 로직 애널라이저에만 연결합니다. SPI 프로그래머(CH341A 등)와 클립 8번(VCC)은 아무 데도 연결하지 않습니다.
5. LA GND → 4번(GND) 먼저. 그다음 D0 → 1번(CS#), D1 → 6번(CLK), D2 → 5번(DI/MOSI), D3 → 2번(DO/MISO).
6. "완료" 라고 알려 주세요. 전원은 제가 캡처를 시작한 뒤에 넣습니다(T3).
```

**T5. I2C EEPROM**
```
[사람 작업 필요] I2C EEPROM 신호 관찰 연결
1. 전원을 끄고 EEPROM(8핀, 예: 24C02/24C64) 마킹을 알려 주세요.
2. 전원을 켜고 6번(SCL)·5번(SDA) 전압을 재 주세요(보통 3.3V 풀업). 1.8V 면 알려 주세요.
3. 전원을 끄고 LA GND → 4번(GND) 먼저, D0 → 6번(SCL), D1 → 5번(SDA) 을 연결합니다. 끝나면 "완료".
```

**T6. 정책 거부 보고**
```
[보고] 로직 애널라이저 드라이버 거부 (우회하지 않음)
- 요청: sigrok_capture(driver="<driver>")
- 응답: status denied (sigrok-policy, 규칙 <rule_id>) — 출력 가능 장치이거나 허용 목록 밖 드라이버
- 측정 전용 로직 애널라이저라면 운영자가 orchestrator/pipeline-config.yaml 의 sigrok.capture_drivers_allow 에
  직접 추가할 수 있습니다(출력 가능 장치는 추가해도 거부됨). 다른 장비로 진행할지 알려 주세요.
```

## 성공·실패 기준

- **success**
  - 목표 A: TX 채널 1개와 pin_label 확정, confidence ≥ 0.9, framing_errors ≈ 0, printable_ratio ≥ 0.9, 부팅 문자열(boot_hints) 확인.
  - 목표 B: 활동 여부를 결론 냈다(활동이 있으면 원인 후보를, 없으면 재캡처 2회 결과를 적음).
  - 목표 C: RDID·Read 명령을 디코드하고 JEDEC ID 를 판독. 목표 D: 장치 주소와 읽기/쓰기 트랜잭션을 디코드.
  - 공통: summary 가 스키마를 통과해 저장됐다.
- **partial**: 보드레이트는 정했지만 confidence 0.5~0.9, 텍스트 일부만 읽힘, SPI 에서 RDID 만 보이고 quad 구간은 복원 못 함.
- **failed / blocked**: 재배선·재캡처 2회 뒤에도 모든 채널 에지 없음, 전압 레벨상 연결 불가, 정책 거부(denied), LA 없음.
  캡처 파일이 하나라도 있으면 그 파일로 summary(status `failed`)를 남긴다. 하나도 없으면 capture.file 이 필수라서
  summary 대신 다른 step 이름으로 기록하고 `case_set_phase` 를 호출한다([reference.md §6](reference.md#6-캡처-파일이-없을-때의-실패-기록)).

## 출력

`report_generate` 는 `summary` 문자열을 그대로 싣는다. 핵심 결론을 한 줄로 넣는다. data 는 다음 출처에서 채운다.

| 필드 | 출처 |
|---|---|
| capture.file | `sigrok_capture` 의 `path` (job 이면 `result.path`) |
| capture.device | `sigrok_capture` 의 `driver` 와 `sigrok_scan` 의 description |
| capture.samplerate | `sigrok_capture` 의 정수 값. `sigrok_file_info` 는 실수를 주므로 쓰지 않는다 |
| capture.duration_s, capture.channels | `result.duration_s`, `[{name, pin_label}]` |
| uart_estimate | `sigrok_uart_autodecode` 의 같은 이름 필드를 그대로. UART 가 아니면 null |
| decoders[] | 디코드마다 stack, annotations, output_file(`output_path` 또는 `decode_text_path`), 한 줄 요약 |
| conclusions[] | 다음 단계에 넘길 사실과 근거 |

추가 캡처 파일은 `artifacts` 에 넣는다. 스키마가 additionalProperties 를 허용하므로 같은 모양으로 `additional_captures[]` 에 넣어도 된다.

```text
case_record_step(
  case_id="20261018-acme-ipc",
  skill="logic-analyzer-protocol-decode",
  step="summary",
  status="success",
  summary="LA 캡처로 UART 확인: 대상 TX = 패드 J3-2, 115200 8N1 비반전 (confidence 0.999), U-Boot 2016.11/Linux 4.9.37 부팅 로그와 autoboot 프롬프트 디코드",
  data=<아래 JSON>,
  artifacts=["signals/uart-pads-boot.sr", "signals/uart-pads-boot.J3_2.uart-115200.txt", "signals/uart-pads-boot.J3_2.uart-115200.bin"],
  next_actions=["uart-shell-acquisition: J3-2(대상 TX)→USB-UART RX, J3-3→USB-UART TX, GND 연결 후 115200 8N1 로 콘솔 열기"]
)
```

```json
{
  "capture": {
    "file": "signals/uart-pads-boot.sr",
    "device": "fx2lafw (Saleae Logic clone, 8ch)",
    "samplerate": 8000000,
    "duration_s": 20.0,
    "channels": [
      {"name": "J3_2", "pin_label": "J3-2"},
      {"name": "J3_3", "pin_label": "J3-3"}
    ]
  },
  "uart_estimate": {"channel": "J3_2", "baudrate": 115200, "confidence": 0.999, "idle_level": 1},
  "decoders": [
    {
      "stack": "uart:rx=J3_2:baudrate=115200:data_bits=8:parity=none:format=hex",
      "annotations": "uart=rx-data:rx-warnings",
      "output_file": "signals/uart-pads-boot.J3_2.uart-115200.txt",
      "summary": "sigrok_uart_autodecode: 217 bytes, framing_errors 0, printable 100%, boot_hints = uboot_banner, autoboot_prompt, linux_version, login_prompt"
    }
  ],
  "conclusions": [
    "대상 UART TX = 패드 J3-2 (LA 채널 J3_2): 부팅 중 유일한 활동 채널, idle HIGH (confirmed: 부트 배너 디코드)",
    "보드레이트 115200, 8N1, 비반전 (confidence 0.999, samples_per_bit 69.4, framing_errors 0)",
    "J3-3 은 idle HIGH, 에지 0 → 대상 RX 로 추정 (likely, uart-shell-acquisition 에서 확인)",
    "J3-1 = GND(연속성 확인), J3-4 = VCC 3.3V(측정, 프로브 미연결). 신호 레벨 3.3V → 3.3V USB-UART 사용",
    "autoboot 프롬프트 'Hit any key to stop autoboot' 확인 → U-Boot 인터럽트 경로 가능"
  ]
}
```

서버가 data 를 거부하면 오류 메시지대로 고쳐서 다시 저장한다. 스키마는 `schema_get(name="signal-capture")` 로 볼 수 있다.

## 다음 단계

- **UART 를 찾았다** → `uart-shell-acquisition`. 사람에게 대상 TX 패드 → USB-UART RX, 대상 RX 패드 → USB-UART TX, GND 배선을 요청한다(처음에는 TX 만 연결해도 된다).
  그 Skill 에서 콘솔을 열 때 uart_open 의 baudrate 인자에 data.uart_estimate.baudrate 를 넣고, uart-recon 요약의 baud_detection.method 는 `logic-analyzer` 로 적는다.
- **반전 TTL 라인이다** → 일반 USB-UART 로는 바로 읽을 수 없다. 결론에 적어 넘긴다. 반전을 지원하는 어댑터나 인버터가 필요하다.
- **silent 이거나 활동이 없다** → JTAG(`pweh-openocd`), JTAGulator UART 스캔(전압 설정은 사람 승인), Phase B 경로(master-prompt §4).
- **SPI 를 관찰했다** → 읽은 오프셋과 JEDEC ID 를 `firmware-dump-via-uart`(덤프 크기)와 `firmware-static-analysis`(파티션 오프셋)에서 교차 확인한다.
- **I2C 를 관찰했다** → EEPROM 내용의 의미는 `firmware-static-analysis` 에서 해당 코드를 찾아 해석한다.

## 참고

- [reference.md](reference.md): samplerate 표, 디코더 스택·annotation 표, SPI NOR 핀·명령·JEDEC ID, 해석과 문제 해결, 발견사항·실패 기록 예
- `mcp-servers/sigrok-mcp/README.md`: 도구, 안전 정책, 배선, samplerate
- `docs/references/sigrok-cli.md`: §4 캡처·트리거, §5 디코드 문법, §6 디코더, §12 보드레이트 추정과 함정
- `docs/hardware-setup.md` §3–4, `docs/safety.md` §2.3·§2.5·§7, `orchestrator/master-prompt.md` §1·§4·§5·§6
