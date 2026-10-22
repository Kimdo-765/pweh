# pweh-sigrok (sigrok-mcp)

로직 애널라이저를 `sigrok-cli` 로 다루는 PWEH MCP 서버다. 본인 소유 또는 서면 허가를 받은 CCTV/IoT 기기에서
UART·SPI·I²C 같은 보드 신호를 **수동으로(입력 전용)** 캡처하고 디코딩한다.

REA 의 `decode_signal_recording` / `inspect_signal_decoders` 는 이미 녹화된 파일을 디코딩한다. 이 서버는 REA 에 없는 기능을 더한다.

- 장치 스캔과 장치 정보 조회
- **캡처** — `cases/<id>/signals/<name>.sr` 로 저장하고 아티팩트로 등록한다.
- 형식 변환과 디코딩 래퍼 — 결과 전체를 파일로 저장하고, 미리보기와 통계를 돌려준다.
- **오프라인 보드레이트 추정기** — 순수 Python 이라 sigrok-cli 가 없어도 동작한다.
- UART 자동 디코드 — ASCII 미리보기와 부트 로그 힌트를 함께 돌려준다.

실행 명령은 `pweh-sigrok-mcp` 또는 `python -m sigrok_mcp` (stdio)이다.

## 도구

시그니처는 주요 인자만 적었다(`approval_id`, 타임아웃, `active_only` 같은 선택 인자는 일부 생략). 전체 인자와 기본값은 [`docs/references/pweh-mcp-tools.md`](../../docs/references/pweh-mcp-tools.md) 를 본다.

| 도구 | 설명 / 주요 반환 |
|---|---|
| `sigrok_version(backend="linux")` | sigrok-cli·libsigrok·libsigrokdecode 버전, 실행 파일 `path`, 드라이버·디코더 수(`counts`) |
| `sigrok_scan(driver=None, conn=None, case_id=None, backend="linux", approval_id=None)` | 연결된 장치 `devices[{driver, conn, description, serial_number, channels, capture_allowed, ...}]`. 시리얼/네트워크 `conn` 을 쓰면 `case_id` 가 필요하다 |
| `sigrok_list(kind="drivers"\|"decoders"\|"input-formats"\|"output-formats"\|"transforms"\|"all", query=None, backend="linux")` | 지원 목록. drivers 항목에는 캡처 정책(`capture_allowed`, `output_capable`, `reason`)이 붙는다 |
| `sigrok_decoder_help(decoder)` | 디코더의 채널, 옵션(값 목록·기본값), annotation 클래스와 행, 바이너리 클래스, 문서, `example_stack` |
| `sigrok_device_info(case_id, driver, conn=None, backend="linux", approval_id=None)` *(추가)* | 드라이버 기능, 채널 그룹, 지원 samplerate 목록 또는 범위, 트리거 문자, 최대 샘플 수 |
| `sigrok_capture(case_id, driver, samplerate="1m", duration_ms=None, samples=None, channels=None, triggers=None, output_name=None, conn=None, capture_ratio=None, background=None, timeout_s=None)` | `duration_ms` 와 `samples` 중 **정확히 하나**를 준다(둘 다 없거나 둘 다 주면 `validation_failed`). `signals/<name>.sr` 를 만들고 아티팩트로 등록한다. `path`, `samples`, `samplerate`, `channels`, 채널별 `activity`, `next_steps` 를 돌려준다. 예상 시간이 20초를 넘거나 트리거를 쓰면 job 으로 돌고 `job_id` 를 반환한다 |
| `sigrok_decode(case_id, input_path, decoders, annotations=None, input_format=None, samplenum=False, max_lines=400, background=None)` | 결과 전체를 `signals/<입력>.<디코더>.txt` 로 저장한다(`signal-decode`). `lines`(미리보기), `lines_total`, `instances`, `sample_range` 를 돌려준다 |
| `sigrok_export(case_id, input_path, output_format="vcd", output_name=None)` | 형식을 변환한다(srzip↔vcd, csv 등). 출력이 vcd/srzip 이면 다시 읽어서 검증한다 |
| `sigrok_file_info(case_id, input_path)` *(추가)* | 순수 Python 으로 만든 요약(형식, samplerate, 채널, 샘플 수, 길이)과 채널별 활동(에지 수, high 비율, 처음/끝 레벨), `uart_candidates` |
| `sigrok_estimate_baud(case_id, input_path, channel=None, data_bits=8, parity="none")` | `baudrate`, `baudrate_raw`, `confidence`(0~1), `idle_level`(1=정상, 0=반전), `inverted`, `candidates`, `samples_per_bit`, `frame_check`, `segments`, `warnings`, `suggested_decoder` |
| `sigrok_uart_autodecode(case_id, input_path, channel=None, baudrate=None, data_bits=8, parity="none", engine="auto", background=None)` | 보드레이트를 추정한 뒤 uart 디코더로 디코드한다. `text_preview`, `hex_preview`, `framing_errors`, `boot_hints`, `uart_estimate`, 디코드 텍스트와 바이트 파일(`.txt`/`.bin`) 경로를 돌려준다. 입력이 크면 job 으로 돈다 |
| `sigrok_job_status(job_id, wait_seconds=0, case_id=None)`, `sigrok_job_cancel(job_id)`, `sigrok_jobs(active_only=False, case_id=None)` | 백그라운드 캡처·디코드 작업. 취소하면 부분 캡처를 `<name>-partial.sr` 로 보존하고 등록한다 |

작업 상태·목록의 `case_id`를 생략하면 이 서버 프로세스의 작업만 보인다. 재시작 뒤에는
`sigrok_job_status(job_id, case_id="<케이스 ID>")` 또는 `sigrok_jobs(case_id="<케이스 ID>")`로 같은 서버의 저장 기록을 확인한다.
소유 서버 종료가 확실한 활성 기록만 `failed`(`error.code=job_owner_terminated`)로 정리한다. 소유자 없는 과거 기록·다른 호스트/namespace·관찰 불가는
원본 상태를 보존하고 `recovery.owner_state="unknown"`과 사유를 표시한다. 살아 있는 다른 서버 프로세스의 기록도 보존한다.
원시 owner 식별자는 응답에 나오지 않는다. 저장 기록의 재개/취소는 없고, `wait_seconds`는 이 프로세스의 작업만 기다린다.
한 기록 1MiB, 목록 512디렉터리 항목·256기록·누적 8MiB·2초로 제한하며 목록의 `recovery.truncated/reasons`가 확인하지 못한 범위를 알린다.
이 두 도구는 로컬 기록을 정리하므로 `readOnlyHint=false`다. 파일·기기·외부 자식의 정리 여부는 별도로 확인한다.

경로 인자는 케이스 상대 경로(`signals/x.sr`)를 쓴다. `signals/` 는 생략해도 된다. 케이스 밖 경로는 거부한다.
`channel` 에는 이름(`D0`, `RX`)이나 인덱스를 쓸 수 있다. srzip 의 인덱스는 비트 위치이고, VCD 의 인덱스는 선언 순서다.

## Windows 무장치 정보 조회

`sigrok_version(backend="windows")`와 `sigrok_list(backend="windows")`는 등록 Windows 번들의 버전·지원 목록만 조회한다. 요청별 전체 사본을 사용하고 실제 Windows 프로세스·wrapper 종료와 사본 검증을 마친 뒤 반환한다. 기본 Linux 경로와 캐시는 유지한다. 이 정보 조회는 장치를 열지 않는다. 별도 `sigrok_scan`·`sigrok_device_info`의 Windows 경로는 고정 OLS COM만 지원한다. Windows USB 자동 탐지·capture·decode는 지원하지 않는다.

동봉 Python 3.4.4의 `signature` 디코더 오류가 재현되면 version은 `status="partial"`, `counts=null`, `list_complete=false`를 반환하고 list는 모든 kind에서 오류로 끝난다. 설치 선택·고정 명령·오류·취소/정리 계약은 [Windows 정보 조회](../../docs/references/windows-sigrok-info.md)를 본다.

## Windows OLS COM 조회

`backend="windows"`, `driver="ols"`, `conn="COMn"`과 소유/허가 케이스를 명시한다. 고정 `ols-serial-v1` scan/show만 실행하며 프로토콜 reset 때문에 MODIFY다. `approval_required`이면 사람이 별도 터미널에서 승인한 뒤 `approval_id`를 전달한다. 명령·결과 투영·lease와 Windows 종료 확인·합성 시험 범위는 [COM 조회 계약](../../docs/references/windows-sigrok-com.md)을 본다. 실제 COM 접근·장비 검증은 아직 수행하지 않았다.

## 안전 정책

이 서버는 **로직 애널라이저와 오실로스코프의 입력 전용 캡처**만 한다. sigrok 은 전원공급기, 전자부하, 신호발생기,
릴레이도 제어할 수 있다. 그런 장치는 대상 보드에 전압·전류·신호를 가할 수 있으므로 모두 막는다.

- **출력 가능 장치는 무조건 거부한다.** 대상은 다음과 같다.
  - 전원공급기: `scpi-pps`, `hpib-pps`, `korad-kaxxxxp`, `manson-hcs-3xxx`, `rdtech-dps`, `rdtech-rd`, `gwinstek-gpd`, `gwinstek-psp`, `atten-pps3203`, `motech-lps-301`, `conrad-digi-35-cpu`
  - 전자부하: `maynuo-m97`, `itech-it8500`, `siglent-sdl10x0`, `arachnid-labs-re-load-pro`, `zketech-ebd-usb`, `atorch`
  - 신호발생기: `rigol-dg`, `juntek-jds6600`, `rohde-schwarz-sme-0x`
  - 릴레이: `dcttech-usbrelay`, `icstation-usbrelay`, `devantech-eth008`, `hp-59306a`
  - DUT 전원 차단: `baylibre-acme`

  이 목록은 libsigrok 0.5.2 와 master 소스의 drvopts 와 출력 키를 기준으로 만들었다. 이런 요청은 게이트에 넘기지 않는다.
  그래서 `destructive_policy: approve` 로 설정해도 승인할 방법이 없다. 거부는 `status: denied`(`gate.via: "sigrok-policy"`)로 응답하고 감사 로그에 남긴다.
- **허용 목록 방식이다.** 캡처, 스캔, 장치 정보 조회에는 드라이버 기능이 Logic analyzer 또는 Oscilloscope 인 드라이버와 `demo` 만 쓸 수 있다.
  - 로직 애널라이저: fx2lafw, dreamsourcelab-dslogic, saleae-logic16, saleae-logic-pro, ols, p-ols, asix-sigma, beaglelogic, chronovu-la, hantek-4032l, ikalogic-*, ipdbg-la, lecroy-logicstudio, link-mso19, microchip-pickit2, sysclk-*, zeroplus-logic-cube
  - **`ftdi-la` 는 기본 허용하지 않는다.** 제품 문자열 확인 없이 범용 FTDI VID/PID(FT232R/FT2232H/FT4232H/FT232H)만으로 장치를 잡아,
    같은 칩을 쓰는 USB-UART 어댑터(대상 콘솔)·JTAG 어댑터·JTAGulator 를 LA 로 열고 커널 드라이버(ftdi_sio)를 떼며 핀을 bitbang 입력으로 바꾼다
    (콘솔 세션이 끊기고, JTAGulator 는 DTR 리셋으로 VADJ 가 꺼질 수 있다). 전용 FTDI LA 보드만 연결된 환경이면 운영자가 아래
    `capture_drivers_allow` 에 `ftdi-la` 를 넣는다. 제품 문자열을 확인하는 chronovu-la, ikalogic-scanaplus, p-ols 는 그대로 허용한다.
  - master 전용 로직 애널라이저: kingst-la2016, raspberrypi-pico, greatfet, asix-omega-rtm-cli
  - 오실로스코프

  목록에 없는 드라이버(DMM 등)는 실패-닫힘으로 거부한다. 측정 전용 장비를 추가해야 하면 **사람(운영자)이** `orchestrator/pipeline-config.yaml` 에 다음처럼 적는다.

  ```yaml
  sigrok:
    capture_drivers_allow: [uni-t-ut61e]   # 측정 전용 장비만. 출력 가능 장치는 적어도 거부된다
    capture_drivers_deny: [ols]            # 추가로 막을 드라이버
  ```

  에이전트는 이 설정을 스스로 바꾸지 않는다.
- **config 키는 `samplerate` 와 `captureratio` 만 쓴다.** 값은 항상 정수다. `--set`, `--continuous`, `-g`(채널 그룹), 드라이버 옵션(`conn` 제외)은 절대 생성하지 않는다.
  - samplerate 는 Python 에서 정수 Hz 로 바꿔 넘긴다. sigrok-cli 0.7.2 는 `1.5m` 를 1 Hz 로 해석하는 버그가 있다.
  - Kingst LA2016 의 PWM 출력은 열 때 비활성이다. 이 서버는 PWM 채널 그룹이나 키를 보내지 않는다.
- **항상 `-d <driver>` 를 명시하고 `--dont-scan` 을 붙인다.** `-d` 없이 캡처하면 sigrok-cli 가 스캔된 장치를 자동으로 고른다. 그러면 전원공급기가 선택될 수도 있다.
- 장치를 건드리는 모든 도구는 케이스 소유/허가 증명(`rt().case(case_id, hardware=True)`)을 요구한다. 실행할 **argv 그대로**를 분류기 `classify_sigrok_argv` 에 통과시킨 뒤 `rt().authorize` 를 거친다.
- 디코드(`sigrok_decode` job, `sigrok_uart_autodecode` 의 sigrok-cli 경로)도 sigrok-cli 를 띄우기 직전에 argv 를 다시 분류해 **오프라인 명령(`sigrok.offline`)만** 실행한다.
  - 위험도는 다음과 같다. USB 캡처는 OBSERVE 다. 시리얼/네트워크 `conn` 은 드라이버가 그 포트로 식별 바이트를 보내므로 INTERACT 다. OLS+명시 직렬 scan/show는 reset 때문에 MODIFY로 올려 기존 게이트를 적용한다.
- 시리얼 `conn` 을 다른 프로세스가 열고 있으면 거부한다(Busy). 예를 들어 uart-mcp 가 대상 콘솔을 열고 있는 경우다. 대상 U-Boot/쉘 콘솔에 OLS 프로브 바이트(0x00, 0x02 …)가 들어가는 사고를 막기 위해서다.
- 명시 직렬 `conn`은 승인 전 공용 portlock lease를 잡고 action에 route 지문, 결과·job metadata에 공개 route를 남긴다. child 종료를 확인할 때까지 잠금을 유지하며 취소/고아 정리 미확인으로 먼저 풀지 않는다.
  USB 자동 탐지·일반 libusb는 이 공용 잠금의 적용 범위 밖이다. Windows COM은 고정 OLS scan/show만 허용한다. 기본 Linux와 capture에서는 COM을 거부한다.
- 백그라운드 작업은 프로세스를 띄우기 직전에 같은 분류기로 argv 를 **다시 검사**한다.
- 같은 장치로는 캡처를 동시에 하나만 돌린다.
- subprocess 실행 규칙은 다음과 같다.
  - 인자 리스트만 쓰고 shell 은 쓰지 않는다.
  - `stdin=/dev/null` 로 둔다. MCP stdio 채널은 상속하지 않는다.
  - 새 세션으로 띄운다. 타임아웃이나 취소 시 프로세스 그룹 전체에 SIGTERM, 이어서 SIGKILL 을 보낸다.
- 기존 증거는 덮어쓰지 않는다. 캡처는 숨김 임시 파일(`.<name>.partial.sr`)에 받는다. 검증에 통과해야 최종 이름으로 옮긴다. 같은 이름이 이미 있으면 거부하거나 자동으로 번호를 붙인다.
- sigrok-cli 는 rc=0 인데 실패인 경우가 있다. 예를 들어 없는 채널 이름을 주면 **조용히 첫 채널을 디코드한다**. `SamplerateError` 도 rc=0 으로 끝난다.
  - 그래서 디코드 전에 채널 매핑을 입력 파일의 채널 이름과 대조한다.
  - 실행 후에는 stderr 를 패턴으로 검사해서 실패로 처리한다.

## 지원하는 저가 로직 애널라이저

| 장치 (흔한 이름) | 드라이버 | 비고 |
|---|---|---|
| "24MHz 8CH" Saleae Logic 클론, MCU123, ESLA100, Hantek 6022BL(LA 모드) | `fx2lafw` | 8ch, 최대 24 MHz. VID:PID `0925:3881`. 입력 -0.5~5.25 V, 고정 임계 VIH 2.0 V / VIL 0.8 V. 펌웨어(`fx2lafw-saleae-logic.fw`)는 sigrok 이 자동으로 업로드한다 |
| LHT00SU1 등 USBee AX 클론 | `fx2lafw` | 8ch + 아날로그 A0 |
| CY7C68013A 보드(Lcsoft Mini Board 등) | `fx2lafw` | 16ch 가능. 16비트 모드는 최대 12 MHz |
| DSLogic / Plus / Pro | `dreamsourcelab-dslogic` | 펌웨어는 DSView 에서 추출(`sigrok-fwextract-dreamsourcelab-dslogic`). 임계 전압 3.3/5 V |
| Saleae Logic16 | `saleae-logic16` | 펌웨어 추출 필요 |
| Openbench Logic Sniffer / SUMP 호환 | `ols` | 시리얼 `conn=/dev/ttyACM0` 필요. `case_id` 도 필요 |
| Kingst LA1010/LA2016, Raspberry Pi Pico | `kingst-la2016`, `raspberrypi-pico` | sigrok **master(nightly)** 에만 있다. 0.7.2 패키지에는 없다 |

채널 이름은 드라이버마다 다르다. fx2lafw 는 `D0..D7`, DSLogic 과 Logic16 은 `0..15` 다. `sigrok_scan` 결과에서 확인하라.
범위 표기(`0-7`)는 숫자 이름 채널에서만 동작한다. **0번부터 연속으로** 선택하고 이름만 바꾸기를 권장한다(예: `["D0=RX","D1=TX"]`).
일부 드라이버(demo 등)는 비연속으로 선택하면 .sr 의 비트 위치가 메타데이터와 어긋난다.

## 배선 (사람이 한다)

1. **대상 전원을 끈 상태에서** 연결한다. **GND 를 먼저** 대상 보드 GND(UART 헤더 GND, 커넥터 실드, 전해 콘덴서 - 극)에 물린다.
2. 전압 레벨을 확인한다. 대상이 동작 중일 때 멀티미터로 신호 핀의 idle 전압을 잰다.
   - 3.3 V 와 5 V TTL 은 fx2lafw 클론에 바로 연결해도 된다.
   - **1.8 V UART** 는 VIH 2.0 V 아래라서 에지가 안 보일 수 있다. 레벨 시프터를 쓰거나 임계 전압을 조절할 수 있는 LA(DSLogic)를 쓴다.
   - **RS-232(±12 V) 레벨은 절대 직접 연결하지 않는다.** MAX232 같은 변환기 뒤의 TTL 쪽을 잰다. 변환기 뒤에서는 극성이 반전돼 idle-low 로 보일 수 있다. 추정기가 `idle_level=0` 과 `invert_rx=yes` 를 알려준다.
3. 프로브는 대상의 **TX(기기 출력)** 부터 연결한다. LA 입력은 고임피던스라서 대상 신호를 바꾸지 않는다.
   USB 접지 루프를 조심한다. 전원 어댑터를 쓰는 대상과 PC 의 GND 전위차가 클 수 있다.
4. 부트 로그를 잡으려면 **캡처를 먼저 시작한다.** `background=true` 나 트리거(`triggers="RX=f"`, `capture_ratio=1`)를 쓰면 된다. 그 뒤에 사람에게 대상 전원을 넣어 달라고 요청한다.

## WSL2 / USB

- WSL2 에서는 Windows 의 usbipd-win 으로 USB 장치를 붙인다. 아래는 관리자 PowerShell 에서 실행한다.

  ```powershell
  usbipd list
  usbipd bind --busid <busid>
  usbipd attach --wsl --busid <busid>
  ```

  WSL 에서 `lsusb` 로 확인한다.
- fx2lafw 장치는 펌웨어를 업로드한 뒤 USB 에 **재열거**된다. 그러면 VID:PID 가 바뀔 수 있다. 재열거 뒤에 WSL 에서 떨어지면 다시 attach 하거나 usbipd 의 자동 재연결(`--auto-attach`)을 쓴다. 이 동작은 실기에서 미확인이다.
- 권한 오류(`LIBUSB_ERROR_ACCESS`)가 나면 사람이 libsigrok udev 규칙을 설치하고 장치를 다시 꽂는다. 규칙 파일은 `60-libsigrok.rules` 와 `61-libsigrok-plugdev.rules`(또는 `61-libsigrok-uaccess.rules`)다.

## 설치 / 설정

- 실행 파일은 이 순서로 찾는다.
  1. 설정 `tools.sigrok_cli`, 즉 `${PWEH_SIGROK_CLI:-sigrok-cli}`
  2. 환경변수 `PWEH_SIGROK_CLI`
  3. `PATH`

  없으면 설치 힌트와 함께 `tool_missing` 오류를 낸다. `sigrok_estimate_baud`, `sigrok_file_info`, `sigrok_uart_autodecode(engine="python")` 는 sigrok-cli 없이도 동작한다.
- 이 저장소의 개발 환경: `. ~/pweh-tools/env.sh` 를 하면 `PWEH_SIGROK_CLI=~/pweh-tools/bin/sigrok-cli` 가 잡힌다(sigrok-cli 0.7.2 래퍼). 또는 `sudo apt install sigrok-cli` 로 설치한다(Ubuntu 22.04+ 기준 0.7.2 / libsigrok 0.5.2 / libsigrokdecode 0.5.3).
- libsigrokdecode master 는 annotation 과 옵션 이름이 0.5.3 과 다르다. 이름을 하드코딩하지 말고 `sigrok_decoder_help` 로 확인하라. 예를 들어 0.5.3 의 `rx-warnings` 가 master 에서는 `rx-warning` 이다.

## 샘플레이트 고르기

비트당 **10샘플 이상**을 권장한다. 8배까지는 실측상 양호하다. **4배 미만이면 추정기가 경고한다.**
보드레이트를 모르면 첫 캡처는 **8 MHz 이상**으로 한다. 아래는 fx2lafw 목록 기준의 최소 권장값이다.

| baud | 최소 권장 samplerate (fx2lafw) |
|---|---|
| 9600 | 100 kHz |
| 115200 | 2 MHz (1 MHz = 8.7배도 동작) |
| 230400 | 3 MHz |
| 460800 | 6 MHz |
| 921600 | 12 MHz |
| 1500000 | 16 MHz |
| 3000000 | 24 MHz (8배) |

## 보드레이트 추정기 (sigrok_estimate_baud)

추정기는 순수 Python 이다. srzip(.sr v2)과 VCD 를 직접 읽는다. 청크 단위로 흘려 읽고 `bytes.translate` 로 에지를 뽑는다. numpy 는 쓰지 않는다.

1. 잘린 첫/마지막 run 을 버린 완전한 run 폭에서 1샘플 이하 글리치를 뺀다.
2. 최소 안정 폭 클러스터의 가중 평균을 초기 T 로 잡는다.
3. `k=round(w/T)`(1≤k≤12)이고 `|w-kT| ≤ max(0.3T, 1샘플)` 인 run 으로 `T=Σw/Σk` 를 반복 정제한다. 근사 GCD 방식이다.
4. 전체 run, 레벨 0 run, 레벨 1 run 에서 각각 후보를 만든다. 각 후보와 그 절반(2배 보드레이트)을 두 idle 극성으로 **8N1 프레임 검사**해서 오류율이 가장 낮은 조합을 고른다. 이 단계에서 다음을 판정한다.
   - T 와 T/2 의 모호성
   - 반전 라인
   - 소수배 idle 간격의 영향
5. 표준 보드레이트에서 ±3% 이내면 스냅한다. 표준 목록은 300~3000000 이고, 1500000, 74880(ESP8266), 14400/28800/250000 을 포함한다.
6. 구간별(idle ≥ 30T) 보드레이트가 다르면 `segments` 와 경고로 알린다. 예를 들어 BootROM 과 U-Boot 의 속도가 다른 경우다.

`confidence` 는 다음 값을 곱한 것이다.

- 설명 비율
- 스냅 오차
- 오버샘플링
- 데이터 양
- 프레임 오류율

## 사용 예

```jsonc
// 1) 장치 확인
sigrok_scan()
sigrok_device_info({"case_id": "20261018-acme-ipc", "driver": "fx2lafw"})

// 2) 부트 로그 캡처: 8 MHz, 10초, D0=RX(대상 TX), 첫 하강 에지 트리거 → job
sigrok_capture({"case_id": "20261018-acme-ipc", "driver": "fx2lafw", "samplerate": "8m", "duration_ms": 10000,
                "channels": ["D0=RX", "D1=TX"], "triggers": "RX=f", "capture_ratio": 1, "output_name": "uart-boot"})
// → {"status": "started", "job_id": "job-…"}  (사람에게 대상 전원 투입 요청)
sigrok_job_status({"job_id": "job-…", "wait_seconds": 30})

// 3) 어느 채널이 살아 있나 / 보드레이트
sigrok_file_info({"case_id": "…", "input_path": "signals/uart-boot.sr"})
sigrok_estimate_baud({"case_id": "…", "input_path": "signals/uart-boot.sr", "channel": "RX"})
// → {"baudrate": 115200, "confidence": 0.99, "idle_level": 1, "suggested_decoder": "uart:rx=RX:baudrate=115200", …}

// 4) UART 자동 디코드 (ASCII + 부트 힌트)
sigrok_uart_autodecode({"case_id": "…", "input_path": "signals/uart-boot.sr", "channel": "RX"})

// 5) SPI 플래시 부팅 스니핑 디코드
sigrok_decode({"case_id": "…", "input_path": "signals/spi-boot.sr",
               "decoders": "spi:clk=CLK:mosi=MOSI:miso=MISO:cs=CS,spiflash", "annotations": "spiflash=commands"})

// 6) 형식 변환 (PulseView/GTKWave 용)
sigrok_export({"case_id": "…", "input_path": "signals/uart-boot.sr", "output_format": "vcd"})
```

Skill 은 결과를 `case_record_step(skill="logic-analyzer-protocol-decode", step="summary", data=…)` 로 기록한다.
`data` 는 `schemas/signal-capture.schema.json` 형식을 따른다. 각 필드는 다음 출처에서 채운다.

| 필드 | 출처 |
|---|---|
| `capture.file` | `sigrok_capture.path` |
| `capture.samplerate` | `sigrok_capture.samplerate` |
| `uart_estimate.{channel, baudrate, confidence, idle_level}` | `sigrok_uart_autodecode.uart_estimate` 또는 `sigrok_estimate_baud` |
| `decoders[].output_file` | `sigrok_decode.output_path` |

## 알려진 한계

- 실제 USB 로직 애널라이저(fx2lafw 등)로는 검증하지 않았다. `demo` 드라이버, 합성 파형, 가짜 sigrok-cli 로만 검증했다. `--scan`/`--show` 의 실기 출력과 fx2lafw 재열거 동작은 소스를 근거로 처리했다.
- 순수 Python 추정과 디코드는 8N1 계열 비동기 UART 만 다룬다. 패리티와 7비트는 `data_bits`/`parity` 로 지정한다. 그 밖의 프로토콜은 `sigrok_decode` 를 쓴다.
- 1T 펄스가 전혀 없고 프레임이 간격 없이 붙어 있는 병적인 데이터에서는 T 와 2T 가 모두 유효한 해석이다. 이 경우 낮은 보드레이트를 고른다.
- 비트 시간이 정수 샘플인 VCD 에서 sigrok 주석(`$comment … at <rate>`)이 없으면 실제 샘플링 해상도를 timescale 기준으로 가정한다. 그러면 오버샘플링 경고가 빠질 수 있다.
- 디코드 출력은 512 MiB 에서 끊는다. 그 지점에서 sigrok-cli 를 멈추고 앞부분만 저장·등록한다(`output_truncated: true`, 경고 포함). `annotations` 를 좁혀서 줄여라.
- 큰 캡처의 sha256·활동 분석·디코드는 시간이 걸린다. 디코드와 UART 자동 디코드는 입력이 크면 자동으로 job 으로 돈다. 동기 디코드의 기본 제한은 55초다(Codex/Cursor 의 기본 도구 타임아웃 60초 고려).
