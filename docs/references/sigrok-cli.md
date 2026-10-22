# sigrok-cli 레퍼런스 — sigrok-mcp 래퍼 · 오프라인 보레이트 추정기 구현용

> 대상 독자: `sigrok-mcp`(sigrok-cli 래퍼 MCP 서버)와 오프라인 baud estimator를 구현하는 엔지니어, 그리고 `logic-analyzer-protocol-decode` 등 Skill 작성자.
> 이 문서는 **정확한 명령 문법·출력 문자열·파일 형식**을 우선한다. 산문은 한국어, 명령/식별자/원문 출력은 영어 그대로 둔다.
> 대상 기기는 운영자가 소유했거나 서면 허가를 받은 장비에 한정한다.

---

## 0. 기준 버전과 표기 규칙

| 구성요소 | 기준 버전 | 릴리스일 | 근거 |
|---|---|---|---|
| sigrok-cli | **0.7.2** | 2021-03-01 | `NEWS` (https://github.com/sigrokproject/sigrok-cli/blob/sigrok-cli-0.7.2/NEWS) |
| libsigrok | **0.5.2** | 2019-12-23 | `NEWS` (https://github.com/sigrokproject/libsigrok/blob/libsigrok-0.5.2/NEWS) |
| libsigrokdecode | **0.5.3** | 2019-12-11 | `NEWS` (https://github.com/sigrokproject/libsigrokdecode/blob/libsigrokdecode-0.5.3/NEWS) |

- 2026-10-18 기준 GitHub 태그상 위 세 개가 **최신 정식 릴리스**다(이후에는 `*-unreleased` 태그와 master만 있음). Ubuntu jammy(22.04)부터 최신 시리즈까지 모두 sigrok-cli 0.7.2 / libsigrok 0.5.2 / libsigrokdecode 0.5.3 패키지를 쓴다(https://launchpad.net/ubuntu/+source/sigrok-cli , https://launchpad.net/ubuntu/+source/libsigrokdecode). focal(20.04)은 sigrok-cli **0.7.1**이라 `--protocol-decoder-jsontrace`, `-A` 행(row) 이름 지정이 없다(0.7.2 NEWS).
- nightly/AppImage는 git master로 빌드되며 **디코더 annotation 클래스 이름·옵션이 0.5.3과 다르다**(6장). 래퍼는 클래스 이름을 하드코딩하지 말고 런타임에 `-P <pd> --show`로 조회할 것.

표기:

- **[실측]** — 2026-10-18, 이 머신(Ubuntu 22.04, WSL2)에서 Ubuntu 22.04 패키지(sigrok-cli 0.7.2-1, libsigrok4 0.5.2-3build1, libsigrokdecode4 0.5.3-2ubuntu1)를 `~/pweh-tools/sigrok/root`에 풀어 `~/pweh-tools/bin/sigrok-cli` 래퍼로 직접 실행한 결과. 하드웨어 없이 `demo` 드라이버와 합성(synthetic) 캡처 파일로 검증했다.
- **[소스]** — sigrok.org 릴리스 tarball(`sigrok-cli-0.7.2.tar.gz`, `libsigrok-0.5.2.tar.gz`, `libsigrokdecode-0.5.3.tar.gz`, https://sigrok.org/download/source/)의 소스를 읽고 도출. 같은 파일을 GitHub 태그 URL로 인용한다.
- **[문서]** — man page / sigrok wiki.
- **(미확인)** — 1차 출처로 확인하지 못한 형태. 구현 시 실기에서 재확인 필요.

---

## 1. 설치·실행 환경

### 1.1 pweh 로컬 설치 (sudo 없음)

이 머신에는 시스템 sigrok이 없고, 사용자 승인에 따라 `~/pweh-tools/`에 패키지를 풀어 두었다. 래퍼 스크립트 원문 [실측]:

```bash
#!/bin/bash
# pweh-tools wrapper for the privately unpacked Ubuntu 22.04 sigrok-cli 0.7.2
# (libsigrok 0.5.2 / libsigrokdecode 0.5.3). Private libraries are only put on
# LD_LIBRARY_PATH for this process; nothing is exported globally.
SIGROK_ROOT=$HOME/pweh-tools/sigrok/root
export LD_LIBRARY_PATH="$SIGROK_ROOT/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export SIGROKDECODE_DIR="$SIGROK_ROOT/usr/share/libsigrokdecode/decoders"
export SIGROK_FIRMWARE_DIR="$SIGROK_ROOT/usr/share/sigrok-firmware"
# libsigrokdecode embeds the system libpython3.10; keep it on the system stdlib.
unset PYTHONHOME PYTHONPATH
exec "$SIGROK_ROOT/usr/bin/sigrok-cli" "$@"
```

- MCP 서버는 실행 파일 경로를 설정값으로 받게 하고(예: `SIGROK_CLI=~/pweh-tools/bin/sigrok-cli`), 기본값은 `PATH`의 `sigrok-cli`로 둔다.
- `SIGROKDECODE_DIR`: libsigrokdecode가 추가로 디코더를 찾는 경로 [소스] (`srd.c`, https://github.com/sigrokproject/libsigrokdecode/blob/libsigrokdecode-0.5.3/srd.c).
- 펌웨어 검색 순서 [소스] (`sr_resourcepaths_get()`, https://github.com/sigrokproject/libsigrok/blob/libsigrok-0.5.2/src/resource.c):
  1. `$SIGROK_FIRMWARE_DIR`
  2. `$XDG_DATA_HOME/sigrok-firmware` (보통 `~/.local/share/sigrok-firmware`)
  3. 빌드 시 지정된 `FIRMWARE_DIR`
  4. `$XDG_DATA_DIRS`의 각 항목 + `/sigrok-firmware` (보통 `/usr/local/share/sigrok-firmware`, `/usr/share/sigrok-firmware`)

### 1.2 USB 권한(udev) — 사람이 할 일

wiki 원문 [문서] (https://sigrok.org/wiki/Fx2lafw): `libsigrok/contrib/60-libsigrok.rules`를 `/etc/udev/rules.d/`에 복사하고 `61-libsigrok-uaccess.rules`(systemd/logind 환경) 또는 `61-libsigrok-plugdev.rules`(`plugdev` 그룹 권한) 중 하나를 함께 설치한다. Ubuntu 패키지에는 이 규칙이 `/lib/udev/rules.d/`에 들어 있다 [실측]:

```text
lib/udev/rules.d/60-libsigrok.rules
lib/udev/rules.d/61-libsigrok-plugdev.rules
lib/udev/rules.d/61-libsigrok-uaccess.rules
```

`60-libsigrok.rules` 안의 Saleae Logic(클론 포함) 항목 [실측]:

```text
ATTRS{idVendor}=="0925", ATTRS{idProduct}=="3881", ENV{ID_SIGROK}="1"
```

`61-libsigrok-plugdev.rules`의 핵심 줄 [실측]:

```text
ENV{ID_SIGROK}=="1", MODE="660", GROUP="plugdev"
```

이 머신은 sudo 암호가 필요하므로 규칙 설치는 **사람이 수행**한다. 에이전트는 권한 오류(아래 5.7 표)를 감지하면 사람에게 요청만 한다.

### 1.3 WSL2에서 USB 로직 애널라이저 쓰기 — 사람이 할 일

Microsoft 문서 [문서] (https://learn.microsoft.com/en-us/windows/wsl/connect-usb), Windows 측 PowerShell:

```powershell
usbipd list
usbipd bind --busid 4-4
usbipd attach --wsl --busid <busid>
usbipd detach --busid <busid>
```

WSL에서 `lsusb`로 확인한다. fx2lafw 장치는 펌웨어 업로드 후 USB 재열거(re-enumeration)를 하므로, WSL에 붙인 장치가 재열거 뒤 떨어질 수 있다 → 다시 attach하거나 usbipd-win의 자동 재연결 기능을 써야 할 수 있다 **(미확인: fx2lafw + usbipd 조합에서의 실제 동작)**.

### 1.4 Windows 고정 취득본의 무장치 확인 (2026-10-22)

사용자의 다운로드·무장치 시험 동의 후 [공식 다운로드 목록](https://sigrok.org/download/binary/sigrok-cli/)의
`sigrok-cli-0.7.2-x86_64-installer.exe`(38,968,619바이트)를 취득했다.
SHA-256은 `27ddf838c992381f3d9c52ad9d5a7ec7db382d9aea1905d44538a7c7bd368446`이다.
공식 목록에 checksum·서명은 없어 이 값은 **최초 취득본 지문**이며 공급자 checksum 검증값은 아니다.

설치 프로그램을 실행하지 않고 NSIS 파일 목록에서 CLI·Python·디코더·펌웨어·`COPYING`을 선택했다.
p7zip 16.02는 `python34.zip`에서 `Data Error`를 내므로 불완전 결과를 보존하고 실행하지 않았다.
별도 Linux 7-Zip 26.05로 경로·크기 상한을 적용해 290개 파일(34,159,405바이트)을 추출하고 파일별 SHA-256을 기록했다.
Zadig·uninstaller·설치 플러그인은 제외했다. 실행한 CLI의 SHA-256은
`54c6529790be7923e0f4b77710a2f0653c3534d1e6f19780db27d8f465356699`이다.

전체 파일 해시를 대조한 독립 사본에서 자식 프로세스의 HOME·XDG·APPDATA·Python·디코더 검색 환경을 고정해 다음 두 명령만 실행했다.

| 명령 | 관찰 | 판정 |
|---|---|---|
| `sigrok-cli.exe --version` | 종료 코드 0, stderr 0바이트. CLI 0.7.2·libsigrok 0.5.2·libsigrokdecode 0.5.3·Python 3.4.4 | 버전 조회 확인 |
| `sigrok-cli.exe -L` | 종료 코드 0. 드라이버 159·입력 9·출력 13·변환 3·디코더 110개 목록, stderr 1,938바이트 | 목록 반환 확인, **전체 디코더 로드에는 실패** |

`-L`의 stderr는 번들 `signature/pd.py:138`의 숫자 리터럴 구분자 `_`를 Python 3.4.4가 처리하지 못한
`SyntaxError`를 세 번 보고했다. 따라서 종료 코드 0과 목록 개수만으로 전체 디코더가 정상이라고 판정하면 안 된다.
두 실행 모두 WSL 자식 종료와 해당 Windows 프로세스 잔존 0개를 확인했고 강제 종료는 없었다.

이 결과는 P3 운영 backend·Windows COM·USB 캡처 지원 완료를 뜻하지 않는다.
`--scan`·장치·드라이버 설치·시스템 설정 변경은 없었다. DLL 검색 전체의 격리도 검증하지 않았다.
PE import에 필요한 `MSVCR100.dll`은 추출 트리에 없으며, 이번 두 명령의 실행 성공이 다른 호스트의 런타임 제공을 보장하지 않는다.
`sqlite3.dll`·`tcl86t.dll`·`tk86t.dll`은 `python34.zip` 내부에서만 확인했다.
`COPYING`은 GPLv3 원문이며, 이 파일만으로 정적 링크된 모든 의존성의 라이선스 확인을 완료했다고 볼 수 없다.

---

## 2. 명령행 개요

### 2.1 `--help` 원문 [실측]

```text
Usage:
  sigrok-cli [OPTION?]

Help Options:
  -h, --help                             Show help options

Application Options:
  -V, --version                          Show version
  -L, --list-supported                   List supported devices/modules/decoders
  --list-supported-wiki                  List supported decoders (MediaWiki)
  -l, --loglevel                         Set loglevel (5 is most verbose)
  -d, --driver                           The driver to use
  -c, --config                           Specify device configuration options
  -i, --input-file                       Load input from file
  -I, --input-format                     Input format
  -o, --output-file                      Save output to file
  -O, --output-format                    Output format
  -T, --transform-module                 Transform module
  -C, --channels                         Channels to use
  -g, --channel-group                    Channel groups
  -t, --triggers                         Trigger configuration
  -w, --wait-trigger                     Wait for trigger
  -P, --protocol-decoders                Protocol decoders to run
  -A, --protocol-decoder-annotations     Protocol decoder annotation(s) to show
  -M, --protocol-decoder-meta            Protocol decoder meta output to show
  -B, --protocol-decoder-binary          Protocol decoder binary output to show
  --protocol-decoder-samplenum           Show sample numbers in decoder output
  --protocol-decoder-jsontrace           Output in Google Trace Event format (JSON)
  --scan                                 Scan for devices
  -D, --dont-scan                        Don't auto-scan (use -d spec only)
  --show                                 Show device/format/decoder details
  --time                                 How long to sample (ms)
  --samples                              Number of samples to acquire
  --frames                               Number of frames to acquire
  --continuous                           Sample continuously
  --get                                  Get device options only
  --set                                  Set device options only
  --list-serial                          List available serial/HID/BT/BLE ports

```

### 2.2 동작 선택 우선순위 [소스]

`main()`은 아래 순서로 **첫 번째로 해당하는 동작 하나만** 수행한다 (https://github.com/sigrokproject/sigrok-cli/blob/sigrok-cli-0.7.2/main.c):

```text
--version → -L → --list-supported-wiki → (-i 와 --show) → (-I 와 --show) → (-O 와 --show)
→ (-T 와 --show) → --scan → (-P 와 --show) → --show → -i(디코드/변환) → --get → --set
→ (--samples|--time|--frames|--continuous: 캡처) → --list-serial → help
```

- `-P`를 주면 디코더 등록은 동작 선택보다 먼저 수행된다. 따라서 `-P`의 오류(없는 디코더, 잘못된 옵션)는 어떤 동작이든 먼저 실패시킨다.
- `-B`를 `-P` 없이 주면 `Option -B will not take effect in the absence of -P.`로 종료 [소스].

### 2.3 로그·종료 코드 규칙 [소스+실측]

`main.c`의 `logger()` 원문 [소스]:

```c
	if (log_level & (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_WARNING)
			|| opt_loglevel > SR_LOG_WARN) {
		fprintf(stderr, "%s\n", message);
		fflush(stderr);
	}

	if (log_level & (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL))
		exit(1);
```

- 모든 로그는 **stderr**. 데이터/주석은 **stdout**.
- `g_critical`(대부분의 사용자 오류) → 메시지 출력 후 **exit 1**. 그 외에는 `main()`이 `return 0`.
- 따라서 **rc=0이 성공을 뜻하지 않는 경우가 있다**(5.7 표: 없는 채널 이름, 디코더 `SamplerateError`, 입력 모듈 오타 키, 잘못된 단위의 samplerate). 래퍼는 stderr를 반드시 패턴 검사해야 한다.
- 기본 loglevel은 2 (`gint opt_loglevel = SR_LOG_WARN; /* Show errors+warnings by default. */`, `options.c`) [소스]. `-l 3` 이상이면 **stdout 주석 형식 자체가 바뀌므로**(5.4) 래퍼는 loglevel을 고정해야 한다.

---

## 3. 정보 조회 명령

### 3.1 `--version` [실측]

```text
sigrok-cli 0.7.2

Libraries and features:
- libsigrok 0.5.2/5:1:1 (rt: 0.5.2/5:1:1).
 - Libs:
  - glib 2.67.5 (rt: 2.72.4/7204:4)
  - libzip 1.7.3
  - libserialport 0.1.1/1:0:1 (rt: 0.1.1/1:0:1)
  - libusb-1.0 1.0.25.11696 API 0x01000108
  - hidapi 0.10.1
  - bluez 5.56
  - libftdi 1.5
  - Host: x86_64-pc-linux-gnu, little-endian.
  - SCPI backends: TCP, serial, USBTMC.
- libsigrokdecode 0.5.3/6:1:2 (rt: 0.5.3/6:1:2).
 - Libs:
  - glib 2.71.1 (rt: 2.72.4/7204:4)
  - Python 3.10.2 / 0x30a02f0 (API 1013, ABI 3)
  - Host: x86_64-pc-linux-gnu, little-endian.
```

파싱용 정규식(첫 줄은 `printf("sigrok-cli %s\n\n", ...)` [소스]):

```python
import re
CLI_RE  = re.compile(r'^sigrok-cli (\S+)$', re.M)
SR_RE   = re.compile(r'^- libsigrok (\S+?)/(\S+) \(rt: (\S+?)/(\S+)\)\.$', re.M)
SRD_RE  = re.compile(r'^- libsigrokdecode (\S+?)/(\S+) \(rt: (\S+?)/(\S+)\)\.$', re.M)
```

래퍼는 시작 시 버전을 확인해 0.7.2 미만이면 jsontrace·`-A` row 기능을 끄고, libsigrokdecode 버전으로 annotation 이름 체계(0.5.3 vs master)를 판단한다.

### 3.2 `-L` / `--list-supported` [실측+소스]

섹션 헤더와 줄 형식: `printf("  %-20s %s\n", id, longname)` [소스] (`show.c`). id가 20자를 넘으면 공백 하나로 붙는다. 섹션 사이에 빈 줄. 헤더 원문 [실측]:

```text
Supported hardware drivers:
  agilent-dmm          Agilent U12xx series DMMs
  ...
  arachnid-labs-re-load-pro Arachnid Labs Re:load Pro
  ...
  fx2lafw              fx2lafw (generic driver for FX2 based LAs)
  ...

Supported input formats:
  binary               Raw binary logic data
  chronovu-la8         ChronoVu LA8/LA16 native file format data
  csv                  Comma-separated values
  logicport            Intronix LA1034 LogicPort project
  null                 Null input (discards all input)
  raw_analog           Raw analog data without header
  trace32_ad           Lauterbach Trace32 logic analyzer data
  vcd                  Value Change Dump data
  wav                  Microsoft WAV file format data

Supported output formats:
  analog               ASCII analog data values and units
  ascii                ASCII art logic data
  binary               Raw binary logic data
  bits                 0/1 digits logic data
  chronovu-la8         ChronoVu LA8 native file format data
  csv                  Comma-separated values
  hex                  Hexadecimal digits logic data
  null                 Null output (discards all data)
  ols                  OpenBench Logic Sniffer data
  srzip                srzip session file format data
  vcd                  Value Change Dump data
  wav                  Microsoft WAV file format data
  wavedrom             WaveDrom.com file format

Supported transform modules:
  invert               Invert values
  nop                  Do nothing
  scale                Scale analog values by a specified factor

Supported protocol decoders:
  ac97                 Audio Codec '97
  ...
  guess_bitrate        Guess bitrate/baudrate
  i2c                  Inter-Integrated Circuit
  ...
  spi                  Serial Peripheral Interface
  spiflash             SPI flash/EEPROM chips
  ...
  uart                 Universal Asynchronous Receiver/Transmitter
  ...
```

- 이 빌드에서 하드웨어 드라이버 162개, 디코더 111개 [실측]. 입력 형식 목록에 `srzip`은 **없다** — `.sr`은 입력 모듈이 아니라 세션 파일 로더가 처리한다(5.1).
- `-l 3` 이상이면 디코더마다 설명 줄 `printf("  %-20s %s\n", "", dec->desc)`이 한 줄 더 붙는다 [소스].
- 파싱: 섹션 헤더(`^Supported (.+):$`) 다음 줄들을 `^  (\S+)\s+(.*)$`로 분리.

### 3.3 `--scan` [실측+소스]

장치 없음(`-d fx2lafw --scan`, USB 장치 없음) → **stdout 비어 있음, stderr 비어 있음, rc=0** [실측]. 즉 "못 찾음"은 빈 출력으로 판단한다.

demo 드라이버 [실측]:

```text
$ sigrok-cli --scan
The following devices were found:
demo - Demo device with 13 channels: D0 D1 D2 D3 D4 D5 D6 D7 A0 A1 A2 A3 A4
```

```text
$ sigrok-cli -d demo:logic_channels=16:analog_channels=0 --scan
The following devices were found:
demo - Demo device with 16 channels: D0 D1 D2 D3 D4 D5 D6 D7 D8 D9 D10 D11 D12 D13 D14 D15
```

줄 생성 규칙 [소스] (`print_dev_line()`, https://github.com/sigrokproject/sigrok-cli/blob/sigrok-cli-0.7.2/show.c):

```text
<driver>[:conn=<conn>] - [<vendor> ][<model> ][<version> ][[S/N: <serial>] ]with <N> channels: <name1> <name2> ...
<driver>[:conn=<conn>] - ... with 1 channel: <name>
```

- `:conn=`은 드라이버가 `SR_CONF_CONN` get을 지원할 때만 붙는다. fx2lafw는 `"%d.%d"`(bus.address) 형식을 돌려주며, **펌웨어 업로드 직후 재열거 전(address==255)이면 get이 실패해 `:conn=` 없이** 출력된다 [소스] (`fx2lafw/api.c` `config_get`).
- 따라서 fx2lafw Saleae 클론의 예상 출력(**소스 기반, 실기 미확인**):

```text
The following devices were found:
fx2lafw:conn=1.6 - Saleae Logic with 8 channels: D0 D1 D2 D3 D4 D5 D6 D7
```

  (`1.6`은 예시 값. 첫 스캔에서는 `fx2lafw - Saleae Logic with 8 channels: ...`처럼 conn이 빠질 수 있다.)
- man page 예시 `fx2lafw:conn=3.26 - CWAV USBee SX with 8 channels: 0 1 2 3 4 5 6 7`와 `Digitek DT4000ZC with 1 channel: P1`(드라이버 접두어 없음)은 **구버전 형식**이다. libsigrok 0.5.2 fx2lafw는 채널을 `sprintf(channel_name, "D%d", j)`로 만든다 [소스].
- 파싱 정규식:

```python
DEV_RE = re.compile(r'^(?P<driver>[^\s:]+)(?::conn=(?P<conn>\S+))? - (?P<desc>.*?)'
                    r'(?: \[S/N: (?P<sn>[^\]]*)\])? ?with (?P<n>\d+) channels?: (?P<chans>.*)$')
```

- `-d` 없이 캡처하면 sigrok-cli는 스캔 결과 중 **demo가 아닌 장치가 정확히 1개면 그것을 자동 선택**한다(2개 이상이면 `sigrok-cli only supports one device for capturing.`) [소스] (`session.c` `run_session()`). → 래퍼는 항상 `-d <driver>[:conn=...]`를 명시해야 한다(전원공급기 같은 출력 장치가 자동 선택되는 사고 방지, 11장).
- 시리얼 기반 장치는 자동 탐지되지 않으므로 `conn`이 필요하다: `-d ols:conn=/dev/ttyACM0 --scan` [문서].
- USB `conn` 문법 [소스] (`usb.c`): `^([0-9a-fA-F]{4})\.([0-9a-fA-F]{4})$`(VID.PID, 먼저 검사) 또는 `^(\d+)\.(\d+)$`(bus.address).

### 3.4 `--show`

#### (a) 드라이버/장치 — demo [실측]

```text
$ sigrok-cli -d demo --show
Driver functions:
    Demo device
    Logic analyzer
    Oscilloscope
Scan options:
    logic_channels
    analog_channels
    limit_frames
demo - Demo device with 13 channels: D0 D1 D2 D3 D4 D5 D6 D7 A0 A1 A2 A3 A4
Channel groups:
    Logic: channels D0 D1 D2 D3 D4 D5 D6 D7
    Analog: channels A0 A1 A2 A3 A4
    A0: channel A0
    A1: channel A1
    A2: channel A2
    A3: channel A3
    A4: channel A4
Supported configuration options across all channel groups:
    continuous: on, off
    limit_samples: 0 (current)
    limit_time: 0 (current)
    limit_frames: 0 (current)
    samplerate (1 Hz - 1 GHz in steps of 1 Hz)
    averaging: on, off (current)
    avg_samples: 0 (current)
    Supported triggers: 0 1 r f e 
    captureratio: 20 (current)
```

(`Supported triggers:` 줄은 각 문자 뒤에 공백이 붙어 **끝에 공백이 남는다** — `printf("%c ", c)` [소스].)

#### (b) 드라이버만 있고 장치 없음 — fx2lafw [실측]

```text
$ sigrok-cli -d fx2lafw --show
Driver functions:
    Logic analyzer
Scan options:
    conn
```

stderr `No devices found.`, **rc=1**.

#### (c) fx2lafw 장치 연결 시 — **소스 기반, 실기 미확인**

devopts 순서(`fx2lafw/api.c`): `SR_CONF_CONTINUOUS`, `SR_CONF_LIMIT_SAMPLES`, `SR_CONF_CONN`, `SR_CONF_SAMPLERATE`, `SR_CONF_TRIGGER_MATCH`, `SR_CONF_CAPTURE_RATIO`. samplerate가 목록형이면 `show.c`는 다음 형식으로 찍는다 [소스]:

```c
printf("    %s", srci->id);                  /* "    samplerate" */
printf(" - supported samplerates:\n");
printf("      %s", s);                       /* sr_samplerate_string(): "20 kHz" ... */
if (rate == cur_rate) printf(" (current)");
printf("\n");
```

범위형(demo)은 `    samplerate (1 Hz - 1 GHz in steps of 1 Hz)`. fx2lafw의 목록 값(0.5.2 `samplerates[]`) [소스]: `20 kHz, 25 kHz, 50 kHz, 100 kHz, 200 kHz, 250 kHz, 500 kHz, 1 MHz, 2 MHz, 3 MHz, 4 MHz, 6 MHz, 8 MHz, 12 MHz, 16 MHz, 24 MHz, 48 MHz`. 래퍼는 이 목록을 `--show`에서 **파싱해 사용자가 요청한 값이 목록에 있는지 검증**한다(목록 밖 값은 드라이버가 거부).

#### (d) 디코더 — `-P uart --show` [실측, libsigrokdecode 0.5.3]

```text
ID: uart
Name: UART
Long name: Universal Asynchronous Receiver/Transmitter
Description: Asynchronous, serial bus.
License: gplv2+
Possible decoder input IDs:
- logic
Possible decoder output IDs:
- uart
Decoder tags:
Annotation classes:
- rx-data: RX data
- tx-data: TX data
- rx-start: RX start bits
- tx-start: TX start bits
- rx-parity-ok: RX parity OK bits
- tx-parity-ok: TX parity OK bits
- rx-parity-err: RX parity error bits
- tx-parity-err: TX parity error bits
- rx-stop: RX stop bits
- tx-stop: TX stop bits
- rx-warnings: RX warnings
- tx-warnings: TX warnings
- rx-data-bits: RX data bits
- tx-data-bits: TX data bits
- rx-break: RX break
- tx-break: TX break
- rx-packet: RX packet
- tx-packet: TX packet
Annotation rows:
- rx-data-bits (RX bits): rx-data-bits
- rx-data (RX): rx-data, rx-start, rx-parity-ok, rx-parity-err, rx-stop
- rx-warnings (RX warnings): rx-warnings
- rx-break (RX break): rx-break
- rx-packets (RX packets): rx-packet
- tx-data-bits (TX bits): tx-data-bits
- tx-data (TX): tx-data, tx-start, tx-parity-ok, tx-parity-err, tx-stop
- tx-warnings (TX warnings): tx-warnings
- tx-break (TX break): tx-break
- tx-packets (TX packets): tx-packet
Binary classes:
- rx: RX dump
- tx: TX dump
- rxtx: RX/TX dump
Required channels:
None.
Optional channels:
- rx (RX): UART receive line
- tx (TX): UART transmit line
Options:
- baudrate: Baud rate (default 115200)
- data_bits: Data bits (5, 6, 7, 8, 9, default 8)
- parity: Parity ('none', 'odd', 'even', 'zero', 'one', 'ignore', default 'none')
- stop_bits: Stop bits (0.0, 0.5, 1.0, 1.5, default 1.0)
- bit_order: Bit order ('lsb-first', 'msb-first', default 'lsb-first')
- format: Data format ('ascii', 'dec', 'hex', 'oct', 'bin', default 'hex')
- invert_rx: Invert RX ('yes', 'no', default 'no')
- invert_tx: Invert TX ('yes', 'no', default 'no')
- rx_packet_delim: RX packet delimiter (decimal) (default -1)
- tx_packet_delim: TX packet delimiter (decimal) (default -1)
- rx_packet_len: RX packet length (default -1)
- tx_packet_len: TX packet length (default -1)
Documentation:
UART (Universal Asynchronous Receiver Transmitter) is a simple serial
...
```

- `Decoder tags:` 아래가 비어 있다(0.5.3 C 라이브러리가 tags를 노출하지 않음) [실측].
- 파서 요령: 섹션 헤더(`^[A-Z][A-Za-z ]+:$` 또는 `^ID: `)로 분할, 항목은 `^- (\S+): (.*)$`, 행은 `^- (\S+) \((.*)\): (.*)$`, 옵션은 `^- (\w+): (.*?) \((.*)\)$`. `Documentation:` 이후는 자유 텍스트.

#### (e) 입력/출력 모듈 옵션 [실측]

```text
$ sigrok-cli -I binary --show
ID: binary
Name: Binary
Description: Raw binary logic data
Options:
  numchannels: The number of (logic) channels in the data (default 8)
  samplerate: The sample rate of the (logic) data in Hz (default 0)

$ sigrok-cli -I vcd --show
ID: vcd
Name: VCD
Description: Value Change Dump data
Options:
  numchannels: The number of (logic) channels in the data (default 0)
  skip: Skip samples until the specified timestamp; < 0: Skip until first timestamp listed; 0: Don't skip (default -1)
  downsample: Downsample, i.e. divide the samplerate by the specified factor (default 1)
  compress: Compress idle periods longer than the specified value (default 0)

$ sigrok-cli -I csv --show
ID: csv
Name: CSV
Description: Comma-separated values
Options:
  column_formats: Text columns data types. A comma separated list of [<cols>]<fmt>[<bits>] items. * for all remaining columns. - ignores columns, x/o/b/l logic data, a (and digits) analog data, t timestamps. (default '')
  single_column: Simple single-column mode, exclusively use text from the specified column (number starting at 1). Obsoleted by 'column_formats=4-,x16'. (default 0)
  first_column: First column with logic data in simple multi-column mode (number starting at 1, default 1). Obsoleted by 'column_formats=4-,*l'. (default 1)
  logic_channels: Logic channel count, required in simple single-column mode, defaults to "all remaining columns" in simple multi-column mode. Obsoleted by 'column_formats=8l'. (default 0)
  single_format: The input text number format of simple single-column mode: bin, hex, oct. Obsoleted by 'column_formats=x8'. (default 'bin', possible values 'bin', 'hex', 'oct')
  start_line: The line number at which to start processing input text (default: 1). (default 1)
  header: Use the first processed line's column captions (when available) as channel names. Enabled by default. (default true)
  samplerate: The input data's sample rate in Hz. No default value. (default 0)
  column_separator: The sequence which separates text columns. Non-empty text, comma by default. (default ',')
  comment_leader: The text which starts comments at the end of text lines, semicolon by default. (default ';')

$ sigrok-cli -O bits --show
ID: bits
Name: Bits
Description: 0/1 digits logic data
Options:
  width: Number of samples per line (default 64)

$ sigrok-cli -O hex --show
...
  width: Number of samples per line (default 192)

$ sigrok-cli -O ascii --show
...
  width: Number of samples per line (default 74)
  charset: Characters for 0/1 bits (and fall/rise edges) (default '."\\/')

$ sigrok-cli -O csv --show
ID: csv
Name: CSV
Description: Comma-separated values
Options:
  gnuplot: gnuplot script file name (default '')
  scale: Scale gnuplot graphs (default true)
  value: Character to print between values (default ',')
  record: String to print between records (default '\n')
  frame: String to print between frames (default '\n')
  comment: String used at start of comment lines (default ';')
  header: Output header comment with capture metdata (default true)
  label: Type of column labels (default 'units', possible values 'units', 'channel', 'off')
  time: Output sample time as column 1 (default false)
  trigger: Output trigger indicator as last column  (default false)
  dedup: Set to false to output duplicate rows (default false)

$ sigrok-cli -O vcd --show
ID: vcd
Name: VCD
Description: Value Change Dump data

$ sigrok-cli -O binary --show
ID: binary
Name: Binary
Description: Raw binary logic data

$ sigrok-cli -O srzip --show
ID: srzip
Name: srzip
Description: srzip session file format data
Options:
```

(오타 `metdata`, 이중 공백 `column  (default` 는 원문 그대로.)

#### (f) 입력 파일 요약 — `-i <file> --show` [실측]

```text
$ sigrok-cli -i uart1m.sr --show
Samplerate: 1000000
Channels: 2
- D0: logic
- D1: logic
Logic unitsize: 1
Logic sample count: 8608
```

- samplerate를 모르면 `Samplerate:` 줄 자체가 없다(예: `-I csv`에 samplerate 미지정) [실측].
- `.sr`을 다시 읽으면 메타데이터에 없는 채널은 숫자 이름(`2`, `3`, ...)으로 생성된다(8.2) [실측]:

```text
Samplerate: 200000
Channels: 8
- D0: logic
- D1: logic
- 2: logic
- 3: logic
...
```

이 명령은 캡처 후 파일 검증, 샘플 수/샘플레이트 확인에 쓰기 좋다(디코드보다 훨씬 빠름).

### 3.5 `--get`, `--list-serial`

```text
$ sigrok-cli -d demo --get samplerate
200000
$ sigrok-cli -d demo --config samplerate=1m --get samplerate
1000000
```

[실측] 값만 한 줄로 출력. `--get`은 읽기 전용이므로 허용해도 되지만, **`--set`은 래퍼에서 금지**(11장).

`--list-serial` 형식 [소스]: 포트가 있으면

```text
Available serial/HID/BT/BLE ports:
  <name>\t<description>
```

(`printf("  %s\t%s\n", port->name, port->description)`), 없으면 아무것도 출력하지 않는다. 이 WSL2 머신에서는 stdout 빈 채로 stderr에 `sr: bt-bluez: devid failed`가 두 번 찍히고 rc=0 [실측].

---

## 4. 캡처

### 4.1 기본 형태

```bash
sigrok-cli -d fx2lafw --config samplerate=4m --samples 4m --channels D0=RX,D1=TX -o /path/cap.sr
sigrok-cli -d fx2lafw --config samplerate=4m --time 3s   --channels D0=RX       -o /path/cap.sr
```

- `-d <driver>[:key=value[:key=value...]]` — 드라이버 옵션은 `:`로 구분(그래서 값에 `:`를 넣을 수 없다) [문서]. 예: `-d demo:logic_channels=16:analog_channels=0` [실측].
- `-c/--config key=value[:key=value...]`, 여러 번 사용 가능. 첫 항목을 `channel_group=<name>`으로 주면 그 목록에만 채널 그룹 적용 [문서].
- 캡처는 **`--samples`/`--time`/`--frames`/`--continuous` 중 하나가 있어야** 시작된다(2.2).
- **`-P`와 `-o`를 함께 주면 파일이 만들어지지 않는다.** `datafeed_in()`이 `if (!do_props && o && !opt_pds)`일 때만 출력 모듈로 데이터를 보낸다 [소스] (`session.c`); `-d demo ... -P uart:rx=RX -A uart=rx-data -o both.sr` 실행 후 `both.sr` 없음 [실측]. → **캡처(파일 저장)와 디코드는 두 번의 호출로 분리**한다.
- 같은 경로로 다시 저장하면 기존 파일을 지우고 새로 쓴다(`g_unlink(outc->filename)`, `output/srzip.c`) [소스+실측].

### 4.2 `--config samplerate=` 단위 문법 [소스+실측]

장치 옵션 중 `samplerate`는 `sr_parse_sizestring()`으로 파싱한다 (https://github.com/sigrokproject/libsigrok/blob/libsigrok-0.5.2/src/strutil.c). 접미사: `k/K`=1e3, `m/M`=1e6, `g/G`=1e9 (`t`,`p`,`e`도 있음), 끝에 `Hz`(대소문자 무관) 허용, 공백 허용. **소문자 `m`도 mega**.

| 입력 | 결과 (`--get samplerate`) |
|---|---|
| `1000000`, `1000000Hz`, `1m`, `1M`, `1MHz`, `1mhz`, `"1 MHz"` | `1000000` |
| `2400k` | `2400000` |
| `24m`, `24MHz` | `24000000` |
| `1k` / `1g` | `1000` / `1000000000` |
| **`1.5m`** | **`1`** ← 버그 |
| `"1.5 MHz"` (공백 있음) | `1500000` |
| `2.4m` | `2` (메타데이터에도 `samplerate=2 Hz`로 저장됨) |
| `abc` | stderr `Invalid value: 'abc' for option 'samplerate'`, rc=1 |

원인: 소수부를 `g_ascii_strtod`로 읽은 뒤 루프 끝의 `s++`가 바로 다음 문자(단위)를 건너뛴다 [소스]. **래퍼는 항상 정수 Hz(`samplerate=1500000`)만 넘긴다.** 같은 함수가 `--samples`, `--frames`에도 쓰여 `--samples 1.5k` → 1 샘플 [실측].

### 4.3 `--samples` / `--time` / `--frames` / `--continuous`

- `--samples N[k|m|g]` — `--samples 3m` = 3,000,000 [문서]. `--samples 2k` → 2000 [실측].
- `--time` — `sr_parse_timestring()` [소스]: 정수 + 선택 접미사 `s` 또는 `ms`(공백 허용)만. `--time 10` = 10 ms, `--time 1s` = 1000 ms [실측]. **`--time 0.5s` → `Invalid time '0.5s'`, rc=1** [실측]. `us`, 소수 불가.
- 장치가 `SR_CONF_LIMIT_MSEC`을 지원하지 않으면(fx2lafw 등) sigrok-cli가 `limit_samples = samplerate * time_msec / 1000`으로 변환한다. 0이 되면 `Not enough time at this samplerate.` [소스] (`set_limit_time()`).
- 장치가 `limit_samples` 범위를 공개하면 초과 시 `The device can store only <N> samples with the current settings.`(g_critical → exit 1) [소스]. fx2lafw는 스트리밍이라 해당 없음.
- 요청보다 적게 받으면 경고 `Device only sent <N> samples.` (rc에는 영향 없음) [실측: `-w` 사용 시 `Device only sent 15 samples.`].
- `--continuous`는 키 입력으로 멈춘다 [소스] (`anykey.c`): stdin에 `G_IO_IN` 감시를 걸고 아무 바이트나 오면 `sr_session_stop()`. 결과 [실측]:
  - **stdin이 `/dev/null`이면 즉시 EOF로 판정되어 캡처가 곧바로 끝난다**(`-l 3`에서 `Press any key to stop acquisition.` 직후 `sr: session: Stopping.`).
  - stdin을 PIPE로 열고 1.0초 뒤 `b'q'`를 쓰면 정상 종료(rc=0), `.sr`은 로직 청크 27개(zip 엔트리 29개 = `version` + `metadata` + 27)로 유효.
  - SIGINT/SIGTERM에는 핸들러가 없어 rc=-2/-15로 죽는다. 로컬 시험에서는 `.sr`이 여전히 로드 가능(`unzip -t` 오류 없음)했지만, 청크 쓰기 도중 신호가 오면 손상될 수 있다 **(미확인)**.
  - 또한 `add_anykey()`가 stdin 터미널 속성을 바꾼다(`tcsetattr`). **MCP stdio 서버에서는 sigrok-cli가 MCP의 stdin을 상속하면 안 된다.**
- 권장: 유한 캡처(`--samples`/`--time`) + `stdin=DEVNULL`. continuous가 꼭 필요하면 `stdin=PIPE`로 열고 정지 시 1바이트를 쓴다. 어느 경우든 **stdout도 상속 금지**(파일로 받거나 PIPE).

### 4.4 `--channels` (선택·이름 바꾸기) [문서+소스+실측]

- 쉼표 목록, `이름=새이름`으로 rename, 왼쪽부터 처리(오른쪽이 덮어씀): `1=CS,CS=MISO` → 채널 1의 이름은 MISO [문서].
- 범위 `a-b`는 **채널 이름이 숫자일 때만** 동작한다(`strtol` + 이름 `"%d"` 검색) [소스] (`parse_channelstring()`):
  - `-d demo -C D0-D3` → `Invalid channel 'D0'.` rc=1 [실측]
  - `-d demo -C 0-3` → `unknown channel '0'.` rc=1 [실측]
  - man page의 `--channels 1=CLK,2-4,7`은 숫자 이름 채널(구버전 fx2lafw, 현재의 dreamsourcelab-dslogic/saleae-logic16, binary 입력)에서만 유효. fx2lafw 0.5.2는 `D0`..`D7` → **`-C D0,D1,D2,D3`처럼 나열**한다.
- rename 이후에는 **새 이름으로만** 참조된다: `-C D0=RX -t D0=f` → `Invalid channel 'D0'.` rc=1, `-t RX=f`는 동작 [실측]. 디코더 매핑도 같다: `-C D0=RX ... -P uart:rx=D0` → `cli: No channel with name "D0" found.`(rc=0!) [실측].
- `.sr`에는 rename된 이름이 저장된다(`probe1=RX`).
- **연속된 앞쪽 채널(D0부터) 또는 전체 채널을 캡처하고 이름만 바꾸는 것을 권장.** 비연속 선택(예 `-C D0,D3`) 시 출력 모듈마다 비트 위치 해석이 달라질 수 있다: demo 드라이버로 `-C D0,D3=RX`를 `.sr`로 저장하면 메타데이터는 `probe1=D0`, `probe4=RX`인데 데이터는 비트 0·1만 사용(0x01/0x02/0x03)해 되읽은 RX가 전부 0이 되었다. VCD 출력 모듈은 소스 주석상 "dense" 인덱스(`index = p;`)를 쓰고 bits·csv 출력은 채널 인덱스(`ch->index`)를 쓴다 [실측+소스] (`output/vcd.c`, `output/bits.c`, `output/csv.c`). fx2lafw는 포트 전체(8/16비트)를 그대로 보내므로 비트 i = Di 이지만(`fx2lafw/protocol.c`), 래퍼는 이 차이에 의존하지 않도록 한다.

### 4.5 `--triggers` / `--wait-trigger` [문서+소스+실측]

- 문법: `<channel>=<chars>[,<channel>=<chars>...]`. 채널은 **이름**(rename 후 이름, enabled 채널만).
- 문자: `0` low, `1` high, `r` rising, `f` falling, `e` either edge, `o` over, `u` under(아날로그) [소스] (`parse_trigger_match()`).
- **문자열의 n번째 문자는 n번째 스테이지**: `D0=10` = 1단계 D0 high, 2단계 D0 low [소스] (`sr_trigger_stage_add`).
- 장치가 지원하는 문자는 `--show`의 `Supported triggers:` 줄. 잘못된 문자 → `Invalid trigger match 'x'.` rc=1 [실측]. 장치가 지원하지 않는 문자 → `Trigger match '<c>' not supported by device.`, 트리거 미지원 장치 → `Device doesn't support any triggers.` (둘 다 g_critical → rc=1) [소스].
- fx2lafw 계열은 하드웨어 트리거가 없고 소프트웨어 트리거(wiki 인포박스 `none (SW-only)`, https://sigrok.org/wiki/MCU123_Saleae_Logic_clone). trigger_matches는 `0 1 r f e` [소스].
- `--wait-trigger`(`-w`): 트리거 전 데이터(pre-trigger)를 출력하지 않는다 [문서]. `captureratio`(pre-trigger 비율 %)는 장치 옵션(`-c captureratio=1`).
- bits 출력에는 트리거 위치 표시 줄이 붙는다 [실측]:

```text
$ sigrok-cli -d demo -C D0=RX -t RX=f --samples 16 -O bits:width=16
libsigrok 0.5.2
Acquisition with 1/13 channels at 200 kHz
RX:10001111 00001111
T: ^ 1
```

- UART 부트 로그용: `-t RX=f -c captureratio=1`(첫 start bit 앞 여유) 권장. wiki도 "pre-trigger를 0%로 하면 첫 start bit를 놓칠 수 있고 1%로 하면 해결"이라고 적는다 (https://sigrok.org/wiki/Protocol_decoder:Uart).

### 4.6 출력 형식 `-o` / `-O` [문서+소스+실측]

- 기본값 [소스] (`sigrok-cli.h`): 파일이 있으면 `DEFAULT_OUTPUT_FORMAT_FILE "srzip"`, 없으면 `DEFAULT_OUTPUT_FORMAT_NOFILE "bits:width=64"`.
- **확장자로 형식을 추론하지 않는다**: `-o t.vcd`(`-O` 없음) → `t.vcd: Zip archive data` [실측]. 항상 `-O`를 명시.
- `-O srzip`을 `-o` 없이 → `Failed to initialize output module.` rc=1 [실측].
- 형식 옵션: `-O <fmt>[:key=value...]`, 값 없는 boolean은 true (`-O csv:dedup:header=false`) [문서]. **출력/입력 모듈의 정수 옵션은 `strtoul(s, NULL, 10)`으로 파싱**되어 단위 접미사가 무시된다(5.1) [소스] (`generic_arg_to_opt()`, `parsers.c`).
- 모르는 출력/입력 모듈 키는 경고만 하고 계속한다 — 입력 쪽 실측: `Unknown keyword: sample_rate.` rc=0.

각 형식의 실제 출력 [실측, `-d demo`]:

```text
$ sigrok-cli -d demo --samples 70 -C D0,D1 -O bits
libsigrok 0.5.2
Acquisition with 2/13 channels at 200 kHz
D0:10001111 00001111 10001111 00001111 10001111 01110111 11111111 00111111
D1:01110111 10011111 01110111 01110111 01110111 01101111 11111111 00111111
D0:100011
D1:011101

$ sigrok-cli -d demo --samples 70 -C D0,D1 -O hex
libsigrok 0.5.2
Acquisition with 2/13 channels at 200 kHz
D0:8f 0f 8f 0f 8f 77 ff 3f 8c 
D1:77 9f 77 77 77 6f ff 3f 74 

$ sigrok-cli -d demo --samples 30 -C D0,D1 -O ascii
libsigrok 0.5.2
Acquisition with 2/13 channels at 200 kHz
D0:"\../"""\.../""""\../"""\.../"
D1:./""\/"""\./""""\/""\/""\/""\/

$ sigrok-cli -d demo --samples 8 -C D0,D1 -O binary | xxd
00000000: 0102 0202 0103 0303                      ........

$ sigrok-cli -d demo --samples 8 -C D0,D1,D2 -O csv
; CSV generated by libsigrok 0.5.2
; from Demo driver and pattern generator on Sun Oct 18 15:28:01 2026
; Channels (3/13): D0, D1, D2
; Samplerate: 200 kHz
logic,logic,logic
1,0,0
0,1,1
...

$ sigrok-cli -d demo --samples 8 -C D0,D1,D2 -O csv:time=true:header=false
microseconds,logic,logic,logic
5,1,0,0
10,0,1,1
...

$ sigrok-cli -d demo --samples 4 -C D0,D1 -O csv:label=channel:header=false
D0,D1
1,0
0,1
...
```

- bits/hex/ascii: 헤더 2줄(`libsigrok 0.5.2`, `Acquisition with <enabled>/<total> channels at <rate>`), 이후 `<채널이름>:` 접두 블록 반복. hex 줄 끝에 공백이 남는다.
- binary: 헤더 없음, 샘플당 unitsize 바이트(비트 i = 채널 i).
- csv: 기본 `label=units`라 헤더 행이 `logic,logic,...`로 쓸모가 없다 → **`label=channel`** 사용. `time=true`의 첫 행이 0이 아니라 1 sample period(5 µs @200 kHz)에서 시작 [실측]. dedup 기본 off(중복 행 모두 출력, 8608 샘플 → 8608+1 줄) [실측].
- vcd: 9장.

### 4.7 캡처 레시피 (Skill용)

```bash
# 0) 장치 확인
sigrok-cli -d fx2lafw --scan
sigrok-cli -d fx2lafw --show            # samplerate 목록 확인

# 1) UART 부트 로그(보레이트 미상): 8 MHz로 5초, 첫 하강 에지에서 트리거
sigrok-cli -d fx2lafw --config samplerate=8000000:captureratio=1 \
  --channels D0=RX,D1=TX --triggers RX=f --time 5s -O srzip -o /cases/<id>/la/uart_boot.sr

# 2) 파일 검증
sigrok-cli -i /cases/<id>/la/uart_boot.sr --show

# 3) SPI 플래시 부팅 스니핑(4채널)
sigrok-cli -d fx2lafw --config samplerate=24000000 \
  --channels D0=CS,D1=CLK,D2=MOSI,D3=MISO --samples 48m -O srzip -o /cases/<id>/la/spi_boot.sr
```

(사람이 프로브를 연결하고 **캡처 시작 후** 타깃 전원을 넣는다. 위 명령의 실기 성공 여부는 장치별로 **미확인**.)

---

## 5. 디코딩 (기존 파일)

### 5.1 입력 파일 `-i` / `-I`

- `-i file.sr` → 먼저 세션 파일(srzip)인지 검사(`sr_sessionfile_check()`: zip이고 `version` 파일 값이 1..2, `metadata` 존재) [소스] (https://github.com/sigrokproject/libsigrok/blob/libsigrok-0.5.2/src/session_file.c). 아니면 입력 모듈 자동 감지.
- `-i -` = stdin [문서].
- 자동 감지 결과 [실측]:
  - `.sr`(직접 만든 파일 포함), `.vcd` → 자동 감지됨.
  - `.csv` → 자동 감지되지만 samplerate가 없다(`Samplerate:` 줄 없음).
  - raw `.bin` → `Error: no input module found for this file.` rc=1 → `-I binary:...` 필수.
  - 없는 파일 → stderr `sr: session-file: Not a regular file: nonexist.sr.` / `sr: input: Failed to open nonexist.sr: No such file or directory` / `Error: no input module found for this file.` rc=1.

**binary 입력** — 채널 이름은 `0`,`1`,... [실측]:

```text
$ sigrok-cli -i uart1m.bin -I binary:numchannels=2:samplerate=1000000 --show
Samplerate: 1000000
Channels: 2
- 0: logic
- 1: logic
Logic unitsize: 1
Logic sample count: 8608
```

**입력 모듈 samplerate는 정수 Hz만 된다** [실측+소스]:

| `-I binary:numchannels=2:samplerate=<v>` | 결과 `Samplerate:` |
|---|---|
| `1000000` | `1000000` |
| `1m`, `1mhz`, `1MHz`, `"1 MHz"`, `1M`, `1e6` | **`1`** (경고 없음, rc=0, 디코드 결과는 `[00]` 쓰레기) |

man page 예시 `-I binary:numchannels=4:samplerate=1mhz`는 0.7.2에서 **1 Hz로 해석된다**. 원인은 `generic_arg_to_opt()`의 `g_variant_new_uint64(strtoul(s, NULL, 10))` [소스].

**VCD 입력** — samplerate = 1 / `$timescale` [실측]. 외부 도구의 `1 ns` VCD는 1 GHz로 펼쳐지므로(20 µs → 20000 샘플) 긴 파일은 `-I vcd:downsample=<n>`(예: 10 → `Samplerate: 100000000`)을 쓴다. 채널 이름은 `$var` 이름(`rx`).

**CSV 입력** — 반드시 `-I csv:samplerate=<정수Hz>`; 첫 줄을 채널 이름으로 사용(`header=true` 기본). `-O csv:label=channel:header=false` 로 만든 파일은 `-I csv:samplerate=1000000`으로 손실 없이 되읽힘(디코드 동일) [실측].

### 5.2 `-P` 문법 [문서+소스+실측]

```text
-P <pd>[:<key>=<value>...][,<stacked_pd>[:<key>=<value>...]...]
-P <stack1> -P <stack2> ...        # 여러 -P = 병렬 스택
```

- 각 토큰을 `:`로 나눈 뒤 첫 원소가 디코더 ID. `key=value` 중 **디코더 옵션 ID에 해당하면 옵션**, 아니면 채널 ID(`rx`,`tx`,`clk`...)로 해석, 둘 다 아니면 `Unknown option or channel '<key>'` rc=1 [소스+실측] (`register_pd()`, `decode.c`).
- 옵션 타입은 디코더 기본값 타입을 따른다 [소스]: 정수는 `strtoll(val, &conv, 0)`(0x 접두 허용, 남는 문자 있으면 `Protocol decoder '<Name>' option '<id>' requires a number.` rc=1 — 실측 `baudrate=115k`), 실수는 `strtod`, 문자열은 그대로.
- 채널 값은 **캡처/파일의 채널 이름**(`D0`, `RX`, binary 입력이면 `0`)이다. 없는 이름이면 stderr `cli: No channel with name "D7" found.` 출력 후 **그 매핑을 버리고 계속, rc=0** [실측]. 이때 매핑이 하나도 남지 않으면 libsigrokdecode 기본 매핑(디코더 채널 순서 = 입력 채널 순서, `uart`면 rx=첫 채널, tx=둘째 채널)으로 디코드된다(실측: rx=D7 지정 → D0을 디코드). → **래퍼는 `-i <file> --show`로 채널 목록을 먼저 얻어 이름을 검증**하고, stderr에 `No channel with name`이 있으면 실패 처리.
- 채널을 하나라도 지정하면 지정 안 한 채널은 -1(미사용)이 된다 [소스] (`srd_inst_channel_set_all()`, https://github.com/sigrokproject/libsigrokdecode/blob/libsigrokdecode-0.5.3/instance.c). 아무것도 지정 안 하면 기본 매핑 유지 → **항상 채널을 명시**.
- 스택(`,`)에서는 첫 디코더만 채널을 받는다.
- **값에 `:` `,` `=`를 넣을 방법(이스케이프)이 없다** [소스] (`parse_generic_arg()`는 `g_strsplit(arg, ":", 0)`). 래퍼는 구조화된 파라미터로 인자를 조립하고 이 문자들을 거부한다(콜론 주입 방지).

**인스턴스 ID** [소스+실측]: libsigrokdecode 0.5.3은 인스턴스마다 `"%s-%d"`(디코더ID-번호, 1부터)를 만든다(`srd_inst_new()`). 출력 접두어(`proto_id`)는 기본적으로 인스턴스 ID다(`type_decoder.c`: `/* Default to instance ID, which defaults to class ID. */`). 그래서 주석 줄은 `uart:`가 아니라 **`uart-1:`**로 시작한다. `-P` 순서대로 `uart-1`, `uart-2`...; 스택 `spi,spiflash` → `spi-1`, `spiflash-1`.

```text
$ sigrok-cli -i uart1m.sr -P uart:rx=D0:baudrate=115200:format=ascii -P uart:rx=D1:baudrate=115200:format=ascii -A uart=rx-data
uart-1: U
...
uart-2: [0D]
uart-2: [0A]
uart-2: r
...
```

→ **RX/TX를 구분하려면 한 인스턴스에 rx·tx를 함께 주지 말고 스택을 둘로 나눈다**(`-P uart:rx=RX:... -P uart:rx=TX:...`, `uart-1`=RX선, `uart-2`=TX선). 한 인스턴스에 rx+tx를 주면 기본 출력에서 두 방향 줄이 모두 `uart-1:`로 섞인다 [실측].

### 5.3 `-A` 선택 문법 [문서+소스+실측]

```text
-A <pd>[=<cls_or_row>[:<cls_or_row>...]][,<pd>[=...]...]
```

- `<pd>`는 **디코더 ID**(`uart`), 인스턴스 ID(`uart-1`) 아님. 같은 디코더의 모든 인스턴스에 적용된다(가시성 테이블 키가 `di->decoder->id`) [소스].
- 이름 비교는 `canon_cmp()`: 소문자화 후 영숫자만 남겨 비교 → `RX-DATA`, `rxdata`, `rx_data` 모두 `rx-data`와 같다 [소스].
- 먼저 annotation **클래스** ID를, 없으면 **행(row)** ID를 찾는다(0.7.2부터 row 허용). 이름이 겹치면 클래스가 우선 [소스+문서]. 예: 0.5.3 uart에서 `rx-data`는 클래스(0번)이자 행 → `-A uart=rx-data`는 **데이터 클래스만** 보여준다.
- 없는 이름 → `Annotation 'foo' not found for protocol decoder 'uart'.` rc=1 [실측].
- **`-A`를 생략하면 스택의 모든 디코더의 모든 클래스가 출력**된다. 소스는 하위 디코더 주석을 지우려 하지만 키 불일치(인스턴스 ID `spi-1` vs 디코더 ID `spi`)로 지워지지 않는다 [소스+실측]: `-P spi:...,spiflash`에서 `spi-1` 220줄 + `spiflash-1` 12줄. → **항상 `-A`를 명시**.

### 5.4 주석 출력 라인 형식 [소스+실측]

`show_pd_annotations()` 원문 요지 [소스] (https://github.com/sigrokproject/sigrok-cli/blob/sigrok-cli-0.7.2/decode.c):

```c
	if (opt_pd_samplenum || opt_loglevel > SR_LOG_WARN) show_snum = TRUE;
	if (opt_loglevel > SR_LOG_WARN) show_quotes = TRUE;
	if (opt_loglevel > SR_LOG_INFO) { show_class = TRUE; show_abbrev = TRUE; }
	...
	if (show_snum) printf("%" PRIu64 "-%" PRIu64 " ", pdata->start_sample, pdata->end_sample);
	printf("%s: ", pdata->pdo->proto_id);
	if (show_class) printf("%s: ", ann_descr[0]);
	printf("%s%s%s", quote, pda->ann_text[0], quote);
	if (show_abbrev) for (i = 1; pda->ann_text[i]; i++) printf(" %s%s%s", quote, pda->ann_text[i], quote);
	printf("\n");
```

| 조건 | 형식 | 실측 예 |
|---|---|---|
| 기본(loglevel 2) | `<inst>: <text>` | `uart-1: U` |
| `--protocol-decoder-samplenum` | `<ss>-<es> <inst>: <text>` | `509-579 uart-1: U` |
| `-l 3` | `<ss>-<es> <inst>: "<text>"` | `509-579 uart-1: "U"` |
| `-l 4`/`-l 5` | `<ss>-<es> <inst>: <class>: "<text>" ["<abbr>"...]` | `25-25 i2c-1: start: "Start" "S"` |

- `<text>`는 가장 긴 텍스트(ann_text[0]). `ss`/`es`는 **0부터 시작하는 샘플 번호**, 시간(초) = 샘플 / samplerate.
- 줄은 annotation이 확정되는 순서대로 나오며 `ss` 순으로 정렬되어 있지 않다(예: i2c `180-200 Write`가 `40-180 Address write: 50`보다 먼저) [실측]. 정렬이 필요하면 파서가 정렬.
- 따옴표는 이스케이프되지 않는다 → `-l 3` 이상 출력을 파싱하지 말 것.

**권장 파서** (기본 loglevel + `--protocol-decoder-samplenum` 고정):

```python
ANN_RE = re.compile(r'^(?P<ss>\d+)-(?P<es>\d+) (?P<inst>[^: ]+): (?P<text>.*)$')
# - text 안에 ': '가 들어갈 수 있다 ("Address write: 50") → inst 뒤 첫 ': '에서만 분리.
# - 공백 바이트는 "uart-1:  " (콜론 뒤 공백 2개) → 절대 strip() 하지 말 것. 줄 끝 '\n'만 제거.
# - 디코더 ID = inst.rsplit('-', 1)[0]  (0.5.3 디코더 ID에는 '-'가 없고 '_'만 있음)
for line in proc_stdout.splitlines():   # 텍스트에 개행은 나오지 않음(UART ascii는 [0A]로 표기)
    m = ANN_RE.match(line)
```

한 인스턴스 안에서 여러 클래스를 구분해야 하면 **클래스마다 별도 실행**(`-A uart=rx-data`, 그다음 `-A uart=rx-warnings`)하거나 인스턴스를 나눈다. SPI는 같은 구간에 MISO 줄이 먼저, MOSI 줄이 다음에 나오지만 기본 형식에 클래스가 없다 [실측] → `-A spi=mosi-data`와 `-A spi=miso-data`를 따로 돌리거나 `-B`를 쓴다.

### 5.5 `-B` 바이너리 / `-M` 메타 [소스+실측]

- `-B <pd>[=<binclass>][,<pd>...]` — stdout에 원시 바이트만 쓴다(`fwrite(pdb->data, pdb->size, 1, stdout)`). 클래스 이름은 **정확히 일치**(`strcmp`, canon_cmp 아님)하며 **디코더당 클래스 1개**만 고를 수 있다 [소스].
- 없는 클래스 → `binary output '<x>' not found for protocol decoder '<pd>'.`, 바이너리 출력 없는 디코더 → `Protocol decoder '<pd>' has no binary output.` (둘 다 rc=1) [소스].
- uart(0.5.3) 바이너리 클래스: `rx`, `tx`, `rxtx`. 데이터 1개당 `(data_bits+7)//8` 바이트, big-endian [소스]. **클래스 없이 `-B uart`를 쓰면 rx(또는 tx)와 rxtx가 둘 다 나와 모든 바이트가 두 번** 출력된다 [실측]:

```text
$ sigrok-cli -i uart1m.sr -P uart:rx=D0:tx=D1:baudrate=115200 -B uart=rx | xxd | head -2
00000000: 552d 426f 6f74 2032 3031 362e 3131 2028  U-Boot 2016.11 (
00000010: 4a61 6e20 3031 2032 3032 3029 0d0a 4869  Jan 01 2020)..Hi
$ sigrok-cli -i uart1m.sr -P uart:rx=D0:tx=D1:baudrate=115200 -B uart | head -c 16 | xxd
00000000: 5555 2d2d 4242 6f6f 6f6f 7474 2020 3232  UU--BBoooott  22
```

- spi 바이너리: `miso`, `mosi`; i2c: `address-read`, `address-write`, `data-read`, `data-write` [실측 `--show`]. 예: `-B spi=miso` → `ffef 4018 ffff ffff 6873 7173`, `-B i2c=data-read` → `6873 71` [실측].
- `-M <pd>` 형식: `[<ss>-<es> ]<inst>: <meta_name>: <g_variant_print 값>` [소스]. 실측: `spi-1: Bitrate: 140350`. `-B`, `-M`, `-A`(주석)는 **한 번에 하나만** 출력된다(`-B` > `-M` > 주석 순) [소스] (`main.c`).

### 5.6 `--protocol-decoder-jsontrace` (0.7.2 신규)

Google Trace Event 형식. annotation마다 `"B"`/`"E"` 이벤트 2개, `ts`는 µs(`snum * 1e6 / samplerate`, `%lf`), `pid`=인스턴스 ID, `tid`=그 클래스가 속한 **행 설명**(예: `RX`; 어떤 행에도 없으면 클래스 ID), `name`=가장 긴 텍스트 [소스]. 실측:

```text
{"traceEvents": [
{"ph": "B", "ts": 509.000000, "pid": "uart-1", "tid": "RX", "name": "U"},
{"ph": "E", "ts": 579.000000, "pid": "uart-1", "tid": "RX", "name": "U"},
...
{"ph": "E", "ts": 6135.000000, "pid": "uart-1", "tid": "RX", "name": "[0A]"}
]}
```

**문자열을 JSON 이스케이프하지 않는다** [소스+실측]. `format=ascii`로 `"`와 `\`를 디코드하면 `"name": """`, `"name": "\"`가 출력되어 `json.load`가 `JSONDecodeError: Expecting ',' delimiter`로 실패했다. → 기계 파싱에는 jsontrace를 쓰지 말고 5.4의 텍스트 형식을 쓴다(쓰더라도 `format=hex` 등 안전한 텍스트에 한정).

### 5.7 오류·경고 메시지와 종료 코드 (래퍼 판정용)

| 상황 | stderr (원문) | rc | 출처 |
|---|---|---|---|
| 장치 없음(캡처/`--show`) | `No devices found.` | 1 | 실측 |
| 장치 없음(`--scan`) | (없음, stdout도 빈 값) | 0 | 실측 |
| 없는 드라이버 | `Driver nosuchdriver not found.` | 1 | 실측 |
| 없는 디코더 | `srd: ModuleNotFoundError: Failed to load decoder nosuchpd: import by name failed: No module named 'nosuchpd'` + `Failed to load protocol decoder nosuchpd.` | 1 | 실측 |
| 모르는 PD 옵션/채널 | `Unknown option or channel 'parity_type'` | 1 | 실측 |
| PD 정수 옵션 형식 오류 | `Protocol decoder 'UART' option 'baudrate' requires a number.` | 1 | 실측 |
| 없는 annotation | `Annotation 'foo' not found for protocol decoder 'uart'.` | 1 | 실측 |
| **PD 채널 이름 없음** | `cli: No channel with name "D7" found.` | **0** | 실측 |
| **samplerate 없는 입력을 디코드** | `srd: SamplerateError: Protocol decoder instance uart-1: : Cannot decode without samplerate.` + Python traceback | **0** | 실측 |
| **입력 모듈 오타 키** | `Unknown keyword: sample_rate.` | **0** | 실측 |
| **입력 samplerate 단위 사용(`1m`)** | (없음) | **0** | 실측 |
| 잘못된 시간 | `Invalid time '0.5s'` | 1 | 실측 |
| 잘못된 samplerate | `Invalid value: 'abc' for option 'samplerate'` | 1 | 실측 |
| 장치가 모르는 config 키 | `Failed to set device option 'voltage_target': not applicable.` | 1 | 실측(demo) |
| 채널 지정 오류 | `Invalid channel 'D0'.` / `unknown channel '0'.` | 1 | 실측 |
| 트리거 문자 오류 | `Invalid trigger match 'x'.` | 1 | 실측 |
| `-O srzip`인데 `-o` 없음 | `Failed to initialize output module.` | 1 | 실측 |
| raw 파일에 `-I` 없음 | `Error: no input module found for this file.` | 1 | 실측 |
| 샘플 부족 | `Device only sent 15 samples.` | 0 | 실측 |
| 실장치 2대 이상 | `sigrok-cli only supports one device for capturing.` | 1 | 소스 |
| continuous 미지원 | `This device does not support continuous sampling.` | 1 | 소스 |
| `-B`만 있고 `-P` 없음 | `Option -B will not take effect in the absence of -P.` | 1 | 소스 |

접두어 주의: 실측된 libsigrok 로그는 `sr: <module>: `(예: `sr: session-file: `), libsigrokdecode 로그는 `srd: `로 시작하고, sigrok-cli 자신의 `g_critical` 메시지는 접두어가 없다(위 표). 표에서 [소스]로만 확인한 메시지와 본문의 소스 인용 메시지(예: `Unable to sample at <N>Hz when collecting 16-bit samples.`)는 실제 출력 시 앞에 `sr: <module>: ` 등이 붙을 수 있다 **(미확인)** → 래퍼는 정확한 줄 일치가 아니라 **부분 문자열 일치**로 판정한다.

래퍼 판정 규칙(권장): `rc != 0` → 실패. `rc == 0`이어도 stderr에 `No channel with name`, `Error`, `Traceback`, `Unknown keyword`, `Exception`이 있거나, 디코드 결과가 0줄이면 실패/경고로 보고. 디코드 전에 `-i <file> --show`로 `Samplerate:` 줄 존재를 확인.

---

## 6. 디코더 레퍼런스 (libsigrokdecode 0.5.3 기준, master 차이 병기)

소스: https://github.com/sigrokproject/libsigrokdecode/tree/libsigrokdecode-0.5.3/decoders , master: https://github.com/sigrokproject/libsigrokdecode/tree/master/decoders

### 6.1 `uart`

옵션(0.5.3) — 3.4(d)의 `--show` 원문 참조. **옵션 이름은 `parity`, `data_bits`, `stop_bits`** 이다. man page 예시의 `parity_type`과 wiki(https://sigrok.org/wiki/Protocol_decoder:Uart)의 `num_data_bits`, `parity_type`, `parity_check`, `num_stop_bits`는 **구버전 이름**이라 0.5.3에서 `Unknown option or channel 'parity_type'`(rc=1) [실측].

| 옵션 | 값 | 비고 |
|---|---|---|
| `baudrate` | 정수, 기본 115200 | `bit_width = samplerate / baudrate` (float) |
| `data_bits` | 5,6,7,8,9 (기본 8) | |
| `parity` | none, odd, even, zero, one, ignore | |
| `stop_bits` | 0.0, 0.5, 1.0, 1.5 (기본 1.0) | master는 2.0 추가 |
| `bit_order` | lsb-first, msb-first | |
| `format` | ascii, dec, hex, oct, bin (기본 hex) | 아래 |
| `invert_rx` / `invert_tx` | yes, no | idle-low 신호 |
| `rx_packet_delim` / `tx_packet_delim` | 정수(10진), 기본 -1 | 패킷 annotation(rx-packet) |
| `rx_packet_len` / `tx_packet_len` | 정수, 기본 -1 | |
| `sample_point` | **0.5.3에 없음** — master에만 `{'id': 'sample_point', 'desc': 'Sample point (%)', 'default': 50}` | |

`format` 텍스트 규칙 [소스] (`format_value()`):

- `ascii`: 32..126은 문자 그대로, 그 외는 `"[{:02X}]"`(data_bits ≤ 8) / `"[{:03X}]"` → `[0D]`, `[0A]`, `[C2]`. 공백 0x20은 `" "`.
- `hex`: 0 패딩 대문자, 접두사 없음(`55`, `2D`). `dec`: `85`. `oct`/`bin`: 0 패딩.
- 래퍼는 **`format=hex`로 받아 Python에서 바이트로 변환**하는 것이 가장 안전(ascii의 `[0D]`와 실제 문자열 `[0D]`가 구분 불가).

annotation 텍스트 [소스]: 데이터=format 값, start `Start bit`/`Start`/`S`, stop `Stop bit`/`Stop`/`T`, parity `Parity bit`/`Parity`/`P`, parity 오류 `Parity error`/`Parity err`/`PE`, 프레임 오류(rx-warnings) `Frame error`/`Frame err`/`FE`, break `Break condition`/`Break`/`Brk`/`B`, 데이터 비트 `0`/`1`.

**0.5.3 버그**: stop bit annotation이 클래스 `rx-stop`(8)이 아니라 `rxtx + 4` = **`rx-parity-ok`** 로 나온다. 실측: `-A uart=rx-stop` → 0줄, `-A uart=rx-parity-ok` → `uart-1: Stop bit`. master는 `Ann.RX_STOP + rxtx`로 수정됨 [소스].

샘플링 위치 [소스]: start bit 하강 에지 샘플을 `frame_start`로 잡고, 비트 n의 샘플 지점 = `frame_start + (bit_width - 1)/2 + n*bit_width` (0.5.3은 비트 중앙 고정). 즉 start 에지 검출 지연(최대 1 샘플)이 그대로 오차가 된다 → 오버샘플링 권장(12장).

master 차이 요약(래퍼가 버전별 분기해야 하는 부분):

| 항목 | 0.5.3 | master |
|---|---|---|
| warnings 클래스 | `rx-warnings`, `tx-warnings` | `rx-warning`, `tx-warning` |
| 데이터비트 클래스 | `rx-data-bits` | `rx-data-bit` |
| 데이터 행 ID | `rx-data` (행), 클래스 `rx-data`와 동일 이름 | 행 `rx-data-vals` ("RX data") |
| break 행 | `rx-break` | `rx-breaks` |
| `sample_point` | 없음 | 있음(기본 50) |
| `stop_bits` 2.0 | 없음 | 있음 |

### 6.2 `spi` [실측 `--show`, 0.5.3]

```text
Required channels:
- clk (CLK): Clock
Optional channels:
- miso (MISO): Master in, slave out
- mosi (MOSI): Master out, slave in
- cs (CS#): Chip-select
Options:
- cs_polarity: CS# polarity ('active-low', 'active-high', default 'active-low')
- cpol: Clock polarity (0, 1, default 0)
- cpha: Clock phase (0, 1, default 0)
- bitorder: Bit order ('msb-first', 'lsb-first', default 'msb-first')
- wordsize: Word size (default 8)
```

클래스: `miso-data`, `mosi-data`, `miso-bits`, `mosi-bits`, `warnings`, `miso-transfer`, `mosi-transfer`. 행: `miso-bits`, `miso-data`, `miso-transfer`, `mosi-bits`, `mosi-data`, `mosi-transfer`, `other`. 바이너리: `miso`, `mosi`. 데이터 텍스트 `'%02X'`, transfer는 CS 구간 바이트를 공백으로 이은 문자열. 경고 `CS# was deasserted during this data word!` [소스].

실측(합성 캡처, CS/CLK/MOSI/MISO, mode 0):

```text
$ sigrok-cli -i spi.sr -P spi:clk=CLK:mosi=MOSI:miso=MISO:cs=CS -A spi=mosi-transfer:miso-transfer --protocol-decoder-samplenum
20-292 spi-1: FF EF 40 18
20-292 spi-1: 9F 00 00 00
322-850 spi-1: FF FF FF FF 68 73 71 73
322-850 spi-1: 03 00 00 00 00 00 00 00
```

master: 클래스 `miso-bit`, `mosi-bit`, `warning`; 행 `miso-data-vals`, `miso-transfers` 등으로 변경 [소스].

`spi` PD는 MOSI/MISO 단일 라인만 다루므로 **dual/quad I/O 구간 데이터는 복원할 수 없다**(채널 정의상).

### 6.3 `spiflash` [실측 `--show`, 0.5.3]

입력 `spi`(스택 전용: `-P spi:...,spiflash`), 출력/바이너리 없음. 옵션:

```text
- chip: Chip ('adesto_at45db161e', 'atmel_at25128', 'atmel_at25256', 'fidelix_fm25q32', 'macronix_mx25l1605d', 'macronix_mx25l3205d', 'macronix_mx25l6405d', 'winbond_w25q80dv', default 'adesto_at45db161e')
- format: Data format ('hex', 'ascii', default 'hex')
```

주요 클래스: `read`(Read data), `fast/read`(Fast read data), `rdid`(Read identification), `rdsr`, `wren`, `pp`(Page program), `se`, `be`, `ce`, `2read`, `rems`, `bit`, `field`, `warning`. 행: `bits`, `fields`, `commands`, `warnings` [실측]. 실측 출력:

```text
$ sigrok-cli -i spi.sr -P spi:clk=CLK:mosi=MOSI:miso=MISO:cs=CS,spiflash -A spiflash=commands
spiflash-1: Read identification (RDID): Device = Adesto Unknown
spiflash-1: Read data (addr 0x000000, 4 bytes): 68 73 71 73
```

필드(`-A spiflash` 전체)에는 `Command: Read identification (RDID)`, `Manufacturer ID: 0xef`, `Memory type: 0x40`, `Device ID: 0x18`, `Address: 0x000000`, `Data (4 bytes)` 등이 나온다 [실측]. `Device = Adesto Unknown`은 기본 `chip` 값의 벤더명 때문 — 실제 칩 식별은 RDID 바이트(EF 40 18 = Winbond W25Q128 계열)로 직접 판단한다. 바이너리 출력이 없으므로 읽힌 데이터 복원은 `-A spiflash=read` 주석 파싱 또는 `-B spi=miso`(+ 명령 경계는 별도 파싱)로 한다.

### 6.4 `i2c` [실측 `--show`, 0.5.3]

채널 `scl`, `sda`(필수). 옵션 `address_format`: `'shifted'`(7비트, 기본) / `'unshifted'`(R/W 비트 포함 8비트). 클래스: `start`, `repeat-start`, `stop`, `ack`, `nack`, `bit`, `address-read`, `address-write`, `data-read`, `data-write`, `warnings`. 행: `bits`, `addr-data`, `warnings`. 실측:

```text
$ sigrok-cli -i i2c.sr -P i2c:scl=SCL:sda=SDA -A i2c=addr-data --protocol-decoder-samplenum
25-25 i2c-1: Start
180-200 i2c-1: Write
40-180 i2c-1: Address write: 50
200-220 i2c-1: ACK
220-380 i2c-1: Data write: 00
380-400 i2c-1: ACK
400-400 i2c-1: Start repeat
555-575 i2c-1: Read
415-555 i2c-1: Address read: 50
575-595 i2c-1: ACK
595-755 i2c-1: Data read: 68
...
1115-1135 i2c-1: NACK
1140-1140 i2c-1: Stop
```

- R/W 비트 텍스트 `Write`/`Read`는 각각 `address-write`/`address-read` 클래스로 나온다(`-l 4`: `180-200 i2c-1: address-write: "Write" "Wr" "W"`) [실측].
- `address_format=unshifted` → `Address write: A0`, `Address read: A1` [실측].
- master: 클래스 `warning`(단수), 행 설명 `Address/data` [소스].

### 6.5 `guess_bitrate` (기준선 비교용)

채널 `data` 1개, 옵션 없음, 클래스 `bitrate`. 알고리즘 [소스] (https://github.com/sigrokproject/libsigrokdecode/blob/libsigrokdecode-0.5.3/decoders/guess_bitrate/pd.py): 에지 간 최소 간격 `b`가 갱신될 때마다 `int(samplerate / b)`를 annotation으로 낸다 → **마지막 줄이 최종 추정치**. 실측:

```text
$ sigrok-cli -i uart1m.sr -P guess_bitrate:data=D0 --protocol-decoder-samplenum
500-509 guess_bitrate-1: 111111
509-517 guess_bitrate-1: 125000
```

실제 115200 @ 1 MHz인데 125000(최소 8샘플)으로 나온다. 1샘플 글리치 하나만 있어도 `samplerate`(예 1000000)를 낸다(12.4 표). 우리 추정기의 하한 비교용으로만 쓴다.

---

## 7. 문서·위키와 실제 동작(0.7.2/0.5.x)이 다른 곳

| 문서상 형태 | 실제 동작 | 근거 |
|---|---|---|
| man: `-P uart:baudrate=115200:parity_type=odd` | `Unknown option or channel 'parity_type'`, rc=1. 올바른 키는 `parity` | 실측 |
| wiki UART: `num_data_bits`, `parity_type`, `parity_check`, `num_stop_bits` | 0.5.3 이름은 `data_bits`, `parity`, `stop_bits` | 실측 `--show` |
| man: `-I binary:numchannels=4:samplerate=1mhz` | 1 Hz로 해석. 입력 모듈은 정수 Hz만 | 실측+소스 |
| `--config samplerate=1.5m` | 1 Hz (sizestring 소수 버그). `"1.5 MHz"`(공백)는 정상 | 실측+소스 |
| man `--scan` 예시: fx2lafw 채널 `0 1 2 ...` | 0.5.2 fx2lafw 채널은 `D0`..`D7` | 소스 |
| man `--channels 1=CLK,2-4,7` | 범위는 숫자 이름 채널에서만 동작(`D0-D3` 실패) | 실측+소스 |
| wiki v2 파일 형식: `probe_X`, `analog_X` | 실제 키는 `probe1`, `analog9`처럼 **밑줄 없음**, 번호는 장치 채널 인덱스+1(희소 가능) | 실측+소스 |
| `-o out.vcd` | `-O` 없으면 확장자와 무관하게 srzip | 실측 |
| man `-A`: 클래스 지정 | 0.7.2는 행(row) 이름도 허용, 클래스 우선 | 소스+NEWS |
| 주석 접두어 `uart:` (구버전 출력 예시들) | 0.5.3 인스턴스 ID `uart-1:` | 실측 |
| UART `rx-stop` 클래스 | 0.5.3에서는 stop bit가 `rx-parity-ok`로 나옴(버그) | 실측+소스 |

---

## 8. srzip(`.sr`) v2 파일 형식 — Python에서 직접 읽기

1차 문서: https://sigrok.org/wiki/File_format:Sigrok/v2 (키 목록 수준). 실제 바이트 형식은 libsigrok 0.5.2의 writer `src/output/srzip.c`(https://github.com/sigrokproject/libsigrok/blob/libsigrok-0.5.2/src/output/srzip.c)와 reader `src/session_file.c`, `src/session_driver.c`에서 확인했다.

### 8.1 zip 구성 [실측]

```text
$ sigrok-cli -d demo --samples 1000 -o demo.sr ; unzip -l demo.sr
  Length      Date    Time    Name
---------  ---------- -----   ----
        1  2026-10-18 15:22   version
      261  2026-10-18 15:22   metadata
     1000  2026-10-18 15:22   logic-1-1
     4000  2026-10-18 15:22   analog-1-9-1
     4000  2026-10-18 15:22   analog-1-11-1
     4000  2026-10-18 15:22   analog-1-10-1
     4000  2026-10-18 15:22   analog-1-12-1
     4000  2026-10-18 15:22   analog-1-13-1
```

- `version`: ASCII `2`, **개행 없음**(1바이트), zip 압축 방식 stored. 나머지 엔트리는 deflated [실측 `zipinfo`]. reader는 `version`이 1..2가 아니면 거부 [소스].
- zip 엔트리 순서는 보장되지 않는다(analog-1-11-1이 -10-1보다 앞) → 이름으로 찾을 것.
- 엔트리 이름 [문서+소스]: `logic-1`(구형 단일 파일, deprecated) 또는 `logic-1-1`, `logic-1-2`, ...; 아날로그는 `analog-1-<채널번호>-<청크번호>`.

### 8.2 `metadata` (GKeyFile/INI) [실측+소스]

```ini
[global]
sigrok version=0.5.2

[device 1]
capturefile=logic-1
total probes=8
samplerate=200 kHz
total analog=5
probe1=D0
probe2=D1
probe3=D2
probe4=D3
probe5=D4
probe6=D5
probe7=D6
probe8=D7
analog9=A0
analog10=A1
analog11=A2
analog12=A3
analog13=A4
unitsize=1
```

| 키 | 의미 | 근거 |
|---|---|---|
| `[global] sigrok version` | 생성한 libsigrok 버전 | 소스 |
| `[device 1]` | 장치 섹션(sigrok-cli는 1개만 씀) | 소스 |
| `capturefile` | 로직 데이터 기본 이름, 항상 `logic-1`. **enabled 로직 채널이 없으면 키 자체가 없음** | 소스 |
| `total probes` | 장치의 **전체** 로직 채널 수(enabled 여부 무관) | 소스 |
| `samplerate` | `sr_samplerate_string()` 문자열: `200 kHz`, `1 MHz`, `1.5 MHz`, `1.234567 MHz`, `12.345 kHz`, `24 MHz`, `100 Hz` | 실측 |
| `total analog` | **enabled** 아날로그 채널 수 | 소스 |
| `probe<N>` | 로직 채널 이름. `N = 채널 인덱스 + 1` → **비트 위치 = N-1**. disabled 채널은 키가 없어 번호가 건너뛴다(예: `probe1`, `probe4`) | 실측+소스 |
| `analog<N>` | 아날로그 채널 이름. enabled 로직 채널이 하나라도 있으면 N은 `total probes + 1`부터, 없으면 1부터 연속(enabled 아날로그만) | 소스 |
| `unitsize` | 로직 샘플 1개의 바이트 수(첫 로직 패킷 때 추가됨) | 소스 |
| `driver` | wiki에 optional로 나오지만 0.5.2 writer는 쓰지 않음 | 문서+소스 |

reader 동작 [소스] (`sr_session_load()`):

- 키를 **파일 순서대로** 처리한다. `total probes`가 채널 객체(이름 `"0"`,`"1"`,...; disabled)를 만들고, 이후 `probeN`이 이름을 바꾸고 enable한다 → 직접 파일을 쓸 때 **`total probes`를 `probeN`보다 앞에** 둘 것.
- `samplerate`는 `sr_parse_sizestring()`으로 읽으므로 `1000000 Hz` 같은 정수+Hz도 된다(실측: 직접 쓴 `samplerate=1000000 Hz` 정상 로드). 단 4.2의 소수 버그 때문에 `1.5MHz`처럼 공백 없는 소수는 피한다(writer 자신은 `1.5 MHz`로 공백을 넣음).

### 8.3 로직 청크와 비트 패킹 [소스+실측]

- 청크 읽기 순서 [소스] (`session_driver.c`): `capturefile`(`logic-1`)이 있으면 그것 하나. 없으면 `logic-1-1`, `logic-1-2`, ... **번호가 끊길 때까지 순차**. 사전식 정렬 금지(`logic-1-10` < `logic-1-2`).
- 청크 = 드라이버가 보낸 로직 패킷 1개(USB 전송 단위 등). 크기 제한 없음. continuous demo 약 1초 캡처(100 kHz) → 27개 청크 [실측]. reader의 읽기 버퍼는 `CHUNKSIZE (4 * 1024 * 1024)`.
- 샘플 s = `data[s*unitsize : (s+1)*unitsize]`. 채널(비트) b의 값 = `(sample[b // 8] >> (b % 8)) & 1` — 즉 바이트 0의 LSB가 채널 0, 바이트 1이 채널 8..15 (little-endian) [소스: `output/vcd.c`의 `((unsigned)sample[index / 8] >> (index % 8)) & 1`].
- unitsize: fx2lafw는 8채널 모드 1, D8..D15 중 하나라도 켜면 2 [소스] (`sample_wide = channel_mask > 0xff || num_analog > 0`).
- 검증: 아래 reader로 추출한 모든 채널 비트열이 `sigrok-cli -i <file> -O bits`와 **완전히 일치**(uart1m.sr, demo.sr(아날로그 포함·엔트리 순서 섞임), cont2.sr(28청크), d16.sr(unitsize 2, 16채널), spi.sr, i2c.sr, 1.4M 샘플 파일) [실측].

### 8.4 아날로그 청크 [소스]

`analog-1-<N>-<k>`: 채널 N의 샘플을 `float`(32비트, `sr_analog_to_float()` 결과, 호스트 엔디언 — x86에서 little-endian)로 연속 저장. demo 1000샘플 → 4000바이트 [실측 크기]. 로직 분석에는 필요 없음.

### 8.5 참조 구현 (stdlib만, 검증 완료)

```python
"""Read/write sigrok srzip (.sr v2) logic data. stdlib only.
Verified 2026-10-18 against libsigrok 0.5.2 / sigrok-cli 0.7.2 (-O bits identical)."""
import configparser
import re
import zipfile
from decimal import Decimal

_RATE_RE = re.compile(r'^\s*([0-9]+(?:\.[0-9]+)?)\s*([kMG]?)Hz\s*$')
_MULT = {'': 1, 'k': 10**3, 'M': 10**6, 'G': 10**9}


def parse_samplerate(text):
    """'200 kHz' / '1.234567 MHz' / '1000000 Hz' / '24000000' -> int Hz."""
    text = text.strip()
    if text.isdigit():
        return int(text)
    m = _RATE_RE.match(text)
    if not m:
        raise ValueError('unrecognised samplerate %r' % text)
    num, unit = m.groups()
    return int(Decimal(num) * _MULT[unit])


def read_sr(path):
    """Return dict: samplerate, unitsize, total_probes, channels{name: bit}, data(bytes)."""
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
        version = z.read('version').decode('ascii').strip()
        if version not in ('1', '2'):
            raise ValueError('unsupported session file version %r' % version)
        cp = configparser.ConfigParser(interpolation=None, strict=False)
        cp.optionxform = str                      # keep key case
        cp.read_string(z.read('metadata').decode('utf-8', 'replace'))
        dev = cp['device 1']
        info = {
            'sigrok_version': cp.get('global', 'sigrok version', fallback=None),
            'samplerate': parse_samplerate(dev['samplerate']) if 'samplerate' in dev else None,
            'total_probes': int(dev.get('total probes', '0')),
            'total_analog': int(dev.get('total analog', '0')),
            'unitsize': int(dev['unitsize']) if 'unitsize' in dev else None,
            'channels': {},                       # name -> bit index (probeN => bit N-1)
        }
        for key, val in dev.items():
            m = re.fullmatch(r'probe(\d+)', key)
            if m:
                info['channels'][val] = int(m.group(1)) - 1
        capfile = dev.get('capturefile')          # 'logic-1' or absent (analog-only)
        chunks = []
        if capfile:
            if capfile in names:                  # deprecated single-file layout
                chunks.append(z.read(capfile))
            else:                                 # logic-1-1, logic-1-2, ... until a gap
                n = 1
                while '%s-%d' % (capfile, n) in names:
                    chunks.append(z.read('%s-%d' % (capfile, n)))
                    n += 1
        info['data'] = b''.join(chunks)
    return info


def write_sr(path, data, samplerate_hz, names, unitsize=1, chunk_bytes=4 * 1024 * 1024):
    """Write a logic-only srzip v2 file loadable by sigrok-cli 0.7.2 (mock/test fixtures).
    names[i] is the channel at bit i. 'total probes' must precede probeN keys."""
    meta = ['[global]', 'sigrok version=0.5.2', '', '[device 1]',
            'capturefile=logic-1',
            'total probes=%d' % len(names),
            'samplerate=%d Hz' % samplerate_hz,
            'total analog=0']
    meta += ['probe%d=%s' % (i + 1, n) for i, n in enumerate(names)]
    meta += ['unitsize=%d' % unitsize, '']
    step = chunk_bytes - chunk_bytes % unitsize
    with zipfile.ZipFile(path, 'w') as z:
        z.writestr(zipfile.ZipInfo('version'), '2')          # stored, no newline
        z.writestr('metadata', '\n'.join(meta), compress_type=zipfile.ZIP_DEFLATED)
        for i, off in enumerate(range(0, len(data), step), start=1):
            z.writestr('logic-1-%d' % i, data[off:off + step], compress_type=zipfile.ZIP_DEFLATED)


def channel_runs(data, unitsize, bit):
    """Yield (level, start_sample, length) runs for one channel (C-speed via translate+regex)."""
    lane = data[bit // 8::unitsize] if unitsize > 1 else data
    mask = 1 << (bit % 8)
    table = bytes(1 if (v & mask) else 0 for v in range(256))
    stream = lane.translate(table)
    for m in re.finditer(rb'\x00+|\x01+', stream):
        yield stream[m.start()], m.start(), m.end() - m.start()
```

- `write_sr()`로 만든 파일(3청크, unitsize 1/2)을 sigrok-cli가 정상 로드·디코드(`-B uart=rx` → `U-Boot 2016.11 (Jan `) [실측]. mock-device 시뮬레이터가 LA 캡처 픽스처를 만들 때 사용 가능.
- 큰 캡처(수십~수백 MB)는 `zipfile`이 엔트리를 통째로 읽으므로 메모리에 주의. 필요하면 청크 단위로 `channel_runs`를 이어 붙이도록 바꾼다(청크 경계에서 run을 병합).
- 프로젝트 venv에는 numpy가 없다 [실측]. 위 코드는 numpy 없이 `bytes.translate` + `re.finditer`(C 구현)로 에지를 뽑는다.

---

## 9. VCD

### 9.1 sigrok이 쓰는 VCD [실측+소스]

```text
$ sigrok-cli -i uart1m.sr -O vcd -o uart1m.vcd ; cat uart1m.vcd
$date Sun Oct 18 15:26:56 2026 $end
$version libsigrok 0.5.2 $end
$comment
  Acquisition with 2/2 channels at 1 MHz
$end
$timescale 1 us $end
$scope module libsigrok $end
$var wire 1 ! D0 $end
$var wire 1 " D1 $end
$upscope $end
$enddefinitions $end
#0 1! 1"
#500 0!
#509 1!
#517 0!
...
#6134 1!
#8608
```

- 식별자: enabled 로직 채널 순서대로 `'!' + i` (`!`, `"`, `#`, ...) [소스] (https://github.com/sigrokproject/libsigrok/blob/libsigrok-0.5.2/src/output/vcd.c).
- 값 변화는 **타임스탬프와 같은 줄에 공백으로** 이어 쓴다: `#<t> <v><id>[ <v><id>...]`. 첫 샘플은 모든 채널 값 출력.
- 마지막 줄 `#<총샘플수 환산 시간>`은 캡처 끝 표시.
- `$timescale` 선택 [소스] (`get_timescale_freq()`): samplerate 이상인 첫 10의 거듭제곱을 고르고, 나누어떨어지지 않으면 최대 2단계(×100)까지 더 올린다. 타임스탬프 = `"#%.0f" % (samplecount / samplerate * timescale_freq)`.

| samplerate | `$timescale` [실측] |
|---|---|
| 100 Hz | `10 ms` |
| 12.345 kHz | `100 ns` |
| 200 kHz, 1 MHz | `1 us` |
| 1.5 MHz, 3 MHz, 1.234567 MHz | `1 ns` |
| 24 MHz, 48 MHz | `100 ps` |

  24 MHz에서는 샘플 간격이 416.67 tick이라 시간이 반올림된다 → VCD에서 샘플 번호 복원 시 `round(t * samplerate / timescale_freq)`.
- 비연속 채널 선택 시 VCD writer는 dense 인덱스를 쓴다(4.4).

### 9.2 sigrok이 읽는 VCD [실측]

- 표준 형식(`#t` 줄 다음에 값 줄들) 그대로 읽힌다. 아래 파일 → `Samplerate: 1000000000`, 채널 `rx`, 20000 샘플:

```text
$timescale 1 ns $end
$scope module top $end
$var wire 1 # rx $end
$upscope $end
$enddefinitions $end
#0
1#
#1000
0#
#9680
1#
#20000
```

- samplerate = 1/timescale. 실제 신호 대역보다 지나치게 미세한 timescale은 `downsample`로 줄인다. `skip`, `compress` 옵션은 3.4(e).

---

## 10. 하드웨어 (저가 LA 중심)

### 10.1 요약표

| 장치(흔한 이름) | 드라이버 | libsigrok 0.5.2 | 채널·속도 | 펌웨어 | 근거 |
|---|---|---|---|---|---|
| "24MHz 8CH" Saleae Logic 클론, MCU123 Saleae Logic clone, ESLA100, Hantek 6022BL(LA 모드) | `fx2lafw` | 포함 | 8ch, wiki 표기 "up to 24MHz"; 입력 -0.5V—5.25V, 고정 임계 VIH=2.0V, VIL=0.8V | `fx2lafw-saleae-logic.fw` (VID:PID `0925:3881`) | https://sigrok.org/wiki/MCU123_Saleae_Logic_clone , `fx2lafw/api.c` |
| LHT00SU1, ARMFLY AX-Pro 등 USBee AX 클론 | `fx2lafw` | 포함 | 8ch + 아날로그 1(A0) | `fx2lafw-cwav-usbeeax.fw` (`08a9:0014`) | `fx2lafw/api.c` 주석·표 |
| 펌웨어 없는 CY7C68013A 보드(Lcsoft Mini Board 등) | `fx2lafw` | 포함 | 16ch 가능(16비트 모드 최대 12 MHz 검사) | `fx2lafw-cypress-fx2.fw` (`04b4:8613`) | `fx2lafw/api.c`, `protocol.c` |
| sigrok FX2 LA (fx2grok) | `fx2lafw` | 포함 | 8/16ch | `fx2lafw-sigrok-fx2-8ch.fw`(`1d50:608c`), `-16ch.fw`(`1d50:608d`) | `fx2lafw/api.c` |
| DSLogic / DSLogic Pro / Plus / Basic, DSCope | `dreamsourcelab-dslogic` | 포함 | 최대 400MHz(4ch)/200MHz(8ch)/100MHz(16ch), 입력 -0.6V—6V, 임계 3.3V/5V 선택 | `sigrok-fwextract-dreamsourcelab-dslogic`로 DSView 파일에서 추출(`dreamsourcelab-dslogic-fx2.fw`, `...-fpga-3v3.fw`, `...-fpga-5v.fw` 등) | https://sigrok.org/wiki/DreamSourceLab_DSLogic |
| DSLogic U2Basic, U3Pro16/32, U2Pro16 | — | **미지원** | | | 같은 wiki |
| Saleae Logic16 | `saleae-logic16` | 포함 | 100/50/32/16MHz @ 3/6/9/16ch, 임계 설정 가능 | `sigrok-fwextract-saleae-logic16`로 Saleae Logic 1.2.10 Linux 바이너리에서 `saleae-logic16-fx2.fw`, `saleae-logic16-fpga-18.bitstream`, `saleae-logic16-fpga-33.bitstream` 생성 | https://sigrok.org/wiki/Saleae_Logic16 |
| Saleae Logic Pro 8/16 | `saleae-logic-pro` | 포함 | (미확인) | bitstream 업로드(소스) | https://sigrok.org/wiki/Sigrok-cli 사용 예 |
| Openbench Logic Sniffer / SUMP 호환 | `ols` | 포함 | 장치별 | — (시리얼 `conn` 필수) | man page |
| Raspberry Pi Pico (sigrok-pico 펌웨어) | `raspberrypi-pico` | **미포함** — master에 2023-09-27 추가("raspberrypi-pico: Initial driver skeleton.") | samplerate 표 5 kHz–120 MHz(+오버클럭 값), 시리얼 기본 `115200/8n1/dtr=1/rts=0/flow=0` | Pico에 sigrok-pico UF2 | GitHub commits API, master `src/hardware/raspberrypi-pico/api.c` |
| Kingst LA1010/LA2016 | `kingst-la2016` | **미포함** — master(2020-06~) | — | — | master `src/hardware/kingst-la2016/api.c` (**PWM 출력 기능 있음 → 11장**) |
| GreatFET | `greatfet` | **미포함** — master(2023-10~) | — | — | master |

- master 전용 드라이버는 nightly 빌드가 필요하다. 이 머신의 0.5.2 `-L` 목록에 `raspberrypi-pico`, `kingst-la2016`, `greatfet`은 없다 [실측]. sigrok-rp2350 README 원문: "You need an up to date sigrok to use this: sigrok-cli 0.7.2 lacks the `raspberrypi-pico` driver." 및 "As of 28 Sept 2023 this pull request has been merged into mainline sigrok" (https://github.com/c1570/sigrok-rp2350) [문서].
- **전압 주의**: fx2lafw 클론의 임계 VIH=2.0V(위 wiki) → 1.8V UART는 high로 인식되지 않을 수 있다. RS-232 레벨(±V)을 3.3/5V LA에 직접 물리면 안 된다(레벨 변환 필요). 프로브 연결은 사람이 하며 GND 공통 연결 필수.
- fx2lafw 0.5.2 samplerate 표에는 `48 MHz`까지 있으나 `MAX_8BIT_SAMPLE_RATE SR_MHZ(24)`는 `protocol.h`에 정의만 되어 있고 fx2lafw 디렉터리 안에 사용처가 없다(grep). 실제 검사는 16비트 모드의 `MAX_16BIT_SAMPLE_RATE`(12 MHz) 초과 시 `Unable to sample at <N>Hz when collecting 16-bit samples.`뿐이다 [소스]. 실사용 상한은 장치 wiki 표기대로 24 MHz로 보고, 24 MHz 연속 스트리밍의 USB 대역 안정성은 **(미확인)**.

### 10.2 드라이버별 채널 이름 (0.5.2) [소스+실측]

| 드라이버/입력 | 채널 이름 |
|---|---|
| `fx2lafw` | `D0`..`D7` (16비트 프로파일 `D0`..`D15`), 아날로그 `A0` |
| `demo` | `D0`..`D7`, `A0`..`A4` |
| `dreamsourcelab-dslogic` | `0`..`15` |
| `saleae-logic16` | `0`..`15` |
| `-I binary` | `0`,`1`,... |
| `.sr` 재로드 | `probeN` 이름, 메타데이터 없는 채널은 `"N-1"` 숫자 |
| `-I vcd` | `$var` 이름 |
| `-I csv` | 헤더 행 이름 |

→ 래퍼는 채널 이름을 가정하지 말고 `--scan`/`--show`/`-i --show` 출력에서 얻는다.

### 10.3 fx2lafw 지원 프로파일 (0.5.2) [소스]

`supported_fx2[]`(https://github.com/sigrokproject/libsigrok/blob/libsigrok-0.5.2/src/hardware/fx2lafw/api.c):

| VID:PID | vendor / model | 펌웨어 파일 | 채널 |
|---|---|---|---|
| `08a9:0014` | CWAV / USBee AX | `fx2lafw-cwav-usbeeax.fw` | 8 + A0 |
| `08a9:0015` | CWAV / USBee DX | `fx2lafw-cwav-usbeedx.fw` | 16 |
| `08a9:0009` | CWAV / USBee SX | `fx2lafw-cwav-usbeesx.fw` | 8 |
| `08a9:0005` | CWAV / USBee ZX | `fx2lafw-cwav-usbeezx.fw` | 8 |
| `0925:3881` | Saleae / Logic | `fx2lafw-saleae-logic.fw` | 8 |
| `04B4:8613` | Cypress / FX2 | `fx2lafw-cypress-fx2.fw` | 16 |
| `16d0:0498` | Braintechnology / USB-LPS | `fx2lafw-braintechnology-usb-lps.fw` | 16 |
| `1d50:608c` | sigrok / FX2 LA (8ch) | `fx2lafw-sigrok-fx2-8ch.fw` | 8 |
| `1d50:608d` | sigrok / FX2 LA (16ch) | `fx2lafw-sigrok-fx2-16ch.fw` | 16 |
| `1d50:608f` | sigrok / usb-c-grok | `fx2lafw-usb-c-grok.fw` | 8 |

- Ubuntu `sigrok-firmware-fx2lafw 0.1.7-1`은 `/usr/share/sigrok-firmware/`에 위 파일들(단, `fx2lafw-usb-c-grok.fw`는 없음)과 Hantek/SainSmart 스코프용 파일을 설치한다 [실측].
- devopts: `continuous`, `limit_samples`, `conn`(get), `samplerate`(get/set/list), `triggermatch`(list), `captureratio`(get/set). `limit_time` 없음 → `--time`은 샘플 수로 변환 [소스].
- 장치 선택: `-d fx2lafw:conn=<bus>.<address>` 또는 `-d fx2lafw:conn=0925.3881` [문서+소스].

---

## 11. 출력(구동) 가능 장치 — 래퍼가 거부해야 할 것

sigrok은 측정뿐 아니라 **전원공급기·전자부하·신호발생기·릴레이를 제어**할 수 있다. CCTV 분석 파이프라인의 sigrok-mcp는 **로직 애널라이저 캡처/디코드 전용**이어야 하며, 타깃 보드에 전압·전류·신호를 가할 수 있는 경로를 모두 막는다.

### 11.1 0.5.2 `-L` 이름 기준 출력 가능 드라이버 [소스: `src/hardware/*/api.c` grep]

| 기능 분류 | 드라이버 ID (`-L`에 표시되는 이름) |
|---|---|
| 전원공급기 (`SR_CONF_POWER_SUPPLY`) | `atten-pps3203`, `conrad-digi-35-cpu`, `gwinstek-gpd`, `korad-kaxxxxp`, `manson-hcs-3xxx`, `motech-lps-301`, `rdtech-dps`, `scpi-pps`, `hpib-pps` |
| 전자부하 (`SR_CONF_ELECTRONIC_LOAD`) | `arachnid-labs-re-load-pro`, `maynuo-m97`, `zketech-ebd-usb` |
| 신호발생기 (`SR_CONF_SIGNAL_GENERATOR`) | `rohde-schwarz-sme-0x` (`output_frequency`, `amplitude` set) |
| 대상 전원 차단 | `baylibre-acme` (`power_off` — 프로브가 DUT 전원을 끊고 복구) |
| 계측기 자체 전원 끄기 | `cem-dt-885x`, `gmc-mh-2x-bd232`, `pce-322a` (`power_off`) |
| 로거 설정 | `cem-dt-885x`, `lascar-el-usb` (`datalog` set; man 예시 `--config datalog=on --set`) |

(디렉터리 이름 `atten-pps3xxx`, `motech-lps-30x`와 `-L` 이름이 다르다. 래퍼 정책은 `-L` 이름으로 작성.)

master에 추가된 출력 가능 드라이버(nightly 사용 시) [소스: master `api.c`]: 릴레이 `dcttech-usbrelay`, `icstation-usbrelay`, `devantech-eth008`(`enabled` set), `hp-59306a`(멀티플렉서); 전원 `gwinstek-psp`; 부하 `itech-it8500`, `siglent-sdl10x0`(`voltage_target`/`current_limit`/`power_target`/`resistance_target`/`regulation`/`enabled`); 신호발생기 `juntek-jds6600`, `rigol-dg`(`output_frequency`/`amplitude`/`offset`/`phase`/`duty_cycle`/`enabled`); **로직 애널라이저인 `kingst-la2016`도 PWM 출력(`enabled`, `output_frequency`, `duty_cycle`)**.

### 11.2 출력을 바꾸는 config 키 (0.5.2 `sr_key_info_config[]` ID) [소스]

`voltage_target`, `current_limit`, `enabled`, `channel_config`, `ovp_enabled`, `ovp_threshold`, `ocp_enabled`, `ocp_threshold`, `otp`, `uvc`, `uvc_threshold`, `regulation`, `output_frequency`, `output_frequency_target`, `amplitude`, `offset`, `power_off`, `datalog` (master: `power_target`, `resistance_target`, `phase`, `duty_cycle` 등 추가). `device_mode`, `test_mode` 키도 정의돼 있으나 0.5.2 드라이버에서는 쓰이지 않는다(grep) — allowlist 정책이면 자동으로 차단된다.

### 11.3 래퍼 정책 (allowlist)

1. **드라이버 allowlist**: `fx2lafw`, `dreamsourcelab-dslogic`, `saleae-logic16`, `saleae-logic-pro`, `ols`, `demo`(테스트용) — 필요 시 추가. 나머지는 거부. master 사용 시 `kingst-la2016`은 출력 키 차단을 전제로만 허용.
2. **config 키 allowlist**: `samplerate`, `captureratio`, (DSLogic) `voltage_threshold`, (demo) `pattern`. 그 외 키는 거부. 특히 11.2 목록은 명시적으로 차단 사유와 함께 거부.
3. **`--set` 금지**. `--get`은 allowlist 키만.
4. **항상 `-d` 명시**: `-d` 없이 캡처하면 스캔된 단일 실장치를 자동 선택(3.3)하므로 금지. `-D`(`--dont-scan`, man: "-d 지정이 없을 때 자동 스캔하지 않음")를 함께 붙여 두면 실수로 `-d`가 빠져도 자동 스캔이 일어나지 않는다 [실측: `-D --samples 10` → `No devices found.` rc=1, `-D --scan` → 빈 출력, `-D -d demo ...`는 정상 동작].
5. 인자 값에 `:` `,` `=` 및 공백/제어문자 금지(4.1, 5.2).
6. 위반 시 MCP 에러 메시지에 "출력 장치 제어는 이 서버의 범위가 아님(안전 정책)"을 명시.

---

## 12. 오프라인 보레이트 추정

### 12.1 원리

UART 8N1 프레임은 start(0) + 데이터 8비트(LSB first) + stop(1)이고, 선은 idle에서 high다. 신호의 모든 펄스 폭(연속 같은 레벨 구간 길이)은 **비트 시간 T의 정수배(1..9, idle은 그 이상)**다. 따라서:

- 가장 짧은 안정적 펄스 ≈ 1T (다만 1T 펄스가 드물 수도 있음: `0x00`, `0xFF` 위주 데이터).
- 정수 배 관계를 이용한 근사 GCD: 모든 펄스 r에 대해 `k = round(r / T)`, `T = Σr / Σk`로 반복 정제하면 양자화 오차(±1 샘플)가 평균된다.
- 순수 정수 GCD는 ±1 샘플 지터 때문에 1이 되어 실패한다 → 허용오차가 있는 근사 GCD/히스토그램 방식을 쓴다.
- sigrok의 `guess_bitrate`는 "최소 간격"만 써서 편향(115200@1MHz → 125000)과 글리치 취약성이 있다(6.5).

### 12.2 알고리즘

1. `.sr`에서 대상 채널의 run 목록 `(level, start, length)`을 얻는다(8.5 `channel_runs`).
2. 첫/마지막 run(잘린 idle)을 버린다. 처음과 끝 레벨이 0이면 **idle-low → 반전 신호** 의심(`invert_rx=yes`).
3. `glitch_max`(기본 1샘플) 이하 run은 글리치로 제외하고 개수를 경고로 남긴다.
4. 초기 T: 짧은 쪽 10%(최소 3개) run의 중앙값.
5. 정제(4회): `1 <= k=round(r/T) <= 12` 이고 `|r - kT| <= 0.3T`인 run만 모아 `T = Σr/Σk`. 이 조건을 만족한 비율 = `explained`.
6. `baud_raw = samplerate / T`. 표준 목록에서 비율 오차가 가장 작은 값을 고르고 `|baud_raw/std - 1| <= 3%`면 스냅.
7. 경고: `T < 4`(오버샘플링 부족), `explained < 0.8`(노이즈/잘못된 채널/비UART), 펄스 < 8개(데이터 부족), idle-low.
8. **교차 검증**: 스냅한 baud로 `sigrok-cli -i f.sr -P uart:rx=<ch>:baudrate=<b>[:invert_rx=yes] -A uart=rx-data`(문자 수)와 `-A uart=rx-warnings`(`Frame error` 수, 0.5.3 클래스명)를 세어 오류율이 낮은지 본다. 단 UART 허용오차 때문에 ±4% 이내 오설정은 프레임 오류가 0일 수 있다(실측: 115200 신호를 120000으로 디코드 → FE 0, 128000 → FE 91/91, 110000 → FE 28) → 표준 목록 스냅이 최종 판단.

표준 목록 — Linux termios 상수(https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/termbits.h, `B50`..`B4000000`) 중 300~3000000 구간:

```python
STANDARD_BAUDS = (300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38400, 57600,
                  115200, 230400, 460800, 500000, 576000, 921600, 1000000,
                  1152000, 1500000, 2000000, 2500000, 3000000)
```

(termios에는 14400/28800/76800/250000이 없다. 해당 장치를 다룬다면 목록에 추가하되 pyserial/드라이버 지원 여부는 별도 확인.)

### 12.3 참조 구현 (검증 완료, 8.5의 `channel_runs`와 함께 사용)

```python
def estimate_baud(runs, samplerate, snap_tol=0.03, glitch_max=1):
    """runs: iterable of (level, start, length). Returns dict with baud_raw, baud (snapped
    or None), samples_per_bit, idle_level, n_edges, explained, warnings."""
    runs = list(runs)
    res = {'n_edges': max(len(runs) - 1, 0), 'warnings': []}
    if len(runs) < 3:
        res['warnings'].append('too few edges (idle line or wrong channel)')
        return res
    lead, tail = runs[0], runs[-1]
    res['idle_level'] = lead[0] if lead[0] == tail[0] else None
    if res['idle_level'] == 0:
        res['warnings'].append('line idles LOW: inverted signal? use invert_rx=yes')
    inner = [r[2] for r in runs[1:-1]]                    # drop partial idle runs
    glitches = sum(1 for n in inner if n <= glitch_max)
    if glitches:
        res['warnings'].append('%d glitch runs (<= %d samples) ignored' % (glitches, glitch_max))
    inner = [n for n in inner if n > glitch_max]
    if len(inner) < 8:
        res['warnings'].append('too few usable pulses (%d)' % len(inner))
        if not inner:
            return res
    srt = sorted(inner)                                    # 1) provisional bit time
    k = max(3, len(srt) // 10)
    t = float(srt[min(k, len(srt)) // 2])
    explained = 0
    for _ in range(4):                                     # 2) refine: r ~= k*T
        sum_r = sum_k = 0
        explained = 0
        for n in inner:
            m = round(n / t)
            if 1 <= m <= 12 and abs(n - m * t) <= 0.3 * t:
                sum_r += n
                sum_k += m
                explained += 1
        if sum_k == 0:
            break
        t = sum_r / sum_k
    res['samples_per_bit'] = t
    res['explained'] = explained / len(inner)
    res['baud_raw'] = samplerate / t
    best = min(STANDARD_BAUDS, key=lambda b: abs(res['baud_raw'] / b - 1))
    res['baud'] = best if abs(res['baud_raw'] / best - 1) <= snap_tol else None
    if t < 4:
        res['warnings'].append('only %.1f samples/bit: raise samplerate (>= 10x baud recommended)' % t)
    if res['explained'] < 0.8:
        res['warnings'].append('only %.0f%% of pulses fit a single bit time' % (100 * res['explained']))
    return res

# 사용 예
info = read_sr('uart_boot.sr')
r = estimate_baud(channel_runs(info['data'], info['unitsize'], info['channels']['RX']),
                  info['samplerate'])
# 실측(uart1m.sr, D0): {'n_edges': 374, 'warnings': [], 'idle_level': 1, 'samples_per_bit': 8.681,
#                      'explained': 1.0, 'baud_raw': 115193.468, 'baud': 115200}
```

### 12.4 실측 결과 (합성 캡처, 91문자 U-Boot 배너, 8N1)

| baud | samplerate | 배율 | 변형 | estimate_baud raw | 스냅 | explained | guess_bitrate | 디코드 문자/FE | 경고 |
|---|---|---|---|---|---|---|---|---|---|
| 9600 | 100000 | 10.4 | clean | 9600 | 9600 | 1.00 | 10000 | 91/0 | |
| 19200 | 200000 | 10.4 | clean | 19199 | 19200 | 1.00 | 20000 | 91/0 | |
| 38400 | 500000 | 13.0 | clean | 38400 | 38400 | 1.00 | 38461 | 91/0 | |
| 57600 | 1000000 | 17.4 | clean | 57601 | 57600 | 1.00 | 58823 | 91/0 | |
| 115200 | 1000000 | 8.7 | clean | 115195 | 115200 | 1.00 | 125000 | 91/0 | |
| 115200 | 1000000 | 8.7 | inverted | 115195 | 115200 | 1.00 | 125000 | 91/0 | idle LOW |
| 115200 | 1000000 | 8.7 | glitch×5 | 115131 | 115200 | 0.99 | **1000000** | 91/1 | 6 glitch runs |
| 115200 | 2000000 | 17.4 | clean | 115202 | 115200 | 1.00 | 117647 | 91/0 | |
| 115200 | 4000000 | 34.7 | clean | 115202 | 115200 | 1.00 | 117647 | 91/0 | |
| 230400 | 2000000 | 8.7 | clean | 230389 | 230400 | 1.00 | 250000 | 91/0 | |
| 460800 | 4000000 | 8.7 | clean | 460778 | 460800 | 1.00 | 500000 | 91/0 | |
| 921600 | 8000000 | 8.7 | clean | 921556 | 921600 | 1.00 | 1000000 | 91/0 | |
| 921600 | 8000000 | 8.7 | inverted | 921556 | 921600 | 1.00 | 1000000 | 91/0 | idle LOW |
| 921600 | 8000000 | 8.7 | glitch×5 | 921187 | 921600 | 0.98 | **8000000** | 91/0 | 5 glitch runs |
| 1500000 | 12000000 | 8.0 | clean | 1500000 | 1500000 | 1.00 | 1500000 | 91/0 | |
| 3000000 | 24000000 | 8.0 | clean | 3000000 | 3000000 | 1.00 | 3000000 | 91/0 | |
| 115200 | 400000 | 3.5 | clean | 133333 | None | 0.35 | 133333 | — | 3.0 samples/bit, 35% fit |
| 115200 | 200000 | 1.7 | clean | 100000 | None | 0.70 | 200000 | — | 81 glitch runs, 2.0 samples/bit |

(합성 신호는 지터가 없는 이상적 파형이다. 실기 신호의 결과는 **미확인**이며, 링잉/노이즈가 있으면 `glitch_max`를 2~3으로 올린다.) 결론: 8배 이상이면 안정, 3.5배 이하에서는 오답(133333)을 낸다 — 이때 `baud=None`과 경고로 실패를 명확히 보고해야 한다.

### 12.5 샘플레이트 선택 (fx2lafw 이산 목록 기준)

권장 오버샘플링 **≥10배**(실측상 8배까지 양호, 4배 미만 실패). fx2lafw 목록에서 각 baud의 최소 권장값:

| baud | ≥10배 최소 fx2lafw samplerate | 배율 |
|---|---|---|
| 9600 | 100 kHz | 10.4 |
| 19200 | 200 kHz | 10.4 |
| 38400 | 500 kHz | 13.0 |
| 57600 | 1 MHz | 17.4 |
| 115200 | 2 MHz | 17.4 (1 MHz = 8.7배도 실측 양호) |
| 230400 | 3 MHz | 13.0 |
| 460800 | 6 MHz | 13.0 |
| 921600 | 12 MHz | 13.0 |
| 1500000 | 16 MHz | 10.7 |
| 3000000 | 24 MHz | 8.0 (10배 불가) |

보레이트 미상일 때 첫 캡처는 **8 MHz**(≤921600까지 8.7배 이상) 또는 그 이상으로 하고, 추정 후 필요하면 더 낮은 rate로 긴 캡처를 다시 한다.

### 12.6 함정

- **idle 라인**: 부트 로그는 전원 투입 직후에만 나온다 → 캡처를 먼저 시작하고 사람이 전원을 넣는다, 또는 `-t RX=f -c captureratio=1`. 에지가 없으면 `too few edges`.
- **글리치/링잉**: 1~2샘플 펄스가 `guess_bitrate`를 망친다(표: 1000000/8000000). 글리치 제외 + `explained` 비율로 판단.
- **반전 신호**: idle-low면 `invert_rx=yes`(0.5.3 uart 옵션). RS-232 레벨을 직접 연결하지 말 것(10.1).
- **모든 펄스가 짝수 배인 데이터 → 절반 보레이트로 오인** [실측]: 115200 @ 2 MHz로 `0xE6`을 200번 연속 전송하면 run이 2T,2T,2T,4T 반복이라 추정기가 `baud_raw 57599.63`, `baud 57600`, `explained 1.0`을 낸다. 더 나쁜 점은 57600으로 디코드해도 `AD` 100자 / Frame error 0, 115200으로 디코드하면 `E6` 200자 / Frame error 0으로 **둘 다 오류가 없다**. 같은 조건의 텍스트(`U-Boot 2016.11\r\n` 반복)는 115200을 정확히 냈다. 완화책: 추정 baud `b`와 `2b`를 모두 디코드해 비교하고(문자 수가 2배, 콘솔이면 `format=ascii`의 printable 비율이 높은 쪽), 바이너리 덤프 구간보다 텍스트 부트 로그 구간으로 추정한다.
- **여러 보레이트 혼재**: BootROM과 U-Boot/커널의 속도가 다를 수 있다 → idle 간격(예: 20T 이상)으로 구간을 나눠 구간별 추정.
- **잘못된 채널/GND 미연결**: 랜덤 에지 → `explained` 낮음.
- **임계 전압**: 1.8V UART + VIH 2.0V LA는 에지 누락. DSLogic은 `voltage_threshold` 조정 가능(wiki 예: `-c "samplerate=500k:voltage_threshold=2.5-2.5"`).
- **패리티/7비트**: 비트 시간 추정에는 영향 없음. 디코드 시 `data_bits`, `parity` 지정. 프레임 오류율이 높으면 7E1 등도 시도.
- **샘플레이트 오기입**: 입력 모듈 samplerate를 단위로 주면 1 Hz가 된다(5.1) → 추정 결과가 터무니없이 작음.

---

## 13. MCP 래퍼 구현 체크리스트

프로세스 실행:

- `subprocess.run([...], stdin=subprocess.DEVNULL, capture_output=True, timeout=...)` — **리스트 인자, shell 미사용**. MCP stdio의 stdin/stdout을 절대 상속하지 않는다(4.3).
- `--continuous`는 원칙적으로 금지. 필요하면 `stdin=PIPE` + 정지 시 1바이트 write, 타임아웃 시 SIGTERM(파일 손상 가능성 경고).
- 캡처 타임아웃 = `--time`(또는 samples/samplerate) + 여유(펌웨어 업로드·재열거 수 초). fx2lafw는 펌웨어 업로드 직후 `dev_open`에서 재열거를 최대 `MAX_RENUM_DELAY_MS 3000`(ms) 기다린다 [소스] (`fx2lafw/protocol.h`, `api.c`).
- loglevel은 기본(2)로 고정. 디버그가 필요하면 `-l 5`를 별도 진단 호출로만.
- **디코드 시간은 원시 샘플 수가 아니라 디코드되는 이벤트 수에 비례**한다(idle 구간은 libsigrokdecode C 코드가 건너뜀). 이 머신(WSL2) 실측 [실측]:

| 입력 | 작업 | 시간 | 최대 RSS |
|---|---|---|---|
| 40M 샘플 @ 8 MHz, 대부분 idle + UART 4000자 (`.sr` 74 KB) | `-i --show` | 0.03 s | 12.5 MB |
| 〃 | `-P uart ... -A uart=rx-data --protocol-decoder-samplenum` | 0.56 s | 19 MB |
| 〃 | `-B uart=rx` | 0.56 s | 19 MB |
| 〃 | `-O vcd` 변환 | 0.11 s | 12.7 MB |
| 40M 샘플 @ 8 MHz, UART 연속 트래픽 57,596자 | `-A uart=rx-data` 디코드 | 3.63 s (≈1.6만 자/s) | 19 MB |
| 4.8M 샘플 @ 24 MHz, SPI 6 MHz 클록 연속 150,000바이트(1.2M 비트) | `-A spi=mosi-data` | 6.69 s (≈18만 비트/s) | 62 MB |
| 〃 | `-B spi=mosi` | 6.24 s | — |
| 40M 샘플 dense UART | Python `read_sr` + `estimate_baud` | 0.42 s | 94 MB |
| 40M 샘플 idle 위주 | Python `read_sr` + `estimate_baud` | 0.10 s | — |

디코드 타임아웃 규칙(예): 먼저 Python `channel_runs`로 대상 선의 에지 수 E를 센다(40M 샘플에 0.1~0.4 s). 이 머신 처리율은 SPI ≈ 3.6×10^5 CLK 에지/s(= 1.8×10^5 비트/s), UART ≈ 9×10^4 RX 에지/s(≈ 1.6×10^4 자/s, 텍스트 1자당 에지 약 5.7개: 327,858 에지 / 57,596자)이므로 `timeout = 30 s + 3 × E / rate`로 잡는다. 4.7의 SPI 레시피(48M 샘플 @ 24 MHz)가 6 MHz 클록으로 꽉 차 있다면 약 1분 이상 걸릴 수 있다(외삽, **미확인**). 처리율은 머신 의존적이므로 설정값으로 둔다.

인자 조립:

- `-d <allowlisted driver>[:conn=<validated>]` 항상 명시. config는 allowlist 키만, 값은 **정수 Hz**.
- `-C`는 장치의 실제 채널 이름(스캔 결과) 중에서만, rename 값은 `^[A-Za-z][A-Za-z0-9_]{0,15}$` 등으로 제한.
- `-O`는 항상 명시(`srzip`). 출력 경로는 케이스 작업공간 안으로 제한.
- 디코드: `-i <file>`, raw면 `-I binary:numchannels=<n>:samplerate=<정수Hz>`, `-P` 채널 매핑 명시, `-A` 명시, `--protocol-decoder-samplenum` 항상.
- 버전에 따른 클래스 이름은 `-P <pd> --show`를 캐시해 사용(6장 표).

결과 파싱:

- 주석: 5.4 정규식, strip 금지, 인스턴스 ID → 스택/채널 매핑 역참조.
- `-B` 결과는 바이트로 받아 파일 저장(`stdout` bytes).
- 판정: 5.7 표. rc=0이어도 stderr 패턴 검사, 결과 0줄 경고.

권장 MCP 도구 구성(예시): `sigrok_version`, `sigrok_scan(driver, conn?)`, `sigrok_show_device(driver, conn?)`, `sigrok_capture(driver, conn?, samplerate_hz, samples|time_ms, channels, triggers?, wait_trigger?, out_path)`, `sigrok_file_info(path)`, `sigrok_decode(path, stacks, annotations)`, `sigrok_decode_binary(path, stack, binclass, out_path)`, `sigrok_export(path, format, out_path)`, `estimate_baud(path, channel)`(순수 Python, sigrok-cli 불필요), `verify_baud(path, channel, baud, invert?)`.

---

## 14. 미확인 항목

- fx2lafw/DSLogic 실장치의 `--scan`·`--show` 실제 출력(3.3, 3.4(c))은 소스 기반 추론이며 실기 미확인. 특히 첫 스캔에서 `:conn=`이 빠지는 동작.
- fx2lafw 24 MHz 장시간 스트리밍 안정성, 48 MHz 항목의 실제 동작.
- WSL2 + usbipd에서 fx2lafw 재열거 후 재연결 동작.
- SIGINT/SIGTERM 중단 시 `.sr` 손상 가능성(로컬 2회 시험에서는 정상).
- fx2lafw 첫 사용 시 실제 총 대기 시간(펌웨어 업로드 + 재열거; 소스상 재열거 대기 상한 3000 ms).
- Saleae Logic Pro, raspberrypi-pico, kingst-la2016의 채널 이름·속도(master/nightly 미설치로 미실측).
- 실기 UART 신호(지터·링잉 포함)에서의 추정기 성능.
- master/nightly sigrok-cli의 주석 출력 형식(0.7.2와 동일하다고 가정하지 말 것).
- [소스]로만 확인한 오류 메시지의 실제 stderr 접두어(`sr: <module>: ` 유무).
- 대용량(48M 샘플 이상) dense SPI 디코드 시간(13장의 처리율 외삽) 및 다른 머신에서의 처리율.

---

## 15. 출처

- sigrok-cli 0.7.2 소스/문서: https://github.com/sigrokproject/sigrok-cli/tree/sigrok-cli-0.7.2 (`main.c`, `decode.c`, `show.c`, `session.c`, `parsers.c`, `anykey.c`, `doc/sigrok-cli.1`, `NEWS`), tarball https://sigrok.org/download/source/sigrok-cli/sigrok-cli-0.7.2.tar.gz
- libsigrok 0.5.2: https://github.com/sigrokproject/libsigrok/tree/libsigrok-0.5.2 (`src/output/srzip.c`, `src/output/vcd.c`, `src/session_file.c`, `src/session_driver.c`, `src/strutil.c`, `src/resource.c`, `src/usb.c`, `src/hwdriver.c`, `src/hardware/fx2lafw/*`, `src/hardware/dreamsourcelab-dslogic/api.c`, `src/hardware/saleae-logic16/*`)
- libsigrokdecode 0.5.3: https://github.com/sigrokproject/libsigrokdecode/tree/libsigrokdecode-0.5.3 (`instance.c`, `type_decoder.c`, `srd.c`, `decoders/uart|spi|i2c|spiflash|guess_bitrate/pd.py`)
- libsigrokdecode master: https://github.com/sigrokproject/libsigrokdecode/tree/master/decoders ; libsigrok master: https://github.com/sigrokproject/libsigrok/tree/master/src/hardware
- sigrok wiki: https://sigrok.org/wiki/Sigrok-cli , https://sigrok.org/wiki/File_format:Sigrok/v2 , https://sigrok.org/wiki/Fx2lafw , https://sigrok.org/wiki/MCU123_Saleae_Logic_clone , https://sigrok.org/wiki/DreamSourceLab_DSLogic , https://sigrok.org/wiki/Saleae_Logic16 , https://sigrok.org/wiki/Protocol_decoder:Uart , https://sigrok.org/wiki/Protocol_decoder_output
- Ubuntu 패키지 버전: https://launchpad.net/ubuntu/+source/sigrok-cli , https://launchpad.net/ubuntu/+source/libsigrok , https://launchpad.net/ubuntu/+source/libsigrokdecode
- Linux termios 보레이트 상수: https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/termbits.h
- WSL USB: https://learn.microsoft.com/en-us/windows/wsl/connect-usb
- sigrok-rp2350(0.7.2에 Pico 드라이버 없음 언급): https://github.com/c1570/sigrok-rp2350
