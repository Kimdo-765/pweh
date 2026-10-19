# 하드웨어 셋업 가이드

이 문서는 사람이 하는 물리 작업을 다룬다. 장비 준비, 배선, 분석 PC 연결이 여기에 해당한다.
에이전트는 이 문서를 근거로 사용자에게 무엇을 연결할지 안내한다.
먼저 [안전 가이드](safety.md)를 읽는다.

## 1. 장비

| 용도 | 권장 장비 | 비고 |
|---|---|---|
| UART | USB-UART 어댑터 (CP2102, CH340, FT232R/FT232H, PL2303) | **3.3V 로직** 지원 필수. 1.8V 기기에는 1.8V 지원 어댑터(예: FT232H + 레벨 설정) 또는 레벨 시프터 |
| 로직 애널라이저 | fx2lafw 계열(Saleae Logic 클론, 8ch/24MHz), DSLogic | sigrok(`pweh-sigrok`)으로 사용. UART 보드레이트·핀 확인용 |
| JTAG/SWD 프로브 | FT2232H 보드(Tigard 등), J-Link, ST-Link, CMSIS-DAP, Raspberry Pi GPIO | OpenOCD(`pweh-openocd`)로 사용 |
| 핀아웃 스캐너 | JTAGulator (선택) | `pweh-jtagulator`. 미지의 핀에서 JTAG/UART 탐색 |
| SPI 플래시 직접 읽기 | SOIC-8 클립 + SPI 프로그래머 (CH341A **3.3V 개조판**, FT2232H + flashrom) | UART 덤프가 안 될 때. 사람이 수행 후 `case_import_file` 로 가져옴 |
| 측정 | 멀티미터 (연속성/DC 전압), 확대경 | 전압 레벨과 GND 확인 |
| 작업 | 인두, 2.54mm 핀 헤더, 듀폰 케이블, 정전기 방지 매트/스트랩 | |
| 전원 | 기기용 DC 어댑터 (12V/5V) | PoE 대신 DC 잭 사용 권장 |

## 2. 분석 PC 준비

### 2.1 소프트웨어
```bash
cd /path/to/pweh
./scripts/install.sh              # Python 가상환경 + 외부 도구(~/pweh-tools) + REA, sudo 없음
. ~/pweh-tools/env.sh            # sigrok-cli, openocd, binwalk, unblob, Ghidra, JDK 경로
.venv/bin/pweh doctor             # 환경 점검
```
설치 스크립트의 구성요소·옵션·검증 범위는 [mcp-setup.md](mcp-setup.md) §1 에 있다.

### 2.2 WSL2 에서 USB 장치 쓰기 (usbipd-win)
WSL2 는 USB 장치를 직접 보지 못한다. Windows 쪽에서 [usbipd-win](https://github.com/dorssel/usbipd-win) 으로 장치를 WSL 에 붙인다.

```powershell
# Windows PowerShell (관리자) — 최초 1회 설치: winget install usbipd
usbipd list                          # BUSID 확인 (예: 2-3  CP2102 USB to UART Bridge)
usbipd bind --busid 2-3              # 최초 1회 (관리자 권한)
usbipd attach --wsl --busid 2-3      # 연결할 때마다 (장치를 뽑았다 꽂으면 다시)
```
WSL 쪽 확인:
```bash
ls -l /dev/ttyUSB* /dev/ttyACM*      # USB-UART
lsusb                                # 로직 애널라이저/JTAG 프로브
```

### 2.3 장치 권한
- 시리얼 포트: `dialout` 그룹이 필요하다. `sudo usermod -aG dialout $USER` 를 실행하고 다시 로그인한다.
  일회성으로는 `sudo chmod a+rw /dev/ttyUSB0` 를 쓴다.
- 로직 애널라이저/JTAG 프로브(libusb): `/dev/bus/usb/...` 접근 권한이 필요하다. 방법은 둘 중 하나다.
  - sigrok 의 udev 규칙(`60-libsigrok.rules`, libsigrok 소스의 `contrib/`)이나 OpenOCD 의 `contrib/60-openocd.rules` 를
    `/etc/udev/rules.d/` 에 복사하고 `sudo udevadm control --reload && sudo udevadm trigger` 를 실행한다.
  - WSL2 처럼 udev 가 동작하지 않는 환경에서는 attach 할 때마다 `sudo chmod a+rw /dev/bus/usb/<bus>/<dev>` 를 실행한다.
- fx2lafw 장치는 연결할 때마다 펌웨어를 업로드한다. 이때 USB 장치가 재열거되므로 **WSL 에서는 attach 를 한 번 더** 해야 할 수 있다.
  usbipd 4.x 는 `usbipd attach --wsl --busid X --auto-attach` 를 지원한다.
- `pweh doctor` 가 `dialout` 그룹, 시리얼 포트 목록, WSL 여부를 점검한다.

## 3. UART 찾기와 연결

### 3.1 패드 찾기
카메라 보드에서 UART 는 대개 다음 형태다.
- SoC 근처의 3~4핀 헤더 또는 테스트 패드. `TX RX GND VCC` 실크가 있거나 아무 표시가 없다.
- 1.27mm/2.0mm/2.54mm 간격의 패드 4개가 한 줄로 놓인 경우가 많다.

멀티미터로 구분하는 방법 (기기 전원을 끈 상태에서 시작):
1. **GND**: 연속성 모드로 USB 쉴드나 DC 잭 바깥쪽과 통하는 패드를 찾는다.
2. **VCC**: 전원을 켜고 DC 전압을 잰다. 항상 3.3V(또는 1.8V)로 일정한 패드다. **연결하지 않는다.**
3. **TX** (기기 → PC): 전원을 켠 직후 부팅 로그가 나오는 동안 전압이 흔들리는 패드다.
   멀티미터 평균값이 3.3V 아래로 출렁인다.
4. **RX** (PC → 기기): 나머지 패드다. 대개 3.3V 근처에서 안정적이다.

로직 애널라이저가 있으면 더 확실하다.
1. 후보 패드들과 GND 에 프로브를 물린다.
2. `logic-analyzer-protocol-decode` Skill 로 부팅 중에 캡처한다.
3. `sigrok_estimate_baud` 로 TX 핀과 보드레이트를 한 번에 찾는다.

핀을 전혀 모르면 JTAGulator 로 찾는다.
- 먼저 타깃에 아무것도 보내지 않는 `jtagulator_uart_txd_scan` 으로 TXD 와 보드레이트를 찾고, 필요하면 `jtagulator_uart_scan` 으로 RXD 까지 찾는다.
- 스캔 전에 `jtagulator_set_voltage` 로 타깃 I/O 전압(사람이 멀티미터로 잰 값)을 설정해야 한다. 이 도구는 DESTRUCTIVE 라 기본 정책에서는 거부된다.
  운영자가 `safety.destructive_policy: approve` 로 바꾸고 사람이 승인해야 쓸 수 있다 ([안전 가이드 §2.4, §3.2](safety.md)).

### 3.2 배선

```
  카메라 보드                 USB-UART 어댑터 (3.3V 로직)
  ┌─────────┐                ┌──────────────┐
  │   GND ──┼────────────────┼── GND        │
  │   TX  ──┼────────────────┼── RX         │
  │   RX  ──┼────────────────┼── TX         │
  │   VCC   │  (연결 안 함)   │   VCC (사용 안 함)
  └─────────┘                └──────────────┘
```

- TX/RX 를 반대로 꽂아도 망가지지는 않지만 아무것도 보이지 않는다. 출력이 없으면 먼저 서로 바꿔 본다.
- 출력이 깨진 문자로만 나오면 보드레이트가 틀렸거나 GND 가 빠진 것이다.
  `uart_detect_baud` 를 쓰거나 로직 애널라이저로 확인한다.
- 처음에는 **RX(어댑터 TX) 선을 빼고 TX 만 연결**해서 부팅 로그를 관찰해도 된다. 기기에 아무것도 보내지 않으므로 가장 안전하다.

### 3.3 첫 연결 절차 (uart-shell-acquisition Skill 이 안내)
1. 사람: 배선 후 어댑터를 PC 에 연결한다. WSL 이면 `usbipd attach` 를 실행한다.
2. 에이전트: `uart_list_ports` 로 포트를 확인하고 `uart_detect_baud` 로 보드레이트를 찾는다.
   부팅 출력이 있어야 하므로 전원 투입 타이밍을 맞춘다(아래 순서).
   Ctrl-C 프로브(`probe="ctrl-c"`)는 MODIFY 이고 맞는 속도로 닿으면 autoboot 를 멈출 수 있으므로, 부팅 중에는 `probe="none"` 으로 듣기만 한다.
3. 에이전트: `uart_open` 을 한 뒤 `uart_capture_boot` 로 부팅 로그를 수집한다.
4. U-Boot 진입이 필요하면 에이전트가 `uboot_interrupt` 를 호출한다.

전원 투입 타이밍(2~4단계 공통): 사람은 기기 전원을 **먼저 꺼 둔 채** "준비" 라고 알리고, 에이전트가 도구를 호출해 감시가 시작되면 그때 전원을 넣는다.
켜져 있는 기기에서 감시를 시작하면 이전 부팅의 출력이 섞이고, `uboot_interrupt` 는 창 안에 새 부팅이 없으면 키를 보내지 않고 `window_expired` 로 끝난다.

## 4. 로직 애널라이저

```
  카메라 보드                fx2lafw 로직 애널라이저
     GND ──────────────────── GND   (가장 먼저 연결)
     TX 후보 ───────────────── D0
     RX 후보 ───────────────── D1
     (SPI: CLK/MOSI/MISO/CS ── D2..D5, I2C: SCL/SDA ── D6/D7)
```
- 샘플레이트는 측정할 신호의 **최소 4배, 가능하면 10배 이상**으로 잡는다.
  115200bps UART 에는 1MHz 이상, 1.5Mbps 에는 12MHz 이상, SPI 플래시에는 클럭의 4배 이상이 필요하다.
- 입력 허용 전압을 넘지 않는다 (보통 5V 허용, 3.3V 로직).
- 사용 가능한 장치는 `sigrok_scan` 으로 확인한다. 하드웨어 없이 연습할 때는 sigrok 의 `demo` 드라이버를 쓴다.

## 5. JTAG / SWD

- 카메라 SoC 는 양산품에서 JTAG 가 **퓨즈로 비활성화**되었거나 핀이 GPIO 로 먹스(mux)된 경우가 많다.
  UART/U-Boot 경로가 실패했을 때의 대안으로 본다.
- 표준 헤더(ARM 20핀, 10핀 Cortex, 14핀 MIPS EJTAG)가 보이면 핀맵 문서를 확인한다.
  표시가 없는 패드는 JTAGulator 로 IDCODE/BYPASS 스캔을 한다.
- 프로브의 VTref 는 대상 전압 **감지**용이다. 대상의 VCC 에 연결한다 (전원을 공급하지 않는다). GND 는 반드시 공통으로 묶는다.
- OpenOCD 인터페이스 설정 예 (xPack OpenOCD 0.12 기준 `$PWEH_OPENOCD_SCRIPTS` 아래):

| 프로브 | interface cfg |
|---|---|
| FT2232H 일반 / Tigard | `interface/ftdi/tigard.cfg` 또는 보드에 맞는 `interface/ftdi/*.cfg` |
| J-Link | `interface/jlink.cfg` |
| ST-Link | `interface/stlink.cfg` |
| CMSIS-DAP | `interface/cmsis-dap.cfg` |
| Raspberry Pi GPIO | `interface/raspberrypi-native.cfg` (bcm2835gpio 드라이버). 또는 `-c "adapter driver linuxgpiod"` + `interface/raspberrypi-gpio-connector.cfg` (핀 매핑만 정의: TCK=GPIO11, TMS=GPIO8, TDI=GPIO10 …) |

자세한 내용은 `docs/references/openocd-tcl-rpc.md` 와 `mcp-servers/openocd-mcp/README.md` 를 본다.

## 6. SPI 플래시 직접 읽기 (사람이 수행)

UART 덤프가 불가능하거나 너무 느릴 때 쓴다. 16MiB 를 115200bps 로 받으면 수 시간이 걸린다.
1. 기기 전원을 끄고 SoC 근처의 8핀 SOIC 플래시를 찾는다 (예: W25Q128, MX25L12835F, GD25Q128 계열 — 마킹 확인).
2. 클립 1번 핀(빨간 선)을 칩의 점(●) 표시에 맞춘다.
3. 3.3V 프로그래머로 두 번 읽고 두 덤프의 sha256 이 같은지 확인한다. 예: `flashrom -p ch341a_spi -r dump1.bin`.
   보드 역전원 문제는 [안전 가이드 §2.5](safety.md)를 본다.
4. 에이전트에게 파일 경로를 알려 주면 `case_import_file` 로 케이스에 가져와 `firmware-static-analysis` 를 진행한다.
   UART 덤프가 일부라도 있으면 `case_hash_file(case_id, path, offset, length)` 로 같은 구간의 sha256/md5/crc32 를 비교해 교차 검증한다.

## 7. 하드웨어 없이 연습하기

`pweh-mock-device` 는 카메라 UART 콘솔을 흉내 내는 시뮬레이터다. U-Boot, Linux 부팅, BusyBox 셸, 합성 펌웨어 16MiB 를 갖추고 있다.

```bash
.venv/bin/pweh-mock-device --profile hisilicon-like --pty
# → {"pty": "/dev/pts/7", ...}  이 경로를 uart_open 의 port 로 사용
# 표준입력에 power-cycle 을 입력하면 "사람이 전원을 껐다 켠" 것과 같다
```
자세한 내용은 `tests/mock-targets/README.md` 를 본다.
