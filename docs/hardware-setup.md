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
| ESP32 덤프 | USB **데이터** 케이블 (DevKit 은 USB 하나로 전원·통신). 헤더만 있는 모듈은 3.3V USB-UART 어댑터 | `pweh-esp`(esptool). 칩·보안 정보와 플래시 이중 읽기 덤프 (§8) |
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
(ESP32 보드는 usbipd 없이 Windows 용 esptool.exe 로 쓸 수 있다 — §8.1 방법 A.)
attach 하면 WSL 안의 usbip 클라이언트가 Windows 의 usbipd 서비스(TCP 3240)에 접속해 장치를 가져온다.
아래 동작은 usbipd-win v5.3.0 소스([Wsl.cs](https://github.com/dorssel/usbipd-win/blob/v5.3.0/Usbipd/Wsl.cs) — 접속 주소·방화벽 확인,
[Program.cs](https://github.com/dorssel/usbipd-win/blob/v5.3.0/Usbipd/Program.cs) — 옵션,
[Server.wxs](https://github.com/dorssel/usbipd-win/blob/v5.3.0/Installer/Server.wxs) — 방화벽 규칙)와
[WSL 설정 문서](https://learn.microsoft.com/windows/wsl/wsl-config)의 `networkingMode` 항목을 근거로 한다.

**1) WSL 네트워킹 모드부터 확인한다.** usbipd 는 모드에 따라 WSL 이 Windows 에 다시 접속할 주소를 정한다.
```bash
wslinfo --networking-mode            # WSL 쪽. nat | mirrored | virtioproxy | bridged | none …
```

| 모드 | usbipd 가 쓰는 Windows 주소 | attach 방법 |
|---|---|---|
| `nat` (기본값) | WSL 의 기본 게이트웨이(`/proc/net/route`) | `usbipd attach --wsl --busid <BUSID>` |
| `mirrored`, `virtioproxy` | `127.0.0.1` (루프백) | `usbipd attach --wsl --busid <BUSID>` |
| `bridged` (WSL 2.4.5 부터 deprecated) | 자동으로 정하지 못한다. `Networking mode 'bridged' is not supported.` 로 실패 | `--host-ip` 로 Windows 주소를 직접 준다(아래) |
| `consomme` (예전 이름 `virtioproxy`) | v5.3.0 은 모르는 값이라 위와 같이 실패한다 | `--host-ip 127.0.0.1` |
| `none` | 네트워크가 없어 쓸 수 없다 | `.wslconfig` 의 `networkingMode` 를 바꾼다 |

**2) 장치를 공유(bind)하고 붙인다(attach).**
```powershell
# Windows PowerShell (관리자) — 최초 1회 설치: winget install usbipd
usbipd list                          # BUSID 와 STATE 확인 (예: 2-3  CP2102 USB to UART Bridge  Not shared)
usbipd bind --busid 2-3              # 최초 1회 (관리자 권한, 재부팅 뒤에도 유지)
usbipd attach --wsl --busid 2-3      # nat / mirrored: 연결할 때마다 (장치를 뽑았다 꽂으면 다시)

# bridged 모드: 'vEthernet (WSL External)' 어댑터의 IPv4 주소를 --host-ip 로 준다
ipconfig                             # 'vEthernet (WSL External)' 어댑터의 IPv4 주소를 확인한다
usbipd attach --wsl --busid 2-3 --host-ip <vEthernet (WSL External) IPv4>
```
- bridged 모드의 Windows 주소는 DHCP 로 받으므로 바뀔 수 있다. attach 할 때마다 `ipconfig` 로 다시 확인한다.
  WSL 의 기본 게이트웨이는 공유기라서 usbipd 가 주소를 추정하지 않는다.
- 방화벽: 설치 프로그램이 `usbipd` 규칙(TCP 3240 인바운드, 모든 프로필, 범위 `localSubnet`)을 만든다.
  WSL 주소(`ip -4 addr show eth0`)가 Windows 와 다른 서브넷이거나, 그룹 정책이 로컬 규칙을 막거나(공용 프로필 `AllowLocalPolicyMerge=0` 등),
  서드파티 방화벽을 쓰면 attach 가 `A firewall appears to be blocking the connection; ensure TCP port 3240 is allowed.` 경고를 낸다.
  이때는 관리자가 WSL 주소에서 오는 TCP 3240 인바운드를 허용한다.

**3) 붙어 있는 동안 Windows 는 그 장치를 쓰지 못한다.** Windows 장치 관리자의 COM 포트(예: `COM3`)가 사라지고, Windows 프로그램
(PuTTY, Windows 용 esptool.exe 의 `--port COM3` 등 — WSL interop 으로 실행해도 마찬가지)은 그 포트를 열 수 없다. Windows 쪽에서 다시 쓰려면 떼어 낸다.
```powershell
usbipd detach --busid 2-3            # 또는 usbipd detach --all. 장치를 뽑았다 꽂아도 떨어진다
```
반대로 Windows 쪽 도구로 COM 포트를 쓰는 동안에는 attach 하지 않는다.

**4) 리셋 때 USB 를 다시 열거하는 장치는 `--auto-attach` 를 쓴다.** 재열거되면 WSL 에서 떨어지기 때문이다.
- ESP32-S3 내장 USB-Serial/JTAG(`303a:1001`): esptool 이 칩을 리셋할 때(다운로드 모드 진입·종료 포함) 다시 열거된다.
- fx2lafw 로직 애널라이저: 연결할 때마다 펌웨어를 올린 뒤 다시 열거된다(2.3 절).
```powershell
usbipd attach --wsl --busid 2-3 --auto-attach    # 다시 나타날 때마다 다시 붙인다. 이 창은 계속 실행된다(끝낼 때 Ctrl+C)
```
리셋 뒤 다른 VID:PID 로 나타나는 경우(ESP32-S3 ROM 의 USB-OTG 다운로드 모드 `303a:0009`)는 `usbipd list` 에서 새 항목의 STATE 를 확인하고,
`Not shared` 면 그것도 bind 한다. auto-attach 를 쓰지 못하면 사람이 BOOT 버튼을 누른 채 리셋해 다운로드 모드로 둔 뒤 attach 한다.

WSL 쪽 확인:
```bash
ls -l /dev/ttyUSB* /dev/ttyACM*      # USB-UART (ESP32-S3 USB-Serial/JTAG 는 /dev/ttyACM*)
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

## 8. ESP32 보드 (esptool)

ESP32 계열(ESP32·ESP32-S2·ESP32-S3·ESP32-C3 …) 보드와 모듈은 UART 콘솔 대신 `pweh-esp`(esptool)로 칩·보안 정보를 읽고 SPI 플래시를 덤프한다.
에이전트 절차는 `esp32-flash-dump` Skill, 도구 계약은 [architecture.md](architecture.md) §6.7, 안전 규칙은 [안전 가이드 §2.7·§3.3](safety.md) 에 있다.
보드를 연결하는 방법은 둘이다. WSL 에서는 방법 A 를 권장한다.

### 8.1 방법 A — WSL 에서 Windows esptool.exe + COM 포트 (권장)
- 보드를 Windows PC 에 USB 로 연결한 그대로 둔다. **usbipd attach 를 하지 않는다.** attach 하면 Windows 에서 COM 포트가 사라져 이 방법을 쓸 수 없다(§2.2 의 3).
- Windows 장치 관리자의 '포트(COM & LPT)' 에 COM 포트가 생기는지 본다(예: `Silicon Labs CP210x USB to UART Bridge (COM3)`).
  ESP 내장 USB-Serial/JTAG 는 보통 Windows 기본 드라이버의 'USB 직렬 장치(COMn)' 로 보인다. 에이전트는 `esp_list_ports` 로 같은 목록과 USB ID 를 본다.
- 설치는 `./scripts/install.sh --only esptool` 이고, Windows 쪽에는 따로 설치할 것이 없다. WSL interop 이 켜져 있어야 한다([mcp-setup.md](mcp-setup.md) §6).
- 서버가 WSL interop 으로 Windows 용 esptool.exe 를 실행한다. 에이전트는 `port="COM3"` 처럼 COM 이름을 그대로 주고,
  덤프 파일은 esptool.exe 가 `\\wsl.localhost\<배포판>\…` 경로로 케이스 `dumps/` 에 바로 쓴다.

### 8.2 방법 B — usbipd + 리눅스 esptool
- WSL interop 을 쓸 수 없거나 네이티브 리눅스면 §2.2 대로 `usbipd bind`·`usbipd attach` 한 뒤 리눅스 포트를 쓴다.
- 포트 이름은 연결 방식에 따라 다르다.
  - ESP 내장 USB-Serial/JTAG(`303a:1001`, ESP32-S3·C3·C6·H2 의 네이티브 USB): `/dev/ttyACM0`.
  - USB-UART 브리지(CP210x `10c4:ea60`, CH340 `1a86:7523`, CH343, CH9102, FTDI): `/dev/ttyUSB0`.
- 내장 USB-Serial/JTAG 는 esptool 이 칩을 리셋할 때(다운로드 모드 진입·종료 포함) USB 를 다시 열거해 WSL 에서 떨어진다.
  `usbipd attach --wsl --busid <BUSID> --auto-attach` 를 쓴다(§2.2 의 4). ESP32-S3 ROM 의 USB-OTG 다운로드 모드(`303a:0009`)처럼 다른 VID:PID 로 나타나면 그 항목도 bind 한다.
  다시 열거되면 장치 번호(`/dev/ttyACM0` → `/dev/ttyACM1`)가 바뀔 수 있으니 `esp_list_ports` 로 다시 확인한다.
- 시리얼 포트 권한(`dialout`)은 §2.3 을 따른다. 그 tty 를 연 다른 프로그램(시리얼 모니터, uart-mcp 세션)이 있으면 서버가 `busy` 로 거부한다.

### 8.3 보드 준비와 물리 작업 (사람)
- 데이터 케이블을 쓴다. 충전 전용 케이블이면 포트가 생기지 않는다.
- USB 포트가 둘인 DevKit(예: ESP32-S3 DevKit 의 `UART` 와 `USB`)은 역할이 다르다. 하나는 USB-UART 브리지 칩을 거치는 UART0 포트이고, 하나는 칩 내장 USB-Serial/JTAG 포트다.
  둘 다 esptool 로 쓸 수 있다. 연결에 실패하면 다른 포트로 바꿔 본다.
- 자동 리셋: DevKit 은 USB-UART 의 DTR/RTS 가 EN 과 부트 스트랩 핀에 연결되어 있어 esptool 이 스스로 다운로드 모드로 넣는다. 내장 USB-Serial/JTAG 는 USB 쪽 리셋을 쓴다.
- 자동 리셋이 안 되면(`esp_no_serial_data`, `esp_wrong_boot_mode`) 사람이 BOOT 를 누른 채 RESET(EN)을 눌렀다 떼고, 그다음 BOOT 를 놓는다. 그 뒤 에이전트가 `before="no-reset"` 으로 다시 호출한다
  (`after="no-reset-stub"` 이면 호출 사이에도 칩이 다운로드 모드에 머물러 BOOT+RESET 을 다시 하지 않아도 된다).
  BOOT 버튼은 부트 스트랩 핀을 내린다(ESP32·ESP32-S2·ESP32-S3 는 GPIO0, ESP32-C3·C6·H2 는 GPIO9). 정확한 핀은 칩 데이터시트로 확인한다.
- 같은 포트를 연 시리얼 모니터(Arduino IDE, `idf.py monitor`, PuTTY)는 닫는다.
- **보드는 재부팅된다.** esptool 은 연결할 때마다 칩을 리셋해 ROM 다운로드 모드로 넣으므로 실행 중이던 펌웨어가 멈춘다.
  덤프가 끝나면 기본(`after="hard-reset"`)으로 앱이 다시 시작된다. 덤프를 취소했거나 `after="no-reset-stub"`(`no-reset` 요청 포함)이라 칩이 다운로드 모드에 남았으면 RESET 을 누른다.
- 방법 A 에서 덤프를 취소하거나 시간이 초과된 뒤 에이전트가 'Windows 에 esptool.exe(PID n)가 남았다' 고 알리면, Windows 작업 관리자에서 그 esptool.exe 를 끝내거나
  Windows 터미널에서 `taskkill /F /PID n` 을 실행한다(보드 USB 를 뽑았다 꽂아도 된다). 그 프로세스가 COM 포트를 잡고 있는 동안에는 다시 읽을 수 없다.
- 헤더만 있는 모듈이나 제품 보드: 3.3V USB-UART 어댑터를 UART0 의 TX/RX/GND 에 §3.2 처럼 연결한다(VCC 연결 안 함).
  부트 스트랩 핀을 GND 로 내린 채 EN 을 리셋해 다운로드 모드로 넣는다. 어떤 패드가 UART0·스트랩 핀·EN 인지는 모듈 데이터시트로 확인한다.

### 8.4 주의
- PWEH 는 esptool 의 쓰기·삭제·eFuse 명령(`write-flash`, `erase-flash`, espefuse 등)을 실행하지 않는다. 요청해도 거부되고 승인으로도 풀리지 않는다.
  끝날 때 FLASH_BEGIN 을 보내는 `--after no-reset`·`soft-reset` 도 쓰지 않는다(레거시 스텁은 이때 SPI 플래시 상태 레지스터를 다시 쓴다).
- esptool 설정 파일(`~/.config/esptool/esptool.cfg`, Windows `%USERPROFILE%\AppData\Local\esptool\esptool.cfg`)은 읽지 않는다. 그런 설정을 읽었다는 오류(`esp_foreign_config`)가 나면
  사람이 그 파일의 `[esptool]` 섹션을 확인·제거하거나 파일을 옮긴다.
- Secure Download Mode 가 켜진 칩은 esptool 로 플래시를 읽을 수 없다. `esp_security_info` 의 `read_flash_possible=false` 면 덤프하지 않고, 글리칭·eFuse 조작 같은 우회도 하지 않는다.
- 플래시 암호화가 켜져 있으면 덤프는 암호문이다(`ciphertext_expected=true`). 키는 읽기 보호된 eFuse 에 있다.
- 속도: 921600 baud 에서 4 MB 는 보통 1~2분, 115200 baud 면 6분 이상 걸린다(기본 이중 읽기는 두 배).
  전송 오류나 baud 변경 직후 끊김(`esp_baud_switch_failed` — USB-UART 브리지가 921600 을 못 버팀)이 나면 baud 를 460800, 115200 으로 낮춘다. ESP 내장 USB-Serial/JTAG 연결은 baud 와 무관하다.
