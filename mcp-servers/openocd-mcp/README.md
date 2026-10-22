# openocd-mcp (pweh-openocd)

OpenOCD 프로세스를 띄우고 TCL RPC(기본 포트 6666)로 JTAG/SWD 디버그 프로브를 제어하는 PWEH MCP 서버다.
스캔체인/타깃 확인, halt·reset, 레지스터/메모리 읽기, 메모리·플래시 덤프(백그라운드 작업)를 제공하고,
모든 기기 조작은 서버 측 안전 게이트를 거친다. **본인 소유이거나 서면 허가를 받은 기기에만 사용한다.**

- 계약: `docs/architecture.md` 6.4 / 프로토콜·출력 형식 근거: `docs/references/openocd-tcl-rpc.md`,
  `~/pweh-tools/INSTALL_REPORT.md` (xPack OpenOCD 0.12.0-7 로 실측)
- 실행: `pweh-openocd-mcp` 또는 `python -m openocd_mcp` (stdio). 로그는 stderr (`pweh.openocd`).

WSL의 명시 Windows backend는 [dummy-noinit-v1 무장치 진단](../../docs/references/windows-openocd-dummy.md)과 [tigard-jtag-v1 고정 어댑터 조회](../../docs/references/windows-openocd-tigard.md)를 제공한다. Tigard는 JTAG 100 kHz·전체 USB lease·가드가 적용된 init과 version/scan_chain/targets·status·stop만 지원하며, 타깃 설정·메모리·덤프는 포함하지 않는다. Tigard 실기 검증은 남아 있다. 아래 준비·배선·덤프 절차는 기본 Linux backend에 적용한다.

## 1. 준비

| 항목 | 내용 |
|---|---|
| OpenOCD | `PWEH_OPENOCD`(절대경로) 또는 `pipeline-config.yaml` 의 `tools.openocd`. 없으면 `ToolMissing`. `~/pweh-tools/env.sh` 가 xPack 0.12.0-7 을 가리킨다 |
| scripts | `PWEH_OPENOCD_SCRIPTS` 가 있으면 `-s` 로 넘긴다 (xPack 은 없어도 자체 scripts 를 찾는다) |
| 버전 | xPack 0.12.0+dev 로 검증. 0.12.0 릴리스/0.11.0(우분투 22.04 apt)도 고려: 포트 명령은 `if {[catch {tcl port N}]} {tcl_port N}` 이식형, 응답 끝 개행/음수 오류 코드/`capture` 의미 차이/`read_memory` 부재(0.11 → `mdw` 파싱)를 처리 |
| 케이스 | 하드웨어 도구는 소유/허가 증명이 있는 케이스(`case_create`)에서만 동작 |
| WSL2 | USB 프로브는 `usbipd` 로 리눅스에 붙여야 OpenOCD 가 볼 수 있다. 권한 문제는 udev 규칙 |

## 2. 기본 흐름 (에이전트)

1. 사람이 배선을 마쳤는지 확인 (아래 3장). 타깃 전원은 사람이 켠다.
2. `openocd_list_configs(kind="interface", pattern="ftdi")` 로 cfg 확인.
3. `openocd_start(case_id, interface_cfg, target_cfg=… | extra_commands=[…], transport="jtag", adapter_speed_khz=500, tcl_port=0)`
   - 응답의 `health`, `startup.taps`(IDCODE·제조사), `startup.auto_newtap_suggestions`, `diagnosis`(배선/전원 힌트)를 먼저 본다.
   - 카메라 SoC 는 전용 target cfg 가 거의 없다 → target cfg 없이 시작해 OpenOCD 의 자동 탐색(`AUTO auto0.tap - use "jtag newtap …"`) 결과로 TAP 을 정의하고, `extra_commands` 로 `jtag newtap …`, `target create …` 를 준다.
   - 이미 떠 있는 OpenOCD 는 `openocd_attach(case_id, host, tcl_port)`.
4. `openocd_scan_chain`, `openocd_targets` → `openocd_halt` (MODIFY) → `openocd_read_registers`, `openocd_read_memory`(≤4 KiB)
5. 덤프: `openocd_dump_memory_start` / `openocd_flash_read_start` → `openocd_job_status(job_id, wait_seconds=30)` 반복
6. 끝나면 `openocd_stop` (덤프 작업은 먼저 취소되고 부분 결과는 보존).

## 3. 프로브 배선 개요

**JTAG**: TCK, TMS, TDI, TDO, GND (+ 가능하면 VREF/VTref, nTRST, nSRST). **SWD**: SWCLK, SWDIO, GND (+VREF).

- **GND 공통**이 먼저다. 프로브 GND 와 타깃 GND 를 반드시 연결한다.
- **전압**: 카메라 SoC 의 JTAG I/O 는 대개 3.3V, 일부 1.8V. 프로브의 VREF 입력에 타깃 I/O 전압을 물려 레벨을 맞춘다.
  프로브에서 타깃으로 전원을 공급하지 않는다(타깃은 자체 전원). 레벨이 다르면 레벨 시프터를 쓴다.
- **TDI/TDO 방향**: 프로브의 TDI → 타깃 TDI(프로브 출력), 타깃 TDO → 프로브 TDO(프로브 입력). 뒤바뀌면
  `JTAG scan chain interrogation failed: all ones/zeroes` 가 난다. 확신이 없으면 JTAGulator(`pweh-jtagulator`)로 핀아웃부터 찾는다.
- 선은 짧게(10~20cm 이하), 처음엔 낮은 속도(`adapter_speed_khz` 100~1000). 신호가 불안하면 덤프 시 `verify=true`.
- nTRST/nSRST 가 헤더에 없으면 cfg 에 `reset_config none` (대부분의 카메라 보드).
- FT2232H/FT232H(MPSSE) 범용 보드의 관례: MPSSE 채널의 xDBUS0=TCK, xDBUS1=TDI, xDBUS2=TDO, xDBUS3=TMS.

### 흔한 interface cfg (scripts 디렉터리 기준 상대경로)

| 프로브 | cfg | 메모 |
|---|---|---|
| FT2232H 범용 (Mini-Module 등) | `interface/ftdi/minimodule.cfg`, `ftdi/olimex-arm-usb-ocd-h.cfg`, `ftdi/dp_busblaster.cfg`, `ftdi/tumpa.cfg` | 보드마다 `layout_init`/리셋 핀 정의가 다르니 맞는 파일을 고른다 |
| FT232H 범용 | `interface/ftdi/um232h.cfg`, `ftdi/c232hm.cfg`, `ftdi/ft232h-module-swd.cfg`(SWD) | Shikra 류 FT232H 보드는 전용 cfg 가 없어 um232h.cfg 를 바탕으로 직접 작성 |
| **Tigard** (FT2232H) | `interface/ftdi/tigard.cfg` | `ftdi channel 1`(채널 B)을 JTAG/SWD 에 쓰고 nTRST/nSRST 를 정의한다. 헤더 실크 인쇄대로 배선 |
| **J-Link** | `interface/jlink.cfg` | JTAG/SWD 모두. 여러 대면 `adapter serial <sn>` |
| ST-Link | `interface/stlink.cfg`, `interface/stlink-dap.cfg` | 주로 STM32 SWD 용. 카메라 SoC 디버깅에는 부적합 |
| **CMSIS-DAP** | `interface/cmsis-dap.cfg` | DAPLink/Pico 기반 프로브 등 |
| **Raspberry Pi GPIO** | `interface/raspberrypi-native.cfg`(Pi1~4, bcm2835gpio), `raspberrypi2-native.cfg`, `sysfsgpio-raspberrypi.cfg`, `raspberrypi5-gpiod.cfg` | 핀 번호는 cfg 가 기준이다. 최신 cfg 는 TCK=GPIO11, TDI=GPIO10, TDO=GPIO9, TMS=GPIO8 이며 `TMS/SWDIO moved to GPIO 8 (pin 24)` 경고를 찍는다(0.12.0 릴리스는 TMS=GPIO25). Pi 에서 OpenOCD 를 띄우고 이 서버는 `openocd_attach(host=<pi>)` 로 붙을 수 있다(원격이면 메모리 덤프는 read_memory 방식, 플래시 read_bank 불가). Pi 의 OpenOCD 를 `bindto 0.0.0.0` 으로 열면 TCL 포트가 곧 호스트 코드 실행 권한이므로 신뢰하는 랩 네트워크에서만 |
| Bus Pirate | `interface/buspirate.cfg` | 매우 느려 덤프에는 부적합 |

## 4. 카메라 SoC 노트

- **전용 target cfg 없음**: HiSilicon Hi35xx, Ingenic, SigmaStar, Novatek 용 cfg 는 OpenOCD 트리에 없다. 손으로 쓴다
  (골격은 `docs/references/openocd-tcl-rpc.md` §9.2):
  - ARM926EJ-S (Hi3518EV200/Hi3516CV200, Anyka 등): `jtag newtap … -irlen 4` + `target create … arm926ejs -endian little -chain-position …`
  - Cortex-A7 (Hi3516EV200/EV300, Goke GK7205V200, SigmaStar SSC33x): DAP(`-irlen 4`, IDCODE `0x?ba00477` 류) + `dap create` + `target create … cortex_a -dap …`.
    AHB-AP 가 있으면 `target create cam.ahb mem_ap -dap cam.dap -ap-num 0` 을 만들고 도구의 `target="cam.ahb"` 로 **CPU 를 멈추지 않고** 메모리를 읽을 수 있다.
    점 없는 이름(`mem_ap`, `cpu0`)도 쓸 수 있다 — 서버가 `target names` 목록에서 확인한 뒤 쓴다(5장 '타깃 인자'). 다만 OpenOCD 명령과 같은 이름(`mww`, `reset` …)은 거부된다.
  - MIPS (Ingenic T31 등 XBurst): `mips_m4k -endian little` — XBurst EJTAG 호환성은 미확인.
- **JTAG 이 꺼져 있거나 먹스됨**: JTAG 패드가 부팅 후 SDIO/GPIO/UART 로 재할당되거나(예: TDI 가 SDIO 전원 제어로), 보안 퓨즈로
  디버그가 꺼져 있는 경우가 흔하다. 증상은 `all ones` 또는 IDCODE 는 보이는데 `Examination failed`. 전원 직후 짧은 시간만
  JTAG 이 살아 있는 SoC 도 있다(Allwinner V3s cfg 주석: 약 20ms 창). U-Boot 단계에서 멈춘 상태로 붙는 전략이 유효하다.
  **eFuse/OTP 쓰기로 "되살리기"를 시도하지 않는다** (비가역, 이 서버는 기본 거부).
- **SPI NOR 덤프**: HiSilicon FMC/SFC, Ingenic SFC, SigmaStar 컨트롤러용 OpenOCD flash 드라이버가 없어 `flash read_bank` 를 쓸 수
  없는 경우가 대부분이다. 우회: U-Boot 에서 `sf probe; sf read <RAM> <off> <len>` → `openocd_halt` →
  `openocd_dump_memory_start(address=<RAM>, length=<len>, kind="flash-dump")` (dumps/ 에 저장) → UART 덤프 결과와 sha256 비교.
- **클럭**: PLL 설정 전 코어 클럭이 낮으면 높은 JTAG 속도에서 실패한다. 100~500 kHz 로 시작하고, RTCK 가 있으면 `adapter_speed_khz=0`(RCLK).

## 5. 안전 동작

| 구분 | 동작 |
|---|---|
| 분류 | 보내는 Tcl 텍스트를 `classify_openocd`(코어) **와** 로컬 엄격 규칙(`guard.py`)으로 분류해 더 위험한 쪽을 쓴다. INTERACT 도 감사 로그를 위해 `rt().authorize` 를 거친다 |
| 정책 | 조회(scan_chain, targets, reg, mdw/read_memory, flash banks/info/probe/list)=허용, `halt`/`resume`/`reset`/`openocd_start`=MODIFY(`safety.modify_policy`), `mww`/`write_memory`/`flash write·erase`/`program`/OTP·eFuse·옵션바이트=DESTRUCTIVE(**기본 거부**). Espressif 포크의 플래시 프로그래밍 proc `program_esp`·`program_esp_bins`(그 밖의 `program_*` 포함, `openocd.flash.program_esp`)과 호스트 파일·네트워크로 쓰는 `esp gcov`(타깃 펌웨어가 경로를 정함)·`esp apptrace`·`esp sysview` 의 `start`/`dump`·`xtensa tracedump`, `xtensa exe`, `<칩> flashbootstrap <값>` 도 DESTRUCTIVE(`flashbootstrap` 은 바로 앞 단어가 ESP 칩 그룹 `esp32`·`esp32s2`·`esp32s3`·`esp32c3`… 일 때만 스트랩 명령으로 보고, 그 뒤에도 일반 표·명령 규칙을 그대로 적용해 더 위험한 쪽을 쓴다 — `program flashbootstrap`·`load_image flashbootstrap` 은 DESTRUCTIVE, 값 없는 조회 `esp32 flashbootstrap` 은 알 수 없는 명령 기준(기본 MODIFY)). semihosting 을 켜는 핸들러를 다시 설치하는 ESP 표준 proc `configure_event_examine_end`·`configure_openocd_events`·`create_esp_target`(`openocd.esp.semihosting-proc`)과 이름에 `semihost` 가 든 명령(`openocd.semihosting-proc`), 호스트 임의 경로에 파일을 쓰는 `profile <초> <파일>`(gmon 출력, 예전에는 MODIFY)·트레이스 출력 `<tpiu|swo> create/configure … -output <파일|:포트>`(`openocd.trace.output`)·`tpiu config internal <파일>`(`openocd.tpiu.config.internal`)도 DESTRUCTIVE. 스텁을 돌리는 `esp verify_bank_hash`·`esp flash_stub_clock_boost` 같은 검증·설정은 MODIFY |
| 로컬 엄격 규칙 | 코어가 놓치는 형태를 DESTRUCTIVE 로 올린다: `::mww`, `m\ww`(실제로 mww 가 실행됨을 확인), 명령 위치의 `[…]`/`{*}`, 따옴표 스크립트 본문(`capture "flash erase_sector …"`), Jim 호스트 탈출(`popen`, `socket`, `load`, `script`, `os.fork`, `pipe`, `kill`, `package`, `bindto`), `log_output <path>`, `irscan`/`drscan`/`svf`/`xsvf`(바운더리 스캔 핀 구동·CPLD 프로그래밍), `mmw`/`memwrite*`/`array2mem`, `<dap> apreg` 쓰기, `semihosting enable`. 검토 단계 추가(모두 xPack 0.12.0-7 의 Jim 에서 본문 실행 확인): ① 로컬 파서가 나눈 **문장마다 코어 분류를 다시** 돌린다 — 코어는 `#` 로 시작하는 줄을 주석으로 지운다. 예전 코어는 `splitlines()` 로 나눠 Python 이 `\r \v \x1c` 에서도 줄을 나눴고(`catch {<VT># } ; mww 0 0` 의 mww 가 사라짐, 지금 코어는 `\n` 으로만 나눈다), 따옴표 안 개행 뒤의 `#` 는 Jim 에서 주석이 아닌데도 지금도 지운다(`set x "<LF># "; mww 0 0` 은 코어만으로는 INTERACT). 코어 `classify_openocd` 만으로는 불완전하다(코어 독스트링). ② 스크립트 본문 위치: `catch -error -- "본문"`, `dict for/with/update … 본문`, `loop … 본문`, 이벤트 핸들러 `-event <이름> 본문`(target configure/create, jtag configure), 명령 접두 `-command <명령>`(lsort/lsearch/regsub — `lsort -command mww {0 0}` 은 mww 를 호출). ③ 식 위치(expr, if/elseif/while 조건, for 검사식): 중괄호 없는 식의 변수/명령 치환은 expr 가 결과를 다시 해석(이중 치환, `expr $x`)하므로 DESTRUCTIVE, 중괄호 식 안의 `[…]` 도 재귀 분류. ④ 코어 표에 없는 명령의 따옴표/중괄호/백슬래시 인자(예: `stdout readable "…"`)는 본문으로 재귀 분류, `update`/`vwait`/`xtrace`/`curry` 는 간접 실행. ⑤ 이 서버가 끈 telnet/GDB 명령 서버를 다시 여는 `telnet port N`/`gdb port N`/`-gdb-port N`(`disabled` 제외)은 그 포트의 명령(GDB `monitor` 포함)이 게이트를 거치지 않으므로 DESTRUCTIVE. ⑥ 점 없는 타깃 접두: 코어는 점 있는 첫 단어만 타깃 접두로 봐서 점 없는 타깃의 `cpu0 mww 0x… 1`(실측: 타깃의 메모리 쓰기)이 '알 수 없는 명령'(MODIFY, 기본 허용)이었다 → 코어 표에 없는 첫 단어 뒤의 고정 단어를 하위 명령으로도 분류해 더 엄격한 쪽을 쓴다(`cpu0 mww`/`load_image`/`program` = DESTRUCTIVE, `cpu0 read_memory …` 는 그대로 MODIFY, 하위 명령이 `$x` 처럼 동적이면 이 규칙은 적용되지 않음). ⑦ semihosting 켜기의 값 우회: OpenOCD 는 `arm semihosting` 의 값을 대소문자 없이 enable/on/true/yes/1 로 해석한다(실측: `arm semihosting ENABLE`, `arm semihosting on`, `arm semihosting $x` 모두 켜짐, 예전 규칙은 정확히 `enable` 만 보았다) → `arm semihosting`·`arm semihosting_fileio` 뒤 값이 끄는 값(`disable`/`off`/`false`/`no`/`0`)이 아니거나 동적이면 DESTRUCTIVE(`openocd.local.semihosting`). ⑧ 알려진 하위 명령 그룹(`flash`, `nand`, `arm`, `jtag`, `esp` …)의 하위 명령 자리가 변수·명령 치환이면 DESTRUCTIVE(`openocd.local.dynamic-subcommand`) — 코어는 `[…]` 를 떼어 보므로 `flash [string cat erase_sector] 0 0 last` 가 INTERACT 였다. ⑨ 세션의 OpenOCD 에서 semihosting 가드가 찾은 'semihosting 을 켜는 proc'(본문에 `semihost` 가 있거나 그런 proc 을 부르는 proc — 전이적, cfg 의 사용자 정의 proc 포함) 호출은 DESTRUCTIVE(`openocd.local.semihosting-proc`). ⑩ OpenOCD 훅 변수 `post_init_commands`(init 끝)·`pre_shutdown_commands`(shutdown 직전)의 원소는 eval 된다(실측) → `lappend`/`set`/`append`/`lset` 로 넣는 값을 스크립트로 분류한다(변수 이름이 동적이어도) — 수정 전 `lappend pre_shutdown_commands "mww 0 0"` 은 INTERACT 로 통과해 `openocd_stop` 때 승인 없이 실행되었다. ⑪ 검증 단계 추가(Jim 0.84 실측): `switch` 는 Jim 규칙대로 나눈다(옵션은 앞 두 글자 `-e*`/`-g*`/`-r*`/`-c* <명령>`, `--*` 는 옵션 끝, 한 단어 목록 `switch a {a init}` 이면 목록 안 패턴/본문 쌍의 본문, `-` 는 다음 본문) — 예전에는 목록 전체를 한 스크립트로 읽어 `switch echo {echo {arm semihosting enable}}`·`switch x {echo z x mww\ 0x20000000\ 0}` 가 MODIFY, `switch a {a init}` 의 init 을 못 찾았다. 목록이 동적(`switch x "x $y"`)이면 DESTRUCTIVE(`openocd.local.switch-dynamic-body`). `apply {인자 본문}` 의 람다 본문도 본문이다. `-command` 는 줄임말(`lsort -c`, `-comm` — 실측: `lsort -c cmpx {p q}` 가 `cmpx p q` 실행, 수정 전 INTERACT)도 같고, 명령 접두에 데이터가 덧붙는 호출(lsort: `P a b`, lsearch: `P 패턴 원소`, switch: `P 패턴 string`)을 실제로 만들어 분류한다 — `lsort -command esp32 {flashbootstrap 1.8}` 은 `esp32 flashbootstrap 1.8`(DESTRUCTIVE, `openocd.local.command-prefix:…`), 덧붙는 값이 동적이거나 후보가 12개를 넘으면 DESTRUCTIVE(`openocd.local.command-prefix-dynamic`) |
| semihosting 무력화 | `openocd_start` 는 semihosting 을 항상 꺼 둔 채 끝내고, 시작 뒤에도 꺼져 있는지 계속 확인한다(`openocd_mcp/semihosting.py` 의 Tcl 가드 `pweh_semihosting_guard <단계>`). semihosting 이 켜지면 타깃 펌웨어가 분석 PC 의 파일을 열고 쓰고 `SYS_SYSTEM` 으로 명령까지 실행할 수 있는데, 신뢰 scripts 의 표준 cfg 는 내용을 분류하지 않고 xPack `target/esp_common.cfg` 는 ESP32/ESP32-S2/ESP32-S3 의 `examine-end` 핸들러에서 `arm semihosting enable` 을 실행한다. **관련 핸들러** = 본문에 `semihost` 가 있거나 semihosting 을 켜는 proc 이름이 든 핸들러. **감싸기** = `try {원래 본문} finally {모든 타깃의 semihosting 끄기}`(원래 본문·오류·return 은 그대로, 다른 타깃을 켜는 핸들러도 끝나면 꺼짐, 관련 없는 핸들러와 ARM 표준 cfg 는 바이트 단위로 그대로, 정확히 그 4원소 형태인지로 이미 감쌌는지 판단). 단계: (1) `pre-init`(모든 cfg·`extra_commands` 뒤, `init` 직전) — `[command mode]` 가 `config` 가 아니면 init 이 이미 실행된 것(실측: init 전 `config`, 뒤 `exec`)이라 `init-before-guard`, 그다음 타깃 핸들러 감싸기. (2) `post-init`(`init` 직후, TCL 포트가 열리기 전) — init 중(init_board/init_targets) 설치된 핸들러까지 다시 감싸고, TAP 핸들러(`jtag cget` 은 init 뒤에만 됨)도 감싸고, 타깃마다 `command mode <타깃> arm semihosting` 으로 조용히 확인한 뒤 enabled 면 끄고 다시 확인. (3) `verify` — 연결 직후 TCL RPC 로 **반드시** 다시 실행하고, 가드가 전역 변수에 남긴 시작 단계 기록(로그 형식·리다이렉트와 무관)과 함께 받아 판정한다. 가드 proc 이 없거나 결과가 불완전하면 `start_failed`(`semihosting-verification-failed`), init 이 가드보다 먼저 실행됐으면 `init-before-semihosting-guard`, 감싸기·끄기 실패나 스크립트 오류면 `semihosting-neutralization-failed` — 모두 OpenOCD 를 끄고 빈 실행 디렉터리를 지운다. 시작 로그 표식 `PWEH-SEMIHOSTING …` 은 `-d3` 이상의 `User : … handle_echo(): ` 접두도 읽고 `script_debug(): command - echo …` 줄은 무시한다. (4) `check` — MODIFY 이상 `openocd_command`(`unknown_command_risk: interact` 면 모든 명령), `openocd_halt`/`openocd_resume`/`openocd_reset`, `openocd_write_memory`/`openocd_flash_write` 뒤마다 RPC 로 다시 감싸고 끈다: 켜진 타깃이나 감싸지 않은 핸들러를 찾아 무력화했으면 응답 `semihosting_reneutralized`(`<타깃>:<이벤트>`, `<타깃>:after-command`)·`semihosting_warning`, 감사 로그 `openocd_semihosting_reneutralized`. 끄지/감싸지 못했거나 가드가 사라졌거나 결과가 불완전하면 OpenOCD 를 종료하고(`status: "semihosting_failsafe"`, `semihosting_failsafe{reasons, stop_method, process}`, 감사 로그 `openocd_semihosting_failsafe`) 그 뒤 기기 명령은 이유와 함께 거부한다. 명령이 시간 초과로 끝나면(OpenOCD 가 계속 실행 중일 수 있어 죽이지 않음) 확인을 미뤄 두고 다음 RPC 전에 먼저 확인한다(못 하면 `busy`). (5) `status` — `openocd_status` 의 읽기 전용 확인(`semihosting_live`). 끄기 정책인데 켜진 타깃/감싸지 않은 핸들러가 보이면 그 자리에서 `check` 를 돈다. `openocd_status` 의 `semihosting` 은 시작 보고가 아니라 최신 상태(`last_check`, `reneutralized` 기록, `policy`, `check_pending`, `startup`). `extra_commands` 의 init 계열 명령(`init`, `target/transport/jtag/dap/flash/nand/pld/tpiu/swo init`, `jtag arp_init*`, `jtag_init`, `init_reset`, init 끝에 실행될 `post_init_commands` 수정 — catch/eval/따옴표 본문, switch 목록 안 본문, apply 람다, proc 본문, defer, subst 의 `[…]`, `-command` 접두 안 포함)은 `validation_failed`, 사용자 cfg 안의 init 계열 명령은 DESTRUCTIVE(`openocd.local.init-before-guard`). 정적 검사가 못 찾는 init(신뢰 cfg 끝의 `init`, 신뢰 cfg 의 proc 이 부르는 init, 승인된 동적 형태)을 위해 `-f` 하나하나와 `extra_commands` 하나하나 바로 뒤에 **init 조기 실행 검사**(`semihosting.EARLY_CHECK_SCRIPT` — proc 없는 한 줄)를 넣는다: `[command mode]` 가 `config` 가 아니면 모든 타깃의 semihosting 을 바로 끄고 `init-before-guard`·`done early-check` 표식을 남긴 뒤 `error` 로 OpenOCD 를 끝낸다(실측: 시작 `-c` 의 오류는 뒤의 `-c` 를 실행하지 않고 종료 코드 1). 서버는 프로세스 종료 대신 표식의 치명 사유로 `start_failed`(`init-before-semihosting-guard`)를 돌려준다. 그래서 init 을 먼저 실행한 cfg/명령 *뒤의* 시작 명령은 semihosting 이 켜진 채 실행되지 않는다(수정 전: 그 사이의 `extra_commands` 가 켜진 채 실행된 뒤 pre-init 에서야 실패). 꼭 필요하면 사람 승인 후 `openocd_command` 로 `arm semihosting enable`(DESTRUCTIVE) — 승인된 명령이 semihosting 을 켜고 성공하면(실패하면 그대로 끈다) 그 세션은 `policy: "enabled-by-approval"` 이 되어 `openocd_stop` 까지 끄지 않고 상태만 보고한다(감사 로그 `openocd_semihosting_enabled_by_approval`) |
| 타깃 인자 | `openocd_read_memory`, `openocd_dump_memory_start`, `openocd_write_memory` 의 `target` 으로 서버가 직접 만드는 `<타깃> read_memory …`/`<타깃> md[bhwd] …`(덤프 작업의 청크 읽기, write_memory 확인 읽기 포함)는, 서버가 실제 `target names` 목록(실측: xPack 은 이름마다 한 줄, 0.12.0 이하는 Jim 리스트)에서 확인한 이름일 때만 접두를 떼고 분류한다(`guard.classify_target_read`, 덤프 작업은 `trusted_targets` 로 전달) → 점 없는 `mem_ap`/`cpu0` 의 읽기도 INTERACT, 덤프 작업도 시작된다. 목록은 세션(프로세스 시작/연결) 단위로 캐시하고, 요청한 이름이 없으면 한 번 다시 조회한다. 그래도 **목록에 없는 이름은 보내기 전에 거부**(`validation_failed`, 사용 가능한 이름 안내 — 점 있는 이름도 같음)한다. **OpenOCD/Tcl 명령과 같은 이름**(분류 표·Jim 내장 명령·`ocd_` 형태·fuse/otp 휴리스틱에 걸리는 이름, 예: `mww`, `reset`, `flash`)은 목록에 있어도 거부한다 — 실측: xPack 은 `target create mww …` 를 받아 전역 `mww` 를 가리지만 버전마다 다를 수 있다. 목록을 얻지 못하면 접두를 떼지 않는다(기존 분류: 점 없는 이름은 MODIFY, 덤프 작업은 시작 거부). 에이전트 원시 명령(`openocd_command`)에는 적용하지 않는다(위 ⑥ 만 적용). 한계: 목록에 있는 이름의 명령을 나중에 `proc`/`rename`/`alias` 로 바꿔치기한 경우는 감지하지 않는다(이 명령들은 DESTRUCTIVE 라 사람 승인 없이는 실행되지 않음, 신뢰 scripts 의 표준 cfg 는 예외) |
| 호스트 파일 쓰기 | `dump_image`, `flash read_bank` 는 원시 명령으로는 거부. 덤프 작업만 **케이스의 jtag/ 또는 dumps/ 안의 서버 생성 경로**로 보낸다(정확한 정규식 + 경로 검사, `classify_managed`) |
| 백그라운드 작업 | 시작 전 계획 명령 전체를 검사해 INTERACT 를 넘으면 시작 거부, 매 청크 명령도 다시 검사 |
| 작업 중 보호 | 덤프 작업이 도는 케이스에서는 halt/resume/reset/쓰기/MODIFY 이상 원시 명령을 `busy` 로 거부(결과 오염 방지). 조회는 허용 |
| cfg 해석 | OpenOCD 는 상대 cfg 경로를 **cwd 에서 먼저** 찾는다(`find_file`, xPack 에서 실측). 그래서 표준 cfg 는 scripts 디렉터리에서 확인한 **절대경로**로 넘기고, OpenOCD 는 실행마다 새로 만든 빈 작업 디렉터리(`jtag/.openocd-<n>-cwd-*`, 종료 시 비어 있으면 삭제)에서 띄운다 → 케이스에 손으로 쓴 같은 이름 파일이 표준 cfg 나 그 안의 `source [find …]` 를 가로챌 수 없다 |
| 사용자 cfg | scripts 디렉터리 밖(절대경로/`./`, 서버 cwd 기준으로 존재하는 상대경로, 또는 OpenOCD 기본 검색 위치 `$OPENOCD_SCRIPTS`·`~/.config/openocd`·`~/.openocd`·site 에서 찾은 이름) cfg 는 **내용 전체를 분류**한다(1 MiB 초과는 잘라 분류하지 않고 거부). 승인 지문에 cfg 의 sha256 이 들어가고 프로세스를 띄우기 직전에 다시 확인하므로, 승인 뒤 내용이 바뀌면 실행되지 않는다. 신뢰 scripts 디렉터리는 모두 `-s` 로 넘겨 표준 cfg 안의 `source [find …]` 가 사용자 위치(`~/.openocd` 등)의 같은 이름 파일보다 먼저 찾게 한다. `$_TARGETNAME configure -event reset-init {mww …}` 처럼 변수/쓰기를 쓰는 cfg 는 DESTRUCTIVE 로 분류되어 기본 거부 → 표준 cfg + `extra_commands` 조합을 쓰거나, 운영자가 승인 정책을 바꾼다 |
| 쓰기 도구 | `openocd_write_memory`, `openocd_flash_write` 는 DESTRUCTIVE. `destructive_policy: approve` 일 때만 `approval_required` → 사람이 `pweh approve <id>` → 같은 인자 + `approval_id` 로 1회. flash write 의 승인 지문에는 파일 sha256 이 들어가고 실행 직전에 다시 확인 |
| 종료 | 이 서버가 띄운 프로세스는 `shutdown` RPC → SIGTERM → SIGKILL(프로세스 그룹). attach 한 외부 OpenOCD 는 연결만 끊고, `shutdown_attached=true` 일 때만 MODIFY 게이트를 거쳐 `shutdown`. 서버 종료 시 띄운 OpenOCD 를 정리(atexit) |
| 포트 | TCL 만 127.0.0.1 에 열고 telnet/gdb 는 `disabled`. cfg 가 다시 열면 경고 |

이 분류기는 협조적이지만 성급한 에이전트의 실수를 막기 위한 것이다. 강한 격리가 필요하면 서버를 별도 OS 계정으로 실행한다.

## 6. 도구

시그니처는 주요 인자만 적었다(`approval_id`, 타임아웃, `active_only` 같은 선택 인자는 일부 생략). 전체 인자와 기본값은 [`docs/references/pweh-mcp-tools.md`](../../docs/references/pweh-mcp-tools.md) 를 본다.

| 도구 | 위험도 | 요약 |
|---|---|---|
| `openocd_start(case_id, interface_cfg, target_cfg?, transport?, adapter_speed_khz?, extra_commands?, tcl_port=6666, extra_cfgs?, ready_timeout=30, approval_id?)` | MODIFY | 프로세스 시작·준비 대기(로그의 `Listening on port N for tcl connections` + `version` 왕복). `tcl_port=0` 이면 빈 포트 자동. semihosting 무력화 결과 `semihosting_neutralized`(`<타깃>:<이벤트>`, `tap:<TAP>:<이벤트>`, `<타깃>:after-init`, `<타깃>:after-start`)·`semihosting`(`verified`, `source: "rpc"`, `log_markers`, `phases`, `handlers_wrapped`, `targets`, `procs`, `failures`). `extra_commands` 의 init 계열 명령은 `validation_failed`. 실패 시 `ok=false, status=start_failed, reason`(`init-before-semihosting-guard`·`semihosting-verification-failed`·`semihosting-neutralization-failed` 포함)`, errors, diagnosis, log_tail` |
| `openocd_attach(case_id, host="127.0.0.1", tcl_port=6666)` | INTERACT | 실행 중인 OpenOCD 에 연결. 이 케이스가 전에 띄운 프로세스면 상태 파일로 입양(mode=adopted). 입양한 프로세스에 가드 proc 이 있으면 semihosting 을 다시 확인한다(`semihosting_check`·`semihosting_warning`, 끄지 못하면 `status=semihosting_failsafe`. 가드가 없으면 경고만) |
| `openocd_stop(case_id, shutdown_attached=false)` | - | 종료 + 로그 아티팩트 등록 |
| `openocd_status(case_id, log_lines=40)` | INTERACT | 프로세스/연결/로그 꼬리/진단 + `targets` 로 현재 상태. 이 서버가 띄운 세션은 `semihosting`(최신 확인 결과·정책·재무력화 기록·시작 보고)과 `semihosting_live`(읽기 전용 확인), fail closed 로 종료됐으면 `semihosting_failsafe` |
| `openocd_command(case_id, command, approval_id?, timeout=30)` | 분류 결과 | 원시 Tcl. `list [catch {capture {CMD}} r] $r` 봉투로 실행, 실패는 `status=tcl_error`. MODIFY 이상이면 뒤에 semihosting 재확인(`semihosting_check`, 켜져 있었으면 `semihosting_reneutralized`, 끄지 못하면 `status=semihosting_failsafe` — 5장). 승인된 명령이 semihosting 을 켜고 성공하면 `semihosting_policy: "enabled-by-approval"` |
| `openocd_scan_chain(case_id)` | INTERACT | `tap_name, enabled, idcode, expected(목록), irlen, ircap, irmask, mismatch, decoded{manufacturer, part, version, valid}` |
| `openocd_targets(case_id)` | INTERACT | `index, current, name, type, endian, tap_name, state` |
| `openocd_halt(case_id, target?)` / `openocd_resume(case_id, address?, target?)` / `openocd_reset(case_id, mode=halt\|run\|init)` | MODIFY | `messages`(OpenOCD 메시지), `state`, `semihosting_check`(명령 뒤 semihosting 재확인 — `semihosting_reneutralized`/`semihosting_failsafe` 는 5장) |
| `openocd_read_registers(case_id, names?, target?, refresh=true)` | INTERACT | `reg` 파싱, `jtag/registers-<n>.json` 저장(jtag-dump 아티팩트) |
| `openocd_read_memory(case_id, address, count, width=32, target?, phys=false)` | INTERACT | ≤4 KiB. `values`, `bytes_hex`, `hexdump`, `endian`. `target` 은 `target names` 에 있는 이름만(5장 '타깃 인자') |
| `openocd_dump_memory_start(case_id, address, length, output_name?, chunk_size=64k, target?, method=auto, verify=false, resume=true, kind=memory-dump)` | INTERACT(job) | `jtag/<name>.bin`(+`.json`) / `kind=flash-dump` 면 `dumps/`. `target` 은 시작 전에 `target names` 로 확인 |
| `openocd_flash_banks(case_id, probe=false, info=false)` | INTERACT | `bank, name, driver, base, size, bus/chip width, target, info.sectors` |
| `openocd_flash_read_start(case_id, bank, offset=0, length?, output_name?, chunk_size=64k, verify=false)` | INTERACT(job) | `dumps/<name>.bin`(+`.json`), flash-dump 아티팩트 |
| `openocd_write_memory(case_id, address, values, width=32, …)` / `openocd_flash_write(case_id, path, address, erase=true, verify=true, …)` | DESTRUCTIVE | 기본 거부. 승인되어 실행되면 뒤에 semihosting 재확인(`semihosting_check` — 5장) |
| `openocd_list_configs(kind, pattern?)` | - | scripts 의 cfg 목록 |
| `openocd_job_status(job_id, wait_seconds=0, case_id=None)` / `openocd_job_cancel(job_id)` / `openocd_jobs(active_only=False, case_id=None)` | - | 작업 폴링/취소/목록 |

작업 상태·목록의 `case_id`를 생략하면 이 서버 프로세스의 작업만 보인다. 재시작 뒤에는
`openocd_job_status(job_id, case_id="<케이스 ID>")` 또는 `openocd_jobs(case_id="<케이스 ID>")`로 같은 서버의 저장 기록을 확인한다.
소유 서버 종료가 확실한 활성 기록만 `failed`(`error.code=job_owner_terminated`)로 정리한다. 소유자 없는 과거 기록·다른 호스트/namespace·관찰 불가는
원본 상태를 보존하고 `recovery.owner_state="unknown"`과 사유를 표시한다. 살아 있는 다른 서버 프로세스의 기록도 보존한다.
원시 owner 식별자는 응답에 나오지 않는다. 저장 기록의 재개/취소는 없고, `wait_seconds`는 이 프로세스의 작업만 기다린다.
한 기록 1MiB, 목록 512디렉터리 항목·256기록·누적 8MiB·2초로 제한하며 목록의 `recovery.truncated/reasons`가 확인하지 못한 범위를 알린다.
이 두 도구는 로컬 기록을 정리하므로 `readOnlyHint=false`다. 파일·기기·외부 자식의 정리 여부는 별도로 확인한다.

## 7. 산출물 (케이스 디렉터리)

| 경로 | 내용 |
|---|---|
| `jtag/openocd-<n>.log` | OpenOCD stdout/stderr (RPC 결과도 OpenOCD 가 로그에 찍는다) — 종료 시 아티팩트(other) |
| `jtag/openocd-<n>.json` | 세션 상태(pid, 포트, argv, 종료 정보) — 서버 재시작 후 입양에 사용. pid 생존 확인은 코어 `pweh.procutil.pid_alive`(좀비·0 이하·깨진 pid 는 '끝남', 네이티브 Windows 에서는 `os.kill(pid, 0)` 을 부르지 않음) |
| `jtag/registers-<n>.json` | 레지스터 스냅샷 (jtag-dump) |
| `jtag/<name>.bin` + `.json` | 메모리 덤프 + 메타데이터(`method: "jtag-openocd"`, `source`, `output{path, sha256, size}`, `verification`, `chunks`) |
| `dumps/<name>.bin` + `.json` | 플래시 덤프(flash-dump), 또는 `kind=flash-dump` 메모리 덤프 |
| `*.part` / `*.state.json` | 진행 중/중단된 덤프. 같은 `output_name` 으로 다시 호출하면 이어받는다(파라미터가 다르면 거부, `resume=false` 면 처음부터) |
| `jtag/command-output-<n>.txt` | 너무 긴 원시 명령 출력 |

덤프 방식: 메모리는 청크마다 `dump_image` → 파일 크기 확인 → `.part` 에 덧붙임. OpenOCD 가 쓴 파일이 보이지 않으면(원격/컨테이너)
`read_memory` 루프(정렬 안 맞으면 8비트, 타깃 엔디언으로 바이트 복원)로, `read_memory` 가 없으면(0.11) `mdw/mdb` 파싱으로 자동 전환한다.
`verify=true` 면 메모리는 청크를 두 번 읽어 비교, 플래시는 `flash verify_bank` 로 재확인한다(불일치 시 재시도).
대부분의 코어는 메모리 접근 전에 halt 가 필요하다(`not halted` 오류는 재시도하지 않고 힌트와 함께 실패).

## 8. 테스트

- `tests/servers/test_openocd_pipe_rpc.py`, `test_openocd_pipe_process.py`, `test_openocd_pipe_ready.py`: 내부 pipe client·Linux 직접 자식 owner·명령행 구성. 익명 pipe와 `fake_openocd_pipe.py`로 응답 예산, 취소·종료 경합, EOF/TERM/KILL, 리더보다 오래 사는 자식, 준비 진단과 version의 결합을 검증한다. Windows dummy 소비자는 이 pipe client와 별도 Windows owner를 연결한다.
- `tests/servers/test_openocd_parsers.py`: 실측 바이트로 Tcl 리스트/봉투/파서/분류기/명령행 단위 테스트
- `tests/servers/test_openocd_mcp.py`: `tests/servers/fake_openocd.py`(가짜 TCL 서버 + 가짜 실행 파일; xPack/0.12.0/0.11.0 프로파일,
  장애 주입)로 모든 도구·작업·게이트·프로세스 관리, stdio 스모크 테스트
- `tests/servers/test_openocd_target_names.py`: 점 없는 타깃 이름 — `classify_target_read`/`target_name_conflict` 단위,
  가짜 OpenOCD 로 read_memory·덤프 작업·write_memory 확인 읽기, 목록에 없는 이름/명령 이름과 겹치는 이름 거부, 목록 캐시와
  불일치 시 재조회, Jim 리스트 형식(0.12.0), 목록을 못 얻을 때 기존 분류 유지, 실제 xPack 의 점 없는 testee 타깃(`external`)
- `tests/servers/test_openocd_real.py` (`@pytest.mark.external`): 실제 xPack OpenOCD + dummy 어댑터 + testee 타깃.
  testee 에서는 `resume`/`step`/`bp` 와 reset 이후의 `poll` 이 OpenOCD 를 SIGSEGV 로 죽이므로 보내지 않는다.
- `tests/servers/test_openocd_semihosting.py`: semihosting 가드 — 스크립트 형태·명령행 위치, 로그 표식 해석(-d3 접두, 디버그 줄 무시)·단계·치명 판정,
  가드 RPC 에 답하도록 가르친 가짜(`GUARDED_FAKE` — `fake_openocd.py` 를 감싸는 래퍼, 다른 `openocd_start` 테스트도 쓴다)로 RPC 확인 필수(없음/불완전/
  init 먼저 → `start_failed`), 명령 뒤 재확인(재무력화·fail closed·시간 초과 뒤 미룬 확인), 세션 proc 분류, 승인으로 켠 세션, `openocd_status` 최신 상태,
  init 계열 시작 명령 거부, 사용자 cfg 의 init. `external`: 실제 xPack 으로 `board/esp32s3-builtin.cfg` 핸들러 감싸기(init 전에 종료, USB 를 열지 않음),
  ARM 표준 cfg 핸들러 무변경, dummy 어댑터의 arm7tdmi 로 '핸들러가 켬 → 무력화 후 꺼짐'·init 먼저 실행(치명)·TAP 핸들러·init_board 핸들러·다른 타깃을
  켜는 핸들러·proc 을 거쳐 켜는 핸들러, ESP32-S3 의 `configure_event_examine_end` 재설치를 `check` 가 다시 감쌈, MCP 종단(ESP32-S3 target cfg, 신뢰
  scripts 의 semihosting cfg 에서 재무력화와 fail closed, cfg 의 init → `init-before-semihosting-guard`, `debug_level 3`), init 조기 실행 검사(스크립트 형태·
  `-f`/extra 뒤 위치, 가짜의 조기 종료 → 같은 치명 사유, 실제 xPack 에서 cfg 의 init·신뢰 proc 의 init 뒤 시작 명령이 실행되지 않음, 같은 `-c` 안 나머지만 남음)
- `tests/servers/test_openocd_guard.py`: 게이트 우회 형태 회귀(switch 목록 안 본문, `lsort -c` 줄임말, `-command` 접두에 덧붙는 데이터, apply 람다) +
  실제 xPack(Jim 0.84)에서 그 본문·호출이 실행됨을 확인하는 `external` 테스트

## 9. 알려진 제한

- P3-A의 `rpc_pipe.py`는 Windows dummy에도 쓰이며 `process_pipe.py`의 직접 자식 owner는 Linux 전용이다. 이 Linux owner는 `waitid(WNOWAIT)`로 리더를 보존한 채 소유 그룹 부재를 확인한다. `close()`가 미확인으로 끝나면 owner를 보존하여 재시도한다. Windows wrapper 종료나 별도 세션으로 이탈한 프로세스 트리 전체의 부재를 증명하지 않는다.
- pipe 준비는 stderr reader를 시작하고 `version`을 한 번 전송한 뒤, 같은 deadline 안에서 완결된 `accepting 'tcl' connection from pipe` 진단 줄과 정상 version 응답을 모두 요구한다. 고정 OpenOCD는 stdin을 읽을 수 있을 때 연결 진단을 내므로 진단을 먼저 기다리면 연결되지 않는다. 준비 성공 뒤에도 호출자는 owner를 닫아야 하며, 기기 작업에는 별도의 운영 안전 게이트·semihosting 검증이 필요하다.

- 실제 CPU 코어(ARM/MIPS)의 halt 메시지·레지스터 목록은 소스 포맷 기준이며 실기기로 검증하지 못했다(dummy/testee 는 메모리·레지스터가 없음).
- OpenOCD 는 단일 스레드라 긴 명령(큰 청크의 dump_image) 중에는 다른 도구도 기다린다. 프로토콜 수준 취소가 없어 작업 취소는 현재 청크가 끝난 뒤 반영된다.
- 원격 attach 에서는 플래시 `read_bank` 덤프를 할 수 없다(결과 파일이 원격 호스트에 생김).
- 사용자 cfg 내용 분류는 보수적이라 변수/이벤트를 쓰는 실전 cfg 는 기본 정책에서 거부된다.
- 중괄호 조건이라도 `$변수` 로 시작하면(`if {$x} {halt}`, `while {$c < 3} …`) 코어가 명령 위치의 변수로 보고 DESTRUCTIVE 로 거부한다(엄격한 쪽 오탐).
  원시 Tcl 에서는 변수·반복문 대신 실제 값과 타깃 이름을 쓴다.
- 에이전트 원시 명령(`openocd_command`)에서 cfg 의 타깃 이름이 명령 이름을 가리면(`target create reset …` 뒤 `reset mww 0x… 1` — xPack 은 타깃의 mww 를 실행)
  전역 명령 기준(`reset` = MODIFY)으로 분류된다. 점 없는 타깃의 동적 하위 명령(`cpu0 $x 0 0`)도 MODIFY 다. 서버가 만드는 타깃 명령은 이런 이름을 거부한다(5장 '타깃 인자').
- OpenOCD 는 TCL RPC 결과를 자기 로그에도 찍는다. `read_memory` 방식 덤프(원격/파일 미가시)는 로그가 덤프 크기의 약 3배까지 커질 수 있다
  (`dump_image` 방식은 해당 없음).
- semihosting 무력화의 한계: `semihost` 라는 글자 없이(문자열 조립·변수·`eval`) 켜는 핸들러/proc 은 감싸기·DESTRUCTIVE 분류 대상이 아니고, 명령 뒤
  재확인과 init 직후 확인만 끈다 — 그 사이(명령 실행 중, 또는 재확인 전의 폴링)에는 켜져 있을 수 있다. 핸들러가 켠 뒤 같은 핸들러 안에서 오래 기다리면(`sleep`)
  finally 가 돌기 전까지 켜져 있다. proc 본문 전체의 위험도로 호출을 분류하지는 않는다(semihosting 관련 전이적 이름 검사만). 사람이 승인해 켠 세션은
  `openocd_stop` 까지 끄지 않는다. `openocd_attach` 로 붙은 외부 OpenOCD(사람이 띄운 것)는 무력화·재확인하지 않는다 — ESP32 계열 표준 cfg 로 띄웠다면
  `<타깃> arm semihosting` 으로 상태를 확인한다(입양한 프로세스는 가드 proc 이 있으면 재확인한다).
- init 을 직접 실행하는 cfg(표준 scripts 의 `board/sifive/hifive1.cfg`·`board/mini2440.cfg`·`target/rp2040.cfg` 의 rescue 등)는 semihosting 가드보다
  init 이 먼저 돌아 `init-before-semihosting-guard` 로 시작이 실패한다 — init 을 뺀 cfg 로 시작한다(openocd_start 가 가드 뒤에 init 을 실행).
  init 조기 실행 검사가 그 cfg 바로 뒤에서 semihosting 을 끄고 OpenOCD 를 끝내므로 뒤따르는 시작 명령은 실행되지 않지만, 남는 구간이 있다:
  init 을 실행한 **그 신뢰 cfg 파일의 나머지 줄**(신뢰 경계 안), 그리고 init 을 실행한 **extra_commands 항목 하나의 나머지**(같은 `-c` 안 `;` 뒤 —
  정적 검사가 못 찾고 DESTRUCTIVE 면 사람 승인까지 통과한 경우만)는 semihosting 이 켜진 채 실행될 수 있다. `init` 을 가로채는 훅(`rename init`)은
  OpenOCD 의 시작 끝 자동 `init` 호출과 겹쳐 검증하지 않았으므로 쓰지 않는다.
- xPack 0.12.0-7 에서 dummy 어댑터로 ESP32-S3 target cfg 를 쓰면(하드웨어 없이) 체인 검사가 깨져 생긴 auto TAP 때문에 `scan_chain` 이
  `buf_get_u32: Assertion ... failed` 로 OpenOCD 를 SIGABRT 시킨다(무력화와 무관, 실기기에서는 해당 없음). `openocd_start` 응답 뒤 프로세스가 죽어 있을 수 있다.
