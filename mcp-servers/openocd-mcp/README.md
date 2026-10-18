# openocd-mcp (pweh-openocd)

OpenOCD 프로세스를 띄우고 TCL RPC(기본 포트 6666)로 JTAG/SWD 디버그 프로브를 제어하는 PWEH MCP 서버다.
스캔체인/타깃 확인, halt·reset, 레지스터/메모리 읽기, 메모리·플래시 덤프(백그라운드 작업)를 제공하고,
모든 기기 조작은 서버 측 안전 게이트를 거친다. **본인 소유이거나 서면 허가를 받은 기기에만 사용한다.**

- 계약: `docs/architecture.md` 6.4 / 프로토콜·출력 형식 근거: `docs/references/openocd-tcl-rpc.md`,
  `~/pweh-tools/INSTALL_REPORT.md` (xPack OpenOCD 0.12.0-7 로 실측)
- 실행: `pweh-openocd-mcp` 또는 `python -m openocd_mcp` (stdio). 로그는 stderr (`pweh.openocd`).

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
| 정책 | 조회(scan_chain, targets, reg, mdw/read_memory, flash banks/info/probe/list)=허용, `halt`/`resume`/`reset`/`openocd_start`=MODIFY(`safety.modify_policy`), `mww`/`write_memory`/`flash write·erase`/`program`/OTP·eFuse·옵션바이트=DESTRUCTIVE(**기본 거부**) |
| 로컬 엄격 규칙 | 코어가 놓치는 형태를 DESTRUCTIVE 로 올린다: `::mww`, `m\ww`(실제로 mww 가 실행됨을 확인), 명령 위치의 `[…]`/`{*}`, 따옴표 스크립트 본문(`capture "flash erase_sector …"`), Jim 호스트 탈출(`popen`, `socket`, `load`, `script`, `os.fork`, `pipe`, `kill`, `package`, `bindto`), `log_output <path>`, `irscan`/`drscan`/`svf`/`xsvf`(바운더리 스캔 핀 구동·CPLD 프로그래밍), `mmw`/`memwrite*`/`array2mem`, `<dap> apreg` 쓰기, `semihosting enable`. 검토 단계 추가(모두 xPack 0.12.0-7 의 Jim 에서 본문 실행 확인): ① 로컬 파서가 나눈 **문장마다 코어 분류를 다시** 돌린다 — 코어는 `#` 로 시작하는 줄을 주석으로 지운다. 예전 코어는 `splitlines()` 로 나눠 Python 이 `\r \v \x1c` 에서도 줄을 나눴고(`catch {<VT># } ; mww 0 0` 의 mww 가 사라짐, 지금 코어는 `\n` 으로만 나눈다), 따옴표 안 개행 뒤의 `#` 는 Jim 에서 주석이 아닌데도 지금도 지운다(`set x "<LF># "; mww 0 0` 은 코어만으로는 INTERACT). 코어 `classify_openocd` 만으로는 불완전하다(코어 독스트링). ② 스크립트 본문 위치: `catch -error -- "본문"`, `dict for/with/update … 본문`, `loop … 본문`, 이벤트 핸들러 `-event <이름> 본문`(target configure/create, jtag configure), 명령 접두 `-command <명령>`(lsort/lsearch/regsub — `lsort -command mww {0 0}` 은 mww 를 호출). ③ 식 위치(expr, if/elseif/while 조건, for 검사식): 중괄호 없는 식의 변수/명령 치환은 expr 가 결과를 다시 해석(이중 치환, `expr $x`)하므로 DESTRUCTIVE, 중괄호 식 안의 `[…]` 도 재귀 분류. ④ 코어 표에 없는 명령의 따옴표/중괄호/백슬래시 인자(예: `stdout readable "…"`)는 본문으로 재귀 분류, `update`/`vwait`/`xtrace`/`curry` 는 간접 실행. ⑤ 이 서버가 끈 telnet/GDB 명령 서버를 다시 여는 `telnet port N`/`gdb port N`/`-gdb-port N`(`disabled` 제외)은 그 포트의 명령(GDB `monitor` 포함)이 게이트를 거치지 않으므로 DESTRUCTIVE. ⑥ 점 없는 타깃 접두: 코어는 점 있는 첫 단어만 타깃 접두로 봐서 점 없는 타깃의 `cpu0 mww 0x… 1`(실측: 타깃의 메모리 쓰기)이 '알 수 없는 명령'(MODIFY, 기본 허용)이었다 → 코어 표에 없는 첫 단어 뒤의 고정 단어를 하위 명령으로도 분류해 더 엄격한 쪽을 쓴다(`cpu0 mww`/`load_image`/`program` = DESTRUCTIVE, `cpu0 read_memory …` 는 그대로 MODIFY, 하위 명령이 `$x` 처럼 동적이면 이 규칙은 적용되지 않음) |
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
| `openocd_start(case_id, interface_cfg, target_cfg?, transport?, adapter_speed_khz?, extra_commands?, tcl_port=6666, extra_cfgs?, ready_timeout=30, approval_id?)` | MODIFY | 프로세스 시작·준비 대기(로그의 `Listening on port N for tcl connections` + `version` 왕복). `tcl_port=0` 이면 빈 포트 자동. 실패 시 `ok=false, status=start_failed, reason, errors, diagnosis, log_tail` |
| `openocd_attach(case_id, host="127.0.0.1", tcl_port=6666)` | INTERACT | 실행 중인 OpenOCD 에 연결. 이 케이스가 전에 띄운 프로세스면 상태 파일로 입양(mode=adopted) |
| `openocd_stop(case_id, shutdown_attached=false)` | - | 종료 + 로그 아티팩트 등록 |
| `openocd_status(case_id, log_lines=40)` | INTERACT | 프로세스/연결/로그 꼬리/진단 + `targets` 로 현재 상태 |
| `openocd_command(case_id, command, approval_id?, timeout=30)` | 분류 결과 | 원시 Tcl. `list [catch {capture {CMD}} r] $r` 봉투로 실행, 실패는 `status=tcl_error` |
| `openocd_scan_chain(case_id)` | INTERACT | `tap_name, enabled, idcode, expected(목록), irlen, ircap, irmask, mismatch, decoded{manufacturer, part, version, valid}` |
| `openocd_targets(case_id)` | INTERACT | `index, current, name, type, endian, tap_name, state` |
| `openocd_halt(case_id, target?)` / `openocd_resume(case_id, address?, target?)` / `openocd_reset(case_id, mode=halt\|run\|init)` | MODIFY | `messages`(OpenOCD 메시지), `state` |
| `openocd_read_registers(case_id, names?, target?, refresh=true)` | INTERACT | `reg` 파싱, `jtag/registers-<n>.json` 저장(jtag-dump 아티팩트) |
| `openocd_read_memory(case_id, address, count, width=32, target?, phys=false)` | INTERACT | ≤4 KiB. `values`, `bytes_hex`, `hexdump`, `endian`. `target` 은 `target names` 에 있는 이름만(5장 '타깃 인자') |
| `openocd_dump_memory_start(case_id, address, length, output_name?, chunk_size=64k, target?, method=auto, verify=false, resume=true, kind=memory-dump)` | INTERACT(job) | `jtag/<name>.bin`(+`.json`) / `kind=flash-dump` 면 `dumps/`. `target` 은 시작 전에 `target names` 로 확인 |
| `openocd_flash_banks(case_id, probe=false, info=false)` | INTERACT | `bank, name, driver, base, size, bus/chip width, target, info.sectors` |
| `openocd_flash_read_start(case_id, bank, offset=0, length?, output_name?, chunk_size=64k, verify=false)` | INTERACT(job) | `dumps/<name>.bin`(+`.json`), flash-dump 아티팩트 |
| `openocd_write_memory(case_id, address, values, width=32, …)` / `openocd_flash_write(case_id, path, address, erase=true, verify=true, …)` | DESTRUCTIVE | 기본 거부 |
| `openocd_list_configs(kind, pattern?)` | - | scripts 의 cfg 목록 |
| `openocd_job_status(job_id, wait_seconds)` / `openocd_job_cancel(job_id)` / `openocd_jobs()` | - | 작업 폴링/취소/목록 |

## 7. 산출물 (케이스 디렉터리)

| 경로 | 내용 |
|---|---|
| `jtag/openocd-<n>.log` | OpenOCD stdout/stderr (RPC 결과도 OpenOCD 가 로그에 찍는다) — 종료 시 아티팩트(other) |
| `jtag/openocd-<n>.json` | 세션 상태(pid, 포트, argv, 종료 정보) — 서버 재시작 후 입양에 사용 |
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

- `tests/servers/test_openocd_parsers.py`: 실측 바이트로 Tcl 리스트/봉투/파서/분류기/명령행 단위 테스트
- `tests/servers/test_openocd_mcp.py`: `tests/servers/fake_openocd.py`(가짜 TCL 서버 + 가짜 실행 파일; xPack/0.12.0/0.11.0 프로파일,
  장애 주입)로 모든 도구·작업·게이트·프로세스 관리, stdio 스모크 테스트
- `tests/servers/test_openocd_target_names.py`: 점 없는 타깃 이름 — `classify_target_read`/`target_name_conflict` 단위,
  가짜 OpenOCD 로 read_memory·덤프 작업·write_memory 확인 읽기, 목록에 없는 이름/명령 이름과 겹치는 이름 거부, 목록 캐시와
  불일치 시 재조회, Jim 리스트 형식(0.12.0), 목록을 못 얻을 때 기존 분류 유지, 실제 xPack 의 점 없는 testee 타깃(`external`)
- `tests/servers/test_openocd_real.py` (`@pytest.mark.external`): 실제 xPack OpenOCD + dummy 어댑터 + testee 타깃.
  testee 에서는 `resume`/`step`/`bp` 와 reset 이후의 `poll` 이 OpenOCD 를 SIGSEGV 로 죽이므로 보내지 않는다.

## 9. 알려진 제한

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
