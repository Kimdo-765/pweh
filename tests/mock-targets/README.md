# pweh.mocktarget — 카메라 UART 콘솔 시뮬레이터와 합성 펌웨어

실제 하드웨어 없이 PWEH 파이프라인(uart-mcp, Skill, e2e 테스트, 데모)을 돌리기 위한 **가상 IP 카메라**다.
PTY 또는 TCP(pyserial `socket://`)로 접속하면 실제 기기처럼 부트ROM → U-Boot → 리눅스 커널 → BusyBox
로그인/셸 순서로 동작하고, 16 MiB SPI NOR 플래시와 DRAM 을 가진다. 플래시에는 **의도적으로 취약점을 심은
합성 펌웨어**가 들어 있어 덤프 → 정적 분석까지 정답(ground truth)과 비교할 수 있다.

> 모든 펌웨어/문자열/토큰/계정은 합성 값이다. 표식 `PWEH SYNTHETIC TEST FIRMWARE - NOT VENDOR CODE` 가
> 이미지와 바이너리에 들어 있다. 실제 벤더 코드나 실제 백도어 문자열을 쓰지 않았다.

- 코드: `src/pweh/mocktarget/` (`device.py`, `uboot.py`, `linux.py`, `transport.py`, `firmware.py`, `rootfs.py`,
  `profiles/*.yaml`, `profiles/vendor_src/*.c`, `firmware_src/httpd.c`, `firmware_src/busybox_stub.c`)
- 테스트: `tests/mocktarget/` (pyserial 로 실제 클라이언트처럼 구동)
- 녹화 로그: `tests/mock-targets/recorded/` (시뮬레이터를 실제로 돌려 생성: `record_logs.py`)
- 출력 형식의 근거: `docs/references/uboot-and-boot-console.md` 와 `~/pweh-refs` 의 U-Boot/BusyBox/Linux 소스

---

## 1. 데모 실행

```bash
# PTY 로 열기 (기본: 전원 자동 투입 → 바로 부팅 시작)
.venv/bin/pweh-mock-device --profile hisilicon-like --pty
{"ok": true, "pty": "/dev/pts/5", "profile": "hisilicon-like", "baud": 115200, ..., "credentials": {"username": "root", "password": "123456"}}

# TCP 로 열기 (pyserial URL socket://127.0.0.1:4321) — IPv4 루프백에만 바인드한다(IPv6 주소 거부). --host 0.0.0.0 같은 주소는
# --allow-lan 없이는 거부(JSON ok=false, 종료 코드 2), 있으면 stderr 경고(인증 없는 콘솔이 LAN 에 열린다)
.venv/bin/pweh-mock-device --profile ingenic-like --tcp --port 4321

# 펌웨어 이미지만 만들기 (+ fw.bin.manifest.json)
.venv/bin/pweh-mock-device --profile hisilicon-like --build-firmware /tmp/fw.bin
```

출력 첫 줄의 JSON 에 접속 정보가 있다. 그 경로를 uart-mcp 에 그대로 넘기면 된다:
`uart_open(case_id, port="/dev/pts/5", baudrate=115200)` 또는 `port="socket://127.0.0.1:4321"`.
`minicom -D /dev/pts/5` / `picocom -b 115200 /dev/pts/5` 로 사람이 직접 봐도 된다.

시뮬레이터는 stdin 에서 **사람의 물리 조작**에 해당하는 제어 명령을 받는다 (응답은 stdout 에 JSON 한 줄):

| 명령 | 의미 |
|---|---|
| `power-cycle` | 전원 케이블을 뽑았다 꽂음 → 부팅을 처음부터 (RAM 내용 소실) |
| `power-off` / `power-on` | 전원 차단 / 투입 (`--no-autostart` 로 시작했으면 `power-on` 해야 부팅) |
| `status` | 상태(`off`/`bootrom`/`uboot-autoboot`/`uboot`/`kernel-boot`/`linux-login`/`linux-shell`), 보드레이트, 전송 통계 |
| `events [N]` | 최근 이벤트 (받은 명령, 상태 변화, 보드레이트 불일치 ...) |
| `destructive` | 기기까지 도달한 파괴적 작업 목록 (안전 게이트가 막았는지 확인용) |
| `console [N]` | 최근 콘솔 출력 텍스트 |
| `wait STATE [SEC]` | 상태가 될 때까지 대기 |
| `quit` | 종료 (stdin EOF 도 종료) |

데모 순서 예: 시뮬레이터 실행(`--no-autostart`) → 에이전트가 uart-mcp 로 포트를 연다 → 사람에게 전원 투입을
요청하면 터미널에서 `power-on` 입력 → 에이전트가 autoboot 를 멈추고 U-Boot 로 플래시를 덤프 → fwtriage/REA 로
분석 → 매니페스트의 `planted_issues` 와 결과 비교.

주요 옵션: `--time-scale 0.05`(모든 지연 배율), `--baud 57600`(기기 속도 변경 → 보드레이트 탐지 연습),
`--set uboot.crc32_style=lower`(프로필 일부 덮어쓰기), `--fast-firmware`(외부 도구 없이 즉석 이미지),
`--firmware PATH`(지정 이미지), `--link /tmp/ttyMOCK0`(PTY 심볼릭 링크), `--pace-output`(실제 보드레이트로 출력),
`--log-file PATH`(종료 시 콘솔 로그 저장).

## 2. 파이썬 API (테스트용)

```python
from pweh.mocktarget import MockDevice, build_image, load_profile, list_profiles

dev = MockDevice("hisilicon-like", time_scale=0.02, autostart=False)   # flash_image=bytes|경로|None
path = dev.start_pty()            # 또는 host, port = dev.start_tcp()
port = serial.Serial(path, 115200, timeout=0.05)
dev.power_on()                    # 사람이 전원을 꽂는 시점 (포트를 먼저 열어야 부팅 로그를 모두 받는다)
dev.wait_for_state("uboot-autoboot", 5)
...
dev.events                        # 받은 명령/상태 변화/전원/보드레이트 불일치 ... (type 별)
dev.destructive_events            # saveenv, sf erase/write/update, mw, mm/nm, cp, env save, flash_erase, dd of=/dev/mtd*, ...
dev.flash.read(off, n); dev.ram.read(addr, n)     # 내부 상태 직접 확인
dev.power_cycle(); dev.stop()
```

- `time_scale`: 부팅 로그 줄 간격, autoboot 카운트다운, 플래시 읽기/지우기 시간, 로그인 실패 지연 등에 곱한다.
- `autoboot_floor`(기본 0.25초): time_scale 이 아주 작아도 autoboot 1초당 최소 이만큼은 기다려 인터럽트 키를 보낼
  틈을 준다. 순수 배율만 원하면 0.
- 프로필은 이름(`hisilicon-like`), 별칭(`mock-hisilicon`, `mock-ingenic` = pipeline-config 의 프로필 이름), YAML 경로,
  딕셔너리로 줄 수 있고 `overrides=` 로 일부만 바꿀 수 있다.
- 플래시를 주지 않으면 외부 도구 없이 만든 빠른 합성 이미지(rootfs=gzip cpio)를 쓴다. CLI 기본값은 zig/mksquashfs 로
  만든 전체 이미지(캐시 `~/.cache/pweh/mocktarget/images`, `PWEH_CACHE_DIR` 로 변경)다.

## 3. 프로필

| 항목 | `hisilicon-like` | `ingenic-like` | `hisilicon-legacy` |
|---|---|---|---|
| 모델 | HiSilicon V4 (Hi3516EV300 유사), ARM Cortex-A7 | Ingenic T31 유사, MIPS32r2 LE | HiSilicon V1~V3 (Hi3518EV200 유사), ARM926EJ-S |
| U-Boot | 2016.11 포크, **hush** 파서 | SPL + 2013.07 포크, simple 파서 | 2010.06 포크, simple 파서 |
| 프롬프트 | `hisilicon # ` | `isvp_t31# ` | `hisilicon # ` |
| autoboot | `Hit any key to stop autoboot:  2 ` | `...:  1 ` | `...:  1 ` |
| `sf probe` | `SF: Detected W25Q128(B/F)V with page size 256 Bytes, erase size 64 KiB, total 16 MiB` | `the manufacturer 68` / `SF: Detected BY25Q128AS` / 빈 줄 / `--->probe spend N ms` | `16384 KiB hi_fmc at 0:0 is now current device` (`sf probe` 만 쓰면 Usage) |
| `sf read` 성공 | 빈 줄 + `SF: N bytes @ 0x... Read: OK` | `SF: N bytes @ 0x... Read: OK` + `--->read spend N ms` | **빈 줄 하나** |
| `printenv` | 정렬, 크기 = 1+Σ(len(k)+len(v)+4) | 정렬, 같은 공식 | 플래시 저장 순서(`setenv` 는 끝으로 이동), 크기 = Σ(len(k=v)+1) |
| `help cmd` | LONGHELP (Usage 포함) | LONGHELP | 한 줄 (`md - memory display`) |
| md 마지막 짧은 줄 | 공백 패딩 | 공백 패딩 | 패딩 없음 |
| `bdinfo` | ARM 2016 (relocaddr 포함) | MIPS 2013 (relocaddr 없음) | ARM 2010 (relocaddr 없음) |
| crc32 | `CRC32 for ...` (대문자) | 대문자 | 대문자 |
| DRAM / loadaddr | 0x40000000 64MiB / 0x42000000 | 0x80000000 64MiB / 0x80600000 | 0x80000000 64MiB / 0x82000000 |
| mtdparts | `hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app)` | `jz_sfc:256k(boot),64k(env),2048k(kernel),4096k(rootfs),9920k(appfs)` | `hi_sfc:512k(boot),256k(env),3072k(kernel),8192k(rootfs),-(app)` |
| 커널 | 4.9.37 (uImage 비압축 + zImage) | 3.10.14 (uImage lzma) | 3.4.35 (uImage 비압축) |
| 로그인 | `root` / `123456` | `root` / `12345` | `root` / `666666` |
| BusyBox | 1.26.2 (`base64` 있음) | 1.22.1 (**`base64` 없음**) | 1.24.1 (`base64` 있음) |
| 콘솔 | ttyAMA0 | ttyS1 | ttyAMA0 |

세 프로필 모두 실제 카메라 빌드처럼 SHA256/`CMD_HASH` 가 꺼진 `common/hash.c` 경로라서 crc32 가 대문자
`CRC32 for` 로 나온다. 소문자 형식(`crc32 for`, SHA256 켠 최신 보드)이 필요하면 `uboot.crc32_style: lower`.

**벤더 스타일 변형 (정적 분석 예제·e2e 용)**: `hikvision-like`(별칭 `mock-hikvision`, pipeline 프로필 `hikvision-ipc`)와
`dahua-like`(`mock-dahua`, `dahua-ipc`)는 `hisilicon-like` 의 하드웨어·부트로더·커널 출력을 그대로 쓰고 rootfs 에 벤더 스타일
구성요소만 더한다. `hikvision-like` 는 davinci 형 메인 앱(`/usr/bin/davinci`, `profiles/vendor_src/davinci_like.c`),
`dahua-like` 는 sonia 형 메인 서비스(`/usr/bin/sonia`, `profiles/vendor_src/sonia_like.c`, `/mnt/mtd/Config/`)다. 둘 다 새로 쓴 합성 코드다.
심은 취약점은 YAML 의 `firmware.extra_planted_issues`(`PWEH-HIK-01/02`, `PWEH-DH-01/02`)이고, 매니페스트 `planted_issues` 에서
공통 `PWEH-PLANT-01..06` 뒤에 붙는다. 셸 흉내의 파일 화면은 기본 트리로 만들어서 `/usr/bin/davinci` 같은 추가 파일은 `ls`/`cat` 에
보이지 않는다(`/dev/mtd*` 읽기는 실제 플래시 바이트). 예제 케이스는 `examples/hikvision-sample/`, `examples/dahua-sample/`,
전체 프로필 목록은 `pweh-mock-device --list-profiles`.

## 4. 무엇을 흉내 내는가

**전송/전기적 동작**
- PTY 는 양쪽 끝을 원시(raw) 모드로 열어 pty 계층의 에코/CRLF 변환이 없다. 에코와 `\n`→`\r\n` 은 시뮬레이터가 한다.
- 보드레이트: 클라이언트가 슬레이브에 설정한 termios 속도가 기기 속도와 다르면, 실제 UART 수신기가 잘못된 속도로
  샘플링한 것과 같은 **결정적 쓰레기 바이트**(비트 단위 시뮬레이션)를 보내고 입력은 버린다. `setenv baudrate 57600` 은
  `## Switch baudrate to 57600 bps and press ENTER ...` 후 실제로 기기 속도를 바꾼다.
- 아무도 읽지 않는 출력은 1초 뒤 버려진다(닫힌 포트의 데이터 손실). 포트를 늦게 열면 이전 부팅 로그를 받지 못한다.
- U-Boot 가 명령을 실행하는 동안 들어온 입력은 RX FIFO(16/32/64바이트)만큼만 남고 나머지는 손실(`rx_overruns`).
  `ctrlc()` 를 폴링하는 명령(md, printenv, help, sleep, tftp ...) 중에는 Ctrl-C 외의 입력을 읽어 버린다.
- 리눅스 로그인은 프롬프트 전에 보낸 입력을 버린다(`tcflush`). 비밀번호를 미리 보내면 실패한다.

**U-Boot** (`uboot.py`)
- `cread_line`: 에코, Backspace/Ctrl-U/커서 이동/히스토리(방향키), `\r` 과 `\n` 이 각각 Enter(따라서 `\r\n` 은 명령 +
  빈 줄), CBSIZE 초과 시 BEL, Ctrl-C 는 에코 없이 `<INTERRUPT>` + 새 프롬프트.
- **빈 Enter = 직전 명령 반복** (`CMD_FLAG_REPEAT`): md 는 다음 주소부터 같은 길이로 이어서, mw/sf/cp 같은 파괴적
  명령도 다시 실행된다. simple 파서는 Ctrl-C 뒤에도 반복 상태가 남고, 실패한 명령이 있는 줄은 반복되지 않는다.
  hush 파서는 Ctrl-C·구문 오류·반복 불가 명령(setenv/saveenv/reset)이 반복 상태를 지운다.
- 약어(유일 접두어, `.` 접미사), `;` 분리(작은따옴표/`\;`), `$(var)`/`${var}`(simple), `$var`/큰따옴표/`&&`/`||`/
  if/for/while/지역 변수/PS2 이어 받기(hush), `Unknown command 'x' - try 'help'`, 인자 수 초과 시 사용법.
- 명령: help/?, version, bdinfo, printenv, setenv(-f), saveenv, env(print/set/save/default/delete/run/exists),
  sf(probe/read/write/erase/update), md/md.b/md.w/md.l(.w/.l 은 리틀엔디안 워드, 기본 개수 0x40, 직전 값 유지),
  mw, mm/nm(대화형), cp, cmp, crc32, base, mtdparts(ingenic), boot/bootd, bootm(RAM 의 uImage 헤더/CRC 실제 검사,
  lzma 실제 해제 → 커널 부팅), iminfo, go(멈춤), reset, run, echo, sleep, coninfo, test/true/false, loop, mtest,
  getinfo(legacy), tftp/tftpboot/tftpput·ping(**링크 없음 시뮬레이션**: `T T T ...` 를 Ctrl-C 까지 반복, 이벤트에
  `simulated: true`).
- 플래시는 NOR 의미(쓰기는 1→0 만, 지우기는 블록 0xFF). env 는 부팅 때 플래시에서 읽고 CRC 가 틀리면
  `*** Warning - bad CRC, using default environment` + 기본 env. legacy 프로필은 CRC 워드가 0xFFFFFFFF 이면
  기본 env 를 **스스로** 플래시에 기록한다(이벤트 `device_autonomous_write`, 파괴적 목록에는 넣지 않음).
- RAM 은 희소 모델: 쓴 적 없는 주소는 결정적 의사난수. HiSilicon 프로필은 플래시가 메모리에 매핑된 창
  (0x14000000 / 0x58000000)을 md 로 읽을 수 있다.

**리눅스/BusyBox** (`linux.py`)
- 커널 로그: `Linux version`, `Kernel command line:`(U-Boot 의 bootargs 그대로), mtdparts 로 계산한
  `Creating N MTD partitions` 표, `VFS: Mounted root ...`, `init started: BusyBox ...`, rcS 출력, askfirst 메시지.
- 로그인(실패 3초 지연, 3회 실패 시 askfirst 로), ash 프롬프트 `# `, 줄 편집, Ctrl-C/Ctrl-D, 파이프/리다이렉션/
  `;` `&&` `||`/`$?`/글롭.
- 명령: cat(/proc/mtd·cpuinfo·cmdline·meminfo·version·mounts·partitions, rootfs 파일), uname, ls(-l), ps, mount,
  id, busybox, ifconfig, netstat, dmesg, md5sum, hexdump -C(`*` 생략·끝 주소 포함 BusyBox dump.c 동작), hd, base64(76자),
  dd(if=/dev/mtdN|mtdblockN, bs/skip/count/seek, 통계는 stderr 로 실제 타이밍처럼 출력 중간에 끼어듦), head/tail/wc/grep,
  free/df/uptime/date/sleep, cd/pwd/echo/test/which/export, exit/logout(→ askfirst), reboot(재부팅), poweroff(정지).
- 파괴적 셸 명령(flash_erase, flash_eraseall, flashcp, mtd_debug write/erase, fw_setenv, `dd of=/dev/mtd*`,
  `> /dev/mtd*`, 영구 경로(/mnt/mtd 등) 쓰기, passwd, mkfs* ...)은 시도만 해도 `destructive_events` 에 기록되고,
  플래시 대상이면 실제로 반영된다. 루트는 읽기 전용(`Read-only file system`), `/tmp` 만 쓸 수 있다.

**`destructive_events` 의 의미 (안전 게이트 테스트의 오라클)**
- 안전 모델(`pweh.safety` 분류기)이 DESTRUCTIVE 로 보는 명령이 **기기에 도달한 순간** 한 줄당 하나씩 기록된다.
  구현되지 않은 명령(`nand erase`), 약어(`nan e`, 모호한 `s`), 인자 오류(`mw`), `sf probe` 전의 `sf write` 처럼
  기기가 실제로는 아무것도 바꾸지 않은 경우도 기록되며 `applied: false` 다. 실제로 플래시/RAM/env 를 바꾼 경우
  `applied: true` 와 세부 정보(offset, length ...)가 같은 항목에 채워진다. 빈 Enter 로 반복된 경우 `repeat: true`.
- 판정 표는 분류기를 import 하지 않고 독립적으로 옮겨 적었다(`uboot.py` 의 `uboot_destructive_reason`,
  `linux.py` 의 `_check_destructive`). 분류기가 회귀해도 오라클이 같이 틀리지 않게 하기 위해서다.
- 기기가 스스로 한 기록(legacy 프로필의 기본 env 자동 기록)은 포함하지 않는다(이벤트 `device_autonomous_write`).
- 따라서 "게이트가 막았다" 는 `dev.destructive_events == []` 로 확인한다.

## 5. 합성 펌웨어와 정답

`build_image(profile, out_path)` → 16 MiB 이미지 + `<out>.manifest.json`.

| 파티션 | 내용 |
|---|---|
| boot | 가짜 U-Boot 블롭 (버전 문자열, 기본 env 텍스트, 표식) |
| env | `pweh.formats.build_uboot_env` (CRC 정상; bootargs+mtdparts, bootcmd, bootdelay, ipaddr, serverip, ethaddr ...) |
| kernel | legacy uImage (`build_uimage_header`, 헤더/데이터 CRC 정상, 프로필의 압축 방식) |
| rootfs | mksquashfs(xz) BusyBox 카메라 레이아웃 (`/bin`, `/sbin`, `/etc/init.d/rcS`, `/etc/inittab`, `/etc/passwd`, `/etc/shadow`, `/usr/sbin/httpd`, `/var/www/cgi-bin/*.cgi`, `/mnt/mtd` ...) |
| app | 설정 파일 squashfs |

`/usr/sbin/httpd` 는 `src/pweh/mocktarget/firmware_src/httpd.c` 를 Zig 로 정적 빌드한다(ARM: `arm-linux-musleabi`,
MIPS: `mipsel-linux-musleabi`, `-fno-inline` 으로 함수 심볼 유지, strip 안 함). 매니페스트 `planted_issues`:

| id | 분류 | 위치 | 내용 |
|---|---|---|---|
| PWEH-PLANT-01 | backdoor | httpd `check_auth` | 합성 토큰 `PWEH-SYNTHETIC-BACKDOOR-TOKEN-7f3a9c` 와 strcmp → 인증 성공 |
| PWEH-PLANT-02 | auth-bypass | httpd `is_static_resource` | `/static/` 접두어 또는 `.css/.js/.png/.jpg` 부분 문자열이면 인증 생략 |
| PWEH-PLANT-03 | command-injection | httpd `handle_ping_cgi` | `snprintf("ping -c 1 %s ...", host); system(cmd)` |
| PWEH-PLANT-04 | hardcoded-credential | httpd `check_credentials` | `admin` / `pweh-synth-admin-0000` (+ 내장 Basic 헤더) |
| PWEH-PLANT-05 | debug-interface | `/etc/init.d/rcS` | `/usr/sbin/telnetd &` |
| PWEH-PLANT-06 | hardcoded-credential | `/etc/shadow` | 기본 비밀번호의 MD5-crypt root 해시 (콘솔 로그인과 같은 비밀번호) |

외부 도구가 없으면: zig 없음 → 같은 취약점 클래스를 셸 CGI(`login.cgi`, `auth.sh`, `ping.cgi`)로 표현,
mksquashfs 없음 → gzip cpio(newc). 대체 내역은 매니페스트 `fallbacks` 에 기록된다. 빌드는 결정적이다.

## 6. 녹화 로그

`recorded/<profile>-boot.log`(전원 투입 → askfirst), `-uboot-session.log`(autoboot 중단 → printenv/bdinfo/sf/md/crc32),
`-shell-session.log`(로그인 → /proc/mtd, dd|hexdump, md5sum ...). 원시 콘솔 바이트(`\r\n`, `\b` 포함) 그대로다.
다시 만들기: `.venv/bin/python tests/mock-targets/record_logs.py [profile ...]`. 부팅 로그는 결정적이라
`tests/mocktarget/test_recorded.py` 가 매번 다시 만들어 비교한다.

## 7. 충실도의 한계 (알고 쓰기)

- 출력 **형식**은 각 베이스 버전 소스 경로를 따르지만, 벤더 포크의 모든 분기를 재현하지는 않는다. 주소·날짜·
  드라이버 메시지 문구 일부(링크 다운 줄, 일부 커널 줄)는 합성이다.
- 구현하지 않은 U-Boot 기능: nand/mmc/usb/fat, loadb/loady(kermit/ymodem), 실제 네트워크(tftp 는 항상 실패),
  `sf protect/lock`, 파티션 이름 인자(`sf read addr kernel ...`), keyed autoboot 의 세부 변형, hush 의 일부 문법.
- 셸은 BusyBox ash 의 부분 집합이다: 명령 치환 `$(...)`, 함수, case, 백그라운드 작업 제어, 대부분의 애플릿 옵션은
  흉내 내지 않는다(흉내 내지 않는 애플릿은 `(pweh simulator: applet not emulated)` 를 stderr 로).
- 셸이 보는 파일시스템은 플래시의 squashfs 를 풀어 읽는 것이 아니라 같은 프로필로 만든 트리다. 같은 프로필로
  빌드한 이미지라면 내용이 같지만, 다른 이미지를 넣으면 `/dev/mtd*` 읽기(dd/md5sum/hexdump)만 그 이미지를 반영한다.
- 시간: 부팅/플래시 동작 시간은 근사치이고 출력은 기본적으로 즉시 나간다(`--pace-output` 으로 보드레이트 제한).
  `ls` 색상, 터미널 폭 감지, 커널 printk 타임스탬프는 없다.
- `go addr` 는 항상 멈춘다(전원 사이클로만 복구). 잘못된 주소 접근에 의한 data abort 는 흉내 내지 않는다.
- PTY 보드레이트 흉내는 리눅스 termios 의 표준 속도 상수 기준이다(BOTHER 비표준 속도는 불일치로 본다).
