# uart-shell-acquisition 참고 자료

[SKILL.md](SKILL.md) 의 절차를 보조하는 표와 세부 사항이다. 모두 소유 기기나 서면 허가를 받은 기기에만 쓴다.

## 1. 부팅 로그 판독표

`uart_capture_boot` 의 필드와 `text_tail`·`excerpt_path` 를 함께 본다. 정규식 근거는 `docs/references/uboot-and-boot-console.md` §8·§11·§15.1.

| 관찰 | 의미 | 경로·조치 |
|---|---|---|
| stages `uboot → autoboot → kernel → userspace → askfirst`, stopped_by `prompt:askfirst:login` | 표준 BusyBox askfirst 콘솔 | autoboot 가 있으면 A 먼저, 그다음 B. askfirst 뒤 바로 셸인 기기도 있다 |
| stopped_by `prompt:login:login`, login_prompt 있음 | `<hostname> login:` 바로 표시 | B |
| stopped_by `prompt:prompt:linux-shell`, shell_prompt 있음 | 로그인 없이 셸 | C (`uart_sync` 로 evidence `linux` 확인) |
| stopped_by `prompt:prompt:uboot`, stages 에 kernel 없음 | bootcmd 실패로 U-Boot 프롬프트에 떨어짐(`Bad Magic Number`, `ERROR: can't get kernel image!`) | `uart_sync` → A2 |
| autoboot_message `Hit any key to stop autoboot: N` | 비-keyed, 아무 키 | A, 기본 Ctrl-C |
| autoboot_message 가 Ctrl-C/ENTER 를 지정 | keyed 빌드 | A, §8 의 keys |
| U-Boot 배너 뒤 메시지 없이 `Starting kernel ...` | bootdelay 0, silent keyed(SigmaStar), autoboot 끔 | A 1회(프로필 확인) → 안 되면 B/C |
| stages 에 uboot 없이 kernel 부터 | 포트를 늦게 열었거나 U-Boot 콘솔이 꺼짐(`silent` env, CONFIG_SILENT_CONSOLE) | 재투입 후 다시 보거나 A 를 1회 시도 |
| `Starting kernel ...` 뒤 조용함 | 커널 콘솔이 다른 UART(bootargs `console=`), `quiet`, `console=null` | A 만 가능. printenv 의 bootargs console= 를 노트에 남김 |
| kernel_panic 있음 | 예: `VFS: Unable to mount root fs`, `No working init found` | 노트. 부트 루프면 사용자에게 알림 |
| env_bad_crc true (`*** Warning - bad CRC, using default environment`) | 플래시 env 가 비었거나 깨짐. RAM 에 컴파일 기본 env | 노트. saveenv 하면 기본 env 가 플래시에 써진다(금지 유지) |
| flash_write_warnings 에 `Saving Environment to`, `Erasing SPI flash`, `Write default environment to flash` | 우리 명령 없이 기기가 플래시를 씀(R10) | `case_add_note`, 사용자에게 알림. 덤프 전 상태가 이미 바뀌었을 수 있음 |
| flash_write_warnings 에 `RECOVERY: kernel/rootfs invalid, reflashing -- do not power off` | OpenIPC Goke 복구 재기록 중 | **사람에게 지금 전원을 끄지 말라고 즉시 알린다.** 끝난 뒤 기록 |
| 같은 배너가 반복(재부팅 반복) | 부트 루프, 워치독, 전원 부족 | 전원 어댑터 확인, 노트 |
| 바이트는 많은데 텍스트가 깨짐 | 보드레이트, GND, 전압 레벨, 반전 | SKILL 3단계, 안 되면 LA |

## 2. 응답 필드 → uart-recon 매핑

| uart-recon 필드 | 출처 | 비고 |
|---|---|---|
| port, baudrate, framing | `uart_open` 의 port, baudrate, framing | 필수. 콘솔을 못 얻어도 시험한 값을 넣는다 |
| baud_detection.method | SKILL 3단계 표 | auto-scan / profile / manual / logic-analyzer |
| baud_detection.candidates, score | `uart_detect_baud` 의 candidates(상위 3개: baudrate, score, printable_ratio), confidence | 확인 못 했으면 score null |
| console_type | 끝난 시점의 문맥: uboot → `uboot`, linux-shell → `linux-shell`, login/password → `linux-login`, 프롬프트 없이 로그만 → `boot-log-only`, 수신 없음 → `silent`, 그 밖 → `unknown` | 세션을 닫았으면 마지막 문맥 |
| access_level | 얻은 것 중 가장 강한 것: root-shell > uboot > user-shell > login-required > boot-log > none | root-shell 은 `shell_identify` 의 user.uid 0 |
| uboot.version | `uboot_info.version` (없으면 `uart_capture_boot.uboot_version`) | |
| uboot.prompt | `uboot_interrupt.prompt` (또는 `uart_sync.prompt`) | |
| uboot.autoboot | message·bootdelay ← `uboot_interrupt`(없으면 capture_boot), interrupt_keys ← keys_used | |
| uboot.env, bootargs, bootcmd, mtdparts | `uboot_printenv` | 비밀 값은 마스킹 |
| uboot.partitions | `uboot_printenv.partitions` [{name, offset, size}] | `-` 의 size 가 null 이면 `uboot_info.partitions`(알아낸 플래시 크기로 채움). 그래도 null 이면 flash.size_bytes − offset, notes 에 출처 |
| uboot.flash | `uboot_info.flash` {type, model, size_bytes} | model 이 hi_fmc/hi_sfc 면 부팅 로그의 flash_name. 하한이면 notes |
| uboot.ram_load_addr | `uboot_info.safe_ram_addr` | 덤프 Skill 이 ram_addr 로 재사용 |
| uboot.commands | `uboot_info.commands` | |
| linux.kernel_version, cmdline | `shell_identify` (없으면 capture_boot) | U-Boot bootargs 보다 `/proc/cmdline` 이 정답 |
| linux.cpu, mtd, busybox | `shell_identify` 의 cpu, mtd[]{dev, size, erasesize, name}, busybox | |
| linux.user | `shell_identify.user.user` | |
| linux.login_required | 정상 부팅에서 login/askfirst+login 을 봤으면 true, 로그인 없이 셸이면 false, 모르면 null | init=/bin/sh 로 얻었어도 true |
| device_info | soc(출처 포함), arch, hostname, dram, console, rootfs_type, listening 포트, has_base64/has_hexdump/has_md5sum, flash_write_warnings | 자유 형식 |
| session_log | `uart_open.log_path` | 케이스 상대 경로 |
| boot_log (추가) | `uart_capture_boot.excerpt_path` | |
| session (추가) | {session_id, kept_open, context_at_end} | 다음 Skill 이 `uart_sessions` 로 확인 |
| contexts_reached, login_method (추가) | 도달한 문맥 목록, user-credentials / init-sh-ram / none / not-attempted | |
| notes | 확인/추정을 구분한 사실, 실패 이유, 영구 변경 없음 확인 | 비밀번호 금지 |

uboot 에 들어가지 못했으면 `"uboot": null` 이나 부팅 로그에서 얻은 일부(version, autoboot)만 넣는다. linux 도 같다.

## 3. 증상별 문제 해결

| 증상 | 원인 후보 | 조치 |
|---|---|---|
| `uart_list_ports` 에 USB 포트가 없음 | usbipd attach 안 함, 충전 전용 케이블, 드라이버 | H1, 다른 케이블, 사람에게 `pweh doctor` |
| 열 때 권한 오류 | dialout 그룹 | 사람이 `sudo usermod -aG dialout $USER` 후 재로그인(에이전트는 sudo 를 실행하지 않음) |
| 수신 0 바이트 | TX/RX 반대, GND 없음, 기기 전원, 다른 패드 | H4 → 재시도 2회 → `logic-analyzer-protocol-decode` |
| 전부 깨진 문자 | 보드레이트, GND 불량, 1.8V/3.3V 레벨, 반전 신호 | SKILL 3단계, LA 의 `sigrok_estimate_baud` |
| 간헐적으로 깨짐 | 긴 점퍼선, 접촉 불량, 노이즈 | 선을 짧게, GND 재확인, 클립 고정 |
| 출력은 오는데 입력이 안 먹음(`uart_sync` timed_out, 인터럽트 실패) | 어댑터 TX → 기기 RX 미연결, RX 패드 오류, RX 가 막힌 보드 | 배선 확인. RX 가 막혔으면 boot-log-only 로 기록 |
| `uboot_interrupt` 가 계속 `kernel` | 키가 늦음, keyed 빌드, bootdelay 0, U-Boot 콘솔 꺼짐 | §8 keys, 프로필 변경, 3회 뒤 B/C·대안 |
| 문맥이 계속 unknown | 프롬프트가 두 정규식에 맞고 증거 없음 | `uart_sync`, 특이 프롬프트는 `uart_set_context(prompt=…)` |
| 명령마다 `uart.device-busy` 로 거부 | 부팅 중, 앞 명령이 아직 실행 중, 또는 특이한 프롬프트라 명령 뒤 프롬프트를 못 알아봄 | `uart_sessions` 의 device_busy_reason 확인 → 프롬프트를 기다리거나 `uart_set_context(prompt=…)` 로 학습 |
| 로그인 뒤 바로 다시 `login:` | 계정 오류, 셸이 /bin/false | 사용자에게 확인. 다른 계정을 추측하지 않음 |
| 셸 출력에 벤더 앱 로그가 섞임 | printk·앱 로그가 콘솔로 나옴 | `uart_read` 로 프롬프트 확인. 로그 레벨 조정은 덤프 Skill 에서 판단 |
| 세션 `disconnected` | USB 분리, Windows 절전으로 usbipd 분리 | `uart_close` → H1 → `uart_open` |
| `uart_open` 이 `[busy]` | 같은 포트의 다른 세션, 외부 터미널(picocom/minicom) | `uart_sessions`. 외부 프로그램 종료는 사람에게 요청 |
| 기기가 혼자 재부팅 | 워치독(특히 init=/bin/sh), 전원 부족, 부트 루프 | 노트, 전원 어댑터 확인 |

## 4. 추가 템플릿

**H4. 출력 없음·깨짐 점검**
```
[사람 작업 필요] UART 출력 점검
1. 기기 전원을 끕니다.
2. 어댑터 RX 와 TX 두 선을 서로 바꿔 꽂습니다(기기 TX 가 어댑터 RX 로 가야 합니다).
3. GND 가 보드 GND 에 확실히 닿았는지, 어댑터 전압 점퍼가 3.3V 인지 확인합니다.
4. 기기에 전원이 실제로 들어가는지(LED 등) 확인합니다.
5. 끝나면 "완료" 라고 알려 주세요. 제가 감시를 시작하면 전원을 넣어 주세요.
```

**H7. 승인 요청 (approval_required)**
```
[승인 필요] approval_id=ap-xxxx
- 작업: uart_send_command("setenv bootargs ${bootargs} init=/bin/sh") (위험도 MODIFY, 규칙 uboot.setenv)
- 이유: 로그인 없이 root 셸을 1회 얻기 위해 RAM 의 bootargs 에 init=/bin/sh 추가 (동의하신 경로 D)
- 위험: 서비스가 뜨지 않음, 워치독 재부팅 가능. 플래시에는 쓰지 않음
- 되돌리는 방법: 전원 재투입 (env 저장 안 함)
- 승인하려면 별도 터미널에서: pweh approve ap-xxxx   (elicitation 폼이 뜨면 거기서 직접 응답)
```

**H8. 거부 보고 (denied)**
```
[보고] 안전 게이트 거부 (우회하지 않음)
- 요청: uart_send_command("<명령>")
- 응답: status denied (규칙 <rule_id>, 위험도 <risk>) — <message 요약>
- 의미: <예: 플래시에 영구 저장하는 명령 / 내용을 모르는 변수를 실행하는 run>
- 대안: <예: uboot_printenv 로 env 를 읽은 뒤 다시 판단 / 이 단계 생략>. 정책 변경은 운영자가 직접 결정합니다.
```

## 5. 경로 D 세부 (init=/bin/sh)

**원리.** 커널 파라미터 `init=` 은 PID 1 로 실행할 프로그램이다. 여러 번 나오면 마지막 값을 쓴다. `/bin/sh` 를 주면 rcS·서비스·로그인 없이 root 셸이 뜬다.
U-Boot 의 `setenv` 는 RAM 사본만 바꾸므로 다음 전원 재투입에서 원래 env 로 돌아간다. `saveenv`/`env save` 는 DESTRUCTIVE 이고 기본 정책에서 거부된다.

**bootcmd 확인** (`uboot_printenv` 의 bootcmd, 필요하면 `uart_send_command(command="printenv <변수>")` 로 run 대상 확인):

| bootcmd 모양 | 처리 |
|---|---|
| `sf probe 0; sf read <ram> <off> <len>; bootm <ram>` | SKILL 10단계 그대로 (`setenv bootargs ${bootargs} init=/bin/sh` → `boot`) |
| `setenv bootargs …; sf probe …; bootm …` (bootcmd 가 bootargs 를 덮어씀) | 아래 수동 순서 |
| `run setargs; run loadk; bootm` 처럼 run 으로 나눔 | 각 변수를 `printenv` 로 읽고, bootargs 를 설정하는 변수가 있으면 수동 순서 |
| env 에 bootargs 가 없음 | 수동 순서(값은 bootcmd 안의 것) |

**수동 순서 예** (값은 bootcmd 에 적힌 그대로 쓴다):
```text
uart_send_command(session_id="console-001", command="setenv bootargs mem=64M console=ttyAMA0,115200 root=/dev/mtdblock3 init=/bin/sh")   # MODIFY
uart_send_command(session_id="console-001", command="printenv bootargs")                                  # INTERACT, 확인
uart_send_command(session_id="console-001", command="sf probe 0")                                         # INTERACT
uart_send_command(session_id="console-001", command="sf read 0x42000000 0x50000 0x200000", timeout=30)    # INTERACT, RAM 으로만 읽음
uart_send_command(session_id="console-001", command="bootm 0x42000000", timeout=40, expect="Kernel command line: .*init=/bin/sh")  # MODIFY
```
- `sf write`/`sf erase`/`sf update`, `mw`, `saveenv` 는 보내지 않는다. `nand read`/`mmc read` 로 적재하는 기기도 같은 방식이다(읽기만).
- U-Boot 문맥에서 250자를 넘는 줄은 DESTRUCTIVE 로 거부된다(CBSIZE 절단). 길면 `${bootargs}` 를 쓰거나 bootcmd 의 값만 옮긴다.
- 추적 env 가 없으면(`uboot_printenv` 미완료) `run` 은 거부된다. 먼저 printenv 를 완료한다.

**성공 신호.** `Kernel command line:` 줄 끝에 `init=/bin/sh` → `/bin/sh: can't access tty; job control turned off` → `/ # ` 또는 `# `.
**실패 신호.** 명령행에 init=/bin/sh 가 없음(bootcmd 덮어쓰기, 커널 고정 cmdline `CONFIG_CMDLINE_FORCE`) → 평소처럼 login 이 뜬다.
`Kernel panic - not syncing: No working init found` → /bin/sh 가 없다. 어느 경우든 기록하고 멈춘다. 전원 재투입으로 복구된다.

**셸에서.**
- 허용: `mount -t proc proc /proc`, `mount -t sysfs sysfs /sys`, 필요하면 `mount -t devtmpfs devtmpfs /dev`(모두 MODIFY, 휘발성), 읽기 전용 명령, `shell_identify`.
- 금지: `mount -o remount,rw /`, `passwd`(DESTRUCTIVE), 파일 생성·수정, `/dev/mtd*` 쓰기, `exec /sbin/init`·서비스 시작, `reboot`(재부팅이 필요하면 사람이 전원 재투입).
- 제어 터미널이 없어 Ctrl-C 가 안 먹을 수 있다. `uart_sync` 가 timed_out 이면 `uart_read(tail=true)` 로 프롬프트를 확인하고 `uart_set_context(context="linux-shell", prompt="/ # ")` 로 학습시킨다.
- 하드웨어 워치독이 켜진 기기는 아무도 워치독을 갱신하지 않아 수십 초 안에 재부팅될 수 있다. 정상 부팅으로 돌아온다. 이 경우 덤프는 U-Boot 경로를 권한다.

**기록.** `case_add_note` 에 원래 bootargs, 보낸 명령 전부, 결과를 남긴다. summary 의 login_method `init-sh-ram`, linux.login_required true, notes 에 "RAM 한정, saveenv 안 함, 재투입으로 복구".
끝나면 사용자에게 전원을 다시 넣어 정상 부팅을 확인하도록 권한다(선택: `uart_capture_boot` 로 명령행에 init=/bin/sh 가 없는지 확인).

## 6. 실패·부분 성공 summary 예

둘 다 `schemas/uart-recon.schema.json` 검증을 통과한 예다.

**silent (status `failed`)**
```json
{
  "port": "/dev/ttyUSB0", "baudrate": 115200, "framing": "8N1",
  "baud_detection": {"method": "auto-scan", "candidates": [{"baudrate": 115200, "bytes": 0}, {"baudrate": 57600, "bytes": 0}, {"baudrate": 38400, "bytes": 0}], "score": null},
  "console_type": "silent", "access_level": "none", "uboot": null, "linux": null,
  "device_info": {"tx_pad_voltage": "3.3V (사람 측정)"}, "session_log": null,
  "notes": ["uart_detect_baud 2회(전원 재투입, TX/RX 교차 후 재시도) 모두 수신 0 바이트", "baudrate 115200 은 프로필 기본값일 뿐 확인되지 않음",
            "다음: logic-analyzer-protocol-decode 로 패드 활동 확인"]
}
```

**로그인에서 막힘 (status `partial`)**
```json
{
  "port": "/dev/ttyUSB0", "baudrate": 115200, "framing": "8N1",
  "baud_detection": {"method": "profile", "candidates": [115200], "score": null},
  "console_type": "linux-login", "access_level": "login-required",
  "uboot": {"version": "U-Boot 2013.07 (Dec 09 2020 - 11:32:38)", "prompt": null, "autoboot": {"message": "Hit any key to stop autoboot:  0", "interrupt_keys": ["ctrl-c"], "bootdelay": 0}},
  "linux": {"kernel_version": "3.10.14", "cmdline": "console=ttyS1,115200n8 mem=42M@0x0 init=/linuxrc rootfstype=squashfs root=/dev/mtdblock3 rw mtdparts=jz_sfc:256k(boot),64k(env),2048k(kernel),4096k(rootfs),9920k(appfs)",
            "cpu": null, "mtd": [], "user": null, "busybox": "BusyBox v1.22.1 (2020-12-09 11:51:20 CST)", "login_required": true},
  "session_log": "uart/console-001.log", "boot_log": "uart/console-001-boot-01.log", "login_method": "not-attempted",
  "notes": ["uboot_interrupt 3회 실패: outcome=kernel, autoboot 메시지 bootdelay 0", "사용자가 계정을 모름 → 로그인 시도 안 함"]
}
```

**포트조차 없을 때.** port 가 필수라서 summary 를 만들 수 없다.
```text
case_record_step(case_id="20261018-acme-ipc", skill="uart-shell-acquisition", step="port-discovery", status="failed",
                 summary="USB-UART 포트를 찾지 못함", blockers=["usbipd attach 후에도 /dev/ttyUSB* 없음"])
case_set_phase(case_id="20261018-acme-ipc", phase="uart-shell-acquisition", status="failed", note="USB-UART 미검출")
```

## 7. 시뮬레이터로 연습

```bash
.venv/bin/pweh-mock-device --profile hisilicon-like --pty --no-autostart
# 첫 줄 JSON 의 "pty" 경로를 uart_open/uart_detect_baud 의 port 로 쓴다.
# 표준입력에 power-on / power-cycle / power-off 를 입력하면 사람이 전원을 조작한 것과 같다. destructive 로 기기에 도달한 파괴 명령을 확인한다.
```
- 케이스 프로필: `mock-hisilicon`(hisilicon-like), `mock-ingenic`(ingenic-like), `hisilicon-ipcam`(hisilicon-legacy). 시뮬레이터 계정은 첫 줄 JSON 에 있다(연습용).
- 이 Skill 을 작성하며 세 프로필에서 실제로 돌려 본 순서: `uart_detect_baud` → `uart_open` → `uart_capture_boot` → `uboot_interrupt` → `uboot_printenv` → `uboot_info`
  → `setenv bootargs ${bootargs} init=/bin/sh` → `printenv bootargs` → `boot`(Kernel command line 에 반영 확인) → `shell_login`(오답 1회 → login_incorrect, 비밀번호 없이 → password_required)
  → `shell_identify` → `uart_close`. `saveenv` 와 printenv 전 `run bootcmd` 는 denied, 파괴 명령 기기 도달 0건.
- 한계: init=/bin/sh 를 흉내 내지 않는다(부팅은 계속 askfirst/login 으로 감). PTY 보드레이트 흉내 때문에 부팅 출력이 첫 후보 창에 몰리면 `uart_detect_baud` 가
  틀린 best(confidence 0.705, 깨진 sample)를 낼 수 있다. askfirst 화면은 Ctrl-C 에 응답하지 않는다. PTY 에는 DTR/RTS 가 없다.

## 8. autoboot 변형과 keys

| autoboot 메시지 | 빌드 | `uboot_interrupt` 의 keys / 프로필 |
|---|---|---|
| `Hit any key to stop autoboot: N` | 대부분의 벤더 SDK(HiSilicon, Ingenic, Goke, Grain Media, XMedia) | 기본(Ctrl-C). 안 되면 `["ctrl-c", "space"]` |
| `Hit key to stop autoboot('CTRL+C'): N` | Rockchip | `["ctrl-c"]`, 프로필 `rockchip-ipcam`(보드레이트 1500000 후보) |
| `Press Ctrl-c to stop autoboot... N` / `abort` | OpenIPC HiSilicon V4·Goke·Ingenic T40 | `["ctrl-c"]` |
| `Press ENTER to interrupt boot in N...` | OpenIPC Ingenic | `["enter"]` 또는 프로필 `ingenic-openipc` |
| 메시지 없음, bootdelay 0, CR | SigmaStar/MStar SDK | 프로필 `sigmastar-ipcam`(autoboot_silent, CR). 사람이 호출 직후 바로 전원을 넣어야 한다 |
| 메시지 없음, bootdelay 0 | Novatek | 프로필 `novatek-ipcam`(autoboot_silent, Ctrl-C) |
| `Autoboot in N seconds` 또는 벤더 고유 문구 | keyed(`CONFIG_AUTOBOOT_STOP_STR`) | 벤더 문서로 확인한다. 문자열을 추측하지 않는다 |

- 프로필은 `uart_open` 때 정해진다. 바꾸려면 `uart_close` 후 `profile=` 을 주어 다시 열거나, `uboot_interrupt` 에 keys 를 직접 준다.
- Enter 키는 새 부팅 출력을 본 뒤, 수신 끝에 프롬프트가 없을 때만 도구가 보낸다. 프롬프트에서 Enter 는 직전 명령 반복이다.
- 근거: `docs/references/uboot-and-boot-console.md` §1.1, §8.1–8.6, §10, `orchestrator/pipeline-config.yaml` 의 profiles.
