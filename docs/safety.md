# 안전 가이드

PWEH 는 실제 하드웨어를 에이전트가 조작하는 도구다. 실수 하나로 기기가 벽돌이 되거나, 기기·장비가 전기적으로
손상되거나, 법적 문제가 생길 수 있다. 이 문서는 **사람(운영자)** 과 **에이전트** 모두가 지켜야 할 규칙이다.

---

## 1. 법적 범위: 소유 기기 또는 서면 허가 기기만

- 분석 대상은 **본인이 소유한 기기** 또는 **소유자에게서 명시적 서면 허가를 받은 기기**뿐이다.
  임대·회사 자산·고객 장비는 서면 허가(범위·기간·담당자 명시)가 있어야 한다.
- PWEH 는 이를 설계로 강제한다. 모든 하드웨어 도구는 케이스에 소유/허가 증명(`authorization`)이 있어야 동작한다.
  - `basis`: `owned` 또는 `written-authorization`.
  - `owner`: 소유자 또는 허가 주체.
  - `statement`: 사용자가 소유·허가를 확인한 말을 그대로 인용.
  - 서면 허가라면 `document_ref` 가 필수다.
- 에이전트는 사용자에게 소유/허가 여부를 **직접 물어 확인받은 뒤에만** `case_create` 를 호출한다.
  답이 모호하면 진행하지 않는다.
- 분석 결과(펌웨어, 자격증명, 취약점)는 **연구·방어 목적**으로만 쓴다.
  - 같은 모델을 쓰는 제3자 기기에 결과를 적용하지 않는다. 인터넷에 노출된 기기를 스캔하는 데도 쓰지 않는다.
  - 새 취약점을 발견하면 제조사 PSIRT 에 책임 있게 공개(coordinated disclosure)한다.
- 동적 검증(웹 요청 등)은 **격리된 랩 네트워크**에서 **분석 대상 기기에만** 한다. 공격 페이로드를 만들지 않는다.
  보고서의 `verification_plan` 에는 확인 방법만 적는다.

## 2. 전기·물리 안전 (사람이 하는 작업)

PWEH 는 물리 작업을 사람에게 맡긴다. 에이전트는 무엇을 연결해야 하는지 **설명만** 하고, 사람이 확인한 뒤 진행한다.

### 2.1 전원과 고전압
- **AC 전원(220V/110V)을 직접 받는 DVR/NVR 는 내부 SMPS 에 치명적 고전압이 있다.**
  케이스를 연 상태로 전원을 넣지 말고, 외부 DC 어댑터로 메인보드만 구동할 수 있는지 먼저 확인한다.
- **PoE 카메라는 48V** 가 들어온다. 디버그 작업 중에는 PoE 대신 12V/5V DC 잭으로 전원을 넣는다.
- 전원을 껐다 켜는 일(power-cycle)은 사람이 한다. 에이전트가 "지금 전원을 껐다 켜 주세요" 라고 요청하면,
  연결 상태를 다시 확인한 뒤 수행한다.

### 2.2 UART
- 연결은 **GND–GND, 기기 TX → 어댑터 RX, 기기 RX → 어댑터 TX** 세 가닥이다.
  **어댑터의 VCC 핀은 연결하지 않는다.** 기기는 자기 전원으로 구동한다.
- 전압 레벨을 먼저 잰다. 대부분 카메라 SoC 는 **3.3V**, 일부는 **1.8V** 다.
  - 3.3V 어댑터를 1.8V 핀에 연결하면 SoC 가 손상될 수 있다. 1.8V 면 레벨 시프터나 1.8V 지원 어댑터를 쓴다.
  - 5V TTL 어댑터는 쓰지 않는다.
- 멀티미터로 TX 핀을 찾는 방법: 부팅 중에 전압이 출렁이는 핀이 TX 다. RX 는 보통 3.3V 근처에 머문다.
  GND 는 연속성(continuity) 모드로 보드 GND 와 확인한다.
- 핀 헤더를 납땜할 때는 전원을 끄고, 인접 패드와 브리지가 생기지 않았는지 확대경으로 확인한다.

### 2.3 로직 애널라이저
- 저가 fx2lafw(Saleae 클론) 입력은 보통 **최대 5V 허용, 3.3V 로직** 이다. 그보다 높은 전압을 측정하지 않는다.
- **GND 를 가장 먼저** 연결하고, 프로브는 가장 나중에 붙인다.
- 클립이 인접 핀을 단락시키지 않게 한다. SOIC 클립은 정렬을 두 번 확인한다.

### 2.4 JTAG / JTAGulator
- JTAGulator 의 **target I/O voltage 설정은 대상의 I/O 전압과 같아야 한다.**
  틀리면 타깃이 손상될 수 있다. 멀티미터로 대상 전압을 직접 측정한다.
- PWEH 에서 `jtagulator_set_voltage` 는 **DESTRUCTIVE** 로 분류된다. 기본 정책에서는 거부되고,
  허용하려면 사람의 승인이 필요하다 (§3).
- 핀아웃 스캔은 대상 핀에 신호를 넣는다. 전원 핀이나 아날로그 핀에 채널을 물리지 않는다.
- JTAG 디버그 프로브(FT2232H, J-Link 등)의 VTref 는 대상 전압을 **감지**하는 핀이다. 전원을 공급하는 핀이 아니다.

### 2.5 SPI 플래시 직접 읽기 (SOIC 클립 + 프로그래머)
- 보드에 전원이 들어간 상태에서 클립을 물리지 않는다.
- 프로그래머의 3.3V 가 플래시를 거쳐 보드 전체를 역전원(back-power)할 수 있다.
  SoC 가 깨어나 버스를 점유하면 읽기가 실패하거나 SoC 가 손상될 수 있다. 필요하면 플래시를 떼어 내서 읽는다.
- 1.8V 플래시(예: 일부 W25Q…W 계열)에는 1.8V 어댑터를 쓴다.
- CH341A 계열 일부 보드는 데이터 라인이 5V 다. 개조되지 않은 보드는 쓰지 않는다.

### 2.6 ESD 와 작업 환경
- 정전기 방지 매트와 손목 스트랩을 쓴다.
- 작업 전후로 보드를 사진으로 남긴다 (케이스 `notes/` 에 보관). 케이블 위치를 복구할 때 쓴다.

## 3. 소프트웨어 안전: 서버 측 게이트

### 3.1 위험도와 기본 정책

| 위험도 | 예 | 기본 정책 |
|---|---|---|
| OBSERVE | 포트 목록, 수신 버퍼 읽기, 로직 캡처 | 허용 |
| INTERACT | `printenv`, `md.b`, `sf read`(RAM 으로만), `crc32`, `cat /proc/mtd`, `scan_chain`, `mdw` | 허용 |
| MODIFY | `setenv`(저장 안 함), `boot`, `reset`, `halt`, DTR/RTS 토글, 서비스 시작, JTAGulator 스캔, 결과를 저장하는 `crc32 <주소> <크기> <대상>`, `/dev/watchdog`·`/dev/mem` 읽기, `/tmp` 같은 일반 파일 쓰기 | 허용 (`safety.modify_policy`) |
| DESTRUCTIVE | `saveenv`/`env save`, `sf erase/write/update`, `nand erase/write`, `mw`/`cp`(대상 주소와 무관 — 플래시가 메모리에 매핑된 SoC 가 있다), `flash_erase`, `dd of=/dev/mtd*`, 영구 파티션·시스템 디렉터리(`/bin`, `/etc` …) 파일 쓰기, 시스템 디렉터리 밖 실행 파일 실행(`./x`, `/tmp/x`), `PATH`/`LD_PRELOAD` 변경, OpenOCD `flash write_image`/`mww`/`load_image`, eFuse/OTP, JTAGulator 전압 설정 | **거부** (`safety.destructive_policy: deny`) |

운영자가 휘발성 변경까지 실행 전에 확인하고 싶으면 `orchestrator/pipeline-config.yaml` 의 `safety.modify_policy` 를 바꾼다.
`approve` 면 MODIFY 명령도 DESTRUCTIVE 처럼 승인 요청(`approval_required`)을 거쳐 사람이 `pweh approve <id>` 로 한 번씩 허용하고, `deny` 면 거부한다.
기본값 `allow` 는 덤프·분석 흐름이 멈추지 않게 하려는 선택이다. 에이전트는 이 값을 바꾸지 않는다(§4).

- 판단은 **MCP 서버 안에서** 한다. 클라이언트 권한 프롬프트(Claude Code permissions, Codex approval, Cursor Run Mode)는
  우회 모드에서 꺼질 수 있으므로 안전 경계로 간주하지 않는다 (`docs/references/agent-clients.md` §7).
- 모든 결정(허용/승인 필요/거부)은 `cases/<id>/audit.jsonl` 과 `.pweh/state/audit.jsonl` 에 남는다.
  최종 보고서의 "안전 게이트 및 감사 요약" 절에도 실린다.

### 3.2 위험 작업을 꼭 해야 할 때 (승인 흐름)

예: 펌웨어를 원래대로 복구하거나, 사용자가 의도적으로 부트 환경을 저장해야 하는 경우.

1. **사람**이 `orchestrator/pipeline-config.yaml` 에서 `safety.destructive_policy: approve` 로 바꾸고 MCP 서버를 재시작한다.
   에이전트는 이 설정을 스스로 바꾸지 않는다.
2. 에이전트가 위험 도구를 호출하면 서버가 둘 중 하나로 응답한다.
   - **elicitation 확인 폼**: 클라이언트가 지원하면 뜬다 (Claude Code v2.1.76+). 사람이 내용을 읽고 `approve=true` 와
     폼에 표시된 4자리 확인 코드를 입력해야 실행된다. Decline/Esc 를 누르면 거부된다.
     클라이언트가 폼을 자동으로 거절하면(예: Codex `-a never`) CLI 승인으로 넘어가지 않고 거부로 끝나므로,
     그런 환경에서는 사람이 `safety.approval_methods` 를 `[cli]` 로 둔다. 폼 표시 자체가 실패하면(오류·시간 초과) CLI 승인으로 넘어간다.
   - **`status: approval_required` + `approval_id`**: 사람이 **별도 터미널**에서 `pweh approve <approval_id>` 를 실행한다.
     내용과 위험을 확인하고 표시된 확인 코드를 입력한다. 이 명령은 대화형 터미널(TTY)에서만 동작한다.
3. 에이전트가 **같은 인자**에 `approval_id` 를 붙여 다시 호출하면 **딱 한 번** 실행된다.
   - 승인은 작업 지문(서버·도구·케이스·정규화된 명령)에 묶인다. 인자가 하나라도 다르면 무효다.
   - 기본 15분 뒤 만료된다 (`approval_ttl_seconds`).
4. 위험 작업 **전에는 반드시** 전체 플래시 백업이 케이스에 있어야 한다 (§5). 에이전트는 백업 sha256 을 사용자에게 보여 준다.

예외: pweh-sigrok 의 출력 가능 장치(전원공급기·전자부하·신호발생기·릴레이)와 허용 목록 밖 드라이버 거부(`gate.via: "sigrok-policy"`)는
게이트에 넘기지 않으므로 `approve` 정책에서도 승인 경로가 없다. 범용 FTDI 칩을 VID/PID 만으로 잡는 `ftdi-la` 도 기본 허용 목록 밖이다
(같은 칩을 쓰는 대상 콘솔 USB-UART·JTAG 어댑터·JTAGulator 를 가로챌 수 있다). 전용 FTDI LA 만 쓰는 환경에서 운영자가 `sigrok.capture_drivers_allow` 로만 연다.
pweh-jtagulator 는 원시 키 입력 도구 자체가 없다.

### 3.3 분류기가 보수적으로 막는 것들
- **U-Boot**
  - 명령 약어는 후보 중 가장 위험한 것으로 판단한다 (`sav` → `saveenv`).
  - `run <변수>` 와 `boot` 는 추적 중인 env 내용으로 재귀 분류한다. 내용을 모르면 DESTRUCTIVE 로 본다.
    `env run <변수>`(`en r` 같은 약어 포함)는 `run` 과 같고, `time <명령>`(약어 `t`/`ti`/`tim`)은 안쪽 명령으로 판단한다(`time sf erase …` → DESTRUCTIVE).
  - **빈 Enter 는 직전 명령을 반복**하므로 직전 명령의 위험도를 그대로 이어받는다.
    직전 명령을 모르면, 즉 uart 세션이 줄을 보낸 적도 재부팅을 본 적도 없고 이어 받은 명령도 없으면, U-Boot 가 받을 수 있는 문맥의 빈 Enter 는 DESTRUCTIVE 다(`uart.repeat-unknown`).
    세션을 열기 전에 사람이 친 `mw` 같은 명령이 반복될 수 있기 때문이다. 새 프롬프트는 `uart_sync`(Ctrl-C)로 얻는다.
    같은 서버 프로세스에서 같은 케이스·포트를 다시 열면 앞 세션의 마지막 U-Boot 명령을 이어 받는다(`uart_open` 의 `inherited_last_command`).
  - 명령 위치에 변수가 오면(`$x`) 확정할 수 없으므로 막는다.
  - 결과를 메모리나 env 에 저장하는 체크섬 형태(`crc32 <주소> <크기> <대상>`, `md5sum <주소> <크기> <변수>`·`*<주소>`)는 MODIFY 다(조회 형태는 INTERACT).
- **Linux 셸**
  - `sh -c`, `eval`, 명령 치환(`$(…)`, 백틱), `xargs`, `find -exec`, alias/함수 정의는 안쪽 명령을 다시 분류해 그 위험도를 따른다
    (`eval`·alias·함수 정의는 최소 MODIFY). 안쪽에 위험 명령이 있으면 막히고, `sh -c ls` 같은 조회는 허용된다. `exec <명령>` 도 안쪽 명령 기준이고 최소 MODIFY 다.
  - 실행할 **내용**을 확정할 수 없는 것은 DESTRUCTIVE 로 막는다.
    - 스크립트 실행: `| sh`(파이프-to-셸), `source`/`.`, `sh <파일>`·`ash <파일>`, 셸에 파일·here-doc 을 표준 입력으로 넘기기(`sh < f`, `sh <<EOF`, `ash -s < f`).
    - 명령 위치의 변수·글롭(`$X`, `/bin/l*`).
    - 경로로 지정한 실행 파일: `/bin`·`/sbin`·`/usr/bin`·`/usr/sbin` 바로 아래만 이름으로 판단한다. 그 밖(`./x`, `x/y`, `/tmp/x`, `/mnt/mtd/app/x`, `/bin/../tmp/x`)은
      이름과 무관하게 막는다(`linux.exec-nonsystem` — `/tmp/cat` 은 `cat` 이 아닐 수 있다). `nohup`·`env`·`timeout`·`busybox`·`exec` 를 거쳐도 같고,
      시스템 디렉터리 밖의 래퍼 이름(`/tmp/nohup ls`)은 래퍼로 믿지 않는다.
    - 실행·적재할 파일을 바꾸는 환경 변수 변경: `PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `ENV`, `BASH_ENV`
      (`PATH=/tmp:$PATH ls`, `env LD_PRELOAD=/tmp/x.so ls`, `export PATH=/tmp` — `linux.env-hijack`).
    - 다른 루트·다른 내용으로 바꾸기: `chroot`/`pivot_root`/`switch_root`, 바인드·오버레이 마운트(`mount --bind`, `-o bind`, `-t overlay`).
  - 블록·메모리 디바이스(`/dev/mtd*`, `/dev/mtdblock*`, `/dev/mmcblk*`, `/dev/mem` …)로 가는 리다이렉션과 `dd of=`,
    `devmem` 쓰기, `flash_erase`·`nandwrite`·`mtd_debug erase`·`fw_setenv` 같은 플래시 도구를 막는다.
    시스템 실행 파일·라이브러리·설정 경로(`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/lib`, `/usr/lib`, `/etc` 아래)에 쓰는 것도 막는다
    (리다이렉션, `cp`/`mv`/`ln`/`tee` 대상 — `linux.write.system`). `/tmp` 같은 일반 파일 쓰기는 MODIFY 다.
  - 영구 경로(`persistent_paths`)에 쓰는 것을 막는다.
  - 여는 것만으로 기기 상태가 바뀌는 장치를 읽는 명령은 MODIFY 다(`linux.read.side-effect-device`): `/dev/watchdog*`(여는 순간 타이머가 시작돼 재부팅),
    `/dev/mem`·`/dev/kmem`·`/dev/port`(MMIO 읽기 부작용·멈춤). `ls`·`stat`·`lsof`·`du`, `-exec` 없는 `find` 처럼 장치를 열지 않는 명령은 INTERACT 그대로다.
    `shell_dump_start` 는 `/dev/` 아래에서 저장장치만 읽고 이런 장치는 `validation_failed` 로 거부한다.
  - 조회용 `fdisk -l` 과 `[ -e /dev/mtd0 ]` 같은 test 는 INTERACT 다(장치를 주고 `-l` 없이 부르는 `fdisk` 는 DESTRUCTIVE).
- **콘솔 송신(`uart_write`, `uart_send_command`)**
  - 기기 쪽 라인 버퍼처럼 다시 조립해서 판단한다. 나눠 보내기(`sa` + `veenv\r`), Backspace 편집, Ctrl-C/Ctrl-U 처리를 반영한다.
  - 탭 자동완성, 방향키·히스토리 호출(ESC 시퀀스)이 섞이면 실제 명령을 확정할 수 없으므로 막는다. 상위 비트 바이트가 섞인 줄도 막는다(`uart.high-bit` — 콘솔에는 ASCII 만).
  - 기기가 프롬프트에 있지 않을 때(부팅 중, 앞 명령이 실행 중, 마지막 프롬프트 뒤 재부팅 증거) 완성되는 줄은 DESTRUCTIVE 다(`uart.device-busy`).
    기기가 앞 글자를 먹으면 분류한 줄과 다른 명령이 실행될 수 있어서다(`xsaveenv` 의 `x` 만 먹히면 `saveenv`). 그래서 한 `uart_write` 에 여러 줄을 넣으면 첫 줄 뒤는 모두 거부된다.
  - `cmd\r` 를 보낸 다음 호출의 `\n` 도 U-Boot 에서는 빈 줄(직전 명령 반복)로 분류한다(1회용 승인을 `\n` 으로 다시 실행하지 못하게).
  - 우리 입력의 에코와 보낸 텍스트를 되풀이한 출력(U-Boot `echo Linux version 9.9`)은 문맥 증거로 쓰지 않는다. U-Boot 로 본 프롬프트는 리눅스 증거만으로 linux-shell 이 되지 않는다.
  - 승인은 줄과 함께 실행 의미에 묶인다(`env_refs`, `repeat_of`). `run x` 를 승인받은 뒤 `setenv x …` 로 내용을 바꾸면 그 승인은 맞지 않는다.
- **OpenOCD TCL**
  - 중괄호·대괄호 안의 명령까지 검사한다. 코어 분류기만으로는 Jim Tcl 의 실행 경로를 다 다루지 못하므로, Tcl 파서를 가진 `openocd_mcp.guard` 가 문장마다 코어 분류를 다시 하고 더 엄격한 쪽을 쓴다.
  - `eval`/`source`/`proc` 같은 메타 명령과, 호스트 임의 경로에 쓰는 `dump_image`/`flash read_bank` 원시 호출을 막는다.
    전용 도구는 케이스 경로로만 쓴다.
  - 숨은 실행 위치도 막는다: 옵션 뒤 `catch` 본문, `dict`/`loop` 본문, `-event` 핸들러, `-command` 접두(`lsort -command mww …`), `update`/`vwait`/`xtrace`/`curry`,
    `::mww`·`m\ww` 같은 이름 우회, `popen` 같은 Jim 호스트 탈출.
  - 중괄호 없는 식의 치환(`expr $x`, `if [catch {halt}] …`)은 expr 가 결과를 다시 해석하므로 DESTRUCTIVE 다. 식은 항상 중괄호로 감싼다(`expr {1 + 2}`, `if {[catch {halt}]} …`).
  - 서버가 끈 telnet/GDB 명령 서버를 다시 여는 `telnet port N`·`gdb port N`·`-gdb-port N` 은 DESTRUCTIVE 다. 그 포트로 들어온 명령은 게이트를 거치지 않기 때문이다.
  - 점 없는 타깃 이름 뒤의 위험한 하위 명령(`cpu0 mww …`)은 DESTRUCTIVE 다. 서버가 만드는 `<타깃> read_memory …` 는 `target names` 로 확인한 타깃만 쓰고,
    명령 이름과 같은 타깃 이름(`mww`, `reset` …)은 거부한다.
  - `openocd_start` 의 사용자 cfg 는 내용 전체를 분류하고(1 MiB 초과는 거부) 승인 지문에 sha256 을 넣는다. 승인 뒤 바뀐 cfg 는 실행되지 않는다.
- **JTAGulator · sigrok**
  - JTAGulator UART 스캔 프로브는 대상 콘솔이 여러 번 받으므로, 두 번 이어 붙인 형태까지 콘솔 분류기로 검사한다(`_erase X\rflash` → `flash_erase X`).
    `jtagulator_connect` 는 장치 경로·`socket://`·`rfc2217://` 형식만 받고 포트를 exclusive 로 열어, 다른 세션이 쓰는 대상 콘솔에 재동기화 키를 보내지 않는다.
  - sigrok 디코드는 sigrok-cli 를 띄우기 직전에 오프라인 명령인지 다시 확인한다.

### 3.4 위협 모델과 한계 (정직하게)
- 이 게이트는 **협조적이지만 성급한 에이전트의 실수**를 막는 장치다. 같은 OS 계정으로 셸을 쓸 수 있는 적대적
  에이전트를 완벽히 막는 샌드박스는 아니다. 예를 들어 에이전트가 직접 시리얼 포트를 열거나, 승인 파일을 위조하거나,
  설정 파일을 고칠 수 있다. 그래서 다음을 지킨다.
  - 에이전트 규칙(§4)과 감사 로그로 이런 행동을 금지하고 사후에 드러낸다.
  - 강한 격리가 필요하면 MCP 서버를 **별도 OS 계정**으로 실행하고, 시리얼 장치 권한(`dialout`)과
    `.pweh/state`·설정 파일 쓰기 권한을 그 계정에만 준다. 에이전트 계정에는 주지 않는다.
- 정적 분류에는 오탐도 있다. 예를 들어 `which flash_erase` 는 허용되지만, 함수 정의 안에 위험 명령이 있으면 막힌다.
  OpenOCD Tcl 에서 중괄호 조건이 변수로 시작하면(`if {$x} {halt}`) 명령 위치의 변수로 보고 DESTRUCTIVE 로 거부한다.
  막혔다면 우회하지 말고 더 단순한 읽기 전용 명령으로 바꾸거나(변수 대신 실제 값) 사용자에게 설명한다.
- 미탐도 있다. 알려진 것은 아래와 같다. 에이전트는 기기에서 스크립트나 실행 파일을 만들어 실행하지 않는다.
  거부된 명령을 스크립트로 감싸거나 다른 경로·이름으로 바꿔 실행하는 것은 우회다(§4 규칙 4).
  - 리눅스 셸의 현재 디렉터리(cwd)는 세션이 보낸 `cd` 로만 추적한다(`uart_sessions` 의 `linux_cwd`, 같은 줄 안의 `cd` 도 반영).
    그래서 `cd /usr/bin && cp /tmp/x md5sum` 이나 `cd /bin; echo … > y` 는 시스템 경로 쓰기(`linux.write.system`, DESTRUCTIVE)로 거부되고,
    거부되었으니 그 뒤의 `md5sum /dev/mtd3` 이나 이름만 쓴 `y` 가 바뀐 내용을 실행하는 일도 없다. 남은 한계:
    세션을 열기 전·로그인 직후의 시작 디렉터리는 모르므로 그때의 상대 경로 쓰기는 MODIFY(`linux.write.file`, uncertain)이고,
    `cd` 는 성공한다고 보며(실패를 출력으로 확인하지 않음), 서브셸·스크립트 안의 `cd` 는 구분하지 못한다. 재부팅을 보면 cwd 를 모름으로 되돌린다.
  - 이름으로 실행하는 명령은 시스템 디렉터리에 놓인 파일의 내용을 보지 않는다. 표에 없는 이름은 `unknown_command_risk`(기본 MODIFY)다.
  - 콘솔 송신의 Backspace(0x08)/DEL(0x7F)은 편집으로 반영한다. 줄 편집이 없는 리눅스 tty 에서는 erase 문자가 아닌 쪽이 글자로 남아 기기의 줄이 다를 수 있다
    (에이전트는 편집 키를 보내지 않는다).
  - 우리 입력의 되풀이 검사는 텍스트 비교라 `printf` 이스케이프나 변수로 피할 수 있다. 이미 U-Boot 프롬프트로 본·학습한 문자열 규칙이 일부만 막는다.
  - `inherited_last_command` 는 같은 서버 프로세스 안에서만 이어지고, 세션 사이에 사람이 콘솔에 직접 입력했으면 틀릴 수 있다.
    서버가 재시작되면 이어 받지 않으므로 빈 Enter 는 `uart.repeat-unknown` 으로 거부된다. 이때는 사람에게 전원 재투입을 요청한다.
  - '모르는 직전 명령의 빈 Enter' 규칙은 uart 경로(`uart_mcp.guard`)에만 있다. 코어 `classify_uboot` 는 직전 명령이 없으면 빈 줄을 INTERACT(`uboot.empty`)로 본다.
    그래서 `jtagulator_uart_scan` 의 기본 프로브 `\r`(CR)는 INTERACT 로 통과한다. 대상이 U-Boot 프롬프트에 머물러 있으면 직전 명령이 반복될 수 있으니,
    UART 핀 스캔은 수동 TXD 스캔을 먼저 쓰고 대상이 U-Boot 프롬프트에 있지 않을 때 한다.
  - `uboot_dump_start` 에 `ram_addr` 을 직접 주면서 `uboot_info` 를 부르지 않았으면 DRAM 범위를 몰라 주소를 검사하지 못한다(`notes` 에 기록).
    `sf read` 를 임의 주소로 보내면 사실상 메모리 쓰기지만 INTERACT 로 분류된다.
  - 리눅스 init 중(부팅 스크립트가 콘솔을 쥔 동안)의 Ctrl-C 는 INTERACT 다. `uboot_interrupt` 는 리눅스가 도는 동안 키를 보내지 않는다.
  - `/dev/watchdog` 을 가리키는 심볼릭 링크나 다른 이름(`/tmp/wd` → `/dev/watchdog`)은 장치 읽기 규칙과 `shell_dump_start` 의 경로 제한이 알아보지 못한다.
  - OpenOCD: 타깃 이름이 명령 이름을 가리면(cfg 의 `target create reset …` 뒤 `reset mww …`) 에이전트 원시 명령은 전역 명령 기준(MODIFY)으로 분류된다.
    점 없는 타깃의 동적 하위 명령(`cpu0 $x …`)도 MODIFY 다. 목록에 있는 타깃 이름의 명령을 `proc`/`rename` 으로 바꿔치기하는 것은 감지하지 않는다
    (이 명령들은 DESTRUCTIVE 라 승인 없이는 실행되지 않는다).
- Claude Code 사용자는 보조 장치를 추가로 얻는다.
  - 항상 파괴적인 도구 세 개(`openocd_flash_write`, `openocd_write_memory`, `jtagulator_set_voltage`)에만
    `anthropic/requiresUserInteraction` 메타가 붙어 bypass 모드에서도 매번 확인을 띄운다. 다른 도구의 위험은 서버 게이트가 판단한다.
  - `.claude/settings.json` 의 `ask` 규칙도 bypass 모드에서 동작한다. 대상은 원시 쓰기(`uart_write`), DTR/RTS·BREAK
    (`uart_set_signals`, `uart_send_break`), 원시 TCL(`openocd_command`), 위 세 파괴적 도구, 그리고 REA 의 런타임·기기 도구
    (프로세스·디버거·Frida·Cutter·앱·브라우저 세션을 시작·조작·종료하는 도구, adb 기기에 쓰기·설치·실행하거나 파일·화면을 가져오는 도구,
    Rizin 셸 탈출(`!`)로 호스트 명령까지 실행할 수 있는 `execute_rizin_command`)다.
  - `allow` 규칙은 기본 모드에서 묻지 않을 도구다(bypass 모드에서는 의미가 없다): pweh 서버의 `readOnlyHint` 도구,
    `pweh-case`·`pweh-fwtriage` 전체, REA 정적 분석 도구.

## 4. 에이전트 운영 규칙 (master-prompt 와 모든 Skill 에 반영)

1. 시작 전에 소유/허가를 확인한다. 확인되지 않으면 하드웨어 도구를 호출하지 않는다.
2. 물리 작업(배선, 전원, 클립)은 사람에게 **구체적으로** 요청하고, 사람이 완료를 확인한 뒤 진행한다.
3. `approval_required` 를 받으면 사용자에게 작업 내용, 위험, 되돌릴 방법을 설명한다. 승인은 사람이 한다.
   - 에이전트가 `pweh approve` 를 실행하지 않는다.
   - 에이전트가 `.pweh/state/approvals/*.json` 을 수정하지 않는다.
4. `denied` 를 받으면 우회하지 않는다. 예를 들어 같은 동작을 다른 문법으로 다시 보내거나, 셸에서 직접 포트를 열거나,
   설정을 바꾸지 않는다. 사용자에게 보고한다.
5. U-Boot 프롬프트를 다시 얻을 때 **빈 Enter 대신 Ctrl-C** 를 쓴다 (빈 Enter 는 직전 명령을 반복한다).
6. 펌웨어를 쓰거나 지우는 작업은 **검증된 전체 백업**(sha256 + 기기 측 crc32/md5 일치)이 케이스에 있을 때만 제안한다.
7. 기기를 부팅 불가 상태로 만들 수 있는 작업(`bootargs` 에 `init=/bin/sh` 를 넣고 부팅 등)은 사용자에게 설명하고 **명시적 동의**를 받은 뒤
   **RAM 에서만** 하고 저장하지 않는다. `saveenv` 하지 않는다. 다음 전원 재투입으로 원상 복구됨을 사용자에게 알린다.
8. 장시간 작업(덤프, 긴 캡처, 핀아웃 스캔)은 job 으로 돌리고, 진행 상황을 사용자에게 주기적으로 알린다.
   사용자가 멈추라고 하면 즉시 `*_job_cancel` 한다.
9. 콘솔에는 프롬프트가 보일 때 한 줄씩 보낸다(`uart_send_command`). 앞 명령이 실행 중이거나 기기가 부팅 중일 때 보낸 줄과
   `uart_write` 한 번에 넣은 여러 줄의 둘째 줄부터는 `uart.device-busy`(DESTRUCTIVE)로 거부된다. 콘솔에는 ASCII 만 보낸다.
10. 기기 리눅스 셸에서는 시스템 디렉터리(`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`)의 표준 명령만 이름으로 실행한다.
    다른 경로의 파일을 경로로 실행하거나, 도우미 스크립트를 써서 실행하거나, `PATH`·`LD_PRELOAD` 를 바꾸지 않는다
    (게이트가 `linux.exec-nonsystem`, `linux.script`, `linux.env-hijack` 로 거부한다). 무엇을 바꿔도 되는지는 규칙 6·7 과 각 Skill 의 동의 규칙을 따른다
    (§3.4 의 cwd 추적과 한계 참고). 시스템 디렉터리로 `cd` 한 뒤 상대 경로로 쓰지 않는다.

## 5. 백업과 롤백

- **원칙: 쓰기 전에 읽는다.** 쓰기·삭제를 고려하기 전에 전체 플래시를 덤프하고 검증한다.
  - `uboot_dump_start` 는 청크마다 기기 측 crc32 를 비교한다.
  - `shell_dump_start` 는 청크마다 md5 를 비교한다.
  - 그 결과를 `dumps/` 에 sha256 과 함께 보관한다.
- 덤프는 가능하면 **두 번** 받아 sha256 이 같은지 확인한다 (UART 노이즈 대비).
- 원복 방법을 미리 정해 둔다.
  - U-Boot 의 `sf write` 로 RAM 에서 플래시로 쓰기 (DESTRUCTIVE, 승인 필요).
  - SPI 프로그래머로 직접 쓰기 (사람이 수행).
  - JTAG `flash write_image` (DESTRUCTIVE, 승인 필요).
- 환경 변수만 바꾸고 싶다면 `setenv` 후 `boot` 로 **휘발성으로** 시험한다. `saveenv` 는 마지막 수단이다.

## 6. 비상 정지

| 상황 | 조치 |
|---|---|
| 에이전트가 잘못된 방향으로 진행 | 에이전트에게 중지를 지시. 진행 중 job 은 `uart_job_cancel` / `openocd_job_cancel` / `sigrok_job_cancel` / `jtagulator_job_cancel` |
| 즉시 기기 조작을 끊어야 함 | **기기 전원을 뽑는다**. 또는 USB 어댑터를 뽑는다 (세션은 `disconnected` 로 표시됨) |
| MCP 서버 정지 | 에이전트 클라이언트를 종료하거나 `/mcp` 에서 서버를 끈다. 서버 종료 시 세션과 job 이 정리된다 |
| 승인 대기 취소 | `pweh deny <approval_id>` |
| 과열·타는 냄새·연기 | 즉시 전원 차단, 작업 중단, 보드 점검 |

## 7. 데이터 취급

- 덤프한 펌웨어에는 자격증명, 개인키, 클라우드 토큰, Wi-Fi 비밀번호, 녹화 영상 일부, 개인정보가 들어 있을 수 있다.
  `cases/` 는 git 에서 제외되어 있다 (`.gitignore`). 외부에 공유할 때는 민감 정보를 제거한다.
- 보고서에 실제 비밀번호나 키를 그대로 싣지 않는다. 해시 일부 또는 마스킹된 형태로 싣는다.
- 기기 로그인 비밀번호는 이벤트 로그(`uart/*.events.jsonl`)에서 마스킹된다. 단 원시 수신 로그(`*.raw`, `*.log`)에는
  기기가 에코한 내용이 그대로 남을 수 있다.
- 제조사 펌웨어의 저작권을 존중한다. 덤프나 추출본을 재배포하지 않는다.
