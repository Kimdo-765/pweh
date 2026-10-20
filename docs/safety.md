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

### 2.7 ESP32 보드 (esptool, pweh-esp)
- 개발 보드(DevKit)는 보통 USB 케이블 하나로 전원과 통신을 함께 받는다. 충전 전용 케이블이면 포트가 보이지 않으니 데이터 케이블을 쓴다.
  보드를 USB 와 외부 전원에 동시에 연결해도 되는지는 보드 회로도로 먼저 확인한다.
- esptool 은 연결할 때마다 칩을 **리셋해 ROM 다운로드 모드**로 넣는다. 보드의 자동 리셋 회로(DTR/RTS → EN·부트 스트랩 핀)나 ESP 내장 USB-Serial/JTAG 리셋을 쓴다.
  실행 중이던 펌웨어가 멈추고 기기가 재부팅된다. 제품(카메라·IoT 기기) 안의 ESP32 면 제품 전체가 재부팅되므로 사용자에게 미리 알린다.
- 덤프가 끝나면 기본(`after="hard-reset"`)으로 앱이 다시 실행된다. `after="no-reset-stub"`(`after="no-reset"` 요청도 이것으로 실행)이거나 덤프를 취소했으면 칩이 다운로드 모드에 남으므로, 일반 부팅이 필요하면 사람이 RESET 을 누른다.
- 방법 A(Windows esptool.exe)에서 취소·시간 초과 뒤 esptool.exe 가 남았다고 에이전트가 알리면(PID), 사람이 작업 관리자나 Windows 터미널의 `taskkill /F /PID <PID>` 로 끝내거나 보드 USB 를 뽑았다 꽂는다. 그동안 그 COM 포트는 쓸 수 없다.
- 자동 리셋이 안 되는 보드는 사람이 BOOT(부트 스트랩 핀. ESP32·ESP32-S2·ESP32-S3 는 GPIO0, ESP32-C3·C6·H2 는 GPIO9 — 그 밖의 칩은 데이터시트로 확인)를 누른 채 RESET(EN)을 눌렀다 떼고 BOOT 를 놓아 다운로드 모드로 넣는다.
  그 뒤에 에이전트가 `before="no-reset"` 으로 호출한다.
- 같은 포트를 연 시리얼 모니터(Arduino IDE, `idf.py monitor`, PuTTY)는 먼저 닫는다.
- 보드에 헤더를 달아 UART0(TX/RX/GND)·부트 스트랩 핀·EN 을 직접 배선할 때는 §2.2 와 같다: 3.3V 로직이고 어댑터 VCC 는 연결하지 않는다.
- esptool 의 플래시 쓰기·삭제와 espefuse(eFuse 굽기, 되돌릴 수 없음)는 칩을 영구히 바꾼다. PWEH 는 이 명령들을 실행하지 않는다(§3.3).

## 3. 소프트웨어 안전: 서버 측 게이트

### 3.1 위험도와 기본 정책

| 위험도 | 예 | 기본 정책 |
|---|---|---|
| OBSERVE | 포트 목록, 수신 버퍼 읽기, 로직 캡처 | 허용 |
| INTERACT | `printenv`, `md.b`, `sf read`(RAM 으로만), `crc32`, `cat /proc/mtd`, `scan_chain`, `mdw` | 허용 |
| MODIFY | `setenv`(저장 안 함), `boot`, `reset`, `halt`, DTR/RTS 토글, 서비스 시작, JTAGulator 스캔, 결과를 저장하는 `crc32 <주소> <크기> <대상>`, `/dev/watchdog`·`/dev/mem` 읽기, `/tmp` 같은 일반 파일 쓰기, esptool 연결(리셋 → ROM 다운로드 모드 + RAM 스텁: `flash-id`, `get-security-info`, `read-flash`) | 허용 (`safety.modify_policy`) |
| DESTRUCTIVE | `saveenv`/`env save`, `sf erase/write/update`, `nand erase/write`, `mw`/`cp`(대상 주소와 무관 — 플래시가 메모리에 매핑된 SoC 가 있다), `flash_erase`, `dd of=/dev/mtd*`, 영구 파티션·시스템 디렉터리(`/bin`, `/etc` …) 파일 쓰기, 시스템 디렉터리 밖 실행 파일 실행(`./x`, `/tmp/x`), `PATH`/`LD_PRELOAD` 변경, OpenOCD `flash write_image`/`mww`/`load_image`/`program_esp`, eFuse/OTP, JTAGulator 전압 설정, esptool `write-flash`/`erase-flash`·espefuse·`--after no-reset`/`soft-reset`(pweh-esp 는 정책과 무관하게 거부, §3.3) | **거부** (`safety.destructive_policy: deny`) |

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
pweh-esp 도 같다. esptool 의 쓰기·삭제·eFuse·RAM 실행 같은 DESTRUCTIVE argv 는 게이트에 넘기지 않고 `gate.via: "esp-policy"` 로 거부하므로
승인 레코드가 생기지 않고 `pweh approve` 로도 풀 수 없다(§3.3).

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
    전용 도구는 케이스 경로로만 쓴다. 호스트 파일을 쓰는 `profile <초> <파일>`(gmon 출력, 예전에는 MODIFY), 트레이스 출력 `<tpiu|swo> create|configure … -output <파일|:포트>`(`openocd.trace.output`),
    `tpiu config internal <파일>`(`openocd.tpiu.config.internal`)도 DESTRUCTIVE 다.
  - 숨은 실행 위치도 막는다: 옵션 뒤 `catch` 본문, `dict`/`loop` 본문, `-event` 핸들러, `-command` 접두(`lsort -command mww …`), `update`/`vwait`/`xtrace`/`curry`,
    `::mww`·`m\ww` 같은 이름 우회, `popen` 같은 Jim 호스트 탈출.
  - `switch` 는 Jim 규칙대로 나눠 한 단어 목록 안의 본문까지 분류한다(`switch a {a init}`, `switch echo {echo {arm semihosting enable}}` — 예전에는 목록 전체를 한 스크립트로 읽어 놓쳤다).
    목록이 동적이면(`switch x "x $y"`) DESTRUCTIVE 다(`openocd.local.switch-dynamic-body`). `apply` 람다 본문도 본문으로 분류한다.
    `-command` 는 줄임말(`lsort -c`)도 같고, 명령 접두에 데이터가 덧붙어 실행되는 호출을 실제로 만들어 분류한다 — `lsort -command esp32 {flashbootstrap 1.8}` 은
    `esp32 flashbootstrap 1.8` 기준 DESTRUCTIVE. 덧붙는 값이 동적이거나 후보가 많으면 DESTRUCTIVE 다(`openocd.local.command-prefix-dynamic`).
  - OpenOCD 훅 변수 `post_init_commands`(init 끝)·`pre_shutdown_commands`(종료 직전)의 원소는 eval 된다. 그래서 `lappend`/`set`/`append`/`lset` 로 넣는 값을 스크립트로 분류한다
    (변수 이름이 동적이어도). `lappend pre_shutdown_commands "mww 0 0"` 은 안쪽 `mww` 기준 DESTRUCTIVE 다 — 예전에는 INTERACT 로 통과해 `openocd_stop` 때 승인 없이 실행됐다.
  - 중괄호 없는 식의 치환(`expr $x`, `if [catch {halt}] …`)은 expr 가 결과를 다시 해석하므로 DESTRUCTIVE 다. 식은 항상 중괄호로 감싼다(`expr {1 + 2}`, `if {[catch {halt}]} …`).
  - 서버가 끈 telnet/GDB 명령 서버를 다시 여는 `telnet port N`·`gdb port N`·`-gdb-port N` 은 DESTRUCTIVE 다. 그 포트로 들어온 명령은 게이트를 거치지 않기 때문이다.
  - 점 없는 타깃 이름 뒤의 위험한 하위 명령(`cpu0 mww …`)은 DESTRUCTIVE 다. 서버가 만드는 `<타깃> read_memory …` 는 `target names` 로 확인한 타깃만 쓰고,
    명령 이름과 같은 타깃 이름(`mww`, `reset` …)은 거부한다.
  - `openocd_start` 의 사용자 cfg 는 내용 전체를 분류하고(1 MiB 초과는 거부) 승인 지문에 sha256 을 넣는다. 승인 뒤 바뀐 cfg 는 실행되지 않는다.
    사용자 cfg 안의 init 계열 명령(`init`, `target init` 같은 하위 init, `jtag arp_init`, `post_init_commands` 수정)은 DESTRUCTIVE 다(`openocd.local.init-before-guard` — 아래 semihosting 가드보다 먼저 init 이 돈다).
  - semihosting 을 켜는 명령은 DESTRUCTIVE 다(`openocd.local.semihosting`). 켜지면 타깃 펌웨어가 분석 PC 의 파일을 열고 쓰고 지우며 `SYS_SYSTEM` 으로 호스트 명령까지 실행할 수 있다.
    `arm semihosting`·`arm semihosting_fileio` 뒤의 값이 끄는 값(`disable`/`off`/`false`/`no`/`0`)이 아니거나 변수·명령 치환이면 켜는 것으로 본다.
    OpenOCD 는 값을 대소문자 없이 해석하므로 `arm semihosting on`, `arm semihosting ENABLE`, `arm semihosting $x` 모두 켜진다. 조회(`arm semihosting`)와 끄기는 MODIFY 다.
    semihosting 을 켜는 핸들러를 다시 설치하는 ESP 표준 proc `configure_event_examine_end`·`configure_openocd_events`·`create_esp_target`(`openocd.esp.semihosting-proc`),
    이름에 `semihost` 가 든 명령(`openocd.semihosting-proc`), 세션의 OpenOCD 에서 가드가 찾은 semihosting proc(본문에 `semihost` 가 있거나 그런 proc 을 부르는 proc, 전이적 —
    `openocd.local.semihosting-proc`) 호출도 DESTRUCTIVE 다.
  - `openocd_start` 는 semihosting 을 **항상 꺼 둔 채** 끝내고, 시작 뒤에도 꺼져 있는지 계속 확인한다(Tcl 가드 `pweh_semihosting_guard`). 표준 cfg 는 내용을 분류하지 않는데, xPack `target/esp_common.cfg` 는 ESP32 계열 타깃의 `examine-end` 핸들러에서 `arm semihosting enable` 을 실행한다.
    - 감쌀 핸들러: 본문에 `semihost` 가 있거나 semihosting proc 이름이 든 타깃·TAP 이벤트 핸들러. `try {원래 본문} finally {모든 타깃 중 켜진 것을 끔}` 으로 감싼다(다른 타깃을 켜는 핸들러도 끝나면 꺼진다. 관련 없는 핸들러는 그대로).
    - 단계: ① pre-init(모든 cfg·`extra_commands` 뒤, init 직전) — `[command mode]` 가 `config` 가 아니면 init 이 이미 돈 것이라 실패, 아니면 핸들러를 감싼다.
      ② post-init(init 직후, TCL 포트가 열리기 전) — init 중(init_board/init_targets) 설치된 핸들러와 TAP 핸들러까지 다시 감싸고, 타깃마다 조회해 켜져 있으면 끈다.
      ③ verify — 연결 직후 TCL RPC 로 반드시 다시 확인한다(가드가 전역 변수에 남긴 기록을 받으므로 로그 형식과 무관. 로그 표식은 `-d3` 이상의 `handle_echo(): ` 접두도 읽는다).
      ④ check — MODIFY 이상 `openocd_command`, `openocd_halt`/`openocd_resume`/`openocd_reset`, `openocd_write_memory`/`openocd_flash_write` 뒤마다 다시 감싸고 끈다(응답 `semihosting_reneutralized`).
      ⑤ status — `openocd_status` 의 읽기 전용 확인(`semihosting_live`. 위반이 보이면 그 자리에서 check).
    - 확인할 수 없거나(가드 없음·결과 불완전), init 이 가드보다 먼저 돌았거나, 감싸기·끄기에 실패하면 OpenOCD 를 끄고 `start_failed` 로 끝낸다
      (`reason`: `semihosting-verification-failed`·`init-before-semihosting-guard`·`semihosting-neutralization-failed`). 시작 뒤 check 가 실패하면 OpenOCD 를 종료하고
      (`status: "semihosting_failsafe"`) 그 뒤 기기 명령을 거부한다. 꺼졌다고 확신할 수 없으면 실행하지 않는다(fail-closed).
    - 그래서 init 은 가드 뒤에 서버가 실행한다. `extra_commands` 의 init 계열 명령(`init`, `target/transport/jtag/dap/flash init` 등, `jtag arp_init`, `post_init_commands` 수정 —
      catch·eval·따옴표 본문, switch 목록 안 본문, apply 람다, proc 본문, defer, subst 의 `[…]`, `-command` 접두 안 포함)은 `validation_failed` 다. init 을 직접 실행하는 표준 cfg 는 시작에 실패한다.
    - 정적 검사가 못 찾는 init(신뢰 cfg 끝의 `init`, 신뢰 cfg 의 proc 이 부르는 init, 승인된 동적 형태)에 대비해 `-f` 하나하나와 `extra_commands` 하나하나 바로 뒤에서
      init 조기 실행을 검사한다(`[command mode]` 가 `config` 가 아니면). 걸리면 모든 타깃의 semihosting 을 바로 끄고 OpenOCD 를 오류로 끝낸다(시작 `-c` 의 오류는 뒤의 `-c` 를
      실행하지 않는다 — 실측) → `start_failed`(`init-before-semihosting-guard`). 그래서 init 을 먼저 실행한 cfg·명령 뒤의 시작 명령은 semihosting 이 켜진 채 실행되지 않는다.
    - 사람이 승인한 DESTRUCTIVE 명령이 semihosting 을 켜고 성공하면 그 세션은 `openocd_stop` 까지 끄지 않고 상태만 보고한다(`enabled-by-approval`).
  - 알려진 하위 명령 그룹(`flash`, `nand`, `arm`, `jtag`, `esp` …)의 하위 명령 자리가 변수·명령 치환이면 실제 하위 명령을 확정할 수 없으므로 DESTRUCTIVE 다
    (`openocd.local.dynamic-subcommand` — `flash [string cat erase_sector] 0 0 last`).
  - 플래시 프로그래밍 proc: 업스트림 `program` 과 Espressif 포크의 `program_esp`·`program_esp_bins`(예전 `program_esp32`)는 DESTRUCTIVE 다(`openocd.flash.program_esp`).
    reset init 뒤 플래시를 지우고 쓰기 때문이다. 그 밖의 `program_*` 이름도 같은 계열로 보고 DESTRUCTIVE 다(`openocd.flash.program_proc`).
  - Espressif `esp`·Xtensa `xtensa` 하위 명령 표: 호스트 파일·TCP 로 기록하는 `esp apptrace`·`esp sysview`·`esp sysview_mcore` 의 `start`/`dump`, 타깃 펌웨어가 정한 경로·모드로 호스트 파일을 여는 `esp gcov`,
    `xtensa tracedump`, 임의 명령어를 실행하는 `xtensa exe` 는 DESTRUCTIVE 다. 플래시 전압 스트랩 `<칩> flashbootstrap <값>` 도 DESTRUCTIVE 다(`openocd.esp.flashbootstrap` — 1.8V 플래시에 3.3V 를 주면 손상될 수 있다).
    이 규칙은 바로 앞 단어가 ESP 칩 그룹(`esp32`, `esp32s2`, `esp32s3`, `esp32c3` …)일 때만 적용하고 일반 표·명령 규칙도 그대로 적용해 더 위험한 쪽을 쓴다
    (`program flashbootstrap`·`flash write_image flashbootstrap`·`load_image flashbootstrap` 은 DESTRUCTIVE 그대로). 값 없는 조회 `esp32 flashbootstrap` 은 알 수 없는 명령 기준(기본 MODIFY)이다.
    타깃에서 스텁을 돌리는 검증·설정(`esp verify_bank_hash`, `esp flash_stub_clock_boost`, `esp compression` …)은 MODIFY, `esp apptrace status` 는 INTERACT 다.
    표에 없는 `esp`·`xtensa` 하위 명령은 점 없는 타깃 이름의 명령처럼 분류한다. cfg 가 `esp` 라는 타깃을 만들었을 수 있기 때문이다(`esp mww …` → DESTRUCTIVE).
- **ESP32 (esptool, pweh-esp)**
  - 실행하는 esptool 명령은 셋뿐이다: `flash-id`(칩·플래시 정보), `get-security-info`(보안 설정), `read-flash`(덤프 — 출력은 케이스 `dumps/` 안의 서버 예약 경로만, `esp.read-flash`).
    서버가 검증한 인자로 argv 를 직접 조립하고, 실행할 argv 그대로를 `esp_mcp.policy` 로 분류한다. 원시 esptool 인자를 받는 도구는 없다.
  - 셋 다 MODIFY(기본 허용)다. esptool 은 연결할 때 DTR/RTS 또는 USB-Serial/JTAG 리셋으로 칩을 ROM 다운로드 모드에 넣고 RAM 에 플래셔 스텁을 올리며,
    SPI 플래시에 리셋 명령을 보내고 끝나면 다시 리셋한다. 기기가 재부팅되지만 모두 전원을 껐다 켜면 사라지는 변화다. 플래시·eFuse 에 쓰는 명령은 보내지 않는다.
    `modify_policy: approve` 면 도구 호출마다 승인을 받는다(덤프는 호출 한 번의 승인이 이중 읽기 두 번을 덮는다).
  - 끝날 때 FLASH_BEGIN 을 보내는 `--after no-reset`·`--after soft-reset` 은 쓰지 않는다. 레거시 스텁(esptool 4.8~5.2 의 기본, `ESPTOOL_STUB_VERSION=1`)은 FLASH_BEGIN 때
    SPI 플래시 상태 레지스터를 다시 써 쓰기 보호를 푼다(비휘발성). `--chip auto` 는 칩에 남은 스텁을 `--no-stub` 이어도 스텁으로 다루므로 서버는 `after="no-reset"` 을
    항상 `no-reset-stub` 으로 바꿔 실행하고(응답 `after`·`after_requested`), 이중 읽기의 1차 읽기도 `--after no-reset-stub` 이다. `soft-reset` 은 `validation_failed` 다.
    실행하는 `--after` 는 `hard-reset`·`no-reset-stub`·`watchdog-reset`(esptool v5, v4.12 이상)뿐이다.
  - 그 밖의 모든 것은 DESTRUCTIVE 로 보고 게이트에 넘기지 않고 바로 거부한다(`status: "denied"`, `gate.via: "esp-policy"`).
    - 플래시 쓰기·삭제: `write-flash`, `erase-flash`, `erase-region`, `write-flash-status`(`esp.cmd.flash-write`).
    - RAM 적재·실행과 임의 메모리 접근: `load-ram`, `run`(`esp.cmd.ram-exec`), `write-mem`(`esp.cmd.mem-write`), `read-mem`·`dump-mem`(`esp.cmd.mem-read` — 임의 MMIO 읽기는 부작용이 있을 수 있다).
    - 이 서버 범위 밖: `merge-bin`·`image-info`·`elf2image`(`esp.cmd.offline`), espefuse·espsecure·rfc2217 서버 실행 파일(`esp.exe.forbidden` — eFuse 는 되돌릴 수 없다), 모르는 명령·옵션(`esp.cmd.unknown`, `esp.opt.unknown`).
    - 위험한 인자: `@파일` 인자(`esp.argv.unparsed`), 포트를 주지 않아 모든 포트를 훑는 호출(`esp.port.missing`), 검증한 포트와 다른 포트(`esp.port.mismatch`),
      `--connect-attempts 0`(무한 재시도, `esp.opt.value`), 케이스 `dumps/` 밖 출력(`esp.output.outside`),
      `--after no-reset`(`esp.after.no-reset`)·`--after soft-reset`(`esp.after.soft-reset`) — 위의 FLASH_BEGIN.
    - `--no-stub` 과 `--chip esp8266`·`--chip auto`(`esp.nostub.esp8266`): ESP8266 ROM 에는 플래시 연결 명령이 없어 esptool 이 대신 FLASH_BEGIN(0, 0) 을 보낸다.
      위와 같은 위험이고(하드웨어 미확인) `auto` 는 ESP8266 일 수 있다. 인자 검증도 `no_stub=True` 면 ESP8266 이 아닌 칩을 `chip` 으로 명시하게 한다.
  - 승인 레코드가 생기지 않으므로 `destructive_policy: approve` 여도 실행할 방법이 없다(`pweh approve` 로도 풀 수 없다). 다른 인자·다른 도구로 바꿔 시도하지 않고 사용자에게 보고한다.
  - Secure Download Mode 면 ROM 로더가 플래시 읽기를 거부한다(`read_flash_possible=false`, `esp_secure_download_mode`). 플래시 암호화가 켜져 있으면 덤프는 암호문이다(`ciphertext_expected=true`).
    둘 다 우회하지 않는다(글리칭, eFuse 조작, 다른 도구로 다시 읽기 시도 금지). 사실대로 사용자에게 보고한다.
  - 백그라운드 덤프는 esptool 을 띄우기 직전마다 argv 를 다시 분류하고(`esp.read-flash` 가 아니면 중단) 케이스 소유/허가를 다시 확인한다.
    `dumps/` 가 심볼릭 링크로 바뀌었거나 실제 경로가 계획 때와 다르면 멈춘다(`safety_denied`).
    같은 포트는 한 번에 한 작업만 쓰고, 다른 프로세스(시리얼 모니터, uart-mcp 세션)가 연 리눅스 tty 와, 그 COM 포트를 인자로 받은 Windows esptool.exe 가 남아 있는 포트는 `busy` 로 거부한다.
  - 실행 환경: esptool 은 실행마다 새 디렉터리에서 돌고, 그 안의 빈 `[esptool]` 설정을 `ESPTOOL_CFGFILE` 로 가리킨다. 그래서 홈(`~/.config/esptool`, Windows
    `%USERPROFILE%\AppData\Local\esptool`)의 설정을 읽지 않는다(esptool 5.3.1 이하는 설정의 `custom_reset_sequence` 를 코드로 실행한다). 리눅스는 `ESPTOOL_*` 를 지우고
    HOME 을 그 디렉터리로 바꾸며, Windows esptool.exe 는 Windows 쪽 사용자 환경변수를 물려받으므로 WSLENV 로 `ESPTOOL_*` 중립값을 넘겨 덮어쓴다.
    다른 설정 파일을 읽었다는 줄이 보이면 즉시 끝낸다(`esp_foreign_config`).
  - 취소·시간 초과·서버 종료: Windows esptool.exe 는 PyInstaller onefile 이라 WSL interop 프로세스를 끝내도 자식이 COM 포트를 잡은 채 남는다(실측).
    서버는 Windows 프로세스 목록에서 자식부터 끝내고 남은 것이 없을 때만 취소로 보고한다. 남으면 `esp_orphan_process`(PID)로 알리고, 사람이 끝낼 때까지 그 포트는 `busy`,
    덤프의 숨은 예약 파일도 남긴다. 덤프 경로의 Windows 경로 요소가 '.'·공백으로 끝나면 거부한다(Windows 가 끝의 '.' 을 지워 다른 디렉터리에 쓴다. case_id 도 '.' 으로 끝날 수 없다).
    서버가 SIGKILL 로 죽어 정리하지 못해도, 덤프의 출력 UNC 경로를 첫 esptool.exe 실행 전에 소유 표식에 적어 두므로 다음 서버는 그 경로를 명령줄에 가진 esptool.exe 가
    남아 있는 동안 예약 파일을 지우지 않는다. 이때 남는 `%TEMP%\_MEI*` 압축 해제 디렉터리는 막을 수 없다.
- **JTAGulator · sigrok**
  - JTAGulator UART 스캔 프로브는 대상 콘솔이 여러 번 받으므로, 두 번 이어 붙인 형태까지 콘솔 분류기로 검사한다(`_erase X\rflash` → `flash_erase X`).
    `jtagulator_connect` 는 장치 경로·`socket://`·`rfc2217://` 형식만 받고 포트를 exclusive 로 열어, 다른 세션이 쓰는 대상 콘솔에 재동기화 키를 보내지 않는다.
  - sigrok 디코드는 sigrok-cli 를 띄우기 직전에 오프라인 명령인지 다시 확인한다.

### 3.4 위협 모델과 한계 (정직하게)
- 이 게이트는 **협조적이지만 성급한 에이전트의 실수**를 막는 장치다. 같은 OS 계정으로 셸을 쓸 수 있는 적대적
  에이전트를 완벽히 막는 샌드박스는 아니다. 예를 들어 에이전트가 직접 시리얼 포트를 열거나, 승인·증명 파일이나 출처 원장을 위조하거나,
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
  - OpenOCD semihosting 무력화는 `openocd_start` 로 띄운 프로세스(와 가드 proc 이 있는 입양한 프로세스)에만 한다. `openocd_attach` 로 붙은 외부 OpenOCD(사람이 띄운 것)는
    건드리지 않으므로, ESP32 계열 표준 cfg 로 띄웠다면 `<타깃> arm semihosting` 으로 상태를 확인한다.
    `semihost` 라는 글자 없이(문자열 조립·변수·`eval`) 켜는 핸들러·proc 은 감싸기·DESTRUCTIVE 분류 대상이 아니어서 명령 뒤 확인과 init 직후 확인만 끈다 —
    그 사이(명령 실행 중, 확인 전의 백그라운드 폴링)에는 켜져 있을 수 있다. 핸들러가 켠 뒤 같은 핸들러 안에서 오래 기다리면(`sleep`) finally 가 돌기 전까지 켜져 있다.
    proc 본문 전체의 위험도로 호출을 분류하지는 않는다(semihosting 관련 이름의 전이적 검사만). 사람이 승인해 켠 세션은 `openocd_stop` 까지 끄지 않는다.
    init 을 직접 실행하는 표준 cfg(`board/sifive/hifive1.cfg`, `board/mini2440.cfg`, rescue 모드 `target/rp2040.cfg` 등)는 `init-before-semihosting-guard` 로 시작이 실패한다.
    init 조기 실행 검사는 init 을 실행한 그 cfg 파일·그 `extra_commands` 항목이 끝난 뒤에 돈다. 그래서 init 을 실행한 신뢰 cfg 파일의 나머지 줄(신뢰 경계 안)과,
    init 을 실행한 `extra_commands` 항목 하나의 나머지(같은 `-c` 안 `;` 뒤 — 정적 검사를 피하고, DESTRUCTIVE 면 사람 승인까지 받은 경우만)는 semihosting 이 켜진 채 실행될 수 있다.
  - pweh-esp: 분류기는 argv 만 본다. 실행 파일은 설정(`tools.esptool`, `tools.esptool_win`)이 가리키는 것을 믿는다(이름이 espefuse·espsecure 면 거부).
    포트 잠금은 서버 프로세스 안에서만 유효하다. 리눅스 tty 를 연 다른 프로세스는 `/proc` 를 훑어 찾으므로(최선 노력) 다른 계정의 프로세스는 보이지 않을 수 있다.
    Windows COM 포트는 그 포트를 인자로 받은 esptool.exe 만 미리 찾는다(Windows 프로세스 명령줄). 다른 프로그램이 잡고 있으면 esptool 이 `esp_port_busy` 로 실패한다.
    powershell.exe 가 실패하면 이 확인과 취소 뒤 남은 esptool.exe 확인이 약해진다(포트 확인은 기록만 하고 진행, 취소는 경고와 함께 cancelled).
    Windows exe 쪽에서는 WSLENV 가 빈 값을 넘기지 못해 IDE 웹소켓 로그 변수(`ESP_IDE_WS`)와 esptool 4.8.1 의 `ESPTOOL_TESTING` 을 중립화하지 못한다(기기 동작과는 무관).
    덤프의 MODIFY 연결(리셋·스텁)은 job 안에서 읽기마다 다시 일어나고, 승인은 도구 호출에 한 번이다.
- Claude Code 사용자는 보조 장치를 추가로 얻는다.
  - 항상 파괴적인 도구 세 개(`openocd_flash_write`, `openocd_write_memory`, `jtagulator_set_voltage`)에만
    `anthropic/requiresUserInteraction` 메타가 붙어 bypass 모드에서도 매번 확인을 띄운다. 다른 도구의 위험은 서버 게이트가 판단한다.
  - `.claude/settings.json` 의 `ask` 규칙도 bypass 모드에서 동작한다. 대상은 원시 쓰기(`uart_write`), DTR/RTS·BREAK
    (`uart_set_signals`, `uart_send_break`), 원시 TCL(`openocd_command`), 위 세 파괴적 도구, 그리고 REA 의 런타임·기기 도구
    (프로세스·디버거·Frida·Cutter·앱·브라우저 세션을 시작·조작·종료하는 도구, adb 기기에 쓰기·설치·실행하거나 파일·화면을 가져오는 도구,
    Rizin 셸 탈출(`!`)로 호스트 명령까지 실행할 수 있는 `execute_rizin_command`)다.
  - `allow` 규칙은 기본 모드에서 묻지 않을 도구다(bypass 모드에서는 의미가 없다): pweh 서버의 `readOnlyHint` 도구,
    `pweh-case`·`pweh-fwtriage` 전체, REA 정적 분석 도구.

### 3.5 사람 증명(attestation)과 출처 원장(provenance), 보호 상태

- **사람 증명**은 에이전트가 확인할 수 없는 사실을 사람이 직접 답한 기록이다(콘솔 오프라인, 결제 수단 제거, 배선과 멀티미터로 잰 전압, 태그의 목적·소유,
  쓰기 방지 장치 사용, 가져온 파일의 출처 …). 증명을 요구하는 도구는 지금 `fw_patch_build` 하나다(세이브 쓰기 명령을 보여 주기 전 — 네트워크 차단·재부팅 없음·변경 의사·판매 토큰 콘텐츠 아님). 요약·질문의 제어 문자는 이스케이프해 보여 준다.
  서버가 `status: "attestation_required"` 와 `attestation_id` 를 돌려주면, 사람이 **별도 터미널**에서 `pweh attest <id>` 를 실행해
  종류·대상·바인딩을 확인하고 항목마다 y/n 또는 직접 잰 값을 입력한다. 승인이 되는 답이면 화면의 4자리 확인 코드도 입력한다(대화형 터미널 전용).
  클라이언트가 elicitation 을 지원하면 같은 항목이 확인 폼으로 뜬다(4자리 확인 코드. 폼을 거절·취소하면 거부로 기록된다).
  증명 뒤 에이전트가 같은 도구를 같은 인자로 다시 호출하면 서버가 증명을 찾아 쓴다.
  - 승인과 달리 소비되지 않고, 대상·바인딩(케이스, 연결, job, 계측기)·만료에 묶인다. `pweh attest --list` 로 보고 `pweh attest --revoke <id>` 로 철회한다.
  - 이름이 비슷한 `pweh case attest <case_id>` 는 케이스의 소유/허가 증명이다(다른 명령).
  - 서버는 `.pweh/state/attestations/` 의 레코드만 증거로 본다. 에이전트가 넘긴 `attested_*` 인자, 케이스 파일,
    `cases/<id>/attestations.json`(사람이 보는 읽기 전용 사본 — 보고서 생성기는 아직 읽지 않는다), 승인 id 는 증거가 아니다. 서버가 확인 항목을 늘리면 예전 증명은 쓰이지 않고 다시 묻는다. 증명을 결정하거나 조회하는 MCP 도구는 없다.
- **출처 원장**(`.pweh/state/provenance/<case_id>.jsonl`)은 기기 읽기 코드 경로가 쓴 산출물(device-read — 지금은 끝까지 성공한 pweh-esp 덤프)과
  기기 사실(device-fact — `esp_chip_info`·`esp_security_info` 결과)을 해시 체인으로 남긴다. `case_import_file` 로 가져온 파일은 `imported-unattested` 다.
  출처가 중요한 작업(에뮬레이션·올리기·패치 base·계측기 플래시 절차)을 하는 서버는 가져온 파일을 사람의 `provenance-import` 증명이 있을 때만 쓴다(`fw_patch_build` 는 가져온 파일을 base 로 쓰지 않는다 — 기기에서 이중으로 읽은 덤프만).
  체인이 하나라도 깨지면 그 케이스의 출처 확인은 모두 실패한다(fail closed). 기록한 뒤 바뀐 파일도 신뢰하지 않는다. 출처 확인은 `case.json` 의 `producer` 를 보지 않는다.
  device-read 는 출처(기기에서 읽음)이지 무결성이 아니다 — 이중 읽기가 어긋난 덤프(`source.match=false`)는 기록하지만 출처 확인에서 신뢰하지 않는다(`device-read-mismatch`).
- **보호 상태**: `.pweh/state/` 의 `approvals/`, `attestations/`, `provenance/`, `salts/`, `audit.jsonl` 은 에이전트가 만들거나 고치거나 지우지 않는다.
  고치면 증명이 사라지거나(파일 삭제·체인 손상 → 불신) 위조가 된다. `case_import_file` 은 state_dir 안의 파일을 가져오지 않는다(케이스로 복사해 읽어 내지 못하게).
- **한계**: 해시 체인과 레코드 재확인은 실수와 단순 변조를 드러낼 뿐이다. 비밀 키가 없으므로 같은 OS 계정의 적대적 프로세스는 레코드를 처음부터 위조하거나,
  원장 전체를 일관되게 다시 쓰거나, 올바른 `prev` 를 계산해 끝에 줄을 덧붙이거나, 끝 줄을 잘라 낼 수 있다(잘라 내기는 신뢰를 줄일 뿐 만들지 못한다).
  강한 격리가 필요하면 §3.4 처럼 MCP 서버를 별도 OS 계정으로 실행하고 `.pweh/state` 쓰기 권한을 그 계정에만 준다.
  - 자동 허용(allow)된 REA 도구 중 `export_evidence_bundle(path, overwrite)`·`close_binary(snapshot_path, overwrite)` 는 임의 경로를 덮어쓸 수 있어
    `.pweh/state` 의 원장·증명·솔트·`audit.jsonl` 을 지울 수 있다. 내용은 REA 형식이라 위조는 되지 않고, 출처·증명 확인은 실패 쪽으로 닫힌다.
    덮어쓰기 전에 사람이 확인하게 하려면 이 둘을 `.claude/settings.json` 의 allow 에서 빼고 묻기(ask)로 둔다.
- **비밀값**: 게이트 작업 내용(승인 지문)에는 원문 대신 케이스 솔트 다이제스트(`sha256:<16 hex>`)나 `<given>` 만 넣으므로 감사 로그·승인 레코드·`approval_status` 에 원문이 남지 않는다.
  응답·보고서에는 마스킹(긴 값은 앞뒤 일부와 길이, 짧은 값은 길이만)만 싣는다.
  - 게이트에 비밀을 넣도록 설계된 도구는 `shell_login`(비밀번호 → `<given>`) 하나다. 비밀번호 프롬프트에 `uart_send_command` 로 입력하면
    원문이 게이트 작업 내용과 감사 로그에 남으므로 로그인은 `shell_login` 으로 한다.
  - 솔트(`.pweh/state/salts/<case_id>.key`, 0600)는 같은 OS 계정의 에이전트가 읽을 수 있다(파일 도구, 자동 허용된 REA `open_binary` + `read_bytes`).
    그래서 다이제스트는 보고서·감사 로그를 읽는 제3자에게서 원문을 가리지만, 에이전트에게서 낮은 엔트로피 값(짧은 PIN, 32비트 PWD_AUTH, 24–32비트 ID)을
    가리지는 못한다(솔트를 알면 전수 대입으로 되돌릴 수 있다). 그런 값은 게이트에 넣지 말고(`<given>`) 비대상 정보는 개수만 남긴다.
    에이전트에게서도 가리려면 §3.4 처럼 MCP 서버와 `.pweh/state` 를 별도 OS 계정으로 분리한다.

## 4. 에이전트 운영 규칙 (master-prompt 와 모든 Skill 에 반영)

1. 시작 전에 소유/허가를 확인한다. 확인되지 않으면 하드웨어 도구를 호출하지 않는다.
2. 물리 작업(배선, 전원, 클립)은 사람에게 **구체적으로** 요청하고, 사람이 완료를 확인한 뒤 진행한다.
3. `approval_required` 를 받으면 사용자에게 작업 내용, 위험, 되돌릴 방법을 설명한다. 승인은 사람이 한다.
   - 에이전트가 `pweh approve`·`pweh attest` 를 실행하지 않는다.
   - 에이전트가 `.pweh/state/` 의 승인(`approvals/`)·증명(`attestations/`)·출처 원장(`provenance/`)·솔트(`salts/`) 기록을 만들거나 고치거나 지우지 않는다.
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
11. ESP32 는 pweh-esp 의 읽기 도구(`esp_chip_info`, `esp_security_info`, `esp_read_flash_start`)로만 다룬다. 셸에서 esptool·espefuse 를 직접 실행하지 않는다.
    연결할 때마다 기기가 재부팅된다는 것을 사용자에게 알린다. Secure Download Mode(`read_flash_possible=false`)와 플래시 암호화는 우회하지 않고 보고한다.
   예외: 게임 세이브 패치는 `fw_patch_build` 가 검증된 새 백업과 사람 증명을 확인한 뒤 사람이 실행할 esptool 쓰기 명령을 보여 준다(§4 규칙 6, master-prompt §1 규칙 3).
   그 명령은 사람이 별도 터미널에서만 실행하고(쓰기 전에 패치 sha256 을 확인, 섹터 경계가 맞고 다른 영역과 겹치지 않는 파티션 범위만, erase·`--force` 없음), 에이전트는 실행하지 않는다.
   백업 뒤에 그 기기에 다시 연결하면(esp 도구는 연결마다 칩을 리셋한다) 서버가 백업을 낡은 것으로 보고 명령을 주지 않는다. 원장에 남지 않는 연결(같은 포트의 uart-mcp 등)은 서버가 알 수 없으므로 하지 않는다.
12. `attestation_required` 를 받으면 사용자에게 무엇을 직접 확인해야 하는지(물리 작업이면 그 작업도) 설명하고, 사람이 별도 터미널에서 `pweh attest <id>` 로 답하게 한다.
    에이전트가 사실을 대신 답하거나 `attested_*` 인자·케이스 파일로 증명을 대신하지 않는다. 거부(`denied`)면 우회하지 않고 보고한다.

## 5. 백업과 롤백

- **원칙: 쓰기 전에 읽는다.** 쓰기·삭제를 고려하기 전에 전체 플래시를 덤프하고 검증한다.
  - `uboot_dump_start` 는 청크마다 기기 측 crc32 를 비교한다.
  - `shell_dump_start` 는 청크마다 md5 를 비교한다.
  - 그 결과를 `dumps/` 에 sha256 과 함께 보관한다.
- 덤프는 가능하면 **두 번** 받아 sha256 이 같은지 확인한다 (UART 노이즈 대비).
  - `esp_read_flash_start` 는 기본(`verify="double"`)으로 두 번 읽어 sha256 을 비교한다(`verification.method: double-read`). 1차 읽기 뒤에는 앱을 실행하지 않는다(`--after no-reset-stub`).
- 원복 방법을 미리 정해 둔다.
  - U-Boot 의 `sf write` 로 RAM 에서 플래시로 쓰기 (DESTRUCTIVE, 승인 필요).
  - SPI 프로그래머로 직접 쓰기 (사람이 수행).
  - JTAG `flash write_image` (DESTRUCTIVE, 승인 필요).
  - ESP32 플래시는 pweh-esp 로 쓸 수 없다(쓰기 명령은 승인으로도 풀리지 않는다). 원복이 필요하면 사람이 PWEH 밖에서 직접 한다.
- 환경 변수만 바꾸고 싶다면 `setenv` 후 `boot` 로 **휘발성으로** 시험한다. `saveenv` 는 마지막 수단이다.

## 6. 비상 정지

| 상황 | 조치 |
|---|---|
| 에이전트가 잘못된 방향으로 진행 | 에이전트에게 중지를 지시. 진행 중 job 은 `uart_job_cancel` / `openocd_job_cancel` / `sigrok_job_cancel` / `jtagulator_job_cancel` / `esp_job_cancel` |
| 즉시 기기 조작을 끊어야 함 | **기기 전원을 뽑는다**. 또는 USB 어댑터를 뽑는다 (세션은 `disconnected` 로 표시됨) |
| ESP32 덤프를 멈췄는데 Windows 에 esptool.exe 가 남음(`esp_orphan_process`) | 작업 관리자나 Windows 터미널의 `taskkill /F /PID <PID>`(오류의 `data.pids`)로 끝내거나 보드 USB 를 뽑는다 |
| MCP 서버 정지 | 에이전트 클라이언트를 종료하거나 `/mcp` 에서 서버를 끈다. 서버 종료 시 세션과 job 이 정리된다 |
| 승인 대기 취소 | `pweh deny <approval_id>` |
| 잘못 답했거나 더는 맞지 않는 사람 증명 | `pweh attest --revoke <attestation_id>` (대기 중이거나 승인된 증명을 철회. 그 증명에 기대던 동작은 다시 증명을 요청한다) |
| 과열·타는 냄새·연기 | 즉시 전원 차단, 작업 중단, 보드 점검 |

## 7. 데이터 취급

- 덤프한 펌웨어에는 자격증명, 개인키, 클라우드 토큰, Wi-Fi 비밀번호, 녹화 영상 일부, 개인정보가 들어 있을 수 있다.
  `cases/` 는 git 에서 제외되어 있다 (`.gitignore`). 외부에 공유할 때는 민감 정보를 제거한다.
- 보고서에 실제 비밀번호나 키를 그대로 싣지 않는다. 해시 일부 또는 마스킹된 형태로 싣는다(게이트·감사 기록의 비밀값 규칙은 §3.5).
- 기기 로그인 비밀번호는 이벤트 로그(`uart/*.events.jsonl`)에서 마스킹된다. 단 원시 수신 로그(`*.raw`, `*.log`)에는
  기기가 에코한 내용이 그대로 남을 수 있다.
- 제조사 펌웨어의 저작권을 존중한다. 덤프나 추출본을 재배포하지 않는다.
