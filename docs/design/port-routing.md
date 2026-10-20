# 설계안: 환경 감지와 물리 연결 라우팅 (COM·USB·libusb·캡처·블록 장치)

> 상태: **제안 (구현 전 검토용)**. 계약(`docs/architecture.md`)이 아니다. 개요는 [README.md](README.md), 공통 기반은 [common-core.md](common-core.md)(§2 가 이 문서의 요약).
> 이 설계를 쓰는 곳: [game-console-flipper-rf.md](game-console-flipper-rf.md)(Flipper·ChameleonUltra·입력 브리지 COM 포트, SDR·캡처 도구), [sd-forensics.md](sd-forensics.md)(블록 장치는 사람 단계 — §9 R18), [esp32-instrument.md](esp32-instrument.md)(계측기 COM 포트·식별 고정·역할 표지).
> 범위: COM·USB 직렬, libusb 장치, 영상 캡처, 블록 장치를 WSL2·WSL1·네이티브 Linux·macOS·네이티브 Windows 에서 감지·식별·열기·잠그는 방법.
> 근거: 개발 환경 의 읽기 전용 probe(2026-10-19), 저장소 코드(`파일:줄`, **2026-10-19 22:52 기준** — 직전에 들어온 uart `validate_port` 변경 반영),
> 1차 출처(usbipd-win v5.3.0·master, microsoft/WSL, Linux `tty_port.c`·`tty_io.c`, pyserial 3.5, CPython `posixmodule.c`, Apple IOSerialFamily, MS Learn, OpenOCD v0.12.0).
> 초안을 두 관점(코드·계약 일관성 27건, 플랫폼 사실 29건)으로 적대적 검증했고, 부분 수정·반박 27건과 누락 6건을 반영했다.
> 신뢰도: [높음] 출처 원문·실측, [중간] 간접 근거·추론, [미확인] 확인 안 함. 포트·USB 장치·디스크는 하나도 열지 않았다(직접 만든 pty·abstract 소켓만).
> 도구별 바이너리·라이선스·sha256·설치 구성요소 표는 조사 노트에 있고 저장소에는 아직 없다(§13.4: `docs/references/` 로 옮김).

## 1. 요약과 원칙

검증에 쓴 개발 환경은 Windows 11 위의 WSL2(Ubuntu, interop 켜짐)다(정확한 버전·네트워킹 모드 같은 호스트 설정은 이 문서에 적지 않는다).
- 일반적으로 UAC 가 꺼진 관리자 계정 호스트에서는 interop 으로 띄운 Windows 프로세스가 관리자 권한(High IL)으로 돈다(sd-forensics §0).
- usbipd-win 이 없는 환경을 기준으로 삼았다(`C:\Program Files\USBip` 은 반대 방향인 usbip-win2 클라이언트일 수 있다). 에이전트에게 sudo 도 없다.
- 그런 환경에서 하드웨어에 닿는 경로는 **pweh-esp 방법 A(Windows esptool.exe + COMn) 하나뿐**이다 [높음 — probe, `pweh doctor --json`].
  uart·jtagulator·sigrok·openocd 는 usbipd attach 를 전제로 하는데, usbipd 가 없으면 쓸 수 없고 bridged 모드에서는 attach 마다 `--host-ip` 까지 필요하다.

원칙:

1. **라우팅은 (환경, 포트 참조, 용도)의 함수다.** 문자열만으로 정하지 않는다(지금 esp 방식, `esp_mcp/ports.py:3-9,69-95`).
   - `COM3` 은 WSL2+interop 에서는 헬퍼, WSL1 에서는 `/dev/ttyS3`(COM1–COM191 만)이고, 그 밖에서는 거부한다.
   - COMn 이 pyserial-posix 에 닿지 않게 한다. uart 는 이미 막는다(`uart_mcp/session.py:282-289`). jtagulator 는 아직 상대 경로 파일로 연다(G5).
2. **WSL2 + interop 의 기본은 "장치는 Windows 에 두고 Windows 쪽 프로세스가 연다"이다**(방법 A 의 일반화).
   - 직렬 장치는 `pweh-serial-helper.exe` 가, 도구형 장치는 Windows 판 도구가 연다. 드라이버 교체·LAN 노출이 없고 재열거에도 끊기지 않는다.
   - usbipd 는 사람이 고르는 대체 경로다.
3. **전송은 모두 stdio 파이프다.** PWEH 는 어떤 네트워킹 모드에서도 TCP 리스너를 만들지 않는다.
   - 네트워킹 모드는 usbipd 안내와 경고에만 쓴다.
   - bridged WSL 에서는 Windows 의 127.0.0.1 리스너에 닿지 않는다 [높음 — 실측: PowerShell `TcpListener(127.0.0.1)` 에 WSL 에서 접속하면 ConnectionRefused].
4. **열기 전에 잠그고, 연 뒤에는 OS 배타를 건다.**
   - portlock 은 `os.open` **전**에, OS 객체 키로, 호스트 전체(작업 공간·클론·WSL 배포판 공통)에서 잡는다(§6).
   - 연 뒤에는 POSIX 는 `TIOCEXCL` 을 건다. Windows 의 단일 열기는 드라이버 스택의 성질이다(공유 모드 0 은 여는 쪽의 요구 사항일 뿐 — §5.2).
   - 이유: 리눅스는 **모든** open 에서 DTR/RTS 를 올린다(§7) [높음].
5. **분류는 백엔드 위에서 한다.** 게이트·분류기의 위치는 지금 그대로이고 백엔드는 바이트만 나른다. 헬퍼에는 명령 모드가 없다.
6. **감지 결과는 추천일 뿐이다.** 열 때마다 조건을 다시 확인하고(fail closed), override 로 안전 규칙을 완화할 수 없다.
   운영 코드에는 감지·헬퍼 신뢰를 바꾸는 환경 변수가 없다(시험은 프로세스 안 주입 — §14).
7. **사람 단계는 사람이 한다.** 드라이버(Zadig·벤더), usbipd 설치·bind·attach, udev 규칙, brltty 처리, SD 이미징은 에이전트가 하지 않는다.
   interop 은 `wsl.exe -u root` 로 비밀번호 없는 root 가 되고, UAC 가 꺼진 호스트에서는 Windows 관리자이기도 하다. 그래서 PWEH 가 실행하는 Windows 실행 파일은 허용 목록으로 묶는다(§11) [높음 — MS Learn 의 비밀번호 재설정 절차 `wsl -u root`].

| 항목 | 지금 | 목표 |
|---|---|---|
| 환경 감지 | 서로 다른 WSL 감지 4개, macOS·Windows 감지 없음 | `pweh.hostenv` 하나 + `pweh env`·doctor·`pipeline_environment()` |
| 포트 해석 | esp 만 문자열 정규식, uart 는 문법 검사만 | `pweh.ports` 해석기(§4), 모든 장치 서버 |
| Windows COM | esptool.exe 만 | uart·jtagulator·(계획) flipper·nfc·play 도 헬퍼로 |
| 배타 | 프로세스 안 레지스트리 + 열고 나서 flock·`/proc` 검사(최선 노력), 키 형식 4종 | portlock(열기 전, OS 객체 키, 호스트 전체) + TIOCEXCL / 드라이버 단일 열기 |
| libusb 도구(WSL2) | usbipd 만(사람 단계 전부) | Windows 판 도구(P3) + usbipd 대체 |
| doctor | 가짜 `/dev/ttyS0-7` 을 OK 로 표시, usbipd 만 안내 | 환경 보고서 + 장치 종류별 추천 경로 + 모드별 usbipd 안내 |

## 2. 지금 코드의 빈틈 (이 설계가 고치는 것)

| # | 빈틈 | 근거 | 고치는 단계 |
|---|---|---|---|
| G1 | **(uart 는 해결됨 — 기록용)** `uart_open`·`uart_detect_baud` 가 모든 pyserial URL 을 받았다. `spy://…?file=` 는 포트 이름을 정하는 순간 호스트 파일을 덮어쓰고, `hwgrep://…&skip_busy` 는 다른 포트를 exclusive 없이 기본 DTR/RTS 로 연다(점유된 포트도 건너뛰지 못함). INTERACT 변형(`dtr=rts=False`, `probe="none"`)은 게이트가 항상 허용하므로 정책으로 못 막았다(DTR/RTS 를 켜거나 `probe="ctrl-c"` 면 MODIFY). 부작용은 authorize 뒤에 일어났다. 지금은 `validate_port` 가 게이트 전에 스킴 허용 목록, 비Windows COMn 거부, 문자 장치 검사를 한다. **남은 것**: socket·rfc2217 의 LAN 호스트(uart·jtagulator, D4), `_WIN_COM_RE` 상한 없음(COM9999 통과) | `uart_mcp/session.py:256-299,313`, `uart_mcp/server.py:392,408-411,816,829-833`; pyserial `serial/__init__.py:87-88`, `urlhandler/protocol_spy.py:186-187`, `protocol_hwgrep.py:71-79`, `serialutil.py:216-217`; `src/pweh/safety/gate.py:80-81` | P0(남은 것) |
| G2 | (새 발견) **거부되는 두 번째 opener 도 남이 잡은 포트의 DTR/RTS 를 올린다.** pyserial 은 `os.open(O_NONBLOCK)` 뒤에야 flock 을 시도한다. 커널은 open 마다 `tty_port_block_til_ready()` 를 부르고 `C_BAUD` 가 0 이 아니면 `tty_port_raise_dtr_rts()` 를 한다. 마지막 close 가 아니면 다시 내리지 않는다. 그래서 jtagulator 의 "uart 가 잡은 포트 거부", Linux esptool 5.4.0 의 자체 flock, hwgrep 모두 붙잡힌 선로를 건드린다. 게이트 시험은 pty 라 신호를 보지 못한다 | pyserial `serialposix.py:322`(open) → `:331`(reconfigure) → `:385`(flock), 실패 시 `:352`(close, 마지막 close 아님); [tty_port.c](https://raw.githubusercontent.com/torvalds/linux/master/drivers/tty/tty_port.c) `tty_port_open`·`tty_port_block_til_ready`·`tty_port_close_start`; `jtagulator_mcp/driver.py:125-139`; esptool `loader.py:443-453`; `tests/servers/test_jtagulator_gate.py:118-140` [높음 — 소스 / 실제 전기 변화는 드라이버별, 미확인] | P1 |
| G3 | 프로세스 사이 배타가 **열고 나서**이거나 최선 노력이고, 키 형식이 4종이다. uart·jtagulator 는 flock(G2 의 펄스 뒤), esp(Linux)·sigrok 은 `/proc` 검사(같은 계정만 보임). jtagulator 는 원문 문자열로 비교해 `COM3`≠`com3`, by-id 링크≠실제 경로가 된다. job 배타는 프로세스마다 따로다 | `uart_mcp/session.py:302-317`, `jtagulator_mcp/driver.py:130`, `jtagulator_mcp/server.py:303,707`, `esp_mcp/ports.py:79,89`, `esp_mcp/server.py:337-343`, `sigrok_mcp/server.py:134-135,382-388`, `src/pweh/jobs.py:152-160` | P1 |
| G4 | 점유 검사가 fail-open 이다. `/proc` 가 없으면 `[]` 를 돌려주고, PowerShell 이 실패하면 기록만 하고 진행한다 | `esp_mcp/ports.py:322-323`, `sigrok_mcp/policy.py:653-655`, `esp_mcp/server.py:346-349` | P1 |
| G5 | **(uart 는 해결됨)** COMn 이 pyserial-posix 에서 현재 디렉터리 기준 상대 경로 파일로 열린다. uart 는 이제 비Windows COMn 을 거부한다(힌트는 usbipd 만 — G8). **남은 것**: jtagulator 는 `COM\d{1,3}`(COM0·앞자리 0 도 통과)을 받아 그대로 연다. sigrok 은 COMn conn 의 존재를 검사하지 않는다 | `jtagulator_mcp/protocol.py:366`, `uart_mcp/session.py:282-289`, `sigrok_mcp/policy.py:279`, `sigrok_mcp/server.py:379-381` | P1 거부 → P2 헬퍼 |
| G6 | WSL 감지 4개가 서로 다르다. esp `is_wsl` 은 WSL 커널 위 컨테이너에서도 참이고, doctor 는 WSL1 도 "WSL2 감지"로 적는다. 컨테이너 제외, WSL1/2 구분, `wslinfo` 사용이 어디에도 없다. (binfmt `status` 를 보지 않는 것과 시험 유틸이 `WSLInterop-late` 를 모르는 것은 결함이 아니다 — §3.1 H4) | `esp_mcp/ports.py:103-126`, `scripts/install.sh:831-838`, `tests/servers/esp_testutil.py:45-50`, `src/pweh/cli.py:455-460` | P0 |
| G7 | powershell.exe 대체 경로와 cwd 에 `/mnt/c` 를 하드코딩했다. 대체 경로는 `which` 가 실패할 때(`appendWindowsPath=false`)만 쓰이고, `/mnt/c` 가 없으면 cwd 가 `None` 이 되어 UNC cwd 경고와 함께 돈다. 깨지지는 않고 성능이 떨어진다 | `esp_mcp/ports.py:207-215,223` | P0 |
| G8 | doctor 가 가짜 `/dev/ttyS0-7`(sysfs `type=0`, `serial-base` 버스 — pyserial 3.5 는 `subsystem=="platform"` 만 숨김)을 OK 로 표시하고, WSL 힌트는 usbipd 만이다(방법 A, 모드별 `--host-ip`, 관리자 bind, LAN 노출 없음). `uart_list_ports` 도 가짜 포트를 내놓는다. 힌트는 목록이 비었을 때만 나오므로 WSL 에서는 아예 안 나온다. uart 의 COMn 거부 힌트도 usbipd 만이다. doctor 의 esptool.exe 확인은 env.sh 의 `PWEH_ESPTOOL_WIN` 만 본다(설치본은 찾지만 설정 `tools.esptool_win`·esp 후보 목록은 무시). **선례**: `esp_list_ports` 는 `hwid=='n/a'` 이고 vid 가 없는 포트를 숨기고 센다(`hidden_legacy_ports`) | `src/pweh/cli.py:56-60,246-266,440-446,457-465`, `scripts/install.sh:947`, `uart_mcp/server.py:339-362`, `uart_mcp/session.py:285-289`, pyserial `tools/list_ports_linux.py:103`; 선례 `esp_mcp/server.py:718-719`, `tests/servers/test_esp_mcp.py:758` | P0 |
| G9 | 네이티브 Windows 에서 POSIX 전용 프로세스 제어가 깨진다. CPython `os.kill(pid, 0)` 은 Windows 에서 signal 0 = `CTRL_C_EVENT` 라 `GenerateConsoleCtrlEvent(CTRL_C_EVENT, pid)` 가 된다(TerminateProcess 가 아니다). 그룹 id 가 0 이 아니면 호출은 "성공"하지만 이벤트는 가지 않고, 콘솔이 없으면 `OSError` 다 → 생존 검사가 모든 pid 를 살아 있다고 보거나 예외를 낸다(죽이지는 않음). openocd `pid_alive` 는 읽기 전용 `openocd_status` 에서도 닿고 host 가드가 없다. esp 의 host 가드는 WSL·Windows 호스트 이름이 같으면(기본 설정) 구별하지 못한다. `killpg`·`getpgid`·`SIGKILL` 은 4곳에서 `AttributeError`, `/proc` 없는 점유 검사는 fail-open | CPython `Modules/posixmodule.c` `os_kill_impl`(3.12 l.8984-8994), MS Learn `GenerateConsoleCtrlEvent`; `openocd_mcp/process.py:348-381,407-421`(← `server.py:902,1062`), `esp_mcp/server.py:509-534`(가드 `:511`), `esp_mcp/esptool_cli.py:248-268`, `sigrok_mcp/cli.py:128-149`, `fwtriage_mcp/procutil.py:32-50` | P0(win32 시작 거부) + P1(코어 `procutil`) |
| G10 | uart 계약의 "DTR/RTS 를 열기 전에 False 로 두어 리셋을 피한다"는 리눅스에서 성립하지 않는다. 커널이 open 때 둘 다 올리고, pyserial 은 DTR → RTS 순서로 내린다. 그 사이 RTS 만 켜진 순간이 생겨 ESP 2-트랜지스터 자동 리셋 회로가 리셋된다. macOS 도 첫 open 에서 올린다(§7). `uart_detect_baud` 는 후보마다 포트를 다시 열어 펄스를 반복한다 | `docs/architecture.md:290`, pyserial `serialposix.py:335-338`, `uart_mcp/baud.py:62-70` [리셋 여부는 중간] | P1 |
| G11 | esp 는 macOS `/dev/cu.*` 를 거부하고, 네이티브 Windows 에서는 COMn 을 거부한다(WSL 게이트). `list_linux_ports` 는 Windows COM 을 `linux` 로 표시한다 | `esp_mcp/ports.py:28-30,296`, `esp_mcp/policy.py:136`, `esp_mcp/server.py:241-247` | P5 / 미지원 |
| G12 | openocd TCL 은 socket 전용이고 재연결 로직이 있다. 명시적 `bindto` 는 없지만 OpenOCD 기본 바인드가 루프백이므로 `architecture.md:365` 와 모순은 없다(`docs/references/openocd-tcl-rpc.md:96`, 빌드 4개 실측). 문제는 Windows `openocd.exe` 다. bridged WSL 은 Windows 루프백에 닿지 않고 LAN 바인드는 금지이므로 TCP 로는 제어할 수 없다 | `openocd_mcp/rpc.py:64-68,116-122,164-169`, `openocd_mcp/process.py:41,223-229` | P3 |
| G13 | 시뮬레이터를 `--host 0.0.0.0`·`--tcp 0.0.0.0:N` 으로 띄울 수 있다(기본값은 루프백). bridged 에서는 LAN 에 노출된다 | `src/pweh/mocktarget/cli.py:68`, `jtagulator_mcp/sim.py:1245-1250,1395` | P0 |
| G14 | `uart_open` 승인 지문은 `{port, baudrate, framing, dtr, rts}` 뿐이고 장치 식별이 없다. 같은 이름에 다른 장치가 꽂혀도 같은 승인이 통한다(실효는 `modify_policy=approve` 의 MODIFY 변형, 승인 TTL 안) | `uart_mcp/server.py:416-417` | P1 |
| G15 | 문서·안내가 코드·환경과 맞지 않는다. "WSL2 는 udev 가 동작하지 않음"은 systemd=true 인 개발 환경 에서 낡은 내용이다(PID1 systemd, systemd-udevd 동작). usbipd 만 안내하는 줄: uart Skill 39·328, 덤프 Skill 32·117·268, master-prompt 174·215(77행은 ESP32 방법 A 예외를 이미 적었다) | `docs/hardware-setup.md:97-102`, `skills/uart-shell-acquisition/SKILL.md:39,328`, `skills/firmware-dump-via-uart/SKILL.md:32,117,268`, `orchestrator/master-prompt.md:77,174,215` | 각 단계 |
| G16 | 설치·실행 스크립트가 리눅스 전용이다. bash 4(`declare -A`), `timeout`, `sha256sum`, apt 가 필요하고 POSIX venv 를 가정한다 | `scripts/install.sh:89,207-210,227-231,841`, `scripts/mcp-launch.sh:22-41`, `src/pweh/cli.py:283-294` | P5 |

## 3. 환경 감지 — `pweh.hostenv`

모듈 이름은 `hostenv` 다(common-core §1 의 옛 이름 `platform.py` 는 표준 라이브러리 `platform` 과 겹쳐 가림 위험이 있다).
esp 의 `is_wsl`·`interop_status`, install.sh 의 `wsl_interop`, 시험 유틸, doctor 의 감지는 모두 이 모듈을 쓴다(install.sh 는 hostenv 와 같은 감지 규칙에서 smoke 와 설정 override(`hostenv.disable`)를 뺀 것을 셸로 구현한다 — 컨테이너 제외, WSLInterop(-late) enabled, /init, `wslpath -w /`).
> I4 구현 메모: "wslpath 실행" 은 `wslpath -w /` 로 본다(C: 마운트는 Windows 쪽 경로를 찾는 데만 쓴다). 실패한 감지는 30 초 뒤 다시 보고(성공한 smoke 만 300 초 캐시), Windows 실행 파일은 실제 경로가 정확히 맞을 때만 실행한다.

### 3.1 결정 트리

```
H0  sys.platform
    win32  → NATIVE_WINDOWS (sysconfig.get_platform() 이 'mingw' 로 시작하면 MSYS2-MinGW CPython 표시)
             → 서버 시작 거부(§12). doctor 는 "WSL 에서 실행" 안내만
    cygwin → CYGWIN → 거부          msys → MSYS → 거부 (pyserial list_ports 가 ImportError)
    darwin → MACOS: platform.machine() arm64/x86_64, sysctl.proc_translated==1 이면 Rosetta → H9
    linux  → H1
H1  컨테이너? /.dockerenv | /run/.containerenv | 환경 변수 container | systemd-detect-virt -c ∉ {none, wsl}
    예 → CONTAINER. WSL 커널 문자열이 보여도 WSL 로 보지 않는다(WSL 안의 docker 는 흔하다).
         interop 없음, 통과된 /dev 노드만 → 최선 노력
H2  WSL 표지? 'microsoft' ∈ /proc/sys/kernel/osrelease(대소문자 무시) | /run/WSL 존재 | binfmt_misc/WSLInterop* 존재
         | /proc/cmdline 에 WSL_ROOT_INIT(WSL2 전용 — OR 항으로만)   (WSL_DISTRO_NAME 은 보조 — sudo·sshd·깨끗한 환경의 런처가 지움)
    아니오 → NATIVE_LINUX (VM 은 systemd-detect-virt -v, SSH_CONNECTION 이면 '물리 작업은 원격 기계' 경고) → H8
H3  WSL1/WSL2: osrelease '4.4.0-<build>-Microsoft' → WSL1 / '…-microsoft-standard[-WSL2]' → WSL2
    osrelease 로 못 정하면(사용자 커널) `wslinfo --networking-mode` 의 출력으로 정한다:
      'wsl1' → WSL1, 그 밖의 값 → WSL2, 0 이 아닌 종료·실행 불가 → WSL_UNKNOWN(버전 모름)
    ※ wslinfo 는 WSL1 에서도 돈다('wsl1' 출력). "wslinfo 가 있으면 WSL2" 는 틀린 규칙이다.
H4  interop 사용 가능 = (WSLInterop 또는 WSLInterop-late 첫 줄 'enabled') AND /init 존재 AND wslpath 실행 AND smoke 통과
    smoke(10 s, 300 s 캐시): powershell.exe -NoProfile -NonInteractive -Command "exit 0" (MS 서명).
      헬퍼가 실제로 뜨는지(--version)는 따로 본다 — SAC 는 서명 없는 헬퍼를 막을 수 있다(powershell.exe 는 MS 서명).
    binfmt_misc/status 는 참고 값이다. wsl.conf [boot] protectBinfmt=true(기본)면 tmpfs 그림자 파일이라 커널 상태가 아니다.
    cmd.exe·wsl.exe 는 쓰지 않는다(UNC cwd 경고·CP949 / 비밀번호 없는 root)
    실패 → WSL2_NO_INTEROP (WSL1·WSL_UNKNOWN 은 interop 플래그만 끔. Smart App Control·보안 제품이 막은 경우 포함)
H5  Windows 쪽 경로: wslpath -u 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    또는 /proc/mounts 의 drvfs 'path=C:\' (하드코딩 /mnt/c 금지)
    빌드 = [Environment]::OSVersion 의 major.minor.build + 레지스트리 UBR(HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion)
H6  네트워킹: wslinfo --networking-mode → nat | bridged | mirrored | consomme(옛 WSL 은 virtioproxy) | none | wsl1
    0 이 아닌 종료 = unknown. 이 값이 실제 모드다(.wslconfig 는 의도일 뿐). NAT 가 실패하면 WSL 2.3.25+ 는 조용히 consomme 로 떨어진다.
    usbipd 안내(§10)와 리스너 경고에만 쓴다(전송은 어떤 모드든 stdio)
H7  usbipd: usbipd.exe (PATH 또는 C:\Program Files\usbipd-win\) 의 '--version'·'state'·'policy list' 만.
    usbip.exe·wusbip.exe(usbip-win2 클라이언트, 반대 방향)는 usbipd 로 보지 않는다
H8  리눅스 장치 배관: PID1=systemd AND systemd-udevd active (by-id·dialout·모듈 자동 적재)
    그룹(dialout|uucp, plugdev, video — docker·disk 는 root 와 같다고 경고), /dev/bus/usb 노드 권한(stat 만),
    설치된 udev 규칙 이름, brltty(설치됐고 85-brltty.rules 가 1a86:7523 을 잡는지)
H9  macOS: /dev/cu.* 만 쓴다(tty.* 거부, §4.1). /proc 가 없으니 프로세스 점유 검사는 'portlock-only'
결과 kind ∈ {WSL2_INTEROP, WSL2_NO_INTEROP, WSL1, WSL_UNKNOWN, NATIVE_LINUX, MACOS, NATIVE_WINDOWS, CYGWIN, MSYS, CONTAINER}
```

근거:
- [높음] `sys.platform`: https://docs.python.org/3/library/sys.html · osrelease 판별: https://github.com/microsoft/WSL/issues/423
- [높음] `wslinfo --networking-mode`: microsoft/WSL `src/linux/init/wslinfo.cpp:89-126,156-166`. nat·bridged·mirrored·consomme 를 찍고, 그 밖의 값은 `none`, 유틸리티 VM 이 아니면 `wsl1` 이다. 질의가 실패하면 stderr 에 쓰고 종료 코드 1 이다(`unknown` 을 찍지 않는다). VirtioProxy → Consomme 이름 변경은 커밋 b9e1d7044(2026-06-23). 개발 환경 의 `/init` 에는 `consomme`·`wsl1` 문자열이 있고 `virtioproxy` 는 없다.
- [높음] binfmt `status` 그림자: WSL `init.cpp` `ProtectBinfmtStatus()`("Reads reflect the shadow file, not the kernel status"), 개발 환경 의 mountinfo `/wsl/binfmt-status-lock /proc/sys/fs/binfmt_misc/status … tmpfs`.
- [높음] interop 항목 이름: WSL `binfmt.h:21` `LX_INIT_BINFMT_NAME "WSLInterop"` — 현행 WSL 은 이 이름만 등록한다. `-late` 는 받아 두기만 한다(어느 판이 등록했는지 미확인, 받아도 해가 없다).
- [높음] networkingMode 값, NAT → consomme 대체(WSL 2.3.25+), bridged deprecated(2.4.5+): https://learn.microsoft.com/en-us/windows/wsl/wsl-config . usbipd 도 같은 명령으로 모드를 읽는다(v5.3.0 `Usbipd/Wsl.cs:405-430`).
- [높음] WSL2 실측: `systemd-detect-virt` → `wsl`(`-c` 도 `wsl` — H1 에서 `wsl` 을 빼는 이유), `/proc/cmdline` 에 `WSL_ROOT_INIT=1`, WSLInterop 만 있음, `wslinfo` 는 모드 이름 한 줄, `[Environment]::OSVersion.Version` 은 UBR 없이 `10.0.<build>.0` 으로 나온다(UBR 은 레지스트리에서 따로 읽는다). `C:\Program Files\USBip` 은 usbip-win2 클라이언트(반대 방향)의 설치 경로라 usbipd 로 보지 않는다.
- [미확인] WSL1 커널 문자열 형식(문서 근거만)과 오래된 systemd 의 출력.

### 3.2 보고서 (`pweh.hostenv/v1`) — 예시 (값은 설명용 — 실제 호스트 값이 아니다)

```json
{
  "schema": "pweh.hostenv/v1",
  "kind": "WSL2_INTEROP",
  "python": {"sys_platform": "linux", "machine": "x86_64", "version": "3.10.12"},
  "linux": {"distro": "Ubuntu <버전>", "kernel": "<x.y.z>-microsoft-standard-WSL2", "container": false,
            "systemd": true, "udevd": true, "groups": ["dialout", "plugdev", "video"], "root_equivalent_groups": [],
            "udev_rules": [], "brltty": {"installed": false}, "usb_nodes": "absent"},
  "wsl": {"version": 2, "version_source": "osrelease", "release": "<WSL 버전>", "distro": "Ubuntu",
          "networking_mode": "bridged", "drvfs_c": "/mnt/c",
          "interop": {"usable": true, "entry": "WSLInterop", "init": true, "wslpath": true, "smoke": "ok",
                      "binfmt_status_advisory": "enabled"}},
  "windows": {"build": "10.0.<build>", "uac_enabled": true, "smart_app_control": "off",
              "powershell": "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
              "usbipd": {"present": false}, "ignored": ["C:\\Program Files\\USBip\\usbip.exe (usbip-win2 클라이언트)"],
              "serial_helper": {"present": false},
              "tools": {"esptool_win": {"version": "5.4.0", "source": "~/pweh-tools/esptool-win"}}},
  "serial": {"pyserial": "3.5", "backend": "posix", "ghost_ports_hidden": 8, "busy_check": "proc+portlock",
             "portlock": "abstract-unix"},
  "overridden": [],
  "warnings": ["networking_mode=bridged: WSL 의 0.0.0.0 리스너는 LAN 에 열린다(PWEH 는 리스너를 만들지 않음). usbipd 대체 경로는 attach 마다 --host-ip <Windows LAN IP>",
               "(UAC 가 꺼져 있으면) uac_enabled=false: interop 으로 띄운 Windows 프로세스는 관리자 권한(High IL)으로 돈다"],
  "evidence": [{"step": "H3", "signal": "/proc/sys/kernel/osrelease", "value": "<x.y.z>-microsoft-standard-WSL2"}]
}
```

- 볼 수 없는 값은 `null` 로 둔다. 모르는 것과 없는 것을 구별한다.
- 그룹 이름은 표시용이다. 장치를 열 때의 권한 오류가 진실이다.
- 장치 종류별 추천 경로(`routes`)는 이 보고서를 입력으로 하는 별도 함수 `hostenv.recommend_routes(report)` 가 만든다. 형식은 §9 표의 행과 같다.

### 3.3 캐시와 override

| 종류 | 예 | 캐시 |
|---|---|---|
| 정적 값 | kind, WSL 버전, 배포판, Windows 빌드, 네트워킹 모드, UAC | 프로세스 수명 동안. 네트워킹 모드를 바꾸려면 WSL 을 재시작해야 하고, 그러면 서버도 죽는다 |
| interop | WSLInterop 파일 | 해석할 때마다 다시 읽는다(싸다). systemd-binfmt 가 실행 중에 지울 수 있다 |
| smoke·도구 | smoke 결과, 도구 버전 | 300 s. 도구 버전은 (경로, mtime, 크기)로 캐시한다(esp 선례) |
| 휘발 값 | COM 목록, usbipd attach 상태, 포트 점유, 장치 식별 | 캐시하지 않는다. 한 도구 호출 안에서만 ≤2 s 묶음 |

override 규칙:
- **좁히기만 된다.** 설정 `hostenv.disable: [interop, serial_helper, windows_tools]` 와 `ports.prefer.serial: auto|win-helper|usbipd` 는 경로를 끄거나 고를 뿐이다.
- **허용을 넓히는 값(원격 시리얼 호스트)은 `safety.ports.*` 에만 둔다**(§11). 이것은 제안이다.
  지금 `SafetyConfig` 는 평평한 필드만 있고 모르는 키를 조용히 무시한다(`src/pweh/config.py:139-151`). 무시되면 LAN 호스트가 하나도 허용되지 않으므로 fail closed 다.
  중첩 필드 추가와 모르는 키 거부는 common-core §6 의 제안과 함께 간다.
- **환경 변수로 감지를 바꾸지 않는다.** 초안의 `PWEH_HOSTENV_FIXTURE`·`PWEH_TESTING` 은 없앤다(`PWEH_TESTING` 은 지금 존재하지도 않는다). 시험은 probe 객체를 주입한다(§14).
- 보고서의 `overridden` 에 바뀐 키가 남는다. 경로는 열 때마다 실제 조건(헬퍼가 실제로 뜨는지, 노드가 있는지)을 다시 확인하므로 잘못된 override 는 실패로 끝난다.

### 3.4 probe 실행 규칙

- 읽기만 한다: 파일 읽기, `stat`, `wslinfo`, `wslpath`, `systemctl is-active`, `systemd-detect-virt`, `dpkg-query`(brltty).
- Windows 쪽은 `wininterop.run()` 의 허용 목록(§11)으로만 실행하고 시간 제한을 둔다.
  - powershell.exe 는 코드에 박힌 고정 스크립트만 돌린다: CIM/PnP 질의, `OSVersion` 과 레지스트리 UBR·`EnableLUA`·SAC 상태 읽기.
    출력은 `[Console]::OutputEncoding=UTF8`, `$ProgressPreference='SilentlyContinue'`(stderr 의 CLIXML 방지)로 받는다.
  - `usbipd.exe` 는 `--version`·`state`·`policy list` 만 돌린다. 관리자 검사는 bind·unbind·policy add/remove 에만 있다(`CommandHandlersCli.cs`) [중간 — `policy list` 는 실행해 보지 않음].
  - 장치 열거는 CIM/PnP 질의만 하고 포트는 열지 않는다.
- 쓰지 않는 것: `wsl.exe`(UTF-16LE 출력, 비밀번호 없는 root), `cmd.exe`(UNC cwd 경고, CP949), `reg.exe`(CP949), `usbip.exe`.

### 3.5 출력 — `pweh env`, doctor, `pipeline_environment()`

- `pweh env [--json] [--refresh]`(새 CLI)는 보고서와 추천 경로를 보여 준다.
- `pweh doctor` 는 맨 앞에 환경 절을 추가한다.
  - 가짜 ttyS 는 숨기고 센다(§4.5 규칙). usbipd 전용 힌트는 경로·모드 기반 힌트(§10)로 바꾼다.
  - esptool.exe 는 esp 와 같은 해석(설정 → 환경 변수 → 후보 경로)을 쓴다. COM 포트마다 드라이버 `Service` 를 보여 준다.
  - 네이티브 Linux 에서는 brltty 를 검사한다. usbipd AutoBind 정책이 있으면 경고한다. bridged 이면 0.0.0.0 리스너 목록을 보여 준다(스캔 아님).

```
[-- ] env                     WSL2 (WSL <버전>, <x.y.z>-microsoft-standard-WSL2), Ubuntu <버전>, x86_64
[OK ] env:interop             WSLInterop enabled, /init, wslpath, smoke ok (binfmt status=enabled, 참고 값)
[OK ] env:uac                 UAC 켜짐 (꺼져 있으면 [!!] — interop 으로 띄운 Windows 프로그램은 관리자 권한으로 돈다)
[-- ] env:networking          bridged (deprecated) — PWEH 는 리스너를 만들지 않음. 0.0.0.0 리스너: <포트 목록>
[-- ] env:usbipd              없음 (선택). 쓰려면 attach --host-ip <Windows LAN IP>, 세션 동안만 bind — usbip.exe(usbip-win2)는 무시
[OK ] serial:backend          pyserial 3.5 posix, 가짜 /dev/ttyS* 8개 숨김, Windows COM 0개
route:serial    Windows COM(헬퍼) [P2]          대체: PowerShell(설정) / usbipd → /dev/ttyACM*
route:esptool   esptool.exe COMn (방법 A) [현행]  대체: usbipd → Linux esptool
route:openocd   usbipd + Linux openocd [현행 유일, 사람 단계]   목표: openocd.exe + tcl port pipe [P3]
route:sigrok    usbipd + Linux sigrok-cli [현행 유일]          목표: sigrok-cli.exe [P3]
route:sdr/video 서버 없음 [P4]                    route:block  사람 이미징 → case_import_file
```

- `pipeline_environment()` 는 pweh-case 의 새 도구다(OBSERVE, `pipeline_safety_policy()` 옆).
  - 보고서와 `routes` 를 돌려주고, 휘발 목록은 넣지 않는다.
  - master-prompt Phase 0 의 장비 체크리스트(common-core §7, "Windows 관리자 권한 여부")가 이 결과를 쓴다.
  - 카탈로그 재생성·`--check` 와 architecture §6.1 만 고치면 된다. `.claude/settings.json` 은 이미 `mcp__pweh-case__*` 를 허용한다.
- 장치 서버의 `*_list_ports`·`*_version` 결과에는 포트마다 `route`·`device_id`·`held_by` 를, 결과 전체에 `env_kind` 를 추가한다. 기존 필드는 그대로 두고, 목록 의미가 바뀌는 부분은 §13.3 에 계약 변경으로 적는다.

## 4. 포트 참조와 해석기 — `pweh.ports`

### 4.1 참조 문법 (에이전트와 도구가 똑같이 쓰는 형식)

에이전트가 넘기는 값은 지금처럼 **OS 이름**이다. 새 문법은 만들지 않는다. 안정 식별은 결과 메타데이터(`device_id`)로 돌려준다.

| 형식 | 예 | 정규화·검사 | 받는 곳 |
|---|---|---|---|
| Windows COM | `COM3`, `com12` | 대문자 `COM<n>`. `COM[1-9][0-9]{0,3}` 이고 n ≤ 4096, 앞자리 0 금지(COM 이름 DB 의 최대 크기 `COMDB_MAX_PORTS_ARBITRATED`=4096. `\\.\COMn` 형식은 모든 번호에 통함 — CreateFileW 문서) | WSL2+interop(헬퍼), WSL1(n ≤ 191 만 — lxcore 는 `ttyS1`–`ttyS191` 만 COM 에 대응. 192 이상은 분명한 메시지로 거부) |
| 리눅스 tty | `/dev/ttyUSB0`, `/dev/ttyACM1`, `/dev/serial/by-id/usb-…-if00`, `/dev/serial/by-path/…`, `/dev/ttyS<n>` | 절대 경로의 문자 장치(uart 는 이미 검사 — `uart_mcp/session.py:290-298`)이고 realpath 가 `/dev` 아래(esp 선례 `esp_mcp/ports.py:80-89`) | 리눅스, WSL(usbipd 후), WSL1(ttyS) |
| pty | `/dev/pts/7` | 그대로 | 시뮬레이터·시험 |
| macOS | `/dev/cu.usbmodem1101` | `tty.*` 는 `cu.*` 를 쓰라는 안내와 함께 거부한다(아래) | macOS (P5) |
| URL | `socket://127.0.0.1:7777`, `rfc2217://[::1]:2217`, `loop://` | 스킴 허용 목록 3종(uart 는 이미 — `uart_mcp/session.py:256-257`). 호스트는 루프백만(§5.5, D4) | uart, jtagulator |

- COM 문법은 지금 세 가지다: uart 는 상한이 없고(`uart_mcp/session.py:258`), esp 는 COM1–256(`esp_mcp/ports.py:28`), jtagulator 는 `COM\d{1,3}`(COM0·COM007 통과, `protocol.py:366`). `pweh.ports` 하나로 맞춘다.
- **macOS `tty.*` 를 거부하는 이유**: Apple 은 call-out 장치(`cu.*`)를 "should almost always be used" 라 하고, dial-in 장치(`tty.*`)는 착신을 감시할 때 쓴다(SerialPortSample).
  IOSerialBSDClient 의 `open` 은 한 포트의 call-out 세션과 dial-in 세션을 서로 배제한다(call-out 이 쓰는 동안 dial-in open 은 기다리거나 EBUSY). pyserial 목록도 `cu.*` 만 보여 준다.
  (pyserial 은 `O_NONBLOCK`·`CLOCAL` 로 열기 때문에 `tty.*` 를 열어도 DCD 를 기다리며 멈추지는 않는다. 그것은 거부 이유가 아니다.)
- **거부 대상**
  - 다른 URL 스킴: `spy`, `hwgrep`, `alt`, `cp2110`, 모르는 것.
  - 제어 문자, 상대 경로, `..`, 일반 파일.
  - COMn 을 받을 수 없는 환경의 COMn.
- 이 검사는 **인자 검증**(`validation_failed`)이다. 게이트 정책이 아니다. 게이트는 INTERACT 를 항상 허용하기 때문이다(`gate.py:80-81`).
- `winserial://` 같은 내부 표기는 만들지 않는다. 헬퍼 transport 는 `pweh.ports.open_serial(route, settings)` 가 직접 만든다. `serial_for_url` 의 URL 디스패치와 전역 `protocol_handler_packages` 등록은 쓰지 않는다.
- uart `validate_port` 의 `sys.platform == "win32"` 분기(`uart_mcp/session.py:283-284`)는 P0 의 win32 시작 거부 뒤에는 닿지 않는 코드가 된다. 네이티브 Windows 이식 때 다시 쓴다.

### 4.2 해석: `resolve(env, ref, purpose) → PortRoute`

`purpose` 는 `serial-session`(uart·jtagulator·flipper·nfc·play), `esptool`, `sigrok-serial` 중 하나다.

| 참조 | WSL2_INTEROP | WSL2_NO_INTEROP | WSL1 | NATIVE_LINUX | MACOS |
|---|---|---|---|---|---|
| `COMn` + serial-session | `win-helper` (대체 `win-powershell`) | 거부 + usbipd 안내 | `posix-tty` `/dev/ttyS<n>`(n ≤ 191, 대체 `win-helper`) | 거부 | 거부 |
| `COMn` + esptool | `win-exe` esptool.exe (현행) | 거부 | `win-exe` | 거부 | 거부 |
| `COMn` + sigrok-serial | `win-exe` sigrok-cli.exe `conn=COMn` (P3) | 거부 | `win-exe` (P3) | 거부 | 거부 |
| `/dev/…` (tty·by-id·pty) | `posix-tty` (usbipd 로 붙은 것만 있다) | `posix-tty` | `posix-tty` | `posix-tty` | `posix-tty` (`cu.*`) |
| URL | `net-url` / `loop` | 같음 | 같음 | 같음 | 같음 |

- `WSL_UNKNOWN` 은 WSL2 열과 같되 COMn → ttyS 대응을 하지 않는다(헬퍼는 interop 이 있을 때만). CONTAINER 는 `/dev/…` 와 URL 만 받는다.
- 해석기는 **포트를 열지 않는다.** 식별 정보는 CIM/PnP 질의, sysfs(pyserial `ListPortInfo`), `stat` 에서만 얻는다.
- 이름이 없거나 장치가 없으면 "Windows 에 있음(`usbipd state` 가 Attached 면 WSL 에 붙어 있음)" / "WSL 에 있음" / "없음" 을 판정해 안내를 정한다. 예: COM 이 사라졌다면 usbipd 로 WSL 에 붙어 있을 수 있다.

### 4.3 `PortRoute` — 결과·감사·승인 지문에 보인다

```json
{"ref": "COM5", "backend": "win-helper", "side": "windows", "device_path": "\\\\.\\COM5", "lock_key": "win:COM5",
 "device_id": "win-pnp:USB\\VID_0483&PID_5740\\FLIP_ABCD/MI_00",
 "identity": {"vid": "0x0483", "pid": "0x5740", "serial": "flip_Abcd", "strength": "serial", "service": "usbser",
              "instance_id": "USB\\VID_0483&PID_5740&MI_00\\…", "parent_instance_id": "USB\\VID_0483&PID_5740\\FLIP_ABCD",
              "manufacturer": "Flipper Devices Inc.", "role_hint": "flipper-cli"},
 "reset_risk": "possible", "warnings": []}
```

- `backend`: `posix-tty` | `win-helper` | `win-powershell` | `win-exe` | `net-url` | `loop` (`win32-native` 는 이식 전까지 쓰지 않는다). `side`: `local` | `windows` | `remote`.
- `lock_key` 는 **OS 객체**에서만 나온다(§6.2). `device_id` 는 OS 가 보고한 식별(§4.4)의 원문이고, 강도 판정·중복 검사 결과는 넣지 않는다. `strength` 는 표시와 역할 판단에만 쓴다.
- **결과에 보인다.** `*_list_ports` 는 포트마다, `uart_open`·`jtagulator_connect`·`esp_*` 는 `route` 로, `uart_sessions` 는 세션마다 보여 준다. 감사 이벤트에도 `route` 를 기록한다.
- **승인 지문에 들어간다(열기·연결 동작만).**
  - 대상: `uart_open`, `uart_detect_baud`, `jtagulator_connect`, esp 의 세 도구, 앞으로 `flipper_connect`·`nfc_cu_connect`·`input_connect`.
  - 이 도구들의 `action` 에 `route: {backend, lock_key, device_id}` 를 넣는다. "COM3 = CP210x 시리얼 X" 로 받은 승인은 사람이 다른 장치를 COM3 으로 꽂으면 `approval_mismatch` 가 된다. `pweh approve` 화면에도 장치가 보인다.
  - **식별이 흔들리는 경우**: `device_id` 는 휘발 열거에서 온다(CIM 시간 초과면 `null`). 승인과 재시도 사이에 값이 바뀌면 `approval_mismatch` 가 난다. 잘못된 허용이 아니라 거부 쪽으로 틀린다(fail closed). 에이전트는 목록을 다시 보고 새 승인을 요청한다(우회 없음). 같은 시리얼을 가진 장치를 새로 꽂아 강도가 떨어지는 경우는 `device_id` 를 바꾸지 않으므로 이 원인에서 빠진다.
  - 쓰기마다 받는 지문은 지금처럼 `session_id` 를 쓴다. 세션은 열 때 식별에 묶이기 때문이다.
  - esp 의 지문 문단(architecture §6.7 "승인 지문(action)은 command, port, chip, …")과 시험을 함께 고친다.
- `device_id` 는 비밀이 아니다(사용자 소유 장치의 USB 시리얼). common-core §5 의 마스킹 대상이 아니다.

### 4.4 장치 식별 — VID/PID 만으로 정하지 않는다

| 출처 | 얻는 값 |
|---|---|
| Windows (WSL 에서) | CIM `Win32_PnPEntity` 의 `PNPDeviceID`·`Service`·`Status`·`Manufacturer`(esp `_PS_LIST_COM` 확장). 복합 장치의 자식(`&MI_xx`)은 읽기 전용 PnP 속성 `DEVPKEY_Device_Parent` 로 부모 인스턴스 id(시리얼 포함)를, `DEVPKEY_Device_LocationPaths` 로 물리 위치를 얻는다. 질의 시간은 [미확인]이다(≤2 s 묶음) |
| 리눅스·WSL(usbipd 후) | pyserial `ListPortInfo` 의 vid·pid·serial_number·location(`1-1.2:1.0` → 인터페이스 번호)·manufacturer·product·interface, `/dev/serial/by-id` 이름. usbipd 로 붙으면 location 이 vhci 경로라 attach 마다 바뀐다. 시리얼은 그대로다 |
| macOS | pyserial IOKit(`IOUSBHostDevice`)의 vid·pid·serial·location·interface 이름 |

`device_id` 형식:
- Windows: `win-pnp:<부모 인스턴스 id>/<MI_xx 또는 ->`(OS 가 보고한 문자열 그대로).
- 리눅스·macOS: `usb:<vid>:<pid>:<시리얼 원문 또는 by-path 위치>/if<NN>`.
- URL·pty: `null`.

`strength`(식별 강도, 표시·역할 판단용)는 셋이다.
- `serial`: 시리얼이 있고, 일반값 목록(`0001`, `00000001`, `0123456789ABCDEF` 등)에 없고, 지금 꽂힌 장치끼리 겹치지 않는다.
- `location`: Windows 인스턴스 id 가 위치에서 나왔거나(`&` 가 들어 있음), 리눅스 by-path 다.
- `none`: URL, pty, 아무 정보 없음.

**흔한 범용 ID** 는 역할을 VID/PID 만으로 정하지 않는다.
- 해당 ID: `0483:5740`(ST 범용 VCP — Flipper 도 씀), `1a86:7523`(CH340, 시리얼 없음), `10c4:ea60`(CP210x, 기본 시리얼 `0001` 흔함), `0403:6001/6010/6014/6015`(FTDI — JTAGulator·USB-UART·JTAG 어댑터·FTDI LA 가 같은 칩), `0bda:2838`(RTL-SDR, 시리얼 `00000001` 흔함).
- 역할(예: "이것이 Flipper", "이것이 입력 브리지")에는 VID:PID + 시리얼 패턴 또는 제조사·제품 문자열 + 인터페이스 번호가 필요하다.
- 고정해야 하는 역할(브리지 iSerial, JTAGulator)은 처음 쓸 때 기록한 식별이나 사람 증명(common-core §3 `bridge-serial`)과 맞아야 한다.

식별 표는 데이터 파일 `src/pweh/data/usb-ids.yaml` 하나에 둔다. 지금 흩어진 uart `USB_UART_VIDS`(`uart_mcp/server.py:117-118`)와 esp `KNOWN_USB_IDS`(`esp_mcp/ports.py:34-47`)를 합친다.
항목마다 `kind`, `generic`, `interfaces`(예: Flipper `MI_00=cli`/`MI_02=bridge`, ESP `303a:1001` 의 CDC/JTAG), `reset_wiring`(`none` | `auto-reset` | `chip-reset-on-lines`), `role_hint`, `transitions`(ROM OTG·DFU·fx2lafw 재열거)를 둔다.
ESP32 계측기: `303a:4002`(TinyUSB CDC 두 개, 전용 PID 없음 — 식별은 MAC 고정) 항목을 두고, `303a:1001` 의 `transitions` 에 계측기 부팅 창(모든 부팅이 잠깐 1001 을 거침)을 적는다(esp32-instrument §2.3).

### 4.5 열거

`ports.list_serial(env)` 하나를 uart·esp·jtagulator(새 목록 도구는 선택)·doctor 가 함께 쓴다.

| 쪽 | 출처 | 비고 |
|---|---|---|
| Windows | CIM | interop 이 있을 때만. 행의 `device` 는 `COMn` 이고, 드라이버 `Service`(usbser / FTDIBUS / silabser / CH341SER_A64)를 넣는다 |
| 로컬 | pyserial | **가짜 포트 규칙은 esp 선례를 쓴다**: `hwid` 가 `n/a`(또는 없음)이고 vid 가 없으면 숨기고 센다(`esp_mcp/server.py:718-719`). 개발 환경 의 ttyS0-7 이 여기에 해당한다. sysfs `type`(가짜면 0)은 주입한 reader 로 읽어 doctor 진단에만 쓴다. 시험이 실제 호스트 `/sys` 를 읽지 않게 하기 위해서다 |

- 두 쪽을 합친 목록에 `owner_side`, `route`, `device_id`, `held_by`(portlock 소유 기록: 서버·세션·상태)를 붙인다.
- uart 의 `likely_usb_uart` 같은 기존 필드는 유지한다.
- WSL1 에서는 Windows COM 목록(CIM)을 `/dev/ttyS<n>` 에 대응해 보여 준다(n ≤ 191).

## 5. 백엔드

### 5.1 `posix-tty` (리눅스, WSL usbipd 후, macOS, WSL1 의 ttyS)

열기 순서는 아래와 같다. 순서 자체가 안전 장치다.

```
resolve(ref)                                  # 열지 않음. stat(realpath).st_rdev → lock_key (§6.2)
→ portlock.acquire(lock_key)                  # §6. 실패하면 busy — os.open 전에
→ (리눅스) /proc 점유 검사(최선 노력)          # PWEH 밖 프로그램(minicom 등), 있으면 busy
→ 분류 → rt().authorize(...)                  # 열기 동작의 위험도(§7). 승인 대기 중에도 잠금 유지(§6.4)
→ pyserial open(exclusive=True)               # os.open: 커널이 DTR/RTS 를 올린다(피할 수 없음. macOS 는 첫 open)
                                              #   → open() 안에서 flock, DTR → RTS 를 요청값으로
→ ioctl(TIOCEXCL)                             # stock pyserial 로는 open() 이 끝난 뒤에만 걸 수 있다
…
닫기: ioctl(TIOCNXCL) → close → portlock 해제   # 플래그는 close 로 지워지지 않는다(아래)
```

- **남는 창**: `os.open` 과 `TIOCEXCL` 사이(수 ms)에 PWEH 밖 프로그램이 같은 포트를 열 수 있다. PWEH 프로세스끼리는 portlock 이 이미 막는다.
  창을 닫으려면 PWEH 가 직접 `os.open` → `TIOCEXCL` 을 한 뒤 나머지 설정을 하는 `serial.Serial` 하위 클래스가 필요하다(D5 의 선택). 어느 쪽이든 보유자 자신의 open 펄스는 막지 못한다.
- `TIOCEXCL` [높음]: `tty_reopen()` 이 `TTY_EXCLUSIVE && !capable(CAP_SYS_ADMIN)` 이면 `-EBUSY` 를 돌려준다(`tty_io.c:1314-1315`).
  `tty_open()` 은 이 검사가 실패하면 `tty->ops->open()`(→ `tty_port_open` → DTR 올림)을 부르지 않는다(`:2096-2112`).
  출처: [tty_io.c](https://raw.githubusercontent.com/torvalds/linux/master/drivers/tty/tty_io.c). macOS 도 `TS_XCLUDE` 가 걸리면 root 가 아닌 open 은 `EBUSY` 다(`IOSerialBSDClient.cpp:2049-2066`).
- `TIOCEXCL` 의 효과와 한계:
  - flock 을 모르는 minicom·screen 도 막는다.
  - root(ModemManager 등)는 막지 못한다.
  - WSL1·일부 드라이버가 `ENOTTY` 를 돌려주면 경고만 남긴다.
- **닫을 때는 `ioctl(TIOCNXCL)` 로 직접 푼다.** `TTY_EXCLUSIVE` 는 ioctl 로만 바뀌고(`tty_io.c:2703-2707`), tty 구조체가 해제될 때(마지막 보유자가 닫을 때)에만 함께 사라진다.
  - 시뮬레이터가 바로 이 경우다. mocktarget 은 pty slave fd 를 수명 내내 쥐고 있다(`src/pweh/mocktarget/transport.py:173`, 닫는 곳은 `stop()` 의 `:186-194`).
    TIOCNXCL 없이 닫으면 `uart_close` 뒤의 `uart_open` 이 EBUSY 가 된다. 그러면 `setenv baudrate` 뒤 닫고 다시 여는 흐름, `inherited_last_command`, jtagulator 재연결이 깨진다.
    개발 환경 의 pty 실험으로 확인했다(보유자가 master 만 쥐어도 같다).
  - 남는 위험: 서버가 TIOCNXCL 전에 죽고 다른 프로세스가 그 tty 를 쥐고 있으면 플래그가 남는다. 실제 USB 어댑터는 보통 다른 보유자가 없어 마지막 close 에 함께 사라진다. 남았을 때의 오류는 `busy` + "포트를 쥔 프로세스를 끝내거나 장치를 다시 꽂으라"는 안내다.
- pyserial 은 TIOCEXCL 을 쓰지 않는다. 그래서 PWEH 의 `open_serial` 이 직접 걸고 `close` 가 직접 푼다.

### 5.2 `win-helper` — `pweh-serial-helper.exe`

**하는 일:** WSL 서버가 interop 으로 띄우는 Windows 프로세스다. COM 포트 하나를 열어 stdin/stdout 프레임으로 바이트만 나른다.
소스는 저장소 `tools/winserial/pweh-serial-helper.c`(C 하나)다. `zig cc -target x86_64-windows-gnu -O2` 로 만든다(install.sh 가 이미 zig 를 고정 설치 — `scripts/install.sh:47,554-562`).

보안 요구 — 모두 시험한다(§14).

| 요구 | 구현·검사 |
|---|---|
| COMn 만 연다 | Python 과 exe 양쪽에서 `COM[1-9][0-9]{0,3}`, n ≤ 4096 을 검사한다. 경로 문자열을 받지 않고 **정수로 `\\.\COM<n>` 을 만든다**. 그래서 `\\.\PhysicalDrive0`, `\\.\pipe\…`, `\\?\…`, 파일 이름은 표현 자체가 불가능하다. 연 핸들의 `GetFileType` 이 `FILE_TYPE_CHAR` 가 아니거나 `GetCommState` 가 실패하면 닫고 오류를 낸다 |
| 배타로 연다 | `CreateFileW(…, GENERIC_READ\|GENERIC_WRITE, 0 /*공유 모드 0*/, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL)`. 공유 모드 0 은 통신 자원을 여는 쪽의 **요구 사항**이다([CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)). 두 번째 열기를 막는 것은 **드라이버·장치 스택의 성질**이다. I/O 관리자가 배타를 강제하는 것은 장치 객체에 INF 의 Exclusive 속성이 있을 때뿐이다(MS Learn "Specifying Exclusive Access to Device Objects"). serial.sys 와 주요 VCP 드라이버는 막는다. 개발 환경 의 Ports 클래스 키와 inbox `usbser.inf`·`msports.inf` 에는 Exclusive 값이 없어 usbser 는 [미확인]이다 → 드라이버별 두 번째 열기 시험(§15). 두 번째 열기가 성공하는 드라이버면 Windows 쪽 보유자는 Win32_Process 검사(헬퍼 `--token`, esptool.exe)로만 보인다고 결과에 표시한다 |
| 네트워크 없음 | winsock 을 링크하지 않는다. 빌드 산출물의 **PE import 표**가 허용 목록(`KERNEL32.dll` + CRT)에만 있어야 하고 `WS2_32`·`WSOCK32`·`WININET`·`WINHTTP`·`ADVAPI32`·`SHELL32` 는 없어야 한다(정적 검사, 하드웨어 불필요) |
| 명령 모드 없음 | DATA 프레임 내용은 COM 으로만 간다. 제어 프레임은 Python transport 코드만 만든다(세션 API 에 원시 프레임 쓰기가 없음) |
| 시작할 때 아무것도 보내지 않음 | HELLO 만 stdout 으로 보낸다. COM 에는 OPEN 뒤 DATA 가 올 때까지 한 바이트도 쓰지 않는다 |
| 스스로 끝남 | stdin EOF 또는 QUIT 이면 핸들을 닫고 종료한다. 단일 프로세스이고 자식이 없다. PyInstaller onefile 고아 문제(`esp_mcp/winproc.py:3-7`)가 생기지 않는다. 서버가 SIGKILL 로 죽어도 파이프가 닫혀 헬퍼가 끝나고 COM 이 풀린다(실기 확인 §15) |
| 파일·레지스트리·프로세스 생성 없음 | stderr 에는 짧은 ASCII 진단만 쓴다. argv 는 `--port COMn --token <hex>` 다(Windows 프로세스 목록에서 고아를 찾는 표식, esp `windows_tokens` 선례) |
| 무결성 | Python 이 처음 실행하기 전에 sha256 을 **모듈 상수** `PINNED_SHA256` 과 대조한다((경로, mtime, 크기)로 캐시). 상수는 저장소의 `tools/winserial/SHA256SUMS` 에서 만든다. 다르면 `helper_untrusted` 로 거부한다. 설정 `tools.serial_helper`(`${PWEH_SERIAL_HELPER:-}`)는 **경로만** 바꾸고(basename 은 `pweh-serial-helper.exe` 여야 함) 해시를 더할 수 없다. 설정 키나 환경 변수로 핀을 늘리는 길은 없다. 시험은 프로세스 안에서 monkeypatch 한다(§14) |
| 재현 빌드 | zig 빌드가 비트 단위로 재현되는지는 [미확인]이다. P2 관문에서 깨끗한 디렉터리에 두 번 빌드해 sha256 을 비교한다. 재현되면 install.sh 가 로컬 빌드도 같은 핀으로 받는다. 재현되지 않으면 배포한 사전 빌드만 믿고, 로컬 빌드는 유지보수자가 커밋으로 핀을 바꿀 때만 쓴다(D3) |
| 실행 모드 | 셋뿐이다. `--port COMn --token <hex>`(일반), `--version`(HELLO 를 찍고 종료 — 실행 가능 확인), `--echo`(COM 을 열지 않고 DATA 를 되돌림 — 장치 없는 파이프 자체 시험). 그 밖의 인자는 거부한다 |

프레임은 `type(1 B) | len(2 B, LE) | payload(≤16 KiB)` 이다. 바이너리로 안전하다(Win32 `ReadFile`/`WriteFile` 을 표준 핸들에 바로 쓰므로 CRT 텍스트 모드의 CRLF 문제가 없다).

| 방향 | type | 내용 |
|---|---|---|
| 헬퍼→ | `H` | HELLO: 프로토콜 버전, 헬퍼 버전, 빌드 id. 시작 직후 한 번 |
| →헬퍼 | `O` | OPEN: baud(u32), 데이터 비트, 패리티, 정지 비트, `dtr`, `rts`. `CreateFileW` → `GetCommState` → DCB 설정(`fBinary=1`, 흐름 제어 전부 끔, `fDtrControl`/`fRtsControl` = 요청값) → `SetCommState` → `SetCommTimeouts` → `PurgeComm` 순서. **DTR/RTS 는 CreateFile 직후 첫 DCB 에서 정한다** |
| 헬퍼→ | `o` | OPEN 결과: 상태, Win32 오류 코드, 모뎀 선(CTS/DSR/RI/DCD) |
| 양방향 | `D` | 데이터 |
| →헬퍼 | `B` / `L` / `K` / `P` | 보드레이트·프레이밍 변경 / DTR·RTS 설정(유지값 0xFF) / BREAK(ms) / 버퍼 비우기 |
| 헬퍼→ | `A` | `B`/`L`/`K`/`P` 응답 |
| →헬퍼 | `S` | 상태 요청 |
| 헬퍼→ | `s` | 상태(모뎀 선, `ClearCommError` 플래그, 큐 크기) |
| 헬퍼→ | `E` | 오류: `access_denied`(다른 프로그램 점유) / `not_found` / `device_removed` / `io_error` / `bad_frame` / `unsupported` + Win32 코드 |
| →헬퍼 | `Q` | 종료 |

Python 쪽은 `pweh.winserial.HelperSerial(serial.SerialBase)` 다.
- uart 세션과 jtagulator 드라이버가 쓰는 부분 집합을 구현한다: `open`·`close`·`read`·`write`·`in_waiting`·`reset_input_buffer`·`flush`·`cancel_read`, `dtr`·`rts`·`break_condition`·`send_break` 속성, `baudrate` 설정.
- `fileno()` 는 예외를 낸다. 그러면 jtagulator 는 이미 있는 `in_waiting` 폴링으로 내려가고(`jtagulator_mcp/driver.py:164-179`), uart 는 원래 폴링이다.
- 시간 제한: HELLO 5 s, OPEN 응답 5 s. 넘으면 `helper_unavailable` 이다.
- 오류는 세션 상태로 바꾼다. `device_removed`·파이프 끊김은 `disconnected` 다. `access_denied` 는 `busy` 이고, 힌트로 PuTTY·Arduino IDE 를 닫으라고 하고 남은 esptool.exe 를 `winproc` 로 확인해 PID 를 보여 준다.
- 처리량: interop stdout 파이프는 ≈928 MiB/s 로 측정됐다 [중간 — 합성 1회]. 직렬 속도에는 병목이 아니다.

### 5.3 `win-powershell` — 대체 경로 (기본 꺼짐, D3)

- 헬퍼가 없을 때, 실기 관문에 실패했을 때, 서명 없는 exe 를 막는 Smart App Control 이 켜진 PC 에서 쓴다. powershell.exe 는 MS 서명이고 헬퍼는 서명이 없다.
  SAC 정책 예제는 `Disabled:Script Enforcement` 라 .NET `SerialPort` 를 쓰는 데 지장이 없을 것으로 본다 [중간].
- 실행 방식:
  - `powershell.exe -NoProfile -NonInteractive -EncodedCommand <고정 스크립트>` 로 띄운다.
  - 스크립트는 `src/pweh/winserial/relay.ps1` 에 박아 둔다. 정수 인자(COM 번호, baud, 비트)만 검증한 뒤 틀에 넣는다.
  - 같은 프레임 프로토콜을 쓴다(데이터는 `[Console]::OpenStandardInput()`/`OpenStandardOutput()`).
- 주의할 점:
  - .NET `SerialPort.DtrEnable` 의 기본값은 **false** 다 [높음 — MS Learn]. Flipper 는 `DtrEnable=$true` 를 명시한다.
  - 시작에 0.3–1 s 걸린다.
  - 프로토콜 구현이 둘이 되어 시험할 범위가 늘어난다. 그래서 기본값은 꺼 둔다.

### 5.4 `win-exe` — Windows 판 도구 (esptool.exe, openocd.exe, sigrok-cli.exe, ffmpeg.exe, rtl_*.exe)

esp 방법 A 의 실행 규칙을 `pweh.wininterop` 으로 옮겨 일반화한다(common-core §1).
- 실행 전에 argv 분류기를 먼저 돌린다(지금 esp·sigrok 방식).
- `cmd.exe`·`.bat` 을 거치지 않는다(UNC cwd 에서 `C:\Windows` 로 바뀌고, batch 는 interop 으로 실행되지 않는다).
- 파일 인자는 `wslpath -w` 절대 경로로 넘긴다. 끝이 '.'·공백인 경로 요소는 거부한다(`esp_mcp/ports.py:153-168`). cwd 는 Linux 쪽 실행 디렉터리(UNC)여도 된다.
- WSLENV 를 새로 만들어 넘길 변수만 고른다(`esp_mcp/esptool_cli.py:121-149`). OpenOCD 는 Windows 쪽 `OPENOCD_SCRIPTS`·`%APPDATA%\OpenOCD` 를 찾으므로 `-s` 를 먼저 준다.
- 출력은 엄격한 UTF-8 → ACP(한국어 Windows 는 cp949) 순서로 해석한다.
- stdout 을 binary 로 바꾸는 도구만 파이프로 받는다. `hackrf_transfer`·sigrok-cli·ffmpeg `pipe:`·OpenOCD pipe 는 바꾸고, rtl-sdr-blog `rtl_sdr` 은 stdout 대신 stdin 을 binary 로 바꾼다(`rtl_sdr.c:228-232`) → IQ 는 파일로 받는다.
- 스스로 끝나는 실행을 우선한다: `rtl_433 -T`, `rtl_sdr -n`, ffmpeg `q`·`-t`, openocd stdin EOF. 고아 정리는 `winproc` 의 명령줄 표식 방식을 일반화한다(PyInstaller onefile 은 손자가 남는다).
- **esptool 은 헬퍼를 거치지 않는다.** esptool 의 리셋 타이밍(DTR/RTS 연속 토글)은 esptool.exe 가 Win32 에 직접 해야 맞는다.
- **OpenOCD 는 `tcl port pipe` 만 쓴다.** TCP·`bindto` 를 쓰지 않는다. bridged 에서는 Windows 루프백에 닿지 않고, LAN 바인드는 호스트 코드를 실행할 수 있는 Tcl 포트를 노출하는 일이다.
  - 근거 [높음 — 소스·Linux 실측 / Windows 미확인]: OpenOCD v0.12.0 `server.c:219-220`(`pipe` = stdin/stdout), `:299-319`(Windows 이진 모드), `replacements.c:125-240`(`PeekNamedPipe`). interop 의 stdio 핸들은 `FILE_TYPE_PIPE` 로 실측됐다. Linux dummy 어댑터에서 RPC 왕복과 stdin EOF 자동 종료를 확인했다.
  - 바뀌는 것: 연결이 하나뿐이고(`server.c:208`) EOF 가 나면 OpenOCD 가 끝난다(`:567-571`). 그래서 다시 연결하지 않고, `openocd_attach` 는 쓸 수 없으며, 준비 판정 줄이 달라진다(`process.py:41,458` — 'accepting tcl connection from pipe' + `version` 왕복).
- **리스너가 생기는 옵션은 거부한다**: `rtl_tcp.exe`, `rtl_433 -F http|mqtt|influx|syslog|trigger|rtl_tcp`(`-F http` 는 기본 0.0.0.0), SoapyRemote, OpenOCD `bindto`·telnet·gdb 포트(현행 DESTRUCTIVE, `guard.py:219`).

### 5.5 `net-url` (socket://, rfc2217://) 와 `loop://`

- 호스트가 **루프백**(127.0.0.0/8, ::1, 또는 모든 주소가 루프백으로 풀리는 `localhost`)일 때만 받는다.
  LAN 호스트는 운영자가 `safety.ports.remote_serial_hosts`(제안, 기본 빈 목록, 에이전트 수정 금지)에 넣은 것만 받는다(D4).
- 원격 시리얼은 뒤에 어떤 장치가 있는지 식별할 수 없다(`strength: none`). bridged 에서는 그 ser2net 이 인증 없이 LAN 에 열려 있다는 뜻이기도 하다.
- PWEH 가 쓰는 시뮬레이터(mocktarget, jtagulator sim)는 루프백 바인드만 허용한다. 0.0.0.0 처럼 루프백이 아닌 `--host`·`--tcp` 는 `--allow-lan` 이 없으면 거부하고, bridged 이면 경고한다(G13).

## 6. 배타 — `pweh.portlock` (새 동작)

### 6.1 왜 열기 전에 잠그나

리눅스는 tty 를 **열 때마다** DTR/RTS 를 올린다(`C_BAUD≠0`). 마지막 close 가 아니면 내리지 않는다(G2, tty_port.c) [높음].
flock 은 open 이 끝난 뒤에야 거절하므로, 남이 쓰는 포트를 열어 보는 것만으로 그 선로가 바뀐다.
- 영향을 받는 장치: JTAGulator(DTR → Propeller 리셋 → VADJ 꺼짐), DTR/RTS 가 EN·IO0 에 연결된 보드, 신호선을 쓰는 대상.
- 따라서 PWEH 프로세스끼리는 **open 을 시도하기 전에** portlock 으로 거절한다. PWEH 밖 프로그램은 `/proc` 검사(최선 노력)와 보유자 쪽의 TIOCEXCL 로 막는다.
- macOS 는 활성 세션을 비배타로 다시 여는 것이 선을 다시 올리지 않아 G2 가 없다(§7). 그래도 같은 규칙을 쓴다.

초안의 방식(작업 공간 `.pweh/state/locks/` 의 파일 flock, 식별 강도에 따라 형식이 바뀌는 키)은 배타를 보장하지 못했다.
보유자와 새 opener 가 같은 OS 객체에 다른 키를 계산할 수 있고(CIM 시간 초과, 시리얼 중복), 다른 작업 공간·클론·배포판은 서로의 잠금을 못 보며(`src/pweh/config.py:310-320`), 지워진 파일의 flock 은 조용히 무력해진다. 아래가 대안이다.

### 6.2 키 — OS 객체에서만 만든다

| 경로 | `lock_key` |
|---|---|
| `posix-tty` (리눅스·WSL usbipd 후·macOS·pty) | `tty:<major>:<minor>` — `os.stat(realpath).st_rdev`. stat 은 장치를 열지 않는다. by-id·by-path·`/dev/ttyACM0` 같은 별명과 다른 마운트 이름 공간이 모두 같은 키가 된다 |
| WSL1 `/dev/ttyS<n>` | `win:COM<n>` — 헬퍼 경로와 같은 Windows 객체다 |
| `win-helper`·`win-powershell`·`win-exe`(esptool, sigrok `conn=COMn`) | `win:COM<n>` (정규화한 대문자) |
| `net-url` | `url:<scheme>://<소문자 host>:<port>` |
| `loop` | 잠그지 않는다(프로세스 안 객체) |
| (P3) libusb 인터페이스 | Windows `winif:<인터페이스 PnP 인스턴스 id>`, 리눅스 `usbif:<bus>-<port path>:<cfg>.<if>` |

- 식별(`device_id`, `strength`)은 키에 넣지 않는다. 그래서 누가 언제 계산해도, 식별 강도가 어떻든, 같은 OS 객체면 같은 키다.
- Windows↔WSL 이름 공간을 잇는 키는 필요 없다. 한 장치는 Windows 의 COMn 이거나 usbipd attach 뒤 WSL 의 tty 이고, 동시에 둘일 수 없다("as long as the USB device is attached to WSL, it cannot be used by Windows" — MS Learn connect-usb).
  세션 중에 사람이 attach/detach 하면 보유자는 `device_removed`/`EIO` 를 받아 `disconnected` 가 된다.
- **장치 전체 동작**(복합 장치): ESP `303a:1001` 의 esptool usb-reset(재열거로 CDC·JTAG 이 함께 사라짐), Flipper 재부팅·DFU, macOS libusb capture.
  - 그 물리 장치의 **모든 인터페이스 키**를 정렬 순서로, 비차단·전부 아니면 전무로 잡는다. 형제 인터페이스는 열거(PnP 부모의 자식, sysfs 형제)로 찾는다.
  - 열거가 실패하면 그 동작을 거부한다(fail closed — 정보가 필요한 쪽이 실패한다). 나중에 형제 인터페이스를 열려는 쪽은 자기 OS 객체 키에서 부딪힌다.
- 공존: FT2232H 채널 A(JTAG, WinUSB)와 B(UART, FTDIBUS), ESP `303a:1001` 의 JTAG 과 CDC, Flipper `MI_00`(CLI)과 `MI_02`(브리지)는 키가 달라 동시에 쓸 수 있다.

### 6.3 기본 장치와 범위

- **리눅스·WSL**: abstract AF_UNIX 소켓 이름 `\0pweh/portlock/v1/<sha256(lock_key)[:32]>` 에 `bind` 만 한다(listen 하지 않으므로 연결을 받지 않는다).
  - 두 번째 bind 는 `EADDRINUSE` → `busy`. close·종료·SIGKILL 에 커널이 푼다. 오래된 잠금이 생기지 않고 PID 생존 검사(`os.kill(pid,0)`)가 필요 없다.
  - 파일이 아니라서 `rm`·`.pweh` 삭제로 깨지지 않는다. Python 소켓은 기본으로 상속되지 않으므로 자식 프로세스(esptool.exe 등)가 잠금을 물려받지 않는다.
  - 개발 환경 에서 확인했다 [높음 — 실측]: 두 번째 bind 는 `EADDRINUSE`, `inheritable=False`, `/proc/net/unix` 에 보임, 이름을 쥔 자식을 SIGKILL 하면 바로 다시 bind 된다.
- **범위**:

| 상대 | 막히나 | 비고 |
|---|---|---|
| 같은 서버 프로세스 | 예 | 프로세스 안 레지스트리(`_SESSIONS`/`_RESERVED`/`_CONNS`/esp `_port_lock`/`exclusive_key`)가 빠른 경로로 먼저 본다 |
| 같은 배포판의 다른 서버·작업 공간·클론·hardware 시험 | 예 | abstract 이름은 network namespace 전체에 하나다 [높음] |
| 다른 WSL2 배포판 | 배포판들이 network namespace 를 공유하면 예 | 같은 커널과 같은 attach 장치를 본다. netns 공유 여부는 [중간 — 미실측, §15] |
| 다른 사용자 | 예 | 이름은 사용자와 무관하다. 남이 이름을 먼저 쥐면 busy 다(fail closed, 서비스 거부뿐) |
| 컨테이너(자기 netns) | 아니오 | 미지원 플랫폼이다. TIOCEXCL 과 노드 통과 정책에 맡긴다 |
| Windows 쪽 프로세스 | 아니오 | 드라이버의 단일 열기(§5.2)와 Win32_Process 검사에 맡긴다 |

- **`<runtime dir>`** 은 uid 로만 정한다: `/tmp/pweh-<uid>`(0700, 소유자 확인, `O_NOFOLLOW`).
  `XDG_RUNTIME_DIR`·`HOME`·`TMPDIR` 같은 환경 변수는 읽지 않는다. R16 의 `wsl.exe -e` 실행이나 깨끗한 환경의 런처에서도 모든 서버가 같은 곳을 봐야 하기 때문이다(원칙 6).
  소유자·권한·심볼릭 링크 검사가 실패하면 표지·소유 기록을 "모름"으로 보고 fail closed 한다(프로브 바이트 도구는 거부, 다른 사용자가 먼저 만든 경우 포함).
  `/tmp` 는 배포판마다 따로이고 재부팅에 지워진다. 그래서 **표지와 소유 기록은 배포판별, 잠금은 커널 전체**다.
- **macOS(P5) 와 abstract 이름을 못 쓰는 곳**(WSL1 지원 여부 [미확인]): `<runtime dir>/locks/<sha>.lock` 에 `flock(LOCK_EX|LOCK_NB)` 을 건다(사용자별).
  잠금 파일은 **지우지 않는다**. 잡은 뒤 `fstat(fd)` 와 `stat(path)` 의 `(st_dev, st_ino)` 를 비교해 다르면(누가 지우고 새로 만듦) 다시 시도한다. 결과에 `portlock: "flock-file"` 을 적는다.
  이 확인은 잡는 순간만 지킨다. 쥐고 있는 동안 지워지는 것은 못 막으므로, macOS 의 `/tmp` 주기 정리를 피할 위치는 P5 에서 다시 정한다.
- **소유 기록**(메시지용): `<runtime dir>/owners/<sha>.json` 에 서버, pid, case_id, session_id, 역할, ref, route, 상태, 시각을 둔다.
  배타 판단에는 쓰지 않는다. 이름이 비어 있으면 남은 기록은 무시한다. `held_by` 는 이것을 보여 주고, 없으면 `/proc/net/unix` inode → `/proc/*/fd` 로 pid 만 찾는다.
- `fsutil.file_lock`(`src/pweh/fsutil.py:77-116`)은 작업 공간 안의 짧은 잠금이라 쓰지 않는다.

### 6.4 게이트·승인과의 관계

지금 uart 는 게이트 전에 예약 없는 검사(`_port_in_use`, `uart_mcp/server.py:412-415,825-828`)만 하고, 예약은 authorize 뒤에 한다(`:422-427,838-842`). jtagulator 도 게이트 전에는 아무것도 잡지 않는다(`jtagulator_mcp/server.py:301-318`).
아래는 **새 동작**이다.

- 순서: 케이스 확인 → 문법 검사·해석(호스트 쪽 읽기) → **portlock** → `/proc` 검사 → 분류 → authorize → open.
- **승인 대기 중**(MCP elicitation, 최대 300 s — `src/pweh/safety/gate.py:33` `ELICITATION_TIMEOUT_S`)에는 잠금을 쥐고 있다.
  다른 호출은 `busy` 와 `held_by: {state: "awaiting_approval", server, case_id, since, expires_at}` 를 받는다. 대기열은 없다(비차단). 에이전트가 나중에 다시 부른다.
- `approval_required`(CLI 승인 경로), 거부, 오류, 시간 초과, 클라이언트 취소가 나면 **즉시 푼다**(finally).
  재시도는 다시 잡는다. 그 사이 다른 세션이 잡았으면 `busy` 다(fail closed). 승인 레코드는 그대로 남아 다음 시도에 쓸 수 있다.
- 연 뒤에는 세션 수명 동안 쥔다(`disconnected` 상태 포함, `uart_close`·`*_disconnect`·프로세스 종료까지). 세션의 job 은 세션 잠금을 함께 쓴다.
- 한 번에 끝나는 동작(`uart_detect_baud`, esptool 실행)은 호출(또는 job) 동안 쥔다.

### 6.5 역할 표지 (target / bridge)

- 세션이 끝나도 남는 **표지**다. 예: pweh-flipper 가 `MI_02` 를 "케이스 X 의 bridge" 로 기록해 pweh-uart 에 넘긴다(게임 문서 §3.1).
  표지는 서버만 쓴다(자기 스캔·사람 증명에서). 역할은 `target`(대상 콘솔), `bridge`(대상으로 이어지는 브리지 — target 과 같게 다룸), `instrument`(계측기), `instrument-aux`(계측기 보드의 보조 포트 — 예: DevKit 의 USB-UART 칩)다.
  `instrument` 표지 포트는 그 계측기 서버만 연다. 표지와 별도로 `instrument-pin` 증명(common-core §3)도 다른 서버의 거부 근거다(esp32-instrument §5.5).
- 위치는 `<runtime dir>/tags/` 다(§6.3 — 배포판·사용자별, 재부팅에 지워진다. COM 번호도 재부팅·재연결로 바뀔 수 있다).
  `device_id`(있으면)와 `lock_key` 두 색인으로 찾는다. 그래서 재열거로 이름이 바뀌어도 같은 장치면 표지가 따라간다.
- 재동기화·프로브 바이트를 보내는 도구는 지금 잡혀 있지 않아도 `target`/`bridge` 표지가 있는 포트를 거부한다(jtagulator Ctrl-X·CR, flipper 연결 확인, CU, 입력 브리지 HELLO, `uart_detect_baud probe=ctrl-c`).
- 그 키에 표지가 있는데 지금 장치 식별을 확인할 수 없으면(CIM 시간 초과, 강도 `none`) **표지가 유효하다고 보고 거부한다**. 확인된 식별이 표지와 다르면 낡은 표지로 보고 지운다. 장치가 목록에서 사라져도 지운다.

### 6.6 PWEH 밖 보유자와 보호 대상

| 쪽 | 처리 |
|---|---|
| Windows | 드라이버의 단일 열기 → 헬퍼 `access_denied` → `busy`. 남은 esptool.exe 는 `winproc` 로 PID 를 보여 준다. 실패한 CreateFile 이 선로를 건드리는지는 [미확인]이다(§15) |
| 리눅스 | 열기 전에 `/proc` fd 검사(같은 계정만 보임, 최선 노력), 열고 나서 TIOCEXCL |
| macOS | `/proc` 가 없다. portlock + TIOCEXCL 만 쓰고, 결과에 `busy_check: "portlock-only"` 를 적는다(조용한 fail-open 대신 표시) |

`<runtime dir>`(`/tmp/pweh-<uid>` — 표지·소유 기록)를 AGENTS.md·safety.md 의 "에이전트 수정 금지" 목록과 `.claude/settings.json` deny 규칙(제안 — 지금 deny 목록은 비어 있다)에 넣는다.
잠금 자체는 파일이 아니라서 지울 대상이 없다.

## 7. DTR/RTS 정책

백엔드별 사실:

| 백엔드 | 열 때 일어나는 일 | 신뢰도 |
|---|---|---|
| `posix-tty` (리눅스) | 커널이 **모든** open 에서(남이 연 포트를 다시 열 때도) DTR·RTS 를 올린다. pyserial 은 요청값을 DTR → RTS 순서로 적용한다. 그래서 `dtr=rts=False` 여도 짧은 펄스와 "RTS 만 켜진" 순간이 생긴다 | [높음] tty_port.c, `serialposix.py:335-338` |
| `posix-tty` (macOS) | **첫 open** 에서 DTR·RTS 를 올린다. `IOSerialBSDClient` 의 `initSession` 이 DTR 이 최근에 내려갔으면 `kDTRDownDelay`(2 s)를 기다린 뒤 `RTS\|DTR` 을 켠다. 앱이 내리기 전이다 → 리눅스와 같은 리셋 배선 위험. 활성 세션을 비배타로 다시 여는 것은 선을 다시 올리지 않는다(리눅스와 다름) | [높음 — 소스 `IOSerialBSDClient.cpp` ~2040-2066·~2400-2408 / DriverKit 직렬 드라이버는 중간] |
| `win-helper` | CreateFile 직후 첫 `SetCommState` 에서 `fDtrControl`/`fRtsControl` 을 정한다. usbser·벤더 VCP 드라이버가 CreateFile 때 스스로 선을 바꾸는지는 모른다 | [미확인] 드라이버 동작 |
| `win-powershell` | .NET `DtrEnable`·`RtsEnable` 의 기본값은 false 다 | [높음] MS Learn |
| `win-exe` esptool | esptool 의 `--before`/`--after` 가 다룬다(현행) | [높음] |

장치(식별 표 역할)별 정책:

| 장치 | 열 때 | PWEH 처리 |
|---|---|---|
| 일반 USB-UART → 대상 콘솔 (GND/TX/RX 3선) | 둘 다 끔 | INTERACT(현행). 신호선이 대상에 이어져 있지 않으니 리눅스 펄스도 해가 없다(`hardware-setup.md` §3.2 배선) |
| DTR/RTS 가 EN·IO0 에 이어진 보드(ESP DevKit 류) — 식별 표 `reset_wiring: auto-reset` | 끔. 리눅스·macOS 에서는 열 때 리셋될 수 있다 [중간] | 백엔드와 상관없이 `uart_open` 을 MODIFY(`uart.open.reset-wired`)로 분류하고 결과에 `reset_risk: "wired"` 를 넣는다. 헬퍼 경로가 펄스를 내지 않는다는 실기 확인(§15) 뒤에만 헬퍼 경로를 낮출지 정한다 |
| ESP USB-Serial/JTAG `303a:1001` (`chip-reset-on-lines`) | esptool 이 다룬다(`--before usb-reset`) | esptool 이 아닌 일반 열기는 MODIFY. esptool 은 esptool.exe 로 직접(헬퍼 아님) |
| JTAGulator (FT232R, DTR → Propeller 리셋) | 끔. 그래도 리눅스 open 은 한 번 리셋된다(`driver.py:130-138`) | 현행대로: 연결마다 재동기화하고 전압을 '미설정'으로 초기화한다. 열기 전 portlock 으로 남의 세션을 리셋하지 않는다 |
| Flipper Zero CLI (`0483:5740` `MI_00`) | **DTR 켬**, 세션 내내. 펌웨어가 DTR 켜짐 = 연결, 꺼짐 = 셸 종료로 다룬다. RTS 는 무시한다 | 헬퍼 OPEN 에서 `DTR_CONTROL_ENABLE`. 일부러 재동기화할 때만 DTR 을 내린다(게임 문서 §3.1). 근거 [높음]: flipperzero-firmware `applications/services/cli/cli_vcp.c` |
| ChameleonUltra | [미확인] | 기본 끔, 실기로 확인 |
| 입력 브리지 (ESP32-S3 DevKit, 고정 iSerial) | 둘 다 끔(게임 문서 §3.4). DevKit 이라 `auto-reset` | 헬퍼가 1차. 리눅스(usbipd) 경로에서는 열 때 리셋될 수 있음을 결과에 표시 |
| ESP32 계측기 (`303a:4002` TinyUSB CDC, MAC 고정) | 둘 다 끔. `reset_wiring: none`(USB-OTG 라 선 상태로 칩이 리셋되지 않음 — 1b 확인 전에는 `reset_risk: possible`) | 헬퍼. 고정 확인 전에는 한 바이트도 보내지 않는다(esp32-instrument §5.5) |

규칙:
- **한 번 열고, 연 핸들에서 보드레이트를 바꾼다.** `uart_detect_baud` 는 후보마다 다시 열지 않고(`baud.py:62-70`) `ser.baudrate = b` 와 입력 버퍼 비우기로 바꾼다.
  리눅스 펄스가 후보 수만큼에서 1회로 줄고, 헬퍼는 프로세스 N 개가 1 개가 된다. 결과 형식은 같다(architecture.md:301 의 "후보마다 포트를 열고" 문구 변경 — §13.3).
- **자동으로 다시 열지 않는다**(끊김·재열거 뒤, §8).
- 신호를 바꾸는 도구는 지금처럼 MODIFY 다(`uart_set_signals`, `uart_send_break`). 헬퍼에서는 `L`/`K` 프레임이 된다.
- 결과에 `reset_risk`(`none` | `possible` | `wired`)를 넣는다. pty·socket·loop 는 `none`, posix tty 와 헬퍼의 일반 장치는 `possible`, 식별 표에 배선 표시가 있으면 `wired` 다.

## 8. 재열거

| 경로 | 동작 | 신뢰도 |
|---|---|---|
| Windows (헬퍼·Windows 도구) | COM 번호는 PnP 인스턴스에 묶인다. VID/PID/시리얼이 같으면 COMn 도 같다. PID 가 바뀌면 새 인스턴스·새 드라이버다. 예: ESP32-S2/S3 ROM USB-OTG `303a:0002/0009`, Flipper DFU `0483:df11`(COM 없음), fx2lafw `0925:3881`→`1d50:608x` | [높음] 레지스트리 문서 / [중간] COM 번호 유지 |
| 리눅스·WSL(usbipd 후) | 비어 있는 minor 를 쓴다. 이전 노드가 아직 열려 있으면 `ttyACM1` 이 된다. 그래서 by-id 를 권장한다 | [중간] Espressif 문서 |
| usbipd | 리셋·재열거 때마다 attach 가 끊긴다(`--auto-attach` 필요). 새 VID:PID 는 'Not shared' 라 관리자가 bind 해야 한다. 공유 기록이 PnP 인스턴스 단위이기 때문이다 | [높음] usbipd README·`UsbipdRegistry.cs` |
| macOS | `cu.usbmodem` 접미사는 시리얼 또는 locationID 에서 나온다 | [미확인] |

PWEH 처리:
1. I/O 오류(헬퍼 `device_removed`, 파이프 끊김, `EIO`)가 나면 세션은 `disconnected` 가 된다(현행). portlock 은 `uart_close` 까지 옛 OS 객체 키로 유지한다.
2. 재열거로 이름이 바뀌면 새 이름은 새 OS 객체라 잠금이 따라가지 않는다. 대신 역할 표지는 `device_id` 로 따라간다(§6.5). 목록 도구가 같은 `device_id` 를 새 이름으로 보이면 `moved_from` 을 표시한다.
3. **다시 열기는 에이전트가 명시적으로** 한다(새 열기 = 새 분류·새 지문).
4. 식별이 바뀐 경우(새 PID)는 다른 장치로 본다. 예상되는 전환(ESP ROM OTG, Flipper DFU, fx2lafw)은 식별 표의 `transitions` 로 안내한다.
5. usbipd 경로에서 장치가 사라지면 사람에게 재attach(`--auto-attach`)나 bind 를 안내한다. 에이전트는 usbipd 를 실행하지 않는다.

## 9. 플랫폼 지원 입장과 라우팅 표

| 등급 | 플랫폼 | 뜻 |
|---|---|---|
| **1급** | WSL2 + interop (개발 환경), 네이티브 Linux | 모든 단계의 설계·시험 기준이다. fixture 기본값 |
| **최선 노력** | WSL2 interop 없음(usbipd 만), WSL1(직렬만), macOS(P5, 직렬 먼저) | 해석기·라우팅은 지원하지만 실기 시험은 없다. 문제가 생기면 안내로 처리한다 |
| **미지원** | 네이티브 Windows(서버 호스트), Cygwin, MSYS, 컨테이너 | win32/cygwin/msys 에서는 서버가 시작을 거부한다(P0). 컨테이너는 경고하고 통과된 노드만 쓴다. Windows 는 "장치 호스트"로만 쓴다(§12) |

상태 표기: **현행** = 지금 동작함, **P1–P5** = 그 단계에서 생김(§13), **미확인** = 실행해 보지 않음.
[관리자] = Windows 관리자 권한(사람), [root] = Linux·macOS root(사람).

| # | 플랫폼 | 장치 종류 | 1차 | 대체 | 사람 단계 | 위험·상태 |
|---|---|---|---|---|---|---|
| R1 | WSL2+interop | 직렬(USB-UART 콘솔·JTAGulator·Flipper·CU·입력 브리지) | `win-helper`: Windows COMn 을 헬퍼가 연다 [P2] | ① `win-powershell`(D3) ② usbipd attach → `posix-tty` `/dev/serial/by-id`·`/dev/ttyACM*` | 1차: CDC(Flipper·ESP USB-Serial/JTAG 등)는 없음(inbox usbser). FTDI/CP210x/CH34x 는 처음 꽂을 때 드라이버가 필요하다 — 온라인이고 드라이버 업데이트가 허용돼 있으면 Windows Update, 아니면 벤더 설치 프로그램 [관리자]. ②: usbipd 설치 [관리자], 세션 동안만 bind [관리자]하고 끝나면 unbind, attach 는 모드별(§10) | P2 관문 전에는 uart·jtagulator 의 Windows COM 경로가 없다(uart 는 거부, jtagulator 는 상대 경로로 엶 — G5). CreateFile 때 DTR [미확인]. 단일 열기는 드라이버 성질. usbipd 는 3240 무인증이고 attach 동안 COM 이 사라진다 |
| R2 | WSL2+interop | ESP ROM (esptool) | `win-exe` esptool.exe `--port COMn` (방법 A) [현행] | usbipd → Linux esptool `/dev/ttyACM*` | 자동 리셋 실패 시 BOOT+RESET(사람). 대체는 usbipd [관리자] | 헬퍼를 거치지 않는다(리셋 타이밍). PyInstaller 고아는 winproc 가 처리(현행). portlock·식별은 P1 |
| R3 | WSL2+interop | JTAG/SWD (OpenOCD: FTDI·CMSIS-DAP·ST-Link·ESP USB-JTAG·J-Link) | `win-exe` openocd.exe + `tcl port pipe` [P3, Windows 미확인] | usbipd → Linux xPack openocd + udev [**현행 유일**] | 1차: 어댑터별 Windows 드라이버 — FTDI 는 Zadig 로 Interface 0 만 WinUSB, ST-Link STSW-LINK009, ESP JTAG Espressif 드라이버 [관리자]. CMSIS-DAP v1(HID)·v2 는 불필요. 대체: usbipd [관리자] + udev 규칙 [root] | TCP·`bindto` 금지. pipe 는 연결 1개·재연결 없음·`openocd_attach` 불가. J-Link WinUSB 전환 [미확인] |
| R4 | WSL2+interop | 로직 애널라이저 (sigrok fx2lafw, 직렬형 드라이버) | `win-exe` sigrok-cli.exe 포터블 [P3, 미확인]. 직렬형은 `conn=COMn` | usbipd `--auto-attach` → Linux sigrok-cli [**현행 유일**] | 1차: Zadig 로 WinUSB 두 번(올리기 전 `0925:3881`, 뒤 `1d50:608x`) [관리자]. 시리얼 없는 클론(대부분)은 다른 물리 USB 포트로 옮기면 Zadig 를 다시 [관리자]. 대체: usbipd [관리자] + `61-libsigrok-plugdev.rules` [root] | 펌웨어 업로드 뒤 재열거 → usbipd 는 다시 붙여야 한다. 서명 없는 exe 는 SAC 에서 막힌다. 장치 `--scan` 은 fx2 펌웨어를 올리므로 장치 없는 확인만 한다 |
| R5 | WSL2+interop | SDR (RTL-SDR·HackRF, 수신 전용) | `win-exe` `rtl_433_64bit_static.exe`, rtl-sdr-blog exe(파일 출력), HackRF 는 conda-forge exe [P4, 서버 없음] | usbipd → Linux 도구(WSL 커널에 DVB 드라이버 없음) | RTL-SDR: Zadig Interface 0 [관리자], VC++ 런타임 [관리자]. HackRF: 펌웨어의 WCID 로 WinUSB 자동 [중간]. 대체: usbipd·udev | `rtl_tcp`·`-F http`·바이어스 티 금지. `rtl_sdr` stdout 은 CRLF 로 깨진다 → 파일 |
| R6 | WSL2+interop | 영상 캡처 | `win-exe` ffmpeg.exe `-f dshow` → rawvideo 파이프 또는 mkv(UNC), `-an` [P4, 서버 없음] | usbipd → uvcvideo + v4l2 [미확인 성능] | Windows 카메라 권한 "데스크톱 앱 허용"(사람). 대체: usbipd [관리자] | 강제 종료하면 mp4 가 손상된다 → mkv, 멈출 때는 `q` |
| R7 | WSL2, interop 없음·차단 | 모든 USB 클래스 | usbipd attach → Linux 도구(`posix-tty`, Linux esptool·openocd·sigrok·rtl·v4l2) [현행, 사람 단계] | interop 다시 켜기(`wsl.conf [interop]`, 사람) | usbipd 설치·세션 동안 bind [관리자], attach(일반 사용자, 모드별 `--host-ip`: bridged 는 Windows LAN IP, consomme 는 127.0.0.1 — usbipd ≤5.3.0), libusb 용 udev 규칙 [root], 리셋 뒤 재attach | 재열거로 attach 가 끊기고 새 VID:PID 는 'Not shared'. 3240 LAN 노출(모든 모드) |
| R8 | WSL1 | 직렬 + ESP | `posix-tty` `/dev/ttyS<n>` = `COM<n>`(lxcore, **COM1–COM191 만**). esptool 은 esptool.exe COMn 또는 Linux esptool `/dev/ttyS<n>` [P1, 최선 노력] | `win-helper`(interop 있음) | 없음 | 시험 안 함. COM192 이상은 거부(헬퍼로). lxcore 의 TIOCEXCL·flock·abstract 소켓 의미 [미확인]. USB 없음 |
| R9 | WSL1 | libusb·영상 | `win-exe` Windows 판 도구 [P3–P4] | 없음(WSL1 은 USB·usbipd 불가) | 도구별 Windows 드라이버 [관리자] | 최선 노력 |
| R10 | 네이티브 Linux | 직렬 + ESP | `posix-tty` `/dev/serial/by-id/*`(권장)·`ttyUSB*`·`ttyACM*`, Linux esptool [현행] | — | `dialout` 그룹 추가 [root 1회]. Ubuntu 22.04 는 brltty 처리 [root](CH340 `1a86:7523` 을 잡음 — §10) | 열 때 DTR/RTS 펄스(§7). TIOCEXCL·portlock 은 P1 |
| R11 | 네이티브 Linux | libusb (OpenOCD·sigrok·SDR) | Linux 도구 [현행] | — | PWEH udev 규칙(`GROUP="plugdev", MODE="0660"`, 쓰는 VID:PID 만) [root 1회]. RTL-SDR 은 `dvb_usb_rtl28xxu` blacklist [root] | xPack 규칙의 `MODE="666"` 보다 좁게 |
| R12 | 네이티브 Linux | 영상 | ffmpeg `-f v4l2` [P4] | — | `video` 그룹 [root 1회] | — |
| R13 | macOS | 직렬 + ESP | `posix-tty` `/dev/cu.*`(tty.* 거부), venv esptool [P5] | — | CP210x 등 벤더 VCP 드라이버가 필요할 수 있음 [관리자, 미확인] | 첫 open 에 DTR/RTS 가 올라간다 [높음 — 소스] → 리셋 배선 위험. `/proc` 없음 → 점유 검사는 portlock·TIOCEXCL 뿐 |
| R14 | macOS | libusb (OpenOCD·sigrok·SDR) | xPack darwin openocd, conda/Homebrew rtl-sdr, Homebrew sigrok-cli [P5] | — | FTDI 는 Apple 드라이버가 두 채널을 잡아서 libusb capture 에 root/entitlement 가 필요 [root] | FTDI 를 쓰는 동안 UART 채널이 사라진다(장치 전체 동작 — §6.2). PWEH 는 Homebrew 를 설치하지 않는다 |
| R15 | macOS | 영상 | ffmpeg `-f avfoundation` [P5] | — | TCC 카메라 권한(책임 GUI 앱) | 헤드리스(SSH·launchd)는 거부된다 [중간] |
| R16 | 네이티브 Windows | 모든 클래스 | 서버가 시작을 거부한다(P0). 서버는 WSL 에서 돌고, Windows 쪽 MCP 클라이언트가 `wsl.exe -d <배포판> -e <venv>/bin/pweh-…` 로 띄운다(사람이 클라이언트 설정) → R1–R7 적용 | (미래 이식: pyserial win32 COMn, exe 직접) | 클라이언트 설정(사람) | 이식 전에는 실행 금지(G9): 생존 검사가 `GenerateConsoleCtrlEvent` 경로로 모든 pid 를 살아 있다고 보거나 OSError, `killpg`·`SIGKILL` 은 AttributeError, 점유 검사는 fail-open |
| R17 | Cygwin·MSYS·컨테이너 | 모든 클래스 | 거부(안내) | 컨테이너: 통과된 `/dev` 노드만, 최선 노력 | — | WSL 커널 위 컨테이너를 WSL 로 오판하지 않는다(H1). 컨테이너는 portlock 을 공유하지 않는다(§6.3) |
| R18 | 모든 플랫폼 | 블록 장치 (SD 리더) | 사람이 자기 도구로 이미징 → `case_import_file` + sha256 [현행] | — | Linux root 또는 `disk` 그룹(root 와 같음), Windows 관리자(`\\.\PhysicalDriveN`), macOS root + TCC [미확인] | 에이전트 백엔드는 없다. `/dev/sd*`·`PhysicalDrive`·`wsl --mount`·usbipd usb-storage 를 거부한다. `wsl --mount` 는 SD 리더를 아예 지원하지 않으므로 WSL 로 가는 길은 usbipd usb-storage 뿐이다(거부). 헬퍼는 `\\.\COM<n>` 만 만든다(원시 읽기 헬퍼는 §11 규칙 7) |

**복합 장치 규칙:**
- Windows 드라이버는 인터페이스 단위로 붙는다(usbccgp `MI_xx`).
- usbipd 는 장치 전체를 옮기고, macOS libusb capture 도 장치 전체를 잡는다.
- 그래서 **한 물리 장치의 모든 기능은 같은 쪽**(Windows 또는 WSL)에 둔다. 장치 전체에 영향을 주는 동작은 portlock 의 "모든 인터페이스 키" 규칙(§6.2)으로 지킨다.

## 10. 사람 단계 (관리자·root 표시)

| 단계 | 권한 | 비고 |
|---|---|---|
| usbipd-win 설치(msi/winget: 서비스·드라이버·방화벽 규칙 `usbipd` — TCP 3240, LocalSubnet, 모든 프로필) | [관리자] | 선택. 대체 경로에만 필요 |
| `usbipd bind --busid X` (영구) | [관리자] | **모든 네트워킹 모드에서 세션 동안만 bind 하고 끝나면 `usbipd unbind`**. 리스너는 모든 인터페이스에서 인증 없이 받는다(`Server.cs:28,98-125`). bind 된 장치는 attach 되지 않은 동안 3240 에 닿는 LAN 호스트가 가져갈 수 있다 [높음]. 노출은 WSL 네트워킹 모드와 무관하다 |
| AutoBind 정책(`usbipd policy add … --operation AutoBind`) | [관리자] | **LAN 에 닿는 호스트에서는 금지한다.** 정책은 클라이언트 주소를 보지 않고(`Policy.cs` `IsAutoBindAllowed`: "Firewalling is not supported yet"), 원격 import 요청에도 장치를 자동 bind 하고 공유를 영구 저장한다(`ConnectedClient.cs:75-80,128-141`, `UsbipdRegistry.Persist`). 그러면 unbind 규칙이 무력해진다. 방화벽 규칙이 LocalSubnet·모든 프로필이므로 사실상 모든 PC 가 해당한다. doctor 는 정책이 보이면 경고한다 |
| `usbipd attach --wsl --busid X [--host-ip …] [--auto-attach]`, `usbipd detach` | 일반 사용자 | 모드별 아래 표 |
| USB-UART VCP 드라이버(FTDI/CP210x/CH34x) | 자동 또는 [관리자] | 처음 꽂을 때: 온라인이고 드라이버 업데이트가 허용돼 있으면 Windows Update 가 설치한다. 아니면 벤더 설치 프로그램 [관리자]. CDC(usbser)는 필요 없다. 개발 환경 의 DriverStore 에는 usbser 만 있다 |
| Zadig·벤더 드라이버 | [관리자] | FTDI Interface 0 만 WinUSB. fx2lafw 는 두 번(올리기 전·후 VID/PID). **시리얼 없는 장치는 다른 물리 포트로 옮기면 다시** 해야 한다(Windows 는 시리얼로, 없으면 USB 포트 기준으로 드라이버를 붙인다 — sigrok wiki). RTL-SDR Interface 0. ST STSW-LINK009. Espressif JTAG 드라이버. HackRF 는 펌웨어 WCID(`usb_descriptor.c:377-388`)로 자동 [중간] |
| VC++ 재배포 패키지 (rtl-sdr-blog exe) | [관리자] | 없으면 설치 |
| udev 규칙(PWEH plugdev 0660) 설치 + `udevadm control --reload` — **attach 전에** | [root] | uaccess 는 WSL 에서 쓸모없다(logind 세션 없음). `hardware-setup.md:97-102` 의 `sudo chmod` 안내를 대신한다 |
| brltty 처리(네이티브 Ubuntu 22.04) | [root] | 기본 설치된 brltty 가 CH340/CH341(`1a86:7523`)을 점자 장치로 잡아, `ch341` 이 붙자마자 `/dev/ttyUSB0` 이 사라진다(Launchpad #1990189 — 23.10 부터 수정, Jammy 는 미수정. brltty 의 usb-generic 규칙). brltty 를 지우거나 `85-brltty.rules` 를 무력화한다. doctor 가 검사한다. 이 WSL 배포판에는 brltty 가 없다 |
| `dialout`·`plugdev`·`video` 그룹 추가 | [root] | `disk` 그룹은 root 와 같으므로 넣지 않는다 |
| Windows 카메라 개인정보 설정, macOS TCC 권한 | 사람 | |
| SD 카드 이미징, 배선·전원·버튼(BOOT/RESET) | 사람 | `docs/hardware-setup.md`, `docs/safety.md`, sd-forensics §3 |

usbipd ≤5.3.0 의 attach — `wslinfo --networking-mode` 값으로 안내를 정한다(`Wsl.cs` v5.3.0 `:405-430`):

| 모드 | attach | 비고 |
|---|---|---|
| `nat` | `usbipd attach --wsl --busid X` | 기본 게이트웨이로 자동 |
| `mirrored`, `virtioproxy` | 같음 | 루프백으로 자동 |
| `consomme` | `--host-ip 127.0.0.1` 필요 | 5.3.0 은 "not supported" 로 거부한다(처리는 미출시 master f997f95a7). NAT 가 실패하면 WSL 이 조용히 consomme 로 떨어지므로 NAT 로 바꾼 PC 도 여기에 올 수 있다 |
| `bridged` | `--host-ip <Windows LAN IP>` 필요 | DHCP 라 IP 가 바뀐다. bridged 는 WSL 2.4.5 부터 deprecated |
| `none` | 불가 | 네트워크 없음 |
| `wsl1` | 불가 | WSL1 은 usbipd 를 지원하지 않는다 |
| 모름(wslinfo 실패) | usbipd 가 nat 로 가정하고 경고 | |

에이전트는 다음을 실행하지 않는다: `wsl.exe`, `usbipd.exe` 의 쓰기 명령, `usbip.exe`, Zadig, `chmod`·`udevadm`, `apt`(brltty 포함), `wsl --mount`·diskpart·mountvol.
PWEH 자신이 실행하는 것은 `usbipd --version`·`state`·`policy list`(읽기)뿐이다.

## 11. 보안 규칙 (이 문서 고유분)

1. **헬퍼는 바보 바이트 파이프다.**
   - COM1–COM4096 만 받고, 정수로 `\\.\COM<n>` 을 만든다.
   - 공유 모드 0 으로 연다. 단일 열기는 드라이버 성질이라 드라이버별로 확인한다(§5.2).
   - winsock 이 없고(PE import 검사), 명령 모드가 없고, 시작할 때 아무것도 보내지 않으며, stdin EOF 면 끝난다.
   - 실행 전에 sha256 을 모듈 상수와 대조한다.
2. **분류가 먼저다.**
   - 기기로 가는 바이트는 지금처럼 세션의 guard·분류기·게이트를 지난 뒤에야 백엔드에 닿는다. 헬퍼 transport 는 `write()` → DATA 프레임뿐이다.
   - 신호 변경은 MODIFY 게이트를 지난 `uart_set_signals`·`uart_send_break` 와, 열기 설정(열기 분류에 포함)에서만 일어난다.
   - Windows 도구는 argv 분류 뒤에 실행한다. OpenOCD 의 Tcl 은 guard 를 거친 뒤 파이프로 간다.
3. **대상 콘솔·남이 잡은 포트를 거부한다.** portlock 보유(승인 대기 중 포함)와 역할 표지로 판단한다(§6). 재동기화·프로브 바이트를 보내는 도구는 열기 전에 거절한다.
4. **승인 지문에 장치를 넣는다.** 열기·연결 동작의 `action` 에 `route{backend, lock_key, device_id}` 를 넣는다(§4.3). 식별이 흔들리면 `approval_mismatch` 다(fail closed, 문서화한 동작).
5. **리스너는 금지한다.**
   - 서버·헬퍼·시뮬레이터(기본)는 소켓을 듣지 않는다. portlock 의 abstract 소켓은 bind 만 하고 listen 하지 않는다.
   - Windows 도구의 리스너 옵션은 거부한다. URL 은 루프백만 받는다(LAN 은 `safety.ports.remote_serial_hosts`).
   - 이미 WSL 에서 0.0.0.0 으로 열린 서비스는 bridged 에서 LAN 에 노출된다. PWEH 와 무관하지만 doctor 가 알린다(목록만, 스캔 안 함).
6. **interop 은 root 와 같고, UAC 가 꺼진 호스트에서는 Windows 관리자와도 같으므로 실행 파일을 허용 목록으로 묶는다.** `wininterop.run()` 은 아래만 실행한다.

   | 실행 파일 | 조건 |
   |---|---|
   | 고정 헬퍼 | sha256 대조 |
   | `System32\WindowsPowerShell\v1.0\powershell.exe` | 코드에 박힌 스크립트만 |
   | 설정 도구 | basename 이 `esptool.exe`, `openocd.exe`, `sigrok-cli.exe`, `ffmpeg.exe`, `rtl_433_64bit_static.exe`, `rtl_sdr.exe`, `rtl_power.exe`, `rtl_test.exe`, `rtl_eeprom.exe`(쓰기 인자 `-m/-p/-s/-b/-g/-w` 거부), `hackrf_info.exe`, `hackrf_transfer.exe`(송신 플래그 거부), `hackrf_sweep.exe` 중 하나 |
   | `usbipd.exe` | `--version`·`state`·`policy list` 만 |

   그 밖은 모두 거부한다. 특히 `wsl.exe`, `wslconfig.exe`, `bash.exe`, `cmd.exe`, `*.bat`/`*.cmd`, `reg.exe`, `usbip.exe`, `wusbip.exe`, `rtl_tcp.exe`, `rtl_biast.exe`, `zadig*.exe`, `espefuse*`·`espsecure*`, diskpart·mountvol 이다.
7. **블록 장치는 거부한다**(R18). 헬퍼 문법상 디스크를 열 수 없다.
   SD 포렌식의 (선택) Windows 원시 읽기 헬퍼(sd-forensics §3·§10)를 만든다면 `pweh-serial-helper.exe` 와 다른 실행 파일이어야 하고, 자기 허용 목록 항목과 대상 식별 규칙이 필요하다. 지금 허용 목록에는 없다.
8. **override 는 완화하지 못한다.** 허용을 넓히는 값은 `safety.ports.*` 에만 둔다(에이전트 수정 금지, 제안). 감지·헬퍼 신뢰를 바꾸는 환경 변수·설정 키는 없다. 시험 seam 은 프로세스 안 주입뿐이다(§14).
9. **감사 기록.** 열기 이벤트에 `route`·`device_id`·`reset_risk` 를 남긴다. 헬퍼 `E` 프레임, `access_denied`, portlock 의 `busy`(`awaiting_approval` 포함)도 남긴다.
10. **보호 대상을 넓힌다.** `<runtime dir>`(`/tmp/pweh-<uid>` — 표지·소유 기록)를 AGENTS.md·safety.md 의 "에이전트 수정 금지" 목록에 추가한다(승인 파일·`safety` 설정과 같은 급). `.claude/settings.json` deny 규칙도 제안한다.

## 12. 비용 — 네이티브 Windows 와 macOS

**네이티브 Windows (서버 호스트): 미지원으로 둔다.** P0 에서 `pweh.mcpkit.create_server` 가 `sys.platform ∈ {win32, cygwin, msys}` 이면 시작을 거부하고 안내한다.
서버 모듈은 최상위에서 termios·pty 를 import 하지 않으므로 이 거부에 닿는다(jtagulator 서버는 sim 이 아니라 driver 를 import 한다).
이 안전망이 싼 이유는 G9 다. 이식하지 않은 채 돌면 생존 검사가 `GenerateConsoleCtrlEvent` 경로로 모든 pid 를 살아 있다고 보거나 OSError 를 내고, `killpg`·`SIGKILL` 은 AttributeError 를 내며, `/proc` 없는 점유 검사는 fail-open 이다.
Windows 쪽 MCP 클라이언트는 사람이 설정한 `wsl.exe -d <배포판> -e …/.venv/bin/pweh-<서버>` 로 WSL 의 서버를 띄운다 [미확인 — stdio 중계 미시험].
`pweh mcp-config` 에 이 형식을 만드는 옵션을 두는 것은 후속(선택)이다. `-u root` 는 넣지 않는다.

실제 이식에 드는 것:
- 프로세스 그룹·종료를 4곳에서 다시 만든다: `CREATE_NEW_PROCESS_GROUP` + Job Object(`KILL_ON_JOB_CLOSE`)를 ctypes 로.
- PID 생존 확인을 `OpenProcess`·`GetExitCodeProcess` 로 바꾼다.
- `/proc` 기능(입양, PID 재사용 감지, 점유 검사)을 Toolhelp32 등으로 바꾼다.
- portlock 의 abstract 소켓을 Windows 이름 있는 mutex 로 바꾼다.
- PTY 기반 시뮬레이터·시험 하네스를 socket 이나 가상 COM(com0com, 드라이버 설치 = 관리자)으로 바꾼다.
- 설치기를 PowerShell 로, 런처를 `.venv\Scripts` 로 바꾼다. Windows CI 를 새로 만든다.

이 작업은 **수 주** 규모이고, 이후 두 플랫폼을 함께 유지해야 한다. 이 사용자는 WSL2 + interop 으로 이미 Windows 장치에 닿으므로 얻는 것이 거의 없다.

**macOS: 최선 노력, 요청이 생길 때(P5).** 서버는 대부분 POSIX 라서 최소 작업은 아래와 같다.
- 해석기: `cu.*` 를 받는다.
- esp: `linux` 백엔드를 `posix` 로 일반화한다(`/dev/cu.*`, venv esptool). `backend` 값을 추가하므로 architecture §6.7 을 고친다.
- `/proc` 점유 검사 대신 portlock(flock-file)만 쓰고, 그렇다고 표시한다. openocd 입양은 꺼진 채로 둔다.
- 설치기를 표준 라이브러리 Python(`scripts/install.py`)으로 옮긴다. macOS 에는 bash 3.2 만 있고 `timeout`·`sha256sum` 이 없다.
  Homebrew prefix 는 기본값보다 길 수 없다(Apple Silicon 은 `/opt/homebrew` 13바이트, Intel 은 `/usr/local` 10바이트 이하). 그래서 `~/pweh-tools` 아래에 둘 수 없고, PWEH 는 Homebrew 를 설치하지 않고 "있으면 쓴다".
- 도구 원본: xPack darwin openocd, sdist esptool. rtl-sdr·ffmpeg·libusb 는 micromamba. sigrok·rtl_433·flashrom 은 Homebrew 가 있으면 쓴다.

규모는 **1–2주**다. Mac 실기가 없어 검증할 수 없으므로 지금 하지 않는다.

## 13. 이전 계획 (단계)

### 13.1 시험 seam 보존

- 코어 함수는 의존성을 인자로 받는다. 예: `hostenv.detect(probe=…)`, `ports.validate_ref(p, exists=…, realpath=…)`, `wininterop.list_com_ports(status=…, run_ps=…)`, `portlock.PortLock(namespace=…)`.
- `esp_mcp/ports.py` 는 같은 이름의 얇은 래퍼로 남는다. 래퍼는 자기 모듈 속성을 **늦게 묶어** 넘긴다(`exists=lambda p: path_exists(p)`).
  그래서 지금의 `monkeypatch.setattr(ports, "...")` 가 그대로 통한다(`tests/servers/test_esp_mcp.py:78-89,341-348,713,738,748,766,1638`). `winproc` 는 계속 `ports.run_powershell` 을 부른다(`esp_mcp/winproc.py:150,163,246`).
- **새 seam**: 열기 전 장치 식별 질의는 PowerShell CIM 을 부른다. esp `fake` fixture 는 `ports.run_powershell` 을 바꾸지 않으므로(`test_esp_mcp.py:78-89`), 그대로 두면 WSL 개발 PC 에서는 진짜 powershell.exe 를 부르고 CI 에서는 ToolMissing 이 난다.
  - 호출 사슬: esp 호출 지점은 esp 의 늦게 묶인 `ports.run_powershell` 을 코어(`ports.list_serial`, 식별 질의)에 넘긴다. 그 함수의 기본 구현은 `pweh.wininterop.run_powershell` 에 위임한다.
  - conftest 의 autouse fixture 는 `pweh.wininterop.run_powershell` 과 헬퍼 실행기만 "사용 불가"로 바꾼다. 그래서 패치하지 않은 경로의 식별은 결정적으로 `strength: none`·`device_id: null` 이 된다.
  - 시험이 `ports.run_powershell` 을 직접 바꾼 경로(`test_esp_mcp.py:740-758` 의 COM3·COM7·COM9 목록)는 그 패치가 이긴다. `@pytest.mark.external` 시험은 autouse fixture 를 끈다.
- **합격 기준(정직하게)**: esp 시험은 지문 단정만 바뀐다(+ autouse fixture). 목록 결과는 필드 추가와 §13.3 의 의미 변화만 허용한다.

### 13.2 단계

> **구현 상태 (I4 = P0, 2026-10-20)**: `pweh.hostenv`(결정 트리 H0–H9, `pweh.hostenv/v1`, 추천 경로, Windows 실행 허용 목록 — wsl/cmd/reg/usbip 실행 안 함), `pweh env`, doctor 환경 절
> (가짜 ttyS 숨김, WSL1/2, 모드별 usbipd 안내, esptool.exe 해석 통일, brltty·AutoBind·UAC 경고), `pipeline_environment()`, esp 의 WSL 감지·`/mnt/c` 를 hostenv 로(G6·G7),
> install.sh `wsl_interop` 규칙 통일, uart·jtagulator 원격 URL 루프백만(정규형으로 바꿈, pyserial URL 옵션 거부 — D4, `safety.ports.remote_serial_hosts` 는 아직 없음), uart COM1–COM4096,
> 시뮬레이터 루프백 바인드(`--allow-lan` 때만 LAN, G13), 네이티브 Windows·Cygwin·MSYS 시작 거부와 `procutil.pid_alive`(G9 — openocd 만 옮김, 나머지 killpg 는 P1).
> 설계와 다른 점: 코어 `pweh.ports` 는 P1 의 씨앗(문법 검사만), doctor 의 COM 별 `Service` 는 interop 이 될 때만, 보고서에 esptool.exe 버전·`ghost_ports_hidden`·`portlock` 은 없음.
> 남은 usbipd 전용 안내: uart·sigrok·openocd 의 일부 힌트(P1·P2 에서 경로 기반으로).

| 단계 | 내용 | 합격 기준 |
|---|---|---|
| **P0** 감지·안전 정리 (동작 변화 최소) | `pweh.hostenv` + `pweh env` + doctor 환경 절(가짜 ttyS 숨김 — esp 규칙, WSL1/2 구분, 모드별 usbipd 힌트, esptool.exe 해석 통일, COM 별 `Service`, brltty·AutoBind·UAC 경고). `pipeline_environment()`(pweh-case). socket·rfc2217 루프백 검사(uart·jtagulator, D4 — 스킴 허용 목록은 uart 에 이미 있음). uart `_WIN_COM_RE` 에 상한 4096. win32·cygwin·msys 시작 거부와 코어 `procutil.pid_alive`(Windows 에서는 `os.kill(pid,0)` 금지)(G9). WSL 감지 통일(G6)·`/mnt/c` 제거(G7). 시뮬레이터 `--host`·`--tcp` 루프백 강제(G13) | 기존 시험 통과(§13.3 의 바뀌는 단정 제외). hostenv 주입 시험. URL·COM 문법 시험 |
| **P1** 식별·portlock·TIOCEXCL (기존 경로 위에) | `pweh.ports`(문법·해석·열거·식별 표 `usb-ids.yaml`)와 `pweh.portlock`(OS 객체 키, abstract 이름, 장치 전체 동작, 역할 표지, 승인 대기 의미)을 uart(open·detect_baud)·jtagulator(connect)·esp(esptool 실행 전)·sigrok(직렬 conn)에 적용한다. 열기 순서 §5.1, TIOCEXCL/TIOCNXCL. `uart_detect_baud` 를 한 번만 열게 바꾼다. 결과에 `route`·`device_id`·`held_by` 를 추가하고, 열기·연결 지문에 `route` 를 넣는다. 4곳의 killpg 를 코어 `procutil` 로 모은다. 받을 수 없는 경로의 COMn 은 jtagulator·sigrok 에서도 명확한 오류로 바꾼다(G5) | 다중 프로세스 잠금 시험. "거부된 열기는 `os.open` 을 부르지 않는다" 시험. 승인 대기 중 busy·거부 뒤 해제 시험. esp 시험은 지문 단정만 변경 |
| **P2** Windows COM 헬퍼 (진행/중단 관문 = 게임 문서 1b) | `tools/winserial` 소스·zig 빌드·`SHA256SUMS`·사전 빌드, 재현 빌드 확인(D3), install.sh `winserial` 구성요소(gate: `wsl_interop`). `pweh.winserial.HelperSerial` + 가짜 헬퍼. PowerShell 대체(기본 꺼짐). uart·jtagulator 가 WSL2 에서 COMn → `win-helper`, WSL1 은 ttyS. 목록 도구가 Windows COM 을 합쳐 보인다 | external: 헬퍼 HELLO·echo 256값·EOF 종료·PE import. hardware: USB-UART 루프백, Flipper DTR → `>: `, 드라이버별 두 번째 열기. 실패하면 PowerShell 대체 또는 usbipd 로 |
| **P3** Windows 판 libusb 도구 | (D7 동의 뒤) openocd.exe dummy + `tcl port pipe` 확인 → openocd-mcp pipe transport(재연결 없음, attach 불가, 준비 줄 변경, `-f/-s`·덤프 경로 `wslpath -w`). sigrok-cli.exe 포터블(7z 해제 + 목록 검증). install.sh Windows 구성요소. doctor 가 USB 장치마다 Windows `Service`(WINUSB/FTDIBUS/usbser)를 보여 Zadig 가 필요한지 안내한다. libusb 인터페이스 portlock 키 | 가짜 openocd 의 pipe 모드 시험, 실제 dummy(external·opt-in) |
| **P4** SDR·영상 (새 서버) | pweh-sdr, pweh-play 캡처를 같은 wininterop 규칙으로(rtl_sdr 은 파일 출력, ffmpeg `q`·`-an`, 리스너 옵션 거부) | 게임 문서 §8 의 가짜 도구 |
| **P5** macOS 최선 노력 (요청 시) | §12 최소 목록 | macOS fixture 시험만 |

**어떤 도구가 Windows COM 을 얻나:**
- pweh-uart: 세션 도구 전부, P2. usbipd 없이 Windows COM 의 USB-UART 어댑터를 쓴다.
- pweh-jtagulator: `jtagulator_connect` COMn, P2. 지금은 받지만 라우팅되지 않는다(G5).
- 계획된 pweh-flipper·pweh-nfc(CU)·pweh-play 입력 브리지: 처음부터 헬퍼를 쓴다.
- pweh-sigrok 직렬형 드라이버: 헬퍼가 아니라 sigrok-cli.exe `conn=COMn`(P3). sigrok-cli 가 로컬 tty 를 직접 열기 때문이다.
- pweh-esp: esptool.exe 직접(헬퍼 아님). portlock·식별만 공유한다.
- pweh-espprobe(ESP32 계측기): 처음부터 헬퍼(esp32-instrument.md).

### 13.3 계약 변경 (architecture §6 절별)

도구 이름·인자는 그대로다(새 도구는 `pipeline_environment` 하나). 그러나 받는 `port` 값이 좁아지고 일부 반환의 의미가 바뀌므로 절마다 적는다.

| 절 | 바뀌는 것 | 지금 문구 | 함께 고칠 시험·문서 |
|---|---|---|---|
| §6.1 pweh-case | `pipeline_environment()` 추가(OBSERVE) | — | 카탈로그 재생성·`--check`. `.claude/settings.json` 변경 불필요(`mcp__pweh-case__*` 허용) |
| §6.2 pweh-uart | `uart_list_ports`: 가짜 ttyS 행 제거(`hidden_legacy_ports` 개수), Windows COM 행 추가(`device`="COMn", `owner_side`·`route`·`device_id`·`held_by`), `env_kind`. 빈 목록 힌트는 경로 기반으로 | `architecture.md:289` | uart 목록 시험 |
| §6.2 | `uart_open`·`uart_detect_baud` 의 port: "(Windows 가 아닌 곳의) COMn → validation_failed" 가 WSL2+interop 에서는 헬퍼 라우팅(P2), WSL1 은 COM1–191 로 바뀐다. socket·rfc2217 호스트는 루프백만(D4 — LAN ser2net 안내도 바뀜) | `:289`(ser2net), `:290` | `tests/servers/test_uart_mcp.py:619-620,653`(COM3·com12 를 무효로 단정 → hostenv 주입으로 환경을 고정해 나눠 단정) |
| §6.2 | 위험도·동작 문구: "DTR/RTS 는 열기 전에 설정하며 기본 False 로 두어 보드 리셋을 피한다" → 리눅스·macOS 는 열 때 펄스(§7). reset-wired 식별이면 MODIFY `uart.open.reset-wired`. TIOCEXCL(PWEH 밖 프로그램도 동시에 못 엶). 열기 지문에 `route` | `:290` | uart 게이트 시험 |
| §6.2 | `uart_detect_baud`: "후보마다 포트를 열고" → 한 번 열고 보드레이트만 바꾼다 | `:301` | baud 시험 |
| §6.3 pweh-sigrok | 직렬형 `conn=COMn`: 존재 확인·portlock, P3 에서 sigrok-cli.exe 로 | §6.3 | sigrok 정책 시험 |
| §6.4 pweh-openocd | (P3) Windows 백엔드: `tcl port pipe`, 재연결 없음, `openocd_attach` 불가, 준비 판정 줄 변경. `:365`(TCL 127.0.0.1)은 그대로 맞다 | `:372`(준비 = `Listening on port N for tcl connections`) | 가짜 openocd pipe 모드 |
| §6.5 pweh-jtagulator | 원격 URL 축소(루프백만, LAN 은 `safety.ports.remote_serial_hosts`), COMn 은 WSL2·WSL1 에서만 라우팅(그 밖은 validation_failed), 키 정규화(`lock_key`), 연결 지문에 `route` | `:194`, `:410`; `docs/safety.md:255` | `tests/servers/test_jtagulator_gate.py:66-69`(`rfc2217://10.0.0.2:4000` 과 COM3 을 어디서나 유효로 단정) |
| §6.7 pweh-esp | 포트 문법 COM1–256 → COM1–4096, 승인 지문 문단에 `route`·`device_id`, (P5) macOS `cu.*`·`posix` 백엔드 | `:476`, 지문 문단 | esp 지문 시험 |
| 설치 | install.sh 구성요소 `winserial`(P2), `openocd-win`·`sigrok-win`(P3) | — | `tests/core/test_install_script.py:16` 의 `COMPONENTS` |
| safety.md | §3.3 jtagulator 줄, §3.4 portlock·TIOCEXCL 한계·리스너 규칙·interop 실행 허용 목록 | `docs/safety.md:255`, §3.4 | — |

### 13.4 AGENTS.md 가 요구하는 후속 (각 단계 끝)

- `.venv/bin/python scripts/dump_tool_catalog.py` 로 카탈로그를 다시 만들고 `--check` 로 검사한다. architecture §6 표를 §13.3 대로 고친다.
- Skill 을 고친다: `uart-shell-acquisition`(39·328), `firmware-dump-via-uart`(32·117·268), `esp32-flash-dump`, `logic-analyzer-protocol-decode` 의 usbipd 전용 문구를 경로 기반 안내로 바꾼다.
- `orchestrator/master-prompt.md` 를 고친다: 174·215행, Phase 0 에서 `pipeline_environment()` 호출(77행의 ESP32 예외는 이미 있음).
- `hardware-setup.md` 를 고친다: §2.2 방법 A 일반화·모드별 attach·세션 동안만 bind·AutoBind 금지, §2.3 udev 문구 교체(97-102), brltty.
- `safety.md` 를 고친다: §13.3 의 줄.
- AGENTS.md 의 보호 경로에 `/tmp/pweh-<uid>`(§6.3 `<runtime dir>`)를 추가하고, `.claude/settings.json` deny 규칙을 제안한다.
- 조사 노트의 도구별 바이너리·라이선스·sha256·설치 구성요소 표를 `docs/references/` 로 옮긴다.

## 14. 시험 전략 (하드웨어 없이)

- **원칙**: 운영 코드에는 시험용 환경 변수 분기가 없다. 가짜는 모두 프로세스 안 주입(인자·monkeypatch)이다.
  예외는 conftest 만 읽는 opt-in 이다: 내려받은 Windows 바이너리를 실제로 실행하는 시험의 `PWEH_RUN_WIN_TOOLS=1`(`PWEH_HARDWARE` 와 같은 급).
- **감지(hostenv)**
  - probe 를 주입 객체로 바꾼다(파일 읽기, exists, 실행, which, env, `sys.platform`, machine).
  - fixture 10종: WSL2-interop-bridged(개발 환경), WSL2-interop-nat, WSL2-consomme(NAT 대체), WSL2-no-interop, WSL1, WSL-unknown-version, native-linux(brltty 있음), macOS-arm64, windows-native, container-on-WSL-kernel.
  - 함정 사례: `WSLInterop-late` 만 있음(받음), WSLInterop enabled + binfmt `status` disabled(여전히 사용 가능 — 참고 값), 사용자 커널 문자열 + wslinfo `wsl1`/`nat`/종료 1, `virtioproxy` 출력, usbip.exe 는 있고 usbipd.exe 는 없음, UBR 합성(`10.0.<build>.0` + 레지스트리 UBR), 컨테이너 안의 WSL 커널 문자열.
- **해석기**
  - 문법: COM0·COM01·COM4097 거부, COM4096 받음, WSL1 COM192 거부, `cu.*` vs `tty.*`, by-id, pts, URL 허용 목록과 루프백, `spy`·`hwgrep`·`alt`·`cp2110` 거부, 제어 문자.
  - 환경 fixture 마다 경로 표(§4.2)를 시험한다. "COMn 은 `serial_for_url` 에 닿기 전에 거부/라우팅된다"를 확인한다.
- **열거·식별**: 미리 만든 CIM JSON 을 쓴다(esp `parse_windows_ports` 선례).
  - Flipper 복합(`MI_00`/`MI_02` + 부모 시리얼), 시리얼 없는 CH340(위치 기반 인스턴스 id), FT2232H(`MI_00` WinUSB + `MI_01` FTDIBUS), ESP `303a:1001`(CDC + JTAG), `Status=Unknown` 유령 항목.
  - 같은 시리얼 `0001` 두 개: 강도는 떨어지고 `device_id` 는 그대로인지 본다.
  - 가짜 포트는 esp 규칙 그대로다(`test_esp_mcp.py:758` 유지). sysfs `type` 은 주입한 reader 로만 읽는다.
- **가짜 헬퍼**: `tests/servers/fake_serial_helper.py` 를 시험 중에 `pweh-serial-helper.exe` 라는 이름으로 복사한다(가짜 esptool 의 `.exe` 규칙. MZ 가 아닌 `.exe` 는 interop 없이 돈다 — `tests/core/test_install_script.py:124` 선례).
  - 뒤쪽: 메모리 루프백, mocktarget PTY 중계, 오류 주입(OPEN 때 `access_denied`, N 바이트 뒤 `device_removed`, HELLO 버전 불일치, 깨진 프레임, 느린 OPEN, EOF 무시).
  - 신뢰: 가짜의 sha256 을 시험 안에서 `pweh.winserial.PINNED_SHA256` 에 monkeypatch 한다. 설정 스키마 시험으로 "핀을 늘리는 설정 키·환경 변수가 없다"를 확인한다.
  - uart 시험의 매개변수화는 전송과 무관한 시험(I/O, guard, close/reopen, 보드레이트 변경)만 {pty, fake-helper} 로 한다. 백엔드별 시험은 따로 둔다: pty 는 `uart_set_signals` = unsupported(`test_uart_mcp.py:576-577` 그대로), 헬퍼는 `L` 프레임 기록.
  - 가짜 헬퍼는 받은 프레임과 모뎀 선 상태를 기록한다. 시험이 확인할 것: DTR/RTS 가 DATA 보다 먼저 OPEN 에서 정해진다, guard 가 거부한 쓰기는 DATA 프레임을 만들지 않는다, 정책이 거부한 `uart_set_signals` 는 `L` 프레임을 만들지 않는다.
- **portlock**
  - 시험마다 무작위 namespace 를 주입해 실제 서버의 잠금과 부딪히지 않게 한다.
  - 두 Python 프로세스가 다툰다. 보유자를 SIGKILL 하면 즉시 풀린다.
  - 별명(by-id 링크·realpath·pts)이 같은 rdev 키가 되는지, WSL1 `ttyS3` 과 `COM3` 이 같은 키인지 본다.
  - 장치 전체 동작: 형제를 모두 잡는지, 열거가 실패하면 거부하는지 본다.
  - 승인 대기: 느린 가짜 authorize 동안 다른 호출이 `busy` + `awaiting_approval` 을 받는지, `approval_required`·거부·취소 뒤 풀리는지 본다.
  - **거부된 열기는 `os.open`·`serial_for_url` 을 부르지 않는다**(감시 함수로 확인). PTY 로는 DTR 을 볼 수 없으니 이것이 G2 의 소프트웨어 시험이다.
  - flock-file 대체: 잠금 파일을 지우고 다시 만든 뒤 inode 비교로 다시 시도하는지 본다.
- **TIOCEXCL**
  - pty slave 에 TIOCEXCL 을 건 뒤 두 번째 열기가 EBUSY → `busy` 가 되는지 본다.
  - **open → close → open** 을 시험한다. 시뮬레이터가 slave fd 를 계속 쥐고 있는 pty 에서도 두 번째 open 이 성공해야 한다(close 의 TIOCNXCL).
  - root 로 도는 CI 는 CAP_SYS_ADMIN 예외가 있으니 `euid==0` 이면 EBUSY 시험을 skip 한다.
- **승인 지문**: device A 의 COM3 으로 만든 승인이 같은 이름의 device B 로 다시 해석되면 `approval_mismatch` 가 되는지 본다. 식별 모름(`null`) ↔ 앎도 mismatch 다(문서화한 동작). esp 지문 시험도 갱신한다.
- **바뀌는 기존 단정**: `test_uart_mcp.py:619-620,653`, `test_jtagulator_gate.py:66-69`, `tests/core/test_install_script.py:16`(§13.3).
- **doctor·env**: 보고서 객체를 렌더러에 넣은 출력 스냅샷(fixture 별).
- **external** (`@pytest.mark.external`, 도구·interop 이 없으면 skip)
  - 실제 헬퍼의 HELLO, `--echo` 모드(COM 없음)로 256 값 왕복, EOF 뒤 프로세스 종료 확인
  - 빌드 산출물의 PE import 허용 목록(표준 라이브러리로 PE 파싱), 재현 빌드(두 번 빌드한 sha256 비교)
  - 실제 powershell CIM 목록 해석(포트는 열지 않음), `wslinfo --networking-mode`
  - Windows openocd.exe dummy pipe — 내려받은 exe 를 실행하므로 `PWEH_RUN_WIN_TOOLS=1` 일 때만(D7)
- **hardware** (`@pytest.mark.hardware`): §15 의 루프백·DTR 관찰.

## 15. 하드웨어로 확인할 것

| 장치 | 확인할 관찰 |
|---|---|
| USB-UART 어댑터(CP210x 또는 FTDI) + TX–RX 루프백 | 헬퍼로 256 값 왕복, 115200·921600 baud, BREAK, 보드레이트 변경(`B` 프레임)이 맞는지(게임 문서 1b 관문) |
| 같은 어댑터의 DTR·RTS 핀 + 로직 애널라이저(sigrok) 또는 스코프 | ① 헬퍼 OPEN(`dtr=rts=0`) 때 CreateFile~SetCommState 사이 펄스가 있는지(usbser·CP210x·CH340·FTDI VCP 각각) ② 리눅스(usbipd 뒤) pyserial open 의 펄스 모양과 RTS 단독 구간 ③ **보유자가 `dtr=False` 로 연 포트를 두 번째 프로세스가 exclusive 로 열려다 거부될 때 보유자 선로의 DTR/RTS 가 올라가는지**(G2), TIOCEXCL 을 건 뒤에는 안 올라가는지 |
| Windows 단일 열기 — 드라이버별(usbser·FTDIBUS·silabser·CH341SER) | 이미 열린 COM 에 두 번째 CreateFile → `ERROR_ACCESS_DENIED` 인지, 실패한 열기가 선로를 건드리지 않는지(LA). 두 번째 열기가 성공하는 드라이버는 결과 표시 대상(§5.2) |
| ESP32 DevKit(자동 리셋 회로) | 리눅스 일반 열기로 리셋되는지(콘솔 부팅 로그), 헬퍼 열기로는 리셋되지 않는지 → 헬퍼 경로의 reset-wired 분류를 낮출지 정한다(§7) |
| JTAGulator | 열기 전 portlock 이 uart 세션의 포트를 건드리지 않는지. 헬퍼로 연결할 때도 리셋·재동기화·전압 초기화가 지금처럼 동작하는지 |
| Flipper Zero | 헬퍼 OPEN `dtr=1` → 배너·`>: `, `info device`, 1 MB storage md5 왕복(처리량·지연), DTR 내림 → 셸 종료, 단일↔이중 CDC 전환 때 COM 번호 변화(게임 문서 §9) |
| 서버 강제 종료(SIGKILL) | 헬퍼가 stdin EOF 로 끝나고 COM 이 곧바로 다시 열리는지(Windows 작업 관리자로 프로세스가 없는지), abstract 잠금이 풀리는지 |
| ESP32-S3 USB-Serial/JTAG·S2/S3 ROM OTG | esptool 리셋 뒤 COM 번호가 유지되는지, ROM OTG 는 새 COM 인지, 장치 전체 잠금이 두 인터페이스를 함께 잡는지 |
| 시리얼 없는 CH340 | 같은 USB 포트에서는 같은 COM 인지, 다른 포트에 꽂으면 새 식별(location)인지 |
| (네이티브 Ubuntu 22.04 가 있을 때) CH340 + brltty | `/dev/ttyUSB0` 이 사라지는지, doctor 가 경고하는지, 처리 뒤 정상인지 |
| (하드웨어 불필요) 두 번째 WSL2 배포판 | 두 배포판에서 같은 abstract 이름 bind 가 부딪히는지(network namespace 공유 확인, §6.3) |
| (동의 필요, 하드웨어 불필요) xPack Windows openocd.exe | dummy 어댑터 + `tcl port pipe` 로 RPC 왕복, stdin EOF 종료(P3 진입 조건) |
| FTDI JTAG 어댑터(Interface 0 WinUSB, Zadig [관리자]) | openocd.exe pipe 로 `scan_chain`, Interface 1 의 COM 을 동시에 쓸 수 있는지 |
| fx2lafw LA(Zadig 두 번 [관리자]) | sigrok-cli.exe 포터블 트리가 펌웨어·디코더를 찾는지, 캡처 binary stdout 이 맞는지, 시리얼 없는 클론을 다른 포트로 옮긴 뒤 Zadig 가 다시 필요한지 |
| HackRF(있을 때) | 펌웨어 WCID 로 WinUSB 가 자동으로 붙는지 |
| (사용자가 고를 때) usbipd | 모드별 attach(bridged 는 `--host-ip` LAN IP, consomme 는 `--host-ip 127.0.0.1`), udev 규칙 뒤 libusb 접근, 리셋 뒤 재attach, attach 동안 COM 이 사라지는지, 세션 뒤 unbind — 모두 사람이 실행 |
| 다른 LAN 호스트(사람) | bridged 에서 WSL 리스너·Hyper-V 방화벽 적용 여부(WSL 의 0.0.0.0 서비스 노출 확인) |
| (Mac 이 있을 때) macOS | `/dev/cu.*` 첫 open 의 DTR/RTS(소스상 올림 — LA 로 확인), 비배타 재열기가 다시 올리지 않는지, CH34x/CP210x 내장 드라이버, TIOCEXCL·flock |
| ESP32-S3 계측기(esp32-instrument §9) | TinyUSB CDC 두 개가 MI_00/MI_02 로 보이는지, 부팅 창(303a:1001) 동안의 PnP 변화, 다운로드 모드 진입 때 핀 상태, DTR/RTS 끈 열기가 리셋·부작용을 내지 않는지, 303a:1001 iSerial 과 eFuse MAC 일치 |

## 16. 사용자 결정 (기본값 포함)

| # | 결정 | 기본값(권장) |
|---|---|---|
| D1 | 이 설계의 문서 위치 | **확정(반영됨)**: 별도 문서 `docs/design/port-routing.md`. common-core §2 에는 요약과 링크만 두고, common-core §1 표의 모듈 이름·전송 방식·portlock 의미를 이 문서에 맞췄다 |
| D2 | WSL2 의 기본 연결 경로와 usbipd 의 위치 | 기본은 Windows 쪽(헬퍼·Windows 판 도구)이다. usbipd 는 "사람이 고르는 대체 경로"로만 문서화한다. **모든 네트워킹 모드에서** 세션 동안만 bind 하고 끝나면 unbind 한다. AutoBind 정책은 쓰지 않는다(LAN 에 닿는 호스트에서는 금지). bridged 는 그대로 둔다(PWEH 는 리스너를 만들지 않는다). usbipd 를 자주 쓸 계획이면 mirrored 전환을 검토한다. NAT 는 실패하면 조용히 consomme 로 떨어지고, 그때 usbipd ≤5.3.0 은 `--host-ip 127.0.0.1` 이 필요하다(bridged 는 WSL 2.4.5 부터 deprecated) |
| D3 | Windows COM 전송 구현과 헬퍼 신뢰 | 저장소의 C 소스를 zig 로 빌드한 헬퍼 + 고정 sha256 사전 빌드. 실행 때 sha256 을 모듈 상수와 대조하고, 설정·환경 변수로 핀을 늘릴 수 없다. zig 빌드가 재현되면 로컬 빌드도 같은 핀으로 받고, 재현되지 않으면 배포한 사전 빌드만 믿는다(로컬 빌드는 유지보수자가 커밋으로 핀 갱신). PowerShell .NET 대체는 꺼 두고, 헬퍼 실기 관문에 실패하거나 Smart App Control 이 켜진 PC 에서만 켠다 |
| D4 | 원격 시리얼 URL | `socket://`·`rfc2217://` 는 루프백만 받는다. LAN 호스트는 운영자가 `safety.ports.remote_serial_hosts`(새 중첩 키 — `SafetyConfig` 확장 필요)에 넣을 때만 받는다. `spy`·`hwgrep`·`alt`·`cp2110` 은 항상 거부한다(uart 는 이미 거부). 영향: jtagulator 의 문서화된 원격 URL(architecture.md:194·410, safety.md:255)과 `test_jtagulator_gate.py:66-69` 를 고친다 |
| D5 | 계약 강화 묶음 | 수용한다: 열기·연결 지문에 `route{backend, lock_key, device_id}`(esp §6.7 문단 변경 — 식별이 흔들리면 `approval_mismatch` 로 재승인), 리셋 배선 장치의 `uart_open` = MODIFY, `uart_detect_baud` 단일 열기, TIOCEXCL(PWEH 밖 minicom 등도 동시에 열 수 없게 됨). TIOCEXCL 구현은 기본으로 stock pyserial `open()` 직후에 건다(PWEH 밖 프로그램에 수 ms 창이 남음). 창까지 닫으려면 `open()` 을 재정의한 하위 클래스를 쓴다(선택, 유지보수 비용) |
| D6 | 플랫폼 입장 | 1급 = WSL2+interop·네이티브 Linux. 최선 노력 = WSL2(usbipd 만)·WSL1·macOS(P5, 요청 시). 네이티브 Windows·Cygwin·MSYS 는 서버 시작 거부(P0)이고, Windows 는 장치 호스트로만 쓴다 |
| D7 | 내려받은 Windows 바이너리 실행 동의 | P3 시작 때 xPack openocd.exe 를 dummy 어댑터 + `tcl port pipe` 로 한 번 돌려 확인한다(하드웨어 불필요). sigrok-cli.exe 는 장치 없이 `--version`·`-L` 만 돌린다(`--scan` 은 fx2 펌웨어를 올릴 수 있음) |
| D8 | portlock 의 범위와 방식 | 호스트 전체(같은 커널)로 한다. 리눅스·WSL 은 abstract AF_UNIX 이름(파일이 아니라 지울 수 없고 커널이 해제), macOS 는 사용자별 디렉터리 flock(+ inode 확인). 역할 표지·소유 기록은 환경 변수가 아니라 uid 로 정한 `/tmp/pweh-<uid>` 에 둔다(배포판별). 결과: 다른 작업 공간·클론·(network namespace 를 공유하면) 다른 WSL 배포판의 세션도 `busy` 로 막는다. 대안(비권장): 작업 공간 단위 — 같은 장치를 두 작업 공간이 동시에 열 수 있어 배타가 깨진다 |
