# Windows OpenOCD 실행 계획·소유 확인 코어

PWEH의 P3-B는 Windows OpenOCD에 넘길 argv·자식 환경·고유 표식과, 주입된 조회 결과의 프로세스 신원을 검증하는 내부 기반이다. `pweh.wininterop`와 `openocd_mcp.windows_plan`을 합성 경로·가짜 응답으로 시험한다. 운영 MCP의 backend 선택, 실제 Windows child owner, 설치·USB 경로·리스너를 추가하지 않는다.

계획을 만들거나 가짜 runner의 종료 확인이 성공했다는 사실은 실제 Windows 실행·환경 전달·종료 검증을 뜻하지 않는다. 기존 OpenOCD TCP와 P3-A pipe 코어, ESP/P2 경로의 동작은 유지한다.

## 1. 구성과 주입 경계

| 구성 | 책임 |
|---|---|
| `pweh.wininterop` | 제한된 Windows 경로·명령줄·조회 응답 검증, frozen 신원/launch 값, 고정 조회·종료 script와 필수 주입 runner |
| `openocd_mcp.windows_plan` | 로컬 파일 snapshot 관찰·대조, cfg 입력 고정, 미리 만든 run layout 확인, 필수 경로 converter를 통한 argv·환경 계획 |
| 후속 실행 owner | 실제 gate/분류·번들/route 검증, Windows spawn, 파일·경로 예약·fd 수명, 정상 EOF·강제 종료·최종 부재 확인 |

두 모듈은 import 시 환경 감지·장치/프로세스 조회를 하지 않는다. Windows 실행을 위한 기본 subprocess runner나 wslpath converter가 없다. caller는 `path_converter(local_path, deadline)`와 `runner(fixed_script, deadline)`를 명시적으로 주입한다. 이 콜백을 임의 PowerShell 명령 실행용 public 도구로 노출하지 않는다.

콜백 호출 전후와 내부 반복에 absolute monotonic deadline을 적용하며 호출 잔여 시간은 최대30초로 제한한다. 명령줄·snapshot 파서는 별도의 최대5초 상한도 적용한다. Python 콜백 자체를 선점 중단하는 보장은 없으므로, 실제 실행기를 연결할 때도 남은 시간과 출력 상한을 실행기에 적용해야 한다. 조회 실패·시간 초과·불완전 응답을 빈 결과로 바꾸지 않는다.

## 2. 파일 관찰과 계획 입력

`observe_file(path, *, max_bytes, deadline)`은 한 번 연 일반 파일 fd를 한도 안에서 읽어 SHA256을 계산하고, 읽기 전후 fd·경로 이름의 신원을 대조한다. `FileSnapshot`은 `path`, `size`, `sha256`, `identity=(dev,ino,mode,size,mtime_ns,ctime_ns)`를 가진 frozen 값이다. 관찰 결과가 영구 경로 잠금이나 서명·번들 신뢰를 뜻하지 않는다.

`freeze_cfg(ref, observed, *, classified_sha256=None)`는 기존 mutable `process.CfgRef`의 kind와 경로를 frozen `CfgInput(kind,file)`으로 옮긴다. unresolved/path 없음은 실패한다. custom cfg는 실제로 분류한 전체 bytes의 SHA를 필수로 받아 snapshot과 대조한다. standard 표식은 기존 경로 분류이며 배포 bundle의 진위 확인이 아니다.

계획 함수는 다음 값들을 받는다.

```python
build_plan(inputs: PipeStartInputs, layout: RunLayout, *,
           ambient_env: tuple[tuple[str, str], ...],
           path_converter, deadline: float) -> OpenOcdWindowsPlan
```

`PipeStartInputs`는 executable snapshot, 순서가 있는 search_dirs, interface/targets/extras의 CfgInput, transport, adapter_speed_khz, extra_commands를 가진다. 완료한 plan은 inputs/layout, 불변 argv/env_items와 `OwnedWindowsLaunch`를 보유한다. `plan.executable`과 `plan.cwd`는 **로컬 절대 경로**, `plan.launch.image`와 argv의 `-s/-f` 값·제어 환경값은 **Windows 절대 경로**다.

직접 실행파일 상한은64 MiB, custom cfg 한 개는 기존1 MiB, 직접 cfg는 합계64개/64 MiB, search_dirs는1–8개, 최종 argv는 각 항목의 UTF-8 길이+1을 합한 값이32768 이하, env는256 KiB다. 이 argv 예산을 Windows가 최종 인용한 command-line 문자열 길이의 보증으로 사용하지 않는다. 명시 executable을 검증하지 못하면 PATH나 다른 설치로 대체하지 않는다. 대상 basename은 `openocd.exe`다. snapshot을 현재 파일과 다시 대조하고 같은 deadline으로 계획을 만든다.

## 3. 고유 run layout과 argv

호출자가 다음 실제 디렉터리와 owner cfg를 먼저 만든다. planner는 디렉터리·파일을 생성하거나 정리하지 않는다.

```text
run root/
  cwd/
  home/
  config/
  appdata/
  owner-<32 lowercase hex>.cfg
```

cwd/home/config/appdata는 서로 다른 빈 디렉터리이며 root 바로 아래다. root는 이 항목을 담으므로 빈 디렉터리가 아니다. 예상 밖 entry, 링크·탈출·변경된 신원은 거부한다. marker cfg는 모듈의 고정 `OWNER_CONTENT` bytes와 SHA에 맞아야 하고 caller Tcl을 삽입하지 않는다. 고유 경로는 해당 launch의 소유 표식이며 제품 설치 경로·PID·포트만으로 이를 대신하지 않는다.

각 고유 local 경로는 converter로 한 번만 변환하고 결과를 argv/env에서 재사용한다. converter는 str 또는 strict UTF-8 bytes를 반환할 수 있다. 출력은≤8 KiB이며 허용된 terminal newline만 제거한 값으로 검사한다. 공백을 무조건 strip하거나 replacement decoding으로 바꾸지 않는다.

계획은 기존 `build_pipe_argv`를 재사용한다. 검증한 Windows 절대 `-s/-f` 경로를 넣고, owner cfg는 사용자 extras 뒤에 추가한다. pipe TCL, telnet/GDB disabled, debug level3, semihosting guard, EARLY/PRE/init/POST 순서를 유지한다. cfg body나 임의 Tcl 안의 경로를 일반 문자열 치환하지 않는다. planner의 길이·제어문자 검사는 cfg/명령 분류·사용자 허가를 대체하지 않는다.

`launch.argv_tail`은 argv[0]을 제외한 최종 인자다. `launch.path_arg_indices`는 그 tail에서 `-s/-f`의 **값** 위치만 지정한다. 신원 대조는 이 위치에만 제한된 Windows 경로 비교를 적용하고 Tcl/기타 인자는 대소문자를 포함해 정확히 비교한다.

## 4. Windows 경로와 자식 환경

drive-absolute 또는 허용된 WSL UNC만 받고 relative/drive-relative, device namespace, ADS, NUL·CR/LF·quote, `.`/`..` 요소, 끝 점/공백, Win32 예약 basename을 거부한다. 정상 공백·한글 요소의 철자는 보존한다. 이 검사는 모든 Win32 alias의 정규화나 실제 round-trip mapping 증명이 아니다.

자식 환경에 다음 nonempty Windows 경로를 명시한다.

| 변수 | 계획값 |
|---|---|
| OPENOCD_SCRIPTS | 첫 search_dirs의 Windows 경로 |
| HOME, USERPROFILE | run의 home |
| XDG_CONFIG_HOME | run의 config |
| APPDATA | run의 appdata |
| WSLENV | `OPENOCD_SCRIPTS/w:HOME/w:XDG_CONFIG_HOME/w:APPDATA/w:USERPROFILE/w` |

이미 변환된 Windows 경로이므로 WSLENV에 `/p`를 붙이지 않는다. ambient 제어 키·WSLENV의 ASCII 대소문자 변형을 제거하고 canonical 이름 한 개를 만든다. 입력 tuple/dict나 `os.environ`, 사용자 HOME·레지스트리·셸 환경은 수정하지 않는다. 중복 이름은 검증 규칙으로 거부하거나 제어 키 교체로 정리하며 임의 last-wins 순서에 맡기지 않는다.

WSLENV는 **전체 Windows 환경 블록의 대체물이 아니다**. Linux projection에서 값을 지웠다는 이유로 Windows 부모의 상속값, PATH/DLL 환경이나 모든 CRT 병합 충돌이 제거되었다고 판단하지 않는다. nonempty 값은 빈 값 전달에 의존하지 않기 위한 계약이다.

OpenOCD 고정 소스 `e5888bda38f4952e2ae92f7dc5b25fc9a2d1c2b3`에서 확인한 cfg 검색 순서는 다음과 같다.

1. 전달한 이름 그대로: 절대 이름 또는 cwd 상대 이름.
2. CLI `-s` 순서.
3. OPENOCD_SCRIPTS 값 하나.
4. APPDATA/OpenOCD.
5. XDG_CONFIG_HOME/openocd, XDG가 없을 때 HOME/.config/openocd.
6. HOME/.openocd.
7. 실행파일·빌드 경로에서 계산된 bundle site, 그 다음 scripts.

근거는 [configuration.c](https://github.com/openocd-org/openocd/blob/e5888bda38f4952e2ae92f7dc5b25fc9a2d1c2b3/src/helper/configuration.c), [options.c](https://github.com/openocd-org/openocd/blob/e5888bda38f4952e2ae92f7dc5b25fc9a2d1c2b3/src/helper/options.c), [startup.tcl](https://github.com/openocd-org/openocd/blob/e5888bda38f4952e2ae92f7dc5b25fc9a2d1c2b3/src/helper/startup.tcl)이다. `-s` 우선만으로 후순위 검색을 닫았다고 하지 않는다. USERPROFILE은 방어적 중립값이며 위 cfg 검색 목록의 직접 입력으로 추가하지 않는다. [Microsoft WSLENV](https://learn.microsoft.com/en-us/windows/wsl/filesystems#share-environment-variables-between-windows-and-wsl-with-wslenv)와 [Windows 환경 블록](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)의 역할도 구분한다.

## 5. 조회 응답과 정확한 launch 신원

`WindowsIdentity(pid,image,creation_filetime,command_line)`와 `OwnedWindowsLaunch(image,argv_tail,marker_cfg,path_arg_indices)`는 frozen 값이다. 이미지 경로는 CIM ExecutablePath를 기준으로 한다. Windows command line의 argv[0]은 WSL 경로 철자일 수 있어 image 비교 근거로 사용하지 않는다.

`parse_process_snapshot(raw, *, deadline=None)`는 strict UTF-8 JSON의 다음 고정 shape를 검사한다.

```text
{complete: true, items: [{pid, image, creation, cmd}, ...]}
```

응답1 MiB/256행과 문자열·구조 상한, 완전성, 중복 PID, 생성시각·이미지·완전한 명령줄을 검사한다. 생성시각은 CIM의 microsecond(10 FILETIME ticks) 표현이며 native handle의 GetProcessTimes도 같은 단위로 절삭해 비교한다. 원시 100 ns 정밀도 일치를 주장하지 않는다. 손상된 행을 건너뛴 뒤 빈 목록으로 처리하지 않는다. 반환된 raw command line/Windows 경로는 내부 검증값이며 MCP·로그·사용자 결과에 자동 공개하지 않는다. 오류는 원문 없는 고정 code다.

`WindowsOwnedProcessProbe(*, runner)`에는 기본 runner가 없다. `QUERY_SCRIPT`와 `TERMINATE_SCRIPT_TEMPLATE`이 고정 script이며 runner는 query 상수와 종료 요청을 구분할 수 있다. `observe(launch, *, deadline)`는 고정 openocd.exe 조회 script를 runner에 보내고 검증한 exact matching 신원 tuple을 반환한다. 정상 complete 응답의 빈 tuple만 해당 표식의 부재다. 같은 marker 복수, image/argv 불일치·불완전 응답은 unknown 오류이며 소유 프로세스로 선택하지 않는다.

`terminate_and_confirm(launch, observed, *, deadline)`는 이미 관찰한 정확 신원을 받는다. fresh complete snapshot에서 이전 PID/image/creation/cmdline이 일치하지 않으면 종료 요청 없이 false다. 고정 종료 script는 구조화 요청만 받고 임의 PS source를 받지 않는다. native handle을 연 뒤 생성시각과 CIM 신원을 재대조하고, **그 handle**을 종료·wait한 뒤 닫는다. PID만으로 Stop-Process 하는 경로는 없다. `TerminateProcess=True`만으로 성공하지 않으며 마지막 complete 조회에서 정확 marker가 없어야 true다. false는 부재/정리 완료가 아닌 미확인이다.

이 검증은 알려진 image·고유 marker·정확 argv의 OpenOCD 프로세스 범위다. 임의 자손 전체나 marker를 버리고 탈출한 프로세스까지 부재라고 주장하지 않는다. raw PID의 재사용을 같은 실행으로 취급하지 않는다.

## 6. 운영 연결에 남는 경계

plan 성공은 cfg 허가·번들 서명·실행 권한이 아니다. 후속 서버는 동일 frozen 입력으로 분류/승인 action을 구성하고 gate 뒤 spawn 직전에 파일/hash·디렉터리/빈 상태·실제 bundle manifest·route/lease를 다시 확인해야 한다. 무작위 marker 자체를 사용자 요청 지문으로 사용하지 않고 고정 생성 규칙과 실제 launch 신원에 결속한다.

직접 파일 SHA는 DLL·중첩 `source [find ...]`·bundle site/scripts 전체 pin이나 PE/라이선스 검증을 포함하지 않는다. Windows 자식의 실제 환경 전달·nested cfg 검색 충돌·강제 종료/PID 재사용은 별도 무장치 실행에서 확인해야 한다. 기존 D7 dummy/version 정상 EOF 결과가 이 전체 경계를 검증한 것은 아니다.

stderr decoder는 이번 코어에 포함하지 않는다. 후속 runtime에서 UTF-8 우선·명시 ACP의 진단 해석을 구현하더라도 RPC stdout에는 ACP fallback을 적용하지 않는다.

후속 Windows owner는 P3-A의 strict UTF-8 framed RPC client를 재사용할 수 있지만 Linux owner의 `/proc`/POSIX 종료 상태를 Windows 실제 종료로 대체할 수 없다. 준비 확인은 version 한 번 전송 후 동일 deadline에서 정상 응답과 완결된 `Info : accepting 'tcl' connection from pipe` 줄을 모두 확인한다. 상세는 [OpenOCD TCL RPC §6.4.1](openocd-tcl-rpc.md#641-pipe-준비-확인)을 따른다.

정상 EOF/exit0 뒤에도 정확 Windows 표식의 최종 부재 확인이 필요하다. 비정상은 POSIX wrapper가 뒤늦게 child를 만들 가능성을 먼저 닫은 뒤 Windows를 마지막으로 확인한다. 확인이 끝나지 않으면 owner/marker 경로/lease 예약을 유지한다. 이 수명 연결과 실제 spawn은 P3-B의 현재 구현 범위 밖이다.
