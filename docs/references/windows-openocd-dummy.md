# Windows OpenOCD 무장치 진단 세션

WSL에서 등록된 xPack OpenOCD Windows 번들로 `dummy-noinit-v1` 세션을 시작하고, pipe RPC 조회와 종료를 확인한다. 기본 `backend="linux"`의 TCP·실제 프로브 동작은 유지한다. Windows 프로필은 이 진단용 한 개이며 USB 프로브·메모리·플래시·덤프 작업은 지원하지 않는다.

## 시작과 조회

먼저 [로컬 번들 설치](windows-bundles.md)로 등록된 OpenOCD release를 설치한다. 선택 순서는 `tools.openocd_win_bundle` → `PWEH_OPENOCD_WIN_BUNDLE` → 관리 기본 release다. 값은 WSL/Linux에서 보이는 release root이며, 명시한 경로가 잘못되면 다른 설치로 대체하지 않는다. WSL interop과 Windows 도구 실행이 허용된 환경이 필요하다.

```json
{
  "case_id": "<케이스 ID>",
  "backend": "windows",
  "windows_profile": "dummy-noinit-v1",
  "interface_cfg": "interface/dummy.cfg",
  "tcl_port": 0
}
```

위 인자는 `openocd_start`에 전달한다. 기존 케이스 권한과 MODIFY 게이트를 적용한다. `target_cfg`, `extra_cfgs`, `extra_commands`는 생략하거나 빈 목록이어야 한다. `transport`는 생략 또는 `jtag`, `adapter_speed_khz`는 생략 또는 `1000`만 받는다. `ready_timeout`은 유한한 양수로 최대 30초다. `tcl_port=0`은 pipe 선택의 명시 조건이며 실제 TCP 포트를 할당하지 않는다.

시작 뒤 사용할 수 있는 도구는 다음과 같다.

| 도구 | 지원 내용 |
|---|---|
| `openocd_command` | 정확한 `version`, `targets`, `scan_chain`, `jtag names`, `adapter name` 조회 |
| `openocd_targets`, `openocd_scan_chain` | 고정 testee/TAP의 설정 조회 |
| `openocd_status` | 세션 상태와 정리 여부 확인 |
| `openocd_stop` | 소유 프로세스 종료 및 확인 |

허용 목록 밖 Tcl과 halt/reset/resume, 레지스터·메모리·플래시 도구, 덤프 job은 전송·job 생성 전에 거부한다. `openocd_attach`는 TCP 전용이며 Windows pipe 재접속·입양은 제공하지 않는다. `openocd_list_configs`는 기존 Linux scripts 목록이다.

## 결과의 의미

세션은 `transport="windows-pipe"`, `host=null`, `tcl_port=null`, `usb_scope="not-applicable"`로 표시한다. 고정 dummy/testee 설정 뒤 `noinit`만 실행하므로 `hardware_initialized=false`다. `semihosting.mode="fixed-dummy-noinit"`는 이 제한 프로필을 뜻하며 실제 타깃 초기화·semihosting 가드 검증 성공을 뜻하지 않는다. dummy의 TAP/타깃 목록은 실제 장치 검출 결과가 아니다.

준비 확인은 같은 client에서 `version`을 한 번 보내고, 같은 시간 예산 안에 정상 Tcl 응답과 완결된 quoted pipe 연결 진단을 받는 방식이다. 전송 뒤 timeout·EOF·프로토콜 오류는 terminal 상태로 남고 재연결·재전송하지 않는다.

## 소유와 종료

등록 bundle 전체를 확인하고 승인 뒤 worker가 고유 run 디렉터리를 만든다. 승인 지문에는 고정 profile·bundle·cfg 내용을 묶고 매번 달라지는 run UUID를 넣지 않는다. 실행 직전에 원래 bundle·파일 신원과 같은 계획을 다시 대조한다. 자식의 cfg 검색·HOME 관련 환경은 [실행 계획 계약](windows-openocd-plan.md)의 nonempty Windows 경로와 WSLENV `/w` 규칙을 따른다.

종료는 POSIX wrapper 회수와 정확한 Windows 프로세스의 최종 부재를 함께 확인한다. Windows 조회는 고정 실행파일·고유 owner cfg·전체 argv·생성 시각을 대조하며, 강제 종료가 필요하면 같은 native handle의 신원을 확인한다. PID만으로 다른 프로세스를 종료하지 않는다. 고정 PowerShell 제어 호출이 끝났는지도 확인하며, 시간 초과를 성공한 빈 조회로 바꾸지 않는다.

정리 미확인은 `stopped=false`, `cleanup_pending=true`로 남긴다. 같은 owner를 보존하고 이후 stop으로 정리를 재시도한다. 실제 사용 중인 foreground worker가 남으면 run을 지우지 않는다. 서버 재시작 뒤 Windows 상태 기록은 `previous_owner_unverified`이며 자동 재연결·회수의 증거로 사용하지 않는다.

이 경로는 Windows 실행·RPC·소유 수명을 확인하는 진단 기능이다. 실제 USB claim·드라이버·재열거·메모리 덤프, 전체 Windows 환경/DLL 검색 격리, 서버 강제 종료 뒤 자동 회수는 별도 범위다. 정적 `doctor --windows-bundles-only`는 계속 파일 검사만 수행하고 세션을 시작하지 않는다.

## 무장치 수용 결과

2026-10-23 등록 xPack 0.12.0-7 설치본과 격리된 합성 케이스로 공개 MCP start → 허용 조회 5개 → targets/scan/status → 미지원 요청 7개 → stop을 확인했다. 한글을 포함한 WSL 경로를 사용했고, 미지원 요청은 모두 거부되며 job은 생성되지 않았다. 정상 종료 뒤 Windows 부재 확인·세션 제거·owner 해제를 확인했다.

별도의 두 번째 실행에서는 고유 marker와 전체 실행 인자가 일치하는 Windows 프로세스 한 개를 관찰했다. 고정 종료 경로가 같은 native handle의 신원을 재확인해 종료하고 최종 부재를 확인했으며, 이어 공개 stop의 wrapper·run 정리도 성공했다. 추가 다운로드·실제 USB/COM 접근·드라이버 변경은 없었다. 이 두 실행은 임의 자손의 부재나 실제 장비 지원을 검증한 결과가 아니다.
