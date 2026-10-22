# Windows 고정 Tigard JTAG 프로필

`openocd_start(backend="windows", windows_profile="tigard-jtag-v1", interface_cfg="interface/ftdi/tigard.cfg", tcl_port=0)`은 등록 xPack 번들과 WSL interop를 사용한다. 소유·허가된 케이스가 필요하며 기존 MODIFY 정책을 적용한다. 이 프로필은 JTAG 초기화와 자동 TAP 탐색, reset 해제를 수행하므로 수동 관찰이 아니다. 실제 장비·배선·타깃 통신은 합성 시험으로 검증하지 않는다.

## 고정 입력과 실행 범위

| 항목 | 계약 |
|---|---|
| 번들 | `xpack-0.12.0-7-win32-x64`, 등록 manifest와 전체 파일 검증 |
| interface | `interface/ftdi/tigard.cfg`, 506바이트, SHA256 `d463833c32a5abb7545d7c645ad6110a63366809f0f7960a63f0be9dcc587b73` |
| USB 범위 | VID `0403`, PID `6010`과 일치하는 Present parent 정확히 하나 및 그 전체 하위 노드·COM alias |
| OpenOCD 필터 | `Tigard V1.1`, FTDI channel 1; PnP product/descriptor serial 확인을 뜻하지 않음 |
| transport / 속도 | JTAG / 100 kHz; 인자 생략 또는 정확한 고정값 |
| target / 추가 입력 | target cfg·추가 cfg·추가 Tcl 없음; `None` 또는 빈 목록만 |
| 공개 조회 | 정확한 `version`, `scan_chain`, `targets`; 전용 scan/targets 도구와 상태·종료 |
| 지원하지 않음 | 메모리·레지스터·flash·CPU 제어·덤프·백그라운드 작업·임의 Tcl |

VID/PID만 맞는 다른 FTDI 장치도 후보 집합에 포함된다. 후보가 둘 이상이거나 관찰이 불완전하면 시작하지 않는다. OpenOCD가 descriptor 필터를 검사하기 전에 USB handle을 열 수 있으므로, channel 하나나 특정 COM만 잠그지 않는다. 이 선택은 장치 모델·소유권·descriptor serial의 증명이 아니다.

## 승인과 수명

두 번의 완전한 Present graph가 같은 범위를 보이는지 확인하고 전체 `winif:` 및 `win:COMn` key를 기존 `PortLockManager`로 잠근다. lease는 승인 대기에도 유지한다. 승인 지문에는 고정 프로필·interface·번들 manifest·전체 USB 범위 지문이 들어가며 실행 UUID는 들어가지 않는다. gate가 거부되거나 별도 승인이 필요하다고 반환하면 실행 run을 만들지 않고 lease를 해제한다.

실행 직전과 각 조회 직전에 처음 관찰한 scope를 다시 대조하고 보유 lease·role·계측기 가드를 확인한다. 범위가 바뀌면 새 장치로 재선택하거나 잠금을 늘리지 않는다. PWEH 계측기 active pin이 있는데 descriptor serial을 확인할 수 없으면 기존 보수적 거부 규칙을 따른다. pin이 없으면 가드가 별도 계측기 조회를 추가하지 않는다.

공개 조회와 내부 semihosting RPC는 같은 pipe client의 실제 worker 사용권을 갖는다. awaiter 취소만으로 실행 중 worker의 사용권이나 lease를 해제하지 않는다. Windows 소유 프로세스·wrapper·stream 종료, 사용권 0, 고정 run 정리를 모두 확인한 뒤에만 lease를 해제한다. 정리를 확인하지 못하면 세션과 원래 lease를 보존하며 `openocd_stop`으로 재시도한다. stop에는 장치 재탐색·fresh gate를 요구하지 않는다. 이전 Windows 상태 파일은 자동 attach/adopt/reconnect하지 않는다.

## 시작·상태 결과의 의미

고정 cfg 뒤 semihosting pre-init 가드 → `init` → post-init 가드를 실행한다. 준비 marker와 version 응답을 확인한 뒤 같은 pipe로 내부 `VERIFY_CALL`을 한 번 실행하여 세 단계와 target 0을 확인한다. 임의 target 생성과 `noinit`은 허용하지 않는다.

- `transport="windows-pipe"`, `tcl_port=null`, `usb_scope="whole-device"`.
- `hardware_initialized=true`는 adapter 초기화 절차 완료를 뜻한다.
- `target_configured=false`, `target_communication_verified=false`는 타깃 통신을 확인하지 않았음을 명시한다.
- semihosting `mode="fixed-adapter-init"`, `verification_performed=true`는 가드 절차 확인이다. target 0이므로 실제 타깃에서 semihosting 보호를 시험했다는 뜻이 아니다.
- `startup`, `diagnosis`, `warnings`, `health`는 초기화 진단을 보존한다. OpenOCD가 TAP/IR 오류 뒤에도 성공을 반환할 수 있어 해당 오류가 있으면 시작 `ok=true`와 함께 `health="degraded"`가 나올 수 있다.

이 기능은 고정 adapter의 시작·조회·종료까지 지원한다. 타깃 설정·동작 검증이나 덤프 지원을 포함하지 않는다. Linux/TCP와 Windows dummy의 기존 경로는 유지한다.

## 검증

`test_openocd_windows_tigard.py`는 독립 합성 PnP graph, 기존 OS lease, 공개 MCP, 승인 대기·fresh 변경·raw cancellation·정리 미확인·target0/가드 실패를 검사한다. 등록 합성 번들과 실제 Windows owner 코드를 Linux 가짜 pipe 자식에 연결하는 시험도 포함한다. 실제 Windows·PnP·USB 장치는 사용하지 않는다. 물리 장비 수용 시험은 별도이며 이 문서에서 성공을 주장하지 않는다.

고정 읽기 전용 PnP 질의는 query와 parse에 같은 최대 5초 deadline을 적용하고, wrapper 정리에는 별도 최대 2초를 둔다. 이 경로는 Windows의 질의 child가 실제로 종료했는지까지 확인하지 못한다. 질의 실패 시 OpenOCD를 시작하지 않는 계약과, 실행된 OpenOCD를 exact owner로 추적하여 종료를 확인하는 계약은 별개다.

고정 upstream commit `e5888bda38f4952e2ae92f7dc5b25fc9a2d1c2b3`의 [Tigard cfg](https://github.com/openocd-org/openocd/blob/e5888bda38f4952e2ae92f7dc5b25fc9a2d1c2b3/tcl/interface/ftdi/tigard.cfg)는 필터·channel·reset layout의 근거다. [초기화 순서](https://github.com/openocd-org/openocd/blob/e5888bda38f4952e2ae92f7dc5b25fc9a2d1c2b3/src/openocd.c#L100)와 [JTAG 자동 발견 및 오류 처리](https://github.com/openocd-org/openocd/blob/e5888bda38f4952e2ae92f7dc5b25fc9a2d1c2b3/src/jtag/core.c#L1421)는 target 없는 active init 및 degraded 결과의 근거다.
