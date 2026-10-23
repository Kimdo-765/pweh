# Windows pipe의 내부 파일 출력

`openocd_mcp.windows_output`과 `windows_file_job`은 같은 Windows owner의 pipe 명령과
출력 파일을 결속하는 내부 기반이다. Linux 가짜 자식과 합성 Windows 수명 관찰로 검증한다.
공개 Windows dummy/Tigard의 타깃·메모리·플래시·덤프 거부는 유지하며, 이 모듈을 호출하는
새 MCP 도구나 사용자 프로필은 제공하지 않는다.

## 입력과 출력

불변 `PipeFileSpec`은 케이스, memory/flash 구분, 출력 basename, 정확한 정수 범위,
청크 크기, verify/resume 여부를 받는다. 임의 출력 디렉터리·문자열 bank·raw Tcl은 없다.

| 구분 | 입력 범위 | 결과 |
|---|---|---|
| memory | 길이 1..4GiB, 64비트 주소와 합산 범위 검사 | `jtag/<name>.bin`, memory-dump |
| flash | bank 0..2³¹−1, offset 0..2³²−1, 길이·bank 크기 1..2³²−1, `offset+length<=bank_size` | `dumps/<name>.bin`, flash-dump |
| 공통 | 청크 256B..16MiB, 마지막 청크는 남은 길이 | 같은 위치의 `.json`, 중단 시 `.part`·`.state.json` |

결과는 `path`, `metadata_path`, `size`, `sha256`, `artifact`, `source`, `transfer`,
`chunks`, `resumed_from`, `warnings`다. `source`는 내부 요청의 주소 또는 bank 범위다.
실제 장치와의 동일성이나 `device-read` 출처를 새로 증명하지 않는다. 원시 Tcl·Windows
절대경로·덤프 바이트·원문 예외는 결과에 넣지 않는다.

## 파일과 명령 결속

spawn 전 고정 실행 디렉터리 검사는 그대로 유지한다. spawn 뒤 전용 cwd 아래에 0700 출력
디렉터리를 만들고, 각 청크는 O_EXCL로 사전 생성한다. 부모와 파일 FD를 계속 소유하며
이름·inode·단일 링크를 명령 전후에 대조한다. 같은 owner가 이미 선택한 경로 변환기로
local/Windows 경로 쌍을 만들며, 임의 SMB·장치 namespace·ADS·상대경로를 허용하지 않는다.

고정 builder는 `dump_image`, `flash read_bank`, `flash verify_bank`만 만든다. 보유한
Windows 경로를 하나의 Tcl 단어로 인용하고, 같은 쌍의 local 경로로 만든 고정 명령을 기존
관리 명령 분류기에 대조한다. 공개 raw Tcl의 허용 범위를 넓히는 경로 치환 기능은 없다.

정상 RPC 뒤에도 실제 파일의 정확한 크기·FD 신원·전체 바이트를 확인한다. memory verify는
별도 청크 두 개를 비교하며, flash verify는 호출 전후 같은 파일의 seal과 해시도 대조한다.
검증된 청크만 `.part`에 기록하고 checkpoint를 전진시킨다. 짧음·초과·교체·불일치나 RPC
오류가 생기면 추가 명령·재전송·재연결·`read_memory` fallback 없이 종료한다.

고정 upstream `e5888bda38f4952e2ae92f7dc5b25fc9a2d1c2b3`의
[read_bank/verify_bank](https://github.com/openocd-org/openocd/blob/e5888bda38f4952e2ae92f7dc5b25fc9a2d1c2b3/src/flash/nor/tcl.c#L906-L1024)는
32비트 offset/length 및 bank 잔여 길이를 사용한다. verify가 확인하는 길이는 파일 크기와
bank 잔여 중 작은 값이므로, 정상 응답만으로 요청 파일 전체가 검증됐다고 판단하지 않는다.

## 재개와 등록

닫힌 v2 checkpoint에는 요청 범위·검증 방식·번들 pin과 확정 prefix의 크기·SHA256이
결속된다. 같은 FD로 prefix를 검증한 뒤에만 미확정 tail을 줄인다. 기존 TCP v1 상태나
상태 없는 part, 다른 요청·부족한 길이·불일치 해시를 자동 채택하거나 삭제하지 않는다.
state와 metadata는 각각 64KiB 이하이며, 새 상태 파일의 교체는 소유한 checkpoint에 한정한다.

전체 바이트를 받은 뒤 실제 owner 종료 확인이 있어야 게시한다. part를 다시 해시하고
O_EXCL 최종 파일로 복사한 뒤, 최종 파일과 metadata를 0444로 만든다. 기존
`Case.register_artifact(check=..., on_commit=...)`의 metadata 잠금 안에서 입력 part와
두 출력의 이름·FD·seal 및 등록 entry를 대조한다. part와 최종 바이너리는 전체 해시도
확인하며, 나중 파일을 해시하는 동안 앞 파일이 바뀌는 경우는 마지막 전체 seal 검사로 거부한다.

commit 전 실패는 정상 artifact를 만들지 않고 유효 part/checkpoint를 보존한다. 새로 만든
최종 파일은 자기 inode임이 확인될 때만 정리한다. commit 후에는 receipt를 먼저 보관하며,
늦은 취소·감사·정리 실패로 등록된 파일을 삭제하지 않는다. 후커밋 경고는
`post_commit_callback_failed`, `output_close_unconfirmed` 두 값이다.

## 작업과 정리 수명

작업은 기존 `LeaseHandoff`와 세션 사용권을 사용한다. 준비 전 취소·시작 실패는 사용권만
반환한다. 출력 준비가 시작된 뒤에는 성공·실패 모두 같은 owner의 종료 절차를 거친다.

```text
같은 client로 청크 처리 → 새 사용권 차단 → 물리 owner 종료 확인
→ 정상 전체 결과만 게시 → worker 사용권 반환
→ 사용권 0 확인 → 출력 정리 → run 정리 → lease 해제
```

worker는 자기 사용권을 가진 채 `close_session`에서 자신을 기다리지 않는다. 종료 미확인이면
output record·owner·세션·run·lease를 남기며, 다음 명시 stop에서만 정리를 재시도한다.
stop은 미게시 파일을 자동 등록하거나 작업을 재개하지 않는다. 모르는 출력 항목도 삭제하지 않는다.
기존 borrowed `read_memory` 작업은 사용권만 반환하고 client를 재사용하는 수명을 유지한다.

준비·변환·RPC·해시는 처음 정한 최대 3600초 deadline을 공유한다. 마지막 RPC 뒤에는
원래 deadline과 그 시점+60초 중 이른 끝을 사용한다. 정상 owner 종료에는 그 안에서 최대
10초를 사용한다. 이미 실패·취소·만료한 작업은 한 번의 별도 최대 10초 정리만 수행하며
게시하지 않는다. 파일 I/O는 64KiB 이하 단위로 시간·취소를 확인한다.

## 검증 범위와 한계

`test_openocd_windows_output.py`는 FD·경로 쌍·checkpoint·등록을,
`test_openocd_windows_file_jobs.py`는 작업 예약·취소·종료 경합을 검사한다.
`test_openocd_pipe_file_integration.py`는 실제 owner·JobManager·Case와 Linux 가짜 자식으로
청크 생성부터 artifact·출력/run/lease 정리까지 연결한다. Windows 수명 관찰만 합성 주입한다.

실제 Windows CRT/WSL 공유 파일 열기, Unicode 파일명, USB·타깃·주소·flash 사실은 이
시험으로 검증하지 않는다. POSIX와 Windows 사이에 동일 FD를 전달하는 프로토콜도 아니다.
전용 디렉터리와 전후 신원 검사는 같은 uid나 관리자에 의한 cross-OS 이름 교체를 원자적으로
막는 보장이 아니며, checkpoint 해시는 실제 기기의 출처 증명을 대신하지 않는다.
