# Flipper 고정 CLI 읽기 전송

`pweh-flipper`는 공식 Flipper Zero 1.5.1의 USB CLI 문법으로 정보·목록과 파일 하나를 읽는다.
프로필은 `flipper-cli-1.5.1-read-v1`, 문법 근거 commit은
`9e810dc399e027e48ce07751df72168abbb19065`다. 배너·info의 버전 일치는 호환성 관찰이며 공식 펌웨어의
서명·정품·무변조 증명이 아니다. 다른 버전이나 포크를 추정해서 수용하지 않는다.

## 연결과 권한

소유·허가가 기록된 케이스와 명시 USB tty 또는 WSL Windows COM을 사용한다. `flipper_connect(case_id,port)`는
현재 OS 신원·VID/PID `0483:5740`·CLI communication interface `00`·전체 USB sibling 범위를 확인한다.
선택 포트에 target/bridge 표지가 있거나 신원이 불완전하면 열지 않는다. 활성 계측기 보호도 유지한다.
Windows PnP의 `flip_` 인스턴스 꼬리를 USB descriptor serial의 관찰로 승격하지 않는다.

전체 범위의 공용 lease를 얻은 뒤 MODIFY gate를 거친다. 포트 설정은 **115200 8N1, DTR=true/RTS=false**로
고정되며 DTR 변경이 상태에 영향을 줄 수 있다. `approval_required`이면 사람이 별도 터미널에서
`pweh approve <반환 id>`를 실행한 뒤 같은 인자와 `approval_id`로 다시 요청한다. 거부를 다른 포트나 설정으로
우회하지 않는다. 새 연결마다 신원·역할·잠금을 다시 검사한다.

open 뒤 새 배너·버전·기본 프롬프트를 수동 수신하기 전에는 command bytes를 보내지 않는다. prompt만 있거나
침묵·bridge·지원 밖 버전이면 실패한다. 자동 CR/ETX/BREAK, 재연결·재동기화는 없다. 이후 고정 `loader info`의
idle 응답과 `info device`를 확인한다. loader 관찰과 다음 명령 사이 앱 시작을 원자적으로 막는 기능은 아니다.

한 케이스에 한 세션, 프로세스 전체 최대 16개다. 세션에는 command 또는 job 한 개만 실행한다. 이후 정보·목록·파일
읽기는 현재 소유/허가 확인과 OBSERVE gate를 거친다. 각 고정 명령 직전에 포트·전체 scope·role·guard를 재확인한다.

## 호출과 반환

| 도구 | 인자 | 반환 핵심 |
|---|---|---|
| `flipper_connect` | `case_id, port, approval_id=None` | `session_id`, 고정 `profile`, `state='ready'`, `port`, 제한된 `route`, `handshake`, `device`, `limits`, `warnings` |
| `flipper_device_info` | `case_id` | 현재 고정 `device` 정보 |
| `flipper_storage_list` | `case_id, path` | `entries`, `count`, `listing_complete`, `filesystem_completeness_verified=false` |
| `flipper_storage_pull_start` | `case_id, flipper_path, dest_name=None` | `job_id`, `status` |
| `flipper_close` | `case_id` | `closed/cleanup_pending`, `physical_close_verified`, `worker_finished`, `lease_released`, `device_command_termination_verified=false` |

세 공통 job 도구는 `flipper_job_status(job_id,wait_seconds=0,case_id=None)`,
`flipper_job_cancel(job_id)`, `flipper_jobs(active_only=False,case_id=None)`다. 상태 조회는 최대 50초 대기하며
`case_id`를 주면 같은 케이스의 저장 기록도 확인한다. 저장 기록은 재개하거나 취소하지 않는다.

SDK는 추가 인자와 타입 변환을 거부한다. `command/dtr/profile/force` 같은 우회 인자는 없다. 잘못된 키·값이나
원문 예외를 입력 오류에 복사하지 않는다. 장치 UID·이름·BLE MAC·앱 이름·원시 CLI 응답·binary 본문도 반환하지 않는다.
선택 포트·device_id, 사용자가 고른 허용 경로, 파일 목록과 해시는 기능상 반환되는 metadata다.

`device`는 model `Flipper Zero`, hardware target 7, info format 3/3과 version/commit/dirty의 고정 호환 정보를
담는다. `handshake.tx_before_banner=0`은 명령 byte 전송 계수이며 DTR 신호 변경과 구별한다.

## 저장소 경로와 한도

허용 루트는 정확 `/ext/pweh/<case_id>/`다. 사용자가 미리 준비하며 서버가 mkdir/delete하지 않는다. list는 루트
또는 그 아래 디렉터리 한 수준, pull은 그 아래 파일 하나다. 원격 path는 최대 512 ASCII bytes, component는
254 bytes/16개까지이며 `[A-Za-z0-9._ -]+`만 받는다. 빈/`.`/`..` component, 앞뒤 공백, quote, control, backslash,
이중 slash와 다른 케이스 루트는 거부한다. SPI 앱의 저장 위치나 NFC 폴더를 추정해서 추가하지 않는다.

`dest_name`은 `[A-Za-z0-9][A-Za-z0-9._-]*`의 1..96 ASCII basename이고 마지막 dot은 거부한다. 생략하면
`flipper-pull-NNN.bin`을 생성한다. host 출력은 `flipper/` 아래이며 기존 경로·링크를 덮어쓰지 않는다.

| 한도 | 값 |
|---|---|
| 단일 파일 | 0..1 MiB |
| 목록 | 최대 256개, 응답 256 KiB |
| 텍스트 | 최대 256 KiB/1024줄, 줄 1024 bytes; info 최대 256 key/값 512 bytes |
| 연결 | 전체 30초, 배너 최대 16 KiB/10초 |
| 개별 loader/info/list/md5 | 전체 작업의 남은 시간과 10초 중 작은 값 |
| pull | 300초, binary 무진전 10초 |
| 최종 host 검증·등록 | wire 검증 뒤 별도 고정 5초 |
| close 확인 | 최대 10초 후 미확인 owner 보존 |

시간은 협력 checkpoint의 예산이며 커널 I/O나 장치 명령을 강제 중단하는 watchdog이 아니다. Windows helper는
자체 유한 정리 절차를 사용하며 close 반환 뒤에도 정리 worker가 끝나지 않았으면 잠금은 남는다.

목록의 `listing_complete=true`는 CLI 종결까지 받은 것이다. firmware의 디렉터리 순회 종료가 EOF인지 중간 오류인지
별도 구분되지 않으므로 파일시스템 전체 목록 완료를 뜻하지 않는다. `filesystem_completeness_verified`는 항상 false다.
상한 초과·깨진 행은 목록 prefix를 성공 결과로 반환하지 않고 terminal 오류로 닫는다.

## 파일 검증과 아티팩트

wire의 `Size: N` 선언 뒤 정확 N bytes를 binary로 받는다. 본문 안의 prompt·NUL·ANSI를 해석하지 않는다.
후속 CRLF와 기본 prompt까지 확인한 뒤 다시 loader idle을 확인하고 장치 MD5를 읽는다. host MD5와 일치해야 성공이다.
MD5는 전송된 bytes의 두 관찰이 같다는 근거이며 원격 원자 snapshot이나 내용 생성 출처가 아니다.

출력 FD·부모·name을 commit까지 고정하고 SHA256·크기·dev/ino/mtime/ctime/nlink·readonly를 재검증한다.
0444 파일을 `kind='other'`, `producer='flipper-mcp'`, `extra.type='flipper-storage-copy'`로 등록한다.
extra는 고정 profile/session/route, 허용 remote path, 크기·해시와 false 출처 flags만 담는다.
이 파일을 full-flash device-read, NFC inventory, forensics EV/custody로 승격하지 않는다.

job의 성공 `result.artifact`는 `id,path,size,sha256`, `result.transfer`는
`declared_size,received_size,complete,md5_match,device_md5,host_md5,snapshot_atomic,device_file_origin_verified`다.
`declared_size == received_size == artifact.size`, 두 MD5가 같고 `complete/md5_match=true`다.
`snapshot_atomic/device_file_origin_verified`는 false다. complete는 host 파일의 전송 검증 완료다.

RAW 파일이면 반환된 실제 `artifact.id`를 다음처럼 사용한다. 아래 ID는 고정값으로 재사용하지 않는다.

```text
flipper_storage_pull_start(case_id, flipper_path="/ext/pweh/<case_id>/capture.sub")
flipper_job_status(job_id=<반환 job_id>, wait_seconds=30)
sdr_analyze(case_id, artifact_id=<성공 result.artifact.id>, profile="flipper-subghz-raw-v1-strict")
flipper_close(case_id)
```

RAW 분석의 캡처·기기 연관성·RF 허가 미확인 flags는 그대로다. 기존
[RAW 요약 계약](rf-raw-analysis.md#요약과-보고서-연결)과 [Skill](../../skills/flipper-rf-analysis/SKILL.md)을 쓴다.

## 취소·정리·오류

작업 취소는 표시와 reader 깨우기이며 worker가 쓰는 transport/파일/lease를 caller가 먼저 해제하지 않는다.
commit 전 실패는 부분 파일을 등록하지 않고 자신이 만든 신원이 맞는 파일만 정리한다. 교체·unknown 항목이나 정리
미확인은 보존한다. commit 후 늦은 취소·후처리 오류는 등록 파일을 지우지 않으며 job/아티팩트에서 결과를 확인한다.

close는 새 요청을 막고 작업을 취소한 뒤 사용권0·물리 핸들 닫힘·lease 해제를 확인한다. 허가 철회 뒤에도 호출할 수 있다.
`cleanup_pending`이면 같은 close로 다시 정리한다. EOF·terminal·Python 예외·wrapper 종료는 물리 close 증거가 아니다.
host close로 장치 명령 종료나 RF field off를 증명하지 않아 `device_command_termination_verified=false`를 유지한다.

고정 오류에는 `flipper_invalid_input`, `flipper_identity_unknown/changed`, `flipper_firmware_unsupported`,
`flipper_handshake_failed`, `flipper_app_busy`, `flipper_protocol_error`, `flipper_storage_error`, `flipper_limit`,
`flipper_checksum_mismatch`, `flipper_busy`, `flipper_terminal`, `flipper_cleanup_pending`, `flipper_failed`,
`cancelled`, `time_limit`이 있다. 기존 소유/허가·계측기 보호·역할/잠금 오류는 의미를 유지하며 원문 상세는 제거한다.

문법 근거는 고정 commit의
[CLI/info 등록](https://github.com/flipperdevices/flipperzero-firmware/blob/9e810dc399e027e48ce07751df72168abbb19065/applications/services/cli/cli_main_commands.c),
[info 값](https://github.com/flipperdevices/flipperzero-firmware/blob/9e810dc399e027e48ce07751df72168abbb19065/targets/f7/furi_hal/furi_hal_info.c),
[storage 읽기](https://github.com/flipperdevices/flipperzero-firmware/blob/9e810dc399e027e48ce07751df72168abbb19065/applications/services/storage/storage_cli.c),
[USB CDC 구조](https://github.com/flipperdevices/flipperzero-firmware/blob/9e810dc399e027e48ce07751df72168abbb19065/targets/f7/furi_hal/furi_hal_usb_cdc.c)다.
합성 시험은 소프트웨어 계약을 검증하며 실제 Flipper의 DTR 배너·OS USB 매핑·성능·단절 뒤 상태는 실기 미검증이다.
