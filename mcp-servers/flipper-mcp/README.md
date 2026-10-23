# pweh-flipper

소유·허가 케이스에서 Flipper Zero의 고정 USB CLI를 열고 정보·목록·파일 하나를 읽는 서버다.
현재 지원 프로필은 공식 1.5.1 문법의 `flipper-cli-1.5.1-read-v1`이다. 등록 이름은
`pweh-flipper`, 실행 명령은 `pweh-flipper-mcp`(stdio)다.

## 도구와 사용 순서

| 도구 | 인자 | 기능 |
|---|---|---|
| `flipper_connect` | `case_id, port, approval_id=None` | 전체 USB 잠금·MODIFY gate 뒤 DTR=true로 연결하고 새 배너/버전/프롬프트와 info 확인 |
| `flipper_device_info` | `case_id` | loader idle 확인 뒤 model/target/firmware 호환 정보 읽기 |
| `flipper_storage_list` | `case_id, path` | 허용 디렉터리 바로 아래 목록 읽기 |
| `flipper_storage_pull_start` | `case_id, flipper_path, dest_name=None` | 파일 하나를 받는 job 시작 |
| `flipper_nfc_probe` | `case_id, approval_id=None` | 고정 3A 선택·GET_VERSION·scratch 정리 뒤 마스킹 scan 참조 기록 |
| `flipper_job_status` | `job_id, wait_seconds=0, case_id=None` | job 결과 또는 저장 기록 조회 |
| `flipper_job_cancel` | `job_id` | 실행 중 job의 취소 요청 |
| `flipper_jobs` | `active_only=False, case_id=None` | 메모리/저장 job 목록 |
| `flipper_close` | `case_id` | worker와 실제 핸들 정리 확인 후 잠금 해제 |

명시 USB tty 또는 WSL의 Windows COM만 사용한다. VID/PID `0483:5740`, CLI interface `00`과
현재 전체 sibling 신원을 확인한다. 일반 UART·bridge interface·URL·loop 입력은 받지 않는다.
기존 target/bridge 표지와 고정 계측기 보호를 적용하며 모호한 신원을 승인으로 우회하지 않는다.

연결은 115200 8N1, DTR=true/RTS=false로 고정된다. DTR 변경 때문에 connect는 MODIFY다.
새 배너를 확인하기 전 명령 bytes는 보내지 않는다. `approval_required`이면 사람이 별도 터미널에서
승인한 뒤 동일 인자와 반환 `approval_id`로 재호출한다. 정보·목록·파일 명령은 기존 OBSERVE gate를
거친다. NFC probe는 장치 SD의 scratch 생성/삭제를 포함하므로 별도 MODIFY gate를 거친다.
임의 명령·앱 실행·RF 재생·일반 storage 쓰기·태그 메모리 쓰기는 없다.

## 고정 NFC probe

연결 후 `flipper_nfc_probe(case_id)`를 호출하면 `flipper-ntag21x-admission-v1` 고정 순서만 실행한다.
기존 `/ext/pweh/<case_id>/` 아래 새 UUID scratch 한 개로 ISO14443-3A 헤더를 얻고,
UID7/SAK0 전제에서 고정 GET_VERSION을 한 번 전송한다. CRC와 두 선택의 identity가 일치하며
NTAG213/215/216 version일 때만 허용한다. probe 전체45초, scratch 최대4KiB이며 페이지 READ는 없다.

자신이 만든 파일의 크기/MD5와 제거 후 부재를 확인한 뒤에만 보호 원장에 scan 사실을 기록한다.
공개 결과는 `scan_ref`, `family`, 케이스 솔트 `identity_digest`와 한계 flags이며 원문 UID·ATQA·SAK·version은 없다.
반환 `scan_ref`는 같은 케이스의 `nfc_tag_inventory_add`에 넘길 수 있다. 기존 NFC 파일의 오프라인 검사에는
그 inventory 결속과 별도의 기존 import 출처 증명이 필요하며 storage pull만으로 scan 권위가 생기지 않는다.

두 선택은 원자적이지 않다. 중간 태그 교체를 첫 SELECT 이후의 GET_VERSION 송신 전에 host가 막을 수 없으며,
정상 응답도 동일 실물·진품·RF field off·장치 명령 종료의 증명이 아니다. 취소/timeout/문법 실패 뒤에는
exit/remove를 포함한 새 명령을 보내지 않으므로 원격 scratch가 남을 수 있다. 이후 `flipper_close`로 host를 정리한다.

## 파일과 결과

사용자가 Flipper에 준비한 `/ext/pweh/<case_id>/` 아래만 목록화·읽기한다. 이 서버는 폴더를 만들지 않는다.
파일은 최대 1 MiB, 목록은 최대 256개다. 제한 ASCII 경로만 받고 `dest_name`은 host basename이다.
출력은 케이스 `flipper/<dest_name>`의 새 파일이며 기존 파일을 덮어쓰지 않는다.

pull은 binary 본문과 CLI 종결을 확인한 뒤 장치 MD5·host MD5를 대조한다. 같은 host FD의 SHA256와
신원을 검증하고 0444 파일을 일반 아티팩트로 등록한다. 결과의 `artifact.id/path/size/sha256`을 확인한다.
이는 원격 원자 snapshot, 파일 생성 출처, RF 캡처나 forensic custody 증명이 아니다.

RAW 파일이면 반환 `artifact.id`를 [pweh-sdr](../sdr-mcp/README.md)의 `sdr_analyze`에 전달할 수 있다.
분석 요약은 [flipper-rf-analysis Skill](../../skills/flipper-rf-analysis/SKILL.md)의 기존 `rf-analysis`를 쓴다.
전송 자체에 별도 분석 summary를 만들지 않는다.

작업 뒤 항상 `flipper_close`를 호출한다. 허가가 철회돼도 정리는 가능하다. 물리 close나 worker 종료가
미확인이면 `cleanup_pending`과 세션·잠금을 보존하므로 다시 close한다. host close는 장치 명령 종료나
RF field off를 증명하지 않는다. 상세 반환·한도·오류는 [읽기 전송 계약](../../docs/references/flipper-read-transport.md)에 있다.

## 검증 범위

`tests/core/test_flipper_cli.py`, `tests/servers/test_flipper_session.py`, `test_flipper_storage.py`,
`test_flipper_mcp.py`, `test_flipper_nfc.py`는 합성 bytes와 가짜 직렬 factory로 parser·lease·gate·same-FD 등록·취소·실제 MCP 연결을
검사한다. 실물 DTR 배너, OS별 실제 USB 매핑, 전송 성능과 단절 뒤 장치 상태는 실기 미검증이다.
