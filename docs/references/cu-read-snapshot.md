# CU 페이지 snapshot과 같은 inventory 비교

`pweh-nfc`는 고정 ChameleonUltra reader로 NTAG213/215/216의 시작 페이지 응답을
읽고, 같은 케이스 inventory에 결속한 snapshot을 만든다. 읽기 전에 새 scan·version·
UID/BCC를 대조한다. 실제 USB/RF 호환성과 물리 동일 태그는 합성 시험으로 확인하지 않는다.
reader 연결과 wire 규칙은 [CU 전송 계약](cu-ntag-read-provider.md)을 따른다.

## 읽기와 분석 순서

1. 소유·허가된 reader와 태그에 대해 `nfc_cu_connect`의 실제 session_id를 받는다.
   `nfc_cu_scan`의 실제 scan_ref를 `nfc_tag_inventory_add`에 전달한다.
2. `nfc_cu_read_start(case_id, session_id, tag_ref, approval_id=None)`를 호출한다.
   기존 세션과 현재 inventory를 확인한 뒤 MODIFY 게이트를 거친다. `approval_required`면
   사람이 별도 터미널에서 승인한 뒤 같은 인자와 approval_id로 재호출한다.
3. 실제 job_id를 `nfc_job_status`로 조회한다. 필요하면 `nfc_job_cancel`로 취소한다.
   `registered=true` 결과의 실제 artifact_id만 `nfc_parse_file`에 전달한다.
4. 사용자가 콘솔 전후 비교를 원하면 사람이 태그를 콘솔에 제시하고 완료를 알린다.
   같은 inventory의 태그를 다시 읽어 앞·뒤 artifact_id를 `nfc_diff_dumps`에 전달한다.
   관찰된 페이지 변화만 보고하며 콘솔이 변화를 일으켰다고 단정하지 않는다.
5. 항상 같은 case_id/session_id로 `nfc_cu_disconnect`를 호출한다. cleanup_pending이면
   같은 정리를 재확인한다. 호스트 close는 RF-off나 장치 명령 종료의 증거가 아니다.

| 도구 | 정확한 인자 |
|---|---|
| `nfc_cu_read_start` | `case_id, session_id, tag_ref, approval_id=None` |
| `nfc_job_status` | `job_id, wait_seconds=0.0, case_id=None` |
| `nfc_job_cancel` | `job_id` |
| `nfc_jobs` | `active_only=False, case_id=None` |

페이지 범위·UID·family·RAW·출력 경로·읽기 시간·재시도 인자는 없다. status 대기는0..50초다.
추가 키·숫자 문자열·bool과 숫자 간 변환·비유한값을 거부한다. read_start는 실제 기기에
영향을 주는 도구이며, 상태 조회의 로컬 기록 정리와 구분한다. 같은 세션은 읽기 하나만 사용한다.

## 읽기 완료도와 job 결과

worker의 wire 예산은 시작부터45초, 명령 하나는 남은 시간과2초 중 작은 값이다.
읽기 뒤 host 검증·저장에는 별도5초를 한 번 사용한다. 협력적인 한도이며 커널 I/O나
장치 명령을 그 시각에 물리적으로 중단한다는 보장은 없다.

각 READ16B 중 시작 페이지의 첫4B만 저장한다. 계열별45/135/231페이지를 유한 순서로
시도하며, 실패 뒤 남은 페이지를 null로 남긴다. admission 이전 실패는 snapshot을 만들지 않는다.
admission 뒤 time_limit 또는 nfc_scan_invalid만 불완전 읽기로 게시할 수 있다.
취소·프로토콜·허가·신원 오류는 게시 가능한 partial로 바꾸지 않는다. 실패 뒤 재선택·
재전송·재연결·남은 페이지 보충은 없다.

성공 job의 결과는 다음 필드만 가진다.

```text
ok, registered, status, artifact, provenance, tag_ref, family,
pages_total, pages_observed, read_complete, stop_reason,
inventory_binding_verified, physical_same_tag_verified, warnings
```

artifact는 `artifact_id,path,size,sha256`, provenance는
`kind,ledger_seq,ledger_entry_sha256`이다. status는 read_complete에 따른 ok 또는 partial이며
정상 partial 저장도 job succeeded다. 모든 페이지가 있어도 마지막 확인이 실패하면
read_complete=false를 유지한다. 페이지 개수로 완료를 다시 추정하지 않는다.

출처 원장 append와 artifact 등록은 별도 commit이다. 원장에 기록된 뒤 등록이 실패하거나
취소되면 파일과 실제 원장 receipt를 보존하고, job의 partial_result에
`ok=false,registered=false,artifact.artifact_id=null`을 남긴다. 읽기 status와 job의
failed/cancelled를 함께 확인한다. 자동 등록 재시도·원장 rollback·import 변환은 없다.

이미 artifact가 commit된 뒤의 취소·audit·정리 오류는 실제 receipt를 보존한다.
warnings는 해당되는 고정 값만 순서대로 반환한다:
`provenance_close_unconfirmed`, `artifact_registration_incomplete`,
`post_commit_callback_failed`, `output_close_unconfirmed`.

## 파일과 출처

서버 생성 파일은 `nfc/cu-read-NNN.json`, schema `pweh.nfc-cu-snapshot/v1`, profile
`cu-ntag21x-pages-v1`이다. 최대64KiB의 canonical ASCII JSON과 마지막 LF 한 개이며,
단일 링크 일반 파일을0444로 게시한다. 원시 identity와 페이지를 포함하므로 에이전트는
파일을 직접 열지 않고 전용 parse/diff 도구를 사용한다. MCP·job·오류·요약에는 원문을 내보내지 않는다.

snapshot은 현재 scan/inventory의 ref·seq·entry SHA와 케이스 솔트 지문, 고정 reader 버전,
실제 관찰한 family/identity, 읽은 페이지 prefix와 null suffix를 담는다. duplicate key·
추가 키·잘못된 숫자 타입·깊이8·JSON value2048개·정수 token20자리 상한을 검사한다.
페이지 길이·관찰수·UID/BCC·계열/version·완료도 관계도 별도로 확인한다.

Signature·Counter·Tearing은 관찰하지 않는다. 이 필드를0으로 채워 Flipper v4 파일을
만들지 않으며, PWD/PACK 페이지의 반환0은 실제 비밀번호가0이라는 증거가 아니다.
snapshot_atomic, physical_same_tag_verified, device_command_termination_verified,
rf_off_verified, host_crc_verified, tag_content_written, authentication_attempted,
emulation_performed는 모두false다.

분석 입구는 등록 artifact ID, 같은 FD의 전체 크기·SHA, 현재 inventory, 마지막 동일 경로의
전용 device-read 원장 행을 함께 대조한다. source는 정확히
`nfc-mcp/nfc_cu_read_start`여야 한다. producer 문자열·파일명·복사본·일반 device-read·
가져온 CU JSON으로 대신할 수 없다. 오래된 CU 기록 뒤 다른 kind가 기록된 경우도 거부한다.
Flipper 또는 CU로 만든 inventory 모두 동일 신원·계열·원장 결속을 만족하면 사용할 수 있다.

기존 imported NFC v4 파일의 사람 출처 증명과 parser는 그대로 유지한다. CU snapshot은
전용 device-read 출처를 요구하며 import 증명을 새로 만들지 않는다. diff는 imported끼리
또는 CU snapshot끼리만 허용한다. 두 형식의 혼합은 nfc_source_mismatch다.

## 페이지 비교와 요약

새 분석 profile은 `cu-ntag21x-snapshot-analysis-v1`이다. inspect는 관찰한 페이지 수와
미관찰 수, 원래 읽기 완료도를 보고한다. diff는 양쪽 모두 관찰한 페이지만 비교하며
변경 위치의 정렬된 page index만 반환한다. 원문·개별 page hash·비밀값·영역 의미 추정은 없다.

항상 다음 관계를 보존한다.

```text
pages_compared + before_only_pages + after_only_pages
+ neither_observed_pages + comparison_unexamined_pages = pages_total
```

두 입력의 bytes 검사는 끝났어도 비교 시간 제한으로 페이지 비교가 미완료일 수 있다.
이때 changes_complete=false이고 변경 목록은 하한이다. stored_pages_equal은 양쪽 읽기와
전체 비교가 모두 완료된 때만 bool이며, 나머지는 null이다. 공통 prefix가 같다는 사실을
전체 snapshot 동일함이나 같은 실물의 증명으로 해석하지 않는다.

분석 결과는 기존 `analysis/nfc-file-NNN.json` 또는 `analysis/nfc-diff-NNN.json`에
저장한다. `nfc-analysis` 요약의 results6필드는 실제 parse/diff 결과에서만 채운다.
read receipt는 artifact 또는 일반 단계 기록에 남기며 inspect/diff 결과로 넣지 않는다.
요약의 네 false flag와 phase `nfc-behavior-analysis`는 그대로 유지한다.
