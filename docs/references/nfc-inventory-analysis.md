# 스캔 기록에 결속한 NFC 파일 분석

`pweh-flipper`의 고정 NTAG21x probe와 `pweh-nfc`의 inventory·파일 검사·비교를 연결한다.
지원 계열은 NTAG213/215/216이다. 공식 Flipper1.5.1 문법 기준 commit은
`9e810dc399e027e48ce07751df72168abbb19065`이며 실제 reader·태그 검증은 아직 수행하지 않았다.
기존 [NFC 파일 파서](nfc-file-profile.md)의 공개 결과·부분 읽기 의미는 유지한다.

## 도구와 참조

| 도구 | 정확한 인자 | 역할 |
|---|---|---|
| `flipper_nfc_probe` | `case_id, approval_id=None` | 기존 ready Flipper 세션에서 고정 probe·GET_VERSION·임시 SD 파일 정리 후 scan 사실 등록 |
| `nfc_tag_inventory_add` | `case_id, scan_ref` | 같은 케이스 보호 원장의 허용 scan을 inventory에 결속. `US-` scan_ref(`nfc_cu_ul_scan`)는 `tag-ownership` 증명을 다시 확인한 뒤 UL inventory(`UT-`)로 결속 |
| `nfc_parse_file`·`nfc_diff_dumps`(UT-) | `tag_ref` UT- | Ultralight CU snapshot만 받고 `tag-ownership` 증명을 다시 확인(없으면 `attestation_required`)한 뒤 `nfc-ul-file-analysis` 저장 |
| `nfc_parse_file` | `case_id, artifact_id, tag_ref, max_seconds=5` | 같은 inventory와 출처 증명에 결속한 파일의 기존 구조 검사 |
| `nfc_diff_dumps` | `case_id, before_artifact_id, after_artifact_id, tag_ref, max_seconds=5` | 두 파일 각각의 결속을 확인한 뒤 기존 저장 페이지 비교 |

scan/tag 참조는 서버가 생성한 `NS-`/`NT-` 뒤 lowercase hex32, artifact는 같은 케이스의
실제 `A-` ID다. 임의 UID·ATQA·SAK·family·명령·키·attested flag는 받지 않는다.
SDK는 추가 키와 scalar 타입 변환을 거부하고 원문 입력·예외를 고정 오류에 복사하지 않는다.

모든 도구는 케이스 소유·허가를 확인한다. probe는 Flipper SD의 파일 생성·제거를 포함해
MODIFY gate를 거친다. `approval_required`이면 사람이 별도 터미널에서 승인하고 같은
인자와 `approval_id`로 재시도한다. 나머지 세 도구는 로컬 기록을 쓰는 `ANN_LOCAL_WRITE`다.
기존 inventory를 이용할 때 Flipper가 계속 연결되어 있어야 한다는 조건은 없다.

## 고정 probe의 범위

기존 [Flipper 연결](flipper-read-transport.md)의 수동 배너·DTR gate·전체 USB 잠금·
역할/guard·명령 전 fresh 검사를 재사용한다. probe 전체는45초, 개별 명령은 남은 시간과
10초 중 작은 값이다. NFC 응답은4KiB/32줄/줄512B, probe 파일은4KiB 이하다.

1. 사용자가 준비한 `/ext/pweh/<case_id>/`에 서버 생성 `probe-<UUID32>.nfc` 이름의 부재를
   bounded 목록으로 확인한다. 새 디렉터리·기존 파일 덮어쓰기는 없다.
2. 고정 NFC subshell에서 ISO14443-3A probe 파일 하나를 만들고 정상 상위 prompt로 복귀한다.
   메모리로 읽은 파일의 크기·MD5와 strict 식별값을 확인한다. host 원문 아티팩트는 만들지 않는다.
3. UID7·SAK0 후보만 새 activation의 고정 GET_VERSION을 진행한다. 정확한 CRC와 세
   NTAG21x version 중 하나, 두 activation의 식별값 일치가 필요하다. 모든 경로에서 페이지 READ는0이다.
4. 정상 문맥에서 자신이 만든 파일의 크기·MD5를 재확인하고 그 이름 하나를 제거한 뒤 부재를
   확인한다. 응답·식별값·정리가 모두 성공한 경우만 보호 원장에 scan 사실을 남긴다.

NFC `dump -f`는 quote를 제거하지 않는 parser이므로 공백 없는 서버 생성 경로를 비인용으로
구성한다. 상위 `storage` 명령은 기존 인용 경로를 유지한다. 이 차이를 사용자 raw 입력으로
노출하지 않는다. 공식 근거는 [NFC 인자 처리](https://github.com/flipperdevices/flipperzero-firmware/blob/9e810dc399e027e48ce07751df72168abbb19065/applications/main/nfc/cli/nfc_cli_command_processor.c),
[인자 parser](https://github.com/flipperdevices/flipperzero-firmware/blob/9e810dc399e027e48ce07751df72168abbb19065/lib/toolbox/args.c),
[probe 저장](https://github.com/flipperdevices/flipperzero-firmware/blob/9e810dc399e027e48ce07751df72168abbb19065/applications/main/nfc/cli/commands/dump/nfc_cli_command_dump.c)이다.

raw handler는 SELECT 뒤 host 판단을 기다리지 않고 GET_VERSION을 보낸다. 첫 probe가
거부된 경우 전송을 막지만 activation 사이 바뀐 태그에 GET_VERSION이 절대 가지 않았다는
보장은 없다. 최종 불일치는 inventory 허용을 막는다. ATQA는 파일의 MSB 저장 순서로
정규화하며 raw 쪽만 한 번 뒤집는다. [공식 raw 순서](https://github.com/flipperdevices/flipperzero-firmware/blob/9e810dc399e027e48ce07751df72168abbb19065/applications/main/nfc/cli/commands/raw/protocol_handlers/iso14443_3a/nfc_cli_raw_iso14443_3a.c).

timeout·취소·framing 실패는 terminal이다. 추가 exit/remove/ETX·재접속·재동기화 없이
원격 임시 파일 정리 미확인을 보존한다. 항상 `flipper_close`로 worker·물리 핸들·lease 정리를
확인하며, cleanup_pending은 같은 close로 재확인한다. host close는 RF field off 증명이 아니다.

## 출처와 inventory

두 서버는 같은 케이스 보호 출처 원장을 사용한다. scan은 고정 source/tool/profile의
device-fact이며 generic 파일 복사·ESP device-read·사용자 선언을 scan으로 승격하지 않는다.
scan의 private UID/ATQA/SAK/version은 보호 원장 안에 보존한다. CU 읽기 snapshot에도
전용 분석용 identity·page가 있으므로 에이전트가 그 파일을 직접 열지 않는다. 공개 결과의 `identity_digest`는
케이스 솔트 표시값이며 exact 식별값의 권위를 대신하지 않는다.

inventory는 scan의 명시 ref·seq·전체 entry SHA와 결속한다. entry SHA와 fact data의 SHA는
구분한다. 같은 scan 반복 등록은 같은 tag_ref를 반환한다. `nfc/inventory.json`은 최근32개
마스킹 projection과 전체 개수·잘림 표시를 가진 조회 사본이다. 사본만 존재하거나 변조된 경우
허용하지 않으며, tag 조회는 보호 원장의 전체 bounded snapshot을 확인한다.

원장 읽기는16MiB/10000entries/64KiB chunk와 기존 체인 parser를 사용한다. append도 같은
lock에서 제한·대상 scan을 재검증한다. 기존 일반 소비자의 기본 원장 동작은 바꾸지 않는다. 기록이 commit된 뒤 FD 정리를 확인하지 못하면 receipt를 보존하고 `provenance_close_unconfirmed` 경고를 반환한다. 이 경고는 원장 내용이나 해시를 바꾸지 않는다.
이 상한은 협력적 시간 검사이며 JSON·커널 I/O를 강제 중단하는 watchdog은 아니다.

## 가져온 파일 admission과 저장

일반 파일은 `case_import_file(..., dest_subdir="nfc", kind="other")` 또는 기존 Flipper storage pull의
artifact ID로 고른다. 입력 하나는1MiB, diff 합은2MiB 이하다. forensics/emu/보호 경로·링크·
디렉터리는 거부한다. 한 번 연 FD에서 전체 SHA·크기·등록 projection·부모/이름 신원을 대조하고
기존 strict parser가 얻은 private 식별값을 scan과 비교한다.

출처는 최신 경로 기록과 같은 케이스·전체 SHA의 기존 `provenance-import` 사람 증명이 필요하다.
원장 기록이 전혀 없는 일반 복사 artifact는 고정 NFC source의 imported-unattested로만 기록할 수
있다. 다른 출처 기록이나 불일치를 새 import로 덮지 않는다. `attestation_required`이면 사람이
`pweh attest <id>`로 답하고, 대기 동안 입력 FD는 닫힌다. 만족 후 새 worker가 최초 SHA·
inventory·현재 증명을 모두 다시 확인한다. diff 두 SHA는 각각 증명이 필요하다.

입력 작업≤5초와 결과 생성 뒤 최종 검사/등록≤5초를 구분한다. 결과는 새
`analysis/nfc-file-NNN.json` 또는 `analysis/nfc-diff-NNN.json`,0444·128KiB 이하다.
최종 metadata commit에서 입력 전체 SHA·등록 상태·명시 원장 기록·현재 증명·출력 seal을
대조한다. 여러 보호 저장소의 전역 원자 transaction은 아니며 기존 신뢰 모델을 유지한다.
commit 전에는 자기 inode만 정리하고 commit 뒤 취소·audit/close 오류에는 receipt를 보존한다.

## 반환과 해석

scan은 `nfc-scan`, inventory는 `nfc-inventory` schema의 마스킹 projection이다. 파일 도구의
성공 결과는 `ok, report, analysis, warnings`, `analysis`는 `path,sha256,size,artifact_id`다.
`report`는 `nfc-file-analysis` 봉투 안에 기존 `inspection`을 그대로 담는다.

- `source.files`는 입력 순서의 artifact ID·크기·SHA·출처 종류·원장 seq와 imported 증명 id 또는 CU 원장 entry SHA다. 입력 원시 경로는 없다.
- `inventory_binding_verified=true`는 기록·파일 식별값 결속이며 `physical_same_tag_verified=false`다.
- partial read의 0값은 읽기 증거가 아니며 페이지 비교의 unknown/null을 유지한다.
- ISO14443-3A 헤더에는 페이지 배치가 없으므로 diff의 `no_page_layout`은 그대로다.
- 실제 진품·복제 없음·게임 반응·전체 태그 덤프·인증·쓰기·에뮬레이션은 확인하거나 수행하지 않는다.

요약은 [nfc-behavior-analysis Skill](../../skills/nfc-behavior-analysis/SKILL.md)의 `nfc-analysis`다.
실제 참조·해시·status와 네 false flag를 기록한다. 합성 Client 시험은 소프트웨어 계약을 검증하며
실제 Flipper·태그·USB/RF 환경의 호환성 시험을 대신하지 않는다.

## CU 스캔을 사용하는 경우

[CU 고정 읽기 계약](cu-ntag-read-provider.md)의 connect→scan→disconnect로 받은 실제 scan_ref도 같은 inventory 입구에 전달한다. CU는 READ0/1과 reader CRC 검증을 포함하는 별도 source/profile이며 Flipper의 page READ 없음·scratch 정리·host CRC 규칙을 바꾸지 않는다. 기존 imported 파일의 식별값·출처 증명·최종 FD 검사는 동일하다. [CU 페이지 스냅샷](cu-read-snapshot.md)은 read job이 직접 만든 등록 artifact와 최신 동일 경로의 전용 device-read 원장·현재 inventory를 확인한다. CU끼리의 diff는 양쪽 관찰 페이지만 비교하고 읽기/비교 미완료의 null을 유지한다. imported와 CU snapshot의 혼합 비교는 거부하며 가져온 파일을 device-read로 승격하지 않는다.

Ultralight 계열은 별도 namespace다. `nfc_cu_ul_scan`은 READ 없이 계열을 확인하고 사람의 `tag-ownership` 증명(사용자 소유 또는 소유자 서면 허가) 뒤에만
`nfc-ultralight-cu-scan-v1` 사실(`ul_scan_ref` `US-…`, 원장 `attestation_id`)을 남긴다. `nfc_tag_inventory_add`는 `US-` scan_ref를 받으면 같은 증명을 ctx 없이 다시 확인하고
(없으면 기다리지 않고 `attestation_required`) 원장 잠금 안에서 같은 증명 id를 재확인한 뒤 `nfc-ultralight-inventory-v1`(`ul_tag_ref` `UT-…`)을 기록한다.
UL 행은 `scan_ref`·`tag_ref` 키를 쓰지 않으므로 NTAG 색인·NTAG cache(`nfc/inventory.json`)·NS-/NT- 흐름은 바뀌지 않는다.
UL 키를 가진 다른 kind 행이나 형식이 다른 UL 행은 UL 색인 전체를 오염으로 보고, NTAG 키를 가진 UL 행은 두 색인 모두 거부한다.
UL scan 행의 프로필은 닫힌 UL 프로필 집합(`UL_KNOWN`)의 정확한 이름 조회 뒤 hash·commit 전체 일치로 검증한다(NTAG `KNOWN`과 같은 방식).
UL recipe를 다시 고정할 때는 새 이름을 쓰고 이전 행을 검증 전용으로 남기므로 이미 기록한 UL scan·inventory 행은 그대로 검증된다.
inventory 결과의 `attestation.attestation_id`는 이번 호출에서 다시 확인한 현재 증명 id, `attestation.inventory_attestation_id`는 inventory 행의 id다(재증명 뒤에는 다를 수 있다).
UL 확인 지점은 기록의 질문 문구 전체와 recipe의 `decided_via` 목록(cli-tty·elicitation)도 확인한다.
한계: GET_VERSION의 status `0x01`·빈 payload(`01-empty`)는 원조 Ultralight의 무응답과, scan 뒤 auto-select 전에 태그가 field를 벗어난 경우(firmware는 auto-select 실패 때 scan 상태 `0x01`을 돌려준다)가 섞인다. 그래서 그 한 번의 응답으로 NTAG213 같은 다른 Type 2 태그도 `ultralight_or_ultralight_c` UL scan 사실·inventory로 남을 수 있다. 원조 UL/UL C 결과는 태그를 움직이지 않은 채 `nfc_cu_identify`로 다시 확인한다. 페이지 읽기는 읽기 직전 GET_VERSION이 다시 원조 계열이어야 하므로
8B로 답하는 태그는 READ 없이 멈춘다(두 번 모두 `01-empty`인 경우는 하드웨어 확인 항목).

`UT-` tag_ref는 `nfc_cu_read_start`·`nfc_parse_file`·`nfc_diff_dumps`에서 별도 분기다([Ultralight 스냅샷 계약](cu-ultralight-read.md)).
NTAG와 다른 점: 읽기 전·frame 전·원장 append 직전·등록 check와 parse/diff 입구·분석 단계마다 `tag-ownership` 증명을 같은 id로 다시 확인(엄격 재확인,
없으면 `attestation_required`), page마다 f4 단독 activation과 겹침 대조, PWD/PACK·UL C 키 페이지는 요청하지 않는 보류(null), NAK는 정상 끝,
snapshot은 `nfc/cu-ul-read-NNN.json`(device-read 원장에 읽기 때 증명 id), 보고서는 `pweh.nfc-ul-file-analysis/v1`(`analysis/nfc-ul-file|diff-NNN.json`)이다.
가져온 v4·NTAG snapshot은 UT- 흐름에서, UL snapshot은 NT- 흐름에서 `nfc_source_mismatch`다.
