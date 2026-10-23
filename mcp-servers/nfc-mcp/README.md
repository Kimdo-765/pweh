# pweh-nfc

같은 케이스의 고정 Flipper scan 사실과 등록 파일을 결속하는 NFC 오프라인 분석 서버다. NTAG213/215/216만 inventory에 등록하며, 파일 내용을 태그에 쓰거나 인증·키 탐색·에뮬레이션을 수행하지 않는다.

| 도구 | 입력 | 결과 |
|---|---|---|
| `nfc_tag_inventory_add` | `case_id`, `scan_ref` | `tag_ref`, `scan_ref`, family, 케이스 솔트 지문, scan/inventory 원장 seq·SHA |
| `nfc_parse_file` | `case_id`, `artifact_id`, `tag_ref`, `max_seconds=5` | 기존 순수 검사 결과와 출처 결속, 실제 저장 경로·SHA |
| `nfc_diff_dumps` | `case_id`, `before_artifact_id`, `after_artifact_id`, `tag_ref`, `max_seconds=5` | 저장 페이지 비교 결과와 두 파일의 출처 결속, 실제 저장 경로·SHA |

`flipper_nfc_probe`는 별도 `pweh-flipper` 서버에서 실행한다. 성공한 같은 케이스 `scan_ref`를 inventory에 등록한 뒤, `case_import_file` 또는 허용된 Flipper 파일 복사로 등록한 artifact id를 사용한다. 사용자가 제출한 UID·family, cache, 임의 producer 문자열은 scan 사실을 대신하지 않는다. 기존 `provenance-import` 사람 증명을 요구하면 사람이 별도 터미널의 `pweh attest <id>`로 답한다. 에이전트가 증명을 대신하지 않는다.

각 입력은 1 MiB 이하의 단일 링크 일반 파일이다. `forensics/`, `emu/`, 보호 경로, 심볼릭 링크·하드 링크·디렉터리는 거부한다. 증명 요청 전 입력 FD를 모두 닫고, 만족한 뒤 다시 열어 최초 SHA와 scan/inventory 결속을 비교한다. 최종 등록 직전에도 현재 원장·증명과 같은 FD의 내용·이름·부모 신원을 재확인한다. atime는 신원 비교에 쓰지 않는다.

`max_seconds`는 0초 초과 5초 이하이며 각 입구·최종 분석 worker의 읽기·원장·파싱에 적용한다. 분석 결과 생성 뒤 최종 검증·저장에는 별도 5초를 사용한다. 원장 검사는 16 MiB·10,000 entries, 파일 읽기는 64 KiB chunk, 결과는 128 KiB 이하다. 이 한도는 협력적 검사이며 모든 Python·커널 호출의 즉시 중단 보장은 아니다.

성공 반환은 `{ok, report, analysis:{path,sha256,size,artifact_id}, warnings}`다. 결과는 `analysis/nfc-file-NNN.json` 또는 `analysis/nfc-diff-NNN.json`에 0444로 등록한다. import 원장 commit 뒤 FD 정리 불확실성은 `provenance_close_unconfirmed` 경고로 증명 대기/최종 응답에 보존한다. 출력 commit 뒤 오류는 산출물을 보존하고 `post_commit_callback_failed` 또는 `output_close_unconfirmed` 고정 경고로 알린다. commit 전 정리는 이번 생성 inode만 대상으로 하며 확인되지 않은 교체 파일은 보존한다.

공개 결과에는 raw UID·ATQA·SAK·GET_VERSION·페이지·Counter·PWD/PACK이 없다. 보호 scan 원장에만 내부 신원 bytes를 기록한다. 전체 입력 SHA와 케이스 솔트 지문은 익명성 보장이 아니다. `inventory_binding_verified=true`는 기록의 결속이며 `physical_same_tag_verified=false`는 유지한다. 기존 core의 `device_association_verified=false`도 변경하지 않는다.

부분 읽기(`Pages read < Pages total`)의 0값을 실제 읽은 메모리로 해석하지 않는다. ISO 헤더의 검사 결과는 허용하지만 페이지 diff는 `no_page_layout`으로 비교 불가다. 불완전 layout의 null·partial/unsupported 의미를 그대로 보존한다. Skill은 실제 반환된 출력 경로와 해시로 `nfc-analysis` 요약을 기록한다.

개발 시험은 합성 Flipper wire와 격리 케이스만 사용한다: `tests/servers/test_nfc_mcp.py`, `tests/servers/test_nfc_analysis.py`. 전체 공용 계약은 [architecture](../../docs/architecture.md), 운영 흐름은 [NFC 분석](../../docs/references/nfc-inventory-analysis.md)을 따른다.
