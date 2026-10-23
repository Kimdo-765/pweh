# NFC 요약 필드 연결

도구의 실제 반환만 옮긴다. 아래 참조와 해시는 형식을 보여 주는 자리표시자다.

| 요약 필드 | 근거 |
|---|---|
| `tags[].tag_ref/scan_ref/family/identity_digest` | `nfc_tag_inventory_add`의 성공 결과 |
| `results[].artifact_id/path/sha256` | parse/diff 응답의 `analysis.artifact_id/path/sha256` |
| `results[].operation/status/tag_ref` | `report.operation/status/source.tag_ref` |
| `mode` | `scan-bound-offline` 고정 |
| 네 false flag | 이 Skill이 확인하지 않거나 수행하지 않은 범위를 그대로 유지 |

각 배열은 최대32개다. 결과가 더 있으면 선택한 범위를 summary 설명에 명시하고, 도구 결과나 입력을 임의로 잘라 완전한 검사처럼 보고하지 않는다. 원 UID·ATQA·SAK·GET_VERSION·페이지·키·PWD/PACK는 요약에 넣지 않는다.

요약 JSON 예시는 [SKILL.md](SKILL.md)의 정리와 요약 절을 따른다.

`inventory_binding_verified=true`는 보호 원장의 명시 스캔·inventory와 파일 식별값이 일치했다는 뜻이다. 진품·복제 없음·항상 같은 실물·원자적인 태그 선택을 뜻하지 않는다. `identity_digest`는 케이스 솔트가 적용된 표시값이며 권위는 private exact 식별값과 검증된 원장 기록이다.

ISO14443-3A 헤더는 유효한 scan에 결속하여 구조 검사할 수 있으나 페이지 배치가 없으므로 diff의 `no_page_layout`을 유지한다. `Pages read < Pages total`은 기존 partial이며 저장된 0바이트로 읽기 범위를 추정하지 않는다. 같은 UID claim만으로 부분 파일의 페이지 대응을 복원하지 않는다.

일반 복사 파일의 출처 증명은 기존 `provenance-import`의 케이스·전체 SHA에 묶인다. 파일 내용·원장·증명 중 하나가 바뀌면 도구가 재검증하며, 한쪽 파일의 증명으로 다른 SHA를 허용하지 않는다. `nfc/inventory.json`은 마스킹 조회 사본이며 손상·삭제되어도 보호 원장 대신 신뢰하지 않는다.

CU scan은 `nfc_cu_connect`의 실제 세션으로 `nfc_cu_scan`을 호출해 얻는다. 기존 요약 필드는 동일하며 provider별 원시 식별값을 추가하지 않는다. Flipper의 page READ 없음과 CU의 두 시작 페이지 검증을 혼동하지 않으며, 두 경로 모두 물리 동일 태그 검증은 false다.
