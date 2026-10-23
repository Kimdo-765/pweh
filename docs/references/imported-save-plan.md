# 가져온 원시 세이브의 로컬 변경 계획

`fw_plan_imported_save`는 같은 케이스에 가져온 원시 세이브의 지정된 정수와 체크섬을 바꾼
**전체 로컬 사본**을 만든다. 사용자가 값 변경을 명시했을 때만 호출한다. 분석만 요청했다면
`fw_save_diff`·`fw_checksum_find` 결과를 기록하고 편집값이나 checksum 후보를 임의 선택하지 않는다.

## 입력과 범위

```text
fw_plan_imported_save(case_id, artifact_id, offset, length, edits,
  purpose, unlock_source, online_capable, checksum=None, max_seconds=30)
```

소유/허가가 기록된 케이스에서 `case_import_file`로 파일을 가져온 뒤
`case_get(case_id="<id>", include_artifacts=true)`의 아티팩트 목록에서 해당 경로·크기·SHA를
확인하고 `id`를 선택한다. 입력 경로 대신 그 `artifact_id`를 넘긴다.

| 인자 | 계약 |
|---|---|
| `artifact_id` | 같은 케이스의 일반 파일 하나, 전체 크기 1바이트~8MiB |
| `offset`, `length` | 필수 정수. 선택 범위 `[offset, offset+length)`가 입력 파일 안에 있어야 함 |
| `edits` | 1~16개. 각 항목은 정확히 `{offset,encoding,value}`이며 value도 정수 |
| `purpose` | `score`, `progress`, `in-device-unlock` |
| `unlock_source` | `in-device`, `owned-tag` |
| `online_capable` | `no`, `unknown`. 확인하지 않았다면 `unknown` |
| `checksum` | null 또는 정확히 `{algorithm,endian,location,range}` |
| `max_seconds` | 유한한 숫자, `0 < max_seconds <= 30`. 기본30초 |

선택·편집·checksum의 모든 좌표는 **입력 파일 절대 좌표**다. bool·실수·크기 문자열을
offset/length/value로 받지 않는다. 선택 밖 바이트와 전체 파일 길이는 유지한다. 이 좌표는
기기 주소가 아니며 partition·backup_path·port·쓰기 주소 인자는 없다.

지원 encoding은 기존 `u8/i8`, `u16le/u16be/i16le/i16be`, `u32le/u32be/i32le/i32be`,
`bcd2le/bcd2be/bcd4le/bcd4be`다. 문자열·임의 바이트 편집은 받지 않는다. 겹친 편집, 범위 밖
편집, checksum 저장 필드와 겹친 편집, 변화가 없는 결과는 거부한다.

`fw_checksum_find`의 `location_abs`·`range_abs`를 정수로 옮겨 위4필드만 지정한다.
`range=[start,end]`의 end는 제외하며 저장 필드와 계산 범위 모두 선택 범위 안에 있어야 한다.
알고리즘은 기존 24종을 사용한다. endian은 1바이트 알고리즘이면 null, 그 밖에는 `le` 또는 `be`다.
`sum32`는 바이트 합 mod2^32이고 `sum32le`는 u32le 워드 합이다.

원본에 지정된 checksum 규칙이 재현돼야 수정 뒤 같은 계산을 적용한다. 규칙 재현은
알고리즘의 유일성·실제 저장 루틴·게임 수용을 증명하지 않는다. `checksum=null`은 해당
무결성 구조를 검사하지 않았다는 뜻이다. `in_checksum_range`는 편집 span과 계산 범위의
**겹침 여부**이며 완전 포함을 뜻하지 않는다. checksum이 없으면 null이다.

## 출처와 생성 파일

같은 경로의 최신 원장 기록이 `imported-unattested`인지 확인하고, 입력 artifact와 같은 FD의
크기·SHA를 처음과 최종 등록 시점에 대조한다. `source`에는 `kind="case-artifact"`, 입력 `artifact_id/size/sha256`,
`import_provenance={kind:"imported-unattested",seq,record_sha256}`만 담는다.
`record_sha256`은 원장 항목의 canonical JSON 해시다.

`imported-unattested`는 기존 원장의 kind다. 기존 증명 유무와 관계없이 이 로컬 계획은 같은
바이트 결속을 확인하며, 증명을 새로 요청하거나 출처를 device-read로 승격하지 않는다.
두 번 import하거나 이름을 바꾼 사본은 독립 획득·새 기기 백업이 아니다.

새 디렉터리 `patches/imported-save-plan-NNN/`에 `planned.bin`과 `manifest.json`을 만든다.
manifest는 `pweh.imported-save-plan/v1`, profile은 `raw-save-local-plan-v1`, stage는 항상
`planned`다. 두 파일은 읽기 전용으로 저장하고 **manifest 하나**를 아티팩트로 등록한다.
binary는 manifest의 size/SHA에 결속된 파생 파일이며 독립 artifact ID를 만들지 않는다.

성공 반환의 연결은 다음과 같다. 경로와 해시는 실제 반환값을 사용한다.

```text
{
  ok: true, stage: "planned", report: <manifest>,
  analysis: {path, sha256, size, artifact_id},
  patch: {path, size, sha256}, warnings: []
}
```

`report.edits`에는 지정한 위치·encoding·`before_value/after_value/in_checksum_range`,
`report.checksum`에는 계산의 before/after 숫자와 두 재현 여부가 남는다. 유효한 BCD 숫자로
해석되지 않는 원본의 before_value는 null일 수 있다. raw hex·전체 파일 내용·입력 원래 경로·
원장 source/extra는 보고서에 복사하지 않는다. **편집한 숫자 자체는 보고서에 보인다.**
일반 원시 파일의 모든 비밀값을 자동 마스킹하는 기능으로 사용하지 않는다.

입력 전체와 선택 범위에서 NVS 형식, ESP 파티션 표 입력을 식별하면 거부한다. 이 검사가
모든 비밀·암호화·서명 형식을 탐지한다는 뜻은 아니다. NVS 비밀 키 제한을 우회하거나,
서명/HMAC·판매 토큰·온라인 구매 해금을 조작하는 경로로 사용하지 않는다.

다음 6개는 항상 false다: `device_association_verified`, `independent_backup_verified`,
`write_address_verified`, `write_ready`, `device_written`, `game_acceptance_verified`.
새 import/device-read/patch-plan 원장 기록이나 쓰기 명령은 생성하지 않는다.
결과를 `fw_patch_build`의 ESP device-read base 또는 `fw_verify_writeback`의 기대값으로 쓰지 않는다.

## 합성 예제와 요약

[fwtriage README의 64바이트 예제](../../mcp-servers/fwtriage-mcp/README.md#가져온-원시-세이브-분석-예제)는
`raw-save-03.bin`의 offset 16에 score 123456, offset 20에 level 3, offset 60에
`sum32([0,60))=2251`을 저장한다. 실제 게임 형식이나 화면 관찰이 아니다.

**이 합성 score를 999999로 바꾸라는 명시 요청**을 받은 경우, import 후 `case_get`에서
세 번째 파일의 artifact ID를 골라 호출한다. 온라인 사실은 미확인이므로 `unknown`이다.

```text
fw_plan_imported_save(
  case_id="<id>", artifact_id="<case_get에서 선택한 raw-save-03.bin의 id>",
  offset=0, length=64,
  edits=[{"offset":16,"encoding":"u32le","value":999999}],
  checksum={"algorithm":"sum32","endian":"le","location":60,"range":[0,60]},
  purpose="score", unlock_source="in-device", online_capable="unknown", max_seconds=30)
```

격리된 두 MCP Client로 위 예제를 호출해 확인한 결과는 다음과 같다.

| 확인 항목 | 합성 결과 |
|---|---|
| score | `before_value=123456`, `after_value=999999`, `in_checksum_range=true` |
| checksum | `before=2251`, `after=2104`, 원본·수정 후 규칙 모두 재현 |
| 사본 | 64바이트, 점수·checksum 저장 필드 밖 바이트 동일, 원본 유지 |
| 등록 | 기존 입력과 새 manifest 아티팩트 2개. 출처 원장은 기존 import 1개 유지 |
| 요약 | `local_plans` 6필드와 `patches=[]`로 실제 `case_record_step` 저장 |

`save-analysis`의 기존 `patches[]`는 ESP 경로다. 이 로컬 결과는 별도 `local_plans[]`에
반환값으로 다음 6필드를 기록한다. 입력 ID와 생성 manifest의 artifact ID를 혼동하지 않는다.

```text
local_plans = [{
  analysis_path: result.analysis.path,
  report_sha256: result.analysis.sha256,
  patch_path: result.patch.path,
  patch_sha256: result.patch.sha256,
  input_artifact_id: result.report.source.artifact_id,
  stage: "planned"
}]
```

로컬 계획만 만들었으면 `patches=[]`이며 분석만 했으면 `local_plans`를 생략하거나 []로 둔다.
`game-save-unlock-analysis`의 다른 필수 요약 필드와 미확인 한계는 유지한다. 완료는 실제
manifest/binary 경로·SHA·요약 기록으로 판단하며 기기 쓰기·게임 수용 완료로 보고하지 않는다.

## 시간·실패·정리

처리 마감은 최대30초이고, 등록 직전 입력·출력·원장을 최종 확인하는 별도5초 마감을 한 번
정한다. 기존 유한 편집/checksum helper 호출 전후에 취소·시간을 확인한다. helper 내부 계산이나
OS I/O를 즉시 중단하는 보장은 없다.

입력·범위·규칙 오류는 `imported_save_input_invalid`, 입력 한도는 `imported_save_input_limit`,
변경은 `imported_save_input_changed`, 같은 결과는 `imported_save_no_changes`로 닫는다.
그 밖에는 `imported_save_failed`, `imported_save_cleanup_incomplete`, `cancelled`, `time_limit`을
반환하며 원시 예외·입력 내용을 노출하지 않는다. 거부된 파일을 다른 경로나 입력 형식으로
우회하지 않는다. `forensics/`·`emu/` 입력은 이 흐름으로 가져오지 않는다.

등록 전 취소/실패는 부분 산출물을 게시하지 않는다. 등록 뒤 실패는 결과를 보존하며 고정
warning `post_commit_callback_failed` 또는 `output_close_unconfirmed`가 붙을 수 있다.
cleanup 미확정 항목을 임의로 지우지 않는다. warning은 성공한 commit을 취소하거나 ready로
승격하는 값이 아니다.
