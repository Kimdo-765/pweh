# 등록 power CSV의 오프라인 분석

`pweh-sdr`의 `sdr_peaks`는 같은 케이스에 등록된 rtl_power CSV 하나를 검사하고,
입력 SHA256에 결속한 통계·상위 전력값 보고서를 저장한다. 실제 수신기나 RF 캡처는
사용하지 않는다. 지원 profile은 `rtl-power-blog-v1.4.0-csv` 하나로 고정된다.

## 호출과 입력

```json
{
  "case_id": "power-example",
  "artifact_id": "A-0001",
  "max_seconds": 5
}
```

ID는 설명용이다. 소유·허가된 케이스에서 `case_get(include_artifacts=true)`로 등록 입력을
고른다. 아직 등록하지 않은 사용자 지정 일반 파일은 `case_import_file(kind="other")`로
가져온 뒤 응답의 `artifact.id`를 사용한다. 오프라인 분석을 위해 RF 장비를 연결하거나
새 RF 승인·증명을 만들 필요는 없다.

- `artifact_id`는 `A-` 뒤 4..8자리 숫자다. `max_seconds`는 기본5, bool을 제외한 유한 수
  `0 < value <= 5`이며 SDK는 문자열·숫자를 암묵적으로 변환하지 않는다.
- 입력은 등록 크기 0바이트~1MiB의 일반 파일이다. 빈 파일은 `unsupported/empty_input`으로
  기록할 수 있다. 1MiB를 넘으면 앞부분만 분석하지 않고 입구에서 거부한다.
- 직접 경로·URL·EV·offset·수신 설정·threshold·임의 profile을 받지 않는다.
  `forensics/`·`emu/`·보호 상태나 그 별칭, 다른 케이스, symlink·hardlink·특수 파일은 거부한다.
- 같은 FD에서 유한 청크로 읽고 전체 SHA를 대조한다. 등록 직전 입력 FD·부모·이름·원래
  artifact 정보·전체 SHA와 출력 신원·SHA를 다시 확인한다. 현재 등록 bytes의 일치이며,
  실제 수신 시점·장치·캡처 완전성·RF 허가를 입증하지 않는다.

## 제한된 CSV 문법과 수치 의미

형식 근거는 공식 rtl-sdr-blog V1.4.0의 고정 commit
`aed0ea19f3a273370a13c9009b96313c75d54c7b`의
[csv_dbm 출력](https://github.com/rtlsdrblog/rtl-sdr-blog/blob/aed0ea19f3a273370a13c9009b96313c75d54c7b/src/rtl_power.c#L695-L737)이다.
마지막 값은 앞 루프와 나눗셈 순서가 다른 별도 계산으로 출력된다. 앞 열과 값이 같거나
달라도 각 열을 하나씩 센다. 열 수를 FFT bin 수로 바꾸거나 마지막 열을 제거하지 않는다.

한 행은 다음 순서의 ASCII이고 LF 또는 CRLF로 끝나야 한다.

```text
date,time,low,high,step,samples,power,power,...
```

header/quote/BOM/주석/빈 행/탭/다른 인코딩을 조용히 건너뛰지 않는다. token 양끝의 ASCII
space만 제거한다. 날짜·시각은 고정 자리와 숫자 범위만 확인한 뒤 버리며, 실제 달력·시간대·
획득 시각·행의 시간 순서는 검증하지 않는다. 원시 시각은 결과에 없다.

low/high/samples는 unsigned 10진 정수다. `0 <= low < high <= 2**31-1`,
`1 <= samples <= 2**31-1`만 받는다. step은 양의 소수 두 자리이며 centi-Hz로 변환한 값이
1..280000000이다. power는 소수 두 자리의 선택적 음수 또는 정확한 `-inf`이고,
유한값은 `power_centi_db` 정수로 변환한다. NaN·다른 Inf·지수 표기는 지원하지 않는다.
이 제한은 producer의 모든 가능한 출력을 지원한다는 뜻이 아니다.

수용한 행마다 전력값이 최소2개 있어야 한다. `samples`는 파일의 선언값이다. crop과 반올림이
개입하므로 `(high-low)/step`과 열 수의 등식, 주파수 중심·전력 보정·실제 샘플 수를 검증하지 않는다.
한 행 전체가 문법·수치·예산 검사를 통과해야 그 행의 집계와 순위가 반영된다.

## 반환과 검사 범위

| 필드 | 내용 |
|---|---|
| `ok` | 보고서 등록에 성공하면 true |
| `report.schema` | `pweh.rf-power-analysis/v1` |
| `report.status` | inspection의 상태와 같음 |
| `report.source` | `kind="case-artifact"`, 입력 `artifact_id`, `size`, `sha256` |
| `report.params` | 고정 `profile`, `max_seconds` |
| `report.inspection` | `pweh.rf-power-inspection/v1` 전체 결과 |
| `analysis` | 출력 `path`, `sha256`, `size`, `artifact_id` |
| `warnings` | 고정 경고 목록 |

`report.source.size == inspection.coverage.input_bytes`다. 입력 SHA와 저장 보고서의 SHA는
서로 다른 대상이며 실제 취득 증명이 아니다. 입력 이름·경로는 source에 복사하지 않는다.
출력은 `analysis/rf-power-NNN.json`, 0444, 최대64KiB이며 `kind="other"`,
`producer="pweh-sdr"`, `extra.type="rf-power-analysis"`로 등록한다.

inspection은 수용 행·전력값·유한값·음의 무한대 개수, 선언 low/high/step 범위,
유한 power min/max와 상위32개 값을 반환한다. `peaks[]`의 행/값 index는0기반이고,
동률은 `(row_index,value_index)` 오름차순이다. 각 row의 low/high/step/samples는 해당 행의
선언이며 peak의 실제 중심주파수가 아니다. 유한값이 없으면 peaks는 빈 배열일 수 있다.
작은 입력에서는 이 통계로 값을 유추할 수 있으므로 익명화로 설명하지 않는다.

| 상태 | 의미 |
|---|---|
| `complete` | 최소 한 행을 수용하고 지원 문법으로 마지막 종결자까지 검사함 |
| `partial` | 시간·수량·행 길이 한도 또는 마지막 미완성 행으로 중단함 |
| `unsupported` | 빈 입력 또는 지원 밖 인코딩·필드·비유한값 표현 |
| `malformed` | 지원 문법의 행 종결·제어문자·필드 수·시각 문법·숫자 규칙 불일치 |

모두 저장 가능한 검사 상태다. `statistics_scope="accepted_prefix"`이고
`accepted_prefix_bytes + remaining_bytes == input_bytes`다. `remaining_range`는 미수용 suffix이며,
실패한 행에서 일부 검사를 이미 했을 수도 있다. 앞선 완전한 행만 통계에 포함한다.
top32 순위 출력만 잘린 경우는 검사 자체를 partial로 바꾸지 않는다.

입력1MiB, 한 행64KiB, 행4096, 전력값131072, 숫자 처리 단계262144 한도를 적용한다.
결과는 캡처 완전성·장치 결속·허가·주파수 중심·power 보정·프로토콜 해독·송신을 확인하지 않는다.
관련 여덟 검증 flag는 항상 false다.

## 시간·취소·등록

최대5초의 한 processing deadline을 케이스/입력 선택·읽기·해시·parser가 공유한다.
입력 확보 전 만료는 오류이며, parser의 `partial/time_limit`은 그 범위 그대로 저장할 수 있다.
결과가 생긴 뒤 별도5초의 최종 deadline을 한 번 정해 재해시·seal·잠금·원자 등록을 완료한다.
이는 협력 checkpoint이며 OS 호출의 강제 중단 보장은 아니다.

입구 오류는 `rf_power_input_invalid`, `rf_power_input_limit`, `rf_power_input_changed`, 일반 실패는
`rf_power_failed`, 커밋 전 정리 미확인은 `rf_power_cleanup_incomplete`이다.
`time_limit/cancelled`와 기존 케이스·소유/허가 오류는 고정 의미로 유지한다.
오류에 원문 CSV·파일명·예외 traceback을 넣지 않는다.

등록 전 실패는 이번 출력의 동일 inode일 때만 정리한다. 원자 등록 뒤에는 늦은 취소나
후처리 실패로 등록 파일을 지우지 않는다. `post_commit_callback_failed` 또는
`output_close_unconfirmed` 경고와 receipt를 보존한다. 응답이 끊겼으면
`case_get(include_artifacts=true)`에서 이미 게시된 결과를 확인한다.

## 요약 연결

`schema_get(name="rf-analysis")`의 `mode="offline-power"`와 `power_results`를 사용한다.
기존 `offline-raw/raw_results`와 섞지 않는다. `flipper-rf-analysis` Skill의 마지막
`case_record_step(step="summary")`에서 다음 행을1..128개 기록한다.

| `power_results[]` | 응답의 값 |
|---|---|
| `input_artifact_id` | `report.source.artifact_id` |
| `analysis_path` | `analysis.path` |
| `report_sha256` | `analysis.sha256` |
| `status` | `report.status` |
| `rows_accepted` | `report.inspection.statistics.rows_accepted` |
| `values_accepted` | `report.inspection.statistics.values_accepted` |

요약의 `input_completeness_verified`, `capture_verified`, `device_association_verified`,
`authorization_assessed`, `decoded`, `transmitted`는 모두 false다. 모두 complete면 success,
나머지 저장 상태가 섞이면 partial로 기록한다. 입력 오류로 보고서가 없으면 attempt만 남긴다.

## 합성 계획·runner의 개발 범위

내부 `rtl_power_plan.py`는 정수 여섯 값의 frozen `PowerSweepRequest`를 고정9개 인자로
만든다. index0..255, 주파수1..INT32_MAX, bin1..min(2800000,폭), integration/duration1..60초,
integration≤duration만 받는다. argv는 `-d index -f low:high:bin -i integration -e duration -`다.

`run_power_plan_fake`에는 `process_factory` 주입이 필수이며 실행물 탐색·기본 spawn·공개 MCP
연결은 없다. factory는 신뢰된 시험 이음매다. 임의 factory를 안전하게 가두는 sandbox가 아니다.
시험은 고정 Linux Python child만 사용하고 실제 rtl_power/receiver/RF/Windows는 실행하지 않는다.

runner는 stdout1MiB/stderr16KiB, caller deadline과 시작+60초 중 이른 처리 기한,
별도 최대5초 정리를 적용한다. child/group/reader/FD/reap을 확인한 뒤 같은 처리 기한으로
실제 parser를 한 번 부른다. parser의 시간 partial도 `rf_power_fake_timeout`으로 닫으며,
공개 오프라인 저장 worker의 별도 최종 등록5초를 runner에 적용하지 않는다.
정상 rc0·정리 확정 뒤 시간 이외의 CSV 검사 partial은 원래 상태로 보존한다. stderr의 문구만으로
취소를 판단하지 않으며, 원문은 결과에 넣지 않는다.

정리 미확인은 `rf_power_fake_cleanup_unknown`과 strong registry의 private owner로 남긴다.
같은 child에 대한 명시 bounded close만 재시도하며 재실행·자동 게시하지 않는다.
나머지 고정 오류는 `rf_power_fake_invalid/failed/timeout/output_limit/cancelled`다.
정상 결과는 `simulator_only=true`, `hardware_verified=false`, inspection과 두 byte 수뿐이다.
실제 장치 유일성·USB lease·RF 허가·수신·캘리브레이션의 증거로 승격하지 않는다.
