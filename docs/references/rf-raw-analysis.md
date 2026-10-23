# 등록 RAW 파일의 오프라인 분석

`pweh-sdr`의 `sdr_analyze`는 케이스에 등록된 Flipper Sub-GHz RAW 파일을 검사하고 입력 SHA256에 연결한 보고서를 저장한다. [strict RAW profile](flipper-raw-profile.md)의 기존 순수 parser를 사용한다. 파일 선언과 집계 통계만 다루며 실제 장비·대상·캡처·RF 허가를 확인하지 않는다.

## 호출

```json
{
  "case_id": "raw-example",
  "artifact_id": "A-0001",
  "profile": "flipper-subghz-raw-v1-strict",
  "max_seconds": 5
}
```

위 ID는 설명용이다. 소유·허가된 실제 케이스에서 `case_get(include_artifacts=true)`로 입력을 고르고, 아직 등록하지 않은 사용자 지정 일반 파일은 `case_import_file(kind="other")`로 가져와 응답의 `artifact.id`를 쓴다. 기존 허가를 반복해서 확인하거나 오프라인 분석을 위해 RF 장비를 연결할 필요는 없다.

`profile`은 필수이고 위 값 하나만 지원한다. `max_seconds`는 기본 5, bool을 제외한 유한 수 `0 < value <= 5`다. `artifact_id`는 `A-` 뒤 4..8자리 숫자다. SDK는 문자열·숫자를 암묵적으로 바꾸지 않으며 원문 값을 포함하지 않는 오류를 반환한다.

## 입력과 출처

- 같은 케이스의 유일한 아티팩트 ID로 일반 파일 하나를 선택한다. 등록된 크기는 0..1 MiB, SHA256은 필수다. 빈 파일도 parser의 `malformed` 결과를 저장할 수 있다.
- 직접 경로·URL·디렉터리·EV·offset·decoder를 받지 않는다. `forensics/`·`emu/` 파일이나 그 별칭, 다른 케이스 파일, 링크·하드링크는 이 입구로 분석하지 않는다. 보호 파일을 일반 폴더로 복사해 우회하는 흐름도 제공하지 않는다.
- 입력 파일을 한 번 연 FD에서 최대 64 KiB씩 읽고 해시한다. 원자 등록 직전 같은 FD의 전체 SHA와 부모/이름/파일 신원 및 현재 아티팩트 등록 정보를 다시 대조한다.
- 이 검증은 현재 등록 bytes와 분석 입력의 일치다. 실제 Flipper 파일이라는 출처, 원래 캡처의 완전성, 장치 연결 또는 적법한 수신을 증명하지 않는다. 새 RF 증명이나 forensic custody를 만들지 않는다.

## 반환과 파일

| 필드 | 내용 |
|---|---|
| `ok` | 보고서 등록 성공이면 true |
| `report.schema` | `pweh.rf-raw-analysis/v1` |
| `report.status` | 아래 검사 상태 |
| `report.source` | `kind="case-artifact"`, 입력 `artifact_id`, `size`, `sha256` |
| `report.params` | 명시한 `profile`, `max_seconds` |
| `report.inspection` | 기존 `pweh.rf-raw-inspection/v1` 결과 전체 |
| `analysis` | 출력의 `path`, `sha256`, `size`, `artifact_id` |
| `warnings` | 고정 경고 목록 |

`report.status == report.inspection.status`, `report.source.size == report.inspection.coverage.input_bytes`다. `report.source.sha256`은 입력, `analysis.sha256`은 저장한 분석 JSON의 해시로 서로 다르다. 입력 파일명·경로는 source에 복사하지 않는다.

분석 JSON은 최대 128 KiB이며 `analysis/rf-raw-NNN.json`에 0444로 저장한다. 아티팩트는 `kind="other"`, `producer="pweh-sdr"`, `extra.type="rf-raw-analysis"`다. 한 번 호출하면 한 보고서가 등록되며 별도 job·세션 도구는 없다.

| 검사 상태 | 의미 |
|---|---|
| `complete` | 지원 문법을 EOF까지 검사하고 최소 한 pulse를 수용했다. |
| `partial` | 자원·시간 상한으로 검사를 끝내지 못했다. |
| `malformed` | 지원 프로필의 구문·순서·숫자·부호 규칙을 위반했다. |
| `unsupported` | 지원 밖 형식·버전·preset·protocol·필드/인코딩이다. |

네 상태 모두 저장 가능한 검사 결과다. `partial/malformed/unsupported`의 통계는 수용한 줄의 prefix만 나타낸다. 한 RAW 줄의 마지막 token에서 실패해도 그 줄 전체를 집계에서 뺀다. `accepted_prefix_bytes + remaining_bytes == input_bytes`이며 `remaining_range`는 아직 수용하지 않은 suffix다. 이미 일부를 검사했을 수 있다. EOF의 필수 필드 누락처럼 남은 bytes가 0이어도 complete가 아닐 수 있다.

`declared_frequency_hz`·고정 `declared_preset`·pulse 개수·양/음별 절댓값 min/max/sum·선언 duration을 반환한다. pulse 배열·주석·자유 문자열·키/ID·오류 발췌는 반환하지 않는다. 작은 표본에서는 집계로 개별 값을 유추할 수 있어 익명화라고 부르지 않는다. TE·packet·프로토콜·고정코드/롤링코드·재생 위험 판정은 이 결과에 없다.

## 시간·취소·오류

worker 시작의 하나의 작업 deadline을 케이스/입력 선택·읽기·검사가 공유한다. 최대 5초이며, 입력 전체를 얻기 전에 만료되면 보고서 없이 오류로 끝난다. parser가 `partial/time_limit`을 반환하면 그 결과를 저장할 수 있다.

결과 생성 뒤 별도의 5초 deadline을 한 번 정하고 출력 검증·입력 최종 재해시·잠금·등록이 공유한다. 협력 취소와 파일 I/O checkpoint를 사용하며 커널 호출을 강제 중단하는 watchdog은 아니다.

| 오류 코드 | 의미 |
|---|---|
| `rf_raw_input_invalid` | ID·등록 정보·입력 경로/종류가 계약에 맞지 않음 |
| `rf_raw_input_limit` | 입력 크기 한도 초과 |
| `rf_raw_input_changed` | 입력 bytes·신원·등록 정보가 변경됨 |
| `time_limit` / `cancelled` | 게시 전 시간 만료 / 취소 |
| `rf_raw_failed` | 검사·저장의 다른 고정 실패 |
| `rf_raw_cleanup_incomplete` | 이번 출력의 안전한 정리를 확인하지 못함 |

소유·허가 오류는 기존 코드 의미를 유지한다. 실패 응답·로그에 입력 경로나 원문 예외를 복사하지 않는다. 크기가 1 MiB를 넘는 파일은 일부를 잘라 검사하지 않고 입구에서 거부한다.

commit 전 실패는 이번 출력의 신원이 맞을 때만 정리한다. Case metadata에 원자 등록된 뒤에는 취소나 audit 오류가 와도 파일을 보존한다. `post_commit_callback_failed`는 게시 뒤 후처리 실패, `output_close_unconfirmed`는 게시 뒤 FD 정리 미확인 경고이며 등록 결과는 남아 있다. 호출 자체가 취소되어 응답이 없으면 `case_get(include_artifacts=true)`에서 이미 등록된 결과를 확인할 수 있다.

## 요약과 보고서 연결

`schema_get(name="rf-analysis")`의 현재 요약은 `schema="pweh.rf-analysis/v1"`, `mode="offline-raw"`, `raw_results` 1..128개다. `case_record_step`의 Skill 이름은 `flipper-rf-analysis`, 마지막 step은 `summary`다.

| `raw_results[]` | 분석 응답에서 가져올 값 |
|---|---|
| `input_artifact_id` | `report.source.artifact_id` |
| `analysis_path` | `analysis.path` |
| `report_sha256` | `analysis.sha256` |
| `status` | `report.status` |
| `pulse_count` | `report.inspection.statistics.pulse_count` |

여섯 요약 값 `input_completeness_verified`, `capture_verified`, `device_association_verified`, `authorization_assessed`, `decoded`, `transmitted`는 모두 false다. 케이스가 소유·허가를 기록했다는 사실을 RAW 분석이 RF 허가를 판정했다는 뜻으로 바꾸지 않는다.

모두 complete면 단계 success, 그 밖의 검사 상태가 있으면 단계 partial로 기록하고 원래 status를 보존한다. 입구 오류로 보고서가 없으면 attempt만 기록한다. 마지막 `report_generate`가 이 선택 단계와 등록 아티팩트를 모은다. 작업 절차는 [flipper-rf-analysis Skill](../../skills/flipper-rf-analysis/SKILL.md)에 있다.
