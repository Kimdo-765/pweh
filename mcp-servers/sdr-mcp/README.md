# pweh-sdr

케이스에 등록된 Flipper Sub-GHz RAW 또는 rtl_power CSV 파일 하나를 오프라인 검사하는 MCP 서버다. 공개 도구는 RAW의 `sdr_analyze`와 전력 CSV의 `sdr_peaks`이며, 파일 선언과 집계 통계를 분석 보고서로 저장한다. 소유 또는 서면 허가가 기록된 케이스에서 사용한다.

등록 이름은 `pweh-sdr`, 실행 명령은 `pweh-sdr-mcp`(stdio)다. 프로젝트의 Python 패키지 설치에 포함되며 RTL-SDR·Flipper·외부 decoder 실행 파일이 필요하지 않다.

## 사용

```text
case_import_file(case_id, source_path=<사용자가 지정한 일반 RAW 파일>, kind="other")
sdr_analyze(case_id, artifact_id=<반환 artifact.id>,
            profile="flipper-subghz-raw-v1-strict", max_seconds=5)
case_record_step(skill="flipper-rf-analysis", step="summary", ...)
```

| 인자 | 계약 |
|---|---|
| `case_id` | 소유·허가된 케이스 ID |
| `artifact_id` | 같은 케이스의 `A-` + 4..8자리 숫자 ID |
| `profile` | 필수, `flipper-subghz-raw-v1-strict`만 지원 |
| `max_seconds` | 기본 5, 유한 수 `0 < value <= 5`; bool·숫자 문자열 거부 |

입력은 SHA256·크기가 등록된 일반 파일 하나이며 최대 1 MiB다. 경로·URL·EV·decoder 인자는 받지 않는다. `forensics/`·`emu/`, 링크·하드링크, 등록 정보와 다른 파일은 거부한다. 실제 RF 장치·포트·프로세스는 열지 않는다.

전력 CSV는 같은 등록 파일 ID를 `sdr_peaks(case_id, artifact_id, max_seconds=5)`에 넘긴다.
profile 인자는 없으며 `rtl-power-blog-v1.4.0-csv`로 고정한다. ASCII CSV의 날짜·시각 문법,
정수 선언·소수 2자리 전력·정확한 `-inf`를 검사하고 완전히 수용한 행의 값만 집계한다.
유한 값의 상위 32개를 보고된 열 기준으로 반환한다. FFT bin 수·주파수 중심·실제 보정 전력은 확인하지 않는다.

## 결과와 저장

성공 봉투는 `ok`, `report`, `analysis`, `warnings`다. `report`는 `rf-raw-analysis` 또는 `rf-power-analysis` 스키마의 source/params/inspection을 담고, `analysis`는 생성 경로·SHA256·크기·등록 ID를 담는다.

- `complete/partial/malformed/unsupported` 모두 정상 검사 결과이며 RAW는 `analysis/rf-raw-NNN.json`(최대 128 KiB), 전력 CSV는 `analysis/rf-power-NNN.json`(최대 64 KiB)에 저장한다. `complete`는 제한 문법의 EOF 확인이다.
- 원시 pulse·주석·키·ID·입력 경로는 반환하지 않는다. 선언 주파수·preset과 통계는 출력되며 익명화로 해석하지 않는다.
- 작업 예산은 최대 5초, 결과 생성 후 최종 저장 예산은 별도의 고정 5초다. 한 worker가 입력·부모·출력 FD를 소유하고 최종 입력 SHA/등록 정보와 출력 신원을 다시 대조한다.
- 출력은 0444 파일로 등록한다. commit 전 실패는 자신이 만든 신원이 같은 출력만 정리하고, commit 뒤 취소·후처리 오류는 등록 결과를 보존한다. `post_commit_callback_failed` 경고가 있으면 반환된 artifact를 확인한다.

전력 CSV의 문법·오류·요약은 [rf-power-analysis.md](../../docs/references/rf-power-analysis.md), RAW 공개 사용법·오류·요약 매핑은 [rf-raw-analysis.md](../../docs/references/rf-raw-analysis.md), parser 문법·한도는 [flipper-raw-profile.md](../../docs/references/flipper-raw-profile.md), 운영 절차는 [flipper-rf-analysis Skill](../../skills/flipper-rf-analysis/SKILL.md)에 있다.

## 검증 범위

합성 등록 파일로 입력·출력 교체, 같은 FD 해시, 취소·시간·commit 수명과 실제 MCP의 strict 인자/요약 연결을 검사한다. 순수 parser는 `tests/core/test_rf_formats.py`, 서버는 `tests/servers/test_sdr_raw_analysis.py`·`test_sdr_raw_mcp.py`, schema는 `tests/core/test_rf_raw_analysis_schema.py`에서 검증한다. 실제 RF 수신·해독·송신·재생 검증은 포함하지 않는다.

전력 CSV는 `test_rf_power.py`·`test_rf_power_analysis_schema.py`·`test_rf_power_summary.py`와
`test_sdr_power_analysis.py`·`test_sdr_power_mcp.py`로 검증한다. 내부 `rtl_power_plan`은
필수 합성 process factory로만 고정 스윕 인자와 종료 수명을 시험하며 MCP에 연결하지 않는다.
실제 실행물 탐색·설치·장치 수신을 수행하는 경로가 아니다.
