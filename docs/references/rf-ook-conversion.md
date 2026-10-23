# Flipper RAW의 로컬 OOK 변환

등록된 strict RAW의 제한된 duration 쌍을 로컬 OOK 파일로 변환하고 입력·출력 해시를 manifest에 결속한다.

## 입력과 변환 범위

소유·허가된 같은 케이스에 등록한 Flipper Sub-GHz RAW 파일을 선택한다.
`case_import_file`로 가져온 뒤 `case_get(include_artifacts=true)`의 등록 행에서 artifact ID를 확인한다.
호출은 `sdr_import_flipper_sub(case_id, artifact_id, max_seconds=5)`이다.
파일 경로·원문·출력명·주파수·sample rate·decoder 명령은 인자로 받지 않는다.

입력은 등록 ID와 경로가 각각 유일한 1바이트~1MiB의 일반 파일이어야 한다.
등록 size/SHA256과 한 번 연 FD의 실제 bytes를 대조하며 symlink·hardlink 및 보호 경로를 거부한다.
등록 producer 문자열이나 파일 선언을 실제 캡처·장치 연결의 증거로 사용하지 않는다.

기존 `flipper-subghz-raw-v1-strict` 검사 전체가 `complete`여야 변환한다.
부분 검사·손상·미지원 입력에서 읽을 수 있는 앞부분만 변환하지 않는다.
허용 preset은 `FuriHalSubGhzPresetOok270Async`와 `FuriHalSubGhzPresetOok650Async` 두 개다.
FSK·알 수 없는 preset·홀수 duration 수·0 또는 잘못된 부호 순서는 변환을 거부한다.
기존 `sdr_analyze` RAW 검사와 `sdr_peaks` CSV 검사의 범위·결과는 그대로 유지한다.

## 짝과 출력 문법

전체 검사를 통과한 **같은 bytes**를 두 번째로 순회한다.
양수 mark와 뒤따르는 음수 space의 절댓값을 순서대로 한 쌍으로 만든다.
여러 `RAW_Data` 행에 걸친 쌍도 이어 읽으며, 주석·다른 metadata의 숫자를 pulse로 해석하지 않는다.
각 수치는 1~2,147,483,647µs, duration 수는 짝수 2~2,400개, 쌍은 1~1,200개다.
기존 RAW 검사에서 허용할 수 있는 `-2147483648`도 이 변환에서는 거부한다.
수치와 순서는 유지하며 반올림·평활화·gap 추가·packet 분할을 하지 않는다.

생성 파일의 고정 문법은 다음과 같다. 아래 숫자는 문법 예제다.

```text
;pulse data
;version 1
;timescale 1us
100 200
;end
```

숫자 줄은 양수 10진수 두 개를 공백 하나로 나누며 모든 줄 끝은 LF다.
원 입력의 파일명·주석·시각·주파수·RSSI header는 생성 파일에 넣지 않는다.
파일은 실제 47~26,443바이트이며 내부 출력 한도는 64KiB다.
쌍 수·양수/음수 수·각 합계·전체 duration 합계가 첫 검사와 일치해야 완료한다.

## 파일 게시와 실제 receipt

성공하면 다음 두 파일을 같은 새 디렉터리에 쓴다. 번호는 유한한 `001`~`064` 중 예약한다.

- `analysis/rf-ook-NNN/converted.ook`: 순서대로 변환한 mark/space 쌍.
- `analysis/rf-ook-NNN/manifest.json`: 입력·변환 집계·생성 OOK의 크기와 SHA256.

디렉터리는 0700, 두 파일은 0444다. **manifest 하나만** artifact로 등록한다.
생성·검증·등록을 하나의 filesystem transaction이라고 하지 않는다.
등록 직전에 입력 색인과 입력 FD, 두 출력 FD의 SHA·이름·부모·파일 신원을 다시 대조한다.
등록 전 실패·취소는 확인한 자기 산출물만 정리하며 교체물이나 신원 미확인 항목은 임의 삭제하지 않는다.

반환은 `{ok, report, analysis, output, warnings}`다.
`analysis`의 `path,sha256,size,artifact_id`는 실제 등록된 manifest의 receipt다.
`output`의 `path,sha256,size`는 생성 OOK이며 `report.output`과 같다.
입력 SHA, manifest SHA, OOK SHA는 서로 다른 bytes의 지문이므로 바꾸어 사용하지 않는다.
등록 commit 뒤 늦은 취소·audit 실패·close 실패는 이미 게시한 두 파일과 실제 receipt를 보존한다.
이때 warning은 해당하는 `post_commit_callback_failed`, `output_close_unconfirmed`만 반환한다.
새 import/device-read 출처 기록이나 사람 증명 요청을 추가하지 않는다.

## rf-analysis 요약 연결

`flipper-rf-analysis`의 summary는 새 `mode="offline-ook"` 분기를 사용한다.
`conversion_results`는 1~128행이며 각 행은 다음 **6필드**를 실제 성공 반환에서 구성한다.

```python
row = {
    "input_artifact_id": result["report"]["source"]["artifact_id"],
    "analysis_path": result["analysis"]["path"],
    "report_sha256": result["analysis"]["sha256"],
    "output_path": result["output"]["path"],
    "output_sha256": result["output"]["sha256"],
    "pair_count": result["report"]["conversion"]["pair_count"],
}
```

`schema="pweh.rf-analysis/v1"`, `mode`, `conversion_results` 및 아래 false8을 함께 기록한다.
`case_record_step(skill="flipper-rf-analysis", step="summary", status="success", data=...)`로 저장한다.
analysis와 output 경로는 반드시 같은 `rf-ook-NNN` 디렉터리의 manifest/converted 파일 쌍이다.
기존 `offline-raw`·`offline-power`의 결과 배열을 같은 summary에 섞지 않는다.
요약은 receipt 참조이며 등록 사실이나 출처 검증을 대신하지 않는다.

## 한도와 확인하지 않는 사실

처리는 최대 5초이고, 처리 완료 뒤 등록 잠금·최종 무결성 검증에 별도 5초를 한 번만 사용한다.
파일 읽기·쓰기·재해시는 조각당 최대 64KiB, manifest는 canonical ASCII JSON+LF 최대 64KiB다.
두 번째 탐색은 줄당 8,192바이트·총 8,192줄·token당 11바이트·줄당 512token으로 제한한다.
시간 초과나 변환 거부는 partial 변환 파일을 성공 결과로 게시하지 않는다.

`complete`는 이 제한된 변환을 마쳤다는 뜻이다. 다음 8개 값은 계속 false다:
`input_completeness_verified`, `capture_verified`, `device_association_verified`, `authorization_assessed`,
`decoded`, `transmitted`, `packet_boundaries_verified`, `decoder_compatibility_verified`.
`declared_frequency_hz`는 입력의 uint32 선언값(0 포함)이며 측정값·수신 설정·전파 허가가 아니다.
공개 응답·manifest·요약에는 원 pulse 배열을 넣지 않지만, 집계 수치가 익명화를 보장하지는 않는다.

## 고정 문법 근거

rtl_433 25.12 commit `ea7d504877df751a202432d47dbb0c425ab0a93c`의 공식 소스를 근거로 한다.
[pulse_data.c loader/writer](https://github.com/merbanan/rtl_433/blob/ea7d504877df751a202432d47dbb0c425ab0a93c/src/pulse_data.c#L122-L212)에서 두 정수·header·끝 표지 문법을 확인했다.
[PD_MAX_PULSES](https://github.com/merbanan/rtl_433/blob/ea7d504877df751a202432d47dbb0c425ab0a93c/include/pulse_data.h#L20-L37)는 1,200이다.
loader는 caller sample rate로 수치를 환산하며 timescale header 해석이 미완성이다.
또한 최대 쌍 수에서는 끝 표지를 읽기 전에 반환할 수 있다. 이 사실은 packet 경계 검증이 아니다.
PWEH의 문법 변환은 실제 rtl_433 실행·decoder 수용·프로토콜 해독·RF 수신·송신을 검증하지 않는다.
