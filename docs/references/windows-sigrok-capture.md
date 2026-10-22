# Windows OLS 유한 캡처

`sigrok_capture(backend="windows")`는 등록 sigrok Windows 번들과 명시한 OLS 계측기 COM으로 유한한 로직 신호를 캡처한다. 기본 `backend="linux"`는 유지한다. 소유/허가 케이스, `driver="ols"`, 정규 COM1–COM4096, `samples`, 앞쪽 연속 숫자 채널을 모두 명시해야 한다. Windows USB 자동 탐지·다른 드라이버·시간 기반 캡처·트리거·디코드·export는 지원하지 않는다.

## 입력과 장치 영향

```text
sigrok_capture(case_id="<케이스 ID>", driver="ols", conn="COM3",
               backend="windows", samplerate="1m", samples=4096,
               channels=["0=RX", "1=TX"], background=true)
```

COM3과 채널은 사람이 확인한 계측기 포트·배선으로 바꾼다. 대상 콘솔의 COM을 넣지 않는다. 설치 선택·interop 조건은 [Windows 정보 조회](windows-sigrok-info.md)를, 포트 역할·guard·lease·승인 결속은 [OLS COM 조회](windows-sigrok-com.md)를 따른다. 실패한 Windows 경로를 다른 포트·번들·Linux로 자동 대체하지 않는다.

| 인자 | 첫 고정 프로필의 범위 |
|---|---|
| `samplerate` | 10–100,000,000 Hz. DEMUX 구간 제외 |
| `samples` | 4–8,388,608의 4배수. 최소4는 upstream 조건, 4배수는 PWEH 제한 |
| `channels` | 1–32개, 정확히 0부터 연속. 숫자 범위와 기존 ASCII 이름 변경 지원. `D0` 같은 별칭·비연속·중복은 거부 |
| `duration_ms`, `triggers`, `capture_ratio` | 사용하지 않음. 값을 주면 거부 |
| `timeout_s` | 기본60초, 최대300초의 유한한 양수 |
| `background` | 기존 job 선택. 같은 worker가 동기 호출과 job을 처리 |

OLS 캡처는 내부 탐색에서 reset·ID·metadata를 보내고 샘플링 설정·RUN 명령을 전송한다. Linux/Windows의 **OLS+명시 직렬 캡처는 MODIFY**다. 입력 신호를 관찰하는 장비여도 포트 열기의 DTR/RTS LOW를 보장하지 않는다. 출력 가능 장치·허용 목록 밖 드라이버의 정책 거부를 먼저 적용한 뒤 기존 `modify_policy`를 따른다. `approval_required`이면 사람이 별도 터미널에서 승인하고 같은 인자에 `approval_id`를 붙인다. 에이전트가 승인 명령을 대신 실행하지 않는다.

`pweh.sigrok_capture.CaptureCommand`의 `ols-capture-v1`은 다음 순서의 tail만 만든다. 원시 argv·프로필 파일·serialcomm·추가 config를 입력받지 않는다. 정보 조회와 scan/show의 기존 launch 타입은 캡처를 허용하지 않는다.

```text
--driver=ols:conn=COM3 --dont-scan --config=samplerate=1000000
--channels=0=RX,1=TX --samples=4096 --output-format=srzip
--output-file=<owner가 만든 Windows 절대경로의 capture.sr>
```

## 실행·출력·등록 수명

owner는 복사나 Windows 제어 실행 전에 lease에 연결한다. 요청당 등록 payload의 전체 고유 사본 하나와 별도 출력 디렉터리를 만들고 CLI를 한 번 실행한다. srzip writer가 출력을 다시 생성하므로 최종 파일을 미리 만들지 않는다. 실행 직전 출력 디렉터리가 비었는지, 같은 image의 Windows 프로세스가 없는지, source·copy·route·역할·범위·guard·프로필이 유효한지 재확인한다. 이미 존재하거나 불명확한 Windows 프로세스를 새 요청의 소유자로 간주해 종료하지 않는다.

실제 Windows 프로세스 부재와 POSIX wrapper·그룹·reader·제어 조회 종료가 모두 확인된 뒤 출력을 연다. 부모 디렉터리와 파일 이름·fd 신원을 묶고 regular file·링크 수1·크기·mtime/ctime을 확인한다. 같은 fd로 ZIP·CRC·metadata 검사, 해시와 케이스 복사를 수행한다. 파일 이름을 다시 열어 검증을 우회하지 않는다.

케이스 `signals/`의 새 파일을 배타적으로 만들고 복사·fsync·읽기 전용화·신원 확인 후 아티팩트를 등록한다. metadata lock 안에서도 경로·크기·종류·SHA-256을 고정한 fd 사실과 대조하며 기존 항목을 덮어쓰지 않는다. 등록 commit을 owner와 job에 먼저 알린 뒤 감사 기록을 남긴다. 등록 뒤 감사 오류·늦은 취소·정리 실패가 발생해도 등록 파일을 rollback 삭제하지 않는다.

알 수 없는 출력 항목, 교체된 신원, 미검사·미게시 출력은 `output_pending`으로 보존한다. 명백한 빈 파일·잘못된 ZIP, 또는 검증을 끝낸 CLI 실패의 비게시 출력만 제한적으로 정리한다. owner 재정리 호출은 미게시 출력을 자동 게시하거나 삭제하지 않는다. Windows·출력·사본 정리까지 모두 확인해야 lease를 해제하며, 정리 미확인이면 owner·출력·lease와 이미 등록한 아티팩트 참조를 유지한다.

## 검증 상한과 결과 해석

ZIP32의 중앙 디렉터리를 객체 생성 전에 제한한다. archive64MiB, 해제 합계64MiB, 로직32MiB, 항목4096개, 중앙 디렉터리1MiB, metadata64KiB, version64B 상한을 적용한다. ZIP64·알 수 없는 항목·다중 장치·analog·중복 metadata·승인한 채널과 다른 이름/개수·unitsize4 불일치를 허용하지 않는다. 모든 데이터의 크기와 CRC를 검사한다.

활동 통계는 최대8,388,608 채널×샘플의 앞부분만 계산한다. 한도에 닿으면 `activity_complete=false`로 표시하지만 나머지 데이터의 CRC 검증은 계속한다. 반환 검사 요약에도16KiB 상한을 둔다.

OLS의 reported rate는 `100000000 // (100000000 // requested_hz)`와 대조한다. 요청3MHz는 파일에3,030,303Hz로 기록될 수 있으며 `rate_quantized`로 알린다. 파일에 기록된 rate는 독립적인 클럭 측정값이 아니다. 실제 샘플 수가 요청보다 적으면 종료 코드0이어도 `partial=true`·`sample_shortfall`이며, 요청보다 많으면 게시하지 않는다.

취소·시간 초과 뒤에도 닫힌 ZIP 전체가 검증되고 샘플이 있으면 부분 아티팩트로 보존할 수 있다. 검증 전 출력을 정상 캡처로 반환하지 않는다. 정상 등록 뒤의 sample_shortfall은 job이 succeeded여도 결과는 partial이다. 취소된 job의 부분 결과를 정상 완료로 바꾸지 않는다. 원시 stderr·Windows 경로·명령줄·traceback·ZIP metadata 원문은 공개 오류에 넣지 않는다.

worker 전체는420초, 실행 후 검증·게시 deadline은 한 번 정한 `min(worker 종료시각, CLI 종료시각+60초)`다. 번들 검증45초·Windows 제어30초 상한도 남은 전체 예산과 함께 적용한다. 정리는 별도10초다. 각 단계에서 예산을 새로 시작하지 않으며 시간 안에 확인할 수 없는 출력은 보존한다.

## 검증 범위와 근거

고정 명령·같은 fd 검사·승인·job·취소·등록·정리 경로는 합성 파일과 가짜 프로세스로 검증한다. 실제 Windows COM/PnP 조회·장치 캡처·전압·배선·USB 재열거 검증은 수행하지 않았다. 등록 번들의 알려진 decoder/DLL 제약도 그대로 유지한다. 실제 장비 호환성 검증이 남아 있다.

- [libsigrok 0.5.2 OLS api.c](https://github.com/sigrokproject/libsigrok/blob/libsigrok-0.5.2/src/hardware/openbench-logic-sniffer/api.c): rate·samples 범위, 버퍼 제한, divider·capture size·RUN 설정.
- [OLS protocol.c](https://github.com/sigrokproject/libsigrok/blob/libsigrok-0.5.2/src/hardware/openbench-logic-sniffer/protocol.c), [protocol.h](https://github.com/sigrokproject/libsigrok/blob/libsigrok-0.5.2/src/hardware/openbench-logic-sniffer/protocol.h): 100MHz 기준 rate 계산, no-trigger unitsize4와 수신 샘플 수.
- [srzip.c](https://github.com/sigrokproject/libsigrok/blob/libsigrok-0.5.2/src/output/srzip.c), [strutil.c](https://github.com/sigrokproject/libsigrok/blob/libsigrok-0.5.2/src/strutil.c): 출력 교체, metadata와 정수 기반 rate 문자열. 동일 버전 소스 대조이며 배포 바이너리의 재현 빌드 동등성을 증명하지 않는다.
