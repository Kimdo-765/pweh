# Windows OLS COM 스캔·장치 정보 조회

WSL에서 등록 sigrok Windows 번들로 **명시한 OLS 계측기 COM 하나**를 조회한다. `sigrok_scan`과 `sigrok_device_info`의 기본값은 `backend="linux"`다. Windows 경로는 `backend="windows"`, `driver="ols"`, 소유/허가가 기록된 `case_id`, `conn="COMn"`을 모두 요구한다. 정규 COM1–COM4096만 받으며 자동 포트 선택·다른 드라이버·USB 주소·네트워크·Windows 캡처는 지원하지 않는다.

## 호출과 고정 명령

```text
sigrok_scan(case_id="<케이스 ID>", driver="ols", conn="COM3", backend="windows")
sigrok_device_info(case_id="<케이스 ID>", driver="ols", conn="COM3", backend="windows")
```

예시 COM3은 사람이 확인한 계측기 포트로 바꾼다. 등록 번들 선택은 [정보 조회](windows-sigrok-info.md)와 동일하다. 명시 설치 오류나 Windows 경로 실패를 Linux·다른 번들로 대체하지 않는다. `hostenv.disable`의 `interop`·`windows_tools`를 따르며 사용 가능한 WSL interop이 필요하다. helper를 거치지 않고 검증한 sigrok-cli.exe 사본이 COM을 연다.

순수 `pweh.sigrok_com.ComCommand`는 `ols-serial-v1` profile 지문과 다음 두 tail만 만든다. 원시 argv·driver 옵션·프로필 파일은 입력받지 않는다.

```text
--driver=ols:conn=COM3 --dont-scan --scan
--driver=ols:conn=COM3 --dont-scan --show
```

정보용 version/list의 두 tail은 별도 계약에 그대로 남는다. COM owner는 요청당 고유 사본 하나에서 CLI 한 번만 실행한다.

## 장치 영향과 승인

libsigrok 0.5.2의 OLS scan은 지정 포트를 읽기/쓰기로 열어 reset 바이트 5회 뒤 ID·metadata를 질의한다. show도 탐색 후 같은 장치를 다시 연다. CLI의 `--dont-scan`은 명시 driver의 probe를 막지 않는다. 따라서 Linux와 Windows 모두 **OLS+명시 직렬 scan/show를 MODIFY**로 분류한다. 대상 콘솔 대신 계측기 포트를 고르는 것이 필요하며 포트 open의 DTR/RTS LOW를 보장하지 않는다.

출력 가능 장치·허용 목록 밖 드라이버·잘못된 argv의 기존 정책 거부를 먼저 적용한다. 허용된 조회는 기존 `modify_policy`를 따르고, `approval_required`이면 사람이 별도 터미널에서 `pweh approve <id>`로 승인한 뒤 같은 인자에 `approval_id`를 붙여 다시 호출한다. 에이전트는 승인을 대신 만들지 않는다. 새 safety 키나 승인 우회는 없다.

case·target/bridge 역할 표지·계측기 guard·route·필요한 reset scope·공용 lease를 게이트 앞에서 확인한다. 승인 지문은 고정 profile/번들/명령과 안정적인 route·scope를 포함한다. 실행 직전 경로·범위·guard·고정 명령을 다시 확인하며 바뀌면 실행하지 않는다. SUMP reset이나 USB hub metadata 조회만으로 전체 USB reset을 추정하지 않는다. 기존 route의 reset 배선이 확인된 경우에만 전체 장치 형제 lease를 요구한다.

## 실행 수명과 결과

Windows owner는 복사나 Windows 제어 실행 전에 포트 lease에 연결한다. 등록 payload 전체 사본·검색 환경은 [정보 조회의 사본 계약](windows-sigrok-info.md#사본과-종료-확인)을 재사용한다. 실행 전 사본 image의 Windows 프로세스 부재를 확인하며 이미 있거나 불명확한 프로세스를 새 실행의 소유자로 간주해 종료하지 않는다. source·copy 재검증 뒤 마지막 route 검사를 하고 실행한다.

종료에는 실제 Windows 프로세스 부재, POSIX wrapper 회수·그룹 종료, stdout/stderr reader와 제어 조회 종료, 사본 검증·삭제가 모두 필요하다. Windows 강제 종료는 전체 image 경로·정확한 tail·생성 시각이 일치하는 같은 native handle만 사용한다. POSIX 그룹이 비었거나 process state가 없다는 것만으로 완료 처리하지 않는다. 정리 미확인이면 owner·사본·lease를 보존하며 겹치는 후속 요청은 같은 owner를 유한한 시간 안에서 재확인한다.

공개 결과에는 검증한 필드만 투영한다. 장치는 최대 하나이며 driver는 `ols`여야 한다. 출력에 conn이 있으면 승인한 COM과 같아야 하고, OLS가 conn을 출력하지 않는 정상 형식도 받는다. 장치 이름·채널 같은 metadata는 계측기에서 온 정보이며 신원 증명을 대신하지 않는다. 원시 stdout 줄·stderr·명령줄·traceback·예외 문자열은 응답에 넣지 않는다. 알려진 장치 없음은 정상 정리를 확인한 뒤에만 처리하며 decoder 오류를 부분 성공으로 바꾸지 않는다.

전체 worker 예산은 120초, CLI 기본 제한은 scan 45초·show 60초다. `timeout_s`는 유한한 양수이면서 최대60초이고, 내부 검증45초·Windows 제어30초 상한도 전체 남은 예산과 함께 적용한다. 정리는 별도10초 예산이다. stdout 8MiB·stderr 128KiB 상한을 넘으면 오류로 정리한다. 이 계약은 Windows ACL·DLL 검색 전체 격리나 서버 강제 종료 후 자동 회수까지 보장하지 않는다.

## 검증 범위와 소스 근거

포트·정책·승인 결속·fresh 검사·프로세스 신원·부분 준비 실패·취소·정리 미확인·결과 투영은 합성 시험으로 검증한다. **실제 Windows COM/PnP 조회·OLS 장치 접근·드라이버 설치는 수행하지 않았다.** Windows 캡처와 실제 장비 호환성 검증은 후속이며, 이 구현을 실제 장치 시험 통과로 표시하지 않는다.

근거는 배포물이 보고한 동일 버전의 upstream 소스다. 이 대조가 배포 바이너리의 재현 빌드 동등성을 증명하지는 않는다.

- [libsigrok 0.5.2 OLS api.c](https://github.com/sigrokproject/libsigrok/blob/libsigrok-0.5.2/src/hardware/openbench-logic-sniffer/api.c): 명시 conn, read/write open, reset·ID·metadata, conn 출력 미제공.
- [OLS protocol.c](https://github.com/sigrokproject/libsigrok/blob/libsigrok-0.5.2/src/hardware/openbench-logic-sniffer/protocol.c): reset 5회.
- [sigrok-cli 0.7.2 device.c](https://github.com/sigrokproject/sigrok-cli/blob/sigrok-cli-0.7.2/device.c), [show.c](https://github.com/sigrokproject/sigrok-cli/blob/sigrok-cli-0.7.2/show.c): 명시 driver 탐색과 show의 재열기.
- [libsigrok serial.c](https://github.com/sigrokproject/libsigrok/blob/libsigrok-0.5.2/src/serial.c), [libserialport 0.1.1 windows.c](https://github.com/sigrokproject/libserialport/blob/libserialport-0.1.1/windows.c): 기본 DTR/RTS와 지정 USB COM의 metadata 조회. 포트 세부 조회가 USB controller/hub handle을 쓸 수 있으므로 “USB 접근 없음”이나 “한 번만 open”으로 설명하지 않는다.
