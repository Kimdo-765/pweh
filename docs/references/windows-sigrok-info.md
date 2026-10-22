# Windows sigrok 버전·지원 목록 조회

WSL에서 등록된 sigrok Windows 번들의 버전과 지원 목록을 확인한다. `sigrok_version`과 `sigrok_list`에 `backend="windows"`를 명시하면 사용한다. 기본 `backend="linux"`의 실행·캐시는 그대로이며, Windows 장치 스캔·COM·USB 캡처·디코딩은 이 경로에 포함되지 않는다.

## 호출과 설치 선택

[로컬 번들 설치](windows-bundles.md)로 `sigrok-cli-0.7.2-win64-selected` release를 준비한다. 선택 순서는 `tools.sigrok_win_bundle` → `PWEH_SIGROK_WIN_BUNDLE` → 관리 기본 release다. 값은 WSL/Linux release root의 절대 경로이며 명시 경로가 잘못되면 다른 설치로 대체하지 않는다. WSL interop이 사용 가능해야 하며 기존 `hostenv.disable`의 `interop`·`windows_tools` 설정을 따른다.

```text
sigrok_version(backend="windows")
sigrok_list(kind="drivers", query="fx2", backend="windows")
```

버전 조회는 고정 `--version` 뒤 `--list-supported`를 실행하고, 목록 조회는 `--list-supported`만 실행한다. `kind`·`query`는 출력의 필터이며 명령 인자에 들어가지 않는다. 두 정보 도구에는 케이스나 포트가 필요하지 않다. 다른 sigrok 도구는 기존 Linux 경로를 사용한다.

## 결과와 알려진 디코더 오류

Windows 응답에는 `backend`, `status`, 등록 `bundle` 정보가 추가된다. `path`는 검증한 원본 설치본의 실행파일이며, 실행 후 지운 임시 사본을 가리키지 않는다. Windows 정보 결과는 캐시하지 않는다.

| 관찰 | 버전 조회 | 목록 조회 |
|---|---|---|
| 두 실행과 목록 파싱이 정상 | `status="ok"`, 버전과 `counts` | `status="ok"`, 선택 목록과 개수 |
| 버전은 정상, 목록은 종료 코드 0·해석 가능한 출력이나 디코더 로드 오류만 발생 | `status="partial"`, `counts=null`, `list_complete=false`, 고정 경고·오류 코드 | 모든 `kind`에서 오류. 부분 목록·개수는 반환하지 않음 |
| 정리 미확인·취소·시간 초과·출력 상한·비0 종료·다른 치명적 오류·잘못된 출력 | 오류 | 오류 |

등록 번들의 `signature` 디코더에는 동봉 Python 3.4.4가 해석하지 못하는 숫자 리터럴 구분자가 있다. 최초 무장치 시험에서 이 오류를 확인했으므로 종료 코드 0이나 목록 개수만으로 전체 디코더가 정상이라고 표시하지 않는다. 이번 실행에서 관찰한 오류와 번들의 `known_limitations`는 구분한다. 원시 stderr·traceback·Windows 명령줄은 공개 오류에 넣지 않는다.

공식 checksum·서명을 확보하지 못했으므로 등록 SHA-256은 최초 취득본 지문이다. 외부 `MSVCR100.dll`, ZIP 내부 DLL 검색과 의존성 라이선스 검토의 한계는 [취득 기록](sigrok-cli.md#14-windows-고정-취득본의-무장치-확인-2026-10-22)을 따른다. 드라이버의 `capture_allowed` 표시는 기존 캡처 정책이며 Windows 캡처 지원을 뜻하지 않는다.

## 사본과 종료 확인

정보 요청마다 등록 payload 전체 290파일·34,159,405바이트를 고유 run 디렉터리에 복사한다. 원본 열린 파일의 신원·크기·해시와 사본의 정확한 파일 집합을 대조한다. 원본 설치본은 수정하지 않는다. 실행파일·데이터·디렉터리에 읽기 전용 모드를 적용하고 HOME·XDG·APPDATA·Python·디코더·펌웨어 검색 경로는 전용 사본과 고정 환경 트리로 지정한다. Windows가 요청하는 빈 `Microsoft/Windows/Caches` 디렉터리 3개는 실행 전에 생성·기록한다. Windows로 변환한 환경값은 WSLENV `/w`로 한 번만 전달한다.

한 요청의 사본에서는 version → list 또는 list 한 번만 허용한다. 실행마다 원본·사본을 재검증하고, 직전 실행의 Windows 프로세스 부재·POSIX wrapper 회수·출력 스트림 정리가 확인된 뒤에만 다음 실행을 시작한다. 실행 후에도 전체 사본과 고정 환경 트리의 정확한 항목 집합을 확인한다. 미등록 파일·pycache·내용 변경·신원 교체를 발견하면 오류로 보존하며 임의로 지우지 않는다.

Windows 프로세스는 고유 사본의 전체 image 경로, 정확한 인자와 생성 시각으로 식별한다. 강제 종료는 같은 native handle의 신원을 재확인한 뒤 수행하며 최종 부재까지 확인한다. wrapper 종료만으로 Windows 종료를 대신하지 않는다. 제어 조회의 시간 초과나 불완전한 출력도 성공한 빈 목록으로 취급하지 않는다.

호출 취소 뒤에도 실제 worker가 정리를 소유한다. 정리가 확인되지 않으면 owner와 사본을 보존하고 다음 정보 요청의 새 복사·실행을 막는다. 다음 요청은 기존 owner의 정리를 유한한 시간 안에서 재확인한다. 삭제는 자신이 생성한 동일 inode만 대상으로 하며 교체되거나 추가된 파일은 보존한다.

버전 요청의 전체 예산은 90초, 목록 요청은 60초이며 각 내부 단계도 남은 예산과 모듈 상한을 함께 따른다. 자식 stdout은 8MiB, stderr는 128KiB로 제한한다. 정리에는 별도 유한 예산을 적용한다. 이 계약은 Windows ACL·부모 환경·DLL 검색 전체의 격리나 서버 강제 종료 뒤 자동 회수를 보장하지 않는다. 정적 doctor는 계속 파일만 검사하며 이 도구를 실행하지 않는다.

## 무장치 수용 결과

2026-10-23 등록 설치본과 격리 설정으로 공개 MCP의 Windows version → drivers 목록 조회를 확인했다. version은 CLI 0.7.2와 `status="partial"`, `counts=null`, `list_complete=false`를 반환했다. 이어진 목록 요청은 필터와 무관하게 `sigrok_decoder_exception`으로 끝났고 불완전한 목록을 반환하지 않았다. 두 호출 모두 실제 Windows 프로세스 부재, wrapper 종료, 실행 후 사본 검증과 삭제, owner 해제를 확인했다. 원본 설치본은 유지했으며 추가 다운로드·실제 USB/COM 접근·드라이버 변경은 없었다.

첫 시험에서는 Windows가 전용 환경에 빈 `Microsoft/Windows/Caches` 디렉터리를 만들어 정확한 항목 검사에 걸렸다. 구현은 오류를 반환하고 그 사본을 보존했다. 등록 payload 해시 일치와 Windows 프로세스 부재를 별도로 확인한 뒤, 이 세 빈 디렉터리만 준비 단계에 포함했다. 이후 시험은 통과했다. 캐시 파일이나 다른 추가 항목을 자동 삭제하도록 완화하지 않았으며, 예상 밖 파일·디렉터리를 보존하는 합성 회귀도 통과했다.
