# Windows 도구 번들의 로컬 설치·정적 점검

## 범위

이미 추출한 고정 OpenOCD/sigrok Windows payload를 등록된 파일 목록·크기·SHA-256과 대조하고 관리 디렉터리에 복사한다. 새 다운로드나 Windows 설치 프로그램 실행 없이 로컬 설치 상태를 확인할 수 있다. 이 설치는 Windows 실행·USB/COM 사용·드라이버 설치를 수행하지 않는다. 별도의 [OpenOCD 무장치 진단 세션](windows-openocd-dummy.md)·[Tigard 고정 세션](windows-openocd-tigard.md)과 [sigrok 버전·목록 조회](windows-sigrok-info.md), [OLS COM 조회](windows-sigrok-com.md)·[유한 캡처](windows-sigrok-capture.md)가 검증된 설치본을 소비한다.

등록된 SHA는 저장소의 manifest/index에서 가져온다. 입력 디렉터리의 현재 해시로 신뢰 기준을 새로 만들거나, 명시한 경로가 잘못됐을 때 시스템 설치로 대체하지 않는다. 검증 성공은 그 시점의 파일 집합 일치이며 서명·실행 가능·장치 지원의 증거가 아니다.

## 등록 입력의 출처

| 도구 | 등록 버전 | 취득 지문 근거 | 알려진 한계 |
|---|---|---|---|
| OpenOCD | xPack 0.12.0-7 win32-x64 | ZIP SHA-256을 공급자의 package metadata v0.12.0-7.1과 대조 | 정적 tree 일치만으로 Windows 실행 환경·USB driver claim을 검증하지 않음 |
| sigrok | sigrok-cli 0.7.2 win64 선택 payload | 공식 checksum·서명 미확보, 최초 취득본 SHA-256 | signature 디코더의 Python3.4 구문 오류, 외부 MSVCR100.dll, ZIP 내부 DLL 검색·의존성 라이선스 검토 한계 |

등록 release id는 `xpack-0.12.0-7-win32-x64`(1,132파일·7,965,084바이트)와 `sigrok-cli-0.7.2-win64-selected`(290파일·34,159,405바이트)다.

공개 manifest에는 배포물 URL·지문 근거와 payload-relative 파일명/크기/SHA만 기록한다. 원시 취득 로그·실제 호스트 경로·프로세스 ID는 포함하지 않는다. OpenOCD archive의 최상위 디렉터리 하나를 payload root로 사용한다. sigrok은 D7에서 정한 선택 payload만 받으며 Zadig·설치 플러그인·uninstaller·예제 캡처를 포함한 원본 NSIS 전체를 입력으로 받지 않는다.

## 명시 로컬 설치

```sh
./scripts/install.sh --only openocd-win --windows-bundle-source openocd=/path/to/openocd/payload --prefix /path/to/tools
./scripts/install.sh --only sigrok-win --windows-bundle-source sigrok=/path/to/sigrok/payload --prefix /path/to/tools
./scripts/install.sh --check --only openocd-win,sigrok-win --prefix /path/to/tools
PWEH_TOOLS_DIR=/path/to/tools .venv/bin/pweh doctor --windows-bundles-only --json
```

`/path/to/...`를 실제 WSL/Linux 절대 경로로 바꾼다. `openocd-win`·`sigrok-win`은 명시 선택 구성요소로 기본/all/minimal에 들어가지 않는다. 두 항목끼리는 같이 선택할 수 있고 source 옵션도 도구별로 한 번씩 지정할 수 있다. 기존 설치 구성요소와의 혼합은 거부하므로 따로 실행한다.

등록된 설치본이 있으면 source 없이 재검증할 수 있다. 입력이 없고 설치본도 없으면 실패하며 다운로드로 대신하지 않는다. 이 전용 경로는 env.sh·사용자 설정·도구 포인터·드라이버를 바꾸지 않는다. 기존 전체 설치와 전체 doctor의 실행 환경/도구 버전 확인 동작은 그대로다.

## 관리 위치·업데이트·이전 버전 선택

관리 release root는 `<tools-root>/windows-bundles/<tool>/<release_id>-<manifest-sha256>/`이며 `release.json`과 `payload/`만 둔다. receipt는 등록된 manifest를 고르는 힌트이며 자체 신뢰 근거가 아니다. 파일·유도한 디렉터리의 정확 집합을 확인하므로 등록되지 않은 DLL·site/scripts·빈 디렉터리, 링크·특수 파일·하드링크·모호한 경로는 거부한다.

source 검증 → 검증한 동일 fd에서 별도 pending으로 복사·재검증 → receipt 작성·권한 고정 → 충돌 시 덮어쓰지 않는 원자 게시 순서다. 게시 전 source의 처음 신원과 내용을 다시 대조한다. 실행파일은 `0555`, 데이터·receipt는 `0444`, release 디렉터리는 `0555`이며 source의 특수 권한을 복사하지 않는다. 이미 있는 정상 설치본은 재검증 후 성공하며 손상된 같은 release root를 강제로 덮어쓰지 않는다. 실패한 새 설치가 기존 정상 release를 지우지 않는다. 실행 중인 release의 제자리 갱신·자동 삭제·자동 구버전 fallback은 없다.

선택 우선순위는 `tools.openocd_win_bundle`/`tools.sigrok_win_bundle` → `PWEH_OPENOCD_WIN_BUNDLE`/`PWEH_SIGROK_WIN_BUNDLE` → 관리 기본 release다. 명시 값은 payload나 실행파일이 아닌 release root의 절대 경로다. 잘못된 명시 값은 오류이며 낮은 우선순위로 넘어가지 않는다. 이전 버전 사용도 등록된 이전 release root를 명시하고 전체 tree를 다시 검증한다.

## 진단의 의미

`pweh doctor --windows-bundles-only`는 config·순수 환경값·도구 위치 포인터와 등록 manifest/번들만 읽는다. env.sh source, Windows EXE/PowerShell/wslpath 실행, COM/PnP 조회, 케이스/상태 디렉터리 생성은 하지 않는다. 일반 doctor 전체가 이 정적 범위로 바뀌는 것은 아니다.

진단은 선택 설치 없음(`ok=null`), 등록 tree 일치(`ok=true`), 명시 경로/receipt/hash 오류(`ok=false`)를 구분한다. 실패 항목이 있으면 종료 코드가 비0이며 선택 설치 없음만 있으면0이다. 성공해도 Windows 실행은 미확인, 이 진단에서 backend를 활성화하지 않았음을 표시하며 sigrok의 알려진 제한을 보존한다. 고정 입력·파일·깊이·전체 바이트·deadline 상한은 검증 비용을 제한하지만 커널 I/O나 같은 OS 계정의 최종 검사 직후 변경을 강제로 막는 보장은 아니다.

## 검증 API와 한도

`pweh.windows_bundle`은 저장소의 `data/windows-bundles.json`이 고정한 manifest SHA를 확인한다. 두 payload manifest도 Python 패키지에 포함된다. `load_registered_manifest`와 `managed_release_root`가 등록 버전과 관리 위치를 정하며, `verify_payload`는 source, `verify_release`는 receipt·고정 권한을 포함한 설치본을 검사한다. 반환은 frozen 값이며 `open_verified_file`은 관찰했던 신원과 같은 파일 fd만 복사기에 빌려준다. `revalidate_bundle`은 원래 snapshot과 전체 tree를 다시 대조한다. 환경변수나 CLI로 임의 manifest를 신뢰 목록에 추가할 수 없다.

한 번의 검증은 최대45초, 설치는 단계 전체에 공유한 최대120초 예산을 쓴다. 파일10,000개·tree 항목20,000개·깊이32·상대 경로1,024자·파일64 MiB·전체512 MiB를 상한으로 한다. 등록 색인은64 KiB, manifest는2 MiB, receipt는4 KiB다. 한도를 넘거나 취소·검사 실패가 나면 고정 오류 코드를 반환한다. 로컬 원시 예외·경로·내용을 진단에 붙이지 않는다.
