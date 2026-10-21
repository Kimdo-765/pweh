# Windows COM helper

`pweh-serial-helper.c`는 COM1..4096 하나를 여는 중계기다. 일반 파일·네트워크·명령 실행 모드는 없다. `--version --token <hex32>`와 `--echo --token <hex32>`는 COM 함수를 호출하지 않는다. stdout은 길이가 제한된 binary frame만 출력한다. 프로토콜·수명 계약은 `docs/design/port-routing.md`와 Python `pweh.winserial.protocol`을 참고한다.

소스 단계 S에서는 `build-lock.json.artifact=null`, Python runtime pin=None이다. 이 상태에서는 설치·실행 검증이 명시적으로 실패한다. 유지보수자는 S를 확정한 뒤 기존 고정 Zig 0.17.0으로 두 독립 디렉터리/cache에서 빌드하고, 같은 PE bytes를 확인한 다음 R에 실제 binary·pin·보고서를 넣는다. R의 build 입력은 S와 같아야 한다.

```sh
python scripts/build_serial_helper.py build --repo-root . --source-commit <S의40자리SHA> --output-dir <새경로> --zig <고정Zig절대경로>
python scripts/build_serial_helper.py verify-release --repo-root .
```

`--preliminary`는 작업 중 소스를 컴파일하는 개발 점검이다. 이 보고서는 릴리스 증거로 사용할 수 없다. build script는 exe를 실행하지 않으며 네트워크를 사용하지 않는다. installer의 `--only winserial`은 검증한 저장소 사전 빌드를 복사한다.

빌드는 CRT 없는 고정 entrypoint를 사용한다. 고정 KERNEL32 import 33개 이외 함수·DLL, delay import, 잘린/겹친 section과 RVA, 실행·쓰기 section, ASLR/NX 누락을 거부한다. `-s`로 CodeView를 제거하고, Zig가 넣는 content-hash COFF timestamp 네 바이트만 명시적으로 0으로 바꾼다. 원시 PE와 최종 PE의 해시를 함께 기록한다. PE identity section에는 source S와 version/protocol만 들어가며 자기 PE 해시는 넣지 않는다.

고정 Zig의 Windows C SDK 헤더가 포함되지 않아 `win32-abi.h`에 사용하는 공개 Win32 ABI만 선언했다. DWORD/WCHAR/pointer, DCB(28 bytes), COMSTAT(12), COMMTIMEOUTS(20), OVERLAPPED(32), CRITICAL_SECTION(40)의 크기·offset을 compile-time assert한다. Windows x64 기본 호출 규약만 지원한다. CRITICAL_SECTION의 필드 순서는 고정 Zig 0.17.0의 `lib/std/os/windows.zig` 정의와도 대조했다.

근거: Microsoft [Windows data types](https://learn.microsoft.com/en-us/windows/win32/winprog/windows-data-types), [x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention), [DCB](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-dcb), [COMSTAT](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-comstat), [COMMTIMEOUTS](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-commtimeouts), [OVERLAPPED](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-overlapped), [PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

`test-native.c`는 파서·COM 문법·취소 HAL을, `test-win32.c`는 실제 coordinator를 가짜 Win32 함수에 연결해 검사한다. 두 host 프로그램은 Windows나 장치를 사용하지 않는다. 실제 VCP의 share0 배타, 첫 DTR/RTS pulse, 뽑힘·서버 종료 뒤 COM 회수는 별도 실기 확인 대상이다.
