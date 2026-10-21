# native/emu — AVR 실행기 `pweh_avr_run`

pweh-emu 서버(`mcp-servers/emu-mcp`)의 AVR 백엔드가 쓰는 작은 C 드라이버다. simavr 를 라이브러리(`libsimavr.a`)로만
빌드하고 이 소스 하나를 정적으로 링크한다. Arduino AVR 펌웨어(Intel HEX)를 실행하고 USART 를 표준 입출력에 잇는다.
서버는 이것을 고정 argv 로만 띄운다 (에이전트 인자는 들어가지 않는다):

```
<절대 경로>/pweh_avr_run --mcu <mcu> --freq <hz> --uart <n> --realtime --hex-fd <H>
```

`<H>` 는 서버가 확인한 바이트(정규화한 Intel HEX)를 담아 봉인한 memfd 다. 이름으로 여는 파일이 없으므로 확인한 바이트와
실행하는 바이트 사이에 바꿔치기할 틈이 없다. 실행기는 이 fd 를 닫지 않고 끝까지 들고 있다 (`/proc/<pid>/fd` 에 memfd 하나로
보여 넘김 방식을 밖에서 확인할 수 있다). 신호는 `SIGPIPE` 만 스스로 무시한다.

## 사용법

| 형태 | 설명 |
|---|---|
| `pweh_avr_run --version` | 한 줄 `pweh_avr_run <PWEH_AVR_RUN_VERSION> simavr <커밋>` (커밋은 빌드 때 `-DPWEH_SIMAVR_COMMIT`) |
| `pweh_avr_run --mcu NAME --freq HZ [--uart N] [--realtime] [--max-cycles N] (--hex-fd N \| FILE.hex)` | 실행. `FILE.hex` 는 직접 실행할 때만 (이름이 `.hex` 로 끝나야 한다) |

- `--mcu`: simavr 코어 이름(소문자·숫자). 서버의 허용 목록은 atmega8·168·328p·32u4·644p·1280·1284p·2560 이다.
- `--freq`: 1 000–64 000 000 Hz. `--uart`: 0–3 (32u4 의 Arduino `Serial1` 은 1).
- `--realtime`: 게스트 시간을 벽시계에 맞춘다. 바쁜 대기 펌웨어는 앞서 가면 stdin 을 시간 제한 `poll` 로 기다리며 쉬고,
  인터럽트를 켠 채 자는 펌웨어는 simavr 의 `usleep` 대신 이 실행기의 잠 함수가 같은 방식으로 기다린다. 입력이 오면 바로 깬다.
  1 ms(게스트 시간)마다 도는 빈 cycle timer 가 잠 한 번을 1 ms 로 묶어, 느린 타이머로만 자는 펌웨어도 입력 지연과
  일찍 깬 잠의 시간 어긋남이 1 ms 안이다. 서버는 늘 켠다 (바쁜 대기 펌웨어에서 CPU 약 10%).
- `--max-cycles N`: N 사이클에서 멈춘다 (시험용 — 서버는 쓰지 않는다).

## 스트림·종료 코드

| 스트림 | 내용 |
|---|---|
| stdin | UART 입력. 4 KiB 링에 받아 simavr 의 XON/XOFF IRQ 로 넣는다. 펌웨어가 RXEN 을 켤 때까지 보류 (링이 차면 stdin 을 더 읽지 않는다) |
| stdout | UART 출력 원시 바이트. 원래 fd 1 의 복제로만 쓰고 fd 1 은 stderr 로 돌린다 (libsimavr 의 `printf` 가 섞이지 않게) |
| stderr | simavr 로그 + 마지막 줄 `pweh_avr_run: state=done\|crashed\|max-cycles cycles=N pc=0x…` |

| 종료 코드 | 뜻 |
|---|---|
| 0 | 펌웨어가 멈춤 (인터럽트를 끈 `sleep`, 또는 인터럽트를 끈 `rjmp .-2`) |
| 1 | HEX 적재 실패 (형식·체크섬·EOF 없음·플래시/EEPROM 크기 초과·지원하지 않는 주소 영역) |
| 2 | 사용법·MCU·UART 오류 |
| 3 | 충돌 (PC 가 플래시 끝을 넘음) — GDB 서버를 열지 않고 바로 끝난다 |
| 4 | `--max-cycles` 도달 |
| 5 | UART 출력을 읽는 쪽이 사라짐 (`SIGPIPE` 를 무시하므로 `write` 가 `EPIPE` 를 받아 끝난다) |
| 그 밖 | 신호 (서버의 SIGTERM 등) |

진단 문구(`pweh_avr_run:` 으로 시작)에는 줄 번호·주소만 쓰고 HEX 레코드 내용이나 펌웨어 값은 쓰지 않는다.

## HEX 적재

1. 입력 전체를 처음부터 읽어(최대 8 MiB) 엄격히 검사한다: 모든 줄이 `:` + 16진 두 자리 짝, 바이트 수 필드 = 실제 길이,
   체크섬, 유형 00–05, EOF 레코드(01)가 꼭 하나 있고 그 뒤에는 빈 줄만. 유형 02(세그먼트 주소)는 simavr 가 주소를 더하지 않고
   OR 하므로 64 KiB 경계 값만 받는다. 실패하면 줄 번호와 이유를 알리고 종료 코드 1.
2. simavr 의 해석기 `read_ihex_chunks` 로 `/proc/self/fd/<N>` 를 읽는다. 이 함수는 `sim_hex.c` 안의 `static` 함수라
   `pweh_avr_run.c` 가 `sim_hex.c` 를 번역 단위에 끼워 넣는다 (그러면 `libsimavr.a` 의 `sim_hex.o` 는 링크되지 않는다).
   검사 단계와 해석 단계가 본 데이터 바이트 수가 다르면 거부한다.
3. 덩어리를 실행기가 직접 나눈다 (simavr `sim_setup_firmware` 의 분류는 쓰지 않는다):
   - `0x800000` 미만 → 플래시 (MCU 플래시 크기 안이어야 한다),
   - `0x810000`–`0x81FFFF` → EEPROM (MCU EEPROM 크기 안 — 시뮬레이션 EEPROM 에 적재),
   - `0x820000`–`0x85FFFF` → 퓨즈·잠금·서명 — 무시하고 알림만,
   - 그 밖(데이터 공간 `0x800000`–`0x80FFFF` 포함) → 거부.
4. ELF 경로는 없다: `sim_setup_firmware`·`elf_read_firmware` 를 부르지 않고, simavr 를 libelf 없이 빌드해 ELF 해석기
   자체가 없다 (ELF 의 `.mmcu` 섹션은 펌웨어가 정하는 `strcpy`·VCD 파일 경로로 이어진다).

PC 는 늘 0 에서 시작한다. 전체 플래시 덤프 끝의 부트로더(Optiboot 등)는 건너뛴다 (BOOTRST 퓨즈 흉내는 없다).

## 보안 수정과 확인

- **플래시 범위 밖 접근 (고정 커밋 simavr 의 결함)**: LPM(16비트 Z)·ELPM(RAMPZ:Z, 24비트)·SPM 페이지 지우기/쓰기가
  `avr->flash[z]` 를 범위 검사 없이 쓰는데 `avr_init` 은 `flashend + 4` 바이트만 잡는다 → 펌웨어가 호스트 힙을 읽고 쓸 수 있다.
  실행기는 `avr_init` 바로 뒤에 플래시 버퍼를 `(1 << 24) + 1024 + 4` 바이트(0xFF)로 바꾸고 원래 내용(플래시와
  `AVR_OVERFLOW_OPCODE`)을 옮긴다. RAMPZ 가 없는 MCU(ATmega328P 등)도 같은 크기다 — simavr 의 ELPM 은 RAMPZ 가 없으면
  "잘못된 명령" 로그만 남기고 RAMPZ 대신 r0 으로 24비트 색인을 만들어 읽기 때문이다. 실제 플래시 뒤는 지운 상태(0xFF)로 읽히고
  그 영역의 SPM 은 여유 버퍼에만 닿는다. 메모리가 약 16 MiB 늘지만(실측 VmPeak 약 20 MB) AVR 의 `RLIMIT_AS`(64 MiB) 안이다.
  픽스처 `tests/fixtures/emu/avr_oob_probe_{m328p,m2560}.hex` 가 이것을 확인한다 (충돌 없음, 0xFF, 종료 코드 0).
- **GDB 서버 코드 없음**: `avr->gdb_port = 0` 이고, `sim_gdb.o` 의 함수 다섯(`avr_gdb_init`, `avr_deinit_gdb`,
  `avr_gdb_processor`, `avr_gdb_handle_watchpoints`, `avr_gdb_handle_break`)을 이 소스에서 빈 함수로 정의해 정적 링크가
  `sim_gdb.o` 를 끌어오지 않는다 (`-Wl,--wrap` 는 쓰지 않는다). 확인: `nm -D --undefined-only pweh_avr_run` (정적 빌드면 `nm`)에
  `socket`·`bind`·`listen`·`accept`·`connect` 가 없다 — 설치 스크립트가 빌드 직후와 `--check` 때 검사한다.
- **`run_avr` 는 설치하지 않는다**: 펌웨어가 충돌하면 `0.0.0.0:1234` 에 GDB 서버를 열고 기다리며, stdin 입력 연결이 없다.
- **`-DNDEBUG` 로 빌드하지 않는다**: simavr 의 일부 범위 검사(`avr_usb` 의 UENUM 등)는 `assert` 로만 되어 있다.
- 파일 쓰기·VCD·콘솔/명령 레지스터·네트워크 호출이 없다. 서버의 실행 shim 이 rlimit·PDEATHSIG·(가능하면) 빈 네트워크
  네임스페이스·최소 환경으로 띄운다.

## 빌드 (`scripts/install.sh --only simavr`)

설치 스크립트가 사용자 기기에서 빌드한다. 직접 할 때도 같은 단계를 따른다.

1. simavr 를 커밋 `5b08da60497f7564f50941f74a549fe2851db030` 으로 받는다 (`git init` → `git fetch --depth 1 <저장소> <커밋>` →
   `checkout FETCH_HEAD` → `rev-parse HEAD` 확인). 릴리스 asset 이 없어 git 소스이고, `--seed` 로 대신할 수 없다.
2. 라이브러리만 빌드한다 (libelf·libdwarf 자동 감지를 끈다. **`V=1` 금지** — 그러면 `/tmp/simavr_conf.log` 를 쓴다):
   ```
   make -C simavr RELEASE=1 C_LIBELF= LD_LIBELF= C_LIBDWARF= LD_LIBDWARF= CC=<cc> AR=<ar> RANLIB=<ranlib> obj config
   make -C simavr RELEASE=1 C_LIBELF= LD_LIBELF= C_LIBDWARF= LD_LIBDWARF= CC=<cc> AR=<ar> RANLIB=<ranlib> "obj-$(<cc> -dumpmachine)/libsimavr.a"
   ```
3. 실행기를 링크한다:
   ```
   <cc> -std=gnu99 -O2 -Wall -I<simavr>/simavr/sim -I<simavr>/simavr/sim/avr -I<simavr>/simavr \
        -DPWEH_SIMAVR_COMMIT='"<커밋>"' native/emu/pweh_avr_run.c <simavr>/simavr/obj-*/libsimavr.a -lm -o pweh_avr_run
   ```
   `PWEH_SIMAVR_COMMIT` 가 없으면 컴파일 오류다. avr-gcc·avr-libc·libelf 는 필요 없다 (simavr 가 코어용 io 헤더를 들고 있다).

컴파일러는 도구 디렉터리의 PWEH zig 가 있으면 그것(`zig cc`/`zig ar`/`zig ranlib` 래퍼를 `<prefix>/_build/zigcc/` 에,
zig 캐시는 `<prefix>/_build/zig-cache` — `~/.cache/zig` 를 쓰지 않는다), 없거나 실패하면 시스템 `cc` 다. 둘 다 없거나
`git`·`make` 가 없으면 이 선택 구성요소를 건너뛴다. simavr Makefile 은 `-Werror` 라 아주 새 컴파일러에서는 경고로 실패할 수 있다.
결과는 `<prefix>/simavr/bin/pweh_avr_run` 하나이고(약 1.8 MB, libc 만 동적 링크), env.sh 의 `PWEH_AVR_RUN` 으로 알린다
(PATH 에는 넣지 않는다). 빌드 중간물은 `<prefix>/_build/` 에 남는다 (지워도 된다).

**버전**: 이 소스를 바꾸면 `PWEH_AVR_RUN_VERSION` 을 올린다. 설치 스크립트는 설치된 실행 파일의 `--version` 이 저장소 소스의
버전과 고정 simavr 커밋을 함께 보일 때만 설치된 것으로 보고, 다르면 다시 빌드한다. pweh-emu 서버·`pweh doctor` 도 이 줄을 확인한다.

## 라이선스

`pweh_avr_run.c` 는 저장소 라이선스(MIT)다. 빌드할 때 simavr(GPL-3.0)의 헤더와 `sim_hex.c` 를 끼워 넣고 `libsimavr.a` 와 정적으로
링크하므로 만들어진 실행 파일은 GPL-3.0 결합물이다. 사용자 기기에서 빌드해 쓰고 배포하지 않는다 (법률 자문 아님).

## 시험

- 픽스처와 생성기: `tests/fixtures/emu/` (`README.md` 참고) — UART 에코, 충돌, 범위 밖 접근 탐침.
- `tests/servers/test_emu_fixtures.py`: 생성기 출력 = 커밋한 HEX, 레코드 체크섬, 그리고 실행기가 있으면
  (`PWEH_AVR_RUN` 또는 도구 디렉터리, `@pytest.mark.external`) 에코·충돌·탐침·`--version`·소켓 함수 없음·HEX 거부를 직접 확인한다.
- 서버를 거친 시험은 `tests/servers/test_emu_external.py`.
