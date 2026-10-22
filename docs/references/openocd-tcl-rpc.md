# OpenOCD TCL RPC 레퍼런스 (openocd-mcp / fake 서버 구현용)

> 대상 독자: `openocd-mcp`(Python, 공식 MCP SDK) 드라이버·파서 구현자, 테스트용 fake OpenOCD TCL 서버 구현자, 에이전트 Skill 작성자.
> 범위: 본인 소유이거나 서면 허가를 받은 장비를 JTAG/SWD로 디버깅·덤프할 때 쓰는 OpenOCD 제어 계층.
> 원칙: 정확한 문자열과 바이트가 산문보다 중요하다. 실측하지 못한 형식은 **(미확인)**으로 표시한다.

---

## 0. 검증 방법과 표기 규칙

### 0.1 실측에 사용한 OpenOCD 빌드 (2026-10-18)

| 표기 | 버전 문자열 (`version` 응답 그대로) | 출처 |
|---|---|---|
| **master** | `Open On-Chip Debugger 0.12.0+dev-02761-gbb5a52da (2026-10-18-06:21)` | `openocd-org/openocd` master `bb5a52da599c3dac61ddc51d2fa8c1166ee795d0`(2026-10-16)를 직접 빌드 |
| **xPack** | `xPack Open On-Chip Debugger 0.12.0+dev-02228-ge5888bda3-dirty (2025-10-04-22:42)` | xPack OpenOCD `0.12.0-7` 바이너리. 실체는 master `e5888bda3`(2025-09-30) 스냅샷 |
| **0.12.0** | (자체 빌드라 `0.12.0-01004-g9ea7f3d6 …`로 찍힘. 이는 git 빌드에서 생긴 아티팩트다. 릴리스 tarball 빌드는 `Open On-Chip Debugger 0.12.0`) | 태그 `v0.12.0`(2023-01-14). 현재까지 **마지막 공식 릴리스**. 배포판 패키지: Debian 13 trixie `0.12.0-3`(https://packages.debian.org/trixie/openocd), Debian 12 bookworm `0.12.0-1`(https://packages.debian.org/bookworm/openocd), Ubuntu 24.04 noble `0.12.0-1build2`(https://packages.ubuntu.com/noble/openocd). 배포판 패치가 출력 형식을 바꾸는지는 (미확인) |
| **0.11.0** | `Open On-Chip Debugger 0.11.0` | Ubuntu 22.04 `openocd_0.11.0-1` 패키지(apt 기본 버전) |

- 2026-10 기준 GitHub 태그는 `v0.12.0`이 마지막이다(`git ls-remote --tags`). 이후 1,757개 커밋이 쌓인 master가 "0.12.0+dev"다.
- 온라인 매뉴얼 https://openocd.org/doc/html/index.html 은 "release 0.12.0+dev, dated 12 October 2026"을 문서화한다. 즉 **master 문법 기준**이다. 0.12.0 릴리스와 다른 부분이 있으므로 아래 버전 매트릭스(§2)를 반드시 확인한다.

### 0.2 하드웨어 없이 실측한 방법

1. **dummy 어댑터** (`adapter driver dummy`): 서버·프로토콜·설정 단계 명령만 실측했다(§7.1).
2. **remote_bitbang JTAG 시뮬레이터**: Python으로 만든 TAP 상태기계에 ARM ADIv5 JTAG-DP와 AHB MEM-AP(RAM 백엔드)를 붙였다. 이를 OpenOCD `remote_bitbang` 드라이버로 연결해 실제 `init`, 스캔체인 검출, 메모리 읽기/쓰기, 이미지 덤프, faux 플래시 뱅크까지 끝에서 끝으로 실측했다(§7.2, 부록 A).
   - 타깃 타입은 `mem_ap`이다. 따라서 `halt`/`reg`가 빈 결과를 내는 것은 **mem_ap 특성**이다. 실제 CPU 코어의 halt 메시지와 레지스터 형식은 소스에서 가져왔다(§4.7, §4.8).
   - 시뮬레이터의 IDCODE `0x5ba00477`은 `tcl/target/allwinner_v3s.cfg`의 DAP 값을, `0x0792603f`는 `tcl/target/at91sam9.cfg`의 ARM926EJ-S 값을 빌려왔다. 메모리 내용은 합성 데이터다.

### 0.3 표기

- **[실측 master]**, **[실측 0.12.0]**처럼 표시한 것은 위 빌드에서 TCL RPC 소켓으로 받은 **원시 바이트**다. Python `bytes` 리터럴로 적는다. Markdown 코드블록은 줄 끝 공백과 `\x1a` 위치를 숨기기 때문이다.
- **[소스]**는 아래 고정 링크의 코드에서 포맷 문자열을 직접 읽은 것이다.
  - master: `https://github.com/openocd-org/openocd/blob/bb5a52da599c3dac61ddc51d2fa8c1166ee795d0/<path>#L<n>` (이하 `M:<path>#L<n>`)
  - 0.12.0: `https://github.com/openocd-org/openocd/blob/v0.12.0/<path>#L<n>` (이하 `T:<path>#L<n>`)
- 측정 출력에 나오는 긴 임시 경로는 `/tmp/rb.bin` 같은 형태로 줄였다. 소요 시간과 속도 숫자(`in 0.011000s (22.727 KiB/s)`)는 매번 달라진다.

---

## 1. 구현자용 요약 (먼저 읽을 것)

1. **프레이밍**: 요청은 `UTF-8 Tcl 스크립트 + 0x1a`, 응답은 `Jim 결과 문자열 + 0x1a`다. 상태 코드, 길이 헤더, 프롬프트는 없다. [소스 `M:src/server/tcl_server.c#L163`]
2. **실패가 결과 문자열로 구분되지 않는다.** 실패한 명령이 빈 문자열을 돌려주는 경우가 흔하다(`mdd`, 범위 밖 `flash read_bank`, `verify_image_checksum`, `flash info 7` 등). 반드시 아래 **봉투(envelope)**로 감싼다. 0.11.0부터 master까지 모두 실측으로 검증했다(§3.4).
   ```tcl
   set _pweh_rc [catch {<CMD>} _pweh_out]; set _pweh_x "$_pweh_rc $_pweh_out"
   ```
   - 응답은 `"<rc> <out>"`이다. `rc == 0`이면 성공, **0이 아니면 모두 실패**다. master는 1을, 0.11/0.12.0은 OpenOCD 음수 에러코드(`-306`, `-601`, `-4` …)를 돌려준다.
   - 최상위 `return`은 쓰지 않는다. 0.11과 0.12.0에서는 `return ok`조차 `command.c:708: Error: ok\nat file "command.c", line 708`처럼 오류로 포장된다.
3. **진짜 에러 메시지는 OpenOCD 로그(stderr)에만 있는 경우가 많다.** 런처는 stderr를 계속 비워 읽고, 실패 응답에 로그 꼬리(tail)를 붙여 보고한다. `capture`로 일부를 회수할 수 있지만 버전마다 의미가 다르다(§3.6).
4. **버전 차이**(§2)가 크다. 0.11과 0.12.0은 결과 끝에 `\n`이 남고, 리스트를 공백으로 구분하며, `tcl port` 명령이 없다(`tcl_port`만 있다). 파서는 `rstrip("\n")`, 공백·개행 양쪽 구분자, 10진/16진 양쪽을 허용한다.
5. **준비 완료 판정**: `Info : Listening on port 6666 for tcl connections`는 **`init`보다 먼저** 찍힌다. 이 줄 이후 첫 `version` 왕복이 성공해야 준비 완료다. 그 사이 프로세스가 종료되면(init 실패, rc=1) 실패로 처리한다(§6.4).
6. **`init`이 한 번 실패하면 같은 프로세스에서 다시 `init`해도 아무 일 없이 성공(빈 응답)을 돌려준다.** 반드시 OpenOCD를 재시작한다(§6.5).
7. **알림(notification)은 같은 소켓의 응답 앞에 끼어든다.** 별도 연결을 하나 더 열어 그쪽에서만 `tcl notifications on`을 켠다(§3.8).
8. **보안**: OpenOCD 안의 Jim Tcl에는 `exec`, `open`, `socket`, `popen`, `os.fork`, `load`가 있다(4개 빌드 모두 실측). TCL 포트 접근은 곧 OpenOCD 사용자 권한의 **호스트 코드 실행**이다. 기본 바인딩이 루프백뿐이므로 `bindto 0.0.0.0`은 금지한다. MCP는 원시 Tcl 대신 타입이 있는 도구와 허용목록으로만 명령을 만든다(§5).

---

## 2. 버전 매트릭스 (실측 차이)

| 항목 | 0.11.0 | 0.12.0 | xPack(2025-10 dev) | master(2026-10) |
|---|---|---|---|---|
| TCL 포트 지정 | `tcl_port N` | `tcl_port N` (`tcl port`는 `invalid command name "tcl"`) | `tcl port N` (+deprecated `tcl_port`) | `tcl port N` (+deprecated `tcl_port`, 사용 시 로그에 `DEPRECATED! use 'tcl port' not 'tcl_port'`) |
| gdb/telnet 포트 | `gdb_port`, `telnet_port` | `gdb_port`, `telnet_port` | `gdb port`, `telnet port` | `gdb port`, `telnet port` (밑줄형은 deprecated proc) |
| 알림 켜기 | `tcl_notifications on` | `tcl_notifications on` | `tcl notifications on` | `tcl notifications on` |
| `read_memory`/`write_memory` | **없음** (`mem2array`/`array2mem`만) | 있음 | 있음 | 있음 (`mem2array`/`array2mem`은 deprecated Tcl proc) |
| 결과 끝 `\n` | 남음 (`…6f422d55 \n`) | 남음 | 제거 | 제거 |
| `jtag names` 구분자 | 공백 | 공백 (`sim.cpu sim.bs`) | 개행 | 개행 (`sim.cpu\nsim.bs`) |
| `drscan` 다중 필드 | 공백 | 공백 (`0477 5ba0`) | 개행 | 개행 (`0477\n5ba0`) |
| `jtag cget <tap> -idcode` | 10진 (`1537213559`) | 10진 (`1537213559`) | 16진 (`0x5ba00477`) | 16진 (`0x5ba00477`) |
| `flash list` | `{name faux base 134217728 size 262144 bus_width 0 chip_width 0}` (`name`이 **드라이버 이름**, `driver`/`target` 키 없음) | `{name sim.flash driver faux base 134217728 size 262144 bus_width 0 chip_width 0 target sim.mem}` | 여러 줄, `name sim.flash` | 여러 줄, `name {sim.flash}` |
| C 명령 실패 시 `catch` 반환값 | OpenOCD 음수 코드 (`-306`) | 음수 코드 | `1` | `1` |
| `$::errorCode` | `NONE` | `NONE` | `NONE` | `OpenOCD <code>` (예: `OpenOCD -601`) |
| 문법 오류 결과(봉투 사용 시 `_out`) | 빈 문자열 | 빈 문자열 (usage는 로그로) | usage 텍스트 | usage 텍스트 |
| 봉투 없이 보낸 오류 결과 | `<cfg파일>:12: Error: <msg>\nat file "<cfg파일>", line 12` 형태로 포장(경로는 마지막 설정 파일의 경로) | 같음 | 메시지만 | 메시지만 (proc 안 오류면 `Traceback (most recent call last):` 줄이 붙음) |
| 최상위 `return x` | 오류로 포장 | 오류로 포장 | `x` | `x` |
| `capture` 의미 | 로그가 있으면 **로그만**, 없으면 결과 | 같음 | 로그+결과 | 로그+결과 |
| `help`/`usage` 결과 | 빈 문자열(로그로 출력) | 빈 문자열 | 텍스트 | 텍스트 |
| halt 상태 메시지 접두어 ([소스]) | `target halted in …` | `target halted in …` | `[<target>] target halted in …` | `[<target>] target halted in …` |
| `-tap` 옵션 (`dap create`/`target create`) | 없음 (`Unknown param: -tap, try one of: -chain-position, or -ignore-syspwrupack`) | 없음 (`Unknown param: -tap, try one of: -chain-position, -ignore-syspwrupack, -dp-id, -instance-id, -adiv6, or -adiv5`) | 없음 (0.12.0과 같은 메시지) | 있음 (`-chain-position`은 `Warn : [x] DEPRECATED! '-chain-position' will be removed in the future, use '-tap' instead`) |
| remote_bitbang 설정 | `remote_bitbang_host/_port` | `remote_bitbang host/port` | 같음 | 같음 |
| `adapter serial` | 없음 | 있음 | 있음 | 있음 |

**이식성 권장안**: 설정 파일·명령행에는 `-chain-position`, Tcl `catch` 폴백을 쓴 포트 지정(§6.2), 봉투(§3.4)를 쓴다. 파서는 위 두 계열 출력을 모두 받아들이게 만든다.

---

## 3. TCL RPC 프로토콜

### 3.1 포트·바인딩

- 기본 포트는 `6666`이다(`tcl_port = strdup("6666");` [소스 `M:src/server/tcl_server.c#L385`]).
- 매뉴얼: "`tcl port` … Intended as a machine interface. When not specified during the configuration stage, the port number defaults to 6666. When specified as "disabled", this service is not activated." (https://openocd.org/doc/html/Server-Configuration.html)
- 포트 `0`을 주면 OS가 빈 포트를 고르고, **실제 포트가 로그에 찍힌다**. 병렬 테스트에 유용하다.
  - [실측 master] `tcl port 0` → `Info : Listening on port 42923 for tcl connections`
  - [실측 0.12.0] `tcl_port 0` → `Info : Listening on port 39067 for tcl connections`
- 바인딩 주소: `bindto`가 없으면 `INADDR_LOOPBACK`(127.0.0.1)만 쓴다 [소스 `M:src/server/server.c#L278`]. 매뉴얼: "By default, OpenOCD will listen on the loopback interface only." [실측] 4개 빌드 모두 `bindto` 조회 결과는 `bindto name: (null)`.
- 연결 수는 무제한이다(`CONNECTION_LIMIT_UNLIMITED`). 모든 연결이 **하나의 Jim 인터프리터와 전역 변수**를 공유한다. OpenOCD는 단일 스레드라서 한 줄(=0x1a 하나)이 다른 연결의 명령과 섞이지 않고 원자적으로 실행된다.
- 로그 메시지 [소스 `M:src/server/server.c#L96`, `#L319`, `#L594`]:
  ```
  Info : Listening on port 6666 for tcl connections
  Info : accepting 'tcl' connection on tcp/6666
  Info : dropped 'tcl' connection
  ```
  포트를 끈 서비스는 `Info : telnet server disabled`, `Info : tcl server disabled`처럼 찍힌다(gdb는 master에서 `Info : [sim.mem] gdb port disabled`, 0.12.0에서 `Info : gdb port disabled`).

### 3.2 프레이밍 (양방향 0x1a)

[소스 `M:src/server/tcl_server.c#L163-L253`] 요약:

- 수신 바이트를 줄 버퍼에 쌓다가 `0x1a`를 만나면 그 자리를 `\0`으로 바꾸고 `command_run_line()`으로 실행한다.
- 실행 후 `Jim_GetResult()` 문자열 전체를 보내고 이어서 `"\x1a"` 1바이트를 보낸다.
- 버퍼는 4 KiB에서 시작해 최대 `TCL_LINE_MAX = 4*1024*1024`까지 늘어난다 [`#L18`].
- **4 MiB를 넘으면** 그 줄을 버리고 `#define ESTR "line too long\n"`을 `sizeof(ESTR)` 길이로 보낸다. 즉 **NUL을 포함해 15바이트를 보내고 0x1a 종결자는 보내지 않는다** [`#L226-L230`].
  - [실측 master] 응답 `b'line too long\n\x00'`. 클라이언트는 종결자를 못 받아 타임아웃되고, 그 다음 명령은 정상 동작했다.
  - 따라서 클라이언트에서 4 MiB에 가까운 요청을 미리 거부한다.
- 명령 안에 0x1a가 있으면 거기서 잘린다. 클라이언트에서 거부한다.
- **파이프라이닝 가능**: 한 번의 send에 `version\x1aadapter name\x1a`를 넣으면 응답 두 프레임이 순서대로 온다. [실측 master] `b'Open On-Chip Debugger …\x1a'`, 이어서 `b'remote_bitbang\x1a'`. 단, 응답 경계는 0x1a뿐이므로 클라이언트는 남은 바이트를 다음 프레임용으로 보관해야 한다.
- `shutdown`이나 `exit`가 실행되면(`ERROR_COMMAND_CLOSE_CONNECTION`) **빈 응답 `"\x1a"`만 보내고 연결을 닫는다** [`#L236-L242`].
- 결과가 비어 있으면 응답은 `b'\x1a'` 한 바이트다. 성공과 실패 모두 이렇게 올 수 있다.
- OpenOCD 자체 출력의 줄바꿈은 `\n`이다. `\r\n`은 알림 프레임(§3.8)이 쓴다.

### 3.3 결과 문자열이 만들어지는 규칙

- C 명령은 `command_print()`로 출력을 쌓고, 그 누적 문자열이 Tcl 결과가 된다 [소스 `M:src/helper/command.c#L389`, `#L424-L494`].
  - master/xPack은 마지막 `\n` 하나를 지운다("Drop last '\n' to allow command output concatenation", `#L468`).
  - 0.12.0/0.11은 그대로 둔다(`Jim_SetResult(context->interp, cmd.output);` [소스 `T:src/helper/command.c#L522`]).
- `LOG_INFO`/`LOG_USER`/`LOG_ERROR`(`Info : …`, `Error: …`)는 결과에 **포함되지 않는다**. OpenOCD 로그(기본 stderr)로만 간다. `echo hello`와 `puts hi`의 RPC 결과는 빈 문자열이다 [실측 master `b'\x1a'`]. `puts`는 OpenOCD의 stdout으로 나간다.
- 그래서 `halt`, `resume`, `reset …`, `init`, `jtag arp_init`, `irscan`, `mww`, `write_memory`, `load_image`(일부) 등 "동작" 명령은 성공해도 결과가 비거나, 진행 메시지가 로그로만 간다.
- TCL 세션에서 실행한 명령의 결과도 OpenOCD 로그에 그대로 찍힌다(`command_run_line()`이 결과를 `command_output_text()`로도 보낸다 [`M:src/helper/command.c#L497`]). 디버깅할 때 OpenOCD 로그만 봐도 결과를 추적할 수 있다.
- 0.10 이하에서는 모든 명령에 `ocd_` 접두어 버전이 있었고 그것을 써야 결과를 돌려받았다(v0.10.0 `src/helper/startup.tcl` 주석: "All commands are registered with an 'ocd_' prefix"). 0.11부터 제거되었다. [실측] 0.11/0.12.0/master의 `info commands ocd_*`는 `ocd_find ocd_gdb_restart ocd_process_reset ocd_process_reset_inner`뿐이다. 매뉴얼: "It is not needed anymore to prefix the OpenOCD commands with `ocd_` to get the results back. But sometimes you might need the `capture` command." (https://openocd.org/doc/html/Tcl-Scripting-API.html)

### 3.4 오류 감지와 권장 봉투(envelope)

**사실 1. 상태 코드가 없다.** `command_run_line()`이 실패하면 `Jim_MakeErrorMessage()`로 오류 문자열을 결과에 넣고 `LOG_USER`로도 찍는다 [소스 `M:src/helper/command.c#L497-L551`]. TCL 서버는 그 문자열을 일반 결과와 똑같이 보낸다.

**사실 2. 실패해도 결과가 비는 경우가 흔하다.** [실측 master, 봉투 없이 보낸 경우]

| 명령 | RPC 응답 | 실제 원인(로그에만 있음) |
|---|---|---|
| `mdd 0x08000000 2` (MEM-AP가 64비트 미지원) | `b'\x1a'` | `Error: Size 8 not supported` |
| `flash info 7` | `b'\x1a'` | `Error: flash bank 7 does not exist` |
| `flash read_bank 0 /tmp/rb3.bin 0x3fff0 0x100` | `b'\x1a'` | `Error: Length of 256 bytes with offset 0x0003fff0 is out of range of the flash bank` |
| `verify_image_checksum /tmp/blob.bin 0x20000100 bin` | `b'\x1a'` | `Error: checksum mismatch` |
| `tcl notifications on` (init 전) | `b'\x1a'` | `Error: The 'tcl notifications' command must be used after 'init'.` |
| `catch {init}` (어댑터 연결 실패, noinit 모드) | `1` / `_out` 빈 문자열 | `Error: Error on socket 'Failed to connect': errno==9, message: Bad file descriptor.` |

반대로 결과 문자열에 오류 메시지가 들어오는 경우도 있다. 이때도 성공 결과와 형식이 같다.

| 명령 | [실측 master] 응답 |
|---|---|
| `foo_unknown` | `b'invalid command name "foo_unknown"\x1a'` |
| `mdw` (인자 없음) | ``b"flash mdw address [count]\nmdw ['phys'] address [count]\n  sim.mem mdw address [count]\x1a"`` (usage) |
| `mdw 0xzz` | ``b"address option value ('0xzz') is not valid\x1a"`` |
| `read_memory 0x08000000 64 2` | `b'failed to read memory\x1a'` (0.12.0: `b'read_memory: failed to read memory\x1a'`) |
| `error "my error"` | `b'my error\x1a'` |

**사실 3. 0.11/0.12.0은 오류를 이상하게 포장한다.** 봉투 없이 보낸 명령이 실패하면 결과가 다음 모양이 된다.

```python
# [실측 0.12.0] mdd 0x08000000 2   (cfg 경로는 축약)
b'/tmp/cfgS-port.cfg:12: Error: \nat file "/tmp/cfgS-port.cfg", line 12\x1a'
# [실측 0.12.0] mdw 0xzz
b'/tmp/cfgS-port.cfg:12: Error: address option value (\'0xzz\') is not valid\n\nat file "/tmp/cfgS-port.cfg", line 12\x1a'
```
경로와 줄 번호는 **마지막으로 읽은 설정 파일의 마지막 위치**이고 RPC 명령과 무관하다. 최상위 `return`도 같은 식으로 포장된다.

**권장 봉투** (0.11.0, 0.12.0, xPack, master에서 모두 검증):

```tcl
set _pweh_rc [catch {<CMD>} _pweh_out]; set _pweh_x "$_pweh_rc $_pweh_out"
```

[실측] 같은 봉투로 보낸 명령별 응답:

| `<CMD>` | master | 0.12.0 |
|---|---|---|
| `mdw 0x08000000 2` | `b'0 0x08000000: 56190527 6f422d55 \x1a'` | `b'0 0x08000000: 56190527 6f422d55 \n\x1a'` |
| `mdd 0x08000000 2` | `b'1 \x1a'` | `b'-306 \x1a'` |
| `flash info 7` | `b'1 \x1a'` | `b'-4 \x1a'` |
| `mdw` | ``b"1   flash mdw address [count]\nmdw ['phys'] address [count]\n  sim.mem mdw address [count]\x1a"`` | `b'-601 \x1a'` |
| `foo_unknown` | `b'1 invalid command name "foo_unknown"\x1a'` | `b'1 invalid command name "foo_unknown"\x1a'` |
| `read_memory 0x08000000 32 2` | `b'0 0x56190527 0x6f422d55\x1a'` | `b'0 0x56190527 0x6f422d55\x1a'` |
| `capture {mdd 0x08000000 2}` | `b'1 Size 8 not supported\n\x1a'` | `b'-306 \x1a'` |
| `capture {flash info 7}` | `b'1 flash bank 7 does not exist\n\x1a'` | `b'-4 flash bank 7 does not exist\n\x1a'` |
| `capture {reset halt}` | ``b'0 JTAG tap: sim.cpu tap/device found: 0x5ba00477 (mfg: 0x23b (ARM Ltd), part: 0xba00, ver: 0x5)\nJTAG tap: sim.bs tap/device found: 0x0792603f (mfg: 0x01f (Atmel), part: 0x7926, ver: 0x0)\n\x1a'`` | 같음 |
| `capture {echo hello}` | `b'0 hello\n\x1a'` | `b'0 hello\n\x1a'` |

파싱 규칙:

```python
rc_s, _, out = resp.partition(" ")   # resp에서 끝의 \x1a는 이미 뗀 상태
rc = int(rc_s)                       # 0 = 성공. 1 또는 음수 = 실패
out = out.rstrip("\n")               # 0.11/0.12.0의 끝 개행 제거
```

- 0.11/0.12.0의 음수 rc는 OpenOCD 내부 에러코드다(`command_retval_set()`이 `retval`을 Jim 반환 코드로 그대로 쓴다 [소스 `T:src/helper/command.c#L129-L135`]). `-601`=문법 오류(ERROR_COMMAND_SYNTAX_ERROR), `-603`=인자 오류, `-4`=ERROR_FAIL이다. 숫자 자체는 버전마다 달라질 수 있다(같은 "Size 8 not supported"가 0.12.0에서 `-306`, master errorCode에서 `-313`). 그러므로 **"0인가 아닌가"만 판정한다**.
- master는 추가로 `$::errorCode`를 `OpenOCD <code>`로 설정한다 [소스 `M:src/helper/command.c#L492`]. [실측 master] `OpenOCD -313`, `OpenOCD -601`, `OpenOCD -603`, `OpenOCD -4`. xPack/0.12.0/0.11에서는 `NONE`이다. 부가 진단으로만 쓴다.
- 변수 이름은 사용자 스크립트와 겹치지 않게 접두어(`_pweh_`)를 붙인다. 모든 연결이 같은 전역 변수를 공유하지만, 봉투 전체가 한 줄로 원자 실행되므로 경쟁 상태는 없다.
- 봉투 안에서 정상 응답은 항상 `-?\d+ `(숫자 + 공백)로 시작한다. 그러므로 봉투로 보낸 요청에 **빈 프레임(`b'\x1a'`만)이 오면 세션이 닫혔다는 뜻**이다(`shutdown`/`exit`, 직후 EOF). 클라이언트와 fake 서버 모두 이 규칙을 쓴다.
- **봉투가 지켜주지 못하는 것**:
  - `shutdown`/`exit`는 `catch`로도 잡히지 않는다(JIM_EXIT). [실측 master] `catch {shutdown} r` → 응답 `b'\x1a'`, 연결이 끊기고 OpenOCD가 rc=0으로 종료했다.
  - `<CMD>` 안의 중괄호가 짝이 맞지 않으면 봉투가 깨진다. 명령은 검증된 토큰으로만 조립한다(§3.9).

### 3.5 `catch` 동작 정리

- `catch {script} var` → 반환값 0(OK), 1(Tcl 오류), 그리고 0.11/0.12.0에서는 OpenOCD 음수 코드. 본문에서 `return`/`break`/`continue`를 쓰면 Tcl 규칙대로 2/3/4가 나온다(봉투에 넣을 명령에는 이런 제어문을 쓰지 않는다).
- [실측 master] `catch {error "my error"} r opts` → `1`, `set opts` → `-code 1 -level 1 -errorinfo {{} {} 1 {error {my error}}} -errorcode NONE`.
- 봉투 없이 보낸 C 명령 실패의 결과 텍스트는 버전마다 다르다(§2). `catch` 안에서는 C 명령이 `command_print`로 남긴 출력만 `var`에 들어간다(로그 메시지는 안 들어간다).

### 3.6 `capture`

- 매뉴얼: "`capture <command>` — Run <command> and return full log output that was produced during its execution together with the command output. Example: `capture "reset init"`" (https://openocd.org/doc/html/Tcl-Scripting-API.html)
- **master** [소스 `M:src/helper/command.c#L638-L670`]:
  - 실행 중 `log_add_callback()`으로 로그를 모은 뒤 **로그 + 명령 결과**를 둘 다 `command_print`한다.
  - 명령이 실패하면 ERROR_FAIL을 돌려준다(봉투에서 rc≠0).
  - capture 중에는 백그라운드 폴링을 끈다(`jtag_poll_mask()`).
- **0.12.0/0.11** [소스 `T:src/helper/command.c#L692-L715`, `#L108-L127`]:
  - 로그가 비어 있지 않으면 결과를 **로그로 덮어쓴다**(명령 결과는 버려진다). 로그가 비었을 때만 명령 결과를 돌려준다.
- 로그 콜백은 `LOG_INFO` 이하(USER/ERROR/WARNING/INFO)만 받고 DEBUG는 받지 않는다(`if (level <= LOG_LVL_INFO) log_forward(…)` [소스 `M:src/helper/log.c`]). 캡처된 문자열에는 `Info : `, `Error: ` 같은 **접두어가 없다**. 각 줄은 `\n`으로 끝난다.
- [실측 master]
  ```python
  # capture {reset init}
  b'JTAG tap: sim.cpu tap/device found: 0x5ba00477 (mfg: 0x23b (ARM Ltd), part: 0xba00, ver: 0x5)\nJTAG tap: sim.bs tap/device found: 0x0792603f (mfg: 0x01f (Atmel), part: 0x7926, ver: 0x0)\n\x1a'
  # capture {echo hello}
  b'hello\n\x1a'
  # capture {mdw 0x08000000 2}  (로그 없음 → 결과)
  b'0x08000000: 56190527 6f422d55 \x1a'
  # capture {mdd 0x08000000 2}  (실패: 로그 메시지가 결과로)
  b'Size 8 not supported\x1a'
  ```
- 권장 사용처:
  - 결과를 돌려주지 않고 로그로만 말하는 "동작" 명령: `reset *`, `halt`, `init`, `jtag arp_init`, `flash write_image`의 경고 등.
  - `mdw`/`read_memory` 같은 데이터 명령에는 쓰지 않는다. 0.12.0에서는 로그가 한 줄이라도 생기면 데이터가 사라진다.
- 다른 연결이나 이벤트가 그 사이 남긴 로그도 함께 잡힐 수 있다. 캡처 결과는 참고용으로 다룬다.

### 3.7 `exit` / `shutdown`

- `exit`: 현재 TCL/telnet 세션만 닫는다. OpenOCD는 계속 실행된다. [실측 master] 응답 `b'\x1a'` 후 EOF.
  - 세션이 아닌 곳(스크립트)에서 부르면 `Warn : DEPRECATED: 'exit' should only be used in telnet or Tcl sessions to close the session`, `Warn : Did you mean 'shutdown'?`을 찍고 shutdown한다 [소스 `M:src/server/server.c#L833`].
- `shutdown [error|<code>]`: 로그에 `shutdown command invoked`를 찍고 프로세스를 끝낸다. `shutdown error`는 `shutdown 1`과 같다 [소스 `M:src/server/server.c#L798-L831`].
  - [실측 master] 응답 `b'\x1a'` → EOF → 프로세스 종료코드 0. `catch {shutdown} r`도 같았다.
- 공식 예제 클라이언트는 연결을 끊을 때 `exit`를 보낸다(`contrib/rpc_examples/ocd_rpc_example.py`).

### 3.8 알림(`tcl notifications`)과 트레이스(`tcl trace`)

- 형식 [소스 `M:src/server/tcl_server.c#L49-L106`]. 각 프레임은 `\r\n\x1a`로 끝난다.
  ```
  type target_event event <event-name>\r\n\x1a
  type target_state state <state-name>\r\n\x1a
  type target_reset mode <reset-mode>\r\n\x1a
  type target_trace data <hex>\r\n\x1a
  ```
  - `<event-name>` 목록 [소스 `M:src/target/target.c#L167`]: `gdb-halt halted resumed resume-start resume-end step-start step-end gdb-start gdb-end reset-start reset-assert-pre reset-assert reset-assert-post reset-deassert-pre reset-deassert-post reset-init reset-end examine-start examine-fail examine-end debug-halted debug-resumed gdb-attach gdb-detach gdb-flash-write-start gdb-flash-write-end gdb-flash-erase-start gdb-flash-erase-end trace-config semihosting-user-cmd-0x100 … semihosting-user-cmd-0x107`
  - `<state-name>` [`#L219`]: `unknown running halted reset debug-running unavailable`
  - `<reset-mode>`: `unknown run halt init`
  - `type target_state`는 **연결별로 마지막에 본 상태와 달라졌을 때만** 나온다(`tc_laststate` 비교 [소스 `M:src/server/tcl_server.c#L49-L66`]). 이미 halted인 타깃에 `halt`를 보내면 `target_event`만 온다.
- 켜는 명령: master/xPack은 `tcl notifications on|off`, 0.11/0.12.0은 `tcl_notifications on|off`이다. TCL 세션에서만, `init` 이후에만 쓸 수 있다.
  - 활성화 로그는 `Info : Target Notification output  is enabled`(공백 2개 그대로).
  - init 전에 부르면 결과는 빈 문자열이고 로그에 `Error: The 'tcl notifications' command must be used after 'init'.`가 남는다.
- **같은 소켓에서 켜면 알림이 명령 응답 앞에 끼어든다.** [실측 master]
  ```python
  # A 소켓에서 'tcl notifications on' 후 'halt'를 보내면 수신 스트림:
  b'type target_event event gdb-halt\r\n\x1atype target_event event halted\r\n\x1a' + b'\x1a'   # 마지막 \x1a가 halt의 (빈) 응답
  # 'resume':
  b'type target_event event resume-start\r\n\x1a' ... b'type target_event event resume-end\r\n\x1atype target_state state running\r\n\x1a\x1a'
  # 'reset halt':
  b'type target_reset mode halt\r\n\x1a' ... b'type target_event event gdb-halt\r\n\x1atype target_state state halted\r\n\x1atype target_event event halted\r\n\x1a\x1a'
  ```
- **권장: 알림 전용 두 번째 연결.** [실측 master·0.12.0] 연결 B에서만 알림을 켜고 A에서 `halt`/`resume`을 보내면, A의 응답은 깨끗한 `b'\x1a'`이고 B로 다음이 들어왔다.
  ```python
  b'type target_event event gdb-halt\r\n\x1atype target_state state halted\r\n\x1atype target_event event halted\r\n\x1atype target_event event resume-start\r\n\x1atype target_event event resume-end\r\n\x1atype target_state state running\r\n\x1a'
  ```
- 봉투(§3.4)를 쓰면 정상 응답은 항상 `^-?\d+ `로 시작하고 알림은 `type target_`으로 시작한다. 같은 소켓에서도 기계적으로 구분할 수 있다.
- `tcl trace`는 타깃 트레이스 데이터를 16진 문자열로 흘려보낸다. 매뉴얼은 예제로 https://github.com/apmorton/OpenOcdTraceUtil 을 든다. 이 프로젝트에서는 필요성이 낮다.

### 3.9 Python 클라이언트 설계 권장

```python
import socket, re

TERM = b"\x1a"
MAX_REQ = 4 * 1024 * 1024 - 4096          # TCL_LINE_MAX 여유
SAFE_ARG = re.compile(r"^[A-Za-z0-9_.:/+\-]+$")   # 공백·[]{}$;"\\#·개행·0x1a 금지

class OpenOcdTcl:
    def __init__(self, host="127.0.0.1", port=6666):
        self.sock = socket.create_connection((host, port))
        self.buf = b""

    def _frame(self, timeout):
        self.sock.settimeout(timeout)
        while TERM not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("EOF (shutdown/exit 또는 OpenOCD 종료)")
            self.buf += chunk
        frame, _, self.buf = self.buf.partition(TERM)
        return frame.decode("utf-8", "replace")

    def raw(self, script: str, timeout=10.0) -> str:
        data = script.encode("utf-8")
        if TERM in data or len(data) > MAX_REQ:
            raise ValueError("invalid request")
        self.sock.sendall(data + TERM)
        while True:
            f = self._frame(timeout)
            if f.startswith("type target_"):   # 같은 소켓 알림이면 버리거나 큐로
                continue
            return f

    def call(self, *words, timeout=10.0):
        for w in words:
            if not SAFE_ARG.match(w):
                raise ValueError(f"unsafe token: {w!r}")
        cmd = " ".join(words)
        resp = self.raw(f'set _pweh_rc [catch {{{cmd}}} _pweh_out]; '
                        f'set _pweh_x "$_pweh_rc $_pweh_out"', timeout)
        if resp == "":                      # 봉투 응답은 항상 "<rc> "로 시작 → 빈 프레임 = 세션 종료
            raise ConnectionError("session closed (shutdown/exit)")
        rc_s, _, out = resp.partition(" ")
        return int(rc_s), out.rstrip("\n")
```

- `write_memory`의 데이터 리스트(`{0xdeadbeef 0x1}`)는 `SAFE_ARG`가 거부한다. 중괄호를 토큰으로 받지 말고, 검증한 정수들로 클라이언트가 직접 `"{" + " ".join(hex(v) for v in values) + "}"`를 만들어 마지막 인자로 붙인다(이 경로만 별도 메서드로 둔다).

- **타임아웃은 명령별로 다르게 잡는다.** OpenOCD는 단일 스레드라서 긴 명령(`dump_image`로 수 MB, `flash erase`, 느린 `reset`)이 끝날 때까지 다른 연결에도 응답하지 않는다.
  - 예: JTAG 1–4 MHz에서 메모리 덤프 속도는 실측 환경과 무관하게 수십~수백 KiB/s 정도로 보고 크기에 비례하게 잡는다(정확한 속도는 장비별 (미확인)).
- 진행 중인 명령을 프로토콜 수준에서 취소하는 방법은 없다(소켓을 닫아도 실행 중인 명령은 계속된다고 보는 것이 안전하다 (미확인)). 마지막 수단은 OpenOCD 프로세스 종료다.
- 응답 끝 `\n`, 공백 구분과 개행 구분을 모두 허용하는 파서를 쓴다(§2).
- 공식 예제 `contrib/rpc_examples/ocd_rpc_example.py`의 한계 [소스 `M:contrib/rpc_examples/ocd_rpc_example.py`]:
  - 수신 시 `chunk` 안에 토큰이 있는지만 본다. 한 번에 여러 프레임이 오면 경계가 꼬인다.
  - 오류를 판정하지 않는다.
  - `writeMemory(self, wordLen, address, data)`를 인자 4개로 호출하는 버그가 있다.
  - 형식 참고로만 쓴다.

---

## 4. 명령별 정확한 출력 형식

별도 표기가 없으면 응답 바이트는 **[실측 master]**이다. 0.11/0.12.0은 여기에 `\n`이 하나 더 붙은 형태다(§2). 파싱은 정규식으로 하되 공백 개수에 의존하지 않는다.

### 4.1 `version`

```python
b'Open On-Chip Debugger 0.12.0+dev-02761-gbb5a52da (2026-10-18-06:21)\x1a'            # master 빌드
b'xPack Open On-Chip Debugger 0.12.0+dev-02228-ge5888bda3-dirty (2025-10-04-22:42)\x1a'  # xPack
b'Open On-Chip Debugger 0.11.0\x1a'                                                     # Ubuntu 0.11.0
```

- 형식 [소스 `M:src/openocd.c#L41-L46`]:
  - git 빌드: `"Open On-Chip Debugger " VERSION RELSTR " (" PKGBLDDATE ")"`
  - 릴리스 빌드: `"Open On-Chip Debugger " VERSION RELSTR`(날짜 없음)
- 배포판·벤더 빌드는 앞에 이름이 붙을 수 있다(`xPack …`). 버전 파싱 정규식 예: `r"Open On-Chip Debugger (?:v)?(\d+\.\d+\.\d+)(\S*)"`. 이후 `+dev` 여부로 master/릴리스 동작 프로파일을 고른다.
- `version git` (master): `b'v0.11.0-2761-gbb5a52da\x1a'`. 이 값은 저장소의 `git describe` 결과라 신뢰하지 않는다.

### 4.2 어댑터/트랜스포트

| 명령 | 응답 |
|---|---|
| `adapter name` | `b'dummy\x1a'`, `b'remote_bitbang\x1a'` |
| `adapter speed` / `adapter speed 2000` | `b'adapter speed: 1000 kHz\x1a'`, `b'adapter speed: 2000 kHz\x1a'` |
| `transport list` | `b'The following transports are available:\n\tjtag\n\tswd\n\tswim\x1a'` |
| `transport select` (조회) | `b'jtag\x1a'` |

- `adapter speed` [소스 `M:src/jtag/adapter.c#L740-L765`]:
  - 0이 아니면 `adapter speed: %d kHz`, RCLK이면 `adapter speed: RCLK - adaptive`.
  - init 때 로그: `Info : clock speed %d kHz` / `Info : RCLK (adaptive clock speed)` / `Info : RCLK (adaptive clock speed) not supported - fallback to %d kHz`.
  - 속도를 지정하지 않으면 경고 두 줄이 찍힌다. master: `Warn : An adapter speed is not selected in the init scripts. OpenOCD will try to run the adapter at very low speed (100 kHz).`, 0.12.0: `… at the low speed (100 kHz)` + `Warn : To remove this warnings and achieve reasonable communication speed with the target, set "adapter speed" or "jtag_rclk" in the init scripts.`
- 속도 조절이 안 되는 어댑터는 master에서 `Info : Note: The adapter "remote_bitbang" doesn't support configurable speed`, 0.12.0에서 `Info : This adapter doesn't support configurable speed`를 찍는다.
- `adapter list` (master, 실측 xPack): `amt_jtagaccel  { jtag }` 형식으로 줄마다 `<이름 15칸 정렬> { <transport…> }`.
- `transport` 관련 [소스 `M:src/transport/transport.c#L300-L388`]:
  - 목록 헤더 `The following transports are available:` + 탭 들여쓰기.
  - 변경 불가: `Can't change session's transport after the initial selection was made`.
  - 미지원: `Debug adapter doesn't support '%s' transport`.
  - master에서 `transport select` 없이 init하면 `Warn : DEPRECATED: auto-selecting transport "jtag". Use 'transport select jtag' to suppress this message.`
  - 0.12.0은 `Info : only one transport option; autoselect 'jtag'`. 그 뒤 `transport select jtag`를 다시 부르면 `Warn : Transport "jtag" was already selected`.

### 4.3 `init`

- 성공하면 결과는 빈 문자열이고, 진행 상황은 로그로 간다. 두 번째 호출부터는 아무것도 하지 않고 성공한다(`static int initialized; … initialized = 1;`이 **실패 여부와 무관하게 먼저** 설정된다 [소스 `M:src/openocd.c#L108-L182`]).
- [실측 master, noinit 모드] 어댑터 연결 실패 후의 흐름:
  - `catch {init} r` → `1`, `r`는 빈 문자열.
  - 다시 `init` → `b'\x1a'`(성공처럼 보임).
  - `targets` → State `unknown`.
- init 중 대표 로그 [소스 `M:src/jtag/core.c`]:
  ```
  Info : JTAG tap: sim.cpu tap/device found: 0x5ba00477 (mfg: 0x23b (ARM Ltd), part: 0xba00, ver: 0x5)
  ```
  - 형식: `"JTAG tap: %s %16.16s: 0x%08x (mfg: 0x%3.3x (%s), part: 0x%4.4x, ver: 0x%1.1x)"` [`#L1126`]. 가운데 메시지는 `tap/device found`, `UNEXPECTED`, `expected 1 of 2`처럼 16칸 오른쪽 정렬이다.
  - `Error: JTAG scan chain interrogation failed: all ones` / `… all zeroes` 다음에 `Error: Check JTAG interface, timings, target power, etc.` [`#L1118`]. all ones는 보통 타깃 없음/전원 없음/TDO 미연결, all zeroes는 TAP이 리셋에 묶인 경우다(소스 주석).
  - `Warn : AUTO auto0.tap - use "jtag newtap auto0 tap -irlen 4 -expected-id 0x5ba00477"` [`#L1396`]. TAP을 선언하지 않은 체인 탐색에 그대로 쓸 수 있는 힌트다.
  - `Error: <tap>: IR capture error; saw 0x0f not 0x01`, `Error: double-check your JTAG setup (interface, speed, ...)`, `Error: Trying to use configured scan chain anyway...`, `Warn : Bypassing JTAG setup events due to errors`, `Warn : Unexpected idcode after end of chain: 21 0xfffff800`, `Info : TAP auto0.tap does not have valid IDCODE (idcode=0x80000000)`.
  - 타깃 검사 성공은 master에서 `Info : [sim.mem] Examination succeed`. 0.12.0의 mem_ap에서는 출력이 없었다.

### 4.4 `scan_chain`

```python
b'   TapName             Enabled  IdCode     Expected   IrLen IrCap IrMask\n'
b'-- ------------------- -------- ---------- ---------- ----- ----- ------\n'
b' 0 sim.cpu                Y     0x5ba00477 0x5ba00477     4 0x01  0x0f\n'
b' 1 sim.bs                 Y     0x0792603f 0x0792603f     5 0x01  0x03\x1a'
```

- 행 포맷 [소스 `M:src/jtag/tcl.c#L792-L840`]: `"%2u %-18s     %c     0x%08x %s %5u 0x%02x  0x%02x"`
  - 열: 체인 위치, dotted name, `Y`/`n`, 읽은 IDCODE, Expected, IrLen, IrCap, IrMask.
  - `-ignore-version` TAP은 Expected의 버전 니블이 `*`로 바뀐다(`0x*ba00477`).
  - 기대 ID가 여러 개면 다음 줄에 공백 43칸 + `0x%08x`가 이어진다.
- 18자보다 긴 이름은 열을 밀어낸다. **고정 폭이 아니라 공백 분할로 파싱**한다(이름에 공백 없음). 헤더 2줄은 건너뛰고, 공백 43칸으로 시작하는 줄은 직전 TAP의 추가 Expected로 처리한다.
- init 전이나 체인 탐색 실패 시 IdCode는 `0x00000000`이다(noinit 실측).
- dummy 어댑터로 init하면 가짜 `auto0.tap`…`auto19.tap`이 생기고, master에서는 `scan_chain` 실행 시 `buf_get_u32: Assertion 'num >= 1 && num <= 32' failed.`로 **OpenOCD가 abort**했다(§7.1).

### 4.5 `jtag names`, `jtag cget`, `irscan`/`drscan`, `jtag arp_init`

| 명령 | master | 0.12.0 |
|---|---|---|
| `jtag names` | `b'sim.cpu\nsim.bs\x1a'` | `b'sim.cpu sim.bs\x1a'` |
| `jtag cget sim.cpu -idcode` | `b'0x5ba00477\x1a'` | `b'1537213559\x1a'` |
| `jtag tapisenabled sim.cpu` | `b'1\x1a'` | |
| `irscan sim.cpu 0xe` | `b'\x1a'` | `b'\x1a'` |
| `drscan sim.cpu 32 0` (IDCODE IR 후) | `b'5ba00477\x1a'` | |
| `drscan sim.cpu 1 0` (BYPASS IR 후) | `b'00\x1a'` | |
| `drscan sim.cpu 16 0 16 0` | `b'0477\n5ba0\x1a'` | `b'0477 5ba0\x1a'` |
| `jtag arp_init` | `b'\x1a'` (로그로 tap/device found) | |
| `jtag tapdisable sim.cpu` (지원 안 하는 TAP) | `b'failed to disable tap sim.cpu\x1a'` | `b'\x1a'` |

- drscan 필드 값은 `buf_to_hex_str()`의 결과다 [소스 `M:src/jtag/tcl.c#L164`]. `0x` 없이 바이트 단위로 0을 채운 16진수(자릿수 = 2×ceil(bits/8))이고, 필드 순서는 명령 인자 순서(LSB 쪽 필드 먼저)다.
- 매뉴얼 경고: "For portability, never pass fields which are more than 32 bits long."(https://openocd.org/doc/html/JTAG-Commands.html)
- `irscan`은 다른 TAP을 모두 BYPASS로 만든다. `drscan`은 대상 외 TAP이 BYPASS라고 가정한다. **임의 IR(예: EXTEST)은 핀을 실제로 구동할 수 있으니 위험 명령으로 분류한다**(§5).

### 4.6 `targets`, `target names`, `<tgt> curstate`

```python
b'    TargetName         Type       Endian TapName            State       \n'
b'--  ------------------ ---------- ------ ------------------ ------------\n'
b' 0* sim.mem            mem_ap     little sim.cpu            running\x1a'
```

- 헤더 첫 줄은 `State` 뒤에 공백 7칸이 붙어 있다. 행 포맷 [소스 `M:src/target/target.c#L2811-L2848`]: `"%2d%c %-18s %-10s %-6s %-18s %s"`. `*`는 현재 타깃을 뜻한다.
- State 값:
  - `target_state_name()` [`#L271`]: `unknown running halted reset debug-running unavailable`.
  - 검사가 지연된 타깃은 **`examine deferred`(공백 포함)**.
  - TAP이 꺼져 있으면 `tap-disabled`.
  - 그러므로 마지막 열은 5번째 필드 이후 **나머지 전체**로 파싱한다.
- [실측] 상태 변화: init 직후 `running`(mem_ap). `halt` 후 `halted`, `resume` 후 `running`. noinit에서는 `unknown`. xPack mem_ap은 init 직후 `unknown`이었다.
- 기타:
  - `target names` → `b'sim.mem\x1a'`, `target current` → `b'sim.mem\x1a'`.
  - `sim.mem cget -type` → `b'mem_ap\x1a'`, `sim.mem curstate` → `b'halted\x1a'`.
  - 타깃 이름을 접두어로 붙여 쓰는 형태(`sim.mem mdw 0x08000000 2`, `sim.mem read_memory …`)는 현재 타깃과 상관없이 그 타깃에 실행된다.

### 4.7 `halt` / `resume` / `step` / `reset` / `poll`

- RPC 결과는 대부분 **빈 문자열**이다. 상태 메시지는 `LOG_USER`로 로그에만 나간다. 결과로 받으려면 `capture`를 쓴다.
- [실측 master, mem_ap] `halt`, `resume`, `step`, `reset halt`, `reset init`, `reset run`, `reset` 모두 `b'\x1a'`. reset 계열은 로그에 `Info : JTAG tap: … tap/device found: …`가 다시 찍혔다.
- halt 상태 메시지는 `TARGET_EVENT_HALTED` 때 `target_arch_state()`가 찍는다(`verbose_halt_msg`). 코어별 형식 [소스]:
  - **ARM(ARM926EJ-S, ARM1176, Cortex-A 공통)** `arm_arch_state()` [`M:src/target/armv4_5.c#L797-L823`]:
    ```
    [<target>] target halted in <ARM|Thumb|Jazelle|ThumbEE> state due to <debug-reason>, current mode: <mode>
    cpsr: 0x%08x pc: 0x%08x[, semihosting[ fileio]]
    ```
    - 0.12.0은 앞의 `[<target>] `가 없다(`LOG_USER` [`T:src/target/armv4_5.c#L782`]).
    - `<mode>` 값: `User FIQ Supervisor Abort IRQ "Undefined instruction" System "Secure Monitor" Hypervisor …`
    - `<debug-reason>` 값: `debug-request breakpoint watchpoint watchpoint-and-breakpoint single-step target-not-halted program-exit exception-catch undefined` [`M:src/target/target.c#L229`].
  - **ARM926EJ-S** 추가 줄 [`M:src/target/arm926ejs.c#L504`]: `MMU: <enabled|disabled>, D-Cache: <enabled|disabled>, I-Cache: <enabled|disabled>` (`LOG_USER`, 접두어 없음).
  - **ARMv7-A(Cortex-A7)** 추가 줄 [`M:src/target/armv7a.c#L481`]: `[<target>] MMU: …, D-Cache: …, I-Cache: …`. Abort 모드면 폴트 레지스터를 덧붙인다.
  - **MIPS32(mips_m4k)** [`M:src/target/mips32.c#L481`]: `target halted in <MIPS32|MIPS16|MICRO MIPS32> mode due to <debug-reason>, pc: 0x%08x` (`LOG_USER`, master에도 접두어 없음).
  - **Cortex-M**(참고) `armv7m_arch_state()`: `[<t>] halted due to <reason>, current mode: <mode> <exc>\nxPSR: %#8.8x pc: %#8.8x <m|p>sp: %#8.8x`
  - 위 줄들은 소스에서 읽은 형식이다. 실제 ARM/MIPS 코어로 실측하지 못한 값(레지스터 수치 등)은 (미확인)이다.
- 시간 초과와 오류 문자열 [소스 `M:src/target/target.c`]:
  - `Error: timed out while waiting for target halted` (상태 이름이 끝에 들어간다)
  - `Error: [<t>] not examined` (master; 0.12.0은 `Target not examined yet` 계열 (미확인))
  - `Info : Target not halted or running`
- `halt [ms]`: 인자를 생략하면 `wait_halt`로 기본 5000 ms(`DEFAULT_HALT_TIMEOUT`)까지 기다린다. 인자를 주면 그 ms만큼 기다리고, 0이면 기다리지 않는다 [소스 `M:src/target/target.c#L3272`].
- `poll` (인자 없음) [실측]: `b'background polling: on\nTAP: sim.cpu (enabled)\x1a'`. 그 뒤 `target_poll()`과 `target_arch_state()`를 실행하므로 halt 중이면 위 상태 메시지가 **로그로** 찍힌다. `poll off` 후에는 `background polling: off`.

### 4.8 `reg`

[소스 `M:src/target/target.c#L3017-L3155`, 0.12.0 동일 포맷 `T:src/target/target.c#L3103-L3203`]

```
===== <cache name>
(<n>) <reg name> (/<bits>): 0x<hex>[ (dirty)]     ← 캐시 값이 유효할 때
(<n>) <reg name> (/<bits>)                        ← 아직 안 읽은 레지스터
```

- 단일 읽기(`reg pc`, `reg 15`, `reg pc force`) / 쓰기(`reg r0 0x1234`) 성공 시: `<name> (/<bits>): 0x<hex>`.
- `<hex>`는 `buf_to_hex_str(value, size)`의 결과로, 비트 폭에 맞춰 0을 채운다(32비트면 8자리).
- 오류:
  - `register %s not found in current target`
  - `%i is out of bounds, the current target has only %i registers (0 - %i)`
  - `Error: [%s] not examined` (master, `command_print`로 결과에 들어감)
  - 로그 `Could not read register '%s'` / `Could not write to register '%s'`
- [실측] mem_ap는 레지스터 캐시가 없어 `reg` → `b'\x1a'`이다. 실제 코어의 레지스터 목록(ARM `r0`…`pc`, `cpsr`, 모드별 뱅크 등)은 실측하지 못했다(목록은 (미확인), 형식은 위 소스 기준).
- 대안: `get_reg {pc sp}` → Tcl dict(이름-값 쌍). `set_reg {pc 0 sp 0x1000}`은 레지스터를 **쓴다**(위험 등급 R2, §5).

### 4.9 `mdw` / `mdh` / `mdb` / `mdd`

```python
# mdw 0x08000000 8
b'0x08000000: 56190527 6f422d55 3220746f 2e363130 28203131 296d6973 02010000 06050403 \x1a'
# mdw 0x08000000 10   (32바이트마다 줄바꿈)
b'0x08000000: 56190527 6f422d55 3220746f 2e363130 28203131 296d6973 02010000 06050403 \n0x08000020: 0a090807 0e0d0c0b \x1a'
# mdh 0x08000000 8
b'0x08000000: 0527 5619 2d55 6f42 746f 3220 3130 2e36 \x1a'
# mdb 0x08000000 40
b'0x08000000: 27 05 19 56 55 2d 42 6f 6f 74 20 32 30 31 36 2e 31 31 20 28 73 69 6d 29 00 00 01 02 03 04 05 06 \n0x08000020: 07 08 09 0a 0b 0c 0d 0e \x1a'
# mdw phys 0x08000000 2
b'0x08000000: 56190527 6f422d55 \x1a'
# [실측 0.12.0] 같은 명령 → b'0x08000000: … 06050403 \n\x1a'  (끝 공백 뒤에 \n이 하나 더 있음)
```

- 포맷 [소스 `M:src/target/target.c#L3368-L3430`]:
  - 한 줄 32바이트(`line_bytecnt = 32`): word 8개, half 16개, byte 32개, dword 4개.
  - 주소는 `TARGET_ADDR_FMT` = `0x%8.8…`. 64비트 주소면 더 길어진다.
  - 값 포맷: `%16.16`/`%8.8`/`%4.4`/`%2.2` + `PRIx64` + **공백**. 그래서 줄마다 끝에 공백이 하나 있다.
  - 값은 타깃 엔디언으로 해석한 정수다(little 타깃에서 바이트 `27 05 19 56` → word `56190527`).
- 문법: `mdw ['phys'] address [count]` (usage 실측). 실패하면 출력이 없고 rc≠0이다(예: MEM-AP가 크기를 지원하지 않으면 `Error: Size 8 not supported`).
- `flash mdw/mdh/mdb address [count]`도 같은 형식이다(플래시 드라이버 read 경유).
- 파싱 정규식 예: `^(0x[0-9a-f]+): ((?:[0-9a-f]+ )+)$` (줄 단위, `\n`과 끝 공백 허용).

### 4.10 `mww` / `mwh` / `mwb` / `mwd`, `write_memory`, `read_memory`

| 명령 | 응답 |
|---|---|
| `mww 0x20000008 0xcafebabe` | `b'\x1a'` |
| `mwh 0x20000010 0xabcd` / `mwb 0x20000012 0x55` | `b'\x1a'` (이후 `mdw 0x20000010` → `b'0x20000010: 2055abcd \x1a'`) |
| `write_memory 0x20000000 32 {0xdeadbeef 0x12345678}` | `b'\x1a'` |
| `read_memory 0x08000000 32 4` | `b'0x56190527 0x6f422d55 0x3220746f 0x2e363130\x1a'` |
| `read_memory 0x08000000 8 6` | `b'0x27 0x5 0x19 0x56 0x55 0x2d\x1a'` |
| `read_memory 0x08000000 16 3` | `b'0x527 0x5619 0x2d55\x1a'` |
| `read_memory 0x08000000 64 2` (미지원 폭) | `b'failed to read memory\x1a'` + rc≠0 |

- `read_memory` [소스 `M:src/target/target.c#L4477-L4600`]:
  - 원소마다 `"0x%" PRIx64`(**0 패딩 없음**)를 공백 1개로 구분한 Tcl 리스트를 돌려준다.
  - 폭은 8/16/32/64이고, 그 밖이면 `invalid width, must be 8, 16, 32 or 64`.
  - 개수는 최대 65536이고, 넘으면 `too large read request, exceeds 64K elements`(0.12.0: `read_memory: too large read request, exeeds 64K elements` — 철자 그대로).
  - 주소가 0을 넘어 감기면 `memory region wraps over address zero`.
  - 4번째 인자는 `phys`만 허용하며, 아니면 `invalid argument '%s', must be 'phys'`.
- `write_memory address width data ['phys']`의 `data`는 Tcl 리스트다. 성공 시 결과는 비어 있다.
- 0.11.0에는 두 명령이 **없다**. 대신 `mem2array arr 32 0x08000000 4`(결과 빈 문자열)를 쓰고 `array get arr`로 읽는다. [실측 0.11.0] `b'0 1444480295 1 1866607957 2 840987759 3 775303472\x1a'`(인덱스-10진값 쌍).
- 큰 덤프에는 `read_memory` 대신 `dump_image`를 쓴다. 텍스트 변환 비용이 크다.

### 4.11 `dump_image` / `load_image` / `verify_image` / `verify_image_checksum` / `test_image`

```python
# dump_image /tmp/dump.bin 0x08000000 0x100
b'dumped 256 bytes in 0.011000s (22.727 KiB/s)\x1a'
# load_image /tmp/blob.bin 0x20000000 bin
b'256 bytes written at address 0x20000000\ndownloaded 256 bytes in 0.011000s (22.727 KiB/s)\x1a'
# verify_image /tmp/blob.bin 0x20000000 bin   (일치)
b'verified 256 bytes in 0.011000s (22.727 KiB/s)\x1a'
# verify_image /tmp/blob.bin 0x20000100 bin   (불일치, rc≠0)
b'diff 0 address 0x20000101. Was 0x01 instead of 0x07\ndiff 1 address 0x20000102. Was 0x00 instead of 0x0e\n…\ndiff 127 address 0x20000181. Was 0x01 instead of 0x87\nMore than 128 errors, the rest are not printed.\x1a'
#   로그: Error: checksum mismatch - attempting binary compare
# verify_image_checksum (불일치) → b'\x1a', rc≠0, 로그: Error: checksum mismatch
```

- 문법(매뉴얼, https://openocd.org/doc/html/General-Commands.html):
  - `dump_image filename address size`
  - `load_image filename [address [bin|ihex|elf|s19 [min_addr [max_length]]]]`
  - `verify_image filename [address [bin|ihex|elf]]`
  - `verify_image_checksum …`
  - `test_image …`
  - 이미지 타입 문자열(소스 `src/target/image.c`)은 `bin ihex elf mem s19 build`.
- 포맷 [소스 `M:src/target/target.c#L3636-L3925`]:
  - `"dumped %zu bytes in %fs (%0.3f KiB/s)"`
  - `"%u bytes written at address " TARGET_ADDR_FMT` (섹션마다 한 줄)
  - `"downloaded %" PRIu32 " bytes in %fs (%0.3f KiB/s)"`
  - `"verified %" PRIu32 " bytes in %fs (%0.3f KiB/s)"`
  - `"diff %d address " TARGET_ADDR_FMT ". Was 0x%02x instead of 0x%02x"`
  - 128개를 넘으면 `More than 128 errors, the rest are not printed.`, 128개 이하로 끝나면 `No more differences found.`
- 속도 값은 시간이 0이면 0.12.0에서 `inf KiB/s`가 찍혔다. 숫자를 파싱하지 않는다.
- `dump_image`의 `filename`은 **OpenOCD 프로세스의 작업 디렉터리 기준 호스트 경로**다. MCP는 절대경로로 케이스 디렉터리 안만 허용한다(§5).
- `verify_image`는 타깃 측 CRC(`checksum_memory`, 보통 working area 필요)를 먼저 쓴다.
  - master는 지원하지 않는 타깃에서 `Info : [sim.mem] doesn't support fast checksum_memory, using slow read memory`를 찍고 호스트에서 계산한다.
  - xPack(2025-10)은 `Error: Target sim.mem doesn't support checksum_memory`로 실패했다.
  - 0.11.0은 mem_ap 대상 `verify_image`에서 프로세스가 종료됐다(EOF). 버전과 타깃에 따라 결과가 다르므로, 덤프 무결성은 **같은 범위를 두 번 덤프해 호스트에서 해시 비교**하는 방식을 권장한다.

### 4.12 `flash` 명령

출처: [소스 `M:src/flash/nor/tcl.c`], 실측은 faux 드라이버(`flash bank sim.flash faux 0x08000000 0x40000 0 0 sim.mem`).

- faux 드라이버는 쓰기와 지우기를 호스트 메모리에서 하고, 읽기는 `default_flash_read`(타깃 메모리 읽기)로 한다 [소스 `M:src/flash/nor/faux.c`]. 그래서 쓴 뒤 verify가 실패하는 것은 정상이다.

```python
# flash banks
b'#0 : sim.flash (faux) at 0x08000000, size 0x00040000, buswidth 0, chipwidth 0\x1a'
# flash list  (master)
b'{\n    name       {sim.flash}\n    driver     faux\n    base       0x08000000\n    size       0x40000\n    bus_width  0\n    chip_width 0\n    target     sim.mem\n}\x1a'
# flash list  (xPack: name 중괄호 없음)
b'{\n    name       sim.flash\n    driver     faux\n    base       0x08000000\n    size       0x40000\n    bus_width  0\n    chip_width 0\n    target     sim.mem\n}\x1a'
# flash list  (0.12.0: 한 줄 Tcl dict, 10진수)
b'{name sim.flash driver faux base 134217728 size 262144 bus_width 0 chip_width 0 target sim.mem}\x1a'
# flash info 0   (flash info sim.flash sectors 도 동일; 로그: Info : Flash protection check is not implemented.)
b'#0 : faux at 0x08000000, size 0x00040000, buswidth 0, chipwidth 0\n\t#  0: 0x00000000 (0x10000 64kB) not protected\n\t#  1: 0x00010000 (0x10000 64kB) not protected\n\t#  2: 0x00020000 (0x10000 64kB) not protected\n\t#  3: 0x00030000 (0x10000 64kB) not protected\nfaux flash driver\x1a'
# flash probe 0
b"flash 'faux' found at 0x08000000\x1a"
# flash read_bank 0 /tmp/rb.bin 0 0x40
b'wrote 64 bytes to file /tmp/rb.bin from flash bank 0 at offset 0x00000000 in 0.003000s (20.833 KiB/s)\x1a'
# flash read_bank sim.flash /tmp/rb2.bin 0x100 0x20   (뱅크 이름도 가능)
b'wrote 32 bytes to file /tmp/rb2.bin from flash bank 0 at offset 0x00000100 in 0.002000s (15.625 KiB/s)\x1a'
# flash verify_bank 0 /tmp/rb.bin 0
b'read 64 bytes from file /tmp/rb.bin and flash bank 0 at offset 0x00000000 in 0.003000s (20.833 KiB/s)\ncontents match\x1a'
# flash verify_bank (불일치, rc≠0)
b'read 256 bytes from file /tmp/blob.bin and flash bank 0 at offset 0x00000000 in 0.011000s (22.727 KiB/s)\ncontents differ\ndiff 0 address 0x00000000. Was 0x27 instead of 0x00\n…'
# flash erase_sector 0 0 1  /  flash erase_sector 0 0 last
b'erased sectors 0 through 1 on flash bank 0 in 0.000000s\x1a'
b'erased sectors 0 through 3 on flash bank 0 in 0.000000s\x1a'
# flash erase_address 0x08000000 0x10000
b'erased address 0x08000000 (length 65536) in 0.000000s (64000.000 KiB/s)\x1a'
# flash protect 0 0 1 on   (드라이버 미지원, rc≠0, 로그: Error: Flash protection is not supported)
b'failed to set protection\x1a'
# flash write_image erase /tmp/blob.bin 0x08000000 bin   (섹터 단위 패딩 때문에 65536)
b'auto erase enabled\nwrote 65536 bytes from file /tmp/blob.bin in 0.000000s (64000.000 KiB/s)\x1a'
# flash write_bank 0 /tmp/blob.bin 0x100
b'wrote 256 bytes from file /tmp/blob.bin to flash bank 0 at offset 0x00000100 in 0.000000s (250.000 KiB/s)\x1a'
# flash erase_check 0  (실패 시; xPack은 앞부분이 'unknown error when checking erase state of flash bank #0 at 0x08000000')
b'Error: checking erase state of flash bank #0 at 0x08000000\n\t#  0: 0x00000000 (0x10000 64kB) not erased\n\t#  1: 0x00010000 (0x10000 64kB) not erased\n\t#  2: 0x00020000 (0x10000 64kB) not erased\n\t#  3: 0x00030000 (0x10000 64kB) not erased\x1a'
```

포맷 문자열 [소스]:

| 명령 | 포맷 |
|---|---|
| `flash banks` [`#L1473`] | `"#%d : %s (%s) at " TARGET_ADDR_FMT ", size 0x%8.8x, buswidth %u, chipwidth %u"` (번호, 이름, 드라이버) |
| `flash info` [`#L58`] | 헤더 `"#%u : %s at " TARGET_ADDR_FMT ", size 0x%8.8x, buswidth %u, chipwidth %u"` (드라이버 이름), 섹터 `"\t#%3i: 0x%8.8x (0x%x %ukB) %s"`. 상태 문자열은 `not protected`/`protected`/`protection state unknown`. 마지막에 드라이버 고유 정보 |
| `flash probe` [`#L152`] | `"flash '%s' found at " TARGET_ADDR_FMT`. 범위 밖이면 `"flash bank '#%s' is out of bounds"` |
| `flash erase_sector` [`#L302`] | `"erased sectors %u through %u on flash bank %u in %fs"`. 오류: `ERROR: first sector must be <= last`, `ERROR: last sector must be <= %u`, `erase operation is not supported`, `failed to erase sectors` |
| `flash erase_address [pad] [unlock] addr len` [`#L232`] | `"erased address " TARGET_ADDR_FMT " (length %u) in %fs (%0.3f KiB/s)"`. 오류: `Length must be >0`, `erase operation failed` |
| `flash protect num first last on|off` [`#L364`] | `"%s protection for %s %u through %u on flash bank %d"` (set/cleared, sectors/blocks). 오류: `failed to %s protection` |
| `flash write_image [erase] [unlock] file [offset] [type]` [`#L424`] | 앞에 `auto erase enabled`/`auto unlock enabled` 줄, 이어서 `"wrote %u bytes from file %s in %fs (%0.3f KiB/s)"` |
| `flash write_bank num file [offset]` [`#L883`] | `"wrote %zu bytes from file %s to flash bank %u at offset 0x%8.8x in %fs (%0.3f KiB/s)"` |
| `flash read_bank num file [offset [length]]` [`#L998`] | `"wrote %zd bytes to file %s from flash bank %u at offset 0x%8.8x in %fs (%0.3f KiB/s)"`. 메시지의 `wrote`는 **호스트 파일에 썼다**는 뜻이다 |
| `flash verify_bank num file [offset]` [`#L1078`] | `"read %zd bytes from file %s and flash bank %u at offset 0x%8.8x in %fs (%0.3f KiB/s)"` 다음 줄 `contents match`/`contents differ`, 차이는 `"diff %d address 0x%08x. Was 0x%02x instead of 0x%02x"` |
| `flash fill{w,h,b,d} addr pattern count` | 성공 `"wrote %u bytes to " TARGET_ADDR_FMT " in %fs (%0.3f KiB/s)"`. 검증 실패는 로그 `Verification error address …, read back 0x…, expected 0x…` |
| `flash erase_check num` | 성공 `successfully checked erase state` + 지워지지 않은 섹터 목록. 모두 지워졌으면 `\tBank is erased` |

`flash read_bank` 의미 [소스 `#L998-L1076`, 매뉴얼 https://openocd.org/doc/html/Flash-Commands.html]:

- `offset`은 **뱅크 시작 기준 오프셋**이다(절대 주소 아님). 생략하면 0이다.
- `length`를 생략하면 `bank->size - offset`이다.
- `offset > size`이면 로그 `Offset 0x%8.8x is out of range of the flash bank`, `offset+length > size`이면 로그 `Length of %u bytes with offset 0x%8.8x is out of range of the flash bank`. 둘 다 결과는 빈 문자열이고 rc≠0이다.
- `num`은 `flash banks`의 번호 또는 뱅크 이름이다(실측).

`flash write_image erase`는 이미지가 덮는 섹터 전체, 그리고 이미지 섹션 사이의 구멍까지 지울 수 있다. 매뉴얼의 Warning: "Portions of the flash outside those described in the image's sections might be erased with no notice."

`program filename [preverify] [verify] [reset] [exit] [offset]` (Tcl proc, [소스 `M:src/flash/startup.tcl#L21`]):

- 내부에서 `init`, `reset init`, `flash write_image erase …`, `verify_image`, `reset run`, `shutdown`(exit 옵션)을 실행한다.
- 로그(echo) 문자열: `** Programming Started **`, `** Programming Finished **`, `** Verify Started **`, `** Verified OK **`, `** Resetting Target **`, `**pre-verifying**`, `**Verified OK - No flashing**`.
- 실패 문자열: `** OpenOCD init failed **`, `** Unable to reset target **`, `** Programming Failed **`, `** Verify Failed **`.

### 4.13 `bp` / `wp` (소스 기준, 미실측)

[소스 `M:src/target/target.c#L3975-L4140`]

- 설정 성공: `breakpoint set at 0x%08…`, `Context breakpoint set at 0x%8.8x`, `Hybrid breakpoint set at 0x%8.8x`.
- 목록:
  - `Software breakpoint(IVA): addr=0x…, len=0x%x, orig_instr=0x…`
  - `Hardware breakpoint(IVA): addr=0x…, len=0x%x, num=%u`
  - `address: 0x…, len: 0x%8.8x, r/w/a: <r|w|a>, value: 0x%8.8…, mask: 0x%8.8…` (wp)

### 4.14 로그 줄 형식 (stderr / `-l` 파일)

[소스 `M:src/helper/log.c#L40`]

- 레벨 접두어: `"User : "`, `"Error: "`, `"Warn : "`, `"Info : "`, `"Debug: "`.
  - `-d2` 이하에서는 USER 레벨(`echo`, halt 상태 메시지, `shutdown command invoked` 등)에 접두어를 붙이지 않는다.
- `-d3` 이상에서는 모든 레벨이 `<접두어><count> <ms> <file>:<line> <func>(): <msg>` 형식으로 바뀐다(예: `Debug: 123 456 core.c:1118 jtag_examine_chain_check(): …`). 로그 파서는 두 형식을 모두 처리한다.
- 시작 배너(master) [실측]:
  ```
  Open On-Chip Debugger 0.12.0+dev-02761-gbb5a52da (2026-10-18-06:21)
  Licensed under GNU GPL v2
  For bug reports, read
  	http://openocd.org/doc/doxygen/bugs.html
  ```

---

## 5. 안전 게이트용 명령 위험도 분류

### 5.1 분류표

| 등급 | 명령(대표) | 비고 |
|---|---|---|
| **R0 조회(타깃 무영향)** | `version`, `adapter name`, `adapter speed`(인자 없음), `adapter list`, `transport list`, `transport select`(인자 없음), `jtag names`, `jtag cget`, `jtag tapisenabled`, `scan_chain`, `targets`(인자 없음), `target names`, `target current`, `<tgt> curstate`, `<tgt> cget`, `flash banks`, `flash list`, `dap names`, `help`, `usage`, `debug_reason` | |
| **R1 읽기(타깃 메모리/레지스터 읽음)** | `mdw/mdh/mdb/mdd`, `read_memory`, `<tgt> mdw…`, `reg`(목록/읽기), `get_reg`, `poll`(인자 없음), `flash info`, `flash probe`, `flash mdw…`, `flash read_memory`, `flash verify_bank`, `flash verify_image`, `verify_image`, `verify_image_checksum`, `test_image`, `dap info`, `virt2phys` | MMIO를 읽으면 부작용이 생길 수 있다(FIFO/상태 레지스터 read-to-clear). 허용 범위를 RAM/플래시 창으로 제한하고, 그 밖은 R2로 올린다 |
| **R1h 읽기 + 호스트 파일 쓰기** | `dump_image`, `flash read_bank`, `log_output` | 경로는 OpenOCD 작업 디렉터리 기준이다. MCP가 절대경로를 만들고 케이스 디렉터리 밖은 거부한다. 덮어쓰기를 방지한다 |
| **R2 휘발성 상태 변경** | `halt`, `resume`, `step`, `reset [run|halt|init]`, `soft_reset_halt`, `wait_halt`, `<tgt> arp_*`, `reg <name> <value>`, `set_reg`, `bp`/`rbp`/`wp`/`rwp`, RAM 범위의 `mww/mwh/mwb/mwd`, `write_memory`, `load_image`, `adapter speed <khz>`, `adapter assert/deassert srst|trst`, `poll on|off`, `targets <name>`(현재 타깃 변경), `jtag arp_init`, `jtag arp_init-reset`, `jtag tapenable/tapdisable`, `init` | 전원을 껐다 켜면 사라지지만 기기 동작을 멈추거나 바꾼다. 실행 전 사용자 확인 옵션 대상이다 |
| **R3 JTAG 저수준(핀 구동 가능)** | `irscan`, `drscan`, `runtest`, `pathmove`, `tms_sequence`, `jtag drscan`, `svf`, `xsvf` | 임의 IR(EXTEST 등)은 바운더리 스캔 셀로 **핀을 실제로 구동**해 주변 회로를 손상시킬 수 있다. `svf`/`xsvf`는 CPLD/FPGA/플래시를 **영구 프로그래밍**할 수 있으므로 R4로 취급한다 |
| **R4 파괴적·영구** | `flash write_image`, `flash write_bank`, `flash erase_sector`, `flash erase_address`, `flash fill{w,h,b,d}`, `flash protect`, `flash padded_value`(설정), `program`, `nand erase/write/raw_access`, `pld load`, MMIO 범위(플래시·eFuse·OTP 컨트롤러)에 대한 `mww`/`write_memory`, 드라이버별 명령 아래 참조 | 되돌릴 수 없거나 벽돌(brick)이 될 수 있다. 기본 거부, 명시적 이중 확인 |
| **R5 호스트/인터프리터 탈출** | `exec`, `open`, `file`, `socket`, `popen`, `pipe`, `os.fork`, `load`, `package`, `source`, `script`, `cd`, `pwd`, `glob`, `readdir`, `kill`, `signal`, `exit`, `shutdown`, `bindto`, `tcl port`/`telnet port`/`gdb port`, `add_script_search_dir`, `debug_level`, `log_output` | [실측] 4개 빌드 모두 `exec open socket popen os.fork file source load`가 있다. master의 `interface/raspberrypi-native.cfg`는 스스로 `exec vcgencmd measure_clock arm`을 호출한다 |

**드라이버별 영구 명령**(소스 grep, `src/flash/nor/*.c`, `src/target/**`):

- `mass_erase`: 23개 드라이버.
- `lock`/`unlock`: 8개. 예: STM32 RDP는 해제할 때 전체 소거가 일어난다.
- 옵션바이트 쓰기:
  - `stm32f1x options_write`, `stm32f2x options_write`, `str9xpec options_write`
  - `stm32f2x optcr2_write`
  - `stm32l4x option_write`, `stm32h7x option_write`
- OTP:
  - `stm32f2x otp`, `stm32l4x otp`
  - `ambiqmicro program_otp`
- 보안·JTAG 잠금(되돌릴 수 없는 것 포함):
  - `at91sam3/at91sam4/at91sam7/atsamv gpnvm`
  - `lpc2900 secure_sector`/`secure_jtag`/`password`
  - `str7x disable_jtag`
  - `efm32 debuglock`
  - `xmc4xxx flash_password`
- 사용자·부트 영역:
  - `kinetis fcf_source`
  - `atsame5 userpage`/`bootloader`
  - `at91samd nvmuserrow`/`eeprom`/`bootloader`/`chip_erase`
- 기타:
  - `niietcm4 service_mode_erase`/`uflash_full_erase`
  - `numicro write_isp`/`chip_erase`
  - `riscv authdata_write`/`dmi_write`/`dm_write`
- 카메라 SoC(HiSilicon/Ingenic/SigmaStar)에는 eFuse/OTP 전용 OpenOCD 명령이 없다(소스 grep 결과 없음). 현실적인 위험 경로는 **eFuse/OTP 컨트롤러 MMIO에 대한 `mww`/`write_memory`**다. MMIO 쓰기는 주소 허용목록으로만 허용한다.

### 5.2 정적 분류를 어렵게 만드는 Tcl 요소

- 명령 치환 `[ … ]`, 변수 치환 `$x`, `${x}`, `$::x`, 확장 `{*}`, 문장 구분 `;`와 개행, 주석 `#`, 백슬래시 이스케이프, 큰따옴표 안의 치환.
- 동적 실행: `eval`, `uplevel`, `upcall`, `subst`, `apply`, `lambda`, `tailcall`, `try`, `catch`(본문 실행), `capture`(본문 실행), `after`, `vwait`, `time`, `timerate`, `foreach`/`while`/`for`/`if`/`switch`의 본문.
- 정의와 재정의: `proc`, `rename`, `alias`, `local`, `defer`, `namespace`, `interp`.
  - 예: `rename mww safe_name` 뒤에 `safe_name …`을 부르면 이름 기반 필터를 우회한다.
- 지연 실행:
  - `<tgt> configure -event <event> <script>`: reset/halt 등 이벤트 때 스크립트가 실행된다.
  - `<tgt> invoke-event`, `jtag configure <tap> -event …`, `$_TARGETNAME configure -event reset-init {...}`(설정 파일이 흔히 씀).
  - `lappend post_init_commands …`, `pre_shutdown_commands`.
- 별칭과 접두어 형태:
  - 타깃 이름 접두어(`sim.mem mww …`).
  - `flash`/`nand` 하위 명령, 드라이버 그룹 명령(`stm32f1x …`).
  - deprecated 밑줄형 proc(`tcl_port` 등), `ocd_*` proc.
- 설정 파일 자체가 코드다. `-f`로 읽는 cfg도 위 모든 요소를 쓸 수 있다.

### 5.3 권장 정책

1. MCP 도구는 **타입이 있는 고수준 도구**로 노출하고, 내부에서 허용목록으로 명령 문자열을 만든다. 예: `read_memory(addr:int, width:8|16|32|64, count:int)`, `dump_image(range, case_path)`, `halt()`, `scan_chain()`.
2. 인자는 정규식으로 검증한다(숫자, 16진, 단순 식별자, 케이스 디렉터리의 절대경로). `[]{}$;"\\#`, 개행, 0x1a, 공백이 들어간 토큰은 거부한다.
3. 원시 Tcl 도구(`openocd_raw`)를 둔다면 기본으로 끄고, 켜면 매번 사용자 확인을 받으며 전체 스크립트를 로그에 남긴다.
4. 쓰기는 케이스별로 선언한 **RAM 범위**에서만 자동 허용한다. 플래시·MMIO 쓰기는 R4 확인 절차를 거친다.
5. TCL/telnet/gdb 포트는 루프백만 쓴다. 쓰지 않는 서비스는 `disabled`로 둔다(§6.2).
6. 사용자 cfg 파일은 내용을 검토한 뒤에만 로드한다. `exec`, `-event`, `flash`/`program`/`mww` 등 위험 토큰을 grep해 경고한다.

---

## 6. OpenOCD 기동 (명령행)

### 6.1 옵션

[실측 `openocd --help`, 0.11.0/0.12.0/master 동일]

```
--help       | -h	display this help
--version    | -v	display OpenOCD version
--file       | -f	use configuration file <name>
--search     | -s	dir to search for config files and scripts
--debug      | -d	set debug level to 3
             | -d<n>	set debug level to <level>
--log_output | -l	redirect log output to file <name>
--command    | -c	run <command>
```

- `-f`와 `-c`는 **적힌 순서대로** 설정 단계(COMMAND_CONFIG)에서 실행된다.
- 모두 끝나면 `noinit`을 쓰지 않은 한 자동으로 `init`이 실행된다. 이어서 서버 루프가 돈다 [소스 `M:src/openocd.c#L288-L320`].
- 디버그 레벨(매뉴얼 `debug_level`, https://openocd.org/doc/html/General-Commands.html):
  - "Level 0 is error messages only; level 1 adds warnings; level 2 adds informational messages; level 3 adds debugging messages; level 4 adds verbose low-level debug messages; and level 5 adds USB communication messages and amount of free heap space if mallinfo is available. The default is level 2"
  - `-d`만 쓰면 3이다. MCP 운용은 `-d2`, 문제를 분석할 때는 `-d3`.
- `-l file`을 쓰면 로그가 파일로만 간다. 쓰지 않으면 stderr로 간다.
  - 런처가 stderr를 파이프로 받는다면 **별도 스레드로 계속 비워야** 한다. 파이프 버퍼(보통 64 KiB)가 차면 OpenOCD가 막힌다.
- 대부분의 어댑터에서 `adapter speed`는 kHz 단위다. 명령 순서는 `interface cfg` → `transport select` → `adapter speed` → `target cfg`가 안전하다.
  - target cfg가 스스로 `adapter speed`를 바꾸기도 한다(예: `tcl/target/at91sam9.cfg`의 `adapter speed 3`). 나중에 실행된 값이 이긴다.

### 6.2 서버 포트 지정 (버전 호환)

- master: `tcl port 6666`, `gdb port disabled`, `telnet port disabled`.
- 0.11/0.12.0: `tcl_port 6666`, `gdb_port disabled`, `telnet_port disabled`.
  - master의 밑줄형은 deprecated proc이라 동작하지만 로그에 `DEPRECATED! use 'tcl port' not 'tcl_port'`를 찍는다 [소스 `M:src/server/startup.tcl#L100`].
  - 이 proc은 `tcl port` 체계를 도입한 커밋 `73b15194`(2024-07-13 "server/tcl: Restructure commands") 이후에 생겼다.
- **이식형**(0.12.0, master에서 실측 검증):
  ```tcl
  if {[catch {tcl port 6666}]} {tcl_port 6666}
  if {[catch {gdb port disabled}]} {gdb_port disabled}
  if {[catch {telnet port disabled}]} {telnet_port disabled}
  ```
- 명령행 예:
  ```sh
  openocd -s /usr/share/openocd/scripts \
    -f interface/ftdi/tigard.cfg \
    -c "transport select jtag" \
    -c "adapter speed 1000" \
    -f target/at91sam9.cfg \
    -c "if {[catch {tcl port 6666}]} {tcl_port 6666}" \
    -c "if {[catch {gdb port disabled}]} {gdb_port disabled}" \
    -c "if {[catch {telnet port disabled}]} {telnet_port disabled}" \
    -d2
  ```
  - 위 `target/at91sam9.cfg`는 ARM926EJ-S 템플릿 예시일 뿐이다. 카메라 SoC용은 §9 참고.
  - SWD 어댑터는 `transport select swd`.

### 6.3 기동 로그 예

[실측 master, remote_bitbang 시뮬레이터, §7.2 설정]

```
Open On-Chip Debugger 0.12.0+dev-02761-gbb5a52da (2026-10-18-06:21)
Licensed under GNU GPL v2
For bug reports, read
	http://openocd.org/doc/doxygen/bugs.html
Warn : [sim.dap] DEPRECATED! '-chain-position' will be removed in the future, use '-tap' instead
Info : Listening on port 6666 for tcl connections
Info : telnet server disabled
Info : Initializing remote_bitbang driver
Info : Connecting to 127.0.0.1:3335
Info : remote_bitbang driver initialized
Info : Note: The adapter "remote_bitbang" doesn't support configurable speed
Info : JTAG tap: sim.cpu tap/device found: 0x5ba00477 (mfg: 0x23b (ARM Ltd), part: 0xba00, ver: 0x5)
Info : JTAG tap: sim.bs tap/device found: 0x0792603f (mfg: 0x01f (Atmel), part: 0x7926, ver: 0x0)
Info : [sim.mem] Examination succeed
Info : [sim.mem] gdb port disabled
Info : accepting 'tcl' connection on tcp/6666
...
Info : dropped 'tcl' connection
shutdown command invoked
Info : remote_bitbang interface quit
```

[실측 master] init 실패(어댑터 연결 불가) → **프로세스 종료코드 1**:

```
Info : Listening on port 6666 for tcl connections
Info : telnet server disabled
Info : Initializing remote_bitbang driver
Info : Connecting to 127.0.0.1:3335
Error: Error on socket 'Failed to connect': errno==9, message: Bad file descriptor.
```

- 실제 FTDI 어댑터가 없을 때의 메시지(예: `Error: unable to open ftdi device with description '*', serial '*' at bus location '*'`)는 실측하지 않았다 (미확인).

[실측 0.12.0] 설정 파일 오류(`tcl port`를 0.12.0에서 사용):

```
/path/cfgS.cfg:10: Error: invalid command name "tcl"
in procedure 'script'
at file "embedded:startup.tcl", line 28
at file "/path/cfgS.cfg", line 10
```
이 경우 서버를 열기 전에 종료한다.

### 6.4 준비 완료 판정 알고리즘

`server_init()`(TCL 리스닝)이 `init`보다 먼저 실행된다 [소스 `M:src/openocd.c#L304-L312`]. 그래서 "Listening" 줄이 찍혔다고 준비된 것이 아니다. connect()는 성공해도 init이 끝나야 응답이 온다.

1. 프로세스를 시작하고 stderr(또는 `-l` 파일)를 줄 단위로 읽는다.
2. `^Info : Listening on port (\d+) for tcl connections$`를 찾아 실제 포트를 얻는다(포트 0일 때 필수).
3. 접속한 뒤 봉투로 `version`을 보낸다. 타임아웃은 init 시간을 포함해 넉넉히(예: 30–60초) 잡는다.
4. 그 사이 **프로세스 종료를 감시**한다. 종료하면 실패이고, 종료코드(실측: init 실패 1)와 로그 꼬리를 보고한다.
5. 응답 `0 Open On-Chip Debugger …`를 받으면 준비 완료다. 로그에는 `Info : accepting 'tcl' connection on tcp/<port>`가 찍힌다.
6. 이어서 `scan_chain`, `targets`로 TAP 검출과 타깃 상태를 기록한다. 검출이 안 되면 `JTAG scan chain interrogation failed` 등 로그를 근거로 배선·전원·속도 점검을 안내한다.

#### 6.4.1 pipe 준비 확인

2026-10-22, xPack Windows `0.12.0-7`의 dummy/testee + `noinit`에서 별도 동의 후 확인했다. 공식 ZIP의 SHA-256은 `6bfd3c97135aafef8affc9af1acf34fd0e2b9ca26044506f6abd7f95b7630052`이며 [고정 릴리스 메타데이터](https://github.com/xpack-dev-tools/openocd-xpack/blob/v0.12.0-7.1/package.json)에 기록되어 있다. payload의 `bin`과 `scripts`를 함께 사용한다.

- `tcl port pipe`, telnet/GDB disabled로 시작하고 stdout은 RPC, stderr는 진단으로 따로 읽는다. `version` 봉투를 한 번 보내고, 같은 deadline 안에서 완결된 `Info : accepting 'tcl' connection from pipe` 줄과 정상 version 응답을 모두 확인한다.
- 연결 진단을 먼저 기다리면 안 된다. [고정 소스의 서버 루프](https://github.com/openocd-org/openocd/blob/e5888bda38f4952e2ae92f7dc5b25fc9a2d1c2b3/src/server/server.c)는 stdin이 읽기 가능한 상태가 되어야 pipe 연결을 만든다. 실제 출력에도 `tcl` 둘레의 작은따옴표가 있다.
- 이 시험에서 version 응답은 `0.12.0+dev-02228-ge5888bda3-dirty`였고 stdin EOF 뒤 종료 코드 0과 해당 Windows 프로세스 부재를 확인했다. `shutdown`·Ctrl-C·실제 어댑터 초기화는 시험하지 않았다. Linux wrapper의 종료만으로 Windows 자식 종료를 확정하지 않는다.
- 저장소 P3-A는 이 순서를 합성 pipe 자식으로 회귀 검증한다. Linux 내부 owner와 운영 TCP 세션은 별개이며, pipe 준비 성공은 semihosting 검증이나 하드웨어 준비 성공을 뜻하지 않는다.

### 6.5 `noinit` 전략 (선택)

- `-c noinit`으로 띄우면 init 전에 서버 루프가 돌고, 설정 명령(`adapter speed`, `jtag newtap` 등)을 RPC로 조정할 수 있다.
- RPC로 `init`을 호출하면 그 실패를 봉투로 받는다. 단, **init은 프로세스당 한 번만 실제로 실행**된다. 실패하면 재시작해야 한다(§4.3).
- init 전에는 타깃 명령(`mdw`, `halt`, `mww` 등)이 등록되지 않아 `invalid command name "mdw"`가 나온다 [실측]. `target init` 단계에서 등록되기 때문이다.

### 6.6 종료

- 정상 종료: RPC로 `shutdown` → 응답 `\x1a` 후 EOF, 프로세스 종료코드 0.
- 대안은 SIGTERM/SIGINT다. [실측 master] SIGTERM을 받으면 로그에 `shutdown command invoked`, `Info : remote_bitbang interface quit`를 찍어 정리한 뒤 같은 시그널로 다시 종료한다(셸 종료코드 143 = 128+15; `exit_on_signal()` [소스 `M:src/server/server.c`]).

---

## 7. 하드웨어 없이 OpenOCD 실행 (통합 테스트)

### 7.1 dummy 어댑터 — 명령 표면 테스트용 (`noinit` 필수)

[실측] 동작하는 설정(0.12.0/master 공통):

```tcl
adapter driver dummy
adapter speed 1000
jtag newtap tst cpu -irlen 4 -expected-id 0x5ba00477
target create tst.cpu testee -chain-position tst.cpu
if {[catch {tcl port 6666}]} {tcl_port 6666}
if {[catch {gdb port disabled}]} {gdb_port disabled}
if {[catch {telnet port disabled}]} {telnet_port disabled}
noinit
```

- `testee`는 테스트용 더미 타깃이다(poll/halt/reset만 구현, 메모리 접근 없음).
- OpenOCD 자체 회귀 테스트도 dummy와 init 없는 설정을 쓴다(`testing/tcl_commands/test-target-create-command.cfg`: `adapter driver dummy` / `jtag newtap tap cpu -irlen 5`).
- noinit 상태 [실측 master]:
  - 잘 되는 것: `version`, `scan_chain`(IdCode `0x00000000`), `targets`(State `unknown`), `jtag names`, `transport select`, `adapter name`(`dummy`), `adapter speed`, `tcl port`/`tcl_port`, 오류·catch·capture 동작 확인.
  - 안 되는 것: `mdw`, `halt`, `mww`는 `invalid command name`.
- **dummy로 init하면 안 된다.** dummy는 TDO로 처음 32비트는 0, 이후는 영원히 1을 낸다(`dummy_data = (dummy_data >> 1) | (1 << 31)` [소스 `M:src/jtag/drivers/dummy.c#L25`]; 주석 "used to easily check the code path where the target is unresponsive").
  - 그 결과 `Info : TAP auto0.tap does not have valid IDCODE (idcode=0x80000000)` … `auto19.tap`, `Warn : Unexpected idcode after end of chain: 21 0xfffff800`, `Error: tst.cpu: IR capture error; saw 0x0f not 0x01`이 찍힌다.
  - master에서는 그 뒤 `scan_chain` 실행 시 `buf_get_u32: Assertion 'num >= 1 && num <= 32' failed.`로 프로세스가 abort(종료코드 134)했다.

### 7.2 remote_bitbang + 시뮬레이터 — 실제 init·메모리·플래시 경로 테스트

[실측] master/xPack용 설정:

```tcl
adapter driver remote_bitbang
remote_bitbang host 127.0.0.1
remote_bitbang port 3335
transport select jtag
jtag newtap sim cpu -irlen 4 -ircapture 0x1 -irmask 0xf -expected-id 0x5ba00477
jtag newtap sim bs -irlen 5 -expected-id 0x0792603f
dap create sim.dap -chain-position sim.cpu
target create sim.mem mem_ap -dap sim.dap -ap-num 0
flash bank sim.flash faux 0x08000000 0x40000 0 0 sim.mem
tcl port 6666
gdb port disabled
telnet port disabled
```

- 0.12.0: 마지막 세 줄을 §6.2의 이식형으로 바꾼다.
- 0.11.0: 추가로 `remote_bitbang_host 127.0.0.1` / `remote_bitbang_port 3335`를 쓴다(0.11에는 `remote_bitbang host` 형태가 없다 [소스 v0.11.0 `src/jtag/drivers/remote_bitbang.c`]).
- `jtag newtap … bs`는 다중 TAP 출력을 보이려고 넣은 두 번째 TAP이다. 시뮬레이터를 `--tap1-id 0`으로 띄우면 이 줄을 뺀다.

remote_bitbang 프로토콜(ASCII, 1바이트 명령) [소스 `M:src/jtag/drivers/remote_bitbang.c#L150-L280`, 매뉴얼 https://openocd.org/doc/html/Debug-Adapter-Configuration.html]:

| 문자 | 의미 | 응답 |
|---|---|---|
| `'0'`–`'7'` | TCK/TMS/TDI 쓰기, 값 = `tck<<2 \| tms<<1 \| tdi` | 없음 |
| `'R'` | TDO 읽기 | `'0'` 또는 `'1'` |
| `'r' 's' 't' 'u'` | 리셋, `'r' + (trst<<1 \| srst)` | 없음 |
| `'B'`/`'b'` | LED 켬/끔 | 없음 |
| `'Z'`/`'z'` | (원격 sleep) | 없음 |
| `'Q'` | 종료 | 없음 |

- OpenOCD bitbang 코어는 비트마다 `write(0,tms,tdi)` → (필요하면 `'R'`) → `write(1,tms,tdi)` 순서로 보낸다. 시뮬레이터는 **TCK 상승 에지에서만** 상태를 바꾼다(같은 레벨 반복 쓰기는 무시). TDO는 Shift 상태에서 시프트 레지스터 LSB를 낸다.
- ADIv5 JTAG-DP는 IR 4비트다: `ABORT=0x8, DPACC=0xA, APACC=0xB, IDCODE=0xE, BYPASS=0xF`.
  - DPACC/APACC DR은 35비트다. 입력은 `bit0=RnW, bit[2:1]=A[3:2], bit[34:3]=data`이고, Capture 값은 `(직전 읽기 결과<<3) | ACK`이며 ACK OK/FAULT=`0b010`, WAIT=`0b001`이다.
  - OpenOCD `dap_dp_init()`은 CTRL/STAT의 `CDBGPWRUPACK`(bit29)/`CSYSPWRUPACK`(bit31)을 기다린다(REQ bit28/30을 그대로 비춰 주면 된다).
  - `mem_ap_init()`은 CFG를 읽고, CSW 크기·packed 지원을 써 본 뒤 다시 읽어 판정한다. packed를 거부하려면 CSW AddrInc를 `single`로 돌려주면 된다 [소스 `M:src/target/arm_adi_v5.c`].
- 이 구성으로 §4의 `scan_chain`, `targets`, `md*`, `read/write_memory`, `dump/load/verify_image`, `flash *`, `irscan/drscan`, `capture {reset init}`, 알림 출력을 모두 실측했다. 코드는 부록 A.
- `faux` 플래시 [소스 `M:src/flash/nor/faux.c#L22`]: 섹터 크기 고정 `0x10000`, `flash bank <name> faux <base> <size> <chip_width> <bus_width> <target>`. 쓰기와 지우기는 호스트 버퍼에서, 읽기는 타깃 메모리에서 한다.
- `mem_ap` 타깃 [소스 `M:src/target/mem_ap.c#L96`]: `halt`/`resume`은 상태 값만 바꾼다. 레지스터와 arch_state 출력이 없다.
- 참고(미검증): Spike(RISC-V ISA sim)의 `--rbb-port`도 remote_bitbang 서버를 제공한다. 레지스터·halt 경로를 포함한 RISC-V 타깃 테스트에 쓸 수 있으나 이 문서에서는 시도하지 않았다.

### 7.3 fake OpenOCD TCL 서버 구현 계약

실제 OpenOCD 없이 openocd-mcp를 단위 테스트할 때 fake 서버가 지켜야 할 동작이다.

1. `127.0.0.1:<port>`에 TCP 서버를 열고 다중 연결을 받는다. 연결마다 버퍼를 두고 `0x1a`로 프레임을 자른다.
2. 4 MiB(4,194,304바이트)를 넘는 프레임은 `b"line too long\n\x00"`만 보내고 **종결자를 보내지 않는다**.
3. 봉투 정규식을 인식해 내부 명령을 실행하고 `f"{rc} {out}"` + `\x1a`로 응답한다.
   ```python
   ENVELOPE = re.compile(r'^set (\w+) \[catch \{(.*)\} (\w+)\]; set (\w+) "\$\1 \$\3"$', re.S)
   ```
   이 정규식은 §3.9 클라이언트가 보내는 문자열 그대로(`set _pweh_rc [catch {mdw 0x0 2} _pweh_out]; set _pweh_x "$_pweh_rc $_pweh_out"`)와 중첩 중괄호가 있는 `write_memory … {0xdeadbeef 0x1}`에서 모두 매치됨을 확인했다(group(2)가 내부 명령).
   봉투가 아닌 원시 명령에는 `out` + `\x1a`만 보낸다.
4. **프로파일 두 개**를 제공해 같은 테스트를 양쪽으로 돌린다.
   - `master`: 끝 `\n` 제거, 실패 rc=`1`, `jtag names`/`drscan`은 개행 구분, `flash list`는 여러 줄, `jtag cget -idcode`는 16진, `tcl port`, `errorCode=OpenOCD <n>`.
   - `v0.12.0`: 끝 `\n` 유지, 실패 rc=음수(`-4` 일반, `-601` 문법, `-603` 인자, `-306` 크기 미지원 등), 공백 구분, `flash list` 한 줄 10진, `tcl_port`, 원시 오류는 `"<cfg>:<line>: Error: <msg>\nat file \"<cfg>\", line <line>"` 포장.
5. `shutdown` → `b"\x1a"`를 보내고 모든 연결을 닫은 뒤 서버를 종료한다. `exit` → `b"\x1a"`를 보내고 해당 연결만 닫는다. 둘 다 봉투 안에서도 같다(catch 불가).
6. 알림: 연결별 플래그(`tcl notifications on`/`tcl_notifications on`). `halt`/`resume`/`reset` 실행 시 플래그가 켜진 **모든** 연결에 §3.8 순서대로 프레임을 보낸다(명령을 보낸 연결에는 응답보다 먼저).
7. 출력 문자열은 §4의 바이트를 그대로 쓴다. 지연 주입(예: `dump_image` 크기에 비례한 sleep)과 프로세스 종료 시뮬레이션(init 실패 → 연결 직후 EOF)으로 타임아웃과 오류 경로를 테스트한다.
8. "결과는 비었지만 실패" 케이스(`mdd`, 범위 밖 `flash read_bank`, `verify_image_checksum`)를 반드시 포함한다. 파서가 빈 문자열을 성공으로 오인하지 않는지 검증한다.

---

## 8. 프로브별 interface 설정 파일

경로는 OpenOCD scripts 디렉터리 기준이다(예: `/usr/share/openocd/scripts`, xPack은 `<root>/openocd/scripts`). [소스: 0.12.0과 master 트리를 `ls`로 확인]

| 프로브 | 파일 | 핵심 내용 / 버전 차이 |
|---|---|---|
| **FT2232H 범용** | `interface/ftdi/minimodule.cfg` (FT2232H Mini-Module), `ftdi/olimex-arm-usb-ocd-h.cfg`, `ftdi/dp_busblaster.cfg`, `ftdi/jtagkey2.cfg`, `ftdi/flyswatter2.cfg`, `ftdi/tumpa.cfg`, `ftdi/tumpa-lite.cfg` | minimodule(master): `adapter usb product_name "FT2232H MiniModule"`, `adapter usb vid_pid 0x0403 0x6010`, `ftdi layout_init 0x0008 0x000b`, `ftdi layout_signal nSRST -data 0x0020 -oe 0x0020` |
| **FT232H 범용** | `interface/ftdi/um232h.cfg`, `ftdi/c232hm.cfg`, `ftdi/ft232h-module-swd.cfg`(SWD) | um232h: `adapter usb vid_pid 0x0403 0x6014`, `ftdi layout_init 0xfff8 0xfffb`, nTRST `0x0100`, nSRST `0x0200`. ft232h-module-swd는 `transport select swd`까지 포함 |
| **Tigard** | `interface/ftdi/tigard.cfg` (0.12.0, master 모두 있음) | master: `adapter usb product_name "Tigard V1.1"`, `adapter usb vid_pid 0x0403 0x6010`, `ftdi channel 1`, `ftdi layout_init 0x0038 0x003b`, `ftdi layout_signal nTRST -data 0x0010`, `ftdi layout_signal nSRST -data 0x0020`, `reset_config srst_push_pull trst_push_pull`. 0.12.0은 `ftdi device_desc "Tigard V1.1"`, `ftdi vid_pid 0x0403 0x6010`(구 문법) |
| **Shikra** | 트리에 **없음** | FT232H 계열로 알려져 있다(Hackaday 로그 "they all use the same FTDI X232H", BHIS 글의 `flashrom -p ft2232_spi:type=232H` 사용). 핀맵·`layout_init` 값은 (미확인). `um232h.cfg`를 바탕으로 벤더 핀아웃에 맞춰 직접 작성해야 한다 |
| **J-Link** | `interface/jlink.cfg` | `adapter driver jlink` 한 줄. JTAG/SWD 모두 지원 |
| **ST-Link** | `interface/stlink.cfg`, `interface/stlink-dap.cfg`, (master) `interface/stlink-hla.cfg` | master는 `adapter driver st-link`, 0.12.0은 `adapter driver hla` + `hla_layout stlink`. ST-Link는 주로 SWD(STM32 대상)이며 카메라 SoC 디버깅에는 부적합 |
| **CMSIS-DAP** | `interface/cmsis-dap.cfg`, (master) `interface/cmsis-dap-tcp.cfg` | `adapter driver cmsis-dap` |
| **Raspberry Pi GPIO** | `interface/raspberrypi-native.cfg`(bcm2835gpio, Pi 1), `interface/raspberrypi2-native.cfg`, `interface/sysfsgpio-raspberrypi.cfg`, (master) `interface/raspberrypi5-gpiod.cfg`, `interface/raspberrypi-gpio-connector.cfg` | 0.12.0 raspberrypi-native: `adapter driver bcm2835gpio`, `bcm2835gpio peripheral_base 0x20000000`, `adapter gpio tck -chip 0 11`, `tms 25`, `tdi 10`, `tdo 9`. master 버전은 `/proc/device-tree/compatible`로 모델을 감지하고 `exec vcgencmd`로 클럭을 읽는다. linuxgpiod 드라이버는 libgpiod 빌드가 필요하다(xPack 0.12.0-7의 `adapter list`에는 `linuxgpiod`가 없다 [실측]) |
| **Bus Pirate** | `interface/buspirate.cfg` | `adapter driver buspirate`, `buspirate speed normal ;# or fast`, `reset_config srst_only`. 직렬 포트는 직접 지정해야 한다: 0.12.0 이상 `buspirate port /dev/ttyUSB0`(0.11은 `buspirate_port`). 매우 느려서 대용량 덤프에는 부적합 |
| 테스트 | `interface/dummy.cfg`(`adapter driver dummy`), `interface/jtag_vpi.cfg`, `interface/vdebug.cfg` | §7 |

- 0.12.0과 master 공통: 같은 종류 장치가 여러 개면 `adapter serial <sn>` 또는 `adapter usb location <bus>-<port>`로 고른다(0.11에는 `adapter serial`이 없다 [실측]).
- master는 설정 파일을 벤더 폴더로 옮기는 중이다(`tcl/file_renaming.cfg`, `find` proc의 자동 리네임 [소스 `M:src/helper/startup.tcl#L25`]). 옛 경로를 쓰면 `WARNING: '<old>' is deprecated, use '<new>' instead`를 찍고 계속 동작한다. **MCP는 파일 존재 여부를 `find <file>`로 먼저 확인**한다(결과는 전체 경로, 없으면 오류).

---

## 9. 카메라 SoC 노트

### 9.1 SoC별 CPU 아키텍처 (근거: OpenIPC 빌드용 커널 config)

출처는 https://github.com/OpenIPC/firmware (commit `e8d577a1`)의 `br-ext-chip-*/board/**/*.config`다.

| SoC (예) | 커널 config 근거 | OpenOCD 타깃 타입 후보 | 트리 내 템플릿 |
|---|---|---|---|
| HiSilicon Hi3518EV200 / Hi3516CV200 계열 | `CONFIG_CPU_ARM926T=y`, `CONFIG_CPU_32v5=y` (`hi3516cv200/hi3518ev200.generic.config`) | `arm926ejs` | `target/at91sam9.cfg` (ARM926EJ-S: `jtag newtap … -irlen 4 -ircapture 0x1 -irmask 0xf -expected-id 0x0792603f`, `target create … arm926ejs -endian … -tap …`) |
| Anyka AK3918EV300 | `CONFIG_CPU_ARM926T=y` | `arm926ejs` | 같음 |
| Fullhan FH8852V200 | `CONFIG_CPU_V6=y`, `CONFIG_ARCH_FH885xV200=y` | `arm11` (ARMv6 = ARM11 계열로 추정, 정확한 코어명 (미확인)) | `target/bcm2835.cfg` (ARM1176: `-irlen 5`, `expected-id 0x07b7617F`, `target create … arm11 -tap …`) |
| HiSilicon Hi3516EV200/EV300, Goke GK7205V200 | `CONFIG_ARCH_MULTI_V7=y`, `CONFIG_CPU_V7=y`, `CONFIG_ARM_GIC=y` | DAP + `cortex_a` (코어명 Cortex-A7은 일반적으로 알려진 값, 1차 확인은 (미확인)) | `target/allwinner_v3s.cfg`(Cortex-A7 카메라 SoC: `-irlen 4 -ircapture 0x01 -irmask 0x0f -expected-id 0x5ba00477`, `dap create`, `target create … cortex_a -dap …`), `target/imx6ul.cfg`(Cortex-A7: `mem_ap -ap-num 0` + `cortex_a -dbgbase 0x82130000`) |
| HiSilicon Hi3516CV500/DV300 | ARMv7 + `CONFIG_SMP=y` | DAP + `cortex_a` ×2 (SMP) | 같음 |
| SigmaStar SSC33x(infinity6 계열), MSC313E(infinity3) | `CONFIG_ARCH_MULTI_V7=y`, `CONFIG_ARCH_SSTAR=y` / `CONFIG_CPU_V7=y` | DAP + `cortex_a` | 같음 |
| Novatek NT9856x | `CONFIG_CPU_V7=y`, `CONFIG_ARCH_NVT_IVOT_V7=y` | DAP + `cortex_a` | 같음 |
| Ingenic T31 | `CONFIG_MACH_XBURST=y`, `CONFIG_SOC_T31=y`, `CONFIG_CPU_MIPS32_R1=y`, `CONFIG_CPU_LITTLE_ENDIAN=y` | `mips_m4k` (EJTAG), `-endian little` — XBurst EJTAG 호환성은 (미확인) | `target/ar71xx.cfg`, `target/atheros_ar9331.cfg` (MIPS 24K: `-irlen 5`, `target create … mips_m4k -endian big -tap …`, Atheros는 IDCODE `0x00000001`) |
| Ingenic T40 | `CONFIG_MACH_XBURST2=y`, `CONFIG_CPU_MIPS32_R2=y` | `mips_m4k` 시도 (미확인) | 같음 |

- OpenOCD 트리에는 HiSilicon Hi35xx, Ingenic, SigmaStar, Novatek 전용 target cfg가 **없다**(grep 결과; `target/hi6220.cfg`는 휴대폰용 Kirin 620). **target cfg는 손으로 써야 한다.**
- OpenOCD 타깃 타입 목록 — [실측 master·xPack] `target types` (master는 개행 구분, 0.12.0은 공백 구분으로 출력): `aarch64 arcv2 arm11 arm720t arm7tdmi arm920t arm926ejs arm946e arm966e arm9tdmi armv8r avr32_ap7k avr cortex_a cortex_m cortex_r4 dragonite dsp563xx dsp5680xx esirisc esp32s2 esp32s3 esp32 fa526 feroceon hla_target ls1_sap mem_ap mips_m4k mips_mips64 or1k quark_d20xx quark_x10xx riscv stm8 testee xscale xtensa` (0.12.0에는 `nds32_v2 nds32_v3 nds32_v3m`도 있다; 등록 배열 [소스 `M:src/target/target.c#L75-L115`]).
  - MIPS32 계열의 타입 이름은 `mips_m4k`다. `mips32`라는 타깃 타입은 없다. `mips32`는 `mips32 cp0`, `mips32 scan_delay`, `mips32 dsp` 같은 명령 그룹 이름이다 [소스 `M:src/target/mips32.c#L2367-L2407`].

### 9.2 손으로 쓰는 target cfg 골격 (템플릿 — 값은 장비별 확인 필요)

아래 값은 위 트리 템플릿의 구조를 옮긴 것이다. 카메라 SoC의 IDCODE, irlen, 디버그 베이스 주소는 **(미확인)**이며 `scan_chain`/`dap info` 결과로 채운다.

```tcl
# --- ARM926EJ-S (예: Hi3518EV200 계열) : at91sam9.cfg 구조 ---
jtag newtap cam cpu -irlen 4 -ircapture 0x1 -irmask 0xf -expected-id <IDCODE (미확인)>
target create cam.cpu arm926ejs -endian little -chain-position cam.cpu
cam.cpu configure -work-area-phys <SRAM 또는 DRAM 주소 (미확인)> -work-area-size 0x4000 -work-area-backup 1
reset_config none        ;# TRST/SRST가 배선되지 않은 경우
adapter speed 1000       ;# PLL 설정 전 클럭이 낮으면 더 낮춘다 (at91sam9.cfg는 3 kHz에서 시작)

# --- Cortex-A7 (예: Hi3516EV300/SSC33x 계열) : allwinner_v3s.cfg / imx6ul.cfg 구조 ---
jtag newtap cam dap -irlen 4 -ircapture 0x01 -irmask 0x0f -expected-id <IDCODE (미확인)>
dap create cam.dap -chain-position cam.dap
target create cam.ahb mem_ap -dap cam.dap -ap-num 0                ;# AHB-AP가 있으면 CPU를 멈추지 않고 메모리 접근
target create cam.cpu cortex_a -dap cam.dap -dbgbase <디버그 베이스 (미확인)>
reset_config none

# --- MIPS32 EJTAG (예: Ingenic T31) : ar71xx.cfg 구조 ---
jtag newtap cam cpu -irlen 5 -expected-id <IDCODE (미확인)>
target create cam.cpu mips_m4k -endian little -chain-position cam.cpu
```

- 0.12.0 호환을 위해 `-chain-position`을 썼다. master 전용이면 `-tap`.
- `dap info`(AP 목록, ROM 테이블)로 Cortex-A 디버그 베이스를 찾는다. CoreSight ROM 테이블의 형식과 해석은 `dap info` 출력으로 확인한다(이 문서에서 실측하지 않음).
- `mem_ap` 타깃이 쓸 AP 번호는 SoC마다 다르다. 예: V3s cfg 주석은 `dap[0]->MEM-AP AHB`, `dap[1]->MEM-AP APB->CA7[0]`.

### 9.3 흔한 장애물과 근거

1. **JTAG 핀이 다른 기능으로 먹스됨**
   - OpenIPC의 Goke GK7205V200 보드 `ipctool reginfo` 덤프(https://github.com/OpenIPC/wiki/blob/master/en/device-ahd2net-converter.md)를 보면, 같은 패드가 `JTAG_TRSTN SPI1_CSN0 GPIO1_4 … UART2_RXD I2S_MCLK` 등 여러 기능을 가진다.
     ```
     muxctrl_reg47 0x120c0010 0 [JTAG_TRSTN] SPI1_CSN0 GPIO1_4 reserved UART2_RXD I2S_MCLK
     muxctrl_reg48 0x120c0014 0 [JTAG_TCK] SPI1_SCLK GPIO1_5 reserved UART2_TXD I2S_BCLK
     muxctrl_reg49 0x120c0018 0 [JTAG_TMS] SPI1_SDI GPIO1_6 PWM2 UART2_CTSN I2S_WS
     muxctrl_reg50 0x120c001c 0 [JTAG_TDO] SPI1_SDO GPIO1_7 reserved UART2_RTSN I2S_SD_RX
     muxctrl_reg51 0x120c0020 0x3 JTAG_TDI SPI1_CSN1 GPIO2_0 [SDIO0_CARD_POWER_EN] PWM3 I2S_SD_TX
     ```
     대괄호는 현재 선택된 기능을 뜻한다(덤프 형식상 추정; ipctool 문서로 1차 확인은 (미확인)). 이 보드에서는 **TDI 패드가 `SDIO0_CARD_POWER_EN`으로 재할당**되어 부팅 후 JTAG을 쓸 수 없다.
   - 같은 페이지는 SDIO0 패드에도 `JTAG_TCK/TMS/TDO/TDI/TRSTN` 대체 기능이 있음을 보여 준다. 즉 JTAG 위치 후보가 둘 이상일 수 있다.
   - UART 셸이 있으면 먼저 `ipctool reginfo`(또는 `devmem`으로 먹스 레지스터)를 읽어 JTAG 기능이 살아 있는지 확인하고, U-Boot 단계에서 먹스를 되돌리는 방법을 검토한다. 레지스터 값 변경은 기기별 위험이 있으므로 R2/R4 확인을 거친다.
   - Allwinner V3s cfg 주석: "JTAG is enabled by default after power-on … 0200ms JTAG enabled, 0220ms JTAG pins switched to SD mode … The time frame of 20ms can be not enough to init and halt the CPU." 부팅 직후 짧은 창에만 JTAG이 살아 있는 경우가 있다.
2. **TRST/SRST 없음**: V3s cfg "No NRST or SRST is present on the SoC" → `reset_config none srst_pulls_trst`. 카메라 보드는 대개 리셋 핀을 JTAG 헤더로 빼지 않는다. 전원 사이클 + `halt` 경쟁, 또는 U-Boot에서 멈춘 상태에서 붙는 전략을 쓴다.
3. **퓨즈/보안으로 JTAG 비활성화**: 벤더 SoC의 secure boot·eFuse로 디버그 포트를 영구히 끄는 기능이 흔하지만, HiSilicon/Ingenic/SigmaStar 공개 1차 문서로 확인하지 못했다 (미확인).
   - 증상은 보통 `JTAG scan chain interrogation failed: all ones` 또는 IDCODE는 보이는데 코어 examine 실패다.
   - 이때 eFuse/OTP 쓰기로 "되살리기"를 시도하지 않는다(R4, 비가역).
4. **클럭**: ARM926EJ-S는 PLL 설정 전 코어 클럭이 낮을 수 있다(at91sam9.cfg는 `adapter speed 3`으로 시작). 처음에는 낮은 속도(100–1000 kHz)로 붙고, `reset init` 이벤트에서 올리는 것이 일반적이다.
   - 매뉴얼(`adapter speed`): "most ARM cores accept at most one sixth of the CPU clock.", "Speed 0 (khz) selects RTCK method." RTCK가 배선된 보드는 `adapter speed 0`(응답 `adapter speed: RCLK - adaptive`)을 쓸 수 있다(https://openocd.org/doc/html/Debug-Adapter-Configuration.html).
5. **MIPS EJTAG**: EJTAG 버전 검출 로그는 DEBUG 레벨이다(`EJTAG: Version 2.6 Detected` 등 [소스 `M:src/target/mips_ejtag.c`]). `-d3`에서만 보인다. XBurst의 EJTAG/PrAcc 호환성은 공개 자료로 확인하지 못했다 (미확인).
6. **SPI NOR 플래시를 `flash read_bank`로 읽을 수 없음**:
   - OpenOCD의 SPI 계열 NOR 드라이버는 `ath79`, `dw-spi`, `fespi`, `jtagspi`, `lpcspifi`, `max32xxx_qspi`, `mrvlqspi`, `sh_qspi`, `stmqspi`, `eneispif`, `cfi`(병렬 NOR) 등이다 [소스 `M:src/flash/nor/`]. HiSilicon FMC/SFC, Ingenic SFC, SigmaStar 컨트롤러 드라이버는 **없다**.
   - 일반적인 우회 경로:
     - (a) U-Boot 셸에서 `sf probe; sf read <RAM> <off> <len>`으로 RAM에 올린 뒤, JTAG `halt` → `dump_image`로 RAM을 덤프한다.
     - (b) SoC가 메모리 매핑 읽기 창을 제공하면 그 창을 `dump_image`한다(주소는 SoC별 (미확인)).
     - (c) UART 기반 덤프(firmware-dump-via-uart Skill)나 SPI 직접 읽기와 결과를 비교·검증한다.

### 9.4 에이전트 Skill 작성 시 체크리스트 (JTAG 경로)

1. 사람이 배선(TCK/TMS/TDI/TDO/GND, 가능하면 TRST/SRST/VREF)을 마친 것을 확인한다. VREF로 타깃 I/O 전압(1.8/3.3 V)과 프로브 레벨이 맞는지 확인한다.
2. TAP을 선언하지 않고 자동 탐색한다(`-c "transport select jtag" -c "adapter speed 100"`, target cfg 없이). `Warn : AUTO auto0.tap - use "jtag newtap …"`과 `scan_chain`으로 IDCODE와 irlen을 얻는다.
3. IDCODE의 제조사 필드로 코어 계열을 추정한다(`mfg: 0x23b (ARM Ltd)`면 ARM DAP 또는 ARM9/11 TAP). §9.2 골격에서 cfg를 만든다.
4. `targets`, `poll`, `capture halt`로 examine과 halt를 확인한다(R2 확인). 메모리는 먼저 `read_memory`로 작은 범위를 읽는다. 덤프는 `dump_image`를 케이스 경로로 하고, 2회 덤프해 해시를 비교한다.
5. 모든 쓰기/플래시/eFuse 계열은 §5 정책에 따른다.

---

## 부록 A. remote_bitbang JTAG 시뮬레이터 (검증 완료)

OpenOCD master, xPack 0.12.0-7, v0.12.0, 0.11.0 모두에서 init, IDCODE 검출, mem_ap 메모리 접근, faux 플래시 읽기가 동작함을 확인했다(0.11.0의 `verify_image`만 OpenOCD 쪽 문제로 종료).

- 실행: `python3 jtagsim.py --port 3335 --tap1-id 0x0792603f`
- 메모리 내용:
  - 접근하지 않은 페이지는 "word 값 = 주소" 패턴으로 채운다.
  - `0x08000000`에는 `27 05 19 56` + `"U-Boot 2016.11 (sim)\0"` + `00..ff`가 들어 있다.

```python
#!/usr/bin/env python3
"""OpenOCD remote_bitbang JTAG simulator: TAP0 = ADIv5 JTAG-DP + AHB MEM-AP(AP#0, sparse RAM), TAP1 = dumb TAP."""
import argparse, socket, struct

TLR, RTI, SELDR, CAPDR, SHDR, EX1DR, PAUSEDR, EX2DR, UPDR, SELIR, CAPIR, SHIR, EX1IR, PAUSEIR, EX2IR, UPIR = range(16)
NEXT = {TLR: (RTI, TLR), RTI: (RTI, SELDR), SELDR: (CAPDR, SELIR), CAPDR: (SHDR, EX1DR),
        SHDR: (SHDR, EX1DR), EX1DR: (PAUSEDR, UPDR), PAUSEDR: (PAUSEDR, EX2DR), EX2DR: (SHDR, UPDR),
        UPDR: (RTI, SELDR), SELIR: (CAPIR, TLR), CAPIR: (SHIR, EX1IR), SHIR: (SHIR, EX1IR),
        EX1IR: (PAUSEIR, UPIR), PAUSEIR: (PAUSEIR, EX2IR), EX2IR: (SHIR, UPIR), UPIR: (RTI, SELDR)}

class Memory:
    def __init__(self): self.pages = {}
    def _page(self, a):
        b = a & ~0xFFF
        if b not in self.pages:
            self.pages[b] = bytearray(b"".join(struct.pack("<I", x & 0xFFFFFFFF) for x in range(b, b + 0x1000, 4)))
        return self.pages[b]
    def read8(self, a): return self._page(a)[a & 0xFFF]
    def write8(self, a, v): self._page(a)[a & 0xFFF] = v & 0xFF
    def load(self, a, data):
        for i, x in enumerate(data): self.write8(a + i, x)

class Tap:
    irlen, idcode_instr, ircapture = 4, 0xE, 0x1
    def __init__(self, idcode):
        self.idcode, self.ir, self.irsr, self.dr, self.drlen = idcode, self.idcode_instr, 0, 0, 32
    def reset(self): self.ir = self.idcode_instr
    def capture_ir(self): self.irsr = self.ircapture
    def update_ir(self): self.ir = self.irsr
    def dr_len(self): return 32 if self.ir == self.idcode_instr else 1
    def capture_dr(self):
        self.drlen = self.dr_len()
        self.dr = self.idcode if self.ir == self.idcode_instr else 0
    def update_dr(self): pass

class DapTap(Tap):
    ABORT, DPACC, APACC = 0x8, 0xA, 0xB
    def __init__(self, idcode, mem):
        super().__init__(idcode)
        self.mem, self.ctrl_stat, self.select, self.read_result, self.csw, self.tar = mem, 0, 0, 0, 2, 0
    def dr_len(self): return 35 if self.ir in (self.DPACC, self.APACC, self.ABORT) else super().dr_len()
    def capture_dr(self):
        self.drlen = self.dr_len()
        if self.ir in (self.DPACC, self.APACC, self.ABORT):
            self.dr = ((self.read_result & 0xFFFFFFFF) << 3) | 0b010      # ACK OK/FAULT
        else:
            super().capture_dr()
    def update_dr(self):
        if self.ir not in (self.DPACC, self.APACC): return
        rnw, a, data = self.dr & 1, ((self.dr >> 1) & 3) << 2, (self.dr >> 3) & 0xFFFFFFFF
        if self.ir == self.DPACC:
            if rnw: self.read_result = self.dp_read(a)
            else: self.dp_write(a, data)
        else:
            reg, apsel = (self.select & 0xF0) | a, (self.select >> 24) & 0xFF
            if rnw: self.read_result = self.ap_read(apsel, reg)
            else: self.ap_write(apsel, reg, data)
    def dp_read(self, a):
        if a == 0x4:                                  # CTRL/STAT: mirror PWRUPREQ -> PWRUPACK
            v = self.ctrl_stat & ~((1 << 29) | (1 << 31))
            if self.ctrl_stat & (1 << 28): v |= 1 << 29
            if self.ctrl_stat & (1 << 30): v |= 1 << 31
            return v & ~0x22
        return self.select if a == 0x8 else 0         # 0x0 reserved(DPv0), 0xC RDBUFF
    def dp_write(self, a, d):
        if a == 0x4: self.ctrl_stat = d & ~0x32
        elif a == 0x8: self.select = d
    def _lane_read(self, size):
        a = self.tar
        if size == 0: return (self.mem.read8(a) << (8 * (a & 3))), 1
        if size == 1:
            a &= ~1
            return ((self.mem.read8(a) | (self.mem.read8(a + 1) << 8)) << (8 * (a & 2))), 2
        a &= ~3
        return sum(self.mem.read8(a + i) << (8 * i) for i in range(4)), 4
    def _lane_write(self, size, d):
        a = self.tar
        if size == 0: self.mem.write8(a, d >> (8 * (a & 3))); return 1
        if size == 1:
            a &= ~1; hv = d >> (8 * (a & 2))
            self.mem.write8(a, hv); self.mem.write8(a + 1, hv >> 8); return 2
        a &= ~3
        for i in range(4): self.mem.write8(a + i, d >> (8 * i))
        return 4
    def ap_read(self, apsel, reg):
        if apsel != 0: return 0
        if reg == 0x00: return (self.csw | (1 << 6)) & 0xFFFFFFFF                 # CSW (DeviceEn)
        if reg == 0x04: return self.tar
        if reg == 0x0C:                                                           # DRW
            v, inc = self._lane_read(self.csw & 7)
            if (self.csw >> 4) & 3 == 1: self.tar = (self.tar + inc) & 0xFFFFFFFF
            return v & 0xFFFFFFFF
        if 0x10 <= reg <= 0x1C:
            a = (self.tar & ~0xF) + (reg - 0x10)
            return sum(self.mem.read8(a + i) << (8 * i) for i in range(4))
        return {0xF4: 0, 0xF8: 0x00000002, 0xFC: 0x24770011}.get(reg, 0)           # CFG, BASE, IDR(AHB-AP)
    def ap_write(self, apsel, reg, d):
        if apsel != 0: return
        if reg == 0x00:
            size = min(d & 7, 2)                                                  # 8/16/32-bit only
            inc = (d >> 4) & 3
            inc = 1 if inc == 2 else inc                                          # refuse packed transfers
            self.csw = (d & ~0x37) | size | (inc << 4)
        elif reg == 0x04: self.tar = d
        elif reg == 0x0C:
            inc = self._lane_write(self.csw & 7, d)
            if (self.csw >> 4) & 3 == 1: self.tar = (self.tar + inc) & 0xFFFFFFFF
        elif 0x10 <= reg <= 0x1C:
            a = (self.tar & ~0xF) + (reg - 0x10)
            for i in range(4): self.mem.write8(a + i, d >> (8 * i))

class SimpleTap(Tap):
    irlen, idcode_instr, ircapture = 5, 0x1, 0x1

class Chain:
    def __init__(self, taps): self.taps, self.state, self.tck = taps, TLR, 0   # taps[0] = nearest TDO
    def reset(self):
        self.state = TLR
        for t in self.taps: t.reset()
    def tdo(self):
        if self.state == SHDR: return self.taps[0].dr & 1
        if self.state == SHIR: return self.taps[0].irsr & 1
        return 0
    def clock(self, tms, tdi):                       # rising edge: act on the state we are leaving
        st = self.state
        if st == TLR:
            for t in self.taps: t.reset()
        elif st == CAPDR:
            for t in self.taps: t.capture_dr()
        elif st == SHDR:
            b = tdi
            for t in reversed(self.taps):
                out = t.dr & 1; t.dr = (t.dr >> 1) | (b << (t.drlen - 1)); b = out
        elif st == UPDR:
            for t in self.taps: t.update_dr()
        elif st == CAPIR:
            for t in self.taps: t.capture_ir()
        elif st == SHIR:
            b = tdi
            for t in reversed(self.taps):
                out = t.irsr & 1; t.irsr = (t.irsr >> 1) | (b << (t.irlen - 1)); b = out
        elif st == UPIR:
            for t in self.taps: t.update_ir()
        self.state = NEXT[st][tms]
    def write(self, tck, tms, tdi):
        if tck and not self.tck: self.clock(tms, tdi)
        self.tck = tck

def serve(port, chain):
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port)); srv.listen(1)
    while True:
        conn, _ = srv.accept(); conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        chain.reset()
        with conn:
            while True:
                data = conn.recv(65536)
                if not data: break
                out, quit_ = bytearray(), False
                for c in data:
                    if 0x30 <= c <= 0x37:
                        v = c - 0x30; chain.write((v >> 2) & 1, (v >> 1) & 1, v & 1)
                    elif c == ord('R'): out.append(0x30 + chain.tdo())
                    elif c in b'rstu':
                        if ((c - ord('r')) >> 1) & 1: chain.reset()      # TRST
                    elif c == ord('Q'): quit_ = True; break
                if out: conn.sendall(bytes(out))
                if quit_: break

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=3335)
    ap.add_argument("--tap1-id", type=lambda s: int(s, 0), default=0)
    a = ap.parse_args()
    mem = Memory()
    mem.load(0x08000000, b"\x27\x05\x19\x56" + b"U-Boot 2016.11 (sim)\x00" + bytes(range(256)))
    taps = [DapTap(0x5BA00477, mem)] + ([SimpleTap(a.tap1_id)] if a.tap1_id else [])
    serve(a.port, Chain(taps))
```

이 시뮬레이터에 없는 것:
- WAIT ACK, sticky 오류, ABORT 처리.
- packed 전송, 64비트 접근. 그래서 `mdd`는 `Size 8 not supported`가 난다(오류 경로 테스트용으로 오히려 유용하다).
- ROM 테이블, CPU 코어 디버그 레지스터. 그래서 `cortex_a`/`arm926ejs` 타깃은 시험할 수 없다.

---

## 부록 B. 1차 출처

- OpenOCD 소스(고정 커밋): https://github.com/openocd-org/openocd/tree/bb5a52da599c3dac61ddc51d2fa8c1166ee795d0 , 릴리스 태그: https://github.com/openocd-org/openocd/tree/v0.12.0
  - TCL 서버: `src/server/tcl_server.c` (M#L18 `TCL_LINE_MAX`, #L163 `tcl_input`, #L226 `line too long`, #L49–L106 알림, #L385 기본 포트; T#L328 `tcl_port`)
  - 명령 실행·capture: `src/helper/command.c` (M#L424 `jim_exec_command`, #L468 마지막 개행 제거, #L492 errorCode, #L497 `command_run_line`, #L638 `capture`; T#L129 `command_retval_set`, T#L522 `run_command`, T#L692 `jim_capture`)
  - 서버 공통: `src/server/server.c` (M#L278 루프백 바인딩, #L319 Listening, #L798 shutdown, #L833 exit), `src/server/startup.tcl` (M#L100 deprecated `tcl_port`)
  - 기동 순서: `src/openocd.c` (M#L41 버전 문자열, #L108 `init`, #L304 `server_init`)
  - 타깃 명령: `src/target/target.c` (M#L2811 `targets`, #L3017 `reg`, #L3368 md 출력, #L3636 load_image, #L3724 dump_image, #L3792 verify_image, #L4477 read_memory), `src/target/armv4_5.c` #L797, `src/target/arm926ejs.c` #L504, `src/target/armv7a.c` #L481, `src/target/mips32.c` #L481, `src/target/mem_ap.c`, `src/target/mips_ejtag.c`
  - JTAG: `src/jtag/tcl.c` (#L792 scan_chain, #L164 drscan), `src/jtag/core.c` (#L1118, #L1126, #L1396), `src/jtag/adapter.c` #L740, `src/jtag/drivers/dummy.c` #L25, `src/jtag/drivers/remote_bitbang.c` #L211
  - 플래시: `src/flash/nor/tcl.c` (#L58 info, #L152 probe, #L232 erase_address, #L302 erase_sector, #L364 protect, #L424 write_image, #L883 write_bank, #L998 read_bank, #L1078 verify_bank, #L1473 banks, #L1487 list), `src/flash/nor/faux.c`, `src/flash/startup.tcl` #L21 (`program`)
  - 로그: `src/helper/log.c` #L40, 트랜스포트: `src/transport/transport.c` #L300
  - 예제 클라이언트: `contrib/rpc_examples/ocd_rpc_example.py`
  - 회귀 테스트(dummy): `testing/tcl_commands/test-target-create-command.cfg`
- OpenOCD User's Guide (0.12.0+dev, 2026-10-12): https://openocd.org/doc/html/index.html
  - Tcl RPC: https://openocd.org/doc/html/Tcl-Scripting-API.html
  - 포트·bindto: https://openocd.org/doc/html/Server-Configuration.html
  - 어댑터(remote_bitbang, dummy): https://openocd.org/doc/html/Debug-Adapter-Configuration.html
  - 플래시: https://openocd.org/doc/html/Flash-Commands.html
  - 일반 명령(md*, read_memory, dump_image, debug_level): https://openocd.org/doc/html/General-Commands.html
  - JTAG 명령(irscan/drscan): https://openocd.org/doc/html/JTAG-Commands.html
  - 실행(명령행): https://openocd.org/doc/html/Running.html
- OpenIPC: 커널 config — https://github.com/OpenIPC/firmware (commit `e8d577a1a20cfdadf271ed3bdb9562313286cae5`, `br-ext-chip-*/board/**/*.config`); 핀먹스 예 — https://github.com/OpenIPC/wiki/blob/master/en/device-ahd2net-converter.md (wiki commit `3c58d3d3de465c59bcefbd7082613b4b50c7c333`)
- Shikra(2차 자료): https://hackaday.io/project/164346/log/166065 , https://www.blackhillsinfosec.com/hardware-hacking-with-shikra/
- xPack OpenOCD 0.12.0-7: https://github.com/xpack-dev-tools/openocd-xpack/releases
