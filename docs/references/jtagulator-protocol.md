# JTAGulator 시리얼 명령 인터페이스 레퍼런스 (FW 1.12)

> **읽는 사람**: `jtagulator-mcp` 드라이버 구현자, 테스트용 JTAGulator 시뮬레이터 구현자, 에이전트 Skill 작성자.
> **목적**: USB-시리얼로 JTAGulator 메뉴를 자동 조작하는 Python 드라이버와, 그 드라이버를 시험할 충실한 시뮬레이터를 만들 수 있을 만큼 **정확한 문자열·순서·형식**을 제공한다.
> **범위**: 본인이 소유하거나 서면 허가를 받은 장비의 디버그 인터페이스(JTAG/SWD/UART) 핀아웃을 찾는 용도에 한정한다.

---

## 0. 기준 버전, 표기 규약, 근거 수준

### 0.1 기준 펌웨어

| 항목 | 값 | 근거 |
|---|---|---|
| 기준 펌웨어 | **JTAGulator FW 1.12** (`VersionInfo` 문자열 `"JTAGulator FW 1.12"`) | [JTAGulator.spin L2796](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2796) |
| git tag / commit | `1.12` / `5222116d2db853492d294c5e13e55ce340f76def` (2023-06-05) | [tags](https://github.com/grandideastudio/jtagulator/tags), [CHANGES 1.12](https://github.com/grandideastudio/jtagulator/blob/master/CHANGES.markdown#v1_12) |
| 최신 여부 | 2026-10-18 확인 시점 최신 태그. `master` HEAD `6a764cd`(2026-09-01)는 하드웨어 문서·README만 추가했고 `.spin` 펌웨어 소스는 1.12와 동일 (`git diff --stat 1.12 HEAD`로 확인) | [commits](https://github.com/grandideastudio/jtagulator/commits/master) |
| 유지보수 | 2025-07부터 EXPLIoT가 유지보수 | [README](https://github.com/grandideastudio/jtagulator/blob/master/README.markdown) |
| 주 소스 파일 | `JTAGulator.spin`(UI 전체), `PropSerial.spin`(호스트 시리얼·입력 처리), `PropJTAG.spin`, `PropSWD.spin`, `PropSUMP.spin`, `PropOCD.spin`, `JTAGulatorCon.spin`, `JTAGulatorUtil.spin` | raw: `https://raw.githubusercontent.com/grandideastudio/jtagulator/1.12/<파일명>` |

### 0.2 표기 규약

- 바이트 단위로 정확해야 하는 문자열은 **Python 문자열 리터럴**로 쓴다: `'\r'` = CR(0x0D), `'\n'` = LF(0x0A), `'\x08'` = BS, `'\x18'` = Ctrl-X(CAN).
- "→"는 호스트가 장치로 보내는 바이트, "←"는 장치가 호스트로 보내는 바이트다.
- **렌더링 예시**(터미널 화면 모습)와 **바이트열 예시**는 모두 FW 1.12 소스의 출력 루틴(`pst.Dec/Hex/Bin`, `Display_*`)을 그대로 옮긴 모델로 **합성**한 것이다. 실측 캡처가 아니다. (FW 1.12 실측 캡처를 공개 자료에서 찾지 못함. FW 1.6 기준 제3자 캡처가 UART 결과 형식을 뒷받침함: [hcw.ac.at 위키](https://elvis.hcw.ac.at/wiki/index.php/JTAGulator:_Find_IoT-Device%27s_UART_interface).)
- 줄 번호 `L123`은 tag 1.12의 해당 파일 기준이다. 예: [`JTAGulator.spin#L2767-L2778`](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2767-L2778).
- 근거 수준 표시:
  - **[소스]** 펌웨어 소스에서 직접 확인
  - **[위키]** 공식 위키/문서
  - **[추론]** 소스 로직 분석 또는 여러 1차 자료를 결합해 도출(근거를 함께 적음)
  - **(미확인)** 1차 자료로 확인하지 못함

---

## 1. 핵심 요약 — 드라이버가 반드시 지킬 것

1. **115200 bps, 8N1, 흐름제어 없음.** [115200/8N1은 위키 [Quick-Start](https://github.com/grandideastudio/jtagulator/wiki/Quick-Start). "흐름제어 없음"은 위키에 없는 내용이고, 회로도에서 FT232RL의 RTS/CTS가 미연결(NC)인 것이 근거다(§3.1)]
2. 줄 입력은 **CR(0x0D)에서만 끝난다.** LF(0x0A)는 줄 입력 중 버려진다(저장·에코 없음). 위키는 "CR 또는 LF"라고 쓰지만 FW 1.3 이후 소스는 CR만 종료 문자로 처리한다(§3.4). → **드라이버는 `'\r'`만 보낸다.** [소스 [PropSerial.spin L175-L197](https://github.com/grandideastudio/jtagulator/blob/1.12/PropSerial.spin#L175-L197)]
3. 장치는 줄 입력 중 받아들인 문자를 **CR까지 포함해 에코**한다. 응답을 해석하기 전에 에코를 먼저 소비한다.
4. `Press spacebar to begin ...`에는 **공백 1바이트 `' '`만** 보낸다. CR이나 LF를 덧붙이면 스캔 루프가 버퍼에 남은 그 바이트를 키 입력으로 보고 **즉시 중단**한다. [소스 [L2767-L2778](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2767-L2778), [L540](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L540)]
5. 스캔·연속 모니터가 돌고 있을 때는 **어떤 바이트든 1바이트가 도착하면 중단**된다. 의도적 중단에는 **`'\n'`(LF) 1바이트**를 권한다. 스캔은 멈추고, 스캔이 이미 끝나 프롬프트로 돌아와 있었다면 줄 입력이 LF를 버리므로 부작용이 없다. [추론: 위 2·4번의 소스 동작 결합]
6. 명령 키의 뜻은 **메뉴마다 다르다.** 예를 들어 `I`는 메인 메뉴에서는 버전 정보, `JTAG>`에서는 IDCODE 스캔, `SWD>`에서는 SWD 스캔이다. 프롬프트 접두어로 현재 메뉴를 추적한다(§5).
7. 리셋이나 전원 투입 때마다 타깃 I/O 전압은 `Undefined`로 돌아간다. 전압을 설정하기 전에는 타깃을 건드리는 모든 명령이 `'\r\nTarget I/O voltage must be defined!'`로 거부된다. [소스 [L2488-L2491](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2488-L2491)]
8. `[y/N]`·`[Y/n]`에서 대문자가 **현재 저장된 값**이다. 이 값은 이전 스캔 결과에 따라 바뀐다(예: 스캔이 성공하면 "Are any pins already known?"의 기본값이 `Y`가 됨). 드라이버는 빈 줄로 기본값을 받지 말고 **항상 명시적인 값**을 보낸다.
9. 정상 모드로 부팅한 장치는 **아무 키나 받을 때까지 아무것도 출력하지 않는다**(LED 노랑). 키를 받으면 그 키를 에코하고 배너를 보낸다. [소스 [L228-L232](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L228-L232), 위키 Quick-Start]
10. FT232RL의 `DTR`이 커패시터와 트랜지스터를 거쳐 Propeller `RES`에 연결되어 있다. 따라서 **포트를 열거나 닫을 때, 또는 DTR을 바꿀 때 장치가 리셋될 수 있다**(어느 에지에서 리셋되는지는 미확인). 포트는 세션 내내 열어 두고, 연결할 때마다 재동기화(§4.4)와 전압 재설정을 한다. [소스: HW Rev. C 회로도]
11. 로직 분석기(`GPIO>` `L`) 모드와 OpenOCD(`JTAG>` `O`) 모드는 EEPROM에 기록되어 **리셋·전원 재투입 후에도 유지된다.** 이 상태에서는 텍스트 명령에 응답하지 않으며 **`'\x18'`(Ctrl-X)로만 빠져나온다.** [소스, 위키 [Logic-Analyzer](https://github.com/grandideastudio/jtagulator/wiki/Logic-Analyzer)/[OpenOCD](https://github.com/grandideastudio/jtagulator/wiki/OpenOCD)]

---

## 2. 하드웨어·연결 개요 (드라이버 관점)

| 항목 | 내용 | 근거 |
|---|---|---|
| USB | FTDI FT232RL 가상 COM 포트(Linux `/dev/ttyUSB*`) | 위키 Quick-Start, [회로도 Rev. C p.1](https://github.com/grandideastudio/jtagulator/blob/master/Hardware/Rev.%20C/jtagulator_schematic.pdf) |
| MCU | Parallax Propeller P8X32A, 80 MHz (5 MHz × PLL16). 호스트 시리얼은 P31(RX)/P30(TX) | [L34-L35](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L34-L35), [PropSerial L97](https://github.com/grandideastudio/jtagulator/blob/1.12/PropSerial.spin#L97) |
| 채널 | CH0–CH23, 소스 상수 `MAX_CHAN = 24` | [JTAGulatorCon.spin L32](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulatorCon.spin#L32) |
| 레벨 변환 | TXS0108E 3개. 타깃 쪽 전원(VCCA)은 VADJ, Propeller 쪽(VCCB)은 3.3 V. `TXS_OE`(P24)로 한꺼번에 enable하며, R10(10 kΩ)이 OE를 GND로 당긴다. **명령 프롬프트에서 대기하는 동안에는 항상 disable(High-Z)** | 회로도 p.2, [L163](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L163), [JTAGulatorUtil.spin L52-L59](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulatorUtil.spin#L52-L59) |
| 입력 보호 | 채널마다 직렬 저항(R11–R13 어레이)과 NUP4302MR6 쇼트키 클램프(VCC=VADJ). 회로도 주석: "Vf must be < 0.5V to prevent damage to level translators" | 회로도 p.2, §15 |
| VADJ | DAC(PWM) + op-amp(AD8655)로 0–3.3 V를 만든다. 회로도 주석: "0-3.3V @ 256 steps, ~13mV/step, ~150mA max. Iout" | 회로도 p.1 |
| LED | 노랑 = 초기화 또는 부팅 후 키 대기, 녹색 = 프롬프트 대기, 빨강 = 명령 처리 중 또는 영속 모드, 빨강↔노랑 깜빡임 = 스캔 진행 중 | [L164-L167](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L164-L167), [L230](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L230), [L2710-L2714](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2710-L2714), 위키 |
| 리셋 경로 | FT232RL `DTR`(핀 2) → C2 0.01 µF → Q1(MMBT3904) 베이스(R2 10 kΩ 풀다운) → 컬렉터가 Propeller `#RES`. 리셋 버튼 SW1도 `#RES`에 연결 | 회로도 p.1, [BOM Rev. C](https://github.com/grandideastudio/jtagulator/blob/master/Hardware/Rev.%20C/jtagulator_bom.pdf) |

DTR 리셋을 뒷받침하는 정황도 있다. 위키의 Windows용 sigrok-cli 예시는 `serialcomm=115200/8n1/dtr=0`을 쓰고, 알려진 문제 표에는 macOS PulseView에서 장치를 고르면 "the JTAGulator will reset"라고 적혀 있다. [위키 [Logic-Analyzer](https://github.com/grandideastudio/jtagulator/wiki/Logic-Analyzer)]

[추론: 회로 해석] 회로도의 DTR 핀은 액티브 LOW(DTR#)이고 C2(직렬)와 R2(베이스 풀다운)를 거쳐 NPN 베이스로 간다. 따라서 Q1을 켜서 `#RES`를 LOW로 당길 수 있는 것은 DTR# 핀의 **상승 에지**(LOW→HIGH, 곧 호스트가 DTR을 **해제**할 때)뿐이다. 하강 에지(DTR 설정)는 베이스를 음으로 밀어 Q1이 꺼진 채로 남는다. 그러므로 포트를 닫으면서 DTR이 해제되거나(HUPCL) 드라이버가 `dtr=False`로 바꿀 때 리셋될 가능성이 높다. OS·라이브러리별 실제 동작은 **(미확인)**이다.

---

## 3. 시리얼 링크와 입력 처리 규칙

### 3.1 포트 설정

```text
115200 bps, 8 data bits, no parity, 1 stop bit (8N1), no flow control
```

- 위키 원문: "All communication is 115200 bps, 8 data bits, no parity, 1 stop bit." [위키 Quick-Start]
- 소스: `pst.Start(115_200)` [L2485](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2485). 회로도에서 FT232RL의 RTS/CTS 핀은 미연결(NC)이다.

### 3.2 출력 줄바꿈 규칙

- 기본 줄바꿈은 `'\r\n'`이다. 빈 줄을 넣는 곳에서는 `'\r\n\n'`(CR LF LF)을 쓴다(예: 프롬프트 접두 `'\r\n\n'`, `'\r\n\nBring channels LOW ...'`). 즉 **CR 없는 단독 LF가 출력된다.**
- 대부분의 메시지는 **앞에** `'\r\n'`이 붙고 **끝에는 줄바꿈이 없다**(예: `'\r\nIDCODE scan complete.'`). 그래서 줄 단위 읽기(readline)로는 메시지의 끝을 알 수 없다. **프롬프트와 완료 문자열을 정규식으로 기다려야 한다**(§17).
- 파싱 전 정규화 권장: `s.replace('\r\n', '\n').replace('\r', '\n')`.

### 3.3 입력 프리미티브 — 어디서 무엇이 에코되는가

| 프리미티브 (PropSerial.spin) | 사용하는 곳 | 끝나는 조건 | 에코 |
|---|---|---|---|
| `StrInMax(buf, max)` [L175-L197](https://github.com/grandideastudio/jtagulator/blob/1.12/PropSerial.spin#L175-L197) | 명령 프롬프트, 모든 값 입력 프롬프트 | CR(0x0D) 수신 | 받아들인 문자를 **원시 바이트 그대로** 에코(CR 포함). LF는 저장·에코하지 않음. BS(0x08)는 지울 글자가 있을 때만 1글자를 지우고 `'\x08 \x08'` 출력. `max`글자가 찬 뒤 들어오는 문자는 버리고 에코하지 않음(이때는 CR도 에코되지 않음) |
| `CharIn` [L149-L159](https://github.com/grandideastudio/jtagulator/blob/1.12/PropSerial.spin#L149-L159) | 부팅 후 웨이크 키, GPIO `W`의 "Press any key when done...", 핀 매퍼 일시정지, UART 패스스루(로컬 에코 on), FW ≤1.11.1의 스페이스바 대기 | 1바이트 | 0x0D, 0x0A, 0x20–0x7E는 그대로, 나머지는 `'.'` |
| `CharInNoEcho` [L161-L165](https://github.com/grandideastudio/jtagulator/blob/1.12/PropSerial.spin#L161-L165) | `Wait_For_Space`(FW 1.12), UART 패스스루(로컬 에코 off) | 1바이트 | 없음 |
| `RxEmpty` 폴링 | 모든 스캔 루프, GPIO `C`, UART `T`, 핀 매퍼 | 수신 버퍼에 1바이트라도 있으면 중단 | 없음(중단 뒤 `RxFlush`로 버림) |

- 명령 프롬프트 입력의 최대 길이는 `MAX_LEN_CMD = 12`, UART 스캔 문자열 입력은 `MAX_LEN_UART_USER = 34`다. [L48](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L48), [L58](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L58)
- 호스트 수신 링 버퍼는 256바이트(`BUFFER_LENGTH = 256`). [PropSerial L66](https://github.com/grandideastudio/jtagulator/blob/1.12/PropSerial.spin#L66)
- 시뮬레이터 충실도를 위한 세부: DEL(0x7F)은 백스페이스로 처리되지 않고 일반 문자로 저장·에코된다. [소스]

### 3.4 줄 종료 문자 — 소스와 위키가 다르다

- 위키 [Command-Set](https://github.com/grandideastudio/jtagulator/wiki/Command-Set) 원문: "Each command must be terminated with a single `CR` or `LF` (sent by the terminal program when the Enter key is pressed). Some terminal programs send both bytes when the Enter key is pressed, which will cause the JTAGulator to interpret it as two separate key presses."
- 소스(FW 1.3에서 백스페이스 지원이 들어온 커밋 `cb649ba` 이후): `StrInMax`는 `repeat while (c<>NL)`(NL=13)이라 **CR에서만 끝나고**, `elseif m and c<>LF` 조건 때문에 **LF는 버린다.** FW 1.2.x는 CR을 받거나 maxcount 글자가 차면 끝났고, LF를 일반 문자로 저장했다.
- 결론: FW 1.12에서 **LF만 보내면 줄이 끝나지 않는다.** CRLF를 보내면 CR이 줄을 끝내고, 남은 LF는 다음 줄 입력에서 버려진다(1.12의 `Wait_For_Space`도 CR/LF를 건너뜀). 하지만 그 LF가 **스캔이 돌기 시작한 뒤** 도착하면 중단 키로 작동한다. 그래서 드라이버는 `'\r'`만 보낸다.
- 위키 FAQ "After I start any scan, the JTAGulator immediately aborts."는 FW ≤1.11.1의 현상이다. 그때는 스페이스바 대기가 `CharIn`으로 1바이트를 읽었기 때문에, 직전 답의 CRLF에서 남은 LF가 "스페이스가 아닌 키"로 읽혀 중단됐다. 1.12는 Enter를 무시하도록 고쳐([CHANGES 1.12](https://github.com/grandideastudio/jtagulator/blob/master/CHANGES.markdown#v1_12)) 대화형 터미널에서는 대부분 사라졌다. 그래도 드라이버가 스페이스 **뒤에** CR/LF를 붙이면 여전히 즉시 중단된다. [위키 [FAQ](https://github.com/grandideastudio/jtagulator/wiki/Frequently-Asked-Questions)]

### 3.5 숫자·핀 입력 파서

두 함수 모두 `StrInMax(12)`로 한 줄을 읽는다.

`Get_Decimal_Pin` [L2653-L2666](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2653-L2666) — 채널 번호, 지연(ms), 전압, 보율 등에 쓴다.

```text
빈 줄            -> -1   (호출한 쪽이 "현재값 유지"로 해석)
'0'..'9'         -> 10진수로 누적
'.' 또는 ','     -> 무시   (예: '3.3' -> 33, '115,200' -> 115200)
그 밖의 문자     -> -3   (호출한 쪽의 범위 검사에서 "Value out of range!")
```

`Get_Pin` [L2632-L2650](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2632-L2650) — 핀을 "모름/비활성"으로 둘 수 있는 프롬프트에 쓴다(BYPASS 스캔의 알려진 핀, RTCK의 TCK, UART 핀).

```text
빈 줄                    -> -1  (현재값 유지)
'X' 또는 'x' 한 글자     -> -2  (모름/비활성)
'X'로 시작하는 2글자 이상 -> -3
나머지는 Get_Decimal_Pin과 같음
```

y/N형 프롬프트 [예: L2558-L2571](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2558-L2571):
- 0글자(빈 줄)면 현재값을 유지한다.
- 1글자면 `Y/y`·`N/n`만 받는다(핀 매퍼의 fill 질문은 `H/h`·`L/l`).
- 그 밖의 1글자나 2글자 이상(`yes` 등)이면 `'\r\nValue out of range!'`를 출력하고 **명령 전체가 취소**된다.

**모든 값 프롬프트의 오류 처리는 같다.** 오류 메시지를 출력하고, 그 명령을 끝내고, 현재 메뉴 프롬프트로 돌아간다. 다시 묻지 않는다.

### 3.6 드라이버 송신 규칙(권장)

| 상황 | 보낼 바이트 |
|---|---|
| 명령이나 값 입력 | `'<text>\r'` |
| 기본값 수락(권하지 않음) | `'\r'` |
| 스캔 시작 확인 | `' '` (한 바이트만) |
| 실행 중인 스캔·모니터 중단 | `'\n'` 한 바이트 권장(아무 바이트나 동작함) |
| UART 패스스루·영속 모드 종료 | `'\x18'` |
| 부팅 후 웨이크 | `'\r'` (아무 1바이트나 됨. 에코됨) |

- 프롬프트가 완전히 도착한 다음에 응답을 보낸다(lock-step). 응답을 미리 몰아서 보내면, 중간 값이 거부되어 메뉴로 돌아갔을 때 남은 바이트가 메뉴 명령으로 해석된다. [추론]

---

## 4. 부팅과 동기화

### 4.1 정상 모드 부팅 순서

[소스 [L152-L232](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L152-L232), [L2458-L2485](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2458-L2485), [PropSerial L89-L99](https://github.com/grandideastudio/jtagulator/blob/1.12/PropSerial.spin#L89-L99)]

1. `System_Init`: LED 노랑, 레벨 변환기 disable, DAC 0 (VADJ off), `pst.Start(115_200)` 후 **1초 대기**(`waitcnt(clkfreq + cnt)`).
2. `Do_Mode`: EEPROM 모드를 확인한다. 정상 모드면 `Set_Config_Defaults`(전압 Undefined 등)를 실행하고 `pst.CharIn`으로 **아무 키나 기다린다**(LED 노랑). 위키 원문: "the JTAGulator's LED will turn YELLOW and it will wait until the user presses any key". 예외로, EEPROM을 읽지 못하면 키를 기다리기 전에 `'\r\nEEPROM not responding!'`을 먼저 출력하고 정상 모드로 진행한다. [소스 [L200-L206](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L200-L206)]
3. 키를 받으면 `CharIn` 규칙대로 에코하고, 배너(`InitHeader`)를 출력한 뒤 메인 프롬프트 `'\r\n\n> '`를 보낸다(LED 녹색).

Propeller ROM 부트로더와 EEPROM 로딩에 걸리는 시간은 **(미확인)**이다. 드라이버는 리셋 뒤 몇 초 동안 응답이 없을 수 있다고 보고 재시도한다.

배너 바이트열 `InitHeader` [L2782-L2794](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2782-L2794):

```python
INIT_HEADER = (
    '\r\n'
    '\n'
    '                                    UU  LLL\r\n'
    ' JJJ  TTTTTTT AAAAA  GGGGGGGGGGG   UUUU LLL   AAAAA TTTTTTTT OOOOOOO  RRRRRRRRR\r\n'
    ' JJJJ TTTTTTT AAAAAA GGGGGGG       UUUU LLL  AAAAAA TTTTTTTT OOOOOOO  RRRRRRRR\r\n'
    ' JJJJ  TTTT  AAAAAAA GGG      UUU  UUUU LLL  AAA AAA   TTT  OOOO OOO  RRR RRR\r\n'
    ' JJJJ  TTTT  AAA AAA GGG  GGG UUUU UUUU LLL AAA  AAA   TTT  OOO  OOO  RRRRRRR\r\n'
    ' JJJJ  TTTT  AAA  AA GGGGGGGGG UUUUUUUU LLLLLLLL AAAA  TTT OOOOOOOOO  RRR RRR\r\n'
    '  JJJ  TTTT AAA   AA GGGGGGGGG UUUUUUUU LLLLLLLLL AAA  TTT OOOOOOOOO  RRR RRR\r\n'
    '  JJJ  TT                  GGG             AAA                         RR RRR\r\n'
    ' JJJ                        GG             AA                              RRR\r\n'
    'JJJ                          G             A                                 RR\r\n'
    '\n'
    '\n'
    "           Welcome to JTAGulator. Press 'H' for available commands.\r\n"
    '         Warning: Use of this tool may affect target system behavior!'
)
# 웨이크 키 '\r'을 보낸 경우 전체 응답: '\r' + INIT_HEADER + '\r\n\n> '
```

### 4.2 영속 모드로 부팅한 경우

[소스 [L208-L226](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L208-L226), [L1558-L1611](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1558-L1611), [L2249-L2283](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2249-L2283)]

- EEPROM 모드가 SUMP(1)나 OCD(2)이고 저장된 전압이 유효 범위(14–33, 즉 1.4–3.3 V)이면, 텍스트 UI를 띄우지 않는다. 저장된 VADJ를 **바로 DAC로 출력**하고 바이너리 프로토콜 모드로 들어간다(LED 빨강). 배너도, 웨이크 키 대기도 없다.
- `'\x18'`을 받으면: 시리얼을 다시 시작하며 1초 대기 → EEPROM 모드를 NORMAL로 기록 → (부팅 경로로 들어온 경우) `Set_Config_Defaults` → 메시지 → 프롬프트.
  - SUMP: `'\r\nLogic analyzer mode complete.'` 다음에 `'\r\n\nGPIO> '`
  - OpenOCD: `'\r\nOpenOCD mode complete.'` 다음에 `'\r\n\nJTAG> '`
- 위키 원문: "To exit and return to normal JTAGulator functionality, open your terminal program and press `Ctrl-X`." [위키 Quick-Start, FAQ]
- [추론] 부팅 경로로 들어갔다 나오면 `Set_Config_Defaults`가 `vTargetIO = -1`로 바꾸지만 DAC 출력은 끄지 않는다([L2488-L2491](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2488-L2491)). 화면에는 `Undefined`로 보여도 VADJ 노드에는 이전 전압이 계속 나온다.
- 영속 모드 판별용 바이너리 응답(진단 용도):
  - SUMP 모드에서 `0x02`(Query ID)를 보내면 `'1ALS'` [PropSUMP L456](https://github.com/grandideastudio/jtagulator/blob/1.12/PropSUMP.spin#L456)
  - OpenOCD 모드에서 `0x00`을 보내면 `'BBIO1'`, `0x06`이면 `'OCD1'` [PropOCD L241-L242](https://github.com/grandideastudio/jtagulator/blob/1.12/PropOCD.spin#L241-L242)
  - 정상 모드에 이 바이트를 보내면 줄 입력에 섞이니 일상적으로 쓰지 않는다.

### 4.3 리셋 직후 상태 (시뮬레이터 초기값)

Spin의 `VAR`는 0으로 초기화되고, 각 `*_Init`과 `Set_Config_Defaults`가 기본값을 넣는다. [소스 [L89-L131](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L89-L131), [L482-L495](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L482-L495), [L1616-L1629](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1616-L1629), [L2167-L2170](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2167-L2170), [L2288-L2293](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2288-L2293), [L2476-L2491](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2476-L2491)]

| 변수 | 초기값 | 쓰이는 곳 / 바뀌는 때 |
|---|---|---|
| `idMenu` | MAIN | 메뉴 전환 |
| `vTargetIO` | -1 (`Undefined`) | `V` |
| `chStart`, `chEnd` | 0, 0 | 채널 범위 프롬프트의 기본값. 범위 검사를 통과해야 갱신 |
| `pinsLow`, `pinsLowDelay`, `pinsHighDelay` | 0, 100, 100 | "Bring channels LOW..." |
| `jTDI`, `jTDO`, `jTCK`, `jTMS` | 0 | JTAG 스캔 결과나 수동 입력으로 갱신 |
| `jPinsKnown` | 0 | JTAG 스캔이 성공하면 1, 결과가 없으면 0 |
| `jIgnoreReg` | 1 | `Y` |
| `jIR`, `jDRFill`, `jLoopPause` | 0, 0(L), 0 | `P` |
| `uTXD`, `uRXD`, `uBaud` | 0, 0, 0 | UART 스캔 결과나 수동 입력 |
| `uSTR`/`uHex` | 빈 문자열/0 (프롬프트에 `CR`로 표시) | `U` |
| `uPinsKnown`, `uPrintable`, `uWaitDelay`, `uBaudIgnore`, `uLocalEcho` | 0, 0, 10, 0, 0 | UART 명령들 |
| `gWriteValue` | `0xFFFFFF` | GPIO `W` |
| `swdClk`, `swdIo` | 0, 0 | SWD |
| SWD 클럭 | 100 kHz 고정(`SWD_DEFAULT_CLOCK_RATE = 100_000`) | [PropSWD L47](https://github.com/grandideastudio/jtagulator/blob/1.12/PropSWD.spin#L47) |

### 4.4 권장 재동기화 절차

[추론: §3.3의 입력 프리미티브와 각 상태의 처리 결합]

```python
def resync(ser):
    ser.reset_input_buffer()
    ser.write(b'\x18')      # (a) 패스스루·영속 모드 종료, 실행 중 스캔 중단, 스페이스바 대기 취소,
                            #     부팅 키 대기라면 웨이크(에코 '.' 후 배너)
    time.sleep(1.5)         # 영속 모드에서 빠져나올 때 pst.Start()가 1초 기다림
    ser.write(b'\x18\r')    # (b) 값 프롬프트였다면 잘못된 입력 → "Value out of range!" → 메뉴 프롬프트
                            #     메뉴 프롬프트였다면 → "? Press 'H' ..." → 메뉴 프롬프트
    # 수신 버퍼의 '끝'이 RE_MENU_PROMPT(§17)와 맞을 때까지 읽는다(타임아웃 약 3초).
    # 응답이 없으면 (리셋 직후 부팅 중일 수 있으므로) 한 번 더 반복한다.
```

이 절차가 (아래 두 예외를 빼면) 메뉴 프롬프트로 끝나는 이유:
- 메뉴 프롬프트나 값 프롬프트에 있었다면 (a)의 `0x18`은 줄 버퍼에 들어간다. (b)까지 더해지면 줄은 `'\x18\x18'`(2글자)이 된다. 메뉴에서는 잘못된 명령, 숫자·핀·hex·y/N·문자열 프롬프트에서는 모두 `"Value out of range!"`가 된다.
- 부팅 키 대기 상태라면 (a)가 웨이크 키로 쓰인다. 배너와 프롬프트가 나온 뒤 (b)는 잘못된 명령으로 처리된다.
- 스캔, 연속 모니터, 패스스루, 영속 모드, "Press any key when done...", 핀 매퍼 일시정지는 모두 (a)로 끝난다.

예외:
- **메인 메뉴 `A` 실행 중** [추론: [L251-L269](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L251-L269)]: (a)나 (b)는 지금 돌고 있는 하위 스캔만 끝낸다. 곧바로 다음 하위 스캔이 첫 질문(채널 범위 등)을 낸다. 수신 버퍼의 끝이 `RE_VALUE_PROMPT`나 `RE_SPACE_PROMPT`와 맞는 동안 `'\x18\r'`을 되풀이해 보낸다. 남은 하위 스캔 수만큼, 최대 7번 필요하다.
- **OpenOCD 모드에서 명령이 중간에 끊긴 경우** [추론: [PropOCD L155-L162, L191-L193, L233-L236](https://github.com/grandideastudio/jtagulator/blob/1.12/PropOCD.spin#L155-L162)]: `CMD_TAP_SHIFT`(0x05) 바이트 뒤로 인자가 오지 않아도 펌웨어는 `Do_Tap_Shift`를 그대로 실행한다. 이때 길이가 `0xFFFF`에서 8192로 잘려, 인자 바이트를 최대 2048개까지 **바이트마다 100 ms씩** 기다린다(최악 약 205초). 그동안 보낸 `'\x18'`은 인자로 소비된다. 응답이 없으면 사람이 리셋(SW1 또는 전원 재투입)한다. 영속 모드라 다시 OpenOCD 모드로 부팅하므로, 그 뒤 `'\x18'`을 보낸다.

재동기화 뒤의 버전 확인: 서브메뉴라면 `M\r`로 메인 메뉴로 간 다음 `I\r`를 보내고 `RE_VERSION`(§17)으로 버전을 읽는다. 지원하지 않는 버전(예: < 1.10)이면 드라이버는 자동 조작을 거부하는 편이 안전하다.

---

## 5. 프롬프트와 메뉴

### 5.1 명령 프롬프트

[소스 [L452-L473](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L452-L473)]

```python
MENU_PROMPTS = {
    'MAIN': '\r\n\n> ',
    'JTAG': '\r\n\nJTAG> ',
    'UART': '\r\n\nUART> ',
    'GPIO': '\r\n\nGPIO> ',
    'SWD':  '\r\n\nSWD> ',
}
```

모든 명령은 성공·오류·중단과 상관없이 끝나면 이 프롬프트를 다시 출력한다. 메뉴를 바꾸는 명령(`J`/`U`/`G`/`S`/`M`)은 따로 출력하는 것이 없고, 다음 프롬프트의 접두어만 바뀐다.

### 5.2 명령 파싱

[소스 [L162-L193](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L162-L193), [L476-L477](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L476-L477)]

- CR로 끝나는 한 줄을 읽어 **정확히 1글자일 때만** 명령으로 처리한다. 대소문자는 구분하지 않는다.
- 빈 줄(CR만), 2글자 이상, 메뉴에 없는 글자는 모두 아래 메시지를 낸다.
  - FW 1.12: `"\r\n? Press 'H' for available commands."`
  - FW ≤1.11.1: `'\r\n?'`

### 5.3 메뉴별 명령 키

[소스 [L237-L428](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L237-L428)]. "전압 필요"는 `vTargetIO == -1`일 때 `'\r\nTarget I/O voltage must be defined!'`를 내고 실행하지 않는다는 뜻이다.

| 메뉴 | 키 | 동작 | 전압 필요 | 절 |
|---|---|---|---|---|
| MAIN | `J` `U` `G` `S` | JTAG/UART/GPIO/SWD 메뉴로 전환 | – | |
| MAIN | `A` | 모든 스캔을 차례로 실행 | 예 | §12 |
| MAIN | `V` | 타깃 I/O 전압 설정 | – | §7 |
| MAIN | `I` | 버전 정보(**메인 메뉴에서만**) | – | §5.5 |
| MAIN | `H` | 메뉴 텍스트 | – | §5.4 |
| JTAG | `J` | Combined Scan(IDCODE + BYPASS) | 예 | §8.3 |
| JTAG | `I` | IDCODE Scan | 예 | §8.1 |
| JTAG | `B` | BYPASS Scan | 예 | §8.2 |
| JTAG | `R` | RTCK Scan | 예 | §8.4 |
| JTAG | `D` | Get Device ID(s) | 예 | §8.5 |
| JTAG | `T` | Test BYPASS | 예 | §8.6 |
| JTAG | `Y` | IR/DR discovery | 예 | §8.7 |
| JTAG | `P` | Pin mapper (EXTEST) | 예 | §8.8 |
| JTAG | `O` | OpenOCD 모드(영속) | 예 | §8.9 |
| UART | `U` | UART 핀아웃 스캔 | 예 | §9.1 |
| UART | `T` | TXD 전용 연속 스캔 | 예 | §9.2 |
| UART | `P` | UART 패스스루 | 예 | §9.3 |
| GPIO | `R` / `C` / `W` | 1회 읽기 / 연속 읽기 / 24채널 출력 | 예 | §11 |
| GPIO | `L` | 로직 분석기 모드(영속) | 예 | §11, §13 |
| SWD | `I` / `D` | SWD IDCODE 스캔 / Device ID | 예 | §10 |
| 서브메뉴 공통 | `V` / `H` / `M` | 전압 / 도움말 / 메인 메뉴로 | – | |

메인 메뉴에서 `M`을 보내면 잘못된 명령으로 처리된다.

### 5.4 `H` 출력 (정확한 바이트열)

메인 메뉴에서는 `MenuMain`만, 서브메뉴에서는 `MenuX` 다음에 `MenuShared`를 출력한다. [소스 [L431-L449](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L431-L449), [L2801-L2843](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2801-L2843)]

```python
MenuMain = (
    '\r\n'
    'Target Interfaces:\r\n'
    'J   JTAG\r\n'
    'U   UART\r\n'
    'G   GPIO\r\n'
    'S   SWD\r\n'
    'A   All (GPIO, JTAG, SWD, UART)\r\n'
    '\n'
    'General Commands:\r\n'
    'V   Set target I/O voltage\r\n'
    'I   Display version information\r\n'
    'H   Display available commands'
)
MenuJTAG = (
    '\r\n'
    'JTAG Commands:\r\n'
    'J   Identify JTAG pinout (Combined Scan)\r\n'
    'I   Identify JTAG pinout (IDCODE Scan)\r\n'
    'B   Identify JTAG pinout (BYPASS Scan)\r\n'
    'R   Identify RTCK (adaptive clocking)\r\n'
    'D   Get Device ID(s)\r\n'
    'T   Test BYPASS (TDI to TDO)\r\n'
    'Y   Instruction/Data Register (IR/DR) discovery\r\n'
    'P   Pin mapper (EXTEST Scan)\r\n'
    'O   OpenOCD interface'
)
MenuUART = (
    '\r\n'
    'UART Commands:\r\n'
    'U   Identify UART pinout\r\n'
    'T   Identify UART pinout (TXD only, continuous)\r\n'
    'P   UART passthrough'
)
MenuGPIO = (
    '\r\n'
    'GPIO Commands:\r\n'
    'R   Read all channels (input, one shot)\r\n'
    'C   Read all channels (input, continuous)\r\n'
    'W   Write all channels (output)\r\n'
    'L   Logic analyzer (OLS/SUMP)'
)
MenuSWD = (
    '\r\n'
    'SWD Commands:\r\n'
    'I   Identify SWD pinout (IDCODE Scan)\r\n'
    'D   Get Device ID'
)
MenuShared = (
    '\r\n'
    '\n'
    'General Commands:\r\n'
    'V   Set target I/O voltage\r\n'
    'H   Display available commands\r\n'
    'M   Return to main menu'
)
```

키와 설명 사이는 공백 3칸이다.

### 5.5 `I` — 버전 정보 (메인 메뉴에서만)

[소스 [L2796-L2799](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2796-L2799)]

```python
VersionInfo = (
    '\r\n'
    'JTAGulator FW 1.12\r\n'
    'Designed by Joe Grand, Grand Idea Studio, Inc.\r\n'
    'Main: jtagulator.com\r\n'
    'Source: github.com/grandideastudio/jtagulator'
)
# FW ≤1.11.1은 끝에 '\r\nSupport: www.parallax.com/support' 줄이 더 있다(1.10·1.11.1 소스에서 확인).
```

---

## 6. 여러 명령이 함께 쓰는 대화 단계

### 6.1 채널 범위 — `Get_Channels(min_chan)`

[소스 [L2595-L2629](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2595-L2629)]

```text
← '\r\nEnter starting channel [' + str(chStart) + ']: '
→ 숫자\r   (빈 줄이면 chStart)              유효: 0..23
← '\r\nEnter ending channel [' + str(D) + ']: '     D = start if chEnd < start else chEnd
→ 숫자\r   (빈 줄이면 D)                    유효: start + min_chan - 1 .. 23
```

- 범위를 벗어나면 `'\r\nValue out of range!'`를 내고 명령이 취소된다. 두 값을 모두 통과해야 `chStart`/`chEnd`가 바뀐다.
- 리셋 직후에는 `chStart = chEnd = 0`이라 끝 채널 기본값도 0이다. 이 상태에서 빈 줄로 넘기면 `min_chan ≥ 2`인 명령은 범위 오류가 난다. `min_chan = 1`인 UART `T`만 예외로, CH0 하나로 통과한다(0 ≥ 0 + 1 − 1). 드라이버는 항상 값을 보낸다.
- 명령별 `min_chan`: IDCODE 3, BYPASS 4, Combined 4, RTCK 2, SWD 2, UART 스캔 2, UART TXD 1.
- 위키 권고: 타깃 포인트를 CH0부터 차례로 연결한다. [위키 Quick-Start]

### 6.2 `Possible permutations`

[소스 [L2731-L2748](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2731-L2748)]

```text
← '\r\nPossible permutations: ' + str(n! / (n - r)!)     (끝에 줄바꿈 없음)
```

n = 채널 수에서 알려진 핀 수를 뺀 값, r = 찾아야 할 핀 수. 예: CH0–7에서 IDCODE(r=3)는 336, Combined/BYPASS(r=4)는 1680, SWD/UART(r=2)는 56. CH0–23에서 r=3은 12144, r=4는 255024. BYPASS에서 TDO/TCK/TMS를 알고 있으면 n=8−3=5, r=1이므로 5.

### 6.3 스캔 설정 — `Get_Settings`

[소스 [L2552-L2592](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2552-L2592)]

```text
← '\r\n\nBring channels LOW before each permutation? [' + ('y/N]: ' | 'Y/n]: ')
→ y\r | n\r
  (y일 때만)
← '\r\nEnter length of time for channels to remain LOW (in ms, 1 - 1000) [' + pinsLowDelay + ']: '
← '\r\nEnter length of time after channels return HIGH before proceeding (in ms, 1 - 1000) [' + pinsHighDelay + ']: '
```

이 질문을 쓰는 명령: IDCODE, BYPASS, Combined, RTCK, SWD, UART 스캔(FW 1.11부터). y를 고르면 순열을 시도할 때마다 범위 안의 모든 채널을 LOW로 `pinsLowDelay` ms 동안 내렸다가 HIGH로 올리고 `pinsHighDelay` ms를 기다린다. 리셋 신호 등으로 타깃 상태를 초기화하려는 용도다. [CHANGES 1.6](https://github.com/grandideastudio/jtagulator/blob/master/CHANGES.markdown#v1_6)

### 6.4 알려진 핀 — `Get_Pins_Known(type)`

[소스 [L2521-L2549](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2521-L2549)]

```text
← '\r\nAre any pins already known? [' + ('y/N]: ' | 'Y/n]: ')     type 0 = JTAG(jPinsKnown), 1 = UART(uPinsKnown)
```

y이면 호출한 쪽이 `'\r\nEnter X for any unknown pin.'`를 출력한 다음 핀 프롬프트를 이어 간다(BYPASS §8.2, UART §9.1).

### 6.5 스페이스바 대기 — `Wait_For_Space(errMsg)`

[소스 [L2767-L2778](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2767-L2778)]

```text
← '\r\nPress spacebar to begin (any other key besides Enter to abort)...'
→ ' '        에코 없음 → 시작
→ CR 또는 LF  무시하고 계속 기다림
→ 그 밖의 바이트  errMsg 출력 후 메뉴 프롬프트로
```

FW ≤1.11.1에서는 문구가 `'\r\nPress spacebar to begin (any other key to abort)...'`였다. 이때는 `CharIn`으로 1바이트를 읽어 **에코했고**(스페이스면 `' '`가 에코됨) CR/LF도 중단 키로 처리했다.

### 6.6 스캔 시작 문구, 진행 표시, LED

```text
← '\r\nJTAGulating! Press any key to abort...\r\n'      MsgJTAGulating L2851
```

진행 표시는 `Display_Progress(ctr, mod, char)`가 맡는다. `ctr % mod == 0`이면 LED를 토글하고, `char`가 0이 아니면 `'-'`를 출력한다(줄바꿈 없음). [L2710-L2714](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2710-L2714)

| 명령 | `ctr`가 늘어나는 때 | `'-'` 주기 (pinsLow=0 / 1) |
|---|---|---|
| JTAG `I` | 순열마다(`-` 가능), TRST 후보마다(`-` 없음) | 100 / 1 |
| JTAG `J` | 순열마다, 일치하지 않은 TDI 후보마다(`-` 가능), TRST 후보마다(`-` 없음) | 100 / 1 |
| JTAG `B` | 순열마다(`-` 가능), TRST 후보마다(`-` 없음) | 10 / 1 |
| JTAG `R` | 순열마다 | 10 / 1 |
| SWD `I` | 순열마다 | 30 / 1 |
| UART `U` | (TXD,RXD) 쌍마다. 21개 보율을 모두 시도한 뒤 | 1 (pinsLow와 무관) |
| UART `T` | 변화 대기 루프를 돌 때마다(`ctr`) / 무시한 펄스를 검출할 때마다(`ctr_in`) | 대기 루프 16384회마다 / 무시한 펄스 30회마다 (pinsLow와 무관) |
| JTAG `Y` | opcode마다. `-`는 "Ignore single-bit"가 Y일 때만 | 8 (pinsLow와 무관) |
| JTAG `P` | BSR을 채울 때마다 `-`, 레지스터를 한 바퀴 돌 때마다 `'\|'` | 1 (pinsLow와 무관) |

결과 블록은 대부분 `'\r\n'`으로 시작하므로 `-`가 이어진 부분은 보통 자기 줄을 따로 차지한다(정규화 후 `^[-|]*$`).

**예외 — JTAG `Y`(IR/DR discovery)** [소스 [L1108-L1119](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1108-L1119), [L1493-L1508](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1493-L1508)]: 결과 줄 `IR: ...`은 앞에 `'\r\n'` 없이 출력된다. "Ignore single-bit"가 Y이면, 연속한 두 opcode가 모두 출력되고 그 사이에 `ctr`이 8의 배수가 되는 경우가 있다. 이때는 구분 표시(`'-\r\n'`, 건너뛴 opcode가 있을 때만 출력)가 나오지 않으므로 진행 `'-'`가 다음 결과 줄 앞에 붙는다. 예: `'IR: 0111 (0x7) -> DR: 32\r\n-IR: 1000 (0x8) -> DR: 32\r\n'`. 파서는 `IR:` 앞의 `-`를 허용해야 한다(§17의 `RE_IRDR`).

### 6.7 중단 동작

- 스캔 루프는 순열(UART는 보율, 핀 매퍼는 레지스터 비트)을 시도하기 직전에 `pst.RxEmpty`를 확인한다. 바이트가 있으면 정리하고 중단 메시지를 낸 뒤 `RxFlush`로 수신 버퍼를 비우고 메뉴 프롬프트로 돌아간다. 중단 키는 에코되지 않는다.
- JTAG `I`/`J`/`B`, UART `U`, SWD `I`는 중단될 때까지 찾은 마지막 핀아웃을 기억한다(다음 프롬프트의 기본값). 하나도 찾지 못한 채 중단하면 정리 함수가 핀 값을 0으로 지운다. 그러나 `jPinsKnown`/`uPinsKnown`은 정상 종료 때만 0으로 바뀌므로 중단하면 이전 값이 남는다. RTCK 스캔은 결과를 전역 변수에 아예 저장하지 않는다. [소스 [L1464-L1471](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1464-L1471), [L2082-L2090](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2082-L2090), [L2396-L2404](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2396-L2404), [L857-L976](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L857-L976)]
- 중단하면 "scan complete"와 "No target device(s) found!"는 나오지 않는다.

| 명령 | 스페이스바 대기에서 다른 키 | 실행 중 키 입력 |
|---|---|---|
| JTAG `I` | `'\r\nIDCODE scan aborted!'` | 같음 |
| JTAG `J` | `'\r\nJTAG combined scan aborted!'` (≤1.11.1: `'\r\nJTAG scan aborted!'`) | 같음 |
| JTAG `B` | `'\r\nBYPASS scan aborted!'` | 같음 |
| JTAG `R` | `'\r\nRTCK scan aborted!'` | 같음 |
| JTAG `Y` | `'\r\nIR/DR discovery aborted!'` | 같음 |
| JTAG `P` | `'\r\nPin mapper aborted!'` | 중단 메시지 없이 `'\r\nPin mapper complete.'` |
| UART `U` | `'\r\nUART scan aborted!'` | 같음 |
| UART `T` | `'\r\nUART scan aborted!'` | 키 입력이 정상 종료 경로. `'\r\nUART TXD scan complete.'` |
| SWD `I` | `'\r\nIDCODE scan aborted!'` | 같음 |
| GPIO `C` | (스페이스바 대기 없음) | 메시지 없이 프롬프트 |

### 6.8 완료·오류 메시지 목록

[소스 [L2845-L2892](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2845-L2892)]

| 명령 | 완료 문자열 |
|---|---|
| JTAG `I`, SWD `I` | `'\r\nIDCODE scan complete.'` (두 명령이 같은 문구. 어떤 스캔을 시작했는지는 드라이버가 기억해야 함) |
| JTAG `J` | `'\r\nJTAG combined scan complete.'` (≤1.11.1: `'\r\nJTAG scan complete.'`) |
| JTAG `B` | `'\r\nBYPASS scan complete.'` |
| JTAG `R` | `'\r\nRTCK scan complete.'` |
| UART `U` | `'\r\nUART scan complete.'` |
| UART `T` | `'\r\nUART TXD scan complete.'` |
| JTAG `D`, SWD `D` | `'\r\nIDCODE listing complete.'` |
| JTAG `Y` | `'\r\nIR/DR discovery complete.'` |
| JTAG `P` | `'\r\nPin mapper complete.'` |
| UART `P` | `'\r\nUART passthrough complete.'` |
| JTAG `O` | `'\r\nOpenOCD mode complete.'` |
| GPIO `L` | `'\r\nLogic analyzer mode complete.'` |
| JTAG `T` | `'\r\nMatch!'` 또는 `'\r\nNo Match!'` (별도 완료 문구 없음) |

```python
ErrEEPROMNotResponding = '\r\nEEPROM not responding!'
ErrTargetIOVoltage     = '\r\nTarget I/O voltage must be defined!'
ErrOutOfRange          = '\r\nValue out of range!'
ErrPinCollision        = '\r\nPin numbers must be unique!'
ErrNoDeviceFound       = '\r\nNo target device(s) found!'
ErrTooManyDevices      = '\r\nMore than one device detected in the chain!'   # ≤1.11: 'Too many devices in the chain!'
InvalidCommand         = "\r\n? Press 'H' for available commands."           # ≤1.11.1: '\r\n?'
```

---

## 7. 타깃 I/O 전압 (`V`, 모든 메뉴)

[소스 [L2494-L2518](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2494-L2518), [L2701-L2707](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2701-L2707), [L2894-L2898](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2894-L2898)]

```text
← '\r\nCurrent target I/O voltage: ' + ('Undefined' | 'x.y')
← '\r\nEnter new target I/O voltage (1.4 - 3.3, 0 for off): '
→ 값\r                                    (Get_Decimal_Pin)
   값 == 0       → '\r\nTarget I/O voltage off.'           (vTargetIO=-1, DAC off)
   14 ≤ 값 ≤ 33  → '\r\nNew target I/O voltage set: x.y'
                   '\r\nWarning: Ensure VADJ is NOT connected to target!'
   그 밖         → '\r\nValue out of range!'                (기존 값 유지)
```

입력값 해석(`'.'`·`','`는 무시하고 숫자만 이어 붙인 뒤, 정수 2와 3만 예외로 처리):

| 입력 | 해석 | 결과 |
|---|---|---|
| `3.3`, `33`, `3,3` | 33 | 3.3 V |
| `1.8` | 18 | 1.8 V |
| `2`, `3` | 20, 30 | 2.0 V, 3.0 V (FW 1.5부터 정수 허용) |
| `0`, `00`, `0.0` | 0 | 끔 |
| `1`, `1.0`, `3.30`, `3.3V`, 빈 줄 | 1, 10, 330, -3, -1 | `Value out of range!` |

- 유효 값: 1.4–3.3 V, 0.1 V 단위 20단계. 각 값은 DAC 표 `VoltageTable = 109, 116, … , 255`(1.4 → 109, 3.3 → 255)로 바뀐다. 하한 1.4 V는 TXS0108E 데이터시트 때문이다(소스 주석 "TXS0108E level translator is limited from 1.4V to 3.3V per data sheet table 6.3", FW 1.7 이전에는 1.2 V).
- 전압을 설정하는 즉시 VADJ에 출력된다(DAC).
- 전압 미설정 상태의 게이트: §5.3 표에서 "전압 필요"인 명령은 모두 `'\r\nTarget I/O voltage must be defined!'`만 내고 바로 프롬프트로 돌아간다. 질문은 하나도 나오지 않는다.
- 리셋하면 `Undefined`로 돌아가고 DAC도 0이 된다. 위키 Quick-Start: "Set the target I/O voltage (VADJ) using the `V` command. This will ensure that the target receives signals within its acceptable logic levels."

예시(합성):

```text
→ 'V\r'
← 'V\r'
← '\r\nCurrent target I/O voltage: Undefined'
← '\r\nEnter new target I/O voltage (1.4 - 3.3, 0 for off): '
→ '3.3\r'
← '3.3\r'
← '\r\nNew target I/O voltage set: 3.3'
← '\r\nWarning: Ensure VADJ is NOT connected to target!'
← '\r\n\n> '
```

---

## 8. JTAG 명령 (`JTAG>`)

### 8.1 IDCODE Scan (`I`)

[소스 [L498-L698](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L498-L698) (type 0)]

**대화 순서**

1. `Get_Channels(3)` (§6.1)
2. `'\r\nPossible permutations: ' + P(n,3)`
3. `Get_Settings` (§6.3)
4. `Wait_For_Space(ErrIDCODEAborted)` (§6.5)
5. `'\r\nJTAGulating! Press any key to abort...\r\n'`
6. 진행 표시와 결과 블록
7. 결과가 없으면 `'\r\nNo target device(s) found!'`
8. `'\r\nIDCODE scan complete.'` 다음에 `'\r\n\nJTAG> '`

**동작**

- 순열은 TDO(바깥) → TCK → TMS(안쪽) 순서로, 각각 `chStart..chEnd`에서 서로 다른 값을 고른다.
- 각 순열에서 **범위 안의 모든 채널을 출력 HIGH로 만든 뒤**(선택 시 LOW 펄스), TDO만 입력으로 바꾸고 TAP 리셋 직후 DR에서 32비트를 읽는다. 읽은 값이 `0xFFFFFFFF`가 아니고 bit0 = 1이면 결과로 친다.
- TDI는 쓰지 않는다. 내부적으로 채널이 아닌 핀(P29)으로 돌려놓기 때문에 결과에 `N/A`로 나온다.
- 결과가 나오면 최대 32개의 IDCODE를 읽는다. 이어 남은 채널을 하나씩 LOW로 100 ms 유지한 채 첫 IDCODE를 다시 읽고, 값이 바뀌면 그 채널을 `TRST#` 후보로 출력한다.

**결과 블록(정확한 형식)**

```text
'\r\nTDI: N/A\r\nTDO: <d>\r\nTCK: <d>\r\nTMS: <d>\r\n'
'Device ID #<n>: <vvvv> <pppppppppppppppp> <mmmmmmmmmmm> 1 (0x<HHHHHHHH>)\r\n'   × 유효한 ID 수
'TRST#: <d>\r\n'                                                                  × 0개 이상
'\r\n'
```

- Device ID 줄 [L1511-L1555](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1511-L1555): IEEE 1149.1 필드를 2진수로 나눠 쓴다. Version(31..28, 4비트), Part Number(27..12, 16비트), Manufacturer(11..1, 11비트), 고정 1(bit0). 그 뒤에 8자리 대문자 hex가 붙는다. `0xFFFFFFFF`나 bit0 = 0인 값은 출력하지 않는다.
- `#1`은 TDO에 가장 가까운 장치다. [추론: TDO에서 먼저 나오는 32비트를 #1로 저장함, PropJTAG [L284-L319](https://github.com/grandideastudio/jtagulator/blob/1.12/PropJTAG.spin#L284-L319)]
- 제조사 11비트는 JEP106 코드(상위 4비트 = continuation 개수, 하위 7비트 = ID)로 해석한다. 펌웨어는 디코딩하지 않으므로 드라이버가 처리한다. (이 해석 규칙의 1차 출처는 본 문서에서 검증하지 않음)

**예시(합성)** — CH0–7, 타깃 TDO=2/TCK=0/TMS=1, IDCODE `0x4BA00477`:

```text
→ 'I\r'                                      ← 'I\r'
← '\r\nEnter starting channel [0]: '         → '0\r'   ← '0\r'
← '\r\nEnter ending channel [0]: '           → '7\r'   ← '7\r'
← '\r\nPossible permutations: 336'
← '\r\n\nBring channels LOW before each permutation? [y/N]: '   → 'n\r'   ← 'n\r'
← '\r\nPress spacebar to begin (any other key besides Enter to abort)...'
→ ' '                                        (에코 없음)
← '\r\nJTAGulating! Press any key to abort...\r\n'
← '\r\nTDI: N/A\r\nTDO: 2\r\nTCK: 0\r\nTMS: 1\r\nDevice ID #1: 0100 1011101000000000 01000111011 1 (0x4BA00477)\r\n\r\n---\r\nIDCODE scan complete.'
← '\r\n\nJTAG> '
```

렌더링:

```text
JTAG> I
Enter starting channel [0]: 0
Enter ending channel [0]: 7
Possible permutations: 336

Bring channels LOW before each permutation? [y/N]: n
Press spacebar to begin (any other key besides Enter to abort)...
JTAGulating! Press any key to abort...

TDI: N/A
TDO: 2
TCK: 0
TMS: 1
Device ID #1: 0100 1011101000000000 01000111011 1 (0x4BA00477)

---
IDCODE scan complete.

JTAG>
```

**스캔 뒤 상태**: 결과가 있으면 `jPinsKnown = 1`, `jTDI = 0`, `jTDO/jTCK/jTMS` = 마지막 결과. 결과가 없으면 모두 0. [L1464-L1471](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1464-L1471)

**오탐**: 모든 순열을 돌면서 정체를 모르는 핀을 구동하기 때문에 타깃이 엉뚱하게 응답해 오탐이 생길 수 있다. 사람이 결과를 확인해야 한다. [위키 FAQ "Why do I get different responses ... on repeated tries?"]

### 8.2 BYPASS Scan (`B`)

[소스 [L701-L854](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L701-L854), [L1383-L1461](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1383-L1461)]

**대화 순서**

1. `Get_Channels(4)`
2. `Get_Pins_Known(0)`: `'\r\nAre any pins already known? [y/N]: '`
3. (y이면) `'\r\nEnter X for any unknown pin.'` 다음 `Set_JTAG_Partial`, 순서는 **TDI → TDO → TCK → TMS**
   - `'\r\nEnter TDI pin [<jTDI>]: '`, `'\r\nEnter TDO pin [<jTDO>]: '`, `'\r\nEnter TCK pin [<jTCK>]: '`, `'\r\nEnter TMS pin [<jTMS>]: '`
   - 입력은 `Get_Pin`(X 허용). 유효 범위는 −2..`chEnd`. `chStart`보다 작은 값은 검사하지 않아 그대로 통과한다. 빈 줄이면 현재값.
   - 알려진 핀끼리 겹치면 `'\r\nPin numbers must be unique!'`
4. `'\r\nPossible permutations: ' + P(n − 알려진 핀 수, 모르는 핀 수)`
5. `Get_Settings`
6. `Wait_For_Space(ErrBYPASSAborted)`
7. `MsgJTAGulating`, 진행, 결과
8. (없으면) `ErrNoDeviceFound`, 이어 `'\r\nBYPASS scan complete.'`

**동작**: TDI → TDO → TCK → TMS 순서의 4중 순열이다. 각 순열에서 체인 장치 수를 센 다음(`Detect_Devices`, 0–31. 32개 이상이면 0으로 처리됨, [PropJTAG L153-L158](https://github.com/grandideastudio/jtagulator/blob/1.12/PropJTAG.spin#L153-L158)), 32비트 난수 패턴을 BYPASS로 통과시켜 그대로 돌아오면 일치로 본다. 일치하면 TRST# 후보를 찾는다(장치 수가 바뀌는 채널). [PropJTAG L110-L281](https://github.com/grandideastudio/jtagulator/blob/1.12/PropJTAG.spin#L110-L281)

**결과 블록**

```text
'\r\nTDI: <d>\r\nTDO: <d>\r\nTCK: <d>\r\nTMS: <d>\r\n'
'TRST#: <d>\r\n'                         × 0개 이상
'Number of devices detected: <n>\r\n'
```

**예시(합성)** — §8.1에 이어 실행. 기본값이 바뀐 것(`[Y/n]`, `[2]` 등)에 주목:

```text
→ 'B\r'
← '\r\nEnter starting channel [0]: '              → '0\r'
← '\r\nEnter ending channel [7]: '                → '7\r'
← '\r\nAre any pins already known? [Y/n]: '       → 'y\r'
← '\r\nEnter X for any unknown pin.'
← '\r\nEnter TDI pin [0]: '                       → 'x\r'
← '\r\nEnter TDO pin [2]: '                       → '2\r'
← '\r\nEnter TCK pin [0]: '                       → '0\r'
← '\r\nEnter TMS pin [1]: '                       → '1\r'
← '\r\nPossible permutations: 5'
← '\r\n\nBring channels LOW before each permutation? [y/N]: '   → 'n\r'
← '\r\nPress spacebar to begin (any other key besides Enter to abort)...'   → ' '
← '\r\nJTAGulating! Press any key to abort...\r\n'
← '\r\nTDI: 3\r\nTDO: 2\r\nTCK: 0\r\nTMS: 1\r\nNumber of devices detected: 1\r\n\r\nBYPASS scan complete.'
← '\r\n\nJTAG> '
```

(각 입력의 에코는 생략함.) 위키 FAQ에 따르면 IDCODE를 지원하지 않거나 보안 기능이 켜진 타깃도 규격상 BYPASS는 지원해야 하므로, BYPASS로만 찾히는 경우가 있다.

### 8.3 Combined Scan (`J`, "JTAG Scan")

[소스 L498-L698 (type 1), [CHANGES 1.8](https://github.com/grandideastudio/jtagulator/blob/master/CHANGES.markdown#v1_8)]

- **대화**: `Get_Channels(4)`, `Possible permutations: P(n,4)`, `Get_Settings`, `Wait_For_Space(ErrJTAGAborted)`, `MsgJTAGulating`.
- **동작**: IDCODE 스캔처럼 TDO/TCK/TMS 순열을 돌다가 유효한 IDCODE를 만나면, 남은 채널을 TDI 후보로 하나씩 넣어 BYPASS 시험을 한다. 일치하면 결과를 출력하고 그 TDI에서 탐색을 멈춘다. 일치한 경우에만 TRST# 탐색과 `'\r\n'`이 이어진다. IDCODE는 보였지만 TDI를 찾지 못한 순열은 **아무것도 출력하지 않는다.**
- **결과 블록**: `'\r\nTDI: <d>\r\nTDO: <d>\r\nTCK: <d>\r\nTMS: <d>\r\n'`, 이어 `Device ID #n ...` × (감지된 장치 수), `TRST#: d\r\n` × k, `'\r\n'`.
- **완료**: `'\r\nJTAG combined scan complete.'` (FW ≤1.11.1은 `'\r\nJTAG scan complete.'`)

### 8.4 RTCK Scan (`R`)

[소스 [L857-L976](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L857-L976), [CHANGES 1.10](https://github.com/grandideastudio/jtagulator/blob/master/CHANGES.markdown#v1_10)]

```text
Get_Channels(2)
← '\r\nIs TCK already known? [' + ('y/N]: ' | 'Y/n]: ')       기본값은 jPinsKnown. 답은 이번 실행에서만 쓰임
  (y이면) '\r\nEnter X if pin is unknown.' + '\r\nEnter TCK pin [<jTCK>]: '    Get_Pin, 범위 -2..chEnd
'\r\nPossible permutations: ' + P(n − k, 2 − k)
Get_Settings → Wait_For_Space(ErrRTCKAborted) → MsgJTAGulating
결과: '\r\nTCK: <d>\r\nRTCK: <d>\r\n'        (TCK를 10번 토글하는 동안 RTCK가 10번 모두 따라오면)
(없으면) ErrNoDeviceFound → '\r\nRTCK scan complete.'
```

### 8.5 Get Device ID(s) (`D`) — 핀아웃을 알고 있을 때

[소스 [L979-L1002](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L979-L1002), `Set_JTAG(0)` [L1314-L1380](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1314-L1380)]

```text
← '\r\nTDI not needed to retrieve Device ID.\r\n'
← '\r\nEnter TDO pin [<jTDO>]: '  ← '\r\nEnter TCK pin [<jTCK>]: '  ← '\r\nEnter TMS pin [<jTMS>]: '
   (Get_Decimal_Pin, 0..23, X 불가, 서로 달라야 함)
결과(장치마다, 상세 포함):
'\r\n\nDevice ID #<n>: <bits> (0x<HHHHHHHH>)\r\n-> Manufacturer ID: 0x<HHH>\r\n-> Part Number: 0x<HHHH>\r\n-> Version: 0x<H>\r\n'
← '\r\nIDCODE listing complete.'
```

예시(합성) 결과 부분: `'\r\n\nDevice ID #1: 0100 1011101000000000 01000111011 1 (0x4BA00477)\r\n-> Manufacturer ID: 0x23B\r\n-> Part Number: 0xBA00\r\n-> Version: 0x4\r\n'`

[추론] 장치가 없을 때 `'No target device(s) found!'`는 **출력되지 않는다.** 코드는 `repeat i from 0 to 31` 다음에 `if (i == 0)`을 검사하는데, Spin에서 루프가 끝나면 `i`는 32다. 그래서 장치가 없으면 핀 프롬프트 바로 뒤에 `'\r\nIDCODE listing complete.'`만 나온다.

### 8.6 Test BYPASS (`T`)

[소스 [L1005-L1035](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1005-L1035)]

```text
Set_JTAG(1): '\r\nEnter TDI pin [..]: ' → TDO → TCK → TMS   (Get_Decimal_Pin, 0..23, 서로 달라야 함)
← '\r\n' + 'Number of devices detected: <n>'
   n == 0 → '\r\nNo target device(s) found!' 후 종료
← '\r\nPattern in to TDI:    ' + 32자리 2진수      (난수 패턴)
← '\r\nPattern out from TDO: ' + 32자리 2진수
← '\r\nMatch!'  |  '\r\nNo Match!'
```

예: `'\r\nPattern in to TDI:    01011010001111001001011011100001'`. 콜론 뒤 공백은 "in" 줄이 4칸, "out" 줄이 1칸이라 두 패턴의 열이 맞는다.

### 8.7 IR/DR discovery (`Y`) — 체인에 장치가 하나일 때

[소스 [L1038-L1122](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1038-L1122), [L1493-L1508](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1493-L1508), [L2717-L2728](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2717-L2728)]

```text
Set_JTAG(1)
← '\r\nIgnore single-bit Data Registers? [' + ('Y/n]: ' 기본 | 'y/N]: ')
   장치 0개 → ErrNoDeviceFound / 2개 이상 → ErrTooManyDevices (종료)
← '\r\n' + 'Instruction Register (IR) length: ' + (<n> | 'N/A' + ErrOutOfRange 후 종료)
← '\r\nPossible instructions: ' + 2^n
Wait_For_Space(ErrDiscoveryAborted) → MsgJTAGulating
결과 줄: 'IR: <2진수 그룹> (0x<hex>) -> DR: <len>\r\n'
   (Ignore=Y일 때 출력이 건너뛴 구간 뒤에는 '-' + '\r\n' 구분 표시)
← '\r\nIR/DR discovery complete.'
```

- 2진수 표기: IR 길이가 8 미만이면 한 덩어리, 8 이상이면 8비트씩 끊는다. 각 덩어리 뒤에 공백이 하나 붙는다. hex 자릿수는 IR 길이를 4의 배수로 올려 4로 나눈 값이다.
  - 예: `'IR: 0010 (0x2) -> DR: 32\r\n'`, `'IR: 11110 (0x1E) -> DR: 32\r\n'`, `'IR: 11 11111111 (0x3FF) -> DR: 1\r\n'`
- [추론] 펌웨어 표시 버그: IR 길이가 16보다 크고 8의 배수가 아니면, 첫 덩어리는 실제 상위 비트가 아니라 bit (7+mod)..8을 보여 준다(mod = IR 길이 % 8, 원인은 `Bin(data >> 8, mod)`). 예를 들어 IR이 20비트면 bit 11..8, 17비트면 bit 8, 23비트면 bit 14..8이 나온다. hex 값은 정확하므로 파서는 hex를 기준으로 삼는다.
- [추론] `Detect_IR_Length`는 0 또는 2–31만 돌려준다. 루프가 끝나 32가 되면 0으로 바꾸고, 2 미만도 0으로 바꾼다. [PropJTAG L190-L195](https://github.com/grandideastudio/jtagulator/blob/1.12/PropJTAG.spin#L190-L195) 그래서 IR이 32비트인 장치는 `'Instruction Register (IR) length: N/A'` + `'\r\nValue out of range!'`로 끝나고, `Bits_to_Value(32)` 넘침 때문에 `Possible instructions: 0`이 찍히는 경로에는 실제로 도달하지 않는다. 대신 IR이 31비트이면 2^31이 부호 있는 32비트 범위를 넘어 `pst.Dec`가 `Possible instructions: -2147483648`처럼 **음수**로 출력한다.

### 8.8 Pin mapper / EXTEST Scan (`P`) — 체인에 장치가 하나일 때

[소스 [L1125-L1311](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1125-L1311), [CHANGES 1.11](https://github.com/grandideastudio/jtagulator/blob/master/CHANGES.markdown#v1_11)]

```text
Set_JTAG(1) → (장치 수 검사) → '\r\n' + 'Instruction Register (IR) length: <n>'
← '\r\n\nEnter EXTEST instruction (in hex) [' + hex(jIR, IR길이를 4의 배수로 올림/4 자리) + ']: '
   빈 줄=유지, hex 글자만 허용, 자릿수 초과 시 ErrOutOfRange
← '\r\nBoundary Scan Register length: ' + (<n> | 'N/A' + ErrOutOfRange)    (n == 1이어도 ErrOutOfRange)
← '\r\n\nFill Boundary Scan Register with HIGH or LOW? [' + ('h/L]: ' | 'H/l]: ')
← '\r\n\nPause after successful detection? [' + ('y/N]: ' | 'Y/n]: ')
Wait_For_Space(ErrEXTESTAborted) → MsgJTAGulating
진행: BSR을 채울 때마다 '-', 한 바퀴마다 '|'
결과: '\r\nCH<d> -> Register bit: <n>\r\n'
   (Pause=Y이면) 'Press spacebar to continue (any other key to abort)...' → CharIn(에코)
                 스페이스면 '\r\n' 출력 후 계속, 다른 키면 종료
아무 키(실행 중) → '\r\nPin mapper complete.'
```

위키 FAQ: 같은 채널에서 서로 다른 레지스터 비트가 두 개 보이면 출력 활성(OE) 제어선일 수 있다.

### 8.9 OpenOCD 모드 (`O`) — 영속 모드

[소스 [L1558-L1611](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1558-L1611), [PropOCD.spin](https://github.com/grandideastudio/jtagulator/blob/1.12/PropOCD.spin), 위키 [OpenOCD](https://github.com/grandideastudio/jtagulator/wiki/OpenOCD)]

```python
MsgModeWarning = (
    '\r\n'
    'Warning: This mode persists through JTAGulator resets, power cycles,\r\n'
    'and firmware updates. It can only be exited manually by the user.\r\n'
)
# 다음으로 Set_JTAG(1) 핀 질문 4개 → EEPROM에 모드·전압·핀 기록 (실패 시 '\r\nEEPROM not responding!')
# '\r\nEntering OpenOCD mode! Press Ctrl-X to exit...' 다음에:
MsgOCDNote = (
    '\r\n'
    '\n'
    'Example: openocd -f interface/buspirate.cfg -c "transport select jtag; buspirate port /dev/ttyUSB0"\r\n'
)
```

- 100 ms 뒤 텍스트 UI를 멈추고 Bus Pirate 바이너리 JTAG 프로토콜(115200)을 흉내 낸다. 위키 권장 명령: `openocd -f interface/buspirate.cfg -c "transport select jtag; buspirate port <port>" -f <target>`. 속도는 초당 수백 바이트 수준으로 느리다.
- 진입하면 0번부터 24번 핀까지 HIGH로 설정한다(`u.Set_Pins_High(0, g#MAX_CHAN)`, [PropOCD L79](https://github.com/grandideastudio/jtagulator/blob/1.12/PropOCD.spin#L79)). 24번은 `TXS_OE`다.
- 종료는 명령 바이트 자리에서 `'\x18'`을 받는 것이다. 1초 뒤 `'\r\nOpenOCD mode complete.'`, 이어 `'\r\n\nJTAG> '`.
- 이 mcp 프로젝트에서는 디버깅·덤프를 `openocd-mcp`와 전용 어댑터로 하는 편이 낫다. `O` 모드는 영속성 때문에 자동화하기에 위험 요소가 크다(§15).

---

## 9. UART 명령 (`UART>`)

UART 핀 이름은 **타깃 기준**이다. TXD는 타깃이 송신하는 핀(JTAGulator가 받음), RXD는 타깃이 수신하는 핀(JTAGulator가 보냄). 모든 UART 명령은 처음에 `"\r\nNote: UART pin naming is from the target's perspective."`를 출력한다. [L2863](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2863)

### 9.1 UART 핀아웃 스캔 (`U`)

[소스 [L1632-L1804](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1632-L1804), [L1900-L1929](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1900-L1929), [L2036-L2079](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2036-L2079), [L2093-L2112](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2093-L2112)]

**대화 순서(FW 1.12)**

1. `"\r\nNote: UART pin naming is from the target's perspective."`
2. `Get_Channels(2)`
3. `'\r\nAre any pins already known? [y/N]: '` (기본값 `uPinsKnown`)
4. (y이면) `'\r\nEnter X for any unknown pin.'`, `'\r\nEnter TXD pin [<uTXD>]: '`, `'\r\nEnter RXD pin [<uRXD>]: '`
   - `Get_Pin`, 범위 −2..23. 두 값이 같으면(둘 다 X여도) `ErrPinCollision`.
5. `'\r\nPossible permutations: ' + P(n − k, 2 − k)`
6. `'\r\nEnter text string to output (prefix with \\x for hex) [' + 기본표시 + ']: '` (Python 리터럴. 화면에는 `prefix with \x for hex`로 보임)
   - 기본표시: 아직 설정하지 않았으면 `CR`. ASCII면 그 문자열. hex면 `\x` + 바이트마다 대문자 hex 2자리.
7. `'\r\nEnter delay before checking for target response (in ms, 0 - 1000) [<uWaitDelay>]: '` (기본 10)
8. `'\r\n\nIgnore non-printable characters? [y/N]: '`
9. `Get_Settings` (FW 1.11부터)
10. `Wait_For_Space(ErrUARTAborted)`
11. `MsgJTAGulating`, 진행, 결과
12. (없으면) `ErrNoDeviceFound`, 이어 `'\r\nUART scan complete.'`

**보낼 문자열 규칙** (입력 버퍼 34글자)

| 형태 | 조건 | 실제로 보내는 바이트 |
|---|---|---|
| 빈 줄 | – | 이전 설정 유지. 초기값은 빈 문자열이라 CR(0x0D)만 보냄 |
| ASCII | 0x20–0x7E만, 최대 16글자 | 문자열 + **CR(0x0D)** |
| hex | `\x`(소문자 x)로 시작, 이어지는 hex 자릿수가 짝수, 1–16바이트(`\x` + 최대 32자리) | 그 바이트만(**CR 붙지 않음**) |

비출력 문자, 17글자 이상 ASCII, `\x`만 입력, 홀수 자릿수, hex가 아닌 글자는 모두 `ErrOutOfRange`다. 예: `\x0D0A`(CR LF), `\x03`(Ctrl-C).

**동작**: TXD(바깥) → RXD(안쪽) 순열마다 범위 안의 모든 채널을 HIGH로 만든 뒤(선택 시 LOW 펄스), 아래 보율 21개를 차례로 시도한다. [L2900-L2901](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2900-L2901)

```python
BAUD_TABLE = [300, 600, 1200, 1800, 2400, 3600, 4800, 7200, 9600, 14400, 19200, 28800,
              31250, 38400, 57600, 76800, 115200, 153600, 230400, 250000, 307200]
```

각 보율에서 UART를 8N1로 열고 문자열을 보낸 뒤 `uWaitDelay` ms를 기다린다. 이어 바이트당 최대 20 ms씩 기다리며 응답을 **최대 16바이트**까지 모은다(`UART_SCAN_DELAY = 20`, `MAX_LEN_UART_RX = 16`). 1바이트라도 받으면 결과로 친다. "Ignore non-printable"이 y이면, 응답에 CR/LF를 뺀 비출력 바이트가 하나라도 있을 때 그 결과를 통째로 버린다.

**결과 블록**

```text
'\r\nTXD: <d>\r\nRXD: <d>\r\nBaud: <baud>\r\n'
'Data: <ASCII, 0x20-0x7E 밖은 '.'> [ <HH >... ]\r\n'
```

예: `'Data: ..#  [ 0D 0A 23 20 ]\r\n'` (응답 `b'\r\n# '`). ASCII 부분과 hex 바이트 수는 1:1로 대응한다. 실제 타깃은 같은 핀 쌍에서 여러 보율로 깨진 데이터를 함께 보여 주는 경우가 많다. 이때는 읽을 수 있는 데이터와 CR/LF가 보이는 보율을 고른다(FW 1.6 실측 예: [hcw.ac.at](https://elvis.hcw.ac.at/wiki/index.php/JTAGulator:_Find_IoT-Device%27s_UART_interface)에서 TXD 2/RXD 3에 19200·57600·76800 결과가 동시에 나옴).

**예시(합성)** — CH0–3, 타깃 TXD=1/RXD=0 @115200. `'\r'`을 받으면 `'\r\n# '`로 응답한다고 가정(에코 생략):

```text
← "\r\nNote: UART pin naming is from the target's perspective."
← '\r\nEnter starting channel [0]: '        → '0\r'
← '\r\nEnter ending channel [0]: '          → '3\r'
← '\r\nAre any pins already known? [y/N]: ' → 'n\r'
← '\r\nPossible permutations: 12'
← '\r\nEnter text string to output (prefix with \\x for hex) [CR]: '    → '\r'
← '\r\nEnter delay before checking for target response (in ms, 0 - 1000) [10]: '   → '10\r'
← '\r\n\nIgnore non-printable characters? [y/N]: '                   → 'n\r'
← '\r\n\nBring channels LOW before each permutation? [y/N]: '         → 'n\r'
← '\r\nPress spacebar to begin (any other key besides Enter to abort)...'   → ' '
← '\r\nJTAGulating! Press any key to abort...\r\n'
← '---\r\nTXD: 1\r\nRXD: 0\r\nBaud: 115200\r\nData: ..#  [ 0D 0A 23 20 ]\r\n---------\r\nUART scan complete.'
← '\r\n\nUART> '
```

(위 바이트열에서 `\\x`는 Python 리터럴 안의 백슬래시 한 글자다. 장치가 보내는 실제 텍스트는 `prefix with \x for hex`.)

**스캔 뒤 상태**: 결과가 있으면 `uPinsKnown = 1`, `uTXD/uRXD/uBaud` = 마지막 결과. 없으면 0.

### 9.2 TXD 전용 연속 스캔 (`T`)

[소스 [L1807-L1897](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1807-L1897), [L1932-L1957](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1932-L1957), [L2115-L2162](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2115-L2162), [CHANGES 1.10](https://github.com/grandideastudio/jtagulator/blob/master/CHANGES.markdown#v1_10)]

```text
← "\r\nNote: UART pin naming is from the target's perspective."
Get_Channels(1)
← '\r\n\nIgnore non-standard baud rates? [' + ('y/N]: ' | 'Y/n]: ')
Wait_For_Space(ErrUARTAborted)
← '\r\nNote: This scan will continuously monitor all channels for UART\r\nactivity until aborted.'
← '\r\nJTAGulating! Press any key to abort...\r\n'
결과(활동이 감지될 때마다, 같은 채널이 반복 출력될 수 있음):
'\r\nTXD: <d>\r\nBaud (Measured): <측정값>\r\nBaud (Best Fit): <표준 보율> | N/A\r\n'
아무 키 → '\r\nUART TXD scan complete.'        ('aborted'나 'No target device(s) found!'는 출력하지 않음)
```

- **수동 스캔이다.** 범위 안의 채널을 모두 입력으로 둔다(`u.Set_Pins_Input`). 타깃 핀을 능동적으로 구동하지 않으므로(아래의 약한 풀업은 예외) 가장 안전한 첫 단계다.
- 측정 방식: 상태가 바뀐 채널마다 50 ms 동안 LOW 펄스(high-low-high) 폭을 잰다. 32개를 모두 잡은 채널만 결과가 된다. 펄스 폭을 오름차순으로 정렬한 뒤 인덱스 8–15(0부터 셈) 중 가장 짧은 폭(클럭 틱)을 고르고, `80_000_000 / 폭`으로 보율을 계산한다. 정렬돼 있으므로 사실상 인덱스 8의 값이다. 예: 694틱이면 115273, Best Fit은 115200.
- 입력 전용이지만 레벨 변환기는 enable된다. 펌웨어 주석에 따르면 이때 입력 채널은 레벨 변환기 때문에 기본 HIGH가 된다("Set all channels to inputs (default HIGH due to level translators)", [L1235](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1235)). 즉 타깃 쪽에 약한 풀업이 걸린다. [추론]
- Best Fit 표(대체로 ±5%). 범위에 들지 않으면 `N/A`이며, "Ignore non-standard"가 y이면 `N/A` 결과를 출력하지 않는다.

```python
BEST_FIT = [((2280,2520),2400),((3420,3780),3600),((4560,5040),4800),((6840,7560),7200),
            ((9120,10080),9600),((13680,15120),14400),((18240,20160),19200),((27360,30240),28800),
            ((30241,32813),31250),((36480,40320),38400),((54720,60480),57600),((72960,80640),76800),
            ((109440,120960),115200),((145920,161280),153600),((218880,241920),230400),
            ((241921,262500),250000),((291840,322560),307200),((328320,362880),345600),
            ((437760,483840),460800),((875520,949248),921600),((949249,988800),960000),
            ((988801,1050000),1000000),((1140000,1260000),1200000),((1425000,1575000),1500000)]
```

예시 결과(합성): `'\r\nTXD: 1\r\nBaud (Measured): 115273\r\nBaud (Best Fit): 115200\r\n'`

- 스캔 뒤: `uTXD` = 마지막 TXD, `uRXD = 0`, `uBaud` = Best Fit(N/A였다면 0). `uBaud`가 0이면 패스스루에서 빈 줄로 보율 기본값을 받을 때 범위 오류가 나므로, 보율을 명시해서 보낸다.
- 드라이버: 일정 시간(예: 타깃 부팅 로그가 나오는 동안) 결과를 모은 뒤 `'\n'`으로 끝내고, 채널별로 중복을 없애 집계한다.

### 9.3 UART 패스스루 (`P`)

[소스 [L1960-L2033](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1960-L2033), [L2036-L2079](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2036-L2079)]

```text
← "\r\nNote: UART pin naming is from the target's perspective."
← '\r\nEnter X to disable either pin, if desired.'
← '\r\nEnter TXD pin [<uTXD>]: '      Get_Pin, -2..23 (X = 비활성. 한쪽만 가능, 둘이 같으면 ErrPinCollision)
← '\r\nEnter RXD pin [<uRXD>]: '
← '\r\nEnter baud rate [<uBaud>]: '   Get_Decimal_Pin. 300 ≤ 값 ≤ 307200이면 표에 없는 정수도 허용
← '\r\nEnable local echo? [' + ('y/N]: ' | 'Y/n]: ')
← '\r\nEntering UART passthrough! Press Ctrl-X to exit...\r\n'
   ... 양방향으로 원시 바이트를 중계 ...
→ '\x18'
← '\r\nUART passthrough complete.'
← '\r\n\nUART> '
```

- 진입하면: 레벨 변환기 enable, 수신·송신 드라이버 준비, 약 50 ms 대기, 타깃→호스트 중계 cog 시작, 그다음 **호스트 수신 버퍼를 비운다.** 그래서 진입 문구 직후 약 100 ms 안에 보낸 바이트는 버려질 수 있다. 드라이버는 진입 문구를 받고 100 ms 이상 기다린 뒤 보낸다. [추론: L1997-L2004]
- 호스트→타깃: `'\x18'`이 아닌 모든 바이트를 **변환 없이** 보낸다(CR/LF 그대로). 로컬 에코가 on이면 `CharIn` 규칙으로 호스트에 에코하며, 종료할 때 `'\x18'`도 `'.'`로 에코된다.
- 타깃→호스트: 받은 바이트를 그대로 내보낸다(`'.'` 치환 없음).
- 타깃 UART는 8N1, true(비반전) 방식이다(jm_rxserial/jm_txserial). jm_txserial 주석에 "Modified by Joe Grand 3/9/18, changed from 2 stop bits to 1 stop bit"라고 되어 있어 FW 1.5(2018-03-12) 무렵부터 정지 비트가 1개다. 호스트 링크가 115200으로 고정이므로, 타깃이 그보다 빠른 보율로 계속 출력하면 데이터가 빠질 수 있다. [추론, 미확인]
- `RX_from_Target` cog는 `pst.Char`로 출력하고, 로컬 에코도 같은 함수를 쓰므로 두 출력이 섞일 수 있다.
- pweh 통합 팁: 시뮬레이터에서는 이 상태를 mock-device(카메라 UART 콘솔 에뮬레이터)의 바이트 파이프에 연결하면 된다.

---

## 10. SWD 명령 (`SWD>`)

[소스 [L2296-L2453](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2296-L2453), [PropSWD.spin](https://github.com/grandideastudio/jtagulator/blob/1.12/PropSWD.spin)]

두 명령 모두 먼저 아래 경고를 출력한다.

```python
MsgSWDWarning = (
    '\r\n'
    "Warning: The JTAGulator's front-end circuitry is incompatible w/\r\n"
    'many SWD-based target devices. Detection results may be affected.\r\n'
    'Visit github.com/grandideastudio/jtagulator/wiki/Hardware-Modifications\r\n'
    'for details.\r\n'
)   # FW ≤1.11.1에는 'Visit ...'와 'for details.' 두 줄이 없음
```

**`I` — SWD IDCODE Scan**

```text
MsgSWDWarning → Get_Channels(2) → '\r\nPossible permutations: ' + P(n,2)
Get_Settings → Wait_For_Space(ErrIDCODEAborted) → MsgJTAGulating
순열: SWCLK(바깥) × SWDIO(안쪽). 각 순열에서 line reset → JTAG-to-SWD(0xE79E) → DP IDCODE 읽기 (100 kHz)
       ACK=OK(0b001)이고 IDCODE ≠ 0xFFFFFFFF이고 bit0 = 1이면 결과
결과: '\r\nSWDIO: <d>\r\nSWCLK: <d>\r\n' + 'Device ID #1: <bits> (0x<HHHHHHHH>)\r\n' + '\r\n'
(없으면) ErrNoDeviceFound → '\r\nIDCODE scan complete.'     ← JTAG IDCODE 스캔과 같은 문구
```

결과 줄 예(합성): `'Device ID #1: 0010 1011101000000001 01000111011 1 (0x2BA01477)\r\n'`. 결과 블록은 **SWDIO를 먼저, SWCLK를 나중에** 출력하지만, 순열은 SWCLK가 바깥 루프다.

**`D` — Get SWD Device ID**

```text
MsgSWDWarning → '\r\nEnter SWDIO pin [<swdIo>]: ' → '\r\nEnter SWCLK pin [<swdClk>]: '   (0..23, 서로 달라야 함)
성공: '\r\n\nDevice ID #1: ... (0x........)\r\n-> Manufacturer ID: 0x...\r\n-> Part Number: 0x....\r\n-> Version: 0x.\r\n'
실패: '\r\nNo target device(s) found!'
← '\r\nIDCODE listing complete.'
```

호환성 문제는 위키 FAQ와 [PR #30](https://github.com/grandideastudio/jtagulator/pull/30)을 참고한다(전단 회로 때문에 SWD 타깃 검출이 잘 안 될 수 있음).

---

## 11. GPIO 명령 (`GPIO>`)

[소스 [L2173-L2283](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2173-L2283)]

| 키 | 대화 / 출력 |
|---|---|
| `R` | `'\r'`, 이어 `'\r\nCH23..CH0: bbbbbbbb bbbbbbbb bbbbbbbb  (0xHHHHHH)'`. 모든 채널을 입력으로 두고 한 번 읽음 |
| `C` | `'\r\nReading all channels! Press any key to abort...\r\n'`. 처음 한 번 출력한 뒤에는 값이 바뀔 때마다 위 줄 형식을 출력. 아무 키나 받으면 메시지 없이 프롬프트 |
| `W` | `'\r\nEnter value to output (in hex) [' + 6자리 hex(gWriteValue, 기본 FFFFFF) + ']: '`. hex 최대 6자리. 이어 **24채널을 모두 출력으로** 그 값으로 구동한 뒤 위 줄 형식 출력 → `'\r\nPress any key when done...'` → `CharIn`(에코) → 프롬프트(이때 레벨 변환기 disable) |
| `L` | `MsgModeWarning`(§8.9) → EEPROM에 모드 기록 → `'\r\nEntering logic analyzer mode! Press Ctrl-X to exit...'` → `'\r\n\nNote: Switch to analyzer software and use Openbench Logic Sniffer driver @ 115.2kbps\r\n'` → SUMP 바이너리 모드(§13) |

GPIO 줄 형식에서 마지막 8비트 덩어리 뒤 공백 하나와 `' (0x'` 앞 공백 하나가 겹쳐 **공백 2칸**이 된다: `CH23..CH0: 11111111 11111111 11111111  (0xFFFFFF)` ([L2233-L2246](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L2233-L2246)). 공식 시험 절차서(HW Rev. B용, v2.1) p.2에도 같은 형식의 예가 있다([jtagulator_testproc.pdf](https://github.com/grandideastudio/jtagulator/blob/master/Hardware/jtagulator_testproc.pdf)). 다만 PDF에서 뽑은 텍스트로는 공백 수를 확인할 수 없으므로, 공백 2칸은 소스를 근거로 한다.

---

## 12. 전체 스캔 (`A`, 메인 메뉴, FW 1.12에서 추가)

[소스 [L251-L269](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L251-L269), [CHANGES 1.12](https://github.com/grandideastudio/jtagulator/blob/master/CHANGES.markdown#v1_12)]

```text
GPIO R → '\r\n\n-----' → JTAG J(Combined) → '\r\n\n-----' → JTAG I → '\r\n\n-----' → JTAG B
       → '\r\n\n-----' → JTAG R → '\r\n\n-----' → SWD I → '\r\n\n-----' → UART T → '\r\n\n-----' → UART U
```

- 각 스캔은 자기 질문(채널, 설정, 스페이스바)을 그대로 묻는다.
- 한 스캔에서 오류(`Value out of range!`)가 나거나 중단해도 **나머지 스캔은 계속된다.** 반환값을 검사하지 않기 때문이다. 그래서 중단 키를 한 번 보내도 메뉴로 돌아오지 않는다. 남은 하위 스캔마다 취소 입력을 보내야 한다(§4.4 예외).
- [소스] 하위 스캔은 끝날 때 레벨 변환기를 끄지 않는다. `u.TXSDisable`은 메인 명령 루프에서만 호출된다([L163](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L163)). 그래서 두 번째 이후 하위 스캔의 질문에 답하는 동안에도 레벨 변환기는 enable 상태다. 직전 스캔이 출력으로 둔 채널(범위 안 채널 HIGH 등)도 그대로 구동된다.
- UART `T`는 키를 받아야 끝나므로, `A`를 자동화할 때는 `T` 단계에서 `'\n'`을 보내야 다음 단계로 넘어간다.
- 구분선 `-----`는 진행 표시와 모양이 같다. 파서는 둘 다 잡음으로 처리한다.
- 자동화에서는 `A` 대신 개별 명령을 쓰기를 권한다(상태 추적이 쉬움).

---

## 13. 영속 모드 상세 (로직 분석기 SUMP / OpenOCD)

| 항목 | 로직 분석기 (`GPIO>` `L`) | OpenOCD (`JTAG>` `O`) |
|---|---|---|
| 프로토콜 | OLS/SUMP 호환, 115200, 1024 × 24ch 샘플, 최대 1.2 MHz, 레벨 트리거 | Bus Pirate 바이너리 JTAG, 115200 |
| EEPROM에 기록하는 것 | 모드, VADJ | 모드, VADJ, TDI/TDO/TCK/TMS |
| 부팅할 때 | 저장된 VADJ를 바로 출력, 채널은 입력, LED 빨강(캡처 중에는 노랑) | 저장된 VADJ를 바로 출력, **채널 0–24를 HIGH**로 설정한 뒤 JTAG 핀 구성, LED 빨강 |
| 식별 응답 | `0x02` → `'1ALS'`, 메타데이터 장치명 `"JTAGulator"` | `0x00` → `'BBIO1'`, `0x06` → `'OCD1'` |
| 종료 | 명령 위치 또는 캡처 중에 `'\x18'` | 명령 위치에서 `'\x18'` |
| 종료 출력 | (1초 뒤) `'\r\nLogic analyzer mode complete.'` → `GPIO> ` | (1초 뒤) `'\r\nOpenOCD mode complete.'` → `JTAG> ` |
| 근거 | [PropSUMP.spin L159-L245, L456-L467](https://github.com/grandideastudio/jtagulator/blob/1.12/PropSUMP.spin#L159-L245), 위키 Logic-Analyzer | [PropOCD.spin L72-L168, L241-L242](https://github.com/grandideastudio/jtagulator/blob/1.12/PropOCD.spin#L72-L168), 위키 OpenOCD |

- SUMP의 긴 명령(5바이트)과 OCD 명령 인자는 **인자 바이트마다** 100 ms 타임아웃이 있다(`MAX_RX_DELAY_MS = 100`). 시간이 초과돼도 루프를 빠져나가지 않고 남은 인자 바이트를 하나씩 계속 기다린다([PropSUMP L415-L423](https://github.com/grandideastudio/jtagulator/blob/1.12/PropSUMP.spin#L415-L423), [PropOCD L233-L236](https://github.com/grandideastudio/jtagulator/blob/1.12/PropOCD.spin#L233-L236)). 그래서 끊긴 명령 직후에 보낸 `'\x18'`은 인자로 소비될 수 있다. 그 구간은 SUMP에서 최대 약 400 ms(4바이트 × 100 ms)이고, OCD `CMD_TAP_SHIFT`에서는 최악 약 205초다(§4.4 예외). `'\x18'`은 직전 송신에서 충분한 시간(SUMP는 0.5초 이상)이 지난 뒤 보내고, 응답이 없으면 간격을 두고 되풀이한다. [추론]
- sigrok-mcp에서 JTAGulator를 로직 분석기로 쓰려면 `--driver=ols:conn=/dev/ttyUSB0`를 쓴다(위키 예시). 이 경우 장치 상태가 영속 모드로 바뀌므로, jtagulator-mcp와 sigrok-mcp가 같은 포트를 두고 충돌하지 않게 조정해야 한다.

---

## 14. 펌웨어 버전별 차이

[CHANGES.markdown](https://github.com/grandideastudio/jtagulator/blob/master/CHANGES.markdown)과 각 태그 소스의 diff에서 정리했다. ≤1.6 소스는 UTF-16이다.

| FW | 드라이버·시뮬레이터에 영향을 주는 변경 |
|---|---|
| 1.0–1.1.1 | 명령을 글자 입력 즉시 실행(종료 문자 필요 없음). 1.1에서 UART 스캔·패스스루 추가 |
| 1.2 | 명령에 CR/LF 종료가 필요해짐, 로컬 에코, 진행 표시, 버전 명령 `J` |
| 1.2.1 / 1.2.2 | 패스스루 로컬 에코 질문 / 전압 설정 확인 메시지와 VADJ 경고 |
| 1.3 | 백스페이스, 채널 범위 질문, 핀아웃 기억, `No target device(s) found!`. 메뉴는 하나로 평평하고 프롬프트는 `'\r\n:'`, 부팅하자마자 배너 출력 |
| 1.4 | 서브메뉴와 `'\r\n\n<MENU>> '` 프롬프트, **부팅 후 키 대기**, 버전 명령이 메인 메뉴 `I`로 바뀜, `Y` 추가, `X` 추가(1.7에서 삭제), UART `T`(보율 범위·대기시간·반복 횟수 질문) |
| 1.5 | `V`에 정수 허용, non-printable 무시 질문 |
| 1.6 | IDCODE 스캔이 Device ID를 출력, `"Bring channels LOW between each permutation?"`(IDCODE/BYPASS), JTAG `C`(클럭) |
| 1.7 | SWD 메뉴 `S`, VADJ 하한 1.4 V(이전 1.2 V), UART 문자열 16바이트, 소스를 ASCII로 변환 |
| 1.8 | `J` Combined Scan, `L` 로직 분석기 |
| 1.9 | `O` OpenOCD, JTAG/SWD 클럭 명령 `C` 삭제(JTAG 최대 25 kHz, SWD 100 kHz) |
| 1.10 | UART `T`를 연속 자동 보율 감지로 교체(질문: 채널, `"Ignore non-standard baud rates?"`), `U`에 알려진 핀·지연 질문 추가, `R` RTCK 추가. **≤1.9의 `U`는 문자열 질문이 채널 질문보다 먼저 나왔고 지연·알려진 핀 질문이 없었음** |
| 1.11 | `P` 핀 매퍼, 문구가 `"Bring channels LOW before each permutation?"`로 바뀜, `U`에 LOW 펄스 질문, `"Note: UART pin naming ..."`(이전에는 `"UART pin naming ..."`) |
| 1.11.1 | `'More than one device detected in the chain!'`(≤1.11에서는 `'Too many devices in the chain!'`), OCD 예시 문구 `buspirate port`(이전 `buspirate_port`) |
| **1.12** | `A` 추가. `Wait_For_Space`가 Enter를 무시하고 **스페이스를 에코하지 않음**, 문구 `"...(any other key besides Enter to abort)..."`. 잘못된 명령 메시지에 `" Press 'H' for available commands."` 추가. Combined Scan 완료·중단 문구에 `"JTAG combined"`. `T` 시작 시 안내문 추가. SWD 경고에 Visit 줄 추가. 버전 정보에서 `Support:` 줄 삭제. 메뉴 문구 `"J   Identify JTAG pinout (Combined Scan)"` |

드라이버의 버전 대응 권장: `I`로 버전을 읽은 뒤, 1.12에는 위 문자열 집합을 쓰고, 1.10–1.11.1에는 중단·완료·스페이스바 문구 변형(정규식의 `(?: besides Enter)?`, `JTAG(?: combined)?`)과 스페이스 에코를 허용한다. 1.10 미만은 지원하지 않는다.

---

## 15. 안전 관련 사실

1. **VADJ는 타깃 전원이 아니다.**
   - 펌웨어 경고: `"Warning: Ensure VADJ is NOT connected to target!"`
   - 위키: "VADJ should *not* be connected to the target board (it is made available on the headers for testing and future use)."
   - CHANGES 1.2.2: VADJ는 I/O 레벨 변환용이며 타깃에 외부 전원을 대는 용도가 아니다.
2. **전압을 틀리게 설정하면 타깃 I/O가 손상될 수 있다.** JTAGulator는 VADJ 레벨로 채널을 구동한다. 위키 Logic-Analyzer: VADJ를 현재 타깃의 I/O 전압에 맞추는 것이 "will allow for proper detection of logic levels and prevent damage to your target". 전압은 사람이 타깃의 VCC나 I/O 전압을 측정해 정한다. 에이전트가 추정하면 안 된다. [위키 Quick-Start]
3. **채널 입력 보호 한계는 하드웨어 리비전마다 다르다.**
   - 위키 Quick-Start: "maximum input voltage of VADJ + 10 V on each channel"(직렬 1 kΩ 기준).
   - 위키 Hardware-Modifications: R11–R13을 10 Ω(Bourns 4816P-1-100LF)으로 바꾸면 "reduce the maximum allowable input voltage on each channel from the original VADJ + 10 V down to VADJ + 0.5 V".
   - **HW Rev. C BOM(2023-04-28)은 R11–R13이 바로 4816P-1-100LF(10 Ω)다.** [BOM](https://github.com/grandideastudio/jtagulator/blob/master/Hardware/Rev.%20C/jtagulator_bom.pdf)
   - → [추론] Rev. C 장비의 채널 최대 입력은 **VADJ + 0.5 V**로 보아야 한다.
   - EXPLIoT 판매 페이지는 "HW Rev. D"를 표기하지만 Rev. D 문서는 공개되지 않았다(미확인). 같은 페이지에 링크된 회로도·BOM은 저장소의 Rev. C와 같은 파일이다(SHA-256으로 확인).
4. **VADJ가 꺼져 있을 때도 클램프는 VADJ 노드를 기준으로 한다.** [추론: 회로도에서 NUP4302MR6의 VCC가 VADJ, 3번 항목의 "VADJ + 0.5 V"] Rev. C에서 VADJ가 0 V(리셋 직후, `V`→0)인데 타깃 신호선이 켜져 있으면 클램프 다이오드로 전류가 흐를 수 있다. 권장 순서는 다음과 같다.
   1. 타깃 전원을 끈 채 GND와 채널을 연결한다.
   2. `V`로 전압을 설정한다.
   3. 타깃 전원을 켠다.
   4. 스캔한다.
   5. 타깃 전원을 끈 다음 JTAGulator 연결을 끊거나 포트를 닫는다. 포트를 닫으면 리셋되어 VADJ가 꺼질 수 있다(§2).
5. **스캔은 채널을 능동적으로 구동한다.** IDCODE/BYPASS/Combined/RTCK/SWD/UART 스캔은 순열마다 **범위 안의 모든 채널을 출력 HIGH로** 만들고, 선택하면 LOW 펄스도 준다. TRST# 탐색에서는 후보 채널마다 100 ms 동안 LOW를 유지한다. 핀아웃을 아는 상태에서 쓰는 JTAG `D`/`T`/`Y`/`P`는 범위와 상관없이 **24채널 전부**를 출력 HIGH로 둔다(`u.Set_Pins_High(0, g#MAX_CHAN-1)`, [L988](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L988), [L1010](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1010), [L1063](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1063), [L1130](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1130)). 그래서 채널이 타깃 출력, 전원 레일, 민감한 제어선(리셋, 부트 모드, write-protect, 전원 enable)에 물려 있으면 충돌이 나거나 타깃 동작이 바뀔 수 있다.
   - 배너 경고: `"Warning: Use of this tool may affect target system behavior!"`
   - 위키 FAQ: `Abnormal target behavior due to "fuzzing" unknown pins`
6. **수동(입력 전용) 명령**: UART `T`, GPIO `R`/`C`, 로직 분석기는 채널을 입력으로만 쓴다. 다만 레벨 변환기가 enable되므로 약한 풀업은 걸린다(§9.2). 먼저 이 명령들로 활동을 관찰하고, 능동 스캔은 그다음에 한다.
7. **GPIO `W`는 24채널 전부를** 입력한 값으로 구동한다. 연결되지 않은 채널이나 타깃 출력에 물린 채널도 포함된다.
8. **핀 매퍼(`P`)는 EXTEST로 타깃 칩의 실제 핀을 구동한다.** 그 칩에 연결된 보드 회로(전원 스위치, 모터, 릴레이 등)가 움직일 수 있다.
9. 명령 프롬프트에서 대기하는 동안에는 레벨 변환기가 disable(High-Z)된다. 리셋되는 동안에도 R10 풀다운 때문에 OE는 LOW다. 하지만 클램프 다이오드와 직렬 저항은 수동 소자라 항상 연결되어 있다. 또 명령 **안의** 질문 가운데 일부는 레벨 변환기가 enable된 상태에서 나온다(§16.1).
   - JTAG `Y`의 스페이스바 대기
   - JTAG `P`의 EXTEST 명령·fill·pause 질문과 스페이스바 대기(24채널 HIGH)
   - GPIO `W`의 "Press any key when done..."
   - `A`의 두 번째 이후 하위 스캔 질문
10. **영속 모드는 리셋하거나 전원을 다시 넣어도 유지되고, VADJ를 기억한다.**
    - OpenOCD 모드로 부팅하면 사용자 조작 없이 저장된 VADJ로 채널 0–24를 HIGH로 구동한다(PropOCD L77-L80).
    - 다른 타깃으로 바꿔 연결하기 전에 반드시 `'\x18'`로 빠져나와 전압을 다시 설정한다.
11. 공통 GND가 필요하다. 타깃의 풀업·풀다운이 강하면(< 4.7 kΩ, Rev. B 이하의 1 kΩ 직렬 기준) 신호가 논리 임계값에 닿지 못할 수 있다. [위키 FAQ, Hardware-Modifications]
12. `A`는 UART 스캔까지 포함한다. 후보 RXD 채널마다 21개 보율로 문자열(기본 CR)을 보낸다.

### 15.1 Skill 작성자를 위한 권장 흐름 (요약)

1. **사람**: 타깃 전원을 끈 상태에서 공통 GND를 연결하고, 후보 테스트포인트를 CH0부터 차례로 연결한다. VADJ 핀이 연결되지 않았는지 확인한다. 타깃 I/O 전압을 측정해 알려 준다.
2. **에이전트**: 재동기화(§4.4) → 버전 확인(§5.5) → `V`에 측정값을 넣는다.
3. **사람**: 타깃 전원을 켠다.
4. **에이전트(수동 관찰부터)**: `GPIO R`/`C`로 채널 상태를 보고, `UART T`로 송신 활동과 보율을 찾는다.
5. **에이전트(능동 스캔)**:
   - UART: `U`(알려진 TXD를 지정하고 RXD 탐색, 문자열 기본 CR) → 콘솔 확인 → 핀아웃이 확정되면 uart-mcp로 직접 연결(또는 `P` 패스스루).
   - JTAG: `I` → `B`(알려진 TDO/TCK/TMS를 넣고 TDI 탐색) 또는 `J` → `D`(IDCODE 디코딩) → `T`(BYPASS 확인) → 이후 openocd-mcp와 전용 어댑터로 진행.
   - SWD: `S`→`I`. 전단 회로 호환성 경고를 결과와 함께 보고한다.
6. **기록**: 핀아웃, IDCODE, 보율, 사용한 설정, 오탐 여부를 case-mcp findings에 남긴다.
7. **종료**: 타깃 전원을 끈 다음 포트를 닫는다(§15의 4번 항목).

---

## 16. 시뮬레이터용 상태 기계

### 16.1 상태와 전이

| 상태 | 들어갈 때 출력 | 받는 입력 | 전이 |
|---|---|---|---|
| `BOOT` | – | – | EEPROM 모드 NORMAL → `WAKE`, SUMP → `SUMP`, OCD → `OCD` (§4.2) |
| `WAKE` | 없음 (LED 노랑) | 1바이트, `CharIn` 에코 | `INIT_HEADER` 출력 → `PROMPT(MAIN)` |
| `PROMPT(m)` | `MENU_PROMPTS[m]` | `line(12)` | 1글자 명령 → 해당 대화 또는 메뉴 전환. 그 밖 → `InvalidCommand` 출력 후 `PROMPT(m)` |
| `DIALOG(cmd, k)` | k번째 질문 문자열 | `line(n)` | 유효 → 다음 단계. 무효 → 오류 메시지 → `PROMPT(m)` |
| `SPACE_WAIT(cmd)` | `MsgPressSpacebarToBegin` | 1바이트, 에코 없음 | `' '` → `RUN`, CR/LF → 그대로 대기, 그 밖 → 중단 메시지 → `PROMPT(m)` |
| `RUN(cmd)` | `MsgJTAGulating` (+명령별 안내) | 수신 여부만 폴링 | 바이트 수신 → 중단 처리 → `PROMPT(m)`. 끝남 → 완료 문자열 → `PROMPT(m)` |
| `MONITOR` (GPIO `C`, UART `T`) | 각자의 시작 문구 | 폴링 | 바이트 수신 → (T만 완료 문자열) → `PROMPT(m)` |
| `ANYKEY` (GPIO `W`) | `'\r\nPress any key when done...'` | 1바이트, `CharIn` 에코 | → `PROMPT(GPIO)` |
| `EXTEST_PAUSE` | `'Press spacebar to continue (any other key to abort)...'` | 1바이트, `CharIn` 에코 | `' '` → `'\r\n'` 출력 후 `RUN(P)` 계속. 그 밖 → `'\r\nPin mapper complete.'` → `PROMPT(JTAG)` |
| `PASSTHRU` | `'\r\nEntering UART passthrough! Press Ctrl-X to exit...\r\n'` | 원시 바이트 | `0x18` → `'\r\nUART passthrough complete.'` → `PROMPT(UART)`. 그 밖 → 타깃으로 전달 |
| `SUMP` / `OCD` | (메뉴에서 진입했을 때만 안내문) | 바이너리 | `0x18` → 1초 → 완료 문자열 → `PROMPT(GPIO)` / `PROMPT(JTAG)` |

`PROMPT`에서 기다리는 동안 레벨 변환기는 항상 disable이다. `DIALOG`도 대부분 disable 상태에서 진행되지만 예외가 있다.
- JTAG `Y`의 스페이스바 대기, JTAG `P`의 EXTEST 명령·fill·pause 질문과 스페이스바 대기는 레벨 변환기를 enable하고 24채널을 HIGH로 둔 **뒤에** 묻는다(JTAG 핀은 `jtag.Config` 설정을 따름). [소스 [L1062-L1090](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1062-L1090), [L1129-L1229](https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin#L1129-L1229)]
- `A`의 두 번째 이후 하위 스캔 질문도 enable 상태에서 나온다(§12).

### 16.2 입력 프리미티브와 공통 단계 (의사코드)

아래는 FW 1.12 로직을 그대로 옮긴 의사코드다(그대로 실행되는 코드는 아님). `emit()`은 장치→호스트 출력, `rx()`는 블로킹 1바이트 수신, `rx_pending()`은 수신 버퍼가 비어 있지 않은지 확인한다. `Fail(msg)`는 `emit(msg)` 후 현재 메뉴 프롬프트로 돌아간다는 뜻이다.

```python
def line(maxlen):                       # PropSerial.StrInMax
    buf = []
    while True:
        c = rx()
        if c == 0x08:                   # BS
            if buf:
                buf.pop(); emit('\x08 \x08')
        elif c == 0x0D:                 # CR: 정원이 남았을 때만 에코
            if len(buf) < maxlen:
                emit('\r')
            return ''.join(buf)
        elif c == 0x0A:                 # LF: 버림
            pass
        elif len(buf) < maxlen:
            buf.append(chr(c)); emit(chr(c))
        # 정원을 넘는 문자는 버림(에코 없음)

def key_echo():                         # PropSerial.CharIn
    c = rx()
    emit(chr(c) if c in (0x0A, 0x0D) or 0x20 <= c <= 0x7E else '.')
    return c

def dec_pin(s):                         # Get_Decimal_Pin
    if s == '': return -1
    v = 0
    for ch in s:
        if ch.isdigit(): v = v * 10 + int(ch)
        elif ch in '.,': continue
        else: return -3
    return v

def pin(s):                             # Get_Pin
    if s == '': return -1
    if s[0] in 'Xx': return -2 if len(s) == 1 else -3
    return dec_pin(s)

def yes_no(prefix, cur, yes='Y', no='N'):    # 공통 y/N 형식
    emit(prefix + (f'{yes}/{no.lower()}]: ' if cur else f'{yes.lower()}/{no}]: '))
    s = line(12)
    if len(s) > 1: raise Fail(ErrOutOfRange)
    if s == '': return cur
    if s.upper() == yes: return 1
    if s.upper() == no: return 0
    raise Fail(ErrOutOfRange)

def channels(min_chan):                 # Get_Channels
    global chStart, chEnd
    emit(f'\r\nEnter starting channel [{chStart}]: ')
    x = dec_pin(line(12)); x = chStart if x == -1 else x
    if not 0 <= x <= 23: raise Fail(ErrOutOfRange)
    d = x if chEnd < x else chEnd
    emit(f'\r\nEnter ending channel [{d}]: ')
    y = dec_pin(line(12)); y = d if y == -1 else y
    if y < x + min_chan - 1 or y > 23: raise Fail(ErrOutOfRange)
    chStart, chEnd = x, y

def permutations(n, r):
    v = 1
    for i in range(n - r + 1, n + 1): v *= i
    emit(f'\r\nPossible permutations: {v}')

def settings():                         # Get_Settings
    global pinsLow, pinsLowDelay, pinsHighDelay
    pinsLow = yes_no('\r\n\nBring channels LOW before each permutation? [', pinsLow)
    if pinsLow:
        for name, label in (('pinsLowDelay', 'for channels to remain LOW'),
                            ('pinsHighDelay', 'after channels return HIGH before proceeding')):
            emit(f'\r\nEnter length of time {label} (in ms, 1 - 1000) [{globals()[name]}]: ')
            v = dec_pin(line(12))
            if v != -1:
                if not 1 <= v <= 1000: raise Fail(ErrOutOfRange)
                globals()[name] = v

def wait_for_space(err):                # Wait_For_Space (FW 1.12)
    emit('\r\nPress spacebar to begin (any other key besides Enter to abort)...')
    while True:
        c = rx()
        if c in (0x0A, 0x0D): continue
        if c != 0x20: raise Fail(err)
        return

def set_jtag(get_tdi):                  # Set_JTAG — Get_Decimal_Pin, 0..23
    t = {}
    if get_tdi:
        emit(f'\r\nEnter TDI pin [{jTDI}]: '); t['TDI'] = ask_dec(jTDI, 0, 23)
    else:
        emit('\r\nTDI not needed to retrieve Device ID.\r\n'); t['TDI'] = 29   # 채널 밖 임시 핀
    for p in ('TDO', 'TCK', 'TMS'):
        emit(f'\r\nEnter {p} pin [{cur(p)}]: '); t[p] = ask_dec(cur(p), 0, 23)
    if len(set(t.values())) != 4: raise Fail(ErrPinCollision)
    commit(t)

def set_jtag_partial():                 # Set_JTAG_Partial — Get_Pin, -2..chEnd, X 허용
    t = {}
    for p in ('TDI', 'TDO', 'TCK', 'TMS'):
        emit(f'\r\nEnter {p} pin [{cur(p)}]: ')
        v = pin(line(12)); v = cur(p) if v == -1 else v
        if v < -2 or v > chEnd: raise Fail(ErrOutOfRange)
        t[p] = v
    known = [v for v in t.values() if v != -2]
    if len(set(known)) != len(known): raise Fail(ErrPinCollision)
    commit(t)

def set_uart(ask_baud):                 # Set_UART
    emit(f'\r\nEnter TXD pin [{uTXD}]: '); tx = ask_pin(uTXD, -2, 23)
    emit(f'\r\nEnter RXD pin [{uRXD}]: '); rx_ = ask_pin(uRXD, -2, 23)
    if tx == rx_: raise Fail(ErrPinCollision)
    commit_uart(tx, rx_)
    if ask_baud:
        emit(f'\r\nEnter baud rate [{uBaud}]: '); commit_baud(ask_dec(uBaud, 300, 307200))
# ask_dec(cur, lo, hi): dec_pin → -1이면 cur, 범위 밖이면 Fail(ErrOutOfRange). ask_pin은 pin() 버전.
```

### 16.3 명령 디스패치와 대화 스크립트

```python
def main_loop():
    boot()                                        # §16.1 BOOT/WAKE
    while True:
        emit(MENU_PROMPTS[menu])
        s = line(12)
        if len(s) != 1:
            emit(InvalidCommand); continue
        try:
            dispatch(menu, s.upper())
        except Fail as f:
            emit(f.msg)

NEEDS_V = {('MAIN','A'), ('JTAG','J'), ('JTAG','I'), ('JTAG','B'), ('JTAG','R'), ('JTAG','D'),
           ('JTAG','T'), ('JTAG','Y'), ('JTAG','P'), ('JTAG','O'), ('UART','U'), ('UART','T'),
           ('UART','P'), ('GPIO','R'), ('GPIO','C'), ('GPIO','W'), ('GPIO','L'), ('SWD','I'), ('SWD','D')}

def dispatch(m, k):
    if (m, k) in NEEDS_V and vTargetIO == -1:
        raise Fail(ErrTargetIOVoltage)
    # MAIN:  J/U/G/S → 메뉴 전환, A → all_scan, V → set_voltage, I → emit(VersionInfo), H → emit(MenuMain)
    # 서브:  고유 명령 표(§5.3), 공통 V/H/M (H → MenuX + MenuShared, M → MAIN)
    # 그 밖: emit(InvalidCommand)

def idcode_scan(combined):              # JTAG I (combined=False), JTAG J (combined=True)
    r = 4 if combined else 3
    err = ErrJTAGAborted if combined else ErrIDCODEAborted
    channels(r); permutations(chEnd - chStart + 1, r); settings(); wait_for_space(err)
    emit(MsgJTAGulating)
    num = ctr = 0; mod = 1 if pinsLow else 100
    for tdo, tck, tms in perms3():                 # TDO > TCK > TMS, 서로 다름
        if rx_pending(): cleanup(); emit(err); flush(); return
        ids = target.idcodes(tdo, tck, tms)        # DR에서 읽은 32개 값(무효 값 포함). device_id()가 무효 값을 거르므로
                                                   # 번호(#n)는 위치 그대로 유지됨. 판정은 첫 값(≠0xFFFFFFFF, bit0=1)으로
        if valid(ids[0]):
            if not combined:
                emit(jtag_pins('N/A', tdo, tck, tms)); num += 1; remember(0, tdo, tck, tms)
                for i, v in enumerate(ids): emit(device_id(v, i + 1, False))
                ctr = trst_search(ctr, mod); emit('\r\n')
            else:
                for tdi in others(tdo, tck, tms):
                    if rx_pending(): cleanup(); emit(err); flush(); return
                    if target.bypass_ok(tdi, tdo, tck, tms):
                        emit(jtag_pins(tdi, tdo, tck, tms)); num += 1; remember(tdi, tdo, tck, tms)
                        for i, v in enumerate(target.idcodes_n(tdi, tdo, tck, tms)): emit(device_id(v, i + 1, False))
                        ctr = trst_search(ctr, mod); emit('\r\n')
                        break
                    ctr += 1; progress(ctr, mod, dash=True)
        ctr += 1; progress(ctr, mod, dash=True)
    if num == 0: emit(ErrNoDeviceFound); jPinsKnown = 0
    cleanup()
    emit('\r\nJTAG combined' if combined else '\r\nIDCODE'); emit(' scan complete.')
# trst_search: 범위 안에서 사용하지 않은 채널마다 abort 확인 → 해당 채널 LOW 100ms → 값이 바뀌면
#              emit(f'TRST#: {ch}\r\n'); ctr += 1; progress(ctr, mod, dash=False)

def bypass_scan():                      # JTAG B
    channels(4); pins_known('J')
    if jPinsKnown: emit('\r\nEnter X for any unknown pin.'); set_jtag_partial()
    k = 알려진 핀 수
    permutations((chEnd - chStart + 1) - k, 4 - k); settings(); wait_for_space(ErrBYPASSAborted)
    emit(MsgJTAGulating); mod = 1 if pinsLow else 10
    for tdi, tdo, tck, tms in perms4(fixed=알려진 핀):   # TDI > TDO > TCK > TMS
        abort 확인(ErrBYPASSAborted)
        n = target.devices(...)
        if target.bypass_ok(...):
            emit(jtag_pins(tdi, tdo, tck, tms)); trst_search(by='device count')
            emit(f'Number of devices detected: {n}\r\n')
        ctr += 1; progress(ctr, mod, dash=True)
    (없으면 ErrNoDeviceFound); emit('\r\nBYPASS scan complete.')

def uart_scan():                        # UART U
    emit(MsgUARTPinout); channels(2); pins_known('U')
    if uPinsKnown: emit('\r\nEnter X for any unknown pin.'); set_uart(ask_baud=False)
    permutations(...)
    emit('\r\nEnter text string to output (prefix with \\x for hex) [' + shown_string() + ']: ')
    parse_uart_string(line(34))          # §9.1 표
    emit(f'\r\nEnter delay before checking for target response (in ms, 0 - 1000) [{uWaitDelay}]: ')
    uWaitDelay = ask_dec_keep(uWaitDelay, 0, 1000)
    uPrintable = yes_no('\r\n\nIgnore non-printable characters? [', uPrintable)
    settings(); wait_for_space(ErrUARTAborted); emit(MsgJTAGulating)
    for txd, rxd in perms2():
        for baud in BAUD_TABLE:
            abort 확인(ErrUARTAborted)
            resp = target.uart(txd, rxd, baud, payload(), uWaitDelay)  # ≤16바이트, 바이트 간 20ms
            if resp and (not uPrintable or all(0x20 <= b <= 0x7E or b in (13, 10) for b in resp)):
                emit(f'\r\nTXD: {txd}\r\nRXD: {rxd}\r\nBaud: {baud}\r\n'); emit(data_line(resp))
        ctr += 1; progress(ctr, 1, dash=True)
    (없으면 ErrNoDeviceFound); emit('\r\nUART scan complete.')

def all_scan():                         # MAIN A — 하위 Fail은 그 하위 스캔만 끝냄
    for i, sub in enumerate([read_io, lambda: idcode_scan(True), lambda: idcode_scan(False),
                             bypass_scan, rtck_scan, swd_idcode_scan, uart_scan_txd, uart_scan]):
        if i: emit('\r\n\n-----')
        try: sub()
        except Fail as f: emit(f.msg)
```

나머지 명령(`R`, `D`, `T`, `Y`, `P`, `O`, UART `T`/`P`, SWD `I`/`D`, GPIO, `V`)은 §7–§11의 "대화 순서"를 위와 같은 방식으로 옮기면 된다. 각 절의 코드 블록에 질문 문자열, 파서(dec/pin/yes_no), 범위, 오류 전이가 모두 정확히 적혀 있다.

### 16.4 결과를 만드는 규칙 (가상 타깃 모델)

- 시뮬레이터는 "진짜 핀아웃" 설정(예: JTAG `{TDI:3, TDO:2, TCK:0, TMS:1, idcodes:[0x4BA00477]}`, UART `{TXD:1, RXD:0, baud:115200, reply:b'\r\n# '}`, SWD `{SWCLK, SWDIO, idcode}`)을 받는다. 순열 루프는 펌웨어 순서대로 돌리고, 일치하는 순열에서만 결과 블록을 낸다. 오탐 주입 옵션이 있으면 드라이버의 견고성을 시험하기 좋다.
- 진행 표시 `-`는 §6.6의 주기를 지킨다. 예: CH0–7에서 진짜 핀아웃이 위와 같으면 IDCODE 스캔 출력은 결과 블록 → `'\r\n'` → `'---'` → `'\r\nIDCODE scan complete.'` 순서다(TRST 후보 5개가 `ctr`을 5 올려 총 341, 100의 배수 3번).
- UART 스캔에서 보율이 맞지 않을 때는 깨진 바이트(예: `0x80` 이상)를 돌려주는 옵션을 두면, "Ignore non-printable" 동작과 드라이버의 보율 선택 로직을 시험할 수 있다.
- UART `T`: 시뮬레이터 타이머로 활동 이벤트를 만들고 같은 채널을 반복 보고한다. 측정 보율은 `80_000_000 // round(80e6 / baud ± 지터)`로 만든다.
- 타이밍: 실제 순열당 소요 시간은 (미확인)이다. 시뮬레이터는 지연을 설정할 수 있게 하고, 드라이버는 진행 표시를 기준으로 생존을 감시한다.
- 시뮬레이터 시험 시나리오 권장:
  1. 리셋 → 침묵 → 웨이크 키 → 배너
  2. 전압 미설정 게이트
  3. `' \r'`을 보내면 스캔이 즉시 중단되는지
  4. `[Y/n]` 기본값 변화
  5. 범위 오류 후 메뉴 복귀
  6. 영속 모드에서 부팅 → `'\x18'` 종료
  7. 패스스루에서 `'\x18'` 종료
  8. FW 1.11.1 문자열 프로필 전환

---

## 17. 파싱용 정규식

### 17.1 대기 상태 판별 (원시 수신 버퍼의 **끝**에서 검사)

```python
import re

RE_MENU_PROMPT     = re.compile(r'\r\n\n(?P<menu>JTAG|UART|GPIO|SWD)?> \Z')
RE_VALUE_PROMPT    = re.compile(r'\n(?P<label>[^\r\n]*?) ?\[(?P<default>[^\r\n]*)\]: \Z')   # '\r\n'·'\r\n\n' 둘 다 마지막 '\n'에 앵커
RE_VOLTAGE_PROMPT  = re.compile(r'Enter new target I/O voltage \(1\.4 - 3\.3, 0 for off\): \Z')
RE_SPACE_PROMPT    = re.compile(r'Press spacebar to begin \(any other key(?: besides Enter)? to abort\)\.\.\.\Z')
RE_CONTINUE_PROMPT = re.compile(r'Press spacebar to continue \(any other key to abort\)\.\.\.\Z')
RE_ANYKEY_PROMPT   = re.compile(r'Press any key when done\.\.\.\Z')
RE_SCAN_STARTED    = re.compile(r'JTAGulating! Press any key to abort\.\.\.\r\n')
RE_PASSTHRU_ON     = re.compile(r'Entering UART passthrough! Press Ctrl-X to exit\.\.\.\r\n')
RE_MODE_ON         = re.compile(r'Entering (?P<mode>logic analyzer|OpenOCD) mode! Press Ctrl-X to exit\.\.\.')
RE_BANNER          = re.compile(r"Welcome to JTAGulator\. Press 'H' for available commands\.")
```

- `RE_VALUE_PROMPT`의 `label`로 어떤 질문인지 고른다. 예: `Enter starting channel`, `Bring channels LOW before each permutation?`, `Enter TDI pin`. `default`는 현재값이다(`y/N`, `0`, `CR`, `\x0D0A`, `FFFFFF`). UART 문자열 기본값에 `]`가 들어 있어도 탐욕적 매칭으로 맨 끝의 `]: `에 맞춰진다.
- 질문 문자열과 그에 보낼 응답을 표로 두고(label → 응답 생성 함수), 표에 없는 label이 나오면 `'\x18\r'`로 취소한 뒤 오류로 보고한다.

### 17.2 결과 해석 (정규화한 텍스트: `\r\n`→`\n`, `\r`→`\n`, `re.M`)

```python
M = re.M
RE_JTAG_BLOCK = re.compile(
    r'^TDI: (?P<tdi>N/A|\d+)\nTDO: (?P<tdo>\d+)\nTCK: (?P<tck>\d+)\nTMS: (?P<tms>\d+)\n'
    r'(?P<body>(?:(?:Device ID #\d+: .*|TRST#: \d+|Number of devices detected: \d+)\n)*)', M)
RE_DEVICE_ID  = re.compile(
    r'^Device ID #(?P<n>\d+): (?P<ver>[01]{4}) (?P<part>[01]{16}) (?P<mfg>[01]{11}) 1 '
    r'\(0x(?P<idcode>[0-9A-F]{8})\)$', M)
RE_ID_DETAIL  = re.compile(
    r'^-> Manufacturer ID: 0x(?P<mfg>[0-9A-F]{3})\n-> Part Number: 0x(?P<part>[0-9A-F]{4})\n'
    r'-> Version: 0x(?P<ver>[0-9A-F])$', M)
RE_TRST       = re.compile(r'^TRST#: (?P<trst>\d+)$', M)
RE_NDEV       = re.compile(r'^Number of devices detected: (?P<n>\d+)$', M)
RE_RTCK_BLOCK = re.compile(r'^TCK: (?P<tck>\d+)\nRTCK: (?P<rtck>\d+)$', M)
RE_BYPASS_TEST = re.compile(
    r'^Number of devices detected: (?P<n>\d+)\nPattern in to TDI:    (?P<pin>[01]{32})\n'
    r'Pattern out from TDO: (?P<pout>[01]{32})\n(?P<result>Match!|No Match!)$', M)
RE_IR_LEN     = re.compile(r'^Instruction Register \(IR\) length: (?P<irlen>\d+|N/A)$', M)
RE_POSS_INSTR = re.compile(r'^Possible instructions: (?P<n>-?\d+)$', M)      # IR 31비트면 음수로 표시됨(§8.7)
RE_IRDR       = re.compile(r'^-*IR: (?P<bits>[01]+(?: [01]+)*) \(0x(?P<opcode>[0-9A-F]+)\) -> DR: (?P<drlen>\d+)$', M)  # 앞의 '-'는 진행 표시(§6.6)
RE_BSR_LEN    = re.compile(r'^Boundary Scan Register length: (?P<n>\d+|N/A)$', M)
RE_PINMAP     = re.compile(r'^CH(?P<ch>\d+) -> Register bit: (?P<bit>\d+)$', M)

RE_UART_BLOCK = re.compile(
    r'^TXD: (?P<txd>\d+)\nRXD: (?P<rxd>\d+)\nBaud: (?P<baud>\d+)\n'
    r'Data: (?P<ascii>.*) \[ (?P<hex>(?:[0-9A-F]{2} )+)\]$', M)
RE_UART_TXD_BLOCK = re.compile(
    r'^TXD: (?P<txd>\d+)\nBaud \(Measured\): (?P<measured>\d+)\nBaud \(Best Fit\): (?P<bestfit>\d+|N/A)$', M)

RE_SWD_BLOCK  = re.compile(
    r'^SWDIO: (?P<swdio>\d+)\nSWCLK: (?P<swclk>\d+)\n'
    r'Device ID #1: (?P<bits>[01]{4} [01]{16} [01]{11} 1) \(0x(?P<idcode>[0-9A-F]{8})\)$', M)

RE_GPIO_LINE  = re.compile(
    r'^CH23\.\.CH0: (?P<b23_16>[01]{8}) (?P<b15_8>[01]{8}) (?P<b7_0>[01]{8})  \(0x(?P<hex>[0-9A-F]{6})\)$', M)

RE_PERMS      = re.compile(r'^Possible permutations: (?P<n>\d+)$', M)
RE_V_CURRENT  = re.compile(r'^Current target I/O voltage: (?P<v>Undefined|\d\.\d)$', M)
RE_V_SET      = re.compile(r'^New target I/O voltage set: (?P<v>\d\.\d)$', M)
RE_V_OFF      = re.compile(r'^Target I/O voltage off\.$', M)
RE_VERSION    = re.compile(r'^JTAGulator FW (?P<ver>\d+(?:\.\d+)+)$', M)

RE_COMPLETE   = re.compile(r'^(?P<scan>IDCODE|JTAG combined|JTAG|BYPASS|RTCK|UART|UART TXD) scan complete\.$', M)
RE_DONE_OTHER = re.compile(r'^(?P<what>IDCODE listing|IR/DR discovery|Pin mapper|UART passthrough|'
                           r'OpenOCD mode|Logic analyzer mode) complete\.$', M)
RE_ABORTED    = re.compile(r'^(?:(?P<scan>IDCODE|JTAG combined|JTAG|BYPASS|RTCK|UART) scan aborted!|'
                           r'(?P<other>Pin mapper|IR/DR discovery) aborted!)$', M)
RE_ERROR      = re.compile(r'^(?P<err>Target I/O voltage must be defined!|Value out of range!|'
                           r'Pin numbers must be unique!|No target device\(s\) found!|'
                           r'More than one device detected in the chain!|Too many devices in the chain!|'
                           r'EEPROM not responding!)$', M)
RE_INVALID    = re.compile(r"^\?(?: Press 'H' for available commands\.)?$", M)
RE_NOISE      = re.compile(r'^[-|]*$', M)      # 진행 표시, A의 구분선, 빈 줄 (JTAG Y의 '-IR: ...' 줄은 RE_IRDR이 처리)
```

해석할 때 주의할 점:
- JTAG 블록 하나의 `body` 안에서 `RE_DEVICE_ID`, `RE_TRST`, `RE_NDEV`를 다시 찾는다. IDCODE 스캔은 `tdi == 'N/A'`이고, BYPASS 스캔은 `body`에 `Number of devices detected`가 있으며, Combined 스캔은 TDI가 숫자이면서 Device ID가 있다.
- `RE_RTCK_BLOCK`과 JTAG 블록의 `TCK:` 줄을 헷갈리지 않으려면 두 줄 패턴(`TCK` 다음 줄이 `RTCK`)으로만 판정한다.
- JTAG `Y`의 결과 줄은 "Ignore single-bit"가 Y일 때 앞에 진행 표시 `-`가 붙을 수 있다(§6.6). `RE_IRDR`은 그런 줄도 받아들인다. 진행 표시가 언제나 별도 줄이라고 가정하는 파서는 이런 결과를 놓친다.
- UART `Data:`의 ASCII 부분 길이는 hex 바이트 수와 같아야 한다. 다르면 오탐이나 해석 오류로 본다. 데이터 내용은 hex 쪽을 신뢰한다.
- `IDCODE scan complete.`는 JTAG `I`와 SWD `I`에서 같다. 결과 블록 종류(`TDI:` 대 `SWDIO:`)와 드라이버가 기억한 명령으로 구분한다.
- 입력 에코는 프롬프트 줄 끝에 붙고, 정규화하면 빈 줄이 생긴다. 결과 정규식은 줄 전체에 앵커되어 있어 영향을 받지 않는다.

---

## 18. 미확인 항목

| 항목 | 상태 |
|---|---|
| 리셋 후 키를 받을 수 있게 될 때까지 걸리는 시간(Propeller 부트로더 + EEPROM 로딩) | (미확인). 소스로 확인된 것은 그 뒤 `pst.Start`의 1초 대기뿐 |
| DTR 리셋이 일어나는 에지 극성, Linux에서 포트를 열고 닫을 때 실제로 리셋되는지 | (미확인). 회로(DTR→C→NPN→RES)와 위키 정황만 확인. 회로 해석상 DTR# 상승 에지(DTR 해제)일 가능성이 높음(§2 [추론]) |
| HW Rev. D의 직렬 저항 값 등 Rev. C와의 차이 | (미확인). Rev. D 문서가 공개되지 않음 |
| 스캔의 순열당 실제 소요 시간 | (미확인). JTAG 클럭 ≤25 kHz(CHANGES 1.9), SWD 100 kHz만 확인 |
| 타깃 보율이 115200을 넘고 계속 출력될 때 패스스루에서 데이터가 빠지는지 | (미확인), 추론만 |
| UART hex 입력에서 `_` 처리 | **[소스로 해소]** `is_hex`는 `_`를 허용한다. 그러나 `hex2dec(…, 2)`는 바이트 쌍의 첫 글자가 `_`이면 0을 돌려주고, 두 번째 자리의 `_`는 자릿수로 세지 않은 채 건너뛰어 다음 쌍의 글자를 읽는다. 결과 바이트가 의도와 달라지므로 드라이버는 `_`를 보내지 않는다. ([jm_strings.spin L128-L140, L531-L577](https://github.com/grandideastudio/jtagulator/blob/1.12/jm_strings.spin#L531-L577)) |
| FW 1.12 실측 터미널 캡처 | 공개 자료에서 찾지 못함. 본 문서의 예시는 소스로 합성한 것 |
| 위키 "single CR or LF" 서술 | 소스(≥1.3)와 다름(CR만 종료). 소스를 따름 |
| JEP106 제조사 코드 분해 규칙 | 일반 규격 지식. 본 문서에서 1차 출처 검증 안 함 |
| `D`에서 장치가 없을 때 메시지가 나오지 않는 점. IR 31비트일 때 `Possible instructions: -2147483648`, IR 32비트일 때 `N/A` + `Value out of range!`(이전 판의 "IR 32비트면 `Possible instructions: 0`"은 `Detect_IR_Length`가 32를 돌려주지 않으므로 정정함) | [추론]. Spin 의미론 기반, 실측 아님 |
| `A` 실행 중 재동기화에 취소 입력이 여러 번 필요한 점, OCD `CMD_TAP_SHIFT` 인자 대기(최악 약 205초), JTAG `Y`의 `-IR: ...` 줄, `Y`/`P`/`A` 질문 중 레벨 변환기 enable | [추론]. 소스 로직에서 도출, 실측 아님 |

---

## 19. 출처

**펌웨어 소스 (tag 1.12)**
- `JTAGulator.spin` — https://github.com/grandideastudio/jtagulator/blob/1.12/JTAGulator.spin (raw: https://raw.githubusercontent.com/grandideastudio/jtagulator/1.12/JTAGulator.spin)
- `PropSerial.spin` — https://github.com/grandideastudio/jtagulator/blob/1.12/PropSerial.spin
- `PropJTAG.spin` — https://github.com/grandideastudio/jtagulator/blob/1.12/PropJTAG.spin
- `PropSWD.spin` — https://github.com/grandideastudio/jtagulator/blob/1.12/PropSWD.spin
- `PropSUMP.spin` — https://github.com/grandideastudio/jtagulator/blob/1.12/PropSUMP.spin
- `PropOCD.spin` — https://github.com/grandideastudio/jtagulator/blob/1.12/PropOCD.spin
- `JTAGulatorCon.spin`, `JTAGulatorUtil.spin` — 같은 경로
- `jm_strings.spin`(UART hex 문자열 검사·변환 `is_hex`/`hex2dec`, §18) — https://github.com/grandideastudio/jtagulator/blob/1.12/jm_strings.spin
- 이전 버전 비교: tag `1.3`, `1.4`, `1.6`, `1.9`, `1.10`, `1.11`, `1.11.1` 소스(`git diff`)
- 태그 목록 — https://github.com/grandideastudio/jtagulator/tags
- 변경 이력 — https://github.com/grandideastudio/jtagulator/blob/master/CHANGES.markdown

**공식 위키 / 문서**
- Quick-Start — https://github.com/grandideastudio/jtagulator/wiki/Quick-Start
- Command-Set — https://github.com/grandideastudio/jtagulator/wiki/Command-Set
- FAQ — https://github.com/grandideastudio/jtagulator/wiki/Frequently-Asked-Questions
- Hardware-Modifications — https://github.com/grandideastudio/jtagulator/wiki/Hardware-Modifications
- Logic-Analyzer — https://github.com/grandideastudio/jtagulator/wiki/Logic-Analyzer
- OpenOCD — https://github.com/grandideastudio/jtagulator/wiki/OpenOCD
- HW Rev. C 회로도 — https://github.com/grandideastudio/jtagulator/blob/master/Hardware/Rev.%20C/jtagulator_schematic.pdf
- HW Rev. C BOM — https://github.com/grandideastudio/jtagulator/blob/master/Hardware/Rev.%20C/jtagulator_bom.pdf
- 기능 시험 절차서 — https://github.com/grandideastudio/jtagulator/blob/master/Hardware/jtagulator_testproc.pdf
- EXPLIoT 제품 페이지 — https://expliot.io/jtagulator/

**보조 자료 (형식 교차 확인용, FW 1.6)**
- hcw.ac.at 위키 "JTAGulator: Find IoT-Device's UART interface" — https://elvis.hcw.ac.at/wiki/index.php/JTAGulator:_Find_IoT-Device%27s_UART_interface
