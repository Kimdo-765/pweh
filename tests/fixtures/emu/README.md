# tests/fixtures/emu — 펌웨어 에뮬레이션 픽스처

pweh-emu(`mcp-servers/emu-mcp`) 와 AVR 실행기(`native/emu/pweh_avr_run.c`) 시험용 합성 펌웨어다. 모두 손으로 어셈블·인코딩했고
(avr-gcc·ESP-IDF 없음) 실제 기기·덤프에서 나온 것이 없다. 생성기는 표준 라이브러리만 쓰고 결정적이며, 시험
(`tests/servers/test_emu_fixtures.py`)이 생성기 출력과 커밋한 파일이 같은지 확인한다.

| 파일 | 내용 |
|---|---|
| `make_avr_uart_echo.py` | AVR UART 에코 생성기. 미니 어셈블러 `Asm`·`intel_hex` 도 여기 있다 (`make_avr_oob_probe.py` 가 쓴다) |
| `avr_uart_echo_m328p.hex` | ATmega328P 16 MHz, USART0 115200 8N1(U2X0). `OK\r\n` 을 보내고 받은 바이트를 돌려준다. 0x04 를 받으면 `cli; sleep` 으로 멈춘다 (종료 코드 0). 98 바이트, sha256 `473124e258f7a86313fdb251e198a9ffaa5cbe9280c6da970eb86681ae31fafa` |
| `make_avr_oob_probe.py` | 플래시 범위 밖 접근(OOB) 탐침 생성기. 기대 출력은 `EXPECTED` |
| `avr_oob_probe_m328p.hex` | ATmega328P: LPM Z=0xFFFF, 플래시 끝 너머 LPM·SPM 페이지 지우기, RAMPZ 없는 ELPM(r0=0xFF), HEX 의 EEPROM 레코드 되읽기 |
| `avr_oob_probe_m2560.hex` | ATmega2560: RAMPZ=0xFF ELPM·SPM 페이지 지우기(색인 0xFFFF00), 유형 04 레코드로 0x1FFFC 에 둔 표식 `PWEH` 를 ELPM 으로 읽기 |
| `mkimg_esp.py` | ESP32·ESP32-S3·ESP32-C3 의 `hello`(`PWEH-QEMU-OK\r\n`)·`echo`(`PWEH-ECHO>\r\n` 뒤 에코)·`reset`(소프트웨어 리셋) 이미지와 전체 플래시(0xFF 채움) 생성기. 플래시 이미지는 커밋하지 않고 시험 때 만든다 |

## AVR 실행기에서의 기대 결과

`pweh_avr_run --mcu <mcu> --freq 16000000 [--realtime] (--hex-fd N | <파일>.hex)`:

| 펌웨어 | MCU | 기대 |
|---|---|---|
| `avr_uart_echo_m328p.hex` | atmega328p | stdout `OK\r\n`, 입력 바이트가 그대로 돌아옴, 0x04 → `state=done`, 종료 코드 0 |
| 충돌 HEX (아래 두 줄) | atmega328p | `jmp` 로 지운 플래시(0xFFFF) 끝까지 → `state=crashed`, 종료 코드 3, 소켓 없음 (GDB 서버를 열지 않음) |
| `avr_oob_probe_m328p.hex` | atmega328p | stdout `L\xff B\xff\xff\xff\xff S\xff\xff\xff\xff E\xff R EEOK \r\n` (공백 없이), 종료 코드 0. stderr 에 ELPM 의 "Invalid Opcode" 로그 한 줄 |
| `avr_oob_probe_m2560.hex` | atmega2560 | stdout `E\xff\xff\xff\xff S\xff\xff\xff\xff F PWEH \r\n` (공백 없이), 종료 코드 0 |

충돌 HEX (시험 안의 문자열 — 4바이트 `jmp 0x7FFE` + EOF):

```
:040000000C94FF3F1E
:00000001FF
```

넓히기 수정이 없던 연구 단계의 실행기는 328p 탐침에서 호스트 힙 내용을 내보낸 뒤 SIGSEGV 로, 2560 탐침은 첫 ELPM 에서 SIGSEGV 로
끝났다. RAMPZ 유무로 버퍼 크기를 고르면 328p 의 `E`(RAMPZ 대신 r0 을 쓰는 ELPM)에서 SIGSEGV 가 남는다 — 그래서 실행기는 MCU 와
상관없이 24비트 색인 전체를 덮는다 (`native/emu/README.md`).

## 다시 만들기

```
python3 -I tests/fixtures/emu/make_avr_uart_echo.py --out-dir tests/fixtures/emu        # --listing 이면 .lst 도
python3 -I tests/fixtures/emu/make_avr_oob_probe.py --out-dir tests/fixtures/emu
python3 -I tests/fixtures/emu/mkimg_esp.py --out-dir <임시 디렉터리> [--flash]          # 커밋하지 않는다
```

생성기를 바꾸면 실제 실행기·에뮬레이터로 다시 확인하고(`@pytest.mark.external` 시험) 커밋한 HEX 도 함께 바꾼다.
에코 HEX 의 sha256 은 바뀌면 안 된다 (서버 시험·문서가 이 값을 쓴다).
