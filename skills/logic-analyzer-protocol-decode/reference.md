# logic-analyzer-protocol-decode 참고표

[SKILL.md](SKILL.md) 의 절차에서 링크하는 긴 표와 예시를 모은 문서다.

출처는 둘이다.
- `mcp-servers/sigrok-mcp/README.md` 와 `docs/references/sigrok-cli.md`
- 2026-10-18 실측: sigrok-cli 0.7.2, libsigrok 0.5.2, libsigrokdecode 0.5.3 에서 demo 드라이버와 합성 UART/SPI/I2C 파형으로 확인했다.

표의 ✓ 표시는 이 Skill 작성 시 서버를 통해 실제로 실행해 확인한 항목이다. 실제 USB 로직 애널라이저에서는 아직 검증하지 않았다.

## 1. samplerate 선택

**UART.** 비트당 10샘플 이상을 권장한다. 8배까지는 실측상 양호하다. 4배 미만이면 추정기가 경고한다.

| baud | 최소 권장 samplerate (fx2lafw 목록) | 배율 |
|---|---|---|
| 모름 | **8 MHz** 로 첫 캡처 | 921600 까지 8.7배 이상 |
| 9600 | 100 kHz | 10.4 |
| 19200 | 200 kHz | 10.4 |
| 38400 | 500 kHz | 13.0 |
| 57600 | 1 MHz | 17.4 |
| 115200 | 2 MHz (1 MHz = 8.7배도 동작) | 17.4 |
| 230400 | 3 MHz | 13.0 |
| 460800 | 6 MHz | 13.0 |
| 921600 | 12 MHz | 13.0 |
| 1500000 | 16 MHz | 10.7 |
| 3000000 | 24 MHz | 8.0 (10배 불가) |

**SPI / I2C**

| 버스 | 규칙 | fx2lafw(최대 24 MHz)로 가능한 범위 |
|---|---|---|
| SPI | SCK 의 4배 이상, 권장 8~10배 | SCK ≤ 약 6 MHz. 카메라 SoC 부팅 SPI 는 보통 더 빠르다. 고속 LA(DSLogic 등, 채널 수를 줄이면 100 MHz 이상)가 필요하다 |
| I2C 100 kHz | 1~2 MHz | 충분 |
| I2C 400 kHz | 4~8 MHz | 충분 |
| I2C 1 MHz (Fm+) | 8 MHz 이상 | 12~24 MHz 권장 |

**fx2lafw 이산 samplerate 목록 (libsigrok 0.5.2 소스)**: 20k, 25k, 50k, 100k, 200k, 250k, 500k, 1M, 2M, 3M, 4M, 6M, 8M, 12M, 16M, 24M, 48M.
- 48M 항목은 목록에만 있다. 실사용 상한은 24 MHz 로 본다.
- 16채널 모드의 상한은 12 MHz 다.
- 실제 목록은 `sigrok_device_info` 의 `samplerates` 로 확인한다.

**데이터량과 길이의 트레이드오프** (압축 전 크기, 8채널 이하는 샘플당 1바이트)

| samplerate | 10 s | 20 s | 30 s |
|---|---|---|---|
| 1 MHz | 10 MB | 20 MB | 30 MB |
| 2 MHz | 20 MB | 40 MB | 60 MB |
| 8 MHz | 80 MB | 160 MB | 240 MB |
| 24 MHz | 240 MB | 480 MB | 720 MB |

srzip 은 idle 이 많은 신호를 크게 압축한다. 예: 40M 샘플 UART 캡처가 74 KB 였다.

**서버 동작 기준** (impl report, README)

| 대상 | 기준 |
|---|---|
| `sigrok_capture` | 예상 시간 20 s 초과나 트리거 사용 시 job 으로 실행. `background=true` 로 강제할 수 있다 |
| `sigrok_decode` | 50M 샘플 초과나 64 MiB 초과 입력이면 job 으로 실행. 동기 디코드는 55 s 에서 멈춘다 |
| `sigrok_uart_autodecode` | 100M 샘플 초과나 128 MiB 초과 입력이면 job 으로 실행 |
| 활동 분석 | 압축 해제 기준 256 MiB~1 GiB 근처에서 잘린다(`activity_truncated`) |
| 추정 | 에지 2M 개, auto 모드는 채널당 300k 에서 잘린다 |
| 디코드 출력 | 512 MiB 에서 멈추고 `output_truncated` 를 표시한다 |

## 2. 디코더 스택과 annotation

**공통 규칙**
- **채널 매핑은 필수다.** 입력 파일에 있는 채널 이름을 쓴다(`sigrok_file_info` 의 channels).
- **스택에서는 첫 디코더만 채널을 받는다.** 두 번째 이후 디코더에 채널을 주면 `[validation_failed]` 가 난다.
- **값에는 `:` `,` `=` 와 공백을 넣을 수 없다.** 스택은 최대 8개다.
- **옵션·annotation 이름은 `sigrok_decoder_help(decoder=…)` 로 확인한다.** 응답의 `decoder.options`, `decoder.annotation_classes`, `decoder.annotation_rows` 를 본다.
  - 없는 annotation(예: 0.5.3 에서 `uart=rx-warning`)을 주면 `[sigrok_unknown_annotation] … Annotation 'rx-warning' not found` 가 난다. ✓
  - 없는 옵션(예: `parity_type`)을 주면 `[validation_failed] 디코더 uart 에 없는 옵션/채널` 이 나고 사용 가능한 목록이 함께 온다. ✓
- **annotations 는 항상 지정한다.** 생략하면 스택 안 모든 디코더의 모든 클래스가 출력된다. annotations 에는 클래스 이름이나 행(row) 이름을 쓸 수 있다.

| 목적 | decoders | annotations | 비고 |
|---|---|---|---|
| UART 수신(대상 TX) | `uart:rx=RX:baudrate=115200` | `uart=rx-data` | ✓ 기본 format=hex. `format=ascii` 면 제어문자를 `[0D]` 처럼 표기 |
| UART 양방향 | `["uart:rx=RX:baudrate=115200", "uart:rx=TX:baudrate=115200"]` | `uart=rx-data` | ✓ `uart-1`=RX 선, `uart-2`=TX 선 |
| UART 반전 라인 | `uart:rx=RX:baudrate=115200:invert_rx=yes` | `uart=rx-data` | ✓ autodecode 가 idle_level 0 에서 자동 적용 |
| UART 7E1 | `uart:rx=RX:baudrate=115200:data_bits=7:parity=even` | `uart=rx-data:rx-warnings` | 0.5.3 옵션 이름은 parity/data_bits/stop_bits |
| UART 구간별 보드레이트 | `["uart:rx=RX:baudrate=57600:format=ascii", "uart:rx=RX:baudrate=115200:format=ascii"]` + `samplenum=true` | `uart=rx-data:rx-warnings` | ✓ 인스턴스별로 깨끗한 샘플 구간을 비교 |
| SPI 전송(CS 구간) | `spi:clk=CLK:mosi=MOSI:miso=MISO:cs=CS` | `spi=mosi-transfer:miso-transfer` | ✓ 같은 구간에서 MISO 줄이 먼저 나온다 |
| SPI 플래시 명령 | `spi:clk=CLK:mosi=MOSI:miso=MISO:cs=CS,spiflash` | `spiflash=commands` | ✓ 행 이름 |
| SPI 플래시 읽기·ID 만 | `…,spiflash` | `spiflash=read:rdid` | ✓ |
| SPI mode 3 | `spi:…:cpol=1:cpha=1` | | 데이터가 1비트 밀려 보일 때 |
| I2C 주소·데이터 | `i2c:scl=SCL:sda=SDA` | `i2c=addr-data` | ✓ 7비트 주소(`Address write: 50`) |
| I2C 8비트 주소 표기 | `i2c:scl=SCL:sda=SDA:address_format=unshifted` | `i2c=addr-data` | `A0`/`A1` 로 표기 |
| 24xx EEPROM 동작 | `i2c:scl=SCL:sda=SDA,eeprom24xx` | `eeprom24xx=ops` | ✓ `Sequential random read (addr=00, 4 bytes): …` |
| EEPROM 칩 지정 | `…,eeprom24xx:chip=microchip_24lc64` | `eeprom24xx=ops` | chip 값은 `sigrok_decoder_help` 의 options |

**autodecode 와 REA 메모**
- `sigrok_uart_autodecode` 가 쓰는 annotations 는 `uart=rx-data:rx-warnings` 다. 결과 텍스트 파일은 `signals/<입력>.<채널>.uart-<baud>.txt`, 바이트 파일은 같은 이름의 `.bin` 이다. ✓
- REA `decode_signal_recording` 은 `path`(절대 경로), `decoders`(문자열), `annotations`(문자열)를 받는다. 출력은 `line_offset`/`line_limit` 로 페이징한다. ✓
  - 결과는 `normalized_result.annotations_text` 에 samplenum 이 붙은 줄로 들어 있다. 근거는 `evidence_id` 다.
  - 케이스에 파일을 쓰지 않는다.
  - 채널 이름을 미리 검사하지 않는다. 없는 채널(`rx=D7`)이면 첫 채널을 디코드한 결과가 나오고 `normalized_result.diagnostics` 에 `cli: No channel with name "D7" found.` 가 남는다. ✓ diagnostics 가 비어 있지 않으면 결과를 버린다.

## 3. SPI NOR 참고

**SOIC-8 핀** (25 계열 SPI NOR, 예: W25Q/MX25L/GD25Q). 연결 전에 칩 데이터시트로 확인한다. WSON 패키지는 클립을 물릴 수 없다.

| 핀 | 신호 | LA 연결 |
|---|---|---|
| 1 | CS# | D0 (`CS`) |
| 2 | DO (IO1) | D3 (`MISO`) |
| 3 | WP# (IO2) | 연결 안 함. quad 구간은 어차피 복원 불가 |
| 4 | GND | LA GND (**가장 먼저**) |
| 5 | DI (IO0) | D2 (`MOSI`) |
| 6 | CLK | D1 (`CLK`) |
| 7 | HOLD#/RESET# (IO3) | 연결 안 함 |
| 8 | VCC | **연결 안 함** (클립 VCC 는 아무 데도 연결하지 않음) |

**자주 보이는 명령 바이트** (MOSI 첫 바이트)

| 바이트 | 명령 | 이 Skill 에서의 의미 |
|---|---|---|
| `9F` | RDID | MISO 3바이트 = JEDEC ID |
| `90` / `AB` | REMS / RES | 제조사·장치 ID (구형) |
| `05` / `35` | RDSR / RDSR2 | 상태 레지스터 폴링 |
| `03` | READ (3바이트 주소) | 1비트 읽기. 주소와 데이터 모두 디코드 가능 |
| `0B` | FAST READ | 1비트 읽기 + dummy |
| `3B` / `6B` | dual / quad output read | 명령·주소는 보이지만 데이터는 복원 불가 |
| `BB` / `EB` | dual / quad I/O read | 주소부터 복원 불가 |
| `B7`, `13`, `0C` | 4바이트 주소 모드, 4바이트 주소 읽기 | 32 MiB 이상 칩 |
| `06` / `04` | WREN / WRDI | 쓰기 준비. 관찰만 한다 |
| `02` | PP (page program) | **쓰기**. 관찰로만 기록 |
| `20` / `52` / `D8` / `C7`·`60` | 4K / 32K / 64K / 칩 전체 erase | **지우기**. 관찰로만 기록 |

**JEDEC ID** (RDID 응답 3바이트: 제조사, 메모리 타입, 용량 코드). 대표 예이므로 최종 판단은 칩 마킹과 데이터시트로 한다.

| 제조사 바이트 | 제조사 | 예 |
|---|---|---|
| `EF` | Winbond | `EF 40 17` W25Q64, `EF 40 18` W25Q128, `EF 40 19` W25Q256 |
| `C2` | Macronix | `C2 20 17` MX25L64xx, `C2 20 18` MX25L128xx, `C2 20 19` MX25L256xx |
| `C8` | GigaDevice | `C8 40 17` GD25Q64, `C8 40 18` GD25Q128 |
| `20` | Micron / XMC | `20 BA 18` N25Q128, `20 70 18` XM25QH128 |
| `1C` | EON | `1C 70 18` EN25QH128 |
| `9D` | ISSI | `9D 60 18` IS25LP128 |
| `01` | Spansion/Cypress | `01 20 18` S25FL128S |

용량 코드는 대부분 2^N 바이트다. `17` 은 8 MiB, `18` 은 16 MiB, `19` 는 32 MiB 다.

**읽힌 데이터로 형식 짐작** (`Read data` 결과의 첫 바이트)

| 바이트 | 형식 |
|---|---|
| `27 05 19 56` | uImage |
| `D0 0D FE ED` | FIT/DTB |
| `68 73 71 73` ("hsqs") | squashfs(LE) |
| `1F 8B` | gzip |
| `55 42 49 23` ("UBI#") | UBI |
| `85 19` / `19 85` | JFFS2 (LE/BE) |

부팅 순서상 보통 오프셋 0(부트로더)을 먼저 읽고, 그다음 커널, rootfs 순서로 읽는다. 주소는 `case_add_note` 로 남겨 `fw_carve` 와 파티션 추정에서 교차 확인한다.

## 4. 해석과 문제 해결

| 증상 | 가능한 원인 | 조치 |
|---|---|---|
| 모든 채널의 에지가 0 | 캡처 전에 이미 부팅이 끝남, GND 미연결, 1.8 V 레벨(fx2lafw VIH 2.0 V), 잘못된 패드 | 캡처를 먼저 시작(SKILL 5(a))하고 GND·전압을 재확인한다. 다른 후보 패드를 본다 |
| 채널이 늘 0 (high_ratio 0) | GND 패드, 대상 전원 꺼짐, 프로브 빠짐 | 배선과 전원 확인 |
| 채널이 늘 1, 에지 0 | 풀업된 입력(대상 RX 후보), VCC | RX 후보로 기록. VCC 면 프로브를 뗀다 |
| idle LOW 이고 estimate idle_level 0 | 반전 라인(트랜시버 뒤 등) | `invert_rx=yes`. ±V 전압이면 즉시 연결을 해제한다 |
| idle_level 0 인데 file_info 의 처음/끝 레벨은 1 | 짧은 구간과 다른 보드레이트가 섞여 극성을 오판함(실측) | SKILL 7-4 의 두 스택 디코드. 극성은 `sigrok_decode` 에서 직접 지정한다(autodecode 는 극성을 바꿀 수 없음) |
| confidence < 0.5, "4배 미만" 경고 | 오버샘플링 부족(실측: 115200 @ 400 kHz → confidence 0.49) | `recommended_samplerate` 이상으로 재캡처. 이 값은 넘기지 않는다 |
| `stats.glitches` 가 많음, 1~2샘플 펄스 | 링잉, 노이즈, 긴 GND 리드 | GND 를 측정점 가까이에, 리드를 짧게. 추정기는 1샘플 글리치를 제외한다 |
| printable_ratio < 0.7 | 보드레이트·극성·데이터 형식이 틀렸거나 바이너리 구간 | `candidates[]` 순회, b 와 2b, 7E1 시도 |
| b 와 b/2 둘 다 framing 0 | 모든 run 이 짝수 배인 데이터의 T/2T 모호성 (sigrok-cli.md §12.6) | 둘 다 디코드해 문자 수(2배)와 printable 비율을 비교한다. 텍스트 부트 로그 구간으로 판단한다 |
| `segments[]` 의 보드레이트가 다름 | BootROM/SPL/U-Boot/커널 속도 차이 | SKILL 7-4. 콘솔 구간의 값을 넘긴다 |
| "Starting kernel ..." 뒤 조용함 | 커널 콘솔이 다른 UART, `quiet`, `console=` 없음 | U-Boot 인터럽트 경로. 다른 패드도 캡처해 본다 |
| 텍스트 반쯤 맞고 프레임 오류 다수 | 패리티, 7비트 | `data_bits=7, parity="even"` |
| 요청보다 적은 샘플 | USB 대역폭/버퍼(WSL usbipd 포함). demo + 트리거는 약 4096 샘플로 고정(실측) | samplerate 를 낮춘다. 트리거 없이 (a) 방식으로 캡처한다 |
| 트리거 시간 초과(job failed) | 신호 없음, 극성 반대(`f`/`r`), 채널 오지정 | 채널과 극성 확인 후 트리거 없이 재캡처 |
| 캡처 job timeout("…초 안에 끝나지 않아 종료함") | 장치가 실시간으로 데이터를 못 보냄. demo 는 실시간보다 느림(실측: 2 MHz × 15 s → 58 s, 8 MHz × 3 s → 37 s). 기본 제한은 예상 + 30 s(트리거면 + 60 s) | `<name>-partial.sr` 로 분석을 계속하거나, samplerate 를 낮추고 `timeout_s` 를 늘린다. demo 연습은 짧게 |
| warnings "디코드 결과 0줄" | 보드레이트, 채널, 디코더 옵션, annotations 오류 | `sigrok_decoder_help` 로 이름 확인, 채널 재확인 |
| `output_truncated` true | 디코드 출력 512 MiB 상한 | annotations 를 좁힌다 |
| 디코드 TimeoutExpired | 동기 55 s 상한 | `background=true` 후 `sigrok_job_status` |
| `[validation_failed] 채널 'X' … 입력 파일에 없습니다` | rename 전 이름을 씀 | `sigrok_file_info` 의 channels 이름을 쓴다 |
| SPI `Device = <vendor> Unknown` | spiflash `chip` 옵션의 이름일 뿐 | RDID 응답 바이트(§3)로 판단 |
| SPI 명령 바이트가 MISO 쪽에 보임 | MOSI/MISO 뒤바뀜 | 매핑을 바꿔 다시 디코드(재캡처 불필요) |
| SPI 데이터가 1비트 밀림 | SPI 모드 차이 | `cpol=1:cpha=1` |
| SPI 경고 `CS# was deasserted during this data word!` | CS 노이즈, samplerate 부족 | samplerate 를 올리고 CS GND 리드를 짧게 |
| I2C 에서 NACK 만 보이거나 주소가 없음 | SCL/SDA 뒤바뀜, samplerate 부족, 1.8 V 풀업 | 매핑 교체, samplerate 상향, 전압 확인 |

## 5. 선택: 발견사항 기록 예

신호 관찰 자체가 보안상 의미 있을 때만 기록한다. 예: EEPROM 에 평문 자격증명이 있는 경우다. 값은 마스킹한다. id 는 서버가 붙인다.

```text
case_add_finding(case_id="20261018-acme-ipc", finding={
  "title": "부팅 중 I2C EEPROM 에서 평문 관리자 비밀번호로 보이는 문자열 읽힘",
  "category": "info-leak",
  "severity": "medium",
  "confidence": "likely",
  "status": "unverified",
  "summary": "부팅 중 0x50 EEPROM 순차 읽기(addr 0x40, 16 bytes)에서 ASCII 문자열 'ad******' 관찰 (평문 저장 의심)",
  "location": {"interface": "i2c", "offset": "0x40"},
  "evidence": [{"type": "signal", "ref": "signals/i2c-boot.i2c-002.txt",
                "excerpt": "eeprom24xx-1: Sequential random read (addr=40, 16 bytes): 61 64 .. (마스킹)"}],
  "reasoning": "보드의 I2C 버스를 수동 관찰한 결과, 펌웨어가 부팅 때마다 EEPROM 의 같은 오프셋을 읽고 그 값이 웹 UI 로그인 비밀번호 길이·문자 집합과 일치한다. 물리 접근만으로 자격증명이 노출된다.",
  "verification_plan": "firmware-static-analysis 에서 EEPROM 읽기 코드와 인증 비교 경로를 확인한다. 격리 랩에서 소유 기기의 비밀번호를 바꾼 뒤 같은 오프셋 값이 바뀌는지 관찰한다.",
  "produced_by": {"skill": "logic-analyzer-protocol-decode", "tool": "sigrok_decode"}
})
```

## 6. 캡처 파일이 없을 때의 실패 기록

`signal-capture` 스키마는 capture.file 을 요구한다. 그래서 캡처 파일이 하나도 없으면(LA 미검출, 정책 거부 등) summary 를 저장할 수 없다.
이때는 summary 가 아닌 step 이름으로 남기고 단계 상태를 직접 바꾼다. step 결과의 data 는 summary 일 때만 스키마 검사를 받는다.

```text
case_record_step(case_id="20261018-acme-ipc", skill="logic-analyzer-protocol-decode", step="capture", status="blocked",
                 summary="로직 애널라이저 미검출: sigrok_scan count 0 (usbipd attach·재스캔 2회 후)",
                 data={"driver_tried": "fx2lafw", "scan_count": 0},
                 blockers=["로직 애널라이저가 분석 PC 에서 보이지 않음 (WSL usbipd / udev 권한)"],
                 next_actions=["사람: usbipd attach 와 udev 권한 확인 후 재시도", "대안: JTAGulator UART 스캔 또는 멀티미터로 TX 패드 탐색"])
case_set_phase(case_id="20261018-acme-ipc", phase="logic-analyzer-protocol-decode", status="failed", note="캡처 파일 없음: LA 미검출")
```

캡처 파일이 하나라도 있으면(활동이 없는 캡처라도) 그 파일로 summary(status `failed`)를 남긴다. 그러면 단계 상태가 자동으로 갱신된다.
