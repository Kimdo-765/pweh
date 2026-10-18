# U-Boot 및 임베디드 리눅스 부트 콘솔 레퍼런스 (IP 카메라용)

> **대상 독자**: `uart-mcp`(pyserial 콘솔 드라이버), `fwtriage-mcp`(U-Boot env·mtdparts 파서), mock-device 시뮬레이터 구현자, 그리고 `uart-shell-acquisition` / `firmware-dump-via-uart` Skill 작성자.
>
> **범위**: 본인 소유 또는 서면 허가를 받은 카메라의 UART 콘솔에서 U-Boot와 리눅스 부트 출력을 **인식하고, 안전하게 자동화하고, 플래시를 백업**하는 데 필요한 정확한 문자열·포맷·동작 규칙. 인증 우회, 잠긴 부트로더 해제, 비밀번호 추측, 부트 인자의 영구 변경 같은 절차는 **의도적으로 다루지 않는다**. 셸을 얻기 위한 부트 인자 변경은 사용자의 명시적 동의를 받은 RAM 한정 `init=/bin/sh` 한 가지만 프로젝트 정책으로 허용하며, 그 절차는 이 문서가 아니라 Skill 에 있다([§12](#12-범위에서-제외한-항목)).
>
> **조사일**: 2026-10-18. 모든 소스 인용은 [§17](#17-참고-자료)의 태그/커밋 해시에 고정되어 있다.

## 표기 규칙

- 코드 블록의 문자열은 **소스 코드의 printf 포맷 문자열** 또는 **실제 출력**을 그대로 옮긴 것이다. `%08lx` 같은 지정자는 C printf 의미 그대로다.
- `[UB-2010.06] common/main.c:221` 형식은 §17에 정의한 저장소·태그 기준의 파일 경로와 줄 번호다.
- **(미확인)**: 1차 출처(소스 코드, 공식 문서, 원본 로그)를 찾지 못한 항목. 기본값으로 쓰지 말고 후보로만 취급한다.
- **(유도)**: 소스의 매크로 값을 조합해 계산한 값. 실제 출력으로 확인한 것은 아니다.
- **(합성)**: 이 문서에서 만든 예시. 포맷은 소스로 검증했지만 값(주소, 날짜, 크기 등)은 지어낸 것이다.

카메라 SoC의 U-Boot는 메인라인을 포크한 것이라서 **출력 포맷은 포크의 베이스 버전이 결정한다**. OpenIPC가 미러링한 벤더 포크의 베이스 버전은 다음과 같다(각 저장소 `Makefile`의 `VERSION`/`PATCHLEVEL`).

| 벤더 포크 | U-Boot 베이스 | 출처 |
|---|---|---|
| HiSilicon V1~V3 (Hi3516CV100/CV200/CV300, Hi3518EV200, Hi3519V101) | 2010.06 | `[OI-hi3516cv200]` |
| HiSilicon V4 (Hi3516EV200/EV300, Hi3518EV300), Hi3516CV500 | 2016.11 | `[OI-hi3516ev200]` |
| Goke GK7205V200/V300, GK7202V300 | 2016.11 | `[OI-gk7205v200]` |
| Ingenic T20/T21/T30/T31 (T40/T41 SDK 포함) | 2013.07 (+SPL) | `[OI-ingenic]`, `[OI-t40]` |
| SigmaStar Infinity5/6/6E/6C, MStar Infinity3 (MSC313E) | 2015.01 | `[OI-sigmastar]`, `[OI-msc313e]` |
| Grain Media GM8126/GM8136/GM8139/GM8210/GM8287 | 2013.01 | `[OI-grainmedia]` |
| Novatek NA51055 (NT9856x) | 2019.04 | `[OI-nt9856x]` |
| XMedia XM72xx/XM76xx | 2020.01 | `[OI-xmedia]` |
| Rockchip (`rockchip-linux/u-boot` `next-dev`) | 메인라인 2017.09 계열 포크 | `[RK]` |

---

## 0. 드라이버 안전 규칙 (가장 먼저 읽을 것)

아래 규칙은 이 문서의 소스 분석에서 나온 결론이다. `uart-mcp`의 기본 동작과 mock-device 테스트 케이스로 그대로 옮긴다.

| # | 규칙 | 근거 |
|---|---|---|
| R1 | **U-Boot 프롬프트에서 줄 종결자는 `\r` 한 바이트만 보낸다(기본값). `\r\n`은 금지.** readline은 `\r`과 `\n`을 **각각** Enter로 처리하므로 `\r\n`은 "명령 + 빈 줄"이 된다. `\n` 한 바이트도 readline에서는 Enter지만 **`\r`만 받는 경로**가 있으므로 기본값으로 쓰지 않는다: 2010.06 `setenv baudrate` 뒤 확인 대기(`getc() == '\r'`, `[UB-2010.06]` common/cmd_nvedit.c:290-293), keyed autoboot의 CR 키(OpenIPC Ingenic `CONFIG_AUTOBOOT_STOP_STR "\x0D"`, SigmaStar/MStar `CONFIG_AUTOBOOT_DELAY_STR "\x0d"`). | §2.1, §6.2, §8.4 |
| R2 | **빈 줄(맨 Enter)을 프롬프트 확인용으로 보내지 않는다.** 빈 줄은 직전 명령을 **반복 실행**한다(simple 파서, hush 모두). `sf`는 하위 명령을 가리지 않고 반복 가능이라 `sf erase`/`sf write`/`sf update`도 다시 실행된다. `mw`, `cp`, `run`, `bootm`, `tftpboot`도 반복 가능이다. 2010.06(HiSilicon V1~V3 포크 포함)의 `nand`와 2010.06·2013.07(Ingenic 포크 포함)의 `mmc`에는 하위 명령별 반복 검사가 없어 `nand erase/write`, `mmc write/erase`도 반복된다. | §2.3, §2.4 |
| R3 | **"새 프롬프트 받기"는 Ctrl-C(0x03)로 한다.** 프롬프트 상태에서 0x03은 에코 없이 `<INTERRUPT>`를 출력하고 새 프롬프트를 낸다. 단, simple 파서는 Ctrl-C 뒤에도 직전 명령을 기억하므로 R2는 계속 지켜야 한다(hush는 반복 상태를 지운다). | §10 |
| R4 | **명령 완료의 증거(프롬프트 또는 마커)를 받기 전에는 다음 바이트를 보내지 않는다.** 실행 중인 명령이 `ctrlc()`를 폴링하면 0x03이 아닌 수신 바이트를 **읽고 버린다**(type-ahead 소실). | §2.5 |
| R5 | **완료 판정은 "프롬프트 재출현" 또는 "마커 줄"로 한다.** `Read: OK` 같은 결과 문자열에 기대지 않는다. HiSilicon 2010.06 포크의 `sf read`는 성공 시 **빈 줄 하나만** 출력한다. | §5.2 |
| R6 | 마커 기법: `<명령>; echo __pweh_<nonce>` 를 보내고 **줄 시작에 고정한** 정규식 `^__pweh_<nonce>\r?$` 를 기다린다. `echo`가 없는 빌드가 적지 않다: HiSilicon V1~V3 SDK(`CONFIG_CMD_ECHO` 없음), XMedia 벤더 `xm72020300_defconfig:472`, HiSilicon V4/Goke `*_mini_defconfig`, hi3556v200·hi3559v200·hi3519av100_amp·hi3556av100 defconfig(`# CONFIG_CMD_ECHO is not set`). 그러므로 SoC 프로파일로 추측하지 말고 **세션마다 한 번** `echo __pweh_probe`를 보내 `Unknown command 'echo' - try 'help'`가 나오는지 확인한다. 없으면 `<명령>; printenv __pweh_<nonce>` 를 쓰고 `^## Error: "__pweh_<nonce>" not defined\r?$` 를 기다린다. 에코된 입력 줄에서는 마커가 줄 중간에 있어 오탐되지 않는다. | §2.8 |
| R7 | 명령 줄은 `CONFIG_SYS_CBSIZE` − 2 문자 이하로 유지한다(편집 없는 readline은 `n >= CONFIG_SYS_CBSIZE - 2`부터 거부). CBSIZE는 카메라 SDK에서 **256**~1024(Grain Media GM8126/GM8210/GM8287은 256), OpenIPC 빌드는 1024~2048이다. 넘치는 문자는 BEL(`\a`)과 함께 **버려진다**. 인자 수가 `CONFIG_SYS_MAXARGS`(16/32/64)를 넘으면 `** Too many args (max. %d) **`. | §2.7 |
| R8 | U-Boot 출력의 모든 줄은 `\r\n`으로 끝난다(시리얼 드라이버가 `\n` 앞에 `\r` 삽입). 예외: 편집 없는 readline의 Enter 에코는 `puts("\r\n")`이 변환되어 `\r\r\n`이다(§2.1). 파서는 `\r*\n`로 나누고, 프롬프트는 줄바꿈 없이 끝나므로 **수신 버퍼 끝**에서 찾는다. | §2.1 |
| R9 | `md`는 **크기 접미사와 길이를 항상 명시**한다. 길이 인자는 직전 `md` 값이 남는다(sticky). | §3.1 |
| R10 | `setenv`는 RAM 사본만 바꾼다. `saveenv`/`env save`는 **플래시 쓰기**다. 사용자 확인 없이 실행하지 않는다. 단, 우리 명령 없이도 플래시가 바뀌는 경우가 있다(아래는 소스로 확인한 **예**이며 전부가 아니다). (a) HiSilicon V1~V3(2010.06) 포크는 부팅 시 env의 CRC 워드가 `0xFFFFFFFF`(지워진 플래시)이면 `*** Write default environment to flash`를 출력하고 **스스로** `saveenv()`를 호출한다(`[OI-hi3516cv200]` common/env_sf.c:157-163). (b) OpenIPC Ingenic·SigmaStar·XMedia 빌드의 컴파일 기본 `bootcmd`는 `setenv bootcmd ${cmdnor}; sf probe 0; saveenv; run bootcmd`라서, 기본 env로 부팅하면 첫 autoboot에서 `saveenv`가 실행된다(`[OI-ingenic]` isvp_common.h:52, `[OI-sigmastar]` sstar-common.h:38·75, `[OI-xmedia]` xm-common.h:42). (c) OpenIPC Goke 빌드의 `bootcmd`는 `run fwrecovery`로 시작하고, env `bootfail`이 있으면 `*** RECOVERY: kernel/rootfs invalid, reflashing -- do not power off ***`를 출력한 뒤 kernel/rootfs를 다시 쓴다(`[OI-gk7205v200]` gk-common.h:2,10). autoboot 중 `Saving Environment to`, `Erasing SPI flash` 같은 줄이 보이면 case 기록에 남긴다(§15.1). | §6.2 |
| R11 | Tab(0x09, 자동완성)이나 ESC/화살표 시퀀스(명령 이력)를 보내지 않는다. 입력 중인 줄을 지우려면 Ctrl-U(0x15). hush에서 따옴표가 닫히지 않으면 보조 프롬프트 `> `(OpenIPC HiSilicon/Goke 빌드는 ` > `, hi-common.h `CONFIG_SYS_PROMPT_HUSH_PS2 " > "`)가 뜬다. 이때는 Ctrl-C로 빠져나온다. | §2.6, §2.8 |
| R12 | 플래시 쓰기·지우기(`sf erase/write/update`, `nand erase/write`, `mmc write/erase`, `saveenv`, `mw`)는 Skill의 **명시적 사용자 승인 단계**를 거친 뒤에만 보낸다. | 프로젝트 안전 정책 |

---

## 1. SoC/벤더별 프로파일

시뮬레이터 프로파일과 Skill의 "기기 식별" 단계가 쓰는 표다. 칸마다 출처를 달았다. **ODM이 SDK 기본값을 바꾸는 일이 흔하므로** 실제 기기에서는 부트 로그로 다시 확인해야 한다.

**OpenIPC 미러를 인용할 때의 주의**: 이 저장소들의 보드 헤더는 파일 끝에서 OpenIPC 공통 헤더를 include해 프롬프트·env 위치·autoboot·파서를 **다시 정의**한다. 예: `[OI-hi3516cv200]` hi3518ev200.h:351 → hi-common.h, `[OI-hi3516ev200]` hi3516ev200.h:270 → hi-common.h, `[OI-gk7205v200]` gk7205v200.h:264 → gk-common.h, `[OI-sigmastar]` infinity6e.h:491 → sstar-common.h, `[OI-ingenic]` isvp_t31.h:719 → isvp_common.h. 아래 "SDK" 행은 그 include **이전**의 벤더 값을 인용한 것이고, "OpenIPC 빌드" 행이 include **이후** 값이다. `[OI-t40]`의 isvp_t31.h는 isvp_common.h를 include하지 않으므로(그 트리에서는 isvp_t40.h만 include) 벤더 값 그대로다. 실기기 출력으로 확인된 SDK 프롬프트는 `hisilicon # `뿐이다(`[OIW] install-hisi.md`, `help-uboot.md`, cybergibbons 글). 나머지 SDK 프롬프트는 설정 소스 기준이다.

### 1.1 프롬프트와 autoboot (벤더 SDK 기본값)

| 계열 (빌드) | 프롬프트 (`CONFIG_SYS_PROMPT`) | autoboot 표시 | 중단 입력 (U-Boot 설정) | 출처 |
|---|---|---|---|---|
| HiSilicon V1~V3 SDK (2010.06) | `hisilicon # ` | `Hit any key to stop autoboot: %2d ` (bootdelay 1) | 아무 키. 설정 주석 `/*use ^c to interrupt*/`, `CONFIG_ZERO_BOOTDELAY_CHECK` 켜짐 | `[OI-hi3516cv200]` include/configs/hi3518ev200.h:144,160,209 |
| HiSilicon V4 SDK (2016.11) | `hisilicon # ` | `Hit any key to stop autoboot: %2d ` (**bootdelay 2**, `CONFIG_BOOTDELAY=2`) | 아무 키 (`# CONFIG_AUTOBOOT_KEYED is not set`). `*_mini_defconfig`(최소 빌드)는 `# CONFIG_AUTOBOOT is not set`이라 카운트다운 없이 바로 프롬프트(`include/autoboot.h`의 빈 스텁) | `[OI-hi3516ev200]` configs/hi3516ev300_defconfig:227,257,262-263, configs/hi3518ev300_defconfig:227,263, configs/hi3516ev200_mini_defconfig |
| Goke SDK (2016.11) | `goke # ` (실기기 출력은 미확인) | `Hit any key to stop autoboot: %2d ` (bootdelay 2) | 아무 키. `*_mini_defconfig`는 autoboot·hush·echo 모두 꺼짐 | `[OI-gk7205v200]` configs/gk7205v200_emmc_defconfig:219,257,262-263, gk7202v300_mini_defconfig:233-240,314 (OpenIPC가 프롬프트를 바꾸지 않은 defconfig) |
| Ingenic T31 SDK (2013.07) | `isvp_t31# ` (`CONFIG_SYS_BOARD "# "`, 보드명 `isvp_t31`) | 위와 같음 (bootdelay 1) | 아무 키 | `[OI-t40]` include/configs/isvp_t31.h:348,547; `[OI-ingenic]` boards.cfg:586-590, mkconfig:166 |
| Ingenic T20/T21/T23/T30 SDK | `isvp_t20# `, `isvp_t21# `, `isvp_t23# `, `isvp_t30# ` (같은 규칙) | 위와 같음 | 아무 키 | `[OI-ingenic]` boards.cfg, include/configs/isvp_t20.h:298, isvp_t21.h:386 |
| SigmaStar Infinity5/6/6E/6C SDK (2015.01) | `SigmaStar # ` | **없음** (keyed 모드, `CONFIG_AUTOBOOT_PROMPT` 미정의) | `CONFIG_AUTOBOOT_DELAY_STR "\x0d"` = **CR**. `CONFIG_BOOTDELAY 0` + `CONFIG_ZERO_BOOTDELAY_CHECK` | `[OI-sigmastar]` include/configs/infinity6e.h:29-30,64-65,86 |
| MStar Infinity3 (MSC313E) SDK (2015.01) | `MStar # ` | 없음 (keyed) | CR, bootdelay 0 | `[OI-msc313e]` include/configs/infinity.h:63, infinity3.h:13-14,42-43 |
| Novatek NA51055 SDK (2019.04) | `nvt@na51055: ` (nor/nand defconfig), `=> ` (기본 defconfig) | 표준 메시지 | 아무 키, bootdelay 0 | `[OI-nt9856x]` configs/nvt-na51055_nor_defconfig:322, nvt-na51055_defconfig:324, nvt-na51055_nand_defconfig:250,329 |
| Grain Media GM8139/GM8210/GM8287 SDK (2013.01) | `GM # ` (GM8126은 `A320 # `) | 표준 메시지 (bootdelay 3) | 아무 키 | `[OI-grainmedia]` include/configs/gm8139.h:54,379, gm8126.h:51,273 |
| XMedia XM72xx SDK (2020.01) | `xmedia # ` | 표준 메시지 (bootdelay 2) | 아무 키 | `[OI-xmedia]` configs/xm72020300_defconfig:240,330,336-337 |
| Rockchip (`next-dev`, U-Boot 2017.09 베이스) | `=> ` (Kconfig 기본) | `Hit key to stop autoboot('CTRL+C'): %2d ` | **Ctrl-C만** 인식(0x03 외 바이트는 `ctrlc()`가 읽고 버림). 메시지 시점에 0x03이 이미 버퍼에 있으면 `ctrlc()`가 그것을 소비한 뒤 `(void) getc()`가 **다음 바이트를 하나 더 기다린다** | `[RK]` common/autoboot.c:219-247 (사전 확인 222-231); Makefile `VERSION = 2017`, `PATCHLEVEL = 09` |
| OpenIPC 빌드 (HiSilicon V4·Goke, 2016.11) | `OpenIPC # ` | `Press Ctrl-c to stop autoboot... %d \n` (keyed) | `CONFIG_AUTOBOOT_STOP_STR "\x3"` (Ctrl-C) | `[OI-hi3516ev200]` include/configs/hi-common.h:51-57; `[OI-gk7205v200]` include/configs/gk-common.h:58-64 |
| OpenIPC 빌드 (HiSilicon V1~V3, 2010.06) | `OpenIPC # ` | **비-keyed** 표준 `Hit any key to stop autoboot: %2d ` (bootdelay 1). keyed 설정이 없다 | 아무 키 | `[OI-hi3516cv200]` include/configs/hi-common.h:40-52 (hush 파서 정의, PS2 ` > `) |
| OpenIPC 빌드 (Ingenic T10~T31, `u-boot-ingenic`) | `OpenIPC # ` | `\nPress ENTER to interrupt boot in %d...\n` (keyed) | `CONFIG_AUTOBOOT_STOP_STR "\x0D"` (CR) | `[OI-ingenic]` include/configs/isvp_common.h:75-77,90 |
| OpenIPC 빌드 (Ingenic T40, `u-boot-t40`) | `OpenIPC # ` | `Press Ctrl-c to abort autoboot... %d \n` (keyed, **stop이 아니라 abort**) | `CONFIG_AUTOBOOT_STOP_STR "\x3"` (Ctrl-C) | `[OI-t40]` include/configs/isvp_common.h:81-87 (isvp_t40.h만 include) |
| OpenIPC 빌드 (SigmaStar) | `OpenIPC # ` | SDK와 같음(keyed, 메시지 없음, bootdelay 0) | CR (SDK 설정 유지) | `[OI-sigmastar]` include/configs/sstar-common.h:3-8 (프롬프트·hush), 24-29 (NOR env `0x40000`/`0x10000`) |
| OpenIPC 빌드 (XMedia) | `OpenIPC # ` | SDK와 같음(표준 메시지) | 아무 키 | `[OI-xmedia]` include/configs/xm-common.h:12-15 |
| Fullhan | (미확인) | (미확인) | (미확인) | 1차 출처 없음 |
| Anyka | (미확인) | (미확인) | (미확인) | 커널 콘솔은 `ttySAK0`,115200 (BPI-D1 포럼 로그, 2차 출처) |
| Ambarella (AMBoot) | `amboot>` | (미확인) — 배너는 `Amboot(R) Ambarella(R) Copyright (C) 2004-2007` | Dropcam(Ambarella A5s) 사례: 전원 투입 직후 줄바꿈을 연속 송신해 진입(2차 출처) | Include Security 블로그(Dropcam 분석) |

**자동화 메모**: autoboot 중단 처리 순서는 [§8.6](#86-자동화-지침)에 있다. 여기서 중요한 점은 두 가지다. (1) 표준(비-keyed) 빌드는 **어떤 바이트든** 중단으로 받아들인다. (2) keyed 빌드는 지정 문자열만 받아들이고, SigmaStar SDK처럼 `bootdelay 0`인 빌드는 메시지 없이 입력 버퍼를 **두 번**만 확인하고 지나간다(`[OI-sigmastar]` common/autoboot.c `abortboot_keyed`: `etime = bootdelay ? endtick(bootdelay) : 2;`).

### 1.2 플래시 probe 출력, env 위치, mtd-id, 콘솔

| 계열 | U-Boot 플래시 probe 출력 (포맷) | env offset / size | 커널 mtd-id | 콘솔 | 출처 |
|---|---|---|---|---|---|
| HiSilicon V1 SFC v350 (Hi3518A/C/E(V100), Hi3516C(V100), Hi3516A, Hi3520D, Hi3535/Hi3536 등 `CONFIG_SPI_FLASH_HISFC350` 보드) | `Check spi flash controller v350... ` + `Found`<br>`Spi(cs%d) ID: 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X`<br>`Spi(cs%d): Block:%sB Chip:%sB Name:"%s"` (크기는 `ultohstr()`: `64K`, `16M`) | `0x80000` / `0x40000` (SDK 기본) | `hi_sfc` (U-Boot `sf probe` 이름도 `hi_sfc`) | `ttyAMA0`,115200 | `[OI-hi3516cv200]` drivers/mtd/spi/hisfc350/hisfc350.c:954-1017,1170,1206-1212; include/configs/hi3518e.h:66,117-123 |
| HiSilicon V2/V3 FMC v100 (Hi3516CV200, Hi3518EV200/EV201, Hi3516CV300, Hi3519V101 — `CONFIG_HIFMC` 보드) | `Check Flash Memory Controller v100 ...` + ` Found`<br>`SPI Nor(cs %d) ID: %#x %#x %#x` (ID 길이가 3보다 길면 ` %#x`가 더 붙음)<br>`Block:%sB Chip:%sB Name:"%s"`<br>`SPI Nor total size: %uMB` | `0x80000` / `0x40000` (SDK 기본) | `hi_sfc` (U-Boot `sf probe` 이름은 `hi_fmc`) | `ttyAMA0` | `[OI-hi3516cv200]` include/configs/hi3518ev200.h:61-75,129-135,145, drivers/mtd/hifmc_common.c:41-48, drivers/mtd/spi/hifmc100/hifmc_spi_nor_ids.c:2739-2797, hifmc100.c:713, hifmc100_os.c:224; 실기기 로그 `[BL-foscam]`(Hi3518EV200에서 FMC v100 출력) |
| HiSilicon V4 / Goke (2016.11) | (SDK 고유 출력) + `sf read` 결과는 빈 줄 뒤 `SF: %zu bytes @ %#x Read: OK` | `0x80000` / `0x40000`, 섹터 `0x10000` (SDK 기본) | `hi_sfc` (HiSilicon), `sfc` (Goke) — OpenIPC bootargs 기준 | `ttyAMA0` | `[OI-hi3516ev200]` include/configs/hi3516ev200.h:192-195, cmd/sf.c:355-375; `[OIW] install-hisi.md`, `install-goke.md` |
| Ingenic T31 (2013.07) | `SF: Detected %s` (`[OI-ingenic]` 트리)<br>`SF: Detected %s, manufacturer id: %02x` + 빈 줄 (`[OI-t40]` 트리) | `0x3C000` / `0x4000` (유도: `CONFIG_SYS_MONITOR_LEN` 214K + `CONFIG_SPL_MAX_SIZE` 26K) | `jz_sfc` | `ttyS1`,115200n8 | `[OI-ingenic]` drivers/mtd/spi/spi_flash.c:610; `[OI-t40]` drivers/mtd/spi/spi_flash.c:611-622, include/configs/isvp_t31.h:319-340,552-579,617-619 |
| SigmaStar Infinity6 (2015.01) | `SF: %zu bytes @ %#x %s: %s` + ` (cost %ld ms)` (read) | `0x1000` @ `0x4F000` (Infinity6). Infinity6E는 빌드 옵션에 따라 다름(`CONFIG_MS_NOR_ONEBIN`+`CONFIG_MS_PARTITION` 또는 `CONFIG_MSTAR_ENV_OFFSET`이면 런타임 값 `ms_nor_env_offset`, 둘 다 아니면 `0x5F000`) | `NOR_FLASH` | `ttyS0` | `[OI-sigmastar]` include/configs/infinity6.h:160-165, infinity6e.h:165-182, common/cmd_sf.c:522-528; `[OIW] install-sigmastar.md` |
| Xiongmai XM510/XM530 | (미확인) | (미확인) | `xm_sfc` | `ttyAMA0` | `[OIW] install-xm510.md`, `install-xm530.md` |
| OpenIPC 빌드 (HiSilicon/Goke/Ingenic/SigmaStar NOR, XMedia) | — | `0x40000` / `0x10000` (HiSilicon/Goke의 `CONFIG_XM_COMPATIBLE` 빌드는 offset `0x30000`. XMedia는 offset만 `0x40000`으로 재정의하고 size는 defconfig의 `0x10000`) | 위 계열별 mtd-id | 위와 같음 | `[OI-ingenic]` include/configs/isvp_common.h:70-72; `[OI-hi3516ev200]` include/configs/hi-common.h:41-47; `[OI-hi3516cv200]` hi-common.h:33-38; `[OI-gk7205v200]` gk-common.h:39-44; `[OI-sigmastar]` sstar-common.h:24-29; `[OI-xmedia]` xm-common.h:33-34, configs/xm72020300_defconfig:162 |

OpenIPC 표준 파티션 맵(8 MB): `mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(rootfs_data)`. 16 MB 맵(`mtdpartsnor16m`)은 `256k(boot),64k(env),3072k(kernel),10240k(rootfs),-(rootfs_data)`로, 커널 파티션을 3072k로 늘려 rootfs 위치를 `0x250000`에서 `0x350000`으로 옮기고 크기를 `10240k`로 늘린다. 커널 시작은 두 맵 모두 `0x50000`이다(`[OIW] help-uboot.md` "Setting the partition layout after a full image"; `[OI-hi3516ev200]` hi-common.h `mtdpartsnor16m`).

---

## 2. 콘솔 입출력 공통 동작 (readline과 명령 파서)

### 2.1 줄끝과 에코

- **출력**: 모든 시리얼 드라이버가 `\n` 앞에 `\r`을 넣는다. 그래서 U-Boot 출력의 줄끝은 항상 `\r\n`이다.
  ```c
  /* [UB-2010.06] drivers/serial/serial_pl01x.c:159-164 (HiSilicon UART = PL011) */
  void serial_putc (const char c)
  {
  	if (c == '\n')
  		pl01x_putc (CONSOLE_PORT, '\r');
  	pl01x_putc (CONSOLE_PORT, c);
  }
  /* [UB-master] drivers/serial/serial-uclass.c:256-262 (DM serial)  */
  	if (ch == '\n')
  		_serial_putc(dev, '\r');
  ```
- **입력 Enter**: `\r`과 `\n`이 **각각** 줄을 끝낸다.
  ```c
  /* 편집 없는 readline: [UB-2013.07] common/main.c:1079-1083, [UB-master] common/cli_readline.c:572-573 */
  		case '\r':			/* Enter		*/
  		case '\n':
  			*p = '\0';
  			puts ("\r\n");
  			return p - p_buf;
  /* 편집 readline(CONFIG_CMDLINE_EDITING): [UB-2013.07] common/main.c:800-802 */
  		if ((ichar == '\n') || (ichar == '\r')) {
  			putc('\n');
  			break;
  		}
  ```
  최신 코드는 `\r`을 `\n`으로 바꾼 뒤 같은 처리를 한다(`[UB-master]` common/cli_getch.c:170, common/cli_readline.c:279-281). 결론: **`\r\n`을 보내면 빈 줄이 하나 더 들어간다**(→ §2.3 반복 실행).
- **에코**: 입력한 문자는 그대로 되돌아온다. Enter 에코의 바이트는 readline 종류에 따라 다르다. 편집 readline(`CONFIG_CMDLINE_EDITING`; HiSilicon V1/V2, Ingenic T31, SigmaStar Infinity6E, XMedia 등)은 `putc('\n')`이므로 `\r\n`이다. 편집 없는 readline(예: Novatek NA51055 nor/nand defconfig `# CONFIG_CMDLINE_EDITING is not set`)은 `puts("\r\n")`의 `\n` 앞에 시리얼 드라이버가 `\r`을 하나 더 넣으므로 **`\r\r\n`**이다(Novatek 확인: `[OI-nt9856x]` common/cli_readline.c:584-588, NS16550 비-DM 드라이버 drivers/serial/serial_ns16550.c:134-135·141-145, include/configs/novatek/na51055_ca9.h:71 `CONFIG_SYS_NS16550_SERIAL`). 따라서 `printenv\r`을 보내면 `printenv` + `\r\n`(또는 `\r\r\n`) + 출력 + 프롬프트를 받는다. 편집 readline은 커서 이동용 이스케이프·백스페이스 문자를 에코에 섞을 수 있다.
- NUL(0x00)은 편집 없는 readline에서 무시된다(`case '\0': continue;`).

### 2.2 프롬프트 출력 방식

프롬프트는 `CONFIG_SYS_PROMPT` 문자열 그대로이며 **줄바꿈 없이** 출력된다. 대부분 끝에 공백이 있다(`hisilicon # `, `=> `, `isvp_t31# `). 매칭은 "수신 버퍼가 프롬프트로 끝나는가"로 하고, 프롬프트 앞은 `\n`(또는 버퍼 시작)이어야 한다는 조건을 붙인다. `printenv` 값이나 `md` ASCII 칼럼에 `# `가 들어갈 수 있으므로 `#`만으로 판정하지 않는다.

### 2.3 빈 줄 = 직전 명령 반복

**simple 파서** (`[UB-master]` common/cli_simple.c:268-315, 구버전 common/main.c `main_loop`도 같은 구조):

```c
		len = cli_readline(CONFIG_SYS_PROMPT);

		flag = 0;	/* assume no special flags for now */
		if (len > 0)
			strlcpy(lastcommand, console_buffer,
				CONFIG_SYS_CBSIZE + 1);
		else if (len == 0)
			flag |= CMD_FLAG_REPEAT;
		...
		if (len == -1)
			puts("<INTERRUPT>\n");
		else
			rc = run_command_repeatable(lastcommand, flag);

		if (rc <= 0) {
			/* invalid command or not repeatable, forget it */
			lastcommand[0] = 0;
		}
```

- 빈 줄(`len == 0`)이면 `lastcommand`를 `CMD_FLAG_REPEAT`와 함께 다시 실행한다.
- 실행 결과가 "반복 불가"이거나 실패면 `lastcommand`를 지운다. Ctrl-C로 중단된 명령도 반복 불가로 취급된다: `return -1;	/* if stopped then not repeatable */` (`[UB-2013.07]` common/main.c:1336-1338,1430).
- **Ctrl-C(`len == -1`) 경로는 `rc`를 바꾸지 않으므로 `lastcommand`가 남는다.** Ctrl-C를 친 뒤에 맨 Enter를 보내도 직전 반복 가능 명령이 실행된다.

**hush 파서** (`[UB-2013.07]` common/hush.c:1016-1056): 빈 줄이면 `do_repeat = 1`로 직전 명령(`the_command`)을 다시 실행한다. 반복 가능 여부는 `cmd_process(..., &flag_repeat, ...)`가 `*repeatable &= cmdtp->repeatable;`로 판정한다(hush.c:1668, common/command.c:551). readline이 Ctrl-C로 끝나면 `flag_repeat = 0`이 되어 반복 상태가 지워진다(hush.c:1032-1039).

공식 문서도 이 동작을 명시한다: "The empty commands cause a 'repeat', so that md shows the next available data in the same format as before." (`[UB-master]` doc/usage/cmd/md.rst)

### 2.4 반복 가능 명령 목록

`U_BOOT_CMD(name, maxargs, rep, ...)`의 세 번째 인자 `rep`이다. 아래 명령은 `[UB-2010.06]`, `[UB-2013.07]`, `[UB-master]` 중 그 명령이 존재하는 버전에서 값이 같다(소스에서 직접 추출). 2010.06에 없는 명령은 표시했다.

| rep | 명령 |
|---|---|
| **1 (반복 가능)** | `md`, `mm`, `nm`, `mw`, `cp`, `cmp`, `crc32`, `base`, `loop`, `mtest`, `mdc`, `mwc`, **`sf`**, `nand`, `mmc`, `bootm`, `boot`, `bootd`, `go`, **`run`**, `printenv`, `env`(2010.06에 없음), `echo`, `help`, `version`, `bdinfo`, `coninfo`, `tftpboot`(메인라인의 lwIP 스택 구현 `cmd/lwip/tftp.c`만 0), `tftpput`(2013.07~), `dhcp`, `bootp`, `ping`, `usb`, `fatls`, `ext4write`(2010.06에 없음), `hash`(2013.07~), `md5sum`, `sha1sum`, `sleep`, `iminfo`, `ubi`, `flinfo` |
| 0 (반복 불가) | `setenv`, `saveenv`, `reset`, `erase`, `protect`, `fatload`, `fatwrite`(2010.06에 없음), `loadb`, `loady`, `source`, `mtdparts`, `mmcinfo`, `fsload` |

하위 명령별 차이:

- **`sf`**: 디스패처에 반복 차단 코드가 없다. `probe/read/write/erase/update` 모두 반복된다(`[UB-master]` cmd/sf.c:587-623, U_BOOT_CMD:649-651; 구버전도 같음).
- **`nand`**: 2013.01 이후(확인: Grain Media 2013.01, 2013.07, Ingenic, SigmaStar, HiSilicon V4, 메인라인)는 `dump`만 반복된다. 나머지는 반복 시 아무 일도 하지 않고 돌아온다.
  ```c
  	/* Only "dump" is repeatable. */
  	if (repeat && strcmp(cmd, "dump"))
  		return 0;
  ```
  (`[UB-master]` cmd/nand.c:562-564, `[UB-2013.07]` common/cmd_nand.c:478-480) **2010.06(HiSilicon V1~V3 포크 포함)에는 이 검사가 없다**(`[UB-2010.06]` common/cmd_nand.c `do_nand`, `[OI-hi3516cv200]` common/cmd_nand.c). 그래서 `nand erase`/`nand write`도 빈 줄로 다시 실행된다.
- **`mmc`**: 2016.11 이후(HiSilicon V4/Goke 포함)는 하위 명령마다 `rep`이 있다. `read`=1, `rescan`=1, `part`=1, `list`=1, `write`=0, `erase`=0, `info`=0, `dev`=0 (`[UB-2016.11]` cmd/mmc.c:733-747, 검사 240·766행; `[UB-master]` cmd/mmc.c:1243-1275, 검사는 317·1292행 `cmd_is_repeatable()`). **2010.06과 2013.07(Ingenic 포함)에는 하위 명령 검사가 없다**(`mmc` 전체가 rep=1). 그래서 `mmc write`/`mmc erase`도 빈 줄로 다시 실행된다(`[UB-2010.06]`·`[UB-2013.07]` common/cmd_mmc.c에 `CMD_FLAG_REPEAT` 처리 없음).

### 2.5 `ctrlc()`는 입력 바이트를 소비한다

```c
/* [UB-2013.07] common/console.c, [UB-master] common/console.c:901 (getc → getchar) */
int ctrlc(void)
{
	if (!ctrlc_disabled && gd->have_console) {
		if (tstc()) {
			switch (getc()) {
			case 0x03:		/* ^C - Control C */
				ctrlc_was_pressed = 1;
				return 1;
			default:
				break;
			}
		}
	}
	return 0;
}
```

- `ctrlc()`를 폴링하는 명령이 실행되는 동안 들어온 **0x03 이외의 바이트는 버려진다**. `md`(`print_buffer`가 줄마다 호출), 2010.06의 `printenv`(변수마다 호출), 네트워크 전송(`NetLoop`, 중단 시 `\nAbort\n` 출력: `[UB-2013.07]` net/net.c:485)이 여기에 해당한다.
- 그래서 `md.b ...\r\n`처럼 보내면 뒤의 `\n`이 `md` 출력 도중 **먹혀서** 반복이 일어나지 않을 수도 있다. 반면 `ctrlc()`를 부르지 않는 `setenv`, `sf erase` 뒤의 `\n`은 그대로 남아 반복 실행을 일으킨다(카메라 포크 2010.06~2020.01 기준. 최신 메인라인의 `spi-nor-core`는 erase 루프에서 `ctrlc()`를 폴링한다: `[UB-master]` drivers/mtd/spi/spi-nor-core.c:1132). 타이밍 의존적이므로 R1을 지켜야 한다.
- mock-device는 이 동작(실행 중 0x03 외 입력 폐기)을 재현해야 한다.

### 2.6 readline 편집 키

| 입력 | 동작 | 출처 |
|---|---|---|
| `0x03` (Ctrl-C) | 입력 버림, readline이 -1 반환 → `<INTERRUPT>` (§10) | `[UB-2013.07]` common/main.c:866-868, 1088-1090 |
| `0x15` (Ctrl-U) | 줄 지우기 | `[UB-2013.07]` common/main.c:905-906, 1092-1098 |
| `0x08`, `0x7F` | 한 글자 지우기 | readline |
| `0x09` (Tab) | `CONFIG_AUTO_COMPLETE` 빌드에서 자동완성(HiSilicon V2/V3 SDK는 켜짐: hi3518ev200.h:218) | |
| ESC 시퀀스 | 편집 readline에서 커서/이력 | |

### 2.7 버퍼·인자 한계와 오류 메시지

| 항목 | 값/문자열 | 출처 |
|---|---|---|
| `CONFIG_SYS_CBSIZE` | HiSilicon V2 1024, Ingenic T31 1024, SigmaStar I6E 512, GM8136·GM8139 1024, **GM8126·GM8210·GM8287 256**, OpenIPC Ingenic 2048, OpenIPC SigmaStar/XMedia 1024 | hi3518ev200.h:210, isvp_t31.h:548, infinity6e.h:87, gm8136.h:378, gm8139.h:380, gm8126.h:274, gm8210.h:612, gm8287.h:336, `[OI-ingenic]` isvp_common.h:92, sstar-common.h, xm-common.h |
| 버퍼가 차면 | 편집 없는 readline은 `n >= CONFIG_SYS_CBSIZE - 2`이면 `putc('\a')`로 BEL을 내고 문자를 버림(한 줄 최대 CBSIZE−2 문자) | `[UB-2013.07]` common/main.c:1117,1143-1144, `[UB-master]` common/cli_readline.c:606-608 |
| `CONFIG_SYS_MAXARGS` | HiSilicon V2 32, Ingenic T31 64, SigmaStar I6E 64, GM8136 16, OpenIPC HiSilicon V4/Goke/Ingenic 64 | hi3518ev200.h:169, isvp_t31.h:545, infinity6e.h:91, gm8136.h:385, hi-common.h:61, isvp_common.h:83 |
| 인자 초과 | `** Too many args (max. %d) **` | `[UB-2010.06]` common/main.c:1159, `[UB-master]` common/cli_simple.c:168 |
| 없는 명령 | `Unknown command '%s' - try 'help'`. hush는 단어에 `;`가 들어 있으면(예: 변수 확장 결과) `Unknown command '%s' - try 'help' or use 'run' command`를 낸다(2010.06·2013.07·메인라인 모두). 참고: `help <없는 명령>`은 `Unknown command '%s' - try 'help' without arguments for list of all known commands`로 다른 문자열이다 | 프롬프트 디스패치: `[UB-2010.06]` common/main.c:1378, common/hush.c:1679; `[UB-2013.07]` common/command.c:524; `[UB-master]` common/command.c:615. hush `;` 변형: `[UB-2010.06]` hush.c:1671, `[UB-2013.07]` hush.c:1662, `[UB-master]` cli_hush.c:1667. `help` 변형: `[UB-2010.06]` common/command.c:90 |

OpenIPC 위키의 실제 예(HiSilicon 프롬프트, 인자 16개 제한 빌드):

```
hisilicon # setenv uk 'mw.b ${baseaddr} 0xff ${flashsize}; tftp ${baseaddr} uImage.${soc}; sf probe 0; sf erase 0x50000 0x200000; sf write ${baseaddr} 0x50000 ${filesize}'
** Too many args (max. 16) **
```
(`[OIW] help-uboot.md` Troubleshooting)

### 2.8 simple 파서와 hush 파서, 마커

| 항목 | simple 파서 | hush 파서 (`CONFIG_SYS_HUSH_PARSER` / `CONFIG_HUSH_PARSER`) |
|---|---|---|
| 여러 명령 | `;`로 구분 | `;`, `&&`, `\|\|`, `if/then/fi`, `for` 등 |
| 변수 치환 | `${name}` | `$name`, `${name}` (로컬 변수와 env 변수 공간이 분리됨) |
| 특수문자 보호 | `\;`, `\$` 또는 작은따옴표 `'...'` | 따옴표 |
| 실패 처리 | `;` 체인의 앞 명령이 실패해도 나머지는 실행됨. `run a b`는 실패하면 거기서 멈춤 | 같음 |
| 보조 프롬프트 | 없음 | 따옴표/구문 미완성 시 `CONFIG_SYS_PROMPT_HUSH_PS2` (기본 `> `) |

출처: `[UB-2013.07]` README:2414-2450, 4694-4730; `[UB-master]` cmd/Kconfig:94-98.

카메라 빌드별 파서(설정 파일 기준):

| 빌드 | 파서 | 출처 |
|---|---|---|
| HiSilicon V1~V3 SDK (2010.06) | simple (`HUSH_PARSER` 정의 없음) | `[OI-hi3516cv200]` include/configs/hi3518ev200.h (hi-common.h include 이전 부분) |
| OpenIPC HiSilicon V1~V3 (2010.06) | **hush**, PS2 ` > ` | `[OI-hi3516cv200]` include/configs/hi-common.h:45-46 |
| HiSilicon V4 SDK (Hi3516EV300 defconfig) | hush | `[OI-hi3516ev200]` configs/hi3516ev300_defconfig:256 |
| HiSilicon V4/Goke `*_mini_defconfig`, hi3556v200·hi3559v200 등 일부 defconfig | simple (`# CONFIG_HUSH_PARSER is not set`) | `[OI-hi3516ev200]`·`[OI-gk7205v200]` configs/ |
| Ingenic T31 SDK | simple (정의 없음) | `[OI-t40]` include/configs/isvp_t31.h |
| OpenIPC Ingenic | hush | `[OI-ingenic]` include/configs/isvp_common.h:88 |
| OpenIPC SigmaStar | hush | `[OI-sigmastar]` include/configs/sstar-common.h:8 |
| Novatek NA51055 nor defconfig | hush, 편집 readline 꺼짐 | `[OI-nt9856x]` configs/nvt-na51055_nor_defconfig:318-319 |

**마커 기법 (R6)**: 명령 완료를 "프롬프트 재출현"보다 확실하게 잡으려면 명령 뒤에 고유 문자열을 출력하는 명령을 붙인다.

```text
보내기:  sf probe 0; echo __pweh_7f3a\r
기다리기: 정규식 (?m)^__pweh_7f3a\r?$

echo가 없는 빌드(예: HiSilicon V1~V3 SDK 설정에는 CONFIG_CMD_ECHO가 없음):
보내기:  sf probe 0; printenv __pweh_7f3a\r
기다리기: 정규식 (?m)^## Error: "__pweh_7f3a" not defined\r?$
```

- `echo`는 `[UB-2010.06]` include/config_cmd_default.h:22 기본 세트에 있지만, HiSilicon SDK 설정은 이 파일을 포함하지 않고 명령을 개별 정의하며 `CONFIG_CMD_ECHO`가 없다(`[OI-hi3516cv200]` common/Makefile:100 `COBJS-$(CONFIG_CMD_ECHO) += cmd_echo.o`). Ingenic T31(isvp_t31.h:492)과 HiSilicon V4·Goke의 일반 defconfig(`CONFIG_CMD_ECHO=y`, 예: hi3516ev300_defconfig:339)에는 있다. 반면 HiSilicon V4/Goke `*_mini_defconfig`, hi3556v200·hi3559v200·hi3519av100_amp·hi3556av100 defconfig, XMedia `xm72020300_defconfig:472`에는 `# CONFIG_CMD_ECHO is not set`이다. 그래서 R6대로 세션 시작 시 한 번 확인한다.
- `printenv <없는 이름>`은 모든 버전에서 `## Error: "%s" not defined\n`을 출력한다(`[UB-2010.06]` common/cmd_nvedit.c:161, `[UB-master]` cmd/nvedit.c:122).
- 반복 주의: 마커를 붙인 줄 전체가 `lastcommand`가 된다. 맨 Enter를 보내면 줄 전체가 반복된다.

---

## 3. `md` / `md.b` / `md.w` / `md.l` / `md.q`

### 3.1 문법과 인자 해석

```
md[.b, .w, .l, .q] address [# of objects]
```
(`[UB-master]` cmd/mem.c:1315-1318. `.q`는 64비트 데이터 지원 빌드만.)

`do_mem_md` 핵심부(`[UB-master]` cmd/mem.c:66-115, `[UB-2010.06]` common/cmd_mem.c:63~ 동일 구조):

```c
	addr = dp_last_addr;
	size = dp_last_size;
	length = dp_last_length;
	...
	if ((flag & CMD_FLAG_REPEAT) == 0) {
		/* New command specified.  Check for a size specification.
		 * Defaults to long if no or incorrect specification.
		 */
		if ((size = cmd_get_data_size(argv[0], 4)) < 0)
			return 1;
		addr = hextoul(argv[1], NULL);      /* 2010.06: simple_strtoul(argv[1], NULL, 16) */
		addr += base_address;
		/* If another parameter, it is the length to display.
		 * Length is the number of objects, not number of bytes.
		 */
		if (argc > 2)
			length = hextoul(argv[2], NULL);
	}
	bytes = size * length;
	...
	print_buffer(addr, buf, size, length, DISP_LINE_LEN / size);
	addr += bytes;
	...
	dp_last_addr = addr;
	dp_last_length = length;
	dp_last_size = size;
```

| 규칙 | 내용 |
|---|---|
| 주소·길이의 진법 | **항상 16진수**. `0x` 접두사는 있어도 없어도 된다. `md.b 0 100` = 0x100 = 256바이트. 10진수 입력 방법은 없다. |
| 길이 단위 | **객체 개수**(`.b`=1, `.w`=2, `.l`=4, `.q`=8바이트). `md.l X 10` = 16워드 = 64바이트. |
| 크기 접미사 | `.b/.w/.l/.q`(`.s`는 문자열 검색용). 새 명령에서 접미사가 없으면 `.l`(4) (`cmd_get_data_size(argv[0], 4)`, `[UB-master]` common/command.c:473-496) |
| 길이 기본값 | 첫 사용 시 `dp_last_length = 0x40`(64개) → `.b`면 4줄, `.l`이면 16줄 (`[UB-master]` cmd/mem.c:50, `[UB-2010.06]` common/cmd_mem.c:52) |
| **길이는 sticky** | 길이를 생략하면 **직전 `md`의 길이**가 쓰인다(크기 접미사가 달라도). `md.l 0 10` 다음 `md.b 0`은 0x10**바이트**를 보여준다. |
| 크기는 sticky 아님 | 새 명령은 접미사가 없으면 `.l`로 돌아간다. 공식 문서의 "The specified data_size and length become the defaults for future memory commands." 문장은 크기에 대해서는 코드와 다르다. 코드를 따른다. |
| 반복(빈 줄) | 인자를 다시 읽지 않고 `dp_last_addr`(= 이전 끝 주소)부터 같은 크기·길이로 이어서 출력한다. |
| 한 줄 바이트 수 | `DISP_LINE_LEN 16` → 항상 16바이트/줄 (`[UB-master]` cmd/mem.c:65) |
| Ctrl-C | `print_buffer`가 줄마다 `ctrlc()`를 확인하고 중단한다. 반환값은 무시되며, **`dp_last_addr`는 요청한 끝 주소로 갱신된다**(멈춘 곳이 아님). 다만 Ctrl-C로 중단된 명령은 반복 불가로 처리되므로(simple 파서: `had_ctrlc()` → `return -1` → `lastcommand` 삭제, `[UB-2010.06]` common/main.c:1414-1415, `[UB-master]` common/cli_simple.c:261-262; hush: `if (had_ctrlc()) flag_repeat = 0;`) 빈 줄로 이어서 출력할 수는 없다. 이어 받으려면 멈춘 줄의 주소를 다시 지정한다. 중단 시 별도 메시지는 없다. |

### 3.2 출력 포맷 (`print_buffer`) — 버전별 차이

| 버전 | 주소 | 값 필드 | 마지막 짧은 줄 패딩 | ASCII 칼럼 앞 구분자 | 출처 |
|---|---|---|---|---|---|
| 2010.06 (~2013.01) | `"%08lx:"` | `" %02x"` / `" %04x"` / `" %08x"` | **없음** | `"    "` (공백 4) | `[UB-2010.06]` lib/display_options.c:102-145 |
| 2013.04 ~ 2021.07 | `"%08lx:"` | `" %0*x"`(폭 = width×2), 64비트는 `" %0*llx"` | **있음** (빈 칸을 공백으로 채워 ASCII 칼럼 정렬) | `"    %s\n"` (공백 4) | `[UB-2013.07]` lib/display_options.c:101~; 패딩 도입 커밋 efd7c11404e5 (2013-03-11 머지, **v2013.04에 포함**: GitHub compare `efd7c11404e5...v2013.04` = ahead) |
| 2021.10 이후 | `"%08lx:"` | `" %0*lx"` | 있음 | `"  %s"` (**공백 2**) | `[UB-master]` lib/display_options.c:151-213; 커밋 c7b16d830e72 "display_options: Drop two spaces before the ASCII column" (v2021.07에는 없고 v2021.10에는 있음) |
| `USE_TINY_PRINTF`/SPL 빌드 | | `" %x"` (**0 채움 없음**) | | | `[UB-master]` lib/display_options.c:194-195 |

- ASCII 칼럼: `isprint()`이고 `< 0x80`인 바이트만 그대로, 나머지는 `.`. 0x20(공백)은 그대로 공백이다.
- 줄끝은 `\n` → 시리얼에서 `\r\n`.
- 확인한 벤더 포크는 모두 **공백 4** 구분자다. HiSilicon 2010.06 포크와 Grain Media 2013.01 포크는 **짧은 줄 패딩이 없다**. Ingenic(2013.07)·HiSilicon V4(2016.11)·SigmaStar(2015.01)·Novatek(2019.04)·XMedia(2020.01) 포크는 패딩이 있다(각 포크 lib/display_options.c 직접 확인).

### 3.3 실제 출력 예

메인라인 단위 테스트(2021.10 이후 포맷, 공백 2 + 패딩). 테스트 소스의 `\"`를 풀어 적었다:

```
00000000: 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff  .."3DUfw........
00000010: 10 00                                            ..
```
(`[UB-master]` test/common/print.c:178-180)

메인라인 공식 문서 예(공백 4, 문서가 코드 변경 전 형식을 유지하고 있음):

```
=> md.b 10000
00010000: 00 00 01 00 00 00 00 00 00 0f f3 f0 96 55 00 00    .............U..
00010010: 10 10 01 10 00 00 00 00 10 10 01 10 00 00 00 00    ................
```
(`[UB-master]` doc/usage/cmd/md.rst)

HiSilicon 2010.06 실기기(OpenIPC 위키). 짧은 줄인데 패딩 없이 공백 4 뒤에 ASCII가 바로 붙는다:

```
hisilicon # md.l 0x20111050 1
20111050: 00000016    ....
```
(`[OIW] install-hisi.md` "Hi3518EV200: check whether your board is DDR2 or DDR3 first")

### 3.4 `md.w`/`md.l`의 엔디안

값 필드는 **CPU 엔디안으로 읽은 워드**를 출력하고, ASCII 칼럼은 **메모리 바이트 순서**다. IP 카메라 SoC(ARM, Ingenic MIPS)는 리틀엔디안이므로 메모리 `27 05 19 56`은 `md.l`에서 `56190527`로 보인다(§14.3 예). 덤프 복원 시 워드를 리틀엔디안 바이트열로 되돌려야 한다. 엔디안 혼동을 피하려면 `md.b`를 쓴다(대신 처리량이 약 15% 낮다, §13.1).

### 3.5 견고한 파서

- OpenIPC 위키의 변환 명령 `sed -E "s/ {4}.{16}\r?$//"`는 **공백 4 구분자와 꽉 찬 16바이트 줄**을 가정한다. 2021.10 이후 빌드(공백 2)나 패딩 없는 마지막 짧은 줄에서는 깨진다. ASCII 칼럼에 hex처럼 보이는 문자(`ab cd`)가 있으면 토큰 분리 방식도 틀린다.
- 권장 방식: **줄마다 기대 필드 수**(= min(16/width, 남은 객체 수))를 계산하고, 주소 뒤에서 정확히 그만큼의 고정폭 필드(`' '` + 2×width 자리 hex)만 읽는다. 주소 연속성도 검사한다.

```python
import re

MD_LINE = re.compile(r'^([0-9a-fA-F]{8,16}):')

def parse_md(text: str, width: int, start: int, nbytes: int, little_endian=True) -> bytes:
    """U-Boot md.{b,w,l,q} 출력에서 nbytes 바이트를 복원한다.
    width: 1/2/4/8. 버전별 구분자(공백 4/2)와 패딩 유무에 무관하다."""
    out, addr = bytearray(), start
    for line in text.splitlines():
        line = line.rstrip('\r')
        m = MD_LINE.match(line)
        if not m:
            continue                      # 에코, 프롬프트, 빈 줄 등
        if int(m.group(1), 16) != addr:
            raise ValueError(f'address mismatch at {addr:#x}: {m.group(1)}')
        body = line[m.end():]
        nfields = min(16 // width, (nbytes - len(out)) // width)
        pos = 0
        for _ in range(nfields):
            tok = body[pos:pos + 1 + 2 * width]
            if len(tok) != 1 + 2 * width or tok[0] != ' ':
                raise ValueError(f'garbled line at {addr:#x}')
            out += int(tok[1:], 16).to_bytes(width, 'little' if little_endian else 'big')
            pos += 1 + 2 * width
        addr += nfields * width
        if len(out) >= nbytes:
            break
    if len(out) != nbytes:
        raise ValueError(f'incomplete: {len(out)}/{nbytes}')
    return bytes(out)
```

이 함수는 2010.06 형식(패딩 없음, 공백 4), 2013.07~2021.07 형식(패딩, 공백 4), 2021.10 이후 형식(패딩, 공백 2)과 ASCII 칼럼의 hex 유사 문자열로 왕복 테스트를 통과했다(이 문서 작성 중 `print_buffer` 동작을 재현한 생성기로 검증).

### 3.6 피해야 할 메모리 명령

- `mm`, `nm`: 대화형(값 입력 대기). 자동화에서 쓰지 않는다.
- `mdc`, `mwc`: 끝없는 루프. Ctrl-C로만 빠져나오며 `Abort`를 출력한다(`[UB-master]` cmd/mem.c `do_mem_mdc`).
- `mw`, `cp`, `loop`, `mtest`: 쓰기·부하. 반복 가능하므로 R2 위반 시 다시 실행된다.

---

## 4. `crc32` (및 `hash crc32`)

### 4.1 문법

```
crc32 address count [addr]          - compute CRC32 checksum [save at addr]
crc32 -v address count crc          - verify crc of memory area   (CONFIG_CRC32_VERIFY 빌드)
hash crc32 address count [[*]hash_dest]   (CONFIG_CMD_HASH 빌드, 2013.07~)
```
(`[UB-master]` cmd/mem.c:1365-1380, cmd/hash.c U_BOOT_CMD)

- `address`, `count`는 **16진수**, `count`는 **바이트 수**다.
- 출력의 끝 주소는 **포함 범위**(`addr + len - 1`)다.

### 4.2 출력 포맷 — 대문자/소문자 두 가지

| 조건 | 출력 포맷 | 출처 |
|---|---|---|
| 2010.06 (항상) | `CRC32 for %08lx ... %08lx ==> %08lx\n` | `[UB-2010.06]` common/cmd_mem.c:1110 |
| 2010.06 `-v` 불일치 | `CRC32 for %08lx ... %08lx ==> %08lx != %08lx ** ERROR **\n` | `[UB-2010.06]` common/cmd_mem.c:1166 |
| 2013.07~, "multi-hash" 꺼짐 | `CRC32 for %08lx ... %08lx ==> %08lx\n` (대문자) | `[UB-2013.07]` common/hash.c:338, `[UB-master]` common/hash.c:685 |
| 2013.07~, "multi-hash" 켜짐 | `"%s for %08lx ... %08lx ==> "` + 바이트마다 `"%02x"` + `"\n"` → `crc32 for ...` (**소문자 알고리즘 이름**) | `[UB-2013.07]` common/hash.c:237-239, `[UB-master]` common/hash.c:580-582 |
| multi-hash `-v` 불일치 | 위 줄 뒤 `" != "` + 기대값 + `" ** ERROR **\n"` | `[UB-master]` common/hash.c (verify 경로) |

- multi-hash가 켜지는 조건(메인라인): `SHA256`, `CMD_SHA1SUM`, `CRC32_VERIFY`, `CMD_HASH`, `SHA384`, `SHA512`, `CMD_MD5SUM`, `SM3` 중 하나라도 켜짐(`[UB-master]` common/hash.c:375-383). 2013.07은 `CONFIG_CMD_SHA1SUM`, `CONFIG_SHA256`, `CONFIG_HASH_VERIFY`, `CONFIG_CMD_HASH` 중 하나(`[UB-2013.07]` common/hash.c:60-95). 2019.04·2020.01 계열은 `CONFIG_SHA256`, `CONFIG_CMD_SHA1SUM`, `CONFIG_CRC32_VERIFY`, `CONFIG_CMD_HASH` 중 하나(`CMD_MD5SUM`은 조건에 없음: `[UB-2019.04]` common/hash.c:210-214).
- 카메라 빌드 예: XMedia 벤더 `xm72020300_defconfig`는 `CONFIG_SHA256=y`(1107행)라 **소문자** `crc32 for ...`이고, Novatek `nvt-na51055_nor_defconfig`(SHA256·SHA1SUM·CRC32_VERIFY·CMD_HASH 모두 꺼짐)와 HiSilicon V4 `hi3516ev300_defconfig`(`# CONFIG_SHA256 is not set`)는 대문자 `CRC32 for ...`로 판단된다. 빌드마다 다르므로 파서는 대소문자를 구분하지 않는다.
- 두 형식의 16진 값은 **같다**. multi-hash 경로는 `crc32_wd_buf()`가 `htonl()`로 빅엔디안 바이트열을 만든 뒤 `%02x`로 찍기 때문이다(`[UB-master]` lib/crc32.c:265-273).
- 파서 정규식(대소문자 무시):
  ```
  (?i)crc32 for ([0-9a-f]{8,16}) \.\.\. ([0-9a-f]{8,16}) ==> ([0-9a-f]{8})
  ```
- 명령이 빌드에서 빠졌으면 `Unknown command 'crc32' - try 'help'`가 나온다. 이때는 같은 범위를 두 번 덤프해 호스트에서 비교하는 방식으로 대체한다.

### 4.3 알고리즘

U-Boot `lib/crc32.c`는 zlib 1.1.3의 crc32.c에서 파생됐다(`[UB-master]` lib/crc32.c:1-8). 다항식 `0xedb88320`(반사형), 초기값/최종 XOR `0xffffffff`인 표준 CRC-32(IEEE 802.3)이고, `crc32(0, buf, len)`은 Python `zlib.crc32(buf) & 0xffffffff`와 같다.

```python
import zlib
def uboot_crc32(data: bytes) -> str:
    return f'{zlib.crc32(data) & 0xffffffff:08x}'
```

주의: BusyBox `cksum`은 POSIX cksum(빅엔디안 테이블 + 길이 포함)이라 U-Boot `crc32`와 **값이 다르다**(`busybox-1.24.1/coreutils/cksum.c:22-66`). 리눅스 쪽 검증에는 `md5sum`(출력 `"%s  %s\n"`, 공백 2)을 쓴다.

---

## 5. `sf` / `nand` / `mmc` / `tftp` / `fatwrite`

### 5.1 `sf` 문법

```
sf probe [[bus:]cs] [hz] [mode]   - init flash device on given SPI bus and chip select
sf read addr offset len           - read `len' bytes starting at `offset' to memory at `addr'
sf write addr offset len          - write `len' bytes from memory at `addr' to flash at `offset'
sf erase offset [+]len            - erase `len' bytes from `offset'; `+len' round up `len' to block size
sf update addr offset len         - erase and write `len' bytes from memory at `addr' to flash at `offset'
```
(`[UB-2013.07]` common/cmd_sf.c:524-536. 최신 메인라인은 `offset|partition`으로 MTD 파티션 이름도 받는다: `[UB-master]` cmd/sf.c:625-647)

- `addr/offset/len`은 16진수이고 끝까지 hex여야 한다(`*endp != 0`이면 usage). 예: `sf read 0x82000000 0 1000000`.
- `sf probe` 없이 다른 하위 명령을 쓰면 `No SPI flash selected. Please run `sf probe'`.

### 5.2 `sf` 출력 — 버전·벤더별

| 빌드 | `sf probe` 출력 | `sf read` 성공 | `sf write` | `sf erase` | 출처 |
|---|---|---|---|---|---|
| 메인라인 2010.06 | `%u KiB %s at %u:%u is now current device` (드라이버가 `SF: Detected ...`를 printf할 수도 있음, 대부분 debug) | **출력 없음** | **출력 없음** | 출력 없음 | `[UB-2010.06]` common/cmd_sf.c:68-69; drivers/mtd/spi/macronix.c:333 |
| HiSilicon V1~V3 포크 (2010.06) | `%u KiB %s at %u:%u is now current device` (예: `16384 KiB hi_fmc at 0:0 is now current device`) | **`\n` 하나(빈 줄)** | `\rWriting at 0x%lx -- %3d%% complete.` 진행 표시 후 `\n` | `\rErasing at 0x%lx -- %3d%% complete.` 후 `\n`. 정렬 오류: `ERROR: erase start address is not block aligned!` / `ERROR: erase length is not block aligned!` | `[OI-hi3516cv200]` common/cmd_sf.c:69,151,240 및 `do_spi_flash_read_write`/`do_spi_flash_erase` |
| 메인라인 2013.07, Ingenic, SigmaStar/MStar 2015.01 | 드라이버가 `SF: Detected ...` 출력 | `SF: %zu bytes @ %#x %s: %s\n` → `SF: 2097152 bytes @ 0x40000 Read: OK` | 같은 줄, `Written` | `SF: %zu bytes @ %#x Erased: %s\n` | `[UB-2013.07]` common/cmd_sf.c:277,312; `[OI-ingenic]` common/cmd_sf.c:304,339 |
| SigmaStar 포크 | 위와 같음 | `SF: %zu bytes @ %#x %s: %s` + ` (cost %ld ms)\n` | | | `[OI-sigmastar]` common/cmd_sf.c:522-528 |
| 메인라인 2016.11 ~ 최신 | `SF: Detected %s with page size ` + 크기 + `, erase size ` + 크기 + `, total ` + 크기 | `"SF: %zu bytes @ %#x %s: "` + `"OK\n"` 또는 `"ERROR %d\n"` | 같음 | `SF: %zu bytes @ %#x Erased: ` + `OK`/`ERROR %d` | `[UB-2016.11]` drivers/mtd/spi/spi_flash.c:1240; `[UB-master]` cmd/sf.c:333-338,383-387, drivers/mtd/spi/spi-nor-core.c:4761-4765 |
| HiSilicon V4 / Goke / XMedia 포크 (2016.11/2020.01) | (SDK 출력) | **빈 줄** 뒤 `SF: %zu bytes @ %#x Read: OK` (속도 옵션 빌드는 `SF:%zu bytes @ %#x %s: cost:%lu usec;speed:...` 줄 추가) | `\rWriting at 0x%llx -- %3d%% complete.` 후 빈 줄 + `SF: ... Written: OK` | `\rErasing at 0x%llx -- %3d%% complete.` 후 `SF: %zu bytes @ %#x Erased: %s` | `[OI-hi3516ev200]` cmd/sf.c:348-375,450-460 |
| 2013.07 드라이버 | `SF: Detected %s with page size ` + **섹터 크기**(레이블과 달리) + `, total ` + 크기 | | | | `[UB-2013.07]` drivers/mtd/spi/spi_flash.c:557-562 |

크기 표기 `print_size()` 규칙(`[UB-master]` lib/display_options.c `print_size`): 1024 미만이면 `"%u Bytes"`, 그 외에는 `"%lu"` + (소수 한 자리가 0이 아니면 `".%ld"`) + `" %ciB"`. 예: `SF: Detected gd25q128 with page size 256 Bytes, erase size 64 KiB, total 16 MiB` (합성, 포맷은 소스와 일치).

`%#x`는 0이어도 `0x0`을 출력한다(U-Boot 자체 vsprintf의 `need_pfx`에 0 예외가 없음: `[UB-2010.06]` lib/vsprintf.c `number()`, `[UB-master]` lib/vsprintf.c). 그래서 `SF: 16777216 bytes @ 0x0 Read: OK`다.

그 밖의 문자열: `ERROR: attempting %s past flash size (%#x)` (범위 초과, 메인라인), `ERROR: read/write area is out of range!` (HiSilicon 2010.06 포크), `SF: Warning - Only lower 16MiB accessible,` + ` Full access #define CONFIG_SPI_FLASH_BAR` (16 MiB 초과 칩, 2013~2016).

`sf update` (메인라인): 진행 중 `   \rUpdating, %zu%% %lu B/s`, 끝나면 `\r` 후 `%zu bytes written, %zu bytes skipped` + ` in %ld.%lds, speed %ld B/s\n` (`[UB-master]` cmd/sf.c `spi_flash_update`).

### 5.3 `nand`

```
\nNAND read: device 0 offset 0x100000, size 0x400000\n
 4194304 bytes read: OK\n
```
구성 요소:
- `printf("\nNAND %s: ", read ? "read" : "write");` (`[UB-2013.07]` common/cmd_nand.c:642)
- `printf("device %d ", *idx);` + 전체 칩이면 `whole chip\n`, 아니면 `offset 0x%llx, size 0x%llx\n` (2013.07: cmd_nand.c:224-229. 2010.06: `offset 0x%lx, size 0x%zx\n`, cmd_nand.c:147-151)
- `printf(" %zu bytes %s: %s\n", rwsize, read ? "read" : "written", ret ? "ERROR" : "OK");` (2013.07: cmd_nand.c:725-726)
- 배드 블록 때문에 크기가 조정되면 `size adjusted to 0x%llx (%d bad blocks)`

`nand info` (앞에 빈 줄 하나):
```
Device %d: [%dx ]%s, sector size %u KiB
  Page size  %8d b
  OOB size   %8d b
  Erase size %8d b
```
(`[UB-2013.07]` common/cmd_nand.c:380-387. 최신 메인라인은 레이블 폭이 넓어지고 `ecc strength`, `ecc step size`, `subpagesize`, `options`, `bbt options` 줄이 추가됨: `[UB-master]` cmd/nand.c:455-468)

OpenIPC 위키는 HiSilicon/Goke NAND 기기의 부트 로그 크기 표기로 `Chipsize:128 MiB` 또는 `NAND: 128 MiB`를 예로 든다(`[OIW] backup-stock-firmware.md` route G). `sf`는 SPI NOR 전용이고, NAND 기기에서는 `sf` 경로로 백업할 수 없다.

### 5.4 `mmc`

| 버전 | read 출력 | 출처 |
|---|---|---|
| 2010.06 | `\nMMC read: dev # %d, block # %d, count %d ... ` + `%d blocks read: %s\n` | `[UB-2010.06]` common/cmd_mmc.c:185,195 |
| 2013.07 | `\nMMC %s: dev # %d, block # %d, count %d ... ` + `%d blocks %s: %s\n` (`%s` = `read`/`write`/`erase`) | `[UB-2013.07]` common/cmd_mmc.c:386,416 |
| 최신 | `MMC read: dev # %d, block # %d, count %d ... ` (앞 `\n` 없음) + `%d blocks read: %s\n` | `[UB-master]` cmd/mmc.c:369-373 |

- 인자 `blk`, `cnt`는 **16진수로 받지만 출력은 10진수**다(`mmc read 0x82000000 0x10 0x8000` → `block # 16, count 32768`).
- **문법이 버전마다 다르다.** 2013.07 이후는 `mmc dev [dev]`로 장치를 고른 뒤 `mmc read addr blk# cnt` / `mmc write addr blk# cnt` / `mmc erase blk# cnt`(`[UB-2013.07]` common/cmd_mmc.c:427-433). 2010.06과 HiSilicon V1~V3 포크는 장치 번호가 첫 인자인 `mmc read <device num> addr blk# cnt` / `mmc write <device num> addr blk# cnt`이고 `mmc dev`·`mmc erase`가 없다(`[UB-2010.06]` common/cmd_mmc.c:229-235, `[OI-hi3516cv200]` common/cmd_mmc.c:359-370). 2010.06·2013.07에는 하위 명령별 반복 검사도 없다(§2.4).
- `mmc info`: `Device: %s`, `Manufacturer ID: %x`, `OEM: %x`, `Name: %c%c%c%c%c `, `Bus Speed: %d`(신버전), `Rd Block Len: %d`, `High Capacity: %s`, `Capacity: ` + 크기, `Bus Width: %d-bit`. 장치 선택은 `mmc%d is current device`.

### 5.5 `tftpboot` / `tftpput`

메인라인 문법: `tftpput address size [[hostIPaddr:]filename]` (`[UB-master]` doc/usage/cmd/tftpput.rst). 출력 구성(`[UB-2013.07]` net/tftp.c:740-781, net/net.c:532):

```
Using %s device
TFTP %s server %pI4; our IP address is %pI4[; sending through gateway %pI4]   (%s = "to"(put) / "from"(get))
Filename '%s'.[ Size is 0x%x Bytes = <print_size>]
Load address: 0x%lx                                   (get)
Loading: *\b  ... #### ...                            (get)
  -- 또는 (put) --
Save address: 0x%lx
Save size:    0x%lx
Saving: *\b ...
\t <print_size>/s                                     (2013.07~: "\n\t " + 전송 속도, 소요 시간이 0보다 클 때)
done
Bytes transferred = %ld (%lx hex)          (최신: %u (%x hex))
```
- 2010.06은 둘째 줄이 `TFTP from server %pI4; our IP address is %pI4`이고(업로드 없음), 속도 줄 없이 `\ndone\n`이다(`[UB-2010.06]` net/tftp.c:579-603,474).
- `Save address:`와 `Save size:`는 **별개의 두 줄**이다(`[UB-2013.07]` net/tftp.c:771-772). 속도 줄: `[UB-2013.07]` net/tftp.c:304-309.
- 오류: `\nTFTP error: '%s' (%d)\n`, 시간 초과 표시 `T `, Ctrl-C 중단 `\nAbort\n`.
- **HiSilicon 포크 주의**: HiSilicon의 통합 `tftp`는 **인자 3개(`tftp <addr> <file> <len>`)일 때 업로드**, 2개일 때 다운로드다. 플래싱 절차에 3인자 형태를 습관적으로 쓰면 RAM 버퍼를 서버로 보내고 기기에는 아무것도 쓰지 않는다(`[OIW] backup-stock-firmware.md` "The three-argument trap").

### 5.6 `fatwrite`

```
fatwrite <interface> <dev[:part]> <addr> <filename> <bytes>                  (2013.07)
fatwrite <interface> <dev[:part]> <addr> <filename> [<bytes> [<offset>]]     (최신)
```
(`[UB-2013.07]` common/cmd_fat.c:144-148, `[UB-master]` cmd/fat.c:103-107). FAT 쓰기 지원(`CONFIG_FAT_WRITE`)은 카메라 빌드에서 빠진 경우가 많다. 이때는 `mmc write`로 카드의 원시 블록에 쓰는 방법이 있다(§13.3).

---

## 6. 환경 변수 (텍스트 측면)

### 6.1 `printenv` 출력

- 한 변수당 한 줄 `name=value`, 마지막에 빈 줄 하나와 크기 줄:
  ```
  \nEnvironment size: %d/%ld bytes\n
  ```
  (`[UB-2010.06]` common/cmd_nvedit.c:152, `[UB-2013.07]` common/cmd_nvedit.c:145, `[UB-master]` cmd/nvedit.c:112)
- `%ld`(분모) = `ENV_SIZE` = `CONFIG_ENV_SIZE` − 4 (redundant env면 − 5). 예: HiSilicon SDK `CONFIG_ENV_SIZE 0x40000` → `262140`.
- 이름을 주면 그 변수만 `name=value`로 출력한다. 없으면 `## Error: "%s" not defined`.

**출력 순서와 분자(%d)는 버전마다 다르다** (시뮬레이터가 재현해야 함):

| 버전 | 순서 | 분자 `%d`의 의미 | 출처 |
|---|---|---|---|
| 2010.06·2010.09 및 HiSilicon V1~V3 포크 (해시테이블 이전) | **플래시 저장 순서**(정렬 안 됨). `setenv`는 기존 항목을 지우고 끝에 덧붙이므로 바꾼 변수가 뒤로 감 | 사용한 바이트 = Σ(`len(name=value)` + 1) | `[UB-2010.06]` common/cmd_nvedit.c:105-139,240,321 `printenv()` (lib/hashtable.c 없음). v2010.09도 같은 구현(GitHub v2010.09 common/cmd_nvedit.c) |
| 2010.12 ~ 2018.07 (해시테이블) | **키 이름 오름차순** (`qsort`) | `hexport_r()` 반환값 = 1 + Σ(len(key)+len(value)+**4**) (+ 이스케이프 문자). 길이 계산이 중복된 버그 | `[UB-2013.07]` lib/hashtable.c:639-679 `hexport_r`; `[UB-2016.11]` lib/hashtable.c:626; 해시테이블 도입은 v2010.12(v2010.09에는 없음) |
| 2018.09 ~ 2018.11 | 오름차순 | Σ(len(key)+len(value)+2) (**+1 없음**) | 커밋 f1b20acb4a03 "hashtable: Fix length calculation in hexport_r" (v2018.09에 포함, v2018.07에는 없음) |
| 2019.01 이후 | 오름차순 | 1 + Σ(len(key)+len(value)+2) | 커밋 4bca32497c09 "hashtable: fix length calculation in hexport_r" (f1b20acb4a03의 +1 제거를 되돌림, v2019.01에 포함); `[UB-2019.04]` lib/hashtable.c:631-671 |
| 2013.01 이후(확인한 Grain Media 2013.01 포크부터) | 오름차순, `.`으로 시작하는 변수 숨김(`printenv -a`로 표시, `H_HIDE_DOT`) | 위 각 버전 공식 | `[UB-2013.07]` common/cmd_nvedit.c:132-138; `[UB-master]` cmd/nvedit.c:89-126 |

### 6.2 `setenv` / `saveenv` / `env` 의미

- "As long as you don't save the environment, you are working with an in-memory copy." (`[UB-master]` doc/usage/environment.rst). `setenv`는 RAM 사본만 바꾸고 재부팅하면 사라진다.
- `setenv name` (값 없음) = 변수 삭제. `setenv name a b c` = 인자를 공백으로 이어 붙인 값.
- 쓰기 1회 변수: `ethaddr`, `serial#`는 기본적으로 덮어쓸 수 없다. 메시지는 2010.06 `Can't overwrite "%s"` (`[UB-2010.06]` common/cmd_nvedit.c:261), 2013.07 이후 `## Error: Can't overwrite "%s"` (`[UB-2013.07]` common/env_flags.c:533).
- `baudrate`를 바꾸면 즉시 UART 속도가 바뀐다: `## Switch baudrate to %d bps and press ENTER ...` 출력 뒤 새 속도로 `\r`을 기다린다. 표에 없는 값이면 `## Baudrate %d bps not supported`. 표(`CONFIG_SYS_BAUDRATE_TABLE`)는 HiSilicon V2·SigmaStar SDK와 메인라인 기본값이 모두 `{ 9600, 19200, 38400, 57600, 115200 }`이라 **115200을 넘는 속도로 올릴 수 없다**(`[UB-2010.06]` common/cmd_nvedit.c:268-293; hi3518ev200.h:168; infinity6e.h:57; 2013.07 `include/config_fallbacks.h:28-29`; 최신 메인라인은 이름이 `CFG_SYS_BAUDRATE_TABLE`로 바뀜: `[UB-master]` include/config_fallbacks.h:20-21).
- `saveenv` 출력:

| 버전 | SPI NOR 저장 시 출력 | 출처 |
|---|---|---|
| HiSilicon V1~V3 포크 (2010.06) | `Saving Environment to SPI Flash...\n` + `Erasing SPI flash, offset 0x%08x size %s ...` + `done\nWriting to SPI flash, offset 0x%08x size %s ...` + `done\n` (크기는 `ultohstr()`, 예: `256K`). 지울 크기가 erase block보다 작으면 앞에 `Warning: Erase size 0x%08x smaller than one erase block 0x%08x\n` + `         Erasing 0x%08x instead\n` | `[OI-hi3516cv200]` common/cmd_nvedit.c:643, common/env_sf.c:97-123, common/env_common_func.c:48-50 |
| 메인라인 ≤ 2016.11 및 2013.07·2015.01·2016.11 벤더 포크(Ingenic, SigmaStar, HiSilicon V4, Goke) | `Saving Environment to SPI Flash...\n` + `Erasing SPI flash...` + `Writing to SPI flash...` + `done\n`. redundant env 빌드(`CONFIG_ENV_OFFSET_REDUND`)는 뒤에 `Valid environment: %d\n`이 붙는다 | `[UB-2013.07]` common/cmd_nvedit.c:708, common/env_sf.c:287-307(일반), 119-148(redundant); `[UB-2016.11]` cmd/nvedit.c:710, common/env_sf.c:294-314 |
| 2019.04 | `Saving Environment to SPI Flash... ` + (위 3단계, `done\n`까지) + `OK\n` 또는 `Failed (%d)\n` | `[UB-2019.04]` env/env.c:243-248, env/sf.c:314 (`ENV_NAME("SPI Flash")`) |
| 최신 | `Saving Environment to SPIFlash... ` + ... + `OK` | `[UB-master]` env/env.c:268-283, env/sf.c:459-461 |

- 부팅 시 env CRC가 틀리면: `*** Warning - bad CRC, using default environment\n\n` (`[UB-2010.06]` common/env_sf.c:143, `[UB-2013.07]` common/env_common.c:127-128 `set_default_env("!bad CRC")`). 이 줄이 보이면 플래시의 env가 비었거나 깨졌고 **RAM에는 컴파일 시 기본 env가 올라와 있다**는 뜻이다. 이 상태에서 `saveenv`를 하면 기본 env가 플래시에 써진다.
- **HiSilicon V1~V3 포크의 자동 기록**: 위 경고 뒤에 CRC 워드가 `0xFFFFFFFF`(지워진 플래시)이면 `*** Write default environment to flash\n`을 출력하고 `saveenv()`를 **스스로** 호출한다. 그 뒤에 위 표의 `Erasing SPI flash, offset ...`·`Writing to SPI flash, offset ...` 줄이 이어진다(`[OI-hi3516cv200]` common/env_sf.c:155-165). 사람이 아무 명령도 보내지 않아도 플래시가 바뀌므로, 덤프 전 상태를 보존해야 하는 분석에서는 이 줄을 반드시 기록한다(R10). OpenIPC 빌드의 기본 `bootcmd`가 첫 부팅에 `saveenv`를 실행하는 경우와 Goke 빌드의 `fwrecovery`도 R10에 정리했다.

### 6.3 `run`, `bootcmd`, `bootargs`, `bootdelay`

- `run var [...]`: 변수 값을 명령으로 실행한다. 없으면 `## Error: "%s" not defined`. 여러 변수 중 하나가 실패하면 나머지는 실행하지 않는다(`[UB-master]` common/cli.c `do_run`, README "General rules").
- `bootcmd`: autoboot 시 실행. `boot`/`bootd`는 `bootcmd`를 실행한다.
- `bootargs`: `bootm`이 커널에 넘기는 명령행. 벤더 `bootcmd`가 실행 중에 `setenv bootargs ...`로 덮어쓰는 경우가 많으므로, 실제 커널 명령행은 리눅스 쪽 `Kernel command line:` 줄(§11.2)이나 `/proc/cmdline`(§11.4)로 확인한다.
- `bootdelay`: 10진수 초. 의미는 §8.3.
- SDK 기본값 예: HiSilicon V2 `bootcmd=bootm 0x82000000`, `bootargs=mem=96M console=ttyAMA0,115200`, `bootdelay=1` (hi3518ev200.h:143-145). Ingenic T31 SFC NOR `bootcmd=sf probe;sf read 0x80600000 0x40000 0x280000; bootm 0x80600000` (isvp_t31.h:355). HiSilicon 2010.06 기본 env의 `bootfile`은 `MK_STR(CONFIG_BOOTFILE)`로 만들어져 `bootfile="uImage"`처럼 **따옴표가 값에 포함**된다(`[OI-hi3516cv200]` common/env_common.c, hi3518ev200.h:150).

### 6.4 `mtdparts` 문법과 파싱 규칙 (리눅스 cmdlinepart)

```
mtdparts=<mtddef>[;<mtddef]
<mtddef>  := <mtd-id>:<partdef>[,<partdef>]
<partdef> := <size>[@<offset>][<name>][ro][lk][slc]
<mtd-id>  := unique name used in mapping driver/device (mtd->name)
<size>    := standard linux memsize OR "-" to denote all remaining space
             size is automatically truncated at end of device
             if specified or truncated size is 0 the part is skipped
<offset>  := standard linux memsize
             if omitted the part will immediately follow the previous part
             or 0 if the first part
<name>    := '(' NAME ')'
             NAME will appear in /proc/mtd
```
(`[LX-master]` drivers/mtd/parsers/cmdlinepart.c:8-36. v3.10에는 `[slc]`가 없음: `[LX-v3.10]` drivers/mtd/cmdlinepart.c)

파서 구현 규칙:

1. 숫자는 `memparse()` = `simple_strtoull(ptr, &endptr, 0)` → **진법 자동 감지**: `0x` 접두사는 16진수, **선행 `0`은 8진수**, 그 외 10진수. `0100k`는 64 KiB다.
2. 접미사(대소문자 무관): v3.10은 `K/M/G`, 최신은 `K/M/G/T/P/E` (`[LX-v3.10]` lib/cmdline.c `memparse`, `[LX-master]` lib/cmdline.c).
3. `-`(나머지 전부) 뒤에는 파티션을 둘 수 없다. 커널 로그에는 접두사가 붙어 `mtd: no partitions allowed after a fill-up partition`으로 나온다(`[LX-v3.10]` drivers/mtd/cmdlinepart.c:59 `#define ERRP "mtd: "`, :173; `[LX-master]` parsers/cmdlinepart.c:38 `pr_fmt`, :157).
4. 이름이 없으면 `Partition_%03d`. 플래그 `ro`(쓰기 금지), `lk`(잠금), `slc`.
5. `@offset`이 없으면 직전 파티션 바로 뒤에 놓인다. 파티션은 겹치거나 순서가 뒤바뀔 수 있고, MTD 번호는 **명령행에 적힌 순서**대로 매겨진다.
6. `<mtd-id>`는 플래시 드라이버의 `mtd->name`과 같아야 적용된다: HiSilicon `hi_sfc`(FMC v100 계열 — Hi3516CV200/Hi3518EV200/Hi3516CV300 등 — 은 U-Boot `sf probe`에서는 `hi_fmc`로 보이지만 커널 mtd-id는 `hi_sfc`), Goke `sfc`, Ingenic `jz_sfc`, SigmaStar `NOR_FLASH`, Xiongmai `xm_sfc` (§1.2).
7. 예: 벤더 Ingenic T31 SFC NOR 기본값 `mtdparts=jz_sfc:256k(boot),2560k(kernel),2048k(root),-(appfs)` (isvp_t31.h:340), OpenIPC `...:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(rootfs_data)`.

U-Boot 자체의 `mtdparts` 명령(`mtdids` 변수와 함께 쓰는 U-Boot 쪽 파티션 정의)은 카메라 SDK 빌드에서 거의 쓰이지 않는다. 대부분의 카메라는 `bootargs` 안의 `mtdparts=` 문자열로만 커널에 파티션을 전달한다.

---

## 7. U-Boot env 바이너리 레이아웃 (플래시 상의 형식)

### 7.1 구조체

```c
/* [UB-master] include/env_internal.h:57-84 ([UB-2010.06] include/environment.h:122-137 동일) */
#ifdef CONFIG_ENV_REDUNDANT            /* 2010.06: CONFIG_SYS_REDUNDAND_ENVIRONMENT */
# define ENV_HEADER_SIZE	(sizeof(uint32_t) + 1)
#else
# define ENV_HEADER_SIZE	(sizeof(uint32_t))
#endif
#define ENV_SIZE (CONFIG_ENV_SIZE - ENV_HEADER_SIZE)

typedef struct environment_s {
	uint32_t	crc;		/* CRC32 over data bytes	*/
#ifdef CONFIG_ENV_REDUNDANT
	unsigned char	flags;		/* active/obsolete flags ENVF_REDUND_ */
#endif
	unsigned char	data[ENV_SIZE]; /* Environment data		*/
} env_t;
```

| 오프셋 | 크기 | 내용 |
|---|---|---|
| 0 | 4 | `crc` — `data[0..ENV_SIZE)` **전체**(뒤쪽 패딩 포함)의 CRC-32 (§4.3 알고리즘). **CPU 엔디안**으로 저장 → 카메라(ARM/Ingenic MIPS)는 리틀엔디안 |
| 4 | 1 | `flags` — redundant env 빌드에만 있음 |
| 4 또는 5 | `ENV_SIZE` | `name=value\0name=value\0...\0\0` + 패딩 |

- `data`는 NUL로 끝나는 `name=value` 항목의 나열이고, **빈 문자열(연속 NUL 두 개)**이 끝 표시다.
- 패딩: U-Boot `saveenv`는 내보내기 버퍼를 `memset(res, '\0', size)`로 0x00 채움(`[UB-master]` lib/hashtable.c:701-703). 호스트 도구 `mkenvimage`는 기본 **0xFF** 채움(`-p <byte>`로 변경, `[UB-master]` tools/mkenvimage.c:43,80,156). 파서는 끝 표시 뒤를 무시해야 하지만 **CRC는 패딩까지 포함해 계산**해야 맞는다.
- `mkenvimage -b`: 빅엔디안 CRC. `-r`: redundant(플래그 바이트를 `1`로 기록, tools/mkenvimage.c:258-262).

### 7.2 redundant env의 `flags`

| 저장 매체 드라이버 | 의미 | 출처 |
|---|---|---|
| SPI flash (`env/sf.c`), NOR flash | `ENV_REDUND_ACTIVE = 1`, `ENV_REDUND_OBSOLETE = 0`. 새 사본은 ACTIVE로 쓰고, 옛 사본의 flags 바이트만 제자리에서 OBSOLETE로 덮어씀 | `[UB-master]` include/env.h:59-63, env/sf.c:81-97 |
| NAND (`env_nand.c`) | 저장할 때마다 1씩 증가하는 일련번호(`env_new.flags = ++env_flags;`). 큰 값이 최신, `255`와 `0`이 같이 있으면 `0`이 최신(랩어라운드) | `[UB-2013.07]` common/env_nand.c:109-117,195 |

### 7.3 카메라에서 흔한 위치·크기

| 빌드 | `CONFIG_ENV_OFFSET` | `CONFIG_ENV_SIZE` | 비고 | 출처 |
|---|---|---|---|---|
| HiSilicon V1~V3 SDK | `0x80000` | `0x40000` (헤더 포함) | `ENV_SECT_SIZE` = `ENV_SIZE` | hi3518ev200.h:129-135 |
| HiSilicon V4 / Goke SDK | `0x80000` | `0x40000` | 섹터 `0x10000` | hi3516ev200.h:192-195, gk7205v200.h:169-172 |
| Ingenic T31 SDK (SFC NOR) | `0x3C000` (유도) | `0x4000` (16 KiB) | 256 KiB `boot` 파티션 안쪽 끝 | isvp_t31.h:552-579,617-619 |
| SigmaStar Infinity6 SDK (NOR) | `0x4F000` | `0x1000` | | infinity6.h:160-165 |
| SigmaStar Infinity6E SDK (NOR) | 런타임 값 `ms_nor_env_offset`(ONEBIN+PARTITION 또는 `CONFIG_MSTAR_ENV_OFFSET`), 아니면 `0x5F000` | `0x1000` | 파티션 테이블 의존 | infinity6e.h:165-182 |
| OpenIPC (HiSilicon/Goke/Ingenic/SigmaStar NOR) | `0x40000` (HiSilicon/Goke `CONFIG_XM_COMPATIBLE` 빌드는 `0x30000`) | `0x10000` | 독립 `env` 파티션 64 KiB | hi-common.h:41-47, isvp_common.h:70-72, sstar-common.h:24-29 |

위 SDK 행은 OpenIPC 미러에서 공통 헤더 include **이전**의 벤더 값이다(§1 주의 참고). 같은 저장소로 빌드한 OpenIPC 바이너리는 마지막 행의 값을 쓴다.

### 7.4 덤프에서 env 찾기 (fwtriage용)

오프셋·크기를 모르면 **후보 크기를 대입해 CRC가 맞는 곳**을 찾는다. 가짜 일치는 사실상 없다(32비트 CRC + `name=` 형식 검사).

```python
import struct, zlib

SIZES = (0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000, 0x40000)

def parse_env_blob(blob: bytes, redundant=False, big_endian=False):
    hdr = 5 if redundant else 4
    crc = struct.unpack('>I' if big_endian else '<I', blob[:4])[0]
    data = blob[hdr:]
    if zlib.crc32(data) & 0xffffffff != crc:
        return None
    end = data.find(b'\x00\x00')
    if end < 0:
        return None
    env = {}
    for item in data[:end].split(b'\x00'):
        if b'=' in item:
            k, v = item.split(b'=', 1)
            env[k.decode('latin-1')] = v.decode('latin-1')
    return env, (blob[4] if redundant else None)

def find_env(image: bytes, align=0x1000):
    hits = []
    for off in range(0, len(image), align):
        for size in SIZES:
            if off + size > len(image):
                break
            for red in (False, True):
                r = parse_env_blob(image[off:off + size], redundant=red)
                if r:
                    hits.append({'offset': off, 'size': size, 'redundant': red,
                                 'flags': r[1], 'vars': r[0]})
    return hits
```

- 같은 위치에서 여러 크기가 맞을 수는 없지만(CRC 범위가 다름) redundant 쌍은 두 위치에서 나온다. `flags`로 최신본을 고른다(§7.2).
- 0x00 패딩(`saveenv`)과 0xFF 패딩(`mkenvimage`, 공장 이미지) 모두 위 코드로 처리된다(위 함수로 두 경우 모두 검증함).
- 리눅스에서 `fw_printenv`/`fw_setenv`(u-boot-tools)를 쓰려면 `/etc/fw_env.config`에 `# MTD device name	Device offset	Env. size	Flash sector size	Number of sectors` 형식으로 적는다. 예: `/dev/mtd1		0x0000		0x4000		0x4000`. offset은 `0x`가 있어야 16진수로 읽힌다(`[UB-master]` tools/env/fw_env.config:1-12).

---

## 8. Autoboot

### 8.1 표준(비-keyed) 모드 — 정확한 바이트열

2010.06 ~ v2025.07의 메인라인과 확인한 모든 카메라 포크가 쓰는 형식(`[UB-2010.06]` common/main.c:214-262, `[UB-2013.07]` common/main.c:204-258, `[UB-2016.11]` common/autoboot.c:211-253):

```c
	printf("Hit any key to stop autoboot: %2d ", bootdelay);
	...
	if (tstc()) {	/* we got a key press	*/        /* v2016.07~ 항상, 이전은 CONFIG_ZERO_BOOTDELAY_CHECK일 때만 */
		(void) getc();  /* consume input	*/
		puts("\b\b\b 0");
		abort = 1;	/* don't auto boot	*/
	}
	while ((bootdelay > 0) && (!abort)) {
		--bootdelay;
		/* delay 1000 ms */
		ts = get_timer(0);
		do {
			if (tstc()) {	/* we got a key press	*/
				abort  = 1;	/* don't auto boot	*/
				bootdelay = 0;	/* no more delay	*/
				(void) getc();  /* consume input	*/
				break;
			}
			udelay(10000);
		} while (!abort && get_timer(ts) < 1000);
		printf("\b\b\b%2d ", bootdelay);
	}
	putc('\n');
```

| 상황 (bootdelay=3) | 원시 바이트열 (`\b` = 0x08) |
|---|---|
| 아무 입력 없음 | `Hit any key to stop autoboot:  3 ` → 1초마다 `\b\b\b 2 `, `\b\b\b 1 `, `\b\b\b 0 ` → `\r\n` → bootcmd 실행 |
| 카운트다운 중 키 | 직전 숫자 뒤 `\b\b\b 0 ` → `\r\n` → 프롬프트 |
| 메시지 출력 시점에 이미 키가 버퍼에 있음 | `Hit any key to stop autoboot:  3 \b\b\b 0` (**끝 공백 없음**) → `\r\n` → 프롬프트 |
| bootdelay=0, 입력 없음 | `Hit any key to stop autoboot:  0 ` → `\r\n` → bootcmd |

- 터미널 화면에는 마지막 숫자만 남는다(예: `Hit any key to stop autoboot:  0`). **원시 바이트에는 백스페이스가 섞여 있으므로** 정규식은 `Hit any key to stop autoboot:\s*(\d+)` 로 첫 숫자를 잡고, 이후 갱신은 `\x08{3}\s?(\d+)` 로 잡는다.
- 중단에 쓰인 키 1바이트는 소비된다(`getc()`). 그 뒤에 들어온 바이트는 프롬프트의 입력 버퍼로 간다.

### 8.2 최신 메인라인 형식 (v2025.10 이후, 두 단계)

메인라인은 두 번에 걸쳐 갱신 방식을 바꿨다.

| 릴리스 | 첫 출력 | 매초 갱신 | 메시지 시점에 키가 이미 있음 | 출처 |
|---|---|---|---|---|
| v2025.10 ~ v2026.01 (커밋 5f70be08b015, 2025-07 머지) | `Hit any key to stop autoboot: %2d ` (고전 형식 그대로) | `\rHit any key to stop autoboot: %1d\033[K` | `\b\b\b 0` (고전 형식 그대로) | GitHub `u-boot/u-boot` v2025.10 common/autoboot.c:384-414 |
| v2026.04 이후 (커밋 af38567cadca, 2025-10 작성·2025-12 머지) | `\e[2K\rHit any key to stop autoboot: %d` | 같은 문자열 다시 출력 | `print_boot_delay(0)` = `\e[2K\rHit any key to stop autoboot: 0` | `[UB-master]` common/autoboot.c:371-416 |

```c
/* v2026.04~ */
static void print_boot_delay(int bootdelay)
{
	printf(ANSI_CLEAR_LINE "\rHit any key to stop autoboot: %d", bootdelay);   /* ANSI_CLEAR_LINE = "\e[2K" (include/ansi.h:23) */
}
```
두 형식 모두 끝에 `\n`이 붙고, 폭 지정 없는(`%d`/`%1d`) 숫자 뒤에 공백이 없다. 정규식 `Hit any key to stop autoboot:\s*(\d+)`는 세 형식 모두에 맞지만, `\x08{3}` 갱신 정규식은 고전 형식에만 맞는다. 카메라 SDK에서는 아직 보기 어렵지만 시뮬레이터 프로파일로 둘 가치가 있다.

### 8.3 `bootdelay` 값의 의미

| 값 | 의미 | 버전 |
|---|---|---|
| > 0 | N초 카운트다운 | 전 버전 |
| 0 | 지연 없이 부팅. **입력 버퍼를 한 번 확인**해 키가 있으면 중단 | v2016.07 이후 항상(커밋 2fbb8462b0e1 "autoboot: remove CONFIG_ZERO_BOOTDELAY_CHECK", 2016-07-01 머지, v2016.07에 포함·v2016.05에는 없음). 그 이전은 `CONFIG_ZERO_BOOTDELAY_CHECK`가 있을 때만(HiSilicon V1~V3 SDK는 켬, hi3518ev200.h:160) |
| -1 | autoboot 안 함 → 바로 프롬프트 | 2010.06: `bootdelay >= 0`일 때만 autoboot(main.c:400), 2013.07~: `bootdelay != -1` |
| -2 | 지연도 중단 확인도 없이 부팅 | 2013.07~ (`[UB-master]` boot/Kconfig:1641-1648) |

`bootdelay`는 env에서 10진수로 읽고, 없으면 `CONFIG_BOOTDELAY`(메인라인 Kconfig 기본 2).

### 8.4 keyed 모드 (`CONFIG_AUTOBOOT_KEYED`)

- 시작 시 `CONFIG_AUTOBOOT_PROMPT`를 printf로 한 번 출력한다. 메인라인은 2016.11 이후 `printf(CONFIG_AUTOBOOT_PROMPT, bootdelay)`(`[UB-2016.11]` common/autoboot.c:195), 그 이전은 `printf(CONFIG_AUTOBOOT_PROMPT)`이고(`[UB-2010.06]` common/main.c:122, `[UB-2013.07]` common/main.c:117, SigmaStar 2015.01 포크도 같음) `%d`를 쓰려면 인자를 매크로 안에 적는다(예: `[OI-t40]` isvp_common.h:85-86 `"Press Ctrl-c to abort autoboot... %d \n", bootdelay`). OpenIPC `u-boot-ingenic`(2013.07 베이스)은 printf를 `printf(CONFIG_AUTOBOOT_PROMPT, bootdelay)`로 고쳐 두었다(`[OI-ingenic]` common/main.c:120). 메인라인 Kconfig 기본 문구는 `Autoboot in %d seconds\n`(`[UB-master]` boot/Kconfig:1676-1678). 프롬프트가 정의되지 않은 빌드는 **아무것도 출력하지 않는다**(SigmaStar SDK).
- **카운트다운 갱신이 없다.** 수신 바이트를 슬라이딩 버퍼에 모아, 버퍼의 **끝**이 지정 문자열과 같아지면 중단한다(suffix 매칭). 그래서 같은 키를 반복해 보내도 된다(`[UB-master]` common/autoboot.c:240-312 `passwd_abort_key`).
- 문자열 원천: env `bootdelaykey`/`bootstopkey`가 우선, 없으면 `CONFIG_AUTOBOOT_DELAY_STR`/`CONFIG_AUTOBOOT_STOP_STR`. 구버전은 `...2` 변형도 있음. `DELAY_STR` 계열은 부트 재시도(`CONFIG_BOOT_RETRY_TIME`)를 허용하고 `STOP_STR`은 허용하지 않는다(`[UB-master]` boot/Kconfig:1717-1739). SigmaStar 2015.01 포크는 env `bootdelaykey`와 `CONFIG_AUTOBOOT_DELAY_STR`만 본다(`bootstopkey`·`...2`·`STOP_STR` 처리는 주석 또는 `#if 0`: `[OI-sigmastar]` common/autoboot.c:50-53,74-87).
- SHA256/crypt 비교 변형(`CONFIG_AUTOBOOT_ENCRYPTION`, env `bootstopkeysha256`)은 입력 문자열의 해시를 비교한다.
- keyed 빌드는 `bootcmd` 실행 중 Ctrl-C 확인을 끈다(`disable_ctrlc(1)`, 메인라인은 `CONFIG_AUTOBOOT_KEYED_CTRLC`면 예외). 비-keyed 빌드는 `bootcmd` 안의 명령이 `ctrlc()`를 폴링하면 Ctrl-C로 끊길 수 있다(`[UB-2013.07]` common/main.c:410-419, `[UB-master]` common/autoboot.c:493-512).
- OpenIPC HiSilicon V4/Goke 헤더의 `#define AUTOBOOT_KEYED_CTRLC`(hi-common.h:57, gk-common.h:64)는 `CONFIG_` 접두사가 없어 **효과가 없다**. 포크의 검사는 `#if defined(CONFIG_AUTOBOOT_KEYED) && !defined(CONFIG_AUTOBOOT_KEYED_CTRLC)`이므로(`[OI-hi3516ev200]`·`[OI-gk7205v200]` common/autoboot.c:347-354) 이 빌드에서도 `bootcmd` 실행 중 Ctrl-C가 꺼진다.

### 8.5 벤더별 autoboot 변형 (소스로 확인한 것)

| 빌드 | 메시지 | 중단 입력 | 출처 |
|---|---|---|---|
| HiSilicon/Goke/Ingenic/SigmaStar(비-keyed 경로)/Novatek/Grain Media/XMedia 포크 | `Hit any key to stop autoboot: %2d ` (메인라인 그대로) | 아무 바이트 | 각 포크 common/main.c 또는 common/autoboot.c (`[OI-hi3516cv200]` main.c:223, `[OI-ingenic]` main.c:217, `[OI-hi3516ev200]` autoboot.c:219, `[OI-nt9856x]` autoboot.c:223, `[OI-xmedia]` autoboot.c:251, `[OI-grainmedia]` main.c:233) |
| SigmaStar/MStar SDK (keyed) | 없음 | CR(0x0D), bootdelay 0 → 입력 버퍼를 두 번만 확인 | `[OI-sigmastar]` infinity6e.h:29-30, common/autoboot.c `abortboot_keyed` |
| Rockchip | `Hit key to stop autoboot('CTRL+C'): %2d ` | Ctrl-C(0x03)만 | `[RK]` common/autoboot.c:219-247 |
| OpenIPC HiSilicon V4/Goke (2016.11) | `Press Ctrl-c to stop autoboot... %d \n` | 0x03 | `[OI-hi3516ev200]` hi-common.h:53-57, `[OI-gk7205v200]` gk-common.h:60-64 |
| OpenIPC HiSilicon V1~V3 (2010.06) | `Hit any key to stop autoboot: %2d ` (keyed 아님) | 아무 바이트 | `[OI-hi3516cv200]` hi-common.h (keyed 정의 없음), main.c:223 |
| OpenIPC Ingenic (`u-boot-ingenic`) | `\nPress ENTER to interrupt boot in %d...\n` | 0x0D | `[OI-ingenic]` isvp_common.h:75-77 |
| OpenIPC Ingenic T40 (`u-boot-t40`) | `Press Ctrl-c to abort autoboot... %d \n` | 0x03 | `[OI-t40]` isvp_common.h:84-87 |

일반 지침: OpenIPC 위키는 벤더 펌웨어의 중단 키가 대부분 Ctrl-C이고, 드물게 Enter·Esc·`*`·아무 키라고 정리한다(`[OIW] installation.md` Step 4). 소스로 확인할 수 없는 ODM 고유 키는 이 문서에서 다루지 않는다.

### 8.6 자동화 지침

1. **카운트다운 문자열을 감지한 뒤** 프로파일에 맞는 키를 보낸다. 표준 빌드는 0x03을 권장한다. 0x03은 autoboot에서는 "아무 키"로 소비되고, 이미 프롬프트에 도달한 뒤에는 `<INTERRUPT>`만 출력하므로 남는 부작용이 없다(§10). CR을 연타하면 프롬프트 도달 후 빈 줄이 되어 R2에 걸릴 수 있다.
2. 메시지가 없고 `bootdelay 0`인 keyed 빌드(SigmaStar SDK)는 감지할 문자열이 없다. 프로파일이 이를 명시한 경우에만, 사람이 전원을 넣는 시점에 맞춰 지정 키를 짧은 간격으로 보낸다. 이 동작은 Skill에서 사람의 확인을 받는 단계로 둔다.
3. 프롬프트를 확인하면 즉시 키 송신을 멈추고, Ctrl-C 한 번으로 입력 버퍼를 정리한 뒤 `<INTERRUPT>` + 프롬프트를 동기화 지점으로 쓴다.
4. 카운트다운이 끝나고 커널 출력(`Starting kernel ...`, §11.2)이 보이면 "중단 실패"로 기록하고 다음 부팅을 기다린다. 리눅스 콘솔에 들어간 0x03은 포그라운드 프로세스에 SIGINT가 될 수 있으므로 계속 보내지 않는다.

---

## 9. 프롬프트 문자열 표

| 프롬프트 (끝 공백 포함) | 사용처 | 출처 |
|---|---|---|
| `=> ` | 메인라인 Kconfig 기본(Zynq `Zynq> `, ZynqMP `ZynqMP> ` 예외), Rockchip, Novatek 기본 defconfig, 2010.06 다수 보드 | `[UB-master]` cmd/Kconfig:85-89; 2010.06 include/configs 집계 |
| `U-Boot> ` | 2010.06 시절 여러 보드 정의(그 밖에 `-> `, `$ `, `uboot> `, `U-Boot > `, `==> `도 존재) | `[UB-2010.06]` include/configs 집계 |
| `> ` | hush 보조 프롬프트(`CONFIG_SYS_PROMPT_HUSH_PS2`) | `[UB-master]` cmd/Kconfig:94-98 |
| ` > ` (앞 공백 포함) | OpenIPC HiSilicon/Goke 빌드의 hush 보조 프롬프트 | `[OI-hi3516cv200]` hi-common.h:46, `[OI-hi3516ev200]` hi-common.h:107 |
| `hisilicon # ` | HiSilicon SDK (V1~V4) | hi3518ev200.h:209, hi3516ev300_defconfig:257; 실기기 출력 `[OIW] install-hisi.md`, `help-uboot.md` |
| `goke # ` | Goke SDK (설정 소스 기준, 실기기 출력 미확인) | gk7205v200_emmc_defconfig:257 |
| `isvp_t31# ` (`isvp_t20# `, `isvp_t21# `, `isvp_t23# `, `isvp_t30# `), T10은 보드명이 `isvp`라 `isvp# ` | Ingenic SDK (`CONFIG_SYS_BOARD "# "`) | isvp_t31.h:547, isvp.h:278; `[OI-ingenic]` boards.cfg:572-601, mkconfig:166 |
| `SigmaStar # ` | SigmaStar SDK | infinity6e.h:86 |
| `MStar # ` | MStar Infinity3 SDK | infinity.h:63 |
| `nvt@na51055: ` | Novatek NA51055 SDK (nor/nand) | nvt-na51055_nor_defconfig:322 |
| `GM # ` / `A320 # ` | Grain Media GM8139·GM8210·GM8287 / GM8126 | gm8139.h:379, gm8126.h:273 |
| `xmedia # ` | XMedia SDK | xm72020300_defconfig 외 |
| `OpenIPC # ` | OpenIPC 빌드 | isvp_common.h:90, hi-common.h:52 |
| `amboot>` | Ambarella AMBoot | Include Security (Dropcam) |
| Fullhan, Anyka 프롬프트 | (미확인) | — |

---

## 10. Ctrl-C (0x03) 동작 정리

| 상태 | 결과 | 출처 |
|---|---|---|
| U-Boot 프롬프트 (입력 없음/일부 입력) | 0x03은 **에코되지 않음**. 입력을 버리고 `<INTERRUPT>\n` 출력 후 새 프롬프트. 화면: `hisilicon # <INTERRUPT>` / `hisilicon # ` | simple: `[UB-master]` common/cli_simple.c:305-306, `[UB-2010.06]` common/main.c:478; hush: `[UB-2013.07]` common/hush.c:3212 |
| simple 파서의 반복 상태 | `lastcommand` 유지 (Ctrl-C 후 맨 Enter → 직전 반복 가능 명령 실행) | §2.3 |
| hush 파서의 반복 상태 | `flag_repeat = 0` → 반복 안 됨 | `[UB-2013.07]` common/hush.c:1032-1039 |
| `ctrlc()`를 폴링하는 명령 실행 중 | 명령 중단. `md`는 메시지 없이 끝남, 네트워크는 `\nAbort\n`, `mdc`는 `Abort` | §2.5, §3.6 |
| autoboot 카운트다운 (비-keyed) | 아무 키처럼 소비되어 중단 | §8.1 |
| keyed + `bootcmd` 실행 중 | 무시됨(`disable_ctrlc(1)`). OpenIPC HiSilicon V4/Goke 빌드도 해당(`AUTOBOOT_KEYED_CTRLC` 정의가 접두사 없이 적혀 효과 없음) | §8.4 |
| 리눅스 셸 | SIGINT | — |

예상 바이트열(simple 파서, 프롬프트 `hisilicon # `):
```
송신: 03
수신: "<INTERRUPT>\r\nhisilicon # "
```

---

## 11. 리눅스 쪽

### 11.1 U-Boot → 커널 인계 구간

```
## Booting kernel from Legacy Image at %08lx ...          ([UB-2010.06] common/cmd_bootm.c:867, [UB-2013.07] common/cmd_bootm.c:941)
   Image Name:   %.*s                                     (common/image.c:305, IH_NMLEN=32)
   Created:      %4d-%02d-%02d  %2d:%02d:%02d UTC         (CONFIG_TIMESTAMP 또는 CONFIG_CMD_DATE 빌드만. 확인한 HiSilicon V1~V3·Ingenic T31 설정에는 없음)
   Image Type:   %s %s %s (%s)                            (arch os type comp, image.c:279 → "ARM Linux Kernel Image (uncompressed)")
   Data Size:    %d Bytes = <print_size>                  (genimg_print_size)
   Load Address: %08x
   Entry Point:  %08x
   Verifying Checksum ... OK                              (verify=n 이 아니면)
   Loading Kernel Image ... OK                            (비압축)  /  Uncompressing Kernel Image ... OK (lzma/gzip)
OK                                                        (2010.06 비압축은 "OK"가 한 줄 더: cmd_bootm.c:349,426)

Starting kernel ...                                       (ARM 2013.07~: "\nStarting kernel ...%s\n\n", ARM 2010.06/MIPS: "\nStarting kernel ...\n\n")
```
- 이미지 오류: `Bad Magic Number`, `Bad Header Checksum`, `Bad Data CRC`, `Wrong Image Format for %s command`, `ERROR: can't get kernel image!` (`[UB-2010.06]` common/cmd_bootm.c:223,730-748,971). `bootcmd`가 실패하면 U-Boot는 프롬프트로 떨어진다.
- `## Transferring control to Linux (at address %08lx) ...`는 `debug()`라서 보통 출력되지 않는다.
- `Created:` 줄의 조건과 포맷: `[UB-2010.06]` common/image.c:305-309, `[UB-2013.07]` include/image.h:400-405(`IMAGE_ENABLE_TIMESTAMP`), common/image.c:519-531(`genimg_print_time`).

### 11.2 커널 부트 감지 키워드

| 키워드 | 정확한 포맷 | 출처·변형 |
|---|---|---|
| `Uncompressing Linux...` | `"Uncompressing Linux..."` + `" done, booting the kernel.\n"` | ARM zImage 압축 해제기(v3.4~v4.9 동일). 플랫폼이 압축 해제기 출력(`putc`)을 구현한 경우에만 보임 (`[LX-v3.10]` arch/arm/boot/compressed/misc.c:147-153) |
| `Booting Linux on physical CPU` | v3.4 `"Booting Linux on physical CPU %d\n"`, v3.10~ `"... 0x%x\n"` | ARM only (`[LX-v3.4]`/`[LX-v3.10]` arch/arm/kernel/setup.c:442/459) |
| `Linux version ` | `"Linux version " UTS_RELEASE " (" LINUX_COMPILE_BY "@" LINUX_COMPILE_HOST ") (" LINUX_COMPILER ") " UTS_VERSION "\n"` | `[LX-v3.10]` init/version.c:43-45 |
| `Kernel command line: ` | `"Kernel command line: %s\n"` | `[LX-v3.4]` init/main.c:507, `[LX-v3.10]` :512, `[LX-v4.9]` :516 |
| MTD 파티션 | `"%d %s partitions found on MTD device %s\n"`, `"Creating %d MTD partitions on \"%s\":\n"`, `"0x%012llx-0x%012llx : \"%s\"\n"` | `[LX-v3.10]` drivers/mtd/mtdpart.c:459,633,742 |
| SPI NOR (메인라인 드라이버) | `"%s (%lld Kbytes)\n"`, `"unrecognized JEDEC id %06x\n"`. `dev_info()`/`dev_err()`라 실제 줄 앞에 `<드라이버> <장치>: `(예: `m25p80 spi0.0: `)가 붙는다 | `[LX-v3.10]` drivers/mtd/devices/m25p80.c:893,1051. 벤더 드라이버는 고유 출력 |
| `VFS: Mounted root` | `"VFS: Mounted root (%s filesystem)%s on device %u:%u.\n"` (`%s` = `" readonly"` 또는 `""`) | `[LX-v3.10]` init/do_mounts.c:366-369. MTD 블록 장치 major는 31 |
| `Freeing ... memory` | ARM v3.4: `"Freeing %s memory: %dK\n"` → `Freeing init memory: 160K`<br>v3.10: `"Freeing %s memory: %ldK (%lx - %lx)\n"` → `Freeing unused kernel memory: ...`<br>v3.18~v4.9: `"(%p - %p)"`<br>최신: `Freeing unused kernel image (initmem) memory: %ldK` | `[LX-v3.4]` arch/arm/mm/init.c:425,733-735; `[LX-v3.10]` mm/page_alloc.c:5167, include/linux/mm.h:1350-1356; `[LX-master]` mm/memblock.c:959, include/linux/mm.h:4103-4108. 감지는 `^Freeing .* memory` 로 |
| 루트 마운트 실패 | `"VFS: Unable to mount root fs on %s"` (panic) | `[LX-v3.10]` init/do_mounts.c:415,427 |
| 패닉 | `"Kernel panic - not syncing: %s\n"`, `"Rebooting in %d seconds.."` | `[LX-v3.10]` kernel/panic.c:102,139 |
| init 종료 | `"Attempted to kill init! exitcode=0x%08x\n"` (panic 메시지) | `[LX-v3.10]` kernel/exit.c:531 |
| BusyBox init | `"init started: %s"` (`%s` = `BusyBox v<버전> (<빌드 시각>)`) | `busybox-1.24.1/init/init.c:1081-1084`(`#if !ENABLE_FEATURE_EXTRA_QUIET`), 1.36.1:1122(`FEATURE_INIT_QUIET`). **두 옵션 모두 기본값 y라 기본 설정에서는 출력되지 않는다**(1.24.1 init.c:66-68, 1.36.1 init.c:80-82). 벤더 빌드는 이 옵션을 끄는 경우가 있다(실기기 로그 `[BL-foscam]`에 `init started:` 줄이 나온다) |
| askfirst 콘솔 | `"\nPlease press Enter to activate this console. "` | `busybox-1.24.1/init/init.c:492`, 1.36.1:512 |
| ash 배너 | `"\n\n%s %s\n"` + `"Enter 'help' for a list of built-in commands.\n"` + `"\n"` → `BusyBox v1.24.1 (2017-01-01 00:00:00 CST) built-in shell (ash)` | `busybox-1.24.1/shell/ash.c:8762-8770` (help 줄은 `ASH_HELP` 빌드만, `FEATURE_SH_EXTRA_QUIET`면 배너 생략) |
| 로그인 | `"<hostname>" + " login: "`, `"Password: "`, 실패 시 `"Login incorrect"` | `busybox-1.24.1/libbb/login.c:16,92-97`, `libbb/correct_password.c:123`, `loginutils/login.c:430` |
| 셸 프롬프트 | ash 기본 PS1: `FEATURE_EDITING_FANCY_PROMPT` 빌드는 `\w \$ ` (root면 `/ # `, `~ # `), 아니면 root `# `, 일반 `$ ` | `busybox-1.24.1/shell/ash.c:2072-2080` |

BusyBox 배너의 날짜 형식은 버전마다 다르다. 1.24.1 이전은 `" (" BB_BT ")"`, 1.36.1은 `" ("AUTOCONF_TIMESTAMP")"` (`libbb/messages.c`).

### 11.3 `/proc/mtd`

```
dev:    size   erasesize  name
mtd%d: %8.8llx %8.8x "%s"
```
v3.4, v3.10, 최신 모두 같다(`[LX-v3.10]` drivers/mtd/mtdcore.c:1121-1126, `[LX-master]` drivers/mtd/mtdcore.c:2574-2588). 예(합성):

```
dev:    size   erasesize  name
mtd0: 00040000 00010000 "boot"
mtd1: 00010000 00010000 "env"
mtd2: 00200000 00010000 "kernel"
mtd3: 00500000 00010000 "rootfs"
mtd4: 00a60000 00010000 "rootfs_data"
```

파서 정규식: `^mtd(\d+): ([0-9a-f]{8}) ([0-9a-f]{8}) "([^"]*)"$` (size/erasesize는 16진수). 크기를 누적하면 각 파티션의 플래시 오프셋이 나온다(파티션이 연속이라는 가정. `@offset` 지정이 있으면 `/proc/cmdline`의 `mtdparts`가 정답).

출처가 있는 파티션 이름 예:
- OpenIPC: `boot`, `env`, `kernel`, `rootfs`, `rootfs_data` (`[OIW] help-uboot.md`)
- Ingenic T31 SDK 기본 bootargs: `boot`, `kernel`, `root`, `appfs` (isvp_t31.h:340)
- HiSilicon 기반 소비자 카메라 로그 예: `boot`, `kernel`, `app`, `app_ext`, `para` (공개 부트 로그 gist, `[BL-foscam]`)

그 밖의 이름은 ODM마다 다르다.

### 11.4 `/proc/cmdline`

한 줄, `"%s\n"`로 커널이 실제로 받은 명령행을 출력한다(`[LX-v3.10]` fs/proc/cmdline.c:8). U-Boot의 `bootargs`보다 이쪽이 정답이다(§6.3).

### 11.5 `/proc/cpuinfo`

ARM v3.4 (`[LX-v3.4]` arch/arm/kernel/setup.c `c_show`):
```
Processor	: %s rev %d (%s)
BogoMIPS	: %lu.%02lu
Features	: <hwcap 목록, 공백 구분>
CPU implementer	: 0x%02x
CPU architecture: %s
CPU variant	: 0x%x
CPU part	: 0x%03x
CPU revision	: %d

Hardware	: %s
Revision	: %04x
Serial		: %08x%08x
```
ARM v3.10 이후는 첫 줄이 CPU마다 `processor\t: %d` + `model name\t: %s rev %d (%s)` 로 바뀐다(`[LX-v3.10]` arch/arm/kernel/setup.c `c_show`). v4.9의 `Serial`은 `"%s"`.

MIPS v3.10 (`[LX-v3.10]` arch/mips/kernel/proc.c `show_cpuinfo`) 필드 순서:
```
system type		: %s
machine			: %s            (있을 때만)
processor		: %ld
cpu model		: %s V%d.%d[  FPU V%d.%d]
BogoMIPS		: %u.%02u
wait instruction	: yes|no
microsecond timers	: yes|no
tlb_entries		: %d
extra interrupt vector	: yes|no
hardware watchpoint	: yes|no[, count: ...]
isa			: mips1 mips2 mips32r1 mips32r2 ...
ASEs implemented	: ...
shadow register sets	: %d
kscratch registers	: %d
core			: %d
VCED exceptions		: ...
VCEI exceptions		: ...
```
Ingenic 커널이 `system type`에 무엇을 넣는지는 (미확인).

### 11.6 리눅스 셸에서 쓰는 BusyBox 애플릿과 출력 형식

애플릿 존재 여부는 빌드마다 다르다. `busybox`를 인자 없이 실행하면 사용 가능한 목록이 `Currently defined functions:` 아래에 나온다(`busybox-1.24.1/libbb/appletlib.c:649`). 예를 들어 Ubuntu의 BusyBox 1.30.1 빌드에는 `base64`가 없다(이 문서 작성 중 확인).

| 애플릿 | 사용법 (usage 문자열) | 출력 형식 | 출처 |
|---|---|---|---|
| `dd` | `[if=FILE] [of=FILE] [bs=N] [count=N] [skip=N] [seek=N] ...` | stderr에 `%u+%u records in` / `%u+%u records out` (빌드에 따라 `%llu bytes (%sB) copied, ...` 줄 추가) | `coreutils/dd.c:56-66,141-154` |
| `hexdump -C` (`hd`) | `[-bcCdefnosvx] [FILE]...` | `"%08.8_ax  "` + 8×`"%02x "` + `"  "` + 8×`"%02x "` + `"  \|"` + 16×`"%_p"` + `"\|\n"`, 끝에 `"%08.8_Ax\n"` (최종 주소). 같은 줄이 반복되면 `*` 한 줄로 접힘 → **`-v` 필수**. 반복 단위의 마지막 회차에는 끝 공백이 붙지 않으므로 실제 줄은 주소 뒤 공백 2, 8바이트 묶음 사이 공백 2, ASCII 칼럼을 여는 세로줄 앞 공백 2다 | `util-linux/hexdump.c:98-100`(`-C` 포맷), `libbb/dump.c:296-314`(끝 공백 제거), 402-438(`*` 접기) |
| `od` | `[-aBbcDdeFfHhIiLlOovXx] [FILE]` (DESKTOP 빌드는 `-A`, `-t` 지원) | `od -A x -t x1` → `000000 27 05 19 56 ...` | `coreutils/od.c` |
| `base64` | 1.24.1: `[-d] [FILE]`, 1.36.1: `[-d] [-w COL] [FILE]` | 57바이트 → 76문자 줄 (`SRC_BUF_SIZE = 76/4*3`), 1.36.1은 `-w` 기본 76 | `coreutils/uudecode.c` |
| `uuencode` | `[-m] [FILE] STORED_FILENAME` | 헤더 `begin %o %s` / `-m`이면 `begin-base64 %o %s`. 45바이트/줄: 표준은 길이 문자 + 60문자 = **61문자**, `-m`은 **60문자**. 끝은 `` ` `` + `end` / `====` | `coreutils/uuencode.c:36-37,63-80` (BusyBox 1.30.1로 길이 확인) |
| `md5sum` | `[-c[sw]] [FILE]...` | `"%s  %s\n"` (공백 2) | `coreutils/md5_sha1_sum.c:253` |
| `tftp` | `[OPTIONS] HOST [PORT]`, `-l FILE` 로컬, `-r FILE` 원격, `-g` 받기, `-p` 보내기(`FEATURE_TFTP_PUT`), `-b SIZE` | | `networking/tftp.c:22-36` |
| `nc` | 소형: `[-iN] [-wN] [-l] [-p PORT] [-f FILE\|IPADDR PORT] [-e PROG]` / 대형: `[OPTIONS] HOST PORT  - connect` | | `networking/nc.c:57-71`, `nc_bloaty.c:63-71` |
| `ftpput` | `[OPTIONS] HOST [REMOTE_FILE] LOCAL_FILE`, `-v`, `-u USER`, `-p PASS`, `-P PORT` | | `networking/ftpgetput.c:35-50` |
| `dmesg` | `[-c] [-n LEVEL] [-s SIZE]` | `-n 1`로 콘솔 로그 레벨을 낮추면 덤프 출력에 커널 메시지가 끼어들지 않는다 | `util-linux/dmesg.c:12-19` |

`hexdump -C` 실제 출력(BusyBox 1.30.1, 이 문서 작성 중 실행):
```
00000000  27 05 19 56 f5 1b 3a 55  5a 30 1d 8e 00 1f 5d 98  |'..V..:UZ0....].|
00000010  68 69 73 69 6c 69 63 6f  6e 20 23 20 00 00 00 00  |hisilicon # ....|
00000020
```
반복 줄 접기(`-v` 없음): `00000000  00 00 ... |................|` → `*` → `00000040`.

리눅스 tty는 기본 termios(`onlcr`)로 `\n`을 `\r\n`으로 바꿔 보낸다. 파서는 `\r`을 제거한다.

### 11.7 리눅스에서 플래시 전체 읽기 순서

플래시 전체 이미지 = `/proc/mtd`에 **나열된 순서대로** 각 `/dev/mtdblockN`을 이어 붙인 것(파티션이 플래시 전체를 빈틈없이 덮는다는 가정). 셸 글롭 `/dev/mtdblock*`은 `mtdblock10`을 `mtdblock2` 앞에 정렬하므로 파티션이 10개 이상이면 이미지가 뒤섞인다(`[OIW] backup-stock-firmware.md` route A). SPI NAND는 `nanddump`로 OOB와 배드 블록을 처리해야 한다(같은 문서).

---

## 12. 범위에서 제외한 항목

과제 정의의 "연구자들이 자기 기기에서 쓰는 고전적 콘솔 기법(부트 인자 변경, 싱글 유저 등)"은 **이 레퍼런스에 단계별로 넣지 않았다**. 이 문서는 콘솔 출력을 인식하고 안전하게 자동화하고 백업하는 데 필요한 사실만 다룬다. 다음 절차는 이 문서에도 자동화 Skill 에도 싣지 않는다.

- 비밀번호로 잠긴 부트로더를 해제하거나, 부트로더·로그인 비밀번호나 중단 문자열을 추측·대입하는 절차. 도구는 이 상태를 감지만 한다(`uboot_interrupt` 의 `outcome=uboot_password`, `shell_login` 의 `uboot_password_prompt`).
- 하드웨어 조작(글리칭, 핀 단락 등)으로 부트 흐름을 바꾸는 절차.
- 바꾼 부트 인자나 env 를 플래시에 저장(`saveenv`)해 영구히 남기는 절차.

**예외: RAM 한정 `init=/bin/sh`.** 본인 소유 또는 서면 허가를 받은 기기에서 콘솔이 로그인을 요구하고 사용자가 계정을 모를 때, 프로젝트 정책은 부트 인자 변경 한 가지만 허용한다.
에이전트가 사용자에게 위험(부팅 불가 가능성, 워치독 재부팅)과 복구 방법(다음 전원 재투입으로 원상 복구)을 설명하고 **명시적 동의**를 받은 뒤, U-Boot 에서 RAM 의 `bootargs` 에만 `init=/bin/sh` 를 붙여 한 번 부팅한다.
`saveenv` 는 보내지 않고, 그렇게 얻은 셸에서는 읽기만 한다.
근거는 [안전 가이드](../safety.md) §4 규칙 7 과 `orchestrator/master-prompt.md` §1 규칙 3 이고, 절차는 이 문서가 아니라 [uart-shell-acquisition Skill](../../skills/uart-shell-acquisition/SKILL.md) 의 경로 D 에 있다.

그 밖에 판단이 필요한 상황(예: 콘솔이 로그인을 요구하는데 사용자가 계정을 모르고 위 예외에도 동의하지 않음, 부트로더가 비밀번호를 요구함)에서 Skill은 다음만 한다.

1. 현재 상태를 감지해 기록한다(§11.2의 `login: `, `Password: ` 감지).
2. 자동 시도를 멈추고, 운영자에게 상황과 소유권/허가 확인을 요청한다.
3. 비파괴적인 대안 경로(§13.3 외부 SPI 프로그래머로 플래시 읽기, 벤더 공식 펌웨어 이미지 분석)를 제안한다.

---

## 13. 덤프 처리량과 대안 경로

### 13.1 UART 덤프 처리량 계산

8N1 UART는 문자당 10비트이므로 115200 baud = 초당 11,520문자. 16바이트를 표현하는 데 필요한 문자 수(줄끝 `\r\n` 포함):

| 형식 | 한 줄 문자 수 | 문자/바이트 |
|---|---|---|
| `md.b`, 공백 4 (≤ 2021.07, 모든 카메라 포크) | 9 + 16×3 + 4 + 16 + 2 = **79** | 4.94 |
| `md.b`, 공백 2 (≥ 2021.10) | 77 | 4.81 |
| `md.w`, 공백 4 | 9 + 8×5 + 4 + 16 + 2 = 71 | 4.44 |
| `md.l`, 공백 4 | 9 + 4×9 + 4 + 16 + 2 = **67** | 4.19 |
| `hexdump -C` (리눅스, `\r\n`) | 80 | 5.00 |
| `base64` (57바이트당 76문자 + `\r\n`) | — | 1.37 |
| `uuencode` (45바이트당 61문자 + `\r\n`) | — | 1.40 |

| baud | 8 MiB `md.b` | 16 MiB `md.b` | 16 MiB `md.l` | 16 MiB `base64` |
|---|---|---|---|---|
| 115200 | 약 1.0시간 (3,595 s) | **약 2.0시간** (7,191 s) | 약 1.7시간 (6,098 s) | 약 33분 (1,993 s) |
| 57600 | 약 2.0시간 | 약 4.0시간 | 약 3.4시간 | 약 1.1시간 |
| 38400 | 약 3.0시간 | 약 6.0시간 | 약 5.1시간 | 약 1.7시간 |

- 이론값이며 실제로는 회선이 거의 쉬지 않는다(U-Boot는 폴링 방식으로 연속 출력). 외부 보고와도 맞는다: 115200에서 16 MB에 "just over 2 hours"(cybergibbons, 줄당 80문자로 계산), `md.b` 로그는 8 MB 칩에서 약 40 MB(`[OIW] help-uboot.md`; 계산값 8 MiB × 4.94 = 41.4 MB).
- 115200을 넘는 U-Boot 콘솔 속도는 대부분의 카메라 빌드에서 불가능하다(§6.2 baudrate 표).
- `base64`/`uuencode`는 리눅스 셸이 있을 때만 쓸 수 있고, 약 3.6배 빠르다. 0xFF 패딩이 많은 영역은 `gzip -c`로 먼저 압축하면 더 빨라진다(애플릿이 있을 때).

### 13.2 청크·재개·검증 프로토콜 (권장)

몇 시간짜리 단일 스트림은 바이트 하나만 깨져도 전체가 무의미해진다. 다음을 권장한다.

1. `sf probe 0` → `sf read <RAM> 0 <flash_size>`로 플래시 전체를 RAM에 한 번 올린다(수 초). RAM 주소는 SoC DRAM 시작에 맞춰야 한다. OpenIPC는 DRAM이 `0x80000000`인 SoC(Hi3516CV200/CV300, Hi3518EV200/EV201)에 `0x80600000`, `0x40000000`인 SoC(Hi3516EV200/EV300, Hi3518EV300, GK720x)에 `0x40600000`을 쓴다. 틀리면 `data abort`와 리셋이 난다(`[OIW] help-uboot.md`). 읽기 전에 `mw.b <RAM> 0xff <size>`로 채워 두면 `sf read`가 덜 읽었을 때 구분할 수 있다(`[OIW] backup-stock-firmware.md` route C).
2. 청크 크기 64 KiB(= `md.b` 115200에서 약 28초)를 기본으로 한다. 청크마다 `md.b <addr> 10000` → `crc32 <addr> 10000`을 실행하고 호스트에서 `zlib.crc32`로 대조한다.
3. 불일치하거나 주소 연속성 검사(§3.5)가 실패하면 그 청크만 다시 요청한다. 진행 상태(완료 청크 목록, 각 CRC)를 파일에 기록해 연결이 끊겨도 이어서 받는다.
4. 끝나면 전체 이미지에 대해 `crc32 <RAM> <flash_size>`와 호스트 CRC를 한 번 더 대조한다.
5. 검증 3종(`[OIW] backup-stock-firmware.md` "Check the dump"): 크기가 칩 크기와 정확히 같은지(8388608 / 16777216), 압축해도 너무 작아지지 않는지(전부 0xFF가 아닌지), `strings fulldump.bin | grep ^ethaddr`로 env가 들어 있는지.
6. 덤프에는 루트 비밀번호 해시, Wi-Fi 자격 증명, 클라우드 키, MAC/시리얼이 들어 있다. 공개 저장소에 올리지 않도록 case-mcp 보고서에 명시한다(같은 문서 "A dump is a credential store").

### 13.3 더 빠른 대안 경로

| 경로 | 명령 예 | 전제 조건 | 주의 |
|---|---|---|---|
| U-Boot `tftpput` | `setenv ipaddr ...; setenv serverip ...` → `sf read` → `tftpput <RAM> <size> backup.bin` | 이더넷 + PHY 드라이버, `CONFIG_CMD_TFTPPUT`, 호스트 TFTP 서버가 쓰기 허용 | HiSilicon은 통합 `tftp`의 3인자 형태가 업로드(§5.5). `setenv`만 쓰고 `saveenv`는 하지 않는다 |
| SD 카드 원시 블록 | `mmc dev 0` → `mmc erase 0x10 0x8000` → `sf read` → `mmc write <RAM> 0x10 0x8000` (16 MB) → PC에서 `dd bs=512 skip=16 count=32768` | SD 슬롯 + `mmc` 명령. 블록 512바이트. 위 문법은 2013.07 이후용이다. 2010.06(HiSilicon V1~V3)은 `mmc write <dev> <RAM> 0x10 0x8000` 형식이고 `mmc dev`·`mmc erase`가 없다(§5.4) | 카드 내용이 지워진다. erase/write/dd의 블록 수를 반드시 일치시킨다(`[OIW] help-uboot.md`, `backup-stock-firmware.md` route D). 2010.06·2013.07의 `mmc`는 하위 명령 반복 검사가 없으므로 `mmc write`/`mmc erase` 뒤에 빈 줄을 보내면 다시 실행된다(R2) |
| `fatwrite` | `fatwrite mmc 0:1 <RAM> backup.bin <size>` | `CONFIG_FAT_WRITE` 빌드 | 카메라 빌드에는 없는 경우가 많음 |
| 리눅스 셸 + 네트워크 | 파티션별 `cat /dev/mtdblockN` 또는 `dd`를 `nc`/`tftp -p`/`ftpput`/NFS로 전송 | 이미 셸이 있음, 해당 애플릿 존재 | `/proc/mtd` 순서로 이어 붙이기(§11.7). NFS 마운트 실패 시 카메라 내부에 써 버리는 실수에 대비해 마운트 확인 후 저장(`[OIW] backup-stock-firmware.md` route A) |
| 리눅스 셸 + 시리얼 | `dmesg -n 1` 후 `base64` / `uuencode -m` / `hexdump -C -v` | 셸, 애플릿 | §13.1 처리량. `md5sum`으로 검증 |
| 외부 SPI 프로그래머 (SOIC-8 클립 + CH341A 등) | `flashrom -p ch341a_spi -r dump.bin` (두 번 읽어 해시 비교) | 기기 **전원 차단**, 칩 전압 확인(3.3 V/1.8 V), 프로그래머가 칩을 지원 | 보드에 전원이 들어간 채 클립하면 SoC가 버스를 잡아 읽기가 실패하거나 손상될 수 있다(일반적인 하드웨어 주의 사항이며 위키 route F에는 없는 내용). CH341A의 신호 전압 문제는 OpenIPC 위키의 "CH341A programmer voltage fix" 문서 참고. SPI NAND는 지원하지 않는 도구가 많다(`[OIW] backup-stock-firmware.md` route F) |

---

## 14. 합성 콘솔 트랜스크립트

> **모두 (합성)이다.** 공개 문서·로그(아래 "모델")의 **구조를 본떠** 이 문서에서 새로 만들었다. 각 줄의 **포맷은 표에 적은 소스로 검증**했고, 날짜·주소·크기·호스트 이름 등 값은 지어낸 것이다. 원본 로그를 옮겨 붙이지 않았다. `\b`는 0x08, `↵`는 운영자/드라이버 입력이다.

### 14.1 HiSilicon 계열 (Hi3518EV200, ARM926, U-Boot 2010.06, SPI NOR 16 MiB, Linux 3.4)

모델: 공개 Hi3518EV200 부트 로그(`[BL-foscam]`)의 줄 순서, `[OIW] installation.md`의 Step 5 발췌, `[OI-hi3516cv200]` 소스.

```text


System startup


U-Boot 2010.06 (Mar 05 2018 - 10:12:41)

Check Flash Memory Controller v100 ... Found
SPI Nor(cs 0) ID: 0xc2 0x20 0x18
Block:64KB Chip:16MB Name:"MX25L128XX"
SPI Nor total size: 16MB
In:    serial
Out:   serial
Err:   serial
Hit any key to stop autoboot:  1 \b\b\b 0 
16384 KiB hi_fmc at 0:0 is now current device

## Booting kernel from Legacy Image at 82000000 ...
   Image Name:   Linux-3.4.35
   Image Type:   ARM Linux Kernel Image (uncompressed)
   Data Size:    2949120 Bytes = 2.8 MiB
   Load Address: 80008000
   Entry Point:  80008000
   Loading Kernel Image ... OK
OK

Starting kernel ...

Uncompressing Linux... done, booting the kernel.
Booting Linux on physical CPU 0
Linux version 3.4.35 (builder@buildhost) (gcc version 4.8.3 (Hisilicon_v300) ) #1 Mon Mar 5 10:20:11 CST 2018
CPU: ARM926EJ-S [41069265] revision 5 (ARMv5TEJ), cr=00053177
Machine: hi3518ev200
Kernel command line: mem=40M console=ttyAMA0,115200 root=/dev/mtdblock3 rootfstype=squashfs mtdparts=hi_sfc:512k(boot),256k(env),3072k(kernel),8192k(rootfs),-(app)
...
5 cmdlinepart partitions found on MTD device hi_sfc
Creating 5 MTD partitions on "hi_sfc":
0x000000000000-0x000000080000 : "boot"
0x000000080000-0x0000000c0000 : "env"
0x0000000c0000-0x0000003c0000 : "kernel"
0x0000003c0000-0x000000bc0000 : "rootfs"
0x000000bc0000-0x000001000000 : "app"
...
VFS: Mounted root (squashfs filesystem) readonly on device 31:3.
Freeing init memory: 160K
init started: BusyBox v1.24.1 (2018-03-05 10:05:33 CST)
...

Please press Enter to activate this console. 
```

| 줄 | 포맷 출처 |
|---|---|
| `System startup` | `[OI-hi3516cv200]` arch/arm/cpu/hi3518ev200/start.S:363 (`"\r\n\r\nSystem startup\r\n"`) |
| `U-Boot 2010.06 (... - ...)` | 2010.06 `version_string` = `U_BOOT_VERSION" (" U_BOOT_DATE " - " U_BOOT_TIME ")"CONFIG_IDENT_STRING`, `printf("\n\n%s\n\n", version_string)` (`[UB-2010.06]` arch/arm/lib/board.c:77-78,138). 날짜는 `%b %d %Y`. `U_BOOT_VERSION`에 `-svn` 같은 접미사가 붙거나(위키 발췌 `U-Boot 2010.06-svn (Oct 21 2016 - 11:21:29)`) `)` 뒤에 `CONFIG_IDENT_STRING`이 붙을 수 있다 |
| FMC v100 4줄 | §1.2 (hifmc_common.c:41-48, hifmc_spi_nor_ids.c:2739-2797, hifmc100_os.c:224) |
| `In:    serial` 3줄 | `[UB-2010.06]` common/console.c:539-553 |
| autoboot | §8.1 (bootdelay 1, 무입력. 화면에는 `Hit any key to stop autoboot:  0`) |
| `16384 KiB hi_fmc at 0:0 ...` 및 다음 빈 줄 | `bootcmd`의 `sf probe 0`(cmd_sf.c:69)와 `sf read`의 성공 출력 `\n`(§5.2) |
| `## Booting kernel ...` ~ `OK` 2줄 | §11.1 |
| `Starting kernel ...` | `[UB-2010.06]` arch/arm/lib/bootm.c:106 |
| 커널 줄 | §11.2 (v3.4 포맷) |
| MTD 줄 | `bootargs`의 `mtdparts`에서 계산한 오프셋 (512k=0x80000, 256k=0x40000 ...). 합성 레이아웃은 SDK env 위치(0x80000, 0x40000)와 일치하게 설계 |
| `Freeing init memory: 160K` | ARM v3.4 포맷 |
| `Please press Enter ...` | BusyBox askfirst (§11.2) |

### 14.2 Ingenic 계열 (T31, MIPS32 리틀엔디안, U-Boot SPL + 2013.07, SPI NOR 16 MiB, Linux 3.10)

모델: `[OIW] installation.md` Step 5의 Ingenic 발췌(`U-Boot 2013.07 (...)` / `DRAM:  64 MiB` / `MMC:   msc: 0` / `SF: Detected EN25QH64`), `[OI-ingenic]`·`[OI-t40]` 소스, 벤더 `isvp_t31.h` 기본값.

```text



U-Boot SPL 2013.07 (Jul 10 2020 - 14:22:05)
...


U-Boot 2013.07 (Jul 10 2020 - 14:22:05)

Board: ISVP (Ingenic XBurst T31 SoC)
DRAM:  64 MiB
Top of RAM usable for U-Boot at: 84000000
Reserving 446k for U-Boot at: 83f90000
Reserving 32784k for malloc() at: 81f8c000
Reserving 32 Bytes for Board Info at: 81f8bfe0
Reserving 124 Bytes for Global Data at: 81f8bf64
Reserving 128k for boot params() at: 81f6bf64
Stack Pointer at: 81f6bf48
Now running in RAM - U-Boot at: 83f90000
MMC:   msc: 0
SF: Detected GD25Q127C
In:    serial
Out:   serial
Err:   serial
Net:   ...
Hit any key to stop autoboot:  1 \b\b\b 0 
SF: Detected GD25Q127C
SF: 2621440 bytes @ 0x40000 Read: OK
## Booting kernel from Legacy Image at 80600000 ...
   Image Name:   Linux-3.10.14
   Image Type:   MIPS Linux Kernel Image (lzma compressed)
   Data Size:    1946048 Bytes = 1.9 MiB
   Load Address: 80010000
   Entry Point:  80400330
   Verifying Checksum ... OK
   Uncompressing Kernel Image ... OK

Starting kernel ...

Linux version 3.10.14 (builder@buildhost) (gcc version 4.7.2 (Ingenic r2.3.3 2016.12) ) #1 PREEMPT Fri Jul 10 14:30:51 CST 2020
...
Kernel command line: console=ttyS1,115200n8 mem=42M@0x0 rmem=22M@0x2a00000 init=/linuxrc rootfstype=squashfs root=/dev/mtdblock2 rw mtdparts=jz_sfc:256k(boot),2560k(kernel),2048k(root),-(appfs)
...
4 cmdlinepart partitions found on MTD device jz_sfc
Creating 4 MTD partitions on "jz_sfc":
0x000000000000-0x000000040000 : "boot"
0x000000040000-0x0000002c0000 : "kernel"
0x0000002c0000-0x0000004c0000 : "root"
0x0000004c0000-0x000001000000 : "appfs"
...
VFS: Mounted root (squashfs filesystem) readonly on device 31:2.
Freeing unused kernel memory: 228K (80510000 - 80549000)
init started: BusyBox v1.22.1 (2020-07-10 14:01:12 CST)
...
camera login: 
```

| 줄 | 포맷 출처 |
|---|---|
| `U-Boot SPL 2013.07 (...)` | `puts("\n\n\nU-Boot SPL " PLAIN_VERSION " (" U_BOOT_DATE " - " U_BOOT_TIME ")\n")` (`[OI-t40]` common/spl/spl.c:282-283) |
| `U-Boot 2013.07 (...)` | `[OI-ingenic]` arch/mips/lib/board.c:86. (T40 SDK 트리는 이 줄이 주석 처리되어 출력되지 않음: `[OI-t40]` arch/mips/lib/board.c:85) |
| `Board: ISVP (...)` | `[OI-t40]` board/ingenic/isvp_t31/board.c:112 |
| `DRAM:  64 MiB` | `puts("DRAM:  ")` + `print_size` (arch/mips/lib/board.c:72) |
| `Top of RAM...` ~ `Now running in RAM...` | `[OI-ingenic]` arch/mips/lib/board.c:182-275 (T40 SDK는 `CONFIG_FAST_BOOT`면 생략). 주소 값은 합성 |
| `MMC:   msc: 0` | `puts("MMC:   ")` (board.c:331) + 장치 이름 (OpenIPC 위키 발췌와 일치) |
| `SF: Detected %s` | `[OI-ingenic]` drivers/mtd/spi/spi_flash.c:610 (T40 SDK 트리라면 `SF: Detected GD25Q127C, manufacturer id: c8` + 빈 줄) |
| autoboot | §8.1, bootdelay 1 (isvp_t31.h:348) |
| `bootcmd` 출력 | `sf probe;sf read 0x80600000 0x40000 0x280000; bootm 0x80600000` (isvp_t31.h:355) → `SF: %zu bytes @ %#x %s: %s` (0x280000 = 2621440) |
| bootm 블록 | `[UB-2013.07]` common/cmd_bootm.c:402,868-874, image.c:305-315. lzma 압축 → `Uncompressing` |
| `Starting kernel ...` | `[UB-2013.07]` arch/mips/lib/bootm.c:99 |
| 커널 명령행 | 벤더 `BOOTARGS_COMMON` + SFC NOR `CONFIG_BOOTARGS` (isvp_t31.h:321,340) |
| `Freeing unused kernel memory: ...` | v3.10 포맷 (`%lx`, 0x 없음) |
| `camera login: ` | BusyBox `<hostname>` + ` login: ` (호스트 이름 합성) |

MTD 오프셋 검산: boot 256k=0x40000, kernel 2560k=0x280000 → 0x2c0000, root 2048k=0x200000 → 0x4c0000, appfs = 16 MiB − 0x4c0000. env(0x3C000~0x3FFFF, §7.3)는 `boot` 파티션 안쪽 끝이다.

### 14.3 HiSilicon 계열 대화형 세션 (중단 → 동기화 → env → 읽기 → 검증)

§14.1과 같은 기기. 드라이버 입력은 `↵`(실제 송신은 `\r` 한 바이트)와 `<03>`(Ctrl-C)로 표시했다. 0x03은 에코되지 않고 프롬프트에 줄바꿈이 없으므로 `<INTERRUPT>`는 프롬프트와 **같은 줄**에 붙는다.

```text
Hit any key to stop autoboot:  1 \b\b\b 0 
hisilicon # <03><INTERRUPT>
hisilicon # printenv↵
bootargs=mem=40M console=ttyAMA0,115200 root=/dev/mtdblock3 rootfstype=squashfs mtdparts=hi_sfc:512k(boot),256k(env),3072k(kernel),8192k(rootfs),-(app)
bootcmd=sf probe 0;sf read 0x82000000 0xc0000 0x300000;bootm 0x82000000
bootdelay=1
baudrate=115200
ethaddr=00:00:23:34:45:66
ipaddr=192.168.1.10
serverip=192.168.1.2
netmask=255.255.255.0
bootfile="uImage"
stdin=serial
stdout=serial
stderr=serial
ver=U-Boot 2010.06 (Mar 05 2018 - 10:12:41)

Environment size: 444/262140 bytes
hisilicon # sf probe 0↵
16384 KiB hi_fmc at 0:0 is now current device
hisilicon # sf read 0x82000000 0xc0000 0x40↵

hisilicon # md.b 0x82000000 0x40↵
82000000: 27 05 19 56 f1 a4 be 79 5a 9c a9 5b 00 2d 00 00    '..V...yZ..[.-..
82000010: 80 00 80 00 80 00 80 00 5a 3c 1e 2d 05 02 02 00    ........Z<.-....
82000020: 4c 69 6e 75 78 2d 33 2e 34 2e 33 35 00 00 00 00    Linux-3.4.35....
82000030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
hisilicon # md.l 0x82000000 4↵
82000000: 56190527 79bea4f1 5ba99c5a 00002d00    '..V...yZ..[.-..
hisilicon # crc32 0x82000000 0x40↵
CRC32 for 82000000 ... 8200003f ==> 298dbed3
hisilicon # 
```

검증 메모:
- 첫 키 없이 카운트다운이 끝나기 직전에 0x03이 들어간 경우를 그렸다. 이때 프롬프트에 남는 입력이 없으므로 다음 0x03은 `<INTERRUPT>`만 낸다(§10).
- 2010.06 포크이므로 `printenv`는 저장 순서이고(`setenv`로 바뀐 런타임 변수 `stdin/stdout/stderr/ver`가 뒤에 옴), `444` = Σ(항목 길이 + 1), `262140` = 0x40000 − 4 (§6.1). `ver`는 `CONFIG_VERSION_VARIABLE`(hi3518ev200.h:208)이 만든다.
- `sf read` 성공 출력은 빈 줄 하나(§5.2).
- `md.b`의 64바이트는 **유효한 legacy uImage 헤더**(magic `0x27051956`, 헤더 CRC `0xf1a4be79`는 실제 계산값, 이름 `Linux-3.4.35`)로 만들었다. `md.l` 줄은 같은 16바이트의 리틀엔디안 워드 표시이고 ASCII 칼럼은 바이트 순서 그대로다(§3.4).
- `298dbed3`은 위 64바이트의 실제 zlib CRC-32다. 2010.06이므로 대문자 `CRC32 for` 형식, 끝 주소는 포함 범위(`8200003f`)다.
- 포맷은 2010.06 `print_buffer`(공백 4, 짧은 줄 패딩 없음)를 따른다.

---

## 15. 구현 체크리스트

### 15.1 정규식 카탈로그 (`uart-mcp` 상태 감지)

정규식에 `|`가 많아 Markdown 표에 넣으면 셀 구분자로 해석되므로(GFM 표에서는 코드 스팬 안의 `|`도 셀을 나눈다) 아래 코드 블록을 원본으로 삼는다. 모두 Python `re` 문법이고 원시 수신 문자열(백스페이스·`\r` 포함)을 대상으로 한다. 이 블록은 그대로 실행해 컴파일할 수 있다.

```python
import re

UBOOT_PATTERNS = {
    # U-Boot 배너. U_BOOT_VERSION 접미사(예: 2010.06-svn)와 타임존 표기를 허용한다
    "uboot_banner": r'U-Boot (?:SPL )?(\d{4}\.\d{2}[^\s(]*) \(([A-Z][a-z]{2} [ \d]\d \d{4}) - (\d{2}:\d{2}:\d{2})(?: [+-]\d{4})?\)',
    # autoboot (표준). 고전 형식, v2025.10 형식, v2026.04 형식(§8.1, §8.2)에 모두 맞는다
    "autoboot_std": r'Hit any key to stop autoboot:\s*(\d+)',
    "autoboot_rockchip": r"Hit key to stop autoboot\('CTRL\+C'\):\s*(\d+)",
    # OpenIPC: HiSilicon V4/Goke는 stop, Ingenic T40 트리는 abort
    "autoboot_openipc_ctrlc": r'Press Ctrl-c to (?:stop|abort) autoboot\.\.\. (\d+)',
    "autoboot_openipc_enter": r'Press ENTER to interrupt boot in (\d+)\.\.\.',
    # 카운트다운 갱신. 고전 형식 전용. v2025.10~ 메인라인은 \r로 줄을 다시 쓰므로 autoboot_std를 반복 적용한다
    "countdown_update": r'\x08{3}\s?(\d+) ?',
    # 프롬프트(알려진 목록). 수신 버퍼 끝에서만 판정한다
    "prompt_known": r'(?:^|\n)(hisilicon # |goke # |isvp(?:_t\d+)?# |SigmaStar # |MStar # |nvt@na\d+: |GM # |A320 # |xmedia # |OpenIPC # |U-Boot> |=> |amboot>)$',
    # hush 보조 프롬프트(PS2): 기본 "> ", OpenIPC HiSilicon/Goke " > ". 보이면 Ctrl-C로 빠져나온다(R11)
    "prompt_hush_ps2": r'(?:^|\n) ?> $',
    "ctrlc_reply": r'<INTERRUPT>\r?\n',
    "err_unknown_cmd": r"Unknown command '([^']+)' - try 'help'",
    "err_too_many_args": r'\*\* Too many args \(max\. (\d+)\) \*\*',
    "err_not_defined": r'## Error: "([^"]+)" not defined',
    "env_bad_crc": r'\*\*\* Warning - bad CRC, using default environment',
    # HiSilicon 2010.06 포크의 자동 env 기록: 플래시가 바뀌었다는 증거(R10)
    "env_auto_write": r'\*\*\* Write default environment to flash',
    # saveenv 시작(모든 버전 공통 접두사). autoboot 중에 보이면 우리 명령 없이 플래시가 바뀐 것이다(R10)
    "env_save_start": r'Saving Environment to ([^.]+)\.\.\.',
    # OpenIPC Goke 빌드의 fwrecovery: kernel/rootfs를 다시 쓴다(R10)
    "openipc_recovery": r'\*\*\* RECOVERY: kernel/rootfs invalid, reflashing -- do not power off \*\*\*',
    # OpenIPC Goke 빌드의 bootcount 한도 초과(altbootcmd)
    "openipc_failsafe": r'\*\*\* Boot limit exceeded -- entering FAILSAFE \(network \+ SSH only\) \*\*\*',
    # T40 트리의 "SF: Detected %s, manufacturer id: %02x"에서 쉼표를 빼고 이름만 잡는다
    "sf_detected": r'SF: Detected ([^\s,]+)',
    "sf_probe_2010": r'(\d+) KiB (\S+) at (\d+):(\d+) is now current device',
    "hisi_flash_geom": r'Block:(\d+[KMG]?)B Chip:(\d+[KMG]?)B Name:"([^"]+)"',
    "hisi_flash_total": r'SPI Nor total size: (\d+)MB',
    "sf_result": r'SF: (\d+) bytes @ (0x[0-9a-f]+) (Read|Written|Erased): (OK|ERROR(?: -?\d+)?)',
    "crc32": r'(?i)crc32 for ([0-9a-f]{8,16}) \.\.\. ([0-9a-f]{8,16}) ==> ([0-9a-f]{8})',
    "printenv_end": r'Environment size: (\d+)/(\d+) bytes',
    "kernel_start": r'Starting kernel \.\.\.',
    "kernel_cmdline": r'Kernel command line: (.*)',
    "root_mounted": r'VFS: Mounted root \((\S+) filesystem\)( readonly)? on device (\d+):(\d+)\.',
    "kernel_panic": r'Kernel panic - not syncing: (.*)',
    "busybox_askfirst": r'Please press Enter to activate this console\.',
    "login_prompt": r'(\S+) login: $',
    "password_prompt": r'Password: $',
    "login_incorrect": r'Login incorrect',
    # 셸 프롬프트(기본). PS1은 기기마다 다르므로 첫 프롬프트를 학습해 고정한다
    "shell_prompt_generic": r'(?:^|\n)(?:[^\n]*[#$] )$',
}

COMPILED = {k: re.compile(v) for k, v in UBOOT_PATTERNS.items()}
```

### 15.2 mock-device 시뮬레이터 필수 동작

1. 출력 `\n` → `\r\n`, 입력 에코, Enter 에코는 편집 readline 프로파일 `\r\n` / 편집 없는 readline 프로파일 `\r\r\n`(§2.1).
2. `\r`과 `\n` 각각 Enter. 빈 줄은 직전 명령 반복(rep 표 §2.4). `nand`는 2013.01 이후 프로파일에서 `dump`만, 2010.06 프로파일은 전부 반복. `mmc`는 2016.11 이후 프로파일에서 하위 명령별, 2010.06·2013.07 프로파일은 전부 반복.
3. Ctrl-C: 에코 없이 `<INTERRUPT>` + 프롬프트. simple 모드는 `lastcommand` 유지, hush 모드는 지움.
4. 실행 중 입력: 0x03이면 중단, 그 외 바이트는 폐기(`ctrlc()` 모델).
5. CBSIZE 초과 시 BEL, MAXARGS 초과 시 `** Too many args (max. N) **`.
6. `md` 상태 변수 3개(`dp_last_addr/size/length`)와 반복 시 이어서 출력. `print_buffer` 프로파일 3종(2010.06 / 2013~2021.07 / 2021.10~).
7. `printenv` 정렬 여부와 크기 공식(§6.1) 프로파일.
8. `crc32` 대/소문자 프로파일, zlib CRC.
9. `sf` 출력 프로파일(2010.06 HiSilicon 빈 줄 / 2013 단일 줄 / 2016+ `OK` 분리 / HiSilicon V4 빈 줄 + 줄).
10. autoboot 바이트열(§8.1 표 4가지 경우, §8.2의 v2025.10·v2026.04 형식)과 keyed 모드(suffix 매칭, 메시지 없음, bootdelay 0 → 두 번 확인).
11. env 바이너리(§7)를 플래시 이미지에 넣어 `printenv`와 `fwtriage`가 같은 값을 보는지 교차 검증.
12. HiSilicon 2010.06 프로파일: env 영역의 CRC 워드가 `0xFFFFFFFF`이면 부팅 시 `*** Warning - bad CRC, using default environment` 뒤에 `*** Write default environment to flash`와 자동 `saveenv` 출력(§6.2)을 내고, 시뮬레이터의 플래시 이미지도 실제로 갱신한다.
13. `echo` 유무 프로파일(R6): `echo`가 없으면 `Unknown command 'echo' - try 'help'`.

---

## 16. 미확인 항목

| 항목 | 상태 |
|---|---|
| Fullhan SoC의 U-Boot 프롬프트·autoboot 설정 | 1차 출처 없음 (미확인) |
| Anyka SoC의 U-Boot 프롬프트 | 1차 출처 없음 (미확인). 커널 콘솔 `ttySAK0`는 포럼 로그(2차) |
| Ambarella AMBoot의 autoboot 메시지 형식 | (미확인). 프롬프트 `amboot>`와 배너 `Amboot(R) Ambarella(R) Copyright (C) 2004-2007`, Dropcam(A5s)에서 전원 투입 직후 줄바꿈을 연속 송신해 진입한 사례만 Include Security 글(2차 출처)로 확인 |
| Xiongmai 벤더(비-OpenIPC) U-Boot의 프롬프트·중단 키 | (미확인) |
| Ingenic 커널의 `/proc/cpuinfo` `system type` 값 | (미확인) |
| SigmaStar Infinity6E의 정확한 env offset (빌드 옵션 `CONFIG_MSTAR_ENV_NOR_OFFSET` 의존) | 부분 확인: 파티션 테이블에서 읽는 런타임 값 `ms_nor_env_offset`, 아니면 `0x5F000`(infinity6e.h:173-182). 실기기 값은 미확인 |
| Ingenic T31 `CONFIG_ENV_OFFSET` 0x3C000 | (유도) — 매크로 계산값 |
| Goke·Ingenic·SigmaStar·MStar·Novatek·Grain Media·XMedia SDK 프롬프트의 실기기 출력 | 설정 소스로만 확인. 공개 실기기 로그로는 미확인 |
| ~~구버전 `mmc` 하위 명령별 반복 정책~~ | **확인함**: 2010.06·2013.07은 하위 명령 검사 없음(전부 반복), 2016.11 이후 하위 명령별 플래그(§2.4) |
| ~~메인라인 `print_buffer` 짧은 줄 패딩 도입 릴리스~~ | **확인함**: 커밋 efd7c11404e5는 v2013.04에 포함(GitHub compare) |
| ODM 고유 부트로더 중단 키 | 소스로 확인할 수 없어 수록하지 않음 |

---

## 17. 참고 자료

### 소스 저장소 (고정 버전)

| 약칭 | 위치 |
|---|---|
| `[UB-master]` | https://github.com/u-boot/u-boot/tree/8d534cec0cc0109a37c0ded8854da03f1526dc0e (2026-10-16, v2026.10 이후 master) |
| `[UB-2010.06]` | https://github.com/u-boot/u-boot/tree/v2010.06 (https://ftp.denx.de/pub/u-boot/u-boot-2010.06.tar.bz2) |
| `[UB-2013.07]` | https://github.com/u-boot/u-boot/tree/v2013.07 |
| `[UB-2016.11]` | https://github.com/u-boot/u-boot/tree/v2016.11 |
| `[UB-2019.04]` | https://github.com/u-boot/u-boot/tree/v2019.04 |
| `[OI-hi3516cv200]` | https://github.com/OpenIPC/u-boot-hi3516cv200/tree/f769967e4dd56e727ee948e6102ac7544d722460 |
| `[OI-hi3516ev200]` | https://github.com/OpenIPC/u-boot-hi3516ev200/tree/7d5ec8186e3b7ac593db82ec7fd043b16ed3d046 |
| `[OI-gk7205v200]` | https://github.com/OpenIPC/u-boot-gk7205v200/tree/ff09a0946b9e7009c4392ef4e7d274c0339dc2ba |
| `[OI-ingenic]` | https://github.com/OpenIPC/u-boot-ingenic/tree/6a308091ef41fd0ba06ba0c668fe406a19210eef |
| `[OI-t40]` | https://github.com/OpenIPC/u-boot-t40/tree/85ed813cf75fc829182ad33eacfed2209853b20d (Ingenic SDK 트리, isvp_t31 포함) |
| `[OI-sigmastar]` | https://github.com/OpenIPC/u-boot-sigmastar/tree/bf77aff5d44f34d14b89b3f4014aa8dda9834794 |
| `[OI-msc313e]` | https://github.com/OpenIPC/u-boot-msc313e/tree/77361dfcb5abe9757a285273ddb40d5e447c2177 |
| `[OI-nt9856x]` | https://github.com/OpenIPC/u-boot-nt9856x/tree/9b509846bc8b5e5452bd988e90d63addb662db57 |
| `[OI-grainmedia]` | https://github.com/OpenIPC/u-boot-grainmedia/tree/2aa87f868659c7095c633a3e2750435941a851e4 |
| `[OI-xmedia]` | https://github.com/OpenIPC/u-boot-xmedia/tree/bfbba0e5aa8b6d06f1c2d20b50a671152317a498 |
| `[RK]` | https://github.com/rockchip-linux/u-boot/tree/1c535d65b8509f388d09e49fb6961f49fda35a1d (`next-dev`, Makefile 기준 U-Boot 2017.09 베이스) |
| (보조) | OpenIPC `u-boot-hi3516cv300`(a2e47fced511), `u-boot-hi3519v101`(0f36fcf3ea5a): FMC v100·env 위치 확인용. GitHub `u-boot/u-boot` 태그 v2010.09·v2010.12(common/cmd_nvedit.c), v2016.05·v2016.07·v2025.10·v2026.04(common/autoboot.c): 버전 경계 확인용 |
| `[LX-v3.4]`, `[LX-v3.10]`, `[LX-v3.18]`, `[LX-v4.9]`, `[LX-master]` | https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git (태그 v3.4, v3.10, v3.18, v4.9, master) |
| BusyBox | https://busybox.net/downloads/busybox-1.20.2.tar.bz2, busybox-1.24.1.tar.bz2, busybox-1.36.1.tar.bz2 |

### 메인라인 커밋 (포맷 변경 시점)

릴리스 포함 여부는 GitHub compare API(`<commit>...<tag>`의 status)로 확인했다.

- efd7c11404e5 "display_options:print_buffer: align ASCII print" (2013-03-11 머지, v2013.04에 포함)
- c7b16d830e72 "display_options: Drop two spaces before the ASCII column" (2021-06-08 머지, v2021.07에는 없고 v2021.10에 포함)
- 2fbb8462b0e1 "autoboot: remove CONFIG_ZERO_BOOTDELAY_CHECK" (2016-07-01 머지, v2016.07에 포함)
- 5f70be08b015 "Fix autoboot countdown printing wrong" (2025-07-14 머지, v2025.10에 포함), af38567cadca "autoboot: Fix inconsistent countdown output" (2025-10-27 작성, 2025-12-05 머지, v2026.01에는 없고 v2026.04에 포함)
- f1b20acb4a03 "hashtable: Fix length calculation in hexport_r" (2018-07-24 머지, v2018.09에 포함), 4bca32497c09 "hashtable: fix length calculation in hexport_r" (2018-12-15 머지, f1b20acb4a03의 `size = totlen` 변경을 `totlen + 1`로 되돌림, v2019.01에 포함)

### 문서·로그

- `[OIW]` OpenIPC wiki, https://github.com/OpenIPC/wiki/tree/3c58d3d3de465c59bcefbd7082613b4b50c7c333/en — `help-uboot.md`, `backup-stock-firmware.md`, `installation.md`, `install-hisi.md`, `install-goke.md`, `install-sigmastar.md`, `install-xm510.md`, `install-xm530.md`, `failsafe-recovery.md`
- U-Boot 문서: https://docs.u-boot.org/en/latest/usage/cmd/md.html, https://docs.u-boot.org/en/latest/usage/environment.html, https://docs.u-boot.org/en/latest/usage/cmd/tftpput.html (저장소의 doc/usage/ 아래 원문을 위 커밋 기준으로 인용)
- `[BL-foscam]` Hi3518EV200(Foscam C1) 공개 부트 로그: https://gist.github.com/astroza/f7fac5841bf336982f2184cfcd0dfb6e (구조 참고용, 본문에 옮기지 않음)
- Include Security, "Reversing the Dropcam Part 2": https://blog.includesecurity.com/2014/04/reversing-the-dropcam-part-2-rooting-your-dropcam/ (Ambarella A5s `amboot>` 프롬프트·배너·전원 투입 직후 줄바꿈 송신으로 진입한 사례)
- Cybergibbons, "Recovering Firmware Through U-boot": https://cybergibbons.com/hardware-hacking/recovering-firmware-through-u-boot/ (115200에서 16 MB "just over 2 hours", 줄당 80문자 가정)
- Banana Pi BPI-D1 포럼 (Anyka 커널 콘솔 `ttySAK0`): https://forum.banana-pi.org/t/banana-pi-bpi-d1-discussion-board/19
