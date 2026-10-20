# pweh-fwtriage (fwtriage-mcp)

외부 도구 없이(순수 Python + PyYAML) 동작하는 **오프라인 펌웨어 트리아지** MCP 서버다.
UART/JTAG/SPI 로 얻은 플래시 덤프나 벤더 펌웨어에서 "어디에 무엇이 있는지"와 "먼저 볼 곳"을 빠르게 뽑아
`cctv-auth-bypass-hunt`, `firmware-static-analysis`, `game-save-unlock-analysis` Skill 의 1차 근거를 만든다.

- 대상: 운영자가 **소유**하거나 **서면 허가**를 받은 기기의 펌웨어
- 하드웨어를 건드리지 않는다 (안전 게이트 대상 아님). 펌웨어 안의 어떤 것도 **실행하지 않는다**.
  우리가 실행하는 외부 프로그램은 `unsquashfs`/`sasquatch` 뿐이며 비root·시간 제한·디스크 사용량 감시 아래에서만 돈다.
- 모든 입력은 케이스 디렉터리 안의 경로(케이스 상대 경로 권장), 모든 출력은 `analysis/` 또는 `extract/<label>-NNN/` 에
  쓰고 `case.register_artifact` 로 등록한다.
- 응답은 **요약 + 전체 결과 JSON 경로(`result_path`)** 다. 목록은 `max_results` 로 잘린다 (전체는 JSON 파일).
  예외: 케이스를 받지 않는 `fw_hunt_patterns` 에는 `result_path` 가 없고, `background=true` 로 시작하면 응답은 `job_id` 이며
  `result_path` 는 `fwtriage_job_status` 의 `result` 안에 있다.
- 결과는 모두 **후보(heuristic)** 다. 취약점 확정은 REA(Ghidra 디컴파일 등)와 소유 기기·격리 랩 검증으로 한다.

## REA 와의 관계

| | fwtriage | REA (binwalk/unblob/Ghidra) |
|---|---|---|
| 의존성 | 없음 (stdlib + PyYAML, squashfs 추출만 unsquashfs) | binwalk, unblob, Ghidra, JDK |
| 속도 | 수 초 (64MiB 덤프 스캔 ≈ 1초) | 수십 초 ~ 수 분 |
| 강점 | 덤프 지도, U-Boot env/mtdparts, 파티션 분할, rootfs 구성 감사, CCTV·게임(세이브·해금 단서) 문자열 휴리스틱, 기본 비밀번호 해시 대조 | 재귀 추출(모든 형식), 디컴파일, xref, 호출 경로 |
| 제한 | squashfs 외 파일시스템은 위치·크기만 식별 (추출은 REA) | 펌웨어 입력 ≤ 128MiB, MIPS raw 불가 등 |

권장 흐름: `fw_identify` → `fw_uboot_env` → `fw_carve` → `fw_extract_squashfs` → `fw_rootfs_audit` / `fw_strings_hunt` /
`fw_elf_info` → `fw_crack_hashes` → (critical/high 후보) REA `search_strings` → `xrefs` → `procedure_pseudo_code` → `case_add_finding`.
jffs2/UBI/cramfs/ext 파티션은 `fw_carve` 로 분리한 뒤 REA `extract_firmware` 로 추출한다.

## 도구

시그니처는 주요 인자만 적었다(`approval_id`, 타임아웃, `active_only` 같은 선택 인자는 일부 생략). 전체 인자와 기본값은 [`docs/references/pweh-mcp-tools.md`](../../docs/references/pweh-mcp-tools.md) 를 본다.

| 도구 | 하는 일 | 출력 |
|---|---|---|
| `fw_identify(case_id, path, offset=0, length=None, max_results=50, include_nested=False, max_seconds=120, background=False)` | 시그니처 스캔 + 헤더 검증(오탐 억제): uImage(헤더·데이터 CRC), FIT/DTB(구조 파싱), squashfs v1~4(벤더 매직 포함), jffs2(노드 CRC 연쇄), UBI(EC/VID CRC, PEB 크기, 볼륨 이름)/UBIFS, cramfs(CRC)/romfs/erofs/ext2·3·4, gzip/xz/lzma/bzip2(상한 있는 시험 해제로 정확한 크기), zstd/lz4(프레임 연쇄, xxh32), ELF, cpio, ARM zImage, zip, PEM 키/인증서, U-Boot env(CRC, LE/BE), U-Boot/커널 버전 문자열, `PWEH SYNTHETIC` 마커. 압축 스트림·압축 파일시스템 안쪽 후보는 검사하지 않고, 투명 컨테이너(uImage/FIT/ext/cpio) 안쪽은 '중첩'으로 표시. 0xFF/0x00 패딩 구간. | `analysis/identify-NNN.json` |
| `fw_entropy(case_id, path, block_size=65536, offset=0, length=None, high_threshold=7.5, annotate=True, ...)` | 블록 Shannon 엔트로피, 고엔트로피 구간(카이제곱으로 균일/비균일), 알려진 형식과 겹치지 않는 고엔트로피 구간(암호화·난독화 의심), 패딩 구간, 한 줄 프로파일 | `analysis/entropy-NNN.json` |
| `fw_uboot_env(case_id, path, sizes=None, align=4096, include_default_env=True)` | `pweh.formats.find_uboot_env`(CRC, redundant 플래그) + 빅엔디안 CRC 보완, env 전체/주요 변수, mtdparts 해석(`pweh.formats.parse_mtdparts`), redundant 쌍의 활성본 추정, CRC 없는 기본 env(U-Boot 내장) 후보, 이미지 속 `mtdparts=` 문자열 | `analysis/uboot-env-NNN.json` |
| `fw_carve(case_id, path, mtdparts=None, partitions=None, output_label="parts", mtd_device=None, probe=True)` | mtdparts 문자열 / `[{name, offset, size}]` / (둘 다 없으면) 이미지 안의 env → 기본 env → `mtdparts=` 문자열 → DTB partition 노드 순으로 레이아웃 결정 후 분할. 파티션마다 시작 위치 형식 판별(squashfs/uImage/erased...). 응답 `partitions[].path` 는 케이스 상대 경로(`file` 은 같은 값의 별칭) | `extract/<label>-NNN/<idx>-<name>.bin`, `index.json`, `analysis/carve-NNN.json` |
| `fw_uimage_info(case_id, path, offset=0)` | legacy uImage(이름, load/entry, OS/arch/type/압축, CRC, multi 크기표, 페이로드 실제 형식 대조) 또는 FIT(images/configurations/해시/서명)·DTB(model/compatible/bootargs/partition 노드) | `analysis/uimage-NNN.json` |
| `fw_extract_squashfs(case_id, path, offset=0, output_label="rootfs", timeout_seconds=600, max_output_bytes="2G", engine="auto", allow_listing_anomalies=False, background=False)` | superblock 검증 → `unsquashfs -lln` 목록 안전 검사(`..`, 링크 아래 항목 = CVE-2021-41072 형태, 개행 포함 이름, 압축 폭탄) → 비root 추출(장치 노드 안 만듦) → 원본 모드/소유자/setuid 매니페스트 | `extract/<label>-NNN/`, `extract/<label>-NNN.manifest.json`, `analysis/extract-squashfs-NNN.json` |
| `fw_elf_info(case_id, path, max_results=50, max_files=3000, ...)` | 순수 Python ELF: class/엔디언/e_machine, e_flags(MIPS ISA·ABI(o32/n32/n64)·ASE, ARM EABI·float ABI), `.MIPS.abiflags` FP ABI, 인터프리터, DT_NEEDED/SONAME/RPATH, 임포트(섹션 헤더 없는 sstrip 바이너리도 PT_DYNAMIC → DT_SYMTAB, 심볼 수는 DT_HASH/DT_GNU_HASH/DT_MIPS_SYMTABNO), NX/RELRO/PIE/카나리/FORTIFY, 위험 임포트(내장 + YAML `function_heuristics`), 폭 없는 `%s`/`%[` sscanf 포맷. 디렉터리면 전체 ELF 위험 순위 | `analysis/elf-info-NNN.json` |
| `fw_rootfs_audit(case_id, rootfs_dir, max_results=50, crack_defaults=True, crack_seconds=30, max_file_size="16M", ...)` | passwd/shadow(빈/약한 해시와 알고리즘, uid 0 추가 계정, 공개 하드코딩 해시, 기본 비밀번호 오프라인 대조), inittab/init.d/rc/inetd/systemd/벤더 시작 스크립트(telnetd `-l /bin/sh`, dropbear `-B`, `nc -e` 셸, getty 자동 로그인/콘솔 셸, remserial, 쓰기 가능한 영구 저장소 스크립트 실행, world-writable 시작 스크립트), 웹 서버/메인 앱 바이너리·설정(BusyBox httpd 인증 줄 포함)·CGI·웹 루트, setuid/setgid, 개인키/인증서(지문만), 설정/스크립트의 하드코딩 자격증명(값 마스킹), 영구 쓰기 가능 마운트, YAML `credential_patterns`/`interesting_paths`/`web_server_binaries`, 벤더 계열 추정(`vendor.family` + `family_source`: 파일 근거 `evidence` → 없으면 프로필의 구체적인 `hunt.vendor_family` `profile` → 일반 웹 서버만 있으면 `generic`(`generic-web-server`) → 근거 없음 `unknown`(`none`). `votes`/`vendor` 는 파일 근거만, 일반 웹 서버 이름(lighttpd 등)은 벤더 표가 아님). `bin`/`sbin` 의 `passwd` 명령(BusyBox 애플릿 링크)과 바이너리 내용은 계정 DB 로 읽지 않는다 | `analysis/rootfs-audit-NNN.json` |
| `fw_strings_hunt(case_id, path_or_dir, patterns="cctv", max_hits=500, max_results=50, min_severity=None, include=None, min_length=4, utf16=True, per_pattern_cap=50, ...)` | `cctv-hunt-patterns.yaml` 의 `string_heuristics` (scope: strings=ASCII+UTF-16LE 문자열, text=텍스트 줄, raw=바이트). `patterns` 는 `cctv`(전체) 또는 id/category/vendor/severity 선택자, `xm-*` 접두사, `re:<정규식>`, `raw:<바이트 정규식>`, `lit:<문자열>`. `patterns="game"` 은 게임 팩(`game-hunt-patterns.yaml`) 전체, `game:<category\|id\|vendor\|severity\|접두사*>` 는 그 일부이고, 두 팩은 한 호출에서 섞지 않는다(CCTV 선택자와 함께 주거나 없는 `game:` 선택자면 `validation_failed`, 사용자 패턴은 함께 가능). 쓴 팩은 응답 `patterns.pack`·결과 JSON `params.pack`(게임 팩이면 `summary.vendor_family_guess` 는 `null`). `#` 주석 줄의 히트는 별도(`commented_hits`). `checks` 는 auth-hunt 스키마 `checks[]` 형식. `hits[].file` 은 디렉터리·단일 파일 모드 모두 rootfs 절대 경로(rootfs 밖 덤프·파티션 이미지는 `null`), `hits[].path` 는 케이스 상대 경로 (`commented_hits`·`top_files` 도 같음). rootfs 루트는 `fw_extract_squashfs` 트리(`extract/<label>-NNN`, 옆에 `.manifest.json`), 없으면 `etc`+`bin`/`sbin` 을 가진 가장 바깥 상위 디렉터리이고 `summary.rootfs_dirs` 에 적는다. `checks[].evidence_ref` 는 `<file>@<offset_hex>`(file 이 `null` 이면 `<path>@…`). 사용자 패턴의 check id 는 `custom-<lit\|re\|raw>-<sha256 앞 8자>`(같은 패턴이면 실행마다 같은 id, 원문은 `description`), 빈 문자열과 일치하는 사용자 패턴은 건너뛰고 `notes` 에 적는다. `include` glob 은 `path_or_dir` 기준 | `analysis/strings-hunt-NNN.json` |
| `fw_crack_hashes(case_id, hashes=None, source_path=None, wordlist="builtin-defaults", extra_words=None, hash_type=None, max_seconds=60, reveal=False, ...)` | 펌웨어의 해시를 공개 기본 비밀번호 사전과 **오프라인** 대조 (네트워크 로그인 시도 없음). DES crypt(앞 8자), md5crypt/apr1, sha256/512crypt(순수 Python, crypt 모듈 불필요), XiongMai Sofia(`hash_type="xm-sofia"`), 솔트 없는 md5/sha1/sha256 hex, bcrypt/yescrypt(crypt 모듈 지원 시). 공개 하드코딩 해시 일치 표시. 응답의 평문은 기본 마스킹 | `analysis/crack-hashes-NNN.json` (평문 포함 — 케이스 밖 반출 금지) |
| `fw_hunt_patterns(vendor=None, category=None, pack="cctv")` | 휴리스틱 목록, 패턴 파일 출처·sha256·오류. `pack="game"` 이면 게임 팩 목록(`string_heuristics` 만), 응답의 `pack`·`packs` | — |
| `fw_esp_partitions(case_id, path, offset=None, max_results=50)` | ESP32 계열 플래시 덤프의 파티션 표(기본 0x8000, 없으면 4 KiB 경계 탐색). type/subtype 이름, 암호화·읽기 전용 플래그, MD5 항목 검증, 겹침·범위 경고, 세이브 쓰기 분류 `write_class`(`nvs` / `raw-user-data` / `filesystem-analysis-only` / `not-a-save`)와 `write_blockers`(암호화 플래그, `nvs_keys` 파티션) | `analysis/esp-partitions-NNN.json` |
| `fw_esp_image_info(case_id, path, offset=None, partition=None)` | ESP 앱·2단계 부트로더 이미지: 칩·아키텍처, entry, 세그먼트(load 주소·크기·메모리 영역), 체크섬·덧붙은 SHA256 검증, `esp_app_desc_t`(프로젝트 이름·버전·IDF 버전·빌드 시각·ELF sha256). `partition=label` 은 전체 플래시 덤프의 파티션 표로 위치를 찾는다 | `analysis/esp-image-NNN.json` |
| `fw_esp_to_elf(case_id, path, offset=None, partition=None, output_label="esp-app", rea_compat=False)` | 앱 이미지 → ELF32(세그먼트마다 PT_LOAD + 영역 이름 섹션, 심볼 없음). REA 는 Xtensa(ESP32·S2·S3) ELF 를 열지 못하고, RISC-V 는 `rea_compat=true`(e_flags 를 double-float ABI 로 표시)로 만든 ELF 만 연다 | `extract/<label>-NNN/<이름>.elf`, `analysis/esp-to-elf-NNN.json` |
| `fw_esp_nvs(case_id, path, offset=None, length=None, partition=None, namespace=None, key=None, include_erased=False, export_blobs=False, max_results=50)` | NVS 파티션(최대 1 MiB): 페이지 상태·seq·버전, 헤더·항목·데이터 CRC 유효 개수, 네임스페이스, 항목 값(정수·문자열·blob v1/v2), live 여부와 지운 이전 값, live 중복. 비밀로 보이는 값(nvs.net80211 의 모든 값, 비밀번호·PIN·토큰·API 키 등의 키, 그 원문을 담은 다른 값)은 응답·결과 파일 모두 마스킹 + 케이스 솔트 다이제스트. `export_blobs=true` 면 비밀이 아닌 blob 을 파일로 | `analysis/esp-nvs-NNN.json`, `extract/nvs-blobs-NNN/` |
| `fw_save_diff(case_id, paths, labels=None, offset=None, length=None, partition=None, mode="auto", observations=None, merge_gap=0, max_results=50)` | 시간 순서 스냅샷 2~16개 비교. bytes: 바뀐 범위·인코딩 해석(u8/u16/u32 LE·BE, BCD)·추세, nvs: 키 단위 변화(changed·added·removed, 비밀 값 마스킹). NVS 를 담은 범위는 bytes 로 비교하지 않는다. `observations`(스냅샷마다 화면에서 본 값)와 정확히 같은 위치·인코딩(또는 NVS 키)을 찾는다 | `analysis/save-diff-NNN.json` |
| `fw_checksum_find(case_id, paths, offset=None, length=None, partition=None, algorithms=None, max_results=20, max_seconds=120, background=False)` | 모든 스냅샷에서 `저장값 = 알고리즘(범위)` 인 체크섬 후보(합·xor·CRC-8/16/32·adler32·fletcher16 등 24종). 위치 후보는 바뀐 바이트에서만. 시험한 후보 수, 기대 오탐 수, `strong`/`weak`. 합계 8 MiB 까지, NVS 를 담은 범위는 거부 | `analysis/checksum-find-NNN.json` |
| `fw_find_seq_tables(case_id, path, offset=None, length=None, partition=None, base_addr=None, min_len=6, max_results=50, max_seconds=120, background=False)` | 치트 입력(버튼 시퀀스) 표 후보: 작은 알파벳의 배열, 코나미형 모양 점수. ESP 앱 이미지면 코드가 아닌 세그먼트를 load 주소(디컴파일러 주소)로 훑는다 | `analysis/seq-tables-NNN.json` |
| `fwtriage_job_status(job_id, wait_seconds=0)`, `fwtriage_job_cancel(job_id)`, `fwtriage_jobs(active_only=False)` | `background=true` 로 시작한 작업 폴링/취소. `result` 는 인라인 응답과 같다 | `jobs/<job_id>.json` |

## 데이터 파일

- `src/pweh/data/cctv-hunt-patterns.yaml` — `docs/references/cctv-hunt-patterns.yaml`(사실 확인된 원본)을 **그대로 복사**한 것.
  원본이 바뀌면 `cp docs/references/cctv-hunt-patterns.yaml src/pweh/data/` 로 다시 맞춘다
  (`tests/servers/test_fwtriage_units.py::test_patterns_data_synced_with_reference` 가 차이를 알려준다).
  로더는 YAML notes 의 의미(Python re + MULTILINE, scope, glob)를 따르고, 컴파일 오류는 `fw_hunt_patterns` 의 `errors` 로 보고한다.
- `src/pweh/data/game-hunt-patterns.yaml` — 게임 팩(`fw_strings_hunt(patterns="game")`, `fw_hunt_patterns(pack="game")`). 소유 게임기·장난감의 해금 조건·세이브 위치를 찾는 출발점이 되는
  일반 키워드·API 이름 휴리스틱으로, 이 저장소에서 썼고 `docs/references` 원본은 없다. `string_heuristics` 만 있고 category 는 고정 9종(`debug-menu`, `cheat-input`, `unlock-condition`, `save-format`, `save-integrity`, `nfc-tag`, `clock`, `online-sync`, `entitlement`),
  severity 는 `info`(플랫폼·API 앵커)/`low`(게임 논리 키워드)뿐이다. entitlement·판매 토큰·amiibo 류 태그 암호·온라인 동기화되는 서명은 보고만 한다(패치·우회 금지).
  규칙(정규식 컴파일, 빈 문자열 불일치, 사전 필터 리터럴, 패턴별 예시)은 `tests/servers/test_fwtriage_game_patterns.py` 가 검사한다.
- `src/pweh/data/default-passwords.txt` — 작은 내장 기본 비밀번호 사전. 출처: `docs/references/cctv-vuln-patterns.md` 부록 B
  (tothi, Yarmak, Kojenov, SEC Consult, Mirai scanner.c 주석)와 SecLists `telnet-betterdefaultpasslist.txt`(MIT).

## 외부 도구 (squashfs 추출만)

`unsquashfs` 탐색 순서: `pipeline-config.yaml` 의 `tools.unsquashfs`(= `${PWEH_UNSQUASHFS:-unsquashfs}`) → `$PWEH_UNSQUASHFS` →
`$PWEH_TOOLS_DIR/bin/unsquashfs`(기본 `~/pweh-tools`) → `PATH`. 비표준 매직(sqlz/shsq 등)·v4 빅엔디안은 `sasquatch`
(`$PWEH_TOOLS_DIR/extractors/bin/sasquatch[-v4be]`)를 우선한다. 없으면 `tool_missing` 오류와 설치 힌트를 돌려준다.
서버가 root 로 실행 중이면 추출을 거부한다.

## 안전·견고성

- 추출된 rootfs 안의 **심볼릭 링크는 rootfs 안에서만 해석**한다 (절대 경로 링크를 따라가 호스트 파일을 읽지 않음, 루프·`..` 처리).
  파일은 `O_NOFOLLOW|O_NONBLOCK` 로 일반 파일만 읽는다 (FIFO 에서 멈추지 않음). 하드링크는 한 번만 읽는다.
- 비root 추출은 setuid 비트와 소유자가 사라지므로 `fw_rootfs_audit` 는 매니페스트를 우선 사용한다. REA/unblob 로 추출한 트리처럼
  매니페스트가 없으면 `limitations` 에 그 사실을 적는다.
- 시험 해제는 입력/출력 상한(스트림당 64MiB/160MiB, 스캔 전체 768MiB)이 있고, 스캔은 `max_seconds` 시간 예산 안에서 부분 결과로 끝난다.
- 출력 번호(NNN)는 `O_EXCL`/`mkdir` 로 원자적으로 확보한다 (동시 호출 안전).
- 외부 프로세스: 인자 리스트, `stdin=DEVNULL`, 새 프로세스 그룹, 시간 초과·취소 시 그룹 종료, `LC_ALL=C` 최소 환경, 프로세서 수 제한.
- 응답에는 비밀번호·키 값을 넣지 않는다 (마스킹/지문). 평문이 필요한 경우 케이스 안의 JSON 또는 `reveal=true`.
  예외: `fw_strings_hunt` 의 `hits[].match`/`context` 는 일치한 문자열 원문이라 바이너리에 박힌 자격증명(예: `Authorization: Basic <base64>`)이
  그대로 보일 수 있다 (REA `search_strings` 로 따라가는 데 필요). 발견사항·보고서에 옮길 때는 마스킹한다.

## 한계 (반드시 읽을 것)

- 시그니처·문자열·엔트로피는 **휴리스틱**이다. 히트 = 조사 출발점, 취약점 확정이 아니다.
- 해시 대조는 작은 공개 사전만 쓴다. "not_cracked" 는 "안전함"이 아니다.
- squashfs 만 직접 추출한다. jffs2/UBI/UBIFS/cramfs/ext/erofs 는 위치·크기·메타데이터만 확인한다 (추출은 REA).
- zstd/lz4 는 Python 3.10 표준 라이브러리에 해제기가 없어 프레임 구조만 검증한다.
- 벤더 암호화 펌웨어(예: 일부 Hikvision/Dahua 업데이트 파일)는 해독하지 않는다 → `fw_entropy` 로 '설명되지 않는 고엔트로피'만 표시.
- mtdparts 숫자는 코어 파서 기준(10진수)이며, 리눅스 memparse 의 '선행 0 = 8진수' 와 다를 수 있는 값은 경고한다.
- ESP 도구: 파티션 표·NVS 는 로컬 정답(oracle)이 없어 합성 이미지로만 시험했다. NVS CRC 규칙(`zlib.crc32(x, 0xFFFFFFFF)`)은 실기 덤프로 확인하기 전이다
  (`fw_esp_nvs` 의 `crc_summary` 로 바로 드러난다). 앱 이미지·ELF 는 esptool `image-info`·`elf2image` 와 대조해 시험한다.
- REA 는 Xtensa(ESP32·S2·S3) ELF 를 열지 못한다. 이 칩들은 디컴파일 없이 문자열·패턴·표 도구와 세이브 비교로 분석한다.
- 세이브 도구 결과는 후보다. 체크섬은 자기 필드를 덮는 형태·HMAC·서명은 찾지 않고, 큰 범위의 CRC 는 바이트 예산 안에서만 찾는다(`truncated`).
- NVS 비밀값 마스킹은 키 이름 휴리스틱(+ 같은 원문을 담은 값)이다. 평범한 이름에 숨긴 비밀은 못 가릴 수 있다. 바이트 비교·체크섬 찾기는 NVS 를 담은 범위를 거부한다.
  세이브 값 수정(패치 이미지)은 아직 없다.

## 테스트

```
.venv/bin/python -m pytest tests/servers/test_fwtriage_units.py tests/servers/test_fwtriage_mcp.py tests/servers/test_fwtriage_game_patterns.py \
    tests/servers/test_fwtriage_esp.py tests/servers/test_fwtriage_saves.py tests/servers/test_fwtriage_game_mcp.py -q
```

합성 입력(가짜 플래시, 취약 구성 rootfs, 손으로 만든 ELF, zig 로 만든 ARM/MIPS ELF)을 테스트 안에서 만든다.
`mksquashfs`/`unsquashfs`/`zig`/`readelf`/`lz4`/`openssl` 이 필요한 테스트는 `@pytest.mark.external` 이며 없으면 skip 한다.
