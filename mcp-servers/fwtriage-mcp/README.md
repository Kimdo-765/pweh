# pweh-fwtriage (fwtriage-mcp)

외부 도구 없이(순수 Python + PyYAML) 동작하는 **오프라인 펌웨어 트리아지** MCP 서버다.
UART/JTAG/SPI 로 얻은 플래시 덤프나 벤더 펌웨어에서 "어디에 무엇이 있는지"와 "먼저 볼 곳"을 빠르게 뽑아
`cctv-auth-bypass-hunt`, `firmware-static-analysis`, `game-save-unlock-analysis` Skill 의 1차 근거를 만든다.

- 대상: 운영자가 **소유**하거나 **서면 허가**를 받은 기기의 펌웨어·세이브 스냅샷
- 하드웨어를 건드리지 않는다 (안전 게이트 대상 아님). 펌웨어 안의 어떤 것도 **실행하지 않는다**.
  `fw_patch_build` 는 기기에 쓰지 않고, 검증된 새 백업과 사람 증명 뒤 사람이 별도 터미널에서 실행할 쓰기 명령만 보여 준다.
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
| `fw_uboot_env(case_id, path, sizes=None, align=4096, include_default_env=True)` | `pweh.formats.find_uboot_env`(CRC, redundant 플래그) + 빅엔디안 CRC 보완, env 전체/주요 변수, mtdparts 해석(`pweh.formats.parse_mtdparts`), redundant 쌍의 활성본 추정, CRC 없는 기본 env(U-Boot 내장) 후보, 이미지 속 `mtdparts=` 문자열, env 마다 `sd_boot`(mmc 부팅·mmc 에서 읽는 boot.scr/uEnv·verify·카드 업데이트·env 쓰기 가능성 — 장치 자리 변수 `fatload ${bootdev} …` 는 같은 env 의 `bootdev=mmc` 로 읽음, tftp·ubi·nand·sf·usb 출처의 boot.scr 와 이름만 autoupdate 인 TFTP 업데이트는 SD 신호가 아님, 응답 압축형, 결과 파일 전체) | `analysis/uboot-env-NNN.json` |
| `fw_carve(case_id, path, mtdparts=None, partitions=None, output_label="parts", mtd_device=None, probe=True)` | mtdparts 문자열 / `[{name, offset, size}]` / (둘 다 없으면) 이미지 안의 env → 기본 env → `mtdparts=` 문자열 → DTB partition 노드 순으로 레이아웃 결정 후 분할. 파티션마다 시작 위치 형식 판별(squashfs/uImage/erased...). 응답 `partitions[].path` 는 케이스 상대 경로(`file` 은 같은 값의 별칭) | `extract/<label>-NNN/<idx>-<name>.bin`, `index.json`, `analysis/carve-NNN.json` |
| `fw_uimage_info(case_id, path, offset=0)` | legacy uImage(이름, load/entry, OS/arch/type/압축, CRC, multi 크기표, 페이로드 실제 형식 대조) 또는 FIT(images/configurations/해시/서명)·DTB(model/compatible/bootargs/partition 노드) | `analysis/uimage-NNN.json` |
| `fw_extract_squashfs(case_id, path, offset=0, output_label="rootfs", timeout_seconds=600, max_output_bytes="2G", engine="auto", allow_listing_anomalies=False, background=False)` | superblock 검증 → `unsquashfs -lln` 목록 안전 검사(`..`, 링크 아래 항목 = CVE-2021-41072 형태, 개행 포함 이름, 압축 폭탄) → 비root 추출(장치 노드 안 만듦) → 원본 모드/소유자/setuid 매니페스트 | `extract/<label>-NNN/`, `extract/<label>-NNN.manifest.json`, `analysis/extract-squashfs-NNN.json` |
| `fw_elf_info(case_id, path, max_results=50, max_files=3000, ...)` | 순수 Python ELF: class/엔디언/e_machine, e_flags(MIPS ISA·ABI(o32/n32/n64)·ASE, ARM EABI·float ABI), `.MIPS.abiflags` FP ABI, 인터프리터, DT_NEEDED/SONAME/RPATH, 임포트(섹션 헤더 없는 sstrip 바이너리도 PT_DYNAMIC → DT_SYMTAB, 심볼 수는 DT_HASH/DT_GNU_HASH/DT_MIPS_SYMTABNO), NX/RELRO/PIE/카나리/FORTIFY, 위험 임포트(내장 + YAML `function_heuristics`), 폭 없는 `%s`/`%[` sscanf 포맷. 디렉터리면 전체 ELF 위험 순위 | `analysis/elf-info-NNN.json` |
| `fw_rootfs_audit(case_id, rootfs_dir, max_results=50, crack_defaults=True, crack_seconds=30, max_file_size="16M", sd_surface=False, ...)` | passwd/shadow(빈/약한 해시와 알고리즘, uid 0 추가 계정, 공개 하드코딩 해시, 기본 비밀번호 오프라인 대조), inittab/init.d/rc/inetd/systemd/벤더 시작 스크립트(telnetd `-l /bin/sh`, dropbear `-B`, `nc -e` 셸, getty 자동 로그인/콘솔 셸, remserial, 쓰기 가능한 영구 저장소 스크립트 실행, world-writable 시작 스크립트), 웹 서버/메인 앱 바이너리·설정(BusyBox httpd 인증 줄 포함)·CGI·웹 루트, setuid/setgid, 개인키/인증서(base64 본문이 있는 PEM 만 — 라이브러리의 머리줄 상수는 세지 않는다, 지문만), 설정/스크립트의 하드코딩 자격증명(값 마스킹), 영구 쓰기 가능 마운트, YAML `credential_patterns`/`interesting_paths`/`web_server_binaries`, 벤더 계열 추정(`vendor.family` + `family_source`: 파일 근거 `evidence` → 없으면 프로필의 구체적인 `hunt.vendor_family` `profile` → 일반 웹 서버만 있으면 `generic`(`generic-web-server`) → 근거 없음 `unknown`(`none`). `votes`/`vendor` 는 파일 근거만, 일반 웹 서버 이름(lighttpd 등)은 벤더 표가 아님). `bin`/`sbin` 의 `passwd` 명령(BusyBox 애플릿 링크)과 바이너리 내용은 계정 DB 로 읽지 않는다. 핫플러그 처리기(mdev.conf·udev `RUN+=`·hotplug)도 따라가고, `sd_surface=True` 면 SD 표면 rootfs 쪽 섹션 `sd_surface`(응답 요약, 결과 파일 전체). 시작 스크립트는 셸 논리 줄(줄 이어쓰기 — 연산자 뒤 빈 줄·주석 줄 포함, 연산자 뒤 줄 끝 주석은 판정에서 지움, here-document 본문은 잇지 않음(끝 구분자 줄이 없으면 본문 아님), inittab·inetd·udev·systemd 유닛은 줄 끝 `\` 만) 단위로 보고, `VAR=값`·nohup·setsid·env·`start-stop-daemon -x`(멈춤 명령 제외) 뒤의 쓰기 가능 저장소 실행도 잡는다(대입·래퍼 건너뛰기는 셸 문법 파일만 — systemd `ExecStart=프로그램 경로` 의 경로는 인자). 항목은 같은 파일의 같은 규칙마다 20개, 시작 스크립트 전체에서 같은 규칙마다 500개까지 적는다(나머지는 `summary.items_suppressed`, 심볼릭·하드 링크는 한 번만 읽음) | `analysis/rootfs-audit-NNN.json` |
| `fw_sd_surface(case_id, rootfs_dir=None, image_path=None, max_results=50, max_evidence=20, max_file_size="64M", max_seconds=300, background=False)` | 펌웨어 쪽 SD 카드 공격 표면 SD-01~09 정적 점검: 카드 내용 실행(cd 뒤·복사 뒤·복호화 뒤 포함), 서명 없는 SD 업데이트(디렉터리로 복사 뒤 포함), U-Boot mmc 부팅·boot.scr/uEnv·verify(env_get_yesno 기준)·env 쓰기 가능성, 삽입 처리기, 설정 가져오기, 민감 정보 기록, 녹화 암호화(found = 보호 근거), 약한 마운트 옵션, 네트워크 노출. 응답은 점검마다 상태와 근거 앞 3개(파일/줄 또는 이미지 오프셋, 마스킹 발췌), 마운트 지점·`sd_paths_referenced` 요약, 제한된 FIT 선언 구조·완료도인 `fit_security`이고, 결과 파일에는 근거 전체·핫플러그 처리기·`phases`·`stats` 가 있다. `not-found` 는 필요한 입력을 끝까지 알려진 모양에 맞춰 본 경우만이고(카드 경로가 없다는 증명은 아님), 입력이 없거나 시간·크기·줄 길이·히트·env 펼침 상한으로 일부만 보면 `unknown` 이다. 펌웨어의 mdev 정규식·udev glob 은 실행하지 않는다 | `analysis/sd-surface-NNN.json` |
| `fw_strings_hunt(case_id, path_or_dir, patterns="cctv", max_hits=500, max_results=50, min_severity=None, include=None, min_length=4, utf16=True, per_pattern_cap=50, ...)` | `cctv-hunt-patterns.yaml` 의 `string_heuristics` (scope: strings=ASCII+UTF-16LE 문자열, text=텍스트 줄, raw=바이트). `patterns` 는 `cctv`(전체) 또는 id/category/vendor/severity 선택자, `xm-*` 접두사, `re:<정규식>`, `raw:<바이트 정규식>`, `lit:<문자열>`. `patterns="game"` 은 게임 팩(`game-hunt-patterns.yaml`) 전체, `game:<category\|id\|vendor\|severity\|접두사*>` 는 그 일부이고, 두 팩은 한 호출에서 섞지 않는다(CCTV 선택자와 함께 주거나 없는 `game:` 선택자면 `validation_failed`, 사용자 패턴은 함께 가능). 쓴 팩은 응답 `patterns.pack`·결과 JSON `params.pack`(게임 팩이면 `summary.vendor_family_guess` 는 `null`). `#` 주석 줄의 히트는 별도(`commented_hits`). `checks` 는 auth-hunt 스키마 `checks[]` 형식. `hits[].file` 은 디렉터리·단일 파일 모드 모두 rootfs 절대 경로(rootfs 밖 덤프·파티션 이미지는 `null`), `hits[].path` 는 케이스 상대 경로 (`commented_hits`·`top_files` 도 같음). rootfs 루트는 `fw_extract_squashfs` 트리(`extract/<label>-NNN`, 옆에 `.manifest.json`), 없으면 `etc`+`bin`/`sbin` 을 가진 가장 바깥 상위 디렉터리이고 `summary.rootfs_dirs` 에 적는다. `checks[].evidence_ref` 는 `<file>@<offset_hex>`(file 이 `null` 이면 `<path>@…`). 사용자 패턴의 check id 는 `custom-<lit\|re\|raw>-<sha256 앞 8자>`(같은 패턴이면 실행마다 같은 id, 원문은 `description`), 빈 문자열과 일치하는 사용자 패턴은 건너뛰고 `notes` 에 적는다. `include` glob 은 `path_or_dir` 기준. 시간 예산은 파일 사이와 16 MiB 조각 사이에서 본다(파일 하나도 — 넘으면 `summary.truncated`) | `analysis/strings-hunt-NNN.json` |
| `fw_crack_hashes(case_id, hashes=None, source_path=None, wordlist="builtin-defaults", extra_words=None, hash_type=None, max_seconds=60, reveal=False, ...)` | 펌웨어의 해시를 공개 기본 비밀번호 사전과 **오프라인** 대조 (네트워크 로그인 시도 없음). DES crypt(앞 8자), md5crypt/apr1, sha256/512crypt(순수 Python, crypt 모듈 불필요), XiongMai Sofia(`hash_type="xm-sofia"`), 솔트 없는 md5/sha1/sha256 hex, bcrypt/yescrypt(crypt 모듈 지원 시). 공개 하드코딩 해시 일치 표시. 응답의 평문은 기본 마스킹 | `analysis/crack-hashes-NNN.json` (평문 포함 — 케이스 밖 반출 금지) |
| `fw_hunt_patterns(vendor=None, category=None, pack="cctv")` | 휴리스틱 목록, 패턴 파일 출처·sha256·오류. `pack="game"` 이면 게임 팩 목록(`string_heuristics` 만), 응답의 `pack`·`packs` | — |
| `fw_esp_partitions(case_id, path, offset=None, max_results=50)` | ESP32 계열 플래시 덤프의 파티션 표(기본 0x8000, 없으면 4 KiB 경계 탐색). type/subtype 이름, 암호화·읽기 전용 플래그, MD5 항목 검증, 겹침·범위 경고, 세이브 쓰기 분류 `write_class`(`nvs` / `raw-user-data` / `filesystem-analysis-only` / `not-a-save`)와 `write_blockers`(암호화 플래그, `nvs_keys` 파티션) | `analysis/esp-partitions-NNN.json` |
| `fw_esp_image_info(case_id, path, offset=None, partition=None)` | ESP 앱·2단계 부트로더 이미지: 칩·아키텍처, entry, 세그먼트(load 주소·크기·메모리 영역), 체크섬·덧붙은 SHA256 검증, `esp_app_desc_t`(프로젝트 이름·버전·IDF 버전·빌드 시각·ELF sha256). `partition=label` 은 전체 플래시 덤프의 파티션 표로 위치를 찾는다 | `analysis/esp-image-NNN.json` |
| `fw_esp_to_elf(case_id, path, offset=None, partition=None, output_label="esp-app", rea_compat=False)` | 앱 이미지 → ELF32(세그먼트마다 PT_LOAD + 영역 이름 섹션, 심볼 없음). REA 는 Xtensa(ESP32·S2·S3) ELF 를 열지 못하고, RISC-V 는 `rea_compat=true`(e_flags 를 double-float ABI 로 표시)로 만든 ELF 만 연다 | `extract/<label>-NNN/<이름>.elf`, `analysis/esp-to-elf-NNN.json` |
| `fw_esp_nvs(case_id, path, offset=None, length=None, partition=None, namespace=None, key=None, include_erased=False, export_blobs=False, max_results=50)` | NVS 파티션(최대 1 MiB): 페이지 상태·seq·버전, 헤더·항목·데이터 CRC 유효 개수, 네임스페이스, 항목 값(정수·문자열·blob v1/v2), live 여부와 지운 이전 값, live 중복. 비밀로 보이는 값(nvs.net80211 의 모든 값, 비밀번호·PIN·토큰·API 키 등의 키, 그 원문을 담은 다른 값)은 응답·결과 파일 모두 마스킹 + 케이스 솔트 다이제스트. `export_blobs=true` 면 비밀이 아닌 blob 을 파일로 | `analysis/esp-nvs-NNN.json`, `extract/nvs-blobs-NNN/` |
| `fw_save_diff(case_id, paths, labels=None, offset=None, length=None, partition=None, mode="auto", observations=None, merge_gap=0, max_results=50)` | 시간 순서 스냅샷 2~16개 비교. bytes: 바뀐 범위·인코딩 해석(u8/u16/u32 LE·BE, BCD)·추세, nvs: 키 단위 변화(changed·added·removed, 비밀 값 마스킹). NVS 를 담은 범위는 bytes 로 비교하지 않는다. `observations`(스냅샷마다 화면에서 본 값)와 정확히 같은 위치·인코딩(또는 NVS 키)을 찾는다 | `analysis/save-diff-NNN.json` |
| `fw_checksum_find(case_id, paths, offset=None, length=None, partition=None, algorithms=None, max_results=20, max_seconds=120, background=False)` | 모든 스냅샷에서 `저장값 = 알고리즘(범위)` 인 체크섬 후보(합·xor·CRC-8/16/32·adler32·fletcher16 등 24종). 위치 후보는 바뀐 바이트에서만. 시험한 후보 수, 기대 오탐 수, `strong`/`weak`. 합계 8 MiB 까지, NVS 를 담은 범위는 거부 | `analysis/checksum-find-NNN.json` |
| `fw_find_seq_tables(case_id, path, offset=None, length=None, partition=None, base_addr=None, min_len=6, max_results=50, max_seconds=120, background=False)` | 치트 입력(버튼 시퀀스) 표 후보: 작은 알파벳의 배열, 코나미형 모양 점수. ESP 앱 이미지면 코드가 아닌 세그먼트를 load 주소(디컴파일러 주소)로 훑는다 | `analysis/seq-tables-NNN.json` |
| `fw_patch_build(case_id, base_path, target, edits, purpose, unlock_source, online_capable, backup_path=None, description=None)` | 세이브 값 패치(사용자가 원할 때만). base = 기기에서 두 번 읽어 일치한 전체 플래시 덤프(출처 원장 확인), target = NVS 정수 항목 또는 사용자 데이터 파티션(+체크섬). backup_path 없이 → 계획(패치 이미지), 새 백업과 사람 증명 뒤 → 출처 원장 `patch-plan` 기록 + 사람이 실행할 쓰기 명령(sha256 확인 → esptool write-flash, 에이전트는 실행하지 않음) | `patches/<label>-patch-NNN.bin`, `analysis/patch-build-NNN.json` |
| `fw_verify_writeback(case_id, patch_path, readback_path)` | 쓴 뒤 다시 읽은 덤프를 출처 원장의 패치 sha256 과 비교 → applied / not-applied / differs | `analysis/patch-verify-NNN.json` |
| `fwtriage_job_status(job_id, wait_seconds=0, case_id=None)`, `fwtriage_job_cancel(job_id)`, `fwtriage_jobs(active_only=False, case_id=None)` | `background=true` 로 시작한 작업 폴링/취소. `result` 는 인라인 응답과 같다 | `jobs/<job_id>.json` |

작업 상태·목록의 `case_id`를 생략하면 이 서버 프로세스의 작업만 보인다. 재시작 뒤에는
`fwtriage_job_status(job_id, case_id="<케이스 ID>")` 또는 `fwtriage_jobs(case_id="<케이스 ID>")`로 같은 서버의 저장 기록을 확인한다.
소유 서버 종료가 확실한 활성 기록만 `failed`(`error.code=job_owner_terminated`)로 정리한다. 소유자 없는 과거 기록·다른 호스트/namespace·관찰 불가는
원본 상태를 보존하고 `recovery.owner_state="unknown"`과 사유를 표시한다. 살아 있는 다른 서버 프로세스의 기록도 보존한다.
원시 owner 식별자는 응답에 나오지 않는다. 저장 기록의 재개/취소는 없고, `wait_seconds`는 이 프로세스의 작업만 기다린다.
한 기록 1MiB, 목록 512디렉터리 항목·256기록·누적 8MiB·2초로 제한하며 목록의 `recovery.truncated/reasons`가 확인하지 못한 범위를 알린다.
이 두 도구는 로컬 기록을 정리하므로 `readOnlyHint=false`다. 파일·기기·외부 자식의 정리 여부는 별도로 확인한다.

## 가져온 원시 세이브 분석 예제

펌웨어 없이 원시 세이브 파일만 확보했어도 `case_import_file`로 가져온 뒤 `fw_save_diff`·`fw_checksum_find`를 쓸 수 있다.
소유/허가가 기록된 케이스에서 분석하며, 가져온 파일의 출처는 `imported-unattested`다. 이 읽기 전용 분석에는 별도의 `pweh attest`가 필요하지 않다.
현재 `fw_patch_build`의 base는 이 케이스의 `esp_read_flash_start`로 두 번 읽어 일치한 ESP 전체 플래시 덤프(offset0)만 받는다.
가져온 원시 파일은 출처를 증명해도 패치 base가 되지 않는다.

다음 코드는 **직접 만든 합성 형식**의 64바이트 스냅샷 세 개를 새 디렉터리에 만든다. 실제 게임·EEPROM 형식이나 화면 관찰값이 아니다.

```python
from pathlib import Path
import struct

out = Path("synthetic-raw-save")
out.mkdir(exist_ok=False)
for index, (score, level) in enumerate([(1000, 1), (70000, 2), (123456, 3)], 1):
    data = bytearray(range(64))
    data[0:4] = b"SAV1"
    struct.pack_into("<I", data, 0x10, score)
    data[0x14] = level
    checksum = sum(data[:0x3c]) & 0xffffffff
    struct.pack_into("<I", data, 0x3c, checksum)
    (out / f"raw-save-{index:02}.bin").write_bytes(data)
```

생성한 디렉터리의 절대 경로로 source_path를 바꾸어 세 파일을 각각 가져온다(02·03도 같은 호출).

```text
case_import_file(case_id="<id>", source_path="<합성 예제 디렉터리>/raw-save-01.bin", kind="other", description="직접 생성한 합성 원시 세이브 1")
```

다음 도구에는 성공 응답의 `artifact.path`를 시간순으로 사용한다. 동일 basename이 케이스에 이미 있으면 오류이며 자동 덮어쓰기·번호 변경을 하지 않는다.
아래 paths는 해당 이름으로 가져오기가 성공한 경우의 예다.

```text
fw_save_diff(case_id="<id>",
  paths=["dumps/raw-save-01.bin", "dumps/raw-save-02.bin", "dumps/raw-save-03.bin"],
  mode="bytes", offset=0, length=64,
  labels=["synthetic-1", "synthetic-2", "synthetic-3"],
  observations=[{"label":"score", "values":[1000,70000,123456]}, {"label":"level", "values":[1,2,3]}])
fw_checksum_find(case_id="<id>",
  paths=["dumps/raw-save-01.bin", "dumps/raw-save-02.bin", "dumps/raw-save-03.bin"],
  offset=0, length=64, algorithms=["sum32"])
```

격리된 합성 케이스에서 실제 MCP 가져오기→비교→체크섬 탐색을 확인한 결과다.

| 확인 대상 | 응답에서 확인할 값 |
|---|---|
| score | `observation_matches`: `offset_abs="0x10"`, `encoding="u32le"` |
| level | `observation_matches`: `offset_abs="0x14"`, `encoding="u8"` — `0x13`의 u16be·bcd2be 해석도 나옴 |
| checksum | 후보의 `algorithm="sum32"`, `endian="le"`, `location_abs="0x3c"`, `range_abs=["0x0","0x3c"]`, `matches=3`, `stored_values=[2193,2089,2251]` |

`sum32`는 **바이트 합 mod2^32**, `sum32le`는 u32le 워드 합이다. `range_abs`의 끝은 제외하므로 이 예제는 `[0x0,0x3c)`를 덮는다.
이 실행의 checksum 후보는 `strong`이었지만, strength는 탐색의 기대 오탐 기준이다. 실제 저장 루틴 확인이나 모든 형식에서의 유일성을 뜻하지 않는다.
`expected_false_positives`, `range_variants`, `other_ranges`도 함께 기록한다. diff의 `snapshots`는 `{path,sha256}` 목록이고 checksum 응답의 `snapshots`는 경로 문자열 목록이다.

시간순2~16개(3개 이상 권장)를 같은 offset/length로 분석한다. 선택 범위의 **스냅샷 합계**는 비교64 MiB, 체크섬8 MiB까지다.
일반 원시 파일에는 ESP partition label을 쓰지 않는다. NVS를 담은 범위의 bytes 비교·체크섬 탐색은 거부된다.
`truncated`는 검색 미완료 또는 표시 후보 수 잘림이므로 저장 JSON의 `timed_out`, `budget_exhausted`, `candidates_total`과 notes를 함께 확인한다.
체크섬 탐색은 저장 필드 앞 `[s,location)` 또는 뒤 `[location+width,e)` 범위만 시험하며 자기 필드를 덮는 checksum·HMAC·서명을 찾지 않는다.
원시 bytes 비교는 비밀값을 자동 마스킹하지 않는다. 실제 파일은 케이스 안에 두고 `forensics/` 증거·복구물이나 `emu/` 기록을 이 예제의 입력으로 옮기지 않는다.
이 분석 예제를 Skill로 수행하면 결과·입력 출처·미확인 한계를 `save-analysis` 요약에 기록하고 `patches=[]`로 마친다.

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
  세이브 값 변경은 ESP NVS 정수와 raw-user-data 파티션에 한해 `fw_patch_build`·`fw_verify_writeback`을 쓴다. 가져온 원시 파일은 패치 base로 받지 않는다.
  이 서버는 기기에 쓰지 않고, 사람이 실행할 명령만 만든다(검증된 새 백업·사람 증명 뒤).
- SD 표면(`fw_sd_surface`)은 규칙 기반 정적 휴리스틱이다. 상한에 걸리면 not-found 대신 unknown 이지만, not-found 는 알려진 모양에 맞춰 끝까지 보았다는 뜻일 뿐 카드 경로가 없다는 증명이 아니다(간접 실행·내용 시험·압축 풀기 뒤 실행 같은 모양은 architecture §6.6 의 한계 목록 참고). mmc 장치 번호로 SD·eMMC 를 구분하지 못해 `media`·`storage` 같은 일반 이름의 마운트는 FAT 계열 fs 일 때만, `/dev/sdX` 는 장치 이름 디렉터리(`/mnt/sda1`)가 아닐 때만 SD 로 보며, 데몬이 mount(2) 로 마운트하면 옵션을 못 봐 SD-08 이 unknown 이고, 녹화 암호화는 '없음'을 단정하지 않는다. echo·logger 문구 속 `cd`·`sh x` 는 실행으로 보지 않지만, here-document 본문·여러 줄 문자열 속 명령 꼴 줄은 셸에 넘겨지는지 따지지 않고 명령처럼 본다(사용법 안내의 카드 경로 예시도 SD-01 근거가 될 수 있다 — 발췌로 확인).
  카드에 넣을 파일(boot.scr·uEnv·업데이트 이미지·트리거 파일)은 만들지 않고 안내하지도 않는다.

## 테스트

```
.venv/bin/python -m pytest tests/servers/test_fwtriage_units.py tests/servers/test_fwtriage_mcp.py tests/servers/test_fwtriage_game_patterns.py \
    tests/servers/test_fwtriage_esp.py tests/servers/test_fwtriage_saves.py tests/servers/test_fwtriage_game_mcp.py -q
```

합성 입력(가짜 플래시, 취약 구성 rootfs, 손으로 만든 ELF, zig 로 만든 ARM/MIPS ELF)을 테스트 안에서 만든다.
`mksquashfs`/`unsquashfs`/`zig`/`readelf`/`lz4`/`openssl` 이 필요한 테스트는 `@pytest.mark.external` 이며 없으면 skip 한다.

## Android 펌웨어

`fw_identify`로 Android boot/vendor_boot/init_boot·vbmeta·LP·sparse·F2FS 후보를 확인하고, raw GPT/LP는 `fw_carve(layout_source="auto", lp_slot=0)`로 분할한다. `fw_android_surface`는 이미 추출된 rootfs·이미지의 AN-01~09 근거와 coverage를 반환한다. sparse 펼치기·새 파일 시스템 엔진·AVB 서명 검증·증거 폴더 연결은 제공하지 않는다. [설계와 한계](../../docs/design/android-analysis.md)를 참고한다.


## FIT 서명 선언 구조

`fw_sd_surface(image_path=...)`는 기존 env·문자열 분석 뒤 같은 시간 예산으로 비압축 FDT v17을 검색한다.
`fit_security`는 이미지/설정 서명과 control-DTB 형태 키 후보, 검색·구조·목록 완료도를 별도로 기록한다.
저장 JSON과 compact 응답에 같은 section을 남기며 rootfs만 있으면 not-examined다.
검색256 MiB·64후보·32구조·128항목·결과64 KiB의 한도가 있다. 임의 이름·키 힌트·서명/키 바이트는
새 section에 넣지 않는다. 기존 `fit_signature_keys`는 문자열 표지이며 구조 결과와 별개다.

서명 수학 검증·키 신뢰·부팅 강제·SD 경로 연결은 확인하지 않고 기존 SD 위험 상태도 바꾸지 않는다.
`verify=n`은 비활성 환경값 관찰로, 실제 검증 적용은 빌드·부팅 경로·신뢰 키를 추가 확인해야 한다.
한도·부분 결과와 고정 공식 근거는 [FIT 구조 계약](../../docs/references/fit-security-structure.md)을 따른다.
