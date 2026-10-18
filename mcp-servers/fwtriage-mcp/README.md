# pweh-fwtriage (fwtriage-mcp)

외부 도구 없이(순수 Python + PyYAML) 동작하는 **오프라인 펌웨어 트리아지** MCP 서버다.
UART/JTAG/SPI 로 얻은 플래시 덤프나 벤더 펌웨어에서 "어디에 무엇이 있는지"와 "먼저 볼 곳"을 빠르게 뽑아
`cctv-auth-bypass-hunt`, `firmware-static-analysis` Skill 의 1차 근거를 만든다.

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
| 강점 | 덤프 지도, U-Boot env/mtdparts, 파티션 분할, rootfs 구성 감사, CCTV 문자열 휴리스틱, 기본 비밀번호 해시 대조 | 재귀 추출(모든 형식), 디컴파일, xref, 호출 경로 |
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
| `fw_strings_hunt(case_id, path_or_dir, patterns="cctv", max_hits=500, max_results=50, min_severity=None, include=None, min_length=4, utf16=True, per_pattern_cap=50, ...)` | `cctv-hunt-patterns.yaml` 의 `string_heuristics` (scope: strings=ASCII+UTF-16LE 문자열, text=텍스트 줄, raw=바이트). `patterns` 는 `cctv`(전체) 또는 id/category/vendor/severity 선택자, `xm-*` 접두사, `re:<정규식>`, `raw:<바이트 정규식>`, `lit:<문자열>`. `#` 주석 줄의 히트는 별도(`commented_hits`). `checks` 는 auth-hunt 스키마 `checks[]` 형식. `hits[].file` 은 디렉터리·단일 파일 모드 모두 rootfs 절대 경로(rootfs 밖 덤프·파티션 이미지는 `null`), `hits[].path` 는 케이스 상대 경로 (`commented_hits`·`top_files` 도 같음). rootfs 루트는 `fw_extract_squashfs` 트리(`extract/<label>-NNN`, 옆에 `.manifest.json`), 없으면 `etc`+`bin`/`sbin` 을 가진 가장 바깥 상위 디렉터리이고 `summary.rootfs_dirs` 에 적는다. `checks[].evidence_ref` 는 `<file>@<offset_hex>`(file 이 `null` 이면 `<path>@…`). 사용자 패턴의 check id 는 `custom-<lit\|re\|raw>-<sha256 앞 8자>`(같은 패턴이면 실행마다 같은 id, 원문은 `description`), 빈 문자열과 일치하는 사용자 패턴은 건너뛰고 `notes` 에 적는다. `include` glob 은 `path_or_dir` 기준 | `analysis/strings-hunt-NNN.json` |
| `fw_crack_hashes(case_id, hashes=None, source_path=None, wordlist="builtin-defaults", extra_words=None, hash_type=None, max_seconds=60, reveal=False, ...)` | 펌웨어의 해시를 공개 기본 비밀번호 사전과 **오프라인** 대조 (네트워크 로그인 시도 없음). DES crypt(앞 8자), md5crypt/apr1, sha256/512crypt(순수 Python, crypt 모듈 불필요), XiongMai Sofia(`hash_type="xm-sofia"`), 솔트 없는 md5/sha1/sha256 hex, bcrypt/yescrypt(crypt 모듈 지원 시). 공개 하드코딩 해시 일치 표시. 응답의 평문은 기본 마스킹 | `analysis/crack-hashes-NNN.json` (평문 포함 — 케이스 밖 반출 금지) |
| `fw_hunt_patterns(vendor=None, category=None)` | 휴리스틱 목록, 패턴 파일 출처·sha256·오류 | — |
| `fwtriage_job_status(job_id, wait_seconds=0)`, `fwtriage_job_cancel(job_id)`, `fwtriage_jobs(active_only=False)` | `background=true` 로 시작한 작업 폴링/취소. `result` 는 인라인 응답과 같다 | `jobs/<job_id>.json` |

## 데이터 파일

- `src/pweh/data/cctv-hunt-patterns.yaml` — `docs/references/cctv-hunt-patterns.yaml`(사실 확인된 원본)을 **그대로 복사**한 것.
  원본이 바뀌면 `cp docs/references/cctv-hunt-patterns.yaml src/pweh/data/` 로 다시 맞춘다
  (`tests/servers/test_fwtriage_units.py::test_patterns_data_synced_with_reference` 가 차이를 알려준다).
  로더는 YAML notes 의 의미(Python re + MULTILINE, scope, glob)를 따르고, 컴파일 오류는 `fw_hunt_patterns` 의 `errors` 로 보고한다.
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

## 테스트

```
.venv/bin/python -m pytest tests/servers/test_fwtriage_units.py tests/servers/test_fwtriage_mcp.py -q
```

합성 입력(가짜 플래시, 취약 구성 rootfs, 손으로 만든 ELF, zig 로 만든 ARM/MIPS ELF)을 테스트 안에서 만든다.
`mksquashfs`/`unsquashfs`/`zig`/`readelf`/`lz4`/`openssl` 이 필요한 테스트는 `@pytest.mark.external` 이며 없으면 skip 한다.
