---
name: firmware-static-analysis
description: Static analysis of camera/IoT firmware already in the case (UART/JTAG/SPI dump or vendor image), for authorized/owned devices only. Maps the image (fw_identify, entropy, U-Boot env/mtdparts), carves partitions, extracts squashfs/jffs2/UBI (pweh-fwtriage, REA unblob), audits the rootfs (passwd/shadow, telnetd, web servers, setuid, keys), then uses REA + Ghidra to locate authentication logic, hardcoded credentials, backdoor and command-injection candidates and records evidence-backed findings. Trigger words — firmware analysis, static analysis, extract firmware, binwalk, unblob, squashfs, rootfs audit, Ghidra, decompile, hardcoded password, backdoor, auth logic. 펌웨어 분석, 정적 분석, 펌웨어 추출, 루트 파일시스템 감사, 디컴파일, 하드코딩 비밀번호, 백도어, 인증 로직, 명령 주입.
---

# 펌웨어 정적 분석 (firmware-static-analysis)

`orchestrator/master-prompt.md` 의 Phase C 다. 소유/서면 허가가 기록된 케이스에서만 쓴다. 기기를 건드리지 않는 오프라인 분석이다. 결과는 연구·방어용이다(공격 페이로드나 제3자 시스템 공격 없음).
상세 표·응답 필드·오류 코드·발견사항 예시는 [reference.md](reference.md) 에 있다.

## 목적

- 케이스의 펌웨어(덤프 또는 공식 이미지)를 지도화 → 파티션 분할 → 파일시스템 추출 → rootfs 감사 → 관심 바이너리 디컴파일 순서로 분석한다.
- 인증 로직, 하드코딩 자격증명, 백도어, 명령 주입 후보를 **증거(파일 경로·주소·디컴파일 발췌)와 함께** `case_add_finding` 으로 하나씩 기록한다.
- 다음 Skill(cctv-auth-bypass-hunt)이 다시 추출하지 않고 쓸 수 있게 `static-analysis` 요약(추출 경로, rootfs, 관심 바이너리, REA 증거 번들)을 남긴다.

## 언제 쓰나

- **쓴다**: firmware-dump-via-uart 요약이 있거나 사용자가 공식 펌웨어 파일을 줬을 때. "펌웨어 분석/추출/디컴파일", "하드코딩 비밀번호", "백도어 찾기" 요청.
- **쓰지 않는다**
  - 케이스나 소유/허가 증명이 없다 → master-prompt Phase 0 부터.
  - 펌웨어가 아직 없다 → firmware-dump-via-uart, 또는 사람에게 파일 요청(템플릿 A).
  - 동적 검증(웹 요청, 로그인 시도), 퍼징, 펌웨어 쓰기·업데이트 → 이 Skill 범위 밖.
  - CCTV/DVR 벤더별 인증 우회 패턴 전수 점검(P1~P12 checks, 인증 전 디스패치 표) → cctv-auth-bypass-hunt. 이 Skill 의 요약을 입력으로 쓴다.

## 전제 조건

- **case_id**: `case_get` 의 case.authorized 가 true 여야 한다. 아니면 멈추고 master-prompt §1-1 로 돌아간다.
- **이전 요약** (`case_get_step_results(case_id)`):
  - firmware-dump-via-uart → data.output.path / sha256 / size, data.verification.match, data.method, data.partitions(따로 받은 파티션 파일은 partitions[].path·sha256), data.source.flash_type.
  - uart-shell-acquisition → data.linux.mtd(/proc/mtd 표), data.uboot.mtdparts 또는 data.linux.cmdline 의 mtdparts, data.device_info.arch (교차 확인용).
  - 이전 firmware-static-analysis 요약이 있으면 그 extraction.output_dir·rootfs.path 를 재사용하고 빠진 단계만 한다.
- **하드웨어**: 필요 없다. 기기 연결도 필요 없다.
- **MCP 서버**: pweh-case, pweh-fwtriage, rea (Ghidra·JDK·binwalk·unblob 경로는 `~/pweh-tools/env.sh`). squashfs 추출에는 unsquashfs 가 필요하다.

## 안전 규칙

1. **오프라인 분석만 한다.** 하드웨어 도구를 부르지 않는다. 추출물의 코드는 어떤 방식으로도 실행하지 않는다 (qemu·chroot·추출된 스크립트 실행 금지). REA 의 런타임 도구(Frida, GDB, rizin 디버거, capture_process_scenario 등)는 이 Skill 에서 쓰지 않는다.
2. **케이스 밖에 쓰지 않는다.** 새 출력 경로는 `case_paths` 로만 받는다. 기존 추출 디렉터리와 증거 파일을 지우거나 덮어쓰지 않는다 (overwrite 는 false 유지).
3. **비밀값**: fw_crack_hashes 는 오프라인 대조만 한다. 응답은 기본 마스킹이다. reveal=true 는 사용자가 자기 기기 로그인에 평문이 필요하다고 명시할 때만 쓴다(템플릿 E). 사전 결과로 네트워크 로그인을 시도하지 않고, 같은 모델의 제3자 기기에 쓰지 않는다. 발견사항 excerpt 의 비밀번호·토큰·키는 마스킹한다.
4. **execute_rizin_command 는 읽기 전용 정보 명령만** 보낸다 (`iI`, `ii`, `is`, `iz`). 쓰기(`w`), 셸(`!`), 스크립트 로드, 쓰기 모드 열기는 금지다. 이 도구는 열린 Ghidra 세션을 닫으므로 먼저 6-6 을 끝낸다.
5. **정직하게 기록한다.** 문자열 히트만 있으면 possible/unverified 다. 디컴파일로 경로를 확인했으면 confirmed/static-confirmed 다. 기기에서 확인하기 전에는 dynamically-confirmed 를 쓰지 않는다.
6. **verification_plan 에 공격 페이로드·완성된 요청을 쓰지 않는다.** 격리 랩의 소유 기기, 수정 빌드와의 비교, 자격증명 없는 요청이 거부되는지 보는 negative test 만 적는다.
7. **게이트**: 이 Skill 의 도구는 기기 게이트 대상이 아니다. 그래도 응답이 `status: approval_required` 면 master-prompt §1-2 를 따른다(설명 → 사용자가 별도 터미널에서 `pweh approve <id>` → 같은 인자 + approval_id 로 1회 재시도). `status: denied` 면 우회하지 않고 보고한다.

## 사용하는 MCP 도구

| 도구 | 용도 |
|---|---|
| `case_get`, `case_get_step_results`, `pipeline_profile` | 권한·이전 요약·프로필 힌트(firmware.web_servers, config_paths, arch) |
| `case_paths` | 절대 경로 기준(case_dir, analysis_dir)과 REA 용 새 출력 디렉터리(new_output_dir) |
| `case_set_phase`, `case_import_file`, `case_update_target` | 단계 표시, 공식 이미지 반입, SoC·펌웨어 버전 갱신 |
| `fw_identify`, `fw_entropy` | 덤프 지도(영역·형식·CRC), 압축/암호화 후보 구간 |
| `fw_uboot_env`, `fw_carve`, `fw_uimage_info` | env·mtdparts, 파티션 분할, uImage/FIT 헤더 |
| `fw_extract_squashfs` | squashfs 추출 + 원본 모드/setuid 매니페스트 |
| `fw_rootfs_audit`, `fw_strings_hunt`, `fw_hunt_patterns` | rootfs 감사, CCTV 문자열 휴리스틱, 휴리스틱 목록 |
| `fw_elf_info`, `fw_crack_hashes` | ELF 위험 순위·상세, 기본 비밀번호 오프라인 대조 |
| `fwtriage_job_status`, `fwtriage_jobs` | background=true 로 시작한 fwtriage 작업 폴링 (wait_seconds ≤ 50), 남은 작업 확인 |
| `inspect_firmware_regions`, `extract_firmware` | REA binwalk 교차 확인, REA unblob 추출 (jffs2/UBI/cramfs/ext 등) |
| `open_binary`, `binary_overview`, `binary_session`, `close_binary` | Ghidra 세션 열기·분석 시작·상태·닫기 |
| `search_procedures`, `search_strings`, `trace_feature` | 인증 관련 함수·문자열 찾기, 문자열 → 사용 함수 |
| `find_xrefs_to_name`, `xrefs`, `procedure_callers` | system/popen/strcmp 등 참조 위치, 호출자 |
| `procedure_pseudo_code`, `batch_decompile`, `analyze_function`, `inspect_native_api` | 디컴파일, 함수 dossier, 디스패치(jump table) |
| `trace_call_path` | 요청 핸들러 → 위험 싱크 경로 |
| `get_evidence_bundle`, `export_evidence_bundle`, `case_register_artifact` | REA 증거 확인·내보내기·케이스 등록 |
| `inspect_with_objdump`, `execute_rizin_command` | REA 가 바이너리를 거부할 때의 대체 엔진 |
| `case_add_finding`, `case_update_finding`, `case_record_step` | 발견사항 기록·갱신, 최종 summary |

## 절차

### 0. 시작: 권한·입력·경로 확정

목표는 분석할 펌웨어 1개(셸 경로 덤프면 파티션 파일 여러 개)와 절대 경로 기준을 정하는 것이다.

```
case_get(case_id="<id>")                                   → case.authorized, case.profile
case_get_step_results(case_id="<id>")                      → summaries{...}, missing[...]
pipeline_profile(name="<case.profile>")                    → profile.firmware.web_servers / config_paths, profile.arch
case_paths(case_id="<id>", purpose="extract", label="rea") → case_dir, analysis_dir, new_output_dir (모두 절대 경로)
case_set_phase(case_id="<id>", phase="firmware-static-analysis", status="in-progress")
```

- 펌웨어 선택 순서:
  1. firmware-dump-via-uart 요약의 data.output.path (JTAG·SPI 클립 덤프도 이 요약으로 남는다, master-prompt §5). verification.match 가 true 가 아니면 분석은 하되 notes 에 "무결성 미확인"을 적는다.
     method 가 linux-*(셸 경로)이거나 범위를 나눠 받았으면 output 은 한 파티션(또는 우선 범위)뿐이다. data.partitions[] 중 path 가 있는 파일(kernel, app 등)도 분석 대상에 넣는다. 이미 나뉜 파일이므로 fw_carve 없이 1·3단계로 간다.
  2. 요약은 없는데 `case_get(case_id="<id>", include_artifacts=true)` 에 kind `flash-dump` 아티팩트가 있으면(요약 없이 남은 JTAG·SPI 덤프) 그 파일을 쓰고 출처를 사용자에게 확인한다.
  3. 사용자가 준 공식 이미지: `case_import_file(case_id="<id>", source_path="/home/me/fw/IPC_5.5.0.bin", kind="firmware-image", description="vendor download")` → artifact.path(케이스 상대), artifact.sha256, absolute_path. firmware.source 는 "vendor-download" 이고, 실제 기기 펌웨어와 다를 수 있다고 notes 에 적는다.
  4. 셋 다 없으면 멈추고 템플릿 A 로 요청한다.
- **경로 규칙**: fwtriage 는 케이스 상대 경로(`dumps/flash-full.bin`, `extract/rootfs-001`)를 받는다. REA 는 **절대 경로만** 받는다. REA 에는 case_dir + "/" + 상대 경로를 넘긴다 (예: `<case_dir>/extract/rootfs-001/usr/sbin/httpd`). 상대 경로는 Input validation error 로 거부된다. fw_extract_squashfs 는 output_dir_abs 도 준다.

### 1. 펌웨어 지도: 식별과 엔트로피

```
fw_identify(case_id="<id>", path="dumps/flash-full.bin")
fw_entropy(case_id="<id>", path="dumps/flash-full.bin")
```

- fw_identify 에서 볼 것: summary.kinds·arch_hints·uboot_versions·linux_versions, regions[](offset_hex, kind, size, confidence, details — uImage 의 header_crc_ok/data_crc_ok, squashfs 의 compression·endianness·nonstandard), next_steps.
- fw_entropy 에서 볼 것: high_runs[] 의 distribution·known_coverage·note, unexplained_high_entropy_runs. known_coverage < 0.5 인 균일 고엔트로피는 암호화·난독화 **후보**다.
- 판단
  - squashfs/jffs2/UBI/cramfs 영역이 보이면 → 2단계.
  - 영역이 거의 없고 이미지 대부분이 설명되지 않는 고엔트로피 → 암호화된 벤더 업데이트 이미지일 수 있다. 해독을 시도하지 않는다. extraction.status 를 "failed" 로 두고 템플릿 B 로 플래시 덤프를 요청한 뒤 9단계(summary status "blocked")로 간다.
  - 부트 영역(앞쪽 수백 KiB) 안의 설명되지 않는 고엔트로피만 있으면 펌웨어 전체가 암호화됐다고 판단하지 않는다. identification.entropy 에 기록만 한다.
- 교차 확인(선택): `inspect_firmware_regions(path="<case_dir>/dumps/flash-full.bin")`. binwalk 결과는 가설이다. 시뮬레이터 이미지에서 uImage·squashfs 오프셋은 fw_identify 와 같았지만 U-Boot env 는 찾지 못했고, 이전 빌드에서는 S-record 오탐이 uImage 와 rootfs 를 가린 적도 있다. fw_identify 를 기본 지도로 쓰고 차이를 identification.regions_crosscheck 에 적는다.
- 실패 처리: summary.timed_out 이 true 이거나 이미지가 크면 `background=true` 로 다시 부르고 `fwtriage_job_status(job_id="<job>", wait_seconds=30)` 로 폴링한다.

### 2. 파티션: U-Boot env → 분할 → 커널 헤더

```
fw_uboot_env(case_id="<id>", path="dumps/flash-full.bin")
fw_carve(case_id="<id>", path="dumps/flash-full.bin")                       # 레이아웃 인자 없음 = 자동
fw_uimage_info(case_id="<id>", path="extract/parts-001/02-kernel.bin")
```

- fw_uboot_env: envs[].env(bootargs, bootcmd), envs[].mtdparts, recommended_layout(source, text, partitions), embedded_default_envs, mtdparts_strings. redundant 쌍이면 active_guess 를 본다.
- fw_carve 자동 레이아웃 순서: CRC 가 맞는 env(mtdparts 변수, bootargs 의 mtdparts=) → U-Boot 내장 기본 env → 이미지 속 mtdparts= 문자열 → DTB partition 노드. 응답 partitions[] 의 파일 경로는 **path**(케이스 상대 경로)다(`file` 은 같은 값의 하위 호환 별칭). content(squashfs, uimage, uboot-env, bootloader …), status, layout.source, warnings 를 기록한다.
- 파티션 시작 형식이 맞지 않으면 레이아웃을 바꿔 다시 분할한다. 출처는 uart-shell-acquisition 의 mtdparts(`fw_carve(..., mtdparts="mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app)")`)나 fw_identify 오프셋(`partitions=[{"name": "rootfs", "offset": "0x250000", "size": "5M"}]`)이다. 숫자는 10진 기준이고 선행 0 은 경고만 나온다.
- 레이아웃을 끝내 못 정하면 분할 없이 fw_identify 의 squashfs 오프셋으로 3단계에 간다.
- fw_uimage_info: image.name·arch·os·compression, header_crc_ok/data_crc_ok, load_address/entry_point, payload_probe. FIT/DTB 면 images·configurations·partition 노드. 커널 자체 분석은 범위 밖이고 버전과 CRC 만 기록한다.
- 새로 확인한 정보만 `case_update_target(case_id="<id>", target={"soc": "hi3516ev300", "firmware_version": "<uImage 이름 또는 /etc/version>"})` 로 갱신한다.

### 3. 파일시스템 추출

**squashfs** (가장 흔함):

```
fw_extract_squashfs(case_id="<id>", path="extract/parts-001/03-rootfs.bin")                    # → extract/rootfs-001
fw_extract_squashfs(case_id="<id>", path="extract/parts-001/04-app.bin", output_label="app")  # → extract/app-001
```

- 볼 것: status, output_dir, output_dir_abs, manifest_path(원본 모드·소유자·setuid 보존), listing(setuid, setgid, world_writable_files), warnings(장치 노드 미생성은 정상). 분할을 못 했으면 `path="dumps/flash-full.bin", offset="0x250000"` 로 부른다.
- tool_missing 오류 → 템플릿 D, 또는 아래 REA 경로로 간다.
- 목록 안전 검사(`..` 경로 탈출, 링크 아래 항목)에 걸려 거부되면 allow_listing_anomalies 를 켜지 않는다. gap 으로 기록하고 REA 로 그 파티션만 추출한다.

**jffs2 / UBI·UBIFS / cramfs / ext\* / erofs / romfs** (fwtriage 는 식별만 한다): REA unblob 으로 추출한다.

```
case_paths(case_id="<id>", purpose="extract", label="rea")   → new_output_dir (예: <case_dir>/extract/rea-001, 아직 없음)
extract_firmware(path="<case_dir>/extract/parts-001/04-app.bin", output_directory="<new_output_dir>")
case_register_artifact(case_id="<id>", path="extract/rea-001", kind="extracted-tree", producer="rea")
```

- 볼 것(normalized_result): coverage(complete|partial), files[](정규 파일만, 실행 비트 없음), unpublished_entries[](심볼릭 링크는 메타데이터로만), extraction_gaps[](kind, range, continuation_id) + extraction_continuations[](복구 안내), depth_limited_paths.
- coverage 가 partial 이어도 원인이 unpublished-entry(심볼릭 링크)와 부트로더·패딩 영역뿐이면 문제없다. extraction.gaps 에는 kind 별 개수와 의미 있는 영역만 요약한다. 행을 통째로 붙이지 않는다.
- depth_limited_paths 가 있으면 새 new_output_dir 와 max_depth(최대 10)로 다시 추출한다.
- 제한과 오류
  - 입력 파일은 128 MiB 이하다. range 를 줘도 파일 크기로 거부된다(`invalid_request`, reason out_of_range). 큰 덤프는 fw_carve 로 나눈 파티션 파일을 넘긴다.
  - output_directory 는 존재하지 않는 절대 경로여야 하고, 부모는 있어야 한다. 이미 있으면 `execution_failure` 와 "rea doctor" 안내가 오지만 실제 이유는 error.details.diagnostics.reason("Extraction output root already exists")에 있다. 지우지 말고 case_paths 로 새 경로를 받아 한 번만 다시 한다.
- REA 트리를 fw_rootfs_audit 에 넘기면 매니페스트가 없어 setuid·심볼릭 링크 정보가 빠진다(limitations 에 표시, fs_type null). squashfs 는 fw_extract_squashfs 트리를 우선한다.
- 하나도 못 풀었으면(암호화, 미지원 형식, NAND OOB 섞인 덤프) extraction.status 를 "failed" 로 두고 9단계로 간다.

### 4. rootfs 감사

```
fw_rootfs_audit(case_id="<id>", rootfs_dir="extract/rootfs-001")
fw_strings_hunt(case_id="<id>", path_or_dir="extract/rootfs-001")               # 필터 없이 먼저
fw_crack_hashes(case_id="<id>", source_path="extract/app-001/passwd.cfg")       # 필요할 때만 (아래)
```

- fw_rootfs_audit: rootfs(static-analysis 스키마의 rootfs 모양 그대로), items[](id, category = finding 어휘, severity 힌트, file, line, excerpt), accounts[], services[](telnetd -l /bin/sh 등), web_servers[], binaries_of_interest[], vendor.family·family_source(판정 근거, cctv-auth-bypass-hunt 2단계), summary.manifest_used, limitations.
  - accounts 에 이상한 항목(예: user "0", uid null)이 있으면 파서 아티팩트일 수 있다. 원본 줄을 확인하기 전에는 발견사항으로 올리지 않는다.
- fw_strings_hunt: patterns 기본값 "cctv" 로 전체를 먼저 본다. min_severity 는 정리용으로만 쓴다. 검증에서 "high" 필터가 ping 명령 템플릿(medium)을 숨겼다. 볼 것: hits[](file, path, offset_hex, pattern_id, category, severity, match), matched_checks, top_files, result_path(전체 JSON, commented_hits 포함). hits[].file 은 rootfs 절대 경로(추출 트리 밖 파일이면 null), hits[].path 는 다른 도구에 넘길 케이스 상대 경로다.
- **문자열 히트는 단서다.** 6-2 의 trace_feature 로 어떤 함수가 쓰는지 확인하기 전에는 severity 를 확정하지 않는다. 검증에서 하드코딩 Basic 헤더 문자열(high)은 인증 경로가 아니라 selftest 함수에 있었다. 반대로 백도어 토큰은 low 등급 일반 키워드 히트(합성 문자열 안의 "BACKDOOR")로만 잡혔고, 인증을 건너뛰는 역할은 check_auth 디컴파일에서 드러났다.
- fw_crack_hashes: fw_rootfs_audit 가 passwd/shadow 의 기본 비밀번호 대조를 이미 한다(crack_defaults). 설정 파일·htpasswd·바이너리에서 나온 해시, XiongMai 8자 해시(hash_type="xm-sofia")에 쓴다. 응답 password 는 마스킹("12****")되고 평문은 analysis/crack-hashes-NNN.json 에만 있다. not_cracked 는 "안전"이 아니다.
- 오래 걸리면 `background=true` + fwtriage_job_status. rootfs 가 여럿(rootfs, app, config)이면 각각 감사한다.

### 5. 관심 바이너리 선정

```
fw_elf_info(case_id="<id>", path="extract/rootfs-001")                  # 디렉터리: 위험 점수 순위
fw_elf_info(case_id="<id>", path="extract/rootfs-001/usr/sbin/httpd")   # 단일 파일: 상세
```

- 후보를 합친다: rootfs_audit 의 binaries_of_interest·web_servers·services, profile.firmware.web_servers, init 스크립트가 띄우는 벤더 데몬, ELF CGI, 인증 관련 공유 라이브러리(lib*auth*, lib*http*, lib*web* .so), elf_info 디렉터리 순위 상위(score, risky.command-exec, network_facing_hint).
- 우선순위: ① 네트워크 대면 웹/메인 앱 ② CGI·인증 라이브러리 ③ 부팅 때 뜨는 비표준 데몬(디버그 포트 리스너) ④ 나머지. 패치 흔적이 없는 BusyBox·표준 libc 는 뺀다. 벤더별 이름표: [reference.md §4](reference.md#4-관심-바이너리-선정표).
- 단일 상세에서 볼 것: elf.machine·flags(ISA, ABI), static/interpreter/needed, stripped, defined_function_count, hardening(nx, relro, pie, stack_canary), risk.heuristics(fn-command-exec, fn-auth-literal-compare, fn-uri-substring-match …), unbounded_scanf_formats.
- 상위 3~5개만 6단계로 깊게 본다. 나머지는 binaries_of_interest 에 reason 과 analyzed_with "none" 으로 남긴다.
- rootfs.path 밖의 트리(app·config 파티션, 예: extract/app-001)에 있는 바이너리는 항목에 `tree`(그 트리의 케이스 상대 경로)를 붙이고, path 는 그 트리 기준 절대 경로로 쓴다. 다음 Skill 이 `<case_dir>/<tree><path>` 로 파일을 찾는다.
- 절대 경로 심볼릭 링크(예: bin/sh → /bin/busybox)를 넘기면 검증 오류가 난다. 트리 안의 실제 대상(extract/rootfs-001/bin/busybox)을 넘긴다.

### 6. REA + Ghidra 심층 분석 (바이너리마다 반복)

**철칙: 쿼리 → `export_evidence_bundle` → `case_register_artifact` → `close_binary` 순서를 지킨다.** close_binary 와 다른 대상으로의 open_binary 는 세션에 쌓인 증거를 버린다(검증: close 뒤 레코드 0건). execute_rizin_command 도 열린 세션을 닫는다.

**6-1 열기와 분석 시작**

```
open_binary(path="<case_dir>/extract/rootfs-001/usr/sbin/httpd", provider_id="ghidra")  → result.format, architecture, sha256
binary_overview()                                                                       → procedure_count, string_count, segments, image_base
```

- Ghidra 자동 분석은 open_binary 가 아니라 **첫 쿼리**에서 돈다. 그래서 binary_overview 를 먼저 불러 대기 시간을 한곳에 모은다. 1.7 MB 정적 ARM 바이너리는 약 15초, 큰 벤더 바이너리는 수 분이 걸린다. 분석이 끝나야 결과가 나온다(부분 결과 없음).
- 오류 `target_unavailable`("unsupported binary format", constraint file_format_rejected): 셸 스크립트 CGI, raw uImage/커널 등이다 → 7단계. ARM EABI5 와 MIPS32r2 o32 LE ELF 는 검증에서 정상 디컴파일됐다.
- 클라이언트 타임아웃(Codex·Cursor 의 60초 등)으로 끊기면 `binary_session()` 으로 상태를 보고 템플릿 C 로 알린다. 작은 바이너리부터 하거나 타임아웃을 늘린 뒤 다시 한다. 요청을 취소하면 Ghidra 임시 DB 가 버려지고 다음 쿼리에서 다시 임포트된다.

**6-2 인증 앵커 찾기**

```
search_procedures(pattern="(?i)auth|login|passw|cred|session|token|verify", mode="regex")
search_strings(pattern="(?i)passw|login|auth|admin|token|session|realm|nonce|basic |digest", mode="regex")
trace_feature(query="Authorization: Basic")      # 정확한 문자열 → references[].containing_procedure
```

- search_* 결과는 [{address, value}] 다. Ghidra 가 정의한 문자열만 보므로 빈 결과가 "없음"의 증거는 아니다. fwtriage 히트(offset_hex)와 같이 본다.
- 4단계의 critical/high 문자열마다 trace_feature 로 사용 함수를 확인한다. stripped 바이너리는 함수가 FUN_xxxxxxxx 로 나오므로 문자열 → 함수 경로가 주 수단이다.

**6-3 위험 싱크와 비교 함수**

```
find_xrefs_to_name(name="system")        # popen, execve, execl, execv, execvp, posix_spawn 도
find_xrefs_to_name(name="strcmp")        # strncmp, strcasecmp, memcmp, strstr 도
procedure_callers(procedure="system")    → 호출 함수 주소 목록
```

- 응답은 status "resolved" + address + xrefs[], 또는 status "unresolved" + reason "name_not_found" 다. stripped 정적 바이너리는 libc 이름이 없을 수 있다. 그때는 명령 템플릿 문자열("ping -c", "sh -c")을 trace_feature 로 따라간다.
- xrefs 의 `.debug_frame:0x…` 같은 비코드 주소는 무시한다.

**6-4 디컴파일**

```
procedure_pseudo_code(procedure="check_auth")                           # 이름 또는 0x 주소
batch_decompile(addresses=["check_credentials", "is_static_resource"])
analyze_function(procedure="handle_ping_cgi")                           # callers/callees/referenced_strings/basic_blocks (출력 ~100 KB)
inspect_native_api(procedure="handle_client")                           # 시그니처, jump table 디스패치
```

- 표시할 것: 요청 값과 .rodata 리터럴 비교가 곧바로 성공 return(백도어·하드코딩), 인증 함수 앞의 "정적 리소스면 통과" 분기(strstr 부분 문자열), 요청 값으로 신뢰를 결정하는 분기, 해시 직접 비교, sprintf/snprintf 결과가 필터 없이 system/popen 으로 감, 고정 스택 버퍼로의 무제한 복사. 패턴과 category 매핑: [reference.md §6](reference.md#6-디컴파일에서-표시할-패턴과-category).
- 발췌는 판단에 필요한 줄만 짧게 남기고 비밀값은 마스킹한다.

**6-5 요청 처리 → 싱크 경로**

```
trace_call_path(start="handle_client", goal="system")   → goal_status "reached", traversal_path ["0x22084", "0x22470", "0x23d14"]
trace_call_path(start="system", direction="backward")   → 싱크에 도달하는 호출자 사슬 (진입점 찾기)
```

- goal_status 가 reached 가 아니고 residual_unknowns 가 있으면 간접 호출 때문에 "모름"이다. 경로가 없다는 증거로 쓰지 않는다.
- 디스패처를 디컴파일해 인증 검사(check_auth 류)가 핸들러 호출 앞에 있는지 보고 "인증 전/후"를 적는다.

**6-6 증거 내보내기와 닫기**

```
get_evidence_bundle(detail="summary")                                       → total_retained_records (선택)
export_evidence_bundle(path="<analysis_dir>/rea-evidence-httpd-001.json")   → result.path, bytes, records, unknowns
case_register_artifact(case_id="<id>", path="analysis/rea-evidence-httpd-001.json", kind="rea-evidence", producer="rea")
close_binary()
```

- 파일 이름은 rea-evidence-<바이너리 이름>-NNN.json 이다. "Evidence file already exists"(`invalid_request`, reason exists)면 덮어쓰지 말고 NNN 을 올린다. 부모가 없으면 "Evidence output directory does not exist" 가 나온다 → analysis_dir 를 쓴다.
- 각 REA 응답의 evidence_id 를 기억해 두었다가 발견사항 evidence 의 ref 에 번들 경로와 함께 적는다.

### 7. REA 가 거부하거나 쓸 수 없을 때

- 거부 사유(error.code, details.reason, details.constraint)를 rea.limitations 에 적는다.
- 셸 스크립트 CGI·설정 파일은 텍스트로 본다: `fw_strings_hunt(case_id="<id>", path_or_dir="extract/rootfs-001/var/www/cgi-bin")` 와 rootfs_audit items 의 file/line/excerpt. evidence type 은 file, string, config 를 쓴다.
- 거부된 ELF:

```
fw_elf_info(case_id="<id>", path="extract/rootfs-001/usr/bin/vendor_daemon")       # 임포트·위험 함수·보호기법
fw_strings_hunt(case_id="<id>", path_or_dir="extract/rootfs-001/usr/bin/vendor_daemon", patterns=["lit:login", "re:(?i)debug_?mode"])
inspect_with_objdump(operation="architectures")              # 한 번만: 대상 아키텍처 지원 여부
inspect_with_objdump(path="<abs path>", operation="symbols")
execute_rizin_command(path="<abs path>", command="iI")       # 읽기 전용 명령만
```

- 이 환경의 objdump 는 호스트(x86)용이라 MIPS ELF 에 `architecture: UNKNOWN!` 을 냈다. ARM/MIPS 디스어셈블(`disassemble`)에 기대지 말고 symbols·section_headers 정도만 쓴다.
- execute_rizin_command 가 `capability_unavailable`("Unable to run configured command (ENOENT)")이면 rizin 이 없는 것이다. 건너뛴다.
- 대체 경로만으로 얻은 발견사항은 confidence 가 최대 likely(문자열 + 임포트 구조 일치), 대개 possible 이고 status 는 unverified 다.

### 8. 발견사항 기록

후보마다 한 번 부른다. 아래는 검증 케이스(합성 펌웨어)의 실제 결과다. 다른 예시는 [reference.md §7](reference.md#7-발견사항-예시).

```
case_add_finding(case_id="<id>", finding={
  "title": "httpd check_auth 의 하드코딩 토큰 비교로 인증 생략",
  "category": "backdoor", "severity": "critical", "confidence": "confirmed", "status": "static-confirmed",
  "summary": "check_auth 가 요청 token 필드를 고정 문자열과 strcmp 해 일치하면 자격증명 검사 없이 1(인증 성공)을 반환한다.",
  "location": {"firmware": "dumps/flash-full.bin", "file": "/usr/sbin/httpd", "function": "check_auth",
               "address": "0x2235c", "interface": "http"},
  "evidence": [
    {"type": "decompilation", "ref": "analysis/rea-evidence-httpd-001.json#ev_1fb00ae8271ba615549c52382b19f9b3236ce7e126ce20b0de51c05cd0b97e5d",
     "excerpt": "if ((req->token[0] != '\\0') && (strcmp(req->token, \"<고정 문자열, 마스킹>\") == 0)) { return 1; }"},
    {"type": "string", "ref": "/usr/sbin/httpd@0xe7d", "excerpt": "36자 고정 문자열 (마스킹), VA 0x10e7d"}
  ],
  "reasoning": "handle_client 는 모든 요청에서 check_auth 를 먼저 부르고, check_auth 는 토큰 일치 시 Basic 인증 검사 전에 성공을 반환한다 (패턴 P4/P6). 같은 펌웨어의 모든 기기에 같은 값이 있다.",
  "verification_plan": "격리 랩의 소유 기기에서만: 자격증명 없는 요청이 401 로 거부되는지(negative test) 확인하고, 수정 빌드가 있으면 check_auth 를 디컴파일 diff 한다. 토큰을 실은 요청은 보내지 않는다.",
  "remediation": "하드코딩 토큰 분기를 제거하고 모든 경로가 check_credentials 를 거치게 한다.",
  "produced_by": {"skill": "firmware-static-analysis", "tool": "rea procedure_pseudo_code (ghidra)"}
})
→ finding_id "F-001", duplicate false
```

- 필수 필드: title, category, severity, confidence, status, summary, location(최소 1개 필드), evidence(1개 이상, 각 type·ref), reasoning. id 는 서버가 붙인다.
- evidence 규칙: decompilation/rea-evidence 의 ref 는 "<번들 경로>#<evidence_id>", triage 의 ref 는 fwtriage result_path(+ file·line 은 excerpt 나 location 에), string 의 ref 는 "<rootfs 경로>@<파일 오프셋>"(fwtriage offset_hex; REA 가상 주소는 excerpt 나 location.address 에).
- location.file 은 rootfs 절대 경로(`/usr/sbin/httpd`, fw_strings_hunt 의 hits[].file)로 정규화한다. 케이스 상대 경로(hits[].path)를 그대로 쓰지 않는다. rootfs.path 밖 트리의 파일이면 location.tree 에 그 트리를 함께 적는다.
- confidence: confirmed = 디컴파일로 경로 확인, likely = 문자열과 구조가 일치, possible = 문자열 히트만. status: 정적 확인을 마치면 static-confirmed, 그 전은 unverified.
- 서버는 title + location(file, function, address)이 같으면 기존 항목을 돌려준다(duplicate true). 그 id 도 finding_ids 에 넣는다. 나중에 확신이 바뀌면 `case_update_finding(case_id="<id>", finding_id="F-001", patch={"status": "static-confirmed"})`.
- fw_rootfs_audit items 는 category·severity 힌트가 이미 finding 어휘다. telnetd 기동, 기본 비밀번호 같은 항목은 evidence type "triage"(ref = result_path)와 "file"(ref = rootfs 경로)로 기록한다.

### 9. 요약 저장

먼저 `binary_session()` 의 result.open 이 false 이고 `fwtriage_jobs(active_only=true)` 가 비어 있는지 확인한다.
그다음 출력 절의 `case_record_step` 를 부른다. 서버가 스키마 검증에 실패하면 메시지대로 data 를 고쳐 다시 저장한다. summary 저장이 케이스의 단계(phase) 상태도 갱신한다.

- status: success = rootfs 를 추출해 감사하고 상위 바이너리를 분석함. partial = 일부 파티션 미추출, REA 거부로 대체 경로만 씀, 시간 부족으로 상위 바이너리 일부 미분석. failed = 파일시스템을 하나도 못 풂. blocked = 펌웨어 없음·암호화 이미지·도구 누락으로 사람 조치가 필요함.
- extraction.status: complete = 분석 대상 파일시스템(rootfs, app, config)을 모두 풀었고 남은 gap 이 부트로더·패딩·심볼릭 링크뿐. partial = 파일시스템이나 코드 영역 일부를 못 풂. failed = 하나도 못 풂. skipped = 입력이 이미 추출된 트리.

## 사람에게 요청할 일

**A. 펌웨어가 없을 때**
```
[확인 필요] 분석할 펌웨어 파일
케이스에 펌웨어가 없습니다. 둘 중 하나를 알려 주세요.
1. 이 기기의 공식 펌웨어 파일 경로 (모델·하드웨어 리비전이 같은 것). 실제 기기 펌웨어와 다를 수 있다고 보고서에 적습니다.
2. 기기에서 직접 덤프하기 → firmware-dump-via-uart 단계로 돌아갑니다.
```

**B. 암호화된 이미지로 보일 때**
```
[확인 필요] 펌웨어가 암호화된 것으로 보입니다
- 근거: fw_entropy 에서 이미지의 <N>% 가 알려진 형식으로 설명되지 않는 균일 고엔트로피입니다 (analysis/entropy-001.json).
- 업데이트 파일은 암호화돼도 플래시 내용은 평문인 경우가 많습니다. UART/SPI 로 플래시를 덤프할 수 있을까요?
- 복호화된 이미지가 이미 있다면 경로를 알려 주세요. 제가 해독을 시도하지는 않습니다.
```

**C. Ghidra 분석이 오래 걸릴 때**
```
[안내] /usr/sbin/<이름> (<크기> MB) 디컴파일 준비 중입니다. Ghidra 첫 분석은 수 분 걸릴 수 있습니다.
Codex/Cursor 처럼 도구 타임아웃이 60초인 클라이언트라면 늘려 주세요 (예: Codex tool_timeout_sec = 1800).
그동안 작은 바이너리부터 진행하겠습니다.
```

**D. 외부 도구가 없을 때**
```
[사람 작업 필요] <unsquashfs | binwalk | unblob | Ghidra/JDK> 가 없습니다 (오류: <tool_missing 메시지>).
docs/mcp-setup.md 의 설치 절차를 따르거나 ~/pweh-tools/env.sh 를 확인한 뒤, 별도 터미널에서 `pweh doctor` 와 `rea doctor` 결과를 알려 주세요.
설치 전까지는 fwtriage 결과만으로 진행합니다.
```

**E. 평문 비밀번호가 필요한지 확인**
```
[확인 필요] 계정 'root' 의 비밀번호가 공개 기본 비밀번호와 일치합니다 (12****).
평문은 케이스 안 analysis/crack-hashes-001.json 에만 있습니다. 본인 기기 UART 로그인에 평문이 꼭 필요하면 말씀해 주세요.
다른 기기나 네트워크 로그인에는 쓰지 않습니다.
```

## 성공·실패 기준

- **성공**
  - 펌웨어 경로·sha256·출처가 기록되어 있다.
  - 파티션 레이아웃 출처와 추출 결과(output_dir, gap 요약)가 있다.
  - rootfs 감사·문자열 휴리스틱 결과(result_path)가 있다.
  - 관심 바이너리마다 분석 방식(rea-ghidra / fallback / none)이 적혀 있다.
  - 분석한 바이너리마다 증거 번들이 케이스에 등록되어 있다.
  - 발견사항마다 위치·증거·추론·정직한 confidence/status 가 있다.
  - summary 가 스키마 검증을 통과했다. 열린 REA 세션과 실행 중 fwtriage job 이 없다.
- **실패·중단**: 파일시스템을 하나도 못 풂, 암호화 이미지, 도구 누락. 이유를 blockers 에 남기고 status failed/blocked 로 summary 를 저장한다.
  펌웨어 파일이 아예 없으면 firmware(path, sha256)가 필수라 summary 를 만들 수 없다. 다른 Skill 과 같이 summary 가 아닌 step 으로 남긴다:
  `case_record_step(case_id="<id>", skill="firmware-static-analysis", step="input", status="blocked", summary="분석할 펌웨어 없음", blockers=["…"])` → `case_set_phase(case_id="<id>", phase="firmware-static-analysis", status="blocked")`.

## 출력

검증 케이스(시뮬레이터 hisilicon-like 이미지를 UART 로 덤프했다고 가정)의 값으로 채운 예시다. 이 data 는 `static-analysis` 스키마 검증을 통과했다.

```json
{
  "firmware": {"path": "dumps/flash-full.bin", "sha256": "da4bea216008ac0dc31bd0aceb193360b007daefa8ca30dacc858e5f8bb6f970", "size": 16777216, "source": "uart-dump"},
  "identification": {
    "arch": "arm", "endianness": "little", "arch_flags": "EABI5, soft-float", "soc": "hi3516ev300",
    "bootloader": "U-Boot 2016.11 (Mar 23 2020 - 14:58:03 +0800)hi3516ev300",
    "kernel": {"uimage_name": "Linux-4.9.37", "compression": "none", "header_crc_ok": true, "data_crc_ok": true, "load_address": "0x40008000"},
    "uboot_env": {"offset": "0x40000", "size": 65536, "crc_ok": true, "redundant": false, "bootcmd": "sf probe 0; sf read 0x42000000 0x50000 0x200000; bootm 0x42000000"},
    "mtdparts": {"source": "uboot-env@0x40000:bootargs", "text": "mtdparts=hi_sfc:256k(boot),64k(env),2048k(kernel),5120k(rootfs),-(app)"},
    "partitions": [
      {"name": "boot", "offset": "0x0", "size": 262144, "content": "bootloader", "file": "extract/parts-001/00-boot.bin"},
      {"name": "env", "offset": "0x40000", "size": 65536, "content": "uboot-env", "file": "extract/parts-001/01-env.bin"},
      {"name": "kernel", "offset": "0x50000", "size": 2097152, "content": "uimage", "file": "extract/parts-001/02-kernel.bin"},
      {"name": "rootfs", "offset": "0x250000", "size": 5242880, "content": "squashfs", "file": "extract/parts-001/03-rootfs.bin"},
      {"name": "app", "offset": "0x750000", "size": 9109504, "content": "squashfs", "file": "extract/parts-001/04-app.bin"}
    ],
    "entropy": {"unexplained_high_entropy_runs": 1, "note": "0x0-0x20000 (boot 파티션 내부)만 설명되지 않는 균일 고엔트로피. 펌웨어 전체 암호화는 아님"},
    "regions_crosscheck": "REA inspect_firmware_regions(binwalk 3.1.0): uImage@0x50000·squashfs@0x250000 은 fw_identify 와 같고 U-Boot env@0x40000 은 못 찾음 → fw_identify 채택",
    "reports": ["analysis/identify-001.json", "analysis/entropy-001.json", "analysis/uboot-env-001.json", "analysis/carve-001.json", "analysis/uimage-001.json"]
  },
  "extraction": {
    "tool": "fwtriage", "status": "complete", "output_dir": "extract/rootfs-001",
    "gaps": [
      {"region": "0x0-0x50080", "kind": "unknown-chunk-handler", "count": 1, "note": "boot+env 블롭과 uImage 헤더, 파일시스템 아님 (예상된 gap)"},
      {"region": "extract/rea-001", "kind": "unpublished-entry", "count": 125, "note": "REA 교차 추출의 심볼릭 링크 (메타데이터로만 보존)"}
    ],
    "runs": [
      {"tool": "fw_extract_squashfs", "input": "extract/parts-001/03-rootfs.bin", "output_dir": "extract/rootfs-001", "status": "complete", "manifest": "extract/rootfs-001.manifest.json"},
      {"tool": "fw_extract_squashfs", "input": "extract/parts-001/04-app.bin", "output_dir": "extract/app-001", "status": "complete"},
      {"tool": "extract_firmware", "input": "dumps/flash-full.bin", "output_dir": "extract/rea-001", "coverage": "partial", "purpose": "교차 확인"}
    ]
  },
  "rootfs": {
    "path": "extract/rootfs-001", "fs_type": "squashfs 4.0 xz", "arch": "arm", "endianness": "little",
    "init_scripts": ["/etc/inittab", "/etc/profile", "/etc/init.d/rcS"], "services": ["telnetd"], "web_servers": ["/usr/sbin/httpd"]
  },
  "binaries_of_interest": [
    {"path": "/usr/sbin/httpd", "reason": "네트워크 대면 웹 서버, 정적 링크 심볼에 system/execve, 카나리 없음 (elf-info score 28.5)", "arch": "arm", "analyzed_with": "rea-ghidra", "evidence_bundle": "analysis/rea-evidence-httpd-001.json"},
    {"path": "/var/www/cgi-bin/status.cgi", "reason": "CGI (셸 스크립트, REA 거부 → 텍스트 검토)", "analyzed_with": "fallback"},
    {"path": "/usr/sbin/telnetd", "reason": "rcS 가 무조건 기동하는 서비스", "analyzed_with": "none"}
  ],
  "rea": {
    "provider": "ghidra", "evidence_bundle": "analysis/rea-evidence-httpd-001.json",
    "limitations": ["status.cgi: target_unavailable (unsupported binary format, 셸 스크립트)", "간접 호출은 trace_call_path 에서 미해결로 남을 수 있음", "rizin 미설치 (capability_unavailable)"]
  },
  "finding_ids": ["F-001", "F-002", "F-003", "F-004", "F-005", "F-006"],
  "notes": ["펌웨어 출처: firmware-dump-via-uart (crc32 일치)", "triage: analysis/rootfs-audit-001.json, analysis/strings-hunt-001.json, analysis/elf-info-001.json"]
}
```

```
case_record_step(case_id="<id>", skill="firmware-static-analysis", step="summary", status="success",
  summary="rootfs(squashfs) 추출·감사, httpd Ghidra 분석. 발견 6건 (critical 2, high 3, medium 1)",
  data=<위 JSON>,
  artifacts=["extract/rootfs-001", "analysis/rootfs-audit-001.json", "analysis/strings-hunt-001.json", "analysis/rea-evidence-httpd-001.json"],
  next_actions=["cctv-auth-bypass-hunt: httpd 인증 전 디스패치 표 작성", "격리 랩에서 F-001 negative test (사용자 동의 후)"],
  blockers=[])
```

## 다음 단계

- CCTV/DVR 이면 **cctv-auth-bypass-hunt**: 이 요약의 rootfs.path·binaries_of_interest·rea.evidence_bundle 을 그대로 쓴다. 다시 추출하지 않는다.
- 사용자가 목표를 "펌웨어 분석까지"로 줄였으면 `report_generate(case_id="<id>")` 로 보고서를 만들고 master-prompt §10 형식으로 보고한다.
- 동적 확인이 필요한 후보는 verification_plan 에 적고, 격리 랩과 사용자 동의가 갖춰진 뒤에만 진행한다.

## 참고

- [reference.md](reference.md): 응답 필드표, REA 오류 코드, 관심 바이너리 선정표, 탐색 앵커, 패턴·category 매핑, 발견사항 예시.
- `orchestrator/master-prompt.md` §1 절대 규칙, §5 데이터 전달, §8 실패 처리.
- `docs/architecture.md` §3 케이스 구조, §6.6 fwtriage, §7 REA 연동. `docs/safety.md` §1·§7.
- `mcp-servers/fwtriage-mcp/README.md` (한계 절), `docs/references/pweh-mcp-tools.md`, `docs/references/rea-mcp-tools.json`.
- `docs/references/cctv-vuln-patterns.md` §5 패턴 클래스, §6 정적 분석 절차, §7 안전한 검증. `docs/references/cctv-hunt-patterns.yaml`.
