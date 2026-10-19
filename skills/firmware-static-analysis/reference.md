# firmware-static-analysis 참고 자료

[SKILL.md](SKILL.md) 의 보조 자료다. 대상은 운영자가 소유했거나 서면 허가를 받은 기기의 펌웨어뿐이다.
아래 응답 형태와 오류는 2026-10-18 에 실제로 실행해 확인했다: pweh.mocktarget 합성 이미지(hisilicon-like ARM, ingenic-like MIPS),
pweh-fwtriage, rea 6.5.0 (Ghidra 12.1.4, binwalk 3.1.0, unblob 26.6.4).

## 1. 경로와 산출물 위치

| 무엇 | 위치 (케이스 상대) | 만드는 도구 |
|---|---|---|
| 덤프 / 공식 이미지 | `dumps/<name>.bin` | firmware-dump-via-uart, `case_import_file` |
| 파티션 파일 | `extract/parts-NNN/<idx>-<name>.bin` + `index.json` | `fw_carve` |
| squashfs 트리 | `extract/<label>-NNN/` + `extract/<label>-NNN.manifest.json` | `fw_extract_squashfs` |
| REA 추출 트리 | `extract/rea-NNN/` (case_paths 의 new_output_dir) | `extract_firmware` |
| fwtriage 전체 결과 | `analysis/<도구>-NNN.json` (응답의 result_path) | 모든 fw 도구 |
| REA 증거 번들 | `analysis/rea-evidence-<바이너리>-NNN.json` | `export_evidence_bundle` |
| 해시 대조 결과 (평문 포함) | `analysis/crack-hashes-NNN.json` | `fw_crack_hashes` — 케이스 밖 반출 금지 |

- 절대 경로 변환: `case_paths(case_id="<id>")` 의 case_dir + "/" + 케이스 상대 경로. analysis/ 와 extract/ 는 케이스를 만들 때 생기므로 부모 디렉터리 문제는 없다.
- REA unblob 출력 안쪽 구조: `extract/rea-001/firmware.bin_extract/<시작>-<끝>.<handler>_extract/...` (range 를 주면 `selected.bin_extract/...`).
  files[].path 는 절대 경로, relative_path 는 출력 디렉터리 기준이다. 오프셋이 이름에 들어 있어 원본 위치를 알 수 있다.
- 파일 이름에 쓰는 NNN: `case_paths` 는 확장자 없는 `<label>-NNN` 의 존재만 본다. 증거 파일(`.json`)은 이름을 직접 만들고, "already exists" 오류가 나면 번호를 올린다.

## 2. fwtriage 응답에서 볼 필드

| 도구 | 볼 필드 | 주의 (검증에서 확인) |
|---|---|---|
| `fw_identify` | summary.kinds / arch_hints / uboot_versions / linux_versions / coverage_ratio, regions[](offset_hex, kind, size, confidence, details), nested_omitted, next_steps | 압축 스트림 안쪽은 검사하지 않는다. uImage 안쪽 형식은 details.payload |
| `fw_entropy` | profile(한 줄 그림), high_runs[](offset_hex, size, distribution, known_coverage, note), unexplained_high_entropy_runs | 부트로더 블롭도 "설명되지 않는 균일 고엔트로피"로 나왔다. 그것만으로 암호화라고 판단하지 않는다 |
| `fw_uboot_env` | envs[](offset_hex, crc_endian, env, mtdparts[]), recommended_layout, embedded_default_envs, mtdparts_strings | 숫자는 10진 기준, 선행 0 은 경고만 |
| `fw_carve` | output_dir, index_path, layout(source, text, other_candidates), partitions[](name, offset_hex, size, status, **path**, sha256, content), warnings | 파티션 파일 경로는 path(케이스 상대). file 은 같은 값의 하위 호환 별칭 |
| `fw_uimage_info` | image(format, name, arch, os, compression, header_crc_ok, data_crc_ok, load_address, entry_point, payload_probe) | FIT/DTB 면 images·configurations |
| `fw_extract_squashfs` | status, output_dir, output_dir_abs, manifest_path, superblock, listing(setuid, setgid, world_writable_files), warnings | 장치 노드를 만들지 않는 것은 정상. unsquashfs returncode 2 도 status complete 일 수 있다 |
| `fw_rootfs_audit` | summary(items_by_severity, manifest_used), rootfs, platform, items[], accounts[], services[], web_servers[], binaries_of_interest[], vendor, limitations | REA 트리는 manifest_used false, fs_type null, setuid 신뢰 불가. user "0" 같은 이상 계정은 원본 확인 전 보류 |
| `fw_strings_hunt` | summary(by_severity, patterns_selected, rootfs_dirs), hits[](file, path, offset_hex, pattern_id, category, severity, match), matched_checks, top_files | file = rootfs 절대 경로(트리 밖 파일은 null), path = 케이스 상대 경로. checks[].evidence_ref = `<file>@<offset_hex>`(file 이 null 이면 path). `#` 주석 줄 히트는 JSON 의 commented_hits 에만 |
| `fw_elf_info` (디렉터리) | summary(elf_count, arch, with_command_exec, without_canary), binaries[](path, score, risky, heuristics, hardening, network_facing_hint) | 점수는 순위용 힌트다 |
| `fw_elf_info` (파일) | elf(machine, flags.isa/abi, static, stripped, defined_function_count, hardening), imports, risk(builtin, heuristics, wrapper_name_matches, unbounded_scanf_formats) | 정적 링크 바이너리는 imports 가 비고 heuristics 는 심볼 기반(basis static-symbols) |
| `fw_crack_hashes` | counts, results[](user, algorithm, status, source, password 마스킹) | not_cracked ≠ 안전. bcrypt/yescrypt 는 not_checked 일 수 있다 |

공통: 모든 응답에 result_path 가 있고 triage-report 아티팩트로 자동 등록된다. 목록은 max_results(기본 50)로 잘리며 truncated 와 합계로 더 있는지 알 수 있다.
긴 작업은 `background=true` → job_id → `fwtriage_job_status(job_id="<job>", wait_seconds=30)`. max_seconds 를 넘기면 summary.timed_out 과 부분 결과가 온다.

## 3. REA 응답 형태와 오류

**응답 형태**

- 분석 도구는 Evidence 레코드를 돌려준다: evidence_id(`ev_` + 64 hex, 같은 입력이면 세션이 달라도 같은 값), subject(name, digest.sha256, local_path, architecture), provider(id, version), operation, normalized_result, limitations[], confidence, authority.
- 수명 주기 도구는 `{"result": ...}` 형태다: open_binary(path, format, kind, sha256, architecture), close_binary(null), export_evidence_bundle(path, bytes, records, unknowns), get_evidence_bundle(summary 면 total_retained_records, records[]), list_unknowns(items, total).

| 도구 | normalized_result |
|---|---|
| `inspect_firmware_regions` | regions[](offset, reported_size, signature, description, reported_confidence) — 길이 검증 없음, 가설 |
| `extract_firmware` | coverage, files[], unpublished_entries[], chunks[], derivations[], extraction_gaps[](kind, range, continuation_id), extraction_continuations[](id, instruction), depth_limited_paths, published_bytes |
| `binary_overview` | document, image_base, segment_count, procedure_count, string_count, segments[] |
| `search_strings`, `search_procedures` | [{address, value}] |
| `trace_feature` | matches[], references[](source_address, containing_procedure{found, procedure{address, name}}), residual_unknowns |
| `find_xrefs_to_name` | {status "resolved", name, address, xrefs[]} 또는 {status "unresolved", reason "name_not_found"} |
| `procedure_callers` | 호출 함수 주소 목록 |
| `procedure_pseudo_code` | 의사코드 문자열 (null 가능) |
| `batch_decompile` | items[](address, procedure{address, name}, status, pseudocode), succeeded, failed |
| `analyze_function` | procedure, pseudocode, assembly, callers, callees, referenced_strings, referenced_names, basic_blocks, native_api, limitations (약 100 KB) |
| `inspect_native_api` | procedure, boundary(signature, parameters, jump_tables), substeps |
| `trace_call_path` | start, goal, goal_status(reached / not_requested / …), nodes, edges, traversal_path, residual_unknowns, limitations |

**오류와 조치**

| 상황 | error.code / category | 메시지·details | 조치 |
|---|---|---|---|
| 상대 경로 | (입력 검증) | "path must be an absolute local filesystem path" | case_dir 를 붙여 절대 경로로 |
| 입력 > 128 MiB | `invalid_request` / invalid_input | issues[].reason out_of_range, "no larger than 134217728 bytes" (range 를 줘도 같음) | `fw_carve` 로 나눈 파티션 파일을 넘긴다 |
| 출력 디렉터리가 이미 있음 | `execution_failure` | "Run `rea doctor`…" 이지만 details.diagnostics.reason = "Extraction output root already exists" | 지우지 말고 `case_paths` 로 새 경로를 받아 1회 재시도 |
| 지원하지 않는 대상 | `target_unavailable` / unsupported_target | "Cannot open artifact: unsupported binary format", constraint file_format_rejected | 셸 스크립트는 텍스트 검토, raw 커널은 범위 밖으로 기록, ELF 면 대체 경로(SKILL 7단계) |
| rizin 없음 | `capability_unavailable` / unsupported_provider | details.reason "Unable to run configured command (ENOENT)" | 건너뛴다 |
| 증거 파일이 이미 있음 | `invalid_request` | "Evidence file already exists", details.reason exists | NNN 을 올린다 (overwrite 하지 않는다) |
| 증거 파일의 부모가 없음 | `invalid_request` | "Evidence output directory does not exist" | analysis_dir 를 쓴다 |

**세션 수명**: close_binary 뒤 get_evidence_bundle 의 레코드는 0건이었다. 다른 대상으로 open_binary 해도 이전 레코드가 사라졌다. 그래서 바이너리마다 export → register → close 순서를 지킨다.
**Ghidra 시간**: open_binary 는 즉시 끝나고, 자동 분석은 첫 쿼리에서 돈다 (1.7 MB 정적 ARM 바이너리의 binary_overview 약 14초).
**대체 엔진 현황**: 이 환경의 objdump 는 호스트 x86 용이다. MIPS ELF 의 file_headers 가 `architecture: UNKNOWN!` 이었다. `inspect_with_objdump(operation="architectures")` 로 지원 목록을 먼저 본다. `inspect_binary_layout` 는 ELF64 x86-64 프로필이라 카메라 ARM/MIPS 바이너리에는 맞지 않는다.

## 4. 관심 바이너리 선정표

`cctv-hunt-patterns.yaml` 의 web_server_binaries 와 `pipeline-config.yaml` 프로필의 firmware 힌트를 합친 표다. 이름은 단서일 뿐이고, 실제 역할은 init 스크립트와 디컴파일로 확인한다.

| 계열 | 메인/웹 바이너리 이름 | 설정 경로 힌트 | 프로필 |
|---|---|---|---|
| Hikvision 계열 | davinci, centaurus (커뮤니티 출처) | — | hikvision-ipc |
| Dahua 계열 | sonia, Challenge | /mnt/mtd/Config | dahua-ipc |
| XiongMai (XMeye) | Sofia, dvrHelper, macGuarder | /mnt/mtd/Config, /mnt/custom | xiongmai-ipc |
| HiSilicon 비디오 인코더 | box.* | — | hisilicon-ipcam |
| TVT | NVMS9000, ConfigSyncProc | /mnt/mtd | generic-ipcam |
| Uniview | main-cgi, maintain | /program/bin | generic-ipcam |
| Foscam | lighttpd, CGIProxy.fcgi, webService, devMng | — | generic-ipcam |
| 일반 | boa, goahead, lighttpd, thttpd, mini_httpd, uhttpd, httpd, nginx | /mnt/mtd, /etc/config, /config | generic-ipcam |

우선순위 신호 (fw_elf_info, fw_rootfs_audit):
1. network_facing_hint true + risky.command-exec 있음 + 웹 서버/메인 앱 이름 → 최우선.
2. init 스크립트(inittab, rcS, 벤더 시작 스크립트)가 띄우는 비표준 데몬. fn-debug-listener-ports 휴리스틱(socket/bind/listen)이 있으면 디버그 포트 리스너 후보.
3. ELF CGI, 인증·웹 관련 공유 라이브러리(.so). 인증 로직이 라이브러리에 있는 펌웨어가 많다.
4. hardening(stack_canary false, pie false)은 우선순위를 올리는 보조 신호다. 단독 근거로 발견사항을 만들지 않는다.
5. 제외: 패치 흔적이 없는 BusyBox, 표준 libc/ld.so, 커널 모듈(벤더 모듈은 예외로 별도 기록).

## 5. 인증 로직 탐색 앵커

정규식 앵커 (그대로 복사해 쓴다):

```
search_procedures(pattern="(?i)auth|login|passw|cred|session|token|verify|permission", mode="regex")
search_strings(pattern="(?i)passw|login|logout|auth|admin|token|session|cookie|realm|nonce|basic |digest|unauthorized", mode="regex")
```

| 목적 | 도구 | 값 |
|---|---|---|
| 문자열 → 사용 함수 | `trace_feature(query=...)` | fwtriage 히트의 match 값, 로그인 RPC/CGI 이름, 헤더 이름 |
| 명령 실행 싱크 | `find_xrefs_to_name(name=...)` | system, popen, execl, execle, execlp, execv, execve, execvp, posix_spawn |
| 리터럴 비교 | `find_xrefs_to_name(name=...)` | strcmp, strncmp, strcasecmp, strncasecmp, memcmp, bcmp, strstr |
| 위험 복사·포맷 | `find_xrefs_to_name(name=...)` | strcpy, sprintf, vsprintf, sscanf, memcpy |
| 요청 디스패치 | `search_strings` → `trace_feature` | `/cgi-bin/`, `.cgi`, `HTTP/1.`, URL 경로 테이블 문자열 |
| 디버그 서비스 | `fw_strings_hunt`, `fw_rootfs_audit` | telnetd 기동 줄, 무로그인 콘솔(inittab), 벤더별 휴리스틱 id (`fw_hunt_patterns(vendor="xiongmai")` 로 목록 확인 후 patterns=["xm-*"]) |

- Ghidra 공급자에서 `(?i)` 인라인 플래그와 case_sensitive=false 는 같은 결과를 냈다.
- stripped 바이너리는 함수 이름이 없으므로 위 "문자열 → 사용 함수" 경로가 주 수단이다. 정적 링크 + stripped 면 libc 함수 이름도 없을 수 있다.
- 빈 검색 결과는 "없음"이 아니다. Ghidra 가 문자열로 정의하지 않은 바이트는 검색되지 않는다. fwtriage 히트(파일 오프셋)와 비교한다.

## 6. 디컴파일에서 표시할 패턴과 category

패턴 번호는 `docs/references/cctv-vuln-patterns.md` §5 를 따른다.

| 디컴파일에서 보이는 모습 | 패턴 | finding.category | severity 기준 |
|---|---|---|---|
| 요청 값과 .rodata 리터럴 비교가 일치하면 자격증명 검사 없이 성공 return | P4/P5/P6 | backdoor (숨은 토큰·만능 비밀번호), hardcoded-credential (고정 계정) | 인증 전 도달이면 critical |
| 사용자명·비밀번호를 리터럴과 비교 | P5 | hardcoded-credential | 관리자 권한이면 high 이상 |
| 인증 함수보다 앞에서 URI 접두사·확장자·부분 문자열(strstr)로 통과시키는 분기 | P1 | auth-bypass | 통과 뒤 도달 범위에 따라 medium~critical |
| 요청 필드(client type, loopback 표시, 쿠키)나 헤더 부재로 신뢰를 결정 | P4 | auth-bypass | high |
| 저장 해시를 클라이언트 값과 직접 비교, 서버 challenge 없음 | P7 | auth-bypass 또는 weak-crypto | medium~high |
| sprintf/snprintf 로 만든 문자열이 필터 없이 system/popen 으로 감 | P11 | command-injection | 인증 후 기능 high, 인증 전 critical |
| 고정 크기 스택 버퍼로 strcpy/sprintf/폭 없는 sscanf | P12 | memory-corruption | 인증 전 파서면 high |
| 부팅 스크립트의 telnetd 무조건 기동, 무로그인 콘솔 | P6 | debug-interface | medium, 기본 비밀번호와 함께면 high |
| 웹 루트 + URI 결합 후 정규화 없이 open/fopen | P2 | info-leak (인증 우회로 이어지면 auth-bypass) | medium~high |
| 상수 키로 AES/DES, 업데이트 경로에 서명 검증 없음 | P8/P10 | weak-crypto, insecure-update | medium~high |
| 빈 비밀번호·기본 계정 | P5 | insecure-default (공개 기본값과 일치하면 hardcoded-credential) | 원격 서비스와 연결되면 high 이상 |

YAML 카테고리 → finding.category: crypto → weak-crypto (업데이트 서명·무결성이면 insecure-update), memory-safety → memory-corruption,
path-traversal → info-leak (인증 우회로 이어지면 auth-bypass), session-token → auth-bypass 또는 weak-crypto, 나머지는 같은 이름. fw_rootfs_audit items 는 이미 변환된 값이다.

## 7. 발견사항 예시

SKILL.md 8단계의 F-001 과 같은 검증 케이스다. 모두 `case_add_finding` 서버 검증을 통과했다. 비밀값은 마스킹했다.

**F-002 — rootfs 감사 결과 (triage 근거)**

```json
{
  "title": "/etc/shadow 의 root 비밀번호가 공개 기본 비밀번호와 일치",
  "category": "hardcoded-credential", "severity": "critical", "confidence": "confirmed", "status": "static-confirmed",
  "summary": "읽기 전용 rootfs 의 root md5crypt 해시가 공개 IoT 기본 비밀번호 사전과 오프라인 대조에서 일치했다.",
  "location": {"firmware": "dumps/flash-full.bin", "file": "/etc/shadow", "line": 1},
  "evidence": [
    {"type": "triage", "ref": "analysis/rootfs-audit-001.json", "excerpt": "builtin-default-password: root (md5crypt) 12****"},
    {"type": "file", "ref": "/etc/shadow", "excerpt": "root:$1$b8e…:18000:0:99999:7:::"}
  ],
  "reasoning": "squashfs 는 읽기 전용이라 같은 펌웨어를 쓰는 모든 기기가 같은 root 비밀번호를 가진다 (패턴 P5).",
  "verification_plan": "사용자 동의 후 소유 기기의 UART 콘솔에서 해당 계정으로 1회 로그인해 확인한다. 네트워크 서비스로는 시도하지 않는다.",
  "remediation": "기기별 고유 비밀번호를 첫 부팅 때 설정하게 하고 고정 해시를 제거한다.",
  "produced_by": {"skill": "firmware-static-analysis", "tool": "fw_rootfs_audit"}
}
```

**F-003 — 디컴파일 근거 (하드코딩 웹 계정)**

```json
{
  "title": "httpd check_credentials 의 고정 관리자 계정 비교",
  "category": "hardcoded-credential", "severity": "high", "confidence": "confirmed", "status": "static-confirmed",
  "summary": "check_credentials 가 Basic 인증 사용자명·비밀번호를 .rodata 의 고정 문자열과 strcmp 로 비교한다.",
  "location": {"firmware": "dumps/flash-full.bin", "file": "/usr/sbin/httpd", "function": "check_credentials", "address": "0x22b08", "interface": "http"},
  "evidence": [
    {"type": "decompilation", "ref": "analysis/rea-evidence-httpd-001.json#ev_5c7574508a3c3a23d9116d6b4259a3775284e039dc4ccddd0e52d6c6c5d20dfc",
     "excerpt": "if (strcmp(user, \"admin\") == 0 && strcmp(pass, \"<마스킹>\") == 0) return 1;"},
    {"type": "triage", "ref": "analysis/strings-hunt-001.json", "excerpt": "gen-hardcoded-basic-auth /usr/sbin/httpd@0xcce (같은 계정의 Basic 헤더, selftest 함수에서 사용)"}
  ],
  "reasoning": "비밀번호를 바꿀 수 없는 고정 계정이다 (패턴 P5). 같은 값이 selftest 의 Basic 헤더 문자열에도 있어 trace_feature 로 위치를 구분했다.",
  "verification_plan": "수정 빌드가 있으면 check_credentials 를 디컴파일 diff 한다. 격리 랩에서는 자격증명 없는 요청이 401 인지만 확인한다.",
  "remediation": "고정 계정을 제거하고 설정 저장소의 사용자별 해시로 검증한다.",
  "produced_by": {"skill": "firmware-static-analysis", "tool": "rea batch_decompile (ghidra)"}
}
```

**F-004 — 디컴파일 + 호출 경로 근거 (명령 주입 후보)**

```json
{
  "title": "httpd handle_ping_cgi 의 host 파라미터가 셸 명령 문자열에 들어감",
  "category": "command-injection", "severity": "high", "confidence": "confirmed", "status": "static-confirmed",
  "summary": "handle_ping_cgi 가 host 파라미터를 snprintf 명령 템플릿에 넣고 system 으로 실행한다. 사이에 문자 검증이 보이지 않는다.",
  "location": {"firmware": "dumps/flash-full.bin", "file": "/usr/sbin/httpd", "function": "handle_ping_cgi", "address": "0x22470", "interface": "http"},
  "evidence": [
    {"type": "decompilation", "ref": "analysis/rea-evidence-httpd-001.json#ev_db6b98ba2b6e7b6b060ec3f9acc76f7171e8cd775c0741ab687352a08bf1203f",
     "excerpt": "get_param(req->query, \"host\", host, 0x80); snprintf(cmd, 0x100, \"ping -c 1 %s …\", host); system(cmd);"},
    {"type": "rea-evidence", "ref": "analysis/rea-evidence-httpd-001.json#ev_d87b64bd1282dea92c2c47dc15725eb18a19f7b29f4c233bd34dfd5517ffa687",
     "excerpt": "trace_call_path handle_client → handle_ping_cgi → system (goal_status reached)"},
    {"type": "triage", "ref": "analysis/strings-hunt-001.json", "excerpt": "gen-shell-cmd-template /usr/sbin/httpd@0xeda"}
  ],
  "reasoning": "요청 값 → 명령 템플릿 → system 싱크 구조다 (패턴 P11). handle_client 디컴파일에서 이 핸들러는 check_auth 뒤에 호출되므로 인증 후 기능으로 분류했다. get_param 의 필터 유무는 별도 확인 대상이다.",
  "verification_plan": "get_param 과 호출 경로를 정적으로 확인하고 수정 빌드와 비교한다. 격리 랩에서는 자격증명 없는 /cgi-bin/ping.cgi 요청이 401 인지만 본다. 메타문자 시험은 하지 않는다.",
  "remediation": "host 를 IP/호스트명 문법으로 화이트리스트 검증하고 셸을 거치지 않는 실행(execv 인자 배열)으로 바꾼다.",
  "produced_by": {"skill": "firmware-static-analysis", "tool": "rea analyze_function / trace_call_path (ghidra)"}
}
```

**F-005 — 인증 전 분기 (P1)**

```json
{
  "title": "httpd is_static_resource 의 부분 문자열 검사로 인증 생략",
  "category": "auth-bypass", "severity": "medium", "confidence": "confirmed", "status": "static-confirmed",
  "summary": "check_auth 가 맨 먼저 is_static_resource 를 부르고, 경로가 /static/ 로 시작하거나 경로 어디든 .css/.js/.png/.jpg 가 있으면 인증 없이 통과시킨다.",
  "location": {"firmware": "dumps/flash-full.bin", "file": "/usr/sbin/httpd", "function": "is_static_resource", "address": "0x229e0", "interface": "http"},
  "evidence": [
    {"type": "decompilation", "ref": "analysis/rea-evidence-httpd-001.json#ev_5c7574508a3c3a23d9116d6b4259a3775284e039dc4ccddd0e52d6c6c5d20dfc",
     "excerpt": "strncmp(path, \"/static/\", 8) … strstr(path, \".css\") … strstr(path, \".js\") … return 1;"},
    {"type": "decompilation", "ref": "analysis/rea-evidence-httpd-001.json#ev_1fb00ae8271ba615549c52382b19f9b3236ce7e126ce20b0de51c05cd0b97e5d",
     "excerpt": "iVar1 = is_static_resource(req->path); if (iVar1 == 0) { … } return iVar2;"}
  ],
  "reasoning": "확장자를 경로 끝이 아니라 부분 문자열로 검사한다 (패턴 P1). handle_client 의 CGI 분기는 경로 전체 비교라 영향은 정적 파일 처리기로 한정되는 것으로 보인다. 경로 정규화(P2) 여부는 확인하지 않았다.",
  "verification_plan": "정적 파일 처리기의 경로 결합·정규화 코드를 정적으로 확인한다 (cctv-auth-bypass-hunt). 동적 순회 시험은 하지 않는다.",
  "remediation": "정규화한 경로의 끝 확장자와 공개 디렉터리 화이트리스트로만 판단한다.",
  "produced_by": {"skill": "firmware-static-analysis", "tool": "rea batch_decompile (ghidra)"}
}
```

**F-006 — 부팅 스크립트 (file 근거)**

```json
{
  "title": "rcS 가 telnetd 를 무조건 기동",
  "category": "debug-interface", "severity": "high", "confidence": "confirmed", "status": "static-confirmed",
  "summary": "/etc/init.d/rcS 20번째 줄이 부팅마다 /usr/sbin/telnetd 를 백그라운드로 띄운다. 끄는 설정 분기가 없다.",
  "location": {"firmware": "dumps/flash-full.bin", "file": "/etc/init.d/rcS", "line": 20, "interface": "telnet"},
  "evidence": [
    {"type": "triage", "ref": "analysis/rootfs-audit-001.json", "excerpt": "gen-telnetd-launch /etc/init.d/rcS:20"},
    {"type": "file", "ref": "/etc/init.d/rcS", "excerpt": "/usr/sbin/telnetd &"}
  ],
  "reasoning": "원격 로그인 서비스가 항상 열린다 (패턴 P6). F-002 의 공개 기본 root 비밀번호와 같은 계정 DB 를 쓰므로 high 로 올렸다.",
  "verification_plan": "사용자 동의 후 소유 기기의 UART 셸에서 netstat 로 23/tcp 리슨 여부만 확인한다. 네트워크 로그인은 시도하지 않는다.",
  "remediation": "telnetd 를 제거하거나 기본 비활성 + 설정으로만 켜게 한다.",
  "produced_by": {"skill": "firmware-static-analysis", "tool": "fw_rootfs_audit"}
}
```

**대체 경로만 있을 때의 형식 (가상 값, 형식 참고용)**

```json
{
  "title": "<데몬 이름> 에 디버그 셸 관련 문자열",
  "category": "debug-interface", "severity": "medium", "confidence": "possible", "status": "unverified",
  "summary": "REA 가 바이너리를 열지 못해 문자열과 임포트만 확인했다. 함수 수준 근거는 없다.",
  "location": {"file": "/usr/bin/<데몬 이름>"},
  "evidence": [{"type": "triage", "ref": "analysis/strings-hunt-00N.json", "excerpt": "<pattern_id> /usr/bin/<데몬 이름>@0x…"}],
  "reasoning": "문자열 히트 + socket/bind 임포트만 있다. open_binary 거부 사유: target_unavailable (<details.reason>).",
  "verification_plan": "다른 디컴파일 경로가 생기면 정적으로 재확인한다."
}
```

## 8. summary data 작성 규칙

| 키 | 채우는 법 |
|---|---|
| firmware | path(케이스 상대), sha256, size, source. firmware-dump 요약의 method 로 source 를 정한다: uboot-*·linux-* → uart-dump, jtag-openocd → jtag-dump, spi-clip-flashrom → spi-clip, vendor-download → vendor-download, esptool-read-flash → esptool-dump, 그 외 → other. `case_import_file` 로 들인 공식 이미지는 vendor-download. 파티션 파일 여러 개를 분석했으면 firmware 는 rootfs 가 든 파일로 하고 나머지는 identification.partitions[] 에 파일 경로와 함께 둔다 |
| identification | arch, endianness, arch_flags, soc, bootloader, kernel, uboot_env, mtdparts(source, text), partitions[], entropy, regions_crosscheck, reports[] (fwtriage result_path 목록) |
| extraction | tool(rootfs 를 만든 도구: fw_extract_squashfs → fwtriage, extract_firmware → rea-unblob; REA binwalk 는 추출하지 않으므로 rea-binwalk 는 쓰지 않는다), status, output_dir(rootfs 트리), gaps[]({region, kind, count, note} 요약), runs[](추출 실행 기록) |
| rootfs | fw_rootfs_audit 응답의 rootfs 객체를 그대로 |
| binaries_of_interest | 각 항목 {path(rootfs 절대 경로), reason} + arch, analyzed_with(rea-ghidra / fallback / none), evidence_bundle, finding_ids(선택). rootfs.path 밖의 트리(app·config)에 있으면 tree(그 트리의 케이스 상대 경로, 예: extract/app-001)를 붙이고 path 는 그 트리 기준 |
| rea | provider("ghidra", 안 썼으면 null), evidence_bundle(대표 번들, 여럿이면 evidence_bundles 목록을 추가), limitations[](거부 사유, 미해결 간접 호출, 없는 엔진). ESP 덤프는 "open_binary 는 ESP 앱 이미지(ELF 가 아닌 raw 세그먼트 이미지)를 열 수 없음 — raw-binary 는 x86/x86_64/arm/arm64/6502 만 받아 Xtensa·RISC-V 모두 거부" 처럼 사유를 적는다 |
| finding_ids | 이번에 기록하거나 duplicate 로 돌려받은 id 전부 |
| notes | 무결성 상태, 공식 이미지 여부, 시간 부족으로 미분석한 바이너리 등 |

- summary status 와 extraction.status 의 기준은 SKILL.md 9단계에 있다.
- 스키마는 `schema_get(name="static-analysis")` 로 확인한다. 필수는 firmware(path, sha256)와 extraction(tool, status)뿐이지만, 다음 Skill 이 쓰도록 rootfs·binaries_of_interest·rea 를 채운다.
