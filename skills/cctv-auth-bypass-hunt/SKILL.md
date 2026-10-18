---
name: cctv-auth-bypass-hunt
description: "Static hunt for authentication-bypass patterns in Hikvision/Dahua/XiongMai-style IP camera, DVR and NVR firmware, for authorized/owned devices only. Use after firmware-static-analysis has extracted the rootfs. It identifies the vendor family and the web/daemon binaries (davinci, centaurus, sonia, Sofia, boa, goahead, lighttpd), then runs fwtriage heuristics and REA/Ghidra decompilation over a 12-item checklist: magic auth parameters, client-type/loopback trust, unauthenticated config or hash leaks, command injection into system/popen, static-file allowlists, path traversal, telnet backdoors such as XiongMai 9530, default accounts, weak session tokens, unsigned updates, ONVIF/RTSP gaps. It records evidence-backed findings and the auth-hunt summary. Keywords: auth bypass, backdoor, hardcoded credential, CCTV, DVR, NVR, 인증 우회, 백도어, 하드코딩 비밀번호, 명령 주입, 펌웨어 취약점 탐색."
---

# CCTV 인증 우회 패턴 탐색 (cctv-auth-bypass-hunt)

## 목적

추출이 끝난 IP 카메라·DVR/NVR 펌웨어에서 **인증 관련 결함 패턴**을 정적 분석으로 찾는다. 대상은 운영자가 **소유했거나 서면 허가를 받은 기기**뿐이다.

- Hikvision·Dahua·XiongMai 계열(그리고 HiSilicon/Ingenic OEM, 일반 웹 서버)의 메인 앱·웹 서버·데몬을 식별한다.
- 고정 점검표 [checklist.md](checklist.md)의 AH-01 ~ AH-12 를 빠짐없이 판정한다(`match`/`no-match`/`not-applicable`/`inconclusive`).
- 확인된 것은 증거(파일·오프셋·함수·디컴파일 발췌·REA evidence id)와 함께 `case_add_finding` 으로 남긴다.
- 끝에 `case_record_step(step="summary")` 로 `auth-hunt` 요약을 저장한다.

결과는 연구·방어용이다. 공격 페이로드, 재현 요청, 대량 스캔 도구는 만들지 않는다.

## 언제 쓰나

쓰는 경우:
- master-prompt 결정 트리의 **Phase D**(대상이 CCTV/DVR/NVR)이고, `firmware-static-analysis` 요약에 rootfs 경로가 있다.
- 사용자가 "인증 우회", "백도어", "하드코딩 비밀번호", "명령 주입" 점검을 요청했다.
- 이미 끝난 탐색을 새 증거(빌드 정보, 다른 파티션)로 다시 판정할 때.

쓰지 않는 경우:
- 소유/허가가 케이스에 기록되지 않았다 → 멈추고 확인부터 한다.
- 펌웨어를 아직 확보·추출하지 않았다 → `firmware-dump-via-uart` / `firmware-static-analysis` 를 먼저 한다.
- 제3자 기기, 인터넷에 노출된 기기, 같은 모델의 남의 기기에 결과를 적용하려 한다 → 하지 않는다.
- 실기기에 요청을 보내 우회를 "시험"하려 한다 → 이 Skill 범위가 아니다. 검증은 `verification_plan` 에 방법만 적고, 사람이 격리 랩에서 소유 기기로 한다.
- 벤더 무관 일반 펌웨어 분석이 목적이다 → `firmware-static-analysis` 를 쓴다.

## 전제 조건

- **케이스**: case_id 가 있고 `case_get` 결과의 `case.authorized` 가 true 다.
  fwtriage 와 REA 는 소유/허가를 검사하지 않는다(정적 도구). 그래서 1단계에서 직접 확인한다.
- **읽을 이전 요약**: `case_get_step_results(case_id)` 의 `summaries` 를 읽는다.
  - `firmware-static-analysis`(필수)에서 읽을 필드:
    - `data.rootfs.path`: 케이스 상대 경로. 예: `extract/rootfs-001`.
    - `data.rootfs.arch`, `data.rootfs.web_servers`, `data.binaries_of_interest[].path`: rootfs 절대 경로. 항목에 `tree` 가 있으면 path 는 그 트리(예: `extract/app-001`) 기준이다.
    - `data.extraction.runs[].output_dir`: rootfs 밖에 추출한 트리(app·config 파티션). 메인 앱·웹 루트가 여기에 있는 기기(Dahua·XiongMai 계열 등)가 있으니 2·3단계에서 함께 본다.
    - `data.rea.evidence_bundle`, `data.rea.limitations`, `data.finding_ids`.
  - `uart-shell-acquisition`(선택): 셸에서 본 기기 정보와 실행 중 서비스 메모. 실제로 기동되는 서비스인지 판단하는 데 쓴다.
  - `firmware-dump-via-uart`(선택): 펌웨어 출처와 무결성.
- **대상 정보**: `case.target.firmware_version`(빌드 비교용)과 `case.profile` 을 쓴다. `pipeline_profile(name=<profile>)` 의 `hunt.vendor_family`, `firmware.web_servers`, `firmware.config_paths` 도 본다.
- **하드웨어**: 필요 없다. 사람이 연결할 것은 없다. 격리 랩 검증은 이 Skill 이 끝난 뒤 사람이 따로 한다(선택).
- **서버**: `pweh-case`, `pweh-fwtriage`, `rea`(Ghidra 12.1.x + JDK 21, `~/pweh-tools/env.sh`). REA 가 없으면 fwtriage 만으로 진행하고, 코드 확인이 필요한 항목은 `inconclusive` 로 둔다.

## 안전 규칙

master-prompt §1 의 절대 규칙을 그대로 따른다. 이 Skill 에서는 특히 다음을 지킨다.

1. **권한 먼저.** `case.authorized` 가 false 이면 어떤 도구도 더 부르지 않는다. 사람에게 확인받는다(템플릿 A).
   답을 그대로 인용해 `case_set_authorization` 으로 기록한 뒤 시작한다. 답이 모호하면 멈춘다.
2. **정적 분석만.** 이 Skill 은 기기·네트워크에 아무것도 보내지 않는다.
   다음은 하지 않는다: 동적 우회 시험, 경로 순회 시도, 퍼징, 백도어 활성화, 조작된 업데이트 업로드.
3. **페이로드 금지.** finding·노트·요약에 다음을 쓰지 않는다.
   - 공격 요청 본문, 매직 파라미터 값이 든 URL, 쿠키 값
   - 순회 문자열, 매직 패킷 내용
   - 업데이트 기술자 예시
   증거는 경로·주소·문자열·디컴파일 발췌만이다.
4. **검증 계획은 소유 기기·격리 랩 한정.** `verification_plan` 에는 [checklist.md §0.3](checklist.md) 의 방법만 쓴다.
   - 빌드 비교, 패치 전후 디컴파일 diff
   - 기기 자신의 리슨 포트 목록
   - 무자격 요청이 401/403 으로 거부되는지 보는 negative test
5. **비밀 취급.** 다음 값은 케이스 디렉터리 밖으로 내보내지 않는다: 비밀번호·해시·키·복호화한 설정.
   - evidence excerpt 에는 마스킹해서 넣는다.
   - `fw_crack_hashes` 는 reveal=false(기본)로 쓴다.
6. **사실과 추측을 나눈다.** 근거 수준에 맞춰 매긴다.
   - 문자열 히트만 있으면 `confidence: possible`, `status: unverified`.
   - 디컴파일로 경로를 확인했을 때만 `confirmed` / `static-confirmed`.
   - CVE 번호는 [cctv-vuln-patterns.md](../../docs/references/cctv-vuln-patterns.md) 에 있는 것만 쓴다. 근본 원인이 확인되지 않으면 패턴 클래스(P1~P12)만 적는다.
7. **게이트 응답.** 이 Skill 의 도구는 보통 게이트를 거치지 않는다. 그래도 게이트 응답이 오면 다음과 같이 한다.
   - `status: approval_required`: master-prompt §1.2 와 §6 승인 요청 형식으로 설명한다. 사람이 별도 터미널에서 `pweh approve <id>` 를 실행하게 한다.
     승인 뒤 같은 인자에 approval_id 를 붙여 한 번만 재시도한다. `approval_status` 로 상태를 확인할 수 있다.
   - `status: denied`: 우회하지 않고 사용자에게 보고한다. 해당 check 는 `inconclusive` 로 두고 `coverage_gaps` 에 적는다.
   - `pweh approve` 를 직접 실행하거나 `orchestrator/pipeline-config.yaml` 의 safety 를 바꾸지 않는다.
8. **REA 도구 범위.** 분석 도구만 쓴다.
   - `execute_rizin_command` 는 플러그인 실행·파일 변경이 가능한 도구다. 다른 수단이 없을 때 읽기 전용 분석 명령으로만 쓴다.
   - 펌웨어·rootfs 파일을 고치지 않는다. 산출물은 케이스 `analysis/` 안에만 둔다.

## 사용하는 MCP 도구

| 도구 | 용도 |
|---|---|
| `case_get` | `case.authorized`, `case.profile`, `case.target`, 절대 경로(`paths.case_dir`, `paths.analysis_dir`) |
| `case_get_step_results` | 이전 Skill 요약(rootfs 경로, 관심 바이너리), 재개 시 이 Skill 의 중간 단계 |
| `pipeline_profile` | 프로필의 `hunt.vendor_family`, `firmware.web_servers`, `firmware.config_paths` |
| `case_set_phase` / `case_set_authorization` / `case_update_target` | 단계 시작 표시 / (사람 확인 뒤) 소유·허가 기록 / 사람이 알려 준 빌드 정보 기록 |
| `fw_rootfs_audit` | 벤더 계열 추정(`vendor`), 웹·메인 앱 바이너리, 서비스, 계정·해시, 시작 스크립트 항목 |
| `fw_strings_hunt` | `cctv-hunt-patterns.yaml` 문자열 휴리스틱. 결과 JSON 의 `checks[]` 는 auth-hunt 형식 |
| `fw_hunt_patterns` | 사용할 휴리스틱 id·벤더 선택자 확인 |
| `fw_elf_info` | 아키텍처·정적/동적·strip 여부·보호기법·위험 임포트 |
| `fw_crack_hashes` | passwd/shadow 해시의 오프라인 기본 비밀번호 대조(AH-08) |
| `fwtriage_job_status` | background=true 로 시작한 fwtriage 작업 폴링 |
| `open_binary` / `binary_overview` | REA(Ghidra) 대상 열기 / 분석 시작·개요 |
| `trace_feature` / `search_strings` | 문자열 → 참조 위치 → 그 위치를 포함하는 함수 |
| `search_bytes` / `xrefs` / `resolve_containing_procedure` | 정의되지 않은 문자열·키 바이트 → 참조 → 함수 |
| `address_to_file_offset` | REA 가상 주소 ↔ fw_strings_hunt 파일 오프셋 대조 |
| `procedure_pseudo_code` / `analyze_function` / `batch_decompile` | 디컴파일, 호출자·피호출자·참조 문자열 |
| `procedure_callers` / `trace_call_path` | 핸들러 ↔ 싱크 경로 (direction="forward"/"backward") |
| `find_xrefs_to_name` | 심볼이 있는 바이너리의 `system`/`popen` 등 참조 |
| `inspect_native_api` | 점프 테이블(opcode·메시지 ID 디스패치) 매핑 |
| `export_evidence_bundle` / `close_binary` | REA 증거 묶음을 케이스로 내보내기 / 세션 닫기 |
| `inspect_with_objdump` / `execute_rizin_command` | REA 가 바이너리를 거부할 때의 대체 수단 |
| `case_add_finding` / `case_update_finding` / `case_list_findings` | 발견사항 기록·갱신·중복 확인 |
| `case_register_artifact` | REA 증거 묶음을 `rea-evidence` 아티팩트로 등록 |
| `case_record_step` | 중간 단계(재개용)와 최종 `summary`(auth-hunt 스키마) |

## 절차

예시 case_id 는 `cam-001`, rootfs 는 `extract/rootfs-001` 이다. REA 경로는 `paths.case_dir` 로 만든 **절대 경로**다. fwtriage 경로는 **케이스 상대 경로**다.

### 1. 권한과 입력 확인

- **목표**: 권한을 확인하고 rootfs·대상 바이너리·프로필을 확보한다.
- **호출**:
  ```
  case_get(case_id="cam-001")
  case_get_step_results(case_id="cam-001")
  pipeline_profile(name="xiongmai-ipc")          # case.profile 값
  case_list_findings(case_id="cam-001")
  case_set_phase(case_id="cam-001", phase="cctv-auth-bypass-hunt", status="in-progress")
  ```
- **응답에서 볼 것**:
  - `case.authorized`, `paths.case_dir`, `paths.analysis_dir`, `case.target.firmware_version`
  - `summaries["firmware-static-analysis"].data` 의 rootfs 와 관심 바이너리
  - 이미 있는 finding 제목(중복 방지)
- **분기**:
  - authorized=false → 멈추고 템플릿 A 로 묻는다.
  - static-analysis 요약이 없다 → `firmware-static-analysis` 를 먼저 한다. 사용자가 케이스 안의 추출 rootfs 경로를 주면 그 경로로 진행한다. 이때 `coverage_gaps` 에 "static-analysis 요약 없음"을 적는다.
  - `rootfs` 가 null 이다(추출 실패·암호화) → 3단계의 fw_strings_hunt 를 펌웨어 파일에 대해서만 돌려 앵커를 남긴다. 요약은 status `blocked` 로 남기고 blockers 에 이유를 적는다.
- **재개**: 세션이 끊겼으면 다음 호출로 마지막 중간 단계를 확인하고 그 다음부터 한다.
  ```
  case_get_step_results(case_id="cam-001", skill="cctv-auth-bypass-hunt", summaries_only=false)
  ```

### 2. 벤더 계열과 웹 구성요소 식별

- **목표**: `vendor_family` 와 `web_components` 를 정하고 REA 로 볼 바이너리 순서를 정한다.
- **호출**:
  ```
  fw_rootfs_audit(case_id="cam-001", rootfs_dir="extract/rootfs-001")
  fw_hunt_patterns(vendor="xiongmai")             # vendor.vendor 가 정해진 뒤 그 벤더의 휴리스틱 id 확인
  ```
- **응답에서 볼 것**:
  - `vendor`: `{family, family_source, vendor, votes, evidence, profile_vendor_family}`. 표는 바이너리 이름 +3, 배너 +2, 경로 +1 이고, `votes`·`vendor` 에는 파일 근거만 담긴다.
  - `web_servers[]`: `{path, name, vendor, elf}`.
  - `binaries_of_interest[]`, `services[]`, `items[]`(critical/high 는 AH-07·AH-08 근거), `limitations`, `result_path`.
- **계열 판정 지표**:

  | vendor_family | 바이너리·데몬 | 설정·경로 | 배너·포트 지표 |
  |---|---|---|---|
  | `hikvision-like` | davinci, centaurus (커뮤니티 출처), 제한 셸 psh | `/ISAPI/`, `/PSIA/`, `/SDK/` 핸들러 문자열 | `App-webs/`, `Hikvision-Webs`, `DNVRS-Webs`; 80/443/554 |
  | `dahua-like` | `/usr/bin/sonia`, Challenge | `/mnt/mtd/Config/{passwd,Account1}`, `/RPC2_Login`, `global.login` | 37777/37778, 5000(DHIP), 37810/udp, 6789 |
  | `xiongmai-like` | Sofia(`/var/Sofia`), dvrHelper, macGuarder | `/mnt/mtd/Config/Account1`, `/mnt/custom`, 웹 루트 `/mnt/web` | `uc-httpd 1.0.0`, RTSP `H264DVR`; 9527, 9530, 34567 |
  | `hisilicon-oem` | `box.v400_hdmi`(box.*), remserial | `/box/box.ini` | `Server: box`, `Welcome to HiLinux.` |
  | `ingenic-oem` | (fwtriage 는 추정하지 않음) | 프로필 `ingenic-t-series` | — |
  | `generic` | boa, goahead, lighttpd, thttpd, mini_httpd, uhttpd, httpd, nginx (TVT·Uniview·WIFICAM 등도 여기) | 벤더별 | `GoAhead-Webs`, `mini_httpd/<ver>` |

- **분기**: `vendor.family_source` 로 판정 근거를 본다. fw_rootfs_audit 가 프로필 대체까지 이미 적용하므로 계열을 다시 계산하지 않는다.

  | family_source | 뜻 | vendor_family |
  |---|---|---|
  | `evidence` | 파일 근거(바이너리 이름·배너·경로 지표)가 있다 | `vendor.family` 그대로. 근거 벤더가 위 표의 계열이 아니면(uniview·wificam 등) `generic` 으로 온다 |
  | `profile` | 파일 근거가 없어 케이스 프로필의 `hunt.vendor_family`(구체적인 계열)를 썼다 | `vendor.family` 그대로. 근거가 약하므로 3·5단계에서 그 계열 지표를 확인하고, 다른 계열의 파일 근거가 나오면 그쪽으로 고친다 |
  | `generic-web-server` | 일반 웹 서버(boa·goahead·lighttpd 등)만 있다 | `generic` |
  | `none` | 웹 서버도 근거도 없다 | `unknown` |

  - `vendor.family` 는 언제나 auth-hunt 스키마의 vendor_family 값 중 하나다. 요약의 `vendor_evidence` 첫 항목에 `family_source=<값>` 을 적고 `vendor.evidence` 를 이어 붙인다.
  - `evidence` 인데 3단계의 `summary.vendor_family_guess` 와 다르면 바이너리 이름·배너 근거를 우선한다. 문자열 점수(`vendor_scores`)는 보조다.
  - `fw_hunt_patterns` 의 vendor 에는 `vendor.vendor`(파일 근거의 벤더 키)를 넣는다. `profile`·`generic-web-server`·`none` 이면 null 이므로 계열에 맞는 키(`hikvision`, `dahua`, `xiongmai`, `hisilicon_video_encoder`)로 부르거나 건너뛴다.
- **web_components 매핑**: `web_servers[]` 와 CGI·백도어 데몬을 `{path, role, arch}` 로 옮긴다.
  - role 예: `main-app (HTTP uc-httpd, RTSP, 34567)`, `http (generic)`, `cgi`, `debug-daemon (9530)`.
  - arch 에는 `elf` 문자열(예: `arm (EABI5, soft-float)`)을 넣는다. 모르면 null.
- **실패 처리**:
  - 응답의 `summary.timed_out`/`truncated` 가 참이면 background=true 로 다시 시작한다. 그 뒤 `fwtriage_job_status(job_id="job-…", wait_seconds=30)` 를 `succeeded` 가 될 때까지 반복한다(wait ≤ 50).
  - 절대 경로 심볼릭 링크를 넘겨 검증 오류가 나면 링크 대상의 실제 파일(예: busybox)을 넘긴다.
  - REA/unblob 로 추출한 트리면 setuid 정보가 부정확하다고 `limitations` 에 나온다. 그대로 기록한다.

### 3. 문자열·설정 트리아지 (fwtriage)

- **목표**: 점검표 항목별 앵커와 파일 오프셋을 얻는다.
- **호출**:
  ```
  fw_strings_hunt(case_id="cam-001", path_or_dir="extract/rootfs-001", patterns="cctv")
  fw_strings_hunt(case_id="cam-001", path_or_dir="extract/rootfs-001/usr/bin/Sofia", patterns=["xiongmai", "dahua", "lit:127.0.0.1"])
  fw_elf_info(case_id="cam-001", path="extract/rootfs-001/usr/bin/Sofia")
  fw_crack_hashes(case_id="cam-001", source_path="extract/rootfs-001/etc/passwd")
  case_record_step(case_id="cam-001", skill="cctv-auth-bypass-hunt", step="triage", status="in-progress",
                   summary="fwtriage 완료: matched 16, vendor xiongmai-like", data={"strings_hunt": "analysis/strings-hunt-001.json", "rootfs_audit": "analysis/rootfs-audit-001.json"})
  ```
- **응답에서 볼 것**:
  - fw_strings_hunt 응답:
    - `summary.vendor_scores`, `summary.vendor_family_guess`
    - `matched_checks[]`: `{id, count, severity, evidence_ref}`. evidence_ref 는 `"/usr/bin/Sofia@0x5c0"` = rootfs 경로 @ 파일 오프셋이다.
    - `hits[]`, `top_files`, `result_path`
  - result_path 의 전체 JSON 에는 선택한 휴리스틱마다 `checks[]` 가 있다: `{id, description, result, evidence_ref, count, severity, vendor}`.
    `#` 주석 줄 히트는 `commented_hits` 에 따로 있다.
  - lit:/re:/raw: 선택자 결과의 check id 는 `custom-<lit|re|raw>-<해시 8자>` 다(같은 패턴이면 항상 같은 id, description 에 패턴 원문).
  - fw_elf_info 의 `elf.static`, `elf.stripped`, `elf.hardening`, `imports`, `risk.heuristics`.
    정적 링크·strip 바이너리는 `imports` 가 빈다. 이때 싱크는 5단계에서 REA 로 찾는다.
- **분기**:
  - 메인 바이너리에 히트가 거의 없고 크기 대비 문자열이 적으면 패킹·암호화를 의심한다. `fw_entropy(case_id="cam-001", path="extract/rootfs-001/usr/bin/Sofia")` 를 확인하고, 설명되지 않는 고엔트로피면 `coverage_gaps` 에 적는다.
- **실패 처리**: 시간 초과·잘림은 2단계와 같다(background=true + 폴링). 패턴별 상한(per_pattern_cap)에 걸리면 id 를 좁혀 다시 돌린다.

### 4. REA 세션 열기 (바이너리마다)

- **목표**: 메인 앱부터 Ghidra 디컴파일을 준비한다.
  순서는 메인 웹/앱(Sofia, sonia, davinci/centaurus) → 웹 서버·CGI → 백도어 후보 데몬(macGuarder, dvrHelper, maintain) → 인증 코드가 든 공유 라이브러리다.
- **호출**:
  ```
  open_binary(path="<paths.case_dir>/extract/rootfs-001/usr/bin/Sofia", provider_id="ghidra")
  binary_overview()
  ```
  binaries_of_interest 항목에 `tree` 가 있으면 경로는 `<paths.case_dir>/<tree><path>` 다(rootfs 가 아닌 app·config 트리).
- **응답에서 볼 것**:
  - open_binary 는 바로 돌아온다: `{path, format: "elf", kind, sha256, architecture}`.
  - 첫 분석 질의(binary_overview)에서 Ghidra 자동 분석이 끝난다. 응답의 `normalized_result` 에 `procedure_count`, `string_count`, `segments` 가 있다.
  - 모든 REA 응답에는 `evidence_id` 가 있다. finding·check 의 evidence_ref 에 쓴다.
- **분기**: 오류 `target_unavailable`/`unsupported_target` 가 올 수 있다. 원인은 비ELF, 승인되지 않은 MIPS ABI, 손상 등이다. 이때 다음 순서로 대체한다.
  1. fw_elf_info, fw_strings_hunt 로 할 수 있는 데까지 한다.
  2. 필요한 함수만 `inspect_with_objdump(path="<절대 경로>", operation="disassemble")` 로 읽는다.
  3. `execute_rizin_command` 는 마지막 수단이며 읽기 전용 명령만 쓴다.
  코드 확인이 필요한 항목은 `inconclusive` 로 두고, `coverage_gaps` 에 "REA 거부: <사유>" 를 적는다.
- **실패 처리(시간)**:
  - 첫 질의는 작은 바이너리에서 수 초 걸린다(픽스처 35KB 에서 약 8초). 수 MB 메인 앱은 수 분 걸릴 수 있다. 사용자에게 미리 알린다(템플릿 C).
  - 질의를 취소하지 않는다. 취소하면 임시 DB 가 버려지고 다음 질의 때 다시 가져온다.
  - 클라이언트가 시간 초과로 끊겼으면 같은 읽기 질의를 다시 보낸다.

### 5. 점검표 실행 (AH-01 ~ AH-12)

- **목표**: [checklist.md](checklist.md) 의 12개 항목을 모두 판정한다. 항목마다 "찾는 것 → fwtriage id → REA 질의 → 확인 형태 → 반증 → CVE 계열 → 기록" 순서를 따른다.
- **기본 질의 흐름**(합성 테스트 픽스처(zig ARM, strip 된 정적 링크)에서 확인한 순서):
  ```
  trace_feature(query="NetKeyboard")                        # 히트 문자열 → 참조 함수
  procedure_pseudo_code(procedure="0x211e0")                # 주소 또는 FUN_000211e0
  analyze_function(procedure="0x211e0")                     # callers, callees, referenced_strings
  address_to_file_offset(address="0x105c0")                 # fw_strings_hunt 오프셋(0x5c0)과 대조
  search_bytes(pattern="2f 62 69 6e 2f 73 68 00")           # Ghidra 가 문자열로 정의하지 않은 바이트
  xrefs(address="0x105b4")
  resolve_containing_procedure(address="0x21aa0")           # → system 형 싱크 함수
  trace_call_path(start="0x2196c", direction="backward")   # 싱크 → 호출자 사슬(edges)
  trace_call_path(start="0x2130c", goal="0x2196c", direction="forward")
  ```
- **응답에서 볼 것**:
  - `trace_feature`: `normalized_result.matches[]` 는 `{address, value}` 다. `references[].containing_procedure.procedure` 는 `{address, name}` 이다.
    query 는 부분 문자열로 맞춘다(`current_config` → `/current_config/`). `search_strings` 는 기본이 대소문자 무시다.
    matches 가 비어도 텍스트가 없다는 증거가 아니다. Ghidra 가 정의한 문자열만 보기 때문이다. 이때는 search_bytes 로 다시 확인한다.
  - `find_xrefs_to_name(name="system")` 가 `{"status": "unresolved", "reason": "name_not_found"}` 이면 strip 된 정적 바이너리다. [checklist.md §0.5](checklist.md) 의 `/bin/sh` 경로로 싱크를 찾는다.
  - `procedure_pseudo_code` 는 문자열 하나(의사 C)를 돌려준다. libc 함수도 `FUN_…` 로 나오므로 모양(strcmp/sprintf/system 형)으로 읽는다.
- **판정**: [checklist.md §0.1](checklist.md) 의 규칙을 따른다.
  - 문자열 히트만 있고 코드 참조가 없으면 `inconclusive` 다(예: 로드 세그먼트 밖 문자열).
  - 기능 코드를 읽었는데 패턴이 없으면 `no-match` 다.
  - 기능이 없으면 `not-applicable` 이다.
  - 바이너리마다 끝나면 중간 기록을 남긴다(재개용).
    ```
    case_record_step(case_id="cam-001", skill="cctv-auth-bypass-hunt", step="rea-sofia", status="in-progress",
                     summary="AH-01..AH-12 판정(Sofia)", data={"AH-02": "match", "AH-09": "no-match"})
    ```
- **실패 처리**:
  - 간접 호출·점프 테이블로 디스패처를 다 열거하지 못하면 `inspect_native_api(procedure="<디스패처>")` 를 시도한다. 그래도 안 되면 `inconclusive` + `coverage_gaps` 다.
  - 너무 큰 함수는 `batch_decompile(addresses=["0x…", "0x…"])` 로 나눠 읽는다.

### 6. 발견사항 기록

- **목표**: `match` 마다(그리고 강한 `inconclusive` 는 선택적으로) finding 을 하나씩 남긴다.
- **호출**: id 는 서버가 `F-NNN` 으로 붙이므로 넘기지 않는다.
  ```
  case_add_finding(case_id="cam-001", finding={
    "title": "Sofia 로그인 분기가 clientType/loginType 값만으로 성공을 반환",
    "category": "auth-bypass", "severity": "critical", "confidence": "confirmed", "status": "static-confirmed",
    "summary": "로그인 처리 함수가 clientType 이 NetKeyboard 이거나 loginType 이 Loopback 이고 요청 값 ipAddr 가 127.0.0.1 이면 비밀번호 검증 함수를 부르지 않고 1(성공)을 반환한다.",
    "location": {"firmware": "dumps/flash.bin", "file": "/usr/bin/Sofia", "function": "FUN_000211e0", "address": "0x211e0", "offset": "0x5c0", "interface": "http"},
    "evidence": [
      {"type": "triage", "ref": "analysis/strings-hunt-001.json", "excerpt": "dh-login-netkeyboard /usr/bin/Sofia@0x5c0"},
      {"type": "decompilation", "ref": "analysis/rea-evidence-sofia-001.json#ev_685f50f5f043f616", "excerpt": "iVar1 = FUN_0002711c(param_1,\"NetKeyboard\");\nif (iVar1 != 0) { ... return FUN_00021160(...); }\nreturn 1;"}
    ],
    "reasoning": "FUN_0002711c 는 strcmp 형(일치 시 0). 일치하면 검증 함수 FUN_00021160 을 건너뛰고 상수 1 을 반환한다. 로컬 판정 값은 소켓 peer 주소가 아니라 요청 인자다. P4, CVE-2021-33044/33045 계열의 근본 원인 형태다. 두 CVE 는 Dahua 제품 대상이라 이 XiongMai 계열 바이너리의 references 에는 넣지 않았다. 빌드 비교 미실시.",
    "references": ["docs/references/cctv-vuln-patterns.md#4.2"],
    "verification_plan": "소유 기기를 인터넷과 분리된 랩 VLAN 에서만 다룬다. 1) Web UI 빌드 시간을 벤더 공지 기준일과 비교 2) 수정 빌드가 있으면 로그인 분기 디컴파일 diff 3) 동적 확인은 정상 계정의 잘못된 비밀번호 로그인이 거부되는지 보는 negative test 로만 한정하고 우회 요청은 만들지 않는다.",
    "remediation": "모든 로그인 분기에서 서버 측 비밀번호/다이제스트 검증을 강제하고, 로컬 판정은 getpeername 결과로 한다. 벤더 수정 펌웨어로 갱신한다.",
    "produced_by": {"skill": "cctv-auth-bypass-hunt", "tool": "procedure_pseudo_code"}
  })
  ```
- **응답에서 볼 것**: `finding_id`, `duplicate`. 제목과 위치(file/function/address)가 같으면 서버가 기존 항목을 돌려주며 `duplicate: true` 다. 근본 원인이 같은 여러 check 는 같은 finding_id 를 가리킨다.
- **분기**:
  - 나중에 근거가 강해지면 `case_update_finding(case_id="cam-001", finding_id="F-001", patch={"confidence": "confirmed", "status": "static-confirmed"})` 로 고친다.
  - 오탐으로 판명되면 `status: false-positive` 로 고친다.
- **실패 처리**: 스키마 검증 실패는 도구 오류로 온다(예: `category: 'path-traversal' is not one of …`). [checklist.md §0.3](checklist.md) 의 매핑으로 고쳐 다시 보낸다.

### 7. 증거 묶음 내보내기와 세션 닫기 (바이너리마다)

- **호출**:
  ```
  export_evidence_bundle(path="<paths.analysis_dir>/rea-evidence-sofia-001.json")
  case_register_artifact(case_id="cam-001", path="analysis/rea-evidence-sofia-001.json", kind="rea-evidence", description="REA evidence (Sofia)")
  close_binary()
  ```
- **응답에서 볼 것**: `{path, bytes, records, unknowns}`. 묶음에는 이 REA 세션의 모든 레코드(디컴파일 원문 포함)가 들어 있다. evidence_ref 의 `#ev_…` 가 여기서 풀린다.
- **실패 처리**:
  - "Evidence output directory does not exist": 부모 디렉터리는 미리 있어야 한다. case_paths 의 new_output_dir 처럼 아직 없는 경로는 쓰지 말고 `paths.analysis_dir` 바로 아래에 둔다.
  - "Evidence file already exists": 덮어쓰지 않고(overwrite 를 쓰지 않는다) NNN 을 올린다. 기존 묶음은 이미 기록한 finding·check 의 `#ev_…` 참조가 가리키는 증거다.
  - 반드시 close_binary **전에** 내보낸다.

### 8. 요약 저장

- `match` → finding 연결, `inconclusive` → `coverage_gaps` 를 모두 채운 뒤 **출력** 절의 `case_record_step(step="summary")` 를 호출한다.
- status 를 정한다.
  - `success`: 12개 항목이 모두 판정되었고 `coverage_gaps` 가 비었다.
  - `partial`: `inconclusive` 나 gap 이 하나라도 있다.
  - `blocked`: rootfs·바이너리가 없다. 이때도 data 필수 키는 채운다: `vendor_family`(모르면 `unknown`), `web_components: []`, AH-01 ~ AH-12 를 모두 `inconclusive` 로 둔 `checks`, `finding_ids`.
  - `failed`: 도구를 쓸 수 없었다.
- 서버가 스키마 오류(예: `vendor_family: 'xiongmai' is not one of …`)로 거부하면 고쳐서 다시 저장한다.

## 사람에게 요청할 일

**A. 소유/허가 확인** (`case.authorized` 가 false 일 때)
```
[확인 필요] 분석 권한
이 펌웨어가 나온 기기를 직접 소유하고 있습니까, 아니면 소유자의 서면 허가를 받았습니까?
- 소유: "제 소유 기기입니다" 처럼 답해 주세요.
- 서면 허가: 허가 주체와 문서 식별자(번호/날짜)를 알려 주세요.
답하신 문장을 그대로 케이스에 기록합니다. 확인 전에는 분석을 진행하지 않습니다.
```

**B. 빌드 정보** (CVE 대응 여부를 빌드로 비교할 때)
```
[확인 필요] 펌웨어 빌드 확인
기기 Web UI 의 시스템 정보(버전 정보) 화면이나 라벨, 공식 펌웨어 파일명에 있는 버전과 빌드 날짜를 알려 주세요.
벤더 보안 공지의 수정 빌드와 비교하는 데만 씁니다. 기기에 새 요청을 보내지 않습니다.
```
답을 받으면 `case_update_target(case_id="cam-001", target={"firmware_version": "<답한 버전·빌드>"})` 로 기록하고, 각 finding 의 `reasoning` 에 비교 결과를 적는다.

**C. 장시간 분석 안내** (수 MB 메인 앱을 REA 로 열 때)
```
[안내] Ghidra 분석 시간
/usr/bin/Sofia(약 N MB)를 Ghidra 로 분석합니다. 첫 결과까지 수 분 걸릴 수 있습니다.
진행 중에는 중단하지 말아 주세요. 중단하면 분석을 처음부터 다시 합니다.
```

**D. (선택) 격리 랩 확인 동의** (finding 이 나온 뒤)
```
[사람 작업 필요] (선택) 격리 랩에서 F-001 확인 (소유 기기만)
제가 기기에 요청을 보내지는 않습니다. 원하시면 다음을 직접 관찰해 주세요.
1. 기기를 인터넷·사내망과 분리된 스위치(VLAN)에 연결하고 외부 통신을 막습니다.
2. 시스템 정보 화면의 빌드 날짜를 알려 주세요.
3. 정상 계정에 잘못된 비밀번호로 로그인했을 때 거부되는지(정상 동작)만 확인해 주세요.
UART 셸이 있다면 리슨 포트 목록(예: 23, 9527, 9530, 34567)을 uart-shell-acquisition 단계에서 함께 확인할 수 있습니다.
결과를 알려 주시면 F-001 의 status 를 갱신합니다.
```

## 성공·실패 기준

- **성공**: 다음을 모두 만족한다.
  - AH-01 ~ AH-12 가 모두 판정되었다. 각 항목에 `evidence_ref` 가 있거나, null 인 이유가 `description` 에 있다.
  - `match` 마다 finding 이 있고(`finding_id`), finding 에 위치·증거·추론·신뢰도·검증 계획이 있다.
  - REA 를 쓴 바이너리마다 증거 묶음이 `rea-evidence` 아티팩트로 등록되었다.
  - summary 가 스키마를 통과해 저장되었다.
  - 페이로드·평문 비밀이 어디에도 없다.
- **부분 성공(`partial`)**: 일부 항목이 `inconclusive` 다. 원인의 예는 REA 거부, 시간 초과, 간접 디스패치, 업데이트 코드가 rootfs 밖에 있는 경우다. 모든 gap 이 `coverage_gaps` 에 있으면 정상 종료로 본다.
- **실패/차단**:
  - 소유/허가 미확인: 멈춘다. summary 를 저장하지 않는다.
  - rootfs 없음: `blocked` 와 blockers 를 남긴다.
  - 서버 미연결: 사용자에게 `docs/mcp-setup.md` 를 안내한다.
  - 스키마 거부를 고치지 못했다.

## 출력

finding 을 모두 기록한 뒤 다음 호출로 요약을 저장한다.
`data` 는 `schemas/auth-hunt.schema.json` 을 따른다. 필수 키는 `vendor_family`, `web_components`, `checks`, `finding_ids` 다. 추가 키는 허용된다.

```
case_record_step(
  case_id="cam-001", skill="cctv-auth-bypass-hunt", step="summary", status="partial",
  summary="xiongmai-like. AH-01~AH-12 판정: match 6, inconclusive 4, no-match 2. 발견 6건(치명 2). 빌드 비교 미실시.",
  data=<아래 JSON>,
  artifacts=["analysis/rootfs-audit-001.json", "analysis/strings-hunt-001.json", "analysis/elf-info-001.json", "analysis/rea-evidence-sofia-001.json"],
  next_actions=["빌드 날짜를 받아 벤더 공지 수정 빌드와 비교", "업데이트 처리 파티션 추출 후 AH-10 재판정"],
  blockers=[])
```

```json
{
  "vendor_family": "xiongmai-like",
  "web_components": [
    {"path": "/usr/bin/Sofia", "role": "main-app (HTTP uc-httpd, RTSP, 34567)", "arch": "arm (EABI5, soft-float)"},
    {"path": "/usr/sbin/boa", "role": "http (generic)", "arch": "arm (EABI5, soft-float)"},
    {"path": "/var/www/cgi-bin/login.cgi", "role": "cgi", "arch": null}
  ],
  "checks": [
    {"id": "AH-01", "description": "매직/하드코딩 인증 토큰·파라미터 (P4/P5, CVE-2017-7921 계열)", "result": "match", "evidence_ref": "analysis/rea-evidence-sofia-001.json#ev_9a1c", "finding_id": "F-002", "pattern_class": "P5", "confidence": "confirmed"},
    {"id": "AH-02", "description": "클라이언트 주장 값(clientType/loginType/loopback)으로 인증 결정 (P4, CVE-2021-33044/33045 계열)", "result": "match", "evidence_ref": "analysis/rea-evidence-sofia-001.json#ev_685f", "finding_id": "F-001", "pattern_class": "P4", "confidence": "confirmed"},
    {"id": "AH-03", "description": "무인증 핸들러의 설정·해시 유출 (P3/P8, CVE-2017-7925/7923 계열)", "result": "inconclusive", "evidence_ref": "analysis/rea-evidence-sofia-001.json#ev_c3d0", "finding_id": "F-003", "pattern_class": "P8", "confidence": "likely"},
    {"id": "AH-04", "description": "요청 파라미터 → system()/popen() 명령 주입 (P11, CVE-2021-36260 계열)", "result": "match", "evidence_ref": "analysis/rea-evidence-sofia-001.json#ev_b53d", "finding_id": "F-004", "pattern_class": "P11", "confidence": "confirmed"},
    {"id": "AH-05", "description": "정적 파일/URL 접두사 allowlist 가 인증을 건너뜀 (P1)", "result": "match", "evidence_ref": "analysis/rea-evidence-sofia-001.json#ev_c3d0", "finding_id": "F-003", "pattern_class": "P1"},
    {"id": "AH-06", "description": "인증 전 경로 순회 (P2)", "result": "inconclusive", "evidence_ref": "analysis/rea-evidence-sofia-001.json#ev_77e2", "finding_id": null, "pattern_class": "P2"},
    {"id": "AH-07", "description": "디버그·백도어 서비스 (P6, XiongMai 9530 계열)", "result": "match", "evidence_ref": "analysis/rootfs-audit-001.json#gen-telnetd-login-shell", "finding_id": "F-005", "pattern_class": "P6"},
    {"id": "AH-08", "description": "하드코딩·기본 계정 (P5)", "result": "match", "evidence_ref": "analysis/rootfs-audit-001.json#known-hash-xm-root-xc3511", "finding_id": "F-006", "pattern_class": "P5"},
    {"id": "AH-09", "description": "약하거나 예측 가능한 세션·nonce·토큰 (P7). 세션 생성·Digest 응답 함수를 읽음", "result": "no-match", "evidence_ref": "analysis/rea-evidence-sofia-001.json#ev_4e10", "finding_id": null, "pattern_class": "P7"},
    {"id": "AH-10", "description": "서명 없는 펌웨어 업데이트 경로 (P10)", "result": "inconclusive", "evidence_ref": "analysis/strings-hunt-001.json", "finding_id": null, "pattern_class": "P10"},
    {"id": "AH-11", "description": "ONVIF/RTSP 인증 누락·약화 (P9). RTSP 메서드 디스패처가 DESCRIBE/PLAY 전에 인증 함수를 부름", "result": "no-match", "evidence_ref": "analysis/rea-evidence-sofia-001.json#ev_51aa", "finding_id": null, "pattern_class": "P9"},
    {"id": "AH-12", "description": "인증 전 메모리 안전성 결함 기록 (P12, 보조)", "result": "inconclusive", "evidence_ref": "analysis/elf-info-001.json", "finding_id": null, "pattern_class": "P12"},
    {"id": "xm-universal-password", "description": "Sofia 인증 함수의 만능 비밀번호 리터럴", "result": "match", "evidence_ref": "/usr/bin/Sofia@0x5de", "count": 1, "severity": "critical", "vendor": "xiongmai"},
    {"id": "xm-opentelnet-cmd", "description": "TCP 9530 telnetd 활성화 명령 문자열", "result": "match", "evidence_ref": "/usr/bin/Sofia@0x8b61", "count": 1, "severity": "critical", "vendor": "xiongmai"},
    {"id": "hik-sdk-weblanguage", "description": "/SDK/webLanguage", "result": "no-match", "evidence_ref": null, "count": 0, "severity": "high", "vendor": "hikvision"}
  ],
  "finding_ids": ["F-001", "F-002", "F-003", "F-004", "F-005", "F-006"],
  "coverage_gaps": [
    "OpenTelnet:OpenOnce 문자열(/usr/bin/Sofia@0x8b61)이 로드 세그먼트 밖에 있어 REA xref 없음 — 9530 데몬 코드 미확인",
    "34567 바이너리 프로토콜 메시지 디스패처(CVE-2024-3765 형태)는 간접 호출 테이블이라 정적으로 복원하지 못함",
    "업그레이드 파서(InstallDesc/UpgradeCommand) 문자열 없음 — 업데이트 처리 바이너리가 rootfs 밖(별도 파티션)에 있을 수 있음",
    "빌드 비교 미실시: 기기 펌웨어 빌드 날짜를 아직 받지 못함"
  ],
  "vendor_evidence": ["family_source=evidence (fw_rootfs_audit)", "바이너리 이름 /usr/bin/Sofia → xiongmai", "배너 'uc-httpd 1.0.0' in /usr/bin/Sofia"],
  "evidence_bundles": ["analysis/rea-evidence-sofia-001.json"],
  "triage_reports": ["analysis/rootfs-audit-001.json", "analysis/strings-hunt-001.json", "analysis/elf-info-001.json"]
}
```

`checks[]` 는 두 부분으로 구성한다.
1. **AH-01 ~ AH-12**: 반드시 12개 모두 넣는다. 추가 키는 `pattern_class`, `confidence` 다.
2. **fw_strings_hunt 휴리스틱 결과**: `patterns="cctv"` 한 번의 실행에서 나온 result_path JSON 의 `checks[]` 를 **그대로** 이어 붙인다(위 예시는 일부만 보였다).
   다른 선택자로 다시 돌린 결과는 붙이지 않는다(같은 휴리스틱 id 가 겹친다). `custom-*` 결과도 붙이지 않고, 해당 AH 항목의 evidence_ref·description 에 적는다.

`coverage_gaps` 는 보고서의 "한계 및 미확인 사항" 절에 그대로 실린다. 예시의 `ev_…` 는 지면 때문에 줄였다. 실제로는 REA 가 준 evidence_id 전체를 쓴다.

## 다음 단계

- master-prompt Phase E: `report_generate(case_id="cam-001")` 로 `cases/<id>/report.md` 를 만든다. 그 다음 §10 형식으로 사용자에게 요약한다(핵심 finding, 미확인 사항, 기기 상태 "영구 변경 없음").
- 사용자가 원하면 템플릿 D 로 격리 랩 확인을 안내한다. 결과는 `case_update_finding` 으로 반영한다(`dynamically-confirmed` 또는 `false-positive`).
- 업데이트 처리·스트리밍 코드가 rootfs 밖에 있다면 `firmware-static-analysis` 로 돌아가 다른 파티션을 추출한다. 그 뒤 해당 AH 항목만 다시 판정해 summary 를 새로 저장한다.
  다음 Skill 은 최신 summary 를 읽지만, 보고서는 저장된 summary 를 모두 싣는다(이전 `coverage_gaps` 포함). 그래서 재판정은 끝난 뒤 한 번만 저장한다.
- 새 취약점으로 보이면 사용자에게 제조사 PSIRT 에 책임 있는 공개(coordinated disclosure)를 권한다. 결과를 같은 모델의 제3자 기기에 쓰지 않는다.

## 참고

- [checklist.md](checklist.md): AH-01 ~ AH-12 상세. 판정·evidence_ref·카테고리·심각도 규칙, strip 된 정적 바이너리 읽는 법.
- [docs/references/cctv-vuln-patterns.md](../../docs/references/cctv-vuln-patterns.md): §2 빠른 참조, §3 벤더 지형도, §4 CVE 카탈로그, §5 P1~P12, §6 정적 분석 절차, §7 안전한 검증.
- [docs/references/cctv-hunt-patterns.yaml](../../docs/references/cctv-hunt-patterns.yaml): 휴리스틱 id 원본. fwtriage 는 `src/pweh/data/` 의 동일 사본을 쓴다.
- [orchestrator/master-prompt.md](../../orchestrator/master-prompt.md): §1 절대 규칙, §5 데이터 전달, §6 협업·승인 형식. [docs/safety.md](../../docs/safety.md): §1 법적 범위, §7 데이터 취급.
- [mcp-servers/fwtriage-mcp/README.md](../../mcp-servers/fwtriage-mcp/README.md), [docs/references/pweh-mcp-tools.md](../../docs/references/pweh-mcp-tools.md), [docs/references/rea-mcp-tools.json](../../docs/references/rea-mcp-tools.json).
- 스키마: `schemas/auth-hunt.schema.json`(요약), `schemas/finding.schema.json`(발견사항).
