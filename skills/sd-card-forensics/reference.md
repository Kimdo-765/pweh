# SD 카드 포렌식 참고 (sd-card-forensics reference)

[SKILL.md](SKILL.md) 의 보충 자료다. 도구 이름·인자·기본값은 `docs/references/pweh-mcp-tools.md`(자동 생성 카탈로그)가 기준이고,
동작은 `mcp-servers/forensics-mcp/forensics_mcp/server.py`·`fsops.py`, `src/pweh/evidence.py`, `src/pweh/fs/` 를 따른다. 법률 메모는 법률 자문이 아니다.

## 1. 도구 응답 필드

| 도구 | 동작 | 볼 필드 |
|---|---|---|
| `forensics_intake_start` | job. 케이스 소유/허가 확인 → 접수 정보 검사(purpose·legal_basis·business_purpose 3~500자·제어 문자 없음, site_type·role 은 정해진 값, label 80자 이하) → (워커 스레드) 이미지를 한 번 연다: 경로의 링크는 한 번 풀고 일반 파일만(원시 디스크 `\\.\`·`/dev`·`/proc`·`/sys`·FIFO·디렉터리·빈 파일·E01 서명·NUL·케이스·상태 폴더 안의 파일·예약 이름 거부) → 이미징 로그(거부 검사 뒤 연 fd 로 4 MiB 까지) → 여유 공간(이미지 + 256 MiB, 디렉터리를 만들기 전) → 보관 기록 확인(깨졌으면 job 없이 `custody_broken`) → job: EV 번호(확보 잠금 안에서 커밋하지 못한 앞 접수를 정리) → 연 fd 로 확인한 크기만큼 읽으며 sha256·md5·sha1 과 사본 `<이름>.partial`(0444) → 복사 중 원본 크기·mtime 이 바뀌면 `integrity_failed` → `verify_copy` 면 사본 재해시 → 이름 바꿈 → 이미징 로그 대조·사본 보관 → 접수 기록(0444) → **보관 기록 intake(커밋 지점)** → 디렉터리 0555 → 출처 원장(imported-unattested)·아티팩트 `evidence-image`. 커밋 전 실패·취소는 만든 파일을 지우고 번호를 돌려놓는다. 커밋 뒤 취소는 무시하고, 커밋 뒤 보조 기록(integrity-failed 사건·출처 원장·아티팩트 색인·같은 sha256 확인) 실패는 접수를 실패로 만들지 않고 `post_commit_errors` 로 알린다(감사 로그 실패는 서버 로그에만) | 시작: `job_id`. result: `ok`(copy_verified 가 false 면 false), `evidence_id`, `stored_path`, `size`, `hashes`, `copy_verified`, `imaging_log{tool, comparison{status: match/mismatch/no-hashes, details}, conflicts}`, `custody_seq`, `provenance{seq, kind}` 또는 `{error}`, `next_steps`, 있으면 `duplicate_of`·`warning`(같은 sha256 경고와 로그 해시 불일치 경고가 함께면 ' / ' 로 이은 한 문장)·`error`·`post_commit_errors`·`note` |
| `forensics_job_status` | job 상태. `wait_seconds` 최대 50. 이 서버 프로세스의 job 만 — 앞 서버의 job 은 not_found | `status`(queued/running/cancelling/succeeded/failed/cancelled), `progress`, `eta_seconds`, `message`, `result`(cancelled 인 추출에도 있을 수 있다) 또는 `error{code, message, hint, data}`, `log_tail` |
| `forensics_jobs`, `forensics_job_cancel` | 이 서버 프로세스의 job 목록(`active_only`), 취소(다음 안전 지점에서 멈춤). 되돌릴 수 없는 지점(접수: 보관 기록 intake, 검증: 해시 끝, 추출: 보관 기록 extract)을 지난 job 의 취소는 무시한다 — 응답 status 가 그대로이고 끝나면 succeeded. 도구 설명의 '부분 결과는 보존된다'는 추출에만 맞다(커밋 전 접수는 되돌리고, 재해시 도중의 검증은 아무것도 기록하지 않는다 — §7 job cancelled) | — |
| `forensics_verify_start` | job. 열 때 보관 기록·접수 기록 대조와 빠른 지문(크기·mtime·앞뒤 1 MiB 해시·쓰기 권한 없음)이 어긋나면 job 없이 `integrity_failed`(기록). 사본 전체를 그 fd 로 재해시해 보관 기록 intake 의 해시와 비교 → 보관 기록 verify(불일치면 integrity-failed 사건도). 재해시 중 취소는 기록 없이 cancelled, 해시가 끝난 뒤 온 취소는 무시(기록하고 succeeded) | result: `ok`, `evidence_id`, `result`(match/mismatch — 읽는 동안 크기가 바뀌어도 mismatch), `details{sha256, md5, sha1}`, `custody_seq`, 있으면 `post_commit_errors`·`note`(integrity-failed 사건만 못 남김 — 상태는 그래도 integrity-failed) |
| `forensics_acquisition_attest` | 사람 증명 write-blocker. 증거 id·sha256·크기에 묶이고 90일 유효. 승인·거부는 이 도구가 그 결과를 볼 때 보관 기록 attest 로 한 번씩 남고, 철회·만료는 이 도구를 다시 부를 때 남는다(증거 목록은 증명 저장소의 지금 상태를 보인다) | 대기: `status` attestation_required, `attestation_id`(att-…), `kind`, `questions`(blocker_used·blocker_model·blocker_tested·imaging_tool), `how`, `summary`, 앞 결과가 있으면 `previous`. 승인: `status` approved, `attestation_id`, `blocker_tested` |
| `forensics_partitions` | 읽기 전용, 호출 예산 60초. 열 때마다 빠른 지문 확인. 같은 (시작, 크기) 구간은 한 번, 서로 다른 구간은 64개까지 연다 | `scheme`(mbr/gpt/superfloppy/none), `sector_size`, `image_size`, `partitions[{index, scheme, role, start_offset, size_bytes, start_lba, type_id, type_name, name·guid(GPT), bootable, fs_hint, warnings(10개까지 — partition_truncated·partition_beyond_image 등)}]`(128개까지), `partitions_total`, `volumes[{index, fs_hint, duplicate_of, omitted(partitions/time/steps), volume{fs_type, volume_label, volume_id, cluster_size, cluster_count, volume_size, truncated(볼륨이 읽을 수 있는 구간 — 파티션 표 항목과 이미지 끝 중 짧은 쪽 — 보다 김), dirty, …} 또는 error(시작이 이미지 끝 너머인 파티션은 data.reason beyond_image)}]`, `volumes_total`, `partitions_omitted`, `truncated`, `truncated_reason`(time/partitions/steps/response — 파티션을 다 열거나 싣지 못한 것이고 이미지 잘림과는 따로다), `warnings`(50개까지 — ebr_beyond_image 등), `next_steps` |
| `forensics_image_check` | 읽기 전용. 삭제 항목도 본다. 호출 예산 고정(120초·항목 200000·파티션 64·경로 글자 수 268,435,456, 같은 구간은 한 번), 볼륨마다 엔진 예산 하나(열기·정보·순회). 동기 — 취소되지 않는다 | `acquisition_date`, `volumes[{partition, fs, indicators[{indicator, strength, path(300자로 줄임), deleted, note}], walk_truncated(엔진 순회가 잘렸거나 서버가 더한 사유가 있음 — fs_list 의 volumes[].truncated 와 같은 규칙), walk_truncated_reason, walk_truncated_reasons(+ dir_unvalidated·image_truncated·volume_exceeds_partition), cut_dirs[{path, reason}] ≤10개, cut_dirs_total, unvalidated_dirs} 또는 {partition, fs, error}]`(지원하는 파티션이 없으면 비어 있다 — 흔적이 없다는 뜻이 아니다), `strong_indicators`, `call`(fs_list 와 같은 모양), `truncated`, `truncated_reasons`, `note`(본 볼륨이 없으면 '본 볼륨이 없어 흔적을 보지 못했다' — 그때 truncated 는 하나뿐인 파티션이 이미지 끝 너머처럼 사유(image_truncated)가 있으면 true, 지원하지 않는 파티션뿐이면 false), 잘렸으면 `next_steps` |
| `forensics_fs_list` | 전체 목록을 `forensics/analysis/fs-list-<EV>-NNN.json`(0444, `pweh.forensics.fs-list/v1`)에 볼륨마다 이어 쓰고 보관 기록 list 에 sha256 과 call. 호출 전체 한도: max_entries(1~200000)·max_seconds(1~600, 해석 시간 — 목록 쓰기는 별도)·파티션 64·경로 글자 수 268,435,456, 볼륨마다 엔진 예산 하나. 동기 — 취소되지 않는다. 실패한 호출은 확보한 목록 파일을 지운다 | `result_path`, `result_sha256`, `custody_seq`, `volumes[{partition, fs, volume, stats{files, dirs, deleted_files, deleted_dirs, orphans, dirs_read}, truncated, truncated_reason, truncated_reasons, cut_dirs[{path, reason}] ≤10개·경로 300자로 줄임, cut_dirs_total, time_ranges[{state, time_basis, first, last, files}], time_basis, top_dirs, extensions, files_with_residual, orphans, unvalidated_dirs, unvalidated_dirs_live, warnings_count, sample[20]} 또는 {partition, fs, error}]`(128개까지), `volumes_total`, `truncated`, `truncated_reasons`, `call{max_entries, entries_used, max_partitions, max_path_chars, path_chars_used, partitions_walked, partitions_skipped{사유: {count, examples}}, volumes_failed{count, examples[{partition, reason}]}}`, `next_steps` |
| `forensics_extract` | job(300초). ref 확인 순회(요청한 dirspec 을 다 찾으면 멈춤)·경로 찾기·후보 계산은 job 마감·취소 함수 안에서. 고른 파일만 `forensics/recovered/<label>-NNN/` 에 `NNNN-<정리한 이름>`(0444, 실행 비트·링크 없음)과 `manifest.json` → 디렉터리 0555 → 보관 기록 extract(커밋 지점) | result: `ok`, `evidence_id`, `output_dir`, `manifest`, `manifest_sha256`, `custody_seq`, `bytes_total`, `truncated`, `truncated_reasons`, `files[{seq, file, path, deleted, method, confidence, status, size, complete, sha256, limit_reason?, requested_path?}]`, `skipped`(50개까지 — 확인 단계 {ref\|path, code, reason}, 추출 단계 {ref, path, reason}), `skipped_total`, `note`, 있으면 `next_steps`. 매니페스트(열지 않음)는 여기에 ref·region·note·expected_size·runs_total·conflicts·bytes_beyond_image 와 skipped 전체를 더 싣는다 |
| `forensics_evidence_list` | 보관 기록 전체를 다시 읽어 상태를 정한다. 그 전에 커밋한 증거마다 접수 기록·사본 지문을 대조해 새 문제를 무결성 실패로 기록한다(`write_files=false` 여도). `write_files`(기본 true)면 `forensics/evidence-list.json`·`.md` 를 쓰고 보관 기록이 멀쩡하면 evidence-list 사건 | `custody{ok, count, head, detail}`, `items[{evidence_id, label, stored_path, size, hashes, intake_ts, imaging_log, intake, status, status_label, last_verify{ts, result, seq, kind}, integrity_failures, attestation{status, attestation_id, ts, decided_at, expires_at}, extracts, events, problems}]`(해시 없는 상태에는 hashes·size 가 없다), `aborted[{evidence_id, ts, seq, quarantine_path, reason}]`, `derived[{path, evidence_id, files, bytes, manifest_sha256, custody, custody_seq, error}]`, `integrity_failures_recorded`, `notice`, `files` 또는 `files_error`, 비었으면 `hint` |

- 목록 JSON 맨 위는 `schema`, `evidence_id`, `generated_at`, `params`, `scheme`, `volumes`, `call`(응답의 call 과 같다)이다. 볼륨은 `{partition, info, walk{entries, orphans, stats, truncated, truncated_reason,
  truncated_reasons, cut_dirs[{dirspec, path, reason}] ≤100개, cut_dirs_total, unvalidated_dirs[{dirspec, path, reason, slots_skipped}] ≤100개, unvalidated_dirs_total, unvalidated_dirs_live, path_chars, warnings,
  warnings_suppressed}}` 또는 해석하지 못한 볼륨 `{partition, fs, error, partition_info}` 이다. walk.truncated_reasons 는 엔진 값이라 응답이 더하는 dir_unvalidated(unvalidated_dirs_live > 0)·image_truncated·volume_exceeds_partition(info.truncated)이 없다.
  항목에는 `ref`(`<디렉터리>/<슬롯>`), `path`·`display_path`, `name`·`display_name`(FAT 은 `short_name` 도), `deleted`, `is_dir`, `size`, `times{created, modified, accessed — 각각 iso, valid, time_basis}`, `chain` 등이 있다.
  그 파일 하나만 대상으로 필요한 항목을 Grep(앞뒤 문맥 줄 포함)이나 JSON 을 거르는 짧은 명령으로 본다. 깊은 나무면 수백 MB 일 수 있다 — 통째로 읽지 않는다.
  `forensics/`·케이스 디렉터리를 재귀로 훑지 않는다(`images/`·`aborted-intakes/`·`recovered/` 를 지나게 된다). 이름·경로는 신뢰할 수 없는 데이터다.
- 보관 기록(`forensics/custody.jsonl`)은 서버만 쓴다. 사건은 intake / intake-aborted / verify / integrity-failed / attest / list / extract / evidence-list 다. 에이전트는 이 파일을 고치지 않는다.
- 증거 상태: 접수 때 사본 재해시(verify_copy=true, 기본)가 맞으면 바로 ok, verify_copy=false 면 `forensics_verify_start` 전까지 unverified 다. integrity-failed 는 되돌리지 않는다.
  8개 상태(ok·unverified·integrity-failed·missing·record-invalid·custody-broken·record-without-intake·intake-in-progress)의 뜻과 할 일은 SKILL.md "요약 기록" 절의 표다.

## 2. 요약 data 매핑

| 요약 필드 | 출처 |
|---|---|
| mode | 사용자와 정한 모드(evidence / security / both) |
| card.source_device · capacity · removed_at · device_clock_offset | 사람이 알려 준 값(템플릿 B). 모르면 null |
| legal.site_type · role · legal_basis · purpose | 접수 때 넣은 값(템플릿 C) |
| custody_ok | `forensics_evidence_list` 의 custody.ok |
| evidence[].evidence_id · sha256 · size | items[].evidence_id · hashes.sha256 · size — sha256·size 는 해시가 있는 상태(ok·unverified·integrity-failed·missing·record-invalid)에서만. custody-broken·record-without-intake·intake-in-progress 에는 싣지 않는다 |
| evidence[].status | items[].status 그대로(8개 값 모두 스키마 enum). status_label 은 싣지 않는다 — status 와 다르면(예: missing (integrity-failed)) notes 에 |
| evidence[].imaging_log | items[].imaging_log.status, null 이면 "none" |
| evidence[].write_blocker | items[].attestation.status(approved/denied/revoked/expired/invalid), null 이면 "none" |
| filesystems[].evidence_id · partition | 볼륨마다 하나. partition 은 `forensics_partitions` 의 index, scheme 이 superfloppy(파티션 표 없음)면 null(도구 인자로는 index 1) |
| filesystems[].fs | fs_hint 대응: fat12·fat16·fat32·exfat·ext4·ntfs 는 그대로, exfat-invalid 는 exfat(notes 에 "부트 섹터 검사 실패"), ext2·ext3·f2fs·squashfs·luks 는 other(notes 에 원래 값 — luks 는 암호화), zeroed·unknown·null 은 unknown |
| filesystems[].label · dirty | volume.volume_label(카드 텍스트 — 옮기기만), volume.dirty |
| filesystems[].files · deleted | stats.files · stats.deleted_files (목록을 못 본 볼륨은 생략). 잘린 볼륨(truncated)은 본 범위의 개수다 — 사유를 notes 에 |
| filesystems[].time_basis · time_range | 볼륨의 time_basis(local-unknown-tz / local+offset / mixed / unknown). time_range 는 state live 의 first·last — 바탕이 여럿(mixed)이면 null 로 두고 바탕별 범위를 notes 에 |
| device_timezone | 근거가 있을 때만(펌웨어의 마운트 옵션 `tz=`·`time_offset=`, init 스크립트 TZ). 없으면 assumed·basis 모두 null |
| contamination[] | `forensics_image_check` 의 volumes[].indicators[] → {evidence_id, indicator, strength}. path 는 싣지 않는다(카드 경로). image_check 가 truncated 면 "본 범위에서만"과 사유를 notes 에 |
| recovered | `forensics_evidence_list` 의 derived[] 중 recovered/ 아래 추출 매니페스트 항목에서 custody 가 recorded 인 항목의 합계: files, bytes, manifests = derived[].path + "/manifest.json" (경로만 — 열지 않음). mismatch·unrecorded·missing·unknown·error 항목은 notes 에 적고 사람에게 알린다 |
| security.sd_surface_result | `fw_sd_surface` 의 result_path(`analysis/sd-surface-NNN.json`) |
| security.checks_found | `risk_found`. SD-07 found(암호화 근거)는 넣지 않고 notes 에 |
| security.sd_events_summary | 새 빈 시험 카드 부팅의 `sd_summary` 그대로. 관찰하지 않았으면 null |
| security.card_matches_firmware_paths | 10c 대조에서 카드에 있던 `card_relative` 목록. 대조했는데 없으면 [], 대조하지 않았으면 null |
| privacy | 기존 네 값은 false(영상·음성·별도 신원 식별·외부 제공). `still_image_content_viewed`·`still_image_ocr_returned`는 정지 이미지 도구의 실제 반환·관찰 여부 |
| notes | 한계, 잘림 사유와 못 본 범위(목록·오염 검사·추출의 truncated_reasons, volumes_failed), status_label 이 status 와 다른 항목, 목록·증거 목록 경로, 발견사항 id, 시간대 근거 |

스키마에 맞는지는 `schema_get(name="sd-forensics")` 로 확인한다. 서버가 거부하면 메시지대로 고쳐 다시 저장한다.

## 3. 보안 분석 세부

**`fw_sd_surface` 응답**: `result_path`, `input`, `counts{found, not-found, unknown}`, `risk_found`, `checks[{id, title, status, severity_hint, category, found_means, evidence_total, evidence[≤3], unknown_reason, next_steps, severity_reason}]`,
`mount_points`·`mount_points_total`, `sd_paths_referenced[{path, card_relative, actions, checks}]`·`sd_paths_total`·`sd_paths_truncated`, `truncated`, `limitations`, `uboot`, `fit_security`, `next_steps`.
결과 파일에만 근거 전체, 마운트 명령의 옵션, 핫플러그 처리기, `phases`(complete/truncated)가 있다. 오래 걸리면 `background=true` 와 `fwtriage_job_status`.

| 점검 | 내용 | category |
|---|---|---|
| SD-01 | 부팅·핫플러그 때 카드 내용 실행(rcS·init.d·mdev.conf·udev RUN+=·hotplug, 복사·복호화 뒤 실행 포함) | backdoor |
| SD-02 | 카드에서 서명 없는 펌웨어 업데이트(U-Boot 업데이트 명령, 사용자 공간 카드→플래시) | insecure-update |
| SD-03 | U-Boot 의 mmc 부팅·카드의 boot.scr/uEnv/env import, verify 꺼짐, 환경 쓰기 가능 | insecure-default |
| SD-04 | 카드 삽입 처리기 | other |
| SD-05 | 카드에서 설정 가져오기(값이 system()/popen 으로 가는지 — AH-04 와 교차) | insecure-default |
| SD-06 | 카드에 민감 정보 기록(로그·코어 덤프) | info-leak |
| SD-07 | 녹화 암호화 — found 가 보호 근거(found_means protection) | weak-crypto |
| SD-08 | 약한 마운트 옵션(noexec/nosuid/nodev 없음, umask=000), `discard`·fstrim(삭제 데이터 복구 가능성에 영향) | insecure-default |
| SD-09 | 카드 내용의 네트워크 노출(웹 루트·FTP·Samba) | info-leak |

- `fw_rootfs_audit(case_id="<id>", rootfs_dir="extract/rootfs-001", sd_surface=true)`: rootfs 쪽만 본다. U-Boot 쪽 근거가 없으므로 SD-02·SD-03 은 unknown 이다 — U-Boot 쪽은 `fw_sd_surface` 의 image_path 로 본다.
- `fw_uboot_env(case_id="<id>", path="dumps/flash-full.bin")` 의 env 마다 `sd_boot`: fatload/ext4load/load mmc, mmc 에서 읽는 boot.scr·uEnv.txt·env import, distro boot, mmc 를 플래시보다 먼저 시도하는지, verify 꺼짐, SD 업데이트, CRC 유효 env 의 saveenv 쓰기 가능성. mmc 장치 번호로는 SD 와 eMMC 를 구분하지 못한다.
- `fit_security`는 비압축 FDT v17의 이미지/설정 서명 선언과 control-DTB 형태 키 후보를 구조로 관찰한다. `complete/partial/not-examined`와 검색/구조/출력 완료도를 구분하고, 선언의 존재·부재를 서명 유효성·키 신뢰·부팅 강제·SD 경로 증명으로 쓰지 않는다. `verify_off`도 환경값 관찰이며 실제 적용은 추가 근거가 필요하다. [상세 계약](../../docs/references/fit-security-structure.md).
- `discard`·fstrim 이 있으면 지운 데이터가 카드에서 사라졌을 수 있다 → evidence 의 삭제 파일 복구는 "복구 가능성 조건부" 로 notes 에 적는다.
- 펌웨어의 `tz=`·`time_offset=` 마운트 옵션이나 init 스크립트 TZ 는 device_timezone 의 근거가 된다(가정으로만 — 사용자가 장치 설정을 바꿨을 수 있다).
- **부팅 로그**: `uart_capture_boot` 의 `sd_events[{line, kind, also, text}]` kind 는 card-detected·card-removed·card-absent·block-device·partition·fs-mount·fs-error·uboot-mmc·uboot-script(boot.scr·uEnv.txt 읽기)·update·script·card-other 다.
  `sd_summary{card_detected, card_absent, counts, devices, filesystems, events_total, truncated, long_lines_skipped}` — eMMC·SDIO 줄은 counts 의 emmc·sdio 로만 센다. update·script·uboot-script 줄이 있으면 `sd_note` 가 붙는다.
  카드 없음과 시험 카드의 두 로그를 비교해 카드가 감지·마운트되는지, 카드에서 무엇을 찾는지(업데이트 파일 이름·스크립트)를 본다. 그 이름의 파일을 만들어 넣어 보지 않는다.
- **카드와 펌웨어 대조(10c)**: 기존 전체 보고서 둘을 `forensics_sd_ioc_scan`으로 검증·대조한다(§11). ASCII 대소문자 변형도 후보일 뿐 실제 FAT/OEM·exFAT up-case lookup을 확인하지 않는다. 삭제·손상 이름과 목록/스캐너 잘림을 보존한다.

## 4. security 만 한 요약 예시

카드 없이 펌웨어만 본 경우다. mode 가 security 면 legal·evidence·custody_ok 가 필요 없다. 아래는 모양을 보이는 합성 값이며 sd-forensics 스키마 검증을 통과한다.

```json
{
  "mode": "security",
  "device_timezone": {"assumed": "UTC+09:00", "basis": "rootfs 의 init 스크립트 TZ=KST-9 (펌웨어 기본값 — 사용자가 바꿨을 수 있음)"},
  "security": {
    "sd_surface_result": "analysis/sd-surface-001.json",
    "checks_found": ["SD-01", "SD-02", "SD-08"],
    "sd_events_summary": null,
    "card_matches_firmware_paths": null
  },
  "privacy": {"audio_decoded": false, "face_plate_processing": false, "uploads": false, "recording_content_viewed": false},
  "notes": [
    "입력: firmware-static-analysis 요약의 dumps/flash-full.bin, extract/rootfs-001",
    "SD-03 unknown — CRC 가 맞는 U-Boot env 를 찾지 못함",
    "SD-07 unknown — 녹화 암호화 근거를 찾지 못함(암호화가 없다는 증명은 아님)",
    "부팅 로그는 관찰하지 않음 — 새 빈 시험 카드가 없음"
  ]
}
```

## 5. 법률·개인정보 메모 (법률 자문 아님)

설계 `docs/design/sd-forensics.md` §7 의 요약이다(2026-10-19 원문 기준). 사용자에게 법적 판단을 하지 않고, 아래는 접수 정보를 묻는 이유와 행동 규칙의 근거로만 쓴다.

| site_type | 뜻 | role | 뜻 |
|---|---|---|---|
| home | 개인 가정용(업무 목적 아님) | owner | 기기·카드 소유자 본인 |
| public | 공개된 장소에 설치(개인정보 보호법 제25조①) | processor | 소유자의 위탁을 받은 수탁자(위탁 문서 필요) |
| business | 업무용 비공개 장소 | investigator | 적법한 권한으로 의뢰받은 조사자 |
| vehicle | 차량(블랙박스) | other | 기타(notes 에 설명) |
| mobile-business | 업무 목적의 이동형 기기(제25조의2) | | |
| unknown | 모름 | | |

- 개인정보 보호법 제25조④~⑧(안내판·녹음 금지 등)과 표준지침의 영상 장은 공개된 장소의 운영자와 업무 목적 이동형에 적용된다. 개인 가정용 카메라는 대부분 밖이지만 통신비밀보호법 제3조·제14조·제16조는 그대로 적용된다. 복구도 개인정보 "처리"다(제2조2호).
- 오디오는 메타데이터(있음·코덱·길이)만 다룬다. 재생·전사·내보내기를 하지 않는다. 얼굴·번호판 처리, 업로드, 제3자 제공·열람용 사본도 만들지 않는다(PWEH 에는 마스킹 기능이 없다).
- 복구한 Wi-Fi 키·클라우드 토큰·계정으로 어디에도 로그인하지 않는다(정보통신망법 제48조①).
- 모든 보고에 고지를 싣는다: PWEH 는 인증·검증된 포렌식 도구가 아니다. 법적 용도라면 원본 카드를 보존하고 원본·이미지·보관 기록을 자격 있는 전문가에게 넘긴다. 해시값 확인서(`forensics/evidence-list.md`)의 서명은 사람이 한다.

## 6. 카드와 펌웨어 경로 일치의 해석

이름이 같다는 사실만으로 `backdoor`·`high` 발견사항을 만들지 않는다. 정상 설정·로그·업데이트 파일도 같은 이름을 사용한다. `forensics_sd_ioc_scan` 결과는 §11의 요약 참조로 남기고, 실행 경로·내용·장치 연관성에 대한 별도 근거가 있을 때만 그 근거로 발견사항을 작성한다. 파일 내용을 직접 열거나 실행하지 않는다.

## 7. 실패 처리 전체

동기 도구의 오류는 `[code] 메시지` + `힌트:` 텍스트로(세부 data 는 오지 않는다), job 의 오류는 `forensics_job_status` 의 error{code, message, hint, data} 로 온다. 해석 엔진의 오류는 code 가 validation_failed 이고 사유는 data.reason 이다.

| 오류 / 상태 | 뜻 | 조치 |
|---|---|---|
| `authorization_required` | 케이스에 소유/허가 증명이 없다 | 멈추고 master-prompt §1-1. 증명이 생기면 같은 인자로 다시 |
| `validation_failed` (접수) | 원시 디스크·장치·커널 경로, 디렉터리·FIFO 등 일반 파일 아님, 빈 파일, E01(raw 로 내보내야 함), NUL 이 든 경로, 케이스·상태 폴더 안의 파일, 예약 이름(EV-NNNN.json·imaging-log.txt·*.partial), 접수 정보 길이·제어 문자·허용 값, label, 여유 공간, 이미징 로그(4 MiB 이하 일반 파일, 읽는 동안 커지면 거부), 확인하는 동안 바뀐 원본 | 메시지를 사람에게 전하고 고친 값으로 다시. 케이스 안 이미지는 사람이 밖으로 옮긴다 |
| `validation_failed` (해석, 동기) | partition 값·범위(1~4096)·없는 index, acquisition_date 형식(YYYY-MM-DD), refs·paths 없음·합쳐 1000개 초과, region 값, method 형식, max_bytes 형식, 추출 여유 공간(max_bytes + 256 MiB), FAT/exFAT 파티션 없음(fs_list — 파티션이 이미지 끝 너머라 볼 수 없으면 메시지가 잘린 이미지라고 알린다), 고른 partition 의 시작이 이미지 끝 너머(잘린 이미지), 지원하지 않는 파일 시스템 | 인자를 고친다. 지원하지 않는 파일 시스템은 filesystems[] 와 notes 에 적고 멈춘다. 잘린 이미지면 사람에게 알리고 이미징이 끝까지 됐는지 확인하게 한다 |
| `validation_failed` (추출 job — error.data.reason) | bad_argument(FAT/exFAT 파티션이 여럿인데 partition 없음), not_found(없는 partition), unsupported_fs(지원 파티션 없음·지원하지 않는 파일 시스템), beyond_image(고른 partition 의 시작이 이미지 끝 너머, 또는 파티션이 이미지 끝 너머라 볼 수 있는 FAT/exFAT 파티션이 없음 — 잘린 이미지), refs_unverifiable(확인 순회가 잘려 검증된 ref 가 없고 paths 도 없음 — ref 가 모두 bad_ref 인 것은 실패가 아니다) | partition 을 고치거나 paths= 로 다시. beyond_image 는 사람에게 알리고 이미징을 확인하게 한다. refs_unverifiable 이 계속되면 사람에게 알린다 |
| `not_found` | 증거 id 가 없다 / job이 이 서버 프로세스나 지정 케이스의 저장 기록에 없다 | `forensics_evidence_list` 로 확인. `forensics_job_status(job_id="<id>", case_id="<케이스 ID>")`로 저장 기록을 확인한다. recovery.owner_state가 unknown이면 실행 중 여부를 확정하지 않는다 |
| `integrity_failed` (기록함) | 빠른 지문 불일치, 사본 없음·일반 파일 아님·읽을 수 없음, 접수 기록 없음·읽을 수 없음·보관 기록 intake 와 다름, 증거 디렉터리 경로 이상(EV 디렉터리가 링크·파일 — unsafe-path. 증거 목록에는 missing 으로 보인다) | SKILL.md 규칙 7·템플릿 F. 원본에서 다시 접수(새 EV). 사본을 고치지 않는다 |
| `integrity_failed` (기록 없이 거부) | 이미 무결성 실패인 증거, EV 디렉터리가 지워짐(missing — '지워짐'), 보관 기록에 접수가 없는 EV 디렉터리(record-without-intake·intake-in-progress), 같은 번호의 접수 사건이 둘 이상. 접수 job 에서는 복사 중 원본 크기·mtime 변화(번호 반환) | 위와 같다. 상태별 할 일은 SKILL.md 요약 기록 절의 표 |
| 재해시 result mismatch, 접수 결과 copy_verified false(ok false·error) | 사본 전체가 접수 때(접수 사본 재해시면 원본 해시)와 다르다 — 오류 코드가 아니라 job 결과다(job 은 succeeded). 서버가 integrity-failed 를 기록한다(접수는 intake 사건의 copy_verified=false 만으로도 상태 integrity-failed). 그 뒤 내용 도구는 `integrity_failed` 로 거부한다 | 위와 같다 |
| `custody_broken` | 보관 기록 체인이나 보호 위치 고정점과 어긋난다, forensics/ 자체가 링크다 — 내용 도구와 기록 쓰기가 모두 거부된다 | 멈춤, 템플릿 G. 요약은 custody_ok false, status failed. 기록 파일을 고치지 않는다 |
| `path_outside_base` | 서버가 쓰려는 forensics/ 아래 디렉터리(images/·analysis/·recovered/·aborted-intakes/)가 심볼릭 링크·파일이거나, 새 추출 디렉터리에 서버가 만들지 않은 항목(링크 등)이 생겼다 — 따라가 쓰지 않았고 실패한 추출은 출력 디렉터리를 지웠다. 내용 도구가 여는 EV 디렉터리가 링크·파일이면 이 코드가 아니라 `integrity_failed`(unsafe-path, 기록함)다 | 멈추고 사람에게 알린다(누가 forensics/ 를 바꾸는지 확인). 에이전트는 링크를 지우거나 forensics/ 를 고치지 않는다 |
| `busy` | 같은 원본의 접수, 같은 증거의 검증·추출이 이미 돌고 있다 | `forensics_jobs(active_only=true)` 로 확인하고 기다린다 |
| `lock_timeout`, `unsafe_file` | 보관 기록·EV 번호 확보 잠금을 30초 안에 얻지 못했다 / 번호 확보 잠금 파일(`images/.claim.lock`) 자리에 일반 파일이 아닌 것(링크·FIFO)이 있거나, 보관 기록 잠금 파일이 읽은 뒤 덧붙이기 전에 바뀌었거나, 접수 중 사본이 확인한 뒤 바뀌었다(접수는 되돌린다). 보관 기록 잠금 파일(`.custody.lock`)이 처음부터 일반 파일이 아니면 읽을 때 `custody_broken` 이다 | 다시 시도하고, 계속되면 멈추고 사람에게 알린다(다른 프로세스·forensics/ 확인). 에이전트는 잠금 파일을 고치지 않는다 |
| job cancelled | 사람이 중지 | 접수: 커밋 전이면 만든 파일을 지우고 번호를 돌려놓았다(커밋 뒤 취소는 무시 — succeeded). 검증: 재해시 중이면 기록 없음(해시 뒤 취소는 무시). 추출: result 가 없으면 ref 확인·경로 찾기 중 멈춰 출력·보관 기록이 없고, result 가 있으면 그때까지 쓴 파일·매니페스트·보관 기록 extract 가 남았다(시도하지 않은 항목 '취소됨', truncated_reasons cancelled) |
| 추출 job failed | 출력 디렉터리를 지웠다. 보관 기록 extract 를 남긴 뒤의 실패면 출력이 남는다 | 증거 목록 derived 에서 recorded 인지 확인하고 사람에게 알린다 |
| volumes_failed (volumes[].error) | 볼륨을 열거나 해석하지 못했다(손상 이미지일 수 있다, reason internal_error 포함). truncated=true, image_check 는 '흔적 없음'이라 하지 않는다. error.data.reason 이 budget_exceeded 면 실패가 아니라 한도(call.partitions_skipped 의 time·steps) | 사람에게 알리고 partition 을 지정해 다시 보거나 보고서 한계에 적는다 |
| budget_exceeded | 엔진 예산(시간·단계·취소, data.limit)이 다 됐다 — 목록·오염 검사에서는 그 볼륨의 error, 추출에서는 그 파일이 skipped 이고 truncated_reasons 에 time·steps | time 은 범위를 줄이거나(partition) max_seconds 를 늘린다(fs_list). steps 는 사람에게 알린다 |
| 증명 denied / previous denied | 사람이 쓰기 방지 장치를 쓰지 않았다고(또는 폼을 거절) 답했다 | 다시 묻지 않는다. write_blocker denied, notes. 계속할지는 사용자가 정한다 |
| 증명 revoked / expired / invalid | 사람이 철회했거나 90일이 지났거나 증명 레코드를 믿을 수 없다 | 그 상태를 요약에 적는다. 다시 증명할지는 사람이 정한다 |
| 목록·오염 검사 truncated | 한도·예산, 끝까지 읽지 못한 디렉터리, 잘린 이미지 | [§8](#8-잘림불완전-사유와-사람에게-알릴-것) 의 사유별 할 일. 못 본 범위는 notes·blockers |
| 추출 skipped (확인 단계 code) | bad_ref(모양이 틀린 ref, 순회를 끝까지 돌았는데 없는 디렉터리, 검증하지 못한 영역 — ref 가 모두 bad_ref 이고 paths 가 없어도 job 은 성공하고 파일 0개 추출이 보관 기록에 남는다), refs_unverifiable(그 ref 의 디렉터리를 확인하지 못함), ambiguous_path(이름에 맞는 항목이 둘 이상), not_found(검증된 디렉터리를 끝까지 읽었는데 없음 — 삭제 파일은 refs 로), max_depth·max_dir_slots·beyond_image·dir_chain_broken·dir_unvalidated(§8 — 그런 디렉터리에서는 정확히 같은 이름만 받으므로 대소문자·8.3 별칭으로만 맞아도 이 code), dir_unreadable(읽지 못한 살아 있는 디렉터리를 지나는 paths·그 디렉터리를 가리키는 ref), time·steps·cancelled | bad_ref·not_found 는 목록 JSON 의 ref 로 다시 고른다. ambiguous_path 와 대소문자만 맞아 거부된 경로는 대소문자까지 정확한 이름이나 ref 로. dir_unreadable 은 '없음'으로 보고하지 않고 사람에게 알린다. 나머지는 §8 |
| 추출 skipped (추출 단계, 사유 문장) | 디렉터리(파일 ref 를 달라), 파일 수·바이트 상한, 작업 시간 한도, 후보 예산, 그 파일에 없는 method(가능한 방법 목록), '취소됨' | 사유대로 다시 고르거나 notes 에 적는다 |
| 증거 목록 status missing·record-invalid·record-without-intake·intake-in-progress | SKILL.md 요약 기록 절의 표 | 사람에게 알린다 |
| `pweh-fwtriage` 가 `forensics/` 경로를 거부, `case_import_file`·`case_hash_file`·`case_register_artifact` 가 거부 | 펌웨어 도구·케이스 도구는 증거 폴더를 읽지 않는다 | 정상이다. 다른 도구로 우회하지 않는다 |
| `uart_capture_boot` 에 sd_events 없음, card_detected false | 감지 줄을 못 봤다(카드가 없다는 뜻은 아님) | 콘솔 로그 수준·관찰 시간(`duration`)을 확인하고, 결과는 그대로 적는다 |

**아직 없는 것**(F2·F3 단계): 선택 BMFF 구조·제한된 선언 관찰 밖의 녹화 컨테이너·프레임 해석과 CCTV 인덱스(Hikvision·Dahua 등), 녹화 타임라인, 카드 쪽 녹화 암호화 판정·전체 카드 비밀값 자동 탐색·카드 내용의 침해 판정, 원시 이미지 구간 카빙,
E01 입력과 외부 도구(TSK·PhotoRec·ewf·ffprobe), ext4·NTFS 목록, 장치에서 카드 식별 정보 읽기, Windows 원시 읽기 헬퍼, 영상 내보내기.
이것들은 셸이나 외부 프로그램으로 대신하지 않는다. 필요했던 일은 요약 notes 와 `case_record_step` 의 blockers·next_actions 에 "아직 없음" 으로 적는다.

## 8. 잘림·불완전 사유와 사람에게 알릴 것

`forensics_fs_list`(volumes[].truncated_reasons, 맨 위 truncated_reasons)·`forensics_image_check`(volumes[].walk_truncated_reasons, truncated_reasons)·`forensics_extract`(truncated_reasons, skipped 의 code)의 사유다.
응답의 next_steps 에도 사유별 안내가 온다. 다시 부를 수 있는 사유(time·max_entries·max_partitions)만 인자를 늘리거나 partition 으로 나눠 다시 부른다(image_check 의 120초와 두 도구의 파티션 64개는 고정이라 나누기만 한다).
고정 한도와 이미지·카드 상태는 max_seconds 를 늘려 답하지 않는다 — 사람에게 알리고 요약 notes·blockers 와
보고서 한계에 적는다(요약 status partial). 한계의 배경은 `docs/safety.md` §3.6 이다.

| 사유 | 나오는 곳 | 뜻 | 할 일 |
|---|---|---|---|
| time | 셋 다 | 시간 한도 — 목록은 max_seconds(호출 전체), 오염 검사는 120초(고정), 추출은 job 300초. exFAT 루트가 아주 크면 열 때와 순회에서 두 번 읽어(루트 슬롯 100만 개에 약 9초씩) 작은 max_seconds 로는 0 항목일 수 있다 | 목록: max_seconds 를 늘리거나(최대 600) `partition=<index>` 로 나눠 다시. 오염 검사: partition 으로 나눠서만. 추출: 남은 ref·paths 로 다시 |
| steps | 셋 다 | 볼륨의 작업 단계 상한 — 정상적으로 꽉 찬 볼륨은 닿지 않는다(같은 긴 체인을 여러 항목이 가리키는 조작·손상 이미지일 수 있다) | 사람에게 알리고 보고서 한계에 적는다 |
| cancelled | 추출 | 취소로 끝까지 하지 못함 | 필요하면 다시 부른다 |
| max_entries | 목록·오염 검사 | 항목 수 상한(호출 전체 합계, 최대 200000) | 목록: max_entries 를 늘리거나 partition 으로 나눠 다시. 오염 검사: partition 으로 나눠 다시 |
| max_partitions | 목록·오염 검사(맨 위) | 서로 다른 파티션 64개까지만 봤다(call.partitions_skipped.partitions) | 나머지는 `partition=<index>` 로 따로 본다 |
| max_total_slots | 목록·오염 검사 | 디렉터리 슬롯 합계 상한(8,388,608) — 디렉터리가 아주 많거나 크다(조작 의심) | 사람에게 알리고 보고서 한계에 적는다 |
| max_path_chars | 목록·오염 검사 | 경로 글자 수 상한(호출 전체 268,435,456) — 깊고 긴 경로가 아주 많다(조작 의심). 한 볼륨이 이 사유로 멈추면 뒤 파티션은 건너뛴다 | 여러 파티션이면 partition 으로 나눠 보고, 사람에게 알린다 |
| max_depth | 셋 다(추출은 paths 의 code) | 고정 한도 — 깊이 64 의 디렉터리 항목은 싣지만 안으로 내려가지 않는다(cut_dirs). 그 아래 항목은 목록·ref 가 없어 추출할 수 없고, 64단계보다 깊은 paths 는 code max_depth | 사람에게 알리고 보고서 한계에 적는다 |
| max_dir_slots | 셋 다(추출은 code) | 고정 한도 — 디렉터리가 슬롯 한도(FAT 65,536, exFAT 1,048,576)보다 길고 그 안에 끝 표시가 없어 앞부분만 읽었다(cut_dirs, 경고 dir_slot_limit). 뒤쪽 항목은 목록에 없고, 뒤쪽을 가리키는 ref·뒤쪽에 있을 수 있는 paths 는 code max_dir_slots | 사람에게 알리고 보고서 한계에 적는다 |
| beyond_image | 셋 다(추출은 code) | 살아 있는 디렉터리의 데이터가 읽을 수 있는 범위(파티션 표 항목과 이미지 끝 중 짧은 쪽) 끝 너머라 끝까지 읽지 못했다(cut_dirs — 읽은 앞부분 항목은 목록에 있다). 원인은 같은 볼륨의 image_truncated(잘린 이미지)·volume_exceeds_partition(파티션 표보다 큰 파일 시스템)으로 본다. 고른 파티션의 시작이 이미지 끝 너머면 추출 job 이 이 사유(error.data.reason)로 실패한다(§7) | 사람에게 알리고 보고서 한계에 적는다. 원인이 image_truncated 면 이미징이 끝까지 됐는지 확인하게 한다(필요하면 다시 이미징) |
| image_truncated | 목록·오염 검사 | 이미지가 카드보다 짧다 — 볼륨 끝(파티션 시작 + 볼륨 크기)이 이미지 끝 너머이거나(volume.truncated — 그 볼륨의 사유), partition 을 고르지 않았을 때 파티션이 통째로 이미지 끝 너머다(forensics_partitions 의 partition_beyond_image·ebr_beyond_image — 호출의 truncated_reasons 에만). 대개 이미징 중단·용량을 속인 카드. 끝 너머의 파티션·디렉터리·파일 내용·삭제 흔적은 보이지 않는다. partition_truncated(파티션 항목의 끝만 이미지 밖)만으로는 이 사유가 아니다 | 사람에게 알리고 이미징이 끝까지 됐는지 확인하게 한다(필요하면 다시 이미징). 보고서 한계에 적는다 |
| volume_exceeds_partition | 목록·오염 검사 | 이미지는 이어지는데 파일 시스템이 파티션 표 항목보다 크다(volume.truncated) — 파티션 표가 줄었거나 손상됐을 수 있다. 항목 밖으로 이어지는 부분의 디렉터리·파일 내용은 이 파티션으로 읽지 않는다(다른 파티션의 데이터를 이 볼륨 것으로 읽지 않게) | 사람에게 알리고 보고서 한계에 적는다 |
| dir_chain_broken | 셋 다(추출은 code) | 살아 있는 디렉터리의 클러스터 체인이 끝 표시 전에 비정상으로 끝나 뒤쪽 항목을 읽지 못했다(cut_dirs — 읽은 앞부분 항목은 목록에 있다. exFAT 은 DataLength 보다 짧은 체인 포함 — 체인이 읽을 길이(DataLength, 슬롯 한도보다 길면 한도까지)를 다 모았으면 마지막 FAT 항목이 망가져도 잘림이 아니고 경고 dir_chain_* 만. DataLength 가 슬롯 한도보다 길고 한도 안에 끝 표시가 없으면 그래도 max_dir_slots) — 카드 손상일 수 있다 | 사람에게 알리고 보고서 한계에 적는다 |
| dir_unreadable | 셋 다(추출은 code) | 살아 있는 디렉터리를 읽지 못했다(cut_dirs, 경고 dir_unreadable — 그 디렉터리의 내용은 하나도 목록에 없다) — 카드 손상일 수 있다. 추출에서는 그런 디렉터리를 지나는 paths·그 디렉터리를 가리키는 ref 의 code 다(그 아래를 가리키는 ref 는 refs_unverifiable) | 사람에게 알리고 보고서 한계에 적는다 |
| dir_unvalidated | 셋 다(추출은 paths 의 code) | 살아 있는 디렉터리 일부가 디렉터리 데이터로 검증되지 않아 그 뒤쪽 항목은 목록에 없다(unvalidated_dirs_live, 경고 dir_unvalidated) — 손상·교차 연결이거나 엔진이 일부러 엄격하게 거르는 형식 | 사람에게 알리고 보고서 한계에 적는다 |
| refs_unverifiable | 추출 | 확인 순회가 위 사유로 끝까지 가지 못해 그 ref 의 디렉터리를 확인하지 못했다(찾은 ref 는 추출했다) | 살아 있는 파일은 paths= 로 고르거나 partition 을 지정해 다시. 계속되면 사람에게 알린다 |
| max_files, max_bytes | 추출 | 파일 수(최대 1000)·바이트 상한(최대 4 GiB)이 실제로 잘랐다 | 남은 ref 로 다시 하거나 max_bytes 를 늘려(나눠) 다시 |

- 잘림이 아닌 것: 삭제된 디렉터리만 검증하지 못한 것(unvalidated_dirs 에만 세고 unvalidated_dirs_live 는 0 — 클러스터 재사용으로 흔하다. 삭제 흔적이 중요하면 사람에게 알린다), 같은 구간을 가리키는
  파티션(call.partitions_skipped.duplicate), 지어낸 ref(bad_ref). 삭제된 디렉터리와 그 아래는 최선 노력이라 손상·이미지 끝을 잘림으로 세지 않는다(경고만).
- 해석하지 못한 볼륨(call.volumes_failed)은 사유 목록에 없지만 truncated=true 다 — §7 표.
- 오염 검사는 truncated 가 false 이고 본 볼륨(error 가 아닌 volumes[] 항목)이 하나 이상일 때만 "흔적을 찾지 못했다(없음을 증명하지 않음)"로 보고한다. 잘렸으면 "본 범위에서만 없음"과 사유를 적고,
  volumes 가 비었으면 truncated 와 상관없이 '보지 못함'으로 적는다(note 도 '본 볼륨이 없어 흔적을 보지 못했다' — 지원하는 FAT/exFAT 파티션이 없으면 truncated false, 파티션이 이미지 끝 너머면 image_truncated 로 true).
- 추출 파일의 complete=false 는 상한·취소·짧은 후보·읽을 수 있는 범위(파티션 표 항목과 이미지 끝 중 짧은 쪽)의 끝 중 하나다. 끝 너머 바이트 수(bytes_beyond_image)는 매니페스트에만 있다 — 매니페스트는 열지 않으므로, max_bytes·cancelled 사유가 없는데
  그 볼륨이 image_truncated·volume_exceeds_partition·beyond_image 였으면 그 탓(잘린 이미지, 파티션 표보다 큰 파일 시스템)으로 보고 사람에게 알린다.

## 9. 선택 텍스트 비밀값 검사

`forensics_scan_secrets`는 선택 파일 하나만 읽는다. 인자·범위·고정 한도는 architecture §6.8, 결과 구조는 `schema_get(name="secrets-scan")`이다. 결과의 `ok`는 호출 성공이고 `report.status`가 검사 상태다. 비밀값·원래 파일명·계정·URL을 요약에 추가하지 않는다.

| SD 요약 `secret_scan_results[]` | 도구 응답 출처 |
|---|---|
| evidence_id | report.source.evidence_id |
| analysis_path / analysis_sha256 | analysis.path / analysis.sha256 |
| status | report.status (ok / partial / unsupported) |
| hits | report.summary.hits (후보 수, 한도면 하한) |
| scanned_bytes / unscanned_bytes | report.coverage의 같은 필드 |
| reasons | report.coverage.reasons의 고정 코드 |

`privacy.secret_plaintext_returned`는 false다. 후보별 상세 위치·규칙·지문은 원문 없는 분석 JSON에 두고 요약에는 합계·범위·참조만 옮긴다. 경계가 불완전한 후보는 digest=null이며 비밀번호가 없다는 뜻이 아니다. `unsupported`/미검사 범위/복구 불확실성은 notes와 필요시 blockers에 남긴다. 보관 기록은 `secrets-scan` 사건이고 결과 SHA256은 `forensics_evidence_list`의 derived로 다시 확인한다.

## 10. 운영 한계

**알려진 한계** (전체는 `docs/safety.md` §3.6 — 관련되면 사용자에게 그대로 알리고 보고서 한계에 적는다):
- 동기 조회 도구는 계산·직렬화·커밋 직전에 요청 취소를 확인한다. OS 호출은 강제로 중단하지 못하며 이미 커밋된 결과는 보존한다.
- 빠른 지문은 크기·mtime·앞뒤 1 MiB·쓰기 권한만 본다(inode·ctime 없음) — 가운데만 바뀐 사본은 8단계 재해시만 찾고, 재해시는 그 시점의 바이트만 증명한다.
- 서버 재시작 뒤 `forensics_jobs(case_id="<id>")`로 저장 기록을 확인한다. 소유자 종료가 확실한 활성 기록만 실패로 정리하고 불명확한 기록은 그대로 표시한다. 저장 기록 재개/취소는 제공하지 않는다. 입력·증거의 하드 링크와 열린 fd/이름 교체를 확인하지만 같은 OS 계정의 최종 확인 이후 조작까지 막지는 못한다.
- 추출·목록·선택 텍스트 분석 출력은 보관 기록 직전에 열린 fd와 이름·부모를 재확인한다. 이후 교체 창은 남는다. 증거 목록 derived는 추출 매니페스트와 기록된 분석 결과 해시를 대조한다.
- 엔진은 일부러 엄격하다(FAT 속성 비트 0x40/0x80, 하위 디렉터리의 볼륨 레이블, LFN 이상, exFAT 필드) — fsck 가 받는 디렉터리도 unvalidated_dirs(살아 있으면 dir_unvalidated)로 뺄 수 있다.
- max_seconds 는 해석 시간이다(목록 파일 쓰기는 더 걸린다). skip-allocated 후보는 탐색 상한에서 사유 없이 status incomplete(complete=false)로 끝날 수 있다.
- 보관 기록과 고정점을 함께 잃으면 증거 목록은 보관 기록 정상(0개) 옆에 record-without-intake 행을 보인다 — 사람이 알아채야 한다(위 표).

`coverage.analysis_complete`와 `hits_are_lower_bound`는 선택한 바이트의 지원 패턴 검사에 한정된다. 복구 후보나 컨테이너 목록만 불확실하면 각각 true/false여도 report.status는 partial이다. 전체 컨테이너 검사·원본 파일 복구의 확실성을 뜻하지 않는다.

## 11. 펌웨어·카드 보고서 이름 대조

`forensics_sd_ioc_scan`의 입력은 같은 케이스의 등록된 `analysis/sd-surface-NNN.json`과 같은 EV의 보관 기록에 결속된 `forensics/analysis/fs-list-EV-NNNN-NNN.json`이다. 전체 JSON만 받으며 표본20개·임의 JSON·TAR/ZIP 목록은 받지 않는다. 지원 FAT/exFAT 볼륨이 하나가 아니면 `partition`을 지정한다. 같은 케이스도 동일 장치·버전의 증명이 아니므로 결과의 `device_association_verified=false`를 유지한다.

`report.status`는 `ok/partial/unsupported`다. `exact_live_name`·case_variant_candidate·`deleted_name_candidate`·`uncertain_name`은 이름 수준 후보이며 실행·악성 여부·침해를 뜻하지 않는다. 0건도 본 범위의 이름 무검출이다. 원래 목록/스캐너의 잘림·unknown, 삭제·별칭·대소문자 제한을 `coverage`에서 확인한다. 후보가 있다고 자동 finding/severity를 만들지 않는다.

`ioc_scan_results[]`에는 `evidence_id`, `analysis_path`/`sha256`(`analysis.path`/`sha256`), `status`(`report.status`), `matches_total`(`report.summary.matches`, 저장한 `report.matches` 길이), `partition`(`report.selected_partition`, 없으면 null), `firmware_result_path`, `fs_list_path`만 기록한다. 원시 카드 이름·경로·시각·펌웨어 발췌는 요약에 복사하지 않는다. 상세 한계·ref·펌웨어 배열 index·입력 해시는 결과 보고서를 참조한다. `forensics_evidence_list`의 `derived`에서 `sd-ioc-scan` 결과 해시/보관 기록 대조를 확인한다.

입력은 각16 MiB와 JSON 복잡도 상한, 후보는 최대200개다. 큰 전체 목록은 오류이며 앞부분만 성공으로 읽지 않는다. 필요하면 `forensics_fs_list`의 partition/max_entries를 좁혀 다시 만들고 그 목록의 잘림을 그대로 보고한다. 시간·비교 한도는 부분 결과로, 입력 검증 실패는 오류로 남는다. 상세 상한과 입력 fd/목록 사건 결속은 architecture §6.8, 같은 OS 계정의 경합 한계는 safety §3.6이다.

## 12. 선택 미디어 구조 관찰

`forensics_media_inventory`는 EV 자체 또는 FAT/exFAT·TAR/ZIP에서 선택한 완전한 파일 하나의 상자 경계와 허용 계층의 `mvhd/mdhd` 시간 단위·길이 선언, `pssh` 구조를 본다. ref/path 중 하나를 주거나 직접 EV에서는 둘 다 생략한다. 직접 EV는 partition 없이 method=auto다. 최대64 MiB이고 불완전 읽기·한도 초과를 앞부분 성공으로 바꾸지 않는다. 빈 선택 파일은 미지원 결과다.

schema `pweh.media-inventory/v1`은 유지한다. 새 profile `mp4-quicktime-declarations-v1`은 `declarations`가 필수이고, 옛 `mp4-quicktime-box-v1`은 그 section 없이 기존 형식으로 계속 읽는다. 옛 보고서가 새 선언 검사를 받은 것으로 해석하지 않는다.

`report.status`의 ok/partial/unsupported, `framing_status`, `recognition`, `coverage`와 `declarations.status`를 구분한다. 선언 필드가 미지원·불완전하면 상자 경계가 complete여도 전체 partial이다. 선언0개/complete는 보호 신호 부재·평문 확인이 아니다. timing의 timescale/duration_units는 선언 정수이며 재생 길이나 녹화 시작/끝으로 변환하지 않는다. creation/modification는 zero/nonzero/unread만, PSSH는 index/version/status/issues만 반환한다. 원시 시각·식별자·payload는 나오지 않는다.

opaque payload는 검사 바이트와 다르며 timing도20/32bytes prefix 외 필드는 미검사다. brand나 moov/moof/PSSH가 있다고 영상 정상·재생 가능·녹화 시각·암호화를 판정하지 않는다. 삭제·삭제된 부모·알 수 없는 부모·복구 신뢰도의 불확실성은 선언 검사 상태와 별도로 overall partial에 남는다. 전체 컨테이너 미검사를 전체 목록 완료로 쓰지 않는다.

`media_inventory_results[]`에는 `evidence_id`, `analysis_path`/`sha256`(응답 analysis), `status`(report.status), `selected_size`(source.selected_size), `boxes_reported`(보고한 상자 수)만 기록한다. 원래 파일명·경로·시각·FourCC·UUID·메타데이터 원문은 추가하지 않는다. 범위별 한계는 결과 JSON을 참조하고 증거 목록의 derived에서 media-inventory 결과 해시/보관 기록을 확인한다. 기존 privacy.audio_decoded·recording_content_viewed는 false로 유지한다.

상자4096·깊이8·brand 표당64/전체256·범위8193·JSON1 MiB·공통 최대45초의 제한이 있다. timing/PSSH row 합계는 반환 상자 수 이하이며 상자당1개다. 구조 실패/한도에서 검증한 범위와 미검사 tail을 구분한다. 지원 밖을 외부 decoder/파일 도구로 대신하지 않는다. 상세 필드·false 검증 값·구버전은 [선언 관찰](../../docs/references/media-declarations.md), 전체 보관 계약은 architecture §6.8, 한계는 safety §3.6이다. 후보·prefix 도구와 녹화 타임라인 입력은 바뀌지 않는다.

## 13. 선택 미디어 연속 후보

`forensics_media_candidates`는 EV 자체 또는 FAT/exFAT·TAR/ZIP의 완전한 선택 파일 하나(최대64 MiB)에서 ftyp와 연속 최상위 상자 prefix 후보를 찾는다. ref/path 중 하나를 지정하며 직접 EV는 둘 다 생략하고 partition 없이 method=auto다. 큰 EV의 명시 구간은 정수 offset/length를 함께 지정하며 ref/path/partition을 생략하고 method=auto를 유지한다. 구간은 최대64 MiB, EV 안에 있어야 한다. 인자가 없는 큰 EV를 자동으로 잘라 읽거나 미할당/잔여 영역으로 판정하지 않는다.

구간 profile은 ftyp-contiguous-ev-range-v1이며 source.evidence_size/offset/selected_size/selected_sha256에 EV 크기·구간 위치/길이·전체 구간 SHA를 기록한다. source.complete/high는 구간 읽기 신원이고 후보 확신이 아니다. 후보 위치는 구간 상대값이며 이 분기에서만 source.offset을 더해 EV 내 위치를 구한다. 구간 밖은 미검사다. old/new source·params를 섞지 않으며 [명시 구간 계약](../../docs/references/media-evidence-range.md)을 따른다.

`report.status`는 ok/partial/unsupported다. 후보마다 선택 기준 offset과 검증 prefix 길이·고정 known brand·종료 사유를 기록한다. size0·selection_end·next_ftyp는 원본 파일 종료의 증거가 아니다. payload 내부에 우연히 들어 있는 ftyp도 후보가 될 수 있으며, confidence는 possible, complete_recording은 false다. 프레임·음성·시각·암호화·재생·물리 카빙을 검증하지 않는다.

`coverage.search_positions_examined`는 anchor 처리까지 끝난 헤더 시작 위치의 연속 prefix 길이이며 읽은 bytes 수가 아니다. 현재 미처리 anchor와 미검사 suffix, candidate_checks_complete, candidate_list_complete, relations_complete를 각각 확인한다. 관계는 반환 후보들의 검증 prefix 사이에서만 계산한다. 관계 검사가 미완료라면 빈 배열을 겹침 없음으로 읽지 않는다. 삭제·복구·부모 상태 불확실성과 알려진 컨테이너 목록 잘림은 지원 후보0건이어도 partial로 남긴다.

`media_candidate_results[]`에는 `evidence_id`, `analysis_path`/`sha256`(응답 analysis), `status`(report.status), `selected_size`(source.selected_size), `candidates_reported`(report.summary.candidates_reported)만 남긴다. 이름·경로·후보 offset·원문 메타데이터를 요약에 복사하지 않는다. 증거 목록 derived에서 media-candidates 결과의 해시/보관 기록을 확인하고 기존 privacy.audio_decoded·recording_content_viewed는 false로 유지한다.

후보128·anchor probe1024·header 후보당1024/전체8192·brand anchor당64/전체4096·구조 판독 합1 MiB·최종 JSON1 MiB·공통 시간45초의 상한이 있다. 한도나 구조 실패는 부분 후보/검사 범위로 남는다. 원본 녹화 복구·벤더 지원·전카드 탐색 완료로 보고하지 않는다. 전체 계약은 architecture §6.8, 한계는 safety §3.6이다.


## 14. 저장된 후보 prefix 추출

`forensics_extract_media_candidate(case_id, evidence_id, analysis_path, candidate_index)`는 같은 EV의
`media-candidates` 보관 기록에 결속된 보고서와 원래 선택 파일 또는 EV 구간 전체의 해시를 다시 확인한다.
실제 후보 번호 하나를 지정하고 기존 forensics job 조회·취소 도구를 사용한다. offset·length·
복구 방법을 새로 입력하지 않는다. 출력은 `recovered/media-prefix-NNN/`의 고정 이름
`candidate-000.bin`과 `manifest.json`이며 직접 열지 않는다.

전체 prefix를 썼어도 원래 후보/복구/부모/컨테이너 목록 불확실성이 있으면 상태는 partial이다.
원래 source/status/coverage와 새 유효 불확실성을 보존한다. `files[0].complete=true`는 prefix 작성
완료이며 녹화 전체 복구나 재생 성공이 아니다. 영상·음성·시각·암호화·원본 경계 검증 값은 false다.

`forensics_evidence_list.derived`에서 매니페스트가 기존 `extract` 사건과 맞는지 확인한다.
`recorded`는 매니페스트 해시 결속이지 목록 때 추출 바이너리 전체를 재해시했다는 뜻은 아니다.
기존 `recovered`의 files/bytes/manifests에 합산하고 partial·확인하지 못한 사항은 notes에 적는다.
입력64 MiB·보고서1 MiB·매니페스트64 KiB·worker 공통45초와 정리/취소 계약은
[미디어 후보 추출](../../docs/references/media-prefix-extract.md)을 따른다.

## 15. 저장 목록의 자동 비밀값 검사

`forensics_scan_secrets_from_list`에 같은 EV의 `forensics_fs_list` 전체 JSON 경로를 전달한다. 목록 안의 지원 FAT/exFAT 파일을 순서대로 자동 선정하며 최대32파일·합16 MiB·파일당4 MiB·총200후보를 검사한다. TAR/ZIP 또는 명시한 파일 하나는 기존 단일 도구를 쓴다.

[상세 계약과 요약 필드 매핑](../../docs/references/secrets-survey.md#sd-요약)에 따라 `secret_survey_results`를 기록한다. 목록 완료·정책 분류 완료·eligible 검사 완료를 구분하고, 정책 제외·한도·읽기 실패를 notes에 남긴다. whole_card_examined와 privacy.secret_plaintext_returned는 false다. 원래 파일명·시각·키·본문을 요약에 넣지 않으며 후보0건은 비밀 없음/안전 판정이 아니다. `secrets-survey` 사건과 결과 SHA는 증거 목록 derived로 확인한다.

## 16. DHAV record 구조 후보

`forensics_dhav_candidates`는 완전한 선택 파일 또는 명시 EV 구간(최대64 MiB)에서 고정 DHAV
record 구조 후보만 찾는다. ref/path는 배타적이며 직접 EV는 둘 다 생략한다. offset/length는
함께 지정하고 ref/path/partition 없이 method=auto를 쓴다. 파일과 명시 구간의 닫힌 profile은
각각 dhav-record-framing-v1/dhav-record-ev-range-v1이다.

지원 type f0/fc/fd의 길이·표지·범위를 대조하지만 원시 header 시각·채널/counter/checksum,
extension 내부와 payload 의미를 해석하지 않는다. 후보 offset은 선택 상대이며 구간에서만
source.offset을 더해 EV 위치를 구한다. 파일/삭제 복구/아카이브 논리 위치에는 적용하지 않는다.

`report.summary`의 완전 기각/범위 부족/지원/생략 후보와 `coverage`의 search_complete,
candidate_checks_complete(관찰한 anchor만),candidate_list_complete를 따로 읽는다.
후보0건도 범위 부족·한도·출처 불확실성이 있으면 partial이다. possible은 구조 후보의 확신이고
source.complete/high는 선택 bytes의 완전 읽기/신원이므로 서로 대신하지 않는다.

`dhav_candidate_results[]`에는 evidence_id,analysis_path/sha256(analysis),status(report.status),
selected_size(source.selected_size),candidates_reported(summary.candidates_reported)만 넣는다.
좌표·원문 시각·채널·이름·본문을 요약에 추가하지 않는다. partial/unsupported와 미검사 범위는
notes에 남기고 기존 privacy.audio_decoded·recording_content_viewed는 false를 유지한다.
JSON은 `dhav-candidates` 사건과 결속되며 evidence-list derived에서 생성 경로·해시를 확인한다.

공통45초·anchor probe1024·후보128·구조 필드 판독1 MiB·JSON1 MiB 한도와9개 false 값,
footer 반복 길이의 PWEH 추론은 [DHAV 후보 계약](../../docs/references/dhav-candidates.md)을 따른다.
이는 메타데이터 분석이며 저장 후보 한 record의 추출은 다음 §17을 따른다. 영상 해독·녹화 타임라인·암호화 판정은 미지원이다.
기존 `forensics_extract_media_candidate`는 BMFF 보고서만 받는다.

## 17. 저장된 DHAV record 추출

`forensics_extract_dhav_candidate(case_id, evidence_id, analysis_path, candidate_index)`는 같은 EV의
저장된 DHAV 후보 하나만 선택한다. analysis_path는 후보 분석 응답의 analysis.path이며,
번호는 실제 report.candidates에 있는 정수다. 새 offset/length나 복구 방법을 넣지 않는다.
job_id를 받아 `forensics_job_status`로 확인하고 필요한 경우 `forensics_job_cancel`로 취소한다.

원래 선택 파일/명시 구간 전체의 SHA·크기·선택 신원을 다시 대조해 record_length bytes만
복사한다. 출력은 `dhav-record-NNN/record-000.bin`과 매니페스트다. source/candidate/coverage와
원래·새 불확실성을 보존한다. complete=true는 복사 완료이며 원본 경계·완전 녹화·재생 판정이 아니다.
원시 시각·채널·본문을 반환하지 않으며 에이전트는 추출물을 직접 열지 않는다.

기존 `recovered`의 files/bytes/manifests에 합산하고 partial·미확인 사항은 notes에 적는다.
`dhav_candidate_results`는 후보 분석 참조6필드를 유지한다. 증거 목록의 derived.recorded는
매니페스트·extract 사건 결속이며 이후 바이너리 재해시 보장이 아니다.
입력64 MiB·보고서1 MiB·매니페스트64 KiB·공통45초·출력1개와 취소·정리 계약은
[DHAV record 추출](../../docs/references/dhav-record-extract.md)을 따른다.

## 18. EV의 DHAV 스트리밍 검색

`forensics_dhav_scan(case_id, evidence_id, start_offset=0, max_scan_bytes=1073741824,
max_seconds=45)`는 같은 접수 EV fd에서 DHAV 표지를 검색한다. max_scan_bytes는4..1 GiB의
연속 검색 읽기 합계다. 검색창은64 KiB 이하이고 마지막3bytes는 메모리에만 유지한다.
구조 필드 읽기≤1 MiB는 별도여서 검색창 밖 footer도 EV 안이면 확인할 수 있다.
최대1024probe·128row·record64 MiB·JSON1 MiB이며 원문·시각·채널·record hash는 반환하지 않는다.

source4필드의 evidence_sha256은 접수 해시이며 이번 전체 EV 재해시가 아니다.
후보 offset은 **EV 절대 위치**다. 처리한 연속 위치 prefix와 읽기량을 구별하고 next_offset이
있으면 그 위치에서 재개한다. search_complete는 요청 시작 이후, whole_evidence_search_complete는
start0 한 호출의 전체 가능한 시작 위치 검색만 뜻한다. 여러 report를 자동 합쳐 전체 완료로
승격하지 않는다. 한도/시간·잘린/초과 record는 partial, 취소·읽기/무결성 실패는 미게시다.

필요한 row 하나의 offset/record_length를 같은 EV의 `forensics_dhav_candidates`에 offset/length로
전달한다. 새 구간 보고서가 전체 선택 SHA를 결속하면 그 보고서의 실제 후보 번호로만
`forensics_extract_dhav_candidate`를 호출한다. scan 보고서는 직접 extractor 입력으로 쓸 수 없다.
구간 후보 offset은 다시 구간 상대이므로 절대 위치를 중복해서 더하지 않는다.

`dhav_scan_results[]`에는 evidence_id, analysis_path/sha256(analysis), status(report.status),
evidence_size(report.source), candidates_reported(report.summary)6필드만 기록한다.
evidence_size는 검사량이 아니며 next_offset·미검색 영역·완료도는 보고서 coverage에 있다.
기존 dhav_candidate_results와 recovered를 유지하고 partial·미검사 사유는 notes에 쓴다.
출력은 `dhav-scan` 사건/증거 목록에 결속되며 영상·음성·시각·암호화·파일 경계·할당 상태·
완전 녹화는 판정하지 않는다. 상세 계약은 [DHAV streaming 검색](../../docs/references/dhav-scan.md)을 따른다.

## 19. 선택 미디어 단위 후보와 추출

`forensics_media_unit_candidates(case_id, evidence_id, format, ...)`의 format은
`jpeg`·`avc-annexb`·`mpeg2-ps`·`xm` 중 하나다. 자동 형식 추측은 없다. FAT/exFAT·TAR/ZIP의
ref/path 하나, EV 자체 또는 명시 offset/length 구간에서 완전한64 MiB 이하 선택을 검사한다.
구간은 선택자/partition 없이 method=auto다. source16/18과 선택 전체 SHA를 보존한다.

JPEG는 baseline 단일 scan의 EOI, AVC는 다음 prefix/header, XM은 선언 길이로 닫힌 단위다.
PS는 길이를 검증한 pack prefix이며 다음 BA/B9가 없어도 검증된 앞부분은 partial 후보가
될 수 있다. 후보 length는 선택 상대 offset부터의 bytes 수다. range에서만 EV 위치를
계산할 때 source.offset을 한 번 더한다. 원시 header·치수·시각·본문은 반환하지 않는다.

관찰 anchor의 기각/지원밖/불완전과 closed/prefix 후보를 구분한다. search/check/list 완료와
PS prefix 상태는 별개다. 시간·한도·열린 tail·출처 불확실성을 notes에 남긴다. 45초·1024probe·
128후보·8192구조단계·작업량128 MiB·JSON1 MiB 한도이며 일부 검사로 전체 미디어 부재를
말하지 않는다. 상세 경계는 [후보 계약](../../docs/references/media-unit-candidates.md)을 따른다.

`media_unit_candidate_results[]`는 evidence_id, analysis_path/sha256(analysis), status,
format(report), selected_size(source), candidates_reported(summary)의7필드만 기록한다.
raw 시각·내용·후보 좌표·재생 성공을 요약에 추가하지 않는다. 기존 privacy 네 값은 false다.

목적에 필요한 저장 후보 하나를 `forensics_extract_media_unit(case_id, evidence_id,
analysis_path, candidate_index)`로 추출한다(`ask`). 같은 EV의 후보 보고서·사건·선택 전체
SHA·출처를 재검증하며 새 format/범위를 받지 않는다. 기존 job 상태로 완료를 확인하고
recovered·notes 및 증거 목록에 남긴다. 출력은 unit-000.bin과 manifest 두 파일이다.
원래 partial·새 불확실성을 보존하며 complete=true는 지정 bytes 복사 완료일 뿐이다.
추출물을 직접 열거나 영상·음성을 해독하지 않는다. [추출 계약](../../docs/references/media-unit-extract.md).

## 20. EV의 BMFF 스트리밍 검색

`forensics_bmff_scan(case_id, evidence_id, start_offset=0, max_scan_bytes=1073741824,
max_seconds=45)`는 같은 접수 EV fd에서 ftyp 시작점과 연속 최상위 상자 prefix를 찾는다.
max_scan_bytes는8..1 GiB의 연속 검색 읽기 합계다. 검색창은64 KiB 이하, carry는7bytes이고
구조 읽기≤1 MiB는 별도다. 구조 검사가 창 밖으로 나가도 검색 완료 범위를 늘리지 않는다.
최대1024probe·128row·prefix64 MiB·JSON1 MiB이며 box/brand 예산도 호출 전체에 누적한다.

source4필드의 evidence_sha256은 접수 해시이며 이번 전체 EV 재해시가 아니다.
후보 offset은 **EV 절대 상자 헤더 위치**, validated_prefix_length는 완전 상자들의 검증
prefix 길이다.64 MiB를 넘기는 다음 상자를 일부 잘라 넣지 않으며 size0도 EV 끝까지
확장하지 않는다. EV 끝이나 prefix 끝을 원본 파일 EOF로 간주하지 않는다.

next_offset은 처리한 연속 위치 prefix 뒤의 재개 위치다. search_complete는 요청 시작 이후,
whole_evidence_search_complete는 start0 한 호출의 전체 가능한 시작 위치 검색이다.
candidate_checks_complete는 관찰 anchor의 제한 검사 완료로, 행의 framing_status와 별개다.
시간/한도 때문에 chain이 미완료여도 이미 검증한 prefix는 partial로 남을 수 있다.
여러 보고서를 자동 합쳐 전체 완료로 승격하지 않는다. 취소·읽기/무결성 실패는 미게시다.

필요한 행 하나의 offset/validated_prefix_length를 같은 EV의 `forensics_media_candidates`에
offset/length로 전달한다. 새 구간 보고서가 전체 선택 SHA를 결속하면 그 보고서에 실제로
있는 후보 번호로만 `forensics_extract_media_candidate`를 호출한다. scan 보고서는 직접
추출에 쓰지 않는다. 새 후보 offset은 구간 상대이며 이전 index/끝 사유를 복사하지 않는다.
job 완료를 확인하고 기존 recovered·notes에 기록하며 추출물을 직접 열지 않는다.

`bmff_scan_results[]`는 evidence_id, analysis_path/sha256(analysis), status(report.status),
evidence_size(report.source), candidates_reported(report.summary)6필드다. EV 크기는
검색량이 아니며 미검색 범위·재개·부분 chain은 원보고서 coverage를 참조한다.
기존 media_candidate_results와 prefix 추출의 의미는 바꾸지 않는다. 후보 관계·시각·본문·
암호화·원본 경계·전체 녹화·재생을 판정하지 않는다. 출력은 `bmff-scan` 사건에 결속되며
세부 한도·저장 계약은 [BMFF streaming 검색](../../docs/references/bmff-scan.md)을 따른다.

## 21. 명시 구간의 현재 할당 상태

`forensics_allocation_window(case_id, evidence_id, partition, offset, length, max_seconds=45)`는
현재 FAT/exFAT metadata를 allocated/unallocated/bad/unknown으로 분류한다. partition은
`forensics_partitions`의 명시 index(파티션 표 없는 볼륨은1), offset은 EV 절대 위치다.
길이1~64 MiB이며 전체 창이 선택 볼륨의 데이터 클러스터 영역 안에 있어야 한다.

`coverage.window_complete`는 요청 바이트가 모두 행으로 표현됐다는 뜻이고,
`allocation_complete`는 그 안에 unknown이 없을 때만 true다. 한도로 검사하지 못한 suffix는
unknown 행이 아니며 `next_offset`과 `unexamined_bytes`를 사용해 필요한 부분만 다시 지정한다.
FAT 사본 불일치·bitmap 손상 등 unknown 사유를 free로 해석하지 않는다.

목적에 필요한 행의 offset/length를 같은 EV의 `forensics_dhav_candidates` 또는
`forensics_media_candidates`에 구간 인자로 명시할 수 있다. 후보 도구의 새 구간 SHA·출처를
확인한 뒤 그 저장 후보만 기존 추출 도구에 넘긴다. 할당 보고서 자체는 추출 입력이 아니다.
현재 free는 과거 파일 소속·원본 파일 경계·복구/재생 성공을 증명하지 않는다.

`allocation_window_results[]`에는 evidence_id, analysis_path/sha256(analysis),
status(report.status), window_complete/ allocation_complete(report.coverage)의6필드만 쓴다.
최대100개이며 상세 사유·미검사량·재개 위치는 notes와 결과 보고서에 남긴다.
metadata4 MiB·행128·45초·JSON1 MiB, 같은 FD·보관 기록·고정 오류의 정확한 계약은
[현재 할당 상태](../../docs/references/allocation-window.md)를 따른다.

## 22. 현재 live 참조와 할당 일관성

`forensics_cluster_report(case_id, evidence_id, partition, max_seconds=45)`에 기존
`forensics_partitions`의 명시 FAT/exFAT index를 준다. 현재 살아 있는 항목의 참조와
현재 할당 metadata를 대조하며 삭제 항목은 순회하지 않는다. 원문 이름·시각·진단은 반환하지 않는다.

coverage의 reference_walk_complete, reference_map_complete, allocation_complete,
rows_complete를 각각 보존한다. ok는 네 검사가 끝났다는 뜻이며 이상 없음의 증명이 아니다.
참조 지도와 할당 검사가 모두 완료되지 않으면 allocated_without_live_reference는 null이다.
읽지 못한 bitmap 꼬리를 free로 보거나 미참조 할당을 고아 파일·과거 소속의 증거로 삼지 않는다.

필요한 구간 행의 EV 절대 offset/length를 기존 DHAV/BMFF 구간 후보에 별도로 전달할 수 있다.
새 구간 SHA와 출처를 확인한 뒤 그 저장 후보만 기존 추출 도구로 선택한다. cluster 보고서를
직접 추출 입력으로 쓰거나 자동 추출하지 않는다. 파일 ref는 기존 목록·선택 검증을 따른다.

`cluster_report_results[]`는 evidence_id, analysis_path/sha256(analysis), status(report),
reference_map_complete/allocation_complete(report.coverage)의6필드, 최대100개다.
partial에는 두 완료 값이 모두 true인 행 표본 제한도 포함된다. 미검사 수·사유는 notes와
원보고서에 남긴다. metadata32 MiB·행128·45초·같은 FD·보관 기록의 상세 계약은
[현재 참조 일관성](../../docs/references/cluster-report.md)을 따른다.

## 23. exFAT 잔여 후보와 단일 추출

BMFF·DHAV·미디어 단위의 세 후보 도구에 region="residual", 명시 partition/ref를 전달한다.
path/offset/length는 생략하고 실제 exFAT 파일 한 항목만 선택한다. 기본 data는 기존 동작이다.
원래 VDL이 DL보다 작고 잔여 DL-VDL이1 byte..64 MiB여야 하며 완전 읽기만 받는다.

잔여 전용 profile과 source19필드는 region·DL·VDL·선택 SHA·구체 복구 방법을 결속한다.
candidate.offset은 잔여 상대이며 VDL+offset은 파일 논리 위치다. EV 물리 위치로 환산하지 않는다.
기존 세 추출기에 보고서/후보 번호를 넘기면 원래 선택 전체와19필드를 재대조해 한 후보만 쓴다.
extract 사건의 region=residual 및 원래 status/coverage를 보존한다. 추출물을 직접 열지 않는다.

후보 참조 배열·recovered의 기존 필드를 사용하며 잔여 의미·partial·복구 신뢰도와 부모 상태를
notes에 남긴다. 잔여 바이트를 이전 녹화·삭제 시점·완전 복구·재생 근거로 표현하지 않는다.
6종 profile·상한·선택 및 추출 계약은 [잔여 참조](../../docs/references/exfat-residual-candidates.md)를 따른다.

## 24. EV의 미디어 단위 스트리밍 검색

`forensics_media_unit_scan(case_id, evidence_id, format, start_offset=0,
max_scan_bytes=1073741824, max_seconds=45)`는 JPEG/AVC/PS/XM 중 명시한 subset을 검색한다.
검색 읽기≤1 GiB·구조 읽기/작업량 각각≤128 MiB·행128·45초이며 같은 EV fd를 유지한다.
원문·시각·단위 해시는 반환하지 않으며 접수 SHA를 이번 EV 전체 재해시로 표시하지 않는다.

next_offset은 처리 재개 위치이고 read-ahead의 끝이 아니다. search_complete는 요청 시작 이후,
whole_evidence_search_complete는 start0인 이번 호출의 전체 검색이다. candidate_checks_complete는
관찰한 anchor의 검사 완료이며 candidate_list_complete는 검색과 검사가 모두 끝났다는 뜻이다.
PS prefix는 이 값들이 true여도 partial이다. pending·선택 상한·미검사 범위를 notes에 남긴다.

행의 selection_offset/selection_length로 같은 format의 기존 구간 후보를 새로 검사한다.
source.offset+candidate.offset, length/unit_subtype/boundary_kind/framing_status/end_reason가
맞는 행을 고르며 evidence_end만 selection_end에 대응한다. row0을 가정하지 않는다.
그 새 보고서/index만 기존 forensics_extract_media_unit에 넘긴다. scan은 직접 추출 권위가 아니다.

`media_unit_scan_results[]`는 evidence_id, analysis_path/sha256(analysis), status/format(report),
candidates_reported(report.summary)의6필드, 최대100개다. EV 크기·단위 bytes·완료값은 넣지 않는다.
기존 candidate 결과·recovered는 그대로 사용하며 추출물을 직접 열지 않는다.
[출력·예산·재개 계약](../../docs/references/media-unit-scan.md)을 따른다.
