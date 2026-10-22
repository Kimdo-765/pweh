# pweh-forensics (forensics-mcp)

카메라·블랙박스에서 꺼낸 **SD 카드 이미지의 증거 분석** MCP 서버다. 사람이 하드웨어 쓰기 방지 장치를 거쳐 이미징 도구로 만든 이미지 파일을 접수해
해시·보관 기록(custody)을 남기고, 파티션·FAT/exFAT 파일 시스템을 읽기 전용으로 해석해 파일 목록·시각·삭제 항목을 정리하며, 필요한 파일만 케이스 안으로 추출한다.
끝에는 해시값 확인서 서식이 붙은 증거 목록을 만든다.

- 대상: 운영자가 **소유**했거나 **서면 허가**를 받은 기기의 카드. 카드에는 제3자의 영상·음성(개인정보)이 들어 있다.
- 코드: `forensics_mcp/server.py`(도구, 접수·검증·증거 목록, 서버 시작·종료), `forensics_mcp/fsops.py`(볼륨 고르기·호출 예산·목록 요약·잘림 사유·호스트 오염 흔적·추출).
  파일 시스템 엔진은 코어 `src/pweh/fs/`, 보관 기록·증거 목록은 `src/pweh/evidence.py`, 믿을 수 없는 파일을 열고 쓰는 저수준 도구는 `src/pweh/safeio.py`.
- 계약: [`docs/architecture.md`](../../docs/architecture.md) §3(케이스 디렉터리)·§4(SD 카드 증거)·§6.8(도구). 설계: [`docs/design/sd-forensics.md`](../../docs/design/sd-forensics.md) §3·§4·§6·§7.
  인자·설명 원문: [`docs/references/pweh-mcp-tools.md`](../../docs/references/pweh-mcp-tools.md). 안전·데이터 취급: [`docs/safety.md`](../../docs/safety.md) §3.5·§3.6(알려진 한계 전체)·§7.
- 실행: `pweh-forensics-mcp` 또는 `python -m forensics_mcp` (stdio). 증거 접수·파일 시스템은 순수 파이썬이며 정지 이미지 해독은 Pillow, OCR·바코드는 선택 설치한 Tesseract·ZBar를 쓴다.
  시작할 때 모든 케이스의 커밋하지 못한 접수 디렉터리를 정리하고(§5), SIGTERM·입력 종료(EOF) 때는 실행 중인 job 을 취소하고 기다린 뒤 끝낸다(job 마다 최대 10초, SIGTERM 이면 전체 최대 약 15초 — 커밋 전의 접수는 되돌린다).
- 에이전트 절차: `sd-card-forensics` Skill (요약 스키마 `sd-forensics`).

---

## 1. 원칙

- **카드나 원시 디스크를 열지 않는다.** 이미지는 사람이 쓰기 방지 장치(카드 리더 일체형, 희생용 카드로 먼저 시험)와 이미징 도구(FTK Imager 등)로 만든다.
  이 서버는 일반 파일만 받는다 — 장치·FIFO·소켓·디렉터리·빈 파일, `/dev`·`/proc`·`/sys` 아래, Windows 원시 디스크 경로는 거부한다. E01(EWF)은 아직 받지 않는다(raw 로 내보내 접수).
- **이미지에 쓰지 않는다.** 접수한 사본은 0444, 커밋한 증거 디렉터리는 0555 다. 마운트·수리·포맷하지 않고 외부 도구를 실행하지 않는다.
  `forensics/` 아래에는 케이스 디렉터리에서 한 구성요소씩 링크를 따르지 않고 연 디렉터리 fd 기준으로만 만들고 쓴다(`O_CREAT|O_EXCL|O_NOFOLLOW`, 권한도 fd 로 바꾼다).
- **영상·음성 내용은 돌려주지 않는다.** 정지 그림은 `forensics_image_hints`로 미리보기·마스킹하지 않은 OCR·QR·EXIF/XMP·구조 지표를 반환한다. 추출물은 `forensics/recovered/`에만 쓰고 직접 열지 않는다. 영상·음성은 사람이 자기 플레이어로 본다.
  오디오를 재생·전사하지 않고, 얼굴·번호판 처리와 업로드를 하지 않는다. 복구한 자격증명으로 어디에도 로그인하지 않는다.
- **끝까지 보지 못한 것을 '없음'이라 하지 않는다.** 한도·예산에 닿았거나, 이미지가 잘렸거나, 살아 있는 디렉터리를 끝까지 읽거나 검증하지 못했거나, 볼륨을 해석하지 못했으면
  결과는 `truncated=true` 와 사유(`truncated_reasons`)·`next_steps` 를 싣는다(§3.1). 그런 볼륨에서는 호스트 흔적이 없다고 말하지 않는다.
- **기기에 아무것도 보내지 않는다.** 그래서 안전 게이트(분류기)가 없고 `approval_id` 인자도 없다. 대신 케이스 소유/허가 확인, 보관 기록, 빠른 지문, 사람 증명(`write-blocker`),
  Claude Code 권한(쓰는 도구는 매번 확인)으로 지킨다.
- **장치 시간대를 가정하지 않는다.** 시각은 원래 값과 `time_basis`(FAT `local-unknown-tz`, exFAT 은 UtcOffset 이 있으면 `local+offset`)로 돌려준다.
- PWEH 는 인증·검증된 포렌식 도구가 아니다. 법적 용도라면 원본 카드를 보존하고 원본·이미지·보관 기록을 자격 있는 전문가에게 넘긴다(모든 증거 목록·보고서에 같은 고지가 붙는다).

## 2. 일반적인 흐름

1. 사용자에게 소유/허가를 확인받고 `case_create` 로 케이스를 만든다(pweh-case).
2. 사람이 쓰기 방지 장치를 거쳐 이미지를 만든다(케이스 폴더 밖, 예: 증거 보관 폴더). 이미징 도구 로그도 함께 둔다.
3. `forensics_intake_start(case_id, image_path, purpose, legal_basis, site_type, business_purpose, role, imaging_log_path=…)` — 인자·입력 파일·여유 공간·보관 기록 문제는 job 없이 바로 오류다.
   → `forensics_job_status(job_id, wait_seconds=30)`. 결과의 `evidence_id`(예: `EV-0001`)·해시·이미징 로그 대조를 사용자에게 보여 준다.
   로그 해시가 다르면(`warning`) 사람이 다시 이미징할지 정한다. `post_commit_errors` 가 있으면 사람에게 알린다(접수 자체는 커밋됐다).
4. `forensics_verify_start` — 사본 전체 재해시(`verify_copy=true` 로 접수했으면 접수 때 사본을 한 번 다시 해시했다 — 일치하면 상태 `ok`. 보관 중간이나 보고 전에 다시 돌린다).
5. `forensics_acquisition_attest` — 사람이 별도 터미널에서 `pweh attest <id>` 로 쓰기 방지 장치 사용을 증명한다(에이전트는 답하지 않는다).
6. `forensics_partitions` → `forensics_image_check`(호스트 오염 흔적) → `forensics_fs_list`(전체 목록은 `forensics/analysis/` JSON, 응답은 요약).
   응답의 `truncated`·`truncated_reasons`·`next_steps` 를 본다. 시간·항목 한도면 안내대로 다시 부르고, 고정 한도·이미지·카드 상태 사유면 사람에게 알리고 보고서 한계에 적는다(§3.1).
7. 목적에 필요한 파일만 `forensics_extract(refs=[…])`(최소화) → `forensics_job_status` 로 `truncated_reasons`·`skipped` 를 확인 → 사람이 결과를 확인한다.
   저장된 연속 구조 후보가 목적에 필요하면 `forensics_extract_media_candidate(analysis_path=…, candidate_index=…)`로 후보 하나의 검증된 앞부분만 추출한다. 완료한 prefix여도 녹화 복구 성공을 뜻하지 않는다.
8. `forensics_evidence_list` — 증거 목록과 해시값 확인서(`forensics/evidence-list.md`)를 만든다. `report_generate` 는 보고서 §8.1 에 증거 표와 보관 기록 상태를 넣는다.
9. `case_record_step(skill="sd-card-forensics", step="summary", data=…)` (`schema_get("sd-forensics")`). 잘림 사유·해석하지 못한 볼륨·`status_label` 은 스키마에 필드가 없으므로 `notes` 에 적는다.

## 3. 도구

시그니처는 카탈로그의 인자 전체와 기본값이다. job 도구를 뺀 모든 도구는 `case_id` 가 필요하고 케이스에 소유/허가 증명이 있어야 한다.
`evidence_id` 를 받는 도구는 열 때마다 공통 입구(보관 기록·접수 기록·빠른 지문 대조, §5)를 거친다. `partition` 은 `forensics_partitions` 의 index(1~4096)다.

| 도구 | 설명 / 주요 반환 |
|---|---|
| `forensics_image_hints(case_id, evidence_id, partition=None, ref=None, path=None, method="auto", ocr=True, ocr_lang="kor+eng", qr=True, preview=True, crop=None, max_seconds=45.0)` | EV 자체 사진 또는 선택한 파일 하나를 공통 이미지 worker로 분석한다. 입력·시간·픽셀 제한과 진입 무결성 검사, JSON/PNG 해시를 결속한 custody `image-hints`, 실제 MCP 이미지 콘텐츠. 전체 계약은 architecture §6.8, 알려진 한계는 safety §3.8 |
| `forensics_scan_secrets(case_id, evidence_id, partition=None, ref=None, path=None, method="auto", xor_key=None, max_hits=200, max_seconds=45.0)` | 선택 텍스트 하나의 비밀값 후보를 원문 없이 검사한다. EV 자체 또는 FAT/exFAT·TAR/ZIP의 `ref`/`path` 하나, 완전 읽기 4 MiB·UTF-8(BOM 허용). `xor_key`는 생략 또는 정수144만, `max_hits` 1~200, 시간은 유한한 0 초과/45초 이하. 응답은 `report`(상태·출처 지문·규칙·후보·검사/미검사 범위)와 `analysis{path,sha256,size,custody_seq,custody_hash}`. 0444 JSON과 `secrets-scan` 보관 기록을 남긴다. 상세 한계는 아래 선택 텍스트 비밀값 검사 계약 |
| `forensics_scan_secrets_from_list(case_id, evidence_id, fs_list_path, partition=None, xor_key=None, max_seconds=45)` | 같은 EV의 저장 FAT/exFAT 전체 목록에서 고정 정책으로 파일을 자동 선정해 마스킹 검사한다. 최대32파일·데이터 합16 MiB·파일당4 MiB·총200후보·결과1 MiB. 목록 입력16 MiB, 읽기·선정·검사 공통45초 이하이며 partial 기록의 bounded 최종 검증은 별도다. 목록 누락·정책 제외·미검사를 구분하고 whole_card_examined=false를 유지한다. `report`와 `analysis`, 0444 JSON 및 `secrets-survey` 보관 기록. [상세 계약](../../docs/references/secrets-survey.md) |
| `forensics_sd_ioc_scan(case_id, evidence_id, firmware_result_path, fs_list_path, partition=None, max_matches=200, max_seconds=45.0)` | 같은 케이스의 등록된 `analysis/sd-surface-NNN.json`과 같은 EV의 보관 기록으로 검증한 `forensics/analysis/fs-list-EV-NNNN-NNN.json` 전체 보고서를 대조한다. FAT/exFAT 메타데이터만, TAR/ZIP 제외. `partition` 생략 시 지원 볼륨이 하나여야 한다. 정확 이름·ASCII 변형·삭제·불확실 후보와 입력/검사 한도를 구분한다. 원시 카드 경로·내용·펌웨어 발췌는 반환하지 않고 ref·펌웨어 배열 index로 연결한다. `report`와 `analysis{path,sha256,size,custody_seq,custody_hash}`, 0444 JSON 및 `sd-ioc-scan` 보관 기록. 이름 일치는 실행·침해 증명이 아니다 |
| `forensics_media_inventory(case_id, evidence_id, partition=None, ref=None, path=None, method="auto", max_seconds=45)` | EV 자체 또는 FAT/exFAT·TAR/ZIP에서 선택한 파일 하나를 최대64 MiB까지 완전히 읽어 ISO-BMFF 상자 경계·허용 계층의 mvhd/mdhd 시간 단위·길이 선언과 pssh 구조를 관찰한다. ref/path는 배타적이고 직접 EV는 partition 없이 method=auto만 받는다. 고정 box/brand·위치/길이·검사/opaque/미검사 범위·출처 불확실성을 반환한다. 원시 시각·식별자·payload를 반환하거나 프레임·음성·codec·재생·녹화 시각·암호화를 검증하지 않는다. `report`와 `analysis{path,sha256,size,custody_seq,custody_hash}`, 0444 JSON 및 `media-inventory` 보관 기록. 상세 계약은 아래 선택 미디어 구조 절 |
| `forensics_media_candidates(case_id, evidence_id, partition=None, ref=None, path=None, method="auto", max_seconds=45, offset=None, length=None)` | 완전한 선택 파일 하나 또는 명시 EV 구간(각 최대64 MiB)에서 고정 known brand를 가진 ftyp와 연속 최상위 상자 prefix 후보를 찾는다. 선택 기준 offset·검증한 길이·검색/검사/관계 완료도·반환 후보 간 겹침만 보고한다. 원본 경계·녹화 복구·재생 검증 없음. `report`와 `analysis{path,sha256,size,custody_seq,custody_hash}`, 0444 JSON 및 `media-candidates` 보관 기록. 상세 계약은 아래 선택 미디어 후보 절 |
| `forensics_extract_media_candidate(case_id, evidence_id, analysis_path, candidate_index)` | job. 같은 EV의 저장된 `media-candidates` 보고서에서 후보 번호 하나의 검증된 prefix를 추출한다. 원래 선택 파일 또는 EV 구간 전체의 해시·출처를 다시 대조. 출력은 고정 이름 바이너리와 매니페스트, 기존 `extract` 보관 기록. 입력64 MiB·보고서1 MiB·매니페스트64 KiB·공통45초. 내용 반환·녹화 복구/재생 판정 없음 |
| `forensics_intake_start(case_id, image_path, purpose, legal_basis, site_type, business_purpose, role, imaging_log_path=None, label=None, verify_copy=True)` | 증거 접수 **job**. job 을 띄우기 전에 검사한다(동기 오류): `purpose`(목적)·`legal_basis`(법적 근거, 예: '소유자 본인 기기')·`business_purpose`(업무 목적, 가정용이면 '없음')는 앞뒤 공백을 뺀 3~500자(탭 말고 제어 문자 없음), `site_type` 은 `home`/`public`/`business`/`vehicle`/`mobile-business`/`unknown`(설치 장소에 따라 적용 법률이 다르다), `role` 은 `owner`/`processor`/`investigator`/`other`, `label` 은 제어 문자 없는 80자 이하. `image_path` 는 링크를 한 번 푼 비어 있지 않은 일반 파일이어야 한다 — 원시 디스크 경로, `/dev`·`/proc`·`/sys` 아래, 디렉터리·장치·FIFO·소켓, NUL 이 든 경로, E01(EWF) 서명, 케이스·상태 폴더 안의 파일, 정리한 이름이 증거 디렉터리 예약 이름(`EV-NNNN.json`·`imaging-log.txt`·`*.partial`)과 겹치는 파일은 `validation_failed`. 원본은 이때 한 번 연 fd 로만 읽는다(경로를 다시 열지 않음). `imaging_log_path`(FTK Imager·dc3dd·ewfacquire·ewfinfo·Guymager 로그)는 열기 전과 연 뒤 모두 케이스·상태 폴더 검사를 하고 fd 로 4 MiB 까지만 읽는다. 케이스 디스크에 이미지 + 256 MiB 의 여유가 있어야 하고, 보관 기록이 깨져 있으면 아무것도 만들지 않고 `custody_broken`. job: EV 번호 확보(§5) → 원본 fd 에서 확인한 크기만큼 읽으며 sha256·md5·sha1 계산과 `<이름>.partial` 복사(fsync, 0444 — 복사 중 원본의 크기·mtime 이 바뀌면 `integrity_failed`) → `verify_copy=true` 면 사본 재해시 → 이름 바꾸기 → 빠른 지문 → 이미징 로그 대조·사본 `imaging-log.txt` → 접수 기록 `EV-NNNN.json`(원본은 파일 이름·크기·mtime 만, 전체 경로 없음) → **보관 기록 `intake`(커밋 지점** — 해시·크기·저장 경로·빠른 지문·접수 기록 sha256·법적 정보) → 접수 잠금 파일을 지우고 디렉터리 0555 → 커밋 뒤 보조 기록(감사 로그, 사본 재해시가 다르면 `integrity-failed` 사건, 출처 원장 `imported-unattested`, 아티팩트 `evidence-image`, 같은 sha256 확인). 커밋 전의 실패·취소는 만든 파일과 EV 디렉터리를 지우고 번호를 돌려놓는다. 커밋 뒤에 온 취소는 무시하고(succeeded), 감사 로그 실패는 서버 로그만 남기고 그 밖의 보조 기록(`integrity-failed` 사건·출처 원장·아티팩트 색인·같은 sha256 확인) 실패는 `post_commit_errors`·`note` 로 알린다(접수는 그대로). 같은 원본의 접수가 진행 중이면 `busy`. `result`: `ok`(사본 재해시가 다를 때만 false), `evidence_id`, `stored_path`, `size`, `hashes`, `copy_verified`(`verify_copy=false` 면 null), `imaging_log{tool, comparison{status: match/mismatch/no-hashes, details}, conflicts}`(로그가 없으면 null), `custody_seq`, `provenance{seq, kind}`(원장 기록 실패면 `{error}`), `next_steps`, 같은 sha256 의 증거가 이미 있으면 `duplicate_of`·`warning`, 로그 해시가 다르면 `warning`(둘 다면 한 `warning` 에 ' / ' 로 잇는다), 사본 재해시가 다르면 `error` |
| `forensics_verify_start(case_id, evidence_id)` | 사본 전체 재해시 **job**. 공통 입구에서 빠른 지문이 이미 다르면 job 없이 `integrity-failed` 를 기록하고 `integrity_failed`. 입구에서 연 그 fd 를 접수 크기만큼 다시 읽어 보관 기록 `intake` 사건의 sha256·md5·sha1 과 비교 → 보관 기록 `verify` → `result`: `ok`, `result`(`match`/`mismatch` — 크기가 바뀌어도 mismatch), `details{sha256, md5, sha1}`, `custody_seq`. 다르면 `integrity-failed` 사건도 남기고 그 증거의 내용 도구는 모두 거부된다(되돌리지 않는다 — 원본에서 다시 접수). 그 사건을 남기지 못하면 `post_commit_errors`·`note`(상태는 그래도 integrity-failed). 해시하는 도중의 취소는 아무것도 기록하지 않고 `cancelled`, 해시가 끝난 뒤의 취소는 무시하고 기록한다(succeeded). 같은 증거의 검증이 진행 중이면 `busy`. verify 는 그때 디스크에 있는 바이트만 증명한다 |
| `forensics_acquisition_attest(case_id, evidence_id)` | 사람 증명 `write-blocker`: 쓰기 방지 장치를 거쳐 이미징했고 카드를 그 장치에만 넣었다(예여야 승인), 장치 제조사·모델, 희생용 카드로 시험했는지(예/아니오 — 정보 항목), 이미징 도구와 버전. 대상은 증거 id·보관 기록의 sha256·크기, 바인딩은 케이스, 90일 유효. 충족하면 `status: "approved"`, `attestation_id`, `blocker_tested`, `next_steps`. 아니면 `attestation_required`(사람이 `pweh attest <id>`) 또는 `denied` — 앞 증명이 거부·철회·만료됐으면 다시 부를 때 새 요청과 `previous` 가 온다. 보관 기록 `attest` 는 상태가 바뀔 때만 남는다(승인 — 모델·시험 여부·도구 답, 거부, 철회·만료). 증명은 기록일 뿐 다른 도구를 막지 않는다 |
| `forensics_partitions(case_id, evidence_id)` | 읽기 전용, 호출 예산 60초. MBR/EBR·GPT(헤더·항목 CRC, 512/4096 바이트 섹터)·superfloppy → `scheme`, `sector_size`, `image_size`, `partitions[{index, scheme, role, start_offset, size_bytes, start_lba, type_id, type_name, bootable, fs_hint, name·guid(GPT), warnings(10개까지)}]`, `partitions_total`, 파티션마다 `volumes[{index, fs_hint, volume{fs_type, volume_label, volume_id·volume_serial, cluster_size, cluster_count, volume_size, truncated(볼륨이 읽을 수 있는 구간 — 파티션 표 항목과 이미지 끝 중 짧은 쪽 — 보다 김. 원인은 목록·오염 검사의 사유 image_truncated·volume_exceeds_partition), dirty, …} 또는 error(지원하지 않는 파일 시스템 등. 시작이 이미지 끝 너머인 파티션은 data.reason beyond_image — 잘린 이미지, '지원하지 않는 파일 시스템'이 아니다), duplicate_of, omitted}]`, `volumes_total`. 같은 (시작, 크기) 구간은 한 번만 열고(`duplicate_of`), 서로 다른 구간은 64개까지만 연다 — 나머지는 `omitted`(`partitions`/`time`/`steps`)와 `partitions_omitted`. 응답은 파티션·볼륨 128개(넘으면 `truncated`), `warnings` 50개까지(잘라 싣는다). `truncated`·`truncated_reason`(`time`/`partitions`/`steps`/`response`)은 예산·상한·응답 크기 때문에 파티션을 다 열거나 싣지 못했다는 뜻뿐이다 — 이미지 잘림은 파티션 `warnings`(`partition_beyond_image`·`partition_truncated`)·`warnings`(`ebr_beyond_image`)·`volume.truncated`·`beyond_image` 볼륨 오류로 보인다. `next_steps` |
| `forensics_image_check(case_id, evidence_id, partition=None, acquisition_date=None)` | 읽기 전용. 보관 기간에 분석 PC 가 카드에 남겼을 흔적(삭제 항목 포함, 볼륨마다 200개까지): strong — 루트의 `$RECYCLE.BIN`·`.Spotlight-V100`·`.fseventsd`·`.Trashes`·`.Trash-<uid>`, `System Volume Information` 안의 `IndexerVolumeGuid`·`WPSettings.dat`, 어느 깊이든 `.DS_Store`·`._*`·`Thumbs.db`·`desktop.ini` / weak — `System Volume Information` 폴더만, 마지막 접근 날짜가 `acquisition_date`(YYYY-MM-DD, 생략하면 접수 시각의 날짜)와 같은 살아 있는 파일(개수) / ambiguous — dirty 비트. 예산은 고정(§3.1). → `volumes[{partition, fs, indicators[{indicator, strength, path, deleted, note}], walk_truncated(엔진 순회가 잘렸거나 서버가 더한 사유가 있음 — fs_list 의 볼륨 truncated 와 같은 규칙), walk_truncated_reason, walk_truncated_reasons(엔진 사유 + dir_unvalidated·image_truncated·volume_exceeds_partition), cut_dirs, cut_dirs_total, unvalidated_dirs}]`(해석하지 못하면 `error`), `strong_indicators`, `acquisition_date`, `call`, `truncated`, `truncated_reasons`, `note`, 사유가 있으면 `next_steps`. 해석하지 못한 볼륨이 있거나 사유가 하나라도 있으면 `note` 는 '흔적 없음'이라 하지 않는다. 본 볼륨이 하나도 없으면 `note` 는 흔적을 '보지 못했다'고 한다(흔적 없음 문장은 나오지 않는다 — `truncated` 는 지원하는 파티션이 없을 뿐이면 false, 파티션이 이미지 끝 너머면 `image_truncated` 로 true). `partition` 으로 고른 파티션의 시작이 이미지 끝 너머면 `validation_failed`(사유 `beyond_image`, 메시지가 잘린 이미지라고 알린다). 흔적은 정황이다 |
| `forensics_fs_list(case_id, evidence_id, partition=None, include_deleted=True, max_entries=200000, max_seconds=180)` | FAT12/16/32·exFAT 목록(삭제 항목 포함, **동기 호출**). 지원하는 파티션이 없거나 고른 파티션이 지원 밖이면 `validation_failed`(파티션이 이미지 끝 너머라 볼 수 없으면 메시지·힌트가 ext4·NTFS 안내 대신 잘린 이미지라고 알리고, 고른 파티션의 시작이 이미지 끝 너머면 메시지가 잘린 이미지라고 알린다 — 엔진 사유는 `beyond_image`(`unsupported_fs` 가 아니다)지만 동기 도구의 오류에는 메시지·힌트만 온다). 전체 목록은 `forensics/analysis/fs-list-<EV>-NNN.json`(0444, 볼륨마다 한 줄에 항목 하나씩 이어 쓰며 sha256 계산)에만 쓰고 보관 기록 `list` 에 그 sha256 과 `call` 을 남긴다. 실패·중단하면 만든 목록 파일을 지운다. 응답: `result_path`, `result_sha256`, `custody_seq`, `volumes[{partition, fs, volume, stats{files, dirs, deleted_files, deleted_dirs, orphans, dirs_read}, truncated, truncated_reason, truncated_reasons, cut_dirs, cut_dirs_total, time_ranges[{state(live/deleted), time_basis, first, last, files}], time_basis, top_dirs, extensions(개수만), files_with_residual, orphans, unvalidated_dirs, unvalidated_dirs_live, warnings_count, sample(처음 20개: 경로·크기·수정 시각·ref)}]`(해석하지 못하면 `error`, 128개까지 — `volumes_total`), `truncated`, `truncated_reasons`, `call`, `next_steps`. 한도·잘림 사유는 §3.1 |
| `forensics_extract(case_id, evidence_id, refs=None, paths=None, partition=None, method="auto", region="data", label=None, max_files=200, max_bytes="1G")` | 고른 파일만 추출하는 **job**(정책 전체는 §3.2). `refs`(목록 JSON 의 `ref`, 삭제 항목 포함)·`paths`(살아 있는 파일)는 중복을 없애고 합쳐 1000개까지. `region="residual"` 이면 exFAT ValidDataLength 뒤 잔여 영역(이전 녹화 흔적)만. `max_files` 1~1000, `max_bytes` 4 GiB 까지(정수 또는 `"1G"`·`"512M"`), 시작 전에 여유 공간(`max_bytes` + 256 MiB) 확인, `label` 은 `[0-9A-Za-z._-]` 로 정리해 32자(기본 `recovered`). `forensics/recovered/<label>-NNN/` 에 `NNNN-<정리한 이름>`(0444, 실행 비트·링크 없음)과 `manifest.json` → 디렉터리 0555 → 보관 기록 `extract`(커밋 지점). `result`: `output_dir`, `manifest`, `manifest_sha256`, `custody_seq`, `bytes_total`, `truncated`, `truncated_reasons`, `files[{seq, file, path, deleted, method, confidence, status, size, complete, sha256, limit_reason?, requested_path?}]`, `skipped`(50개까지)·`skipped_total`, `note`, `next_steps`. 해시·크기·방법만 돌려준다. 같은 증거의 추출이 진행 중이면 `busy` |
| `forensics_evidence_list(case_id, write_files=True)` | 증거 목록: `custody{ok, count, head, detail}`, `items[{evidence_id, label, stored_path, size, hashes, intake_ts, imaging_log, intake, status, status_label, last_verify{ts, result, seq, kind(intake-copy/full-rehash)}, integrity_failures, attestation, extracts, events, problems?}]`(아래 상태), `aborted[{evidence_id, ts, seq, quarantine_path, reason}]`(커밋하지 못해 `aborted-intakes/` 로 옮긴 것 — 증거가 아니다), `derived[{path, evidence_id, files, bytes, manifest_sha256, custody, custody_seq, error?}]`(`recovered/*/manifest.json` 을 보관 기록 `extract` 사건과 대조: `recorded`/`mismatch`/`unrecorded`/`missing`/`unknown`), `notice`. 목록을 만들기 전에 커밋한 증거마다 공통 입구로 다시 대조하고 새 문제는 `integrity-failed` 로 기록해 `integrity_failures_recorded` 에 싣는다(`write_files=false` 여도). `write_files=true` 면 `forensics/evidence-list.json`·`.md`(해시값 확인서 서식·서명란·고지 — 확인서에는 보관 기록에 해시가 있는 상태만)를 다시 쓰고 `files{json, markdown, json_sha256}`, 보관 기록이 정상이면 `evidence-list` 사건에 JSON sha256 을 남긴다. `forensics/` 가 링크 등이면 파일은 쓰지 않고 `files_error` |
| `forensics_job_status(job_id, wait_seconds=0, case_id=None)`, `forensics_job_cancel(job_id)`, `forensics_jobs(active_only=False, case_id=None)` | `register_job_tools(..., "forensics")`. 접수·검증·추출 job 의 진행률·결과(`wait_seconds` 최대 50초). 기본은 이 서버 프로세스의 job, `case_id`를 주면 `cases/<id>/jobs/<job_id>.json`의 저장 기록도 확인한다(아래 공통 동작). 취소: 접수·검증은 1 MiB 읽기 조각마다 확인한다 — 커밋 전이면 접수는 만든 파일을 지우고 검증은 기록 없이 끝난다(`cancelled`), 커밋(접수 `intake` 사건·검증 해시 완료) 뒤의 취소는 무시한다(succeeded). 추출은 §3.2 의 규칙을 따른다 — job 이 `cancelled` 여도 `result` 가 있으면 그 부분 결과는 보관 기록에 남은 것이다. `forensics_job_cancel` 의 공통 설명('부분 결과는 보존된다')은 추출에만 맞다 |

작업 상태·목록의 `case_id`를 생략하면 이 서버 프로세스의 작업만 보인다. 재시작 뒤에는
`forensics_job_status(job_id, case_id="<케이스 ID>")` 또는 `forensics_jobs(case_id="<케이스 ID>")`로 같은 서버의 저장 기록을 확인한다.
소유 서버 종료가 확실한 활성 기록만 `failed`(`error.code=job_owner_terminated`)로 정리한다. 소유자 없는 과거 기록·다른 호스트/namespace·관찰 불가는
원본 상태를 보존하고 `recovery.owner_state="unknown"`과 사유를 표시한다. 살아 있는 다른 서버 프로세스의 기록도 보존한다.
원시 owner 식별자는 응답에 나오지 않는다. 저장 기록의 재개/취소는 없고, `wait_seconds`는 이 프로세스의 작업만 기다린다.
한 기록 1MiB, 목록 512디렉터리 항목·256기록·누적 8MiB·2초로 제한하며 목록의 `recovery.truncated/reasons`가 확인하지 못한 범위를 알린다.
이 두 도구는 로컬 기록을 정리하므로 `readOnlyHint=false`다. 파일·기기·외부 자식의 정리 여부는 별도로 확인한다.

`status` 값(증거 목록 `items[].status`):

- 보관 기록에 커밋한 접수가 있는 상태 — 해시·크기는 보관 기록 `intake` 사건(고정점으로 보호)의 값이다: `ok`(마지막 검증 — 접수 때 사본 재해시나 전체 재해시 — 이 일치), `unverified`(접수만 — 사본 재해시·전체 재해시 없음),
  `integrity-failed`(무결성 실패 기록, 사본 재해시 불일치, 또는 접수 기록이 `intake` 사건과 다름 — `problems`. 되돌리지 않는다), `missing`(실제 EV 디렉터리가 없음 — 지워졌거나 링크·파일로 바뀜. 링크·파일이면 다시 대조할 때 `integrity-failed`(`unsafe-path`)를 남겨 `status_label` 이 `missing (integrity-failed)` 다), `record-invalid`(접수 기록 파일이 없거나 읽을 수 없음).
- 해시가 없는 상태: `custody-broken`(보관 기록·고정점이 깨짐 — EV 디렉터리마다), `record-without-intake`(보관 기록에 `intake` 가 없는 EV 디렉터리 — 중단된 접수의 흔적이 있으면 다음 접수·서버 시작 때 `aborted-intakes/` 로 옮겨지고, 흔적이 없으면 사람이 판단할 때까지 남는다, §5),
  `intake-in-progress`(접수 job 이 그 디렉터리의 접수 잠금을 잡고 있음).
- `status_label` 은 사람이 읽는 표시다(증거 목록 md·보고서의 상태 칸). `status` 와 같고, EV 디렉터리가 없는 증거에 무결성 실패 기록이 있을 때만 `missing (integrity-failed)` 다(`status` 는 `missing`).

### 3.1 예산과 잘림

이미지는 신뢰할 수 없는 입력이라 모든 해석이 예산 안에서 끝난다. 예산·한도에 닿거나 끝까지 읽지 못한 부분이 있으면 결과는 잘림으로 보고한다.

| 도구 | 호출(또는 job) 예산 |
|---|---|
| `forensics_partitions` | 60초. 엔진 예산 하나(단계 상한은 연 볼륨마다 올린다), 서로 다른 구간 64개 |
| `forensics_image_check` | 고정: 120초, 항목 200,000개(파티션 합계), 경로 글자 수 268,435,456, 파티션 64개(같은 구간은 한 번) |
| `forensics_fs_list` | `max_seconds` 1~600(기본 180, 0 이면 기본값, 1 보다 작으면 1), `max_entries` 1~200,000(파티션 합계), 경로 글자 수 268,435,456, 파티션 64개(같은 구간은 한 번) |
| `forensics_extract` | job 300초, `max_files`·`max_bytes`. 엔진 호출(확인 순회·항목·경로 찾기·후보)마다 job 마감·취소 함수를 함께 쓰는 예산을 새로 만들고, 남은 시간이 1초 미만이면 더 하지 않는다 |
| `forensics_intake_start`·`forensics_verify_start` | 시간 예산 없음(이미지 전체를 읽는다). 취소만 받는다 |

- 목록·오염 검사는 볼륨마다 엔진 예산(`pweh.fs.Budget`) 하나를 열기·정보·순회가 함께 쓴다: 호출의 마감 시각과, 볼륨을 열 때 그 볼륨의 단계 상한 — max(2^24, 2 × N + 8,388,608),
  N = min(클러스터 수, 이미지 안에서 읽을 수 있는 FAT 항목 수 − 2) — 으로 올린 작업 단계 수.
  처음 여는 볼륨은 호출 시간이 조금이라도 남으면 열고, 그 뒤 볼륨은 남은 시간이 0.25초 미만이면 건너뛴다. 경로 글자 수는 호출 전체의 남은 몫을 볼륨마다 넘긴다.
- 엔진의 고정 한도: 디렉터리 깊이 64, 디렉터리 하나의 슬롯 min(1,048,576, 사양 최대 — FAT 은 65,536), 순회 하나의 슬롯 합계 8,388,608.
- `max_seconds` 는 볼륨 열기·정보·순회의 시간이다. 목록 요약과 목록 파일 쓰기는 그 뒤라 응답은 `max_seconds` 보다 늦게 올 수 있다(항목 수에 비례).

잘림 사유(`truncated_reasons`, 처음 나온 순서):

| 사유 | 종류 | 뜻 | 다음 단계(`next_steps`) |
|---|---|---|---|
| `time` | 전역 | 호출·job 시간 예산 | fs_list 는 `max_seconds`(최대 600)를 늘리거나 `partition` 으로 나눈다. image_check 는 `partition` 으로 나눈다(120초 고정). 추출은 남은 ref·paths 로 다시 |
| `steps` | 전역 | 볼륨의 작업 단계 상한 — 정상적으로 꽉 찬 볼륨은 닿지 않는다(같은 긴 체인을 여러 항목이 가리키는 조작·손상 의심) | 사람에게 알리고 보고서 한계에 적는다 |
| `max_entries` | 전역 | 항목 수 합계 상한 | fs_list 는 `max_entries` 를 늘리거나 `partition` 으로 나눈다. image_check 는 `partition` 으로 나눈다 |
| `max_total_slots` | 전역 | 순회 하나의 슬롯 합계 8,388,608 | 사람에게 알린다(조작 의심) |
| `max_path_chars` | 전역 | 호출 전체의 경로 글자 수 268,435,456 | `partition` 으로 나누고 사람에게 알린다 |
| `cancelled` | 전역 | 추출의 부분 결과 취소 사유 — 동기 목록·검사 요청 취소는 커밋 전에 결과 없이 끝난다 | 필요하면 다시 부른다 |
| `max_depth` | 디렉터리 | 깊이 64 — 그 디렉터리 항목은 싣지만 안으로 내려가지 않는다(그 아래는 목록·ref 가 없다) | 고정 한도 — 사람에게 알리고 보고서 한계에 적는다 |
| `max_dir_slots` | 디렉터리 | 디렉터리가 슬롯 한도에서 잘려 뒤쪽 항목이 없다(경고 `dir_slot_limit`) | 고정 한도 — 같음 |
| `beyond_image` | 디렉터리 | 살아 있는 디렉터리 데이터가 읽을 수 있는 범위(파티션 표 항목과 이미지 끝 중 짧은 쪽) 끝 너머 — 원인은 볼륨 사유 `image_truncated`·`volume_exceeds_partition` 으로 본다 | 사람에게 알리고 보고서 한계(원인이 `image_truncated` 면 이미징이 끝까지 됐는지 사람이 확인 — 필요하면 다시 이미징) |
| `dir_chain_broken` | 디렉터리 | 살아 있는 디렉터리의 체인이 끝 표시 전에 비정상으로 끝남(카드 손상 가능. exFAT 은 DataLength 보다 짧은 체인 포함 — 체인이 읽을 길이(DataLength, 슬롯 한도보다 길면 한도까지)를 다 모았으면 마지막 FAT 항목이 망가져도 잘림이 아니고 경고 `dir_chain_*` 만. DataLength 가 슬롯 한도보다 길고 한도 안에 끝 표시가 없으면 그래도 `max_dir_slots`) | 사람에게 알리고 보고서 한계 |
| `dir_unreadable` | 디렉터리 | 살아 있는 디렉터리를 읽지 못함(그 디렉터리의 내용이 하나도 없다). 추출에서는 그 디렉터리를 지나는 `paths`·그 디렉터리를 가리키는 ref 의 code | 같음 |
| `dir_unvalidated` | 볼륨 | 살아 있는 디렉터리가 검증하지 못한 단위에서 멈춰 그 뒤 항목이 없다(`unvalidated_dirs_live`) — 손상·교차 연결이거나 엔진이 일부러 엄격하게 거르는 형식 | 같음 |
| `image_truncated` | 볼륨·호출 | 이미지가 카드보다 짧다 — 볼륨 끝(파티션 시작 + `volume_size`)이 이미지 끝 너머(`volume.truncated` — 볼륨 사유)이거나, `partition` 을 고르지 않았을 때 파티션이 통째로 이미지 끝 너머(`forensics_partitions` 의 `partition_beyond_image`·`ebr_beyond_image` — 호출 사유). 잘린 이미징·용량을 속인 카드. 끝 너머의 파티션·디렉터리·파일 내용·삭제 흔적은 볼 수 없다 | 이미징 확인, 보고서 한계 |
| `volume_exceeds_partition` | 볼륨 | 이미지는 이어지는데 파일 시스템이 파티션 표 항목보다 크다(`volume.truncated`) — 파티션 표가 줄었거나 손상. 항목 밖으로 이어지는 부분은 이 파티션 범위로 읽지 않는다(그 부분의 디렉터리·파일 내용은 볼 수 없다) | 사람에게 알리고 보고서 한계 |
| `max_partitions` | 호출 | 서로 다른 구간 64개를 넘어 나머지 파티션을 건너뜀 | 나머지는 `partition` 으로 따로 본다 |

- 전역 사유는 그 볼륨의 순회를 멈추고, 디렉터리 사유는 그 디렉터리의 읽지 못한 부분만 빠지고 나머지 나무는 계속 본다(`cut_dirs`): `max_dir_slots`·`beyond_image`·`dir_chain_broken` 은 읽은 앞부분 항목(과 그 아래)이 목록에 있고,
  `max_depth` 는 그 디렉터리 항목만 있고 안으로 내려가지 않으며, `dir_unreadable` 은 그 디렉터리의 내용이 하나도 없다(부모 목록의 그 항목만 있다).
  볼륨 사유는 서버가 엔진 결과(`unvalidated_dirs_live`, 볼륨 정보의 `truncated` 와 파티션 시작·이미지 크기)에서 더한다.
  호출 사유는 `call.partitions_skipped`(사유별 개수·예시 index) 이름을 순회 사유와 맞춘 것이다(`entries` → `max_entries`, `path_chars` → `max_path_chars`, `partitions` → `max_partitions`). 같은 구간의 중복 파티션(`duplicate`)은 한도가 아니다.
  파티션 표로 보이는 잘림(통째로 이미지 끝 너머인 파티션, 이미지 끝 너머에서 끊긴 EBR 사슬)은 호출 사유 `image_truncated` 다.
- 해석하지 못한 볼륨(`volumes[].error`)은 사유가 아니라 `call.volumes_failed{count, examples[{partition, reason}]}` 로 세고 `truncated=true` 로 만든다. 엔진 예산이 다 돼 난 볼륨 오류(`budget_exceeded`)는 손상이 아니라 한도라
  `call.partitions_skipped` 의 `time`·`steps` 로 센다(그 볼륨에도 `volumes[].error` 는 있지만 `volumes_failed` 에는 들지 않는다).
- 추출에만 있는 사유는 `max_files`·`max_bytes`·`refs_unverifiable` 이다(§3.2).
- 볼륨의 `truncated` 는 순회가 잘렸거나 사유가 하나라도 있으면 참이고, 응답의 `truncated` 는 사유가 하나라도 있거나 해석하지 못한 볼륨이 있으면 참이다. 고정 한도와 이미지·카드 상태 사유의 `next_steps` 는 시간을 늘리라고 하지 않는다.
- 삭제된 디렉터리(와 그 아래)는 최선 노력이라 손상·이미지 끝·검증 실패를 잘림으로 세지 않는다(경고만). 검증하지 못한 디렉터리가 삭제된 것뿐이면 fs_list 의 `next_steps` 에 따로 알린다.
- `call` 은 응답·목록 파일·보관 기록 `list` 에 같은 모양으로 남는다: `max_entries`, `entries_used`, `max_partitions`, `max_path_chars`, `path_chars_used`, `partitions_walked`, `partitions_skipped`, `volumes_failed`.
- 응답의 경로(`sample`·`cut_dirs`·`indicators`)는 앞·뒤만 남겨 300자로 줄이고, `cut_dirs` 는 10개까지(`cut_dirs_total`)만 싣는다. 목록 파일의 `walk` 에는 엔진 결과 전체(`truncated_reasons`, `dirspec` 이 있는 `cut_dirs`·`unvalidated_dirs` 각 100개까지, `path_chars`)가 있다.

### 3.2 추출 정책 (`forensics_extract`)

- **볼륨**: 지원하는 파티션(같은 구간은 하나로 센다)이 여럿이면 `partition` 이 필요하다(없으면 job 이 `validation_failed` 로 실패).
  고른 파티션의 시작이 이미지 끝 너머이거나, 파티션이 이미지 끝 너머라 볼 수 있는 FAT/exFAT 파티션이 없으면 job 이 `validation_failed`(`data.reason` `beyond_image` — 잘린 이미지)로 실패한다.
- **ref 확인**: 모양이 `<dirspec>/<slot>` 이 아닌 ref 는 순회 없이 `bad_ref`. 나머지는 루트에서 검증한 디렉터리만 따라가는 확인 순회(`reachable_dirspecs`)가 그 ref 의 디렉터리를 찾았을 때만 받는다 — 요청한 디렉터리를 다 찾으면 멈춘다.
  순회를 끝까지 돌았는데 없으면 `bad_ref`. 순회가 한도·예산에서 잘렸거나 살아 있는 디렉터리를 끝까지 읽지 못해(`beyond_image`·`dir_chain_broken`·`dir_unreadable`) 잘렸으면, 찾은 디렉터리의 ref 는 받고 못 찾은 ref 만 `skipped` 의 code `refs_unverifiable` 이다.
  순회가 잘렸는데 검증된 ref 가 하나도 없고 `paths` 도 없을 때만 job 이 `refs_unverifiable` 로 실패한다. ref 가 모두 `bad_ref` 이고 `paths` 가 없으면 실패하지 않고 파일 0개 매니페스트와 보관 기록 `extract` 를 남긴다(`truncated=false`).
  받은 ref 도 항목을 읽을 때 디렉터리를 다시 검증한다 — 검증하지 못한 영역의 ref 는 `bad_ref`, 슬롯 한도·읽을 수 있는 범위의 끝·체인 손상으로 읽지 못한 뒤쪽을 가리키면 그 사유(`max_dir_slots`·`beyond_image`·`dir_chain_broken`)가 code 이고, ref 의 디렉터리를 읽지 못하면 `dir_unreadable` 이다.
  ref 항목의 경로는 확인 순회의 디렉터리 경로 + `/` + 표시 이름이다.
- **paths 찾기**: 검증한 디렉터리만 지난다. 이름(또는 표시 이름)이 정확히 같은 항목이 먼저, 없으면 대소문자를 무시한다 — 글자 수를 바꾸는 접기는 하지 않는다(FAT 은 글자마다 한 글자 대문자로 긴 이름·표시 이름·8.3 이름을, exFAT 은 볼륨의 up-case 표로 비교).
  여럿이 맞으면 code `ambiguous_path`(사유에 이름을 싣지 않는다). 끝까지 읽은 디렉터리에 없으면 `not_found`, 64 단계보다 깊으면 `max_depth`.
  잘렸거나 끝까지 읽지 못했거나 검증하지 못한 디렉터리(예산·슬롯 한도·`beyond_image`·`dir_chain_broken`·검증 실패)에서는 정확히 같은 이름(이름·표시 이름, 대소문자 포함)만 받는다 —
  대소문자만 맞는 항목·8.3 별칭은 고르지 않는다(정확한 이름이 읽지 못한 뒤쪽에 있을 수 있다). 거기서 못 찾으면 그 사유(`max_dir_slots`·`beyond_image`·`dir_chain_broken`·`dir_unvalidated`, 예산이면 `time`·`steps`·`cancelled`)가 code 다.
  예산 멈춤이 아니면(`max_dir_slots`·`beyond_image`·`dir_chain_broken`·`dir_unvalidated`) 대소문자만 맞는 항목이 있을 때 메시지가 그렇게 알린다. 경로의 디렉터리를 읽지 못하면 code `dir_unreadable` 이다(목록의 같은 사유).
  `path` 는 디스크의 이름이고, 호출자가 쓴 철자(8.3 별칭·대소문자 변형)가 다르면 `requested_path` 로 남는다.
- **중복**: 같은 문자열은 물론, 다른 문자열이 같은 항목(ref)을 가리켜도 하나만 추출한다. 디렉터리 항목은 추출하지 않는다(`skipped`).
- **skipped 모양**: 찾지 못한 요청은 `{ref|path, code, reason}`(이미지에서 읽은 이름은 싣지 않는다), 추출 단계에서 건너뛴 항목은 `{ref, path, reason}`.
  code 중 `time`·`steps`·`cancelled`·`refs_unverifiable`·`max_depth`·`max_dir_slots`·`beyond_image`·`dir_chain_broken`·`dir_unreadable`·`dir_unvalidated` 는 결과를 불완전하게 만드는 것이라 `truncated_reasons` 에 더한다(매니페스트 `truncated=true`). 나머지(`bad_ref`·`not_found`·`ambiguous_path` 등)는 `skipped` 에만 있다.
- **method**: `auto`(가장 믿을 만한 후보) 또는 후보 이름 — 살아 있는 파일 `chain`·`nofatchain`, 삭제한 FAT 파일 `contiguous`·`skip-allocated`·`skip-claimed`·`fat-chain`, 삭제한 exFAT 파일 `stale-chain`·`contiguous`·`skip-allocated`.
  이름을 주면 그 후보만 만든다(그 항목에 없는 방법은 가능한 방법을 알려 주며 건너뛴다). 예산이 다 돼 후보를 만들지 못하면 그 항목을 건너뛰고 사유 `time`·`steps` 를 남긴다.
  예산 때문에 덜 만든 계획은 `status: "limit"` + `limit_reason`(`time`/`steps`) 이고, 있는 만큼 쓰고 그 사유를 `truncated_reasons` 에 더한다.
- **쓰기**: 출력 디렉터리 fd 안에 `O_EXCL|O_NOFOLLOW` 로 만들어 조각으로 쓰며 sha256 을 계산한다(메모리에 모으지 않음). 파일마다 매니페스트에 원래 경로·방법·신뢰도·설명·`status`·크기·`complete`·sha256 이 남는다.
  `complete` 는 계획이 크기를 다 담고 그만큼 썼을 때만 참이다. `max_bytes` 는 상한이 실제로 파일을 잘랐을 때만(상한까지 썼는데 계획에 더 있었을 때) 사유가 된다.
  내용이 읽을 수 있는 범위(파티션 표 항목과 이미지 끝 중 짧은 쪽) 끝 너머라 덜 읽은 살아 있는 파일은 실제로 읽은 바이트만 쓰고 `complete=false`·`bytes_beyond_image` 로 남긴다 — 그것만으로는 잘림 사유가 아니다.
  `bytes_beyond_image` 는 매니페스트에만 있고 응답의 `files[]` 에는 `complete=false` 만 보인다.
- **커밋과 취소**: 보관 기록 `extract` 를 덧붙이는 것이 커밋 지점이다. 그 전의 실패(쓰기 오류, 출력 디렉터리에 서버가 만들지 않은 이름이 생김 → `path_outside_base` 등)는 출력 디렉터리를 링크를 따르지 않고 지운다. 덧붙인 뒤에는 무슨 일이 있어도 지우지 않는다.
  - 볼륨을 열거나 ref 를 확인하거나 경로를 찾는 도중의 취소: 바로 `cancelled` — 출력 디렉터리도 보관 기록도 없다.
  - 후보를 만들거나 쓰는 도중의 취소(파일 사이·쓰는 도중·엔진이 후보를 만드는 도중): 쓰던 파일은 `complete=false` 로 남고, 시도하지 않은 항목은 모두 `skipped`(사유 '취소됨')에 싣는다. 매니페스트 `truncated_reasons` 에 `cancelled`, 보관 기록 `extract` 를 남기고 job 은 `cancelled`(`result` 는 같은 모양).
  - 추출이 끝났거나 보관 기록에 남은 뒤에 온 취소: 무시한다(succeeded). job 이 `cancelled` 로 끝나는 것은 매니페스트에 `cancelled` 가 있을 때뿐이다.
- **매니페스트**(`pweh.forensics.recovered/v1`): `evidence_id`, `evidence_sha256`(보관 기록 `intake` 사건의 값 — 추출 때 다시 해시하지 않는다), `partition`, `fs`, `generated_at`, `params`,
  `files[{seq, file, ref, path, deleted, region, method, confidence, status, note, expected_size, size, complete, sha256, runs_total, conflicts, limit_reason?, bytes_beyond_image?, requested_path?}]`, `skipped`, `bytes_total`, `truncated`, `truncated_reasons`.

## 4. 결과 파일 (케이스)

모두 `cases/<id>/forensics/` 아래에 있고 이 서버만 쓴다(처음 접수할 때 만든다).

| 경로 | 내용 | 권한 |
|---|---|---|
| `forensics/images/EV-NNNN/<정리한 원본 이름>` | 접수한 이미지 사본 (아티팩트 `evidence-image`, `extra.evidence_id`). 복사하는 동안은 `<이름>.partial` 이고 다 쓰면 이름을 바꾼다 | 0444 |
| `forensics/images/EV-NNNN/EV-NNNN.json` | 접수 기록(`pweh.evidence/v1`): 원본 파일 이름·크기·mtime(전체 경로는 남기지 않음), 저장 경로·크기, 해시 세 가지, 빠른 지문, 이미징 로그(도구·해시·대조), 접수 정보(시각·목적·법적 근거·설치 장소 유형·업무 목적·역할·`copy_verified`). 이 파일의 sha256 이 보관 기록 `intake` 사건에 있다 | 0444 |
| `forensics/images/EV-NNNN/imaging-log.txt` | 이미징 도구 로그 사본 (주었을 때만) | 0444 |
| `forensics/images/EV-NNNN/.intake.lock` | 접수 job 이 커밋할 때까지 잡는 잠금 — 커밋하면 지운다(남아 있는데 잡은 쪽이 없으면 중단된 접수의 흔적) | 0600 |
| `forensics/images/EV-NNNN/` | EV 디렉터리 | 접수 중 0755, 커밋 뒤 0555 |
| `forensics/images/.claim.lock` | EV 번호 확보·정리 잠금 | 0600 |
| `forensics/aborted-intakes/EV-NNNN-<UTC>/` | 커밋하지 못한 접수를 옮겨 둔 곳(보관 기록 `intake-aborted`, 증거가 아니다 — 지우지 않는다) | 파일 0444, 디렉터리 0555 |
| `forensics/custody.jsonl` | 보관 기록 (`pweh.custody/v1` 해시 체인, 덧붙이기만 — 잠금 안에서 통째로 원자적으로 바꿔 쓴다) | 0644 |
| `forensics/.custody.lock` | 보관 기록 잠금(읽기는 공유, 덧붙이기는 배타) | 0600 |
| `forensics/analysis/fs-list-<EV>-NNN.json` | `forensics_fs_list` 의 전체 목록(`pweh.forensics.fs-list/v1`): `params`, `scheme`, 볼륨마다 `partition`·`info`·`walk`(엔진 결과 전체 + `entries`, 해석하지 못하면 `error`), `call` | 0444 |
| `forensics/recovered/<label>-NNN/NNNN-<이름>` | 추출물 (exFAT 잔여는 `.residual`) | 0444, 디렉터리는 다 쓴 뒤 0555 |
| `forensics/recovered/<label>-NNN/manifest.json` | 추출 매니페스트(`pweh.forensics.recovered/v1`, §3.2) | 0444 |
| `forensics/evidence-list.json`, `forensics/evidence-list.md` | 증거 목록·해시값 확인서 (부를 때마다 원자적으로 다시 씀) | 0644 |

케이스 밖 `.pweh/state/custody/<case_id>.jsonl` 에 보관 기록의 고정점(줄마다 seq·해시, 파일 0600·디렉터리 0700)이 있다. 출처 원장 `.pweh/state/provenance/<case_id>.jsonl` 에는 접수 기록 파일이
`imported-unattested`(extra 에 이미지 sha256·크기)로 남는다. 둘 다 보호 상태라 에이전트가 만들거나 고치거나 지우지 않는다. job 기록은 `cases/<id>/jobs/<job_id>.json` 이다(원본 경로는 남기지 않는다).

## 5. 보관 기록·무결성·사람 증명

- **보관 기록**: 줄마다 정규화 JSON(`schema, seq, ts, case_id, event, evidence_id, actor, data, prev`)이고 `prev` 는 앞 줄의 sha256(첫 줄은 케이스 id 에 묶인 시작값)이다.
  사건은 `intake`, `intake-aborted`, `verify`, `integrity-failed`, `attest`, `list`, `extract`, `evidence-list` 다(`check`·`note` 는 예약만 하고 쓰지 않는다). actor 는 늘 `server` 다.
  같은 사건은 감사 로그에도 남는다(`forensics_<사건>`, `-` 는 `_`).
- **고정점**: 서버는 줄을 덧붙일 때마다 그 줄의 seq·해시를 고정점에도 쓰고, 읽을 때 체인과 고정점을 함께 검증한다. 덧붙이기는 세 단계다 — 1) 고정점에 '기록 중'(pending) 줄 → 2) `custody.jsonl`(커밋 지점) → 3) 고정점 확정.
  1 뒤 2 전에 끊기면 읽는 쪽은 '기록 중' 줄을 기록 전 중단으로 보고(사건 없음 — 다음 덧붙이기가 그 자리를 덮어쓴다), 2 뒤 3 전에 끊기면 '기록 중' 줄이 보관 기록의 마지막 줄과 같으므로 확정으로 본다(다음 덧붙이기가 확정 줄로 다시 쓴다).
  그래서 디스크 가득·강제 종료가 보관 기록을 영구히 깨뜨리지 않는다. 덧붙이기는 사건이 남지 않았을 때만 예외를 던진다(확정 쓰기·정리 실패는 로그만 남긴다). 마지막 고정점이 '기록 중'으로 남은 동안의 틈은 §8.
- **깨짐**: 줄 수정·잘라 내기·서버 밖에서 덧붙인 줄·다른 케이스에서 옮겨 온 기록, `forensics/`·보관 기록·고정점이 링크이거나 일반 파일이 아님, 크기 상한(보관 기록 64 MiB, 고정점 16 MiB) 초과는 모두 깨짐이다.
  깨지면 그 케이스의 내용 도구·접수·기록 쓰기가 `custody_broken` 이고(fail closed) 증거 목록의 항목은 `custody-broken` 이다. 서버는 기록을 고치지 않는다. 읽기는 `forensics/.custody.lock` 공유 잠금, 덧붙이기는 배타 잠금 안에서 한다.
- **공통 입구**(`forensics_verify_start`·`forensics_acquisition_attest`·`forensics_partitions`·`forensics_image_check`·`forensics_fs_list`·`forensics_extract`): 보관 기록 → 그 증거의 `intake` 사건
  → EV 디렉터리와 접수 기록(1 MiB 상한)을 링크를 따르지 않고 열어 `intake` 사건과 대조(접수 기록 sha256·해시·크기·저장 경로·빠른 지문) → 사본을 한 번 안전하게 열어 그 fd 로 빠른 지문 대조. 해석·재해시는 그 fd 로만 한다(경로를 다시 열지 않음).
  - 문제가 있으면 `integrity-failed` 를 기록하고 `integrity_failed` 로 거부한다(읽기 전용 도구도 이때는 한 줄을 쓴다). 기록하는 사유: `stored-copy-missing`, `stored-copy-not-regular`, `stored-copy-unreadable`, `record-missing`, `record-invalid`, `record-mismatch`, `fingerprint-mismatch`, `unsafe-path`
    (접수의 `copy-verify-mismatch`, 검증의 `verify-mismatch` 와 함께). 무결성 실패는 되돌리지 않는다 — 원본 이미지에서 다시 접수한다(새 EV 번호).
  - 기록하지 않고 `integrity_failed` 로 거부: 이미 무결성 실패로 표시됨, EV 디렉터리가 지워짐(증거 목록의 `missing`), 보관 기록에 `intake` 가 없는 디렉터리, 같은 번호의 `intake` 가 둘. 보관 기록에도 디렉터리에도 없는 id 는 `not_found`.
- **빠른 지문**: 크기·mtime_ns·앞/뒤 1 MiB sha256, 쓰기 권한 비트가 없음. inode·ctime 은 보지 않는다 — 가운데만 바꾸고 mtime·권한을 되돌린 변조나 같은 앞/뒤·크기·mtime 의 다른 파일로 바꾼 것은 `forensics_verify_start` 로만 찾는다.
  그 사이의 내용 도구 결과·추출 매니페스트의 `evidence_sha256`·증거 목록의 `ok` 는 접수 때 해시를 가리킬 뿐 지금 읽은 바이트를 증명하지 않는다.
- **EV 번호**: `images/.claim.lock` 안에서 (EV 디렉터리·`aborted-intakes/` 이름·보관 기록에 나온 번호 중 가장 큰 것) + 1. 지운 증거의 번호는 보관 기록에 남으므로 다시 쓰지 않고, 한 번호에 `intake` 는 하나뿐이다(`intake-aborted` 뒤의 `intake` 도 거부).
  커밋 전에 실패·취소된 접수(서버가 정상 종료하며 되돌린 것 포함)는 EV 디렉터리를 지우고 보관 기록에 아무것도 남기지 않으므로 그 번호는 다시 쓰일 수 있다.
- **커밋하지 못한 접수 정리**: 프로세스가 강제로 끝나(SIGKILL 등) 남은 EV 디렉터리는 다음 접수의 번호 확보와 서버 시작(모든 케이스) 때 정리한다. 보관 기록에 `intake` 가 없고 중단된 접수의 흔적이 있을 때만 옮긴다:
  잡은 쪽이 없는 `.intake.lock`(`basis: intake-lock`), 빈 디렉터리(`empty-dir`), `*.partial` 이 있음(`partial-copy`), 앞서 기록한 옮기기의 재시도(`retry`).
  옮긴 곳은 `aborted-intakes/EV-NNNN-<UTC>/`(파일 0444·디렉터리 0555, 지우지 않는다)이고 `intake-aborted` 사건(`reason: uncommitted-intake`, `basis`, `quarantine_path`, `had_record`, `files`)으로 번호를 소비한다.
  흔적이 없는 디렉터리(보관 기록과 고정점을 함께 잃은 커밋한 증거, 사람이 만든 디렉터리 등)는 커밋 여부를 알 수 없으므로 옮기지 않고 `record-without-intake` 로 남긴다 — 사람이 판단한다.
  다른 프로세스가 잠금을 잡은 디렉터리(`intake-in-progress`)와 잠금 자리가 일반 파일이 아닌 디렉터리는 건드리지 않는다. 보관 기록에 `intake` 가 있는데 잠금 파일이 남은 디렉터리(커밋 직후 끝남)는 커밋을 마저 한다(잠금 파일 삭제, 0555). 보관 기록이 깨졌으면 정리하지 않는다.
- **사람 증명 `write-blocker`**: 증명은 기록이다. 없거나 거부돼도 분석 도구는 동작하고, 증거 목록·보고서에 '증명 없음'이나 그 상태로 남는다.
  증거 목록·보고서는 보관 기록의 마지막 `attest` 사건이 가리키는 증명 레코드를 증명 저장소에서 찾아 지금 상태(`approved`/`denied`/`revoked`/`expired`, 믿을 수 없으면 `invalid`)를 보인다 — 레코드의 대상(증거 id·sha256·크기)과 케이스가 그 항목과 같을 때만.
  철회(`pweh attest --revoke <id>`)·만료를 보관 기록에 `attest` 사건으로 남기는 것은 `forensics_acquisition_attest` 를 다시 부를 때다.

## 6. 녹화 내용 경계와 권한

- 자동 허용 서버 pweh-fwtriage 는 입력이 그 케이스의 `forensics/` 안(링크를 풀어 판단)이거나 `forensics/` 를 품은 디렉터리(케이스 루트 등)면 거부한다.
- pweh-case 의 `case_import_file` 은 어느 케이스의 `forensics/` 에서도 파일을 가져오지 않는다(링크를 풀기 전 경로와 푼 경로를 모두 본다 — `forensics/` 자체가 링크여도 막는다. 카드 이미지·추출물을 `dumps/` 로 옮겨 펌웨어 도구가 읽게 하는 우회를 막는다).
  `case_hash_file`·`case_register_artifact` 도 어느 케이스의 `forensics/` 아래는 해시·등록하지 않는다(파일은 경로와 실제로 연 fd 의 경로를 모두 본다). pweh-sigrok 의 입력 파일도 어느 케이스의 `forensics/` 아래면 거부한다.
- 이 경계는 위 서버들만 막는다. 에이전트의 파일 도구나 REA(`open_binary`·`read_bytes`)는 `forensics/` 를 읽을 수 있으므로, 전용 이미지 도구 외에 이미지 사본과 추출물을 직접 열지 않는 것은 에이전트 규칙이다. 정지 그림은 원본 EV의 선택자를 사용하고 반환된 정규화 미리보기만 본다.
  전체 파일 목록 JSON 은 메타데이터라 추출할 `ref` 를 고를 때 읽어도 되지만, 요약·보고서에는 개수·범위·해시만 옮긴다.
- 증거 입구는 부모 디렉터리를 고정하고 하드링크를 거부한다. 다른 서버의 경로 가드와 같은 계정 경합의 남은 범위는 §8을 본다.
- `.claude/settings.json`: 조회 전용 도구 `forensics_partitions`, `forensics_image_check`와 로컬 쓰기가 있는 명시적 예외 `forensics_job_status`·`forensics_jobs`·`forensics_image_hints`·`forensics_scan_secrets`·`forensics_sd_ioc_scan`·`forensics_media_inventory`·`forensics_media_candidates`·`forensics_sqlite_inventory`·`forensics_android_artifacts`·`forensics_timeline`은 `allow`,
  쓰는 도구 `forensics_intake_start`, `forensics_verify_start`, `forensics_acquisition_attest`, `forensics_evidence_list`, `forensics_fs_list`, `forensics_extract`, `forensics_extract_media_candidate`, `forensics_job_cancel` 은 `ask` 다
  (Claude Code 에서는 bypass 모드에서도 묻는다). 클라이언트 권한은 보조 장치이고, 증거를 지키는 것은 보관 기록·지문·경계다.

## 7. 오류 코드

| 코드 | 상황 | 대처 |
|---|---|---|
| `authorization_required` | 케이스에 소유/허가 증명이 없다 | 사용자에게 확인받고 `case_set_authorization` |
| `validation_failed` | 인자 오류, 받지 않는 입력(원시 디스크·장치·FIFO·빈 파일·E01·NUL·케이스/상태 폴더 안·예약 이름, 4 MiB 를 넘는 이미징 로그), 여유 공간 부족, 이미지 해석 실패. 해석 실패의 사유는 `data.reason`: `unsupported_fs`, `beyond_image`(파티션 시작이 이미지 끝 너머 — 잘린 이미지), `not_found`(없는 파티션), `bad_argument`(지원 파티션이 여럿 — `partition` 필요), `bad_ref`, `refs_unverifiable`(추출: 확인 순회가 잘려 검증된 ref 가 하나도 없고 `paths` 도 없음), `budget_exceeded`(`data.limit`), `internal_error`, `malformed` … | 메시지와 `hint` 를 따른다. 이미지 문제면 사람에게 다시 이미징을 요청한다 |
| `not_found` | 없는 증거 id, 선택한 범위에 없는 job id | `forensics_evidence_list`·`forensics_jobs(case_id=...)`로 확인한다 |
| `integrity_failed` | 사본·접수 기록이 보관 기록의 접수 때와 다르거나(빠른 지문·재해시·접수 기록 대조), 무결성 실패로 표시됐거나, EV 디렉터리가 지워졌거나, 커밋하지 못한 디렉터리. 접수 job 에서는 복사 중 원본이 바뀜 | 그 사본은 더 쓰지 않는다. 원본 이미지에서 다시 접수한다(새 EV 번호) |
| `custody_broken` | 보관 기록이나 고정점 대조가 깨졌다(`forensics/` 가 링크인 경우 포함) | 고치지 말고 사람에게 보고한다. 서버는 깨진 기록에 덧붙이지 않는다 |
| `path_outside_base` | 서버가 쓰려는 `forensics/` 아래 디렉터리(`images/`·`analysis/`·`recovered/`·`aborted-intakes/`)가 링크이거나 디렉터리가 아니다, 새 추출 디렉터리에 서버가 만들지 않은 이름이 생겼다. (내용 도구가 여는 EV 디렉터리가 링크면 `integrity_failed`, 사유 `unsafe-path`) | 아무것도 따라가 쓰지 않았다(추출 디렉터리는 지웠다). 사람이 `forensics/` 를 확인한다 |
| `busy` | 같은 원본의 접수, 같은 증거의 검증·추출이 이미 실행 중이다 | `forensics_job_status` 로 기다리거나 취소한다 |
| `lock_timeout`, `unsafe_file` | 보관 기록·번호 확보 잠금을 30초 안에 얻지 못했다 / 번호 확보 잠금 파일(`images/.claim.lock`) 자리에 일반 파일이 아닌 것(링크·FIFO)이 있거나, 보관 기록 잠금 파일이 읽은 뒤 덧붙이기 전에 바뀌었거나, 접수 중 사본이 확인한 뒤 바뀌었다(접수는 되돌린다). 보관 기록 잠금 파일(`.custody.lock`)이 처음부터 일반 파일이 아니면 읽을 때 `custody_broken` 이다 | 다시 시도하고, 계속되면 사람이 다른 프로세스·`forensics/` 를 확인한다 |

job 의 실패는 `forensics_job_status` 의 `error` 에 있다(예상하지 못한 예외는 `internal_error`).

## 8. 한계 (반드시 읽을 것)

알려진 한계의 전체 목록과 정확한 조건은 [`docs/safety.md`](../../docs/safety.md) §3.6 에 있다. 여기에는 요약만 둔다.

- 지원 범위: MBR/EBR·GPT·superfloppy, FAT12/16/32·exFAT와 논리 TAR/ZIP, 선택 SQLite·앱 기록 및 파일·앱 타임라인. ext4·NTFS·E01, 카빙(DHAV·XM·MPEG-PS·MP4·JPEG), CCTV 녹화 인덱스·이름 규칙과 그 타임라인, 카드 전체 비밀값 자동 탐색·녹화 암호화 판정·카드 내용의 침해 판정,
  외부 도구(TSK·PhotoRec·ewf-tools·ffprobe) 교차 확인은 아직 없다(설계 §4·§5.2). 삭제 파일 복구는 디렉터리 항목이 남은 파일만 다룬다.
- 삭제한 FAT 파일은 보통 FAT 체인이 지워져 단편화 여부를 알 수 없다(Windows 는 FAT32 에서 시작 클러스터의 상위 16비트도 지운다). 후보(`contiguous`·`skip-allocated`·`skip-claimed`·`fat-chain`)마다 신뢰도와 설명이 매니페스트에 남지만 결과는 추정이다.
  `skip-allocated` 류 후보가 훑기 상한에서 멈추면 `status: "incomplete"`·`complete=false` 일 뿐 그 사유는 따로 없다. 미리 할당한 녹화 파일(링 버퍼)은 삭제 항목 복구로 아무것도 나오지 않을 수 있다.
- 호스트 오염 흔적은 정황이다. 지원하는 파티션이 없으면 결과가 비어 있을 뿐 흔적이 없다는 뜻이 아니다.
- 보관 기록·고정점·출처 원장에는 비밀 키가 없다. 같은 OS 계정이 보관 기록과 고정점을 함께 일관되게 다시 쓰면 감지하지 못한다. 0444·0555 권한은 실수를 막을 뿐 같은 계정은 되돌릴 수 있다.
  고정점은 케이스 id 로만 묶이므로 지운 케이스와 같은 id 로 새 케이스를 만들면 처음부터 `custody_broken` 이다(새 id 를 쓴다).
- 증거는 기본적으로 케이스로 복사한다. 큰 카드는 그만큼 디스크를 쓴다. 제자리 참조는 `storage="reference"`와 설정된 읽기 전용 마운트 입구를 사용한다(위 참조 모드 계약).
- 요약(docs/safety.md §3.6 의 항목들):
  - 무결성: 빠른 지문은 inode·ctime 을 보지 않고 verify 는 그때의 바이트만 증명한다. 마지막 고정점이 '기록 중'으로 남은 동안에는 보관 기록 마지막 줄을 지워도 드러나지 않는다.
    보관 기록과 고정점을 함께 잃으면 증거 목록은 '보관 기록 정상(항목 0개)' 옆에 `record-without-intake` 줄을 보인다 — 사람이 그 줄을 알아차려야 한다. 정리(reconcile)에도 드문 모서리 경우가 있다(두 겹의 사고, 다른 서버가 되돌리는 중인 접수).
    같은 계정이 `images/` 를 링크로 바꾸면 증거 목록의 다시 대조가 커밋한 EV 마다(이미 무결성 실패인 것 빼고) 무결성 실패(`unsafe-path`)를 남긴다(되돌리지 않는다 — 원본에서 다시 접수).
  - 같은 계정 프로세스: 증거 입구의 부모 디렉터리 고정·하드링크 거부, 출처 기록의 같은 fd 읽기, 출력의 커밋 전 신원 확인을 적용한다. pweh-fwtriage·pweh-sigrok의 경로 재열기,
    마지막 확인 뒤의 변경, 파일을 복사해 출처를 숨기는 행위, 쉼 없는 덧붙이기로 보관 기록 읽기를 굶기는 한계는 남는다. 세부 범위는 safety.md §3.6을 본다.
  - 해석: 일부러 엄격한 검증(FAT 속성 0x40·0x80, 하위 디렉터리의 볼륨 레이블, LFN 이상, exFAT 필드)은 fsck 가 받는 디렉터리도 `unvalidated_dirs`(살아 있으면 `dir_unvalidated`)로 뺀다.
    FAT12/16/32의 역방향 FAT·시작 클러스터 색인 검사가 불완전하면 unknown/partial을 표시한다. 지워졌거나 검증하지 못한 항목은 완전 탐지를 보장하지 않는다. 아주 큰 exFAT 루트는 열 때와 순회 때 두 번 읽어 작은 `max_seconds` 로는 0개를 나열하고 `time` 으로 잘릴 수 있다.
    잘린 이미지·파티션 표보다 큰 파일 시스템·손상된 살아 있는 디렉터리는 사유(§3.1)로 보고하고 읽을 수 있는 범위의 끝을 넘는 살아 있는 파일은 `complete=false`·`bytes_beyond_image` 로 짧게 추출한다 — 삭제된 디렉터리는 최선 노력이다.
  - 운영: 동기 도구는 요청 취소를 엔진·직렬화·커밋 직전에서 확인하고 작업 스레드가 fd와 커밋 전 출력을 정리한다. OS 호출 자체를 강제 중단하지는 못한다. 목록 JSON은 최대 256 MiB이며 초과하면 `output_limit`로 실패한다.
    강제 종료(SIGKILL) 뒤에는 job 조회·목록에 `case_id`를 지정해 저장 기록을 확인한다. 소유 서버 종료가 확실한 활성 기록만 failed로 정리하고, 옛 owner 없는 기록 등은 상태를 보존하며 unknown으로 표시한다. 접수 커밋·증거 무결성 여부는 이 정리로 판정하지 않는다.

## 9. 테스트

```
.venv/bin/pytest -q tests/servers/test_forensics_mcp.py tests/servers/test_forensics_fs.py tests/core/test_evidence.py tests/core/test_safeio.py tests/fs \
    tests/servers/test_fwtriage_forensics_guard.py tests/servers/test_case_mcp.py
```

- `tests/servers/test_forensics_mcp.py`: 접수(해시·사본·보관 기록·출처 원장), 입력 거부·견고성, 원본 fd 만 복사, 복사 중 원본 변경과 되돌리기, 이미징 로그 대조, 전체 재해시의 변조 감지와 늦은 취소,
  접수 기록 위조, 보관 기록 변조, FIFO 로 바꿔치기해도 멈추지 않음, 커밋하지 못한 접수 정리와 번호 소비, 종료 때 되돌리기, 커밋 뒤 취소·보조 기록 실패, 쓰기 방지 장치 증명(철회·만료의 지금 상태),
  증거 목록(다시 대조, 파생 산출물 대조, `status_label`), 보고서 §8.1.
- `tests/servers/test_forensics_fs.py`: 합성 카드 이미지로 파티션·오염 흔적·목록·삭제 파일 추출·exFAT 잔여, 내용 도구의 지문 확인, 호출 예산(같은 구간, 볼륨마다 엔진 예산 하나, 경로 글자 수, 작은 `max_seconds`, 해석하지 못한 볼륨),
  추출(ref 확인·중복, 디스크 이름과 모호성, 바이트 상한, 계획의 `limit_reason`, 취소와 커밋 지점, 실패한 추출, 링크를 따르지 않음), 깊이·슬롯 한도, 잘린 이미지, 검증하지 못한 살아 있는/삭제된 디렉터리.
- `tests/core/test_evidence.py`: 해시 체인·고정점(마지막 줄 수정·잘라 내기·밖에서 덧붙임, '기록 중' 줄), 커밋 뒤 예외 없음, 읽기와 덧붙이기 경합, FIFO·링크 거부, 이미징 로그 형식, 입력 검사, 빠른 지문, 경로 판정,
  번호 확보·정리(중단 지점마다, 커밋 마무리, 보관 기록을 잃은 증거, 일반 파일이 아닌 잠금, 옮기기 재시도), `status_label`, 요약 스키마의 상태 어휘.
- `tests/core/test_safeio.py`: 일반 파일만 열기(바꿔치기, 중간 디렉터리 한계, 쓰는 쪽 없는 FIFO), 크기 상한, fd 해시·복사, 디렉터리 사슬, 링크를 따르지 않는 쓰기, 잠금, 디렉터리 지우기.
- `tests/fs/`: 엔진 단위 시험. `tests/fs/builders.py` 가 MBR/EBR·GPT·FAT·exFAT 이미지를 순수 파이썬으로 만들고(리눅스처럼 지운 파일 포함) `tests/fs/hostile.py` 가 조작 이미지를 만든다.
  `tests/fs/test_hardening.py`·`tests/fs/test_limits_lookup.py` 는 검증·예산·한도·경로 찾기, `tests/fs/test_incomplete_dirs.py` 는 끝까지 읽지 못한 디렉터리의 보고를 본다.
  `tests/fs/test_fuzz.py` 는 메타데이터를 고정 시드로 변조해 예외가 새지 않고 시간 상한 안에 끝나는지 본다. `tests/fs/test_external.py` 는 mkfs.fat·sgdisk 가 있을 때만 도는 `@pytest.mark.external` 교차 확인이다.
- `tests/servers/test_fwtriage_forensics_guard.py`: pweh-fwtriage 가 `forensics/` 와 그 링크·상위 디렉터리를 거부하는지. `case_import_file`·`case_hash_file`·`case_register_artifact` 의 거부는 `tests/servers/test_case_mcp.py` 에 있다.

## Android 논리 증거

TAR/ZIP 목록·멤버 해시·선택 추출과 선택한 SQLite DB의 구조·앱 기록·타임라인을 지원한다. `forensics_sqlite_inventory`, `forensics_android_artifacts`, `forensics_timeline`은 같은 EV 무결성 입구에서 읽고 JSON을 보관 기록에 결속한다. 폰 내용은 전용 도구 응답으로 반환하며 원본·추출 DB를 직접 열지 않는다. 영상·음성은 여전히 사람이 확인한다. 복구 후보·미검사 범위·시각 기준을 보존한다.

접수 기본은 copy, reference는 `forensics.reference_roots`의 실제 읽기 전용 마운트만 허용한다. 참조 EV가 있는 evidence-list는 전체 재해시 job 완료 후 확인서를 만든다. [계약](../../docs/architecture.md) §6.8, [설계·제한](../../docs/design/android-analysis.md), [Skill](../../skills/android-forensics/SKILL.md)을 따른다.

## 선택 텍스트 비밀값 검사 계약

`forensics_scan_secrets`로 EV 자체 또는 목록에서 고른 텍스트 하나를 검사한다. `ref`/`path`는 하나만, 직접 EV는 둘 다 생략한다. 결과는 `report.status`(`ok`/`partial`/`unsupported`), 마스킹된 후보·케이스 솔트 지문, 실제 검사/미검사 범위와 `analysis`의 저장 경로·해시·보관 기록 번호다. UTF-8(BOM 허용)4 MiB, 한 줄16 KiB,100,000줄,200후보, 최대45초로 제한하며 긴 줄·한도·복구 불확실성을 부분 결과로 남긴다. XOR는 사용자가 선택한 `xor_key=144` 보기만 지원한다.

원문·파일명·키 이름·계정·URL·변환 파일은 새 결과에 남기지 않는다. 영상음성·바이너리 해독, 전체 카드 자동 검색, 비밀번호 사용/로그인은 없다. 후보0건도 안전을 뜻하지 않는다. 커밋 전 취소는 출력 없이, 커밋 후는 결과를 보존한다. 입력 EV와 출력 파일 신원을 함께 확인해 `secrets-scan` 사건으로 결속하고 증거 목록에서 대조한다. 상세 계약은 [architecture.md §6.8](../../docs/architecture.md#68-pweh-forensics-선택), 한계는 [safety.md §3.6](../../docs/safety.md#36-sd-카드-증거의-알려진-한계-pweh-forensics)다.

## 펌웨어·카드 보고서 이름 대조

`forensics_sd_ioc_scan`은 등록된 `fw_sd_surface` 전체 결과와 보관 기록에 결속된 FAT/exFAT 전체 목록 JSON만 비교한다. 원시 카드 내용은 읽지 않고, 이름 일치를 실행·침해 증명으로 해석하지 않는다. 같은 케이스도 동일 장치·버전의 증명은 아니다. ref·펌웨어 배열 index로 후보를 연결하고 삭제·이름 손상·중복·목록/스캐너 잘림을 함께 기록한다.

입력 각각16 MiB와 JSON 복잡도 상한을 파싱 전에 적용한다. 큰 목록은 오류이며 앞부분만 읽어 성공시키지 않는다. 정확한 상한·대소문자/별칭 제한·두 입력의 권위와 결속은 [architecture.md §6.8](../../docs/architecture.md#68-pweh-forensics-선택), 남은 경합 한계는 [safety.md §3.6](../../docs/safety.md#36-sd-카드-증거의-알려진-한계-pweh-forensics)다. 결과는 `sd-ioc-scan` 사건과 증거 목록에서 검증한다.

## 선택 미디어 구조 관찰

`forensics_media_inventory`는 완전한 선택 파일 하나(최대64 MiB)의 ISO-BMFF 상자 경계·고정 brand와 허용 계층의 `mvhd/mdhd` 시간 단위·길이 선언, `pssh` 구조를 관찰한다. EV 자체 또는 FAT/exFAT·TAR/ZIP의 ref/path 하나를 고른다. timing은 version 0/1의20/32bytes prefix만 읽으며 creation/modification는 zero/nonzero/unread로만 반환한다. 선언 길이는 실제 재생 길이가 아니고 PSSH 존재는 암호화 증명이 아니다. 원시 시각·SystemID/KID/data·자유 메타데이터를 반환하지 않는다.

schema는 `pweh.media-inventory/v1`을 유지한다. 새 `mp4-quicktime-declarations-v1`은 `declarations`가 필수이며, 옛 `mp4-quicktime-box-v1` 보고서는 section 없이 기존 형식으로 계속 검증한다. 옛 결과에 새 검사를 소급하지 않는다. 상자 경계 완료·선언 필드 완료·brand 인식·삭제/복구 출처 불확실성을 구분한다. 선언이 미지원·불완전하면 framing이 complete여도 전체 partial이며, 선언0개는 보호 신호 부재나 평문 확인이 아니다.

상자4096·깊이8·범위8193·JSON1 MiB·공통45초 상한을 유지하고 미검사 범위를 남긴다. 영상·음성·재생·녹화 시각·암호화·표준 적합성은 검증하지 않는다. `source/params`, `media-inventory` 사건과 요약6필드, 후보·prefix 추출·타임라인 입력은 바뀌지 않는다. 정확 필드와 범위는 [선언 관찰](../../docs/references/media-declarations.md), 보관 계약은 [architecture.md §6.8](../../docs/architecture.md#68-pweh-forensics-선택), 한계는 [safety.md §3.6](../../docs/safety.md#36-sd-카드-증거의-알려진-한계-pweh-forensics)이다. 원시 이미지 전체 카빙·녹화 인덱스 타임라인·벤더 포맷 검증과 암호화 판정은 별도 미구현 범위다.

## 선택 미디어 후보 탐색

`forensics_media_candidates`는 완전한 선택 파일 또는 명시 EV 구간(최대64 MiB)에서 ftyp와 연속 최상위 상자 prefix 후보를 기록한다. 선택 기준 offset/검증 길이·고정 brand·검색/검사/목록/관계 완료도를 반환한다. payload 내부 오탐 가능성이 있으며 size0·선택 끝을 원본 파일 끝으로 해석하지 않는다. 후보 위치는 선택 bytes 기준이다. `offset/length`를 함께 지정한 EV 구간에서만 `source.offset+candidate.offset`이 이미지 내 위치이며, 후보 검색은 파일을 추출하지 않는다. 구간 인자는 ref/path/partition과 혼용할 수 없고 method=auto만 허용한다. source의 구간 위치·크기·SHA와 별도 profile을 보존하며 [명시 구간 계약](../../docs/references/media-evidence-range.md)을 따른다.

후보 최대128개, input64 MiB, JSON1 MiB, 공통 시간45초다. 후보의 confidence는 possible이고 원본 녹화·재생·암호화·물리 카빙 검증은 false다. 삭제/복구 출처의 불확실성은 후보0건에도 partial로 남긴다. `media-candidates` 보관 사건과 증거 목록 derived로 결과를 확인한다. 상세 계약은 [architecture.md §6.8](../../docs/architecture.md#68-pweh-forensics-선택), 요약은 `media_candidate_results`다.

## 저장된 미디어 후보 추출

`forensics_extract_media_candidate`는 `analysis_path`와 정수 `candidate_index`로 저장된 후보 하나를 고른다. 같은 EV의 보관 기록·보고서 해시·원래 선택 바이트 전체를 대조한 뒤 고정 이름 `candidate-000.bin`과 엄격한 매니페스트만 `forensics/recovered/media-prefix-NNN/`에 쓴다. 기존 forensics job 조회·취소와 같은 EV 추출 배타 잠금을 사용한다.

보고서1 MiB·완전히 읽은 선택 파일/구간64 MiB·매니페스트64 KiB·출력1개·worker 공통45초가 고정 한도다. 기존 `extract` 사건에 `method="media_candidate_prefix"`로 기록하며 요약에는 `recovered`를 쓴다. 원래 상태/검사 범위와 새 불확실성을 보존한다. 내용 반환·원본 녹화 경계·재생 검증은 하지 않는다. 입력 결속, 커밋 전후 취소·정리와 `derived.recorded`의 의미는 [전체 계약](../../docs/references/media-prefix-extract.md)을 따른다.

## 저장 목록의 자동 비밀값 검사

`forensics_scan_secrets_from_list`는 같은 EV의 `list` 사건과 전체 해시에 결속된 FAT/exFAT JSON에서 자동 선정한다. 저장 목록 안의 지원 볼륨을 대상으로 하며, 원래 목록의 파티션 제한·잘림·실패 볼륨을 보존한다. 각 파일을 다시 찾아 metadata와 완전한 복구 계획을 확인하고 기존 UTF-8 scanner를 적용한다.

선정 완료·eligible 검사 완료·목록 완료는 별개이며 whole_card_examined는 항상false다. 정책 제외와 보류·미시도·읽기 실패를 구분하고 파일명·시각·키·본문을 새 결과에 복사하지 않는다. `secret_survey_results`에 참조·검사 수·미읽기 수를 기록한다. 정확한 입출력·상한·최종 검증·요약 매핑은 [저장 목록 비밀값 검사 계약](../../docs/references/secrets-survey.md)을 따른다.
