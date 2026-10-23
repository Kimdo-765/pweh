# 저장 PNG 영역 비교

`pweh-play`의 `vision_template_match`는 같은 소유·허가 케이스에 등록된 두 image-hints 보고서에서
PNG를 하나씩 선택하고 같은 크기의 영역을 비교한다. 고정 profile은
`stored-png-roi-rgb-mae-v1`이다. 원본 화면 취득이나 게임 상태의 판정은 포함하지 않는다.

## 입력 선택과 호출

1. 일반 케이스의 정지 이미지를 `case_image_hints(..., preview=true)`로 분석한다.
   저장 PNG가 이미 있으면 다시 분석할 필요가 없다.
2. `case_get(include_artifacts=true)`의 아티팩트 색인에서 반환된 `analysis.path/sha256/size`와
   일치하고 kind=`image-hints`, producer=`pweh-case`인 유일한 보고서 ID를 선택한다.
   현재 `case_image_hints`의 `analysis`에는 artifact_id가 없으므로 ID를 순번으로 만들지 않는다.
3. 각 보고서의 `artifacts.previews`에서 실제 존재하는 index0 또는1을 고른다.
   ROI는 **저장 PNG**의 픽셀 좌표다. PNG가 축소됐을 수 있으므로 원본·EXIF·crop·OCR 좌표를
   그대로 사용하거나 자동 변환하지 않는다.
4. 두 ROI의 폭과 높이를 같게 지정하고 허용할 평균 절대차를 명시한다.

```text
vision_template_match(
  case_id=<소유·허가된 케이스>,
  reference_artifact_id=<등록 보고서 ID>, reference_preview_index=0,
  reference_roi=[0,0,32,24],
  candidate_artifact_id=<등록 보고서 ID>, candidate_preview_index=0,
  candidate_roi=[8,4,32,24], max_mean_error=2
)
```

여덟 인자는 모두 필수다. ROI는 원 JSON 배열 `[x,y,width,height]`이며 exact 정수4개다.
x/y는0..1600, 폭/높이는1..1600이며 각 PNG 안에 들어가야 한다. index는 정수0/1,
max_mean_error는 정수0..255다. bool·실수·숫자 문자열·문자열로 포장한 배열·추가 인자는 거부한다.
같은 보고서나 PNG를 양쪽에 선택할 수 있고, 결과에는 실제 같은 ID와 해시가 그대로 나타난다.

입력 보고서는 최대8MiB이고 `analysis/image-hints-NNN.json`의 등록된 일반 케이스 결과여야 한다.
보고서의 status는 ok 또는partial을 허용하지만 선택 PNG는 완전한 파일이어야 한다.
개별 PNG는 최대1MiB·1600×1600의 정규화 RGB이며 overview/crop 역할을 받는다.
파일 이름·보고서 preview 참조·색인 ID/크기/SHA/producer를 대조한다. 누락·중복 등록은 거부한다.
forensics/emu 입력이나 다른 생산자의 결과를 이 경로로 연결하지 않는다.

## 비교와 반환

각 RGB 채널쌍의 절대차를 더한 정수 `sum_abs`, 채널쌍 수 `samples=width*height*3`으로 계산한다.
판정은 `sum_abs <= max_mean_error*samples`다. `mean_abs_error=sum_abs/samples`는 표시용 값이며
확률이나 신뢰도가 아니다. threshold0은 정확한 동일 픽셀을 요구하고,255는 모든 유효 RGB 비교를
통과시킬 수 있다. resize·alignment·sliding·색상 보정이나 OCR은 수행하지 않는다.

반환의 정확한 키는 `ok`, `report`, `artifact_id`, `analysis_path`, `sha256`, `size`, `warnings`다.
`matched=false`도 정상 분석 성공이다. report는 `pweh.template-match/v1`이며 다음 내용을 담는다.

- 양쪽 보고서의 등록 ID·크기·SHA와 선택 PNG의 index·등록 ID·크기·SHA·dimension·role.
- 요청 ROI·threshold 및 `sum_abs/samples/mean_abs_error/matched`.
- 항상 false인 `frame_freshness_verified/game_semantics_verified/action_generated`와 고정 한계6개.

원본 경로·이미지·OCR·EXIF·개별 픽셀·시각은 비교 보고서에 넣지 않는다. 등록 해시와 producer
표시는 해당 바이트의 결속이며 실제 화면 취득이나 신선도의 암호학적 증명은 아니다.
`schema_get('template-match')`와 `schema_get('template-analysis')`로 두 스키마를 확인할 수 있다.

## 저장·시간·정리

케이스 확인부터 입력 선택·별도 PNG worker·최종 해시·등록까지 하나의 고정5초 예산을 사용한다.
worker는 CRC·청크·완결성·RGB·dimension을 검사하고, 제한된 자식 프로세스에서 PNG만 해독한다.
기존 image-hints 분석의 기본 해독·OCR 경로와 응답 상한은 유지된다.

입력의 같은 FD를 유지하고 부모·이름·읽기 전용 모드·링크 수·seal·색인·전체SHA를 등록 직전에
다시 대조한다. `analysis/template-match-NNN.json`을 최대64KiB·0444로 저장하고 kind=`other`,
producer=`pweh-play`, extra.type=`template-match`로 등록한다. 입력 파일은 수정하지 않는다.
취소·시간 만료에는 미완료 비교를 성공으로 저장하지 않는다. 등록 전 실패는 이번에 만든 동일
inode만 정리한다. 실제 등록 뒤 늦은 취소·감사/close 실패에는 파일과 등록 receipt를 보존하며
`post_commit_callback_failed` 또는 `output_close_unconfirmed` 경고가 있을 수 있다.

## 결과 요약

이 도구 전용 단계에는 별도 Skill 파일이 없다. 성공 반환의 실제 값을 아래 구조에 대입하여
`case_record_step(skill='image-template-analysis', step='summary', status='success', data=...)`로 기록한다.
matched 참/거짓 모두 success다. 예시 ID·해시를 실제 결과 대신 기록하지 않는다.

```json
{
  "schema": "pweh.template-analysis/v1",
  "results": [
    {
      "artifact_id": "A-0005",
      "analysis_path": "analysis/template-match-001.json",
      "report_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "matched": false
    }
  ],
  "frame_freshness_verified": false,
  "game_semantics_verified": false,
  "action_generated": false
}
```

results는 실제 비교 보고서1..128개만 담는다. `case_get_step_results`와 최종 보고서는 이 선택
단계를 수행한 케이스에만 표시한다. numeric-analysis·image-hints 요약이나 play-run으로 대체하지 않는다.

## 시험 범위

합성 RGB·ROI 정수 경계·오염 PNG·worker 응답·취소·최대 크기, 같은 FD와 색인의 교체·등록 실패를
검사한다. 실제 두 MCP Client에서 `case_image_hints`→색인 ID→비교→요약→보고서를 연결한다.
실기 화면·프레임 신선도·게임 의미·자동 입력을 검증했다는 뜻은 아니다.
