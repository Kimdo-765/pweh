# 고정 RGB24 프레임 queue와 내부 owner

이 내부 경로는 고정 RGB24 bytes를 frame으로 조립하고, 필수로 주입한 source의 수신·정지 수명을
합성으로 검증한다. 공개 도구와 실제 영상 source·PNG 연결은 포함하지 않는다.

## 범위와 입력

내부 queue는 명시한 폭·높이의 packed RGB24 bytes를 완전한 frame으로 조립한다.
pixel은 R/G/B 각1바이트이며 위에서 아래·왼쪽에서 오른쪽 순서다.
stride, 행 padding, alpha, planar 배열, 자동 색 변환과 geometry 변경은 받지 않는다.
`frame_bytes = width * height * 3`이며 폭·높이는 각각 정확한 정수1..1600이다.
bool이나 숫자 문자열을 geometry로 변환하지 않는다. 최대 한 frame은7,680,000바이트다.

owner는 필수로 주입한 메모리 fake source만 소비한다. 실제 포트·장치·프로세스·ffmpeg·
DirectShow·URL source를 자동으로 만들지 않는다. 공개 화면 도구와 캡처 기능의 완료가 아니다.
기존 숫자 관찰·image-hints·PNG template API 및 파일 출처 검증은 그대로 유지한다.
frame을 PNG로 게시하거나 OCR·template·숫자 관찰·입력 제어에 자동 전달하지 않는다.

## 한도와 순수 queue

누적 완료 frame은 최대16개, 수용 bytes와 늦은 read bytes의 합은 최대16MiB다.
한 read는 최대64KiB이며 남은 byte/frame 예산에 맞춰 더 작아진다.
최대 geometry에서는 두 frame 뒤1,417,216바이트의 tail을 수용하면16MiB에 도달한다.
상한을 채우려고 부분 frame을 padding하거나 cap 뒤 EOF 확인용 read를 추가하지 않는다.

`RawFrameQueue`는 시계·source·파일·thread를 호출하지 않는 순수 상태 객체다.
`read_size`로 남은 입력 크기를 알리고, `feed(bytes, receipt_ns=...)`로 bytes를 수용한다.
정확한 bytes만 받으며 요청 크기 초과를 잘라서 일부 수용하지 않는다.
`take()`는 최신 pending frame 하나를 반환하고 제거한다. 반복 호출은 같은 frame을 반환하지 않는다.
`finish(reason, at_ns=...)`는 첫 종료를 기록하고, `discard_pending()`은 미소비 frame을 폐기한다.
owner가 모든 queue 변경·snapshot을 같은 condition으로 직렬화한다.

반환 `RawFrame`은 불변의 `index`, `receipt_ns`, `pixels` 세 필드다.
pixels는 정확한 frame 크기의 immutable bytes이며 기본 repr에는 표시하지 않는다.
pending은 최대 하나다. 새 frame이 기존 pending을 교체하면 dropped가1 증가한다.
조립 중 buffer는 frame보다 작게 유지한다. 소비자가 take 뒤 보관한 bytes와 임시 사본·전체 RSS는
이 소유 buffer 한도의 보장에 포함하지 않는다. 검정이나 반복 pixels도 정상 bytes로 취급한다.

## 수신 시각과 처리 기한

producer worker가 첫 단조 시각을 받고 caller deadline과 시작+5초 중 이른 end를 한 번 고정한다.
caller deadline이 이미 지났으면 read 없이 시간 종료와 source 정리로 간다.
주입 clock은 같은 worker만 호출한다. take·snapshot·close 소비자가 시계를 별도로 샘플링하지 않는다.
시각은 정확한 정수 ns이고 같거나 증가해야 한다. 역행·clock 오류는 고정 종료로 처리한다.
한 feed에서 완성된 여러 frame은 같은 receipt를 유지하며 epsilon을 더하지 않는다.
분할 frame의 receipt는 마지막 bytes를 받은 feed의 시각이다. 순서는 frame index로 표현한다.
host receipt는 실제 노출·취득·렌더링 시각이나 화면 freshness를 증명하지 않는다.

## source callback과 late bytes

fake source는 `read(max_bytes, timeout_s=...)`, `cancel_read()`, `close()`, `closed`를 제공한다.
read의 None은 해당 poll에 출력 없음, 빈 bytes는 EOF다. 일반 bytes는 길이를 확인한 뒤 처리한다.
read timeout은50ms와 남은 처리시간 중 작은 값이며 한 producer·한 in-flight read만 허용한다.
clock·cancel·source callback은 condition 밖에서 실행한다. source.close는 worker만 한 번 시도한다.
잘못된 타입·요청 초과 반환·callback 예외는 고정 오류이며 원문·source repr를 결과에 넣지 않는다.

read 뒤에도 clock과 cancel을 확인한다. 정지 후 도착한 정상 bytes는 queue에 넣지 않고
owner의 `late_read_bytes`에 한 번만 센다. 이 값은 최대64KiB다.
요청 초과·비bytes 반환은 수용/late 계수에 넣지 않는다. 늦은 EOF도 정상 EOF로 승격하지 않는다.
cancel은 latch와 비차단 cancel_read 대기 해제 요청이며, source 종료 확인을 대신하지 않는다.
정지 뒤에는 추가 read나 새 frame 게시가 없다.

## 회계와 완료 의미

항상 `bytes_accepted = frames_completed * frame_bytes + tail_bytes`다.
또한 `frames_completed = frames_taken + frames_dropped + pending_frames`다.
pending은0 또는1이며 tail은 마지막 수용 prefix의 미완성 길이다. 정리 후에도 tail 관찰값은 남는다.
마지막 index/receipt는 마지막 완성 frame의 값이며 take나 drop 뒤에도 보존한다.

EOF와 tail0이면 `eof`, tail이 남으면 `partial_eof`다. 빈 스트림 EOF도 framing만 완료다.
frame/byte/time 상한·취소·오류는 EOF나 framing 완료로 간주하지 않는다.
최초 stop reason은 이후 cleanup이나 반복 finish가 바꾸지 않는다.
정상 EOF 뒤 pending은 한 번 take할 수 있고, 명시 close가 먼저 폐기하면 dropped에 반영한다.
snapshot에는 고정 geometry·수치·완료 bool만 있으며 pixels·base64·원시 예외는 없다.

## close 확인과 남는 한계

close는 closing/cancel을 latch하고 pending을 폐기한 뒤 cancel_read로 대기 해제를 요청한다.
실제 worker join은 한 번 최대0.1초 기다리며, self-join하지 않는다.
반환은 `confirmed`, `snapshot`, `error` 세 키다. 실제 join과 `source.closed is True`가 모두
확인돼야 confirmed다. source가 닫혔다는 주장은 truthy 값이나 cancel 요청만으로 인정하지 않는다.
미확정이면 `frame_cleanup_incomplete`와 같은 owner를 보존하고 이후 close에서 종료를 재확인한다.
다른 thread의 강제 source.close·재연결·새 cleanup worker는 만들지 않는다.

source가 비차단 cancel_read나 bounded read/close 계약을 어기면 전체 종료5초나 close0.1초를
보장하지 않는다. source_closed는 fake host 객체의 확인이며 자식 프로세스·장치·RF 종료 증명이 아니다.
이 단위의 종료 범위는 합성 RGB24 조립·수신 시각·drop/EOF·정지 수명이다.
실제 영상 source·물리 취득·HDMI/HDCP·게임 의미·인식률·자동 플레이는 계속 미검증이다.
