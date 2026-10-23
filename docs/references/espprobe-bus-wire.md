# ESP 버스의 내부 wire와 두 패스 수집

이 경로는 [버스 C 코어](espprobe-bus-core.md)의 제한 읽기를 고정 frame과 주입된 합성
transport로 연결한다. 실제 C의 HELLO와 버스 코어를 Python collector와 함께 시험한다.
공개 MCP의 여섯 sim 도구, hello 이미지의 CMake·release·기능 광고와 credit0은 유지한다.
운영 포트·GPIO adapter·Case/원장·공개 덤프 job은 이 내부 경로에 포함되지 않는다.

## 고정 wire와 C 수명

기존 v1 LE header16B·COBS·CRC, payload4096B·wire4134B 한도를 사용한다.
내부 SPI_PROBE(0x10)는 요청4B/응답19B, READ_BEGIN(0x11)은 요청15B,
DONE(0x12)은 event13B다. caller가 임의 opcode·버스 주소 폭·송신 데이터를 넣지 않는다.
DATA에는 USB generation·pass·absolute offset·길이와 읽은 bytes를 넣고,
SPI 한 청크는256B, I²C는32B 이하로 제한한다.

REQ는 opcode별 cache가 아닌 전역 high-water와 cache4개를 사용한다. 같은 전체 canonical
요청만 이전 RSP를 반환하며 버스를 다시 읽지 않는다. 다른 payload의 같은 seq와 cache 밖의
과거 seq는 거부한다. 정상 해제 뒤에는 정확한 cleanup tombstone 요청에 원 ACK를 재전달하며
버스·abort를 다시 실행하지 않는다. 하나의 wire generation에서 BEGIN은 한 번만 시작한다.
기존 typed bus API의 DONE 뒤 새 BEGIN 가능 여부는 별개다.

하트비트는 새 seq에만 liveness·credit0..4를 반영한다. deliver callback은 frame 직렬화만
수행하며 버스 API로 재진입하지 않는다. C step이 성공하고 직후 guard까지 실제 DONE을
확정한 때만 DONE을 내보낸다. DATA 전달 뒤 guard 실패를 성공으로 바꾸지 않는다.
시계는 HAL guard가 갱신한 실제 bus 시각을 사용하고 이전 feed 시각으로 되돌리지 않는다.

wire context는 새 저장소에서 init하고 하나의 caller가 bus를 독점한다. 동적 할당이나
실제 firmware dispatch 등록은 없다. malformed frame·시간·전압·HB 실패 뒤 재동기화·
재시도·자동 재선택을 하지 않는다. 전기적 해제 시간은 합성 시험으로 증명하지 않는다.

## Python 값과 수집기

`pweh.espprobe_bus_wire`는 binding·읽기 계획의 불변 값과 고정 builder/parser만 제공한다.
binding은 HELLO 결과의 session·USB generation·hello/HB seq·1000ms HB·boot_id16B를
받으며 자체 HELLO를 만들어 입장을 대신하지 않는다. 계획은 SPI 또는 I²C의 offset·length와
두 패스다. raw frame 인자나 자동 JSON 공개 경로는 없다.

`pweh.espprobe_bus_collect.BusCollector`는 read/write/close 메서드가 있는 transport와
서로 다른 빈 일반 파일 FD 두 개를 필수로 받는다. 생성자는 외부 I/O를 하지 않는다.
run은 한 번만 호출하고 실행 중 transport/FD는 caller가 닫거나 교체하지 않는다.
수집기가 FD·경로를 새로 열거나 복제·닫기·삭제·rename·artifact 등록을 하지 않는다.

두 FD는 읽기/쓰기 가능·단일 링크·비 O_APPEND이고 길이는 각각0이어야 한다. 수집 범위는
1..64MiB, u32 offset과 끝 범위이며 장치 용량 검증은 C 코어의 역할이다. 동일 inode·bool FD·
닫힌 FD는 첫 TX 전에 거부한다. 이 검사는 타인의 다른 파일 핸들이 없음을 증명하지 않는다.

run 입구에서 작업 end=min(caller deadline, now+600초)를 한 번 정한다. clock 역행과
비유한값을 거부하고 transport 호출은 정한 deadline 안에 돌아오는 주입 계약을 따른다.
REQ와 HB는 각각 하나만 outstanding이며 grant는1이다. HB는1000ms의1/3 이내 주기로
진행한다. 응답 대기에는 credit0 HB를 허용하지만 새 BEGIN/probe는 보내지 않는다.

StreamDecoder 오류가 있으면 같은 feed에서 반환한 정상처럼 보이는 frame도 버린다.
bare delimiter·다른 generation·예상 밖 응답·중복·늦은 DATA/DONE도 terminal이다.
한 feed는 최대3개 frame과 partial suffix 하나만 허용한다. 부분 송신은 같은 frame의
남은 suffix만 보내고 실패 뒤 새로운 TX를 이어가지 않는다.

## 수집·완료와 해시

DATA는 BEGIN seq·pass0 다음 pass1·정확 offset·청크 길이를 검사한다. gap/overlap/중복과
패스 순서 위반을 거부한다. received는 검사한 byte 수, stored는 실제 pwrite 성공 byte 수다.
partial write만큼 stored와 stream SHA를 갱신하며 다음 grant는 쓰기를 마친 뒤 보낸다.
각 쓰기의 전후에 FD identity·mode·nlink·size와 seal을 확인한다.

정상 순서는 DONE→새 seq BYE→정확 ACK→transport close 확인→두 FD 전체 SHA다.
DONE만으로 완료를 선언하거나 stream SHA를 최종 파일 해시로 대신하지 않는다.
최종 해시는 원래 end/cancel 안에서64KiB씩 같은 FD를 읽고 전후 seal·마지막 기한을 확인한다.
두 완전 파일이 달라도 완료된 수집일 수 있으며 이때 match=false다. 미완료면 match는 null이다.
pass별 최종 같은 FD 검증까지 끝난 SHA만 보존하고, 누적 stream SHA만 있는 pass는
sha256=null로 남긴다. 실제 칩·전기적 정확성·출처 원장을 이 receipt로 증명하지 않는다.

정리는 별도5초를 한 번 사용하고 동기화가 유지된 stream에서만 ABORT를 한 번 시도한다.
최초 실패 이유를 보존한다. transport close가 미확정이면 caller가 같은 owner를 보존하고
명시 close로 물리 종료만 재확인한다. 이 재확인은 wire 송신·해시·receipt 변경을 하지 않는다.
호스트 종료 확인은 RF/핀/버스의 물리 상태 증명이 아니다.

## 검증 범위

독립 순수 wire 시험, FD/실패 수명 시험과 실제 C fixture를 함께 사용한다. C fixture는
실제 common HELLO→bind/claim에서 시작하고 미리 SPI probe를 수행하지 않는다. 두 패스의
합성 byte 패턴과 전역 cache·HB·tombstone·DATA 뒤 실패·DONE/BYE 종료를 대조한다.
시험용 process/pipe는 fixture에만 있으며 production 기본 transport가 아니다.
실제 포트·배선·전압·flash는 [계측기 설계](../design/esp32-instrument.md)의 별도 사실을 필요로 한다.
