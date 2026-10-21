"""emu-mcp 한도 (코드 상수 — 새 ``safety.*`` 설정 키를 만들지 않는다, 결정 D13).

모든 코드는 이 값을 **쓸 때마다** ``limits.NAME`` 으로 읽는다(모듈 import 때 복사하지 않는다). 그래서 시험이
``monkeypatch.setattr(limits, "RAW_LOG_CAP", 4096)`` 처럼 바꿀 수 있다.
"""

from __future__ import annotations

MiB = 1 << 20
GiB = 1 << 30

#: 케이스당 동시 세션 (케이스 잠금 emu/.lock 안에서 디스크의 meta.json — 살아 있는 주인 — 을 센다: 서버 프로세스가 여럿이어도 맞다)
MAX_SESSIONS_PER_CASE = 2
#: 이 서버 프로세스의 동시 세션 (ESP 게스트 하나가 호스트 코어 1–2 개를 쓴다)
MAX_SESSIONS_PER_PROCESS = 4

#: 게스트 UART 원시 바이트 파일(console.bin) 상한 — 넘으면 계속 읽어 버리고 raw_dropped_bytes 만 센다
RAW_LOG_CAP = 32 * MiB
#: 에뮬레이터 stderr 파일(emulator.stderr.log) 상한 — 서버가 파이프에서 읽어 쓰므로 서버가 자른다
STDERR_LOG_CAP = 1 * MiB
#: 마스킹한 기록 파일(transcript.masked.txt) 상한
TRANSCRIPT_CAP = 16 * MiB

#: emu_stop·한도 정지: SIGTERM 뒤 SIGKILL 까지 기다리는 시간(초)
STOP_GRACE_S = 3.0
#: shim → 에뮬레이터 exec 확인(상태 파이프 EOF)을 기다리는 시간(초)
EXEC_CONFIRM_TIMEOUT_S = 5.0
#: exec 뒤 이 시간 안에 rc 1·2 로 끝나면 emu_start 가 emu_spawn_failed 를 낸다(그 뒤면 세션이 stopped_by=config-error 로 끝난다).
#: 첫 출력 바이트가 오거나 프로세스가 끝나면 기다림을 일찍 마친다.
START_SETTLE_S = 0.5
#: 열린 줄(줄 끝 없는 프롬프트)을 pending_line 으로 보이기 전 조용해야 하는 시간(초)
OPEN_QUIET_S = 0.2
#: emu_read 가 새 바이트를 받은 뒤 더 모으는 시간(초)
READ_SETTLE_S = 0.15
#: emu_write 한 번의 최대 바이트
WRITE_MAX = 4096
#: emu_write 의 비차단 쓰기 + poll 합계 시간(초) — 넘으면 일부만 쓰고 돌려준다
WRITE_TIMEOUT_S = 2.0
#: 감독 스레드 합류(emu_stop) 최대 대기(초)
SUPERVISOR_JOIN_S = 10.0
#: 서버 종료(SIGTERM) 때 정리 스레드 합류 최대 대기(초)
SHUTDOWN_JOIN_S = 30.0

#: 주소 공간 한도: QEMU 는 -accel tcg,tb-size=64 와 짝(VmPeak 412–545 MB), pweh_avr_run VmPeak 약 4 MB
RLIMIT_AS_QEMU = 1 * GiB
RLIMIT_AS_AVR = 64 * MiB
#: 자식이 직접 쓰는 파일 크기 한도: QEMU 는 -snapshot 덮어쓰기 파일(TMPDIR)뿐, AVR 은 쓰는 파일이 없다
RLIMIT_FSIZE_QEMU = 64 * MiB
RLIMIT_FSIZE_AVR = 1 * MiB
RLIMIT_NOFILE = 256
RLIMIT_CORE = 0
#: emu_status 의 버전·머신 조회(shim 아래) 제한 시간(초)
PROBE_TIMEOUT_S = 10.0

#: emu_start 인자 범위
TIMEOUT_S_MIN, TIMEOUT_S_MAX, TIMEOUT_S_DEFAULT = 10, 3600, 600
IDLE_TIMEOUT_S_MIN, IDLE_TIMEOUT_S_MAX, IDLE_TIMEOUT_S_DEFAULT = 30, 1800, 300
#: emu_read 인자 범위
READ_MAX_CHARS_MIN, READ_MAX_CHARS_MAX = 256, 65536
READ_WAIT_MAX_S = 50.0
UNTIL_MAX_LITERALS = 8
UNTIL_MAX_CHARS = 64

#: 입력 읽기 상한
ESP_FLASH_MAX = 16 * MiB
AVR_HEX_MAX = 2 * MiB

#: LineTranscript 메모리 상한 (pweh.console 기본값과 같게 명시)
TRANSCRIPT_MAX_RECORDS = 20000
TRANSCRIPT_MAX_TEXT_BYTES = 4 * MiB
TRANSCRIPT_MAX_LINE_BYTES = 16 * 1024

#: stderr_tail 렌더 상한(글자)
STDERR_TAIL_CHARS = 2000
#: 메모리에 남겨 두는 끝난 세션 수 (그보다 오래된 것은 emu_read(session_id, case_id=…) 가 디스크 기록으로 돌려준다)
ENDED_SESSIONS_KEPT = 32
#: 진단 힌트: 부트로더 'Loaded app'/'entry 0x' 뒤 이만큼 조용하면 USB 콘솔 힌트
HINT_SILENCE_AFTER_BOOT_S = 10.0
#: PSRAM 실패 뒤 다른 psram 으로 다시 시작하는 최대 횟수 (Skill 절차 — 힌트 문구에 쓴다)
PSRAM_RESTARTS_MAX = 2


def rlimit_cpu(timeout_s: int, vcpus: int) -> tuple[int, int]:
    """RLIMIT_CPU (soft, hard): soft = ⌈timeout_s × vcpus × 1.1⌉ + 5, hard = soft + 5 (바쁜 게스트의 보조 상한).

    정수로 계산한다(⌈t·v·11/10⌉): 부동소수 1.1 은 정확하지 않아 곱이 정수여야 할 때도 1 이 더 올라갈 수 있다(예: 100 × 1.1 = 110.00000000000001 → 111)."""
    soft = -(-int(timeout_s) * int(vcpus) * 11 // 10) + 5
    return soft, soft + 5


def as_dict() -> dict[str, object]:
    """emu_status·emu_sessions 의 ``limits`` (지금 값)."""
    return {
        "max_sessions_per_case": MAX_SESSIONS_PER_CASE,
        "max_sessions_per_process": MAX_SESSIONS_PER_PROCESS,
        "timeout_s": {"min": TIMEOUT_S_MIN, "max": TIMEOUT_S_MAX, "default": TIMEOUT_S_DEFAULT},
        "idle_timeout_s": {"min": IDLE_TIMEOUT_S_MIN, "max": IDLE_TIMEOUT_S_MAX, "default": IDLE_TIMEOUT_S_DEFAULT},
        "raw_log_cap": RAW_LOG_CAP,
        "stderr_log_cap": STDERR_LOG_CAP,
        "transcript_cap": TRANSCRIPT_CAP,
        "rlimit_as": {"esp-qemu": RLIMIT_AS_QEMU, "avr-simavr": RLIMIT_AS_AVR},
        "rlimit_fsize": {"esp-qemu": RLIMIT_FSIZE_QEMU, "avr-simavr": RLIMIT_FSIZE_AVR},
        "rlimit_nofile": RLIMIT_NOFILE,
        "rlimit_core": RLIMIT_CORE,
        "rlimit_cpu": "ceil(timeout_s × vcpus × 1.1) + 5 (hard = soft + 5)",
        "write_max": WRITE_MAX,
        "write_timeout_s": WRITE_TIMEOUT_S,
        "stop_grace_s": STOP_GRACE_S,
        "read_max_chars": {"min": READ_MAX_CHARS_MIN, "max": READ_MAX_CHARS_MAX},
        "read_wait_max_s": READ_WAIT_MAX_S,
        "until": {"max_literals": UNTIL_MAX_LITERALS, "max_chars": UNTIL_MAX_CHARS},
        "esp_flash_max": ESP_FLASH_MAX,
        "avr_hex_max": AVR_HEX_MAX,
    }
