"""고정 RGB24 bytes의 제한된 조립·최신 대기 frame·호스트 수신 시각 회계.

시계·source·파일·thread를 호출하지 않는다. caller가 모든 호출을 직렬화하며,
frame의 수신 시각은 실제 화면의 취득 시각이나 신선도 증명이 아니다.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import PwehError

PIXEL_FORMAT = "rgb24"
MAX_DIMENSION = 1600
MAX_FRAMES = 16
MAX_BYTES = 16 << 20
MAX_READ_BYTES = 64 << 10
MAX_RUNTIME_NS = 5_000_000_000
MAX_TIME_NS = (1 << 63) - 1

_FINISH_REASONS = (
    "eof", "frame_limit", "byte_limit", "time_limit", "cancelled", "source_failed", "clock_regression",
)
_ERROR_CODES = (
    "frame_input_invalid", "frame_source_failed", "frame_clock_regression", "frame_cleanup_incomplete",
)


class FrameError(PwehError):
    """픽셀·source·임의 예외 문구를 포함하지 않는 닫힌 오류."""

    def __init__(self, code: str = "frame_input_invalid") -> None:
        fixed = code if type(code) is str and code in _ERROR_CODES else "frame_input_invalid"
        super().__init__("RGB24 프레임 상태를 확인할 수 없습니다.", code=fixed)


@dataclass(frozen=True, slots=True, repr=False)
class RawFrame:
    """완전 frame 하나. pixels는 내부 소비자에게만 명시적으로 전달한다."""

    index: int
    receipt_ns: int
    pixels: bytes


def _integer(value: object, lower: int, upper: int) -> bool:
    return type(value) is int and lower <= value <= upper


class RawFrameQueue:
    """최신 pending 하나와 미완성 buffer만 가진 순수 queue. 자체 동시성 보장은 없다."""

    __slots__ = (
        "_width", "_height", "_frame_bytes", "_deadline_ns", "_last_sample_ns", "_buffer", "_pending",
        "_bytes_accepted", "_frames_completed", "_frames_taken", "_frames_dropped", "_last_receipt_ns",
        "_stop_reason",
    )

    def __init__(self, width: int, height: int, *, started_ns: int, deadline_ns: int) -> None:
        if (not _integer(width, 1, MAX_DIMENSION) or not _integer(height, 1, MAX_DIMENSION) or
                not _integer(started_ns, 0, MAX_TIME_NS) or not _integer(deadline_ns, 0, MAX_TIME_NS) or
                not started_ns < deadline_ns <= min(MAX_TIME_NS, started_ns + MAX_RUNTIME_NS)):
            raise FrameError()
        self._width = width
        self._height = height
        self._frame_bytes = width * height * 3
        self._deadline_ns = deadline_ns
        self._last_sample_ns = started_ns
        self._buffer = bytearray()
        self._pending: RawFrame | None = None
        self._bytes_accepted = 0
        self._frames_completed = 0
        self._frames_taken = 0
        self._frames_dropped = 0
        self._last_receipt_ns: int | None = None
        self._stop_reason: str | None = None

    @property
    def read_size(self) -> int:
        """한 번에 수용할 수 있는 bytes. 완료 상한 뒤 EOF 확인용 read는 하지 않는다."""
        if self._stop_reason is not None:
            return 0
        tail = self._bytes_accepted - self._frames_completed * self._frame_bytes
        return min(MAX_READ_BYTES, MAX_BYTES - self._bytes_accepted,
                   (MAX_FRAMES - self._frames_completed) * self._frame_bytes - tail)

    def _stop(self, reason: str) -> None:
        if self._stop_reason is not None:
            return
        tail = self._bytes_accepted - self._frames_completed * self._frame_bytes
        self._stop_reason = "partial_eof" if reason == "eof" and tail else reason
        # 관찰한 tail 회계는 accepted/completed에 남기고 원시 미완성 buffer는 버린다.
        self._buffer.clear()

    def _reject(self, code: str = "frame_input_invalid") -> None:
        self._stop("clock_regression" if code == "frame_clock_regression" else "source_failed")
        raise FrameError(code)

    def _sample(self, value: int) -> None:
        if not _integer(value, 0, MAX_TIME_NS):
            self._reject()
        if value < self._last_sample_ns:
            self._reject("frame_clock_regression")
        if self._stop_reason is None:
            self._last_sample_ns = value

    def feed(self, data: bytes, *, receipt_ns: int) -> None:
        """입력 전체를 검증한 뒤 조립한다. 빈 bytes 자체는 EOF가 아니다."""
        if self._stop_reason is not None:
            raise FrameError()
        if type(data) is not bytes or len(data) > self.read_size:
            self._reject()
        self._sample(receipt_ns)
        if receipt_ns >= self._deadline_ns:
            self._stop("time_limit")
            return
        self._bytes_accepted += len(data)
        position = 0
        while position < len(data):
            amount = min(self._frame_bytes - len(self._buffer), len(data) - position)
            self._buffer.extend(data[position:position + amount])
            position += amount
            if len(self._buffer) == self._frame_bytes:
                current = RawFrame(self._frames_completed, receipt_ns, bytes(self._buffer))
                self._buffer.clear()
                if self._pending is not None:
                    self._frames_dropped += 1
                self._pending = current
                self._frames_completed += 1
                self._last_receipt_ns = receipt_ns
        if self._frames_completed == MAX_FRAMES:
            self._stop("frame_limit")
        elif self._bytes_accepted == MAX_BYTES:
            self._stop("byte_limit")

    def take(self) -> RawFrame | None:
        """pending을 한 번만 넘긴다. terminal이어도 이미 완성한 frame은 소비할 수 있다."""
        current = self._pending
        if current is not None:
            self._pending = None
            self._frames_taken += 1
        return current

    def finish(self, reason: str, *, at_ns: int) -> None:
        """첫 종료 의미를 보존한다. 정리 표본이 deadline 뒤여도 end를 연장하지 않는다."""
        if type(reason) is not str or reason not in _FINISH_REASONS:
            self._reject()
        self._sample(at_ns)
        self._stop(reason)

    def discard_pending(self) -> None:
        """미소비 완전 frame을 dropped로 한 번 옮긴다. tail/첫 종료는 보존한다."""
        if self._pending is not None:
            self._pending = None
            self._frames_dropped += 1

    def snapshot(self) -> dict:
        """원문 pixels와 source 사실이 없는 정확 15필드 복사본을 반환한다."""
        return {
            "pixel_format": PIXEL_FORMAT,
            "width": self._width,
            "height": self._height,
            "frame_bytes": self._frame_bytes,
            "bytes_accepted": self._bytes_accepted,
            "frames_completed": self._frames_completed,
            "frames_taken": self._frames_taken,
            "frames_dropped": self._frames_dropped,
            "pending_frames": int(self._pending is not None),
            "tail_bytes": self._bytes_accepted - self._frames_completed * self._frame_bytes,
            "last_index": self._frames_completed - 1 if self._frames_completed else None,
            "last_receipt_ns": self._last_receipt_ns,
            "stop_reason": self._stop_reason,
            "eof_observed": self._stop_reason in ("eof", "partial_eof"),
            "framing_complete": self._stop_reason == "eof",
        }
