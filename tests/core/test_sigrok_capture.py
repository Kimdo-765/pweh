"""실행·장치 조회 없이 고정 capture 입력/argv/승인 투영을 확인한다."""

from dataclasses import FrozenInstanceError, replace

import pytest

from pweh.errors import ValidationFailed
from pweh.sigrok_capture import (
    CaptureChannel, CaptureCommand, MAX_RATE, MAX_SAMPLES, PROFILE_ID, PROFILE_SHA256,
    from_argv_tail, normalize_channels,
)


def command(**changes):
    values = dict(profile_id=PROFILE_ID, conn="COM31", samplerate_hz=3_000_000,
                  samples=12, channels=normalize_channels(["0=RX", "1"]))
    return CaptureCommand(**(values | changes))


@pytest.mark.parametrize("path", [r"C:\synthetic\capture.sr", r"\\wsl.localhost\Synthetic\tmp\out\capture.sr",
                                 "D:/space here/capture.sr"])
def test_exact_command_roundtrip_and_output_identity(path):
    c = command(conn="com31")
    tail = c.argv_tail(path)
    assert tail == ("--driver=ols:conn=COM31", "--dont-scan", "--config=samplerate=3000000",
                    "--channels=0=RX,1", "--samples=12", "--output-format=srzip", f"--output-file={path}")
    parsed = from_argv_tail(tail)
    assert parsed.command == c and parsed.output_windows == path
    assert c.expected_reported_rate_hz == 3_030_303
    with pytest.raises(FrozenInstanceError):
        c.samples = 16
    projection = c.approval_identity()
    assert projection["profile_sha256"] == PROFILE_SHA256 and len(PROFILE_SHA256) == 64
    projection["channels"][0]["name"] = "changed"
    assert c.channels[0].name == "RX"
    for other in (replace(c, conn="COM32"), replace(c, samples=16), replace(c, samplerate_hz=1_000_000)):
        assert other.approval_identity() != c.approval_identity()


@pytest.mark.parametrize("raw,expected", [([0], ((0, "0"),)), ("0-2", ((0, "0"), (1, "1"), (2, "2"))),
    (["1=CLK", " 0=DATA "], ((0, "DATA"), (1, "CLK"))), (tuple(range(32)), tuple((i, str(i)) for i in range(32)))])
def test_normalize_contiguous_channels(raw, expected):
    assert tuple((ch.index, ch.name) for ch in normalize_channels(raw)) == expected


@pytest.mark.parametrize("value", [None, [], (), "", "0,", "0,,1", "1", "0,2", "0-32", "0-999999999",
    "0-0", "2-0", "00", "０", "D0", "0=1", "0=x\nsecret", "0=secret/path", "0=a-b", "0=" + "a" * 33,
    "0=RX,1=RX", "0,0=RX", "0-2,2", "0=RX=MORE", "0, 1\nsecret", [True], [1.0], [None],
    "0" * 2049, ["0"] * 33, [" " * 100000], [10**10000], "0,1-999"])
def test_invalid_channels_are_bounded_and_do_not_echo_input(value):
    with pytest.raises(ValidationFailed) as exc:
        normalize_channels(value)
    assert exc.value.code == "sigrok_capture_invalid"
    assert "secret" not in str(exc.value)


@pytest.mark.parametrize("changes", [
    {"profile_id": "other"}, {"profile_id": None}, {"conn": "COM0"}, {"conn": "COM01"},
    {"conn": "COM4097"}, {"conn": "COM31:serialcomm=1/8n1"}, {"conn": True},
    {"samplerate_hz": 9}, {"samplerate_hz": MAX_RATE + 1}, {"samplerate_hz": True},
    {"samplerate_hz": 1.0}, {"samplerate_hz": "1000"}, {"samples": 0}, {"samples": 5},
    {"samples": True}, {"samples": MAX_SAMPLES + 4}, {"samples": 12.0},
    {"channels": None}, {"channels": []}, {"channels": (CaptureChannel(1, "1"),)},
    {"channels": (CaptureChannel(0, "X"), CaptureChannel(1, "X"))},
])
def test_closed_command_inputs(changes):
    with pytest.raises(ValidationFailed, match="sigrok_capture_invalid"):
        command(**changes)


@pytest.mark.parametrize("rate,expected", [(10, 10), (100_000_000, 100_000_000), (99_999_999, 100_000_000),
                                         (3_000_000, 3_030_303), (200_000, 200_000)])
def test_source_integer_divider_boundaries(rate, expected):
    assert command(samplerate_hz=rate).expected_reported_rate_hz == expected
    command(samplerate_hz=rate, samples=MAX_SAMPLES)


@pytest.mark.parametrize("path", [None, "capture.sr", "/tmp/capture.sr", "C:capture.sr", r"C:\out\other.sr",
    r"C:\out\CAPTURE.SR", r"C:\out\capture.sr:stream", r"C:\out\..\capture.sr",
    r"\\server\share\capture.sr", r"\\.\COM31", "C:\\secret\n\\capture.sr", "X" * 100000])
def test_output_is_fixed_basename_validated_windows_path(path):
    with pytest.raises(ValidationFailed) as exc:
        command().argv_tail(path)
    assert exc.value.code == "sigrok_capture_invalid" and "secret" not in str(exc.value)


@pytest.mark.parametrize("index,value", [(0, "--driver=ols:conn=com31"), (0, "--driver=demo"),
    (1, "--scan"), (2, "--config=samplerate=3m"), (2, "--config=samplerate=03000000"),
    (3, "--channels=0-1"), (3, "--channels=1,0=RX"), (3, "--channels=0=RX,1=1"),
    (4, "--samples=012"), (4, "--time=1"), (5, "--output-format=vcd"),
    (6, "--output-file=C:\\out\\other.sr")])
def test_reverse_parser_rejects_aliases_reordering_and_extra_options(index, value):
    tail = list(command().argv_tail(r"C:\out\capture.sr"))
    tail[index] = value
    with pytest.raises(ValidationFailed):
        from_argv_tail(tuple(tail))


def test_reverse_parser_is_tuple_exact_and_does_not_claim_directory_ownership():
    tail = command().argv_tail(r"C:\one\capture.sr")
    for bad in (None, list(tail), tail + ("--scan",), tail[:-1], (True,) + tail[1:]):
        with pytest.raises(ValidationFailed):
            from_argv_tail(bad)
    other = from_argv_tail(command().argv_tail(r"C:\two\capture.sr"))
    assert other.command == command()
    assert other.output_windows != from_argv_tail(tail).output_windows
