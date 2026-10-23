"""합성 CLI bytes의 경로·배너·고정 명령·opaque 전송 경계를 검증한다."""
from __future__ import annotations

import json
import traceback

import pytest

from pweh import flipper_cli as F

CASE = "synthetic-cli"
ROOT = "/ext/pweh/" + CASE
PATH = ROOT + "/a file.raw"
HASH = F.COMMIT[:8]
PRIVATE = "SYNTHETIC_FLIPPER_PRIVATE"
BANNER = (b"\r\nWelcome to Flipper Zero Command Line Interface!\r\n"
          b"Firmware version: release 1.5.1 (" + HASH.encode()
          + b" built on 01-10-2025)\r\n" + F.PROMPT)
INFO = {
    "format.major": "3", "format.minor": "3", "hardware.model": "Flipper Zero",
    "hardware.target": "7", "firmware.version": "1.5.1", "firmware.commit.hash": HASH,
    "firmware.commit.dirty": "false", "hardware.uid": PRIVATE,
    "hardware.name": PRIVATE, "radio.ble.mac": PRIVATE,
}


def feed(cli, data, width=4096):
    result = bytearray()
    for pos in range(0, len(data), width):
        result.extend(cli.feed(data[pos:pos + width]))
    return bytes(result)


def body_info(values=None):
    return b"".join(k.encode().ljust(30) + b": " + v.encode() + b"\r\n"
                    for k, v in (INFO if values is None else values).items())


def answer(cli, kind, body, path=None, width=4096):
    command = cli.begin(kind, path)
    assert command.endswith(b"\r") and not command.endswith(b"\r\n")
    return feed(cli, command[:-1] + b"\r\n" + body + F.PROMPT, width)


def idle(cli, width=4096):
    assert answer(cli, "loader", b"No application is running\r\n", width=width) == b""
    assert cli.result == {"idle": True}


def ready(width=4096):
    cli = F.FlipperCli(CASE)
    assert feed(cli, BANNER, width) == b""
    idle(cli, width)
    assert answer(cli, "info", body_info(), width=width) == b""
    return cli


def failed(call, *, code=None, cli=None):
    with pytest.raises(F.FlipperCliError) as caught:
        call()
    exc = caught.value
    if code:
        assert exc.code == code
    assert exc.data == {}
    assert PRIVATE not in str(exc) + json.dumps(exc.to_dict()) + "".join(traceback.format_exception(exc))
    if cli is not None:
        assert cli.state == "terminal" and not cli.ready and cli.result is None
        with pytest.raises(F.FlipperCliError, match="flipper_terminal"):
            cli.begin("loader")
        with pytest.raises(F.FlipperCliError, match="flipper_terminal"):
            cli.feed(b"\r\n>: ")
    return exc


@pytest.mark.parametrize("path", [ROOT, ROOT + "/", ROOT + "/some dir", ROOT + "/a-b_c.12.raw"])
def test_paths_are_validated_without_rewriting(path):
    assert F.remote_path(CASE, path) == path


@pytest.mark.parametrize("suffix", ["", "/", "//a", "/a/", "/../x", "/./x", "/a//b",
                                      "/a\\b", '/a"b', "/a\rb", "/a\nb", "/a\tb", "/a\x00b",
                                      "/a\x7fb", "/한글", "/ a", "/a ", "/a;exit", "/$x", "/a:b",
                                      "/" + "a" * 255, "/" + "/".join("a" for _ in range(14))])
def test_invalid_file_path_is_fixed_error(suffix):
    failed(lambda: F.remote_path(CASE, ROOT + suffix, file=True), code="flipper_invalid_input")


@pytest.mark.parametrize("path", ["/ext/pweh/another/a", ROOT + "other/a", "//ext/pweh/" + CASE + "/a",
                                    ROOT + "/" + "a" * 254 + "/" + "b" * 254, None, b"x", 1, True])
def test_scope_and_exact_path_types(path):
    failed(lambda: F.remote_path(CASE, path), code="flipper_invalid_input")


@pytest.mark.parametrize("case", ["../x", "", "a/../b", "é", "a" * 81, True, None, b"case"])
def test_case_validation(case):
    failed(lambda: F.FlipperCli(case), code="flipper_invalid_input")
    failed(lambda: F.remote_path(case, ROOT), code="flipper_invalid_input")


@pytest.mark.parametrize("value", ["a", "a.bin", "a_b-c.7", "a" * 96])
def test_destination_accepts_only_host_basename(value):
    assert F.destination_name(value) == value


@pytest.mark.parametrize("value", [None, True, b"a", "", ".", "..", ".x", "../x", "a/b", "a\\b",
                                    "x.", " a", "a ", "a b", "한글", "a" * 97, "a\x00"])
def test_destination_rejects_invalid_names(value):
    failed(lambda: F.destination_name(value), code="flipper_invalid_input")


@pytest.mark.parametrize("width", [1, 2, 3, 4, 5, 7, 16, 31, 64, 512, 4096])
def test_handshake_and_info_every_chunk_width(width):
    cli = ready(width)
    assert cli.ready and cli.banner == {"version": "1.5.1", "commit_hash": HASH, "dirty": False}
    assert cli.result == {"model": "Flipper Zero", "hardware_target": 7,
                          "info_format": {"major": 3, "minor": 3},
                          "firmware": cli.banner, "profile_compatible": True,
                          "firmware_claim_verified": False}
    assert PRIVATE not in json.dumps(cli.result)
    result = cli.result
    result["firmware"]["version"] = "bad"
    assert cli.result["firmware"]["version"] == "1.5.1"


def test_no_command_before_complete_banner():
    for length in (0, 1, len(BANNER) - 1):
        cli = F.FlipperCli(CASE)
        cli.feed(BANNER[:length])
        failed(lambda: cli.begin("loader"), code="flipper_protocol_error", cli=cli)


@pytest.mark.parametrize("data,code", [
    (F.PROMPT, "flipper_protocol_error"),
    (b"U-Boot\r\n" + F.PROMPT, "flipper_handshake_failed"),
    (BANNER.replace(b"1.5.1", b"1.4.2"), "flipper_firmware_unsupported"),
    (BANNER.replace(HASH.encode(), b"deadbeef"), "flipper_firmware_unsupported"),
    (BANNER.replace(HASH.encode(), HASH.encode() + b"-dirty"), "flipper_firmware_unsupported"),
    (BANNER.replace(HASH.encode(), b"9e810d"), "flipper_firmware_unsupported"),
    (BANNER.replace(b"01-10-2025", b"2025-10-01"), "flipper_firmware_unsupported"),
    (BANNER + b"extra", "flipper_protocol_error"),
    (BANNER.replace(b"\r\n", b"\n", 1), "flipper_protocol_error"),
    (BANNER.replace(b"Welcome", b"\x1b]" + PRIVATE.encode() + b"\x07Welcome"), "flipper_handshake_failed"),
    (BANNER.replace(b"Welcome", b"\x1b[2JWelcome"), "flipper_handshake_failed"),
    (BANNER.replace(b"Welcome", b"\x1b[" + b"1" * 33 + b"mWelcome"), "flipper_handshake_failed"),
])
def test_bad_banner_and_firmware_never_enable_tx(data, code):
    cli = F.FlipperCli(CASE)
    failed(lambda: feed(cli, data), code=code, cli=cli)


def test_banner_sgr_only_and_count_limit():
    cli = F.FlipperCli(CASE)
    feed(cli, b"\x1b[38;2;255;130;0m" + BANNER.replace(b"Firmware", b"\x1b[0mFirmware"), 1)
    assert cli.ready
    cli = F.FlipperCli(CASE)
    failed(lambda: feed(cli, b"\x1b[m" * 65 + BANNER), code="flipper_limit", cli=cli)


def test_banner_total_limit():
    cli = F.FlipperCli(CASE)
    failed(lambda: feed(cli, b"a" * (F.MAX_BANNER_BYTES + 1)), code="flipper_limit", cli=cli)


@pytest.mark.parametrize("replace_key,replace_value", [
    ("format.major", "2"), ("format.minor", "4"), ("hardware.model", PRIVATE),
    ("hardware.target", "8"), ("firmware.version", "1.5.0"), ("firmware.commit.dirty", "true"),
    ("firmware.commit.hash", F.COMMIT[:7]), ("firmware.commit.hash", "deadbeef"),
])
def test_info_matches_banner_and_profile(replace_key, replace_value):
    cli = F.FlipperCli(CASE)
    feed(cli, BANNER)
    idle(cli)
    values = dict(INFO, **{replace_key: replace_value})
    failed(lambda: answer(cli, "info", body_info(values)), code="flipper_firmware_unsupported", cli=cli)


@pytest.mark.parametrize("badline,code", [
    (b"x: y\r\n", "flipper_protocol_error"),
    (b"hardware.uid".ljust(30) + b": " + PRIVATE.encode() + b"\r\n", "flipper_protocol_error"),
    (b"bad key".ljust(30) + b": x\r\n", "flipper_protocol_error"),
    (b"unknown".ljust(30) + b": " + b"a" * 513 + b"\r\n", "flipper_limit"),
    (b"unknown".ljust(30) + b": \x1b[0m\r\n", "flipper_protocol_error"),
])
def test_info_malformed_duplicate_or_unbounded_values(badline, code):
    cli = ready()
    idle(cli)
    failed(lambda: answer(cli, "info", body_info() + badline), code=code, cli=cli)


def test_info_key_limit():
    cli = ready()
    idle(cli)
    body = body_info() + b"".join(("x" + str(i)).encode().ljust(30) + b": v\r\n" for i in range(257))
    failed(lambda: answer(cli, "info", body), code="flipper_limit", cli=cli)


@pytest.mark.parametrize("body", [b'Application "' + PRIVATE.encode() + b'" is running\r\n',
                                  b"unknown\r\n", b"No application is running\r\nextra\r\n"])
def test_loader_busy_or_unknown_stops_all_commands(body):
    cli = ready()
    failed(lambda: answer(cli, "loader", body), code="flipper_app_busy", cli=cli)


def test_loader_permission_is_single_use_and_info_precedes_storage():
    cli = F.FlipperCli(CASE)
    feed(cli, BANNER)
    idle(cli)
    failed(lambda: cli.begin("list", ROOT), code="flipper_protocol_error", cli=cli)
    cli = ready()
    failed(lambda: cli.begin("info"), code="flipper_protocol_error", cli=cli)


@pytest.mark.parametrize("kind,path", [("help", None), ("read_chunks", PATH), ("exit", None),
                                       ("loader", PATH), ("info", PATH), (None, None)])
def test_fixed_command_set_only(kind, path):
    cli = ready()
    failed(lambda: cli.begin(kind, path), code="flipper_invalid_input", cli=cli)


def test_list_names_sizes_and_empty_are_closed():
    cli = ready()
    idle(cli)
    answer(cli, "list", b"\t[D] some dir\r\n\t[F] a file 123b 4294967295b\r\n", ROOT, width=1)
    assert cli.result == {"entries": [{"name": "some dir", "type": "directory", "size": None},
                                      {"name": "a file 123b", "type": "file", "size": 0xffffffff}],
                          "count": 2, "listing_complete": True, "filesystem_completeness_verified": False}
    idle(cli)
    answer(cli, "list", b"\tEmpty\r\n", ROOT + "/")
    assert cli.result["entries"] == [] and cli.result["count"] == 0


@pytest.mark.parametrize("body,code", [
    (b"", "flipper_protocol_error"), (b"\t[F] a 01b\r\n", "flipper_protocol_error"),
    (b"\t[F] a -1b\r\n", "flipper_protocol_error"), (b"\t[F] a 4294967296b\r\n", "flipper_protocol_error"),
    (b"\t[D] ../a\r\n", "flipper_protocol_error"), (b"\t[D] .\r\n", "flipper_protocol_error"),
    (b"\t[F] a 1b\r\n\t[D] a\r\n", "flipper_protocol_error"),
    (b"\tEmpty\r\n\t[D] a\r\n", "flipper_protocol_error"),
    (b"Storage error: " + PRIVATE.encode() + b"\r\n", "flipper_storage_error"),
    (b"\t[D] " + b"a" * 255 + b"\r\n", "flipper_protocol_error"),
])
def test_list_failure_returns_no_prefix(body, code):
    cli = ready()
    idle(cli)
    failed(lambda: answer(cli, "list", body, ROOT), code=code, cli=cli)


def test_list_entry_limit():
    cli = ready()
    idle(cli)
    failed(lambda: answer(cli, "list", b"".join(b"\t[D] a%d\r\n" % i for i in range(257)), ROOT),
           code="flipper_limit", cli=cli)


@pytest.mark.parametrize("width", [1, 2, 3, 4, 5, 7, 17, 128, 4096])
@pytest.mark.parametrize("data", [b"", b"x", b"\r\n>: \r\nSize: 0\r\nStorage error: hidden\x00\x03\x1b[0m\xff"])
def test_binary_is_opaque_and_trailer_is_exact(width, data):
    cli = ready(width)
    idle(cli, width)
    got = answer(cli, "read", b"Size: %d\r\n" % len(data) + data + b"\r\n", PATH, width)
    assert got == data
    assert cli.result == {"declared_size": len(data), "received_size": len(data), "complete": True}
    assert cli.declared_size == cli.received_size == len(data)
    idle(cli, width)
    answer(cli, "md5", b"0123456789abcdef0123456789abcdef\r\n", PATH, width)
    assert cli.result == {"md5": "0123456789abcdef0123456789abcdef"}


def test_binary_size_read_request_and_max_file_stream():
    cli = ready()
    idle(cli)
    cmd = cli.begin("read", PATH)
    assert cli.feed(cmd[:-1] + b"\r\nSize: 1048576\r\n") == b""
    payload = bytes(range(256)) * 4096
    out = bytearray()
    for pos in range(0, len(payload), 4096):
        assert cli.state == "binary" and cli.read_size == min(4096, len(payload) - pos)
        out.extend(cli.feed(payload[pos:pos + cli.read_size]))
        assert len(cli._buffer) == 0
    assert out == payload
    cli.feed(b"\r\n" + F.PROMPT)
    assert cli.result["complete"] is True


def test_binary_remaining_read_cap():
    cli = ready()
    idle(cli)
    cmd = cli.begin("read", PATH)
    cli.feed(cmd[:-1] + b"\r\nSize: 3\r\n")
    assert cli.read_size == 3
    assert cli.feed(b"ab") == b"ab"
    assert cli.read_size == 1
    assert cli.feed(b"c") == b"c"
    assert cli.state == "trailer"


@pytest.mark.parametrize("size,code", [(b"1048577", "flipper_limit"), (b"4294967295", "flipper_limit"),
                                       (b"4294967296", "flipper_protocol_error"),
                                       (b"01", "flipper_protocol_error"), (b"-1", "flipper_protocol_error"),
                                       (b"1 ", "flipper_protocol_error"), (b"1.0", "flipper_protocol_error"),
                                       (b"9" * 100, "flipper_protocol_error")])
def test_size_bound_before_binary(size, code):
    cli = ready()
    idle(cli)
    cmd = cli.begin("read", PATH)
    failed(lambda: cli.feed(cmd[:-1] + b"\r\nSize: " + size + b"\r\n"), code=code, cli=cli)
    assert cli.received_size == 0


@pytest.mark.parametrize("tail", [b"\r\n>: ", b"extra\r\n\r\n>: ", b"\r\n\r\n>! ",
                                  b"\r\n\r\n>: extra"])
def test_binary_trailer_mismatch_is_terminal(tail):
    cli = ready()
    idle(cli)
    cmd = cli.begin("read", PATH)
    failed(lambda: cli.feed(cmd[:-1] + b"\r\nSize: 1\r\nx" + tail),
           code="flipper_protocol_error", cli=cli)


@pytest.mark.parametrize("digest", [b"a" * 31, b"A" * 32, b"g" * 32, b"a" * 33,
                                    b"a" * 32 + b"\r\nextra", b"Storage error: " + PRIVATE.encode()])
def test_md5_requires_one_exact_lower_hex_line(digest):
    cli = ready()
    idle(cli)
    code = "flipper_storage_error" if digest.startswith(b"Storage error:") else "flipper_protocol_error"
    failed(lambda: answer(cli, "md5", digest + b"\r\n", PATH), code=code, cli=cli)


@pytest.mark.parametrize("phase", ["passive", "ready", "echo", "size", "binary", "trailer", "text"])
def test_abort_and_eof_never_reenable_commands(phase):
    for action in ("abort", "eof"):
        cli = F.FlipperCli(CASE) if phase == "passive" else ready()
        if phase in ("echo", "size", "binary", "trailer"):
            idle(cli)
            cmd = cli.begin("read", PATH)
            if phase != "echo":
                cli.feed(cmd[:-1] + b"\r\n")
            if phase in ("binary", "trailer"):
                cli.feed(b"Size: 1\r\n")
            if phase == "trailer":
                cli.feed(b"x")
        elif phase == "text":
            cmd = cli.begin("loader")
            cli.feed(cmd[:-1] + b"\r\n")
        assert cli.state == phase
        if action == "abort":
            cli.abort(PRIVATE)
            assert cli.terminal_reason == "flipper_terminal"
        else:
            with pytest.raises(F.FlipperCliError):
                cli.eof()
        assert cli.state == "terminal" and not cli._buffer
        failed(lambda: cli.begin("loader"), code="flipper_terminal", cli=cli)


@pytest.mark.parametrize("bad", [b"X", b"loader info\n", b"loader info\r\nPRIVATE\r\n\r\n>: "])
def test_echo_or_unrecognized_body_does_not_resync(bad):
    cli = ready()
    cli.begin("loader")
    failed(lambda: cli.feed(bad), cli=cli)


def test_line_and_total_response_caps():
    cli = ready()
    cmd = cli.begin("loader")
    cli.feed(cmd[:-1] + b"\r\n")
    failed(lambda: feed(cli, b"x" * 1025), code="flipper_limit", cli=cli)
    cli = ready()
    cmd = cli.begin("loader")
    cli.feed(cmd[:-1] + b"\r\n")
    failed(lambda: feed(cli, (b"x" * 1022 + b"\r\n") * 257), code="flipper_limit", cli=cli)


@pytest.mark.parametrize("bad", [bytearray(b"x"), memoryview(b"x"), "x", None, b"x" * 4097])
def test_feed_requires_bounded_exact_bytes(bad):
    cli = F.FlipperCli(CASE)
    failed(lambda: cli.feed(bad), cli=cli)


def test_unsolicited_ready_bytes_are_terminal_and_no_raw_repr():
    cli = ready()
    assert cli.feed(b"") == b""
    failed(lambda: cli.feed(PRIVATE.encode()), code="flipper_protocol_error", cli=cli)
    assert PRIVATE not in repr(cli)


def test_all_split_points_of_binary_response():
    data = b"\x00\xff\r\n>: \r\nSize: 5\r\n\x1b[31m\x03"
    expected = ('storage read "' + PATH + '"').encode() + b"\r\nSize: %d\r\n" % len(data) + data + b"\r\n" + F.PROMPT
    for pos in range(len(expected) + 1):
        cli = ready()
        idle(cli)
        cli.begin("read", PATH)
        assert cli.feed(expected[:pos]) + cli.feed(expected[pos:]) == data
        assert cli.ready and cli.received_size == len(data)


def test_profile_limits_are_immutable():
    assert dict(F.LIMITS) == {"max_file_bytes": 1 << 20, "max_text_bytes": 256 << 10,
                              "max_list_entries": 256, "connect_seconds": 30, "pull_seconds": 300}
    with pytest.raises(TypeError):
        F.LIMITS["max_file_bytes"] = 10
