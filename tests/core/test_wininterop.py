"""Windows를 실행하지 않는 경로·snapshot·동일 세대 종료 계약 시험."""
from __future__ import annotations

import base64
from dataclasses import FrozenInstanceError, replace
import json
import subprocess
import time
import traceback

import pytest

from pweh import wininterop as W

IMAGE = r"C:\synthetic bundle\openocd.exe"
MARKER = "C:\\synthetic run\\owner-" + "a" * 32 + ".cfg"
TAIL = ("-d3", "-s", r"C:\synthetic bundle\scripts", "-c", "tcl port pipe",
        "-f", MARKER, "-c", "init")
LAUNCH = W.OwnedWindowsLaunch(IMAGE, TAIL, MARKER, (2, 6))


def end():
    return time.monotonic() + 5


def row(*, pid=12, creation="1000", image=IMAGE, args=TAIL, argv0="/synthetic/openocd.exe"):
    return {"pid": pid, "image": image, "creation": creation,
            "cmd": subprocess.list2cmdline([argv0, *args])}


def snapshot(*rows):
    return json.dumps({"complete": True, "items": list(rows)}, ensure_ascii=True).encode()


class Runner:
    """응답 bytes만 돌려주는 주입. subprocess/PnP/파일을 실행하거나 읽지 않는다."""
    def __init__(self, *responses):
        self.responses = iter(responses)
        self.calls = []

    def __call__(self, script, deadline):
        self.calls.append((script, deadline))
        value = next(self.responses)
        if isinstance(value, Exception):
            raise value
        return value

    @property
    def terminations(self):
        return [script for script, _ in self.calls if script != W.QUERY_SCRIPT]


@pytest.mark.parametrize("path", [
    "C:\\", r"c:\synthetic\a.txt", "D:/synthetic/한글 space/file.cfg",
    r"\\wsl$\Synthetic\tmp\run", r"\\wsl.localhost\Synthetic\tmp\run",
    r"C:\synthetic\COM10.cfg", r"C:\synthetic\space inside.cfg",
])
def test_path_preserves_valid_spelling(path):
    assert W.validate_windows_path(path) == path


@pytest.mark.parametrize("path", [
    "", None, b"C:\\x", "relative.cfg", r"C:relative", r"\rooted", "/mnt/c/x",
    r"\\server\share\x", r"\\?\C:\x", r"\\.\COM3", "\\\\wsl$\\", r"\\wsl$",
    r"C:\a\..\b", r"C:\a\.\b", "C:\\a\\\\b", "C:\\a\\",
    r"C:\a:stream", r"C:\a\b:stream", "C:\\a ", "C:\\a.", "C:\\a\0b",
    "C:\\a\nb", "C:\\a\rb", "C:\\a\tb", "C:\\a\x7fb", "C:\\a\x85b",
    'C:\\a"b', "C:\\a*b", "C:\\a?b", "C:\\a|b", "C:\\a<b", "C:\\a>b",
    "C:\\a\ud800b", "C:\\" + "x" * 8193, "C:\\" + "한" * 3000,
    r"C:\CON", r"C:\con.txt", r"C:\COM1.cfg", r"C:\lpt9", r"C:\COM¹.bin",
    r"C:\NUL.cfg", r"C:\CON .txt", r"C:\CONIN$", r"C:\CLOCK$",
])
def test_path_rejects_unsafe_or_unmapped_forms(path):
    with pytest.raises(W.WinInteropError) as exc:
        W.validate_windows_path(path)
    assert "Windows 실행 입력" in str(exc.value)
    assert not exc.value.data


@pytest.mark.parametrize("args", [
    ["/synthetic/openocd.exe", "-c", "tcl port pipe"],
    [IMAGE, "", "plain", r"a\b", 'quoted"text', "trailing space ", "한글"],
    [IMAGE, "a \\", "a \\\\", 'a\\"b', "-c", "set x {C:/a b}"],
    [IMAGE, *TAIL],
    [IMAGE, "-c", "set x {\n  한글\tvalue\r\n}\nputs $x"],
])
def test_splitter_matches_canonical_windows_command_encoding(args):
    assert W.split_command_line(subprocess.list2cmdline(args)) == tuple(args)


@pytest.mark.parametrize("value", [
    "", "   ", '"unterminated', 'x "a""b"', "x\0y", "x\x01y", "x\x85y", "x\udcff",
    "x" * 32769, "x " + "a " * 1024, "😀" * 16385, None, b"x",
])
def test_splitter_rejects_unknown_quote_control_and_budgets(value):
    with pytest.raises(W.WinInteropError):
        W.split_command_line(value)


def test_launch_is_deeply_immutable_and_ignores_c_option_contents():
    with pytest.raises(FrozenInstanceError):
        LAUNCH.marker_cfg = "other"
    launch = W.OwnedWindowsLaunch(IMAGE, ("-c", "-f", "-f", MARKER), MARKER, (3,))
    assert launch.path_arg_indices == (3,)


@pytest.mark.parametrize("changes", [
    {"argv_tail": list(TAIL)}, {"path_arg_indices": [2, 6]}, {"path_arg_indices": (6, 2)},
    {"path_arg_indices": (2, True)}, {"path_arg_indices": (2,)}, {"path_arg_indices": (2, 6, 6)},
    {"image": r"C:\other.exe"}, {"marker_cfg": r"C:\owner-other.cfg"},
    {"argv_tail": ("-c", "init")}, {"argv_tail": TAIL + ("-f",)},
    {"argv_tail": TAIL + ("--unknown",)}, {"argv_tail": TAIL + ("-c", "bad\x01arg")},
    {"argv_tail": TAIL + ("-f", MARKER), "path_arg_indices": (2, 6, 10)},
])
def test_invalid_launch_never_becomes_identity(changes):
    with pytest.raises(W.WinInteropError):
        replace(LAUNCH, **changes)


def test_snapshot_normal_empty_and_bom():
    assert W.parse_process_snapshot(snapshot()) == ()
    rows = W.parse_process_snapshot(b"\xef\xbb\xbf" + snapshot(row()))
    assert rows == (W.WindowsIdentity(12, IMAGE, "1000", row()["cmd"]),)
    assert W.matches_launch(rows[0], LAUNCH)


@pytest.mark.parametrize("raw", [
    b"", b"\xff", b"[]", b"{}", b'{"complete":false,"items":[]}',
    b'{"complete":1,"items":[]}', b'{"complete":true,"items":null}',
    b'{"complete":true,"items":[],"other":0}', b'{"complete":true,"complete":true,"items":[]}',
    b'{"complete":true,"items":[] } trailing', b'{"complete":NaN,"items":[]}',
    b'{"complete":Infinity,"items":[]}', b'{"complete":1.0,"items":[]}',
    b'{"complete":1e500,"items":[]}', b'{"complete":' + b"9" * 10000 + b',"items":[]}',
    b"[" * 9 + b"0" + b"]" * 9, b"[" + b"0," * 9000 + b"0]", b" " * (W.MAX_SNAPSHOT_BYTES + 1),
    snapshot(*[row(pid=i + 1) for i in range(257)]), snapshot(row(), row()),
    snapshot({**row(), "extra": "secret"}), snapshot({k: v for k, v in row().items() if k != "cmd"}),
    snapshot({**row(), "cmd": '"bad'}), snapshot({**row(), "cmd": ""}),
    snapshot({**row(), "cmd": "a\ud800"}),
    b'{"complete":true,"items":[{"pid":1,"pid":2,"image":"x","creation":"10","cmd":"x"}]}',
])
def test_snapshot_never_skips_invalid_data_as_absence(raw):
    with pytest.raises(W.WinInteropError) as exc:
        W.parse_process_snapshot(raw)
    assert not exc.value.data
    assert exc.value.__suppress_context__


@pytest.mark.parametrize("key,value", [
    ("pid", True), ("pid", 0), ("pid", -1), ("pid", 2**32), ("pid", "12"),
    ("creation", "0"), ("creation", "0010"), ("creation", "11"), ("creation", "-10"),
    ("creation", str(2**63)), ("creation", "9" * 100), ("creation", 10),
    ("image", r"C:\different.exe"), ("image", "relative\\openocd.exe"),
    ("cmd", None), ("cmd", "x\0y"), ("cmd", "x\x01secret"),
])
def test_identity_requires_all_exact_fields(key, value):
    with pytest.raises(W.WinInteropError):
        W.parse_process_snapshot(snapshot({**row(), key: value}))


def test_observe_posix_argv0_and_drive_separator_normalization():
    args = list(TAIL)
    args[2] = args[2].replace("C:", "c:").replace("\\", "/")
    args[6] = args[6].replace("C:", "c:").replace("\\", "/")
    run = Runner(snapshot(row(args=args, image=IMAGE.replace("C:", "c:").replace("\\", "/"))))
    result = W.WindowsOwnedProcessProbe(runner=run).observe(LAUNCH, deadline=end())
    assert len(result) == 1
    assert run.calls[0][0] == W.QUERY_SCRIPT
    assert not run.terminations


def test_observe_ignores_only_valid_unrelated_launches():
    other = row(args=("-f", r"C:\synthetic\different.cfg"))
    run = Runner(snapshot(other))
    assert W.WindowsOwnedProcessProbe(runner=run).observe(LAUNCH, deadline=end()) == ()


@pytest.mark.parametrize("changed", [
    row(image=r"D:\different\openocd.exe"),
    row(args=TAIL + ("-c", "different")),
    row(args=tuple(x.replace("synthetic", "Synthetic") for x in TAIL)),
    row(args=tuple(x.replace("owner-", "OWNER-") for x in TAIL)),
    row(args=("-c", "echo " + MARKER)),
])
def test_marker_variant_or_wrong_identity_is_unknown_not_absent(changed):
    run = Runner(snapshot(changed))
    with pytest.raises(W.WinInteropError):
        W.WindowsOwnedProcessProbe(runner=run).observe(LAUNCH, deadline=end())
    assert not run.terminations


def test_marker_broken_by_valid_quotes_is_still_a_candidate():
    altered = row()
    # Windows는 quote를 제거하므로 raw 문자열 검색만 하면 이 표식을 놓친다.
    altered["cmd"] = altered["cmd"].replace("owner-", 'owner-""')
    run = Runner(snapshot(altered))
    with pytest.raises(W.WinInteropError):
        W.WindowsOwnedProcessProbe(runner=run).observe(LAUNCH, deadline=end())


def test_duplicate_marker_processes_are_unknown():
    run = Runner(snapshot(row(), row(pid=13)))
    with pytest.raises(W.WinInteropError):
        W.WindowsOwnedProcessProbe(runner=run).observe(LAUNCH, deadline=end())


def test_terminate_exact_generation_fixed_script_and_complete_absence():
    observed = W.parse_process_snapshot(snapshot(row()))
    run = Runner(snapshot(row()), b'{"terminated":true}', snapshot())
    assert W.WindowsOwnedProcessProbe(runner=run).terminate_and_confirm(LAUNCH, observed, deadline=end())
    assert len(run.calls) == 3 and len(run.terminations) == 1
    script = run.terminations[0]
    encoded = script.split("FromBase64String('", 1)[1].split("')", 1)[0]
    request = json.loads(base64.b64decode(encoded))
    assert request == {**row(), "wait_ms": 2000}
    assert script == W.TERMINATE_SCRIPT_TEMPLATE.replace("__REQUEST__", encoded)
    assert IMAGE not in script and MARKER not in script
    assert "Stop-Process" not in script
    assert script.index("::OpenProcess(") < script.index("::GetProcessTimes(") < script.index("$p=Get-CimInstance")
    assert script.index("::GetProcessTimes(") < script.index("::TerminateProcess(")
    assert "($c - ($c % 10))" in script
    assert "::WaitForSingleObject($h,[uint32]$r.wait_ms)" in script
    assert "finally {if(![PwehOpenOcdProcess]::CloseHandle($h))" in script


@pytest.mark.parametrize("new", [
    snapshot(row(creation="1010")), snapshot(row(pid=13)), snapshot(),
    snapshot(row(image=r"D:\other\openocd.exe")), b"malformed", RuntimeError("SYNTHETIC SECRET"),
])
def test_old_snapshot_or_unverified_query_never_terminates(new):
    run = Runner(new)
    observed = W.parse_process_snapshot(snapshot(row()))
    assert not W.WindowsOwnedProcessProbe(runner=run).terminate_and_confirm(LAUNCH, observed, deadline=end())
    assert not run.terminations


@pytest.mark.parametrize("reply", [
    b'{"terminated":false}', b'{"terminated":1}', b'{"terminated":true,"extra":1}',
    b'{"terminated":true,"terminated":true}', b"null", b"[true]", b"x" * 1025,
    RuntimeError("SYNTHETIC SECRET"),
])
def test_failed_handle_or_wait_never_becomes_confirmed(reply):
    run = Runner(snapshot(row()), reply)
    observed = W.parse_process_snapshot(snapshot(row()))
    assert not W.WindowsOwnedProcessProbe(runner=run).terminate_and_confirm(LAUNCH, observed, deadline=end())
    assert len(run.terminations) == 1


@pytest.mark.parametrize("final", [
    snapshot(row()), snapshot(row(creation="1010")), snapshot(row(pid=13)),
    b'{"complete":false,"items":[]}', b"invalid", RuntimeError("SYNTHETIC SECRET"),
])
def test_final_query_missing_or_marker_remaining_is_not_confirmed(final):
    run = Runner(snapshot(row()), b'{"terminated":true}', final)
    observed = W.parse_process_snapshot(snapshot(row()))
    assert not W.WindowsOwnedProcessProbe(runner=run).terminate_and_confirm(LAUNCH, observed, deadline=end())


def test_empty_snapshot_requires_fresh_and_final_complete_absence():
    run = Runner(snapshot(), snapshot())
    assert W.WindowsOwnedProcessProbe(runner=run).terminate_and_confirm(LAUNCH, (), deadline=end())
    assert len(run.calls) == 2 and not run.terminations
    run = Runner(snapshot(row()))
    assert not W.WindowsOwnedProcessProbe(runner=run).terminate_and_confirm(LAUNCH, (), deadline=end())
    assert not run.terminations


@pytest.mark.parametrize("value", [None, True, "future", float("nan"), float("inf"), 10**400, 0, -1])
def test_invalid_or_expired_deadline_does_not_call_runner(value):
    run = Runner()
    with pytest.raises(W.WinInteropError):
        W.WindowsOwnedProcessProbe(runner=run).observe(LAUNCH, deadline=value)
    assert not run.calls


def test_deadline_expiry_after_runner_is_unknown(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(W.time, "monotonic", lambda: clock[0])
    def runner(script, deadline):
        clock[0] = deadline
        return snapshot()
    with pytest.raises(W.WinInteropError):
        W.WindowsOwnedProcessProbe(runner=runner).observe(LAUNCH, deadline=105)


def test_parser_checks_clock_during_bounded_work(monkeypatch):
    tick = [100.0]
    def clock():
        tick[0] += .1
        return tick[0]
    monkeypatch.setattr(W.time, "monotonic", clock)
    with pytest.raises(W.WinInteropError):
        W.parse_process_snapshot(snapshot(row(args=("-c", "x" * 16000))), deadline=100.4)


def test_no_default_runner_or_exception_source_text():
    with pytest.raises(TypeError):
        W.WindowsOwnedProcessProbe()
    with pytest.raises(W.WinInteropError):
        W.WindowsOwnedProcessProbe(runner=None)
    run = Runner(RuntimeError("SYNTHETIC SECRET COMMAND"))
    with pytest.raises(W.WinInteropError) as exc:
        W.WindowsOwnedProcessProbe(runner=run).observe(LAUNCH, deadline=end())
    assert "SECRET" not in str(exc.value) and not exc.value.data and exc.value.__suppress_context__


def test_fixed_query_cannot_be_broadened_by_launch():
    assert "Name='openocd.exe'" in W.QUERY_SCRIPT
    assert "-OperationTimeoutSec 2" in W.QUERY_SCRIPT and "-First 257" in W.QUERY_SCRIPT
    assert "complete=$true" in W.QUERY_SCRIPT
    assert "__REQUEST__" not in W.QUERY_SCRIPT


def test_same_absolute_deadline_reaches_every_identity_comparison(monkeypatch):
    original = W.matches_launch
    deadlines = []
    def checked(identity, launch, *, deadline=None):
        deadlines.append(deadline)
        return original(identity, launch, deadline=deadline)
    monkeypatch.setattr(W, "matches_launch", checked)
    deadline = end()
    observed = W.parse_process_snapshot(snapshot(row()))
    run = Runner(snapshot(row()), b'{"terminated":true}', snapshot())
    assert W.WindowsOwnedProcessProbe(runner=run).terminate_and_confirm(LAUNCH, observed, deadline=deadline)
    assert deadlines and all(value == deadline for value in deadlines)
    assert all(value == deadline for _, value in run.calls)


def test_runner_exception_traceback_does_not_include_source_message():
    run = Runner(RuntimeError("SYNTHETIC SECRET COMMAND"))
    with pytest.raises(W.WinInteropError) as exc:
        W.WindowsOwnedProcessProbe(runner=run).observe(LAUNCH, deadline=end())
    assert "SYNTHETIC SECRET COMMAND" not in "".join(traceback.format_exception(exc.type, exc.value, exc.tb))


def test_script_success_is_published_only_after_handle_close():
    script = W.TERMINATE_SCRIPT_TEMPLATE
    assert script.index("::CloseHandle($h)") < script.index("'{\"terminated\":true}'")


def test_future_deadline_ceiling_has_no_runner_fallback():
    run = Runner()
    with pytest.raises(W.WinInteropError):
        W.WindowsOwnedProcessProbe(runner=run).observe(LAUNCH, deadline=time.monotonic() + 60)
    assert not run.calls
