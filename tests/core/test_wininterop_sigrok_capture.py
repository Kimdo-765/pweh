"""실제 Windows/포트 없이 검증하는 고정 capture profile의 신원·세대 계약."""
from dataclasses import FrozenInstanceError, replace
import base64
import json
import subprocess
import time
import traceback

import pytest

from pweh import wininterop as W, wininterop_sigrok as I, wininterop_sigrok_capture as C
from pweh.sigrok_capture import CaptureCommand, CaptureChannel, PROFILE_ID

IMAGE = r'C:\synthetic\unique\sigrok-cli.exe'
OUTPUT = r'C:\synthetic\output\capture.sr'
COMMAND = CaptureCommand(PROFILE_ID, 'COM4096', 1_000_000, 4, (CaptureChannel(0, '0'),))
LAUNCH = C.SigrokCaptureLaunch(IMAGE, COMMAND, OUTPUT)


def end():
    return time.monotonic() + 5


def row(*, pid=12, creation='1000', image=IMAGE, tail=COMMAND.argv_tail(OUTPUT)):
    return {'pid': pid, 'image': image, 'creation': creation,
            'cmd': subprocess.list2cmdline(['/synthetic/sigrok-cli.exe', *tail])}


def snapshot(*rows):
    return json.dumps({'complete': True, 'items': list(rows)}).encode()


class Runner:
    def __init__(self, *responses):
        self.responses = iter(responses)
        self.calls = []

    def __call__(self, script, deadline):
        self.calls.append((script, deadline))
        result = next(self.responses)
        if isinstance(result, BaseException):
            raise result
        return result

    @property
    def terminations(self):
        return [script for script, _ in self.calls if script != C.QUERY_SCRIPT]


@pytest.mark.parametrize('conn', ['COM1', 'COM10', 'COM4096'])
def test_exact_profile_launch_and_immutable_state(conn):
    command = replace(COMMAND, conn=conn)
    launch = C.SigrokCaptureLaunch(IMAGE, command, OUTPUT)
    assert launch.argv_tail == command.argv_tail(OUTPUT)
    identity = I.parse_process_snapshot(snapshot(row(tail=command.argv_tail(OUTPUT))))[0]
    assert C.matches_launch(identity, launch)
    with pytest.raises(FrozenInstanceError):
        launch.command = COMMAND


@pytest.mark.parametrize('image,command', [
    (r'C:\openocd.exe', COMMAND), ('/synthetic/sigrok-cli.exe', COMMAND),
    (r'C:\synthetic\SIGROK-CLI.EXE', COMMAND), (IMAGE, COMMAND.argv_tail(OUTPUT)), (IMAGE, None),
])
def test_wrong_image_or_raw_command_is_refused(image, command):
    with pytest.raises(W.WinInteropError):
        C.SigrokCaptureLaunch(image, command, OUTPUT)


@pytest.mark.parametrize('tail', [
    ('--version',), ('--list-supported',), ('--scan',),
    ('--driver=ols:conn=COM1', '--dont-scan', '--scan'),
    ('--driver=ols:conn=COM4096', '--scan'),
    ('--driver=p-ols:conn=COM4096', '--dont-scan', '--scan'),
    ('--driver=ols:conn=com4096', '--dont-scan', '--scan'),
    COMMAND.argv_tail(OUTPUT) + ('--output-file=private',),
    COMMAND.argv_tail(r'C:\other\capture.sr'),
])
def test_same_image_wrong_tail_is_unknown_never_absent(tail):
    runner = Runner(snapshot(row(tail=tail)))
    with pytest.raises(W.WinInteropError):
        C.SigrokCaptureProcessProbe(runner=runner).observe(LAUNCH, deadline=end())
    assert not runner.terminations


@pytest.mark.parametrize('rows', [(row(), row(pid=13)), (row(image=IMAGE.replace('unique', 'Unique')),),
                                   ({**row(), 'creation': '1001'},), ({**row(), 'cmd': '"broken'},)])
def test_ambiguous_or_invalid_snapshot_cannot_be_absence(rows):
    with pytest.raises(W.WinInteropError):
        C.SigrokCaptureProcessProbe(runner=Runner(snapshot(*rows))).observe(LAUNCH, deadline=end())


def test_unrelated_image_and_limited_path_normalization():
    other = row(pid=13, image=r'D:\other\sigrok-cli.exe', tail=('--version',))
    own = row(image=IMAGE.replace('C:', 'c:').replace('\\', '/'))
    result = C.SigrokCaptureProcessProbe(runner=Runner(snapshot(other, own))).observe(LAUNCH, deadline=end())
    assert len(result) == 1 and result[0].pid == 12


def test_info_probe_and_launch_stay_information_only():
    with pytest.raises(W.WinInteropError):
        I.SigrokLaunch(IMAGE, COMMAND.argv_tail(OUTPUT))
    with pytest.raises(W.WinInteropError):
        I.SigrokOwnedProcessProbe(runner=Runner()).observe(LAUNCH, deadline=end())
    with pytest.raises(W.WinInteropError):
        C.SigrokCaptureProcessProbe(runner=Runner()).observe(I.SigrokLaunch(IMAGE, ('--version',)), deadline=end())


def test_exact_generation_termination_uses_same_handle_and_final_absence():
    observed = I.parse_process_snapshot(snapshot(row()))
    runner = Runner(snapshot(row()), b'{"terminated":true}', snapshot())
    assert C.SigrokCaptureProcessProbe(runner=runner).terminate_and_confirm(LAUNCH, observed, deadline=end())
    script, = runner.terminations
    encoded = script.split("FromBase64String('", 1)[1].split("')", 1)[0]
    assert json.loads(base64.b64decode(encoded)) == {**row(), 'wait_ms': 2000}
    assert script.index('::OpenProcess(') < script.index('::GetProcessTimes(') < script.index('::TerminateProcess(')
    assert '::WaitForSingleObject($h,[uint32]$r.wait_ms)' in script
    assert 'finally {if(![PwehSigrokProcess]::CloseHandle($h))' in script
    assert IMAGE not in script and 'Stop-Process' not in script


@pytest.mark.parametrize('fresh', [snapshot(row(creation='1010')), snapshot(row(pid=13)), snapshot(),
    snapshot(row(tail=('--version',))), b'{"complete":false,"items":[]}', RuntimeError('PRIVATE')])
def test_changed_generation_or_unverified_fresh_snapshot_never_kills(fresh):
    observed = I.parse_process_snapshot(snapshot(row()))
    runner = Runner(fresh)
    assert not C.SigrokCaptureProcessProbe(runner=runner).terminate_and_confirm(LAUNCH, observed, deadline=end())
    assert not runner.terminations


@pytest.mark.parametrize('reply', [b'{"terminated":false}', b'{"terminated":1}',
    b'{"terminated":true,"extra":0}', b'{"terminated":true,"terminated":true}', b'x' * 1025])
def test_bad_control_reply_is_not_success(reply):
    runner = Runner(snapshot(row()), reply)
    assert not C.SigrokCaptureProcessProbe(runner=runner).terminate_and_confirm(
        LAUNCH, I.parse_process_snapshot(snapshot(row())), deadline=end())


def test_short_exit_requires_complete_absence_again():
    runner = Runner(snapshot(), snapshot())
    assert C.SigrokCaptureProcessProbe(runner=runner).terminate_and_confirm(LAUNCH, (), deadline=end())
    assert len(runner.calls) == 2 and not runner.terminations


def test_final_remaining_same_image_is_not_confirmed():
    runner = Runner(snapshot(row()), b'{"terminated":true}', snapshot(row()))
    assert not C.SigrokCaptureProcessProbe(runner=runner).terminate_and_confirm(
        LAUNCH, I.parse_process_snapshot(snapshot(row())), deadline=end())


def test_runner_private_error_is_suppressed():
    runner = Runner(RuntimeError('SYNTHETIC_PRIVATE'))
    with pytest.raises(W.WinInteropError) as exc:
        C.SigrokCaptureProcessProbe(runner=runner).observe(LAUNCH, deadline=end())
    assert 'SYNTHETIC_PRIVATE' not in ''.join(traceback.format_exception(exc.value))
    assert not exc.value.data


def test_all_parser_and_runner_steps_share_one_deadline(monkeypatch):
    calls = []
    original = C.split_command_line
    def split(value, *, deadline=None):
        calls.append(deadline)
        return original(value, deadline=deadline)
    monkeypatch.setattr(C, 'split_command_line', split)
    runner = Runner(snapshot(row()))
    deadline = end()
    C.SigrokCaptureProcessProbe(runner=runner).observe(LAUNCH, deadline=deadline)
    assert calls and set(calls) == {deadline}
    assert runner.calls[0][1] == deadline
