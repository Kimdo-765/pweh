"""Windows를 호출하지 않는 sigrok 전용 고정 신원·종료 계약."""
from dataclasses import FrozenInstanceError, replace
import base64
import json
import subprocess
import time
import traceback

import pytest

from pweh import wininterop as O, wininterop_sigrok as W

IMAGE = r'C:\synthetic\unique-run\payload\sigrok-cli.exe'
LAUNCH = W.SigrokLaunch(IMAGE, ('--version',))


def end():
    return time.monotonic() + 5


def row(pid=12, creation='1000', image=IMAGE, args=('--version',)):
    return {'pid': pid, 'image': image, 'creation': creation,
            'cmd': subprocess.list2cmdline(['/synthetic/sigrok-cli.exe', *args])}


def snapshot(*rows):
    return json.dumps({'complete': True, 'items': list(rows)}).encode()


class Runner:
    def __init__(self, *responses):
        self.responses = iter(responses)
        self.calls = []

    def __call__(self, script, deadline):
        self.calls.append(script)
        result = next(self.responses)
        if isinstance(result, Exception):
            raise result
        return result

    @property
    def terminations(self):
        return [c for c in self.calls if c != W.QUERY_SCRIPT]


@pytest.mark.parametrize('tail', [('--version',), ('--list-supported',)])
def test_exact_fixed_commands_and_frozen_launch(tail):
    launch = W.SigrokLaunch(IMAGE, tail)
    with pytest.raises(FrozenInstanceError):
        launch.image = 'changed'
    assert W.matches_launch(W.parse_process_snapshot(snapshot(row(args=tail)))[0], launch)


@pytest.mark.parametrize('tail', [(), ['--version'], ('-L',), ('--scan',), ('--version', '--scan'),
                                  ('--list-supported', 'private'), ('--show',), ('--version\n',)])
def test_noninformation_tail_is_refused(tail):
    with pytest.raises(W.WinInteropError):
        W.SigrokLaunch(IMAGE, tail)


@pytest.mark.parametrize('image', [r'C:\other.exe', r'C:\openocd.exe', '/tmp/sigrok-cli.exe',
                                  r'C:\x\..\sigrok-cli.exe', r'C:\x\SIGROK-CLI.EXE'])
def test_launch_image_must_be_fixed_basename(image):
    with pytest.raises(W.WinInteropError):
        W.SigrokLaunch(image, ('--version',))


def test_openocd_identity_and_script_contract_are_not_relaxed():
    with pytest.raises(O.WinInteropError):
        O.WindowsIdentity(12, IMAGE, '1000', row()['cmd'])
    assert "Name='openocd.exe'" in O.QUERY_SCRIPT
    assert 'PwehOpenOcdProcess' in O.TERMINATE_SCRIPT_TEMPLATE
    assert "Name='sigrok-cli.exe'" in W.QUERY_SCRIPT
    assert 'PwehSigrokProcess' in W.TERMINATE_SCRIPT_TEMPLATE


@pytest.mark.parametrize('raw', [
    b'', b'\xff', b'[]', b'{}', b'{"complete":false,"items":[]}',
    b'{"complete":true,"complete":true,"items":[]}',
    b'{"complete":true,"items":[],"extra":0}', b'{"complete":NaN,"items":[]}',
    b'{"complete":Infinity,"items":[]}', b'{"complete":1e999,"items":[]}',
    b'{"complete":' + b'9' * 10000 + b',"items":[]}', b'[' * 9 + b'0' + b']' * 9,
    b' ' * (W.MAX_SNAPSHOT_BYTES + 1), snapshot(row(), row()),
    snapshot(*[row(pid=n + 1) for n in range(257)]), snapshot({**row(), 'extra': 'SECRET'}),
    snapshot({**row(), 'cmd': '"broken'}), snapshot({**row(), 'pid': True}),
    snapshot({**row(), 'creation': '1001'}), snapshot({**row(), 'creation': 1000}),
    snapshot({**row(), 'image': r'C:\other.exe'}), snapshot({**row(), 'cmd': '\ud800'}),
])
def test_invalid_complete_snapshot_is_never_absence(raw):
    with pytest.raises(W.WinInteropError) as exc:
        W.parse_process_snapshot(raw)
    assert not exc.value.data and exc.value.__suppress_context__


def test_empty_and_bom_snapshot():
    assert W.parse_process_snapshot(snapshot()) == ()
    assert W.parse_process_snapshot(b'\xef\xbb\xbf' + snapshot(row()))[0].pid == 12


def test_other_full_image_is_not_owned_and_normalized_drive_is_supported():
    other = row(pid=13, image=r'D:\unrelated\sigrok-cli.exe', args=('--scan',))
    own = row(image=IMAGE.replace('C:', 'c:').replace('\\', '/'))
    runner = Runner(snapshot(other, own))
    assert len(W.SigrokOwnedProcessProbe(runner=runner).observe(LAUNCH, deadline=end())) == 1
    assert not runner.terminations


@pytest.mark.parametrize('rows', [
    (row(args=('--list-supported',)),), (row(args=('--version', 'extra')),),
    (row(image=IMAGE.replace('synthetic', 'Synthetic')),), (row(), row(pid=13)),
])
def test_same_image_wrong_arguments_or_ambiguous_case_is_unknown(rows):
    runner = Runner(snapshot(*rows))
    with pytest.raises(W.WinInteropError):
        W.SigrokOwnedProcessProbe(runner=runner).observe(LAUNCH, deadline=end())
    assert not runner.terminations


def test_same_handle_generation_termination_and_final_complete_absence():
    observed = W.parse_process_snapshot(snapshot(row()))
    runner = Runner(snapshot(row()), b'{"terminated":true}', snapshot())
    assert W.SigrokOwnedProcessProbe(runner=runner).terminate_and_confirm(LAUNCH, observed, deadline=end())
    script, = runner.terminations
    encoded = script.split("FromBase64String('", 1)[1].split("')", 1)[0]
    assert json.loads(base64.b64decode(encoded)) == {**row(), 'wait_ms': 2000}
    assert script.index('::OpenProcess(') < script.index('::GetProcessTimes(') < script.index('$p=Get-CimInstance')
    assert script.index('::GetProcessTimes(') < script.index('::TerminateProcess(')
    assert '::WaitForSingleObject($h,[uint32]$r.wait_ms)' in script
    assert 'finally {if(![PwehSigrokProcess]::CloseHandle($h))' in script
    assert IMAGE not in script and 'Stop-Process' not in script


@pytest.mark.parametrize('fresh', [snapshot(row(creation='1010')), snapshot(row(pid=13)), snapshot(),
                                  snapshot(row(args=('--list-supported',))), b'invalid', RuntimeError('PRIVATE')])
def test_stale_generation_never_terminates(fresh):
    runner = Runner(fresh)
    observed = W.parse_process_snapshot(snapshot(row()))
    assert not W.SigrokOwnedProcessProbe(runner=runner).terminate_and_confirm(LAUNCH, observed, deadline=end())
    assert not runner.terminations


@pytest.mark.parametrize('response', [b'{"terminated":false}', b'{"terminated":1}',
    b'{"terminated":true,"extra":0}', b'{"terminated":true,"terminated":true}',
    b'x' * 1025, RuntimeError('PRIVATE')])
def test_termination_reply_does_not_make_unknown_success(response):
    runner = Runner(snapshot(row()), response)
    observed = W.parse_process_snapshot(snapshot(row()))
    assert not W.SigrokOwnedProcessProbe(runner=runner).terminate_and_confirm(LAUNCH, observed, deadline=end())


def test_final_presence_or_partial_query_is_not_confirmed():
    runner = Runner(snapshot(row()), b'{"terminated":true}', snapshot(row()))
    assert not W.SigrokOwnedProcessProbe(runner=runner).terminate_and_confirm(
        LAUNCH, W.parse_process_snapshot(snapshot(row())), deadline=end())


def test_empty_observation_requires_two_complete_snapshots():
    runner = Runner(snapshot(), snapshot())
    assert W.SigrokOwnedProcessProbe(runner=runner).terminate_and_confirm(LAUNCH, (), deadline=end())
    assert runner.calls == [W.QUERY_SCRIPT, W.QUERY_SCRIPT]


def test_runner_errors_are_fixed_and_have_no_raw_exception_chain():
    runner = Runner(RuntimeError('SYNTHETIC_PRIVATE'))
    with pytest.raises(W.WinInteropError) as exc:
        W.SigrokOwnedProcessProbe(runner=runner).observe(LAUNCH, deadline=end())
    assert 'SYNTHETIC_PRIVATE' not in ''.join(traceback.format_exception(exc.value))
    assert not exc.value.data


@pytest.mark.parametrize('deadline', [None, True, float('inf'), float('nan'), -1, 10**400])
def test_invalid_execution_budget_is_fixed(deadline):
    with pytest.raises(W.WinInteropError):
        W.SigrokOwnedProcessProbe(runner=Runner()).observe(LAUNCH, deadline=deadline)


def test_probe_passes_shared_deadline_to_command_parser(monkeypatch):
    calls = []
    original = W.split_command_line
    def split(value, *, deadline=None):
        calls.append(deadline)
        return original(value, deadline=deadline)
    monkeypatch.setattr(W, 'split_command_line', split)
    deadline = end()
    assert W.SigrokOwnedProcessProbe(runner=Runner(snapshot(row()))).observe(LAUNCH, deadline=deadline)
    assert calls and all(value == deadline for value in calls)
