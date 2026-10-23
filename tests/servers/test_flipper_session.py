"""합성 CLI의 단일 worker, fresh 범위, 물리 close 이후 lease 해제를 확인한다."""
from __future__ import annotations

import json
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'mcp-servers/flipper-mcp'))
from flipper_mcp import session as S
from pweh.errors import PwehError
from pweh import portlock, serialtransport
from .fake_flipper_cli import setup, FakeFlipper, BANNER, INFO, PROMPT


def operation(owner, name='device_info', *args):
    use = owner.reserve_use()
    assert use.claim()
    try:
        return getattr(owner, name)(use, *args)
    finally:
        use.finish()


@pytest.mark.parametrize('setup', ['posix-tty', 'win-helper'], indirect=True)
def test_passive_connect_then_fixed_loader_info_and_complete_close(setup):
    owner = setup.prepare()
    assert setup.fake.writes == [] and setup.opens == [] and not owner.lease.closed
    result = owner.connect(threading.Event())
    assert result['handshake']['tx_before_banner'] == 0
    assert result['route']['whole_device_locked'] is True
    assert result['device']['firmware']['version'] == '1.5.1'
    assert setup.fake.commands == [b'loader info', b'info device']
    assert setup.opens[0].dtr is True and setup.opens[0].rts is False
    assert setup.opens[0].write_timeout == 1
    assert 'PRIVATE_' not in json.dumps(result)
    assert operation(owner)['device'] == result['device']
    result = operation(owner, 'storage_list', f'/ext/pweh/{setup.case.id}/')
    assert result['count'] == 1 and result['listing_complete'] is True
    assert result['filesystem_completeness_verified'] is False
    closed = owner.close()
    assert closed['ok'] is True and closed['physical_close_verified'] is True
    assert closed['lease_released'] is True and closed['worker_finished'] is True
    assert closed['device_command_termination_verified'] is False
    assert owner.lease.closed and setup.fake.close_calls == 1
    assert S.close_session(setup.case.id)['already_closed'] is True


@pytest.mark.parametrize('banner', [PROMPT, b'U-Boot> ', b'bridge bytes', BANNER.replace(b'1.5.1', b'1.5.0'), b''])
def test_bad_or_missing_banner_never_transmits(setup, monkeypatch, banner):
    setup.fake.buffer[:] = banner
    monkeypatch.setattr(S, 'TEXT_SECONDS', .005)
    owner = setup.prepare()
    with pytest.raises(PwehError):
        owner.connect(threading.Event())
    assert setup.fake.writes == [] and owner.state == 'terminal'
    assert not owner.lease.closed
    assert owner.close()['ok'] is True


@pytest.mark.parametrize('field,value', [('vid', '303a'), ('pid', '1001'), ('interface_number', '02'),
                                       ('interface_number', None), ('serial', 'unknown'),
                                       ('serial_basis', None), ('status', 'unknown'), ('present', False)])
def test_identity_failure_is_before_open(setup, monkeypatch, field, value):
    route = replace(setup.route, identity=replace(setup.route.identity, **{field: value}))
    monkeypatch.setattr(S, '_resolve', lambda r, p: route)
    with pytest.raises(PwehError) as caught:
        setup.prepare()
    assert caught.value.code == 'flipper_identity_unknown'
    assert setup.opens == [] and setup.fake.writes == []


def test_duplicate_connect_and_sibling_lease_conflict(setup):
    owner = setup.prepare()
    with pytest.raises(PwehError) as caught:
        setup.prepare()
    assert caught.value.code == 'flipper_busy'
    with pytest.raises(PwehError):
        portlock.get_manager().acquire(('synthetic-flipper-sibling',), owner=portlock.PortOwner(
            server='other', case_id=setup.case.id, ref='synthetic'))
    assert owner.close()['ok']
    lease = portlock.get_manager().acquire(('synthetic-flipper-sibling',), owner=portlock.PortOwner(
        server='other', case_id=setup.case.id, ref='synthetic'))
    lease.close()


@pytest.mark.parametrize('change', ['scope', 'route', 'role', 'guard', 'authorization'])
def test_fresh_failure_prevents_next_command(setup, monkeypatch, change):
    owner = setup.connect()
    before = list(setup.fake.commands)
    def denied(*a, **kw):
        raise PwehError('PRIVATE_UNTRUSTED_ERROR', code='authorization_required' if change == 'authorization' else 'instrument_port')
    if change == 'scope':
        setup.keys = (*setup.keys, 'changed')
    elif change == 'route':
        setup.route = replace(setup.route, device_id='different')
    elif change == 'role':
        monkeypatch.setattr(S.portlock.get_role_store(), 'assert_probe_allowed', denied)
    elif change == 'guard':
        monkeypatch.setattr(S, 'guard_target_port', denied)
    else:
        monkeypatch.setattr(owner.runtime, 'case', denied)
    with pytest.raises(PwehError) as caught:
        operation(owner)
    assert setup.fake.commands == before and owner.state == 'terminal'
    assert 'PRIVATE_' not in json.dumps(caught.value.to_dict())


def test_busy_loader_no_info_or_storage_followup(setup):
    owner = setup.connect()
    setup.fake.responses[b'loader info'] = b'loader info\r\nApplication PRIVATE_APP is running\r\n' + PROMPT
    before = len(setup.fake.commands)
    with pytest.raises(PwehError) as caught:
        operation(owner)
    assert caught.value.code == 'flipper_app_busy'
    assert setup.fake.commands[before:] == [b'loader info']
    assert 'PRIVATE_' not in json.dumps(caught.value.to_dict())
    with pytest.raises(PwehError):
        owner.reserve_use()


def test_partial_open_unknown_transport_retained_until_verified(setup, monkeypatch):
    owner = setup.prepare()
    setup.fake.close_verified = False
    def fail(*a, **kw):
        raise serialtransport.SerialOpenError(setup.fake, RuntimeError('PRIVATE_OPEN'))
    # 부분 open 예외의 진단 metadata는 합성 transport에도 고정값만 둔다.
    setup.fake.cleanup_errors = ()
    monkeypatch.setattr(S.serialtransport, 'open_serial', fail)
    with pytest.raises(PwehError):
        owner.connect(threading.Event())
    result = owner.close()
    assert result['state'] == 'cleanup_pending' and not owner.lease.closed
    assert S.get_session(setup.case.id) is owner
    setup.fake.close_verified = True
    assert owner.close()['ok'] is True


def test_close_waits_for_claimed_worker_and_preserves_lease(setup, monkeypatch):
    owner = setup.connect()
    use = owner.reserve_use()
    assert use.claim()
    monkeypatch.setattr(S, 'CLOSE_SECONDS', .01)
    result = owner.close()
    assert result['state'] == 'cleanup_pending' and result['worker_finished'] is False
    assert setup.fake.close_calls == 0 and not owner.lease.closed and use.cancelled()
    use.finish()
    assert owner._cleanup_done.wait(1)
    assert owner.close()['ok'] is True


def test_reserved_cancel_and_late_cancel_do_not_touch_another_reader(setup):
    owner = setup.connect()
    pending = owner.reserve_use()
    pending.cancel()
    assert not pending.claim() and not owner._uses and setup.fake.cancel_calls == 0
    done = owner.reserve_use()
    assert done.claim()
    done.finish()
    current = owner.reserve_use()
    assert current.claim()
    done.cancel()
    assert setup.fake.cancel_calls == 0 and not current.cancelled()
    current.finish()


def test_close_before_claim_blocks_late_worker(setup):
    owner = setup.connect()
    use = owner.reserve_use()
    assert owner.close()['ok']
    assert not use.claim() and not owner._uses


def test_close_failure_with_physical_unknown_keeps_same_owner(setup):
    owner = setup.connect()
    setup.fake.close_verified = False
    setup.fake.close_error = True
    result = owner.close()
    assert result['ok'] is False and not result['physical_close_verified']
    assert not result['lease_released'] and S.get_session(setup.case.id) is owner
    assert 'PRIVATE_' not in json.dumps(result)
    setup.fake.close_verified = True
    assert owner.close()['ok']


def test_write_error_after_suffix_is_terminal_no_retry(setup):
    owner = setup.connect()
    setup.fake.write_chunk = 3
    before = len(setup.fake.writes)
    calls = []
    def fail(data):
        calls.append(data)
        if len(calls) == 2:
            raise OSError('PRIVATE_WRITE')
    setup.fake.before_write = fail
    with pytest.raises(PwehError):
        operation(owner)
    assert len(setup.fake.writes) == before + 1 and owner.state == 'terminal'


def test_fresh_deadline_expiry_sends_nothing(setup, monkeypatch):
    owner = setup.connect()
    before = list(setup.fake.commands)
    monkeypatch.setattr(S, 'TEXT_SECONDS', .001)
    monkeypatch.setattr(S, '_roles', lambda *a: time.sleep(.003))
    with pytest.raises(PwehError) as caught:
        operation(owner)
    assert caught.value.code == 'time_limit' and setup.fake.commands == before


@pytest.mark.parametrize('original,expected', [('busy', 'flipper_busy'),
    ('port_role_unknown', 'port_role_unknown'), ('instrument_identity_unknown', 'instrument_identity_unknown'),
    ('unknown_private_code', 'flipper_failed')])
def test_fixed_error_projection_preserves_known_semantics(original, expected):
    result = S.public_error(PwehError('PRIVATE_PROVIDER_DETAIL', code=original, data={'private': 'PRIVATE'}))
    assert result.code == expected and 'PRIVATE' not in json.dumps(result.to_dict())
