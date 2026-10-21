"""네 서버의 계측기 guard 순서·실패 정리 회귀. 격리 증명과 가짜 PnP만 사용한다."""
from dataclasses import replace
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp import Client

from mcp_helpers import call
from pweh import instrument_guard as G
from pweh.portidentity import PortIdentity
from pweh.runtime import get_runtime
from servers.test_esp_mcp import fake as esp_fake
from servers.test_sigrok_mcp import fake as sigrok_fake
from servers.test_jtagulator_mcp import sim_env

pytestmark = pytest.mark.anyio
MAC = '020000000001'


@pytest.fixture
def anyio_backend():
    return 'asyncio'


def approve_pin(rt):
    subject = {'schema': G.PIN_SCHEMA, 'base_mac': MAC, 'native_usb': {'serial': MAC},
               'boot_usb': [{'serial': 'rom-fixture'}], 'aux_usb': []}
    rec = rt.attestations.request('instrument-pin', subject, {'scope': 'instrument', 'instrument_id': MAC}, G.PIN_QUESTIONS)
    return rt.attestations.decide(rec['id'], {q['id']: 'yes' for q in G.PIN_QUESTIONS}, via='cli-tty', by='synthetic')


def snapshot(pinned=True):
    return PortIdentity('synthetic', 'known', present=True, serial=MAC if pinned else 'other-fixture', vid='303a', pid='4001')


@pytest.fixture(autouse=True)
def isolate_guard(workspace, tmp_path, monkeypatch):
    tags = G.InstrumentTagStore(tmp_path / 'runtime-tags')
    monkeypatch.setattr(G, 'InstrumentTagStore', lambda: tags)
    monkeypatch.setattr(G, 'probe_identity', lambda *a, **k: pytest.fail('실제 PnP 호출 금지'))
    yield
    from uart_mcp import server as us
    from jtagulator_mcp import server as js
    us.shutdown_all('test cleanup')
    js._shutdown_all()


@pytest.mark.parametrize('module,name,kwargs', [
    ('esp_mcp', 'esp_chip_info', {'port': '/dev/ttyACM123'}),
    ('esp_mcp', 'esp_security_info', {'port': '/dev/ttyACM123'}),
    ('esp_mcp', 'esp_read_flash_start', {'port': '/dev/ttyACM123'}),
    ('uart_mcp', 'uart_open', {'port': '/dev/ttyACM123'}),
    ('uart_mcp', 'uart_detect_baud', {'port': '/dev/ttyACM123', 'probe': 'none'}),
    ('jtagulator_mcp', 'jtagulator_connect', {'port': '/dev/ttyACM123'}),
    ('sigrok_mcp', 'sigrok_scan', {'driver': 'fx2lafw'}),
    ('sigrok_mcp', 'sigrok_device_info', {'driver': 'fx2lafw'}),
    ('sigrok_mcp', 'sigrok_capture', {'driver': 'fx2lafw', 'samples': 64}),
])
async def test_preflight_before_authorize_program_or_serial(module, name, kwargs, auth, monkeypatch):
    import importlib
    S = importlib.import_module(module + '.server')
    rt = S.rt(); case = rt.cases.create(title='합성 guard', authorization=auth)
    if module == 'esp_mcp': kwargs = {**kwargs, 'port': 'COM31'}
    approve_pin(rt)
    monkeypatch.setattr(G, 'probe_identity', lambda *a, **k: snapshot())
    def forbidden(*a, **k): pytest.fail('보호 거부 전에 프로그램/포트/승인 접근')
    monkeypatch.setattr(rt, 'authorize', forbidden)
    for attr in ('_resolve_backend', '_locate_exe', '_cli', 'SerialLink'):
        if hasattr(S, attr): monkeypatch.setattr(S, attr, forbidden)
    async with Client(S.server) as client:
        result = await call(client, name, case_id=case.id, **kwargs)
    assert 'instrument_port' in result['_error']
    assert rt.jobs.list() == []
    assert not list(case.subdir('dumps').iterdir())


@pytest.mark.parametrize('name,kwargs', [('sigrok_scan', {}), ('sigrok_scan', {'driver': 'fx2lafw', 'conn': '1.7'}),
                                      ('uart_open', {'port': 'socket://127.0.0.1:9000'}),
                                      ('jtagulator_connect', {'port': 'rfc2217://[::1]:9000'})])
async def test_unresolved_routes_fail_closed(name, kwargs, auth, monkeypatch):
    import importlib
    from pweh.portidentity import probe_identity
    module = 'sigrok_mcp' if name.startswith('sigrok') else ('uart_mcp' if name.startswith('uart') else 'jtagulator_mcp')
    S = importlib.import_module(module + '.server')
    rt = S.rt(); case = rt.cases.create(title='합성 경로', authorization=auth)
    approve_pin(rt)
    # 이 경로들은 probe_identity가 OS runner 호출 전에 unknown으로 돌린다.
    monkeypatch.setattr(G, 'probe_identity', probe_identity)
    async with Client(S.server) as client:
        result = await call(client, name, case_id=case.id, **kwargs)
    assert 'instrument_identity_unknown' in result['_error']


@pytest.mark.parametrize('module,name', [('uart_mcp', 'uart_open'), ('jtagulator_mcp', 'jtagulator_connect')])
async def test_preopen_recheck_releases_reservation(module, name, auth, monkeypatch):
    import importlib
    S = importlib.import_module(module + '.server')
    rt = S.rt(); case = rt.cases.create(title='합성 재검사', authorization=auth)
    approve_pin(rt)
    calls = []
    def sequence(*a, **k):
        calls.append(1); return snapshot(len(calls) > 1)
    monkeypatch.setattr(G, 'probe_identity', sequence)
    import serial
    monkeypatch.setattr(serial, 'serial_for_url', lambda *a, **k: pytest.fail('open 전 재검사 누락'))
    async with Client(S.server) as client:
        result = await call(client, name, case_id=case.id, port='/dev/ttyACM123')
    assert 'instrument_port' in result['_error'] and len(calls) == 2
    assert not (S._RESERVED if module == 'uart_mcp' else S._CONNECTING)
    assert not (S._SESSIONS if module == 'uart_mcp' else S._CONNS)


async def test_esp_worker_rechecks_before_process(esp_fake, auth, monkeypatch):
    from esp_mcp import server as S
    rt = S.rt(); case = rt.cases.create(title='합성 esp', authorization=auth)
    approve_pin(rt)
    calls = []
    def sequence(*a, **k):
        calls.append(1); return snapshot(len(calls) > 1)
    monkeypatch.setattr(G, 'probe_identity', sequence)
    monkeypatch.setattr(S, 'run_streaming', lambda *a, **k: pytest.fail('장치 프로그램 실행 금지'))
    async with Client(S.server) as client:
        result = await call(client, 'esp_chip_info', case_id=case.id, port='/dev/ttyACM123')
    assert 'instrument_port' in result['_error'] and len(calls) == 2
    assert not list(case.subdir('uart').glob('esptool-chip-info*'))


async def test_sigrok_queued_recheck_cleanup(sigrok_fake, auth, monkeypatch):
    from sigrok_mcp import server as S
    rt = S.rt(); case = rt.cases.create(title='합성 sigrok', authorization=auth)
    approve_pin(rt)
    calls = []
    def sequence(*a, **k):
        calls.append(1); return snapshot(len(calls) > 1)
    monkeypatch.setattr(G, 'probe_identity', sequence)
    async with Client(S.server) as client:
        start = await call(client, 'sigrok_capture', case_id=case.id, driver='fx2lafw', samples=64, background=True)
        assert 'job_id' in start, start
        status = await call(client, 'sigrok_job_status', job_id=start['job_id'], wait_seconds=5)
    assert status['status'] == 'failed' and status['error']['code'] == 'instrument_port'
    assert sigrok_fake.calls('capture') == []
    assert not list(case.subdir('signals').glob('*.sr'))
    assert not list(case.subdir('signals').glob('*.part'))


async def test_uart_new_pin_blocks_tx_but_read_close_work(auth, monkeypatch):
    from uart_mcp import server as S
    rt = S.rt(); case = rt.cases.create(title='합성 UART', authorization=auth)
    master, slave = os.openpty()
    try:
        async with Client(S.server) as client:
            opened = await call(client, 'uart_open', case_id=case.id, port=os.ttyname(slave))
            assert opened['ok'], opened
            sid = opened['session_id']
            approve_pin(rt)
            monkeypatch.setattr(G, 'probe_identity', lambda *a, **k: snapshot())
            result = await call(client, 'uart_write', session_id=sid, data='\x03')
            assert 'instrument_port' in result['_error']
            assert (await call(client, 'uart_read', session_id=sid))['ok']
            assert (await call(client, 'uart_close', session_id=sid))['ok']
            assert S._SESSIONS[sid].tx_bytes == 0 if sid in S._SESSIONS else True
    finally:
        os.close(master); os.close(slave)


async def test_jtagulator_new_pin_closes_without_resync(sim_env, auth, monkeypatch):
    from jtagulator_mcp import server as S
    sim, srv = sim_env()
    rt = S.rt(); case = rt.cases.create(title='합성 JTAGulator', authorization=auth)
    async with Client(S.server) as client:
        opened = await call(client, 'jtagulator_connect', case_id=case.id, port=srv.url)
        assert opened['ok'], opened
        conn = S._get_conn(case.id); before = conn.link.tx_bytes
        approve_pin(rt)
        monkeypatch.setattr(G, 'probe_identity', lambda *a, **k: snapshot())
        result = await call(client, 'jtagulator_version', case_id=case.id)
        assert 'instrument_port' in result['_error'] and conn.link.tx_bytes == before
        assert (await call(client, 'jtagulator_status', case_id=case.id))['ok']
        assert (await call(client, 'jtagulator_disconnect', case_id=case.id))['ok']


async def test_esp_second_read_guard_keeps_first_unverified(esp_fake, auth, monkeypatch):
    from esp_mcp import server as S
    rt = S.rt(); case = rt.cases.create(title='합성 이중 읽기', authorization=auth)
    approve_pin(rt)
    calls = []
    def sequence(*a, **k):
        calls.append(1); return snapshot(len(calls) >= 3)
    monkeypatch.setattr(G, 'probe_identity', sequence)
    async with Client(S.server) as client:
        start = await call(client, 'esp_read_flash_start', case_id=case.id, port='/dev/ttyACM123', size=4096)
        assert 'job_id' in start, start
        status = await call(client, 'esp_job_status', job_id=start['job_id'], wait_seconds=10)
    assert status['status'] == 'failed' and status['error']['code'] == 'instrument_port'
    assert len(esp_fake.calls('read-flash')) == 1
    assert not S._ACTIVE_RESERVATIONS
    assert not list(case.subdir('dumps').glob('*.partial'))
    import json
    meta = json.loads(next(case.subdir('dumps').glob('*.json')).read_text())
    assert meta['verification']['method'] == 'none'
    assert not meta.get('provenance', {}).get('recorded')


def test_baud_second_guard_not_swallowed(monkeypatch):
    from uart_mcp import baud
    from pweh.errors import PwehError
    calls = []
    closed = []
    class FakeSerial:
        def reset_input_buffer(self): pass
        def read(self, size): return b''
        def close(self): closed.append(1)
    def guard():
        calls.append(1)
        if len(calls) == 2:
            raise PwehError('합성 거부', code='instrument_port')
    monkeypatch.setattr(baud, 'open_serial', lambda *a, **k: FakeSerial())
    with pytest.raises(PwehError, match='instrument_port'):
        baud.detect('/dev/synthetic', [9600, 115200], 0.001, 'none', early_stop=False, before_io=guard)
    assert len(calls) == 2 and len(closed) == 1


async def test_jtagulator_cancel_after_pin_sends_no_abort(sim_env, workspace, auth, monkeypatch):
    from jtagulator_mcp import server as S
    from servers.test_jtagulator_mcp import set_voltage_approved
    workspace['set_safety'](destructive_policy='approve', approval_methods=['cli'])
    sim, srv = sim_env()
    rt = S.rt(); case = rt.cases.create(title='합성 스캔 취소', authorization=auth)
    async with Client(S.server) as client:
        assert (await call(client, 'jtagulator_connect', case_id=case.id, port=srv.url))['ok']
        await set_voltage_approved(client, case.id)
        start = await call(client, 'jtagulator_uart_txd_scan', case_id=case.id, start_channel=0, end_channel=7, duration_seconds=30)
        assert 'job_id' in start, start
        conn = S._get_conn(case.id); before = conn.link.tx_bytes
        approve_pin(rt)
        monkeypatch.setattr(G, 'probe_identity', lambda *a, **k: snapshot())
        await call(client, 'jtagulator_job_cancel', job_id=start['job_id'])
        status = await call(client, 'jtagulator_job_status', job_id=start['job_id'], wait_seconds=10)
        assert status['status'] == 'failed' and status['error']['code'] == 'instrument_port'
        assert conn.link.tx_bytes == before and not conn.link.alive
        assert (await call(client, 'jtagulator_disconnect', case_id=case.id))['ok']
