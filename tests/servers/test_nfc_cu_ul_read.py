"""합성 CU와 실제 Client로 Ultralight 계열 페이지 읽기 job의 wire·멈춤 규칙·소유 증명 재확인·원장 결속을 검사한다.

사람 증명은 격리 상태의 저장소 API(decide/revoke)로만 답한다. 실제 `pweh attest`·장치·포트는 쓰지 않는다.
fake는 사람 증명 전 READ, f4 이외 option, 금지 opcode, 보류·키 페이지 READ, UL frame 뒤 켜진 field를 위반으로 기록한다.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import stat
import time

import pytest
from mcp import Client

from mcp_helpers import call
from pweh import cu_protocol as C, nfc_cu_ul_snapshot as UN, schemas
import pweh.safety.attestations as att_mod
from nfc_mcp import server as S, cu_owner as O, cu_read as R
from .fake_cu import (setup as cu_setup, FakeCu, UID, UL_FAMILY_OF, UL_MODELS, DENIED, VERSION_WIRE, TICKET_UID,
                      ul_pages)

pytestmark = pytest.mark.anyio
SCAN_WIRE = [(1002, b''), (2000, b''), (2010, VERSION_WIRE)]
LAST = {'mf0icu1': 43, 'mf0icu1-silent': 43, 'mf0icu2': 43, 'mf0ul11': 17, 'mf0ulh11': 17,
        'mf0ul21': 38, 'mf0ulh21': 38}
RECEIPT_KEYS = {'ok', 'registered', 'status', 'artifact', 'provenance', 'tag_ref', 'family', 'pages_total',
                'pages_observed', 'read_complete', 'stop_reason', 'read_end', 'observed_variant', 'attestation_id',
                'inventory_binding_verified', 'physical_same_tag_verified', 'warnings'}
# receipt 안쪽 dict의 정확한 키 — 원시 UID·페이지가 들어갈 자리가 없다(설계 개정 E).
RECEIPT_NESTED_KEYS = {'artifact': {'artifact_id', 'path', 'size', 'sha256'},
                       'provenance': {'kind', 'ledger_seq', 'ledger_entry_sha256'}, 'read_end': {'kind', 'page'}}


def assert_receipt_shape(receipt):
    assert set(receipt) == RECEIPT_KEYS
    for key, keys in RECEIPT_NESTED_KEYS.items():
        assert set(receipt[key]) == keys, (key, receipt[key])


def observed_page_hex(model, receipt, pages=None):
    """receipt가 관찰했다고 한 page 0..k-1의 hex 전부(page 0–3 포함). 결과·로그에 하나도 없어야 한다."""
    pages = ul_pages(model, UID) if pages is None else pages
    return [page.hex() for page in pages[:receipt['pages_observed']]]


@pytest.fixture
def anyio_backend():
    return 'asyncio'


def read_wire(page):
    return (2010, bytes.fromhex('f40064001030') + bytes((page,)))


def decide(env, aid, answer='yes', via='cli-tty'):
    return env.runtime.attestations.decide(aid, {'owned_tag': answer}, via=via)


async def connect(client, env):
    result = await call(client, 'nfc_cu_connect', case_id=env.case.id, port=env.port)
    assert result.get('ok'), result
    return O.get_cu_session(env.case.id, result['session_id'])


async def inventory(client, env, owner):
    """UL scan(증명 요청)→decide→재호출→inventory. READ는 아직 허용하지 않는다."""
    first = await call(client, 'nfc_cu_ul_scan', case_id=env.case.id, session_id=owner.session_id)
    assert first.get('status') == 'attestation_required', first
    decide(env, first['attestation_id'])
    scan = await call(client, 'nfc_cu_ul_scan', case_id=env.case.id, session_id=owner.session_id)
    assert scan.get('ok'), scan
    inv = await call(client, 'nfc_tag_inventory_add', case_id=env.case.id, scan_ref=scan['scan_ref'])
    assert inv.get('ok'), inv
    assert env.fake.ul_reads() == []
    return inv


async def prepare(client, env, monkeypatch, model='mf0ul11', **kwargs):
    env.fake = FakeCu(ul=model, **kwargs)
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    monkeypatch.setattr(S, 'get_runtime', lambda name: env.runtime)
    owner = await connect(client, env)
    inv = await inventory(client, env, owner)
    env.fake.ul_reads_allowed = True
    return owner, inv


async def start(client, env, owner, inv, **kwargs):
    return await call(client, 'nfc_cu_read_start', case_id=env.case.id, session_id=owner.session_id,
                      tag_ref=inv['tag_ref'], **kwargs)


async def wait(client, env, started):
    assert started.get('ok'), started
    status = await call(client, 'nfc_job_status', job_id=started['job_id'], wait_seconds=10, case_id=env.case.id)
    assert status.get('ok') and status['status'] not in ('queued', 'running', 'cancelling'), status
    return status


async def read(client, env, owner, inv):
    return await wait(client, env, await start(client, env, owner, inv))


async def disconnect(client, env, owner):
    out = await call(client, 'nfc_cu_disconnect', case_id=env.case.id, session_id=owner.session_id)
    assert out['ok'], out


def snapshot_of(env, job):
    row = job['result']['artifact']
    path = env.case.dir / row['path']
    data = path.read_bytes()
    assert stat.S_IMODE(path.stat().st_mode) == 0o444
    assert hashlib.sha256(data).hexdigest() == row['sha256'] and len(data) == row['size']
    value = json.loads(data)
    schemas.validate('nfc-cu-ul-snapshot', value)
    UN.parse_cu_ul_snapshot(data, deadline=time.monotonic() + 5)
    return value


def device_reads(env):
    return [e for e in env.runtime.provenance.entries(env.case) if e.get('kind') == 'device-read']


def read_frames(fake):
    """connect·scan 뒤 마지막 job의 frame들. 첫 1002부터 센다."""
    commands = fake.commands
    starts = [i for i, c in enumerate(commands) if c == (1002, b'')]
    return commands[starts[-1]:]


def assert_wire_clean(fake):
    sent = {command for command, _ in fake.commands}
    assert not sent & DENIED
    assert all(payload[0] == 0xf4 for command, payload in fake.commands if command == 2010)
    assert all(field is False for _, _, field in fake.field_log)


@pytest.mark.parametrize('model', sorted(UL_MODELS))
@pytest.mark.parametrize('cu_setup', ['posix-tty', 'win-helper'], indirect=True)
async def test_exact_frame_sequence_and_complete_or_rollover_read(cu_setup, monkeypatch, caplog, model):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, model)
        job = await read(client, env, owner, inv)
        assert job['status'] == 'succeeded', job
        receipt = job['result']
        assert_receipt_shape(receipt)
        assert receipt['registered'] is True
        family = UL_FAMILY_OF[model]
        spec = C.UL_SPECS[family]
        assert receipt['family'] == family and receipt['pages_total'] == spec.pages_total
        if model in ('mf0icu1', 'mf0icu1-silent'):
            # 원조 UL은 0x10에서 NAK, 직전 응답이 page0–2로 roll-over → 완료, 변형은 모호(0x10 정확).
            expected_pages = list(range(0x11))
            assert receipt['read_end'] == {'kind': 'nak_with_rollover', 'page': 0x10}
            assert receipt['observed_variant'] == 'ultralight_or_ultralight_c'
            assert receipt['pages_observed'] == 0x10
        else:
            expected_pages = list(range(spec.last_target + 1))
            assert receipt['read_end'] == {'kind': 'end_of_targets', 'page': None}
            assert receipt['pages_observed'] == spec.last_target + 1
            assert receipt['observed_variant'] == ('ultralight_c' if model == 'mf0icu2' else family)
        assert receipt['read_complete'] is True and receipt['stop_reason'] is None and receipt['status'] == 'ok'
        assert read_frames(env.fake) == SCAN_WIRE + [read_wire(p) for p in expected_pages]
        assert env.fake.ul_reads() == expected_pages
        assert not set(env.fake.ul_reads()) & set(spec.withheld_pages)
        assert max(env.fake.ul_reads()) < 0x2c
        snap = snapshot_of(env, job)
        assert snap['attestation'] == {'kind': 'tag-ownership', 'attestation_id': inv['attestation']['attestation_id']}
        assert snap['binding']['ul_tag_ref'] == inv['tag_ref'] and snap['reader'] == C.UL_READ.reader()
        pages = ul_pages(model, UID)
        for index, value in enumerate(snap['pages']):
            if index < receipt['pages_observed']:
                assert value == pages[index].hex()
            else:
                assert value is None
        rows = device_reads(env)
        assert len(rows) == 1 and rows[0]['attestation_id'] == inv['attestation']['attestation_id']
        assert rows[0]['path'] == receipt['artifact']['path'] and rows[0]['path'].startswith('nfc/cu-ul-read-')
        assert owner.state == 'ready' and not owner._uses
        assert_wire_clean(env.fake)
        await disconnect(client, env, owner)
    visible = json.dumps(job) + caplog.text
    secrets = observed_page_hex(model, receipt)
    assert len(secrets) == receipt['pages_observed'] >= 16
    for secret in (UID.hex(), *secrets, 'reader_binding', 'CU_SYNTHETIC'):
        assert secret not in visible, secret


async def finished_partial(client, env, owner, inv):
    job = await read(client, env, owner, inv)
    assert job['status'] == 'succeeded', job
    assert_receipt_shape(job['result'])
    for secret in observed_page_hex(None, job['result'], env.fake.ul_pages):
        assert secret not in json.dumps(job), secret
    return job['result']


@pytest.mark.parametrize('auth0,boundary,variant', [
    (0x03, 0x03, 'ultralight_c'), (0x08, 0x08, 'ultralight_c'),
    (0x10, 0x10, 'ultralight_or_ultralight_c'), (0x2a, 0x2a, 'ultralight_c')])
async def test_ultralight_c_auth0_read_protection_matrix(cu_setup, monkeypatch, auth0, boundary, variant):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0icu2', auth0=auth0, prot=True)
        receipt = await finished_partial(client, env, owner, inv)
        assert receipt['read_end'] == {'kind': 'nak_with_rollover', 'page': boundary}
        assert receipt['pages_observed'] == boundary and receipt['read_complete'] is True
        assert receipt['observed_variant'] == variant and receipt['status'] == 'ok'
        assert env.fake.ul_reads() == list(range(boundary + 1))
        snap = snapshot_of(env, {'result': receipt})
        assert all(value is None for value in snap['pages'][boundary:])
        assert owner.state == 'ready'
        await disconnect(client, env, owner)


async def test_ultralight_c_auth0_beyond_user_memory_reads_all_targets(cu_setup, monkeypatch):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0icu2', auth0=0x30, prot=True)
        receipt = await finished_partial(client, env, owner, inv)
        assert receipt['read_end'] == {'kind': 'end_of_targets', 'page': None} and receipt['pages_observed'] == 44
        assert receipt['observed_variant'] == 'ultralight_c' and len(read_frames(env.fake)) == 47
        snap = snapshot_of(env, {'result': receipt})
        assert snap['pages'][44:] == [None] * 4 and snap['withheld_pages'] == {'key_never_readable': [44, 45, 46, 47]}
        await disconnect(client, env, owner)


@pytest.mark.parametrize('model', ['mf0ul11', 'mf0ul21'])
@pytest.mark.parametrize('auth0', [0x00, 0x01, 0x04, 0x10, 0x12, 0xff])
@pytest.mark.parametrize('prot', [False, True])
async def test_ev1_auth0_prot_matrix(cu_setup, monkeypatch, model, auth0, prot):
    env = cu_setup
    spec = C.UL_SPECS[UL_FAMILY_OF[model]]
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, model, auth0=auth0, prot=prot)
        job = await read(client, env, owner, inv)
        boundary = min(auth0, spec.pages_total) if prot else spec.pages_total
        if boundary < 3:
            # AUTH0 ≤ 2와 READ 보호: UID 페이지를 검증할 수 없으므로 snapshot·device-read 없이 끝나고 terminal이다.
            assert job['status'] == 'failed' and 'nfc_identity_mismatch' in json.dumps(job), job
            assert device_reads(env) == [] and not env.case.load()['artifacts']
            assert owner.state == 'terminal'
            # 경계가 0이면 READ0이 NAK, 1–2면 READ0 응답의 뒤 바이트가 roll-over라 UID/BCC 대조에서 멈춘다.
            assert env.fake.ul_reads() == [0]
        elif boundary > spec.last_target:
            receipt = job['result']
            assert receipt['read_end'] == {'kind': 'end_of_targets', 'page': None}
            assert receipt['pages_observed'] == spec.last_target + 1 and receipt['read_complete'] is True
            assert env.fake.ul_reads() == list(range(spec.last_target + 1))
            snap = snapshot_of(env, job)
            # PWD/PACK는 요청하지 않고 null로 보류한다(응답 뒤 12B의 00h도 보관하지 않는다).
            assert snap['pages'][spec.last_target + 1:] == [None, None]
            assert owner.state == 'ready'
        else:
            receipt = job['result']
            assert receipt['read_end'] == {'kind': 'nak_with_rollover', 'page': boundary}
            assert receipt['read_complete'] is True and receipt['pages_observed'] == boundary
            assert receipt['observed_variant'] == spec.family and owner.state == 'ready'
            assert env.fake.ul_reads() == list(range(boundary + 1))
        assert not set(env.fake.ul_reads()) & set(spec.withheld_pages)
        assert_wire_clean(env.fake)
        await disconnect(client, env, owner)


async def test_owned_used_ev1_ticket_ends_at_auth0_nak_with_pwd_pack_null(cu_setup, monkeypatch):
    """사용자 소유의 사용한 EV1 MF0UL11 종이 승차권(합성): AUTH0 보호 위에서 NAK로 끝난 부분 snapshot이 정상 결과다."""
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11', uid=TICKET_UID, auth0=0x10, prot=True,
                                   no_rollover=True)
        receipt = await finished_partial(client, env, owner, inv)
        assert receipt['read_end'] == {'kind': 'nak_without_rollover', 'page': 0x10}
        assert receipt['stop_reason'] == 'tag_nak' and receipt['status'] == 'partial'
        assert receipt['read_complete'] is False and owner.state == 'ready'
        snap = snapshot_of(env, {'result': receipt})
        assert snap['pages'][0x10:] == [None] * 4 and snap['withheld_pages'] == {'pwd_pack_readback_zero': [18, 19]}
        assert TICKET_UID.hex() not in json.dumps(receipt)
        await disconnect(client, env, owner)


async def test_tag_swap_mid_read_is_identity_mismatch_without_file_or_ledger(cu_setup, monkeypatch):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul21', swap_after_page=6)
        job = await read(client, env, owner, inv)
        assert job['status'] == 'failed' and 'nfc_identity_mismatch' in json.dumps(job), job
        assert env.fake.ul_reads() == list(range(8)) and env.fake.ul_reads()[-1] == 7
        assert device_reads(env) == [] and not env.case.load()['artifacts']
        assert not list((env.case.dir / 'nfc').glob('cu-ul-read-*'))
        assert owner.state == 'terminal'
        await disconnect(client, env, owner)


@pytest.mark.parametrize('mutation', ['uid', 'bcc0', 'bcc1'])
async def test_page0_uid_bcc_checks(cu_setup, monkeypatch, mutation):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11')
        index, offset = {'uid': (1, 2), 'bcc0': (0, 3), 'bcc1': (2, 0)}[mutation]
        page = bytearray(env.fake.ul_pages[index])
        page[offset] ^= 0x01
        env.fake.ul_pages[index] = bytes(page)
        job = await read(client, env, owner, inv)
        assert job['status'] == 'failed' and 'nfc_identity_mismatch' in json.dumps(job), job
        assert env.fake.ul_reads() == [0] and device_reads(env) == []
        await disconnect(client, env, owner)


@pytest.mark.parametrize('status', [0x01, 0x03, 0x07])
@pytest.mark.parametrize('page', [1, 2, 5])
async def test_rf_error_publishes_validated_prefix_only_from_three_pages(cu_setup, monkeypatch, status, page):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul21', inject={page: (status, b'')})
        job = await read(client, env, owner, inv)
        assert env.fake.ul_reads() == list(range(page + 1))
        assert owner.state == 'terminal'
        if page < 3:
            assert job['status'] == 'failed' and 'nfc_scan_invalid' in json.dumps(job), job
            assert device_reads(env) == [] and not env.case.load()['artifacts']
        else:
            receipt = job['result']
            assert job['status'] == 'succeeded' and receipt['stop_reason'] == 'nfc_scan_invalid', job
            assert receipt['read_end'] == {'kind': 'stopped', 'page': page} and receipt['pages_observed'] == page
            assert receipt['status'] == 'partial' and receipt['registered'] is True
            snapshot_of(env, job)
        await disconnect(client, env, owner)


async def test_wrong_length_reply_is_rf_error(cu_setup, monkeypatch):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11', inject={4: (0x00, bytes(8))})
        receipt = await finished_partial(client, env, owner, inv)
        assert receipt['stop_reason'] == 'nfc_scan_invalid' and receipt['read_end'] == {'kind': 'stopped', 'page': 4}
        assert owner.state == 'terminal'
        await disconnect(client, env, owner)


async def test_two_byte_garbage_is_indistinguishable_from_nak(cu_setup, monkeypatch):
    """check_crc에서 3B 미만 응답은 status0·빈 payload라 4bit NAK와 같다(문서화한 한계). roll-over 근거가 없어 tag_nak 부분이다."""
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul21', inject={9: (0x00, b'')})
        receipt = await finished_partial(client, env, owner, inv)
        assert receipt['read_end'] == {'kind': 'nak_without_rollover', 'page': 9}
        assert receipt['stop_reason'] == 'tag_nak' and owner.state == 'ready'
        await disconnect(client, env, owner)


async def test_clone_without_rollover_is_partial_tag_nak(cu_setup, monkeypatch):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0icu1', no_rollover=True)
        receipt = await finished_partial(client, env, owner, inv)
        assert receipt['read_end'] == {'kind': 'nak_without_rollover', 'page': 0x10}
        assert receipt['stop_reason'] == 'tag_nak' and receipt['read_complete'] is False
        await disconnect(client, env, owner)


async def test_coincident_user_pages_still_read_correctly(cu_setup, monkeypatch):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11', coincident=True)
        job = await read(client, env, owner, inv)
        receipt = job['result']
        assert receipt['read_end'] == {'kind': 'end_of_targets', 'page': None} and receipt['pages_observed'] == 18
        snap = snapshot_of(env, job)
        assert snap['pages'][4:7] == snap['pages'][0:3]
        await disconnect(client, env, owner)


@pytest.mark.parametrize('page,published', [(2, False), (3, True), (9, True)])
async def test_time_limit_keeps_validated_prefix(cu_setup, monkeypatch, page, published):
    from pweh.errors import PwehError
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul21')
        real = owner._request

        def limited(use, kind, end, **kw):
            if kind == 'ul_read' and kw.get('page') == page:
                raise PwehError('PRIVATE_TIME_SENTINEL', code='time_limit')
            return real(use, kind, end, **kw)

        monkeypatch.setattr(owner, '_request', limited)
        job = await read(client, env, owner, inv)
        assert owner.state == 'terminal'
        if published:
            receipt = job['result']
            assert_receipt_shape(receipt)
            assert receipt['stop_reason'] == 'time_limit' and receipt['read_end'] == {'kind': 'stopped', 'page': page}
            assert receipt['pages_observed'] == page
            for secret in (UID.hex(), *observed_page_hex(None, receipt, env.fake.ul_pages)):
                assert secret not in json.dumps(job), secret
        else:
            assert job['status'] == 'failed' and 'time_limit' in json.dumps(job), job
            assert device_reads(env) == []
        assert 'PRIVATE_TIME_SENTINEL' not in json.dumps(job)
        await disconnect(client, env, owner)


async def test_read_time_version_must_match_inventory_family(cu_setup, monkeypatch):
    """원조 UL/UL C inventory인데 READ 직전 8B version이 오면 READ 없이 identity mismatch다."""
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0icu1')
        env.fake.version_status, env.fake.version = 0, bytes.fromhex('0004030101000b03')
        job = await read(client, env, owner, inv)
        assert job['status'] == 'failed' and 'nfc_identity_mismatch' in json.dumps(job), job
        assert env.fake.ul_reads() == [] and read_frames(env.fake) == SCAN_WIRE
        env.fake.version_status, env.fake.version = 0x03, b''
        await disconnect(client, env, owner)


async def test_revocation_before_wire_sends_zero_frames(cu_setup, monkeypatch):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11')
        real = R.CuUlReadWork.start

        def revoke_then_start(work):
            env.runtime.attestations.revoke(work.attestation_id)
            return real(work)

        monkeypatch.setattr(R.CuUlReadWork, 'start', revoke_then_start)
        before = len(env.fake.commands)
        job = await read(client, env, owner, inv)
        assert job['status'] == 'failed' and 'nfc_attestation_required' in json.dumps(job), job
        assert len(env.fake.commands) == before and env.fake.ul_reads() == []
        assert device_reads(env) == [] and owner.state == 'ready' and not owner._uses
        await disconnect(client, env, owner)


async def test_revocation_after_wire_blocks_ledger_append(cu_setup, monkeypatch):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11')
        real = owner.read_ultralight

        def then_revoke(*args, **kwargs):
            result = real(*args, **kwargs)
            env.runtime.attestations.revoke(inv['attestation']['attestation_id'])
            return result

        monkeypatch.setattr(owner, 'read_ultralight', then_revoke)
        job = await read(client, env, owner, inv)
        assert job['status'] == 'failed' and 'nfc_attestation_required' in json.dumps(job), job
        assert env.fake.ul_reads() == list(range(18))
        assert device_reads(env) == [] and not env.case.load()['artifacts']
        assert not list((env.case.dir / 'nfc').glob('cu-ul-read-*'))
        await disconnect(client, env, owner)


@pytest.mark.parametrize('mode', ['expired', 'revoked', 'denied-retry'])
async def test_read_start_requires_current_ownership_before_any_reservation(cu_setup, monkeypatch, mode):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11')
        aid = inv['attestation']['attestation_id']
        if mode == 'expired':
            real_now = att_mod._now
            monkeypatch.setattr(att_mod, '_now', lambda: real_now() + dt.timedelta(days=8))
        else:
            env.runtime.attestations.revoke(aid)
        before = len(env.fake.commands)
        out = await start(client, env, owner, inv)
        assert out.get('ok') is False and out['status'] == 'attestation_required', out
        assert out['kind'] == 'tag-ownership' and out['page_reads_sent'] is False and out['job_started'] is False
        assert out['tag_ref'] == inv['tag_ref'] and out['family'] == 'ultralight_ev1_mf0ul11'
        assert len(env.fake.commands) == before and not owner._uses and owner.state == 'ready'
        assert env.runtime.jobs.list() == []
        if mode == 'denied-retry':
            assert decide(env, out['attestation_id'], answer='no')['status'] == 'denied'
            again = await start(client, env, owner, inv)
            assert again.get('ok') is False and again['previous']['status'] in ('denied', 'revoked'), again
            assert any(r['status'] == 'denied' for r in env.runtime.attestations.list(case_id=env.case.id))
            assert len(env.fake.commands) == before and env.runtime.jobs.list() == []
        await disconnect(client, env, owner)


async def test_reattested_id_differs_from_inventory_id_and_is_recorded(cu_setup, monkeypatch):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11')
        env.runtime.attestations.revoke(inv['attestation']['attestation_id'])
        pending = await start(client, env, owner, inv)
        decide(env, pending['attestation_id'], via='elicitation')
        job = await read(client, env, owner, inv)
        assert job['status'] == 'succeeded', job
        assert job['result']['attestation_id'] == pending['attestation_id'] != inv['attestation']['attestation_id']
        assert device_reads(env)[0]['attestation_id'] == pending['attestation_id']
        assert snapshot_of(env, job)['attestation']['attestation_id'] == pending['attestation_id']
        await disconnect(client, env, owner)


async def test_read_start_attests_without_ctx_and_without_cu_use(cu_setup, monkeypatch):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11')
        seen = []
        real = env.runtime.attest

        async def spy(kind, subject, binding, questions, case_id=None, ctx='MISSING', summary=None, **kw):
            seen.append((kw.get('tool'), kind, ctx, bool(owner._uses), json.dumps(subject) + str(summary)))
            return await real(kind, subject, binding, questions, case_id, ctx, summary, **kw)

        monkeypatch.setattr(env.runtime, 'attest', spy)
        job = await read(client, env, owner, inv)
        assert job['status'] == 'succeeded', job
        assert seen and all(row[0] == 'nfc_cu_read_start' for row in seen)
        for tool, kind, ctx, busy, text in seen:
            assert kind == 'tag-ownership' and ctx is None and busy is False and UID.hex() not in text
        await disconnect(client, env, owner)


@pytest.mark.parametrize('policy', ['approve', 'deny'])
async def test_gate_pending_or_denied_releases_reservation_without_frames(cu_setup, monkeypatch, policy):
    from pweh.runtime import get_runtime
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul21')
        env.workspace['set_safety'](modify_policy=policy)
        configured = get_runtime('cu-test')
        monkeypatch.setattr(env.runtime, 'authorize', configured.authorize)
        before = list(env.fake.commands)
        out = await start(client, env, owner, inv)
        assert out['status'] == ('approval_required' if policy == 'approve' else 'denied'), out
        assert out['gate']['classification']['rule_id'] == 'cu.ul-read'
        assert env.fake.commands == before and not owner._uses and owner.state == 'ready'
        assert env.runtime.jobs.list() == []
        if policy == 'approve':
            record = env.runtime.approvals.get(out['approval_id'])
            action = record['action']
            spec = C.UL_SPECS['ultralight_ev1_mf0ul21']
            assert action['operation'] == 'ul_read' and action['raw_option'] == 'f4'
            assert action['activation_per_page'] is True and action['family'] == spec.family
            assert (action['pages_total'], action['read_last_target']) == (41, 38)
            assert action['withheld_pages'] == {'pwd_pack_readback_zero': [39, 40]}
            assert action['ul_profile_sha256'] == C.UL_READ.profile_sha256
            assert action['attestation_id'] == inv['attestation']['attestation_id']
            assert action['ul_tag_ref'] == inv['tag_ref'] and 'ul_identity_digest' not in action
            assert UID.hex() not in json.dumps(record)
            env.runtime.approvals.decide(out['approval_id'], approve=True, code=record['code'], via='cli-tty')
            job = await wait(client, env, await start(client, env, owner, inv, approval_id=out['approval_id']))
            assert job['status'] == 'succeeded', job
        await disconnect(client, env, owner)


async def test_disconnect_cancels_running_ultralight_job(cu_setup, monkeypatch):
    import asyncio
    import threading
    env = cu_setup
    entered, release = threading.Event(), threading.Event()
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul21')

        def blocked(size):
            if env.fake.ul_log:
                entered.set()
                assert release.wait(3)

        env.fake.before_read = blocked
        started = await start(client, env, owner, inv)
        for _ in range(400):
            if entered.is_set():
                break
            await asyncio.sleep(.005)
        assert entered.is_set()
        job = env.runtime.jobs.get(started['job_id'])
        assert job.kind == 'nfc-cu-read' and job.meta['session_id'] == owner.session_id
        try:
            task = asyncio.create_task(disconnect(client, env, owner))
            for _ in range(400):
                if job._cancel.is_set():
                    break
                await asyncio.sleep(.005)
            assert job._cancel.is_set()
        finally:
            env.fake.before_read = None
            release.set()
        await task
        status = await call(client, 'nfc_job_status', job_id=started['job_id'], wait_seconds=5)
        assert status['status'] == 'cancelled' and status.get('result') is None, status
        assert device_reads(env) == [] and not env.case.load()['artifacts']


async def test_ntag_read_in_case_with_ul_rows_is_unchanged(cu_setup, monkeypatch):
    """같은 케이스에 UL scan·inventory·snapshot 행이 있어도 NTAG 읽기는 기존 이름·결과 그대로다."""
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11')
        ul_job = await read(client, env, owner, inv)
        assert ul_job['status'] == 'succeeded', ul_job
        env.fake.ul = None
        env.fake.version_status, env.fake.version = 0, bytes.fromhex('0004040201000f03')
        scan = await call(client, 'nfc_cu_scan', case_id=env.case.id, session_id=owner.session_id)
        assert scan.get('ok'), scan
        nt = await call(client, 'nfc_tag_inventory_add', case_id=env.case.id, scan_ref=scan['scan_ref'])
        assert nt.get('ok') and nt['tag_ref'].startswith('NT-'), nt
        job = await wait(client, env, await call(client, 'nfc_cu_read_start', case_id=env.case.id,
                                                 session_id=owner.session_id, tag_ref=nt['tag_ref']))
        assert job['status'] == 'succeeded' and job['result']['artifact']['path'] == 'nfc/cu-read-001.json', job
        assert 'read_end' not in job['result'] and 'attestation_id' not in job['result']
        ntag_rows = [e for e in device_reads(env) if e['path'] == 'nfc/cu-read-001.json']
        assert len(ntag_rows) == 1 and ntag_rows[0]['attestation_id'] is None
        await disconnect(client, env, owner)


async def test_auto_allowed_tools_refuse_written_ul_snapshot(cu_setup, monkeypatch):
    """서버가 쓴 nfc/cu-ul-read-NNN.json(원시 UID·페이지)은 자동 허용 pweh-fwtriage·pweh-case 도구가 읽거나 훑지 않는다
    (리뷰 재현: fw_strings_hunt 의 lit:UID·pages 정규식). pweh-nfc 의 전용 분석은 그대로 같은 파일을 받는다."""
    from fwtriage_mcp.server import server as fw_server
    from case_mcp.server import server as case_server
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11')
        job = await read(client, env, owner, inv)
        assert job['status'] == 'succeeded', job
        path = job['result']['artifact']['path']
        assert path == 'nfc/cu-ul-read-001.json'
        await disconnect(client, env, owner)
        parsed = await call(client, 'nfc_parse_file', case_id=env.case.id, artifact_id=job['result']['artifact']['artifact_id'],
                            tag_ref=inv['tag_ref'])
        assert parsed.get('ok'), parsed
    pages = ul_pages('mf0ul11', UID)
    patterns = [f'lit:{UID.hex()}', r're:"pages":\[[^\]]*\]']
    async with Client(fw_server) as fw:
        for target in (path, str(env.case.dir / path), 'nfc', '.'):
            r = await call(fw, 'fw_strings_hunt', case_id=env.case.id, path_or_dir=target, patterns=patterns)
            assert 'validation_failed' in r.get('_error', '') and 'CU 페이지 스냅샷' in r['_error'], (target, r)
            assert UID.hex() not in json.dumps(r) and pages[4].hex() not in json.dumps(r)
    async with Client(case_server) as cs:
        r = await call(cs, 'case_hash_file', case_id=env.case.id, path=path)
        assert 'validation_failed' in r.get('_error', '') and 'CU 페이지 스냅샷' in r['_error'], r


@pytest.mark.parametrize('failure', ['revoke-at-register-check', 'register-raises'])
async def test_registration_window_keeps_ledger_row_and_file_with_registered_false(cu_setup, monkeypatch, failure):
    """원장 append 뒤 artifact 등록이 실패하면(등록 check 안의 철회, 등록 예외) device-read 행 하나와 0444 snapshot은 남고
    job은 실패하며 partial receipt는 registered=false·artifact_id null·artifact_registration_incomplete다. artifact 행은 없다."""
    from pweh.case import Case
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11')
        aid = inv['attestation']['attestation_id']
        original = Case.register_artifact

        def changed(case, path, **kw):
            if kw.get('extra', {}).get('type') == 'nfc-cu-ul-snapshot':
                if failure == 'register-raises':
                    raise RuntimeError('PRIVATE-REGISTER-FAILURE')
                # 원장 append 뒤·등록 check(final) 전에 철회한다 — final의 증명 재확인만 이것을 잡는다.
                env.runtime.attestations.revoke(aid)
            return original(case, path, **kw)

        monkeypatch.setattr(Case, 'register_artifact', changed)
        job = await read(client, env, owner, inv)
        code = 'nfc_attestation_required' if failure == 'revoke-at-register-check' else 'nfc_artifact_registration_failed'
        assert job['status'] == 'failed' and code in json.dumps(job), job
        receipt = job['result']
        assert_receipt_shape(receipt)
        assert receipt['ok'] is False and receipt['registered'] is False
        assert receipt['artifact']['artifact_id'] is None and receipt['attestation_id'] == aid
        assert 'artifact_registration_incomplete' in receipt['warnings']
        for secret in ('PRIVATE-REGISTER-FAILURE', UID.hex(), *observed_page_hex('mf0ul11', receipt)):
            assert secret not in json.dumps(job), secret
        rows = device_reads(env)
        assert len(rows) == 1 and rows[0]['attestation_id'] == aid and rows[0]['path'] == receipt['artifact']['path']
        snap = env.case.dir / receipt['artifact']['path']
        assert snap.exists() and stat.S_IMODE(snap.stat().st_mode) == 0o444
        assert hashlib.sha256(snap.read_bytes()).hexdigest() == receipt['artifact']['sha256']
        assert not [a for a in env.case.load()['artifacts'] if a.get('extra', {}).get('type') == 'nfc-cu-ul-snapshot']
        assert owner.state == 'ready' and not owner._uses
        await disconnect(client, env, owner)


async def test_revocation_between_attest_and_reservation_opens_no_gate(cu_setup, monkeypatch):
    """read_start의 ctx 없는 증명 확인이 충족을 돌려준 직후 철회되면, 예약 단계의 같은 id 동기 재확인이 막는다:
    MODIFY gate·승인 요청·CU 사용권 예약·frame이 없다."""
    from pweh import nfc_ul_inventory as UL
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11')
        real = UL.ul_attest

        async def then_revoke(*args, **kwargs):
            decision = await real(*args, **kwargs)
            assert decision.satisfied
            env.runtime.attestations.revoke(decision.attestation_id)
            return decision

        authorized = []
        real_authorize = env.runtime.authorize

        async def spy(*args, **kwargs):
            authorized.append(kwargs.get('tool'))
            return await real_authorize(*args, **kwargs)

        monkeypatch.setattr(UL, 'ul_attest', then_revoke)
        monkeypatch.setattr(env.runtime, 'authorize', spy)
        before = list(env.fake.commands)
        out = await start(client, env, owner, inv)
        assert 'nfc_attestation_required' in out.get('_error', ''), out
        assert authorized == [] and env.runtime.approvals.list() == []
        assert env.fake.commands == before and not owner._uses and owner.state == 'ready'
        assert env.runtime.jobs.list() == []
        await disconnect(client, env, owner)
