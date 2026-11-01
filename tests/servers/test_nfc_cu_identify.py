"""합성 CU와 실제 Client로 HF 식별·상태 조회의 wire·gate·세션 수명·공개 투영을 검사한다."""
from __future__ import annotations

import asyncio
import json
import threading

import pytest
from mcp import Client

from mcp_helpers import call
from pweh import cu_protocol as C, nfc_inventory as I
from pweh.nfc_formats import _NfcFileIdentity
from pweh.runtime import get_runtime
from nfc_mcp import server as S, cu_tools as T, cu_owner as O
from .fake_cu import (setup as cu_setup, FakeCu, UID, UID4, VERSIONS, TAG_MODELS, SCAN_MODELS, DENIED,
                      VERSION_WIRE, frame)

pytestmark = pytest.mark.anyio
PRIVATE = 'CU_IDENTIFY_PRIVATE_SENTINEL_512'
RESULT_KEYS = {'ok', 'case_id', 'session_id', 'profile', 'family', 'policy', 'uid_length', 'ats_present',
               'get_version_sent', 'page_reads_sent', 'authentication_attempted', 'identity_digest',
               'physical_same_tag_verified', 'rf_off_verified'}
STATUS_KEYS = {'ok', 'case_id', 'session_id', 'battery_mv', 'battery_percent', 'battery_percent_is_estimate',
               'active_slot', 'mode', 'hf14a_config_default', 'app_version', 'git_version', 'model'}
# (fake 인자, family, policy, uid_length, ats_present, GET_VERSION 송신 여부)
CASES = [
    ({'family': 213}, 'ntag213', 'allowed', 7, False, True),
    ({'family': 215}, 'ntag215', 'allowed', 7, False, True),
    ({'family': 216}, 'ntag216', 'allowed', 7, False, True),
    ({'tag': 'ul-ev1'}, 'ultralight_ev1_mf0ul11', 'attestation_required', 7, False, True),
    ({'tag': 'ul-ev1-mf0ulh21'}, 'ultralight_ev1_mf0ulh21', 'attestation_required', 7, False, True),
    ({'tag': 'type2-other-version'}, 'type2_other_version', 'attestation_required', 7, False, True),
    ({'tag': 'mf0icu1-nak'}, 'ultralight_or_ultralight_c', 'attestation_required', 7, False, True),
    ({'tag': 'mf0icu1-timeout'}, 'ultralight_or_ultralight_c', 'attestation_required', 7, False, True),
    ({'tag': 'version-crc-error'}, 'type2_version_unreadable', 'attestation_required', 7, False, True),
    ({'scan': 'none'}, 'none', 'not_applicable', None, None, False),
    ({'scan': 'multiple'}, 'multiple', 'not_applicable', None, None, False),
    ({'scan': 'classic-mini'}, 'mifare_classic_mini', 'attestation_required', 4, False, False),
    ({'scan': 'classic-1k'}, 'mifare_classic_1k', 'attestation_required', 4, False, False),
    ({'scan': 'tnp3xxx'}, 'mifare_classic_tnp3xxx', 'attestation_required', 4, False, False),
    ({'scan': 'classic-4k'}, 'mifare_classic_4k', 'refused', 4, False, False),
    ({'scan': 'classic-2k'}, 'mifare_classic_2k', 'refused', 4, False, False),
    ({'scan': 'iso14443-4'}, 'iso14443_4', 'refused', 7, True, False),
    ({'scan': 'plus-sl2'}, 'mifare_plus_sl2', 'refused', 4, False, False),
    ({'scan': 'other-sak02'}, 'other', 'not_applicable', 4, False, False),
    ({'scan': 'type2-uid4'}, 'other', 'not_applicable', 4, False, False),
]


@pytest.fixture
def anyio_backend():
    return 'asyncio'


def operation(owner, method, *, deadline=None, cancel=None):
    use = owner.reserve_use(cancel=cancel)
    assert use.claim()
    try:
        import time
        return getattr(owner, method)(use, deadline=deadline or time.monotonic() + 45)
    finally:
        use.finish()


def raw_payloads(fake):
    return [payload for command, payload in fake.commands if command == 2010]


def assert_no_read_or_auth(fake):
    # 0x30 READ·0x1A/0x1B 인증·RATS(0xE0) 직접 송신·거부 목록 명령이 한 번도 없다.
    assert fake.reads() == []
    for payload in raw_payloads(fake):
        assert payload == VERSION_WIRE
    assert not any(len(p) > 5 and p[5] in (0x30, 0x1a, 0x1b, 0xe0, 0x3a, 0x3c, 0x39) and p != VERSION_WIRE
                   for p in raw_payloads(fake))
    assert not {command for command, _ in fake.commands} & DENIED


async def connect(client, env):
    result = await call(client, 'nfc_cu_connect', case_id=env.case.id, port=env.port)
    assert result.get('ok'), result
    return O.get_cu_session(env.case.id, result['session_id'])


async def identify(client, env, owner, **kwargs):
    return await call(client, 'nfc_cu_identify', case_id=env.case.id, session_id=owner.session_id, **kwargs)


async def status(client, env, owner):
    return await call(client, 'nfc_cu_status', case_id=env.case.id, session_id=owner.session_id)


async def close(client, env, owner):
    out = await call(client, 'nfc_cu_disconnect', case_id=env.case.id, session_id=owner.session_id)
    assert out['ok'], out
    return out


@pytest.mark.parametrize('kwargs,family,policy,uid_length,ats_present,version_sent', CASES)
@pytest.mark.parametrize('cu_setup', ['posix-tty', 'win-helper'], indirect=True)
async def test_every_family_policy_wire_and_session_stays_ready(cu_setup, monkeypatch, caplog, kwargs, family,
                                                                policy, uid_length, ats_present, version_sent):
    env = cu_setup
    env.fake = FakeCu(**kwargs)
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        first = await identify(client, env, owner)
        assert first.get('ok'), first
        assert set(first) == RESULT_KEYS
        assert (first['family'], first['policy'], first['uid_length'], first['ats_present'],
                first['get_version_sent']) == (family, policy, uid_length, ats_present, version_sent)
        assert first['profile'] == 'cu-hf14a-identify-v2.3.0-v1' == C.IDENTIFY.profile
        assert first['page_reads_sent'] is first['authentication_attempted'] is False
        assert first['physical_same_tag_verified'] is first['rf_off_verified'] is False
        assert (first['identity_digest'] is None) == (family in ('none', 'multiple'))
        expected = [(1002, b''), (2000, b'')] + ([(2010, VERSION_WIRE)] if version_sent else [])
        assert env.fake.commands[4:] == expected
        assert_no_read_or_auth(env.fake)
        # scan의 after-hook과 keep=0 GET_VERSION 뒤 fake field는 꺼진 상태다.
        assert env.fake.field is False and all(field is False for _, _, field in env.fake.field_log)
        # 분류 결과는 terminal이 아니며 같은 세션으로 다시 호출할 수 있다.
        assert owner.state == 'ready' and not owner._uses
        again = await identify(client, env, owner)
        assert again == first and env.fake.commands[4 + len(expected):] == expected
        # scan 사실·inventory·artifact를 만들지 않는다.
        assert env.runtime.provenance.entries(env.case) == []
        assert not env.case.load()['artifacts']
        await close(client, env, owner)
    public = json.dumps([first, again]) + caplog.text
    for value in (UID.hex(), UID4.hex(), UID.hex(' ').upper(), PRIVATE, 'CU_SYNTHETIC',
                  *(v.hex() for v in VERSIONS.values()), *(v[1].hex() for v in TAG_MODELS.values() if v[1])):
        assert value not in public


async def test_ntag_identify_then_existing_scan_on_same_session(cu_setup, monkeypatch):
    env = cu_setup
    env.fake = FakeCu(family=215)
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        found = await identify(client, env, owner)
        assert found['family'] == 'ntag215' and found['policy'] == 'allowed'
        scanned = await call(client, 'nfc_cu_scan', case_id=env.case.id, session_id=owner.session_id)
        assert scanned.get('ok') and scanned['family'] == 'ntag215', scanned
        # 식별 지문은 inventory 지문과 다른 domain이다.
        inventory = await call(client, 'nfc_tag_inventory_add', case_id=env.case.id, scan_ref=scanned['scan_ref'])
        assert inventory.get('ok'), inventory
        assert found['identity_digest'] != inventory['identity_digest']
        await close(client, env, owner)


def test_digest_is_salted_domain_separated_and_never_raw(cu_setup):
    env = cu_setup
    runtime = env.runtime
    scan = C.CuHfScan('type2', UID, b'\x00\x44', 0, 0)
    version = C.CuHfVersion('ntag215', VERSIONS[215])
    digest = T._identify_digest(runtime, env.case.id, 'ntag215', scan, version)
    assert digest.startswith('sha256:') and len(digest) == 23
    assert UID.hex() not in digest and VERSIONS[215].hex() not in digest
    # 같은 UID·ATQA·SAK의 다른 계열은 다른 지문이다.
    other = T._identify_digest(runtime, env.case.id, 'ultralight_or_ultralight_c', scan,
                               C.CuHfVersion('ultralight_or_ultralight_c', None))
    assert other != digest
    # family만 다른 쌍: ATS 길이는 지문 입력이 아니고 version도 둘 다 비어 있으므로
    # 남은 입력(UID 길이·UID·ATQA·SAK·빈 version)이 같다. family domain만 두 지문을 가른다.
    ats_scan = C.CuHfScan('other', UID, b'\x00\x44', 0, 1)
    assert C.classify_cu_scan(C.CuFrame(2000, 0, bytes((7,)) + UID + b'\x44\x00\x00\x01\x01')).scan_class == 'other'
    bare = T._identify_digest(runtime, env.case.id, 'other', ats_scan, None)
    for family in ('ultralight_or_ultralight_c', 'type2_version_unreadable'):
        empty = T._identify_digest(runtime, env.case.id, family, scan, C.CuHfVersion(family, None))
        assert empty != bare
    assert (T._identify_digest(runtime, env.case.id, 'ultralight_or_ultralight_c', scan,
                               C.CuHfVersion('ultralight_or_ultralight_c', None))
            != T._identify_digest(runtime, env.case.id, 'type2_version_unreadable', scan,
                                  C.CuHfVersion('type2_version_unreadable', None)))
    # 기존 inventory 지문(같은 식별값)과도 다르다.
    identity = _NfcFileIdentity(UID, b'\x00\x44', b'\x00', VERSIONS[215], 'iso14443-3a')
    case = runtime.cases.get(env.case.id)
    assert I._digest(runtime, case, identity) != digest
    # 다른 케이스 솔트는 같은 값을 다른 지문으로 만든다.
    other_case = runtime.cases.create(title='합성 다른 케이스', authorization=env.case.load()['authorization'])
    assert T._identify_digest(runtime, other_case.id, 'ntag215', scan, version) != digest
    assert T._identify_digest(runtime, env.case.id, 'none', C.CuHfScan('none', None, None, None, None), None) is None


@pytest.mark.parametrize('fault,code', [
    ('scan-truncated', 'nfc_scan_invalid'), ('scan-two-records', 'nfc_scan_invalid'),
    ('scan-bcc-error', 'nfc_scan_invalid'), ('scan-sak-missing', 'nfc_scan_invalid'),
    ('scan-not-reader', 'nfc_scan_invalid'), ('version-status-02', 'nfc_scan_invalid'),
    ('version-9-bytes', 'nfc_scan_invalid'), ('version-no-frame', 'time_limit'), ('mode', 'cu_reader_required'),
    ('scope-after-scan', 'route_changed'),
])
def test_malformed_timeout_or_mode_change_is_terminal_without_suffix(cu_setup, monkeypatch, fault, code):
    env = cu_setup
    owner = env.connect()
    fake = env.fake
    if fault == 'scan-truncated':
        fake.scan_data = fake.scan_data[:-1]
    elif fault == 'scan-two-records':
        fake.scan_data = fake.scan_data * 2
    elif fault == 'scan-bcc-error':
        fake.scan_status, fake.scan_data = 0x05, b''
    elif fault == 'scan-sak-missing':
        fake.scan_status, fake.scan_data = 0x02, b''
    elif fault == 'scan-not-reader':
        fake.scan_status, fake.scan_data = 0x66, b''
    elif fault == 'version-status-02':
        fake.responses[(2010, VERSION_WIRE)] = frame(2010, b'', status=0x02)
    elif fault == 'version-9-bytes':
        fake.version = VERSIONS[213] + b'\0'
    elif fault == 'version-no-frame':
        monkeypatch.setattr(O, 'COMMAND_SECONDS', .005)
        fake.responses[(2010, VERSION_WIRE)] = b''
    elif fault == 'scope-after-scan':
        # scan 응답 뒤 USB 형제 범위가 바뀌면 GET_VERSION frame 직전 재검증이 막는다.
        def changed(command, payload):
            env.keys = tuple(sorted((*env.keys, 'new-sibling')))
            return fake.response(command, payload)
        fake.responses[2000] = changed
    else:
        fake.responses[1002] = frame(1002, b'\0')
    with pytest.raises(Exception) as caught:
        operation(owner, 'identify_hf')
    assert getattr(caught.value, 'code', None) == code and caught.value.data == {}
    assert owner.state == 'terminal' and not owner._uses
    assert_no_read_or_auth(fake)
    if fault == 'mode':
        assert not any(command in (2000, 2010) for command, _ in fake.commands)
    elif fault.startswith('scan') or fault == 'scope-after-scan':
        assert not any(command == 2010 for command, _ in fake.commands)
    assert fake.field is False
    before = list(fake.commands)
    with pytest.raises(Exception):
        owner.reserve_use()
    assert fake.commands == before


def test_cancel_after_scan_is_terminal_and_sends_no_version(cu_setup):
    env = cu_setup
    owner = env.connect()
    cancelled = threading.Event()
    def stop(command, payload):
        cancelled.set()
        return env.fake.response(command, payload)
    env.fake.responses[2000] = stop
    with pytest.raises(Exception) as caught:
        operation(owner, 'identify_hf', cancel=cancelled.is_set)
    assert caught.value.code == 'cancelled' and owner.state == 'terminal'
    assert not any(command == 2010 for command, _ in env.fake.commands)


def test_identify_on_terminal_or_opening_owner_never_writes(cu_setup):
    env = cu_setup
    pending = env.prepare()
    with pytest.raises(Exception):
        pending.reserve_use()
    assert env.fake.writes == []
    assert pending.close(deadline=__import__('time').monotonic() + 1).cleanup_confirmed


@pytest.mark.parametrize('policy', ['approve', 'deny'])
async def test_identify_gate_has_no_wire_and_keeps_session(cu_setup, monkeypatch, isolated_ports, policy):
    env = cu_setup
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        before = list(env.fake.commands)
        env.workspace['set_safety'](modify_policy=policy)
        env.runtime = get_runtime('cu-test')
        result = await identify(client, env, owner)
        assert result.get('status') == ('approval_required' if policy == 'approve' else 'denied'), result
        assert result['gate']['classification']['risk'] == 'modify'
        assert result['gate']['classification']['rule_id'] == 'cu.hf-identify'
        assert env.fake.commands == before and not owner._uses and owner.state == 'ready'
        await close(client, env, owner)


async def test_identify_approval_fingerprint_binds_identify_profile(cu_setup, monkeypatch):
    env = cu_setup
    env.fake = FakeCu(scan='classic-1k')
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        env.workspace['set_safety'](modify_policy='approve')
        env.runtime = get_runtime('cu-test')
        action = T.identify_approval_action(owner)
        assert action['operation'] == 'hf_identify' and action['session_id'] == owner.session_id
        assert action['identify_profile'] == C.IDENTIFY.profile
        assert action['identify_profile_sha256'] == C.IDENTIFY.profile_sha256
        assert action['profile_sha256'] == C.LIVE.profile_sha256
        assert action['page_reads'] == 0 and action['authentication'] is False
        assert action != T.approval_action(owner)
        # scan 승인은 다른 지문이므로 식별에 쓸 수 없다.
        scan_pending = await call(client, 'nfc_cu_scan', case_id=env.case.id, session_id=owner.session_id)
        scan_aid = scan_pending['approval_id']
        record = env.runtime.approvals.get(scan_aid)
        env.runtime.approvals.decide(scan_aid, approve=True, code=record['code'], via='cli-tty')
        before = list(env.fake.commands)
        misuse = await identify(client, env, owner, approval_id=scan_aid)
        assert not misuse.get('ok') and env.fake.commands == before
        pending = await identify(client, env, owner)
        assert pending.get('status') == 'approval_required', pending
        aid = pending['approval_id']
        record = env.runtime.approvals.get(aid)
        assert record['action']['identify_profile_sha256'] == C.IDENTIFY.profile_sha256
        env.runtime.approvals.decide(aid, approve=True, code=record['code'], via='cli-tty')
        # 반대 방향: 식별 승인으로 scan을 실행할 수 없다. 지문이 달라 wire가 없고 승인은 소비되지 않는다.
        before = list(env.fake.commands)
        reverse = await call(client, 'nfc_cu_scan', case_id=env.case.id, session_id=owner.session_id,
                             approval_id=aid)
        assert not reverse.get('ok') and env.fake.commands == before, reverse
        assert env.runtime.approvals.get(aid)['status'] == 'approved' and owner.state == 'ready'
        result = await identify(client, env, owner, approval_id=aid)
        assert result.get('ok') and result['family'] == 'mifare_classic_1k', result
        await close(client, env, owner)


async def test_raw_cancel_of_identify_keeps_worker_and_lease_until_finish(cu_setup, monkeypatch, isolated_ports):
    env = cu_setup
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    entered, release = threading.Event(), threading.Event()
    async with Client(S.server) as client:
        owner = await connect(client, env)
        def blocked(size):
            entered.set()
            assert release.wait(3)
        env.fake.before_read = blocked
        task = asyncio.create_task(S.nfc_cu_identify(env.case.id, owner.session_id))
        try:
            for _ in range(300):
                if entered.is_set():
                    break
                await asyncio.sleep(.005)
            assert entered.is_set()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert owner._uses and isolated_ports['manager']._leases
        finally:
            release.set()
            env.fake.before_read = None
        for _ in range(300):
            if not owner._uses:
                break
            await asyncio.sleep(.005)
        assert not owner._uses and owner.state == 'terminal'
        await close(client, env, owner)


@pytest.mark.parametrize('cu_setup', ['posix-tty', 'win-helper'], indirect=True)
async def test_status_getters_values_and_no_rf(cu_setup, monkeypatch, caplog):
    env = cu_setup
    env.fake.battery, env.fake.slot = (4012, 87), 3
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        out = await status(client, env, owner)
        assert out.get('ok'), out
        assert set(out) == STATUS_KEYS
        assert (out['battery_mv'], out['battery_percent'], out['active_slot']) == (4012, 87, 3)
        assert out['battery_percent_is_estimate'] is True and out['mode'] == 'reader'
        assert out['hf14a_config_default'] is True
        assert (out['model'], out['app_version'], out['git_version']) == ('chameleon-ultra', '2.3', 'v2.3.0')
        assert env.fake.commands[4:] == [(1002, b''), (1025, b''), (1018, b''), (2200, b'')]
        assert env.fake.field is False and all(field is False for _, _, field in env.fake.field_log)
        assert not {command for command, _ in env.fake.commands} & DENIED
        assert owner.state == 'ready' and not owner._uses
        # 상태 조회 뒤 같은 세션으로 식별할 수 있다.
        env.fake.hf14a_config = b'\x00\x00\x00\x01'
        changed = await status(client, env, owner)
        assert changed['hf14a_config_default'] is False
        found = await identify(client, env, owner)
        assert found['family'] == 'ntag213'
        assert env.runtime.provenance.entries(env.case) == []
        await close(client, env, owner)
    assert PRIVATE not in json.dumps(out) + caplog.text


@pytest.mark.parametrize('policy', ['approve', 'deny'])
async def test_status_is_interact_and_runs_under_any_modify_policy(cu_setup, monkeypatch, policy):
    env = cu_setup
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        env.workspace['set_safety'](modify_policy=policy)
        env.runtime = get_runtime('cu-test')
        out = await status(client, env, owner)
        assert out.get('ok'), out
        events = [json.loads(line) for line in (env.case.dir / 'audit.jsonl').read_text().splitlines()
                  if line.strip()]
        decisions = [e for e in events if e.get('event') == 'safety_decision' and e.get('tool') == 'nfc_cu_status']
        assert decisions and decisions[-1]['status'] == 'allowed'
        assert decisions[-1]['classification']['risk'] == 'interact'
        assert decisions[-1]['classification']['rule_id'] == 'cu.status'
        assert decisions[-1]['action']['status_queries'] == [1002, 1025, 1018, 2200]
        await close(client, env, owner)


def test_status_action_lists_fixed_getters(cu_setup):
    env = cu_setup
    owner = env.connect()
    action = T.status_action(owner)
    assert action['operation'] == 'device_status' and action['session_id'] == owner.session_id
    assert action['status_queries'] == [1002, 1025, 1018, 2200]


@pytest.mark.parametrize('command,data,status', [
    (1025, b'\x0f\x3c', 0x68), (1025, b'\x0f\x3c\x65', 0x68), (1018, b'\x08', 0x68), (1018, b'', 0x68),
    (2200, b'\x03\x00\x00\x00', 0x68), (2200, b'\x00\x00\x00', 0x68), (1025, b'\x0f\x3c\x3d', 0x00),
    (1018, b'\x00', 0x67), (2200, b'\x00\x00\x00\x00', 0x66),
])
def test_status_malformed_reply_is_terminal(cu_setup, command, data, status):
    env = cu_setup
    owner = env.connect()
    env.fake.responses[command] = frame(command, data, status=status)
    with pytest.raises(Exception) as caught:
        operation(owner, 'device_status')
    assert caught.value.code == 'cu_protocol_invalid' and owner.state == 'terminal'
    # connect의 네 조회처럼 세 getter를 모두 받은 뒤 한 번에 검사한다. 그 뒤 명령·RF는 없다.
    assert [c for c, _ in env.fake.commands[4:]] == [1002, 1025, 1018, 2200]
    before = list(env.fake.commands)
    with pytest.raises(Exception):
        owner.reserve_use()
    assert env.fake.commands == before and env.fake.field is False


def test_status_mode_change_is_terminal_before_getters(cu_setup):
    env = cu_setup
    owner = env.connect()
    env.fake.responses[1002] = frame(1002, b'\x00')
    with pytest.raises(Exception) as caught:
        operation(owner, 'device_status')
    assert caught.value.code == 'cu_reader_required' and owner.state == 'terminal'
    assert [c for c, _ in env.fake.commands[4:]] == [1002]


def test_scan_models_used_here_cover_spec_list():
    assert {'none', 'multiple', 'classic-1k', 'classic-4k', 'iso14443-4', 'plus-sl2'} <= set(SCAN_MODELS)
    assert {'mf0icu1-nak', 'mf0icu1-timeout', 'ul-ev1', 'version-crc-error'} <= set(TAG_MODELS)
    # 서버 표는 모든 최종 family를 한 번 이상 지난다.
    assert {family for _, family, *_ in CASES} == C.HF_FAMILIES - {'ultralight_ev1_mf0ulh11', 'ultralight_ev1_mf0ul21'}
