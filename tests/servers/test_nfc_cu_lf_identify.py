"""합성 CU와 실제 Client로 LF 125 kHz 식별의 wire 순서·첫 감지 멈춤·gate·세션 수명·마스킹 투영을 검사한다."""
from __future__ import annotations

import asyncio
import json
import re
import threading
import time

import pytest
from mcp import Client

from mcp_helpers import call
from pweh import cu_protocol as C, schemas
from pweh.runtime import get_runtime
from nfc_mcp import server as S, cu_tools as T, cu_owner as O
from .fake_cu import (setup as cu_setup, FakeCu, DENIED, LF_DENIED, LF_SCANS, LF_MODELS, EM_ID, ELECTRA_EPILOGUE,
                      HID16, IOPROX16, UID, frame)

pytestmark = pytest.mark.anyio
RESULT_KEYS = {'ok', 'case_id', 'session_id', 'profile', 'family', 'variant', 'policy', 'scans_sent', 'id_returned',
               'identity_digest', 'physical_same_tag_verified', 'lf_field_off_by_firmware',
               'authentication_attempted'}
NAMES = {3000: 'em410x_scan', 3002: 'hidprox_scan', 3010: 'ioprox_scan', 3004: 'viking_scan', 3014: 'pac_scan',
         3019: 'jablotron_scan', 3021: 'pyramid_scan'}
ORDER = [command for command, _ in LF_SCANS]
# (fake 모델, family, variant, 감지한 scan 명령). None 모델은 일곱 scan 모두 0x41이다.
CASES = [
    ('em410x-16', 'em410x', 'em410x_16', 3000), ('em410x-32', 'em410x', 'em410x_32', 3000),
    ('em410x-64', 'em410x', 'em410x_64', 3000), ('electra', 'em410x', 'em410x_electra', 3000),
    ('hidprox', 'hidprox', None, 3002), ('ioprox', 'ioprox', None, 3010), ('viking', 'viking', None, 3004),
    ('pac', 'pac', None, 3014), ('jablotron', 'jablotron', None, 3019), ('pyramid', 'pyramid', None, 3021),
    (None, 'none', None, None),
]


@pytest.fixture
def anyio_backend():
    return 'asyncio'


def operation(owner, method, *, deadline=None, cancel=None):
    use = owner.reserve_use(cancel=cancel)
    assert use.claim()
    try:
        return getattr(owner, method)(use, deadline=deadline or time.monotonic() + 20)
    finally:
        use.finish()


def private_values():
    """공개 결과·로그에 나오면 안 되는 합성 원시 ID 조각(hex)."""
    values = {EM_ID.hex(), ELECTRA_EPILOGUE.hex(), HID16.hex(), IOPROX16.hex(), HID16[1:5].hex(), HID16[5:10].hex(),
              HID16[10:13].hex(), IOPROX16[4:12].hex(), UID.hex()}
    values |= {data.hex() for _, data in LF_MODELS.values()}
    values |= {data[2:].hex() for command, data in LF_MODELS.values() if command == 3000}
    return values


def lf_ids():
    """합성 LF 모델의 원시 ID 바이트(EM410x는 tag_type 2B를 뺀 ID, 그 밖은 0x40 payload 전체)."""
    return {data[2:] if command == 3000 else data for command, data in LF_MODELS.values()}


def would_be_digests(runtime, case_id):
    """지난 구현이 만들던 지문과 원시 ID 단독 지문. 어느 공개 기록에도 나오면 안 된다."""
    out = set()
    for name, (command, data) in LF_MODELS.items():
        family = C.LF_SCAN_SPECS[C.CuLfScan(command)].family
        ident = data[2:] if command == 3000 else data
        variant = C._EM410X_VARIANTS[int.from_bytes(data[:2], 'big')] if command == 3000 else ''
        old = (b'pweh.cu-lf-identify/v1\0' + family.encode() + b'\0' + variant.encode() + b'\0'
               + bytes((len(ident),)) + ident)
        out |= {runtime.secret_digest(case_id, old), runtime.secret_digest(case_id, ident),
                runtime.secret_digest(case_id, data), runtime.secret_digest(case_id, ident.hex())}
    return out


def audit_text(env):
    """격리 시험 작업공간의 케이스·전역 감사 기록 전문."""
    paths = (env.case.dir / 'audit.jsonl', env.runtime.global_audit.path)
    return ''.join(path.read_text(encoding='utf-8') for path in paths if path.exists())


def lf_commands(fake):
    return [(command, payload) for command, payload in fake.commands if 3000 <= command < 4000]


def expected_wire(hit):
    stop = ORDER.index(hit) + 1 if hit is not None else len(ORDER)
    return [(1002, b'')] + list(LF_SCANS[:stop])


def assert_never_forbidden(fake):
    sent = {command for command, _ in fake.commands}
    assert not sent & DENIED and not sent & LF_DENIED
    # HF RF·RAW·인증·READ와 모드·slot 변경 명령도 LF 식별에서 보내지 않는다.
    assert fake.reads() == []


async def connect(client, env):
    result = await call(client, 'nfc_cu_connect', case_id=env.case.id, port=env.port)
    assert result.get('ok'), result
    return O.get_cu_session(env.case.id, result['session_id'])


async def lf_identify(client, env, owner, **kwargs):
    return await call(client, 'nfc_cu_lf_identify', case_id=env.case.id, session_id=owner.session_id, **kwargs)


async def close(client, env, owner):
    out = await call(client, 'nfc_cu_disconnect', case_id=env.case.id, session_id=owner.session_id)
    assert out['ok'], out
    return out


@pytest.mark.parametrize('model,family,variant,hit', CASES)
@pytest.mark.parametrize('cu_setup', ['posix-tty', 'win-helper'], indirect=True)
async def test_order_stop_at_first_hit_masking_and_session_ready(cu_setup, monkeypatch, caplog, model, family,
                                                                 variant, hit):
    env = cu_setup
    env.fake = FakeCu(lf=model)
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    # 도구 경로 어디에서도 ID 바이트로 케이스 솔트 지문을 계산하지 않는다.
    digest_inputs, real_digest = [], env.runtime.secret_digest

    def spy(case_id, value):
        digest_inputs.append(value)
        return real_digest(case_id, value)

    monkeypatch.setattr(env.runtime, 'secret_digest', spy)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        first = await lf_identify(client, env, owner)
        assert first.get('ok'), first
        assert set(first) == RESULT_KEYS
        assert (first['family'], first['variant']) == (family, variant)
        assert first['policy'] == ('not_applicable' if family == 'none' else 'refused')
        assert first['profile'] == 'cu-lf125-identify-v2.3.0-v1' == C.LF_IDENTIFY.profile
        wire = expected_wire(hit)
        assert first['scans_sent'] == [NAMES[command] for command, _ in wire[1:]]
        assert first['id_returned'] is first['physical_same_tag_verified'] is False
        assert first['authentication_attempted'] is False and first['lf_field_off_by_firmware'] is True
        # ID 파생 출력이 없다: 감지 계열(모두 refused)과 none 모두 identity_digest는 null이고 지문 모양 값도 없다.
        assert first['identity_digest'] is None
        assert re.search(r'sha256:[0-9a-f]{16}', json.dumps(first)) is None
        # connect 네 조회 뒤 mode 한 번과 고정 순서 scan만 나가고 첫 감지 뒤 scan은 없다.
        assert env.fake.commands[4:] == wire
        assert env.fake.lf_log == [command for command, _ in wire[1:]]
        assert_never_forbidden(env.fake)
        assert env.fake.field is False
        # 잘 형성된 결과는 terminal이 아니며 같은 세션으로 다시 호출할 수 있다(결과도 같다).
        assert owner.state == 'ready' and not owner._uses
        again = await lf_identify(client, env, owner)
        assert again == first and env.fake.commands[4 + len(wire):] == wire
        # scan 사실·inventory·artifact를 만들지 않는다.
        assert env.runtime.provenance.entries(env.case) == []
        assert not env.case.load()['artifacts']
        # 공개 결과는 요약 lf_identifications 항목으로 그대로 옮길 수 있다.
        item = {'operation': 'cu-lf-identify', **{key: first[key] for key in (
            'profile', 'family', 'variant', 'policy', 'scans_sent', 'identity_digest', 'id_returned')}}
        schemas.validate('nfc-analysis', {'schema': 'pweh.nfc-analysis/v1', 'mode': 'cu-lf-identify', 'tags': [],
                                          'results': [], 'lf_identifications': [item],
                                          'physical_same_tag_verified': False, 'tag_content_written': False,
                                          'authentication_attempted': False, 'emulation_performed': False})
        await close(client, env, owner)
    ids = lf_ids()
    for value in digest_inputs:
        raw = value if type(value) is bytes else str(value).encode()
        assert not any(ident in raw or ident.hex().encode() in raw.lower() for ident in ids), value
    # 결과·로그에는 원시 ID 조각도 합성 reader serial도 없다.
    public = json.dumps([first, again]) + caplog.text
    for value in private_values() | {'CU_SYNTHETIC', 'SYNPAC01'}:
        assert value not in public and value.upper() not in public
    # 케이스/전역 감사 기록(gate 결정·승인 action 포함)까지 더해도 원시 ID 조각과 ID에서 만든 지문은 없다.
    # (감사 기록의 connect action에는 reader 자신의 USB serial이 남으며 카드 ID가 아니다.)
    recorded = public + audit_text(env)
    assert 'lf_identify' in recorded
    for value in private_values() | {'SYNPAC01'}:
        assert value not in recorded and value.upper() not in recorded
    for digest in would_be_digests(env.runtime, env.case.id):
        assert digest not in recorded


async def test_hf_then_lf_identify_on_same_session(cu_setup, monkeypatch):
    env = cu_setup
    env.fake = FakeCu(scan='classic-1k', lf='hidprox')
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        hf = await call(client, 'nfc_cu_identify', case_id=env.case.id, session_id=owner.session_id)
        assert hf.get('ok') and hf['family'] == 'mifare_classic_1k', hf
        lf = await lf_identify(client, env, owner)
        assert lf.get('ok') and lf['family'] == 'hidprox' and lf['policy'] == 'refused', lf
        # HF 식별 지문은 기존대로 문자열이고 LF 식별은 ID 파생 값이 없다.
        assert lf['identity_digest'] is None and type(hf['identity_digest']) is str
        # HF 식별은 LF scan을 보내지 않고 LF 식별은 HF scan·RAW를 보내지 않는다.
        assert [c for c, _ in env.fake.commands[4:]] == [1002, 2000, 1002, 3000, 3002]
        assert owner.state == 'ready'
        await close(client, env, owner)


def flipped(command, data):
    """같은 계열·변형에서 ID 바이트만 모두 바꾼 payload. EM410x는 tag_type 2B를 그대로 둔다."""
    head = data[:2] if command == 3000 else b''
    return head + bytes(b ^ 0xff for b in data[len(head):])


def test_lf_projection_has_no_id_derived_value(cu_setup):
    """투영은 지문을 계산하지 않는다. 같은 계열·변형이면 ID 바이트가 달라도 공개 결과가 바이트 단위로 같다."""
    env = cu_setup
    sid = 'a' * 32
    assert not hasattr(T, '_lf_identify_digest') and not hasattr(C, 'LF_DIGEST_DOMAIN')
    nf = [C.CuLfReply(scan, False, None, None, None) for scan in C.LF_SCAN_ORDER]
    seen = set()
    for name, (command, data) in LF_MODELS.items():
        scan = C.CuLfScan(command)
        index = C.LF_SCAN_ORDER.index(scan)
        outs = []
        for payload in (data, flipped(command, data)):
            reply = C.classify_lf_scan(scan, C.CuFrame(command, 0x40, payload))
            result = O.CuLfIdentify(sid, tuple(nf[:index]) + (reply,), reply.family)
            out = T._lf_identify_projection(env.case.id, sid, result)
            assert out['identity_digest'] is None and set(out) == RESULT_KEYS
            text = json.dumps(out)
            assert payload.hex() not in text and payload[len(data) - len(reply.id_bytes):].hex() not in text
            assert re.search(r'sha256:[0-9a-f]{16}', text) is None
            outs.append(out)
        assert outs[0] == outs[1], name
        seen.add(outs[0]['family'])
    none = T._lf_identify_projection(env.case.id, sid, O.CuLfIdentify(sid, tuple(nf), 'none'))
    assert none['identity_digest'] is None and none['family'] == 'none' and none['variant'] is None
    assert seen | {'none'} == C.LF_FAMILIES


@pytest.mark.parametrize('fault,code,sent', [
    # (fault, 고정 오류, 오류 응답까지 실제로 보낸 LF scan 수)
    ('em-type-100', 'nfc_scan_invalid', 1), ('em-type-105', 'nfc_scan_invalid', 1),
    ('electra-short', 'nfc_scan_invalid', 1), ('em16-electra-length', 'nfc_scan_invalid', 1),
    ('hid-15', 'nfc_scan_invalid', 2), ('viking-5', 'nfc_scan_invalid', 4), ('pyramid-15', 'nfc_scan_invalid', 7),
    ('notfound-payload', 'nfc_scan_invalid', 1), ('status-42', 'nfc_scan_invalid', 3),
    ('status-68', 'nfc_scan_invalid', 2), ('mode-error-first', 'cu_reader_required', 1),
    ('mode-error-later', 'cu_reader_required', 5), ('no-frame', 'time_limit', 3),
    ('mode', 'cu_reader_required', 0), ('scope-after-first', 'route_changed', 1),
])
def test_malformed_mode_timeout_or_revalidation_is_terminal_without_suffix(cu_setup, monkeypatch, fault, code, sent):
    env = cu_setup
    owner = env.connect()
    fake = env.fake
    responses = {
        'em-type-100': (3000, frame(3000, b'\x00\x64' + EM_ID, status=0x40)),
        'em-type-105': (3000, frame(3000, b'\x00\x69' + EM_ID, status=0x40)),
        'electra-short': (3000, frame(3000, b'\x00\x68' + EM_ID, status=0x40)),
        'em16-electra-length': (3000, frame(3000, b'\x00\x65' + EM_ID + ELECTRA_EPILOGUE, status=0x40)),
        'hid-15': (3002, frame(3002, HID16[:15], status=0x40)),
        'viking-5': (3004, frame(3004, b'\x01\x02\x03\x04\x05', status=0x40)),
        'pyramid-15': (3021, frame(3021, bytes(15), status=0x40)),
        'notfound-payload': (3000, frame(3000, b'\x00', status=0x41)),
        'status-42': (3010, frame(3010, b'', status=0x42)),
        'status-68': (3002, frame(3002, b'', status=0x68)),
        'mode-error-first': (3000, frame(3000, b'', status=0x66)),
        'mode-error-later': (3014, frame(3014, b'', status=0x66)),
    }
    if fault in responses:
        command, data = responses[fault]
        fake.responses[command] = data
    elif fault == 'no-frame':
        monkeypatch.setattr(O, 'COMMAND_SECONDS', .005)
        fake.responses[3010] = b''
    elif fault == 'mode':
        fake.responses[1002] = frame(1002, b'\0')
    else:
        # 첫 scan 응답 뒤 USB 형제 범위가 바뀌면 다음 scan frame 직전 재검증이 막는다.
        def changed(command, payload):
            env.keys = tuple(sorted((*env.keys, 'new-sibling')))
            return fake.response(command, payload)
        fake.responses[3000] = changed
    with pytest.raises(Exception) as caught:
        operation(owner, 'identify_lf')
    assert getattr(caught.value, 'code', None) == code and caught.value.data == {}
    # 고정 오류 문구에도 잘못된 응답에 실린 ID 조각이 없다.
    shown = (str(caught.value) + repr(caught.value)).lower()
    assert not any(value in shown for value in private_values())
    assert owner.state == 'terminal' and not owner._uses
    assert lf_commands(fake) == list(LF_SCANS[:sent])
    assert_never_forbidden(fake)
    before = list(fake.commands)
    with pytest.raises(Exception):
        owner.reserve_use()
    assert fake.commands == before


def test_cancel_after_first_not_found_is_terminal_and_sends_no_more_scans(cu_setup):
    env = cu_setup
    owner = env.connect()
    cancelled = threading.Event()
    def stop(command, payload):
        cancelled.set()
        return env.fake.response(command, payload)
    env.fake.responses[3000] = stop
    with pytest.raises(Exception) as caught:
        operation(owner, 'identify_lf', cancel=cancelled.is_set)
    assert caught.value.code == 'cancelled' and owner.state == 'terminal'
    assert lf_commands(env.fake) == [(3000, b'')]


async def test_tool_passes_the_documented_whole_tool_budget(cu_setup, monkeypatch):
    """계약 문서의 "도구 전체 예산은 20초"가 owner에 넘어가는 deadline이다(owner 상한 45초로 흐려지지 않는다)."""
    env = cu_setup
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    seen, real = [], O.CuOwner.identify_lf

    def spy(self, use, *, deadline):
        seen.append(deadline - time.monotonic())
        return real(self, use, deadline=deadline)

    monkeypatch.setattr(O.CuOwner, 'identify_lf', spy)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        result = await lf_identify(client, env, owner)
        assert result.get('ok'), result
        await close(client, env, owner)
    assert T.LF_IDENTIFY_SECONDS == 20 < O.OPERATION_SECONDS
    assert len(seen) == 1 and 19 < seen[0] <= 20


def test_whole_tool_deadline_inside_a_scan_is_terminal_without_next_scan(cu_setup):
    """명령 예산(2초)보다 짧은 도구 deadline이 scan 응답 대기에서 끊긴다."""
    env = cu_setup
    owner = env.connect()

    def slow(command, payload):
        time.sleep(.9)
        return env.fake.response(command, payload)

    env.fake.responses[3000] = slow
    started = time.monotonic()
    with pytest.raises(Exception) as caught:
        operation(owner, 'identify_lf', deadline=started + .6)
    assert getattr(caught.value, 'code', None) == 'time_limit' and caught.value.data == {}
    assert time.monotonic() - started < O.COMMAND_SECONDS
    assert owner.state == 'terminal' and not owner._uses
    assert lf_commands(env.fake) == [(3000, b'')]
    assert_never_forbidden(env.fake)


def test_whole_tool_deadline_between_scans_sends_no_next_scan(cu_setup, monkeypatch):
    """첫 미감지 응답을 받은 뒤 도구 deadline이 지나면 다음 scan frame을 쓰기 전에 time_limit terminal이다."""
    env = cu_setup
    owner = env.connect()
    deadline = time.monotonic() + 1
    real = C.classify_lf_scan

    def late(scan, frame):
        reply = real(scan, frame)
        time.sleep(max(0.0, deadline - time.monotonic()) + .02)
        return reply

    monkeypatch.setattr(O.P, 'classify_lf_scan', late)
    with pytest.raises(Exception) as caught:
        operation(owner, 'identify_lf', deadline=deadline)
    assert getattr(caught.value, 'code', None) == 'time_limit' and caught.value.data == {}
    assert owner.state == 'terminal' and not owner._uses
    assert lf_commands(env.fake) == [(3000, b'')]
    assert_never_forbidden(env.fake)


def test_lf_identify_on_opening_owner_never_writes(cu_setup):
    env = cu_setup
    pending = env.prepare()
    with pytest.raises(Exception):
        pending.reserve_use()
    assert env.fake.writes == []
    assert pending.close(deadline=time.monotonic() + 1).cleanup_confirmed


@pytest.mark.parametrize('policy', ['approve', 'deny'])
async def test_lf_gate_has_no_wire_and_keeps_session(cu_setup, monkeypatch, isolated_ports, policy):
    env = cu_setup
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        before = list(env.fake.commands)
        env.workspace['set_safety'](modify_policy=policy)
        env.runtime = get_runtime('cu-test')
        result = await lf_identify(client, env, owner)
        assert result.get('status') == ('approval_required' if policy == 'approve' else 'denied'), result
        assert result['gate']['classification']['risk'] == 'modify'
        assert result['gate']['classification']['rule_id'] == 'cu.lf-identify'
        assert env.fake.commands == before and not owner._uses and owner.state == 'ready'
        await close(client, env, owner)


async def test_lf_approval_fingerprint_binds_lf_profile_and_is_not_interchangeable(cu_setup, monkeypatch):
    env = cu_setup
    env.fake = FakeCu(lf='viking')
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        env.workspace['set_safety'](modify_policy='approve')
        env.runtime = get_runtime('cu-test')
        action = T.lf_identify_approval_action(owner)
        assert action['operation'] == 'lf_identify' and action['session_id'] == owner.session_id
        assert action['lf_identify_profile'] == C.LF_IDENTIFY.profile
        assert action['lf_identify_profile_sha256'] == C.LF_IDENTIFY.profile_sha256
        assert action['lf_scan_commands'] == ORDER and action['stop_at_first_found'] is True
        assert action['authentication'] is False and action['tag_writes'] == 0
        # 승인 지문은 고정 recipe 값만 더하며 ID에서 나온 값을 담을 자리가 없다.
        assert set(action) - set(owner.action) == {
            'operation', 'session_id', 'lf_identify_profile', 'lf_identify_profile_sha256', 'lf_scan_commands',
            'stop_at_first_found', 'authentication', 'tag_writes'}
        assert action['profile_sha256'] == C.LIVE.profile_sha256
        assert action not in (T.identify_approval_action(owner), T.approval_action(owner))
        # HF 식별·NTAG scan 승인은 다른 지문이므로 LF 식별에 쓸 수 없다.
        for tool in ('nfc_cu_identify', 'nfc_cu_scan'):
            pending = await call(client, tool, case_id=env.case.id, session_id=owner.session_id)
            other_aid = pending['approval_id']
            record = env.runtime.approvals.get(other_aid)
            env.runtime.approvals.decide(other_aid, approve=True, code=record['code'], via='cli-tty')
            before = list(env.fake.commands)
            misuse = await lf_identify(client, env, owner, approval_id=other_aid)
            assert not misuse.get('ok') and env.fake.commands == before, misuse
        pending = await lf_identify(client, env, owner)
        assert pending.get('status') == 'approval_required', pending
        aid = pending['approval_id']
        record = env.runtime.approvals.get(aid)
        assert record['action']['lf_identify_profile_sha256'] == C.LF_IDENTIFY.profile_sha256
        env.runtime.approvals.decide(aid, approve=True, code=record['code'], via='cli-tty')
        # 반대 방향: LF 승인으로 HF 식별·NTAG scan을 실행할 수 없다. wire가 없고 승인은 소비되지 않는다.
        for tool in ('nfc_cu_identify', 'nfc_cu_scan'):
            before = list(env.fake.commands)
            reverse = await call(client, tool, case_id=env.case.id, session_id=owner.session_id, approval_id=aid)
            assert not reverse.get('ok') and env.fake.commands == before, reverse
        assert env.runtime.approvals.get(aid)['status'] == 'approved' and owner.state == 'ready'
        result = await lf_identify(client, env, owner, approval_id=aid)
        assert result.get('ok') and result['family'] == 'viking', result
        assert result['scans_sent'] == ['em410x_scan', 'hidprox_scan', 'ioprox_scan', 'viking_scan']
        await close(client, env, owner)


async def test_raw_cancel_of_lf_identify_keeps_worker_and_lease_until_finish(cu_setup, monkeypatch, isolated_ports):
    env = cu_setup
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    entered, release = threading.Event(), threading.Event()
    async with Client(S.server) as client:
        owner = await connect(client, env)
        def blocked(size):
            entered.set()
            assert release.wait(3)
        env.fake.before_read = blocked
        task = asyncio.create_task(S.nfc_cu_lf_identify(env.case.id, owner.session_id))
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
        assert len(lf_commands(env.fake)) <= 1
        await close(client, env, owner)


def test_projection_rejects_inconsistent_results(cu_setup):
    env = cu_setup
    sid = 'a' * 32
    nf = {scan: C.CuLfReply(scan, False, None, None, None) for scan in C.LF_SCAN_ORDER}
    hit = C.classify_lf_scan(C.CuLfScan.VIKING, C.CuFrame(3004, 0x40, b'1234'))
    good = O.CuLfIdentify(sid, (nf[C.CuLfScan.EM410X], nf[C.CuLfScan.HIDPROX], nf[C.CuLfScan.IOPROX], hit), 'viking')
    assert T._lf_identify_projection(env.case.id, sid, good)['family'] == 'viking'
    bad = [
        O.CuLfIdentify(sid, (hit,), 'viking'),                                    # 순서 앞부분이 아니다
        O.CuLfIdentify(sid, (nf[C.CuLfScan.EM410X],), 'none'),                     # 일곱 scan 전에 none
        O.CuLfIdentify(sid, tuple(nf.values()), 'em410x'),                         # 감지 없이 계열
        O.CuLfIdentify(sid, good.replies, 'pac'),                                  # 계열 불일치
        O.CuLfIdentify(sid, (), 'none'),
        O.CuLfIdentify('b' * 32, good.replies, 'viking'),                          # 다른 세션
        O.CuLfIdentify(sid, list(good.replies), 'viking'),
    ]
    for result in bad:
        with pytest.raises(Exception) as caught:
            T._lf_identify_projection(env.case.id, sid, result)
        assert caught.value.code == 'nfc_scan_invalid'


def test_lf_models_cover_every_family():
    assert {family for _, family, _, _ in CASES} == C.LF_FAMILIES
    assert {variant for _, _, variant, _ in CASES} - {None} == C.LF_VARIANTS
    assert [command for command, _ in LF_SCANS] == [3000, 3002, 3010, 3004, 3014, 3019, 3021]
