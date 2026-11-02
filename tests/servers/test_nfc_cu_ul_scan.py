"""합성 CU와 실제 Client로 Ultralight scan의 READ 없는 wire·소유 증명 순서·원장 결속·UL inventory를 검사한다.

사람 증명은 격리 상태의 저장소 API(decide)로만 답한다. 실제 `pweh attest`·장치·포트는 쓰지 않는다.
모든 경로에서 0x30 READ는 한 번도 보내지 않는다(fake의 non-NTAG READ 규칙이 위반으로 기록한다).
"""
from __future__ import annotations

import json

import pytest
from mcp import Client

from mcp_helpers import call
from pweh import cu_protocol as C, nfc_ul_inventory as UL, schemas
from pweh.runtime import get_runtime
from nfc_mcp import server as S, cu_tools as T, cu_owner as O
from .fake_cu import (setup as cu_setup, FakeCu, UID, VERSIONS, TAG_MODELS, UL_SCAN_MODELS, TICKET_UID, DENIED,
                      VERSION_WIRE, scan_bytes)

pytestmark = pytest.mark.anyio
OTHER_UID = bytes.fromhex('04a1a2a3a4a5a6')
SCAN_WIRE = [(1002, b''), (2000, b''), (2010, VERSION_WIRE)]
SCAN_KEYS = {'ok', 'schema', 'scan_ref', 'family', 'ul_identity_digest', 'uid_length', 'profile', 'policy',
             'policy_profile', 'attestation', 'inventory_eligible', 'page_read_performed', 'read_requests',
             'version_requests', 'authentication_attempted', 'physical_same_tag_verified', 'rf_off_verified',
             'warnings'}


@pytest.fixture
def anyio_backend():
    return 'asyncio'


async def connect(client, env):
    result = await call(client, 'nfc_cu_connect', case_id=env.case.id, port=env.port)
    assert result.get('ok'), result
    return O.get_cu_session(env.case.id, result['session_id'])


async def ul_scan(client, env, owner, **kwargs):
    return await call(client, 'nfc_cu_ul_scan', case_id=env.case.id, session_id=owner.session_id, **kwargs)


async def close(client, env, owner):
    out = await call(client, 'nfc_cu_disconnect', case_id=env.case.id, session_id=owner.session_id)
    assert out['ok'], out


def decide(env, aid, answer='yes', via='cli-tty'):
    return env.runtime.attestations.decide(aid, {'owned_tag': answer}, via=via)


def ul_entries(env):
    return [e for e in env.runtime.provenance.entries(env.case) if e['fact_kind'] in UL.UL_FACTS]


def assert_no_read(fake):
    """0x30 READ·인증·다른 RAW option이 없고 모든 frame 뒤 field가 꺼져 있다."""
    assert fake.reads() == []
    assert all(payload == VERSION_WIRE for command, payload in fake.commands if command == 2010)
    assert not {command for command, _ in fake.commands} & DENIED
    assert fake.field is False and all(field is False for _, _, field in fake.field_log)


def assert_pending(out, family):
    assert out.get('ok') is False and out['status'] == 'attestation_required', out
    assert out['kind'] == 'tag-ownership' and out['family'] == family
    assert out['page_reads_sent'] is False and out['scan_fact_recorded'] is False
    assert [q['id'] for q in out['questions']] == ['owned_tag'] and 'pweh attest' in out['how']
    assert out['ul_identity_digest'].startswith('sha256:') and len(out['ul_identity_digest']) == 23


@pytest.mark.parametrize('model', sorted(UL_SCAN_MODELS))
@pytest.mark.parametrize('cu_setup', ['posix-tty', 'win-helper'], indirect=True)
async def test_ownership_is_requested_first_and_recall_records_fact(cu_setup, monkeypatch, caplog, model):
    env = cu_setup
    tag, family = UL_SCAN_MODELS[model]
    env.fake = FakeCu(tag=tag)
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        first = await ul_scan(client, env, owner)
        assert_pending(first, family)
        assert env.fake.commands[4:] == SCAN_WIRE
        # 증명 전에는 UL scan 사실이 없고 세션은 ready다.
        assert env.runtime.provenance.entries(env.case) == [] and owner.state == 'ready' and not owner._uses
        rec = env.runtime.attestations.get(first['attestation_id'])
        assert rec['status'] == 'pending' and rec['subject'] == {
            'tag_family': family, 'ul_identity_digest': first['ul_identity_digest'],
            'policy_profile': 'ultralight-attested-v1'}
        mirror = (env.case.dir / 'attestations.json').read_text(encoding='utf-8')
        for text in (json.dumps(rec, ensure_ascii=False), mirror):
            assert UID.hex() not in text and UID.hex().upper() not in text
        # 같은 태그로 다시 불러도 같은 pending 요청을 재사용한다(새 frame은 보낸다).
        again = await ul_scan(client, env, owner)
        assert again['attestation_id'] == first['attestation_id'] and env.fake.commands[7:] == SCAN_WIRE
        decide(env, first['attestation_id'])
        done = await ul_scan(client, env, owner)
        assert done.get('ok'), done
        assert set(done) == SCAN_KEYS and done['family'] == family
        schemas.validate('nfc-ul-scan', done)
        assert done['attestation'] == {'kind': 'tag-ownership', 'attestation_id': first['attestation_id']}
        assert done['ul_identity_digest'] == first['ul_identity_digest'] and done['scan_ref'].startswith('US-')
        assert (done['page_read_performed'], done['read_requests'], done['version_requests']) == (False, 0, 1)
        assert env.fake.commands[10:] == SCAN_WIRE
        facts = ul_entries(env)
        assert len(facts) == 1 and facts[0]['attestation_id'] == first['attestation_id']
        assert facts[0]['data']['ul_scan_ref'] == done['scan_ref']
        inventory = await call(client, 'nfc_tag_inventory_add', case_id=env.case.id, scan_ref=done['scan_ref'])
        assert inventory.get('ok'), inventory
        schemas.validate('nfc-ul-inventory', inventory)
        assert inventory['tag_ref'].startswith('UT-') and inventory['scan_ref'] == done['scan_ref']
        assert inventory['attestation']['attestation_id'] == first['attestation_id']
        repeat = await call(client, 'nfc_tag_inventory_add', case_id=env.case.id, scan_ref=done['scan_ref'])
        assert repeat['tag_ref'] == inventory['tag_ref']
        assert [e['fact_kind'] for e in ul_entries(env)] == [UL.UL_SCAN_FACT, UL.UL_INVENTORY_FACT]
        assert_no_read(env.fake)
        assert owner.state == 'ready' and not owner._uses
        await close(client, env, owner)
    public = json.dumps([first, again, done, inventory, repeat], ensure_ascii=False) + caplog.text
    for value in (UID.hex(), UID.hex(' ').upper(), 'CU_SYNTHETIC', *(v[1].hex() for v in TAG_MODELS.values() if v[1])):
        assert value not in public


async def test_denied_ownership_stops_without_fact_or_read(cu_setup, monkeypatch):
    env = cu_setup
    env.fake = FakeCu(tag='mf0icu1-nak')
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        first = await ul_scan(client, env, owner)
        assert_pending(first, 'ultralight_or_ultralight_c')
        assert decide(env, first['attestation_id'], answer='no')['status'] == 'denied'
        # 사용자가 원해 다시 부르면 새 요청을 만들 뿐 scan 사실은 없다(거부 기록은 previous로 보인다).
        out = await ul_scan(client, env, owner)
        assert out.get('ok') is False and out['status'] in ('attestation_required', 'denied'), out
        assert out['previous']['status'] == 'denied' and out['previous']['attestation_id'] == first['attestation_id']
        assert out['scan_fact_recorded'] is False and env.runtime.provenance.entries(env.case) == []
        assert_no_read(env.fake)
        await close(client, env, owner)


IDENTIFY_ITEM_KEYS = ('profile', 'family', 'policy', 'uid_length', 'ats_present', 'get_version_sent',
                      'page_reads_sent', 'identity_digest')


@pytest.mark.parametrize('tag', ['mf0icu1-nak', 'ul-ev1'])
async def test_stopped_ul_run_summary_comes_from_recorded_identify(cu_setup, monkeypatch, tag):
    """Skill의 UL 흐름: nfc_cu_identify → step="ul-identify" 기록 → nfc_cu_ul_scan. 사람이 거부해 inventory 전에 멈추면
    그 기록의 identifications로 만든 mode cu-hf-identify 요약이 스키마를 통과하고 기록된다(설계 개정 G — 멈춘 실행도 요약 가능)."""
    from case_mcp import server as CS
    env = cu_setup
    env.fake = FakeCu(tag=tag)
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client, Client(CS.server) as cc:
        owner = await connect(client, env)
        ident = await call(client, 'nfc_cu_identify', case_id=env.case.id, session_id=owner.session_id)
        assert ident.get('ok') and ident['family'].startswith('ultralight_'), ident
        item = {'operation': 'cu-identify', **{key: ident[key] for key in IDENTIFY_ITEM_KEYS}}
        recorded = await call(cc, 'case_record_step', case_id=env.case.id, skill='nfc-behavior-analysis',
                              step='ul-identify', status='success', summary='UL 식별(READ 없음)',
                              data={'identifications': [item]})
        assert recorded.get('ok'), recorded
        first = await ul_scan(client, env, owner)
        assert_pending(first, ident['family'])
        assert decide(env, first['attestation_id'], answer='no')['status'] == 'denied'
        assert env.runtime.provenance.entries(env.case) == []
        steps = await call(cc, 'case_get_step_results', case_id=env.case.id, skill='nfc-behavior-analysis',
                           summaries_only=False)
        assert steps.get('ok'), steps
        saved = json.dumps(steps, ensure_ascii=False)
        assert '"ul-identify"' in saved and UID.hex() not in saved
        summary = {'schema': 'pweh.nfc-analysis/v1', 'mode': 'cu-hf-identify', 'tags': [], 'results': [],
                   'identifications': [item], 'physical_same_tag_verified': False, 'tag_content_written': False,
                   'authentication_attempted': False, 'emulation_performed': False}
        schemas.validate('nfc-analysis', summary)
        done = await call(cc, 'case_record_step', case_id=env.case.id, skill='nfc-behavior-analysis', step='summary',
                          status='partial', summary='소유 증명 거부로 inventory 전에 멈춤', data=summary)
        assert done.get('ok'), done
        assert_no_read(env.fake)
        await close(client, env, owner)


async def test_tag_purpose_record_does_not_satisfy_the_ultralight_gate(cu_setup, monkeypatch):
    env = cu_setup
    env.fake = FakeCu(tag='ul-ev1')
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        first = await ul_scan(client, env, owner)
        rec = env.runtime.attestations.get(first['attestation_id'])
        purpose = env.runtime.attestations.request('tag-purpose', rec['subject'], rec['binding'], UL.ul_questions(),
                                                   env.case.id)
        assert decide(env, purpose['id'])['status'] == 'approved'
        out = await ul_scan(client, env, owner)
        assert_pending(out, 'ultralight_ev1_mf0ul11')
        assert out['attestation_id'] == first['attestation_id'] and env.runtime.provenance.entries(env.case) == []
        assert_no_read(env.fake)
        await close(client, env, owner)


async def test_owned_ev1_transit_ticket_passes_once_ownership_is_attested(cu_setup, monkeypatch):
    """사용자 소유의 사용한 EV1 MF0UL11 종이 승차권(합성 모델)도 소유 증명 뒤 scan·inventory에 오른다."""
    env = cu_setup
    env.fake = FakeCu(tag='ul-ev1', uid=TICKET_UID)
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        first = await ul_scan(client, env, owner)
        assert_pending(first, 'ultralight_ev1_mf0ul11')
        decide(env, first['attestation_id'])
        done = await ul_scan(client, env, owner)
        assert done.get('ok') and done['family'] == 'ultralight_ev1_mf0ul11', done
        inventory = await call(client, 'nfc_tag_inventory_add', case_id=env.case.id, scan_ref=done['scan_ref'])
        assert inventory.get('ok') and inventory['family'] == 'ultralight_ev1_mf0ul11', inventory
        assert ul_entries(env)[0]['data']['identity']['uid'] == TICKET_UID.hex()
        assert TICKET_UID.hex() not in json.dumps([first, done, inventory])
        assert_no_read(env.fake)
        await close(client, env, owner)


async def test_elicitation_decided_record_is_accepted(cu_setup, monkeypatch):
    env = cu_setup
    env.fake = FakeCu(tag='ul-ev1-mf0ulh21')
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        first = await ul_scan(client, env, owner)
        assert decide(env, first['attestation_id'], via='elicitation')['decided_via'] == 'elicitation'
        done = await ul_scan(client, env, owner)
        assert done.get('ok') and done['attestation']['attestation_id'] == first['attestation_id'], done
        assert_no_read(env.fake)
        await close(client, env, owner)


async def test_attestation_is_bound_to_uid_family_and_case(cu_setup, monkeypatch, auth):
    env = cu_setup
    env.fake = FakeCu(tag='ul-ev1')
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        first = await ul_scan(client, env, owner)
        decide(env, first['attestation_id'])
        assert (await ul_scan(client, env, owner)).get('ok')
        # 다른 UID(태그 B): 같은 계열이어도 A의 증명을 쓰지 않는다.
        env.fake.scan_data = scan_bytes(uid=OTHER_UID)
        other_tag = await ul_scan(client, env, owner)
        assert_pending(other_tag, 'ultralight_ev1_mf0ul11')
        assert other_tag['attestation_id'] != first['attestation_id']
        assert other_tag['ul_identity_digest'] != first['ul_identity_digest']
        # 같은 UID의 다른 계열(MF0UL21 version): 지문·대상이 다르다.
        env.fake.scan_data = scan_bytes()
        env.fake.version_status, env.fake.version = TAG_MODELS['ul-ev1-mf0ul21']
        other_family = await ul_scan(client, env, owner)
        assert_pending(other_family, 'ultralight_ev1_mf0ul21')
        assert other_family['attestation_id'] not in (first['attestation_id'], other_tag['attestation_id'])
        assert len(ul_entries(env)) == 1
        assert_no_read(env.fake)
        await close(client, env, owner)
    # 다른 케이스에서는 같은 태그의 지문도 증명 대상도 다르다.
    other_case = env.runtime.cases.create(title='합성 다른 케이스', authorization=auth)
    identity = UL.UlIdentity(UID, b'\x00\x44', b'\x00', bytes.fromhex('0004030101000b03'))
    other_digest = UL.ul_identity_digest(env.runtime, other_case.id, identity, 'ultralight_ev1_mf0ul11')
    assert other_digest != first['ul_identity_digest']
    with pytest.raises(Exception):
        UL.ul_require(env.runtime, other_case.id, 'ultralight_ev1_mf0ul11', first['ul_identity_digest'])


@pytest.mark.parametrize('kwargs,wire', [
    ({'family': 213}, SCAN_WIRE), ({'family': 216}, SCAN_WIRE),
    ({'tag': 'type2-other-version'}, SCAN_WIRE), ({'tag': 'version-crc-error'}, SCAN_WIRE),
    ({'scan': 'classic-1k'}, SCAN_WIRE[:2]), ({'scan': 'classic-mini'}, SCAN_WIRE[:2]),
    ({'scan': 'none'}, SCAN_WIRE[:2]), ({'scan': 'multiple'}, SCAN_WIRE[:2]),
    ({'scan': 'iso14443-4'}, SCAN_WIRE[:2]), ({'scan': 'type2-uid4'}, SCAN_WIRE[:2]),
])
async def test_non_ultralight_family_is_refused_without_attestation(cu_setup, monkeypatch, kwargs, wire):
    env = cu_setup
    env.fake = FakeCu(**kwargs)
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        out = await ul_scan(client, env, owner)
        assert 'nfc_family_unsupported' in out.get('_error', ''), out
        assert env.fake.commands[4:] == wire
        assert env.runtime.attestations.list() == [] and env.runtime.provenance.entries(env.case) == []
        # 잘 형성된 분류이므로 세션은 ready이고 같은 세션으로 식별을 다시 할 수 있다.
        assert owner.state == 'ready' and not owner._uses
        follow = await call(client, 'nfc_cu_identify', case_id=env.case.id, session_id=owner.session_id)
        assert follow.get('ok') and follow['family'] not in C.UL_FAMILIES, follow
        assert env.fake.reads() == []
        await close(client, env, owner)


async def test_attest_runs_without_ctx_and_without_cu_use(cu_setup, monkeypatch):
    env = cu_setup
    env.fake = FakeCu(tag='ul-ev1')
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    seen = []
    real = env.runtime.attest

    async def spy(kind, subject, binding, questions, case_id=None, ctx='MISSING', summary=None, **kw):
        owner = O._REGISTRY.get(env.case.id)
        seen.append((kw.get('tool'), kind, ctx, bool(owner and owner._uses), json.dumps(subject) + str(summary)))
        return await real(kind, subject, binding, questions, case_id, ctx, summary, **kw)

    monkeypatch.setattr(env.runtime, 'attest', spy)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        first = await ul_scan(client, env, owner)
        decide(env, first['attestation_id'])
        done = await ul_scan(client, env, owner)
        await call(client, 'nfc_tag_inventory_add', case_id=env.case.id, scan_ref=done['scan_ref'])
        await close(client, env, owner)
    assert [row[0] for row in seen] == ['nfc_cu_ul_scan', 'nfc_cu_ul_scan', 'nfc_tag_inventory_add']
    for tool, kind, ctx, busy, text in seen:
        assert kind == 'tag-ownership' and ctx is None and busy is False
        assert UID.hex() not in text and 'Ultralight' in text


async def test_revocation_between_attest_and_ledger_lock_records_nothing(cu_setup, monkeypatch):
    env = cu_setup
    env.fake = FakeCu(tag='ul-ev1')
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        first = await ul_scan(client, env, owner)
        decide(env, first['attestation_id'])
        real = UL.ul_attest

        async def then_revoke(*args, **kwargs):
            decision = await real(*args, **kwargs)
            env.runtime.attestations.revoke(decision.attestation_id)
            return decision

        monkeypatch.setattr(UL, 'ul_attest', then_revoke)
        out = await ul_scan(client, env, owner)
        assert 'nfc_attestation_required' in out.get('_error', ''), out
        assert env.runtime.provenance.entries(env.case) == [] and owner.state == 'ready'
        assert_no_read(env.fake)
        await close(client, env, owner)


async def test_inventory_add_rechecks_ownership_and_ntag_branch_is_unchanged(cu_setup, monkeypatch):
    env = cu_setup
    env.fake = FakeCu(tag='ul-ev1')
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        first = await ul_scan(client, env, owner)
        decide(env, first['attestation_id'])
        done = await ul_scan(client, env, owner)
        env.runtime.attestations.revoke(first['attestation_id'])
        out = await call(client, 'nfc_tag_inventory_add', case_id=env.case.id, scan_ref=done['scan_ref'])
        assert out.get('ok') is False and out['status'] == 'attestation_required', out
        assert out['previous']['status'] == 'revoked' and out['inventory_recorded'] is False
        assert out['scan_ref'] == done['scan_ref'] and out['family'] == 'ultralight_ev1_mf0ul11'
        assert [e['fact_kind'] for e in ul_entries(env)] == [UL.UL_SCAN_FACT]
        decide(env, out['attestation_id'])
        added = await call(client, 'nfc_tag_inventory_add', case_id=env.case.id, scan_ref=done['scan_ref'])
        assert added.get('ok') and added['attestation']['attestation_id'] == out['attestation_id'], added
        # 같은 세션의 NTAG 태그는 기존 NS-/NT- 흐름 그대로다.
        env.fake.tag = None
        env.fake.version_status, env.fake.version = 0, VERSIONS[213]
        ntag = await call(client, 'nfc_cu_scan', case_id=env.case.id, session_id=owner.session_id)
        assert ntag.get('ok') and ntag['scan_ref'].startswith('NS-'), ntag
        nt = await call(client, 'nfc_tag_inventory_add', case_id=env.case.id, scan_ref=ntag['scan_ref'])
        assert nt.get('ok') and nt['tag_ref'].startswith('NT-') and nt['schema'] == 'pweh.nfc-inventory/v1', nt
        schemas.validate('nfc-inventory', nt)
        cache = json.loads((env.case.dir / 'nfc' / 'inventory.json').read_text())
        assert [row['tag_ref'] for row in cache['entries']] == [nt['tag_ref']]
        await close(client, env, owner)


@pytest.mark.parametrize('ref,code', [
    ('US-' + '0' * 32, 'nfc_scan_required'), ('XS-' + '0' * 32, 'nfc_input_invalid'),
    ('US-' + '0' * 31, 'nfc_input_invalid'), ('UT-' + '0' * 32, 'nfc_input_invalid'),
])
async def test_inventory_scan_ref_prefixes_are_closed(cu_setup, monkeypatch, ref, code):
    env = cu_setup
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        out = await call(client, 'nfc_tag_inventory_add', case_id=env.case.id, scan_ref=ref)
    assert out.get('ok') is not True and code in out.get('_error', ''), out
    assert env.runtime.attestations.list() == []


async def test_ul_scan_approval_fingerprint_binds_ul_profile(cu_setup, monkeypatch):
    env = cu_setup
    env.fake = FakeCu(tag='ul-ev1')
    monkeypatch.setattr(S, 'rt', lambda: env.runtime)
    async with Client(S.server) as client:
        owner = await connect(client, env)
        env.workspace['set_safety'](modify_policy='approve')
        env.runtime = get_runtime('cu-test')
        action = T.ul_scan_approval_action(owner)
        assert action['operation'] == 'ul_scan' and action['session_id'] == owner.session_id
        assert (action['ul_profile'], action['ul_profile_sha256']) == (C.UL_READ.profile, C.UL_READ.profile_sha256)
        assert action['identify_profile_sha256'] == C.IDENTIFY.profile_sha256
        assert action['page_reads'] == 0 and action['authentication'] is False and action['version_requests_max'] == 1
        assert action != T.identify_approval_action(owner) and action != T.approval_action(owner)
        # 식별 승인은 다른 지문이므로 UL scan에 쓸 수 없다.
        identify_pending = await call(client, 'nfc_cu_identify', case_id=env.case.id, session_id=owner.session_id)
        iid = identify_pending['approval_id']
        record = env.runtime.approvals.get(iid)
        env.runtime.approvals.decide(iid, approve=True, code=record['code'], via='cli-tty')
        before = list(env.fake.commands)
        misuse = await ul_scan(client, env, owner, approval_id=iid)
        assert not misuse.get('ok') and env.fake.commands == before
        pending = await ul_scan(client, env, owner)
        assert pending.get('status') == 'approval_required', pending
        assert pending['gate']['classification']['rule_id'] == 'cu.ul-scan'
        assert env.fake.commands == before and not owner._uses and owner.state == 'ready'
        aid = pending['approval_id']
        record = env.runtime.approvals.get(aid)
        assert record['action']['ul_profile_sha256'] == C.UL_READ.profile_sha256
        env.runtime.approvals.decide(aid, approve=True, code=record['code'], via='cli-tty')
        out = await ul_scan(client, env, owner, approval_id=aid)
        assert_pending(out, 'ultralight_ev1_mf0ul11')
        assert env.fake.commands[len(before):] == SCAN_WIRE
        assert_no_read(env.fake)
        await close(client, env, owner)
