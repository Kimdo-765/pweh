"""Ultralight 계열 CU snapshot(UT- inventory)의 nfc_parse_file·nfc_diff_dumps와 소유 증명 재확인·출처 분기를 검사한다.

사람 증명은 격리 상태의 저장소 API(decide/revoke)로만 답한다. 실제 `pweh attest`·장치·포트는 쓰지 않는다.
"""
from __future__ import annotations

import copy
import datetime as dt
import json

import pytest
from mcp import Client

from mcp_helpers import call
from pweh import nfc_cu_ul_snapshot as UN, schemas
import pweh.safety.attestations as att_mod
from nfc_mcp import server as S, analysis as A, ul_analysis as U
from .fake_cu import setup as cu_setup, UID, VERSIONS  # noqa: F401 - fixture 재사용
from .test_nfc_cu_ul_read import prepare, read, wait, disconnect, decide
from .test_nfc_mcp import ntag, register

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return 'asyncio'


def analyses(env, kind='nfc-ul-file-analysis'):
    return [a for a in env.case.load()['artifacts'] if a.get('extra', {}).get('type') == kind]


async def parse(client, env, inv, artifact_id, **kw):
    return await call(client, 'nfc_parse_file', case_id=env.case.id, artifact_id=artifact_id,
                      tag_ref=inv['tag_ref'], **kw)


async def diff(client, env, inv, before, after):
    return await call(client, 'nfc_diff_dumps', case_id=env.case.id, tag_ref=inv['tag_ref'],
                      before_artifact_id=before, after_artifact_id=after)


def aid_of(job):
    return job['result']['artifact']['artifact_id']


# parse/diff 반환의 정확한 키 — 원시 페이지가 들어갈 자리가 없다(설계 개정 E).
RESULT_KEYS = {'ok', 'report', 'analysis', 'warnings'}
ANALYSIS_KEYS = {'path', 'sha256', 'size', 'artifact_id'}


def assert_result_shape(result):
    assert set(result) == RESULT_KEYS, set(result)
    assert set(result['analysis']) == ANALYSIS_KEYS, result['analysis']


def observed_hex(pages, job):
    """그 읽기가 관찰한 page 0..k-1(page 0–3 포함)의 hex. 결과·로그에 하나도 없어야 한다."""
    return [page.hex() for page in pages[:job['result']['pages_observed']]]


@pytest.mark.parametrize('model,kwargs,status', [
    ('mf0ul11', {}, 'ok'), ('mf0icu1', {}, 'ok'), ('mf0icu2', {'auth0': 0x08, 'prot': True}, 'ok'),
    ('mf0ul21', {'auth0': 0x10, 'prot': True, 'no_rollover': True}, 'partial')])
async def test_parse_and_diff_happy_paths(cu_setup, monkeypatch, caplog, model, kwargs, status):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, model, **kwargs)
        before_pages = list(env.fake.ul_pages)
        before = await read(client, env, owner, inv)
        assert before['status'] == 'succeeded', before
        parsed = await parse(client, env, inv, aid_of(before))
        assert parsed.get('ok'), parsed
        assert_result_shape(parsed)
        report = parsed['report']
        schemas.validate('nfc-ul-file-analysis', report)
        assert report['status'] == status and report['operation'] == 'inspect'
        assert report['params']['profile'] == UN.ANALYSIS_PROFILE
        assert parsed['analysis']['path'].startswith('analysis/nfc-ul-file-')
        source = report['source']
        assert source['tag_ref'] == inv['tag_ref'] and source['scan_ref'] == inv['scan_ref']
        aid = inv['attestation']['attestation_id']
        assert source['tag_ownership_attestation_id'] == aid
        assert source['files'][0]['read_attestation_id'] == aid and source['files'][0]['provenance_kind'] == 'device-read'
        summary = report['inspection']['summary']
        assert summary['read_end'] == before['result']['read_end']
        assert summary['observed_variant'] == before['result']['observed_variant']
        env.fake.ul_pages[5] = b'\x12\x34\xab\xcd'
        after = await read(client, env, owner, inv)
        assert after['status'] == 'succeeded', after
        out = await diff(client, env, inv, aid_of(before), aid_of(after))
        assert out.get('ok'), out
        assert_result_shape(out)
        d = out['report']['inspection']['summary']
        schemas.validate('nfc-ul-file-analysis', out['report'])
        assert d['changed_pages'] == [5] and d['read_end_changed'] is False
        assert d['stored_pages_equal'] is (False if status == 'ok' else None)
        assert (d['pages_compared'] + d['before_only_pages'] + d['after_only_pages'] + d['neither_observed_pages']
                + d['withheld_pages'] + d['comparison_unexamined_pages']) == d['pages_total']
        assert out['analysis']['path'].startswith('analysis/nfc-ul-diff-')
        assert len(analyses(env)) == 2
        await disconnect(client, env, owner)
        # 완료한 snapshot 분석은 살아 있는 CU 세션이 필요 없다.
        offline = await parse(client, env, inv, aid_of(before))
        assert offline.get('ok'), offline
        assert_result_shape(offline)
        after_pages = list(env.fake.ul_pages)
    visible = json.dumps([before, after, parsed, out, offline]) + caplog.text
    secrets = observed_hex(before_pages, before) + observed_hex(after_pages, after)
    assert len(secrets) >= 16 and '1234abcd' in secrets
    for secret in (UID.hex(), 'reader_binding', *secrets):
        assert secret not in visible, secret


async def test_diff_reports_read_end_change_without_claiming_equality(cu_setup, monkeypatch):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11')
        before = await read(client, env, owner, inv)
        env.fake.ul_auth0, env.fake.ul_prot = 0x08, True
        after = await read(client, env, owner, inv)
        assert after['result']['read_end'] == {'kind': 'nak_with_rollover', 'page': 8}
        out = await diff(client, env, inv, aid_of(before), aid_of(after))
        assert out.get('ok'), out
        d = out['report']['inspection']['summary']
        assert d['read_end_changed'] is True and d['stored_pages_equal'] is None and d['changed_pages'] == []
        assert d['pages_compared'] == 8 and d['before_only_pages'] == 10 and d['withheld_pages'] == 2
        await disconnect(client, env, owner)


@pytest.mark.parametrize('mode', ['revoked', 'expired', 'denied'])
async def test_parse_and_diff_require_current_ownership(cu_setup, monkeypatch, mode):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11')
        job = await read(client, env, owner, inv)
        await disconnect(client, env, owner)
        aid = inv['attestation']['attestation_id']
        if mode == 'expired':
            real_now = att_mod._now
            monkeypatch.setattr(att_mod, '_now', lambda: real_now() + dt.timedelta(days=8))
        else:
            env.runtime.attestations.revoke(aid)
        out = await parse(client, env, inv, aid_of(job))
        assert out.get('ok') is False and out['status'] == 'attestation_required', out
        assert out['kind'] == 'tag-ownership' and out['analysis_recorded'] is False
        assert out['tag_ref'] == inv['tag_ref']
        both = await diff(client, env, inv, aid_of(job), aid_of(job))
        assert both.get('ok') is False and both['status'] == 'attestation_required', both
        if mode == 'denied':
            decide(env, out['attestation_id'], answer='no')
            again = await parse(client, env, inv, aid_of(job))
            assert again.get('ok') is False and again['previous']['status'] in ('denied', 'revoked'), again
        elif mode == 'revoked':
            # 새 증명은 읽기 때와 다른 id여도 받으며 둘 다 기록한다.
            decide(env, out['attestation_id'])
            ok = await parse(client, env, inv, aid_of(job))
            assert ok.get('ok'), ok
            src = ok['report']['source']
            assert src['tag_ownership_attestation_id'] == out['attestation_id'] != aid
            assert src['files'][0]['read_attestation_id'] == aid
        if mode != 'revoked':
            assert analyses(env) == []


async def test_revocation_after_attest_blocks_analysis_step(cu_setup, monkeypatch):
    """입구의 ctx 없는 증명 확인 직후 철회되면 분석 단계의 같은 id 동기 재확인이 막는다 — inspect·diff 계산과 출력 파일 생성 전이다
    (등록 check의 재확인에 기대지 않는다)."""
    from pweh import nfc_ul_inventory as UL
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11')
        job = await read(client, env, owner, inv)
        second = await read(client, env, owner, inv)
        real = UL.ul_attest
        reached = []

        async def then_revoke(*args, **kwargs):
            decision = await real(*args, **kwargs)
            assert decision.satisfied
            env.runtime.attestations.revoke(decision.attestation_id)
            return decision

        def spy(name, original):
            def wrapped(*args, **kwargs):
                reached.append(name)
                return original(*args, **kwargs)
            return wrapped

        monkeypatch.setattr(UN, 'inspect_cu_ul_snapshot', spy('inspect', UN.inspect_cu_ul_snapshot))
        monkeypatch.setattr(UN, 'diff_cu_ul_snapshots', spy('diff', UN.diff_cu_ul_snapshots))
        monkeypatch.setattr(UL, 'ul_attest', then_revoke)
        out = await parse(client, env, inv, aid_of(job))
        assert 'nfc_attestation_required' in out.get('_error', ''), out
        # diff도 같은 창을 본다: 사람이 새로 증명한 뒤(격리 저장소 API) 다시 충족 직후 철회한다.
        monkeypatch.setattr(UL, 'ul_attest', real)
        pending = await parse(client, env, inv, aid_of(job))
        assert pending['status'] == 'attestation_required', pending
        decide(env, pending['attestation_id'])
        monkeypatch.setattr(UL, 'ul_attest', then_revoke)
        both = await diff(client, env, inv, aid_of(job), aid_of(second))
        assert 'nfc_attestation_required' in both.get('_error', ''), both
        assert reached == []
        assert analyses(env) == [] and not list((env.case.dir / 'analysis').glob('nfc-ul-*'))
        await disconnect(client, env, owner)


async def test_revocation_inside_register_check_leaves_no_analysis(cu_setup, monkeypatch):
    from pweh import nfc_ul_inventory as UL
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11')
        job = await read(client, env, owner, inv)
        real = UL.resolve_ul_inventory
        calls = []

        def counting(*args, **kwargs):
            calls.append(1)
            # 입구·분석 단계 다음(등록 check 안)의 재풀이 직전에 철회한다.
            if len(calls) == 3:
                env.runtime.attestations.revoke(inv['attestation']['attestation_id'])
            return real(*args, **kwargs)

        monkeypatch.setattr(UL, 'resolve_ul_inventory', counting)
        out = await parse(client, env, inv, aid_of(job))
        assert 'nfc_attestation_required' in out.get('_error', ''), out
        assert len(calls) == 3 and analyses(env) == []
        assert not list((env.case.dir / 'analysis').glob('nfc-ul-*'))
        await disconnect(client, env, owner)


async def test_parse_attests_without_ctx(cu_setup, monkeypatch):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11')
        job = await read(client, env, owner, inv)
        seen = []
        real = env.runtime.attest

        async def spy(kind, subject, binding, questions, case_id=None, ctx='MISSING', summary=None, **kw):
            seen.append((kw.get('tool'), kind, ctx))
            return await real(kind, subject, binding, questions, case_id, ctx, summary, **kw)

        monkeypatch.setattr(env.runtime, 'attest', spy)
        assert (await parse(client, env, inv, aid_of(job))).get('ok')
        assert (await diff(client, env, inv, aid_of(job), aid_of(job))).get('ok')
        assert seen == [('nfc_parse_file', 'tag-ownership', None), ('nfc_diff_dumps', 'tag-ownership', None)]
        await disconnect(client, env, owner)


async def ntag_inventory_and_snapshot(client, env, owner):
    env.fake.ul = None
    env.fake.version_status, env.fake.version = 0, VERSIONS[213]
    scan = await call(client, 'nfc_cu_scan', case_id=env.case.id, session_id=owner.session_id)
    assert scan.get('ok'), scan
    nt = await call(client, 'nfc_tag_inventory_add', case_id=env.case.id, scan_ref=scan['scan_ref'])
    assert nt.get('ok'), nt
    job = await wait(client, env, await call(client, 'nfc_cu_read_start', case_id=env.case.id,
                                             session_id=owner.session_id, tag_ref=nt['tag_ref']))
    assert job['status'] == 'succeeded', job
    return nt, job


async def test_cross_pairs_are_source_mismatch_and_ntag_flow_is_unchanged(cu_setup, monkeypatch):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11')
        ul_job = await read(client, env, owner, inv)
        nt, nt_job = await ntag_inventory_and_snapshot(client, env, owner)
        imported = register(env.case, ntag(uid=UID), name='synthetic-import.nfc')
        count = len(env.runtime.provenance.entries(env.case))
        reached = []
        real_ul, real_nt = U.analyze_ul_files, A.analyze_files
        monkeypatch.setattr(U, 'analyze_ul_files', lambda *a, **k: reached.append('ul') or real_ul(*a, **k))
        monkeypatch.setattr(A, 'analyze_files', lambda *a, **k: reached.append('nt') or real_nt(*a, **k))
        cases = [
            # NT- ref + UL snapshot: NTAG 흐름은 UL snapshot을 받지 않는다.
            ('nfc_parse_file', {'artifact_id': aid_of(ul_job), 'tag_ref': nt['tag_ref']}),
            # UT- ref + NTAG snapshot / 가져온 v4.
            ('nfc_parse_file', {'artifact_id': aid_of(nt_job), 'tag_ref': inv['tag_ref']}),
            ('nfc_parse_file', {'artifact_id': imported['id'], 'tag_ref': inv['tag_ref']}),
            # 혼합 비교.
            ('nfc_diff_dumps', {'before_artifact_id': aid_of(ul_job), 'after_artifact_id': aid_of(nt_job),
                                'tag_ref': inv['tag_ref']}),
            ('nfc_diff_dumps', {'before_artifact_id': aid_of(ul_job), 'after_artifact_id': aid_of(nt_job),
                                'tag_ref': nt['tag_ref']}),
            ('nfc_diff_dumps', {'before_artifact_id': imported['id'], 'after_artifact_id': aid_of(ul_job),
                                'tag_ref': inv['tag_ref']}),
        ]
        for tool, args in cases:
            out = await call(client, tool, case_id=env.case.id, **args)
            assert 'nfc_source_mismatch' in out.get('_error', ''), (tool, args, out)
        assert reached == [] and analyses(env) == []
        # 가져온 v4가 UT- 입구에서 import 원장 행을 만들지 않는다.
        assert len(env.runtime.provenance.entries(env.case)) == count
        # 같은 케이스의 NTAG parse는 기존 결과 그대로다.
        monkeypatch.setattr(A, 'analyze_files', real_nt)
        ntag_out = await call(client, 'nfc_parse_file', case_id=env.case.id, artifact_id=aid_of(nt_job),
                              tag_ref=nt['tag_ref'])
        assert ntag_out.get('ok'), ntag_out
        assert ntag_out['report']['schema'] == 'pweh.nfc-file-analysis/v1'
        assert ntag_out['analysis']['path'] == 'analysis/nfc-file-001.json'
        schemas.validate('nfc-file-analysis', ntag_out['report'])
        await disconnect(client, env, owner)


@pytest.mark.parametrize('mutation', ['extra', 'attestation_id', 'attestation_none', 'source', 'binding',
                                      'latest-import', 'registration', 'path-name'])
async def test_ul_source_branch_requires_exact_ledger_row(cu_setup, monkeypatch, mutation):
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11')
        job = await read(client, env, owner, inv)
        row = job['result']['artifact']
        rec = next(e for e in env.runtime.provenance.entries(env.case) if e.get('path') == row['path'])
        artifact_id = row['artifact_id']
        if mutation in ('extra', 'attestation_id', 'attestation_none', 'source', 'binding'):
            extra, source, att = copy.deepcopy(rec['extra']), dict(rec['source']), rec['attestation_id']
            if mutation == 'extra':
                extra['pages_observed'] -= 1
            elif mutation == 'attestation_id':
                att = 'att-0000000000'
            elif mutation == 'attestation_none':
                # NTAG device-read처럼 증명 id 없는 최신 행은 UL snapshot 출처가 아니다.
                att = None
            elif mutation == 'source':
                source['tool'] = 'synthetic-other'
            else:
                extra['binding']['inventory_seq'] += 1
            env.runtime.provenance.record_device_read(env.case, row['path'], source, extra, attestation_id=att)
        elif mutation == 'latest-import':
            env.runtime.provenance.record_import(env.case, row['path'], {'server': 'synthetic', 'tool': 'fixture'})
        elif mutation == 'registration':
            data = env.case.load()
            next(a for a in data['artifacts'] if a['id'] == artifact_id)['producer'] = 'synthetic'
            env.case.meta_path.write_text(json.dumps(data))
        else:
            target = env.case.dir / 'nfc/cu-ul-read-7.json'
            target.write_bytes((env.case.dir / row['path']).read_bytes())
            target.chmod(0o444)
            artifact_id = env.case.register_artifact(target, kind='other', producer='pweh-nfc',
                                                     extra={'type': 'nfc-cu-ul-snapshot'})['id']
        count = len(env.runtime.provenance.entries(env.case))
        out = await parse(client, env, inv, artifact_id)
        assert not out.get('ok') and '_error' in out, out
        assert len(env.runtime.provenance.entries(env.case)) == count and analyses(env) == []
        await disconnect(client, env, owner)


async def test_ul_summary_validates_and_records_with_ul_tags_and_results(cu_setup, monkeypatch):
    from case_mcp import server as C
    env = cu_setup
    async with Client(S.server) as client:
        owner, inv = await prepare(client, env, monkeypatch, 'mf0ul11')
        job = await read(client, env, owner, inv)
        out = await parse(client, env, inv, aid_of(job))
        assert out.get('ok'), out
        summary = {'schema': 'pweh.nfc-analysis/v1', 'mode': 'scan-bound-offline',
                   'tags': [{'tag_ref': inv['tag_ref'], 'scan_ref': inv['scan_ref'], 'family': inv['family'],
                             'ul_identity_digest': inv['ul_identity_digest'],
                             'tag_ownership_attestation_id': inv['attestation']['attestation_id']}],
                   'results': [{'artifact_id': out['analysis']['artifact_id'], 'path': out['analysis']['path'],
                                'sha256': out['analysis']['sha256'], 'operation': 'inspect',
                                'status': out['report']['status'], 'tag_ref': inv['tag_ref']}],
                   'physical_same_tag_verified': False, 'tag_content_written': False,
                   'authentication_attempted': False, 'emulation_performed': False}
        schemas.validate('nfc-analysis', summary)
        # 결과 없이 scan·inventory만 한 UL 실행도 tags 하나로 요약할 수 있다.
        schemas.validate('nfc-analysis', {**summary, 'results': []})
        async with Client(C.server) as case_client:
            saved = await call(case_client, 'case_record_step', case_id=env.case.id, skill='nfc-behavior-analysis',
                               step='summary', status='success', summary='합성 UL snapshot 분석', data=summary,
                               artifacts=[out['analysis']['path']])
            assert saved.get('ok'), saved
            report = await call(case_client, 'report_generate', case_id=env.case.id)
            assert report.get('ok'), report
        # 서버가 만든 v2 분석은 보고서 §8.2 에 표준 필드 표로 실리고 '싣지 않음'이 없다.
        text = (env.case.dir / 'report.md').read_text(encoding='utf-8')
        section = text[text.index('## 8.2 NFC 분석 결과'):text.index('## 9.')]
        assert '| 정적 잠금 (page 2) |' in section and '싣지 않음' not in section
        await disconnect(client, env, owner)
