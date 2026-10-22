"""실제 Windows/PnP 없이 두 합성 Present graph의 결속만 시험한다."""
import copy
from dataclasses import FrozenInstanceError, asdict, replace
import json
import time
import traceback
from types import SimpleNamespace

import pytest

from pweh import portidentity as I, usb_binding as U
from pweh.errors import PwehError

VID, PID = '0403', '6010'
PARENT = r'USB\VID_0403&PID_6010\SYNTHETIC_A'
OTHER = r'USB\VID_1234&PID_5678\SYNTHETIC_OTHER'
MI0 = r'USB\VID_0403&PID_6010&MI_00\SYNTHETIC_MI0'
MI1 = r'USB\VID_0403&PID_6010&MI_01\SYNTHETIC_MI1'
ROOT = r'HTREE\ROOT\0'


def node(ident, parent=ROOT, com=None, cls='USB', state='ok'):
    return {'instance_id': ident, 'parent': parent, 'parent_state': state,
            'com': com, 'pnp_class': cls}


def graph(nodes=None):
    if nodes is None:
        nodes = [node(PARENT), node(MI0, PARENT, 'COM31', 'Ports'),
                 node(MI1, PARENT, 'COM4096', 'Ports'), node(OTHER)]
    snapshot = {'present_count': len(nodes), 'nodes': nodes, 'errors': []}
    return {'schema': 'pweh.pnp-usb-scope/v1', 'snapshots': [snapshot, copy.deepcopy(snapshot)]}


def raw(data):
    return json.dumps(data, separators=(',', ':')).encode()


def parse(data=None, **kwargs):
    options = dict(vid=VID, pid=PID, deadline=time.monotonic() + 5)
    options.update(kwargs)
    return U.parse_windows_usb_scope(raw(graph() if data is None else data), **options)


def change(data, mutate):
    for snapshot in data['snapshots']:
        mutate(snapshot['nodes'])
        snapshot['present_count'] = len(snapshot['nodes'])
    return data


def error(code, call):
    with pytest.raises(PwehError) as exc:
        call()
    assert exc.value.code == code
    assert exc.value.data == {} and exc.value.hint is None
    return exc.value


@pytest.fixture(autouse=True)
def no_live_queries(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('순수 입력 시험에서 OS 조회 금지')
    for name in ('_windows_output', 'probe_identity', 'linux_sibling_scope'):
        monkeypatch.setattr(I, name, forbidden)


def test_unique_parent_whole_subtree_aliases_and_closed_fields():
    scope = parse()
    assert scope.usb_parent == PARENT
    assert scope.claim_keys == tuple(sorted(('winif:' + PARENT, 'winif:' + MI0,
                                            'winif:' + MI1, 'win:COM31', 'win:COM4096')))
    assert scope.com_aliases == (('COM31', MI0), ('COM4096', MI1))
    assert scope.backend == 'windows' and scope.whole_device is True
    assert scope.selector_kind == 'vid-pid' and scope.provider_basis == 'pweh.pnp-usb-scope/v1'
    assert set(asdict(scope)) == {'vid', 'pid', 'usb_parent', 'claim_keys', 'com_aliases',
                                 'binding_nodes', 'backend', 'selector_kind', 'whole_device', 'provider_basis'}
    assert not any(OTHER in key for key in scope.claim_keys)
    assert hash(scope)


@pytest.mark.parametrize('include_root', [False, True])
def test_non_com_parent_is_valid_and_root_sentinel_remains_optional(include_root):
    nodes = [node(PARENT)]
    if include_root:
        nodes.append(node(ROOT, None, state='root'))
    scope = parse(graph(nodes))
    assert scope.claim_keys == ('winif:' + PARENT,) and scope.com_aliases == ()


def test_com_can_be_below_non_usb_function_child():
    child = r'FTDIBUS\SYNTHETIC\0000'
    scope = parse(graph([node(PARENT), node(MI0, PARENT), node(child, MI0, 'COM8', 'Ports')]))
    assert scope.com_aliases == (('COM8', child),)
    assert 'winif:' + child in scope.claim_keys


def test_normalization_permutation_and_caller_mutation_are_independent():
    data = graph()
    expected = parse(data)
    data['snapshots'][1]['nodes'].reverse()
    for snap in data['snapshots']:
        for row in snap['nodes']:
            row['instance_id'] = row['instance_id'].lower()
            row['parent'] = row['parent'].lower()
            row['pnp_class'] = row['pnp_class'].upper()
            if row['com']:
                row['com'] = row['com'].lower()
    scope = parse(data, vid='0403', pid='6010')
    assert scope == expected
    data['snapshots'][0]['nodes'].clear()
    assert scope == expected
    with pytest.raises(FrozenInstanceError):
        scope.usb_parent = OTHER
    with pytest.raises(TypeError):
        scope.claim_keys[0] = 'different'


def test_ascii_hex_ids_canonicalize():
    parent = r'USB\VID_ABCD&PID_EF01\SYNTHETIC'
    scope = parse(graph([node(parent)]), vid='aBcD', pid='EF01')
    assert (scope.vid, scope.pid) == ('abcd', 'ef01')


@pytest.mark.parametrize('value', [None, 403, True, '', '403', '04030', '0x403', ' 0403', '0403 ',
                                   '０４０３', '04ſ3', '040\n', 'ZZZZ', b'0403'])
@pytest.mark.parametrize('field', ['vid', 'pid'])
def test_identifier_is_exact_four_ascii_hex(field, value):
    error('usb_scope_invalid', lambda: parse(**{field: value}))


@pytest.mark.parametrize('value', [None, {}, [], 'text', bytearray(b'{}'), memoryview(b'{}')])
def test_only_exact_bytes_are_admitted(value):
    error('usb_scope_invalid', lambda: U.parse_windows_usb_scope(value, vid=VID, pid=PID,
                                                                deadline=time.monotonic() + 5))


@pytest.mark.parametrize('deadline', [True, None, '5', float('nan'), float('inf'), -float('inf'), 10**400])
def test_invalid_deadline_is_fixed(deadline):
    error('usb_scope_invalid', lambda: parse(deadline=deadline))


def test_expired_deadline_and_long_deadline_clamp(monkeypatch):
    error('usb_scope_timeout', lambda: parse(deadline=time.monotonic() - 1))
    called = []
    original = I._parse_windows_scope_graph
    def observed(value, *, deadline, cancel):
        called.append(deadline - time.monotonic())
        return original(value, deadline=deadline, cancel=cancel)
    monkeypatch.setattr(I, '_parse_windows_scope_graph', observed)
    parse(deadline=time.monotonic() + 1000)
    assert 0 < called[0] <= 5


def test_absent_requires_complete_graph():
    error('usb_scope_absent', lambda: parse(graph([node(OTHER)])))
    data = graph([node(OTHER)])
    data['snapshots'][0]['errors'] = ['SYNTHETIC_PRIVATE']
    error('usb_scope_unknown', lambda: parse(data))


def test_two_physical_parents_are_ambiguous_not_two_interfaces():
    second = PARENT.replace('SYNTHETIC_A', 'SYNTHETIC_B')
    error('usb_scope_ambiguous', lambda: parse(change(graph(), lambda rows: rows.append(node(second)))))
    assert parse().usb_parent == PARENT


@pytest.mark.parametrize('ident', [
    r'USB\VID_0403&PID_6010&REV_0000\SYNTHETIC_PRIVATE',
    r'USB\VID_0403&PID_6010&MI_XX\SYNTHETIC_PRIVATE',
    r'USB\VID_0403&PID_6010\SYNTHETIC_PRIVATE\EXTRA',
    r'USB\VID_0403&PID_BAD\SYNTHETIC_PRIVATE',
    r'USB\VID_BAD&PID_6010\SYNTHETIC_PRIVATE',
    r'USB\VID_0403\SYNTHETIC_PRIVATE',
    r'USB\VID0403&PID6010\SYNTHETIC_PRIVATE',
])
def test_unparsed_possible_candidate_cannot_be_dropped_to_unique(ident):
    error('usb_scope_unknown', lambda: parse(change(graph(), lambda rows: rows.append(node(ident)))))


def test_definite_other_pair_and_infrastructure_are_not_requested_candidates():
    extra = [node(r'USB\VID_1234&PID_5678&REV_0000\SYNTHETIC'), node(r'USB\ROOT_HUB30\SYNTHETIC')]
    assert parse(change(graph(), lambda rows: rows.extend(extra))) == parse()


@pytest.mark.parametrize('nodes', [
    [node(MI0)],
    [node(OTHER), node(MI0, OTHER)],
    [node(PARENT), node(OTHER), node(MI0, OTHER)],
    [node(PARENT), node(r'USB\VID_1234&PID_5678&MI_00\SYNTHETIC', PARENT)],
])
def test_mi_requires_matching_physical_parent(nodes):
    error('usb_scope_unknown', lambda: parse(graph(nodes)))


def test_unrelated_mi_with_its_own_parent_is_not_ambiguous():
    extra = node(r'USB\VID_1234&PID_5678&MI_00\SYNTHETIC', OTHER)
    assert parse(change(graph(), lambda rows: rows.append(extra))) == parse()


@pytest.mark.parametrize('inside', [False, True])
def test_selected_com_duplicate_anywhere_is_unknown(inside):
    extra = node(r'ROOT\SYNTHETIC\DUPLICATE', PARENT if inside else OTHER, 'COM31', 'Ports')
    error('usb_scope_unknown', lambda: parse(change(graph(), lambda rows: rows.append(extra))))


def test_ports_without_alias_unknown_but_unrelated_ports_do_not_change_scope():
    error('usb_scope_unknown', lambda: parse(change(graph(), lambda rows: rows[1].update(com=None))))
    extra = node(r'ROOT\SYNTHETIC\UNMAPPED', OTHER, cls='Ports')
    assert parse(change(graph(), lambda rows: rows.append(extra))) == parse()


@pytest.mark.parametrize('malformed', [
    b'\xff', b'{"SYNTHETIC_PRIVATE":', b'{}', b'[]', b'null',
    b'{"schema":1,"schema":2}', b'{"private":NaN}', b'{"private":1e999}',
    b'[' * 17 + b']' * 17, b'{"private":' + b'1' * 129 + b'}',
    b' ' * ((1 << 20) + 1),
])
def test_malformed_or_over_budget_graph_is_unknown_without_raw_leak(malformed):
    exc = error('usb_scope_unknown', lambda: U.parse_windows_usb_scope(
        malformed, vid=VID, pid=PID, deadline=time.monotonic() + 5))
    assert 'SYNTHETIC_PRIVATE' not in ''.join(traceback.format_exception(exc))


@pytest.mark.parametrize('fault', ['missing', 'count', 'duplicate', 'cycle', 'errors', 'changed', 'parent-state'])
def test_incomplete_graph_never_produces_binding(fault):
    data = graph()
    a = data['snapshots'][0]
    if fault == 'missing': a['nodes'][1]['parent'] = 'ROOT\\SYNTHETIC_MISSING'
    elif fault == 'count': a['present_count'] += 1
    elif fault == 'duplicate': a['nodes'][1] = a['nodes'][0].copy()
    elif fault == 'cycle': a['nodes'][0]['parent'] = MI0
    elif fault == 'errors': a['errors'] = ['SYNTHETIC_PRIVATE']
    elif fault == 'changed': a['nodes'][1]['com'] = 'COM32'
    elif fault == 'parent-state': a['nodes'][1]['parent_state'] = 'unknown'
    error('usb_scope_unknown', lambda: parse(data))


@pytest.mark.parametrize('total', [64, 65, 256, 257])
def test_scope_key_limit_is_not_truncated_to_success(total):
    nodes = [node(PARENT)] + [node(f'ROOT\\SYNTHETIC\\{i}', PARENT) for i in range(total - 1)]
    if total == 64:
        assert len(parse(graph(nodes)).claim_keys) == total
    else:
        error('usb_scope_unknown', lambda: parse(graph(nodes)))


@pytest.mark.parametrize('cancel,code', [(lambda: True, 'usb_scope_cancelled'),
                                        (lambda: 1, 'usb_scope_unknown'),
                                        (lambda: None, 'usb_scope_unknown')])
def test_cancel_results_never_return_partial(cancel, code):
    error(code, lambda: parse(cancel=cancel))


def test_callback_exception_is_closed_and_fresh_maps_unknown_to_changed():
    scope = parse()
    def private():
        raise ValueError('SYNTHETIC_PRIVATE_CALLBACK')
    exc = error('usb_scope_unknown', lambda: parse(cancel=private))
    assert 'SYNTHETIC_PRIVATE_CALLBACK' not in ''.join(traceback.format_exception(exc))
    error('usb_scope_changed', lambda: U.revalidate_windows_usb_scope(scope, raw(graph()),
             deadline=time.monotonic() + 5, cancel=private))


def test_candidate_loop_and_subtree_share_deadline(monkeypatch):
    clock = {'now': time.monotonic()}
    original = I._parse_windows_scope_graph
    deadlines = []
    monkeypatch.setattr(U, 'time', SimpleNamespace(monotonic=lambda: clock['now']))
    def advance(value, *, deadline, cancel):
        deadlines.append(deadline)
        result = original(value, deadline=deadline, cancel=cancel)
        clock['now'] = deadline
        return result
    monkeypatch.setattr(I, '_parse_windows_scope_graph', advance)
    error('usb_scope_timeout', lambda: parse(deadline=clock['now'] + 100))
    assert deadlines == [clock['now']]


def test_same_end_reaches_subtree_and_cancellation_after_graph(monkeypatch):
    original_graph, original_subtree = I._parse_windows_scope_graph, I._windows_scope_subtree
    ends = []
    def first(value, *, deadline, cancel):
        ends.append(deadline)
        return original_graph(value, deadline=deadline, cancel=cancel)
    def second(value, parent, *, deadline, cancel):
        ends.append(deadline)
        return original_subtree(value, parent, deadline=deadline, cancel=cancel)
    monkeypatch.setattr(I, '_parse_windows_scope_graph', first)
    monkeypatch.setattr(I, '_windows_scope_subtree', second)
    parse()
    assert len(ends) == 2 and ends[0] == ends[1]
    cancelled = {'value': False}
    def cancel_after_graph(value, *, deadline, cancel):
        result = original_graph(value, deadline=deadline, cancel=cancel)
        cancelled['value'] = True
        return result
    monkeypatch.setattr(I, '_parse_windows_scope_graph', cancel_after_graph)
    error('usb_scope_cancelled', lambda: parse(cancel=lambda: cancelled['value']))


def test_final_callback_cannot_return_success_after_deadline(monkeypatch):
    clock = {'now': time.monotonic(), 'built': False}
    deadline = clock['now'] + 1
    original = U.WindowsUsbScope
    def built(*args, **kwargs):
        result = original(*args, **kwargs)
        clock['built'] = True
        return result
    def cancelled():
        if clock['built']:
            clock['now'] = deadline
        return False
    monkeypatch.setattr(U, 'WindowsUsbScope', built)
    monkeypatch.setattr(U, 'time', SimpleNamespace(monotonic=lambda: clock['now']))
    error('usb_scope_timeout', lambda: parse(deadline=deadline, cancel=cancelled))


@pytest.mark.parametrize('fault', ['parent', 'alias', 'class', 'subtree', 'absent', 'ambiguous', 'unknown'])
def test_fresh_requires_same_binding_and_never_reselects(fault):
    scope = parse()
    data = graph()
    if fault == 'parent':
        data = json.loads(raw(data).replace(b'SYNTHETIC_A', b'SYNTHETIC_NEW'))
    elif fault == 'alias': change(data, lambda rows: rows[1].update(com='COM32'))
    elif fault == 'class': change(data, lambda rows: rows[1].update(pnp_class='USB'))
    elif fault == 'subtree': change(data, lambda rows: rows.append(node(r'ROOT\SYNTHETIC\NEW', PARENT)))
    elif fault == 'absent': data = graph([node(OTHER)])
    elif fault == 'ambiguous': change(data, lambda rows: rows.append(node(PARENT + '2')))
    elif fault == 'unknown': data['snapshots'][0]['errors'] = ['SYNTHETIC_PRIVATE']
    error('usb_scope_changed', lambda: U.revalidate_windows_usb_scope(scope, raw(data), deadline=time.monotonic() + 5))
    assert scope == parse()


def test_fresh_accepts_unrelated_changes_but_rechecks_complete_graphs():
    scope = parse()
    data = change(graph(), lambda rows: rows.append(node(r'ROOT\SYNTHETIC\OTHER', OTHER)))
    fresh = U.revalidate_windows_usb_scope(scope, raw(data), deadline=time.monotonic() + 5)
    assert fresh == scope and fresh is not scope
    data['snapshots'][1]['nodes'].pop()
    error('usb_scope_changed', lambda: U.revalidate_windows_usb_scope(scope, raw(data), deadline=time.monotonic() + 5))


@pytest.mark.parametrize('cancel,deadline,code', [
    (lambda: True, 5, 'usb_scope_cancelled'), (None, -1, 'usb_scope_timeout'),
])
def test_fresh_preserves_cancel_and_timeout(cancel, deadline, code):
    scope = parse()
    error(code, lambda: U.revalidate_windows_usb_scope(scope, raw(graph()),
          deadline=time.monotonic() + deadline, cancel=cancel))


@pytest.mark.parametrize('field,value', [('claim_keys', []), ('com_aliases', []), ('binding_nodes', []),
                                       ('usb_parent', OTHER), ('vid', 'ABCD'), ('pid', True),
                                       ('claim_keys', ('win:COM1',))])
def test_frozen_value_rejects_mutable_or_inconsistent_fields(field, value):
    scope = parse()
    error('usb_scope_invalid', lambda: replace(scope, **{field: value}))


def test_api_input_and_helper_unexpected_exception_do_not_leak(monkeypatch):
    error('usb_scope_invalid', lambda: parse(cancel='private'))
    error('usb_scope_invalid', lambda: U.revalidate_windows_usb_scope({}, raw(graph()), deadline=time.monotonic() + 5))
    def private(*args, **kwargs):
        raise RuntimeError('SYNTHETIC_PRIVATE_HELPER')
    monkeypatch.setattr(I, '_parse_windows_scope_graph', private)
    exc = error('usb_scope_unknown', lambda: parse())
    assert 'SYNTHETIC_PRIVATE_HELPER' not in ''.join(traceback.format_exception(exc))
