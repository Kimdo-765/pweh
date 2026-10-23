"""live 참조 보고서의 독립 닫힌 fixture·숫자 회계. 실제 증거 없음."""
from copy import deepcopy
import json
from pathlib import Path

import jsonschema
import pytest

from pweh.fs import cluster_report as C

SCHEMA = json.loads((Path(C.__file__).parents[1] / 'schemas/cluster-report.schema.json').read_text())
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


def report():
    """생산자를 호출하지 않고 손으로 구성한 8클러스터 관찰."""
    return {
        'schema': 'pweh.cluster-report/v1', 'profile': 'fat-exfat-live-reference-v1', 'status': 'ok',
        'source': {'kind': 'evidence', 'evidence_id': 'EV-0001', 'evidence_sha256': 'a'*64, 'evidence_size': 8192},
        'params': {'partition': 1, 'max_seconds': 45},
        'geometry': {'fs_type': 'fat12', 'partition_offset': 0, 'partition_size': 8192,
                     'data_offset': 4096, 'cluster_size': 512, 'cluster_count': 8},
        'counts': {'allocation_examined': 8, 'allocated': 3, 'free': 5, 'bad': 0, 'invalid_values': 0,
                   'observed_referenced_clusters': 1, 'overlap_reference_events': 0,
                   'unallocated_reference_count': 0, 'unallocated_reference_basis': 'fat-chain-heads',
                   'allocated_without_live_reference': 2},
        'rows': [{'kind': 'allocated-without-live-reference', 'ref': None, 'cluster': 3, 'clusters': 2,
                  'offset': 4608, 'length': 1024, 'chain_status': None, 'size_check': None,
                  'observed_clusters': None, 'expected_clusters': None}],
        'coverage': {'reference_walk_complete': True, 'reference_map_complete': True, 'allocation_complete': True,
                     'rows_complete': True, 'entries_observed': 1, 'allocation_clusters_examined': 8,
                     'allocation_clusters_unexamined': 0, 'rows_reported': 1, 'metadata_bytes_read': 2048,
                     'steps': 100, 'reasons': []},
        'limitations': ['current_live_reference_model_only', 'observed_metadata_only', 'incomplete_reference_map_not_orphan_evidence',
                        'allocation_state_not_historical_ownership', 'samples_are_bounded', 'no_automatic_extraction',
                        'no_media_decoding', 'no_playback_or_complete_recording_verification'],
        **{k: False for k in ('whole_evidence_examined', 'orphan_files_verified', 'historical_allocation_verified',
                             'file_ownership_verified', 'media_decoded', 'playback_verified', 'payload_semantics_examined')},
    }


def set_at(value, path, replacement):
    keys = path.split('.')
    for key in keys[:-1]:
        value = value[int(key)] if isinstance(value, list) else value[key]
    key = int(keys[-1]) if isinstance(value, list) else keys[-1]
    value[key] = replacement


def validate(value):
    VALIDATOR.validate(value)
    C.validate_cluster_report_accounting(value)


def test_schema_itself_and_independent_report():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    validate(report())


@pytest.mark.parametrize('kind', ['fat12', 'fat16', 'fat32', 'exfat'])
def test_four_filesystems_closed_units(kind):
    value = report(); value['geometry']['fs_type'] = kind
    if kind == 'exfat':
        value['counts'].update(bad=None, invalid_values=None, unallocated_reference_basis='exfat-clusters')
    validate(value)


@pytest.mark.parametrize('path,value', [
    ('schema','other'), ('profile','other'), ('status','unsupported'), ('source.kind','file'),
    ('source.evidence_id','EV-001'), ('source.evidence_id','EV-0000001'), ('source.evidence_id','EV-0001\n'),
    ('source.evidence_sha256','a'*64+'\n'), ('source.evidence_sha256','A'*64),
    ('params.partition',0), ('params.partition',4097), ('params.max_seconds',0), ('params.max_seconds',46),
    ('geometry.fs_type','ntfs'), ('geometry.cluster_size',513), ('geometry.cluster_size',1<<26),
    ('rows.0.kind','orphan'), ('rows.0.ref','SYNTHETIC_PRIVATE'), ('rows.0.ref','root/0\n'),
    ('rows.0.chain_status','ok'), ('rows.0.clusters',0), ('rows.0.cluster',1),
    ('coverage.entries_observed',16385), ('coverage.metadata_bytes_read',(32<<20)+1),
    ('coverage.rows_reported',129), ('coverage.reasons',['SYNTHETIC_PRIVATE']),
    ('coverage.reasons',['rows_limit','rows_limit']), ('counts.unallocated_reference_basis','files'),
])
def test_schema_rejects_closed_fields(path, value):
    out=report(); set_at(out,path,value)
    with pytest.raises(jsonschema.ValidationError): VALIDATOR.validate(out)


@pytest.mark.parametrize('path', ['source','params','geometry','counts','coverage','rows.0',''])
def test_unknown_keys_and_missing_required(path):
    for remove in (False,True):
        out=report(); node=out
        if path:
            for k in path.split('.'): node=node[int(k)] if isinstance(node,list) else node[k]
        if remove: node.pop(next(iter(node)))
        else: node['SYNTHETIC_PRIVATE']='SYNTHETIC_PRIVATE'
        with pytest.raises(jsonschema.ValidationError): VALIDATOR.validate(out)


@pytest.mark.parametrize('field', C.FALSE_FIELDS)
@pytest.mark.parametrize('value', [True,0,None,'false'])
def test_never_promote_false_guarantees(field,value):
    out=report(); out[field]=value
    with pytest.raises(jsonschema.ValidationError): VALIDATOR.validate(out)


@pytest.mark.parametrize('path', ['params.partition','params.max_seconds','source.evidence_size','geometry.cluster_count',
    'geometry.partition_offset','geometry.cluster_size','counts.allocated','counts.bad','counts.invalid_values',
    'counts.observed_referenced_clusters','counts.allocated_without_live_reference','coverage.steps','coverage.entries_observed',
    'rows.0.cluster','rows.0.clusters','rows.0.length','rows.0.offset'])
@pytest.mark.parametrize('kind', ['bool','float'])
def test_exact_integer_not_coerced(path,kind):
    out=report(); node=out
    for k in path.split('.'): node=node[int(k)] if isinstance(node,list) else node[k]
    if path=='params.max_seconds' and kind=='float':
        return  # 공개 초 인자는 유한 float를 명시적으로 허용한다.
    set_at(out,path,True if kind=='bool' else float(node))
    with pytest.raises(C.ClusterReportError): C.validate_cluster_report_accounting(out)


@pytest.mark.parametrize('path,value', [
    ('counts.free',4), ('counts.invalid_values',4), ('counts.observed_referenced_clusters',9),
    ('counts.allocation_examined',7), ('coverage.allocation_clusters_examined',7),
    ('coverage.allocation_clusters_unexamined',1), ('coverage.rows_reported',0),
    ('rows.0.offset',4609), ('rows.0.length',512), ('rows.0.cluster',9),
    ('counts.allocated_without_live_reference',1), ('status','partial'), ('coverage.reference_walk_complete',False),
    ('coverage.reference_map_complete',False), ('coverage.allocation_complete',False),
    ('params.max_seconds',float('inf')), ('params.max_seconds',10**400),
    ('geometry.partition_size',(1<<63)-1), ('geometry.data_offset',(1<<63)-1),
])
def test_semantic_relations(path,value):
    out=report(); set_at(out,path,value)
    with pytest.raises(C.ClusterReportError) as caught: C.validate_cluster_report_accounting(out)
    assert caught.value.data=={} and 'SYNTHETIC_PRIVATE' not in str(caught.value)


def test_partial_counts_preserved_but_no_unref_claim():
    out=report(); out['status']='partial'
    out['coverage'].update(reference_walk_complete=False,reference_map_complete=False,reasons=['max_entries'],rows_reported=0)
    out['rows']=[]; out['counts']['allocated_without_live_reference']=None
    validate(out)
    out['rows']=report()['rows']; out['coverage']['rows_reported']=1
    with pytest.raises(C.ClusterReportError): C.validate_cluster_report_accounting(out)


def test_geometry_only_inconsistent_zero_observation():
    out=report(); out['source']['evidence_size']=4096; out['status']='partial'; out['rows']=[]
    for k in C.COUNT_KEYS:
        if k not in ('unallocated_reference_basis','allocated_without_live_reference'): out['counts'][k]=0
    out['counts']['allocated_without_live_reference']=None
    out['coverage'].update(**dict.fromkeys(C.FLAGS,False),rows_reported=0,allocation_clusters_examined=0,
                           allocation_clusters_unexamined=8,entries_observed=0,reasons=['metadata_inconsistent'])
    validate(out)


def test_rows_truncation_keeps_counts_and_steps_actual_value():
    out=report(); out['status']='partial'; out['rows']=[]
    out['coverage'].update(rows_complete=False,rows_reported=0,reasons=['rows_limit'],steps=(1<<20)+17)
    validate(out)


@pytest.mark.parametrize('ref', ['root/3','c4/1','c4+512/1','n4+512/1',None])
def test_chain_anomaly_without_invented_extent_or_counts(ref):
    out=report(); out['status']='partial'; out['counts']['allocated_without_live_reference']=None
    out['coverage'].update(reference_map_complete=False,reasons=['reference_chain_incomplete'])
    out['rows']=[dict.fromkeys(C.ROW_KEYS)]
    out['rows'][0].update(kind='chain-anomaly',ref=ref,chain_status='empty',size_check='no_clusters')
    validate(out)


def test_unref_runs_cannot_overlap_or_hide_missing_complete_rows():
    out=report(); out['rows']*=2; out['coverage']['rows_reported']=2
    with pytest.raises(C.ClusterReportError): C.validate_cluster_report_accounting(out)
    out=report(); out['rows']=[]; out['coverage']['rows_reported']=0
    with pytest.raises(C.ClusterReportError): C.validate_cluster_report_accounting(out)


def test_validator_requires_full_envelope():
    out=report(); out.pop('source'); out.pop('params')
    with pytest.raises(C.ClusterReportError): C.validate_cluster_report_accounting(out)
