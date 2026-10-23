"""합성 FS의 닫힌 cluster report 투영·예산·원인 보존 시험."""
from copy import deepcopy
from dataclasses import fields, replace
import json
from pathlib import Path
import time
from types import SimpleNamespace

import jsonschema
import pytest

from pweh.fs import BytesReader, Budget, FsError
from pweh.fs import cluster_report as C
SCHEMA = json.loads((Path(C.__file__).parents[1] / "schemas/cluster-report.schema.json").read_text())
from .builders import FatBuilder, ExfatBuilder, put_mbr

PRIVATE='SYNTHETIC_PRIVATE'


class RecordingSource(BytesReader):
    def __init__(self,data):
        super().__init__(data); self.reads=[]; self.hook=None
    def read(self,offset,size):
        self.reads.append((offset,size))
        if self.hook: self.hook(offset,size)
        return super().read(offset,size)


def fat(bits=12):
    return FatBuilder(bits,total_sectors={12:2048,16:8192,32:67000}[bits])


def inspect(data,**kwargs):
    src=data if isinstance(data,RecordingSource) else RecordingSource(data)
    args={'partition':1,'deadline':time.monotonic()+30}; args.update(kwargs)
    out=C.inspect_cluster_report(src,**args)
    out['source']={'kind':'evidence','evidence_id':'EV-0001','evidence_sha256':'a'*64,'evidence_size':src.size}
    out['params']={'partition':args['partition'],'max_seconds':30}
    jsonschema.Draft202012Validator(SCHEMA).validate(out)
    C.validate_cluster_report_accounting(out)
    assert out['coverage']['metadata_bytes_read']==sum(n for _,n in src.reads)
    assert all(n<=65536 for _,n in src.reads)
    assert PRIVATE not in json.dumps(out)
    return out


def failed(call,code):
    with pytest.raises(C.ClusterReportError) as caught: call()
    assert caught.value.code==code
    assert caught.value.data=={} and PRIVATE not in str(caught.value)
    assert caught.value.__suppress_context__


@pytest.mark.parametrize('bits',[12,16,32])
def test_actual_fat_complete_live_and_unreferenced(bits):
    b=fat(bits)
    b.add_file('/'+PRIVATE+'.BIN',b'123',clusters=[10])
    b.write_chain([20,21])
    out=inspect(b.image())
    assert out['status']=='ok'
    assert out['counts']['allocated_without_live_reference']==2
    assert out['rows'][0]['cluster']==20 and out['rows'][0]['clusters']==2
    assert out['rows'][0]['offset']==b.data_off+18*b.cs
    assert out['coverage']['allocation_clusters_examined']==b.count
    assert all(out[k] is False for k in C.FALSE_FIELDS)


@pytest.mark.parametrize('bits',[12,16,32])
def test_same_allocation_different_live_reference(bits):
    b=fat(bits); b.write_chain([20,21]); before=inspect(b.image())
    b.add_file('/'+PRIVATE+'.BIN',b'x'*(b.cs*2),clusters=[20,21]); after=inspect(b.image())
    assert before['counts']['allocated']==after['counts']['allocated']
    assert before['counts']['allocated_without_live_reference']==2
    assert after['counts']['allocated_without_live_reference']==0


@pytest.mark.parametrize('kind',['fat','exfat'])
def test_real_overlap_and_unallocated_units(kind):
    b=fat(16) if kind=='fat' else ExfatBuilder(total_sectors=8192)
    b.add_file('/A.BIN',b'a'*b.cs,clusters=[30]); b.add_file('/B.BIN',b'b'*b.cs,clusters=[40])
    if kind=='fat':
        b.set_fat(40,30)
        b.add_file('/ZERO.BIN',b'z',clusters=[50]); b.set_fat(50,0)
    else:
        b.used.discard(30)
        b.add_file('/C.BIN',b'c'*b.cs,clusters=[30])
        b.used.discard(40)
    out=inspect(b.image())
    assert out['counts']['unallocated_reference_count']==1
    assert out['counts']['unallocated_reference_basis']==('fat-chain-heads' if kind=='fat' else 'exfat-clusters')
    assert out['counts']['overlap_reference_events']>=1
    if kind=='fat':
        assert out['counts']['allocated_without_live_reference'] is None
        assert any(r['kind']=='chain-anomaly' and r['offset'] is None for r in out['rows'])
    else:
        assert all(r['ref'] is None for r in out['rows'] if r['kind']=='unallocated-reference')


def test_actual_exfat_complete_and_bitmap_free_count():
    b=ExfatBuilder(total_sectors=8192); b.add_file('/'+PRIVATE+'.BIN',b'x')
    b.reserve([30,31]); out=inspect(b.image())
    assert out['status']=='ok' and out['counts']['allocated_without_live_reference']==2
    assert out['counts']['bad'] is None and out['counts']['invalid_values'] is None
    assert out['counts']['free']+out['counts']['allocated']==b.count


@pytest.mark.parametrize('kind',['fat','exfat'])
def test_declared_cluster_cap_zero_observations(kind):
    b=fat() if kind=='fat' else ExfatBuilder(total_sectors=8192)
    out=inspect(b.image(),limits=C.ClusterReportLimits(scan_clusters=1))
    assert out['geometry']['cluster_count']==b.count
    assert out['counts']['allocation_examined']==0 and not out['rows']
    assert out['counts']['allocated_without_live_reference'] is None
    assert 'cluster_limit' in out['coverage']['reasons'] and out['coverage']['metadata_bytes_read']>0


def test_truncated_declared_geometry_is_not_shrunk():
    b=fat(); out=inspect(b.image()[:-512])
    assert out['geometry']['cluster_count']==b.count
    assert out['counts']['allocation_examined']==0 and not out['rows']
    assert out['coverage']['allocation_clusters_unexamined']==b.count
    assert out['coverage']['reasons']==['metadata_inconsistent']


def test_rows_cap_preserves_whole_counts():
    b=fat()
    for c in [20,22,24]: b.set_fat(c,b.eoc)
    out=inspect(b.image(),limits=C.ClusterReportLimits(rows=1))
    assert out['counts']['allocated_without_live_reference']==3
    assert len(out['rows'])==1 and not out['coverage']['rows_complete']
    assert out['coverage']['reference_map_complete'] and out['coverage']['allocation_complete']
    assert out['coverage']['reasons']==['rows_limit']


@pytest.mark.parametrize('field',[f.name for f in fields(C.ClusterReportLimits)])
@pytest.mark.parametrize('bad',['bool','zero','float','high'])
def test_limits_downward_exact(field,bad):
    base=getattr(C.ClusterReportLimits(),field)
    value={'bool':True,'zero':0,'float':float(base),'high':base+1}[bad]
    failed(lambda:C.ClusterReportLimits(**{field:value}),'cluster_report_invalid')


@pytest.mark.parametrize('kwargs',[
    {'partition':True},{'partition':1.0},{'partition':0},{'partition':4097},
    {'deadline':True},{'deadline':float('nan')},{'deadline':float('inf')},{'deadline':10**400},
    {'limits':{}},{'cancel':True},
])
def test_exact_ingress_before_read(kwargs):
    src=RecordingSource(b'x'*512)
    args={'partition':1,'deadline':time.monotonic()+5}; args.update(kwargs)
    failed(lambda:C.inspect_cluster_report(src,**args),'cluster_report_invalid')
    assert not src.reads


@pytest.mark.parametrize('field,value',[('size',0),('size',True),('size',1.0),('size',1<<63),('base_offset',True),('base_offset',1),('read',None)])
def test_source_contract(field,value):
    src=SimpleNamespace(size=512,base_offset=0,read=lambda *a:pytest.fail('read'))
    setattr(src,field,value)
    failed(lambda:C.inspect_cluster_report(src,partition=1,deadline=time.monotonic()+5),'cluster_report_invalid')


@pytest.mark.parametrize('cancel',[lambda:True,lambda:1,lambda:PRIVATE,lambda:(_ for _ in ()).throw(RuntimeError(PRIVATE))])
def test_cancel_callbacks_fixed_before_read(cancel):
    src=RecordingSource(b'x'*512)
    failed(lambda:C.inspect_cluster_report(src,partition=1,deadline=time.monotonic()+5,cancel=cancel),'cancelled')
    assert not src.reads


def test_expired_deadline_before_geometry_no_output():
    src=RecordingSource(fat().image())
    failed(lambda:C.inspect_cluster_report(src,partition=1,deadline=time.monotonic()-1),'time_limit')
    assert not src.reads


@pytest.mark.parametrize('limit', ['steps','metadata_bytes'])
def test_pregeometry_cutoff_is_fixed_failure(limit):
    failed(lambda:inspect(fat().image(),limits=C.ClusterReportLimits(**{limit:1})),'cluster_report_failed')


def test_partition_missing_and_unsupported_filesystem():
    failed(lambda:inspect(fat().image(),partition=2),'partition_unavailable')
    failed(lambda:inspect(b'x'*4096),'partition_unavailable')
    data=bytearray(8192); put_mbr(data,[(0x07,1,15)])
    failed(lambda:inspect(bytes(data)),'cluster_report_unsupported')


@pytest.mark.parametrize('bad',[b'',bytearray(b'x'*512),PRIVATE,None,OSError(PRIVATE)])
def test_leaf_failure_is_fatal_even_if_fs_catches_it(monkeypatch,bad):
    src=RecordingSource(fat().image())
    def read(offset,n):
        if isinstance(bad,Exception): raise bad
        return bad
    src.read=read
    failed(lambda:C.inspect_cluster_report(src,partition=1,deadline=time.monotonic()+5),'cluster_read_failed')


def test_counted_leaf_splitting_rereads_and_exact_metadata_cap():
    src=RecordingSource(b'x'*(256<<10))
    lim=C.ClusterReportLimits(metadata_bytes=131073)
    counted=C._CountingSource(src,lim,Budget(deadline=time.monotonic()+5,max_steps=100),None)
    assert len(counted.read(0,131072))==131072
    assert counted.read(0,1)==b'x'
    with pytest.raises(FsError) as exc: counted.read(0,1)
    assert exc.value.data['limit']=='metadata_bytes'
    assert src.reads==[(0,65536),(65536,65536),(0,1)]
    assert counted.bytes_read==131073


def fake_volume(monkeypatch, *, legacy=None, after=None):
    """FS 구현을 반복하지 않고 조정기→부가 관찰의 접점만 고정한다."""
    geo=dict(kind='fat',fat_type='fat12',heap_offset=4096,cluster_size=512,max_cluster=9,volume_size=8192,
             bpb={'cluster_count':8,'fat_type':'fat12','fat_type_by_count':'fat12','num_fats':1},_w=SimpleNamespace(codes=lambda:[]))
    observed={}
    def open_volume(src,**kwargs):
        observed.update(kwargs); observed['src']=src
        if after: after(src,kwargs)
        return SimpleNamespace(**geo,cluster_report=lambda **k:deepcopy(legacy))
    monkeypatch.setattr(C,'detect_partitions',lambda src,**k:{'scheme':'none','partitions':[{'index':1,'start_offset':0,'size_bytes':8192}]})
    monkeypatch.setattr(C,'open_volume',open_volume)
    return observed


def legacy():
    return {'allocated':3,'bad':0,'invalid_values':0,'cross_linked':0,'unallocated_referenced':0,'allocated_unreferenced':2,
            'allocated_unreferenced_runs':[[3,2]],'unallocated_referenced_samples':[],'cross_linked_samples':[],
            'chain_anomalies':[], 'inspection':{**dict.fromkeys(C.FLAGS,True),'entries_observed':1,
            'allocation_clusters_examined':8,'allocation_free':5,'observed_referenced_clusters':1,'reasons':[]}}


def test_constructor_receives_one_budget_and_all_limits(monkeypatch):
    got=fake_volume(monkeypatch,legacy=legacy())
    inspect(b'x'*8192)
    assert got['metadata_mode']=='full'
    lim=got['limits']; budget=got['budget']
    assert lim.max_follow_steps==budget.max_steps==1<<20
    assert lim.max_entries==lim.max_list==16384
    assert lim.max_total_slots==lim.max_dir_slots==262144
    assert lim.max_report_items==128 and lim.max_scan_clusters==1<<20


@pytest.mark.parametrize('mutation', ['missing','unknown_reason','bool_count','unknown_ref','raw_state'])
def test_bad_internal_projection_never_publishes_raw(monkeypatch,mutation):
    data=legacy()
    if mutation=='missing': data.pop('inspection')
    elif mutation=='unknown_reason': data['inspection']['reasons']=[PRIVATE]
    elif mutation=='bool_count': data['inspection']['allocation_free']=True
    elif mutation=='unknown_ref': data['cross_linked_samples']=[{'cluster':3,'ref':PRIVATE}]
    else: data['chain_anomalies']=[{'ref':'root/1','status':PRIVATE,'size_check':'ok'}]
    fake_volume(monkeypatch,legacy=data)
    with pytest.raises(C.ClusterReportError) as caught: inspect(b'x'*8192)
    assert PRIVATE not in str(caught.value) and caught.value.data=={}


def test_output_bytes_truncates_rows_not_counts(monkeypatch):
    data=legacy(); data['allocated_unreferenced_runs']=[]; data['allocated_unreferenced']=0
    data['inspection']['reference_map_complete']=False; data['inspection']['reasons']=['reference_chain_incomplete']
    data['chain_anomalies']=[{'ref':'c123456789+123456789/123456789','status':'too_fragmented','size_check':'chain_shorter','clusters':123456789,'expected_clusters':1234567890} for _ in range(128)]
    fake_volume(monkeypatch,legacy=data)
    out=inspect(b'x'*8192,limits=C.ClusterReportLimits(output_bytes=8192))
    assert 0<len(out['rows'])<128 and not out['coverage']['rows_complete']
    assert out['counts']['allocated']==3 and 'rows_limit' in out['coverage']['reasons']


def test_system_refs_are_null_not_public_names(monkeypatch):
    data=legacy(); data['cross_linked']=3
    data['cross_linked_samples']=[{'cluster':3,'ref':name,'path':PRIVATE} for name in ('root','bitmap','upcase')]
    fake_volume(monkeypatch,legacy=data)
    out=inspect(b'x'*8192)
    assert [r['ref'] for r in out['rows'] if r['kind']=='overlap-reference']==[None]*3


def test_expired_after_geometry_keeps_zero_observation_partial(monkeypatch):
    now=[time.monotonic()]; end=now[0]+5
    fake_volume(monkeypatch,legacy=legacy(),after=lambda *a:now.__setitem__(0,end+1))
    monkeypatch.setattr(C.time,'monotonic',lambda:now[0])
    out=inspect(b'x'*8192,deadline=end)
    assert out['coverage']['reasons']==['time_limit']
    assert out['coverage']['allocation_clusters_unexamined']==8


def test_first_leaf_problem_not_replaced_by_later_cancel(monkeypatch):
    stop=[False]
    src=RecordingSource(b'x'*8192)
    def read(offset,size): stop[0]=True; raise OSError(PRIVATE)
    src.read=read
    failed(lambda:C.inspect_cluster_report(src,partition=1,deadline=time.monotonic()+5,cancel=lambda:stop[0]),'cluster_read_failed')


def test_postgeometry_metadata_stop_is_partial_without_second_deadline(monkeypatch):
    data=legacy()
    def open_volume(src,**kwargs):
        def cluster_report(**unused):
            try: src.read(0,4096)
            except FsError: pass
            data['inspection'].update(reference_map_complete=False,allocation_complete=False,allocation_clusters_examined=0,
                                      allocation_free=0,reasons=['metadata_bytes_limit'])
            data['allocated']=0
            return data
        return SimpleNamespace(kind='fat',fat_type='fat12',heap_offset=4096,cluster_size=512,max_cluster=9,volume_size=8192,
            bpb={'cluster_count':8,'fat_type':'fat12','fat_type_by_count':'fat12','num_fats':1},_w=SimpleNamespace(codes=lambda:[]),cluster_report=cluster_report)
    fake_volume(monkeypatch,legacy=data); monkeypatch.setattr(C,'open_volume',open_volume)
    out=inspect(b'x'*8192,limits=C.ClusterReportLimits(metadata_bytes=1024))
    assert out['coverage']['metadata_bytes_read']==1024 and out['coverage']['reasons']==['metadata_bytes_limit']


@pytest.mark.parametrize('signature',[b'PK\x03\x04',b'PK\x05\x06',b'PK\x07\x08',b'ustar\0',b'ustar '])
def test_archive_signature_from_existing_detection_read(signature):
    data=bytearray(4096); offset=257 if signature.startswith(b'ustar') else 0
    data[offset:offset+len(signature)]=signature
    src=RecordingSource(bytes(data))
    failed(lambda:inspect(src),'cluster_report_unsupported')
    assert src.reads.count((0,512))==1


def test_exfat_single_fat_active_one_does_not_promote_full_fallback():
    b=ExfatBuilder(total_sectors=8192,number_of_fats=1,volume_flags=1)
    b.add_file('/'+PRIVATE+'.BIN',b'x'); b.reserve([30,31])
    out=inspect(b.image())
    assert out['status']=='partial' and out['geometry']['cluster_count']==b.count
    assert out['coverage']['reasons']==['metadata_inconsistent']
    assert out['counts']['allocation_examined']==out['counts']['allocated']==out['counts']['free']==0
    assert out['counts']['observed_referenced_clusters']==0
    assert out['counts']['allocated_without_live_reference'] is None and out['rows']==[]
    assert out['coverage']['allocation_clusters_unexamined']==b.count
    assert not any(out['coverage'][k] for k in C.FLAGS[:3])
