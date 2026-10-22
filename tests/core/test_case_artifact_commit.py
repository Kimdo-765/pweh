"""선택 artifact seal/commit callback의 합성 회귀."""
import time
import pytest
from pweh.runtime import get_runtime
from pweh.errors import PwehError

@pytest.fixture
def case(workspace,auth):
    c=get_runtime('test').cases.create(title='합성 artifact commit',authorization=auth)
    (c.dir/'signals/capture.sr').write_bytes(b'PWEH SYNTHETIC')
    return c

def add(case,**kwargs):
    return case.register_artifact('signals/capture.sr',kind='signal-capture',producer='test',**kwargs)

def test_check_precedes_commit_and_commit_precedes_audit(case,monkeypatch):
    seen=[]
    def check(entry):
        assert entry['size']==14 and entry['is_dir'] is False
        assert entry['path']=='signals/capture.sr' and len(entry['sha256'])==64
        assert case.artifacts()==[]
        seen.append('check')
    def committed(entry):
        assert case.artifacts()==[entry]
        seen.append('commit')
    def audit(value):
        assert seen==['check','commit']
        seen.append('audit')
    monkeypatch.setattr(case,'audit',audit)
    add(case,check=check,on_commit=committed,deadline=time.monotonic()+2,replace_existing=False)
    assert seen==['check','commit','audit']

@pytest.mark.parametrize('return_value',[False,True,'not-completed'])
def test_check_must_complete_with_none(case,return_value):
    with pytest.raises(PwehError): add(case,check=lambda e:return_value)
    assert not case.artifacts()

def test_check_error_does_not_commit(case):
    def check(e): raise PwehError('합성 검사 실패')
    with pytest.raises(PwehError): add(case,check=check)
    assert not case.artifacts()

@pytest.mark.parametrize('where',['commit','audit'])
def test_post_commit_error_keeps_metadata(case,monkeypatch,where):
    seen=[]
    def fail(*a): raise RuntimeError('합성 후속 오류')
    def committed(e):
        seen.append(e)
        if where=='commit': fail()
    if where=='audit': monkeypatch.setattr(case,'audit',fail)
    with pytest.raises(RuntimeError): add(case,on_commit=committed)
    assert seen==case.artifacts() and len(seen)==1

def test_explicit_no_replace_and_default_update(case):
    first=add(case)
    with pytest.raises(PwehError,match='artifact_exists'): add(case,replace_existing=False)
    assert case.artifacts()==[first]
    assert add(case)['id']==first['id']

@pytest.mark.parametrize('deadline',[True,float('inf'),float('nan'),10**400,'1',0])
def test_deadline_invalid_or_expired_cannot_commit(case,deadline):
    with pytest.raises(PwehError): add(case,deadline=deadline)
    assert not case.artifacts()

def test_corrupted_observed_entry_rejected_before_metadata_publish(case,monkeypatch):
    # path stat을 사용하는 기본 생산자를 바꾸지 않고 최종 check에서 사실을 대조한다.
    import pweh.case as C
    original=C.atomic_write_json
    called=[]
    monkeypatch.setattr(C,'atomic_write_json',lambda *a,**k:called.append(1))
    def check(entry):
        if entry['sha256']!='a'*64: raise PwehError('고정 fd 해시 불일치')
    with pytest.raises(PwehError): add(case,sha256='b'*64,check=check)
    assert not called and not case.artifacts()
