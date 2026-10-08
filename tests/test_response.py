import importlib.util
import pytest


def system(tmp_path):
    assert importlib.util.find_spec('backend.store'), 'persistent store is required'
    from backend.store import Store
    from backend.response import ResponseService
    s = Store('sqlite:///' + str(tmp_path/'test.db'))
    s.initialize()
    return s, ResponseService(s)


def test_simulation_has_audit_but_no_actual_block(tmp_path):
    s,r=system(tmp_path)
    action=r.request('block','8.8.4.4','capstone fixture',mode='SIMULATION')
    assert action['status']=='simulated'
    assert not s.list_sources('blocked')
    assert len(s.actions())==1


def test_manual_requires_separate_approval_and_is_idempotent(tmp_path):
    s,r=system(tmp_path)
    a=r.request('block','8.8.4.4','review',mode='MANUAL')
    assert a['status']=='pending'
    assert not s.list_sources('blocked')
    b=r.decide(a['id'],True)
    assert b['status']=='simulated'
    assert r.decide(a['id'],True)['status']=='simulated'
    assert len(s.actions())==1


@pytest.mark.parametrize('ip',['127.0.0.1','::1','0.0.0.0','224.0.0.1','192.168.1.1','8.8.8.8 & whoami','not-an-ip'])
def test_unsafe_addresses_refused(tmp_path,ip):
    s,r=system(tmp_path)
    with pytest.raises(ValueError): r.request('block',ip,'test')
    assert not s.list_sources('blocked')


def test_whitelist_checked_again_at_approval(tmp_path):
    s,r=system(tmp_path)
    a=r.request('block','8.8.4.4','review',mode='MANUAL')
    r.request('whitelist','8.8.4.4','protected resolver')
    with pytest.raises(ValueError): r.decide(a['id'],True)
    assert not s.list_sources('blocked')


def test_active_disabled_by_default(tmp_path):
    s,r=system(tmp_path)
    with pytest.raises(ValueError,match='disabled'): r.request('block','8.8.4.4','test',mode='ACTIVE')

def test_active_cannot_be_enabled_before_adapter_validation(tmp_path):
    from backend.response import ResponseService
    s,_=system(tmp_path)
    r=ResponseService(s,active_enabled=True)
    with pytest.raises(ValueError,match='disabled'):r.request('block','8.8.4.4','test',mode='ACTIVE')
    assert not r.active_enabled


def test_risk_is_not_confidence_and_is_monotonic():
    assert importlib.util.find_spec('backend.risk'), 'risk policy is required'
    from backend.risk import score_risk
    a=score_risk('DDoS',.8,0,{'fwd_packets':1,'bwd_packets':1,'duration_s':1})
    b=score_risk('DDoS',.8,10,{'fwd_packets':1000,'bwd_packets':0,'duration_s':1})
    assert b['score']>a['score']
    assert a['score'] != 80
    assert b['level'] in ['HIGH','CRITICAL']
    assert score_risk('Benign',.99,10,{})['score']==0
