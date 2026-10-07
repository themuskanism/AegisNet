import importlib.util
import time
from fastapi.testclient import TestClient


def app_for(tmp_path):
    assert importlib.util.find_spec('backend.api'), 'API integration is required'
    from backend.api import create_app
    return create_app(database_url='sqlite:///'+str(tmp_path/'api.db'),artifacts=tmp_path,token='test-secret')


def test_health_reports_missing_model_and_empty_database(tmp_path):
    with TestClient(app_for(tmp_path)) as c:
        h=c.get('/api/health').json()
        assert h['database']['status']=='ready'
        assert h['model']['status']=='unavailable'
        assert h['capture']['status']=='stopped'
        assert c.get('/api/overview').json()['totals']['flows']==0


def test_mutations_require_token_and_validate_input(tmp_path):
    with TestClient(app_for(tmp_path)) as c:
        body={'action':'block','ip':'8.8.4.4','reason':'test','mode':'SIMULATION'}
        assert c.post('/api/actions',json=body).status_code==401
        result=c.post('/api/actions',json=body,headers={'Authorization':'Bearer test-secret'})
        assert result.status_code==200 and result.json()['status']=='simulated'
        body['ip']='8.8.8.8;whoami'
        assert c.post('/api/actions',json=body,headers={'Authorization':'Bearer test-secret'}).status_code==422
        assert c.get('/api/response').json()['blocked']==[]


def test_unknown_incident_and_missing_replay_are_explicit(tmp_path):
    with TestClient(app_for(tmp_path)) as c:
        assert c.get('/api/incidents/absent').status_code==404
        assert c.post('/api/demo/replay',headers={'Authorization':'Bearer test-secret'}).status_code==409


def test_queue_overflow_is_counted_without_blocking(tmp_path):
    assert importlib.util.find_spec('backend.runtime'), 'bounded runtime is required'
    from backend.runtime import Runtime
    from backend.store import Store
    from backend.flows import Packet
    s=Store('sqlite:///:memory:');s.initialize()
    r=Runtime(s,tmp_path,packet_capacity=1)
    p=Packet(1,'192.0.2.1','198.51.100.2',1,2,6,40)
    r.enqueue(p);r.enqueue(p)
    assert r.packet_queue.qsize()==1 and r.counters['packet_drops']==1


def test_fixture_inference_unavailable_never_becomes_benign(tmp_path):
    app=app_for(tmp_path)
    from backend.flows import Flow,Packet
    with TestClient(app) as c:
        f=Flow([Packet(1,'192.0.2.1','198.51.100.2',1,2,6,40)])
        app.state.runtime.flow_queue.put((f,'synthetic_fixture',time.perf_counter()))
        for _ in range(100):
            rows=c.get('/api/flows').json()
            if rows:break
            time.sleep(.02)
        assert rows[0]['prediction'] is None
        assert rows[0]['provenance']=='synthetic_fixture'
        assert c.get('/api/incidents').json()==[]


def test_shutdown_drains_explanations_after_inference(tmp_path):
    from backend.runtime import Runtime
    from backend.store import Store
    from backend.flows import Flow,Packet
    import threading
    s=Store('sqlite:///'+str(tmp_path/'drain.db'));s.initialize()
    r=Runtime(s,tmp_path)
    entered=threading.Event()
    class SlowDetector:
        ready=True;metadata={'version':'test'}
        def predict(self,values):
            entered.set();time.sleep(.3)
            return {'label':'DDoS','malicious_probability':1.,'confidence':1.,'model_version':'test'}
        def explain(self,values):return {'method':'test-double','elapsed_ms':1}
    r.detector=SlowDetector();r.start()
    f=Flow([Packet(1,'8.8.4.4','198.51.100.2',1,2,6,40)]*200)
    r.flow_queue.put((f,'synthetic_fixture',time.perf_counter()));assert entered.wait(3)
    r.shutdown()
    assert r.xai_queue.empty()
    assert s.incident(f.id)['explanation']['status']=='ready'
    assert s.actions()[0]['status']=='simulated'
    assert s.actions()[0]['incident_id']==f.id

def test_capture_start_audit_failure_stops_sniffer(tmp_path,monkeypatch):
    import scapy.all
    from backend.runtime import Runtime
    from backend.store import Store
    stopped=[]
    class Sniffer:
        def __init__(self,**kwargs):self.kwargs=kwargs;self.running=False
        def start(self):self.running=True;self.kwargs['started_callback']()
        def stop(self):self.running=False;stopped.append(True)
    s=Store('sqlite:///:memory:');s.initialize();r=Runtime(s,tmp_path)
    monkeypatch.setattr(scapy.all,'get_if_list',lambda:['fixture'])
    monkeypatch.setattr(scapy.all,'AsyncSniffer',Sniffer)
    monkeypatch.setattr(s,'event',lambda *a:(_ for _ in ()).throw(RuntimeError('DB unavailable')))
    import pytest
    with pytest.raises(ValueError,match='DB unavailable'):r.start_capture('fixture')
    assert stopped and r.sniffer is None and r.capture['status']=='error'
