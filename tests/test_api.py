import importlib.util
import json
import time
import pytest
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
        app.state.runtime.flow_queue.put((f,'synthetic_fixture'))
        for _ in range(100):
            rows=c.get('/api/flows').json()
            if rows:break
            time.sleep(.02)
        assert rows[0]['prediction'] is None
        assert rows[0]['provenance']=='synthetic_fixture'
        assert c.get('/api/incidents').json()==[]
