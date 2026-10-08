import json
from fastapi.testclient import TestClient
from backend.api import create_app

def test_bad_evaluation_is_explicit_unavailable(tmp_path):
    (tmp_path/'evaluation.json').write_text('{broken')
    with TestClient(create_app('sqlite:///'+str(tmp_path/'a.db'),tmp_path,'test')) as client:
        assert client.get('/api/model').json()['evaluation'] is None
        assert 'evaluation' in client.get('/api/health').json()['errors']

def test_interface_permission_error_does_not_hide_dashboard(tmp_path,monkeypatch):
    import scapy.all
    monkeypatch.setattr(scapy.all,'get_if_list',lambda:(_ for _ in ()).throw(PermissionError('capture denied')))
    with TestClient(create_app('sqlite:///'+str(tmp_path/'a.db'),tmp_path,'test')) as client:
        assert client.get('/api/interfaces').json()==[]
        assert client.get('/api/overview').status_code==200
        assert 'capture_interfaces' in client.get('/api/health').json()['errors']

def test_database_failure_is_not_an_empty_success(tmp_path,monkeypatch):
    app=create_app('sqlite:///'+str(tmp_path/'a.db'),tmp_path,'test')
    with TestClient(app) as client:
        monkeypatch.setattr(app.state.store,'observations',lambda:(_ for _ in ()).throw(RuntimeError('database offline')))
        assert client.get('/api/flows').status_code==503

def test_missing_model_keeps_historical_evaluation(tmp_path):
    (tmp_path/'evaluation.json').write_text(json.dumps({'metadata':{'model':'Historical'}}))
    with TestClient(create_app('sqlite:///'+str(tmp_path/'a.db'),tmp_path,'test')) as client:
        result=client.get('/api/model').json()
        assert result['status']=='unavailable' and result['evaluation']['metadata']['model']=='Historical'
