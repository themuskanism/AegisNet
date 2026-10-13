"""Opt-in local integration check against a running sensor. Uses only normal loopback HTTP."""
import argparse
import json
import os
from pathlib import Path
import threading
import time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import httpx
import numpy as np
from backend.flows import Flow,Packet,features
from backend.model import Detector


def verify(url,token,out,live):
    client=httpx.Client(base_url=url,headers={'Authorization':'Bearer '+token},timeout=30)
    def get(path):
        r=client.get('/api'+path);r.raise_for_status();return r.json()
    def post(path,body=None):
        r=client.post('/api'+path,json=body or {});r.raise_for_status();return r.json()
    initial=get('/health');assert initial['model']['status']=='ready'
    assert initial['database']['engine']=='postgresql'
    before=get('/overview')['totals']['flows'];post('/demo/replay')
    deadline=time.monotonic()+120
    while time.monotonic()<deadline:
        state=get('/health')
        if not state['replaying'] and state['queues']['flows']==0 and get('/overview')['totals']['flows']>=before+12:break
        time.sleep(.5)
    else:raise AssertionError('replay did not finish')
    incidents=get('/incidents');assert incidents
    target=next(i for i in incidents if i['provenance']=='benchmark_replay')
    post('/incidents/'+target['id']+'/explain')
    while time.monotonic()<deadline:
        detail=get('/incidents/'+target['id']);exp=detail['explanation']
        if exp['status']=='ready':break
        if exp['status']=='error':raise AssertionError(exp)
        time.sleep(.5)
    else:raise AssertionError('XAI timed out')
    reconstruction=abs(exp['base_value']+sum(c['contribution'] for c in exp['contributions'])-exp['output_value'])
    assert reconstruction<1e-6
    ack=post('/actions',{'action':'acknowledge','ip':target['flow']['source'],'reason':'Operational verification: analyst reviewed benchmark evidence','incident_id':target['id']})
    assert ack['status']=='applied'
    sim=post('/actions',{'action':'block','ip':'8.8.4.4','reason':'Verification target only; no traffic generated and no firewall change','mode':'MANUAL'})
    assert sim['status']=='pending'
    decision=post('/actions/'+sim['id']+'/decision',{'approve':True});assert decision['status']=='simulated'
    assert post('/actions/'+sim['id']+'/decision',{'approve':True})['status']=='simulated'
    assert get('/response')['blocked']==[]
    detector=Detector('artifacts');parity=[]
    for r in json.loads(Path('artifacts/demo.json').read_text())['records']:
        f=Flow([Packet(**p) for p in r['packets']]);values=features(f)
        # The replay and live workers consume precisely this same Packet -> Flow -> features path.
        expected=r.get('features')
        if expected is not None:assert values==expected
        parity.append(detector.predict(values)['label'])
    live_result={'status':'not_requested'}
    if live:
        interfaces=get('/interfaces');interface=next(i['id'] for i in interfaces if 'loopback' in (i['name']+' '+i['id']).lower())
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200);self.end_headers();self.wfile.write(b'Agisnest safe local verification')
            def log_message(self,*args):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        prior=get('/overview')['totals']['flows'];prior_ids={r['flow']['id'] for r in get('/flows')}
        post('/capture/start',{'interface':interface});start=time.perf_counter()
        try:
            with httpx.Client(trust_env=False) as local:
                for _ in range(10):local.get(f'http://127.0.0.1:{server.server_port}/');time.sleep(.1)
            time.sleep(1)
        finally:post('/capture/stop');server.shutdown();server.server_close()
        end=time.monotonic()+30
        while time.monotonic()<end:
            if get('/overview')['totals']['flows']>prior and get('/health')['queues']['flows']==0:break
            time.sleep(.2)
        overview=get('/overview');flows=[r for r in get('/flows') if r['provenance']=='live' and r['flow']['id'] not in prior_ids];assert flows and all(r['prediction'] for r in flows)
        live_result={'status':'verified','interface':interface,'safe_http_requests':10,'elapsed_seconds':time.perf_counter()-start,'persisted_live_flows':len(flows),'capture_state_after':get('/health')['capture']['status'],'counters':get('/health')['counters']}
    overview=get('/overview')
    def distribution(v):return {'samples':len(v),'p50':float(np.percentile(v,50)) if v else None,'p95':float(np.percentile(v,95)) if v else None}
    result={'verified_at':time.time(),'database':initial['database'],'model_version':initial['model']['version'],'replay_flows':12,'incident_id':target['id'],'explanation_method':exp['method'],'explanation_ms':exp['elapsed_ms'],'shap_reconstruction_absolute_error':reconstruction,'manual_approval_status':decision['status'],'repeat_approval_idempotent':True,'actual_firewall_blocks':0,'replay_predictions':parity,'live':live_result,'service_latency_ms':distribution(overview['service_latency_ms']),'queue_latency_ms':distribution(overview['queue_latency_ms']),'flow_completion_wait_seconds':distribution(overview['live_completion_wait_seconds']),'limitations':['Loopback functional verification; not production-link throughput or packet-loss capacity testing.','Service latency combines feature extraction, inference and DB write; flow completion and queue waits reported separately.','Shared process traffic from API requests can also be captured on loopback.','Timing distributions and counters cover the current sensor process; they can include earlier replay activity in that process.']}
    Path(out).write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2));client.close()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--url',default='http://127.0.0.1:8000');p.add_argument('--out',default='artifacts/operational_evaluation.json');p.add_argument('--live-loopback',action='store_true');args=p.parse_args()
    verify(args.url,os.environ['AEGIS_API_TOKEN'],args.out,args.live_loopback)
