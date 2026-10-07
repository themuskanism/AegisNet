"""Bounded capture, flow, inference and explanation workers with observable failures."""
from collections import deque
from dataclasses import asdict
import json
from pathlib import Path
from queue import Queue, Empty, Full
import threading
import time
import uuid
from backend.flows import FlowBuilder,Flow,Packet,features
from backend.model import Detector
from backend.packet_capture import packet_metadata
from backend.risk import score_risk


class Runtime:
    def __init__(self,store,artifacts,packet_capacity=2048):
        self.store=store;self.artifacts=Path(artifacts);self.detector=Detector(artifacts)
        self.packet_queue=Queue(packet_capacity);self.flow_queue=Queue(128);self.xai_queue=Queue(16)
        self.builder=FlowBuilder();self.stop_event=threading.Event();self.threads=[];self.sniffer=None
        self.capture={'status':'stopped','error':None,'interface':None};self.started=time.time()
        self.counters={'packets':0,'unsupported_packets':0,'packet_drops':0,'flow_drops':0,'flows_processed':0,'inference_errors':0,'database_errors':0,'xai_errors':0}
        self.errors={};self.last_packet=None;self.rates=deque(maxlen=120);self.latencies=deque(maxlen=1000)
        self.lock=threading.RLock();self.xai_pending=set();self.replaying=False

    def start(self):
        for fn in [self._flow_loop,self._inference_loop,self._xai_loop]:
            t=threading.Thread(target=fn,daemon=True);t.start();self.threads.append(t)

    def shutdown(self):
        self.stop_capture();self.stop_event.set()
        for t in self.threads:t.join(timeout=10)

    def enqueue(self,p):
        self.counters['packets']+=1;self.last_packet=time.time()
        try:self.packet_queue.put_nowait(p)
        except Full:self.counters['packet_drops']+=1

    def _raw(self,raw):
        p=packet_metadata(raw)
        if p:self.enqueue(p)
        else:self.counters['unsupported_packets']+=1

    def start_capture(self,interface):
        from scapy.all import AsyncSniffer,get_if_list
        with self.lock:
            if self.capture['status'] in ['running','starting']:raise ValueError('capture already running')
            if self.replaying:raise ValueError('replay is running')
            if interface not in get_if_list():raise ValueError('unknown capture interface')
            self.capture={'status':'starting','error':None,'interface':interface}
            ready=threading.Event()
            try:
                self.sniffer=AsyncSniffer(iface=interface,prn=self._raw,store=False,started_callback=ready.set)
                self.sniffer.start()
                if not ready.wait(3):
                    raise RuntimeError(str(getattr(self.sniffer,'exception',None) or 'capture did not start; check Npcap/permissions'))
                self.capture['status']='running'
                self.store.event('capture.started',{'interface':interface})
            except Exception as exc:
                self.capture.update(status='error',error=str(exc));raise ValueError(str(exc)) from exc
        return self.capture.copy()

    def stop_capture(self):
        with self.lock:
            if self.sniffer and self.sniffer.running:
                try:self.sniffer.stop()
                except Exception as exc:self.capture.update(status='error',error=str(exc))
            self.sniffer=None
            if self.capture['status']!='error':self.capture['status']='stopped'
        return self.capture.copy()

    def _submit(self,f,provenance):
        try:self.flow_queue.put_nowait((f,provenance))
        except Full:self.counters['flow_drops']+=1

    def _flow_loop(self):
        last_rate=time.monotonic();previous=0
        while not self.stop_event.is_set() or not self.packet_queue.empty():
            try:
                p=self.packet_queue.get(timeout=.2)
                try:
                    for f in self.builder.add(p):self._submit(f,'live')
                finally:self.packet_queue.task_done()
            except Empty:
                for f in self.builder.flush(time.time()):self._submit(f,'live')
            except Exception as exc:self.errors['flow']=str(exc)
            if time.monotonic()-last_rate>=1:
                n=self.counters['packets'];elapsed=time.monotonic()-last_rate
                self.rates.append({'time':time.time(),'packets_per_second':(n-previous)/elapsed});previous=n;last_rate=time.monotonic()
        for f in self.builder.flush(time.time(),force=True):self._submit(f,'live')

    def _inference_loop(self):
        while not self.stop_event.is_set() or not self.flow_queue.empty() or self.threads[0].is_alive():
            try:f,provenance=self.flow_queue.get(timeout=.2)
            except Empty:continue
            try:
                start=time.perf_counter();values=features(f);prediction=None;risk=None
                if self.detector.ready:
                    try:
                        prediction=self.detector.predict(values)
                        recurrence=self.store.recent_count(f.first.src,provenance)
                        risk=score_risk(prediction['label'],prediction['malicious_probability'],recurrence,values)
                    except Exception as exc:
                        self.counters['inference_errors']+=1;self.errors['inference']=str(exc);prediction=None
                self.store.save_observation(f.summary(),values,prediction,risk,provenance)
                self.counters['flows_processed']+=1;self.latencies.append((time.perf_counter()-start)*1000)
                if risk and risk['level'] in ('HIGH','CRITICAL'):
                    self.request_explanation(f.id)
                self.errors.pop('database',None)
            except Exception as exc:
                self.counters['database_errors']+=1;self.errors['database']=str(exc)
            finally:self.flow_queue.task_done()

    def request_explanation(self,id):
        incident=self.store.incident(id)
        if incident['explanation'].get('status')=='ready':return {'status':'ready','cached':True}
        if not self.detector.ready:raise ValueError('model unavailable')
        if incident['prediction']['model_version']!=self.detector.metadata['version']:raise ValueError('incident model version differs from loaded model')
        with self.lock:
            if id in self.xai_pending:return {'status':'pending'}
            try:self.xai_queue.put_nowait(id)
            except Full:raise ValueError('explanation queue full; retry later')
            self.xai_pending.add(id);self.store.explanation(id,{'status':'pending'})
        return {'status':'pending'}

    def _xai_loop(self):
        while not self.stop_event.is_set() or not self.xai_queue.empty():
            try:id=self.xai_queue.get(timeout=.2)
            except Empty:continue
            try:
                incident=self.store.incident(id);result=self.detector.explain(incident['features'])
                self.store.explanation(id,{'status':'ready',**result})
            except Exception as exc:
                self.counters['xai_errors']+=1;self.errors['xai']=str(exc)
                try:self.store.explanation(id,{'status':'error','error':str(exc)})
                except Exception:pass
            finally:
                with self.lock:self.xai_pending.discard(id)
                self.xai_queue.task_done()

    def replay(self):
        path=self.artifacts/'demo.json'
        if not path.exists():raise ValueError('benchmark replay artifact unavailable; run training first')
        with self.lock:
            if self.capture['status'] in ('running','starting') or self.replaying:raise ValueError('stop capture or wait for current replay')
            records=json.loads(path.read_text())['records']
            if len(records)>100:raise ValueError('replay exceeds safe fixture limit')
            self.replaying=True
        def run():
            try:
                for r in records:
                    f=Flow([Packet(**p) for p in r['packets']],id=uuid.uuid4().hex,reason='benchmark-replay')
                    self._submit(f,'benchmark_replay');time.sleep(.15)
            finally:self.replaying=False
        threading.Thread(target=run,daemon=True).start()
        return {'status':'started','records':len(records),'provenance':'benchmark_replay','network_packets_sent':0}

    def health(self):
        if self.sniffer and getattr(self.sniffer,'exception',None):self.capture.update(status='error',error=str(self.sniffer.exception))
        try:db=self.store.health()
        except Exception as exc:db={'status':'error','error':str(exc),'engine':self.store.kind}
        return {'backend':{'status':'ready','uptime_seconds':time.time()-self.started},'capture':{**self.capture,'last_packet_at':self.last_packet},'model':{'status':'ready' if self.detector.ready else 'unavailable','error':self.detector.error,'version':self.detector.metadata.get('version')},'database':db,'flow':{'status':'error' if 'flow' in self.errors else 'ready','active':len(self.builder.flows),'out_of_order':self.builder.out_of_order,'evicted':self.builder.evicted},'inference':{'status':'error' if 'inference' in self.errors else 'ready' if self.detector.ready else 'unavailable'},'xai':{'status':'error' if 'xai' in self.errors else 'working' if self.xai_pending else 'ready','pending':len(self.xai_pending)},'response':{'status':'simulation_default'},'queues':{'packets':self.packet_queue.qsize(),'flows':self.flow_queue.qsize(),'xai':self.xai_queue.qsize()},'counters':self.counters.copy(),'errors':self.errors.copy(),'replaying':self.replaying}
