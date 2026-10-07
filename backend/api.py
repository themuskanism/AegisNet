"""Typed SOC API. Run one API worker; the capture runtime is a single sensor."""
import asyncio
from collections import Counter
from contextlib import asynccontextmanager
import hmac
import json
import os
from pathlib import Path
import time
from typing import Literal
from fastapi import FastAPI,HTTPException,Depends,Header,Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse,FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel,ConfigDict,Field,IPvAnyAddress
from backend.store import Store,ModelRecord
from backend.runtime import Runtime
from backend.response import ResponseService

ROOT=Path(__file__).resolve().parents[1]


class ActionRequest(BaseModel):
    model_config=ConfigDict(extra='forbid')
    action:Literal['block','unblock','whitelist','unwhitelist','acknowledge','ignore']
    ip:IPvAnyAddress
    reason:str=Field(min_length=1,max_length=500)
    mode:Literal['SIMULATION','MANUAL','ACTIVE']='SIMULATION'
    incident_id:str|None=None


class CaptureRequest(BaseModel):
    model_config=ConfigDict(extra='forbid')
    interface:str=Field(min_length=1,max_length=250)


class Decision(BaseModel):
    model_config=ConfigDict(extra='forbid')
    approve:bool


def create_app(database_url=None,artifacts=None,token=None):
    url=database_url or os.environ.get('AEGIS_DATABASE_URL','sqlite:///'+str(ROOT/'data/aegis-local.db'))
    artifacts=Path(artifacts or ROOT/'artifacts');api_token=token if token is not None else os.environ.get('AEGIS_API_TOKEN','')
    store=Store(url);runtime=Runtime(store,artifacts)
    response=ResponseService(store,active_enabled=os.environ.get('AEGIS_ACTIVE_RESPONSE')=='true')
    @asynccontextmanager
    async def lifespan(app):
        try:
            if store.kind=='sqlite':store.initialize()
            store.health()
            if runtime.detector.ready:
                with store.transaction() as s:s.merge(ModelRecord(id=runtime.detector.metadata['version'],data=runtime.detector.metadata))
        except Exception as exc:runtime.errors['database']=str(exc)
        runtime.start()
        yield
        runtime.shutdown();store.engine.dispose()
    app=FastAPI(title='AegisNet 2.0',version='2.0.0',lifespan=lifespan)
    app.state.runtime=runtime;app.state.store=store
    app.add_middleware(CORSMiddleware,allow_origins=['http://localhost:5173','http://127.0.0.1:5173'],allow_methods=['GET','POST'],allow_headers=['Authorization','Content-Type'])
    def auth(authorization:str=Header(default='')):
        if not api_token:raise HTTPException(503,'Configure AEGIS_API_TOKEN to enable analyst actions')
        if not hmac.compare_digest(authorization,'Bearer '+api_token):raise HTTPException(401,'Analyst token required')
    def call(fn,*args,**kwargs):
        try:return fn(*args,**kwargs)
        except KeyError as exc:raise HTTPException(404,str(exc)) from exc
        except ValueError as exc:raise HTTPException(409,str(exc)) from exc
        except Exception as exc:
            runtime.errors['service']=str(exc)
            raise HTTPException(503,'Service unavailable; inspect System Health') from exc
    @app.get('/api/health')
    @app.get('/api/status')
    def health():return runtime.health()
    @app.get('/api/interfaces')
    def interfaces():
        from scapy.all import get_if_list,conf
        return [{'id':i,'name':getattr(conf.ifaces.dev_from_networkname(i),'description',i)} for i in get_if_list()]
    @app.get('/api/flows')
    def flows():return call(store.observations)
    @app.get('/api/incidents')
    def incidents():return call(store.incidents)
    @app.get('/api/incidents/{id}')
    def incident(id:str):return call(store.incident,id)
    @app.post('/api/incidents/{id}/explain',dependencies=[Depends(auth)])
    def explain(id:str):return call(runtime.request_explanation,id)
    @app.get('/api/response')
    def responses():return call(lambda:{'actions':store.actions(),'whitelist':store.list_sources('whitelist'),'blocked':store.list_sources('blocked'),'active_enabled':response.active_enabled,'default_mode':'SIMULATION'})
    @app.post('/api/actions',dependencies=[Depends(auth)])
    def action(body:ActionRequest):return call(response.request,**{**body.model_dump(),'ip':str(body.ip)})
    @app.post('/api/actions/{id}/decision',dependencies=[Depends(auth)])
    def decision(id:str,body:Decision):return call(response.decide,id,body.approve)
    @app.post('/api/capture/start',dependencies=[Depends(auth)])
    def start(body:CaptureRequest):return call(runtime.start_capture,body.interface)
    @app.post('/api/capture/stop',dependencies=[Depends(auth)])
    def stop():return call(runtime.stop_capture)
    @app.post('/api/demo/replay',dependencies=[Depends(auth)])
    def replay():return call(runtime.replay)
    @app.get('/api/events')
    def events():return call(store.events)
    @app.get('/api/model')
    def model():
        path=artifacts/'evaluation.json'
        return {'status':'ready' if runtime.detector.ready else 'unavailable','metadata':runtime.detector.metadata,'evaluation':json.loads(path.read_text()) if path.exists() else None}
    @app.get('/api/overview')
    @app.get('/api/traffic')
    def overview():
        def data():
            rows=store.observations();incs=store.incidents()
            return {'totals':store.counts(),'session':runtime.counters.copy(),'health':runtime.health(),'packet_rates':list(runtime.rates),'recent_incidents':incs[:8],'risk_distribution':dict(Counter(i['risk']['level'] for i in incs)),'attack_distribution':dict(Counter(i['prediction']['label'] for i in incs)),'sources':dict(Counter(i['flow']['source'] for i in incs).most_common(6)),'provenance':dict(Counter(r['provenance'] for r in rows)),'distribution_scope':'most recent 200 persisted records','pipeline_latency_ms':list(runtime.latencies),'updated_at':time.time()}
        return call(data)
    @app.get('/api/stream')
    async def stream(request:Request):
        async def events():
            while not await request.is_disconnected():
                state=await asyncio.to_thread(runtime.health)
                yield 'event: telemetry\ndata: '+json.dumps({'time':time.time(),'health':state})+'\n\n'
                await asyncio.sleep(2)
        return StreamingResponse(events(),media_type='text/event-stream',headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})
    dist=ROOT/'frontend/dist'
    if dist.exists():
        app.mount('/assets',StaticFiles(directory=dist/'assets'),name='assets')
        @app.get('/')
        def index():return FileResponse(dist/'index.html')
    else:
        @app.get('/')
        def index():return {'project':'AegisNet 2.0','dashboard':'Run frontend npm build or npm run dev','health':'/api/health'}
    return app


app=create_app()
