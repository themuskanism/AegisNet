"""Relational records with JSON evidence snapshots; PostgreSQL is the deployment backend."""
from contextlib import contextmanager
import time
import uuid
from sqlalchemy import create_engine, String, Float, JSON, ForeignKey, select, func, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase): pass


class Observation(Base):
    __tablename__='observations'
    id:Mapped[str]=mapped_column(String(40),primary_key=True)
    created:Mapped[float]=mapped_column(Float,index=True)
    source:Mapped[str]=mapped_column(String(64),index=True)
    provenance:Mapped[str]=mapped_column(String(32),index=True)
    data:Mapped[dict]=mapped_column(JSON)


class Incident(Base):
    __tablename__='incidents'
    id:Mapped[str]=mapped_column(String(40),primary_key=True)
    flow_id:Mapped[str]=mapped_column(ForeignKey('observations.id'),unique=True)
    source:Mapped[str]=mapped_column(String(64),index=True)
    created:Mapped[float]=mapped_column(Float,index=True)
    status:Mapped[str]=mapped_column(String(24),default='open')
    data:Mapped[dict]=mapped_column(JSON)


class Explanation(Base):
    __tablename__='explanations'
    id:Mapped[str]=mapped_column(ForeignKey('incidents.id'),primary_key=True)
    data:Mapped[dict]=mapped_column(JSON)


class Action(Base):
    __tablename__='actions'
    id:Mapped[str]=mapped_column(String(40),primary_key=True)
    created:Mapped[float]=mapped_column(Float,index=True)
    status:Mapped[str]=mapped_column(String(24))
    data:Mapped[dict]=mapped_column(JSON)


class Source(Base):
    __tablename__='sources'
    ip:Mapped[str]=mapped_column(String(64),primary_key=True)
    kind:Mapped[str]=mapped_column(String(24),primary_key=True)
    data:Mapped[dict]=mapped_column(JSON)


class Event(Base):
    __tablename__='events'
    id:Mapped[str]=mapped_column(String(40),primary_key=True)
    created:Mapped[float]=mapped_column(Float,index=True)
    data:Mapped[dict]=mapped_column(JSON)


class ModelRecord(Base):
    __tablename__='models'
    id:Mapped[str]=mapped_column(String(80),primary_key=True)
    data:Mapped[dict]=mapped_column(JSON)


class Store:
    def __init__(self,url):
        options={'pool_pre_ping':True}
        if url.startswith('sqlite'):
            options['connect_args']={'check_same_thread':False,'timeout':15}
            if ':memory:' in url: options['poolclass']=StaticPool
        self.engine=create_engine(url,**options)
        self.Session=sessionmaker(self.engine,expire_on_commit=False)
        self.kind=self.engine.dialect.name

    def initialize(self):
        # Lightweight tests only. Deployment uses Alembic migrations.
        if self.kind!='sqlite': raise RuntimeError('Use alembic upgrade head for PostgreSQL')
        Base.metadata.create_all(self.engine)

    @contextmanager
    def transaction(self):
        with self.Session.begin() as session: yield session

    def health(self):
        with self.Session() as s:
            s.execute(text('SELECT 1'));s.scalar(select(func.count()).select_from(Incident))
        return {'status':'ready','engine':self.kind,'local_test_mode':self.kind=='sqlite'}

    @staticmethod
    def audit(s,kind,details):
        s.add(Event(id=uuid.uuid4().hex,created=time.time(),data={'kind':kind,**details}))

    def event(self,kind,details):
        with self.transaction() as s: self.audit(s,kind,details)

    def save_observation(self,flow,values,prediction,risk,provenance):
        now=time.time(); data={'flow':flow,'features':values,'prediction':prediction,'risk':risk,'provenance':provenance,'ingested_at':now}
        with self.transaction() as s:
            s.add(Observation(id=flow['id'],created=now,source=flow['source'],provenance=provenance,data=data));s.flush()
            if prediction and prediction['label']!='Benign':
                s.add(Incident(id=flow['id'],flow_id=flow['id'],source=flow['source'],created=now,status='open',data=data))
                self.audit(s,'incident.created',{'incident_id':flow['id'],'provenance':provenance})
        return data

    def recent_count(self,source,provenance,seconds=300):
        with self.Session() as s:
            return s.scalar(select(func.count()).select_from(Incident).join(Observation,Observation.id==Incident.flow_id).where(Incident.source==source,Incident.created>=time.time()-seconds,Observation.provenance==provenance)) or 0

    def observations(self,limit=200):
        with self.Session() as s: return [r.data for r in s.scalars(select(Observation).order_by(Observation.created.desc()).limit(limit))]

    def incidents(self,limit=200):
        with self.Session() as s: return [{**r.data,'id':r.id,'status':r.status} for r in s.scalars(select(Incident).order_by(Incident.created.desc()).limit(limit))]

    def incident(self,id):
        with self.Session() as s:
            r=s.get(Incident,id)
            if not r: raise KeyError('incident not found')
            exp=s.get(Explanation,id)
            return {**r.data,'id':r.id,'status':r.status,'explanation':exp.data if exp else {'status':'not_requested'}}

    def explanation(self,id,data):
        with self.transaction() as s:
            if not s.get(Incident,id): raise KeyError('incident not found')
            s.merge(Explanation(id=id,data=data))

    def list_sources(self,kind):
        with self.Session() as s: return [{'ip':r.ip,**r.data} for r in s.scalars(select(Source).where(Source.kind==kind))]

    def actions(self,limit=200):
        with self.Session() as s: return [{'id':r.id,'created':r.created,'status':r.status,**r.data} for r in s.scalars(select(Action).order_by(Action.created.desc()).limit(limit))]

    def events(self,limit=100):
        with self.Session() as s: return [{'id':r.id,'created':r.created,**r.data} for r in s.scalars(select(Event).order_by(Event.created.desc()).limit(limit))]

    def counts(self):
        with self.Session() as s:
            return {'flows':s.scalar(select(func.count()).select_from(Observation)), 'incidents':s.scalar(select(func.count()).select_from(Incident)), 'actions':s.scalar(select(func.count()).select_from(Action))}
