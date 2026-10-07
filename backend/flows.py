"""One deterministic flow/feature implementation for offline training and live inference."""
from collections import OrderedDict
from dataclasses import dataclass, field
import math
import statistics
import uuid

SCHEMA_VERSION = 'ip-flow-v2'
FLOW_POLICY = {'idle_timeout':30.0,'active_timeout':120.0,'max_packets':256,
               'direction':'first-observed','bytes':'IP-layer','sequence_length':32}
FEATURE_NAMES = ['duration_s','protocol','fwd_packets','bwd_packets','fwd_bytes','bwd_bytes',
                 'length_min','length_max','length_mean','length_std','iat_mean_s','iat_std_s',
                 'syn_count','ack_count','rst_count','fin_count','psh_count','packets_per_s',
                 'bytes_per_s','direction_ratio']


@dataclass(frozen=True)
class Packet:
    timestamp: float
    src: str
    dst: str
    sport: int
    dport: int
    protocol: int
    ip_bytes: int
    flags: int = 0
    ip_version: int = 4

    @property
    def key(self):
        return (self.ip_version,self.protocol,tuple(sorted(((self.src,self.sport),(self.dst,self.dport)))))


@dataclass
class Flow:
    packets: list[Packet]
    id: str = field(default_factory=lambda:uuid.uuid4().hex)
    reason: str = 'open'

    @property
    def first(self): return self.packets[0]
    @property
    def start(self): return min(p.timestamp for p in self.packets)
    @property
    def end(self): return max(p.timestamp for p in self.packets)

    def forward(self,p):
        return (p.src,p.sport)==(self.first.src,self.first.sport)

    def summary(self):
        p=self.first
        return {'id':self.id,'start':self.start,'end':self.end,'source':p.src,'destination':p.dst,
                'source_port':p.sport,'destination_port':p.dport,'protocol':'TCP' if p.protocol==6 else 'UDP',
                'ip_version':p.ip_version,'packets':len(self.packets),'bytes':sum(p.ip_bytes for p in self.packets),
                'closure':self.reason}


class FlowBuilder:
    def __init__(self,idle_timeout=30.,active_timeout=120.,max_flows=10000,max_packets=256):
        if min(idle_timeout,active_timeout,max_flows,max_packets)<=0: raise ValueError('limits must be positive')
        self.idle_timeout=idle_timeout; self.active_timeout=active_timeout
        self.max_flows=max_flows; self.max_packets=max_packets
        self.flows=OrderedDict(); self.out_of_order=0; self.evicted=0; self.watermark=0.
        self.next_sweep=0.

    def _close(self,key,reason):
        f=self.flows.pop(key); f.reason=reason; return f

    def add(self,p):
        if not isinstance(p,Packet) or not math.isfinite(p.timestamp): raise ValueError('invalid packet')
        if p.timestamp<self.watermark: self.out_of_order+=1
        self.watermark=max(self.watermark,p.timestamp)
        done=[]
        if self.watermark>=self.next_sweep:
            done.extend(self.flush(self.watermark));self.next_sweep=self.watermark+1
        key=p.key; f=self.flows.get(key)
        if f and (p.timestamp-f.end>=self.idle_timeout or p.timestamp-f.start>=self.active_timeout):
            done.append(self._close(key,'timeout'));f=None
        if f and p.flags&2 and not p.flags&16 and any(q.flags&16 for q in f.packets):
            done.append(self._close(key,'new-syn'));f=None
        if f is None:
            if len(self.flows)>=self.max_flows:
                done.append(self._close(next(iter(self.flows)),'capacity'));self.evicted+=1
            f=Flow([]);self.flows[key]=f
        f.packets.append(p)
        fins={f.forward(q) for q in f.packets if q.flags&1}
        if p.flags&4 or len(fins)==2 or len(f.packets)>=self.max_packets:
            done.append(self._close(key,'rst' if p.flags&4 else 'fin' if len(fins)==2 else 'packet-limit'))
        return done

    def flush(self,now,force=False):
        done=[]
        for k,f in list(self.flows.items()):
            if force or now-f.end>=self.idle_timeout or now-f.start>=self.active_timeout:
                done.append(self._close(k,'shutdown' if force else 'timeout'))
        return done


def features(f):
    ps=sorted(f.packets,key=lambda p:p.timestamp)
    if not ps: raise ValueError('empty flow')
    fw=[p for p in ps if f.forward(p)];bw=[p for p in ps if not f.forward(p)]
    lengths=[p.ip_bytes for p in ps]; iats=[b.timestamp-a.timestamp for a,b in zip(ps,ps[1:])]
    duration=ps[-1].timestamp-ps[0].timestamp
    values=[duration,ps[0].protocol,len(fw),len(bw),sum(p.ip_bytes for p in fw),sum(p.ip_bytes for p in bw),
            min(lengths),max(lengths),statistics.fmean(lengths),statistics.pstdev(lengths),
            statistics.fmean(iats) if iats else 0.,statistics.pstdev(iats) if iats else 0.]
    values += [sum(bool(p.flags&flag) for p in ps) for flag in [2,16,4,1,8]]
    values += [len(ps)/duration if duration else 0.,sum(lengths)/duration if duration else 0.,len(bw)/len(ps)]
    return dict(zip(FEATURE_NAMES,map(float,values)))


def sequence(f,length=32):
    """Chronological packet sequence; fixed log transforms, zero padding, explicit length."""
    import numpy as np
    ps=sorted(f.packets,key=lambda p:p.timestamp)[:length]
    x=np.zeros((length,8),dtype=np.float32)
    for i,p in enumerate(ps):
        dt=p.timestamp-ps[i-1].timestamp if i else 0
        x[i]=[1 if f.forward(p) else -1,math.log1p(p.ip_bytes),math.log1p(dt),
              *[float(bool(p.flags&flag)) for flag in [2,16,4,1,8]]]
    return x,len(ps)


def pcap_flows(path):
    from scapy.all import PcapReader
    from backend.packet_capture import packet_metadata
    builder=FlowBuilder()
    with PcapReader(str(path)) as reader:
        for raw in reader:
            p=packet_metadata(raw)
            if p:
                yield from builder.add(p)
    yield from builder.flush(builder.watermark,force=True)
