"""Extract benchmark features using the exact live flow code and align original labels."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import numpy as np
from sklearn.model_selection import GroupShuffleSplit
from backend.flows import Packet, features, sequence, pcap_flows, FEATURE_NAMES, FLOW_POLICY


def read_labels(path):
    index=defaultdict(list)
    with open(path,encoding='utf-8') as file:
        for line in file:
            if line.startswith('#fields'): fields=line.rstrip().split('\t')[1:]
            if line.startswith('#'): continue
            row=dict(zip(fields,line.rstrip().split('\t')))
            if row['proto'] not in ('tcp','udp'): continue
            p=Packet(float(row['ts']),row['id.orig_h'],row['id.resp_h'],int(row['id.orig_p']),int(row['id.resp_p']),6 if row['proto']=='tcp' else 17,0,ip_version=6 if ':' in row['id.orig_h'] else 4)
            duration=0 if row['duration']=='-' else float(row['duration'])
            label='Benign' if row['label']=='Benign' else row['det_label']
            if label in ('-','Unknown','unknown'): continue
            index[p.key].append({'start':p.timestamp,'end':p.timestamp+duration,'uid':row['uid'],'label':label})
    return index


def match_label(flow,index):
    matches=[r for r in index.get(flow.first.key,[]) if r['start']-.001<=flow.start and flow.end<=r['end']+.001]
    if len(matches)!=1: return None
    return matches[0]['label'],matches[0]['uid']


def split_groups(x,groups):
    parent=list(range(len(x)))
    def root(i):
        while parent[i]!=i: parent[i]=parent[parent[i]];i=parent[i]
        return i
    def join(a,b): parent[root(a)]=root(b)
    seen_g={};seen_x={}
    for i,(row,g) in enumerate(zip(x,groups)):
        fingerprint=np.round(row,9).tobytes()
        if g in seen_g: join(i,seen_g[g])
        if fingerprint in seen_x: join(i,seen_x[fingerprint])
        seen_g[g]=i;seen_x[fingerprint]=i
    united=np.array([root(i) for i in range(len(x))])
    train,remaining=next(GroupShuffleSplit(n_splits=1,test_size=.4,random_state=42).split(x,groups=united))
    va,te=next(GroupShuffleSplit(n_splits=1,test_size=.5,random_state=43).split(x[remaining],groups=united[remaining]))
    split=np.zeros(len(x),dtype=int);split[remaining[va]]=1;split[remaining[te]]=2
    return split


def extract(pcap,labels,out):
    out=Path(out);out.mkdir(parents=True,exist_ok=True)
    source_hashes={str(Path(p).name):hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in [pcap,labels]}
    index=read_labels(labels); xs=[];ys=[];gs=[];seqs=[];lengths=[];records=[];excluded=0
    from dataclasses import asdict
    for i,f in enumerate(pcap_flows(pcap)):
        matched=match_label(f,index)
        if matched is None: excluded+=1;continue
        y,g=matched;x=features(f);sq,n=sequence(f)
        xs.append(list(x.values()));ys.append(y);gs.append(g);seqs.append(sq);lengths.append(n)
        records.append({'flow':f.summary(),'features':x,'label':y,'group':g,'packets':[asdict(p) for p in f.packets]})
        if i%5000==0: print(f'processed flows {i}, matched {len(xs)}',flush=True)
    x=np.array(xs);y=np.array(ys);groups=np.array(gs);split=split_groups(x,groups)
    support={name:dict(Counter(y[split==k])) for k,name in enumerate(['train','validation','test'])}
    classes=set(y)
    if any(set(s)!=classes for s in support.values()): raise ValueError(f'class coverage missing: {support}')
    np.savez_compressed(out/'dataset.npz',x=x,y=y,groups=groups,split=split,sequences=np.array(seqs),lengths=np.array(lengths))
    with (out/'records.jsonl').open('w') as f:
        for row,s in zip(records,split): f.write(json.dumps({**row,'split':int(s)})+'\n')
    final_hashes={str(Path(p).name):hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in [pcap,labels]}
    if source_hashes!=final_hashes: raise RuntimeError('dataset changed during extraction')
    manifest={'dataset':'IoT-23 / CTU-IoT-Malware-Capture-34-1','matched_flows':len(x),'excluded_unmatched_or_ambiguous':excluded,'support':support,'features':FEATURE_NAMES,'flow_policy':FLOW_POLICY,'split':'UID + duplicate-feature union groups; seeded 60/20/20; within one scenario','sources':source_hashes}
    (out/'dataset_manifest.json').write_text(json.dumps(manifest,indent=2));print(json.dumps(manifest,indent=2),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--pcap',default='data/benchmark/scenario34.pcap');p.add_argument('--labels',default='data/benchmark/conn.log.labeled');p.add_argument('--out',default='artifacts');a=p.parse_args();extract(a.pcap,a.labels,a.out)
