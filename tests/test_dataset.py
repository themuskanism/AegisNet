import importlib.util
from backend.flows import Flow, Packet


def test_label_matching_requires_one_unambiguous_original_connection():
    assert importlib.util.find_spec('research.dataset'), 'dataset matcher is required'
    from research.dataset import match_label
    p=Packet(10,'192.0.2.1','198.51.100.2',100,80,6,40)
    f=Flow([p,Packet(11,p.dst,p.src,80,100,6,40)])
    record={'start':9.9,'end':11.1,'uid':'A','label':'DDoS'}
    index={p.key:[record]}
    assert match_label(f,index)==('DDoS','A')
    index[p.key].append({**record,'uid':'B','label':'Benign'})
    assert match_label(f,index) is None


def test_split_preserves_connection_and_identical_feature_groups():
    assert importlib.util.find_spec('research.dataset'), 'dataset splitter is required'
    from research.dataset import split_groups
    import numpy as np
    x=np.arange(240).reshape(60,4).astype(float)
    x[2]=x[0]
    groups=np.array([str(i//2) for i in range(60)])
    split=split_groups(x,groups)
    assert len(set(split))==3
    assert split[0]==split[1]==split[2]==split[3]
    for g in set(groups): assert len(set(split[groups==g]))==1
