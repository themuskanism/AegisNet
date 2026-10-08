"""Exercises the shipped held-out metadata through the live worker feature contract."""
import json
from pathlib import Path
import numpy as np
from backend.flows import Flow,Packet,features,FEATURE_NAMES,SCHEMA_VERSION
from backend.model import Detector

def test_held_out_replay_has_exact_feature_and_reloaded_prediction_parity():
    folder=Path('artifacts');detector=Detector(folder)
    assert detector.ready,detector.error
    assert detector.metadata['schema']==SCHEMA_VERSION
    for record in json.loads((folder/'demo.json').read_text())['records']:
        assert record['split']==2
        live=features(Flow([Packet(**p) for p in record['packets']]))
        assert live==record['features']
        row=np.array([[live[name] for name in FEATURE_NAMES]])
        probability=detector.pipeline.predict_proba(row)[0]
        prediction=detector.predict(live)
        assert prediction['label']==detector.pipeline.classes_[probability.argmax()]
        # Parallel forest reduction can differ by a few machine-epsilon ULPs.
        assert abs(prediction['confidence']-float(probability.max()))<1e-12

def test_shipped_split_has_no_uid_or_duplicate_feature_overlap():
    from research.dataset import split_groups
    data=np.load('artifacts/dataset.npz');x=data['x'];g=data['groups'];split=data['split']
    assert np.array_equal(split,split_groups(x,g))
    fingerprints=[set(np.round(row,9).tobytes() for row in x[split==s]) for s in range(3)]
    for i in range(3):
        for j in range(i+1,3):
            assert set(g[split==i]).isdisjoint(set(g[split==j]))
            assert fingerprints[i].isdisjoint(fingerprints[j])
