import importlib.util
import numpy as np
import pytest


def test_missing_model_is_explicit(tmp_path):
    assert importlib.util.find_spec('backend.model'), 'model runtime is required'
    from backend.model import Detector
    d=Detector(tmp_path)
    assert not d.ready
    with pytest.raises(RuntimeError,match='unavailable'): d.predict({})


def test_schema_requires_exact_names_and_finite_values():
    assert importlib.util.find_spec('backend.model'), 'model runtime is required'
    from backend.model import vector
    from backend.flows import FEATURE_NAMES
    values={n:1.0 for n in FEATURE_NAMES}
    assert vector(values).shape==(1,len(FEATURE_NAMES))
    values['surprise']=1
    with pytest.raises(ValueError): vector(values)
    values.pop('surprise'); values[FEATURE_NAMES[0]]=float('nan')
    with pytest.raises(ValueError): vector(values)


def test_real_artifact_prediction_and_shap(tmp_path):
    assert importlib.util.find_spec('backend.model'), 'model runtime is required'
    import joblib, json
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from backend.flows import FEATURE_NAMES, SCHEMA_VERSION, FLOW_POLICY
    from backend.model import Detector
    rng=np.random.default_rng(12)
    x=rng.normal(size=(60,len(FEATURE_NAMES)))
    y=np.where(x[:,0]>0,'DDoS','Benign')
    p=make_pipeline(StandardScaler(),RandomForestClassifier(n_estimators=12,random_state=12)).fit(x,y)
    joblib.dump({'pipeline':p,'background':x[:8]},tmp_path/'model.joblib')
    (tmp_path/'metadata.json').write_text(json.dumps({'version':'fixture','schema':SCHEMA_VERSION,'features':FEATURE_NAMES,'flow_policy':FLOW_POLICY,'classes':list(p.classes_)}))
    d=Detector(tmp_path)
    values=dict(zip(FEATURE_NAMES,x[0]))
    pred=d.predict(values)
    assert pred['label'] in y
    exp=d.explain(values)
    assert exp['method']=='SHAP permutation'
    assert exp['elapsed_ms']>0
    assert abs(exp['base_value']+sum(c['contribution'] for c in exp['contributions'])-exp['output_value'])<1e-5
    assert exp['label']==pred['label']
