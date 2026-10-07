"""Load trusted local model artifacts; never accept serialized models through HTTP."""
import hashlib
import json
from pathlib import Path
from time import perf_counter
import joblib
import numpy as np
from backend.flows import FEATURE_NAMES,SCHEMA_VERSION,FLOW_POLICY


def vector(values):
    if set(values)!=set(FEATURE_NAMES): raise ValueError('feature schema mismatch')
    x=np.array([[values[n] for n in FEATURE_NAMES]],dtype=float)
    if not np.isfinite(x).all(): raise ValueError('nonfinite features')
    return x


class Detector:
    def __init__(self,path):
        self.ready=False;self.error=None;self.metadata={};self.explainer=None
        try:
            path=Path(path);meta=json.loads((path/'metadata.json').read_text())
            if meta['schema']!=SCHEMA_VERSION or meta['features']!=FEATURE_NAMES or meta['flow_policy']!=FLOW_POLICY: raise ValueError('artifact schema or flow policy mismatch')
            digest=hashlib.sha256((path/'model.joblib').read_bytes()).hexdigest()
            if meta.get('sha256',digest)!=digest: raise ValueError('artifact checksum mismatch')
            artifact=joblib.load(path/'model.joblib')
            self.pipeline=artifact['pipeline'];self.background=artifact['background']
            if list(self.pipeline.classes_)!=meta['classes']: raise ValueError('artifact class mismatch')
            self.metadata=meta;self.ready=True
        except Exception as exc: self.error=f'{type(exc).__name__}: {exc}'

    def predict(self,values):
        if not self.ready: raise RuntimeError('model unavailable: '+str(self.error))
        start=perf_counter();probs=self.pipeline.predict_proba(vector(values))[0];idx=int(probs.argmax())
        classes=list(self.pipeline.classes_)
        return {'label':str(classes[idx]),'confidence':float(probs[idx]),'malicious_probability':float(1-probs[classes.index('Benign')]) if 'Benign' in classes else 1.,'probabilities':dict(zip(classes,map(float,probs))),'model_version':self.metadata['version'],'elapsed_ms':(perf_counter()-start)*1000}

    def explain(self,values):
        if not self.ready: raise RuntimeError('model unavailable')
        import shap
        start=perf_counter();x=vector(values)
        if self.explainer is None:
            self.explainer=shap.Explainer(self.pipeline.predict_proba,self.background,algorithm='permutation',feature_names=FEATURE_NAMES,seed=42)
        result=self.explainer(x,max_evals=2*(2*len(FEATURE_NAMES)+1),silent=True)
        p=self.pipeline.predict_proba(x)[0];idx=int(p.argmax())
        contributions=[{'feature':n,'value':float(x[0,i]),'contribution':float(result.values[0,i,idx])} for i,n in enumerate(FEATURE_NAMES)]
        return {'method':'SHAP permutation','output_space':'calibrated class probability','label':str(self.pipeline.classes_[idx]),'model_version':self.metadata['version'],'base_value':float(result.base_values[0,idx]),'output_value':float(p[idx]),'contributions':sorted(contributions,key=lambda c:abs(c['contribution']),reverse=True),'background_size':len(self.background),'elapsed_ms':(perf_counter()-start)*1000,'caution':'Associations within this model and background, not causal proof of an attack.'}
