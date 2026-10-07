"""Held-out, observational policy comparison. No actions or network traffic are emitted."""
import json
from collections import defaultdict, deque
from pathlib import Path
import numpy as np
from backend.model import Detector
from backend.risk import score_risk


def evaluate(out=Path('artifacts')):
    out=Path(out); detector=Detector(out)
    records=[json.loads(line) for line in (out/'records.jsonl').open()]
    records=sorted((r for r in records if r['split']==2),key=lambda r:r['flow']['start'])
    history=defaultdict(deque); truth=[]; confidence=[]; risk=[]; scores=[]
    for r in records:
        now=r['flow']['start']; q=history[r['flow']['source']]
        while q and q[0]<now-300:q.popleft()
        pred=detector.predict(r['features'])
        policy=score_risk(pred['label'],pred['malicious_probability'],len(q),r['features'])
        truth.append(r['label']!='Benign')
        confidence.append(pred['label']!='Benign' and pred['confidence']>=.9)
        risk.append(policy['score']>=65)
        scores.append(policy['score'])
        if pred['label']!='Benign':q.append(now)
    truth=np.array(truth)
    def stats(decisions):
        d=np.array(decisions);tp=int((d&truth).sum());fp=int((d&~truth).sum())
        return {'recommendations':int(d.sum()),'true_malicious_recommended':tp,'benign_recommended':fp,'malicious_not_recommended':int((~d&truth).sum()),'precision':tp/(tp+fp) if tp+fp else None,'malicious_coverage':float(d[truth].mean()),'benign_recommendation_rate':float(d[~truth].mean())}
    result={'scope':'held-out flows of one IoT-23 scenario; recommendations only, no firewall changes', 'rows':len(records),'model_version':detector.metadata['version'],'confidence_policy':'predicted malicious AND selected-class confidence >= 0.90','risk_policy':'documented risk >= 65 (HIGH/CRITICAL)','recurrence':'previous predicted malicious test flows from same source in preceding 300 seconds of original capture time','confidence_only':stats(confidence),'risk_aware':stats(risk),'risk_threshold_sensitivity':{str(t):stats(np.array(scores)>=t) for t in [55,65,75,85]},'limitations':['Not causal evidence that automated blocking prevents harm.','Response address protections are applied by the service; these recommendation counts precede those safeguards.','One scenario and sparse minority classes; no claim that the risk policy dominates.','Thresholds and weights are documented expert choices, not learned operational utility.']}
    (out/'policy_evaluation.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))

if __name__=='__main__':evaluate()
