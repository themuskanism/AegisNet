"""Policy v1: transparent ordinal triage score, not a probability of compromise."""
import math

SEVERITY={'Benign':0.,'DDoS':1.,'C&C':.8,'PartOfAHorizontalPortScan':.5}


def score_risk(label,malicious_probability,recurrence,features):
    if not math.isfinite(malicious_probability) or not 0<=malicious_probability<=1: raise ValueError('invalid probability')
    if label=='Benign': return {'score':0,'level':'LOW','policy':'risk-v1','factors':{},'advisory':'No malicious class predicted; this is not proof of safety.'}
    confidence=malicious_probability;severity=SEVERITY.get(label,.5)
    frequency=min(max(recurrence,0)/10,1.)
    packets=features.get('fwd_packets',0)+features.get('bwd_packets',0)
    rate=packets/max(features.get('duration_s',0),1.)
    evidence=.5*min(rate/100,1.)+.5*(1 if packets>=3 and features.get('bwd_packets',0)==0 else 0)
    score=round(100*(.35*confidence+.30*severity+.20*frequency+.15*evidence),2)
    level='CRITICAL' if score>=85 else 'HIGH' if score>=65 else 'MEDIUM' if score>=40 else 'LOW'
    return {'score':score,'level':level,'policy':'risk-v1','factors':{'malicious_probability':confidence,'severity':severity,'recurrence_5m':frequency,'flow_evidence':evidence},'weights':{'malicious_probability':.35,'severity':.30,'recurrence_5m':.20,'flow_evidence':.15},'advisory':'Validate endpoint context and explanation; seek analyst approval before any real block.'}
