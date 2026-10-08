"""Synchronize measured tables from saved evidence; does not synthesize metrics."""
import json
from pathlib import Path
import re

def main():
    e=json.loads(Path('artifacts/evaluation.json').read_text());p=json.loads(Path('artifacts/policy_evaluation.json').read_text())
    text=Path('docs/RESEARCH.md').read_text(encoding='utf-8-sig')
    table='| Model | Accuracy | Macro precision | Macro recall | Macro F1 | Benign FPR |\n|---|---:|---:|---:|---:|---:|\n'
    for experiment in e['experiments']:
        name=experiment['name']+(' (operational)' if experiment['name']==e['metadata']['model'] else '')
        m=experiment['test'];table+='| '+name+' | '+' | '.join(f'{100*m[k]:.2f}%' for k in ['accuracy','precision_macro','recall_macro','f1_macro','false_positive_rate'])+' |\n'
    text=re.sub(r'\| Model \| Accuracy.*?(?=\nThe frontend)',table,text,flags=re.S)
    c=p['confidence_only'];r=p['risk_aware']
    text=re.sub(r'Confidence-only recommended .*?\*\*Risk-v1',f"Confidence-only recommended {c['recommendations']} flows ({c['benign_recommended']} benign); risk recommended {r['recommendations']} ({r['benign_recommended']} benign). Malicious coverage fell from {100*c['malicious_coverage']:.2f}% to {100*r['malicious_coverage']:.2f}%. **Risk-v1",text,flags=re.S)
    Path('docs/RESEARCH.md').write_text(text,encoding='utf-8')

if __name__=='__main__':main()
