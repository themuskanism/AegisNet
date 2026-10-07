"""Reproducible evaluated baselines and a real temporal CNN-BiLSTM experiment."""
import argparse
from collections import Counter
import copy
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import platform
from time import perf_counter
import joblib
import numpy as np
import psutil
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.ensemble import RandomForestClassifier,HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score,classification_report,confusion_matrix,precision_recall_fscore_support,log_loss
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from backend.flows import FEATURE_NAMES,SCHEMA_VERSION,FLOW_POLICY


def metrics(y,p,classes):
    precision,recall,f1,_=precision_recall_fscore_support(y,p,average='macro',zero_division=0)
    benign=y=='Benign'
    return {'accuracy':float(accuracy_score(y,p)),'precision_macro':float(precision),'recall_macro':float(recall),'f1_macro':float(f1),'false_positive_rate':float(np.mean(p[benign]!='Benign')) if benign.any() else None,'confusion_matrix':confusion_matrix(y,p,labels=classes).tolist(),'per_class':classification_report(y,p,labels=classes,output_dict=True,zero_division=0)}


def benchmark(pipeline,x):
    pipeline.predict_proba(x[:1]);times=[]
    for row in x[:100]:
        start=perf_counter();pipeline.predict_proba(row.reshape(1,-1));times.append((perf_counter()-start)*1000)
    start=perf_counter();pipeline.predict_proba(x);elapsed=perf_counter()-start
    return {'single_flow_p50_ms':float(np.percentile(times,50)),'single_flow_p95_ms':float(np.percentile(times,95)),'batch_flows_per_second':len(x)/elapsed,'batch_size':len(x),'includes':'preprocessing + classification; excludes capture/flow wait, DB and XAI'}


def train(out,epochs=12):
    out=Path(out);d=np.load(out/'dataset.npz');x=d['x'];y=d['y'];split=d['split']
    train_i=split==0;val_i=split==1;test_i=split==2
    classes=sorted(set(y));models={
        'Logistic Regression':LogisticRegression(max_iter=2000,class_weight='balanced',random_state=42),
        'Random Forest':RandomForestClassifier(n_estimators=120,max_depth=16,min_samples_leaf=2,class_weight='balanced',random_state=42,n_jobs=2),
        'Histogram Gradient Boosting':HistGradientBoostingClassifier(max_iter=120,max_leaf_nodes=15,l2_regularization=1,random_state=42)}
    experiments=[];pipelines={};process=psutil.Process();start_cpu=process.cpu_times();total_start=perf_counter()
    for name,model in models.items():
        start=perf_counter();base=make_pipeline(StandardScaler(),model).fit(x[train_i],y[train_i])
        # Validation is used for sigmoid calibration and comparison, never the held-out test.
        calibrated=CalibratedClassifierCV(FrozenEstimator(base),method='sigmoid').fit(x[val_i],y[val_i])
        pipelines[name]=calibrated
        result={'name':name,'training_seconds':perf_counter()-start,'validation':metrics(y[val_i],calibrated.predict(x[val_i]),classes),'test':None,'latency':None,'parameters':model.get_params()}
        experiments.append(result);print(name,result['validation']['f1_macro'],flush=True)
    # Choose by validation only; test metrics are evaluated after freezing the selection.
    winner=max(experiments,key=lambda r:r['validation']['f1_macro'])['name']
    for r in experiments:
        pipe=pipelines[r['name']];probs=pipe.predict_proba(x[test_i]);r['test']=metrics(y[test_i],pipe.classes_[probs.argmax(axis=1)],classes)
        r['test']['log_loss']=float(log_loss(y[test_i],probs,labels=classes));r['latency']=benchmark(pipe,x[test_i])
    import torch
    from torch import nn
    from backend.deep import CNNBiLSTM
    torch.manual_seed(42);torch.set_num_threads(2);torch.use_deterministic_algorithms(True)
    sx=torch.tensor(d['sequences']);lengths=torch.tensor(d['lengths']);target=torch.tensor([classes.index(v) for v in y])
    net=CNNBiLSTM(len(classes));counts=np.bincount(target[train_i].numpy(),minlength=len(classes));weights=torch.tensor(counts.sum()/(len(classes)*counts),dtype=torch.float32)
    optimizer=torch.optim.Adam(net.parameters(),lr=.002);lossfn=nn.CrossEntropyLoss(weight=weights)
    best=-1.;state=None;history=[];start=perf_counter()
    train_idx=np.flatnonzero(train_i);val_idx=np.flatnonzero(val_i);test_idx=np.flatnonzero(test_i)
    def logits(indices):
        net.eval();parts=[]
        with torch.no_grad():
            for batch in np.array_split(indices,max(1,int(np.ceil(len(indices)/256)))):parts.append(net(sx[batch],lengths[batch]))
        return torch.cat(parts)
    for epoch in range(epochs):
        net.train();rng=np.random.default_rng(42+epoch);order=rng.permutation(train_idx);total_loss=0.
        for batch in np.array_split(order,max(1,int(np.ceil(len(order)/128)))):
            optimizer.zero_grad();loss=lossfn(net(sx[batch],lengths[batch]),target[batch]);loss.backward();optimizer.step();total_loss+=loss.item()
        validation=metrics(y[val_i],np.array(classes)[logits(val_idx).argmax(1).numpy()],classes)
        history.append({'epoch':epoch+1,'train_loss_sum':total_loss,'validation_f1_macro':validation['f1_macro']})
        if validation['f1_macro']>best:best=validation['f1_macro'];state=copy.deepcopy(net.state_dict())
        print('CNN-BiLSTM',history[-1],flush=True)
    net.load_state_dict(state);net.eval()
    torch.save({'state_dict':state,'classes':classes,'schema':SCHEMA_VERSION,'flow_policy':FLOW_POLICY},out/'cnn_bilstm.pt')
    # Temperature scaling on validation logits; selected temperature never observes test labels.
    vl=logits(val_idx);temperatures=np.geomspace(.25,4,25)
    temperature=float(min(temperatures,key=lambda t:nn.functional.cross_entropy(vl/t,target[val_idx]).item()))
    test_logits=logits(test_idx);pr=torch.softmax(test_logits/temperature,dim=1).numpy()
    deepmetrics=metrics(y[test_i],np.array(classes)[pr.argmax(1)],classes);deepmetrics['log_loss']=float(log_loss(y[test_i],pr,labels=classes))
    t0=perf_counter();logits(test_idx);elapsed=perf_counter()-t0
    experiments.append({'name':'CNN-BiLSTM','training_seconds':perf_counter()-start,'validation':{'f1_macro':best},'test':deepmetrics,'latency':{'batch_flows_per_second':len(test_idx)/elapsed,'batch_size':len(test_idx),'includes':'tensor model inference; excludes feature extraction'},'temperature':temperature,'epochs':epochs,'history':history,'representation':'first 32 chronological packets; direction/log IP bytes/log IAT/flags; packed BiLSTM lengths'})
    rng=np.random.default_rng(42);background=x[train_i][rng.choice(train_i.sum(),min(16,train_i.sum()),replace=False)]
    joblib.dump({'pipeline':pipelines[winner],'background':background},out/'model.joblib')
    manifest=json.loads((out/'dataset_manifest.json').read_text());version='iot23-34-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    metadata={'version':version,'schema':SCHEMA_VERSION,'features':FEATURE_NAMES,'flow_policy':FLOW_POLICY,'classes':classes,'model':winner,'dataset':manifest['dataset'],'experiment_date':datetime.now(timezone.utc).isoformat(),'sha256':hashlib.sha256((out/'model.joblib').read_bytes()).hexdigest(),'selection':'Best validation macro-F1 among calibrated tabular baselines. Operational tabular model supports bounded full-pipeline SHAP; CNN-BiLSTM remains evaluated research candidate, not claimed superior.','limitations':['One IoT scenario; not cross-scenario or enterprise validation.','Validation reused for calibration and model comparison; test remains held out.','Unsupported traffic and domain shift can produce unreliable predictions.','No zero-day detection claim.']}
    (out/'metadata.json').write_text(json.dumps(metadata,indent=2))
    from backend.model import Detector
    detector=Detector(out);exp=detector.explain(dict(zip(FEATURE_NAMES,x[test_i][0])))
    cpu=process.cpu_times();report={'metadata':metadata,'dataset':manifest,'experiments':experiments,'resources':{'wall_seconds':perf_counter()-total_start,'cpu_seconds':cpu.user+cpu.system-start_cpu.user-start_cpu.system,'rss_bytes':process.memory_info().rss,'platform':platform.platform(),'python':platform.python_version(),'logical_cpus':psutil.cpu_count()},'xai_measurement':{'method':exp['method'],'first_call_ms':exp['elapsed_ms'],'background_size':exp['background_size'],'scope':'one held-out flow; not an analyst usefulness study'},'research_status':{'RQ1':'measured within scenario','RQ2':'measured, representation differs','RQ3':'shared extractor + parity tests','RQ4':'real SHAP; usefulness study outstanding','RQ5':'model latency measured; live pipeline measured separately','RQ6':'policy simulation tested; evaluation recorded separately'}}
    (out/'evaluation.json').write_text(json.dumps(report,indent=2))
    # Safe metadata-only replay samples, selected from held-out test partition, never network injection.
    selected=[];seen=Counter()
    with (out/'records.jsonl').open() as f:
        for line in f:
            r=json.loads(line)
            if r['split']==2 and seen[r['label']]<3:
                selected.append(r);seen[r['label']]+=1
    (out/'demo.json').write_text(json.dumps({'provenance':'benchmark_replay','dataset':manifest['dataset'],'records':selected},indent=2))
    print(json.dumps({'winner':winner,'tests':{r['name']:r['test']['f1_macro'] for r in experiments}},indent=2),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',default='artifacts');p.add_argument('--epochs',type=int,default=12);a=p.parse_args();train(a.out,a.epochs)
