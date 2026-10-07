import importlib.util
import numpy as np


def test_metrics_count_false_positives_against_benign_support():
    assert importlib.util.find_spec('research.train'), 'experiment evaluator is required'
    from research.train import metrics
    r=metrics(np.array(['Benign','Benign','DDoS','DDoS']),np.array(['Benign','DDoS','DDoS','DDoS']),['Benign','DDoS'])
    assert r['accuracy']==.75
    assert r['false_positive_rate']==.5
    assert r['confusion_matrix']==[[1,1],[0,2]]


def test_deep_padding_does_not_change_output():
    import torch
    from backend.deep import CNNBiLSTM
    torch.manual_seed(7)
    net=CNNBiLSTM(3).eval()
    x=torch.zeros(2,32,8);x[:,:3,:]=1
    with torch.no_grad():
        a=net(x,torch.tensor([3,3]))
    assert a.shape==(2,3)
    assert torch.allclose(a[0],a[1])
