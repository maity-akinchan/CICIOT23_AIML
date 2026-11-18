import numpy as np
from sentinel_ml.decision import classify, select_policy

def test_tied_false_positive_scores_and_serving_decisions():
    classes = ['Benign', 'DDoS', 'DoS']
    scores = np.array([[.001,.999,0],[.001,.999,0],[.0001,.9999,0],[.9,.1,0]])
    labels = ['Benign','Benign','DDoS','Benign']
    policy = select_policy(classes,scores,labels,0)
    assert classify(classes,scores,policy).tolist() == ['Benign','Benign','DDoS','Benign']
    assert policy['validation_false_positives'] == 0
    assert policy['validation_attack_recall'] == 1
