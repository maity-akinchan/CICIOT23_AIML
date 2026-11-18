"""Validation-selected attack threshold, shared by training and serving."""
import numpy as np


def classify(classes, scores, policy=None):
    classes = np.asarray(classes)
    scores = np.asarray(scores)
    prediction = classes[scores.argmax(axis=1)].copy()
    if policy is not None:
        benign = list(classes).index('Benign')
        attack_score = 1 - scores[:, benign]
        prediction[attack_score < policy['attack_threshold']] = 'Benign'
    return prediction


def select_policy(classes, scores, labels, max_false_positive_rate=0.001):
    """Choose the most permissive threshold meeting the validation FP budget."""
    if not 0 <= max_false_positive_rate < 1:
        raise ValueError('False-positive budget must be in [0,1)')
    classes = list(classes)
    labels = np.asarray(labels)
    benign = labels == 'Benign'
    if not benign.any():
        raise ValueError('Validation requires benign examples')
    scores = np.asarray(scores)
    attack_score = 1 - scores[:, classes.index('Benign')]
    raw_attack = np.asarray(classes)[scores.argmax(axis=1)] != 'Benign'
    false_scores = np.sort(attack_score[benign & raw_attack])[::-1]
    allowed = int(np.floor(max_false_positive_rate * benign.sum()))
    threshold = 0.0
    if len(false_scores) > allowed:
        threshold = float(np.nextafter(false_scores[allowed], np.inf))
    policy = dict(attack_threshold=threshold, max_validation_false_positive_rate=max_false_positive_rate,
                  validation_benign_count=int(benign.sum()), scope='dataset_features',
                  packet_validated=False)
    predicted = classify(classes, scores, policy)
    policy['validation_false_positives'] = int(((predicted != 'Benign') & benign).sum())
    policy['validation_attack_recall'] = float((predicted[~benign] != 'Benign').mean()) if (~benign).any() else 0.0
    policy['usable'] = policy['validation_attack_recall'] > 0
    return policy
