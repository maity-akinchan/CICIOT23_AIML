"""Strict artifact loading and golden-row verification on every deployment."""
from pathlib import Path
import hashlib
import joblib
import numpy as np
import pandas as pd
from .contract import BASE, FEATURES, CLASSES, CONTRACT_ID, CONTRACT_HASH, matrix

def load(path):
    bundle=joblib.load(path)
    if bundle.get('contract_id')!=CONTRACT_ID or bundle.get('contract_hash')!=CONTRACT_HASH:
        raise ValueError('Artifact measurement contract is incompatible; retrain with the shared pipeline')
    if bundle.get('feature_names')!=list(FEATURES):raise ValueError('Artifact feature order mismatch')
    model=bundle['model'];encoder=bundle['label_encoder']
    classes=list(encoder.inverse_transform(model.classes_.astype(int)) if encoder is not None else model.classes_)
    if classes!=bundle['classes'] or set(classes)!=set(CLASSES):raise ValueError('Class/probability order mismatch')
    if list(model.feature_names_in_)!=list(FEATURES):raise ValueError('Estimator input schema mismatch')
    golden=matrix(pd.DataFrame(bundle['golden_base'],columns=BASE))
    actual=model.predict_proba(golden)
    if not np.allclose(actual,bundle['golden_probabilities'],atol=1e-6,rtol=1e-6):raise ValueError('Golden prediction mismatch')
    bundle['artifact_sha256']=hashlib.sha256(Path(path).read_bytes()).hexdigest()
    return bundle

def predict(bundle,base):
    x=matrix(base);scores=np.asarray(bundle['model'].predict_proba(x))
    if scores.shape!=(len(x),len(CLASSES)) or not np.isfinite(scores).all() or (scores<0).any() or (scores>1).any() or not np.allclose(scores.sum(axis=1),1,atol=1e-5):
        raise ValueError('Invalid probability output')
    return x,scores
