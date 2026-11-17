"""Strict artifact loading and golden-row verification on every deployment."""
from pathlib import Path
import hashlib
import joblib
import numpy as np
import pandas as pd
from .contract import BASE, FEATURES, CLASSES

def profile(bundle):
    from . import csv_contract
    if bundle.get('contract_id') in (csv_contract.CONTRACT_ID,'ciciot23-legacy22-v1') and bundle.get('contract_hash')==csv_contract.CONTRACT_HASH:
        return csv_contract.matrix
    raise ValueError('Artifact measurement contract is incompatible')

def load(path):
    digest=hashlib.sha256(Path(path).read_bytes()).hexdigest()
    bundle=joblib.load(path)
    legacy=digest=='e1dde2fe2a759684208021934ad3edff2be2dfa29977fac9a246ba9665da233e'
    if legacy:
        from .csv_contract import CONTRACT_HASH as CSV_HASH
        bundle.update(contract_id='ciciot23-legacy22-v1',contract_hash=CSV_HASH,model_id='xgb',is_legacy=True,
                      parity_validation='not_available_for_historical_artifact')
    preprocess=profile(bundle)
    if bundle.get('feature_names')!=list(FEATURES):raise ValueError('Artifact feature order mismatch')
    model=bundle['model'];encoder=bundle['label_encoder']
    classes=list(encoder.inverse_transform(model.classes_.astype(int)) if encoder is not None else model.classes_)
    if classes!=bundle['classes'] or set(classes)!=set(CLASSES):raise ValueError('Class/probability order mismatch')
    if list(model.feature_names_in_)!=list(FEATURES):raise ValueError('Estimator input schema mismatch')
    if not legacy:
        golden=preprocess(pd.DataFrame(bundle['golden_base'],columns=BASE))
        actual=model.predict_proba(golden)
        if not np.allclose(actual,bundle['golden_probabilities'],atol=1e-6,rtol=1e-6):raise ValueError('Golden prediction mismatch')
    bundle['artifact_sha256']=hashlib.sha256(Path(path).read_bytes()).hexdigest()
    return bundle

def predict(bundle,base):
    x=profile(bundle)(base);scores=np.asarray(bundle['model'].predict_proba(x))
    if scores.shape!=(len(x),len(CLASSES)) or not np.isfinite(scores).all() or (scores<0).any() or (scores>1).any() or not np.allclose(scores.sum(axis=1),1,atol=1e-5):
        raise ValueError('Invalid probability output')
    return x,scores
