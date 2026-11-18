"""Train only from the three supplied Kaggle CSV splits; no capture dependency."""
from pathlib import Path
import numpy as np
import pandas as pd
from .contract import BASE,CLASSES
from .csv_contract import matrix,CONTRACT_ID,CONTRACT_HASH
from .training import fit_export,sha

def labels(series):
    text=series.astype(str)
    result=pd.Series(None,index=series.index,dtype='object')
    result.loc[text=='BenignTraffic']='Benign'
    result.loc[text.str.startswith('DDoS-')]='DDoS'
    result.loc[text.str.startswith('DoS-')]='DoS'
    return result

def build_dataset(root):
    root=Path(root);parts=[];sources=[];fingerprints={}
    for split,folder,name in [('train','train','train.csv'),('validation','validation','validation.csv'),('test','test','test.csv')]:
        candidates=list(root.rglob(name))+list(root.rglob(name+".gz"))
        if len(candidates)!=1:raise ValueError(f'Expected exactly one {name} below {root}')
        path=candidates[0]
        raw=pd.read_csv(path,usecols=list(BASE)+['label'],dtype={k:'float32' for k in BASE})
        y=labels(raw.label);chosen=y.notna();base=raw.loc[chosen,BASE].copy();y=y.loc[chosen]
        valid=np.isfinite(base.to_numpy()).all(axis=1)&(base.flow_duration>=0)&(base.Rate>=0)
        invalid=int((~valid).sum());base=base.loc[valid];y=y.loc[valid]
        # No test-label conflict filtering, cross-split row deletion or resplitting.
        matrix(base)
        hashes=pd.util.hash_pandas_object(base,index=False)
        fingerprints[split]=set(hashes)
        if split=='train':
            keep=~pd.DataFrame({'hash':hashes,'label':y}).duplicated()
            base=base.loc[keep];y=y.loc[keep]
        if set(y)!=set(CLASSES):raise ValueError(f'{split} lacks a target class')
        part=base.assign(label=y,split=split)
        parts.append(part)
        sources.append(dict(split=split,path=str(path),sha256=sha(path),raw_rows=len(raw),
                            excluded_other_labels=int((~chosen).sum()),invalid_rows=invalid,retained_rows=len(part),
                            class_counts=y.value_counts().to_dict()))
    overlap={f'{a}/{b}':len(fingerprints[a]&fingerprints[b]) for a,b in [('train','validation'),('train','test'),('validation','test')]}
    return pd.concat(parts,ignore_index=True),dict(dataset='himadri07/ciciot2023',contract_id=CONTRACT_ID,
        contract_hash=CONTRACT_HASH,sources=sources,exact_feature_overlap=overlap,
        capture_group_split_verified=False,pcap_compatible=False,
        limitations=['Supplied row splits retained; recording independence unknown','Exact overlap reported, not used to modify holdout labels or training'])

def train(root,output_dir,model_names=None):
    frame,provenance=build_dataset(root)
    return fit_export(frame,provenance,output_dir,preprocess=matrix,contract_id=CONTRACT_ID,contract_hash=CONTRACT_HASH,model_names=model_names)
