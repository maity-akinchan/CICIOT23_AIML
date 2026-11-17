"""Contract for the user's himadri07/ciciot2023 CSV experiment."""
import hashlib
import json
import numpy as np
import pandas as pd
from .contract import BASE,FEATURES,CLASSES
SPEC=dict(id='ciciot23-kaggle-csv22-v2',dataset='himadri07/ciciot2023',features=list(FEATURES),
          base_dtype='float32',intermediate_dtype='float64',output_dtype='float32',
          invalid='reject nonfinite or negative duration/rate; no imputation or clipping',
          formulas=['Rate*AVG','(syn_count+1)/(ack_count+1)','Header_Length/(AVG+1e-5)','Std/(AVG+1e-5)'],
          packet_semantics='original CSV measurements; raw packet compatibility unverified')
CONTRACT_ID=SPEC['id']
CONTRACT_HASH=hashlib.sha256(json.dumps(SPEC,sort_keys=True).encode()).hexdigest()

def matrix(frame):
    if list(frame.columns)!=list(BASE):raise ValueError('Expected exactly the ordered 18 base columns')
    if not all(pd.api.types.is_numeric_dtype(t) and not pd.api.types.is_bool_dtype(t) for t in frame.dtypes):
        raise ValueError('Features must have numeric dtypes')
    # Match CSV training rounding BEFORE feature engineering in both consumers.
    x=frame.astype('float32').astype('float64')
    if not np.isfinite(x.to_numpy()).all():raise ValueError('Nonfinite CSV features')
    if (x[['flow_duration','Rate']]<0).any().any():raise ValueError('Negative duration/rate')
    if ((x.ack_count==-1)|(x.AVG==-1e-5)).any():raise ValueError('Invalid ratio denominator')
    x['bytes_per_sec']=x.Rate*x.AVG
    x['syn_ack_ratio']=(x.syn_count+1)/(x.ack_count+1)
    x['hdr_pkt_ratio']=x.Header_Length/(x.AVG+1e-5)
    x['pkt_cv']=x.Std/(x.AVG+1e-5)
    out=x.loc[:,FEATURES].astype('float32')
    if not np.isfinite(out.to_numpy()).all():raise ValueError('Nonfinite engineered features')
    return out
