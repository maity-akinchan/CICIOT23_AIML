"""Synthetic software fixtures only; no scores from these fixtures are dataset evidence."""
import json
import numpy as np
import pandas as pd
from fastapi.testclient import TestClient
from sentinel_ml.contract import BASE
from sentinel_ml.csv_contract import matrix,CONTRACT_ID
from sentinel_ml.csv_training import train,build_dataset
from sentinel_ml.artifacts import load,predict
from app.main import app

def test_csv_training_api_parity_and_pcap_gate(tmp_path,monkeypatch):
    for split,name in [('train','train.csv'),('validation','validation.csv'),('test','test.csv')]:
        records=[]
        for k,label in enumerate(['BenignTraffic','DoS-SYN_Flood','DDoS-SYN_Flood']):
            for i in range(4):
                # These original-CSV-style magnitudes intentionally violate packet contract bounds.
                row=dict.fromkeys(BASE,0.0)
                row.update(flow_duration=float(k),Rate=20.+k*100,Header_Length=500000.+k*1000+i,
                           Duration=64.,AVG=300.+k,Std=120.,syn_count=.6,rst_count=641.2,TCP=1.)
                records.append({**row,'label':label})
        folder=tmp_path/split;folder.mkdir();pd.DataFrame(records).to_csv(folder/name,index=False)
    report=train(tmp_path,tmp_path/'models')
    frame,provenance=build_dataset(tmp_path)
    assert provenance['capture_group_split_verified'] is False
    assert provenance['pcap_compatible'] is False
    base=frame.loc[frame.split=='test',BASE]
    bundle=load(tmp_path/'models/ciciot_22f_xgb.joblib')
    x,p=predict(bundle,base)
    assert bundle['contract_id']==CONTRACT_ID
    monkeypatch.setenv('MODEL_DIR',str(tmp_path/'models'));monkeypatch.setenv('DATABASE_URL',f'sqlite:///{tmp_path}/app.db')
    with TestClient(app) as client:
        r=client.post('/api/v1/csv/upload',files={'file':('features.csv',base.to_csv(index=False).encode())})
        assert r.status_code==200,r.text
        for i,prediction in enumerate(r.json()['predictions']):
            assert np.array_equal(list(prediction['features_22'].values()),x.iloc[i].to_numpy())
            assert np.allclose(list(prediction['probabilities'].values()),p[i],atol=1e-6)
        assert client.post('/api/v1/pcap/upload',files={'file':('capture.pcap',b'')}).status_code==422
        assert client.get('/api/v1/flows').json()['total']==0
    # Editing final test labels cannot change training rows.
    before=frame.loc[frame.split=='train'].copy()
    path=tmp_path/'test/test.csv';test=pd.read_csv(path);test['label']=test.label.map({'BenignTraffic':'DoS-SYN_Flood','DoS-SYN_Flood':'DDoS-SYN_Flood','DDoS-SYN_Flood':'BenignTraffic'});test.to_csv(path,index=False)
    after,_=build_dataset(tmp_path)
    pd.testing.assert_frame_equal(before,after.loc[after.split=='train'])
