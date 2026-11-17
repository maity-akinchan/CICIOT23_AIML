import io,json,socket
from pathlib import Path
import dpkt
import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient
from sentinel_ml.capture import extract
from sentinel_ml.contract import BASE,CONTRACT_ID,CONTRACT_HASH,matrix
from sentinel_ml.training import train,build_dataset
from sentinel_ml.artifacts import load,predict
from app.main import app

def capture(path,flags=2,size=0,step=.001):
    with open(path,'wb') as out:
        writer=dpkt.pcap.Writer(out)
        for i in range(100):
            tcp=dpkt.tcp.TCP(sport=1234,dport=80,flags=flags,off=5,data=b'x'*size)
            ip=dpkt.ip.IP(src=socket.inet_aton('172.18.0.50'),dst=socket.inet_aton('172.18.0.10'),p=6,ttl=64,data=tcp);ip.len=len(ip)
            eth=dpkt.ethernet.Ethernet(src=b'\x00'*6,dst=b'\x01'*6,type=2048,data=ip)
            writer.writepkt(bytes(eth),ts=i*step)

@pytest.fixture(scope='module')
def experiment(tmp_path_factory):
    root=tmp_path_factory.mktemp('training');items=[]
    for j,split in enumerate(('train','validation','test')):
        for k,label in enumerate(('Benign','DoS','DDoS')):
            path=root/f'{split}-{label}.pcap';capture(path,flags=16 if k==0 else 2,size=100*k+j,step=.001*(k+1)+j*.0001)
            items.append(dict(path=path.name,capture_group=path.stem,split=split,label=label))
    manifest=root/'manifest.json';manifest.write_text(json.dumps(items));report=train(manifest,root/'models')
    return root,manifest,report

def test_training_serving_and_api_parity(experiment,monkeypatch):
    root,manifest,report=experiment
    monkeypatch.setenv('MODEL_DIR',str(root/'models'));monkeypatch.setenv('DATABASE_URL',f'sqlite:///{root}/api.db')
    rows,_=build_dataset(manifest);base=rows.loc[rows.split=='validation',BASE]
    bundle=load(root/'models/ciciot_22f_xgb.joblib');expected_x,expected=predict(bundle,base)
    with TestClient(app) as client:
        assert client.get('/health').json()['model_loaded']
        data=[]
        for i,row in enumerate(base.to_dict('records')):
            data.append(dict(**row,src_ip='172.18.0.50',dst_ip='172.18.0.10',window_id=f'row-{i}'))
        payload=dict(feature_contract_id=CONTRACT_ID,contract_hash=CONTRACT_HASH,data=data)
        response=client.post('/api/v1/predict/batch',json=payload)
        assert response.status_code==200,response.text
        for i,p in enumerate(response.json()['predictions']):
            assert list(p['features_22'])==list(expected_x.columns)
            assert np.array_equal(list(p['features_22'].values()),expected_x.iloc[i].to_numpy())
            assert np.allclose(list(p['probabilities'].values()),expected[i],atol=1e-6)
            assert p['artifact_sha256']==bundle['artifact_sha256']
        assert client.get('/api/v1/flows').json()['total']==0  # pure prediction
        assert client.post('/api/v1/predict/batch',json={**payload,'contract_hash':'wrong'}).status_code==422
        data[0]['Rate']='100'
        assert client.post('/api/v1/predict/batch',json=payload).status_code==422
        assert client.post('/api/devices/any/action',json={'action':'BLOCK_IP','ip':'1.2.3.4'}).status_code==403
        pc=root/'validation-Benign.pcap'
        result=client.post('/api/v1/pcap/upload',files={'file':('capture.pcap',pc.read_bytes())})
        assert result.status_code==200,result.text
        assert result.json()['processed_windows']==1

def test_invalid_inputs_and_artifacts(experiment):
    root,manifest,_=experiment
    frame,_=build_dataset(manifest);base=frame.loc[:,BASE]
    for wrong in (base.iloc[:,::-1],base.astype(str),base.assign(Rate=np.inf),base.assign(syn_count=200)):
        with pytest.raises(ValueError):matrix(wrong)
    import joblib
    bundle=joblib.load(root/'models/ciciot_22f_xgb.joblib');bundle['contract_hash']='wrong'
    joblib.dump(bundle,root/'wrong.joblib')
    with pytest.raises(ValueError,match='incompatible'):load(root/'wrong.joblib')
    items=json.loads(manifest.read_text());items[3]['capture_group']=items[0]['capture_group']
    bad=root/'bad.json';bad.write_text(json.dumps(items))
    with pytest.raises(ValueError,match='crosses splits'):build_dataset(bad)

def test_missing_model_never_bootstraps(tmp_path,monkeypatch):
    monkeypatch.setenv('MODEL_DIR',str(tmp_path));monkeypatch.setenv('DATABASE_URL',f'sqlite:///{tmp_path}/empty.db')
    with TestClient(app) as client:
        assert not client.get('/health').json()['model_loaded']
        assert all(not m['available'] for m in client.get('/api/v1/models').json()['models'])
        assert client.post('/api/v1/models/select',json={'model_id':'xgb'}).status_code==503

def test_retry_atomic_failure_and_utc(experiment,monkeypatch):
    root,manifest,_=experiment
    monkeypatch.setenv('MODEL_DIR',str(root/'models'));monkeypatch.setenv('DATABASE_URL',f'sqlite:///{root}/retry.db')
    rows,_=build_dataset(manifest);f=rows.loc[:,BASE].iloc[0].to_dict()
    window=dict(window_id='stable',timestamp_end='2026-01-01T05:30:00+05:30',packet_count=100,
                metadata=dict(src_ip='172.18.0.50',dst_ip='172.18.0.10'),features_18=f)
    payload=dict(feature_contract_id=CONTRACT_ID,contract_hash=CONTRACT_HASH,collector_id='sensor',capture_session_id='session',windows=[window])
    with TestClient(app) as client:
        for _ in range(2):
            r=client.post('/api/v1/ingest/windows',json=payload)
            assert r.status_code==200,r.text
        flows=client.get('/api/v1/flows').json()
        assert flows['total']==1
        assert flows['items'][0]['timestamp']=='2026-01-01T00:00:00'
        valid=(root/'train-Benign.pcap').read_bytes()
        bad=client.post('/api/v1/pcap/upload',files={'file':('bad.pcap',valid+b'broken')})
        assert bad.status_code==422
        assert client.get('/api/v1/flows').json()['total']==1
        client.post('/api/v1/system/reset')
        assert client.get('/api/v1/flows').json()['total']==0

def test_extractor_rejects_truncation_and_timeout(tmp_path):
    import struct
    p=tmp_path/'timeout.pcap';capture(p,step=.5)
    stats={}
    with p.open('rb') as stream:assert list(extract(stream,stats))==[]
    assert stats['insufficient_packets']==100
    p=tmp_path/'valid.pcap';capture(p)
    data=bytearray(p.read_bytes());caplen=struct.unpack('<I',data[32:36])[0]
    data[36:40]=struct.pack('<I',caplen+1)
    with pytest.raises(ValueError,match='Truncated'):list(extract(io.BytesIO(data)))
