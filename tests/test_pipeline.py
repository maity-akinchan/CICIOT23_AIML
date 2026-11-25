import io,json,socket
from pathlib import Path
import dpkt
import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient
from sentinel_ml.capture import extract
from sentinel_ml.contract import BASE
from sentinel_ml.csv_contract import matrix
from sentinel_ml.approximation import CONTRACT_ID,CONTRACT_HASH
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
    root=tmp_path_factory.mktemp('inference')
    path=root/'capture.pcap';capture(path)
    with path.open('rb') as stream:rows=list(extract(stream))
    base=pd.DataFrame([row['features_18'] for row in rows],columns=BASE)
    return root,Path(__file__).resolve().parents[1]/'ml/artifacts',base

def test_training_serving_and_api_parity(experiment,monkeypatch):
    root,models,base=experiment
    monkeypatch.setenv('MODEL_DIR',str(models));monkeypatch.setenv('DATABASE_URL',f'sqlite:///{root}/api.db')
    bundle=load(models/'ciciot_22f_xgb.joblib');expected_x,expected=predict(bundle,base)
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
        pc=root/'capture.pcap'
        result=client.post('/api/v1/pcap/upload',files={'file':('capture.pcap',pc.read_bytes())})
        assert result.status_code==200,result.text
        assert result.json()['processed_windows']==1

def test_invalid_inputs_and_artifacts(experiment):
    root,models,base=experiment
    for wrong in (base.iloc[:,::-1],base.astype(str),base.assign(Rate=np.inf),base.assign(Rate=-1)):
        with pytest.raises(ValueError):matrix(wrong)
    import joblib
    bundle=joblib.load(models/'ciciot_22f_xgb.joblib');bundle['contract_hash']='wrong'
    joblib.dump(bundle,root/'wrong.joblib')
    with pytest.raises(ValueError,match='incompatible'):load(root/'wrong.joblib')

def test_missing_model_never_bootstraps(tmp_path,monkeypatch):
    monkeypatch.setenv('MODEL_DIR',str(tmp_path));monkeypatch.setenv('DATABASE_URL',f'sqlite:///{tmp_path}/empty.db')
    with TestClient(app) as client:
        assert not client.get('/health').json()['model_loaded']
        assert all(not m['available'] for m in client.get('/api/v1/models').json()['models'])
        assert client.post('/api/v1/models/select',json={'model_id':'xgb'}).status_code==503

def test_retry_atomic_failure_and_utc(experiment,monkeypatch):
    root,models,base=experiment
    monkeypatch.setenv('MODEL_DIR',str(models));monkeypatch.setenv('DATABASE_URL',f'sqlite:///{root}/retry.db')
    f=base.iloc[0].to_dict()
    window=dict(window_id='stable',timestamp_end='2026-01-01T05:30:00+05:30',packet_count=100,
                metadata=dict(src_ip='172.18.0.50',dst_ip='172.18.0.10',transport_header_mean=20.),features_18=f)
    payload=dict(feature_contract_id=CONTRACT_ID,contract_hash=CONTRACT_HASH,collector_id='sensor',capture_session_id='session',windows=[window])
    with TestClient(app) as client:
        for _ in range(2):
            r=client.post('/api/v1/ingest/windows',json=payload)
            assert r.status_code==200,r.text
        flows=client.get('/api/v1/flows').json()
        assert flows['total']==1
        assert flows['items'][0]['timestamp']=='2026-01-01T00:00:00'
        valid=(root/'capture.pcap').read_bytes()
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


def test_monitoring_device_reports_and_recent_live_predictions(experiment, tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import update
    from app.models import Flow, MonitoredCollector

    _, models, base = experiment
    monkeypatch.setenv('MODEL_DIR', str(models))
    monkeypatch.setenv('DATABASE_URL', f'sqlite:///{tmp_path}/devices.db')
    monkeypatch.setenv('SENTINEL_AUTH_DISABLED', '1')
    now = datetime.now(timezone.utc)
    coverage = dict(collector_id='windows-test', session='live', iface='Ethernet', captured=100,
                    accepted=100, insufficient_packets=0, capacity_evictions=0, kernel_drops=0,
                    queue_drops=0, windows_emitted=1, windows_dropped=0, http_ok=0, http_fail=0)
    window = dict(window_id='one', timestamp_end=now.isoformat(), packet_count=100,
                  metadata=dict(src_ip='192.0.2.1', dst_ip='192.0.2.2', transport_header_mean=20.),
                  features_18=base.iloc[0].to_dict())
    payload = dict(feature_contract_id=CONTRACT_ID, contract_hash=CONTRACT_HASH,
                   collector_id='windows-test', capture_session_id='live', windows=[window])

    with TestClient(app) as client:
        assert client.post('/api/v1/ingest/coverage', json=coverage).status_code == 204
        report, = client.get('/api/v1/monitoring/devices').json()
        assert report['status'] == 'online' and report['windows_24h'] == 0
        assert report['coverage']['iface'] == 'Ethernet'
        with client.websocket_connect('/ws/live') as ws:
            assert ws.receive_json()['event_type'] == 'SNAPSHOT'
            response = client.post('/api/v1/ingest/windows', json=payload)
            assert response.status_code == 200, response.text
            update_frame = ws.receive_json()
            assert update_frame['new_alerts'][0]['input_representation'] == 'packet_approximation'
            assert update_frame['flows'][0]['top_anomalies']
        assert client.post('/api/v1/ingest/windows', json=payload).status_code == 200
        replay = {**payload, 'capture_mode': 'PCAP_REPLAY', 'capture_session_id': 'historical'}
        assert client.post('/api/v1/ingest/windows', json=replay).status_code == 200
        report, = client.get('/api/v1/monitoring/devices').json()
        assert report['windows_24h'] == report['dos_24h'] == 1
        assert report['last_flagged_24h'] == now.isoformat()
        with app.state.sessions.begin() as db:
            db.execute(update(Flow).values(top_anomalies_json='[]'))
            db.execute(update(MonitoredCollector).values(last_seen=(now - timedelta(minutes=1)).replace(tzinfo=None)))
        assert client.get('/api/v1/flows').json()['items'][0]['top_anomalies']

    with TestClient(app) as client:
        report, = client.get('/api/v1/monitoring/devices').json()
        assert report['status'] == 'offline' and report['dos_24h'] == 1
        assert report['coverage']['iface'] == 'Ethernet'
