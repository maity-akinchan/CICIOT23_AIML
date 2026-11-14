from fastapi.testclient import TestClient
from app.main import app
from app.schemas import BASE_FEATURE_NAMES

def test_trained_model_and_persistence(tmp_path, monkeypatch):
    monkeypatch.setenv('DATABASE_URL',f'sqlite:///{tmp_path}/test.db')
    features=dict.fromkeys(BASE_FEATURE_NAMES,0.0)
    features.update(flow_duration=.0099,Rate=100/.0099,Header_Length=40,Duration=64,syn_flag_number=1,syn_count=100,TCP=1,AVG=54)
    with TestClient(app) as client:
        assert not client.get('/health').json()['is_bootstrap_model']
        data={'collector_id':'test','capture_mode':'PCAP_UPLOAD','windows':[{'window_id':'fixture','timestamp_start':'2026-01-01T00:00:00Z','timestamp_end':'2026-01-01T00:00:00.009900Z','packet_count':100,'metadata':{'src_ip':'172.18.0.50','dst_ip':'172.18.0.10'},'features_18':features}]}
        response=client.post('/api/v1/ingest/windows',json=data)
        assert response.status_code==200,response.text
        p=response.json()['predictions'][0]
        assert p['predicted_class'] in ('Benign','DoS','DDoS')
        assert abs(sum(p['probabilities'].values())-1)<1e-5
        assert p['features_22']['syn_ack_ratio']==101
        assert abs(p['features_22']['hdr_pkt_ratio']-40/54.00001)<1e-5
        assert client.get('/api/v1/overview/summary').json()['total_flows']==1
        assert client.get('/api/v1/flows').json()['total']==1
        assert len(client.get('/api/v1/models').json()['models'])==4
        metrics=client.get('/api/v1/models/xgb/analytics').json()
        assert metrics['test_accuracy']>.8
        assert len(client.get('/api/devices').json())==2
        client.post('/api/v1/system/reset')
        assert client.get('/api/v1/overview/summary').json()['total_flows']==0
