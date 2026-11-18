import hashlib
from datetime import datetime
from fastapi.testclient import TestClient
from sqlalchemy import select
from app.main import app
from app.models import ServiceCredential, Alert, Incident
from test_pipeline import capture

def test_device_tokens_history_alerts(monkeypatch,tmp_path):
    monkeypatch.delenv('SENTINEL_AUTH_DISABLED',raising=False)
    monkeypatch.setenv('SENTINEL_OPERATOR_TOKEN','operator-secret')
    monkeypatch.setenv('DATABASE_URL',f'sqlite:///{tmp_path}/lifecycle.db')
    headers={'Authorization':'Bearer operator-secret'}
    with TestClient(app) as client:
        issued=client.post('/api/v1/services/credentials',json={'collector_id':'sensor-a'},headers=headers)
        assert issued.status_code==201,issued.text
        credential=issued.json();token=credential['token'];device={'Authorization':'Bearer '+token}
        assert client.post('/api/v1/services/verify',json={'collector_id':'sensor-a'},headers=device).status_code==200
        assert client.post('/api/v1/services/verify',json={'collector_id':'sensor-b'},headers=device).status_code==403
        assert client.get('/api/v1/captures',headers=device).status_code==403
        report = dict(collector_id='sensor-a', iface='eth0', session='session-1', captured=100,
                      accepted=100, insufficient_packets=100, capacity_evictions=0, kernel_drops=0,
                      queue_drops=0, windows_emitted=0, windows_dropped=0, http_ok=0, http_fail=0)
        assert client.post('/api/v1/ingest/coverage', json=report, headers=device).status_code == 204
        assert client.post('/api/v1/ingest/coverage', json={**report, 'collector_id':'other'}, headers=device).status_code == 403
        assert client.get('/api/v1/capture/coverage', headers=device).status_code == 403
        assert client.get('/api/v1/capture/coverage', headers=headers).json()[0]['captured'] == 100
        with app.state.sessions() as db:
            saved=db.get(ServiceCredential,credential['id'])
            assert saved.token_hash==hashlib.sha256(token.encode()).hexdigest()
        assert 'token_hash' not in client.get('/api/v1/services/credentials',headers=headers).text
        assert client.delete('/api/v1/services/credentials/'+credential['id'],headers=headers).status_code==200
        assert client.post('/api/v1/services/verify',json={'collector_id':'sensor-a'},headers=device).status_code==401
        issued=client.post('/api/v1/services/credentials',json={'collector_id':'sensor-a'},headers=headers).json()
        with app.state.sessions.begin() as db:
            db.get(ServiceCredential,issued['id']).expires_at=datetime(2000,1,1)
        assert client.post('/api/v1/services/verify',json={'collector_id':'sensor-a'},headers={'Authorization':'Bearer '+issued['token']}).status_code==401
        file=tmp_path/'sample.pcap';capture(file)
        uploaded=client.post('/api/v1/pcap/upload',headers=headers,files={'file':('sample.pcap',file.read_bytes())})
        assert uploaded.status_code==200,uploaded.text
        session=uploaded.json()['capture_session_id']
        with app.state.sessions.begin() as db:
            incident=Incident(title='test',attack_category='DoS',target_ip='1.2.3.4',source_ips_json='[]',status='ACTIVE');db.add(incident);db.flush()
            alert=Alert(incident_id=incident.id,attack_type='DoS',severity='HIGH',timestamp=datetime.utcnow(),src_ip='1.2.3.5',dst_ip='1.2.3.4',protocol='TCP',confidence=.9,top_anomalies_json='[]');db.add(alert);db.flush();alert_id=alert.id
        assert client.patch(f'/api/v1/alerts/{alert_id}/acknowledge',headers=headers).status_code==200
    with TestClient(app) as client:
        history=client.get('/api/v1/captures',headers=headers).json()
        assert history['total']==1 and history['items'][0]['id']==session
        assert client.get('/api/v1/flows',params={'capture_session_id':session},headers=headers).json()['total']==1
        alerts=client.get('/api/v1/alerts',headers=headers).json()
        assert next(a for a in alerts if a['id']==alert_id)['acknowledged'] is True
