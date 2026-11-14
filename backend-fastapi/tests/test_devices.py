from fastapi.testclient import TestClient
from app.main import app

def test_enrollment_and_commands(tmp_path,monkeypatch):
    monkeypatch.setenv('DATABASE_URL',f'sqlite:///{tmp_path}/devices.db')
    with TestClient(app) as client:
        payload={'device_id':'camera','device_name':'Camera','ip_address':'172.18.0.10'}
        enrolled=client.post('/api/devices/register',json=payload)
        assert enrolled.status_code==200
        token=enrolled.json()['token']
        assert client.post('/api/devices/register',json=payload).status_code==409
        assert client.post('/api/devices/heartbeat',json={**payload,'token':'wrong'}).status_code==401
        assert client.post('/api/devices/heartbeat',json={**payload,'token':token}).status_code==200
        assert 'token' not in client.get('/api/devices').json()[0]
        assert client.post('/api/devices/camera/action',json={'action':'BLOCK_IP','ip':'172.18.0.50'}).status_code==409
        with client.websocket_connect(f'/ws/agent/camera?token={token}') as socket:
            response=client.post('/api/devices/camera/action',json={'action':'BLOCK_IP','ip':'172.18.0.50'})
            assert response.status_code==200
            assert socket.receive_json()['payload']['ip']=='172.18.0.50'
        assert len(client.get('/api/devices/camera/history').json()['actions'])==1
        assert client.get('/api/downloads/agent/linux-amd64').status_code==503
        assert '--sandbox=true' in client.get('/install.sh').text
        with client.websocket_connect('/ws/live') as socket:
            assert socket.receive_json()['event_type']=='SNAPSHOT'
