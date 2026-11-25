import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from app.main import app

def test_authenticated_websocket_receives_updates(monkeypatch,tmp_path):
    monkeypatch.delenv('SENTINEL_AUTH_DISABLED',raising=False)
    monkeypatch.setenv('SENTINEL_OPERATOR_TOKEN','websocket-test-token')
    monkeypatch.setenv('DATABASE_URL',f'sqlite:///{tmp_path}/ws.db')
    with TestClient(app) as client:
        profile = {'email': 'test@sentinel.local', 'password': 'test-password', 'mode': 'create'}
        assert client.get('/health').json()['operator_auth_required'] is True
        assert client.post('/api/v1/auth/login', json=profile).status_code == 401
        assert client.post('/api/v1/auth/login', json=profile, headers={
            'Authorization': 'Bearer websocket-test-token',
        }).status_code == 200
        with pytest.raises(WebSocketDisconnect) as rejected:
            with client.websocket_connect('/ws/live'):
                pass
        assert rejected.value.code == 1008
        with client.websocket_connect('/ws/live',subprotocols=['sentinel.websocket-test-token']) as ws:
            assert ws.accepted_subprotocol=='sentinel.websocket-test-token'
            assert ws.receive_json()['event_type']=='SNAPSHOT'
            response=client.post('/api/v1/ingest/windows',headers={'Authorization':'Bearer websocket-test-token'},json={})
            assert response.status_code==422
