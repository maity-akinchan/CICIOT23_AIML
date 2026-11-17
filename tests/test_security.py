from fastapi.testclient import TestClient
from app.main import app

def test_scoped_credentials(monkeypatch,tmp_path):
    monkeypatch.delenv('SENTINEL_AUTH_DISABLED',raising=False)
    monkeypatch.setenv('SENTINEL_OPERATOR_TOKEN','operator-test-secret')
    monkeypatch.setenv('SENTINEL_COLLECTOR_TOKEN','collector-test-secret')
    monkeypatch.setenv('DATABASE_URL',f'sqlite:///{tmp_path}/security.db')
    with TestClient(app) as client:
        assert client.get('/health').status_code==200
        assert client.get('/api/v1/flows').status_code==401
        assert client.get('/api/v1/flows',headers={'Authorization':'Bearer collector-test-secret'}).status_code==403
        assert client.get('/api/v1/flows',headers={'Authorization':'Bearer operator-test-secret'}).status_code==200
        assert client.post('/api/v1/ingest/windows',json={},headers={'Authorization':'Bearer collector-test-secret'}).status_code==422
        assert client.get('/api/v1/downloads/collectors',headers={'Authorization':'Bearer operator-test-secret'}).status_code==200
