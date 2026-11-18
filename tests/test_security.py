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


def test_simple_password_login_and_tokenless_service_access(monkeypatch, tmp_path):
    monkeypatch.delenv('SENTINEL_AUTH_DISABLED', raising=False)
    monkeypatch.delenv('SENTINEL_OPERATOR_TOKEN', raising=False)
    monkeypatch.delenv('SENTINEL_COLLECTOR_TOKEN', raising=False)
    monkeypatch.setenv('DATABASE_URL', f'sqlite:///{tmp_path}/login.db')
    with TestClient(app) as client:
        # Anyone can access endpoints and run the collector service without an operator token
        assert client.get('/api/v1/flows').status_code == 200
        # Simple login/password registration and sign-in
        r1 = client.post('/api/v1/auth/login', json={'email': 'analyst@sentinel.local', 'password': 'secretpassword', 'org_name': 'SOC Lab', 'mode': 'create'})
        assert r1.status_code == 200
        assert r1.json()['email'] == 'analyst@sentinel.local'
        # Sign in with correct password
        r2 = client.post('/api/v1/auth/login', json={'email': 'analyst@sentinel.local', 'password': 'secretpassword', 'mode': 'signin'})
        assert r2.status_code == 200
        # Sign in with wrong password fails with 401
        r3 = client.post('/api/v1/auth/login', json={'email': 'analyst@sentinel.local', 'password': 'wrongpassword', 'mode': 'signin'})
        assert r3.status_code == 401
