import hashlib
import shutil
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from fastapi.testclient import TestClient

from app.main import app
from sentinel_ml.approximation import CONTRACT_HASH, CONTRACT_ID
from sentinel_ml.contract import BASE
from sentinel_ml.csv_contract import matrix
from test_pipeline import capture

ARTIFACTS = Path(__file__).resolve().parents[1] / 'ml' / 'artifacts'
XGBOOST = 'ciciot_22f_xgb'
SVM = 'ciciot23_calibrated_svm_22f'
LOGISTIC = 'ciciot23_logistic_regression_22f'


def test_switch_uploaded_models_for_csv_and_pcap(tmp_path, monkeypatch):
    model_dir = tmp_path / 'models'
    model_dir.mkdir()
    for name in (XGBOOST, SVM, LOGISTIC):
        shutil.copyfile(ARTIFACTS / f'{name}.joblib', model_dir / f'{name}.joblib')
    monkeypatch.setenv('MODEL_DIR', str(model_dir))
    monkeypatch.setenv('DATABASE_URL', f'sqlite:///{tmp_path}/app.db')
    capture_path = tmp_path / 'capture.pcap'
    capture(capture_path)
    base = pd.DataFrame([{**dict.fromkeys(BASE, 0.0), 'Rate': 50.0, 'AVG': 70.0}], columns=BASE)
    csv = base.to_csv(index=False).encode()

    with TestClient(app) as client:
        catalog = client.get('/api/v1/models').json()
        assert catalog['active_model_id'] == XGBOOST
        assert {model['model_id'] for model in catalog['models']} == {XGBOOST, SVM, LOGISTIC}
        assert {model['model_id'] for model in catalog['models'] if model['loaded']} == {XGBOOST}

        extra = 'additional_model'
        joblib.dump(joblib.load(model_dir / f'{LOGISTIC}.joblib')['model'], model_dir / f'{extra}.joblib')
        (model_dir / 'broken.joblib').write_bytes(b'broken')
        assert extra in {m['model_name'] for m in client.get('/api/v1/models').json()['models']}

        for name in (SVM, LOGISTIC, extra):
            assert client.post('/api/v1/models/select', json={'model_id': name}).json() == {
                'active_model_id': name,
            }
            health = client.get('/health').json()
            assert health['active_model_id'] == name
            assert health['allowed_contracts'] == [CONTRACT_ID]
            path = model_dir / f'{name}.joblib'
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            original = joblib.load(path)
            estimator = original['model'] if isinstance(original, dict) else original
            expected = estimator.predict_proba(matrix(base))[0]

            result = client.post('/api/v1/csv/upload', files={'file': ('features.csv', csv)})
            assert result.status_code == 200, result.text
            assert result.json()['model_used'] == name
            assert result.json()['artifact_sha256'] == digest
            probabilities = result.json()['predictions'][0]['probabilities']
            assert np.allclose([probabilities[label] for label in estimator.classes_], expected)

            result = client.post('/api/v1/pcap/upload', files={'file': ('capture.pcap', capture_path.read_bytes())})
            assert result.status_code == 200, result.text
            assert result.json()['model_used'] == name
            flows = client.get('/api/v1/flows', params={'capture_session_id': result.json()['capture_session_id']})
            assert flows.json()['items'][0]['model_used'] == name

            response = client.post('/api/v1/predict/batch', json={
                'feature_contract_id': CONTRACT_ID, 'contract_hash': CONTRACT_HASH,
                'data': [{
                    **base.iloc[0].to_dict(), 'window_id': 'packet-window',
                    'src_ip': '192.0.2.10', 'dst_ip': '192.0.2.20',
                    'input_representation': 'packet_approximation',
                }],
            })
            assert response.status_code == 200, response.text
            prediction = response.json()['predictions'][0]
            assert prediction['input_representation'] == 'packet_approximation'
            assert prediction['model_used'] == name
            assert prediction['is_anomaly'] is False

        assert client.post('/api/v1/models/select', json={'model_id': 'missing'}).status_code == 404
        assert client.post('/api/v1/models/select', json={'model_id': 'broken'}).status_code == 422
        assert client.get('/health').json()['active_model_id'] == extra
