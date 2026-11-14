from datetime import datetime,timedelta,timezone
from fastapi.testclient import TestClient
from app.main import app
from app.schemas import FlowWindowPayload,BASE_FEATURE_NAMES,PredictionResult
from app.services.incident_manager import IncidentManager
from app.models import Incident,Alert
from sqlalchemy import select,func

def test_three_windows_create_one_incident(tmp_path,monkeypatch):
    monkeypatch.setenv('DATABASE_URL',f'sqlite:///{tmp_path}/incidents.db')
    with TestClient(app):
        manager=IncidentManager()
        for i in range(12):
            payload=FlowWindowPayload(**dict.fromkeys(BASE_FEATURE_NAMES,1),src_ip='172.18.0.50',dst_ip='172.18.0.10',timestamp=datetime.now(timezone.utc)+timedelta(milliseconds=i))
            prediction=PredictionResult(window_id=str(i),timestamp=payload.timestamp,src_ip=payload.src_ip,dst_ip=payload.dst_ip,predicted_class='DoS',confidence_score=.95,is_anomaly=True,probabilities={'DoS':.95,'Benign':.05,'DDoS':0},model_used='fixture',features_22={'Rate':10000})
            with app.state.sessions.begin() as db: manager.record(db,[payload],[prediction])
        with app.state.sessions() as db:
            assert db.scalar(select(func.count()).select_from(Alert))==1
            incident=db.scalar(select(Incident))
            assert incident.affected_flows_count==12
            assert incident.peak_rate_pps==10000
