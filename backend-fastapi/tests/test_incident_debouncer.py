from datetime import datetime,timedelta,timezone
from fastapi.testclient import TestClient
from app.main import app
from app.schemas import FlowWindowPayload,BASE_FEATURE_NAMES,PredictionResult
from app.services.incident_manager import IncidentManager
from app.models import Incident,Alert,Flow
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


def test_unverified_packet_predictions_create_one_labeled_alert(tmp_path, monkeypatch):
    monkeypatch.setenv('DATABASE_URL', f'sqlite:///{tmp_path}/packet.db')
    with TestClient(app):
        manager = IncidentManager()
        payload = FlowWindowPayload(
            **dict.fromkeys(BASE_FEATURE_NAMES, 1), src_ip='192.0.2.1', dst_ip='192.0.2.2',
            input_representation='packet_approximation', capture_mode='PCAP_UPLOAD',
        )
        prediction = PredictionResult(
            window_id='fixture', timestamp=payload.timestamp, src_ip=payload.src_ip, dst_ip=payload.dst_ip,
            predicted_class='DDoS', confidence_score=.999, is_anomaly=False,
            probabilities={'DoS':.001, 'Benign':0, 'DDoS':.999}, model_used='fixture',
            input_representation='packet_approximation', features_22={'Rate':10000},
        )
        with app.state.sessions.begin() as db:
            flows, alerts, incidents = manager.record(db, [payload], [prediction])
            assert flows[0]['predicted_class'] == 'DDoS'
            assert flows[0]['is_anomaly'] is False
            assert alerts[0]['input_representation'] == 'packet_approximation'
            assert alerts[0]['capture_mode'] == 'PCAP_UPLOAD'
            assert len(incidents) == 1
            _, repeated_alerts, incidents = manager.record(db, [payload], [prediction])
            assert not repeated_alerts
            assert incidents[0]['affected_flows_count'] == 2
        with app.state.sessions() as db:
            assert db.scalar(select(func.count()).select_from(Flow)) == 2
            assert db.scalar(select(func.count()).select_from(Incident)) == 1
