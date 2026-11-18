"""Transactional flow persistence and incident aggregation."""
import json
from collections import defaultdict, deque
from datetime import timedelta, timezone
from uuid import uuid4
from sqlalchemy import select
from app.models import Flow, Device, Incident, Alert
from sentinel_ml.approximation import WARNING


def serialize(row):
    result = {}
    for column in row.__table__.columns:
        if column.name == 'token':
            continue
        value = getattr(row, column.name)
        if column.name.endswith('_json'):
            result[column.name[:-5]] = json.loads(value)
        elif column.name in ('blocked_ips', 'current_dns'):
            result[column.name] = json.loads(value)
        else:
            result[column.name] = value.isoformat() if hasattr(value, 'isoformat') else value
    if isinstance(row, Flow) and row.input_representation == 'packet_approximation':
        result.update(is_anomaly=False, compatibility_warning=WARNING)
    return result

class IncidentManager:
    def __init__(self):
        self.benign_counts = {}
        self.pending = defaultdict(lambda: deque(maxlen=10000))

    def record(self, db, payloads, predictions, fresh_upload=False):
        devices = {}
        flows, alerts, incidents = [], [], []
        for payload, prediction in zip(payloads, predictions):
            p = prediction.model_dump(mode='json')
            existing = db.scalar(select(Flow).where(Flow.window_id == payload.window_id)) if payload.window_id and not fresh_upload else None
            if existing is not None:
                if existing.features_22_json != json.dumps(p['features_22']) or existing.src_ip != payload.src_ip or existing.dst_ip != payload.dst_ip:
                    raise ValueError('Observation ID reused with different content')
                flows.append(serialize(existing))
                continue
            now = payload.timestamp.astimezone(timezone.utc).replace(tzinfo=None)
            flow = Flow(input_representation=prediction.input_representation,capture_session_id=payload.capture_session_id,window_id=payload.window_id or str(uuid4()), timestamp=now,
                capture_mode=payload.capture_mode, src_ip=payload.src_ip, dst_ip=payload.dst_ip,
                src_mac=payload.src_mac, dst_mac=payload.dst_mac, src_port=payload.src_port,
                dst_port=payload.dst_port, protocol=payload.dominant_protocol, packet_count=payload.packet_count,
                predicted_class=prediction.predicted_class, confidence=prediction.confidence_score,
                model_used=prediction.model_used, artifact_sha256=prediction.artifact_sha256, probabilities_json=json.dumps(p['probabilities']),
                top_anomalies_json=json.dumps(p['top_anomalies']), features_22_json=json.dumps(p['features_22']))
            db.add(flow)
            for ip, mac in {(payload.src_ip, payload.src_mac), (payload.dst_ip, payload.dst_mac)}:
                device = devices.get(ip)
                if device is None:
                    device = db.scalar(select(Device).where(Device.ip_address == ip))
                if device is None:
                    device = Device(device_id='observed-' + ip, ip_address=ip, mac_address=mac,
                                    total_flows_seen=0, attack_flows_seen=0)
                    db.add(device)
                devices[ip] = device
                device.total_flows_seen += 1
                device.attack_flows_seen += int(prediction.is_anomaly and prediction.input_representation != 'packet_approximation')
                device.last_seen = now
            if prediction.input_representation == 'packet_approximation':
                if not fresh_upload:
                    db.flush()
                    flows.append(serialize(flow))
                continue
            if prediction.is_anomaly:
                self.benign_counts[payload.dst_ip] = 0
                key = (payload.dst_ip, prediction.predicted_class, payload.capture_session_id)
                queue = self.pending[key]
                queue.append(flow)
                while queue and (now - queue[0].timestamp).total_seconds() > 5:
                    queue.popleft()
                incident = db.scalar(select(Incident).where(Incident.target_ip == key[0],
                    Incident.attack_category == key[1], Incident.capture_session_id == key[2], Incident.status == 'ACTIVE',
                    Incident.last_seen_at >= now - timedelta(seconds=15)).order_by(Incident.id.desc()))
                if incident or len(queue) >= (1 if payload.capture_mode == 'PCAP_UPLOAD' else 3):
                    batch = list(queue)
                    queue.clear()
                    fresh = incident is None
                    if fresh:
                        incident = Incident(capture_session_id=payload.capture_session_id,title=f'{flow.protocol} {key[1]} Flood targeting {key[0]}',
                            attack_category=key[1], severity='CRITICAL' if key[1]=='DDoS' else 'HIGH',
                            target_ip=key[0], source_ips_json='[]', started_at=batch[0].timestamp,
                            last_seen_at=now, affected_flows_count=0, peak_rate_pps=0, model_used=flow.model_used)
                        db.add(incident)
                    before = incident.affected_flows_count
                    incident.affected_flows_count += len(batch)
                    incident.last_seen_at = now
                    incident.source_ips_json = json.dumps(sorted(set(json.loads(incident.source_ips_json)) | {f.src_ip for f in batch}))
                    incident.peak_rate_pps = max(incident.peak_rate_pps, *(json.loads(f.features_22_json)['Rate'] for f in batch))
                    db.flush()
                    if fresh or any(before < n <= incident.affected_flows_count for n in (100,1000,10000,100000)):
                        alert = Alert(incident_id=incident.id, timestamp=now, attack_type=key[1],
                            severity=incident.severity, src_ip=flow.src_ip, dst_ip=key[0], protocol=flow.protocol,
                            confidence=sum(f.confidence for f in batch)/len(batch), top_anomalies_json=flow.top_anomalies_json)
                        db.add(alert)
                        db.flush()
                        alerts.append(serialize(alert))
                    target = db.scalar(select(Device).where(Device.ip_address == key[0]))
                    target.under_attack_status = key[1] + ' Attack'
                    incidents.append(serialize(incident))
            else:
                self.benign_counts[payload.dst_ip] = self.benign_counts.get(payload.dst_ip, 0) + 1
                if self.benign_counts[payload.dst_ip] >= 10:
                    recent = db.scalar(select(Incident).where(Incident.target_ip == payload.dst_ip,
                        Incident.status == 'ACTIVE', Incident.last_seen_at >= now - timedelta(seconds=15)))
                    if recent is None:
                        for target in db.scalars(select(Device).where(Device.ip_address == payload.dst_ip)):
                            target.under_attack_status = 'Normal'
            db.flush()
            flows.append(serialize(flow))
        return flows, alerts, incidents
