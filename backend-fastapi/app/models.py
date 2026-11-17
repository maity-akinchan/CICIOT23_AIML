from datetime import datetime
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import mapped_column
from app.database import Base

class Device(Base):
    __tablename__ = 'devices'
    id = mapped_column(Integer, primary_key=True)
    device_id = mapped_column(String(64), unique=True, index=True)
    device_name = mapped_column(String(128), default='Observed device')
    token = mapped_column(String(128), nullable=True)
    ip_address = mapped_column(String(64), index=True)
    mac_address = mapped_column(String(32), default='')
    hostname = mapped_column(String(128), default='')
    vendor = mapped_column(String(128), default='Generic IoT Endpoint')
    status = mapped_column(String(32), default='OFFLINE')
    uptime_seconds = mapped_column(Integer, default=0)
    under_attack_status = mapped_column(String(32), default='Normal')
    auto_block_enabled = mapped_column(Boolean, default=False)
    internet_blocked = mapped_column(Boolean, default=False)
    current_dns = mapped_column(Text, default='["1.1.1.1"]')
    blocked_ips = mapped_column(Text, default='[]')
    total_flows_seen = mapped_column(Integer, default=0)
    attack_flows_seen = mapped_column(Integer, default=0)
    last_seen = mapped_column(DateTime, default=datetime.utcnow)

class Flow(Base):
    __tablename__ = 'flow_logs'
    input_representation = mapped_column(String(64), default='dataset_features')
    capture_session_id = mapped_column(String(64), default='', index=True)
    id = mapped_column(Integer, primary_key=True)
    window_id = mapped_column(String(128), unique=True, index=True)
    timestamp = mapped_column(DateTime, index=True)
    capture_mode = mapped_column(String(32))
    src_ip = mapped_column(String(64), index=True)
    dst_ip = mapped_column(String(64), index=True)
    src_mac = mapped_column(String(32), default='')
    dst_mac = mapped_column(String(32), default='')
    src_port = mapped_column(Integer)
    dst_port = mapped_column(Integer)
    protocol = mapped_column(String(16), index=True)
    packet_count = mapped_column(Integer)
    predicted_class = mapped_column(String(16), index=True)
    confidence = mapped_column(Float, index=True)
    probabilities_json = mapped_column(Text)
    model_used = mapped_column(String(64))
    artifact_sha256 = mapped_column(String(64), default="")
    top_anomalies_json = mapped_column(Text)
    features_22_json = mapped_column(Text)

class Incident(Base):
    __tablename__ = 'incidents'
    capture_session_id = mapped_column(String(64), default='', index=True)
    id = mapped_column(Integer, primary_key=True)
    title = mapped_column(String(256))
    attack_category = mapped_column(String(16))
    severity = mapped_column(String(16))
    target_ip = mapped_column(String(64), index=True)
    source_ips_json = mapped_column(Text)
    started_at = mapped_column(DateTime)
    last_seen_at = mapped_column(DateTime)
    resolved_at = mapped_column(DateTime, nullable=True)
    status = mapped_column(String(32), default='ACTIVE', index=True)
    affected_flows_count = mapped_column(Integer, default=0)
    peak_rate_pps = mapped_column(Float, default=0)
    model_used = mapped_column(String(64))

class Alert(Base):
    __tablename__ = 'security_alerts'
    id = mapped_column(Integer, primary_key=True)
    incident_id = mapped_column(ForeignKey('incidents.id'), index=True)
    timestamp = mapped_column(DateTime, index=True)
    attack_type = mapped_column(String(16))
    severity = mapped_column(String(16))
    src_ip = mapped_column(String(64))
    dst_ip = mapped_column(String(64))
    protocol = mapped_column(String(16))
    confidence = mapped_column(Float)
    top_anomalies_json = mapped_column(Text)
    acknowledged = mapped_column(Boolean, default=False, index=True)

class DeviceAction(Base):
    __tablename__ = 'device_actions'
    id = mapped_column(Integer, primary_key=True)
    timestamp = mapped_column(DateTime, default=datetime.utcnow, index=True)
    device_id = mapped_column(String(64), index=True)
    triggered_by = mapped_column(String(32))
    action_type = mapped_column(String(32))
    target_value = mapped_column(String(128))
    reason = mapped_column(String(256))
