from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

BASE_FEATURE_NAMES = (
    "flow_duration", "Rate", "Header_Length", "Duration", "fin_flag_number",
    "syn_flag_number", "rst_flag_number", "psh_flag_number", "ack_flag_number",
    "ack_count", "syn_count", "fin_count", "rst_count", "TCP", "UDP", "ICMP",
    "AVG", "Std",
)
DERIVED_FEATURE_NAMES = ("bytes_per_sec", "syn_ack_ratio", "hdr_pkt_ratio", "pkt_cv")
FEATURE_NAMES = BASE_FEATURE_NAMES + DERIVED_FEATURE_NAMES
FiniteFloat = float


class FlowWindowPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    src_ip: str = Field(min_length=1, max_length=64)
    dst_ip: str = Field(min_length=1, max_length=64)
    src_mac: str = Field(default="", max_length=32)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    window_id: str | None = Field(default=None, max_length=64)
    packet_count: int = Field(default=100, ge=1)
    capture_mode: str = Field(default="LIVE_INTERFACE", max_length=32)
    src_port: int = Field(default=0, ge=0, le=65535)
    dst_port: int = Field(default=0, ge=0, le=65535)
    dominant_protocol: Literal["TCP", "UDP", "ICMP"] = "TCP"
    flow_duration: FiniteFloat
    Rate: FiniteFloat
    Header_Length: FiniteFloat
    Duration: FiniteFloat
    fin_flag_number: FiniteFloat
    syn_flag_number: FiniteFloat
    rst_flag_number: FiniteFloat
    psh_flag_number: FiniteFloat
    ack_flag_number: FiniteFloat
    ack_count: FiniteFloat
    syn_count: FiniteFloat
    fin_count: FiniteFloat
    rst_count: FiniteFloat
    TCP: FiniteFloat
    UDP: FiniteFloat
    ICMP: FiniteFloat
    AVG: FiniteFloat
    Std: FiniteFloat

    @field_validator(*BASE_FEATURE_NAMES)
    @classmethod
    def validate_finite(cls, value: float) -> float:
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("feature values must be finite")
        return value


class CollectorMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    src_ip: str
    dst_ip: str
    src_mac: str = ""
    dst_mac: str = ""
    src_port: int = Field(default=0, ge=0, le=65535)
    dst_port: int = Field(default=0, ge=0, le=65535)
    dominant_protocol: Literal["TCP", "UDP", "ICMP"] = "TCP"
    device_vendor: str = ""


class Features18Payload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    flow_duration: FiniteFloat
    Rate: FiniteFloat
    Header_Length: FiniteFloat
    Duration: FiniteFloat
    fin_flag_number: FiniteFloat
    syn_flag_number: FiniteFloat
    rst_flag_number: FiniteFloat
    psh_flag_number: FiniteFloat
    ack_flag_number: FiniteFloat
    ack_count: FiniteFloat
    syn_count: FiniteFloat
    fin_count: FiniteFloat
    rst_count: FiniteFloat
    TCP: FiniteFloat
    UDP: FiniteFloat
    ICMP: FiniteFloat
    AVG: FiniteFloat
    Std: FiniteFloat

    @field_validator(*BASE_FEATURE_NAMES)
    @classmethod
    def validate_finite(cls, value: float) -> float:
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("feature values must be finite")
        return value


class CollectorWindow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    window_id: str
    timestamp_end: datetime
    packet_count: int = Field(ge=1)
    metadata: CollectorMetadata
    features_18: Features18Payload

    def to_flow_payload(self, capture_mode: str) -> FlowWindowPayload:
        metadata = self.metadata
        return FlowWindowPayload(
            **self.features_18.model_dump(),
            src_ip=metadata.src_ip, dst_ip=metadata.dst_ip, src_mac=metadata.src_mac,
            timestamp=self.timestamp_end, window_id=self.window_id,
            packet_count=self.packet_count, capture_mode=capture_mode,
            src_port=metadata.src_port, dst_port=metadata.dst_port,
            dominant_protocol=metadata.dominant_protocol,
        )


class IngestBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    collector_id: str
    capture_mode: str = "LIVE_INTERFACE"
    source_ref: str = ""
    windows: list[CollectorWindow] = Field(min_length=1, max_length=100)


class BatchPredictionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    data: list[FlowWindowPayload] = Field(min_length=1, max_length=100)


class AnomalyExplanation(BaseModel):
    feature: str
    value: float
    benign_median: float
    z_iqr: float
    direction: Literal["HIGH", "LOW"]


class PredictionResult(BaseModel):
    window_id: str | None
    timestamp: datetime
    src_ip: str
    dst_ip: str
    predicted_class: str
    confidence_score: float
    is_anomaly: bool
    probabilities: dict[str, float]
    model_used: str
    features_22: dict[str, float]
    top_anomalies: list[AnomalyExplanation] = Field(default_factory=list)


class BatchPredictionResponse(BaseModel):
    predictions: list[PredictionResult]
    processed_windows: int
    benign_count: int
    dos_count: int
    ddos_count: int


def json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        return 0.0
    return value
