from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.schemas import PredictionResult

logger = logging.getLogger(__name__)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass
class Incident:
    src_ip: str
    attack_type: str
    dst_ip: str
    started_at: datetime
    last_seen_timestamp: datetime
    flow_count: int = 1
    status: str = "Active"
    source_ips: set[str] = field(default_factory=set)

    def as_dict(self) -> dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "attack_type": self.attack_type,
            "dst_ip": self.dst_ip,
            "started_at": self.started_at.isoformat(),
            "last_seen_timestamp": self.last_seen_timestamp.isoformat(),
            "flow_count": self.flow_count,
            "status": self.status,
            "source_ips": sorted(self.source_ips),
        }


class IncidentManager:
    """Debounces malicious windows into one active incident per source IP."""

    def __init__(self, resolve_after_seconds: float = 15.0) -> None:
        self.resolve_after_seconds = resolve_after_seconds
        self.active_incidents: dict[str, Incident] = {}
        self.resolved_incidents: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def process(self, predictions: list[PredictionResult]) -> list[dict[str, Any]]:
        new_alerts: list[dict[str, Any]] = []
        async with self._lock:
            for prediction in predictions:
                if prediction.predicted_class not in {"DoS", "DDoS"}:
                    continue
                now = _as_utc(prediction.timestamp)
                incident = self.active_incidents.get(prediction.src_ip)
                if incident is None:
                    incident = Incident(
                        src_ip=prediction.src_ip,
                        attack_type=prediction.predicted_class,
                        dst_ip=prediction.dst_ip,
                        started_at=now,
                        last_seen_timestamp=now,
                        source_ips={prediction.src_ip},
                    )
                    self.active_incidents[prediction.src_ip] = incident
                    new_alerts.append({
                        "src_ip": prediction.src_ip,
                        "dst_ip": prediction.dst_ip,
                        "attack_type": prediction.predicted_class,
                        "incident": incident.as_dict(),
                    })
                else:
                    incident.flow_count += 1
                    incident.last_seen_timestamp = now
                    incident.status = "Active"
        return new_alerts

    async def cleanup_once(self, now: datetime | None = None) -> list[dict[str, Any]]:
        current_time = _as_utc(now or datetime.now(timezone.utc))
        resolved: list[dict[str, Any]] = []
        async with self._lock:
            for src_ip, incident in tuple(self.active_incidents.items()):
                age = (current_time - incident.last_seen_timestamp).total_seconds()
                if age <= self.resolve_after_seconds:
                    continue
                incident.status = "Resolved"
                incident.last_seen_timestamp = current_time
                resolved_record = incident.as_dict()
                self.resolved_incidents.append(resolved_record)
                resolved.append(resolved_record)
                del self.active_incidents[src_ip]
        if resolved:
            logger.info("Resolved %d inactive incidents", len(resolved))
        return resolved

    async def cleanup_loop(self, stop_event: asyncio.Event) -> None:
        try:
            while not stop_event.is_set():
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=10.0)
                except asyncio.TimeoutError:
                    await self.cleanup_once()
        except asyncio.CancelledError:
            raise