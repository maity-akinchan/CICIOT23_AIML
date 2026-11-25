"""Persist the last report from each live monitoring service."""
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, func, select
from sqlalchemy.dialects.sqlite import insert

from app.models import Flow, MonitoredCollector


def track_collector(db, collector_id, received_at, coverage=None):
    values = {'collector_id': collector_id, 'last_seen': received_at}
    updates = {'last_seen': func.max(MonitoredCollector.last_seen, received_at)}
    if coverage is not None:
        values['coverage_json'] = json.dumps(coverage)
        updates['coverage_json'] = values['coverage_json']
    db.execute(insert(MonitoredCollector).values(**values).on_conflict_do_update(
        index_elements=[MonitoredCollector.collector_id], set_=updates,
    ))


def collector_health(db):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(hours=24)
    recent = (
        select(Flow.collector_id, func.count().label('windows'),
               func.sum(case((Flow.predicted_class == 'DoS', 1), else_=0)).label('dos'),
               func.sum(case((Flow.predicted_class == 'DDoS', 1), else_=0)).label('ddos'),
               func.max(case((Flow.predicted_class.in_(('DoS', 'DDoS')), Flow.timestamp))).label('last_flagged'))
        .where(Flow.capture_mode == 'LIVE_INTERFACE', Flow.collector_id.is_not(None), Flow.timestamp >= cutoff,
               Flow.timestamp <= now)
        .group_by(Flow.collector_id)
        .subquery()
    )
    query = (select(MonitoredCollector, recent.c.windows, recent.c.dos, recent.c.ddos, recent.c.last_flagged)
             .outerjoin(recent, MonitoredCollector.collector_id == recent.c.collector_id)
             .order_by(MonitoredCollector.last_seen.desc(), MonitoredCollector.collector_id))
    return [
        {
            'collector_id': collector.collector_id,
            'status': 'online' if collector.last_seen >= now - timedelta(seconds=30) else 'offline',
            'last_seen': collector.last_seen.replace(tzinfo=timezone.utc).isoformat(),
            'coverage': json.loads(collector.coverage_json) or None,
            'windows_24h': windows or 0,
            'dos_24h': dos or 0,
            'ddos_24h': ddos or 0,
            'last_flagged_24h': last_flagged.replace(tzinfo=timezone.utc).isoformat() if last_flagged else None,
        }
        for collector, windows, dos, ddos, last_flagged in db.execute(query)
    ]
