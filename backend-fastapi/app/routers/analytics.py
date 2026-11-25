from fastapi import APIRouter, HTTPException, Request, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, or_, delete
from app.models import Flow, Alert, Incident, Device, CaptureSession
from app.services.incident_manager import serialize
from app.services.inference import InferenceEngine

router = APIRouter()

def summary(db):
    counts = dict(db.execute(select(Flow.predicted_class, func.count()).group_by(Flow.predicted_class)).all())
    total = sum(counts.values())
    return dict(total_flows=total, benign_count=counts.get('Benign',0), dos_count=counts.get('DoS',0),
        ddos_count=counts.get('DDoS',0), attack_percentage=100*(total-counts.get('Benign',0))/max(total,1),
        active_incidents_count=db.scalar(select(func.count()).select_from(Incident).where(Incident.status=='ACTIVE')),
        protocol_distribution=dict(db.execute(select(Flow.protocol,func.count()).group_by(Flow.protocol)).all()),
        recent_alerts=[serialize(x) for x in db.scalars(select(Alert).order_by(Alert.id.desc()).limit(10))])

@router.get('/overview/summary')
def overview(request: Request):
    with request.app.state.sessions() as db:
        return summary(db)

@router.get('/flows')
def flows(request: Request, limit: int=Query(100,ge=1,le=1000), offset: int=Query(0,ge=0),
          predicted_class: str|None=None, protocol: str|None=None, ip_search: str|None=None,
          min_confidence: float=Query(0,ge=0,le=1), capture_session_id: str|None=None):
    query = select(Flow).where(Flow.confidence>=min_confidence)
    if capture_session_id: query=query.where(Flow.capture_session_id==capture_session_id)
    if predicted_class: query=query.where(Flow.predicted_class==predicted_class)
    if protocol: query=query.where(Flow.protocol==protocol)
    if ip_search: query=query.where(or_(Flow.src_ip.contains(ip_search),Flow.dst_ip.contains(ip_search),Flow.src_mac.contains(ip_search)))
    with request.app.state.sessions() as db:
        return {'total':db.scalar(select(func.count()).select_from(query.subquery())),
                'items':[serialize(x) for x in db.scalars(query.order_by(Flow.id.desc()).offset(offset).limit(limit))]}

@router.get('/alerts')
def alerts(request: Request, acknowledged: bool|None=None, severity: str|None=None, limit: int=Query(50,ge=1,le=1000)):
    query=select(Alert)
    if acknowledged is not None: query=query.where(Alert.acknowledged==acknowledged)
    if severity: query=query.where(Alert.severity==severity)
    with request.app.state.sessions() as db:
        return [serialize(x) for x in db.scalars(query.order_by(Alert.id.desc()).limit(limit))]

@router.patch('/alerts/{alert_id}/acknowledge')
async def acknowledge(alert_id:int, request:Request):
    with request.app.state.sessions.begin() as db:
        row=db.get(Alert,alert_id)
        if row is None: raise HTTPException(404,'Alert not found')
        row.acknowledged=True
        result=serialize(row)
    await request.app.state.ws_manager.broadcast({'event_type':'ALERT_UPDATED','alert':result})
    return result

@router.post('/system/reset')
async def reset(request:Request):
    async with request.app.state.ingest_lock:
        with request.app.state.sessions.begin() as db:
            for model in (Alert,Incident,Flow,CaptureSession): db.execute(delete(model))
            for device in db.scalars(select(Device)):
                device.total_flows_seen=0
                device.attack_flows_seen=0
                device.under_attack_status='Normal'
        request.app.state.incidents.pending.clear()
        request.app.state.incidents.benign_counts.clear()
        request.app.state.auto_blocker.windows.clear()
        request.app.state.auto_blocker.sent.clear()
        return {'status':'reset'}


def model_details(model_id: str, active: InferenceEngine):
    details = {'model_id': model_id, 'model_name': model_id, 'available': True,
               'loaded': active.is_loaded and active.model_id == model_id}
    if not details['loaded']:
        return details
    bundle = active.bundle
    metrics = bundle.get('metrics', {})
    test = metrics.get('test', metrics)
    scores = test.get('metrics', test)
    return details | {
        'is_bootstrap_model': active.is_bootstrap_model,
        'artifact_sha256': bundle['artifact_sha256'],
        'classes': bundle['classes'],
        'test_accuracy': scores.get('accuracy', scores.get('test_accuracy')),
        'test_macro_f1': scores.get('macro_f1', scores.get('test_macro_f1')),
        'confusion_matrix': test.get('confusion_matrix'),
        'classification_report': test.get('classification_report'),
        'feature_importances': bundle.get('feature_importance', metrics.get('feature_importances', {})),
        'training_scope': bundle.get('training_scope', {}),
        'packet_compatibility': 'approximate' if active.accepts_packet_approximation else 'csv_only',
        'parity_validation': bundle.get('parity_validation', 'golden_rows_verified'),
    }


@router.get('/models')
def models(request: Request):
    catalog = request.app.state.model_catalog
    active = catalog.active
    model_ids = list(catalog.paths())
    if active.is_loaded and active.model_id not in model_ids:
        model_ids.append(active.model_id)
    return {
        'active_model_id': active.model_id if active.is_loaded else None,
        'models': [model_details(model_id, active) for model_id in model_ids],
    }


@router.get('/models/{model_id}/analytics')
def analytics(model_id: str, request: Request):
    catalog = request.app.state.model_catalog
    active = catalog.active
    paths = catalog.paths()
    if model_id not in paths and model_id != active.model_id:
        model_id = catalog.resolve_id(model_id)
    if model_id not in paths and not (active.is_loaded and model_id == active.model_id):
        raise HTTPException(404, 'Model not found')
    return model_details(model_id, active)


class ModelSelection(BaseModel):
    model_id: str = Field(min_length=1, max_length=255)


@router.post('/models/select')
async def select_model(payload: ModelSelection, request: Request):
    engine = await request.app.state.model_catalog.select(payload.model_id)
    return {'active_model_id': engine.model_id}
