from fastapi import APIRouter, HTTPException, Request, Query
from sqlalchemy import select, func, or_, delete
from app.models import Flow, Alert, Incident, Device
from app.services.incident_manager import serialize

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
          min_confidence: float=Query(0,ge=0,le=1)):
    query = select(Flow).where(Flow.confidence>=min_confidence)
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
def reset(request:Request):
    with request.app.state.sessions.begin() as db:
        for model in (Alert,Incident,Flow): db.execute(delete(model))
        for device in db.scalars(select(Device)):
            device.total_flows_seen=0
            device.attack_flows_seen=0
            device.under_attack_status='Normal'
    request.app.state.incidents.pending.clear()
    return {'status':'reset'}

@router.get('/models')
def models(request:Request):
    return {'active_model_id':request.app.state.inference_engine.bundle['model_id'],
            'models':[analytics(key,request) for key in request.app.state.registry]}

@router.get('/models/{model_id}/analytics')
def analytics(model_id:str,request:Request):
    engine=request.app.state.registry.get(model_id)
    if engine is None: raise HTTPException(404,'Model not found')
    b=engine.bundle
    metrics=b.get('metrics',{})
    test=metrics.get('test',metrics)
    scores=test.get('metrics',test)
    return {'model_id':model_id,'model_name':b['model_name'],'is_bootstrap_model':engine.is_bootstrap_model,
            'classes':b['classes'],'test_accuracy':scores.get('accuracy',scores.get('test_accuracy')),
            'test_macro_f1':scores.get('macro_f1',scores.get('test_macro_f1')),
            'confusion_matrix':test.get('confusion_matrix'), 'classification_report':test.get('classification_report'),
            'feature_importances':b.get('feature_importance',metrics.get('feature_importances',{})),
            'training_scope':b.get('training_scope',{})}

from pydantic import BaseModel
from typing import Literal
class ModelSelection(BaseModel):
    model_id: Literal['xgb','brf','svm','lr']

@router.post('/models/select')
def select_model(payload:ModelSelection,request:Request):
    request.app.state.inference_engine=request.app.state.registry[payload.model_id]
    return {'active_model_id':payload.model_id}
