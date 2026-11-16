import csv
import io
import json
from datetime import datetime
from typing import Literal
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from app.models import Incident, Alert, Device
from app.services.incident_manager import serialize
router=APIRouter()

@router.get('/incidents')
def incidents(request:Request,status:Literal['ACTIVE','RESOLVED']|None=None):
    query=select(Incident)
    if status: query=query.where(Incident.status==status)
    with request.app.state.sessions() as db:
        return [serialize(x) for x in db.scalars(query.order_by(Incident.last_seen_at.desc()))]

@router.patch('/incidents/{incident_id}/resolve')
async def resolve(incident_id:int,request:Request):
    with request.app.state.sessions.begin() as db:
        row=db.get(Incident,incident_id)
        if row is None: raise HTTPException(404,'Incident not found')
        row.status='RESOLVED'
        row.resolved_at=datetime.utcnow()
        db.flush()
        active=db.scalar(select(Incident).where(Incident.target_ip==row.target_ip,Incident.status=='ACTIVE'))
        if active is None:
            for d in db.scalars(select(Device).where(Device.ip_address==row.target_ip)): d.under_attack_status='Normal'
        result=serialize(row)
    await request.app.state.ws_manager.broadcast({'event_type':'INCIDENT_UPDATED','incident':result})
    return result

@router.get('/incidents/{incident_id}/export')
def export(incident_id:int,request:Request,format:Literal['json','csv']='json'):
    with request.app.state.sessions() as db:
        row=db.get(Incident,incident_id)
        if row is None: raise HTTPException(404,'Incident not found')
        incident=serialize(row)
        alerts=[serialize(x) for x in db.scalars(select(Alert).where(Alert.incident_id==incident_id))]
    if format=='json': content=json.dumps({'incident':incident,'alerts':alerts}); media='application/json'
    else:
        output=io.StringIO()
        fields=list(incident)+['alerts']
        writer=csv.DictWriter(output,fieldnames=fields)
        writer.writeheader();writer.writerow({**incident,'alerts':json.dumps(alerts)})
        content=output.getvalue();media='text/csv'
    return Response(content,media_type=media,headers={'Content-Disposition':f'attachment; filename="incident-{incident_id}.{format}"'})
