import json
import secrets
from datetime import datetime, timedelta
from typing import Literal
from uuid import uuid4
from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field, IPvAnyAddress
from sqlalchemy import select
from app.models import Device, DeviceAction, Incident
from app.services.collector_health import collector_health
from app.services.incident_manager import serialize
router=APIRouter()
connections={}

class Registration(BaseModel):
    device_id:str=Field(pattern=r'^[a-zA-Z0-9_-]{1,64}$')
    device_name:str=Field(min_length=1,max_length=128)
    ip_address:IPvAnyAddress='0.0.0.0'
    mac_address:str=''

class Heartbeat(Registration):
    token:str
    uptime_seconds:int=Field(0,ge=0)
    internet_blocked:bool=False
    auto_block_enabled:bool=True
    current_dns:list[IPvAnyAddress]=Field(default_factory=lambda:['1.1.1.1'])
    blocked_ips:list[IPvAnyAddress]=Field(default_factory=list)

class Action(BaseModel):
    action:Literal['BLOCK_IP','UNBLOCK_IP','SET_DNS','BLOCK_ALL_INTERNET','RESTORE_INTERNET','AUTO_BLOCK']
    ip:IPvAnyAddress|None=None
    enabled:bool|None=None
    reason:str=Field('Requested by operator',max_length=256)

def find(db,device_id):
    d=db.scalar(select(Device).where(Device.device_id==device_id))
    if d is None: raise HTTPException(404,'Device not found')
    return d

@router.post('/api/devices/register')
def register(payload:Registration,request:Request):
    with request.app.state.sessions.begin() as db:
        if db.scalar(select(Device).where(Device.device_id==payload.device_id)):
            raise HTTPException(409,'Device ID already registered')
        d=Device(**payload.model_dump(mode='json'),token=secrets.token_urlsafe(32))
        db.add(d);db.flush()
        return {**serialize(d),'token':d.token}

@router.post('/api/devices/heartbeat')
def heartbeat(payload:Heartbeat,request:Request):
    with request.app.state.sessions.begin() as db:
        d=find(db,payload.device_id)
        if not d.token or not secrets.compare_digest(d.token,payload.token): raise HTTPException(401,'Invalid device token')
        for key in ('device_name','mac_address','uptime_seconds','internet_blocked'):
            setattr(d,key,getattr(payload,key))
        d.ip_address=str(payload.ip_address)
        d.current_dns=json.dumps([str(x) for x in payload.current_dns])
        d.blocked_ips=json.dumps([str(x) for x in payload.blocked_ips])
        d.last_seen=datetime.utcnow();d.status='ONLINE'
        return serialize(d)

@router.get('/api/devices')
@router.get('/api/v1/devices')
def devices(request:Request):
    with request.app.state.sessions() as db:
        results=[]
        for d in db.scalars(select(Device).order_by(Device.attack_flows_seen.desc())):
            result=serialize(d)
            if d.last_seen<datetime.utcnow()-timedelta(seconds=15): result['status']='OFFLINE'
            results.append(result)
        return results

@router.get('/api/devices/{device_id}/history')
def history(device_id:str,request:Request):
    with request.app.state.sessions() as db:
        d=find(db,device_id)
        return {'actions':[serialize(x) for x in db.scalars(select(DeviceAction).where(DeviceAction.device_id==device_id).order_by(DeviceAction.id.desc()))],
                'incidents':[serialize(x) for x in db.scalars(select(Incident).where(Incident.target_ip==d.ip_address))]}

@router.get('/api/v1/monitoring/devices')
def monitored_devices(request: Request):
    with request.app.state.sessions() as db:
        return collector_health(db)

@router.post('/api/devices/{device_id}/action')
async def action(device_id:str,payload:Action,request:Request):
    raise HTTPException(403, 'Device actions are disabled: observe-only project mode')

@router.websocket('/ws/agent/{device_id}')
async def agent(socket:WebSocket,device_id:str,token:str=''):
    with socket.app.state.sessions() as db:
        d=db.scalar(select(Device).where(Device.device_id==device_id))
        valid=d is not None and d.token and secrets.compare_digest(d.token,token)
    if not valid:
        await socket.close(code=1008);return
    await socket.accept()
    connections[device_id]=socket
    try:
        while True:
            ack=await socket.receive_json()
            await socket.app.state.ws_manager.broadcast({'event_type':'DEVICE_ACK','device_id':device_id,'acknowledgement':ack})
    except WebSocketDisconnect:
        if connections.get(device_id) is socket: connections.pop(device_id,None)

from pathlib import Path
from fastapi.responses import FileResponse, PlainTextResponse

@router.get('/api/downloads/agent/{arch}')
def download(arch:Literal['linux-amd64','linux-arm64']):
    path=Path(__file__).resolve().parents[3]/'collector-go/bin'/f'collector-{arch}'
    if not path.is_file(): raise HTTPException(503,f'Build collector-go/bin/collector-{arch} before downloading')
    return FileResponse(path,filename=f'collector-{arch}',media_type='application/octet-stream')

@router.get('/install.sh',response_class=PlainTextResponse)
def installer(request:Request):
    import shlex
    base=shlex.quote(str(request.base_url).rstrip('/'))
    return '''#!/bin/sh
set -eu
name=''
token=''
for arg in "$@"; do
 case "$arg" in
 --name=*) name=${arg#*=} ;;
 --token=*) token=${arg#*=} ;;
 *) exit 2 ;;
 esac
done
[ -n "$name" ] && [ -n "$token" ] || exit 2
case "$(uname -m)" in
 x86_64) arch=linux-amd64 ;;
 aarch64|arm64) arch=linux-arm64 ;;
 *) exit 2 ;;
esac
base='''+base+'''
curl -fSL "$base/api/downloads/agent/$arch" -o ./sentinel-collector
chmod 700 ./sentinel-collector
exec ./sentinel-collector --mode live --iface eth0 --server-url "$base" --device-id "$name" --device-name "$name" --token "$token" --sandbox=true
'''
