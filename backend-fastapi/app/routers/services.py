from datetime import datetime, timedelta
import hashlib
import secrets
from uuid import uuid4
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from app.models import ServiceCredential
router=APIRouter()
class Issue(BaseModel):
    collector_id:str=Field(pattern=r'^[A-Za-z0-9_-]{1,64}$')
    valid_days:int=Field(30,ge=1,le=365)
@router.post('/services/credentials',status_code=201)
def issue(payload:Issue,request:Request):
    token=secrets.token_urlsafe(48)
    with request.app.state.sessions.begin() as db:
        c=ServiceCredential(id=str(uuid4()),collector_id=payload.collector_id,token_hash=hashlib.sha256(token.encode()).hexdigest(),expires_at=datetime.utcnow()+timedelta(days=payload.valid_days))
        db.add(c);db.flush()
        return dict(id=c.id,collector_id=c.collector_id,token=token,expires_at=c.expires_at.isoformat())
@router.get('/services/credentials')
def listing(request:Request):
    with request.app.state.sessions() as db:
        return [dict(id=c.id,collector_id=c.collector_id,expires_at=c.expires_at,revoked=c.revoked,last_used_at=c.last_used_at) for c in db.scalars(select(ServiceCredential).order_by(ServiceCredential.created_at.desc()))]
@router.delete('/services/credentials/{credential_id}')
def revoke(credential_id:str,request:Request):
    with request.app.state.sessions.begin() as db:
        c=db.get(ServiceCredential,credential_id)
        if c is None:raise HTTPException(404,'Credential not found')
        c.revoked=True
    return {'revoked':True}

@router.post('/services/verify')
def verify(payload:Issue,request:Request):
    expected=getattr(request.state,'collector_id',None)
    if expected is None or payload.collector_id!=expected:raise HTTPException(403,'Use a device-bound service credential for this service ID')
    return {'authorized':True,'collector_id':expected}

class Redeem(BaseModel):
    code:str=Field(min_length=32,max_length=128)

@router.post('/services/enrollments',status_code=201)
def enrollment(payload:Issue,request:Request):
    from app.models import Enrollment
    code=secrets.token_urlsafe(32)
    with request.app.state.sessions.begin() as db:
        db.add(Enrollment(token_hash=hashlib.sha256(code.encode()).hexdigest(),collector_id=payload.collector_id,expires_at=datetime.utcnow()+timedelta(minutes=15)))
    return {'code':code,'collector_id':payload.collector_id,'expires_in_seconds':900}

@router.post('/services/enroll')
def enroll(payload:Redeem,request:Request):
    from sqlalchemy import update
    from app.models import Enrollment
    digest=hashlib.sha256(payload.code.encode()).hexdigest()
    with request.app.state.sessions.begin() as db:
        claimed=db.execute(update(Enrollment).where(Enrollment.token_hash==digest,Enrollment.used==False,Enrollment.expires_at>datetime.utcnow()).values(used=True))
        if claimed.rowcount!=1:raise HTTPException(401,'Setup code expired, already used, or invalid. Generate a new code in Monitoring service.')
        e=db.get(Enrollment,digest)
        token=secrets.token_urlsafe(48)
        db.add(ServiceCredential(id=str(uuid4()),collector_id=e.collector_id,token_hash=hashlib.sha256(token.encode()).hexdigest(),expires_at=datetime.utcnow()+timedelta(days=365)))
        return {'collector_id':e.collector_id,'token':token}
