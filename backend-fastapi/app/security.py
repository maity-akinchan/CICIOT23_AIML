"""Scoped bearer credentials. Configure secrets externally; no default credentials."""
import os
import secrets
from starlette.responses import JSONResponse

def role(token):
    for name, scope in [('SENTINEL_OPERATOR_TOKEN','operator'),('SENTINEL_COLLECTOR_TOKEN','collector')]:
        expected=os.getenv(name,'')
        if expected and secrets.compare_digest(token.encode(),expected.encode()):return scope
    return None

async def authorize(request, call_next):
    if request.method=='OPTIONS' or (request.method=='GET' and request.url.path in ('/health','/api/v1/install.sh')) or (request.method=='POST' and request.url.path=='/api/v1/services/enroll'):return await call_next(request)
    if os.getenv('SENTINEL_AUTH_DISABLED')=='1':return await call_next(request)
    token=request.headers.get('authorization','').removeprefix('Bearer ')
    scope=role(token)
    if not scope and token:
        import hashlib
        from datetime import datetime
        from sqlalchemy import select
        from app.models import ServiceCredential
        with request.app.state.sessions.begin() as db:
            credential=db.scalar(select(ServiceCredential).where(ServiceCredential.token_hash==hashlib.sha256(token.encode()).hexdigest()))
            if credential and not credential.revoked and credential.expires_at>datetime.utcnow():
                scope='collector'
                request.state.collector_id=credential.collector_id
                credential.last_used_at=datetime.utcnow()
    if not scope:return JSONResponse({'detail':'Valid bearer credential required'},status_code=401)
    live_download=request.method=='GET' and request.url.path in ('/api/v1/downloads/collectors/sentinel-service-linux-amd64','/api/v1/downloads/collectors/sentinel-service-linux-arm64','/api/v1/downloads/collectors/LIVE-SHA256SUMS')
    if scope=='collector' and not live_download and (request.url.path not in ('/api/v1/ingest/windows','/api/v1/services/verify') or request.method!='POST'):
        return JSONResponse({'detail':'Operator credential required'},status_code=403)
    return await call_next(request)
