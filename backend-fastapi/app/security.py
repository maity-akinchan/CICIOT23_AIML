"""Simple login/password authentication and optional service credentials."""
import hashlib
import os
import secrets
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from starlette.responses import JSONResponse
from app.models import UserAccount

router = APIRouter()


class LoginPayload(BaseModel):
    email: str = Field(min_length=3, max_length=128)
    password: str = Field(min_length=4, max_length=128)
    org_name: str | None = Field(default=None, max_length=128)
    mode: str = Field(default='signin')


@router.post('/auth/login')
def login(payload: LoginPayload, request: Request):
    token = request.headers.get('authorization', '').removeprefix('Bearer ')
    if credentials_required() and role(token) != 'operator':
        raise HTTPException(401, 'Enter the operator access token configured on the server')
    email = payload.email.strip().lower()
    pw_hash = hashlib.sha256(payload.password.encode()).hexdigest()
    with request.app.state.sessions.begin() as db:
        user = db.scalar(select(UserAccount).where(UserAccount.email == email))
        if user is None:
            user = UserAccount(
                email=email,
                password_hash=pw_hash,
                org_name=(payload.org_name or 'Sentinel Workspace').strip() or 'Sentinel Workspace',
            )
            db.add(user)
            db.flush()
        elif payload.mode == 'create':
            user.password_hash = pw_hash
            if payload.org_name and payload.org_name.strip():
                user.org_name = payload.org_name.strip()
        else:
            if not secrets.compare_digest(user.password_hash, pw_hash):
                raise HTTPException(401, 'Invalid email or password')
        return {
            'status': 'ok',
            'email': user.email,
            'org_name': user.org_name,
        }


def role(token):
    for name, scope in [('SENTINEL_OPERATOR_TOKEN','operator'),('SENTINEL_COLLECTOR_TOKEN','collector')]:
        expected=os.getenv(name,'')
        if expected and secrets.compare_digest(token.encode(),expected.encode()):return scope
    return None


def credentials_required():
    return os.getenv('SENTINEL_AUTH_DISABLED') != '1' and bool(
        os.getenv('SENTINEL_OPERATOR_TOKEN') or os.getenv('SENTINEL_COLLECTOR_TOKEN')
    )


async def authorize(request, call_next):
    if request.method=='OPTIONS' or (request.method=='GET' and request.url.path in ('/health','/api/v1/install.sh')) or (request.method=='POST' and request.url.path in ('/api/v1/services/enroll','/api/v1/auth/login')):return await call_next(request)
    if not credentials_required():
        return await call_next(request)
    token=request.headers.get('authorization','').removeprefix('Bearer ')
    scope=role(token)
    if not scope and token:
        from datetime import datetime
        from app.models import ServiceCredential
        def check_credential():
            with request.app.state.sessions.begin() as db:
                credential=db.scalar(select(ServiceCredential).where(ServiceCredential.token_hash==hashlib.sha256(token.encode()).hexdigest()))
                if credential and not credential.revoked and credential.expires_at>datetime.utcnow():
                    credential.last_used_at=datetime.utcnow()
                    return credential.collector_id
            return None
        from starlette.concurrency import run_in_threadpool
        collector_id=await run_in_threadpool(check_credential)
        if collector_id is not None:
            scope='collector'
            request.state.collector_id=collector_id
    if not scope:return JSONResponse({'detail':'Valid bearer credential required'},status_code=401)
    live_download=request.method=='GET' and request.url.path in ('/api/v1/downloads/collectors/sentinel-service-linux-amd64','/api/v1/downloads/collectors/sentinel-service-linux-arm64','/api/v1/downloads/collectors/LIVE-SHA256SUMS')
    if scope=='collector' and not live_download and (request.url.path not in ('/api/v1/ingest/windows','/api/v1/ingest/coverage','/api/v1/services/verify') or request.method!='POST'):
        return JSONResponse({'detail':'Operator credential required'},status_code=403)
    return await call_next(request)
