"""Scoped bearer credentials. Configure secrets externally; no default credentials."""
import os
import secrets
from starlette.responses import JSONResponse

def role(token):
    for name, scope in [('SENTINEL_OPERATOR_TOKEN','operator'),('SENTINEL_COLLECTOR_TOKEN','collector')]:
        expected=os.getenv(name,'')
        if expected and secrets.compare_digest(token,expected):return scope
    return None

async def authorize(request, call_next):
    if request.method=='OPTIONS' or request.url.path=='/health':return await call_next(request)
    if os.getenv('SENTINEL_AUTH_DISABLED')=='1':return await call_next(request)
    scope=role(request.headers.get('authorization','').removeprefix('Bearer '))
    if not scope:return JSONResponse({'detail':'Valid bearer credential required'},status_code=401)
    if scope=='collector' and request.url.path!='/api/v1/ingest/windows':
        return JSONResponse({'detail':'Operator credential required'},status_code=403)
    return await call_next(request)
