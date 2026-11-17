from pathlib import Path
from fastapi import APIRouter,HTTPException
from fastapi.responses import FileResponse
router=APIRouter()
ROOT=Path(__file__).resolve().parents[3]/'dist/collectors'
@router.get('/downloads/collectors')
def listing():
    return {'files':[p.name for p in ROOT.glob('*') if p.is_file()], 'capability':'Linux monitoring service (libpcap runtime required)' }
@router.get('/downloads/collectors/{name}')
def download(name:str):
    allowed={'SHA256SUMS','LIVE-SHA256SUMS','sentinel-service-linux-amd64','sentinel-service-linux-arm64'}|{f'collector-{os}-{arch}'+('.exe' if os=='windows' else '') for os in ('linux','darwin','windows') for arch in ('amd64','arm64')}
    if name not in allowed or not (ROOT/name).is_file():raise HTTPException(404,'Build artifact unavailable')
    return FileResponse(ROOT/name,filename=name)
