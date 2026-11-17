import io
from uuid import uuid4
from fastapi import APIRouter,UploadFile,Request,HTTPException
from starlette.concurrency import run_in_threadpool
from app.services.pcap_runner import pcap_windows
from app.routers.ingest import _response
router=APIRouter()

@router.post('/pcap/upload')
async def upload(request:Request,file:UploadFile):
    engine=request.app.state.inference_engine
    if not engine.is_loaded:raise HTTPException(503,engine.error)
    try:data=await file.read(32*1024*1024+1)
    finally:await file.close()
    if len(data)>32*1024*1024:raise HTTPException(413,'Maximum upload size is 32 MiB')
    if not (file.filename or '').lower().endswith('.pcap'):raise HTTPException(415,'Only classic Ethernet PCAP is supported by this contract')
    session=str(uuid4())
    def analyze():
        windows=list(pcap_windows(io.BytesIO(data)))
        if len(windows)>10000:raise ValueError('Upload exceeds 10,000 windows')
        for window in windows:window.capture_session_id=session
        predictions=engine.predict_batch(windows) if windows else []
        with request.app.state.sessions.begin() as db:
            request.app.state.incidents.record(db,windows,predictions)
        result=_response(predictions)
        return {k:getattr(result,k) for k in ('processed_windows','benign_count','dos_count','ddos_count')} | {'capture_session_id':session,'artifact_sha256':engine.bundle['artifact_sha256']}
    async with request.app.state.ingest_lock:
        try:return await run_in_threadpool(analyze)
        except ValueError as exc:raise HTTPException(422,str(exc)) from exc
