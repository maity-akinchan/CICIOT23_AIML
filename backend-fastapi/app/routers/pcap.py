import io
from uuid import uuid4
from fastapi import APIRouter,UploadFile,Request,HTTPException,Query
from starlette.concurrency import run_in_threadpool
from app.services.pcap_runner import pcap_windows
from app.routers.ingest import _response
router=APIRouter()

@router.post('/pcap/upload')
async def upload(request:Request,file:UploadFile):
    engine=request.app.state.inference_engine
    if engine.is_loaded:
        if not engine.bundle.get("is_legacy"): raise HTTPException(422,"PCAP extraction has not been verified against the Kaggle CSV measurements; use CSV upload")
    if not engine.is_loaded:raise HTTPException(503,engine.error)
    if not (file.filename or '').lower().endswith('.pcap'):
        await file.close()
        raise HTTPException(415,'Choose a classic .pcap file; PCAPNG is not supported')
    session=str(uuid4())
    def analyze():
        # UploadFile is disk-spooled by Starlette. Never read the entire capture.
        import hashlib
        from itertools import islice
        from app.models import CaptureSession
        from app.services.incident_manager import IncidentManager
        digest=hashlib.sha256();size=0
        file.file.seek(0)
        while chunk:=file.file.read(1024*1024):digest.update(chunk);size+=len(chunk)
        file.file.seek(0)
        # Isolate transient incident state so a malformed file cannot pollute live state.
        incidents=IncidentManager()
        counts=dict(processed_windows=0,benign_count=0,dos_count=0,ddos_count=0)
        diagnostics={}
        windows=iter(pcap_windows(file.file, diagnostics))
        with request.app.state.sessions.begin() as db:
            while batch:=list(islice(windows,256)):
                for window in batch:window.capture_session_id=session
                predictions=engine.predict_batch(batch)
                result=_response(predictions)
                for key in counts:counts[key]+=getattr(result,key)
                incidents.record(db,batch,predictions)
                db.flush();db.expunge_all()
                incidents.pending.clear();incidents.benign_counts.clear()
            db.add(CaptureSession(id=session,filename=(file.filename or 'capture.pcap')[:255],
                file_sha256=digest.hexdigest(),size_bytes=size,
                artifact_sha256=engine.bundle['artifact_sha256'],**counts))
        return counts|{'coverage':diagnostics,'capture_session_id':session,'artifact_sha256':engine.bundle['artifact_sha256']}
    try:
        async with request.app.state.ingest_lock:
            return await run_in_threadpool(analyze)
    except (ValueError,EOFError) as exc:raise HTTPException(422,str(exc)) from exc
    finally:await file.close()


@router.post('/csv/upload')
async def csv_upload(request:Request,file:UploadFile):
    from sentinel_ml.csv_contract import CONTRACT_ID,matrix
    from sentinel_ml.artifacts import predict
    from sentinel_ml.contract import BASE
    import pandas as pd
    engine=request.app.state.inference_engine
    if not engine.is_loaded:raise HTTPException(503,engine.error)
    if engine.bundle['contract_id'] not in (CONTRACT_ID,'ciciot23-legacy22-v1'):raise HTTPException(422,'Select a Kaggle CSV-trained model')
    try:data=await file.read(32*1024*1024+1)
    finally:await file.close()
    if len(data)>32*1024*1024:raise HTTPException(413,'Maximum upload size is 32 MiB')
    def analyze():
        frame=pd.read_csv(io.BytesIO(data))
        if len(frame)>10000:raise ValueError('Maximum 10,000 rows per request')
        if not set(BASE)<=set(frame.columns):raise ValueError('Missing original base features')
        # CSV serialization is decoded by pandas, then strictly checked by the shared builder.
        x,scores=predict(engine.bundle,frame.loc[:,BASE])
        return dict(processed_rows=len(x),feature_contract_id=CONTRACT_ID,artifact_sha256=engine.bundle['artifact_sha256'],
            predictions=[dict(row_index=i,predicted_class=engine.bundle['classes'][int(score.argmax())],
                probabilities=dict(zip(engine.bundle['classes'],map(float,score))),features_22=x.iloc[i].astype(float).to_dict())
                for i,score in enumerate(scores)])
    try:return await run_in_threadpool(analyze)
    except (ValueError,UnicodeError) as exc:raise HTTPException(422,str(exc)) from exc

@router.get('/features/export')
def export_features(request:Request,capture_session_id:str):
    import csv
    from fastapi.responses import Response
    from sqlalchemy import select
    from app.models import Flow
    from sentinel_ml.contract import FEATURES
    import json
    output=io.StringIO();writer=csv.DictWriter(output,fieldnames=list(FEATURES));writer.writeheader()
    with request.app.state.sessions() as db:
        for flow in db.scalars(select(Flow).where(Flow.capture_session_id==capture_session_id).order_by(Flow.id)):
            writer.writerow(json.loads(flow.features_22_json))
    return Response(output.getvalue(),media_type='text/csv',headers={'Content-Disposition':'attachment; filename="model-inputs-22f.csv"',
        'X-Measurement-Compatibility':'packet-approximation-unverified'})

@router.get('/captures')
def captures(request:Request,limit:int=Query(25,ge=1,le=100),offset:int=Query(0,ge=0)):
    from sqlalchemy import select,func
    from app.models import CaptureSession
    from app.services.incident_manager import serialize
    with request.app.state.sessions() as db:
        return {'total':db.scalar(select(func.count()).select_from(CaptureSession)),
                'items':[serialize(c) for c in db.scalars(select(CaptureSession).order_by(CaptureSession.uploaded_at.desc()).offset(offset).limit(limit))]}
