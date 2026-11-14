import io
from fastapi import APIRouter, UploadFile, Request, HTTPException
from app.services.pcap_runner import csv_windows,pcap_windows
from app.routers.ingest import _predict
router=APIRouter()

@router.post('/pcap/upload')
async def upload(request:Request,file:UploadFile):
    data=await file.read(32*1024*1024+1)
    if len(data)>32*1024*1024: raise HTTPException(413,'Maximum upload size is 32 MiB')
    suffix=(file.filename or '').rsplit('.',1)[-1].lower()
    if suffix not in ('csv','pcap','pcapng'): raise HTTPException(415,'Upload a CSV, PCAP or PCAPNG file')
    counts=dict(processed_windows=0,benign_count=0,dos_count=0,ddos_count=0)
    try:
        windows=csv_windows(data.decode('utf-8-sig')) if suffix=='csv' else pcap_windows(io.BytesIO(data))
        batch=[]
        for window in windows:
            batch.append(window)
            if len(batch)==100:
                result=await _predict(request,batch)
                for key in counts:counts[key]+=getattr(result,key)
                batch=[]
        if batch:
            result=await _predict(request,batch)
            for key in counts:counts[key]+=getattr(result,key)
    except (ValueError,UnicodeError) as exc: raise HTTPException(422,str(exc)) from exc
    return counts
