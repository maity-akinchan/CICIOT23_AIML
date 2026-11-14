import asyncio
from pathlib import Path
from typing import Literal
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, Field
from app.services.pcap_runner import csv_windows
from app.routers.ingest import _predict
router=APIRouter()
class Control(BaseModel):
    action:Literal['start','stop']
    speed_fps:int=Field(10,ge=1,le=100)

async def run(request,path):
    try:
        for row in csv_windows(path.read_text()):
            await _predict(request,[row])
            request.app.state.replay['rows_streamed']+=1
            await asyncio.sleep(1/request.app.state.replay['speed_fps'])
    finally: request.app.state.replay['is_running']=False

@router.get('/replay/status')
def status(request:Request):return request.app.state.replay

@router.post('/replay/control')
async def control(payload:Control,request:Request):
    task=request.app.state.replay_task
    if task and not task.done():
        task.cancel()
        try: await task
        except asyncio.CancelledError: pass
    if payload.action=='start':
        path=Path(__file__).resolve().parents[3]/'ml/sample_data/test_sample_500.csv'
        if not path.exists():raise HTTPException(409,'Add ml/sample_data/test_sample_500.csv to start replay')
        request.app.state.replay=dict(is_running=True,speed_fps=payload.speed_fps,rows_streamed=0)
        request.app.state.replay_task=asyncio.create_task(run(request,path))
    return request.app.state.replay
