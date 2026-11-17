from fastapi import APIRouter,HTTPException
router=APIRouter()
@router.get('/replay/status')
def status():return {'is_running':False,'available':False,'reason':'Unmanifested feature-row replay is unsupported'}
@router.post('/replay/control')
def control():raise HTTPException(409,'Use labeled capture sessions; unmanifested replay is unsupported')
