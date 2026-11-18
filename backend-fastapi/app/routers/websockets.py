from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.services.ws_manager import manager

router = APIRouter()


@router.websocket("/ws/live")
async def live_socket(websocket: WebSocket) -> None:
    protocols=websocket.headers.get('sec-websocket-protocol','').split(',')
    token=next((p.strip()[9:] for p in protocols if p.strip().startswith('sentinel.')), '')
    if os.getenv('SENTINEL_AUTH_DISABLED')!='1' and os.getenv('SENTINEL_OPERATOR_TOKEN') and role(token)!='operator':
        await websocket.close(code=1008)
        return
    selected=next((p.strip() for p in protocols if p.strip().startswith("sentinel.")), None)
    await manager.connect(websocket, subprotocol=selected)
    from app.models import Flow
    from app.routers.analytics import summary
    from app.services.incident_manager import serialize
    from sqlalchemy import select
    with websocket.app.state.sessions() as db:
        await websocket.send_json({"event_type":"SNAPSHOT", "kpis":summary(db),
            "flows":[serialize(f) for f in db.scalars(select(Flow).order_by(Flow.id.desc()).limit(25))]})
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
