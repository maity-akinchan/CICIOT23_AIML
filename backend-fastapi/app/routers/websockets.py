from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool

from app.models import Flow
from app.routers.analytics import summary
from app.security import credentials_required, role
from app.services.incident_manager import serialize

router = APIRouter()


@router.websocket("/ws/live")
async def live_socket(websocket: WebSocket) -> None:
    prefix = 'sentinel.'
    offered = websocket.scope.get('subprotocols', [])
    selected = next((protocol for protocol in offered if protocol.startswith(prefix)), None)
    if credentials_required() and (selected is None or role(selected.removeprefix(prefix)) != 'operator'):
        await websocket.close(code=1008)
        return
    state = websocket.app.state

    def snapshot():
        with state.sessions() as db:
            kpis = summary(db)
            flows = [serialize(f) for f in db.scalars(select(Flow).order_by(Flow.id.desc()).limit(25))]
        return {'event_type': 'SNAPSHOT', 'kpis': kpis,
                'flows': state.inference_engine.restore_explanations(flows)}

    try:
        initial = await run_in_threadpool(snapshot)
        await state.ws_manager.connect(websocket, subprotocol=selected)
        await websocket.send_json(initial)
        while True:
            await websocket.receive_text()
    except (WebSocketDisconnect, OSError):
        pass
    finally:
        state.ws_manager.disconnect(websocket)
