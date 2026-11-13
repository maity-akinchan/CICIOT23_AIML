from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.services.ws_manager import manager

router = APIRouter()


@router.websocket("/ws/live")
async def live_socket(websocket: WebSocket) -> None:
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
