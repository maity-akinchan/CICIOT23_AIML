from __future__ import annotations

import logging

from fastapi import WebSocket

from app.schemas import json_safe

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.discard(websocket)

    async def broadcast(self, message: dict) -> None:
        failed: list[WebSocket] = []
        for connection in tuple(self.active_connections):
            try:
                await connection.send_json(json_safe(message))
            except Exception:
                failed.append(connection)
        for connection in failed:
            self.disconnect(connection)


manager = ConnectionManager()
