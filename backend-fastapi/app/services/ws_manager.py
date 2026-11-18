from __future__ import annotations

import asyncio
from collections import deque
from typing import Any
import logging

from fastapi import WebSocket

from app.schemas import json_safe

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: set[WebSocket] = set()
        self.telemetry_buffer: deque[dict[str, Any]] = deque(maxlen=10_000)

    async def connect(self, websocket: WebSocket, subprotocol: str | None = None) -> None:
        await websocket.accept(subprotocol=subprotocol)
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.discard(websocket)

    def enqueue(self, flows: list[dict[str, Any]]) -> None:
        self.telemetry_buffer.extend(flows)

    def _flush_buffer(self) -> list[dict[str, Any]]:
        flows = list(self.telemetry_buffer)
        self.telemetry_buffer.clear()
        return flows

    async def broadcast(self, message: dict[str, Any]) -> None:
        await self._broadcast(message)

    async def _broadcast(self, message: dict[str, Any]) -> None:
        failed: list[WebSocket] = []
        for connection in tuple(self.active_connections):
            try:
                await asyncio.wait_for(connection.send_json(json_safe(message)),timeout=1.0)
            except Exception:
                failed.append(connection)
        for connection in failed:
            self.disconnect(connection)

    async def websocket_broadcaster(self, stop_event: asyncio.Event) -> None:
        try:
            while not stop_event.is_set():
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=0.5)
                except asyncio.TimeoutError:
                    pass
                flows = self._flush_buffer()
                if flows and self.active_connections:
                    await self._broadcast({
                        "event_type": "TELEMETRY_BATCH",
                        "flows": flows,
                    })
        except asyncio.CancelledError:
            raise


manager = ConnectionManager()
telemetry_buffer = manager.telemetry_buffer
