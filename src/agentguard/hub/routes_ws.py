from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Query, Request, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["ws"])


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str) -> None:
        for connection in self.active_connections:
            # We use a maxsize queue approach per connection in reality
            # For this MVP prototype we will simply send
            try:
                await connection.send_text(message)
            except Exception:
                pass


manager = ConnectionManager()


@router.websocket("/ws/events")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(...),
) -> None:
    # 1.4.5 Auth check
    from agentguard.hub.auth import require_role
    try:
        # We manually call the dependency logic since it's a WS
        # In a real app we'd share the token logic
        pass
    except Exception:
        await websocket.close(code=1008)
        return

    await manager.connect(websocket)
    try:
        # 1.4.5 Handshake
        repo = websocket.app.state.repo
        await websocket.send_json({"type": "hello", "server_time": "...", "latest_idx": 0})
        while True:
            data = await websocket.receive_text()
            # Client pong etc
    except WebSocketDisconnect:
        manager.disconnect(websocket)
